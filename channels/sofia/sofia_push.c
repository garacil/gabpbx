/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

/*! \file sofia_push.c
 * \brief chan_sofia mobile push wake-up — wake a mobile softphone before delivering the call (P1).
 *
 * A mobile softphone cannot keep its SIP socket alive in the background: the OS kills the
 * app (contact gone) or freezes it (socket open but dead). This module lets the driver WAKE
 * the phone before delivering the call: the REGISTER carries X-Device-ID / X-Push-Token /
 * X-Push-Platform / X-Push-Type; we persist the tokens locally and, when a call hits a
 * dynamic peer with no live contact but stored tokens, the driver parks the call, runs the
 * push sender and resumes with the announced Call-ID once the device re-registers.
 *
 * THREAD/STORAGE DOCTRINE (hard rules):
 *   - sofia_thread NEVER touches the database. REGISTER capture updates the in-memory
 *     cache synchronously (ao2 locks only) and queues the row write to the "sofia/pushdb"
 *     taskprocessor as a by-value snapshot (regpool pattern).
 *   - The dial path NEVER queries SQLite: it reads the cache. The cache is preloaded at
 *     module init (the table only holds mobile devices) and marked COMPLETE, so a miss is
 *     answered from memory; if preload fails we degrade to lazy load-on-first-use (PBX
 *     dialing thread only) with negative entries.
 *   - A storage failure of any kind degrades to exactly today's behavior (no tokens ->
 *     CHANUNAVAIL); it can never corrupt call state or block a SIP-thread operation.
 *   - Tokens are credentials: every log/CLI rendering goes through sofia_push_redact()
 *     (first6…last4/len). push_log rows never carry a token.
 *
 * Storage: /var/lib/gabpbx/push_tokens.sqlite3 via res_config_sqlite3 (extconfig families
 * "pushtokens" -> push_tokens, "pushlog" -> push_log; schema created at deploy, WAL on).
 */

#include "gabpbx.h"
#include "gabpbx/channel.h"
#include "gabpbx/astobj2.h"
#include "gabpbx/lock.h"
#include "gabpbx/utils.h"
#include "gabpbx/strings.h"
#include "gabpbx/logger.h"
#include "gabpbx/config.h"		/* ast_load_realtime_multientry / ast_update2_realtime / ... */
#include "gabpbx/taskprocessor.h"
#include "gabpbx/sched.h"		/* ast_sched_thread_add/del (push_wait timer) */
#include "gabpbx/causes.h"		/* AST_CAUSE_NO_ANSWER (cause 19 -> DIALSTATUS=NOANSWER, app_dial.c:2576/754) */

#include <sofia-sip/sip.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/su_uniqueid.h>	/* su_guid_* - pre-generated Call-ID, same 36-hex shape as the stack's own */

#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>

#include "gabpbx/app.h"		/* ast_safe_fork / ast_safe_fork_cleanup / ast_close_fds_above_n */
#include "gabpbx/cli.h"		/* sip show push */

#include "include/chan_sofia_internal.h"

#define SOFIA_PUSH_MAX_DEVICES 10	/* hard array bound; the knob clamps to this */
#define SOFIA_PUSH_TOKEN_MAX 512	/* header hygiene: cap + printable-ASCII-no-space */
#define SOFIA_PUSH_DEVID_MAX 64		/* expect 8 hex, accept [A-Za-z0-9._-]{1,63} (older builds) */
#define SOFIA_PUSH_FAIL_PURGE 5		/* pushes with no wake REGISTER before the device is dropped */
#define SOFIA_PUSH_DBQ_MAX 64		/* self-counted pushdb queue cap (no depth API in this fork) */

struct sofia_push_device {
	char device_id[SOFIA_PUSH_DEVID_MAX];
	char platform[16];		/* ios | android */
	char push_type[8];		/* voip | fcm */
	char token[SOFIA_PUSH_TOKEN_MAX];
	char instance[128];		/* +sip.instance of the binding */
	char user_agent[64];
	time_t updated_at;
	time_t reg_expires;
	time_t last_push_at;
	int fail_count;
	char last_result[121];
};

/* One cache entry per peer name; devices mutated ONLY under ao2_lock(entry).
 * Keyed globally by name (NOT hung off struct sofia_peer): `sip prune realtime`
 * replaces the peer OBJECT and the cache must survive it. */
struct sofia_push_tokens {
	char peername[128];		/* container key (case-insensitive) */
	int loaded_from_db;		/* 1 = a DB read populated it (empty allowed = negative entry) */
	int ndev;
	struct sofia_push_device dev[SOFIA_PUSH_MAX_DEVICES];
};

static struct ao2_container *sofia_push_cache;	/* NULL = push disabled everywhere */
static struct ast_taskprocessor *sofia_pushdb_tps;
static int sofia_push_cache_complete;		/* 1 = preload succeeded: a cache miss means "no tokens", no DB read ever */
static int sofia_pushdb_depth;			/* atomic self-counted queue depth (ast_atomic_fetchadd_int) */

static int sofia_push_tokens_hash(const void *obj, const int flags)
{
	const struct sofia_push_tokens *e = obj;
	return ast_str_case_hash(e->peername);
}

static int sofia_push_tokens_cmp(void *obj, void *arg, int flags)
{
	struct sofia_push_tokens *a = obj, *b = arg;
	return strcasecmp(a->peername, b->peername) ? 0 : (CMP_MATCH | CMP_STOP);
}

/* ---------- token privacy ---------- */

/* Render a token as "first6…last4/len". Short/empty tokens never leak. */
const char *sofia_push_redact(const char *token, char *buf, size_t buflen)
{
	size_t n = token ? strlen(token) : 0;
	if (!buf || !buflen) {
		return "";
	}
	if (n < 12) {
		snprintf(buf, buflen, "short/%zu", n);
	} else {
		snprintf(buf, buflen, "%.6s…%.4s/%zu", token, token + n - 4, n);
	}
	return buf;
}

/* ---------- header hygiene ---------- */

static int sofia_push_token_valid(const char *t)
{
	size_t i, n;
	if (ast_strlen_zero(t)) {
		return 0;
	}
	n = strlen(t);
	if (n >= SOFIA_PUSH_TOKEN_MAX) {
		return 0;
	}
	for (i = 0; i < n; i++) {	/* printable ASCII, no spaces: crosses into argv + JSON */
		if (t[i] <= 0x20 || t[i] > 0x7e) {
			return 0;
		}
	}
	return 1;
}

static int sofia_push_devid_valid(const char *d)
{
	size_t i, n;
	if (ast_strlen_zero(d)) {
		return 0;
	}
	n = strlen(d);
	if (n >= SOFIA_PUSH_DEVID_MAX) {
		return 0;
	}
	for (i = 0; i < n; i++) {
		if (!isalnum((unsigned char) d[i]) && d[i] != '.' && d[i] != '_' && d[i] != '-') {
			return 0;
		}
	}
	return 1;
}

static int sofia_push_token_is_voip(const char *t)	/* Kamailio classifier: 64 lowercase hex = APNs VoIP */
{
	size_t i, n = strlen(t);
	if (n != 64) {
		return 0;
	}
	for (i = 0; i < n; i++) {
		if (!isxdigit((unsigned char) t[i]) || isupper((unsigned char) t[i])) {
			return 0;
		}
	}
	return 1;
}

/* ---------- pushdb taskprocessor (the ONLY database writer) ---------- */

enum sofia_pushdb_kind {
	PUSHDB_UPSERT = 0,
	PUSHDB_DELETE,
	PUSHDB_LOG,
	PUSHDB_FIELDS,		/* partial device update: last_push_at / last_result / fail_count */
};

struct sofia_pushdb_job {
	enum sofia_pushdb_kind kind;
	char peer[128];
	char device_id[SOFIA_PUSH_DEVID_MAX];
	/* upsert payload */
	char platform[16], push_type[8], token[SOFIA_PUSH_TOKEN_MAX], instance[128], user_agent[64];
	time_t updated_at, reg_expires, last_push_at;
	int fail_count;
	char last_result[121];
	/* log payload */
	char callid[64], event[24], detail[160];
};

static int sofia_pushdb_exe(void *data)
{
	struct sofia_pushdb_job *j = data;
	char ts_s[24], upd_s[24], exp_s[24], lpush_s[24], fc_s[12];

	switch (j->kind) {
	case PUSHDB_UPSERT:
		snprintf(upd_s, sizeof(upd_s), "%ld", (long) j->updated_at);
		snprintf(exp_s, sizeof(exp_s), "%ld", (long) j->reg_expires);
		if (ast_update2_realtime("pushtokens",
				"peer", j->peer, "device_id", j->device_id, SENTINEL,
				"platform", j->platform, "push_type", j->push_type, "token", j->token,
				"instance", j->instance, "user_agent", j->user_agent,
				"updated_at", upd_s, "reg_expires", exp_s, "fail_count", "0",
				SENTINEL) <= 0) {
			if (ast_store_realtime("pushtokens",
					"peer", j->peer, "device_id", j->device_id,
					"platform", j->platform, "push_type", j->push_type, "token", j->token,
					"instance", j->instance, "user_agent", j->user_agent,
					"updated_at", upd_s, "reg_expires", exp_s,
					"last_push_at", "0", "last_result", "", "fail_count", "0",
					SENTINEL) < 0) {
				ast_log(LOG_WARNING, "Sofia PUSH: token store failed for peer '%s' dev '%s' (next REGISTER retries)\n",
					j->peer, j->device_id);
			}
		}
		break;
	case PUSHDB_DELETE:
		ast_destroy_realtime("pushtokens", "peer", j->peer, "device_id", j->device_id, SENTINEL);
		break;
	case PUSHDB_FIELDS:
		snprintf(lpush_s, sizeof(lpush_s), "%ld", (long) j->last_push_at);
		snprintf(fc_s, sizeof(fc_s), "%d", j->fail_count);
		ast_update2_realtime("pushtokens",
			"peer", j->peer, "device_id", j->device_id, SENTINEL,
			"last_push_at", lpush_s, "last_result", j->last_result, "fail_count", fc_s,
			SENTINEL);
		break;
	case PUSHDB_LOG:
		snprintf(ts_s, sizeof(ts_s), "%ld", (long) time(NULL));
		ast_store_realtime("pushlog",
			"ts", ts_s, "peer", j->peer, "device_id", j->device_id,
			"callid", j->callid, "event", j->event, "detail", j->detail,
			SENTINEL);
		break;
	}
	ast_atomic_fetchadd_int(&sofia_pushdb_depth, -1);
	ast_free(j);
	return 0;
}

/* Queue a DB job (by-value snapshot). Failure = log + drop, cache stays correct
 * (regpool doctrine: never block, never reorder; the next REGISTER heals the row). */
static void sofia_pushdb_queue(const struct sofia_pushdb_job *src)
{
	struct sofia_pushdb_job *j;
	static time_t last_warn;

	if (!sofia_pushdb_tps) {
		return;
	}
	if (ast_atomic_fetchadd_int(&sofia_pushdb_depth, +1) >= SOFIA_PUSH_DBQ_MAX) {
		ast_atomic_fetchadd_int(&sofia_pushdb_depth, -1);
		if (time(NULL) - last_warn >= 60) {
			last_warn = time(NULL);
			ast_log(LOG_WARNING, "Sofia PUSH: pushdb queue cap (%d) hit - dropping DB write (cache stays authoritative)\n",
				SOFIA_PUSH_DBQ_MAX);
		}
		return;
	}
	if (!(j = ast_calloc(1, sizeof(*j)))) {
		ast_atomic_fetchadd_int(&sofia_pushdb_depth, -1);
		return;
	}
	*j = *src;
	if (ast_taskprocessor_push(sofia_pushdb_tps, sofia_pushdb_exe, j) < 0) {
		ast_atomic_fetchadd_int(&sofia_pushdb_depth, -1);
		ast_free(j);
	}
}

void sofia_push_log_event(const char *peer, const char *device_id, const char *callid,
	const char *event, const char *detail)
{
	struct sofia_pushdb_job j = { .kind = PUSHDB_LOG };
	ast_copy_string(j.peer, S_OR(peer, ""), sizeof(j.peer));
	ast_copy_string(j.device_id, S_OR(device_id, ""), sizeof(j.device_id));
	ast_copy_string(j.callid, S_OR(callid, ""), sizeof(j.callid));
	ast_copy_string(j.event, S_OR(event, ""), sizeof(j.event));
	ast_copy_string(j.detail, S_OR(detail, ""), sizeof(j.detail));
	sofia_pushdb_queue(&j);
}

/* ---------- cache ---------- */

/* find-or-create under the container lock (ao2 mutexes are recursive: ao2_link inside
 * ao2_lock(container) is safe) so two threads can never create twin entries. +1 ref. */
static struct sofia_push_tokens *sofia_push_entry_get(const char *peername, int create)
{
	struct sofia_push_tokens key = { { 0 } };
	struct sofia_push_tokens *e;

	if (!sofia_push_cache || ast_strlen_zero(peername)) {
		return NULL;
	}
	ast_copy_string(key.peername, peername, sizeof(key.peername));
	/* Hold the container lock across find+create+link so twin entries can never race into
	 * existence; ao2 mutexes are recursive in this fork (lock.h AST_MUTEX_KIND), so the
	 * internal locking of ao2_find/ao2_link nests safely under it. */
	ao2_lock(sofia_push_cache);
	e = ao2_find(sofia_push_cache, &key, OBJ_POINTER);
	if (!e && create) {
		e = ao2_alloc(sizeof(*e), NULL);
		if (e) {
			ast_copy_string(e->peername, peername, sizeof(e->peername));
			if (!ao2_link(sofia_push_cache, e)) {
				ao2_ref(e, -1);
				e = NULL;
			}
		}
	}
	ao2_unlock(sofia_push_cache);
	return e;
}

static int sofia_push_device_stale(const struct sofia_push_device *d, time_t now)
{
	if (d->fail_count >= SOFIA_PUSH_FAIL_PURGE) {
		return 1;
	}
	if (sofia_cfg.push_token_ttl_days > 0
		&& d->updated_at < now - (time_t) sofia_cfg.push_token_ttl_days * 86400) {
		return 1;
	}
	return 0;
}

/* Upsert one device into the entry (entry lock). Evicts the oldest device at the cap. */
static void sofia_push_cache_upsert(struct sofia_push_tokens *e, const struct sofia_push_device *nd)
{
	int i, slot = -1, oldest = 0;

	ao2_lock(e);
	for (i = 0; i < e->ndev; i++) {
		if (!strcasecmp(e->dev[i].device_id, nd->device_id)) {
			slot = i;
			break;
		}
		if (e->dev[i].updated_at < e->dev[oldest].updated_at) {
			oldest = i;
		}
	}
	if (slot < 0) {
		int cap = sofia_cfg.push_max_devices;
		if (cap < 1 || cap > SOFIA_PUSH_MAX_DEVICES) {
			cap = SOFIA_PUSH_MAX_DEVICES;
		}
		if (e->ndev < cap) {
			slot = e->ndev++;
		} else {
			slot = oldest;	/* Kamailio devlist parity: bounded per peer, oldest loses */
		}
	}
	e->dev[slot] = *nd;
	ao2_unlock(e);
}

static int sofia_push_cache_delete(struct sofia_push_tokens *e, const char *device_id)
{
	int i, found = 0;

	ao2_lock(e);
	for (i = 0; i < e->ndev; i++) {
		if (!strcasecmp(e->dev[i].device_id, device_id)) {
			e->dev[i] = e->dev[e->ndev - 1];
			memset(&e->dev[e->ndev - 1], 0, sizeof(e->dev[0]));
			e->ndev--;
			found = 1;
			break;
		}
	}
	ao2_unlock(e);
	return found;
}

/* Build one cache device from a realtime row (variable list of one category). */
static void sofia_push_device_from_vars(struct sofia_push_device *d, const struct ast_variable *v)
{
	memset(d, 0, sizeof(*d));
	for (; v; v = v->next) {
		if (!strcasecmp(v->name, "device_id")) {
			ast_copy_string(d->device_id, v->value, sizeof(d->device_id));
		} else if (!strcasecmp(v->name, "platform")) {
			ast_copy_string(d->platform, v->value, sizeof(d->platform));
		} else if (!strcasecmp(v->name, "push_type")) {
			ast_copy_string(d->push_type, v->value, sizeof(d->push_type));
		} else if (!strcasecmp(v->name, "token")) {
			ast_copy_string(d->token, v->value, sizeof(d->token));
		} else if (!strcasecmp(v->name, "instance")) {
			ast_copy_string(d->instance, v->value, sizeof(d->instance));
		} else if (!strcasecmp(v->name, "user_agent")) {
			ast_copy_string(d->user_agent, v->value, sizeof(d->user_agent));
		} else if (!strcasecmp(v->name, "updated_at")) {
			d->updated_at = (time_t) atol(v->value);
		} else if (!strcasecmp(v->name, "reg_expires")) {
			d->reg_expires = (time_t) atol(v->value);
		} else if (!strcasecmp(v->name, "last_push_at")) {
			d->last_push_at = (time_t) atol(v->value);
		} else if (!strcasecmp(v->name, "fail_count")) {
			d->fail_count = atoi(v->value);
		} else if (!strcasecmp(v->name, "last_result")) {
			ast_copy_string(d->last_result, v->value, sizeof(d->last_result));
		}
	}
}

/* Lazy per-peer DB load (PBX dialing thread ONLY - the same thread that already does
 * realtime peer loads; never sofia_thread). Used only when the preload failed. */
static void sofia_push_lazy_load(struct sofia_push_tokens *e)
{
	struct ast_config *cfg;
	char *cat = NULL;

	e->loaded_from_db = 1;	/* even an empty result is an answer (negative cache) */
	cfg = ast_load_realtime_multientry("pushtokens", "peer", e->peername, SENTINEL);
	if (!cfg) {
		return;
	}
	/* 1.8 browse idiom: pass back the exact name pointer ast_category_browse returned -
	 * ast_variable_browse matches it against last_browse BY POINTER (config.c:586), so
	 * duplicate category names (one per row) still resolve positionally. */
	while ((cat = ast_category_browse(cfg, cat))) {
		struct sofia_push_device d;
		sofia_push_device_from_vars(&d, ast_variable_browse(cfg, cat));
		if (d.device_id[0] && d.token[0]) {
			sofia_push_cache_upsert(e, &d);
		}
	}
	ast_config_destroy(cfg);
}

/* ---------- public gates ---------- */

/* Effective per-peer enable: [general] push master AND the peer not opted out. */
int sofia_push_peer_enabled(const struct sofia_peer *peer)
{
	if (!sofia_cfg.push_enabled || !sofia_push_cache) {
		return 0;
	}
	return peer ? (peer->push != 0) : 0;
}

/* Does this peer have at least one usable (non-stale) push token? Cache-only when the
 * preload succeeded; lazy DB load (PBX thread) when it did not. Never touches SQLite
 * on sofia_thread: REGISTER capture pre-populates the cache before any resume runs. */
int sofia_push_peer_pushable(struct sofia_peer *peer)
{
	struct sofia_push_tokens *e;
	time_t now = time(NULL);
	int i, usable = 0;

	if (!sofia_push_peer_enabled(peer)) {
		return 0;
	}
	e = sofia_push_entry_get(peer->name, !sofia_push_cache_complete /* create only in lazy mode */);
	if (!e) {
		/* complete cache: miss == no tokens, answered from memory. debug-level only —
		 * this gate now runs on EVERY single-contact call (P2 Call-ID pre-gen), and
		 * "no tokens" is the normal state of trunks and desk phones. */
		ast_debug(2, "Sofia PUSH: peer '%s' not pushable - no cached tokens (cache %s)\n",
			peer->name, sofia_push_cache_complete ? "complete" : "lazy");
		return 0;
	}
	if (!sofia_push_cache_complete && !e->loaded_from_db) {
		sofia_push_lazy_load(e);
	}
	ao2_lock(e);
	for (i = 0; i < e->ndev; i++) {
		if (!sofia_push_device_stale(&e->dev[i], now)) {
			usable++;
		}
	}
	ao2_unlock(e);
	if (!usable) {
		ast_verb(3, "Sofia PUSH: peer '%s' not pushable - %d device(s) cached, 0 usable (stale/failed)\n",
			peer->name, e->ndev);
	}
	ao2_ref(e, -1);
	return usable > 0;
}

/* ---------- push sender (its own taskprocessor; argv exec, NEVER a shell) ----------
 *
 * One job per device per call, on the dedicated "sofia/push" lane (separate from
 * "sofia/pushdb" so a hung APNs TLS handshake can never delay token persistence).
 * The child is the companion sender script (send_push_voip.py for voip, send_push.py
 * for fcm) exec'd with an argv ARRAY — the caller display name is attacker-influenced and
 * must never cross a shell. stdout(+stderr) is captured through a pipe with an 8 s
 * deadline (covers APNs prod->sandbox double round-trip), then SIGKILL; waitpid ALWAYS
 * runs (no zombies, the lane can never wedge past the deadline). BEST-EFFORT INVARIANT:
 * the park/timer/resume lifecycle committed BEFORE these jobs were queued and never
 * reads their outcome — a broken sender costs observability only. */

#define SOFIA_PUSH_EXEC_TIMEOUT_MS 8000
#define SOFIA_PUSH_RESULT_MAX 256

static struct ast_taskprocessor *sofia_push_tps;

struct sofia_push_send_job {
	char script[300];		/* absolute path (push_scripts + send_push[_voip].py) */
	char token[SOFIA_PUSH_TOKEN_MAX];
	char cid_num[80];
	char cid_name[80];
	char callid[64];
	char peername[128];
	char device_id[SOFIA_PUSH_DEVID_MAX];
};

/* Dead-token classification from the scripts' stdout markers (verified live):
 * APNs: "ERR:sandbox:400 ...BadDeviceToken" (prod already returned BadDeviceToken —
 * dead in BOTH environments) or "ERR:prod:410" (Unregistered). FCM (send_push.py
 * prints "ERR:<code>"): 404 UNREGISTERED; 400 INVALID_ARGUMENT (the payload is fixed,
 * so the token is the only variable). */
static int sofia_push_result_is_dead_token(const char *out)
{
	if (!out) {
		return 0;
	}
	if (!strncmp(out, "ERR:sandbox:400", 15) && strstr(out, "BadDeviceToken")) {
		return 1;
	}
	if (!strncmp(out, "ERR:prod:410", 12)) {
		return 1;
	}
	if (!strcmp(out, "ERR:404") || !strcmp(out, "ERR:400")) {
		return 1;
	}
	return 0;
}

static void sofia_push_purge_device(const char *peername, const char *device_id, const char *reason)
{
	struct sofia_push_tokens *e = sofia_push_entry_get(peername, 0);
	struct sofia_pushdb_job dj = { .kind = PUSHDB_DELETE };

	if (e) {
		sofia_push_cache_delete(e, device_id);
		ao2_ref(e, -1);
	}
	ast_copy_string(dj.peer, peername, sizeof(dj.peer));
	ast_copy_string(dj.device_id, device_id, sizeof(dj.device_id));
	sofia_pushdb_queue(&dj);
	sofia_push_log_event(peername, device_id, "", "dead_token", reason);
	ast_log(LOG_NOTICE, "Sofia PUSH: purged dead token peer='%s' dev='%s' (%s)\n",
		peername, device_id, reason);
}

/* Update last_result (+ last_push_at) in cache + DB after a sender run. */
static void sofia_push_record_result(const char *peername, const char *device_id, const char *result)
{
	struct sofia_push_tokens *e = sofia_push_entry_get(peername, 0);
	struct sofia_pushdb_job fj = { .kind = PUSHDB_FIELDS };
	time_t now = time(NULL);
	int fail_count = 0;

	if (e) {
		int i;
		ao2_lock(e);
		for (i = 0; i < e->ndev; i++) {
			if (!strcasecmp(e->dev[i].device_id, device_id)) {
				ast_copy_string(e->dev[i].last_result, result, sizeof(e->dev[i].last_result));
				e->dev[i].last_push_at = now;
				fail_count = e->dev[i].fail_count;
				break;
			}
		}
		ao2_unlock(e);
		ao2_ref(e, -1);
	}
	ast_copy_string(fj.peer, peername, sizeof(fj.peer));
	ast_copy_string(fj.device_id, device_id, sizeof(fj.device_id));
	ast_copy_string(fj.last_result, result, sizeof(fj.last_result));
	fj.last_push_at = now;
	fj.fail_count = fail_count;
	sofia_pushdb_queue(&fj);
}

/* Runs on the sofia/push taskprocessor thread (blocking up to the deadline is FINE here;
 * this is neither sofia_thread nor the PBX dialing thread). */
static int sofia_push_send_exe(void *data)
{
	struct sofia_push_send_job *j = data;
	char out[SOFIA_PUSH_RESULT_MAX] = "";
	char redact[64];
	int pfd[2] = { -1, -1 };
	pid_t pid;
	struct timeval t0 = ast_tvnow();
	static time_t last_exec_warn;

	if (access(j->script, X_OK)) {
		ast_copy_string(out, "ERR:noexec", sizeof(out));
		if (time(NULL) - last_exec_warn >= 60) {
			last_exec_warn = time(NULL);
			ast_log(LOG_WARNING, "Sofia PUSH: sender script '%s' missing/not executable - pushes are being dropped (calls still park + NOANSWER cleanly)\n",
				j->script);
		}
		goto record;
	}
	if (pipe(pfd)) {
		ast_copy_string(out, "ERR:pipe", sizeof(out));
		goto record;
	}
	pid = ast_safe_fork(1);	/* stop_reaper: we waitpid ourselves; paired with ast_safe_fork_cleanup below */
	if (pid < 0) {
		close(pfd[0]);
		close(pfd[1]);
		ast_safe_fork_cleanup();
		ast_copy_string(out, "ERR:fork", sizeof(out));
		goto record;
	}
	if (pid == 0) {
		/* child: /dev/null stdin, pipe stdout+stderr (a python traceback's first line
		 * lands in last_result), close the rest, exec the script (shebang python3). */
		int devnull = open("/dev/null", O_RDONLY);
		if (devnull >= 0) {
			dup2(devnull, STDIN_FILENO);
		}
		dup2(pfd[1], STDOUT_FILENO);
		dup2(pfd[1], STDERR_FILENO);
		ast_close_fds_above_n(STDERR_FILENO);
		{
			char *argv[] = { j->script, j->token, j->cid_num, j->cid_name, j->callid, NULL };
			execv(j->script, argv);
		}
		_exit(1);
	}
	close(pfd[1]);
	{
		/* parent: poll-read up to the deadline; then SIGKILL. waitpid on every path. */
		struct pollfd pf = { .fd = pfd[0], .events = POLLIN };
		int deadline = SOFIA_PUSH_EXEC_TIMEOUT_MS;
		size_t got = 0;
		int st;
		for (;;) {
			struct timeval it0 = ast_tvnow();
			int pr = poll(&pf, 1, deadline);
			if (pr > 0) {
				ssize_t n = read(pfd[0], out + got, sizeof(out) - 1 - got);
				if (n <= 0) {
					break;	/* EOF: child closed stdout (exited or done writing) */
				}
				got += (size_t) n;
				out[got] = '\0';
				if (got >= sizeof(out) - 1) {
					break;	/* flood guard: stop reading, kill below */
				}
			} else {
				break;	/* timeout or poll error */
			}
			deadline -= (int) ast_tvdiff_ms(ast_tvnow(), it0);
			if (deadline <= 0) {
				break;
			}
		}
		close(pfd[0]);
		kill(pid, SIGKILL);	/* idempotent: already-exited child ignores it */
		waitpid(pid, &st, 0);
		ast_safe_fork_cleanup();
		if (!got) {
			ast_copy_string(out, "ERR:timeout", sizeof(out));
		}
	}
record:
	/* keep the first line only (python tracebacks are multi-line) */
	{
		char *nl = strchr(out, '\n');
		if (nl) {
			*nl = '\0';
		}
	}
	ast_verb(2, "Sofia PUSH: sender %s dev=%s token=%s callid=%s result=%s (%ldms)\n",
		j->script, j->device_id, sofia_push_redact(j->token, redact, sizeof(redact)),
		j->callid, out, (long) ast_tvdiff_ms(ast_tvnow(), t0));
	sofia_push_log_event(j->peername, j->device_id, j->callid, "sent", out);
	sofia_push_record_result(j->peername, j->device_id, out);
	if (sofia_push_result_is_dead_token(out)) {
		sofia_push_purge_device(j->peername, j->device_id, out);
	}
	ast_atomic_fetchadd_int(&sofia_pushdb_depth, -1);	/* shared best-effort budget */
	ast_free(j);
	return 0;
}

/* ---------- parked-call registry (park / push_wait timeout / caller hangup) ----------
 *
 * One entry per parked CALL, keyed by peername in a GLOBAL container (the peer OBJECT can
 * be replaced by `sip prune realtime`; the registry must survive that). The entry's ao2
 * lock is a LEAF: nothing is ever taken under it, and no nua_* / channel call runs while
 * it is held. state moves ONLY under that lock — exactly one terminal CAS wins; losers see
 * the changed state and back out with ref drops. The push_wait timer follows the
 * defer-BYE idiom verbatim (arm under the entry lock while the sched callback's first act
 * is taking that same lock — safe because ast_sched_runq invokes callbacks with the sched
 * lock RELEASED, main/sched.c:652-653; cancel is del-or-fire: del()==0 drops the timer's
 * ref, otherwise the callback owns it). */

enum sofia_push_park_state {
	SOFIA_PUSH_PARKED = 0,
	SOFIA_PUSH_RESUMING,	/* claimed by the resume path; terminal for everyone else */
	SOFIA_PUSH_DONE,
};

struct sofia_push_park {
	char peername[128];		/* container key (multi-entry per peer allowed) */
	struct sofia_pvt *pvt;		/* +1 held while the entry lives (sole dropper: destructor) */
	char callid[64];		/* pre-generated SIP Call-ID = the push uuid */
	char cid_num[80];
	char cid_name[80];
	int sched_id;			/* push_wait; -1 = none */
	enum sofia_push_park_state state;
	int inflight;			/* P2: an INVITE is ALREADY on the wire (no-provisional guard fired); resume swaps the leg instead of creating the first one */
	time_t parked_at;
	int npushed;			/* devices actually notified */
	char pushed_dev[SOFIA_PUSH_MAX_DEVICES][SOFIA_PUSH_DEVID_MAX];
};

#define SOFIA_PUSH_PARK_MAX_PER_PEER 4
#define SOFIA_PUSH_PARK_MAX_GLOBAL 64	/* also bounds parked RTP port pairs */

static struct ao2_container *sofia_push_parked;

static void sofia_push_park_destructor(void *obj)
{
	struct sofia_push_park *e = obj;
	if (e->pvt) {
		ao2_ref(e->pvt, -1);
		e->pvt = NULL;
	}
}

static int sofia_push_park_hash(const void *obj, const int flags)
{
	const struct sofia_push_park *e = obj;
	return ast_str_case_hash(e->peername);
}

static int sofia_push_park_cmp(void *obj, void *arg, int flags)
{
	struct sofia_push_park *a = obj, *b = arg;
	return strcasecmp(a->peername, b->peername) ? 0 : CMP_MATCH;	/* no CMP_STOP: multi-entry */
}

static void sofia_push_resume_one(struct sofia_push_park *e, struct sofia_peer *peer,
	const struct sofia_register_update *update);

/* Queue the sender jobs for every eligible device of the peer. Returns the number of
 * jobs queued, and reports (via *rate_limited) devices skipped only by push_min_interval
 * (a park with 0 jobs is still valid if a push went out moments ago — the phone is
 * already waking; a second push inside the phone's own 5 s dedup window would be
 * actively harmful — iOS reports-and-cancels it). Also records the pushed device ids. */
static int sofia_push_notify_devices(struct sofia_push_park *entry, int *rate_limited)
{
	struct sofia_push_tokens *e;
	struct sofia_push_device snap[SOFIA_PUSH_MAX_DEVICES];
	int nsnap = 0, i, queued = 0;
	time_t now = time(NULL);
	int cap = sofia_cfg.push_max_devices;

	*rate_limited = 0;
	if (cap < 1 || cap > SOFIA_PUSH_MAX_DEVICES) {
		cap = SOFIA_PUSH_MAX_DEVICES;
	}
	if (!sofia_push_tps) {
		return 0;
	}
	if (!(e = sofia_push_entry_get(entry->peername, 0))) {
		return 0;
	}
	ao2_lock(e);
	for (i = 0; i < e->ndev && nsnap < cap; i++) {
		if (sofia_push_device_stale(&e->dev[i], now)) {
			continue;
		}
		if (sofia_cfg.push_min_interval > 0
			&& e->dev[i].last_push_at > now - sofia_cfg.push_min_interval) {
			(*rate_limited)++;
			continue;
		}
		e->dev[i].last_push_at = now;	/* stamp NOW so a racing second park rate-limits */
		snap[nsnap++] = e->dev[i];
	}
	ao2_unlock(e);
	ao2_ref(e, -1);

	for (i = 0; i < nsnap; i++) {
		struct sofia_push_send_job *j;
		if (ast_atomic_fetchadd_int(&sofia_pushdb_depth, +1) >= SOFIA_PUSH_DBQ_MAX) {
			ast_atomic_fetchadd_int(&sofia_pushdb_depth, -1);
			break;
		}
		if (!(j = ast_calloc(1, sizeof(*j)))) {
			ast_atomic_fetchadd_int(&sofia_pushdb_depth, -1);
			break;
		}
		snprintf(j->script, sizeof(j->script), "%s/%s", sofia_cfg.push_scripts,
			!strcasecmp(snap[i].push_type, "voip") ? "send_push_voip.py" : "send_push.py");
		ast_copy_string(j->token, snap[i].token, sizeof(j->token));
		ast_copy_string(j->cid_num, entry->cid_num, sizeof(j->cid_num));
		ast_copy_string(j->cid_name, entry->cid_name, sizeof(j->cid_name));
		ast_copy_string(j->callid, entry->callid, sizeof(j->callid));
		ast_copy_string(j->peername, entry->peername, sizeof(j->peername));
		ast_copy_string(j->device_id, snap[i].device_id, sizeof(j->device_id));
		if (ast_taskprocessor_push(sofia_push_tps, sofia_push_send_exe, j) < 0) {
			ast_atomic_fetchadd_int(&sofia_pushdb_depth, -1);
			ast_free(j);
			break;
		}
		if (entry->npushed < SOFIA_PUSH_MAX_DEVICES) {
			ast_copy_string(entry->pushed_dev[entry->npushed++], snap[i].device_id,
				sizeof(entry->pushed_dev[0]));
		}
		queued++;
	}
	return queued;
}

/* push_wait fired (sched thread, sched lock NOT held). No nua call is made here, so no
 * marshal to sofia_thread is needed (unlike defer-BYE, which marshals for its nua_bye). */
static int sofia_push_wait_cb(const void *data)
{
	struct sofia_push_park *e = (struct sofia_push_park *) data;
	struct sofia_pvt *pvt;
	struct ast_channel *owner = NULL;

	ao2_lock(e);
	e->sched_id = -1;
	if (e->state != SOFIA_PUSH_PARKED) {
		ao2_unlock(e);
		ao2_ref(e, -1);		/* the arm-time ref; resume/hangup owns the entry */
		return 0;
	}
	e->state = SOFIA_PUSH_DONE;
	ao2_unlock(e);

	/* No wake REGISTER arrived: fail_count++ on every device we pushed (>=5 purges —
	 * the uninstalled-without-logout phone). A REGISTER resets it (capture upserts 0). */
	{
		struct sofia_push_tokens *te = sofia_push_entry_get(e->peername, 0);
		int i;
		if (te) {
			for (i = 0; i < e->npushed; i++) {
				struct sofia_pushdb_job fj = { .kind = PUSHDB_FIELDS };
				int fc = 0, k;
				time_t lp = 0;
				char lr[121] = "";
				ao2_lock(te);
				for (k = 0; k < te->ndev; k++) {
					if (!strcasecmp(te->dev[k].device_id, e->pushed_dev[i])) {
						fc = ++te->dev[k].fail_count;
						lp = te->dev[k].last_push_at;
						ast_copy_string(lr, te->dev[k].last_result, sizeof(lr));
						break;
					}
				}
				ao2_unlock(te);
				if (fc >= SOFIA_PUSH_FAIL_PURGE) {
					sofia_push_purge_device(e->peername, e->pushed_dev[i], "failcount");
				} else if (fc > 0) {
					ast_copy_string(fj.peer, e->peername, sizeof(fj.peer));
					ast_copy_string(fj.device_id, e->pushed_dev[i], sizeof(fj.device_id));
					fj.fail_count = fc;
					fj.last_push_at = lp;
					ast_copy_string(fj.last_result, lr, sizeof(fj.last_result));
					sofia_pushdb_queue(&fj);
				}
			}
			ao2_ref(te, -1);
		}
	}

	pvt = e->pvt;	/* stable: the entry's own ref outlives this callback */
	if (pvt) {
		ast_mutex_lock(&pvt->lock);
		pvt->push_parked = 0;
		owner = pvt->owner;
		if (owner) {
			ast_channel_ref(owner);
		}
		ast_mutex_unlock(&pvt->lock);
	}
	if (owner) {
		/* Cause 19 -> handle_cause counts nothing -> DIALSTATUS=NOANSWER (source-proven):
		 * no-answer forwards + voicemail fire; trunk backups do NOT rotate. Queue with NO
		 * pvt/entry lock held (ast_queue_hangup_with_cause takes the channel lock). */
		ast_queue_hangup_with_cause(owner, AST_CAUSE_NO_ANSWER);
		ast_channel_unref(owner);
	}
	ast_log(LOG_NOTICE, "Sofia PUSH: timeout callid=%s peer='%s' after %lds -> NOANSWER\n",
		e->callid, e->peername, (long) (time(NULL) - e->parked_at));
	sofia_push_log_event(e->peername, "", e->callid, "timeout", "");
	if (sofia_push_parked) {
		ao2_unlink(sofia_push_parked, e);
	}
	ao2_ref(e, -1);		/* arm-time ref */
	return 0;
}

/* del-or-fire cancel: the caller must have already claimed the state transition. */
static void sofia_push_park_cancel_timer(struct sofia_push_park *e)
{
	int sid;

	ao2_lock(e);
	sid = e->sched_id;
	e->sched_id = -1;
	ao2_unlock(e);
	if (sid > -1 && sofia_sched && ast_sched_thread_del(sofia_sched, sid) == 0) {
		ao2_ref(e, -1);	/* timer never ran: drop its ref */
	}
}

/* Core entry creation shared by the P1 park and the P2 inflight guard: alloc + link +
 * sender jobs + push_wait timer, fail-closed at every step (an entry either ends up
 * fully armed and announced, or does not exist). Returns the entry +1 (caller drops)
 * or NULL. Any thread that holds NO pvt/peer/entry locks. */
static struct sofia_push_park *sofia_push_park_create(struct sofia_pvt *pvt, const char *callid,
	const char *cid_num, const char *cid_name, int inflight)
{
	struct sofia_push_park *e;

	if (!sofia_push_parked || !sofia_sched || !callid || !callid[0]) {
		return NULL;
	}
	if (!(e = ao2_alloc(sizeof(*e), sofia_push_park_destructor))) {
		return NULL;
	}
	ast_copy_string(e->peername, pvt->peername, sizeof(e->peername));
	ast_copy_string(e->callid, callid, sizeof(e->callid));
	ast_copy_string(e->cid_num, S_OR(cid_num, "unknown"), sizeof(e->cid_num));
	ast_copy_string(e->cid_name, S_OR(cid_name, e->cid_num), sizeof(e->cid_name));
	e->pvt = pvt;
	ao2_ref(pvt, +1);
	e->sched_id = -1;
	e->state = SOFIA_PUSH_PARKED;
	e->inflight = inflight;
	e->parked_at = time(NULL);

	if (!ao2_link(sofia_push_parked, e)) {
		ao2_ref(e, -1);
		return NULL;
	}

	/* Notify: one sender job per eligible device. A park nobody was told about is a
	 * silent hole — fail it (unwind) UNLESS the only reason no job went out is the
	 * per-device rate limit (a push from moments ago is already waking the phone). */
	{
		int rate_limited = 0;
		int queued = sofia_push_notify_devices(e, &rate_limited);
		if (!queued && !rate_limited) {
			ao2_unlink(sofia_push_parked, e);
			ao2_ref(e, -1);
			ast_log(LOG_WARNING, "Sofia PUSH: no sender job could be queued for peer '%s' - failing the park\n",
				pvt->peername);
			return NULL;
		}
	}

	/* Arm push_wait UNDER the entry lock (defer-BYE idiom): the callback's first act is
	 * taking this lock, so the id store below happens-before it can observe the entry. */
	ao2_lock(e);
	ao2_ref(e, +1);		/* the timer's ref */
	e->sched_id = ast_sched_thread_add(sofia_sched, sofia_cfg.push_wait * 1000, sofia_push_wait_cb, e);
	if (e->sched_id < 0) {
		e->sched_id = -1;
		ao2_unlock(e);
		ao2_ref(e, -1);	/* timer ref rollback */
		ao2_unlink(sofia_push_parked, e);
		ao2_ref(e, -1);	/* alloc ref */
		ast_log(LOG_WARNING, "Sofia PUSH: could not arm push_wait for peer '%s' - failing the park (never park untimed)\n",
			pvt->peername);
		return NULL;
	}
	ao2_unlock(e);
	return e;
}

/* ---------- P2: the no-provisional guard ----------
 *
 * A suspended phone keeps its connection-oriented socket open but never processes the
 * INVITE: the flow watch sees nothing, the INVITE black-holes until Timer B (32 s). The
 * guard arms after the single-contact INVITE to a tokened peer; with no >=100 response in
 * push_noresponse seconds it pushes with the SAME Call-ID already on the wire and parks
 * the pvt in INFLIGHT mode. Progress on the old leg cancels the park itself (the leg
 * lives, nothing is swapped); the wake REGISTER swaps the leg: unbind the old handle
 * FIRST (synchronous — from that instant its late events carry a NULL magic and can
 * never validate against this pvt), async-destroy it, and post a fresh INVITE with the
 * same Call-ID to the new binding (new from-tag; the phone dedups by uuid). */

static int sofia_push_transport_is_co(const char *t)	/* tcp/tls/ws/wss (mirror of the driver's helper) */
{
	return t && (!strcasecmp(t, "tcp") || !strcasecmp(t, "tls")
		|| !strcasecmp(t, "ws") || !strcasecmp(t, "wss"));
}

/* Guard fired (sched thread; sched lock released, defer-BYE contract). */
static int sofia_push_guard_cb(const void *data)
{
	struct sofia_pvt *pvt = (struct sofia_pvt *) data;
	struct ast_channel *owner = NULL;
	struct sofia_push_park *e;
	char callid[64] = "", cid_num[80] = "unknown", cid_name[80] = "";
	int fire = 0;

	ast_mutex_lock(&pvt->lock);
	pvt->push_guard_sched_id = -1;
	if (!pvt->got_provisional && !pvt->push_parked && pvt->nh
		&& pvt->state == SOFIA_DIALOG_STATE_TRYING && pvt->owner && pvt->sip_callid[0]) {
		fire = 1;
		ast_copy_string(callid, pvt->sip_callid, sizeof(callid));
		owner = pvt->owner;
		ast_channel_ref(owner);
	}
	ast_mutex_unlock(&pvt->lock);

	if (fire) {
		/* caller identity for the push payload: channel lock, nothing else held */
		ast_channel_lock(owner);
		ast_copy_string(cid_num, S_OR(owner->caller.id.number.str, "unknown"), sizeof(cid_num));
		ast_copy_string(cid_name, S_OR(owner->caller.id.name.str, cid_num), sizeof(cid_name));
		ast_channel_unlock(owner);
		ast_channel_unref(owner);

		e = sofia_push_park_create(pvt, callid, cid_num, cid_name, 1 /* inflight */);
		if (e) {
			ast_log(LOG_NOTICE, "Sofia PUSH: guard fired %s peer='%s' - no 1xx in %ds on a connection-oriented leg, pushed with the in-flight Call-ID\n",
				e->callid, e->peername, sofia_cfg.push_noresponse);
			sofia_push_log_event(e->peername, "", e->callid, "sent", "noresponse");
			ao2_ref(e, -1);
		}
	} else if (owner) {
		ast_channel_unref(owner);
	}
	ao2_ref(pvt, -1);	/* the arm-time ref */
	return 0;
}

/* Arm after the single-contact INVITE (PBX thread, channel lock held, no pvt/peer lock).
 * No-op unless: knob on, sched up, the peer has usable tokens, the target contact's
 * transport is connection-oriented, and the Call-ID was pre-generated. */
void sofia_push_guard_arm(struct sofia_pvt *pvt)
{
	char transport[8] = "";

	if (!pvt || sofia_cfg.push_noresponse <= 0 || !sofia_sched || !sofia_push_parked) {
		return;
	}
	if (!pvt->sip_callid[0] || !pvt->peer || !sofia_push_peer_pushable(pvt->peer)) {
		return;
	}
	if (pvt->active_contact) {
		ao2_lock(pvt->active_contact);
		ast_copy_string(transport, pvt->active_contact->transport, sizeof(transport));
		ao2_unlock(pvt->active_contact);
	}
	if (!sofia_push_transport_is_co(transport)) {
		return;		/* UDP: a dead peer does not black-hole silently the same way; out of P2 v1 scope */
	}
	ast_mutex_lock(&pvt->lock);
	if (pvt->push_guard_sched_id == -1 && !pvt->got_provisional) {
		ao2_ref(pvt, +1);
		pvt->push_guard_sched_id = ast_sched_thread_add(sofia_sched,
			sofia_cfg.push_noresponse * 1000, sofia_push_guard_cb, pvt);
		if (pvt->push_guard_sched_id < 0) {
			pvt->push_guard_sched_id = -1;
			ao2_ref(pvt, -1);	/* arm failed: guard silently off, the call keeps today's Timer-B bound */
		}
	}
	ast_mutex_unlock(&pvt->lock);
}

/* Any >=100 response on the in-flight INVITE (sofia_thread, no locks held): the leg is
 * alive. Disarm the guard and UNPARK a pending inflight entry — the old leg wins, no
 * swap will happen (rule agreed with the phone team). Also the 486-after-swap field
 * counter: a fast failure on a freshly swapped leg is the P2.1 tripwire. */
void sofia_push_guard_progress(struct sofia_pvt *pvt, int status)
{
	int sid;
	time_t swapped;

	if (!pvt || status < 100) {
		return;
	}
	ast_mutex_lock(&pvt->lock);
	pvt->got_provisional = 1;
	sid = pvt->push_guard_sched_id;
	pvt->push_guard_sched_id = -1;
	swapped = pvt->push_swapped_at;
	ast_mutex_unlock(&pvt->lock);
	if (sid > -1 && sofia_sched && ast_sched_thread_del(sofia_sched, sid) == 0) {
		ao2_ref(pvt, -1);	/* timer never ran */
	}
	if (status >= 300 && swapped && time(NULL) - swapped <= 10) {
		ast_log(LOG_NOTICE, "Sofia PUSH: new leg answered %d within 10s of an inflight swap - P2.1 field counter (old socket answered the phone?)\n",
			status);
		sofia_push_log_event(pvt->peername, "", pvt->sip_callid, "swap_fail", "");
	}
	if (sofia_push_parked) {
		struct ao2_iterator it = ao2_iterator_init(sofia_push_parked, 0);
		struct sofia_push_park *e;
		while ((e = ao2_iterator_next(&it))) {
			int won = 0;
			if (e->pvt == pvt && e->inflight) {
				ao2_lock(e);
				if (e->state == SOFIA_PUSH_PARKED) {
					e->state = SOFIA_PUSH_DONE;
					won = 1;
				}
				ao2_unlock(e);
				if (won) {
					sofia_push_park_cancel_timer(e);
					ast_verb(2, "Sofia PUSH: unparked %s peer='%s' - the in-flight leg progressed (%d), old leg wins\n",
						e->callid, e->peername, status);
					sofia_push_log_event(e->peername, "", e->callid, "unparked", "");
					ao2_unlink(sofia_push_parked, e);
				}
			}
			ao2_ref(e, -1);
		}
		ao2_iterator_destroy(&it);
	}
}

/* Disarm only (hangup entry / teardown): the registry entries themselves are cleaned by
 * sofia_push_on_pvt_hangup (which matches inflight entries too). Any thread, no locks. */
void sofia_push_guard_cancel(struct sofia_pvt *pvt)
{
	int sid;

	if (!pvt) {
		return;
	}
	ast_mutex_lock(&pvt->lock);
	sid = pvt->push_guard_sched_id;
	pvt->push_guard_sched_id = -1;
	ast_mutex_unlock(&pvt->lock);
	if (sid > -1 && sofia_sched && ast_sched_thread_del(sofia_sched, sid) == 0) {
		ao2_ref(pvt, -1);
	}
}

/* Park the call: registry entry + sender jobs + push_wait timer. PBX dialing
 * thread, CHANNEL lock held by ast_call (the serializer the resume path also takes).
 * Fail-closed: any piece missing -> -1 and the call fails exactly as today. */
int sofia_push_park_and_notify(struct sofia_pvt *pvt, struct ast_channel *ast)
{
	struct sofia_push_park *e;
	su_guid_t guid[1];
	static time_t last_cap_warn;

	if (!pvt || !ast || !sofia_push_parked || !sofia_sched) {
		return -1;
	}
	if (ao2_container_count(sofia_push_parked) >= SOFIA_PUSH_PARK_MAX_GLOBAL) {
		if (time(NULL) - last_cap_warn >= 60) {
			last_cap_warn = time(NULL);
			ast_log(LOG_WARNING, "Sofia PUSH: global parked-call cap (%d) hit - failing new parks as unrouteable\n",
				SOFIA_PUSH_PARK_MAX_GLOBAL);
		}
		return -1;
	}
	{
		/* per-peer cap: bounded walk of this hash key's entries */
		struct ao2_iterator it = ao2_iterator_init(sofia_push_parked, 0);
		struct sofia_push_park *o;
		int mine = 0;
		while ((o = ao2_iterator_next(&it))) {
			if (!strcasecmp(o->peername, pvt->peername)) {
				mine++;
			}
			ao2_ref(o, -1);
		}
		ao2_iterator_destroy(&it);
		if (mine >= SOFIA_PUSH_PARK_MAX_PER_PEER) {
			ast_log(LOG_NOTICE, "Sofia PUSH: peer '%s' already has %d parked call(s) - failing this one\n",
				pvt->peername, mine);
			return -1;
		}
	}

	/* Publish the pre-generated Call-ID on the pvt first (resume + CLI + P2 read it
	 * there); sofia_call may have pre-generated it already for the P2 guard. */
	ast_mutex_lock(&pvt->lock);
	if (!pvt->sip_callid[0]) {
		su_guid_generate(guid);
		su_guid_sprintf(pvt->sip_callid, sizeof(pvt->sip_callid), guid);
	}
	ast_mutex_unlock(&pvt->lock);

	e = sofia_push_park_create(pvt, pvt->sip_callid,
		S_OR(ast->caller.id.number.str, "unknown"),	/* channel lock held by ast_call */
		S_OR(ast->caller.id.name.str, S_OR(ast->caller.id.number.str, "unknown")),
		0 /* not inflight: no INVITE exists yet */);
	if (!e) {
		return -1;
	}

	ast_verb(2, "Sofia PUSH: parked call %s peer='%s' from %s wait %ds\n",
		e->callid, e->peername, e->cid_num, sofia_cfg.push_wait);
	sofia_push_log_event(e->peername, "", e->callid, "parked", e->cid_num);

	/* Commit-then-recheck: a REGISTER that bound between sofia_request_call's contact
	 * scan and the entry link above found NO entry to resume. Re-scan once now that the
	 * entry is published; if a live contact appeared, resume it ourselves — this is the
	 * PBX dialing thread, the same inline nua_invite context sofia_call uses, and the
	 * channel lock ast_call holds is recursive, so resume_one's own channel_lock nests. */
	if (pvt->peer) {
		int nu = 0, nt = 0;
		struct sofia_contact *lc = sofia_peer_select_single_live_contact(pvt->peer, &nu, &nt);
		if (lc) {
			ao2_ref(lc, -1);
			sofia_push_resume_one(e, pvt->peer, NULL);
		}
	}
	ao2_ref(e, -1);		/* alloc ref: container + timer hold the entry now */
	return 0;
}

/* Caller hangup / Dial-timeout reaping of a parked pvt. PBX thread, NO locks held (called
 * from sofia_hangup after pvt->lock is released; the caller still holds a pvt ref). */
void sofia_push_on_pvt_hangup(struct sofia_pvt *pvt)
{
	struct ao2_iterator it;
	struct sofia_push_park *e;

	if (!sofia_push_parked || !pvt) {
		return;
	}
	it = ao2_iterator_init(sofia_push_parked, 0);
	while ((e = ao2_iterator_next(&it))) {
		int won = 0;
		if (e->pvt == pvt) {
			ao2_lock(e);
			if (e->state == SOFIA_PUSH_PARKED) {
				e->state = SOFIA_PUSH_DONE;
				won = 1;
			}
			ao2_unlock(e);
			if (won) {
				sofia_push_park_cancel_timer(e);
				ast_verb(2, "Sofia PUSH: cancelled %s peer='%s' (caller hangup)\n",
					e->callid, e->peername);
				sofia_push_log_event(e->peername, "", e->callid, "caller_hangup", "");
				ao2_unlink(sofia_push_parked, e);
			}
			/* RESUMING/DONE: the owner of that transition cleans up; nothing here. */
		}
		ao2_ref(e, -1);
	}
	ao2_iterator_destroy(&it);
}

/* ---------- resume (the ts_append moment): deliver parked calls on a wake REGISTER ----------
 *
 * sofia_thread (REGISTER tail), peer->lock NOT held, the 200 OK already queued. The
 * commit runs UNDER THE CHANNEL LOCK — the same serializer ast_call gives sofia_call —
 * so a racing sofia_hangup (core holds the channel lock across it) is structurally
 * excluded: whoever takes the lock first wins and the loser sees the changed state. */
static void sofia_push_resume_one(struct sofia_push_park *e, struct sofia_peer *peer,
	const struct sofia_register_update *update)
{
	struct sofia_pvt *pvt = e->pvt;
	struct ast_channel *owner = NULL;
	struct sofia_contact *c = NULL;
	nua_handle_t *nh = NULL;
	char url[256] = "", path_buf[1024] = "", route_buf[256] = "", sr_buf[1024] = "";
	char contact_proxy_url[128] = "";
	int peer_gruu = 0, rc = -1;
	struct ast_sockaddr target;
	time_t waited = time(NULL) - e->parked_at;

	/* The freshly bound contact FIRST (by the REGISTER's learned source, else the
	 * single-live selector). No contact yet -> leave the entry PARKED: the push_wait
	 * timer stays armed as the safety net and a later REGISTER retries. */
	if (update && !ast_sockaddr_isnull(&update->new_src)) {
		c = sofia_peer_find_contact_by_addr(peer, &update->new_src);
	}
	if (!c) {
		int nu = 0, nt = 0;
		c = sofia_peer_select_single_live_contact(peer, &nu, &nt);
	}
	if (!c || !pvt || !sofia_nua) {
		if (c) {
			ao2_ref(c, -1);
		}
		return;
	}

	/* Claim: PARKED -> RESUMING (exactly one winner), then disarm the timer. */
	ao2_lock(e);
	if (e->state != SOFIA_PUSH_PARKED) {
		ao2_unlock(e);
		ao2_ref(c, -1);
		return;
	}
	e->state = SOFIA_PUSH_RESUMING;
	ao2_unlock(e);
	sofia_push_park_cancel_timer(e);

	/* Owner snapshot+ref under pvt->lock; the commit itself under the channel lock. */
	ast_mutex_lock(&pvt->lock);
	owner = pvt->owner;
	if (owner) {
		ast_channel_ref(owner);
	}
	ast_mutex_unlock(&pvt->lock);
	if (!owner) {
		goto orphan;	/* caller hung up racing the wake */
	}
	ast_channel_lock(owner);
	ast_mutex_lock(&pvt->lock);
	if (e->inflight) {
		/* P2 swap: an INVITE is ALREADY on the wire. Swap ONLY if the old leg showed no
		 * progress (rule agreed with the phone team: any >=100 means the old leg wins —
		 * normally guard_progress already unparked us; this is the race-safe recheck). */
		nua_handle_t *old_nh;
		if (pvt->owner != owner || !pvt->nh || pvt->got_provisional) {
			ast_mutex_unlock(&pvt->lock);
			ast_channel_unlock(owner);
			ast_channel_unref(owner);
			owner = NULL;
			goto orphan;
		}
		old_nh = pvt->nh;
		pvt->nh = NULL;
		pvt->push_swapped_at = time(NULL);
		ast_mutex_unlock(&pvt->lock);
		/* Unbind FIRST, synchronously: from this instant a late 408/487/200 on the old
		 * leg carries a NULL magic and can never validate against this live pvt (the
		 * dispatch gate skips it); then destroy on sofia_thread — nua completes the old
		 * client transaction internally, nothing goes on the wire (a CANCEL with no 1xx
		 * would be deferred and never leave the box anyway, RFC 3261 §9.1). */
		nua_handle_bind(old_nh, NULL);
		sofia_nh_destroy_async(old_nh);
		ast_verb(2, "Sofia PUSH: inflight swap %s peer='%s' - old leg unbound+destroyed, re-posting to the fresh binding\n",
			e->callid, e->peername);
	} else if (pvt->owner != owner || pvt->nh || !pvt->push_parked) {
		ast_mutex_unlock(&pvt->lock);
		ast_channel_unlock(owner);
		ast_channel_unref(owner);
		owner = NULL;
		goto orphan;	/* hangup/masquerade won between snapshot and lock */
	} else {
		ast_mutex_unlock(&pvt->lock);
	}

	/* Builders: routes/gruu under peer->lock; RURI+Path from the contact (contact lock
	 * only, sofia_build_contact_ruri takes it); NAT proxy helper takes peer+contact
	 * locks itself; then re-aim our egress IP at the real binding (IP literal target —
	 * kernel route lookup only, no DNS). Mirrors sofia_request_call 7246-7343. */
	{
		int path_support;
		ast_mutex_lock(&peer->lock);
		path_support = peer->path_support;
		sofia_format_outboundproxy(peer, route_buf, sizeof(route_buf));
		if (peer->use_service_route && peer->registered) {
			ast_copy_string(sr_buf, peer->service_route, sizeof(sr_buf));
		}
		peer_gruu = peer->gruu;
		ast_mutex_unlock(&peer->lock);
		sofia_build_contact_ruri(c, pvt->exten, url, sizeof(url), path_support, path_buf, sizeof(path_buf));
	}
	sofia_build_contact_proxy_url(peer, c, contact_proxy_url, sizeof(contact_proxy_url));
	ao2_lock(c);
	target = c->src_addr;
	ao2_unlock(c);
	if (!ast_sockaddr_isnull(&target)) {
		sofia_resolve_ourip(pvt, &target);
	}

	nh = nua_handle(sofia_nua, pvt,
		NUTAG_URL(url),
		SIPTAG_TO_STR(url),
		TAG_IF(route_buf[0], NUTAG_INITIAL_ROUTE_STR(route_buf)),
		TAG_IF(sr_buf[0], NUTAG_INITIAL_ROUTE_STR(sr_buf)),
		TAG_IF(path_buf[0], NUTAG_INITIAL_ROUTE_STR(path_buf)),
		TAG_IF(peer_gruu, NUTAG_SUPPORTED("gruu")),
		TAG_END());	/* mirror of sofia_request_call 7331-7343 */
	if (!nh) {
		ast_channel_unlock(owner);
		goto fail_call;
	}
	ast_mutex_lock(&pvt->lock);
	pvt->nh = nh;	/* hangup (6262+) and the destructor read nh under pvt->lock */
	ast_string_field_set(pvt, ruri, url);
	if (contact_proxy_url[0]) {
		ast_string_field_set(pvt, outbound_proxy, contact_proxy_url);
	}
	pvt->push_parked = 0;
	ast_mutex_unlock(&pvt->lock);
	sofia_pvt_set_active_contact(pvt, c);	/* in-dialog routing + call accounting */

	rc = sofia_post_invite(pvt, owner, e->callid);	/* the SAME builder sofia_call uses; Call-ID = the push uuid */
	ast_channel_unlock(owner);
	if (rc) {
		goto fail_call;
	}
	ast_channel_unref(owner);
	ao2_ref(c, -1);
	ast_verb(2, "Sofia PUSH: resumed %s peer='%s' -> INVITE to the fresh binding after %lds parked\n",
		e->callid, e->peername, (long) waited);
	sofia_push_log_event(e->peername, "", e->callid, "resumed", "");
	ao2_lock(e);
	e->state = SOFIA_PUSH_DONE;
	ao2_unlock(e);
	if (sofia_push_parked) {
		ao2_unlink(sofia_push_parked, e);
	}
	return;

fail_call:
	/* Claimed but could not deliver (handle/provisioning failure): the call must not
	 * dangle — NOANSWER it, outside every lock (the queue takes the channel lock). */
	if (owner) {
		ast_channel_unref(owner);
	}
	{
		struct ast_channel *o2 = NULL;
		ast_mutex_lock(&pvt->lock);
		o2 = pvt->owner;
		if (o2) {
			ast_channel_ref(o2);
		}
		ast_mutex_unlock(&pvt->lock);
		if (o2) {
			ast_queue_hangup_with_cause(o2, AST_CAUSE_NO_ANSWER);
			ast_channel_unref(o2);
		}
	}
	ast_log(LOG_WARNING, "Sofia PUSH: resume of %s peer='%s' failed - call ends NOANSWER\n",
		e->callid, e->peername);
	sofia_push_log_event(e->peername, "", e->callid, "orphaned", "resume_failed");
	goto done;

orphan:
	ast_verb(2, "Sofia PUSH: resume of %s peer='%s' aborted - caller already gone\n",
		e->callid, e->peername);
	sofia_push_log_event(e->peername, "", e->callid, "orphaned", "caller_gone");
done:
	if (c) {
		ao2_ref(c, -1);
	}
	ao2_lock(e);
	e->state = SOFIA_PUSH_DONE;
	ao2_unlock(e);
	if (sofia_push_parked) {
		ao2_unlink(sofia_push_parked, e);
	}
}

/* Scan-and-resume every parked call of this peer. Runs for ANY successful REGISTER of
 * the account (with or without push headers — a desk phone binding delivers the call
 * too, Kamailio ts_append parity), and even if push= was just turned off: delivering an
 * already-parked call is strictly correct. */
static void sofia_push_try_resume(struct sofia_peer *peer, const struct sofia_register_update *update)
{
	struct ao2_iterator it;
	struct sofia_push_park *pe;
	int logged = 0;

	if (!sofia_push_parked || !peer) {
		return;
	}
	it = ao2_iterator_init(sofia_push_parked, 0);
	while ((pe = ao2_iterator_next(&it))) {
		if (!strcasecmp(pe->peername, peer->name)) {
			if (!logged++) {
				sofia_push_log_event(peer->name, "", "", "registered", "wake");
			}
			sofia_push_resume_one(pe, peer, update);
		}
		ao2_ref(pe, -1);
	}
	ao2_iterator_destroy(&it);
}

/* ---------- REGISTER capture (sofia_thread; peer->lock NOT held; sip may be NULL) ---------- */

static void sofia_push_capture(struct sofia_peer *peer, sip_t const *sip,
	const struct sofia_register_update *update)
{
	const char *dev = NULL, *tok = NULL, *plat = NULL, *type = NULL;
	sip_unknown_t const *u;
	int req;
	char redact[64];

	if (!peer || !sip || !update || !sofia_push_cache) {
		return;		/* flow-close caller passes sip=NULL: nothing to capture */
	}
	if (!sofia_push_peer_enabled(peer)) {
		return;		/* master off or per-peer push=no: store nothing (privacy) */
	}

	for (u = sip->sip_unknown; u; u = u->un_next) {
		if (!u->un_name || !u->un_value) {
			continue;
		}
		if (!strcasecmp(u->un_name, "X-Device-ID")) {
			dev = u->un_value;
		} else if (!strcasecmp(u->un_name, "X-Push-Token")) {
			tok = u->un_value;
		} else if (!strcasecmp(u->un_name, "X-Push-Platform")) {
			plat = u->un_value;
		} else if (!strcasecmp(u->un_name, "X-Push-Type")) {
			type = u->un_value;
		}
	}

	/* Requested expiry: Contact ;expires= wins over the Expires header (RFC 3261 §10.2.1);
	 * only the 0 vs >0 distinction matters for the retention rules. */
	if (sip->sip_contact) {
		req = sofia_contact_requested_expiry(sip->sip_contact,
			sip->sip_expires ? (int) sip->sip_expires->ex_delta : 3600);
	} else if (sip->sip_expires) {
		req = (int) sip->sip_expires->ex_delta;
	} else {
		req = 3600;
	}

	if (req == 0) {
		/* Unregister: delete ONLY when X-Device-ID names the device (web-phone logout).
		 * The mobile app strips the X-* headers on logout ON PURPOSE: its token must
		 * survive so a later push can still wake it. */
		if (dev && sofia_push_devid_valid(dev)) {
			struct sofia_push_tokens *e = sofia_push_entry_get(peer->name, 0);
			if (e) {
				if (sofia_push_cache_delete(e, dev)) {
					struct sofia_pushdb_job j = { .kind = PUSHDB_DELETE };
					ast_copy_string(j.peer, peer->name, sizeof(j.peer));
					ast_copy_string(j.device_id, dev, sizeof(j.device_id));
					sofia_pushdb_queue(&j);
					sofia_push_log_event(peer->name, dev, "", "dead_token", "unregister");
					ast_verb(3, "Sofia PUSH: token deleted on unregister peer='%s' dev='%s'\n",
						peer->name, dev);
				}
				ao2_ref(e, -1);
			}
		}
		return;
	}

	if (!tok) {
		return;		/* desk phone / trunk: no push header, nothing to do */
	}
	if (!sofia_push_token_valid(tok)) {
		ast_log(LOG_WARNING, "Sofia PUSH: rejecting malformed X-Push-Token from peer '%s' (len=%zu)\n",
			peer->name, strlen(tok));
		return;
	}

	{
		struct sofia_push_device d;
		struct sofia_push_tokens *e;
		struct sofia_pushdb_job j = { .kind = PUSHDB_UPSERT };
		time_t now = time(NULL);
		int is_voip;

		memset(&d, 0, sizeof(d));
		is_voip = type ? !strcasecmp(type, "voip") : sofia_push_token_is_voip(tok);
		ast_copy_string(d.push_type, is_voip ? "voip" : "fcm", sizeof(d.push_type));
		if (plat && (!strcasecmp(plat, "ios") || !strcasecmp(plat, "android"))) {
			ast_copy_string(d.platform, plat, sizeof(d.platform));
		} else {
			ast_copy_string(d.platform, is_voip ? "ios" : "android", sizeof(d.platform));
		}
		/* Device key: X-Device-ID, else the platform name (Kamailio fallback for old builds). */
		if (dev && sofia_push_devid_valid(dev)) {
			ast_copy_string(d.device_id, dev, sizeof(d.device_id));
		} else {
			ast_copy_string(d.device_id, d.platform, sizeof(d.device_id));
		}
		ast_copy_string(d.token, tok, sizeof(d.token));
		if (sip->sip_contact) {
			int reg_id = 0;
			sofia_contact_parse_instance(sip->sip_contact, d.instance, sizeof(d.instance), &reg_id);
		}
		if (sip->sip_user_agent && sip->sip_user_agent->g_string) {
			ast_copy_string(d.user_agent, sip->sip_user_agent->g_string, sizeof(d.user_agent));
		}
		d.updated_at = now;
		d.reg_expires = now + (update->new_expires > 0 ? update->new_expires : req);
		d.fail_count = 0;

		if (!(e = sofia_push_entry_get(peer->name, 1))) {
			return;
		}
		sofia_push_cache_upsert(e, &d);
		ao2_ref(e, -1);

		ast_copy_string(j.peer, peer->name, sizeof(j.peer));
		ast_copy_string(j.device_id, d.device_id, sizeof(j.device_id));
		ast_copy_string(j.platform, d.platform, sizeof(j.platform));
		ast_copy_string(j.push_type, d.push_type, sizeof(j.push_type));
		ast_copy_string(j.token, d.token, sizeof(j.token));
		ast_copy_string(j.instance, d.instance, sizeof(j.instance));
		ast_copy_string(j.user_agent, d.user_agent, sizeof(j.user_agent));
		j.updated_at = d.updated_at;
		j.reg_expires = d.reg_expires;
		sofia_pushdb_queue(&j);

		ast_verb(3, "Sofia PUSH: token upsert peer='%s' dev='%s' plat=%s type=%s token=%s exp=+%lds\n",
			peer->name, d.device_id, d.platform, d.push_type,
			sofia_push_redact(d.token, redact, sizeof(redact)),
			(long) (d.reg_expires - now));
	}

}

/* Entry point from sofia_emit_register_side_effects (both auth branches + flow-close). */
void sofia_push_on_register(struct sofia_peer *peer, sip_t const *sip,
	const struct sofia_register_update *update)
{
	if (!peer || !update) {
		return;
	}
	if (sip) {	/* flow-close passes sip=NULL: nothing to capture, nothing to wake */
		sofia_push_capture(peer, sip, update);
		if (!update->emit_unregister && update->now_registered) {
			sofia_push_try_resume(peer, update);
		}
	}
}

/* ---------- CLI: sip show push [peer] (tokens ALWAYS redacted) ---------- */

static char *sofia_push_cli_show(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	const char *filter = NULL;
	struct ao2_iterator it;
	time_t now = time(NULL);
	int shown = 0;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show push";
		e->usage = "Usage: sip show push [peer]\n"
			"       Mobile push wake-up: cached tokens (redacted) + parked calls.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}
	if (a->argc > 4) {
		return CLI_SHOWUSAGE;
	}
	if (a->argc == 4) {
		filter = a->argv[3];
	}
	ast_cli(a->fd, "Push wake-up: %s  scripts=%s  wait=%ds  noresponse=%ds  ttl=%dd  max_devices=%d  min_interval=%ds  cache=%s  queue=%d\n",
		sofia_cfg.push_enabled ? "ENABLED" : "disabled",
		sofia_cfg.push_scripts, sofia_cfg.push_wait, sofia_cfg.push_noresponse,
		sofia_cfg.push_token_ttl_days,
		sofia_cfg.push_max_devices, sofia_cfg.push_min_interval,
		sofia_push_cache_complete ? "complete" : "lazy", sofia_pushdb_depth);
	if (!sofia_push_cache) {
		return CLI_SUCCESS;
	}
	ast_cli(a->fd, "%-20s %-14s %-7s %-5s %-22s %8s %8s %-14s %5s\n",
		"Peer", "Device", "Plat", "Type", "Token", "Age", "RegExp", "LastResult", "Fails");
	it = ao2_iterator_init(sofia_push_cache, 0);
	{
		struct sofia_push_tokens *te;
		while ((te = ao2_iterator_next(&it))) {
			int i;
			if (filter && strcasecmp(te->peername, filter)) {
				ao2_ref(te, -1);
				continue;
			}
			ao2_lock(te);
			for (i = 0; i < te->ndev; i++) {
				char red[64];
				ast_cli(a->fd, "%-20s %-14s %-7s %-5s %-22s %7lds %7lds %-14s %5d\n",
					te->peername, te->dev[i].device_id, te->dev[i].platform,
					te->dev[i].push_type,
					sofia_push_redact(te->dev[i].token, red, sizeof(red)),
					(long) (now - te->dev[i].updated_at),
					(long) (te->dev[i].reg_expires - now),
					te->dev[i].last_result[0] ? te->dev[i].last_result : "-",
					te->dev[i].fail_count);
				shown++;
			}
			ao2_unlock(te);
			ao2_ref(te, -1);
		}
	}
	ao2_iterator_destroy(&it);
	ast_cli(a->fd, "%d token(s)\n", shown);
	if (sofia_push_parked) {
		struct sofia_push_park *pe;
		int parked = 0;
		it = ao2_iterator_init(sofia_push_parked, 0);
		while ((pe = ao2_iterator_next(&it))) {
			if (!filter || !strcasecmp(pe->peername, filter)) {
				const char *st;
				ao2_lock(pe);
				st = pe->state == SOFIA_PUSH_PARKED ? "PARKED"
					: pe->state == SOFIA_PUSH_RESUMING ? "RESUMING" : "DONE";
				ast_cli(a->fd, "parked: %-20s %s %s age=%lds from=%s pushed=%d\n",
					pe->peername, pe->callid, st,
					(long) (now - pe->parked_at), pe->cid_num, pe->npushed);
				ao2_unlock(pe);
				parked++;
			}
			ao2_ref(pe, -1);
		}
		ao2_iterator_destroy(&it);
		ast_cli(a->fd, "%d parked call(s)\n", parked);
	}
	return CLI_SUCCESS;
}

static struct ast_cli_entry sofia_push_cli[] = {
	AST_CLI_DEFINE(sofia_push_cli_show, "Show push wake-up tokens and parked calls"),
};

/* ---------- init (called from load_module, before the channel tech registers) ---------- */

int sofia_push_init(void)
{
	struct ast_config *cfg;

	sofia_push_cache = ao2_container_alloc(563, sofia_push_tokens_hash, sofia_push_tokens_cmp);
	if (!sofia_push_cache) {
		ast_log(LOG_WARNING, "Sofia PUSH: cache alloc failed - push wake-up disabled\n");
		return -1;	/* non-fatal: the driver runs, push is just off */
	}
	sofia_push_parked = ao2_container_alloc(89, sofia_push_park_hash, sofia_push_park_cmp);
	if (!sofia_push_parked) {
		ast_log(LOG_WARNING, "Sofia PUSH: parked-call registry alloc failed - parking disabled (calls fail as today)\n");
	}
	sofia_pushdb_tps = ast_taskprocessor_get("sofia/pushdb", TPS_REF_DEFAULT);
	if (!sofia_pushdb_tps) {
		ast_log(LOG_WARNING, "Sofia PUSH: pushdb taskprocessor unavailable - token persistence disabled (cache-only)\n");
	}
	sofia_push_tps = ast_taskprocessor_get("sofia/push", TPS_REF_DEFAULT);
	if (!sofia_push_tps) {
		ast_log(LOG_WARNING, "Sofia PUSH: sender taskprocessor unavailable - pushes disabled (parks would be silent, so parking disables too)\n");
	}
	ast_cli_register_multiple(sofia_push_cli, ARRAY_LEN(sofia_push_cli));

	/* Preload the whole table (it only holds mobile devices) so the dial path never
	 * reads the DB: a complete-cache miss IS the answer. Engine/family missing or the
	 * read failing -> lazy mode with negative entries, one NOTICE, no per-call spam. */
	if (!ast_check_realtime("pushtokens")) {
		ast_log(LOG_NOTICE, "Sofia PUSH: realtime family 'pushtokens' not configured - lazy token loads (enable res_config_sqlite3 + extconfig for preload)\n");
		return 0;
	}
	cfg = ast_load_realtime_multientry("pushtokens", "peer LIKE", "%", SENTINEL);
	if (cfg) {
		char *cat = NULL;
		int nrows = 0, npeers = 0;
		while ((cat = ast_category_browse(cfg, cat))) {	/* pointer-idiom: duplicate names OK (config.c:586) */
			struct sofia_push_device d;
			const struct ast_variable *v = ast_variable_browse(cfg, cat);
			const struct ast_variable *pv;
			char peername[128] = "";
			for (pv = v; pv; pv = pv->next) {
				if (!strcasecmp(pv->name, "peer")) {
					ast_copy_string(peername, pv->value, sizeof(peername));
					break;
				}
			}
			sofia_push_device_from_vars(&d, v);
			if (peername[0] && d.device_id[0] && d.token[0]) {
				struct sofia_push_tokens *e = sofia_push_entry_get(peername, 1);
				if (e) {
					if (!e->loaded_from_db) {
						e->loaded_from_db = 1;
						npeers++;
					}
					sofia_push_cache_upsert(e, &d);
					ao2_ref(e, -1);
					nrows++;
				}
			}
		}
		ast_config_destroy(cfg);
		sofia_push_cache_complete = 1;
		ast_verb(2, "Sofia PUSH: preloaded %d token(s) for %d peer(s) - cache COMPLETE\n", nrows, npeers);
	} else {
		/* NULL = empty table OR read failure; ast_check_realtime passed, so treat as
		 * empty and stay complete (a real engine failure would have failed the probe). */
		sofia_push_cache_complete = 1;
		ast_verb(2, "Sofia PUSH: token table empty - cache COMPLETE\n");
	}
	return 0;
}
