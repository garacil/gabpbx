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
#include "gabpbx/callerid.h"	/* AST_PRES_* (push caller presentation) */
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

#ifndef SOFIA_PUSH_MAX_DEVICES
#define SOFIA_PUSH_MAX_DEVICES 10	/* hard array bound; the knob clamps to this */
#endif
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
	int cancelled;			/* a call_cancel went out after the last push: its card is gone, so the next call pushes even inside push_min_interval (cache only) */
	time_t hold_push_at;		/* =hold only: last_push_at and cancelled as they were before the REGISTER the push made, which resets */
	int hold_cancelled;		/* those two; kept across that REGISTER (cache only), read by sofia_push_live_held alone */
	time_t rereg_for;		/* the reg_expires a re-register push was queued for in this run (cache only; after a restart last_push_at says it went) */
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
	PUSHDB_LASTPUSH,	/* last_push_at only (a re-register push: nothing else of the row is touched) */
	PUSHDB_FAILCOUNT,	/* fail_count only (a push_wait timeout) */
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
	case PUSHDB_LASTPUSH:
		snprintf(lpush_s, sizeof(lpush_s), "%ld", (long) j->last_push_at);
		ast_update2_realtime("pushtokens",
			"peer", j->peer, "device_id", j->device_id, SENTINEL,
			"last_push_at", lpush_s, SENTINEL);
		break;
	case PUSHDB_FAILCOUNT:
		snprintf(fc_s, sizeof(fc_s), "%d", j->fail_count);
		ast_update2_realtime("pushtokens",
			"peer", j->peer, "device_id", j->device_id, SENTINEL,
			"fail_count", fc_s, SENTINEL);
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
static int sofia_pushdb_queue(const struct sofia_pushdb_job *src)
{
	struct sofia_pushdb_job *j;
	static time_t last_warn;

	if (!sofia_pushdb_tps) {
		return -1;
	}
	if (ast_atomic_fetchadd_int(&sofia_pushdb_depth, +1) >= SOFIA_PUSH_DBQ_MAX) {
		ast_atomic_fetchadd_int(&sofia_pushdb_depth, -1);
		if (time(NULL) - last_warn >= 60) {
			last_warn = time(NULL);
			ast_log(LOG_WARNING, "Sofia PUSH: pushdb queue cap (%d) hit - dropping DB write (cache stays authoritative)\n",
				SOFIA_PUSH_DBQ_MAX);
		}
		return -1;
	}
	if (!(j = ast_calloc(1, sizeof(*j)))) {
		ast_atomic_fetchadd_int(&sofia_pushdb_depth, -1);
		return -1;
	}
	*j = *src;
	if (ast_taskprocessor_push(sofia_pushdb_tps, sofia_pushdb_exe, j) < 0) {
		ast_atomic_fetchadd_int(&sofia_pushdb_depth, -1);
		ast_free(j);
		return -1;
	}
	return 0;
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

/* Upsert one device into the entry (entry lock). Evicts the oldest device at the cap.
 *
 * TOKEN COLLAPSE (operator-approved 2026-09-07): after the upsert, any OTHER row holding
 * the IDENTICAL token is the SAME handset re-keyed and is removed. The invariant comes
 * straight from the official Apple/Google docs: an APNs/PushKit or FCM token identifies
 * ONE app installation - never two handsets. Without this, a client that drops
 * X-Device-ID mid-session (phone bug 4(a), fixed in build 107) re-keys itself under the
 * platform-name fallback and the handset ends up with TWO live rows = two pushes per
 * call, un-cleanable by either the logout delete (keyed to one device_id) or the 410
 * purge (both rows carry the same LIVE token, so no error ever comes back). Last write
 * wins: the newest REGISTER is the installation's authoritative row. DB deletes + log
 * rows are queued OUTSIDE the entry lock (leaf-lock discipline). */
/* A device that is pushed even when it has a live binding: an APNs VoIP token (iOS PushKit) with push_voip_live on.
 * iOS suspends an app in the background and its open socket can stay up meanwhile, so a live binding is no
 * knowledge that the app is awake (RFC 8599 §1, §5.6.2: a proxy skips the push only with "knowledge that the UA is
 * awake"); a VoIP push makes the app report the call to CallKit (Apple PushKit: every VoIP push must be reported),
 * with the push uuid = the Call-ID of the INVITE the binding gets, so the app keeps one call. An FCM (Android) device
 * with a live binding is pushed in the same way with push_fcm_live=yes: an Android app can also keep its socket while
 * the system no longer lets it show the call. (=hold does not push it here: such a device is left out of the live
 * bindings and pushed as an asleep one, sofia_push_live_held.) Cache entry lock held (or a snapshot). */
static int sofia_push_device_pushed_when_live(const struct sofia_push_device *d)
{
	return (sofia_cfg.push_voip_live == 1 && !strcasecmp(d->push_type, "voip"))
		|| (sofia_cfg.push_fcm_live == 1 && !strcasecmp(d->push_type, "fcm"));
}

/* push_hold_exclude: 1 when the device's X-Device-ID or +sip.instance is in the [general] list (comma or blank
 * separated, case-insensitive; an instance matches with or without its "urn:uuid:" prefix, angle brackets and double
 * quotes, as copied from a Contact). Such a device is never held: its
 * VoIP pushes never make it REGISTER (an iOS app on a Mac: macOS drops them), so holding its INVITE would lose every
 * call to it. Reads sofia_cfg only (set at load/reload). */
static int sofia_push_hold_excluded(const struct sofia_push_device *d)
{
	char list[sizeof(sofia_cfg.push_hold_exclude)];
	char *cur, *tok;
	const char *inst = d->instance;

	if (!sofia_cfg.push_hold_exclude[0]) {
		return 0;
	}
	if (!strncasecmp(inst, "<urn:uuid:", 10)) {
		inst += 10;
	} else if (!strncasecmp(inst, "urn:uuid:", 9)) {
		inst += 9;
	}
	ast_copy_string(list, sofia_cfg.push_hold_exclude, sizeof(list));
	cur = list;
	while ((tok = strsep(&cur, ", \t"))) {
		size_t n;

		if (*tok == '"') {
			tok++;
		}
		if (*tok == '<') {
			tok++;
		}
		if (!strncasecmp(tok, "urn:uuid:", 9)) {
			tok += 9;
		}
		n = strlen(tok);
		if (n && tok[n - 1] == '"') {
			tok[--n] = '\0';
		}
		if (n && tok[n - 1] == '>') {
			tok[--n] = '\0';
		}
		if (!n) {
			continue;
		}
		if (!strcasecmp(tok, d->device_id)
				|| (inst[0] && (!strcasecmp(tok, inst) || (!strncasecmp(inst, tok, n) && inst[n] == '>')))) {
			return 1;
		}
	}
	return 0;
}

/* push_fcm_live=hold / push_voip_live=hold (RFC 8599 §5.6.2, the push bucket): the proxy pushes for every initial
 * request and forwards it only after the 2xx to the REGISTER the push triggers, to that REGISTER's binding. A live
 * binding is no proof that the app reads its socket (an iOS app may be frozen on a socket the NAT dropped long ago, an
 * Android one may not be allowed to show the call). Such a device (FCM, or APNs VoIP) with a live binding is then
 * treated as an asleep one: its binding is left out of the call's first fork (sofia_call), it is pushed,
 * and the existing wake path sends it the INVITE on the binding of its REGISTER (late append, or the resume of a parked
 * call), with the push's Call-ID; push_wait bounds the wait and the call_cancel push follows a call that ends first.
 * Only when the push will go out: a usable token of that type for that +sip.instance, outside push_min_interval (unless a
 * call_cancel went out since); otherwise the binding gets its INVITE as before, so the device is never left without
 * the call: within push_min_interval of its last push (hold_push_at, kept across the REGISTER that push may have made,
 * sofia_push_cache_upsert) it gets the INVITE on its binding (woken: the binding it has just refreshed; not woken: a
 * second push would be dropped). A timer refresh REGISTER alone proves nothing (RFC 8599 §4.1.4 NOTE: the UA may still
 * be suspended). Any thread; takes the cache container lock and then the entry lock (leaves). */
int sofia_push_live_held(struct sofia_peer *peer, const char *instance)
{
	struct sofia_push_tokens *e;
	time_t now = time(NULL);
	int i, held = 0;

	if ((sofia_cfg.push_fcm_live != 2 && sofia_cfg.push_voip_live != 2) || !peer || !instance || !instance[0]
			|| !sofia_push_peer_enabled(peer)
			|| !(e = sofia_push_entry_get(peer->name, 0))) {
		return 0;
	}
	ao2_lock(e);
	for (i = 0; i < e->ndev; i++) {
		struct sofia_push_device *d = &e->dev[i];

		if (!d->instance[0] || strcasecmp(d->instance, instance)) {
			continue;
		}
		held = ((sofia_cfg.push_fcm_live == 2 && !strcasecmp(d->push_type, "fcm"))
				|| (sofia_cfg.push_voip_live == 2 && !strcasecmp(d->push_type, "voip")))
			&& d->token[0] && !sofia_push_device_stale(d, now)
			&& (sofia_cfg.push_min_interval <= 0 || d->hold_cancelled
				|| d->hold_push_at <= now - sofia_cfg.push_min_interval)
			&& !sofia_push_hold_excluded(d);
		break;
	}
	ao2_unlock(e);
	ao2_ref(e, -1);
	return held;
}

static void sofia_push_cache_upsert(struct sofia_push_tokens *e, const struct sofia_push_device *nd)
{
	int i, slot = -1, oldest = 0;
	char collapsed[SOFIA_PUSH_MAX_DEVICES][SOFIA_PUSH_DEVID_MAX];
	int ncollapsed = 0;

	time_t kept_hold_push_at = 0;
	int kept_hold_cancelled = 0;

	ao2_lock(e);
	for (i = 0; i < e->ndev; i++) {
		if (!strcasecmp(e->dev[i].device_id, nd->device_id)) {
			slot = i;
			/* The same device REGISTERing again keeps the =hold copy of its push stamp (cache only; the rate
			 * limit's own last_push_at / cancelled reset with the REGISTER, as always): within push_min_interval
			 * of a push the device is not held again (sofia_push_live_held). */
			kept_hold_push_at = e->dev[i].hold_push_at;
			kept_hold_cancelled = e->dev[i].hold_cancelled;
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
	{
		int same = !strcasecmp(e->dev[slot].device_id, nd->device_id);

		e->dev[slot] = *nd;
		if (same) {
			if (kept_hold_push_at > e->dev[slot].hold_push_at) {
				e->dev[slot].hold_push_at = kept_hold_push_at;
			}
			e->dev[slot].hold_cancelled = kept_hold_cancelled;
		}
	}

	/* Collapse duplicate-token rows (same installation under another key). Tokens are
	 * case-sensitive (FCM is base64url) -> strcmp, not strcasecmp. Swap-with-last removal;
	 * do not advance on removal (the swapped-in row still needs checking), and track the
	 * slot if the tail row we just wrote gets moved. */
	if (nd->token[0]) {
		i = 0;
		while (i < e->ndev) {
			if (i != slot && !strcmp(e->dev[i].token, nd->token)) {
				if (ncollapsed < SOFIA_PUSH_MAX_DEVICES) {
					ast_copy_string(collapsed[ncollapsed++], e->dev[i].device_id,
						sizeof(collapsed[0]));
				}
				e->dev[i] = e->dev[e->ndev - 1];
				memset(&e->dev[e->ndev - 1], 0, sizeof(e->dev[0]));
				e->ndev--;
				if (slot == e->ndev) {
					slot = i;	/* the row we upserted was the tail we just moved */
				}
				continue;
			}
			i++;
		}
	}
	ao2_unlock(e);

	for (i = 0; i < ncollapsed; i++) {
		struct sofia_pushdb_job dj = { .kind = PUSHDB_DELETE };

		ast_copy_string(dj.peer, e->peername, sizeof(dj.peer));
		ast_copy_string(dj.device_id, collapsed[i], sizeof(dj.device_id));
		sofia_pushdb_queue(&dj);
		sofia_push_log_event(e->peername, collapsed[i], "", "collapsed", nd->device_id);
		ast_log(LOG_NOTICE, "Sofia PUSH: collapsed duplicate-token row peer='%s' dev='%s' (same installation now keyed dev='%s')\n",
			e->peername, collapsed[i], nd->device_id);
	}
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
	char script[300];		/* absolute path (push_scripts + send_push[_voip|_cancel].py) */
	char token[SOFIA_PUSH_TOKEN_MAX];
	char cid_num[80];
	char cid_name[80];
	char callid[64];
	char peername[128];
	char device_id[SOFIA_PUSH_DEVID_MAX];
	int cancel;			/* call_cancel job: argv gains the reason, the result only goes to push_log */
	char reason[24];
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

/* Forget one device's token: cache delete + queued DB delete + push_log event. -1 when the DB delete was not queued
 * (queue cap, no database). */
static int sofia_push_forget_device(const char *peername, const char *device_id, const char *event,
	const char *what, const char *reason)
{
	struct sofia_push_tokens *e = sofia_push_entry_get(peername, 0);
	struct sofia_pushdb_job dj = { .kind = PUSHDB_DELETE };
	int res;

	if (e) {
		sofia_push_cache_delete(e, device_id);
		ao2_ref(e, -1);
	}
	ast_copy_string(dj.peer, peername, sizeof(dj.peer));
	ast_copy_string(dj.device_id, device_id, sizeof(dj.device_id));
	res = sofia_pushdb_queue(&dj);
	sofia_push_log_event(peername, device_id, "", event, reason);
	ast_log(LOG_NOTICE, "Sofia PUSH: purged %s peer='%s' dev='%s' (%s)\n", what, peername, device_id, reason);
	return res;
}

static void sofia_push_purge_device(const char *peername, const char *device_id, const char *reason)
{
	sofia_push_forget_device(peername, device_id, "dead_token", "dead token", reason);
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
				e->dev[i].hold_push_at = now;
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

/* A re-register result: last_push_at goes to the DATABASE only (it is what tells the next load that this
 * registration was pushed), while the cache keeps the call push's last_push_at and last_result, so
 * push_min_interval never holds back a call push behind a re-register push. The token is dropped only when FCM
 * says it no longer exists (404 UNREGISTERED), not on a 400: a 400 could also be FCM refusing the message
 * itself, and that must not cost every device its token. */
static void sofia_push_record_rereg(const char *peername, const char *device_id, const char *result)
{
	struct sofia_pushdb_job fj = { .kind = PUSHDB_LASTPUSH };

	ast_copy_string(fj.peer, peername, sizeof(fj.peer));
	ast_copy_string(fj.device_id, device_id, sizeof(fj.device_id));
	fj.last_push_at = time(NULL);
	sofia_pushdb_queue(&fj);
	if (result && !strcmp(result, "ERR:404")) {
		sofia_push_purge_device(peername, device_id, result);
	}
}

/* A call_cancel result is logged only: it never touches last_result (which keeps the call
 * push's outcome for `sip show push`) and never purges, so a cancel can never cost a device
 * its token; the next call push classifies the token as usual. */
static void sofia_push_record_cancel(const char *peername, const char *device_id,
	const char *callid, const char *reason, const char *out)
{
	char detail[160];

	snprintf(detail, sizeof(detail), "%s %s", S_OR(reason, ""), S_OR(out, ""));
	sofia_push_log_event(peername, device_id, callid, "cancel", detail);
}

/* Completion entry for the NATIVE sender lane (sofia_push_sender.c). Lives here, beside the
 * static consumers, so both lanes run the IDENTICAL record path: first-line truncate, redacted
 * verb line, push_log 'sent', last_result cache+DB, dead-token purge (a call_cancel: push_log
 * 'cancel' only). Runs on the native sender thread — the same safety class as the script lane's
 * taskprocessor thread (leaf cache-entry locks + pushdb queue only; never pvt/peer/channel). */
void sofia_push_sender_complete(enum sofia_push_purpose purpose, const char *peername,
	const char *device_id, const char *callid, const char *reason, const char *sender_label,
	const char *token_redacted, const char *out_in, long ms)
{
	char out[SOFIA_PUSH_RESULT_MAX];
	char *nl;

	ast_copy_string(out, S_OR(out_in, ""), sizeof(out));
	if ((nl = strchr(out, '\n'))) {
		*nl = '\0';	/* first line only, script-lane parity */
	}
	ast_verb(2, "Sofia PUSH: sender %s dev=%s token=%s callid=%s result=%s (%ldms)\n",
		sender_label, device_id, token_redacted, callid, out, ms);
	if (purpose == SOFIA_PUSH_PURPOSE_CANCEL) {
		sofia_push_record_cancel(peername, device_id, callid, reason, out);
		return;
	}
	if (purpose == SOFIA_PUSH_PURPOSE_REREGISTER) {
		sofia_push_log_event(peername, device_id, callid, "sent", out);
		sofia_push_record_rereg(peername, device_id, out);
		return;
	}
	sofia_push_log_event(peername, device_id, callid, "sent", out);
	sofia_push_record_result(peername, device_id, out);
	if (sofia_push_result_is_dead_token(out)) {
		sofia_push_purge_device(peername, device_id, out);
	}
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
		if (j->cancel) {
			/* A box without send_push_cancel.py still pushes calls: note it, nothing else. */
			static time_t last_cancel_warn;
			if (time(NULL) - last_cancel_warn >= 60) {
				last_cancel_warn = time(NULL);
				ast_log(LOG_NOTICE, "Sofia PUSH: cancel script '%s' missing/not executable - call_cancel pushes are not sent by the script sender\n",
					j->script);
			}
		} else if (time(NULL) - last_exec_warn >= 60) {
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
			char *argv[] = { j->script, j->token, j->cid_num, j->cid_name, j->callid,
				j->cancel ? j->reason : NULL, NULL };
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
			if (pr < 0 && errno == EINTR) {
				/* a signal handler ran on this thread (a child's SIGCHLD): not a timeout, wait on */
				deadline -= (int) ast_tvdiff_ms(ast_tvnow(), it0);
				if (deadline <= 0) {
					break;
				}
				continue;
			}
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
	if (j->cancel) {
		sofia_push_record_cancel(j->peername, j->device_id, j->callid, j->reason, out);
	} else {
		sofia_push_log_event(j->peername, j->device_id, j->callid, "sent", out);
		sofia_push_record_result(j->peername, j->device_id, out);
		if (sofia_push_result_is_dead_token(out)) {
			sofia_push_purge_device(j->peername, j->device_id, out);
		}
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
	SOFIA_PUSH_COLLECTING,	/* multi-ring: first wake REGISTER seen; holding push_resume_window s so every pushed device binds before the fork */
	SOFIA_PUSH_RESUMING,	/* claimed by the resume path; terminal for everyone else */
	SOFIA_PUSH_APPENDING,	/* fork resume posted; entry stays live so a LATER wake REGISTER appends a branch while the call still rings (Android only registers after the user accepts the card) */
	SOFIA_PUSH_DONE,
};

struct sofia_push_park {
	char peername[128];		/* container key (multi-entry per peer allowed) */
	struct sofia_pvt *pvt;		/* +1 held while the entry lives (sole dropper: destructor) */
	char callid[64];		/* pre-generated SIP Call-ID = the push uuid */
	char cid_num[80];
	char cid_name[80];
	int sched_id;			/* push_wait; -1 = none */
	int collect_sched_id;		/* multi-ring collect window; -1 = none */
	int collected;			/* a collect window already ran: stragglers resume immediately */
	struct ast_sockaddr dialed[SOFIA_PUSH_MAX_DEVICES];	/* REGISTER source addrs already given a branch (late-append dedup; entry lock) */
	char dialed_inst[SOFIA_PUSH_MAX_DEVICES][128];	/* +sip.instance of each dialed[] binding ("" = none): those devices got the INVITE, so no call_cancel */
	char woken_inst[SOFIA_PUSH_MAX_DEVICES][128];	/* =hold, parked call: +sip.instance of each device whose wake REGISTER came while PARKED/COLLECTING (entry lock) */
	int nwoken;
	int ndialed;
	char live_inst[SOFIA_PUSH_MAX_DEVICES][128];	/* push-assist: +sip.instance of devices ALREADY ringing (a live binding) — their push is skipped, only the asleep devices are woken */
	int n_live_inst;
	char exclude_instance[128];	/* self-call: the CALLING device's +sip.instance - its push is skipped (never wake the phone that is placing the call) */
	struct ast_sockaddr exclude_src;	/* self-call: the CALLING device's transport source - its own re-REGISTER is NOT a wake (must not resume this park) and its binding is never a resume target */
	int exclude_valid;
	enum sofia_push_park_state state;
	int inflight;			/* P2: an INVITE is ALREADY on the wire (no-provisional guard fired); resume swaps the leg instead of creating the first one */
	time_t parked_at;
	int npushed;			/* devices actually notified */
	int npushed_live;		/* of them, devices that also had a live binding (push_voip_live): they got the INVITE
					 * already, so they are not waited for as woken devices (all_joined) */
	int njoined_asleep;		/* late appends of devices that had no live binding (all_joined) */
	char pushed_live_inst[SOFIA_PUSH_MAX_DEVICES][128];	/* +sip.instance of the devices pushed while live */
	char pushed_dev[SOFIA_PUSH_MAX_DEVICES][SOFIA_PUSH_DEVID_MAX];
	int cancel_sent;		/* the call_cancel pushes went out (once per call; entry lock) */
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
static int sofia_push_collect_cb(const void *data);
static void sofia_push_collect_cancel_timer(struct sofia_push_park *e);

/* Queue the sender jobs for every eligible device of the peer. Returns the number of
 * jobs queued, and reports (via *rate_limited) devices skipped only by push_min_interval
 * (a park with 0 jobs is still valid if a push went out moments ago — the phone is
 * already waking; a second push inside the phone's own 5 s dedup window would be
 * actively harmful — iOS reports-and-cancels it). Also records the pushed device ids. */
static int sofia_push_notify_devices(struct sofia_push_park *entry, int *rate_limited, int only_cancelled)
{
	struct sofia_push_tokens *e;
	struct sofia_push_device snap[SOFIA_PUSH_MAX_DEVICES];
	int snap_live[SOFIA_PUSH_MAX_DEVICES];	/* the device also has a live binding (pushed_when_live) */
	char already[SOFIA_PUSH_MAX_DEVICES][SOFIA_PUSH_DEVID_MAX];
	int nsnap = 0, nalready = 0, i, queued = 0;
	time_t now = time(NULL);
	int cap = sofia_cfg.push_max_devices;

	*rate_limited = 0;
	if (only_cancelled) {
		/* outside the cache lock: two leaf locks never nest */
		ao2_lock(entry);
		nalready = entry->npushed;
		memcpy(already, entry->pushed_dev, sizeof(already));
		ao2_unlock(entry);
	}
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
		int is_live = 0;	/* the device has a live binding forked to it (push-assist) */

		if (sofia_push_device_stale(&e->dev[i], now)) {
			continue;
		}
		if (only_cancelled) {
			/* Re-announce: only a device whose card for another call was just cancelled,
			 * and only if this call has not pushed it yet. */
			int k, dup = 0;
			if (!e->dev[i].cancelled) {
				continue;
			}
			for (k = 0; k < nalready; k++) {
				if (!strcasecmp(already[k], e->dev[i].device_id)) {
					dup = 1;
					break;
				}
			}
			if (dup) {
				continue;
			}
		}
		/* Self-call: never push the device that is PLACING this call (matched by the
		 * normalized +sip.instance both sides store via sofia_contact_parse_instance). */
		if (entry->exclude_instance[0] && e->dev[i].instance[0]
				&& !strcasecmp(e->dev[i].instance, entry->exclude_instance)) {
			continue;
		}
		/* Hybrid push-assist: a device that is ALREADY ringing (a live binding was
		 * forked to it) is not also pushed — only the ASLEEP devices are woken — unless it
		 * is pushed even when live (an iOS VoIP device, sofia_push_device_pushed_when_live). */
		if (entry->n_live_inst && e->dev[i].instance[0]) {
			int li;
			for (li = 0; li < entry->n_live_inst; li++) {
				if (!strcasecmp(e->dev[i].instance, entry->live_inst[li])) {
					is_live = 1;
					break;
				}
			}
			if (is_live && !sofia_push_device_pushed_when_live(&e->dev[i])) {
				continue;
			}
		}
		if (sofia_cfg.push_min_interval > 0 && !e->dev[i].cancelled
			&& e->dev[i].last_push_at > now - sofia_cfg.push_min_interval) {
			if (!is_live) {
				(*rate_limited)++;	/* it is already waking: the call waits for it */
			}
			continue;	/* a live one rings on its binding: nothing to wait for */
		}
		e->dev[i].last_push_at = now;	/* stamp NOW so a racing second park rate-limits */
		e->dev[i].cancelled = 0;
		e->dev[i].hold_push_at = now;
		e->dev[i].hold_cancelled = 0;
		snap_live[nsnap] = is_live;
		snap[nsnap++] = e->dev[i];
	}
	ao2_unlock(e);
	ao2_ref(e, -1);

	for (i = 0; i < nsnap; i++) {
		struct sofia_push_send_job *j;
		/* NATIVE lane first (push_sender=native, the default): its own bounded queue and
		 * NO shared-budget slot held for the HTTP flight (only the completion's
		 * log/record/purge jobs draw on sofia_pushdb_depth, exactly like the script
		 * lane's completion). submit()==1 means "lane can't serve this job" (down, or
		 * that push type's creds are sick) -> fall THROUGH to the script sender below
		 * (auto-fallback); submit()==-1 means the native queue is full -> drop this
		 * device (bounded, same semantics as the script cap; a burst must never
		 * degrade into fork/exec). */
		if (sofia_cfg.push_sender_native) {
			int sr = sofia_push_sender_submit(SOFIA_PUSH_PURPOSE_CALL, snap[i].push_type,
				snap[i].token, entry->cid_num, entry->cid_name, entry->callid,
				entry->peername, snap[i].device_id, NULL);
			if (sr == 0) {
				ao2_lock(entry);	/* the entry is already linked: send_cancels reads these under it */
				if (entry->npushed < SOFIA_PUSH_MAX_DEVICES) {
					ast_copy_string(entry->pushed_dev[entry->npushed++], snap[i].device_id,
						sizeof(entry->pushed_dev[0]));
					if (snap_live[i]) {
						ast_copy_string(entry->pushed_live_inst[entry->npushed_live++], snap[i].instance,
							sizeof(entry->pushed_live_inst[0]));
					}
				}
				ao2_unlock(entry);
				queued++;
				continue;
			}
			if (sr < 0) {
				continue;	/* native queue full: drop, never burst into fork/exec */
			}
			{	/* sr == 1: native selected but unusable -> script fallback, throttled note */
				static time_t last_fb_warn;
				if (time(NULL) - last_fb_warn >= 60) {
					last_fb_warn = time(NULL);
					ast_log(LOG_WARNING, "Sofia PUSH: push_sender=native but the native lane cannot serve this job - using the script sender\n");
				}
			}
		}
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
		ao2_lock(entry);
		if (entry->npushed < SOFIA_PUSH_MAX_DEVICES) {
			ast_copy_string(entry->pushed_dev[entry->npushed++], snap[i].device_id,
				sizeof(entry->pushed_dev[0]));
			if (snap_live[i]) {
				ast_copy_string(entry->pushed_live_inst[entry->npushed_live++], snap[i].instance,
					sizeof(entry->pushed_live_inst[0]));
			}
		}
		ao2_unlock(entry);
		queued++;
	}
	return queued;
}

/* +sip.instance of the binding the pvt's call is on ("" = none). ao2_lock(pvt) is a leaf. */
static void sofia_push_pvt_instance(struct sofia_pvt *pvt, char *buf, size_t len)
{
	ao2_lock(pvt);
	ast_copy_string(buf, pvt->dev_instance, len);
	ao2_unlock(pvt);
}

/* Another call to the same account that arrived inside push_min_interval did not push a device
 * (its card for this call was already showing) and now waits on a card that was just
 * cancelled: announce that call to the device. Same lock context as sofia_push_send_cancels. */
static void sofia_push_renotify_waiting(const char *peername, struct sofia_push_park *done)
{
	struct ao2_iterator it;
	struct sofia_push_park *o;

	if (!sofia_push_parked) {
		return;
	}
	it = ao2_iterator_init(sofia_push_parked, 0);
	while ((o = ao2_iterator_next(&it))) {
		int waiting = 0;
		if (o != done && !strcasecmp(o->peername, peername)) {
			ao2_lock(o);
			waiting = (o->state == SOFIA_PUSH_PARKED || o->state == SOFIA_PUSH_COLLECTING);
			ao2_unlock(o);
		}
		if (waiting) {
			int rate_limited = 0;
			int queued = sofia_push_notify_devices(o, &rate_limited, 1);
			if (queued) {
				ast_verb(2, "Sofia PUSH: %s peer='%s' - pushed %d device(s) whose card for another call was cancelled\n",
					o->callid, o->peername, queued);
				sofia_push_log_event(o->peername, "", o->callid, "sent", "renotify");
			}
		}
		ao2_ref(o, -1);
	}
	ao2_iterator_destroy(&it);
}

/* call_cancel: the call announced by this entry's push will never reach these devices as an
 * INVITE (the caller hung up, another destination or device answered, push_wait expired, or
 * the call went to one device only), so nothing in SIP can stop the card the push put on
 * screen. Send an FCM type=call_cancel with the same uuid to every pushed Android device
 * (push_type fcm) that did not get an INVITE for this call: the dialed bindings, and keep_inst
 * when the call went to one binding outside the fork ("" = that binding has no instance, so a
 * device without one may be it and is skipped). iOS is never sent one: a VoIP push must
 * report a call, and a woken iPhone gets the INVITE and the CANCEL. Once per entry. Both
 * lanes, like the call push: native first, the script sender (send_push_cancel.py) when the
 * native lane cannot serve it. Any thread holding no pvt/peer/entry lock (the channel lock
 * may be held: only the cache entry lock, a leaf, and the sender queues are taken). */
static void sofia_push_send_cancels(struct sofia_push_park *e, const char *reason, const char *keep_inst)
{
	char pushed[SOFIA_PUSH_MAX_DEVICES][SOFIA_PUSH_DEVID_MAX];
	char joined[SOFIA_PUSH_MAX_DEVICES + 1][128];
	char peername[128], callid[64], cid_num[80], cid_name[80];
	struct sofia_push_tokens *te;
	struct {
		char device_id[SOFIA_PUSH_DEVID_MAX];
		char token[SOFIA_PUSH_TOKEN_MAX];
	} snap[SOFIA_PUSH_MAX_DEVICES];
	int npushed, njoined = 0, any_joined, nsnap = 0, i, k, sent = 0;

	ao2_lock(e);
	if (e->cancel_sent || !e->npushed) {
		ao2_unlock(e);
		return;
	}
	e->cancel_sent = 1;
	npushed = e->npushed;
	memcpy(pushed, e->pushed_dev, sizeof(pushed));
	for (i = 0; i < e->ndialed && i < SOFIA_PUSH_MAX_DEVICES; i++) {
		ast_copy_string(joined[njoined++], e->dialed_inst[i], sizeof(joined[0]));
	}
	ast_copy_string(peername, e->peername, sizeof(peername));
	ast_copy_string(callid, e->callid, sizeof(callid));
	ast_copy_string(cid_num, e->cid_num, sizeof(cid_num));
	ast_copy_string(cid_name, e->cid_name, sizeof(cid_name));
	ao2_unlock(e);
	if (keep_inst) {
		ast_copy_string(joined[njoined++], keep_inst, sizeof(joined[0]));
	}
	any_joined = njoined > 0;

	if (!(te = sofia_push_entry_get(peername, 0))) {
		return;
	}
	ao2_lock(te);
	for (i = 0; i < npushed; i++) {
		struct sofia_push_device *d = NULL;
		int got_invite = 0;
		for (k = 0; k < te->ndev; k++) {
			if (!strcasecmp(te->dev[k].device_id, pushed[i])) {
				d = &te->dev[k];
				break;
			}
		}
		if (!d || !d->token[0] || strcasecmp(d->platform, "android") || strcasecmp(d->push_type, "fcm")) {
			continue;
		}
		if (d->instance[0]) {
			for (k = 0; k < njoined; k++) {
				if (!strcasecmp(d->instance, joined[k])) {
					got_invite = 1;
					break;
				}
			}
		} else {
			got_invite = any_joined;	/* cannot tell it from the binding that got the INVITE */
		}
		if (got_invite) {
			continue;
		}
		ast_copy_string(snap[nsnap].device_id, d->device_id, sizeof(snap[0].device_id));
		ast_copy_string(snap[nsnap].token, d->token, sizeof(snap[0].token));
		nsnap++;
		d->cancelled = 1;	/* its card goes: a redial right now must push again */
		d->hold_cancelled = 1;
	}
	ao2_unlock(te);
	ao2_ref(te, -1);

	for (i = 0; i < nsnap; i++) {
		struct sofia_push_send_job *j;
		if (sofia_cfg.push_sender_native) {
			int sr = sofia_push_sender_submit(SOFIA_PUSH_PURPOSE_CANCEL, "fcm", snap[i].token,
				cid_num, cid_name, callid, peername, snap[i].device_id, reason);
			if (sr == 0) {
				sent++;
				continue;
			}
			if (sr < 0) {
				continue;	/* native queue full: drop, as the call push does */
			}
		}
		if (!sofia_push_tps) {
			break;
		}
		/* Half the shared budget at most: call pushes and token writes keep their room. */
		if (ast_atomic_fetchadd_int(&sofia_pushdb_depth, +1) >= SOFIA_PUSH_DBQ_MAX / 2) {
			ast_atomic_fetchadd_int(&sofia_pushdb_depth, -1);
			break;
		}
		if (!(j = ast_calloc(1, sizeof(*j)))) {
			ast_atomic_fetchadd_int(&sofia_pushdb_depth, -1);
			break;
		}
		snprintf(j->script, sizeof(j->script), "%s/send_push_cancel.py", sofia_cfg.push_scripts);
		ast_copy_string(j->token, snap[i].token, sizeof(j->token));
		ast_copy_string(j->cid_num, cid_num, sizeof(j->cid_num));
		ast_copy_string(j->cid_name, cid_name, sizeof(j->cid_name));
		ast_copy_string(j->callid, callid, sizeof(j->callid));
		ast_copy_string(j->peername, peername, sizeof(j->peername));
		ast_copy_string(j->device_id, snap[i].device_id, sizeof(j->device_id));
		ast_copy_string(j->reason, reason, sizeof(j->reason));
		j->cancel = 1;
		if (ast_taskprocessor_push(sofia_push_tps, sofia_push_send_exe, j) < 0) {
			ast_atomic_fetchadd_int(&sofia_pushdb_depth, -1);
			ast_free(j);
			break;
		}
		sent++;
	}
	if (nsnap) {
		ast_verb(2, "Sofia PUSH: call_cancel %s peer='%s' reason=%s -> %d of %d Android device(s)\n",
			callid, peername, reason, sent, nsnap);
		sofia_push_renotify_waiting(peername, e);
	}
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
	if (e->state == SOFIA_PUSH_APPENDING) {
		/* Push-assist deadline: the woken device had push_wait to join the fork. Release the
		 * fork's hold, which ends the call now if every branch has failed meanwhile; the entry
		 * stays for late appends until the call ends (hangup reaps it). */
		pvt = e->pvt;	/* stable: the entry's own ref outlives this callback */
		ao2_unlock(e);
		if (pvt) {
			sofia_fork_push_hold_release(pvt);
		}
		ao2_ref(e, -1);		/* the arm-time ref */
		return 0;
	}
	if (e->state != SOFIA_PUSH_PARKED && e->state != SOFIA_PUSH_COLLECTING) {
		ao2_unlock(e);
		ao2_ref(e, -1);		/* the arm-time ref; resume/hangup owns the entry */
		return 0;
	}
	e->state = SOFIA_PUSH_DONE;
	ao2_unlock(e);
	sofia_push_collect_cancel_timer(e);	/* a pending multi-ring window loses to the deadline */
	sofia_push_send_cancels(e, "timeout", NULL);

	/* No wake REGISTER arrived: fail_count++ on every device we pushed (>=5 purges —
	 * the uninstalled-without-logout phone). A REGISTER resets it (capture upserts 0). */
	{
		struct sofia_push_tokens *te = sofia_push_entry_get(e->peername, 0);
		int i;
		if (te) {
			for (i = 0; i < e->npushed; i++) {
				struct sofia_pushdb_job fj = { .kind = PUSHDB_FAILCOUNT };	/* fail_count only: never lowers a stored last_push_at */
				int fc = 0, k;
				ao2_lock(te);
				for (k = 0; k < te->ndev; k++) {
					if (!strcasecmp(te->dev[k].device_id, e->pushed_dev[i])) {
						fc = ++te->dev[k].fail_count;
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

/* Same del-or-fire discipline for the multi-ring collect window. */
static void sofia_push_collect_cancel_timer(struct sofia_push_park *e)
{
	int sid;

	ao2_lock(e);
	sid = e->collect_sched_id;
	e->collect_sched_id = -1;
	ao2_unlock(e);
	if (sid > -1 && sofia_sched && ast_sched_thread_del(sofia_sched, sid) == 0) {
		ao2_ref(e, -1);	/* timer never ran: drop its ref */
	}
}

/* Caller identity for the push payload: the calling party exactly as the INVITE's From
 * carries it (sofia_resolve_identity). On an outbound leg Dial stores the dialled extension
 * in caller.id and the calling party in connected.id (Originate sets both), so caller.id
 * would show the callee its own number. A restricted presentation of the connected line
 * sends "anonymous", as the From does. callerName carries the number as well: the phone draws
 * its incoming-call screen from it, and the screen built from the INVITE shows the From user,
 * which is the number, not the configured name. Caller holds the channel lock. */
static void sofia_push_caller_id(struct ast_channel *ast,
	char *num, size_t num_len, char *name, size_t name_len)
{
	if ((ast_party_id_presentation(&ast->connected.id) & AST_PRES_RESTRICTION) != AST_PRES_ALLOWED) {
		ast_copy_string(num, "anonymous", num_len);
		ast_copy_string(name, "Anonymous", name_len);
		return;
	}
	ast_copy_string(num, S_COR(ast->connected.id.number.valid, ast->connected.id.number.str, "unknown"),
		num_len);
	ast_copy_string(name, num, name_len);
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
	ast_copy_string(e->exclude_instance, pvt->push_exclude_instance, sizeof(e->exclude_instance));
	if (pvt->fork_exclude_valid) {
		ast_sockaddr_copy(&e->exclude_src, &pvt->fork_exclude_src);
		e->exclude_valid = 1;
	}
	ast_copy_string(e->callid, callid, sizeof(e->callid));
	ast_copy_string(e->cid_num, S_OR(cid_num, "unknown"), sizeof(e->cid_num));
	ast_copy_string(e->cid_name, S_OR(cid_name, e->cid_num), sizeof(e->cid_name));
	e->pvt = pvt;
	ao2_ref(pvt, +1);
	e->sched_id = -1;
	e->collect_sched_id = -1;
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
		int queued = sofia_push_notify_devices(e, &rate_limited, 0);
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
		int alive;
		/* caller identity for the push payload: channel lock, nothing else held */
		ast_channel_lock(owner);
		sofia_push_caller_id(owner, cid_num, sizeof(cid_num), cid_name, sizeof(cid_name));
		/* The hangup may have run while we waited for the channel lock (the core holds it
		 * across sofia_hangup): never push for a call that is already gone or answered. */
		ast_mutex_lock(&pvt->lock);
		alive = (pvt->owner == owner && pvt->nh && !pvt->got_provisional);
		ast_mutex_unlock(&pvt->lock);
		ast_channel_unlock(owner);
		ast_channel_unref(owner);

		e = alive ? sofia_push_park_create(pvt, callid, cid_num, cid_name, 1 /* inflight */) : NULL;
		if (e) {
			int gone;
			/* Mark the pvt so its hangup reaps the entry. sofia_hangup clears the owner and
			 * reads the flag under this same lock: either it sees the flag, or we see it gone
			 * and reap the entry ourselves. */
			ast_mutex_lock(&pvt->lock);
			gone = !pvt->owner;
			if (!gone) {
				pvt->push_inflight = 1;
			}
			ast_mutex_unlock(&pvt->lock);
			ast_log(LOG_NOTICE, "Sofia PUSH: guard fired %s peer='%s' - no 1xx in %ds on a connection-oriented leg, pushed with the in-flight Call-ID\n",
				e->callid, e->peername, sofia_cfg.push_noresponse);
			sofia_push_log_event(e->peername, "", e->callid, "sent", "noresponse");
			if (gone) {
				sofia_push_on_pvt_hangup(pvt, 0);
			}
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
					char a_inst[128];
					sofia_push_park_cancel_timer(e);
					ast_verb(2, "Sofia PUSH: unparked %s peer='%s' - the in-flight leg progressed (%d), old leg wins\n",
						e->callid, e->peername, status);
					sofia_push_log_event(e->peername, "", e->callid, "unparked", "");
					/* The other pushed devices will get no INVITE for this call. */
					sofia_push_pvt_instance(pvt, a_inst, sizeof(a_inst));
					sofia_push_send_cancels(e, status < 300 ? "answered_elsewhere" : "cancelled", a_inst);
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
	char cid_num[80], cid_name[80];
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

	sofia_push_caller_id(ast, cid_num, sizeof(cid_num), cid_name, sizeof(cid_name));	/* channel lock held by ast_call */
	e = sofia_push_park_create(pvt, pvt->sip_callid, cid_num, cid_name,
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
		struct sofia_contact *lc = sofia_peer_select_single_live_contact(pvt->peer, &nu, &nt, NULL, NULL);
		if (lc) {
			ao2_ref(lc, -1);
			/* =hold: a call parked BECAUSE its live bindings are devices pushed first (sofia_request_call) has
			 * nothing fresh to resume on: only the REGISTER the push makes resumes it (RFC 8599 §5.6.2). (The push
			 * just went out, so asking sofia_push_live_held again would find them inside push_min_interval.) */
			if (!pvt->push_park_held) {
				sofia_push_resume_one(e, pvt->peer, NULL);
			}
		}
	}
	ao2_ref(e, -1);		/* alloc ref: container + timer hold the entry now */
	return 0;
}

/* Caller hangup / Dial-timeout reaping of a parked pvt. PBX thread, NO locks held (called
 * from sofia_hangup after pvt->lock is released; the caller still holds a pvt ref). */
void sofia_push_on_pvt_hangup(struct sofia_pvt *pvt, int answered_elsewhere)
{
	struct ao2_iterator it;
	struct sofia_push_park *e;

	if (!sofia_push_parked || !pvt) {
		return;
	}
	it = ao2_iterator_init(sofia_push_parked, 0);
	while ((e = ao2_iterator_next(&it))) {
		int won = 0, was_appending = 0;
		if (e->pvt == pvt) {
			ao2_lock(e);
			if (e->state == SOFIA_PUSH_PARKED || e->state == SOFIA_PUSH_COLLECTING
					|| e->state == SOFIA_PUSH_APPENDING) {
				was_appending = (e->state == SOFIA_PUSH_APPENDING);
				e->state = SOFIA_PUSH_DONE;
				won = 1;
			}
			ao2_unlock(e);
			if (won) {
				sofia_push_park_cancel_timer(e);
				sofia_push_collect_cancel_timer(e);
				/* Parked: no device got the INVITE. Appending: those that never joined the
				 * fork (no-op when an answer already sent them). */
				sofia_push_send_cancels(e, answered_elsewhere ? "answered_elsewhere" : "cancelled", NULL);
				if (was_appending) {
					/* the call was DELIVERED (fork resume) and has now ended; this is
					 * just the late-append window closing, not an abandoned park */
					ast_debug(1, "Sofia PUSH: %s peer='%s' - late-append window closed (call ended)\n",
						e->callid, e->peername);
					sofia_push_log_event(e->peername, "", e->callid, "unparked", "ended");	/* closes it for the restart reader */
				} else {
					ast_verb(2, "Sofia PUSH: cancelled %s peer='%s' (caller hangup)\n",
						e->callid, e->peername);
					sofia_push_log_event(e->peername, "", e->callid, "caller_hangup", "");
				}
				ao2_unlink(sofia_push_parked, e);
			}
			/* RESUMING/DONE: the owner of that transition cleans up; nothing here. */
		}
		ao2_ref(e, -1);
	}
	ao2_iterator_destroy(&it);
}

/* A fork branch answered on a master that a push resumed or assisted (sofia_thread, no locks
 * held): the call is over for every pushed device that never joined, so they get their
 * call_cancel now. The entry stays APPENDING; the master's hangup reaps it (and finds the
 * cancels already sent). */
void sofia_push_on_fork_answered(struct sofia_pvt *master)
{
	struct ao2_iterator it;
	struct sofia_push_park *e;

	if (!sofia_push_parked || !master) {
		return;
	}
	it = ao2_iterator_init(sofia_push_parked, 0);
	while ((e = ao2_iterator_next(&it))) {
		int appending;
		if (e->pvt == master) {
			ao2_lock(e);
			appending = (e->state == SOFIA_PUSH_APPENDING);
			ao2_unlock(e);
			if (appending) {
				sofia_push_send_cancels(e, "answered_elsewhere", NULL);
			}
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
/* =hold, a call parked for its live bindings (push_park_held): 1 when this +sip.instance is one of the devices pushed
 * first (pvt->push_held_inst) whose wake REGISTER has not come yet (not in woken_inst): its old binding is not dialed.
 * Takes the entry lock (leaf); no contact lock may be held. */
static int sofia_push_held_not_woken(struct sofia_push_park *e, struct sofia_pvt *pvt, const char *inst)
{
	int k, w, held = 0;

	if (!pvt || !pvt->push_park_held || !inst || !inst[0]) {
		return 0;
	}
	for (k = 0; k < pvt->push_held_n; k++) {
		if (!strcasecmp(inst, pvt->push_held_inst[k])) {
			held = 1;
			break;
		}
	}
	if (!held) {
		return 0;
	}
	ao2_lock(e);
	for (w = 0; w < e->nwoken && strcasecmp(e->woken_inst[w], inst); w++) {
	}
	held = (w == e->nwoken);
	ao2_unlock(e);
	return held;
}

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
	char bound_inst[128] = "";
	int old_leg_lives = 0;	/* P2: the in-flight leg progressed while we claimed: it keeps the call */

	/* The freshly bound contact FIRST (by the REGISTER's learned source, else the
	 * single-live selector). No contact yet -> leave the entry PARKED: the push_wait
	 * timer stays armed as the safety net and a later REGISTER retries. */
	int c_from_update = 0;
	if (update && !ast_sockaddr_isnull(&update->new_src)
			&& !(e->exclude_valid && !ast_sockaddr_cmp(&update->new_src, &e->exclude_src))) {
		c = sofia_peer_find_contact_by_addr(peer, &update->new_src);
		if (c && (e->exclude_valid || e->exclude_instance[0])) {
			/* The caller's device may have re-registered from a NEW source (mid-call
			 * socket rebuild): recognize it by instance and refuse it as a wake. */
			char c_inst[128];
			struct ast_sockaddr c_src;
			ao2_lock(c);
			ast_copy_string(c_inst, c->instance_id, sizeof(c_inst));
			ast_sockaddr_copy(&c_src, &c->src_addr);
			ao2_unlock(c);
			if (sofia_selfcall_contact_excluded(&c_src, c_inst,
					e->exclude_valid ? &e->exclude_src : NULL,
					e->exclude_instance[0] ? e->exclude_instance : NULL)) {
				ao2_ref(c, -1);
				c = NULL;
			}
		}
		c_from_update = (c != NULL);
	}
	if (!c && pvt && pvt->push_park_held) {
		/* =hold: only the REGISTER of a pushed device resumes the call, on its own binding; a live binding found
		 * otherwise is the old one of a device still waking (RFC 8599 §5.6.2). push_park_held is set before the
		 * channel exists (cleared only when the park itself fails, when no entry exists). */
		return;
	}
	if (!c) {
		int nu = 0, nt = 0;
		/* Self-call park: the caller's own binding is never a resume target. */
		c = sofia_peer_select_single_live_contact(peer, &nu, &nt,
			e->exclude_valid ? &e->exclude_src : NULL,
			e->exclude_instance[0] ? e->exclude_instance : NULL);
	}
	if (!c || !pvt || !sofia_nua) {
		if (c) {
			ao2_ref(c, -1);
		}
		return;
	}
	/* Snapshot outside the entry lock (contact locks never nest under it). */
	ao2_lock(c);
	ast_copy_string(bound_inst, c->instance_id, sizeof(bound_inst));
	ao2_unlock(c);
	if (c_from_update && bound_inst[0]) {
		/* =hold: this device has woken; the collect window's fork may dial its binding (sofia_push_collect_cb). */
		int w;

		ao2_lock(e);
		if (e->state == SOFIA_PUSH_PARKED || e->state == SOFIA_PUSH_COLLECTING) {
			for (w = 0; w < e->nwoken && strcasecmp(e->woken_inst[w], bound_inst); w++) {
			}
			if (w == e->nwoken && e->nwoken < SOFIA_PUSH_MAX_DEVICES) {
				ast_copy_string(e->woken_inst[e->nwoken++], bound_inst, sizeof(e->woken_inst[0]));
			}
		}
		ao2_unlock(e);
	}

	/* Claim. Multi-ring: the FIRST wake REGISTER of a plain parked call does not take
	 * the call — it opens a short collect window (push_resume_window) so EVERY pushed
	 * device can bind; the window's callback then forks one INVITE per live binding,
	 * all carrying the announced Call-ID. First-registrant-wins remains for window=0,
	 * for inflight entries (P2 swap: an INVITE is already on the wire) and for a
	 * straggler REGISTER after a window already ran (collected). */
	ao2_lock(e);
	if (e->state == SOFIA_PUSH_COLLECTING) {
		ao2_unlock(e);
		ao2_ref(c, -1);
		ast_debug(1, "Sofia PUSH: %s peer='%s' - another device bound inside the collect window\n",
			e->callid, e->peername);
		return;
	}
	if (e->state == SOFIA_PUSH_APPENDING) {
		/* LATE APPEND: the fork resume already went out and the call is still ringing;
		 * this fresh binding gets its own branch (same announced Call-ID - the phone is
		 * already showing the card for that uuid). Only a binding identified by the
		 * REGISTER source may append; a refresh of an already-dialed one dedups. */
		int i, dup = 0, all_joined, slot;
		if (!c_from_update) {
			ao2_unlock(e);
			ao2_ref(c, -1);
			return;
		}
		for (i = 0; i < e->ndialed; i++) {
			if (!ast_sockaddr_cmp(&e->dialed[i], &update->new_src)) {
				dup = 1;
				break;
			}
		}
		if (dup || e->ndialed >= SOFIA_PUSH_MAX_DEVICES) {
			ao2_unlock(e);
			ao2_ref(c, -1);
			return;
		}
		ast_sockaddr_copy(&e->dialed[e->ndialed], &update->new_src);
		slot = e->ndialed++;	/* reserve BEFORE posting: a racing re-REGISTER dedups here */
		/* A device that had a live binding (pushed while live, back on a new connection) is not one of the
		 * woken devices the fork waits for. */
		for (i = 0; bound_inst[0] && i < e->n_live_inst; i++) {
			if (!strcasecmp(bound_inst, e->live_inst[i])) {
				break;
			}
		}
		if (!bound_inst[0] || i == e->n_live_inst) {
			e->njoined_asleep++;
		}
		/* Every pushed device has now joined: the fork no longer needs to be held open for a
		 * woken device, so its own branches decide the outcome from here (released below). A
		 * device pushed while it had a live binding already rings on it and is not waited for. */
		all_joined = e->njoined_asleep >= e->npushed - e->npushed_live;
		ao2_unlock(e);
		ast_mutex_lock(&pvt->lock);
		owner = pvt->owner;
		if (owner) {
			ast_channel_ref(owner);
		}
		ast_mutex_unlock(&pvt->lock);
		if (owner) {
			int arc = -1;
			ast_channel_lock(owner);
			if (pvt->owner == owner) {
				arc = sofia_fork_append_contact(pvt, c);
				if (!arc) {
					/* This device got the INVITE: no call_cancel for it. Recorded under the
					 * channel lock, which the hangup's cancels also run under. */
					ao2_lock(e);
					ast_copy_string(e->dialed_inst[slot], bound_inst, sizeof(e->dialed_inst[0]));
					ao2_unlock(e);
				}
			}
			ast_channel_unlock(owner);
			ast_channel_unref(owner);
			if (!arc) {
				ast_verb(2, "Sofia PUSH: late append %s peer='%s' - extra branch INVITE to the just-woken binding\n",
					e->callid, e->peername);
				sofia_push_log_event(e->peername, "", e->callid, "resumed", "append");
				if (all_joined) {
					sofia_fork_push_hold_release(pvt);
				}
			}
		}
		ao2_ref(c, -1);
		return;
	}
	if (e->state != SOFIA_PUSH_PARKED) {
		ao2_unlock(e);
		ao2_ref(c, -1);
		return;
	}
	if (!e->inflight && !e->collected && sofia_cfg.push_resume_window > 0) {
		/* Arm under the entry lock (defer-BYE idiom): the callback's first act is
		 * taking this lock, so the id store happens-before it can observe the entry. */
		int cid_sched;
		ao2_ref(e, +1);		/* the collect timer's ref */
		cid_sched = ast_sched_thread_add(sofia_sched, sofia_cfg.push_resume_window * 1000,
			sofia_push_collect_cb, e);
		if (cid_sched > -1) {
			e->collect_sched_id = cid_sched;
			e->state = SOFIA_PUSH_COLLECTING;
			ao2_unlock(e);
			ao2_ref(c, -1);
			ast_verb(2, "Sofia PUSH: %s peer='%s' - first wake REGISTER; collecting bindings for %ds (multi-ring)\n",
				e->callid, e->peername, sofia_cfg.push_resume_window);
			return;
		}
		ao2_ref(e, -1);		/* arm failed: fall through to the immediate single resume */
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
			old_leg_lives = (pvt->owner == owner && pvt->nh && pvt->got_provisional);
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
	/* The call went to this one binding; the entry closes, so no later wake REGISTER gets a
	 * branch: the other pushed devices' cards lead nowhere. */
	sofia_push_send_cancels(e, "answered_elsewhere", bound_inst);
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
	sofia_push_send_cancels(e, "cancelled", NULL);
	goto done;

orphan:
	if (old_leg_lives) {
		/* Not orphaned: the old leg answered meanwhile and keeps ringing its device (the
		 * guard's unpark saw RESUMING and left the entry to us). */
		char a_inst[128];
		sofia_push_pvt_instance(pvt, a_inst, sizeof(a_inst));
		ast_verb(2, "Sofia PUSH: resume of %s peer='%s' dropped - the in-flight leg progressed, old leg wins\n",
			e->callid, e->peername);
		sofia_push_log_event(e->peername, "", e->callid, "unparked", "");
		sofia_push_send_cancels(e, "answered_elsewhere", a_inst);
		goto done;
	}
	ast_verb(2, "Sofia PUSH: resume of %s peer='%s' aborted - caller already gone\n",
		e->callid, e->peername);
	sofia_push_log_event(e->peername, "", e->callid, "orphaned", "caller_gone");
	sofia_push_send_cancels(e, "cancelled", NULL);
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

/* Multi-ring collect window fired (sched thread, sched lock NOT held). Dial EVERY live
 * binding the wake REGISTERs bound during the window: >=2 -> ONE fork INVITE per binding
 * through sofia_fork_dial, all branches carrying the announced Call-ID (each phone
 * matches its push card to its own INVITE; first 200 wins, the fork engine CANCELs the
 * losers); exactly 1 -> the proven single-resume path; 0 (every binding lapsed inside
 * the window - pathological) -> back to PARKED under the still-armed push_wait deadline.
 * The commit runs UNDER THE CHANNEL LOCK, same serializer as ast_call/sofia_hangup. */
static int sofia_push_collect_cb(const void *data)
{
	struct sofia_push_park *e = (struct sofia_push_park *) data;
	struct sofia_peer *peer = NULL;
	struct sofia_pvt *pvt = e->pvt;
	struct ast_channel *owner = NULL;
	int live = 0, rc = -1;
	time_t waited = time(NULL) - e->parked_at;
	char skip_inst[SOFIA_PUSH_MAX_DEVICES][128];	/* =hold: the devices left out of the fork (recheck below) */
	int nskip = 0;

	ao2_lock(e);
	e->collect_sched_id = -1;
	e->collected = 1;	/* stragglers from now on resume immediately */
	if (e->state != SOFIA_PUSH_COLLECTING) {
		/* timeout/hangup claimed the entry while we were queued */
		ao2_unlock(e);
		ao2_ref(e, -1);		/* the arm-time ref */
		return 0;
	}
	ao2_unlock(e);

	peer = sofia_find_peer_cached(e->peername);	/* just registered => in memory; +1 */
	if (peer && peer->contacts) {
		time_t now = time(NULL);
		struct ao2_iterator ci = ao2_iterator_init(peer->contacts, 0);
		struct sofia_contact *ct;
		while ((ct = ao2_iterator_next(&ci))) {
			time_t c_exp;
			struct ast_sockaddr c_src;
			ao2_lock(ct);
			c_exp = ct->expires;
			ast_sockaddr_copy(&c_src, &ct->src_addr);
			ao2_unlock(ct);
			/* Self-call park: the caller's own binding never counts as a wake target. */
			{
				char ct_inst[128];
				ao2_lock(ct);
				ast_copy_string(ct_inst, ct->instance_id, sizeof(ct_inst));
				ao2_unlock(ct);
				if (sofia_selfcall_contact_excluded(&c_src, ct_inst,
						e->exclude_valid ? &e->exclude_src : NULL,
						e->exclude_instance[0] ? e->exclude_instance : NULL)
						|| sofia_push_held_not_woken(e, pvt, ct_inst)) {	/* =hold: not dialed below */
					ao2_ref(ct, -1);
					continue;
				}
			}
			if (c_exp > now) {	/* sofia_contact_is_unexpired: RFC 3261 soft state */
				live++;
			}
			ao2_ref(ct, -1);
		}
		ao2_iterator_destroy(&ci);
	}

	ast_verb(3, "Sofia PUSH: %s peer='%s' - collect window closed: %d wakeable binding(s)%s\n",
		e->callid, e->peername, live, e->exclude_valid ? " (caller's own excluded)" : "");
	if (live == 0 || !peer) {
		/* Every binding lapsed inside the window (pathological): back under push_wait. */
		ao2_lock(e);
		if (e->state == SOFIA_PUSH_COLLECTING) {
			e->state = SOFIA_PUSH_PARKED;
		}
		ao2_unlock(e);
		ast_verb(2, "Sofia PUSH: %s peer='%s' - collect window closed with no live binding; parked until push_wait\n",
			e->callid, e->peername);
		goto done;
	}

	/* Claim and fork to every live binding - ALWAYS through the fork engine (one binding
	 * makes a 1-child fork) so a device waking LATER can still get a branch appended
	 * while the call rings: on Android the wake REGISTER only goes out after the user
	 * ACCEPTS the push card, easily 10-30 s after the push. */
	ao2_lock(e);
	if (e->state != SOFIA_PUSH_COLLECTING) {
		ao2_unlock(e);
		goto done;
	}
	e->state = SOFIA_PUSH_RESUMING;
	ao2_unlock(e);
	sofia_push_park_cancel_timer(e);

	if (!pvt || !sofia_nua) {
		goto fail_call;
	}
	/* Owner snapshot+ref under pvt->lock; commit under the channel lock (the same
	 * discipline as sofia_push_resume_one - a racing sofia_hangup is excluded). */
	ast_mutex_lock(&pvt->lock);
	owner = pvt->owner;
	if (owner) {
		ast_channel_ref(owner);
	}
	ast_mutex_unlock(&pvt->lock);
	if (!owner) {
		goto orphan;
	}
	ast_channel_lock(owner);
	ast_mutex_lock(&pvt->lock);
	if (pvt->owner != owner || pvt->nh || pvt->fork || !pvt->push_parked) {
		ast_mutex_unlock(&pvt->lock);
		ast_channel_unlock(owner);
		ast_channel_unref(owner);
		owner = NULL;
		goto orphan;	/* hangup/masquerade won between snapshot and lock */
	}
	/* Every fork branch inherits this as its Call-ID = the push uuid. */
	ast_copy_string(pvt->sip_callid, e->callid, sizeof(pvt->sip_callid));
	pvt->push_parked = 0;
	if (pvt->push_park_held) {
		/* =hold: the old bindings of the devices pushed first that have not woken yet are left out; each gets its
		 * INVITE on the binding of its own REGISTER, by late append (RFC 8599 §5.6.2). push_held_inst holds every
		 * held device (sofia_request_call); keep only those not in woken_inst. */
		int k, w, n = 0;

		ao2_lock(e);
		for (k = 0; k < pvt->push_held_n; k++) {
			for (w = 0; w < e->nwoken && strcasecmp(e->woken_inst[w], pvt->push_held_inst[k]); w++) {
			}
			if (w == e->nwoken) {
				if (n != k) {
					ast_copy_string(pvt->push_held_inst[n], pvt->push_held_inst[k], sizeof(pvt->push_held_inst[0]));
				}
				n++;
			}
		}
		ao2_unlock(e);
		pvt->push_held_n = n;
	}
	ast_mutex_unlock(&pvt->lock);

	rc = sofia_fork_dial(pvt, 0);	/* the sofia_call live>1 engine, under the channel lock */
	ast_channel_unlock(owner);
	ast_channel_unref(owner);
	owner = NULL;
	if (rc) {
		goto fail_call;
	}
	/* Seed the late-append dedup table with the REGISTER sources the fork just dialed
	 * (gather OUTSIDE the entry lock - the entry lock is a leaf, contact locks must not
	 * nest under it), mark the pvt so hangup still reaps the entry, and leave the entry
	 * linked in APPENDING: every wake REGISTER until answer/hangup gets its own branch.
	 * (A REGISTER racing the posting above saw RESUMING and was skipped - that device
	 * does not ring this call, exactly the pre-multi-ring behavior - except a device left out
	 * by =hold, rechecked below.) */
	{
		struct ast_sockaddr got[SOFIA_PUSH_MAX_DEVICES];
		char got_inst[SOFIA_PUSH_MAX_DEVICES][128];
		int ngot = 0, gi;

		for (nskip = 0; nskip < pvt->push_held_n; nskip++) {
			ast_copy_string(skip_inst[nskip], pvt->push_held_inst[nskip], sizeof(skip_inst[0]));
		}
		if (peer && peer->contacts) {
			time_t now2 = time(NULL);
			struct ao2_iterator ci2 = ao2_iterator_init(peer->contacts, 0);
			struct sofia_contact *ct2;
			while ((ct2 = ao2_iterator_next(&ci2))) {
				time_t x2;
				int hk, skipped = 0;
				ao2_lock(ct2);
				x2 = ct2->expires;
				for (hk = 0; ct2->instance_id[0] && hk < pvt->push_held_n; hk++) {
					if (!strcasecmp(ct2->instance_id, pvt->push_held_inst[hk])) {
						skipped = 1;	/* left out of the fork above: its REGISTER must still append */
						break;
					}
				}
				if (x2 > now2 && !skipped && ngot < SOFIA_PUSH_MAX_DEVICES) {
					ast_sockaddr_copy(&got[ngot], &ct2->src_addr);
					ast_copy_string(got_inst[ngot], ct2->instance_id, sizeof(got_inst[0]));
					ngot++;
				}
				ao2_unlock(ct2);
				ao2_ref(ct2, -1);
			}
			ao2_iterator_destroy(&ci2);
			pvt->push_held_n = 0;
		}
		ao2_lock(e);
		for (gi = 0; gi < ngot; gi++) {
			ast_sockaddr_copy(&e->dialed[gi], &got[gi]);
			ast_copy_string(e->dialed_inst[gi], got_inst[gi], sizeof(e->dialed_inst[0]));
		}
		e->ndialed = ngot;
		e->state = SOFIA_PUSH_APPENDING;
		ao2_unlock(e);
	}
	ast_mutex_lock(&pvt->lock);
	pvt->push_appending = 1;
	ast_mutex_unlock(&pvt->lock);
	if (nskip && peer && peer->contacts) {
		/* =hold, commit-then-recheck: a device left out above whose wake REGISTER came while the fork was being
		 * posted (the entry was RESUMING, so that REGISTER was not taken) joins now, on the binding it refreshed,
		 * through the late-append path. */
		struct ao2_iterator ri = ao2_iterator_init(peer->contacts, 0);
		struct sofia_contact *rc2;

		while ((rc2 = ao2_iterator_next(&ri))) {
			struct sofia_register_update u;
			char r_inst[128];
			time_t r_reg;
			int k, late = 0;

			memset(&u, 0, sizeof(u));
			ao2_lock(rc2);
			ast_copy_string(r_inst, rc2->instance_id, sizeof(r_inst));
			r_reg = rc2->last_register;
			ast_sockaddr_copy(&u.new_src, &rc2->src_addr);
			ao2_unlock(rc2);
			ao2_ref(rc2, -1);
			for (k = 0; r_inst[0] && k < nskip; k++) {
				if (!strcasecmp(r_inst, skip_inst[k])) {
					late = r_reg >= e->parked_at;
					break;
				}
			}
			if (late) {
				sofia_push_resume_one(e, peer, &u);
			}
		}
		ao2_iterator_destroy(&ri);
	}
	ast_verb(2, "Sofia PUSH: resumed %s peer='%s' -> multi-ring INVITE to %d binding(s) after %lds parked; late wakers join while it rings\n",
		e->callid, e->peername, live, (long) waited);
	sofia_push_log_event(e->peername, "", e->callid, "resumed", "multi");
	goto done;

fail_call:
	/* Claimed but could not deliver: the call must not dangle - NOANSWER it, outside
	 * every lock (the queue takes the channel lock). */
	{
		struct ast_channel *o2 = NULL;
		if (pvt) {
			ast_mutex_lock(&pvt->lock);
			o2 = pvt->owner;
			if (o2) {
				ast_channel_ref(o2);
			}
			ast_mutex_unlock(&pvt->lock);
		}
		if (o2) {
			ast_queue_hangup_with_cause(o2, AST_CAUSE_NO_ANSWER);
			ast_channel_unref(o2);
		}
	}
	ast_log(LOG_WARNING, "Sofia PUSH: multi-ring resume of %s peer='%s' failed - call ends NOANSWER\n",
		e->callid, e->peername);
	sofia_push_log_event(e->peername, "", e->callid, "orphaned", "resume_failed");
	sofia_push_send_cancels(e, "cancelled", NULL);
	goto cleanup;

orphan:
	ast_verb(2, "Sofia PUSH: multi-ring resume of %s peer='%s' aborted - caller already gone\n",
		e->callid, e->peername);
	sofia_push_log_event(e->peername, "", e->callid, "orphaned", "caller_gone");
	sofia_push_send_cancels(e, "cancelled", NULL);
cleanup:
	ao2_lock(e);
	e->state = SOFIA_PUSH_DONE;
	ao2_unlock(e);
	if (sofia_push_parked) {
		ao2_unlink(sofia_push_parked, e);
	}
done:
	if (peer) {
		ao2_ref(peer, -1);
	}
	ao2_ref(e, -1);		/* the arm-time ref */
	return 0;
}

/* Scan-and-resume every parked call of this peer. Runs for ANY successful REGISTER of
 * the account (with or without push headers — a desk phone binding delivers the call
 * too, Kamailio ts_append parity), and even if push= was just turned off: delivering an
 * already-parked call is strictly correct. */
/* Hybrid push-assist: count the peer's push targets — the ASLEEP devices (a usable cached token whose
 * +sip.instance is neither the caller's (self-call) nor any of the devices already ringing, a live binding
 * was forked to them) and the live devices that are pushed even when live (iOS VoIP,
 * sofia_push_device_pushed_when_live). Returns how many would be pushed. Any thread; takes only the cache
 * entry lock. */
int sofia_push_count_asleep(struct sofia_peer *peer, const char *exclude_instance,
	char live_inst[][128], int n_live)
{
	struct sofia_push_tokens *e;
	time_t now = time(NULL);
	int i, asleep = 0;

	if (!peer || !(e = sofia_push_entry_get(peer->name, 0))) {
		return 0;
	}
	ao2_lock(e);
	for (i = 0; i < e->ndev; i++) {
		int li, live = 0;
		if (sofia_push_device_stale(&e->dev[i], now)) {
			continue;
		}
		if (exclude_instance && exclude_instance[0] && e->dev[i].instance[0]
				&& !strcasecmp(e->dev[i].instance, exclude_instance)) {
			continue;	/* the caller's own device */
		}
		for (li = 0; li < n_live; li++) {
			if (e->dev[i].instance[0] && !strcasecmp(e->dev[i].instance, live_inst[li])) {
				live = 1;
				break;
			}
		}
		if (!live || sofia_push_device_pushed_when_live(&e->dev[i])) {
			asleep++;	/* has a token, no live binding (a wake target), or pushed even when live */
		}
	}
	ao2_unlock(e);
	ao2_ref(e, -1);
	return asleep;
}

/* Hybrid push-assist: the call is already ringing the peer's LIVE devices through the fork
 * master `pvt` (its sip_callid seeds every branch). Wake the ASLEEP devices too by pushing
 * them with that same Call-ID and leaving a parked-registry entry in APPENDING state, so
 * when a woken device re-registers the existing late-append path adds it a fork branch
 * (the phone dedups push+INVITE by the shared uuid). The fork was posted held open
 * (sofia_fork_dial push_hold) so a live binding that fails at once cannot end the call before
 * a woken device joins; push_wait bounds that hold (released on expiry, or once every pushed
 * device has joined), after which the branches own the call outcome. The entry is reaped by
 * sofia_push_on_pvt_hangup when the master tears down. Caller holds the channel lock; pvt is a live fork master with
 * sip_callid set and (for a self-call) the exclude fields populated.
 *
 * The push carries the REAL caller identity (sofia_push_caller_id), as the parked path does:
 * a woken device shows the notification before its late-appended INVITE arrives, and on some
 * platforms the incoming-call UI is built from the notification alone, so a placeholder here
 * is what the callee would see as the caller. */
int sofia_push_assist_wake(struct sofia_pvt *pvt, struct ast_channel *ast,
	struct ast_sockaddr *live_srcs, char live_inst[][128], int n_live)
{
	struct sofia_push_park *e;
	int i, queued, rate_limited = 0, held = 0;

	if (!sofia_push_parked || !pvt || !ast || !pvt->sip_callid[0]) {
		return 0;
	}
	if (!(e = ao2_alloc(sizeof(*e), sofia_push_park_destructor))) {
		return 0;
	}
	ast_copy_string(e->peername, pvt->peername, sizeof(e->peername));
	ast_copy_string(e->exclude_instance, pvt->push_exclude_instance, sizeof(e->exclude_instance));
	if (pvt->fork_exclude_valid) {
		ast_sockaddr_copy(&e->exclude_src, &pvt->fork_exclude_src);
		e->exclude_valid = 1;
	}
	ast_copy_string(e->callid, pvt->sip_callid, sizeof(e->callid));
	/* Caller identity for the push payload, same source and lock contract as the parked
	 * path: the channel lock is held by ast_call. */
	sofia_push_caller_id(ast, e->cid_num, sizeof(e->cid_num), e->cid_name, sizeof(e->cid_name));
	e->pvt = pvt;
	ao2_ref(pvt, +1);
	e->sched_id = -1;
	e->collect_sched_id = -1;
	e->state = SOFIA_PUSH_APPENDING;	/* the fork already went out; only late appends from here */
	e->collected = 1;			/* stragglers append immediately, never a fresh collect window */
	e->parked_at = time(NULL);
	/* Seed the dedup with the live bindings' sources (never re-dial a device already ringing)
	 * and their instances (never push a device already ringing). Bounded by MAX_DEVICES. */
	for (i = 0; i < n_live && i < SOFIA_PUSH_MAX_DEVICES; i++) {
		ast_sockaddr_copy(&e->dialed[i], &live_srcs[i]);
		ast_copy_string(e->live_inst[i], live_inst[i], sizeof(e->live_inst[i]));
		ast_copy_string(e->dialed_inst[i], live_inst[i], sizeof(e->dialed_inst[i]));
	}
	e->ndialed = (n_live < SOFIA_PUSH_MAX_DEVICES) ? n_live : SOFIA_PUSH_MAX_DEVICES;
	e->n_live_inst = e->ndialed;

	if (!ao2_link(sofia_push_parked, e)) {
		ao2_ref(e, -1);
		return 0;
	}
	/* Mark the master so its hangup reaps this entry (push_appending gates the hook). */
	ast_mutex_lock(&pvt->lock);
	pvt->push_appending = 1;
	ast_mutex_unlock(&pvt->lock);

	queued = sofia_push_notify_devices(e, &rate_limited, 0);
	if (!queued && !rate_limited) {
		/* No asleep device could be pushed (all rang, or none usable): nothing to assist.
		 * Drop the entry; the fork to the live devices stands on its own. */
		ast_mutex_lock(&pvt->lock);
		pvt->push_appending = 0;
		ast_mutex_unlock(&pvt->lock);
		ao2_unlink(sofia_push_parked, e);
		ao2_ref(e, -1);
		return 0;
	}
	{
		int pushed_live, pushed_asleep;
		char live_insts[SOFIA_PUSH_MAX_DEVICES][128];

		ao2_lock(e);
		pushed_live = e->npushed_live;
		pushed_asleep = e->npushed - e->npushed_live;
		memcpy(live_insts, e->pushed_live_inst, sizeof(live_insts));
		ao2_unlock(e);
		ast_verb(2, "Sofia PUSH: push-assist %s peer='%s' - ringing %d live device(s)%s%s\n",
			e->callid, e->peername, n_live, pushed_asleep || rate_limited ? ", woke the asleep one(s)" : "",
			pushed_live ? ", pushed the live iOS one(s) too" : "");
		sofia_push_log_event(e->peername, "", e->callid, "sent", "assist");
		if (!pushed_asleep && !rate_limited) {
			/* Every pushed device already rings on its live binding. The fork is held (below) only for one of
			 * them coming back on a new connection after the stack failed its branch (the dead flow of an app iOS
			 * suspended): a final response the device itself sends (486, 603...) ends the call at once, as
			 * without the push (sofia_fork_push_hold_live_only). */
			sofia_fork_push_hold_live_only(pvt, live_insts, pushed_live);
		}
	}
	/* push_wait bounds the fork's hold (sofia_fork_dial push_hold): when it fires,
	 * sofia_push_wait_cb releases the hold and the call ends if every branch has failed by
	 * then. Armed under the entry lock (defer-BYE idiom, as sofia_push_park_create). With no
	 * timer there is no hold: the caller releases it at once. */
	if (sofia_sched) {
		ao2_lock(e);
		ao2_ref(e, +1);		/* the timer's ref */
		e->sched_id = ast_sched_thread_add(sofia_sched, sofia_cfg.push_wait * 1000, sofia_push_wait_cb, e);
		if (e->sched_id < 0) {
			e->sched_id = -1;
			ao2_unlock(e);
			ao2_ref(e, -1);	/* timer ref rollback */
		} else {
			ao2_unlock(e);
			held = 1;
		}
	}
	ao2_ref(e, -1);		/* container holds the entry; hangup reaps it */
	return held;
}

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
			/* Self-call park: the CALLING device's own re-REGISTER (refresh, or a NAT
			 * rebinding from a NEW source - recognized by instance) must not resume
			 * the park it created - the wake we wait for is one of the OTHER devices. */
			if ((pe->exclude_valid || pe->exclude_instance[0])
					&& update && !ast_sockaddr_isnull(&update->new_src)) {
				int own = pe->exclude_valid
					&& !ast_sockaddr_cmp(&update->new_src, &pe->exclude_src);
				if (!own && pe->exclude_instance[0]) {
					struct sofia_contact *rc = sofia_peer_find_contact_by_addr(peer, &update->new_src);
					if (rc) {
						char rinst[128];
						ao2_lock(rc);
						ast_copy_string(rinst, rc->instance_id, sizeof(rinst));
						ao2_unlock(rc);
						ao2_ref(rc, -1);
						own = rinst[0] && !strcasecmp(rinst, pe->exclude_instance);
					}
				}
				if (own) {
					ast_debug(1, "Sofia PUSH: %s peer='%s' - caller's own REGISTER, not a wake\n",
						pe->callid, pe->peername);
					ao2_ref(pe, -1);
					continue;
				}
			}
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

/* ---------- silent re-register before a registration ends (P3; scheduled, survives a restart) ----------
 *
 * Every device whose stored token is an FCM one gets ONE `type=reregister` push (the phone contract: "server
 * sends this ~2 min before SIP registration expires") at reg_expires - push_reregister_lead. The schedule is
 * kept nowhere else than in the token rows: reg_expires is written on every REGISTER and last_push_at after
 * every push, both in push_tokens (the local SQLite), and the whole table is read back at load
 * (sofia_push_init). So a restart loses no scheduled push: after the load every due time is computed again
 * from what the database holds. A push that fell due while gabpbx was down goes out within
 * SOFIA_PUSH_REREG_SPREAD seconds of the first tick, at a fixed per-device offset, never all together; a
 * registration that ended more than SOFIA_PUSH_REREG_LATE_MAX seconds ago is not chased (the call push still
 * wakes that phone), and neither is one shorter than 2 * (lead + SOFIA_PUSH_REREG_JITTER) (the live app refreshes
 * it itself, and a push per half-life would never stop). Each device also goes 0..SOFIA_PUSH_REREG_JITTER-1 s earlier (fixed per device), so phones
 * that registered together (every phone right after a restart) do not stay due together. A tick sends at most
 * SOFIA_PUSH_REREG_PER_TICK pushes and none while the token database queue is loaded; the native lane gives these
 * pushes a quarter of its queue, so a call push always finds room. The rest wait for the next tick.
 *
 * NATIVE sender only and FCM-shaped only, whatever push_sender says (the servers run no external sender for
 * these): never the script lane, and never an APNs VoIP push (Apple, PushKit:
 * a VoIP push must report a call to CallKit or iOS terminates the app), so a VoIP-token device gets none.
 * Runs on sofia_sched; takes only the cache entry locks (leaf) and queues on the native lane. */
#define SOFIA_PUSH_REREG_TICK_MS 5000
#define SOFIA_PUSH_REREG_PER_TICK 20
#define SOFIA_PUSH_REREG_SPREAD 120
#define SOFIA_PUSH_REREG_JITTER 60
#define SOFIA_PUSH_REREG_LATE_MAX 1800

struct sofia_push_rereg_job {
	char peer[128];
	char device_id[SOFIA_PUSH_DEVID_MAX];
	char token[SOFIA_PUSH_TOKEN_MAX];
	time_t reg_expires;
};

static int sofia_push_rereg_sched_id = -1;
static time_t sofia_push_rereg_t0;	/* when the schedule became active (load, or push turned back on): pushes due before it are spread */
static int sofia_push_rereg_active;	/* the previous tick passed the gates */
static time_t sofia_push_load_time;	/* sofia_push_init: rows older than this were written by the previous run */
static int sofia_push_restart_done;	/* the restart call_cancel check was queued for this load */
static volatile int sofia_push_restart_finished;	/* ... and has run: re-register pushes wait for it (the cancels get the lane first) */
static int sofia_push_restart_exe(void *data);

/* Fixed offset in [0, SOFIA_PUSH_REREG_SPREAD) for a push that fell due before the first tick. */
static int sofia_push_rereg_offset(const char *peer, const char *device_id)
{
	unsigned int h = 5381;
	const char *p;

	for (p = peer; *p; p++) {
		h = h * 33 + (unsigned char) ((*p >= 'A' && *p <= 'Z') ? *p + 32 : *p);
	}
	for (p = device_id; *p; p++) {
		h = h * 33 + (unsigned char) ((*p >= 'A' && *p <= 'Z') ? *p + 32 : *p);
	}
	return (int) (h % SOFIA_PUSH_REREG_SPREAD);
}

/* When the device's re-register push is due; 0 = none for it now (not an FCM token, stale token, no stored
 * expiry, a registration that ended too long ago, or already pushed for this registration). Entry lock held. */
static time_t sofia_push_rereg_due(const char *peername, const struct sofia_push_device *d, time_t now)
{
	time_t due;

	if (strcasecmp(d->push_type, "fcm") || !d->token[0] || d->reg_expires <= 0) {
		return 0;
	}
	if (sofia_push_device_stale(d, now) || d->reg_expires < now - SOFIA_PUSH_REREG_LATE_MAX) {
		return 0;
	}
	if (d->updated_at > 0 && d->reg_expires - d->updated_at < 2 * (sofia_cfg.push_reregister_lead + SOFIA_PUSH_REREG_JITTER)) {
		return 0;	/* a short registration: the live app refreshes it itself, and a push per half-life would never stop */
	}
	due = d->reg_expires - sofia_cfg.push_reregister_lead - sofia_push_rereg_offset(peername, d->device_id) % SOFIA_PUSH_REREG_JITTER;
	if (d->updated_at > 0 && d->updated_at < d->reg_expires && due < d->updated_at + (d->reg_expires - d->updated_at) / 2) {
		due = d->updated_at + (d->reg_expires - d->updated_at) / 2;	/* a short registration: never before its half, so a push never follows its own REGISTER */
	}
	if (d->rereg_for == d->reg_expires || d->last_push_at >= due) {
		return 0;	/* queued in this run, or pushed (before a restart too: last_push_at is stored) */
	}
	if (sofia_push_rereg_t0 && due < sofia_push_rereg_t0) {
		due = sofia_push_rereg_t0 + sofia_push_rereg_offset(peername, d->device_id);	/* fell due while down */
	}
	return due;
}

/* A job the native lane did not take: forget the mark so a later tick tries again. */
static void sofia_push_rereg_unmark(const struct sofia_push_rereg_job *j)
{
	struct sofia_push_tokens *e = sofia_push_entry_get(j->peer, 0);
	int i;

	if (!e) {
		return;
	}
	ao2_lock(e);
	for (i = 0; i < e->ndev; i++) {
		if (!strcasecmp(e->dev[i].device_id, j->device_id) && e->dev[i].rereg_for == j->reg_expires) {
			e->dev[i].rereg_for = 0;
			break;
		}
	}
	ao2_unlock(e);
	ao2_ref(e, -1);
}

/* ---------- push_log retention ----------
 *
 * push_log only grows (one row per push step). push_log_retention days (0 = keep everything) bound it: every night at
 * push_log_purge_time (local time) the rows older than that go, on the database lane (the only writer, so no write of
 * ours ever waits on the engine's lock). One run removes at most one day of rows, counted from the oldest one left
 * (ts < X LIMIT 1, an index lookup with push_log(ts)), so a long backlog (the first night, a lowered retention) never
 * holds the database for long: the next tick takes the next day. The engine's delete must take an operator in the
 * field name ("ts <"), as res_config_sqlite3 does; a delete that fails (an engine without it, a full disk, a database
 * an operator holds) is reported and tried again the next night. A run acts on the settings it was planned with,
 * never on ones a reload is still applying. The restart check reads only the last push_wait +
 * SOFIA_PUSH_RESTART_LOOKBACK seconds. */
#define SOFIA_PUSH_PURGE_SLICE 86400	/* at most one day of rows per run */

static volatile time_t sofia_push_purge_next;
static volatile int sofia_push_purge_inflight;
static volatile int sofia_push_purge_failed;	/* nights in a row the delete failed (sip show push) */
/* the settings sofia_push_purge_next was planned with (sched thread only): a change re-plans instead of running */
static int sofia_push_purge_planned_for = -1, sofia_push_purge_planned_days = -1;
static int sofia_push_purge_total, sofia_push_purge_runs;	/* this night's purge so far (database lane only) */

struct sofia_push_purge_job {
	int days;	/* the retention this run applies */
	int minute;	/* the push_log_purge_time the next night is planned for */
};

/* the next push_log_purge_time (minutes after local midnight) strictly after now */
static time_t sofia_push_purge_next_at(time_t now, int minute)
{
	struct timeval tv = { .tv_sec = now }, at;
	struct ast_tm base, tm;
	int day;

	ast_localtime(&tv, &base, NULL);
	for (day = 0; day < 3; day++) {
		tm = base;
		tm.tm_mday += day;	/* ast_mktime normalises the month end */
		tm.tm_hour = minute / 60;
		tm.tm_min = minute % 60;
		tm.tm_sec = 0;
		tm.tm_usec = 0;
		tm.tm_isdst = -1;	/* whatever the offset is on that day */
		at = ast_mktime(&tm, NULL);
		if (at.tv_sec > now) {
			return at.tv_sec;
		}
	}
	return now + 86400;
}

static int sofia_push_log_purge_exe(void *data)
{
	struct sofia_push_purge_job *job = data;
	int days = job->days, more = 0, failed = 0, n;
	time_t now = time(NULL), cutoff, oldest = 0, upto;
	struct ast_variable *row, *v;
	char cut_s[24], upto_s[24];

	if (ast_check_realtime("pushlog")) {
		cutoff = now - (time_t) days * 86400;
		snprintf(cut_s, sizeof(cut_s), "%ld", (long) cutoff);
		if ((row = ast_load_realtime("pushlog", "ts <", cut_s, SENTINEL))) {
			for (v = row; v; v = v->next) {
				if (!strcasecmp(v->name, "ts")) {
					oldest = (time_t) strtol(v->value, NULL, 10);
				}
			}
			ast_variables_destroy(row);
			upto = (oldest > 0 && oldest < cutoff - SOFIA_PUSH_PURGE_SLICE) ? oldest + SOFIA_PUSH_PURGE_SLICE : cutoff;
			more = upto < cutoff;
			snprintf(upto_s, sizeof(upto_s), "%ld", (long) upto);
			if ((n = ast_destroy_realtime("pushlog", "ts <", upto_s, SENTINEL)) < 0) {
				failed = 1;
				more = 0;
			} else {
				sofia_push_purge_total += n;
				sofia_push_purge_runs++;
				ast_verb(4, "Sofia PUSH: push_log retention: %d row(s) before %s removed%s\n", n, upto_s,
					more ? ", older ones next" : "");
			}
		}
	}
	if (!more && sofia_push_purge_total > 0) {
		/* one line a night: the whole purge, however many steps it took */
		ast_verb(3, "Sofia PUSH: push_log retention (%d day(s)): %d row(s) removed in %d step(s)\n",
			days, sofia_push_purge_total, sofia_push_purge_runs);
	}
	if (!more) {
		sofia_push_purge_total = sofia_push_purge_runs = 0;
	}
	if (failed) {
		sofia_push_purge_failed++;
		ast_log(LOG_WARNING, "Sofia PUSH: push_log retention: the database refused the delete (%d night(s) in a row) - next try at %02d:%02d\n",
			sofia_push_purge_failed, job->minute / 60, job->minute % 60);
	} else if (!more) {
		sofia_push_purge_failed = 0;
	}
	/* a backlog goes on at the next tick; otherwise the next night */
	sofia_push_purge_next = more ? now + SOFIA_PUSH_REREG_TICK_MS / 1000 : sofia_push_purge_next_at(now, job->minute);
	ast_free(job);
	sofia_push_purge_inflight = 0;
	return 0;
}

/* from the 5 s tick, whatever the push lanes do: the rows of a box whose sender is down still age out */
static void sofia_push_log_purge_check(time_t now)
{
	int days = sofia_cfg.push_log_retention, minute = sofia_cfg.push_log_purge_minute;
	struct sofia_push_purge_job *job;

	if (days <= 0 || !sofia_pushdb_tps) {
		sofia_push_purge_planned_for = sofia_push_purge_planned_days = -1;	/* turned back on: planned afresh */
		return;
	}
	if (sofia_push_purge_inflight) {
		return;
	}
	if (sofia_push_purge_planned_for != minute || sofia_push_purge_planned_days != days) {
		/* the load, or a reload that changed a setting (or is still applying it): plan, never run, this tick */
		if (sofia_push_purge_planned_for != minute || !sofia_push_purge_next) {
			sofia_push_purge_next = sofia_push_purge_next_at(now, minute);
		}
		sofia_push_purge_planned_for = minute;
		sofia_push_purge_planned_days = days;
		return;
	}
	if (now < sofia_push_purge_next || sofia_pushdb_depth > SOFIA_PUSH_DBQ_MAX / 4) {
		return;	/* not yet, or the token and log writes are behind: they come first */
	}
	if (!(job = ast_calloc(1, sizeof(*job)))) {
		return;	/* the next tick tries again */
	}
	job->days = days;
	job->minute = minute;
	sofia_push_purge_inflight = 1;
	if (ast_taskprocessor_push(sofia_pushdb_tps, sofia_push_log_purge_exe, job)) {
		ast_free(job);
		sofia_push_purge_inflight = 0;
		sofia_push_purge_next = sofia_push_purge_next_at(now, minute);
	}
}

static int sofia_push_rereg_tick(const void *data)
{
	struct sofia_push_rereg_job *jobs;
	struct ao2_iterator it;
	struct sofia_push_tokens *te;
	time_t now = time(NULL), next = 0;
	int n = 0, planned = 0, first = 0, i;

	sofia_push_log_purge_check(now);
	if (!sofia_cfg.push_enabled || !sofia_push_cache || !sofia_push_cache_complete || !sofia_push_sender_available()) {
		sofia_push_rereg_active = 0;	/* native only: a later tick retries, never the scripts */
		return SOFIA_PUSH_REREG_TICK_MS;
	}
	if (!sofia_push_restart_done) {
		/* once per load, on the database lane (it reads push_log): the parked calls the restart cut */
		sofia_push_restart_done = 1;
		if (!sofia_pushdb_tps || ast_taskprocessor_push(sofia_pushdb_tps, sofia_push_restart_exe, NULL)) {
			ast_log(LOG_WARNING, "Sofia PUSH: could not queue the restart call_cancel check\n");
			sofia_push_restart_finished = 1;
		}
	}
	if (!sofia_push_restart_finished) {
		return SOFIA_PUSH_REREG_TICK_MS;	/* the restart cancels take the native lane first */
	}
	if (!sofia_cfg.push_reregister) {
		sofia_push_rereg_active = 0;
		return SOFIA_PUSH_REREG_TICK_MS;
	}
	if (sofia_pushdb_depth > SOFIA_PUSH_DBQ_MAX / 4) {
		return SOFIA_PUSH_REREG_TICK_MS;	/* the token database is behind: its writes (the schedule itself) come first */
	}
	if (!sofia_push_rereg_active) {
		sofia_push_rereg_active = 1;	/* loaded, or turned back on: rebuild and spread what is overdue */
		sofia_push_rereg_t0 = now;
		first = 1;
	}
	if (!(jobs = ast_calloc(SOFIA_PUSH_REREG_PER_TICK, sizeof(*jobs)))) {
		return SOFIA_PUSH_REREG_TICK_MS;
	}
	it = ao2_iterator_init(sofia_push_cache, 0);
	while ((te = ao2_iterator_next(&it))) {
		ao2_lock(te);
		for (i = 0; i < te->ndev; i++) {
			struct sofia_push_device *d = &te->dev[i];
			time_t due = sofia_push_rereg_due(te->peername, d, now);

			if (!due) {
				continue;
			}
			if (due > now || n >= SOFIA_PUSH_REREG_PER_TICK) {
				planned++;
				if (!next || due < next) {
					next = due;
				}
				continue;
			}
			d->rereg_for = d->reg_expires;
			ast_copy_string(jobs[n].peer, te->peername, sizeof(jobs[n].peer));
			ast_copy_string(jobs[n].device_id, d->device_id, sizeof(jobs[n].device_id));
			ast_copy_string(jobs[n].token, d->token, sizeof(jobs[n].token));
			jobs[n].reg_expires = d->reg_expires;
			n++;
		}
		ao2_unlock(te);
		ao2_ref(te, -1);
	}
	ao2_iterator_destroy(&it);

	if (first) {
		char nexts[32] = "";
		if (next) {
			snprintf(nexts, sizeof(nexts), ", next in %lds", (long) (next > now ? next - now : 0));
		}
		ast_verb(2, "Sofia PUSH: re-register schedule rebuilt from the database: %d push(es) due now, %d planned%s\n",
			n, planned, nexts);
	}
	for (i = 0; i < n; i++) {
		char red[64];
		int rc = sofia_push_sender_submit(SOFIA_PUSH_PURPOSE_REREGISTER, "fcm", jobs[i].token, jobs[i].peer, "",
			"reregister", jobs[i].peer, jobs[i].device_id, NULL);

		if (rc) {
			int k;
			for (k = i; k < n; k++) {
				sofia_push_rereg_unmark(&jobs[k]);	/* this one and the rest: a later tick */
			}
			ast_debug(1, "Sofia PUSH: re-register push for peer '%s' dev '%s' not queued (%s) - next tick\n",
				jobs[i].peer, jobs[i].device_id, rc > 0 ? "native lane cannot serve" : "native queue share full");
			break;
		}
		ast_verb(3, "Sofia PUSH: re-register push queued peer='%s' dev='%s' token=%s registration ends in %lds\n",
			jobs[i].peer, jobs[i].device_id, sofia_push_redact(jobs[i].token, red, sizeof(red)),
			(long) (jobs[i].reg_expires - now));
	}
	ast_free(jobs);
	return SOFIA_PUSH_REREG_TICK_MS;
}

/* ---------- parked calls a restart cut: their call_cancel, from push_log ----------
 *
 * A parked call lives in RAM only (sofia_push_parked, its timers on sofia_sched, the native queue): a restart
 * ends the call, and nothing would tell the Android phones that showed its card. push_log (the local SQLite)
 * holds every step: "parked" (or a "sent" with no device for an assist / no-response / renotify push), a "sent"
 * per pushed device, a "cancel" per cancelled device, and the end ("resumed", "timeout", "caller_hangup",
 * "orphaned", "unparked"). So once per load, on the database lane, the rows the PREVIOUS run wrote in its last
 * push_wait + SOFIA_PUSH_RESTART_LOOKBACK seconds (ts before sofia_push_load_time) are read: a call with no end
 * row was cut, and every Android device pushed for it and not cancelled yet gets the call_cancel the call would
 * have sent (reason=cancelled). An iPhone gets nothing (never an APNs push that is not a call). Each such call is
 * then closed with "orphaned"/"restart", so a second restart does not cancel it again. Native sender only. The
 * ended calls are collected first, so a busy window cannot crowd the cut ones out of the bounded arrays. */
#define SOFIA_PUSH_RESTART_LOOKBACK 180
#define SOFIA_PUSH_RESTART_MAX_CALLS 256
#define SOFIA_PUSH_RESTART_MAX_ENDED 1024
#define SOFIA_PUSH_RESTART_MAX_DEVS SOFIA_PUSH_MAX_DEVICES

struct sofia_push_cut_call {
	char peer[128];
	char callid[64];
	char cid_num[80];
	int ndev;
	char dev[SOFIA_PUSH_RESTART_MAX_DEVS][SOFIA_PUSH_DEVID_MAX];
	int devcancelled[SOFIA_PUSH_RESTART_MAX_DEVS];
};

struct sofia_push_log_row {
	const char *peer, *dev, *callid, *event, *detail;
};

static void sofia_push_log_row_read(struct ast_config *cfg, const char *cat, struct sofia_push_log_row *r)
{
	const struct ast_variable *v;

	r->peer = r->dev = r->callid = r->event = r->detail = "";
	for (v = ast_variable_browse(cfg, cat); v; v = v->next) {
		if (!strcasecmp(v->name, "peer")) {
			r->peer = v->value;
		} else if (!strcasecmp(v->name, "device_id")) {
			r->dev = v->value;
		} else if (!strcasecmp(v->name, "callid")) {
			r->callid = v->value;
		} else if (!strcasecmp(v->name, "event")) {
			r->event = v->value;
		} else if (!strcasecmp(v->name, "detail")) {
			r->detail = v->value;
		}
	}
}

static int sofia_push_log_row_is_end(const struct sofia_push_log_row *r)
{
	return !strcmp(r->event, "resumed") || !strcmp(r->event, "timeout") || !strcmp(r->event, "caller_hangup")
		|| !strcmp(r->event, "orphaned") || !strcmp(r->event, "unparked");
}

static int sofia_push_restart_exe(void *data)
{
	struct sofia_push_cut_call *calls;
	char (*ended)[64];
	struct ast_config *cfg;
	char since[24], until[24], *cat;
	int ncalls = 0, nended = 0, i, k, ncut = 0, nsent = 0;

	if (!ast_check_realtime("pushlog")) {
		sofia_push_restart_finished = 1;
		return 0;
	}
	snprintf(since, sizeof(since), "%ld",
		(long) (sofia_push_load_time - sofia_cfg.push_wait - SOFIA_PUSH_RESTART_LOOKBACK));
	snprintf(until, sizeof(until), "%ld", (long) sofia_push_load_time);
	if (!(cfg = ast_load_realtime_multientry("pushlog", "ts >=", since, "ts <", until, SENTINEL))) {
		sofia_push_restart_finished = 1;
		return 0;	/* no rows in the window, or no table: nothing was cut */
	}
	calls = ast_calloc(SOFIA_PUSH_RESTART_MAX_CALLS, sizeof(*calls));
	ended = ast_calloc(SOFIA_PUSH_RESTART_MAX_ENDED, sizeof(*ended));
	if (!calls || !ended) {
		ast_free(calls);
		ast_free(ended);
		ast_config_destroy(cfg);
		sofia_push_restart_finished = 1;
		return 0;
	}
	/* pass 1: the ended calls */
	for (cat = NULL; (cat = ast_category_browse(cfg, cat)); ) {
		struct sofia_push_log_row r;
		sofia_push_log_row_read(cfg, cat, &r);
		if (r.callid[0] && sofia_push_log_row_is_end(&r) && nended < SOFIA_PUSH_RESTART_MAX_ENDED) {
			ast_copy_string(ended[nended++], r.callid, sizeof(ended[0]));
		}
	}
	/* pass 2: the opened calls that did not end */
	for (cat = NULL; (cat = ast_category_browse(cfg, cat)); ) {
		struct sofia_push_log_row r;
		struct sofia_push_cut_call *c = NULL;
		sofia_push_log_row_read(cfg, cat, &r);
		if (!r.callid[0] || !strcmp(r.callid, "reregister")
				|| !(!strcmp(r.event, "parked") || (!strcmp(r.event, "sent") && !r.dev[0]))) {
			continue;
		}
		for (i = 0; i < nended && strcmp(ended[i], r.callid); i++) {
		}
		if (i < nended) {
			continue;
		}
		for (i = 0; i < ncalls && strcmp(calls[i].callid, r.callid); i++) {
		}
		if (i < ncalls) {
			c = &calls[i];
		} else if (ncalls < SOFIA_PUSH_RESTART_MAX_CALLS) {
			c = &calls[ncalls++];
			ast_copy_string(c->peer, r.peer, sizeof(c->peer));
			ast_copy_string(c->callid, r.callid, sizeof(c->callid));
		}
		if (c && !strcmp(r.event, "parked")) {
			ast_copy_string(c->cid_num, r.detail, sizeof(c->cid_num));
		}
	}
	/* pass 3: the devices pushed for them, and those already cancelled */
	for (cat = NULL; ncalls && (cat = ast_category_browse(cfg, cat)); ) {
		struct sofia_push_log_row r;
		struct sofia_push_cut_call *c;
		sofia_push_log_row_read(cfg, cat, &r);
		if (!r.dev[0] || (strcmp(r.event, "sent") && strcmp(r.event, "cancel"))) {
			continue;
		}
		for (k = 0; k < ncalls && strcmp(calls[k].callid, r.callid); k++) {
		}
		if (k == ncalls) {
			continue;
		}
		c = &calls[k];
		for (i = 0; i < c->ndev && strcasecmp(c->dev[i], r.dev); i++) {
		}
		if (i == c->ndev) {
			if (c->ndev >= SOFIA_PUSH_RESTART_MAX_DEVS) {
				continue;
			}
			ast_copy_string(c->dev[i], r.dev, sizeof(c->dev[i]));
			c->ndev++;
		}
		if (!strcmp(r.event, "cancel")) {
			c->devcancelled[i] = 1;
		}
	}
	ast_config_destroy(cfg);

	for (k = 0; k < ncalls; k++) {
		struct sofia_push_cut_call *c = &calls[k];
		struct sofia_push_tokens *e;
		int sent = 0, refused = 0;

		ncut++;
		if ((e = sofia_push_entry_get(c->peer, 0))) {
			for (i = 0; i < c->ndev; i++) {
				char token[SOFIA_PUSH_TOKEN_MAX] = "";
				int j;

				if (c->devcancelled[i]) {
					continue;
				}
				ao2_lock(e);
				for (j = 0; j < e->ndev; j++) {
					if (!strcasecmp(e->dev[j].device_id, c->dev[i]) && !strcasecmp(e->dev[j].platform, "android")
							&& !strcasecmp(e->dev[j].push_type, "fcm")) {
						ast_copy_string(token, e->dev[j].token, sizeof(token));
						break;
					}
				}
				ao2_unlock(e);
				if (token[0]) {
					int tries = 0, rc;
					/* a full queue drains: give it a moment (this is the database thread, not sofia_sched);
					 * a lane that cannot serve (down, FCM credentials failing) is not retried */
					while ((rc = sofia_push_sender_submit(SOFIA_PUSH_PURPOSE_CANCEL, "fcm", token, c->cid_num,
							c->cid_num, c->callid, c->peer, c->dev[i], "cancelled")) < 0 && ++tries < 10) {
						usleep(200000);
					}
					if (rc) {
						refused++;
					} else {
						sent++;
					}
				}
			}
			ao2_ref(e, -1);
		}
		nsent += sent;
		if (refused) {
			/* not closed: a load within push_wait + SOFIA_PUSH_RESTART_LOOKBACK seconds of these rows tries again */
			ast_log(LOG_WARNING, "Sofia PUSH: call %s peer='%s' was parked when gabpbx stopped: %d call_cancel(s) could not be queued (native lane busy or down)\n",
				c->callid, c->peer, refused);
			continue;
		}
		sofia_push_log_event(c->peer, "", c->callid, "orphaned", "restart");
		ast_verb(2, "Sofia PUSH: call %s peer='%s' was parked when gabpbx stopped: call_cancel -> %d Android device(s)\n",
			c->callid, c->peer, sent);
	}
	if (ncut) {
		ast_verb(2, "Sofia PUSH: %d parked call(s) cut by the restart, %d call_cancel(s) queued\n", ncut, nsent);
	}
	ast_free(calls);
	ast_free(ended);
	sofia_push_restart_finished = 1;
	return 0;
}

void sofia_push_rereg_start(void)
{
	if (!sofia_sched || sofia_push_rereg_sched_id >= 0) {
		return;
	}
	sofia_push_rereg_sched_id = ast_sched_thread_add(sofia_sched, SOFIA_PUSH_REREG_TICK_MS, sofia_push_rereg_tick, NULL);
	if (sofia_push_rereg_sched_id < 0) {
		ast_log(LOG_WARNING, "Sofia PUSH: could not arm the re-register schedule - no re-register pushes\n");
	}
}

/* ---------- CLI: sip show push [peer] (tokens ALWAYS redacted) ---------- */

/* sip push purge <peer> <device-id>: forget a stored push token (cache + database), as a dead token is purged. For a
 * token left behind by an app that has stopped sending push headers but never un-registers it (an iOS app on a Mac
 * once it no longer asks for VoIP pushes); a device still sending them stores its token again at its next REGISTER. */
static char *sofia_push_cli_purge(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct sofia_push_tokens *te;
	char peer[128] = "", dev[SOFIA_PUSH_DEVID_MAX] = "";
	int i;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip push purge";
		e->usage = "Usage: sip push purge <peer> <device-id>\n"
			"       Forget the push token stored for that device of that peer (cache and database).\n"
			"       The next REGISTER with push headers stores it again.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}
	if (a->argc != 5) {
		return CLI_SHOWUSAGE;
	}
	if (!sofia_push_cache) {
		ast_cli(a->fd, "Push wake-up is not running\n");
		return CLI_SUCCESS;
	}
	/* the stored spelling: the cache matches case-insensitively, the database key is exact */
	if ((te = sofia_push_entry_get(a->argv[3], 0))) {
		ao2_lock(te);
		for (i = 0; i < te->ndev; i++) {
			if (!strcasecmp(te->dev[i].device_id, a->argv[4])) {
				ast_copy_string(peer, te->peername, sizeof(peer));
				ast_copy_string(dev, te->dev[i].device_id, sizeof(dev));
				break;
			}
		}
		ao2_unlock(te);
		ao2_ref(te, -1);
	}
	if (!dev[0]) {
		if (sofia_push_cache_complete) {
			ast_cli(a->fd, "Peer '%s' has no push token for device '%s'\n", a->argv[3], a->argv[4]);
			return CLI_SUCCESS;
		}
		/* lazy cache: the row may be in the database only; delete it as typed */
		ast_copy_string(peer, a->argv[3], sizeof(peer));
		ast_copy_string(dev, a->argv[4], sizeof(dev));
		ast_cli(a->fd, "Not in the cache (lazy mode): deleting '%s' '%s' from the database as typed\n", peer, dev);
	}
	if (sofia_push_forget_device(peer, dev, "purged", "token", "cli") < 0) {
		ast_cli(a->fd, "Removed from the cache, but the database delete was NOT queued (queue full or no database): "
			"run it again\n");
		return CLI_SUCCESS;
	}
	ast_cli(a->fd, "Purged the push token of peer '%s' device '%s'\n", peer, dev);
	return CLI_SUCCESS;
}

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
	ast_cli(a->fd, "Push wake-up: %s  sender=%s%s  scripts=%s  wait=%ds  noresponse=%ds  resume_window=%ds  voip_live=%s  fcm_live=%s  hold_exclude=%s  ttl=%dd  max_devices=%d  min_interval=%ds  cache=%s  queue=%d  natq=%d\n",
		sofia_cfg.push_enabled ? "ENABLED" : "disabled",
		sofia_cfg.push_sender_native ? "native" : "script",
		sofia_cfg.push_sender_native && !sofia_push_sender_available() ? "(lane DOWN: script fallback)" : "",
		sofia_cfg.push_scripts, sofia_cfg.push_wait, sofia_cfg.push_noresponse,
		sofia_cfg.push_resume_window, sofia_cfg.push_voip_live == 2 ? "hold" : sofia_cfg.push_voip_live ? "yes" : "no",
		sofia_cfg.push_fcm_live == 2 ? "hold" : sofia_cfg.push_fcm_live ? "yes" : "no",
		S_OR(sofia_cfg.push_hold_exclude, "-"),
		sofia_cfg.push_token_ttl_days,
		sofia_cfg.push_max_devices, sofia_cfg.push_min_interval,
		sofia_push_cache_complete ? "complete" : "lazy", sofia_pushdb_depth,
		sofia_push_sender_natq_depth());
	if (!sofia_push_cache) {
		return CLI_SUCCESS;
	}
	ast_cli(a->fd, "Re-register push: %s  lead=%ds  (native, FCM tokens only)\n",
		!(sofia_cfg.push_enabled && sofia_cfg.push_reregister) ? "off"
			: !sofia_push_cache_complete ? "on (waiting: token cache not complete)"
			: !sofia_push_sender_available() ? "on (waiting: native lane down)"
			: !sofia_push_restart_finished ? "on (waiting: restart call_cancel check)" : "on",
		sofia_cfg.push_reregister_lead);
	if (sofia_cfg.push_log_retention <= 0) {
		ast_cli(a->fd, "push_log retention: off (rows kept forever)\n");
	} else if (!ast_check_realtime("pushlog")) {
		ast_cli(a->fd, "push_log retention: %d day(s), idle: no pushlog family in extconfig.conf\n",
			sofia_cfg.push_log_retention);
	} else {
		char when[40], fail[64] = "";
		time_t nx = sofia_push_purge_next;

		if (!nx) {
			ast_copy_string(when, "not planned yet", sizeof(when));
		} else if (sofia_push_purge_inflight || nx <= now + SOFIA_PUSH_REREG_TICK_MS / 1000) {
			ast_copy_string(when, "running", sizeof(when));
		} else {
			snprintf(when, sizeof(when), "next in %ldh %02ldm", (long) (nx - now) / 3600, ((long) (nx - now) % 3600) / 60);
		}
		if (sofia_push_purge_failed) {
			snprintf(fail, sizeof(fail), ", last run failed (%d night(s) in a row)", sofia_push_purge_failed);
		}
		ast_cli(a->fd, "push_log retention: %d day(s), every night at %02d:%02d (%s)%s\n",
			sofia_cfg.push_log_retention, sofia_cfg.push_log_purge_minute / 60, sofia_cfg.push_log_purge_minute % 60,
			when, fail);
	}
	ast_cli(a->fd, "%-20s %-14s %-7s %-5s %-22s %8s %8s %-14s %5s %8s\n",
		"Peer", "Device", "Plat", "Type", "Token", "Age", "RegExp", "LastResult", "Fails", "ReReg");
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
				char red[64], rr[16];
				time_t due = sofia_cfg.push_enabled && sofia_cfg.push_reregister
					? sofia_push_rereg_due(te->peername, &te->dev[i], now) : 0;
				if (due) {
					snprintf(rr, sizeof(rr), "%lds", (long) (due > now ? due - now : 0));
				} else {
					ast_copy_string(rr, "-", sizeof(rr));
				}
				ast_cli(a->fd, "%-20s %-14s %-7s %-5s %-22s %7lds %7lds %-14s %5d %8s\n",
					te->peername, te->dev[i].device_id, te->dev[i].platform,
					te->dev[i].push_type,
					sofia_push_redact(te->dev[i].token, red, sizeof(red)),
					(long) (now - te->dev[i].updated_at),
					(long) (te->dev[i].reg_expires - now),
					te->dev[i].last_result[0] ? te->dev[i].last_result : "-",
					te->dev[i].fail_count, rr);
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
	AST_CLI_DEFINE(sofia_push_cli_purge, "Forget the push token of one device"),
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

	sofia_push_load_time = time(NULL);	/* the restart reader looks only at rows written before this */

	/* Native sender lane (sofia_push_sender.c) — non-fatal like the taskprocessors above:
	 * without it, push_sender=native auto-falls back to the script sender per job. */
	sofia_push_sender_init();

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
