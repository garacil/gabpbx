/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

/*! \file sofia_eventsub.c
 * \brief chan_sofia GENERIC outbound SUBSCRIBE watcher (RFC 6665), split from chan_sofia.c.
 *
 * Per-peer `subscribe_event = <package>[;<accept-mime>][;<expires>]` makes chan_sofia SUBSCRIBE the
 * trunk for an ARBITRARY event package (presence, dialog, reg, conference, ...) and surface each
 * received NOTIFY as the AMI event `SofiaEventNotify` (+ a LOG NOTICE) WITHOUT interpreting the body —
 * an observability/integration primitive. This is a SEPARATE subsystem from the MWI watcher
 * (sofia_subscribe.c): a distinct sentinel keeps the wire-tested MWI hot path untouched; the SUBSCRIBE
 * dialog/auth/refresh/retry idioms are reused (copied + parameterized), not branched.
 *
 * Design: v1 = per-peer config trigger (reuses the proven on_registered / reconcile /
 * on_peer_gone path, all on sofia_thread — NO thread hop), AMI+log surface, peer-only target (creds +
 * Route available), single-dialog/non-forking (this sofia fork 481s a forked sub), standing subs
 * (nua owns refresh). Deferred to v2: CLI/AMI dynamic trigger, dialplan/func surface, body parsing /
 * typed dispatch / devstate injection, raw sip: URI targets, multiple events per peer.
 *
 * Like the MWI watcher: ALL nua_* run on sofia_thread; nua owns refresh/Timer-N/Retry-After/Min-Expires/
 * terminated-teardown of an ESTABLISHED sub, so we only F1b-retry a FAILED INITIAL SUBSCRIBE.
 */

#include "gabpbx.h"
#include "gabpbx/channel.h"
#include "gabpbx/astobj2.h"
#include "gabpbx/lock.h"
#include "gabpbx/utils.h"
#include "gabpbx/strings.h"
#include "gabpbx/logger.h"
#include "gabpbx/manager.h"		/* manager_event */

#include <sofia-sip/nua.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/su_tag.h>
#include <sofia-sip/sip_tag.h>
#include <sofia-sip/nua_tag.h>
#include <sofia-sip/su_wait.h>		/* su_timer_t for the F1b retry sweep */

#include "include/chan_sofia_internal.h"
#include "include/sofia_eventsub.h"

#define SOFIA_EVENTSUB_MAX_AUTH 3
#define SOFIA_EVENTSUB_RETRY_MIN 30	/* s: first backoff after a failed initial SUBSCRIBE */
#define SOFIA_EVENTSUB_RETRY_MAX 300	/* s: backoff cap */
#define SOFIA_EVENTSUB_SWEEP_MS 1000	/* retry sweep tick */
#define SOFIA_EVENTSUB_MAX 256		/* soft cap on concurrent generic subscriptions (warn past it) */
#define SOFIA_EVENTSUB_BODY_CAP 8192	/* raw NOTIFY body bytes surfaced to AMI before truncation */

static su_timer_t *evsub_retry_timer;	/* recurring retry sweep on sofia_thread */
static void evsub_retry_sweep(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg);

/* Sentinel hmagic for generic outbound-SUBSCRIBE handles — DISTINCT from the MWI sentinel so the
 * nua_r_subscribe / nua_i_notify dispatch routes here, never to the MWI watcher. */
static char sofia_evsub_sentinel;
#define SOFIA_EVENTSUB_HMAGIC ((nua_hmagic_t *)&sofia_evsub_sentinel)

struct sofia_evsub {
	nua_handle_t *nh;		/* the outbound SUBSCRIBE dialog handle; bound to SOFIA_EVENTSUB_HMAGIC */
	char peername[80];		/* owning peer (key) */
	char event[64];			/* Event package token (e.g. "presence", "dialog") */
	char accept[128];		/* Accept MIME (auto-filled for known packages; "" = omit) */
	int expires;			/* requested Expires (seconds) */
	char target[256];		/* Request-URI/To we SUBSCRIBE (peer AOR at the trunk) */
	char from[256];			/* From identity (the peer's register identity) */
	char route[256];		/* outboundproxy initial Route (empty = none) */
	char spec[200];			/* raw peer->subscribe_event value at create time (reload diff key) */
	int auth_tries;			/* reactive-auth attempt guard */
	int established;		/* 1 once a 2xx SUBSCRIBE arrived (nua then owns refresh) */
	int in_flight;			/* a (re)SUBSCRIBE is outstanding */
	time_t next_send;		/* when the sweep should retry a failed initial SUBSCRIBE; 0 = none */
	int retry_attempts;		/* consecutive failed initial attempts (drives the backoff) */
};

#define MAX_EVENTSUB_BUCKETS 563	/* prime; one entry per subscribe_event=... peer */
static struct ao2_container *evsubs;	/* keyed by peername; created in sofia_eventsub_init */

static int evsub_hash_fn(const void *obj, int flags)
{
	const struct sofia_evsub *s = obj;
	return ast_str_hash(s->peername);
}
static int evsub_cmp_fn(void *obj, void *arg, int flags)
{
	struct sofia_evsub *s = obj;
	struct sofia_evsub *match = arg;
	return strcmp(s->peername, match->peername) ? 0 : (CMP_MATCH | CMP_STOP);
}

static void evsub_destructor(void *obj)
{
	/* No nua_* here — the handle is detached + destroyed on sofia_thread before unlink. */
}

/* Backoff: 30, 60, 120, 240, then capped. attempts is 1-based. */
static int evsub_backoff_secs(int attempts)
{
	int shift = (attempts > 0) ? attempts - 1 : 0;
	int secs;

	if (shift > 4) {
		shift = 4;
	}
	secs = SOFIA_EVENTSUB_RETRY_MIN << shift;
	return (secs > SOFIA_EVENTSUB_RETRY_MAX) ? SOFIA_EVENTSUB_RETRY_MAX : secs;
}

static struct sofia_evsub *evsub_find_by_peer(const char *name)
{
	struct sofia_evsub tmp;

	if (!evsubs || ast_strlen_zero(name)) {
		return NULL;
	}
	ast_copy_string(tmp.peername, name, sizeof(tmp.peername));
	return ao2_find(evsubs, &tmp, OBJ_POINTER);
}

static struct sofia_evsub *evsub_find_by_nh(nua_handle_t *nh)
{
	struct ao2_iterator it;
	struct sofia_evsub *s, *found = NULL;

	if (!evsubs || !nh) {
		return NULL;
	}
	it = ao2_iterator_init(evsubs, 0);
	while ((s = ao2_iterator_next(&it))) {
		if (s->nh == nh) {
			found = s;	/* keep the +1 ref */
			break;
		}
		ao2_ref(s, -1);
	}
	ao2_iterator_destroy(&it);
	return found;
}

/* Detach + destroy one sub's handle (sofia_thread). schedule_retry==0: full removal (best-effort
 * Expires:0 unsubscribe + unlink). schedule_retry!=0: drop the failed handle, keep linked, arm next_send. */
static void evsub_teardown(struct sofia_evsub *sub, int schedule_retry)
{
	if (!sub) {
		return;
	}
	if (sub->nh) {
		if (!schedule_retry) {
			nua_unsubscribe(sub->nh, TAG_END());	/* best-effort Expires:0 */
		}
		nua_handle_bind(sub->nh, NULL);
		nua_handle_destroy(sub->nh);
		sub->nh = NULL;
	}
	sub->in_flight = 0;
	if (schedule_retry) {
		sub->established = 0;
		sub->retry_attempts++;
		sub->next_send = time(NULL) + evsub_backoff_secs(sub->retry_attempts);
	} else {
		ao2_unlink(evsubs, sub);
	}
}

/* Build the SUBSCRIBE target/From = the peer's register identity (sip:user@host:port) + the
 * outboundproxy initial Route. Takes peer->lock itself. Returns 0 on success, -1 on truncation/empty host. */
static int evsub_build_target(struct sofia_peer *peer, char *target, size_t tlen,
	char *route, size_t rlen)
{
	char hbuf[80];
	int n;

	if (!peer || !target || tlen == 0) {
		return -1;
	}
	ast_mutex_lock(&peer->lock);
	if (ast_strlen_zero(peer->host)) {
		ast_mutex_unlock(&peer->lock);
		return -1;
	}
	n = snprintf(target, tlen, "sip:%s@%s:%d", S_OR(peer->defaultuser, peer->name),
		sofia_uri_format_host(peer->host, hbuf, sizeof(hbuf)), peer->port);
	/* Same defect class as the INVITE/REGISTER R-URI: a bare sip:user@host:port makes sofia-sip
	 * default to UDP, so a tls/tcp/ws/wss peer's SUBSCRIBE went out UDP. Append ;transport= for the
	 * peer's configured transport (no-op for udp/empty, so UDP peers stay byte-identical). These
	 * startup/reconcile watchers target static-host / register-line peers, so peer->transport is the
	 * correct immediate value; done under the SAME peer->lock the snapshot already holds. */
	sofia_uri_append_transport(target, tlen, sofia_transport_name(peer->transport));
	if (route && rlen) {
		sofia_format_outboundproxy(peer, route, rlen);
	}
	ast_mutex_unlock(&peer->lock);
	if (n < 0 || (size_t) n >= tlen) {
		return -1;
	}
	return 0;
}

/* Auto-fill the package-default Accept for well-known event tokens (RFC 6665 §3.1.3 makes Accept
 * optional, but supplying the package body type is the safe default). Unknown tokens -> "" (omit Accept,
 * let nua/the notifier default). */
static void evsub_default_accept(const char *event, char *accept, size_t alen)
{
	struct { const char *ev; const char *mime; } map[] = {
		{ "presence",      "application/pidf+xml" },		/* RFC 3856 */
		{ "dialog",        "application/dialog-info+xml" },	/* RFC 4235 */
		{ "message-summary", "application/simple-message-summary" },	/* RFC 3842 */
		{ "reg",           "application/reginfo+xml" },		/* RFC 3680 */
		{ "conference",    "application/conference-info+xml" },	/* RFC 4575 */
		{ "presence.winfo", "application/watcherinfo+xml" },	/* RFC 3857 */
	};
	size_t i;

	accept[0] = '\0';
	for (i = 0; i < ARRAY_LEN(map); i++) {
		if (!strcasecmp(event, map[i].ev)) {
			ast_copy_string(accept, map[i].mime, alen);
			return;
		}
	}
}

/* (Re)create the SUBSCRIBE handle and send the SUBSCRIBE (sofia_thread). Sets in_flight on success. */
static int evsub_send_subscribe(struct sofia_evsub *sub)
{
	char exp[16];

	if (!sub || !sofia_nua) {
		return -1;
	}
	if (sub->nh) {
		nua_handle_bind(sub->nh, NULL);
		nua_handle_destroy(sub->nh);
		sub->nh = NULL;
	}
	sub->nh = nua_handle(sofia_nua, SOFIA_EVENTSUB_HMAGIC,
		NUTAG_URL(sub->target),
		TAG_IF(!ast_strlen_zero(sub->route), NUTAG_INITIAL_ROUTE_STR(sub->route)),
		TAG_END());
	if (!sub->nh) {
		return -1;
	}
	snprintf(exp, sizeof(exp), "%d", sub->expires);
	sub->auth_tries = 0;
	sub->in_flight = 1;
	nua_subscribe(sub->nh,
		SIPTAG_EVENT_STR(sub->event),
		TAG_IF(!ast_strlen_zero(sub->accept), SIPTAG_ACCEPT_STR(sub->accept)),
		SIPTAG_EXPIRES_STR(exp),
		TAG_IF(!ast_strlen_zero(sub->from), SIPTAG_FROM_STR(sub->from)),
		TAG_END());
	return 0;
}

/* Parse "event[;accept][;expires]" from a snapshot. event is required; accept auto-fills for known
 * packages if not given; expires defaults to 3600 (7200 for dialog, RFC 4235 §3.4). Returns 0 ok, -1 bad. */
static int evsub_parse_spec(const char *spec, char *event, size_t elen, char *accept, size_t alen,
	int *expires)
{
	char tmp[200], *p, *tok;
	int field = 0;

	/* Reject (don't truncate) an over-long spec, and CR/LF anywhere — Event/Accept go straight onto SIP
	 * headers, so a newline must never reach the framing. */
	if (ast_strlen_zero(spec) || strlen(spec) >= sizeof(tmp) || strpbrk(spec, "\r\n")) {
		return -1;
	}
	ast_copy_string(tmp, spec, sizeof(tmp));
	event[0] = accept[0] = '\0';
	*expires = 0;
	p = tmp;
	while ((tok = strsep(&p, ";"))) {
		tok = ast_strip(tok);
		if (field == 0) {
			/* Event token: a single word — no whitespace, no embedded Event params/id (RFC 6665
			 * §8.2.1 id matching is not modeled in v1, so reject rather than misparse). */
			if (ast_strlen_zero(tok) || strlen(tok) >= elen || strpbrk(tok, " \t")) {
				return -1;
			}
			ast_copy_string(event, tok, elen);
		} else if (field == 1) {
			/* Optional Accept: must look like a MIME type (contains '/'), so a stray "id=foo" can't be
			 * silently accepted as an Accept value (the presence;id=foo misparse). */
			if (!ast_strlen_zero(tok)) {
				if (strlen(tok) >= alen || !strchr(tok, '/')) {
					return -1;
				}
				ast_copy_string(accept, tok, alen);
			}
		} else if (field == 2) {
			/* Optional Expires: strict 1*DIGIT in a sane range (no atoi "60junk"/overflow). */
			if (!ast_strlen_zero(tok)) {
				char *end;
				long e = strtol(tok, &end, 10);
				if (*end != '\0' || e < 1 || e > 86400) {
					return -1;
				}
				*expires = (int) e;
			}
		} else {
			return -1;	/* extra fields beyond event;accept;expires */
		}
		field++;
	}
	if (ast_strlen_zero(accept)) {
		evsub_default_accept(event, accept, alen);	/* package default (may stay "") */
	}
	if (*expires <= 0) {
		*expires = !strcasecmp(event, "dialog") ? 7200 : 3600;
	}
	return 0;
}

/* Create + send the initial SUBSCRIBE for one peer (sofia_thread). Idempotent. */
static void evsub_start_one(struct sofia_peer *peer)
{
	struct sofia_evsub *sub;
	char spec[200], event[64], accept[128];
	char target[256], from[256], route[256];
	int expires = 0;

	if (!evsubs || !peer || !sofia_nua) {
		return;
	}
	if (ast_strlen_zero(peer->subscribe_event)) {
		return;
	}
	if ((sub = evsub_find_by_peer(peer->name))) {	/* idempotent */
		ao2_ref(sub, -1);
		return;
	}
	if (ao2_container_count(evsubs) >= SOFIA_EVENTSUB_MAX) {
		ast_log(LOG_WARNING, "Sofia EVENT-SUBSCRIBE: soft cap %d reached — peer '%s' subscribe_event skipped\n",
			SOFIA_EVENTSUB_MAX, peer->name);
		return;
	}

	ast_mutex_lock(&peer->lock);
	if (ast_strlen_zero(peer->subscribe_event)) {
		ast_mutex_unlock(&peer->lock);
		return;
	}
	ast_copy_string(spec, peer->subscribe_event, sizeof(spec));
	ast_mutex_unlock(&peer->lock);

	if (evsub_parse_spec(spec, event, sizeof(event), accept, sizeof(accept), &expires) != 0) {
		ast_log(LOG_WARNING, "Sofia EVENT-SUBSCRIBE: peer '%s' subscribe_event '%s' is malformed "
			"(empty/over-long event) — skipped\n", peer->name, spec);
		return;
	}
	if (evsub_build_target(peer, target, sizeof(target), route, sizeof(route)) != 0) {
		ast_log(LOG_WARNING, "Sofia EVENT-SUBSCRIBE: peer '%s' target build failed — skipped\n", peer->name);
		return;
	}
	ast_copy_string(from, target, sizeof(from));

	if (!(sub = ao2_alloc(sizeof(*sub), evsub_destructor))) {
		return;
	}
	ast_copy_string(sub->peername, peer->name, sizeof(sub->peername));
	ast_copy_string(sub->event, event, sizeof(sub->event));
	ast_copy_string(sub->accept, accept, sizeof(sub->accept));
	sub->expires = expires;
	ast_copy_string(sub->target, target, sizeof(sub->target));
	ast_copy_string(sub->from, from, sizeof(sub->from));
	ast_copy_string(sub->route, route, sizeof(sub->route));
	ast_copy_string(sub->spec, spec, sizeof(sub->spec));
	sub->established = sub->in_flight = 0;
	sub->next_send = 0;
	sub->retry_attempts = 0;

	if (!ao2_link(evsubs, sub)) {
		ast_log(LOG_WARNING, "Sofia EVENT-SUBSCRIBE: ao2_link failed for peer '%s'\n", peer->name);
		ao2_ref(sub, -1);
		return;
	}
	if (evsub_send_subscribe(sub) != 0) {
		sub->next_send = time(NULL) + evsub_backoff_secs(++sub->retry_attempts);
		ast_log(LOG_WARNING, "Sofia EVENT-SUBSCRIBE: peer '%s' initial handle create failed — retry scheduled\n",
			peer->name);
	} else if (sofia_debug) {
		ast_verbose("Sofia EVENT-SUBSCRIBE: peer '%s' -> %s (Event: %s, expires %d)\n",
			sub->peername, sub->target, sub->event, sub->expires);
	}
	ao2_ref(sub, -1);
}

/* Public: a peer completed a successful outbound REGISTER 200 — start its generic watcher. sofia_thread. */
void sofia_eventsub_on_registered(struct sofia_peer *peer)
{
	evsub_start_one(peer);
}

/* Public startup sweep (sofia_thread): start watchers for non-register static-host peers + arm the sweep. */
void sofia_eventsub_start(void)
{
	struct ao2_iterator pit;
	struct sofia_peer *peer;

	if (!evsubs) {
		return;
	}
	if (!evsub_retry_timer) {
		evsub_retry_timer = su_timer_create(su_root_task(sofia_root), SOFIA_EVENTSUB_SWEEP_MS);
		if (evsub_retry_timer) {
			su_timer_set_for_ever(evsub_retry_timer, evsub_retry_sweep, NULL);
		} else {
			ast_log(LOG_WARNING, "Sofia EVENT-SUBSCRIBE: could not create retry sweep timer\n");
		}
	}
	pit = ao2_iterator_init(peers, 0);
	while ((peer = ao2_iterator_next(&pit))) {
		if (!ast_strlen_zero(peer->subscribe_event)
			&& !ast_strlen_zero(peer->host)
			&& strcasecmp(peer->host, "dynamic") != 0
			&& !peer->is_register_line) {
			evsub_start_one(peer);
		}
		ao2_ref(peer, -1);
	}
	ao2_iterator_destroy(&pit);
}

/* Public reload reconcile (sofia_thread): stop subs whose peer no longer has subscribe_event (or whose
 * peer is gone, or whose spec/target/route changed), and start subs for peers that now have it. */
void sofia_eventsub_reconcile(void)
{
	struct ao2_iterator it, pit;
	struct sofia_evsub *sub;
	struct sofia_peer *peer;

	if (!evsubs) {
		return;
	}
	it = ao2_iterator_init(evsubs, 0);
	while ((sub = ao2_iterator_next(&it))) {
		struct sofia_peer *p = sofia_find_peer(sub->peername);
		int keep = 0;

		if (p) {
			char cur_spec[200] = "", cur_target[256] = "", cur_route[256] = "";

			ast_mutex_lock(&p->lock);
			ast_copy_string(cur_spec, S_OR(p->subscribe_event, ""), sizeof(cur_spec));
			ast_mutex_unlock(&p->lock);
			if (!ast_strlen_zero(cur_spec)
				&& evsub_build_target(p, cur_target, sizeof(cur_target), cur_route, sizeof(cur_route)) == 0
				&& !strcmp(cur_spec, sub->spec)
				&& !strcmp(cur_target, sub->target)
				&& !strcmp(cur_route, sub->route)) {
				keep = 1;
			}
			ao2_ref(p, -1);
		}
		if (!keep) {
			evsub_teardown(sub, 0);
		}
		ao2_ref(sub, -1);
	}
	ao2_iterator_destroy(&it);

	pit = ao2_iterator_init(peers, 0);
	while ((peer = ao2_iterator_next(&pit))) {
		if (!ast_strlen_zero(peer->subscribe_event)
			&& !ast_strlen_zero(peer->host)
			&& strcasecmp(peer->host, "dynamic") != 0
			&& !peer->is_register_line) {
			evsub_start_one(peer);
		}
		ao2_ref(peer, -1);
	}
	ao2_iterator_destroy(&pit);
}

/* F1b retry sweep (sofia_thread su_timer): re-SUBSCRIBE each due, not-established, not-in-flight sub. */
static void evsub_retry_sweep(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg)
{
	struct ao2_iterator it;
	struct sofia_evsub *sub;
	time_t now = time(NULL);

	if (!evsubs) {
		return;
	}
	it = ao2_iterator_init(evsubs, 0);
	while ((sub = ao2_iterator_next(&it))) {
		if (!sub->established && !sub->in_flight && sub->next_send != 0 && sub->next_send <= now) {
			struct sofia_peer *p = sofia_find_peer(sub->peername);
			int wanted = 0;

			if (p) {
				char cur_target[256] = "", cur_route[256] = "";

				ast_mutex_lock(&p->lock);
				wanted = !ast_strlen_zero(p->subscribe_event);
				ast_mutex_unlock(&p->lock);
				if (wanted
					&& evsub_build_target(p, cur_target, sizeof(cur_target), cur_route, sizeof(cur_route)) == 0) {
					ast_copy_string(sub->target, cur_target, sizeof(sub->target));
					ast_copy_string(sub->from, cur_target, sizeof(sub->from));
					ast_copy_string(sub->route, cur_route, sizeof(sub->route));
				} else {
					wanted = 0;
				}
				ao2_ref(p, -1);
			}
			if (!wanted) {
				evsub_teardown(sub, 0);
			} else {
				sub->next_send = 0;
				if (evsub_send_subscribe(sub) != 0) {
					evsub_teardown(sub, 1);
				} else if (sofia_debug) {
					ast_verbose("Sofia EVENT-SUBSCRIBE: peer '%s' retry SUBSCRIBE -> %s (attempt %d)\n",
						sub->peername, sub->target, sub->retry_attempts);
				}
			}
		}
		ao2_ref(sub, -1);
	}
	ao2_iterator_destroy(&it);
}

/* Public: nua_r_subscribe response handler (sofia_thread). Returns 1 if consumed. Reactive digest auth
 * mirrors the REGISTER/MWI path. */
int sofia_eventsub_on_subscribe_response(nua_handle_t *nh, sip_t const *sip, int status)
{
	struct sofia_evsub *sub;

	if (!nh || nua_handle_magic(nh) != SOFIA_EVENTSUB_HMAGIC) {
		return 0;
	}
	if (status < 200) {
		return 1;
	}
	if (!(sub = evsub_find_by_nh(nh))) {
		return 1;
	}

	if ((status == 401 || status == 407) && sip && sub->auth_tries < SOFIA_EVENTSUB_MAX_AUTH) {
		struct sofia_peer *peer = sofia_find_peer(sub->peername);
		char www_creds[512] = "", proxy_creds[512] = "";
		int have_www = 0, have_proxy = 0;

		if (peer) {
			char user[80] = "", secret[80] = "";

			ast_mutex_lock(&peer->lock);
			ast_copy_string(user, S_OR(peer->defaultuser, peer->name), sizeof(user));
			ast_copy_string(secret, S_OR(peer->secret, ""), sizeof(secret));
			ast_mutex_unlock(&peer->lock);
			ao2_ref(peer, -1);

			if (!ast_strlen_zero(secret)) {
				if (sip->sip_www_authenticate && sofia_format_auth_creds(
						sip->sip_www_authenticate, user, secret, www_creds, sizeof(www_creds)) == 0) {
					have_www = 1;
				}
				if (sip->sip_proxy_authenticate && sofia_format_auth_creds(
						sip->sip_proxy_authenticate, user, secret, proxy_creds, sizeof(proxy_creds)) == 0) {
					have_proxy = 1;
				}
			}
		}
		if (have_www || have_proxy) {
			sub->auth_tries++;
			nua_authenticate(sub->nh,
				TAG_IF(have_www, NUTAG_AUTH(www_creds)),
				TAG_IF(have_proxy, NUTAG_AUTH(proxy_creds)),
				TAG_END());
			ao2_ref(sub, -1);
			return 1;
		}
		ast_log(LOG_WARNING, "Sofia EVENT-SUBSCRIBE: auth failed for peer '%s' (%d) — check secret; not retrying\n",
			sub->peername, status);
		evsub_teardown(sub, 0);
		ao2_ref(sub, -1);
		return 1;
	}

	if (status >= 200 && status < 300) {
		sub->established = 1;	/* nua now owns refresh */
		sub->in_flight = 0;
		sub->next_send = 0;
		sub->retry_attempts = 0;
		sub->auth_tries = 0;
	} else if (status >= 300) {
		/* A VISIBLE final >=300 means nua declined recovery (auth/423/Retry-After already tried). */
		if (sub->established) {
			sub->in_flight = 0;
			ast_log(LOG_NOTICE, "Sofia EVENT-SUBSCRIBE: peer '%s' refresh got %d (nua will retry)\n",
				sub->peername, status);
		} else if (status == 401 || status == 407) {
			ast_log(LOG_WARNING, "Sofia EVENT-SUBSCRIBE: peer '%s' auth exhausted (%d) — check secret; not retrying\n",
				sub->peername, status);
			evsub_teardown(sub, 0);
		} else {
			evsub_teardown(sub, 1);	/* failed initial — F1b backoff */
			ast_log(LOG_NOTICE, "Sofia EVENT-SUBSCRIBE: peer '%s' initial SUBSCRIBE got %d — retry in %ds\n",
				sub->peername, status, evsub_backoff_secs(sub->retry_attempts));
		}
	}

	ao2_ref(sub, -1);
	return 1;
}

/* Surface one NOTIFY as the AMI event SofiaEventNotify (+ LOG NOTICE) WITHOUT interpreting the body.
 * The body is base64-encoded and capped at SOFIA_EVENTSUB_BODY_CAP raw bytes (Truncated flag set when
 * it overflows) so a multi-line XML body cannot break AMI framing. */
static void evsub_surface_notify(struct sofia_evsub *sub, sip_t const *sip)
{
	const char *ev = (sip && sip->sip_event && sip->sip_event->o_type) ? sip->sip_event->o_type : sub->event;
	const char *ctype = "";
	const char *substate = "", *reason = "";
	char expires[16] = "";
	char b64[SOFIA_EVENTSUB_BODY_CAP * 2];
	int truncated = 0;

	b64[0] = '\0';
	if (sip && sip->sip_content_type && sip->sip_content_type->c_type) {
		ctype = sip->sip_content_type->c_type;
	}
	if (sip && sip->sip_subscription_state) {
		if (sip->sip_subscription_state->ss_substate) {
			substate = sip->sip_subscription_state->ss_substate;
		}
		if (sip->sip_subscription_state->ss_reason) {
			reason = sip->sip_subscription_state->ss_reason;
		}
		if (sip->sip_subscription_state->ss_expires) {
			ast_copy_string(expires, sip->sip_subscription_state->ss_expires, sizeof(expires));
		}
	}
	if (sip && sip->sip_payload && sip->sip_payload->pl_data && sip->sip_payload->pl_len > 0) {
		size_t n = sip->sip_payload->pl_len;

		if (n > SOFIA_EVENTSUB_BODY_CAP) {
			n = SOFIA_EVENTSUB_BODY_CAP;
			truncated = 1;
		}
		ast_base64encode(b64, (const unsigned char *) sip->sip_payload->pl_data, n, sizeof(b64));
	}

	manager_event(EVENT_FLAG_CALL, "SofiaEventNotify",
		"SubId: %s:%s\r\n"
		"Peer: %s\r\n"
		"Event: %s\r\n"
		"ContentType: %s\r\n"
		"SubscriptionState: %s\r\n"
		"Reason: %s\r\n"
		"Expires: %s\r\n"
		"Truncated: %s\r\n"
		"BodyBase64: %s\r\n",
		sub->peername, sub->event, sub->peername, ev, ctype, substate, reason, expires,
		truncated ? "yes" : "no", b64);

	ast_log(LOG_NOTICE, "Sofia EVENT-SUBSCRIBE: NOTIFY peer='%s' event='%s' state='%s' ctype='%s' (%d body bytes%s)\n",
		sub->peername, ev, substate, ctype,
		(sip && sip->sip_payload) ? (int) sip->sip_payload->pl_len : 0, truncated ? ", truncated" : "");
}

/* Public: nua_i_notify hook (sofia_thread), called EARLY from sofia_process_notify. Returns 1 if it
 * consumed a generic-SUBSCRIBE NOTIFY (and 200-OK'd it), 0 otherwise. */
int sofia_eventsub_on_notify(nua_handle_t *nh, nua_t *nua, sip_t const *sip)
{
	struct sofia_evsub *sub;
	int terminated;

	if (!nh || nua_handle_magic(nh) != SOFIA_EVENTSUB_HMAGIC) {
		return 0;
	}
	if (!(sub = evsub_find_by_nh(nh))) {
		if (sip) {	/* only an actual NOTIFY request gets a response; a synthetic event has none */
			nua_respond(nh, SIP_200_OK, NUTAG_WITH_THIS(nua), TAG_END());
		}
		return 1;
	}

	/* HIGH 2: a SYNTHETIC nua_i_notify (sip == NULL) — Timer-N timeout / refresh failure; there is NO
	 * incoming request to answer. Surface a terminal event, do NOT nua_respond, and tear the dead sub
	 * down (else it lingers as a stale blocker; the established sub is not on the retry sweep). */
	if (!sip) {
		manager_event(EVENT_FLAG_CALL, "SofiaEventNotify",
			"SubId: %s:%s\r\n" "Peer: %s\r\n" "Event: %s\r\n"
			"SubscriptionState: terminated\r\n" "Reason: synthetic\r\n",
			sub->peername, sub->event, sub->peername, sub->event);
		ast_log(LOG_NOTICE, "Sofia EVENT-SUBSCRIBE: peer '%s' synthetic terminate (no NOTIFY request) — torn down\n",
			sub->peername);
		evsub_teardown(sub, 0);
		ao2_ref(sub, -1);
		return 1;
	}

	/* HIGH 1: RFC 6665 §4.1.3/§8.2.1 — a NOTIFY MUST match the subscription. Verify the Event package
	 * byte-for-byte (case-sensitive) and reject an Event carrying an id (v1 does not model Event id) with
	 * 481, WITHOUT surfacing — so a wrong-package or fork/unsolicited NOTIFY can't masquerade as this
	 * subscription's state to AMI consumers. */
	if (!sip->sip_event || ast_strlen_zero(sip->sip_event->o_type)
			|| strcmp(sip->sip_event->o_type, sub->event) || sip->sip_event->o_id) {
		nua_respond(nh, 481, "Subscription Does Not Exist", NUTAG_WITH_THIS(nua), TAG_END());
		ao2_ref(sub, -1);
		return 1;
	}

	terminated = (sip->sip_subscription_state && sip->sip_subscription_state->ss_substate
		&& !strcasecmp(sip->sip_subscription_state->ss_substate, "terminated"));

	evsub_surface_notify(sub, sip);
	nua_respond(nh, SIP_200_OK, NUTAG_WITH_THIS(nua), TAG_END());

	/* Subscription-State: terminated — the upstream ended it; tear down (no retry). A later reload /
	 * re-REGISTER recreates it. */
	if (terminated) {
		if (sofia_debug) {
			ast_verbose("Sofia EVENT-SUBSCRIBE: peer '%s' subscription terminated by upstream — torn down\n",
				sub->peername);
		}
		evsub_teardown(sub, 0);
	}

	ao2_ref(sub, -1);
	return 1;
}

/* Public (sofia_thread): a peer was removed/destroyed — tear down its generic watcher. Race-safe via the
 * cache-only lookup (a realtime fallback would resurrect a just-pruned peer). */
void sofia_eventsub_on_peer_gone(const char *peername)
{
	struct sofia_peer *p;
	struct sofia_evsub *sub;

	if (ast_strlen_zero(peername) || !evsubs) {
		return;
	}
	if ((p = sofia_find_peer_cached(peername))) {
		ao2_ref(p, -1);
		return;
	}
	if ((sub = evsub_find_by_peer(peername))) {
		evsub_teardown(sub, 0);
		ao2_ref(sub, -1);
	}
}

/* ---- lifecycle (called from chan_sofia.c) ---- */
int sofia_eventsub_init(void)
{
	evsubs = ao2_container_alloc(MAX_EVENTSUB_BUCKETS, evsub_hash_fn, evsub_cmp_fn);
	return evsubs ? 0 : -1;
}

void sofia_eventsub_stop(void)
{
	if (evsub_retry_timer) {
		su_timer_destroy(evsub_retry_timer);
		evsub_retry_timer = NULL;
	}
	if (evsubs) {
		struct ao2_iterator it = ao2_iterator_init(evsubs, 0);
		struct sofia_evsub *sub;

		while ((sub = ao2_iterator_next(&it))) {
			evsub_teardown(sub, 0);
			ao2_ref(sub, -1);
		}
		ao2_iterator_destroy(&it);
	}
}

void sofia_eventsub_destroy(void)
{
	if (evsubs) {
		ao2_ref(evsubs, -1);
		evsubs = NULL;
	}
}
