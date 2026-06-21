/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

/*! \file sofia_subscribe.c
 * \brief chan_sofia outbound MWI SUBSCRIBE (a watcher), split from chan_sofia.c.
 *
 * chan_sofia SUBSCRIBEs to an upstream trunk for `Event: message-summary` and injects the
 * received MWI (Voice-Message: N/M) into the LOCAL ast_event MWI cache so local phones light up.
 * Driven by the per-peer `mwi_subscribe = <localmailbox>[@context]` knob (DISTINCT from the
 * inbound `subscribemwi` bool). ALL nua_* run on sofia_thread; the triggers (on_registered, the
 * NOTIFY hook, the subscribe-response hook, the retry sweep, the peer-gone hook) are all already on
 * sofia_thread. The MWI injection (ast_event_queue_and_cache) is thread-safe. Peer strings are
 * snapshotted under peer->lock.
 *
 * Hardening (3-way reviewed, grounded in the sofia-sip nua/nta sources):
 *  - F2: the outbound SUBSCRIBE honors outboundproxy via NUTAG_INITIAL_ROUTE_STR (REGISTER parity).
 *  - F3: a body-less `Subscription-State: terminated` NOTIFY clears the local MWI (lamp off), while a
 *    NOTIFY that carries a body is always rendered (RFC 6665 §3.1.4, RFC 3842 §3.8/§3.9).
 *  - F1a: when a peer is removed/destroyed its watcher is torn down (no leak, no stale blocker).
 *  - F1b: a FAILED INITIAL SUBSCRIBE is retried with backoff. nua does NOT auto-retry a
 *    transport/DNS-synthesized failure (nta.c synthesizes 503 "No transport"/"DNS Error" and 408 on
 *    timeout, none carrying Retry-After; nua_client.c:1352 only restarts a Retry-After-bearing
 *    response, and nua_subnotref.c:386-475 auto-refreshes ESTABLISHED subs only). So without F1b a
 *    transient upstream outage would leave the watcher permanently dead.
 */

#include "gabpbx.h"
#include "gabpbx/channel.h"
#include "gabpbx/event.h"
#include "gabpbx/astobj2.h"
#include "gabpbx/lock.h"
#include "gabpbx/utils.h"
#include "gabpbx/strings.h"
#include "gabpbx/logger.h"
#include "gabpbx/module.h"

#include <sofia-sip/nua.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/su_tag.h>
#include <sofia-sip/sip_tag.h>
#include <sofia-sip/nua_tag.h>
#include <sofia-sip/su_string.h>
#include <sofia-sip/su_wait.h>		/* su_timer_t for the F1b retry sweep */
#include <sofia-sip/url.h>

#include "include/chan_sofia_internal.h"
#include "include/sofia_subscribe.h"

#define SOFIA_MWISUB_MAX_AUTH 3

/* F1b retry-with-backoff for a FAILED INITIAL outbound SUBSCRIBE (the never-established case only;
 * nua owns refresh of established subs and restart of Retry-After-bearing failures). */
#define SOFIA_MWISUB_RETRY_MIN 30	/* s: first backoff after a failed initial SUBSCRIBE */
#define SOFIA_MWISUB_RETRY_MAX 300	/* s: backoff cap */
#define SOFIA_MWISUB_SWEEP_MS 1000	/* retry sweep tick (next_send granularity) */

static su_timer_t *mwisub_retry_timer;	/* recurring retry sweep on sofia_thread */
static void mwisub_retry_sweep(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg);

/* Sentinel hmagic for outbound MWI-SUBSCRIBE handles — routes the nua_r_subscribe response and the
 * nua_i_notify NOTIFY to this handler before any pvt/peer dispatch. A fixed address, so it is never
 * confusable with a live pvt/peer/sub pointer (per-object correlation is mwisub_find_by_nh's job). */
static char sofia_mwisub_sentinel;
#define SOFIA_MWISUB_HMAGIC ((nua_hmagic_t *)&sofia_mwisub_sentinel)

struct sofia_mwisub {
	nua_handle_t *nh;		/* the outbound SUBSCRIBE dialog handle; bound to SOFIA_MWISUB_HMAGIC */
	char peername[80];		/* owning peer (key) */
	char mailbox[80];		/* local mailbox to inject */
	char context[80];		/* local context (default "default") */
	char target[256];		/* Request-URI/To we SUBSCRIBE (peer AOR at the trunk) */
	char from[256];			/* From identity (the peer's register identity) */
	char route[256];		/* F2: outboundproxy initial Route (empty = none) */
	char spec[160];			/* raw peer->mwi_subscribe value at create time (reload diff key) */
	int auth_tries;			/* reactive-auth attempt guard (cap at SOFIA_MWISUB_MAX_AUTH) */
	int established;		/* F1b: 1 once a 2xx SUBSCRIBE response arrived (nua then owns refresh) */
	int in_flight;			/* F1b: a (re)SUBSCRIBE is outstanding; the sweep must not re-arm it */
	time_t next_send;		/* F1b: when the sweep should retry a failed initial SUBSCRIBE; 0 = none */
	int retry_attempts;		/* F1b: consecutive failed initial attempts (drives the backoff) */
};

#define MAX_MWISUB_BUCKETS 563		/* prime; one entry per mwi_subscribe=... peer (trunks are few) */
static struct ao2_container *mwisubs;	/* keyed by peername; created in sofia_subscribe_init */

/* ao2 hash: on the peer name. */
static int mwisub_hash_fn(const void *obj, int flags)
{
	const struct sofia_mwisub *s = obj;	/* full sub or {.peername} shim */
	return ast_str_hash(s->peername);
}
/* ao2 cmp: exact match on the peer name. */
static int mwisub_cmp_fn(void *obj, void *arg, int flags)
{
	struct sofia_mwisub *s = obj;
	struct sofia_mwisub *match = arg;	/* {.peername} shim */
	return strcmp(s->peername, match->peername) ? 0 : (CMP_MATCH | CMP_STOP);
}

static void mwisub_destructor(void *obj)
{
	/* No nua_* here — the handle is detached + destroyed on sofia_thread before unlink. */
}

/* F1b backoff: 30, 60, 120, 240, then capped at SOFIA_MWISUB_RETRY_MAX. attempts is 1-based. */
static int mwisub_backoff_secs(int attempts)
{
	int shift = (attempts > 0) ? attempts - 1 : 0;
	int secs;

	if (shift > 4) {
		shift = 4;
	}
	secs = SOFIA_MWISUB_RETRY_MIN << shift;
	return (secs > SOFIA_MWISUB_RETRY_MAX) ? SOFIA_MWISUB_RETRY_MAX : secs;
}

/* Find a sub by owning peer name; returns it with a +1 ref. */
static struct sofia_mwisub *mwisub_find_by_peer(const char *name)
{
	struct sofia_mwisub tmp;

	if (!mwisubs || ast_strlen_zero(name)) {
		return NULL;
	}
	ast_copy_string(tmp.peername, name, sizeof(tmp.peername));
	return ao2_find(mwisubs, &tmp, OBJ_POINTER);
}

/* Find a sub by its nua handle (linear scan); returns it with a +1 ref. */
static struct sofia_mwisub *mwisub_find_by_nh(nua_handle_t *nh)
{
	struct ao2_iterator it;
	struct sofia_mwisub *s, *found = NULL;

	if (!mwisubs || !nh) {
		return NULL;
	}
	it = ao2_iterator_init(mwisubs, 0);
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

/* Detach + destroy one sub's handle (sofia_thread). Two modes (the collapsed teardown helper):
 *  - schedule_retry == 0: full removal — best-effort nua_unsubscribe (Expires:0) on an established
 *    dialog, destroy the handle, and UNLINK the sub from the container.
 *  - schedule_retry != 0: F1b drop-failed-handle — destroy the handle but KEEP the sub linked and arm
 *    next_send so the retry sweep re-SUBSCRIBEs when due. No nua_unsubscribe (a failed initial
 *    SUBSCRIBE never established a dialog to cancel).
 * The upstream expires any soft subscription state by its TTL regardless. */
static void mwisub_teardown(struct sofia_mwisub *sub, int schedule_retry)
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
		sub->next_send = time(NULL) + mwisub_backoff_secs(sub->retry_attempts);
	} else {
		ao2_unlink(mwisubs, sub);
	}
}

/* Build the SUBSCRIBE target/From URI for a peer = its register identity (sip:user@host:port), the
 * trunk AOR, AND (F2) the outboundproxy initial Route. Takes peer->lock itself (callers must NOT
 * already hold it) so target+route are a consistent snapshot. Uses S_OR(defaultuser,name) for the
 * user part and IPv6-brackets the host. route may be NULL (skip). Returns 0 on success, -1 on
 * truncation/empty host. */
static int mwisub_build_target(struct sofia_peer *peer, char *target, size_t tlen,
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
	/* F2: outboundproxy -> initial Route, snapshotted under the SAME lock (the helper REQUIRES
	 * peer->lock held; REGISTER does the same at chan_sofia.c). */
	if (route && rlen) {
		sofia_format_outboundproxy(peer, route, rlen);
	}
	ast_mutex_unlock(&peer->lock);
	if (n < 0 || (size_t) n >= tlen) {
		return -1;	/* fail closed on truncation */
	}
	return 0;
}

/* (Re)create the SUBSCRIBE handle for an already-populated, linked sub and send the SUBSCRIBE
 * (sofia_thread). Used by mwisub_start_one (initial) and the retry sweep (F1b). Any prior handle is
 * dropped first. Sets in_flight on success. Returns 0 on success, -1 if the handle could not be
 * created. */
static int mwisub_send_subscribe(struct sofia_mwisub *sub)
{
	char exp[16];

	if (!sub || !sofia_nua) {
		return -1;
	}
	if (sub->nh) {	/* defensively drop any prior handle (no dialog to unsubscribe) */
		nua_handle_bind(sub->nh, NULL);
		nua_handle_destroy(sub->nh);
		sub->nh = NULL;
	}
	sub->nh = nua_handle(sofia_nua, SOFIA_MWISUB_HMAGIC,
		NUTAG_URL(sub->target),
		TAG_IF(!ast_strlen_zero(sub->route), NUTAG_INITIAL_ROUTE_STR(sub->route)),
		TAG_END());
	if (!sub->nh) {
		return -1;
	}
	snprintf(exp, sizeof(exp), "%d", sofia_cfg.mwi_expiry > 0 ? sofia_cfg.mwi_expiry : 3600);
	sub->auth_tries = 0;
	sub->in_flight = 1;
	nua_subscribe(sub->nh,
		SIPTAG_EVENT_STR("message-summary"),
		SIPTAG_ACCEPT_STR("application/simple-message-summary"),
		SIPTAG_EXPIRES_STR(exp),
		TAG_IF(!ast_strlen_zero(sub->from), SIPTAG_FROM_STR(sub->from)),
		TAG_END());
	return 0;
}

/* Create + send the initial SUBSCRIBE for one peer (sofia_thread). Idempotent: if peer->mwi_subscribe
 * is empty, or a sub already exists for this peer, returns without doing anything. */
static void mwisub_start_one(struct sofia_peer *peer)
{
	struct sofia_mwisub *sub;
	char spec[160];			/* snapshot of peer->mwi_subscribe */
	char target[256], from[256], route[256];
	const char *atp;
	size_t mblen, ctxlen;
	char *at;

	if (!mwisubs || !peer || !sofia_nua) {
		return;
	}
	if (ast_strlen_zero(peer->mwi_subscribe)) {
		return;
	}
	/* Idempotent: a sub already exists for this peer. */
	if ((sub = mwisub_find_by_peer(peer->name))) {
		ao2_ref(sub, -1);
		return;
	}

	/* Snapshot the mwi_subscribe spec under peer->lock. */
	ast_mutex_lock(&peer->lock);
	if (ast_strlen_zero(peer->mwi_subscribe)) {
		ast_mutex_unlock(&peer->lock);
		return;
	}
	ast_copy_string(spec, peer->mwi_subscribe, sizeof(spec));
	ast_mutex_unlock(&peer->lock);

	/* F4: fail closed on mailbox/context overflow instead of silently truncating (a truncated
	 * mailbox would inject MWI into the wrong/again-truncated local mailbox). */
	atp = strchr(spec, '@');
	mblen = atp ? (size_t) (atp - spec) : strlen(spec);
	ctxlen = atp ? strlen(atp + 1) : 0;
	if (mblen == 0 || mblen >= sizeof(((struct sofia_mwisub *) 0)->mailbox)
		|| ctxlen >= sizeof(((struct sofia_mwisub *) 0)->context)) {
		ast_log(LOG_WARNING, "Sofia MWI-SUBSCRIBE: peer '%s' mwi_subscribe '%s' has an empty or "
			"over-long mailbox/context — skipped\n", peer->name, spec);
		return;
	}

	/* Build the SUBSCRIBE target/From = the peer's register identity, plus the F2 Route. Fail closed
	 * on truncation. */
	if (mwisub_build_target(peer, target, sizeof(target), route, sizeof(route)) != 0) {
		ast_log(LOG_WARNING, "Sofia MWI-SUBSCRIBE: peer '%s' target build failed (empty host or "
			"truncation) — skipped\n", peer->name);
		return;
	}
	ast_copy_string(from, target, sizeof(from));

	if (!(sub = ao2_alloc(sizeof(*sub), mwisub_destructor))) {
		return;
	}
	ast_copy_string(sub->peername, peer->name, sizeof(sub->peername));
	/* Parse mwi_subscribe into mailbox[@context], default context "default" (lengths pre-checked). */
	ast_copy_string(sub->mailbox, spec, sizeof(sub->mailbox));
	if ((at = strchr(sub->mailbox, '@'))) {
		*at++ = '\0';
		ast_copy_string(sub->context, at, sizeof(sub->context));
	}
	if (ast_strlen_zero(sub->context)) {
		ast_copy_string(sub->context, "default", sizeof(sub->context));
	}
	ast_copy_string(sub->target, target, sizeof(sub->target));
	ast_copy_string(sub->from, from, sizeof(sub->from));
	ast_copy_string(sub->route, route, sizeof(sub->route));
	ast_copy_string(sub->spec, spec, sizeof(sub->spec));	/* reload diff key */
	sub->established = 0;
	sub->in_flight = 0;
	sub->next_send = 0;
	sub->retry_attempts = 0;

	if (!ao2_link(mwisubs, sub)) {	/* container +1 */
		ast_log(LOG_WARNING, "Sofia MWI-SUBSCRIBE: ao2_link failed for peer '%s'\n", peer->name);
		ao2_ref(sub, -1);
		return;
	}

	if (mwisub_send_subscribe(sub) != 0) {
		/* Could not create the handle now — keep the sub linked and let the sweep retry. */
		sub->next_send = time(NULL) + mwisub_backoff_secs(++sub->retry_attempts);
		ast_log(LOG_WARNING, "Sofia MWI-SUBSCRIBE: peer '%s' initial handle create failed — retry "
			"scheduled\n", peer->name);
	} else if (sofia_debug) {
		ast_verbose("Sofia MWI-SUBSCRIBE: peer '%s' -> %s (mailbox %s@%s)\n",
			sub->peername, sub->target, sub->mailbox, sub->context);
	}
	ao2_ref(sub, -1);	/* drop our local alloc ref (the container holds its own) */
}

/* Public: a peer just completed a successful outbound REGISTER 200 — start its MWI watcher (if
 * mwi_subscribe is set). sofia_thread. */
void sofia_subscribe_on_registered(struct sofia_peer *peer)
{
	mwisub_start_one(peer);
}

/* Public startup sweep (sofia_thread): for each peer with mwi_subscribe set AND a static host (not
 * host=dynamic), start its watcher now. register=> trunks (host static + secret) start via
 * on_registered too, but a static MWI source with no REGISTER still needs the startup kick. Also
 * arms the F1b retry sweep timer. */
void sofia_subscribe_start(void)
{
	struct ao2_iterator pit;
	struct sofia_peer *peer;

	if (!mwisubs) {
		return;
	}

	/* F1b: recurring retry sweep on sofia_thread (idempotent — created once). */
	if (!mwisub_retry_timer) {
		mwisub_retry_timer = su_timer_create(su_root_task(sofia_root), SOFIA_MWISUB_SWEEP_MS);
		if (mwisub_retry_timer) {
			su_timer_set_for_ever(mwisub_retry_timer, mwisub_retry_sweep, NULL);
		} else {
			ast_log(LOG_WARNING, "Sofia MWI-SUBSCRIBE: could not create retry sweep timer "
				"(failed initial SUBSCRIBEs will not auto-retry until reload)\n");
		}
	}

	pit = ao2_iterator_init(peers, 0);
	while ((peer = ao2_iterator_next(&pit))) {
		/* register=> trunks subscribe ONLY after their REGISTER 200 (sofia_subscribe_on_registered);
		 * the startup sweep starts only NON-register static-host MWI sources. */
		if (!ast_strlen_zero(peer->mwi_subscribe)
			&& !ast_strlen_zero(peer->host)
			&& strcasecmp(peer->host, "dynamic") != 0
			&& !peer->is_register_line) {
			mwisub_start_one(peer);
		}
		ao2_ref(peer, -1);
	}
	ao2_iterator_destroy(&pit);
}

/* Public reload reconcile (sofia_thread, which owns mwisubs so teardown is UAF-safe): stop subs
 * whose peer no longer has mwi_subscribe (or whose peer is gone, or whose spec/target/route changed),
 * and start subs for peers that now have it. */
void sofia_subscribe_reconcile(void)
{
	struct ao2_iterator it, pit;
	struct sofia_mwisub *sub;
	struct sofia_peer *peer;

	if (!mwisubs) {
		return;
	}

	/* Pass 1: drop stale subs (peer gone, mwi_subscribe now empty, OR the desired spec/target/route
	 * changed since this sub was created — a mailbox/context/host/port/defaultuser/outboundproxy
	 * edit). Pass 2 recreates the changed ones with the new values (mwisub_start_one is idempotent). */
	it = ao2_iterator_init(mwisubs, 0);
	while ((sub = ao2_iterator_next(&it))) {
		struct sofia_peer *p = sofia_find_peer(sub->peername);
		int keep = 0;

		if (p) {
			char cur_spec[160] = "", cur_target[256] = "", cur_route[256] = "";

			ast_mutex_lock(&p->lock);
			ast_copy_string(cur_spec, S_OR(p->mwi_subscribe, ""), sizeof(cur_spec));
			ast_mutex_unlock(&p->lock);
			/* Keep ONLY if still requested AND the raw spec, freshly-built target, and Route all
			 * still match. mwisub_build_target takes p->lock itself, so call it unlocked. */
			if (!ast_strlen_zero(cur_spec)
				&& mwisub_build_target(p, cur_target, sizeof(cur_target), cur_route, sizeof(cur_route)) == 0
				&& !strcmp(cur_spec, sub->spec)
				&& !strcmp(cur_target, sub->target)
				&& !strcmp(cur_route, sub->route)) {
				keep = 1;
			}
			ao2_ref(p, -1);
		}
		if (!keep) {
			mwisub_teardown(sub, 0);
		}
		ao2_ref(sub, -1);
	}
	ao2_iterator_destroy(&it);

	/* Pass 2: start missing subs for peers that now have mwi_subscribe (mwisub_start_one is
	 * idempotent — an existing sub is left alone). NON-register static-host peers start here;
	 * register=> trunks (re)start via on_registered after their next REGISTER 200. */
	pit = ao2_iterator_init(peers, 0);
	while ((peer = ao2_iterator_next(&pit))) {
		if (!ast_strlen_zero(peer->mwi_subscribe)
			&& !ast_strlen_zero(peer->host)
			&& strcasecmp(peer->host, "dynamic") != 0
			&& !peer->is_register_line) {
			mwisub_start_one(peer);
		}
		ao2_ref(peer, -1);
	}
	ao2_iterator_destroy(&pit);
}

/* F1b retry sweep (sofia_thread su_timer): re-SUBSCRIBE each due, not-established, not-in-flight,
 * scheduled sub. A sub is scheduled (next_send != 0) only after a failed INITIAL SUBSCRIBE that nua
 * does NOT own (no Retry-After, never established). If the peer is gone or no longer wants MWI, the
 * sub is fully torn down instead of retried. */
static void mwisub_retry_sweep(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg)
{
	struct ao2_iterator it;
	struct sofia_mwisub *sub;
	time_t now = time(NULL);

	if (!mwisubs) {
		return;
	}
	it = ao2_iterator_init(mwisubs, 0);
	while ((sub = ao2_iterator_next(&it))) {
		if (!sub->established && !sub->in_flight && sub->next_send != 0 && sub->next_send <= now) {
			struct sofia_peer *p = sofia_find_peer(sub->peername);
			int wanted = 0;

			if (p) {
				char cur_target[256] = "", cur_route[256] = "";

				ast_mutex_lock(&p->lock);
				wanted = !ast_strlen_zero(p->mwi_subscribe);
				ast_mutex_unlock(&p->lock);
				/* Refresh target/route in case the host/proxy moved since the first attempt (a
				 * spec/mailbox change is handled by reconcile, which tears this down + recreates). */
				if (wanted
					&& mwisub_build_target(p, cur_target, sizeof(cur_target), cur_route, sizeof(cur_route)) == 0) {
					ast_copy_string(sub->target, cur_target, sizeof(sub->target));
					ast_copy_string(sub->from, cur_target, sizeof(sub->from));
					ast_copy_string(sub->route, cur_route, sizeof(sub->route));
				} else {
					wanted = 0;	/* target build failed — treat as gone for this tick */
				}
				ao2_ref(p, -1);
			}
			if (!wanted) {
				mwisub_teardown(sub, 0);	/* peer gone or knob cleared — full removal */
			} else {
				sub->next_send = 0;		/* clear; on_subscribe_response reschedules on failure */
				if (mwisub_send_subscribe(sub) != 0) {
					mwisub_teardown(sub, 1);	/* couldn't create handle — reschedule */
				} else if (sofia_debug) {
					ast_verbose("Sofia MWI-SUBSCRIBE: peer '%s' retry SUBSCRIBE -> %s (attempt %d)\n",
						sub->peername, sub->target, sub->retry_attempts);
				}
			}
		}
		ao2_ref(sub, -1);
	}
	ao2_iterator_destroy(&it);
}

/* Public: nua_r_subscribe response handler (sofia_thread). Returns 1 if it was a MWISUB handle
 * (consumed), 0 otherwise. Reactive digest auth mirrors the REGISTER auth path. */
int sofia_subscribe_on_subscribe_response(nua_handle_t *nh, sip_t const *sip, int status)
{
	struct sofia_mwisub *sub;

	if (!nh || nua_handle_magic(nh) != SOFIA_MWISUB_HMAGIC) {
		return 0;
	}
	if (status < 200) {
		return 1;	/* provisional — consumed, nothing to do */
	}
	if (!(sub = mwisub_find_by_nh(nh))) {
		return 1;	/* our sentinel but no live sub (torn down) — still consumed */
	}

	if ((status == 401 || status == 407) && sip && sub->auth_tries < SOFIA_MWISUB_MAX_AUTH) {
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

			/* One response may carry both WWW- and Proxy-Authenticate — build a cred for each
			 * and feed both in one nua_authenticate call (REGISTER-path parity). */
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
				TAG_END());	/* resends; the response returns here */
			ao2_ref(sub, -1);
			return 1;
		}
		/* No usable credentials (missing secret / unparseable challenge) — a persistent CONFIG error,
		 * not a transient one. Tear the failed watcher down WITHOUT scheduling a retry; a config fix +
		 * reload, or the next REGISTER 200, recreates it cleanly. (3-way grounded: mwisub_send_subscribe
		 * resets auth_tries each attempt, so a scheduled retry would re-challenge forever.) */
		ast_log(LOG_WARNING, "Sofia MWI-SUBSCRIBE: auth failed for peer '%s' (%d) — check secret; not retrying\n",
			sub->peername, status);
		mwisub_teardown(sub, 0);
		ao2_ref(sub, -1);
		return 1;
	}

	if (status >= 200 && status < 300) {
		sub->established = 1;		/* nua now owns refresh (nua_subnotref.c:386-475) */
		sub->in_flight = 0;
		sub->next_send = 0;
		sub->retry_attempts = 0;
		sub->auth_tries = 0;
	} else if (status >= 300) {
		/* nua_client_check_restart() runs BEFORE the app sees the final (nua_client.c:1167): if nua can
		 * restart (auth, 423 Min-Expires @1287, Retry-After @1352) it does so WITHOUT reporting to us.
		 * So a VISIBLE final >=300 here PROVES nua declined recovery (final-not-restarted @1384). We do
		 * NOT special-case Retry-After/423 — their visibility already means nua gave up. */
		if (sub->established) {
			/* nua owns refresh of an established sub (nua_subnotref.c:386-475) — log only. */
			sub->in_flight = 0;
			ast_log(LOG_NOTICE, "Sofia MWI-SUBSCRIBE: peer '%s' refresh got %d (nua will retry)\n",
				sub->peername, status);
		} else if (status == 401 || status == 407) {
			/* Terminal auth (attempts exhausted) — a persistent config error, not transient. Tear down
			 * WITHOUT retry (avoids a perpetual auth loop; auth_tries resets per attempt). */
			ast_log(LOG_WARNING, "Sofia MWI-SUBSCRIBE: peer '%s' auth exhausted (%d) — check secret; not retrying\n",
				sub->peername, status);
			mwisub_teardown(sub, 0);
		} else {
			/* Failed INITIAL SUBSCRIBE — transport/DNS 503 (nta.c:8634/10237), 408 timeout (nta.c:9229),
			 * a visible 423, or any other final nua declined. Drop the dead handle and schedule an
			 * app-level backoff retry (F1b). */
			mwisub_teardown(sub, 1);
			ast_log(LOG_NOTICE, "Sofia MWI-SUBSCRIBE: peer '%s' initial SUBSCRIBE got %d — retry in %ds\n",
				sub->peername, status, mwisub_backoff_secs(sub->retry_attempts));
		}
	}

	ao2_ref(sub, -1);
	return 1;
}

/* Parse the simple-message-summary body into new/old message counts. Falls back to
 * "Messages-Waiting: yes/no" when no Voice-Message line is present. */
static void mwisub_parse_summary(const char *body, int *newmsgs, int *oldmsgs)
{
	const char *p;

	*newmsgs = 0;
	*oldmsgs = 0;

	if ((p = strcasestr(body, "Voice-Message:"))) {
		char *end = NULL;
		long n, m;

		p += strlen("Voice-Message:");
		n = strtol(p, &end, 10);
		if (end && *end == '/') {
			m = strtol(end + 1, NULL, 10);
			/* Clamp to [0, 65535]: <0 -> 0, and cap so a bogus huge value cannot poison the cache. */
			*newmsgs = (n < 0) ? 0 : (n > 65535 ? 65535 : (int) n);
			*oldmsgs = (m < 0) ? 0 : (m > 65535 ? 65535 : (int) m);
			return;
		}
		/* Malformed N/M — treat any positive count as "new waiting". */
		*newmsgs = (n <= 0) ? 0 : (n > 65535 ? 65535 : (int) n);
		return;
	}
	/* No Voice-Message line: fall back to Messages-Waiting. */
	if ((p = strcasestr(body, "Messages-Waiting:"))) {
		p += strlen("Messages-Waiting:");
		while (*p == ' ' || *p == '\t') {
			p++;
		}
		if (!strncasecmp(p, "yes", 3)) {
			*newmsgs = 1;
		}
	}
}

/* Inject one MWI count into the LOCAL ast_event cache for this sub's mailbox/context. */
static void mwisub_inject(struct sofia_mwisub *sub, int newmsgs, int oldmsgs, const char *why)
{
	struct ast_event *event;

	event = ast_event_new(AST_EVENT_MWI,
		AST_EVENT_IE_MAILBOX, AST_EVENT_IE_PLTYPE_STR, sub->mailbox,
		AST_EVENT_IE_CONTEXT, AST_EVENT_IE_PLTYPE_STR, sub->context,
		AST_EVENT_IE_NEWMSGS, AST_EVENT_IE_PLTYPE_UINT, (unsigned int) newmsgs,
		AST_EVENT_IE_OLDMSGS, AST_EVENT_IE_PLTYPE_UINT, (unsigned int) oldmsgs,
		AST_EVENT_IE_END);
	if (event) {
		ast_event_queue_and_cache(event);
		if (sofia_debug) {
			ast_verbose("Sofia MWI-SUBSCRIBE: peer '%s' mailbox %s@%s -> new=%d old=%d%s\n",
				sub->peername, sub->mailbox, sub->context, newmsgs, oldmsgs, why ? why : "");
		}
	}
}

/* Public: nua_i_notify hook (sofia_thread), called EARLY from sofia_process_notify. Returns 1 if it
 * consumed a MWISUB NOTIFY (and 200-OK'd it), 0 otherwise. pvt-free: it only reads nua_handle_magic. */
int sofia_subscribe_on_notify(nua_handle_t *nh, nua_t *nua, sip_t const *sip)
{
	struct sofia_mwisub *sub;
	char buf[1024];
	int newmsgs = 0, oldmsgs = 0;
	int have_body, terminated;

	if (!nh || nua_handle_magic(nh) != SOFIA_MWISUB_HMAGIC) {
		return 0;
	}
	if (!(sub = mwisub_find_by_nh(nh))) {
		/* Our sentinel but no live sub — still consume it (200-OK + return). */
		nua_respond(nh, SIP_200_OK, NUTAG_WITH_THIS(nua), TAG_END());
		return 1;
	}

	/* Verify Event: message-summary. */
	if (!sip || !sip->sip_event || ast_strlen_zero(sip->sip_event->o_type)
		|| strcasecmp(sip->sip_event->o_type, "message-summary")) {
		nua_respond(nh, SIP_200_OK, NUTAG_WITH_THIS(nua), TAG_END());
		ao2_ref(sub, -1);
		return 1;
	}

	have_body = (sip->sip_payload && sip->sip_payload->pl_data && sip->sip_payload->pl_len > 0);
	terminated = (sip->sip_subscription_state && sip->sip_subscription_state->ss_substate
		&& !strcasecmp(sip->sip_subscription_state->ss_substate, "terminated"));

	/* F3 inject policy (RFC 6665 §3.1.4, RFC 3842 §3.8/§3.9):
	 *  - body present            -> render the body's summary (always; even on terminate).
	 *  - body absent + terminated -> the MWI source is gone; clear the lamp (new=0/old=0).
	 *  - body absent + active     -> nothing to render; leave the cache as-is. */
	if (have_body) {
		size_t n = sip->sip_payload->pl_len;	/* pl_data is NOT NUL-terminated */

		if (n > sizeof(buf) - 1) {
			n = sizeof(buf) - 1;
		}
		memcpy(buf, sip->sip_payload->pl_data, n);
		buf[n] = '\0';
		mwisub_parse_summary(buf, &newmsgs, &oldmsgs);
		mwisub_inject(sub, newmsgs, oldmsgs, terminated ? " (terminated, body honored)" : "");
	} else if (terminated) {
		mwisub_inject(sub, 0, 0, " (terminated-clear)");
	}

	nua_respond(nh, SIP_200_OK, NUTAG_WITH_THIS(nua), TAG_END());

	/* Subscription-State: terminated — the upstream ended this subscription. Tear it down (full
	 * removal, no retry) so it does not linger as a stale blocker; a later mwisub_start_one (reload /
	 * re-REGISTER) recreates it. nua auto-removes the dialog usage on a terminated NOTIFY
	 * (nua_server.c) — our handle vs that usage are different objects, so this does not double-free.
	 * mwisub_teardown unlinks (drops the container ref); then drop our find_by_nh +1. */
	if (terminated) {
		if (sofia_debug) {
			ast_verbose("Sofia MWI-SUBSCRIBE: peer '%s' subscription terminated by upstream — torn down\n",
				sub->peername);
		}
		mwisub_teardown(sub, 0);
	}

	ao2_ref(sub, -1);
	return 1;
}

/* Public (sofia_thread): a peer was removed/destroyed (config reload removal, `sip prune realtime`,
 * realtime expiry). Tear down its MWI watcher so it neither leaks nor blocks a same-named peer
 * re-create. Race-safe: if a peer with this name still exists (a re-create already happened, or this
 * fired spuriously), leave the watcher to reconcile/start_one. No-op if the peer had none. */
void sofia_subscribe_on_peer_gone(const char *peername)
{
	struct sofia_peer *p;
	struct sofia_mwisub *sub;

	if (ast_strlen_zero(peername) || !mwisubs) {
		return;
	}
	if ((p = sofia_find_peer_cached(peername))) {
		/* CACHE-ONLY: sofia_find_peer() would take the realtime fallback (chan_sofia.c:2823) and
		 * RESURRECT a peer that `sip prune realtime` just unlinked (DB row survives, sofia_cli.c:1094),
		 * defeating this very teardown. A cached hit means a real (re-created) peer owns this name. */
		ao2_ref(p, -1);
		return;
	}
	if ((sub = mwisub_find_by_peer(peername))) {
		mwisub_teardown(sub, 0);
		ao2_ref(sub, -1);
	}
}

/* ---- lifecycle (called from chan_sofia.c) ---- */
/* Allocate the mwisubs container. Returns 0 on success. */
int sofia_subscribe_init(void)
{
	mwisubs = ao2_container_alloc(MAX_MWISUB_BUCKETS, mwisub_hash_fn, mwisub_cmp_fn);
	return mwisubs ? 0 : -1;
}

/* Stop the retry sweep timer, then detach + destroy every sub's handle (best-effort nua_unsubscribe +
 * nua_handle_destroy). MUST run on sofia_thread BEFORE nua_destroy — same split as
 * sofia_publications_stop. */
void sofia_subscribe_stop(void)
{
	if (mwisub_retry_timer) {
		su_timer_destroy(mwisub_retry_timer);	/* stop the sweep before tearing subs down */
		mwisub_retry_timer = NULL;
	}
	if (mwisubs) {
		struct ao2_iterator it = ao2_iterator_init(mwisubs, 0);
		struct sofia_mwisub *sub;

		while ((sub = ao2_iterator_next(&it))) {
			mwisub_teardown(sub, 0);
			ao2_ref(sub, -1);
		}
		ao2_iterator_destroy(&it);
	}
}

/* Drop the container only. Runs on the unload path AFTER the Sofia thread has stopped (handles are
 * already detached+destroyed by sofia_subscribe_stop) — same as sofia_publications_destroy. */
void sofia_subscribe_destroy(void)
{
	if (mwisubs) {
		ao2_ref(mwisubs, -1);
		mwisubs = NULL;
	}
}
