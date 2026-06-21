/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

/*! \file sofia_transfer.c
 * \brief chan_sofia outbound SIP REFER (call transfer), split from chan_sofia.c.
 *
 * Implements the .transfer tech callback (blind transfer via Transfer()/ast_transfer)
 * and the SofiaTransfer() dialplan app (blind, or attended when ?Replaces is given).
 *
 * THE CONTRACT (main/channel.c ast_transfer): when .transfer returns 0, ast_transfer()
 * BLOCKS reading the channel until an AST_CONTROL_TRANSFER control frame arrives. So
 * returning 0 means "pending — I WILL queue AST_CONTROL_TRANSFER". The REFER outcome
 * (from the nua_r_refer rejection, the refer-event NOTIFY sipfrag, or a 30s timeout) is
 * fed back as that control frame, carrying enum ast_control_transfer (SUCCESS/FAILED).
 *
 * CONCURRENCY: every nua_ and su_timer op runs on sofia_thread. The .transfer callback and
 * the SofiaTransfer app run on a channel/PBX thread, so they marshal the send onto
 * sofia_thread via sofia_dispatch_to_root_thread. The event-callback hooks
 * (sofia_transfer_on_refer_response / _on_notify) already run on sofia_thread. The
 * hangup/destructor hook (sofia_transfer_cleanup) may run off-thread, so it marshals the
 * completion onto sofia_thread too (su_timer_destroy must run there). Frames are queued
 * to pvt->owner by snapshot+ref under pvt->lock, then ast_queue_control_data OUTSIDE the
 * lock, then unref (lock order channel -> pvt -> peer). Mirrors sofia_t38.c.
 */

#include "gabpbx.h"
#include "gabpbx/channel.h"
#include "gabpbx/pbx.h"
#include "gabpbx/app.h"
#include "gabpbx/module.h"
#include "gabpbx/utils.h"
#include "gabpbx/strings.h"
#include "gabpbx/logger.h"
#include "gabpbx/lock.h"
#include "gabpbx/astobj2.h"
#include "gabpbx/frame.h"

#include <sofia-sip/nua.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/su_tag.h>
#include <sofia-sip/sip_tag.h>
#include <sofia-sip/nua_tag.h>
#include <sofia-sip/su_string.h>
#include <sofia-sip/url.h>

#include "include/chan_sofia_internal.h"
#include "include/sofia_transfer.h"

#define SOFIA_REFER_TIMEOUT_MS 30000   /* fail a pending outbound REFER if no terminal NOTIFY in 30s */

const char *app_sofiatransfer = "SofiaTransfer";

/* ------------------------------------------------------------------------- */
/* Percent-encode `in` into out[0..outlen), encoding any char outside the RFC 3986 unreserved
 * set (ALPHA / DIGIT / - . _ ~) as %HH. Returns 0 on success, -1 if the encoded form would
 * overflow `out` — FAILS CLOSED so a clipped Replaces can never target the wrong dialog. */
static int sofia_transfer_pct_encode(const char *in, char *out, size_t outlen)
{
	static const char hex[] = "0123456789ABCDEF";
	size_t o = 0;

	if (!out || outlen == 0) {
		return -1;
	}
	for (; in && *in; in++) {
		unsigned char c = (unsigned char)*in;
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		    (c >= '0' && c <= '9') ||
		    c == '-' || c == '.' || c == '_' || c == '~') {
			if (o + 1 >= outlen) {
				out[o] = '\0';
				return -1;
			}
			out[o++] = (char)c;
		} else {
			if (o + 3 >= outlen) {
				out[o] = '\0';
				return -1;
			}
			out[o++] = '%';
			out[o++] = hex[(c >> 4) & 0xF];
			out[o++] = hex[c & 0xF];
		}
	}
	out[o] = '\0';
	return 0;
}

/* Build the Refer-To header value from a transfer destination.
 *   sip:/sips:        -> verbatim
 *   configured peer   -> its registered/static contact (sofia_resolve_peer_target)
 *   bare extension    -> sip:<exten>@<domain> ONLY if a concrete local domain is derivable
 *                        (sofia_cfg.realm, else sofia_cfg.bindaddr); else fail (-1).
 * A non-empty `replaces` is percent-encoded and appended as ?Replaces= (attended transfer).
 * Returns 0 / -1. */
static int sofia_transfer_build_refer_to(const char *dest, const char *replaces,
		char *out, size_t outlen)
{
	char base[512];

	if (ast_strlen_zero(dest) || !out || outlen == 0) {
		return -1;
	}

	if (!strncasecmp(dest, "sip:", 4) || !strncasecmp(dest, "sips:", 5)) {
		if (strlen(dest) >= sizeof(base)) {
			ast_log(LOG_WARNING, "Sofia transfer: Refer-To URI too long — refusing\n");
			return -1;
		}
		ast_copy_string(base, dest, sizeof(base));
	} else {
		struct sofia_peer *peer = sofia_find_peer(dest);
		if (peer) {
			base[0] = '\0';
			ast_mutex_lock(&peer->lock);
			sofia_resolve_peer_target(peer, peer->defaultuser, base, sizeof(base));
			ast_mutex_unlock(&peer->lock);
			ao2_ref(peer, -1);
			if (ast_strlen_zero(base)) {
				ast_log(LOG_WARNING, "Sofia transfer: peer '%s' has no resolvable contact\n", dest);
				return -1;
			}
		} else {
			/* Bare extension: need a concrete local domain to form sip:<exten>@<domain>. */
			const char *domain = NULL;
			if (!ast_strlen_zero(sofia_cfg.realm)) {
				domain = sofia_cfg.realm;
			} else if (!ast_strlen_zero(sofia_cfg.bindaddr)) {
				domain = sofia_cfg.bindaddr;
			}
			if (ast_strlen_zero(domain)) {
				ast_log(LOG_WARNING, "Sofia transfer: cannot derive a local domain for bare "
					"extension '%s' (set realm/bindaddr or pass a sip: URI)\n", dest);
				return -1;
			}
			/* Bracket-wrap an IPv6 literal domain (e.g. bindaddr = ::) for a valid SIP URI host.
			 * Fail closed on truncation: a clipped Refer-To would target the wrong extension. */
			int blen = (strchr(domain, ':') && domain[0] != '[')
				? snprintf(base, sizeof(base), "sip:%s@[%s]", dest, domain)
				: snprintf(base, sizeof(base), "sip:%s@%s", dest, domain);
			if (blen < 0 || (size_t) blen >= sizeof(base)) {
				ast_log(LOG_WARNING, "Sofia transfer: bare-extension Refer-To too long — refusing\n");
				return -1;
			}
		}
	}

	if (!ast_strlen_zero(replaces)) {
		char enc[512];
		const char *sep = strchr(base, '?') ? "&" : "?";
		int len;
		/* Fail closed on encode overflow: a clipped Replaces would target the wrong dialog. */
		if (sofia_transfer_pct_encode(replaces, enc, sizeof(enc))) {
			ast_log(LOG_WARNING, "Sofia transfer: Replaces too long to encode — refusing\n");
			return -1;
		}
		len = snprintf(out, outlen, "%s%sReplaces=%s", base, sep, enc);
		if (len < 0 || (size_t) len >= outlen) {
			ast_log(LOG_WARNING, "Sofia transfer: Refer-To with Replaces too long — refusing\n");
			return -1;
		}
	} else if (strlen(base) >= outlen) {
		ast_log(LOG_WARNING, "Sofia transfer: Refer-To too long — refusing\n");
		return -1;
	} else {
		ast_copy_string(out, base, outlen);
	}
	return 0;
}

/* ------------------------------------------------------------------------- */
/* Feed the REFER outcome back to the transferer as AST_CONTROL_TRANSFER so the
 * ast_transfer() wait loop unblocks. Idempotent: only acts while op->refer_pending.
 * Snapshots+refs owner under op->lock, queues OUTSIDE the lock. Runs on sofia_thread
 * (su_timer_destroy must). */
static void sofia_transfer_complete(struct sofia_pvt *op, int success)
{
	struct ast_channel *owner = NULL;
	int drop_timer_ref = 0;

	if (!op) {
		return;
	}
	ast_mutex_lock(&op->lock);
	if (!op->refer_pending) {
		ast_mutex_unlock(&op->lock);
		return;
	}
	op->refer_pending = 0;
	if (op->refer_timer) {
		/* An armed timer holds a +1 pvt ref. Destroying it here (NOTIFY / REFER-response /
		 * cleanup path) means the timer callback will NOT fire, so WE must drop that ref.
		 * The timeout path detaches refer_timer first so it never reaches this branch. */
		su_timer_destroy(op->refer_timer);
		op->refer_timer = NULL;
		drop_timer_ref = 1;
	}
	owner = op->owner;
	if (owner) {
		ast_channel_ref(owner);
	}
	ast_mutex_unlock(&op->lock);

	if (owner) {
		enum ast_control_transfer message = success ? AST_TRANSFER_SUCCESS : AST_TRANSFER_FAILED;
		ast_queue_control_data(owner, AST_CONTROL_TRANSFER, &message, sizeof(message));
		ast_channel_unref(owner);
	}
	if (drop_timer_ref) {
		ao2_ref(op, -1);	/* release the armed-timer's pvt ref (may be the last ref) */
	}
}

/* su_timer one-shot timeout (sofia_thread): no terminal NOTIFY within 30s -> FAIL. arg
 * carries a +1-reffed pvt (ref taken when arming); drop it here. */
static void sofia_transfer_timeout(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg)
{
	struct sofia_pvt *op = (struct sofia_pvt *)arg;

	(void)magic;
	if (!op) {
		return;
	}
	ast_log(LOG_NOTICE, "Sofia transfer: REFER timed out after %dms — failing transfer\n",
		SOFIA_REFER_TIMEOUT_MS);
	/* Detach the just-fired timer so sofia_transfer_complete() does NOT try to destroy it or
	 * drop the timer ref — WE own both here. */
	ast_mutex_lock(&op->lock);
	if (op->refer_timer == t) {
		op->refer_timer = NULL;
	}
	ast_mutex_unlock(&op->lock);
	su_timer_destroy(t);
	sofia_transfer_complete(op, 0);
	ao2_ref(op, -1);	/* the timer arg's pvt ref */
}

/* ------------------------------------------------------------------------- */
/* Marshaled REFER send (sofia_thread). Owns one +1 dialog ref (taken by the caller). */
struct sofia_transfer_req {
	struct sofia_pvt *op;
	char refer_to[512];
};

static void sofia_transfer_send_root(void *data)
{
	struct sofia_transfer_req *r = data;
	struct sofia_pvt *op = r->op;
	su_timer_t *timer;

	/* Arm a LOCAL one-shot timeout first (off the pvt), so the no-hang guarantee always holds:
	 * a transfer cannot be left in flight without a backstop. The armed timer owns a +1 pvt
	 * ref. We only publish it into op->refer_timer once we have committed to sending. */
	timer = su_timer_create(su_root_task(sofia_root), SOFIA_REFER_TIMEOUT_MS);
	if (timer) {
		ao2_ref(op, +1);	/* the armed timer's pvt ref */
		if (su_timer_set(timer, sofia_transfer_timeout, op) < 0) {
			su_timer_destroy(timer);
			ao2_ref(op, -1);
			timer = NULL;
		}
	}

	/* Re-validate UNDER op->lock: the call may have hung up (sofia_hangup sets state=DOWN +
	 * NULLs nh and sofia_transfer_cleanup may have cleared refer_pending) between dispatch and
	 * now. Publish the timer and send the REFER while holding the lock so hangup cannot null nh
	 * or clear pending underneath us — this closes the dead-check->nua_refer TOCTOU and a
	 * spurious-REFER-after-cleanup race. (nua_refer under pvt->lock mirrors the re-INVITE path.) */
	ast_mutex_lock(&op->lock);
	if (!timer || !op->refer_pending || op->state == SOFIA_DIALOG_STATE_DOWN || !op->nh) {
		int was_pending = op->refer_pending;
		ast_mutex_unlock(&op->lock);
		if (timer) {
			su_timer_destroy(timer);
			ao2_ref(op, -1);	/* drop the armed-timer ref */
		} else {
			ast_log(LOG_WARNING, "Sofia transfer: could not arm REFER timeout — failing transfer\n");
		}
		if (was_pending) {
			sofia_transfer_complete(op, 0);	/* fail; no-op if cleanup already completed it */
		}
		ao2_ref(op, -1);	/* the send-dispatch ref */
		ast_free(r);
		return;
	}
	op->refer_timer = timer;
	nua_refer(op->nh, SIPTAG_REFER_TO_STR(r->refer_to), TAG_END());
	ast_mutex_unlock(&op->lock);

	ao2_ref(op, -1);	/* the send-dispatch ref */
	ast_free(r);
}

/* ------------------------------------------------------------------------- */
/* Shared blind/attended entry. Off-thread (channel/PBX thread): set the pending flag,
 * build Refer-To, marshal the send. Returns 0 = pending, -1 = could not start. */
static int sofia_transfer_common(struct ast_channel *ast, const char *dest, const char *replaces)
{
	struct sofia_pvt *pvt;
	struct sofia_transfer_req *req;
	char refer_to[512];

	/* .transfer is only ever called on Sofia channels, but SofiaTransfer() is a dialplan app
	 * that can run on ANY channel — guard the tech before treating tech_pvt as a sofia_pvt,
	 * otherwise we would lock a foreign tech's private data and crash. */
	if (!ast || !ast->tech || !ast->tech->type
			|| strcmp(ast->tech->type, SOFIA_CHANNEL_TYPE)) {
		ast_log(LOG_WARNING, "SofiaTransfer: '%s' is not a Sofia (SIP) channel\n",
			ast ? ast->name : "(null)");
		return -1;
	}
	pvt = ast->tech_pvt;

	if (!pvt) {
		return -1;
	}

	ast_mutex_lock(&pvt->lock);
	if (pvt->refer_pending || !pvt->nh) {
		ast_mutex_unlock(&pvt->lock);
		ast_log(LOG_WARNING, "Sofia transfer: %s — cannot start REFER\n",
			pvt->refer_pending ? "a transfer is already pending" : "no active dialog");
		return -1;
	}
	pvt->refer_pending = 1;
	ast_mutex_unlock(&pvt->lock);

	if (sofia_transfer_build_refer_to(dest, replaces, refer_to, sizeof(refer_to))) {
		ast_mutex_lock(&pvt->lock);
		pvt->refer_pending = 0;
		ast_mutex_unlock(&pvt->lock);
		return -1;
	}

	if (!(req = ast_calloc(1, sizeof(*req)))) {
		ast_mutex_lock(&pvt->lock);
		pvt->refer_pending = 0;
		ast_mutex_unlock(&pvt->lock);
		return -1;
	}
	req->op = pvt;
	ao2_ref(pvt, +1);	/* dialog ref for the dispatch; dropped in sofia_transfer_send_root */
	ast_copy_string(req->refer_to, refer_to, sizeof(req->refer_to));

	if (sofia_dispatch_to_root_thread(sofia_transfer_send_root, req) < 0) {
		ao2_ref(pvt, -1);
		ast_free(req);
		ast_mutex_lock(&pvt->lock);
		pvt->refer_pending = 0;
		ast_mutex_unlock(&pvt->lock);
		ast_log(LOG_WARNING, "Sofia transfer: failed to dispatch REFER to sofia_thread\n");
		return -1;
	}

	return 0;	/* pending — AST_CONTROL_TRANSFER will come from the NOTIFY/timeout */
}

/* .transfer tech callback: blind transfer. */
int sofia_transfer(struct ast_channel *ast, const char *dest)
{
	return sofia_transfer_common(ast, dest, NULL);
}

/* SofiaTransfer(<refer-to>[,<replaces>]) — <replaces> = "callid;to-tag=X;from-tag=Y". */
int sofia_app_transfer(struct ast_channel *chan, const char *data)
{
	char *parse;
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(refer_to);
		AST_APP_ARG(replaces);
	);

	if (ast_strlen_zero(data)) {
		ast_log(LOG_WARNING, "SofiaTransfer requires a Refer-To target\n");
		return -1;
	}
	parse = ast_strdupa(data);
	AST_STANDARD_APP_ARGS(args, parse);

	if (ast_strlen_zero(args.refer_to)) {
		ast_log(LOG_WARNING, "SofiaTransfer requires a Refer-To target\n");
		return -1;
	}

	return sofia_transfer_common(chan, args.refer_to, S_OR(args.replaces, NULL)) ? -1 : 0;
}

/* ------------------------------------------------------------------------- */
/* Event-callback hooks (sofia_thread). */

/* nua_r_refer: the REFER request's own response. 1xx/2xx = accepted/pending (NOT transfer
 * success — that comes from the refer-event NOTIFY); >=300 = REFER rejected -> fail now. */
void sofia_transfer_on_refer_response(struct sofia_pvt *op, int status)
{
	if (status >= 300) {
		sofia_transfer_complete(op, 0);
	}
}

/* refer-event NOTIFY: parse the message/sipfrag body ("SIP/2.0 NNN ...") -> transfer result.
 * Returns 1 if this was an Event: refer NOTIFY (consumed for transfer state), else 0. The
 * caller still 200-OKs the NOTIFY. */
int sofia_transfer_on_notify(struct sofia_pvt *op, sip_t const *sip)
{
	int code = 0;
	int subscription_terminated;

	if (!op || !sip || !sip->sip_event || !sip->sip_event->o_type
	    || strcasecmp(sip->sip_event->o_type, "refer")) {
		return 0;
	}

	if (sip->sip_payload && sip->sip_payload->pl_data && sip->sip_payload->pl_len) {
		/* The sipfrag body is pl_len-bounded and NOT guaranteed NUL-terminated: copy the
		 * status line into a local NUL-terminated buffer before parsing. */
		char frag[128];
		const char *q;
		size_t n = sip->sip_payload->pl_len;
		if (n >= sizeof(frag)) {
			n = sizeof(frag) - 1;
		}
		memcpy(frag, sip->sip_payload->pl_data, n);
		frag[n] = '\0';
		q = strstr(frag, "SIP/2.0 ");
		if (q) {
			code = (int) strtol(q + 8, NULL, 10);
		}
	}
	subscription_terminated = (sip->sip_subscription_state && sip->sip_subscription_state->ss_substate
		&& !strcasecmp(sip->sip_subscription_state->ss_substate, "terminated"));

	if (code >= 200 && code < 300) {
		sofia_transfer_complete(op, 1);			/* SUCCESS */
	} else if (code >= 300 || subscription_terminated) {
		sofia_transfer_complete(op, 0);			/* FAILED */
	}
	/* code 1xx (100 Trying) = in progress — leave pending. */
	return 1;
}

/* ------------------------------------------------------------------------- */
/* Hangup/destructor: fail a pending REFER + disarm the timer. May run off sofia_thread
 * (sofia_hangup on a channel thread, the destructor on any thread), so marshal the
 * completion onto sofia_thread — su_timer_destroy must run there. While the timer is
 * armed it holds a +1 pvt ref, so the destructor never runs with a live timer; this
 * mainly matters for the hangup path. */
static void sofia_transfer_cleanup_root(void *data)
{
	struct sofia_pvt *op = data;

	sofia_transfer_complete(op, 0);	/* no-op if not pending; disarms the timer */
	ao2_ref(op, -1);		/* the cleanup-dispatch ref */
}

void sofia_transfer_cleanup(struct sofia_pvt *op)
{
	int pending;

	if (!op) {
		return;
	}
	ast_mutex_lock(&op->lock);
	pending = op->refer_pending;
	ast_mutex_unlock(&op->lock);
	if (!pending) {
		return;	/* nothing armed/pending — no timer to disarm, no frame to queue */
	}

	ao2_ref(op, +1);	/* dispatch ref; dropped in sofia_transfer_cleanup_root */
	if (sofia_dispatch_to_root_thread(sofia_transfer_cleanup_root, op) < 0) {
		/* Could not marshal to sofia_thread. Do NOT complete here: sofia_transfer_complete()
		 * calls su_timer_destroy(), which MUST run on sofia_thread, and the armed timer may be
		 * firing there right now. Drop the dispatch ref and leave completion to the timeout
		 * timer (its +1 pvt ref keeps the dialog alive on sofia_thread); on a real shutdown the
		 * dialog teardown unblocks any waiting ast_transfer() via the channel hangup. */
		ao2_ref(op, -1);
		ast_log(LOG_WARNING, "Sofia transfer: could not marshal REFER cleanup to sofia_thread; "
			"leaving completion to the timeout timer\n");
	}
}
