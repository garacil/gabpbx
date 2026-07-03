/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

/*! \file sofia_message.c
 * \brief chan_sofia out-of-dialog SIP SIMPLE messaging (MESSAGE), split from chan_sofia.c.
 *
 * chan_sofia-native: inbound out-of-dialog MESSAGE from an authenticated sender is natively RELAYED to a
 * registered local peer resolved via the sender's subscribecontext hint (exten -> SIP/<peer>), fanned out
 * to the peer's live contacts (message_autorelay, default on); it otherwise falls through to the opt-in
 * message_context dialplan. Explicit outbound via SofiaSendMessage (dialplan) + SofiaMessageSend (AMI).
 * All nua_* on sofia_thread.
 */

#include "gabpbx.h"
#include "gabpbx/channel.h"
#include "gabpbx/pbx.h"
#include "gabpbx/manager.h"
#include "gabpbx/module.h"
#include "gabpbx/app.h"
#include "gabpbx/utils.h"
#include "gabpbx/strings.h"
#include "gabpbx/logger.h"
#include "gabpbx/astobj2.h"
#include "gabpbx/lock.h"

#include <sofia-sip/nua.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/su_tag.h>
#include <sofia-sip/sip_tag.h>
#include <sofia-sip/nua_tag.h>
#include <sofia-sip/url.h>

#include "include/chan_sofia_internal.h"
#include "include/sofia_message.h"

struct sofia_message {
	char from[256];          /* From URI (sip:user@host) */
	char from_display[128];  /* From display-name */
	char to[256];            /* To URI */
	char route[1024];        /* RFC 3327 Path as a ready Route (NUTAG_INITIAL_ROUTE_STR on the handle); "" = none */
	char proxy[256];         /* NAT NUTAG_PROXY override on the message op (learned public src); "" = none */
	char ruri[256];          /* Request-URI */
	char peer[80];           /* matched local peer name, "" if guest */
	char context[AST_MAX_CONTEXT];  /* resolved dialplan context (inbound) */
	char exten[AST_MAX_EXTENSION];  /* resolved exten = To-user (inbound) */
	char content_type[64];
	char *body;              /* heap copy, NUL-terminated */
	size_t body_len;
};

static void sofia_message_free(struct sofia_message *m)
{
	if (m) {
		ast_free(m->body);
		ast_free(m);
	}
}

/* Format a sip url_t into "sip:user@host[:port]" for the SIPMESSAGE_* vars. */
static void sofia_message_format_url(url_t const *url, char *out, size_t outlen)
{
	if (!url || !out || !outlen) {
		if (out && outlen) out[0] = '\0';
		return;
	}
	if (url->url_port && url->url_port[0]) {
		snprintf(out, outlen, "sip:%s@%s:%s",
			url->url_user ? url->url_user : "",
			url->url_host ? url->url_host : "",
			url->url_port);
	} else {
		snprintf(out, outlen, "sip:%s@%s",
			url->url_user ? url->url_user : "",
			url->url_host ? url->url_host : "");
	}
}

/* Native peer-to-peer relay: resolve exten via the sender's subscribecontext hint (exten -> SIP/<peer>)
 * and re-originate the MESSAGE to the resolved local peer(s)' live contact(s). Returns the SIP code to
 * answer the sender: 202 (>=1 contact queued), 480 (hint resolves to a peer with no live contact), or
 * 0 = "not a local hinted extension" (caller falls through to the message_context/dialplan path). */
static int sofia_message_relay_local(const char *exten, const char *subscribecontext, const char *to_aor,
		const char *from, const char *body, const char *content_type);

/* Allocate a media-less channel that runs the dialplan for one inbound out-of-dialog
 * MESSAGE. Keeps the core null_tech (ast_channel_alloc default) - no media, hangs up cleanly. */
static int sofia_message_deliver_inbound_launch(struct sofia_message *m)
{
	struct ast_channel *chan;
	static unsigned int seq;   /* label only; not load-bearing */
	const char *cidnum = m->from[0] ? m->from : "anonymous";

	chan = ast_channel_alloc(1, AST_STATE_DOWN, cidnum, m->from_display, "",
			m->exten, m->context, NULL, 0, "%s/message-%08x", SOFIA_CHANNEL_TYPE,
			(unsigned)ast_atomic_fetchadd_int((int *)&seq, 1));
	if (!chan) {
		return -1;
	}
	pbx_builtin_setvar_helper(chan, "SIPMESSAGE_FROM", m->from);
	pbx_builtin_setvar_helper(chan, "SIPMESSAGE_FROM_DISPLAY", m->from_display);
	pbx_builtin_setvar_helper(chan, "SIPMESSAGE_TO", m->to);
	pbx_builtin_setvar_helper(chan, "SIPMESSAGE_RURI", m->ruri);
	pbx_builtin_setvar_helper(chan, "SIPMESSAGE_PEER", m->peer);
	pbx_builtin_setvar_helper(chan, "SIPMESSAGE_CONTENT_TYPE", m->content_type);
	pbx_builtin_setvar_helper(chan, "SIPMESSAGE_BODY", m->body ? m->body : "");
	if (ast_pbx_start(chan)) {
		ast_hangup(chan);
		return -1;
	}
	sofia_message_free(m);   /* the channel owns its var copies now */
	return 0;
}

/* Respond to an inbound MESSAGE and reap a fresh out-of-dialog handle. Sofia source
 * (nua_message.c): an incoming MESSAGE outside a dialog creates a NEW handle the app must
 * destroy after responding. No-op for in-dialog handles (magic == the dialog pvt). */
static void sofia_message_respond_and_reap(nua_t *nua, nua_handle_t *nh, int code, const char *phrase)
{
	nua_respond(nh, code, phrase, NUTAG_WITH_THIS(nua), TAG_END());
	if (nua_handle_magic(nh) == NULL) {
		nua_handle_destroy(nh);
	}
}

/* Inbound out-of-dialog MESSAGE (chan_sofia-native SIP SIMPLE). Authenticate the sender (by Authorization
 * username), then: if message_autorelay and the To-user resolves through the sender's subscribecontext
 * hint to a registered local peer, natively re-originate the MESSAGE to that peer's live contact(s)
 * (202/480); otherwise fall through to the opt-in message_context dialplan (405 when no context). Runs on
 * sofia_thread (event callback); a launched dialplan channel runs on its own thread. */
static void sofia_message_deliver_inbound(nua_t *nua, nua_handle_t *nh, sip_t const *sip,
		const char *body)
{
	struct sofia_peer *peer;
	struct sofia_message *m;
	char context[AST_MAX_CONTEXT] = "";
	char subscribecontext[AST_MAX_CONTEXT] = "";
	char peername[80] = "";
	char exten[AST_MAX_EXTENSION] = "";
	char to_aor[256] = "";
	char from_uri[256] = "";
	char from_host[128] = "";
	char sender_regexten[AST_MAX_EXTENSION] = "";
	const char *content_type = "text/plain";
	int challenged = 0;

	if (sip->sip_to && sip->sip_to->a_url && sip->sip_to->a_url->url_user) {
		ast_copy_string(exten, sip->sip_to->a_url->url_user, sizeof(exten));
	}
	if (sip->sip_to && sip->sip_to->a_url) {
		sofia_message_format_url(sip->sip_to->a_url, to_aor, sizeof(to_aor));	/* original logical To, preserved verbatim */
	}
	if (sip->sip_from && sip->sip_from->a_url && sip->sip_from->a_url->url_host) {
		ast_copy_string(from_host, sip->sip_from->a_url->url_host, sizeof(from_host));
	}
	if (sip->sip_from && sip->sip_from->a_url) {
		sofia_message_format_url(sip->sip_from->a_url, from_uri, sizeof(from_uri));	/* fallback (guest) From */
	}
	if (sip->sip_content_type && sip->sip_content_type->c_type) {
		content_type = sip->sip_content_type->c_type;
	}

	/* Identify + authenticate the sender by the digest Authorization username (NOT the From-user, which
	 * in a numeric-extension deployment is the dialed number, not the peer name). Challenges an
	 * unknown/unauthenticated sender (alwaysauthreject parity); on a challenge the 401/4xx is emitted and
	 * the out-of-dialog handle reaped. Only an authenticated sender's tenant subscribecontext is trusted. */
	peer = sofia_message_authenticate_sender(nua, nh, sip, &challenged);
	if (challenged) {
		return;
	}
	/* peer != NULL => authenticated sender; peer == NULL => un-challenged guest (alwaysauthreject off). */
	if (peer) {
		ast_mutex_lock(&peer->lock);
		if (!ast_strlen_zero(peer->message_context)) {
			ast_copy_string(context, peer->message_context, sizeof(context));
		}
		ast_copy_string(subscribecontext, peer->subscribecontext, sizeof(subscribecontext));
		ast_copy_string(peername, peer->name, sizeof(peername));
		ast_copy_string(sender_regexten, peer->regexten, sizeof(sender_regexten));
		ast_mutex_unlock(&peer->lock);
		ao2_ref(peer, -1);
	}

	/* Relay From = the sender's LOGICAL extension (its regexten, first token), NOT the peer name — some
	 * UAs (e.g. SIP.js Browser Phone) drop an inbound MESSAGE whose From-user is longer than the extension
	 * length. Plain URI, no display name: avoids display quoting/sanitization risk and Browser Phone keys
	 * off the URI user anyway. Guests (no regexten) keep the verbatim From. */
	if (!ast_strlen_zero(sender_regexten) && !ast_strlen_zero(from_host)) {
		char *p;
		if ((p = strchr(sender_regexten, '&'))) {
			*p = '\0';	/* multi-token regexten -> first */
		}
		if ((p = strchr(sender_regexten, '@'))) {
			*p = '\0';	/* strip a per-token @context */
		}
		snprintf(from_uri, sizeof(from_uri), "sip:%s@%s", sender_regexten, from_host);
	}

	/* Native peer-to-peer relay (RFC 3428 §10): an authenticated sender's MESSAGE whose To-user resolves
	 * through the sender's OWN subscribecontext hint (exten -> SIP/<peer>, tenant-scoped) is re-originated
	 * to that registered local peer's live contact(s). Falls through to the message_context dialplan path
	 * when the extension is not a local hinted peer. */
	if (sofia_cfg.message_autorelay && !ast_strlen_zero(subscribecontext) && !ast_strlen_zero(exten)) {
		int code = sofia_message_relay_local(exten, subscribecontext, to_aor, from_uri, body, content_type);
		if (code == 202) {
			sofia_message_respond_and_reap(nua, nh, 202, "Accepted");
			return;
		}
		if (code == 480) {
			sofia_message_respond_and_reap(nua, nh, 480, "Temporarily Unavailable");
			return;
		}
		/* code == 0: not a local hinted extension -> fall through. */
	}

	/* Fallback: opt-in message_context dialplan. Context = the authenticated peer's override (snapshotted
	 * above) else [general]; both empty -> messaging OFF (405). */
	if (ast_strlen_zero(context)) {
		ast_copy_string(context, sofia_cfg.message_context, sizeof(context));
	}
	if (ast_strlen_zero(context)) {
		sofia_message_respond_and_reap(nua, nh, 405, "Method Not Allowed");
		return;
	}

	/* Known-peer policy: reject anonymous senders when guests are disallowed. */
	if (ast_strlen_zero(peername) && !sofia_cfg.allowguest) {
		sofia_message_respond_and_reap(nua, nh, 403, "Forbidden");
		return;
	}

	if (ast_strlen_zero(exten)
			|| !ast_exists_extension(NULL, context, exten, 1, NULL)) {
		sofia_message_respond_and_reap(nua, nh, 404, "Not Found");
		return;
	}

	m = ast_calloc(1, sizeof(*m));
	if (!m) {
		sofia_message_respond_and_reap(nua, nh, 500, "Internal Server Error");
		return;
	}
	if (sip->sip_from && sip->sip_from->a_url) {
		sofia_message_format_url(sip->sip_from->a_url, m->from, sizeof(m->from));
	}
	if (sip->sip_from && sip->sip_from->a_display) {
		ast_copy_string(m->from_display, sip->sip_from->a_display, sizeof(m->from_display));
	}
	if (sip->sip_to && sip->sip_to->a_url) {
		sofia_message_format_url(sip->sip_to->a_url, m->to, sizeof(m->to));
	}
	if (sip->sip_request && sip->sip_request->rq_url) {
		sofia_message_format_url(sip->sip_request->rq_url, m->ruri, sizeof(m->ruri));
	}
	ast_copy_string(m->peer, peername, sizeof(m->peer));
	ast_copy_string(m->context, context, sizeof(m->context));
	ast_copy_string(m->exten, exten, sizeof(m->exten));
	if (sip->sip_content_type && sip->sip_content_type->c_type) {
		ast_copy_string(m->content_type, sip->sip_content_type->c_type, sizeof(m->content_type));
	} else {
		ast_copy_string(m->content_type, "text/plain", sizeof(m->content_type));
	}
	m->body = ast_strdup(body ? body : "");
	if (!m->body) {
		sofia_message_free(m);
		sofia_message_respond_and_reap(nua, nh, 500, "Internal Server Error");
		return;
	}
	m->body_len = strlen(m->body);

	if (sofia_message_deliver_inbound_launch(m) == 0) {
		sofia_message_respond_and_reap(nua, nh, 202, "Accepted");
	} else {
		sofia_message_respond_and_reap(nua, nh, 500, "Internal Server Error");
		sofia_message_free(m);
	}
}

void sofia_process_message(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	char buf[1400];
	const char *body = NULL;
	char *bufp;
	struct ast_frame f;

	/* text/plain only, case-insensitive full-match (RFC 3261 §7.3.1; c_type has no ;params). */
	if (!sip || !sip->sip_content_type || !sip->sip_content_type->c_type
			|| strcasecmp(sip->sip_content_type->c_type, "text/plain")) {
		sofia_message_respond_and_reap(nua, nh, 415, "Unsupported Media Type");
		return;
	}

	if (sip->sip_payload && sip->sip_payload->pl_data) {
		body = sip->sip_payload->pl_data;
	}
	if (!body) {
		sofia_message_respond_and_reap(nua, nh, 500, "Internal Server Error");
		return;
	}
	/* Bound the copy by pl_len: payload may hold embedded NULs and isn't NUL-terminated. */
	{
		size_t n = sip->sip_payload->pl_len;
		if (n >= sizeof(buf)) {
			n = sizeof(buf) - 1;
		}
		memcpy(buf, body, n);
		buf[n] = '\0';
	}

	/* Trailing-LF strip (chan_sip parity). */
	bufp = buf + strlen(buf);
	while (bufp > buf && bufp[-1] == '\n') {
		*--bufp = '\0';
	}

	/* Safety: op is pinned by the teardown-race guard, but op->owner is nulled under
	 * op->lock by sofia_hangup. Snapshot+ref the owner under op->lock, then queue the
	 * frame outside the lock (it takes the channel lock — order channel->pvt). */
	if (op) {
		struct ast_channel *owner;
		ast_mutex_lock(&op->lock);
		owner = op->owner;
		if (owner) {
			ast_channel_ref(owner);
		}
		ast_mutex_unlock(&op->lock);
		if (owner) {
			if (sofia_debug) {
				ast_verbose("Sofia: in-call MESSAGE received: '%s'\n", buf);
			}
			/* AST_FRAME_TEXT queue (chan_sip parity) */
			memset(&f, 0, sizeof(f));
			f.frametype = AST_FRAME_TEXT;
			f.subclass.integer = 0;
			f.offset = 0;
			f.data.ptr = buf;
			f.datalen = strlen(buf) + 1;
			ast_queue_frame(owner, &f);
			ast_channel_unref(owner);
			sofia_message_respond_and_reap(nua, nh, 202, "Accepted");
			return;
		}
	}

	/* Out-of-dialog MESSAGE -> dialplan (chan_sofia-native SIP SIMPLE; opt-in via message_context). */
	sofia_message_deliver_inbound(nua, nh, sip, buf);
}

/* Sentinel hmagic for one-shot outbound MESSAGE handles: reaped on nua_r_message. */
static char sofia_outmsg_sentinel;
#define SOFIA_OUTMSG_HMAGIC ((nua_hmagic_t *)&sofia_outmsg_sentinel)

/* sofia_thread: send one out-of-dialog MESSAGE, reaped on nua_r_message via the sentinel. */
static void sofia_message_send_root(void *data)
{
	struct sofia_message *m = data;
	nua_handle_t *nh;
	const char *url;

	if (!sofia_nua) {
		sofia_message_free(m);
		return;
	}
	/* Routing target (Request-URI) = the per-contact ruri when relaying (learned WSS/UDP host:port); the
	 * To header stays the logical AOR (m->to) so the recipient recognizes itself. The SofiaSendMessage
	 * path leaves ruri empty and routes on m->to as before. */
	url = !ast_strlen_zero(m->ruri) ? m->ruri : m->to;
	nh = nua_handle(sofia_nua, NULL, NUTAG_URL(url),
		TAG_IF(!ast_strlen_zero(m->route), NUTAG_INITIAL_ROUTE_STR(m->route)),	/* RFC 3327 Path as Route (per-contact) */
		TAG_END());
	if (!nh) {
		sofia_message_free(m);
		return;
	}
	nua_handle_bind(nh, SOFIA_OUTMSG_HMAGIC);
	nua_message(nh,
		NUTAG_URL(url),
		SIPTAG_TO_STR(m->to),
		TAG_IF(!ast_strlen_zero(m->from), SIPTAG_FROM_STR(m->from)),
		TAG_IF(!ast_strlen_zero(m->proxy), NUTAG_PROXY(m->proxy)),	/* NAT: steer to the contact's learned public source (operation-level) */
		SIPTAG_CONTENT_TYPE_STR(m->content_type[0] ? m->content_type : "text/plain"),
		SIPTAG_PAYLOAD_STR(m->body ? m->body : ""),
		TAG_END());
	sofia_message_free(m);
}

/* Dispatch one out-of-dialog MESSAGE: ruri = the per-contact routing target (Request-URI, learned
 * source), to_aor = the logical To header (the recipient's AOR, so it recognizes itself), plus the
 * per-contact RFC 3327 Path (Route) and NAT proxy. Marshalled onto sofia_thread; reaped via the sentinel. */
static int sofia_message_dispatch(const char *ruri, const char *to_aor, const char *route, const char *proxy,
		const char *from, const char *body, const char *content_type)
{
	struct sofia_message *m;

	if (ast_strlen_zero(ruri)) {
		return -1;
	}
	m = ast_calloc(1, sizeof(*m));
	if (!m) {
		return -1;
	}
	ast_copy_string(m->ruri, ruri, sizeof(m->ruri));	/* Request-URI = routing target */
	ast_copy_string(m->to, !ast_strlen_zero(to_aor) ? to_aor : ruri, sizeof(m->to));	/* To header = AOR */
	if (!ast_strlen_zero(route)) {
		ast_copy_string(m->route, route, sizeof(m->route));
	}
	if (!ast_strlen_zero(proxy)) {
		ast_copy_string(m->proxy, proxy, sizeof(m->proxy));
	}
	if (!ast_strlen_zero(from)) {
		ast_copy_string(m->from, from, sizeof(m->from));
	}
	ast_copy_string(m->content_type, ast_strlen_zero(content_type) ? "text/plain" : content_type,
		sizeof(m->content_type));
	m->body = ast_strdup(body ? body : "");
	if (!m->body) {
		sofia_message_free(m);
		return -1;
	}
	m->body_len = strlen(m->body);
	if (sofia_dispatch_to_root_thread(sofia_message_send_root, m) < 0) {
		sofia_message_free(m);
		return -1;
	}
	return 0;
}

/* Fan a MESSAGE out to every unexpired registered contact of a resolved local peer, mirroring the fork's
 * per-contact routing (RURI from the learned source + RFC 3327 Path + NAT proxy). Returns the count of
 * contacts the send was queued to. Must NOT hold peer->lock (iterates the contacts container). */
static int sofia_message_relay_to_peer(struct sofia_peer *peer, const char *to_aor, const char *from,
		const char *body, const char *content_type)
{
	struct ao2_iterator ci;
	struct sofia_contact *c;
	char user[80];
	int path_support;
	int queued = 0;
	time_t now = time(NULL);

	if (!peer || !peer->contacts) {
		return 0;
	}
	ast_mutex_lock(&peer->lock);
	ast_copy_string(user, S_OR(peer->defaultuser, peer->name), sizeof(user));
	path_support = peer->path_support;	/* Path is an opt-in trust decision (mirror the fork/INVITE) */
	ast_mutex_unlock(&peer->lock);

	/* To header = the ORIGINAL logical To AOR the sender addressed (e.g. sip:200@domain), preserved
	 * verbatim (RFC 3428 / FreeSWITCH dup_dest) so the recipient UI recognizes it; the Request-URI stays
	 * the per-contact routing target below. */

	ci = ao2_iterator_init(peer->contacts, 0);
	while ((c = ao2_iterator_next(&ci))) {
		char ruri[256] = "";
		char path[1024] = "";
		char proxy[256] = "";
		time_t c_exp;

		ao2_lock(c);
		c_exp = c->expires;	/* REGISTER refresh mutates expires under the contact ao2 lock — snapshot it */
		ao2_unlock(c);
		if (c_exp > now) {	/* routable only while the registration is unexpired (RFC 3261 §10.3) */
			sofia_build_contact_ruri(c, user, ruri, sizeof(ruri), path_support, path, sizeof(path));
			sofia_build_contact_proxy_url(peer, c, proxy, sizeof(proxy));
			if (!ast_strlen_zero(ruri)
					&& sofia_message_dispatch(ruri, to_aor, path, proxy, from, body, content_type) == 0) {
				queued++;
			}
		}
		ao2_ref(c, -1);
	}
	ao2_iterator_destroy(&ci);
	return queued;
}

/* Native peer-to-peer relay: resolve exten through the sender's subscribecontext hint (chan_sofia's own
 * location service: exten -> "SIP/<peer>") and re-originate to the resolved local peer(s)' live contacts. */
static int sofia_message_relay_local(const char *exten, const char *subscribecontext, const char *to_aor,
		const char *from, const char *body, const char *content_type)
{
	char hintdev[512] = "";
	char *devs, *dev;
	int found = 0, queued = 0;

	if (ast_strlen_zero(exten) || ast_strlen_zero(subscribecontext)) {
		return 0;	/* no tenant namespace -> fall through */
	}
	if (!ast_get_hint(hintdev, sizeof(hintdev), NULL, 0, NULL, subscribecontext, exten)
			|| ast_strlen_zero(hintdev)) {
		return 0;	/* no such hinted extension in this tenant -> fall through (dialplan/404) */
	}
	devs = ast_strdupa(hintdev);
	while ((dev = strsep(&devs, "&"))) {
		struct sofia_peer *dst;
		dev = ast_strip(dev);
		if (strncasecmp(dev, "SIP/", 4)) {
			continue;	/* only our own tech */
		}
		dst = sofia_find_peer(dev + 4);
		if (!dst) {
			continue;
		}
		found++;
		queued += sofia_message_relay_to_peer(dst, to_aor, from, body, content_type);
		ao2_ref(dst, -1);
	}
	if (queued > 0) {
		return 202;	/* Accepted: queued to >=1 live contact */
	}
	if (found > 0) {
		return 480;	/* extension resolves but has no live contact (registered-but-offline) */
	}
	return 0;	/* hint pointed only at non-SIP/unknown devices -> fall through */
}

/* Resolve an outbound MESSAGE target. dest = "sip:..." used verbatim; else treated as a
 * peer name -> "sip:user@host:port" from the peer's routing + its from identity. */
static int sofia_message_resolve_target(const char *dest, char *uri, size_t urilen,
		char *from, size_t fromlen)
{
	struct sofia_peer *peer;

	if (ast_strlen_zero(dest)) {
		return -1;
	}
	if (!strncasecmp(dest, "sip:", 4) || !strncasecmp(dest, "sips:", 5)) {
		ast_copy_string(uri, dest, urilen);
		return 0;
	}

	peer = sofia_find_peer(dest);
	if (!peer) {
		return -1;
	}
	ast_mutex_lock(&peer->lock);
	sofia_resolve_peer_target(peer, peer->defaultuser, uri, urilen);
	/* From identity: peer fromuser@fromdomain when set, else leave empty (sofia auto-From). */
	if (from && fromlen) {
		from[0] = '\0';
		if (!ast_strlen_zero(peer->fromuser) && !ast_strlen_zero(peer->fromdomain)) {
			snprintf(from, fromlen, "sip:%s@%s", peer->fromuser, peer->fromdomain);
		} else if (!ast_strlen_zero(peer->fromdomain)) {
			snprintf(from, fromlen, "sip:%s@%s", peer->defaultuser, peer->fromdomain);
		}
	}
	ast_mutex_unlock(&peer->lock);
	ao2_ref(peer, -1);
	return ast_strlen_zero(uri) ? -1 : 0;
}

/* Public entry shared by SofiaSendMessage (dialplan) and SofiaMessageSend (AMI): resolve
 * the target, build the heap snapshot, and marshal the send onto sofia_thread. */
static int sofia_message_send(const char *to, const char *from, const char *body,
		const char *content_type)
{
	struct sofia_message *m;
	char uri[256] = "";
	char resolved_from[256] = "";

	if (ast_strlen_zero(to)) {
		return -1;
	}
	if (sofia_message_resolve_target(to, uri, sizeof(uri), resolved_from, sizeof(resolved_from)) < 0) {
		return -1;
	}

	m = ast_calloc(1, sizeof(*m));
	if (!m) {
		return -1;
	}
	ast_copy_string(m->to, uri, sizeof(m->to));
	/* Caller-supplied From wins over the peer-derived identity. */
	if (!ast_strlen_zero(from)) {
		ast_copy_string(m->from, from, sizeof(m->from));
	} else {
		ast_copy_string(m->from, resolved_from, sizeof(m->from));
	}
	ast_copy_string(m->content_type, ast_strlen_zero(content_type) ? "text/plain" : content_type,
		sizeof(m->content_type));
	m->body = ast_strdup(body ? body : "");
	if (!m->body) {
		sofia_message_free(m);
		return -1;
	}
	m->body_len = strlen(m->body);

	if (sofia_dispatch_to_root_thread(sofia_message_send_root, m) < 0) {
		sofia_message_free(m);
		return -1;
	}
	return 0;
}

const char *app_sofiasendmessage = "SofiaSendMessage";
int sofia_app_sendmessage(struct ast_channel *chan, const char *data)
{
	char *parse;
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(to);
		AST_APP_ARG(body);
		AST_APP_ARG(from);
	);

	if (ast_strlen_zero(data)) {
		ast_log(LOG_WARNING, "SofiaSendMessage requires arguments: <peer-or-uri>,<body>[,<from>]\n");
		return -1;
	}
	parse = ast_strdupa(data);
	AST_STANDARD_APP_ARGS(args, parse);
	if (ast_strlen_zero(args.to) || ast_strlen_zero(args.body)) {
		ast_log(LOG_WARNING, "SofiaSendMessage requires <peer-or-uri> and <body>\n");
		return -1;
	}
	return sofia_message_send(args.to, S_OR(args.from, ""), args.body, "text/plain") ? -1 : 0;
}

int manager_sofia_messagesend(struct mansession *s, const struct message *mm)
{
	const char *to = astman_get_header(mm, "To");
	const char *from = astman_get_header(mm, "From");
	const char *body = astman_get_header(mm, "Body");

	if (ast_strlen_zero(to) || ast_strlen_zero(body)) {
		astman_send_error(s, mm, "To and Body required");
		return 0;
	}
	if (sofia_message_send(to, from, body, "text/plain")) {
		astman_send_error(s, mm, "Message send failed");
		return 0;
	}
	astman_send_ack(s, mm, "Message queued");
	return 0;
}


/* Reap a one-shot outbound MESSAGE handle on its final response (sofia_thread). Returns 1 if nh
 * was an outbound-message handle (matched the sentinel), else 0. */
int sofia_message_reap_outbound(nua_handle_t *nh, int status)
{
	if (nua_handle_magic(nh) != SOFIA_OUTMSG_HMAGIC) {
		return 0;
	}
	if (status >= 200) {
		nua_handle_bind(nh, NULL);
		nua_handle_destroy(nh);
	}
	return 1;
}


