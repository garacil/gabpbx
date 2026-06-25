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
 * chan_sofia-native: inbound out-of-dialog MESSAGE -> message_context dialplan (opt-in);
 * outbound via SofiaSendMessage (dialplan) + SofiaMessageSend (AMI). struct sofia_message is the
 * forward-compat seam for a future ast_msg core port. All nua_* on sofia_thread.
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

/* Inbound out-of-dialog MESSAGE -> dialplan (chan_sofia-native SIP SIMPLE). Opt-in:
 * delivers only when a [general] or per-peer message_context resolves; else 405. Runs on
 * sofia_thread (event callback); the launched channel runs the dialplan on its own thread. */
static void sofia_message_deliver_inbound(nua_t *nua, nua_handle_t *nh, sip_t const *sip,
		const char *body)
{
	struct sofia_peer *peer;
	struct sofia_message *m;
	char context[AST_MAX_CONTEXT] = "";
	char peername[80] = "";
	char exten[AST_MAX_EXTENSION] = "";
	const char *from_user = NULL;

	if (sip->sip_to && sip->sip_to->a_url && sip->sip_to->a_url->url_user) {
		ast_copy_string(exten, sip->sip_to->a_url->url_user, sizeof(exten));
	}
	if (sip->sip_from && sip->sip_from->a_url) {
		from_user = sip->sip_from->a_url->url_user;
	}

	/* Resolve the sender peer (NULL = guest); snapshot its message_context + name.
	 * The ref is held across the digest gate below (the verifier reads peer fields),
	 * then released. */
	peer = from_user ? sofia_find_peer(from_user) : NULL;
	if (peer) {
		ast_mutex_lock(&peer->lock);
		if (!ast_strlen_zero(peer->message_context)) {
			ast_copy_string(context, peer->message_context, sizeof(context));
		}
		ast_copy_string(peername, peer->name, sizeof(peername));
		ast_mutex_unlock(&peer->lock);
	}

	/* Context: peer override else [general]; both empty -> messaging OFF (405). */
	if (ast_strlen_zero(context)) {
		ast_copy_string(context, sofia_cfg.message_context, sizeof(context));
	}
	if (ast_strlen_zero(context)) {
		if (peer) {
			ao2_ref(peer, -1);
		}
		sofia_message_respond_and_reap(nua, nh, 405, "Method Not Allowed");
		return;
	}

	/* DIGEST GATE (RFC 3428): a matched, credentialed sender must pass the SAME
	 * challenge/verify as INVITE before the From-user is trusted as the peer and
	 * routed to the dialplan — without this an attacker who only knows a peer name
	 * could inject messages under that identity. The helper emits the 401/4xx and
	 * returns nonzero; we reap the out-of-dialog handle (sofia_verify_digest_auth
	 * does not destroy it) and stop. An unmatched (guest) sender is NOT challenged
	 * here and still falls to the allowguest policy below. */
	if (peer && sofia_message_authenticate(peer, nua, nh, sip)) {
		ao2_ref(peer, -1);
		if (nua_handle_magic(nh) == NULL) {
			nua_handle_destroy(nh);	/* reap fresh out-of-dialog handle (the 401/4xx is already sent) */
		}
		return;
	}
	if (peer) {
		ao2_ref(peer, -1);
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

	if (!sofia_nua) {
		sofia_message_free(m);
		return;
	}
	nh = nua_handle(sofia_nua, NULL, NUTAG_URL(m->to), TAG_END());
	if (!nh) {
		sofia_message_free(m);
		return;
	}
	nua_handle_bind(nh, SOFIA_OUTMSG_HMAGIC);
	nua_message(nh,
		NUTAG_URL(m->to),
		SIPTAG_TO_STR(m->to),
		TAG_IF(!ast_strlen_zero(m->from), SIPTAG_FROM_STR(m->from)),
		SIPTAG_CONTENT_TYPE_STR(m->content_type[0] ? m->content_type : "text/plain"),
		SIPTAG_PAYLOAD_STR(m->body ? m->body : ""),
		TAG_END());
	sofia_message_free(m);
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


