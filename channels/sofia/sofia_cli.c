/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

/*! \file sofia_cli.c
 * \brief chan_sofia CLI commands (sip show/set/reload/unregister), split from chan_sofia.c.
 */

#include "gabpbx.h"
#include <regex.h>
#include "gabpbx/astobj2.h"
#include "gabpbx/cli.h"
#include "gabpbx/lock.h"
#include "gabpbx/utils.h"
#include "gabpbx/strings.h"
#include "gabpbx/logger.h"
#include "gabpbx/channel.h"
#include "gabpbx/callerid.h"
#include "gabpbx/pbx.h"
#include "gabpbx/acl.h"
#include "gabpbx/manager.h"
#include "gabpbx/module.h"

#include <sofia-sip/nua.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/nta.h>
#include <sofia-sip/nta_tport.h>
#include <sofia-sip/tport.h>
#include <sofia-sip/tport_tag.h>
#include <sofia-sip/nta_tag.h>

#include "include/chan_sofia_internal.h"
#include "include/sofia_publish.h"
#include "include/sofia_history.h"
#include "include/sofia_cli.h"

#define SOFIA_CLI_PEER_RULE_WIDTH 78
#define SOFIA_CLI_PEER_LABEL_WIDTH 20

static void sofia_cli_peer_rule(struct ast_str **out, char fill)
{
	char line[SOFIA_CLI_PEER_RULE_WIDTH + 1];

	memset(line, fill, SOFIA_CLI_PEER_RULE_WIDTH);
	line[SOFIA_CLI_PEER_RULE_WIDTH] = '\0';
	ast_str_append(out, 0, "%s\n", line);
}

static void sofia_cli_peer_section(struct ast_str **out, const char *title)
{
	char line[SOFIA_CLI_PEER_RULE_WIDTH + 1];
	int used;

	used = snprintf(line, sizeof(line), "-- %s ", title);
	if (used < 0 || used >= (int) sizeof(line)) {
		ast_str_append(out, 0, "\n-- %s --\n", title);
		return;
	}
	memset(line + used, '-', SOFIA_CLI_PEER_RULE_WIDTH - used);
	line[SOFIA_CLI_PEER_RULE_WIDTH] = '\0';

	ast_str_append(out, 0, "\n%s\n", line);
}

static void sofia_cli_peer_line(struct ast_str **out, const char *label, const char *fmt, ...)
{
	char value[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(value, sizeof(value), fmt, ap);
	va_end(ap);

	ast_str_append(out, 0, "  %-*.*s : %s\n",
		SOFIA_CLI_PEER_LABEL_WIDTH, SOFIA_CLI_PEER_LABEL_WIDTH, label, value);
}

static void sofia_cli_peer_subline(struct ast_str **out, const char *label, const char *fmt, ...)
{
	char value[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(value, sizeof(value), fmt, ap);
	va_end(ap);

	ast_str_append(out, 0, "    %-*.*s : %s\n",
		SOFIA_CLI_PEER_LABEL_WIDTH, SOFIA_CLI_PEER_LABEL_WIDTH, label, value);
}

static char *complete_sofia_peer(const char *word, int state, int only_realtime);

static void sofia_print_ha_lines(struct ast_str **out, const struct ast_ha *ha)
{
	const struct ast_ha *p;

	for (p = ha; p; p = p->next) {
		char addr[128];
		char netmask[128];

		ast_copy_string(addr, ast_sockaddr_stringify_addr(&p->addr), sizeof(addr));
		ast_copy_string(netmask, ast_sockaddr_stringify_addr(&p->netmask), sizeof(netmask));
		ast_str_append(out, 0, "    %-*.*s : %s %s/%s\n",
			SOFIA_CLI_PEER_LABEL_WIDTH, SOFIA_CLI_PEER_LABEL_WIDTH,
			"ACL rule",
			p->sense == AST_SENSE_ALLOW ? "permit" : "deny",
			addr, netmask);
	}
}

static char *complete_sofia_peer(const char *word, int state, int only_realtime)
{
	char *result = NULL;
	int wordlen = strlen(word);
	int which = 0;
	struct ao2_iterator i = ao2_iterator_init(peers, 0);
	struct sofia_peer *peer;

	while ((peer = ao2_iterator_next(&i))) {
		char l_name[256];
		int l_realtime;

		/* reload-UAF: snapshot name + is_realtime under peer->lock (reload writer frees
		 * the stringfield under it). peer->lock is a leaf here. */
		ast_mutex_lock(&peer->lock);
		ast_copy_string(l_name, peer->name, sizeof(l_name));
		l_realtime = peer->is_realtime;
		ast_mutex_unlock(&peer->lock);

		if (!strncasecmp(word, l_name, wordlen)
				&& (!only_realtime || l_realtime)
				&& ++which > state) {
			result = ast_strdup(l_name);
		}
		ao2_ref(peer, -1);
		if (result) {
			break;
		}
	}
	ao2_iterator_destroy(&i);
	return result;
}

char *sofia_cli_show_peers(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct sofia_peer *peer;
	struct ao2_iterator i;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show peers";
		e->usage = "Usage: sip show peers\n"
			   "       List all Sofia-SIP peers\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	ast_cli(a->fd, "%-20s %-30s %-4s %-5s %-15s %s\n",
		"Name/username", "Host", "Dyn", "Port", "Status", "NAT");

	i = ao2_iterator_init(peers, 0);
	while ((peer = ao2_iterator_next(&i))) {
		char status[32];
		char nat_str[16] = "";
		char l_name[256];
		char l_host[256];

		if (peer->qualify) {
			switch (peer->peer_status) {
			case PEER_REACHABLE:
				snprintf(status, sizeof(status), "OK (%d ms)", peer->lastms);
				break;
			case PEER_LAGGED:
				snprintf(status, sizeof(status), "LAGGED (%d ms)", peer->lastms);
				break;
			case PEER_UNREACHABLE:
				ast_copy_string(status, "UNREACHABLE", sizeof(status));
				break;
			default:
				ast_copy_string(status, "UNKNOWN", sizeof(status));
				break;
			}
		} else {
			ast_copy_string(status, peer->registered ? "Registered" : "Unmonitored", sizeof(status));
		}

		if (peer->nat & SOFIA_NAT_FORCE_RPORT)
			strcat(nat_str, "R");
		if (peer->nat & SOFIA_NAT_COMEDIA)
			strcat(nat_str, "C");

		/* reload-UAF: name/host are unbounded stringfields the reload writer frees
		 * under peer->lock — snapshot under the lock, then drop it before the
		 * blocking ast_cli. */
		ast_mutex_lock(&peer->lock);
		ast_copy_string(l_name, peer->name, sizeof(l_name));
		ast_copy_string(l_host, peer->host, sizeof(l_host));
		ast_mutex_unlock(&peer->lock);

		ast_cli(a->fd, "%-20s %-30s %-4s %-5d %-15s %s\n",
			l_name,
			l_host,
			peer->registered ? "Dyn" : "",
			peer->port,
			status,
			nat_str);
		ao2_ref(peer, -1);
	}
	ao2_iterator_destroy(&i);

	return CLI_SUCCESS;
}

char *sofia_cli_show_peer(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct sofia_peer *peer;
	char status[32];
	char nat[64];
	char codec_buf[256];
	char limit_str[32];
	const char *dtmf_str;
	const char *source_str;
	const char *st_mode_str;
	const char *st_refresher_str;
	const char *sendrpid_str;
	const char *transport_str;
	const char *type_str;
	int contacts_used;
	struct ast_str *buf;
	int detail = 0;	/* "sip show peer <name> detail" -> full per-field dump; bare -> concise operational summary */

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show peer";
		e->usage = "Usage: sip show peer <name> [detail]\n"
			   "       Show a Sofia-SIP peer. Without 'detail' a concise operational summary\n"
			   "       (endpoint, media, calls, and the full Contacts list) is shown; add\n"
			   "       'detail' for the full per-field dump.\n";
		return NULL;
	case CLI_GENERATE:
		/* complete the peer name (token 3) by prefix; offer 'detail' at token 4. */
		if (a->pos == 3) {
			return complete_sofia_peer(a->word, a->n, 0);
		}
		if (a->pos == 4 && a->n == 0 && !strncasecmp(a->word, "detail", strlen(a->word))) {
			return ast_strdup("detail");
		}
		return NULL;
	}

	if (a->argc < 4 || a->argc > 5
			|| (a->argc == 5 && strcasecmp(a->argv[4], "detail"))) {
		ast_cli(a->fd, "Usage: sip show peer <name> [detail]\n");
		return CLI_FAILURE;
	}
	detail = (a->argc == 5);

	peer = sofia_find_peer(a->argv[3]);
	if (!peer) {
		ast_cli(a->fd, "Peer '%s' not found\n", a->argv[3]);
		return CLI_FAILURE;
	}

	/* Assemble under peer->lock, emit once after the unlock. Allocate before locking. */
	buf = ast_str_create(8192);
	if (!buf) {
		ao2_ref(peer, -1);
		return CLI_FAILURE;
	}

	ast_mutex_lock(&peer->lock);

	contacts_used = peer->contacts ? ao2_container_count(peer->contacts) : 0;

	if (peer->nat & (SOFIA_NAT_FORCE_RPORT | SOFIA_NAT_COMEDIA)) {
		nat[0] = '\0';
		if (peer->nat & SOFIA_NAT_FORCE_RPORT) {
			ast_copy_string(nat, "force_rport", sizeof(nat));
		}
		if (peer->nat & SOFIA_NAT_COMEDIA) {
			if (nat[0]) {
				strncat(nat, ", ", sizeof(nat) - strlen(nat) - 1);
			}
			strncat(nat, "comedia", sizeof(nat) - strlen(nat) - 1);
		}
	} else {
		ast_copy_string(nat, "no", sizeof(nat));
	}

	dtmf_str =
		peer->dtmfmode == SOFIA_DTMF_RFC2833 ? "rfc2833" :
		peer->dtmfmode == SOFIA_DTMF_INFO ? "info" :
		peer->dtmfmode == SOFIA_DTMF_SHORTINFO ? "shortinfo" :
		peer->dtmfmode == SOFIA_DTMF_INBAND ? "inband" : "auto";
	type_str =
		peer->type == SOFIA_TYPE_FRIEND ? "friend" :
		peer->type == SOFIA_TYPE_USER ? "user" : "peer";
	transport_str =
		peer->transport == SOFIA_TRANSPORT_TCP ? "tcp" :
		peer->transport == SOFIA_TRANSPORT_TLS ? "tls" :
		peer->transport == SOFIA_TRANSPORT_WS  ? "ws"  :
		peer->transport == SOFIA_TRANSPORT_WSS ? "wss" : "udp";
	source_str = peer->is_realtime ? "realtime (sippeers)" :
		peer->is_register_line ? "register => synthetic peer" : "sofia.conf";
	st_mode_str =
		(peer->session_timers == SESSION_TIMERS_ORIGINATE) ? "originate" :
		(peer->session_timers == SESSION_TIMERS_REFUSE)    ? "refuse"    :
		(peer->session_timers == SESSION_TIMERS_ACCEPT)    ? "accept"    : "off";
	st_refresher_str =
		(peer->session_refresher == SESSION_REFRESHER_UAC) ? "uac" :
		(peer->session_refresher == SESSION_REFRESHER_UAS) ? "uas" : "auto";
	sendrpid_str =
		(peer->sendrpid == 1) ? "pai" :
		(peer->sendrpid == 2) ? "rpid" : "no";
	if (peer->call_limit > 0) {
		snprintf(limit_str, sizeof(limit_str), "%d", peer->call_limit);
	} else {
		ast_copy_string(limit_str, "unlimited", sizeof(limit_str));
	}
	ast_codec_pref_string(&peer->prefs, codec_buf, sizeof(codec_buf));

	if (peer->qualify) {
		switch (peer->peer_status) {
		case PEER_REACHABLE:
			snprintf(status, sizeof(status), "OK (%d ms)", peer->lastms);
			break;
		case PEER_LAGGED:
			snprintf(status, sizeof(status), "LAGGED (%d ms)", peer->lastms);
			break;
		case PEER_UNREACHABLE:
			ast_copy_string(status, "UNREACHABLE", sizeof(status));
			break;
		default:
			ast_copy_string(status, "UNKNOWN", sizeof(status));
			break;
		}
	} else {
		ast_copy_string(status, "disabled", sizeof(status));
	}

	ast_str_append(&buf, 0, "\n");
	sofia_cli_peer_rule(&buf, '=');
	sofia_cli_peer_line(&buf, "SIP peer", "%s", peer->name);
	sofia_cli_peer_line(&buf, "Registration", "%s", peer->registered ? "registered" : "not registered");
	sofia_cli_peer_rule(&buf, '=');
	sofia_cli_peer_line(&buf, "Endpoint", "%s@%s:%d via %s",
		S_OR(peer->defaultuser, peer->name), peer->host, peer->port, transport_str);
	sofia_cli_peer_line(&buf, "Context / source", "%s / %s", peer->context, source_str);
	sofia_cli_peer_line(&buf, "Contact slots", "%d used of %d allowed", contacts_used, peer->max_contacts);
	sofia_cli_peer_line(&buf, "Media", "codecs=%s dtmf=%s nat=%s directmedia=%s",
		ast_strlen_zero(codec_buf) ? "(default)" : codec_buf,
		dtmf_str, nat, AST_CLI_YESNO(peer->directmedia));
	sofia_cli_peer_line(&buf, "Calls", "%d/%s active, %d ringing, %d on-hold",
		peer->inUse, limit_str, peer->inRinging, peer->onHold);
	if (peer->qualify) {
		sofia_cli_peer_line(&buf, "Qualify", "yes, status=%s", status);
	} else {
		sofia_cli_peer_line(&buf, "Qualify", "no");
	}
	/* Account code (a billing tag, not a credential) stays in the concise summary. */
	sofia_cli_peer_line(&buf, "Account code", "%s", S_OR(peer->accountcode, "(none)"));

	/* "detail" gates the FULL per-field dump below. The concise (bare) view keeps the operational summary
	 * above + the full Contacts section further down (the hot diagnostic path) — but NEVER a credential:
	 * Secret stays masked, and md5secret / password / key / nonce are never printed. */
	if (detail) {
	sofia_cli_peer_line(&buf, "Session timers", "%s, expires=%d, minse=%d, refresher=%s",
		st_mode_str, peer->session_expires, peer->session_minse, st_refresher_str);
	sofia_cli_peer_line(&buf, "Identity headers", "send=%s, trust=%s, presentation=%s",
		sendrpid_str, AST_CLI_YESNO(peer->trustrpid),
		ast_named_caller_presentation(peer->callingpres));

	sofia_cli_peer_section(&buf, "Identity");
	sofia_cli_peer_line(&buf, "Name", "%s", peer->name);
	sofia_cli_peer_line(&buf, "Username", "%s", S_OR(peer->defaultuser, "(none)"));
	sofia_cli_peer_line(&buf, "Type", "%s", type_str);
	sofia_cli_peer_line(&buf, "Host", "%s", peer->host);
	sofia_cli_peer_line(&buf, "Port", "%d", peer->port);
	sofia_cli_peer_line(&buf, "Transport", "%s", transport_str);
	sofia_cli_peer_line(&buf, "Context", "%s", peer->context);
	sofia_cli_peer_line(&buf, "Registered", "%s", AST_CLI_YESNO(peer->registered));
	/* Expires (registration TTL) is meaningful ONLY when this peer takes part in registration: a
	 * dynamic peer that registers TO us, or a register=> peer we register to. A static challenge-auth
	 * trunk (host=<ip/fqdn>, no register=>) never registers either way, so a TTL there was misleading. */
	if (peer->is_register_line || !strcasecmp(peer->host, "dynamic")) {
		sofia_cli_peer_line(&buf, "Expires", "%ds", peer->expiresecs);
	}
	sofia_cli_peer_line(&buf, "Secret", "%s", ast_strlen_zero(peer->secret) ? "(none)" : "(set)");
	if (peer->qualify) {
		sofia_cli_peer_line(&buf, "Qualify", "yes, freq=%ds, timeout=%ds, status=%s",
			peer->qualifyfreq, peer->qualifytimeout, status);
	} else {
		sofia_cli_peer_line(&buf, "Qualify", "no");
	}
	if (!ast_strlen_zero(peer->callerid)) {
		sofia_cli_peer_line(&buf, "CallerID", "%s", peer->callerid);
	}
	if (!ast_strlen_zero(peer->cid_num) || !ast_strlen_zero(peer->cid_name)) {
		char merged[256];
		ast_callerid_merge(merged, sizeof(merged),
			S_OR(peer->cid_name, ""), S_OR(peer->cid_num, ""), "<unknown>");
		sofia_cli_peer_line(&buf, "Callerid", "%s", merged);
	}
	if (!ast_strlen_zero(peer->cid_tag)) {
		sofia_cli_peer_line(&buf, "CID tag", "%s", peer->cid_tag);
	}

	sofia_cli_peer_section(&buf, "Network and media");
	sofia_cli_peer_line(&buf, "NAT", "%s", nat);
	sofia_cli_peer_line(&buf, "DTMF mode", "%s", dtmf_str);
	sofia_cli_peer_line(&buf, "Direct media", "%s", AST_CLI_YESNO(peer->directmedia));
	sofia_cli_peer_line(&buf, "Encryption", "%s", AST_CLI_YESNO(peer->encryption));
	sofia_cli_peer_line(&buf, "WebRTC", "%s", AST_CLI_YESNO(peer->webrtc));
	sofia_cli_peer_line(&buf, "Codecs", "%s", ast_strlen_zero(codec_buf) ? "(default)" : codec_buf);
	sofia_cli_peer_line(&buf, "Max call BR", "%d kbps", peer->maxcallbitrate);

	sofia_cli_peer_section(&buf, "Limits and features");
	sofia_cli_peer_line(&buf, "Busy on active", "%s", AST_CLI_YESNO(peer->busy_on_active));
	sofia_cli_peer_line(&buf, "Max contacts", "%d (used: %d)", peer->max_contacts, contacts_used);
	sofia_cli_peer_line(&buf, "Transfer mode", "%s", sofia_transfer_mode_str(peer->allowtransfer));
	sofia_cli_peer_line(&buf, "Lock user-agent", "%s", AST_CLI_YESNO(peer->lockuseragent));
	if (peer->lockuseragent && peer->locked_user_agent[0]) {
		sofia_cli_peer_line(&buf, "Locked UA", "%s", peer->locked_user_agent);
	}
	if (peer->lockuseragent && !ast_strlen_zero(peer->lockuseragent_prefixes)) {
		sofia_cli_peer_line(&buf, "UA prefixes", "%s", peer->lockuseragent_prefixes);
	}
	sofia_cli_peer_line(&buf, "Language", "%s", ast_strlen_zero(peer->language) ? "(none)" : peer->language);
	sofia_cli_peer_line(&buf, "Default IP", "%s", ast_sockaddr_stringify(&peer->defaddr));
	sofia_cli_peer_line(&buf, "AMA flags", "%s", ast_cdr_flags2str(peer->amaflags));
	sofia_cli_peer_line(&buf, "Subscribe MWI", "%s", AST_CLI_YESNO(peer->subscribemwi));
	sofia_cli_peer_line(&buf, "Preferred codec", "%s", AST_CLI_YESNO(peer->preferred_codec_only));
	/* ignoresdpversion: parse-compatibility only (every SDP is processed). */
	sofia_cli_peer_line(&buf, "Ignore SDP ver", "%s", AST_CLI_YESNO(peer->ignoresdpversion));
	/* promiscredir: parse-compatibility only (no nua_r_redirect handler). */
	sofia_cli_peer_line(&buf, "Promisc redir", "%s", AST_CLI_YESNO(peer->promiscredir));
	/* autoframing: parse-compatibility only (ptime gate not wired). */
	sofia_cli_peer_line(&buf, "Auto framing", "%s", AST_CLI_YESNO(peer->autoframing));
	/* faxdetect per-peer mode (DSP CNG + peer T.38 reINVITE detection). */
	sofia_cli_peer_line(&buf, "Fax detect", "%s",
		peer->faxdetect_mode == SOFIA_FAX_DETECT_NONE ? "no" :
		peer->faxdetect_mode == SOFIA_FAX_DETECT_BOTH ? "yes (cng,t38)" :
		peer->faxdetect_mode == SOFIA_FAX_DETECT_CNG ? "cng" : "t38");
	sofia_cli_peer_section(&buf, "Fax and T.38");
	/* 5-field T.38 display (chan_sip parity). */
	sofia_cli_peer_line(&buf, "T38 support", "%s", AST_CLI_YESNO(peer->t38pt_udptl));
	sofia_cli_peer_line(&buf, "T38 EC mode", "%s",
		peer->t38_ec_mode == SOFIA_T38_EC_REDUNDANCY ? "Redundancy" :
		peer->t38_ec_mode == SOFIA_T38_EC_FEC ? "FEC" : "None");
	sofia_cli_peer_line(&buf, "T38 max datagram", "%d", peer->t38_maxdatagram);
	sofia_cli_peer_line(&buf, "T38 RTP source", "%s", AST_CLI_YESNO(peer->t38pt_usertpsource));
	sofia_cli_peer_section(&buf, "Timers and RTP");
	sofia_cli_peer_line(&buf, "Timer B", "%d", peer->timer_b);
	sofia_cli_peer_line(&buf, "Timer T1", "%d", peer->timer_t1);
	sofia_cli_peer_line(&buf, "Overlap dial", "%s", sofia_allowoverlap_str(peer->allowoverlap_mode));
	/* rtp-timeout bundle (chan_sip parity). */
	sofia_cli_peer_line(&buf, "RTP timeout", "%d", peer->rtptimeout);
	sofia_cli_peer_line(&buf, "RTP hold timeout", "%d", peer->rtpholdtimeout);
	sofia_cli_peer_line(&buf, "RTP keepalive", "%d", peer->rtpkeepalive);
	sofia_cli_peer_section(&buf, "Routing and dialplan");
	sofia_cli_peer_line(&buf, "Parking lot", "%s", ast_strlen_zero(peer->parkinglot) ? "(none)" : peer->parkinglot);
	/* usereqphone (chan_sip parity): 3-state inheritance display. */
	if (peer->usereqphone) {
		int from_general = sofia_cfg.default_usereqphone && peer->usereqphone == sofia_cfg.default_usereqphone;
		sofia_cli_peer_line(&buf, "User=Phone", "yes%s", from_general ? " (from [general])" : "");
	} else {
		sofia_cli_peer_line(&buf, "User=Phone", "no");
	}
	/* Account code is shown in the concise summary (above); not duplicated here. */
	/* maxforwards (chan_sip parity): 3-state inheritance display. */
	if (peer->maxforwards == sofia_cfg.default_max_forwards) {
		sofia_cli_peer_line(&buf, "Max forwards", "%d (from [general])", peer->maxforwards);
	} else {
		sofia_cli_peer_line(&buf, "Max forwards", "%d", peer->maxforwards);
	}
	{
		/* MWI mailbox list (NOLOCK; peer->lock is held by the outer caller). */
		struct sofia_mailbox *mb;
		char mailbox_buf[512] = "";
		int first = 1;
		AST_LIST_TRAVERSE(&peer->mailboxes, mb, list) {
			char mailbox_entry[128];
			snprintf(mailbox_entry, sizeof(mailbox_entry), "%s@%s", mb->mailbox, mb->context);
			if (!first) {
				strncat(mailbox_buf, ", ", sizeof(mailbox_buf) - strlen(mailbox_buf) - 1);
			}
			strncat(mailbox_buf, mailbox_entry, sizeof(mailbox_buf) - strlen(mailbox_buf) - 1);
			first = 0;
		}
		sofia_cli_peer_line(&buf, "Mailbox", "%s", first ? "(none)" : mailbox_buf);
	}
	{
		/* outboundproxy: peer value, else [general] inherit-marker, else (none). */
		const char *peer_p = peer->outboundproxy;
		if (!ast_strlen_zero(peer_p)) {
			sofia_cli_peer_line(&buf, "Outbound proxy", "%s", peer_p);
		} else if (!ast_strlen_zero(sofia_cfg.outboundproxy)) {
			sofia_cli_peer_line(&buf, "Outbound proxy", "%s (from [general])", sofia_cfg.outboundproxy);
		} else {
			sofia_cli_peer_line(&buf, "Outbound proxy", "(none)");
		}
	}
	{
		/* MOH Interpret + Suggest (chan_sip parity). Suggest signals INBOUND only today
		 * (outbound HOLD re-INVITE is not issued). */
		sofia_cli_peer_line(&buf, "MOH interpret", "%s",
			ast_strlen_zero(peer->mohinterpret) ? "(none)" : peer->mohinterpret);
		sofia_cli_peer_line(&buf, "MOH suggest", "%s",
			ast_strlen_zero(peer->mohsuggest) ? "(none)" : peer->mohsuggest);
	}
	{
		/* SRTP cipher: 3-state inheritance display. */
		if (!ast_strlen_zero(peer->srtpcipher)) {
			sofia_cli_peer_line(&buf, "SRTP cipher", "%s", peer->srtpcipher);
		} else if (!ast_strlen_zero(sofia_cfg.default_srtpcipher)) {
			sofia_cli_peer_line(&buf, "SRTP cipher", "%s (from [general])", sofia_cfg.default_srtpcipher);
		} else {
			sofia_cli_peer_line(&buf, "SRTP cipher", "(default AES_CM_128_HMAC_SHA1_80)");
		}
	}
	sofia_cli_peer_section(&buf, "Session and identity headers");
	/* Session timers (RFC 4028): 4-line display. */
	sofia_cli_peer_line(&buf, "Session timers", "%s", st_mode_str);
	sofia_cli_peer_line(&buf, "Session expires", "%d", peer->session_expires);
	sofia_cli_peer_line(&buf, "Session Min-SE", "%d", peer->session_minse);
	sofia_cli_peer_line(&buf, "Session refresher", "%s", st_refresher_str);
	sofia_cli_peer_line(&buf, "Calling pres", "%s", ast_named_caller_presentation(peer->callingpres));
	sofia_cli_peer_line(&buf, "Send RPID", "%s", sendrpid_str);
	sofia_cli_peer_line(&buf, "Trust RPID", "%s", AST_CLI_YESNO(peer->trustrpid));
	sofia_cli_peer_line(&buf, "Concurrent calls", "%d/%s (%d ringing, %d on-hold)",
		peer->inUse, limit_str, peer->inRinging, peer->onHold);

	sofia_cli_peer_section(&buf, "Groups and source");
	{
		char grp_buf[256];
		sofia_cli_peer_line(&buf, "Call group", "%s", ast_print_group(grp_buf, sizeof(grp_buf), peer->callgroup));
		sofia_cli_peer_line(&buf, "Pickup group", "%s", ast_print_group(grp_buf, sizeof(grp_buf), peer->pickupgroup));
	}
	/* regexten display-gate (chan_sip parity): shown only when regcontext is set. */
	if (!ast_strlen_zero(sofia_cfg.regcontext) && !ast_strlen_zero(peer->regexten)) {
		sofia_cli_peer_line(&buf, "Reg ext", "%s", peer->regexten);
	}
	if (!ast_strlen_zero(peer->callbackextension)) {
		sofia_cli_peer_line(&buf, "Callback ext", "%s", peer->callbackextension);
	}
	/* GRUU (RFC 5627): advertisement opt-in + any GRUU the registrar minted. */
	if (peer->gruu) {
		sofia_cli_peer_line(&buf, "GRUU", "advertised (+sip.instance)");
		if (!ast_strlen_zero(peer->pub_gruu)) {
			sofia_cli_peer_line(&buf, "Pub-GRUU", "%s", peer->pub_gruu);
		}
		if (!ast_strlen_zero(peer->temp_gruu)) {
			sofia_cli_peer_line(&buf, "Temp-GRUU", "%s", peer->temp_gruu);
		}
	}
	/* Service-Route (RFC 3608): opt-in + any route learned from the registrar's REGISTER 200. */
	if (peer->use_service_route) {
		sofia_cli_peer_line(&buf, "Service-Route", "%s",
			!ast_strlen_zero(peer->service_route) ? peer->service_route : "(enabled, none learned)");
	}
	/* 100rel/PRACK (RFC 3262): reliable non-183 provisionals to this peer (opt-in). */
	if (peer->rel100) {
		sofia_cli_peer_line(&buf, "100rel", "reliable provisionals (PRACK)");
	}
	/* SIP Outbound (RFC 5626): opt-in advertisement + the registrar's runtime confirmation/Flow-Timer. */
	if (peer->sip_outbound) {
		char ft[32] = "";
		if (peer->flow_timer > 0) {
			snprintf(ft, sizeof(ft), ", Flow-Timer %ds", peer->flow_timer);
		}
		sofia_cli_peer_line(&buf, "SIP Outbound", "advertised (reg-id=1, +sip.instance); registrar %s%s",
			peer->sip_outbound_active ? "confirmed (Require: outbound)" : "not confirmed", ft);
	}
	/* setvar + header display (chan_sip parity): header= entries carry the
	 * __SIPADDHEADERpre%2d= prefix. */
	if (peer->chanvars) {
		struct ast_variable *var;
		for (var = peer->chanvars; var; var = var->next) {
			/* FULL-security: never print the VALUE of a chanvar whose NAME suggests a credential (an admin
			 * could stash a token/password in setvar=). Case-insensitive substring match on the name. */
			int secret_name = strcasestr(var->name, "secret") || strcasestr(var->name, "password")
				|| strcasestr(var->name, "pass") || strcasestr(var->name, "token")
				|| strcasestr(var->name, "key") || strcasestr(var->name, "nonce")
				|| strcasestr(var->name, "auth");
			sofia_cli_peer_line(&buf, "Variable", "%s = %s", var->name,
				secret_name ? "<redacted>" : var->value);
		}
	}
	/* subscribecontext (chan_sip parity): 3-state inheritance display. */
	if (!ast_strlen_zero(peer->subscribecontext)) {
		int from_general = !ast_strlen_zero(sofia_cfg.default_subscribecontext)
			&& !strcmp(peer->subscribecontext, sofia_cfg.default_subscribecontext);
		sofia_cli_peer_line(&buf, "Subscribe context", "%s%s", peer->subscribecontext,
			from_general ? " (from [general])" : "");
	} else if (!ast_strlen_zero(sofia_cfg.default_subscribecontext)) {
		sofia_cli_peer_line(&buf, "Subscribe context", "%s (from [general])", sofia_cfg.default_subscribecontext);
	} else {
		sofia_cli_peer_line(&buf, "Subscribe context", "<Not set>");
	}
	if (!ast_strlen_zero(peer->fromuser)) {
		sofia_cli_peer_line(&buf, "From user", "%s", peer->fromuser);
	}
	if (!ast_strlen_zero(peer->fromdomain)) {
		sofia_cli_peer_line(&buf, "From domain", "%s", peer->fromdomain);
	}

	sofia_cli_peer_section(&buf, "Security and ACL");
	{
		char ins[64] = "";
		if (peer->insecure & SOFIA_INSECURE_PORT) {
			ast_copy_string(ins, "port", sizeof(ins));
		}
		if (peer->insecure & SOFIA_INSECURE_INVITE) {
			if (ins[0]) {
				strncat(ins, ",", sizeof(ins) - strlen(ins) - 1);
			}
			strncat(ins, "invite", sizeof(ins) - strlen(ins) - 1);
		}
		sofia_cli_peer_line(&buf, "Insecure", "%s", ins[0] ? ins : "no");
	}

	if (peer->ha) {
		sofia_cli_peer_line(&buf, "ACL", "yes");
		sofia_print_ha_lines(&buf, peer->ha);
	} else {
		sofia_cli_peer_line(&buf, "ACL", "no");
	}
	sofia_cli_peer_line(&buf, "Contact ACL", "%s", peer->contactha ? "yes" : "no");
	sofia_cli_peer_line(&buf, "Direct media ACL", "%s", peer->directmediaha ? "yes" : "no");
	sofia_cli_peer_line(&buf, "DNS managed", "%s", peer->dnsmgr ? "yes" : "no");

	sofia_cli_peer_section(&buf, "Registration");
	sofia_cli_peer_line(&buf, "Source", "%s", source_str);
	/* Outbound register state — ONLY for an explicit register=> peer (is_register_line), matching
	 * sofia_do_register's opt-in gate. A static challenge-auth trunk (secret only for outbound digest
	 * auth, e.g. a carrier or SBC challenge-auth trunk) is NOT a register target and must not show register
	 * scaffolding — showing it falsely implied the peer was registering. */
	if (peer->is_register_line) {
		sofia_cli_peer_line(&buf, "Outbound reg", "target=%s:%d expiry=%lds attempts=%d",
			peer->host, peer->port,
			peer->reg_expiry > 0 ? (long)(peer->reg_expiry - time(NULL)) : 0,
			peer->reg_attempts);
	}

	if (!ast_sockaddr_isnull(&peer->src_addr)) {
		sofia_cli_peer_line(&buf, "Source addr", "%s", ast_sockaddr_stringify(&peer->src_addr));
	}
	}	/* end of the "detail"-only per-field dump; the Contacts section below is always shown */

	sofia_cli_peer_section(&buf, "Contacts");
	if (peer->contacts && contacts_used > 0) {
		struct ao2_iterator ci;
		struct sofia_contact *c;
		time_t now = time(NULL);
		int idx = 1;

		sofia_cli_peer_line(&buf, "Contact count", "%d", contacts_used);
		ci = ao2_iterator_init(peer->contacts, 0);
		while ((c = ao2_iterator_next(&ci))) {
			char ttl_buf[32];
			char contact_status[32];
			char contact_label[32];
			char src_buf[64];
			int active_calls;
			long ttl;
			time_t c_last;
			const char *src;

			/* Snapshot the mutable contact fields under the contact lock (a REGISTER
			 * refresh rewrites them). Lock order: peer->lock (held) -> contact lock. */
			char ua_buf[256];
			char c_path[1024];
			ao2_lock(c);
			ttl = (long)(c->expires - now);
			c_last = c->last_register;
			ast_copy_string(src_buf, !ast_sockaddr_isnull(&c->src_addr) ?
				ast_sockaddr_stringify(&c->src_addr) : "(unknown)", sizeof(src_buf));
			ast_copy_string(ua_buf, c->user_agent[0] ? c->user_agent : "(none)", sizeof(ua_buf));
			ast_copy_string(c_path, c->path, sizeof(c_path));
			active_calls = c->active_calls;
			ao2_unlock(c);
			src = src_buf;

			snprintf(ttl_buf, sizeof(ttl_buf), "%lds", ttl > 0 ? ttl : 0);
			if (ttl <= 0) {
				ast_copy_string(contact_status, "EXPIRED", sizeof(contact_status));	/* registration lapsed -> not routable (CHANUNAVAIL on a dynamic peer) */
			} else if (active_calls > 0) {
				snprintf(contact_status, sizeof(contact_status),
					"IN-CALL:%d", active_calls);
			} else {
				ast_copy_string(contact_status, "AVAILABLE", sizeof(contact_status));
			}
			snprintf(contact_label, sizeof(contact_label), "Contact %d URI", idx++);
			sofia_cli_peer_line(&buf, contact_label, "%s", c->contact_uri);
			sofia_cli_peer_subline(&buf, "State", "%s", contact_status);
			sofia_cli_peer_subline(&buf, "TTL", "%s", ttl_buf);
			{	/* diagnostic: seconds since this contact last (re)REGISTERed + expiry state */
				char idle_buf[128];
				if (!c_last) {
					ast_copy_string(idle_buf, "unknown (never stamped)", sizeof(idle_buf));
				} else {
					long age = (long)(now - c_last);
					snprintf(idle_buf, sizeof(idle_buf), "%lds ago - %s", age,
						ttl <= 0 ? "EXPIRED (re-REGISTER required)" : "live");
				}
				sofia_cli_peer_subline(&buf, "Last-REGISTER", "%s", idle_buf);
			}
			sofia_cli_peer_subline(&buf, "Source", "%s", src);
			sofia_cli_peer_subline(&buf, "User-Agent", "%s", ua_buf);
			if (!ast_strlen_zero(c_path)) {
				sofia_cli_peer_subline(&buf, "Path", "%s", c_path);	/* RFC 3327 */
			}
			ao2_ref(c, -1);
		}
		ao2_iterator_destroy(&ci);
	} else {
		sofia_cli_peer_line(&buf, "Contacts", "(none)");
	}
	ast_mutex_unlock(&peer->lock);

	/* Single blocking write after the unlock; literal "%s" (peer data may contain '%'). */
	ast_cli(a->fd, "%s", ast_str_buffer(buf));
	ast_free(buf);

	ao2_ref(peer, -1);

	return CLI_SUCCESS;
}

char *sofia_cli_show_inuse(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
#define FORMAT "%-25.25s %-15.15s %-15.15s \n"
#define FORMAT2 "%-25.25s %-15.15s %-15.15s \n"
	char ilimits[40];
	char iused[40];
	char l_name[256];
	int showall = 0;
	struct ao2_iterator iter;
	struct sofia_peer *peer;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show inuse";
		e->usage =
			"Usage: sip show inuse [all]\n"
			"       List all SIP devices usage counters and limits.\n"
			"       Add option \"all\" to show all devices, not only those with a limit.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc < 3)
		return CLI_SHOWUSAGE;

	if (a->argc == 4 && !strcmp(a->argv[3], "all"))
		showall = 1;

	ast_cli(a->fd, FORMAT, "* Peer name", "In use", "Limit");

	iter = ao2_iterator_init(peers, 0);
	while ((peer = ao2_iterator_next(&iter))) {
		ao2_lock(peer);
		/* peer->name is an unbounded stringfield freed by the reload writer under
		 * peer->lock (NOT ao2_lock); snapshot under peer->lock to avoid a UAF. */
		ast_mutex_lock(&peer->lock);
		ast_copy_string(l_name, peer->name, sizeof(l_name));
		ast_mutex_unlock(&peer->lock);
		if (peer->call_limit) {
			snprintf(ilimits, sizeof(ilimits), "%d", peer->call_limit);
		} else {
			ast_copy_string(ilimits, "N/A", sizeof(ilimits));
		}
		snprintf(iused, sizeof(iused), "%d/%d/%d",
			peer->inUse, peer->inRinging, peer->onHold);
		/* Decide under the ao2 lock, release, then do the blocking ast_cli on snapshots. */
		int show = (showall || peer->call_limit > 0 || peer->busy_level > 0
				|| peer->inUse > 0 || peer->inRinging > 0 || peer->onHold > 0);
		ao2_unlock(peer);
		if (show) {
			ast_cli(a->fd, FORMAT2, l_name, iused, ilimits);
		}
		ao2_ref(peer, -1);
	}
	ao2_iterator_destroy(&iter);

	return CLI_SUCCESS;
#undef FORMAT
#undef FORMAT2
}

char *sofia_cli_show_settings(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show settings";
		e->usage =
			"Usage: sip show settings\n"
			"       Show global Sofia-SIP [general] configuration values.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	ast_cli(a->fd, "\nGlobal Settings:\n");
	ast_cli(a->fd, "----------------\n");
	ast_cli(a->fd, "  User Agent:             %s\n", sofia_cfg.useragent);
	ast_cli(a->fd, "  Realm:                  %s\n", sofia_cfg.realm);
	ast_cli(a->fd, "  Bind Address:           %s\n", sofia_cfg.bindaddr);
	ast_cli(a->fd, "  Bind Port:              %d\n", sofia_cfg.bindport);
	/* TLS/WS/WSS bind ports: "(disabled)" when 0. */
	if (sofia_cfg.tlsbindport > 0) {
		ast_cli(a->fd, "  TLS Bind Port:          %d\n", sofia_cfg.tlsbindport);
	} else {
		ast_cli(a->fd, "  TLS Bind Port:          (disabled)\n");
	}
	if (sofia_cfg.wsbindport > 0) {
		ast_cli(a->fd, "  WS Bind Port:           %d\n", sofia_cfg.wsbindport);
	} else {
		ast_cli(a->fd, "  WS Bind Port:           (disabled)\n");
	}
	if (sofia_cfg.wssbindport > 0) {
		ast_cli(a->fd, "  WSS Bind Port:          %d\n", sofia_cfg.wssbindport);
	} else {
		ast_cli(a->fd, "  WSS Bind Port:          (disabled)\n");
	}
	/* ignoresdpversion: parse-compatibility only (every SDP is processed). */
	ast_cli(a->fd, "  Ignore SDP sess. ver.:  %s\n", AST_CLI_YESNO(sofia_cfg.default_ignoresdpversion));
	/* progressinband: Never/Yes/No (NO degrades to NEVER). */
	ast_cli(a->fd, "  Progress inband:        %s\n",
		sofia_cfg.default_progressinband == SOFIA_PROG_INBAND_NEVER ? "Never" :
		sofia_cfg.default_progressinband == SOFIA_PROG_INBAND_YES ? "Yes" : "No");
	/* subscribe_network_change_event: parse-compatibility only (delegated to sofia-sip/dnsmgr). */
	ast_cli(a->fd, "  Network change subscribe: %s\n",
		AST_CLI_YESNO(sofia_cfg.subscribe_network_change_event));
	ast_cli(a->fd, "  Save sys. name:         %s\n", AST_CLI_YESNO(sofia_cfg.rtsave_sysname));
	ast_cli(a->fd, "  Update:                 %s\n", AST_CLI_YESNO(sofia_cfg.peer_rtupdate));
	ast_cli(a->fd, "  Q.850 Reason header:    %s\n", AST_CLI_YESNO(sofia_cfg.use_q850_reason));
	/* rtcachefriends: parse-compatibility only (the ao2 registry always caches all peers). */
	ast_cli(a->fd, "  Cache Friends:          %s\n", AST_CLI_YESNO(sofia_cfg.rtcachefriends));
	/* rtautoclear: parse-compatibility only (no peer-level auto-clear). */
	ast_cli(a->fd, "  Auto Clear:             %d (%s)\n", sofia_cfg.rtautoclear,
		sofia_cfg.rtautoclear_enabled ? "Enabled" : "Disabled");
	ast_cli(a->fd, "  Use domains as realms:  %s\n", AST_CLI_YESNO(sofia_cfg.domainsasrealm));
	ast_cli(a->fd, "  Call to non-local dom.: %s\n", AST_CLI_YESNO(sofia_cfg.allow_external_domains));
	ast_cli(a->fd, "  Auto Domain:            %s\n", AST_CLI_YESNO(sofia_cfg.autodomain));
	/* promiscredir: parse-compatibility only (no nua_r_redirect handler). */
	ast_cli(a->fd, "  Allow promisc. redir.:  %s\n", AST_CLI_YESNO(sofia_cfg.default_promiscredir));
	/* matchexternaddrlocally: parse-compatibility only. */
	ast_cli(a->fd, "  Match extern locally:   %s\n", AST_CLI_YESNO(sofia_cfg.matchexternaddrlocally));
	/* autoframing: parse-compatibility only (ptime gate not wired). */
	ast_cli(a->fd, "  Auto-Framing:           %s\n", AST_CLI_YESNO(sofia_cfg.default_autoframing));
	/* faxdetect: 4-state display (CNG + T.38 detection implemented). */
	ast_cli(a->fd, "  Fax Detect:             %s\n",
		sofia_cfg.default_faxdetect_mode == SOFIA_FAX_DETECT_NONE ? "no" :
		sofia_cfg.default_faxdetect_mode == SOFIA_FAX_DETECT_BOTH ? "cng,t38" :
		sofia_cfg.default_faxdetect_mode == SOFIA_FAX_DETECT_CNG ? "cng" : "t38");
	/* [general] T.38 default MaxDatagram: sentinel -1 displays as "(default 200)". */
	if (sofia_cfg.default_t38_maxdatagram > 0) {
		ast_cli(a->fd, "  T.38 MaxDatagram:       %d\n", sofia_cfg.default_t38_maxdatagram);
	} else {
		ast_cli(a->fd, "  T.38 MaxDatagram:       (default 200)\n");
	}
	ast_cli(a->fd, "  MWI expiry:             %d\n", sofia_cfg.mwi_expiry);
	ast_cli(a->fd, "  Timer B:                %d\n", sofia_cfg.default_timer_b);
	ast_cli(a->fd, "  Timer T1:               %d\n", sofia_cfg.default_timer_t1);
	ast_cli(a->fd, "  Allow overlap dialing:  %s\n", sofia_allowoverlap_str(sofia_cfg.default_allowoverlap_mode));
	/* SRTP per-suite fresh-key option (chan_sofia-only). */
	ast_cli(a->fd, "  SRTP per-suite keys:    %s\n", AST_CLI_YESNO(sofia_cfg.srtp_per_suite_keys));
	/* WebRTC [general] default (DTLS-SRTP + ICE-lite + rtcp-mux); per-peer webrtc= overrides. */
	ast_cli(a->fd, "  WebRTC (default):       %s\n", AST_CLI_YESNO(sofia_cfg.webrtc));
	/* Force INVITE auth (chan_sofia-only global security override). */
	ast_cli(a->fd, "  Force INVITE auth:      %s\n", AST_CLI_YESNO(sofia_cfg.force_invite_auth));
	/* Auth algorithms (RFC 7616): static report; challenges are MD5-first, SHA-256
	 * omitted for md5secret-only peers. */
	ast_cli(a->fd, "  Auth algorithms:        MD5, SHA-256\n");
	/* auth_qop: yes = RFC 2617/7616 qop="auth" MD5 challenge; no = chan_sip legacy no-qop (RFC 2069). */
	ast_cli(a->fd, "  Auth qop:               %s\n", AST_CLI_YESNO(sofia_cfg.auth_qop));
	/* apply_peer_callerid: yes = force matched-peer callerid on inbound (chan_sip parity); no = keep From. */
	ast_cli(a->fd, "  Apply peer callerid:    %s\n", AST_CLI_YESNO(sofia_cfg.apply_peer_callerid));
	/* [general] callerid: fallback From identity when nothing else resolves (chan_sip default_callerid). */
	ast_cli(a->fd, "  Default callerid:       %s\n", S_OR(sofia_cfg.default_callerid, "gabpbx"));

	{
		char hist_filter[SOFIA_HISTORY_FILTER];
		sofia_history_filter_copy(hist_filter, sizeof(hist_filter));
		ast_cli(a->fd, "  Record SIP history:     %s%s%s\n", sofia_record_history ? "Yes" : "No",
			(sofia_record_history && !ast_strlen_zero(hist_filter)) ? ", filter " : "",
			(sofia_record_history && !ast_strlen_zero(hist_filter)) ? hist_filter : "");
	}

	/* Outbound PUBLISH (RFC 3903) — password REDACTED. */
	ast_cli(a->fd, "  Outbound PUBLISH:       %s\n",
		ast_strlen_zero(sofia_cfg.publish_server) ? "(off)" : sofia_cfg.publish_server);
	if (!ast_strlen_zero(sofia_cfg.publish_server)) {
		ast_cli(a->fd, "    Presentity domain:    %s\n",
			ast_strlen_zero(sofia_cfg.publish_domain) ? "(publish_server host)" : sofia_cfg.publish_domain);
		ast_cli(a->fd, "    Expires:              %d\n",
			sofia_cfg.publish_expires > 0 ? sofia_cfg.publish_expires : SOFIA_PUBLISH_DEFAULT_EXPIRES);
		ast_cli(a->fd, "    Auth user:            %s\n",
			ast_strlen_zero(sofia_cfg.publish_username) ? "(none)" : sofia_cfg.publish_username);
		ast_cli(a->fd, "    Auth password:        %s\n",
			ast_strlen_zero(sofia_cfg.publish_password) ? "(none)" : "<set>");
	}
	ast_cli(a->fd, "\n");

	return CLI_SUCCESS;
}

char *sofia_set_debug(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	const char *what;

	if (cmd == CLI_INIT) {
		e->command = "sip set debug";
		e->usage =
			"Usage: sip set debug [on|off|peer <name>|ip <addr>|file <path>|off|capture <host:port>|off|fork {on|off}|dtmf {on|off}]\n"
			"       Show current debug state, or enable/disable Sofia-SIP debug.\n"
			"       'on'  - enable debug for all peers\n"
			"       'off' - disable debug\n"
			"       'peer <name>' - enable debug for a specific peer\n"
			"       'ip <addr>'   - enable debug for a specific IP address\n"
			"       'file <path>' - append EVERY decrypted SIP message (incl. SDP, over ws/wss/tls/udp)\n"
			"                       to <path>; 'file off' stops it (Homer/HEP-free, plain text)\n"
			"       'capture <host:port>' - stream all decrypted SIP as HEP (UDP) to a Homer/sipcapture\n"
			"                       server (e.g. 127.0.0.1:9060); 'capture off' stops it. HEP version\n"
			"                       from sip_capture_hep (default 3).\n"
			"       'fork {on|off}' - fork/flow lifecycle trace (child create/cancel, winner nh/rtp/fd\n"
			"                       steal, regflow drop + media_error). Correlates to 'rtp set debug ice'\n"
			"                       by the rtp pointer. Pure logging, default OFF.\n"
			"       'dtmf {on|off}' - NOTICE per received DTMF digit (RFC2833 / SIP INFO / inband) so you\n"
			"                       can SEE keypresses in the CLI + messages. Pure logging, default OFF.\n";
		return NULL;
	} else if (cmd == CLI_GENERATE) {
		if (a->pos == 3)
			return ast_cli_complete(a->word, (const char *[]){ "on", "off", "peer", "ip", "file", "capture", "fork", "dtmf", NULL }, a->n);
		if (a->pos == 4 && (!strcasecmp(a->argv[3], "file") || !strcasecmp(a->argv[3], "capture")))
			return ast_cli_complete(a->word, (const char *[]){ "off", NULL }, a->n);
		if (a->pos == 4 && (!strcasecmp(a->argv[3], "fork") || !strcasecmp(a->argv[3], "dtmf")))
			return ast_cli_complete(a->word, (const char *[]){ "on", "off", NULL }, a->n);
		return NULL;
	}

	if (a->argc == 3) {
		ast_cli(a->fd, "Sofia debug is %s", sofia_debug ? "enabled" : "disabled");
		if (sofia_debug == 2)
			ast_cli(a->fd, " (peer: %s)", sofia_debug_filter);
		else if (sofia_debug == 3)
			ast_cli(a->fd, " (ip: %s)", sofia_debug_filter);
		ast_cli(a->fd, "\n");
		return CLI_SUCCESS;
	}

	if (a->argc < 4 || a->argc > 5)
		return CLI_SHOWUSAGE;

	what = a->argv[3];

	/* sofia_apply_log_from_cli marshals the tport TPTAG_LOG toggle onto sofia_thread (tport_set_params
	 * mutates shared stack state). Dispatch FIRST and only mutate sofia_debug / claim success if it
	 * succeeds — on failure the tport log state is unchanged, so claiming success (esp. peer/ip, which
	 * turn full logging OFF) would leave the real state disagreeing with the CLI. */
	if (!strcasecmp(what, "on")) {
		if (sofia_apply_log_from_cli(1) < 0) {
			ast_cli(a->fd, "Sofia debug: failed to apply tport log change (dispatch)\n");
			return CLI_FAILURE;
		}
		sofia_debug = 1;
		sofia_debug_filter[0] = '\0';
		ast_cli(a->fd, "Sofia debug enabled\n");
		return CLI_SUCCESS;
	} else if (!strcasecmp(what, "off")) {
		if (sofia_apply_log_from_cli(0) < 0) {
			ast_cli(a->fd, "Sofia debug: failed to apply tport log change (dispatch)\n");
			return CLI_FAILURE;
		}
		sofia_debug = 0;
		sofia_debug_filter[0] = '\0';
		ast_cli(a->fd, "Sofia debug disabled\n");
		return CLI_SUCCESS;
	} else if (!strcasecmp(what, "peer")) {
		if (a->argc != 5)
			return CLI_SHOWUSAGE;
		if (sofia_apply_log_from_cli(0) < 0) {
			ast_cli(a->fd, "Sofia debug: failed to apply tport log change (dispatch)\n");
			return CLI_FAILURE;
		}
		sofia_debug = 2;
		ast_copy_string(sofia_debug_filter, a->argv[4], sizeof(sofia_debug_filter));
		ast_cli(a->fd, "Sofia debug enabled for peer '%s'\n", sofia_debug_filter);
		return CLI_SUCCESS;
	} else if (!strcasecmp(what, "ip")) {
		if (a->argc != 5)
			return CLI_SHOWUSAGE;
		if (sofia_apply_log_from_cli(0) < 0) {
			ast_cli(a->fd, "Sofia debug: failed to apply tport log change (dispatch)\n");
			return CLI_FAILURE;
		}
		sofia_debug = 3;
		ast_copy_string(sofia_debug_filter, a->argv[4], sizeof(sofia_debug_filter));
		ast_cli(a->fd, "Sofia debug enabled for IP '%s'\n", sofia_debug_filter);
		return CLI_SUCCESS;
	} else if (!strcasecmp(what, "fork")) {
		/* B1: fork/flow lifecycle trace (fork child create/cancel, winner nh/rtp/fd steal, regflow
		 * drop + media_error). Separate flag from sofia_debug; pure logging, no behavior change. */
		if (a->argc != 5)
			return CLI_SHOWUSAGE;
		if (!strcasecmp(a->argv[4], "on")) {
			sofia_forkdebug = 1;
			ast_cli(a->fd, "Sofia fork/flow debug enabled\n");
		} else if (!strcasecmp(a->argv[4], "off")) {
			sofia_forkdebug = 0;
			ast_cli(a->fd, "Sofia fork/flow debug disabled\n");
		} else {
			return CLI_SHOWUSAGE;
		}
		return CLI_SUCCESS;
	} else if (!strcasecmp(what, "dtmf")) {
		/* NOTICE per received DTMF digit (RFC2833 / SIP INFO / inband) so operators can SEE what users
		 * press, in the CLI + messages file. Own toggle (not tied to full sip debug); pure logging. */
		if (a->argc != 5)
			return CLI_SHOWUSAGE;
		if (!strcasecmp(a->argv[4], "on")) {
			sofia_dtmflog = 1;
			ast_cli(a->fd, "Sofia DTMF logging enabled (received digits -> NOTICE)\n");
		} else if (!strcasecmp(a->argv[4], "off")) {
			sofia_dtmflog = 0;
			ast_cli(a->fd, "Sofia DTMF logging disabled\n");
		} else {
			return CLI_SHOWUSAGE;
		}
		return CLI_SUCCESS;
	} else if (!strcasecmp(what, "file")) {
		/* Dump EVERY decrypted SIP message (recv+sent, udp/tcp/tls/ws/wss, incl. SDP) to a file
		 * via sofia-sip's built-in TPTAG_DUMP. Runtime override; a `sip reload` re-applies sofia.conf. */
		if (a->argc != 5)
			return CLI_SHOWUSAGE;
		/* Thread-safety: the apply mutates the shared tport dump FILE* — marshal it onto sofia_thread
		 * (sofia_apply_capture_from_cli) instead of touching tport_set_params from the CLI thread. */
		if (!strcasecmp(a->argv[4], "off")) {
			if (sofia_apply_capture_from_cli(0, "") < 0) {
				ast_cli(a->fd, "Sofia: failed to queue capture change (sofia thread unavailable)\n");
				return CLI_FAILURE;
			}
			ast_cli(a->fd, "Sofia: SIP message dump to file disabled\n");
		} else {
			if (sofia_apply_capture_from_cli(0, a->argv[4]) < 0) {
				ast_cli(a->fd, "Sofia: failed to queue capture change (sofia thread unavailable)\n");
				return CLI_FAILURE;
			}
			ast_cli(a->fd, "Sofia: dumping decrypted SIP messages to '%s'\n", a->argv[4]);
		}
		return CLI_SUCCESS;
	} else if (!strcasecmp(what, "capture")) {
		/* Stream all decrypted SIP as HEP (UDP) to a Homer/sipcapture server via TPTAG_CAPT.
		 * HEP version from sip_capture_hep (default 3). Runtime override; `sip reload` re-applies. */
		if (a->argc != 5)
			return CLI_SHOWUSAGE;
		/* Thread-safety: marshal onto sofia_thread (the apply reopens the shared tport capture socket). */
		if (!strcasecmp(a->argv[4], "off")) {
			if (sofia_apply_capture_from_cli(1, "") < 0) {
				ast_cli(a->fd, "Sofia: failed to queue capture change (sofia thread unavailable)\n");
				return CLI_FAILURE;
			}
			ast_cli(a->fd, "Sofia: SIP HEP capture disabled\n");
		} else {
			int hep = (sofia_cfg.sip_capture_hep >= 1 && sofia_cfg.sip_capture_hep <= 3)
				? sofia_cfg.sip_capture_hep : 3;
			if (sofia_apply_capture_from_cli(1, a->argv[4]) < 0) {
				ast_cli(a->fd, "Sofia: failed to queue capture change (sofia thread unavailable)\n");
				return CLI_FAILURE;
			}
			ast_cli(a->fd, "Sofia: streaming decrypted SIP as HEPv%d (UDP) to '%s'\n", hep, a->argv[4]);
		}
		return CLI_SUCCESS;
	}

	return CLI_SHOWUSAGE;
}

char *sofia_cli_reload(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	char errmsg[256] = "";

	if (cmd == CLI_INIT) {
		e->command = "sip reload";
		e->usage =
			"Usage: sip reload\n"
			"       Re-read /etc/gabpbx/sofia.conf and apply changes to peers,\n"
			"       trunks and [general] settings without restarting GABPBX.\n"
			"       chan_sip-parity alias for `module reload chan_sofia.so`.\n"
			"       Listener-level settings (bindaddr/bindport/tlsbindaddr/\n"
			"       tlsbindport/tlsenable/tlscertfile/tlscafile/wsbindaddr/\n"
			"       wsbindport/wsenable/wssbindaddr/wssbindport/wssenable/\n"
			"       tcp_keepalive/tcp_pingpong/timert1/timerb/tlsverify/\n"
			"       tlsverifyclient/tls_ciphers/tls_min_version/tls_verify_depth)\n"
			"       are baked into the SIP listener\n"
			"       at module load and require `systemctl restart gabpbx` to\n"
			"       take effect; the reload reports `listener config changed`\n"
			"       and aborts if any of these differs from the running value.\n";
		return NULL;
	} else if (cmd == CLI_GENERATE) {
		return NULL;
	}
	if (a->argc != 2) {
		return CLI_SHOWUSAGE;
	}
	if (sofia_reload_request_sync(errmsg, sizeof(errmsg), 30000) == 0) {
		ast_cli(a->fd, "Sofia: sofia.conf reloaded\n");
	} else {
		ast_cli(a->fd, "Sofia: reload failed — %s\n",
			errmsg[0] ? errmsg : "see log");
	}
	return CLI_SUCCESS;
}

char *sofia_cli_prune_realtime(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct sofia_peer *peer;
	int prunepeer = 0;
	int multi = 0;
	const char *name = NULL;
	regex_t regexbuf;
	int havepattern = 0;
	static const char * const choices[] = { "all", "like", NULL };
	char *cmplt;

	if (cmd == CLI_INIT) {
		e->command = "sip prune realtime [peer|all]";
		e->usage =
			"Usage: sip prune realtime [peer [<name>|all|like <pattern>]|all]\n"
			"       Prunes object(s) from the cache.\n"
			"       Optional regular expression pattern is used to filter the objects.\n";
		return NULL;
	} else if (cmd == CLI_GENERATE) {
		if (a->pos == 4 && !strcasecmp(a->argv[3], "peer")) {
			cmplt = ast_cli_complete(a->word, choices, a->n);
			if (!cmplt) {
				cmplt = complete_sofia_peer(a->word, a->n - 2, 1);
			}
			return cmplt;
		}
		if (a->pos == 5 && !strcasecmp(a->argv[4], "like")) {
			return complete_sofia_peer(a->word, a->n, 1);
		}
		return NULL;
	}

	switch (a->argc) {
	case 4:
		name = a->argv[3];
		if (!strcasecmp(name, "peer") || !strcasecmp(name, "like")) {
			return CLI_SHOWUSAGE;
		}
		prunepeer = 1;
		if (!strcasecmp(name, "all")) {
			multi = 1;
			name = NULL;
		}
		break;
	case 5:
		name = a->argv[4];
		if (!strcasecmp(a->argv[3], "peer")) {
			prunepeer = 1;
		} else if (!strcasecmp(a->argv[3], "like")) {
			prunepeer = 1;
			multi = 1;
		} else {
			return CLI_SHOWUSAGE;
		}
		if (!strcasecmp(name, "like")) {
			return CLI_SHOWUSAGE;
		}
		if (!multi && !strcasecmp(name, "all")) {
			multi = 1;
			name = NULL;
		}
		break;
	case 6:
		name = a->argv[5];
		multi = 1;
		if (strcasecmp(a->argv[4], "like")) {
			return CLI_SHOWUSAGE;
		}
		if (!strcasecmp(a->argv[3], "peer")) {
			prunepeer = 1;
		} else {
			return CLI_SHOWUSAGE;
		}
		break;
	default:
		return CLI_SHOWUSAGE;
	}

	if (multi && name) {
		if (regcomp(&regexbuf, name, REG_EXTENDED | REG_NOSUB)) {
			return CLI_SHOWUSAGE;
		}
		havepattern = 1;
	}

	if (multi) {
		if (prunepeer) {
			/* ao2 allows unlink during iteration: the iterator holds its own ref. */
			int pruned = 0;
			struct ao2_iterator i = ao2_iterator_init(peers, 0);
			struct sofia_peer *pi;
			while ((pi = ao2_iterator_next(&i))) {
				if (!pi->is_realtime) {
					ao2_ref(pi, -1);
					continue;
				}
				if (havepattern && regexec(&regexbuf, pi->name, 0, NULL, 0)) {
					ao2_ref(pi, -1);
					continue;
				}
				/* Release dnsmgr + drop its +1 ref BEFORE ao2_unlink, else the dnsmgr ref pins
				 * the peer at refcount >= 1 and the destructor never runs (peer + res_dnsmgr
				 * callback leak). Atomic detach-under-lock + release-outside guards against a
				 * concurrent prune/reload double-releasing the same handle. */
				sofia_peer_release_dnsmgr(pi, 1);
				/* Drop the realtime-peer dialplan hint (registrar "realtime_peer") — the reload
				 * sweep uses "sofia_config_peer" + skips realtime peers, so it never reclaims these;
				 * else the hint dangles at a freed SIP/<name>. */
				{
					/* Snapshot stringfields under pi->lock (leaf) — racing the reload worker's
					 * stringfield-pool free. */
					char l_sub[AST_MAX_CONTEXT], l_rex[256];	/* l_rex = multi-token regexten SPEC -> 256 (splitter), not one exten */
					ast_mutex_lock(&pi->lock);
					ast_copy_string(l_sub, pi->subscribecontext, sizeof(l_sub));
					ast_copy_string(l_rex, pi->regexten, sizeof(l_rex));
					ast_mutex_unlock(&pi->lock);
					if (!ast_strlen_zero(l_sub) && !ast_strlen_zero(l_rex)) {
						sofia_remove_peer_hints(l_rex, l_sub, "realtime_peer");
					}
				}
				/* Drain MWI before the final unref so the destructor's drain can't resurrect the
				 * peer via a concurrent mwi_event_cb. */
				sofia_peer_drain_mwi(pi);
				sofia_peer_ipport_unindex(pi);	/* B: unindex BEFORE unlink (the index pins a peer ref) */
				ao2_unlink(peers, pi);
				pruned++;
				ao2_ref(pi, -1);
			}
			ao2_iterator_destroy(&i);
			if (pruned > 0) {
				ast_cli(a->fd, "%d peers pruned.\n", pruned);
			} else {
				ast_cli(a->fd, "No peers found to prune.\n");
			}
		}
	} else {
		if (prunepeer) {
			peer = sofia_find_peer(name);
			if (peer) {
				if (!peer->is_realtime) {
					ast_cli(a->fd, "Peer '%s' is not a Realtime peer, cannot be pruned.\n", name);
				} else {
					/* Release dnsmgr + drop its +1 ref BEFORE ao2_unlink (see multi-prune branch).
					 * Atomic detach-under-lock guards a concurrent prune/reload double-release. */
					sofia_peer_release_dnsmgr(peer, 1);
					/* Drop the realtime-peer dialplan hint (registrar "realtime_peer") before unlink
					 * (see multi-prune branch). */
					{
						/* Snapshot under peer->lock (leaf) — racing the reload stringfield-pool free. */
						char l_sub[AST_MAX_CONTEXT], l_rex[256];	/* l_rex = multi-token regexten SPEC -> 256 (splitter), not one exten */
						ast_mutex_lock(&peer->lock);
						ast_copy_string(l_sub, peer->subscribecontext, sizeof(l_sub));
						ast_copy_string(l_rex, peer->regexten, sizeof(l_rex));
						ast_mutex_unlock(&peer->lock);
						if (!ast_strlen_zero(l_sub) && !ast_strlen_zero(l_rex)) {
							sofia_remove_peer_hints(l_rex, l_sub, "realtime_peer");
						}
					}
					/* Drain MWI subscriptions before the final unref (see the multi-prune branch). */
					sofia_peer_drain_mwi(peer);
					sofia_peer_ipport_unindex(peer);	/* B: unindex BEFORE unlink */
					ao2_unlink(peers, peer);
					ast_cli(a->fd, "Peer '%s' pruned.\n", name);
				}
				ao2_ref(peer, -1);
			} else {
				ast_cli(a->fd, "Peer '%s' not found.\n", name);
			}
		}
	}

	if (havepattern) {
		regfree(&regexbuf);
	}

	return CLI_SUCCESS;
}

char *sofia_cli_show_registry(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct ao2_iterator iter;
	struct sofia_peer *peer;
	int count = 0;
	time_t now;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show registry";
		e->usage =
			"Usage: sip show registry\n"
			"       List this server's outbound trunk registrations (register => lines)\n"
			"       and their current state.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 3) {
		return CLI_SHOWUSAGE;
	}

	now = time(NULL);
	ast_cli(a->fd, "%-42.42s  %-16.16s  %-8s  %s\n", "Host", "Username", "Refresh", "State");

	iter = ao2_iterator_init(peers, 0);
	while ((peer = ao2_iterator_next(&iter))) {
		int is_regline, port = 5060, registered = 0, attempts = 0;
		long refresh_secs = 0;
		char l_host[256] = "", l_user[256] = "";

		ast_mutex_lock(&peer->lock);
		is_regline = peer->is_register_line;
		if (is_regline) {
			port = peer->port ? peer->port : 5060;
			registered = peer->registered;
			attempts = peer->reg_attempts;
			refresh_secs = (registered && peer->reg_expiry > now)
				? (long)(peer->reg_expiry - now) : 0;
			ast_copy_string(l_host, S_OR(peer->host, ""), sizeof(l_host));
			ast_copy_string(l_user, S_OR(peer->defaultuser, ""), sizeof(l_user));
		}
		ast_mutex_unlock(&peer->lock);

		if (is_regline) {
			char hostport[300];
			char state[48];
			snprintf(hostport, sizeof(hostport), "%s:%d", l_host, port);
			if (registered) {
				ast_copy_string(state, "Registered", sizeof(state));
			} else if (attempts > 0) {
				snprintf(state, sizeof(state), "Unregistered (%d attempt%s)",
					attempts, attempts == 1 ? "" : "s");
			} else {
				ast_copy_string(state, "Unregistered", sizeof(state));
			}
			ast_cli(a->fd, "%-42.42s  %-16.16s  %-8ld  %s\n",
				hostport, l_user, refresh_secs, state);
			count++;
		}
		ao2_ref(peer, -1);
	}
	ao2_iterator_destroy(&iter);

	ast_cli(a->fd, "%d SIP registration%s.\n", count, count == 1 ? "" : "s");
	return CLI_SUCCESS;
}

/* `sip qualify peer <peer> [load]` — on-demand OPTIONS qualify (chan_sip parity). Async: the result
 * lands via the normal qualify path (sip show peers / PeerStatus AMI). [load] is a chan_sip-compat
 * no-op (sofia_find_peer already realtime-loads on a cache miss). */
char *sofia_cli_qualify_peer(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct sofia_peer *peer;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip qualify peer";
		e->usage =
			"Usage: sip qualify peer <peer> [load]\n"
			"       Send an on-demand OPTIONS qualify to a SIP peer. The result is asynchronous —\n"
			"       watch 'sip show peers' or the PeerStatus AMI event. 'load' is accepted for\n"
			"       chan_sip compatibility (realtime peers load automatically).\n";
		return NULL;
	case CLI_GENERATE:
		return (a->pos == 3) ? complete_sofia_peer(a->word, a->n, 0) : NULL;
	}

	if (a->argc != 4 && a->argc != 5) {
		return CLI_SHOWUSAGE;
	}
	peer = sofia_find_peer(a->argv[3]);
	if (!peer) {
		ast_cli(a->fd, "Peer unknown: '%s'.\n", a->argv[3]);
		return CLI_SUCCESS;
	}
	if (sofia_qualify_peer_async(peer) < 0) {	/* consumes the peer ref */
		ast_cli(a->fd, "Failed to dispatch qualify for '%s'.\n", a->argv[3]);
		return CLI_SUCCESS;
	}
	ast_cli(a->fd, "Qualify Peer '%s' triggered (asynchronous).\n", a->argv[3]);
	return CLI_SUCCESS;
}

char *sofia_cli_unregister(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct sofia_peer *peer;
	int was_registered = 0, had_contacts = 0, did_clear = 0;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip unregister";
		e->usage =
			"Usage: sip unregister <peer>\n"
			"       Force-expire a SIP peer's inbound registration (the peer must re-register).\n"
			"       Operates on in-RAM peers; a realtime peer's database binding is untouched.\n";
		return NULL;
	case CLI_GENERATE:
		return complete_sofia_peer(a->word, a->n, 0);
	}

	if (a->argc != 3) {
		return CLI_SHOWUSAGE;
	}

	peer = sofia_find_peer(a->argv[2]);
	if (!peer) {
		ast_cli(a->fd, "Peer unknown: '%s'. Not unregistered.\n", a->argv[2]);
		return CLI_SUCCESS;
	}

	ast_mutex_lock(&peer->lock);
	/* Reject an OUTBOUND register => trunk: it carries registered=1/reg_expiry for its OWN upstream
	 * registration, which clearing here would wrongly mark down. */
	if (peer->is_register_line) {
		ast_mutex_unlock(&peer->lock);
		ast_cli(a->fd, "Peer '%s' is an outbound registration (register =>); "
			"'sip unregister' applies to inbound peer registrations.\n", a->argv[2]);
		ao2_ref(peer, -1);
		return CLI_SUCCESS;
	}
	was_registered = peer->registered;
	/* Also clear stale contacts present while the flag is already 0 (defensive). */
	had_contacts = ao2_container_count(peer->contacts) > 0;
	did_clear = was_registered || had_contacts;
	if (did_clear) {
		/* Unconditional clear (NULL cb matches all) — NOT sofia_expire_contacts_cb, which only
		 * matches expired contacts and would leave the live bindings. */
		ao2_callback(peer->contacts, OBJ_UNLINK | OBJ_NODATA | OBJ_MULTIPLE, NULL, NULL);
		peer->registered = 0;
		memset(&peer->src_addr, 0, sizeof(peer->src_addr));
		ast_copy_string(peer->reg_transport, "udp", sizeof(peer->reg_transport));
		peer->expire = 0;
		peer->reg_expiry = 0;
	}
	ast_mutex_unlock(&peer->lock);

	if (did_clear) {
		sofia_peer_ipport_reindex(peer);	/* B: src_addr cleared above → re-key (drops the now-stale index entry) */
		/* Side-effects AFTER the unlock — same path natural expiry uses (regexten cleanup + AMI
		 * PeerStatus Unregistered + devstate/BLF). sip=NULL safe: the emit_unregister branch never derefs it. */
		struct sofia_register_update upd = { 0 };
		upd.emit_unregister = 1;
		upd.unregister_cause = "CLI";
		sofia_emit_register_side_effects(peer, NULL, &upd);
		ast_cli(a->fd, "Unregistered peer '%s'\n", a->argv[2]);
	} else {
		ast_cli(a->fd, "Peer '%s' not registered\n", a->argv[2]);
	}
	ao2_ref(peer, -1);
	return CLI_SUCCESS;
}

