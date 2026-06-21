/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

/*! \file sofia_ami.c
 * \brief chan_sofia AMI (manager) actions, split from chan_sofia.c.
 */

#include "gabpbx.h"
#include "gabpbx/stringfields.h"
#include "gabpbx/astobj2.h"
#include "gabpbx/manager.h"
#include "gabpbx/cli.h"
#include "gabpbx/lock.h"
#include "gabpbx/utils.h"
#include "gabpbx/strings.h"
#include "gabpbx/logger.h"
#include "gabpbx/channel.h"
#include "gabpbx/callerid.h"
#include "gabpbx/causes.h"

#include <sofia-sip/nua.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/su_tag.h>
#include <sofia-sip/sip_tag.h>
#include <sofia-sip/nua_tag.h>

#include "include/chan_sofia_internal.h"
#include "include/sofia_ami.h"
/* AMI SIPpeers: one PeerEntry per peer (chan_sip parity). */
int manager_sofia_show_peers(struct mansession *s, const struct message *m)
{
	const char *id = astman_get_header(m, "ActionID");
	char idtext[256] = "";
	struct ao2_iterator i;
	struct sofia_peer *peer;
	int total = 0;

	if (!ast_strlen_zero(id)) {
		snprintf(idtext, sizeof(idtext), "ActionID: %s\r\n", id);
	}

	astman_send_listack(s, m, "Peer status list will follow", "start");

	i = ao2_iterator_init(peers, 0);
	while ((peer = ao2_iterator_next(&i))) {
		struct ast_sockaddr addr;
		char tmp_host[64], tmp_port[16], status[64];
		/* Snapshot every peer-> field under peer->lock into locals, then emit AFTER the unlock:
		 * the blocking AMI socket write must not stall the lock holder. */
		char l_name[256];	/* peer->name is an unbounded stringfield; size loss-free vs the AMI ObjectName baseline */
		int l_dynamic, l_forcerport, l_video, l_acl, l_realtime;

		ast_mutex_lock(&peer->lock);

		if (peer->is_register_line) {
			/* Outbound register-line peers surface via SIPshowregistry. */
			ast_mutex_unlock(&peer->lock);
			ao2_ref(peer, -1);
			continue;
		}

		/* IP/port - src_addr fallback for dynamic-registered peers. */
		if (!strcasecmp(peer->host, "dynamic") && peer->registered) {
			addr = peer->src_addr;
		} else {
			addr = peer->addr;
		}
		if (ast_sockaddr_isnull(&addr)) {
			ast_copy_string(tmp_host, "-none-", sizeof(tmp_host));
			ast_copy_string(tmp_port, "0", sizeof(tmp_port));
		} else {
			ast_copy_string(tmp_host, ast_sockaddr_stringify_addr(&addr), sizeof(tmp_host));
			snprintf(tmp_port, sizeof(tmp_port), "%u", ast_sockaddr_port(&addr));
		}

		/* Status from peer_status enum + lastms. */
		switch (peer->peer_status) {
		case PEER_REACHABLE:
			snprintf(status, sizeof(status), "OK (%dms)", peer->lastms);
			break;
		case PEER_LAGGED:
			snprintf(status, sizeof(status), "LAGGED (%dms)", peer->lastms);
			break;
		case PEER_UNREACHABLE:
			ast_copy_string(status, "UNREACHABLE", sizeof(status));
			break;
		default:
			ast_copy_string(status, "UNKNOWN", sizeof(status));
			break;
		}

		/* Snapshot the remaining reads, then drop the lock before the blocking astman_append. */
		ast_copy_string(l_name, peer->name, sizeof(l_name));
		l_dynamic = !strcasecmp(peer->host, "dynamic");
		l_forcerport = (peer->nat & SOFIA_NAT_FORCE_RPORT) ? 1 : 0;
		l_video = (peer->capability & AST_FORMAT_VIDEO_MASK) ? 1 : 0;
		l_acl = peer->ha ? 1 : 0;
		l_realtime = peer->is_realtime ? 1 : 0;

		ast_mutex_unlock(&peer->lock);
		ao2_ref(peer, -1);

		astman_append(s,
			"Event: PeerEntry\r\n"
			"%s"
			"Channeltype: SIP\r\n"
			"ObjectName: %s\r\n"
			"ChanObjectType: peer\r\n"
			"IPaddress: %s\r\n"
			"IPport: %s\r\n"
			"Dynamic: %s\r\n"
			"Forcerport: %s\r\n"
			"VideoSupport: %s\r\n"
			"TextSupport: no\r\n"
			"ACL: %s\r\n"
			"Status: %s\r\n"
			"RealtimeDevice: %s\r\n"
			"\r\n",
			idtext,
			l_name,
			tmp_host,
			tmp_port,
			l_dynamic ? "yes" : "no",
			l_forcerport ? "yes" : "no",
			l_video ? "yes" : "no",
			l_acl ? "yes" : "no",
			status,
			l_realtime ? "yes" : "no");

		total++;
	}
	ao2_iterator_destroy(&i);

	astman_append(s,
		"Event: PeerlistComplete\r\n"
		"EventList: Complete\r\n"
		"ListItems: %d\r\n"
		"%s"
		"\r\n",
		total, idtext);

	return 0;
}

/* AMI SIPshowpeer: detailed Key:Value response for one peer (chan_sip parity). Fields chan_sofia
 * does not model emit empty/default to preserve the chan_sip output format. */
int manager_sofia_show_peer(struct mansession *s, const struct message *m)
{
	const char *peername = astman_get_header(m, "Peer");
	const char *id = astman_get_header(m, "ActionID");
	char idText[256] = "";
	struct sofia_peer *peer;
	struct sofia_contact *contact;
	struct ast_sockaddr addr;
	char tmp_host[64], tmp_port[16];
	char status[64];
	char dtmfmode[16];
	char insecure[32];
	char codec_buf[256];
	char group_buf[256];
	long reg_secs;
	struct ast_str *buf;

	if (ast_strlen_zero(peername)) {
		astman_send_error(s, m, "Peer: <name> missing.");
		return 0;
	}
	peer = sofia_find_peer(peername);
	if (!peer) {
		astman_send_error(s, m, "Peer not found");
		return 0;
	}
	if (!ast_strlen_zero(id)) {
		snprintf(idText, sizeof(idText), "ActionID: %s\r\n", id);
	}

	/* Assemble the whole response into buf under peer->lock, then emit with one astman_append AFTER
	 * the unlock so a slow AMI consumer cannot stall the lock holder. Allocate before locking. */
	buf = ast_str_create(8192);
	if (!buf) {
		astman_send_error(s, m, "Out of memory");
		ao2_ref(peer, -1);
		return 0;
	}

	ast_mutex_lock(&peer->lock);

	/* IP/port - src_addr fallback for dynamic-registered peers. */
	if (!strcasecmp(peer->host, "dynamic") && peer->registered) {
		addr = peer->src_addr;
	} else {
		addr = peer->addr;
	}
	if (ast_sockaddr_isnull(&addr)) {
		ast_copy_string(tmp_host, "(null)", sizeof(tmp_host));
		ast_copy_string(tmp_port, "0", sizeof(tmp_port));
	} else {
		ast_copy_string(tmp_host, ast_sockaddr_stringify_addr(&addr), sizeof(tmp_host));
		snprintf(tmp_port, sizeof(tmp_port), "%u", ast_sockaddr_port(&addr));
	}

	/* dtmfmode → string */
	switch (peer->dtmfmode) {
	case SOFIA_DTMF_INFO:    ast_copy_string(dtmfmode, "info", sizeof(dtmfmode)); break;
	case SOFIA_DTMF_INBAND:  ast_copy_string(dtmfmode, "inband", sizeof(dtmfmode)); break;
	case SOFIA_DTMF_AUTO:    ast_copy_string(dtmfmode, "auto", sizeof(dtmfmode)); break;
	default:                 ast_copy_string(dtmfmode, "rfc2833", sizeof(dtmfmode)); break;
	}

	/* insecure flags to string (chan_sip-parity values). */
	if ((peer->insecure & SOFIA_INSECURE_PORT) && (peer->insecure & SOFIA_INSECURE_INVITE)) {
		ast_copy_string(insecure, "port,invite", sizeof(insecure));
	} else if (peer->insecure & SOFIA_INSECURE_PORT) {
		ast_copy_string(insecure, "port", sizeof(insecure));
	} else if (peer->insecure & SOFIA_INSECURE_INVITE) {
		ast_copy_string(insecure, "invite", sizeof(insecure));
	} else {
		ast_copy_string(insecure, "no", sizeof(insecure));
	}

	/* Status from peer_status enum + lastms. */
	switch (peer->peer_status) {
	case PEER_REACHABLE:
		snprintf(status, sizeof(status), "OK (%dms)", peer->lastms);
		break;
	case PEER_LAGGED:
		snprintf(status, sizeof(status), "LAGGED (%dms)", peer->lastms);
		break;
	case PEER_UNREACHABLE:
		ast_copy_string(status, "UNREACHABLE", sizeof(status));
		break;
	default:
		ast_copy_string(status, "UNKNOWN", sizeof(status));
		break;
	}

	/* reg_secs - seconds until expiry (clamp 0 if past). */
	{
		time_t now = time(NULL);
		reg_secs = peer->reg_expiry > now ? (long)(peer->reg_expiry - now) : 0;
	}

	/* First contact for UserAgent + Reg-Contact (NULL-safe). */
	contact = sofia_peer_first_contact(peer);

	ast_str_append(&buf, 0, "Response: Success\r\n%s", idText);
	ast_str_append(&buf, 0, "Channeltype: SIP\r\n");
	ast_str_append(&buf, 0, "ObjectName: %s\r\n", peer->name);
	ast_str_append(&buf, 0, "ChanObjectType: peer\r\n");
	ast_str_append(&buf, 0, "SecretExist: %s\r\n", ast_strlen_zero(peer->secret) ? "N" : "Y");
	ast_str_append(&buf, 0, "RemoteSecretExist: N\r\n");
	ast_str_append(&buf, 0, "MD5SecretExist: N\r\n");
	ast_str_append(&buf, 0, "Context: %s\r\n", peer->context);
	ast_str_append(&buf, 0, "Language: \r\n");
	ast_str_append(&buf, 0, "AMAflags: Unknown\r\n");
	ast_str_append(&buf, 0, "CID-CallingPres: Allowed, Not Screened\r\n");
	if (!ast_strlen_zero(peer->fromuser)) {
		ast_str_append(&buf, 0, "SIP-FromUser: %s\r\n", peer->fromuser);
	}
	if (!ast_strlen_zero(peer->fromdomain)) {
		ast_str_append(&buf, 0, "SIP-FromDomain: %s\r\n", peer->fromdomain);
	}
	/* Transport: chan_sofia emits the full set udp/tcp/tls/ws/wss (chan_sip lacks WS/WSS). */
	ast_str_append(&buf, 0, "Transport: %s\r\n",
		peer->transport == SOFIA_TRANSPORT_TCP ? "tcp" :
		peer->transport == SOFIA_TRANSPORT_TLS ? "tls" :
		peer->transport == SOFIA_TRANSPORT_WS  ? "ws"  :
		peer->transport == SOFIA_TRANSPORT_WSS ? "wss" : "udp");
	ast_str_append(&buf, 0, "Callgroup: %s\r\n",
		ast_print_group(group_buf, sizeof(group_buf), peer->callgroup));
	ast_str_append(&buf, 0, "Pickupgroup: %s\r\n",
		ast_print_group(group_buf, sizeof(group_buf), peer->pickupgroup));
	/* chan_sip parity. */
	ast_str_append(&buf, 0, "MOHInterpret: %s\r\n",
		ast_strlen_zero(peer->mohinterpret) ? "" : peer->mohinterpret);
	ast_str_append(&buf, 0, "MOHSuggest: %s\r\n",
		ast_strlen_zero(peer->mohsuggest) ? "" : peer->mohsuggest);
	ast_str_append(&buf, 0, "VoiceMailbox: \r\n");
	/* chan_sip parity. */
	if (!ast_strlen_zero(peer->accountcode)) {
		ast_str_append(&buf, 0, "Accountcode: %s\r\n", peer->accountcode);
	}
	/* chan_sip parity. */
	ast_str_append(&buf, 0, "TransferMode: %s\r\n", sofia_transfer_mode_str(peer->allowtransfer));
	/* chan_sip parity. */
	ast_str_append(&buf, 0, "AllowSubscribe: %s\r\n", peer->allowsubscribe ? "yes" : "no");
	/* chan_sip parity. */
	ast_str_append(&buf, 0, "BuggyMWI: %s\r\n", peer->buggymwi ? "yes" : "no");
	/* LockedUserAgent (the current locked UA string) is a chan_sofia addition for UA-spoofing audit. */
	ast_str_append(&buf, 0, "Lockuseragent: %s\r\n", peer->lockuseragent ? "yes" : "no");
	ast_str_append(&buf, 0, "LockedUserAgent: %s\r\n", peer->locked_user_agent);
	ast_str_append(&buf, 0, "LockUserAgentPrefixes: %s\r\n", S_OR(peer->lockuseragent_prefixes, ""));
	/* chan_sip parity. */
	ast_str_append(&buf, 0, "Language: %s\r\n", peer->language);
	/* chan_sip parity. */
	ast_str_append(&buf, 0, "Default-addr-IP: %s\r\nDefault-addr-port: %d\r\n",
		ast_sockaddr_stringify_addr(&peer->defaddr),
		ast_sockaddr_port(&peer->defaddr));
	/* chan_sip parity. */
	ast_str_append(&buf, 0, "MaxCallBR: %d kbps\r\n", peer->maxcallbitrate);
	/* chan_sip parity. */
	ast_str_append(&buf, 0, "AMAflags: %s\r\n", ast_cdr_flags2str(peer->amaflags));
	/* chan_sip parity. */
	ast_str_append(&buf, 0, "SubscribeMWI: %s\r\n", peer->subscribemwi ? "yes" : "no");
	/* chan_sip parity. */
	ast_str_append(&buf, 0, "PreferredCodec: %s\r\n", peer->preferred_codec_only ? "yes" : "no");
	/* PARSE-COMPAT-ONLY: chan_sofia processes every SDP unconditionally. */
	ast_str_append(&buf, 0, "IgnoreSDPVersion: %s\r\n", peer->ignoresdpversion ? "yes" : "no");
	/* chan_sip parity. */
	ast_str_append(&buf, 0, "SIP-PromiscRedir: %s\r\n", peer->promiscredir ? "Y" : "N");
	/* PARSE-COMPAT-ONLY: the sofia_parse_sdp ptime gate is not wired today. */
	ast_str_append(&buf, 0, "Autoframing: %s\r\n", peer->autoframing ? "yes" : "no");
	/* FaxDetect: runtime mode for DSP CNG detection + peer T.38 reINVITE detection. */
	ast_str_append(&buf, 0, "FaxDetect: %s\r\n",
		peer->faxdetect_mode == SOFIA_FAX_DETECT_NONE ? "no" :
		peer->faxdetect_mode == SOFIA_FAX_DETECT_BOTH ? "cng,t38" :
		peer->faxdetect_mode == SOFIA_FAX_DETECT_CNG ? "cng" : "t38");
	/* chan_sip parity. */
	ast_str_append(&buf, 0, "Timer-B: %d\r\n", peer->timer_b);
	/* chan_sip parity. */
	ast_str_append(&buf, 0, "Timer-T1: %d\r\n", peer->timer_t1);
	/* chan_sip parity. */
	ast_str_append(&buf, 0, "OverlapDial: %s\r\n", sofia_allowoverlap_str(peer->allowoverlap_mode));
	/* Tri-state, partial wire-in: NEVER + YES exact; NO degrades to NEVER. */
	ast_str_append(&buf, 0, "ProgressInband: %s\r\n",
		peer->progressinband == SOFIA_PROG_INBAND_NEVER ? "never" :
		peer->progressinband == SOFIA_PROG_INBAND_YES ? "yes" : "no");
	/* chan_sip parity. */
	ast_str_append(&buf, 0, "RTPTimeout: %d\r\n", peer->rtptimeout);
	ast_str_append(&buf, 0, "RTPHoldTimeout: %d\r\n", peer->rtpholdtimeout);
	ast_str_append(&buf, 0, "RTPKeepalive: %d\r\n", peer->rtpkeepalive);
	/* chan_sip parity. */
	ast_str_append(&buf, 0, "Parkinglot: %s\r\n", peer->parkinglot);
	ast_str_append(&buf, 0, "LastMsgsSent: 0\r\n");
	/* chan_sip parity. */
	ast_str_append(&buf, 0, "Maxforwards: %d\r\n", peer->maxforwards);
	/* Always-emit (no zero-gate) so AMI scripts get a consistent field set - chan_sip parity. */
	ast_str_append(&buf, 0, "Call-limit: %d\r\n", peer->call_limit);
	ast_str_append(&buf, 0, "Busy-level: %d\r\n", peer->busy_level);
	ast_str_append(&buf, 0, "InUse: %d\r\n", peer->inUse);
	ast_str_append(&buf, 0, "InRinging: %d\r\n", peer->inRinging);
	ast_str_append(&buf, 0, "OnHold: %d\r\n", peer->onHold);
	ast_str_append(&buf, 0, "MaxCallBR: 384 kbps\r\n");
	ast_str_append(&buf, 0, "Dynamic: %s\r\n", !strcasecmp(peer->host, "dynamic") ? "Y" : "N");
	/* Callerid via ast_callerid_merge; falls back to legacy peer->callerid when both fields empty. */
	if (!ast_strlen_zero(peer->cid_num) || !ast_strlen_zero(peer->cid_name)) {
		char merged[256];
		ast_callerid_merge(merged, sizeof(merged),
			S_OR(peer->cid_name, ""), S_OR(peer->cid_num, ""), "<unknown>");
		ast_str_append(&buf, 0, "Callerid: %s\r\n", merged);
	} else {
		ast_str_append(&buf, 0, "Callerid: %s\r\n", peer->callerid);
	}
	if (!ast_strlen_zero(peer->cid_tag)) {
		ast_str_append(&buf, 0, "CIDtag: %s\r\n", peer->cid_tag);
	}
	ast_str_append(&buf, 0, "RegExpire: %ld seconds\r\n", reg_secs);
	ast_str_append(&buf, 0, "SIP-AuthInsecure: %s\r\n", insecure);
	ast_str_append(&buf, 0, "SIP-Forcerport: %s\r\n", (peer->nat & SOFIA_NAT_FORCE_RPORT) ? "Y" : "N");
	ast_str_append(&buf, 0, "SIP-Comedia: %s\r\n", (peer->nat & SOFIA_NAT_COMEDIA) ? "Y" : "N");
	ast_str_append(&buf, 0, "ACL: %s\r\n", peer->ha ? "Y" : "N");
	/* chan_sip parity. */
	ast_str_append(&buf, 0, "ContactACL: %s\r\n", peer->contactha ? "Y" : "N");
	/* chan_sip parity. */
	ast_str_append(&buf, 0, "DirectMedACL: %s\r\n", peer->directmediaha ? "Y" : "N");
	/* chan_sip parity. */
	ast_str_append(&buf, 0, "DnsMgr: %s\r\n", peer->dnsmgr ? "Y" : "N");
	ast_str_append(&buf, 0, "SIP-CanReinvite: %s\r\n", peer->directmedia ? "Y" : "N");
	ast_str_append(&buf, 0, "SIP-DirectMedia: %s\r\n", peer->directmedia ? "Y" : "N");
	ast_str_append(&buf, 0, "SIP-PromiscRedir: N\r\n");
	/* chan_sip parity. */
	ast_str_append(&buf, 0, "SIP-UserPhone: %s\r\n", peer->usereqphone ? "Y" : "N");
	ast_str_append(&buf, 0, "SIP-VideoSupport: %s\r\n", (peer->capability & AST_FORMAT_VIDEO_MASK) ? "Y" : "N");
	ast_str_append(&buf, 0, "SIP-TextSupport: N\r\n");
	ast_str_append(&buf, 0, "SIP-T.38Support: N\r\n");
	ast_str_append(&buf, 0, "SIP-T.38EC: None\r\n");
	ast_str_append(&buf, 0, "SIP-T.38MaxDtgrm: 0\r\n");
	ast_str_append(&buf, 0, "SIP-Sess-Timers: Refuse\r\n");
	ast_str_append(&buf, 0, "SIP-Sess-Refresh: uas\r\n");
	ast_str_append(&buf, 0, "SIP-Sess-Expires: 1800\r\n");
	ast_str_append(&buf, 0, "SIP-Sess-Min: 90\r\n");
	ast_str_append(&buf, 0, "SIP-RTP-Engine: gabpbx\r\n");
	ast_str_append(&buf, 0, "SIP-Encryption: %s\r\n", peer->encryption ? "Y" : "N");
	/* chan_sip parity. */
	ast_str_append(&buf, 0, "SRTPCipher: %s\r\n", S_OR(peer->srtpcipher, ""));
	/* chan_sip parity. */
	{
		const char *st_mode_str =
			(peer->session_timers == SESSION_TIMERS_ORIGINATE) ? "originate" :
			(peer->session_timers == SESSION_TIMERS_REFUSE)    ? "refuse"    :
			(peer->session_timers == SESSION_TIMERS_ACCEPT)    ? "accept"    : "off";
		const char *st_refresher_str =
			(peer->session_refresher == SESSION_REFRESHER_UAC) ? "uac" :
			(peer->session_refresher == SESSION_REFRESHER_UAS) ? "uas" : "auto";
		ast_str_append(&buf, 0, "SessionTimers: %s\r\n", st_mode_str);
		ast_str_append(&buf, 0, "SessionExpires: %d\r\n", peer->session_expires);
		ast_str_append(&buf, 0, "SessionMinSE: %d\r\n", peer->session_minse);
		ast_str_append(&buf, 0, "SessionRefresher: %s\r\n", st_refresher_str);
	}
	ast_str_append(&buf, 0, "SIP-DTMFmode: %s\r\n", dtmfmode);
	ast_str_append(&buf, 0, "ToHost: %s\r\n", peer->host);
	ast_str_append(&buf, 0, "Address-IP: %s\r\nAddress-Port: %s\r\n", tmp_host, tmp_port);
	ast_str_append(&buf, 0, "Default-Username: %s\r\n", peer->defaultuser);
	/* Emitted only when the auto-extension mechanism (regcontext) is active - chan_sip parity. */
	if (!ast_strlen_zero(sofia_cfg.regcontext) && !ast_strlen_zero(peer->regexten)) {
		ast_str_append(&buf, 0, "RegExtension: %s\r\n", peer->regexten);
	}
	/* Emitted only when set; chan_sofia addition (chan_sip never exposes it in AMI). */
	if (!ast_strlen_zero(peer->callbackextension)) {
		ast_str_append(&buf, 0, "CallbackExtension: %s\r\n", peer->callbackextension);
	}
	/* ChanVariable iteration - both setvar= and header= entries (chan_sip parity). */
	if (peer->chanvars) {
		struct ast_variable *var;
		for (var = peer->chanvars; var; var = var->next) {
			ast_str_append(&buf, 0, "ChanVariable: %s=%s\r\n", var->name, var->value);
		}
	}
	ast_getformatname_multiple(codec_buf, sizeof(codec_buf) - 1, peer->capability);
	ast_str_append(&buf, 0, "Codecs: %s\r\n", codec_buf);
	/* CodecOrder — walk peer->prefs in priority order */
	{
		int x;
		format_t codec;
		ast_str_append(&buf, 0, "CodecOrder: ");
		for (x = 0; x < 64; x++) {
			codec = ast_codec_pref_index(&peer->prefs, x);
			if (!codec) {
				break;
			}
			ast_str_append(&buf, 0, "%s%s", x ? "," : "", ast_getformatname(codec));
		}
		ast_str_append(&buf, 0, "\r\n");
	}
	ast_str_append(&buf, 0, "Status: %s\r\n", status);
	{
		/* Snapshot the mutable user_agent under the contact lock. */
		char ua[256] = "";
		if (contact) {
			ao2_lock(contact);
			ast_copy_string(ua, S_OR(contact->user_agent, ""), sizeof(ua));
			ao2_unlock(contact);
		}
		ast_str_append(&buf, 0, "SIP-Useragent: %s\r\n", ua);
	}
	ast_str_append(&buf, 0, "Reg-Contact: %s\r\n", contact ? S_OR(contact->contact_uri, "") : "");
	/* qualifyfreq is stored in seconds; emit *1000 with the "ms" label for chan_sip AMI parity
	 * (a relabel to "s" would silently break migrated NMS scripts). */
	ast_str_append(&buf, 0, "QualifyFreq: %d ms\r\n", peer->qualifyfreq * 1000);
	ast_str_append(&buf, 0, "Parkinglot: \r\n");
	/* chan_sofia-only fields (T21/T22/T37) */
	ast_str_append(&buf, 0, "BusyOnActive: %s\r\n", peer->busy_on_active ? "Y" : "N");
	ast_str_append(&buf, 0, "MaxContacts: %d\r\n", peer->max_contacts);
	ast_str_append(&buf, 0, "QualifyTimeout: %d\r\n", peer->qualifytimeout);
	ast_str_append(&buf, 0, "LastMs: %d\r\n", peer->lastms);
	ast_str_append(&buf, 0, "RealtimeDevice: %s\r\n", peer->is_realtime ? "yes" : "no");
	ast_str_append(&buf, 0, "\r\n");

	if (contact) {
		ao2_ref(contact, -1);
	}
	ast_mutex_unlock(&peer->lock);

	/* Single AMI write AFTER the unlock. Literal "%s" - peer data may contain a percent sign. */
	astman_append(s, "%s", ast_str_buffer(buf));
	ast_free(buf);

	ao2_ref(peer, -1);
	return 0;
}

/* AMI SIPqualifypeer: trigger an immediate qualify probe. Dispatched to sofia_thread because
 * sofia_qualify_peer creates a nua_handle (same-thread-as-create contract) and we run off-thread. */


int manager_sofia_qualify_peer(struct mansession *s, const struct message *m)
{
	const char *peername = astman_get_header(m, "Peer");
	struct sofia_peer *peer;
	struct sipqualifypeer_data *dispatch;

	if (ast_strlen_zero(peername)) {
		astman_send_error(s, m, "Peer: <name> missing.");
		return 0;
	}
	peer = sofia_find_peer(peername);
	if (!peer) {
		astman_send_error(s, m, "Peer not found");
		return 0;
	}
	dispatch = ast_calloc(1, sizeof(*dispatch));
	if (!dispatch) {
		ao2_ref(peer, -1);
		astman_send_error(s, m, "Memory allocation failed");
		return 0;
	}
	dispatch->peer = peer;	/* TRANSFER the +1 ref to the callback */
	if (sofia_dispatch_to_root_thread(sipqualifypeer_callback, dispatch) < 0) {
		ao2_ref(peer, -1);
		ast_free(dispatch);
		astman_send_error(s, m, "Failed to dispatch qualify");
		return 0;
	}
	astman_send_ack(s, m, "Qualify Peer triggered");
	return 0;
}

/* AMI SIPshowregistry: list outbound register-lines (stored as peers with is_register_line==1).
 * State is a simplified Registered/Unregistered - sofia-sip handles retries internally, so the
 * granular chan_sip states are not modeled (documented divergence). */
int manager_sofia_show_registry(struct mansession *s, const struct message *m)
{
	const char *id = astman_get_header(m, "ActionID");
	char idText[256] = "";
	struct ao2_iterator iter;
	struct sofia_peer *peer;
	int count = 0;
	time_t now = time(NULL);

	if (!ast_strlen_zero(id)) {
		snprintf(idText, sizeof(idText), "ActionID: %s\r\n", id);
	}

	astman_send_listack(s, m, "Registrations will follow", "start");

	iter = ao2_iterator_init(peers, 0);
	while ((peer = ao2_iterator_next(&iter))) {
		/* Snapshot the registry fields UNDER peer->lock, release, then astman_append: it
		 * blocks on a slow AMI client, and holding peer->lock across it would stall REGISTER/reload. */
		int is_regline, port = 5060, registered = 0;
		long refresh_secs = 0, reg_time = 0;
		char l_host[256] = "", l_user[256] = "", l_domain[256] = "";
		ast_mutex_lock(&peer->lock);
		is_regline = peer->is_register_line;
		if (is_regline) {
			refresh_secs = peer->reg_expiry > now ? (long)(peer->reg_expiry - now) : 0;
			port = peer->port ? peer->port : 5060;
			registered = peer->registered;
			reg_time = (long)peer->reg_expiry;
			ast_copy_string(l_host, S_OR(peer->host, ""), sizeof(l_host));
			ast_copy_string(l_user, S_OR(peer->defaultuser, ""), sizeof(l_user));
			ast_copy_string(l_domain, S_OR(peer->fromdomain, ""), sizeof(l_domain));
		}
		ast_mutex_unlock(&peer->lock);
		if (is_regline) {
			astman_append(s,
				"Event: RegistryEntry\r\n"
				"%s"
				"Host: %s\r\n"
				"Port: %d\r\n"
				"Username: %s\r\n"
				"Domain: %s\r\n"
				"DomainPort: %d\r\n"
				"Refresh: %ld\r\n"
				"State: %s\r\n"
				"RegistrationTime: %ld\r\n"
				"\r\n",
				idText, l_host, port, l_user, l_domain, port,
				refresh_secs, registered ? "Registered" : "Unregistered", reg_time);
			count++;
		}
		ao2_ref(peer, -1);
	}
	ao2_iterator_destroy(&iter);

	astman_append(s,
		"Event: RegistrationsComplete\r\n"
		"EventList: Complete\r\n"
		"%s"
		"ListItems: %d\r\n"
		"\r\n",
		idText, count);

	return 0;
}

/* AMI SIPnotify: send a SIP NOTIFY to a peer. The nua ops run on sofia_thread (same-thread-as-create
 * contract). Variable: pairs - Event=<name> (default check-sync), Content=<body> the payload, all
 * others become extra SIP headers (CRLF-joined into one SIPTAG_HEADER_STR). */

struct sipnotify_header {
	char *name;
	char *value;
};

struct sipnotify_data {
	struct sofia_peer *peer;	/* +1 ref TRANSFERRED to callback */
	struct sofia_contact *contact;	/* +1 ref TRANSFERRED; may be NULL for never-registered peers */
	char *target_uri;		/* heap; freed in sipnotify_data_free */
	char *event;			/* heap */
	char *content;			/* heap (may be empty string) */
	struct sipnotify_header *headers;
	int header_count;
};

/* Safe-on-any-thread: drops refs + frees heap. NO nua ops. Used by both the
 * sofia_thread callback and the manager-thread dispatch-failure path. */
static void sipnotify_data_free(struct sipnotify_data *d)
{
	int i;
	if (!d) {
		return;
	}
	if (d->peer) {
		ao2_ref(d->peer, -1);
	}
	if (d->contact) {
		ao2_ref(d->contact, -1);
	}
	ast_free(d->target_uri);
	ast_free(d->event);
	ast_free(d->content);
	for (i = 0; i < d->header_count; i++) {
		ast_free(d->headers[i].name);
		ast_free(d->headers[i].value);
	}
	ast_free(d->headers);
	ast_free(d);
}

/* Runs on sofia_thread via sofia_dispatch_to_root_thread. Builds the
 * extra-headers buffer, creates an out-of-dialog nua_handle to the target,
 * dispatches the NOTIFY, then frees all dispatch resources. */
static void sipnotify_callback(void *data)
{
	struct sipnotify_data *d = data;
	nua_handle_t *nh;
	struct ast_str *header_buf = NULL;
	int i;

	if (!d) {
		return;
	}
	if (!sofia_nua || ast_strlen_zero(d->target_uri)) {
		sipnotify_data_free(d);
		return;
	}

	/* Assemble extra headers as CRLF-separated single string for SIPTAG_HEADER_STR. */
	if (d->header_count > 0) {
		header_buf = ast_str_create(256);
		if (header_buf) {
			for (i = 0; i < d->header_count; i++) {
				ast_str_append(&header_buf, 0, "%s: %s\r\n",
					d->headers[i].name, d->headers[i].value);
			}
		}
	}

	/* Bind the SIPnotify sentinel hmagic so sofia_event_callback can destroy this app-owned one-shot
	 * handle on the final nua_r_notify (sofia-sip does NOT auto-reap it). Destroying it here, right
	 * after nua_notify, would drop the queued NOTIFY before it hits the wire - so the destroy is
	 * deferred to the transaction final response. */
	nh = nua_handle(sofia_nua, SOFIA_SIPNOTIFY_HMAGIC, NUTAG_URL(d->target_uri), TAG_END());
	if (nh) {
		nua_notify(nh,
			SIPTAG_EVENT_STR(d->event),
			TAG_IF(header_buf, SIPTAG_HEADER_STR(header_buf ? ast_str_buffer(header_buf) : "")),
			TAG_IF(!ast_strlen_zero(d->content), SIPTAG_PAYLOAD_STR(d->content)),
			TAG_END());
	} else {
		ast_log(LOG_WARNING, "Sofia SIPnotify: nua_handle creation failed for target %s\n",
			d->target_uri);
	}

	if (header_buf) {
		ast_free(header_buf);
	}
	sipnotify_data_free(d);
}
/* AMI SIPnotify entry: resolve the target URI, build the dispatch, and hand it to sofia_thread. */
int manager_sofia_notify(struct mansession *s, const struct message *m)
{
	const char *channelname = astman_get_header(m, "Channel");
	const char *peername;
	struct sofia_peer *peer;
	struct sofia_contact *contact;
	struct sipnotify_data *dispatch;
	struct ast_variable *vars, *v;
	char target_uri[512];

	if (ast_strlen_zero(channelname)) {
		astman_send_error(s, m, "Channel: missing");
		return 0;
	}
	/* Strip leading "SIP/" if present (chan_sip-compat channel name format). */
	peername = channelname;
	if (!strncasecmp(peername, "SIP/", 4)) {
		peername += 4;
	}

	peer = sofia_find_peer(peername);
	if (!peer) {
		astman_send_error(s, m, "Peer not found");
		return 0;
	}

	/* Target URI: registered contact preferred; constructed fallback for never-registered. */
	contact = sofia_peer_first_contact(peer);
	if (contact && !ast_strlen_zero(contact->contact_uri)) {
		char c_transport[8];
		ast_copy_string(target_uri, contact->contact_uri, sizeof(target_uri));
		/* contact_uri is the transport-less stable key - route over the registered transport. */
		ao2_lock(contact);
		ast_copy_string(c_transport, contact->transport, sizeof(c_transport));
		ao2_unlock(contact);
		sofia_uri_append_transport(target_uri, sizeof(target_uri), c_transport);
	} else {
		/* Fallback URI; sofia_uri_format_host bracket-wraps a bare IPv6 host. */
		char hbuf[80];
		/* reload-UAF fix: defaultuser/name/host are unbounded stringfields the reload writer frees
		 * under peer->lock on grow - snapshot them (and port) under the lock, then build from locals. */
		char l_defaultuser[256], l_name[256], l_host[256];
		int l_port;

		ast_mutex_lock(&peer->lock);
		ast_copy_string(l_defaultuser, peer->defaultuser, sizeof(l_defaultuser));
		ast_copy_string(l_name, peer->name, sizeof(l_name));
		ast_copy_string(l_host, peer->host, sizeof(l_host));
		l_port = peer->port;
		ast_mutex_unlock(&peer->lock);

		snprintf(target_uri, sizeof(target_uri), "sip:%s@%s:%d",
			!ast_strlen_zero(l_defaultuser) ? l_defaultuser : l_name,
			sofia_uri_format_host(
				!ast_strlen_zero(l_host) ? l_host : "unknown",
				hbuf, sizeof(hbuf)),
			l_port ? l_port : 5060);
	}

	dispatch = ast_calloc(1, sizeof(*dispatch));
	if (!dispatch) {
		if (contact) {
			ao2_ref(contact, -1);
		}
		ao2_ref(peer, -1);
		astman_send_error(s, m, "Memory allocation failed");
		return 0;
	}
	dispatch->peer = peer;		/* TRANSFER +1 ref */
	dispatch->contact = contact;	/* TRANSFER +1 ref (may be NULL) */
	dispatch->target_uri = ast_strdup(target_uri);

	/* Walk Variable: pairs — Event/Content special-cased, others become extra headers. */
	vars = astman_get_variables(m);
	for (v = vars; v; v = v->next) {
		if (!strcasecmp(v->name, "Event")) {
			ast_free(dispatch->event);
			dispatch->event = ast_strdup(v->value);
		} else if (!strcasecmp(v->name, "Content")) {
			ast_free(dispatch->content);
			dispatch->content = ast_strdup(v->value);
		} else {
			struct sipnotify_header *resized;
			resized = ast_realloc(dispatch->headers,
				(dispatch->header_count + 1) * sizeof(*dispatch->headers));
			if (resized) {
				char *hn = ast_strdup(v->name);
				char *hv = ast_strdup(v->value);
				dispatch->headers = resized;
				/* Only COUNT the header when BOTH strdups succeed - the callback formats
				 * "%s: %s" over name/value, so a NULL would deref. On partial failure, free + skip. */
				if (hn && hv) {
					dispatch->headers[dispatch->header_count].name = hn;
					dispatch->headers[dispatch->header_count].value = hv;
					dispatch->header_count++;
				} else {
					ast_free(hn);
					ast_free(hv);
				}
			}
		}
	}
	ast_variables_destroy(vars);

	/* Defaults — operator-friendly check-sync if no Event provided. */
	if (!dispatch->event) {
		dispatch->event = ast_strdup("check-sync");
	}
	if (!dispatch->content) {
		dispatch->content = ast_strdup("");
	}

	if (sofia_dispatch_to_root_thread(sipnotify_callback, dispatch) < 0) {
		/* Dispatch failure: clean up inline (safe — sipnotify_data_free does no nua ops). */
		sipnotify_data_free(dispatch);
		astman_send_error(s, m, "Failed to dispatch notify");
		return 0;
	}

	astman_send_ack(s, m, "Notify Sent");
	return 0;
}
