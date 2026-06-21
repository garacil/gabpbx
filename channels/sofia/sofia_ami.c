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
		/* Fix B (2026-06-11): snapshot every peer-> field the astman_append
		 * reads into locals under peer->lock, then emit AFTER the unlock so the
		 * blocking AMI socket write never stalls the lock holder. */
		char l_name[256];	/* peer->name is an unbounded stringfield; size loss-free vs the AMI ObjectName baseline */
		int l_dynamic, l_forcerport, l_video, l_acl, l_realtime;

		ast_mutex_lock(&peer->lock);

		if (peer->is_register_line) {
			/* Outbound register-line peers surface via SIPshowregistry. */
			ast_mutex_unlock(&peer->lock);
			ao2_ref(peer, -1);
			continue;
		}

		/* IP/port — src_addr fallback for dynamic-registered peers (T46.3 SIPPEER pattern) */
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

		/* Status — peer_status enum + lastms (T46.3 SIPPEER pattern) */
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

		/* Fix B (2026-06-11): snapshot the remaining peer-> reads into locals,
		 * then drop the lock before the blocking astman_append. */
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

/* T47.2 (2026-04-27): AMI Action: SIPshowpeer — detailed Key:Value response for a
 * single peer. chan_sip parity (chan_sip.c:18454 manager_sip_show_peer + the
 * detail block at chan_sip.c:18761-18854). Re-uses T46.3 SIPPEER field set +
 * sofia_peer_first_contact helper. Fields chan_sofia does not model (Language,
 * MD5SecretExist, RemoteSecretExist, MOHSuggest, parking, etc.) emit as empty
 * or default values to preserve chan_sip-parity output format. */
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

	/* Fix B (2026-06-11): assemble the whole detail response into buf while
	 * holding peer->lock, then emit it with one blocking astman_append AFTER
	 * the unlock so a slow AMI consumer can't stall the lock holder. Allocate
	 * before locking and bail if it fails. */
	buf = ast_str_create(8192);
	if (!buf) {
		astman_send_error(s, m, "Out of memory");
		ao2_ref(peer, -1);
		return 0;
	}

	ast_mutex_lock(&peer->lock);

	/* IP/port — src_addr fallback for dynamic-registered peers (T46.3 pattern) */
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

	/* insecure flags → string (chan_sip-parity values) */
	if ((peer->insecure & SOFIA_INSECURE_PORT) && (peer->insecure & SOFIA_INSECURE_INVITE)) {
		ast_copy_string(insecure, "port,invite", sizeof(insecure));
	} else if (peer->insecure & SOFIA_INSECURE_PORT) {
		ast_copy_string(insecure, "port", sizeof(insecure));
	} else if (peer->insecure & SOFIA_INSECURE_INVITE) {
		ast_copy_string(insecure, "invite", sizeof(insecure));
	} else {
		ast_copy_string(insecure, "no", sizeof(insecure));
	}

	/* status — peer_status enum + lastms (T46.3 pattern) */
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

	/* reg_secs — seconds-until-expiry (clamp 0 if past) */
	{
		time_t now = time(NULL);
		reg_secs = peer->reg_expiry > now ? (long)(peer->reg_expiry - now) : 0;
	}

	/* First contact for UserAgent + Reg-Contact (NULL-safe) */
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
	/* post-T56 Task #2 D-3 SS1 (2026-04-28, GAP-4 fix + chan_sofia surpass —
	 * chan_sip baseline emits Transport but lacks WS/WSS; chan_sofia includes
	 * full set udp/tcp/tls/ws/wss). AMI Transport field per chan_sip-equivalent
	 * convention; mirrors sip show peer Transport ternary at chan_sofia.c
	 * :11062-11066. Operator NMS / monitoring systems can correlate per-peer
	 * transport for alerting (e.g., expected WSS browser-UA peer arrives via
	 * different transport → anomaly). */
	ast_str_append(&buf, 0, "Transport: %s\r\n",
		peer->transport == SOFIA_TRANSPORT_TCP ? "tcp" :
		peer->transport == SOFIA_TRANSPORT_TLS ? "tls" :
		peer->transport == SOFIA_TRANSPORT_WS  ? "ws"  :
		peer->transport == SOFIA_TRANSPORT_WSS ? "wss" : "udp");
	ast_str_append(&buf, 0, "Callgroup: %s\r\n",
		ast_print_group(group_buf, sizeof(group_buf), peer->callgroup));
	ast_str_append(&buf, 0, "Pickupgroup: %s\r\n",
		ast_print_group(group_buf, sizeof(group_buf), peer->pickupgroup));
	/* post-T56 MOH per-peer parity (2026-04-27): MOHInterpret + MOHSuggest
	 * AMI fields. chan_sip parity at chan_sip.c:18784 string format verbatim.
	 * In-flight Pattern 6 implicit-empty stub fix: existing MOHSuggest line
	 * emitted hardcoded empty string regardless of peer config (parsed-but-
	 * never-read-from-correct-source variant). Both fields now emit peer's
	 * actual value. */
	ast_str_append(&buf, 0, "MOHInterpret: %s\r\n",
		ast_strlen_zero(peer->mohinterpret) ? "" : peer->mohinterpret);
	ast_str_append(&buf, 0, "MOHSuggest: %s\r\n",
		ast_strlen_zero(peer->mohsuggest) ? "" : peer->mohsuggest);
	ast_str_append(&buf, 0, "VoiceMailbox: \r\n");
	/* post-T56 accountcode per-peer parity (2026-04-27): chan_sip-parity AMI field
	 * gated on !ast_strlen_zero per chan_sip.c:18772-18773. */
	if (!ast_strlen_zero(peer->accountcode)) {
		ast_str_append(&buf, 0, "Accountcode: %s\r\n", peer->accountcode);
	}
	/* post-T56 allowtransfer per-peer parity (2026-04-27): in-flight stub fix —
	 * pre-existing hardcoded "open" emitted regardless of peer config (Pattern 1
	 * stored-but-never-read variant; ADDENDUM #4 SS6 8-in-flight-catches-pattern).
	 * Now reflects peer->allowtransfer; chan_sip parity at chan_sip.c:18787 verbatim. */
	ast_str_append(&buf, 0, "TransferMode: %s\r\n", sofia_transfer_mode_str(peer->allowtransfer));
	/* post-T56 allowsubscribe per-peer parity (2026-04-27): chan_sip parity field
	 * (chan_sip flag SIP_PAGE2_ALLOWSUBSCRIBE → operator-visible yes/no). REQUEST-EVENT
	 * GATING dimension #6 sibling to TransferMode. */
	ast_str_append(&buf, 0, "AllowSubscribe: %s\r\n", peer->allowsubscribe ? "yes" : "no");
	/* post-T56 buggymwi per-peer parity (2026-04-27): chan_sip parity field
	 * (chan_sip flag SIP_PAGE2_BUGGY_MWI → operator-visible yes/no for verifying
	 * buggy-stack workaround applied per-peer). */
	ast_str_append(&buf, 0, "BuggyMWI: %s\r\n", peer->buggymwi ? "yes" : "no");
	/* post-T56 lockuseragent per-peer parity (2026-04-27): chan_sip parity Lockuseragent
	 * field (yes/no) + chan_sofia surpass LockedUserAgent display field (current
	 * locked UA string for compliance audit / UA-spoofing investigation). */
	ast_str_append(&buf, 0, "Lockuseragent: %s\r\n", peer->lockuseragent ? "yes" : "no");
	ast_str_append(&buf, 0, "LockedUserAgent: %s\r\n", peer->locked_user_agent);
	ast_str_append(&buf, 0, "LockUserAgentPrefixes: %s\r\n", S_OR(peer->lockuseragent_prefixes, ""));
	/* post-T56 language per-peer parity (2026-04-27): per-peer audio-locale field. */
	ast_str_append(&buf, 0, "Language: %s\r\n", peer->language);
	/* post-T56 defaultip per-peer parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:18820 verbatim Default-addr-IP + Default-addr-port fields. */
	ast_str_append(&buf, 0, "Default-addr-IP: %s\r\nDefault-addr-port: %d\r\n",
		ast_sockaddr_stringify_addr(&peer->defaddr),
		ast_sockaddr_port(&peer->defaddr));
	/* post-T56 maxcallbitrate per-peer parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:18792 verbatim "MaxCallBR: %d kbps" field. */
	ast_str_append(&buf, 0, "MaxCallBR: %d kbps\r\n", peer->maxcallbitrate);
	/* post-T56 amaflags per-peer parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:18774 verbatim "AMAflags: %s" via ast_cdr_flags2str. */
	ast_str_append(&buf, 0, "AMAflags: %s\r\n", ast_cdr_flags2str(peer->amaflags));
	/* post-T56 subscribemwi per-peer parity (2026-04-28): chan_sip parity field
	 * (sip.h:324 SIP_PAGE2_SUBSCRIBEMWIONLY → operator-visible yes/no). */
	ast_str_append(&buf, 0, "SubscribeMWI: %s\r\n", peer->subscribemwi ? "yes" : "no");
	/* post-T56 preferred_codec_only per-peer parity (2026-04-28): chan_sip parity field
	 * (sip.h:313 SIP_PAGE2_PREFERRED_CODEC → operator-visible yes/no). */
	ast_str_append(&buf, 0, "PreferredCodec: %s\r\n", peer->preferred_codec_only ? "yes" : "no");
	/* post-T56 ignoresdpversion per-peer parity (2026-04-28): chan_sip parity field
	 * (sip.h:325 SIP_PAGE2_IGNORESDPVERSION → operator-visible yes/no). PARSE-COMPAT-
	 * ONLY (chan_sofia processes every SDP unconditionally). */
	ast_str_append(&buf, 0, "IgnoreSDPVersion: %s\r\n", peer->ignoresdpversion ? "yes" : "no");
	/* post-T56 promiscredir per-peer parity (2026-04-28): chan_sip-parity AMI field
	 * "SIP-PromiscRedir" per chan_sip.c:18801 verbatim Y/N format. PARSE-COMPAT-ONLY. */
	ast_str_append(&buf, 0, "SIP-PromiscRedir: %s\r\n", peer->promiscredir ? "Y" : "N");
	/* post-T56 autoframing per-peer parity (2026-04-28): chan_sip-parity AMI field
	 * "Autoframing" yes/no format. PARSE-COMPAT-ONLY (sofia_parse_sdp ptime gate
	 * not wired today). */
	ast_str_append(&buf, 0, "Autoframing: %s\r\n", peer->autoframing ? "yes" : "no");
	/* faxdetect per-peer AMI field: reports the runtime mode used by DSP CNG
	 * detection and peer T.38 reINVITE detection. */
	ast_str_append(&buf, 0, "FaxDetect: %s\r\n",
		peer->faxdetect_mode == SOFIA_FAX_DETECT_NONE ? "no" :
		peer->faxdetect_mode == SOFIA_FAX_DETECT_BOTH ? "cng,t38" :
		peer->faxdetect_mode == SOFIA_FAX_DETECT_CNG ? "cng" : "t38");
	/* post-T56 timerb per-peer parity (2026-04-28): chan_sip-parity AMI field
	 * "Timer-B: %d ms" — operator-visible RFC 3261 Timer B value. */
	ast_str_append(&buf, 0, "Timer-B: %d\r\n", peer->timer_b);
	/* post-T56 timert1 per-peer parity (2026-04-28): chan_sip-parity AMI field
	 * "Timer-T1: %d ms" — operator-visible RFC 3261 §17.1.1.1 T1 retransmission
	 * interval value. Pattern 16 sofia-sip-native 7th-instance REWIRED. */
	ast_str_append(&buf, 0, "Timer-T1: %d\r\n", peer->timer_t1);
	/* post-T56 allowoverlap per-peer + [general] parity (2026-04-28, Option A
	 * FULL WIRE-IN + chan_sofia surpass — chan_sip AMI silent verified ABSENT
	 * via grep): operator-visible RFC 3261 §3 overlap-dial mode tri-state. */
	ast_str_append(&buf, 0, "OverlapDial: %s\r\n", sofia_allowoverlap_str(peer->allowoverlap_mode));
	/* post-T56 progressinband per-peer parity (2026-04-28): chan_sip parity tri-state
	 * field (sip.h:282-285 SIP_PROG_INBAND_NEVER/NO/YES → operator-visible never/no/yes).
	 * Option B partial wire-in (NEVER + YES exact; NO degrades to NEVER). */
	ast_str_append(&buf, 0, "ProgressInband: %s\r\n",
		peer->progressinband == SOFIA_PROG_INBAND_NEVER ? "never" :
		peer->progressinband == SOFIA_PROG_INBAND_YES ? "yes" : "no");
	/* post-T56 rtp-timeout bundle per-peer parity (2026-04-28): 3 fields chan_sip parity. */
	ast_str_append(&buf, 0, "RTPTimeout: %d\r\n", peer->rtptimeout);
	ast_str_append(&buf, 0, "RTPHoldTimeout: %d\r\n", peer->rtpholdtimeout);
	ast_str_append(&buf, 0, "RTPKeepalive: %d\r\n", peer->rtpkeepalive);
	/* post-T56 parkinglot per-peer parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:18849 verbatim "Parkinglot: %s" field. */
	ast_str_append(&buf, 0, "Parkinglot: %s\r\n", peer->parkinglot);
	ast_str_append(&buf, 0, "LastMsgsSent: 0\r\n");
	/* post-T56 maxforwards parity (2026-04-27): in-flight Pattern 1 stub-fix #13 —
	 * pre-existing hardcoded "Maxforwards: 0" emitted regardless of peer config
	 * (stored-but-never-read variant; ADDENDUM #4 SS6 8-in-flight-catches-pattern
	 * advances to 13/13 1-day peak). Now reflects peer->maxforwards; chan_sip
	 * parity at chan_sip.c:18789 verbatim. */
	ast_str_append(&buf, 0, "Maxforwards: %d\r\n", peer->maxforwards);
	/* post-T56 call-limit parity SS6 R8 (2026-04-27): chan_sip-parity field
	 * values for Call-limit + Busy-level + InUse/InRinging/OnHold. Fixed
	 * pre-existing stubs that emitted busy_on_active as Call-limit and
	 * hardcoded 0 as Busy-level. Always-emit (no zero-gate) per chan_sip
	 * L18790-18791 — operator AMI scripts get consistent field set. */
	ast_str_append(&buf, 0, "Call-limit: %d\r\n", peer->call_limit);
	ast_str_append(&buf, 0, "Busy-level: %d\r\n", peer->busy_level);
	ast_str_append(&buf, 0, "InUse: %d\r\n", peer->inUse);
	ast_str_append(&buf, 0, "InRinging: %d\r\n", peer->inRinging);
	ast_str_append(&buf, 0, "OnHold: %d\r\n", peer->onHold);
	ast_str_append(&buf, 0, "MaxCallBR: 384 kbps\r\n");
	ast_str_append(&buf, 0, "Dynamic: %s\r\n", !strcasecmp(peer->host, "dynamic") ? "Y" : "N");
	/* post-T56 cid bundle parity (2026-04-28): chan_sip-parity Callerid AMI field
	 * via ast_callerid_merge per chan_sip.c:18794 verbatim format; reflects
	 * cid_name + cid_num set via callerid/fullname/cid_number/cid_name keys.
	 * Falls back to legacy peer->callerid when both new fields empty. */
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
	/* post-T56 contactpermit/contactdeny per-peer parity (2026-04-27): chan_sip
	 * parity AMI field. */
	ast_str_append(&buf, 0, "ContactACL: %s\r\n", peer->contactha ? "Y" : "N");
	/* post-T56 directmediapermit/directmediadeny per-peer parity (2026-04-27): chan_sip
	 * parity AMI field at chan_sip.c:18676 "DirectMedACL" wording. */
	ast_str_append(&buf, 0, "DirectMedACL: %s\r\n", peer->directmediaha ? "Y" : "N");
	/* post-T56 dnsmgr per-peer parity (2026-04-27): chan_sip parity AMI field. */
	ast_str_append(&buf, 0, "DnsMgr: %s\r\n", peer->dnsmgr ? "Y" : "N");
	ast_str_append(&buf, 0, "SIP-CanReinvite: %s\r\n", peer->directmedia ? "Y" : "N");
	ast_str_append(&buf, 0, "SIP-DirectMedia: %s\r\n", peer->directmedia ? "Y" : "N");
	ast_str_append(&buf, 0, "SIP-PromiscRedir: N\r\n");
	/* post-T56 usereqphone parity (2026-04-27): in-flight Pattern 1 stub-fix —
	 * pre-existing hardcoded "N" emitted regardless of peer config (stored-but-
	 * never-read variant; ADDENDUM #4 SS6 8-in-flight-catches-pattern continues
	 * to 11th instance in 1 day's work). Now reflects peer->usereqphone; chan_sip
	 * parity at chan_sip.c:18802 verbatim. */
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
	/* post-T56 srtpcipher operator option (2026-04-27): SRTPCipher field for AMI SIPshowpeer. */
	ast_str_append(&buf, 0, "SRTPCipher: %s\r\n", S_OR(peer->srtpcipher, ""));
	/* post-T56 session timers (RFC 4028) (2026-04-27): 4 chan_sip-parity AMI fields. */
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
	/* post-T56 regexten display-gate parity (2026-04-27): chan_sip.c:18822 gates
	 * AMI RegExtension field on !ast_strlen_zero(sip_cfg.regcontext) — only
	 * emitted when the auto-extension mechanism is active. */
	if (!ast_strlen_zero(sofia_cfg.regcontext) && !ast_strlen_zero(peer->regexten)) {
		ast_str_append(&buf, 0, "RegExtension: %s\r\n", peer->regexten);
	}
	/* post-T56 callbackextension per-peer parity (2026-04-28, Option A FULL WIRE-IN
	 * + chan_sofia surpass over chan_sip AMI silent — chan_sip never exposes
	 * callbackextension in any AMI action): conditional emit only when set. */
	if (!ast_strlen_zero(peer->callbackextension)) {
		ast_str_append(&buf, 0, "CallbackExtension: %s\r\n", peer->callbackextension);
	}
	/* post-T56 setvar+header per-peer parity (2026-04-28, COMBINED ship): AMI
	 * ChanVariable iteration per chan_sip.c:18850-18854 verbatim format. Includes
	 * both setvar= and header= entries. */
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
		/* Codex#4: snapshot the mutable user_agent under the contact lock. */
		char ua[256] = "";
		if (contact) {
			ao2_lock(contact);
			ast_copy_string(ua, S_OR(contact->user_agent, ""), sizeof(ua));
			ao2_unlock(contact);
		}
		ast_str_append(&buf, 0, "SIP-Useragent: %s\r\n", ua);
	}
	ast_str_append(&buf, 0, "Reg-Contact: %s\r\n", contact ? S_OR(contact->contact_uri, "") : "");
	/* R6 #6 (3-way consensus): chan_sofia stores qualifyfreq in SECONDS but chan_sip's AMI
	 * emits it in ms (it stores freq*1000). Emit *1000 and KEEP the "ms" label so migrated
	 * NMS scripts read the same value as chan_sip (a relabel to "s" would be a silent AMI break). */
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

	/* Fix B (2026-06-11): single blocking AMI write AFTER the lock is dropped.
	 * Literal "%s" — peer data may contain '%'. */
	astman_append(s, "%s", ast_str_buffer(buf));
	ast_free(buf);

	ao2_ref(peer, -1);
	return 0;
}

/* T47.3 (2026-04-27): AMI Action: SIPqualifypeer — trigger immediate qualify probe
 * on a peer. chan_sip parity (chan_sip.c:18513 manager_sip_qualify_peer +
 * sip_poke_peer). chan_sofia variant DISPATCHES the qualify call to sofia_thread
 * via sofia_dispatch_to_root_thread because manager handlers run on a separate
 * thread + sofia_qualify_peer creates a nua_handle (would hit the T40 same-
 * thread-as-create assert if called directly from manager thread). */


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

/* T47.4 (2026-04-27): AMI Action: SIPshowregistry — list outbound register-lines
 * (peers chan_sofia is REGISTER-ing TO). chan_sip parity (chan_sip.c:17651
 * manager_show_registry). chan_sofia stores register-lines as PEERS with
 * peer->is_register_line==1 (unified storage vs chan_sip's separate regl
 * ASTOBJ container — see T47.1 SIPpeers for the inverse filter). State field
 * uses simplified Registered/Unregistered mapping (chan_sip's regstate2str
 * granular states No Auth/Failed/Timeout/Rejected aren't modeled here since
 * sofia-sip handles registration retries internally — documented divergence). */
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
		/* Codex#5: snapshot the registry fields UNDER peer->lock, release it, then
		 * astman_append — astman_append writes the AMI socket and blocks on a slow
		 * client, so holding peer->lock across it stalls REGISTER/reload. */
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

/* T47.5 (2026-04-27): AMI Action: SIPnotify — send a SIP NOTIFY to a peer.
 * chan_sip parity (chan_sip.c:13846 manager_sipnotify). chan_sofia variant
 * uses sofia_dispatch_to_root_thread (T47.3 helper) so the nua_handle +
 * nua_notify ops run on sofia_thread (per the same-thread-as-create contract).
 *
 * Variable: pairs from the AMI message: Event=<name> picks the SIP Event
 * header (default check-sync if missing), Content=<body> becomes the NOTIFY
 * payload, all others become extra SIP headers (assembled CRLF-separated as
 * a single SIPTAG_HEADER_STR). */

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

	/* R5 Codex#3/#4: bind the SIPnotify sentinel hmagic so sofia_event_callback can
	 * recognise this app-owned one-shot handle and destroy it on the final nua_r_notify
	 * (sofia-sip does NOT auto-reap it — each AMI SIPnotify would otherwise leak a
	 * nua_handle + su_home). Destroying it here, right after nua_notify, is UNSAFE — it
	 * would drop the queued NOTIFY before it reaches the wire — so the destroy is deferred
	 * to the transaction's final response. */
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
		/* Round5 transport-route: contact_uri is the transport-less stable key —
		 * route the NOTIFY over the contact's registered transport. */
		ao2_lock(contact);
		ast_copy_string(c_transport, contact->transport, sizeof(c_transport));
		ao2_unlock(contact);
		sofia_uri_append_transport(target_uri, sizeof(target_uri), c_transport);
	} else {
		/* Step A IPv6 parity SS3 (2026-04-28): bracket-wrap IPv6 host. The
		 * peer->host fallback may be unbracketed IPv6 from operator config. */
		char hbuf[80];
		/* reload-UAF fix: peer->defaultuser/name/host are unbounded
		 * stringfields the reload writer frees under peer->lock on grow.
		 * Snapshot them (and the port) into locals under peer->lock, then
		 * build the URI from the locals so the lock-free read can't race
		 * sofia_parse_peer_config. */
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
				/* Round5 Codex#4: only COUNT the header when BOTH strdups succeed —
				 * the callback formats "%s: %s" over name/value, so a NULL from a failed
				 * strdup would deref NULL. On partial failure free what we got and skip. */
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
