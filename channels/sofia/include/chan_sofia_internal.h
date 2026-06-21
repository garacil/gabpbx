/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * GABPBX was first created in 2008 by
 * Germán Luis Aracil Boned <garacilb@gmail.com>.
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

/*! \file
 * \brief chan_sofia shared internal definitions.
 *
 * Internal header for the chan_sofia driver and the modules split out under
 * channels/sofia/. Holds types/globals/prototypes shared across those translation
 * units. NOT a public API — private to the chan_sofia build.
 */

#ifndef CHAN_SOFIA_INTERNAL_H
#define CHAN_SOFIA_INTERNAL_H

#include "gabpbx/channel.h"	/* AST_MAX_CONTEXT / AST_MAX_EXTENSION */
#include "gabpbx/acl.h"		/* struct ast_ha */
#include "gabpbx/frame.h"	/* struct ast_codec_pref */
#include "gabpbx/netsock2.h"	/* struct ast_sockaddr */

#include "gabpbx/stringfields.h"	/* AST_STRING_FIELD / AST_DECLARE_STRING_FIELDS */
#include "gabpbx/linkedlists.h"	/* AST_LIST_HEAD_NOLOCK */
#include "gabpbx/lock.h"		/* ast_mutex_t */
#include "gabpbx/dnsmgr.h"	/* struct ast_dnsmgr_entry */
#include "gabpbx/config.h"	/* struct ast_variable */

#include <sofia-sip/sip.h>	/* sip_t */
#include <sofia-sip/su.h>	/* su_root_t */
#include <sofia-sip/nua.h>	/* nua_handle_t, nua_t */

/* Cross-module helpers defined in chan_sofia.c, used by the split-out modules. */
void sofia_get_source_addr(sip_t const *sip, struct ast_sockaddr *addr);
int sofia_dispatch_to_root_thread(void (*callback)(void *), void *data);
int sofia_format_auth_creds(msg_auth_t const *challenge, const char *user, const char *secret, char *buf, size_t len);
void sofia_split_hostport_from_uri(const char *hostport, char *host, size_t hostlen, int *port);
void sofia_presence_state_map(int state, const char **statestring, const char **pidfstate, const char **pidfnote, int *local_state);

/* Globals defined in chan_sofia.c, shared with the split modules. */
extern struct ao2_container *peers;
extern nua_t *sofia_nua;
extern su_root_t *sofia_root;
extern int sofia_debug;

/* ===== Peer/config model constants, enums, display helpers (shared with split modules) ===== */

#define SOFIA_PROG_INBAND_NEVER 0
#define SOFIA_PROG_INBAND_NO    1
#define SOFIA_PROG_INBAND_YES   2
#define SOFIA_FAX_DETECT_NONE   0
#define SOFIA_FAX_DETECT_CNG    1
#define SOFIA_FAX_DETECT_T38    2
#define SOFIA_FAX_DETECT_BOTH   3
#define SOFIA_T38_DISABLED          0
#define SOFIA_T38_LOCAL_REINVITE    1
#define SOFIA_T38_PEER_REINVITE     2
#define SOFIA_T38_ENABLED           3
#define SOFIA_T38_EC_NONE           0
#define SOFIA_T38_EC_FEC            1
#define SOFIA_T38_EC_REDUNDANCY     2
#define SOFIA_OVERLAP_NO        0
#define SOFIA_OVERLAP_YES       1
#define SOFIA_OVERLAP_DTMF      2
#define SOFIA_TYPE_PEER    (1 << 0)
#define SOFIA_TYPE_USER    (1 << 1)
#define SOFIA_TYPE_FRIEND  (SOFIA_TYPE_PEER | SOFIA_TYPE_USER)
#define SOFIA_DTMF_RFC2833 0
#define SOFIA_DTMF_INBAND  1
#define SOFIA_DTMF_INFO    2
#define SOFIA_DTMF_AUTO    3
#define SOFIA_INSECURE_PORT    (1 << 0)
#define SOFIA_INSECURE_INVITE  (1 << 1)
#define SOFIA_TRANSPORT_UDP 1
#define SOFIA_TRANSPORT_TCP 2
#define SOFIA_TRANSPORT_TLS 4
#define SOFIA_TRANSPORT_WS  8
#define SOFIA_TRANSPORT_WSS 16
#define SOFIA_NAT_FORCE_RPORT (1 << 0)
#define SOFIA_NAT_COMEDIA     (1 << 1)
#define SOFIA_AUTH_ALG_BOTH   0   /* offer MD5 + SHA-256 (default) */
#define SOFIA_AUTH_ALG_MD5    1   /* offer MD5 only */
#define SOFIA_AUTH_ALG_SHA256 2   /* offer SHA-256 only */

enum sofia_session_timer_mode {
	SESSION_TIMERS_OFF       = 0, /* unset / inherit from [general] */
	SESSION_TIMERS_ACCEPT    = 1, /* honor inbound peer Session-Expires; no initiate */
	SESSION_TIMERS_ORIGINATE = 2, /* originate outbound Session-Expires + honor inbound */
	SESSION_TIMERS_REFUSE    = 3, /* Round3 T2 (my#3): disables OUR origination only —
	                               * NUTAG_SESSION_TIMER(0) tells sofia-sip not to run a
	                               * refresher, it does NOT 422-refuse a peer-offered
	                               * Session-Expires (sofia-sip still accepts inbound
	                               * timers). Effectively equivalent-to-ACCEPT inbound. */
};

enum sofia_session_refresher {
	SESSION_REFRESHER_AUTO = 0, /* sofia-sip nua_any_refresher; negotiation decides */
	SESSION_REFRESHER_UAC  = 1, /* we refresh; chan_sip stimer.st_ref UAC parity */
	SESSION_REFRESHER_UAS  = 2, /* peer refreshes; chan_sip stimer.st_ref UAS parity */
};

enum sofia_transfer_mode {
	TRANSFER_OPENFORALL = 0, /* allow all SIP REFER transfers; chan_sip parity */
	TRANSFER_CLOSED     = 1, /* reject all SIP REFER with 603 Declined (policy) */
};

static inline const char *sofia_transfer_mode_str(int mode)
{
	return (mode == TRANSFER_CLOSED) ? "closed" : "open";
}

static inline const char *sofia_allowoverlap_str(int mode)
{
	switch (mode) {
	case SOFIA_OVERLAP_YES:  return "Yes";
	case SOFIA_OVERLAP_DTMF: return "DTMF";
	default:                 return "No";
	}
}

/* Per-registration contact (one peer can hold several). */
struct sofia_contact {
	char contact_uri[256];
	char host[64];
	int port;
	char transport[8];
	char user_agent[64];
	time_t expires;
	struct ast_sockaddr src_addr;
	int active_calls;          /* count of active calls on this contact */
};

extern char sofia_sipnotify_sentinel;

struct sofia_peer *sofia_find_peer(const char *name);
struct sofia_contact *sofia_peer_first_contact(struct sofia_peer *peer);
const char *sofia_uri_format_host(const char *host, char *out_buf, size_t out_len);
void sofia_uri_append_transport(char *url, size_t len, const char *transport);
void sofia_qualify_peer(struct sofia_peer *peer);
#define SOFIA_SIPNOTIFY_HMAGIC ((nua_hmagic_t *)&sofia_sipnotify_sentinel)

struct sipqualifypeer_data {
	struct sofia_peer *peer;	/* +1 ref TRANSFERRED to callback (caller doesn't drop) */
	int clear_pending;		/* Round5 #1: 1 = timer dispatch owns peer->qualify_pending (callback clears it); 0 = AMI manual qualify (leaves the timer gate alone) */
};
void sipqualifypeer_callback(void *data);

/* Per-peer reachability state (qualify). */
enum sofia_peer_status {
	PEER_UNREACHABLE = -1,
	PEER_UNKNOWN     = 0,
	PEER_REACHABLE   = 1,
	PEER_LAGGED      = 2,
};

/* Per-peer MWI mailbox list head. struct sofia_mailbox itself stays in chan_sofia.c;
 * the head only needs the node forward-declared (it stores pointers). */
struct sofia_mailbox;
AST_LIST_HEAD_NOLOCK(sofia_mailbox_list, sofia_mailbox);

/* The peer/trunk object — the central chan_sofia data structure, shared with split modules. */
struct sofia_peer {
	AST_DECLARE_STRING_FIELDS(
		AST_STRING_FIELD(name);
		AST_STRING_FIELD(secret);
		AST_STRING_FIELD(md5secret);    /* post-T56 Task #3 INVITE digest auth SS4 (2026-04-28, SW11 audit-discovered chan_sip parity gap fix): pre-hashed digest secret = MD5(user:realm:secret) stored as 32-hex-char string. chan_sip parity at chan_sip.c:15415-16 verbatim — when set, used directly as a1_hash bypassing cleartext-secret path. Security improvement over peer->secret cleartext: server config doesn't store cleartext password; compromised config file leaks only realm-bound MD5 hash (not password). Operator best-practice for hardened deployments. md5secret takes PRECEDENCE over peer->secret when both set (chan_sip parity per L15415); LOG_WARNING fires on dual-set ambiguity. SS4 ships sofia_compute_a1_hash #38 md5secret branch + parser branches in sofia_parse_peer_config + sofia_apply_peer_variables realtime. */
		AST_STRING_FIELD(context);
		AST_STRING_FIELD(host);
		AST_STRING_FIELD(defaultuser);
		AST_STRING_FIELD(fromuser);
		AST_STRING_FIELD(fromdomain);
		AST_STRING_FIELD(regexten);
		AST_STRING_FIELD(callbackextension);	/* post-T56 callbackextension per-peer parity (2026-04-28, Option A FULL WIRE-IN via Pattern 16 sofia-sip-native 12th-instance NUTAG_M_USERNAME at 3 nua_register call sites): when chan_sofia registers AS A CLIENT to upstream provider, this user-portion of the Contact URI tells upstream which extension to call back into our local dialplan. chan_sip parity at chan_sip.c:28869-28870 verbatim per-peer parser via DIRECT build_peer (containing function chan_sip.c:28565); chan_sip uses local-var `char callback[256]` at L28578 then auto-builds reg_string + sip_register at L29240-29246 + transmit_register sets p->exten = r->callback at L14267-14269 (chan_sip indirect Contact-URI-user-derivation-via-pvt-state state-machine). chan_sofia uses sofia-sip native NUTAG_M_USERNAME tag (per nua_tag.c:1955+L1983 verbatim "Username for Contact URI") via TAG_IF gate at 3 nua_register call sites — chan_sofia helper-architecture-advantage NEW DIMENSION sofia-sip-native-tag-vs-state-machine (1-tag wire-in vs chan_sip indirect state-machine). chan_sofia surpass over chan_sip CLI/AMI silent (chan_sip stores in local-var + discards; never displayed). Empty-default = chan_sip drop-in baseline (no callback registered). */
		AST_STRING_FIELD(subscribecontext);	/* post-T56 subscribecontext per-peer parity (2026-04-27): SUBSCRIBE-method dispatch context override; chan_sip parity sip_peer.subscribecontext; inherits sofia_cfg.default_subscribecontext at sofia_peer_alloc when empty. KNOWN LIMITATION: pivot-site override deferred until presence/dialog event-package handler lands (chan_sofia today: MWI uses peer->mailboxes; unknown events auto-202; no peer->context dialplan dispatch yet). */
		AST_STRING_FIELD(accountcode);	/* post-T56 accountcode per-peer parity (2026-04-27): CDR billing-tag propagated to channel->accountcode at sofia_new via dialog cache. chan_sip parity (chan_sip.c:28884-28885 + L17127). Inherited by sofia_pvt at sofia_request_call (outbound) + sofia_process_invite (inbound). Unbounded AST_STRING_FIELD on peer; truncated to AST_MAX_ACCOUNT_CODE=20 at CDR-write time (cdr.h:73 verbatim chan_sip parity). [general] default_accountcode ABSENT in chan_sip — per-peer-only design. */
		AST_STRING_FIELD(disallowed_methods);	/* post-T56 disallowed_methods per-peer parity (2026-04-27): comma-separated SIP method names blocked from outbound Allow header; chan_sip parity (chan_sip.c:29002-29004). Pattern 12 honest-disclosure 9th-instance: PARSE-COMPAT-ONLY string-storage shortcut; dynamic NUTAG_ALLOW generation DEFERRED per Pattern 15. Inherits sofia_cfg.disallowed_methods at sofia_peer_alloc when empty. */
		AST_STRING_FIELD(callerid);
		AST_STRING_FIELD(cid_name);   /* post-T56 cid bundle parity (2026-04-28): per-peer CID name; chan_sip parity sip_peer.cid_name. Set via fullname / cid_name (chan_sofia surpass alias) / callerid combined-form / trunkname (clears). Used at sofia_resolve_identity as base/default fallback when channel connected.id.name empty (chan_sip-verbatim L5957 dialog-inheritance Option 6-B). */
		AST_STRING_FIELD(cid_num);    /* post-T56 cid bundle parity (2026-04-28): per-peer CID number; chan_sip parity sip_peer.cid_num at chan_sip.c:28752-28753 + L5957 dialog-inheritance. Set via cid_number / callerid combined-form. Used at sofia_resolve_identity as base/default fallback when channel connected.id.number empty (channel CID via dialplan CALLERID() overrides per chan_sip-verbatim semantic). */
		AST_STRING_FIELD(cid_tag);    /* post-T56 cid bundle parity (2026-04-28): per-peer CID tag; chan_sip parity sip_peer.cid_tag at chan_sip.c:28754-28755 + L5959 dialog-inheritance. Set via cid_tag key. Used at sofia_build_from to override sofia-sip auto-generated From-tag when set. */
		AST_STRING_FIELD(forceddiversion);  /* CLI-forward compliance (2026-06-16): per-trunk redirecting DID forced into the outbound Diversion header (RFC 5806) on a FORWARDED call, so the carrier receives a trunk-owned number it can validate instead of whatever the channel's redirecting chain carried. Empty = disabled (default; legacy data-driven Diversion behaviour preserved byte-for-byte). Read by sofia_add_diversion under peer->lock; set by both peer config parsers + readable via SIPPEER(<peer>,forceddiversion). */
		AST_STRING_FIELD(nonce);
		AST_STRING_FIELD(outboundproxy);	/* T56.1 (2026-04-27): per-peer outbound proxy override; empty = inherit sofia_cfg.outboundproxy or no Route */
		AST_STRING_FIELD(srtpcipher);		/* post-T56 srtpcipher operator option (2026-04-27): comma-separated SRTP suite preference (e.g. "AEAD_AES_256_GCM,AES_CM_128_HMAC_SHA1_80"); empty = inherit sofia_cfg.default_srtpcipher or sdp_crypto.c default AES_CM_128_HMAC_SHA1_80 */
		AST_STRING_FIELD(mohinterpret);		/* post-T56 MOH per-peer parity (2026-04-27): per-peer MOH class to play when remote puts us on hold; empty = inherit sofia_cfg.default_mohinterpret or system default */
		AST_STRING_FIELD(mohsuggest);		/* post-T56 MOH per-peer parity (2026-04-27): suggested MOH class propagated to bridged channel when this peer puts us on hold (R5 INBOUND-direction: ast_queue_control_data data param at sofia_process_reinvite); OUTBOUND-direction Alert-Info signaling deferred to outbound-HOLD-re-INVITE feature task */
		AST_STRING_FIELD(language);		/* post-T56 language per-peer parity (2026-04-27): per-peer audio language locale propagated to ast_channel.language at sofia_new for prompts/sounds in peer's preferred locale. chan_sip parity sip.h peer.language AST_STRING_FIELD + chan_sip.c:28865-28866 verbatim parser + L28447 inheritance from default_language. Bounded to channel.h:138 MAX_LANGUAGE=40 at consumption (ast_channel.language is also AST_STRING_FIELD per channel.h:776). Empty = inherit sofia_cfg.default_language or gabpbx-core default. */
		AST_STRING_FIELD(parkinglot);	/* post-T56 parkinglot per-peer parity (2026-04-28): per-peer parking-lot routing field propagated to ast_channel.parkinglot at sofia_new for Park()/transfer routing. chan_sip parity sip.h:1212 peer.parkinglot AST_STRING_FIELD + chan_sip.c:28890-28891 verbatim parser + L8577 inheritance from default_parkinglot + L5961-5962 + L17046-17047 dialog inheritance + L7943-7944 channel propagation. Empty = inherit sofia_cfg.default_parkinglot. Pattern 12 16th-instance behavior-change-from-chan_sofia-baseline-disclosure: chan_sip default_parkinglot = "default" per features.h:37 DEFAULT_PARKINGLOT (string non-empty). */
		AST_STRING_FIELD(lockuseragent_prefixes);	/* per-peer comma-separated User-Agent prefix allowlist (2026-05-17): when lockuseragent=yes AND this list is non-empty, an inbound REGISTER passes when its User-Agent: header starts (case-insensitive) with ANY listed prefix; first-REGISTER auto-capture into locked_user_agent is bypassed. Empty value preserves the original strict capture-on-first-REGISTER semantics verbatim. Targets the multi-device-per-peer use case (desk phone + softphone) and vendor-family allowlists (by useragent vendor family). */
	);
	int type;
	int port;
	int expire;
	int lastms;
	int expiresecs;
	format_t capability;
	struct ast_codec_pref prefs;
	int nat;
	int dtmfmode;
	int directmedia;
	int busy_on_active;
	int max_contacts;
	int encryption;                 /* T37: SDES-SRTP per-peer toggle (0/1); default off; explicit encryption=yes enables */
	int callingpres;                /* post-T56 identity-headers parity (2026-04-27): AST_PRES_* mask; per-peer default presentation; chan_sip parity sip.h:1238; default AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED (=0) */
	int sendrpid;                   /* post-T56 identity-headers parity (2026-04-27): 0=none / 1=PAI / 2=RPID; chan_sip SIP_SENDRPID parity */
	int trustrpid;                  /* post-T56 identity-headers parity (2026-04-27): 0/1; trust inbound PAI/RPID; chan_sip SIP_TRUSTRPID parity */
	int call_limit;                 /* post-T56 call-limit parity SS1 (2026-04-27): max simultaneous calls; 0=unlimited; chan_sip parity peer->call_limit */
	int inUse;                      /* post-T56 call-limit parity SS1 (2026-04-27): runtime cached aggregate of active calls; NOT realtime-persisted (chan_sip L6570 parity) */
	int inRinging;                  /* post-T56 call-limit parity SS1 (2026-04-27): runtime cached aggregate of ringing/proceeding calls */
	int onHold;                     /* post-T56 call-limit parity SS1 (2026-04-27): runtime cached aggregate of on-hold calls; ast_atomic_fetchadd_int at hold transition */
	int busy_level;                 /* post-T56 call-limit parity SS1 (2026-04-27): soft-cap; outbound returns BUSY (486) when inUse >= busy_level; chan_sip parity */
	/* post-T56 session timers (RFC 4028) (2026-04-27): chan_sip-parity 4-key per-peer config; sofia-sip handles wire mechanics via NUTAG_*. Inherits sofia_cfg.default_session_* at sofia_peer_alloc. Pattern 16 sofia-sip-native-mechanics-chan_sofia-config-wiring. */
	int session_timers;             /* SESSION_TIMERS_* mode enum (OFF/ACCEPT/ORIGINATE/REFUSE); chan_sip sip.h L518-521 parity (SESSION_TIMER_MODE_*) */
	int session_expires;            /* Session-Expires seconds; chan_sip stimer.st_max_se parity; default sofia_cfg.default_session_expires=1800 */
	int session_minse;              /* Min-SE seconds; chan_sip stimer.st_min_se parity; default 90 (RFC 4028 §3 floor) */
	int session_refresher;          /* SESSION_REFRESHER_AUTO/UAC/UAS preference; chan_sip stimer.st_ref parity; mapped to sofia-sip nua_*_refresher at NUTAG emit */
	int allowtransfer;              /* post-T56 allowtransfer per-peer parity (2026-04-27): TRANSFER_OPENFORALL/CLOSED REFER gate; chan_sip parity sip.h:1246 (peer->allowtransfer); inherits sofia_cfg.default_allowtransfer at sofia_peer_alloc; gated at sofia_process_refer entry */
	int allowsubscribe;             /* post-T56 allowsubscribe per-peer parity (2026-04-27): REQUEST-EVENT GATING dimension #6 sibling to allowtransfer; chan_sip parity sip.h:316 SIP_PAGE2_ALLOWSUBSCRIBE flag bit; inherits sofia_cfg.default_allowsubscribe at sofia_peer_alloc; gated at sofia_process_mwi_subscribe AFTER peer-lookup (per-peer) + sofia_process_subscribe ENTRY (global ban via DERIVED sofia_cfg.allowsubscribe). 0 = block; 1 = allow. Default inherited from default_allowsubscribe (1 TRUE per sip.h:478 chan_sip drop-in). */
	int publish;                    /* outbound PUBLISH (RFC 3903): when 1 and [general] publish_server is set, chan_sofia PUBLISHes this peer's hint (regexten/subscribecontext) dialog-info state to the central server. Default 0. */
	int gruu;                       /* GRUU/RFC 5626 (Phase 1): when 1, the outbound REGISTER advertises a stable +sip.instance (urn:uuid from EID+name) so a GRUU-capable registrar can mint a pub-gruu. Default 0 (opt-in). */
	/* post-T56 buggymwi per-peer parity (2026-04-27): chan_sip parity sip.h:338
	 * SIP_PAGE2_BUGGY_MWI flag bit (1<<22) "Buggy CISCO MWI fix". When set, the
	 * Voice-Message: NOTIFY body line OMITS the trailing " (0/0)" suffix per
	 * chan_sip.c:13800-13802 verbatim comment "some endpoints have a bug in the SIP stack
	 * where it can't accept the (0/0) notification. This can temporarily be
	 * disabled in sip.conf with the 'buggymwi' option". Per-peer-only flag
	 * (no [general] default — operators set per-affected-peer); default 0 (FALSE)
	 * = chan_sip drop-in standard RFC 3842 behavior. Consumed at
	 * transmit_mwi_notify_for_peer Voice-Message body emission. */
	int buggymwi;
	/* post-T56 lockuseragent per-peer parity (2026-04-27): security feature locks
	 * peer registration to a single User-Agent string captured at first successful
	 * REGISTER; subsequent REGISTERs from a different User-Agent string are rejected
	 * with 401 silent-reject (chan_sip-faithful AUTH_SECRET_FAILED-equivalent path) +
	 * AMI LockUserAgentReject event for NMS UA-spoofing-attack visibility (chan_sofia
	 * surpass; chan_sip silent baseline). chan_sip parity sip.h:1268 unsigned short
	 * lockuseragent:1 + chan_sip.c:28708-28712 verbatim realtime-only parser
	 * (strcasecmp v->value "0" non-ast_true quirk) + L15839-15843 verbatim REGISTER
	 * auth-OK use-site (ternary useragent-var-pick + compare-loop). chan_sofia surpass:
	 * extends parser to config-file too via T46.3 dual-parser (chan_sip realtime-only
	 * is parser-quirk; use-site fires regardless of realtime/config-file once peer
	 * field set). Default 0 (FALSE) — chan_sip drop-in. */
	int lockuseragent;
	/* post-T56 lockuseragent companion (2026-04-27): captured User-Agent string at
	 * first successful REGISTER while lockuseragent=1. chan_sip doubles peer->useragent
	 * for both display + lock-anchor; chan_sofia separates concerns — locked_user_agent
	 * is the lock-anchor, sofia_contact.user_agent (per-contact) remains the display
	 * string. Empty string = no lock captured yet (first-registration will populate). */
	char locked_user_agent[64];
	int usereqphone;                /* post-T56 usereqphone parity (2026-04-27): RFC 3966 telephone-uri ;user=phone parameter on outbound URIs when peer->name (or From username) matches digit-only pattern. chan_sip parity sip.h:253 SIP_USEREQPHONE flag bit; inherits sofia_cfg.default_usereqphone at sofia_peer_alloc; consumed by sofia_resolve_peer_target (Request-URI) + sofia_build_from (From-URI). */
	int maxforwards;                /* post-T56 maxforwards parity (2026-04-27): RFC 3261 §20.22 Max-Forwards header initial value (1-255 valid range; chan_sip parity bounds-check at chan_sip.c:28879-28882). Inherits sofia_cfg.default_max_forwards at sofia_peer_alloc; emitted via SIPTAG_MAX_FORWARDS_STR at 8 outbound nua_* callsites. */
	ast_group_t callgroup;          /* call group bitmask (groups 0-63) */
	ast_group_t pickupgroup;        /* pickup group bitmask — call groups this peer can pick up */
	struct ast_variable *chanvars;  /* post-T56 setvar+header per-peer parity (2026-04-28, COMBINED ship via Pattern 5 helper #33 sofia_add_var + chan_sofia helper-architecture-advantage 24 → 25 TWO surpass dimensions including NEW DIMENSION existing-infrastructure-leverage via T46 sofia_build_addheader_str absorption): linked-list of setvar=name=value + header=Name: value entries from per-peer config. setvar entries applied to channel via pbx_builtin_setvar_helper at sofia_new (mirrors chan_sip.c:8007-8010 verbatim sip_new iteration); header entries stored as `__SIPADDHEADERpre%2d=Name: value` channel-vars (mirrors chan_sip.c:28955-28958 verbatim format) → __ inheritance prefix strips underscores → existing T46 sofia_build_addheader_str at chan_sofia.c:4509+L4523 picks up via 12-char strncasecmp("SIPADDHEADER", 12) at sofia_call (L4858) → SIPTAG_HEADER_STR injection. chan_sip parity at chan_sip.c:28953-28958 verbatim per-peer parser via DIRECT build_peer (containing function chan_sip.c:28565) + chan_sip.c:28415-28428 add_var helper + chan_sip.c:6045+L17086 chanvars copy sites + chan_sip.c:13160-13187 outbound __SIPADDHEADER prefix-recognition + chan_sip.c:18742-18745 sip show peer Variables iteration + chan_sip.c:18850-18854 AMI ChanVariable iteration. **chan_sofia surpass via simpler-iteration-vs-chan_sip-3-step-machine** — chan_sip copies peer->chanvars → pvt->chanvars at sip_alloc (L6045) + copy at find_peer (L17086) + iterates pvt->chanvars at sip_new (L8007); chan_sofia skips both copy steps via direct peer->chanvars iteration at sofia_new (peer ao2-ref held by pvt for lifetime invariant). **Pattern 14 6th-instance chan_sofia-infrastructure-PRESENT catch class**: T46 dialplan-apps SIPAddHeader infrastructure (chan_sofia.c:4509 sofia_build_addheader_str) absorbs header= mechanism via channel-var prefix matching — ZERO new outbound-builder code needed. Cleanup at sofia_peer_destructor via ast_variables_destroy. */
	struct ast_ha *ha;              /* per-peer permit/deny ACL chain (NULL = no ACL) */
	struct ast_ha *contactha;       /* post-T56 contactpermit/contactdeny per-peer parity (2026-04-27): SEPARATE ACL chain applied to peer Contact-header IP at REGISTER processing. Distinct from peer->ha (source-IP ACL — Task 32) — operator can have peer registering FROM allowed source-IP but with disallowed Contact-IP (security against forwarding-via-attacker pattern). chan_sip parity sip_peer.contactha + chan_sip.c:15043-15044 verbatim apply semantic. Inherits sofia_cfg.contact_ha at sofia_peer_alloc via ast_duplicate_ha_list. */
	struct ast_dnsmgr_entry *dnsmgr; /* post-T56 dnsmgr per-peer parity (2026-04-27): async DNS-tracking handle for peers with host=hostname (non-IP). Allocated at sofia_peer_alloc when ast_sockaddr_parse fails on peer->host (i.e., it's a name not an IP). NULL when system-wide dnsmgr (res_dnsmgr.so dnsmgr.conf) disabled OR peer host is IP-literal. Callback sofia_on_dns_update_peer fires on DNS change → updates peer->src_addr + emits AMI DnsManagerUpdate (chan_sofia surpass). chan_sip parity at chan_sip.c:3419-3422 cleanup + L29137-29161 lookup. Lifecycle: ao2_bump(peer) at registration (callback-time-safe ref); explicit release-then-unref BEFORE refcount-drops-to-0 at reload-sweep; defensive ast_dnsmgr_release in destructor for orphan-cleanup. */
	struct ast_ha *directmediaha;   /* post-T56 directmediapermit/directmediadeny per-peer parity (2026-04-27): cross-peer cross-leg ACL — chan_sip parity at chan_sip.c:30376 verbatim semantic. Applied at sofia_get_rtp_peer (THIS leg's context) AGAINST THIS leg's RTP REMOTE addr USING THE BRIDGE PARTNER'S peer->directmediaha. Operator semantic: "peer X has directmediadeny=Y/24" means: when X is bridge partner, refuses direct-media if the OTHER leg's remote endpoint is in Y/24. Per-peer-only (chan_sip [general] ABSENT). chan_sofia ARCHITECTURAL ADVANTAGE 6th-instance ACTIVE — single sofia_get_rtp_peer gate vs chan_sip 4 process_sdp callouts (L30414+L30503+L30561+L30610). Closes Pattern 12 11th-instance deferral from commit e9d6cb1. */
	unsigned int last_nc;
	time_t nonce_issued_at;
	int insecure;
	int transport;
	nua_handle_t *nh;
	struct ast_sockaddr addr;
	int registered;
	time_t lastmsgsent;
	time_t reg_expiry;
	int reg_attempts;
	ast_mutex_t lock;
	/* Qualify/NAT fields */
	int qualify;
	int qualifyfreq;
	int qualify_pending;             /* Round5 #1: 1 = a qualify dispatch onto sofia_thread is in flight; gates the aux-thread timer from piling up duplicates */
	int qualifytimeout;
	enum sofia_peer_status peer_status;
	struct timeval last_response;
	struct timeval qualify_sent;
	struct timeval last_qualify;
	nua_handle_t *qualify_nh;
	int is_realtime;
		int is_register_line;
	/* Transient flag used only by sofia_reload_worker for mark-and-sweep
	 * (chan_sofia.c sofia_peer_mark_cb / sofia_peer_sweep_cb). Set/cleared
	 * exclusively on sofia_thread inside the reload critical section, so it
	 * never needs a lock. Outside reload, always 0. */
	int _reload_marked;
	struct ast_sockaddr src_addr;
	/* Round5 transport-route (Codex#7): registration-route transport snapshot,
	 * paired with src_addr above. Set under peer->lock by sofia_update_peer_contacts
	 * from the registering Contact's ;transport= (sofia_resolve_peer_target and the
	 * NAT-proxy helpers append it so ACK/INVITE/NOTIFY/BYE to a TCP/TLS-registered
	 * phone don't silently default to UDP). "udp"/empty -> no param emitted (the
	 * existing UDP fleet is byte-identical). ws/wss are stored on the contact but
	 * NOT yet synthesized into RURIs here (flow/Path routing is deferred). */
	char reg_transport[8];
	/* post-T56 maxcallbitrate per-peer parity (2026-04-28): per-peer SDP video
	 * bandwidth ceiling emitted as b=CT:%d media-level attribute per RFC 4566
	 * §5.8. chan_sip parity sip.h:218 DEFAULT_MAX_CALL_BITRATE=384 verbatim +
	 * chan_sip.c:28967-28970 verbatim per-peer parser atoi + bounds-clamp + L12285-12286
	 * SDP b=CT emission inside if (needvideo) block (VIDEO-MEDIA-LEVEL only;
	 * audio unchanged). Default 384 kbps inherited from sofia_cfg.default_maxcallbitrate.
	 * Pattern 12 honest-disclosure 14th-instance NEW sub-pattern
	 * behavior-change-from-chan_sofia-baseline: prior chan_sofia silent-no-b=CT
	 * baseline replaced by chan_sip-verbatim 384-kbps default; operators preferring
	 * silent baseline set [general] maxcallbitrate=0 explicitly. */
	int maxcallbitrate;
	/* post-T56 amaflags per-peer parity (2026-04-28): per-peer CDR AMA-flags
	 * (DOCUMENTATION/BILLING/OMIT) propagated to ast_channel.amaflags at sofia_new
	 * for cdr_sqlite3/pgsql/etc. recording per-peer accounting policy. chan_sip
	 * parity at chan_sip.c:28871-28877 verbatim ast_cdr_amaflags2int + LOG_WARNING-
	 * on-invalid + skip-the-bad-key + chan_sip.c:7947-7948 verbatim channel
	 * propagation gated on non-zero (preserves channel-core default when peer
	 * has no AMA flags). cdr.h enum AST_CDR_DOCUMENTATION/BILLING/OMIT. Default
	 * 0 (no AMA flags) — chan_sip drop-in. Per-peer-only ([general] ABSENT). */
	int amaflags;
	/* post-T56 subscribemwi per-peer parity (2026-04-28, Pattern 12 honest-disclosure
	 * 17th-instance — NEW sub-pattern chan_sofia-architectural-divergence): per-peer
	 * MWI subscription model gate. chan_sip parity at chan_sip.c:28902-28903 verbatim
	 * per-peer parser ast_set2_flag(peer->flags[1], ast_true(v->value),
	 * SIP_PAGE2_SUBSCRIBEMWIONLY) + sip.h:324 verbatim flag bit (1<<15) + 3 use sites:
	 * L26096 handle_request_subscribe MWI handler (when peer SUBSCRIBEs + flag set →
	 * add_peer_mwi_subs); L26978 transmit_state_notify (if flag + no peer->mwipvt →
	 * skip unsolicited); L29227 build_peer (if NOT flag + has mailboxes → add_peer_mwi_subs
	 * for unsolicited). PARSE-COMPAT-ONLY ship — chan_sofia is SUBSCRIBE-only-by-design
	 * via T55 sofia_process_mwi_subscribe + transmit_mwi_notify_for_peer; chan_sofia
	 * does NOT implement unsolicited MWI NOTIFY. subscribemwi=yes operators get
	 * drop-in compat (chan_sofia behavior matches). subscribemwi=no operators get
	 * parse-clean migration with LOG_NOTICE at parse-time + KNOWN LIMITATION
	 * sample.conf disclosure (operator-honest divergence). Default 0 (FALSE) per
	 * chan_sip drop-in. Future-fix path: implement peer->mwipvt-equivalent +
	 * AST_EVENT_MWI subscription per peer + nua_notify out-of-dialog NOTIFY emission
	 * (~100-200 LoC follow-up task if operator demand surfaces). */
	int subscribemwi;
	/* post-T56 ignoresdpversion per-peer parity (2026-04-28, Pattern 12 honest-disclosure
	 * 23rd-instance — chan_sofia-architectural-divergence sub-pattern 4th-instance
	 * post-PROVEN): per-peer flag bypassing inbound SDP o-line session-version skip-on-
	 * no-change gate when set. chan_sip parity at chan_sip.c:28199-28201 verbatim parser
	 * via handle_common_options indirection (per-peer call site L28671 + [general] call
	 * site L29544 share single parser branch) + chan_sip.c:29539 verbatim default-init
	 * via ast_clear_flag(&global_flags[1], SIP_PAGE2_IGNORESDPVERSION) BEFORE re-parsing
	 * + sip.h:325 verbatim flag bit (1<<16) "GDP: Ignore the SDP session version number
	 * we receive and treat all sessions as new" + chan_sip.c:10310-10330 verbatim use
	 * site at process_sdp (when set, bypass version-bump-required gate; otherwise skip
	 * re-process when sessionversion_remote not bumped). chan_sofia-architectural-
	 * divergence sub-pattern 4th-instance post-PROVEN (joins subscribemwi 17th +
	 * notifyringing 19th + autocreatepeer 20th): chan_sofia processes EVERY inbound SDP
	 * unconditionally by design — ZERO sessionversion tracking infrastructure exists
	 * (chan_sofia delegates SDP parsing to sofia-sip; sofia-sip exposes sdp_origin_t
	 * with version field per sdp.h:49+86 but chan_sofia never consumes it for
	 * skip-on-no-change). chan_sofia INTRINSIC behavior matches chan_sip ignoresdpversion
	 * =yes ALWAYS regardless of flag value. PARSE-COMPAT-ONLY ship: parse + store + AMI/
	 * CLI display but NO behavioral wire-in (no gate to bypass). Default 0 (FALSE) per
	 * chan_sip drop-in. ignoresdpversion=yes operators: parse-clean migration matching
	 * chan_sofia intrinsic baseline (no observable change). ignoresdpversion=no operators
	 * expecting chan_sip skip-on-no-change semantic: KNOWN LIMITATION (chan_sofia
	 * infrastructure ABSENT; documented in sample.conf). Future-fix path: implement SDP
	 * version-tracking gate at sofia_process_invite SDP handler if operator demand
	 * surfaces (~50-100 LoC follow-up). production sofia.conf has commented `;ignoresdpversion
	 * =yes` (operator-aware-but-not-active) — finally parse-clean on next reload. */
	int ignoresdpversion;
	/* post-T56 promiscredir per-peer parity (2026-04-28, Pattern 12 honest-disclosure
	 * 29th-instance + chan_sofia-architectural-divergence sub-pattern 9th-sub-instance
	 * post-PROVEN): per-peer flag for honoring 3xx Moved Temporarily redirects via
	 * ast_channel.call_forward dialplan mechanism. chan_sip parity at chan_sip.c:
	 * 28173-28175 verbatim parser via handle_common_options indirection (per-peer
	 * call site L28671 + [general] call site L29544 share single parser branch) +
	 * sip.h:251 verbatim flag bit (1<<11) + sip.h:295 SIP_FLAGS_TO_COPY mask peer→
	 * dialog inheritance + chan_sip.c:20907-20925 verbatim use site at 3xx Contact
	 * handler (when set + 3xx received → ast_string_field_build call_forward to
	 * "SIP/contact_number@host" format) + 4 display sites L18681 sip show peer +
	 * L18801 AMI SIPshowpeer + L19274 sip show settings + L19817 sip show channel
	 * (chan_sofia 4th display DEFERRED — sip show channel infrastructure verification
	 * needed). PARSE-COMPAT-ONLY ship — chan_sofia nua_r_redirect handler ABSENT
	 * (sofia-sip exposes nua_r_redirect event in nua.h:151 + deprecated nua_redirect
	 * function but NUTAG_AUTO_TARGET does NOT exist in sofia-sip-1.13 headers
	 * verified via grep across nua_tag.h+sip_tag.h+nta_tag.h+tport_tag.h+sdp.h).
	 * chan_sofia today doesn't handle 3xx redirects at all → no infrastructure to
	 * gate. KNOWN LIMITATION promiscredir=yes operators get parse-clean migration
	 * but chan_sofia doesn't follow 3xx redirects regardless of flag value. Future-
	 * fix path: implement nua_r_redirect handler + 3xx Contact parser + ast_channel
	 * .call_forward setter (~80-120 LoC follow-up if operator demand surfaces).
	 * Backup-fork verification (canonical Asterisk chan_sip.c L27934 parser + L12283 AMI) CONFIRMED
	 * chan_sip-parity-NOT-fork-regression-class. Joins sub-pattern 9-sub-instance
	 * series (subscribemwi 17th + notifyringing 19th + autocreatepeer 20th +
	 * ignoresdpversion 23rd + progressinband 24th-partial + subscribe_network_change_
	 * event 25th + rtcachefriends 27th + rtautoclear 28th + this 29th — all
	 * post-PROVEN N=3 threshold). Default 0 (FALSE) per chan_sip drop-in BSS
	 * static-zero. Inherited from sofia_cfg.default_promiscredir at sofia_peer_alloc. */
	int promiscredir;
	/* post-T56 autoframing per-peer + [general] parity (2026-04-28, PARSE-COMPAT-ONLY
	 * + Pattern 12 31st-instance + chan_sofia-architectural-divergence sub-pattern
	 * 11-sub-instances post-PROVEN): per-peer flag for codec ptime auto-detection
	 * from SDP. chan_sip semantic at chan_sip.c:10415 (when set + framing in SDP →
	 * use peer-advertised ptime via ast_codec_pref_setsize) + chan_sip.c:12663 (when
	 * NOT set + incoming → use config ptime via ast_rtp_codecs_packetization_set).
	 * chan_sip parity at chan_sip.c:28924-28925 verbatim per-peer parser ast_true
	 * (DIRECT build_peer parser NOT handle_common_options indirection per Pattern 14
	 * source-correction at R-ACK; chan_sip has SEPARATE [general] + per-peer parsers)
	 * + chan_sip.c:29865-29866 verbatim [general] parser ast_true global_autoframing
	 * + chan_sip.c:747 verbatim static unsigned int global_autoframing + chan_sip.c
	 * :29469 verbatim default-init = 0 + sip.h:1018 + L1231 verbatim bit field
	 * declarations on sip_pvt + sip_peer + 5 inheritance sites L5942 + L8547 +
	 * L17021 + L17157 + L28459 + chan_sip.c:18728 sip show peer "Auto-Framing : %s"
	 * + L18963 sip show user + L19403 sip show settings "Auto-Framing: %s" 3 display
	 * sites. Default 0 (FALSE) per chan_sip drop-in BSS static-zero. **chan_sofia
	 * infrastructure-presence verification**: sofia_parse_sdp at chan_sofia.c:2210+
	 * has SDP attribute walker (media→m_attributes); gabpbx-core ast_codec_pref_
	 * setsize + ast_rtp_codecs_packetization_set APIs available. PARSE-COMPAT-ONLY
	 * ship: parse + store + display but NO behavioral wire-in (sofia_parse_sdp
	 * autoframing gate not implemented today; future-fix ~50-70 LoC follow-up
	 * implementing SDP ptime attribute walker + ast_codec_pref_setsize wire-in if
	 * operator demand surfaces). Backup-fork verification (canonical Asterisk chan_sip.c L738 +
	 * L5909 + L8408 + L10276 + L12515 + L16844 + L16978 + L18541 + L18764 + L19202)
	 * CONFIRMED chan_sip-parity-NOT-fork-regression-class. Joins sub-pattern 11-
	 * sub-instance series (subscribemwi 17th + notifyringing 19th + autocreatepeer
	 * 20th + ignoresdpversion 23rd + progressinband 24th-partial + subscribe_network_
	 * change_event 25th + rtcachefriends 27th + rtautoclear 28th + promiscredir
	 * 29th + matchexternaddrlocally 30th + this 31st — all post-PROVEN N=3 threshold).
	 * KNOWN LIMITATION autoframing=yes operators expecting chan_sip ptime auto-
	 * detection get parse-clean migration but chan_sofia infrastructure-not-wired-
	 * today. Inherited from sofia_cfg.default_autoframing at sofia_peer_alloc. */
	int autoframing;
	/* post-T56 faxdetect per-peer + [general] multi-mode parity (2026-04-28):
	 * per-peer fax CNG tone detection and T.38 reINVITE trigger mode. Values
	 * mirror chan_sip's two-bit encoding: none, cng, t38, or cng+t38. The
	 * parser accepts yes/no and comma-separated cng,t38 values. Current
	 * behavior is wired: CNG enables DSP fax-tone detection in
	 * sofia_enable_dsp_detect(), and T38 redirects to the fax extension when
	 * a peer T.38 reINVITE is detected. */
	int faxdetect_mode;
	/* post-T56 Task #8 T.38 fax UDPTL parity SS2 (2026-04-28, skeleton +
	 * lifecycle): per-peer T.38 enable + EC mode + MaxDatagram override +
	 * symmetric-RTP UDPTL destination. Mirrors chan_sip.c:28038-28063 verbatim
	 * (t38pt_udptl + t38pt_usertpsource via handle_t38_options) +
	 * chan_sip.c:18565-18567 SIP_PAGE2_T38SUPPORT_UDPTL/_FEC/_REDUNDANCY flag
	 * mapping. Default 0 (chan_sip drop-in — operator opts in via
	 * t38pt_udptl=yes|fec|redundancy|none[,maxdatagram=N] per peer).
	 *   t38pt_udptl: 0=disabled / 1=enabled (with t38_ec_mode selecting EC mode)
	 *   t38_ec_mode: SOFIA_T38_EC_NONE/_FEC/_REDUNDANCY (parsed from t38pt_udptl=)
	 *   t38_maxdatagram: per-peer FaxMaxDatagram override (-1 = inherit
	 *     sofia_cfg.default_t38_maxdatagram; 0+ = explicit override)
	 *   t38pt_usertpsource: 1 = symmetric-RTP UDPTL destination override per
	 *     SS1.5 N3 audit catch (chan_sip.c:28061-28063 SIP_PAGE2_UDPTL_DESTINATION
	 *     mirror; consumed at SS3a SDP processing per chan_sip.c:10171 gate
	 *     `SIP_PAGE2_SYMMETRICRTP && SIP_PAGE2_UDPTL_DESTINATION`).
	 * Inherited at sofia_pvt allocation by SS4-arriving sofia_initialize_udptl;
	 * SS2 stores fields on peer + parses; SS3a/SS4 consume. */
	int t38pt_udptl;
	int t38_ec_mode;
	int t38_maxdatagram;
	int t38pt_usertpsource;
	/* post-T56 timerb [general]+per-peer parity (2026-04-28, FULL WIRE-IN +
	 * Pattern 16 sofia-sip-native 11th-instance NTATAG_SIP_T1X64 + chan_sofia
	 * parser-correctness surpass over chan_sip [general] parser-BUG + chan_sofia
	 * helper-architecture-advantage 19 → 20 NEW DOUBLE surpass dimensions): per-
	 * peer RFC 3261 §17.1.1.2 INVITE transaction timeout — Timer B = 64*T1 default
	 * (caps INVITE retry at this duration; 408 Request Timeout final response).
	 * chan_sip parity at chan_sip.c:28947-28952 verbatim per-peer parser DIRECT-
	 * build_peer (NOT handle_common_options indirection) sscanf %30d + clamp-to-
	 * global-on-invalid-or-<200 + LOG_WARNING + chan_sip.c:29601-29607 verbatim
	 * [general] parser **BUG-DISCLOSURE**: chan_sip parses int tmp = atoi but
	 * ONLY assigns to global_timer_b in `< 500` invalid-value branch — valid
	 * values ≥ 500 are PARSED via atoi but NEVER ASSIGNED to global_timer_b
	 * (operator setting [general] timerb=10000 has NO effect; global_timer_b
	 * stays at L29522 default 64*DEFAULT_TIMER_T1 = 32000ms). chan_sip parser-
	 * bug discovered at R-ACK Pattern 14 source-correction. **chan_sofia parser-
	 * correctness surpass**: chan_sofia [general] parser correctly assigns valid
	 * values via missing-`else` branch fix — chan_sip operators get CORRECT
	 * behavior under chan_sofia where chan_sip silently ignored their valid
	 * timerb settings + chan_sip.c:745-746 verbatim globals (global_t1 +
	 * global_timer_b) + chan_sip.c:29522 verbatim default-init = 64 *
	 * DEFAULT_TIMER_T1 (32000ms) + sip.h:1024 + L1285 verbatim int field
	 * declarations on sip_pvt + sip_peer + chan_sip.c:4519 + L6030-6033 +
	 * L17061-17064 inheritance use sites + chan_sip.c:6354 ast_sched_add per-
	 * pvt scheduler use site + L18697 sip show peer + L19412 sip show settings
	 * "Timer B" displays. **Pattern 16 sofia-sip-native 11th-instance**: wire-
	 * in via TAG_IF(sofia_cfg.default_timer_b, NTATAG_SIP_T1X64(sofia_cfg.
	 * default_timer_b)) at nua_create — sofia-sip native gate at nta_tag.h:182-
	 * 186 verbatim NTATAG_SIP_T1X64(x) macro applies T1*64 (Timer B) globally
	 * via NTA-layer transaction timeout setting. Mirrors NTATAG_SIP_T1 t1min
	 * ac8d1ef Pattern 16 7th-instance precedent — single global wire-in covering
	 * all NTA-layer transactions; per-peer dynamic override deferred (Pattern 12
	 * sub-pattern per-peer-dynamic-deferral repeat per t1min ac8d1ef precedent).
	 * **chan_sofia helper-architecture-advantage cluster**: single nua_create
	 * tag-emit-site vs chan_sip per-pvt ast_sched_add scheduler at L6354 (sofia-
	 * sip absorbs per-transaction Timer B into NTA layer transparently). Default
	 * 32000ms per chan_sip drop-in. Backup-fork verification CONFIRMED chan_sip-
	 * parity-NOT-fork-regression-class. Inherited from sofia_cfg.default_timer_b
	 * at sofia_peer_alloc. */
	int timer_b;
	/* post-T56 timert1 [general]+per-peer parity (2026-04-28, FULL WIRE-IN +
	 * LATENT BUG FIX at chan_sofia.c:9537 NTATAG_SIP_T1 REWIRE + chan_sofia
	 * helper-architecture-advantage 20 → 22 TWO surpass dimensions): per-peer
	 * RFC 3261 §17.1.1.1 T1 retransmission interval (ms) — initial duration for
	 * request retransmission timers A and E (UDP) and response retransmission
	 * timer G per sofia-sip nta_tag.c:497-500 docstring. chan_sip parity at
	 * chan_sip.c:744 verbatim `static int global_t1` storage + chan_sip.c:28482
	 * verbatim peer_alloc inherit `peer->timer_t1 = global_t1` + chan_sip.c
	 * :28941-28946 verbatim per-peer parser DIRECT-build_peer (NOT handle_common
	 * _options) sscanf %30d + triple-clamp (val < 200 || val < global_t1min) →
	 * LOG_WARNING + fallback peer->timer_t1 = global_t1min (chan_sip-faithful
	 * "fallback to t1min not default_timer_t1" floor semantic) + timert1_set = 1
	 * + chan_sip.c:29521 verbatim default-init `global_t1 = DEFAULT_TIMER_T1` +
	 * chan_sip.c:29596-29600 verbatim [general] parser bare `atoi` with NO range
	 * validation (chan_sip parser-class — chan_sofia parser-correctness surpass
	 * dimension applies; mirrors timerb a2e16b7 precedent) + chan_sip.c:30038-
	 * 30040 + L30043-30055 verbatim post-config-load cross-validation (T1 vs
	 * t1min lower-bound + Timer B vs T1*64 nested logic with timerb_set/timert1_
	 * set flags) + sip.h:89 verbatim `#define DEFAULT_TIMER_T1 500` + chan_sip.c
	 * :19410 verbatim "Timer T1: %d" sip show settings display + chan_sip.c
	 * :18697 sip show peer "Timer T1" display. Backup-fork verification CONFIRMED
	 * chan_sip-parity-NOT-fork-regression-class. **LATENT BUG FIX**: chan_sofia.c
	 * :9537 currently passes sofia_cfg.t1min (100ms default per t1min ac8d1ef
	 * mirroring chan_sip DEFAULT_T1MIN) as NTATAG_SIP_T1 argument — but per
	 * sofia-sip nta_tag.c:497-500 NTATAG_SIP_T1 is the T1 VALUE (default 500ms)
	 * NOT the t1min minimum-bound. Operational impact: 5× over-aggressive
	 * retransmits across ALL SIP transactions globally (UDP request retransmits
	 * timer A+E + response retransmit timer G all use this T1 value).
	 * **Fix**: REWIRE NTATAG_SIP_T1(sofia_cfg.t1min) → NTATAG_SIP_T1(sofia_cfg.
	 * default_timer_t1). Pattern 16 sofia-sip-native 7th-instance counter STAYS
	 * unchanged (REWIRED not new instance). **TWO chan_sofia surpass dimensions**:
	 * (A) parser-correctness over chan_sip [general] no-range-validation parser
	 * (R3 — mirrors timerb a2e16b7 parser-correctness surpass precedent); (B)
	 * NEW DIMENSION — bug-correction-as-byproduct-of-parity (R4 — chan_sofia
	 * ships timert1 parity AND fixes prior chan_sofia latent bug at chan_sofia.c
	 * :9537 in same commit; Pattern 14 BIDIRECTIONAL design-stage catch enabled
	 * this dimension). Default 500ms per chan_sip drop-in. Pattern 12 sub-pattern
	 * per-peer-dynamic-deferral 3rd-instance (t1min ac8d1ef + timerb a2e16b7 +
	 * this timert1 — 3-instance NTATAG_*_T1 family deferral consistency). Inherited
	 * from sofia_cfg.default_timer_t1 at sofia_peer_alloc. */
	int timer_t1;
	/* post-T56 allowoverlap per-peer + [general] parity (2026-04-28, Option A
	 * FULL WIRE-IN 3 sites + Pattern 5 helper #32 sofia_allowoverlap_str + chan_
	 * sofia helper-architecture-advantage NEW DIMENSION 3-site-additive-wire-in-
	 * without-infrastructure-rework): per-peer tri-state overlap-dial mode for
	 * RFC 3261 §3 digit-by-digit dialing scenarios. Values per SOFIA_OVERLAP_*
	 * macros: 0=NO (404 Not Found on partial-match) / 1=YES (default; 484
	 * Address Incomplete on partial-match) / 2=DTMF (parsed + stored but treated
	 * as fall-through to standard handling per chan_sip own design at chan_sip.c
	 * :23937-23943 verbatim "For SIP_PAGE2_ALLOWOVERLAP_DTMF it is better to do
	 * this in the dialplan using the Incomplete application rather than having
	 * the channel driver do it" dialplan-deferral comment). chan_sip parity at
	 * chan_sip.c:28188-28195 verbatim per-peer parser via handle_common_options
	 * (containing function chan_sip.c:28078) — chan_sofia mirrors as 3 SEPARATE
	 * parser branches T46.3 dual-parser per faxdetect 55d4444 precedent. sip.h
	 * :318-322 verbatim 2-bit-flag-encoding-at-position-13 SIP_PAGE2_ALLOWOVERLAP
	 * NO/YES/DTMF/SPARE (3 << 13). chan_sip.c:29479 verbatim default-init
	 * `ast_set_flag(&global_flags[1], SIP_PAGE2_ALLOWOVERLAP_YES);` with chan_sip
	 * trailing comment "Default for all devices: Yes" — chan_sip drop-in critical default YES preserved.
	 * Wire-in sites:
	 *   (A) sofia_process_invite ast_canmatch_extension dual-test mirrors chan_
	 *       sip.c:16491-16497 verbatim get_destination MATCHMORE-detect helper +
	 *       chan_sip.c:23930-23934 verbatim handle_request_invite SIP_GET_DEST_
	 *       EXTEN_MATCHMORE → 484 emit. peer->allowoverlap_mode == YES + canmatch
	 *       partial → nua_respond(SIP_484_ADDRESS_INCOMPLETE) + ao2 cleanup +
	 *       early-return BEFORE sofia_new (no PBX dispatch).
	 *   (B) sofia_indicate AST_CONTROL_INCOMPLETE case mirrors chan_sip.c:7661-
	 *       7669 verbatim dialplan-driven Incomplete-app path. peer->allowoverlap
	 *       _mode == YES → emit 484 via nua_respond.
	 *   (C) nua_r_invite 484 status special-case mirrors chan_sip.c:22508-22518
	 *       verbatim outbound 484 response handling. peer->allowoverlap_mode ==
	 *       YES → ast_queue_hangup_with_cause AST_CAUSE_NUMBER_CHANGED (484);
	 *       NO/DTMF → AST_CAUSE_404 (404).
	 * Inherited from sofia_cfg.default_allowoverlap_mode at sofia_peer_alloc
	 * before per-peer parser overrides. CLI displays: sip show peer "Overlap
	 * dial: %s" (chan_sip.c:18689 verbatim wording) + AMI SIPshowpeer
	 * "OverlapDial: %s" (chan_sofia surpass — chan_sip AMI silent verified via
	 * grep ABSENT) + sip show settings "Allow overlap dialing: %s" (chan_sip.c
	 * :19273 verbatim wording, 22nd field on sofia_cli_show_settings).
	 * Pattern 14 verification 11/11 CLEAN R-ACK + 2 ENRICHMENT corrections
	 * (3 inbound wire-in sites verified + chan_sofia get_destination-equivalent
	 * absence finding). chan_sofia helper-architecture-advantage advances 22→23. */
	int allowoverlap_mode;
	/* post-T56 progressinband per-peer + [general] tri-state parity (2026-04-28,
	 * REAL OPERATOR DRIVER on production sofia.conf progressinband=no silently-ignored
	 * prior to this commit; finally honored on next reload as NEVER-equivalent
	 * NO-state semantic per Option B partial wire-in): per-peer tri-state SDP
	 * early-media in-band audio control. Values per SOFIA_PROG_INBAND_* macros:
	 * 0=NEVER (default; emit 180 only, no in-band audio) / 1=NO (emit 180 only,
	 * NO state degrades to NEVER per chan_sofia partial-feature-parity Pattern
	 * 12 24th-instance) / 2=YES (emit 180 + return -1 to force in-band audio
	 * playback per chan_sip.c:7631 verbatim). chan_sip parity at chan_sip.c:
	 * 28166-28172 verbatim per-peer parser via handle_common_options indirection
	 * (per-peer call site L28671 + [general] call site L29544 share single parser
	 * branch) + sip.h:282-285 verbatim 3 macros (SIP_PROG_INBAND (3<<25) +
	 * SIP_PROG_INBAND_NEVER (0<<25) + SIP_PROG_INBAND_NO (1<<25) + SIP_PROG_INBAND
	 * _YES (2<<25)) + chan_sip.c:7616-7637 verbatim use site at sip_indicate
	 * AST_CONTROL_RINGING (outer-if emit 180 when !progress_sent OR NEVER; inner-if
	 * after-180 break unless YES → return -1 forcing in-band). Pattern 12 24th-
	 * instance + chan_sofia-architectural-divergence sub-pattern 5th-instance
	 * partial-feature-parity flavor (NEVER + YES states match chan_sip semantic
	 * exactly; NO state degrades to NEVER behavior because chan_sofia lacks
	 * SIP_PROGRESS_SENT tracking infrastructure for chan_sip's "after-progress-
	 * sent in-band" subtle 2nd-call semantic). Default NEVER per chan_sip
	 * drop-in. Future-fix path: implement pvt->progress_sent state-tracking
	 * (~30 LoC follow-up if operator demand surfaces for full NO-state
	 * semantic). Use case: early-media for IVR/announcement playback BEFORE
	 * 200 OK answer. Inherited from sofia_cfg.default_progressinband at
	 * sofia_peer_alloc when peer omits the key. */
	int progressinband;
	/* post-T56 preferred_codec_only per-peer parity (2026-04-28): SDP codec-offer-list
	 * narrowing to single most-preferred codec for bandwidth-constrained scenarios +
	 * codec-locked trunks. chan_sip parity at chan_sip.c:28922-28923 verbatim per-peer
	 * parser ast_set2_flag SIP_PAGE2_PREFERRED_CODEC + L29863-29864 verbatim [general]
	 * parser ast_set2_flag global_flags[1] + sip.h:313 verbatim define
	 * SIP_PAGE2_PREFERRED_CODEC (1<<9) "GDP: Only respond with single most preferred
	 * joint codec" + L10076 verbatim use site inside process_sdp narrows
	 * pvt->jointcapability via ast_codec_choose. chan_sofia ARCHITECTURAL ADVANTAGE
	 * 12th-instance: Option 6-A chan_sofia-strict-direction-symmetric narrowing
	 * applies to BOTH initial-INVITE-offer + response paths (chan_sip narrows
	 * RESPONSE-direction only at process_sdp); chan_sofia operator-honest surpass
	 * — preferred_codec_only operator semantic preserved consistently across both
	 * SDP-emit paths via single sofia_generate_sdp helper site. Default 0 (FALSE)
	 * inherited from sofia_cfg.default_preferred_codec_only. */
	int preferred_codec_only;
	/* post-T56 rtp-timeout bundle per-peer parity (2026-04-28): 3-key bundle for
	 * RTP-stream no-traffic detection + dead-call cleanup + keepalive emission.
	 * chan_sip parity at chan_sip.c:721-723 verbatim 3 static int globals
	 * (global_rtptimeout/holdtimeout/keepalive) + L28926-28940 verbatim per-peer
	 * parsers sscanf %30d + LOG_WARNING + clamp-to-global-on-invalid + L29668-29680
	 * verbatim [general] parsers + L28455-28456 build_peer inheritance + L5930-5932
	 * + L17151-17153 dialog inheritance + L5862-5864 + L5880-5882 use sites at
	 * SDP-process. gabpbx-core APIs at rtp_engine.h:1671 ast_rtp_instance_set_timeout
	 * + L1689 set_hold_timeout + L1707 set_keepalive. Default 0 (disabled) per
	 * chan_sip drop-in. Inherited from sofia_cfg.default_X at sofia_peer_alloc.
	 * production sofia.conf line rtptimeout=30 + rtpholdtimeout=300 currently
	 * silently-ignored on chan_sofia until this commit; finally honored on next reload
	 * (REAL OPERATOR DRIVER). */
	int rtptimeout;
	int rtpholdtimeout;
	int rtpkeepalive;
	/* post-T56 defaultip per-peer parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:28814-28818 verbatim per-peer parser ast_get_ip into peer->defaddr
	 * + L5913-5915 verbatim dialog->sa = ast_sockaddr_isnull(addr) ? defaddr : addr
	 * fallback semantic + sip.h peer.defaddr counterpart. Default empty via
	 * ast_sockaddr_setnull at sofia_peer_alloc. Use case: peer has host=dynamic
	 * but operator knows fallback IP — outbound calls before peer registers route
	 * to defaddr; once peer registers src_addr takes precedence. chan_sofia 1-site
	 * wire-in at sofia_resolve_peer_target (chan_sip 4 use sites; chan_sofia
	 * realtime-load + MWI/poke skip-paths absent). */
	struct ast_sockaddr defaddr;
	struct ao2_container *contacts;
	/* T55.1 (2026-04-27): MWI per-peer mailbox list (NOLOCK; peer->lock guards). */
	struct sofia_mailbox_list mailboxes;
	nua_handle_t *mwi_subscription_handle; /* T55.3 will populate; NULL until first SUBSCRIBE */
};


/* The [general] configuration block. Defined once in chan_sofia.c (static sofia_cfg);
 * the named type lets split modules reference it. */
struct sofia_config {
	char bindaddr[128];
	int bindport;
	char context[AST_MAX_CONTEXT];
	char default_user[80];
	char default_secret[80];
	char realm[80];
	int tcp_keepalive_ms;     /* feature #5: [general] tcp_keepalive (seconds in config, stored ms). 0 = OFF (default). Application-level CRLF keepalive (TPTAG_KEEPALIVE) on connection-oriented transports — a periodic CRLF on an idle connection holds the NAT binding. TCP-only (sofia-sip's TLS/WS vtables do not use this timer). Socket-level SO_KEEPALIVE is already on by default (sofia-sip ~30s). */
	int tcp_pingpong_ms;      /* feature #5: [general] tcp_pingpong (seconds in config, stored ms). 0 = OFF (default). TPTAG_PINGPONG — if no pong arrives within this after a keepalive ping, the connection is treated as dead. Opt-in (an aggressive value can tear down a slow-but-alive connection). */
	int allowguest;
	int busy_on_active;
	int max_contacts;
	int encryption;                   /* T37: SDES-SRTP general default (0=off, 1=on); soft-zeroed at load if res_srtp absent */
	char default_srtpcipher[256];     /* post-T56 srtpcipher operator option (2026-04-27): comma-separated cipher preference list inherited by sofia_peer_alloc when peer omits the key; empty = use sdp_crypto.c default AES_CM_128_HMAC_SHA1_80 */
	int srtp_per_suite_keys;          /* post-T56 Task 7b SRTP per-suite-fresh-key option (2026-04-28, deferred from #7a 612759d R4 strategy (b) — chan_sofia surpass dimension feature-not-in-chan_sip-at-all): 0 = shared-key mode default (current behavior; #7a strategy (a) — single 46-byte master_key shared across all suites in multi-cipher offer; peer picks one so unused key material discarded on answer) / 1 = per-suite-fresh-key mode (forensic-grade key separation; each suite gets independent fresh random master_key via res_srtp->get_random; key material recovery from one suite cannot decrypt others — MIKEY/DTLS-SRTP convention). [general]-only operator option (no per-peer override; operator-policy is global). chan_sofia surpass dimension — no chan_sip equivalent (chan_sip has no multi-suite SRTP offer mechanism therefore no shared-vs-per-suite key strategy choice). Wire-in via module-scope sofia_srtp_per_suite_keys mirror (set in sofia_load_config; consumed by sdp_crypto.c sdp_crypto_offer_list multi-cipher loop + sdp_crypto_activate suite-key selection). Mem cost ~1.7 KB per active SRTP call when enabled (16-slot static arrays in struct sdp_crypto). */
	int force_invite_auth;            /* post-T56 Task #3 INVITE digest auth SS3 (2026-04-28, R18 chan_sofia surpass dimension operator-policy-global-security-override + SW6 INSECURE_INVITE-visibility-vs-chan_sip-silent NEW DIMENSION): 0 = drop-in chan_sip parity baseline (per-peer insecure=invite bypass active) / 1 = global lockdown override (ALL inbound INVITEs require digest auth regardless of per-peer insecure=invite config). [general]-only operator security-lockdown switch. chan_sofia surpass — no chan_sip equivalent (chan_sip has only per-peer insecure=invite; no global override mechanism). Use cases: compliance audit during scheduled review (temporarily disable bypass), incident response (lock down auth in response to detected attack), default-deny posture (progressive operator hardening). When force_invite_auth=1 AND a peer hits with insecure=invite, LOG_NOTICE fires "Sofia: force_invite_auth=yes overrides per-peer insecure=invite for peer X — auth required" so operator sees policy taking effect. Mirrors sofia_srtp_per_suite_keys [general]-only design pattern. */
	int nonce_ttl_seconds;            /* Digest auth nonce TTL override. 0 = use SOFIA_NONCE_TTL_SEC_DEFAULT (3600s); positive value = explicit operator override. Consumed by sofia_verify_digest_auth nonce-staleness check. */
	int auth_algorithms;              /* SOFIA_AUTH_ALG_BOTH/MD5/SHA256: which digest algorithm(s) to OFFER in the WWW-Authenticate challenge. [general] auth_algorithms = both|md5|sha256. Built-in default BOTH = MD5 + SHA-256 (the shipped sofia.conf sets md5). GLOBAL — same offer to all peers, no per-peer override. Verification accepts exactly what was offered (anti-downgrade). */
	/* post-T56 session timers (RFC 4028) (2026-04-27): chan_sip-parity 4-key dual-scope config inherited by sofia_peer_alloc; sofia-sip handles wire mechanics via NUTAG_SESSION_TIMER + NUTAG_MIN_SE + NUTAG_SESSION_REFRESHER (Pattern 16 sofia-sip-native-mechanics-chan_sofia-config-wiring; ~6.7x leverage vs chan_sip handcoded). */
	int default_session_timers;       /* SESSION_TIMERS_OFF/ACCEPT/ORIGINATE/REFUSE; default=ACCEPT per chan_sip parity (honor inbound, no initiate) */
	int default_session_expires;      /* default Session-Expires seconds; chan_sip parity 1800s (RFC 4028 §4 typical) */
	int default_session_minse;        /* default Min-SE seconds; chan_sip parity 90s (RFC 4028 §3 absolute floor) */
	int default_session_refresher;    /* SESSION_REFRESHER_AUTO/UAC/UAS; default=AUTO per sofia-sip nua_any_refresher (negotiation-decided) */
	/* post-T56 identity-headers parity (2026-04-27): RPID/PAI/Diversion defaults inherited by sofia_peer_alloc when peer omits the key. */
	int default_callingpres;          /* AST_PRES_* mask; default for peers without explicit callingpres; static-zero == AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED */
	int default_sendrpid;             /* 0=none / 1=PAI / 2=RPID; default for peers without explicit sendrpid */
	int default_trustrpid;            /* 0/1; default for peers without explicit trustrpid */
	/* post-T56 call-limit parity SS1 (2026-04-27): call-limit defaults inherited by sofia_peer_alloc. */
	int default_call_limit;           /* default cap for peers without explicit call-limit; chan_sip parity */
	int default_busy_level;           /* default busy_level for peers without explicit busylevel */
	/* post-T56 allowtransfer per-peer parity (2026-04-27): default REFER policy
	 * inherited by sofia_peer_alloc; chan_sip parity sip.h:707 (sip_cfg.allowtransfer)
	 * + L29476 (TRANSFER_OPENFORALL backwards-compat default). Static-zero == OPENFORALL. */
	int default_allowtransfer;        /* TRANSFER_OPENFORALL/CLOSED; default OPENFORALL via static-zero */
	/* post-T56 allowsubscribe [general]+per-peer parity (2026-04-27): REQUEST-EVENT
	 * GATING dimension #6 sibling to allowtransfer — gates inbound SUBSCRIBE per-peer
	 * + global. chan_sip parity at chan_sip.c:28196-28198 (per-peer parser ast_set2_flag
	 * SIP_PAGE2_ALLOWSUBSCRIBE) + L29478 ([general] global_flags[1] default TRUE per
	 * sip.h:478) + L29217-29218 (sip_cfg.allowsubscribe DERIVED TRUE-if-any-peer-allows
	 * post-build) + 2 use sites L25856 global ban gate + L25940 per-peer gate (both
	 * 403 "Forbidden (policy)" verbatim-with-parens). default_allowsubscribe is the
	 * [general] inheritance default for sofia_peer_alloc; allowsubscribe is the
	 * derived global ban-all flag (FALSE only when EVERY peer has allowsubscribe=0)
	 * computed by sofia_post_config_derive_allowsubscribe at config-load conclusion +
	 * post-realtime-peer-build. Default 1 (TRUE) per sip.h:478 chan_sip drop-in. */
	int default_allowsubscribe;       /* [general] inheritance default; default 1 (TRUE) */
	int allowsubscribe;               /* DERIVED global ban-all flag; FALSE only when no peer allows */
	/* post-T56 regexten + regextenonqualify parity (2026-04-27): chan_sip-parity
	 * registration-coupled dialplan auto-extension mechanism. regcontext is the
	 * MASTER SWITCH (chan_sip.c:5198-5199 — register_peer_exten returns early if
	 * empty); names the dialplan context where extensions get auto-added on REGISTER
	 * + auto-removed on unregister. Empty default = mechanism disabled (chan_sip
	 * parity default). regextenonqualify gates qualify-state-transition coupling
	 * (chan_sip.c:22087+27574) — when peer transitions to/from REACHABLE the
	 * extension is added/removed; default FALSE per sip.h:215 DEFAULT_REGEXTENONQUALIFY. */
	char regcontext[AST_MAX_CONTEXT];  /* dialplan context for auto-added register extensions; empty = mechanism disabled */
	int regextenonqualify;             /* couple regexten add/remove to qualify state transitions; default 0 (FALSE) */
	/* post-T56 subscribecontext per-peer parity (2026-04-27): chan_sip parity
	 * sip.h:714 + chan_sip.c:29564-29565 + L29496. [general] default routing context
	 * for SIP SUBSCRIBE method dispatch. Inherited by sofia_peer_alloc when peer
	 * omits subscribecontext=. KNOWN LIMITATION: pivot-site override at
	 * sofia_process_subscribe deferred until presence/dialog event-package handler
	 * lands; today's MWI handler uses peer->mailboxes lookup (not peer->context),
	 * unknown events auto-202 (no dialplan dispatch). Field is parsed + persisted
	 * + displayed today; effect-pending. */
	char default_subscribecontext[AST_MAX_CONTEXT];
	/* post-T56 registration TTL bounds + 423 Interval Too Brief parity (2026-04-27):
	 * chan_sip [general]-only TTL governance — min_expiry rejects under-min REGISTER
	 * with 423 Interval Too Brief + Min-Expires header (RFC 3261 §10.2.8); max_expiry
	 * silently caps over-max REGISTER + accepts. default_expiry is fallback when peer
	 * omits expires (and per Option A also fallback for peer->expiresecs at sofia_peer_alloc).
	 * chan_sip parity at chan_sip.c:567-569 + L25699-25702 + L29760-29773. Operators
	 * with chan_sip [general] minexpiry/maxexpiry/defaultexpiry configs migrate verbatim
	 * (typo-tolerance: chan_sip historically accepts both Xexpiry + Xexpirey forms;
	 * chan_sofia mirrors dual-acceptance). */
	int min_expiry;     /* default DEFAULT_MIN_EXPIRY=60s — under this rejects 423 */
	int max_expiry;     /* default DEFAULT_MAX_EXPIRY=3600s — over this silently caps */
	int default_expiry; /* default DEFAULT_DEFAULT_EXPIRY=120s — fallback for peer->expiresecs (Option A dual-scope) */
	/* post-T56 usereqphone parity (2026-04-27): RFC 3966 telephone-uri ;user=phone
	 * parameter for E.164 numbers via PSTN gateways. chan_sip parity at
	 * chan_sip.c:29660-29661 ([general] global_flags[0] SIP_USEREQPHONE bit) +
	 * L28781-28782 (per-peer flag). chan_sofia uses int field consistent with
	 * busy_on_active / trustrpid / callcounter conventions. Inherited by
	 * sofia_peer_alloc when peer omits the key. Default 0 (chan_sip flag-bit
	 * static-zero behavior). */
	int default_usereqphone;
	/* post-T56 maxforwards parity (2026-04-27): RFC 3261 §20.22 Max-Forwards header
	 * initial value (decremented by each proxy hop; reaching 0 returns 483 Too Many
	 * Hops). chan_sip parity at chan_sip.c:30011-30015 [general] + L29497 default-init.
	 * Inherited by sofia_peer_alloc; emitted via SIPTAG_MAX_FORWARDS_STR at outbound
	 * nua_invite + nua_register (Pattern 16 sofia-sip-native 6th-instance). */
	int default_max_forwards;
	/* post-T56 t1min parity (2026-04-27): RFC 3261 §17.1.1.2 T1 retry-timer
	 * minimum bound (milliseconds). chan_sip parity sip.h:217 DEFAULT_T1MIN=100
	 * + chan_sip.c:745 global_t1min + L29608 [general] parser. Wired via
	 * sofia-sip native NTATAG_SIP_T1 at nua_create (Pattern 16 7th-instance). */
	int t1min;
	/* post-T56 relaxdtmf + prematuremedia parity (2026-04-27): [general] media-layer
	 * policy flags. relaxdtmf=ast_dsp DSP_DIGITMODE_RELAXDTMF flag (chan_sip parity
	 * chan_sip.c:719 + L4958-4960; default FALSE). prematuremediafilter=183 Session
	 * Progress emission gate at sofia_indicate AST_CONTROL_PROGRESS (chan_sip parity
	 * chan_sip.c:720 + L7298 + L29458; default TRUE = filter ON = 183 SUPPRESSED).
	 * INVERTED-SEMANTIC chan_sip-quirk: operator key "prematuremedia=yes" → variable
	 * TRUE → filter ON → 183 SUPPRESSED (preserve chan_sip drop-in compat verbatim). */
	int relaxdtmf;
	int prematuremediafilter;
	/* post-T56 registertimeout + registerattempts parity (2026-04-27): outbound
	 * REGISTER application-level scheduled-retry control; chan_sip parity at
	 * chan_sip.c:724-725 + L29799-29805 + L14092 (attempt-cap gate) + L14217
	 * (sleep-then-retry interval). NOT sofia-sip-internal NUTAG_RETRY_COUNT
	 * (different semantic layer — that's transaction-internal retry). chan_sofia
	 * mirrors via sofia_reg_thread sleep + reg_attempts cap. */
	int register_timeout;  /* seconds between retry attempts; default 20s (DEFAULT_REGISTRATION_TIMEOUT) */
	int register_attempts; /* maximum scheduled-retry count; 0 = unlimited (chan_sip parity) */
	/* post-T56 directrtpsetup parity (2026-04-27): chan_sip experimental feature
	 * (default DISABLED per chan_sip.c:29449 "Experimental feature, disabled by
	 * default"). Pattern 12 honest-disclosure 8th-instance — PARSE-COMPAT-ONLY
	 * ship; full-feature early-RTP-bridge wire-in DEFERRED per Pattern 15 (no
	 * operator driver since chan_sip itself defaults DISABLED). Operators get
	 * drop-in reload-clean compat for chan_sip configs containing this key. */
	int directrtpsetup;
	/* post-T56 alwaysauthreject [general] parity (2026-04-27): chan_sip parity at
	 * chan_sip.c:29699-29700 ([general]-only key) + sip.h:213 DEFAULT_ALWAYSAUTHREJECT
	 * TRUE verbatim. Security-critical RFC 3261 §22.4 username-enumeration prevention:
	 * when set, REGISTER from unknown peer + MWI SUBSCRIBE for unknown mailbox both
	 * return 401 Unauthorized (with bogus challenge) instead of 403/404 — attacker
	 * cannot distinguish "peer exists, bad password" from "peer does not exist".
	 * Default 1 (TRUE) per chan_sip drop-in critical security default. chan_sofia
	 * surpass: every alwaysauthreject-triggered 401 emits AMI AuthFailure event
	 * (Peer:UNKNOWN + Method + Reason + RemoteAddr) for brute-force monitoring
	 * (chan_sip silent baseline). Pattern 12 framework-feature-absence: GabPBX has
	 * no EVENT_FLAG_SECURITY (only SYSTEM/CALL/LOG/...); fallback EVENT_FLAG_SYSTEM
	 * matches existing chan_sofia AMI events. */
	int alwaysauthreject;
	/* post-T56 compactheaders [general] parity (2026-04-27, Pattern 12 honest-disclosure
	 * 12th-instance — NEW sub-pattern sofia-sip-native-gate-absence-PARSE-COMPAT-ONLY).
	 * chan_sip emits compact-form SIP headers (m=Contact, t=To, etc.) when this flag is
	 * set via find_alias per-header translation at message-build time (chan_sip.c:10716).
	 * sofia-sip ZERO native compact-emit gate (verified across nta_tag.h + nua_tag.h +
	 * sip_tag.h — no NUTAG_USE_COMPACT / SIPTAG_COMPACT / use_compact). chan_sofia
	 * delegates message-build to sofia-sip layer = NO interception point. PARSE-COMPAT-ONLY:
	 * field parsed + stored + reload-clean for chan_sip drop-in compat; full-feature
	 * compact-emit DEFERRED until upstream sofia-sip exposes native gate. Default 0
	 * (FALSE) per chan_sip parity sip.h:194 DEFAULT_COMPACTHEADERS verbatim. */
	int compactheaders;
	/* post-T56 disallowed_methods parity (2026-04-27): chan_sip parity at chan_sip.c:29453
	 * (sip_cfg.disallowed_methods = SIP_UNKNOWN bitmask) + L29998-30000 ([general] parser
	 * via mark_parsed_methods). Pattern 12 honest-disclosure 9th-instance — PARSE-COMPAT-ONLY
	 * ship via STRING-STORAGE SHORTCUT (R5; avoids porting mark_parsed_methods + SIP_METHOD_*
	 * bitmask constants). Default empty string (operator-honest divergence from chan_sip
	 * SIP_UNKNOWN bitmask default; sofia-sip NUTAG_APPL_METHOD handles unknown-method gating
	 * natively at NUA layer). Full-feature dynamic NUTAG_ALLOW generation per-handle
	 * DEFERRED per Pattern 15. */
	char disallowed_methods[128];
	/* post-T56 contactpermit/contactdeny [general] parity (2026-04-27): chan_sip
	 * parity at chan_sip.c:29646-29648 (sip_cfg.contact_ha) + L29359-29360 cleanup +
	 * L29454 reset + L15043 apply. Inherited by sofia_peer_alloc via
	 * ast_duplicate_ha_list when peer omits per-peer contactpermit/contactdeny. */
	struct ast_ha *contact_ha;
	int srvlookup;
	int pedantic;
	char externaddr[128];
	/* post-T56 NAT parity fill (2026-04-27): externhost (DDNS hostname; lazy-resolves to externaddr per externrefresh) + externtcpport/externtlsport (per-transport external port; chan_sip L1213-1215 parity). */
	char externhost[256];     /* DDNS hostname; resolved into externaddr at module-load + lazy-refreshed at sofia_resolve_ourip; empty = no DDNS, externaddr used as-is */
	time_t externexpire;      /* Lazy-refresh deadline; 0 = no DDNS / no refresh; chan_sip externexpire parity */
	int externrefresh;        /* DNS-refresh interval in seconds; default 10 (chan_sip L1213 parity) */
	int externtcpport;        /* External TCP port for outbound headers; default 5060; uint16 in chan_sip but stored as int for atoi simplicity */
	int externtlsport;        /* External TLS port; default 5061 */
	char localnet[128];
		struct ast_ha *localha;
	int udpport;
	/* T36: optional TLS / WS / WSS listeners */
	char tlsbindaddr[64];
	int  tlsbindport;        /* 0 = disabled; common: 5061 */
	char tlscertfile[256];   /* directory containing agent.pem (combined cert+key) */
	int  tlsverify;          /* Round4 #3: verify the peer cert chain on TLS/WSS (default 0
	                          * = OFF, sofia-sip default; opt-in, requires a CA bundle). */
	/* feature #6: TLS hardening knobs for the TLS listener (opt-in; empty/0 = sofia-sip default, no
	 * behavior change). These map to TPTAG_TLS_* at nua_create. They affect the TLS listener ONLY —
	 * the WSS listener builds its own SSL_CTX (tport_type_ws.c tport_wss_create_ssl_ctx) and ignores
	 * TPTAG_TLS_*. */
	char tls_ciphers[256];   /* OpenSSL cipher list -> TPTAG_TLS_CIPHERS (empty = sofia default
	                          * "!eNULL:!aNULL:!EXP:!LOW:!MD5:ALL:@STRENGTH"). */
	char tls_min_version[8]; /* "1.0"|"1.1"|"1.2"|"1.3" -> a TPTAG_TLS_VERSION enable-bitmask of that
	                          * protocol and every higher one (TLS1.3 is always on). Stored as the
	                          * STRING (not the computed mask) because "1.3" maps to bitmask 0 which is
	                          * indistinguishable from "unset"; the reload detector compares the string. */
	int  tls_verify_depth;   /* max cert-chain depth -> TPTAG_TLS_VERIFY_DEPTH (0 = sofia default 2). */
	/* outbound PUBLISH (RFC 3903): chan_sofia as an Event Publication Agent, publishing each
	 * `publish=yes` peer's local hint (dialog-info) state OUT to a central state/presence server.
	 * publish_server empty = feature OFF (no impact). */
	char publish_server[256];  /* central ESC Request-URI (e.g. sip:presence@central.example); empty = OFF */
	int  publish_expires;      /* PUBLISH Expires in seconds (0 -> default 3600) */
	char publish_domain[128];  /* entity-URI domain for the published PIDF/dialog-info; empty -> derived from publish_server host */
	char publish_username[80]; /* digest credentials for the central server (401/407) */
	char publish_password[80];
	char wsbindaddr[64];
	int  wsbindport;         /* 0 = disabled; common: 5066 */
	char wssbindaddr[64];
	int  wssbindport;        /* 0 = disabled; common: 7443 */
	/* T55.1 (2026-04-27): MWI message-summary defaults (RFC 3842). */
	char mwi_from[80];        /* From header used in MWI NOTIFY; empty -> peer->fromdomain or sofia_cfg.realm fallback */
	char notifymime[80];      /* Content-Type for MWI NOTIFY body; default "application/simple-message-summary" */
	char vmexten[80];         /* Voicemail user-part for Message-Account URI; default "asterisk" */
	int  mwi_expiry;          /* MWI subscription default expiry seconds; default 3600.
	                           * post-T56 mwiexpiry/mwiexpirey [general] dual-key parity (2026-04-28):
	                           * field active per T55.1; parser extended to 3-spelling OR-chained
	                           * acceptance — chan_sofia "mwi_expiry" (T55.1 historical) + chan_sip
	                           * "mwiexpiry" + chan_sip "mwiexpirey" alternate spelling. chan_sip
	                           * parity citations: chan_sip.c:29775-29782 verbatim dual-key parser
	                           * + chan_sip.c:570 verbatim static field + sip.h:58 verbatim
	                           * DEFAULT_MWI_EXPIRY = 3600 + chan_sip.c:13378 + L21749 chan_sip-CLIENT
	                           * outbound SUBSCRIBE refresh-timer use sites. chan_sofia uses field
	                           * for SERVER-side outbound NOTIFY Expires header per RFC 6665 (T55
	                           * notifier at chan_sofia.c:8339); same time interval, different
	                           * direction; same field serves both purposes. NOT PARSE-COMPAT-ONLY
	                           * — full chan_sip-faithful semantic active immediately via T55.1
	                           * wire-in. */
	/* T56.1 (2026-04-27): outbound proxy default for outbound INVITE + REGISTER. Per-peer
	 * outboundproxy= overrides this; empty here = no Route header injection by default. */
	char outboundproxy[80];
	/* post-T56 MOH per-peer parity (2026-04-27): default MOH classes inherited by sofia_peer_alloc when peer omits the key; chan_sip parity char[MAX_MUSICCLASS=80] */
	char default_mohinterpret[80];
	char default_mohsuggest[80];
	/* post-T56 language per-peer parity (2026-04-27): [general] default_language
	 * inherited by sofia_peer_alloc when peer omits the key; chan_sip parity at
	 * chan_sip.c:29709-29710 verbatim ast_copy_string + L29498 default-init empty.
	 * Bounded to channel.h:138 MAX_LANGUAGE=40 (matches ast_channel.language field
	 * size). Default empty string = no language override; gabpbx-core default
	 * language used for prompts/sounds. */
	char default_language[MAX_LANGUAGE];
	/* post-T56 parkinglot [general] parity (2026-04-28): [general] default_parkinglot
	 * inherited by sofia_peer_alloc when peer omits the key; chan_sip parity at
	 * chan_sip.c:30027-30028 verbatim ast_copy_string + L29510 default-init via
	 * ast_copy_string(default_parkinglot, DEFAULT_PARKINGLOT, sizeof) — features.h:37
	 * verbatim DEFAULT_PARKINGLOT = "default". Bounded to AST_MAX_CONTEXT (chan_sip.c:699
	 * default_parkinglot[AST_MAX_CONTEXT]). Pattern 12 16th-instance behavior-change-
	 * from-chan_sofia-baseline-disclosure 2nd-instance — prior chan_sofia silent-empty
	 * baseline replaced by chan_sip-verbatim "default" string default. Operators
	 * preferring silent-baseline restoration set [general] parkinglot= empty. */
	char default_parkinglot[AST_MAX_CONTEXT];
	/* post-T56 ignoreregexpire [general] parity (2026-04-28): when set, expired
	 * SIP registrations are NOT removed from peer->contacts — preserves last-known
	 * contact across short upstream-trunk outages (e.g., stable PSTN gateway with
	 * intermittent network drops; carrier-softswitch-style scenarios). chan_sip parity at
	 * chan_sip.c:29594-29595 verbatim [general] parser ast_true + L14625-14637
	 * destroy_association cleanup-skip-when-set + L29197-29204 realtime peer-load
	 * expired-contact-preserve-when-set. chan_sip default = implicit sip_cfg
	 * static-zero (no explicit init line); chan_sofia explicit-init = 0 for
	 * clarity (more disciplined than chan_sip). Production sofia.conf line
	 * 71 ignoreregexpire=yes precedent — silently ignored prior to this task;
	 * finally honored on next reload. chan_sofia 1-site wire-in at
	 * sofia_expire_contacts_cb (chan_sip 2nd site sofia_find_peer_realtime
	 * equivalent ABSENT — chan_sofia realtime-load doesn't check regseconds). */
	int ignore_regexpire;
	/* post-T56 maxcallbitrate [general] parity (2026-04-28): default video bandwidth
	 * ceiling inherited by sofia_peer_alloc; chan_sip parity at chan_sip.c:701
	 * default_maxcallbitrate static + L29502 verbatim default-init via
	 * DEFAULT_MAX_CALL_BITRATE = 384 (sip.h:218). Bounds-clamp negative-values back
	 * to 384 mirrors chan_sip.c:29952-29953. Used by sofia_generate_sdp video block
	 * to emit b=CT:%d line per RFC 4566 §5.8 media-level attribute (gated inside
	 * if (needvideo) block — audio-only operators unaffected). */
	int default_maxcallbitrate;
	/* post-T56 match_auth_username [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:717 verbatim static int global_match_auth_username "Match auth
	 * username if available instead of From: Default off." + L29472 verbatim
	 * default-init FALSE + L29754-29755 verbatim [general] parser ast_true +
	 * L17258-17277 verbatim use site (gates Authorization-username override of
	 * From-username for peer-lookup search-key). Security-relevant: spoofing-
	 * prevention + multi-identity scenarios where From-header doesn't reliably
	 * identify the peer (operator wants peer-matching by Authorization digest
	 * username). Default 0 (FALSE) — chan_sip drop-in. */
	int match_auth_username;
	/* post-T56 legacy_useroption_parsing [general] parity (2026-04-28, Pattern 12
	 * honest-disclosure 15th-instance — sofia-sip-library-feature-absence sub-pattern
	 * 2nd-instance, repeats compactheaders 12th-instance template at commit 62f7f23):
	 * chan_sip strips trailing semicolons from URI user-field post-parse via
	 * parse_uri_legacy_check at chan_sip.c:14818-14828 (called from 7 use sites at
	 * L14847+L14988+L15743+L16369+L16397+L16819+L17225 — Contact/From/Request-URI
	 * parsing paths). Default FALSE per sip.h:216 verbatim DEFAULT_LEGACY_USEROPTION_PARSING.
	 * sofia-sip ZERO native URI per-component-rewrite gate (verified in sofia-sip
	 * url_t parser API — no post-parse semicolon-strip hook). chan_sofia delegates
	 * URI parsing to sofia-sip below per-component-rewrite point = NO interception.
	 * PARSE-COMPAT-ONLY: field parsed + stored + reload-clean for chan_sip drop-in
	 * compat; full-feature URI-rewrite DEFERRED until upstream sofia-sip exposes
	 * hook OR upstream patch. Most operators don't need this flag — chan_sofia URI
	 * parsing is already RFC 3261-compliant via sofia-sip. */
	int legacy_useroption_parsing;
	/* post-T56 shrinkcallerid [general] parity (2026-04-28, Pattern 12 honest-disclosure
	 * 18th-instance — behavior-change-from-chan_sofia-baseline sub-pattern 3rd-instance,
	 * pattern proven via 3-instance repeat: maxcallbitrate 14th 1st + parkinglot 16th
	 * 2nd + this 18th 3rd): chan_sip parity at chan_sip.c:30001-30009 verbatim
	 * [general] parser ast_true/ast_false tri-state + LOG_WARNING-on-invalid + L29526
	 * default-init = 1 + L726 static int global_shrinkcallerid + 4 use sites
	 * L16080+L16196+L17103+L17252 — ast_is_shrinkable_phonenumber gate strips leading
	 * '+' and parens from CID phone numbers. callerid.h:233+249 ast_shrink_phone_number
	 * + ast_is_shrinkable_phonenumber core APIs. Default 1 (TRUE) per chan_sip drop-in
	 * critical default — operators upgrading retain identical CID-normalization behavior;
	 * prior chan_sofia silent-baseline-no-normalization replaced. Operators preferring
	 * silent-baseline restoration set [general] shrinkcallerid=no explicitly. Bounded-
	 * impact: only CID phone-number strings affected (non-phone-number CIDs like
	 * "John Doe" unchanged regardless of setting via ast_is_shrinkable_phonenumber gate). */
	int shrinkcallerid;
	/* post-T56 notifyhold [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:29448 verbatim default-init FALSE + L29691-29692 verbatim
	 * [general] parser ast_true + L9477-9478 verbatim sip_peer_hold gate
	 * (peer-level on-hold counter tracking — NOT AMI Hold event gate; AMI
	 * Hold at L9480 is gated on sip_cfg.callevents — DIFFERENT chan_sip flag).
	 * chan_sofia equivalent peer->onHold counter atomic update at
	 * chan_sofia.c:4471-4473 (post-T56 call-limit parity SS2 R10) — wire-in
	 * gate on this `if (sofia_cfg.notifyhold)`. AMI Hold at chan_sofia.c:4521
	 * REMAINS UNCONDITIONAL (matches chan_sip callevents=yes typical case;
	 * chan_sip parity HOLDS). Default 0 (FALSE) per chan_sip drop-in. Operator-
	 * honest disclosure: chan_sofia operators using sip show inuse / SIPshowpeer
	 * onHold see counter freeze when notifyhold=no — minor counter-tracking
	 * divergence from prior chan_sofia always-tracked baseline; chan_sip-drop-in
	 * correction toward chan_sip-faithful semantics. production
	 * sofia.conf has notifyhold=yes — counter tracking unchanged for that
	 * deployment. */
	int notifyhold;
	/* post-T56 notifyringing [general] parity (2026-04-28, Pattern 12 honest-disclosure
	 * 19th-instance — chan_sofia-architectural-divergence sub-pattern 2nd-instance,
	 * repeats subscribemwi 17th-instance template at commit 3ee3a6c): chan_sip parity
	 * at chan_sip.c:29689-29690 verbatim [general] parser ast_true + L29446 verbatim
	 * default-init via DEFAULT_NOTIFYRINGING + sip.h:206 verbatim define = TRUE +
	 * 2 use sites L13452+L13550 inside cb_extensionstate (BLF/dialog-info presence
	 * emission callback — flag gates "early" vs "confirmed" presence state when
	 * extension RINGING). PARSE-COMPAT-ONLY ship — chan_sofia presence/dialog-info
	 * NOTIFY infrastructure ABSENT (T55 subscribecontext data-infrastructure pivot
	 * deferred per Pattern 12 4th-instance); flag effect-deferred until presence-
	 * NOTIFY infrastructure landed. Default 1 (TRUE) per chan_sip drop-in critical
	 * default. chan_sofia silent baseline preserved (no presence emission today
	 * regardless of flag). Future-fix path: implement presence/dialog-info subscription
	 * handler (~150-300 LoC follow-up if operator demand surfaces). */
	int notifyringing;
	/* post-T56 dynamic_exclude_static [general] parity (2026-04-28): security
	 * hardening flag preventing dynamic peers from claiming static peer names by
	 * Contact-IP spoofing. chan_sip parity at chan_sip.c:29644-29645 verbatim
	 * dual-key parser dynamic_exclude_static OR dynamic_excludes_static (variant
	 * spellings) + L29481 verbatim default-init = 0 + L759 verbatim static int
	 * global_dynamic_exclude_static + L29164 verbatim peer-build-time mechanism:
	 * when peer has static addr (ast_sockaddr non-null) + flag set → ast_append_ha
	 * (deny, peer->addr, sip_cfg.contact_ha) appends static peer addr to GLOBAL
	 * contact_ha as DENY rule. Subsequent REGISTER processing rejects Contact
	 * pointing to static-peer-IP via existing contact_ha apply infrastructure
	 * (chan_sip.c:15043-15044; chan_sofia mirror at sofia_process_register
	 * L5398-5405 from commit e9d6cb1). chan_sofia revised mechanism leverages
	 * existing contact_ha infrastructure more elegantly than dispatch's original
	 * REGISTER-rejection plan. Default 0 (FALSE) chan_sip drop-in. */
	int dynamic_exclude_static;
	/* post-T56 autocreatepeer [general] parity (2026-04-28, Pattern 12 honest-disclosure
	 * 20th-instance — chan_sofia-architectural-divergence sub-pattern 3rd-instance PROVEN
	 * at 3-instance repeat: subscribemwi 17th 1st + notifyringing 19th 2nd + this 20th
	 * 3rd; sub-pattern stability validated at N=3 PROVEN per per-sub-pattern instance-
	 * count threshold discipline established at notifyringing 19th-instance):
	 * chan_sip parity at chan_sip.c:29752-29753 verbatim [general] parser ast_true +
	 * L29468 verbatim default-init via DEFAULT_AUTOCREATEPEER + sip.h:209 verbatim
	 * define DEFAULT_AUTOCREATEPEER FALSE + L15880-15883 verbatim use site (REGISTER
	 * unknown peer + autocreatepeer set → temp_peer(name) auto-creation + ao2_t_link).
	 * chan_sip.c:15807 verbatim alwaysauthreject + !autocreatepeer interaction: when
	 * alwaysauthreject set + !autocreatepeer + unknown peer → bogus_peer challenge
	 * (matches chan_sofia alwaysauthreject c293e54 sofia_send_auth_challenge behavior).
	 * PARSE-COMPAT-ONLY ship — chan_sofia design refuses to auto-create unknown peers
	 * (security-stronger by alwaysauthreject c293e54 default behavior). Default 0
	 * (FALSE) per sip.h:209 chan_sip drop-in. Future-fix path: implement
	 * sofia_create_temp_peer helper if operator demand surfaces — likely-never-needed
	 * (chan_sip default also FALSE; security-anti-pattern). */
	int autocreatepeer;
	/* post-T56 preferred_codec_only [general] parity (2026-04-28): default codec-
	 * offer-list narrowing inherited by sofia_peer_alloc when peer omits the key.
	 * chan_sip parity at chan_sip.c:29863-29864 verbatim global_flags[1] init.
	 * Default 0 (FALSE) per chan_sip drop-in (no narrowing — full codec list). */
	int default_preferred_codec_only;
	/* post-T56 ignoresdpversion [general] parity (2026-04-28, Pattern 12 23rd-instance
	 * chan_sofia-architectural-divergence sub-pattern 4th-instance post-PROVEN): default
	 * SDP version-bypass flag inherited by sofia_peer_alloc when peer omits the key.
	 * chan_sip parity at chan_sip.c:29539 verbatim default-init via ast_clear_flag(
	 * &global_flags[1], SIP_PAGE2_IGNORESDPVERSION). Default 0 (FALSE) per chan_sip
	 * drop-in. PARSE-COMPAT-ONLY — chan_sofia processes every SDP unconditionally;
	 * flag has no behavioral effect (KNOWN LIMITATION documented in sample.conf). */
	int default_ignoresdpversion;
	/* post-T56 promiscredir [general] parity (2026-04-28, Pattern 12 29th-instance
	 * chan_sofia-architectural-divergence sub-pattern 9th-sub-instance post-PROVEN):
	 * default 3xx redirect honor flag inherited by sofia_peer_alloc. Default 0
	 * (FALSE) per chan_sip drop-in BSS static-zero of global_flags[0] SIP_PROMISCREDIR
	 * bit. PARSE-COMPAT-ONLY (chan_sofia nua_r_redirect handler ABSENT). */
	int default_promiscredir;
	/* post-T56 autoframing [general] parity (2026-04-28, Pattern 12 31st-instance
	 * chan_sofia-architectural-divergence sub-pattern 11-sub-instances post-PROVEN):
	 * default codec ptime auto-detection flag inherited by sofia_peer_alloc. Default
	 * 0 (FALSE) per chan_sip drop-in BSS static-zero of global_autoframing. PARSE-
	 * COMPAT-ONLY (chan_sofia sofia_parse_sdp ptime gate not wired today; future-
	 * fix path documented in sample.conf). */
	int default_autoframing;
	/* post-T56 faxdetect [general] multi-mode parity (2026-04-28): default
	 * fax CNG/T.38 detection mode inherited by sofia_peer_alloc. Default NONE
	 * (0) per chan_sip drop-in BSS static-zero of global_flags[1] FAX_DETECT
	 * bits. Current wire-in handles DSP CNG detection and peer T.38 reINVITE
	 * detection when configured. */
	int default_faxdetect_mode;
	/* post-T56 Task #8 T.38 fax UDPTL parity SS2 (2026-04-28, skeleton +
	 * lifecycle): T38FaxMaxDatagram global override mirrors chan_sip.c:780
	 * verbatim semantic + chan_sip.c:29525 sentinel `-1` init (means "use
	 * 200-byte built-in"). Inherited by sofia_peer_alloc into
	 * peer->t38_maxdatagram when peer omits the t38pt_udptl maxdatagram=N
	 * sub-option. SS3a SDP outbound emit consumes
	 * `pvt->t38_maxdatagram > 0 ? pvt->t38_maxdatagram :
	 * SOFIA_T38_MAXDATAGRAM_BUILTIN` for `a=T38FaxMaxDatagram:` line. */
	int default_t38_maxdatagram;
	/* post-T56 timerb [general] parity (2026-04-28, Pattern 16 sofia-sip-native
	 * 11th-instance NTATAG_SIP_T1X64): default RFC 3261 Timer B inherited by
	 * sofia_peer_alloc. Default 32000ms (64 * 500ms T1) per chan_sip drop-in
	 * (chan_sip.c:29522 verbatim global_timer_b = 64 * DEFAULT_TIMER_T1). Wire-in
	 * via TAG_IF(default_timer_b, NTATAG_SIP_T1X64(default_timer_b)) at nua_create;
	 * per-peer dynamic override deferred per t1min ac8d1ef precedent. */
	int default_timer_b;
	/* post-T56 timert1 [general] parity (2026-04-28, Pattern 16 sofia-sip-native
	 * 7th-instance REWIRED): default RFC 3261 T1 retransmission interval (ms)
	 * inherited by sofia_peer_alloc. Default 500ms (DEFAULT_TIMER_T1) per chan_sip
	 * drop-in (chan_sip.c:29521 verbatim global_t1 = DEFAULT_TIMER_T1; sip.h:89
	 * verbatim 500ms). Wire-in via REWIRED NTATAG_SIP_T1(default_timer_t1) at
	 * nua_create — fixes pre-this-commit latent bug where NTATAG_SIP_T1 received
	 * sofia_cfg.t1min (100ms) instead of the T1 VALUE (500ms). Per-peer dynamic
	 * override deferred per Pattern 12 sub-pattern 3rd-instance (NTATAG_*_T1
	 * family deferral: t1min ac8d1ef + timerb a2e16b7 + this timert1). */
	int default_timer_t1;
	/* post-T56 allowoverlap [general] parity (2026-04-28, Option A FULL WIRE-IN
	 * 3 sites): default tri-state overlap-dial mode inherited by sofia_peer_alloc.
	 * Default YES (SOFIA_OVERLAP_YES = 1) per chan_sip drop-in critical default
	 * (chan_sip.c:29479 verbatim `ast_set_flag(&global_flags[1], SIP_PAGE2_ALLOW
	 * OVERLAP_YES);` with chan_sip trailing comment "Default for all devices: Yes"). Operators upgrading from
	 * chan_sip retain identical overlap-dialing behavior baseline. Wire-in active
	 * at 3 sites: sofia_process_invite ast_canmatch_extension MATCHMORE 484 emit
	 * (mirrors chan_sip.c:23930-23934 + L16491-16497 inbound flow) + sofia_indicate
	 * AST_CONTROL_INCOMPLETE case (mirrors chan_sip.c:7661-7669 dialplan-driven
	 * Incomplete app path) + nua_r_invite 484 status special-case (mirrors chan_
	 * sip.c:22508-22518 outbound 484 response handling). DTMF mode parsed + stored
	 * + displayed but treated as fall-through per chan_sip own design (chan_sip.c
	 * :23937-23943 verbatim dialplan-deferral comment). */
	int default_allowoverlap_mode;
	/* post-T56 progressinband [general] parity (2026-04-28, Pattern 12 24th-instance
	 * chan_sofia-architectural-divergence sub-pattern 5th-instance partial-feature-
	 * parity flavor): default tri-state SDP early-media in-band audio control inherited
	 * by sofia_peer_alloc. Values per SOFIA_PROG_INBAND_NEVER/NO/YES macros. Default
	 * NEVER per chan_sip drop-in (ast_clear_flag at chan_sip handle_common_options
	 * leaves all bits = 0 = NEVER). Option B partial wire-in: NEVER + YES match
	 * chan_sip semantic exactly; NO degrades to NEVER (KNOWN LIMITATION — chan_sofia
	 * lacks SIP_PROGRESS_SENT tracking infrastructure). */
	int default_progressinband;
	/* post-T56 subscribe_network_change_event [general] parity (2026-04-28, Pattern 12
	 * 25th-instance + chan_sofia-architectural-divergence sub-pattern 6th-instance
	 * post-PROVEN): chan_sip-parity flag controlling AST_EVENT_NETWORK_CHANGE
	 * subscription for re-register on network IP change. chan_sip parity at
	 * chan_sip.c:30017-30024 verbatim [general] parser tri-state ast_true/ast_false
	 * + LOG_WARNING-on-invalid + chan_sip.c:29314 verbatim default-init = 1 (TRUE
	 * — note: chan_sip declares as LOCAL var in reload_config function scope, NOT
	 * sip_cfg global; chan_sofia persists as sofia_cfg member for parse-compat +
	 * display purposes — operationally equivalent for PARSE-COMPAT-ONLY ship intent)
	 * + chan_sip.c:30032 verbatim use site (network_change_event_subscribe / unsubscribe
	 * gating) + chan_sip.c:15507 ast_event_subscribe(AST_EVENT_NETWORK_CHANGE, ...).
	 * gabpbx-core AST_EVENT_NETWORK_CHANGE = 0x09 at event_defs.h:56. PARSE-COMPAT-
	 * ONLY ship — chan_sofia delegates network-change handling to sofia-sip
	 * sres_resolver (transport layer rebinds on IP change automatically) + per-peer
	 * dnsmgr per c0e26b0 (peer hostname tracking + sofia_on_dns_update_peer callback
	 * → peer->src_addr update + AMI DnsManagerUpdate emit). chan_sip's manual
	 * AST_EVENT_NETWORK_CHANGE subscription not applicable to chan_sofia architecture
	 * (sofia-sip + dnsmgr stack absorbs the responsibility). chan_sofia surpass
	 * IN-SCOPE per R11: sip show settings display added at CLI where chan_sip silent
	 * (chan_sip displays only LOG_WARNING at parse-time on invalid; no runtime CLI
	 * exposure). Default 1 (TRUE) per chan_sip drop-in. */
	int subscribe_network_change_event;
	/* post-T56 rtsavesysname [general] parity (2026-04-28, REAL OPERATOR DRIVER on
	 * production sofia.conf rtsavesysname=yes silently-ignored prior to this commit; finally
	 * honored on next reload + Pattern 12 26th-instance behavior-change-from-chan_sofia-
	 * baseline-disclosure sub-pattern 5th-sub-instance): chan_sip-parity flag for
	 * multi-server gabpbx realtime deployments. When set + ast_config_AST_SYSTEM_NAME
	 * non-empty, ast_update_realtime calls include "regserver", AST_SYSTEM_NAME pair
	 * tracking which gabpbx instance has the registration. chan_sip parity at
	 * chan_sip.c:29590-29591 verbatim [general] parser ast_true + sip.h:686 verbatim
	 * field `int rtsave_sysname` (doxygen tag G: Save system name at registration?)
	 * + chan_sip.c:19440 verbatim "Save sys. name" sip show settings display +
	 * canonical Asterisk chan_sip.c:5103-
	 * 5151 canonical realtime_update_peer wire-in pattern (Asterisk-upstream pattern).
	 * IMPORTANT NOTE: active chan_sip.c FuturePBX fork has DROPPED the realtime_update_
	 * peer wire-in entirely — only parser + display present (rtsavesysname is currently
	 * a DEAD flag in active chan_sip; canonical wire-in preserved only in canonical Asterisk chan_sip.c
	 * backup). chan_sofia restores canonical Asterisk-upstream behavior — chan_sofia
	 * parity-with-canonical-source-where-current-chan_sip-fork-regressed flavor.
	 * Default 0 (FALSE) per chan_sip drop-in BSS static-zero (chan_sip has no explicit
	 * default-init line; chan_sofia uses explicit-init = 0 disciplined pattern).
	 * Pattern 12 26th-instance behavior-change-from-chan_sofia-baseline-disclosure
	 * sub-pattern 5th-sub-instance (joins 384 maxcallbitrate + "default" parkinglot
	 * + cid_name alias + useragent verbatim default + this restored-canonical-behavior).
	 * Wire-in at 5 sites at sofia_process_register paths via inline 2-var setup
	 * (sysname + syslabel) + appended `syslabel, sysname` pair to ast_update_realtime
	 * varargs (NULL-key pair = no-op when not active). */
	int rtsave_sysname;
	/* post-T56 rtupdate [general] parity (2026-04-28, REAL OPERATOR DRIVER on production
	 * sofia.conf rtupdate=yes commented operator-aware): chan_sip-parity flag gating
	 * whether peer registration changes propagate to realtime DB via ast_update_realtime
	 * calls. Default 1 (TRUE) per chan_sip drop-in (chan_sip.c:29480 verbatim explicit
	 * default-init NOT BSS static-zero — chan_sofia explicit-init = 1 disciplined
	 * pattern). chan_sip parity at chan_sip.c:29592-29593 verbatim [general] parser
	 * ast_true + sip.h:685 verbatim field declaration (doxygen tag G: Update database
	 * with registration data for peer?) + chan_sip.c:19438 verbatim "Update: %s" sip
	 * show settings wording + 6 use sites L14630+L14743+L15094+L22080+L27569+L29221
	 * (active chan_sip wire-in CONFIRMED — NOT canonical-vs-current-fork-divergence
	 * class like rtsavesysname). Use case: cached-realtime operators want to skip DB
	 * write churn (peer state cached in memory; DB write per registration unnecessary).
	 * Wire-in via Option C combined-gate at 3 chan_sofia `if (peer->is_realtime)`
	 * blocks → `if (peer->is_realtime && sofia_cfg.peer_rtupdate)` mirroring chan_sip.c
	 * :14630+L14743 verbatim combined-gate pattern; covers 5 ast_update_realtime
	 * sites. rtupdate=no skips ALL realtime DB writes regardless of rtsavesysname. */
	int peer_rtupdate;
	/* Phase 1 bounded REGISTER realtime-DB-write offload pool (kill-switch, default OFF). */
	int register_pool;          /* offload the realtime REGISTER DB writes to a bounded pool */
	int register_pool_workers;  /* lane count; 0 = auto = clamp(ncpu/2+1, 2, 16) */
	/* post-T56 rtcachefriends [general] parity (2026-04-28, REAL OPERATOR DRIVER on
	 * production sofia.conf rtcachefriends=yes silently-ignored prior to this commit;
	 * finally honored on next reload as parse-clean migration matching chan_sofia
	 * intrinsic baseline + Pattern 12 27th-instance chan_sofia-architectural-
	 * divergence sub-pattern 7th-sub-instance post-PROVEN): chan_sip-parity flag for
	 * cache-realtime-as-static behavior. chan_sip semantic: when set, realtime
	 * peers are kept in memory after first lookup like static peers (speeds
	 * subsequent lookups; reduces DB churn; required for qualify-on-realtime per
	 * chan_sip.c:29046-29051). chan_sip parity at chan_sip.c:29588-29589 verbatim
	 * [general] parser ast_set2_flag(global_flags[1], ast_true(v->value),
	 * SIP_PAGE2_RTCACHEFRIENDS) + sip.h:304 verbatim flag bit (1<<0) (doxygen tag
	 * GP: Should we keep RT objects in memory for extended time?) + chan_sip.c:19437
	 * verbatim "Cache Friends:" sip show settings wording + 15+ active use sites at
	 * L5285+L5622+L5624+L15010+L15061+L15081+L18272+L18276+L18343+L18365+L28585+
	 * L28619+L29046+L29051+L29310 (active chan_sip wire-in CONFIRMED — chan_sip-
	 * parity-NOT-fork-regression-class verified via backup-fork verification;
	 * canonical Asterisk chan_sip.c has same wire-in pattern). PARSE-COMPAT-ONLY ship — chan_sofia
	 * ao2 peer registry already keeps ALL peers (static + realtime) in memory after
	 * first ao2_link; there's no "destroy after lookup" path in chan_sofia. chan_sofia
	 * INTRINSIC behavior matches chan_sip rtcachefriends=YES regardless of flag value.
	 * chan_sofia-architectural-divergence sub-pattern 7th-sub-instance post-PROVEN
	 * (joins subscribemwi 17th + notifyringing 19th + autocreatepeer 20th +
	 * ignoresdpversion 23rd + progressinband 24th + subscribe_network_change_event
	 * 25th + this 27th — sub-pattern stability strongly validated past N=3 PROVEN
	 * threshold). KNOWN LIMITATION: rtcachefriends=no operators wanting destroy-
	 * realtime-peer-after-each-lookup get parse-clean migration but chan_sofia
	 * infrastructure ABSENT (always caches via ao2_link); future-fix path likely
	 * never needed (most operators want caching for performance). Default 0 (FALSE)
	 * per chan_sip drop-in BSS static-zero. */
	int rtcachefriends;
	/* post-T56 rtautoclear [general] parity (2026-04-28, Pattern 12 28th-instance
	 * chan_sofia-architectural-divergence sub-pattern 8th-sub-instance post-PROVEN):
	 * chan_sip-parity flag for cache-realtime-peer-auto-clear-after-expire behavior.
	 * TWO-PIECE storage architecture per chan_sip parity (chan_sip uses sip_cfg.
	 * rtautoclear int seconds + SIP_PAGE2_RTAUTOCLEAR flag bit; chan_sofia int-field
	 * idiom for both pieces). chan_sip semantic: when flag set + peer is realtime,
	 * schedule peer expiration via AST_SCHED_REPLACE_UNREF after rtautoclear*1000 ms;
	 * on fire, ao2_unlink/destroy peer from sip_peers registry. chan_sip parity at
	 * chan_sip.c:29652-29659 verbatim two-phase [general] parser (atoi+i>0 sets seconds
	 * else i=0; flag=numeric>0 OR ast_true("yes")) + chan_sip.c:29477 verbatim explicit
	 * default-init = 120 seconds + sip.h:305 verbatim flag bit (1<<1) (doxygen tag GP:
	 * Should we clean memory from peers after expiry?) + sip.h:688 verbatim int field
	 * + chan_sip.c:19441 verbatim "Auto Clear: %d (%s)" sip show settings TWO-PIECE
	 * display + 3 active use sites at L5624 (peer-flag-propagation) + L5625-5626
	 * (AST_SCHED_REPLACE_UNREF schedule peer expire) + L14684 (re-check at expire_
	 * register call). Backup-fork verification CONFIRMED chan_sip-parity-NOT-fork-
	 * regression-class (canonical Asterisk chan_sip.c has same wire-in pattern at corresponding lines).
	 * PARSE-COMPAT-ONLY ship — chan_sofia ao2 peer registry has NO peer-level auto-
	 * clear infrastructure (sofia_expire_contacts_cb is per-AOR per-CONTACT expiry NOT
	 * peer-level; chan_sofia peers persist in ao2 registry until module reload). Joins
	 * sub-pattern 8-sub-instance series (subscribemwi 17th + notifyringing 19th +
	 * autocreatepeer 20th + ignoresdpversion 23rd + progressinband 24th-partial +
	 * subscribe_network_change_event 25th + rtcachefriends 27th + this 28th) — all
	 * post-PROVEN N=3 threshold. KNOWN LIMITATION rtautoclear=N OR yes-set operators
	 * get parse-clean migration but chan_sofia continues caching realtime peers until
	 * reload regardless. Future-fix path: implement peer-level scheduler infrastructure
	 * (peer->autoclear_sched field + sofia_autoclear_cb scheduler callback +
	 * AST_SCHED_REPLACE_UNREF wire-in at sofia_update_peer_contacts; ~50-100 LoC if
	 * operator demand surfaces). TWO defaults per chan_sip drop-in: sofia_cfg.
	 * rtautoclear = 120 (seconds) + sofia_cfg.rtautoclear_enabled = 0 (flag DISABLED). */
	int rtautoclear;
	int rtautoclear_enabled;
	/* post-T56 domainsasrealm [general] parity (2026-04-28, FULL WIRE-IN per Enginer
	 * R6 Option B verdict — chan_sofia HAS domain_list infrastructure already from
	 * T46.2 work; full chan_sip-faithful parity achievable): chan_sip-parity flag for
	 * multi-tenant SIP servers with domain-specific auth realms. When set + domain_list
	 * non-empty, use From or To header domain (if it matches a configured domain) as
	 * auth realm in WWW-Authenticate digest challenge; falls back to sofia_cfg.realm.
	 * chan_sip parity at chan_sip.c:29572-29573 verbatim [general] parser ast_true
	 * + chan_sip.c:29461 verbatim default-init via DEFAULT_DOMAINSASREALM (FALSE per
	 * sip.h:205) + sip.h:711 verbatim int field + chan_sip.c:11645-11673 verbatim
	 * get_realm function pattern (check From → check To → fallback) + chan_sip.c:19293
	 * verbatim "Use domains as realms" sip show settings wording. Backup-fork
	 * verification CONFIRMED chan_sip-parity-NOT-fork-regression-class (canonical Asterisk chan_sip.c
	 * has same wire-in at L11506+L19092+L29200+L29311-29312). chan_sofia leverages
	 * existing domain_list infrastructure from T46.2 work (chan_sofia.c:750
	 * AST_LIST_HEAD_STATIC + L5539-5559 func_sofia_check_sipdomain walker pattern) —
	 * Pattern 5 helper #29 sofia_get_realm_for_dialog extracted at 3 auth-challenge
	 * callsites (L6192 lockuseragent + L6224 REGISTER unknown-peer + L6790 MOH).
	 * chan_sofia helper-architecture-advantage 15th-instance (centralized realm-
	 * resolution NEW dimension — chan_sip get_realm is single-call-site at p->realm
	 * pre-resolution; chan_sofia centralizes at 3 auth-challenge callsites for the
	 * same chan_sip-faithful semantic). Default 0 (FALSE) per chan_sip drop-in. */
	int domainsasrealm;
	/* post-T56 allowexternaldomains [general] parity (2026-04-28, FULL WIRE-IN +
	 * Pattern 5 helper #30 + retroactive-refactor): chan_sip-parity flag for
	 * multi-tenant SIP servers gating INVITE/REFER acceptance to non-local SIP
	 * domains; security against domain-traversal attacks. When clear + domain_list
	 * non-empty + Request-URI/Refer-To domain not in domain_list → reject 403
	 * Forbidden. chan_sip parity at chan_sip.c:29867-29868 verbatim [general] parser
	 * ast_true + chan_sip.c:29441 verbatim default-init via DEFAULT_ALLOW_EXT_DOM
	 * (TRUE PERMISSIVE per sip.h:203) + sip.h:697 verbatim int field + chan_sip.c:
	 * 16410-16425 verbatim handle_request use site (gates non-local INVITE/REFER) +
	 * chan_sip.c:24719 verbatim REFER target check + chan_sip.c:19294 verbatim
	 * "Call to non-local dom.: %s" sip show settings wording + chan_sip.c:30056-
	 * 30058 verbatim special-case auto-set when domain_list empty (operator-friendly
	 * safety net). Backup-fork verification CONFIRMED chan_sip-parity-NOT-fork-
	 * regression-class. chan_sofia FULL WIRE-IN leveraging existing domain_list
	 * infrastructure from T46.2 work + sofia_get_realm_for_dialog helper #29 from
	 * 5fbee76 — Pattern 5 helper #30 sofia_check_sip_domain extracted as generic
	 * walker; retroactive-refactor of func_sofia_check_sipdomain (T46.2) +
	 * sofia_get_realm_for_dialog (5fbee76) to use new helper eliminates 3-site
	 * walker pattern duplication. chan_sofia helper-architecture-advantage 16th-
	 * instance NEW DIMENSION centralized-domain-validation across 4 callsites
	 * (2 INVITE/REFER gate + 1 realm + 1 dialplan). Default 1 (TRUE PERMISSIVE)
	 * per chan_sip drop-in. */
	int allow_external_domains;
	/* post-T56 autodomain [general] parity (2026-04-28, FULL WIRE-IN + Pattern 5
	 * helper #31 + retroactive-refactor + chan_sofia helper-architecture-advantage
	 * 17th-instance NEW DIMENSION centralized-domain-list-mutation): chan_sip-parity
	 * flag for auto-adding system listening-addresses + FQDN to domain_list at
	 * module-load. When set, sofia_load_config conclusion auto-adds bindaddr +
	 * tlsbindaddr + wsbindaddr + externaddr + gethostname() FQDN via Pattern 5
	 * helper #31 sofia_domain_list_add. chan_sip parity at chan_sip.c:29869-29870
	 * verbatim [general] parser ast_true (LOCAL var auto_sip_domains in reload_config
	 * function-scope; chan_sofia mirror = sofia_cfg member for parse-compat + display
	 * + auto-add) + chan_sip.c:29311 verbatim local-var default-init = FALSE +
	 * chan_sip.c:30295-30340+ verbatim COMPREHENSIVE auto-add list (bindaddr + TCP
	 * local_address + TLS local_address + externaddr + externhost + gethostname()
	 * FQDN; all added via add_sip_domain SIP_DOMAIN_AUTO type marker). chan_sip CLI
	 * ABSENT — does NOT display autodomain at sip show settings (Pattern 14 source-
	 * correction caught at R-ACK). chan_sofia surpass IN-SCOPE: sip show settings
	 * 14th field display where chan_sip silent. Backup-fork verification CONFIRMED
	 * chan_sip-parity-NOT-fork-regression-class (active chan_sip + canonical Asterisk chan_sip.c
	 * both have wire-in at L30295+/L30033+). chan_sofia leverages existing
	 * domain_list infrastructure from T46.2 work + sofia_check_sip_domain helper #30
	 * + sofia_get_realm_for_dialog helper #29 + Pattern 5 helper #31 sofia_domain_
	 * list_add 6-callsite extraction (5 NEW auto-add sites + 1 retroactive existing
	 * domain= parser). Default 0 (FALSE) per chan_sip drop-in. */
	int autodomain;
	/* post-T56 matchexternaddrlocally [general] parity (2026-04-28, PARSE-COMPAT-ONLY
	 * + Pattern 12 30th-instance + chan_sofia-architectural-divergence sub-pattern
	 * 10th-sub-instance post-PROVEN + chan_sofia surpass CLI 16th field): chan_sip-
	 * parity flag for NAT hairpin-edge-case (operators with externaddr falling within
	 * localnet range avoid externaddr substitution when our IP is also local). chan_sip
	 * semantic at chan_sip.c:4015-4024: when set + localnet ACL configured + our IP
	 * inside localnet → don't substitute externaddr (treat our IP as local; useful
	 * when externaddr falls within localnet range; prevents hairpin-NAT confusion).
	 * Default 0 (FALSE) per sip.h:210 verbatim DEFAULT_MATCHEXTERNADDRLOCALLY. chan_sip
	 * parity at chan_sip.c:29954-29955 verbatim [general] dual-key parser OR-chained
	 * acceptance (matchexternaddrlocally + matchexterniplocally — BOTH spellings parsed
	 * identically) + chan_sip.c:29531 verbatim default-init via DEFAULT_MATCHEXTERNADDRLOCALLY
	 * macro + sip.h:701 verbatim int field. Backup-fork verification (canonical Asterisk chan_sip.c
	 * L4009 + L29270 + L29692-29693) CONFIRMED chan_sip-parity-NOT-fork-regression-class.
	 * **Architectural divergence**: chan_sofia sofia_should_use_externaddr signature at
	 * chan_sofia.c:1471-1478 takes peer_addr ONLY (compares peer against localnet);
	 * chan_sip's L4024 logic compares OUR IP (us) against localnet — DIFFERENT
	 * parameter semantic. PARSE-COMPAT-ONLY ship: parse + store + display but NO
	 * behavioral wire-in (full chan_sip parity requires extending sofia_should_use_
	 * externaddr signature OR adding gate at sofia_resolve_ourip; ~25-35 LoC follow-up
	 * if operator demand surfaces). chan_sofia surpass IN-SCOPE: sip show settings
	 * 16th field display where chan_sip CLI ABSENT (verified via grep — chan_sip does
	 * NOT display matchexternaddrlocally at sip show settings; typical NAT operator-
	 * edge-case flag pattern). Joins sub-pattern 10-sub-instance series (subscribemwi
	 * 17th + notifyringing 19th + autocreatepeer 20th + ignoresdpversion 23rd +
	 * progressinband 24th-partial + subscribe_network_change_event 25th + rtcachefriends
	 * 27th + rtautoclear 28th + promiscredir 29th + this 30th — all post-PROVEN N=3
	 * threshold). KNOWN LIMITATION matchexternaddrlocally=yes operators get parse-
	 * clean migration but chan_sofia continues to substitute externaddr regardless. */
	int matchexternaddrlocally;
	/* post-T56 rtp-timeout bundle [general] parity (2026-04-28): 3-key bundle defaults
	 * inherited by sofia_peer_alloc when peer omits the keys. chan_sip parity at
	 * chan_sip.c:721-723 verbatim global_rtptimeout/holdtimeout/keepalive static
	 * fields. Default 0 (disabled) per chan_sip drop-in (no RTP-timeout enforcement). */
	int default_rtptimeout;
	int default_rtpholdtimeout;
	int default_rtpkeepalive;
	/* post-T56 tos/cos bundle 8-key [general] parity (2026-04-28): QoS markings
	 * for SIP signaling + RTP audio/video/text streams. chan_sip parity at
	 * chan_sip.c:730-737 verbatim 8 globals (global_tos_sip/audio/video/text +
	 * global_cos_sip/audio/video/text) all unsigned int + L29893-29917 verbatim
	 * 8 [general] parsers ast_str2tos/ast_str2cos + LOG_WARNING-on-invalid +
	 * L5888 verbatim use site ast_rtp_instance_set_qos(dialog->rtp,
	 * global_tos_audio, global_cos_audio, "SIP RTP"). gabpbx-core API at
	 * rtp_engine.h:1311 ast_rtp_instance_set_qos(instance, tos, cos, desc).
	 *
	 * tos_sip wire-in via Pattern 16 sofia-sip-native 9th-instance: TPTAG_TOS
	 * at tport_tag.h:319 — passed to nua_create at sofia listener-create-time;
	 * sofia-sip applies via setsockopt at TCP/UDP transport level. cos_sip
	 * Pattern 12 sub-pattern sofia-sip-library-feature-absence (TPTAG_COS
	 * verified ABSENT in tport_tag.h grep) — PARSE-COMPAT-ONLY ship.
	 *
	 * tos/cos audio/video full wire-in via ast_rtp_instance_set_qos at
	 * sofia_rtp_init. tos/cos text PARSE-COMPAT-ONLY (chan_sofia text-RTP
	 * infrastructure ABSENT — no pvt->trtp). Default 0 (no QoS markings)
	 * per chan_sip drop-in. production sofia.conf line tos_sip=cs3 +
	 * tos_audio=ef + tos_video=af41 silently-ignored prior to this commit;
	 * finally honored on next reload (REAL OPERATOR DRIVER). */
	unsigned int tos_sip;
	unsigned int tos_audio;
	unsigned int tos_video;
	unsigned int tos_text;
	unsigned int cos_sip;
	unsigned int cos_audio;
	unsigned int cos_video;
	unsigned int cos_text;
	/* post-T56 useragent [general] parity (2026-04-28): User-Agent header value
	 * advertised in outbound SIP requests + Server header in responses. Sized
	 * AST_MAX_EXTENSION verbatim chan_sip.c:740 (static char global_useragent[
	 * AST_MAX_EXTENSION]). Default-initialized at sofia_load_config init via
	 * snprintf "%s %s", DEFAULT_USERAGENT, ast_get_version(). Operator
	 * customization via [general] useragent= directive (chan_sip.c:29574-29575
	 * verbatim parser shape). Wired at sofia_create_root_thread nua_create via
	 * TAG_IF + SIPTAG_USER_AGENT_STR (Pattern 16 sofia-sip-native 10th-instance
	 * DOUBLE-DIGIT MILESTONE — sofia-sip emits header on every outbound request
	 * automatically once tag set on nua handle; chan_sofia helper-architecture-
	 * advantage 13th-instance: single emit-site vs chan_sip 5-site add_header
	 * duplication 11132/11307/12986/14331/+others). REAL OPERATOR DRIVER:
	 * production sofia.conf useragent=a carrier softswitch silently-ignored
	 * prior to this commit; finally honored on next reload. */
	char useragent[AST_MAX_EXTENSION];
		int default_qualify;
		int default_qualifyfreq;
		int default_qualifytimeout;
		format_t capability;
		struct ast_codec_pref prefs;
};

extern struct sofia_config sofia_cfg;

#endif /* CHAN_SOFIA_INTERNAL_H */
