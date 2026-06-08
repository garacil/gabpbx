/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * GABPBX was first created in 2008 by
 * Germán Luis Aracil Boned <garacilb@gmail.com>.
 *
 * GABPBX as a project is based on Asterisk 1.8 and was later updated
 * to the final stable Asterisk 1.8 release.
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 *
 * Existing copyright, authorship, Asterisk/Digium notices,
 * third-party notices, and GPL licensing terms are preserved when present.
 *
 * chan_sofia - Sofia-SIP based channel driver for GABPBX
 *
 * Uses the sofia-sip NUA API for full SIP stack handling.
 * Config file: sofia.conf (compatible with sip.conf format)
 *
 * ============================================================
 * DROP-IN chan_sip COMPATIBILITY POLICY (2026-04-27)
 * ============================================================
 * chan_sofia is intentionally drop-in-compatible with chan_sip
 * configurations and dialplans. Operators can swap the loaded
 * SIP driver from chan_sip to chan_sofia without rewriting
 * dialplans, realtime schemas, or AMI integrations.
 *
 * Compatibility surface:
 *   - Channel tech name:     "SIP"      (not "Sofia")
 *     Dialplan: Dial(SIP/peer) routes to chan_sofia.
 *   - Realtime family:       "sippeers" (chan_sip default)
 *     extconfig.conf: sippeers => pgsql,general,voip_sip_conf
 *   - Dialplan functions:    SIPPEER / SIPCHANINFO / SIP_HEADER /
 *                            CHECKSIPDOMAIN  (T46 — chan_sip-parity
 *                            names, drop-in for existing dialplans).
 *   - AMI actions:           SIPpeers / SIPshowpeer / SIPqualifypeer /
 *                            SIPshowregistry / SIPnotify  (T47 —
 *                            chan_sip-parity names).
 *   - AMI events:            PeerStatus / Registry / Hold  (T35 —
 *                            chan_sip-parity names).
 *   - CLI commands:          "sip show peers" / "sip show channels" /
 *                            "sip show peer <name>" / "sip set debug"
 *                            (chan_sip-compat — operators retrain zero
 *                            muscle-memory).
 *
 * MUTUAL-EXCLUSIVITY CONSTRAINT:
 * chan_sofia and chan_sip CANNOT be loaded simultaneously. Both
 * register the SAME global names (channel tech, dialplan functions,
 * AMI actions, realtime family). The second module to load fails
 * its registrations. Operators must pick exactly ONE SIP driver
 * per gabpbx instance. This is intentional — the drop-in trade-off
 * is "no rewrites OR coexistence" and we picked no-rewrites.
 *
 * To switch: noload => chan_sip.so in modules.conf, ensure
 * chan_sofia.so loads, restart gabpbx.
 * ============================================================
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>  /* post-T56 sip prune realtime CLI parity (2026-04-27): regcomp/regexec for `like <pattern>` form */
#include <unistd.h>
#include <fcntl.h>  /* post-T56 Task #3 SS2 (2026-04-28): open() O_RDONLY|O_CLOEXEC for /dev/urandom in sofia_secure_nonce_gen Pattern 5 helper #37 */
#include <errno.h>  /* post-T56 Task #3 SS2 (2026-04-28): EINTR retry loop in sofia_secure_nonce_gen Pattern 5 helper #37 per N7 audit hardening */
#include <openssl/sha.h>  /* post-T56 Task #3 SS4 (2026-04-28): OpenSSL SHA256() for RFC 7616 SHA-256 digest auth. Use libcrypto's exported API instead of gabpbx-core SHA256* symbols, which are not exported to loadable modules. */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/time.h>
#include <time.h>

#include "gabpbx/channel.h"
#include "gabpbx/config.h"
#include "gabpbx/logger.h"
#include "gabpbx/module.h"
#include "gabpbx/pbx.h"
#include "gabpbx/utils.h"
#include "gabpbx/lock.h"
#include "gabpbx/cli.h"
#include "gabpbx/frame.h"
#include "gabpbx/callerid.h"
#include "gabpbx/app.h"
#include "gabpbx/manager.h"
#include "gabpbx/event.h"  /* T55.2 (2026-04-27): AST_EVENT_MWI subscribe/unsubscribe */
#include "gabpbx/linkedlists.h"
#include "gabpbx/astobj2.h"
#include "gabpbx/devicestate.h"
#include "gabpbx/threadstorage.h"
#include "gabpbx/rtp_engine.h"
#include "gabpbx/dsp.h"  /* post-T56 inband DTMF detect parity (2026-04-27): ast_dsp_new + ast_dsp_process + ast_dsp_set_features for inbound DTMF tone detection */
#include "gabpbx/dnsmgr.h"  /* post-T56 dnsmgr per-peer parity (2026-04-27): ast_dnsmgr_lookup_cb + ast_dnsmgr_release for async hostname-tracking on peers with host=hostname (non-IP) */
#include "gabpbx/udptl.h"  /* T.38 fax UDPTL: ast_udptl_protocol + ast_udptl_proto_register/unregister + ast_udptl_destroy + struct ast_control_t38_parameters via frame.h. */
#include "gabpbx/sched.h"  /* post-T56 Task #8 T.38 fax UDPTL parity SS4 (2026-04-28): ast_sched_thread_create/destroy/add/del for sofia_t38_abort 5s reINVITE timeout per SS1.5 N2 LOAD-BEARING (chan_sip.c:24288 ast_sched_add 5000ms). chan_sofia uses ast_sched_thread managed-thread API (sched.h:316-403) — sofia owns separate sched-thread vs chan_sip's monitor-thread sched_runq pattern; equivalent semantic + cleaner thread-ownership */
#include "gabpbx/causes.h"
#include "gabpbx/acl.h"
#include "gabpbx/musiconhold.h"
#include "gabpbx/ast_version.h"  /* post-T56 useragent [general] parity (2026-04-28): ast_get_version() for User-Agent default value */
#include "gabpbx/paths.h"        /* post-T56 rtsavesysname [general] parity (2026-04-28): ast_config_AST_SYSTEM_NAME extern for regserver column writes */

#include "sofia/include/srtp.h"
#include "sofia/include/sdp_crypto.h"

#include <sofia-sip/nua.h>
#include <sofia-sip/su.h>
#include <sofia-sip/su_string.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/url.h>
#include <sofia-sip/nua_tag.h>
#include <sofia-sip/sip_tag.h>
#include <sofia-sip/nta_tag.h>
#include <sofia-sip/su_tag.h>
#include <sofia-sip/sdp.h>
#include <sofia-sip/sdp_tag.h>
#include <sofia-sip/tport.h>
#include <sofia-sip/nta_tport.h>
#include <sofia-sip/tport_tag.h>	/* post-T56 tos/cos bundle (2026-04-28): TPTAG_TOS for SIP-listener-side TOS via nua_create. Pattern 16 sofia-sip-native 9th-instance. */

#define SOFIA_CONFIG "sofia.conf"
#define SOFIA_CHANNEL_TYPE "SIP"

#define DEFAULT_CONTEXT "default"
#define DEFAULT_BINDADDR "0.0.0.0"
#define DEFAULT_SIP_PORT 5060
#define DEFAULT_EXPIRY 120
/* post-T56 registration TTL bounds + 423 Interval Too Brief parity (2026-04-27):
 * chan_sip parity sip.h:55-57 verbatim macro values (DEFAULT_DEFAULT_EXPIRY=120 +
 * DEFAULT_MIN_EXPIRY=60 + DEFAULT_MAX_EXPIRY=3600). Used at sofia_load_config
 * explicit-init + sofia_parse_general_config clamp-on-invalid fallback. */
#define DEFAULT_MIN_EXPIRY      60
#define DEFAULT_MAX_EXPIRY      3600
#define DEFAULT_DEFAULT_EXPIRY  120
/* post-T56 maxforwards parity (2026-04-27): RFC 3261 §20.22 Max-Forwards header
 * default value; chan_sip parity sip.h:60 verbatim "#define DEFAULT_MAX_FORWARDS 70". */
#define DEFAULT_MAX_FORWARDS    70
/* post-T56 t1min parity (2026-04-27): RFC 3261 §17.1.1.2 T1 retry-timer minimum;
 * chan_sip parity sip.h:217 verbatim "#define DEFAULT_T1MIN 100" — 100ms minimum
 * roundtrip-time bound (chan_sip override of RFC 3261 §17.1.1.2 default 500ms). */
#define DEFAULT_T1MIN           100
/* post-T56 registertimeout parity (2026-04-27): outbound REGISTER application-level
 * scheduled-retry interval seconds; chan_sip parity sip.h:59 verbatim
 * "#define DEFAULT_REGISTRATION_TIMEOUT 20". */
#define DEFAULT_REGISTRATION_TIMEOUT 20
/* post-T56 useragent [general] parity (2026-04-28): User-Agent header value
 * advertised in outbound SIP requests + Server header in responses. chan_sip
 * parity sip.h:219-220 verbatim "#define DEFAULT_USERAGENT \"GABpbx PBX\"".
 * Composed at config-load via snprintf "%s %s" with ast_get_version() yielding
 * runtime form e.g. "GABpbx PBX 2.7.1". chan_sip drop-in: operators copying
 * sip.conf [general] useragent= line to sofia.conf get byte-identical
 * User-Agent header in SIP traces / billing / fingerprinting. Pattern 12
 * 22nd-instance behavior-change-from-chan_sofia-baseline-disclosure
 * (4th-sub-instance past N=3 PROVEN; sofia-sip default "sofia-sip/1.13.17"
 * silently overridden by chan_sip-verbatim default for drop-in faithfulness). */
#define DEFAULT_USERAGENT       "GABpbx PBX"
/* post-T56 progressinband per-peer + [general] tri-state parity (2026-04-28):
 * 3 named constants for chan_sofia int-field idiom mirroring chan_sip flag-bit
 * triple at sip.h:282-285 verbatim "SIP_PROG_INBAND (3 << 25) / NEVER (0 << 25)
 * / NO (1 << 25) / YES (2 << 25)". Used at sofia_load_config explicit-init +
 * sofia_indicate AST_CONTROL_RINGING wire-in + sip show settings tri-state
 * display. Default NEVER per chan_sip drop-in. */
#define SOFIA_PROG_INBAND_NEVER 0
#define SOFIA_PROG_INBAND_NO    1
#define SOFIA_PROG_INBAND_YES   2
/* post-T56 faxdetect per-peer + [general] multi-mode parity (2026-04-28): 4 named
 * constants for chan_sofia int-field idiom mirroring chan_sip 2-bit flag encoding
 * triple at sip.h:341-344 verbatim "SIP_PAGE2_FAX_DETECT (3 << 24) / SIP_PAGE2_
 * FAX_DETECT_CNG (1 << 24) / SIP_PAGE2_FAX_DETECT_T38 (2 << 24) / SIP_PAGE2_FAX_
 * DETECT_BOTH (3 << 24)". Bit-OR semantic: CNG (1) | T38 (2) = BOTH (3). Default
 * NONE per chan_sip drop-in (BSS static-zero of global_flags[1] FAX_DETECT bits). */
#define SOFIA_FAX_DETECT_NONE   0
#define SOFIA_FAX_DETECT_CNG    1
#define SOFIA_FAX_DETECT_T38    2
#define SOFIA_FAX_DETECT_BOTH   3

/* T.38 fax UDPTL 4-state negotiation machine:
 *
 * State transitions queue AST_CONTROL_T38_PARAMETERS for 3 of 4 states
 * (LOCAL_REINVITE deliberately silent — waits for peer 200 OK). pvt->t38_state
 * is zero-initialized to DISABLED at sofia_pvt_alloc; transition logic lives
 * in the
 * sofia_change_t38_state Pattern 5 helper (#43 candidate). */
#define SOFIA_T38_DISABLED          0
#define SOFIA_T38_LOCAL_REINVITE    1
#define SOFIA_T38_PEER_REINVITE     2
#define SOFIA_T38_ENABLED           3

/* T.38 UDPTL error-correction mode mirroring chan_sip.c:18565-18567 verbatim
 * (SIP_PAGE2_T38SUPPORT_UDPTL = NONE / _FEC / _REDUNDANCY). Per-peer
 * t38pt_udptl parser sets peer->t38_ec_mode at SS2; SDP a=T38FaxUdpEC
 * negotiation parses peer choice at SS3a; ast_udptl_set_error_correction_scheme
 * wire-in lands at SS3a/SS4. */
#define SOFIA_T38_EC_NONE           0
#define SOFIA_T38_EC_FEC            1
#define SOFIA_T38_EC_REDUNDANCY     2

/* T.38 FaxMaxDatagram default per chan_sip drop-in (chan_sip.c:29525 sentinel
 * `-1` semantic; chan_sip emits 200-byte default when absent). chan_sofia
 * sentinel `-1` = use 200-byte built-in; positive integer overrides per
 * peer or [general]. Wired at SS3a SDP outbound a=T38FaxMaxDatagram emit. */
#define SOFIA_T38_MAXDATAGRAM_SENTINEL  -1
#define SOFIA_T38_MAXDATAGRAM_BUILTIN   200

/* T.38 reINVITE 5-second abort timeout per chan_sip.c:24288 verbatim
 * (ast_sched_add 5000ms + sip_t38_abort callback at chan_sip.c:23384-23398).
 * Without this timer, peers that fail to ack the 200 OK leave chan_sofia
 * stuck in T38_PEER_REINVITE forever. SS2 declares the constant + adds
 * pvt->t38id field with -1 sentinel; ast_sched_add + cancel sites land
 * at SS4 with sched-context creation (chan_sip.c:32330 verbatim sched_context_create
 * pattern; chan_sofia's own sched-context to be added at SS4). */
#define SOFIA_T38_ABORT_TIMEOUT_MS  5000
/* REFER transferer-leg BYE deferral. After we send the terminal NOTIFY 200 OK on a
 * blind/attended transfer the transferer's UA is expected to send BYE per
 * RFC 5589 §6.1. If it does not within this window, fire nua_bye ourselves so the
 * dialog does not leak. 32 s mirrors chan_sip DEFAULT_TRANS_TIMEOUT
 * (sip_scheddestroy path at chan_sip.c:7058). */
#define SOFIA_DEFER_BYE_TIMEOUT_MS  32000
/* post-T56 allowoverlap [general]+per-peer parity (2026-04-28, Option A FULL WIRE-IN
 * 3 sites: sofia_process_invite ast_canmatch_extension + sofia_indicate AST_CONTROL_
 * INCOMPLETE + nua_r_invite 484 status special-case): 3 named constants for
 * chan_sofia int-field idiom mirroring chan_sip 2-bit flag encoding triple at
 * sip.h:319-321 verbatim "SIP_PAGE2_ALLOWOVERLAP_NO (0 << 13) / SIP_PAGE2_ALLOW
 * OVERLAP_YES (1 << 13) / SIP_PAGE2_ALLOWOVERLAP_DTMF (2 << 13)". Default YES per
 * chan_sip drop-in critical default (chan_sip.c:29479 verbatim
 * `ast_set_flag(&global_flags[1], SIP_PAGE2_ALLOWOVERLAP_YES);` with chan_sip
 * trailing comment "Default for all devices: Yes"). DTMF mode parsed + stored + displayed but inbound 484 emit
 * treats DTMF as fall-through to standard handling per chan_sip own design at
 * chan_sip.c:23937-23943 verbatim comment "For SIP_PAGE2_ALLOWOVERLAP_DTMF it is
 * better to do this in the dialplan using the Incomplete application rather than
 * having the channel driver do it" — chan_sip itself defers DTMF detection to
 * dialplan; chan_sofia mirrors. */
#define SOFIA_OVERLAP_NO        0
#define SOFIA_OVERLAP_YES       1
#define SOFIA_OVERLAP_DTMF      2
#define MAX_PEER_BUCKETS 53
#define MAX_DIALOG_BUCKETS 53

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
/* post-T56 Task #2 D-3 SS1 (2026-04-28, GAP-1 chan_sofia surpass dimension —
 * Pattern 12 chan_sofia-feature-not-in-chan_sip-at-all 33rd-instance + T36
 * Stage A WS/WSS listener infrastructure operator-config completion):
 * RFC 7118 SIP-over-WebSocket transport types. Wire-in via NUTAG_WS_URL +
 * NUTAG_WSS_URL at nua_create (T36 ec1bcd9 commit). Per-peer transport=ws
 * or transport=wss now operator-configurable; chan_sip has NO WebSocket
 * support whatsoever (verified via grep — 0 hits in chan_sip.c +
 * chan_sip.c.bk). Power-of-2 enum continues SOFIA_TRANSPORT_* bitmask
 * convention. */
#define SOFIA_TRANSPORT_WS  8
#define SOFIA_TRANSPORT_WSS 16

#define SOFIA_NAT_FORCE_RPORT (1 << 0)
#define SOFIA_NAT_COMEDIA     (1 << 1)

/* Digest-auth nonce TTL fallback when sofia_cfg.nonce_ttl_seconds is unset
 * (=0). Keep the default aligned with the normal SIP registration maximum so
 * long-lived phones do not receive stale=true on every normal refresh. Operators
 * can still tighten this with [general] nonce_ttl_seconds=N. */
#define SOFIA_NONCE_TTL_SEC_DEFAULT 3600
#define SOFIA_NONCE_TTL_SEC_LEGACY  300  /* for operator-honest disclosure / migration reference */

#define DEFAULT_QUALIFYFREQ   60
#define DEFAULT_QUALIFYTIMEOUT 3
#define DEFAULT_FREQ_NOTOK    10

#define SOFIA_BLACKLIST_BUCKETS 1024
#define SOFIA_BLACKLIST_MAX_DEFAULT 1024
#define SOFIA_BLACKLIST_COUNT_DEFAULT 5

enum sofia_peer_status {
	PEER_UNREACHABLE = -1,
	PEER_UNKNOWN     = 0,
	PEER_REACHABLE   = 1,
	PEER_LAGGED      = 2,
};

static struct {
	char bindaddr[128];
	int bindport;
	char context[AST_MAX_CONTEXT];
	char default_user[80];
	char default_secret[80];
	char realm[80];
	int allowguest;
	int busy_on_active;
	int max_contacts;
	int encryption;                   /* T37: SDES-SRTP general default (0=off, 1=on); soft-zeroed at load if res_srtp absent */
	char default_srtpcipher[256];     /* post-T56 srtpcipher operator option (2026-04-27): comma-separated cipher preference list inherited by sofia_peer_alloc when peer omits the key; empty = use sdp_crypto.c default AES_CM_128_HMAC_SHA1_80 */
	int srtp_per_suite_keys;          /* post-T56 Task 7b SRTP per-suite-fresh-key option (2026-04-28, deferred from #7a 612759d R4 strategy (b) — chan_sofia surpass dimension feature-not-in-chan_sip-at-all): 0 = shared-key mode default (current behavior; #7a strategy (a) — single 46-byte master_key shared across all suites in multi-cipher offer; peer picks one so unused key material discarded on answer) / 1 = per-suite-fresh-key mode (forensic-grade key separation; each suite gets independent fresh random master_key via res_srtp->get_random; key material recovery from one suite cannot decrypt others — MIKEY/DTLS-SRTP convention). [general]-only operator option (no per-peer override; operator-policy is global). chan_sofia surpass dimension — no chan_sip equivalent (chan_sip has no multi-suite SRTP offer mechanism therefore no shared-vs-per-suite key strategy choice). Wire-in via module-scope sofia_srtp_per_suite_keys mirror (set in sofia_load_config; consumed by sdp_crypto.c sdp_crypto_offer_list multi-cipher loop + sdp_crypto_activate suite-key selection). Mem cost ~1.7 KB per active SRTP call when enabled (16-slot static arrays in struct sdp_crypto). */
	int force_invite_auth;            /* post-T56 Task #3 INVITE digest auth SS3 (2026-04-28, R18 chan_sofia surpass dimension operator-policy-global-security-override + SW6 INSECURE_INVITE-visibility-vs-chan_sip-silent NEW DIMENSION): 0 = drop-in chan_sip parity baseline (per-peer insecure=invite bypass active) / 1 = global lockdown override (ALL inbound INVITEs require digest auth regardless of per-peer insecure=invite config). [general]-only operator security-lockdown switch. chan_sofia surpass — no chan_sip equivalent (chan_sip has only per-peer insecure=invite; no global override mechanism). Use cases: compliance audit during scheduled review (temporarily disable bypass), incident response (lock down auth in response to detected attack), default-deny posture (progressive operator hardening). When force_invite_auth=1 AND a peer hits with insecure=invite, LOG_NOTICE fires "Sofia: force_invite_auth=yes overrides per-peer insecure=invite for peer X — auth required" so operator sees policy taking effect. Mirrors sofia_srtp_per_suite_keys [general]-only design pattern. */
	int nonce_ttl_seconds;            /* Digest auth nonce TTL override. 0 = use SOFIA_NONCE_TTL_SEC_DEFAULT (3600s); positive value = explicit operator override. Consumed by sofia_verify_digest_auth nonce-staleness check. */
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
	 * intermittent network drops; SoftX3000-style scenarios). chan_sip parity at
	 * chan_sip.c:29594-29595 verbatim [general] parser ast_true + L14625-14637
	 * destroy_association cleanup-skip-when-set + L29197-29204 realtime peer-load
	 * expired-contact-preserve-when-set. chan_sip default = implicit sip_cfg
	 * static-zero (no explicit init line); chan_sofia explicit-init = 0 for
	 * clarity (more disciplined than chan_sip). Production .193 sofia.conf line
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
	 * correction toward chan_sip-faithful semantics. .193 production
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
	 * .193 sofia.conf rtsavesysname=yes silently-ignored prior to this commit; finally
	 * honored on next reload + Pattern 12 26th-instance behavior-change-from-chan_sofia-
	 * baseline-disclosure sub-pattern 5th-sub-instance): chan_sip-parity flag for
	 * multi-server gabpbx realtime deployments. When set + ast_config_AST_SYSTEM_NAME
	 * non-empty, ast_update_realtime calls include "regserver", AST_SYSTEM_NAME pair
	 * tracking which gabpbx instance has the registration. chan_sip parity at
	 * chan_sip.c:29590-29591 verbatim [general] parser ast_true + sip.h:686 verbatim
	 * field `int rtsave_sysname` (doxygen tag G: Save system name at registration?)
	 * + chan_sip.c:19440 verbatim "Save sys. name" sip show settings display +
	 * chan_sip.c.bk:5103-
	 * 5151 canonical realtime_update_peer wire-in pattern (Asterisk-upstream pattern).
	 * IMPORTANT NOTE: active chan_sip.c FuturePBX fork has DROPPED the realtime_update_
	 * peer wire-in entirely — only parser + display present (rtsavesysname is currently
	 * a DEAD flag in active chan_sip; canonical wire-in preserved only in chan_sip.c.bk
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
	/* post-T56 rtupdate [general] parity (2026-04-28, REAL OPERATOR DRIVER on .193
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
	/* post-T56 rtcachefriends [general] parity (2026-04-28, REAL OPERATOR DRIVER on
	 * .193 sofia.conf rtcachefriends=yes silently-ignored prior to this commit;
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
	 * chan_sip.c.bk has same wire-in pattern). PARSE-COMPAT-ONLY ship — chan_sofia
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
	 * regression-class (chan_sip.c.bk has same wire-in pattern at corresponding lines).
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
	 * verification CONFIRMED chan_sip-parity-NOT-fork-regression-class (chan_sip.c.bk
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
	 * chan_sip-parity-NOT-fork-regression-class (active chan_sip + chan_sip.c.bk
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
	 * macro + sip.h:701 verbatim int field. Backup-fork verification (chan_sip.c.bk
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
	 * per chan_sip drop-in. .193 production sofia.conf line tos_sip=cs3 +
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
	 * .193 sofia.conf useragent=Huawei SoftX3000 V300R011 silently-ignored
	 * prior to this commit; finally honored on next reload. */
	char useragent[AST_MAX_EXTENSION];
		int default_qualify;
		int default_qualifyfreq;
		int default_qualifytimeout;
		format_t capability;
		struct ast_codec_pref prefs;
	} sofia_cfg;

	static su_root_t *sofia_root;
	static nua_t *sofia_nua;
	static pthread_t sofia_thread;
	static pthread_t sofia_reg_thread;
	static pthread_t sofia_qualify_tid;
	/* post-T56 Task #8 T.38 fax UDPTL parity SS4 (2026-04-28, SS1.5 N2 LOAD-BEARING):
	 * ast_sched_thread managed-thread for T.38 reINVITE 5-second timeout
	 * (sofia_t38_abort callback). chan_sip pattern at chan_sip.c:32330 creates
	 * own sched_context + runs ast_sched_runq from monitor thread; chan_sofia
	 * uses higher-level ast_sched_thread API which manages thread internally.
	 * Created at load_module (post-nua-init); destroyed at unload (defensive —
	 * T40 returns -1 first). NULL when not yet initialized — gates t38id arm
	 * call sites. */
	static struct ast_sched_thread *sofia_sched;

static int sofia_debug;
static char sofia_debug_filter[64];
static int sofia_debug_match(const char *peer_name, const char *src_ip);
/* post-T56 timert1 [general] parity (2026-04-28): cross-validation flags per
 * chan_sip.c:29607 + chan_sip.c:28946 verbatim. Set when respective [general]
 * key parsed; consumed at sofia_load_config conclusion R5 cross-validation
 * (mirror chan_sip.c:30043-30055 verbatim nested logic for Timer B vs T1*64). */
static int sofia_timerb_set;
static int sofia_timert1_set;
/* post-T56 Task 7b SRTP per-suite-fresh-key option (2026-04-28, deferred from
 * #7a 612759d R4 strategy (b)): module-scope mirror of sofia_cfg.srtp_per_suite
 * _keys for sdp_crypto.c extern-visibility access. Set at sofia_load_config
 * after [general] parsing; read by sdp_crypto_offer_list multi-cipher loop +
 * sdp_crypto_activate per-suite key selection. NOT static (extern visibility
 * required). Mirrors sofia_debug + sofia_timerb_set + sofia_timert1_set
 * extern-visibility pattern (file-scope int set at config-load consumed by
 * peer modules). */
int sofia_srtp_per_suite_keys;

static struct ao2_container *peers;
static struct ao2_container *dialogs;
static struct ao2_container *sofia_blacklist;
static int sofia_blacklist_max = SOFIA_BLACKLIST_MAX_DEFAULT;
static int sofia_blacklist_count = SOFIA_BLACKLIST_COUNT_DEFAULT;
AST_MUTEX_DEFINE_STATIC(sofia_blacklist_lock);

struct sofia_blacklist_entry {
	char ip[80];
	int counter;
	time_t first_seen;
	time_t last_seen;
};

/* T46.2: local SIP domains for ${CHECKSIPDOMAIN(domain)} dialplan function.
 * Populated from sofia.conf [general] domain= lines (multi-allowed). */
struct sofia_domain {
	char domain[80];
	AST_LIST_ENTRY(sofia_domain) list;
};
static AST_LIST_HEAD_STATIC(domain_list, sofia_domain);

static void sofia_get_source_addr(sip_t const *sip, struct ast_sockaddr *addr);
static int sofia_blacklist_add_sip(sip_t const *sip, const char *reason);
static int sofia_blacklist_check_sip(sip_t const *sip);
/* post-T56 match_auth_username (2026-04-28): forward-decl for sofia_pick_auth_username
 * Pattern 5 helper #28 — definition at ~L5297 after sofia_au_get_unq cluster; called
 * earlier from sofia_process_invite L4462 + sofia_process_register L5470 (distance
 * >500 LoC per chan-sip-compat-naming-rules.md ADDENDUM #4 forward-decl discipline). */
static const char *sofia_pick_auth_username(sip_t const *sip,
		const char *fallback_user, char *buf, size_t len);

/* post-T56 Task #3 INVITE digest auth SS3 (2026-04-28): forward declarations
 * for INVITE wire-in at sofia_process_invite L5745. Definitions live in
 * helper cluster post-L7000 (distance >1000 LoC; per chan-sip-compat-naming-
 * rules.md ADDENDUM #4 forward-decl discipline). enum sofia_auth_result
 * declared here so sofia_process_invite can take its return-type.
 *
 * struct sofia_peer is defined later at L1118; opaque forward-decl here
 * sufficient because we only take pointer-to-struct in helper signature. */
struct sofia_peer;
enum sofia_auth_result {
	SOFIA_AUTH_OK = 0,
	SOFIA_AUTH_CHALLENGE = 1,    /* helper emitted 401; caller short-circuits */
	SOFIA_AUTH_REJECT = 2,       /* helper emitted 4xx terminal; caller short-circuits */
};
static enum sofia_auth_result sofia_verify_digest_auth(struct sofia_peer *peer,
		nua_t *nua, nua_handle_t *nh,
		sip_t const *sip,
		sip_authorization_t const *au,
		const char *method,
		const char *realm);
static const char *sofia_get_realm_for_dialog(sip_t const *sip, char *buf, size_t buflen);

/* SS5 forward-decls for INVITE auth helpers called from sofia_process_invite L5876+
 * (auth dispatch + ACL-deny timing-equal + alwaysauthreject extension). Definitions
 * live ~L7400-7600 (distance >1500 LoC; forward-decl-when-distance discipline). */
static void sofia_emit_timing_equalized_reject(void);
static void sofia_send_auth_challenge(nua_t *nua, nua_handle_t *nh, sip_t const *sip,
		const char *realm, const char *method, const char *reason);

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

struct sofia_register_update {
	int was_registered;
	int now_registered;
	int contacts_before;
	int contacts_after;
	int contacts_added;
	int contacts_refreshed;
	int contacts_removed;
	int contacts_moved;
	int wildcard_removed;
	char changed_uri[256];
	struct ast_sockaddr old_src;
	struct ast_sockaddr new_src;
	struct ast_sockaddr changed_old_src;
};

static void sofia_register_update_set_uri(struct sofia_register_update *update, const char *uri)
{
	if (update && ast_strlen_zero(update->changed_uri)) {
		ast_copy_string(update->changed_uri, uri, sizeof(update->changed_uri));
	}
}

static int contact_hash_fn(const void *obj, int flags)
{
	const struct sofia_contact *c = obj;
	return ast_str_case_hash(c->contact_uri);
}

static int contact_cmp_fn(void *obj, void *arg, int flags)
{
	struct sofia_contact *c = obj;
	const char *uri = arg;
	return strcasecmp(c->contact_uri, uri) ? 0 : CMP_MATCH;
}

#define SOFIA_FORK_ID_LEN 40

struct sofia_pvt; /* forward declaration */
static void sofia_pvt_snapshot_initreq(struct sofia_pvt *pvt, sip_t const *sip); /* T46.1 */

enum sofia_fork_state {
	FORK_PRE_RING,
	FORK_RINGING,
	FORK_WINNER_PICKED,
	FORK_DEAD,
};

struct sofia_fork {
	struct ao2_container *children;   /* child sofia_pvt objects keyed by fork_branch_id */
	struct sofia_pvt *master;         /* pvt that owns the ast_channel (never changes) */
	struct sofia_pvt *winner;         /* first child that got 200 OK, NULL until picked */
	int winner_picked;                /* 0=no winner yet, 1=winner claimed */
	enum sofia_fork_state state;
	time_t fork_start;                /* timestamp when fork was initiated */
	char fork_id[SOFIA_FORK_ID_LEN]; /* unique ID for debug logging */
	ast_mutex_t lock;                 /* guards winner_picked, winner, child_count, children, state */
	int child_count;                  /* live children remaining */
};

/* T55.1 (2026-04-27): MWI per-peer mailbox tracking. struct sofia_mailbox is
 * the per-mailbox node; sofia_mailbox_list is the per-peer head. Defined here
 * BEFORE struct sofia_peer so the head is a complete type when sofia_peer
 * embeds it. T55.2 will add event_sub field; T55.3 will add mwi_subscription_handle
 * to sofia_peer for the subscriber dialog. */
struct sofia_mailbox {
	char mailbox[80];
	char context[80];
	struct ast_event_sub *event_sub;	/* T55.2 (2026-04-27): AST_EVENT_MWI subscription per mailbox */
	AST_LIST_ENTRY(sofia_mailbox) list;
};
AST_LIST_HEAD_NOLOCK(sofia_mailbox_list, sofia_mailbox);

/* post-T56 session timers (RFC 4028) (2026-04-27): chan_sip-parity mode + refresher
 * enums. session-timers config-key value semantics mirror chan_sip sip.h L518-521
 * verbatim; refresher value semantics mirror chan_sip parity (uac/uas). Mapped to
 * sofia-sip nua_session_refresher enum at NUTAG_SESSION_REFRESHER emit time. */
enum sofia_session_timer_mode {
	SESSION_TIMERS_OFF       = 0, /* unset / inherit from [general] */
	SESSION_TIMERS_ACCEPT    = 1, /* honor inbound peer Session-Expires; no initiate */
	SESSION_TIMERS_ORIGINATE = 2, /* originate outbound Session-Expires + honor inbound */
	SESSION_TIMERS_REFUSE    = 3, /* explicit-disable; sofia-sip emits 422 if peer offers */
};
enum sofia_session_refresher {
	SESSION_REFRESHER_AUTO = 0, /* sofia-sip nua_any_refresher; negotiation decides */
	SESSION_REFRESHER_UAC  = 1, /* we refresh; chan_sip stimer.st_ref UAC parity */
	SESSION_REFRESHER_UAS  = 2, /* peer refreshes; chan_sip stimer.st_ref UAS parity */
};

/* post-T56 allowtransfer per-peer parity (2026-04-27): chan_sip-parity REFER gate.
 * Binary enum mirrors chan_sip sip.h:378-379 (transfermodes). Values chosen so
 * static-zero struct init == TRANSFER_OPENFORALL == chan_sip backwards-compat
 * default ("Merrily accept all transfers" — chan_sip.c:29476). Drop-in operator
 * config allowtransfer=yes|no maps via ast_true → enum value at parse time
 * (chan_sip.c:28909 verbatim parser semantic). chan_sip's transfermode2str
 * "strict" branch (chan_sip.c:17460) is dead code — no parser path produces a
 * third state — so chan_sofia mirrors only the 2 reachable values. */
enum sofia_transfer_mode {
	TRANSFER_OPENFORALL = 0, /* allow all SIP REFER transfers; chan_sip parity */
	TRANSFER_CLOSED     = 1, /* reject all SIP REFER with 603 Declined (policy) */
};

/* post-T56 allowtransfer per-peer parity (2026-04-27): display-string helper.
 * chan_sip.c:17454-17461 transfermode2str parity (skip dead "strict" branch).
 * Used by sip show peer CLI + AMI SIPshowpeer TransferMode field. */
static inline const char *sofia_transfer_mode_str(int mode)
{
	return (mode == TRANSFER_CLOSED) ? "closed" : "open";
}

/* post-T56 allowoverlap [general]+per-peer parity (2026-04-28, Pattern 5 helper #32):
 * tri-state mode → display string mapping. chan_sip parity at chan_sip.c:18123-18133
 * verbatim allowoverlapstr[] map_x_s walker — chan_sofia surpass via switch-case
 * idiom (cleaner for 3-value enum). Used at sip show settings + sip show peer +
 * AMI SIPshowpeer 3 callsites ≥ 3-callsite extraction threshold. */
static inline const char *sofia_allowoverlap_str(int mode)
{
	switch (mode) {
	case SOFIA_OVERLAP_YES:  return "Yes";
	case SOFIA_OVERLAP_DTMF: return "DTMF";
	default:                 return "No";
	}
}

/* post-T56 setvar+header per-peer parity (2026-04-28, Pattern 5 helper #33): split
 * "name=value" buffer + create ast_variable + LIFO list-prepend. Mirrors chan_sip.c
 * :28415-28428 verbatim add_var semantic. Used at 4 callsites (setvar + header in
 * sofia_parse_peer_config + sofia_apply_peer_variables T46.3 dual-parser branches).
 * NULL value = malformed input (no '=' separator) → list returned unchanged. */
static struct ast_variable *sofia_add_var(const char *buf, struct ast_variable *list)
{
	struct ast_variable *tmpvar = NULL;
	char *varname = ast_strdupa(buf), *varval = NULL;

	if ((varval = strchr(varname, '='))) {
		*varval++ = '\0';
		if ((tmpvar = ast_variable_new(varname, varval, ""))) {
			tmpvar->next = list;
			list = tmpvar;
		}
	}
	return list;
}

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
		AST_STRING_FIELD(nonce);
		AST_STRING_FIELD(outboundproxy);	/* T56.1 (2026-04-27): per-peer outbound proxy override; empty = inherit sofia_cfg.outboundproxy or no Route */
		AST_STRING_FIELD(srtpcipher);		/* post-T56 srtpcipher operator option (2026-04-27): comma-separated SRTP suite preference (e.g. "AEAD_AES_256_GCM,AES_CM_128_HMAC_SHA1_80"); empty = inherit sofia_cfg.default_srtpcipher or sdp_crypto.c default AES_CM_128_HMAC_SHA1_80 */
		AST_STRING_FIELD(mohinterpret);		/* post-T56 MOH per-peer parity (2026-04-27): per-peer MOH class to play when remote puts us on hold; empty = inherit sofia_cfg.default_mohinterpret or system default */
		AST_STRING_FIELD(mohsuggest);		/* post-T56 MOH per-peer parity (2026-04-27): suggested MOH class propagated to bridged channel when this peer puts us on hold (R5 INBOUND-direction: ast_queue_control_data data param at sofia_process_reinvite); OUTBOUND-direction Alert-Info signaling deferred to outbound-HOLD-re-INVITE feature task */
		AST_STRING_FIELD(language);		/* post-T56 language per-peer parity (2026-04-27): per-peer audio language locale propagated to ast_channel.language at sofia_new for prompts/sounds in peer's preferred locale. chan_sip parity sip.h peer.language AST_STRING_FIELD + chan_sip.c:28865-28866 verbatim parser + L28447 inheritance from default_language. Bounded to channel.h:138 MAX_LANGUAGE=40 at consumption (ast_channel.language is also AST_STRING_FIELD per channel.h:776). Empty = inherit sofia_cfg.default_language or gabpbx-core default. */
		AST_STRING_FIELD(parkinglot);	/* post-T56 parkinglot per-peer parity (2026-04-28): per-peer parking-lot routing field propagated to ast_channel.parkinglot at sofia_new for Park()/transfer routing. chan_sip parity sip.h:1212 peer.parkinglot AST_STRING_FIELD + chan_sip.c:28890-28891 verbatim parser + L8577 inheritance from default_parkinglot + L5961-5962 + L17046-17047 dialog inheritance + L7943-7944 channel propagation. Empty = inherit sofia_cfg.default_parkinglot. Pattern 12 16th-instance behavior-change-from-chan_sofia-baseline-disclosure: chan_sip default_parkinglot = "default" per features.h:37 DEFAULT_PARKINGLOT (string non-empty). */
		AST_STRING_FIELD(lockuseragent_prefixes);	/* per-peer comma-separated User-Agent prefix allowlist. When lockuseragent=yes AND this list is non-empty, an inbound REGISTER passes when its User-Agent: header starts (case-insensitive) with ANY listed prefix; first-REGISTER auto-capture into locked_user_agent is bypassed. Empty value preserves the original strict capture-on-first-REGISTER semantics verbatim. Targets the multi-device-per-peer use case (desk phone + softphone) and vendor-family allowlists. */
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
	/* post-T56 buggymwi per-peer parity (2026-04-27): chan_sip parity sip.h:338
	 * SIP_PAGE2_BUGGY_MWI flag bit (1<<22) "Buggy CISCO MWI fix". When set, the
	 * Voice-Message: NOTIFY body line OMITS the trailing " (0/0)" suffix per
	 * chan_sip.c:13800-13802 verbatim comment "Cisco has a bug in the SIP stack
	 * where it can't accept the (0/0) notification. This can temporarily be
	 * disabled in sip.conf with the 'buggymwi' option". Per-peer-only flag
	 * (no [general] default — operators set per-Cisco-peer); default 0 (FALSE)
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
	 * surfaces (~50-100 LoC follow-up). .193 sofia.conf has commented `;ignoresdpversion
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
	 * Backup-fork verification (chan_sip.c.bk L27934 parser + L12283 AMI) CONFIRMED
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
	 * operator demand surfaces). Backup-fork verification (chan_sip.c.bk L738 +
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
	 * REAL OPERATOR DRIVER on .193 sofia.conf progressinband=no silently-ignored
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
	 * .193 production sofia.conf line rtptimeout=30 + rtpholdtimeout=300 currently
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

enum sofia_dialog_state {
	SOFIA_DIALOG_STATE_DOWN,
	SOFIA_DIALOG_STATE_TRYING,
	SOFIA_DIALOG_STATE_RINGING,
	SOFIA_DIALOG_STATE_UP,
};

struct sofia_pvt {
	AST_DECLARE_STRING_FIELDS(
		AST_STRING_FIELD(callid);
		AST_STRING_FIELD(exten);
		AST_STRING_FIELD(context);
		AST_STRING_FIELD(subscribecontext);	/* post-T56 subscribecontext per-peer parity (2026-04-27): per-call cache of peer->subscribecontext for in-dialog SUBSCRIBE routing; chan_sip parity sip_pvt.subscribecontext at chan_sip.c:17043. Inherits at sofia_request_call (outbound) + sofia_process_invite (inbound). Inert until presence/dialog event-package handler wires the pivot. */
		AST_STRING_FIELD(accountcode);	/* post-T56 accountcode per-peer parity (2026-04-27): per-call dialog cache of peer->accountcode. Consumed by sofia_new at ast_channel_alloc 5th-arg for chan->accountcode propagation (CDR billing-tag). Pre-existing CDR-billing-bug fix: sofia_new previously passed pvt->username (auth-identity) as 5th arg; now passes pvt->accountcode (semantically correct per channel.h:1136 ast_channel_alloc signature). */
		AST_STRING_FIELD(username);
		AST_STRING_FIELD(peername);
		AST_STRING_FIELD(peersecret);
		AST_STRING_FIELD(fromdomain);
		AST_STRING_FIELD(fromuser);
		AST_STRING_FIELD(uri);
		AST_STRING_FIELD(ruri);
		AST_STRING_FIELD(cid_num);   /* post-T56 identity-headers parity SS4 (2026-04-27): inbound caller-id number; populated from sip_from at sofia_process_invite, overwritten by sofia_get_pai/sofia_get_rpid when peer->trustrpid=1 */
		AST_STRING_FIELD(cid_name);  /* post-T56 identity-headers parity SS4 (2026-04-27): inbound caller-id name; same population/overwrite chain as cid_num */
	);
	enum sofia_dialog_state state;
	int dtmfmode;
	int alreadygone;
	int owner_busy;
	struct ast_channel *owner;
	struct sofia_peer *peer;
	nua_handle_t *nh;
	su_home_t *home;
	int cseq;
	struct ast_rtp_instance *rtp;
	struct ast_rtp_instance *vrtp;
	format_t capability;
	struct ast_codec_pref prefs;
	int lastinvite;
	ast_mutex_t lock;
	/* Fork fields — NULL/single for normal (non-forked) call path */
	struct sofia_fork *fork;         /* shared fork object, NULL = no forking */
	int is_fork_master;              /* 1 = this pvt owns the ast_channel in a fork */
	int is_fork_child;               /* 1 = this pvt is a fork child leg */
	char fork_branch_id[SOFIA_FORK_ID_LEN]; /* unique branch ID per child */
	struct sofia_contact *active_contact;  /* contact this call is on (holds ao2 ref) */
	struct ast_sockaddr redirip;     /* directmedia: peer's RTP target; zero = relay through PBX */
	int reinvite_pending;            /* 1 = directmedia re-INVITE in flight; gates response handler */
	int hold_state;                  /* 1 = peer holding us (a=sendonly/inactive); 0 = active (sendrecv) */
	struct sofia_srtp *srtp;         /* T37: audio SDES-SRTP context (NULL = plain RTP); freed in destructor */
	struct sofia_srtp *vsrtp;        /* T37: video SDES-SRTP context (NULL = plain RTP); freed in destructor */
	struct ast_variable *initreq_headers; /* T46.1: snapshot of inbound INVITE headers for ${SIP_HEADER()} (NULL if outbound or pre-INVITE); freed in destructor */
	struct ast_sockaddr last_src_addr; /* T46.4: transport-source captured at INVITE for ${SIPCHANINFO(peerip|recvip)} */
	struct ast_sockaddr ourip; /* post-T56 outbound-headers parity: kernel-routed source IP for outbound INVITE From/Contact + SDP c=; resolved by sofia_resolve_ourip at sofia_request_call time; zero-init for inbound flows (R5 fallback) */
	int callingpres; /* post-T56 identity-headers parity (2026-04-27): AST_PRES_* mask; per-call presentation; inherits peer->callingpres at sofia_call/sofia_new (else AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED=0); chan_sip parity sip.h:1045; sub-step 2 will populate from ast_party_id_presentation; sub-step 4 will populate from inbound PAI/RPID */
	int outgoing; /* post-T56 identity-headers parity SS2 (2026-04-27): 1=outbound dial (sofia_request_call), 0=inbound INVITE (sofia_process_invite); consumed by sofia_add_rpid RPID branch ;party=calling/called field */
	int call_inc_done; /* post-T56 call-limit parity SS1 (2026-04-27): 1 = this pvt incremented peer->inUse — race-prevention flag for DEC sites; chan_sip SIP_INC_COUNT parity */
	int ring_inc_done; /* post-T56 call-limit parity SS1 (2026-04-27): 1 = this pvt incremented peer->inRinging — race-prevention; chan_sip SIP_INC_RINGING parity */
	struct ast_dsp *dsp; /* Allocated by sofia_enable_dsp_detect when inband/auto DTMF or fax-CNG detection is enabled; freed in destructor. */

	/* T.38 fax UDPTL per-dialog state:
	 *
	 *   udptl: per-dialog UDPTL session pointer; NULL when no T.38 in flight.
	 *     Allocated lazily (chan_sip pattern at chan_sip.c:7591 verbatim) on
	 *     first T.38 reINVITE detect (SS3a inbound or SS4 outbound). Destroyed
	 *     in sofia_pvt_destructor via ast_udptl_destroy.
	 *
	 *   t38_state: 4-state machine SOFIA_T38_DISABLED/LOCAL_REINVITE/PEER_
	 *     REINVITE/ENABLED. Init DISABLED in sofia_pvt_alloc. Transition logic
	 *     SS4 (sofia_change_t38_state Pattern 5 helper #43 candidate; queues
	 *     AST_CONTROL_T38_PARAMETERS for 3 of 4 states per chan_sip.c:5803
	 *     verbatim — LOCAL_REINVITE silent waiting for peer 200 OK).
	 *
	 *   t38id: scheduler ID for sofia_t38_abort 5-second reINVITE timeout per
	 *     SS1.5 N2 LOAD-BEARING audit catch (chan_sip.c:8512 init `-1` +
	 *     chan_sip.c:24288 ast_sched_add 5000ms verbatim). Init `-1` in
	 *     sofia_pvt_alloc; arm/cancel SS4 via sched-context creation
	 *     (chan_sip.c:32330 verbatim sched_context_create pattern). Without
	 *     this timer, peers that fail to ack the 200 OK leave chan_sofia stuck
	 *     in PEER_REINVITE forever.
	 *
	 *   t38_max_ifp: far-end advertised max_ifp from peer SDP; LOAD-BEARING per
	 *     SS1.5 N1 audit catch (chan_sip.c:5786, 5792, 7549 + 7520, 7525). Set
	 *     at SS3a parser via ast_udptl_set_local_max_ifp + ast_udptl_get_far_max_ifp.
	 *     Without max_ifp wiring, real-fax negotiation rejects on every call
	 *     (chan_sip.c:7496 `change_t38_state(p, T38_DISABLED)` when max_ifp==0).
	 *
	 *   t38_maxdatagram: inherited from peer->t38_maxdatagram or sofia_cfg.
	 *     default_t38_maxdatagram (-1 = use SOFIA_T38_MAXDATAGRAM_BUILTIN 200).
	 *     Consumed at SS3a SDP outbound emit `a=T38FaxMaxDatagram:` per
	 *     chan_sip.c:12439 verbatim ast_udptl_get_local_max_datagram pattern.
	 *
	 *   t38_ec_mode: per-call EC mode SOFIA_T38_EC_NONE/_FEC/_REDUNDANCY;
	 *     inherited from peer->t38_ec_mode at SS4 sofia_initialize_udptl
	 *     (paired with ast_udptl_set_error_correction_scheme).
	 *
	 *   t38pt_usertpsource: 1 = symmetric-RTP UDPTL destination override per
	 *     SS1.5 N3 audit catch; inherited from peer->t38pt_usertpsource;
	 *     consumed at SS3a SDP processing.
	 *
	 *   t38_our_parms / t38_their_parms: full 7-field ast_control_t38_parameters
	 *     per frame.h:385-393 (version + max_ifp + rate + rate_management +
	 *     fill_bit_removal:1 + transcoding_mmr:1 + transcoding_jbig:1).
	 *     Zero-initialized via ao2_alloc memset; populated by SS3a/SS4. */
	struct ast_udptl *udptl;
	int t38_state;
	int t38id;
	unsigned int t38_max_ifp;        /* SS3a B1 fix (2026-04-28): unsigned per frame.h:388 ast_control_t38_parameters.max_ifp + ast_udptl_get_far_max_ifp return type */
	int t38_maxdatagram;
	int t38_ec_mode;
	int t38pt_usertpsource;
	struct ast_control_t38_parameters t38_our_parms;
	struct ast_control_t38_parameters t38_their_parms;
	/* post-T56 session timers (RFC 4028) (2026-04-27): per-call refresh tracking
	 * for R13.a sip show channels Session-Timer:N/N display + R13.b AMI
	 * SessionTimerRefresh event. Populated at refresh-fire-time inside
	 * sofia_process_reinvite (uas) + nua_r_invite handler (uac) when
	 * SIPTAG_SESSION_EXPIRES present on the re-INVITE. zero-init = no
	 * session-timer active or not yet fired. */
	int session_negotiated_expires; /* negotiated Session-Expires (seconds); 0 = no timer active */
	time_t session_last_refresh_at; /* time of most recent refresh; 0 = never refreshed */
	int allowtransfer; /* post-T56 allowtransfer per-peer parity (2026-04-27): per-call REFER policy; inherits peer->allowtransfer at sofia_request_call (outbound) or sofia_process_invite (inbound); chan_sip parity sip.h:1065 (dialog->allowtransfer); gated at sofia_process_refer entry */
	/* Blind/attended-transfer BYE deferral (chan_sip parity for SIP_DEFER_BYE_ON_TRANSFER
	 * at chan_sip.c:24949 + L7051-7067). After we send the terminal NOTIFY 200 OK for a
	 * REFER, RFC 5589 §6.1 expects the transferer's UA to send BYE on its own; we must
	 * not race the UA with our own nua_bye, otherwise sofia-sip drops the pending
	 * terminal NOTIFY and the UA never sees the transfer complete. When set,
	 * sofia_hangup skips its nua_bye, and a sched-thread timer (defer_bye_sched_id)
	 * fires nua_bye after SOFIA_DEFER_BYE_TIMEOUT_MS as the safety net for UAs that do
	 * not auto-BYE. The incoming-BYE handler cancels the timer. */
	int defer_bye;
	int defer_bye_sched_id;
};

/* post-T56 call-limit parity SS2 (2026-04-27): centralized counter helper.
 * Mirrors chan_sip update_call_counter at chan_sip.c:6576-6810. 4 events
 * (INC_CALL_LIMIT inbound / INC_CALL_RINGING outbound / DEC_CALL_LIMIT hangup /
 * DEC_CALL_RINGING outbound 200 OK). Returns -1 on rejection. Lock-ordering
 * pvt->lock then ao2_lock(peer) per chan_sip L6713-6730. Idempotency via
 * pvt->call_inc_done + ring_inc_done flags (chan_sip SIP_INC_COUNT + SIP_INC_RINGING
 * parity). Helper emits PeerStatus AMI events itself (centralized per chan_sip
 * L6687/L6734) so callers just call helper. Declared HERE (before
 * sofia_pvt_destructor at L1329 which calls it) — earlier than the identity-
 * headers forward-decl cluster which lands further down. */
enum sofia_call_event {
	SOFIA_INC_CALL_LIMIT,    /* inbound INVITE accepted */
	SOFIA_INC_CALL_RINGING,  /* outbound dial dispatched */
	SOFIA_DEC_CALL_LIMIT,    /* inbound or outbound hangup */
	SOFIA_DEC_CALL_RINGING,  /* outbound 200 OK received */
};
static int sofia_update_call_counter(struct sofia_pvt *pvt, enum sofia_call_event event);

static int fork_branch_hash_fn(const void *obj, int flags)
{
	const struct sofia_pvt *p = obj;
	return ast_str_case_hash(p->fork_branch_id);
}

static int fork_branch_cmp_fn(void *obj, void *arg, int flags)
{
	struct sofia_pvt *p = obj;
	const char *branch = arg;
	return strcasecmp(p->fork_branch_id, branch) ? 0 : CMP_MATCH;
}

/* Active contact tracking helpers */
static void sofia_pvt_set_active_contact(struct sofia_pvt *pvt, struct sofia_contact *contact)
{
	if (!pvt || !contact)
		return;
	if (pvt->active_contact) {
		ast_log(LOG_WARNING, "Sofia: active_contact already set for %s\n",
			pvt->callid ? pvt->callid : "unknown");
		return;
	}
	pvt->active_contact = contact;
	ao2_ref(contact, +1);
	ao2_lock(contact);
	contact->active_calls++;
	ao2_unlock(contact);
}

static void sofia_pvt_clear_active_contact(struct sofia_pvt *pvt)
{
	struct sofia_contact *contact;
	if (!pvt || !pvt->active_contact)
		return;
	contact = pvt->active_contact;
	ao2_lock(contact);
	contact->active_calls--;
	ao2_unlock(contact);
	ao2_ref(contact, -1);
	pvt->active_contact = NULL;
}

static const char *sofia_uri_format_host(const char *host, char *out_buf, size_t out_len);

static void sofia_uri_user_from_contact(const char *uri, const char *fallback,
		char *buf, size_t len)
{
	const char *start, *at, *scheme;
	size_t user_len;

	if (!buf || !len) {
		return;
	}
	buf[0] = '\0';

	if (ast_strlen_zero(uri)) {
		ast_copy_string(buf, S_OR(fallback, ""), len);
		return;
	}

	scheme = strchr(uri, ':');
	start = scheme ? scheme + 1 : uri;
	at = strchr(start, '@');
	if (!at || at <= start) {
		ast_copy_string(buf, S_OR(fallback, ""), len);
		return;
	}

	user_len = at - start;
	if (user_len >= len) {
		user_len = len - 1;
	}
	memcpy(buf, start, user_len);
	buf[user_len] = '\0';
}

/* Build NAT-traversal proxy URL from peer->src_addr for outbound in-dialog
 * messages when peer has nat=force_rport (or comedia). Used by sofia_call to
 * disable sofia-sip's auto-ACK and the nua_r_invite 200-OK handler to emit
 * a manual ACK with NUTAG_PROXY override — without this, sofia-sip routes
 * the 2xx-ACK to the dialog's remote_target (= Contact URI from the 200 OK),
 * which for NAT'd phones typically carries the unroutable private LAN IP
 * (the phone advertises its LAN address even when registered from a public
 * NAT-mapped source). The ACK never arrives, leaving the phone
 * to retransmit 200 OK forever and the call to die silently. peer->src_addr
 * holds the registered public source (set on REGISTER for dynamic peers,
 * by sofia_dnsmgr_setup_peer for static host=<ip> peers). Returns 1 if the
 * proxy URL was filled, 0 if peer doesn't need NAT routing. */
static int sofia_build_nat_proxy_url_from_peer(const struct sofia_peer *peer,
                                                char *buf, size_t len)
{
	char host_buf[80];
	int port;

	if (!peer || !buf || len < 16) {
		return 0;
	}
	buf[0] = '\0';

	if (!(peer->nat & (SOFIA_NAT_FORCE_RPORT | SOFIA_NAT_COMEDIA))) {
		return 0;
	}
	if (ast_sockaddr_isnull(&peer->src_addr)) {
		return 0;
	}

	port = ast_sockaddr_port(&peer->src_addr);
	if (!port) {
		port = peer->port ? peer->port : 5060;
	}

	snprintf(buf, len, "sip:%s:%d",
		sofia_uri_format_host(ast_sockaddr_stringify_host(&peer->src_addr),
			host_buf, sizeof(host_buf)),
		port);
	return 1;
}

static int sofia_pvt_build_nat_target_url(struct sofia_pvt *pvt, char *buf, size_t len)
{
	struct ast_sockaddr src;
	struct sofia_contact *contact;
	char user[128];
	char host[80];

	if (!pvt || !buf || !len) {
		return 0;
	}
	buf[0] = '\0';

	contact = pvt->active_contact;
	if (!contact || ast_sockaddr_isnull(&contact->src_addr)) {
		return 0;
	}

	src = contact->src_addr;
	if (contact->port == ast_sockaddr_port(&src) &&
			!strcasecmp(contact->host, ast_sockaddr_stringify_host(&src))) {
		return 0;
	}

	sofia_uri_user_from_contact(contact->contact_uri,
		S_OR(pvt->username, pvt->peername), user, sizeof(user));
	if (ast_strlen_zero(user)) {
		return 0;
	}

	snprintf(buf, len, "sip:%s@%s:%d", user,
		sofia_uri_format_host(ast_sockaddr_stringify_host(&src), host, sizeof(host)),
		ast_sockaddr_port(&src) ? ast_sockaddr_port(&src) : 5060);
	return 1;
}

/* Build sip:user@host:port target URL for a peer.
 * Resolves "dynamic" placeholder OR force_rport-flagged peers to their last-known
 * src_addr from REGISTER. Static-host peers (provider trunks) keep their configured
 * host:port — outbound REGISTER targets correctly skip this helper since they need
 * the configured upstream address, not the peer's own register-source. */
/* post-T56 usereqphone parity (2026-04-27): RFC 3966 telephone-uri digit-pattern
 * matcher. Mirrors chan_sip.c:12844-12852 verbatim semantic — digit-only with
 * optional leading '+' tolerance. POSIX isdigit() functional equivalent of
 * AST_DIGIT_ANYNUM strchr lookup (chan_sofia.c includes ctype.h implicitly via
 * standard headers; AST_DIGIT_ANYNUM lives in gabpbx/file.h not yet included).
 * Pattern 14 isdigit() adaptation acknowledged in commit body. */
/* Step A IPv6 parity SS3 (2026-04-28): forward-decl for sofia_uri_format_host
 * Pattern 5 helper #45 — used by sofia_resolve_peer_target at L1954 +
 * sofia_fork child at L5879 (~100 LoC distance) BEFORE definition at ~L2050
 * (post-sofia_should_use_externaddr block). Forward-decl-when-distance
 * discipline matured at Task #3 + Task #8. */
static const char *sofia_uri_format_host(const char *host, char *out_buf, size_t out_len);

static inline int sofia_user_looks_like_phone(const char *s)
{
	if (!s || !*s) {
		return 0;
	}
	if (*s == '+') {
		s++;
	}
	if (!*s) {
		return 0; /* lone "+" is not a phone number */
	}
	for (; *s; s++) {
		if (!isdigit((unsigned char)*s)) {
			return 0;
		}
	}
	return 1;
}

static void sofia_resolve_peer_target(struct sofia_peer *peer, const char *user,
		char *out_url, size_t out_len)
{
	const char *target_host = peer->host;
	int target_port = peer->port;
	char addr_buf[128];

	if (peer->registered && !ast_sockaddr_isnull(&peer->src_addr)
		&& ((peer->nat & SOFIA_NAT_FORCE_RPORT)
			|| !strcasecmp(peer->host, "dynamic"))) {
		ast_copy_string(addr_buf, ast_sockaddr_stringify_host(&peer->src_addr), sizeof(addr_buf));
		target_host = addr_buf;
		target_port = ast_sockaddr_port(&peer->src_addr);
	} else if (!strcasecmp(peer->host, "dynamic") && !ast_sockaddr_isnull(&peer->defaddr)) {
		/* post-T56 defaultip per-peer parity (2026-04-28): chan_sip parity at
		 * chan_sip.c:5913-5915 verbatim dialog->sa = isnull(addr) ? defaddr : addr
		 * fallback semantic. host=dynamic peer not registered AND defaultip
		 * configured → route to fallback IP. Once peer registers, src_addr
		 * branch above takes precedence. */
		ast_copy_string(addr_buf, ast_sockaddr_stringify_host(&peer->defaddr), sizeof(addr_buf));
		target_host = addr_buf;
		if (ast_sockaddr_port(&peer->defaddr)) {
			target_port = ast_sockaddr_port(&peer->defaddr);
		}
	}
	{
		/* Step A IPv6 parity SS3 (2026-04-28): bracket-wrap IPv6 host per
		 * RFC 3261 §19.1.2. target_host may come from peer->host (raw config
		 * string, possibly unbracketed IPv6) or stringify_host (already
		 * bracketed); helper #45 idempotent at both. */
		char hbuf[80];
		snprintf(out_url, out_len, "sip:%s@%s:%d", user ? user : "",
			sofia_uri_format_host(target_host, hbuf, sizeof(hbuf)), target_port);
	}
	/* post-T56 usereqphone parity (2026-04-27): chan_sofia ARCHITECTURAL ADVANTAGE
	 * — single helper internal extension catches all 3 outbound URI consumers
	 * (sofia_request_call INVITE + sofia_process_refer transfer-target +
	 * sofia_qualify_peer) with zero per-callsite changes. Mirrors chan_sip.c:12836-12853
	 * digit-pattern check; appends ;user=phone when peer has usereqphone set
	 * AND user-part matches phone-number pattern. */
	if (peer->usereqphone && sofia_user_looks_like_phone(user)) {
		size_t cur = strlen(out_url);
		const char *suffix = ";user=phone";
		size_t suffix_len = strlen(suffix);
		if (cur + suffix_len < out_len) {
			memcpy(out_url + cur, suffix, suffix_len + 1); /* include null terminator */
		}
	}
}

/* Contact lookup by source address (for inbound traffic) */
static struct sofia_contact *sofia_peer_find_contact_by_addr(struct sofia_peer *peer,
	const struct ast_sockaddr *addr)
{
	struct ao2_iterator ci;
	struct sofia_contact *c, *found = NULL;
	if (!peer || !peer->contacts || !addr)
		return NULL;
	ci = ao2_iterator_init(peer->contacts, 0);
	while ((c = ao2_iterator_next(&ci))) {
		if (ast_sockaddr_cmp(&c->src_addr, addr) == 0) {
			found = c;
			/* keep the ref from ao2_iterator_next */
			break;
		}
		ao2_ref(c, -1);
	}
	ao2_iterator_destroy(&ci);
	return found;
}

/* Contact lookup by host:port (for outbound traffic) */
static struct sofia_contact *sofia_peer_find_contact_by_host_port(struct sofia_peer *peer,
	const char *host, int port)
{
	struct ao2_iterator ci;
	struct sofia_contact *c, *found = NULL;
	if (!peer || !peer->contacts || !host)
		return NULL;
	ci = ao2_iterator_init(peer->contacts, 0);
	while ((c = ao2_iterator_next(&ci))) {
		if (c->port == port && strcasecmp(c->host, host) == 0) {
			found = c;
			break;
		}
		ao2_ref(c, -1);
	}
	ao2_iterator_destroy(&ci);
	return found;
}

static int sofia_clamp_max_contacts(int val, const char *who)
{
	if (val < 1) {
		ast_log(LOG_WARNING, "Sofia: max_contacts %d clamped to 1 for %s\n", val, who);
		return 1;
	}
	if (val > 6) {
		ast_log(LOG_WARNING, "Sofia: max_contacts %d clamped to ceiling 6 for %s\n", val, who);
		return 6;
	}
	return val;
}

/*! \brief Determine if SDP should advertise externaddr for a given peer address.
 * Returns 1 when the peer is outside localnet (WAN) and externaddr is configured. */
static int sofia_should_use_externaddr(const struct ast_sockaddr *peer_addr)
{
	if (ast_strlen_zero(sofia_cfg.externaddr))
		return 0;
	if (!sofia_cfg.localha)
		return 1;
	return ast_apply_ha(sofia_cfg.localha, peer_addr) == AST_SENSE_ALLOW;
}

/* Pattern 5 helper #45 — Step A IPv6 parity SS3 (2026-04-28, RFC 3261 §19.1.2):
 * format host portion of SIP URI with IPv6-bracket-awareness. IPv6 literals
 * (containing `:`) MUST be bracket-wrapped to disambiguate colons in address
 * from port-separator colon; IPv4 literals + hostnames passthrough unchanged.
 * Idempotent — already-bracketed input passes through unmodified (caller may
 * pass output of ast_sockaddr_stringify_host which returns bracketed IPv6
 * directly per netsock2.c:117-120). 17-callsite migration above 3-callsite
 * Pattern 5 helper-extraction threshold; helper unifies all SIP URI host-
 * portion emissions across outbound INVITE / REGISTER / Contact / From /
 * listener-bind / RURI / outboundproxy / fork-child paths.
 *
 * Returns out_buf for chained snprintf use:
 *   sofia_uri_format_host(host, hbuf, sizeof(hbuf)) → "[2001:db8::1]" / "1.2.3.4" / "host.example.com"
 *
 * NULL/empty input → empty out_buf. */
static const char *sofia_uri_format_host(const char *host, char *out_buf, size_t out_len)
{
	if (!host || !*host) {
		if (out_buf && out_len > 0) {
			out_buf[0] = '\0';
		}
		return out_buf;
	}
	/* Detect IPv6 literal: contains ':' AND not already bracketed.
	 * IPv4 dot-notation uses no `:`; hostnames typically no `:`; bracketed
	 * IPv6 starts with `[`. Robust without regex. */
	if (strchr(host, ':') && host[0] != '[') {
		snprintf(out_buf, out_len, "[%s]", host);
	} else {
		ast_copy_string(out_buf, host, out_len);
	}
	return out_buf;
}

static void sofia_fork_destructor(void *obj)
{
	struct sofia_fork *fork = obj;
	if (fork->children) {
		ao2_ref(fork->children, -1);
		fork->children = NULL;
	}
	ast_mutex_destroy(&fork->lock);
}

static struct sofia_fork *sofia_fork_alloc(void)
{
	struct sofia_fork *fork;
	fork = ao2_alloc(sizeof(*fork), sofia_fork_destructor);
	if (!fork) return NULL;
	ast_mutex_init(&fork->lock);
	fork->children = ao2_container_alloc(8, fork_branch_hash_fn, fork_branch_cmp_fn);
	if (!fork->children) {
		ao2_ref(fork, -1);
		return NULL;
	}
	snprintf(fork->fork_id, sizeof(fork->fork_id), "fork-%lx", (unsigned long)time(NULL));
	fork->master = NULL;
	fork->winner = NULL;
	fork->winner_picked = 0;
	fork->child_count = 0;
	fork->fork_start = 0;
	fork->state = FORK_PRE_RING;
	return fork;
}

static int sofia_parse_sdp(struct sofia_pvt *pvt, sip_t const *sip);

/* ao2_callback: cancel + unlink every fork child EXCEPT the winner (passed via arg).
 * Returns CMP_MATCH to drive OBJ_UNLINK from fork->children. */
static int sofia_fork_cancel_loser_cb(void *obj, void *arg, int flags)
{
	struct sofia_pvt *child = obj;
	struct sofia_pvt *winner = arg;
	if (child == winner) {
		return 0;
	}
	if (child->nh) {
		nua_cancel(child->nh, TAG_END());
	}
	ao2_unlink(dialogs, child);
	return CMP_MATCH;
}

/* ao2_callback: cancel + unlink every fork child unconditionally.
 * Used by sofia_hangup when the master is torn down before any winner was picked. */
static int sofia_fork_cancel_all_cb(void *obj, void *arg, int flags)
{
	struct sofia_pvt *child = obj;
	if (child->nh) {
		nua_cancel(child->nh, TAG_END());
	}
	ao2_unlink(dialogs, child);
	return CMP_MATCH;
}

static int sofia_fork_pick_winner(struct sofia_fork *fork, struct sofia_pvt *child, sip_t const *sip)
{
	struct sofia_pvt *master;

	/* T37.2.5: validate the child's answer SDP BEFORE claiming winner status. If
	 * encryption policy fails, return -1 so the caller treats this child as a
	 * loser (CANCEL + unlink); other in-flight children may still answer with
	 * valid crypto. Done OUTSIDE fork->lock since parse_sdp is read-only on the
	 * fork object — it operates only on child + sip. */
	if (sip && sip->sip_payload && sip->sip_payload->pl_data) {
		if (sofia_parse_sdp(child, sip) < 0) {
			ast_log(LOG_NOTICE, "Sofia: fork-child '%s' answer rejected — encryption mismatch (peer=%s)\n",
				child->fork_branch_id,
				child->peer ? child->peer->name : "<unknown>");
			return -1;
		}
	}

	ast_mutex_lock(&fork->lock);
	if (fork->winner_picked) {
		ast_mutex_unlock(&fork->lock);
		return -1;
	}
	fork->winner_picked = 1;
	fork->winner = child;
	fork->state = FORK_WINNER_PICKED;
	ast_mutex_unlock(&fork->lock);

	master = fork->master;

	/* Move media resources from winner child to master */
	master->nh = child->nh;
	child->nh = NULL;
	nua_handle_bind(master->nh, master);

	/* Set active contact on master from winner child's ruri (sip:exten@host:port) */
	if (master->peer && !ast_strlen_zero(child->ruri)) {
		const char *at = strchr(child->ruri, '@');
		if (at) {
			char rhost[64] = "";
			int rport = 5060;
			const char *colon = strchr(at + 1, ':');
			if (colon) {
				{ int hlen = colon - (at + 1); if (hlen >= (int)sizeof(rhost)) hlen = sizeof(rhost) - 1; ast_copy_string(rhost, at + 1, hlen + 1); }
				rport = atoi(colon + 1);
			} else {
				ast_copy_string(rhost, at + 1, sizeof(rhost));
				/* strip any trailing > or params */
				char *semi = strchr(rhost, ';');
				if (semi) *semi = '\0';
			}
			struct sofia_contact *contact = sofia_peer_find_contact_by_host_port(master->peer, rhost, rport);
			if (contact) {
				sofia_pvt_set_active_contact(master, contact);
				ao2_ref(contact, -1);
			}
		}
	}

	/* post-T56 outbound RTP fd-wire-order fix R6/(a1) (2026-04-27): explicit
	 * destroy of pre-existing master->rtp/vrtp BEFORE winner-steal. Required
	 * because sofia_request_call now pre-allocates master->rtp via sofia_rtp_init
	 * (chan_sip-architectural-parity ordering); without explicit destroy the
	 * steal at the next two lines would leak the pre-fork master rtp instance.
	 * NULL-guard handles non-fork path (master->rtp may be unset on
	 * sofia_request_call alloc-fail re-tries). */
	if (master->rtp) {
		ast_rtp_instance_destroy(master->rtp);
		master->rtp = NULL;
	}
	if (master->vrtp) {
		ast_rtp_instance_destroy(master->vrtp);
		master->vrtp = NULL;
	}
	master->rtp = child->rtp;
	child->rtp = NULL;
	master->vrtp = child->vrtp;
	child->vrtp = NULL;

	/* T37.2.5: transfer SRTP context pointers from winner child to master so the
	 * master's RTP read/write paths use the validated keys. Loser children's
	 * srtp/vsrtp are freed by their own destructors (idempotent NULL guard from
	 * T37.2.2 handles the case where a loser never allocated). */
	master->srtp = child->srtp;
	child->srtp = NULL;
	master->vsrtp = child->vsrtp;
	child->vsrtp = NULL;

	/* Update master channel file descriptors from stolen RTP instances */
	if (master->owner && master->rtp) {
		master->owner->fds[0] = ast_rtp_instance_fd(master->rtp, 0);
		master->owner->fds[1] = ast_rtp_instance_fd(master->rtp, 1);
		if (master->vrtp) {
			master->owner->fds[2] = ast_rtp_instance_fd(master->vrtp, 0);
			master->owner->fds[3] = ast_rtp_instance_fd(master->vrtp, 1);
		}
	}

	/* Signal answer on master */
	if (master->owner) {
		ast_queue_control(master->owner, AST_CONTROL_ANSWER);
		ast_setstate(master->owner, AST_STATE_UP);
	}
	master->state = SOFIA_DIALOG_STATE_UP;

	ast_verbose("Sofia: Fork winner picked - branch %s for peer '%s' (%s)\n",
		child->fork_branch_id, master->peername, fork->fork_id);

	/* Cancel + unlink all losing siblings via ao2_callback (safe iterator-while-unlink). */
	ao2_callback(fork->children, OBJ_UNLINK | OBJ_MULTIPLE | OBJ_NODATA,
		sofia_fork_cancel_loser_cb, child);

	/* Winner child's resources are now on master; unlink the empty shell */
	ao2_unlink(dialogs, child);
	ao2_unlink(fork->children, child);

	return 0;
}

static struct ast_channel *sofia_request_call(const char *type, format_t format, const struct ast_channel *requestor, void *data, int *cause);
static int sofia_call(struct ast_channel *ast, char *dest, int timeout);
static int sofia_hangup(struct ast_channel *ast);
static int sofia_answer(struct ast_channel *ast);
static struct ast_frame *sofia_read(struct ast_channel *ast);
static int sofia_write(struct ast_channel *ast, struct ast_frame *frame);
static int sofia_write_video(struct ast_channel *ast, struct ast_frame *frame);
/* post-T56 SIP MESSAGE parity SS2 (2026-04-27): outbound text-message via
 * nua_message API. Mirrors chan_sip sip_sendtext at chan_sip.c:5160-5185 with
 * R6 simplification (skip is_method_allowed check; UA replies 405 if not
 * supported — best-effort send). Wired into sofia_tech.send_text below. */
static int sofia_send_text(struct ast_channel *ast, const char *text);
static int sofia_indicate(struct ast_channel *ast, int condition, const void *data, size_t datalen);
static int sofia_queryoption(struct ast_channel *chan, int option, void *data, int *datalen);
/* post-T56 allowexternaldomains forward-decl (2026-04-28): Pattern 5 helper #30
 * sofia_check_sip_domain called from sofia_process_invite (L5132+) and sofia_process_
 * refer (L8290+) which are defined BEFORE the helper definition (~L5604). Forward-decl
 * required per ADDENDUM #4 forward-decl-distance discipline (>500 LoC distance). */
static int sofia_check_sip_domain(const char *domain);
static int sofia_fixup(struct ast_channel *oldchan, struct ast_channel *newchan);
static int sofia_send_digit_begin(struct ast_channel *ast, char digit);
static int sofia_send_digit_end(struct ast_channel *ast, char digit, unsigned int duration);
static const char *sofia_get_callid(struct ast_channel *ast);

static struct ast_channel_tech sofia_tech = {
	.type = SOFIA_CHANNEL_TYPE,
	.description = "Sofia-SIP Channel Driver",
	.capabilities = AST_FORMAT_G723_1 | AST_FORMAT_GSM | AST_FORMAT_ULAW | AST_FORMAT_ALAW
			| AST_FORMAT_G726_AAL2 | AST_FORMAT_ADPCM | AST_FORMAT_SLINEAR | AST_FORMAT_LPC10
			| AST_FORMAT_G729A | AST_FORMAT_SPEEX | AST_FORMAT_ILBC | AST_FORMAT_G726
			| AST_FORMAT_G722 | AST_FORMAT_SIREN7 | AST_FORMAT_SIREN14 | AST_FORMAT_SLINEAR16
			| AST_FORMAT_G719 | AST_FORMAT_SPEEX16 | AST_FORMAT_OPUS
			| AST_FORMAT_H261 | AST_FORMAT_H263 | AST_FORMAT_H263_PLUS | AST_FORMAT_H264
			| AST_FORMAT_MP4_VIDEO | AST_FORMAT_VP8,
	.properties = AST_CHAN_TP_WANTSJITTER | AST_CHAN_TP_CREATESJITTER,
	.requester = sofia_request_call,
	.devicestate = NULL,
	.send_digit_begin = sofia_send_digit_begin,
	.send_digit_end = sofia_send_digit_end,
	.call = sofia_call,
	.hangup = sofia_hangup,
	.answer = sofia_answer,
	.read = sofia_read,
	.write = sofia_write,
	.send_text = sofia_send_text,
	.send_image = NULL,
	.send_html = NULL,
	.exception = NULL,
	.bridge = ast_rtp_instance_bridge,
	.early_bridge = ast_rtp_instance_early_bridge,
	.indicate = sofia_indicate,
	.fixup = sofia_fixup,
	.setoption = NULL,
	.queryoption = sofia_queryoption,
	.transfer = NULL,
	.write_video = sofia_write_video,
	.write_text = NULL,
	.bridged_channel = NULL,
	.func_channel_read = NULL,
	.func_channel_write = NULL,
	.get_base_channel = NULL,
	.set_base_channel = NULL,
	.get_pvt_uniqueid = sofia_get_callid,
	.cc_callback = NULL,
};

/* post-T56 Task #8 T.38 fax UDPTL parity SS2 (2026-04-28, skeleton + lifecycle):
 * ast_udptl_protocol registration mirrors chan_sip.c:3579-3582 verbatim.
 * .type="SIP" matches chan_sip per chan-sip-compat-naming-rules memory —
 * mutual-exclusive load with chan_sip prevents .type collision (only one
 * channel driver registers .type="SIP" at a time per ast_udptl_proto_register
 * uniqueness rule at main/udptl.c:1104).
 *
 * Current callbacks expose pvt->udptl while T.38 negotiation is in
 * progress or active. sofia_set_udptl_peer is intentionally a no-op for
 * now, so chan_sofia keeps UDPTL in the PBX media path instead of handing
 * direct UDPTL relay to a bridge peer. */
static struct ast_udptl *sofia_get_udptl_peer(struct ast_channel *chan);
static int sofia_set_udptl_peer(struct ast_channel *chan, struct ast_udptl *udptl);

static struct ast_udptl_protocol sofia_udptl = {
	.type = "SIP",
	.get_udptl_info = sofia_get_udptl_peer,
	.set_udptl_peer = sofia_set_udptl_peer,
};

static struct ast_udptl *sofia_get_udptl_peer(struct ast_channel *chan)
{
	/* post-T56 Task #8 T.38 fax UDPTL parity SS3a (2026-04-28): return
	 * pvt->udptl when T.38 negotiation is in progress or active. Mirrors
	 * chan_sip.c:30387 sip_get_udptl_peer pattern semantically — chan_sip
	 * gates on SIP_PAGE2_T38SUPPORT flag + p->udptl non-NULL; chan_sofia
	 * gates on t38_state >= PEER_REINVITE (which already implies udptl
	 * allocated by sofia_parse_sdp lazy-create). NULL means no UDPTL
	 * session is available. Direct UDPTL transfer is not enabled by
	 * sofia_set_udptl_peer(), so the PBX remains in the media path.
	 *
	 * SS3a.1 C4 audit fold-in (2026-04-28): pvt->lock taken around state +
	 * udptl reads per chan_sip.c:30406 sip_pvt_lock parity. Race window was
	 * narrow on x86_64 (single-pointer reads word-atomic) but lock-discipline
	 * divergence flagged by 4th-pass parallel-audit. Lock dropped before
	 * return so caller doesn't see chan_sofia mutex held. */
	struct sofia_pvt *pvt;
	struct ast_udptl *udptl_local;
	int state_local;

	if (!chan) {
		return NULL;
	}
	pvt = chan->tech_pvt;
	if (!pvt) {
		return NULL;
	}
	ast_mutex_lock(&pvt->lock);
	state_local = pvt->t38_state;
	udptl_local = pvt->udptl;
	ast_mutex_unlock(&pvt->lock);

	if (state_local >= SOFIA_T38_PEER_REINVITE && udptl_local) {
		return udptl_local;
	}
	return NULL;
}

static int sofia_set_udptl_peer(struct ast_channel *chan, struct ast_udptl *udptl)
{
	/* Direct UDPTL transfer is not enabled here. Return success so the core
	 * keeps the PBX relay path rather than treating this as a driver error. */
	(void)chan;
	(void)udptl;
	return 0;
}

/* post-T56 Task #8 T.38 fax UDPTL parity SS4 (2026-04-28, LOAD-BEARING per
 * SS1.5 N1+N2+N5 audit findings + S3 MIN-clamp): forward declarations for
 * 3-helper SS4 cluster — sofia_change_t38_state (Pattern 5 #43) +
 * sofia_interpret_t38_parameters (Pattern 5 #44) + sofia_t38_abort (5s
 * timer callback). Defined immediately below; forward-decl needed because
 * sofia_t38_abort references sofia_change_t38_state which appears AFTER it. */
static void sofia_change_t38_state(struct sofia_pvt *pvt, int new_state);
static int sofia_interpret_t38_parameters(struct sofia_pvt *pvt, const struct ast_control_t38_parameters *parameters);
static int sofia_t38_abort(const void *data);

/* sofia_change_t38_state — Pattern 5 #43 (chan_sip.c:5765-5811 verbatim
 * mirror). 4-state machine T38_DISABLED ↔ LOCAL_REINVITE / PEER_REINVITE
 * ↔ ENABLED. Queues AST_CONTROL_T38_PARAMETERS frame for 3 of 4 states
 * (LOCAL_REINVITE silent — chan_sip.c:5803 verbatim "wait until we get a
 * peer response" semantic per SS1.5 N5 audit correction). max_ifp wired
 * via ast_udptl_get_far_max_ifp on PEER_REINVITE + ENABLED transitions
 * per SS1.5 N1 LOAD-BEARING (chan_sip.c:5786, 5792). ast_udptl_set_tag
 * on every transition for log-correlation per SS1.5 N4 (chan_sip.c:5788,
 * 5794). */
static void sofia_change_t38_state(struct sofia_pvt *pvt, int new_state)
{
	int old;
	struct ast_control_t38_parameters parameters = { .request_response = 0 };
	struct ast_channel *chan;

	if (!pvt) {
		return;
	}
	/* SS4.1 BUG#4 audit fold-in (2026-04-28): idempotency early-out per
	 * chan_sip.c:5772-5773 verbatim "Don't bother changing if we are already
	 * in the state wanted". Without this gate, re-entering same state queues
	 * duplicate AST_CONTROL_T38_PARAMETERS frames to channel — app_fax/res_fax
	 * may double-process. */
	if (pvt->t38_state == new_state) {
		return;
	}
	chan = pvt->owner;
	if (!chan) {
		return;
	}
	old = pvt->t38_state;
	pvt->t38_state = new_state;
	ast_debug(2, "Sofia: T.38 state changed to %d on channel %s\n", new_state, chan->name);

	switch (new_state) {
	case SOFIA_T38_PEER_REINVITE:
		parameters = pvt->t38_their_parms;
		if (pvt->udptl) {
			parameters.max_ifp = ast_udptl_get_far_max_ifp(pvt->udptl);
			ast_udptl_set_tag(pvt->udptl, "%s", chan->name);
		}
		parameters.request_response = AST_T38_REQUEST_NEGOTIATE;
		break;
	case SOFIA_T38_ENABLED:
		parameters = pvt->t38_their_parms;
		if (pvt->udptl) {
			parameters.max_ifp = ast_udptl_get_far_max_ifp(pvt->udptl);
			ast_udptl_set_tag(pvt->udptl, "%s", chan->name);
		}
		parameters.request_response = AST_T38_NEGOTIATED;
		break;
	case SOFIA_T38_DISABLED:
		if (old == SOFIA_T38_ENABLED) {
			parameters.request_response = AST_T38_TERMINATED;
		} else if (old == SOFIA_T38_LOCAL_REINVITE) {
			parameters.request_response = AST_T38_REFUSED;
		}
		break;
	case SOFIA_T38_LOCAL_REINVITE:
		/* wait until we get a peer response before responding to local reinvite */
		break;
	}

	/* Queue control frame only when request_response set — chan_sip.c:5810
	 * verbatim gate. LOCAL_REINVITE leaves it 0 → no queue. */
	if (parameters.request_response) {
		ast_queue_control_data(chan, AST_CONTROL_T38_PARAMETERS, &parameters, sizeof(parameters));
	}

	/* post-T56 Task #8 T.38 fax UDPTL parity SS6 (2026-04-28, helper-arch-
	 * advantage 32nd-dimension NEW DIMENSION AMI-T38-event-chan_sip-silent-
	 * surpass): emit AMI T38FaxNegotiation event on every T.38 state
	 * transition. chan_sip is SILENT on AMI for T.38 transitions (verified
	 * via grep — 0 hits manager_event.*T38 in chan_sip.c + apps/app_fax.c +
	 * res/res_fax.c). chan_sofia surpass dimension via direct manager_event
	 * emit at single helper site (vs chan_sip per-callsite which would
	 * require 4-state × N-callsites duplication). EVENT_FLAG_SYSTEM per
	 * c293e54 alwaysauthreject precedent (this fork lacks
	 * EVENT_FLAG_SECURITY). Format mirrors AMI Hold (T35) + AMI Registry
	 * (T35) + AMI MWI (T55) chan_sofia-surpass series — `ChannelType: SIP`
	 * + Channel + Uniqueid + Peer + State (DISABLED/LOCAL_REINVITE/
	 * PEER_REINVITE/ENABLED) + RequestResponse (chan_sip enum dispatch
	 * value) + MaxIfp + MaxDatagram + Version + RateManagement + EC. */
	{
		const char *state_str = "Unknown";
		const char *rr_str = "None";
		const char *rm_str = "transferredTCF";
		const char *ec_str = "None";
		switch (new_state) {
		case SOFIA_T38_DISABLED:       state_str = "Disabled";       break;
		case SOFIA_T38_LOCAL_REINVITE: state_str = "LocalReinvite";  break;
		case SOFIA_T38_PEER_REINVITE:  state_str = "PeerReinvite";   break;
		case SOFIA_T38_ENABLED:        state_str = "Enabled";        break;
		}
		switch (parameters.request_response) {
		case AST_T38_REQUEST_NEGOTIATE: rr_str = "RequestNegotiate"; break;
		case AST_T38_REQUEST_TERMINATE: rr_str = "RequestTerminate"; break;
		case AST_T38_NEGOTIATED:        rr_str = "Negotiated";       break;
		case AST_T38_TERMINATED:        rr_str = "Terminated";       break;
		case AST_T38_REFUSED:           rr_str = "Refused";          break;
		case AST_T38_REQUEST_PARMS:     rr_str = "RequestParms";     break;
		}
		if (parameters.rate_management == AST_T38_RATE_MANAGEMENT_LOCAL_TCF) {
			rm_str = "localTCF";
		}
		if (pvt->udptl) {
			switch (ast_udptl_get_error_correction_scheme(pvt->udptl)) {
			case UDPTL_ERROR_CORRECTION_FEC:        ec_str = "FEC";        break;
			case UDPTL_ERROR_CORRECTION_REDUNDANCY: ec_str = "Redundancy"; break;
			case UDPTL_ERROR_CORRECTION_NONE:       ec_str = "None";       break;
			}
		}
		manager_event(EVENT_FLAG_SYSTEM, "T38FaxNegotiation",
			/* SS7 BUG #1 fix (2026-04-28): chan_sip_compat policy parity per
			 * chan-sip-compat-naming-rules.md GOLDEN RULE — all 14 other
			 * chan_sofia AMI sites emit "ChannelType: SIP" not "Sofia"; SS6
			 * doxygen claim of T35/T55 "Sofia" precedent was incorrect. */
			"ChannelType: SIP\r\n"
			"Channel: %s\r\n"
			"Uniqueid: %s\r\n"
			"Peer: SIP/%s\r\n"
			"State: %s\r\n"
			"RequestResponse: %s\r\n"
			"MaxIfp: %u\r\n"
			"MaxDatagram: %u\r\n"
			"Version: %u\r\n"
			"RateManagement: %s\r\n"
			"EC: %s\r\n",
			chan->name,
			chan->uniqueid,
			(pvt->peer && pvt->peer->name) ? pvt->peer->name : "<unknown>",
			state_str,
			rr_str,
			parameters.max_ifp,
			pvt->udptl ? ast_udptl_get_local_max_datagram(pvt->udptl) : 0,
			parameters.version,
			rm_str,
			ec_str);
	}
}

/* sofia_interpret_t38_parameters — Pattern 5 #44 (chan_sip.c:7485-7563
 * verbatim mirror). 6-op dispatcher invoked from sofia_indicate
 * AST_CONTROL_T38_PARAMETERS case. Handles app_fax/res_fax requests:
 *   AST_T38_REQUEST_NEGOTIATE → move local state toward T.38
 *   AST_T38_REQUEST_TERMINATE → move local state away from T.38
 *   AST_T38_NEGOTIATED → peer accepted (PEER_REINVITE → ENABLED)
 *   AST_T38_TERMINATED → peer dropped session
 *   AST_T38_REFUSED → peer rejected offer
 *   AST_T38_REQUEST_PARMS → fax stack queries far-end advertised parms
 * SS1.5 N1 max_ifp REJECTION GATE (chan_sip.c:7496): max_ifp == 0 →
 * change_t38_state(DISABLED). SS1.5 S3 MIN-clamp on version
 * (chan_sip.c:7518). This helper owns state and parameter updates only:
 * peer-offer acceptance uses the existing response/SDP path, while
 * app-originated outbound T.38 reINVITE transmission is not emitted here. */
static int sofia_interpret_t38_parameters(struct sofia_pvt *pvt, const struct ast_control_t38_parameters *parameters)
{
	int res = 0;

	if (!pvt || !pvt->peer || !pvt->peer->t38pt_udptl || !pvt->udptl) {
		return -1;
	}

	switch (parameters->request_response) {
	case AST_T38_NEGOTIATED:
	case AST_T38_REQUEST_NEGOTIATE:
		if (parameters->max_ifp == 0) {
			/* SS1.5 N1 LOAD-BEARING REJECTION GATE — chan_sip.c:7496 verbatim */
			sofia_change_t38_state(pvt, SOFIA_T38_DISABLED);
			/* SS4.1 BUG#1 audit fold-in (2026-04-28): cancel t38id 5s timer
			 * per chan_sip.c:7499 verbatim ("when you delete the t38id sched,
			 * you should dec the refcount for the stored dialog ptr").
			 * Pattern 14 verbatim-mirror discipline — without this cancel,
			 * scheduler holds dangling 5s ghost ref per fax flow. */
			if (pvt->t38_state == SOFIA_T38_PEER_REINVITE && pvt->t38id != -1 && sofia_sched) {
				if (ast_sched_thread_del(sofia_sched, pvt->t38id) == 0) {
					ao2_ref(pvt, -1);
				}
				pvt->t38id = -1;
			}
		} else if (pvt->t38_state == SOFIA_T38_PEER_REINVITE) {
			/* SS4.1 BUG#1 audit fold-in (2026-04-28): cancel t38id 5s timer
			 * per chan_sip.c:7504 verbatim — accepting peer offer, no longer
			 * need timeout. */
			if (pvt->t38id != -1 && sofia_sched) {
				if (ast_sched_thread_del(sofia_sched, pvt->t38id) == 0) {
					ao2_ref(pvt, -1);
				}
				pvt->t38id = -1;
			}
			/* Peer offered T.38; app_fax accepts. Merge our_parms with
			 * their_parms per chan_sip.c:7505-7521 verbatim semantic. */
			pvt->t38_our_parms = *parameters;
			if (!pvt->t38_their_parms.fill_bit_removal) {
				pvt->t38_our_parms.fill_bit_removal = 0;
			}
			if (!pvt->t38_their_parms.transcoding_mmr) {
				pvt->t38_our_parms.transcoding_mmr = 0;
			}
			if (!pvt->t38_their_parms.transcoding_jbig) {
				pvt->t38_our_parms.transcoding_jbig = 0;
			}
			/* SS1.5 S3 MIN-clamp version per RFC 3362 + chan_sip.c:7518 verbatim */
			pvt->t38_our_parms.version = MIN(pvt->t38_our_parms.version, pvt->t38_their_parms.version);
			pvt->t38_our_parms.rate_management = pvt->t38_their_parms.rate_management;
			ast_udptl_set_local_max_ifp(pvt->udptl, pvt->t38_our_parms.max_ifp);
			sofia_change_t38_state(pvt, SOFIA_T38_ENABLED);
			/* Peer-offer acceptance: state is now enabled, and response SDP
			 * generation can include the T.38 block because pvt->udptl exists. */
		} else if (pvt->t38_state != SOFIA_T38_ENABLED) {
			/* app_fax requests outbound T.38 reINVITE (voice → fax). */
			pvt->t38_our_parms = *parameters;
			ast_udptl_set_local_max_ifp(pvt->udptl, pvt->t38_our_parms.max_ifp);
			sofia_change_t38_state(pvt, SOFIA_T38_LOCAL_REINVITE);
			/* Local fax stack requested T.38. This records LOCAL_REINVITE state;
			 * the outbound SIP reINVITE is not sent by this helper. */
		}
		break;
	case AST_T38_TERMINATED:
	case AST_T38_REFUSED:
	case AST_T38_REQUEST_TERMINATE:
		if (pvt->t38_state == SOFIA_T38_PEER_REINVITE) {
			/* SS4.1 BUG#1 audit fold-in (2026-04-28): cancel t38id 5s timer
			 * per chan_sip.c:7538 verbatim — fax stack rejecting peer offer. */
			if (pvt->t38id != -1 && sofia_sched) {
				if (ast_sched_thread_del(sofia_sched, pvt->t38id) == 0) {
					ao2_ref(pvt, -1);
				}
				pvt->t38id = -1;
			}
			sofia_change_t38_state(pvt, SOFIA_T38_DISABLED);
		} else if (pvt->t38_state == SOFIA_T38_ENABLED) {
			sofia_change_t38_state(pvt, SOFIA_T38_LOCAL_REINVITE);
		}
		break;
	case AST_T38_REQUEST_PARMS:
		/* fax stack asks "what did the far end advertise?" — return
		 * their_parms via control frame per chan_sip.c:7547-7553. */
		if (pvt->t38_state == SOFIA_T38_PEER_REINVITE) {
			struct ast_control_t38_parameters reply;
			/* SS4.1 BUG#1 audit fold-in (2026-04-28): cancel t38id 5s timer
			 * per chan_sip.c:7548 verbatim — fax stack acknowledging
			 * negotiation; timeout no longer needed. */
			if (pvt->t38id != -1 && sofia_sched) {
				if (ast_sched_thread_del(sofia_sched, pvt->t38id) == 0) {
					ao2_ref(pvt, -1);
				}
				pvt->t38id = -1;
			}
			reply = pvt->t38_their_parms;
			reply.max_ifp = ast_udptl_get_far_max_ifp(pvt->udptl);
			reply.request_response = AST_T38_REQUEST_PARMS;
			res = ast_queue_control_data(pvt->owner, AST_CONTROL_T38_PARAMETERS,
				&reply, sizeof(reply));
			return res;
		}
		break;
	}
	return res;
}

/* sofia_t38_abort — 5-second reINVITE timeout callback per SS1.5 N2
 * LOAD-BEARING audit catch (chan_sip.c:23384-23398 sip_t38_abort verbatim
 * mirror). Without this timer, peers that fail to ack the 200 OK leave
 * chan_sofia stuck in T38_PEER_REINVITE forever. Returns 0 = don't
 * reschedule (one-shot). Drops the ao2 ref taken at ast_sched_thread_add.
 * Locks pvt for state read; releases before queue (avoids deadlock with
 * channel-locks in ast_queue_control_data). */
static int sofia_t38_abort(const void *data)
{
	struct sofia_pvt *pvt = (struct sofia_pvt *)data;
	int do_disable = 0;

	if (!pvt) {
		return 0;
	}

	/* SS4.1 BUG#2 audit fold-in (2026-04-28): TOCTOU fix on pvt->owner +
	 * pvt->t38_state read-then-act pattern. Pre-fix: lock state read;
	 * unlock; sofia_change_t38_state re-reads pvt->owner + pvt->t38_state
	 * WITHOUT lock — racy if sofia_hangup nulls pvt->owner between unlock
	 * and call. chan_sip.c:23388-23400 holds sip_pvt_lock across entire
	 * callback. chan_sofia mirrors by re-taking pvt->lock around
	 * sofia_change_t38_state — sofia_change_t38_state itself doesn't take
	 * pvt->lock so no recursion; ast_queue_control_data inside is
	 * channel-lock not pvt-lock so no deadlock with held pvt->lock. */
	{
		int was_peer_reinvite = 0;
		ast_mutex_lock(&pvt->lock);
		if (pvt->t38id != -1) {
			pvt->t38id = -1;
			if (pvt->t38_state == SOFIA_T38_PEER_REINVITE ||
			    pvt->t38_state == SOFIA_T38_LOCAL_REINVITE) {
				ast_log(LOG_NOTICE, "Sofia: T.38 reINVITE timeout (5s) on channel %s — aborting\n",
					pvt->owner ? pvt->owner->name : "<no-owner>");
				do_disable = 1;
				was_peer_reinvite = (pvt->t38_state == SOFIA_T38_PEER_REINVITE);
			}
		}
		if (do_disable) {
			/* Hold pvt->lock across state change to prevent owner-null TOCTOU. */
			sofia_change_t38_state(pvt, SOFIA_T38_DISABLED);
			/* SS5 D1 audit fold-in (2026-04-28): emit 488 Not Acceptable Here
			 * to peer when aborting T38_PEER_REINVITE per chan_sip.c:23396
			 * verbatim semantic (chan_sip transmit_response_reliable 488).
			 * Only fires for PEER_REINVITE (NOT LOCAL_REINVITE) since
			 * LOCAL_REINVITE means we sent re-INVITE — peer either responds
			 * or we time out without 488 emission. nua_respond plain
			 * status-phrase per sofia-sip-quirks SIPTAG_REASON_STR-causes-500
			 * catalog avoidance. */
			if (was_peer_reinvite && pvt->nh) {
				nua_respond(pvt->nh, 488, "Not Acceptable Here", TAG_END());
			}
		}
		ast_mutex_unlock(&pvt->lock);
	}

	/* Drop the ref taken when scheduling */
	ao2_ref(pvt, -1);
	return 0;
}

/* Mark this dialog as "already gone" so a late 2xx arriving for it can be
 * recognised in the nua_r_invite status==200 branch and handled via the
 * orphan ACK+BYE path per RFC 3261 §13.2.2.4 / RFC 6026.  Mirrors chan_sip's
 * sip_alreadygone() helper at chan_sip.c:3637-3640.  Called from the non-2xx
 * final response paths in sofia_event_callback case nua_r_invite (status 484
 * special-case + status >= 300 catch-all) so the flag is set BEFORE the
 * channel hangup races with the late 2xx, and from anywhere else the dialog
 * has been irrevocably abandoned (e.g. local pre-answer hangup). */
static void sofia_alreadygone(struct sofia_pvt *pvt)
{
	if (!pvt) {
		return;
	}
	ast_debug(3, "Sofia: setting alreadygone on dialog %s\n",
		pvt->callid ? pvt->callid : "(no-callid)");
	pvt->alreadygone = 1;
}

/* Safety-net timer for REFER transferer-leg BYE deferral. Mirrors the
 * `sip_scheddestroy(p, DEFAULT_TRANS_TIMEOUT)` path at chan_sip.c:7058. After
 * we send the terminal NOTIFY 200 OK for a transfer, sofia_hangup leaves the
 * SIP dialog alive so the transferer's UA can BYE per RFC 5589 §6.1. If no
 * BYE arrives within SOFIA_DEFER_BYE_TIMEOUT_MS this callback fires nua_bye
 * itself so we don't leak the dialog. Returns 0 = one-shot. Drops the ao2 ref
 * taken at ast_sched_thread_add. */
static int sofia_defer_bye_cb(const void *data)
{
	struct sofia_pvt *pvt = (struct sofia_pvt *)data;

	if (!pvt) {
		return 0;
	}

	ast_mutex_lock(&pvt->lock);
	pvt->defer_bye_sched_id = -1;
	if (pvt->defer_bye && pvt->nh) {
		char target_url[256];
		int use_target = sofia_pvt_build_nat_target_url(pvt, target_url, sizeof(target_url));
		ast_log(LOG_NOTICE, "Sofia: transferer-leg BYE deferral timed out (%dms) — "
			"sending nua_bye on call-id %s\n",
			SOFIA_DEFER_BYE_TIMEOUT_MS,
			pvt->callid ? pvt->callid : "(none)");
		nua_bye(pvt->nh,
			TAG_IF(use_target, NUTAG_PROXY(target_url)),
			TAG_END());
	}
	pvt->defer_bye = 0;
	pvt->state = SOFIA_DIALOG_STATE_DOWN;
	ast_mutex_unlock(&pvt->lock);

	/* Drop the dialog-container ref so the pvt is collected once sofia-sip
	 * finishes processing the outbound BYE we just queued. */
	ao2_unlink(dialogs, pvt);

	/* Drop the ref we took when we scheduled. */
	ao2_ref(pvt, -1);
	return 0;
}

/* post-T56 inband DTMF/fax tone detect parity (2026-04-27/2026-04-28):
 * allocate ast_dsp and configure it for incoming audio tone detection.
 * Mirrors chan_sip enable_dsp_detect at chan_sip.c:4929-4961 for DTMF,
 * and also enables DSP fax CNG detection when faxdetect=cng is configured.
 *
 * R9 early-return idempotency: helper safe to call multiple times — second
 * call returns no-op if pvt->dsp already allocated (chan_sip L4933-4935
 * parity). Prevents double-allocation on race between sofia_call entry
 * + sofia_process_invite entry on forked outbound peer.
 *
 * R2 gate: DSP allocation requires inband/auto DTMF mode or fax CNG
 * detection. INBAND/AUTO matches chan_sip at L4937-4938; fax-CNG uses
 * the same DSP instance with DSP_FEATURE_FAX_DETECT.
 *
 * Caller must ensure pvt->rtp bound (R4 — wire-in AFTER rtp_init in
 * sofia_call/sofia_process_invite). Defensive NULL-check kept for safety. */
static void sofia_enable_dsp_detect(struct sofia_pvt *pvt)
{
	int features = 0;
	int dtmf_inband = 0;
	int fax_cng = 0;

	if (!pvt || pvt->dsp) {
		return;
	}
	if (!pvt->rtp) {
		return;
	}

	dtmf_inband = (pvt->dtmfmode == SOFIA_DTMF_INBAND || pvt->dtmfmode == SOFIA_DTMF_AUTO);
	/* post-T56 Task #8 T.38 fax UDPTL parity SS6 (2026-04-28): DSP
	 * fax-CNG tone detection is enabled when peer has faxdetect=cng
	 * (or cng,t38). Mirrors
	 * chan_sip.c:4945-4946 verbatim semantic — `if (...FAX_DETECT_CNG)
	 * features |= DSP_FEATURE_FAX_DETECT`. CNG detection emits AST_FRAME_DTMF
	 * subclass 'f' on inbound audio → sofia_read post-DSP path async-gotos
	 * channel to "fax" extension per chan_sip.c:8288 verbatim semantic. */
	if (pvt->peer && (pvt->peer->faxdetect_mode & SOFIA_FAX_DETECT_CNG)) {
		fax_cng = 1;
	}

	if (!dtmf_inband && !fax_cng) {
		return;
	}

	if (dtmf_inband) {
		ast_rtp_instance_dtmf_mode_set(pvt->rtp, AST_RTP_DTMF_MODE_INBAND);
		features |= DSP_FEATURE_DIGIT_DETECT;
	}
	if (fax_cng) {
		features |= DSP_FEATURE_FAX_DETECT;
	}

	if (!(pvt->dsp = ast_dsp_new())) {
		return;
	}
	ast_dsp_set_features(pvt->dsp, features);
	/* post-T56 relaxdtmf parity (2026-04-27): chan_sip parity at chan_sip.c:4958-4960
	 * verbatim — apply DSP_DIGITMODE_RELAXDTMF flag when sofia_cfg.relaxdtmf set
	 * (relaxes threshold for poor-quality line DTMF detection). chan_sofia
	 * ARCHITECTURAL ADVANTAGE 4th-instance: single helper internal extension.
	 * SS6 (2026-04-28): only set DTMF mode when DTMF detection is enabled
	 * (fax-only path skips digitmode setup since no DTMF processing needed). */
	if (dtmf_inband) {
		ast_dsp_set_digitmode(pvt->dsp, DSP_DIGITMODE_DTMF |
			(sofia_cfg.relaxdtmf ? DSP_DIGITMODE_RELAXDTMF : 0));
	}
}

/* post-T56 inband DTMF detect parity (2026-04-27): release ast_dsp.
 * Mirrors chan_sip disable_dsp_detect at chan_sip.c:4963-4969. NULL-safe.
 * Single-callsite from sofia_pvt_destructor (R5). */
static void sofia_disable_dsp_detect(struct sofia_pvt *pvt)
{
	if (pvt && pvt->dsp) {
		ast_dsp_free(pvt->dsp);
		pvt->dsp = NULL;
	}
}

static int sofia_rtp_init(struct sofia_pvt *pvt)
{
	struct ast_sockaddr addr;

	if (pvt->rtp) {
		return 0;
	}

	ast_sockaddr_parse(&addr, sofia_cfg.bindaddr, 0);
	pvt->rtp = ast_rtp_instance_new("gabpbx", NULL, &addr, NULL);
	if (!pvt->rtp) {
		ast_log(LOG_ERROR, "Failed to create RTP instance for Sofia\n");
		return -1;
	}

	ast_rtp_instance_set_prop(pvt->rtp, AST_RTP_PROPERTY_NAT, 1);
	ast_rtp_instance_dtmf_mode_set(pvt->rtp, AST_RTP_DTMF_MODE_RFC2833);

	if (!pvt->vrtp && (pvt->capability & AST_FORMAT_VIDEO_MASK)) {
		pvt->vrtp = ast_rtp_instance_new("gabpbx", NULL, &addr, NULL);
		if (pvt->vrtp) {
			ast_rtp_instance_set_prop(pvt->vrtp, AST_RTP_PROPERTY_RTCP, 1);
		}
	}

	/* post-T56 tos/cos bundle [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:5888 verbatim — apply audio QoS markings (TOS/DSCP at L3 +
	 * 802.1p CoS at L2) to RTP audio instance via gabpbx-core API
	 * ast_rtp_instance_set_qos (rtp_engine.h:1311). Same for video on pvt->vrtp.
	 * tos/cos values are unsigned int; ast_rtp_instance_set_qos signature accepts
	 * int — cast for API conformance. .193 production sofia.conf line tos_audio=ef
	 * + tos_video=af41 finally honored on next reload (REAL OPERATOR DRIVER). */
	if (sofia_cfg.tos_audio || sofia_cfg.cos_audio) {
		ast_rtp_instance_set_qos(pvt->rtp, (int)sofia_cfg.tos_audio,
			(int)sofia_cfg.cos_audio, "Sofia RTP audio");
	}
	if (pvt->vrtp && (sofia_cfg.tos_video || sofia_cfg.cos_video)) {
		ast_rtp_instance_set_qos(pvt->vrtp, (int)sofia_cfg.tos_video,
			(int)sofia_cfg.cos_video, "Sofia RTP video");
	}

	/* post-T56 rtp-timeout bundle per-peer parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:5862-5864 + L5880-5882 verbatim — apply per-peer RTP timeouts +
	 * keepalive via gabpbx-core APIs (rtp_engine.h:1671/1689/1707). Each non-zero
	 * value enables the respective behavior on the RTP instance: rtptimeout drops
	 * stream after N seconds with no inbound RTP; rtpholdtimeout same but for
	 * on-hold state; rtpkeepalive sends periodic keepalive packets. .193 production
	 * sofia.conf rtptimeout=30 + rtpholdtimeout=300 finally honored on next reload. */
	if (pvt->peer) {
		if (pvt->peer->rtptimeout > 0) {
			ast_rtp_instance_set_timeout(pvt->rtp, pvt->peer->rtptimeout);
			if (pvt->vrtp) {
				ast_rtp_instance_set_timeout(pvt->vrtp, pvt->peer->rtptimeout);
			}
		}
		if (pvt->peer->rtpholdtimeout > 0) {
			ast_rtp_instance_set_hold_timeout(pvt->rtp, pvt->peer->rtpholdtimeout);
			if (pvt->vrtp) {
				ast_rtp_instance_set_hold_timeout(pvt->vrtp, pvt->peer->rtpholdtimeout);
			}
		}
		if (pvt->peer->rtpkeepalive > 0) {
			ast_rtp_instance_set_keepalive(pvt->rtp, pvt->peer->rtpkeepalive);
			if (pvt->vrtp) {
				ast_rtp_instance_set_keepalive(pvt->vrtp, pvt->peer->rtpkeepalive);
			}
		}
	}

	return 0;
}

static char *sofia_generate_sdp(struct sofia_pvt *pvt, char *buf, size_t len)
{
	struct ast_sockaddr rtp_addr;
	struct ast_sockaddr dest_addr;
	const char *sdp_family;
	char host[128];
	int port;
	/* Step A IPv6 parity SS2 (2026-04-28): sockaddr_storage handles both
	 * AF_INET (16 bytes) + AF_INET6 (28 bytes); was struct sockaddr_in
	 * IPv4-only (16 bytes) which silently truncated IPv6 getsockname result.
	 * Family-aware extraction below dispatches on ss_family. */
	struct sockaddr_storage sin;
	socklen_t sinlen = sizeof(sin);
	char payload_buf[512] = "";
	char rtpmap_buf[2048] = "";
	char tmp_buf[128];
	int first = 1;
	int i;
	format_t fmt;
	format_t emitted = 0;

	if (!pvt || !pvt->rtp) {
		return NULL;
	}

	/* Get local address from RTP fd. Step A IPv6 parity SS2: sockaddr_storage
	 * + ss_family dispatch (was AF_INET-hardcoded; broke IPv6 RTP socket case). */
	if (getsockname(ast_rtp_instance_fd(pvt->rtp, 0),
			(struct sockaddr *)&sin, &sinlen) == 0) {
		if (sin.ss_family == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&sin;
			inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof(host));
			port = ntohs(sin6->sin6_port);
		} else {
			struct sockaddr_in *sin4 = (struct sockaddr_in *)&sin;
			inet_ntop(AF_INET, &sin4->sin_addr, host, sizeof(host));
			port = ntohs(sin4->sin_port);
		}
	} else {
		ast_rtp_instance_get_local_address(pvt->rtp, &rtp_addr);
		ast_copy_string(host, ast_sockaddr_stringify_host(&rtp_addr), sizeof(host));
		/* post-T56 fallback-port=0 fix (2026-04-27): when getsockname() fails
		 * (transient RTP fd state during reload, SDP renegotiation timing),
		 * earlier code set port=0 → SDP m= line emitted "m=audio 0" which RFC 4566
		 * §5.14 means "no media this leg" — peer accepts but RTP never flows.
		 * ast_sockaddr_port reads the bound port from the resolved sockaddr. */
		port = ast_sockaddr_port(&rtp_addr);
	}

	/* post-T56 outbound-headers parity (2026-04-27): R5 4-priority host chain.
	 * Drops the previous `pvt->peer->registered &&` gate which only fired for
	 * dynamic+registered peers — outbound-to-static-trunk (host=upstream.example.com)
	 * never hit it, leaving SDP c= line as 0.0.0.0 from the bound socket.
	 * Priority (highest wins, evaluated bottom-up so later clauses override earlier):
	 *   (1) getsockname() / rtp instance local addr — set above (fallback)
	 *   (2) pvt->ourip — outbound flows: kernel-routed source IP from sofia_resolve_ourip
	 *   (3) Externaddr — sofia_should_use_externaddr(target) WITHOUT registered gate
	 *   (4) Direct media (pvt->redirip) — bridged peer's RTP target wins over all
	 * Inbound flows: pvt->ourip stays zero (R2 helper only fires from sofia_request_call),
	 * pvt->peer may be NULL or peer->src_addr unset — falls through to (1) cleanly. */
	if (pvt && !ast_sockaddr_isnull(&pvt->ourip)) {
		ast_copy_string(host, ast_sockaddr_stringify_host(&pvt->ourip), sizeof(host));
	}

	/* NAT: substitute externaddr when target is outside localnet (no registered gate). */
	if (pvt->peer && !ast_sockaddr_isnull(&pvt->peer->src_addr)
			&& sofia_should_use_externaddr(&pvt->peer->src_addr)
			&& !ast_strlen_zero(sofia_cfg.externaddr)) {
		ast_copy_string(host, sofia_cfg.externaddr, sizeof(host));
	}

	/* Direct media: redirect c=/port to the bridged peer's RTP target.
	 * Set by sofia_set_rtp_peer when ast_rtp_glue picks remote bridging.
	 * Wins over local socket, ourip, and externaddr overrides. */
	if (!ast_sockaddr_isnull(&pvt->redirip)) {
		ast_copy_string(host, ast_sockaddr_stringify_host(&pvt->redirip), sizeof(host));
		port = ast_sockaddr_port(&pvt->redirip);
	}

	/* Iterate codecs in preference order */
	for (i = 0; (fmt = ast_codec_pref_index(&pvt->prefs, i)); i++) {
		int pt;
		const char *enc;
		unsigned int rate;
		int channels = 0;
		if (!(fmt & pvt->capability) || !(fmt & AST_FORMAT_AUDIO_MASK))
			continue;
		pt = ast_rtp_codecs_payload_code(ast_rtp_instance_get_codecs(pvt->rtp), 1, fmt);
		if (pt < 0)
			continue;
		enc = ast_rtp_lookup_mime_subtype2(1, fmt, 0);
		rate = ast_rtp_lookup_sample_rate2(1, fmt);
		if (fmt == AST_FORMAT_OPUS)
			channels = 2;
		if (!first)
			strcat(payload_buf, " ");
		snprintf(tmp_buf, sizeof(tmp_buf), "%d", pt);
		strcat(payload_buf, tmp_buf);
		first = 0;
		if (channels)
			snprintf(tmp_buf, sizeof(tmp_buf), "a=rtpmap:%d %s/%u/%d\r\n", pt, enc, rate, channels);
		else
			snprintf(tmp_buf, sizeof(tmp_buf), "a=rtpmap:%d %s/%u\r\n", pt, enc, rate);
		strcat(rtpmap_buf, tmp_buf);
		/* fmtp for specific codecs */
		if (fmt == AST_FORMAT_G729A) {
			snprintf(tmp_buf, sizeof(tmp_buf), "a=fmtp:%d annexb=no\r\n", pt);
			strcat(rtpmap_buf, tmp_buf);
		} else if (fmt == AST_FORMAT_OPUS) {
			snprintf(tmp_buf, sizeof(tmp_buf), "a=fmtp:%d useinbandfec=1;usedtx=0\r\n", pt);
			strcat(rtpmap_buf, tmp_buf);
		} else if (fmt == AST_FORMAT_ILBC) {
			snprintf(tmp_buf, sizeof(tmp_buf), "a=fmtp:%d mode=20\r\n", pt);
			strcat(rtpmap_buf, tmp_buf);
		}
		emitted |= fmt;
		/* post-T56 preferred_codec_only per-peer parity (2026-04-28): chan_sip parity at
		 * chan_sip.c:10076 verbatim semantic — narrow to single most-preferred codec.
		 * chan_sofia ARCHITECTURAL ADVANTAGE 12th-instance Option 6-A: applies to BOTH
		 * initial-INVITE-offer + response paths (chan_sip narrows RESPONSE-direction only
		 * at process_sdp); chan_sofia centralized direction-symmetric narrowing via
		 * single sofia_generate_sdp helper site. After first successful emission, break
		 * the prefs loop (and skip fallback loop) so only the single most-preferred
		 * codec appears in the m=audio rtpmap list. */
		if (pvt->peer && pvt->peer->preferred_codec_only) {
			break;
		}
	}

	/* Fallback: emit any remaining capability bits not in prefs.
	 * post-T56 preferred_codec_only per-peer parity (2026-04-28): skip fallback when
	 * narrowing — single-codec semantic preserves chan_sip "single most preferred"
	 * intent verbatim (chan_sip.c:10076). */
	for (fmt = 1; fmt && !(pvt->peer && pvt->peer->preferred_codec_only); fmt <<= 1) {
		int pt;
		const char *enc;
		unsigned int rate;
		int channels = 0;
		if (!(fmt & pvt->capability) || !(fmt & AST_FORMAT_AUDIO_MASK) || (fmt & emitted))
			continue;
		pt = ast_rtp_codecs_payload_code(ast_rtp_instance_get_codecs(pvt->rtp), 1, fmt);
		if (pt < 0)
			continue;
		enc = ast_rtp_lookup_mime_subtype2(1, fmt, 0);
		rate = ast_rtp_lookup_sample_rate2(1, fmt);
		if (fmt == AST_FORMAT_OPUS)
			channels = 2;
		if (!first)
			strcat(payload_buf, " ");
		snprintf(tmp_buf, sizeof(tmp_buf), "%d", pt);
		strcat(payload_buf, tmp_buf);
		first = 0;
		if (channels)
			snprintf(tmp_buf, sizeof(tmp_buf), "a=rtpmap:%d %s/%u/%d\r\n", pt, enc, rate, channels);
		else
			snprintf(tmp_buf, sizeof(tmp_buf), "a=rtpmap:%d %s/%u\r\n", pt, enc, rate);
		strcat(rtpmap_buf, tmp_buf);
		if (fmt == AST_FORMAT_G729A) {
			snprintf(tmp_buf, sizeof(tmp_buf), "a=fmtp:%d annexb=no\r\n", pt);
			strcat(rtpmap_buf, tmp_buf);
		} else if (fmt == AST_FORMAT_OPUS) {
			snprintf(tmp_buf, sizeof(tmp_buf), "a=fmtp:%d useinbandfec=1;usedtx=0\r\n", pt);
			strcat(rtpmap_buf, tmp_buf);
		} else if (fmt == AST_FORMAT_ILBC) {
			snprintf(tmp_buf, sizeof(tmp_buf), "a=fmtp:%d mode=20\r\n", pt);
			strcat(rtpmap_buf, tmp_buf);
		}
		emitted |= fmt;
	}

	/* Hardcoded telephone-event (PT 101) */
	if (!first)
		strcat(payload_buf, " ");
	strcat(payload_buf, "101");
	strcat(rtpmap_buf, "a=rtpmap:101 telephone-event/8000\r\n");
	strcat(rtpmap_buf, "a=fmtp:101 0-16\r\n");

	/* T37: append local a=crypto for SDES-SRTP. sdp_crypto_attrib returns the
	 * full "a=crypto:tag suite inline:key64\r\n" string including prefix + CRLF. */
	if (pvt->srtp && pvt->srtp->crypto) {
		const char *a_crypto = sdp_crypto_attrib(pvt->srtp->crypto);
		if (a_crypto) {
			strncat(rtpmap_buf, a_crypto, sizeof(rtpmap_buf) - strlen(rtpmap_buf) - 1);
		}
	}

	/* Step A IPv6 parity SS2 (2026-04-28): SDP family-conditional emission
	 * mirrors chan_sip.c:12237+12242 verbatim semantic. ast_sockaddr_is_ipv4_mapped
	 * gate ensures `::ffff:1.2.3.4` IPv4-mapped IPv6 emits "IP4" per RFC 6052 §2.2
	 * + N5 chan_sofia surpass (RFC 4038 §4.2 prefer-IPv4-for-IPv4-mapped). Parses
	 * `host` (may be IPv4 dot / IPv6 colon / hostname) into ast_sockaddr_t so
	 * family-detect handles all 4 priority chain producers (rtp_addr / pvt->ourip /
	 * externaddr / pvt->redirip) uniformly. */
	if (ast_sockaddr_parse(&dest_addr, host, PARSE_PORT_FORBID) &&
	    ast_sockaddr_is_ipv6(&dest_addr) &&
	    !ast_sockaddr_is_ipv4_mapped(&dest_addr)) {
		sdp_family = "IP6";
	} else {
		sdp_family = "IP4";
	}

	/* Assemble audio SDP — m= proto switches to RTP/SAVP when SRTP active */
	snprintf(buf, len,
		"v=0\r\n"
		"o=- %lu %lu IN %s %s\r\n"
		"s=GABpbx\r\n"
		"c=IN %s %s\r\n"
		"t=0 0\r\n"
		"m=audio %d %s %s\r\n"
		"%s"
		"a=sendrecv\r\n",
		(unsigned long)time(NULL), (unsigned long)time(NULL),
		sdp_family, host, sdp_family, host, port,
		(pvt->srtp && pvt->srtp->crypto) ? "RTP/SAVP" : "RTP/AVP",
		payload_buf, rtpmap_buf);

	/* Append video block -- only when video capability present and vrtp allocated */
	if (pvt->vrtp && (pvt->capability & AST_FORMAT_VIDEO_MASK)) {
		struct ast_sockaddr vrtp_addr;
		char vhost[128];
		int vport = 0;
		/* Step A IPv6 parity SS2 (2026-04-28): sockaddr_storage + ss_family
		 * dispatch for video RTP getsockname (was IPv4-only struct sockaddr_in). */
		struct sockaddr_storage vsin;
		socklen_t vsinlen = sizeof(vsin);
		char vpayload_buf[256] = "";
		char vrtpmap_buf[512] = "";
		int vfirst = 1;

		if (getsockname(ast_rtp_instance_fd(pvt->vrtp, 0),
				(struct sockaddr *)&vsin, &vsinlen) == 0) {
			if (vsin.ss_family == AF_INET6) {
				struct sockaddr_in6 *vsin6 = (struct sockaddr_in6 *)&vsin;
				inet_ntop(AF_INET6, &vsin6->sin6_addr, vhost, sizeof(vhost));
				vport = ntohs(vsin6->sin6_port);
			} else {
				struct sockaddr_in *vsin4 = (struct sockaddr_in *)&vsin;
				inet_ntop(AF_INET, &vsin4->sin_addr, vhost, sizeof(vhost));
				vport = ntohs(vsin4->sin_port);
			}
		} else {
			ast_rtp_instance_get_local_address(pvt->vrtp, &vrtp_addr);
			ast_copy_string(vhost, ast_sockaddr_stringify_host(&vrtp_addr), sizeof(vhost));
			/* post-T56 fallback-port=0 fix (2026-04-27): video-path implicit-zero
			 * variant — vport stayed at the int-init value of 0 because this
			 * else-branch never reassigned it (audio-path had explicit port=0
			 * literal; video had no assignment at all → harder to spot via grep).
			 * Same RFC 4566 §5.14 "m=video 0 = no media" symptom. */
			vport = ast_sockaddr_port(&vrtp_addr);
		}

		for (i = 0; (fmt = ast_codec_pref_index(&pvt->prefs, i)); i++) {
			int pt;
			const char *enc;
			unsigned int rate;
			if (!(fmt & pvt->capability) || !(fmt & AST_FORMAT_VIDEO_MASK))
				continue;
			pt = ast_rtp_codecs_payload_code(ast_rtp_instance_get_codecs(pvt->vrtp), 1, fmt);
			if (pt < 0)
				continue;
			enc = ast_rtp_lookup_mime_subtype2(1, fmt, 0);
			rate = ast_rtp_lookup_sample_rate2(1, fmt);
			if (!vfirst)
				strcat(vpayload_buf, " ");
			snprintf(tmp_buf, sizeof(tmp_buf), "%d", pt);
			strcat(vpayload_buf, tmp_buf);
			vfirst = 0;
			snprintf(tmp_buf, sizeof(tmp_buf), "a=rtpmap:%d %s/%u\r\n", pt, enc, rate);
			strcat(vrtpmap_buf, tmp_buf);
			emitted |= fmt;
		}
		for (fmt = 1; fmt; fmt <<= 1) {
			int pt;
			const char *enc;
			unsigned int rate;
			if (!(fmt & pvt->capability) || !(fmt & AST_FORMAT_VIDEO_MASK) || (fmt & emitted))
				continue;
			pt = ast_rtp_codecs_payload_code(ast_rtp_instance_get_codecs(pvt->vrtp), 1, fmt);
			if (pt < 0)
				continue;
			enc = ast_rtp_lookup_mime_subtype2(1, fmt, 0);
			rate = ast_rtp_lookup_sample_rate2(1, fmt);
			if (!vfirst)
				strcat(vpayload_buf, " ");
			snprintf(tmp_buf, sizeof(tmp_buf), "%d", pt);
			strcat(vpayload_buf, tmp_buf);
			vfirst = 0;
			snprintf(tmp_buf, sizeof(tmp_buf), "a=rtpmap:%d %s/%u\r\n", pt, enc, rate);
			strcat(vrtpmap_buf, tmp_buf);
			emitted |= fmt;
		}

		/* T37: append video a=crypto if vsrtp installed */
		if (pvt->vsrtp && pvt->vsrtp->crypto) {
			const char *va_crypto = sdp_crypto_attrib(pvt->vsrtp->crypto);
			if (va_crypto) {
				strncat(vrtpmap_buf, va_crypto, sizeof(vrtpmap_buf) - strlen(vrtpmap_buf) - 1);
			}
		}

		if (!vfirst) {
			int vlen = strlen(buf);
			/* post-T56 maxcallbitrate per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:12285-12286 verbatim format string b=CT:%d emitted at
			 * media-level after m=video line per RFC 4566 §5.8. Gated on peer-known
			 * AND bitrate>0; default 384 from sofia_cfg.default_maxcallbitrate
			 * inheritance produces b=CT:384 by default (chan_sip drop-in). */
			char bw_buf[32] = "";
			if (pvt->peer && pvt->peer->maxcallbitrate > 0) {
				snprintf(bw_buf, sizeof(bw_buf), "b=CT:%d\r\n", pvt->peer->maxcallbitrate);
			}
			snprintf(buf + vlen, len - vlen,
				"m=video %d %s %s\r\n"
				"%s"
				"%s"
				"a=sendrecv\r\n",
				vport,
				(pvt->vsrtp && pvt->vsrtp->crypto) ? "RTP/SAVP" : "RTP/AVP",
				vpayload_buf, bw_buf, vrtpmap_buf);
		}
	}

	/* post-T56 Task #8 T.38 fax UDPTL parity SS3b (2026-04-28, SDP outbound
	 * emitter; bidirectional symmetric pair with SS3a inbound parser):
	 * append m=image PORT udptl t38 line + 8 a=T38Fax* attributes mirroring
	 * chan_sip.c:12420-12447 verbatim semantic. Gated on pvt->udptl non-NULL
	 * (UDPTL session lazy-created at SS3a inbound peer T.38 OFFER OR at SS4
	 * outbound REQUEST_NEGOTIATE; emitter only fires when chan_sofia has
	 * something to advertise). 5 mandatory attributes + 3 optional bare-flag
	 * attributes (FillBitRemoval / TranscodingMMR / TranscodingJBIG emitted
	 * only when our_parms bit is set per chan_sip.c:12422-12430 verbatim
	 * conditional pattern). RFC 4566 §5.14 m= line + §6 attribute syntax
	 * compliant per SS1.5 R14 RFC reference table. */
	if (pvt->udptl) {
		struct ast_sockaddr udptl_local;
		int t38vlen = strlen(buf);
		const char *rate_mgmt_str;
		const char *udpec_str;
		unsigned int max_bitrate;
		unsigned int max_datagram;

		ast_udptl_get_us(pvt->udptl, &udptl_local);

		/* T38MaxBitRate enum→integer mapping mirrors chan_sip.c:11977 t38_get_rate
		 * verbatim 6-rate table. AST_T38_RATE_14400 default per pvt->t38_our_parms
		 * init at sofia_pvt_alloc. */
		switch (pvt->t38_our_parms.rate) {
		case AST_T38_RATE_2400:  max_bitrate = 2400;  break;
		case AST_T38_RATE_4800:  max_bitrate = 4800;  break;
		case AST_T38_RATE_7200:  max_bitrate = 7200;  break;
		case AST_T38_RATE_9600:  max_bitrate = 9600;  break;
		case AST_T38_RATE_12000: max_bitrate = 12000; break;
		case AST_T38_RATE_14400: max_bitrate = 14400; break;
		default:                 max_bitrate = 14400; break;
		}

		/* T38FaxRateManagement default transferredTCF per RFC 3362 + chan_sip.c:12433 */
		switch (pvt->t38_our_parms.rate_management) {
		case AST_T38_RATE_MANAGEMENT_LOCAL_TCF:
			rate_mgmt_str = "localTCF";
			break;
		case AST_T38_RATE_MANAGEMENT_TRANSFERRED_TCF:
		default:
			rate_mgmt_str = "transferredTCF";
			break;
		}

		/* T38FaxUdpEC from negotiated EC scheme (set at SS3a parser via
		 * ast_udptl_set_error_correction_scheme; emit using current scheme
		 * per chan_sip.c:12441-12447 verbatim).
		 * NONE → omit a=T38FaxUdpEC line (chan_sip pattern). */
		switch (ast_udptl_get_error_correction_scheme(pvt->udptl)) {
		case UDPTL_ERROR_CORRECTION_FEC:
			udpec_str = "t38UDPFEC";
			break;
		case UDPTL_ERROR_CORRECTION_REDUNDANCY:
			udpec_str = "t38UDPRedundancy";
			break;
		case UDPTL_ERROR_CORRECTION_NONE:
		default:
			udpec_str = NULL;
			break;
		}

		max_datagram = ast_udptl_get_local_max_datagram(pvt->udptl);

		/* Append m=image + a=T38Fax* attributes (5 mandatory). RFC 4566 §5.14:
		 * m=image port udptl t38 — UDPTL transport per RFC 3362. */
		snprintf(buf + t38vlen, len - t38vlen,
			"m=image %d udptl t38\r\n"
			"a=T38FaxVersion:%u\r\n"
			"a=T38MaxBitRate:%u\r\n"
			"a=T38FaxRateManagement:%s\r\n"
			"a=T38FaxMaxDatagram:%u\r\n",
			ast_sockaddr_port(&udptl_local),
			pvt->t38_our_parms.version,
			max_bitrate,
			rate_mgmt_str,
			max_datagram);

		/* 3 optional bare-flag attributes (chan_sip.c:12422-12430 verbatim
		 * conditional pattern — emit when our_parms bit is set). */
		if (pvt->t38_our_parms.fill_bit_removal) {
			int blen = strlen(buf);
			snprintf(buf + blen, len - blen, "a=T38FaxFillBitRemoval\r\n");
		}
		if (pvt->t38_our_parms.transcoding_mmr) {
			int blen = strlen(buf);
			snprintf(buf + blen, len - blen, "a=T38FaxTranscodingMMR\r\n");
		}
		if (pvt->t38_our_parms.transcoding_jbig) {
			int blen = strlen(buf);
			snprintf(buf + blen, len - blen, "a=T38FaxTranscodingJBIG\r\n");
		}

		/* T38FaxUdpEC emitted only when EC scheme is FEC or Redundancy
		 * (NONE = omit per chan_sip.c:12441 NONE-case-empty-block convention). */
		if (udpec_str) {
			int blen = strlen(buf);
			snprintf(buf + blen, len - blen, "a=T38FaxUdpEC:%s\r\n", udpec_str);
		}
	}

	return buf;
}

/* T37: parse one inbound a=crypto attribute. Returns 1 on accept (srtp installed),
 * 0 on reject/unsupported. Lazy-allocates *srtp + crypto helper on first valid line.
 * On any failure frees and NULLs *srtp so the caller's view stays clean.
 *
 * Note: sofia-sip's sdp_attribute_t->a_value strips the "crypto:" prefix that the
 * underlying sdp_crypto.c parser expects (it was written to chew chan_sip's full
 * attribute string starting with "crypto:"). Re-prefix here so the helper's
 * strsep tokenizer lands on the right boundaries. */
static int sofia_process_crypto(struct sofia_pvt *pvt, struct ast_rtp_instance *rtp,
		struct sofia_srtp **srtp, const char *attr)
{
	char prefixed[512];

	if (!rtp || !attr) {
		return 0;
	}
	if (!*srtp) {
		*srtp = sofia_srtp_alloc();
		if (!*srtp) {
			return 0;
		}
	}
	if (!(*srtp)->crypto) {
		(*srtp)->crypto = sdp_crypto_setup();
		if (!(*srtp)->crypto) {
			sofia_srtp_destroy(*srtp);
			*srtp = NULL;
			return 0;
		}
	}
	snprintf(prefixed, sizeof(prefixed), "crypto:%s", attr);
	if (sdp_crypto_process((*srtp)->crypto, prefixed, rtp) < 0) {
		sofia_srtp_destroy(*srtp);
		*srtp = NULL;
		return 0;
	}
	(*srtp)->flags |= SRTP_CRYPTO_OFFER_OK;
	return 1;
}

static int sofia_parse_sdp(struct sofia_pvt *pvt, sip_t const *sip)
{
	sdp_parser_t *parser;
	sdp_session_t *sdp;
	sdp_media_t *media;
	const char *sdp_data;
	int audio_offered = 0;
	int video_offered = 0;
	int audio_secure_offered = 0;
	int video_secure_offered = 0;
	int processed_crypto_audio = 0;
	int processed_crypto_video = 0;

	if (!sip || !pvt || !pvt->rtp) {
		return 0;
	}

	if (!sip->sip_payload || !sip->sip_payload->pl_data) {
		return 0;
	}

	sdp_data = sip->sip_payload->pl_data;
	parser = sdp_parse(pvt->home, sdp_data, sip->sip_payload->pl_len, 0);
	if (!parser) {
		return 0;
	}

	sdp = sdp_session(parser);
	if (!sdp) {
		sdp_parser_free(parser);
		return 0;
	}

	for (media = sdp->sdp_media; media; media = media->m_next) {
		if (media->m_type == sdp_media_audio && media->m_port != 0) {
			sdp_attribute_t *a;
			audio_offered = 1;
			if (media->m_proto == sdp_proto_srtp) {
				audio_secure_offered = 1;
			}
			for (a = media->m_attributes; a; a = a->a_next) {
				if (a->a_name && su_casematch(a->a_name, "crypto") && a->a_value) {
					if (sofia_process_crypto(pvt, pvt->rtp, &pvt->srtp, a->a_value)) {
						processed_crypto_audio = 1;
						break;
					}
				}
			}
			char addr[128];
			sdp_connection_t *conn = media->m_connections;

			if (!conn && sdp->sdp_connection) {
				conn = sdp->sdp_connection;
			}

			if (conn && conn->c_address) {
				snprintf(addr, sizeof(addr), "%s", conn->c_address);
			} else {
				continue;
			}

			{
				struct ast_sockaddr remote;
				ast_sockaddr_parse(&remote, addr, 0);
				ast_sockaddr_set_port(&remote, media->m_port);
				/* NAT override (chan_sip parity): if the peer is behind NAT,
				 * the SDP c= line usually leaks its private LAN IP. Replace
				 * the host portion with peer->src_addr (registered public IP
				 * or DNS-resolved address) while keeping the SDP-advertised
				 * media port. Symmetric-RTP / comedia will further refine
				 * the port when the first inbound packet arrives. */
				if (pvt->peer
				    && (pvt->peer->nat & (SOFIA_NAT_FORCE_RPORT | SOFIA_NAT_COMEDIA))
				    && !ast_sockaddr_isnull(&pvt->peer->src_addr)) {
					struct ast_sockaddr nat_remote = pvt->peer->src_addr;
					ast_sockaddr_set_port(&nat_remote, media->m_port);
					remote = nat_remote;
				}
				ast_rtp_instance_set_remote_address(pvt->rtp, &remote);
			}

			{
				struct ast_rtp_codecs newaudiortp;
				format_t local_cap = pvt->capability;
				format_t offered = 0;
				int noncodec = 0;
				sdp_rtpmap_t *rm;
				sdp_list_t *fmt;

				ast_rtp_codecs_payloads_clear(&newaudiortp, NULL);

				/* Step 1: register PTs from m= line */
				for (fmt = media->m_format; fmt; fmt = fmt->l_next) {
					int pt = atoi(fmt->l_text);
					ast_rtp_codecs_payloads_set_m_type(&newaudiortp, NULL, pt);
				}

				/* Step 2: override with a=rtpmap entries (handles dynamic PTs) */
				for (rm = media->m_rtpmaps; rm; rm = rm->rm_next) {
					if (rm->rm_encoding) {
						int rc = ast_rtp_codecs_payloads_set_rtpmap_type_rate(
							&newaudiortp, NULL, rm->rm_pt, "audio",
							(char *)rm->rm_encoding, 0, rm->rm_rate);
						if (rc) {
							ast_rtp_codecs_payloads_unset(&newaudiortp, NULL, rm->rm_pt);
						}
					}
				}

				/* Step 3: extract negotiated formats */
				ast_rtp_codecs_payload_formats(&newaudiortp, &offered, &noncodec);

				/* Step 4: intersect with local capability */
				pvt->capability = local_cap & offered;
				if (pvt->capability == 0) {
					ast_log(LOG_WARNING, "Sofia: No common codec with peer; falling back to local capability\n");
					pvt->capability = local_cap;
				}

				/* Step 5: install into RTP instance */
				ast_rtp_codecs_payloads_copy(&newaudiortp,
					ast_rtp_instance_get_codecs(pvt->rtp), pvt->rtp);

				if (pvt->owner && (pvt->capability & AST_FORMAT_AUDIO_MASK)) {
					format_t chosen = ast_codec_choose(&pvt->prefs,
						pvt->capability & AST_FORMAT_AUDIO_MASK, 1);
					if (!chosen) {
						chosen = ast_best_codec(pvt->capability & AST_FORMAT_AUDIO_MASK);
					}
					if (chosen) {
						pvt->owner->nativeformats =
							(pvt->owner->nativeformats & ~AST_FORMAT_AUDIO_MASK) | chosen;
						ast_set_read_format(pvt->owner, chosen);
						ast_set_write_format(pvt->owner, chosen);
					}
				}
			}
		} else if (media->m_type == sdp_media_video && media->m_port != 0) {
			char addr[128];
			sdp_connection_t *conn = media->m_connections;
			sdp_attribute_t *a;

			video_offered = 1;
			if (media->m_proto == sdp_proto_srtp) {
				video_secure_offered = 1;
			}

			if (!conn && sdp->sdp_connection)
				conn = sdp->sdp_connection;
			if (!conn || !conn->c_address)
				continue;

			snprintf(addr, sizeof(addr), "%s", conn->c_address);

			/* Allocate vrtp on demand when we see m=video */
			if (!pvt->vrtp) {
				struct ast_sockaddr bindaddr;
				ast_sockaddr_parse(&bindaddr, sofia_cfg.bindaddr, 0);
				pvt->vrtp = ast_rtp_instance_new("gabpbx", NULL, &bindaddr, NULL);
				if (pvt->vrtp)
					ast_rtp_instance_set_prop(pvt->vrtp, AST_RTP_PROPERTY_RTCP, 1);
			}

			for (a = media->m_attributes; a; a = a->a_next) {
				if (a->a_name && su_casematch(a->a_name, "crypto") && a->a_value) {
					if (sofia_process_crypto(pvt, pvt->vrtp, &pvt->vsrtp, a->a_value)) {
						processed_crypto_video = 1;
						break;
					}
				}
			}

			if (pvt->vrtp) {
				struct ast_sockaddr remote;
				struct ast_rtp_codecs newvideortp;
				format_t offered = 0;
				int noncodec = 0;
				sdp_rtpmap_t *rm;
				sdp_list_t *vfmt;

				ast_sockaddr_parse(&remote, addr, 0);
				ast_sockaddr_set_port(&remote, media->m_port);
				/* NAT override (chan_sip parity): mirror audio-side reasoning
				 * for video — SDP c= from a NAT'd peer typically leaks the
				 * private LAN IP; use peer->src_addr instead. */
				if (pvt->peer
				    && (pvt->peer->nat & (SOFIA_NAT_FORCE_RPORT | SOFIA_NAT_COMEDIA))
				    && !ast_sockaddr_isnull(&pvt->peer->src_addr)) {
					struct ast_sockaddr nat_remote = pvt->peer->src_addr;
					ast_sockaddr_set_port(&nat_remote, media->m_port);
					remote = nat_remote;
				}
				ast_rtp_instance_set_remote_address(pvt->vrtp, &remote);

				ast_rtp_codecs_payloads_clear(&newvideortp, NULL);

				for (vfmt = media->m_format; vfmt; vfmt = vfmt->l_next) {
					int pt = atoi(vfmt->l_text);
					ast_rtp_codecs_payloads_set_m_type(&newvideortp, NULL, pt);
				}
				for (rm = media->m_rtpmaps; rm; rm = rm->rm_next) {
					if (rm->rm_encoding) {
						int rc = ast_rtp_codecs_payloads_set_rtpmap_type_rate(
							&newvideortp, NULL, rm->rm_pt, "video",
							(char *)rm->rm_encoding, 0, rm->rm_rate);
						if (rc)
							ast_rtp_codecs_payloads_unset(&newvideortp, NULL, rm->rm_pt);
					}
				}

				ast_rtp_codecs_payload_formats(&newvideortp, &offered, &noncodec);
				if (offered & AST_FORMAT_VIDEO_MASK) {
					pvt->capability |= offered & AST_FORMAT_VIDEO_MASK;
				}
				ast_rtp_codecs_payloads_copy(&newvideortp,
					ast_rtp_instance_get_codecs(pvt->vrtp), pvt->vrtp);
			}
		} else if (media->m_type == sdp_media_image && media->m_port != 0) {
			/* post-T56 Task #8 T.38 fax UDPTL parity SS3a (2026-04-28, SDP
			 * inbound parser): mirrors chan_sip.c:9866-10220 + 10580-10685
			 * verbatim semantic. sofia-sip natively types m=image media via
			 * sdp_media_image enum (sdp.h:235) + sdp_proto_udptl (sdp.h:249);
			 * Pattern 16 sofia-sip-native-protocol-mechanics 13th-instance
			 * (chan_sip parses raw "image %30u udptl t38" via sscanf at L9866;
			 * chan_sofia rides typed enum dispatch — cleaner code path).
			 *
			 * SS3a populates pvt->t38_their_parms from peer's offer attributes
			 * + lazy-creates pvt->udptl + sets UDPTL peer addr + transitions
			 * pvt->t38_state to SOFIA_T38_PEER_REINVITE on first valid detect.
			 * SS3b emits chan_sofia OUR offer; SS4 wires sofia_change_t38_state
			 * + AST_CONTROL_T38_PARAMETERS frame queue + 5s timer.
			 *
			 * RFC 5347 §2.5.2: T.38 attribute names parsed case-insensitively
			 * (typo in IANA registration documented in chan_sip.c:10588 comment).
			 * sofia-sip preserves attribute name+value as-given by peer; we
			 * lowercase a concatenated "name:value" buffer for sscanf matches. */
			sdp_attribute_t *a;
			sdp_connection_t *conn = media->m_connections;
			char addr[128];

			/* Verify proto is UDPTL via sofia-sip native enum (Pattern 16) */
			if (media->m_proto != sdp_proto_udptl) {
				ast_log(LOG_WARNING, "Sofia: ignoring m=image media with non-UDPTL proto\n");
				continue;
			}

			if (!conn && sdp->sdp_connection) {
				conn = sdp->sdp_connection;
			}
			if (!conn || !conn->c_address) {
				continue;
			}

			/* Lazy-create UDPTL session (chan_sip.c:7591 verbatim
			 * ast_udptl_new_with_bindaddr fresh-bind semantic — separate
			 * UDPTL socket, NOT reusing audio RTP port per design doc §3 SS2 R9).
			 * SS4 will reuse pvt->udptl across re-INVITEs; destroyed in
			 * sofia_pvt_destructor. NULL sched/io for SS3a — SS4 may revisit
			 * if scheduled fax-CNG triggers need callback mode. */
			if (!pvt->udptl) {
				struct ast_sockaddr bindaddr;
				ast_sockaddr_parse(&bindaddr, sofia_cfg.bindaddr, 0);
				pvt->udptl = ast_udptl_new_with_bindaddr(NULL, NULL, 0, &bindaddr);
				if (!pvt->udptl) {
					ast_log(LOG_WARNING, "Sofia: failed to allocate UDPTL session for T.38 (peer offer ignored)\n");
					continue;
				}
				/* SS5 (2026-04-28): attach UDPTL fd to channel fds[5] for
				 * sofia_read fd-5 dispatch. Mirrors chan_sip.c:7924 verbatim
				 * ast_channel_set_fd pattern. Covers re-INVITE-arriving-after-
				 * channel-exists ordering (sofia_new only attaches if udptl
				 * pre-existed at channel-alloc time; this path covers
				 * lazy-create-after-channel-exists). */
				if (pvt->owner) {
					pvt->owner->fds[5] = ast_udptl_fd(pvt->udptl);
				}
			}

			/* Set UDPTL peer address (mirrors chan_sip.c:10178
			 * ast_udptl_set_peer pattern). SS3a.1 C1 audit fold-in
			 * (2026-04-28): symmetric-RTP UDPTL destination gate per
			 * chan_sip.c:10171 verbatim — when peer has NAT (force_rport
			 * OR comedia) AND t38pt_usertpsource=yes, override UDPTL
			 * DESTINATION with RTP remote address (audio's actual seen
			 * endpoint, solving NAT for T.38 fax over NAT'd peers);
			 * UDPTL PORT always taken from m=image regardless. SS1.5 N3
			 * audit-discovered field finally wired; without this gate
			 * NAT'd T.38 peers using t38pt_usertpsource=yes get WRONG
			 * UDPTL destination and fax fails. */
			snprintf(addr, sizeof(addr), "%s", conn->c_address);
			{
				struct ast_sockaddr remote;
				if (pvt->peer && pvt->peer->t38pt_usertpsource &&
				    (pvt->peer->nat & (SOFIA_NAT_FORCE_RPORT | SOFIA_NAT_COMEDIA)) &&
				    pvt->rtp) {
					ast_rtp_instance_get_remote_address(pvt->rtp, &remote);
				} else {
					ast_sockaddr_parse(&remote, addr, 0);
				}
				ast_sockaddr_set_port(&remote, media->m_port);
				ast_udptl_set_peer(pvt->udptl, &remote);
			}

			/* Reset their_parms before parsing each new offer (mirrors
			 * chan_sip.c:9892-9894). EC default NONE per chan_sip.c:9896. */
			if (pvt->t38_state != SOFIA_T38_ENABLED) {
				memset(&pvt->t38_their_parms, 0, sizeof(pvt->t38_their_parms));
				ast_udptl_set_error_correction_scheme(pvt->udptl, UDPTL_ERROR_CORRECTION_NONE);
			}

			/* Walk a=T38Fax* attributes per chan_sip.c:10580-10685 verbatim
			 * semantic. 8 attributes handled (5 mandatory + 3 optional bare-flag).
			 * RFC 5347 §2.5.2 case-insensitive parsing applied via lowercase
			 * concatenation buffer. */
			for (a = media->m_attributes; a; a = a->a_next) {
				unsigned int x;
				char s[256];
				char attrib[512];
				char *pos;

				if (!a->a_name) {
					continue;
				}
				if (a->a_value) {
					snprintf(attrib, sizeof(attrib), "%s:%s", a->a_name, a->a_value);
				} else {
					snprintf(attrib, sizeof(attrib), "%s", a->a_name);
				}
				for (pos = attrib; *pos; ++pos) {
					*pos = tolower(*pos);
				}

				if (sscanf(attrib, "t38faxversion:%30u", &x) == 1) {
					pvt->t38_their_parms.version = x;
				} else if (sscanf(attrib, "t38maxbitrate:%30u", &x) == 1 ||
					   sscanf(attrib, "t38faxmaxrate:%30u", &x) == 1) {
					switch (x) {
					case 14400: pvt->t38_their_parms.rate = AST_T38_RATE_14400; break;
					case 12000: pvt->t38_their_parms.rate = AST_T38_RATE_12000; break;
					case 9600:  pvt->t38_their_parms.rate = AST_T38_RATE_9600;  break;
					case 7200:  pvt->t38_their_parms.rate = AST_T38_RATE_7200;  break;
					case 4800:  pvt->t38_their_parms.rate = AST_T38_RATE_4800;  break;
					case 2400:  pvt->t38_their_parms.rate = AST_T38_RATE_2400;  break;
					}
				} else if (sscanf(attrib, "t38faxmaxdatagram:%30u", &x) == 1 ||
					   sscanf(attrib, "t38maxdatagram:%30u", &x) == 1) {
					/* Apply per-peer override per chan_sip.c:10626-10629 */
					if ((pvt->t38_maxdatagram > 0) && ((unsigned int)pvt->t38_maxdatagram > x)) {
						x = (unsigned int)pvt->t38_maxdatagram;
					}
					ast_udptl_set_far_max_datagram(pvt->udptl, x);
				} else if (sscanf(attrib, "t38faxratemanagement:%255s", s) == 1) {
					if (!strcasecmp(s, "localtcf")) {
						pvt->t38_their_parms.rate_management = AST_T38_RATE_MANAGEMENT_LOCAL_TCF;
					} else if (!strcasecmp(s, "transferredtcf")) {
						pvt->t38_their_parms.rate_management = AST_T38_RATE_MANAGEMENT_TRANSFERRED_TCF;
					}
				} else if (sscanf(attrib, "t38faxudpec:%255s", s) == 1) {
					if (!strcasecmp(s, "t38udpredundancy")) {
						ast_udptl_set_error_correction_scheme(pvt->udptl, UDPTL_ERROR_CORRECTION_REDUNDANCY);
					} else if (!strcasecmp(s, "t38udpfec")) {
						ast_udptl_set_error_correction_scheme(pvt->udptl, UDPTL_ERROR_CORRECTION_FEC);
					} else {
						ast_udptl_set_error_correction_scheme(pvt->udptl, UDPTL_ERROR_CORRECTION_NONE);
					}
				} else if (strncmp(attrib, "t38faxfillbitremoval", 20) == 0) {
					pvt->t38_their_parms.fill_bit_removal = 1;
				} else if (strncmp(attrib, "t38faxtranscodingmmr", 20) == 0) {
					pvt->t38_their_parms.transcoding_mmr = 1;
				} else if (strncmp(attrib, "t38faxtranscodingjbig", 21) == 0) {
					pvt->t38_their_parms.transcoding_jbig = 1;
				}
			}

			/* SS1.5 N1 LOAD-BEARING — read peer-advertised max_ifp into
			 * pvt->t38_max_ifp. chan_sip.c:5786,5792,7549 + 7520,7525.
			 * Without max_ifp wiring, real-fax negotiation rejects on every
			 * call (chan_sip.c:7496 `change_t38_state(p, T38_DISABLED)`
			 * when parameters->max_ifp == 0). Used at SS4 sofia_change_t38_state
			 * via parameters.max_ifp = ast_udptl_get_far_max_ifp(pvt->udptl). */
			pvt->t38_max_ifp = ast_udptl_get_far_max_ifp(pvt->udptl);

			/* State transition: T38_DISABLED → T38_PEER_REINVITE on first
			 * detect. Mirrors chan_sip.c:10194 verbatim. SS4 wire-in:
			 * sofia_change_t38_state Pattern 5 #43 queues AST_CONTROL_T38_
			 * PARAMETERS frame to channel (3-of-4 transitions queue per
			 * SS1.5 N5 — PEER_REINVITE is one of the 3 that DO queue) +
			 * tags UDPTL session with channel name (SS1.5 N4) + populates
			 * parameters.max_ifp from ast_udptl_get_far_max_ifp (SS1.5 N1
			 * LOAD-BEARING). 5s reINVITE timeout armed via ast_sched_thread_add
			 * with sofia_t38_abort callback (SS1.5 N2 LOAD-BEARING; chan_sip.c
			 * :24288 verbatim 5000ms). ao2_bump pvt for ref-transferred to
			 * scheduler — abort callback drops the ref. */
			if (pvt->t38_state == SOFIA_T38_DISABLED) {
				sofia_change_t38_state(pvt, SOFIA_T38_PEER_REINVITE);
				if (sofia_sched && pvt->t38id == -1) {
					ao2_ref(pvt, +1);  /* held by scheduler entry */
					pvt->t38id = ast_sched_thread_add(sofia_sched,
						SOFIA_T38_ABORT_TIMEOUT_MS, sofia_t38_abort, pvt);
					if (pvt->t38id < 0) {
						pvt->t38id = -1;
						ao2_ref(pvt, -1);  /* schedule failed; release ref */
					}
				}
				/* post-T56 Task #8 T.38 fax UDPTL parity SS6 (2026-04-28):
				 * when peer sends T.38 reINVITE AND peer has
				 * faxdetect=t38 (or cng,t38), async-goto channel to "fax"
				 * extension per chan_sip.c:10196 verbatim semantic. Dialplan
				 * runs SendFAX/ReceiveFAX which negotiates T.38 mode via
				 * setoption / control-frame chain (SS4 sofia_interpret_t38_
				 * parameters dispatch). FAXEXTEN channel-var carries original
				 * extension for return-on-fax-end. */
				if (pvt->owner &&
				    pvt->peer && (pvt->peer->faxdetect_mode & SOFIA_FAX_DETECT_T38)) {
					struct ast_channel *chan = pvt->owner;
					if (strcmp(chan->exten, "fax")) {
						const char *target_context = S_OR(chan->macrocontext, chan->context);
						if (ast_exists_extension(chan, target_context, "fax", 1,
						    S_COR(chan->caller.id.number.valid, chan->caller.id.number.str, NULL))) {
							ast_verbose(VERBOSE_PREFIX_2 "Sofia: redirecting '%s' to fax extension due to peer T.38 re-INVITE\n",
								chan->name);
							pbx_builtin_setvar_helper(chan, "FAXEXTEN", chan->exten);
							if (ast_async_goto(chan, target_context, "fax", 1)) {
								ast_log(LOG_NOTICE, "Sofia: T.38 reINVITE detected — failed async goto fax extension on '%s'\n",
									chan->name);
							}
						} else {
							ast_log(LOG_NOTICE, "Sofia: T.38 reINVITE detected but no fax extension on '%s'\n",
								chan->name);
						}
					}
				}
			}
		}
	}

	sdp_parser_free(parser);

	/* T37: SRTP policy enforcement (mirrors chan_sip.c:9892-9938) */
	if (audio_secure_offered && !processed_crypto_audio) {
		ast_log(LOG_NOTICE, "Sofia: SDP rejected — m=audio RTP/SAVP without valid a=crypto\n");
		return -1;
	}
	if (video_secure_offered && !processed_crypto_video) {
		ast_log(LOG_NOTICE, "Sofia: SDP rejected — m=video RTP/SAVP without valid a=crypto\n");
		return -1;
	}
	if (pvt->peer && pvt->peer->encryption) {
		if (audio_offered && !audio_secure_offered) {
			ast_log(LOG_NOTICE, "Sofia: SDP rejected — peer '%s' requires encryption, audio offer is plain RTP/AVP\n",
				pvt->peer->name);
			return -1;
		}
		if (video_offered && !video_secure_offered) {
			ast_log(LOG_NOTICE, "Sofia: SDP rejected — peer '%s' requires encryption, video offer is plain RTP/AVP\n",
				pvt->peer->name);
			return -1;
		}
	}

	return 0;
}

static struct ast_channel *sofia_new(struct sofia_pvt *pvt, int state, const char *linkedid)
{
	struct ast_channel *chan;

	if (!pvt) {
		return NULL;
	}

	/* post-T56 accountcode per-peer parity (2026-04-27): pre-existing CDR-billing-bug
	 * fix — channel.h:1136 ast_channel_alloc 5th-arg = ACCTCODE per signature.
	 * chan_sofia previously passed pvt->username (auth identity from REGISTER URI
	 * user-part); operators saw SIP auth user as CDR accountcode (semantic mismatch).
	 * Now passes pvt->accountcode (correct per channel.h signature; populated via
	 * dialog inheritance at sofia_request_call + sofia_process_invite from
	 * peer->accountcode). chan_sip parity at chan_sip.c:7945-7946. */
	chan = ast_channel_alloc(1, state, pvt->fromuser, NULL, pvt->accountcode,
			pvt->exten, pvt->context, linkedid, 0, "%s/%s",
			SOFIA_CHANNEL_TYPE, pvt->peername);
	if (!chan) {
		ast_log(LOG_ERROR, "Unable to allocate Sofia channel\n");
		return NULL;
	}

	chan->tech = &sofia_tech;
	chan->nativeformats = pvt->capability;
	chan->readformat = AST_FORMAT_ULAW;
	chan->writeformat = AST_FORMAT_ULAW;

	if (pvt->rtp) {
		chan->fds[0] = ast_rtp_instance_fd(pvt->rtp, 0);
		chan->fds[1] = ast_rtp_instance_fd(pvt->rtp, 1);
	}

	if (pvt->vrtp) {
		chan->fds[2] = ast_rtp_instance_fd(pvt->vrtp, 0);
		chan->fds[3] = ast_rtp_instance_fd(pvt->vrtp, 1);
	}

	/* post-T56 Task #8 T.38 fax UDPTL parity SS5 (2026-04-28): fd-5 attach
	 * for UDPTL packet read mirrors chan_sip.c:7923-7924 verbatim (chan_sip
	 * uses ast_channel_set_fd(tmp, 5, ast_udptl_fd); chan_sofia uses direct
	 * chan->fds[5] assignment per chan_sofia idiom at L3567-3573 audio/video
	 * fds). pvt->udptl typically NULL at sofia_new for inbound INVITE flow
	 * (lazy-created by sofia_parse_sdp on m=image detection); SS5 covers BOTH
	 * orderings: (a) udptl pre-existing → wire here; (b) udptl created later
	 * → sofia_parse_sdp lazy-create site sets pvt->owner->fds[5] post-alloc. */
	if (pvt->udptl) {
		chan->fds[5] = ast_udptl_fd(pvt->udptl);
	}

	chan->tech_pvt = pvt;

	if (pvt->peer) {
		chan->callgroup = pvt->peer->callgroup;
		chan->pickupgroup = pvt->peer->pickupgroup;
		/* post-T56 language per-peer parity (2026-04-27): propagate per-peer audio
		 * language locale to ast_channel.language so prompts/sounds play in peer's
		 * preferred locale. chan_sip parity sofia_new equivalent. Empty peer->language
		 * leaves chan->language at gabpbx-core default (channel.h:776 AST_STRING_FIELD). */
		if (!ast_strlen_zero(pvt->peer->language)) {
			ast_string_field_set(chan, language, pvt->peer->language);
		}
		/* post-T56 cid bundle parity (2026-04-28): propagate per-peer cid_tag to
		 * ast_channel.caller.id.tag — chan_sip parity at chan_sip.c:7837 verbatim
		 * `tmp->caller.id.tag = ast_strdup(i->cid_tag)`. ast_party_id.tag is an
		 * Asterisk-internal channel-side identifier (NOT a SIP-protocol From-tag —
		 * sofia-sip auto-generates the SIP From-tag for dialog uniqueness per
		 * RFC 3261 §8.1.1.3). Empty peer->cid_tag leaves chan->caller.id.tag NULL
		 * (channel-core default). */
		if (!ast_strlen_zero(pvt->peer->cid_tag)) {
			chan->caller.id.tag = ast_strdup(pvt->peer->cid_tag);
		}
		/* post-T56 amaflags per-peer parity (2026-04-28): propagate per-peer
		 * AMA flags to ast_channel.amaflags for CDR per-peer accounting policy.
		 * chan_sip parity at chan_sip.c:7947-7948 verbatim — gated on non-zero
		 * (channel-core default preserved when peer has no AMA flags). */
		if (pvt->peer->amaflags) {
			chan->amaflags = pvt->peer->amaflags;
		}
		/* post-T56 parkinglot per-peer parity (2026-04-28): propagate per-peer
		 * parking-lot to ast_channel.parkinglot for Park()/transfer routing.
		 * chan_sip parity at chan_sip.c:7943-7944 verbatim — gated on non-empty
		 * (channel-core default preserved when peer parkinglot empty). */
		if (!ast_strlen_zero(pvt->peer->parkinglot)) {
			ast_string_field_set(chan, parkinglot, pvt->peer->parkinglot);
		}
		/* post-T56 setvar+header per-peer parity (2026-04-28, COMBINED ship): apply
		 * peer->chanvars to channel via pbx_builtin_setvar_helper. Mirrors chan_sip.c
		 * :8007-8010 verbatim sip_new iteration semantic. setvar entries become regular
		 * channel-vars consumed by dialplan; header entries (__SIPADDHEADERpre%2d=
		 * Name: value) become inherited channel-vars consumed by existing T46 sofia_
		 * build_addheader_str at chan_sofia.c:4509 which emits SIPTAG_HEADER_STR
		 * concatenation at sofia_call (L4858) — ZERO new outbound-builder code needed
		 * (chan_sofia helper-architecture-advantage NEW DIMENSION existing-infra-
		 * structure-leverage). chan_sofia surpass via simpler-iteration-vs-chan_sip-
		 * 3-step-machine (chan_sip copies peer->chanvars → pvt->chanvars at sip_alloc
		 * L6045 + copy at find_peer L17086 + iterates pvt->chanvars at sip_new L8007;
		 * chan_sofia skips both copy steps via direct peer iteration here — peer ao2-
		 * ref held by pvt for lifetime invariant). */
		if (pvt->peer->chanvars) {
			struct ast_variable *var;
			for (var = pvt->peer->chanvars; var; var = var->next) {
				pbx_builtin_setvar_helper(chan, var->name, var->value);
			}
		}
	}

	return chan;
}

static void sofia_pvt_destructor(void *obj)
{
	struct sofia_pvt *pvt = obj;

	sofia_pvt_clear_active_contact(pvt);

	/* post-T56 call-limit parity SS2 R9 (2026-04-27): destructor catchall DEC.
	 * Race-recovery for orphaned pvts (e.g., sofia_request_call alloc-fail before
	 * any other DEC site fired). Flag-gated idempotency keeps multi-site safe.
	 * Must run BEFORE peer ao2_ref drop below — counter helper needs pvt->peer. */
	if (pvt->peer && (pvt->call_inc_done || pvt->ring_inc_done)) {
		if (pvt->ring_inc_done) {
			sofia_update_call_counter(pvt, SOFIA_DEC_CALL_RINGING);
		}
		if (pvt->call_inc_done) {
			sofia_update_call_counter(pvt, SOFIA_DEC_CALL_LIMIT);
		}
	}

	if (pvt->peer) {
		ao2_ref(pvt->peer, -1);
		pvt->peer = NULL;
	}

	if (pvt->nh) {
		nua_handle_destroy(pvt->nh);
		pvt->nh = NULL;
	}

	/* post-T56 inband DTMF detect parity SS1 R5 (2026-04-27): single-site
	 * cleanup catchall. Place BEFORE pvt->rtp destroy (DSP holds no rtp ref
	 * but ordering preserves chan_sip L7082 convention). NULL-safe. */
	sofia_disable_dsp_detect(pvt);

	if (pvt->rtp) {
		ast_rtp_instance_destroy(pvt->rtp);
		pvt->rtp = NULL;
	}

	if (pvt->vrtp) {
		ast_rtp_instance_destroy(pvt->vrtp);
		pvt->vrtp = NULL;
	}

	if (pvt->srtp) {
		sofia_srtp_destroy(pvt->srtp);
		pvt->srtp = NULL;
	}

	if (pvt->vsrtp) {
		sofia_srtp_destroy(pvt->vsrtp);
		pvt->vsrtp = NULL;
	}

	/* post-T56 Task #8 T.38 fax UDPTL parity SS2 (2026-04-28): UDPTL session
	 * teardown mirrors chan_sip.c:6485-6486 verbatim. Place AFTER rtp/vrtp/
	 * srtp/vsrtp destroy (chan_sip ordering convention) + BEFORE home unref
	 * (sofia-sip su_home arena unrelated to UDPTL allocation). NULL-safe.
	 * SS4 (2026-04-28): t38id sched-cancel mirrors chan_sip.c:3553 verbatim
	 * destructor pattern. ast_sched_thread_del returns the void* arg the
	 * callback would have received; we ao2_ref-drop it locally to balance
	 * the ref taken at ast_sched_thread_add (T53 refcount-audit pattern —
	 * race-safe because del-or-fire dichotomy: if cancel succeeds, callback
	 * never runs and we drop the ref; if callback ran first and finished,
	 * t38id is already -1 and sched_thread_del is a no-op). */
	if (pvt->t38id != -1 && sofia_sched) {
		if (ast_sched_thread_del(sofia_sched, pvt->t38id) == 0) {
			ao2_ref(pvt, -1);  /* successfully cancelled — release scheduler's ref */
		}
		pvt->t38id = -1;
	}
	if (pvt->udptl) {
		ast_udptl_destroy(pvt->udptl);
		pvt->udptl = NULL;
	}

	if (pvt->home) {
		su_home_unref(pvt->home);
		pvt->home = NULL;
	}

	if (pvt->fork) {
		ao2_ref(pvt->fork, -1);
		pvt->fork = NULL;
	}

	if (pvt->initreq_headers) {
		ast_variables_destroy(pvt->initreq_headers);
		pvt->initreq_headers = NULL;
	}

	ast_string_field_free_memory(pvt);
	ast_mutex_destroy(&pvt->lock);
}

static struct sofia_pvt *sofia_pvt_alloc(void)
{
	struct sofia_pvt *pvt;

	pvt = ao2_alloc(sizeof(*pvt), sofia_pvt_destructor);
	if (!pvt) {
		return NULL;
	}

	if (ast_string_field_init(pvt, 512)) {
		ao2_ref(pvt, -1);
		return NULL;
	}

	ast_mutex_init(&pvt->lock);
	pvt->state = SOFIA_DIALOG_STATE_DOWN;
	pvt->home = su_home_new(sizeof(*pvt->home));

	/* post-T56 Task #8 T.38 fax UDPTL parity SS2 (2026-04-28): explicit
	 * initialization for non-zero-default T.38 fields. udptl pointer +
	 * t38_max_ifp + t38_maxdatagram + t38_ec_mode + t38pt_usertpsource +
	 * t38_our_parms + t38_their_parms zero-init via ao2_alloc; t38_state
	 * matches SOFIA_T38_DISABLED=0 by zero-init but explicit assignment
	 * documents intent; t38id MUST be `-1` sentinel per chan_sip.c:8512
	 * verbatim ("no scheduler entry pending" — distinct from valid sched ID 0). */
	pvt->t38_state = SOFIA_T38_DISABLED;
	pvt->t38id = -1;
	pvt->defer_bye_sched_id = -1;

	/* post-T56 Task #8 T.38 fax UDPTL parity SS3b (2026-04-28): chan_sofia
	 * default OUR T.38 capabilities per chan_sip drop-in baseline. version=0
	 * (T.38 v0 default per RFC 3362; SS4 negotiation MIN-clamps with peer
	 * via chan_sip.c:7518 `MIN(our_parms.version, their_parms.version)`).
	 * rate=14400 (highest bit-rate our_parms emits in SDP via
	 * a=T38MaxBitRate:14400 per chan_sip.c:12421 t38_get_rate(AST_T38_RATE_14400)).
	 * rate_management=TRANSFERRED_TCF (RFC 3362 default per chan_sip.c:12434).
	 * Optional bare-flags default 0 (FillBitRemoval / TranscodingMMR /
	 * TranscodingJBIG emitted only when set; app_fax/res_fax may set via
	 * setoption SS5 wire-in based on fax stack capabilities). max_ifp /
	 * max_datagram zero-init at struct level — UDPTL stack provides
	 * sensible defaults via ast_udptl_get_local_max_datagram. */
	pvt->t38_our_parms.version = 0;
	pvt->t38_our_parms.rate = AST_T38_RATE_14400;
	pvt->t38_our_parms.rate_management = AST_T38_RATE_MANAGEMENT_TRANSFERRED_TCF;

	return pvt;
}

/* T55.5 (2026-04-27): forward declarations — mwi_event_cb (defined just below)
 * needs sofia_dispatch_to_root_thread (T47.3 helper, defined ~L5814) and
 * mwi_notify_callback needs transmit_mwi_notify_for_peer (defined ~L3785).
 * Same forward-decl-before-static-use lesson as T55.1 (struct sofia_mailbox)
 * and T55.3 (sofia_process_mwi_subscribe define-before-use).
 * T56.2 (2026-04-27): sofia_call (~L2564) + sofia_do_register (~L5808) need
 * sofia_format_outboundproxy (defined later). Same forward-decl pattern. */
static int sofia_dispatch_to_root_thread(void (*callback)(void *), void *data);
static void transmit_mwi_notify_for_peer(struct sofia_peer *peer);
static void sofia_format_outboundproxy(struct sofia_peer *peer, char *buf, size_t len);
/* post-T56 outbound-headers parity (2026-04-27): outbound INVITE From + Contact +
 * SDP c= line wire-level chan_sip parity. sofia_resolve_ourip mirrors chan_sip
 * ast_sip_ouraddrfor (kernel routing + externaddr remap); sofia_build_from +
 * sofia_build_contact mirror chan_sip initreqprep + build_contact. */
static void sofia_resolve_ourip(struct sofia_pvt *pvt, const struct ast_sockaddr *target);
static void sofia_build_from(struct sofia_pvt *pvt, char *buf, size_t len);
/* post-T56 directmediapermit/directmediadeny per-peer parity (2026-04-27): forward-decl
 * needed because sofia_get_rtp_peer at L2594 calls helper defined at L6631 (~4000 LoC
 * distance; ADDENDUM #4 forward-decl-distance discipline triggered). Helper extracted
 * at commit 7ff03dc REFER blind-transfer fix; reused here per Pattern 5
 * helper-extraction-compounds-value at predicted future-reuse instance. */
static struct ast_channel *sofia_find_bridged_channel(struct sofia_pvt *op);
/* post-T56 dnsmgr per-peer parity (2026-04-27): callback signature per dnsmgr.h:132
 * dns_update_func — (old, new, data). chan_sip parity at chan_sip.c:13292 verbatim
 * arg order. Forward-decl placed adjacent to sofia_find_bridged_channel because the
 * registration callsite (sofia_peer_alloc) is upstream of the callback definition. */
static void sofia_on_dns_update_peer(struct ast_sockaddr *old, struct ast_sockaddr *new, void *data);
static void sofia_build_contact(struct sofia_pvt *pvt, char *buf, size_t len);
/* post-T56 identity-headers parity SS2 (2026-04-27): outbound RPID/PAI/Privacy
 * emitter + DRY identity-resolution helper. sofia_add_rpid is consumed at 4
 * nua_invite sites (sofia_call SDP/no-SDP + fork-child SDP/no-SDP);
 * sofia_resolve_identity is shared by sofia_build_from (post-ebd26fe refactor)
 * and sofia_add_rpid. Same forward-decl-before-static-use lesson as T55.x. */
static int sofia_resolve_identity(struct sofia_pvt *pvt, char **lid_num_out,
                                   char **lid_name_out, int *lid_pres_out,
                                   char *fromdomain_buf, size_t fromdomain_len);
static int sofia_add_rpid(struct sofia_pvt *pvt, char *header_buf, size_t header_len);
/* post-T56 identity-headers parity SS3 (2026-04-27): outbound Diversion emitter
 * mirrors chan_sip add_diversion_header at chan_sip.c:12999 + R11-revised
 * privacy parameter. Consumed at the same 4 nua_invite sites as sofia_add_rpid. */
static int sofia_add_diversion(struct sofia_pvt *pvt, char *header_buf, size_t header_len);
/* post-T56 identity-headers parity SS4 + R11-revised (2026-04-27): inbound
 * RPID/PAI/Privacy parsers. sofia_check_privacy_id walks sip->sip_privacy
 * (sofia-sip native at sip.h:340/L816); sofia_get_pai/sofia_get_rpid walk
 * sip->sip_unknown for header by name (T55.4 init-snapshot precedent —
 * version-independent, no sip_extra.h class-init dependency). All three
 * trust-gated on peer->trustrpid (R6). Wire-in at sofia_process_invite
 * after peer-bind, before sofia_new (R9 — channel starts with correct
 * presentation). */
static int sofia_check_privacy_id(sip_t const *sip);
static int sofia_get_pai(struct sofia_pvt *pvt, sip_t const *sip);
static int sofia_get_rpid(struct sofia_pvt *pvt, sip_t const *sip);
/* post-T56 identity-headers parity SS5 (2026-04-27): inbound Diversion parser.
 * Mirrors chan_sip change_redirecting_information at chan_sip.c:20793 +
 * get_rdnis at chan_sip.c:16251. Walks sip->sip_unknown for "Diversion" by
 * name (T55.4 + SS4 precedent). Wired at 3 sites: sofia_process_invite,
 * sofia_process_refer, nua_r_invite status==200 — covers chan_sip's 5 sites
 * (chan_sofia collapses sites because no separate cancel-path parser). */
static int sofia_change_redirecting_info(struct sofia_pvt *pvt, sip_t const *sip);

/* T55.5 (2026-04-27): MWI re-NOTIFY cross-thread dispatch carrier.
 * mwi_event_cb fires on event-bus thread (NOT sofia_thread); we cannot
 * call nua_notify there per T40 same-thread-as-create assert. The peer
 * ref is TRANSFERRED to the callback (event_cb takes +1, dispatch carries,
 * callback drops — same ao2 ref TRANSFER pattern as T47.5 SIPnotify). */
struct mwi_dispatch_data {
	struct sofia_peer *peer;	/* +1 ref TRANSFERRED — callback drops */
};

/* T55.5: cleanup helper for mwi_dispatch_data. Safe on any thread; does
 * NO nua ops (only ao2 ref drop + ast_free). Called by both the sofia_thread
 * callback success path AND the dispatch-failure path on event-bus thread. */
static void mwi_dispatch_data_free(void *arg)
{
	struct mwi_dispatch_data *d = arg;
	if (!d) {
		return;
	}
	if (d->peer) {
		ao2_ref(d->peer, -1);
	}
	ast_free(d);
}

/* T55.5: callback dispatched to sofia_thread by mwi_event_cb. Calls
 * transmit_mwi_notify_for_peer (which re-fetches counts on this thread for
 * freshest state — closes the event-cb-to-callback latency window) then
 * frees the dispatch carrier. */
static void mwi_notify_callback(void *arg)
{
	struct mwi_dispatch_data *d = arg;
	if (!d) {
		return;
	}
	if (d->peer) {
		transmit_mwi_notify_for_peer(d->peer);
	}
	mwi_dispatch_data_free(d);
}

/* T55.5: R10 destructor cleanup callback. Issues final NOTIFY with
 * Subscription-State: terminated;reason=deactivated + destroys nh.
 * Called on sofia_thread via sofia_dispatch_to_root_thread.
 *
 * Carries ONLY nh (no peer ref) — destructor runs after peer last-unref
 * so we cannot keep peer alive across the dispatch; cleanup never accesses
 * peer fields. */
static void mwi_handle_cleanup(void *arg)
{
	nua_handle_t *nh = arg;
	if (!nh) {
		return;
	}
	nua_notify(nh,
		SIPTAG_EVENT_STR("message-summary"),
		SIPTAG_SUBSCRIPTION_STATE_STR("terminated;reason=deactivated"),
		TAG_END());
	nua_handle_destroy(nh);
}

/* Generic deferred nua_handle_destroy — runs on sofia_thread.  Used by the
 * peer destructor for peer->nh (outbound REGISTER) and peer->qualify_nh
 * (OPTIONS qualify ping) when the destructor itself may run on a non-
 * sofia_thread context (last ao2_ref drop can fire from any caller).
 * Unlike mwi_handle_cleanup this does NOT emit a terminal NOTIFY first —
 * REGISTER and OPTIONS handles do not carry a subscription dialog.
 *
 * The handle MUST already be detached from any owning struct (the caller
 * NULLs peer->nh / peer->qualify_nh before dispatching) so sofia-sip
 * cannot deliver events back to a freed peer via nh->hmagic. */
static void sofia_nh_destroy_cleanup(void *arg)
{
	nua_handle_t *nh = arg;
	if (!nh) {
		return;
	}
	nua_handle_destroy(nh);
}

/* T55.5 (2026-04-27): AST_EVENT_MWI callback fired by gabpbx core when a
 * mailbox's voicemail state changes. Runs on event-bus thread (NOT
 * sofia_thread); per T40 same-thread-as-create contract, nua_notify must
 * happen on sofia_thread. We dispatch via sofia_dispatch_to_root_thread
 * (T47.3 helper — 3rd-and-4th callsite tally with R10 destructor below
 * solidifies the helper as shared cross-thread infrastructure).
 *
 * userdata is the peer pointer captured at ast_event_subscribe time.
 * Quick-exit when no active subscription (R7 pre-subscribe-state behavior);
 * TOCTOU safety provided by transmit_mwi_notify_for_peer's nh re-check
 * under peer->lock. */
static void mwi_event_cb(const struct ast_event *event, void *userdata)
{
	struct sofia_peer *peer = userdata;
	struct mwi_dispatch_data *d;

	if (!event || !peer) {
		return;
	}

	if (!peer->mwi_subscription_handle) {
		if (sofia_debug) {
			ast_debug(2, "Sofia MWI: peer %s event ignored (no active subscriber)\n",
				peer->name);
		}
		return;
	}

	d = ast_calloc(1, sizeof(*d));
	if (!d) {
		ast_log(LOG_WARNING, "Sofia MWI: ast_calloc failed for peer %s\n", peer->name);
		return;
	}

	/* TRANSFER ref: take +1 here, dispatch carries, callback drops. */
	ao2_ref(peer, +1);
	d->peer = peer;

	if (sofia_dispatch_to_root_thread(mwi_notify_callback, d) < 0) {
		ast_log(LOG_WARNING,
			"Sofia MWI: dispatch to sofia_thread failed for peer %s\n", peer->name);
		mwi_dispatch_data_free(d);	/* drops peer ref + frees struct */
	}
}

/* T55.1 (2026-04-27): parse one mailbox spec ("mbox" or "mbox@context") and
 * append to peer->mailboxes. Caller holds peer->lock (or peer is being built
 * before insertion into peers ao2). spec is NOT consumed/owned.
 * T55.2: subscribes to AST_EVENT_MWI for the new mailbox after insertion. */
static void sofia_peer_add_mailbox(struct sofia_peer *peer, const char *spec)
{
	struct sofia_mailbox *mb;
	char *at;

	if (!peer || ast_strlen_zero(spec)) {
		return;
	}
	mb = ast_calloc(1, sizeof(*mb));
	if (!mb) {
		return;
	}
	ast_copy_string(mb->mailbox, spec, sizeof(mb->mailbox));
	at = strchr(mb->mailbox, '@');
	if (at) {
		*at++ = '\0';
		ast_copy_string(mb->context, at, sizeof(mb->context));
	} else {
		/* Per chan_sip parity: no @context defaults to "default". */
		ast_copy_string(mb->context, "default", sizeof(mb->context));
	}
	AST_LIST_INSERT_TAIL(&peer->mailboxes, mb, list);

	/* T55.2: subscribe to AST_EVENT_MWI for this mailbox+context. peer is
	 * passed as userdata; mwi_event_cb pulls IEs from the event itself. */
	mb->event_sub = ast_event_subscribe(AST_EVENT_MWI, mwi_event_cb,
		"chan_sofia MWI",
		peer,
		AST_EVENT_IE_MAILBOX, AST_EVENT_IE_PLTYPE_STR, mb->mailbox,
		AST_EVENT_IE_CONTEXT, AST_EVENT_IE_PLTYPE_STR, mb->context,
		AST_EVENT_IE_END);
	if (!mb->event_sub) {
		ast_log(LOG_WARNING,
			"Sofia MWI: ast_event_subscribe failed for peer %s mailbox %s@%s\n",
			peer->name, mb->mailbox, mb->context);
	}
}

/* T55.1: parse "mbox1@ctx1,mbox2@ctx2" comma-separated list. Spec is COPIED
 * (not consumed); each comma-segment becomes a separate sofia_mailbox entry. */
static void sofia_peer_parse_mailboxes(struct sofia_peer *peer, const char *value)
{
	char *copy, *cur, *next;

	if (!peer || ast_strlen_zero(value)) {
		return;
	}
	copy = ast_strdupa(value);
	for (cur = copy; cur; cur = next) {
		next = strchr(cur, ',');
		if (next) {
			*next++ = '\0';
		}
		while (*cur == ' ' || *cur == '\t') {
			cur++;
		}
		if (*cur) {
			sofia_peer_add_mailbox(peer, cur);
		}
	}
}

static void sofia_peer_destructor(void *obj)
{
	struct sofia_peer *peer = obj;
	struct sofia_mailbox *mb;
	if (peer->contacts) {
		ao2_ref(peer->contacts, -1);
		peer->contacts = NULL;
	}
	if (peer->ha) {
		ast_free_ha(peer->ha);
		peer->ha = NULL;
	}
	/* post-T56 contactpermit/contactdeny per-peer parity (2026-04-27): cleanup
	 * separate ACL chain. */
	if (peer->contactha) {
		ast_free_ha(peer->contactha);
		peer->contactha = NULL;
	}
	/* post-T56 directmediapermit/directmediadeny per-peer parity (2026-04-27):
	 * cleanup cross-peer-applied ACL chain. */
	if (peer->directmediaha) {
		ast_free_ha(peer->directmediaha);
		peer->directmediaha = NULL;
	}
	/* post-T56 setvar+header per-peer parity (2026-04-28, COMBINED ship): cleanup
	 * peer->chanvars linked-list of setvar + header entries. ast_variables_destroy
	 * walks the list freeing each ast_variable. Mirrors chan_sip.c:28641-28644
	 * verbatim peer destructor cleanup pattern. */
	if (peer->chanvars) {
		ast_variables_destroy(peer->chanvars);
		peer->chanvars = NULL;
	}
	/* post-T56 dnsmgr per-peer parity (2026-04-27): defensive cleanup for orphan
	 * paths (refcount=0 with peer->dnsmgr still set indicates external code did
	 * ao2_ref(-1) but missed ast_dnsmgr_release — which would leak the dnsmgr
	 * entry). Normal path: explicit reload-sweep does ast_dnsmgr_release THEN
	 * ao2_ref(-1) BEFORE refcount drops to 0; destructor sees peer->dnsmgr == NULL.
	 * Defensive release here prevents leak in edge cases. NO ao2_ref(-1) — we are
	 * already inside the destructor at refcount=0. */
	if (peer->dnsmgr) {
		ast_dnsmgr_release(peer->dnsmgr);
		peer->dnsmgr = NULL;
	}
	/* T55.1+T55.2: drain mailbox list — unsubscribe (synchronous; waits for any
	 * pending mwi_event_cb firing to complete with this mb's userdata=peer)
	 * BEFORE ast_free closes the race against concurrent event-bus delivery. */
	while ((mb = AST_LIST_REMOVE_HEAD(&peer->mailboxes, list))) {
		if (mb->event_sub) {
			mb->event_sub = ast_event_unsubscribe(mb->event_sub);
		}
		ast_free(mb);
	}

	/* T55.5 (2026-04-27): R10 — clean up active MWI subscription. nh ownership
	 * passed to mwi_handle_cleanup which runs on sofia_thread (nua_handle_destroy
	 * has same-thread-as-create requirement per T40). NO peer ref taken — we are
	 * IN the destructor (peer refcount already 0); cleanup carries only nh.
	 * If sofia_root is torn down (shutdown path), dispatch fails — leak the nh,
	 * cleared on next gabpbx restart (operationally identical to T40 fallback). */
	if (peer->mwi_subscription_handle) {
		nua_handle_t *nh = peer->mwi_subscription_handle;
		peer->mwi_subscription_handle = NULL;
		if (sofia_dispatch_to_root_thread(mwi_handle_cleanup, nh) < 0) {
			ast_log(LOG_NOTICE,
				"Sofia MWI: peer %s destructor — sofia_thread dispatch failed; "
				"leaking nh (cleared on next gabpbx restart)\n", peer->name);
		}
	}
	/* Outbound REGISTER handle (peer->nh) and qualify OPTIONS handle
	 * (peer->qualify_nh).  Same same-thread-as-create constraint as
	 * mwi_subscription_handle: nua_handle_destroy MUST run on sofia_thread.
	 * Without these cleanups a peer swept by the reload worker (or freed
	 * by any other path that drops the last ao2 ref to a non-realtime
	 * peer with an active outbound register / pending qualify) would
	 * leak the sofia-sip nua_handle and its su_home arena.
	 *
	 * The normal sweep path (sofia_peer_sweep_cb) destroys these handles
	 * synchronously before dropping the container ref so the destructor
	 * sees NULLs and skips the dispatch.  These defensive branches catch
	 * orphan paths where the peer ref drops without going through sweep
	 * (e.g. realtime peer cache rebuild after `sip prune realtime peer
	 * <name>` while a register/qualify is in flight). */
	if (peer->nh) {
		nua_handle_t *nh = peer->nh;
		peer->nh = NULL;
		if (sofia_dispatch_to_root_thread(sofia_nh_destroy_cleanup, nh) < 0) {
			ast_log(LOG_NOTICE,
				"Sofia: peer %s destructor — sofia_thread dispatch failed for "
				"peer->nh; leaking handle (cleared on next gabpbx restart)\n",
				peer->name);
		}
	}
	if (peer->qualify_nh) {
		nua_handle_t *nh = peer->qualify_nh;
		peer->qualify_nh = NULL;
		if (sofia_dispatch_to_root_thread(sofia_nh_destroy_cleanup, nh) < 0) {
			ast_log(LOG_NOTICE,
				"Sofia: peer %s destructor — sofia_thread dispatch failed for "
				"peer->qualify_nh; leaking handle (cleared on next gabpbx "
				"restart)\n", peer->name);
		}
	}
	ast_string_field_free_memory(peer);
}

/* post-T56 dnsmgr per-peer parity (2026-04-27): async DNS-update callback fired by
 * res_dnsmgr.so refresh thread when peer->host hostname resolves to a different IP
 * than previously cached. chan_sip parity at chan_sip.c:13292 verbatim signature
 * (old, new, data) — argument order critical (R6 Pattern 14 source-correction).
 *
 * Updates peer->src_addr atomically under ao2_lock (callback runs on res_dnsmgr
 * thread; concurrent reads via sofia_resolve_peer_target etc. lock-protected).
 * chan_sofia surpass: AMI DnsManagerUpdate event emission for NMS visibility into
 * upstream gateway DNS changes (chan_sip silent at on_dns_update_peer).
 *
 * Race-safety: peer ref bumped at ast_dnsmgr_lookup_cb registration via ao2_bump —
 * callback safely accesses peer even mid-destroy (ao2 holds object alive while
 * any ref outstanding). Cleanup contract: peer reload-sweep MUST call
 * ast_dnsmgr_release(peer->dnsmgr) (synchronous; waits for in-flight callbacks
 * to complete) BEFORE ao2_ref(peer, -1) for the dnsmgr-held ref. */
static void sofia_on_dns_update_peer(struct ast_sockaddr *old, struct ast_sockaddr *new, void *data)
{
	struct sofia_peer *peer = data;
	char old_buf[128], new_buf[128];

	if (!peer || !new) {
		return;
	}

	ast_copy_string(old_buf, old ? ast_sockaddr_stringify(old) : "(none)", sizeof(old_buf));
	ast_copy_string(new_buf, ast_sockaddr_stringify(new), sizeof(new_buf));

	ast_mutex_lock(&peer->lock);
	memcpy(&peer->src_addr, new, sizeof(peer->src_addr));
	ast_mutex_unlock(&peer->lock);

	ast_verbose("Sofia: dnsmgr — peer '%s' resolved %s -> %s\n",
		peer->name, old_buf, new_buf);

	manager_event(EVENT_FLAG_SYSTEM, "DnsManagerUpdate",
		"Peer: SIP/%s\r\n"
		"OldAddr: %s\r\n"
		"NewAddr: %s\r\n",
		peer->name, old_buf, new_buf);
}

/* post-T56 dnsmgr per-peer parity (2026-04-27): register async DNS lookup at peer
 * load conclusion. Skip if peer->host parses as IP literal (no DNS needed) or
 * empty/dynamic. Caller responsibility: invoke at sofia_apply_peer_variables /
 * sofia_parse_peer_config conclusion AFTER host is finalized but BEFORE ao2_link
 * publishes the peer. chan_sip parity at chan_sip.c:29137-29161 verbatim semantic. */
static void sofia_dnsmgr_setup_peer(struct sofia_peer *peer)
{
	struct ast_sockaddr probe;

	if (!peer || ast_strlen_zero(peer->host) || !strcasecmp(peer->host, "dynamic")) {
		return;
	}
	if (peer->dnsmgr) {
		return; /* already registered (idempotent for reload paths) */
	}
	/* IP-literal pre-check — if peer->host parses as an address, no DNS managment needed.
	 * Still copy the parsed address into peer->src_addr so downstream consumers
	 * (sofia_find_peer_by_ip IP-fallback, sofia_generate_sdp externaddr-substitution
	 * gate at chan_sofia.c:3031) see a populated canonical "where to reach this peer"
	 * value. Without this, static host=<ip-literal> trunks have src_addr left at the
	 * zero-init value: IP-based peer match misses them (inbound INVITE → 401) and SDP
	 * c= line stays at the bound 0.0.0.0 (no audio). */
	if (ast_sockaddr_parse(&probe, peer->host, PARSE_PORT_FORBID)) {
		ast_sockaddr_copy(&peer->src_addr, &probe);
		return;
	}
	/* ao2_bump peer ref for callback-time-safe access; ast_dnsmgr_release at cleanup
	 * decrements via the explicit ao2_ref(-1) in reload-sweep path. */
	ao2_ref(peer, +1);
	if (ast_dnsmgr_lookup_cb(peer->host, &peer->src_addr, &peer->dnsmgr, NULL,
			sofia_on_dns_update_peer, peer)) {
		ast_log(LOG_WARNING, "Sofia: dnsmgr lookup failed for peer '%s' host='%s'\n",
			peer->name, peer->host);
		ao2_ref(peer, -1);
		return;
	}
	if (!peer->dnsmgr) {
		/* dnsmgr disabled system-wide (res_dnsmgr.so dnsmgr.conf); release the
		 * ref we bumped speculatively. */
		ao2_ref(peer, -1);
	}
}

static struct sofia_peer *sofia_peer_alloc(const char *name)
{
	struct sofia_peer *peer;

	peer = ao2_alloc(sizeof(*peer), sofia_peer_destructor);
	if (!peer) {
		return NULL;
	}

	if (ast_string_field_init(peer, 512)) {
		ao2_ref(peer, -1);
		return NULL;
	}

	ast_string_field_set(peer, name, name);
	ast_string_field_set(peer, context, sofia_cfg.context);
	ast_mutex_init(&peer->lock);
	peer->type = 0;
	peer->port = DEFAULT_SIP_PORT;
	/* peer->transport is decorative in chan_sofia: per-listener bindings
	 * control which transports the server accepts, per-Contact transport is
	 * derived from the Contact URL scheme at REGISTER-time (sofia_contact at
	 * L8704-8712), and the parsers no longer write this field — the operator's
	 * `transport=` value is accepted for chan_sip drop-in template compatibility
	 * and otherwise ignored. Defensive explicit init so CLI/AMI display and the
	 * outbound-extern-port switch at sofia_build_ourip see a defined value. */
	peer->transport = SOFIA_TRANSPORT_UDP;
	/* post-T56 defaultip per-peer parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:28452 verbatim ast_sockaddr_setnull(peer->defaddr) default-init.
	 * Set non-empty by per-peer parser via ast_get_ip(peer->defaddr, v->value). */
	ast_sockaddr_setnull(&peer->defaddr);
	/* post-T56 maxcallbitrate per-peer parity (2026-04-28): inherit [general]
	 * default_maxcallbitrate; chan_sip parity at chan_sip.c:28454 verbatim. */
	peer->maxcallbitrate = sofia_cfg.default_maxcallbitrate;
	/* post-T56 amaflags per-peer parity (2026-04-28): default 0 (no AMA flags) per
	 * chan_sip drop-in; per-peer-only ([general] ABSENT). Channel-core default
	 * preserved when peer has no AMA flags (sofia_new gated on non-zero per
	 * chan_sip.c:7947-7948 verbatim). */
	peer->amaflags = 0;
	/* post-T56 subscribemwi per-peer parity (2026-04-28): default 0 FALSE per
	 * chan_sip drop-in (sip.h:324 SIP_PAGE2_SUBSCRIBEMWIONLY default-clear).
	 * PARSE-COMPAT-ONLY ship — Pattern 12 17th-instance NEW sub-pattern
	 * chan_sofia-architectural-divergence. */
	peer->subscribemwi = 0;
	/* post-T56 preferred_codec_only per-peer parity (2026-04-28): inherit [general]
	 * default_preferred_codec_only before per-peer parser overrides; chan_sip parity
	 * default-FALSE drop-in. Consumed at sofia_generate_sdp Option 6-A direction-
	 * symmetric narrowing (chan_sofia helper-architecture-advantage 12th-instance). */
	peer->preferred_codec_only = sofia_cfg.default_preferred_codec_only;
	/* post-T56 ignoresdpversion per-peer parity (2026-04-28): inherit [general] default
	 * before per-peer parser overrides. PARSE-COMPAT-ONLY (chan_sofia processes every
	 * SDP unconditionally; flag has no behavioral effect). */
	peer->ignoresdpversion = sofia_cfg.default_ignoresdpversion;
	/* post-T56 promiscredir per-peer parity (2026-04-28): inherit [general] default
	 * before per-peer parser overrides. PARSE-COMPAT-ONLY (chan_sofia nua_r_redirect
	 * handler ABSENT; flag has no behavioral effect). */
	peer->promiscredir = sofia_cfg.default_promiscredir;
	/* post-T56 autoframing per-peer parity (2026-04-28): inherit [general] default
	 * before per-peer parser overrides. PARSE-COMPAT-ONLY (chan_sofia sofia_parse_
	 * sdp ptime gate not wired today; flag has no behavioral effect). */
	peer->autoframing = sofia_cfg.default_autoframing;
	/* post-T56 faxdetect per-peer multi-mode parity (2026-04-28): inherit [general]
	 * default 4-state. SS6 (2026-04-28): chan_sofia fax-CNG + T.38 reinvite wire-
	 * in IMPLEMENTED — closes 55d4444 KNOWN LIMITATION. */
	peer->faxdetect_mode = sofia_cfg.default_faxdetect_mode;
	/* post-T56 Task #8 T.38 fax UDPTL parity SS2 (2026-04-28): T.38 defaults
	 * inherit from [general] before per-peer parser overrides. t38pt_udptl
	 * default 0 (chan_sip drop-in — operator opts in explicitly per peer);
	 * t38_ec_mode default FEC matches chan_sip `t38pt_udptl=yes` semantic;
	 * t38_maxdatagram inherits sofia_cfg.default_t38_maxdatagram (-1 sentinel
	 * = use SOFIA_T38_MAXDATAGRAM_BUILTIN 200); t38pt_usertpsource default 0. */
	peer->t38pt_udptl = 0;
	peer->t38_ec_mode = SOFIA_T38_EC_FEC;
	peer->t38_maxdatagram = sofia_cfg.default_t38_maxdatagram;
	peer->t38pt_usertpsource = 0;
	/* post-T56 timerb per-peer parity (2026-04-28): inherit [general] default
	 * Timer B before per-peer parser overrides. Pattern 16 sofia-sip-native via
	 * NTATAG_SIP_T1X64 nua_create wire-in serves global default; per-peer dynamic
	 * override deferred per t1min ac8d1ef precedent. */
	peer->timer_b = sofia_cfg.default_timer_b;
	/* post-T56 timert1 per-peer parity (2026-04-28): inherit [general] default
	 * T1 retransmission interval before per-peer parser overrides per chan_sip.c
	 * :28482 verbatim. Pattern 16 sofia-sip-native 7th-instance REWIRED via
	 * NTATAG_SIP_T1 nua_create wire-in serves global default; per-peer dynamic
	 * override deferred per Pattern 12 sub-pattern 3rd-instance (NTATAG_*_T1
	 * family deferral: t1min ac8d1ef + timerb a2e16b7 + this timert1). */
	peer->timer_t1 = sofia_cfg.default_timer_t1;
	/* post-T56 allowoverlap per-peer parity (2026-04-28, Option A FULL WIRE-IN):
	 * inherit [general] default before per-peer parser overrides. Default YES per
	 * chan_sip drop-in critical default (chan_sip.c:29479). Wire-in active at 3
	 * sites: sofia_process_invite + sofia_indicate AST_CONTROL_INCOMPLETE +
	 * nua_r_invite 484. */
	peer->allowoverlap_mode = sofia_cfg.default_allowoverlap_mode;
	/* post-T56 progressinband per-peer parity (2026-04-28): inherit [general] default
	 * tri-state. Option B partial wire-in at sofia_indicate AST_CONTROL_RINGING
	 * honors NEVER + YES exactly; NO degrades to NEVER (KNOWN LIMITATION). */
	peer->progressinband = sofia_cfg.default_progressinband;
	/* post-T56 rtp-timeout bundle per-peer parity (2026-04-28): inherit [general]
	 * 3 defaults before per-peer parser overrides; chan_sip parity at
	 * chan_sip.c:28455-28456 verbatim. Consumed at sofia_rtp_init. */
	peer->rtptimeout = sofia_cfg.default_rtptimeout;
	peer->rtpholdtimeout = sofia_cfg.default_rtpholdtimeout;
	peer->rtpkeepalive = sofia_cfg.default_rtpkeepalive;
	/* post-T56 registration TTL bounds parity (2026-04-27): Option A dual-scope —
	 * peer->expiresecs inherits [general] default_expiry. Per-peer expiresecs= /
	 * defaultexpiry= (legacy chan_sofia alias) overrides at parser branches. If
	 * sofia_load_config has already initialized sofia_cfg.default_expiry to
	 * DEFAULT_DEFAULT_EXPIRY=120, this is identical to the prior DEFAULT_EXPIRY=120
	 * macro — no behavior change for operators not using [general] defaultexpiry. */
	peer->expiresecs = sofia_cfg.default_expiry > 0 ? sofia_cfg.default_expiry : DEFAULT_EXPIRY;
	peer->capability = sofia_cfg.capability;
	peer->prefs = sofia_cfg.prefs;
	peer->dtmfmode = SOFIA_DTMF_RFC2833;
	peer->directmedia = 0;
	/* chan_sip defaults nat=force_rport. Keep the same default so migrated
	 * sip.conf peers behind NAT do not silently route in-dialog requests to
	 * private Contact addresses unless nat=no is explicitly configured. */
	peer->nat = SOFIA_NAT_FORCE_RPORT;
	peer->busy_on_active = sofia_cfg.busy_on_active;
	peer->max_contacts = sofia_cfg.max_contacts ? sofia_cfg.max_contacts : 6;
	/* Encryption must be opt-in per peer. A missing/NULL/empty realtime field is
	 * treated as encryption=no, even if [general] has encryption=yes. */
	peer->encryption = 0;
	/* post-T56 srtpcipher operator option (2026-04-27): inherit default cipher list from [general]; empty default = sdp_crypto.c hardcoded fallback. */
	if (!ast_strlen_zero(sofia_cfg.default_srtpcipher)) {
		ast_string_field_set(peer, srtpcipher, sofia_cfg.default_srtpcipher);
	}
	/* post-T56 session timers (RFC 4028) (2026-04-27): inherit defaults from [general].
	 * Default mode = ACCEPT per chan_sip parity (honor inbound, no initiate). */
	peer->session_timers = sofia_cfg.default_session_timers;
	peer->session_expires = sofia_cfg.default_session_expires;
	peer->session_minse = sofia_cfg.default_session_minse;
	peer->session_refresher = sofia_cfg.default_session_refresher;
	/* post-T56 identity-headers parity (2026-04-27): inherit identity defaults from [general]. */
	peer->callingpres = sofia_cfg.default_callingpres; /* AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED == 0 by static-zero */
	peer->sendrpid = sofia_cfg.default_sendrpid;
	peer->trustrpid = sofia_cfg.default_trustrpid;
	/* post-T56 call-limit parity SS1 (2026-04-27): inherit call-limit defaults; inUse/inRinging/onHold zero-init (runtime-only). */
	peer->call_limit = sofia_cfg.default_call_limit;
	peer->busy_level = sofia_cfg.default_busy_level;
	/* post-T56 allowtransfer per-peer parity (2026-04-27): inherit REFER policy
	 * default from [general]; chan_sip parity at chan_sip.c:8571 + L28458. Static-zero
	 * default == TRANSFER_OPENFORALL (chan_sip.c:29476 backwards-compat behavior). */
	peer->allowtransfer = sofia_cfg.default_allowtransfer;
	/* post-T56 allowsubscribe per-peer parity (2026-04-27): inherit SUBSCRIBE policy
	 * default from [general]; chan_sip parity at chan_sip.c:29478 global_flags[1]
	 * SIP_PAGE2_ALLOWSUBSCRIBE default TRUE (sip.h:478). */
	peer->allowsubscribe = sofia_cfg.default_allowsubscribe;
	/* post-T56 buggymwi per-peer parity (2026-04-27): default 0 (FALSE) — chan_sip
	 * per-peer-only flag with no [general] default. Operators with Cisco-buggy phones
	 * explicitly set buggymwi=yes; standard RFC 3842 phones use the (0/0) suffix. */
	peer->buggymwi = 0;
	/* post-T56 lockuseragent per-peer parity (2026-04-27): default 0 (FALSE) — chan_sip
	 * per-peer-only flag with no [general] default. locked_user_agent empty until first
	 * successful REGISTER captures the User-Agent string under the lock. */
	peer->lockuseragent = 0;
	peer->locked_user_agent[0] = '\0';
	/* lockuseragent_prefixes per-peer allowlist: default empty — empty value
	 * preserves the strict capture-on-first-REGISTER semantics. */
	ast_string_field_set(peer, lockuseragent_prefixes, "");
	/* post-T56 usereqphone parity (2026-04-27): inherit ;user=phone policy default
	 * from [general]; chan_sip parity at chan_sip.c:29660-29661 global_flags[0]
	 * SIP_USEREQPHONE; default 0 (off) per chan_sip flag-bit static-zero. */
	peer->usereqphone = sofia_cfg.default_usereqphone;
	/* post-T56 maxforwards parity (2026-04-27): inherit RFC 3261 §20.22 default
	 * from [general]; chan_sip parity at chan_sip.c:8519 verbatim. Default
	 * DEFAULT_MAX_FORWARDS=70 unless operator overrides via [general] maxforwards. */
	peer->maxforwards = sofia_cfg.default_max_forwards;
	/* post-T56 disallowed_methods parity (2026-04-27): inherit [general] default;
	 * chan_sip parity at chan_sip.c:28485. Pattern 12 9th-instance PARSE-COMPAT-ONLY
	 * string-storage shortcut; full-feature dynamic NUTAG_ALLOW deferred. */
	if (!ast_strlen_zero(sofia_cfg.disallowed_methods)) {
		ast_string_field_set(peer, disallowed_methods, sofia_cfg.disallowed_methods);
	}
	/* post-T56 contactpermit/contactdeny per-peer parity (2026-04-27): inherit
	 * [general] default ACL via ast_duplicate_ha_list when peer omits per-peer
	 * contactpermit/contactdeny. chan_sip parity (chan_sip.c sip_alloc-equivalent
	 * peer-build pattern). NULL passthrough handled by ast_duplicate_ha_list. */
	if (sofia_cfg.contact_ha) {
		peer->contactha = ast_duplicate_ha_list(sofia_cfg.contact_ha);
	}
	/* post-T56 subscribecontext per-peer parity (2026-04-27): inherit SUBSCRIBE
	 * dispatch-context default from [general] when peer omits subscribecontext=.
	 * chan_sip parity at chan_sip.c:28446 sip_cfg.default_subscribecontext fallback. */
	if (!ast_strlen_zero(sofia_cfg.default_subscribecontext)) {
		ast_string_field_set(peer, subscribecontext, sofia_cfg.default_subscribecontext);
	}
	/* post-T56 MOH per-peer parity (2026-04-27): inherit MOH class defaults; chan_sip parity at L8568-8569. */
	/* post-T56 language per-peer parity (2026-04-27): inherit [general] default_language
	 * before per-peer parser overrides; chan_sip parity at chan_sip.c:28447 verbatim
	 * ast_string_field_set(peer, language, default_language). */
	ast_string_field_set(peer, language, sofia_cfg.default_language);
	/* post-T56 parkinglot per-peer parity (2026-04-28): inherit [general] default_parkinglot
	 * before per-peer parser overrides; chan_sip parity at chan_sip.c:8577 verbatim
	 * ast_string_field_set(p, parkinglot, default_parkinglot). */
	ast_string_field_set(peer, parkinglot, sofia_cfg.default_parkinglot);
	if (!ast_strlen_zero(sofia_cfg.default_mohinterpret)) {
		ast_string_field_set(peer, mohinterpret, sofia_cfg.default_mohinterpret);
	}
	if (!ast_strlen_zero(sofia_cfg.default_mohsuggest)) {
		ast_string_field_set(peer, mohsuggest, sofia_cfg.default_mohsuggest);
	}
	peer->qualifyfreq = 60;
	peer->is_realtime = 0;
		peer->is_register_line = 0;
	peer->_reload_marked = 0;
	peer->contacts = ao2_container_alloc(8, contact_hash_fn, contact_cmp_fn);
	if (!peer->contacts) {
		ao2_ref(peer, -1);
		return NULL;
	}

	return peer;
}

/* post-T56 regexten + regextenonqualify parity (2026-04-27): chan_sip-parity
 * register_peer_exten helper at chan_sip.c:5189-5223 verbatim. Auto-adds (onoff=1)
 * or removes (onoff=0) one or more dialplan extensions for a peer when its
 * registration or qualify state transitions. The helper is wired at 4 sites:
 * (a) sofia_handle_register REGISTER-success after registered=1; (b) wildcard
 * unregister; (c) expiry-driven unregister; (d) qualify state-transition
 * (gated additionally on sofia_cfg.regextenonqualify).
 *
 * 4 chan_sip-parity features:
 *   - OUTER GATE on sofia_cfg.regcontext (master switch; empty = no-op)
 *   - MULTI-EXTENSION via strsep "&" (regexten=200&201@otherctx)
 *   - PER-EXT @context override (each token can override the global regcontext)
 *   - peer->name FALLBACK when peer->regexten is empty (S_OR semantic)
 *   - IDEMPOTENT add/remove (ast_exists_extension before add; pbx_find_extension
 *     E_MATCH before remove) so repeat REGISTERs don't duplicate / repeat
 *     deregisters don't error
 *
 * chan_sofia surpass over chan_sip silent fire: AMI RegextenOnQualifyTransition
 * event emitted on every add/remove so NMS systems can monitor regexten
 * dialplan-mutation in real time (chan_sip emits no AMI signal here). Direction
 * field discriminates add|remove; Trigger field is the helper's caller context.
 *
 * cleanup_stale_contexts (chan_sip.c:29714 reload-time stale-extension sweep)
 * intentionally NOT mirrored — chan_sofia is non-unloadable per T40 (sofia-sip
 * same-thread-as-create assert); operators changing regcontext value across
 * config reload restart gabpbx instead. Documented in sofia.conf.sample. */
static void register_peer_exten(struct sofia_peer *peer, int onoff)
{
	char multi[256];
	char *stringp, *ext, *context;
	struct pbx_find_info q = { .stacklen = 0 };

	if (!peer || ast_strlen_zero(sofia_cfg.regcontext)) {
		return;
	}

	ast_copy_string(multi, S_OR(peer->regexten, peer->name), sizeof(multi));
	stringp = multi;
	while ((ext = strsep(&stringp, "&"))) {
		if ((context = strchr(ext, '@'))) {
			*context++ = '\0';	/* split ext@context */
			if (!ast_context_find(context)) {
				ast_log(LOG_WARNING, "Sofia: context '%s' must exist in regcontext= in sofia.conf!\n", context);
				continue;
			}
		} else {
			context = sofia_cfg.regcontext;
		}
		if (onoff) {
			if (!ast_exists_extension(NULL, context, ext, 1, NULL)) {
				ast_add_extension(context, 1, ext, 1, NULL, NULL, "Noop",
					ast_strdup(peer->name), ast_free_ptr, "SIP");
				manager_event(EVENT_FLAG_SYSTEM, "RegextenOnQualifyTransition",
					"Peer: SIP/%s\r\n"
					"Extension: %s\r\n"
					"Context: %s\r\n"
					"Direction: add\r\n",
					peer->name, ext, context);
			}
		} else if (pbx_find_extension(NULL, NULL, &q, context, ext, 1, NULL, "", E_MATCH)) {
			ast_context_remove_extension(context, ext, 1, NULL);
			manager_event(EVENT_FLAG_SYSTEM, "RegextenOnQualifyTransition",
				"Peer: SIP/%s\r\n"
				"Extension: %s\r\n"
				"Context: %s\r\n"
				"Direction: remove\r\n",
				peer->name, ext, context);
		}
	}
}

/* post-T56 registration TTL bounds + 423 Interval Too Brief parity (2026-04-27):
 * chan_sip-parity helper for inbound REGISTER expires bounds enforcement. Mirrors
 * chan_sip.c:25699-25702 + L26148-26155 verbatim semantics — max_expiry silently
 * caps; min_expiry rejects with 423 Interval Too Brief + Min-Expires header
 * (RFC 3261 §10.2.8); expires==0 (unregister) bypasses bounds.
 *
 * sofia-sip native SIPTAG_MIN_EXPIRES_STR (sip_tag.h:1747) handles Min-Expires
 * header emission at the wire layer — Pattern 16 sofia-sip-native-protocol-mechanics
 * 5th-instance reaffirmed (no handcoded header build).
 *
 * chan_sofia surpass over chan_sip silent reject: AMI RegisterIntervalRejected
 * event (Peer + RequestedExpires + MinExpires + ResponseCode + Reason) emitted
 * at reject path so NMS systems gain real-time signal for REGISTER-storm /
 * aggressive-re-register monitoring. chan_sip emits no AMI signal on 423 (only
 * LOG_NOTICE).
 *
 * Returns 0 = accept (with *expires bounded to max_expiry if exceeded);
 *         -1 = reject (helper has emitted 423 + AMI; caller MUST return).
 *
 * Pattern 5 helper extraction at 2 callsites (sofia_process_register no-secret +
 * auth-OK paths) borderline-but-justified per (i) duplicated bounds-logic risk;
 * (ii) Min-Expires header construction non-trivial; (iii) future SUBSCRIBE/INFO
 * refresh bounds-paths reuse same helper. 21st reusable helper inventory entry. */
static int sofia_check_register_expiry(nua_t *nua, nua_handle_t *nh,
		struct sofia_peer *peer, int *expires)
{
	char min_str[16];

	if (!expires || *expires == 0) {
		/* unregister bypass per chan_sip parity at L25701 "& expires_int > 0" */
		return 0;
	}
	if (*expires > sofia_cfg.max_expiry) {
		/* silent caps per chan_sip parity at L25700 expires_int = max_expiry */
		*expires = sofia_cfg.max_expiry;
		return 0;
	}
	if (*expires < sofia_cfg.min_expiry) {
		snprintf(min_str, sizeof(min_str), "%d", sofia_cfg.min_expiry);
		nua_respond(nh, 423, "Interval Too Brief",
			SIPTAG_MIN_EXPIRES_STR(min_str),
			NUTAG_WITH_THIS(nua),
			TAG_END());
		manager_event(EVENT_FLAG_SYSTEM, "RegisterIntervalRejected",
			"Peer: SIP/%s\r\n"
			"RequestedExpires: %d\r\n"
			"MinExpires: %d\r\n"
			"ResponseCode: 423\r\n"
			"Reason: BelowMinExpiry\r\n",
			peer ? peer->name : "unknown",
			*expires, sofia_cfg.min_expiry);
		return -1;
	}
	return 0;
}

/* post-T56 germanico dynamic hints parity (2026-04-27): chan_sip-parity static
 * hint extension creation at peer load time — pairs regexten + subscribecontext
 * into a PRIORITY_HINT extension that tracks peer presence via DEVICE_STATE().
 * Mirrors germanico dynamic hints patch at chan_sip.c:5599-5606 verbatim
 * semantics with chan_sofia adaptations:
 *
 *   - Hint device "SIP/<peer->name>" (chan_sofia operator-facing convention;
 *     chan_sip uses peer->username = SIP auth identity, but chan_sofia AMI
 *     events + Dial(SIP/<peer-name>) consistently use peer->name; preserves
 *     operator-facing semantic equivalence).
 *   - snprintf for buffer safety (T42 warnings-cleanup discipline; chan_sip
 *     uses sprintf legacy form).
 *   - 2 callsites via source argument: "realtime" (sofia_find_peer_realtime
 *     conclusion) + "config" (sofia_parse_peer_config conclusion). chan_sofia
 *     surpass — chan_sip only fires at realtime-peer-load.
 *   - Registrar string differentiation: "realtime_peer" (chan_sip parity) vs
 *     "sofia_config_peer" (chan_sofia surpass) — operators inspecting via
 *     `core show hints` see hint origin.
 *   - AMI HintCreated event (Peer + Extension + Context + HintDevice + Source)
 *     emitted on every installation; chan_sofia surpass for NMS visibility into
 *     hint lifecycle (chan_sip silent).
 *
 * KNOWN LIMITATION (Pattern 12 honest-disclosure 6th-instance): no removal
 * counterpart — chan_sip absence + chan_sofia non-unloadable per T40 means
 * hints persist for module lifetime; operator restart for cleanup. Documented
 * in sofia.conf.sample. */
static void sofia_create_peer_hint(struct sofia_peer *peer, const char *source)
{
	struct ast_context *hintcontext;
	char hintsip[AST_MAX_EXTENSION + 5];
	const char *registrar;

	if (!peer || ast_strlen_zero(peer->subscribecontext) || ast_strlen_zero(peer->regexten)) {
		return; /* gate per chan_sip.c:5602-5603 verbatim — both fields required */
	}
	hintcontext = ast_context_find_or_create(NULL, NULL, peer->subscribecontext, "chan_sofia");
	if (!hintcontext) {
		ast_log(LOG_WARNING, "Sofia: failed to find_or_create hint context '%s' for peer '%s'\n",
			peer->subscribecontext, peer->name);
		return;
	}
	snprintf(hintsip, sizeof(hintsip), "SIP/%s", peer->name);
	registrar = (source && !strcmp(source, "realtime")) ? "realtime_peer" : "sofia_config_peer";
	ast_add_extension2(hintcontext, 0, peer->regexten, PRIORITY_HINT, NULL, NULL,
		hintsip, NULL, NULL, registrar);
	manager_event(EVENT_FLAG_SYSTEM, "HintCreated",
		"Peer: SIP/%s\r\n"
		"Extension: %s\r\n"
		"Context: %s\r\n"
		"HintDevice: %s\r\n"
		"Source: %s\r\n",
		peer->name, peer->regexten, peer->subscribecontext, hintsip,
		source ? source : "unknown");
}

static void sofia_apply_peer_variables(struct sofia_peer *peer, struct ast_variable *v)
{
	/* post-T56 setvar+header per-peer parity (2026-04-28, COMBINED ship): per-peer
	 * header counter — each header= entry gets unique __SIPADDHEADERpre%2d= channel-
	 * var name. Local scope resets per peer-build per chan_sip.c:28582 verbatim
	 * idiom. */
	int headercount = 0;
	for (; v; v = v->next) {
		if (!strcasecmp(v->name, "encryption") && ast_strlen_zero(v->value)) {
			peer->encryption = 0;
			continue;
		}
		if (ast_strlen_zero(v->value)) continue;
		if (!strcasecmp(v->name, "secret") || !strcasecmp(v->name, "password")) {
			ast_string_field_set(peer, secret, v->value);
			/* SS5 Finding #1 audit hardening: dual-set LOG_WARNING (symmetric
			 * to md5secret-parser site) — fires when secret= comes AFTER
			 * md5secret= in config order. md5secret takes precedence. */
			if (!ast_strlen_zero(peer->md5secret) && !ast_strlen_zero(v->value)) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' has BOTH secret= and "
					"md5secret= set — md5secret takes precedence (chan_sip.c"
					":15415-16 parity); recommend operator unset secret= to "
					"remove ambiguity\n", peer->name);
			}
		} else if (!strcasecmp(v->name, "md5secret")) {
			/* post-T56 Task #3 INVITE digest auth SS4 (2026-04-28, SW11 audit-
			 * discovered chan_sip parity gap fix): pre-hashed MD5(user:realm:secret)
			 * digest secret. chan_sip parity at chan_sip.c:15415-16 verbatim — when
			 * set, used directly as a1_hash bypassing cleartext-secret path. md5secret
			 * takes PRECEDENCE over peer->secret when both set. SS5 Finding #1
			 * audit hardening: dual-set LOG_WARNING fires HERE (config-time) —
			 * once at load instead of per-auth-call. */
			ast_string_field_set(peer, md5secret, v->value);
			if (!ast_strlen_zero(peer->secret)) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' has BOTH secret= and "
					"md5secret= set — md5secret takes precedence (chan_sip.c"
					":15415-16 parity); recommend operator unset secret= to "
					"remove ambiguity\n", peer->name);
			}
		} else if (!strcasecmp(v->name, "context")) {
			ast_string_field_set(peer, context, v->value);
		} else if (!strcasecmp(v->name, "host")) {
			ast_string_field_set(peer, host, v->value);
		} else if (!strcasecmp(v->name, "defaultuser") || !strcasecmp(v->name, "username")) {
			ast_string_field_set(peer, defaultuser, v->value);
		} else if (!strcasecmp(v->name, "fromuser")) {
			ast_string_field_set(peer, fromuser, v->value);
		} else if (!strcasecmp(v->name, "fromdomain")) {
			ast_string_field_set(peer, fromdomain, v->value);
		} else if (!strcasecmp(v->name, "callerid")) {
			ast_string_field_set(peer, callerid, v->value);
		} else if (!strcasecmp(v->name, "regexten")) {
			ast_string_field_set(peer, regexten, v->value);
		} else if (!strcasecmp(v->name, "callbackextension")) {
			/* post-T56 callbackextension per-peer parity (2026-04-28, Option A FULL
			 * WIRE-IN via Pattern 16 sofia-sip-native 12th-instance NUTAG_M_USERNAME):
			 * chan_sip parity at chan_sip.c:28869-28870 verbatim per-peer parser via
			 * DIRECT build_peer (chan_sip uses local-var `char callback[256]`; chan_
			 * sofia stores on peer for CLI/AMI display + reload-time access — chan_
			 * sofia surpass via persistence). */
			ast_string_field_set(peer, callbackextension, v->value);
		} else if (!strcasecmp(v->name, "setvar")) {
			/* post-T56 setvar per-peer parity (2026-04-28, COMBINED setvar+header
			 * ship): chan_sip parity at chan_sip.c:28953-28954 verbatim — append to
			 * peer->chanvars linked-list via Pattern 5 helper #33 sofia_add_var. */
			peer->chanvars = sofia_add_var(v->value, peer->chanvars);
		} else if (!strcasecmp(v->name, "header")) {
			/* post-T56 header per-peer parity (2026-04-28, COMBINED setvar+header
			 * ship): chan_sip parity at chan_sip.c:28955-28958 verbatim — encode as
			 * `__SIPADDHEADERpre%2d=value` channel-var with double-underscore __
			 * inheritance prefix; existing T46 sofia_build_addheader_str at chan_
			 * sofia.c:4509 absorbs via 12-char strncasecmp("SIPADDHEADER", 12) at
			 * sofia_call (L4858) → SIPTAG_HEADER_STR injection. ZERO new outbound-
			 * builder code needed. */
			char tmp[4096];
			snprintf(tmp, sizeof(tmp), "__SIPADDHEADERpre%2d=%s", ++headercount, v->value);
			peer->chanvars = sofia_add_var(tmp, peer->chanvars);
		} else if (!strcasecmp(v->name, "subscribecontext")) {
			/* post-T56 subscribecontext per-peer parity (2026-04-27): chan_sip parity at
			 * chan_sip.c:28759-28760 — per-peer SUBSCRIBE-method dispatch context override.
			 * KNOWN LIMITATION: pivot-site override deferred until presence/dialog handler. */
			ast_string_field_set(peer, subscribecontext, v->value);
		} else if (!strcasecmp(v->name, "accountcode")) {
			/* post-T56 accountcode per-peer parity (2026-04-27): chan_sip parity at
			 * chan_sip.c:28884-28885 — CDR billing-tag propagated to channel->accountcode
			 * via sofia_new acctcode-arg. Per-peer-only design (chan_sip [general]
			 * default_accountcode ABSENT; ast_default_accountcode lives at gabpbx-core
			 * cdr.conf level). Truncated to AST_MAX_ACCOUNT_CODE=20 at CDR-write time. */
			ast_string_field_set(peer, accountcode, v->value);
		} else if (!strcasecmp(v->name, "disallowed_methods")) {
			/* post-T56 disallowed_methods per-peer parity (2026-04-27): chan_sip parity at
			 * chan_sip.c:29002-29004. Pattern 12 9th-instance PARSE-COMPAT-ONLY string-storage
			 * shortcut; full-feature dynamic NUTAG_ALLOW deferred per Pattern 15. */
			ast_string_field_set(peer, disallowed_methods, v->value);
		} else if (!strcasecmp(v->name, "maxforwards")) {
			/* post-T56 maxforwards parity (2026-04-27): chan_sip parity at
			 * chan_sip.c:28878-28883 verbatim — sscanf %30d + 1-255 bounds-check +
			 * clamp-to-default on invalid. RFC 3261 §20.22 Max-Forwards initial value. */
			if (sscanf(v->value, "%30d", &peer->maxforwards) != 1
				|| peer->maxforwards < 1 || 255 < peer->maxforwards) {
				ast_log(LOG_WARNING, "Sofia: '%s' is not a valid maxforwards value for peer '%s' — using default %d\n",
					v->value, peer->name, sofia_cfg.default_max_forwards);
				peer->maxforwards = sofia_cfg.default_max_forwards;
			}
		} else if (!strcasecmp(v->name, "type")) {
			if (!strcasecmp(v->value, "friend")) peer->type = SOFIA_TYPE_FRIEND;
			else if (!strcasecmp(v->value, "peer")) peer->type = SOFIA_TYPE_PEER;
			else if (!strcasecmp(v->value, "user")) peer->type = SOFIA_TYPE_USER;
		} else if (!strcasecmp(v->name, "port")) {
			peer->port = atoi(v->value);
		} else if (!strcasecmp(v->name, "insecure")) {
			if (!strcasecmp(v->value, "port")) peer->insecure = SOFIA_INSECURE_PORT;
			else if (!strcasecmp(v->value, "invite")) peer->insecure = SOFIA_INSECURE_INVITE;
			else if (!strcasecmp(v->value, "port,invite") || !strcasecmp(v->value, "very"))
				peer->insecure = SOFIA_INSECURE_PORT | SOFIA_INSECURE_INVITE;
		} else if (!strcasecmp(v->name, "dtmfmode")) {
			if (!strcasecmp(v->value, "rfc2833")) peer->dtmfmode = SOFIA_DTMF_RFC2833;
			else if (!strcasecmp(v->value, "info")) peer->dtmfmode = SOFIA_DTMF_INFO;
			else if (!strcasecmp(v->value, "inband")) peer->dtmfmode = SOFIA_DTMF_INBAND;
			else if (!strcasecmp(v->value, "auto")) peer->dtmfmode = SOFIA_DTMF_AUTO;
		} else if (!strcasecmp(v->name, "qualify")) {
			peer->qualify = ast_true(v->value);
		} else if (!strcasecmp(v->name, "qualifyfreq")) {
			peer->qualifyfreq = atoi(v->value);
			if (peer->qualifyfreq <= 0) peer->qualifyfreq = DEFAULT_QUALIFYFREQ;
		} else if (!strcasecmp(v->name, "qualifytimeout")) {
			peer->qualifytimeout = atoi(v->value);
			if (peer->qualifytimeout <= 0) peer->qualifytimeout = DEFAULT_QUALIFYTIMEOUT;
		} else if (!strcasecmp(v->name, "directmedia")
				|| !strcasecmp(v->name, "canreinvite")) {
			/* post-T56 canreinvite alias acceptance (2026-04-28): chan_sip parity at
			 * chan_sip.c:28137 verbatim dual-key OR-chain — chan_sip operators
			 * with legacy canreinvite= configs migrate verbatim zero-rewrite. */
			peer->directmedia = ast_true(v->value);
		} else if (!strcasecmp(v->name, "busy_on_active")) {
			peer->busy_on_active = ast_true(v->value);
		} else if (!strcasecmp(v->name, "max_contacts")) {
			peer->max_contacts = sofia_clamp_max_contacts(atoi(v->value), peer->name);
		} else if (!strcasecmp(v->name, "encryption")) {
			peer->encryption = ast_true(v->value);
		} else if (!strcasecmp(v->name, "srtpcipher")) {
			/* post-T56 srtpcipher operator option (2026-04-27): comma-separated SRTP suite
			 * preference; outbound a=crypto:N emission per RFC 4568 §6.1. Lenient WARN-on-typo
			 * happens at sdp_crypto_offer_list emit time, not at parse time (operator may
			 * intentionally use suite names a future res_srtp release will support). */
			ast_string_field_set(peer, srtpcipher, v->value);
		} else if (!strcasecmp(v->name, "session-timers")) {
			/* post-T56 session timers (RFC 4028) (2026-04-27): chan_sip-verbatim dash-style
			 * key (chan_sip.c:28972). Values originate/accept/refuse map to enum at NUTAG emit. */
			if (!strcasecmp(v->value, "originate"))      peer->session_timers = SESSION_TIMERS_ORIGINATE;
			else if (!strcasecmp(v->value, "accept"))    peer->session_timers = SESSION_TIMERS_ACCEPT;
			else if (!strcasecmp(v->value, "refuse"))    peer->session_timers = SESSION_TIMERS_REFUSE;
			else {
				ast_log(LOG_WARNING, "Sofia: invalid session-timers value '%s' for peer '%s' — using default\n",
					v->value, peer->name);
				peer->session_timers = sofia_cfg.default_session_timers;
			}
		} else if (!strcasecmp(v->name, "session-expires")) {
			peer->session_expires = atoi(v->value);
			if (peer->session_expires < 90) peer->session_expires = sofia_cfg.default_session_expires;
		} else if (!strcasecmp(v->name, "session-minse")) {
			peer->session_minse = atoi(v->value);
			if (peer->session_minse < 90) peer->session_minse = sofia_cfg.default_session_minse;
		} else if (!strcasecmp(v->name, "session-refresher")) {
			if (!strcasecmp(v->value, "uac"))      peer->session_refresher = SESSION_REFRESHER_UAC;
			else if (!strcasecmp(v->value, "uas")) peer->session_refresher = SESSION_REFRESHER_UAS;
			else                                   peer->session_refresher = SESSION_REFRESHER_AUTO;
		} else if (!strcasecmp(v->name, "callingpres")) {
			/* post-T56 identity-headers parity (2026-04-27): per-peer default presentation override.
			 * Reuses gabpbx core ast_parse_caller_presentation (callerid.h:356); chan_sip parity. */
			int p = ast_parse_caller_presentation(v->value);
			peer->callingpres = (p < 0) ? AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED : p;
		} else if (!strcasecmp(v->name, "sendrpid")) {
			/* post-T56 identity-headers parity (2026-04-27): outbound RPID/PAI emission mode.
			 * "no" / "pai" / "rpid" exact strings; chan_sip SIP_SENDRPID parity. */
			if (!strcasecmp(v->value, "pai")) peer->sendrpid = 1;
			else if (!strcasecmp(v->value, "rpid")) peer->sendrpid = 2;
			else peer->sendrpid = 0;
		} else if (!strcasecmp(v->name, "trustrpid")) {
			/* post-T56 identity-headers parity (2026-04-27): trust inbound PAI/RPID; chan_sip SIP_TRUSTRPID parity. */
			peer->trustrpid = ast_true(v->value);
		} else if (!strcasecmp(v->name, "callcounter")) {
			/* post-T56 call-limit parity SS1 (2026-04-27): chan_sip parity at chan_sip.c:29055.
			 * yes -> unlimited counter participation (call_limit = INT_MAX); no -> disable. */
			peer->call_limit = ast_true(v->value) ? INT_MAX : 0;
		} else if (!strcasecmp(v->name, "call-limit") || !strcasecmp(v->name, "call_limit")) {
			/* post-T56 call-limit parity SS1 (2026-04-27): chan_sip parity at chan_sip.c:29056.
			 * call-limit = canonical hyphen form; call_limit accepted alias (R12 operator-friendly drop-in). */
			peer->call_limit = atoi(v->value);
			if (peer->call_limit < 0) peer->call_limit = 0;
		} else if (!strcasecmp(v->name, "busylevel")) {
			/* post-T56 call-limit parity SS1 (2026-04-27): chan_sip parity at chan_sip.c:29061.
			 * Soft-cap; outbound returns BUSY (486) when inUse >= busy_level. */
			peer->busy_level = atoi(v->value);
			if (peer->busy_level < 0) peer->busy_level = 0;
		} else if (!strcasecmp(v->name, "mailbox")) {
			/* T55.1 (2026-04-27): comma-separated mbox@ctx list onto peer->mailboxes (no @ defaults to context "default"). */
			sofia_peer_parse_mailboxes(peer, v->value);
		} else if (!strcasecmp(v->name, "outboundproxy")) {
			/* T56.1 (2026-04-27): per-peer outbound proxy override. Empty = unset (no Route),
			 * non-empty = use this proxy. If peer field empty + sofia_cfg.outboundproxy set, peer
			 * inherits the general default at use time. */
			ast_string_field_set(peer, outboundproxy, v->value);
		} else if (!strcasecmp(v->name, "mohinterpret")) {
			/* post-T56 MOH per-peer parity (2026-04-27): per-peer MOH class for hold-MOH (chan_sip parity). */
			ast_string_field_set(peer, mohinterpret, v->value);
		} else if (!strcasecmp(v->name, "mohsuggest")) {
			/* post-T56 MOH per-peer parity (2026-04-27): per-peer mohsuggest INBOUND-direction propagation (chan_sip parity); OUTBOUND-direction Alert-Info signaling deferred. */
			ast_string_field_set(peer, mohsuggest, v->value);
		} else if (!strcasecmp(v->name, "language")) {
			/* post-T56 language per-peer parity (2026-04-27): chan_sip parity at
			 * chan_sip.c:28865-28866 verbatim ast_string_field_set(peer, language,
			 * v->value). Per-peer audio-locale propagated to ast_channel.language at
			 * sofia_new for prompts/sounds in peer's preferred locale. */
			ast_string_field_set(peer, language, v->value);
		} else if (!strcasecmp(v->name, "parkinglot")) {
			/* post-T56 parkinglot per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28890-28891 verbatim ast_string_field_set(peer, parkinglot,
			 * v->value). Per-peer parking-lot routing propagated to ast_channel.parkinglot
			 * at sofia_new for Park()/transfer routing. */
			ast_string_field_set(peer, parkinglot, v->value);
		} else if (!strcasecmp(v->name, "defaultip")) {
			/* post-T56 defaultip per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28814-28818 verbatim ast_get_ip(peer->defaddr, v->value).
			 * chan_sofia surpass on resolve-fail: LOG_WARNING + leave defaddr setnull
			 * (preserve peer with empty defaddr); chan_sip hard-fails build_peer
			 * (return NULL drops the entire peer alloc). */
			if (!ast_strlen_zero(v->value) && ast_get_ip(&peer->defaddr, v->value)) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' defaultip='%s' could not be resolved; ignoring\n",
					peer->name, v->value);
				ast_sockaddr_setnull(&peer->defaddr);
			}
		} else if (!strcasecmp(v->name, "maxcallbitrate")) {
			/* post-T56 maxcallbitrate per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28967-28970 verbatim atoi + bounds-clamp-on-negative-to-default. */
			peer->maxcallbitrate = atoi(v->value);
			if (peer->maxcallbitrate < 0) {
				peer->maxcallbitrate = sofia_cfg.default_maxcallbitrate;
			}
		} else if (!strcasecmp(v->name, "amaflags")) {
			/* post-T56 amaflags per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28871-28877 verbatim ast_cdr_amaflags2int + LOG_WARNING-
			 * on-invalid + skip-the-bad-key. Preserves peer with empty amaflags
			 * on parse-fail (channel-core default applies at sofia_new). */
			int format = ast_cdr_amaflags2int(v->value);
			if (format < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid AMA Flags '%s'; ignoring\n",
					peer->name, v->value);
			} else {
				peer->amaflags = format;
			}
		} else if (!strcasecmp(v->name, "subscribemwi")) {
			/* post-T56 subscribemwi per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28902-28903 verbatim ast_true + SIP_PAGE2_SUBSCRIBEMWIONLY.
			 * PARSE-COMPAT-ONLY ship — chan_sofia is SUBSCRIBE-only by T55 design;
			 * subscribemwi=yes drop-in compat; subscribemwi=no operator-honest LOG_NOTICE
			 * at parse-time + KNOWN LIMITATION (no unsolicited MWI NOTIFY support).
			 * Pattern 12 17th-instance NEW sub-pattern chan_sofia-architectural-divergence. */
			peer->subscribemwi = ast_true(v->value);
			if (!peer->subscribemwi) {
				ast_log(LOG_NOTICE,
					"Sofia: peer '%s' subscribemwi=no — chan_sofia is SUBSCRIBE-only MWI "
					"(Pattern 12 17th-instance chan_sofia-architectural-divergence); "
					"unsolicited MWI NOTIFY not implemented; behavior matches chan_sip "
					"subscribemwi=yes regardless of this setting\n",
					peer->name);
			}
		} else if (!strcasecmp(v->name, "preferred_codec_only")) {
			/* post-T56 preferred_codec_only per-peer parity (2026-04-28): chan_sip parity
			 * at chan_sip.c:28922-28923 verbatim ast_set2_flag SIP_PAGE2_PREFERRED_CODEC. */
			peer->preferred_codec_only = ast_true(v->value);
		} else if (!strcasecmp(v->name, "ignoresdpversion")) {
			/* post-T56 ignoresdpversion per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28199-28201 verbatim ast_set2_flag SIP_PAGE2_IGNORESDPVERSION
			 * via handle_common_options. PARSE-COMPAT-ONLY — chan_sofia processes every
			 * SDP unconditionally (KNOWN LIMITATION documented in sample.conf). */
			peer->ignoresdpversion = ast_true(v->value);
		} else if (!strcasecmp(v->name, "promiscredir")) {
			/* post-T56 promiscredir per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28173-28175 verbatim ast_set2_flag SIP_PROMISCREDIR via
			 * handle_common_options. PARSE-COMPAT-ONLY — chan_sofia nua_r_redirect
			 * handler ABSENT (KNOWN LIMITATION documented in sample.conf). */
			peer->promiscredir = ast_true(v->value);
		} else if (!strcasecmp(v->name, "autoframing")) {
			/* post-T56 autoframing per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28924-28925 verbatim DIRECT build_peer parser (NOT
			 * handle_common_options indirection). PARSE-COMPAT-ONLY — chan_sofia
			 * sofia_parse_sdp ptime gate not wired today (KNOWN LIMITATION
			 * documented in sample.conf; future-fix ~50-70 LoC follow-up). */
			peer->autoframing = ast_true(v->value);
		} else if (!strcasecmp(v->name, "timerb")) {
			/* post-T56 timerb per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28947-28952 verbatim DIRECT build_peer parser sscanf
			 * %30d + clamp-to-default-on-invalid-or-<200 + LOG_WARNING. */
			int tmp_b;
			if ((sscanf(v->value, "%30d", &tmp_b) != 1) || tmp_b < 200) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid timerb '%s' (< 200ms or non-integer); using default %d\n",
					peer->name, v->value, sofia_cfg.default_timer_b);
				peer->timer_b = sofia_cfg.default_timer_b;
			} else {
				peer->timer_b = tmp_b;
			}
		} else if (!strcasecmp(v->name, "timert1")) {
			/* post-T56 timert1 per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28941-28946 verbatim DIRECT build_peer parser sscanf
			 * %30d + triple-clamp (val < 200 || val < t1min) → LOG_WARNING +
			 * fallback peer->timer_t1 = sofia_cfg.t1min (chan_sip-faithful
			 * "fallback to t1min not default_timer_t1" floor semantic). */
			int tmp_t1;
			if ((sscanf(v->value, "%30d", &tmp_t1) != 1) || tmp_t1 < 200 || tmp_t1 < sofia_cfg.t1min) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid timert1 '%s' (< 200ms or < t1min %d); using t1min floor\n",
					peer->name, v->value, sofia_cfg.t1min);
				peer->timer_t1 = sofia_cfg.t1min;
			} else {
				peer->timer_t1 = tmp_t1;
			}
		} else if (!strcasecmp(v->name, "faxdetect")) {
			/* faxdetect parser: yes -> cng+t38, no -> none, or a
			 * comma-separated cng/t38 set. Runtime wire-in handles DSP
			 * CNG detection and peer T.38 reINVITE detection. */
			if (ast_true(v->value)) {
				peer->faxdetect_mode = SOFIA_FAX_DETECT_BOTH;
			} else if (ast_false(v->value)) {
				peer->faxdetect_mode = SOFIA_FAX_DETECT_NONE;
			} else {
				char *fbuf = ast_strdupa(v->value);
				char *fword, *fnext = fbuf;
				peer->faxdetect_mode = SOFIA_FAX_DETECT_NONE;
				while ((fword = strsep(&fnext, ","))) {
					if (!strcasecmp(fword, "cng")) {
						peer->faxdetect_mode |= SOFIA_FAX_DETECT_CNG;
					} else if (!strcasecmp(fword, "t38")) {
						peer->faxdetect_mode |= SOFIA_FAX_DETECT_T38;
					} else {
						ast_log(LOG_WARNING, "Sofia: peer '%s' unknown faxdetect mode '%s'\n",
							peer->name, fword);
					}
				}
			}
		} else if (!strcasecmp(v->name, "t38pt_udptl")) {
			/* post-T56 Task #8 T.38 fax UDPTL parity SS2 (2026-04-28, T46.3
			 * dual-parser: same logic at config-file path + realtime path).
			 * Per-peer T.38 enable + EC mode + MaxDatagram override mirrors
			 * chan_sip.c:28038-28057 verbatim handle_t38_options semantic.
			 * Comma-separated value list: yes|no|fec|redundancy|none[,maxdatagram=N].
			 * `yes` defaults EC = FEC per chan_sip drop-in. SDP wire-in arrives
			 * SS3a; this parser only stores fields. */
			char *value = ast_strdupa(v->value);
			char *word, *next = value;
			peer->t38pt_udptl = 0;
			peer->t38_ec_mode = SOFIA_T38_EC_FEC;
			while ((word = strsep(&next, ","))) {
				int x;
				if (!strcasecmp(word, "yes")) {
					peer->t38pt_udptl = 1;
					peer->t38_ec_mode = SOFIA_T38_EC_FEC;
				} else if (!strcasecmp(word, "no")) {
					peer->t38pt_udptl = 0;
				} else if (!strcasecmp(word, "fec")) {
					peer->t38pt_udptl = 1;
					peer->t38_ec_mode = SOFIA_T38_EC_FEC;
				} else if (!strcasecmp(word, "redundancy")) {
					peer->t38pt_udptl = 1;
					peer->t38_ec_mode = SOFIA_T38_EC_REDUNDANCY;
				} else if (!strcasecmp(word, "none")) {
					peer->t38pt_udptl = 1;
					peer->t38_ec_mode = SOFIA_T38_EC_NONE;
				} else if (sscanf(word, "maxdatagram=%30d", &x) == 1) {
					peer->t38_maxdatagram = x;
				} else {
					ast_log(LOG_WARNING, "Sofia: peer '%s' unknown t38pt_udptl option '%s'\n",
						peer->name, word);
				}
			}
		} else if (!strcasecmp(v->name, "t38pt_usertpsource")) {
			/* post-T56 Task #8 T.38 fax UDPTL parity SS2 (2026-04-28, SS1.5 N3
			 * audit catch): symmetric-RTP UDPTL destination override per chan_sip.c
			 * :28061-28063 verbatim. Boolean. Consumed at SS3a SDP processing per
			 * chan_sip.c:10171 gate `SIP_PAGE2_SYMMETRICRTP && SIP_PAGE2_UDPTL_
			 * DESTINATION` mirror. */
			peer->t38pt_usertpsource = ast_true(v->value) ? 1 : 0;
		} else if (!strcasecmp(v->name, "allowoverlap")) {
			/* post-T56 allowoverlap per-peer parity (2026-04-28, Option A FULL
			 * WIRE-IN 3 sites): chan_sip parity at chan_sip.c:28188-28195 verbatim
			 * tri-state parser via handle_common_options. ast_true → YES;
			 * !strcasecmp("dtmf") → DTMF; else → NO. */
			if (ast_true(v->value)) {
				peer->allowoverlap_mode = SOFIA_OVERLAP_YES;
			} else if (!strcasecmp(v->value, "dtmf")) {
				peer->allowoverlap_mode = SOFIA_OVERLAP_DTMF;
			} else {
				peer->allowoverlap_mode = SOFIA_OVERLAP_NO;
			}
		} else if (!strcasecmp(v->name, "progressinband")) {
			/* post-T56 progressinband per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28167-28172 verbatim tri-state semantic via handle_common_options.
			 * Mirror: ast_true(v->value) → YES; non-"never" → NO; "never" literal → NEVER.
			 * Option B partial wire-in at sofia_indicate AST_CONTROL_RINGING. */
			if (ast_true(v->value)) {
				peer->progressinband = SOFIA_PROG_INBAND_YES;
			} else if (strcasecmp(v->value, "never")) {
				peer->progressinband = SOFIA_PROG_INBAND_NO;
			} else {
				peer->progressinband = SOFIA_PROG_INBAND_NEVER;
			}
		} else if (!strcasecmp(v->name, "rtptimeout")) {
			/* post-T56 rtp-timeout bundle per-peer parity (2026-04-28): chan_sip parity
			 * at chan_sip.c:28927-28930 verbatim sscanf %30d + LOG_WARNING + clamp-to-
			 * global-on-invalid semantic. */
			if ((sscanf(v->value, "%30d", &peer->rtptimeout) != 1) || peer->rtptimeout < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid rtptimeout '%s'; using default\n",
					peer->name, v->value);
				peer->rtptimeout = sofia_cfg.default_rtptimeout;
			}
		} else if (!strcasecmp(v->name, "rtpholdtimeout")) {
			/* post-T56 rtp-timeout bundle per-peer parity (2026-04-28): chan_sip parity
			 * at chan_sip.c:28932-28935 verbatim. */
			if ((sscanf(v->value, "%30d", &peer->rtpholdtimeout) != 1) || peer->rtpholdtimeout < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid rtpholdtimeout '%s'; using default\n",
					peer->name, v->value);
				peer->rtpholdtimeout = sofia_cfg.default_rtpholdtimeout;
			}
		} else if (!strcasecmp(v->name, "rtpkeepalive")) {
			/* post-T56 rtp-timeout bundle per-peer parity (2026-04-28): chan_sip parity
			 * at chan_sip.c:28937-28940 verbatim. */
			if ((sscanf(v->value, "%30d", &peer->rtpkeepalive) != 1) || peer->rtpkeepalive < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid rtpkeepalive '%s'; using default\n",
					peer->name, v->value);
				peer->rtpkeepalive = sofia_cfg.default_rtpkeepalive;
			}
		} else if (!strcasecmp(v->name, "callerid")) {
			/* post-T56 cid bundle parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28739-28744 verbatim ast_callerid_split → cid_name + cid_num. */
			char cid_name_buf[80] = "", cid_num_buf[80] = "";
			ast_callerid_split(v->value, cid_name_buf, sizeof(cid_name_buf),
				cid_num_buf, sizeof(cid_num_buf));
			ast_string_field_set(peer, cid_name, cid_name_buf);
			ast_string_field_set(peer, cid_num, cid_num_buf);
		} else if (!strcasecmp(v->name, "fullname")
				|| !strcasecmp(v->name, "cid_name")) {
			/* post-T56 cid bundle parity (2026-04-28): fullname (chan_sip parity at
			 * chan_sip.c:28747-28748 verbatim) + cid_name (chan_sofia ARCHITECTURAL
			 * ADVANTAGE 11th-instance natural-named-field-as-alias for operator
			 * convenience; chan_sip ABSENT). */
			ast_string_field_set(peer, cid_name, v->value);
		} else if (!strcasecmp(v->name, "trunkname")) {
			/* post-T56 cid bundle parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28749-28751 verbatim — trunkname clears cid_name. */
			ast_string_field_set(peer, cid_name, "");
		} else if (!strcasecmp(v->name, "cid_number")) {
			/* post-T56 cid bundle parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28752-28753 verbatim. */
			ast_string_field_set(peer, cid_num, v->value);
		} else if (!strcasecmp(v->name, "cid_tag")) {
			/* post-T56 cid bundle parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28754-28755 verbatim. */
			ast_string_field_set(peer, cid_tag, v->value);
		} else if (!strcasecmp(v->name, "callgroup")) {
			peer->callgroup = ast_get_group(v->value);
		} else if (!strcasecmp(v->name, "allowtransfer")) {
			/* post-T56 allowtransfer per-peer parity (2026-04-27): chan_sip-verbatim
			 * binary parser at chan_sip.c:28909 (ast_true → OPENFORALL/CLOSED).
			 * Drop-in operator config allowtransfer=yes/no/true/false copies verbatim. */
			peer->allowtransfer = ast_true(v->value) ? TRANSFER_OPENFORALL : TRANSFER_CLOSED;
		} else if (!strcasecmp(v->name, "allowsubscribe")) {
			/* post-T56 allowsubscribe per-peer parity (2026-04-27): chan_sip parity
			 * at chan_sip.c:28197-28198 verbatim ast_set2_flag SIP_PAGE2_ALLOWSUBSCRIBE
			 * → chan_sofia int field. REQUEST-EVENT GATING dimension #6 sibling to
			 * allowtransfer; gates inbound SUBSCRIBE per-peer (sofia_process_mwi_subscribe). */
			peer->allowsubscribe = ast_true(v->value);
		} else if (!strcasecmp(v->name, "buggymwi")) {
			/* post-T56 buggymwi per-peer parity (2026-04-27): chan_sip parity at
			 * chan_sip.c:28225-28227 verbatim ast_set2_flag SIP_PAGE2_BUGGY_MWI →
			 * chan_sofia int field. Cisco-buggy-stack MWI workaround — gates the
			 * Voice-Message " (0/0)" suffix at transmit_mwi_notify_for_peer. */
			peer->buggymwi = ast_true(v->value);
		} else if (!strcasecmp(v->name, "lockuseragent")) {
			/* post-T56 lockuseragent per-peer parity (2026-04-27): chan_sip parity
			 * at chan_sip.c:28708-28712 (realtime-only strcasecmp "0" quirk).
			 * chan_sofia surpass: ast_true generic semantic (yes/no/0/1/true/false)
			 * preserves operator-script compat — chan_sip strcasecmp "0" treats
			 * 0/no/false equivalently behaviorally. */
			peer->lockuseragent = ast_true(v->value);
		} else if (!strcasecmp(v->name, "lockuseragent_prefixes")) {
			/* lockuseragent_prefixes per-peer parity: comma-separated User-Agent
			 * prefix allowlist consulted by sofia_check_lockuseragent when
			 * lockuseragent=yes. Storage is verbatim; tokenization/trim/match
			 * happens at REGISTER-time so operators can edit the list via `sip
			 * reload` or realtime UPDATE without a restart. */
			ast_string_field_set(peer, lockuseragent_prefixes, v->value);
		} else if (!strcasecmp(v->name, "usereqphone")) {
			/* post-T56 usereqphone parity (2026-04-27): chan_sip parity at
			 * chan_sip.c:28781-28782 (flag-bit) → chan_sofia int field. RFC 3966
			 * telephone-uri ;user=phone parameter for E.164 numbers via PSTN gateways. */
			peer->usereqphone = ast_true(v->value);
		} else if (!strcasecmp(v->name, "pickupgroup")) {
			peer->pickupgroup = ast_get_group(v->value);
		} else if (!strcasecmp(v->name, "permit") || !strcasecmp(v->name, "deny")) {
			int ha_error = 0;
			peer->ha = ast_append_ha(v->name, v->value, peer->ha, &ha_error);
			if (ha_error) {
				ast_log(LOG_ERROR, "Sofia: bad %s line for peer '%s': %s\n",
					v->name, peer->name, v->value);
			}
		} else if (!strcasecmp(v->name, "contactpermit") || !strcasecmp(v->name, "contactdeny")) {
			/* post-T56 contactpermit/contactdeny per-peer parity (2026-04-27): chan_sip
			 * parity at chan_sip.c:28827-28832 verbatim — ast_append_ha(v->name + 7, ...)
			 * skips "contact" prefix. Separate ACL chain from peer->ha (Task 32 source-IP). */
			int ha_error = 0;
			if (!ast_strlen_zero(v->value)) {
				peer->contactha = ast_append_ha(v->name + 7, v->value, peer->contactha, &ha_error);
			}
			if (ha_error) {
				ast_log(LOG_ERROR, "Sofia: bad %s line for peer '%s': %s\n",
					v->name, peer->name, v->value);
			}
		} else if (!strcasecmp(v->name, "directmediapermit") || !strcasecmp(v->name, "directmediadeny")) {
			/* post-T56 directmediapermit/directmediadeny per-peer parity (2026-04-27):
			 * chan_sip parity at chan_sip.c:28835-28838 verbatim — ast_append_ha(v->name + 11, ...)
			 * skips "directmedia" prefix; remaining "permit" or "deny" passed as sense. Cross-peer
			 * cross-leg ACL applied at sofia_get_rtp_peer (chan_sofia ARCHITECTURAL ADVANTAGE
			 * 6th-instance — single gate vs chan_sip 4 process_sdp callouts). */
			int ha_error = 0;
			peer->directmediaha = ast_append_ha(v->name + 11, v->value, peer->directmediaha, &ha_error);
			if (ha_error) {
				ast_log(LOG_ERROR, "Sofia: bad directmedia %s line for peer '%s': %s\n",
					v->name, peer->name, v->value);
			}
		} else if (!strcasecmp(v->name, "nat")) {
			if (!strcasecmp(v->value, "yes")
					|| !strcasecmp(v->value, "force_rport,comedia")
					|| !strcasecmp(v->value, "comedia,force_rport"))
				peer->nat = SOFIA_NAT_FORCE_RPORT | SOFIA_NAT_COMEDIA;
			else if (!strcasecmp(v->value, "force_rport")) peer->nat = SOFIA_NAT_FORCE_RPORT;
			else if (!strcasecmp(v->value, "comedia")) peer->nat = SOFIA_NAT_COMEDIA;
			else peer->nat = 0;
		} else if (!strcasecmp(v->name, "expiresecs")) {
			peer->expiresecs = atoi(v->value);
		} else if (!strcasecmp(v->name, "transport")) {
			/* Silently accept for chan_sip drop-in template compatibility.
			 * chan_sofia does not gate per-peer inbound transport (the chan_sip
			 * check_request_transport allowlist has no security value — the
			 * check runs after socket accept + parse + peer lookup, it is
			 * policy not attack-surface reduction; FreeSWITCH's mod_sofia does
			 * not implement it). The transports the server accepts are
			 * controlled per-listener via [general] bindport / tcpbindaddr /
			 * tlsbindaddr / wsbindaddr / wssbindaddr, and per-Contact transport
			 * is derived from the Contact URL scheme at REGISTER-time
			 * (sofia_contact at L8704-8712). The value here is read but not
			 * applied; operators upgrading from chan_sip can leave their
			 * existing `transport=udp` / `transport=udp,tcp` rows in place. */
		} else if (!strcasecmp(v->name, "allow")) {
			ast_parse_allow_disallow(&peer->prefs, &peer->capability, v->value, 1);
		} else if (!strcasecmp(v->name, "disallow")) {
			ast_parse_allow_disallow(&peer->prefs, &peer->capability, v->value, 0);
		}
	}
	if (ast_strlen_zero(peer->host)) ast_string_field_set(peer, host, "dynamic");
	if (ast_strlen_zero(peer->context)) ast_string_field_set(peer, context, sofia_cfg.context);
	if (ast_strlen_zero(peer->defaultuser)) ast_string_field_set(peer, defaultuser, peer->name);
}

static struct sofia_peer *sofia_find_peer_realtime(const char *name)
{
	struct ast_variable *var;
	struct sofia_peer *peer;

	var = ast_load_realtime("sippeers", "name", name, SENTINEL);
	if (!var) return NULL;

	peer = sofia_peer_alloc(name);
	if (!peer) {
		ast_variables_destroy(var);
		return NULL;
	}

	sofia_apply_peer_variables(peer, var);
	ast_variables_destroy(var);

	/* post-T56 sipregs separate-table parity SS3 R5 (2026-04-27): sipregs
	 * overlay. When extconfig.conf wires `sipregs => …`, registration state
	 * (ipaddr/port/regseconds/fullcontact/etc.) lives in sipregs not sippeers
	 * (chan_sip parity). Sequential dual-load: sippeers config + sipregs
	 * registration overlay. R5c verified safe — sofia_apply_peer_variables at
	 * L1819 has `if (ast_strlen_zero(v->value)) continue;` skip-on-empty +
	 * `ast_string_field_set` field-replace; second application is idempotent.
	 * R5b: NULL sipregs result (peer not yet registered) silently continues
	 * with sippeers-only data — normal first-time state, not an error.
	 *
	 * Operator contract — sipregs MUST carry only registration-state columns
	 * (ipaddr, port, regseconds, fullcontact, etc.).  Never permit/deny,
	 * never contactpermit/contactdeny, never directmediapermit/
	 * directmediadeny, never setvar=, never header=.  Those columns belong
	 * in sippeers exclusively.  Putting any of them in sipregs would
	 * silently leak (the overlay's sofia_apply_peer_variables APPENDS to
	 * peer->ha / peer->contactha / peer->directmediaha / peer->chanvars
	 * already populated by the sippeers parse — per-row inside one apply
	 * call the append is correct; across two consecutive applies on the
	 * same struct it is duplication).  schema-design responsibility, not
	 * enforced in code. */
	if (ast_check_realtime("sipregs")) {
		struct ast_variable *regvar = ast_load_realtime("sipregs", "name", name, SENTINEL);
		if (regvar) {
			sofia_apply_peer_variables(peer, regvar);
			ast_variables_destroy(regvar);
		}
	}

	/* post-T56 germanico dynamic hints parity (2026-04-27): create static
	 * presence-hint extension per chan_sip.c:5599-5606 mirror — gated on
	 * peer->subscribecontext + peer->regexten both non-empty. Helper handles
	 * chan_sip-parity ast_context_find_or_create + ast_add_extension2 +
	 * AMI HintCreated surpass. Wire-in placement matches chan_sip site
	 * (after build_peer-equivalent + before peer-publish). */
	sofia_create_peer_hint(peer, "realtime");

	/* post-T56 dnsmgr per-peer parity (2026-04-27): register async DNS lookup if
	 * peer->host is hostname (not IP literal). chan_sip parity at chan_sip.c:29137-29161
	 * placement (peer-build conclusion before publish). Helper handles IP-literal
	 * pre-check + ao2_bump for callback ref + system-wide-dnsmgr-disabled fallback. */
	sofia_dnsmgr_setup_peer(peer);

	/* post-T56 dynamic_exclude_static [general] parity (2026-04-28): mirror of
	 * sofia_parse_peer_config wire-in at realtime peer-build conclusion; same
	 * chan_sip.c:29164 verbatim peer-build-time mechanism. */
	if (sofia_cfg.dynamic_exclude_static && !ast_strlen_zero(peer->host)
			&& strcasecmp(peer->host, "dynamic")) {
		struct ast_sockaddr static_addr;
		if (ast_sockaddr_parse(&static_addr, peer->host, 0)) {
			int ha_error = 0;
			sofia_cfg.contact_ha = ast_append_ha("deny",
				ast_sockaddr_stringify_addr(&static_addr),
				sofia_cfg.contact_ha, &ha_error);
			if (ha_error) {
				ast_log(LOG_ERROR,
					"Sofia: dynamic_exclude_static — bad addr for realtime static peer '%s' (%s)\n",
					peer->name, peer->host);
			}
		}
	}

	peer->is_realtime = 1;
	/* NOTE: this function is now called ONLY with ao2_lock(peers) held by
	 * sofia_find_peer (see the atomicity comment there).  That serialises
	 * concurrent realtime-cache-miss builds so no two threads can ever
	 * link duplicate peer structs for the same name into the container.
	 * Avoids the rollback problem an "optimistic build + post-lock dup-
	 * check" approach would have: by the time we get here we have ALREADY
	 * registered a dialplan hint, an ast_dnsmgr_entry with a peer ao2
	 * ref-bump, and possibly appended a dynamic_exclude_static entry to
	 * sofia_cfg.contact_ha — none of which can be cleanly unwound. */
	ao2_link(peers, peer);

	/* post-T56 allowsubscribe derive (2026-04-27): runtime-added realtime peer —
	 * if it allows, flip the global derived flag (one-way; mirrors chan_sip.c:29217
	 * post-build-peer semantic). Already-TRUE short-circuits cheaply. */
	if (peer->allowsubscribe) {
		sofia_cfg.allowsubscribe = 1;
	}

	return peer;
}

static struct sofia_peer *sofia_find_peer(const char *name)
{
	struct ao2_iterator i;
	struct sofia_peer *peer, *found = NULL;

	/* Atomically: check the in-memory cache, and on miss build via
	 * realtime — BOTH under ao2_lock(peers) so two concurrent misses for
	 * the same name cannot both run sofia_find_peer_realtime and link
	 * duplicate peer structs into the container.  The peers container
	 * was allocated with hash_fn=NULL (chan_sofia.c:17445) so it does
	 * not natively refuse duplicates by name — name uniqueness must be
	 * enforced by the callers, here.
	 *
	 * Holding the lock through the realtime DB query (sippeers +
	 * optional sipregs overlay + hint create + dnsmgr setup) briefly
	 * serialises realtime cache-miss work across threads.  This is the
	 * correct trade-off: the alternative — optimistic-build outside the
	 * lock + post-lock dup-check — would leak the LOSER thread's hint
	 * extension, dnsmgr entry and any sofia_cfg.contact_ha append (from
	 * dynamic_exclude_static) because those side effects cannot be
	 * cleanly rolled back.  Cache hits (the common case for live peers)
	 * never invoke the realtime path so concurrency on hot peers is
	 * unaffected.  Container locks in gabpbx ao2 are recursive, so
	 * helpers invoked under the lock (sofia_create_peer_hint,
	 * sofia_dnsmgr_setup_peer) that re-enter ao2 on the same container
	 * do not deadlock. */
	ao2_lock(peers);

	i = ao2_iterator_init(peers, 0);
	while ((peer = ao2_iterator_next(&i))) {
		if (!strcasecmp(peer->name, name)) {
			found = peer;
			break;
		}
		ao2_ref(peer, -1);
	}
	ao2_iterator_destroy(&i);

	if (found) {
		ao2_unlock(peers);
		return found;
	}

	if (ast_check_realtime("sippeers")) {
		found = sofia_find_peer_realtime(name);
		if (found) {
			if (sofia_debug)
				ast_verbose("Sofia: Peer '%s' found via realtime\n", name);
		}
	}

	ao2_unlock(peers);
	return found;
}

/* chan_sip parity: IP-based fallback peer match.
 * Used by sofia_process_invite after the From-username lookup fails — typical
 * for trunk gateways whose From-user is the caller-ID number rather than the
 * peer name configured in sofia.conf (host=<ip> trunks where the upstream PBX
 * sends From: <sip:<dialled-number>@…> with no relation to the local peer
 * stanza). Matches peer->src_addr (set both by dnsmgr for static host=<ip>
 * peers and by REGISTER for dynamic
 * peers) or, if that is unset, peer->defaddr. Port is ignored on purpose so
 * the existing SOFIA_INSECURE_PORT semantic stays the only port-mismatch
 * knob. First match wins (chan_sip find_peer(NULL,&addr,…) parity). */
static struct sofia_peer *sofia_find_peer_by_ip(const struct ast_sockaddr *src)
{
	struct ao2_iterator i;
	struct sofia_peer *peer, *found = NULL;

	if (!src || ast_sockaddr_isnull(src)) {
		return NULL;
	}

	i = ao2_iterator_init(peers, 0);
	while ((peer = ao2_iterator_next(&i))) {
		struct ast_sockaddr parsed;
		const struct ast_sockaddr *candidate = NULL;
		if (!ast_sockaddr_isnull(&peer->src_addr)) {
			candidate = &peer->src_addr;
		} else if (!ast_strlen_zero(peer->host)
		           && strcasecmp(peer->host, "dynamic")
		           && ast_sockaddr_parse(&parsed, peer->host, PARSE_PORT_FORBID)) {
			/* Static host=<ip-literal> peers never get src_addr populated by
			 * sofia_dnsmgr_setup_peer (it returns early at the IP-literal
			 * pre-check, chan_sofia.c:4483), so parse it on-the-fly here. */
			candidate = &parsed;
		} else if (!ast_sockaddr_isnull(&peer->defaddr)) {
			candidate = &peer->defaddr;
		}
		if (candidate && !ast_sockaddr_cmp_addr(candidate, src)) {
			found = peer;
			break;
		}
		ao2_ref(peer, -1);
	}
	ao2_iterator_destroy(&i);
	return found;
}

/* Direct media (audit bug #4): ast_rtp_glue plumbing.
 * Surpasses chan_sip's tangled flag set with a single reinvite_pending guard. */

static enum ast_rtp_glue_result sofia_get_rtp_peer(struct ast_channel *chan,
		struct ast_rtp_instance **instance)
{
	struct sofia_pvt *pvt;

	if (!chan || !(pvt = chan->tech_pvt) || !pvt->rtp) {
		return AST_RTP_GLUE_RESULT_FORBID;
	}

	ao2_ref(pvt->rtp, +1);
	*instance = pvt->rtp;

	/* T37.2.6: direct media incompatible with SRTP — disclosing the SRTP key to
	 * a remote endpoint via re-INVITE would defeat the encryption (the keys
	 * negotiated for THIS leg are not what the bridged peer would use). Force
	 * LOCAL relay whenever SRTP is active on this leg, regardless of NAT or
	 * peer->directmedia. Mirrors chan_sip.c:6172-6174. */
	if (pvt->srtp || pvt->vsrtp) {
		ast_debug(2, "Sofia: get_rtp_peer LOCAL (SRTP active, direct media inhibited)\n");
		return AST_RTP_GLUE_RESULT_LOCAL;
	}
	if (!pvt->peer || !pvt->peer->directmedia) {
		return AST_RTP_GLUE_RESULT_LOCAL;
	}
	/* Direct media is incompatible with NAT — peers behind NAT advertise
	 * private addresses the other side cannot reach. */
	if (pvt->peer->nat & (SOFIA_NAT_FORCE_RPORT | SOFIA_NAT_COMEDIA)) {
		return AST_RTP_GLUE_RESULT_LOCAL;
	}
	/* post-T56 directmediapermit/directmediadeny per-peer parity (2026-04-27):
	 * cross-peer cross-leg ACL — apply BRIDGE PARTNER's peer->directmediaha against
	 * THIS leg's RTP REMOTE addr. chan_sip parity at chan_sip.c:30362-30385
	 * apply_directmedia_ha verbatim semantic. chan_sofia ARCHITECTURAL ADVANTAGE
	 * 6th-instance ACTIVE — single gate covers all media (chan_sip applies at 4
	 * process_sdp callouts L30414+L30503+L30561+L30610 per-medium duplication).
	 * Closes Pattern 12 11th-instance deferral from commit e9d6cb1.
	 *
	 * Defensive fall-throughs: NULL bridged-chan (early bridge state) / non-sofia
	 * tech bridge partner (chan_local/chan_iax2) / NULL bridged_pvt->peer / NULL
	 * directmediaha — ALL allow REMOTE per chan_sip parity at L30372 verbatim
	 * "if (!p2->relatedpeer) return res;" NULL-passthrough. */
	{
		struct ast_channel *bridged_chan = sofia_find_bridged_channel(pvt);
		if (bridged_chan && bridged_chan->tech == &sofia_tech) {
			struct sofia_pvt *bridged_pvt = bridged_chan->tech_pvt;
			if (bridged_pvt && bridged_pvt->peer && bridged_pvt->peer->directmediaha) {
				struct ast_sockaddr them = { { 0, }, };
				ast_rtp_instance_get_remote_address(pvt->rtp, &them);
				if (ast_apply_ha(bridged_pvt->peer->directmediaha, &them) == AST_SENSE_DENY) {
					ast_debug(2, "Sofia: get_rtp_peer LOCAL — direct media to %s denied by bridge-partner '%s' directmedia ACL\n",
						ast_sockaddr_stringify(&them), bridged_pvt->peer->name);
					return AST_RTP_GLUE_RESULT_LOCAL;
				}
			}
		}
	}
	return AST_RTP_GLUE_RESULT_REMOTE;
}

static enum ast_rtp_glue_result sofia_get_vrtp_peer(struct ast_channel *chan,
		struct ast_rtp_instance **instance)
{
	/* Video direct media deferred to a future task; force relay path. */
	return AST_RTP_GLUE_RESULT_FORBID;
}

static format_t sofia_get_codec(struct ast_channel *chan)
{
	struct sofia_pvt *pvt = chan ? chan->tech_pvt : NULL;
	return pvt ? pvt->capability : 0;
}

/* post-T56 session timers (RFC 4028) (2026-04-27): compute session-timer NUTAG
 * values for a given peer + direction. Pattern 5 helper-extraction at 4 callsites
 * (sofia_call single-contact + 2 fork-child outbound INVITE + sofia_answer 200-OK
 * inbound accept-path). Pattern 16 sofia-sip-native-mechanics: chan_sofia computes
 * config-derived integers; sofia-sip handles wire mechanics (Session-Expires
 * header construction + auto-refresh scheduling + 422 Min-SE rejection).
 *
 * Returns 3 values via out-params:
 *   *out_st_seconds: -1 = skip NUTAG_SESSION_TIMER entirely (sofia-sip default behavior;
 *                         used for ACCEPT outbound — don't initiate); 0 = explicit
 *                         disable (REFUSE mode); N = include NUTAG_SESSION_TIMER(N).
 *   *out_min_se:     0 = skip NUTAG_MIN_SE; N = include NUTAG_MIN_SE(N).
 *   *out_refresher:  -1 = skip NUTAG_SESSION_REFRESHER (sofia-sip nua_any_refresher
 *                         default; negotiation decides); else maps to nua_*_refresher
 *                         enum values from /usr/local/include/sofia-sip-1.13/sofia-sip/nua_tag.h L179-184.
 *
 * Mode mapping (chan_sip sip.h L518-521 SESSION_TIMER_MODE_* parity):
 *   OFF      -> all skip (no timer activity; sofia-sip default-disabled-for-this-handle).
 *   ACCEPT   -> outbound: skip session_timer (no initiate) + publish min_se.
 *               inbound:  set session_timer (200-OK includes Session-Expires when peer asked) + publish min_se.
 *   ORIGINATE-> outbound: NUTAG_SESSION_TIMER(session_expires) + publish min_se + refresher per peer config.
 *               inbound:  same as ACCEPT (we are UAS; can't originate).
 *   REFUSE   -> NUTAG_SESSION_TIMER(0) explicit-disable (both directions); sofia-sip emits 422 Session Interval Too Small if peer offers. */
static void sofia_session_timer_values(const struct sofia_peer *peer, int is_outbound,
		int *out_st_seconds, int *out_min_se, int *out_refresher)
{
	int mode = peer ? peer->session_timers : SESSION_TIMERS_OFF;
	int expires = peer ? peer->session_expires : 0;
	int minse = peer ? peer->session_minse : 0;
	int refresher = peer ? peer->session_refresher : SESSION_REFRESHER_AUTO;

	*out_st_seconds = -1;
	*out_min_se = 0;
	*out_refresher = -1;

	if (mode == SESSION_TIMERS_REFUSE) {
		*out_st_seconds = 0;
		return;
	}
	if (mode == SESSION_TIMERS_OFF) {
		return;
	}
	if (mode == SESSION_TIMERS_ACCEPT) {
		if (is_outbound) {
			if (minse > 0) *out_min_se = minse;
			return;
		}
		if (expires > 0) *out_st_seconds = expires;
		if (minse > 0) *out_min_se = minse;
		return;
	}
	if (mode == SESSION_TIMERS_ORIGINATE) {
		if (is_outbound) {
			if (expires > 0) *out_st_seconds = expires;
			if (minse > 0) *out_min_se = minse;
			if (refresher == SESSION_REFRESHER_UAC) *out_refresher = nua_local_refresher;
			else if (refresher == SESSION_REFRESHER_UAS) *out_refresher = nua_remote_refresher;
			return;
		}
		if (expires > 0) *out_st_seconds = expires;
		if (minse > 0) *out_min_se = minse;
	}
}

/* Build an in-dialog INVITE (sofia-sip auto-detects re-INVITE on established dialog).
 * Caller MUST hold pvt->lock — this function reads pvt->redirip and writes
 * pvt->reinvite_pending; both are also touched by the sofia event-loop thread. */
static void sofia_send_reinvite(struct sofia_pvt *pvt)
{
	char sdp_buf[2048];
	/* post-T56 maxforwards parity (2026-04-27): RFC 3261 §20.22 — every outbound
	 * request needs Max-Forwards header. Pattern 16 sofia-sip-native 6th-instance
	 * via SIPTAG_MAX_FORWARDS_STR (sip_tag.h:557). */
	char mf_str[8];
	int mf = (pvt && pvt->peer) ? pvt->peer->maxforwards : sofia_cfg.default_max_forwards;
	snprintf(mf_str, sizeof(mf_str), "%d", mf);

	if (!pvt || !pvt->nh || !sofia_generate_sdp(pvt, sdp_buf, sizeof(sdp_buf))) {
		return;
	}
	pvt->reinvite_pending = 1;
	nua_invite(pvt->nh,
		SIPTAG_CONTENT_TYPE_STR("application/sdp"),
		SIPTAG_PAYLOAD_STR(sdp_buf),
		SIPTAG_MAX_FORWARDS_STR(mf_str),
		TAG_END());
	ast_verbose("Sofia: directmedia re-INVITE sent on '%s' -> %s:%d\n",
		pvt->callid ? pvt->callid : "(no-callid)",
		ast_sockaddr_stringify_host(&pvt->redirip),
		ast_sockaddr_port(&pvt->redirip));
}

static int sofia_set_rtp_peer(struct ast_channel *chan, struct ast_rtp_instance *instance,
		struct ast_rtp_instance *vinstance, struct ast_rtp_instance *tinstance,
		format_t codecs, int nat_active)
{
	struct sofia_pvt *pvt;
	struct ast_sockaddr new_redirip = {{0,}};

	if (!chan || !(pvt = chan->tech_pvt)) {
		return -1;
	}
	/* Read the bridged peer's RTP target before taking pvt->lock — the instance
	 * argument is owned by gabpbx core, not by us, so this read is independent. */
	if (instance) {
		ast_rtp_instance_get_remote_address(instance, &new_redirip);
	}

	ast_mutex_lock(&pvt->lock);
	if (pvt->alreadygone) {
		ast_mutex_unlock(&pvt->lock);
		return 0;
	}
	/* Defensive: gabpbx core only invokes this from remote_bridge_loop after
	 * both legs are bridged (post-answer), but guard against any caller that
	 * hits us before SDP negotiation completes. */
	if (pvt->state != SOFIA_DIALOG_STATE_UP) {
		ast_mutex_unlock(&pvt->lock);
		return 0;
	}
	/* If a re-INVITE is already in flight, update target but do not fire a second one;
	 * the in-flight response handler will pick up the new redirip via the next bridge tick. */
	if (pvt->reinvite_pending) {
		ast_sockaddr_copy(&pvt->redirip, &new_redirip);
		ast_mutex_unlock(&pvt->lock);
		return 0;
	}
	/* Compare against current redirip; only fire when target actually changes. */
	if (!ast_sockaddr_cmp(&new_redirip, &pvt->redirip)) {
		ast_mutex_unlock(&pvt->lock);
		return 0;
	}
	ast_sockaddr_copy(&pvt->redirip, &new_redirip);
	sofia_send_reinvite(pvt);
	ast_mutex_unlock(&pvt->lock);
	return 0;
}

static struct ast_rtp_glue sofia_rtp_glue = {
	.type = SOFIA_CHANNEL_TYPE,
	.get_rtp_info = sofia_get_rtp_peer,
	.get_vrtp_info = sofia_get_vrtp_peer,
	.update_peer = sofia_set_rtp_peer,
	.get_codec = sofia_get_codec,
};

/* Dialplan apps (T33): SIPAddHeader / SIPRemoveHeader / SIPDtmfMode.
 * Storage uses channel variables __SIPADDHEADERnn (matches chan_sip pattern at chan_sip.c:30703).
 * Outbound INVITE iterates chan->varshead and appends each as SIPTAG_HEADER_STR. */
static const char *app_dtmfmode = "SIPDtmfMode";
static const char *app_sipaddheader = "SIPAddHeader";
static const char *app_sipremoveheader = "SIPRemoveHeader";

static int sofia_app_dtmfmode(struct ast_channel *chan, const char *data)
{
	struct sofia_pvt *pvt;
	const char *mode = data;

	if (ast_strlen_zero(mode)) {
		ast_log(LOG_WARNING, "SIPDtmfMode requires argument: rfc2833 / info / inband / auto\n");
		return 0;
	}
	ast_channel_lock(chan);
	if (chan->tech != &sofia_tech) {
		ast_log(LOG_WARNING, "SIPDtmfMode only valid on Sofia channels\n");
		ast_channel_unlock(chan);
		return 0;
	}
	pvt = chan->tech_pvt;
	if (!pvt) {
		ast_channel_unlock(chan);
		return 0;
	}
	ast_mutex_lock(&pvt->lock);
	if (!strcasecmp(mode, "rfc2833"))      pvt->dtmfmode = SOFIA_DTMF_RFC2833;
	else if (!strcasecmp(mode, "info"))    pvt->dtmfmode = SOFIA_DTMF_INFO;
	else if (!strcasecmp(mode, "inband"))  pvt->dtmfmode = SOFIA_DTMF_INBAND;
	else if (!strcasecmp(mode, "auto"))    pvt->dtmfmode = SOFIA_DTMF_AUTO;
	else ast_log(LOG_WARNING, "SIPDtmfMode: unknown mode '%s'\n", mode);
	ast_mutex_unlock(&pvt->lock);
	ast_channel_unlock(chan);
	return 0;
}

static int sofia_app_addheader(struct ast_channel *chan, const char *data)
{
	int no = 0;
	int ok = 0;
	char varbuf[32];

	if (ast_strlen_zero(data)) {
		ast_log(LOG_WARNING, "SIPAddHeader requires argument: \"Header-Name: value\"\n");
		return 0;
	}
	ast_channel_lock(chan);
	while (!ok && no < 50) {
		no++;
		snprintf(varbuf, sizeof(varbuf), "__SIPADDHEADER%02d", no);
		/* getvar matches without leading underscores */
		if (pbx_builtin_getvar_helper(chan, varbuf + 2) == NULL) {
			ok = 1;
		}
	}
	if (ok) {
		size_t len = strlen(data);
		char *subbuf = ast_alloca(len + 1);
		ast_get_encoded_str(data, subbuf, len + 1);
		pbx_builtin_setvar_helper(chan, varbuf, subbuf);
	} else {
		ast_log(LOG_WARNING, "SIPAddHeader: too many headers (max 50)\n");
	}
	ast_channel_unlock(chan);
	return 0;
}

static int sofia_app_removeheader(struct ast_channel *chan, const char *data)
{
	struct ast_var_t *var;
	struct varshead *headp;
	int removeall = ast_strlen_zero(data);

	ast_channel_lock(chan);
	headp = &chan->varshead;
	AST_LIST_TRAVERSE_SAFE_BEGIN(headp, var, entries) {
		if (strncasecmp(ast_var_name(var), "SIPADDHEADER", 12) == 0) {
			if (removeall || strncasecmp(ast_var_value(var), data, strlen(data)) == 0) {
				AST_LIST_REMOVE_CURRENT(entries);
				ast_var_delete(var);
			}
		}
	}
	AST_LIST_TRAVERSE_SAFE_END;
	ast_channel_unlock(chan);
	return 0;
}

/* Build a concatenated "Name: value\r\nName2: value2\r\n..." string from the
 * channel's __SIPADDHEADER* vars. Returns 1 if any headers were added, 0 if none.
 * Caller passes a buffer (typically 2048+) and uses the result via SIPTAG_HEADER_STR. */
static int sofia_build_addheader_str(struct ast_channel *chan, char *out_buf, size_t out_len)
{
	struct ast_var_t *current;
	int found = 0;
	size_t used = 0;

	if (!chan || !out_buf || out_len < 2) {
		return 0;
	}
	out_buf[0] = '\0';
	ast_channel_lock(chan);
	AST_LIST_TRAVERSE(&chan->varshead, current, entries) {
		const char *name = ast_var_name(current);
		const char *value = ast_var_value(current);
		if (strncasecmp(name, "SIPADDHEADER", 12) != 0 || ast_strlen_zero(value)) {
			continue;
		}
		int written = snprintf(out_buf + used, out_len - used, "%s\r\n", value);
		if (written < 0 || (size_t)written >= out_len - used) {
			break;
		}
		used += written;
		found = 1;
	}
	ast_channel_unlock(chan);
	return found;
}

static int sofia_call(struct ast_channel *ast, char *dest, int timeout)
{
	struct sofia_pvt *pvt = ast->tech_pvt;
	char sdp_buf[2048];
	char addheader_buf[2048];
	int has_addheaders;

	if (!pvt) {
		ast_log(LOG_ERROR, "Sofia call: no pvt\n");
		return -1;
	}

	/* post-T56 call-limit parity SS2 R5 (2026-04-27): outbound counter increment
	 * + 486 enforcement. Wire-in BEFORE any state transition. AST_CAUSE_USER_BUSY
	 * maps to 486 Busy Here at dialplan layer (chan_sip parity at L6300).
	 * sofia_update_call_counter no-op when peer not configured (call_limit=0
	 * + busy_level=0). */
	if (sofia_update_call_counter(pvt, SOFIA_INC_CALL_RINGING) == -1) {
		ast->hangupcause = AST_CAUSE_USER_BUSY;
		return -1;
	}

	/* post-T56 identity-headers parity SS2 R8+R10 (2026-04-27): pick callingpres
	 * from channel.caller.id (chan_sip L6303 parity) — peer override (R10)
	 * applied after so operator trust-but-verify wins over channel state. */
	pvt->callingpres = ast_party_id_presentation(&ast->caller.id);
	if (pvt->peer && pvt->peer->callingpres) {
		pvt->callingpres = pvt->peer->callingpres;
	}
	/* post-T56 identity-headers parity SS6 R9 (2026-04-27): write the resolved
	 * presentation back onto the channel so dialplan reads + outbound RPID
	 * emission see consistent presentation source-of-truth. sofia_new fired
	 * earlier in sofia_request_call with pvt->callingpres = default;
	 * sofia_call now has the actual value (chan_sip parity at L7941-7942
	 * timing-shifted to here for the outbound case). */
	if (ast) {
		ast->caller.id.number.presentation = pvt->callingpres;
		ast->caller.id.name.presentation = pvt->callingpres;
	}

	/* Busy-on-active: reject if any contact has an active call */
	if (pvt->peer && pvt->peer->busy_on_active && pvt->peer->contacts) {
		int any_busy = 0;
		struct ao2_iterator ci = ao2_iterator_init(pvt->peer->contacts, 0);
		struct sofia_contact *c;
		while ((c = ao2_iterator_next(&ci))) {
			ao2_lock(c);
			if (c->active_calls > 0) {
				any_busy = 1;
				ao2_unlock(c);
				ao2_ref(c, -1);
				break;
			}
			ao2_unlock(c);
			ao2_ref(c, -1);
		}
		ao2_iterator_destroy(&ci);
		if (any_busy) {
			ast_verbose("Sofia: busy_on_active — peer '%s' has active call(s), rejecting new call\n",
				pvt->peer->name);
			ast_queue_control(ast, AST_CONTROL_BUSY);
			return 0;
		}
	}

	/* Check if peer has multiple live contacts for forking */
	if (pvt->peer && pvt->peer->contacts) {
		int live = 0;
		time_t now = time(NULL);
		struct ao2_iterator ci;
		struct sofia_contact *c;

		ci = ao2_iterator_init(pvt->peer->contacts, 0);
		while ((c = ao2_iterator_next(&ci))) {
			if (c->expires > now)
				live++;
			ao2_ref(c, -1);
		}
		ao2_iterator_destroy(&ci);

		if (live > 1) {
			/* Forking mode — create one child per live contact */
			struct sofia_fork *fork;
			int branch_idx = 0;

			fork = sofia_fork_alloc();
			if (!fork) {
				ast_log(LOG_ERROR, "Sofia: fork alloc failed\n");
				return -1;
			}

			ast_mutex_lock(&fork->lock);
			fork->master = pvt;
			fork->fork_start = now;
			ast_mutex_unlock(&fork->lock);

			pvt->fork = fork;
			pvt->is_fork_master = 1;
			/* Master has no nh — INVITEs go through child handles */

			ci = ao2_iterator_init(pvt->peer->contacts, 0);
			while ((c = ao2_iterator_next(&ci))) {
				struct sofia_pvt *child;
				char ruri[256];

				if (c->expires <= now) {
					ao2_ref(c, -1);
					continue;
				}

				child = sofia_pvt_alloc();
				if (!child) {
					ao2_ref(c, -1);
					continue;
				}

				child->fork = fork;
				ao2_ref(fork, +1);
				child->is_fork_child = 1;
				snprintf(child->fork_branch_id, sizeof(child->fork_branch_id),
					"b%d-%lx", branch_idx, (unsigned long)now);

				/* Copy dial parameters from master */
				ast_string_field_set(child, exten, pvt->exten);
				ast_string_field_set(child, peername, pvt->peername);
				ast_string_field_set(child, context, pvt->context);
				ast_string_field_set(child, username, pvt->username);
				ast_string_field_set(child, peersecret, pvt->peersecret);
				ast_string_field_set(child, fromuser, pvt->fromuser);
				ast_string_field_set(child, fromdomain, pvt->fromdomain);
				child->capability = pvt->capability;
				child->prefs = pvt->prefs;
				child->dtmfmode = pvt->dtmfmode;
				child->peer = pvt->peer;
				ao2_ref(child->peer, +1);
				/* child->owner = NULL — children never own the ast_channel */

				/* Build RURI targeting this specific contact (Step A IPv6
				 * parity SS3: c->host may be unbracketed IPv6 from REGISTER
				 * Contact URI parsing — helper #45 wraps for RFC 3261 §19.1.2). */
				{
					char hbuf[80];
					snprintf(ruri, sizeof(ruri), "sip:%s@%s:%d", pvt->exten,
						sofia_uri_format_host(c->host, hbuf, sizeof(hbuf)),
						c->port);
				}
				ast_string_field_set(child, ruri, ruri);

				/* Create handle auto-bound to child */
				if (sofia_nua) {
					child->nh = nua_handle(sofia_nua, child,
						NUTAG_URL(ruri),
						SIPTAG_TO_STR(ruri),
						TAG_END());
				}

				/* Initialize RTP and (if encryption=yes) per-child SRTP context, then SDP */
				if (child->nh && sofia_rtp_init(child) == 0) {
					int crypto_ok = 1;
					/* T37.2.5: each fork-child needs independent crypto keys per RFC 4568.
					 * Hard-fail per child on alloc errors → skip nua_invite for this contact;
					 * other contacts may still succeed. If ALL fail, fork->child_count stays 0
					 * and caller gets 503 via existing fork-empty path. No silent downgrade. */
					if (pvt->peer->encryption) {
						/* post-T56 srtpcipher operator option (2026-04-27): per-peer cipher list
						 * (or [general] fallback) drives multi-cipher a=crypto:N offer. NULL list
						 * = legacy single-line AES_CM_128_HMAC_SHA1_80. */
						const char *cipher_list = !ast_strlen_zero(pvt->peer->srtpcipher) ? pvt->peer->srtpcipher
							: (!ast_strlen_zero(sofia_cfg.default_srtpcipher) ? sofia_cfg.default_srtpcipher : NULL);
						child->srtp = sofia_srtp_alloc();
						if (!child->srtp || !(child->srtp->crypto = sdp_crypto_setup())
								|| sdp_crypto_offer_list(child->srtp->crypto, cipher_list) < 0) {
							ast_log(LOG_ERROR, "Sofia: fork-child %d crypto setup failed (peer '%s')\n",
								branch_idx, pvt->peer->name);
							if (child->srtp) { sofia_srtp_destroy(child->srtp); child->srtp = NULL; }
							crypto_ok = 0;
						}
						if (crypto_ok && child->vrtp) {
							child->vsrtp = sofia_srtp_alloc();
							if (!child->vsrtp || !(child->vsrtp->crypto = sdp_crypto_setup())
									|| sdp_crypto_offer_list(child->vsrtp->crypto, cipher_list) < 0) {
								ast_log(LOG_ERROR, "Sofia: fork-child %d video crypto setup failed (peer '%s')\n",
									branch_idx, pvt->peer->name);
								if (child->vsrtp) { sofia_srtp_destroy(child->vsrtp); child->vsrtp = NULL; }
								sofia_srtp_destroy(child->srtp); child->srtp = NULL;
								crypto_ok = 0;
							}
						}
					}
					if (crypto_ok) {
						/* post-T56 outbound-headers parity (2026-04-27): fork-child
						 * INVITE needs From + Contact too. child pvt inherits the
						 * resolved ourip from the master (set when sofia_request_call
						 * built the master pvt); helpers read child->owner connected.id
						 * (forks share the same channel/owner).
						 * post-T56 identity-headers parity SS2 (2026-04-27): same
						 * sofia_add_rpid wire-in as single-contact path. child shares
						 * master's pvt->callingpres/sendrpid/peer; helper reads them. */
						char from_buf[256];
						char contact_buf[256];
						char rpid_buf[512];
						char diversion_buf[512];
						sofia_build_from(child, from_buf, sizeof(from_buf));
						sofia_build_contact(child, contact_buf, sizeof(contact_buf));
						sofia_add_rpid(child, rpid_buf, sizeof(rpid_buf));
						/* post-T56 identity-headers parity SS3 (2026-04-27): outbound
						 * Diversion header per RFC 5806 when redirecting chain present. */
						sofia_add_diversion(child, diversion_buf, sizeof(diversion_buf));
						/* post-T56 session timers (RFC 4028) (2026-04-27): per-child
						 * NUTAG_* wire-in; helper computes per-peer + outbound values.
						 * Pattern 16 sofia-sip auto-handles refresh re-INVITE scheduling. */
						int st_seconds, st_min_se, st_refresher;
						sofia_session_timer_values(pvt->peer, 1 /* outbound */, &st_seconds, &st_min_se, &st_refresher);
						/* post-T56 maxforwards parity (2026-04-27): RFC 3261 §20.22 fork-child outbound emission. */
						char mf_str_child[8];
						snprintf(mf_str_child, sizeof(mf_str_child), "%d", child->peer ? child->peer->maxforwards : sofia_cfg.default_max_forwards);
						if (sofia_generate_sdp(child, sdp_buf, sizeof(sdp_buf))) {
							nua_invite(child->nh,
								SIPTAG_FROM_STR(from_buf),
								SIPTAG_CONTACT_STR(contact_buf),
								TAG_IF(rpid_buf[0], SIPTAG_HEADER_STR(rpid_buf)),
								TAG_IF(diversion_buf[0], SIPTAG_HEADER_STR(diversion_buf)),
								TAG_IF(st_seconds >= 0, NUTAG_SESSION_TIMER(st_seconds)),
								TAG_IF(st_min_se > 0, NUTAG_MIN_SE(st_min_se)),
								TAG_IF(st_refresher >= 0, NUTAG_SESSION_REFRESHER(st_refresher)),
								SIPTAG_CONTENT_TYPE_STR("application/sdp"),
								SIPTAG_PAYLOAD_STR(sdp_buf),
								SIPTAG_MAX_FORWARDS_STR(mf_str_child),
								TAG_END());
						} else {
							nua_invite(child->nh,
								SIPTAG_FROM_STR(from_buf),
								SIPTAG_CONTACT_STR(contact_buf),
								TAG_IF(rpid_buf[0], SIPTAG_HEADER_STR(rpid_buf)),
								TAG_IF(diversion_buf[0], SIPTAG_HEADER_STR(diversion_buf)),
								TAG_IF(st_seconds >= 0, NUTAG_SESSION_TIMER(st_seconds)),
								TAG_IF(st_min_se > 0, NUTAG_MIN_SE(st_min_se)),
								TAG_IF(st_refresher >= 0, NUTAG_SESSION_REFRESHER(st_refresher)),
								SIPTAG_MAX_FORWARDS_STR(mf_str_child),
								TAG_END());
						}
					}
				}

				ao2_link(fork->children, child);
				ao2_link(dialogs, child);

				ast_mutex_lock(&fork->lock);
				fork->child_count++;
				ast_mutex_unlock(&fork->lock);

				if (sofia_debug)
					ast_verbose("Sofia: Fork child %d -> %s (branch=%s)\n",
						branch_idx, ruri, child->fork_branch_id);

				ao2_ref(child, -1);
				branch_idx++;
				ao2_ref(c, -1);
			}
			ao2_iterator_destroy(&ci);

			pvt->state = SOFIA_DIALOG_STATE_TRYING;
			if (sofia_debug)
				ast_verbose("Sofia: Forking %d INVITEs to peer '%s' (%s)\n",
					branch_idx, pvt->peername, fork->fork_id);

			return 0;
		}
	}

	/* Single-contact path (original behavior) */
	if (!pvt->nh) {
		ast_log(LOG_ERROR, "Sofia call: no handle\n");
		return -1;
	}

	/* post-T56 outbound RTP fd-wire-order fix (2026-04-27): sofia_rtp_init
	 * MOVED to sofia_request_call BEFORE sofia_new (chan_sip-architectural-
	 * parity at chan_sip.c create_addr → sip_new ordering). Without this
	 * ordering, chan->fds[0..3] wired with pvt->rtp == NULL → bridge poll
	 * never sees outbound RTP read fd → silent one-way audio. sofia_rtp_init
	 * idempotent (L839 `if (pvt->rtp) return 0;` guard) so a second call
	 * here would be safe but explicit-delete keeps the architectural-parity
	 * intent unambiguous. */

	/* post-T56 inband DTMF detect parity SS1 R4 (2026-04-27): outbound enable
	 * after RTP setup. pvt->dtmfmode + pvt->peer were bound at
	 * sofia_request_call (L2937) before sofia_call entry — helper internal-
	 * gates on dtmfmode INBAND/AUTO so non-inband peers pay zero alloc cost. */
	sofia_enable_dsp_detect(pvt);

	/* T37: outbound encryption setup BEFORE generate_sdp so SAVP + a=crypto land
	 * in the offer. Hard-fail on alloc errors — peer config says encryption=yes
	 * and we cannot honor it; loud failure (-1 → 503 to caller) is rock-hard
	 * correct vs silent downgrade. */
	if (pvt->peer && pvt->peer->encryption) {
		/* post-T56 srtpcipher operator option (2026-04-27): per-peer cipher list (or
		 * [general] fallback) drives multi-cipher a=crypto:N offer. NULL list = legacy
		 * single-line AES_CM_128_HMAC_SHA1_80 for backwards-compat. */
		const char *cipher_list = !ast_strlen_zero(pvt->peer->srtpcipher) ? pvt->peer->srtpcipher
			: (!ast_strlen_zero(sofia_cfg.default_srtpcipher) ? sofia_cfg.default_srtpcipher : NULL);
		pvt->srtp = sofia_srtp_alloc();
		if (!pvt->srtp || !(pvt->srtp->crypto = sdp_crypto_setup())) {
			ast_log(LOG_ERROR, "Sofia: encryption=yes for peer '%s' but sdp_crypto_setup failed (res_srtp loaded?)\n",
				pvt->peer->name);
			if (pvt->srtp) { sofia_srtp_destroy(pvt->srtp); pvt->srtp = NULL; }
			return -1;
		}
		if (sdp_crypto_offer_list(pvt->srtp->crypto, cipher_list) < 0) {
			ast_log(LOG_ERROR, "Sofia: sdp_crypto_offer failed for peer '%s'\n", pvt->peer->name);
			sofia_srtp_destroy(pvt->srtp); pvt->srtp = NULL;
			return -1;
		}
		if (pvt->vrtp) {
			pvt->vsrtp = sofia_srtp_alloc();
			if (!pvt->vsrtp || !(pvt->vsrtp->crypto = sdp_crypto_setup())
					|| sdp_crypto_offer_list(pvt->vsrtp->crypto, cipher_list) < 0) {
				ast_log(LOG_ERROR, "Sofia: video crypto setup failed for peer '%s'\n", pvt->peer->name);
				if (pvt->vsrtp) { sofia_srtp_destroy(pvt->vsrtp); pvt->vsrtp = NULL; }
				sofia_srtp_destroy(pvt->srtp); pvt->srtp = NULL;
				return -1;
			}
		}
	}

	pvt->state = SOFIA_DIALOG_STATE_TRYING;

	has_addheaders = sofia_build_addheader_str(ast, addheader_buf, sizeof(addheader_buf));

	{
		/* post-T56 outbound-headers parity (2026-04-27): build From + Contact via R3+R4
		 * helpers — wire-level chan_sip parity. ourip is set by sofia_resolve_ourip in
		 * sofia_request_call so by the time we reach sofia_call (called by gabpbx core
		 * after request) ourip is populated. sofia-sip auto-emits the From-tag (R3
		 * refinement); we provide URI without ;tag=. */
		char from_buf[256];
		char contact_buf[256];
		char rpid_buf[512];
		char diversion_buf[512];
		sofia_build_from(pvt, from_buf, sizeof(from_buf));
		sofia_build_contact(pvt, contact_buf, sizeof(contact_buf));
		/* post-T56 identity-headers parity SS2 (2026-04-27): outbound RPID/PAI/
		 * Privacy emission per peer->sendrpid (sofia_add_rpid no-op when 0). */
		sofia_add_rpid(pvt, rpid_buf, sizeof(rpid_buf));
		/* post-T56 identity-headers parity SS3 (2026-04-27): outbound Diversion
		 * header per RFC 5806 when channel redirecting chain present. */
		sofia_add_diversion(pvt, diversion_buf, sizeof(diversion_buf));

		/* post-T56 session timers (RFC 4028) (2026-04-27): single-contact outbound
		 * NUTAG_* wire-in; helper computes per-peer + outbound values. */
		int st_seconds, st_min_se, st_refresher;
		sofia_session_timer_values(pvt->peer, 1 /* outbound */, &st_seconds, &st_min_se, &st_refresher);
		/* post-T56 maxforwards parity (2026-04-27): RFC 3261 §20.22 outbound emission. */
		char mf_str_call[8];
		snprintf(mf_str_call, sizeof(mf_str_call), "%d", pvt->peer ? pvt->peer->maxforwards : sofia_cfg.default_max_forwards);
		/* NAT auto-ACK suppression: if peer is behind NAT, the 200 OK Contact
		 * URI carries the LAN IP and sofia-sip's auto-ACK would route there
		 * (unroutable). We disable auto-ACK and emit a manual ACK with
		 * NUTAG_PROXY in the nua_r_invite 200 handler. */
		char nat_proxy_probe[128];
		int needs_manual_ack = sofia_build_nat_proxy_url_from_peer(pvt->peer,
			nat_proxy_probe, sizeof(nat_proxy_probe));
		if (sofia_generate_sdp(pvt, sdp_buf, sizeof(sdp_buf))) {
			nua_invite(pvt->nh,
				SIPTAG_FROM_STR(from_buf),
				SIPTAG_CONTACT_STR(contact_buf),
				TAG_IF(has_addheaders, SIPTAG_HEADER_STR(addheader_buf)),
				TAG_IF(rpid_buf[0], SIPTAG_HEADER_STR(rpid_buf)),
				TAG_IF(diversion_buf[0], SIPTAG_HEADER_STR(diversion_buf)),
				TAG_IF(st_seconds >= 0, NUTAG_SESSION_TIMER(st_seconds)),
				TAG_IF(st_min_se > 0, NUTAG_MIN_SE(st_min_se)),
				TAG_IF(st_refresher >= 0, NUTAG_SESSION_REFRESHER(st_refresher)),
				TAG_IF(needs_manual_ack, NUTAG_AUTOACK(0)),
				SIPTAG_CONTENT_TYPE_STR("application/sdp"),
				SIPTAG_PAYLOAD_STR(sdp_buf),
				SIPTAG_MAX_FORWARDS_STR(mf_str_call),
				TAG_END());
		} else {
			nua_invite(pvt->nh,
				SIPTAG_FROM_STR(from_buf),
				SIPTAG_CONTACT_STR(contact_buf),
				TAG_IF(has_addheaders, SIPTAG_HEADER_STR(addheader_buf)),
				TAG_IF(rpid_buf[0], SIPTAG_HEADER_STR(rpid_buf)),
				TAG_IF(diversion_buf[0], SIPTAG_HEADER_STR(diversion_buf)),
				TAG_IF(st_seconds >= 0, NUTAG_SESSION_TIMER(st_seconds)),
				TAG_IF(st_min_se > 0, NUTAG_MIN_SE(st_min_se)),
				TAG_IF(st_refresher >= 0, NUTAG_SESSION_REFRESHER(st_refresher)),
				TAG_IF(needs_manual_ack, NUTAG_AUTOACK(0)),
				SIPTAG_MAX_FORWARDS_STR(mf_str_call),
				TAG_END());
		}
	}

	return 0;
}

/* post-T56 SIP MESSAGE parity SS2 (2026-04-27): outbound text-message sender.
 * Mirrors chan_sip sip_sendtext at chan_sip.c:5160-5185 with R6 simplification
 * (skip is_method_allowed check; UA replies 405 Method Not Allowed if MESSAGE
 * not supported — best-effort send + sofia-sip handles UA capability internally).
 *
 * RFC 3428 §10 zero-length message specifically allowed (chan_sip L5170 parity).
 * NULL text returns 0 (no-op success); empty-string proceeds normally.
 *
 * Wired into sofia_tech.send_text — gabpbx core dialplan SendText() invokes this
 * during active calls. nua_message is in-dialog (no NUTAG_WITH_THIS needed —
 * pvt->nh already bound to the dialog from initial INVITE).
 *
 * Returns 0 on success or no-op (NULL text); -1 on missing pvt/nh (channel
 * teardown race; ast_channel_tech contract). */
static int sofia_send_text(struct ast_channel *ast, const char *text)
{
	struct sofia_pvt *pvt = ast->tech_pvt;

	if (!pvt) {
		return -1;
	}
	if (!text) {
		return 0;
	}
	if (!pvt->nh) {
		return -1;
	}

	if (sofia_debug) {
		ast_verbose("Sofia: outbound MESSAGE on %s: '%s'\n", ast->name, text);
	}

	nua_message(pvt->nh,
		SIPTAG_CONTENT_TYPE_STR("text/plain"),
		SIPTAG_PAYLOAD_STR(text),
		TAG_END());

	return 0;
}

static int sofia_write_video(struct ast_channel *ast, struct ast_frame *frame)
{
	struct sofia_pvt *pvt = ast->tech_pvt;

	if (!pvt || !pvt->vrtp) {
		return -1;
	}

	return ast_rtp_instance_write(pvt->vrtp, frame);
}

static int sofia_hangup(struct ast_channel *ast)
{
	struct sofia_pvt *pvt = ast->tech_pvt;

	if (!pvt) {
		return -1;
	}

	/* post-T56 call-limit parity SS2 R9 (2026-04-27): channel-hangup DEC site.
	 * Decrements peer->inUse if this pvt incremented it (call_inc_done flag-gated
	 * for multi-site safety with nua_i_bye + nua_r_bye + destructor catchall). */
	sofia_update_call_counter(pvt, SOFIA_DEC_CALL_LIMIT);

	ast_mutex_lock(&pvt->lock);

	/* Fork master hangup — CANCEL all children if no winner yet */
	if (pvt->is_fork_master && pvt->fork) {
		struct sofia_fork *fork = pvt->fork;
		int picked;

		ast_mutex_lock(&fork->lock);
		picked = fork->winner_picked;
		ast_mutex_unlock(&fork->lock);

		if (!picked) {
			ao2_callback(fork->children, OBJ_UNLINK | OBJ_MULTIPLE | OBJ_NODATA,
				sofia_fork_cancel_all_cb, NULL);
			ast_verbose("Sofia: Fork master hangup — cancelled all children (%s)\n",
				fork->fork_id);
		}
		/* Post-winner: master has stolen winner's nh, fall through to nua_bye below */

		ao2_ref(fork, -1);
		pvt->fork = NULL;
		pvt->is_fork_master = 0;
	}

	/* chan_sip parity (SIP_DEFER_BYE_ON_TRANSFER at chan_sip.c:7051-7067). When the
	 * REFER handler has armed defer_bye, the transferer's UA owns the dialog teardown:
	 * detach the channel side here but leave the SIP dialog alive (no nua_bye, no
	 * ao2_unlink). The safety-net timer sofia_defer_bye_cb or the incoming-BYE handler
	 * (sofia_process_bye) tears the pvt down later. */
	if (pvt->defer_bye) {
		pvt->owner = NULL;
		ast->tech_pvt = NULL;
		ast_mutex_unlock(&pvt->lock);
		ao2_ref(pvt, -1);
		return 0;
	}

	if (pvt->nh) {
		if (pvt->state == SOFIA_DIALOG_STATE_UP || pvt->state == SOFIA_DIALOG_STATE_RINGING) {
			char target_url[256];
			int use_target = sofia_pvt_build_nat_target_url(pvt, target_url, sizeof(target_url));
			nua_bye(pvt->nh,
				TAG_IF(use_target, NUTAG_PROXY(target_url)),
				TAG_END());
		} else {
			nua_cancel(pvt->nh, TAG_END());
		}
	}

	pvt->owner = NULL;
	ast->tech_pvt = NULL;
	pvt->state = SOFIA_DIALOG_STATE_DOWN;

	ast_mutex_unlock(&pvt->lock);

	ao2_unlink(dialogs, pvt);
	ao2_ref(pvt, -1);

	return 0;
}

static int sofia_answer(struct ast_channel *ast)
{
	struct sofia_pvt *pvt = ast->tech_pvt;
	/* SS4 audit pre-existing concern fold-in (2026-04-28): bump sdp_buf
	 * 1024 → 2048 for parity with other 4 callsites at L5058/5259/6264/etc.
	 * T.38 emission at SS3b adds ~250 bytes (m=image + 8 a=T38Fax* attributes)
	 * to worst-case audio+video SDP; 1024 too tight under T.38-with-codec-rich
	 * peers. SS3b emitter snprintf-truncates safely if oversize but silently
	 * drops trailing attributes — operator-invisible bug. Bump preserves all
	 * attrs in flight. */
	char sdp_buf[2048];

	if (!pvt || !pvt->nh) {
		return -1;
	}

	{
		/* post-T56 session timers (RFC 4028) (2026-04-27): inbound 200-OK
		 * accept-path NUTAG_* wire-in; helper computes per-peer + inbound
		 * values. sofia-sip auto-includes Session-Expires header in 200-OK
		 * when peer's INVITE carried Session-Expires + our mode != REFUSE. */
		int st_seconds, st_min_se, st_refresher;
		sofia_session_timer_values(pvt->peer, 0 /* inbound */, &st_seconds, &st_min_se, &st_refresher);
		if (sofia_generate_sdp(pvt, sdp_buf, sizeof(sdp_buf))) {
			nua_respond(pvt->nh, SIP_200_OK,
				TAG_IF(st_seconds >= 0, NUTAG_SESSION_TIMER(st_seconds)),
				TAG_IF(st_min_se > 0, NUTAG_MIN_SE(st_min_se)),
				TAG_IF(st_refresher >= 0, NUTAG_SESSION_REFRESHER(st_refresher)),
				SIPTAG_CONTENT_TYPE_STR("application/sdp"),
				SIPTAG_PAYLOAD_STR(sdp_buf),
				TAG_END());
		} else {
			nua_respond(pvt->nh, SIP_200_OK,
				TAG_IF(st_seconds >= 0, NUTAG_SESSION_TIMER(st_seconds)),
				TAG_IF(st_min_se > 0, NUTAG_MIN_SE(st_min_se)),
				TAG_IF(st_refresher >= 0, NUTAG_SESSION_REFRESHER(st_refresher)),
				TAG_END());
		}
	}

	pvt->state = SOFIA_DIALOG_STATE_UP;
	ast_setstate(ast, AST_STATE_UP);

	return 0;
}

static struct ast_frame *sofia_read(struct ast_channel *ast)
{
	struct sofia_pvt *pvt = ast->tech_pvt;

	if (!pvt) {
		return &ast_null_frame;
	}

	if (pvt->is_fork_master && pvt->fork) {
		int picked;
		ast_mutex_lock(&pvt->fork->lock);
		picked = pvt->fork->winner_picked;
		ast_mutex_unlock(&pvt->fork->lock);
		if (!picked)
			return &ast_null_frame;
	}

	switch (ast->fdno) {
	case 0: {
		struct ast_frame *f;
		if (!pvt->rtp) return &ast_null_frame;
		f = ast_rtp_instance_read(pvt->rtp, 0);
		/* post-T56 inband DTMF detect parity SS1 R6 (2026-04-27): audio-path
		 * DSP processing. ast_dsp_process emits AST_FRAME_DTMF when tone
		 * detected; otherwise passes the frame through unchanged. chan_sip
		 * parity at chan_sip.c:8254-8255 (audio-only; rtcp + video paths
		 * bypass DSP). DSP is NULL when neither DTMF nor fax-CNG detection
		 * needs it. */
		if (f && pvt->dsp && pvt->owner) {
			f = ast_dsp_process(pvt->owner, pvt->dsp, f);
			/* post-T56 Task #8 T.38 fax UDPTL parity SS6 (2026-04-28):
			 * ast_dsp_process emits AST_FRAME_DTMF subclass 'f' on fax CNG
			 * tone detection. Mirrors chan_sip.c:8288 verbatim semantic —
			 * `if (faxdetected && SIP_PAGE2_FAX_DETECT_CNG)`. async-goto
			 * channel into "fax" extension per chan_sip pattern; dialplan
			 * runs SendFAX/ReceiveFAX which uses ast_channel_get_t38_state
			 * (SS5 sofia_queryoption AST_OPTION_T38_STATE handler) to
			 * trigger T.38 reINVITE via setoption / control-frame chain.
			 * FAXEXTEN channel-var carries original extension for return-on-
			 * fax-end pattern (chan_sip parity). pvt->faxdetect_mode-gated
			 * via pvt->peer->faxdetect_mode (no mid-call override). */
			if (f && f->frametype == AST_FRAME_DTMF &&
			    f->subclass.integer == 'f' &&
			    pvt->peer && (pvt->peer->faxdetect_mode & SOFIA_FAX_DETECT_CNG)) {
				struct ast_channel *chan = pvt->owner;
				if (chan && strcmp(chan->exten, "fax")) {
					const char *target_context = S_OR(chan->macrocontext, chan->context);
					if (ast_exists_extension(chan, target_context, "fax", 1,
					    S_COR(chan->caller.id.number.valid, chan->caller.id.number.str, NULL))) {
						ast_verbose(VERBOSE_PREFIX_2 "Sofia: redirecting '%s' to fax extension due to CNG detection\n",
							chan->name);
						pbx_builtin_setvar_helper(chan, "FAXEXTEN", chan->exten);
						if (ast_async_goto(chan, target_context, "fax", 1)) {
							ast_log(LOG_NOTICE, "Sofia: failed to async goto '%s' into fax of '%s'\n",
								chan->name, target_context);
						}
						ast_frfree(f);
						return &ast_null_frame;
					}
				}
			}
		}
		return f;
	}
	case 1:
		if (!pvt->rtp) return &ast_null_frame;
		return ast_rtp_instance_read(pvt->rtp, 1);
	case 2:
		if (!pvt->vrtp) return &ast_null_frame;
		return ast_rtp_instance_read(pvt->vrtp, 0);
	case 3:
		if (!pvt->vrtp) return &ast_null_frame;
		return ast_rtp_instance_read(pvt->vrtp, 1);
	case 5:
		/* post-T56 Task #8 T.38 fax UDPTL parity SS5 (2026-04-28, packet
		 * relay read path): UDPTL frame dispatch from fd-5 (chan_sip.c:8223
		 * verbatim semantic). Returns AST_FRAME_MODEM frames into core for
		 * res_fax/app_fax consumption. NULL-safe — returns null_frame if
		 * pvt->udptl raced to NULL between fd-poll and read (sofia_hangup
		 * + sofia_pvt_destructor ast_udptl_destroy ordering). */
		if (!pvt->udptl) return &ast_null_frame;
		return ast_udptl_read(pvt->udptl);
	default:
		return &ast_null_frame;
	}
}

static int sofia_write(struct ast_channel *ast, struct ast_frame *frame)
{
	struct sofia_pvt *pvt = ast->tech_pvt;

	if (!pvt) {
		return -1;
	}

	if (pvt->is_fork_master && pvt->fork) {
		int picked;
		ast_mutex_lock(&pvt->fork->lock);
		picked = pvt->fork->winner_picked;
		ast_mutex_unlock(&pvt->fork->lock);
		if (!picked)
			return 0;
	}

	/* post-T56 Task #8 T.38 fax UDPTL parity SS5 (2026-04-28, packet relay
	 * write path): AST_FRAME_MODEM frame-type → ast_udptl_write mirrors
	 * chan_sip.c:7353-7370 verbatim semantic. Gated on dialog UP-state +
	 * pvt->udptl non-NULL + t38_state == ENABLED to avoid emitting UDPTL
	 * before negotiation completes (chan_sip pattern: silently drops MODEM
	 * frames pre-negotiation; fax stack re-transmits — comment at chan_sip.c
	 * :7355-7358 explains UDPTL is two-way so early-media has no value). */
	if (frame->frametype == AST_FRAME_MODEM) {
		if (ast->_state == AST_STATE_UP &&
		    pvt->udptl &&
		    pvt->t38_state == SOFIA_T38_ENABLED) {
			return ast_udptl_write(pvt->udptl, frame);
		}
		return 0;
	}

	if (!pvt->rtp) {
		return -1;
	}

	return ast_rtp_instance_write(pvt->rtp, frame);
}

static int sofia_indicate(struct ast_channel *ast, int condition, const void *data, size_t datalen)
{
	struct sofia_pvt *pvt = ast->tech_pvt;

	if (!pvt) {
		return -1;
	}

	if (pvt->is_fork_master && pvt->fork) {
		int picked;
		ast_mutex_lock(&pvt->fork->lock);
		picked = pvt->fork->winner_picked;
		ast_mutex_unlock(&pvt->fork->lock);
		if (!picked)
			return 0;
	}

	if (!pvt->nh) {
		return -1;
	}

	switch (condition) {
	case AST_CONTROL_RINGING:
		nua_respond(pvt->nh, SIP_180_RINGING, TAG_END());
		/* post-T56 progressinband per-peer + [general] tri-state parity (2026-04-28,
		 * Option B partial wire-in): YES → return -1 to force core in-band audio
		 * playback per chan_sip.c:7631 verbatim semantic. NEVER (default) + NO
		 * states return 0 (SIP-handled, no in-band). NO state degrades to NEVER
		 * behavior (KNOWN LIMITATION: chan_sofia lacks SIP_PROGRESS_SENT tracking
		 * infrastructure for chan_sip's "after-progress-sent in-band" 2nd-call
		 * semantic; Pattern 12 24th-instance + chan_sofia-architectural-divergence
		 * sub-pattern 5th-instance partial-feature-parity). */
		if (pvt->peer && pvt->peer->progressinband == SOFIA_PROG_INBAND_YES) {
			return -1;
		}
		break;
	case AST_CONTROL_BUSY:
		nua_respond(pvt->nh, SIP_486_BUSY_HERE, TAG_END());
		break;
	case AST_CONTROL_INCOMPLETE:
		/* post-T56 allowoverlap per-peer + [general] parity (2026-04-28, Option A
		 * FULL WIRE-IN site B — sofia_indicate AST_CONTROL_INCOMPLETE case): mirror
		 * chan_sip.c:7661-7669 verbatim semantic for dialplan-driven Incomplete-app
		 * path. ast_state pre-UP gating + tri-state mode dispatch. YES → 484 Address
		 * Incomplete; DTMF → wait for inband DTMF (no-op per chan_sip.c:7669 comment
		 * "Just wait for inband DTMF digits"); NO/default → 404 Not Found. Effective
		 * mode = pvt->peer->allowoverlap_mode when peer bound; else sofia_cfg
		 * .default_allowoverlap_mode. */
		if (ast->_state != AST_STATE_UP) {
			int overlap_mode = pvt->peer ? pvt->peer->allowoverlap_mode : sofia_cfg.default_allowoverlap_mode;
			switch (overlap_mode) {
			case SOFIA_OVERLAP_YES:
				nua_respond(pvt->nh, SIP_484_ADDRESS_INCOMPLETE, TAG_END());
				break;
			case SOFIA_OVERLAP_DTMF:
				/* Just wait for inband DTMF digits per chan_sip.c:7669 verbatim. */
				break;
			default:
				nua_respond(pvt->nh, SIP_404_NOT_FOUND, TAG_END());
				break;
			}
		}
		break;
	case AST_CONTROL_CONGESTION:
		nua_respond(pvt->nh, SIP_503_SERVICE_UNAVAILABLE, TAG_END());
		break;
	case AST_CONTROL_PROGRESS:
		/* post-T56 prematuremedia parity (2026-04-27): INVERTED-SEMANTIC chan_sip-quirk
		 * preserved per chan_sip.c:7298 verbatim — when sofia_cfg.prematuremediafilter
		 * is TRUE (filter ON, default), 183 Session Progress is SUPPRESSED even on
		 * dialplan explicit Progress() call. operator-key "prematuremedia=yes" reads
		 * counter-intuitively but matches chan_sip drop-in compat exactly. */
		if (!sofia_cfg.prematuremediafilter) {
			/* chan_sip parity (chan_sip.c:7710 transmit_provisional_response with_sdp=TRUE):
			 * emit 183 Session Progress with an SDP body so the INVITE offer is
			 * properly answered at the early-media stage.
			 *
			 * Without SDP the offer recorded by sofia-sip at sr_offer_recv stays
			 * unanswered when the UAC PRACKs the reliable 183. Require: 100rel is
			 * auto-added by sofia-sip per nua_session.c:2493 for status==183 whenever
			 * the UAC's INVITE advertised Supported: 100rel, and there is no NUTAG
			 * to suppress it for 183. sofia-sip's nua_prack_server_report then
			 * fires an empty 200 OK on the INVITE milliseconds after the PRACK; the
			 * UAC ACKs the bogus 2xx, sees no media, and BYEs.
			 *
			 * Including SDP here sets sr_answer_sent at nua_session.c:2435 (because
			 * NUTAG_MEDIA_ENABLE(0) makes sofia-sip read the body directly from the
			 * response message at nua_session.c:2364-2370), so offer/answer is
			 * settled in the 183 itself. The spurious 200 OK no longer fires;
			 * PRACK is harmless and RFC-3262-correct. sofia_generate_sdp is the
			 * same helper sofia_answer uses below. */
			char sdp_buf[2048];
			if (pvt->rtp && sofia_generate_sdp(pvt, sdp_buf, sizeof(sdp_buf))) {
				nua_respond(pvt->nh, SIP_183_SESSION_PROGRESS,
					SIPTAG_CONTENT_TYPE_STR("application/sdp"),
					SIPTAG_PAYLOAD_STR(sdp_buf),
					TAG_END());
			} else {
				/* RTP not yet bound — fall back to bodyless 183. Should be rare
				 * in practice: sofia_rtp_init runs in sofia_process_invite
				 * (inbound) and sofia_request_call (outbound) before
				 * AST_CONTROL_PROGRESS can reach the channel. */
				nua_respond(pvt->nh, SIP_183_SESSION_PROGRESS, TAG_END());
			}
		}
		break;
	case AST_CONTROL_ANSWER:
		sofia_answer(ast);
		break;
	case AST_CONTROL_HOLD:
		/* post-T56 MOH per-peer parity R4 (2026-04-27): peer->mohinterpret as
		 * interpclass fallback when data (mohsuggest from upstream bridge) is
		 * empty. Mirrors chan_sip ast_moh_start(ast, data, p->mohinterpret) at
		 * chan_sip.c:7704. */
		ast_moh_start(ast, data,
			(pvt && pvt->peer && !ast_strlen_zero(pvt->peer->mohinterpret))
				? pvt->peer->mohinterpret : NULL);
		break;
	case AST_CONTROL_UNHOLD:
		ast_moh_stop(ast);
		break;
	case AST_CONTROL_SRCUPDATE:
		/* post-T56 REFER blind-transfer audio fix (2026-04-27): RTP source-update
		 * indication. gabpbx core fires this when the audio SOURCE feeding the
		 * channel changes WITHOUT changing identity (e.g., bridge re-cued after
		 * MOH-stop). Set RTP marker bit so receiver knows to reset packet-stream
		 * state but keep the same SSRC. chan_sip parity at chan_sip.c:7728-7729
		 * (case AST_CONTROL_SRCUPDATE: ast_rtp_instance_update_source(p->rtp)).
		 * Returns 0 on success — must NOT return -1 (default branch) since gabpbx
		 * interprets -1 as "channel-driver doesn't handle, drop the indication"
		 * and the SSRC/marker change never happens. */
		if (pvt->rtp) {
			ast_rtp_instance_update_source(pvt->rtp);
		}
		break;
	case AST_CONTROL_SRCCHANGE:
		/* post-T56 REFER blind-transfer audio fix (2026-04-27): RTP source CHANGED
		 * indication. gabpbx core fires this when the audio SOURCE itself changes
		 * (e.g., async_goto-driven masquerade swap, bridge transition, file-play
		 * start). Bumps local outbound SSRC + sets marker bit so the far end can
		 * cleanly reset its jitter-buffer to track the new logical stream. chan_sip
		 * parity at chan_sip.c:7731-7732 (case AST_CONTROL_SRCCHANGE:
		 * ast_rtp_instance_change_source(p->rtp)). PRE-FIX: chan_sofia returned -1
		 * (default branch) which caused gabpbx core to drop the indication; PSTN
		 * gateways kept jitter-buffer state from the OLD source, dropping frames
		 * after REFER blind-transfer bridge swap and producing one-way silence. */
		if (pvt->rtp) {
			ast_rtp_instance_change_source(pvt->rtp);
		}
		break;
	case -1:
		/* gabpbx core convention: ast_indicate(chan, -1) signals "stop whatever
		 * indication you're doing" (e.g., stop ringing tone). chan_sofia has no
		 * pending indication state; silently succeed without warning. chan_sip
		 * parity (chan_sip.c default branch handles -1 silently). */
		break;
	case AST_CONTROL_T38_PARAMETERS:
		/* post-T56 Task #8 T.38 fax UDPTL parity SS4 (2026-04-28, frame-channel
		 * dispatch): app_fax / res_fax queue this control frame to drive T.38
		 * negotiation (chan_sip.c:7723-7724 verbatim semantic via
		 * interpret_t38_parameters). 6-op dispatcher — see sofia_interpret_
		 * t38_parameters helper (Pattern 5 #44) for full op-table. */
		if (datalen != sizeof(struct ast_control_t38_parameters)) {
			ast_log(LOG_ERROR, "Sofia: AST_CONTROL_T38_PARAMETERS datalen mismatch (got %zu expected %zu)\n",
				datalen, sizeof(struct ast_control_t38_parameters));
			return -1;
		}
		if (sofia_interpret_t38_parameters(pvt, (const struct ast_control_t38_parameters *)data) < 0) {
			return -1;
		}
		break;
	default:
		ast_log(LOG_WARNING, "Sofia: Don't know how to indicate condition %d\n", condition);
		return -1;
	}

	return 0;
}

static int sofia_fixup(struct ast_channel *oldchan, struct ast_channel *newchan)
{
	struct sofia_pvt *pvt;

	if (!newchan || !(pvt = newchan->tech_pvt)) {
		return -1;
	}

	ast_mutex_lock(&pvt->lock);
	if (oldchan && pvt->owner && pvt->owner != oldchan) {
		ast_debug(1, "Sofia fixup owner mismatch for %s: expected %s, had %s\n",
			newchan->name, oldchan->name, pvt->owner->name);
	}
	pvt->owner = newchan;
	ast_mutex_unlock(&pvt->lock);

	sofia_set_rtp_peer(newchan, NULL, NULL, NULL, 0, 0);
	return 0;
}

/* post-T56 Task #8 T.38 fax UDPTL parity SS5 (2026-04-28, SS1.5 N7 LOAD-BEARING
 * — DEFERRAL REJECTED): AST_OPTION_T38_STATE queryoption handler mirrors
 * chan_sip.c:5042-5064 verbatim semantic. Required by apps/app_fax.c (6 sites
 * at L438/766/847/854/855/860) + res/res_fax.c (6+ sites at L1055/1058/1061/
 * 1157/1417/1475) — both call ast_channel_get_t38_state inline wrapper at
 * channel.h:2428-2433 which routes through ast_channel_queryoption(chan,
 * AST_OPTION_T38_STATE, ...). Without this handler, no fax stack works on
 * chan_sofia (returns ENOSUPPORT or core silently drops query → fax stack
 * sees T38_STATE_UNKNOWN or T38_STATE_UNAVAILABLE → fax flow rejected). Maps
 * pvt->t38_state to enum ast_t38_state (frame.h-defined): LOCAL_REINVITE +
 * PEER_REINVITE → NEGOTIATING; ENABLED → NEGOTIATED; default → UNKNOWN.
 * UNAVAILABLE returned when pvt->peer->t38pt_udptl=0 (T.38 disabled per peer
 * config). pvt->lock held across state read for chan_sip parity at L5040
 * sip_pvt_lock. */
static int sofia_queryoption(struct ast_channel *chan, int option, void *data, int *datalen)
{
	struct sofia_pvt *pvt;
	enum ast_t38_state state = T38_STATE_UNAVAILABLE;
	int res = -1;

	if (!chan) {
		return -1;
	}
	pvt = chan->tech_pvt;
	if (!pvt) {
		return -1;
	}

	switch (option) {
	case AST_OPTION_T38_STATE:
		if (*datalen != sizeof(enum ast_t38_state)) {
			ast_log(LOG_ERROR, "Sofia: AST_OPTION_T38_STATE datalen mismatch (got %d expected %zu)\n",
				*datalen, sizeof(enum ast_t38_state));
			break;
		}
		ast_mutex_lock(&pvt->lock);
		if (pvt->peer && pvt->peer->t38pt_udptl) {
			switch (pvt->t38_state) {
			case SOFIA_T38_LOCAL_REINVITE:
			case SOFIA_T38_PEER_REINVITE:
				state = T38_STATE_NEGOTIATING;
				break;
			case SOFIA_T38_ENABLED:
				state = T38_STATE_NEGOTIATED;
				break;
			default:
				state = T38_STATE_UNKNOWN;
				break;
			}
		}
		ast_mutex_unlock(&pvt->lock);
		*((enum ast_t38_state *) data) = state;
		res = 0;
		break;
	default:
		/* Other options not supported — return -1 so core can fall back to
		 * defaults or signal unsupported. */
		break;
	}
	return res;
}

static int sofia_send_digit_begin(struct ast_channel *ast, char digit)
{
	struct sofia_pvt *pvt = ast->tech_pvt;

	if (!pvt) {
		return -1;
	}

	if (digit == ' ') {
		return 0;
	}

	switch (pvt->dtmfmode) {
	case SOFIA_DTMF_RFC2833:
	case SOFIA_DTMF_AUTO:
		if (pvt->rtp) {
			ast_rtp_instance_dtmf_begin(pvt->rtp, digit);
		}
		break;
	case SOFIA_DTMF_INFO:
		break;
	case SOFIA_DTMF_INBAND:
		return -1;
	default:
		break;
	}

	return 0;
}

static int sofia_send_digit_end(struct ast_channel *ast, char digit, unsigned int duration)
{
	struct sofia_pvt *pvt = ast->tech_pvt;

	if (!pvt) {
		return -1;
	}

	if (digit == ' ') {
		return 0;
	}

	switch (pvt->dtmfmode) {
	case SOFIA_DTMF_RFC2833:
	case SOFIA_DTMF_AUTO:
		if (pvt->rtp) {
			if (duration) {
				ast_rtp_instance_dtmf_end_with_duration(pvt->rtp, digit, duration);
			} else {
				ast_rtp_instance_dtmf_end(pvt->rtp, digit);
			}
		}
		break;
	case SOFIA_DTMF_INFO:
		if (pvt->nh) {
			char info_body[64];
			snprintf(info_body, sizeof(info_body),
				"Signal=%c\r\nDuration=%d\r\n", digit, duration ? duration : 250);
			nua_info(pvt->nh,
				SIPTAG_CONTENT_TYPE_STR("application/dtmf-relay"),
				SIPTAG_PAYLOAD_STR(info_body),
				TAG_END());
		}
		break;
	case SOFIA_DTMF_INBAND:
		return -1;
	default:
		break;
	}

	return 0;
}

static const char *sofia_get_callid(struct ast_channel *ast)
{
	struct sofia_pvt *pvt = ast->tech_pvt;
	return pvt ? pvt->callid : "";
}

static struct ast_channel *sofia_request_call(const char *type, format_t format, const struct ast_channel *requestor, void *data, int *cause)
{
	char *dest = (char *)data;
	char *peername, *exten;
	struct sofia_peer *peer;
	struct sofia_pvt *pvt;
	struct ast_channel *chan = NULL;
	char tmp[256];

	ast_copy_string(tmp, dest, sizeof(tmp));
	peername = tmp;

	exten = strchr(tmp, '/');
	if (exten) {
		*exten = '\0';
		exten++;
	} else {
		/* Drop-in chan_sip parity (post-T56 dial-atpeer fix, 2026-04-27): no '/' separator
		 * — try chan_sip "exten@peer" syntax before falling back to bare-peer-name. Per
		 * chan_sip sip_request_call parsing, dial string before '@' is the Request-URI user
		 * (extension/number to dial), part after '@' is the configured peer name used for
		 * routing. Required for drop-in compatibility (chan-sip-compat-naming-rules.md):
		 * production dialplans like Dial(SIP/9999#622501314@trunk_eli3) MUST resolve to
		 * peer=trunk_eli3, exten=9999#622501314 — without this fix peer lookup fails on
		 * the full string and the call ends in CHANUNAVAIL. If neither '/' nor '@' is
		 * present, treat the whole input as a plain peer name (no extension) — matches
		 * the original Dial(SIP/peer) behavior. */
		char *at = strchr(tmp, '@');
		if (at) {
			*at = '\0';
			peername = at + 1;
			exten = tmp;
		} else {
			exten = peername;
		}
	}

	peer = sofia_find_peer(peername);

	pvt = sofia_pvt_alloc();
	if (!pvt) {
		*cause = AST_CAUSE_CONGESTION;
		if (peer) {
			ao2_ref(peer, -1);
		}
		return NULL;
	}

	ast_string_field_set(pvt, exten, exten);
	ast_string_field_set(pvt, peername, peername ? peername : "unknown");

	if (peer) {
		ast_string_field_set(pvt, context, peer->context);
		ast_string_field_set(pvt, username, peer->defaultuser);
		ast_string_field_set(pvt, peersecret, peer->secret);
		ast_string_field_set(pvt, fromuser, peer->fromuser);
		ast_string_field_set(pvt, fromdomain, peer->fromdomain);
		pvt->capability = peer->capability;
		pvt->prefs = peer->prefs;
		pvt->dtmfmode = peer->dtmfmode;
		pvt->allowtransfer = peer->allowtransfer; /* post-T56 allowtransfer per-peer parity (2026-04-27): outbound dialog inherits peer REFER policy; chan_sip parity chan_sip.c:5973 */
		ast_string_field_set(pvt, subscribecontext, peer->subscribecontext); /* post-T56 subscribecontext per-peer parity (2026-04-27): outbound dialog inherits peer SUBSCRIBE dispatch context; chan_sip parity chan_sip.c:17043; inert until presence/dialog event-package handler wires pivot */
		ast_string_field_set(pvt, accountcode, peer->accountcode); /* post-T56 accountcode per-peer parity (2026-04-27): outbound dialog inherits peer CDR billing-tag; chan_sip parity chan_sip.c:17127; consumed by sofia_new at ast_channel_alloc 5th-arg for chan->accountcode propagation */
		ao2_ref(peer, +1); pvt->peer = peer;

		{
			char url[256];
			char route_buf[256];

			sofia_resolve_peer_target(peer, exten, url, sizeof(url));
			/* T56.2 (2026-04-27): outbound INVITE Route header from peer/[general] outboundproxy.
			 * Sticky-on-handle per R7: NUTAG_INITIAL_ROUTE_STR at handle-create persists for
			 * subsequent nua_invite/etc on the same handle. */
			sofia_format_outboundproxy(peer, route_buf, sizeof(route_buf));
			/* post-T56 outbound-headers parity (2026-04-27): resolve our source IP for this
			 * peer's reachable address. Used by R5 sofia_generate_sdp + R6 wire-ins
			 * (sofia_build_from + sofia_build_contact) at the nua_invite sites below. */
			{
				struct ast_sockaddr target;
				if (peer->registered && !ast_sockaddr_isnull(&peer->src_addr)) {
					target = peer->src_addr;
				} else {
					char target_url[128];
					snprintf(target_url, sizeof(target_url), "%s:%d",
						!ast_strlen_zero(peer->host) ? peer->host : "127.0.0.1",
						peer->port ? peer->port : 5060);
					ast_sockaddr_parse(&target, target_url, 0);
				}
				sofia_resolve_ourip(pvt, &target);
			}
			ast_string_field_set(pvt, ruri, url);
			if (sofia_debug) {
				ast_verbose("Sofia: Outbound call to peer %s, RURI=%s%s%s\n",
					peername, url,
					route_buf[0] ? ", Route=" : "",
					route_buf[0] ? route_buf : "");
			}

			/* NAT in-dialog routing override (chan_sip parity): when peer is
			 * behind NAT (force_rport / comedia), sofia-sip's auto-generated
			 * ACK and BYE would honor the 200 OK Contact URI which usually
			 * carries the peer's private LAN IP rather than the public
			 * NAT-mapped address it actually registered from. NUTAG_PROXY pins all
			 * outgoing dialog messages to peer->src_addr — the registered/
			 * resolved public address — so ACK reaches the phone, suppressing
			 * the 200 OK retransmit loop and unblocking the call. */
			char proxy_url[128] = "";
			if (peer && (peer->nat & (SOFIA_NAT_FORCE_RPORT | SOFIA_NAT_COMEDIA))
			    && !ast_sockaddr_isnull(&peer->src_addr)) {
				char host_buf[80];
				int port = ast_sockaddr_port(&peer->src_addr);
				if (!port) {
					port = peer->port ? peer->port : 5060;
				}
				snprintf(proxy_url, sizeof(proxy_url), "sip:%s:%d",
					sofia_uri_format_host(ast_sockaddr_stringify_host(&peer->src_addr),
						host_buf, sizeof(host_buf)),
					port);
			}
			if (sofia_nua) {
				pvt->nh = nua_handle(sofia_nua, pvt,
					NUTAG_URL(url),
					SIPTAG_TO_STR(url),
					TAG_IF(route_buf[0], NUTAG_INITIAL_ROUTE_STR(route_buf)),
					TAG_IF(proxy_url[0], NUTAG_PROXY(proxy_url)),
					TAG_END());
			}
		}

		ao2_ref(peer, -1);
	} else {
		ast_string_field_set(pvt, context, sofia_cfg.context);
		ast_string_field_set(pvt, ruri, dest);
		pvt->capability = sofia_cfg.capability ? sofia_cfg.capability : (AST_FORMAT_ULAW | AST_FORMAT_ALAW);
		pvt->prefs = sofia_cfg.prefs;
	}

	snprintf(tmp, sizeof(tmp), "%lx", (unsigned long)pvt);
	ast_string_field_set(pvt, callid, tmp);

	ao2_link(dialogs, pvt);

	/* post-T56 outbound RTP fd-wire-order fix (2026-04-27): sofia_rtp_init
	 * MUST run BEFORE sofia_new because sofia_new wires chan->fds[0..3] from
	 * pvt->rtp/pvt->vrtp at L1397-1404 — without rtp allocated first, the
	 * `if (pvt->rtp)` gate fails and fds stay at ast_channel_alloc default
	 * (-1), so the bridge-poll select never sees the outbound RTP read fd
	 * and incoming trunk audio sits in the kernel socket buffer forever
	 * (silent one-way audio symptom). Mirrors chan_sip flow: chan_sip
	 * sip_request_call calls create_addr → dialog_initialize_rtp (allocates
	 * dialog->rtp at chan_sip.c:5853) BEFORE sip_new wires fds at
	 * chan_sip.c:7910-7912. Inbound flow at sofia_process_invite already
	 * has correct ordering (rtp_init before sofia_new). Fork-pick-winner
	 * at L694-701 already refreshes fds from stolen rtp post-pick. */
	if (sofia_rtp_init(pvt)) {
		ao2_unlink(dialogs, pvt);
		ao2_ref(pvt, -1);
		*cause = AST_CAUSE_CONGESTION;
		return NULL;
	}

	chan = sofia_new(pvt, AST_STATE_DOWN, requestor ? requestor->linkedid : NULL);
	if (!chan) {
		ao2_unlink(dialogs, pvt);
		ao2_ref(pvt, -1);
		*cause = AST_CAUSE_CONGESTION;
		return NULL;
	}

	pvt->owner = chan;
	pvt->outgoing = 1; /* post-T56 identity-headers parity SS2 (2026-04-27): outbound dial — sofia_add_rpid RPID branch reads this for ;party=calling */

	return chan;
}

/* Detect peer hold direction from offered SDP (RFC 3264 §5.1).
 * Returns 1 if peer is asking us to hold (a=sendonly or a=inactive on m=audio),
 * 0 if normal (a=sendrecv or default). Uses pvt->home as the parser arena. */
static int sofia_sdp_extract_hold(sip_t const *sip, su_home_t *home)
{
	sdp_parser_t *parser;
	sdp_session_t *sdp;
	int hold = 0;

	if (!sip || !sip->sip_payload || !sip->sip_payload->pl_data || !home) {
		return 0;
	}
	parser = sdp_parse(home, sip->sip_payload->pl_data, sip->sip_payload->pl_len, 0);
	if (!parser) {
		return 0;
	}
	sdp = sdp_session(parser);
	if (sdp && sdp->sdp_media) {
		if (sdp->sdp_media->m_mode == sdp_sendonly ||
			sdp->sdp_media->m_mode == sdp_inactive) {
			hold = 1;
		}
	}
	sdp_parser_free(parser);
	return hold;
}

/* Handle in-dialog re-INVITE (peer-initiated hold/unhold/codec renegotiation).
 * Distinguished from initial INVITE by hmagic being non-NULL on the bound nh. */
static void sofia_process_reinvite(struct sofia_pvt *pvt, nua_t *nua,
		nua_handle_t *nh, sip_t const *sip)
{
	char sdp_buf[2048];
	int old_hold;
	int new_hold;
	int trans;
	int sdp_ok;
	int st_refresh = 0; /* post-T56 session timers (RFC 4028) (2026-04-27): R13.b discriminator */
	int st_refresh_seconds = 0;
	const char *st_refresher_str = NULL;
	/* SIPTAG_SESSION_EXPIRES presence on inbound re-INVITE = uas-side refresh fire.
	 * sofia-sip parses Session-Expires into sip->sip_session_expires struct (sofia-sip
	 * sip_session_expires struct exposes x_delta seconds + x_refresher param). */
	if (sip && sip->sip_session_expires) {
		st_refresh = 1;
		st_refresh_seconds = sip->sip_session_expires->x_delta;
		st_refresher_str = sip->sip_session_expires->x_refresher; /* NULL if param absent */
	}

	if (!pvt) {
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
		return;
	}

	ast_mutex_lock(&pvt->lock);
	old_hold = pvt->hold_state;
	new_hold = sofia_sdp_extract_hold(sip, pvt->home);
	pvt->hold_state = new_hold;
	trans = (old_hold != new_hold);
	/* post-T56 call-limit parity SS2 R10 (2026-04-27): peer.onHold atomic
	 * counter on hold transition. chan_sip L15487 parity.
	 * post-T56 notifyhold [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:9477-9478 verbatim semantic — sip_peer_hold (peer-counter
	 * tracking) gated on sip_cfg.notifyhold. chan_sofia equivalent gate on
	 * sofia_cfg.notifyhold; default 0 means counter freeze unless operator
	 * sets [general] notifyhold=yes. AMI Hold at L4521 UNCONDITIONAL (matches
	 * chan_sip callevents=yes typical case; chan_sip parity HOLDS). */
	if (trans && pvt->peer && sofia_cfg.notifyhold) {
		ast_atomic_fetchadd_int(&pvt->peer->onHold, new_hold ? +1 : -1);
	}
	if (sip && sip->sip_payload && sip->sip_payload->pl_data) {
		if (sofia_parse_sdp(pvt, sip) < 0) {
			/* T37: in-dialog re-INVITE encryption downgrade — reject 488,
			 * leave existing crypto context + call up (RFC 3261 §14). */
			ast_mutex_unlock(&pvt->lock);
			ast_log(LOG_NOTICE, "Sofia: in-dialog re-INVITE rejected — encryption mismatch on '%s'\n",
				pvt->callid ? pvt->callid : "(no-callid)");
			nua_respond(nh, SIP_488_NOT_ACCEPTABLE,
				NUTAG_WITH_THIS(nua), TAG_END());
			return;
		}
	}
	if (trans && pvt->owner) {
		if (new_hold) {
			/* post-T56 MOH per-peer parity R5 INBOUND (2026-04-27): peer puts
			 * us on hold via re-INVITE sendonly; propagate peer->mohsuggest as
			 * data to bridged channel via AST_CONTROL_HOLD data param so the
			 * other party plays the suggested MOH class. Mirrors chan_sip
			 * ast_queue_control_data at chan_sip.c:10255-10257.
			 * OUTBOUND-direction Alert-Info signaling deferred (chan_sofia
			 * does NOT issue outbound HOLD re-INVITE today). */
			const char *suggest = (pvt->peer && !ast_strlen_zero(pvt->peer->mohsuggest))
				? pvt->peer->mohsuggest : NULL;
			ast_queue_control_data(pvt->owner, AST_CONTROL_HOLD,
				S_OR(suggest, NULL),
				suggest ? strlen(suggest) + 1 : 0);
		} else {
			ast_queue_control(pvt->owner, AST_CONTROL_UNHOLD);
		}
	}
	sdp_ok = (sofia_generate_sdp(pvt, sdp_buf, sizeof(sdp_buf)) != NULL);
	ast_mutex_unlock(&pvt->lock);

	if (sdp_ok) {
		nua_respond(nh, SIP_200_OK,
			NUTAG_WITH_THIS(nua),
			SIPTAG_CONTENT_TYPE_STR("application/sdp"),
			SIPTAG_PAYLOAD_STR(sdp_buf),
			TAG_END());
	} else {
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
	}

	if (trans) {
		ast_verbose("Sofia: in-dialog re-INVITE on '%s' - hold=%d\n",
			pvt->callid ? pvt->callid : "(no-callid)", new_hold);
		if (pvt->owner) {
			manager_event(EVENT_FLAG_CALL, "Hold",
				"Status: %s\r\n"
				"Channel: %s\r\n"
				"Uniqueid: %s\r\n",
				new_hold ? "On" : "Off",
				pvt->owner->name,
				pvt->owner->uniqueid);
		}
	}

	/* post-T56 session timers (RFC 4028) (2026-04-27) R13.b: SessionTimerRefresh
	 * AMI event for uas-side refresh fire (peer sent refresh re-INVITE; we are
	 * the refresher target). Discriminator: SIPTAG_SESSION_EXPIRES presence on
	 * the re-INVITE (st_refresh==1 above). chan_sofia surpass — chan_sip emits
	 * no equivalent; operators monitoring long-call stability lacked this signal. */
	if (st_refresh) {
		pvt->session_negotiated_expires = st_refresh_seconds;
		pvt->session_last_refresh_at = time(NULL);
		manager_event(EVENT_FLAG_CALL, "SessionTimerRefresh",
			"Channel: %s\r\n"
			"Uniqueid: %s\r\n"
			"Peer: Sofia/%s\r\n"
			"SessionExpires: %d\r\n"
			"Refresher: %s\r\n"
			"Direction: uas\r\n",
			pvt->owner ? pvt->owner->name : "",
			pvt->owner ? pvt->owner->uniqueid : "",
			pvt->peername,
			st_refresh_seconds,
			st_refresher_str ? st_refresher_str : "auto");
	}
}

static void sofia_process_invite(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	struct sofia_pvt *pvt;
	struct ast_channel *chan;
	const char *exten = NULL;
	char cid_num[80] = "";
	char cid_name[80] = "";

	if (!sip) {
		nua_respond(nh, SIP_400_BAD_REQUEST, TAG_END());
		return;
	}

	/* post-T56 allowexternaldomains [general] parity (2026-04-28, FULL WIRE-IN
	 * Pattern 5 helper #30): mirror chan_sip.c:16410-16425 verbatim semantic.
	 * Reject INVITE to non-local SIP domain when domain_list non-empty AND
	 * Request-URI domain not in domain_list AND !allow_external_domains. */
	if (!AST_LIST_EMPTY(&domain_list) && !sofia_cfg.allow_external_domains
	    && sip->sip_request && sip->sip_request->rq_url
	    && sip->sip_request->rq_url->url_host
	    && !sofia_check_sip_domain(sip->sip_request->rq_url->url_host)) {
		ast_debug(1, "Sofia: Got INVITE to non-local domain '%s'; refusing request.\n",
			sip->sip_request->rq_url->url_host);
		nua_respond(nh, SIP_403_FORBIDDEN, NUTAG_WITH_THIS(nua), TAG_END());
		return;
	}

	pvt = sofia_pvt_alloc();
	if (!pvt) {
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
		return;
	}

	pvt->nh = nh;
	pvt->outgoing = 0; /* post-T56 identity-headers parity SS2 (2026-04-27): inbound INVITE — sofia_add_rpid RPID branch reads this for ;party=called (B-leg outbound) */
	/* post-T56 session timers (RFC 4028) (2026-04-27): capture peer-requested
	 * Session-Expires for R13.a display. The 200-OK we'll send via sofia_answer
	 * carries our NUTAG_SESSION_TIMER value (which sofia-sip negotiates against
	 * peer's request); the value here is the peer's offer, useful for diagnostic
	 * display before negotiation completes. */
	if (sip && sip->sip_session_expires) {
		pvt->session_negotiated_expires = sip->sip_session_expires->x_delta;
	}

	pvt->capability = sofia_cfg.capability ? sofia_cfg.capability : (AST_FORMAT_ULAW | AST_FORMAT_ALAW);
	pvt->prefs = sofia_cfg.prefs;

	/* Initialize RTP */
	if (sofia_rtp_init(pvt)) {
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
		ao2_ref(pvt, -1);
		return;
	}

	pvt->dtmfmode = SOFIA_DTMF_RFC2833;

	/* T46.1: snapshot inbound INVITE headers BEFORE any potential 4xx/5xx early-return
	 * paths so ${SIP_HEADER()} reads the original request even from h-extension. */
	sofia_pvt_snapshot_initreq(pvt, sip);

	/* T46.4: capture transport-source for ${SIPCHANINFO(peerip|recvip)} */
	sofia_get_source_addr(sip, &pvt->last_src_addr);

	/* T46.4: capture Request-URI for ${SIPCHANINFO(uri)} on inbound calls
	 * (outbound path sets pvt->ruri at sofia_call time). */
	if (sip->sip_request && sip->sip_request->rq_url && pvt->home) {
		char *url_str = url_as_string(pvt->home, sip->sip_request->rq_url);
		if (url_str) {
			ast_string_field_set(pvt, ruri, url_str);
		}
	}

	if (sip->sip_call_id && sip->sip_call_id->i_id) {
		ast_string_field_set(pvt, callid, sip->sip_call_id->i_id);
	}

	if (sip->sip_from) {
		if (sip->sip_from->a_url->url_user) {
			snprintf(cid_num, sizeof(cid_num), "%.79s", sip->sip_from->a_url->url_user);
			/* post-T56 shrinkcallerid [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:16080 + L16196 + L17103 + L17252 verbatim ast_is_shrinkable_phonenumber
			 * gate + ast_shrink_phone_number strip. Applied BEFORE pvt->username + pvt->cid_num
			 * assignments so shrink reflects in BOTH downstream consumers. Pattern 12
			 * 18th-instance behavior-change-from-baseline sub-pattern 3rd-instance —
			 * default 1 (TRUE) per chan_sip drop-in critical default. */
			if (sofia_cfg.shrinkcallerid && ast_is_shrinkable_phonenumber(cid_num)) {
				ast_shrink_phone_number(cid_num);
			}
			ast_string_field_set(pvt, username, cid_num);
		}
		if (sip->sip_from->a_display) {
			snprintf(cid_name, sizeof(cid_name), "%.79s", sip->sip_from->a_display);
		}
		/* post-T56 identity-headers parity SS4 (2026-04-27): seed pvt->cid_num/
		 * cid_name from From header. sofia_get_rpid (called below after peer
		 * bind) overrides these when peer->trustrpid=1 and PAI/RPID present. */
		ast_string_field_set(pvt, cid_num, cid_num);
		ast_string_field_set(pvt, cid_name, cid_name);
	}

	/* post-T56 match_auth_username [general] parity (2026-04-28): chan_sip parity
	 * at chan_sip.c:17258 verbatim — when set, override peer-lookup search-key
	 * with Authorization-username (or Proxy-Authorization fallback). Pattern 5
	 * helper #28 sofia_pick_auth_username. Overrides cid_num for downstream
	 * sofia_find_peer(cid_num) at L4456. NOTE: sofia_process_invite has no
	 * digest-auth validation today; this still works whenever sip->sip_authorization
	 * arrives (proxy pass-through OR future INVITE-digest-auth landing). */
	if (sofia_cfg.match_auth_username) {
		char auth_user_buf[128];
		const char *auth_user = sofia_pick_auth_username(sip, cid_num,
			auth_user_buf, sizeof(auth_user_buf));
		if (auth_user != cid_num) {
			ast_copy_string(cid_num, auth_user, sizeof(cid_num));
		}
	}

	if (sip->sip_to && sip->sip_to->a_url && sip->sip_to->a_url->url_user) {
		exten = sip->sip_to->a_url->url_user;
	} else {
		exten = "s";
	}
	ast_string_field_set(pvt, exten, exten);
	ast_string_field_set(pvt, context, sofia_cfg.context);
	ast_string_field_set(pvt, peername, cid_num[0] ? cid_num : "unknown");

	/* Peer lookup runs BEFORE sofia_parse_sdp so the SDP encryption-policy check
	 * (T37) sees pvt->peer attached. ACL also runs before SDP parse so banned IPs
	 * never trigger SRTP key generation. */
	{
		struct sofia_peer *caller_peer = NULL;
		if (cid_num[0]) {
			caller_peer = sofia_find_peer(cid_num);
		}
		if (!caller_peer) {
			/* chan_sip parity: From-username lookup failed, fall back to
			 * source-IP match so host=<ip> trunks (typically insecure=invite,
			 * whose From-user is the caller-ID number not the peer-name) get
			 * identified. Without this fallback unknown-peer + alwaysauthreject
			 * below emits a 401 the trunk cannot answer, breaking inbound
			 * calls from gateways that don't carry the local peer-name in From. */
			struct ast_sockaddr src;
			sofia_get_source_addr(sip, &src);
			caller_peer = sofia_find_peer_by_ip(&src);
		}
		if (caller_peer) {
			if (caller_peer->ha) {
				struct ast_sockaddr src;
				sofia_get_source_addr(sip, &src);
				if (ast_apply_ha(caller_peer->ha, &src) != AST_SENSE_ALLOW) {
					ast_log(LOG_NOTICE, "Sofia: INVITE from %s rejected by peer '%s' ACL\n",
						ast_sockaddr_stringify(&src), caller_peer->name);
					/* SS5 N10 audit hardening: timing-equalize ACL-deny path
					 * with auth-401-slow path. Without this jitter, ACL-403-fast
					 * vs auth-401-slow gives peer-existence oracle defeating
					 * alwaysauthreject username-enumeration prevention. Helper
					 * #39 sofia_emit_timing_equalized_reject covers ACL-deny +
					 * auth-failure paths uniformly. */
					sofia_emit_timing_equalized_reject();
					nua_respond(nh, SIP_403_FORBIDDEN,
						NUTAG_WITH_THIS(nua), TAG_END());
					ao2_ref(caller_peer, -1);
					ao2_ref(pvt, -1);
					return;
				}
			}
			pvt->dtmfmode = caller_peer->dtmfmode;
			pvt->prefs = caller_peer->prefs;
			if (!ast_strlen_zero(caller_peer->context)) {
				ast_string_field_set(pvt, context, caller_peer->context);
			}
			pvt->allowtransfer = caller_peer->allowtransfer; /* post-T56 allowtransfer per-peer parity (2026-04-27): inbound dialog inherits peer REFER policy; chan_sip parity chan_sip.c:5973 */
			ast_string_field_set(pvt, subscribecontext, caller_peer->subscribecontext); /* post-T56 subscribecontext per-peer parity (2026-04-27): inbound dialog inherits peer SUBSCRIBE dispatch context; chan_sip parity chan_sip.c:17043; inert until presence/dialog event-package handler wires pivot */
			ast_string_field_set(pvt, accountcode, caller_peer->accountcode); /* post-T56 accountcode per-peer parity (2026-04-27): inbound dialog inherits peer CDR billing-tag; chan_sip parity chan_sip.c:17127; consumed by sofia_new at ast_channel_alloc 5th-arg for chan->accountcode propagation */
			ao2_ref(caller_peer, +1); pvt->peer = caller_peer;
			ao2_ref(caller_peer, -1);
		}
	}

	/* post-T56 Task #3 INVITE digest auth SS3 (2026-04-28, primary value-prop —
	 * closes auth-bypass-class gap; chan_sofia previously accepted ALL inbound
	 * INVITEs without auth challenge). Wire-in placement preserves T32 ACL-
	 * before-auth ordering (per acl_before_auth.md memory): caller_peer block
	 * above runs ast_apply_ha BEFORE this auth block. Pre-auth-mutation
	 * discipline per E3 SW9-additional: pvt->peer = caller_peer at L5897 is
	 * REFCOUNT-only (not state-mutation); PVT-side state copies above (dtmfmode/
	 * context/allowtransfer/subscribecontext/accountcode) are scoped to dialog;
	 * if auth fails, pvt destroyed. PEER-side state mutation MUST NOT happen
	 * pre-auth — verified zero `peer->X = ...` assignments above this block.
	 *
	 * Three-tier auth dispatch:
	 * (1) sofia_cfg.force_invite_auth global lockdown override — when set,
	 *     bypasses are DISABLED globally; auth required regardless of
	 *     per-peer insecure=invite config. LOG_NOTICE fires when override
	 *     takes effect on a peer with insecure=invite (operator visibility).
	 * (2) per-peer SOFIA_INSECURE_INVITE flag — short-circuit auth bypass
	 *     for trusted-IP trunks. SW6 chan_sofia surpass over chan_sip silent
	 *     bypass: per-call LOG_NOTICE + AMI InsecureInviteBypass event for
	 *     monitoring + audit visibility (chan_sip's chan_sip.c:17068-17072
	 *     blanks peersecret silently — chan_sofia uses flag-check short-
	 *     circuit, no state mutation).
	 * (3) sofia_verify_digest_auth call — full digest verification via
	 *     Pattern 5 helper #34 (REGISTER refactor in SS2 already established).
	 *     Per SS1.6 ADR: try sip_authorization first, fallback to sip_proxy_
	 *     authorization for proxy-fronted INVITE.
	 *
	 * Unknown-peer path (cid_num empty OR sofia_find_peer returned NULL):
	 * pvt->peer is NULL. SS5 will add alwaysauthreject extension. For SS3,
	 * unknown-peer INVITEs proceed without auth (chan_sip behavior parity
	 * for non-alwaysauthreject case). */
	if (pvt->peer) {
		int auth_required = 1;
		if (sofia_cfg.force_invite_auth && (pvt->peer->insecure & SOFIA_INSECURE_INVITE)) {
			struct ast_sockaddr src;
			char addr_buf[80];
			sofia_get_source_addr(sip, &src);
			ast_copy_string(addr_buf, ast_sockaddr_stringify(&src), sizeof(addr_buf));
			ast_log(LOG_NOTICE, "Sofia: force_invite_auth=yes overrides per-peer "
				"insecure=invite for peer '%s' from %s — auth required\n",
				pvt->peer->name, addr_buf);
			/* auth_required stays 1 — fall through to digest check */
		} else if (pvt->peer->insecure & SOFIA_INSECURE_INVITE) {
			struct ast_sockaddr src;
			char addr_buf[80];
			sofia_get_source_addr(sip, &src);
			ast_copy_string(addr_buf, ast_sockaddr_stringify(&src), sizeof(addr_buf));
			/* Cosmetic bypass trace: every INVITE from an insecure=invite peer
			 * (typical for IP-validated SBC trunks) used to fire LOG_NOTICE here,
			 * flooding production logs on busy trunks. Gate behind `sip set
			 * debug` so production runs silent; the AMI InsecureInviteBypass
			 * event immediately below stays the auditable surface for SIEM/NMS. */
			if (sofia_debug_match(pvt->peer->name, addr_buf)) {
				ast_verbose("Sofia: INVITE auth bypassed per insecure=invite "
					"for peer '%s' from %s\n",
					pvt->peer->name, addr_buf);
			}
			manager_event(EVENT_FLAG_SYSTEM, "InsecureInviteBypass",
				"Peer: SIP/%s\r\n"
				"RemoteAddr: %s\r\n"
				"ChannelType: SIP\r\n",
				pvt->peer->name, addr_buf);
			auth_required = 0;
		}
		if (auth_required) {
			char realm_buf[MAXHOSTNAMELEN];
			const char *realm = sofia_get_realm_for_dialog(sip, realm_buf, sizeof(realm_buf));
			/* Per SS1.6 ADR: try sip_authorization first; fallback to sip_proxy_
			 * authorization for proxy-fronted INVITE (RFC 3261 §22). */
			sip_authorization_t const *au = sip->sip_authorization
				? sip->sip_authorization
				: (sip_authorization_t const *)sip->sip_proxy_authorization;
			enum sofia_auth_result auth_res = sofia_verify_digest_auth(
				pvt->peer, nua, nh, sip, au, "INVITE", realm);
			if (auth_res != SOFIA_AUTH_OK) {
				ao2_ref(pvt, -1);
				return;
			}
		}
	} else if (sofia_cfg.alwaysauthreject) {
		/* post-T56 Task #3 INVITE digest auth SS5 (2026-04-28, SW5 alwaysauthreject
		 * extension to INVITE per RFC 3261 §22.4 username-enumeration prevention):
		 * unknown peer + alwaysauthreject set → emit auth challenge with real-fresh
		 * nonce + dual-algorithm offer + timing-equalization (sofia_send_auth_
		 * challenge handles all 3 internally per SS5 helper upgrade). Mirrors
		 * REGISTER + SUBSCRIBE c293e54 alwaysauthreject pattern. Unknown-peer
		 * INVITE response now indistinguishable from known-peer-bad-password
		 * response (timing + status code + WWW-Authenticate format) — defeats
		 * username-enumeration via probe-and-measure. */
		char realm_buf[MAXHOSTNAMELEN];
		const char *realm = sofia_get_realm_for_dialog(sip, realm_buf, sizeof(realm_buf));
		sofia_send_auth_challenge(nua, nh, sip, realm, "INVITE", "UnknownPeer");
		ao2_ref(pvt, -1);
		return;
	}

	/* post-T56 inband DTMF detect parity SS1 R4 (2026-04-27): inbound enable
	 * after pvt->peer + pvt->dtmfmode bound (must run AFTER caller_peer block
	 * above; the rtp_init at sofia_process_invite entry forces RFC2833 default
	 * which is then overridden by peer->dtmfmode here). Helper internal-gates
	 * on dtmfmode INBAND/AUTO. */
	sofia_enable_dsp_detect(pvt);

	/* post-T56 identity-headers parity SS4 + R6 + R10 (2026-04-27): inbound
	 * RPID/PAI/Privacy parsing. Trust-gated by peer->trustrpid; sofia_get_rpid
	 * falls back to sofia_get_pai when Remote-Party-ID absent. R10 peer-side
	 * callingpres OVERRIDES received RPID/PAI presentation (operator
	 * trust-but-verify). Apply BEFORE sofia_new so chan->caller.id picks up
	 * the parsed values via the post-sofia_new ast_set_callerid below. */
	sofia_get_rpid(pvt, sip);
	if (pvt->peer && pvt->peer->callingpres) {
		pvt->callingpres = pvt->peer->callingpres;
	}

	/* post-T56 call-limit parity SS4 R4 (2026-04-27): inbound 480
	 * Temporarily Unavailable enforcement. Mirrors chan_sip
	 * update_call_counter INC_CALL_LIMIT path at chan_sip.c:23906-23909.
	 * Reason text VERBATIM with trailing space preserved per chan_sip L23909
	 * (operator AMI/log scripts pattern-match on this exact string).
	 *
	 * Single hard-cap on inbound; busy_level is outbound-only concern per
	 * chan_sip L6297-6301. CallLimitExceeded PeerStatus AMI event is emitted
	 * by sofia_update_call_counter (R8 centralized).
	 *
	 * Cleanup pattern matches existing 488 SDP-mismatch reject at L3146:
	 * pvt is NOT yet in dialogs container (ao2_link happens after sofia_new
	 * at L3215), so only ao2_ref drop needed. Destructor catchall (R9) DEC
	 * is a safe no-op since call_inc_done flag stays 0 on rejection (helper
	 * sets flag AFTER cap check returns OK; rejection short-circuits). */
	if (sofia_update_call_counter(pvt, SOFIA_INC_CALL_LIMIT) == -1) {
		ast_log(LOG_NOTICE, "Sofia: inbound INVITE from peer '%s' rejected — call_limit %d reached\n",
			pvt->peer->name, pvt->peer->call_limit);
		nua_respond(nh, 480, "Temporarily Unavailable (Call limit) ",
			NUTAG_WITH_THIS(nua), TAG_END());
		ao2_ref(pvt, -1);
		return;
	}

	/* post-T56 allowoverlap per-peer + [general] parity (2026-04-28, Option A
	 * FULL WIRE-IN site A — sofia_process_invite ambiguous-extension MATCHMORE
	 * 484 emit): mirror chan_sip.c:23930-23934 verbatim handle_request_invite
	 * SIP_GET_DEST_EXTEN_MATCHMORE → 484 emit + chan_sip.c:16491-16497 verbatim
	 * get_destination ast_canmatch_extension dual-test. When extension does NOT
	 * exact-match BUT canmatch (partial-match scenario) AND mode == YES → emit
	 * 484 Address Incomplete and short-circuit BEFORE sofia_new (no PBX dispatch
	 * for partial extensions). DTMF mode falls through to standard handling per
	 * chan_sip own design at chan_sip.c:23937-23943 verbatim dialplan-deferral
	 * comment. NO mode falls through to standard handling — PBX dispatch will
	 * 404 from dialplan if extension truly absent. NO SIPTAG_REASON_STR per
	 * sofia_sip_quirks #1 catalog (sofia-sip flips it to 500). Effective mode =
	 * peer->allowoverlap_mode when peer bound; else sofia_cfg.default_allowoverlap
	 * _mode. Cleanup pattern matches existing 480 call-limit reject above (pvt
	 * not yet in dialogs container; ao2_ref drop only). */
	{
		int overlap_mode = pvt->peer ? pvt->peer->allowoverlap_mode : sofia_cfg.default_allowoverlap_mode;
		if (overlap_mode == SOFIA_OVERLAP_YES
		    && !ast_strlen_zero(pvt->exten)
		    && !ast_exists_extension(NULL, pvt->context, pvt->exten, 1, S_OR(pvt->cid_num, NULL))
		    && ast_canmatch_extension(NULL, pvt->context, pvt->exten, 1, S_OR(pvt->cid_num, NULL))) {
			ast_log(LOG_NOTICE, "Sofia: inbound INVITE exten '%s'@'%s' partial-match — 484 Address Incomplete (overlap=yes)\n",
				pvt->exten, pvt->context);
			nua_respond(nh, SIP_484_ADDRESS_INCOMPLETE,
				NUTAG_WITH_THIS(nua), TAG_END());
			ao2_ref(pvt, -1);
			return;
		}
	}

	/* chan_sip parity: reject unknown inbound destinations before channel/PBX
	 * allocation. If this is the default context, count it as a blacklist
	 * failure just like chan_sip's get_destination() not-found path. */
	if (!ast_strlen_zero(pvt->exten)
	    && !ast_exists_extension(NULL, pvt->context, pvt->exten, 1, S_OR(pvt->cid_num, NULL))
	    && !ast_canmatch_extension(NULL, pvt->context, pvt->exten, 1, S_OR(pvt->cid_num, NULL))) {
		ast_log(LOG_NOTICE, "Sofia: call from '%s' to extension '%s' rejected because extension not found in context '%s'\n",
			S_OR(pvt->cid_num, pvt->peername), pvt->exten, pvt->context);
		if (!strcasecmp(pvt->context, sofia_cfg.context)) {
			sofia_blacklist_add_sip(sip, "INVITE unknown extension in default context");
		}
		sofia_update_call_counter(pvt, SOFIA_DEC_CALL_LIMIT);
		nua_respond(nh, SIP_404_NOT_FOUND, NUTAG_WITH_THIS(nua), TAG_END());
		ao2_ref(pvt, -1);
		return;
	}

	if (sip->sip_payload && sip->sip_payload->pl_data) {
		if (sofia_parse_sdp(pvt, sip) < 0) {
			/* T37: SDP rejected — encryption mismatch. NO SIPTAG_REASON_STR per
			 * sofia_sip_quirks #1 (sofia-sip flips it to 500). Free srtp/vsrtp
			 * explicitly mirroring max_contacts T22 reject pattern; destructor
			 * would also catch them but explicit free is the rock-hard discipline. */
			ast_log(LOG_NOTICE, "Sofia: 488 reject — encryption mismatch (peer=%s, peer_encryption=%d)\n",
				pvt->peer ? pvt->peer->name : "<unknown>",
				pvt->peer ? pvt->peer->encryption : 0);
			nua_respond(nh, SIP_488_NOT_ACCEPTABLE,
				NUTAG_WITH_THIS(nua), TAG_END());
			if (pvt->srtp) {
				sofia_srtp_destroy(pvt->srtp);
				pvt->srtp = NULL;
			}
			if (pvt->vsrtp) {
				sofia_srtp_destroy(pvt->vsrtp);
				pvt->vsrtp = NULL;
			}
			ao2_ref(pvt, -1);
			return;
		}
	}

	/* comedia: override RTP remote address with SIP source (after parse so the
	 * SDP-derived remote is the value being overridden). */
	if (pvt->peer && (pvt->peer->nat & SOFIA_NAT_COMEDIA) && pvt->rtp) {
		struct ast_sockaddr src;
		sofia_get_source_addr(sip, &src);
		if (!ast_sockaddr_isnull(&src)) {
			struct ast_sockaddr cur_remote;
			ast_rtp_instance_get_remote_address(pvt->rtp, &cur_remote);
			int rtp_port = ast_sockaddr_port(&cur_remote);
			if (rtp_port == 0)
				rtp_port = 5004;
			ast_sockaddr_set_port(&src, rtp_port);
			ast_rtp_instance_set_remote_address(pvt->rtp, &src);
			if (sofia_debug)
				ast_verbose("Sofia: comedia - RTP remote set to %s\n",
					ast_sockaddr_stringify(&src));
		}
	}

	nua_handle_bind(nh, pvt);

	/* Set active contact for inbound call — match source addr to peer contacts */
	if (pvt->peer) {
		struct ast_sockaddr src;
		sofia_get_source_addr(sip, &src);
		struct sofia_contact *contact = sofia_peer_find_contact_by_addr(pvt->peer, &src);
		if (contact) {
			sofia_pvt_set_active_contact(pvt, contact);
			ao2_ref(contact, -1);
		}
	}

	nua_respond(nh, SIP_100_TRYING, TAG_END());

	chan = sofia_new(pvt, AST_STATE_RING, NULL);
	if (!chan) {
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
		ao2_ref(pvt, -1);
		return;
	}

	pvt->owner = chan;

	/* post-T56 identity-headers parity SS4 (2026-04-27): apply pvt->cid_num/
	 * cid_name + pvt->callingpres to channel. Source-of-truth is pvt fields
	 * (sofia_get_rpid may have overwritten From-header seed values). When
	 * trustrpid=0 or no RPID/PAI present, pvt->cid_num/cid_name = From-header
	 * values + pvt->callingpres = AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED
	 * (zero default). */
	if (!ast_strlen_zero(pvt->cid_num)) {
		ast_set_callerid(chan, pvt->cid_num,
			!ast_strlen_zero(pvt->cid_name) ? pvt->cid_name : NULL,
			pvt->cid_num);
		chan->caller.id.number.presentation = pvt->callingpres;
		chan->caller.id.name.presentation = pvt->callingpres;
	}

	/* post-T56 identity-headers parity SS5 (2026-04-27): inbound Diversion
	 * parsing — applies to pvt->owner->redirecting per chan_sip parity at
	 * chan_sip.c:20793-20850. Always evaluated; no trust-gating. Must run
	 * AFTER pvt->owner = chan binding so dialplan vars + redirecting struct
	 * land on the inbound channel. */
	sofia_change_redirecting_info(pvt, sip);

	ao2_link(dialogs, pvt);

	if (ast_pbx_start(chan)) {
		ast_log(LOG_ERROR, "Failed to start PBX on incoming Sofia call\n");
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
		ast_hangup(chan);
	}
}

static void sofia_process_bye(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	nua_respond(nh, SIP_200_OK, TAG_END());

	/* post-T56 call-limit parity SS2 R9 (2026-04-27): nua_i_bye DEC site.
	 * Flag-gated so the eventual sofia_hangup DEC is a no-op (call_inc_done=0). */
	if (op) {
		sofia_update_call_counter(op, SOFIA_DEC_CALL_LIMIT);
	}

	/* REFER transferer-leg BYE arrived as expected (RFC 5589 §6.1). Cancel the
	 * safety-net timer that sofia_process_refer armed and unlink the pvt so it
	 * gets collected. The channel side was already detached in sofia_hangup
	 * (op->owner == NULL), so no ast_queue_hangup is needed. chan_sip parity:
	 * handle_request_bye relies on `needdestroy` + the scheduled destroy fired
	 * in sip_hangup at chan_sip.c:7058. */
	if (op && op->defer_bye) {
		ast_mutex_lock(&op->lock);
		if (op->defer_bye_sched_id != -1 && sofia_sched
				&& ast_sched_thread_del(sofia_sched, op->defer_bye_sched_id) == 0) {
			ao2_ref(op, -1);
		}
		op->defer_bye_sched_id = -1;
		op->defer_bye = 0;
		op->state = SOFIA_DIALOG_STATE_DOWN;
		ast_mutex_unlock(&op->lock);
		ao2_unlink(dialogs, op);
		return;
	}

	if (op && op->owner) {
		ast_queue_hangup(op->owner);
	}
}

static void sofia_process_cancel(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	nua_respond(nh, SIP_200_OK, TAG_END());

	if (op && op->owner) {
		ast_queue_hangup_with_cause(op->owner, AST_CAUSE_NORMAL_CLEARING);
	}
}

static void sofia_process_options(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	nua_respond(nh, SIP_200_OK,
		SIPTAG_ALLOW_STR("INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER, "
				"SUBSCRIBE, NOTIFY, REFER, MESSAGE, INFO, PUBLISH, PRACK"),
		SIPTAG_ACCEPT_STR("application/sdp"),
		TAG_END());
}

/* T46.1: append a name/value pair to pvt->initreq_headers (preserves insertion order
 * so SIP_HEADER(name, N) returns the Nth occurrence as it appeared on the wire). */
static void sofia_initreq_append(struct sofia_pvt *pvt, const char *name, const char *value)
{
	struct ast_variable *v, *cur;

	if (!pvt || !name || !value) {
		return;
	}
	v = ast_variable_new(name, value, "");
	if (!v) {
		return;
	}
	if (!pvt->initreq_headers) {
		pvt->initreq_headers = v;
		return;
	}
	for (cur = pvt->initreq_headers; cur->next; cur = cur->next) {
		;
	}
	cur->next = v;
}

/* T46.1: snapshot the headers of an inbound INVITE so ${SIP_HEADER(name)} can read them
 * later from dialplan. Stores: From / To / Call-ID / Contact / Via* / User-Agent / Subject
 * via sip_header_as_string (formats the raw value into pvt->home), plus EVERY entry in
 * sip->sip_unknown (catches X-* + P-Asserted-Identity + Remote-Party-ID + Diversion etc.
 * since sofia-sip parks unrecognized headers there). Caller must own pvt. */
static void sofia_pvt_snapshot_initreq(struct sofia_pvt *pvt, sip_t const *sip)
{
	if (!pvt || !sip || !pvt->home) {
		return;
	}

	if (sip->sip_from) {
		sofia_initreq_append(pvt, "From",
			sip_header_as_string(pvt->home, (sip_header_t const *)sip->sip_from));
	}
	if (sip->sip_to) {
		sofia_initreq_append(pvt, "To",
			sip_header_as_string(pvt->home, (sip_header_t const *)sip->sip_to));
	}
	if (sip->sip_call_id && sip->sip_call_id->i_id) {
		sofia_initreq_append(pvt, "Call-ID", sip->sip_call_id->i_id);
	}
	if (sip->sip_contact) {
		sofia_initreq_append(pvt, "Contact",
			sip_header_as_string(pvt->home, (sip_header_t const *)sip->sip_contact));
	}
	if (sip->sip_user_agent && sip->sip_user_agent->g_string) {
		sofia_initreq_append(pvt, "User-Agent", sip->sip_user_agent->g_string);
	}
	if (sip->sip_subject && sip->sip_subject->g_string) {
		sofia_initreq_append(pvt, "Subject", sip->sip_subject->g_string);
	}
	{
		sip_via_t const *via;
		for (via = sip->sip_via; via; via = via->v_next) {
			sofia_initreq_append(pvt, "Via",
				sip_header_as_string(pvt->home, (sip_header_t const *)via));
		}
	}
	{
		sip_unknown_t const *un;
		for (un = sip->sip_unknown; un; un = un->un_next) {
			if (un->un_name && un->un_value) {
				sofia_initreq_append(pvt, un->un_name, un->un_value);
			}
		}
	}
}

/* T46.1: ${SIP_HEADER(name[,N])} — return Nth (default 1) value of named header from
 * the snapshot taken at INVITE-arrival time. chan_sip parity: warns + returns -1 on
 * empty arg or non-Sofia channel; empty buf if header not present. */
static int func_sofia_sip_header_read(struct ast_channel *chan, const char *function,
		char *data, char *buf, size_t len)
{
	struct sofia_pvt *pvt;
	struct ast_variable *v;
	int number = 1, occurrence = 0;
	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(header);
		AST_APP_ARG(number);
	);

	*buf = '\0';

	if (ast_strlen_zero(data)) {
		ast_log(LOG_WARNING, "SIP_HEADER requires a header name.\n");
		return -1;
	}

	ast_channel_lock(chan);
	if (chan->tech != &sofia_tech) {
		ast_log(LOG_WARNING, "SIP_HEADER can only be used on Sofia channels.\n");
		ast_channel_unlock(chan);
		return -1;
	}
	pvt = chan->tech_pvt;
	if (!pvt) {
		ast_channel_unlock(chan);
		return -1;
	}

	AST_STANDARD_APP_ARGS(args, data);
	if (!ast_strlen_zero(args.number)) {
		sscanf(args.number, "%30d", &number);
		if (number < 1) {
			number = 1;
		}
	}

	ast_mutex_lock(&pvt->lock);
	for (v = pvt->initreq_headers; v; v = v->next) {
		if (!strcasecmp(v->name, args.header)) {
			if (++occurrence == number) {
				ast_copy_string(buf, v->value, len);
				break;
			}
		}
	}
	ast_mutex_unlock(&pvt->lock);
	ast_channel_unlock(chan);

	return 0;
}

static struct ast_custom_function sofia_sip_header_function = {
	.name = "SIP_HEADER",
	.read = func_sofia_sip_header_read,
};

/* post-T56 autodomain [general] parity (2026-04-28, Pattern 5 helper #31 + retroactive-
 * refactor of T46.2 domain= parser): generic domain_list mutator. Adds name to
 * domain_list if non-empty + not already present (duplicate-check via existing
 * sofia_check_sip_domain helper #30). Centralizes mutation pattern previously inlined
 * at chan_sofia.c domain= parser; 6 wire-in callsites total: 5 NEW auto-add sites
 * (bindaddr + tlsbindaddr + wsbindaddr + externaddr + gethostname FQDN) + 1
 * retroactive existing domain= parser. chan_sofia helper-architecture-advantage 17th-
 * instance NEW DIMENSION centralized-domain-list-mutation across config + auto-add
 * dimensions. */
static void sofia_domain_list_add(const char *name)
{
	struct sofia_domain *d;

	if (ast_strlen_zero(name)) {
		return;
	}
	if (sofia_check_sip_domain(name)) {
		return;  /* duplicate-check; already present */
	}
	d = ast_calloc(1, sizeof(*d));
	if (!d) {
		return;
	}
	ast_copy_string(d->domain, name, sizeof(d->domain));
	AST_LIST_LOCK(&domain_list);
	AST_LIST_INSERT_TAIL(&domain_list, d, list);
	AST_LIST_UNLOCK(&domain_list);
}

/* post-T56 allowexternaldomains [general] parity (2026-04-28, Pattern 5 helper #30 +
 * retroactive-refactor of T46.2 + 5fbee76): generic domain_list walker. Returns 1 if
 * domain matches a configured entry in domain_list, 0 otherwise. Centralizes walker
 * pattern previously duplicated at 3 callsites (func_sofia_check_sipdomain T46.2 +
 * sofia_get_realm_for_dialog 5fbee76 inlined From-host + To-host). chan_sofia helper-
 * architecture-advantage 16th-instance NEW DIMENSION centralized-domain-validation. */
static int sofia_check_sip_domain(const char *domain)
{
	struct sofia_domain *d;
	int found = 0;

	if (ast_strlen_zero(domain)) {
		return 0;
	}
	AST_LIST_LOCK(&domain_list);
	AST_LIST_TRAVERSE(&domain_list, d, list) {
		if (!strcasecmp(d->domain, domain)) {
			found = 1;
			break;
		}
	}
	AST_LIST_UNLOCK(&domain_list);
	return found;
}

/* T46.2: ${CHECKSIPDOMAIN(domain)} — return the domain if it matches one in domain_list,
 * else empty. chan_sip parity (chan_sip.c:20510). Operators populate the list via
 * sofia.conf [general] domain= entries.
 * post-T56 allowexternaldomains retroactive-refactor (2026-04-28): uses Pattern 5
 * helper #30 sofia_check_sip_domain for centralized walker. */
static int func_sofia_check_sipdomain(struct ast_channel *chan, const char *cmd,
		char *data, char *buf, size_t len)
{
	if (ast_strlen_zero(data)) {
		ast_log(LOG_WARNING, "CHECKSIPDOMAIN requires a domain argument\n");
		return -1;
	}
	buf[0] = '\0';
	if (sofia_check_sip_domain(data)) {
		ast_copy_string(buf, data, len);
	}
	return 0;
}

static struct ast_custom_function sofia_check_sipdomain_function = {
	.name = "CHECKSIPDOMAIN",
	.read = func_sofia_check_sipdomain,
};

/* T46.3: helper — return first contact in peer->contacts (ao2 ref +1) or NULL.
 * Used by useragent + fullcontact items in SIPPEER. */
static struct sofia_contact *sofia_peer_first_contact(struct sofia_peer *peer)
{
	struct ao2_iterator iter;
	struct sofia_contact *c;

	if (!peer || !peer->contacts) {
		return NULL;
	}
	iter = ao2_iterator_init(peer->contacts, 0);
	c = ao2_iterator_next(&iter);
	ao2_iterator_destroy(&iter);
	return c;
}

/* T46.3: ${SIPPEER(peername[,item])} — read peer config field. chan_sip parity
 * (chan_sip.c:20529 function_sippeer) plus chan_sofia-only items
 * (busy_on_active T21, max_contacts T22, qualifyfreq, qualifytimeout, lastms).
 * item defaults to "ip" if omitted. Unknown item -> empty buf + 0 (chan_sip parity). */
static int func_sofia_sippeer(struct ast_channel *chan, const char *cmd,
		char *data, char *buf, size_t len)
{
	struct sofia_peer *peer;
	char *peername, *colname, *parts;

	if (ast_strlen_zero(data)) {
		ast_log(LOG_WARNING, "SIPPEER requires a peer name\n");
		return -1;
	}
	parts = ast_strdupa(data);
	peername = strsep(&parts, ",");
	colname = strsep(&parts, ",");
	if (!colname) {
		colname = "ip";
	}

	peer = sofia_find_peer(peername);
	if (!peer) {
		return -1;
	}

	buf[0] = '\0';

	if (!strcasecmp(colname, "ip")) {
		struct ast_sockaddr addr;
		if (!strcasecmp(peer->host, "dynamic") && peer->registered) {
			addr = peer->src_addr;
		} else {
			addr = peer->addr;
		}
		ast_copy_string(buf, ast_sockaddr_stringify_addr(&addr), len);
	} else if (!strcasecmp(colname, "port")) {
		struct ast_sockaddr addr = (!strcasecmp(peer->host, "dynamic") && peer->registered)
			? peer->src_addr : peer->addr;
		snprintf(buf, len, "%u", ast_sockaddr_port(&addr));
	} else if (!strcasecmp(colname, "status")) {
		switch (peer->peer_status) {
		case PEER_REACHABLE:
			snprintf(buf, len, "OK (%dms)", peer->lastms);
			break;
		case PEER_LAGGED:
			snprintf(buf, len, "LAGGED (%dms)", peer->lastms);
			break;
		case PEER_UNREACHABLE:
			ast_copy_string(buf, "UNREACHABLE", len);
			break;
		default:
			ast_copy_string(buf, "UNKNOWN", len);
			break;
		}
	} else if (!strcasecmp(colname, "useragent")) {
		struct sofia_contact *c = sofia_peer_first_contact(peer);
		if (c) {
			ast_copy_string(buf, S_OR(c->user_agent, ""), len);
			ao2_ref(c, -1);
		}
	} else if (!strcasecmp(colname, "regexpire") || !strcasecmp(colname, "expire")) {
		time_t now = time(NULL);
		long secs = peer->reg_expiry > now ? (long)(peer->reg_expiry - now) : 0;
		snprintf(buf, len, "%ld", secs);
	} else if (!strcasecmp(colname, "callgroup")) {
		ast_print_group(buf, len, peer->callgroup);
	} else if (!strcasecmp(colname, "pickupgroup")) {
		ast_print_group(buf, len, peer->pickupgroup);
	} else if (!strcasecmp(colname, "context")) {
		ast_copy_string(buf, peer->context, len);
	} else if (!strcasecmp(colname, "codecs")) {
		ast_getformatname_multiple(buf, len - 1, peer->capability);
	} else if (!strcasecmp(colname, "encryption")) {
		snprintf(buf, len, "%d", peer->encryption ? 1 : 0);
	} else if (!strcasecmp(colname, "srtpcipher")) {
		/* post-T56 srtpcipher operator option (2026-04-27): SIPPEER dialplan column read. */
		ast_copy_string(buf, peer->srtpcipher, len);
	} else if (!strcasecmp(colname, "dynamic")) {
		ast_copy_string(buf, !strcasecmp(peer->host, "dynamic") ? "yes" : "no", len);
	} else if (!strcasecmp(colname, "callerid_name") || !strcasecmp(colname, "callerid_num")) {
		char tmp[256];
		char *cidname = NULL, *cidnum = NULL;
		ast_copy_string(tmp, peer->callerid, sizeof(tmp));
		ast_callerid_parse(tmp, &cidname, &cidnum);
		if (!strcasecmp(colname, "callerid_name")) {
			ast_copy_string(buf, S_OR(cidname, ""), len);
		} else {
			ast_copy_string(buf, S_OR(cidnum, ""), len);
		}
	} else if (!strcasecmp(colname, "fromuser")) {
		ast_copy_string(buf, peer->fromuser, len);
	} else if (!strcasecmp(colname, "fromdomain")) {
		ast_copy_string(buf, peer->fromdomain, len);
	} else if (!strcasecmp(colname, "accountcode")) {
		/* post-T56 accountcode per-peer parity (2026-04-27): SIPPEER(<peer>,accountcode)
		 * dialplan reader; chan_sip parity at chan_sip.c:20662-20663 verbatim. */
		ast_copy_string(buf, peer->accountcode, len);
	} else if (!strcasecmp(colname, "fullcontact")) {
		struct sofia_contact *c = sofia_peer_first_contact(peer);
		if (c) {
			ast_copy_string(buf, S_OR(c->contact_uri, ""), len);
			ao2_ref(c, -1);
		}
	} else if (!strcasecmp(colname, "curcalls")) {
		int total = 0;
		if (peer->contacts) {
			struct ao2_iterator iter = ao2_iterator_init(peer->contacts, 0);
			struct sofia_contact *c;
			while ((c = ao2_iterator_next(&iter))) {
				total += c->active_calls;
				ao2_ref(c, -1);
			}
			ao2_iterator_destroy(&iter);
		}
		snprintf(buf, len, "%d", total);
	} else if (!strcasecmp(colname, "busy_on_active")) {
		snprintf(buf, len, "%d", peer->busy_on_active ? 1 : 0);
	} else if (!strcasecmp(colname, "max_contacts")) {
		snprintf(buf, len, "%d", peer->max_contacts);
	} else if (!strcasecmp(colname, "qualifyfreq")) {
		snprintf(buf, len, "%d", peer->qualifyfreq);
	} else if (!strcasecmp(colname, "qualifytimeout")) {
		snprintf(buf, len, "%d", peer->qualifytimeout);
	} else if (!strcasecmp(colname, "lastms")) {
		snprintf(buf, len, "%d", peer->lastms);
	}
	/* unknown colname -> empty buf + return 0 (chan_sip parity) */

	ao2_ref(peer, -1);
	return 0;
}

static struct ast_custom_function sofia_sippeer_function = {
	.name = "SIPPEER",
	.read = func_sofia_sippeer,
};

/* T46.4: ${SIPCHANINFO(item)} — read current Sofia channel info. chan_sip parity
 * (chan_sip.c:20630). peerip + recvip are COLLAPSED to last_src_addr (sofia-sip
 * resolves transport source via Via received/rport at INVITE time; the chan_sip
 * SDP-c=-vs-rport distinction is hidden by the NUA layer). */
static int func_sofia_sipchaninfo(struct ast_channel *chan, const char *cmd,
		char *data, char *buf, size_t len)
{
	struct sofia_pvt *pvt;

	if (ast_strlen_zero(data)) {
		ast_log(LOG_WARNING, "SIPCHANINFO requires an item argument\n");
		return -1;
	}
	if (!chan || chan->tech != &sofia_tech) {
		ast_log(LOG_WARNING, "SIPCHANINFO must be called on a Sofia channel\n");
		return -1;
	}
	pvt = chan->tech_pvt;
	if (!pvt) {
		return -1;
	}

	buf[0] = '\0';
	ast_mutex_lock(&pvt->lock);
	if (!strcasecmp(data, "peerip") || !strcasecmp(data, "recvip")) {
		ast_copy_string(buf, ast_sockaddr_stringify_addr(&pvt->last_src_addr), len);
	} else if (!strcasecmp(data, "from") || !strcasecmp(data, "useragent")) {
		const char *target = !strcasecmp(data, "from") ? "From" : "User-Agent";
		struct ast_variable *v;
		for (v = pvt->initreq_headers; v; v = v->next) {
			if (!strcasecmp(v->name, target)) {
				ast_copy_string(buf, v->value, len);
				break;
			}
		}
	} else if (!strcasecmp(data, "uri")) {
		ast_copy_string(buf, S_OR(pvt->ruri, ""), len);
	} else if (!strcasecmp(data, "peername")) {
		ast_copy_string(buf, pvt->peer ? pvt->peer->name : "", len);
	} else if (!strcasecmp(data, "t38passthrough")) {
		/* Current compatibility behavior: this dialplan function reports
		 * 0 here. T.38 call state is handled by the channel T.38 control
		 * path and UDPTL callbacks, not exposed through SIPCHANINFO yet. */
		ast_copy_string(buf, "0", len);
	}
	/* unknown item -> empty buf + return 0 (chan_sip parity, matches T46.3 SIPPEER) */
	ast_mutex_unlock(&pvt->lock);
	return 0;
}

static struct ast_custom_function sofia_sipchaninfo_function = {
	.name = "SIPCHANINFO",
	.read = func_sofia_sipchaninfo,
};

/* Extract source IP:port from incoming SIP message for NAT handling */
static void sofia_get_source_addr(sip_t const *sip, struct ast_sockaddr *addr)
{
	sip_via_t const *via;

	if (!sip || !addr)
		return;

	via = sip->sip_via;
	if (!via)
		return;

	/* Use received parameter (set by NTA for actual source IP) or Via host */
	if (via->v_received) {
		const char *src_port = via->v_rport ? via->v_rport : via->v_port;
		char addr_str[256];
		snprintf(addr_str, sizeof(addr_str), "%s:%s",
			via->v_received, src_port ? src_port : "5060");
		ast_sockaddr_parse(addr, addr_str, 0);
		if (sofia_debug)
			ast_verbose("Sofia: source addr (via received): %s\n", addr_str);
	} else {
		const char *host = via->v_host;
		const char *port = via->v_rport ? via->v_rport : via->v_port;
		char addr_str[256];
		if (!host)
			return;
		snprintf(addr_str, sizeof(addr_str), "%s:%s", host, port ? port : "5060");
		ast_sockaddr_parse(addr, addr_str, 0);
		if (sofia_debug)
			ast_verbose("Sofia: source addr (via host): %s\n", addr_str);
	}
}

static int sofia_blacklist_hash_fn(const void *obj, int flags)
{
	const struct sofia_blacklist_entry *entry = obj;

	return ast_str_case_hash(entry->ip);
}

static int sofia_blacklist_cmp_fn(void *obj, void *arg, int flags)
{
	struct sofia_blacklist_entry *entry = obj;
	struct sofia_blacklist_entry *match = arg;

	return !strcasecmp(entry->ip, match->ip) ? (CMP_MATCH | CMP_STOP) : 0;
}

static int sofia_blacklist_ip_from_addr(const struct ast_sockaddr *addr, char *buf, size_t len)
{
	const char *ip;

	if (!addr || ast_sockaddr_isnull(addr) || !buf || !len) {
		return -1;
	}

	ip = ast_sockaddr_stringify_addr(addr);
	if (ast_strlen_zero(ip)) {
		return -1;
	}

	ast_copy_string(buf, ip, len);
	return 0;
}

static int sofia_blacklist_ip_from_sip(sip_t const *sip, char *buf, size_t len)
{
	struct ast_sockaddr src;

	memset(&src, 0, sizeof(src));
	sofia_get_source_addr(sip, &src);
	return sofia_blacklist_ip_from_addr(&src, buf, len);
}

static int sofia_blacklist_ip_from_text(const char *text, char *buf, size_t len)
{
	struct ast_sockaddr addr;

	if (ast_strlen_zero(text) || !buf || !len) {
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	if (ast_sockaddr_parse(&addr, text, PARSE_PORT_IGNORE)
			&& sofia_blacklist_ip_from_addr(&addr, buf, len) == 0) {
		return 0;
	}

	ast_copy_string(buf, text, len);
	return 0;
}

static int sofia_blacklist_check_ip(const char *ip, int add, const char *reason)
{
	struct sofia_blacklist_entry key;
	struct sofia_blacklist_entry *entry;
	int blocked = 0;
	time_t now = time(NULL);

	if (!sofia_blacklist || ast_strlen_zero(ip)) {
		return 0;
	}

	memset(&key, 0, sizeof(key));
	ast_copy_string(key.ip, ip, sizeof(key.ip));

	ast_mutex_lock(&sofia_blacklist_lock);
	entry = ao2_find(sofia_blacklist, &key, OBJ_POINTER);
	if (!entry && add) {
		if (ao2_container_count(sofia_blacklist) >= sofia_blacklist_max) {
			ast_log(LOG_ERROR, "Sofia blacklist FULL\n");
			ast_mutex_unlock(&sofia_blacklist_lock);
			return 0;
		}
		entry = ao2_alloc(sizeof(*entry), NULL);
		if (!entry) {
			ast_mutex_unlock(&sofia_blacklist_lock);
			return 0;
		}
		ast_copy_string(entry->ip, ip, sizeof(entry->ip));
		entry->counter = 0;
		entry->first_seen = now;
		entry->last_seen = now;
		ao2_link(sofia_blacklist, entry);
	}
	if (entry) {
		if (add) {
			entry->counter++;
			entry->last_seen = now;
			if (option_debug > 3) {
				ast_log(LOG_DEBUG, "Sofia blacklist host %s counter %d/%d (%s)\n",
					entry->ip, entry->counter, sofia_blacklist_count,
					S_OR(reason, "no reason"));
			}
		}
		blocked = entry->counter >= sofia_blacklist_count;
		ao2_ref(entry, -1);
	}
	ast_mutex_unlock(&sofia_blacklist_lock);

	return blocked;
}

static int sofia_blacklist_add_sip(sip_t const *sip, const char *reason)
{
	char ip[80];

	if (sofia_blacklist_ip_from_sip(sip, ip, sizeof(ip)) < 0) {
		return 0;
	}

	return sofia_blacklist_check_ip(ip, 1, reason);
}

static int sofia_blacklist_check_sip(sip_t const *sip)
{
	char ip[80];

	if (sofia_blacklist_ip_from_sip(sip, ip, sizeof(ip)) < 0) {
		return 0;
	}

	if (!sofia_blacklist_check_ip(ip, 0, NULL)) {
		return 0;
	}

	return 1;
}

static void sofia_contact_uri_from_url(char *buf, size_t len, const url_t *url)
{
	if (!url || !buf) {
		buf[0] = '\0';
		return;
	}
	snprintf(buf, len, "sip:%s%s%s:%s",
		url->url_user ? url->url_user : "",
		url->url_user ? "@" : "",
		url->url_host ? url->url_host : "",
		url->url_port ? url->url_port : "5060");
}

static int sofia_expire_contacts_cb(void *obj, void *arg, int flags)
{
	struct sofia_contact *c = obj;
	time_t *now = arg;
	/* post-T56 ignoreregexpire [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:14629 destroy_association cleanup-skip-when-set semantic. Preserves
	 * last-known contact across short upstream-trunk outages (stable-trunk use case
	 * such as PSTN gateway routing across intermittent network drops). */
	if (sofia_cfg.ignore_regexpire) {
		return 0;
	}
	if (c->expires > 0 && c->expires < *now) {
		ast_verbose("Sofia: Expiring contact %s\n", c->contact_uri);
		return CMP_MATCH;
	}
	return 0;
}

static int sofia_update_peer_contacts(struct sofia_peer *peer, sip_t const *sip, int expires,
	struct sofia_register_update *update)
{
	time_t now = time(NULL);
	struct ast_sockaddr src;
	sip_contact_t *m;

	sofia_get_source_addr(sip, &src);
	if (update) {
		memset(update, 0, sizeof(*update));
		update->was_registered = peer->registered;
		update->contacts_before = ao2_container_count(peer->contacts);
		ast_sockaddr_copy(&update->old_src, &peer->src_addr);
		ast_sockaddr_copy(&update->new_src, &src);
	}

	if (expires == 0) {
		/* Check for Contact: * wildcard */
		for (m = sip->sip_contact; m; m = m->m_next) {
			if (m->m_url->url_type == url_any) {
				/* Wildcard — clear all contacts */
				ao2_callback(peer->contacts, OBJ_UNLINK | OBJ_NODATA | OBJ_MULTIPLE,
					NULL, NULL);
				peer->registered = 0;
				memset(&peer->src_addr, 0, sizeof(peer->src_addr));
				if (update) {
					update->wildcard_removed = 1;
					update->contacts_removed = update->contacts_before;
					update->now_registered = 0;
					update->contacts_after = 0;
					sofia_register_update_set_uri(update, "*");
				}
				/* post-T56 regexten parity (2026-04-27): auto-remove dialplan extension on
				 * wildcard unregister (chan_sip parity). No-op if sofia_cfg.regcontext empty. */
				register_peer_exten(peer, 0);
				manager_event(EVENT_FLAG_SYSTEM, "PeerStatus",
					"ChannelType: SIP\r\n"
					"Peer: SIP/%s\r\n"
					"PeerStatus: Unregistered\r\n"
					"Cause: Wildcard\r\n",
					peer->name);
				return 0;
				}
			}
		/* Specific contact(s) de-registration */
		for (m = sip->sip_contact; m; m = m->m_next) {
			char uri[256];
			struct sofia_contact *c;

			sofia_contact_uri_from_url(uri, sizeof(uri), m->m_url);
			c = ao2_find(peer->contacts, uri, OBJ_POINTER);
			if (c) {
				if (update) {
					update->contacts_removed++;
					sofia_register_update_set_uri(update, uri);
				}
				ao2_ref(c, -1);
			}
			ao2_find(peer->contacts, uri, OBJ_UNLINK | OBJ_NODATA);
			if (sofia_debug)
				ast_verbose("Sofia: Unlinked contact %s\n", uri);
		}
	} else {
		/* Registration / re-registration */
		for (m = sip->sip_contact; m; m = m->m_next) {
			char uri[256];
			struct sofia_contact *c;

			sofia_contact_uri_from_url(uri, sizeof(uri), m->m_url);

			/* post-T56 contactpermit/contactdeny per-peer parity (2026-04-27):
			 * apply BOTH sofia_cfg.contact_ha (global) AND peer->contactha
			 * against the Contact: URL host:port. Short-circuit OR (either rejects
			 * = DENY entire REGISTER per Contact). chan_sip parity at chan_sip.c:15043-15044
			 * verbatim semantic. NULL ha chains pass-through (ast_apply_ha returns
			 * AST_SENSE_ALLOW); peers without contactpermit/contactdeny configs behave
			 * identically to today (Task 12 backwards-compat ABSOLUTE). */
			if (sofia_cfg.contact_ha || peer->contactha) {
				struct ast_sockaddr contact_addr;
				char addr_buf[128];
				snprintf(addr_buf, sizeof(addr_buf), "%s:%d",
					m->m_url->url_host ? m->m_url->url_host : "0.0.0.0",
					m->m_url->url_port ? atoi(m->m_url->url_port) : 5060);
				if (ast_sockaddr_parse(&contact_addr, addr_buf, 0)) {
					if ((sofia_cfg.contact_ha && ast_apply_ha(sofia_cfg.contact_ha, &contact_addr) != AST_SENSE_ALLOW) ||
					    (peer->contactha && ast_apply_ha(peer->contactha, &contact_addr) != AST_SENSE_ALLOW)) {
						ast_log(LOG_NOTICE, "Sofia: REGISTER from peer '%s' Contact %s rejected by contact-ACL\n",
							peer->name, uri);
						return -1;
					}
				}
			}

			c = ao2_find(peer->contacts, uri, OBJ_POINTER);
			if (c) {
				/* Refresh existing contact */
				if (update) {
					update->contacts_refreshed++;
					if (ast_sockaddr_cmp(&c->src_addr, &src)) {
						update->contacts_moved++;
						sofia_register_update_set_uri(update, uri);
						ast_sockaddr_copy(&update->changed_old_src, &c->src_addr);
						ast_sockaddr_copy(&update->new_src, &src);
					}
				}
				c->expires = now + expires;
				memcpy(&c->src_addr, &src, sizeof(src));
				if (sip->sip_user_agent && sip->sip_user_agent->g_string)
					ast_copy_string(c->user_agent, sip->sip_user_agent->g_string,
						sizeof(c->user_agent));
				ao2_ref(c, -1);
				if (sofia_debug)
					ast_verbose("Sofia: Refreshed contact %s (expires in %ds)\n", uri, expires);
			} else {
				/* New contact */
				c = ao2_alloc(sizeof(*c), NULL);
				if (!c) continue;
				if (update) {
					update->contacts_added++;
					sofia_register_update_set_uri(update, uri);
					ast_sockaddr_copy(&update->new_src, &src);
				}
				ast_copy_string(c->contact_uri, uri, sizeof(c->contact_uri));
				if (m->m_url->url_host)
					ast_copy_string(c->host, m->m_url->url_host, sizeof(c->host));
				c->port = m->m_url->url_port ? atoi(m->m_url->url_port) : 5060;
				if (m->m_url->url_scheme && strcasestr(m->m_url->url_scheme, "tls"))
					ast_copy_string(c->transport, "tls", sizeof(c->transport));
				else if (m->m_url->url_scheme && strcasestr(m->m_url->url_scheme, "tcp"))
					ast_copy_string(c->transport, "tcp", sizeof(c->transport));
				else
					ast_copy_string(c->transport, "udp", sizeof(c->transport));
				if (sip->sip_user_agent && sip->sip_user_agent->g_string)
					ast_copy_string(c->user_agent, sip->sip_user_agent->g_string,
						sizeof(c->user_agent));
				c->expires = now + expires;
				memcpy(&c->src_addr, &src, sizeof(src));
				ao2_lock(peer->contacts);
				if (ao2_container_count(peer->contacts) >= peer->max_contacts) {
					/* chan_sip parity: peer is at max_contacts and a NEW Contact
					 * URI just arrived (the refresh branch above didn't match).
					 * chan_sip never rejected in this case — it replaced the
					 * existing binding. Mirror that here by evicting the contact
					 * with the earliest expiry (LRU by `expires`), then link the
					 * new one. The phone keeps a valid registration; only the
					 * stale row goes away. Holding peer->contacts lock across the
					 * iteration is safe because ao2_iterator with flags=0 does
					 * not re-take the lock. */
					struct ao2_iterator i;
					struct sofia_contact *cand, *oldest = NULL;

					i = ao2_iterator_init(peer->contacts, 0);
					while ((cand = ao2_iterator_next(&i))) {
						if (!oldest || cand->expires < oldest->expires) {
							if (oldest) {
								ao2_ref(oldest, -1);
							}
							oldest = cand;
						} else {
							ao2_ref(cand, -1);
						}
					}
					ao2_iterator_destroy(&i);

					if (oldest) {
						/* Cosmetic eviction trace: gated by `sip set debug` so
						 * production runs silent. AMI/verbose registration
						 * summary at sofia_verbose_register_update still
						 * reports per-REGISTER `contacts_removed` counts. */
						if (sofia_debug_match(peer->name, NULL)) {
							ast_verbose("Sofia: peer '%s' at max_contacts=%d \xe2\x80\x94 evicting oldest contact %s\n",
								peer->name, peer->max_contacts, oldest->contact_uri);
						}
						if (update) {
							update->contacts_removed++;
						}
						ao2_unlink(peer->contacts, oldest);
						ao2_ref(oldest, -1);
					}
				}
				ao2_link(peer->contacts, c);
				ao2_unlock(peer->contacts);
				ao2_ref(c, -1);
				if (sofia_debug)
					ast_verbose("Sofia: New contact %s for peer '%s'\n", uri, peer->name);
			}
		}
	}

	/* Opportunistic expiry sweep */
	ao2_callback(peer->contacts, OBJ_UNLINK | OBJ_NODATA | OBJ_MULTIPLE,
		sofia_expire_contacts_cb, &now);

	/* Update legacy src_addr from newest contact, update registered flag */
	if (ao2_container_count(peer->contacts) > 0) {
		peer->registered = 1;
		peer->expire = expires;
		memcpy(&peer->src_addr, &src, sizeof(peer->src_addr));
	} else {
		peer->registered = 0;
		memset(&peer->src_addr, 0, sizeof(peer->src_addr));
		if (update && update->was_registered && !update->contacts_removed) {
			update->contacts_removed = update->contacts_before;
		}
		/* post-T56 regexten parity (2026-04-27): auto-remove dialplan extension on
		 * expiry-driven unregister (chan_sip parity). No-op if sofia_cfg.regcontext empty. */
		register_peer_exten(peer, 0);
		manager_event(EVENT_FLAG_SYSTEM, "PeerStatus",
			"ChannelType: SIP\r\n"
			"Peer: SIP/%s\r\n"
			"PeerStatus: Unregistered\r\n"
			"Cause: Expired\r\n",
			peer->name);
	}
	if (update) {
		update->now_registered = peer->registered;
		update->contacts_after = ao2_container_count(peer->contacts);
		ast_sockaddr_copy(&update->new_src, &peer->src_addr);
	}

	return 0;
}

static void sofia_verbose_register_update(const struct sofia_peer *peer,
	const struct sofia_register_update *update)
{
	const char *new_src;

	if (!peer || !update || !VERBOSITY_ATLEAST(6)) {
		return;
	}

	if (update->wildcard_removed) {
		ast_verbose(VERBOSE_PREFIX_3 "Unregistered SIP '%s' (all contacts)\n",
			peer->name);
		return;
	}

	if (update->contacts_removed) {
		if (update->contacts_removed == 1 && !ast_strlen_zero(update->changed_uri)) {
			ast_verbose(VERBOSE_PREFIX_3 "Unregistered SIP '%s' contact %s\n",
				peer->name, update->changed_uri);
		} else {
			ast_verbose(VERBOSE_PREFIX_3 "Unregistered SIP '%s' %d contacts\n",
				peer->name, update->contacts_removed);
		}
		return;
	}

	if (!update->was_registered && update->now_registered) {
		new_src = ast_strdupa(ast_sockaddr_stringify(&update->new_src));
		if (update->contacts_after > 1) {
			ast_verbose(VERBOSE_PREFIX_3 "Registered SIP '%s' at %s (%d contacts)\n",
				peer->name, new_src, update->contacts_after);
		} else {
			ast_verbose(VERBOSE_PREFIX_3 "Registered SIP '%s' at %s\n",
				peer->name, new_src);
		}
		return;
	}

	if (update->contacts_added) {
		new_src = ast_strdupa(ast_sockaddr_stringify(&update->new_src));
		if (update->contacts_added == 1 && !ast_strlen_zero(update->changed_uri)) {
			ast_verbose(VERBOSE_PREFIX_3 "Registered SIP '%s' new contact %s via %s\n",
				peer->name, update->changed_uri, new_src);
		} else {
			ast_verbose(VERBOSE_PREFIX_3 "Registered SIP '%s' %d new contacts via %s\n",
				peer->name, update->contacts_added, new_src);
		}
		return;
	}

	if (update->contacts_moved && !ast_strlen_zero(update->changed_uri)) {
		const char *old_src = ast_strdupa(ast_sockaddr_stringify(&update->changed_old_src));
		new_src = ast_strdupa(ast_sockaddr_stringify(&update->new_src));
		ast_verbose(VERBOSE_PREFIX_3 "Registered SIP '%s' contact moved %s from %s to %s\n",
			peer->name, update->changed_uri, old_src, new_src);
	}
}

static const char *sofia_au_get_unq(sip_authorization_t const *au, const char *name,
		char *buf, size_t len)
{
	const char *raw;
	size_t raw_len;
	size_t n;

	if (!au || !au->au_params) {
		return NULL;
	}
	raw = msg_header_find_param(au->au_common, name);
	if (!raw) {
		return NULL;
	}
	/* post-T56 Task #3 SS2 (2026-04-28, N2 audit hardening): reject silently-
	 * truncated overflow. ast_copy_string truncates raw to len-1 bytes; without
	 * length-check, a malicious 17-char nc could truncate to 15 chars passing
	 * a smaller value to nc-monotonic check. Return NULL on overflow so callers
	 * reject 400 Bad Request per RFC 2617 §3.2.2. */
	raw_len = strlen(raw);
	if (raw_len >= len) {
		return NULL;
	}
	ast_copy_string(buf, raw, len);
	n = strlen(buf);
	if (n >= 2 && buf[0] == '"' && buf[n - 1] == '"') {
		buf[n - 1] = '\0';
		return buf + 1;
	}
	return buf;
}

/* post-T56 match_auth_username (2026-04-28): Pattern 5 helper #28 — chan_sip-parity
 * peer-lookup search-key picker. When sofia_cfg.match_auth_username is set, peer
 * lookup uses Authorization-username (or Proxy-Authorization fallback per chan_sip
 * L17268 verbatim) instead of From-username. chan_sip parity at chan_sip.c:17258-17277
 * verbatim Authorization → Proxy-Authorization fallback chain semantic.
 *
 * chan_sofia ARCHITECTURAL ADVANTAGE 10th-instance: centralized auth-username pick
 * vs chan_sip inline at single L17258-17277 site. chan_sofia has 2 callsites
 * (sofia_process_register + sofia_process_invite) that both need the same
 * Authorization → Proxy-Authorization fallback chain; helper centralizes.
 *
 * Returns: const char * pointing into buf (when auth-username found) OR
 * fallback_user (when no Authorization/Proxy-Authorization OR username field
 * absent/empty). Caller MUST treat the returned pointer as borrowed. */
static const char *sofia_pick_auth_username(sip_t const *sip,
		const char *fallback_user, char *buf, size_t len)
{
	const char *result;

	if (!sip || !buf || len == 0) {
		return fallback_user;
	}

	if (sip->sip_authorization) {
		result = sofia_au_get_unq(sip->sip_authorization, "username", buf, len);
		if (result && *result) {
			return result;
		}
	}

	/* chan_sip parity L17268 verbatim Proxy-Authorization fallback. Both
	 * sip_authorization_t and sip_proxy_authorization_t are typedefs of
	 * struct msg_auth_s per sip.h L152+L177; cast is type-safe. */
	if (sip->sip_proxy_authorization) {
		result = sofia_au_get_unq((sip_authorization_t const *)sip->sip_proxy_authorization,
			"username", buf, len);
		if (result && *result) {
			return result;
		}
	}

	return fallback_user;
}

/* post-T56 Task #3 INVITE digest auth SS2 (2026-04-28): forward decl for
 * sofia_regen_nonce_locked — called from sofia_verify_digest_auth helper #34
 * for nonce-stale-challenge regen path; defined later in same translation unit
 * to keep adjacent to existing nonce-state-management code. */
static void sofia_regen_nonce_locked(struct sofia_peer *peer, char *out_buf, size_t out_len);
/* SS5 forward-decl for sofia_peer_offers_sha256 — called from sofia_verify_
 * digest_auth (Pattern 5 helper #34) per Finding #2 per-peer-algorithm-offer;
 * defined at sofia_send_auth_challenge cluster ~L7508 (distance >300 LoC;
 * forward-decl-when-distance discipline). NOTE: sofia_emit_timing_equalized_
 * reject + sofia_send_auth_challenge moved to early forward-decl cluster
 * (L992+) for sofia_process_invite visibility. */
static int sofia_peer_offers_sha256(struct sofia_peer *peer);

/* post-T56 Task #3 INVITE digest auth SS2 (2026-04-28, Pattern 5 helper #36 +
 * SW1 timing-attack fix + N6 compiler-elision hardening): constant-time memory
 * comparison for digest hash verification. Replaces strncasecmp at sofia_process_
 * register L7282 (was vulnerable to timing-attack byte-by-byte enumeration of
 * expected MD5 hash). volatile accumulator + memory barrier per N6 audit
 * hardening prevents GCC/Clang -O2/-O3 unroll/branch-predict optimizations
 * from defeating constant-time guarantee. Returns 0 on match; nonzero on
 * mismatch. chan_sip parity ABSENT — chan_sip uses strncasecmp at
 * chan_sip.c:15438 (vulnerable). chan_sofia surpass dimension via constant-
 * time-comparison-where-chan_sip-vulnerable. */
static inline int sofia_ct_memcmp(const void *a, const void *b, size_t len)
{
	const unsigned char *pa = a;
	const unsigned char *pb = b;
	volatile unsigned char diff = 0;
	for (size_t i = 0; i < len; i++) {
		diff |= pa[i] ^ pb[i];
	}
	__asm__ __volatile__("" ::: "memory");
	return diff;
}

/* post-T56 Task #3 INVITE digest auth SS2 (2026-04-28, Pattern 5 helper #37 +
 * SW2 weak-nonce fix + N7 EINTR-retry hardening): crypto-secure 128-bit
 * nonce generation via /dev/urandom direct read. Replaces gettimeofday-based
 * nonce (was ~20 bits effective entropy vs network attacker per E1 audit;
 * fully predictable wall-clock). Output: 32 hex chars (128 bits). Fallback
 * path (4× ast_random composite) ~96-100 bits effective with LOG_WARNING for
 * operator visibility into degraded entropy state. EINTR retry loop ensures
 * signal-during-read does not silently degrade to fallback when /dev/urandom
 * fully available. Caller passes out_buf with size ≥ 33 (32 hex + null). */
static int sofia_secure_nonce_gen(char *out_buf, size_t out_len)
{
	unsigned char raw[16];
	int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		ssize_t r;
		size_t got = 0;
		do {
			r = read(fd, raw + got, sizeof(raw) - got);
			if (r < 0) {
				if (errno == EINTR) continue;
				break;
			}
			if (r == 0) break;
			got += (size_t)r;
		} while (got < sizeof(raw));
		close(fd);
		if (got == sizeof(raw)) {
			for (size_t i = 0; i < sizeof(raw); i++) {
				snprintf(out_buf + (i * 2), out_len - (i * 2), "%02x", raw[i]);
			}
			return 0;
		}
	}
	ast_log(LOG_WARNING, "Sofia: /dev/urandom unavailable for nonce; "
		"falling back to ast_random composite (degraded entropy ~96-100 bits vs ideal 128)\n");
	snprintf(out_buf, out_len, "%08lx%08lx%08lx%08lx",
		(unsigned long)ast_random(), (unsigned long)ast_random(),
		(unsigned long)ast_random(), (unsigned long)ast_random());
	return 0;
}

/* post-T56 Task #3 INVITE digest auth SS4 (2026-04-28, RFC 7616 SHA-256
 * algorithm-dispatch enum): chan_sofia supports MD5 and SHA-256. Challenges
 * emit MD5 first for chan_sip/legacy-client compatibility and SHA-256 second
 * when the peer can use it; verification dispatches by Authorization
 * algorithm=. RFC 2069 + RFC 2617 backward-compat is preserved by using MD5
 * when the client omits algorithm=. */
#define SOFIA_DIGEST_MD5     0
#define SOFIA_DIGEST_SHA256  1

/* post-T56 Task #3 INVITE digest auth SS4 (2026-04-28, RFC 7616 chan_sofia
 * surpass): SHA-256 hash wrapper using OpenSSL/libcrypto's exported SHA256()
 * API. Output: 64 hex chars + null (caller passes buf size >= 65). Mirrors
 * ast_md5_hash interface for symmetric call-site usage in sofia_compute_a1_hash
 * + sofia_compute_digest. */
static void sofia_sha256_hash(char *out_buf, const char *input)
{
	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256((const unsigned char *)input, strlen(input), digest);
	for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		snprintf(out_buf + (i * 2), 3, "%02x", digest[i]);
	}
}

/* post-T56 Task #3 INVITE digest auth SS4 (2026-04-28, Pattern 5 helper #38
 * UPGRADED with SW11 md5secret branch + RFC 7616 SHA-256 algorithm parameter):
 * compute A1 hash for digest auth. md5secret-precedence per chan_sip.c:15415-16
 * parity: when peer->md5secret set, use it DIRECTLY as a1_hash bypassing
 * cleartext-secret path. md5secret takes precedence over peer->secret when
 * BOTH set (chan_sip parity); LOG_WARNING fires on dual-set ambiguity for
 * operator visibility. SHA-256 algorithm path: A1 = SHA-256(user:realm:secret)
 * (or md5secret-direct when set). out_hash buffer size: 33 chars for MD5;
 * 65 chars for SHA-256. Caller responsible for sufficient size. */
static void sofia_compute_a1_hash(struct sofia_peer *peer, const char *realm,
		int algorithm, char *out_hash)
{
	char a1_pre[256];

	/* SW11 md5secret-precedence per chan_sip.c:15415-16. NOTE: md5secret is a
	 * pre-computed MD5 hash; SHA-256 algorithm path with md5secret-set is a
	 * mismatch (md5secret WAS computed for MD5 path; chan_sofia preserves
	 * MD5-derived hash even when SHA-256 algorithm requested — this is a
	 * deliberate operator-config choice; algorithm-mismatch detection is
	 * future-fix; SS4 mirrors chan_sip md5secret-precedence verbatim).
	 *
	 * SS5 Finding #1 audit hardening: dual-set LOG_WARNING relocated to
	 * config-time at sofia_parse_peer_config + sofia_apply_peer_variables —
	 * emits ONCE at load instead of per-auth-call (was syslog spam on every
	 * REGISTER refresh / INVITE / SUBSCRIBE for peers with both fields set). */
	if (!ast_strlen_zero(peer->md5secret)) {
		ast_copy_string(out_hash, peer->md5secret, 33);
		return;
	}

	snprintf(a1_pre, sizeof(a1_pre), "%s:%s:%s",
		peer->name, realm, peer->secret);
	if (algorithm == SOFIA_DIGEST_SHA256) {
		sofia_sha256_hash(out_hash, a1_pre);
	} else {
		ast_md5_hash(out_hash, a1_pre);
	}
}

/* post-T56 Task #3 INVITE digest auth SS4 (2026-04-28, Pattern 5 helper #35
 * EXTENDED with RFC 7616 SHA-256 algorithm parameter): full digest computation
 * per RFC 2617 (MD5) or RFC 7616 (SHA-256). HA1 = sofia_compute_a1_hash(peer,
 * realm, algorithm); HA2 = hash(method:uri); response = hash(HA1:nonce:nc:
 * cnonce:qop:HA2) for qop=auth (RFC 2617) OR hash(HA1:nonce:HA2) for no-qop
 * (RFC 2069). Hash function per algorithm: MD5 (32 hex chars) or SHA-256
 * (64 hex chars). out_hash buffer size: 33 for MD5; 65 for SHA-256. */
static void sofia_compute_digest(struct sofia_peer *peer, const char *realm,
		const char *method, const char *uri,
		const char *nonce, const char *nc, const char *cnonce,
		const char *qop, int algorithm, char *out_hash)
{
	char a1_hash[65];
	char a2_pre[256];
	char a2_hash[65];
	char resp_pre[1024];

	sofia_compute_a1_hash(peer, realm, algorithm, a1_hash);
	snprintf(a2_pre, sizeof(a2_pre), "%s:%s", method, uri);
	if (algorithm == SOFIA_DIGEST_SHA256) {
		sofia_sha256_hash(a2_hash, a2_pre);
	} else {
		ast_md5_hash(a2_hash, a2_pre);
	}

	if (qop && !ast_strlen_zero(qop)) {
		snprintf(resp_pre, sizeof(resp_pre), "%s:%s:%s:%s:%s:%s",
			a1_hash, nonce, nc, cnonce, qop, a2_hash);
	} else {
		snprintf(resp_pre, sizeof(resp_pre), "%s:%s:%s",
			a1_hash, nonce, a2_hash);
	}

	if (algorithm == SOFIA_DIGEST_SHA256) {
		sofia_sha256_hash(out_hash, resp_pre);
	} else {
		ast_md5_hash(out_hash, resp_pre);
	}
}

/* post-T56 Task #3 INVITE digest auth SS2 (2026-04-28, Pattern 5 helper #34):
 * unified digest auth verifier covering REGISTER + (SS3) INVITE + SUBSCRIBE.
 * Returns enum sofia_auth_result indicating outcome. Caller dispatches sip_
 * authorization vs sip_proxy_authorization (REGISTER uses former; INVITE-via-
 * proxy uses latter per Pattern 5 helper #28 sofia_pick_auth_username precedent).
 *
 * Security hardening per parallel-audit findings:
 * - N1 realm validation: byte-exact strcmp(auth_realm, server_realm) per
 *   RFC 2617 §3.2.1 + RFC 7616 §3.2; reject 401-stale on mismatch
 * - N2 truncation rejection: sofia_au_get_unq returns NULL on overflow;
 *   reject 400 Bad Request
 * - N3 missing-uri: reject 400 if uri= absent per RFC 2617 §3.2.2
 * - SW1 timing-attack: sofia_ct_memcmp constant-time digest comparison
 * - SW2 nonce TTL: reject 401-stale if nonce_issued_at exceeds TTL
 * - SW7 nc-replay: reject 401-stale if using_qop && new_nc <= peer->last_nc
 *
 * Caller responsibility:
 * - Acquires peer ao2 ref + holds for duration of call
 * - Receives AUTH_OK → proceeds with normal flow
 * - Receives AUTH_CHALLENGE → already emitted 401 with fresh nonce; caller
 *   ao2_ref(peer, -1) and returns
 * - Receives AUTH_REJECT → already emitted 4xx; caller ao2_ref(peer, -1) and returns
 *
 * sofia_process_register refactor at SS2 — calls this helper instead of inline
 * verification at L7186-7290. SS3 INVITE wire-in calls this helper at sofia_
 * process_invite. SS5 SUBSCRIBE wire-in (if needed) calls same.
 *
 * Note: enum sofia_auth_result + forward-decl moved to L973-979 forward-decl
 * cluster (visible to sofia_process_invite at L5745) per SS3 wire-in.
 */

static enum sofia_auth_result sofia_verify_digest_auth(struct sofia_peer *peer,
		nua_t *nua, nua_handle_t *nh,
		sip_t const *sip,
		sip_authorization_t const *au,
		const char *method,
		const char *realm)
{
	char auth_realm_buf[128] = "";
	char auth_nonce_buf[128] = "";
	char auth_response_buf[128] = "";
	char auth_uri_buf[256] = "";
	char auth_nc_buf[16] = "";
	char auth_cnonce_buf[128] = "";
	char auth_qop_buf[32] = "";
	char auth_algorithm_buf[32] = "";
	const char *auth_realm;
	const char *auth_nonce;
	const char *auth_response;
	const char *auth_uri;
	const char *auth_nc;
	const char *auth_cnonce;
	const char *auth_qop;
	const char *auth_algorithm;
	int using_qop;
	unsigned int new_nc = 0;
	int algorithm = SOFIA_DIGEST_MD5;  /* RFC 2617 backward-compat default */
	int hash_len_hex;
	char expected_hash[65];  /* sized for SHA-256 (64 hex + null); MD5 uses 32+null */

	/* Challenge emission when no Authorization header is present. Offer MD5
	 * first for chan_sip/legacy-client compatibility, then SHA-256 for
	 * clients that can select the stronger RFC 7616 algorithm. */
	if (!au) {
		char nonce[64];
		char auth_header_md5[256];
		char auth_header_sha256[256];

		ast_mutex_lock(&peer->lock);
		sofia_regen_nonce_locked(peer, nonce, sizeof(nonce));
		ast_mutex_unlock(&peer->lock);

		snprintf(auth_header_sha256, sizeof(auth_header_sha256),
			"Digest realm=\"%s\", nonce=\"%s\", qop=\"auth\", algorithm=SHA-256",
			realm, nonce);
		snprintf(auth_header_md5, sizeof(auth_header_md5),
			"Digest realm=\"%s\", nonce=\"%s\", qop=\"auth\", algorithm=MD5",
			realm, nonce);

		/* SS5 Finding #2 audit hardening: per-peer algorithm offer. md5secret-
		 * only peer (no plaintext secret) cannot satisfy SHA-256 path — peer's
		 * client cannot derive matching SHA-256 HA1 from a pre-MD5-hashed
		 * secret. Omit SHA-256 from challenge offer in that case. Closes
		 * silent-403 case where md5secret peer sees SHA-256 challenge + retries
		 * with SHA-256 + fails forever. SS6 Finding #6 audit hardening:
		 * cache sofia_peer_offers_sha256 result to local int (was called twice
		 * — once for dispatch + once for sofia_debug log). */
		int offer_sha256 = sofia_peer_offers_sha256(peer);
		if (offer_sha256) {
			nua_respond(nh, SIP_401_UNAUTHORIZED,
				SIPTAG_WWW_AUTHENTICATE_STR(auth_header_md5),
				SIPTAG_WWW_AUTHENTICATE_STR(auth_header_sha256),
				NUTAG_WITH_THIS(nua),
				TAG_END());
		} else {
			nua_respond(nh, SIP_401_UNAUTHORIZED,
				SIPTAG_WWW_AUTHENTICATE_STR(auth_header_md5),
				NUTAG_WITH_THIS(nua),
				TAG_END());
		}
		if (sofia_debug) {
			ast_verbose("Sofia: Challenging %s from '%s' (nonce=%s, algorithms=%s)\n",
				method, peer->name, nonce,
				offer_sha256 ? "MD5+SHA-256" : "MD5-only");
		}
		return SOFIA_AUTH_CHALLENGE;
	}

	/* Parse all Authorization parameters. sofia_au_get_unq returns NULL on
	 * overflow per N2 audit hardening — caller rejects 400. */
	auth_realm     = sofia_au_get_unq(au, "realm",     auth_realm_buf,     sizeof(auth_realm_buf));
	auth_nonce     = sofia_au_get_unq(au, "nonce",     auth_nonce_buf,     sizeof(auth_nonce_buf));
	auth_response  = sofia_au_get_unq(au, "response",  auth_response_buf,  sizeof(auth_response_buf));
	auth_uri       = sofia_au_get_unq(au, "uri",       auth_uri_buf,       sizeof(auth_uri_buf));
	auth_nc        = sofia_au_get_unq(au, "nc",        auth_nc_buf,        sizeof(auth_nc_buf));
	auth_cnonce    = sofia_au_get_unq(au, "cnonce",    auth_cnonce_buf,    sizeof(auth_cnonce_buf));
	auth_qop       = sofia_au_get_unq(au, "qop",       auth_qop_buf,       sizeof(auth_qop_buf));
	auth_algorithm = sofia_au_get_unq(au, "algorithm", auth_algorithm_buf, sizeof(auth_algorithm_buf));

		/* N9 audit hardening: algorithm-parameter strict-parse per RFC 7616 §3.3
		 * (case-insensitive enum match). Reject 400 on unknown/unoffered algorithm.
		 * Default MD5 only when client OMITS algorithm= entirely (RFC 2617
		 * backward-compat). chan_sofia verifies MD5 and SHA-256; reject any other
		 * claimed algorithm. */
	if (auth_algorithm) {
		if (!strcasecmp(auth_algorithm, "MD5")) {
			algorithm = SOFIA_DIGEST_MD5;
		} else if (!strcasecmp(auth_algorithm, "SHA-256")) {
			algorithm = SOFIA_DIGEST_SHA256;
		} else {
			nua_respond(nh, SIP_400_BAD_REQUEST, NUTAG_WITH_THIS(nua), TAG_END());
			ast_verbose("Sofia: %s auth rejected for '%s' - unknown algorithm '%s' (server offers MD5 + SHA-256)\n",
				method, peer->name, auth_algorithm);
			sofia_blacklist_add_sip(sip, "digest unknown algorithm");
			return SOFIA_AUTH_REJECT;
		}
	}
	hash_len_hex = (algorithm == SOFIA_DIGEST_SHA256) ? 64 : 32;

	/* N3 audit hardening: reject 400 when uri= missing per RFC 2617 §3.2.2. */
	if (!auth_uri) {
		nua_respond(nh, SIP_400_BAD_REQUEST, NUTAG_WITH_THIS(nua), TAG_END());
		ast_verbose("Sofia: %s auth rejected for '%s' - uri= missing\n",
			method, peer->name);
		sofia_blacklist_add_sip(sip, "digest missing uri");
		return SOFIA_AUTH_REJECT;
	}

	/* N1 audit hardening: reject 401-stale on realm mismatch per RFC 2617
	 * §3.2.1 + RFC 7616 §3.2 (byte-exact strcmp). Multi-tenant cross-realm
	 * replay prevention. Treat missing realm as mismatch. Stale challenge
	 * uses dual-algorithm offer for client retry-with-different-algorithm. */
	if (!auth_realm || strcmp(auth_realm, realm) != 0) {
		char fresh_nonce[64];
		char auth_stale_sha256[256];
		char auth_stale_md5[256];
		ast_mutex_lock(&peer->lock);
		sofia_regen_nonce_locked(peer, fresh_nonce, sizeof(fresh_nonce));
		ast_mutex_unlock(&peer->lock);
		snprintf(auth_stale_sha256, sizeof(auth_stale_sha256),
			"Digest realm=\"%s\", nonce=\"%s\", qop=\"auth\", algorithm=SHA-256, stale=true",
			realm, fresh_nonce);
		snprintf(auth_stale_md5, sizeof(auth_stale_md5),
			"Digest realm=\"%s\", nonce=\"%s\", qop=\"auth\", algorithm=MD5, stale=true",
			realm, fresh_nonce);
		nua_respond(nh, SIP_401_UNAUTHORIZED,
			SIPTAG_WWW_AUTHENTICATE_STR(auth_stale_md5),
			SIPTAG_WWW_AUTHENTICATE_STR(auth_stale_sha256),
			NUTAG_WITH_THIS(nua),
			TAG_END());
		ast_verbose("Sofia: %s auth realm mismatch for '%s' - expected '%s' got '%s'\n",
			method, peer->name, realm, auth_realm ? auth_realm : "(none)");
		return SOFIA_AUTH_CHALLENGE;
	}

	using_qop = (auth_qop && !strcasecmp(auth_qop, "auth"));

	/* RFC 2617 §3.2.2: if qop is sent, nc and cnonce MUST also be present. */
	if (auth_qop && (!auth_nc || !auth_cnonce)) {
		nua_respond(nh, SIP_400_BAD_REQUEST, NUTAG_WITH_THIS(nua), TAG_END());
		ast_verbose("Sofia: %s auth rejected for '%s' - qop without nc/cnonce\n",
			method, peer->name);
		sofia_blacklist_add_sip(sip, "digest malformed qop");
		return SOFIA_AUTH_REJECT;
	}

	/* Parse nc as 8-hex-digit non-zero unsigned. */
	if (using_qop) {
		char *endptr = NULL;
		new_nc = (unsigned int)strtoul(auth_nc, &endptr, 16);
		if (!endptr || endptr == auth_nc || *endptr != '\0' || new_nc == 0) {
			nua_respond(nh, SIP_400_BAD_REQUEST, NUTAG_WITH_THIS(nua), TAG_END());
			ast_verbose("Sofia: %s auth rejected for '%s' - malformed nc=%s\n",
				method, peer->name, auth_nc);
			sofia_blacklist_add_sip(sip, "digest malformed nc");
			return SOFIA_AUTH_REJECT;
		}
	}

	ast_mutex_lock(&peer->lock);

	/* 4-condition need-regen: empty/mismatched nonce + TTL expiry +
	 * nc-replay (using_qop && new_nc <= peer->last_nc). */
	int need_regen = ast_strlen_zero(peer->nonce)
		|| !auth_nonce
		|| strcmp(auth_nonce, peer->nonce)
		|| (peer->nonce_issued_at && (time(NULL) - peer->nonce_issued_at) >
			(sofia_cfg.nonce_ttl_seconds > 0 ? sofia_cfg.nonce_ttl_seconds : SOFIA_NONCE_TTL_SEC_DEFAULT))
		|| (using_qop && new_nc <= peer->last_nc);

	if (need_regen) {
		char fresh_nonce[64];
		char auth_stale_sha256[256];
		char auth_stale_md5[256];
		sofia_regen_nonce_locked(peer, fresh_nonce, sizeof(fresh_nonce));
		ast_mutex_unlock(&peer->lock);
		snprintf(auth_stale_sha256, sizeof(auth_stale_sha256),
			"Digest realm=\"%s\", nonce=\"%s\", qop=\"auth\", algorithm=SHA-256, stale=true",
			realm, fresh_nonce);
		snprintf(auth_stale_md5, sizeof(auth_stale_md5),
			"Digest realm=\"%s\", nonce=\"%s\", qop=\"auth\", algorithm=MD5, stale=true",
			realm, fresh_nonce);
		nua_respond(nh, SIP_401_UNAUTHORIZED,
			SIPTAG_WWW_AUTHENTICATE_STR(auth_stale_md5),
			SIPTAG_WWW_AUTHENTICATE_STR(auth_stale_sha256),
			NUTAG_WITH_THIS(nua),
			TAG_END());
		if (sofia_debug) {
			ast_verbose("Sofia: %s auth challenge for '%s' - stale/replay; fresh nonce=%s\n",
				method, peer->name, fresh_nonce);
		}
		return SOFIA_AUTH_CHALLENGE;
	}

	/* Compute expected response. peer->lock held — peer->secret + peer->name
	 * read-side stable across the helper boundary. SS4: algorithm parameter
	 * routes through sofia_compute_digest → sofia_compute_a1_hash for MD5
	 * vs SHA-256 dispatch. */
	sofia_compute_digest(peer, realm, method, auth_uri,
		peer->nonce, auth_nc, auth_cnonce,
		using_qop ? "auth" : NULL,
		algorithm,
		expected_hash);

	/* SW1 timing-attack fix: constant-time digest comparison via Pattern 5
	 * helper #36 sofia_ct_memcmp. Was strncasecmp (vulnerable). Compare
	 * algorithm-specific hex length: 32 (MD5) or 64 (SHA-256). */
	if (!auth_response || sofia_ct_memcmp(auth_response, expected_hash, hash_len_hex) != 0) {
		ast_mutex_unlock(&peer->lock);
		nua_respond(nh, SIP_403_FORBIDDEN, NUTAG_WITH_THIS(nua), TAG_END());
		ast_verbose("Sofia: %s auth failed for '%s' - bad response\n",
			method, peer->name);
		sofia_blacklist_add_sip(sip, "digest bad response");
		return SOFIA_AUTH_REJECT;
	}

	/* Auth success — commit nonce/nc state under lock.
	 * RFC 2617 (qop=auth): keep nonce, advance last_nc.
	 * RFC 2069 (no qop): clear nonce (single-use). */
	if (using_qop) {
		peer->last_nc = new_nc;
	} else {
		ast_string_field_set(peer, nonce, "");
	}
	ast_mutex_unlock(&peer->lock);

	return SOFIA_AUTH_OK;
}

/* Caller must hold peer->lock. Generates fresh nonce, records issue time, resets nc counter.
 * post-T56 Task #3 INVITE digest auth SS2 (2026-04-28, SW2 weak-nonce fix +
 * N7 EINTR-retry hardening): now uses Pattern 5 helper #37 sofia_secure_nonce_gen
 * for /dev/urandom 128-bit nonce. Was gettimeofday-based ~20 bits effective
 * entropy (predictable wall-clock). */
static void sofia_regen_nonce_locked(struct sofia_peer *peer, char *out_buf, size_t out_len)
{
	sofia_secure_nonce_gen(out_buf, out_len);
	ast_string_field_set(peer, nonce, out_buf);
	peer->nonce_issued_at = time(NULL);
	peer->last_nc = 0;
}

/* post-T56 domainsasrealm [general] parity (2026-04-28, Pattern 5 helper #29 + chan_sofia
 * helper-architecture-advantage 15th-instance): mirror chan_sip.c:11645-11673 verbatim
 * get_realm semantic. When sofia_cfg.domainsasrealm is set + domain_list non-empty, check
 * From header domain first then To header domain; if either matches a configured domain
 * via existing func_sofia_check_sipdomain walker pattern (T46.2 work at chan_sofia.c:5552-
 * 5559), use that domain as auth realm. Falls back to sofia_cfg.realm (or "gabpbx" if
 * empty) when domainsasrealm clear OR domain_list empty OR no matching From/To domain.
 * Wired at 3 auth-challenge callsites (sofia_check_lockuseragent + sofia_send_auth_challenge
 * unknown-peer + MOH challenge). Returns const char * pointer (either pointing into
 * caller-provided buf for matched domain OR sofia_cfg.realm/"gabpbx" literal). Buffer-
 * scope discipline: caller MUST ensure buf outlives all uses of the returned pointer
 * (caller usually copies into permanent string field via snprintf into Digest header). */
static const char *sofia_get_realm_for_dialog(sip_t const *sip, char *buf, size_t buflen)
{
	const char *from_host = NULL;
	const char *to_host = NULL;

	if (!sofia_cfg.domainsasrealm || AST_LIST_EMPTY(&domain_list)) {
		return sofia_cfg.realm[0] ? sofia_cfg.realm : "gabpbx";
	}

	if (sip && sip->sip_from && sip->sip_from->a_url && sip->sip_from->a_url->url_host) {
		from_host = sip->sip_from->a_url->url_host;
	}
	if (sip && sip->sip_to && sip->sip_to->a_url && sip->sip_to->a_url->url_host) {
		to_host = sip->sip_to->a_url->url_host;
	}

	/* post-T56 allowexternaldomains retroactive-refactor (2026-04-28): use Pattern 5
	 * helper #30 sofia_check_sip_domain instead of inlined walker. */
	if (from_host && sofia_check_sip_domain(from_host)) {
		ast_copy_string(buf, from_host, buflen);
		return buf;
	}
	if (to_host && sofia_check_sip_domain(to_host)) {
		ast_copy_string(buf, to_host, buflen);
		return buf;
	}

	return sofia_cfg.realm[0] ? sofia_cfg.realm : "gabpbx";
}

/* post-T56 alwaysauthreject (2026-04-27): RFC 3261 §22.4 username-enumeration prevention
 * helper. Emits 401 Unauthorized with bogus digest challenge (nonce="empty") for
 * REGISTER from unknown peer + MWI SUBSCRIBE for unknown mailbox; attacker cannot
 * distinguish "peer exists, bad password" from "peer does not exist".
 *
 * chan_sofia surpass: also fires AMI AuthFailure event for brute-force monitoring.
 * chan_sip is silent on the same code paths — operators must grep LOG_NOTICE under
 * authpedantic. Centralized here as a single helper instead of duplicating
 * challenge+event emission at every callsite (chan_sofia helper-architecture-advantage).
 *
 * Pattern 12 honest-disclosure (framework-feature-absence): GabPBX has NO
 * EVENT_FLAG_SECURITY (manager.h:71-88 — only SYSTEM/CALL/LOG/VERBOSE/COMMAND/AGENT/
 * USER/CONFIG/DTMF/REPORTING/CDR/DIALPLAN/ORIGINATE/AGI/HOOKRESPONSE/CC/AOC/TEST).
 * Security-class events route through the dedicated ast_security_event_report() API
 * (security_events.h) which is not AMI-visible. Fallback EVENT_FLAG_SYSTEM matches
 * all existing chan_sofia AMI events (PeerStatus / Registry / RegisterIntervalRejected)
 * and is the cleanest AMI-subscribable signal for NMS brute-force detection here. */
/* post-T56 Task #3 INVITE digest auth SS5 (2026-04-28, Pattern 5 helper #39 +
 * SW5 timing-equalization fix + N10 ACL-deny-jitter audit hardening; SS6
 * Finding #5 fold-in 3-SHA-256 dummy-work parity): inject dummy HMAC
 * computation + jitter delay before reject emission. Mitigates username-
 * enumeration attacks via timing oracle on auth-fail vs ACL-deny vs unknown-
 * peer paths. Helper-level fix covers all callsites uniformly: sofia_send_
 * auth_challenge (REGISTER/SUBSCRIBE/INVITE unknown-peer) + sofia_process_
 * invite ACL-deny + sofia_process_register/subscribe ACL-deny.
 *
 * Dummy work: 3× SHA-256 hashes matching sofia_compute_a1_hash + a2 + final
 * response in real auth-fail path (Finding #5 audit hardening — symmetric
 * timing). volatile sink prevents compiler dead-code elimination. Jitter:
 * 10-50ms randomized via ast_random % 40_000us + 10_000us baseline. Both
 * layers compose for defense-in-depth.
 *
 * Pattern 14 BIDIRECTIONAL: chan_sip ABSENT — chan_sip emits 401/403 with
 * NO timing equalization (verified via grep). chan_sofia surpass dimension
 * timing-equalized-rejects-where-chan_sip-vulnerable.
 *
 * SS6 Finding #4 disclosure: usleep blocks single sofia_thread; under
 * reject-flood DoS attack, throughput limited to ~33 rejects/sec. Trade-
 * off vs username-enumeration is reasonable; operator-honest disclosure in
 * sample.conf recommends fail2ban / firewall rate-limit pairing for high-
 * volume rejection scenarios. */
static void sofia_emit_timing_equalized_reject(void)
{
	char dummy_a1[256];
	char dummy_a2[256];
	char dummy_resp[1024];
	char dummy_hash1[65];
	char dummy_hash2[65];
	char dummy_hash3[65];
	volatile char sink;

	/* SS6 Finding #5 audit hardening: 3× SHA-256 hashes match real auth path
	 * compute cost (sofia_compute_a1_hash + a2 + final). Was 1× SHA-256 at
	 * SS5 (~10-30μs asymmetry; non-material vs 10-50ms jitter window but
	 * tightened for closer parity per audit). */
	snprintf(dummy_a1, sizeof(dummy_a1),
		"sofia-timing-equalize-dummy:realm:secret-with-padding-to-match-real-a1-length");
	sofia_sha256_hash(dummy_hash1, dummy_a1);
	snprintf(dummy_a2, sizeof(dummy_a2), "INVITE:sip:dummy@example.com");
	sofia_sha256_hash(dummy_hash2, dummy_a2);
	snprintf(dummy_resp, sizeof(dummy_resp), "%s:dummy-nonce:00000001:dummy-cnonce:auth:%s",
		dummy_hash1, dummy_hash2);
	sofia_sha256_hash(dummy_hash3, dummy_resp);
	sink = dummy_hash1[0] ^ dummy_hash2[0] ^ dummy_hash3[0];  /* prevent compiler DCE */
	(void)sink;

	/* Jitter delay 10-50ms randomized — masks residual timing variance. */
	usleep((useconds_t)(10000 + (ast_random() % 40000)));
}

/* post-T56 Task #3 INVITE digest auth SS6 (2026-04-28, audit catalog item 10
 * + Finding #4 trail — WWW-Authenticate header injection prevention):
 * validate nonce + realm strings before emit. Reject if invalid characters
 * (CR/LF/quote). Per RFC 2617 quoted-string production rules: no unescaped
 * CR, LF, or quote characters allowed in nonce/realm values. chan_sofia
 * generates both via controlled paths (sofia_secure_nonce_gen produces hex-
 * only output; realm comes from sofia_cfg.realm operator config), so this
 * is defense-in-depth not a current vulnerability. Returns 1 if string is
 * safe to embed in quoted-string context; 0 if invalid. */
static int sofia_auth_str_safe(const char *s)
{
	if (!s) return 0;
	for (const char *p = s; *p; p++) {
		if (*p == '\r' || *p == '\n' || *p == '"' || *p == '\\') {
			return 0;
		}
	}
	return 1;
}

/* Determine whether the server can offer SHA-256 to a peer.
 * When peer has only md5secret + no secret, offer MD5 only (SHA-256 with
 * md5secret-pre-hash would silent-fail — peer's client cannot compute
 * matching SHA-256 HA1 from a pre-MD5-hashed secret). When peer has secret
 * (with or without md5secret), offer both algorithms. NULL peer (unknown-
 * peer challenge path) offers both algorithms for oracle parity. MD5 is
 * emitted first at challenge sites for chan_sip/legacy-client compatibility. */
static int sofia_peer_offers_sha256(struct sofia_peer *peer)
{
	if (!peer) {
		return 1;  /* unknown-peer: offer both for oracle-parity */
	}
	/* md5secret-only (no plaintext secret) → cannot derive SHA-256 HA1 */
	if (!ast_strlen_zero(peer->md5secret) && ast_strlen_zero(peer->secret)) {
		return 0;
	}
	return 1;
}

static void sofia_send_auth_challenge(nua_t *nua, nua_handle_t *nh, sip_t const *sip,
		const char *realm, const char *method, const char *reason)
{
	/* SS5 N5 audit hardening: real fresh nonce instead of literal "empty"
	 * placeholder. Defeats attacker oracle distinguishing unknown-peer
	 * (literal "empty") from known-peer (real hex nonce) responses.
	 * SS5 Finding #3 audit hardening: dual-algorithm offer (MD5 + SHA-256)
	 * mirroring sofia_verify_digest_auth pattern at 3 challenge sites. */
	char fresh_nonce[64];
	char auth_md5[256];
	char auth_sha256[256];
	struct ast_sockaddr src;
	char addr_buf[80];

	sofia_secure_nonce_gen(fresh_nonce, sizeof(fresh_nonce));

	/* SS6 audit catalog item 10 (header injection prevention) defense-in-
	 * depth: validate realm + fresh_nonce charset before WWW-Authenticate
	 * emission. realm comes from sofia_cfg.realm operator-config (controlled
	 * but defensive); fresh_nonce comes from sofia_secure_nonce_gen
	 * (hex-only output by construction). Reject pathological configs (rare
	 * but defensive). */
	if (!sofia_auth_str_safe(realm) || !sofia_auth_str_safe(fresh_nonce)) {
		ast_log(LOG_WARNING, "Sofia: refusing to emit auth challenge — "
			"unsafe characters in realm or nonce (defense-in-depth)\n");
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR,
			NUTAG_WITH_THIS(nua), TAG_END());
		return;
	}

	/* SS5 SW5+N10 timing-equalization: dummy HMAC + jitter to match known-
	 * peer-bad-password timing. Helper-level fix covers all 3 callsites
	 * (REGISTER/SUBSCRIBE/INVITE unknown-peer) uniformly. */
	sofia_emit_timing_equalized_reject();

	snprintf(auth_sha256, sizeof(auth_sha256),
		"Digest realm=\"%s\", nonce=\"%s\", qop=\"auth\", algorithm=SHA-256",
		realm, fresh_nonce);
	snprintf(auth_md5, sizeof(auth_md5),
		"Digest realm=\"%s\", nonce=\"%s\", qop=\"auth\", algorithm=MD5",
		realm, fresh_nonce);

	/* Unknown-peer challenge offers both algorithms, MD5 first for legacy clients
	 * that fail instead of skipping an unsupported first challenge. */
	nua_respond(nh, SIP_401_UNAUTHORIZED,
		SIPTAG_WWW_AUTHENTICATE_STR(auth_md5),
		SIPTAG_WWW_AUTHENTICATE_STR(auth_sha256),
		NUTAG_WITH_THIS(nua),
		TAG_END());

	sofia_get_source_addr(sip, &src);
	ast_copy_string(addr_buf, ast_sockaddr_stringify(&src), sizeof(addr_buf));

	manager_event(EVENT_FLAG_SYSTEM, "AuthFailure",
		"Peer: SIP/UNKNOWN\r\n"
		"Method: %s\r\n"
		"Reason: %s\r\n"
		"RemoteAddr: %s\r\n"
		"ChannelType: SIP\r\n",
		method ? method : "UNKNOWN",
		reason ? reason : "UnknownPeer",
		addr_buf);
}

/* post-T56 allowsubscribe AMI surpass (2026-04-27): emits SubscribeRejected event
 * at every gate-rejected SUBSCRIBE (global ban or per-peer flag). chan_sip silent
 * on these paths — chan_sofia ARCHITECTURAL ADVANTAGE for NMS subscribe-abuse
 * monitoring. Pattern 12 13th-instance EVENT_FLAG_SECURITY-absence fallback per
 * sofia_send_auth_challenge precedent: GabPBX manager.h has no EVENT_FLAG_SECURITY;
 * fallback EVENT_FLAG_SYSTEM matches existing chan_sofia AMI events. */
static void sofia_emit_subscribe_rejected(sip_t const *sip, const char *peer_name,
		const char *event, const char *reason)
{
	struct ast_sockaddr src;
	char addr_buf[80];

	sofia_get_source_addr(sip, &src);
	ast_copy_string(addr_buf, ast_sockaddr_stringify(&src), sizeof(addr_buf));

	manager_event(EVENT_FLAG_SYSTEM, "SubscribeRejected",
		"Peer: SIP/%s\r\n"
		"Event: %s\r\n"
		"Reason: %s\r\n"
		"RemoteAddr: %s\r\n"
		"ChannelType: SIP\r\n",
		peer_name ? peer_name : "UNKNOWN",
		event ? event : "(unknown)",
		reason ? reason : "AllowSubscribeClosed",
		addr_buf);
}

/* post-T56 lockuseragent per-peer parity (2026-04-27): chan_sip-parity security gate
 * at REGISTER auth-success. When peer->lockuseragent is set, locks the peer to a
 * single User-Agent string captured at first successful REGISTER; subsequent
 * REGISTERs with a different User-Agent reject via 401 silent-challenge (chan_sip-
 * faithful AUTH_SECRET_FAILED-equivalent path) + chan_sofia surpass AMI
 * LockUserAgentReject event for NMS UA-spoofing-attack visibility.
 *
 * chan_sip parity at chan_sip.c:15839-15843 verbatim ternary useragent-var-pick +
 * compare-loop. chan_sofia ARCHITECTURAL ADVANTAGE 9th-instance: centralized gate
 * helper called from BOTH sofia_process_register sites (no-secret + auth-OK) vs
 * chan_sip inline single-site at L15839 — chan_sofia's separate auth-flow paths
 * each need the gate; helper centralizes it.
 *
 * Pattern 5 helper #27 reusable. Cross-task helper reuse: sofia_send_auth_challenge
 * (#25) graduates to 3rd callsite (REGISTER unknown-peer + MWI SUBSCRIBE unknown-peer
 * + this REGISTER UA-mismatch).
 *
 * Returns 0 = PASS (caller continues), -1 = REJECT (helper has emitted 401 + AMI;
 * caller MUST ao2_ref(peer,-1) and return). */
static int sofia_check_lockuseragent(nua_t *nua, nua_handle_t *nh,
		sip_t const *sip, struct sofia_peer *peer)
{
	const char *current_ua = NULL;
	const char *realm;
	struct ast_sockaddr src;
	char addr_buf[80];
	int prefix_mode = 0;	/* 1 when lockuseragent_prefixes is non-empty — suppresses capture/anchor logic and tags rejection AMI with MatchPolicy: prefix-list */

	if (!peer->lockuseragent) {
		return 0;
	}

	if (sip && sip->sip_user_agent && sip->sip_user_agent->g_string) {
		current_ua = sip->sip_user_agent->g_string;
	}

	/* Prefix-list mode: when peer->lockuseragent_prefixes is non-empty, the
	 * operator has pre-declared which UA families may register — skip the
	 * first-REGISTER auto-capture entirely and walk the comma-separated
	 * allowlist. Any prefix that matches (case-insensitive, length of token)
	 * the inbound User-Agent passes the gate. No match falls through to the
	 * shared rejection path below with MatchPolicy: prefix-list. Tokenizing
	 * per REGISTER (a rare event vs INVITE) keeps config-load O(1) and lets
	 * `sip reload` or realtime UPDATE on the lockuseragent_prefixes column
	 * take effect on the very next REGISTER with no restart. Empty list
	 * preserves the strict capture-on-first-REGISTER behaviour verbatim
	 * (else-branch). */
	if (!ast_strlen_zero(peer->lockuseragent_prefixes)) {
		prefix_mode = 1;
		if (current_ua && current_ua[0]) {
			char *list_dup = ast_strdupa(peer->lockuseragent_prefixes);
			char *tok, *next = list_dup;
			while ((tok = strsep(&next, ","))) {
				size_t toklen;
				tok = ast_strip(tok);
				if (ast_strlen_zero(tok)) {
					continue;
				}
				toklen = strlen(tok);
				if (!strncasecmp(current_ua, tok, toklen)) {
					return 0;
				}
			}
		}
		/* No prefix matched — fall through to rejection block. */
	} else {
		/* Strict-anchor mode (chan_sip parity, behaviour preserved verbatim). */
		/* First-registration capture: empty lock-anchor + non-empty current UA.
		 * Lock under peer->lock for write race-safety vs concurrent REGISTERs. */
		if (peer->locked_user_agent[0] == '\0') {
			if (current_ua && current_ua[0]) {
				ast_mutex_lock(&peer->lock);
				ast_copy_string(peer->locked_user_agent, current_ua,
					sizeof(peer->locked_user_agent));
				ast_mutex_unlock(&peer->lock);
				ast_verbose("Sofia: lockuseragent captured \"%s\" for peer '%s'\n",
					current_ua, peer->name);
			}
			return 0;
		}

		/* Lock-anchor set: compare current UA. Match → pass; mismatch → reject. */
		if (current_ua && !strcasecmp(current_ua, peer->locked_user_agent)) {
			return 0;
		}
	}

	/* Mismatch — silent 401 challenge (chan_sip-faithful AUTH_SECRET_FAILED-
	 * equivalent path; attacker cannot distinguish UA-mismatch from bad-secret) +
	 * AMI LockUserAgentReject for NMS visibility (chan_sofia surpass).
	 * post-T56 domainsasrealm wire-in (2026-04-28): Pattern 5 helper #29
	 * sofia_get_realm_for_dialog returns From/To-domain match if domainsasrealm
	 * set + domain_list non-empty; falls back to sofia_cfg.realm. */
	{
		char realm_buf[MAXHOSTNAMELEN];
		realm = sofia_get_realm_for_dialog(sip, realm_buf, sizeof(realm_buf));
		sofia_send_auth_challenge(nua, nh, sip, realm, "REGISTER", "UserAgentMismatch");
	}

	sofia_get_source_addr(sip, &src);
	ast_copy_string(addr_buf, ast_sockaddr_stringify(&src), sizeof(addr_buf));

	manager_event(EVENT_FLAG_SYSTEM, "LockUserAgentReject",
		"Peer: SIP/%s\r\n"
		"MatchPolicy: %s\r\n"
		"LockedUserAgent: %s\r\n"
		"Prefixes: %s\r\n"
		"AttemptedUserAgent: %s\r\n"
		"RemoteAddr: %s\r\n"
		"ChannelType: SIP\r\n",
		peer->name,
		prefix_mode ? "prefix-list" : "strict-anchor",
		peer->locked_user_agent,
		prefix_mode ? peer->lockuseragent_prefixes : "",
		current_ua ? current_ua : "",
		addr_buf);

	if (prefix_mode) {
		ast_log(LOG_NOTICE,
			"Sofia: REGISTER from peer '%s' rejected — User-Agent \"%s\" "
			"does not match any prefix in lockuseragent_prefixes=\"%s\"\n",
			peer->name,
			current_ua ? current_ua : "(none)",
			peer->lockuseragent_prefixes);
	} else {
		ast_log(LOG_NOTICE,
			"Sofia: REGISTER from peer '%s' rejected — lockuseragent mismatch "
			"(locked=\"%s\", attempted=\"%s\")\n",
			peer->name, peer->locked_user_agent,
			current_ua ? current_ua : "(none)");
	}

	return -1;
}

static void sofia_process_register(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	const char *user = NULL;
	const char *domain = NULL;
	struct sofia_peer *peer;
	char realm_buf[MAXHOSTNAMELEN];
	const char *realm;
	struct sofia_register_update reg_update;

	if (!sip || !sip->sip_from) {
		nua_respond(nh, SIP_400_BAD_REQUEST, TAG_END());
		return;
	}
	/* post-T56 domainsasrealm wire-in (2026-04-28): Pattern 5 helper #29
	 * sofia_get_realm_for_dialog returns From/To-domain match if domainsasrealm
	 * set + domain_list non-empty; falls back to sofia_cfg.realm. */
	realm = sofia_get_realm_for_dialog(sip, realm_buf, sizeof(realm_buf));

	user = sip->sip_from->a_url->url_user;
	domain = sip->sip_from->a_url->url_host;

	if (sofia_debug) {
		ast_verbose("Sofia: REGISTER from %s@%s\n",
			user ? user : "(null)", domain ? domain : "(null)");
	}

	if (!user) {
		char auth_empty[256];
		snprintf(auth_empty, sizeof(auth_empty),
			"Digest realm=\"%s\", nonce=\"empty\", qop=\"auth\", algorithm=MD5", realm);
		nua_respond(nh, SIP_401_UNAUTHORIZED,
			SIPTAG_WWW_AUTHENTICATE_STR(auth_empty),
			TAG_END());
		sofia_blacklist_add_sip(sip, "REGISTER missing user");
		return;
	}

	/* post-T56 match_auth_username [general] parity (2026-04-28): chan_sip parity
	 * at chan_sip.c:17258 verbatim — when set, override peer-lookup search-key
	 * with Authorization-username (or Proxy-Authorization fallback). Pattern 5
	 * helper #28 sofia_pick_auth_username. Buffer at function scope so the
	 * returned pointer (into buf when auth-username found) stays valid for
	 * downstream sofia_find_peer + diagnostic uses of user. */
	char auth_user_buf[128];
	if (sofia_cfg.match_auth_username) {
		user = sofia_pick_auth_username(sip, user, auth_user_buf, sizeof(auth_user_buf));
	}

	peer = sofia_find_peer(user);
	if (!peer) {
		if (sofia_cfg.alwaysauthreject) {
			sofia_send_auth_challenge(nua, nh, sip, realm, "REGISTER", "UnknownPeer");
			ast_verbose("Sofia: REGISTER from unknown peer '%s' — 401 challenge (alwaysauthreject)\n", user);
		} else {
			nua_respond(nh, SIP_403_FORBIDDEN, TAG_END());
			ast_verbose("Sofia: Registration rejected for unknown peer '%s'\n", user);
		}
		sofia_blacklist_add_sip(sip, "REGISTER unknown peer");
		return;
	}

	/* Per-peer ACL check (permit/deny) — applied BEFORE auth so a banned IP cannot
	 * even probe for valid credentials. */
	if (peer->ha) {
		struct ast_sockaddr src;
		sofia_get_source_addr(sip, &src);
		if (ast_apply_ha(peer->ha, &src) != AST_SENSE_ALLOW) {
			ast_log(LOG_NOTICE, "Sofia: REGISTER from %s rejected by peer '%s' ACL\n",
				ast_sockaddr_stringify(&src), peer->name);
			nua_respond(nh, SIP_403_FORBIDDEN,
				NUTAG_WITH_THIS(nua), TAG_END());
			sofia_blacklist_add_sip(sip, "REGISTER peer ACL reject");
			ao2_ref(peer, -1);
			return;
		}
	}

	/* If peer has no secret, accept without auth */
	if (ast_strlen_zero(peer->secret)) {
		int expires = sip->sip_expires ? sip->sip_expires->ex_delta : DEFAULT_EXPIRY;
		/* post-T56 registration TTL bounds + 423 Interval Too Brief parity (2026-04-27):
		 * chan_sip parity at chan_sip.c:25699-25702 — bounds check BEFORE
		 * sofia_update_peer_contacts. Helper emits 423 + Min-Expires + AMI on reject
		 * (caller MUST return immediately). */
		if (sofia_check_register_expiry(nua, nh, peer, &expires) < 0) {
			ao2_ref(peer, -1);
			return;
		}
		/* post-T56 lockuseragent gate (2026-04-27): chan_sip parity at chan_sip.c:15839
		 * placement (post-auth-success, pre-contact-update). no-secret path wire-in. */
		if (sofia_check_lockuseragent(nua, nh, sip, peer) < 0) {
			sofia_blacklist_add_sip(sip, "REGISTER user-agent lock reject");
			ao2_ref(peer, -1);
			return;
		}
		ast_mutex_lock(&peer->lock);
		int rc = sofia_update_peer_contacts(peer, sip, expires, &reg_update);
		ast_mutex_unlock(&peer->lock);
		if (rc < 0) {
			ast_verbose("Sofia: REGISTER from peer '%s' rejected with 403 \xe2\x80\x94 too many registered devices (limit=%d)\n",
				peer->name, peer->max_contacts);
			nua_respond(nh, SIP_403_FORBIDDEN,
				NUTAG_WITH_THIS(nua),
				TAG_END());
			ao2_ref(peer, -1);
			return;
		}
		/* post-T56 rtupdate [general] parity (2026-04-28, Option C combined-gate per
		 * Enginer R6 verdict): chan_sip parity at chan_sip.c:14630+L14743 verbatim
		 * combined-gate pattern. rtupdate=no skips ALL realtime DB writes. */
		if (peer->is_realtime && sofia_cfg.peer_rtupdate) {
			/* post-T56 rtsavesysname [general] parity (2026-04-28): inline 2-var setup
			 * mirroring chan_sip.c.bk:5103-5151 canonical realtime_update_peer pattern.
			 * NULL-key pair appended to ast_update_realtime varargs = no-op when
			 * sofia_cfg.rtsave_sysname clear OR AST_SYSTEM_NAME empty. */
			const char *sysname = ast_config_AST_SYSTEM_NAME;
			const char *syslabel = NULL;
			if (ast_strlen_zero(sysname)) {
				sysname = NULL;
			} else if (sofia_cfg.rtsave_sysname) {
				syslabel = "regserver";
			}
			if (peer->registered) {
				char port_str[32], regsec_str[32];
				const char *contact_str = sip->sip_contact ?
					sip->sip_contact->m_url->url_host : "";
				snprintf(port_str, sizeof(port_str), "%d",
					ast_sockaddr_port(&peer->src_addr));
				snprintf(regsec_str, sizeof(regsec_str), "%ld",
					(long)time(NULL));
				ast_update_realtime(ast_check_realtime("sipregs") ? "sipregs" : "sippeers", "name", peer->name,
					"ipaddr", ast_sockaddr_stringify_host(&peer->src_addr),
					"port", port_str,
					"regseconds", regsec_str,
					"fullcontact", contact_str,
					syslabel, sysname,
					SENTINEL);
			} else {
				ast_update_realtime(ast_check_realtime("sipregs") ? "sipregs" : "sippeers", "name", peer->name,
					"ipaddr", "",
					"regseconds", "0",
					"fullcontact", "",
					syslabel, sysname,
					SENTINEL);
			}
		}
		nua_respond(nh, SIP_200_OK,
			SIPTAG_CONTACT(sip->sip_contact),
			NUTAG_WITH_THIS(nua),
			TAG_END());
		sofia_verbose_register_update(peer, &reg_update);
		ao2_ref(peer, -1);
		return;
	}

	/* post-T56 Task #3 INVITE digest auth SS2 (2026-04-28): unified digest
	 * verification via Pattern 5 helper #34 sofia_verify_digest_auth. Replaces
	 * inline 100-line block with single helper call. Helper handles challenge
	 * emission (no Authorization header) + 401-stale + 403 + AUTH_OK paths +
	 * SW1 timing-attack fix (sofia_ct_memcmp) + SW2 weak-nonce fix (sofia_
	 * secure_nonce_gen) + N1 realm-validation + N2 truncation rejection +
	 * N3 missing-uri rejection. REGISTER + future INVITE + SUBSCRIBE share
	 * the same verifier — chan_sofia helper-architecture-advantage NEW DIMENSION
	 * centralized-multi-method-auth. */
	{
		enum sofia_auth_result auth_res = sofia_verify_digest_auth(peer,
			nua, nh, sip, sip->sip_authorization, "REGISTER", realm);
		if (auth_res != SOFIA_AUTH_OK) {
			ao2_ref(peer, -1);
			return;
		}
	}

	{
			int expires = sip->sip_expires ? sip->sip_expires->ex_delta : DEFAULT_EXPIRY;
			/* post-T56 registration TTL bounds + 423 Interval Too Brief parity (2026-04-27):
			 * second wire-in site (auth-OK path). Helper emits 423 + Min-Expires + AMI
			 * on reject (caller MUST return immediately). */
			if (sofia_check_register_expiry(nua, nh, peer, &expires) < 0) {
				ao2_ref(peer, -1);
				return;
			}
			/* post-T56 lockuseragent gate (2026-04-27): chan_sip parity at chan_sip.c:15839
			 * placement (post-auth-success, pre-contact-update). auth-OK path wire-in. */
			if (sofia_check_lockuseragent(nua, nh, sip, peer) < 0) {
				sofia_blacklist_add_sip(sip, "REGISTER user-agent lock reject");
				ao2_ref(peer, -1);
				return;
			}
			ast_mutex_lock(&peer->lock);
			int rc = sofia_update_peer_contacts(peer, sip, expires, &reg_update);
			ast_mutex_unlock(&peer->lock);
			if (rc < 0) {
				ast_verbose("Sofia: REGISTER from peer '%s' rejected with 403 \xe2\x80\x94 too many registered devices (limit=%d)\n",
					peer->name, peer->max_contacts);
				nua_respond(nh, SIP_403_FORBIDDEN,
					NUTAG_WITH_THIS(nua),
					TAG_END());
				ao2_ref(peer, -1);
				return;
			}
		}

		/* post-T56 rtupdate [general] parity (2026-04-28, Option C combined-gate per
		 * Enginer R6 verdict): auth-OK path realtime updates gated by combined check. */
		if (peer->is_realtime && sofia_cfg.peer_rtupdate) {
			/* post-T56 rtsavesysname [general] parity (2026-04-28): inline 2-var setup
			 * mirroring chan_sip.c.bk:5103-5151 canonical realtime_update_peer pattern. */
			const char *sysname = ast_config_AST_SYSTEM_NAME;
			const char *syslabel = NULL;
			if (ast_strlen_zero(sysname)) {
				sysname = NULL;
			} else if (sofia_cfg.rtsave_sysname) {
				syslabel = "regserver";
			}
			if (peer->registered) {
				char port_str[32], regsec_str[32];
				const char *contact_str = sip->sip_contact ?
					sip->sip_contact->m_url->url_host : "";
				snprintf(port_str, sizeof(port_str), "%d",
					ast_sockaddr_port(&peer->src_addr));
				snprintf(regsec_str, sizeof(regsec_str), "%ld",
					(long)time(NULL));
				ast_update_realtime(ast_check_realtime("sipregs") ? "sipregs" : "sippeers", "name", peer->name,
					"ipaddr", ast_sockaddr_stringify_host(&peer->src_addr),
					"port", port_str,
					"regseconds", regsec_str,
					"fullcontact", contact_str,
					syslabel, sysname,
					SENTINEL);
			} else {
				ast_update_realtime(ast_check_realtime("sipregs") ? "sipregs" : "sippeers", "name", peer->name,
					"ipaddr", "",
					"regseconds", "0",
					"fullcontact", "",
					syslabel, sysname,
					SENTINEL);
			}
		}

		nua_respond(nh, SIP_200_OK,
			SIPTAG_CONTACT(sip->sip_contact),
			NUTAG_WITH_THIS(nua),
			TAG_END());
		sofia_verbose_register_update(peer, &reg_update);
		/* post-T56 regexten parity (2026-04-27): auto-add dialplan extension on
		 * REGISTER success (chan_sip parity). No-op if sofia_cfg.regcontext empty. */
		register_peer_exten(peer, 1);
		manager_event(EVENT_FLAG_SYSTEM, "PeerStatus",
			"ChannelType: SIP\r\n"
			"Peer: SIP/%s\r\n"
			"PeerStatus: Registered\r\n"
			"Address: %s\r\n"
			"RegContact: %s\r\n"
			"UserAgent: %s\r\n"
			"Context: %s\r\n",
			peer->name,
			ast_sockaddr_stringify(&peer->src_addr),
			(sip && sip->sip_contact && sip->sip_contact->m_url->url_host) ?
				sip->sip_contact->m_url->url_host : "",
			(sip && sip->sip_user_agent && sip->sip_user_agent->g_string) ?
				sip->sip_user_agent->g_string : "",
			peer->context);
		ao2_ref(peer, -1);
}

/* post-T56 SIP MESSAGE parity (2026-04-27): inbound MESSAGE handler.
 * Mirrors chan_sip receive_message at chan_sip.c:17350-17399 with R1+R8
 * Content-Type strcasecmp full-match refinement (RFC 3261 §7.3.1
 * compliance + sofia-sip-tokenized c_type cleaner than chan_sip's raw
 * get_header line — fixes 2 chan_sip bugs: case-sensitive strncmp +
 * 10-char prefix-truncation that mis-accepts "text/plainXYZ").
 *
 * In-dialog (op->owner): queue AST_FRAME_TEXT + 202 Accepted (chan_sip
 * L17380-17392 parity). Out-of-dialog: 405 Method Not Allowed +
 * LOG_WARNING (chan_sip L17395-17398 parity). */
static void sofia_process_message(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	char buf[1400];
	const char *body = NULL;
	char *bufp;
	struct ast_frame f;

	/* R1+R8 Content-Type validation: text/plain only (case-insensitive
	 * full-match per RFC 3261 §7.3.1; sofia-sip strips ;params at
	 * tokenization time so c_type is the canonical type/subtype only). */
	if (!sip || !sip->sip_content_type || !sip->sip_content_type->c_type
			|| strcasecmp(sip->sip_content_type->c_type, "text/plain")) {
		nua_respond(nh, 415, "Unsupported Media Type",
			NUTAG_WITH_THIS(nua), TAG_END());
		return;
	}

	if (sip->sip_payload && sip->sip_payload->pl_data) {
		body = sip->sip_payload->pl_data;
	}
	if (!body) {
		nua_respond(nh, 500, "Internal Server Error",
			NUTAG_WITH_THIS(nua), TAG_END());
		return;
	}
	ast_copy_string(buf, body, sizeof(buf));

	/* R4 trailing-LF strip (chan_sip L17374-17378 parity). */
	bufp = buf + strlen(buf);
	while (--bufp >= buf && *bufp == '\n') {
		*bufp = '\0';
	}

	/* R2 in-dialog vs out-of-dialog dispatch */
	if (op && op->owner) {
		if (sofia_debug) {
			ast_verbose("Sofia: in-call MESSAGE received: '%s'\n", buf);
		}
		/* R3 AST_FRAME_TEXT queue (chan_sip L17383-17389 parity) */
		memset(&f, 0, sizeof(f));
		f.frametype = AST_FRAME_TEXT;
		f.subclass.integer = 0;
		f.offset = 0;
		f.data.ptr = buf;
		f.datalen = strlen(buf) + 1;
		ast_queue_frame(op->owner, &f);
		nua_respond(nh, 202, "Accepted", NUTAG_WITH_THIS(nua), TAG_END());
		return;
	}

	/* Out-of-dialog: chan_sip parity 405 + LOG_WARNING (chan_sip L17395-17398). */
	ast_log(LOG_WARNING, "Sofia: out-of-dialog MESSAGE dropped (no active call). "
		"Content-Type: %s, Body: '%s'\n",
		sip->sip_content_type->c_type, buf);
	nua_respond(nh, 405, "Method Not Allowed", NUTAG_WITH_THIS(nua), TAG_END());
}

/* post-T56 outbound-headers parity (2026-04-27): resolve the source IP we will
 * present to `target` for outbound INVITE From + Contact + SDP c= line. Mirrors
 * chan_sip ast_sip_ouraddrfor (chan_sip.c:3988-4080):
 *   - kernel routing query (ast_ouraddrfor) gives the OS-chosen source IP for
 *     reaching `target` — closes the bindaddr=0.0.0.0 case
 *   - if sofia_should_use_externaddr(target) → substitute sofia_cfg.externaddr
 *     (NAT remap; same helper reused from L508 — zero new helper for the decision)
 *   - port defaults to sofia_cfg.bindport if unset
 *
 * On entry: target points to the peer's reachable sockaddr (src_addr if
 * registered+dynamic, else constructed from peer->host:port).
 * On exit: pvt->ourip is fully populated (host + port).
 *
 * Inbound flows: not called. pvt->ourip stays zero-initialized; sofia_generate_sdp
 * R5 fallback chain handles the unset case via getsockname() on rtp fd. */
static void sofia_resolve_ourip(struct sofia_pvt *pvt, const struct ast_sockaddr *target)
{
	if (!pvt || !target) {
		return;
	}

	/* post-T56 NAT parity fill (2026-04-27) R6: lazy-refresh externhost when
	 * DDNS deadline expired. Mirrors chan_sip lazy-refresh at chan_sip.c:4026-4031.
	 * Re-resolves externhost into externaddr + bumps externexpire. Single re-resolve
	 * site per R6 — sofia_should_use_externaddr + sofia_generate_sdp downstream
	 * consumers read sofia_cfg.externaddr (resolved IP) so refresh transparently
	 * propagates without their code change. */
	if (sofia_cfg.externexpire && time(NULL) >= sofia_cfg.externexpire
			&& !ast_strlen_zero(sofia_cfg.externhost)) {
		struct ast_sockaddr *addrs = NULL;
		/* Step A IPv6 parity SS4 (2026-04-28, SS1.5 N1 LOAD-BEARING fix):
		 * AST_AF_INET → AST_AF_UNSPEC for dual-stack DNS resolution. Operator
		 * setting externhost=ipv6.example.com (AAAA-only) was silently failing
		 * pre-fix because AST_AF_INET hint excluded AAAA records — externaddr
		 * stayed empty + NAT rewrite never fired. AST_AF_UNSPEC accepts both
		 * A + AAAA records; first result captured into externaddr per RFC 6724
		 * source-address-selection (resolver-policy preferred family). chan_sip
		 * parity at chan_sip.c:4027 uses ast_sockaddr_resolve_first family=0
		 * (equivalent dual-stack semantic). */
		int addrs_cnt = ast_sockaddr_resolve(&addrs, sofia_cfg.externhost, 0, AST_AF_UNSPEC);
		if (addrs_cnt > 0) {
			ast_copy_string(sofia_cfg.externaddr,
				ast_sockaddr_stringify_host(&addrs[0]),
				sizeof(sofia_cfg.externaddr));
		} else {
			ast_log(LOG_NOTICE, "Sofia: re-lookup of externhost '%s' failed; keeping stale externaddr\n",
				sofia_cfg.externhost);
		}
		if (addrs) {
			ast_free(addrs);
		}
		sofia_cfg.externexpire = time(NULL) + (sofia_cfg.externrefresh > 0 ? sofia_cfg.externrefresh : 10);
	}

	memset(&pvt->ourip, 0, sizeof(pvt->ourip));
	if (ast_ouraddrfor(target, &pvt->ourip) != 0) {
		/* Kernel route query failed (target not reachable yet?) — fall back to
		 * sofia_cfg.bindaddr; better than 0.0.0.0 in the wire output. */
		ast_sockaddr_parse(&pvt->ourip, sofia_cfg.bindaddr, PARSE_PORT_FORBID);
	}
	if (sofia_should_use_externaddr(target)
			&& !ast_strlen_zero(sofia_cfg.externaddr)) {
		ast_sockaddr_parse(&pvt->ourip, sofia_cfg.externaddr, PARSE_PORT_FORBID);

		/* post-T56 NAT parity fill (2026-04-27) R4+R5: per-transport external
		 * port substitution. Mirrors chan_sip L4034-4052 switch on transport.
		 * UDP keeps externaddr port (or bindport fallback below). TCP/WS use
		 * externtcpport (with externaddr-port fallback when externtcpport==0).
		 * TLS/WSS use externtlsport.
		 *
		 * NOTE: since the per-peer transport= parsers now silent-accept without
		 * writing peer->transport (the field stays at the SOFIA_TRANSPORT_UDP
		 * init from sofia_peer_alloc), the TCP/TLS branches below are
		 * unreachable for normally-configured peers. Kept structurally so the
		 * switch + SOFIA_TRANSPORT_* enum remain available for the listener-
		 * level paths. For static TCP/TLS peers that previously relied on
		 * externtcpport/externtlsport substitution here, set the listener port
		 * explicitly via port=<listener-port> or use a dedicated TLS-only
		 * listener profile. */
		if (pvt->peer) {
			switch (pvt->peer->transport) {
			case SOFIA_TRANSPORT_TCP:
				if (sofia_cfg.externtcpport) {
					ast_sockaddr_set_port(&pvt->ourip, sofia_cfg.externtcpport);
				} else if (ast_sockaddr_port(&pvt->ourip)) {
					/* externtcpport unset + externaddr has port — keep externaddr port */
				}
				break;
			case SOFIA_TRANSPORT_TLS:
				if (sofia_cfg.externtlsport) {
					ast_sockaddr_set_port(&pvt->ourip, sofia_cfg.externtlsport);
				}
				break;
			case SOFIA_TRANSPORT_UDP:
			default:
				/* UDP keeps externaddr port; bindport fallback below if 0 */
				break;
			}
		}
	}
	if (ast_sockaddr_port(&pvt->ourip) == 0) {
		ast_sockaddr_set_port(&pvt->ourip,
			sofia_cfg.bindport ? sofia_cfg.bindport : 5060);
	}
}

/* post-T56 outbound-headers parity (2026-04-27): build outbound INVITE From
 * header URI. Mirrors chan_sip initreqprep at chan_sip.c:12822-12910 + cid
 * resolution at chan_sip.c:11759-11767.
 *
 * - Reads pvt->owner->connected.id.number.str + connected.id.name.str
 *   (NOT cid.cid_num/cid_name directly; chan_sip parity — connected.id is the
 *   "who is initiating from-our-side" identity that mod_futurepbx + gabpbx core
 *   populate via ast_set_callerid).
 * - Privacy honoring: ast_party_id_presentation(&pvt->owner->connected.id);
 *   if AST_PRES_RESTRICTION → l="anonymous", n="" (chan_sip L11780 pattern).
 * - Fallback chain: connected.id missing → peer->fromuser → peer->name → "asterisk".
 * - URI-encoding: ast_uri_encode the user-part — required for # / ? / @ / etc.
 *   (post-T56 dial-atpeer fix exposed exten#did@peer form like 9999#622501314).
 * - Tag: NEVER add ;tag= manually — sofia-sip nua layer auto-emits the From-tag
 *   as part of dialog state. Format: "\"%s\" <sip:%s@%s>" (no tag). */
static void sofia_build_from(struct sofia_pvt *pvt, char *buf, size_t len)
{
	char *lid_num = NULL, *lid_name = NULL;
	int lid_pres;
	char fromdomain[128];

	if (!buf || len < 1) {
		return;
	}
	buf[0] = '\0';

	/* post-T56 identity-headers parity SS2 R12 (2026-04-27): identity resolution
	 * + URI-encode + fromdomain delegated to sofia_resolve_identity (DRY shared
	 * with sofia_add_rpid). R8 refinement: presentation source now prefers
	 * pvt->callingpres (set by R8/R10 sofia_call pickup or SS4 inbound parser)
	 * over connected.id direct read. */
	/* Step A IPv6 parity SS3 (2026-04-28): bracket-wrap IPv6 fromdomain
	 * per RFC 3261 §19.1.2. Operator may set fromdomain=2001:db8::1 (raw IPv6
	 * literal) — helper #45 wraps; IPv4 + hostname passthrough; idempotent. */
	char fbuf[80];
	if (sofia_resolve_identity(pvt, &lid_num, &lid_name, &lid_pres,
			fromdomain, sizeof(fromdomain)) < 0) {
		/* No identity available — degrade to bare anonymous so downstream still
		 * has a syntactically valid From URI. */
		snprintf(buf, len, "\"Anonymous\" <sip:anonymous@%s>",
			sofia_uri_format_host(
				!ast_strlen_zero(sofia_cfg.realm) ? sofia_cfg.realm : "gabpbx",
				fbuf, sizeof(fbuf)));
		return;
	}

	/* Privacy honoring (chan_sip L11780 pattern preserved here, post-helper):
	 * if presentation restricts the number, From identity becomes anonymous. */
	if ((lid_pres & AST_PRES_RESTRICTION) != AST_PRES_ALLOWED) {
		snprintf(buf, len, "\"Anonymous\" <sip:anonymous@%s>",
			sofia_uri_format_host(fromdomain, fbuf, sizeof(fbuf)));
		return;
	}

	/* post-T56 usereqphone parity (2026-04-27): RFC 3966 ;user=phone parameter on
	 * From URI when peer has usereqphone set AND lid_num matches digit-only pattern.
	 * chan_sofia ARCHITECTURAL ADVANTAGE — single sofia_build_from helper site
	 * catches all 5 callers (sofia_call SDP/no-SDP + 2 fork-children + post-T56
	 * outbound-headers parity sites). Mirror chan_sip.c:12836-12853 digit-pattern
	 * applied to From URI. */
	if (pvt && pvt->peer && pvt->peer->usereqphone && sofia_user_looks_like_phone(lid_num)) {
		snprintf(buf, len, "\"%s\" <sip:%s@%s;user=phone>", lid_name, lid_num,
			sofia_uri_format_host(fromdomain, fbuf, sizeof(fbuf)));
	} else {
		snprintf(buf, len, "\"%s\" <sip:%s@%s>", lid_name, lid_num,
			sofia_uri_format_host(fromdomain, fbuf, sizeof(fbuf)));
	}
}

/* post-T56 outbound-headers parity (2026-04-27): build outbound Contact header.
 * Mirrors chan_sip build_contact at chan_sip.c:12807-12820.
 *
 * - User-part fallback: connected.id.number.str → peer->fromuser → peer->name → "asterisk".
 * - Host:port from pvt->ourip (resolved by sofia_resolve_ourip).
 * - URI-encode the user-part (R9; same rationale as sofia_build_from).
 * - Format: <sip:user@host:port> angle-bracketed per RFC 3261 §8.1.1.8. */
static void sofia_build_contact(struct sofia_pvt *pvt, char *buf, size_t len)
{
	const char *user = NULL;
	char encoded_user[160];
	char host_port[128];

	if (!buf || len < 1) {
		return;
	}
	buf[0] = '\0';

	if (pvt && pvt->owner
			&& pvt->owner->connected.id.number.valid
			&& !ast_strlen_zero(pvt->owner->connected.id.number.str)) {
		user = pvt->owner->connected.id.number.str;
	}
	if (ast_strlen_zero(user) && pvt && pvt->peer) {
		if (!ast_strlen_zero(pvt->peer->fromuser)) {
			user = pvt->peer->fromuser;
		} else if (!ast_strlen_zero(pvt->peer->name)) {
			user = pvt->peer->name;
		}
	}
	if (ast_strlen_zero(user)) {
		user = "asterisk";
	}

	ast_uri_encode(user, encoded_user, sizeof(encoded_user), 0);

	if (pvt && !ast_sockaddr_isnull(&pvt->ourip)) {
		ast_copy_string(host_port, ast_sockaddr_stringify(&pvt->ourip),
			sizeof(host_port));
	} else {
		snprintf(host_port, sizeof(host_port), "%s:%d",
			!ast_strlen_zero(sofia_cfg.bindaddr) ? sofia_cfg.bindaddr : "127.0.0.1",
			sofia_cfg.bindport ? sofia_cfg.bindport : 5060);
	}

	snprintf(buf, len, "<sip:%s@%s>", encoded_user, host_port);
}

/* post-T56 identity-headers parity SS2 (2026-04-27): single source of truth
 * for outbound identity-resolution chain shared by sofia_build_from
 * (post-ebd26fe refactor) and sofia_add_rpid. Reads pvt->owner->connected.id
 * (chan_sip parity at chan_sip.c:11759-11767), applies fallback chain
 * (peer->fromuser → peer->name → "asterisk"), URI-encodes user-part, resolves
 * fromdomain (peer->fromdomain → ourip host → sofia_cfg.realm → "gabpbx").
 *
 * On entry: out-pointer params receive pointers into the helper's thread-local
 * scratch (caller copies before next call); fromdomain_buf is caller-provided.
 * Returns: 0 on success, -1 on no-identity-available.
 *
 * Thread-local scratch is safe because each outbound INVITE site (sofia_call,
 * fork-child loop body, sofia_build_from, sofia_add_rpid) runs to completion
 * on the same thread before another can re-enter.
 *
 * Presentation source: prefers pvt->callingpres if non-zero (set by SS2 R8
 * sofia_call pickup or R10 peer override or SS4 inbound PAI/RPID parser);
 * falls back to ast_party_id_presentation(connected.id). */
static int sofia_resolve_identity(struct sofia_pvt *pvt, char **lid_num_out,
                                   char **lid_name_out, int *lid_pres_out,
                                   char *fromdomain_buf, size_t fromdomain_len)
{
	static __thread char lid_num_buf[128];
	static __thread char lid_name_buf[128];
	const char *lid_num_src = NULL;
	const char *lid_name_src = NULL;
	int lid_pres = AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED;

	if (!lid_num_out || !lid_name_out || !lid_pres_out
			|| !fromdomain_buf || fromdomain_len < 2) {
		return -1;
	}

	if (pvt && pvt->owner && pvt->owner->connected.id.number.valid
			&& !ast_strlen_zero(pvt->owner->connected.id.number.str)) {
		lid_num_src = pvt->owner->connected.id.number.str;
	}
	if (pvt && pvt->owner && pvt->owner->connected.id.name.valid
			&& !ast_strlen_zero(pvt->owner->connected.id.name.str)) {
		lid_name_src = pvt->owner->connected.id.name.str;
	}

	if (pvt && pvt->callingpres) {
		lid_pres = pvt->callingpres;
	} else if (pvt && pvt->owner) {
		lid_pres = ast_party_id_presentation(&pvt->owner->connected.id);
	}

	if (ast_strlen_zero(lid_num_src) && pvt && pvt->peer) {
		/* post-T56 cid bundle parity (2026-04-28): chan_sip-verbatim Option 6-B
		 * dialog-inheritance semantic per chan_sip.c:5957 — peer->cid_num is
		 * base/default when channel connected.id empty; channel CID via dialplan
		 * CALLERID() overrides this when set (above branch at L6151). Fallback
		 * chain: connected.id → peer->cid_num → peer->fromuser → peer->name → "asterisk". */
		if (!ast_strlen_zero(pvt->peer->cid_num)) {
			lid_num_src = pvt->peer->cid_num;
		} else if (!ast_strlen_zero(pvt->peer->fromuser)) {
			lid_num_src = pvt->peer->fromuser;
		} else if (!ast_strlen_zero(pvt->peer->name)) {
			lid_num_src = pvt->peer->name;
		} else {
			lid_num_src = "asterisk";
		}
	}
	if (ast_strlen_zero(lid_num_src)) {
		lid_num_src = "asterisk";
	}
	/* post-T56 cid bundle parity (2026-04-28): chan_sip-verbatim Option 6-B —
	 * peer->cid_name fallback before lid_num_src copy (matches L5958 dialog-
	 * inheritance for cid_name field). */
	if (ast_strlen_zero(lid_name_src) && pvt && pvt->peer
			&& !ast_strlen_zero(pvt->peer->cid_name)) {
		lid_name_src = pvt->peer->cid_name;
	}
	if (ast_strlen_zero(lid_name_src)) {
		lid_name_src = lid_num_src;
	}

	ast_uri_encode(lid_num_src, lid_num_buf, sizeof(lid_num_buf), 0);
	ast_copy_string(lid_name_buf, lid_name_src, sizeof(lid_name_buf));

	*lid_num_out = lid_num_buf;
	*lid_name_out = lid_name_buf;
	*lid_pres_out = lid_pres;

	if (pvt && pvt->peer && !ast_strlen_zero(pvt->peer->fromdomain)) {
		ast_copy_string(fromdomain_buf, pvt->peer->fromdomain, fromdomain_len);
	} else if (pvt && !ast_sockaddr_isnull(&pvt->ourip)) {
		ast_copy_string(fromdomain_buf,
			ast_sockaddr_stringify_host(&pvt->ourip), fromdomain_len);
	} else if (!ast_strlen_zero(sofia_cfg.realm)) {
		ast_copy_string(fromdomain_buf, sofia_cfg.realm, fromdomain_len);
	} else {
		ast_copy_string(fromdomain_buf, "gabpbx", fromdomain_len);
	}

	return 0;
}

/* post-T56 identity-headers parity SS2 + R11 revised (2026-04-27): outbound
 * RPID/PAI emitter with Privacy: id alongside on AST_PRES_RESTRICTION.
 * Mirrors chan_sip add_rpid at chan_sip.c:11743-11825 + Privacy header per
 * RFC 3325 §9.3 / RFC 3323.
 *
 * Gated on pvt->peer->sendrpid: 0=no emit, 1=PAI emit, 2=RPID emit.
 * Reads identity via sofia_resolve_identity (R12 DRY).
 *
 * PAI branch (sendrpid=1): builds "P-Asserted-Identity: <sip:user@host>" with
 * anonymous fallback on AST_PRES_RESTRICTION (chan_sip L11787 parity:
 * "<sip:anonymous@anonymous.invalid>"). When AST_PRES_RESTRICTION,
 * additionally emits "Privacy: id" header per RFC 3325 §9.3.
 *
 * RPID branch (sendrpid=2): builds "Remote-Party-ID: \"name\" <sip:user@host>;
 * party=calling/called;privacy=full|off;screen=yes|no" with mapping table per
 * chan_sip L11787-11820. When privacy=full, additionally emits "Privacy: id"
 * (RFC 3323 alignment with RPID-stated privacy).
 *
 * On entry: pvt non-NULL; header_buf points to writable buffer of header_len
 * bytes (recommend >=512 for combined RPID + Privacy).
 * On exit: header_buf populated with assembled CRLF-separated header(s);
 * empty string on no emit.
 * Returns: 0 on no-emit, 1 on PAI emit, 2 on RPID emit. */
static int sofia_add_rpid(struct sofia_pvt *pvt, char *header_buf, size_t header_len)
{
	char *lid_num, *lid_name;
	int lid_pres;
	char fromdomain[128];
	int mode;

	if (!header_buf || header_len < 2) {
		return 0;
	}
	header_buf[0] = '\0';

	if (!pvt || !pvt->peer || pvt->peer->sendrpid == 0) {
		return 0;
	}
	mode = pvt->peer->sendrpid;

	if (sofia_resolve_identity(pvt, &lid_num, &lid_name, &lid_pres,
			fromdomain, sizeof(fromdomain)) < 0) {
		return 0;
	}

	if (mode == 1) {
		/* PAI branch — chan_sip L11780-11790 parity */
		if ((lid_pres & AST_PRES_RESTRICTION) != AST_PRES_ALLOWED) {
			snprintf(header_buf, header_len,
				"P-Asserted-Identity: <sip:anonymous@anonymous.invalid>\r\n"
				"Privacy: id\r\n");
		} else {
			snprintf(header_buf, header_len,
				"P-Asserted-Identity: \"%s\" <sip:%s@%s>\r\n",
				lid_name, lid_num, fromdomain);
		}
		return 1;
	}

	/* mode == 2: RPID branch — chan_sip L11787-11820 mapping table */
	{
		const char *privacy_str = "off";
		const char *screen_str = "no";
		const char *party_str = pvt->outgoing ? "calling" : "called";
		int restricted = 0;

		switch (lid_pres) {
		case AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED:
		case AST_PRES_ALLOWED_USER_NUMBER_FAILED_SCREEN:
			privacy_str = "off"; screen_str = "no"; break;
		case AST_PRES_ALLOWED_USER_NUMBER_PASSED_SCREEN:
		case AST_PRES_ALLOWED_NETWORK_NUMBER:
			privacy_str = "off"; screen_str = "yes"; break;
		case AST_PRES_PROHIB_USER_NUMBER_NOT_SCREENED:
		case AST_PRES_PROHIB_USER_NUMBER_FAILED_SCREEN:
			privacy_str = "full"; screen_str = "no"; restricted = 1; break;
		case AST_PRES_PROHIB_USER_NUMBER_PASSED_SCREEN:
		case AST_PRES_PROHIB_NETWORK_NUMBER:
			privacy_str = "full"; screen_str = "yes"; restricted = 1; break;
		case AST_PRES_NUMBER_NOT_AVAILABLE:
			privacy_str = NULL; screen_str = NULL; break;
		default:
			if ((lid_pres & AST_PRES_RESTRICTION) != AST_PRES_ALLOWED) {
				privacy_str = "full"; restricted = 1;
			}
			screen_str = "no";
			break;
		}

		if (privacy_str && screen_str) {
			snprintf(header_buf, header_len,
				"Remote-Party-ID: \"%s\" <sip:%s@%s>;party=%s;privacy=%s;screen=%s\r\n%s",
				lid_name, lid_num, fromdomain, party_str, privacy_str, screen_str,
				restricted ? "Privacy: id\r\n" : "");
		} else {
			snprintf(header_buf, header_len,
				"Remote-Party-ID: \"%s\" <sip:%s@%s>;party=%s\r\n",
				lid_name, lid_num, fromdomain, party_str);
		}
		return 2;
	}
}

/* post-T56 identity-headers parity SS3 (2026-04-27): mirror chan_sip
 * sip_reason_table at chan_sip.c:664-680 + sip_reason_code_to_str at L2545.
 * Maps AST_REDIRECTING_REASON_* enum (callerid.h:390-403) to Diversion
 * ;reason= string per RFC 5806 §4.4. AST_REDIRECTING_REASON_CALL_FWD_DTE
 * deliberately maps to "unknown" (chan_sip parity — DTE forwarding has no
 * canonical Diversion reason). */
static const struct {
	enum AST_REDIRECTING_REASON code;
	char * const text;
} sofia_reason_table[] = {
	{ AST_REDIRECTING_REASON_UNKNOWN, "unknown" },
	{ AST_REDIRECTING_REASON_USER_BUSY, "user-busy" },
	{ AST_REDIRECTING_REASON_NO_ANSWER, "no-answer" },
	{ AST_REDIRECTING_REASON_UNAVAILABLE, "unavailable" },
	{ AST_REDIRECTING_REASON_UNCONDITIONAL, "unconditional" },
	{ AST_REDIRECTING_REASON_TIME_OF_DAY, "time-of-day" },
	{ AST_REDIRECTING_REASON_DO_NOT_DISTURB, "do-not-disturb" },
	{ AST_REDIRECTING_REASON_DEFLECTION, "deflection" },
	{ AST_REDIRECTING_REASON_FOLLOW_ME, "follow-me" },
	{ AST_REDIRECTING_REASON_OUT_OF_ORDER, "out-of-service" },
	{ AST_REDIRECTING_REASON_AWAY, "away" },
	{ AST_REDIRECTING_REASON_CALL_FWD_DTE, "unknown" },
};

static const char *sofia_reason_code_to_str(int code)
{
	if (code >= 0 && code < (int)ARRAY_LEN(sofia_reason_table)) {
		return sofia_reason_table[code].text;
	}
	return "unknown";
}

/* post-T56 identity-headers parity SS5 (2026-04-27): reverse of
 * sofia_reason_code_to_str — string from Diversion ;reason= param to enum.
 * Used by sofia_change_redirecting_info inbound parser. */
static int sofia_reason_str_to_code(const char *str)
{
	size_t i;
	if (!str) {
		return AST_REDIRECTING_REASON_UNKNOWN;
	}
	for (i = 0; i < ARRAY_LEN(sofia_reason_table); i++) {
		if (!strcasecmp(str, sofia_reason_table[i].text)) {
			return sofia_reason_table[i].code;
		}
	}
	return AST_REDIRECTING_REASON_UNKNOWN;
}

/* post-T56 identity-headers parity SS3 + R11-revised (2026-04-27): outbound
 * Diversion header emitter. Mirrors chan_sip add_diversion_header at
 * chan_sip.c:12999 + R11-revised privacy=full|off param.
 *
 * Triggered when pvt->owner->redirecting.from.number is set (call-forward
 * chain from B-side reaches chan_sofia outbound). Emits "Diversion" header
 * per RFC 5806 with reason from sofia_reason_code_to_str + privacy parameter
 * derived from AST_PRES_RESTRICTION on redirecting.from presentation
 * (R11-revised — Diversion-side privacy alongside RPID/PAI Privacy: id).
 *
 * On entry: pvt non-NULL; header_buf points to writable buffer of len bytes.
 * On exit: header_buf populated with "Diversion: <value>\r\n" or empty.
 * Returns: 0 on no-emit, 1 on emit. */
static int sofia_add_diversion(struct sofia_pvt *pvt, char *header_buf, size_t header_len)
{
	const char *diverting_number;
	const char *diverting_name;
	const char *reason;
	const char *privacy_str;
	char fromhost[128];
	int redir_pres;

	if (!header_buf || header_len < 2) {
		return 0;
	}
	header_buf[0] = '\0';

	if (!pvt || !pvt->owner) {
		return 0;
	}

	diverting_number = pvt->owner->redirecting.from.number.str;
	if (!pvt->owner->redirecting.from.number.valid
			|| ast_strlen_zero(diverting_number)) {
		return 0;
	}

	reason = sofia_reason_code_to_str(pvt->owner->redirecting.reason);
	diverting_name = pvt->owner->redirecting.from.name.str;

	if (!ast_sockaddr_isnull(&pvt->ourip)) {
		ast_copy_string(fromhost,
			ast_sockaddr_stringify_host(&pvt->ourip), sizeof(fromhost));
	} else if (pvt->peer && !ast_strlen_zero(pvt->peer->fromdomain)) {
		ast_copy_string(fromhost, pvt->peer->fromdomain, sizeof(fromhost));
	} else if (!ast_strlen_zero(sofia_cfg.realm)) {
		ast_copy_string(fromhost, sofia_cfg.realm, sizeof(fromhost));
	} else {
		ast_copy_string(fromhost, "gabpbx", sizeof(fromhost));
	}

	/* R11-revised: privacy parameter from redirecting.from presentation —
	 * SEPARATE identity from pvt->callingpres (the outbound caller's
	 * presentation). The redirecting party is its own party_id. */
	redir_pres = ast_party_id_presentation(&pvt->owner->redirecting.from);
	privacy_str = ((redir_pres & AST_PRES_RESTRICTION) != AST_PRES_ALLOWED) ? "full" : "off";

	if (!pvt->owner->redirecting.from.name.valid
			|| ast_strlen_zero(diverting_name)) {
		snprintf(header_buf, header_len,
			"Diversion: <sip:%s@%s>;reason=%s;privacy=%s\r\n",
			diverting_number, fromhost, reason, privacy_str);
	} else {
		snprintf(header_buf, header_len,
			"Diversion: \"%s\" <sip:%s@%s>;reason=%s;privacy=%s\r\n",
			diverting_name, diverting_number, fromhost, reason, privacy_str);
	}
	return 1;
}

/* post-T56 identity-headers parity SS4 + R11-revised (2026-04-27): detect
 * Privacy: id header per RFC 3323 §4.2. Uses sofia-sip native sip->sip_privacy
 * (parsed by default mclass at sip.h:340 + struct at L816). priv_values is a
 * NULL-terminated msg_param_t array of priv-value tokens; "id" forces caller-id
 * restriction regardless of PAI/RPID URI form (chan_sip parity at L16100).
 * Returns 1 if Privacy: id present, 0 otherwise. */
static int sofia_check_privacy_id(sip_t const *sip)
{
	msg_param_t const *v;
	if (!sip || !sip->sip_privacy || !sip->sip_privacy->priv_values) {
		return 0;
	}
	for (v = sip->sip_privacy->priv_values; *v; v++) {
		if (!strcasecmp(*v, "id")) {
			return 1;
		}
	}
	return 0;
}

/* post-T56 identity-headers parity SS4 + R11-revised (2026-04-27): inbound
 * P-Asserted-Identity parser. Mirrors chan_sip get_pai at chan_sip.c:16058-16128.
 *
 * Trust-gated on peer->trustrpid (R6). Walks sip->sip_unknown for
 * "P-Asserted-Identity" by name (T55.4 init-snapshot precedent — robust
 * across sofia-sip versions, no sip_extra.h class-init dependency).
 *
 * Anonymous detection: PAI URI starting "sip:anonymous@anonymous.invalid"
 * forces AST_PRES_PROHIB_USER_NUMBER_NOT_SCREENED (chan_sip L16085).
 * Privacy: id detection: forces same presentation regardless of PAI URI form
 * (R11-revised + chan_sip L16100 parity).
 *
 * Updates pvt->cid_num + pvt->cid_name + pvt->callingpres; if pvt->owner is
 * already bound (post-sofia_new caller, future use), also updates channel.
 * Returns 1 on update, 0 on no-update or no-PAI. */
static int sofia_get_pai(struct sofia_pvt *pvt, sip_t const *sip)
{
	sip_unknown_t const *u;
	const char *pai_value = NULL;
	char tmp[256];
	char *uri_buf, *cid_name = NULL, *cid_num = NULL;
	int callingpres = AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED;
	int is_anonymous = 0;

	if (!pvt || !pvt->peer || !pvt->peer->trustrpid || !sip) {
		return 0;
	}

	for (u = sip->sip_unknown; u; u = u->un_next) {
		if (u->un_name && !strcasecmp(u->un_name, "P-Asserted-Identity")) {
			pai_value = u->un_value;
			break;
		}
	}
	if (!pai_value || ast_strlen_zero(pai_value)) {
		return 0;
	}

	ast_copy_string(tmp, pai_value, sizeof(tmp));

	/* Format expected: ["display"] <sip:user@host>[;params].
	 * Inline parser — chan_sip uses internal get_name_and_number (reqresp_parser.h)
	 * which is not exposed across modules. Simpler form here covers RFC 3325 §9.1. */
	uri_buf = strchr(tmp, '<');
	if (uri_buf) {
		char *end;
		char *q1;
		*uri_buf++ = '\0';
		end = strchr(uri_buf, '>');
		if (end) {
			*end = '\0';
		}
		q1 = strchr(tmp, '"');
		if (q1) {
			char *q2;
			q1++;
			q2 = strchr(q1, '"');
			if (q2) {
				*q2 = '\0';
				cid_name = q1;
			}
		}
		if (!strncasecmp(uri_buf, "sip:anonymous@anonymous.invalid", 31)) {
			callingpres = AST_PRES_PROHIB_USER_NUMBER_NOT_SCREENED;
			is_anonymous = 1;
		} else if (!strncasecmp(uri_buf, "sip:", 4)) {
			char *at = strchr(uri_buf + 4, '@');
			if (at) {
				*at = '\0';
				cid_num = uri_buf + 4;
			}
		}
	}

	if (sofia_check_privacy_id(sip)) {
		callingpres = AST_PRES_PROHIB_USER_NUMBER_NOT_SCREENED;
	}

	if (!is_anonymous && !ast_strlen_zero(cid_num)) {
		ast_string_field_set(pvt, cid_num, cid_num);
	}
	if (!ast_strlen_zero(cid_name)) {
		ast_string_field_set(pvt, cid_name, cid_name);
	}
	pvt->callingpres = callingpres;

	if (pvt->owner) {
		ast_set_callerid(pvt->owner,
			!ast_strlen_zero(pvt->cid_num) ? pvt->cid_num : NULL,
			!ast_strlen_zero(pvt->cid_name) ? pvt->cid_name : NULL,
			NULL);
		pvt->owner->caller.id.number.presentation = callingpres;
		pvt->owner->caller.id.name.presentation = callingpres;
	}
	return 1;
}

/* post-T56 identity-headers parity SS4 + R11-revised (2026-04-27): inbound
 * Remote-Party-ID parser. Mirrors chan_sip get_rpid at chan_sip.c:16134-16245.
 *
 * Trust-gated on peer->trustrpid (R6). Walks sip->sip_unknown for
 * "Remote-Party-ID". If absent, falls back to sofia_get_pai per chan_sip L16151.
 *
 * Parses RPID format: [display-name] LAQUOT addr-spec RAQUOT *(SEMI rpi-token)
 * with ;privacy= + ;screen= mapping per chan_sip L16216-16229.
 * Privacy: id detection same as sofia_get_pai. */
static int sofia_get_rpid(struct sofia_pvt *pvt, sip_t const *sip)
{
	sip_unknown_t const *u;
	const char *rpid_value = NULL;
	char tmp[256];
	char *cid_name = "";
	char *cid_num = "";
	int callingpres = AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED;
	const char *privacy = "";
	const char *screen = "";
	char *start, *end;

	if (!pvt || !pvt->peer || !pvt->peer->trustrpid || !sip) {
		return 0;
	}

	for (u = sip->sip_unknown; u; u = u->un_next) {
		if (u->un_name && !strcasecmp(u->un_name, "Remote-Party-ID")) {
			rpid_value = u->un_value;
			break;
		}
	}
	if (!rpid_value || ast_strlen_zero(rpid_value)) {
		return sofia_get_pai(pvt, sip);
	}

	ast_copy_string(tmp, rpid_value, sizeof(tmp));
	start = tmp;

	if (*start == '"') {
		*start++ = '\0';
		end = strchr(start, '"');
		if (!end) {
			return 0;
		}
		*end++ = '\0';
		cid_name = start;
		start = ast_skip_blanks(end);
	} else {
		cid_name = start;
		end = strchr(start, '<');
		if (!end) {
			return 0;
		}
		start = end;
		while (--end >= cid_name && *end < 33) {
			*end = '\0';
		}
	}

	if (*start != '<') {
		return 0;
	}
	*start++ = '\0';
	end = strchr(start, '@');
	if (!end) {
		return 0;
	}
	*end++ = '\0';
	if (strncasecmp(start, "sip:", 4)) {
		return 0;
	}
	cid_num = start + 4;
	start = end;

	end = strchr(start, '>');
	if (!end) {
		return 0;
	}
	*end++ = '\0';

	if (*end == ';') {
		start = end + 1;
		while (!ast_strlen_zero(start)) {
			end = strchr(start, ';');
			if (end) {
				*end++ = '\0';
			}
			if (!strncasecmp(start, "privacy=", 8)) {
				privacy = start + 8;
			} else if (!strncasecmp(start, "screen=", 7)) {
				screen = start + 7;
			}
			start = end;
		}

		/* Mapping table per chan_sip L16216-16229 */
		if (!strcasecmp(privacy, "full")) {
			if (!strcasecmp(screen, "yes")) {
				callingpres = AST_PRES_PROHIB_USER_NUMBER_PASSED_SCREEN;
			} else {
				callingpres = AST_PRES_PROHIB_USER_NUMBER_NOT_SCREENED;
			}
		} else {
			if (!strcasecmp(screen, "yes")) {
				callingpres = AST_PRES_ALLOWED_USER_NUMBER_PASSED_SCREEN;
			} else {
				callingpres = AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED;
			}
		}
	}

	/* Privacy: id forces restriction regardless of RPID ;privacy= form (R11-revised). */
	if (sofia_check_privacy_id(sip)) {
		callingpres = AST_PRES_PROHIB_USER_NUMBER_NOT_SCREENED;
	}

	ast_string_field_set(pvt, cid_num, cid_num);
	ast_string_field_set(pvt, cid_name, cid_name);
	pvt->callingpres = callingpres;

	if (pvt->owner) {
		ast_set_callerid(pvt->owner,
			!ast_strlen_zero(pvt->cid_num) ? pvt->cid_num : NULL,
			!ast_strlen_zero(pvt->cid_name) ? pvt->cid_name : NULL,
			NULL);
		pvt->owner->caller.id.number.presentation = callingpres;
		pvt->owner->caller.id.name.presentation = callingpres;
	}
	return 1;
}

/* post-T56 identity-headers parity SS5 (2026-04-27): inbound Diversion header
 * parser + apply to pvt->owner->redirecting. Mirrors chan_sip
 * change_redirecting_information at chan_sip.c:20793 + get_rdnis at
 * chan_sip.c:16251.
 *
 * Walks sip->sip_unknown for "Diversion" by name (T55.4 + SS4 precedent —
 * robust across sofia-sip versions, no sip_extra.h class-init dependency).
 * Extracts redirecting-from name + URI user-part + ;reason= parameter,
 * updates pvt->owner->redirecting struct + dialplan variables
 * __SIPREDIRECTREASON / __SIPRDNISDOMAIN per chan_sip parity.
 *
 * No trust-gating — Diversion is structural metadata, operator dialplan
 * decides trust via the dialplan variables.
 *
 * On entry: pvt->owner expected non-NULL (caller checks).
 * Returns: 1 on update applied, 0 on no-Diversion-header. */
static int sofia_change_redirecting_info(struct sofia_pvt *pvt, sip_t const *sip)
{
	sip_unknown_t const *u;
	const char *div_value = NULL;
	char tmp[256];
	char *uri;
	char *user;
	char *domain = NULL;
	char *params;
	char *end;
	char *redir_name = NULL;
	char *redir_num = NULL;
	char *reason_str = NULL;
	int reason = AST_REDIRECTING_REASON_UNCONDITIONAL;

	if (!pvt || !pvt->owner || !sip) {
		return 0;
	}

	for (u = sip->sip_unknown; u; u = u->un_next) {
		if (u->un_name && !strcasecmp(u->un_name, "Diversion")) {
			div_value = u->un_value;
			break;
		}
	}
	if (!div_value || ast_strlen_zero(div_value)) {
		return 0;
	}

	ast_copy_string(tmp, div_value, sizeof(tmp));

	/* Optional display-name in quotes. */
	if (*tmp == '"') {
		char *end_q;
		redir_name = tmp + 1;
		end_q = strchr(redir_name, '"');
		if (end_q) {
			*end_q = '\0';
		}
	}

	/* Extract URI from <...> — chan_sip parity get_in_brackets */
	uri = strchr(tmp, '<');
	if (!uri) {
		return 0;
	}
	uri++;
	end = strchr(uri, '>');
	if (end) {
		*end = '\0';
	}

	/* Split off ;params (chan_sip L16284 parity) before scheme strip + user@domain split. */
	params = strchr(uri, ';');
	if (params) {
		*params++ = '\0';
	}

	if (!strncasecmp(uri, "sip:", 4)) {
		uri += 4;
	} else if (!strncasecmp(uri, "sips:", 5)) {
		uri += 5;
	} else {
		return 0;
	}

	domain = uri;
	user = strsep(&domain, "@");
	redir_num = user;

	/* Walk ;reason=X;... params for canonical reason mapping. */
	while (params && *params) {
		char *param_end = strchr(params, ';');
		if (param_end) {
			*param_end++ = '\0';
		}
		while (*params == ' ') {
			params++;
		}
		if (!strncasecmp(params, "reason=", 7)) {
			reason_str = params + 7;
			/* Strip enclosing quotes if present (chan_sip L16291 parity). */
			if (*reason_str == '"') {
				char *end_q;
				reason_str++;
				end_q = strchr(reason_str, '"');
				if (end_q) {
					*end_q = '\0';
				}
			}
			reason = sofia_reason_str_to_code(reason_str);
		}
		params = param_end;
	}

	/* Apply to pvt->owner->redirecting (chan_sip L20826-20838 parity).
	 * ast_free of existing strs BEFORE ast_strdup — prevents leak. */
	if (!ast_strlen_zero(redir_num)) {
		ast_free(pvt->owner->redirecting.from.number.str);
		pvt->owner->redirecting.from.number.str = ast_strdup(redir_num);
		pvt->owner->redirecting.from.number.valid = 1;
	}
	if (!ast_strlen_zero(redir_name)) {
		ast_free(pvt->owner->redirecting.from.name.str);
		pvt->owner->redirecting.from.name.str = ast_strdup(redir_name);
		pvt->owner->redirecting.from.name.valid = 1;
	}
	pvt->owner->redirecting.reason = reason;

	/* Dialplan variables for chan_sip parity (chan_sip L16296-16306). */
	if (!ast_strlen_zero(reason_str)) {
		pbx_builtin_setvar_helper(pvt->owner, "__SIPREDIRECTREASON", reason_str);
	}
	if (!ast_strlen_zero(domain)) {
		pbx_builtin_setvar_helper(pvt->owner, "__SIPRDNISDOMAIN", domain);
	}

	return 1;
}

/* post-T56 call-limit parity SS2 (2026-04-27): centralized counter helper.
 * Mirrors chan_sip update_call_counter at chan_sip.c:6576-6810.
 *
 * Event semantics (R3 critical refinement):
 * - SOFIA_INC_CALL_LIMIT (inbound INVITE post-auth at sofia_process_invite):
 *   bumps inUse only; chan_sip parity at L23906.
 * - SOFIA_INC_CALL_RINGING (outbound dial at sofia_call entry):
 *   bumps BOTH inUse + inRinging atomically; chan_sip parity at L6297.
 * - SOFIA_DEC_CALL_LIMIT (hangup at 4 sites — sofia_hangup, nua_i_bye,
 *   nua_r_bye, sofia_pvt_destructor catchall):
 *   decrements inUse if call_inc_done set; chan_sip parity at L7041/L7061/etc.
 * - SOFIA_DEC_CALL_RINGING (outbound 200 OK at nua_r_invite):
 *   decrements inRinging if ring_inc_done set (call_inc_done stays — call
 *   still in inUse pool until hangup); chan_sip parity at L21448.
 *
 * Quick-exit at peer->call_limit==0 + busy_level==0 (chan_sip L6587 parity)
 * — peers with no participation pay zero cost.
 *
 * Lock ordering pvt->lock then ao2_lock(peer) per chan_sip L6713-6730 verbatim.
 * Idempotency via pvt->call_inc_done + ring_inc_done (chan_sip SIP_INC_COUNT
 * + SIP_INC_RINGING parity).
 *
 * Emits PeerStatus AMI events: CallLimitExceeded on rejection +
 * CallCountUpdated on increment (chan_sip L6687/L6734 parity verbatim).
 * EVENT_FLAG_SYSTEM. ChannelType: SIP + Peer: SIP/%s per drop-in compat.
 * TuCloudPBXName + Accountcode: empty placeholder (R12.1 minimum scope —
 * field source not on sofia_peer; full field-add deferred future-task per
 * "minimum scope expansion" rule).
 *
 * Returns 0 on success, -1 on call rejection (caller emits 480 inbound or
 * AST_CAUSE_USER_BUSY → 486 outbound). */
static int sofia_update_call_counter(struct sofia_pvt *pvt, enum sofia_call_event event)
{
	struct sofia_peer *peer;

	if (!pvt || !pvt->peer) {
		return 0;
	}
	peer = pvt->peer;

	if (peer->call_limit == 0 && peer->busy_level == 0) {
		return 0;
	}

	switch (event) {
	case SOFIA_INC_CALL_LIMIT:
	case SOFIA_INC_CALL_RINGING:
		if (peer->call_limit > 0 && peer->inUse >= peer->call_limit) {
			ast_log(LOG_NOTICE, "Call %s peer '%s' rejected due to usage limit of %d\n",
				(event == SOFIA_INC_CALL_RINGING) ? "to" : "from",
				peer->name, peer->call_limit);

			/* post-T56 accountcode per-peer parity (2026-04-27): in-flight Pattern 1
			 * stub fix #12 — pre-existing hardcoded "Accountcode: \r\n" empty stub
			 * (R12.1 deferred-future-task referenced at L5970-5972) corrected to emit
			 * peer->accountcode actual value. ADDENDUM #4 SS6 8-in-flight-catches-pattern
			 * advances to 12/12 1-day peak. */
			manager_event(EVENT_FLAG_SYSTEM, "PeerStatus",
				"ChannelType: SIP\r\n"
				"Peer: SIP/%s\r\n"
				"PeerStatus: CallLimitExceeded\r\n"
				"Address: %s\r\n"
				"TuCloudPBXName: \r\n"
				"Context: %s\r\n"
				"Accountcode: %s\r\n"
				"ActiveCalls: %d\r\n"
				"RingingCalls: %d\r\n"
				"CallLimit: %d\r\n"
				"Event: CALL_REJECTED\r\n",
				peer->name,
				!ast_sockaddr_isnull(&peer->src_addr) ? ast_sockaddr_stringify(&peer->src_addr) : "",
				peer->context,
				S_OR(peer->accountcode, ""),
				peer->inUse, peer->inRinging, peer->call_limit);
			return -1;
		}

		ast_mutex_lock(&pvt->lock);
		ao2_lock(peer);
		if (event == SOFIA_INC_CALL_RINGING && !pvt->ring_inc_done) {
			peer->inRinging++;
			pvt->ring_inc_done = 1;
		}
		if (!pvt->call_inc_done) {
			peer->inUse++;
			pvt->call_inc_done = 1;
		}
		ao2_unlock(peer);
		ast_mutex_unlock(&pvt->lock);

		/* post-T56 accountcode per-peer parity (2026-04-27): in-flight Pattern 1
		 * stub fix #12 (companion to L6004) — second hardcoded "Accountcode: \r\n"
		 * empty stub corrected to emit peer->accountcode actual value. */
		manager_event(EVENT_FLAG_SYSTEM, "PeerStatus",
			"ChannelType: SIP\r\n"
			"Peer: SIP/%s\r\n"
			"PeerStatus: CallCountUpdated\r\n"
			"Address: %s\r\n"
			"TuCloudPBXName: \r\n"
			"Context: %s\r\n"
			"Accountcode: %s\r\n"
			"ActiveCalls: %d\r\n"
			"RingingCalls: %d\r\n"
			"CallLimit: %d\r\n"
			"Event: %s\r\n",
			peer->name,
			!ast_sockaddr_isnull(&peer->src_addr) ? ast_sockaddr_stringify(&peer->src_addr) : "",
			peer->context,
			S_OR(peer->accountcode, ""),
			peer->inUse, peer->inRinging, peer->call_limit,
			event == SOFIA_INC_CALL_RINGING ? "INC_CALL_RINGING" : "INC_CALL_LIMIT");
		break;

	case SOFIA_DEC_CALL_LIMIT:
		ast_mutex_lock(&pvt->lock);
		ao2_lock(peer);
		if (pvt->call_inc_done && peer->inUse > 0) {
			peer->inUse--;
			pvt->call_inc_done = 0;
		}
		ao2_unlock(peer);
		ast_mutex_unlock(&pvt->lock);
		break;

	case SOFIA_DEC_CALL_RINGING:
		ast_mutex_lock(&pvt->lock);
		ao2_lock(peer);
		if (pvt->ring_inc_done && peer->inRinging > 0) {
			peer->inRinging--;
			pvt->ring_inc_done = 0;
		}
		ao2_unlock(peer);
		ast_mutex_unlock(&pvt->lock);
		break;
	}

	return 0;
}

/* T56.2 (2026-04-27): normalize outboundproxy spec into canonical Route URI.
 * Resolves R3 inheritance (peer overrides [general]) + R2 3-form acceptance
 * (bare host / host:port / full sip:URI) + R9 defensive ;lr append.
 *
 * On entry: buf points to writable buffer of at least len bytes.
 * On exit: buf is empty (buf[0]='\0') if no proxy applies; else holds the
 * canonical "sip:HOST[:PORT];lr" or "sips:..." form.
 *
 * Caller pattern: TAG_IF(buf[0], NUTAG_INITIAL_ROUTE_STR(buf))
 *
 * Lock: caller must own a peer ref preventing concurrent mutation of
 * peer->outboundproxy. Both T56.2 wire-in callers hold a peer ref
 * (sofia_call ao2_ref +1; sofia_do_register ao2_iterator ref). */
static void sofia_format_outboundproxy(struct sofia_peer *peer, char *buf, size_t len)
{
	const char *spec;
	int has_scheme;
	int has_lr;

	if (!buf || len < 1) {
		return;
	}
	buf[0] = '\0';

	if (!peer) {
		return;
	}

	/* R3 inheritance chain: peer override > [general] default > none */
	if (!ast_strlen_zero(peer->outboundproxy)) {
		spec = peer->outboundproxy;
	} else if (!ast_strlen_zero(sofia_cfg.outboundproxy)) {
		spec = sofia_cfg.outboundproxy;
	} else {
		return;
	}

	/* R2/R9 form detection */
	has_scheme = (!strncasecmp(spec, "sip:", 4) || !strncasecmp(spec, "sips:", 5));
	has_lr = (strstr(spec, ";lr") != NULL);

	if (has_scheme) {
		/* Full SIP URI form — pass through; defensive ;lr append if missing */
		snprintf(buf, len, "%s%s", spec, has_lr ? "" : ";lr");
	} else {
		/* Bare host or host:port — prepend sip: + always append ;lr */
		snprintf(buf, len, "sip:%s;lr", spec);
	}
}

/* T55.4 (2026-04-27): build + send MWI NOTIFY to peer's active subscriber.
 * Aggregates inbox counts across all peer->mailboxes; emits single
 * Messages-Waiting + Message-Account + Voice-Message body per RFC 3842.
 * Caller MUST own a peer ref AND must have verified
 * peer->mwi_subscription_handle is non-NULL before calling.
 *
 * Lock discipline: takes peer->lock internally for the mailbox traversal +
 * field reads; releases before nua_notify. Caller must NOT be holding
 * peer->lock at entry.
 *
 * Runs on sofia_thread (called from sofia_process_mwi_subscribe initial
 * NOTIFY path in T55.4; T55.5 will add re-NOTIFY callsite from cross-
 * thread dispatch callback). */
static void transmit_mwi_notify_for_peer(struct sofia_peer *peer)
{
	struct sofia_mailbox *mb;
	struct ast_str *body;
	int total_new = 0, total_old = 0, total_urgent = 0;
	const char *vmexten;
	const char *notifymime;
	const char *fromdomain;
	nua_handle_t *nh;

	if (!peer) {
		return;
	}

	ast_mutex_lock(&peer->lock);
	nh = peer->mwi_subscription_handle;
	if (!nh) {
		ast_mutex_unlock(&peer->lock);
		return;
	}
	/* Sum counts across all configured mailboxes. ast_app_inboxcount2 is the
	 * RFC 3842 form (urgent + new + old); we capture urgent for accuracy. */
	AST_LIST_TRAVERSE(&peer->mailboxes, mb, list) {
		int new_msgs = 0, old_msgs = 0, urgent_msgs = 0;
		char mailbox_full[160];
		snprintf(mailbox_full, sizeof(mailbox_full), "%s@%s", mb->mailbox, mb->context);
		if (ast_app_inboxcount2(mailbox_full, &urgent_msgs, &new_msgs, &old_msgs) == 0) {
			total_new    += new_msgs;
			total_old    += old_msgs;
			total_urgent += urgent_msgs;
		}
	}
	/* Snapshot the cfg-derived strings + peer->fromdomain under peer->lock so
	 * the body assembly happens after release without dangling pointers. */
	fromdomain = !ast_strlen_zero(peer->fromdomain) ? peer->fromdomain : sofia_cfg.realm;
	ast_mutex_unlock(&peer->lock);

	body = ast_str_create(256);
	if (!body) {
		ast_log(LOG_WARNING, "Sofia MWI: ast_str_create failed for peer %s\n", peer->name);
		return;
	}

	vmexten    = !ast_strlen_zero(sofia_cfg.vmexten) ? sofia_cfg.vmexten : "asterisk";
	notifymime = !ast_strlen_zero(sofia_cfg.notifymime) ? sofia_cfg.notifymime
		: "application/simple-message-summary";

	/* RFC 3842 body. chan_sip parity per chan_sip.c:13771-13820. */
	ast_str_append(&body, 0, "Messages-Waiting: %s\r\n",
		total_new ? "yes" : "no");
	ast_str_append(&body, 0, "Message-Account: sip:%s@%s\r\n",
		vmexten, fromdomain);
	/* post-T56 buggymwi per-peer parity (2026-04-27): chan_sip parity at
	 * chan_sip.c:13800-13804 verbatim — Cisco SIP stack rejects Voice-Message
	 * lines containing the "(0/0)" tally suffix. Per-peer buggymwi=yes omits
	 * the suffix as a workaround. Default behavior (suffix included) preserves
	 * RFC 3842-compliant phones unchanged. */
	ast_str_append(&body, 0, "Voice-Message: %d/%d%s\r\n",
		total_new, total_old, peer->buggymwi ? "" : " (0/0)");

	nua_notify(nh,
		SIPTAG_EVENT_STR("message-summary"),
		SIPTAG_CONTENT_TYPE_STR(notifymime),
		SIPTAG_PAYLOAD_STR(ast_str_buffer(body)),
		TAG_END());

	if (sofia_debug) {
		ast_verbose("Sofia MWI: NOTIFY emitted for peer '%s' (new=%d old=%d urgent=%d)\n",
			peer->name, total_new, total_old, total_urgent);
	}

	ast_free(body);
}

/* T55.3 (2026-04-27): MWI SUBSCRIBE handler. Accepts in-dialog
 * SUBSCRIBE Event:message-summary, identifies the mailbox-owner peer via
 * To URI user-part (R4 Option C), enforces 1-subscription-per-peer cap
 * by terminating any existing subscription before assigning the new nh.
 *
 * Uses nua_notifier API (R1 Option A) — sofia-sip handles dialog state +
 * Subscription-State auto-emission per RFC 6665.
 *
 * Lock-ordering discipline: peer->lock is held ONLY while mutating peer
 * fields (mailbox-empty check, swap mwi_subscription_handle, capture old
 * handle to local). All nua_* ops happen AFTER releasing peer->lock to
 * avoid nesting peer->lock under sofia-sip internal locks.
 *
 * Runs on sofia_thread (nua_i_subscribe handler context). T55.5 will
 * call into transmit_mwi_notify_for_peer here for synchronous initial
 * NOTIFY emission per RFC 6665 §4.4.1. */
static void sofia_process_mwi_subscribe(nua_t *nua, nua_handle_t *nh,
		struct sofia_pvt *op, sip_t const *sip, tagi_t tags[])
{
	struct sofia_peer *peer;
	const char *to_user;
	nua_handle_t *old_nh = NULL;

	/* R4 Option C: To URI user-part identifies the mailbox-owning peer */
	if (!sip || !sip->sip_to || !sip->sip_to->a_url || !sip->sip_to->a_url->url_user) {
		nua_respond(nh, SIP_404_NOT_FOUND, NUTAG_WITH_THIS(nua), TAG_END());
		return;
	}
	to_user = sip->sip_to->a_url->url_user;

	peer = sofia_find_peer(to_user);
	if (!peer) {
		if (sofia_cfg.alwaysauthreject) {
			/* post-T56 domainsasrealm wire-in (2026-04-28): Pattern 5 helper #29
			 * sofia_get_realm_for_dialog (mirror chan_sip get_realm semantic). */
			char realm_buf[MAXHOSTNAMELEN];
			const char *realm = sofia_get_realm_for_dialog(sip, realm_buf, sizeof(realm_buf));
			ast_log(LOG_NOTICE, "Sofia MWI: SUBSCRIBE for unknown peer '%s' — 401 challenge (alwaysauthreject)\n", to_user);
			sofia_send_auth_challenge(nua, nh, sip, realm, "SUBSCRIBE", "UnknownPeer");
		} else {
			ast_log(LOG_NOTICE, "Sofia MWI: SUBSCRIBE for unknown peer '%s' — 404\n", to_user);
			nua_respond(nh, SIP_404_NOT_FOUND, NUTAG_WITH_THIS(nua), TAG_END());
		}
		return;
	}

	/* post-T56 allowsubscribe per-peer gate (2026-04-27): chan_sip parity at
	 * chan_sip.c:25940 — when peer->allowsubscribe is FALSE, reject with
	 * verbatim "403 Forbidden (policy)" (operator scripts pattern-match exact
	 * text including parens). REQUEST-EVENT GATING dimension #6 sibling to
	 * allowtransfer (gated at sofia_process_refer entry). */
	if (!peer->allowsubscribe) {
		ast_log(LOG_NOTICE,
			"Sofia MWI: SUBSCRIBE for peer '%s' rejected by allowsubscribe=no — 403\n",
			peer->name);
		nua_respond(nh, 403, "Forbidden (policy)",
			NUTAG_WITH_THIS(nua), TAG_END());
		sofia_emit_subscribe_rejected(sip, peer->name, "message-summary",
			"AllowSubscribeClosed");
		ao2_ref(peer, -1);
		return;
	}

	ast_mutex_lock(&peer->lock);

	/* Reject if peer has no mailboxes configured */
	if (AST_LIST_EMPTY(&peer->mailboxes)) {
		ast_mutex_unlock(&peer->lock);
		ast_log(LOG_NOTICE,
			"Sofia MWI: SUBSCRIBE for peer '%s' has no mailbox= configured — 404\n",
			peer->name);
		nua_respond(nh, SIP_404_NOT_FOUND, NUTAG_WITH_THIS(nua), TAG_END());
		ao2_ref(peer, -1);
		return;
	}

	/* R4 1-cap: capture existing handle (if any) for terminate-old; assign new. */
	old_nh = peer->mwi_subscription_handle;
	peer->mwi_subscription_handle = nh;

	ast_mutex_unlock(&peer->lock);

	/* All peer-state mutations done; safe to do nua_* ops without peer->lock. */
	if (old_nh) {
		nua_notify(old_nh,
			SIPTAG_EVENT_STR("message-summary"),
			SIPTAG_SUBSCRIPTION_STATE_STR("terminated;reason=deactivated"),
			TAG_END());
		nua_handle_destroy(old_nh);
	}

	/* R1 Option A: bind nh as nua_notifier — sofia-sip opens server-side
	 * dialog + auto-emits Subscription-State. T55.4 wires the RFC 6665 §4.4.1
	 * initial NOTIFY body via transmit_mwi_notify_for_peer immediately after. */
	{
		char expires_buf[16];
		int expiry = sofia_cfg.mwi_expiry > 0 ? sofia_cfg.mwi_expiry : 3600;
		snprintf(expires_buf, sizeof(expires_buf), "%d", expiry);
		nua_notifier(nh,
			SIPTAG_EVENT_STR("message-summary"),
			SIPTAG_EXPIRES_STR(expires_buf),
			TAG_END());
	}

	/* T55.4 (2026-04-27): RFC 6665 §4.4.1 — initial NOTIFY immediately after
	 * accepting SUBSCRIBE. Already on sofia_thread; transmit takes peer->lock
	 * internally for mailbox traversal (we released peer->lock above). */
	transmit_mwi_notify_for_peer(peer);

	if (sofia_debug) {
		ast_verbose("Sofia MWI: SUBSCRIBE accepted for peer '%s'\n", peer->name);
	}

	ao2_ref(peer, -1);
	/* nh ownership: peer->mwi_subscription_handle field holds the borrowed
	 * pointer; cleanup is via sofia_peer_destructor (T55 R10 path — to be
	 * wired in T55.5 with cross-thread dispatch since destructor may run
	 * off sofia_thread). */
}

static void sofia_process_subscribe(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	const char *event = NULL;

	if (sip && sip->sip_event && sip->sip_event->o_type) {
		event = sip->sip_event->o_type;
	}

	/* post-T56 allowsubscribe global ban gate (2026-04-27): chan_sip parity at
	 * chan_sip.c:25856 — when sofia_cfg.allowsubscribe (DERIVED) is FALSE, NO
	 * peer in the system allows subscriptions; reject upfront before any
	 * peer-lookup or event-routing. Verbatim "403 Forbidden (policy)" string
	 * (operator AMI/log scripts pattern-match exact text including parens). */
	if (!sofia_cfg.allowsubscribe) {
		nua_respond(nh, 403, "Forbidden (policy)",
			NUTAG_WITH_THIS(nua), TAG_END());
		sofia_emit_subscribe_rejected(sip, NULL,
			S_OR(event, "(missing)"), "AllowSubscribeClosed");
		return;
	}

	/* T55.3 (2026-04-27): split by Event package. message-summary -> MWI handler;
	 * unknown events fall through to legacy auto-202 (preserves T55.1-and-prior
	 * behavior; future T-tasks will add presence/dialog/etc. paths here). */
	if (event && !strcasecmp(event, "message-summary")) {
		sofia_process_mwi_subscribe(nua, nh, op, sip, tags);
		return;
	}

	if (sofia_debug) {
		ast_verbose("Sofia: Received SUBSCRIBE Event=%s (unhandled, auto-202)\n",
			S_OR(event, "(missing)"));
	}
	nua_respond(nh, SIP_202_ACCEPTED,
		NUTAG_WITH_THIS(nua),
		SIPTAG_EXPIRES_STR("3600"),
		TAG_END());
}

static void sofia_process_notify(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	if (sofia_debug)
		ast_verbose("Sofia: Received NOTIFY\n");
	nua_respond(nh, SIP_200_OK, TAG_END());
}

/* post-T56 REFER blind-transfer fix (2026-04-27): 3-method bridged-channel
 * finder, extracted from inline ATTENDED-branch duplication. Pattern 5
 * helper at 2 callsites (ATTENDED + BLIND) — 23rd reusable helper.
 *
 * Methods (try in order):
 *  (1) ast_bridged_channel(op->owner)         — _bridge pointer (no ref bump)
 *  (2) BRIDGEPEER channel-var name lookup     — set by ast_bridge_call;
 *      ast_channel_get_by_name_prefix bumps refcount (+1 ref); see NOTE
 *  (3) dialogs container walk by linkedid      — finds the other Sofia leg
 *
 * Returns: borrowed ast_channel pointer (do NOT unref), or NULL when none
 * found. Callers immediately use the pointer (e.g. ast_async_goto +
 * ast_queue_hangup the transferer); no long-lived reference is held.
 *
 * NOTE: Method 2 leaks the +1 ref obtained from ast_channel_get_by_name_prefix
 * — pre-existing behavior in chan_sofia ATTENDED branch, preserved here for
 * minimum-blast-radius. In practice the channel survives because it's still
 * bridged (held by its bridge partner ref). Separate cleanup task. */
static struct ast_channel *sofia_find_bridged_channel(struct sofia_pvt *op)
{
	struct ast_channel *bridged = NULL;
	const char *bridgepeer_name = NULL;

	if (!op || !op->owner) {
		return NULL;
	}

	/* Method 1: _bridge pointer */
	bridged = ast_bridged_channel(op->owner);
	if (bridged) {
		if (sofia_debug) {
			ast_verbose("Sofia: bridged-finder method 1 (_bridge): %s\n", bridged->name);
		}
		return bridged;
	}

	/* Method 2: BRIDGEPEER channel-var (set by ast_bridge_call) */
	bridgepeer_name = pbx_builtin_getvar_helper(op->owner, "BRIDGEPEER");
	if (bridgepeer_name && !ast_strlen_zero(bridgepeer_name)) {
		bridged = ast_channel_get_by_name_prefix(bridgepeer_name, strlen(bridgepeer_name));
		if (bridged) {
			if (sofia_debug) {
				ast_verbose("Sofia: bridged-finder method 2 (BRIDGEPEER=%s): %s\n",
					bridgepeer_name, bridged->name);
			}
			return bridged;
		}
	}

	/* Method 3: dialogs container linkedid walk (sibling Sofia leg) */
	{
		struct ao2_iterator it = ao2_iterator_init(dialogs, 0);
		struct sofia_pvt *p;
		while ((p = ao2_iterator_next(&it))) {
			if (p != op && p->owner && p->owner->linkedid &&
				op->owner->linkedid &&
				!strcmp(p->owner->linkedid, op->owner->linkedid)) {
				bridged = p->owner;
				if (sofia_debug) {
					ast_verbose("Sofia: bridged-finder method 3 (linkedid=%s): %s\n",
						op->owner->linkedid, bridged->name);
				}
				ao2_ref(p, -1);
				break;
			}
			ao2_ref(p, -1);
		}
		ao2_iterator_destroy(&it);
	}

	return bridged;
}

struct sofia_replaces_info {
	char callid[256];
	char to_tag[128];
	char from_tag[128];
};

static int sofia_hexval(int c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;
}

static void sofia_url_decode(const char *src, char *dst, size_t dstlen)
{
	size_t di = 0;

	if (!dstlen) {
		return;
	}
	if (!src) {
		dst[0] = '\0';
		return;
	}

	while (*src && di + 1 < dstlen) {
		if (*src == '%' && src[1] && src[2]) {
			int hi = sofia_hexval((unsigned char) src[1]);
			int lo = sofia_hexval((unsigned char) src[2]);
			if (hi >= 0 && lo >= 0) {
				dst[di++] = (char) ((hi << 4) | lo);
				src += 3;
				continue;
			}
		}
		dst[di++] = *src++;
	}
	dst[di] = '\0';
}

static int sofia_parse_replaces_query(const char *query, struct sofia_replaces_info *out)
{
	const char *p;

	if (!query || !out) {
		return -1;
	}

	memset(out, 0, sizeof(*out));
	p = query;
	while (*p) {
		const char *end = strchr(p, '&');
		size_t len = end ? (size_t) (end - p) : strlen(p);

		if (len > 9 && !strncasecmp(p, "Replaces=", 9)) {
			char encoded[512];
			char decoded[512];
			char *saveptr = NULL;
			char *tok;

			len -= 9;
			if (len >= sizeof(encoded)) {
				len = sizeof(encoded) - 1;
			}
			memcpy(encoded, p + 9, len);
			encoded[len] = '\0';
			sofia_url_decode(encoded, decoded, sizeof(decoded));

			tok = strtok_r(decoded, ";", &saveptr);
			if (!tok || ast_strlen_zero(tok)) {
				return -1;
			}
			ast_copy_string(out->callid, tok, sizeof(out->callid));
			while ((tok = strtok_r(NULL, ";", &saveptr))) {
				if (!strncasecmp(tok, "to-tag=", 7)) {
					ast_copy_string(out->to_tag, tok + 7, sizeof(out->to_tag));
				} else if (!strncasecmp(tok, "from-tag=", 9)) {
					ast_copy_string(out->from_tag, tok + 9, sizeof(out->from_tag));
				}
			}
			return 0;
		}

		if (!end) {
			break;
		}
		p = end + 1;
	}

	return -1;
}

static struct sofia_pvt *sofia_find_dialog_by_callid(const char *callid, struct sofia_pvt *exclude)
{
	struct ao2_iterator it;
	struct sofia_pvt *p;

	if (ast_strlen_zero(callid)) {
		return NULL;
	}

	it = ao2_iterator_init(dialogs, 0);
	while ((p = ao2_iterator_next(&it))) {
		if (p != exclude && !ast_strlen_zero(p->callid) && !strcmp(p->callid, callid)) {
			ao2_iterator_destroy(&it);
			return p;
		}
		ao2_ref(p, -1);
	}
	ao2_iterator_destroy(&it);

	return NULL;
}

static struct ast_channel *sofia_ref_bridged_channel(struct ast_channel *owner)
{
	struct ast_channel *bridged = NULL;
	const char *bridgepeer_name = NULL;

	if (!owner) {
		return NULL;
	}

	bridged = ast_bridged_channel(owner);
	if (bridged) {
		ast_channel_ref(bridged);
		return bridged;
	}

	bridgepeer_name = pbx_builtin_getvar_helper(owner, "BRIDGEPEER");
	if (!ast_strlen_zero(bridgepeer_name)) {
		bridged = ast_channel_get_by_name_prefix(bridgepeer_name, strlen(bridgepeer_name));
	}

	return bridged;
}

static void sofia_quiet_chan(struct ast_channel *chan)
{
	if (chan && chan->_state == AST_STATE_UP) {
		if (ast_test_flag(chan, AST_FLAG_MOH)) {
			ast_moh_stop(chan);
		} else if (chan->generatordata) {
			ast_deactivate_generator(chan);
		}
	}
}

static int sofia_local_attended_transfer(struct sofia_pvt *transferer, const struct sofia_replaces_info *replaces)
{
	struct sofia_pvt *target_pvt;
	struct ast_channel *transferer_chan = NULL;
	struct ast_channel *transferee_chan = NULL;
	struct ast_channel *target_chan = NULL;
	struct ast_channel *target_peer_chan = NULL;
	struct ast_channel *chans[2];
	int res = -1;

	if (!transferer || !transferer->owner || !replaces || ast_strlen_zero(replaces->callid)) {
		return -1;
	}

	target_pvt = sofia_find_dialog_by_callid(replaces->callid, transferer);
	if (!target_pvt) {
		return 1; /* Not local; caller may fall back to remote attended behavior. */
	}

	if (!target_pvt->owner) {
		ast_log(LOG_WARNING, "Sofia: attended transfer Replaces call '%s' has no owner channel\n",
			replaces->callid);
		ao2_ref(target_pvt, -1);
		return -1;
	}

	transferer_chan = ast_channel_ref(transferer->owner);
	transferee_chan = sofia_ref_bridged_channel(transferer_chan);
	target_chan = ast_channel_ref(target_pvt->owner);
	target_peer_chan = sofia_ref_bridged_channel(target_chan);

	if (!transferee_chan || !target_peer_chan) {
		ast_log(LOG_WARNING, "Sofia: attended transfer Replaces call '%s' missing bridge "
			"(transferee=%s targetpeer=%s)\n",
			replaces->callid,
			transferee_chan ? transferee_chan->name : "(none)",
			target_peer_chan ? target_peer_chan->name : "(none)");
		goto cleanup;
	}

	if (sofia_debug) {
		ast_verbose("Sofia: attended transfer local bridge %s <-> %s using Replaces %s\n",
			transferee_chan->name, target_peer_chan->name, replaces->callid);
	}

	sofia_quiet_chan(transferer_chan);
	sofia_quiet_chan(target_chan);
	sofia_quiet_chan(transferee_chan);
	sofia_quiet_chan(target_peer_chan);

	res = ast_channel_masquerade(target_chan, transferee_chan);
	if (res) {
		ast_log(LOG_WARNING, "Sofia: attended transfer masquerade failed (%s into %s)\n",
			transferee_chan->name, target_chan->name);
		goto cleanup;
	}

	chans[0] = transferer_chan;
	chans[1] = target_chan;
	ast_manager_event_multichan(EVENT_FLAG_CALL, "Transfer", 2, chans,
		"TransferMethod: SIP\r\n"
		"TransferType: Attended\r\n"
		"Channel: %s\r\n"
		"Uniqueid: %s\r\n"
		"SIP-Callid: %s\r\n"
		"TargetChannel: %s\r\n"
		"TargetUniqueid: %s\r\n",
		transferer_chan->name,
		transferer_chan->uniqueid,
		transferer->callid,
		target_chan->name,
		target_chan->uniqueid);

	ast_do_masquerade(target_chan);
	if (ast_channel_make_compatible(target_chan, target_peer_chan)) {
		ast_log(LOG_WARNING, "Sofia: attended transfer could not make %s and %s codec-compatible\n",
			target_chan->name, target_peer_chan->name);
	}
	ast_indicate(target_chan, AST_CONTROL_SRCCHANGE);
	ast_indicate(target_peer_chan, AST_CONTROL_SRCCHANGE);
	ast_indicate(target_chan, AST_CONTROL_UNHOLD);
	ast_indicate(target_peer_chan, AST_CONTROL_UNHOLD);
	res = 0;

cleanup:
	if (target_peer_chan) {
		ast_channel_unref(target_peer_chan);
	}
	if (target_chan) {
		ast_channel_unref(target_chan);
	}
	if (transferee_chan) {
		ast_channel_unref(transferee_chan);
	}
	if (transferer_chan) {
		ast_channel_unref(transferer_chan);
	}
	ao2_ref(target_pvt, -1);

	return res;
}

/* post-T56 RFC 3515 NOTIFY-sipfrag transfer-progress (2026-04-27): emits
 * NOTIFY message/sipfrag to the transferer (REFER originator) signaling
 * progress + final outcome of the transfer. Closes Pattern 12 honest-disclosure
 * 10th-instance (deferred from commit 7ff03dc REFER bridged-redirect fix).
 *
 * chan_sip parity at chan_sip.c:13823 transmit_notify_with_sipfrag — 12
 * callsites in chan_sip emit various sipfrag status strings:
 *   - "180 Ringing" (chan_sip.c:24913, terminate=FALSE) — in-progress
 *   - "200 OK" (chan_sip.c:22665 + L24469 + L24974, terminate=TRUE) — terminal success
 *   - "503 Service Unavailable (cant handle one-legged xfers)" (chan_sip.c:24929,
 *     terminate=TRUE) — terminal failure when transferee leg unavailable
 *
 * Pattern 16 sofia-sip-native-protocol-mechanics 8th-instance — uses 5 sofia-sip
 * native tags within helper: NUTAG_NEWSUB + NUTAG_SUBSTATE +
 * SIPTAG_SUBSCRIPTION_STATE_STR + SIPTAG_CONTENT_TYPE_STR + SIPTAG_PAYLOAD_STR
 * + SIPTAG_EVENT_STR. FreeSWITCH mod_sofia.c:1268-1273 verbatim recipe.
 *
 * Helper signature: terminate=0 → in-progress (NUTAG_SUBSTATE active); terminate=1
 * → terminal (NUTAG_SUBSTATE terminated;reason=noresource). Maps to chan_sip's
 * `int terminate` parameter at chan_sip.c:13823.
 *
 * chan_sofia surpass — AMI ReferProgress event emitted at every NOTIFY emission
 * (chan_sip silent). Channel + Peer + Status + Direction fields for NMS visibility.
 *
 * Pattern 5 24th reusable helper — extracted at 3 callsites (in-progress 180 +
 * terminal-success 200 + terminal-failure 503) within sofia_process_refer. */
static void sofia_send_refer_notify(struct sofia_pvt *op, const char *sipfrag_status, int terminate)
{
	char payload[64];
	char target_url[256];
	int use_target;

	if (!op || !op->nh || ast_strlen_zero(sipfrag_status)) {
		return;
	}

	snprintf(payload, sizeof(payload), "SIP/2.0 %s\r\n", sipfrag_status);
	use_target = sofia_pvt_build_nat_target_url(op, target_url, sizeof(target_url));

	nua_notify(op->nh,
		NUTAG_NEWSUB(1),
		TAG_IF(use_target, NUTAG_PROXY(target_url)),
		SIPTAG_CONTENT_TYPE_STR("message/sipfrag;version=2.0"),
		NUTAG_SUBSTATE(terminate ? nua_substate_terminated : nua_substate_active),
		SIPTAG_SUBSCRIPTION_STATE_STR(terminate ? "terminated;reason=noresource" : "active"),
		SIPTAG_PAYLOAD_STR(payload),
		SIPTAG_EVENT_STR("refer"),
		TAG_END());

	manager_event(EVENT_FLAG_SYSTEM, "ReferProgress",
		"Channel: %s\r\n"
		"Peer: SIP/%s\r\n"
		"Status: %s\r\n"
		"Direction: %s\r\n",
		op->owner ? op->owner->name : "",
		op->peername ? op->peername : "",
		sipfrag_status,
		terminate ? "terminal" : "in-progress");
}

static void sofia_process_refer(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	const char *refer_to = NULL;
	struct sofia_replaces_info replaces;
	int is_attended = 0;

	memset(&replaces, 0, sizeof(replaces));
	if (sip && sip->sip_refer_to && sip->sip_refer_to->r_url) {
		refer_to = sip->sip_refer_to->r_url->url_user;
		/* Detect attended transfer: Replaces parameter in Refer-To URI headers */
		if (sip->sip_refer_to->r_url->url_headers) {
			if (!sofia_parse_replaces_query(sip->sip_refer_to->r_url->url_headers, &replaces)) {
				is_attended = 1;
			}
		}
	}

	/* post-T56 allowexternaldomains [general] parity (2026-04-28, FULL WIRE-IN
	 * Pattern 5 helper #30): mirror chan_sip.c:16410-16425 verbatim semantic.
	 * Reject REFER targeting non-local SIP domain when domain_list non-empty AND
	 * Refer-To domain not in domain_list AND !allow_external_domains. */
	if (!AST_LIST_EMPTY(&domain_list) && !sofia_cfg.allow_external_domains
	    && sip && sip->sip_refer_to && sip->sip_refer_to->r_url
	    && sip->sip_refer_to->r_url->url_host
	    && !sofia_check_sip_domain(sip->sip_refer_to->r_url->url_host)) {
		ast_debug(1, "Sofia: Got REFER to non-local domain '%s'; refusing request.\n",
			sip->sip_refer_to->r_url->url_host);
		nua_respond(nh, SIP_403_FORBIDDEN, NUTAG_WITH_THIS(nua), TAG_END());
		return;
	}

	if (sofia_debug)
		ast_verbose("Sofia: REFER from %s to %s%s\n",
			op ? op->username : "unknown",
			refer_to ? refer_to : "unknown",
			is_attended ? " (ATTENDED)" : " (BLIND)");

	/* post-T56 allowtransfer per-peer parity (2026-04-27): chan_sip-parity REFER
	 * gate at chan_sip.c:24655. When dialog (or its peer) has allowtransfer=no,
	 * reject the REFER with 603 Declined (policy) — VERBATIM string per chan_sip
	 * parity (operator AMI/log scripts pattern-match this exact text). Early
	 * return BEFORE 202 Accepted (the transfer body is never accepted nor
	 * processed). chan_sofia surpass: AMI TransferRejected event for real-time
	 * REFER-abuse monitoring (chan_sip silently rejects with history-only log;
	 * NMS systems lack a signal to act on). */
	if (op && op->allowtransfer == TRANSFER_CLOSED) {
		nua_respond(nh, 603, "Declined (policy)",
			NUTAG_WITH_THIS(nua),
			TAG_END());
		manager_event(EVENT_FLAG_CALL, "TransferRejected",
			"Channel: %s\r\n"
			"Uniqueid: %s\r\n"
			"Peer: SIP/%s\r\n"
			"ReferTo: %s\r\n"
			"Reason: AllowTransferClosed\r\n",
			op->owner ? op->owner->name : "",
			op->owner ? op->owner->uniqueid : "",
			op->peername ? op->peername : "",
			refer_to ? refer_to : "");
		if (sofia_debug)
			ast_verbose("Sofia: REFER rejected (allowtransfer=no) — 603 Declined (policy)\n");
		return;
	}

	nua_respond(nh, SIP_202_ACCEPTED,
		NUTAG_WITH_THIS(nua),
		TAG_END());

	if (!refer_to || !op || !op->owner) {
		ast_log(LOG_WARNING, "Sofia: REFER missing Refer-To or no active call\n");
		return;
	}

	/* post-T56 identity-headers parity SS5 (2026-04-27): REFER may carry
	 * Diversion header for transfer-source attribution. Update redirecting
	 * chain before transfer dispatch so child Dial inherits the chain. */
	sofia_change_redirecting_info(op, sip);

	if (is_attended) {
		int attended_res;

		attended_res = sofia_local_attended_transfer(op, &replaces);
		if (attended_res == 0) {
			sofia_send_refer_notify(op, "200 OK", 1);
			ast_queue_hangup(op->owner);
			return;
		} else if (attended_res < 0) {
			sofia_send_refer_notify(op, "486 Busy Here", 1);
			return;
		}

		/* Replaces did not identify a local dialog. Fall through to the existing
		 * remote attended-transfer behavior, which routes the transferee through
		 * dialplan and lets outbound INVITE generation carry future remote-Replaces
		 * support. */
	}

		/* Blind transfer and remote attended-transfer fallback redirect the
		 * transferee (bridged peer = the held leg) to the Refer-To extension via
		 * ast_async_goto. Local attended transfer with Replaces is handled above
		 * using chan_sip's masquerade model and must not create a new call.
		 *
		 * Order critical: ast_queue_hangup MUST run AFTER find-bridged +
		 * ast_async_goto + all NOTIFY emissions, because hanging up op->owner tears
	 * down channel state the bridged-finder relies on (Methods 2+3 walk
	 * op->owner's vars/linkedid) AND the NOTIFY emit needs op->nh + op->owner
	 * state alive for AMI ReferProgress event Channel + Peer fields.
	 *
	 * post-T56 RFC 3515 NOTIFY-sipfrag transfer-progress (2026-04-27): closes
	 * Pattern 12 honest-disclosure 10th-instance deferral from commit 7ff03dc.
	 * Helper sofia_send_refer_notify emits NOTIFY message/sipfrag at 3 sites:
	 *  - "180 Ringing" before ast_async_goto (in-progress; chan_sip.c:24913)
	 *  - "200 OK" after ast_async_goto (terminal success; chan_sip.c:22665)
	 *  - "503 Service Unavailable (cant handle one-legged xfers)" when bridged
	 *    NULL (terminal failure; chan_sip.c:24929 verbatim paren-tail). */
	{
		struct ast_channel *bridged = sofia_find_bridged_channel(op);

		if (sofia_debug) {
			ast_verbose("Sofia: %s transfer to %s — bridged=%s\n",
				is_attended ? "Attended" : "Blind",
				refer_to,
				bridged ? bridged->name : "(none)");
		}

		if (bridged) {
			if (sofia_debug) {
				ast_verbose("Sofia: redirecting %s to %s@%s\n",
					bridged->name, refer_to, op->context);
			}
			/* RFC 3515: in-progress NOTIFY before transferee redirect. */
			sofia_send_refer_notify(op, "180 Ringing", 0);
			/* Match chan_sip blind-transfer media handling: the transferer
			 * commonly sends hold before REFER, so unhold the transferee before
			 * redirecting it. Doing this before ast_async_goto keeps the
			 * indication on the real channel when local channels/masquerades are
			 * involved. */
			ast_indicate(bridged, AST_CONTROL_UNHOLD);
			ast_async_goto(bridged, op->context, refer_to, 1);
			/* RFC 3515: terminal NOTIFY after redirect dispatched. ast_async_goto
			 * is async-fire-and-forget; operator semantic = REFER successfully
			 * accepted + routed (chan_sip.c:22665 parking parity). */
			sofia_send_refer_notify(op, "200 OK", 1);

			/* chan_sip parity (SIP_DEFER_BYE_ON_TRANSFER at chan_sip.c:24949
			 * + L7051-7067 + comment "Do not hangup call, the other side do that
			 * when we say 200 OK"). RFC 5589 §6.1 — after the terminal NOTIFY
			 * 200 OK, the transferer's UA owns the dialog teardown via BYE.
			 * Issuing our own nua_bye now would race the pending terminal NOTIFY
			 * inside sofia-sip and silently drop it, leaving the UA stuck on a
			 * dialog with no audio.
			 *
			 * Mark the pvt as defer-bye so sofia_hangup skips its nua_bye when
			 * the channel core eventually tears the leg down (which happens
			 * naturally once Dial returns after ast_async_goto breaks the
			 * bridge). Arm a SOFIA_DEFER_BYE_TIMEOUT_MS safety-net timer that
			 * fires nua_bye if the UA misbehaves and never BYEs us. */
			ast_mutex_lock(&op->lock);
			if (sofia_sched && op->defer_bye_sched_id == -1) {
				op->defer_bye = 1;
				ao2_ref(op, +1);
				op->defer_bye_sched_id = ast_sched_thread_add(sofia_sched,
					SOFIA_DEFER_BYE_TIMEOUT_MS, sofia_defer_bye_cb, op);
				if (op->defer_bye_sched_id < 0) {
					/* sched_add failed — drop the speculative ref and fall
					 * through to the natural sofia_hangup nua_bye path. */
					ao2_ref(op, -1);
					op->defer_bye = 0;
					op->defer_bye_sched_id = -1;
				}
			}
			ast_mutex_unlock(&op->lock);
		} else {
			ast_log(LOG_WARNING, "Sofia: %s transfer to %s — no bridged channel found "
				"(tried _bridge, BRIDGEPEER, linkedid); transferee will not be redirected\n",
				is_attended ? "Attended" : "Blind", refer_to);
			/* RFC 3515: terminal failure NOTIFY when bridged-finder NULL.
			 * chan_sip.c:24929 verbatim paren-tail preserved for operator-script
			 * grep compat. */
			sofia_send_refer_notify(op, "503 Service Unavailable (cant handle one-legged xfers)", 1);
			/* No bridged peer to redirect — tear the transferer leg down
			 * immediately (chan_sip parity: failure path does not set
			 * SIP_DEFER_BYE_ON_TRANSFER at chan_sip.c:25002). */
			ast_queue_hangup(op->owner);
		}
	}
}

static void sofia_process_info(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	const char *content_type = NULL;
	const char *body = NULL;
	char digit = '\0';
	unsigned int duration = 250;

	nua_respond(nh, SIP_200_OK, TAG_END());

	if (!sip || !op || !op->owner) {
		return;
	}

	if (sip->sip_content_type) {
		content_type = sip->sip_content_type->c_type;
	}

	if (sip->sip_payload && sip->sip_payload->pl_data) {
		body = sip->sip_payload->pl_data;
	}

	if (!content_type || !body) {
		return;
	}

	/* application/dtmf-relay: Signal=X\r\nDuration=Y */
	if (strstr(content_type, "application/dtmf-relay")) {
		const char *sig = strstr(body, "Signal=");
		const char *dur = strstr(body, "Duration=");
		if (sig) {
			sig += strlen("Signal=");
			while (*sig == ' ') sig++;
			digit = *sig;
		}
		if (dur) {
			dur += strlen("Duration=");
			duration = atoi(dur);
		}
	}
	/* application/dtmf: single digit in body */
	else if (strstr(content_type, "application/dtmf")) {
		digit = body[0];
	}

	if (digit && digit != ' ') {
		struct ast_frame f = {
			.frametype = AST_FRAME_DTMF_BEGIN,
			.subclass.integer = digit,
			.src = __PRETTY_FUNCTION__,
		};
		ast_queue_frame(op->owner, &f);

		f.frametype = AST_FRAME_DTMF_END;
		f.len = duration;
		ast_queue_frame(op->owner, &f);

		if (sofia_debug)
			ast_verbose("Sofia: Received DTMF '%c' via SIP INFO (duration=%u)\n", digit, duration);
	}
}

static void sofia_process_publish(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	if (sofia_debug)
		ast_verbose("Sofia: Received PUBLISH\n");
	nua_respond(nh, SIP_200_OK,
		NUTAG_WITH_THIS(nua),
		SIPTAG_EXPIRES_STR("3600"),
		TAG_END());
}

static void sofia_process_prack(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	if (sofia_debug)
		ast_verbose("Sofia: Received PRACK\n");
	nua_respond(nh, SIP_200_OK, TAG_END());
}

static void sofia_process_ack(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	if (op) {
		op->state = SOFIA_DIALOG_STATE_UP;
		/* For late-offer INVITEs (no SDP in INVITE), the ACK may carry SDP */
		if (sip && sip->sip_payload && sip->sip_payload->pl_data && op->rtp) {
			sofia_parse_sdp(op, sip);
			if (sofia_debug)
				ast_verbose("Sofia: ACK with SDP, remote RTP set\n");
		}
	}
}

static void sofia_qualify_peer(struct sofia_peer *peer)
{
	char url[256];
	nua_handle_t *nh;

	if (!sofia_nua || !peer->registered)
		return;

	ast_mutex_lock(&peer->lock);

	/* Skip if a qualify is already pending (response not yet received) */
	if (peer->qualify_nh) {
		ast_mutex_unlock(&peer->lock);
		return;
	}

	sofia_resolve_peer_target(peer, peer->defaultuser, url, sizeof(url));

	nh = nua_handle(sofia_nua, peer, NUTAG_URL(url), TAG_END());
	if (!nh) {
		ast_mutex_unlock(&peer->lock);
		return;
	}

	peer->qualify_nh = nh;
	peer->qualify_sent = ast_tvnow();
	if (sofia_debug)
			ast_verbose("Sofia: Sending OPTIONS qualify to %s (url=%s, hmagic=%p)\n",
			peer->name, url, (void *)peer);
	ast_mutex_unlock(&peer->lock);

	nua_options(nh,
		SIPTAG_FROM_STR(url),
		NUTAG_WITH_THIS(sofia_nua),
		TAG_END());
}

static void *sofia_qualify_thread(void *data)
{
	while (sofia_nua) {
		struct sofia_peer *peer;
		struct ao2_iterator i;

		sleep(1);

		if (!sofia_nua)
			break;

		i = ao2_iterator_init(peers, 0);
		while ((peer = ao2_iterator_next(&i))) {
			if (peer->qualify && peer->registered) {
				time_t now = time(NULL);
				time_t last_check = peer->last_qualify.tv_sec;
				int freq = peer->qualifyfreq > 0 ? peer->qualifyfreq : DEFAULT_QUALIFYFREQ;

				if (peer->peer_status == PEER_UNREACHABLE)
					freq = DEFAULT_FREQ_NOTOK;

				if ((now - last_check) >= freq) {
					sofia_qualify_peer(peer);
				}
			}
			ao2_ref(peer, -1);
		}
		ao2_iterator_destroy(&i);
	}

	return NULL;
}

static void sofia_event_callback(nua_event_t event, int status, char const *phrase,
		nua_t *nua, nua_magic_t *magic,
		nua_handle_t *nh, nua_hmagic_t *hmagic,
		sip_t const *sip, tagi_t tags[])
{
	struct sofia_pvt *pvt = (struct sofia_pvt *)hmagic;
	const char *event_name = nua_event_name(event);

	/* Debug-gated event logging for peer/ip filter modes */
	if (sofia_debug > 1 && sip) {
		const char *peer = NULL;
		const char *src_ip = NULL;
		char src_buf[128];

		if (sip->sip_from && sip->sip_from->a_url && sip->sip_from->a_url->url_user)
			peer = sip->sip_from->a_url->url_user;
		if (sip->sip_via) {
			if (sip->sip_via->v_received)
				src_ip = sip->sip_via->v_received;
			else if (sip->sip_via->v_host)
				src_ip = sip->sip_via->v_host;
		}
		if (!src_ip) src_ip = "";
		snprintf(src_buf, sizeof(src_buf), "%s", src_ip);

		if (sofia_debug_match(peer, src_buf)) {
			ast_verbose("Sofia [%s]: peer=%s src=%s status=%d %s\n",
				event_name, peer ? peer : "(none)", src_buf, status, phrase);
		}
	}

	switch (event) {
	case nua_i_invite:
	case nua_i_bye:
	case nua_i_cancel:
	case nua_i_options:
	case nua_i_register:
	case nua_i_message:
	case nua_i_subscribe:
	case nua_i_notify:
	case nua_i_refer:
	case nua_i_info:
	case nua_i_publish:
	case nua_i_prack:
	case nua_i_ack:
		if (sofia_blacklist_check_sip(sip)) {
			return;
		}
		break;
	default:
		break;
	}

	switch (event) {
	case nua_i_invite:
		/* hmagic non-NULL means the nh has an existing dialog usage — treat as re-INVITE.
		 * NULL hmagic = fresh inbound INVITE → original sofia_process_invite path. */
		if (pvt) {
			sofia_process_reinvite(pvt, nua, nh, sip);
		} else {
			sofia_process_invite(nua, nh, pvt, sip, tags);
		}
		break;
	case nua_i_bye:
		sofia_process_bye(nua, nh, pvt, sip, tags);
		break;
	case nua_i_cancel:
		sofia_process_cancel(nua, nh, pvt, sip, tags);
		break;
	case nua_i_options:
		sofia_process_options(nua, nh, pvt, sip, tags);
		break;
	case nua_i_register:
		sofia_process_register(nua, nh, pvt, sip, tags);
		break;
	case nua_i_message:
		sofia_process_message(nua, nh, pvt, sip, tags);
		break;
	case nua_i_subscribe:
		sofia_process_subscribe(nua, nh, pvt, sip, tags);
		break;
	case nua_i_notify:
		sofia_process_notify(nua, nh, pvt, sip, tags);
		break;
	case nua_i_refer:
		sofia_process_refer(nua, nh, pvt, sip, tags);
		break;
	case nua_i_info:
		sofia_process_info(nua, nh, pvt, sip, tags);
		break;
	case nua_i_publish:
		sofia_process_publish(nua, nh, pvt, sip, tags);
		break;
	case nua_i_prack:
		sofia_process_prack(nua, nh, pvt, sip, tags);
		break;
	case nua_i_ack:
		sofia_process_ack(nua, nh, pvt, sip, tags);
		break;

	case nua_r_register:
		ast_verbose("Sofia: REGISTER response %d %s\n", status, phrase);
		if (status == 200) {
			if (sip && sip->sip_contact) {
				int expires = DEFAULT_EXPIRY;
				if (sip->sip_expires && sip->sip_expires->ex_delta) {
					expires = sip->sip_expires->ex_delta;
				} else if (sip->sip_contact->m_expires) {
					expires = atoi(sip->sip_contact->m_expires);
				}
				ast_verbose("Sofia: Registration OK, expires=%d\n", expires);
				if (hmagic) {
					struct sofia_peer *peer = (struct sofia_peer *)hmagic;
					ast_mutex_lock(&peer->lock);
					peer->registered = 1;
					peer->reg_expiry = time(NULL) + expires - 10;
					peer->reg_attempts = 0;
					ast_mutex_unlock(&peer->lock);
					manager_event(EVENT_FLAG_SYSTEM, "Registry",
						"ChannelType: SIP\r\n"
						"Username: %s\r\n"
						"Domain: %s\r\n"
						"Status: Registered\r\n",
						peer->defaultuser, peer->host);
						/* post-T56 rtupdate [general] parity (2026-04-28, Option C combined-
						 * gate per Enginer R6 verdict): outbound REGISTER response handler
						 * realtime update gated by combined check. */
						if (peer->is_realtime && sofia_cfg.peer_rtupdate) {
							/* post-T56 rtsavesysname [general] parity (2026-04-28): inline 2-var
							 * setup mirroring chan_sip.c.bk:5103-5151 canonical pattern. */
							const char *sysname = ast_config_AST_SYSTEM_NAME;
							const char *syslabel = NULL;
							char port_str[32], regsec_str[32];
							if (ast_strlen_zero(sysname)) {
								sysname = NULL;
							} else if (sofia_cfg.rtsave_sysname) {
								syslabel = "regserver";
							}
							snprintf(port_str, sizeof(port_str), "%d", peer->port);
							snprintf(regsec_str, sizeof(regsec_str), "%ld", (long)time(NULL));
							ast_update_realtime(ast_check_realtime("sipregs") ? "sipregs" : "sippeers", "name", peer->name,
								"ipaddr", peer->host,
								"port", port_str,
								"regseconds", regsec_str,
								syslabel, sysname,
								SENTINEL);
						}
					}
				}
			} else if (status == 401 || status == 407) {
			if (hmagic) {
				struct sofia_peer *peer = (struct sofia_peer *)hmagic;
				char auth_creds[256];
				char uri[256];

				ast_mutex_lock(&peer->lock);

				/* post-T56 registerattempts parity (2026-04-27): chan_sip parity at
				 * chan_sip.c:14092 verbatim attempt-cap gate — when register_attempts > 0
				 * AND peer has reached the cap, give up on auth-challenge re-register
				 * to prevent runaway authentication storms. */
				if (sofia_cfg.register_attempts > 0 && peer->reg_attempts >= sofia_cfg.register_attempts) {
					ast_log(LOG_NOTICE, "Sofia: Registration attempts exhausted for peer '%s' (reg_attempts=%d cap=%d) — giving up\n",
						peer->name, peer->reg_attempts, sofia_cfg.register_attempts);
					ast_mutex_unlock(&peer->lock);
					break;
				}

				snprintf(auth_creds, sizeof(auth_creds), "%s:%s",
					peer->defaultuser, peer->secret);
				/* Step A IPv6 parity SS3 (2026-04-28): bracket-wrap IPv6 host
				 * per RFC 3261 §19.1.2 — peer->host may be raw operator-config
				 * IPv6 literal (e.g. host=2001:db8::1). Helper #45 idempotent. */
				{
					char hbuf[80];
					snprintf(uri, sizeof(uri), "sip:%s@%s:%d", peer->defaultuser,
						sofia_uri_format_host(peer->host, hbuf, sizeof(hbuf)),
						peer->port);
				}

				ast_verbose("Sofia: Responding to auth challenge for %s\n", peer->name);

				/* post-T56 maxforwards parity (2026-04-27): RFC 3261 §20.22 outbound REGISTER. */
				char mf_str_reg[8];
				snprintf(mf_str_reg, sizeof(mf_str_reg), "%d", peer->maxforwards);
				/* post-T56 callbackextension per-peer parity (2026-04-28, Option A FULL
				 * WIRE-IN site 1/3 — auth-challenge re-REGISTER): when peer has
				 * callbackextension set, override Contact URL username via sofia-sip
				 * native NUTAG_M_USERNAME tag (mirrors chan_sip p->exten = r->callback
				 * → set_contact_string state-machine at chan_sip.c:14267-14269 verbatim
				 * semantic). Pattern 16 sofia-sip-native 12th-instance. */
				nua_register(peer->nh,
					NUTAG_URL(uri),
					SIPTAG_FROM_STR(uri),
					NUTAG_AUTH(auth_creds),
					SIPTAG_MAX_FORWARDS_STR(mf_str_reg),
					TAG_IF(!ast_strlen_zero(peer->callbackextension),
						NUTAG_M_USERNAME(peer->callbackextension)),
					TAG_END());

				peer->reg_attempts++;
				ast_mutex_unlock(&peer->lock);
			}
		} else if (status >= 300) {
			ast_verbose("Sofia: Registration failed %d %s\n", status, phrase);
			if (hmagic) {
				struct sofia_peer *peer = (struct sofia_peer *)hmagic;
				ast_mutex_lock(&peer->lock);
				peer->registered = 0;
				ast_mutex_unlock(&peer->lock);
				manager_event(EVENT_FLAG_SYSTEM, "Registry",
					"ChannelType: SIP\r\n"
					"Username: %s\r\n"
					"Domain: %s\r\n"
					"Status: Failed\r\n"
					"Cause: %d %s\r\n",
					peer->defaultuser, peer->host, status, phrase ? phrase : "");
			}
		}
		break;
	case nua_r_invite:
		if (sofia_debug)
			ast_verbose("Sofia: INVITE response %d %s\n", status, phrase);
		/* post-T56 session timers (RFC 4028) (2026-04-27): capture negotiated
		 * Session-Expires on every 200-OK (initial + refresh); R13.a sip show
		 * channels display reads pvt->session_negotiated_expires at any
		 * dialog-state. R13.b SessionTimerRefresh AMI fires only on REFRESH
		 * (dialog already UP at response-arrival time). */
		if (pvt && status == 200 && sip && sip->sip_session_expires) {
			int already_up = (pvt->state == SOFIA_DIALOG_STATE_UP);
			pvt->session_negotiated_expires = sip->sip_session_expires->x_delta;
			pvt->session_last_refresh_at = time(NULL);
			if (already_up) {
				/* R13.b uac-refresh AMI emit; chan_sofia surpass — chan_sip emits no equivalent. */
				manager_event(EVENT_FLAG_CALL, "SessionTimerRefresh",
					"Channel: %s\r\n"
					"Uniqueid: %s\r\n"
					"Peer: Sofia/%s\r\n"
					"SessionExpires: %d\r\n"
					"Refresher: %s\r\n"
					"Direction: uac\r\n",
					pvt->owner ? pvt->owner->name : "",
					pvt->owner ? pvt->owner->uniqueid : "",
					pvt->peername,
					(int)sip->sip_session_expires->x_delta,
					sip->sip_session_expires->x_refresher ? sip->sip_session_expires->x_refresher : "auto");
			}
		}
		if (pvt && pvt->is_fork_master) {
			ast_log(LOG_WARNING, "Sofia: master pvt received nua_r_invite (should not happen)\n");
			break;
		}
		if (pvt && pvt->is_fork_child && pvt->fork) {
			struct sofia_fork *fork = pvt->fork;
			if (status == 100) {
				break;
			}
			if (status >= 180 && status < 200) {
				int first;
				ast_mutex_lock(&fork->lock);
				first = (fork->state == FORK_PRE_RING);
				if (first) fork->state = FORK_RINGING;
				ast_mutex_unlock(&fork->lock);
				if (fork->master && fork->master->owner) {
					if (status == 183) {
						ast_queue_control(fork->master->owner, AST_CONTROL_PROGRESS);
					} else {
						ast_queue_control(fork->master->owner, AST_CONTROL_RINGING);
					}
					ast_setstate(fork->master->owner, AST_STATE_RINGING);
				}
				if (sofia_debug)
					ast_verbose("Sofia: Fork child %s -> %d %s (first=%d)\n",
						pvt->fork_branch_id, status, phrase, first);
			} else if (status >= 200 && status < 300) {
				int rc = sofia_fork_pick_winner(fork, pvt, sip);
				if (rc != 0) {
					nua_cancel(pvt->nh, TAG_END());
					ao2_unlink(dialogs, pvt);
					ao2_unlink(fork->children, pvt);
				}
			} else if (status >= 300) {
				int empty, picked;
				ast_mutex_lock(&fork->lock);
				fork->child_count--;
				ao2_unlink(fork->children, pvt);
				ast_mutex_unlock(&fork->lock);
				ao2_unlink(dialogs, pvt);
				ast_mutex_lock(&fork->lock);
				empty = (fork->child_count == 0);
				picked = fork->winner_picked;
				ast_mutex_unlock(&fork->lock);
				if (empty && !picked && fork->master && fork->master->owner) {
					ast_queue_control(fork->master->owner, AST_CONTROL_HANGUP);
				}
				if (sofia_debug)
					ast_verbose("Sofia: Fork child %s failed %d %s (remaining=%d)\n",
						pvt->fork_branch_id, status, phrase, fork->child_count);
			}
			break;
		}
		if (pvt && pvt->reinvite_pending && status >= 200) {
			/* Direct media re-INVITE response — call is already up.
			 * pvt->reinvite_pending and pvt->redirip are shared with the gabpbx
			 * bridge thread (sofia_set_rtp_peer); guard with pvt->lock. */
			int rejected = (status >= 300);
			int has_sdp = (!rejected && sip && sip->sip_payload && sip->sip_payload->pl_data);
			ast_mutex_lock(&pvt->lock);
			pvt->reinvite_pending = 0;
			if (rejected) {
				/* Peer refused (488 Not Acceptable etc); revert to PBX relay. */
				memset(&pvt->redirip, 0, sizeof(pvt->redirip));
			} else if (has_sdp) {
				/* 2xx — peer accepted; SDP tells us where they will send. */
				sofia_parse_sdp(pvt, sip);
			}
			ast_mutex_unlock(&pvt->lock);
			if (rejected) {
				ast_log(LOG_NOTICE, "Sofia: directmedia re-INVITE rejected on '%s' (%d %s) — staying in relay mode\n",
					pvt->callid ? pvt->callid : "(no-callid)", status, phrase ? phrase : "");
			} else if (has_sdp) {
				ast_verbose("Sofia: directmedia re-INVITE accepted on '%s'\n",
					pvt->callid ? pvt->callid : "(no-callid)");
			}
			break;
		}
		if (pvt) {
			if (status == 180) {
				pvt->state = SOFIA_DIALOG_STATE_RINGING;
				if (sip && sip->sip_payload && sip->sip_payload->pl_data) {
					sofia_parse_sdp(pvt, sip);
				}
				if (pvt->owner) {
					ast_queue_control(pvt->owner, AST_CONTROL_RINGING);
					ast_setstate(pvt->owner, AST_STATE_RINGING);
				}
			} else if (status == 183) {
				if (sip && sip->sip_payload && sip->sip_payload->pl_data) {
					sofia_parse_sdp(pvt, sip);
				}
				if (pvt->owner) {
					ast_queue_control(pvt->owner, AST_CONTROL_PROGRESS);
					ast_setstate(pvt->owner, AST_STATE_RINGING);
				}
			} else if (status == 200) {
				/* RFC 3261 13.2.2.4 / RFC 6026: a 200 OK for an INVITE we have
				 * already abandoned (a forking proxy sent 486 Busy Here and then
				 * 200 OK on the same dialog, or we already hung up the leg) must
				 * be ACKed and then BYEd, not turned into an answered call.
				 * Dropping it leaves the UAS retransmitting its 200 OK for 64*T1
				 * with a ghost media leg.
				 * NOTE: this only fires if the late 2xx is still delivered to us,
				 * i.e. the pvt / nua handle survived the orphan window.  The
				 * handle is released in sofia_pvt_destructor (nua_handle_destroy)
				 * when the last pvt ref drops; verify by test that teardown is
				 * deferred long enough to receive the late 2xx (RFC 6026 Timer M
				 * = 64*T1).  If not, also defer the pvt teardown on outbound
				 * final-failure (mirror chan_sip sip_scheddestroy DEFAULT_TRANS_TIMEOUT). */
				if (pvt->alreadygone || !pvt->owner) {
					char orphan_proxy_url[128];
					ast_log(LOG_NOTICE,
						"Sofia: orphan 200 OK on terminated INVITE %s: ACK + BYE per RFC 3261 13.2.2.4\n",
						pvt->callid ? pvt->callid : "(no-callid)");
					/* sofia-sip auto-ACKs unless AUTOACK(0) was set for a NAT
					 * peer; in that case emit the ACK ourselves (same condition
					 * as the answered path below). */
					if (sofia_build_nat_proxy_url_from_peer(pvt->peer, orphan_proxy_url, sizeof(orphan_proxy_url)))
						nua_ack(nh, NUTAG_PROXY(orphan_proxy_url), TAG_END());
					nua_bye(nh, TAG_END());
					break;
				}
				int sdp_rc = 0;
				if (sip && sip->sip_payload && sip->sip_payload->pl_data) {
					sdp_rc = sofia_parse_sdp(pvt, sip);
				}
				/* post-T56 identity-headers parity SS5 (2026-04-27): final 2xx
				 * may carry Diversion if downstream proxy redirected. Update
				 * redirecting chain on the master/originating channel — chan_sip
				 * parses redirect chain via parse_moved_contact at the same path. */
				if (pvt->owner) {
					sofia_change_redirecting_info(pvt, sip);
				}
				/* post-T56 call-limit parity SS2 R3 (2026-04-27): outbound
				 * ringing transition complete on 200 OK. Decrement inRinging
				 * (call still in inUse pool, decremented at hangup). chan_sip
				 * parity at L21448. */
				sofia_update_call_counter(pvt, SOFIA_DEC_CALL_RINGING);
				if (sdp_rc < 0) {
					/* T37: peer's 200 OK answer failed encryption policy
					 * (no a=crypto echo, downgraded to AVP, or invalid crypto).
					 * Tear down — BYE peer + queue HANGUP to channel. */
					ast_log(LOG_NOTICE, "Sofia: outbound 200 OK rejected — encryption mismatch in answer (peer=%s)\n",
						pvt->peer ? pvt->peer->name : "<unknown>");
					nua_bye(nh, TAG_END());
					if (pvt->owner) {
						ast_queue_control(pvt->owner, AST_CONTROL_HANGUP);
					}
					break;
				}
				/* NAT-aware manual ACK (chan_sip parity): for peers with
				 * nat=force_rport/comedia, sofia-sip's auto-ACK was disabled
				 * at nua_invite via NUTAG_AUTOACK(0). Emit the ACK ourselves
				 * with NUTAG_PROXY pointing at peer->src_addr (the registered
				 * public source) so the request bypasses the LAN-IP Contact
				 * URI sofia-sip would otherwise route to. Phones that don't
				 * see the ACK keep retransmitting 200 OK until they BYE the
				 * dialog — exactly the symptom this fix removes. */
				{
					char nat_proxy_url[128];
					if (sofia_build_nat_proxy_url_from_peer(pvt->peer,
							nat_proxy_url, sizeof(nat_proxy_url))) {
						nua_ack(nh, NUTAG_PROXY(nat_proxy_url), TAG_END());
					}
				}
				pvt->state = SOFIA_DIALOG_STATE_UP;
				if (pvt->owner) {
					ast_queue_control(pvt->owner, AST_CONTROL_ANSWER);
					ast_setstate(pvt->owner, AST_STATE_UP);
				}
				/* Set active contact for single-contact outbound path */
				if (pvt->peer && !pvt->is_fork_child && !pvt->fork && !ast_strlen_zero(pvt->ruri)) {
					const char *at = strchr(pvt->ruri, '@');
					if (at) {
						char rhost[64] = "";
						int rport = 5060;
						const char *colon = strchr(at + 1, ':');
						if (colon) {
							{ int hlen = colon - (at + 1); if (hlen >= (int)sizeof(rhost)) hlen = sizeof(rhost) - 1; ast_copy_string(rhost, at + 1, hlen + 1); }
							rport = atoi(colon + 1);
						} else {
							ast_copy_string(rhost, at + 1, sizeof(rhost));
							char *semi = strchr(rhost, ';');
							if (semi) *semi = '\0';
						}
						struct sofia_contact *contact = sofia_peer_find_contact_by_host_port(pvt->peer, rhost, rport);
						if (contact) {
							sofia_pvt_set_active_contact(pvt, contact);
							ao2_ref(contact, -1);
						}
					}
				}
			} else if (status == 484) {
				/* post-T56 allowoverlap per-peer + [general] parity (2026-04-28,
				 * Option A FULL WIRE-IN site C — nua_r_invite 484 status special-
				 * case): mirror chan_sip.c:22508-22518 verbatim outbound 484
				 * response handling. ALLOWOVERLAP_YES → propagate AST_CAUSE_INVALID
				 * _NUMBER_FORMAT (484 native semantic per chan_sip hangup_sip2cause
				 * at chan_sip.c:6866-6867); NO/DTMF → propagate AST_CAUSE_UNALLOCATED
				 * (404 semantic per chan_sip hangup_sip2cause at L6836-6837 — hides
				 * overlap-dial reality from caller). Effective mode = peer when
				 * bound; else sofia_cfg.default_allowoverlap_mode. */
				/* Mark dialog as gone BEFORE the channel hangup races, so a late
				 * 2xx (RFC 3261 §16.7-violating proxy) can be ACK+BYE'd by the
				 * orphan guard at the status==200 branch above. chan_sip parity:
				 * chan_sip.c:22570 sip_alreadygone(p) after the final-response
				 * switch. */
				sofia_alreadygone(pvt);
				if (pvt->owner) {
					int overlap_mode = pvt->peer ? pvt->peer->allowoverlap_mode : sofia_cfg.default_allowoverlap_mode;
					ast_queue_hangup_with_cause(pvt->owner,
						(overlap_mode == SOFIA_OVERLAP_YES)
							? AST_CAUSE_INVALID_NUMBER_FORMAT
							: AST_CAUSE_UNALLOCATED);
				}
			} else if (status >= 300) {
				/* Mark dialog as gone for the same reason as the 484 branch
				 * above: a forking proxy may relay a non-2xx final and then a
				 * 2xx on the same transaction (RFC 3261 §16.7 violation in the
				 * field). Setting alreadygone here lets the status==200 orphan
				 * guard recognise the late 2xx and emit ACK+BYE per RFC 3261
				 * §13.2.2.4 / RFC 6026 instead of dropping it silently. */
				sofia_alreadygone(pvt);
				if (pvt->owner) {
					ast_queue_control(pvt->owner, AST_CONTROL_HANGUP);
				}
			}
		}
		break;
	case nua_r_bye:
		if (sofia_debug)
			ast_verbose("Sofia: BYE response %d %s\n", status, phrase);
		/* post-T56 call-limit parity SS2 R9 (2026-04-27): nua_r_bye DEC site.
		 * Defensive — typically sofia_hangup already fired DEC, but flag-gated
		 * idempotency keeps multi-site safe. */
		if (pvt) {
			sofia_update_call_counter(pvt, SOFIA_DEC_CALL_LIMIT);
		}
		break;
	case nua_r_cancel:
		if (sofia_debug)
			ast_verbose("Sofia: CANCEL response %d %s\n", status, phrase);
		if (pvt && pvt->is_fork_child && pvt->fork) {
			ao2_unlink(dialogs, pvt);
			ao2_unlink(pvt->fork->children, pvt);
		}
		break;
	case nua_r_options:
			if (sofia_debug)
				ast_verbose("Sofia: OPTIONS response %d %s for peer %s (hmagic=%p)\n",
			status, phrase,
			hmagic ? ((struct sofia_peer *)hmagic)->name : "NULL",
			(void *)hmagic);
		/* Handle qualify response - hmagic is the peer for qualify pings */
		if (hmagic) {
			struct sofia_peer *peer = (struct sofia_peer *)hmagic;
			int pingtime = ast_tvdiff_ms(ast_tvnow(), peer->qualify_sent);
			if (pingtime < 1)
				pingtime = 1;

			ast_mutex_lock(&peer->lock);
			{
				enum sofia_peer_status old_status = peer->peer_status;
				if (status == 200) {
					int timeout = peer->qualifytimeout * 1000;
					if (timeout <= 0)
						timeout = DEFAULT_QUALIFYTIMEOUT * 1000;
					peer->lastms = pingtime;
					peer->last_response = ast_tvnow();
					peer->peer_status = (pingtime <= timeout) ? PEER_REACHABLE : PEER_LAGGED;
				} else {
					peer->peer_status = PEER_UNREACHABLE;
					peer->lastms = -1;
				}
				if (old_status != peer->peer_status) {
					const char *new_name =
						peer->peer_status == PEER_REACHABLE ? "Reachable" :
						peer->peer_status == PEER_LAGGED ? "Lagged" : "Unreachable";
					ast_verbose("Sofia: Peer '%s' is now %s (%dms)\n",
						peer->name, new_name, peer->lastms);
					manager_event(EVENT_FLAG_SYSTEM, "PeerStatus",
						"ChannelType: SIP\r\n"
						"Peer: SIP/%s\r\n"
						"PeerStatus: %s\r\n"
						"Time: %d\r\n",
						peer->name, new_name, peer->lastms);
					/* post-T56 regextenonqualify parity (2026-04-27): qualify-state-coupled
					 * dialplan auto-extension. ADD on transition INTO REACHABLE (chan_sip
					 * parity at chan_sip.c:22087 is_reachable&&regextenonqualify). REMOVE
					 * on transition INTO UNREACHABLE (chan_sip parity at chan_sip.c:27574
					 * regextenonqualify). LAGGED transition fires neither (chan_sip
					 * ambiguity preserved — safe default). All gated on
					 * sofia_cfg.regextenonqualify; helper itself further gates on
					 * sofia_cfg.regcontext non-empty. */
					if (sofia_cfg.regextenonqualify) {
						if (peer->peer_status == PEER_REACHABLE) {
							register_peer_exten(peer, 1);
						} else if (peer->peer_status == PEER_UNREACHABLE) {
							register_peer_exten(peer, 0);
						}
					}
				}
			}
			if (peer->qualify_nh) {
				nua_handle_destroy(peer->qualify_nh);
				peer->qualify_nh = NULL;
			}
			/* Reset qualify_sent so next cycle calculates fresh pingtime */
			memset(&peer->qualify_sent, 0, sizeof(peer->qualify_sent));
			peer->last_qualify = ast_tvnow();
			ast_mutex_unlock(&peer->lock);
		}
		break;
	case nua_r_message:
		if (sofia_debug)
			ast_verbose("Sofia: MESSAGE response %d %s\n", status, phrase);
		break;
	case nua_r_subscribe:
		if (sofia_debug)
			ast_verbose("Sofia: SUBSCRIBE response %d %s\n", status, phrase);
		break;
	case nua_r_notify:
		if (sofia_debug)
			ast_verbose("Sofia: NOTIFY response %d %s\n", status, phrase);
		break;
	case nua_r_refer:
		if (sofia_debug)
			ast_verbose("Sofia: REFER response %d %s\n", status, phrase);
		break;
	case nua_r_info:
		if (sofia_debug)
			ast_verbose("Sofia: INFO response %d %s\n", status, phrase);
		break;
	case nua_r_publish:
		if (sofia_debug)
			ast_verbose("Sofia: PUBLISH response %d %s\n", status, phrase);
		break;
	case nua_r_prack:
		if (sofia_debug)
			ast_verbose("Sofia: PRACK response %d %s\n", status, phrase);
		break;
	case nua_r_shutdown:
		ast_verbose("Sofia: Shutdown response %d %s\n", status, phrase);
		break;
	case nua_i_state:
		break;
	case nua_i_error:
		if (sofia_debug)
			ast_verbose("Sofia: Error event status=%d phrase=%s\n", status, phrase ? phrase : "(null)");
		if (pvt) {
			if (sofia_debug)
					ast_verbose("Sofia: Error pvt=%p owner=%p nh=%p state=%d\n",
					(void *)pvt, pvt->owner ? (void *)pvt->owner : NULL,
					(void *)pvt->nh, pvt->state);
		}
		break;
	case nua_i_terminated:
		if (pvt) {
			pvt->state = SOFIA_DIALOG_STATE_DOWN;
		}
		break;
	case nua_r_set_params:
	case nua_r_get_params:
	case nua_r_authenticate:
	case nua_r_redirect:
	case nua_r_destroy:
	case nua_r_respond:
	case nua_r_ack:
		break;
	default:
		break;
	}
}

static void *sofia_thread_func(void *data)
{
	if (su_init() != 0) {
		ast_log(LOG_ERROR, "Failed to initialize Sofia-SIP SU\n");
		return NULL;
	}

	sofia_root = su_root_create(NULL);
	if (!sofia_root) {
		ast_log(LOG_ERROR, "Failed to create Sofia-SIP root\n");
		su_deinit();
		return NULL;
	}

	/* T36 Phase 2: per-transport URLs passed as separate sofia-sip tags
	 * (NUTAG_URL + NUTAG_SIPS_URL + NUTAG_WS_URL + NUTAG_WSS_URL).
	 * Comma-concatenation into NUTAG_URL is rejected by sofia-sip URL parser. */
	{
		char udp_url[128];
		char tls_url[128] = "";
		char ws_url[128]  = "";
		char wss_url[128] = "";
		int needs_cert;

		/* Step A IPv6 parity SS3 (2026-04-28): listener bind URLs apply
		 * Pattern 5 helper #45 sofia_uri_format_host for IPv6 bracket-form
		 * (RFC 3261 §19.1.2). Operator config sofia_cfg.bindaddr=`::` (IPv6
		 * dual-stack) or `2001:db8::1` (IPv6 literal) gets bracket-wrapped;
		 * IPv4 literals + hostnames passthrough unchanged. Wildcard `*`
		 * (no-bindaddr-set fallback) passes through (no `:` so helper no-op). */
		char hbuf_udp[80], hbuf_tls[80], hbuf_ws[80], hbuf_wss[80];
		snprintf(udp_url, sizeof(udp_url), "sip:%s:%d",
			sofia_uri_format_host(
				ast_strlen_zero(sofia_cfg.bindaddr) ? "*" : sofia_cfg.bindaddr,
				hbuf_udp, sizeof(hbuf_udp)),
			sofia_cfg.bindport);
		if (sofia_cfg.tlsbindport > 0) {
			/* Without ;transport=tls, sofia-sip enumerates both TLS+WSS for sips:
			 * scheme and tries to bind both to the same port — WSS bind fails with
			 * "unknown(pf=2 wss/...)". Explicit transport=tls forces TLS-only. */
			snprintf(tls_url, sizeof(tls_url), "sips:%s:%d;transport=tls",
				sofia_uri_format_host(
					ast_strlen_zero(sofia_cfg.tlsbindaddr) ? "*" : sofia_cfg.tlsbindaddr,
					hbuf_tls, sizeof(hbuf_tls)),
				sofia_cfg.tlsbindport);
		}
		if (sofia_cfg.wsbindport > 0) {
			snprintf(ws_url, sizeof(ws_url), "sip:%s:%d;transport=ws",
				sofia_uri_format_host(
					ast_strlen_zero(sofia_cfg.wsbindaddr) ? "*" : sofia_cfg.wsbindaddr,
					hbuf_ws, sizeof(hbuf_ws)),
				sofia_cfg.wsbindport);
		}
		if (sofia_cfg.wssbindport > 0) {
			snprintf(wss_url, sizeof(wss_url), "sips:%s:%d;transport=wss",
				sofia_uri_format_host(
					ast_strlen_zero(sofia_cfg.wssbindaddr) ? "*" : sofia_cfg.wssbindaddr,
					hbuf_wss, sizeof(hbuf_wss)),
				sofia_cfg.wssbindport);
		}

		needs_cert = (tls_url[0] || wss_url[0]);

		/* WSS requires cert files with WSS-specific names (wss.pem + ca-bundle.crt
		 * per sofia-sip tport_type_ws.c:357-376). TLS uses agent.pem + cafile.pem.
		 * Auto-alias to avoid the two-file footgun: when wssbindport is set and the
		 * WSS-specific files are missing, link them from the TLS files. Idempotent. */
		if (sofia_cfg.wssbindport > 0 && !ast_strlen_zero(sofia_cfg.tlscertfile)) {
			char wss_pem[512], ca_bundle[512], agent[512], cafile[512];
			snprintf(wss_pem,   sizeof(wss_pem),   "%s/wss.pem",       sofia_cfg.tlscertfile);
			snprintf(ca_bundle, sizeof(ca_bundle), "%s/ca-bundle.crt", sofia_cfg.tlscertfile);
			snprintf(agent,     sizeof(agent),     "%s/agent.pem",     sofia_cfg.tlscertfile);
			snprintf(cafile,    sizeof(cafile),    "%s/cafile.pem",    sofia_cfg.tlscertfile);
			if (access(wss_pem, R_OK) != 0 && access(agent, R_OK) == 0) {
				if (link(agent, wss_pem) != 0 && symlink(agent, wss_pem) != 0) {
					ast_log(LOG_WARNING, "Sofia: could not create %s from %s — WSS may fail\n",
						wss_pem, agent);
				}
			}
			if (access(ca_bundle, R_OK) != 0 && access(cafile, R_OK) == 0) {
				if (link(cafile, ca_bundle) != 0 && symlink(cafile, ca_bundle) != 0) {
					ast_log(LOG_WARNING, "Sofia: could not create %s from %s — WSS may fail\n",
						ca_bundle, cafile);
				}
			}
		}

		ast_debug(1, "Creating NUA: udp=%s tls=%s ws=%s wss=%s cert_dir=%s\n",
			udp_url, tls_url[0] ? tls_url : "(none)",
			ws_url[0] ? ws_url : "(none)",
			wss_url[0] ? wss_url : "(none)",
			needs_cert ? sofia_cfg.tlscertfile : "(none)");

		sofia_nua = nua_create(sofia_root,
			sofia_event_callback,
			NULL,
			NUTAG_URL(udp_url),
			TAG_IF(tls_url[0], NUTAG_SIPS_URL(tls_url)),
			TAG_IF(ws_url[0],  NUTAG_WS_URL(ws_url)),
			TAG_IF(wss_url[0], NUTAG_WSS_URL(wss_url)),
			TAG_IF(needs_cert && !ast_strlen_zero(sofia_cfg.tlscertfile),
				NUTAG_CERTIFICATE_DIR(sofia_cfg.tlscertfile)),
			NUTAG_MEDIA_ENABLE(0),
			NUTAG_ALLOW("INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, REFER, MESSAGE, INFO, PUBLISH, PRACK"),
			NUTAG_APPL_METHOD("REGISTER"),
			NUTAG_ALLOW_EVENTS("presence"),
			NUTAG_ALLOW_EVENTS("dialog"),
			NUTAG_ALLOW_EVENTS("message-summary"),
			NUTAG_ALLOW_EVENTS("refer"),
			NUTAG_ALLOW_EVENTS("presence.winfo"),
			NUTAG_M_USERNAME("*"),
			SIPTAG_EXPIRES_STR("3600"),
			/* post-T56 timert1 [general] parity (2026-04-28, LATENT BUG FIX +
			 * Pattern 16 sofia-sip-native 7th-instance REWIRED): NTATAG_SIP_T1 is
			 * the T1 VALUE — RFC 3261 §17.1.1.1 T1 retransmission interval (in
			 * milliseconds; default 500ms) per sofia-sip nta_tag.c:497-500 docstring
			 * "Initial retransmission interval used by request retransmission timers
			 * A and E (UDP) and response retransmission timer G". NOT the t1min
			 * minimum-bound (sofia_cfg.t1min remains separately consumed at sofia_
			 * parse_peer_config per-peer parser fallback floor + sofia_load_config
			 * conclusion R5 cross-validation lower-bound).
			 *
			 * **post-T56 timert1 [general] parity LATENT BUG FIX 2026-04-28**:
			 * REWIRED from sofia_cfg.t1min (100ms default per t1min ac8d1ef) to
			 * sofia_cfg.default_timer_t1 (500ms default chan_sip-faithful per
			 * sip.h:89 DEFAULT_TIMER_T1). Operational impact: 5× retransmit-rate
			 * change toward chan_sip drop-in baseline (operators previously saw
			 * 100ms initial retransmit interval; now 500ms matching chan_sip).
			 * Affects ALL SIP transactions globally (UDP request retransmits
			 * timer A+E + response retransmit timer G).
			 *
			 * Pattern 14 BIDIRECTIONAL design-stage catch (Enginer dispatch
			 * surfaced this latent bug pre-implementation; sofia-sip nta_tag.c:497
			 * docstring grep verified at R-ACK). Pattern 16 7th-instance counter
			 * STAYS unchanged (REWIRED not new instance). chan_sofia helper-
			 * architecture-advantage NEW DIMENSION bug-correction-as-byproduct-of-
			 * parity (R4) — chan_sofia ships timert1 parity AND fixes prior latent
			 * bug in same commit. chan_sofia ARCHITECTURAL ADVANTAGE 3rd-instance
			 * preserved — single wire-in vs chan_sip per-dialog dynamic T1
			 * selection (chan_sip.c:6024+L17056). */
			NTATAG_SIP_T1(sofia_cfg.default_timer_t1),
			/* post-T56 timerb [general] parity (2026-04-28): Pattern 16 sofia-sip-native
			 * 11th-instance — NTATAG_SIP_T1X64 at nua_create caps INVITE transaction
			 * timeout at default_timer_b ms (RFC 3261 §17.1.1.2). nta_tag.h:182-186
			 * verbatim macro. chan_sofia helper-architecture-advantage cluster: single
			 * nua_create tag-emit-site vs chan_sip per-pvt ast_sched_add scheduler at
			 * L6354. Per-peer dynamic override deferred per t1min ac8d1ef precedent. */
			TAG_IF(sofia_cfg.default_timer_b,
				NTATAG_SIP_T1X64(sofia_cfg.default_timer_b)),
			/* post-T56 tos/cos bundle (2026-04-28): Pattern 16 sofia-sip-native 9th-instance
			 * — TPTAG_TOS at nua_create applies SIP-listener-side TOS via setsockopt at
			 * UDP/TCP transport level. tport_tag.h:319 verbatim. .193 production
			 * tos_sip=cs3 finally honored on next reload (REAL OPERATOR DRIVER). */
			TAG_IF(sofia_cfg.tos_sip, TPTAG_TOS((int)sofia_cfg.tos_sip)),
			/* post-T56 useragent [general] parity (2026-04-28): Pattern 16
			 * sofia-sip-native 10th-instance DOUBLE-DIGIT MILESTONE —
			 * SIPTAG_USER_AGENT_STR at nua_create installs User-Agent + Server
			 * header value; sofia-sip emits on every outbound request + response
			 * automatically. sip_tag.h:2183 macro. chan_sofia helper-architecture-
			 * advantage 13th-instance: single emit-site vs chan_sip 5-site
			 * add_header duplication (chan_sip.c:11132 response Server +
			 * L11307+12986+14331 outbound User-Agent + others). REAL OPERATOR
			 * DRIVER: .193 useragent=Huawei SoftX3000 V300R011 finally honored
			 * on next reload. Empty-string default-init guard via TAG_IF skips
			 * tag (sofia-sip falls back to library default). */
			TAG_IF(!ast_strlen_zero(sofia_cfg.useragent),
				SIPTAG_USER_AGENT_STR(sofia_cfg.useragent)),
			TAG_END());
	}

	if (!sofia_nua) {
		ast_log(LOG_ERROR, "Failed to create Sofia-SIP NUA agent\n");
		su_root_destroy(sofia_root);
		sofia_root = NULL;
		su_deinit();
		return NULL;
	}

	nua_set_params(sofia_nua,
		NUTAG_ENABLEMESSAGE(1),
		NUTAG_ALLOW("INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, REFER, MESSAGE, INFO, PUBLISH, PRACK"),
		TAG_END());

	/* Add methods to appl_method one at a time */
	nua_set_params(sofia_nua, NUTAG_APPL_METHOD("REGISTER"), TAG_END());
	nua_set_params(sofia_nua, NUTAG_APPL_METHOD("SUBSCRIBE"), TAG_END());
	nua_set_params(sofia_nua, NUTAG_APPL_METHOD("PUBLISH"), TAG_END());
	nua_set_params(sofia_nua, NUTAG_APPL_METHOD("NOTIFY"), TAG_END());
	nua_set_params(sofia_nua, NUTAG_APPL_METHOD("INFO"), TAG_END());
	nua_set_params(sofia_nua, NUTAG_APPL_METHOD("REFER"), TAG_END());

	/* Allow event packages one at a time */
	nua_set_params(sofia_nua, NUTAG_ALLOW_EVENTS("presence"), TAG_END());
	nua_set_params(sofia_nua, NUTAG_ALLOW_EVENTS("dialog"), TAG_END());
	nua_set_params(sofia_nua, NUTAG_ALLOW_EVENTS("message-summary"), TAG_END());
	nua_set_params(sofia_nua, NUTAG_ALLOW_EVENTS("refer"), TAG_END());
	nua_set_params(sofia_nua, NUTAG_ALLOW_EVENTS("presence.winfo"), TAG_END());

	/* Apply initial debug state to transport layer */
	if (sofia_debug && sofia_nua) {
		tport_set_params(nta_agent_tports(nua_get_agent(sofia_nua)),
			TPTAG_LOG(1), TAG_END());
	}

	su_root_run(sofia_root);

	/* T40: ownership-correct teardown. su_root_destroy enforces same-thread-as-
	 * su_root_create (sofia-sip internal assert; verified via T40 Phase 1 gdb
	 * bt — cross-thread destroy aborts via __assert_fail). unload_module
	 * signals us via nua_shutdown + su_root_break + pthread_join; we destroy
	 * here in our own thread context so the assert never fires. Order:
	 * nua_destroy first (drops the NUA event-loop registrations), then
	 * su_root_destroy (event loop dead, structures freed), then su_deinit
	 * (process-wide sofia-sip cleanup paired with su_init() above). */
	if (sofia_nua) {
		nua_destroy(sofia_nua);
		sofia_nua = NULL;
	}
	if (sofia_root) {
		su_root_destroy(sofia_root);
		sofia_root = NULL;
	}
	su_deinit();
	return NULL;
}

static char *sofia_cli_show_peers(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
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

		ast_cli(a->fd, "%-20s %-30s %-4s %-5d %-15s %s\n",
			peer->name,
			peer->host,
			peer->registered ? "Dyn" : "",
			peer->port,
			status,
			nat_str);
		ao2_ref(peer, -1);
	}
	ao2_iterator_destroy(&i);

	return CLI_SUCCESS;
}

static char *sofia_cli_show_channels(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct sofia_pvt *pvt;
	struct ao2_iterator i;
	int count = 0;
	const char *state_str;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show channels";
		e->usage = "Usage: sip show channels\n"
			   "       List active Sofia-SIP channels\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	ast_cli(a->fd, "%-40s %-20s %-10s %-15s\n",
		"Call-ID", "Peer", "State", "Session-Timer");

	if (!dialogs) {
		return CLI_SUCCESS;
	}

	i = ao2_iterator_init(dialogs, 0);
	while ((pvt = ao2_iterator_next(&i))) {
		if (pvt->is_fork_child) {
			ao2_ref(pvt, -1);
			continue;
		}
		ast_mutex_lock(&pvt->lock);
		switch (pvt->state) {
		case SOFIA_DIALOG_STATE_DOWN:
			state_str = "Down";
			break;
		case SOFIA_DIALOG_STATE_TRYING:
			state_str = "Trying";
			break;
		case SOFIA_DIALOG_STATE_RINGING:
			state_str = "Ringing";
			break;
		case SOFIA_DIALOG_STATE_UP:
			state_str = "Up";
			break;
		default:
			state_str = "Unknown";
			break;
		}

		{
			/* post-T56 session timers (RFC 4028) (2026-04-27) R13.a chan_sofia
			 * surpass: Session-Timer:N/M column where N = seconds-since-last-
			 * refresh + M = negotiated Session-Expires. Operators today guess
			 * refresh schedule; chan_sip displays nothing equivalent. (none) =
			 * no session timer active for this call. */
			char st_buf[24];
			if (pvt->session_negotiated_expires > 0) {
				time_t since = pvt->session_last_refresh_at
					? (time(NULL) - pvt->session_last_refresh_at) : 0;
				snprintf(st_buf, sizeof(st_buf), "%lds/%ds",
					(long)since, pvt->session_negotiated_expires);
			} else {
				ast_copy_string(st_buf, "(none)", sizeof(st_buf));
			}
			ast_cli(a->fd, "%-40s %-20s %-10s %-15s\n",
				pvt->callid,
				pvt->peername,
				state_str,
				st_buf);
		}
		count++;
		ast_mutex_unlock(&pvt->lock);
		ao2_ref(pvt, -1);
	}
	ao2_iterator_destroy(&i);

	ast_cli(a->fd, "%d active sofia channel%s\n", count, count != 1 ? "s" : "");
	return CLI_SUCCESS;
}

#define SOFIA_CLI_PEER_RULE_WIDTH 78
#define SOFIA_CLI_PEER_LABEL_WIDTH 20

static void sofia_print_ha_lines(int fd, const struct ast_ha *ha)
{
	const struct ast_ha *p;

	for (p = ha; p; p = p->next) {
		char addr[128];
		char netmask[128];

		ast_copy_string(addr, ast_sockaddr_stringify_addr(&p->addr), sizeof(addr));
		ast_copy_string(netmask, ast_sockaddr_stringify_addr(&p->netmask), sizeof(netmask));
		ast_cli(fd, "    %-*.*s : %s %s/%s\n",
			SOFIA_CLI_PEER_LABEL_WIDTH, SOFIA_CLI_PEER_LABEL_WIDTH,
			"ACL rule",
			p->sense == AST_SENSE_ALLOW ? "permit" : "deny",
			addr, netmask);
	}
}

static void sofia_cli_peer_rule(int fd, char fill)
{
	char line[SOFIA_CLI_PEER_RULE_WIDTH + 1];

	memset(line, fill, SOFIA_CLI_PEER_RULE_WIDTH);
	line[SOFIA_CLI_PEER_RULE_WIDTH] = '\0';
	ast_cli(fd, "%s\n", line);
}

static void sofia_cli_peer_section(int fd, const char *title)
{
	char line[SOFIA_CLI_PEER_RULE_WIDTH + 1];
	int used;

	used = snprintf(line, sizeof(line), "-- %s ", title);
	if (used < 0 || used >= (int) sizeof(line)) {
		ast_cli(fd, "\n-- %s --\n", title);
		return;
	}
	memset(line + used, '-', SOFIA_CLI_PEER_RULE_WIDTH - used);
	line[SOFIA_CLI_PEER_RULE_WIDTH] = '\0';

	ast_cli(fd, "\n%s\n", line);
}

static void sofia_cli_peer_line(int fd, const char *label, const char *fmt, ...)
{
	char value[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(value, sizeof(value), fmt, ap);
	va_end(ap);

	ast_cli(fd, "  %-*.*s : %s\n",
		SOFIA_CLI_PEER_LABEL_WIDTH, SOFIA_CLI_PEER_LABEL_WIDTH, label, value);
}

static void sofia_cli_peer_subline(int fd, const char *label, const char *fmt, ...)
{
	char value[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(value, sizeof(value), fmt, ap);
	va_end(ap);

	ast_cli(fd, "    %-*.*s : %s\n",
		SOFIA_CLI_PEER_LABEL_WIDTH, SOFIA_CLI_PEER_LABEL_WIDTH, label, value);
}

static char *sofia_cli_show_peer(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
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

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show peer";
		e->usage = "Usage: sip show peer <name>\n"
			   "       Show detailed info for a Sofia-SIP peer\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 4) {
		ast_cli(a->fd, "Usage: sip show peer <name>\n");
		return CLI_FAILURE;
	}

	peer = sofia_find_peer(a->argv[3]);
	if (!peer) {
		ast_cli(a->fd, "Peer '%s' not found\n", a->argv[3]);
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

	ast_cli(a->fd, "\n");
	sofia_cli_peer_rule(a->fd, '=');
	sofia_cli_peer_line(a->fd, "SIP peer", "%s", peer->name);
	sofia_cli_peer_line(a->fd, "Registration", "%s", peer->registered ? "registered" : "not registered");
	sofia_cli_peer_rule(a->fd, '=');
	sofia_cli_peer_line(a->fd, "Endpoint", "%s@%s:%d via %s",
		S_OR(peer->defaultuser, peer->name), peer->host, peer->port, transport_str);
	sofia_cli_peer_line(a->fd, "Context / source", "%s / %s", peer->context, source_str);
	sofia_cli_peer_line(a->fd, "Contact slots", "%d used of %d allowed", contacts_used, peer->max_contacts);
	sofia_cli_peer_line(a->fd, "Media", "codecs=%s dtmf=%s nat=%s directmedia=%s",
		ast_strlen_zero(codec_buf) ? "(default)" : codec_buf,
		dtmf_str, nat, AST_CLI_YESNO(peer->directmedia));
	sofia_cli_peer_line(a->fd, "Calls", "%d/%s active, %d ringing, %d on-hold",
		peer->inUse, limit_str, peer->inRinging, peer->onHold);
	if (peer->qualify) {
		sofia_cli_peer_line(a->fd, "Qualify", "yes, status=%s", status);
	} else {
		sofia_cli_peer_line(a->fd, "Qualify", "no");
	}
	sofia_cli_peer_line(a->fd, "Session timers", "%s, expires=%d, minse=%d, refresher=%s",
		st_mode_str, peer->session_expires, peer->session_minse, st_refresher_str);
	sofia_cli_peer_line(a->fd, "Identity headers", "send=%s, trust=%s, presentation=%s",
		sendrpid_str, AST_CLI_YESNO(peer->trustrpid),
		ast_named_caller_presentation(peer->callingpres));

	sofia_cli_peer_section(a->fd, "Identity");
	sofia_cli_peer_line(a->fd, "Name", "%s", peer->name);
	sofia_cli_peer_line(a->fd, "Username", "%s", S_OR(peer->defaultuser, "(none)"));
	sofia_cli_peer_line(a->fd, "Type", "%s", type_str);
	sofia_cli_peer_line(a->fd, "Host", "%s", peer->host);
	sofia_cli_peer_line(a->fd, "Port", "%d", peer->port);
	sofia_cli_peer_line(a->fd, "Transport", "%s", transport_str);
	sofia_cli_peer_line(a->fd, "Context", "%s", peer->context);
	sofia_cli_peer_line(a->fd, "Registered", "%s", AST_CLI_YESNO(peer->registered));
	sofia_cli_peer_line(a->fd, "Expires", "%ds", peer->expiresecs);
	sofia_cli_peer_line(a->fd, "Secret", "%s", ast_strlen_zero(peer->secret) ? "(none)" : "(set)");
	if (peer->qualify) {
		sofia_cli_peer_line(a->fd, "Qualify", "yes, freq=%ds, timeout=%ds, status=%s",
			peer->qualifyfreq, peer->qualifytimeout, status);
	} else {
		sofia_cli_peer_line(a->fd, "Qualify", "no");
	}
	if (!ast_strlen_zero(peer->callerid)) {
		sofia_cli_peer_line(a->fd, "CallerID", "%s", peer->callerid);
	}
	if (!ast_strlen_zero(peer->cid_num) || !ast_strlen_zero(peer->cid_name)) {
		char merged[256];
		ast_callerid_merge(merged, sizeof(merged),
			S_OR(peer->cid_name, ""), S_OR(peer->cid_num, ""), "<unknown>");
		sofia_cli_peer_line(a->fd, "Callerid", "%s", merged);
	}
	if (!ast_strlen_zero(peer->cid_tag)) {
		sofia_cli_peer_line(a->fd, "CID tag", "%s", peer->cid_tag);
	}

	sofia_cli_peer_section(a->fd, "Network and media");
	sofia_cli_peer_line(a->fd, "NAT", "%s", nat);
	sofia_cli_peer_line(a->fd, "DTMF mode", "%s", dtmf_str);
	sofia_cli_peer_line(a->fd, "Direct media", "%s", AST_CLI_YESNO(peer->directmedia));
	sofia_cli_peer_line(a->fd, "Encryption", "%s", AST_CLI_YESNO(peer->encryption));
	sofia_cli_peer_line(a->fd, "Codecs", "%s", ast_strlen_zero(codec_buf) ? "(default)" : codec_buf);
	sofia_cli_peer_line(a->fd, "Max call BR", "%d kbps", peer->maxcallbitrate);

	sofia_cli_peer_section(a->fd, "Limits and features");
	sofia_cli_peer_line(a->fd, "Busy on active", "%s", AST_CLI_YESNO(peer->busy_on_active));
	sofia_cli_peer_line(a->fd, "Max contacts", "%d (used: %d)", peer->max_contacts, contacts_used);
	/* post-T56 allowtransfer per-peer parity (2026-04-27): chan_sip-parity REFER
	 * policy display; "Transfer mode" wording verbatim per chan_sip.c:18650. */
	sofia_cli_peer_line(a->fd, "Transfer mode", "%s", sofia_transfer_mode_str(peer->allowtransfer));
	/* post-T56 lockuseragent per-peer parity (2026-04-27): chan_sip-parity wording
	 * "Lockuseragent" per chan_sip.c:18733 + chan_sofia surpass display of current
	 * locked UA string ("Locked-UA") for inspection / UA-spoofing investigation. */
	sofia_cli_peer_line(a->fd, "Lock user-agent", "%s", AST_CLI_YESNO(peer->lockuseragent));
	if (peer->lockuseragent && peer->locked_user_agent[0]) {
		sofia_cli_peer_line(a->fd, "Locked UA", "%s", peer->locked_user_agent);
	}
	if (peer->lockuseragent && !ast_strlen_zero(peer->lockuseragent_prefixes)) {
		sofia_cli_peer_line(a->fd, "UA prefixes", "%s", peer->lockuseragent_prefixes);
	}
	/* post-T56 language per-peer parity (2026-04-27): chan_sip-parity per-peer audio
	 * locale display ("Language" wording). Empty string preserved (operators see
	 * unset state). */
	sofia_cli_peer_line(a->fd, "Language", "%s", ast_strlen_zero(peer->language) ? "(none)" : peer->language);
	/* post-T56 defaultip per-peer parity (2026-04-28): chan_sip-parity Defaddr->IP
	 * display per chan_sip.c:18701 verbatim wording. */
	sofia_cli_peer_line(a->fd, "Default IP", "%s", ast_sockaddr_stringify(&peer->defaddr));
	/* post-T56 amaflags per-peer parity (2026-04-28): chan_sip-parity
	 * "AMA flags    : %s" display per chan_sip.c:18649 verbatim wording
	 * (4-space alignment chan_sip parity) via ast_cdr_flags2str. */
	sofia_cli_peer_line(a->fd, "AMA flags", "%s", ast_cdr_flags2str(peer->amaflags));
	/* post-T56 subscribemwi per-peer parity (2026-04-28): chan_sip-parity field
	 * display (yes/no for operator visibility into MWI subscription model). */
	sofia_cli_peer_line(a->fd, "Subscribe MWI", "%s", AST_CLI_YESNO(peer->subscribemwi));
	/* post-T56 preferred_codec_only per-peer parity (2026-04-28): chan_sip-parity
	 * field display (yes/no for operator visibility into codec-list-narrowing). */
	sofia_cli_peer_line(a->fd, "Preferred codec", "%s", AST_CLI_YESNO(peer->preferred_codec_only));
	/* post-T56 ignoresdpversion per-peer parity (2026-04-28): chan_sip-parity field
	 * "Ign SDP ver" wording per chan_sip.c:18685 verbatim. PARSE-COMPAT-ONLY display
	 * (chan_sofia processes every SDP unconditionally; flag has no behavioral effect). */
	sofia_cli_peer_line(a->fd, "Ignore SDP ver", "%s", AST_CLI_YESNO(peer->ignoresdpversion));
	/* post-T56 promiscredir per-peer parity (2026-04-28): chan_sip-parity field
	 * "PromiscRedir" wording per chan_sip.c:18681 verbatim. PARSE-COMPAT-ONLY
	 * display (chan_sofia nua_r_redirect handler ABSENT). */
	sofia_cli_peer_line(a->fd, "Promisc redir", "%s", AST_CLI_YESNO(peer->promiscredir));
	/* post-T56 autoframing per-peer parity (2026-04-28): chan_sip-parity field
	 * "Auto-Framing" wording per chan_sip.c:18728 verbatim. PARSE-COMPAT-ONLY
	 * display (chan_sofia sofia_parse_sdp ptime gate not wired today). */
	sofia_cli_peer_line(a->fd, "Auto framing", "%s", AST_CLI_YESNO(peer->autoframing));
	/* faxdetect per-peer display: reports the runtime mode used by DSP CNG
	 * detection and peer T.38 reINVITE detection. */
	sofia_cli_peer_line(a->fd, "Fax detect", "%s",
		peer->faxdetect_mode == SOFIA_FAX_DETECT_NONE ? "no" :
		peer->faxdetect_mode == SOFIA_FAX_DETECT_BOTH ? "yes (cng,t38)" :
		peer->faxdetect_mode == SOFIA_FAX_DETECT_CNG ? "cng" : "t38");
	sofia_cli_peer_section(a->fd, "Fax and T.38");
	/* post-T56 Task #8 T.38 fax UDPTL parity SS7 FINAL CLOSE (2026-04-28):
	 * 5-field T.38 display surface — chan_sip parity at chan_sip.c:18677-18681
	 * verbatim semantic. T38 support enable status + EC mode + MaxDatagram +
	 * t38pt_usertpsource + per-peer overrides displayed for operator
	 * visibility into T.38 negotiation policy. */
	sofia_cli_peer_line(a->fd, "T38 support", "%s", AST_CLI_YESNO(peer->t38pt_udptl));
	sofia_cli_peer_line(a->fd, "T38 EC mode", "%s",
		peer->t38_ec_mode == SOFIA_T38_EC_REDUNDANCY ? "Redundancy" :
		peer->t38_ec_mode == SOFIA_T38_EC_FEC ? "FEC" : "None");
	sofia_cli_peer_line(a->fd, "T38 max datagram", "%d", peer->t38_maxdatagram);
	sofia_cli_peer_line(a->fd, "T38 RTP source", "%s", AST_CLI_YESNO(peer->t38pt_usertpsource));
	sofia_cli_peer_section(a->fd, "Timers and RTP");
	/* post-T56 timerb per-peer parity (2026-04-28): chan_sip-parity field
	 * "Timer B" wording per chan_sip.c:18697 verbatim. Pattern 16 sofia-sip-
	 * native 11th-instance NTATAG_SIP_T1X64 wire-in active at nua_create. */
	sofia_cli_peer_line(a->fd, "Timer B", "%d", peer->timer_b);
	/* post-T56 timert1 per-peer parity (2026-04-28): chan_sip-parity field
	 * "Timer T1" wording. Pattern 16 sofia-sip-native 7th-instance REWIRED
	 * NTATAG_SIP_T1 wire-in active at nua_create per LATENT BUG FIX. */
	sofia_cli_peer_line(a->fd, "Timer T1", "%d", peer->timer_t1);
	/* post-T56 allowoverlap per-peer + [general] parity (2026-04-28, Option A
	 * FULL WIRE-IN): chan_sip parity field "Overlap dial" wording per chan_sip.c
	 * :18689 verbatim. Tri-state: Yes / No / DTMF (DTMF mode parsed + stored
	 * but treated as fall-through per chan_sip own design). */
	sofia_cli_peer_line(a->fd, "Overlap dial", "%s", sofia_allowoverlap_str(peer->allowoverlap_mode));
	/* post-T56 rtp-timeout bundle per-peer parity (2026-04-28): 3 fields display
	 * for operator visibility into RTP-timeout enforcement. */
	sofia_cli_peer_line(a->fd, "RTP timeout", "%d", peer->rtptimeout);
	sofia_cli_peer_line(a->fd, "RTP hold timeout", "%d", peer->rtpholdtimeout);
	sofia_cli_peer_line(a->fd, "RTP keepalive", "%d", peer->rtpkeepalive);
	sofia_cli_peer_section(a->fd, "Routing and dialplan");
	/* post-T56 parkinglot per-peer parity (2026-04-28): chan_sip-parity
	 * "Parkinglot   : %s" display per chan_sip.c:18753 verbatim wording
	 * (4-space alignment chan_sip parity). */
	sofia_cli_peer_line(a->fd, "Parking lot", "%s", ast_strlen_zero(peer->parkinglot) ? "(none)" : peer->parkinglot);
	/* post-T56 usereqphone parity (2026-04-27): chan_sip-parity "User=Phone" wording
	 * per chan_sip.c:18682 + R11(a) chan_sofia surpass — 3-state inheritance display
	 * (peer-set explicit / inherited from [general] / default off) per outboundproxy +
	 * srtpcipher + subscribecontext precedents. */
	if (peer->usereqphone) {
		int from_general = sofia_cfg.default_usereqphone && peer->usereqphone == sofia_cfg.default_usereqphone;
		sofia_cli_peer_line(a->fd, "User=Phone", "yes%s", from_general ? " (from [general])" : "");
	} else {
		sofia_cli_peer_line(a->fd, "User=Phone", "no");
	}
	/* post-T56 accountcode per-peer parity (2026-04-27): chan_sip-parity CDR
	 * billing-tag display gated on !ast_strlen_zero per chan_sip.c:18647-18648. */
	if (!ast_strlen_zero(peer->accountcode)) {
		sofia_cli_peer_line(a->fd, "Account code", "%s", peer->accountcode);
	}
	/* post-T56 maxforwards parity (2026-04-27): chan_sip-parity "Max forwards"
	 * wording per chan_sip.c:18666 + R11(a) chan_sofia surpass — 3-state
	 * inheritance display per outboundproxy + srtpcipher + subscribecontext +
	 * usereqphone precedents. */
	if (peer->maxforwards == sofia_cfg.default_max_forwards) {
		sofia_cli_peer_line(a->fd, "Max forwards", "%d (from [general])", peer->maxforwards);
	} else {
		sofia_cli_peer_line(a->fd, "Max forwards", "%d", peer->maxforwards);
	}
	{
		/* T55.1 (2026-04-27): MWI mailbox list (NOLOCK; we hold peer->lock from outer caller). */
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
		sofia_cli_peer_line(a->fd, "Mailbox", "%s", first ? "(none)" : mailbox_buf);
	}
	{
		/* T56.1 (2026-04-27): outboundproxy display — show peer-set value if any,
		 * else inherit-marker if sofia_cfg.outboundproxy non-empty, else (none). */
		const char *peer_p = peer->outboundproxy;
		if (!ast_strlen_zero(peer_p)) {
			sofia_cli_peer_line(a->fd, "Outbound proxy", "%s", peer_p);
		} else if (!ast_strlen_zero(sofia_cfg.outboundproxy)) {
			sofia_cli_peer_line(a->fd, "Outbound proxy", "%s (from [general])", sofia_cfg.outboundproxy);
		} else {
			sofia_cli_peer_line(a->fd, "Outbound proxy", "(none)");
		}
	}
	{
		/* post-T56 MOH per-peer parity (2026-04-27): MOH Interpret + MOH Suggest
		 * display — chan_sip parity at chan_sip.c:18661 string format verbatim.
		 * R11 doc-clarity: MOH Suggest displays the stored value but ONLY signals
		 * INBOUND-direction today (peer-puts-us-on-hold propagates suggest to
		 * bridged channel); OUTBOUND-direction Alert-Info on chan_sofia-issued
		 * HOLD re-INVITE is deferred (chan_sofia does not issue outbound HOLD
		 * re-INVITE today; tracked as separate task). */
		sofia_cli_peer_line(a->fd, "MOH interpret", "%s",
			ast_strlen_zero(peer->mohinterpret) ? "(none)" : peer->mohinterpret);
		sofia_cli_peer_line(a->fd, "MOH suggest", "%s",
			ast_strlen_zero(peer->mohsuggest) ? "(none)" : peer->mohsuggest);
	}
	{
		/* post-T56 srtpcipher operator option (2026-04-27): SRTP cipher preference display.
		 * 3-state inheritance follows outboundproxy convention: peer-set / from [general] / (default). */
		if (!ast_strlen_zero(peer->srtpcipher)) {
			sofia_cli_peer_line(a->fd, "SRTP cipher", "%s", peer->srtpcipher);
		} else if (!ast_strlen_zero(sofia_cfg.default_srtpcipher)) {
			sofia_cli_peer_line(a->fd, "SRTP cipher", "%s (from [general])", sofia_cfg.default_srtpcipher);
		} else {
			sofia_cli_peer_line(a->fd, "SRTP cipher", "(default AES_CM_128_HMAC_SHA1_80)");
		}
	}
	sofia_cli_peer_section(a->fd, "Session and identity headers");
	/* post-T56 session timers (RFC 4028) (2026-04-27): chan_sip-parity 4-line display. */
	sofia_cli_peer_line(a->fd, "Session timers", "%s", st_mode_str);
	sofia_cli_peer_line(a->fd, "Session expires", "%d", peer->session_expires);
	sofia_cli_peer_line(a->fd, "Session Min-SE", "%d", peer->session_minse);
	sofia_cli_peer_line(a->fd, "Session refresher", "%s", st_refresher_str);
	/* post-T56 identity-headers parity (2026-04-27): RPID/PAI/Privacy display.
	 * ast_named_caller_presentation (callerid.h:358) maps int to canonical string. */
	sofia_cli_peer_line(a->fd, "Calling pres", "%s", ast_named_caller_presentation(peer->callingpres));
	sofia_cli_peer_line(a->fd, "Send RPID", "%s", sendrpid_str);
	sofia_cli_peer_line(a->fd, "Trust RPID", "%s", AST_CLI_YESNO(peer->trustrpid));
	sofia_cli_peer_line(a->fd, "Concurrent calls", "%d/%s (%d ringing, %d on-hold)",
		peer->inUse, limit_str, peer->inRinging, peer->onHold);

	sofia_cli_peer_section(a->fd, "Groups and source");
	{
		char grp_buf[256];
		sofia_cli_peer_line(a->fd, "Call group", "%s", ast_print_group(grp_buf, sizeof(grp_buf), peer->callgroup));
		sofia_cli_peer_line(a->fd, "Pickup group", "%s", ast_print_group(grp_buf, sizeof(grp_buf), peer->pickupgroup));
	}
	/* post-T56 regexten display-gate parity (2026-04-27): chan_sip.c:18704 gates
	 * on !ast_strlen_zero(sip_cfg.regcontext) — RegExten line shown only when the
	 * register_peer_exten mechanism is actually active. Previously chan_sofia gated
	 * only on peer->regexten which misled operators into thinking the auto-add
	 * mechanism worked even when regcontext was unset. */
	if (!ast_strlen_zero(sofia_cfg.regcontext) && !ast_strlen_zero(peer->regexten)) {
		sofia_cli_peer_line(a->fd, "Reg ext", "%s", peer->regexten);
	}
	/* post-T56 callbackextension per-peer parity (2026-04-28, Option A FULL WIRE-IN
	 * via Pattern 16 sofia-sip-native 12th-instance NUTAG_M_USERNAME + chan_sofia
	 * surpass over chan_sip CLI silent — chan_sip discards callback in build_peer
	 * local-var; never displayed): conditional display only when set, mirrors sip
	 * show peer regexten gating idiom. */
	if (!ast_strlen_zero(peer->callbackextension)) {
		sofia_cli_peer_line(a->fd, "Callback ext", "%s", peer->callbackextension);
	}
	/* post-T56 setvar+header per-peer parity (2026-04-28, COMBINED ship): sip show
	 * peer "Variables:" subsection iterating peer->chanvars per chan_sip.c:18742-
	 * 18745 verbatim format. Includes both setvar= and header= entries (header
	 * entries appear with __SIPADDHEADERpre%2d= prefix making the storage mechanism
	 * transparent to operator). */
	if (peer->chanvars) {
		struct ast_variable *var;
		for (var = peer->chanvars; var; var = var->next) {
			sofia_cli_peer_line(a->fd, "Variable", "%s = %s", var->name, var->value);
		}
	}
	/* post-T56 subscribecontext per-peer parity (2026-04-27): chan_sip.c:18645
	 * "Subscr.Cont." line verbatim wording + R11(b) chan_sofia surpass — 3-state
	 * inheritance display (peer-set / from [general] / Not set) per outboundproxy +
	 * srtpcipher precedents. KNOWN LIMITATION: value displayed today but pivot
	 * effect deferred until presence/dialog event-package handler. */
	if (!ast_strlen_zero(peer->subscribecontext)) {
		int from_general = !ast_strlen_zero(sofia_cfg.default_subscribecontext)
			&& !strcmp(peer->subscribecontext, sofia_cfg.default_subscribecontext);
		sofia_cli_peer_line(a->fd, "Subscribe context", "%s%s", peer->subscribecontext,
			from_general ? " (from [general])" : "");
	} else if (!ast_strlen_zero(sofia_cfg.default_subscribecontext)) {
		sofia_cli_peer_line(a->fd, "Subscribe context", "%s (from [general])", sofia_cfg.default_subscribecontext);
	} else {
		sofia_cli_peer_line(a->fd, "Subscribe context", "<Not set>");
	}
	if (!ast_strlen_zero(peer->fromuser)) {
		sofia_cli_peer_line(a->fd, "From user", "%s", peer->fromuser);
	}
	if (!ast_strlen_zero(peer->fromdomain)) {
		sofia_cli_peer_line(a->fd, "From domain", "%s", peer->fromdomain);
	}

	sofia_cli_peer_section(a->fd, "Security and ACL");
	/* Insecure flags */
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
		sofia_cli_peer_line(a->fd, "Insecure", "%s", ins[0] ? ins : "no");
	}

	/* ACL detail (was: just yes/no) */
	if (peer->ha) {
		sofia_cli_peer_line(a->fd, "ACL", "yes");
		sofia_print_ha_lines(a->fd, peer->ha);
	} else {
		sofia_cli_peer_line(a->fd, "ACL", "no");
	}
	/* post-T56 contactpermit/contactdeny per-peer parity (2026-04-27): chan_sip
	 * parity at chan_sip.c:18676 "ContactACL" wording (chan_sofia uses
	 * "Contact-ACL" for visual separation from "ACL:" line above). */
	sofia_cli_peer_line(a->fd, "Contact ACL", "%s", peer->contactha ? "yes" : "no");
	/* post-T56 directmediapermit/directmediadeny per-peer parity (2026-04-27): chan_sip
	 * parity at chan_sip.c:18676 "DirectMedACL" wording verbatim. */
	sofia_cli_peer_line(a->fd, "Direct media ACL", "%s", peer->directmediaha ? "yes" : "no");
	/* post-T56 dnsmgr per-peer parity (2026-04-27): chan_sip parity at chan_sip.c:19066
	 * "dnsmgr" Y/N column display. */
	sofia_cli_peer_line(a->fd, "DNS managed", "%s", peer->dnsmgr ? "yes" : "no");

	sofia_cli_peer_section(a->fd, "Registration");
	/* Source: where the peer definition came from. */
	sofia_cli_peer_line(a->fd, "Source", "%s", source_str);
	/* Outbound register state — only meaningful when this peer is a register target */
	if (!ast_strlen_zero(peer->secret)
		&& !ast_strlen_zero(peer->host)
		&& strcasecmp(peer->host, "dynamic") != 0) {
		sofia_cli_peer_line(a->fd, "Outbound reg", "target=%s:%d expiry=%lds attempts=%d",
			peer->host, peer->port,
			peer->reg_expiry > 0 ? (long)(peer->reg_expiry - time(NULL)) : 0,
			peer->reg_attempts);
	}

	if (!ast_sockaddr_isnull(&peer->src_addr)) {
		sofia_cli_peer_line(a->fd, "Source addr", "%s", ast_sockaddr_stringify(&peer->src_addr));
	}

	sofia_cli_peer_section(a->fd, "Contacts");
	if (peer->contacts && contacts_used > 0) {
		struct ao2_iterator ci;
		struct sofia_contact *c;
		time_t now = time(NULL);
		int idx = 1;

		sofia_cli_peer_line(a->fd, "Contact count", "%d", contacts_used);
		ci = ao2_iterator_init(peer->contacts, 0);
		while ((c = ao2_iterator_next(&ci))) {
			long ttl = (long)(c->expires - now);
			char ttl_buf[32];
			char contact_status[32];
			char contact_label[32];
			const char *src = !ast_sockaddr_isnull(&c->src_addr) ?
				ast_sockaddr_stringify(&c->src_addr) : "(unknown)";

			snprintf(ttl_buf, sizeof(ttl_buf), "%lds", ttl > 0 ? ttl : 0);
			if (c->active_calls > 0) {
				snprintf(contact_status, sizeof(contact_status),
					"IN-CALL:%d", c->active_calls);
			} else {
				ast_copy_string(contact_status, "IDLE", sizeof(contact_status));
			}
			snprintf(contact_label, sizeof(contact_label), "Contact %d URI", idx++);
			sofia_cli_peer_line(a->fd, contact_label, "%s", c->contact_uri);
			sofia_cli_peer_subline(a->fd, "State", "%s", contact_status);
			sofia_cli_peer_subline(a->fd, "TTL", "%s", ttl_buf);
			sofia_cli_peer_subline(a->fd, "Source", "%s", src);
			sofia_cli_peer_subline(a->fd, "User-Agent", "%s",
				c->user_agent[0] ? c->user_agent : "(none)");
			ao2_ref(c, -1);
		}
		ao2_iterator_destroy(&ci);
	} else {
		sofia_cli_peer_line(a->fd, "Contacts", "(none)");
	}
	ast_mutex_unlock(&peer->lock);
	ao2_ref(peer, -1);

	return CLI_SUCCESS;
}

static int sofia_debug_match(const char *peer_name, const char *src_ip)
{
	if (sofia_debug == 1)
		return 1;
	if (sofia_debug == 2 && peer_name && !strcasecmp(peer_name, sofia_debug_filter))
		return 1;
	if (sofia_debug == 3 && src_ip && !strcmp(src_ip, sofia_debug_filter))
		return 1;
	return 0;
}

/* post-T56 call-limit parity SS5 (2026-04-27): sip show inuse CLI command.
 * Mirrors chan_sip sip_show_inuse at chan_sip.c:17402-17449 byte-equivalent
 * (FORMAT strings + header text + row format preserved verbatim including
 * trailing space before \n — operator scripts pattern-match column alignment).
 *
 * Default shows only peers with call_limit>0; "all" arg shows every peer
 * including unlimited (call_limit==0 → "N/A" in Limit column).
 *
 * chan_sofia surpass: default-show filter ALSO includes peers with
 * busy_level>0 OR active runtime counters (inUse/inRinging/onHold>0) —
 * operator-friendly proactive monitoring without needing "all" arg. Strictly
 * more inclusive than chan_sip filter; no chan_sip operator script breakage. */
static char *sofia_cli_show_inuse(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
#define FORMAT "%-25.25s %-15.15s %-15.15s \n"
#define FORMAT2 "%-25.25s %-15.15s %-15.15s \n"
	char ilimits[40];
	char iused[40];
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
		if (peer->call_limit) {
			snprintf(ilimits, sizeof(ilimits), "%d", peer->call_limit);
		} else {
			ast_copy_string(ilimits, "N/A", sizeof(ilimits));
		}
		snprintf(iused, sizeof(iused), "%d/%d/%d",
			peer->inUse, peer->inRinging, peer->onHold);
		if (showall || peer->call_limit > 0 || peer->busy_level > 0
				|| peer->inUse > 0 || peer->inRinging > 0 || peer->onHold > 0) {
			ast_cli(a->fd, FORMAT2, peer->name, iused, ilimits);
		}
		ao2_unlock(peer);
		ao2_ref(peer, -1);
	}
	ao2_iterator_destroy(&iter);

	return CLI_SUCCESS;
#undef FORMAT
#undef FORMAT2
}

/* post-T56 useragent [general] parity (2026-04-28): minimal `sip show settings`
 * CLI seeded with User-Agent display line. chan_sip parity at chan_sip.c:19298
 * verbatim shape ("  User Agent:             %s\n"). Greenfield chan_sofia CLI;
 * incremental expansion as additional [general] knobs ship. Drop-in name "sip
 * show settings" matches chan_sip naming exactly per chan-sip-compat-naming-rules. */
static char *sofia_cli_show_settings(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
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
	/* post-T56 Task #2 D-3 SS1 (2026-04-28, GAP-3 fix + 28-FIELD MILESTONE):
	 * TLS/WS/WSS listener bind port visibility. Operator running `sip show
	 * settings` previously could not see which transports enabled without
	 * checking config or netstat. Display "(disabled)" when port == 0;
	 * display port number otherwise. CLI infrastructure 21st-task dividend
	 * post-25-FIELD MILESTONE; sofia_cli_show_settings advances 25 → 28 fields. */
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
	/* post-T56 ignoresdpversion [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:19268 verbatim "Ignore SDP sess. ver." wording. PARSE-COMPAT-ONLY
	 * display (chan_sofia processes every SDP unconditionally). */
	ast_cli(a->fd, "  Ignore SDP sess. ver.:  %s\n", AST_CLI_YESNO(sofia_cfg.default_ignoresdpversion));
	/* post-T56 progressinband [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:19425 verbatim "Progress inband" wording (Never/Yes/No tri-state
	 * via switch). Option B partial wire-in (NEVER + YES exact; NO degrades to NEVER). */
	ast_cli(a->fd, "  Progress inband:        %s\n",
		sofia_cfg.default_progressinband == SOFIA_PROG_INBAND_NEVER ? "Never" :
		sofia_cfg.default_progressinband == SOFIA_PROG_INBAND_YES ? "Yes" : "No");
	/* post-T56 subscribe_network_change_event [general] parity (2026-04-28): chan_sofia
	 * surpass IN-SCOPE per R11 — chan_sip sip show settings does NOT display this field
	 * (chan_sip displays only LOG_WARNING at parse-time on invalid). chan_sofia adds
	 * runtime CLI exposure for operator visibility (helper-architecture-advantage
	 * 14th-instance). PARSE-COMPAT-ONLY (chan_sofia delegates to sofia-sip + dnsmgr;
	 * flag has no behavioral effect). */
	ast_cli(a->fd, "  Network change subscribe: %s\n",
		AST_CLI_YESNO(sofia_cfg.subscribe_network_change_event));
	/* post-T56 rtsavesysname [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:19440 verbatim "Save sys. name" wording. Wire-in at 5 sofia_process_
	 * register ast_update_realtime sites includes regserver column when set + AST_
	 * SYSTEM_NAME non-empty. */
	ast_cli(a->fd, "  Save sys. name:         %s\n", AST_CLI_YESNO(sofia_cfg.rtsave_sysname));
	/* post-T56 rtupdate [general] parity (2026-04-28): chan_sip parity at chan_sip.c
	 * :19438 verbatim "Update:" wording. chan_sip-parity field display (NOT chan_sofia
	 * surpass — chan_sip already displays at sip show settings). Option C combined-
	 * gate at sofia_process_register paths skips ALL ast_update_realtime when clear. */
	ast_cli(a->fd, "  Update:                 %s\n", AST_CLI_YESNO(sofia_cfg.peer_rtupdate));
	/* post-T56 rtcachefriends [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:19437 verbatim "Cache Friends:" wording. chan_sip-parity field
	 * display (NOT chan_sofia surpass — chan_sip already displays). PARSE-COMPAT-
	 * ONLY (chan_sofia ao2 peer registry intrinsic-equivalent-to-yes baseline;
	 * always caches all peers regardless of flag value). 10th field on
	 * sofia_cli_show_settings — DOUBLE-DIGIT MILESTONE. */
	ast_cli(a->fd, "  Cache Friends:          %s\n", AST_CLI_YESNO(sofia_cfg.rtcachefriends));
	/* post-T56 rtautoclear [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:19441 verbatim "Auto Clear: %d (%s)" TWO-PIECE display (int seconds
	 * + Enabled|Disabled flag state). chan_sip-parity field (NOT chan_sofia surpass).
	 * PARSE-COMPAT-ONLY (chan_sofia ao2 registry no peer-level auto-clear infra).
	 * 11th field on sofia_cli_show_settings — post-DOUBLE-DIGIT-MILESTONE. */
	ast_cli(a->fd, "  Auto Clear:             %d (%s)\n", sofia_cfg.rtautoclear,
		sofia_cfg.rtautoclear_enabled ? "Enabled" : "Disabled");
	/* post-T56 domainsasrealm [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:19293 verbatim "Use domains as realms" wording. FULL WIRE-IN via
	 * Pattern 5 helper #29 sofia_get_realm_for_dialog at 3 auth-challenge callsites
	 * (chan_sofia helper-architecture-advantage 15th-instance). 12th field on
	 * sofia_cli_show_settings — post-DOUBLE-DIGIT-MILESTONE 8th-task dividend. */
	ast_cli(a->fd, "  Use domains as realms:  %s\n", AST_CLI_YESNO(sofia_cfg.domainsasrealm));
	/* post-T56 allowexternaldomains [general] parity (2026-04-28): chan_sip parity
	 * at chan_sip.c:19294 verbatim "Call to non-local dom.:" wording. FULL WIRE-IN
	 * via Pattern 5 helper #30 sofia_check_sip_domain at 2 INVITE/REFER gate
	 * callsites + retroactive-refactor of T46.2 + 5fbee76 walker pattern (chan_sofia
	 * helper-architecture-advantage 16th-instance NEW DIMENSION centralized-domain-
	 * validation). 13th field on sofia_cli_show_settings — 9th-task dividend. */
	ast_cli(a->fd, "  Call to non-local dom.: %s\n", AST_CLI_YESNO(sofia_cfg.allow_external_domains));
	/* post-T56 autodomain [general] parity (2026-04-28): chan_sofia surpass IN-SCOPE
	 * — chan_sip CLI ABSENT for autodomain (verified via grep at R-ACK; chan_sip
	 * does NOT display autodomain at sip show settings). chan_sofia adds runtime
	 * CLI exposure for operator visibility (helper-architecture-advantage 17th-
	 * instance NEW DIMENSION centralized-domain-list-mutation across config + auto-
	 * add dimensions). 14th field on sofia_cli_show_settings — 10th-task dividend
	 * post-DOUBLE-DIGIT-MILESTONE. */
	ast_cli(a->fd, "  Auto Domain:            %s\n", AST_CLI_YESNO(sofia_cfg.autodomain));
	/* post-T56 promiscredir [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:19274 verbatim "Allow promisc. redir." wording. PARSE-COMPAT-ONLY
	 * (chan_sofia nua_r_redirect handler ABSENT). 15th field on sofia_cli_show_
	 * settings — 11th-task dividend. */
	ast_cli(a->fd, "  Allow promisc. redir.:  %s\n", AST_CLI_YESNO(sofia_cfg.default_promiscredir));
	/* post-T56 matchexternaddrlocally [general] parity (2026-04-28): chan_sofia
	 * surpass IN-SCOPE — chan_sip CLI ABSENT for matchexternaddrlocally (verified
	 * via grep at R-ACK; typical NAT operator-edge-case flag pattern). chan_sofia
	 * adds runtime CLI exposure for operator visibility (helper-architecture-
	 * advantage 18th-instance — CLI-exposure-where-chan_sip-silent dimension joins
	 * autodomain eebeae6 + subscribe_network_change_event 25th precedent). PARSE-
	 * COMPAT-ONLY (chan_sofia sofia_should_use_externaddr signature divergence).
	 * 16th field on sofia_cli_show_settings — 12th-task dividend. */
	ast_cli(a->fd, "  Match extern locally:   %s\n", AST_CLI_YESNO(sofia_cfg.matchexternaddrlocally));
	/* post-T56 autoframing [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:19403 verbatim "Auto-Framing" wording. chan_sip-parity field display
	 * (NOT chan_sofia surpass — chan_sip already displays). PARSE-COMPAT-ONLY
	 * (chan_sofia sofia_parse_sdp ptime gate not wired today). 17th field on
	 * sofia_cli_show_settings — 13th-task dividend post-DOUBLE-DIGIT-MILESTONE. */
	ast_cli(a->fd, "  Auto-Framing:           %s\n", AST_CLI_YESNO(sofia_cfg.default_autoframing));
	/* post-T56 faxdetect [general] multi-mode parity (2026-04-28): 4-state display
	 * "Fax Detect" wording chan_sip-parity-style. chan_sip-parity field display
	 * (NOT chan_sofia surpass). SS6 (2026-04-28): chan_sofia fax-CNG + T.38 wire-
	 * in IMPLEMENTED — closes 55d4444 KNOWN LIMITATION. 18th field on sofia_cli_
	 * show_settings — 14th-task dividend post-DOUBLE-DIGIT-MILESTONE. */
	ast_cli(a->fd, "  Fax Detect:             %s\n",
		sofia_cfg.default_faxdetect_mode == SOFIA_FAX_DETECT_NONE ? "no" :
		sofia_cfg.default_faxdetect_mode == SOFIA_FAX_DETECT_BOTH ? "cng,t38" :
		sofia_cfg.default_faxdetect_mode == SOFIA_FAX_DETECT_CNG ? "cng" : "t38");
	/* post-T56 Task #8 T.38 fax UDPTL parity SS7 FINAL CLOSE (2026-04-28):
	 * [general] T.38 default MaxDatagram display per chan_sip.c:19316 verbatim
	 * semantic. Sentinel `-1` displayed as "(default 200)" per chan_sip pattern
	 * (chan_sip.c:29525 sets global_t38_maxdatagram = -1 = use built-in 200).
	 * 29th field on sofia_cli_show_settings — 22nd-task dividend post-25-FIELD
	 * MILESTONE; advances to 30-FIELD MILESTONE when SS7 closes. */
	if (sofia_cfg.default_t38_maxdatagram > 0) {
		ast_cli(a->fd, "  T.38 MaxDatagram:       %d\n", sofia_cfg.default_t38_maxdatagram);
	} else {
		ast_cli(a->fd, "  T.38 MaxDatagram:       (default 200)\n");
	}
	/* post-T56 mwiexpiry/mwiexpirey [general] parity (2026-04-28): chan_sofia surpass
	 * IN-SCOPE — chan_sip CLI ABSENT for mwi_expiry (verified via grep at SS1-time;
	 * chan_sip does NOT display mwi_expiry at sip show settings). chan_sofia adds
	 * runtime CLI exposure for operator visibility (helper-architecture-advantage
	 * 19th-instance — CLI-exposure-where-chan_sip-silent dimension joins autodomain
	 * eebeae6 + matchexternaddrlocally d930a3f + subscribe_network_change_event
	 * 25th-instance precedent). T55.1 wire-in active. 19th field on sofia_cli_show_
	 * settings — 15th-task dividend post-DOUBLE-DIGIT-MILESTONE. */
	ast_cli(a->fd, "  MWI expiry:             %d\n", sofia_cfg.mwi_expiry);
	/* post-T56 timerb [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:19412 verbatim "Timer B: %d" wording. chan_sip-parity field
	 * display + Pattern 16 sofia-sip-native 11th-instance NTATAG_SIP_T1X64
	 * wire-in active at nua_create. 20th field on sofia_cli_show_settings —
	 * 16th-task dividend post-DOUBLE-DIGIT-MILESTONE + 20-field DOUBLE-DIGIT
	 * MILESTONE on field count. */
	ast_cli(a->fd, "  Timer B:                %d\n", sofia_cfg.default_timer_b);
	/* post-T56 timert1 [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:19410 verbatim "Timer T1: %d" wording. chan_sip-parity field
	 * display + Pattern 16 sofia-sip-native 7th-instance REWIRED NTATAG_SIP_T1
	 * wire-in active at nua_create. 21st field on sofia_cli_show_settings —
	 * 17th-task dividend post-DOUBLE-DIGIT-MILESTONE post-20-FIELD MILESTONE. */
	ast_cli(a->fd, "  Timer T1:               %d\n", sofia_cfg.default_timer_t1);
	/* post-T56 allowoverlap [general] parity (2026-04-28, Option A FULL WIRE-IN):
	 * chan_sip parity at chan_sip.c:19273 verbatim "Allow overlap dialing:  %s"
	 * wording (double-space). 22nd field on sofia_cli_show_settings — 18th-task
	 * dividend post-DOUBLE-DIGIT-MILESTONE post-21-FIELD MILESTONE. */
	ast_cli(a->fd, "  Allow overlap dialing:  %s\n", sofia_allowoverlap_str(sofia_cfg.default_allowoverlap_mode));
	/* post-T56 Task 7b SRTP per-suite-fresh-key option (2026-04-28, deferred from
	 * #7a 612759d R4 strategy (b)): chan_sofia surpass dimension feature-not-in-
	 * chan_sip-at-all. CLI infrastructure 19th-task dividend post-22-FIELD MILESTONE.
	 * 23rd field on sofia_cli_show_settings. */
	ast_cli(a->fd, "  SRTP per-suite keys:    %s\n", AST_CLI_YESNO(sofia_cfg.srtp_per_suite_keys));
	/* post-T56 Task #3 INVITE digest auth SS3 (2026-04-28, R18 chan_sofia surpass
	 * dimension operator-policy-global-security-override): chan_sofia surpass —
	 * no chan_sip equivalent. CLI infrastructure 20th-task dividend post-23-FIELD
	 * MILESTONE. 24th field on sofia_cli_show_settings. */
	ast_cli(a->fd, "  Force INVITE auth:      %s\n", AST_CLI_YESNO(sofia_cfg.force_invite_auth));
	/* post-T56 Task #3 INVITE digest auth SS4 (2026-04-28, RFC 7616 chan_sofia
	 * surpass over chan_sip MD5-only — auth-algorithm-modernization-where-chan_
	 * sip-MD5-only NEW DIMENSION). CLI infrastructure 21st-task dividend post-
	 * 24-FIELD MILESTONE. 25th field on sofia_cli_show_settings. Static "MD5,
	 * SHA-256" reports the verifier capabilities; challenges are sent MD5-first
	 * and may omit SHA-256 for md5secret-only peers. */
	ast_cli(a->fd, "  Auth algorithms:        MD5, SHA-256\n");
	ast_cli(a->fd, "\n");

	return CLI_SUCCESS;
}

static char *sofia_set_debug(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	const char *what;

	if (cmd == CLI_INIT) {
		e->command = "sip set debug";
		e->usage =
			"Usage: sip set debug [on|off|peer <name>|ip <addr>]\n"
			"       Show current debug state, or enable/disable Sofia-SIP debug.\n"
			"       'on'  - enable debug for all peers\n"
			"       'off' - disable debug\n"
			"       'peer <name>' - enable debug for a specific peer\n"
			"       'ip <addr>'   - enable debug for a specific IP address\n";
		return NULL;
	} else if (cmd == CLI_GENERATE) {
		if (a->pos == 3)
			return ast_cli_complete(a->word, (const char *[]){ "on", "off", "peer", "ip", NULL }, a->n);
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

	if (!strcasecmp(what, "on")) {
		sofia_debug = 1;
		sofia_debug_filter[0] = '\0';
		if (sofia_nua)
			tport_set_params(nta_agent_tports(nua_get_agent(sofia_nua)), TPTAG_LOG(1), TAG_END());
		ast_cli(a->fd, "Sofia debug enabled\n");
		return CLI_SUCCESS;
	} else if (!strcasecmp(what, "off")) {
		sofia_debug = 0;
		sofia_debug_filter[0] = '\0';
		if (sofia_nua)
			tport_set_params(nta_agent_tports(nua_get_agent(sofia_nua)), TPTAG_LOG(0), TAG_END());
		ast_cli(a->fd, "Sofia debug disabled\n");
		return CLI_SUCCESS;
	} else if (!strcasecmp(what, "peer")) {
		if (a->argc != 5)
			return CLI_SHOWUSAGE;
		sofia_debug = 2;
		ast_copy_string(sofia_debug_filter, a->argv[4], sizeof(sofia_debug_filter));
		if (sofia_nua)
			tport_set_params(nta_agent_tports(nua_get_agent(sofia_nua)), TPTAG_LOG(0), TAG_END());
		ast_cli(a->fd, "Sofia debug enabled for peer '%s'\n", sofia_debug_filter);
		return CLI_SUCCESS;
	} else if (!strcasecmp(what, "ip")) {
		if (a->argc != 5)
			return CLI_SHOWUSAGE;
		sofia_debug = 3;
		ast_copy_string(sofia_debug_filter, a->argv[4], sizeof(sofia_debug_filter));
		if (sofia_nua)
			tport_set_params(nta_agent_tports(nua_get_agent(sofia_nua)), TPTAG_LOG(0), TAG_END());
		ast_cli(a->fd, "Sofia debug enabled for IP '%s'\n", sofia_debug_filter);
		return CLI_SUCCESS;
	}

	return CLI_SHOWUSAGE;
}

/* Forward declaration so the `sip reload` CLI alias below can invoke the
 * same config-reread path that AST_MODULE_INFO's .reload hook uses. The
 * full definition lives at sofia_load_config() much further down the file. */
static int sofia_load_config(int reload);
static int sofia_reload_request_sync(char *errmsg, size_t errmsglen, int timeout_ms);

/* chan_sip-parity `sip reload` CLI alias. chan_sip exposes a dedicated
 * `sip reload` command at chan_sip.c:31171; operators and reload-scripts
 * historically type `sip reload` rather than `module reload chan_sofia.so`.
 * The two are equivalent — both go through sofia_reload_request_sync,
 * which posts the work onto sofia_thread (the NUA event loop) via
 * sofia_dispatch_to_root_thread.  Running the reload there eliminates
 * the UAF races on sofia_cfg.localha / sofia_cfg.contact_ha and the
 * peer->chanvars UAF that the historical "run on the caller's thread"
 * model carried.  Listener-config changes are detected and refused with
 * a clear error.  No SIP traffic is paused beyond the brief
 * defaults-reset + parse window. */
static char *sofia_cli_reload(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
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
			"       tlsbindport/tlscertfile/wsbindaddr/wsbindport/wssbindaddr/\n"
			"       wssbindport/timert1/timerb) are baked into the SIP listener\n"
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

/* post-T56 sip prune realtime CLI parity (2026-04-27): tab-completion helper.
 * Mirrors chan_sip complete_sip_peer at chan_sip.c:19640 — walks peers ao2
 * container with optional realtime filter; returns ast_strdup(peer->name) on
 * the N-th match for state==N. chan_sofia uses peer->is_realtime int field
 * (chan_sip parity replaces SIP_PAGE2_RTCACHEFRIENDS flag-bit with simpler
 * int check). When only_realtime==0, all peers match; when 1, only realtime
 * peers (matches CLI_GENERATE position-4 + position-5 use cases of
 * sofia_cli_prune_realtime which want realtime-only completions). */
static char *complete_sofia_peer(const char *word, int state, int only_realtime)
{
	char *result = NULL;
	int wordlen = strlen(word);
	int which = 0;
	struct ao2_iterator i = ao2_iterator_init(peers, 0);
	struct sofia_peer *peer;

	while ((peer = ao2_iterator_next(&i))) {
		if (!strncasecmp(word, peer->name, wordlen)
				&& (!only_realtime || peer->is_realtime)
				&& ++which > state) {
			result = ast_strdup(peer->name);
		}
		ao2_ref(peer, -1);
		if (result) {
			break;
		}
	}
	ao2_iterator_destroy(&i);
	return result;
}


/* post-T56 sip prune realtime CLI parity (2026-04-27): operator cache-flush
 * command. Mirrors chan_sip sip_prune_realtime at chan_sip.c:18249-18385
 * with full 4-form argv parity (R2) + 5-output-string parity (R7) +
 * single-container architecture (R5; chan_sofia has no peers_by_ip). When an
 * operator edits a peer's config via SQL, this command flushes the in-memory
 * cached realtime peer so the next access reloads fresh values from realtime.
 * Without this, gabpbx restart was the only flush mechanism (T40 non-unloadable). */
static char *sofia_cli_prune_realtime(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
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
			/* R4 single-pass ao2_iterator + manual ao2_unlink + counter.
			 * chan_sofia simpler than chan_sip's two-phase the_mark+sweep
			 * (chan_sip needs the_mark for cross-container peers_by_ip
			 * unlink; chan_sofia has no peers_by_ip per R5). ao2 allows
			 * unlink during iteration since iterator holds its own ref. */
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

static char *sofia_cli_show_blacklist(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
#define BLACKLIST_FORMAT "%-39s %-11s %-19s %-19s\n"
	struct ao2_iterator iter;
	struct sofia_blacklist_entry *entry;
	int total = 0;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show blacklist";
		e->usage =
			"Usage: sip show blacklist\n"
			"       Lists local Sofia-SIP blacklist entries.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (!sofia_blacklist) {
		ast_cli(a->fd, "Blacklist is not initialized\n");
		return CLI_FAILURE;
	}

	ast_cli(a->fd, BLACKLIST_FORMAT, "IP", "Counter", "First seen", "Last seen");
	ast_mutex_lock(&sofia_blacklist_lock);
	iter = ao2_iterator_init(sofia_blacklist, 0);
		while ((entry = ao2_iterator_next(&iter))) {
			char first[32];
			char last[32];
			char counter[32];
			struct ast_tm tm;
			struct timeval tv;

			tv.tv_sec = entry->first_seen;
			tv.tv_usec = 0;
			ast_localtime(&tv, &tm, NULL);
			ast_strftime(first, sizeof(first), "%Y-%m-%d %H:%M:%S", &tm);
			tv.tv_sec = entry->last_seen;
			tv.tv_usec = 0;
			ast_localtime(&tv, &tm, NULL);
			ast_strftime(last, sizeof(last), "%Y-%m-%d %H:%M:%S", &tm);
		snprintf(counter, sizeof(counter), "%d/%d",
			entry->counter, sofia_blacklist_count);

		ast_cli(a->fd, BLACKLIST_FORMAT, entry->ip, counter, first, last);
		ao2_ref(entry, -1);
		total++;
	}
	ao2_iterator_destroy(&iter);
	ast_mutex_unlock(&sofia_blacklist_lock);

	ast_cli(a->fd, "Total %d/%d\n", total, sofia_blacklist_max);
	return CLI_SUCCESS;
#undef BLACKLIST_FORMAT
}

static char *sofia_cli_blacklist_search(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct sofia_blacklist_entry key;
	struct sofia_blacklist_entry *entry;
	char ip[80];

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip blacklist search";
		e->usage =
			"Usage: sip blacklist search <IP>\n"
			"       Search an IP in the local Sofia-SIP blacklist.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 4) {
		return CLI_SHOWUSAGE;
	}
	if (sofia_blacklist_ip_from_text(a->argv[3], ip, sizeof(ip)) < 0) {
		return CLI_SHOWUSAGE;
	}

	memset(&key, 0, sizeof(key));
	ast_copy_string(key.ip, ip, sizeof(key.ip));
	ast_mutex_lock(&sofia_blacklist_lock);
	entry = sofia_blacklist ? ao2_find(sofia_blacklist, &key, OBJ_POINTER) : NULL;
	if (entry) {
		ast_cli(a->fd, "Found IP %s local blacklist (%d/%d)\n",
			entry->ip, entry->counter, sofia_blacklist_count);
		ao2_ref(entry, -1);
	} else {
		ast_cli(a->fd, "IP %s not exist\n", ip);
	}
	ast_mutex_unlock(&sofia_blacklist_lock);

	return CLI_SUCCESS;
}

static char *sofia_cli_blacklist_delete(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct sofia_blacklist_entry key;
	struct sofia_blacklist_entry *entry;
	char ip[80];

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip blacklist delete";
		e->usage =
			"Usage: sip blacklist delete <IP>\n"
			"       Delete an IP from the local Sofia-SIP blacklist.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 4) {
		return CLI_SHOWUSAGE;
	}
	if (sofia_blacklist_ip_from_text(a->argv[3], ip, sizeof(ip)) < 0) {
		return CLI_SHOWUSAGE;
	}

	memset(&key, 0, sizeof(key));
	ast_copy_string(key.ip, ip, sizeof(key.ip));
	ast_mutex_lock(&sofia_blacklist_lock);
	entry = sofia_blacklist ? ao2_find(sofia_blacklist, &key, OBJ_POINTER | OBJ_UNLINK) : NULL;
	if (entry) {
		ast_cli(a->fd, "IP %s delete from local blacklist\n", ip);
		ao2_ref(entry, -1);
	} else {
		ast_cli(a->fd, "IP %s not found\n", ip);
	}
	ast_mutex_unlock(&sofia_blacklist_lock);

	return CLI_SUCCESS;
}

static int sofia_blacklist_clear_cb(void *obj, void *arg, int flags)
{
	int *count = arg;

	(*count)++;
	return CMP_MATCH;
}

static char *sofia_cli_blacklist_clear(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	int deleted = 0;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip blacklist clear";
		e->usage =
			"Usage: sip blacklist clear\n"
			"       Clear local Sofia-SIP blacklist.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 3) {
		return CLI_SHOWUSAGE;
	}

	ast_mutex_lock(&sofia_blacklist_lock);
	if (sofia_blacklist) {
		ao2_callback(sofia_blacklist, OBJ_UNLINK | OBJ_NODATA | OBJ_MULTIPLE,
			sofia_blacklist_clear_cb, &deleted);
	}
	ast_mutex_unlock(&sofia_blacklist_lock);
	ast_cli(a->fd, "Delete %d items\n", deleted);

	return CLI_SUCCESS;
}

static struct ast_cli_entry cli_sofia[] = {
	AST_CLI_DEFINE(sofia_cli_show_peers, "List Sofia-SIP peers"),
	AST_CLI_DEFINE(sofia_cli_show_channels, "List active Sofia-SIP channels"),
	AST_CLI_DEFINE(sofia_cli_show_peer, "Show detailed Sofia-SIP peer info"),
	AST_CLI_DEFINE(sofia_cli_show_inuse, "Show SIP peer call usage counters"),
	AST_CLI_DEFINE(sofia_cli_show_settings, "Show Sofia-SIP global settings"),
	AST_CLI_DEFINE(sofia_cli_prune_realtime, "Prune cached Realtime users/peers"),
	AST_CLI_DEFINE(sofia_set_debug, "Enable Sofia debug logging"),
	AST_CLI_DEFINE(sofia_cli_reload, "Reload sofia.conf (chan_sip-parity alias for `module reload chan_sofia.so`)"),
	AST_CLI_DEFINE(sofia_cli_show_blacklist, "List local SIP blacklist"),
	AST_CLI_DEFINE(sofia_cli_blacklist_search, "Search an IP in local SIP blacklist"),
	AST_CLI_DEFINE(sofia_cli_blacklist_delete, "Delete an IP from local SIP blacklist"),
	AST_CLI_DEFINE(sofia_cli_blacklist_clear, "Clear local SIP blacklist"),
};

static void sofia_parse_register_line(const char *value)
{
	char buf[256];
	char *userpart, *hostpart, *user, *secret, *host, *portstr;
	int port = DEFAULT_SIP_PORT;
	struct sofia_peer *peer;

	if (ast_strlen_zero(value)) {
		ast_log(LOG_WARNING, "Sofia: Empty register=> line, ignoring\n");
		return;
	}

	ast_copy_string(buf, value, sizeof(buf));

	/* Split at @: userpart@hostpart */
	hostpart = strchr(buf, '@');
	if (!hostpart) {
		ast_log(LOG_WARNING, "Sofia: Invalid register=> format (missing @): %s\n", value);
		return;
	}
	*hostpart++ = '\0';
	userpart = buf;

	/* Split userpart: user[:secret] */
	user = userpart;
	secret = strchr(userpart, ':');
	if (secret) {
		*secret++ = '\0';
	}

	/* Split hostpart: host[:port] */
	host = hostpart;
	portstr = strchr(hostpart, ':');
	if (portstr) {
		*portstr++ = '\0';
		port = atoi(portstr);
		if (port <= 0) port = DEFAULT_SIP_PORT;
	}

	if (ast_strlen_zero(user) || ast_strlen_zero(host)) {
		ast_log(LOG_WARNING, "Sofia: Invalid register=> format (empty user or host): %s\n", value);
		return;
	}
	if (ast_strlen_zero(secret)) {
		ast_log(LOG_WARNING, "Sofia: register=> line for '%s' has no secret, skipping\n", user);
		return;
	}

	/* Find-or-alloc, like sofia_parse_peer_config does for [section] peers.
	 * Without this, every reload that re-parses a `register =>` line would
	 * sofia_peer_alloc + ao2_link a SECOND struct with the same name into
	 * the peers container — the peers container has no name-based hash
	 * (allocated with hash_fn=NULL at chan_sofia.c:17445), so duplicates
	 * by name are silently allowed.  The mark-and-sweep sweep would then
	 * race to remove the OLD struct (marked at reload-start) while the
	 * NEW one (allocated with _reload_marked = 0) survives, but during
	 * the worker's parse window BOTH would coexist and sofia_find_peer
	 * would return whichever ao2 happened to put first — unpredictable. */
	{
		int new_alloc = 0;
		peer = sofia_find_peer(user);
		if (!peer) {
			peer = sofia_peer_alloc(user);
			if (!peer) {
				ast_log(LOG_ERROR, "Sofia: Failed to allocate peer for register=> line\n");
				return;
			}
			new_alloc = 1;
		}

		ast_mutex_lock(&peer->lock);
		ast_string_field_set(peer, secret, secret);
		ast_string_field_set(peer, host, host);
		ast_string_field_set(peer, defaultuser, user);
		peer->port = port;
		peer->type = SOFIA_TYPE_PEER;
		peer->is_register_line = 1;
		ast_mutex_unlock(&peer->lock);

		/* Survives this reload — must not be swept. */
		peer->_reload_marked = 0;

		if (new_alloc) {
			ao2_link(peers, peer);
			ast_verbose("Sofia: register=> peer '%s' created (target %s:%d)\n",
				user, host, port);
		}
		ao2_ref(peer, -1);
	}
}

static void sofia_parse_general_config(struct ast_config *cfg)
{
	struct ast_variable *v;

	for (v = ast_variable_browse(cfg, "general"); v; v = v->next) {
		if (!strcasecmp(v->name, "bindaddr")) {
			ast_copy_string(sofia_cfg.bindaddr, v->value, sizeof(sofia_cfg.bindaddr));
		} else if (!strcasecmp(v->name, "bindport") || !strcasecmp(v->name, "udpbindaddr")) {
			if (strchr(v->value, ':')) {
				char *port_str = strchr((char *)v->value, ':');
				*port_str = '\0';
				port_str++;
				ast_copy_string(sofia_cfg.bindaddr, v->value, sizeof(sofia_cfg.bindaddr));
				sofia_cfg.bindport = atoi(port_str);
			} else {
				sofia_cfg.bindport = atoi(v->value);
			}
		} else if (!strcasecmp(v->name, "port")) {
			sofia_cfg.bindport = atoi(v->value);
		} else if (!strcasecmp(v->name, "tlsbindaddr")) {
			ast_copy_string(sofia_cfg.tlsbindaddr, v->value, sizeof(sofia_cfg.tlsbindaddr));
		} else if (!strcasecmp(v->name, "tlsbindport")) {
			sofia_cfg.tlsbindport = atoi(v->value);
		} else if (!strcasecmp(v->name, "tlscertfile") || !strcasecmp(v->name, "tlscertdir")) {
			ast_copy_string(sofia_cfg.tlscertfile, v->value, sizeof(sofia_cfg.tlscertfile));
		} else if (!strcasecmp(v->name, "wsbindaddr")) {
			ast_copy_string(sofia_cfg.wsbindaddr, v->value, sizeof(sofia_cfg.wsbindaddr));
		} else if (!strcasecmp(v->name, "wsbindport")) {
			sofia_cfg.wsbindport = atoi(v->value);
		} else if (!strcasecmp(v->name, "wssbindaddr")) {
			ast_copy_string(sofia_cfg.wssbindaddr, v->value, sizeof(sofia_cfg.wssbindaddr));
		} else if (!strcasecmp(v->name, "wssbindport")) {
			sofia_cfg.wssbindport = atoi(v->value);
		} else if (!strcasecmp(v->name, "context")) {
			ast_copy_string(sofia_cfg.context, v->value, sizeof(sofia_cfg.context));
		} else if (!strcasecmp(v->name, "realm")) {
			ast_copy_string(sofia_cfg.realm, v->value, sizeof(sofia_cfg.realm));
		} else if (!strcasecmp(v->name, "useragent")) {
			/* post-T56 useragent [general] parity (2026-04-28): operator override
			 * of User-Agent header value. chan_sip parity chan_sip.c:29574-29575
			 * verbatim:
			 *   ast_copy_string(global_useragent, v->value, sizeof(global_useragent));
			 *   ast_debug(1, "Setting SIP channel User-Agent Name to %s\n", global_useragent);
			 * Empty string ALLOWED — wire-in skips SIPTAG_USER_AGENT_STR via
			 * TAG_IF(!ast_strlen_zero(...)) so sofia-sip falls back to library default. */
			ast_copy_string(sofia_cfg.useragent, v->value, sizeof(sofia_cfg.useragent));
			ast_debug(1, "Sofia: Setting SIP channel User-Agent to %s\n", sofia_cfg.useragent);
		} else if (!strcasecmp(v->name, "allowguest")) {
			sofia_cfg.allowguest = ast_true(v->value);
		} else if (!strcasecmp(v->name, "busy_on_active")) {
			sofia_cfg.busy_on_active = ast_true(v->value);
		} else if (!strcasecmp(v->name, "max_contacts")) {
			sofia_cfg.max_contacts = sofia_clamp_max_contacts(atoi(v->value), "general");
		} else if (!strcasecmp(v->name, "encryption")) {
			sofia_cfg.encryption = ast_true(v->value);
		} else if (!strcasecmp(v->name, "default_srtpcipher") || !strcasecmp(v->name, "srtpcipher")) {
			/* post-T56 srtpcipher operator option (2026-04-27): default cipher list inherited
			 * by sofia_peer_alloc when peer omits the key. Both default_srtpcipher and bare
			 * srtpcipher accepted in [general] (chan_sip MOH-style leniency). */
			ast_copy_string(sofia_cfg.default_srtpcipher, v->value, sizeof(sofia_cfg.default_srtpcipher));
		} else if (!strcasecmp(v->name, "srtp_per_suite_keys")) {
			/* post-T56 Task 7b SRTP per-suite-fresh-key option (2026-04-28, deferred
			 * from #7a 612759d R4 strategy (b)): chan_sofia surpass dimension feature-
			 * not-in-chan_sip-at-all (chan_sip has no multi-suite SRTP offer mechanism
			 * therefore no shared-vs-per-suite key strategy choice). [general]-only
			 * operator option (no per-peer override). Default 0 = shared-key mode
			 * preserves #7a strategy (a) baseline (current behavior). */
			sofia_cfg.srtp_per_suite_keys = ast_true(v->value);
			sofia_srtp_per_suite_keys = sofia_cfg.srtp_per_suite_keys;
		} else if (!strcasecmp(v->name, "force_invite_auth")) {
			/* post-T56 Task #3 INVITE digest auth SS3 (2026-04-28, R18 chan_sofia
			 * surpass dimension operator-policy-global-security-override): when
			 * set, ALL inbound INVITEs require digest auth regardless of per-peer
			 * insecure=invite config. Operator security-lockdown switch — no
			 * chan_sip equivalent. [general]-only (no per-peer override; policy
			 * is global). */
			sofia_cfg.force_invite_auth = ast_true(v->value);
		} else if (!strcasecmp(v->name, "nonce_ttl_seconds")) {
			/* Operator override for nonce time-based staleness checks. The default
			 * is 3600s, aligned with the normal SIP registration maximum; smaller
			 * values can be used for stricter deployments. Invalid values fall
			 * back to SOFIA_NONCE_TTL_SEC_DEFAULT with LOG_WARNING. */
			int tmp_ttl = atoi(v->value);
			if (tmp_ttl > 0) {
				sofia_cfg.nonce_ttl_seconds = tmp_ttl;
			} else {
				ast_log(LOG_WARNING, "Sofia: invalid nonce_ttl_seconds '%s' "
					"(must be positive integer); using default %d\n",
					v->value, SOFIA_NONCE_TTL_SEC_DEFAULT);
				sofia_cfg.nonce_ttl_seconds = 0;
			}
		} else if (!strcasecmp(v->name, "session-timers")) {
			/* post-T56 session timers (RFC 4028) (2026-04-27): [general] default; chan_sip parity. */
			if (!strcasecmp(v->value, "originate"))      sofia_cfg.default_session_timers = SESSION_TIMERS_ORIGINATE;
			else if (!strcasecmp(v->value, "accept"))    sofia_cfg.default_session_timers = SESSION_TIMERS_ACCEPT;
			else if (!strcasecmp(v->value, "refuse"))    sofia_cfg.default_session_timers = SESSION_TIMERS_REFUSE;
			else {
				ast_log(LOG_WARNING, "Sofia: invalid [general] session-timers value '%s' — using ACCEPT default\n", v->value);
				sofia_cfg.default_session_timers = SESSION_TIMERS_ACCEPT;
			}
		} else if (!strcasecmp(v->name, "session-expires")) {
			sofia_cfg.default_session_expires = atoi(v->value);
			if (sofia_cfg.default_session_expires < 90) sofia_cfg.default_session_expires = 1800;
		} else if (!strcasecmp(v->name, "session-minse")) {
			sofia_cfg.default_session_minse = atoi(v->value);
			if (sofia_cfg.default_session_minse < 90) sofia_cfg.default_session_minse = 90;
		} else if (!strcasecmp(v->name, "session-refresher")) {
			if (!strcasecmp(v->value, "uac"))      sofia_cfg.default_session_refresher = SESSION_REFRESHER_UAC;
			else if (!strcasecmp(v->value, "uas")) sofia_cfg.default_session_refresher = SESSION_REFRESHER_UAS;
			else                                   sofia_cfg.default_session_refresher = SESSION_REFRESHER_AUTO;
		} else if (!strcasecmp(v->name, "callingpres")) {
			/* post-T56 identity-headers parity (2026-04-27): default presentation for peers that
			 * omit callingpres=. Reuses ast_parse_caller_presentation (callerid.h:356). */
			int p = ast_parse_caller_presentation(v->value);
			sofia_cfg.default_callingpres = (p < 0) ? AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED : p;
		} else if (!strcasecmp(v->name, "sendrpid")) {
			/* post-T56 identity-headers parity (2026-04-27): default outbound RPID/PAI emission mode. */
			if (!strcasecmp(v->value, "pai")) sofia_cfg.default_sendrpid = 1;
			else if (!strcasecmp(v->value, "rpid")) sofia_cfg.default_sendrpid = 2;
			else sofia_cfg.default_sendrpid = 0;
		} else if (!strcasecmp(v->name, "trustrpid")) {
			/* post-T56 identity-headers parity (2026-04-27): default trust on inbound PAI/RPID. */
			sofia_cfg.default_trustrpid = ast_true(v->value);
		} else if (!strcasecmp(v->name, "callcounter")) {
			/* post-T56 call-limit parity SS1 (2026-04-27): default callcounter shorthand. */
			sofia_cfg.default_call_limit = ast_true(v->value) ? INT_MAX : 0;
		} else if (!strcasecmp(v->name, "call-limit") || !strcasecmp(v->name, "call_limit")) {
			/* post-T56 call-limit parity SS1 (2026-04-27): default cap inherited by sofia_peer_alloc. */
			sofia_cfg.default_call_limit = atoi(v->value);
			if (sofia_cfg.default_call_limit < 0) sofia_cfg.default_call_limit = 0;
		} else if (!strcasecmp(v->name, "busylevel")) {
			/* post-T56 call-limit parity SS1 (2026-04-27): default busy-level inherited by sofia_peer_alloc. */
			sofia_cfg.default_busy_level = atoi(v->value);
			if (sofia_cfg.default_busy_level < 0) sofia_cfg.default_busy_level = 0;
		} else if (!strcasecmp(v->name, "default_allowtransfer") || !strcasecmp(v->name, "allowtransfer")) {
			/* post-T56 allowtransfer per-peer parity (2026-04-27): default REFER policy
			 * inherited by sofia_peer_alloc when peer omits the key. Both default_allowtransfer
			 * and bare allowtransfer accepted in [general] (chan_sip MOH-style leniency).
			 * chan_sip parity at chan_sip.c:29587 verbatim binary parser. */
			sofia_cfg.default_allowtransfer = ast_true(v->value) ? TRANSFER_OPENFORALL : TRANSFER_CLOSED;
		} else if (!strcasecmp(v->name, "allowsubscribe")) {
			/* post-T56 allowsubscribe [general] parity (2026-04-27): chan_sip parity
			 * at chan_sip.c:29478 (ast_set_flag global_flags[1] SIP_PAGE2_ALLOWSUBSCRIBE
			 * default TRUE per sip.h:478). REQUEST-EVENT GATING dimension #6 sibling to
			 * allowtransfer. Sets the [general] inheritance default for new peers; the
			 * derived sofia_cfg.allowsubscribe global ban-all flag is computed by
			 * sofia_post_config_derive_allowsubscribe at config-load conclusion. */
			sofia_cfg.default_allowsubscribe = ast_true(v->value);
		} else if (!strcasecmp(v->name, "regcontext")) {
			/* post-T56 regexten parity (2026-04-27): chan_sip parity at chan_sip.c:29711-29721.
			 * Master switch — empty disables the entire register_peer_exten mechanism. Names
			 * the dialplan context where extensions get auto-added on REGISTER + auto-removed
			 * on unregister. cleanup_stale_contexts on regcontext-value-change across reload
			 * (chan_sip.c:29714) intentionally not mirrored — chan_sofia is non-unloadable per
			 * T40 architectural; operators restart for regcontext value changes. */
			ast_copy_string(sofia_cfg.regcontext, v->value, sizeof(sofia_cfg.regcontext));
		} else if (!strcasecmp(v->name, "regextenonqualify")) {
			/* post-T56 regextenonqualify parity (2026-04-27): chan_sip parity at
			 * chan_sip.c:29722-29723. Couples regexten add/remove to qualify state transitions —
			 * extension auto-added when peer transitions INTO REACHABLE / auto-removed when
			 * INTO UNREACHABLE. Default 0 (FALSE) per sip.h:215 DEFAULT_REGEXTENONQUALIFY. */
			sofia_cfg.regextenonqualify = ast_true(v->value);
		} else if (!strcasecmp(v->name, "subscribecontext")) {
			/* post-T56 subscribecontext per-peer parity (2026-04-27): chan_sip parity
			 * at chan_sip.c:29564-29565 — [general] default subscribecontext inherited
			 * by sofia_peer_alloc when peer omits the key. KNOWN LIMITATION: pivot-site
			 * override at sofia_process_subscribe deferred (no dialplan-dispatch
			 * infrastructure for SUBSCRIBE today); field parsed + persisted + displayed
			 * for drop-in chan_sip config-parse compat. */
			ast_copy_string(sofia_cfg.default_subscribecontext, v->value, sizeof(sofia_cfg.default_subscribecontext));
		} else if (!strcasecmp(v->name, "maxexpiry") || !strcasecmp(v->name, "maxexpirey")) {
			/* post-T56 registration TTL bounds + 423 Interval Too Brief parity (2026-04-27):
			 * chan_sip parity at chan_sip.c:29760-29764 — typo-tolerance dual-acceptance
			 * (historical maxexpirey + corrected maxexpiry both accepted). Clamp invalid
			 * values to DEFAULT_MAX_EXPIRY per chan_sip parity at L29762-29763. */
			sofia_cfg.max_expiry = atoi(v->value);
			if (sofia_cfg.max_expiry < 1) {
				sofia_cfg.max_expiry = DEFAULT_MAX_EXPIRY;
			}
		} else if (!strcasecmp(v->name, "minexpiry") || !strcasecmp(v->name, "minexpirey")) {
			/* post-T56 registration TTL bounds parity (2026-04-27): chan_sip parity at
			 * chan_sip.c:29765-29769 — typo-tolerance dual-acceptance. */
			sofia_cfg.min_expiry = atoi(v->value);
			if (sofia_cfg.min_expiry < 1) {
				sofia_cfg.min_expiry = DEFAULT_MIN_EXPIRY;
			}
		} else if (!strcasecmp(v->name, "defaultexpiry") || !strcasecmp(v->name, "defaultexpirey")) {
			/* post-T56 registration TTL bounds parity (2026-04-27): chan_sip parity at
			 * chan_sip.c:29770-29774 — typo-tolerance dual-acceptance. Option A dual-scope:
			 * [general] defaultexpiry inherited by peer->expiresecs at sofia_peer_alloc;
			 * existing per-peer expiresecs/defaultexpiry alias at sofia_parse_peer_config
			 * KEPT for legacy chan_sofia operators (KNOWN DIVERGENCE from chan_sip
			 * [general]-only — documented in sofia.conf.sample). */
			sofia_cfg.default_expiry = atoi(v->value);
			if (sofia_cfg.default_expiry < 1) {
				sofia_cfg.default_expiry = DEFAULT_DEFAULT_EXPIRY;
			}
		} else if (!strcasecmp(v->name, "usereqphone")) {
			/* post-T56 usereqphone parity (2026-04-27): chan_sip parity at
			 * chan_sip.c:29660-29661 — [general] default inherited by sofia_peer_alloc.
			 * RFC 3966 telephone-uri ;user=phone parameter for E.164 numbers via PSTN
			 * gateways. */
			sofia_cfg.default_usereqphone = ast_true(v->value);
		} else if (!strcasecmp(v->name, "maxforwards")) {
			/* post-T56 maxforwards parity (2026-04-27): chan_sip parity at
			 * chan_sip.c:30011-30015 verbatim — [general] default inherited by
			 * sofia_peer_alloc; sscanf %30d + 1-255 bounds-check + clamp-to-default. */
			if (sscanf(v->value, "%30d", &sofia_cfg.default_max_forwards) != 1
				|| sofia_cfg.default_max_forwards < 1 || 255 < sofia_cfg.default_max_forwards) {
				ast_log(LOG_WARNING, "Sofia: '%s' is not a valid [general] maxforwards value — using default %d\n",
					v->value, DEFAULT_MAX_FORWARDS);
				sofia_cfg.default_max_forwards = DEFAULT_MAX_FORWARDS;
			}
		} else if (!strcasecmp(v->name, "t1min")) {
			/* post-T56 t1min parity (2026-04-27): RFC 3261 §17.1.1.2 T1 retry-timer
			 * minimum bound (milliseconds). chan_sip parity at chan_sip.c:29608.
			 * Defensive minimum 10ms — values below cause spurious retransmission storms
			 * (chan_sofia operator-honest minimum guard; chan_sip accepts any int). */
			int v_int = 0;
			if (sscanf(v->value, "%30d", &v_int) != 1 || v_int < 10) {
				ast_log(LOG_WARNING, "Sofia: '%s' is not a valid [general] t1min value (minimum 10ms) — using default %d\n",
					v->value, DEFAULT_T1MIN);
				sofia_cfg.t1min = DEFAULT_T1MIN;
			} else {
				sofia_cfg.t1min = v_int;
			}
		} else if (!strcasecmp(v->name, "relaxdtmf")) {
			/* post-T56 relaxdtmf parity (2026-04-27): chan_sip parity at
			 * chan_sip.c:29664-29665 — DSP_DIGITMODE_RELAXDTMF flag toggle for poor-quality
			 * line DTMF detection (relaxes threshold; trades sensitivity for false-positive
			 * tolerance). */
			sofia_cfg.relaxdtmf = ast_true(v->value);
		} else if (!strcasecmp(v->name, "prematuremedia")) {
			/* post-T56 prematuremedia parity (2026-04-27): chan_sip parity at
			 * chan_sip.c:29662-29663 — INVERTED-SEMANTIC chan_sip-quirk preserved verbatim:
			 * operator-key "prematuremedia=yes" → variable TRUE → filter ON → 183 Session
			 * Progress SUPPRESSED. operator-key "prematuremedia=no" → variable FALSE →
			 * filter OFF → 183 ALLOWED. Default TRUE per chan_sip.c:29458. */
			sofia_cfg.prematuremediafilter = ast_true(v->value);
		} else if (!strcasecmp(v->name, "registertimeout")) {
			/* post-T56 registertimeout parity (2026-04-27): chan_sip parity at
			 * chan_sip.c:29799-29803 — atoi + clamp-to-default if <1. Application-level
			 * scheduled-retry interval seconds. */
			sofia_cfg.register_timeout = atoi(v->value);
			if (sofia_cfg.register_timeout < 1) {
				sofia_cfg.register_timeout = DEFAULT_REGISTRATION_TIMEOUT;
			}
		} else if (!strcasecmp(v->name, "registerattempts")) {
			/* post-T56 registerattempts parity (2026-04-27): chan_sip parity at
			 * chan_sip.c:29804-29805 — atoi direct (no clamp; 0=unlimited). Application-level
			 * scheduled-retry attempt-cap. */
			sofia_cfg.register_attempts = atoi(v->value);
		} else if (!strcasecmp(v->name, "directrtpsetup")) {
			/* post-T56 directrtpsetup parity (2026-04-27): chan_sip parity at
			 * chan_sip.c:29687-29688 — experimental feature (default DISABLED).
			 * PARSE-COMPAT-ONLY ship per Pattern 12 honest-disclosure 8th-instance:
			 * field parsed + stored; full-feature early-RTP-bridge wire-in deferred
			 * (no operator driver; chan_sip itself defaults DISABLED). */
			sofia_cfg.directrtpsetup = ast_true(v->value);
		} else if (!strcasecmp(v->name, "alwaysauthreject")) {
			/* post-T56 alwaysauthreject parity (2026-04-27): chan_sip parity at
			 * chan_sip.c:29699-29700 verbatim ast_true(v->value) semantic.
			 * Security-critical RFC 3261 §22.4 username-enumeration prevention —
			 * drives REGISTER unknown-peer + MWI SUBSCRIBE unknown-mailbox to emit
			 * 401 challenge instead of 403/404 disclosure. Default TRUE per
			 * sip.h:213 DEFAULT_ALWAYSAUTHREJECT. */
			sofia_cfg.alwaysauthreject = ast_true(v->value);
		} else if (!strcasecmp(v->name, "compactheaders")) {
			/* post-T56 compactheaders parity (2026-04-27): chan_sip parity at
			 * chan_sip.c:29683-29684 — Pattern 12 honest-disclosure 12th-instance
			 * PARSE-COMPAT-ONLY ship. sofia-sip native compact-emit gate ABSENT
			 * (verified across nta_tag.h + nua_tag.h + sip_tag.h); field parsed +
			 * stored + reload-clean for chan_sip drop-in compat; full-feature
			 * compact-emit DEFERRED until upstream sofia-sip exposes native gate. */
			sofia_cfg.compactheaders = ast_true(v->value);
		} else if (!strcasecmp(v->name, "disallowed_methods")) {
			/* post-T56 disallowed_methods parity (2026-04-27): chan_sip parity at
			 * chan_sip.c:29998-30000 — comma-separated SIP method names. Pattern 12
			 * honest-disclosure 9th-instance: PARSE-COMPAT-ONLY string-storage shortcut
			 * (avoids porting mark_parsed_methods + SIP_METHOD_* constants). Dynamic
			 * NUTAG_ALLOW generation per-handle DEFERRED per Pattern 15. */
			ast_copy_string(sofia_cfg.disallowed_methods, v->value, sizeof(sofia_cfg.disallowed_methods));
		} else if (!strcasecmp(v->name, "contactpermit") || !strcasecmp(v->name, "contactdeny")) {
			/* post-T56 contactpermit/contactdeny [general] parity (2026-04-27): chan_sip
			 * parity at chan_sip.c:29646-29648 verbatim — ast_append_ha(v->name + 7, ...)
			 * skips "contact" prefix; remaining "permit" or "deny" passed as sense. */
			int ha_error = 0;
			if (!ast_strlen_zero(v->value)) {
				sofia_cfg.contact_ha = ast_append_ha(v->name + 7, v->value, sofia_cfg.contact_ha, &ha_error);
			}
			if (ha_error) {
				ast_log(LOG_ERROR, "Sofia: bad %s [general] entry: %s\n", v->name, v->value);
			}
		} else if (!strcasecmp(v->name, "srvlookup")) {
			sofia_cfg.srvlookup = ast_true(v->value);
		} else if (!strcasecmp(v->name, "domain")) {
			/* T46.2: append local SIP domain for CHECKSIPDOMAIN. Multi-line allowed.
			 * post-T56 autodomain retroactive-refactor (2026-04-28): uses Pattern 5
			 * helper #31 sofia_domain_list_add for centralized mutation + duplicate-
			 * check via helper #30 sofia_check_sip_domain. */
			sofia_domain_list_add(v->value);
		} else if (!strcasecmp(v->name, "outboundproxy")) {
			/* T56.1 (2026-04-27): default outbound proxy for outbound INVITE + REGISTER.
			 * Per-peer outboundproxy= overrides this. Accepts bare host / host:port / sip:URI;
			 * normalized to "sip:HOST[:PORT];lr" by sofia_format_outboundproxy at use time. */
			ast_copy_string(sofia_cfg.outboundproxy, v->value, sizeof(sofia_cfg.outboundproxy));
		} else if (!strcasecmp(v->name, "default_mohinterpret") || !strcasecmp(v->name, "mohinterpret")) {
			/* post-T56 MOH per-peer parity (2026-04-27): default MOH interpret class — peers without explicit mohinterpret inherit at sofia_peer_alloc. chan_sip parity at L8568. Both default_mohinterpret and bare mohinterpret accepted (chan_sip leniency). */
			ast_copy_string(sofia_cfg.default_mohinterpret, v->value, sizeof(sofia_cfg.default_mohinterpret));
		} else if (!strcasecmp(v->name, "default_mohsuggest") || !strcasecmp(v->name, "mohsuggest")) {
			/* post-T56 MOH per-peer parity (2026-04-27): default mohsuggest. */
			ast_copy_string(sofia_cfg.default_mohsuggest, v->value, sizeof(sofia_cfg.default_mohsuggest));
		} else if (!strcasecmp(v->name, "language")) {
			/* post-T56 language per-peer parity (2026-04-27): chan_sip parity at
			 * chan_sip.c:29709-29710 verbatim ast_copy_string(default_language, v->value,
			 * sizeof(default_language)) [general] semantic. Inherited by sofia_peer_alloc
			 * when peer omits language= per-peer. */
			ast_copy_string(sofia_cfg.default_language, v->value, sizeof(sofia_cfg.default_language));
		} else if (!strcasecmp(v->name, "parkinglot")) {
			/* post-T56 parkinglot [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:30027-30028 verbatim ast_copy_string semantic. Operators set
			 * empty to restore chan_sofia silent-baseline; non-empty becomes inheritance
			 * default for new peers. Pattern 12 16th-instance behavior-change-from-baseline. */
			ast_copy_string(sofia_cfg.default_parkinglot, v->value, sizeof(sofia_cfg.default_parkinglot));
		} else if (!strcasecmp(v->name, "ignoreregexpire")) {
			/* post-T56 ignoreregexpire [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:29594-29595 verbatim ast_true(v->value) semantic. When yes,
			 * expired contacts preserved across short upstream-trunk outages (stable-trunk
			 * use case). Production .193 sofia.conf line 71 ignoreregexpire=yes precedent. */
			sofia_cfg.ignore_regexpire = ast_true(v->value);
		} else if (!strcasecmp(v->name, "maxcallbitrate")) {
			/* post-T56 maxcallbitrate [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:29950-29953 verbatim atoi + bounds-clamp-on-negative-back-to-default
			 * (sip.h:218 DEFAULT_MAX_CALL_BITRATE=384). Inherited by sofia_peer_alloc when
			 * peer omits the key. */
			sofia_cfg.default_maxcallbitrate = atoi(v->value);
			if (sofia_cfg.default_maxcallbitrate < 0) {
				sofia_cfg.default_maxcallbitrate = 384;
			}
		} else if (!strcasecmp(v->name, "match_auth_username")) {
			/* post-T56 match_auth_username [general] parity (2026-04-28): chan_sip
			 * parity at chan_sip.c:29754-29755 verbatim ast_true(v->value) semantic.
			 * When yes, peer-lookup uses Authorization-username (or Proxy-Authorization)
			 * instead of From-username (sofia_pick_auth_username helper #28). */
			sofia_cfg.match_auth_username = ast_true(v->value);
		} else if (!strcasecmp(v->name, "legacy_useroption_parsing")) {
			/* post-T56 legacy_useroption_parsing [general] parity (2026-04-28): chan_sip
			 * parity at chan_sip.c:29724-29725 verbatim ast_true(v->value) semantic.
			 * Pattern 12 honest-disclosure 15th-instance sofia-sip-library-feature-absence
			 * sub-pattern 2nd-instance — PARSE-COMPAT-ONLY ship; full-feature URI per-
			 * component semicolon-strip DEFERRED until upstream sofia-sip exposes hook. */
			sofia_cfg.legacy_useroption_parsing = ast_true(v->value);
		} else if (!strcasecmp(v->name, "shrinkcallerid")) {
			/* post-T56 shrinkcallerid [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:30001-30009 verbatim ast_true/ast_false tri-state + LOG_WARNING
			 * on invalid (chan_sip-verbatim semantic; preserves current value on parse-fail).
			 * Pattern 12 18th-instance behavior-change-from-chan_sofia-baseline sub-pattern
			 * 3rd-instance. */
			if (ast_true(v->value)) {
				sofia_cfg.shrinkcallerid = 1;
			} else if (ast_false(v->value)) {
				sofia_cfg.shrinkcallerid = 0;
			} else {
				ast_log(LOG_WARNING, "Sofia: shrinkcallerid value '%s' is not valid; ignoring\n",
					v->value);
			}
		} else if (!strcasecmp(v->name, "notifyhold")) {
			/* post-T56 notifyhold [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:29691-29692 verbatim ast_true(v->value) semantic. Gates
			 * peer->onHold counter atomic update (chan_sip-faithful Option 6-A). */
			sofia_cfg.notifyhold = ast_true(v->value);
		} else if (!strcasecmp(v->name, "notifyringing")) {
			/* post-T56 notifyringing [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:29689-29690 verbatim ast_true(v->value) semantic. PARSE-COMPAT-
			 * ONLY ship (Pattern 12 19th-instance chan_sofia-architectural-divergence
			 * sub-pattern 2nd-instance) — chan_sofia presence/dialog-info NOTIFY
			 * infrastructure ABSENT; flag effect-deferred until landed. */
			sofia_cfg.notifyringing = ast_true(v->value);
		} else if (!strcasecmp(v->name, "dynamic_exclude_static")
				|| !strcasecmp(v->name, "dynamic_excludes_static")) {
			/* post-T56 dynamic_exclude_static [general] parity (2026-04-28): chan_sip
			 * parity at chan_sip.c:29644-29645 verbatim dual-key parser (variant
			 * spellings dynamic_exclude_static + dynamic_excludes_static both accepted)
			 * + ast_true(v->value) semantic. Security hardening flag. */
			sofia_cfg.dynamic_exclude_static = ast_true(v->value);
		} else if (!strcasecmp(v->name, "autocreatepeer")) {
			/* post-T56 autocreatepeer [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:29752-29753 verbatim ast_true(v->value) semantic. PARSE-COMPAT-
			 * ONLY ship (Pattern 12 20th-instance chan_sofia-architectural-divergence
			 * sub-pattern 3rd-instance PROVEN at 3-instance repeat) — chan_sofia design
			 * refuses auto-create unknown peers (security-stronger via alwaysauthreject
			 * c293e54). */
			sofia_cfg.autocreatepeer = ast_true(v->value);
		} else if (!strcasecmp(v->name, "preferred_codec_only")) {
			/* post-T56 preferred_codec_only [general] parity (2026-04-28): chan_sip
			 * parity at chan_sip.c:29863-29864 verbatim ast_set2_flag(global_flags[1],
			 * ast_true(v->value), SIP_PAGE2_PREFERRED_CODEC) → chan_sofia int. */
			sofia_cfg.default_preferred_codec_only = ast_true(v->value);
		} else if (!strcasecmp(v->name, "ignoresdpversion")) {
			/* post-T56 ignoresdpversion [general] parity (2026-04-28): chan_sip parity
			 * at chan_sip.c:28199-28201 verbatim parser via handle_common_options
			 * indirection (L29544 [general] call site shares parser with L28671 per-peer
			 * call site) + chan_sip.c:29539 verbatim default-init via ast_clear_flag.
			 * PARSE-COMPAT-ONLY — chan_sofia processes every SDP unconditionally. */
			sofia_cfg.default_ignoresdpversion = ast_true(v->value);
		} else if (!strcasecmp(v->name, "promiscredir")) {
			/* post-T56 promiscredir [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28173-28175 verbatim parser via handle_common_options
			 * indirection. PARSE-COMPAT-ONLY — chan_sofia nua_r_redirect handler
			 * ABSENT (sofia-sip NUTAG_AUTO_TARGET verified ABSENT). */
			sofia_cfg.default_promiscredir = ast_true(v->value);
		} else if (!strcasecmp(v->name, "autoframing")) {
			/* post-T56 autoframing [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:29865-29866 verbatim ast_true global_autoframing (SEPARATE
			 * from per-peer parser per Pattern 14 source-correction). PARSE-COMPAT-
			 * ONLY — chan_sofia sofia_parse_sdp ptime gate not wired today. */
			sofia_cfg.default_autoframing = ast_true(v->value);
		} else if (!strcasecmp(v->name, "timerb")) {
			/* post-T56 timerb [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:29601-29607 verbatim parser BUT with chan_sofia parser-
			 * correctness surpass over chan_sip parser-BUG (chan_sip parses
			 * `int tmp = atoi(v->value)` but ONLY assigns to global_timer_b in
			 * `< 500` invalid-value branch — valid values ≥ 500 are PARSED but
			 * NEVER ASSIGNED to global_timer_b; operator setting timerb=10000
			 * has NO effect; chan_sip global_timer_b stays at default 32000ms).
			 * chan_sofia adds the missing `else` branch to correctly assign valid
			 * values — chan_sofia helper-architecture-advantage parser-correctness
			 * surpass dimension. Wire-in via NTATAG_SIP_T1X64 at nua_create.
			 * post-T56 timert1 cross-validation flag (2026-04-28): set sofia_
			 * timerb_set per chan_sip.c:29607 verbatim flag-tracking for R5
			 * cross-validation Timer B vs T1*64 nested logic. */
			int tmp_b = atoi(v->value);
			if (tmp_b < 500) {
				ast_log(LOG_WARNING, "Sofia: invalid [general] timerb '%s' (< 500ms); using default %d\n",
					v->value, sofia_cfg.t1min * 64);
				sofia_cfg.default_timer_b = sofia_cfg.t1min * 64;
			} else {
				sofia_cfg.default_timer_b = tmp_b;
			}
			sofia_timerb_set = 1;
		} else if (!strcasecmp(v->name, "timert1")) {
			/* post-T56 timert1 [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:29596-29600 verbatim parser BUT with chan_sofia parser-
			 * correctness surpass over chan_sip [general] no-range-validation
			 * (chan_sip uses bare `global_t1 = atoi(v->value)` with no parse-time
			 * range validation — relies on L30038-30040 post-load cross-validation
			 * only; operator can set timert1=0 or negative without parse-time
			 * warning). chan_sofia adds parse-time sscanf %30d + < 200 clamp +
			 * LOG_WARNING + clamp-to-DEFAULT_TIMER_T1 (500). chan_sofia helper-
			 * architecture-advantage parser-correctness surpass dimension —
			 * mirrors timerb a2e16b7 precedent commit. Set sofia_timert1_set per
			 * chan_sip.c:28946 verbatim flag-tracking for R5 cross-validation. */
			int tmp_t1;
			if ((sscanf(v->value, "%30d", &tmp_t1) != 1) || tmp_t1 < 200) {
				ast_log(LOG_WARNING, "Sofia: invalid [general] timert1 '%s' (< 200ms or non-integer); using default %d\n",
					v->value, 500);
				sofia_cfg.default_timer_t1 = 500;
			} else {
				sofia_cfg.default_timer_t1 = tmp_t1;
			}
			sofia_timert1_set = 1;
		} else if (!strcasecmp(v->name, "faxdetect")) {
			/* faxdetect parser: yes -> cng+t38, no -> none, or a
			 * comma-separated cng/t38 set. Runtime wire-in handles DSP
			 * CNG detection and peer T.38 reINVITE detection. */
			if (ast_true(v->value)) {
				sofia_cfg.default_faxdetect_mode = SOFIA_FAX_DETECT_BOTH;
			} else if (ast_false(v->value)) {
				sofia_cfg.default_faxdetect_mode = SOFIA_FAX_DETECT_NONE;
			} else {
				char *fbuf = ast_strdupa(v->value);
				char *fword, *fnext = fbuf;
				sofia_cfg.default_faxdetect_mode = SOFIA_FAX_DETECT_NONE;
				while ((fword = strsep(&fnext, ","))) {
					if (!strcasecmp(fword, "cng")) {
						sofia_cfg.default_faxdetect_mode |= SOFIA_FAX_DETECT_CNG;
					} else if (!strcasecmp(fword, "t38")) {
						sofia_cfg.default_faxdetect_mode |= SOFIA_FAX_DETECT_T38;
					} else {
						ast_log(LOG_WARNING, "Sofia: unknown [general] faxdetect mode '%s'\n", fword);
					}
				}
			}
		} else if (!strcasecmp(v->name, "t38_maxdatagram") ||
				!strcasecmp(v->name, "global_t38_maxdatagram")) {
			/* post-T56 Task #8 T.38 fax UDPTL parity SS2 (2026-04-28): [general]
			 * default T38FaxMaxDatagram override mirrors chan_sip.c:780 +
			 * chan_sip.c:29525 verbatim sentinel `-1` semantic. Parsed integer
			 * (positive 0+ = explicit override; -1 = use SOFIA_T38_MAXDATAGRAM_
			 * BUILTIN 200). Inherited by sofia_peer_alloc into
			 * peer->t38_maxdatagram when peer omits per-peer maxdatagram=N
			 * sub-option of t38pt_udptl. Both `t38_maxdatagram` (chan_sip.c:780
			 * static var name) and `global_t38_maxdatagram` aliases accepted
			 * for operator-friendly drop-in. */
			int x;
			if (sscanf(v->value, "%30d", &x) == 1) {
				sofia_cfg.default_t38_maxdatagram = x;
			} else {
				ast_log(LOG_WARNING, "Sofia: invalid [general] %s value '%s' (expected integer)\n",
					v->name, v->value);
			}
		} else if (!strcasecmp(v->name, "allowoverlap")) {
			/* post-T56 allowoverlap [general] parity (2026-04-28, Option A FULL
			 * WIRE-IN 3 sites): chan_sip parity at chan_sip.c:28188-28195 verbatim
			 * tri-state parser via handle_common_options. ast_true → YES;
			 * !strcasecmp("dtmf") → DTMF; else → NO. Default YES per chan_sip.c
			 * :29479 verbatim drop-in critical default. */
			if (ast_true(v->value)) {
				sofia_cfg.default_allowoverlap_mode = SOFIA_OVERLAP_YES;
			} else if (!strcasecmp(v->value, "dtmf")) {
				sofia_cfg.default_allowoverlap_mode = SOFIA_OVERLAP_DTMF;
			} else {
				sofia_cfg.default_allowoverlap_mode = SOFIA_OVERLAP_NO;
			}
		} else if (!strcasecmp(v->name, "progressinband")) {
			/* post-T56 progressinband [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28167-28172 verbatim tri-state semantic via handle_common_options
			 * indirection (L29544 [general] call site shares parser with L28671 per-peer
			 * call site). Mirror: ast_true → YES; non-"never" → NO; "never" → NEVER.
			 * Option B partial wire-in at sofia_indicate AST_CONTROL_RINGING. */
			if (ast_true(v->value)) {
				sofia_cfg.default_progressinband = SOFIA_PROG_INBAND_YES;
			} else if (strcasecmp(v->value, "never")) {
				sofia_cfg.default_progressinband = SOFIA_PROG_INBAND_NO;
			} else {
				sofia_cfg.default_progressinband = SOFIA_PROG_INBAND_NEVER;
			}
		} else if (!strcasecmp(v->name, "subscribe_network_change_event")) {
			/* post-T56 subscribe_network_change_event [general] parity (2026-04-28):
			 * chan_sip parity at chan_sip.c:30017-30024 verbatim tri-state semantic
			 * (ast_true → 1; ast_false → 0; else LOG_WARNING + skip). PARSE-COMPAT-ONLY
			 * (chan_sofia delegates network-change handling to sofia-sip + dnsmgr). */
			if (ast_true(v->value)) {
				sofia_cfg.subscribe_network_change_event = 1;
			} else if (ast_false(v->value)) {
				sofia_cfg.subscribe_network_change_event = 0;
			} else {
				ast_log(LOG_WARNING, "Sofia: subscribe_network_change_event value '%s' is not valid at line %d.\n",
					v->value, v->lineno);
			}
		} else if (!strcasecmp(v->name, "rtsavesysname")) {
			/* post-T56 rtsavesysname [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:29590-29591 verbatim ast_true. Wire-in at 5 sofia_process_
			 * register ast_update_realtime callsites mirrors chan_sip.c.bk:5103-5151
			 * canonical realtime_update_peer pattern. */
			sofia_cfg.rtsave_sysname = ast_true(v->value);
		} else if (!strcasecmp(v->name, "rtupdate")) {
			/* post-T56 rtupdate [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:29592-29593 verbatim ast_true. Wire-in via Option C combined-
			 * gate at 3 sofia_process_register `if (peer->is_realtime)` blocks
			 * mirroring chan_sip.c:14630+L14743 verbatim combined-gate pattern. */
			sofia_cfg.peer_rtupdate = ast_true(v->value);
		} else if (!strcasecmp(v->name, "rtcachefriends")) {
			/* post-T56 rtcachefriends [general] parity (2026-04-28): chan_sip parity
			 * at chan_sip.c:29588-29589 verbatim ast_set2_flag(global_flags[1],
			 * ast_true(v->value), SIP_PAGE2_RTCACHEFRIENDS) → chan_sofia int-field
			 * idiom. PARSE-COMPAT-ONLY — chan_sofia ao2 peer registry intrinsic-
			 * equivalent-to-rtcachefriends=yes baseline (always caches all peers). */
			sofia_cfg.rtcachefriends = ast_true(v->value);
		} else if (!strcasecmp(v->name, "rtautoclear")) {
			/* post-T56 rtautoclear [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:29652-29659 verbatim two-phase parser. Numeric > 0 sets
			 * seconds; flag enabled when numeric > 0 OR ast_true("yes"). PARSE-
			 * COMPAT-ONLY — chan_sofia ao2 registry no peer-level auto-clear infra. */
			int i = atoi(v->value);
			if (i > 0) {
				sofia_cfg.rtautoclear = i;
			} else {
				i = 0;
			}
			sofia_cfg.rtautoclear_enabled = (i || ast_true(v->value)) ? 1 : 0;
		} else if (!strcasecmp(v->name, "domainsasrealm")) {
			/* post-T56 domainsasrealm [general] parity (2026-04-28): chan_sip parity
			 * at chan_sip.c:29572-29573 verbatim ast_true. FULL WIRE-IN — Pattern 5
			 * helper #29 sofia_get_realm_for_dialog at 3 auth-challenge callsites
			 * mirrors chan_sip.c:11645-11673 verbatim get_realm semantic. */
			sofia_cfg.domainsasrealm = ast_true(v->value);
		} else if (!strcasecmp(v->name, "allowexternaldomains")) {
			/* post-T56 allowexternaldomains [general] parity (2026-04-28): chan_sip
			 * parity at chan_sip.c:29867-29868 verbatim ast_true. FULL WIRE-IN —
			 * Pattern 5 helper #30 sofia_check_sip_domain at 2 sofia_process_invite/
			 * refer gate callsites mirrors chan_sip.c:16410-16425 verbatim semantic. */
			sofia_cfg.allow_external_domains = ast_true(v->value);
		} else if (!strcasecmp(v->name, "autodomain")) {
			/* post-T56 autodomain [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:29869-29870 verbatim ast_true. FULL WIRE-IN — Pattern 5
			 * helper #31 sofia_domain_list_add at 5 NEW auto-add callsites +
			 * retroactive-refactor of existing domain= parser; auto-add fires at
			 * sofia_load_config conclusion mirroring chan_sip.c:30295-30340+. */
			sofia_cfg.autodomain = ast_true(v->value);
		} else if (!strcasecmp(v->name, "matchexternaddrlocally")
		           || !strcasecmp(v->name, "matchexterniplocally")) {
			/* post-T56 matchexternaddrlocally [general] dual-key parity (2026-04-28):
			 * chan_sip parity at chan_sip.c:29954-29955 verbatim OR-chained dual-key
			 * acceptance (BOTH spellings parsed identically). PARSE-COMPAT-ONLY —
			 * chan_sofia sofia_should_use_externaddr signature divergence (peer_addr-
			 * only; future-fix path documented in sample.conf). */
			sofia_cfg.matchexternaddrlocally = ast_true(v->value);
		} else if (!strcasecmp(v->name, "rtptimeout")) {
			/* post-T56 rtp-timeout bundle [general] parity (2026-04-28): chan_sip
			 * parity at chan_sip.c:29669-29672 verbatim sscanf %30d + LOG_WARNING +
			 * clamp-to-0 on invalid. */
			if ((sscanf(v->value, "%30d", &sofia_cfg.default_rtptimeout) != 1)
					|| sofia_cfg.default_rtptimeout < 0) {
				ast_log(LOG_WARNING, "Sofia: '%s' is not a valid RTP timeout; using default 0\n", v->value);
				sofia_cfg.default_rtptimeout = 0;
			}
		} else if (!strcasecmp(v->name, "rtpholdtimeout")) {
			/* post-T56 rtp-timeout bundle [general] parity (2026-04-28): chan_sip
			 * parity at chan_sip.c:29673-29676 verbatim. */
			if ((sscanf(v->value, "%30d", &sofia_cfg.default_rtpholdtimeout) != 1)
					|| sofia_cfg.default_rtpholdtimeout < 0) {
				ast_log(LOG_WARNING, "Sofia: '%s' is not a valid RTP hold timeout; using default 0\n", v->value);
				sofia_cfg.default_rtpholdtimeout = 0;
			}
		} else if (!strcasecmp(v->name, "rtpkeepalive")) {
			/* post-T56 rtp-timeout bundle [general] parity (2026-04-28): chan_sip
			 * parity at chan_sip.c:29678-29680 verbatim. */
			if ((sscanf(v->value, "%30d", &sofia_cfg.default_rtpkeepalive) != 1)
					|| sofia_cfg.default_rtpkeepalive < 0) {
				ast_log(LOG_WARNING, "Sofia: '%s' is not a valid RTP keepalive; using default 0\n", v->value);
				sofia_cfg.default_rtpkeepalive = 0;
			}
		} else if (!strcasecmp(v->name, "tos_sip")) {
			/* post-T56 tos/cos bundle [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:29893-29896 verbatim ast_str2tos + LOG_WARNING-on-invalid.
			 * Pattern 16 sofia-sip-native 9th-instance — TPTAG_TOS at nua_create. */
			if (ast_str2tos(v->value, &sofia_cfg.tos_sip)) {
				ast_log(LOG_WARNING, "Sofia: invalid tos_sip value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "tos_audio")) {
			/* post-T56 tos/cos bundle [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:29897-29900 verbatim. Wired via ast_rtp_instance_set_qos at sofia_rtp_init. */
			if (ast_str2tos(v->value, &sofia_cfg.tos_audio)) {
				ast_log(LOG_WARNING, "Sofia: invalid tos_audio value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "tos_video")) {
			/* post-T56 tos/cos bundle [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:29901-29904 verbatim. Wired via ast_rtp_instance_set_qos at sofia_rtp_init. */
			if (ast_str2tos(v->value, &sofia_cfg.tos_video)) {
				ast_log(LOG_WARNING, "Sofia: invalid tos_video value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "tos_text")) {
			/* post-T56 tos/cos bundle [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:29905-29908 verbatim. PARSE-COMPAT-ONLY (chan_sofia text-RTP
			 * infrastructure ABSENT — no pvt->trtp). */
			if (ast_str2tos(v->value, &sofia_cfg.tos_text)) {
				ast_log(LOG_WARNING, "Sofia: invalid tos_text value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "cos_sip")) {
			/* post-T56 tos/cos bundle [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:29909-29912 verbatim. PARSE-COMPAT-ONLY (sofia-sip TPTAG_COS
			 * verified ABSENT in tport_tag.h grep — Pattern 12 sub-pattern sofia-sip-
			 * library-feature-absence; full-feature DEFERRED until upstream surfaces). */
			if (ast_str2cos(v->value, &sofia_cfg.cos_sip)) {
				ast_log(LOG_WARNING, "Sofia: invalid cos_sip value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "cos_audio")) {
			/* post-T56 tos/cos bundle [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:29913-29916 verbatim. Wired via ast_rtp_instance_set_qos. */
			if (ast_str2cos(v->value, &sofia_cfg.cos_audio)) {
				ast_log(LOG_WARNING, "Sofia: invalid cos_audio value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "cos_video")) {
			/* post-T56 tos/cos bundle [general] parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:29917+ verbatim. Wired via ast_rtp_instance_set_qos. */
			if (ast_str2cos(v->value, &sofia_cfg.cos_video)) {
				ast_log(LOG_WARNING, "Sofia: invalid cos_video value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "cos_text")) {
			/* post-T56 tos/cos bundle [general] parity (2026-04-28): chan_sip parity. PARSE-COMPAT-
			 * ONLY (chan_sofia text-RTP infrastructure ABSENT — no pvt->trtp). */
			if (ast_str2cos(v->value, &sofia_cfg.cos_text)) {
				ast_log(LOG_WARNING, "Sofia: invalid cos_text value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "mwi_from")) {
			/* T55.1 (2026-04-27): MWI From-header default; empty -> peer->fromdomain or sofia_cfg.realm fallback */
			ast_copy_string(sofia_cfg.mwi_from, v->value, sizeof(sofia_cfg.mwi_from));
		} else if (!strcasecmp(v->name, "notifymime")
				|| !strcasecmp(v->name, "notifymimetype")) {
			/* T55.1: MWI NOTIFY Content-Type; default application/simple-message-summary (RFC 3842).
			 * post-T56 notifymimetype alias acceptance (2026-04-28): chan_sip uses ONLY
			 * "notifymimetype" verbose key per chan_sip.c:29685-29686 verbatim; chan_sofia
			 * chose shorter "notifymime" name unilaterally. Alias acceptance restores
			 * chan_sip drop-in zero-rewrite migration. */
			ast_copy_string(sofia_cfg.notifymime, v->value, sizeof(sofia_cfg.notifymime));
		} else if (!strcasecmp(v->name, "vmexten")) {
			/* T55.1: voicemail user-part for Message-Account URI; default "asterisk" */
			ast_copy_string(sofia_cfg.vmexten, v->value, sizeof(sofia_cfg.vmexten));
		} else if (!strcasecmp(v->name, "mwi_expiry")
		           || !strcasecmp(v->name, "mwiexpiry")
		           || !strcasecmp(v->name, "mwiexpirey")) {
			/* T55.1: MWI subscription default expiry seconds; default 3600 (chan_sip
			 * DEFAULT_MWI_EXPIRY parity at sip.h:58).
			 * post-T56 mwiexpiry/mwiexpirey [general] dual-key parity (2026-04-28):
			 * extended to 3-spelling OR-chained acceptance — chan_sofia "mwi_expiry"
			 * (T55.1 historical) + chan_sip "mwiexpiry" + chan_sip "mwiexpirey"
			 * alternate spelling. Mirror chan_sip.c:29775-29782 verbatim atoi +
			 * clamp-to-default-on-invalid (< 1 → 3600). T55.1 wire-in already active
			 * at chan_sofia.c:8339 MWI server-side notifier; this parser-naming-fix
			 * adds chan_sip drop-in compat for both chan_sip dual-key spellings. */
			sofia_cfg.mwi_expiry = atoi(v->value);
			if (sofia_cfg.mwi_expiry < 1) {
				sofia_cfg.mwi_expiry = 3600;
			}
		} else if (!strcasecmp(v->name, "externaddr") || !strcasecmp(v->name, "externhost")) {
			/* post-T56 NAT parity fill (2026-04-27) R2 lenient backwards-compat:
			 * chan_sip distinguishes externaddr=IP from externhost=NAME; chan_sofia
			 * historically aliased both to externaddr field. To preserve operator
			 * scripts that mis-use externaddr=mypbx.dyndns.net (hostname in
			 * externaddr key) AND honor explicit externhost= for DDNS, detect
			 * value type via ast_sockaddr_parse: if parses as IP, store as static
			 * externaddr (no refresh); else treat as hostname (set externhost +
			 * resolve to externaddr + arm externexpire for lazy-refresh). */
			struct ast_sockaddr probe;
			int is_explicit_host = !strcasecmp(v->name, "externhost");
			int parses_as_ip = ast_sockaddr_parse(&probe, v->value, PARSE_PORT_FORBID);
			if (!is_explicit_host && parses_as_ip) {
				ast_copy_string(sofia_cfg.externaddr, v->value, sizeof(sofia_cfg.externaddr));
				sofia_cfg.externhost[0] = '\0';
				sofia_cfg.externexpire = 0;
			} else {
				struct ast_sockaddr *addrs = NULL;
				int addrs_cnt;
				ast_copy_string(sofia_cfg.externhost, v->value, sizeof(sofia_cfg.externhost));
				addrs_cnt = ast_sockaddr_resolve(&addrs, v->value, 0, AST_AF_INET);
				if (addrs_cnt > 0) {
					ast_copy_string(sofia_cfg.externaddr,
						ast_sockaddr_stringify_host(&addrs[0]),
						sizeof(sofia_cfg.externaddr));
				}
				if (addrs) {
					ast_free(addrs);
				}
				sofia_cfg.externexpire = time(NULL) + (sofia_cfg.externrefresh > 0 ? sofia_cfg.externrefresh : 10);
			}
		} else if (!strcasecmp(v->name, "externrefresh")) {
			sofia_cfg.externrefresh = atoi(v->value);
			if (sofia_cfg.externrefresh < 1) sofia_cfg.externrefresh = 10;
		} else if (!strcasecmp(v->name, "externtcpport")) {
			sofia_cfg.externtcpport = atoi(v->value);
		} else if (!strcasecmp(v->name, "externtlsport")) {
			sofia_cfg.externtlsport = atoi(v->value);
		} else if (!strcasecmp(v->name, "localnet")) {
			ast_copy_string(sofia_cfg.localnet, v->value, sizeof(sofia_cfg.localnet));
			{
				int ha_error = 0;
				struct ast_ha *na;
				na = ast_append_ha("d", v->value, sofia_cfg.localha, &ha_error);
				if (na) {
					sofia_cfg.localha = na;
				} else {
					ast_log(LOG_WARNING, "Sofia: Invalid localnet value: %s\n", v->value);
				}
				if (ha_error) {
					ast_log(LOG_ERROR, "Sofia: Bad localnet configuration line %d: %s\n",
						v->lineno, v->value);
				}
			}
		} else if (!strcasecmp(v->name, "qualify")) {
			if (ast_true(v->value)) {
				sofia_cfg.default_qualify = DEFAULT_QUALIFYFREQ;
			} else {
				sofia_cfg.default_qualify = 0;
			}
		} else if (!strcasecmp(v->name, "qualifyfreq")) {
			sofia_cfg.default_qualifyfreq = atoi(v->value);
			if (sofia_cfg.default_qualifyfreq <= 0)
				sofia_cfg.default_qualifyfreq = DEFAULT_QUALIFYFREQ;
		} else if (!strcasecmp(v->name, "qualifytimeout")) {
			sofia_cfg.default_qualifytimeout = atoi(v->value);
			if (sofia_cfg.default_qualifytimeout <= 0)
				sofia_cfg.default_qualifytimeout = DEFAULT_QUALIFYTIMEOUT;
		} else if (!strcasecmp(v->name, "allow")) {
			ast_parse_allow_disallow(&sofia_cfg.prefs, &sofia_cfg.capability, v->value, 1);
		} else if (!strcasecmp(v->name, "disallow")) {
			ast_parse_allow_disallow(&sofia_cfg.prefs, &sofia_cfg.capability, v->value, 0);
		} else if (!strcasecmp(v->name, "register")) {
			sofia_parse_register_line(v->value);
		}
	}
}

static void sofia_parse_peer_config(const char *cat, struct ast_config *cfg)
{
	struct ast_variable *v;
	struct sofia_peer *peer;
	/* post-T56 setvar+header per-peer parity (2026-04-28, COMBINED ship): per-peer
	 * header counter — each header= entry gets unique __SIPADDHEADERpre%2d= channel-
	 * var name. Local scope resets per peer-build per chan_sip.c:28582 verbatim
	 * idiom. */
	int headercount = 0;

	peer = sofia_find_peer(cat);
	if (!peer) {
		peer = sofia_peer_alloc(cat);
		if (!peer) {
			return;
		}
	} else {
		/* Take peer->lock around the reset-and-repopulate window.  The
		 * reload worker runs on sofia_thread, so the primary SIP-event
		 * reader cannot race here — but the auxiliary threads
		 * (sofia_sched / sofia_reg_thread / sofia_qualify_tid) legitimately
		 * read peer fields outside sofia_thread and would otherwise see
		 * the transient empty-string window for secret/context/host/...
		 * and the freed-mid-iteration chanvars list. */
		ast_mutex_lock(&peer->lock);
		/* Drop the existing dialplan hint extension BEFORE wiping
		 * subscribecontext / regexten — we need the OLD values to locate
		 * the right extension to remove.  The subsequent
		 * sofia_create_peer_hint call at the end of this function adds a
		 * fresh hint based on the new values.  Without this, an operator
		 * changing regexten= from one number to another on reload would
		 * leak the old hint extension; an unchanged regexten= would
		 * accumulate a duplicate hint on every reload (depending on
		 * ast_add_extension2 dedup semantics, the dialplan extension
		 * table grows linearly with reload count). */
		if (!ast_strlen_zero(peer->subscribecontext) && !ast_strlen_zero(peer->regexten)) {
			ast_context_remove_extension(peer->subscribecontext,
				peer->regexten, PRIORITY_HINT, "sofia_config_peer");
		}
		/* Reset ACL chains so the permit/deny parsers below append onto a
		 * fresh list instead of stacking on top of the previous load's
		 * rules.  Without these resets, every reload of an existing peer
		 * with permit/deny grows peer->ha linearly; an N-th reload would
		 * have N copies of every rule, slowing ast_apply_ha O(N*rules)
		 * and leaking ~24 bytes per rule per reload.  Same reasoning for
		 * peer->contactha and peer->directmediaha. */
		if (peer->ha) {
			ast_free_ha(peer->ha);
			peer->ha = NULL;
		}
		if (peer->contactha) {
			ast_free_ha(peer->contactha);
			peer->contactha = NULL;
		}
		if (peer->directmediaha) {
			ast_free_ha(peer->directmediaha);
			peer->directmediaha = NULL;
		}
		/* Drain the mailbox list — sofia_peer_parse_mailboxes appends via
		 * AST_LIST_INSERT_TAIL without checking for duplicates, so every
		 * reload of a peer with mailbox= would otherwise accumulate
		 * mailbox structs (each carrying an ast_event_subscribe handle).
		 * Mirror the destructor's drain pattern (chan_sofia.c:4548-4553):
		 * unsubscribe synchronously (waits for in-flight mwi_event_cb
		 * before returning, closing the race against concurrent event-bus
		 * delivery) then ast_free the struct. */
		{
			struct sofia_mailbox *mb;
			while ((mb = AST_LIST_REMOVE_HEAD(&peer->mailboxes, list))) {
				if (mb->event_sub) {
					mb->event_sub = ast_event_unsubscribe(mb->event_sub);
				}
				ast_free(mb);
			}
		}
		ast_string_field_set(peer, secret, "");
		ast_string_field_set(peer, context, "");
		ast_string_field_set(peer, host, "");
		ast_string_field_set(peer, defaultuser, "");
		ast_string_field_set(peer, fromuser, "");
		ast_string_field_set(peer, fromdomain, "");
		ast_string_field_set(peer, callerid, "");
		ast_string_field_set(peer, regexten, "");
		/* post-T56 setvar+header per-peer parity (2026-04-28, COMBINED ship): on
		 * peer reload (peer found existing), free prior chanvars before re-parsing.
		 * Mirrors string-field reset above. */
		if (peer->chanvars) {
			ast_variables_destroy(peer->chanvars);
			peer->chanvars = NULL;
		}
		ast_mutex_unlock(&peer->lock);
	}

	/* Clear the reload-sweep mark: this peer survived the new config and
	 * must not be swept at the end of the reload worker. */
	peer->_reload_marked = 0;

	for (v = ast_variable_browse(cfg, cat); v; v = v->next) {
		if (!strcasecmp(v->name, "secret") || !strcasecmp(v->name, "password")) {
			ast_string_field_set(peer, secret, v->value);
			/* SS5 Finding #1 audit hardening: dual-set LOG_WARNING (symmetric
			 * to md5secret-parser site) — fires when secret= comes AFTER
			 * md5secret= in config order. md5secret takes precedence. */
			if (!ast_strlen_zero(peer->md5secret) && !ast_strlen_zero(v->value)) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' has BOTH secret= and "
					"md5secret= set — md5secret takes precedence (chan_sip.c"
					":15415-16 parity); recommend operator unset secret= to "
					"remove ambiguity\n", peer->name);
			}
		} else if (!strcasecmp(v->name, "md5secret")) {
			/* post-T56 Task #3 INVITE digest auth SS4 (2026-04-28, SW11 audit-
			 * discovered chan_sip parity gap fix): pre-hashed MD5(user:realm:secret)
			 * digest secret. chan_sip parity at chan_sip.c:15415-16 verbatim — when
			 * set, used directly as a1_hash bypassing cleartext-secret path. md5secret
			 * takes PRECEDENCE over peer->secret when both set. SS5 Finding #1
			 * audit hardening: dual-set LOG_WARNING fires HERE (config-time) —
			 * once at load instead of per-auth-call. */
			ast_string_field_set(peer, md5secret, v->value);
			if (!ast_strlen_zero(peer->secret)) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' has BOTH secret= and "
					"md5secret= set — md5secret takes precedence (chan_sip.c"
					":15415-16 parity); recommend operator unset secret= to "
					"remove ambiguity\n", peer->name);
			}
		} else if (!strcasecmp(v->name, "context")) {
			ast_string_field_set(peer, context, v->value);
		} else if (!strcasecmp(v->name, "host")) {
			ast_string_field_set(peer, host, v->value);
		} else if (!strcasecmp(v->name, "defaultuser") || !strcasecmp(v->name, "username") || !strcasecmp(v->name, "user")) {
			ast_string_field_set(peer, defaultuser, v->value);
		} else if (!strcasecmp(v->name, "fromuser")) {
			ast_string_field_set(peer, fromuser, v->value);
		} else if (!strcasecmp(v->name, "fromdomain")) {
			ast_string_field_set(peer, fromdomain, v->value);
		} else if (!strcasecmp(v->name, "type")) {
			if (!strcasecmp(v->value, "friend")) {
				peer->type = SOFIA_TYPE_FRIEND;
			} else if (!strcasecmp(v->value, "peer")) {
				peer->type = SOFIA_TYPE_PEER;
			} else if (!strcasecmp(v->value, "user")) {
				peer->type = SOFIA_TYPE_USER;
			}
		} else if (!strcasecmp(v->name, "port")) {
			peer->port = atoi(v->value);
		} else if (!strcasecmp(v->name, "callerid")) {
			ast_string_field_set(peer, callerid, v->value);
		} else if (!strcasecmp(v->name, "regexten")) {
			ast_string_field_set(peer, regexten, v->value);
		} else if (!strcasecmp(v->name, "callbackextension")) {
			/* post-T56 callbackextension per-peer parity (2026-04-28, Option A FULL
			 * WIRE-IN via Pattern 16 sofia-sip-native 12th-instance NUTAG_M_USERNAME):
			 * T46.3 dual-parser realtime branch. Same chan_sip-verbatim semantic as
			 * config-file branch. */
			ast_string_field_set(peer, callbackextension, v->value);
		} else if (!strcasecmp(v->name, "setvar")) {
			/* post-T56 setvar per-peer parity (2026-04-28, COMBINED setvar+header
			 * ship): T46.3 dual-parser config-file branch. chan_sip parity at chan_
			 * sip.c:28953-28954 verbatim. Pattern 5 helper #33 sofia_add_var. */
			peer->chanvars = sofia_add_var(v->value, peer->chanvars);
		} else if (!strcasecmp(v->name, "header")) {
			/* post-T56 header per-peer parity (2026-04-28, COMBINED setvar+header
			 * ship): T46.3 dual-parser config-file branch. chan_sip parity at chan_
			 * sip.c:28955-28958 verbatim format string. Existing T46 sofia_build_
			 * addheader_str at chan_sofia.c:4509 absorbs via channel-var prefix
			 * matching at sofia_call. */
			char tmp[4096];
			snprintf(tmp, sizeof(tmp), "__SIPADDHEADERpre%2d=%s", ++headercount, v->value);
			peer->chanvars = sofia_add_var(tmp, peer->chanvars);
		} else if (!strcasecmp(v->name, "subscribecontext")) {
			/* post-T56 subscribecontext per-peer parity (2026-04-27): T46.3 dual-parser
			 * branch (config-file). Same chan_sip-verbatim semantic as the realtime branch. */
			ast_string_field_set(peer, subscribecontext, v->value);
		} else if (!strcasecmp(v->name, "accountcode")) {
			/* post-T56 accountcode per-peer parity (2026-04-27): T46.3 dual-parser
			 * branch (config-file). CDR billing-tag; chan_sip parity at chan_sip.c:28884. */
			ast_string_field_set(peer, accountcode, v->value);
		} else if (!strcasecmp(v->name, "disallowed_methods")) {
			/* post-T56 disallowed_methods per-peer parity (2026-04-27): T46.3 dual-parser
			 * branch (config-file). PARSE-COMPAT-ONLY string-storage; same semantic as realtime branch. */
			ast_string_field_set(peer, disallowed_methods, v->value);
		} else if (!strcasecmp(v->name, "maxforwards")) {
			/* post-T56 maxforwards parity (2026-04-27): T46.3 dual-parser branch
			 * (config-file). Same chan_sip-verbatim bounds-check semantic as realtime branch. */
			if (sscanf(v->value, "%30d", &peer->maxforwards) != 1
				|| peer->maxforwards < 1 || 255 < peer->maxforwards) {
				ast_log(LOG_WARNING, "Sofia: '%s' is not a valid maxforwards value for peer '%s' — using default %d\n",
					v->value, peer->name, sofia_cfg.default_max_forwards);
				peer->maxforwards = sofia_cfg.default_max_forwards;
			}
		} else if (!strcasecmp(v->name, "insecure")) {
			if (!strcasecmp(v->value, "port")) {
				peer->insecure = SOFIA_INSECURE_PORT;
			} else if (!strcasecmp(v->value, "invite")) {
				peer->insecure = SOFIA_INSECURE_INVITE;
			} else if (!strcasecmp(v->value, "port,invite") || !strcasecmp(v->value, "very")) {
				peer->insecure = SOFIA_INSECURE_PORT | SOFIA_INSECURE_INVITE;
			}
		} else if (!strcasecmp(v->name, "dtmfmode")) {
			if (!strcasecmp(v->value, "rfc2833")) {
				peer->dtmfmode = SOFIA_DTMF_RFC2833;
			} else if (!strcasecmp(v->value, "info")) {
				peer->dtmfmode = SOFIA_DTMF_INFO;
			} else if (!strcasecmp(v->value, "inband")) {
				peer->dtmfmode = SOFIA_DTMF_INBAND;
			} else if (!strcasecmp(v->value, "auto")) {
				peer->dtmfmode = SOFIA_DTMF_AUTO;
			}
		} else if (!strcasecmp(v->name, "qualify")) {
			if (ast_true(v->value)) {
				peer->qualify = 1;
				peer->qualifyfreq = sofia_cfg.default_qualifyfreq > 0 ?
					sofia_cfg.default_qualifyfreq : DEFAULT_QUALIFYFREQ;
				peer->qualifytimeout = sofia_cfg.default_qualifytimeout > 0 ?
					sofia_cfg.default_qualifytimeout : DEFAULT_QUALIFYTIMEOUT;
			} else if (strcasecmp(v->value, "no")) {
				peer->qualify = 1;
				peer->qualifytimeout = atoi(v->value);
				if (peer->qualifytimeout <= 0)
					peer->qualifytimeout = DEFAULT_QUALIFYTIMEOUT;
				peer->qualifyfreq = sofia_cfg.default_qualifyfreq > 0 ?
					sofia_cfg.default_qualifyfreq : DEFAULT_QUALIFYFREQ;
			} else {
				peer->qualify = 0;
			}
		} else if (!strcasecmp(v->name, "qualifyfreq")) {
			peer->qualifyfreq = atoi(v->value);
			if (peer->qualifyfreq <= 0)
				peer->qualifyfreq = DEFAULT_QUALIFYFREQ;
		} else if (!strcasecmp(v->name, "qualifytimeout")) {
			peer->qualifytimeout = atoi(v->value);
			if (peer->qualifytimeout <= 0)
				peer->qualifytimeout = DEFAULT_QUALIFYTIMEOUT;
		} else if (!strcasecmp(v->name, "directmedia")
				|| !strcasecmp(v->name, "canreinvite")) {
			/* post-T56 canreinvite alias acceptance (2026-04-28): chan_sip parity at
			 * chan_sip.c:28137 verbatim dual-key OR-chain — chan_sip operators
			 * with legacy canreinvite= configs migrate verbatim zero-rewrite. */
			peer->directmedia = ast_true(v->value);
		} else if (!strcasecmp(v->name, "busy_on_active")) {
			peer->busy_on_active = ast_true(v->value);
		} else if (!strcasecmp(v->name, "max_contacts")) {
			peer->max_contacts = sofia_clamp_max_contacts(atoi(v->value), peer->name);
		} else if (!strcasecmp(v->name, "encryption")) {
			peer->encryption = ast_true(v->value);
		} else if (!strcasecmp(v->name, "srtpcipher")) {
			/* post-T56 srtpcipher operator option (2026-04-27): T46.3 dual-parser branch — config-file
			 * variant of the realtime branch in sofia_apply_peer_variables. Lenient WARN-on-typo
			 * happens at sdp_crypto_offer_list emit time. */
			ast_string_field_set(peer, srtpcipher, v->value);
		} else if (!strcasecmp(v->name, "session-timers")) {
			/* post-T56 session timers (RFC 4028) (2026-04-27): T46.3 dual-parser branch (config-file). */
			if (!strcasecmp(v->value, "originate"))      peer->session_timers = SESSION_TIMERS_ORIGINATE;
			else if (!strcasecmp(v->value, "accept"))    peer->session_timers = SESSION_TIMERS_ACCEPT;
			else if (!strcasecmp(v->value, "refuse"))    peer->session_timers = SESSION_TIMERS_REFUSE;
			else {
				ast_log(LOG_WARNING, "Sofia: invalid session-timers value '%s' for peer '%s' — using default\n",
					v->value, peer->name);
				peer->session_timers = sofia_cfg.default_session_timers;
			}
		} else if (!strcasecmp(v->name, "session-expires")) {
			peer->session_expires = atoi(v->value);
			if (peer->session_expires < 90) peer->session_expires = sofia_cfg.default_session_expires;
		} else if (!strcasecmp(v->name, "session-minse")) {
			peer->session_minse = atoi(v->value);
			if (peer->session_minse < 90) peer->session_minse = sofia_cfg.default_session_minse;
		} else if (!strcasecmp(v->name, "session-refresher")) {
			if (!strcasecmp(v->value, "uac"))      peer->session_refresher = SESSION_REFRESHER_UAC;
			else if (!strcasecmp(v->value, "uas")) peer->session_refresher = SESSION_REFRESHER_UAS;
			else                                   peer->session_refresher = SESSION_REFRESHER_AUTO;
		} else if (!strcasecmp(v->name, "callingpres")) {
			/* post-T56 identity-headers parity (2026-04-27): per-peer default presentation override.
			 * Reuses gabpbx core ast_parse_caller_presentation (callerid.h:356); chan_sip parity. */
			int p = ast_parse_caller_presentation(v->value);
			peer->callingpres = (p < 0) ? AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED : p;
		} else if (!strcasecmp(v->name, "sendrpid")) {
			/* post-T56 identity-headers parity (2026-04-27): outbound RPID/PAI emission mode. */
			if (!strcasecmp(v->value, "pai")) peer->sendrpid = 1;
			else if (!strcasecmp(v->value, "rpid")) peer->sendrpid = 2;
			else peer->sendrpid = 0;
		} else if (!strcasecmp(v->name, "trustrpid")) {
			/* post-T56 identity-headers parity (2026-04-27): trust inbound PAI/RPID. */
			peer->trustrpid = ast_true(v->value);
		} else if (!strcasecmp(v->name, "callcounter")) {
			/* post-T56 call-limit parity SS1 (2026-04-27): chan_sip parity shorthand. */
			peer->call_limit = ast_true(v->value) ? INT_MAX : 0;
		} else if (!strcasecmp(v->name, "call-limit") || !strcasecmp(v->name, "call_limit")) {
			/* post-T56 call-limit parity SS1 (2026-04-27): chan_sip parity. */
			peer->call_limit = atoi(v->value);
			if (peer->call_limit < 0) peer->call_limit = 0;
		} else if (!strcasecmp(v->name, "busylevel")) {
			/* post-T56 call-limit parity SS1 (2026-04-27): chan_sip parity soft-cap. */
			peer->busy_level = atoi(v->value);
			if (peer->busy_level < 0) peer->busy_level = 0;
		} else if (!strcasecmp(v->name, "mailbox")) {
			/* T55.1 (2026-04-27): comma-separated mbox@ctx list onto peer->mailboxes (no @ defaults to context "default"). */
			sofia_peer_parse_mailboxes(peer, v->value);
		} else if (!strcasecmp(v->name, "outboundproxy")) {
			/* T56.1 (2026-04-27): per-peer outbound proxy override. Empty = unset (no Route),
			 * non-empty = use this proxy. If peer field empty + sofia_cfg.outboundproxy set, peer
			 * inherits the general default at use time. */
			ast_string_field_set(peer, outboundproxy, v->value);
		} else if (!strcasecmp(v->name, "mohinterpret")) {
			/* post-T56 MOH per-peer parity (2026-04-27): per-peer MOH class for hold-MOH (chan_sip parity). */
			ast_string_field_set(peer, mohinterpret, v->value);
		} else if (!strcasecmp(v->name, "mohsuggest")) {
			/* post-T56 MOH per-peer parity (2026-04-27): per-peer mohsuggest INBOUND-direction propagation (chan_sip parity); OUTBOUND-direction Alert-Info signaling deferred. */
			ast_string_field_set(peer, mohsuggest, v->value);
		} else if (!strcasecmp(v->name, "language")) {
			/* post-T56 language per-peer parity (2026-04-27): chan_sip parity at
			 * chan_sip.c:28865-28866 verbatim ast_string_field_set(peer, language,
			 * v->value). Per-peer audio-locale propagated to ast_channel.language at
			 * sofia_new for prompts/sounds in peer's preferred locale. */
			ast_string_field_set(peer, language, v->value);
		} else if (!strcasecmp(v->name, "parkinglot")) {
			/* post-T56 parkinglot per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28890-28891 verbatim ast_string_field_set(peer, parkinglot,
			 * v->value). Per-peer parking-lot routing propagated to ast_channel.parkinglot
			 * at sofia_new for Park()/transfer routing. */
			ast_string_field_set(peer, parkinglot, v->value);
		} else if (!strcasecmp(v->name, "defaultip")) {
			/* post-T56 defaultip per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28814-28818 verbatim ast_get_ip(peer->defaddr, v->value).
			 * chan_sofia surpass on resolve-fail: LOG_WARNING + leave defaddr setnull
			 * (preserve peer with empty defaddr); chan_sip hard-fails build_peer
			 * (return NULL drops the entire peer alloc). */
			if (!ast_strlen_zero(v->value) && ast_get_ip(&peer->defaddr, v->value)) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' defaultip='%s' could not be resolved; ignoring\n",
					peer->name, v->value);
				ast_sockaddr_setnull(&peer->defaddr);
			}
		} else if (!strcasecmp(v->name, "maxcallbitrate")) {
			/* post-T56 maxcallbitrate per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28967-28970 verbatim atoi + bounds-clamp-on-negative-to-default. */
			peer->maxcallbitrate = atoi(v->value);
			if (peer->maxcallbitrate < 0) {
				peer->maxcallbitrate = sofia_cfg.default_maxcallbitrate;
			}
		} else if (!strcasecmp(v->name, "amaflags")) {
			/* post-T56 amaflags per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28871-28877 verbatim ast_cdr_amaflags2int + LOG_WARNING-
			 * on-invalid + skip-the-bad-key. Preserves peer with empty amaflags
			 * on parse-fail (channel-core default applies at sofia_new). */
			int format = ast_cdr_amaflags2int(v->value);
			if (format < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid AMA Flags '%s'; ignoring\n",
					peer->name, v->value);
			} else {
				peer->amaflags = format;
			}
		} else if (!strcasecmp(v->name, "subscribemwi")) {
			/* post-T56 subscribemwi per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28902-28903 verbatim ast_true + SIP_PAGE2_SUBSCRIBEMWIONLY.
			 * PARSE-COMPAT-ONLY ship — chan_sofia is SUBSCRIBE-only by T55 design;
			 * subscribemwi=yes drop-in compat; subscribemwi=no operator-honest LOG_NOTICE
			 * at parse-time + KNOWN LIMITATION (no unsolicited MWI NOTIFY support).
			 * Pattern 12 17th-instance NEW sub-pattern chan_sofia-architectural-divergence. */
			peer->subscribemwi = ast_true(v->value);
			if (!peer->subscribemwi) {
				ast_log(LOG_NOTICE,
					"Sofia: peer '%s' subscribemwi=no — chan_sofia is SUBSCRIBE-only MWI "
					"(Pattern 12 17th-instance chan_sofia-architectural-divergence); "
					"unsolicited MWI NOTIFY not implemented; behavior matches chan_sip "
					"subscribemwi=yes regardless of this setting\n",
					peer->name);
			}
		} else if (!strcasecmp(v->name, "preferred_codec_only")) {
			/* post-T56 preferred_codec_only per-peer parity (2026-04-28): chan_sip parity
			 * at chan_sip.c:28922-28923 verbatim ast_set2_flag SIP_PAGE2_PREFERRED_CODEC. */
			peer->preferred_codec_only = ast_true(v->value);
		} else if (!strcasecmp(v->name, "ignoresdpversion")) {
			/* post-T56 ignoresdpversion per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28199-28201 verbatim ast_set2_flag SIP_PAGE2_IGNORESDPVERSION
			 * via handle_common_options. PARSE-COMPAT-ONLY — chan_sofia processes every
			 * SDP unconditionally (KNOWN LIMITATION documented in sample.conf). */
			peer->ignoresdpversion = ast_true(v->value);
		} else if (!strcasecmp(v->name, "promiscredir")) {
			/* post-T56 promiscredir per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28173-28175 verbatim ast_set2_flag SIP_PROMISCREDIR via
			 * handle_common_options. PARSE-COMPAT-ONLY — chan_sofia nua_r_redirect
			 * handler ABSENT (KNOWN LIMITATION documented in sample.conf). */
			peer->promiscredir = ast_true(v->value);
		} else if (!strcasecmp(v->name, "autoframing")) {
			/* post-T56 autoframing per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28924-28925 verbatim DIRECT build_peer parser (NOT
			 * handle_common_options indirection). PARSE-COMPAT-ONLY — chan_sofia
			 * sofia_parse_sdp ptime gate not wired today (KNOWN LIMITATION
			 * documented in sample.conf; future-fix ~50-70 LoC follow-up). */
			peer->autoframing = ast_true(v->value);
		} else if (!strcasecmp(v->name, "timerb")) {
			/* post-T56 timerb per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28947-28952 verbatim DIRECT build_peer parser sscanf
			 * %30d + clamp-to-default-on-invalid-or-<200 + LOG_WARNING. */
			int tmp_b;
			if ((sscanf(v->value, "%30d", &tmp_b) != 1) || tmp_b < 200) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid timerb '%s' (< 200ms or non-integer); using default %d\n",
					peer->name, v->value, sofia_cfg.default_timer_b);
				peer->timer_b = sofia_cfg.default_timer_b;
			} else {
				peer->timer_b = tmp_b;
			}
		} else if (!strcasecmp(v->name, "timert1")) {
			/* post-T56 timert1 per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28941-28946 verbatim DIRECT build_peer parser sscanf
			 * %30d + triple-clamp (val < 200 || val < t1min) → LOG_WARNING +
			 * fallback peer->timer_t1 = sofia_cfg.t1min (chan_sip-faithful
			 * "fallback to t1min not default_timer_t1" floor semantic). */
			int tmp_t1;
			if ((sscanf(v->value, "%30d", &tmp_t1) != 1) || tmp_t1 < 200 || tmp_t1 < sofia_cfg.t1min) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid timert1 '%s' (< 200ms or < t1min %d); using t1min floor\n",
					peer->name, v->value, sofia_cfg.t1min);
				peer->timer_t1 = sofia_cfg.t1min;
			} else {
				peer->timer_t1 = tmp_t1;
			}
		} else if (!strcasecmp(v->name, "faxdetect")) {
			/* faxdetect parser: yes -> cng+t38, no -> none, or a
			 * comma-separated cng/t38 set. Runtime wire-in handles DSP
			 * CNG detection and peer T.38 reINVITE detection. */
			if (ast_true(v->value)) {
				peer->faxdetect_mode = SOFIA_FAX_DETECT_BOTH;
			} else if (ast_false(v->value)) {
				peer->faxdetect_mode = SOFIA_FAX_DETECT_NONE;
			} else {
				char *fbuf = ast_strdupa(v->value);
				char *fword, *fnext = fbuf;
				peer->faxdetect_mode = SOFIA_FAX_DETECT_NONE;
				while ((fword = strsep(&fnext, ","))) {
					if (!strcasecmp(fword, "cng")) {
						peer->faxdetect_mode |= SOFIA_FAX_DETECT_CNG;
					} else if (!strcasecmp(fword, "t38")) {
						peer->faxdetect_mode |= SOFIA_FAX_DETECT_T38;
					} else {
						ast_log(LOG_WARNING, "Sofia: peer '%s' unknown faxdetect mode '%s'\n",
							peer->name, fword);
					}
				}
			}
		} else if (!strcasecmp(v->name, "t38pt_udptl")) {
			/* post-T56 Task #8 T.38 fax UDPTL parity SS2 (2026-04-28, T46.3
			 * dual-parser: same logic at config-file path + realtime path).
			 * Per-peer T.38 enable + EC mode + MaxDatagram override mirrors
			 * chan_sip.c:28038-28057 verbatim handle_t38_options semantic.
			 * Comma-separated value list: yes|no|fec|redundancy|none[,maxdatagram=N].
			 * `yes` defaults EC = FEC per chan_sip drop-in. SDP wire-in arrives
			 * SS3a; this parser only stores fields. */
			char *value = ast_strdupa(v->value);
			char *word, *next = value;
			peer->t38pt_udptl = 0;
			peer->t38_ec_mode = SOFIA_T38_EC_FEC;
			while ((word = strsep(&next, ","))) {
				int x;
				if (!strcasecmp(word, "yes")) {
					peer->t38pt_udptl = 1;
					peer->t38_ec_mode = SOFIA_T38_EC_FEC;
				} else if (!strcasecmp(word, "no")) {
					peer->t38pt_udptl = 0;
				} else if (!strcasecmp(word, "fec")) {
					peer->t38pt_udptl = 1;
					peer->t38_ec_mode = SOFIA_T38_EC_FEC;
				} else if (!strcasecmp(word, "redundancy")) {
					peer->t38pt_udptl = 1;
					peer->t38_ec_mode = SOFIA_T38_EC_REDUNDANCY;
				} else if (!strcasecmp(word, "none")) {
					peer->t38pt_udptl = 1;
					peer->t38_ec_mode = SOFIA_T38_EC_NONE;
				} else if (sscanf(word, "maxdatagram=%30d", &x) == 1) {
					peer->t38_maxdatagram = x;
				} else {
					ast_log(LOG_WARNING, "Sofia: peer '%s' unknown t38pt_udptl option '%s'\n",
						peer->name, word);
				}
			}
		} else if (!strcasecmp(v->name, "t38pt_usertpsource")) {
			/* post-T56 Task #8 T.38 fax UDPTL parity SS2 (2026-04-28, SS1.5 N3
			 * audit catch): symmetric-RTP UDPTL destination override per chan_sip.c
			 * :28061-28063 verbatim. Boolean. Consumed at SS3a SDP processing per
			 * chan_sip.c:10171 gate `SIP_PAGE2_SYMMETRICRTP && SIP_PAGE2_UDPTL_
			 * DESTINATION` mirror. */
			peer->t38pt_usertpsource = ast_true(v->value) ? 1 : 0;
		} else if (!strcasecmp(v->name, "allowoverlap")) {
			/* post-T56 allowoverlap per-peer parity (2026-04-28, Option A FULL
			 * WIRE-IN 3 sites): chan_sip parity at chan_sip.c:28188-28195 verbatim
			 * tri-state parser via handle_common_options. ast_true → YES;
			 * !strcasecmp("dtmf") → DTMF; else → NO. */
			if (ast_true(v->value)) {
				peer->allowoverlap_mode = SOFIA_OVERLAP_YES;
			} else if (!strcasecmp(v->value, "dtmf")) {
				peer->allowoverlap_mode = SOFIA_OVERLAP_DTMF;
			} else {
				peer->allowoverlap_mode = SOFIA_OVERLAP_NO;
			}
		} else if (!strcasecmp(v->name, "progressinband")) {
			/* post-T56 progressinband per-peer parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28167-28172 verbatim tri-state semantic via handle_common_options.
			 * Mirror: ast_true(v->value) → YES; non-"never" → NO; "never" literal → NEVER.
			 * Option B partial wire-in at sofia_indicate AST_CONTROL_RINGING. */
			if (ast_true(v->value)) {
				peer->progressinband = SOFIA_PROG_INBAND_YES;
			} else if (strcasecmp(v->value, "never")) {
				peer->progressinband = SOFIA_PROG_INBAND_NO;
			} else {
				peer->progressinband = SOFIA_PROG_INBAND_NEVER;
			}
		} else if (!strcasecmp(v->name, "rtptimeout")) {
			/* post-T56 rtp-timeout bundle per-peer parity (2026-04-28): chan_sip parity
			 * at chan_sip.c:28927-28930 verbatim sscanf %30d + LOG_WARNING + clamp-to-
			 * global-on-invalid semantic. */
			if ((sscanf(v->value, "%30d", &peer->rtptimeout) != 1) || peer->rtptimeout < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid rtptimeout '%s'; using default\n",
					peer->name, v->value);
				peer->rtptimeout = sofia_cfg.default_rtptimeout;
			}
		} else if (!strcasecmp(v->name, "rtpholdtimeout")) {
			/* post-T56 rtp-timeout bundle per-peer parity (2026-04-28): chan_sip parity
			 * at chan_sip.c:28932-28935 verbatim. */
			if ((sscanf(v->value, "%30d", &peer->rtpholdtimeout) != 1) || peer->rtpholdtimeout < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid rtpholdtimeout '%s'; using default\n",
					peer->name, v->value);
				peer->rtpholdtimeout = sofia_cfg.default_rtpholdtimeout;
			}
		} else if (!strcasecmp(v->name, "rtpkeepalive")) {
			/* post-T56 rtp-timeout bundle per-peer parity (2026-04-28): chan_sip parity
			 * at chan_sip.c:28937-28940 verbatim. */
			if ((sscanf(v->value, "%30d", &peer->rtpkeepalive) != 1) || peer->rtpkeepalive < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid rtpkeepalive '%s'; using default\n",
					peer->name, v->value);
				peer->rtpkeepalive = sofia_cfg.default_rtpkeepalive;
			}
		} else if (!strcasecmp(v->name, "callerid")) {
			/* post-T56 cid bundle parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28739-28744 verbatim ast_callerid_split → cid_name + cid_num. */
			char cid_name_buf[80] = "", cid_num_buf[80] = "";
			ast_callerid_split(v->value, cid_name_buf, sizeof(cid_name_buf),
				cid_num_buf, sizeof(cid_num_buf));
			ast_string_field_set(peer, cid_name, cid_name_buf);
			ast_string_field_set(peer, cid_num, cid_num_buf);
		} else if (!strcasecmp(v->name, "fullname")
				|| !strcasecmp(v->name, "cid_name")) {
			/* post-T56 cid bundle parity (2026-04-28): fullname (chan_sip parity at
			 * chan_sip.c:28747-28748 verbatim) + cid_name (chan_sofia ARCHITECTURAL
			 * ADVANTAGE 11th-instance natural-named-field-as-alias for operator
			 * convenience; chan_sip ABSENT). */
			ast_string_field_set(peer, cid_name, v->value);
		} else if (!strcasecmp(v->name, "trunkname")) {
			/* post-T56 cid bundle parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28749-28751 verbatim — trunkname clears cid_name. */
			ast_string_field_set(peer, cid_name, "");
		} else if (!strcasecmp(v->name, "cid_number")) {
			/* post-T56 cid bundle parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28752-28753 verbatim. */
			ast_string_field_set(peer, cid_num, v->value);
		} else if (!strcasecmp(v->name, "cid_tag")) {
			/* post-T56 cid bundle parity (2026-04-28): chan_sip parity at
			 * chan_sip.c:28754-28755 verbatim. */
			ast_string_field_set(peer, cid_tag, v->value);
		} else if (!strcasecmp(v->name, "callgroup")) {
			peer->callgroup = ast_get_group(v->value);
		} else if (!strcasecmp(v->name, "allowtransfer")) {
			/* post-T56 allowtransfer per-peer parity (2026-04-27): T46.3 dual-parser
			 * branch (config-file). Same chan_sip-verbatim binary semantic as the
			 * realtime branch in sofia_apply_peer_variables. */
			peer->allowtransfer = ast_true(v->value) ? TRANSFER_OPENFORALL : TRANSFER_CLOSED;
		} else if (!strcasecmp(v->name, "allowsubscribe")) {
			/* post-T56 allowsubscribe per-peer parity (2026-04-27): T46.3 dual-parser
			 * branch (config-file). Same chan_sip-verbatim binary semantic as the
			 * realtime branch in sofia_apply_peer_variables. */
			peer->allowsubscribe = ast_true(v->value);
		} else if (!strcasecmp(v->name, "buggymwi")) {
			/* post-T56 buggymwi per-peer parity (2026-04-27): T46.3 dual-parser
			 * branch (config-file). Same chan_sip-verbatim binary semantic as the
			 * realtime branch in sofia_apply_peer_variables. */
			peer->buggymwi = ast_true(v->value);
		} else if (!strcasecmp(v->name, "lockuseragent")) {
			/* post-T56 lockuseragent per-peer parity (2026-04-27): T46.3 dual-parser
			 * branch (config-file). chan_sofia surpass over chan_sip realtime-only
			 * parser-quirk — config-file operators get same lock semantic. */
			peer->lockuseragent = ast_true(v->value);
		} else if (!strcasecmp(v->name, "lockuseragent_prefixes")) {
			/* lockuseragent_prefixes per-peer parity: config-file dual-parser
			 * branch. Mirrors sofia_apply_peer_variables realtime branch so
			 * sofia.conf and voip_sip_conf consumers share identical semantics. */
			ast_string_field_set(peer, lockuseragent_prefixes, v->value);
		} else if (!strcasecmp(v->name, "usereqphone")) {
			/* post-T56 usereqphone parity (2026-04-27): T46.3 dual-parser branch
			 * (config-file). Same chan_sip-verbatim semantic as realtime branch. */
			peer->usereqphone = ast_true(v->value);
		} else if (!strcasecmp(v->name, "pickupgroup")) {
			peer->pickupgroup = ast_get_group(v->value);
		} else if (!strcasecmp(v->name, "permit") || !strcasecmp(v->name, "deny")) {
			int ha_error = 0;
			peer->ha = ast_append_ha(v->name, v->value, peer->ha, &ha_error);
			if (ha_error) {
				ast_log(LOG_ERROR, "Sofia: bad %s line for peer '%s': %s\n",
					v->name, peer->name, v->value);
			}
		} else if (!strcasecmp(v->name, "contactpermit") || !strcasecmp(v->name, "contactdeny")) {
			/* post-T56 contactpermit/contactdeny per-peer parity (2026-04-27): chan_sip
			 * parity at chan_sip.c:28827-28832 verbatim — ast_append_ha(v->name + 7, ...)
			 * skips "contact" prefix. Separate ACL chain from peer->ha (Task 32 source-IP). */
			int ha_error = 0;
			if (!ast_strlen_zero(v->value)) {
				peer->contactha = ast_append_ha(v->name + 7, v->value, peer->contactha, &ha_error);
			}
			if (ha_error) {
				ast_log(LOG_ERROR, "Sofia: bad %s line for peer '%s': %s\n",
					v->name, peer->name, v->value);
			}
		} else if (!strcasecmp(v->name, "directmediapermit") || !strcasecmp(v->name, "directmediadeny")) {
			/* post-T56 directmediapermit/directmediadeny per-peer parity (2026-04-27):
			 * chan_sip parity at chan_sip.c:28835-28838 verbatim — ast_append_ha(v->name + 11, ...)
			 * skips "directmedia" prefix; remaining "permit" or "deny" passed as sense. Cross-peer
			 * cross-leg ACL applied at sofia_get_rtp_peer (chan_sofia ARCHITECTURAL ADVANTAGE
			 * 6th-instance — single gate vs chan_sip 4 process_sdp callouts). */
			int ha_error = 0;
			peer->directmediaha = ast_append_ha(v->name + 11, v->value, peer->directmediaha, &ha_error);
			if (ha_error) {
				ast_log(LOG_ERROR, "Sofia: bad directmedia %s line for peer '%s': %s\n",
					v->name, peer->name, v->value);
			}
		} else if (!strcasecmp(v->name, "nat")) {
			if (!strcasecmp(v->value, "yes")) {
				peer->nat = SOFIA_NAT_FORCE_RPORT | SOFIA_NAT_COMEDIA;
			} else if (!strcasecmp(v->value, "force_rport")) {
				peer->nat = SOFIA_NAT_FORCE_RPORT;
			} else if (!strcasecmp(v->value, "comedia")) {
				peer->nat = SOFIA_NAT_COMEDIA;
			} else if (!strcasecmp(v->value, "force_rport,comedia") || !strcasecmp(v->value, "comedia,force_rport")) {
				peer->nat = SOFIA_NAT_FORCE_RPORT | SOFIA_NAT_COMEDIA;
			} else {
				peer->nat = 0;
			}
		} else if (!strcasecmp(v->name, "expiresecs") || !strcasecmp(v->name, "defaultexpiry")) {
			peer->expiresecs = atoi(v->value);
		} else if (!strcasecmp(v->name, "transport")) {
			/* Silently accept for chan_sip drop-in template compatibility — see
			 * sofia_apply_peer_variables transport= branch for rationale. The
			 * value is not applied to peer->transport; transports are controlled
			 * per-listener at [general] bindport / tcpbindaddr / tlsbindaddr /
			 * wsbindaddr / wssbindaddr, and per-Contact at REGISTER-time. */
		} else if (!strcasecmp(v->name, "allow")) {
			ast_parse_allow_disallow(&peer->prefs, &peer->capability, v->value, 1);
		} else if (!strcasecmp(v->name, "disallow")) {
			ast_parse_allow_disallow(&peer->prefs, &peer->capability, v->value, 0);
		}
	}

	if (ast_strlen_zero(peer->host)) {
		ast_string_field_set(peer, host, "dynamic");
	}
	if (ast_strlen_zero(peer->context)) {
		ast_string_field_set(peer, context, sofia_cfg.context);
	}
	if (ast_strlen_zero(peer->defaultuser)) {
		ast_string_field_set(peer, defaultuser, cat);
	}
	if (peer->capability == 0) {
		peer->capability = AST_FORMAT_ULAW | AST_FORMAT_ALAW;
	}

	/* post-T56 germanico dynamic hints parity (2026-04-27): chan_sofia surpass —
	 * config-file peer hint creation (chan_sip fires only at realtime-peer-load).
	 * Operationally useful for non-realtime deployments (sofia.conf static peers
	 * gain presence-hint dialplan injection). Helper differentiates origin via
	 * "config" source argument → "sofia_config_peer" registrar (operator visibility
	 * into hint origin via `core show hints` Replace registrar). */
	sofia_create_peer_hint(peer, "config");

	/* post-T56 dnsmgr per-peer parity (2026-04-27): register async DNS lookup
	 * for config-file peers (mirror sofia_find_peer_realtime conclusion). */
	sofia_dnsmgr_setup_peer(peer);

	/* post-T56 dynamic_exclude_static [general] parity (2026-04-28): chan_sip parity
	 * at chan_sip.c:29164 verbatim peer-build-time mechanism — when flag set + peer
	 * has static IP literal, append deny rule to global contact_ha (existing e9d6cb1
	 * infrastructure leverage). Subsequent REGISTER processing rejects via existing
	 * sofia_process_register contact_ha apply at L5398-5405. */
	if (sofia_cfg.dynamic_exclude_static && !ast_strlen_zero(peer->host)
			&& strcasecmp(peer->host, "dynamic")) {
		struct ast_sockaddr static_addr;
		if (ast_sockaddr_parse(&static_addr, peer->host, 0)) {
			int ha_error = 0;
			sofia_cfg.contact_ha = ast_append_ha("deny",
				ast_sockaddr_stringify_addr(&static_addr),
				sofia_cfg.contact_ha, &ha_error);
			if (ha_error) {
				ast_log(LOG_ERROR,
					"Sofia: dynamic_exclude_static — bad addr for static peer '%s' (%s)\n",
					peer->name, peer->host);
			}
		}
	}

	ao2_link(peers, peer);
	ao2_ref(peer, -1);
}

/* post-T56 allowsubscribe derive (2026-04-27): mirror chan_sip.c:29217-29218 verbatim
 * "sip_cfg.allowsubscribe = TRUE if any peer flag-allows" semantic. Pre-derive FALSE
 * + ao2_callback sweep flips global to TRUE on first allowing peer. Centralized
 * post-config sweep vs chan_sip per-peer-build duplication (chan_sofia ARCHITECTURAL
 * ADVANTAGE 8th-instance — single sweep callsite vs build_peer inline at every peer).
 * One-way flip: once TRUE, stays TRUE for module lifetime (chan_sip same semantic;
 * "No global ban any more" comment).
 *
 * Called at sofia_load_config conclusion (initial + reload). For runtime-added
 * realtime peers, sofia_find_peer_realtime sets sofia_cfg.allowsubscribe=1 inline
 * if the new peer allows — no full sweep needed (already-TRUE short-circuits). */
static int sofia_derive_allowsubscribe_cb(void *obj, void *arg, int flags)
{
	struct sofia_peer *peer = obj;

	if (peer->allowsubscribe) {
		sofia_cfg.allowsubscribe = 1;
		return CMP_MATCH | CMP_STOP;
	}
	return 0;
}

static void sofia_post_config_derive_allowsubscribe(void)
{
	sofia_cfg.allowsubscribe = 0;
	ao2_callback(peers, OBJ_NODATA, sofia_derive_allowsubscribe_cb, NULL);
}

/* Apply a parsed sofia.conf to the live sofia_cfg + peers state.  Extracted
 * from the historical sofia_load_config body so both the init path
 * (sofia_load_config wraps this with ast_config_load/destroy) and the
 * reload worker (sofia_reload_worker) can share the same defaults-reset +
 * [general] parse + per-peer parse + cross-validate + autodomain +
 * derive_allowsubscribe logic.  Caller owns the cfg lifetime — do NOT
 * destroy it here.  Returns 0 on success, -1 on a hard failure that
 * leaves the live state partially mutated (caller should log + bail). */
static int sofia_apply_config(struct ast_config *cfg)
{
	char *cat;

	/* Drain the global domain_list before we re-populate it from the new
	 * config (domain= directives + autodomain auto-add).  Without this,
	 * a domain removed from sofia.conf would stay in the allowed-domains
	 * set until module unload — both a stale-state correctness bug and a
	 * security concern (deleted domain still accepted as local).  On
	 * initial load the list is already empty so the drain is a no-op. */
	{
		struct sofia_domain *d;
		AST_LIST_LOCK(&domain_list);
		while ((d = AST_LIST_REMOVE_HEAD(&domain_list, list))) {
			ast_free(d);
		}
		AST_LIST_UNLOCK(&domain_list);
	}

	ast_copy_string(sofia_cfg.bindaddr, DEFAULT_BINDADDR, sizeof(sofia_cfg.bindaddr));
	sofia_cfg.bindport = DEFAULT_SIP_PORT;
	ast_copy_string(sofia_cfg.context, DEFAULT_CONTEXT, sizeof(sofia_cfg.context));
	ast_copy_string(sofia_cfg.realm, "gabpbx", sizeof(sofia_cfg.realm));
	/* post-T56 useragent [general] parity (2026-04-28): default-init User-Agent
	 * via DEFAULT_USERAGENT macro + runtime ast_get_version() yielding e.g.
	 * "GABpbx PBX 2.7.1". chan_sip parity chan_sip.c:29455 verbatim shape:
	 *   snprintf(global_useragent, sizeof(global_useragent), "%s %s",
	 *           DEFAULT_USERAGENT, ast_get_version());
	 * Operator [general] useragent= directive overrides via ast_copy_string at
	 * sofia_parse_general_config branch. */
	snprintf(sofia_cfg.useragent, sizeof(sofia_cfg.useragent), "%s %s",
		DEFAULT_USERAGENT, ast_get_version());
	sofia_cfg.allowguest = 1;
	sofia_cfg.busy_on_active = 0;
	sofia_cfg.max_contacts = 6;
	sofia_cfg.encryption = 0;
	/* post-T56 srtpcipher operator option (2026-04-27): empty default = sdp_crypto.c hardcoded fallback (AES_CM_128_HMAC_SHA1_80). */
	sofia_cfg.default_srtpcipher[0] = '\0';
	/* post-T56 Task 7b SRTP per-suite-fresh-key option (2026-04-28, deferred from
	 * #7a 612759d R4 strategy (b)): default 0 = shared-key mode preserves #7a
	 * strategy (a) baseline (current behavior). Module-scope mirror reset adjacent
	 * for sdp_crypto.c extern visibility. */
	sofia_cfg.srtp_per_suite_keys = 0;
	sofia_srtp_per_suite_keys = 0;
	/* post-T56 Task #3 INVITE digest auth SS3 (2026-04-28, R18 chan_sofia surpass
	 * dimension operator-policy-global-security-override): default 0 = drop-in
	 * chan_sip parity baseline (per-peer insecure=invite bypass remains active).
	 * Operator must explicitly set force_invite_auth=yes to activate global
	 * lockdown override. */
	sofia_cfg.force_invite_auth = 0;
	/* Default 0 = use SOFIA_NONCE_TTL_SEC_DEFAULT (3600s).
	 * Operator override via [general] nonce_ttl_seconds=N. */
	sofia_cfg.nonce_ttl_seconds = 0;
	/* post-T56 session timers (RFC 4028) (2026-04-27): chan_sip-parity defaults. */
	sofia_cfg.default_session_timers = SESSION_TIMERS_ACCEPT; /* honor inbound; no initiate */
	sofia_cfg.default_session_expires = 1800;                  /* RFC 4028 §4 typical */
	sofia_cfg.default_session_minse = 90;                      /* RFC 4028 §3 floor */
	sofia_cfg.default_session_refresher = SESSION_REFRESHER_AUTO;
	/* post-T56 allowtransfer per-peer parity (2026-04-27): chan_sip parity at
	 * chan_sip.c:29476 ("Merrily accept all transfers by default"). */
	sofia_cfg.default_allowtransfer = TRANSFER_OPENFORALL;
	/* post-T56 allowsubscribe per-peer parity (2026-04-27): chan_sip parity at
	 * chan_sip.c:29478 ast_set_flag(global_flags[1], SIP_PAGE2_ALLOWSUBSCRIBE)
	 * default TRUE per sip.h:478. The DERIVED sofia_cfg.allowsubscribe global
	 * ban-all flag starts FALSE and is flipped TRUE by sofia_post_config_derive_allowsubscribe
	 * if any peer ends up allowing — same semantic as chan_sip.c:29217-29218 build_peer
	 * derive (post-config-load sweep instead of per-peer-build duplication). */
	sofia_cfg.default_allowsubscribe = 1;
	sofia_cfg.allowsubscribe = 0;
	/* post-T56 regexten + regextenonqualify parity (2026-04-27): empty regcontext
	 * default = mechanism disabled (chan_sip parity at chan_sip.c:29442); regextenonqualify
	 * default FALSE per sip.h:215 DEFAULT_REGEXTENONQUALIFY (chan_sip.c:29444). */
	sofia_cfg.regcontext[0] = '\0';
	sofia_cfg.regextenonqualify = 0;
	/* post-T56 subscribecontext per-peer parity (2026-04-27): empty default per
	 * chan_sip.c:29496 sip_cfg.default_subscribecontext[0] = '\0'. */
	sofia_cfg.default_subscribecontext[0] = '\0';
	/* post-T56 registration TTL bounds + 423 Interval Too Brief parity (2026-04-27):
	 * sip.h:55-57 verbatim DEFAULT_* values (60/3600/120). Operators override via
	 * [general] minexpiry/maxexpiry/defaultexpiry (or typo-form variants). */
	sofia_cfg.min_expiry     = DEFAULT_MIN_EXPIRY;
	sofia_cfg.max_expiry     = DEFAULT_MAX_EXPIRY;
	sofia_cfg.default_expiry = DEFAULT_DEFAULT_EXPIRY;
	/* post-T56 usereqphone parity (2026-04-27): chan_sip parity static-zero
	 * default flag-bit behavior — operator opts in via [general] usereqphone=yes
	 * or per-peer override. */
	sofia_cfg.default_usereqphone = 0;
	/* post-T56 maxforwards parity (2026-04-27): RFC 3261 §20.22 default value 70
	 * per sip.h:60 verbatim chan_sip parity. */
	sofia_cfg.default_max_forwards = DEFAULT_MAX_FORWARDS;
	/* post-T56 t1min parity (2026-04-27): RFC 3261 §17.1.1.2 minimum bound
	 * default 100ms per sip.h:217 verbatim chan_sip parity. */
	sofia_cfg.t1min = DEFAULT_T1MIN;
	/* post-T56 relaxdtmf + prematuremedia parity (2026-04-27): chan_sip parity
	 * direct literal defaults (no DEFAULT_* macros) per chan_sip.c:29458 + L29518. */
	sofia_cfg.relaxdtmf = 0;
	sofia_cfg.prematuremediafilter = 1;
	/* post-T56 registertimeout + registerattempts parity (2026-04-27): chan_sip
	 * parity defaults — register_timeout=20s per sip.h:59 verbatim;
	 * register_attempts=0 (unlimited) per chan_sip.c:725 static-zero init. */
	sofia_cfg.register_timeout = DEFAULT_REGISTRATION_TIMEOUT;
	sofia_cfg.register_attempts = 0;
	/* post-T56 directrtpsetup parity (2026-04-27): chan_sip parity at chan_sip.c:29449
	 * verbatim direct literal default FALSE (no DEFAULT_* macro). PARSE-COMPAT-ONLY ship
	 * per Pattern 12 — experimental feature; effect-deferred. */
	sofia_cfg.directrtpsetup = 0;
	/* post-T56 alwaysauthreject parity (2026-04-27): chan_sip parity DEFAULT_ALWAYSAUTHREJECT=TRUE
	 * per sip.h:213 verbatim. Drop-in critical security default — operators upgrading from
	 * chan_sip retain identical baseline behavior; RFC 3261 §22.4 username-enumeration
	 * prevention active out-of-the-box. */
	sofia_cfg.alwaysauthreject = 1;
	/* post-T56 compactheaders parity (2026-04-27): chan_sip parity DEFAULT_COMPACTHEADERS=FALSE
	 * per sip.h:194 verbatim. Pattern 12 12th-instance PARSE-COMPAT-ONLY ship — sofia-sip
	 * native compact-emit gate ABSENT; field parsed + stored but no behavioral effect today. */
	sofia_cfg.compactheaders = 0;
	/* post-T56 disallowed_methods parity (2026-04-27): empty string default
	 * (operator-honest divergence from chan_sip SIP_UNKNOWN bitmask at L29453 —
	 * chan_sofia uses sofia-sip NUTAG_APPL_METHOD for unknown-method gating). */
	sofia_cfg.disallowed_methods[0] = '\0';
	/* post-T56 contactpermit/contactdeny [general] parity (2026-04-27): clear ACL
	 * chain on each load (chan_sip.c:29359-29360 + L29454 verbatim pattern). */
	if (sofia_cfg.contact_ha) {
		ast_free_ha(sofia_cfg.contact_ha);
		sofia_cfg.contact_ha = NULL;
	}
	/* T55.1 (2026-04-27): MWI defaults (RFC 3842 + chan_sip parity). */
	sofia_cfg.mwi_from[0] = '\0';
	ast_copy_string(sofia_cfg.notifymime, "application/simple-message-summary", sizeof(sofia_cfg.notifymime));
	ast_copy_string(sofia_cfg.vmexten, "asterisk", sizeof(sofia_cfg.vmexten));
	sofia_cfg.mwi_expiry = 3600;
	/* T56.1 (2026-04-27): outboundproxy default empty — operator opts in via [general] or per-peer */
	sofia_cfg.outboundproxy[0] = '\0';
	/* post-T56 language per-peer parity (2026-04-27): chan_sip parity at chan_sip.c:29498
	 * default_language[0]='\0' verbatim — empty default = no language override; gabpbx-core
	 * default language used unless [general] or per-peer language= overrides. */
	sofia_cfg.default_language[0] = '\0';
	/* post-T56 parkinglot [general] parity (2026-04-28): chan_sip parity at chan_sip.c:29510
	 * verbatim ast_copy_string(default_parkinglot, DEFAULT_PARKINGLOT, sizeof) — features.h:37
	 * DEFAULT_PARKINGLOT = "default" string. R3 Option 3-B chan_sip-verbatim default per
	 * Enginer verdict — Pattern 12 16th-instance behavior-change-from-chan_sofia-baseline
	 * disclosure 2nd-instance (prior chan_sofia silent-empty baseline replaced; operators
	 * preferring silent-baseline restoration set [general] parkinglot= empty). */
	ast_copy_string(sofia_cfg.default_parkinglot, "default", sizeof(sofia_cfg.default_parkinglot));
	/* post-T56 ignoreregexpire [general] parity (2026-04-28): default 0 (FALSE) — chan_sip
	 * drop-in (chan_sip default = implicit sip_cfg static-zero with no explicit init line;
	 * chan_sofia explicit-init for clarity). When 0, expired contacts removed normally
	 * by sofia_expire_contacts_cb periodic ao2_callback. */
	sofia_cfg.ignore_regexpire = 0;
	/* post-T56 maxcallbitrate [general] parity (2026-04-28): default 384 kbps per
	 * sip.h:218 DEFAULT_MAX_CALL_BITRATE + chan_sip.c:29502 verbatim. chan_sip
	 * drop-in critical default — every video SDP emits b=CT:384 by default.
	 * Pattern 12 14th-instance NEW sub-pattern behavior-change-from-chan_sofia-baseline:
	 * prior chan_sofia silent-no-b=CT baseline replaced; operators preferring
	 * silent baseline set [general] maxcallbitrate=0 explicitly. Audio-only
	 * operators unaffected (b=CT gated inside if (needvideo) block). */
	sofia_cfg.default_maxcallbitrate = 384;
	/* post-T56 match_auth_username [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:29472 verbatim default-init FALSE. */
	sofia_cfg.match_auth_username = 0;
	/* post-T56 legacy_useroption_parsing [general] parity (2026-04-28): chan_sip parity
	 * at chan_sip.c:29445 verbatim default-init via DEFAULT_LEGACY_USEROPTION_PARSING
	 * = FALSE per sip.h:216. PARSE-COMPAT-ONLY ship — Pattern 12 15th-instance
	 * sofia-sip-library-feature-absence sub-pattern 2nd-instance. */
	sofia_cfg.legacy_useroption_parsing = 0;
	/* post-T56 shrinkcallerid [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:29526 verbatim default-init = 1 chan_sip drop-in critical default.
	 * Pattern 12 18th-instance behavior-change-from-chan_sofia-baseline sub-pattern
	 * 3rd-instance — prior chan_sofia silent-baseline-no-normalization replaced. */
	sofia_cfg.shrinkcallerid = 1;
	/* post-T56 notifyhold [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:29448 verbatim default-init FALSE. Gates peer->onHold counter
	 * atomic update at sofia_process_reinvite hold transition (chan_sofia.c:4471-4473);
	 * AMI Hold emission at L4521 UNCONDITIONAL per chan_sip callevents=yes typical case. */
	sofia_cfg.notifyhold = 0;
	/* post-T56 notifyringing [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:29446 verbatim default-init via DEFAULT_NOTIFYRINGING = TRUE per
	 * sip.h:206. PARSE-COMPAT-ONLY ship (Pattern 12 19th-instance chan_sofia-
	 * architectural-divergence sub-pattern 2nd-instance) — flag effect-deferred
	 * until presence/dialog-info NOTIFY infrastructure landed. */
	sofia_cfg.notifyringing = 1;
	/* post-T56 dynamic_exclude_static [general] parity (2026-04-28): chan_sip parity
	 * at chan_sip.c:29481 verbatim default-init = 0 chan_sip drop-in. Security
	 * hardening flag — peer-build wire-in appends static peer IPs as deny rules
	 * to sofia_cfg.contact_ha (existing e9d6cb1 contact_ha infrastructure leverage). */
	sofia_cfg.dynamic_exclude_static = 0;
	/* post-T56 autocreatepeer [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:29468 verbatim default-init via DEFAULT_AUTOCREATEPEER = FALSE per
	 * sip.h:209. PARSE-COMPAT-ONLY ship (Pattern 12 20th-instance chan_sofia-
	 * architectural-divergence sub-pattern 3rd-instance PROVEN) — chan_sofia design
	 * refuses auto-create unknown peers (security-stronger via alwaysauthreject c293e54). */
	sofia_cfg.autocreatepeer = 0;
	/* post-T56 preferred_codec_only [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:29863-29864 default-init = 0 (FALSE) chan_sip drop-in. Inherited
	 * by sofia_peer_alloc; codec-list-narrowing wired at sofia_generate_sdp Option 6-A
	 * direction-symmetric (chan_sofia helper-architecture-advantage 12th-instance). */
	sofia_cfg.default_preferred_codec_only = 0;
	/* post-T56 progressinband [general] parity (2026-04-28): chan_sip parity default
	 * NEVER per ast_clear_flag at chan_sip handle_common_options (no in-band audio
	 * with provisional response). Operators get current chan_sofia behavior preserved
	 * when omitting the key. Option B partial wire-in honored at sofia_indicate
	 * AST_CONTROL_RINGING for YES state. */
	sofia_cfg.default_progressinband = SOFIA_PROG_INBAND_NEVER;
	/* post-T56 promiscredir [general] parity (2026-04-28): chan_sip parity default
	 * FALSE per BSS static-zero of global_flags[0] SIP_PROMISCREDIR bit. PARSE-
	 * COMPAT-ONLY (chan_sofia nua_r_redirect handler ABSENT; flag has no behavioral
	 * effect; future-fix path documented in sample.conf). */
	sofia_cfg.default_promiscredir = 0;
	/* post-T56 autoframing [general] parity (2026-04-28): chan_sip parity default
	 * FALSE per chan_sip.c:29469 verbatim default-init `global_autoframing = 0`.
	 * PARSE-COMPAT-ONLY (chan_sofia sofia_parse_sdp ptime gate not wired today). */
	sofia_cfg.default_autoframing = 0;
	/* post-T56 faxdetect [general] multi-mode parity (2026-04-28): chan_sip
	 * default NONE per chan_sip.c:29536. When enabled, current runtime
	 * wire-in covers DSP CNG detection and peer T.38 reINVITE detection. */
	sofia_cfg.default_faxdetect_mode = SOFIA_FAX_DETECT_NONE;
	/* post-T56 Task #8 T.38 fax UDPTL parity SS2 (2026-04-28): default
	 * T38FaxMaxDatagram override sentinel `-1` per chan_sip.c:29525 verbatim
	 * (`-1` = "use built-in 200-byte default"; chan_sip emits this when
	 * a=T38FaxMaxDatagram absent in peer SDP). Operator overrides via
	 * [general] t38_maxdatagram=N or per-peer t38pt_udptl=...,maxdatagram=N. */
	sofia_cfg.default_t38_maxdatagram = SOFIA_T38_MAXDATAGRAM_SENTINEL;
	/* post-T56 timerb [general] parity (2026-04-28): chan_sip parity default
	 * 32000ms per chan_sip.c:29522 verbatim global_timer_b = 64 * DEFAULT_TIMER_T1
	 * (DEFAULT_TIMER_T1 = 500ms; 64 * 500 = 32000ms). Wire-in via NTATAG_SIP_T1X64
	 * at nua_create — Pattern 16 sofia-sip-native 11th-instance. */
	sofia_cfg.default_timer_b = 32000;
	/* post-T56 timert1 [general] parity (2026-04-28): chan_sip parity default
	 * 500ms per chan_sip.c:29521 verbatim global_t1 = DEFAULT_TIMER_T1 + sip.h:89
	 * verbatim DEFAULT_TIMER_T1 = 500. Wire-in via NTATAG_SIP_T1(default_timer_t1)
	 * at nua_create — Pattern 16 sofia-sip-native 7th-instance REWIRED (latent
	 * bug fix from sofia_cfg.t1min 100ms → sofia_cfg.default_timer_t1 500ms). */
	sofia_cfg.default_timer_t1 = 500;
	/* post-T56 timert1 cross-validation flags (2026-04-28): clear at config-load
	 * start; set when respective [general] key parsed; consumed at sofia_load_
	 * config conclusion R5 cross-validation. */
	sofia_timerb_set = 0;
	sofia_timert1_set = 0;
	/* post-T56 allowoverlap [general] parity (2026-04-28): chan_sip parity default
	 * YES per chan_sip.c:29479 verbatim `ast_set_flag(&global_flags[1], SIP_PAGE2_
	 * ALLOWOVERLAP_YES);` with chan_sip trailing comment "Default for all devices: Yes". CRITICAL chan_sip
	 * drop-in: operators with NO explicit allowoverlap config get YES behavior —
	 * this is a behavior-change-from-chan_sofia-pre-baseline (chan_sofia previously
	 * had NO overlap-dial behavior at all). Wire-in active at 3 sites (sofia_
	 * process_invite + sofia_indicate AST_CONTROL_INCOMPLETE + nua_r_invite 484). */
	sofia_cfg.default_allowoverlap_mode = SOFIA_OVERLAP_YES;
	/* post-T56 subscribe_network_change_event [general] parity (2026-04-28): chan_sip
	 * parity default TRUE per chan_sip.c:29314 verbatim local-var default-init.
	 * PARSE-COMPAT-ONLY (chan_sofia delegates network-change handling to sofia-sip
	 * sres_resolver + per-peer dnsmgr per c0e26b0). */
	sofia_cfg.subscribe_network_change_event = 1;
	/* post-T56 rtsavesysname [general] parity (2026-04-28): chan_sip parity default
	 * FALSE per BSS static-zero. chan_sofia explicit-init = 0 disciplined pattern.
	 * Wire-in at 5 sofia_process_register ast_update_realtime callsites via inline
	 * 2-var setup; NULL-key pair no-op when flag clear. */
	sofia_cfg.rtsave_sysname = 0;
	/* post-T56 rtupdate [general] parity (2026-04-28): chan_sip parity default TRUE
	 * per chan_sip.c:29480 verbatim explicit default-init. Wire-in via Option C
	 * combined-gate at 3 sofia_process_register `if (peer->is_realtime)` blocks. */
	sofia_cfg.peer_rtupdate = 1;
	/* post-T56 rtcachefriends [general] parity (2026-04-28): chan_sip parity default
	 * FALSE per BSS static-zero of global_flags[1] SIP_PAGE2_RTCACHEFRIENDS bit.
	 * PARSE-COMPAT-ONLY (chan_sofia ao2 peer registry intrinsic-equivalent-to-yes
	 * baseline; flag has no behavioral effect — chan_sofia always caches all peers). */
	sofia_cfg.rtcachefriends = 0;
	/* post-T56 rtautoclear [general] parity (2026-04-28): chan_sip parity TWO defaults
	 * per chan_sip.c:29477 verbatim explicit default-init = 120 seconds + flag bit
	 * BSS static-zero of global_flags[1] SIP_PAGE2_RTAUTOCLEAR = 0 (DISABLED). PARSE-
	 * COMPAT-ONLY (chan_sofia ao2 registry no peer-level auto-clear infrastructure). */
	sofia_cfg.rtautoclear = 120;
	sofia_cfg.rtautoclear_enabled = 0;
	/* post-T56 domainsasrealm [general] parity (2026-04-28): chan_sip parity default
	 * FALSE per sip.h:205 verbatim DEFAULT_DOMAINSASREALM. FULL WIRE-IN — chan_sofia
	 * uses sofia_get_realm_for_dialog Pattern 5 helper #29 at 3 auth-challenge
	 * callsites (leverages existing domain_list infrastructure from T46.2 work). */
	sofia_cfg.domainsasrealm = 0;
	/* post-T56 allowexternaldomains [general] parity (2026-04-28): chan_sip parity
	 * default TRUE PERMISSIVE per sip.h:203 verbatim DEFAULT_ALLOW_EXT_DOM. Special-
	 * case auto-set logic post-config-load wired at end of sofia_load_config (mirror
	 * chan_sip.c:30056-30058 verbatim safety net). */
	sofia_cfg.allow_external_domains = 1;
	/* post-T56 autodomain [general] parity (2026-04-28): chan_sip parity default
	 * FALSE per chan_sip.c:29311 verbatim local-var default-init `int auto_sip_
	 * domains = FALSE;`. Auto-add wire-in fires at sofia_load_config conclusion
	 * AFTER allowexternaldomains 89ee266 special-case auto-set logic (gating order:
	 * allowexternaldomains first → autodomain auto-add second → both honored). */
	sofia_cfg.autodomain = 0;
	/* post-T56 matchexternaddrlocally [general] parity (2026-04-28): chan_sip parity
	 * default FALSE per sip.h:210 verbatim DEFAULT_MATCHEXTERNADDRLOCALLY. PARSE-
	 * COMPAT-ONLY (chan_sofia sofia_should_use_externaddr signature divergence;
	 * future-fix path documented in sample.conf). */
	sofia_cfg.matchexternaddrlocally = 0;
	/* post-T56 rtp-timeout bundle [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:721-723 verbatim 3 globals default 0 (disabled) chan_sip drop-in.
	 * Inherited by sofia_peer_alloc; sofia_rtp_init wires gabpbx-core APIs
	 * ast_rtp_instance_set_timeout/set_hold_timeout/set_keepalive when non-zero. */
	sofia_cfg.default_rtptimeout = 0;
	sofia_cfg.default_rtpholdtimeout = 0;
	sofia_cfg.default_rtpkeepalive = 0;
	/* post-T56 tos/cos bundle [general] parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:29427-29437 default-init 8 globals = 0 chan_sip drop-in (no QoS
	 * markings). RTP audio/video full wire-in via ast_rtp_instance_set_qos at
	 * sofia_rtp_init. tos_sip via TPTAG_TOS at nua_create (Pattern 16 9th-instance).
	 * cos_sip + tos_text + cos_text PARSE-COMPAT-ONLY (sofia-sip TPTAG_COS absent +
	 * chan_sofia text-RTP infrastructure absent). */
	sofia_cfg.tos_sip = 0;
	sofia_cfg.tos_audio = 0;
	sofia_cfg.tos_video = 0;
	sofia_cfg.tos_text = 0;
	sofia_cfg.cos_sip = 0;
	sofia_cfg.cos_audio = 0;
	sofia_cfg.cos_video = 0;
	sofia_cfg.cos_text = 0;
	sofia_cfg.srvlookup = 1;
	sofia_cfg.capability = 0;
	memset(&sofia_cfg.prefs, 0, sizeof(sofia_cfg.prefs));
	ast_free_ha(sofia_cfg.localha);
	sofia_cfg.localha = NULL;

	sofia_parse_general_config(cfg);

	for (cat = ast_category_browse(cfg, NULL); cat; cat = ast_category_browse(cfg, cat)) {
		if (!strcasecmp(cat, "general") || !strcasecmp(cat, "authentication")) {
			continue;
		}
		sofia_parse_peer_config(cat, cfg);
	}

	/* post-T56 timert1 [general] parity (2026-04-28, R5 cross-validation): mirror
	 * chan_sip.c:30038-30040 + L30043-30055 verbatim post-config-load nested
	 * cross-validation. Order matters — fires BEFORE nua_create reads sofia_cfg
	 * .default_timer_t1 + sofia_cfg.default_timer_b. */
	if (sofia_cfg.default_timer_t1 < sofia_cfg.t1min) {
		ast_log(LOG_WARNING, "Sofia: 't1min' (%d) cannot be greater than 'timert1' (%d). Resetting 'timert1' to the value of 't1min'\n",
			sofia_cfg.t1min, sofia_cfg.default_timer_t1);
		sofia_cfg.default_timer_t1 = sofia_cfg.t1min;
	}
	if (sofia_cfg.default_timer_b < sofia_cfg.default_timer_t1 * 64) {
		if (sofia_timerb_set && sofia_timert1_set) {
			ast_log(LOG_WARNING, "Sofia: Timer B has been set lower than recommended (%d < 64 * timert1=%d). (RFC 3261, 17.1.1.2)\n",
				sofia_cfg.default_timer_b, sofia_cfg.default_timer_t1);
		} else if (sofia_timerb_set) {
			sofia_cfg.default_timer_t1 = sofia_cfg.default_timer_b / 64;
			if (sofia_cfg.default_timer_t1 < sofia_cfg.t1min) {
				ast_log(LOG_WARNING, "Sofia: Timer B has been set lower than recommended (%d < 64 * timert1=%d). (RFC 3261, 17.1.1.2)\n",
					sofia_cfg.default_timer_b, sofia_cfg.default_timer_t1);
				sofia_cfg.default_timer_t1 = sofia_cfg.t1min;
				sofia_cfg.default_timer_b = sofia_cfg.default_timer_t1 * 64;
			}
		} else {
			sofia_cfg.default_timer_b = sofia_cfg.default_timer_t1 * 64;
		}
	}

	/* post-T56 autodomain [general] parity (2026-04-28): chan_sip parity
	 * comprehensive auto-add per chan_sip.c:30295-30340+ verbatim. When set,
	 * auto-add system listening-addresses + FQDN to domain_list at module-load
	 * conclusion. Mirror chan_sip 5+ auto-add types: bindaddr + tlsbindaddr +
	 * wsbindaddr + externaddr + gethostname() FQDN. Order matters — this fires
	 * BEFORE allowexternaldomains special-case auto-set so the gating logic
	 * sees the auto-added domains as "domain_list non-empty". */
	if (sofia_cfg.autodomain) {
		char temp[MAXHOSTNAMELEN];
		/* (1) bindaddr IP — Sofia primary listener (skip wildcard 0.0.0.0) */
		if (!ast_strlen_zero(sofia_cfg.bindaddr)
		    && strcmp(sofia_cfg.bindaddr, "0.0.0.0") != 0) {
			sofia_domain_list_add(sofia_cfg.bindaddr);
		}
		/* (2) TLS bindaddr IP if configured (T36 multi-transport) */
		if (!ast_strlen_zero(sofia_cfg.tlsbindaddr)
		    && strcmp(sofia_cfg.tlsbindaddr, "0.0.0.0") != 0) {
			sofia_domain_list_add(sofia_cfg.tlsbindaddr);
		}
		/* (3) WS bindaddr IP if configured (T36 WebSocket) */
		if (!ast_strlen_zero(sofia_cfg.wsbindaddr)
		    && strcmp(sofia_cfg.wsbindaddr, "0.0.0.0") != 0) {
			sofia_domain_list_add(sofia_cfg.wsbindaddr);
		}
		/* (4) externaddr IP if configured (NAT traversal) */
		if (!ast_strlen_zero(sofia_cfg.externaddr)) {
			sofia_domain_list_add(sofia_cfg.externaddr);
		}
		/* (5) gethostname() FQDN — system hostname (chan_sip parity at L30337+) */
		if (!gethostname(temp, sizeof(temp))) {
			sofia_domain_list_add(temp);
		}
	}

	/* post-T56 allowexternaldomains [general] parity (2026-04-28): chan_sip parity
	 * special-case auto-set per chan_sip.c:30056-30058 verbatim. When operator
	 * explicitly disables BUT no domain= entries configured → auto-revert to allow
	 * + LOG_WARNING (no point disabling external when no local domains defined;
	 * operator-friendly safety net mirroring chan_sip behavior). NOTE: autodomain
	 * auto-add fires BEFORE this gate so auto-added domains count toward
	 * domain_list non-empty check. */
	if (!sofia_cfg.allow_external_domains && AST_LIST_EMPTY(&domain_list)) {
		ast_log(LOG_WARNING, "Sofia: allowexternaldomains=no but no domain= entries configured; reverting to allow=yes\n");
		sofia_cfg.allow_external_domains = 1;
	}

	/* post-T56 allowsubscribe derive (2026-04-27): mirror chan_sip.c:29217-29218 —
	 * sip_cfg.allowsubscribe = TRUE if any peer flag-allows. Centralized sweep
	 * (chan_sofia ARCHITECTURAL ADVANTAGE 8th-instance vs chan_sip per-peer-build
	 * duplication). */
	sofia_post_config_derive_allowsubscribe();

	return 0;
}

/* Init-path wrapper: load sofia.conf from disk and hand it to
 * sofia_apply_config.  Only called from load_module() during module init.
 * The reload path goes through sofia_reload_request_sync /
 * sofia_reload_worker (defined alongside sofia_dispatch_to_root_thread).
 * The `reload` parameter is retained for back-compat with the existing
 * load_module call site but on a clean init it is always 0; passing 1
 * here would short-circuit on FILEUNCHANGED which is not the intent. */
static int sofia_load_config(int reload)
{
	struct ast_config *cfg;
	struct ast_flags config_flags = { reload ? CONFIG_FLAG_FILEUNCHANGED : 0 };
	int rc;

	cfg = ast_config_load(SOFIA_CONFIG, config_flags);
	if (!cfg || cfg == CONFIG_STATUS_FILEUNCHANGED) {
		return 0;
	}
	if (cfg == CONFIG_STATUS_FILEINVALID) {
		ast_log(LOG_ERROR, "Config file %s is invalid\n", SOFIA_CONFIG);
		return -1;
	}

	rc = sofia_apply_config(cfg);
	ast_config_destroy(cfg);
	return rc;
}

static void *sofia_reg_thread_func(void *data)
{
	while (sofia_nua) {
		struct ao2_iterator i;
		struct sofia_peer *peer;
		time_t now;

		/* post-T56 registertimeout parity (2026-04-27): chan_sip parity at
		 * chan_sip.c:14217 sleep-then-retry semantic — operator-tuned interval
		 * between scheduled register-retry passes. Default 20s per chan_sip
		 * DEFAULT_REGISTRATION_TIMEOUT; defensive lower-bound 1s in case bad
		 * config slipped past parser clamp. */
		sleep(sofia_cfg.register_timeout > 0 ? sofia_cfg.register_timeout : DEFAULT_REGISTRATION_TIMEOUT);

		if (!sofia_nua) {
			break;
		}

		now = time(NULL);
		i = ao2_iterator_init(peers, 0);
		while ((peer = ao2_iterator_next(&i))) {
			if (peer->nh && peer->reg_expiry > 0 &&
			    !ast_strlen_zero(peer->secret) &&
			    strcasecmp(peer->host, "dynamic") != 0 &&
			    /* post-T56 registerattempts parity (2026-04-27): chan_sip parity
			     * at chan_sip.c:14092 verbatim attempt-cap gate — skip when
			     * register_attempts > 0 AND peer has reached the cap. */
			    (sofia_cfg.register_attempts == 0 || peer->reg_attempts < sofia_cfg.register_attempts)) {
				ast_mutex_lock(&peer->lock);
				if (now >= peer->reg_expiry) {
					char uri[256];
					/* Step A IPv6 parity SS3 (2026-04-28): bracket-wrap IPv6 host */
					char hbuf[80];
					snprintf(uri, sizeof(uri), "sip:%s@%s:%d",
						peer->defaultuser,
						sofia_uri_format_host(peer->host, hbuf, sizeof(hbuf)),
						peer->port);
					if (sofia_debug)
						ast_verbose("Sofia: Re-registering %s\n", uri);
					/* post-T56 maxforwards parity (2026-04-27): RFC 3261 §20.22 outbound REGISTER refresh. */
					char mf_str_reregister[8];
					snprintf(mf_str_reregister, sizeof(mf_str_reregister), "%d", peer->maxforwards);
					/* post-T56 callbackextension per-peer parity (2026-04-28, Option A
					 * FULL WIRE-IN site 2/3 — qualify-cycle re-REGISTER): same
					 * NUTAG_M_USERNAME override as initial-register and auth-challenge
					 * sites for consistency. Pattern 16 sofia-sip-native 12th-instance. */
					nua_register(peer->nh,
						NUTAG_URL(uri),
						SIPTAG_FROM_STR(uri),
						SIPTAG_MAX_FORWARDS_STR(mf_str_reregister),
						TAG_IF(!ast_strlen_zero(peer->callbackextension),
							NUTAG_M_USERNAME(peer->callbackextension)),
						TAG_END());
					peer->reg_expiry = now + 60;
				}
				ast_mutex_unlock(&peer->lock);
			}
			ao2_ref(peer, -1);
		}
		ao2_iterator_destroy(&i);
	}
	return NULL;
}

static void sofia_do_register(void)
{
	struct ao2_iterator i;
	struct sofia_peer *peer;
	char uri[256];

	i = ao2_iterator_init(peers, 0);
	while ((peer = ao2_iterator_next(&i))) {
		if (peer->type == SOFIA_TYPE_FRIEND || peer->type == SOFIA_TYPE_PEER) {
			if (!ast_strlen_zero(peer->secret) &&
			    !ast_strlen_zero(peer->host) &&
			    strcasecmp(peer->host, "dynamic") != 0) {
				char route_buf[256];
				/* Step A IPv6 parity SS3 (2026-04-28): bracket-wrap IPv6 host */
				char hbuf[80];

				snprintf(uri, sizeof(uri), "sip:%s@%s:%d",
					peer->defaultuser,
					sofia_uri_format_host(peer->host, hbuf, sizeof(hbuf)),
					peer->port);

				/* T56.2 (2026-04-27): outbound REGISTER Route header from peer/[general]
				 * outboundproxy. Sticky-on-handle per R7. Re-register reuses the existing
				 * handle's route until the next destroy+recreate cycle (operator reload of
				 * outboundproxy mid-registration takes effect on next register-cycle). */
				sofia_format_outboundproxy(peer, route_buf, sizeof(route_buf));

				if (peer->nh) {
					nua_handle_destroy(peer->nh);
				}

				peer->nh = nua_handle(sofia_nua, peer,
					NUTAG_URL(uri),
					SIPTAG_TO_STR(uri),
					TAG_IF(route_buf[0], NUTAG_INITIAL_ROUTE_STR(route_buf)),
					TAG_END());

				/* post-T56 maxforwards parity (2026-04-27): RFC 3261 §20.22 outbound REGISTER. */
				char mf_str_initreg[8];
				snprintf(mf_str_initreg, sizeof(mf_str_initreg), "%d", peer->maxforwards);
				/* post-T56 callbackextension per-peer parity (2026-04-28, Option A
				 * FULL WIRE-IN site 3/3 — initial-REGISTER inside sofia_do_register):
				 * primary wire-in site driving Contact URL username at first-register
				 * time. Pattern 16 sofia-sip-native 12th-instance. */
				nua_register(peer->nh,
					NUTAG_URL(uri),
					SIPTAG_FROM_STR(uri),
					SIPTAG_MAX_FORWARDS_STR(mf_str_initreg),
					TAG_IF(!ast_strlen_zero(peer->callbackextension),
						NUTAG_M_USERNAME(peer->callbackextension)),
					TAG_END());

				if (sofia_debug) {
					ast_verbose("Sofia: Registering %s%s%s\n", uri,
						route_buf[0] ? " via " : "",
						route_buf[0] ? route_buf : "");
				}
			}
		}
		ao2_ref(peer, -1);
	}
	ao2_iterator_destroy(&i);
}

/* T47.3 (2026-04-27): cross-thread dispatch helper — post a callback to run on
 * sofia_thread (where sofia_root was created). AMI handlers run on a separate
 * manager thread; nua_handle ops MUST run on sofia_thread per the same-thread-as-
 * create contract (T40 lesson — sofia-sip's su_root_destroy + nua_handle ops
 * assert same-thread-as-create). The msg is allocated by su_msg_create + populated
 * + sent via su_msg_send; sofia_root's run loop picks it up and invokes
 * sofia_dispatch_handler which calls the user callback.
 *
 * Caller responsibility: data lifetime must outlast the dispatch (typical pattern:
 * heap-allocate, callback frees). NULL data is allowed if callback ignores it.
 *
 * Returns 0 on success, -1 on failure. Does NOT block — returns immediately after
 * queueing. Future callback runs asynchronously on sofia_thread. Reused by T47.3
 * SIPqualifypeer + T47.5 SIPnotify. */

struct sofia_dispatch_msg {
	void (*callback)(void *data);
	void *data;
};

static void sofia_dispatch_handler(su_root_magic_t *magic, su_msg_r msg, su_msg_arg_t *arg)
{
	struct sofia_dispatch_msg *m = (struct sofia_dispatch_msg *)arg;
	if (m && m->callback) {
		m->callback(m->data);
	}
}

static int sofia_dispatch_to_root_thread(void (*callback)(void *), void *data)
{
	su_msg_r msg = SU_MSG_R_INIT;
	struct sofia_dispatch_msg *m;

	if (!sofia_root || !callback) {
		return -1;
	}
	if (su_msg_create(msg, su_root_task(sofia_root), su_root_task(sofia_root),
			sofia_dispatch_handler, sizeof(*m)) < 0) {
		return -1;
	}
	m = (struct sofia_dispatch_msg *)su_msg_data(msg);
	if (!m) {
		su_msg_destroy(msg);
		return -1;
	}
	m->callback = callback;
	m->data = data;
	if (su_msg_send(msg) < 0) {
		return -1;
	}
	return 0;
}

/* =========================================================================
 *  Thread-safe `sip reload` infrastructure
 *
 *  The historical reload path called sofia_load_config(1) directly on the
 *  CLI / AMI / module-manager caller's thread, while sofia_thread (the NUA
 *  event loop) read sofia_cfg / peers / peer->fields concurrently from
 *  inbound SIP processing. That model had real UAF races (sofia_cfg.localha
 *  and sofia_cfg.contact_ha freed while sofia_thread iterated them;
 *  peer->chanvars destroyed without peer->lock while sofia_call iterated
 *  them) plus silent misconfigs (listener-baked fields like bindport were
 *  re-read into sofia_cfg but never re-applied to the live NUA listener).
 *
 *  The new design dispatches the reload work into sofia_thread via the
 *  existing sofia_dispatch_to_root_thread IPC. The reader becomes the
 *  writer; there is no concurrent access to sofia_cfg / peers because the
 *  single consumer of those (sofia_thread) is now blocked inside the
 *  worker. The CLI caller posts the request, blocks on a condvar with a
 *  30-second deadline, and reports the worker's verdict.
 *
 *  Listener-config changes (the 11 fields baked into nua_create at
 *  sofia_thread startup — bindaddr, bindport, tlsbindaddr, tlsbindport,
 *  tlscertfile, wsbindaddr, wsbindport, wssbindaddr, wssbindport,
 *  timert1, timerb) are pre-validated BEFORE any sofia_cfg mutation:
 *  sofia_reload_listener_changed reads them from the parsed config via
 *  ast_variable_retrieve and compares against the live sofia_cfg. Any
 *  diff aborts the reload with a clear error — silent recreation of the
 *  NUA listener would either lie (no effect on running sockets) or kill
 *  every active call and TLS connection.
 *
 *  Stale peers (present in the running container but removed from
 *  sofia.conf) are handled by mark-and-sweep inside the worker: every
 *  peer marked before re-parsing, unmarked as each [section] is parsed,
 *  swept (ao2_unlink + hint removal) at the end. Realtime peers are
 *  exempt because their lifecycle is per-lookup, not config-file driven.
 * ========================================================================= */

AST_MUTEX_DEFINE_STATIC(sofia_reload_lock);

/* Forward declaration of the apply-config helper that does the actual
 * defaults-reset + parse + cross-validate work. Extracted from
 * sofia_load_config so both the init path (load_module) and the reload
 * worker can share it. Defined alongside sofia_load_config below. */
static int sofia_apply_config(struct ast_config *cfg);

struct sofia_reload_req {
	ast_mutex_t mutex;
	ast_cond_t  cond;
	int         done;
	int         result;     /* 0 = OK, -1 = error */
	char       *errmsg;     /* points at caller's buffer; NULL = no buffer */
	size_t      errmsglen;
};

static void sofia_reload_req_destructor(void *obj)
{
	struct sofia_reload_req *req = obj;
	ast_cond_destroy(&req->cond);
	ast_mutex_destroy(&req->mutex);
}

/* Compare the 11 listener-baked fields in the freshly-parsed cfg against
 * the live sofia_cfg. Returns 1 if any differs (reload must be refused),
 * 0 if all match. Does NOT mutate sofia_cfg — reads the new values
 * straight from ast_variable_retrieve so the abort path is safe even if
 * the operator screwed up half the listener config.
 *
 * On change, fills `errmsg` with a comma-separated list of changed keys
 * so the operator can see exactly which knob requires the restart. */
static int sofia_reload_listener_changed(struct ast_config *cfg,
		char *errmsg, size_t errmsglen)
{
	struct {
		const char *key;
		const char *alt_key;        /* secondary key name (e.g. tlscertfile / tlscertdir) */
		int  is_string;
		void *current_value;        /* pointer into sofia_cfg */
		size_t string_size;         /* for string fields, size of the sofia_cfg buffer */
	} fields[] = {
		{ "bindaddr",      NULL,         1, sofia_cfg.bindaddr,     sizeof(sofia_cfg.bindaddr) },
		{ "bindport",      NULL,         0, &sofia_cfg.bindport,    0 },
		{ "tlsbindaddr",   NULL,         1, sofia_cfg.tlsbindaddr,  sizeof(sofia_cfg.tlsbindaddr) },
		{ "tlsbindport",   NULL,         0, &sofia_cfg.tlsbindport, 0 },
		{ "tlscertfile",   "tlscertdir", 1, sofia_cfg.tlscertfile,  sizeof(sofia_cfg.tlscertfile) },
		{ "wsbindaddr",    NULL,         1, sofia_cfg.wsbindaddr,   sizeof(sofia_cfg.wsbindaddr) },
		{ "wsbindport",    NULL,         0, &sofia_cfg.wsbindport,  0 },
		{ "wssbindaddr",   NULL,         1, sofia_cfg.wssbindaddr,  sizeof(sofia_cfg.wssbindaddr) },
		{ "wssbindport",   NULL,         0, &sofia_cfg.wssbindport, 0 },
		{ "timert1",       NULL,         0, &sofia_cfg.default_timer_t1, 0 },
		{ "timerb",        NULL,         0, &sofia_cfg.default_timer_b,  0 },
	};
	const size_t nfields = sizeof(fields) / sizeof(fields[0]);
	size_t i;
	char buf[256];
	int changed = 0;
	int written = 0;

	buf[0] = '\0';

	for (i = 0; i < nfields; i++) {
		const char *new_val = ast_variable_retrieve(cfg, "general", fields[i].key);
		if (!new_val && fields[i].alt_key) {
			new_val = ast_variable_retrieve(cfg, "general", fields[i].alt_key);
		}
		/* Absent key means the operator did not touch this knob — treat
		 * as "no change" rather than comparing to a synthetic zero/empty,
		 * which would false-alarm on every reload for keys whose runtime
		 * defaults are non-zero (timert1=500, timerb=32000, ...). */
		if (!new_val) {
			continue;
		}
		if (fields[i].is_string) {
			const char *cur = (const char *)fields[i].current_value;
			if (strcmp(cur, new_val) != 0) {
				changed = 1;
				if (written < (int)sizeof(buf) - 16) {
					written += snprintf(buf + written, sizeof(buf) - written,
						"%s%s", written ? "," : "", fields[i].key);
				}
			}
		} else {
			int cur_int = *((int *)fields[i].current_value);
			int new_int = atoi(new_val);
			if (cur_int != new_int) {
				changed = 1;
				if (written < (int)sizeof(buf) - 16) {
					written += snprintf(buf + written, sizeof(buf) - written,
						"%s%s", written ? "," : "", fields[i].key);
				}
			}
		}
	}

	if (changed && errmsg && errmsglen > 0) {
		snprintf(errmsg, errmsglen,
			"listener config changed (%s) — `systemctl restart gabpbx` required",
			buf);
	}
	return changed;
}

/* Mark-and-sweep callbacks for reloading the peers container.  Marking is
 * an O(N) ao2 walk that sets a transient flag on every peer.  The peer
 * re-parse path (sofia_parse_peer_config) clears the flag for every peer
 * that survived the new config.  Sweep then ao2_unlinks the still-marked
 * (= disappeared) non-realtime peers.  Realtime peers are skipped because
 * their lifecycle is per-lookup, not file-driven. */
static int sofia_peer_mark_cb(void *obj, void *arg, int flags)
{
	struct sofia_peer *peer = obj;
	peer->_reload_marked = 1;
	return 0;
}

static int sofia_peer_sweep_cb(void *obj, void *arg, int flags)
{
	struct sofia_peer *peer = obj;
	if (!peer->_reload_marked || peer->is_realtime) {
		return 0;
	}
	/* Drop the dialplan hint extension this peer created, if any.  The
	 * registrar string here matches what sofia_create_peer_hint passed
	 * (chan_sofia.c sofia_create_peer_hint) so we remove only the
	 * extension we own. */
	if (!ast_strlen_zero(peer->subscribecontext) && !ast_strlen_zero(peer->regexten)) {
		ast_context_remove_extension(peer->subscribecontext,
			peer->regexten, PRIORITY_HINT, "sofia_config_peer");
	}
	/* Release the dnsmgr entry FIRST, and drop the ao2 ref that
	 * sofia_dnsmgr_setup_peer bumped at chan_sofia.c:4642 for callback
	 * safety.  The destructor would otherwise never run: dnsmgr's held
	 * ref would keep refcount >= 1 even after ao2_unlink drops the
	 * container's ref.  Pattern documented at the destructor comment
	 * (chan_sofia.c:4537-4538: "explicit reload-sweep does
	 * ast_dnsmgr_release THEN ao2_ref(-1) BEFORE refcount drops to 0").
	 * ast_dnsmgr_release is synchronous — waits for in-flight callbacks
	 * to complete with the peer pointer before returning, so no UAF
	 * window when ao2_unlink runs next. */
	if (peer->dnsmgr) {
		ast_dnsmgr_release(peer->dnsmgr);
		peer->dnsmgr = NULL;
		ao2_ref(peer, -1);
	}
	/* Destroy the outbound REGISTER handle and the qualify OPTIONS
	 * handle synchronously HERE — the sweep callback runs on
	 * sofia_thread (invoked by the reload worker which is itself
	 * dispatched into sofia_thread), so nua_handle_destroy's same-
	 * thread-as-create constraint is satisfied without needing a
	 * dispatch.  Closing the handles before ao2_unlink also detaches
	 * sofia-sip's hmagic backpointer to this peer struct, so no later
	 * event can deliver into an event_callback that would dereference
	 * a freed peer.  The destructor's defensive dispatch branches then
	 * see NULL and skip. */
	if (peer->nh) {
		nua_handle_destroy(peer->nh);
		peer->nh = NULL;
	}
	if (peer->qualify_nh) {
		nua_handle_destroy(peer->qualify_nh);
		peer->qualify_nh = NULL;
	}
	ast_log(LOG_NOTICE, "Sofia: peer '%s' removed by reload sweep "
		"(no longer present in sofia.conf)\n", peer->name);
	/* CMP_MATCH tells ao2_callback to ao2_unlink this entry.  The
	 * sofia_peer_destructor runs on the final ao2 ref drop (now reachable
	 * because dnsmgr's ref was just released above) and frees contactha,
	 * ha, directmediaha, contacts container, chanvars, mailboxes, etc. */
	return CMP_MATCH;
}

/* Forward declaration for the worker.  Body defined alongside the
 * sync-invoker further down. */
static void sofia_reload_worker(void *data);

/* Synchronous reload invoker — called from CLI / AMI / .reload hook.
 * Posts the request into sofia_thread's event queue via
 * sofia_dispatch_to_root_thread, then blocks on a condvar (with a
 * 30-second deadline) until the worker signals completion.  Returns 0
 * on success or -1 on failure (the worker fills errmsg with the
 * specific reason).
 *
 * Refcount discipline: the request struct is ao2_alloc'd with initial
 * refcount 1 (caller's).  Before dispatch we ao2_ref(req,+1) for the
 * worker.  On dispatch failure we drop both refs.  After cond_timedwait
 * returns (whether by signal or timeout), the caller drops its ref.
 * The worker drops its ref at the very end of its body.  Whichever
 * runs last frees the struct via the destructor — safe under timeout
 * because cond/mutex live inside the ref-protected struct. */
static int sofia_reload_request_sync(char *errmsg, size_t errmsglen, int timeout_ms)
{
	struct sofia_reload_req *req;
	struct timespec deadline;
	int result;
	int dispatched;

	if (errmsg && errmsglen > 0) {
		errmsg[0] = '\0';
	}

	if (ast_mutex_trylock(&sofia_reload_lock) != 0) {
		if (errmsg && errmsglen > 0) {
			snprintf(errmsg, errmsglen, "another reload is in progress");
		}
		return -1;
	}

	req = ao2_alloc(sizeof(*req), sofia_reload_req_destructor);
	if (!req) {
		if (errmsg && errmsglen > 0) {
			snprintf(errmsg, errmsglen, "out of memory");
		}
		ast_mutex_unlock(&sofia_reload_lock);
		return -1;
	}
	ast_mutex_init(&req->mutex);
	ast_cond_init(&req->cond, NULL);
	req->done = 0;
	req->result = -1;
	req->errmsg = errmsg;
	req->errmsglen = errmsglen;

	ao2_ref(req, +1);   /* worker's ref */

	dispatched = sofia_dispatch_to_root_thread(sofia_reload_worker, req);
	if (dispatched != 0) {
		if (errmsg && errmsglen > 0) {
			snprintf(errmsg, errmsglen, "failed to dispatch reload to sofia_thread");
		}
		ao2_ref(req, -1);  /* drop worker's ref — worker won't run */
		ao2_ref(req, -1);  /* drop caller's ref */
		ast_mutex_unlock(&sofia_reload_lock);
		return -1;
	}

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec  += timeout_ms / 1000;
	deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
	if (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000L;
	}

	ast_mutex_lock(&req->mutex);
	while (!req->done) {
		int rc = ast_cond_timedwait(&req->cond, &req->mutex, &deadline);
		if (rc == ETIMEDOUT) {
			if (errmsg && errmsglen > 0 && errmsg[0] == '\0') {
				snprintf(errmsg, errmsglen,
					"reload timed out after %d ms (sofia_thread busy)", timeout_ms);
			}
			break;
		}
	}
	result = req->done ? req->result : -1;
	ast_mutex_unlock(&req->mutex);

	ao2_ref(req, -1);  /* drop caller's ref; worker drops its own when it runs */
	ast_mutex_unlock(&sofia_reload_lock);
	return result;
}

/* The actual reload work — runs on sofia_thread.  Because sofia_thread is
 * the SINGLE consumer of sofia_cfg / peers / peer->fields during normal
 * SIP event dispatch, and that thread is now blocked inside this function
 * for the duration of the reload, there is no concurrent reader.  ast_ha
 * lists can be freed safely; sofia_cfg fields can be overwritten in-place.
 * Per-peer mutations still take peer->lock as a defence against the
 * auxiliary threads (sofia_sched / sofia_reg_thread / sofia_qualify_tid)
 * that legitimately read peer state from outside sofia_thread. */
static void sofia_reload_worker(void *data)
{
	struct sofia_reload_req *req = data;
	struct ast_config *cfg;
	struct ast_flags config_flags = { 0 };
	int result = -1;
	char local_errmsg[256] = "";

	cfg = ast_config_load(SOFIA_CONFIG, config_flags);
	if (!cfg) {
		snprintf(local_errmsg, sizeof(local_errmsg),
			"sofia.conf could not be loaded");
		goto signal_done;
	}
	if (cfg == CONFIG_STATUS_FILEINVALID) {
		snprintf(local_errmsg, sizeof(local_errmsg),
			"sofia.conf is invalid (parse error)");
		goto signal_done;
	}

	if (sofia_reload_listener_changed(cfg, local_errmsg, sizeof(local_errmsg))) {
		ast_config_destroy(cfg);
		goto signal_done;
	}

	/* Mark every existing peer.  Surviving peers will clear their mark in
	 * sofia_parse_peer_config; remaining marked peers get swept below. */
	ao2_callback(peers, OBJ_NODATA, sofia_peer_mark_cb, NULL);

	if (sofia_apply_config(cfg) < 0) {
		/* sofia_apply_config already logged the specifics.  Don't sweep —
		 * the peer state may be partially populated, sweeping could remove
		 * live peers that the partial parse didn't get to. */
		snprintf(local_errmsg, sizeof(local_errmsg),
			"sofia_apply_config failed — see log; no peers swept");
		ast_config_destroy(cfg);
		goto signal_done;
	}

	/* Sweep peers that disappeared from sofia.conf. */
	ao2_callback(peers, OBJ_NODATA | OBJ_UNLINK | OBJ_MULTIPLE,
		sofia_peer_sweep_cb, NULL);

	ast_config_destroy(cfg);
	result = 0;

signal_done:
	ast_mutex_lock(&req->mutex);
	req->done = 1;
	req->result = result;
	if (req->errmsg && req->errmsglen > 0 && local_errmsg[0] != '\0') {
		ast_copy_string(req->errmsg, local_errmsg, req->errmsglen);
	}
	ast_cond_signal(&req->cond);
	ast_mutex_unlock(&req->mutex);
	ao2_ref(req, -1);   /* drop worker's ref */
}

/* T47.1 (2026-04-27): AMI Action: SIPpeers — list every peer (one PeerEntry per
 * peer, plus a final PeerlistComplete with ListItems count). chan_sip parity
 * (chan_sip.c:17701 manager_sip_show_peers + chan_sip.c:17984 PeerEntry format).
 * Filters out is_register_line==1 entries (those are outbound-register peers
 * surfaced via SIPshowregistry instead). */
static int manager_sofia_show_peers(struct mansession *s, const struct message *m)
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
			peer->name,
			tmp_host,
			tmp_port,
			!strcasecmp(peer->host, "dynamic") ? "yes" : "no",
			(peer->nat & SOFIA_NAT_FORCE_RPORT) ? "yes" : "no",
			(peer->capability & AST_FORMAT_VIDEO_MASK) ? "yes" : "no",
			peer->ha ? "yes" : "no",
			status,
			peer->is_realtime ? "yes" : "no");

		ast_mutex_unlock(&peer->lock);
		ao2_ref(peer, -1);
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
static int manager_sofia_show_peer(struct mansession *s, const struct message *m)
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

	astman_append(s, "Response: Success\r\n%s", idText);
	astman_append(s, "Channeltype: SIP\r\n");
	astman_append(s, "ObjectName: %s\r\n", peer->name);
	astman_append(s, "ChanObjectType: peer\r\n");
	astman_append(s, "SecretExist: %s\r\n", ast_strlen_zero(peer->secret) ? "N" : "Y");
	astman_append(s, "RemoteSecretExist: N\r\n");
	astman_append(s, "MD5SecretExist: N\r\n");
	astman_append(s, "Context: %s\r\n", peer->context);
	astman_append(s, "Language: \r\n");
	astman_append(s, "AMAflags: Unknown\r\n");
	astman_append(s, "CID-CallingPres: Allowed, Not Screened\r\n");
	if (!ast_strlen_zero(peer->fromuser)) {
		astman_append(s, "SIP-FromUser: %s\r\n", peer->fromuser);
	}
	if (!ast_strlen_zero(peer->fromdomain)) {
		astman_append(s, "SIP-FromDomain: %s\r\n", peer->fromdomain);
	}
	/* post-T56 Task #2 D-3 SS1 (2026-04-28, GAP-4 fix + chan_sofia surpass —
	 * chan_sip baseline emits Transport but lacks WS/WSS; chan_sofia includes
	 * full set udp/tcp/tls/ws/wss). AMI Transport field per chan_sip-equivalent
	 * convention; mirrors sip show peer Transport ternary at chan_sofia.c
	 * :11062-11066. Operator NMS / monitoring systems can correlate per-peer
	 * transport for alerting (e.g., expected WSS browser-UA peer arrives via
	 * different transport → anomaly). */
	astman_append(s, "Transport: %s\r\n",
		peer->transport == SOFIA_TRANSPORT_TCP ? "tcp" :
		peer->transport == SOFIA_TRANSPORT_TLS ? "tls" :
		peer->transport == SOFIA_TRANSPORT_WS  ? "ws"  :
		peer->transport == SOFIA_TRANSPORT_WSS ? "wss" : "udp");
	astman_append(s, "Callgroup: %s\r\n",
		ast_print_group(group_buf, sizeof(group_buf), peer->callgroup));
	astman_append(s, "Pickupgroup: %s\r\n",
		ast_print_group(group_buf, sizeof(group_buf), peer->pickupgroup));
	/* post-T56 MOH per-peer parity (2026-04-27): MOHInterpret + MOHSuggest
	 * AMI fields. chan_sip parity at chan_sip.c:18784 string format verbatim.
	 * In-flight Pattern 6 implicit-empty stub fix: existing MOHSuggest line
	 * emitted hardcoded empty string regardless of peer config (parsed-but-
	 * never-read-from-correct-source variant). Both fields now emit peer's
	 * actual value. */
	astman_append(s, "MOHInterpret: %s\r\n",
		ast_strlen_zero(peer->mohinterpret) ? "" : peer->mohinterpret);
	astman_append(s, "MOHSuggest: %s\r\n",
		ast_strlen_zero(peer->mohsuggest) ? "" : peer->mohsuggest);
	astman_append(s, "VoiceMailbox: \r\n");
	/* post-T56 accountcode per-peer parity (2026-04-27): chan_sip-parity AMI field
	 * gated on !ast_strlen_zero per chan_sip.c:18772-18773. */
	if (!ast_strlen_zero(peer->accountcode)) {
		astman_append(s, "Accountcode: %s\r\n", peer->accountcode);
	}
	/* post-T56 allowtransfer per-peer parity (2026-04-27): in-flight stub fix —
	 * pre-existing hardcoded "open" emitted regardless of peer config (Pattern 1
	 * stored-but-never-read variant; ADDENDUM #4 SS6 8-in-flight-catches-pattern).
	 * Now reflects peer->allowtransfer; chan_sip parity at chan_sip.c:18787 verbatim. */
	astman_append(s, "TransferMode: %s\r\n", sofia_transfer_mode_str(peer->allowtransfer));
	/* post-T56 allowsubscribe per-peer parity (2026-04-27): chan_sip parity field
	 * (chan_sip flag SIP_PAGE2_ALLOWSUBSCRIBE → operator-visible yes/no). REQUEST-EVENT
	 * GATING dimension #6 sibling to TransferMode. */
	astman_append(s, "AllowSubscribe: %s\r\n", peer->allowsubscribe ? "yes" : "no");
	/* post-T56 buggymwi per-peer parity (2026-04-27): chan_sip parity field
	 * (chan_sip flag SIP_PAGE2_BUGGY_MWI → operator-visible yes/no for verifying
	 * Cisco-buggy-stack workaround applied per-peer). */
	astman_append(s, "BuggyMWI: %s\r\n", peer->buggymwi ? "yes" : "no");
	/* post-T56 lockuseragent per-peer parity (2026-04-27): chan_sip parity Lockuseragent
	 * field (yes/no) + chan_sofia surpass LockedUserAgent display field (current
	 * locked UA string for compliance audit / UA-spoofing investigation). */
	astman_append(s, "Lockuseragent: %s\r\n", peer->lockuseragent ? "yes" : "no");
	astman_append(s, "LockedUserAgent: %s\r\n", peer->locked_user_agent);
	astman_append(s, "LockUserAgentPrefixes: %s\r\n", S_OR(peer->lockuseragent_prefixes, ""));
	/* post-T56 language per-peer parity (2026-04-27): per-peer audio-locale field. */
	astman_append(s, "Language: %s\r\n", peer->language);
	/* post-T56 defaultip per-peer parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:18820 verbatim Default-addr-IP + Default-addr-port fields. */
	astman_append(s, "Default-addr-IP: %s\r\nDefault-addr-port: %d\r\n",
		ast_sockaddr_stringify_addr(&peer->defaddr),
		ast_sockaddr_port(&peer->defaddr));
	/* post-T56 maxcallbitrate per-peer parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:18792 verbatim "MaxCallBR: %d kbps" field. */
	astman_append(s, "MaxCallBR: %d kbps\r\n", peer->maxcallbitrate);
	/* post-T56 amaflags per-peer parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:18774 verbatim "AMAflags: %s" via ast_cdr_flags2str. */
	astman_append(s, "AMAflags: %s\r\n", ast_cdr_flags2str(peer->amaflags));
	/* post-T56 subscribemwi per-peer parity (2026-04-28): chan_sip parity field
	 * (sip.h:324 SIP_PAGE2_SUBSCRIBEMWIONLY → operator-visible yes/no). */
	astman_append(s, "SubscribeMWI: %s\r\n", peer->subscribemwi ? "yes" : "no");
	/* post-T56 preferred_codec_only per-peer parity (2026-04-28): chan_sip parity field
	 * (sip.h:313 SIP_PAGE2_PREFERRED_CODEC → operator-visible yes/no). */
	astman_append(s, "PreferredCodec: %s\r\n", peer->preferred_codec_only ? "yes" : "no");
	/* post-T56 ignoresdpversion per-peer parity (2026-04-28): chan_sip parity field
	 * (sip.h:325 SIP_PAGE2_IGNORESDPVERSION → operator-visible yes/no). PARSE-COMPAT-
	 * ONLY (chan_sofia processes every SDP unconditionally). */
	astman_append(s, "IgnoreSDPVersion: %s\r\n", peer->ignoresdpversion ? "yes" : "no");
	/* post-T56 promiscredir per-peer parity (2026-04-28): chan_sip-parity AMI field
	 * "SIP-PromiscRedir" per chan_sip.c:18801 verbatim Y/N format. PARSE-COMPAT-ONLY. */
	astman_append(s, "SIP-PromiscRedir: %s\r\n", peer->promiscredir ? "Y" : "N");
	/* post-T56 autoframing per-peer parity (2026-04-28): chan_sip-parity AMI field
	 * "Autoframing" yes/no format. PARSE-COMPAT-ONLY (sofia_parse_sdp ptime gate
	 * not wired today). */
	astman_append(s, "Autoframing: %s\r\n", peer->autoframing ? "yes" : "no");
	/* faxdetect per-peer AMI field: reports the runtime mode used by DSP CNG
	 * detection and peer T.38 reINVITE detection. */
	astman_append(s, "FaxDetect: %s\r\n",
		peer->faxdetect_mode == SOFIA_FAX_DETECT_NONE ? "no" :
		peer->faxdetect_mode == SOFIA_FAX_DETECT_BOTH ? "cng,t38" :
		peer->faxdetect_mode == SOFIA_FAX_DETECT_CNG ? "cng" : "t38");
	/* post-T56 timerb per-peer parity (2026-04-28): chan_sip-parity AMI field
	 * "Timer-B: %d ms" — operator-visible RFC 3261 Timer B value. */
	astman_append(s, "Timer-B: %d\r\n", peer->timer_b);
	/* post-T56 timert1 per-peer parity (2026-04-28): chan_sip-parity AMI field
	 * "Timer-T1: %d ms" — operator-visible RFC 3261 §17.1.1.1 T1 retransmission
	 * interval value. Pattern 16 sofia-sip-native 7th-instance REWIRED. */
	astman_append(s, "Timer-T1: %d\r\n", peer->timer_t1);
	/* post-T56 allowoverlap per-peer + [general] parity (2026-04-28, Option A
	 * FULL WIRE-IN + chan_sofia surpass — chan_sip AMI silent verified ABSENT
	 * via grep): operator-visible RFC 3261 §3 overlap-dial mode tri-state. */
	astman_append(s, "OverlapDial: %s\r\n", sofia_allowoverlap_str(peer->allowoverlap_mode));
	/* post-T56 progressinband per-peer parity (2026-04-28): chan_sip parity tri-state
	 * field (sip.h:282-285 SIP_PROG_INBAND_NEVER/NO/YES → operator-visible never/no/yes).
	 * Option B partial wire-in (NEVER + YES exact; NO degrades to NEVER). */
	astman_append(s, "ProgressInband: %s\r\n",
		peer->progressinband == SOFIA_PROG_INBAND_NEVER ? "never" :
		peer->progressinband == SOFIA_PROG_INBAND_YES ? "yes" : "no");
	/* post-T56 rtp-timeout bundle per-peer parity (2026-04-28): 3 fields chan_sip parity. */
	astman_append(s, "RTPTimeout: %d\r\n", peer->rtptimeout);
	astman_append(s, "RTPHoldTimeout: %d\r\n", peer->rtpholdtimeout);
	astman_append(s, "RTPKeepalive: %d\r\n", peer->rtpkeepalive);
	/* post-T56 parkinglot per-peer parity (2026-04-28): chan_sip parity at
	 * chan_sip.c:18849 verbatim "Parkinglot: %s" field. */
	astman_append(s, "Parkinglot: %s\r\n", peer->parkinglot);
	astman_append(s, "LastMsgsSent: 0\r\n");
	/* post-T56 maxforwards parity (2026-04-27): in-flight Pattern 1 stub-fix #13 —
	 * pre-existing hardcoded "Maxforwards: 0" emitted regardless of peer config
	 * (stored-but-never-read variant; ADDENDUM #4 SS6 8-in-flight-catches-pattern
	 * advances to 13/13 1-day peak). Now reflects peer->maxforwards; chan_sip
	 * parity at chan_sip.c:18789 verbatim. */
	astman_append(s, "Maxforwards: %d\r\n", peer->maxforwards);
	/* post-T56 call-limit parity SS6 R8 (2026-04-27): chan_sip-parity field
	 * values for Call-limit + Busy-level + InUse/InRinging/OnHold. Fixed
	 * pre-existing stubs that emitted busy_on_active as Call-limit and
	 * hardcoded 0 as Busy-level. Always-emit (no zero-gate) per chan_sip
	 * L18790-18791 — operator AMI scripts get consistent field set. */
	astman_append(s, "Call-limit: %d\r\n", peer->call_limit);
	astman_append(s, "Busy-level: %d\r\n", peer->busy_level);
	astman_append(s, "InUse: %d\r\n", peer->inUse);
	astman_append(s, "InRinging: %d\r\n", peer->inRinging);
	astman_append(s, "OnHold: %d\r\n", peer->onHold);
	astman_append(s, "MaxCallBR: 384 kbps\r\n");
	astman_append(s, "Dynamic: %s\r\n", !strcasecmp(peer->host, "dynamic") ? "Y" : "N");
	/* post-T56 cid bundle parity (2026-04-28): chan_sip-parity Callerid AMI field
	 * via ast_callerid_merge per chan_sip.c:18794 verbatim format; reflects
	 * cid_name + cid_num set via callerid/fullname/cid_number/cid_name keys.
	 * Falls back to legacy peer->callerid when both new fields empty. */
	if (!ast_strlen_zero(peer->cid_num) || !ast_strlen_zero(peer->cid_name)) {
		char merged[256];
		ast_callerid_merge(merged, sizeof(merged),
			S_OR(peer->cid_name, ""), S_OR(peer->cid_num, ""), "<unknown>");
		astman_append(s, "Callerid: %s\r\n", merged);
	} else {
		astman_append(s, "Callerid: %s\r\n", peer->callerid);
	}
	if (!ast_strlen_zero(peer->cid_tag)) {
		astman_append(s, "CIDtag: %s\r\n", peer->cid_tag);
	}
	astman_append(s, "RegExpire: %ld seconds\r\n", reg_secs);
	astman_append(s, "SIP-AuthInsecure: %s\r\n", insecure);
	astman_append(s, "SIP-Forcerport: %s\r\n", (peer->nat & SOFIA_NAT_FORCE_RPORT) ? "Y" : "N");
	astman_append(s, "SIP-Comedia: %s\r\n", (peer->nat & SOFIA_NAT_COMEDIA) ? "Y" : "N");
	astman_append(s, "ACL: %s\r\n", peer->ha ? "Y" : "N");
	/* post-T56 contactpermit/contactdeny per-peer parity (2026-04-27): chan_sip
	 * parity AMI field. */
	astman_append(s, "ContactACL: %s\r\n", peer->contactha ? "Y" : "N");
	/* post-T56 directmediapermit/directmediadeny per-peer parity (2026-04-27): chan_sip
	 * parity AMI field at chan_sip.c:18676 "DirectMedACL" wording. */
	astman_append(s, "DirectMedACL: %s\r\n", peer->directmediaha ? "Y" : "N");
	/* post-T56 dnsmgr per-peer parity (2026-04-27): chan_sip parity AMI field. */
	astman_append(s, "DnsMgr: %s\r\n", peer->dnsmgr ? "Y" : "N");
	astman_append(s, "SIP-CanReinvite: %s\r\n", peer->directmedia ? "Y" : "N");
	astman_append(s, "SIP-DirectMedia: %s\r\n", peer->directmedia ? "Y" : "N");
	astman_append(s, "SIP-PromiscRedir: N\r\n");
	/* post-T56 usereqphone parity (2026-04-27): in-flight Pattern 1 stub-fix —
	 * pre-existing hardcoded "N" emitted regardless of peer config (stored-but-
	 * never-read variant; ADDENDUM #4 SS6 8-in-flight-catches-pattern continues
	 * to 11th instance in 1 day's work). Now reflects peer->usereqphone; chan_sip
	 * parity at chan_sip.c:18802 verbatim. */
	astman_append(s, "SIP-UserPhone: %s\r\n", peer->usereqphone ? "Y" : "N");
	astman_append(s, "SIP-VideoSupport: %s\r\n", (peer->capability & AST_FORMAT_VIDEO_MASK) ? "Y" : "N");
	astman_append(s, "SIP-TextSupport: N\r\n");
	astman_append(s, "SIP-T.38Support: N\r\n");
	astman_append(s, "SIP-T.38EC: None\r\n");
	astman_append(s, "SIP-T.38MaxDtgrm: 0\r\n");
	astman_append(s, "SIP-Sess-Timers: Refuse\r\n");
	astman_append(s, "SIP-Sess-Refresh: uas\r\n");
	astman_append(s, "SIP-Sess-Expires: 1800\r\n");
	astman_append(s, "SIP-Sess-Min: 90\r\n");
	astman_append(s, "SIP-RTP-Engine: gabpbx\r\n");
	astman_append(s, "SIP-Encryption: %s\r\n", peer->encryption ? "Y" : "N");
	/* post-T56 srtpcipher operator option (2026-04-27): SRTPCipher field for AMI SIPshowpeer. */
	astman_append(s, "SRTPCipher: %s\r\n", S_OR(peer->srtpcipher, ""));
	/* post-T56 session timers (RFC 4028) (2026-04-27): 4 chan_sip-parity AMI fields. */
	{
		const char *st_mode_str =
			(peer->session_timers == SESSION_TIMERS_ORIGINATE) ? "originate" :
			(peer->session_timers == SESSION_TIMERS_REFUSE)    ? "refuse"    :
			(peer->session_timers == SESSION_TIMERS_ACCEPT)    ? "accept"    : "off";
		const char *st_refresher_str =
			(peer->session_refresher == SESSION_REFRESHER_UAC) ? "uac" :
			(peer->session_refresher == SESSION_REFRESHER_UAS) ? "uas" : "auto";
		astman_append(s, "SessionTimers: %s\r\n", st_mode_str);
		astman_append(s, "SessionExpires: %d\r\n", peer->session_expires);
		astman_append(s, "SessionMinSE: %d\r\n", peer->session_minse);
		astman_append(s, "SessionRefresher: %s\r\n", st_refresher_str);
	}
	astman_append(s, "SIP-DTMFmode: %s\r\n", dtmfmode);
	astman_append(s, "ToHost: %s\r\n", peer->host);
	astman_append(s, "Address-IP: %s\r\nAddress-Port: %s\r\n", tmp_host, tmp_port);
	astman_append(s, "Default-Username: %s\r\n", peer->defaultuser);
	/* post-T56 regexten display-gate parity (2026-04-27): chan_sip.c:18822 gates
	 * AMI RegExtension field on !ast_strlen_zero(sip_cfg.regcontext) — only
	 * emitted when the auto-extension mechanism is active. */
	if (!ast_strlen_zero(sofia_cfg.regcontext) && !ast_strlen_zero(peer->regexten)) {
		astman_append(s, "RegExtension: %s\r\n", peer->regexten);
	}
	/* post-T56 callbackextension per-peer parity (2026-04-28, Option A FULL WIRE-IN
	 * + chan_sofia surpass over chan_sip AMI silent — chan_sip never exposes
	 * callbackextension in any AMI action): conditional emit only when set. */
	if (!ast_strlen_zero(peer->callbackextension)) {
		astman_append(s, "CallbackExtension: %s\r\n", peer->callbackextension);
	}
	/* post-T56 setvar+header per-peer parity (2026-04-28, COMBINED ship): AMI
	 * ChanVariable iteration per chan_sip.c:18850-18854 verbatim format. Includes
	 * both setvar= and header= entries. */
	if (peer->chanvars) {
		struct ast_variable *var;
		for (var = peer->chanvars; var; var = var->next) {
			astman_append(s, "ChanVariable: %s=%s\r\n", var->name, var->value);
		}
	}
	ast_getformatname_multiple(codec_buf, sizeof(codec_buf) - 1, peer->capability);
	astman_append(s, "Codecs: %s\r\n", codec_buf);
	/* CodecOrder — walk peer->prefs in priority order */
	{
		int x;
		format_t codec;
		astman_append(s, "CodecOrder: ");
		for (x = 0; x < 64; x++) {
			codec = ast_codec_pref_index(&peer->prefs, x);
			if (!codec) {
				break;
			}
			astman_append(s, "%s%s", x ? "," : "", ast_getformatname(codec));
		}
		astman_append(s, "\r\n");
	}
	astman_append(s, "Status: %s\r\n", status);
	astman_append(s, "SIP-Useragent: %s\r\n", contact ? S_OR(contact->user_agent, "") : "");
	astman_append(s, "Reg-Contact: %s\r\n", contact ? S_OR(contact->contact_uri, "") : "");
	astman_append(s, "QualifyFreq: %d ms\r\n", peer->qualifyfreq);
	astman_append(s, "Parkinglot: \r\n");
	/* chan_sofia-only fields (T21/T22/T37) */
	astman_append(s, "BusyOnActive: %s\r\n", peer->busy_on_active ? "Y" : "N");
	astman_append(s, "MaxContacts: %d\r\n", peer->max_contacts);
	astman_append(s, "QualifyTimeout: %d\r\n", peer->qualifytimeout);
	astman_append(s, "LastMs: %d\r\n", peer->lastms);
	astman_append(s, "RealtimeDevice: %s\r\n", peer->is_realtime ? "yes" : "no");
	astman_append(s, "\r\n");

	if (contact) {
		ao2_ref(contact, -1);
	}
	ast_mutex_unlock(&peer->lock);
	ao2_ref(peer, -1);
	return 0;
}

/* T47.3 (2026-04-27): AMI Action: SIPqualifypeer — trigger immediate qualify probe
 * on a peer. chan_sip parity (chan_sip.c:18513 manager_sip_qualify_peer +
 * sip_poke_peer). chan_sofia variant DISPATCHES the qualify call to sofia_thread
 * via sofia_dispatch_to_root_thread because manager handlers run on a separate
 * thread + sofia_qualify_peer creates a nua_handle (would hit the T40 same-
 * thread-as-create assert if called directly from manager thread). */

struct sipqualifypeer_data {
	struct sofia_peer *peer;	/* +1 ref TRANSFERRED to callback (caller doesn't drop) */
};

static void sipqualifypeer_callback(void *data)
{
	struct sipqualifypeer_data *d = data;
	if (d) {
		if (d->peer) {
			sofia_qualify_peer(d->peer);
			ao2_ref(d->peer, -1);
		}
		ast_free(d);
	}
}

static int manager_sofia_qualify_peer(struct mansession *s, const struct message *m)
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
static int manager_sofia_show_registry(struct mansession *s, const struct message *m)
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
		ast_mutex_lock(&peer->lock);
		if (peer->is_register_line) {
			long refresh_secs = peer->reg_expiry > now ? (long)(peer->reg_expiry - now) : 0;
			int port = peer->port ? peer->port : 5060;
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
				idText,
				S_OR(peer->host, ""),
				port,
				S_OR(peer->defaultuser, ""),
				S_OR(peer->fromdomain, ""),
				port,
				refresh_secs,
				peer->registered ? "Registered" : "Unregistered",
				(long)peer->reg_expiry);
			count++;
		}
		ast_mutex_unlock(&peer->lock);
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

	nh = nua_handle(sofia_nua, NULL, NUTAG_URL(d->target_uri), TAG_END());
	if (nh) {
		nua_notify(nh,
			SIPTAG_EVENT_STR(d->event),
			TAG_IF(header_buf, SIPTAG_HEADER_STR(header_buf ? ast_str_buffer(header_buf) : "")),
			TAG_IF(!ast_strlen_zero(d->content), SIPTAG_PAYLOAD_STR(d->content)),
			TAG_END());
		/* nua_handle is reaped by sofia-sip when the NOTIFY transaction completes. */
	} else {
		ast_log(LOG_WARNING, "Sofia SIPnotify: nua_handle creation failed for target %s\n",
			d->target_uri);
	}

	if (header_buf) {
		ast_free(header_buf);
	}
	sipnotify_data_free(d);
}

static int manager_sofia_notify(struct mansession *s, const struct message *m)
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
		ast_copy_string(target_uri, contact->contact_uri, sizeof(target_uri));
	} else {
		/* Step A IPv6 parity SS3 (2026-04-28): bracket-wrap IPv6 host. The
		 * peer->host fallback may be unbracketed IPv6 from operator config. */
		char hbuf[80];
		snprintf(target_uri, sizeof(target_uri), "sip:%s@%s:%d",
			!ast_strlen_zero(peer->defaultuser) ? peer->defaultuser : peer->name,
			sofia_uri_format_host(
				!ast_strlen_zero(peer->host) ? peer->host : "unknown",
				hbuf, sizeof(hbuf)),
			peer->port ? peer->port : 5060);
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
				dispatch->headers = resized;
				dispatch->headers[dispatch->header_count].name = ast_strdup(v->name);
				dispatch->headers[dispatch->header_count].value = ast_strdup(v->value);
				dispatch->header_count++;
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

static int load_module(void)
{
	ast_verbose("Sofia-SIP channel loading...\n");

	peers = ao2_container_alloc(MAX_PEER_BUCKETS, NULL, NULL);
	dialogs = ao2_container_alloc(MAX_DIALOG_BUCKETS, NULL, NULL);
	sofia_blacklist = ao2_container_alloc(SOFIA_BLACKLIST_BUCKETS,
		sofia_blacklist_hash_fn, sofia_blacklist_cmp_fn);
	if (!peers || !dialogs || !sofia_blacklist) {
		ast_log(LOG_ERROR, "Unable to create Sofia containers\n");
		return AST_MODULE_LOAD_FAILURE;
	}

	if (sofia_load_config(0)) {
		ast_log(LOG_ERROR, "Unable to load config %s\n", SOFIA_CONFIG);
		return AST_MODULE_LOAD_DECLINE;
	}

	if (!ast_rtp_engine_srtp_is_registered()) {
		ast_log(LOG_WARNING, "Sofia: res_srtp not loaded — encryption support disabled\n");
		sofia_cfg.encryption = 0;
	}

	if (ast_pthread_create(&sofia_thread, NULL, sofia_thread_func, NULL)) {
		ast_log(LOG_ERROR, "Failed to create Sofia event thread\n");
		return AST_MODULE_LOAD_FAILURE;
	}

	/* Wait for the thread to create NUA */
	{
		int retries = 50;
		while (!sofia_nua && retries-- > 0) {
			usleep(100000);
		}
		if (!sofia_nua) {
			ast_log(LOG_ERROR, "Sofia NUA failed to initialize\n");
			return AST_MODULE_LOAD_FAILURE;
		}
	}

	if (ast_channel_register(&sofia_tech)) {
		ast_log(LOG_ERROR, "Unable to register channel type '%s'\n", SOFIA_CHANNEL_TYPE);
		/* T40: same-thread-affinity rule for su_root_destroy applies here too —
		 * sofia_thread is already spawned, so signal+join lets it tear down
		 * sofia_root + nua + su_deinit in its own context. */
		if (sofia_nua) {
			nua_shutdown(sofia_nua);
		}
		if (sofia_root) {
			su_root_break(sofia_root);
			pthread_join(sofia_thread, NULL);
		}
		return AST_MODULE_LOAD_FAILURE;
	}

	ast_rtp_glue_register(&sofia_rtp_glue);

	/* Register UDPTL protocol callbacks after RTP glue. The get callback
	 * exposes active T.38 UDPTL sessions; the set callback is intentionally
	 * a no-op while chan_sofia keeps UDPTL relayed through the PBX. */
	ast_udptl_proto_register(&sofia_udptl);

	/* post-T56 Task #8 T.38 fax UDPTL parity SS4 (2026-04-28, SS1.5 N2
	 * LOAD-BEARING 5s reINVITE timeout): create managed scheduler thread
	 * for sofia_t38_abort. ast_sched_thread_create returns NULL on failure
	 * — log warning + continue (T.38 timer disabled but other paths
	 * functional; arm sites null-check sofia_sched). chan_sip pattern at
	 * chan_sip.c:32330 sched_context_create + monitor-thread sched_runq;
	 * chan_sofia uses higher-level ast_sched_thread which manages thread
	 * internally. */
	sofia_sched = ast_sched_thread_create();
	if (!sofia_sched) {
		ast_log(LOG_WARNING, "Sofia: ast_sched_thread_create failed — T.38 5s reINVITE timeout disabled\n");
	}

	ast_register_application_xml(app_dtmfmode, sofia_app_dtmfmode);
	ast_register_application_xml(app_sipaddheader, sofia_app_addheader);
	ast_register_application_xml(app_sipremoveheader, sofia_app_removeheader);

	/* T46.1: ${SIP_HEADER(name[,N])} dialplan function */
	ast_custom_function_register(&sofia_sip_header_function);
	/* T46.2: ${CHECKSIPDOMAIN(domain)} dialplan function */
	ast_custom_function_register(&sofia_check_sipdomain_function);
	/* T46.3: ${SIPPEER(peer[,item])} dialplan function */
	ast_custom_function_register(&sofia_sippeer_function);
	/* T46.4: ${SIPCHANINFO(item)} dialplan function */
	ast_custom_function_register(&sofia_sipchaninfo_function);

	/* T47.1 (2026-04-27): AMI Action SIPpeers */
	ast_manager_register_xml("SIPpeers",
		EVENT_FLAG_SYSTEM | EVENT_FLAG_REPORTING, manager_sofia_show_peers);
	/* T47.2 (2026-04-27): AMI Action SIPshowpeer */
	ast_manager_register_xml("SIPshowpeer",
		EVENT_FLAG_SYSTEM | EVENT_FLAG_REPORTING, manager_sofia_show_peer);
	/* T47.3 (2026-04-27): AMI Action SIPqualifypeer (uses sofia_dispatch_to_root_thread) */
	ast_manager_register_xml("SIPqualifypeer",
		EVENT_FLAG_SYSTEM | EVENT_FLAG_REPORTING, manager_sofia_qualify_peer);
	/* T47.4 (2026-04-27): AMI Action SIPshowregistry */
	ast_manager_register_xml("SIPshowregistry",
		EVENT_FLAG_SYSTEM | EVENT_FLAG_REPORTING, manager_sofia_show_registry);
	/* T47.5 (2026-04-27): AMI Action SIPnotify (uses sofia_dispatch_to_root_thread) */
	ast_manager_register_xml("SIPnotify",
		EVENT_FLAG_SYSTEM, manager_sofia_notify);

	ast_cli_register_multiple(cli_sofia, ARRAY_LEN(cli_sofia));

	sofia_do_register();

	ast_pthread_create(&sofia_reg_thread, NULL, sofia_reg_thread_func, NULL);

	ast_pthread_create(&sofia_qualify_tid, NULL, sofia_qualify_thread, NULL);

	ast_verbose("Sofia-SIP channel driver loaded successfully\n");

	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	ast_verbose("Sofia-SIP channel unloading...\n");

	ast_rtp_glue_unregister(&sofia_rtp_glue);
	/* post-T56 Task #8 T.38 fax UDPTL parity SS2 (2026-04-28): defensive
	 * UDPTL protocol unregister mirrors chan_sip pattern; T40 unload returns
	 * -1 below before any teardown runs, so this is documentation-only at
	 * runtime. Symmetric with load_module register. SS4 (2026-04-28):
	 * ast_sched_thread_destroy reaps managed thread + sched_context. */
	ast_udptl_proto_unregister(&sofia_udptl);
	if (sofia_sched) {
		sofia_sched = ast_sched_thread_destroy(sofia_sched);
	}
	ast_unregister_application(app_dtmfmode);
	ast_unregister_application(app_sipaddheader);
	ast_unregister_application(app_sipremoveheader);
	/* T46.1: dialplan function unregister (defensive — T40 unload body returns -1 before this runs) */
	ast_custom_function_unregister(&sofia_sip_header_function);
	/* T46.2: CHECKSIPDOMAIN unregister + free domain_list entries (defensive) */
	ast_custom_function_unregister(&sofia_check_sipdomain_function);
	/* T46.3: SIPPEER unregister (defensive) */
	ast_custom_function_unregister(&sofia_sippeer_function);
	/* T46.4: SIPCHANINFO unregister (defensive) */
	ast_custom_function_unregister(&sofia_sipchaninfo_function);
	/* T47.1: SIPpeers AMI action unregister (defensive — T40 fallback returns -1) */
	ast_manager_unregister("SIPpeers");
	/* T47.2: SIPshowpeer AMI action unregister (defensive) */
	ast_manager_unregister("SIPshowpeer");
	/* T47.3: SIPqualifypeer AMI action unregister (defensive) */
	ast_manager_unregister("SIPqualifypeer");
	/* T47.4: SIPshowregistry AMI action unregister (defensive) */
	ast_manager_unregister("SIPshowregistry");
	/* T47.5: SIPnotify AMI action unregister (defensive) */
	ast_manager_unregister("SIPnotify");
	{
		struct sofia_domain *d;
		AST_LIST_LOCK(&domain_list);
		while ((d = AST_LIST_REMOVE_HEAD(&domain_list, list))) {
			ast_free(d);
		}
		AST_LIST_UNLOCK(&domain_list);
	}
	ast_channel_unregister(&sofia_tech);
	ast_cli_unregister_multiple(cli_sofia, ARRAY_LEN(cli_sofia));

	/* T40: chan_sofia does NOT support runtime unload.
	 *
	 * Three independent thread-discipline issues conspire to make a clean unload
	 * impossible without a deeper refactor than the operational benefit warrants:
	 *
	 *   (1) sofia-sip's su_root_destroy() asserts on same-thread-as-su_root_create
	 *       (T40 Phase 1 gdb bt: SIGABRT in __assert_fail under su_root_destroy
	 *       called from CLI thread). Phase 2 fix moved teardown into sofia_thread_func.
	 *
	 *   (2) sofia_reg_thread + sofia_qualify_tid leak past dlclose with sleep(30) +
	 *       sleep(1) granularity even after pthread_join (Phase 2 fold-in attempt).
	 *
	 *   (3) libsofia-sip-ua spawns its OWN internal worker threads (su_base_port_run
	 *       inside its tport thread pool) that aren't reaped by su_root_destroy.
	 *       Surfaced in cycle-2 stress (Phase 2 core /tmp/core.gabpbx.983655 showed
	 *       TWO live su_base_port_run threads after a clean unload+load).
	 *
	 * Operationally: operators already restart gabpbx for any chan_sofia config
	 * change (the reload path uses sofia_load_config + module reload, not unload).
	 * Refusing unload is correctness-preserving. T41 (condvar replacement for the
	 * sleep(30) loops) is no longer relevant under this resolution.
	 */
	ast_log(LOG_NOTICE,
		"chan_sofia does not support runtime unload — restart gabpbx for config changes\n");
	return -1;

	/* dead code below (kept for reference + to leave the original teardown
	 * shape visible in source for any future re-attempt at clean unload):
	 *
	 *   if (sofia_nua) nua_shutdown(sofia_nua);
	 *   if (sofia_root) { su_root_break(sofia_root); pthread_join(sofia_thread, NULL); }
	 *   if (sofia_reg_thread != AST_PTHREADT_NULL) pthread_join(sofia_reg_thread, NULL);
	 *   if (sofia_qualify_tid != AST_PTHREADT_NULL) pthread_join(sofia_qualify_tid, NULL);
	 *   ast_free_ha(...); ao2_ref(peers, -1); ao2_ref(dialogs, -1);
	 */

	ast_free_ha(sofia_cfg.localha);
	sofia_cfg.localha = NULL;
	/* post-T56 contactpermit/contactdeny [general] parity (2026-04-27): final cleanup
	 * at module-unload (chan_sip.c:32621 verbatim cleanup pattern). */
	if (sofia_cfg.contact_ha) {
		ast_free_ha(sofia_cfg.contact_ha);
		sofia_cfg.contact_ha = NULL;
	}

	if (peers) {
		ao2_ref(peers, -1);
		peers = NULL;
	}
	if (dialogs) {
		ao2_ref(dialogs, -1);
		dialogs = NULL;
	}
	if (sofia_blacklist) {
		ao2_ref(sofia_blacklist, -1);
		sofia_blacklist = NULL;
	}

	return 0;
}

/* AST_MODULE_INFO .reload hook — invoked by `module reload chan_sofia.so`
 * from the module manager (CLI / AMI ModuleLoad).  Routed through the
 * same sofia_reload_request_sync path as the `sip reload` CLI alias, so
 * both invocations share the thread-safe reload-on-sofia_thread flow,
 * the 30-second deadline, the listener-change refusal, and the mark-
 * and-sweep peer cleanup.  Returns 0 on success or -1 on failure so the
 * module manager surfaces the result. */
static int reload(void)
{
	char errmsg[256] = "";
	int rc = sofia_reload_request_sync(errmsg, sizeof(errmsg), 30000);
	if (rc != 0) {
		ast_log(LOG_WARNING, "Sofia: module reload failed — %s\n",
			errmsg[0] ? errmsg : "see log");
	}
	return rc;
}

AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "Sofia-SIP Channel Driver",
	.load = load_module,
	.unload = unload_module,
	.reload = reload,
	.load_pri = AST_MODPRI_CHANNEL_DRIVER,
);
