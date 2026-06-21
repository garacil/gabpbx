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

/* =====================================================================
 * chan_sofia LOCKING & CONCURRENCY INVARIANT  (authoritative reference —
 * every inline "LOCK ORDER" note in this file is an instance of the rules
 * below; cite this block, do not re-derive the model ad hoc)
 * =====================================================================
 *
 * THREAD MODEL.  A SINGLE sofia_thread (the sofia-sip su_root event loop)
 * runs ALL SIP signaling: every nua_* callback (sofia_event_callback and the
 * sofia_process_* handlers) AND config reload (a "sip reload" is dispatched
 * onto sofia_thread via sofia_dispatch_to_root_thread).  So sofia_thread
 * OWNS all mutable peer/dialog signaling state; two code paths that BOTH run
 * on sofia_thread are mutually serialized for free.  Everyone else only
 * READS that state and must do so under a lock:
 *   - the channel/PBX/bridge thread (tech callbacks: sofia_call/_answer/
 *     _hangup/_indicate/_fixup/_write/_read, sofia_get/set_rtp_peer),
 *   - the dialplan thread           (func_sofia_sippeer / sipchaninfo, ...),
 *   - CLI / AMI threads,
 *   - the ast_sched scheduler thread (timer cbs: t38 abort, defer-bye, ...),
 *   - the registration/qualify aux threads (sofia_reg_thread, sofia_qualify_tid),
 *   - dnsmgr.
 * RACE DISCRIMINATOR: a data race exists only if at least one party runs OFF
 * sofia_thread.  State the thread of each party when reasoning about a lock.
 *
 * LOCK ORDER (HARD, never invert):
 *     channel-lock  ->  pvt->lock  ->  peer-family (ao2_lock(peer) / peer->lock)
 * peer->lock is a dedicated ast_mutex_t struct field, DISTINCT from
 * ao2_lock(peer).  ast_channel locks and the ast_mutex_t locks (pvt->lock,
 * peer->lock) are RECURSIVE, so a thread re-entering its own held lock is
 * safe.  The reload writer (sofia_parse_peer_config) holds peer->lock as a
 * LEAF — it never takes a channel or pvt lock under it — so widening a
 * reader's hold of peer->lock cannot invert against it.
 *   fork->lock (sofia_fork coordination: winner/children/count/state) is a
 *   SEPARATE sub-lock taken UNDER pvt->lock — the master->lock -> fork->lock
 *   order sofia_hangup uses — and is NEVER co-held with peer-family (verified:
 *   no path holds both), so it is not ordered against peer->lock.
 *
 * GLOBAL config lists are not per-object-lockable, so they have dedicated
 * rwlocks (both leaves): sofia_localha_lock guards sofia_cfg.localha (read by
 * the channel-thread SDP build), sofia_contactha_lock guards
 * sofia_cfg.contact_ha (read off-thread on the realtime peer build).
 *
 * THE SNAPSHOT IDIOM (mandatory by default for any FREEABLE peer/owner data
 * touched off sofia_thread):
 *   - stringfields/lists: take peer->lock, ast_copy_string into a local
 *     (peer stringfields are UNBOUNDED -> size >= 256) or deep-copy a list,
 *     release, then use the local.  ast_string_field_set frees the old pool
 *     on growth, so a lock-free off-thread read is a use-after-free.
 *   - owner/channel: ref owner under pvt->lock, drop pvt->lock,
 *     ast_channel_lock(owner), re-lock pvt->lock, REVALIDATE pvt->owner==owner
 *     (masquerade/hangup window), unref on every path  (sip_pvt_lock_full).
 *   - NEVER hold pvt->lock or peer->lock across a channel-locking or blocking
 *     call (nua_*, su_*, DNS, ast_moh_start, pbx_builtin_setvar_helper,
 *     ast_cli, ast_request).  Snapshot first, release, then call.
 *
 * DIALOG TEARDOWN RACE.  An in-dialog nua_i_* or nua_r_* event carries the
 * dialog pvt as hmagic, but sofia_hangup (channel thread) can free that pvt
 * concurrently.  sofia_event_callback re-validates the hmagic against the
 * dialogs container and pins a +1 ref for the whole dispatch
 * (sofia_pvt_ref_if_linked, dropped once at function exit) for every such
 * event; per-handler `if (pvt)` guards and op->owner snapshots cover the rest.
 * ===================================================================== */

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
#include "gabpbx/taskprocessor.h"
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
#include "gabpbx/udptl.h"  /* post-T56 Task #8 T.38 fax UDPTL parity SS2 (2026-04-28): ast_udptl_protocol + ast_udptl_proto_register/unregister + ast_udptl_destroy public API + struct ast_control_t38_parameters via frame.h. Skeleton + lifecycle this SS; SDP/state-machine/relay/queryoption arriving SS3a-SS5 per the T.38 design notes §3 */
#include "gabpbx/sched.h"  /* post-T56 Task #8 T.38 fax UDPTL parity SS4 (2026-04-28): ast_sched_thread_create/destroy/add/del for sofia_t38_abort 5s reINVITE timeout per SS1.5 N2 LOAD-BEARING (chan_sip.c:24288 ast_sched_add 5000ms). chan_sofia uses ast_sched_thread managed-thread API (sched.h:316-403) — sofia owns separate sched-thread vs chan_sip's monitor-thread sched_runq pattern; equivalent semantic + cleaner thread-ownership */
#include "gabpbx/causes.h"
#include "gabpbx/acl.h"
#include "gabpbx/musiconhold.h"
#include "gabpbx/ast_version.h"  /* post-T56 useragent [general] parity (2026-04-28): ast_get_version() for User-Agent default value */
#include "gabpbx/paths.h"        /* post-T56 rtsavesysname [general] parity (2026-04-28): ast_config_AST_SYSTEM_NAME extern for regserver column writes */

#include "sofia/include/srtp.h"
#include "sofia/include/sdp_crypto.h"
#include "sofia/include/chan_sofia_internal.h"
#include "sofia/include/sofia_blacklist.h"
#include "sofia/include/sofia_publish.h"
#include "sofia/include/sofia_ami.h"

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
#include <sofia-sip/tport_tag.h>	/* TPTAG_TOS for SIP-listener-side TOS via nua_create. */

#define SOFIA_CONFIG "sofia.conf"
#define SOFIA_CHANNEL_TYPE "SIP"

#define DEFAULT_CONTEXT "default"
#define DEFAULT_BINDADDR "0.0.0.0"
#define DEFAULT_SIP_PORT 5060
#define DEFAULT_EXPIRY 120
/* Registration TTL bounds + 423 Interval Too Brief (chan_sip parity). Used at
 * config explicit-init + clamp-on-invalid fallback. */
#define DEFAULT_MIN_EXPIRY      60
#define DEFAULT_MAX_EXPIRY      3600
#define DEFAULT_DEFAULT_EXPIRY  120
/* RFC 3261 §20.22 Max-Forwards default (chan_sip parity). */
#define DEFAULT_MAX_FORWARDS    70
/* RFC 3261 §17.1.1.2 T1 retry-timer minimum; 100ms (chan_sip parity, overrides
 * the RFC default of 500ms). */
#define DEFAULT_T1MIN           100
/* Outbound REGISTER application-level scheduled-retry interval, seconds (chan_sip parity). */
#define DEFAULT_REGISTRATION_TIMEOUT 20
/* User-Agent (outbound requests) + Server (responses) header value (chan_sip parity).
 * Composed at config-load as "%s %s" with ast_get_version(), e.g. "GABpbx PBX 2.7.1".
 * Overrides sofia-sip's own default for drop-in faithfulness. */
#define DEFAULT_USERAGENT       "GABpbx PBX"
/* progressinband tri-state (chan_sip parity). Default NEVER. */
/* faxdetect multi-mode (chan_sip parity). Bit-OR semantic: CNG (1) | T38 (2) = BOTH (3).
 * Default NONE. */

/* 4-state T.38 negotiation machine (chan_sip parity). State transitions queue
 * AST_CONTROL_T38_PARAMETERS for 3 of 4 states (LOCAL_REINVITE deliberately
 * silent — waits for the peer 200 OK). */

/* T.38 UDPTL error-correction mode (NONE / FEC / REDUNDANCY, chan_sip parity).
 * Per-peer t38pt_udptl parser sets peer->t38_ec_mode; SDP a=T38FaxUdpEC
 * negotiation parses the peer choice. */

/* T.38 FaxMaxDatagram default (chan_sip parity): sentinel -1 = use the 200-byte
 * built-in; positive integer overrides per peer or [general]. */
#define SOFIA_T38_MAXDATAGRAM_SENTINEL  -1
#define SOFIA_T38_MAXDATAGRAM_BUILTIN   200

/* T.38 reINVITE 5-second abort timeout (chan_sip parity). Without this timer,
 * peers that fail to ack the 200 OK leave chan_sofia stuck in T38_PEER_REINVITE
 * forever. */
#define SOFIA_T38_ABORT_TIMEOUT_MS  5000
/* REFER transferer-leg BYE deferral (chan_sip parity for SIP_DEFER_BYE_ON_TRANSFER).
 * After we send
 * the terminal NOTIFY 200 OK on a blind/attended transfer we expect the transferer's
 * UA to BYE us (RFC 5589 §6.1). If it does not within this window, fire nua_bye
 * ourselves so the dialog does not leak. 32 s mirrors chan_sip DEFAULT_TRANS_TIMEOUT. */
#define SOFIA_DEFER_BYE_TIMEOUT_MS  32000
/* allowoverlap tri-state NO/YES/DTMF (chan_sip parity). Default YES. DTMF mode is
 * parsed/stored/displayed but the inbound 484 emit treats it as fall-through to
 * standard handling — like chan_sip, DTMF overlap detection is deferred to the
 * dialplan (Incomplete application) rather than handled in the channel driver. */
/* Hash-table bucket caps sized for carrier scale: a low load factor at 10k+
 * registered peers and high concurrent-dialog volume, so peer/dialog lookups
 * stay O(1) under load. Primes give an even ao2 bucket distribution. */
#define MAX_PEER_BUCKETS 65521    /* ~2^16 prime: ~50k peers at load factor < 1 */
#define MAX_DIALOG_BUCKETS 32749  /* ~2^15 prime: concurrent-dialog headroom */




/* RFC 7118 SIP-over-WebSocket transport types. Wire-in via NUTAG_WS_URL +
 * NUTAG_WSS_URL at nua_create. Per-peer transport=ws or transport=wss is
 * operator-configurable (chan_sip has no WebSocket support). Power-of-2 enum
 * continues the SOFIA_TRANSPORT_* bitmask convention. */


/* Digest-auth nonce TTL fallback when sofia_cfg.nonce_ttl_seconds is unset
 * (=0). Keep the default aligned with the normal SIP registration maximum so
 * long-lived phones do not receive stale=true on every normal refresh. Operators
 * can still tighten this with [general] nonce_ttl_seconds=N. */
#define SOFIA_NONCE_TTL_SEC_DEFAULT 3600
#define SOFIA_NONCE_TTL_SEC_LEGACY  300  /* migration reference */

/* Which digest algorithm(s) chan_sofia OFFERS in the WWW-Authenticate challenge.
 * Verification accepts exactly what was offered (anti-downgrade). Operator-
 * selectable via [general] auth_algorithms = both | md5 | sha256. Built-in default
 * BOTH = offer MD5 + SHA-256 (the shipped sofia.conf sets md5). */

#define DEFAULT_QUALIFYFREQ   60
#define DEFAULT_QUALIFYTIMEOUT 3
#define DEFAULT_FREQ_NOTOK    10



struct sofia_config sofia_cfg;

	su_root_t *sofia_root;
	nua_t *sofia_nua;
	static pthread_t sofia_thread;
	static pthread_t sofia_reg_thread;
	static pthread_t sofia_qualify_tid;
	/* ast_sched_thread managed-thread for the T.38 reINVITE 5-second timeout
	 * (sofia_t38_abort callback). Created at load_module (post-nua-init);
	 * destroyed at unload. NULL when not yet initialized — gates t38id arm
	 * call sites. */
	static struct ast_sched_thread *sofia_sched;

int sofia_debug;
static char sofia_debug_filter[64];
static int sofia_debug_match(const char *peer_name, const char *src_ip);
/* timert1/timerb cross-validation flags (chan_sip parity). Set when the
 * respective [general] key is parsed; consumed at config conclusion for the
 * Timer B vs T1*64 cross-validation. */
static int sofia_timerb_set;
static int sofia_timert1_set;
/* SRTP per-suite-fresh-key option: module-scope mirror of
 * sofia_cfg.srtp_per_suite_keys for sdp_crypto.c extern-visibility. Set at
 * config-load after [general] parsing; read by sdp_crypto_offer_list +
 * sdp_crypto_activate. NOT static (extern visibility required). */
int sofia_srtp_per_suite_keys;

struct ao2_container *peers;
static struct ao2_container *dialogs;

/* Bounded REGISTER realtime-DB-write offload pool (kill-switch, default OFF).
 * The ast_update_realtime() writes in sofia_process_register() are the only slow
 * blocking I/O left on the single sofia_thread under a registration storm;
 * offloading them to a small fixed pool of taskprocessor lanes keeps
 * INVITE/OPTIONS signalling responsive when the realtime DB is slow. Lanes are
 * keyed by peer name so all writes for one account stay FIFO-ordered on one lane
 * (a de-REGISTER can never overtake a prior REGISTER). */
#define SOFIA_REGPOOL_MAX 16
static struct ast_taskprocessor *sofia_regpool[SOFIA_REGPOOL_MAX];
static int sofia_regpool_n;                 /* active lane count (0 = not created) */
static int sofia_regpool_enabled;           /* runtime gate: config ON && lanes created */
/* Guards the GLOBAL sofia_cfg.localha ast_ha list: read by the channel-thread
 * SDP build (sofia_should_use_externaddr) while sip reload frees+rebuilds it on
 * sofia_thread. */
AST_RWLOCK_DEFINE_STATIC(sofia_localha_lock);
/* Guards the GLOBAL sofia_cfg.contact_ha ast_ha list. Besides the sofia_thread
 * REGISTER reader, it is ALSO read (and appended) off sofia_thread by
 * sofia_peer_alloc on the realtime peer-build path (sofia_find_peer ->
 * sofia_find_peer_realtime, reached from sofia_request_call / func_sofia_sippeer
 * / AMI), all racing the reload free+rebuild. Same treatment as localha. */
AST_RWLOCK_DEFINE_STATIC(sofia_contactha_lock);


/* Local SIP domains for ${CHECKSIPDOMAIN(domain)} dialplan function.
 * Populated from sofia.conf [general] domain= lines (multi-allowed). */
struct sofia_domain {
	char domain[80];
	AST_LIST_ENTRY(sofia_domain) list;
};
static AST_LIST_HEAD_STATIC(domain_list, sofia_domain);

/* sofia_get_source_addr is declared in chan_sofia_internal.h (shared with the split modules). */
/* Forward-decl for sofia_pick_auth_username (definition further down; called
 * earlier from sofia_process_invite + sofia_process_register). */
static const char *sofia_pick_auth_username(sip_t const *sip,
		const char *fallback_user, char *buf, size_t len);

/* Forward declarations for INVITE digest-auth wire-in (definitions further down).
 * enum sofia_auth_result is declared here so sofia_process_invite can take it as a
 * return-type. struct sofia_peer is defined later; an opaque forward-decl suffices
 * (helper signature only takes pointer-to-struct). */
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

/* Forward-decls for INVITE auth helpers called from sofia_process_invite (auth
 * dispatch + ACL-deny timing-equal + alwaysauthreject); definitions further down. */
static void sofia_emit_timing_equalized_reject(void);
static void sofia_send_auth_challenge(nua_t *nua, nua_handle_t *nh, sip_t const *sip,
		const char *realm, const char *method, const char *reason);


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
	/* Set by sofia_update_peer_contacts (under peer->lock, pure accumulator) and
	 * consumed by sofia_emit_register_side_effects AFTER unlock — moves the
	 * register_peer_exten / PeerStatus AMI / ast_devstate_changed emissions out from
	 * under peer->lock. emit_unregister is mutually exclusive with the registered tail. */
	int emit_unregister;
	const char *unregister_cause;	/* string literal: "Wildcard" / "Expired" */
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
static void sofia_pvt_snapshot_initreq(struct sofia_pvt *pvt, sip_t const *sip);

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

/* MWI per-peer mailbox tracking. struct sofia_mailbox is the per-mailbox node;
 * sofia_mailbox_list is the per-peer head. Defined here BEFORE struct sofia_peer
 * so the head is a complete type when sofia_peer embeds it. */
struct sofia_mailbox {
	char mailbox[80];
	char context[80];
	struct ast_event_sub *event_sub;	/* AST_EVENT_MWI subscription per mailbox */
	AST_LIST_ENTRY(sofia_mailbox) list;
};

/* Session timers (RFC 4028) mode + refresher enums (chan_sip parity). Mapped to the
 * sofia-sip nua_session_refresher enum at NUTAG_SESSION_REFRESHER emit time. */

/* allowtransfer per-peer REFER gate (chan_sip parity). Values chosen so static-zero
 * struct init == TRANSFER_OPENFORALL == chan_sip backwards-compat default ("accept
 * all transfers"). chan_sip's "strict" transfermode is dead code (no parser path
 * produces it), so chan_sofia mirrors only the 2 reachable values. */

/* allowtransfer display-string helper (chan_sip transfermode2str parity, skips the
 * dead "strict" branch). Used by sip show peer + AMI SIPshowpeer TransferMode. */

/* allowoverlap tri-state mode → display string mapping (chan_sip parity). Used at
 * sip show settings + sip show peer + AMI SIPshowpeer. */

/* Split "name=value" buffer, create ast_variable, LIFO list-prepend (chan_sip add_var
 * parity). Used for setvar + header in both peer-config parsers. NULL value =
 * malformed input (no '=' separator) → list returned unchanged. */
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
		AST_STRING_FIELD(subscribecontext);	/* per-call cache of peer->subscribecontext for in-dialog SUBSCRIBE routing (chan_sip parity). Inherits at sofia_request_call (outbound) + sofia_process_invite (inbound). */
		AST_STRING_FIELD(accountcode);	/* per-call cache of peer->accountcode. Consumed by sofia_new as the ast_channel_alloc 5th arg for chan->accountcode propagation (CDR billing-tag) — must NOT be pvt->username (auth-identity), which is the wrong semantic. */
		AST_STRING_FIELD(username);
		AST_STRING_FIELD(peername);
		AST_STRING_FIELD(peersecret);
		AST_STRING_FIELD(fromdomain);
		AST_STRING_FIELD(fromuser);
		AST_STRING_FIELD(uri);
		AST_STRING_FIELD(ruri);
		AST_STRING_FIELD(cid_num);   /* inbound caller-id number; from sip_from at sofia_process_invite, overwritten by sofia_get_pai/sofia_get_rpid when peer->trustrpid=1 */
		AST_STRING_FIELD(cid_name);  /* inbound caller-id name; same population/overwrite chain as cid_num */
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
	int outbound_invite_auth_attempts; /* count of 401/407 answered on this outbound INVITE — bounded (allows sequential WWW+Proxy challenges, caps the loop on bad creds) */
	unsigned long sess_id;           /* SDP o= session-id, set ONCE per dialog (RFC 4566 §5.2 / RFC 3264 §8 require it constant across all offers/answers) */
	unsigned long sess_version;      /* SDP o= session-version, bumped on each generated SDP */
	int hold_state;                  /* 1 = peer holding us (a=sendonly/inactive); 0 = active (sendrecv) */
	struct sofia_srtp *srtp;         /* audio SDES-SRTP context (NULL = plain RTP); freed in destructor */
	struct sofia_srtp *vsrtp;        /* video SDES-SRTP context (NULL = plain RTP); freed in destructor */
	struct ast_variable *initreq_headers; /* snapshot of inbound INVITE headers for ${SIP_HEADER()} (NULL if outbound or pre-INVITE); freed in destructor */
	struct ast_sockaddr last_src_addr; /* transport-source captured at INVITE for ${SIPCHANINFO(peerip|recvip)} */
	struct ast_sockaddr ourip; /* kernel-routed source IP for outbound INVITE From/Contact + SDP c=; resolved by sofia_resolve_ourip at sofia_request_call; zero-init for inbound flows */
	int callingpres; /* AST_PRES_* mask; per-call presentation; inherits peer->callingpres at sofia_call/sofia_new (else AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED=0); chan_sip parity */
	int outgoing; /* 1=outbound dial (sofia_request_call), 0=inbound INVITE; consumed by sofia_add_rpid RPID ;party=calling/called field */
	int call_inc_done; /* 1 = this pvt incremented peer->inUse — race-prevention flag for DEC sites (chan_sip SIP_INC_COUNT parity) */
	int ring_inc_done; /* 1 = this pvt incremented peer->inRinging — race-prevention (chan_sip SIP_INC_RINGING parity) */
	struct ast_dsp *dsp; /* Allocated by sofia_enable_dsp_detect when inband/auto DTMF or fax-CNG detection is enabled; freed in destructor. */

	/* T.38 fax UDPTL state (chan_sip parity):
	 *
	 *   udptl: per-dialog UDPTL session pointer; NULL when no T.38 in flight.
	 *     Allocated lazily on first T.38 reINVITE detect; destroyed in
	 *     sofia_pvt_destructor via ast_udptl_destroy.
	 *
	 *   t38_state: 4-state machine DISABLED/LOCAL_REINVITE/PEER_REINVITE/ENABLED.
	 *     Init DISABLED in sofia_pvt_alloc.
	 *
	 *   t38id: scheduler ID for the sofia_t38_abort 5-second reINVITE timeout.
	 *     Init -1 in sofia_pvt_alloc. Without this timer, peers that fail to ack
	 *     the 200 OK leave chan_sofia stuck in PEER_REINVITE forever.
	 *
	 *   t38_max_ifp: far-end advertised max_ifp from peer SDP. LOAD-BEARING:
	 *     without max_ifp wiring, real-fax negotiation rejects on every call
	 *     (peer max_ifp==0 forces T38_DISABLED).
	 *
	 *   t38_maxdatagram: inherited from peer->t38_maxdatagram or
	 *     sofia_cfg.default_t38_maxdatagram (-1 = use SOFIA_T38_MAXDATAGRAM_BUILTIN 200).
	 *
	 *   t38_ec_mode: per-call EC mode NONE/FEC/REDUNDANCY; inherited from
	 *     peer->t38_ec_mode (paired with ast_udptl_set_error_correction_scheme).
	 *
	 *   t38pt_usertpsource: 1 = symmetric-RTP UDPTL destination override;
	 *     inherited from peer->t38pt_usertpsource.
	 *
	 *   t38_our_parms / t38_their_parms: full 7-field ast_control_t38_parameters.
	 *     Zero-initialized via ao2_alloc memset; populated during negotiation. */
	struct ast_udptl *udptl;
	int t38_state;
	int t38id;
	unsigned int t38_max_ifp;        /* unsigned per ast_control_t38_parameters.max_ifp + ast_udptl_get_far_max_ifp return type */
	int t38_maxdatagram;
	int t38_ec_mode;
	int t38pt_usertpsource;
	struct ast_control_t38_parameters t38_our_parms;
	struct ast_control_t38_parameters t38_their_parms;
	/* Session timers (RFC 4028) per-call refresh tracking for sip show channels
	 * Session-Timer display + AMI SessionTimerRefresh event. Populated at
	 * refresh-fire-time inside sofia_process_reinvite (uas) + nua_r_invite (uac)
	 * when SIPTAG_SESSION_EXPIRES is present on the re-INVITE. zero-init = no
	 * session-timer active or not yet fired. */
	int session_negotiated_expires; /* negotiated Session-Expires (seconds); 0 = no timer active */
	time_t session_last_refresh_at; /* time of most recent refresh; 0 = never refreshed */
	int allowtransfer; /* per-call REFER policy (chan_sip parity); inherits peer->allowtransfer at sofia_request_call/sofia_process_invite; gated at sofia_process_refer entry */
	/* Blind/attended-transfer BYE deferral (chan_sip parity for SIP_DEFER_BYE_ON_TRANSFER).
	 * After we send the terminal NOTIFY 200 OK for a
	 * REFER, RFC 5589 §6.1 expects the transferer's UA to send BYE on its own; we must
	 * not race the UA with our own nua_bye, otherwise sofia-sip drops the pending
	 * terminal NOTIFY and the UA never sees the transfer complete (call lingers).
	 * When set, sofia_hangup skips its nua_bye, and a sched-thread timer
	 * (defer_bye_sched_id) fires nua_bye after SOFIA_DEFER_BYE_TIMEOUT_MS as the safety
	 * net for UAs that do not auto-BYE. The incoming-BYE handler cancels the timer. */
	int defer_bye;
	int defer_bye_sched_id;
};

/* Centralized call-counter helper (chan_sip update_call_counter parity). 4 events
 * (INC_CALL_LIMIT inbound / INC_CALL_RINGING outbound / DEC_CALL_LIMIT hangup /
 * DEC_CALL_RINGING outbound 200 OK). Returns -1 on rejection. Lock order: pvt->lock
 * then ao2_lock(peer). Idempotency via pvt->call_inc_done + ring_inc_done flags. The
 * helper emits PeerStatus AMI events itself. Declared HERE (before
 * sofia_pvt_destructor, which calls it). */
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

const char *sofia_uri_format_host(const char *host, char *out_buf, size_t out_len);

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

/* Derive the registration transport from a Contact URL. RFC 3261 §19.1.1: an
 * explicit ;transport= parameter wins; failing
 * that, a sips: scheme implies tls, otherwise udp. The legacy code derived this
 * from the url_scheme alone (sip/sips) so a "sip:user@host;transport=tcp" Contact
 * was wrongly stored as udp. Writes a lowercase token (udp/tcp/tls/ws/wss) into
 * out (>= 8 bytes); unknown/oversized values fall back to udp. */
static void sofia_contact_transport_from_url(const url_t *url, char *out, size_t outlen)
{
	char buf[16] = "";

	ast_copy_string(out, "udp", outlen);
	if (!url) {
		return;
	}
	if (url->url_params) {
		/* url_param returns the value length (0 if absent); guard against an
		 * oversized value that would be truncated (>= sizeof(buf)). */
		isize_t r = url_param(url->url_params, "transport", buf, sizeof(buf));
		if (r > 0 && r < (isize_t)sizeof(buf)) {
			char *p;
			for (p = buf; *p; p++) {
				*p = tolower((unsigned char)*p);
			}
			if (!strcmp(buf, "udp") || !strcmp(buf, "tcp") || !strcmp(buf, "tls")
					|| !strcmp(buf, "ws") || !strcmp(buf, "wss")) {
				ast_copy_string(out, buf, outlen);
				return;
			}
		}
	}
	if (url->url_scheme && !strcasecmp(url->url_scheme, "sips")) {
		ast_copy_string(out, "tls", outlen);
	}
}

/* Append ;transport= to an outbound URI so a call/ACK/NOTIFY/BYE to a
 * TCP/TLS-registered phone is routed over the same transport it registered on
 * (sofia-sip otherwise defaults to UDP). Only tcp/tls are routed today: udp /
 * empty / unknown / ws / wss are no-ops (keeps UDP-registered phones unchanged;
 * WS/WSS deferred to the flow/Path-routing item). We do NOT rewrite the scheme to
 * sips: — ";transport=tls" alone selects TLS without changing SIP/SIPS semantics. */
void sofia_uri_append_transport(char *url, size_t len, const char *transport)
{
	size_t cur;

	if (!url || ast_strlen_zero(transport)) {
		return;
	}
	if (strcasecmp(transport, "tcp") && strcasecmp(transport, "tls")) {
		return;
	}
	cur = strlen(url);
	if (cur < len) {
		snprintf(url + cur, len - cur, ";transport=%s", transport);
	}
}

/* Build NAT-traversal proxy URL from peer->src_addr for outbound in-dialog
 * messages when peer has nat=force_rport (or comedia). Used by sofia_call to
 * disable sofia-sip's auto-ACK and the nua_r_invite 200-OK handler to emit
 * a manual ACK with NUTAG_PROXY override — without this, sofia-sip routes
 * the 2xx-ACK to the dialog's remote_target (= Contact URI from the 200 OK),
 * which for NAT'd phones (e.g. a NAT'd phone behind a home router) carries the
 * unroutable private LAN IP and the ACK never arrives, leaving the phone
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
	/* A TCP/TLS-registered NAT phone must get its ACK/NOTIFY/BYE proxy route over
	 * the same transport, else sofia-sip opens a fresh UDP flow to the registered
	 * source and the in-dialog request is lost. */
	sofia_uri_append_transport(buf, len, peer->reg_transport);
	return 1;
}

static int sofia_pvt_build_nat_target_url(struct sofia_pvt *pvt, char *buf, size_t len)
{
	struct ast_sockaddr src;
	struct sofia_contact *contact;
	char user[128];
	char host[80];
	char transport[8];

	if (!pvt || !buf || !len) {
		return 0;
	}
	buf[0] = '\0';

	contact = pvt->active_contact;
	if (!contact) {
		return 0;
	}
	/* Snapshot the contact's mutable src_addr under its ao2 lock — a concurrent
	 * REGISTER refresh rewrites it (memcpy of a sockaddr), so an unlocked read could
	 * observe a torn address and route the BYE to the wrong target.
	 * contact->port/host/contact_uri are set once at contact creation (safe).
	 * transport is likewise refresh-mutable, so snapshot it here too. */
	ao2_lock(contact);
	src = contact->src_addr;
	ast_copy_string(transport, contact->transport, sizeof(transport));
	ao2_unlock(contact);
	if (ast_sockaddr_isnull(&src)) {
		return 0;
	}
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
	/* Send the in-dialog BYE over the contact's transport. */
	sofia_uri_append_transport(buf, len, transport);
	return 1;
}

/* Build sip:user@host:port target URL for a peer.
 * Resolves "dynamic" placeholder OR force_rport-flagged peers to their last-known
 * src_addr from REGISTER. Static-host peers (provider trunks) keep their configured
 * host:port — outbound REGISTER targets correctly skip this helper since they need
 * the configured upstream address, not the peer's own register-source. */
/* usereqphone: RFC 3966 telephone-uri digit-pattern matcher (chan_sip parity) —
 * digit-only with optional leading '+' tolerance. */
/* Forward-decl for sofia_uri_format_host (definition further down, after the
 * sofia_should_use_externaddr block). */
const char *sofia_uri_format_host(const char *host, char *out_buf, size_t out_len);

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
	/* Only the registered-source branch below carries a learned transport; a
	 * statically-configured host routes per its (decorative) config, leave it UDP. */
	int routed_via_registration = 0;

	if (peer->registered && !ast_sockaddr_isnull(&peer->src_addr)
		&& ((peer->nat & SOFIA_NAT_FORCE_RPORT)
			|| !strcasecmp(peer->host, "dynamic"))) {
		ast_copy_string(addr_buf, ast_sockaddr_stringify_host(&peer->src_addr), sizeof(addr_buf));
		target_host = addr_buf;
		target_port = ast_sockaddr_port(&peer->src_addr);
		routed_via_registration = 1;
	} else if (!strcasecmp(peer->host, "dynamic") && !ast_sockaddr_isnull(&peer->defaddr)) {
		/* defaultip fallback (chan_sip parity): host=dynamic peer not registered
		 * AND defaultip configured → route to the fallback IP. Once the peer
		 * registers, the src_addr branch above takes precedence. */
		ast_copy_string(addr_buf, ast_sockaddr_stringify_host(&peer->defaddr), sizeof(addr_buf));
		target_host = addr_buf;
		if (ast_sockaddr_port(&peer->defaddr)) {
			target_port = ast_sockaddr_port(&peer->defaddr);
		}
	}
	{
		/* Bracket-wrap IPv6 host per RFC 3261 §19.1.2. target_host may come from
		 * peer->host (raw config, possibly unbracketed IPv6) or stringify_host
		 * (already bracketed); the helper is idempotent at both. */
		char hbuf[80];
		snprintf(out_url, out_len, "sip:%s@%s:%d", user ? user : "",
			sofia_uri_format_host(target_host, hbuf, sizeof(hbuf)), target_port);
	}
	/* Route a call/qualify to a TCP/TLS-registered phone over the transport it
	 * registered on (no-op for UDP). */
	if (routed_via_registration) {
		sofia_uri_append_transport(out_url, out_len, peer->reg_transport);
	}
	/* usereqphone (chan_sip parity): append ;user=phone when the peer has
	 * usereqphone set AND the user-part matches the phone-number pattern. One
	 * helper covers all 3 outbound URI consumers (INVITE / REFER target / qualify). */
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
		int match;
		/* Compare the mutable src_addr under the contact lock (a REGISTER refresh
		 * rewrites it concurrently). */
		ao2_lock(c);
		match = (ast_sockaddr_cmp(&c->src_addr, addr) == 0);
		ao2_unlock(c);
		if (match) {
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
	int res;
	if (ast_strlen_zero(sofia_cfg.externaddr))
		return 0;
	/* reload-UAF fix: sofia_cfg.localha is a freeable global ast_ha list that
	 * sip reload frees+rebuilds on sofia_thread; this runs on the channel
	 * thread. rdlock the NULL-check + the ast_apply_ha walk together (leaf —
	 * no other lock taken inside). */
	ast_rwlock_rdlock(&sofia_localha_lock);
	res = !sofia_cfg.localha ? 1
		: (ast_apply_ha(sofia_cfg.localha, peer_addr) == AST_SENSE_ALLOW);
	ast_rwlock_unlock(&sofia_localha_lock);
	return res;
}

/* Format the host portion of a SIP URI with IPv6-bracket-awareness (RFC 3261
 * §19.1.2). IPv6 literals (containing `:`) MUST be bracket-wrapped to disambiguate
 * the address colons from the port-separator colon; IPv4 literals + hostnames pass
 * through unchanged. Idempotent — already-bracketed input passes through unmodified.
 * Returns out_buf for chained snprintf use. NULL/empty input → empty out_buf. */
const char *sofia_uri_format_host(const char *host, char *out_buf, size_t out_len)
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

/* R6 #5 (3-way consensus): IPv6-aware host:port split for a "user@host[:port]" RURI tail.
 * Ports the ']'-first algorithm already used at the bindaddr/active-contact sites so a
 * bracketed [2001:db8::1]:5060 is NOT split at the first inner colon (the old inline
 * strchr(at+1,':') mis-split bare IPv6). Fills host (bracket-stripped, NUL-terminated,
 * clamped to hostlen) and *port; strips a trailing ;params / '>' in the no-port branch.
 * Factored into ONE helper to stop the N-inline-copies drift that caused this bug. */
void sofia_split_hostport_from_uri(const char *hostport, char *host, size_t hostlen, int *port)
{
	const char *first, *last;

	if (!host || hostlen == 0) {
		return;
	}
	host[0] = '\0';
	if (ast_strlen_zero(hostport)) {
		return;
	}

	if (*hostport == '[') {				/* [IPv6](:port) */
		const char *end = strchr(hostport, ']');
		if (end) {
			size_t hlen = end - (hostport + 1);
			if (hlen >= hostlen) {
				hlen = hostlen - 1;
			}
			memcpy(host, hostport + 1, hlen);
			host[hlen] = '\0';
			if (port && end[1] == ':') {	/* opencode nit: NULL-guard *port */
				*port = atoi(end + 2);
			}
			return;
		}
		/* malformed (no closing ']') — fall through to copy raw */
	}

	first = strchr(hostport, ':');
	last = strrchr(hostport, ':');
	if (first && first == last) {			/* exactly one colon: host:port */
		size_t hlen = first - hostport;
		if (hlen >= hostlen) {
			hlen = hostlen - 1;
		}
		memcpy(host, hostport, hlen);
		host[hlen] = '\0';
		if (port) {				/* opencode nit: NULL-guard *port */
			*port = atoi(first + 1);
		}
	} else {					/* no colon (host), or bare IPv6 (>1 colon, no port) */
		char *p;
		ast_copy_string(host, hostport, hostlen);
		if ((p = strchr(host, ';'))) {
			*p = '\0';
		}
		if ((p = strchr(host, '>'))) {
			*p = '\0';
		}
	}
}

static int sofia_fork_pick_winner(struct sofia_fork *fork, struct sofia_pvt *child, sip_t const *sip)
{
	struct sofia_pvt *master;

	/* Validate the child's answer SDP BEFORE claiming winner status. If
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
	/* Claim winner AND snapshot+ref the master under the same fork->lock hold.
	 * fork->master is NULL'd (with its anchoring ref dropped) by a concurrent
	 * master sofia_hangup; if that already happened the master is being torn
	 * down, so treat this child as a loser (return -1 → caller CANCELs + unlinks
	 * it). The +1 ref pins the master pvt for the steal/answer mutation below so
	 * it cannot be freed mid-flight by the channel thread. */
	master = fork->master;
	if (!master) {
		ast_mutex_unlock(&fork->lock);
		return -1;
	}
	ao2_ref(master, +1);
	fork->winner_picked = 1;
	fork->winner = child;
	fork->state = FORK_WINNER_PICKED;
	ast_mutex_unlock(&fork->lock);

	/* All master-pvt mutation (nh/rtp/srtp steal, owner->fds, answer, state) runs
	 * under master->lock so it is serialized against sofia_hangup, which NULLs
	 * master->owner and tears the dialog down under the same lock. Taken AFTER
	 * fork->lock is released (never nested) to preserve the master->lock →
	 * fork->lock order that sofia_hangup uses. */
	ast_mutex_lock(&master->lock);

	/* Move media resources from winner child to master.
	 * sofia_request_call pre-allocated master->nh (H_master) which never sent an
	 * INVITE in fork mode; destroy it before stealing the winner's handle or it
	 * (and its su_home arena) leaks. Mirrors the master->rtp/vrtp explicit
	 * destroy-before-steal below. On sofia_thread so synchronous destroy is safe;
	 * bind(NULL) first neutralizes any in-flight event for H_master. */
	if (master->nh) {
		nua_handle_t *old_nh = master->nh;
		master->nh = NULL;
		nua_handle_bind(old_nh, NULL);
		nua_handle_destroy(old_nh);
	}
	master->nh = child->nh;
	child->nh = NULL;
	nua_handle_bind(master->nh, master);

	/* The winner CHILD generated the initial SDP offer (its sess_id/sess_version)
	 * and the dialog now continues on the master. Inherit the child's o= session
	 * identity so the first master-generated re-INVITE keeps the same sess-id (a
	 * fresh master->sess_id would change it, breaking RFC 3264 §8 in-dialog session
	 * identity after a forked call). */
	master->sess_id = child->sess_id;
	master->sess_version = child->sess_version;

	/* Set active contact on master from winner child's ruri (sip:exten@host:port) */
	if (master->peer && !ast_strlen_zero(child->ruri)) {
		const char *at = strchr(child->ruri, '@');
		if (at) {
			char rhost[64] = "";
			int rport = 5060;
			sofia_split_hostport_from_uri(at + 1, rhost, sizeof(rhost), &rport);	/* IPv6-aware */
			struct sofia_contact *contact = sofia_peer_find_contact_by_host_port(master->peer, rhost, rport);
			if (contact) {
				sofia_pvt_set_active_contact(master, contact);
				ao2_ref(contact, -1);
			}
		}
	}

	/* Explicitly destroy pre-existing master->rtp/vrtp BEFORE winner-steal:
	 * sofia_request_call pre-allocates master->rtp via sofia_rtp_init, so without
	 * this the steal below would leak the pre-fork master rtp instance. NULL-guard
	 * handles the non-fork path (master->rtp may be unset on alloc-fail re-tries). */
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

	/* Transfer SRTP context pointers from winner child to master so the master's
	 * RTP read/write paths use the validated keys. Loser children's srtp/vsrtp are
	 * freed by their own destructors (idempotent NULL guard handles the case where
	 * a loser never allocated). */
	master->srtp = child->srtp;
	child->srtp = NULL;
	master->vsrtp = child->vsrtp;
	child->vsrtp = NULL;

	/* Compute the stolen-RTP fds HERE (under master->lock, where master->rtp/vrtp
	 * are stable) but DEFER writing them into the channel's fds[] until below, under
	 * the CHANNEL lock on the reffed m_owner. Writing owner->fds[] here would re-read
	 * master->owner unlocked and race ast_do_masquerade's fd swap. */
	int win_fd[4] = { -1, -1, -1, -1 };
	if (master->rtp) {
		win_fd[0] = ast_rtp_instance_fd(master->rtp, 0);
		win_fd[1] = ast_rtp_instance_fd(master->rtp, 1);
		if (master->vrtp) {
			win_fd[2] = ast_rtp_instance_fd(master->vrtp, 0);
			win_fd[3] = ast_rtp_instance_fd(master->vrtp, 1);
		}
	}

	/* Signal answer on master. ast_queue_control re-locks the owner channel;
	 * snapshot+ref it under master->lock, set master->state, drop master->lock,
	 * THEN queue/setstate on the reffed owner so we never reach a fresh channel
	 * lock while holding master->lock (canonical channel->pvt order; would
	 * otherwise invert against ast_hangup → sofia_hangup). */
	struct ast_channel *m_owner = master->owner;
	if (m_owner) {
		ast_channel_ref(m_owner);
	}
	master->state = SOFIA_DIALOG_STATE_UP;
	ast_mutex_unlock(&master->lock);

	if (m_owner) {
		/* Write the stolen-RTP fds under the CHANNEL lock (master->lock is already
		 * dropped, so this is the canonical channel->pvt order) — serializes with
		 * ast_do_masquerade's fds[] swap instead of racing it. */
		if (win_fd[0] >= 0) {
			ast_channel_lock(m_owner);
			ast_mutex_lock(&master->lock);
			/* Revalidate the owner under the channel lock — a masquerade between
			 * dropping master->lock above and here could have swapped master->owner,
			 * so only write fds[] when m_owner is STILL the master's channel. */
			if (master->owner == m_owner) {
				m_owner->fds[0] = win_fd[0];
				m_owner->fds[1] = win_fd[1];
				if (win_fd[2] >= 0) {
					m_owner->fds[2] = win_fd[2];
					m_owner->fds[3] = win_fd[3];
				}
			}
			ast_mutex_unlock(&master->lock);
			ast_channel_unlock(m_owner);
		}
		ast_queue_control(m_owner, AST_CONTROL_ANSWER);
		ast_setstate(m_owner, AST_STATE_UP);
		ast_channel_unref(m_owner);
	}

	ast_verbose("Sofia: Fork winner picked - branch %s for peer '%s' (%s)\n",
		child->fork_branch_id, master->peername, fork->fork_id);

	/* Release the master lifetime ref taken under fork->lock above. master->peername
	 * read in the verbose log is an immutable string field, so it is safe while the
	 * ref still pins the struct. */
	ao2_ref(master, -1);

	/* Cancel + unlink all losing siblings via ao2_callback (safe iterator-while-unlink). */
	ao2_callback(fork->children, OBJ_UNLINK | OBJ_MULTIPLE | OBJ_NODATA,
		sofia_fork_cancel_loser_cb, child);

	/* Winner child's resources are now on master; unlink the empty shell */
	ao2_unlink(dialogs, child);
	ao2_unlink(fork->children, child);

	return 0;
}

/* A counted fork child has failed or been rejected: drop the live count, unlink it
 * from both containers, and — if it was the last live branch with no winner picked —
 * queue HANGUP on the master so the call fails promptly instead of hanging. SIP
 * teardown (BYE for a rejected 2xx, nothing for a 3xx) is the CALLER's job. Returns
 * the remaining live child count (snapshotted under fork->lock) for logging.
 * sofia_thread only. Shared by the status>=300 branch and the 2xx-winner-rejected
 * (rc!=0) branch so the accounting cannot drift between them. */
static int sofia_fork_child_failed(struct sofia_fork *fork, struct sofia_pvt *pvt)
{
	int empty, picked, remaining;
	struct sofia_pvt *m;
	ast_mutex_lock(&fork->lock);
	fork->child_count--;
	ao2_unlink(fork->children, pvt);
	ast_mutex_unlock(&fork->lock);
	ao2_unlink(dialogs, pvt);
	/* Snapshot + ref fork->master under fork->lock so the all-children-failed HANGUP
	 * cannot race a concurrent master sofia_hangup into a UAF. */
	ast_mutex_lock(&fork->lock);
	empty = (fork->child_count == 0);
	remaining = fork->child_count;
	picked = fork->winner_picked;
	m = fork->master;
	if (m) {
		ao2_ref(m, +1);
	}
	ast_mutex_unlock(&fork->lock);
	if (m) {
		if (empty && !picked) {
			/* ABBA fix: snapshot+ref m->owner under m->lock, drop it, then queue
			 * HANGUP on the reffed owner (never hold m->lock across the channel lock). */
			struct ast_channel *m_owner;
			ast_mutex_lock(&m->lock);
			m_owner = m->owner;
			if (m_owner) {
				ast_channel_ref(m_owner);
			}
			ast_mutex_unlock(&m->lock);
			if (m_owner) {
				ast_queue_control(m_owner, AST_CONTROL_HANGUP);
				ast_channel_unref(m_owner);
			}
		}
		ao2_ref(m, -1);
	}
	return remaining;
}

static struct ast_channel *sofia_request_call(const char *type, format_t format, const struct ast_channel *requestor, void *data, int *cause);
static int sofia_call(struct ast_channel *ast, char *dest, int timeout);
static int sofia_hangup(struct ast_channel *ast);
static int sofia_answer(struct ast_channel *ast);
static struct ast_frame *sofia_read(struct ast_channel *ast);
static int sofia_write(struct ast_channel *ast, struct ast_frame *frame);
static int sofia_write_video(struct ast_channel *ast, struct ast_frame *frame);
/* Outbound text-message via nua_message API (chan_sip sip_sendtext parity).
 * Skips an is_method_allowed check — the UA replies 405 if unsupported
 * (best-effort send). Wired into sofia_tech.send_text below. */
static int sofia_send_text(struct ast_channel *ast, const char *text);
static int sofia_indicate(struct ast_channel *ast, int condition, const void *data, size_t datalen);
static int sofia_queryoption(struct ast_channel *chan, int option, void *data, int *datalen);
/* allowexternaldomains forward-decl: sofia_check_sip_domain is called from
 * sofia_process_invite and sofia_process_refer, which are defined before the
 * helper's definition. */
static int sofia_check_sip_domain(const char *domain);
static int sofia_fixup(struct ast_channel *oldchan, struct ast_channel *newchan);
static int sofia_send_digit_begin(struct ast_channel *ast, char digit);
static int sofia_send_digit_end(struct ast_channel *ast, char digit, unsigned int duration);
static const char *sofia_get_callid(struct ast_channel *ast);
static int sofia_devicestate(void *data);	/* BLF/presence: report SIP/<peer> device state to the core */

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
	.devicestate = sofia_devicestate,
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

/* T.38 fax UDPTL ast_udptl_protocol registration (chan_sip parity).
 * .type="SIP" matches chan_sip; mutual-exclusive load with chan_sip prevents a
 * .type collision (only one driver may register .type="SIP" per the
 * ast_udptl_proto_register uniqueness rule).
 *
 * The callbacks expose pvt->udptl while T.38 negotiation is in progress or
 * active. sofia_set_udptl_peer is intentionally a no-op, so chan_sofia keeps
 * UDPTL in the PBX media path instead of handing direct UDPTL relay to a peer. */
static struct ast_udptl *sofia_get_udptl_peer(struct ast_channel *chan);
static int sofia_set_udptl_peer(struct ast_channel *chan, struct ast_udptl *udptl);

static struct ast_udptl_protocol sofia_udptl = {
	.type = "SIP",
	.get_udptl_info = sofia_get_udptl_peer,
	.set_udptl_peer = sofia_set_udptl_peer,
};

static struct ast_udptl *sofia_get_udptl_peer(struct ast_channel *chan)
{
	/* Return pvt->udptl when T.38 negotiation is in progress or active
	 * (chan_sip sip_get_udptl_peer parity). Gate on t38_state >= PEER_REINVITE
	 * (which already implies udptl allocated by sofia_parse_sdp lazy-create).
	 * NULL means no UDPTL session is available; direct UDPTL transfer is not
	 * enabled by sofia_set_udptl_peer(), so the PBX stays in the media path.
	 *
	 * pvt->lock is taken around the state + udptl reads, then dropped before
	 * return so the caller doesn't see the chan_sofia mutex held. */
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

/* Forward declarations for the T.38 helper cluster — sofia_change_t38_state +
 * sofia_interpret_t38_parameters + sofia_t38_abort (5s timer callback). Defined
 * below; the forward-decl is needed because sofia_t38_abort references
 * sofia_change_t38_state which appears AFTER it. */
static void sofia_change_t38_state(struct sofia_pvt *pvt, int new_state);
static int sofia_interpret_t38_parameters(struct sofia_pvt *pvt, const struct ast_control_t38_parameters *parameters);
static int sofia_t38_abort(const void *data);

/* sofia_change_t38_state — 4-state machine (chan_sip parity)
 * T38_DISABLED ↔ LOCAL_REINVITE / PEER_REINVITE ↔ ENABLED. Queues an
 * AST_CONTROL_T38_PARAMETERS frame for 3 of 4 states (LOCAL_REINVITE is silent —
 * wait until we get a peer response). max_ifp is wired via
 * ast_udptl_get_far_max_ifp on PEER_REINVITE + ENABLED transitions;
 * ast_udptl_set_tag on every transition for log-correlation. */
static void sofia_change_t38_state(struct sofia_pvt *pvt, int new_state)
{
	int old;
	struct ast_control_t38_parameters parameters = { .request_response = 0 };
	struct ast_channel *chan;

	if (!pvt) {
		return;
	}
	/* Idempotency early-out: don't bother changing if we are already in the state
	 * wanted. Without this gate, re-entering the same state queues duplicate
	 * AST_CONTROL_T38_PARAMETERS frames — app_fax/res_fax may double-process. */
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

	/* Queue control frame only when request_response is set; LOCAL_REINVITE
	 * leaves it 0 → no queue. */
	if (parameters.request_response) {
		ast_queue_control_data(chan, AST_CONTROL_T38_PARAMETERS, &parameters, sizeof(parameters));
	}

	/* Emit an AMI T38FaxNegotiation event on every T.38 state transition (chan_sip
	 * emits no AMI for T.38 transitions). Done once at this single helper site.
	 * EVENT_FLAG_SYSTEM since this fork lacks EVENT_FLAG_SECURITY. Fields:
	 * ChannelType: SIP + Channel + Uniqueid + Peer + State + RequestResponse
	 * + MaxIfp + MaxDatagram + Version + RateManagement + EC. */
	{
		const char *state_str = "Unknown";
		const char *rr_str = "None";
		const char *rm_str = "transferredTCF";
		const char *ec_str = "None";
		/* reload-UAF fix: pvt->peer->name is an unbounded peer stringfield; the
		 * reload writer (sofia_parse_peer_config on sofia_thread) frees its pool
		 * under peer->lock when the value grows, so a lock-free read of
		 * pvt->peer->name would be a crash-UAF racing reload. Snapshot it under
		 * peer->lock into a local, then emit the AMI event using the local.
		 * LOCK ORDER: peer->lock is taken AFTER any already-held lock here.
		 * Three callers reach sofia_change_t38_state:
		 *   (1) sofia_indicate (channel-locked by core, no pvt->lock) -> order
		 *       channel -> peer;
		 *   (2) sofia_parse_sdp on sofia_thread (no pvt/peer lock held);
		 *   (3) sofia_t38_abort which HOLDS pvt->lock across this call
		 *       -> order pvt -> peer.
		 * All three respect the canonical channel -> pvt -> peer-family order;
		 * the reload writer never takes pvt->lock under peer->lock, so no cycle. */
		char l_peername[256];	/* peer->name is unbounded; snapshot target */
		ast_copy_string(l_peername, "<unknown>", sizeof(l_peername));
		if (pvt->peer) {
			ast_mutex_lock(&pvt->peer->lock);
			if (pvt->peer->name) {
				ast_copy_string(l_peername, pvt->peer->name, sizeof(l_peername));
			}
			ast_mutex_unlock(&pvt->peer->lock);
		}
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
			/* "ChannelType: SIP" for chan_sip compat — all other chan_sofia
			 * AMI sites emit "SIP", not "Sofia". */
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
			l_peername,
			state_str,
			rr_str,
			parameters.max_ifp,
			pvt->udptl ? ast_udptl_get_local_max_datagram(pvt->udptl) : 0,
			parameters.version,
			rm_str,
			ec_str);
	}
}

/* sofia_interpret_t38_parameters — 6-op dispatcher (chan_sip parity) invoked
 * from the sofia_indicate AST_CONTROL_T38_PARAMETERS case. Handles
 * app_fax/res_fax requests:
 *   AST_T38_REQUEST_NEGOTIATE → move local state toward T.38
 *   AST_T38_REQUEST_TERMINATE → move local state away from T.38
 *   AST_T38_NEGOTIATED → peer accepted (PEER_REINVITE → ENABLED)
 *   AST_T38_TERMINATED → peer dropped session
 *   AST_T38_REFUSED → peer rejected offer
 *   AST_T38_REQUEST_PARMS → fax stack queries far-end advertised parms
 * max_ifp == 0 is a rejection gate → change_t38_state(DISABLED); version is
 * MIN-clamped. This helper owns state and parameter updates only: peer-offer
 * acceptance uses the existing response/SDP path, and app-originated outbound
 * T.38 reINVITE transmission is not emitted here. */
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
			/* max_ifp==0 rejection gate. Snapshot the PEER_REINVITE state BEFORE
			 * the DISABLED transition — sofia_change_t38_state() overwrites
			 * pvt->t38_state, so testing it after the change always failed and the
			 * timer-cancel below was dead code. */
			int was_peer_reinvite = (pvt->t38_state == SOFIA_T38_PEER_REINVITE);
			sofia_change_t38_state(pvt, SOFIA_T38_DISABLED);
			/* Cancel the t38id 5s timer (and dec the refcount for the stored
			 * dialog ptr). Without this cancel the scheduler holds a dangling
			 * 5s ghost ref per fax flow. */
			if (was_peer_reinvite && pvt->t38id != -1 && sofia_sched) {
				if (ast_sched_thread_del(sofia_sched, pvt->t38id) == 0) {
					ao2_ref(pvt, -1);
				}
				pvt->t38id = -1;
			}
		} else if (pvt->t38_state == SOFIA_T38_PEER_REINVITE) {
			/* Cancel the t38id 5s timer — accepting the peer offer, no longer
			 * need the timeout. */
			if (pvt->t38id != -1 && sofia_sched) {
				if (ast_sched_thread_del(sofia_sched, pvt->t38id) == 0) {
					ao2_ref(pvt, -1);
				}
				pvt->t38id = -1;
			}
			/* Peer offered T.38; app_fax accepts. Merge our_parms with
			 * their_parms (chan_sip parity). */
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
			/* MIN-clamp version per RFC 3362 */
			pvt->t38_our_parms.version = MIN(pvt->t38_our_parms.version, pvt->t38_their_parms.version);
			pvt->t38_our_parms.rate_management = pvt->t38_their_parms.rate_management;
			ast_udptl_set_local_max_ifp(pvt->udptl, pvt->t38_our_parms.max_ifp);
			sofia_change_t38_state(pvt, SOFIA_T38_ENABLED);
			/* State is now enabled, so response SDP generation can include the
			 * T.38 block because pvt->udptl exists. */
		} else if (pvt->t38_state != SOFIA_T38_ENABLED) {
			/* app_fax requests outbound T.38 reINVITE (voice → fax). */
			pvt->t38_our_parms = *parameters;
			ast_udptl_set_local_max_ifp(pvt->udptl, pvt->t38_our_parms.max_ifp);
			sofia_change_t38_state(pvt, SOFIA_T38_LOCAL_REINVITE);
			/* Records LOCAL_REINVITE state; the outbound SIP reINVITE is not
			 * sent by this helper. */
		}
		break;
	case AST_T38_TERMINATED:
	case AST_T38_REFUSED:
	case AST_T38_REQUEST_TERMINATE:
		if (pvt->t38_state == SOFIA_T38_PEER_REINVITE) {
			/* Cancel the t38id 5s timer — fax stack rejecting the peer offer. */
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
		 * their_parms via control frame. */
		if (pvt->t38_state == SOFIA_T38_PEER_REINVITE) {
			struct ast_control_t38_parameters reply;
			/* Cancel the t38id 5s timer — fax stack acknowledging negotiation;
			 * timeout no longer needed. */
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

/* sofia_t38_abort — 5-second reINVITE timeout callback (chan_sip sip_t38_abort
 * parity). Without this timer, peers that fail to ack the 200 OK leave chan_sofia
 * stuck in T38_PEER_REINVITE forever. Returns 0 = one-shot. Drops the ao2 ref
 * taken at ast_sched_thread_add. Locks pvt for the state read; releases before
 * queue (avoids deadlock with channel-locks in ast_queue_control_data).
 * The 488 Not Acceptable Here is a nua_* call and must run on sofia_thread, not
 * this ast_sched thread: the owner-dance + sofia_change_t38_state (which only
 * queues a channel frame) stay on the sched thread; only the nua_respond is
 * marshaled, with a FRESH +1 pvt ref. */
int sofia_dispatch_to_root_thread(void (*callback)(void *), void *data);
static void sofia_t38_respond_488_root(void *data)
{
	struct sofia_pvt *pvt = data;

	ast_mutex_lock(&pvt->lock);
	if (pvt->nh) {
		nua_respond(pvt->nh, 488, "Not Acceptable Here", TAG_END());
	}
	ast_mutex_unlock(&pvt->lock);
	ao2_ref(pvt, -1);
}

static int sofia_t38_abort(const void *data)
{
	struct sofia_pvt *pvt = (struct sofia_pvt *)data;
	int do_disable = 0;

	if (!pvt) {
		return 0;
	}

	/* TOCTOU fix on the pvt->owner + pvt->t38_state read-then-act pattern: hold
	 * pvt->lock across sofia_change_t38_state (else sofia_hangup could null
	 * pvt->owner between read and call). Because that queues
	 * AST_CONTROL_T38_PARAMETERS via ast_queue_control_data (which takes the
	 * channel lock), first ref+lock pvt->owner in canonical channel->pvt order
	 * (the recursive channel lock re-enters safely) to avoid a channel<->pvt ABBA
	 * deadlock with the PBX/bridge thread. When owner is NULL,
	 * sofia_change_t38_state early-returns (no queue), so that path is safe. */
	{
		int was_peer_reinvite = 0;
		struct ast_channel *owner = NULL;
		ast_mutex_lock(&pvt->lock);
		for (;;) {
			owner = pvt->owner;
			if (!owner) {
				break;
			}
			ast_channel_ref(owner);
			ast_mutex_unlock(&pvt->lock);
			ast_channel_lock(owner);
			ast_mutex_lock(&pvt->lock);
			if (pvt->owner == owner) {
				break;
			}
			ast_channel_unlock(owner);
			ast_channel_unref(owner);
			owner = NULL;
		}
		if (pvt->t38id != -1) {
			pvt->t38id = -1;
			if (pvt->t38_state == SOFIA_T38_PEER_REINVITE ||
			    pvt->t38_state == SOFIA_T38_LOCAL_REINVITE) {
				ast_log(LOG_NOTICE, "Sofia: T.38 reINVITE timeout (5s) on channel %s — aborting\n",
					owner ? owner->name : "<no-owner>");
				do_disable = 1;
				was_peer_reinvite = (pvt->t38_state == SOFIA_T38_PEER_REINVITE);
			}
		}
		if (do_disable) {
			/* Hold pvt->lock (and the channel lock taken above) across the state
			 * change to prevent owner-null TOCTOU and the queue lock inversion. */
			sofia_change_t38_state(pvt, SOFIA_T38_DISABLED);
			/* Emit 488 Not Acceptable Here to the peer when aborting
			 * T38_PEER_REINVITE. Only fires for PEER_REINVITE, not LOCAL_REINVITE
			 * (there we sent the re-INVITE — peer either responds or we time out).
			 * Plain status-phrase: SIPTAG_REASON_STR causes a 500 in sofia-sip. */
			if (was_peer_reinvite && pvt->nh) {
				/* Marshal the nua_respond onto sofia_thread with a FRESH +1 pvt ref (the
				 * scheduler ref stays with this callback for its ao2_ref(-1) below);
				 * sofia_t38_respond_488_root drops the fresh ref. */
				ao2_ref(pvt, +1);
				if (sofia_dispatch_to_root_thread(sofia_t38_respond_488_root, pvt) < 0) {
					ao2_ref(pvt, -1);
				}
			}
		}
		ast_mutex_unlock(&pvt->lock);
		if (owner) {
			ast_channel_unlock(owner);
			ast_channel_unref(owner);
		}
	}

	/* Drop the ref taken when scheduling */
	ao2_ref(pvt, -1);
	return 0;
}

/* Mark this dialog as "already gone" so a late 2xx arriving for it can be
 * recognised in the nua_r_invite status==200 branch and handled via the orphan
 * ACK+BYE path per RFC 3261 §13.2.2.4 / RFC 6026 (chan_sip sip_alreadygone
 * parity). Called from the non-2xx final response paths (status 484 + status
 * >= 300 catch-all) so the flag is set BEFORE the channel hangup races the late
 * 2xx, and from anywhere else the dialog has been abandoned (e.g. local
 * pre-answer hangup). */
static void sofia_alreadygone(struct sofia_pvt *pvt)
{
	if (!pvt) {
		return;
	}
	ast_debug(3, "Sofia: setting alreadygone on dialog %s\n",
		pvt->callid ? pvt->callid : "(no-callid)");
	pvt->alreadygone = 1;
}

/* Safety-net timer for REFER transferer-leg BYE deferral. After we send the
 * terminal NOTIFY 200 OK for a transfer, sofia_hangup leaves the SIP dialog
 * alive so the transferer's UA can BYE per RFC 5589 §6.1. If no BYE arrives
 * within SOFIA_DEFER_BYE_TIMEOUT_MS this callback fires nua_bye itself so we
 * don't leak the dialog. Returns 0 = one-shot. Drops the ao2 ref taken at
 * ast_sched_thread_add. nua_bye must run on sofia_thread, NOT this ast_sched
 * thread: the sched callback only clears its sched-id and marshals. */
static void sofia_defer_bye_root(void *data)
{
	struct sofia_pvt *pvt = data;

	ast_mutex_lock(&pvt->lock);
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

	/* The scheduler's pvt ref was TRANSFERRED to this dispatch — drop it now. */
	ao2_ref(pvt, -1);
}

static int sofia_defer_bye_cb(const void *data)
{
	struct sofia_pvt *pvt = (struct sofia_pvt *)data;

	if (!pvt) {
		return 0;
	}

	ast_mutex_lock(&pvt->lock);
	pvt->defer_bye_sched_id = -1;
	ast_mutex_unlock(&pvt->lock);

	/* Marshal the nua_bye onto sofia_thread, TRANSFERRING the scheduler's pvt ref
	 * to the dispatch (sofia_defer_bye_root drops it). On dispatch failure, tear the
	 * dialog down here so the pvt is not leaked (the deferred BYE is then lost). */
	if (sofia_dispatch_to_root_thread(sofia_defer_bye_root, pvt) < 0) {
		/* Mirror the handler's terminal state on the failure path too — the deferred
		 * BYE is lost, but the dialog must still transition DOWN and be collected
		 * (otherwise defer_bye stays set and the state is left mid-teardown). */
		ast_mutex_lock(&pvt->lock);
		pvt->defer_bye = 0;
		pvt->state = SOFIA_DIALOG_STATE_DOWN;
		ast_mutex_unlock(&pvt->lock);
		ao2_unlink(dialogs, pvt);
		ao2_ref(pvt, -1);
	}
	return 0;
}

/* Allocate ast_dsp and configure it for incoming audio tone detection
 * (chan_sip enable_dsp_detect parity for DTMF); also enables DSP fax CNG
 * detection when faxdetect=cng is configured.
 *
 * Idempotent: a second call is a no-op if pvt->dsp is already allocated,
 * preventing double-allocation on a race between sofia_call entry and
 * sofia_process_invite entry on a forked outbound peer.
 *
 * DSP allocation requires inband/auto DTMF mode or fax CNG detection; fax-CNG
 * reuses the same DSP instance with DSP_FEATURE_FAX_DETECT.
 *
 * Caller must ensure pvt->rtp is bound (wire-in AFTER rtp_init in
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
	/* DSP fax-CNG tone detection is enabled when the peer has faxdetect=cng
	 * (or cng,t38). CNG detection emits an AST_FRAME_DTMF subclass 'f' on
	 * inbound audio → the sofia_read post-DSP path async-gotos the channel to
	 * the "fax" extension. */
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
	/* Apply the DSP_DIGITMODE_RELAXDTMF flag when sofia_cfg.relaxdtmf is set
	 * (relaxes the threshold for poor-quality-line DTMF detection). Only set the
	 * DTMF mode when DTMF detection is enabled (the fax-only path skips digitmode
	 * setup since no DTMF processing is needed). */
	if (dtmf_inband) {
		ast_dsp_set_digitmode(pvt->dsp, DSP_DIGITMODE_DTMF |
			(sofia_cfg.relaxdtmf ? DSP_DIGITMODE_RELAXDTMF : 0));
	}
}

/* Release ast_dsp (chan_sip disable_dsp_detect parity). NULL-safe.
 * Single-callsite from sofia_pvt_destructor. */
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
	 * int — cast for API conformance. production sofia.conf line tos_audio=ef
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
	 * on-hold state; rtpkeepalive sends periodic keepalive packets. production
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

/* Is payload type `pt` already present as a whole token in the space-separated
 * SDP m= payload list? Used to avoid emitting telephone-event on a PT a negotiated
 * codec already took (a duplicate PT is malformed; some UAs reject the m= line). */
static int sofia_sdp_pt_in_use(const char *list, int pt)
{
	char needle[8];
	const char *p;
	size_t nl;

	if (ast_strlen_zero(list)) {
		return 0;
	}
	snprintf(needle, sizeof(needle), "%d", pt);
	nl = strlen(needle);
	for (p = list; (p = strstr(p, needle)); p += nl) {
		char before = (p == list) ? ' ' : p[-1];
		char after = p[nl];
		if ((before == ' ' || before == '\0') && (after == ' ' || after == '\0')) {
			return 1;
		}
	}
	return 0;
}

/* Bounded SDP-fragment appender. sofia_generate_sdp builds the payload-type list,
 * the rtpmap block, and the video equivalents in fixed stack buffers; unbounded
 * strcat/strncat could overrun or silently truncate into a half-built SDP. Appends
 * src to dst only if it fully fits (room for the NUL), else returns -1; callers OR
 * the result into an `overflow` flag and return NULL (treated as "no SDP") if set. */
static int sofia_sdp_cat(char *dst, size_t dstsize, const char *src)
{
	size_t dlen = strlen(dst);
	size_t slen = strlen(src);
	if (dlen + slen + 1 > dstsize) {
		return -1;
	}
	memcpy(dst + dlen, src, slen + 1);
	return 0;
}

static char *sofia_generate_sdp(struct sofia_pvt *pvt, char *buf, size_t len)
{
	struct ast_sockaddr rtp_addr;
	struct ast_sockaddr dest_addr;
	const char *sdp_family;
	char host[128];
	int port;
	/* sockaddr_storage handles both AF_INET + AF_INET6; a plain struct sockaddr_in
	 * would silently truncate an IPv6 getsockname result. Family-aware extraction
	 * below dispatches on ss_family. */
	struct sockaddr_storage sin;
	socklen_t sinlen = sizeof(sin);
	char payload_buf[512] = "";
	char rtpmap_buf[2048] = "";
	char tmp_buf[128];
	int first = 1;
	int i;
	format_t fmt;
	format_t emitted = 0;
	int overflow = 0;	/* set if any SDP fragment would overrun its fixed buffer */

	if (!pvt || !pvt->rtp) {
		return NULL;
	}

	/* Get local address from RTP fd. sockaddr_storage + ss_family dispatch so an
	 * IPv6 RTP socket is handled (was AF_INET-hardcoded). */
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
		/* getsockname() failed (transient RTP fd state). Read the bound port from
		 * the resolved sockaddr; port=0 would emit "m=audio 0" = "no media this leg"
		 * (RFC 4566 §5.14), accepted by the peer but with no RTP flow. */
		port = ast_sockaddr_port(&rtp_addr);
	}

	/* 4-priority host chain for the SDP c= line. No `registered` gate (an
	 * outbound-to-static-trunk peer would otherwise leave c= as 0.0.0.0 from the
	 * bound socket). Priority (highest wins, evaluated bottom-up so later clauses
	 * override earlier):
	 *   (1) getsockname() / rtp instance local addr — set above (fallback)
	 *   (2) pvt->ourip — outbound: kernel-routed source IP from sofia_resolve_ourip
	 *   (3) Externaddr — sofia_should_use_externaddr(target)
	 *   (4) Direct media (pvt->redirip) — bridged peer's RTP target wins over all
	 * Inbound: pvt->ourip stays zero, pvt->peer may be NULL or src_addr unset —
	 * falls through to (1) cleanly. */
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
			overflow |= sofia_sdp_cat(payload_buf, sizeof(payload_buf), " ");
		snprintf(tmp_buf, sizeof(tmp_buf), "%d", pt);
		overflow |= sofia_sdp_cat(payload_buf, sizeof(payload_buf), tmp_buf);
		first = 0;
		if (channels)
			snprintf(tmp_buf, sizeof(tmp_buf), "a=rtpmap:%d %s/%u/%d\r\n", pt, enc, rate, channels);
		else
			snprintf(tmp_buf, sizeof(tmp_buf), "a=rtpmap:%d %s/%u\r\n", pt, enc, rate);
		overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
		/* fmtp for specific codecs */
		if (fmt == AST_FORMAT_G729A) {
			snprintf(tmp_buf, sizeof(tmp_buf), "a=fmtp:%d annexb=no\r\n", pt);
			overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
		} else if (fmt == AST_FORMAT_OPUS) {
			snprintf(tmp_buf, sizeof(tmp_buf), "a=fmtp:%d useinbandfec=1;usedtx=0\r\n", pt);
			overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
		} else if (fmt == AST_FORMAT_ILBC) {
			snprintf(tmp_buf, sizeof(tmp_buf), "a=fmtp:%d mode=20\r\n", pt);
			overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
		}
		emitted |= fmt;
		/* preferred_codec_only (chan_sip parity): narrow to the single most-preferred
		 * codec. Applies to both initial-INVITE-offer and response paths via this single
		 * helper. After the first successful emission, break the prefs loop (and skip the
		 * fallback loop) so only that codec appears in the m=audio rtpmap list. */
		if (pvt->peer && pvt->peer->preferred_codec_only) {
			break;
		}
	}

	/* Fallback: emit any remaining capability bits not in prefs.
	 * Skip the fallback when preferred_codec_only narrowing is active. */
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
			overflow |= sofia_sdp_cat(payload_buf, sizeof(payload_buf), " ");
		snprintf(tmp_buf, sizeof(tmp_buf), "%d", pt);
		overflow |= sofia_sdp_cat(payload_buf, sizeof(payload_buf), tmp_buf);
		first = 0;
		if (channels)
			snprintf(tmp_buf, sizeof(tmp_buf), "a=rtpmap:%d %s/%u/%d\r\n", pt, enc, rate, channels);
		else
			snprintf(tmp_buf, sizeof(tmp_buf), "a=rtpmap:%d %s/%u\r\n", pt, enc, rate);
		overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
		if (fmt == AST_FORMAT_G729A) {
			snprintf(tmp_buf, sizeof(tmp_buf), "a=fmtp:%d annexb=no\r\n", pt);
			overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
		} else if (fmt == AST_FORMAT_OPUS) {
			snprintf(tmp_buf, sizeof(tmp_buf), "a=fmtp:%d useinbandfec=1;usedtx=0\r\n", pt);
			overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
		} else if (fmt == AST_FORMAT_ILBC) {
			snprintf(tmp_buf, sizeof(tmp_buf), "a=fmtp:%d mode=20\r\n", pt);
			overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
		}
		emitted |= fmt;
	}

	/* telephone-event: prefer PT 101 (interop default) but if a negotiated codec
	 * already took it (dynamic PTs 96..127 can land on 101), pick the first free
	 * dynamic PT so the emitted m= line has no duplicate payload type. */
	{
		int te_pt = 101;
		if (sofia_sdp_pt_in_use(payload_buf, te_pt)) {
			for (te_pt = 96; te_pt <= 127 && sofia_sdp_pt_in_use(payload_buf, te_pt); te_pt++) {
				;
			}
			if (te_pt > 127) {
				te_pt = 101;	/* no free dynamic PT — collision unavoidable */
			}
		}
		if (!first) {
			overflow |= sofia_sdp_cat(payload_buf, sizeof(payload_buf), " ");
		}
		snprintf(tmp_buf, sizeof(tmp_buf), "%d", te_pt);
		overflow |= sofia_sdp_cat(payload_buf, sizeof(payload_buf), tmp_buf);
		snprintf(tmp_buf, sizeof(tmp_buf), "a=rtpmap:%d telephone-event/8000\r\n", te_pt);
		overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
		snprintf(tmp_buf, sizeof(tmp_buf), "a=fmtp:%d 0-16\r\n", te_pt);
		overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
	}

	/* Append local a=crypto for SDES-SRTP. sdp_crypto_attrib returns the full
	 * "a=crypto:tag suite inline:key64\r\n" string including prefix + CRLF. */
	if (pvt->srtp && pvt->srtp->crypto) {
		const char *a_crypto = sdp_crypto_attrib(pvt->srtp->crypto);
		if (a_crypto) {
			overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), a_crypto);
		}
	}

	/* SDP family-conditional emission. The ast_sockaddr_is_ipv4_mapped gate makes
	 * `::ffff:1.2.3.4` emit "IP4" (RFC 6052 §2.2, RFC 4038 §4.2 prefer-IPv4-for-
	 * IPv4-mapped). Parses `host` (IPv4 dot / IPv6 colon / hostname) so family-detect
	 * handles all 4 priority-chain producers uniformly. */
	if (ast_sockaddr_parse(&dest_addr, host, PARSE_PORT_FORBID) &&
	    ast_sockaddr_is_ipv6(&dest_addr) &&
	    !ast_sockaddr_is_ipv4_mapped(&dest_addr)) {
		sdp_family = "IP6";
	} else {
		sdp_family = "IP4";
	}

	/* Assemble audio SDP — m= proto switches to RTP/SAVP when SRTP active */
	/* Set the o= session-id ONCE per dialog and bump only the session-version on each
	 * generated SDP (RFC 4566 5.2 / RFC 3264 8 — the id MUST stay constant across all
	 * offers/answers in a dialog; only the version increments when the SDP changes). */
	if (!pvt->sess_id) {
		pvt->sess_id = (unsigned long)time(NULL);
	}
	pvt->sess_version++;
	if (snprintf(buf, len,
		"v=0\r\n"
		"o=- %lu %lu IN %s %s\r\n"
		"s=GABpbx\r\n"
		"c=IN %s %s\r\n"
		"t=0 0\r\n"
		"m=audio %d %s %s\r\n"
		"%s"
		"a=sendrecv\r\n",
		pvt->sess_id, pvt->sess_version,
		sdp_family, host, sdp_family, host, port,
		(pvt->srtp && pvt->srtp->crypto) ? "RTP/SAVP" : "RTP/AVP",
		payload_buf, rtpmap_buf) >= (int)len) {	/* truncated audio SDP */
		overflow = 1;
	}

	/* Append video block -- only when video capability present and vrtp allocated */
	if (pvt->vrtp && (pvt->capability & AST_FORMAT_VIDEO_MASK)) {
		struct ast_sockaddr vrtp_addr;
		char vhost[128];
		int vport = 0;
		/* sockaddr_storage + ss_family dispatch for video RTP getsockname
		 * (was IPv4-only struct sockaddr_in). */
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
			/* getsockname() failed: read the bound port. Without this vport stays 0,
			 * emitting "m=video 0" = "no media" (RFC 4566 §5.14). */
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
				overflow |= sofia_sdp_cat(vpayload_buf, sizeof(vpayload_buf), " ");
			snprintf(tmp_buf, sizeof(tmp_buf), "%d", pt);
			overflow |= sofia_sdp_cat(vpayload_buf, sizeof(vpayload_buf), tmp_buf);
			vfirst = 0;
			snprintf(tmp_buf, sizeof(tmp_buf), "a=rtpmap:%d %s/%u\r\n", pt, enc, rate);
			overflow |= sofia_sdp_cat(vrtpmap_buf, sizeof(vrtpmap_buf), tmp_buf);
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
				overflow |= sofia_sdp_cat(vpayload_buf, sizeof(vpayload_buf), " ");
			snprintf(tmp_buf, sizeof(tmp_buf), "%d", pt);
			overflow |= sofia_sdp_cat(vpayload_buf, sizeof(vpayload_buf), tmp_buf);
			vfirst = 0;
			snprintf(tmp_buf, sizeof(tmp_buf), "a=rtpmap:%d %s/%u\r\n", pt, enc, rate);
			overflow |= sofia_sdp_cat(vrtpmap_buf, sizeof(vrtpmap_buf), tmp_buf);
			emitted |= fmt;
		}

		/* Append video a=crypto if vsrtp installed */
		if (pvt->vsrtp && pvt->vsrtp->crypto) {
			const char *va_crypto = sdp_crypto_attrib(pvt->vsrtp->crypto);
			if (va_crypto) {
				overflow |= sofia_sdp_cat(vrtpmap_buf, sizeof(vrtpmap_buf), va_crypto);
			}
		}

		if (!vfirst) {
			int vlen = strlen(buf);
			/* maxcallbitrate (chan_sip parity): b=CT:%d at media-level after the
			 * m=video line (RFC 4566 §5.8). Gated on peer-known AND bitrate>0; the
			 * default 384 inheritance produces b=CT:384. */
			char bw_buf[32] = "";
			if (pvt->peer && pvt->peer->maxcallbitrate > 0) {
				snprintf(bw_buf, sizeof(bw_buf), "b=CT:%d\r\n", pvt->peer->maxcallbitrate);
			}
			if (snprintf(buf + vlen, len - vlen,
				"m=video %d %s %s\r\n"
				"%s"
				"%s"
				"a=sendrecv\r\n",
				vport,
				(pvt->vsrtp && pvt->vsrtp->crypto) ? "RTP/SAVP" : "RTP/AVP",
				vpayload_buf, bw_buf, vrtpmap_buf) >= (int)(len - vlen)) {	/* truncated video SDP */
				overflow = 1;
			}
		}
	}

	/* T.38 fax UDPTL SDP outbound emitter (chan_sip parity): append m=image PORT
	 * udptl t38 + a=T38Fax* attributes. Gated on pvt->udptl non-NULL (UDPTL session
	 * lazy-created on inbound peer T.38 OFFER or outbound REQUEST_NEGOTIATE).
	 * 5 mandatory attributes + 3 optional bare-flag attributes (FillBitRemoval /
	 * TranscodingMMR / TranscodingJBIG, emitted only when our_parms bit is set).
	 * RFC 4566 §5.14 m= line + §6 attribute syntax. */
	if (pvt->udptl) {
		struct ast_sockaddr udptl_local;
		int t38vlen = strlen(buf);
		const char *rate_mgmt_str;
		const char *udpec_str;
		unsigned int max_bitrate;
		unsigned int max_datagram;

		ast_udptl_get_us(pvt->udptl, &udptl_local);

		/* T38MaxBitRate enum→integer mapping (6-rate table). Default
		 * AST_T38_RATE_14400 per pvt->t38_our_parms init at sofia_pvt_alloc. */
		switch (pvt->t38_our_parms.rate) {
		case AST_T38_RATE_2400:  max_bitrate = 2400;  break;
		case AST_T38_RATE_4800:  max_bitrate = 4800;  break;
		case AST_T38_RATE_7200:  max_bitrate = 7200;  break;
		case AST_T38_RATE_9600:  max_bitrate = 9600;  break;
		case AST_T38_RATE_12000: max_bitrate = 12000; break;
		case AST_T38_RATE_14400: max_bitrate = 14400; break;
		default:                 max_bitrate = 14400; break;
		}

		/* T38FaxRateManagement default transferredTCF per RFC 3362 */
		switch (pvt->t38_our_parms.rate_management) {
		case AST_T38_RATE_MANAGEMENT_LOCAL_TCF:
			rate_mgmt_str = "localTCF";
			break;
		case AST_T38_RATE_MANAGEMENT_TRANSFERRED_TCF:
		default:
			rate_mgmt_str = "transferredTCF";
			break;
		}

		/* T38FaxUdpEC from the negotiated EC scheme; emit using the current scheme.
		 * NONE → omit the a=T38FaxUdpEC line. */
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
		if (snprintf(buf + t38vlen, len - t38vlen,
			"m=image %d udptl t38\r\n"
			"a=T38FaxVersion:%u\r\n"
			"a=T38MaxBitRate:%u\r\n"
			"a=T38FaxRateManagement:%s\r\n"
			"a=T38FaxMaxDatagram:%u\r\n",
			ast_sockaddr_port(&udptl_local),
			pvt->t38_our_parms.version,
			max_bitrate,
			rate_mgmt_str,
			max_datagram) >= (int)(len - t38vlen)) {	/* truncated T.38 SDP */
			overflow = 1;
		}

		/* 3 optional bare-flag attributes — emit when our_parms bit is set. */
		if (pvt->t38_our_parms.fill_bit_removal) {
			int blen = strlen(buf);
			if (snprintf(buf + blen, len - blen, "a=T38FaxFillBitRemoval\r\n") >= (int)(len - blen)) {
				overflow = 1;
			}
		}
		if (pvt->t38_our_parms.transcoding_mmr) {
			int blen = strlen(buf);
			if (snprintf(buf + blen, len - blen, "a=T38FaxTranscodingMMR\r\n") >= (int)(len - blen)) {
				overflow = 1;
			}
		}
		if (pvt->t38_our_parms.transcoding_jbig) {
			int blen = strlen(buf);
			if (snprintf(buf + blen, len - blen, "a=T38FaxTranscodingJBIG\r\n") >= (int)(len - blen)) {
				overflow = 1;
			}
		}

		/* T38FaxUdpEC emitted only when EC scheme is FEC or Redundancy (NONE = omit). */
		if (udpec_str) {
			int blen = strlen(buf);
			if (snprintf(buf + blen, len - blen, "a=T38FaxUdpEC:%s\r\n", udpec_str) >= (int)(len - blen)) {
				overflow = 1;
			}
		}
	}

	/* If any fragment overran a build buffer or the final SDP truncated, fail the whole
	 * SDP rather than emit a half-built body — every caller treats NULL as "no SDP". */
	if (overflow) {
		ast_log(LOG_WARNING, "Sofia: SDP for '%s' exceeded its build buffers (too many codecs/attributes) — emitting no SDP\n",
			S_OR(pvt->callid, "<unknown>"));
		return NULL;
	}

	return buf;
}

/* Parse one inbound a=crypto attribute. Returns 1 on accept (srtp installed),
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
	char *prefixed = NULL;	/* dynamic — validate the FULL a=crypto line, no truncation */
	/* Only tear down *srtp on failure if we allocated it in THIS call. On an in-dialog
	 * re-INVITE *srtp may be a live, already-validated SRTP context; a rejected/invalid
	 * a=crypto must NOT destroy it (that would silently downgrade the active media to
	 * plaintext and breaks the 488 "keep existing crypto" contract). A pre-existing
	 * context is left intact and we just reject the line. */
	int was_new = (*srtp == NULL);

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
			if (was_new) {
				sofia_srtp_destroy(*srtp);
				*srtp = NULL;
			}
			return 0;
		}
	}
	/* Build "crypto:<attr>" DYNAMICALLY so a long a=crypto line is validated in FULL.
	 * A fixed buffer + unchecked snprintf would truncate an overlong line, so
	 * sdp_crypto_process would validate a DIFFERENT line than the wire — an unsupported
	 * session-param or key lifetime in the tail could be silently dropped, bypassing its
	 * rejection. sdp_crypto_process is length-safe, so the full untruncated line is fine. */
	if (ast_asprintf(&prefixed, "crypto:%s", attr) < 0) {
		/* OOM — treat as crypto-not-OK and reject the offer (fail-closed). */
		if (was_new) {
			sofia_srtp_destroy(*srtp);
			*srtp = NULL;
		}
		return 0;
	}
	/* defer=1 — validate + stage only; the live add_srtp_policy is deferred to
	 * sdp_crypto_commit() after sofia_parse_sdp's reject gates pass. (The was_new
	 * rollback below still covers an immediate VALIDATION failure on this same call.) */
	{
		int rc = sdp_crypto_process((*srtp)->crypto, prefixed, rtp, 1);
		ast_free(prefixed);
		if (rc < 0) {
			if (was_new) {
				sofia_srtp_destroy(*srtp);
				*srtp = NULL;
			}
			return 0;
		}
	}
	(*srtp)->flags |= SRTP_CRYPTO_OFFER_OK;
	return 1;
}

/* On ANY sofia_parse_sdp reject, drop the staged-but-not-committed crypto and roll back
 * an SRTP context THIS parse lazily created, so a rejected re-INVITE leaves the live media
 * exactly as it was (no half-applied SRTP, no staged key a later parse could commit).
 * audio_was_new/video_was_new = the context did not exist before this parse. */
static void sofia_sdp_stage_rollback(struct sofia_pvt *pvt, int audio_was_new, int video_was_new)
{
	if (pvt->srtp && pvt->srtp->crypto) {
		sdp_crypto_clear_staged(pvt->srtp->crypto);
	}
	if (pvt->vsrtp && pvt->vsrtp->crypto) {
		sdp_crypto_clear_staged(pvt->vsrtp->crypto);
	}
	if (audio_was_new && pvt->srtp) {
		sofia_srtp_destroy(pvt->srtp);
		pvt->srtp = NULL;
	}
	if (video_was_new && pvt->vsrtp) {
		sofia_srtp_destroy(pvt->vsrtp);
		pvt->vsrtp = NULL;
	}
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
	int image_active_seen = 0;	/* a live UDPTL T.38 image leg was present this parse */
	/* Whether THIS parse's a=crypto lazily creates the SRTP context (for reject
	 * rollback). Captured AFTER the !pvt guard below — do not deref pvt here. */
	int audio_srtp_was_new = 0;
	int video_srtp_was_new = 0;

	if (!sip || !pvt || !pvt->rtp) {
		return 0;
	}

	/* pvt is non-NULL here — capture whether THIS parse's a=crypto lazily creates the
	 * SRTP context (for reject rollback) and clear any stale staged crypto up front so a
	 * prior rejected parse cannot leave a key this one commits. */
	audio_srtp_was_new = (pvt->srtp == NULL);
	video_srtp_was_new = (pvt->vsrtp == NULL);
	if (pvt->srtp && pvt->srtp->crypto) {
		sdp_crypto_clear_staged(pvt->srtp->crypto);
	}
	if (pvt->vsrtp && pvt->vsrtp->crypto) {
		sdp_crypto_clear_staged(pvt->vsrtp->crypto);
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

	/* Negotiate VIDEO from THIS SDP offer only. pvt->capability enters the loop holding
	 * the peer's CONFIGURED audio+video, so drop the config video bits up front; the
	 * per-media blocks below re-add ONLY the video actually offered. Combined with the
	 * audio block preserving (local_cap & VIDEO_MASK), this makes negotiation
	 * ORDER-INDEPENDENT: an SDP listing m=video before m=audio no longer loses video, and
	 * an SDP with no m=video no longer advertises stale config video. Audio stays narrowed
	 * per-offer by the audio block, so it needs no pre-clear. */
	/* Snapshot the pre-parse capability so EVERY reject path can restore it. sofia_parse_sdp
	 * must NOT mutate pvt->capability on a rejected SDP — otherwise the pre-clear (and the
	 * audio-block narrowing) would leave a rejected re-INVITE having stripped an ESTABLISHED
	 * call's video. Restored at the sdp_reject label. */
	format_t orig_capability = pvt->capability;
	pvt->capability &= ~AST_FORMAT_VIDEO_MASK;

	/* Validate-then-commit: snapshot the live media state the media loop mutates BEFORE the
	 * post-loop reject gates, so a rejected SDP restores it and leaves an established call
	 * untouched (RFC 3261 §14). (B) simple pvt fields; (C) RTP/UDPTL remote addresses.
	 * pvt->rtp is guaranteed. pvt->vrtp / pvt->udptl may be NULL now and be lazily created
	 * during the loop — those lazy creates use was_new-rollback, so here we only
	 * snapshot+restore a remote on an instance that ALREADY exists; had_vrtp/had_udptl gate
	 * the restore. */
	struct ast_control_t38_parameters orig_t38_their_parms = pvt->t38_their_parms;	/* (B) */
	unsigned int orig_t38_max_ifp = pvt->t38_max_ifp;				/* (B) */
	struct ast_sockaddr orig_audio_remote;						/* (C) */
	struct ast_sockaddr orig_video_remote;						/* (C) */
	struct ast_sockaddr orig_udptl_peer;						/* (C) */
	enum ast_t38_ec_modes orig_udptl_ec = UDPTL_ERROR_CORRECTION_NONE;		/* (C) */
	unsigned int orig_udptl_far_datagram = 0;					/* (C) */
	int had_vrtp = (pvt->vrtp != NULL);
	int had_udptl = (pvt->udptl != NULL);
	ast_sockaddr_setnull(&orig_audio_remote);
	ast_sockaddr_setnull(&orig_video_remote);
	ast_sockaddr_setnull(&orig_udptl_peer);
	ast_rtp_instance_get_remote_address(pvt->rtp, &orig_audio_remote);
	if (had_vrtp) {
		ast_rtp_instance_get_remote_address(pvt->vrtp, &orig_video_remote);
	}
	if (had_udptl) {
		ast_udptl_get_peer(pvt->udptl, &orig_udptl_peer);
		/* Snapshot the EFFECTIVE EC scheme + far_max_datagram so a rejected re-INVITE
		 * restores a PRE-EXISTING udptl's config. The getter values are value-faithful
		 * (post per-peer override + normalization), not raw-bit-exact for the -1/0 sentinel. */
		orig_udptl_ec = ast_udptl_get_error_correction_scheme(pvt->udptl);
		orig_udptl_far_datagram = ast_udptl_get_far_max_datagram(pvt->udptl);
	}

	/* The negotiated audio/video codec payload maps are built into these function-scope
	 * ast_rtp_codecs during the media loop, but the install into the live pvt->rtp/vrtp
	 * (ast_rtp_codecs_payloads_copy) is DEFERRED to the commit phase after every reject gate
	 * passes — so a rejected SDP never overwrites an established call's codec map. Init here;
	 * destroy at the commit copy AND at sdp_reject (clearing an unused/empty map is a safe
	 * no-op). staged_*_valid gates only the copy, not the clear. */
	struct ast_rtp_codecs staged_audio_codecs;
	struct ast_rtp_codecs staged_video_codecs;
	int staged_audio_valid = 0;
	int staged_video_valid = 0;
	ast_rtp_codecs_payloads_clear(&staged_audio_codecs, NULL);
	ast_rtp_codecs_payloads_clear(&staged_video_codecs, NULL);

	/* The chosen audio channel native format is computed during the media loop but APPLIED
	 * (o->nativeformats + ast_set_read/write_format — irreversible channel core mutations)
	 * only in the commit phase, so a rejected SDP never reformats an established channel.
	 * staged_chosen_audio_valid gates the deferred apply. */
	format_t staged_chosen_audio = 0;
	int staged_chosen_audio_valid = 0;

	/* The T.38 irreversible side-effects are STAGED here during the media loop and fired in
	 * the commit phase (after every reject gate) so a rejected SDP never touches the channel /
	 * T.38 state. The udptl INSTANCE is still created + configured in-loop
	 * (was_new-destroy-on-reject; a pre-existing udptl's peer/EC/far_datagram are
	 * snapshot-restored above), but its fds[5] channel attach and the
	 * state-change/timer/withdraw/async-goto-to-fax are all deferred. Advance (enter
	 * PEER_REINVITE) and withdraw (return to DISABLED) are mutually exclusive. */
	int t38_stage_fds5 = 0;			/* attach o->fds[5] = ast_udptl_fd(udptl) at commit (was_new only) */
	int t38_stage_enter_reinvite = 0;	/* sofia_change_t38_state(PEER_REINVITE) + arm t38id at commit */
	int t38_stage_withdraw = 0;		/* sofia_change_t38_state(DISABLED) + cancel t38id at commit */
	/* The fax-redirect inputs (owner exten/context + ast_exists_extension) are evaluated at
	 * COMMIT under the channel lock — only the advance intent is staged here (snapshot channel
	 * fields at commit, not during the loop). */

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
				/* R7 C2 (3-way): never feed an uninitialized ast_sockaddr to the
				 * RTP engine. ast_sockaddr_parse() returns 0 WITHOUT writing the
				 * destination on a malformed/non-IP c= address, so the old
				 * unchecked call left `remote` as stack garbage (a garbage ->len
				 * then drives ast_sockaddr_copy's memcpy). Track parse success and
				 * treat the NAT override as an explicit fallback source. */
				struct ast_sockaddr remote;
				int have_remote = ast_sockaddr_parse(&remote, addr, 0);
				if (have_remote) {
					ast_sockaddr_set_port(&remote, media->m_port);
				}
				/* NAT override (chan_sip parity): a NAT'd peer's SDP c= usually
				 * leaks its private LAN IP. Use peer->src_addr (registered public
				 * IP) for the host while keeping the SDP media port; symmetric-RTP /
				 * comedia refines the port on the first inbound packet. */
				if (pvt->peer
				    && (pvt->peer->nat & (SOFIA_NAT_FORCE_RPORT | SOFIA_NAT_COMEDIA))
				    && !ast_sockaddr_isnull(&pvt->peer->src_addr)) {
					struct ast_sockaddr nat_remote = pvt->peer->src_addr;
					ast_sockaddr_set_port(&nat_remote, media->m_port);
					remote = nat_remote;
					have_remote = 1;
				}
				/* Audio is mandatory: a c= we can neither parse nor NAT-override
				 * is malformed SDP -> reject. sdp_reject restores capability +
				 * staged SRTP and leaves an established call untouched (RFC 3261
				 * §14). A garbage conn-address is rejected even if a valid m=image
				 * (T.38) leg exists — distinct from the no-common-audio-CODEC T.38
				 * carve-out below. */
				if (!have_remote) {
					ast_log(LOG_WARNING, "Sofia: unparseable audio media address '%s' in SDP offer — rejecting\n", addr);
					goto sdp_reject;
				}
				ast_rtp_instance_set_remote_address(pvt->rtp, &remote);
			}

			{
				format_t local_cap = pvt->capability;
				format_t offered = 0;
				int noncodec = 0;
				sdp_rtpmap_t *rm;
				sdp_list_t *fmt;

				/* Re-init the staged map at the start of EACH m=audio block so a
				 * (rare) second m=audio line wins last. The install into pvt->rtp is
				 * deferred to the commit phase. */
				ast_rtp_codecs_payloads_clear(&staged_audio_codecs, NULL);

				/* Step 1: register PTs from m= line */
				for (fmt = media->m_format; fmt; fmt = fmt->l_next) {
					int pt = atoi(fmt->l_text);
					ast_rtp_codecs_payloads_set_m_type(&staged_audio_codecs, NULL, pt);
				}

				/* Step 2: override with a=rtpmap entries (handles dynamic PTs) */
				for (rm = media->m_rtpmaps; rm; rm = rm->rm_next) {
					if (rm->rm_encoding) {
						int rc = ast_rtp_codecs_payloads_set_rtpmap_type_rate(
							&staged_audio_codecs, NULL, rm->rm_pt, "audio",
							(char *)rm->rm_encoding, 0, rm->rm_rate);
						if (rc) {
							ast_rtp_codecs_payloads_unset(&staged_audio_codecs, NULL, rm->rm_pt);
						}
					}
				}

				/* Step 3: extract negotiated formats */
				ast_rtp_codecs_payload_formats(&staged_audio_codecs, &offered, &noncodec);

				/* Step 4: intersect with local capability.
				 * If audio was OFFERED but we share NO common audio codec, reject 488
				 * instead of accepting un-negotiated codecs (one-way / dead audio) —
				 * UNLESS the same SDP also offers a T.38/image leg (carve-out, chan_sip
				 * udptlportno parity), where the m=image handling below takes over. Do
				 * NOT overwrite pvt->capability on the reject path. */
				if ((local_cap & offered & AST_FORMAT_AUDIO_MASK) == 0) {
					int has_t38 = 0;
					sdp_media_t *mm;
					for (mm = sdp->sdp_media; mm; mm = mm->m_next) {
						if (mm->m_type == sdp_media_image
								&& mm->m_proto == sdp_proto_udptl
								&& mm->m_port != 0) {
							has_t38 = 1;
							break;
						}
					}
					if (!has_t38) {
						ast_log(LOG_WARNING, "Sofia: no common audio codec with peer — rejecting (488 Not Acceptable Here)\n");
						goto sdp_reject;	/* label clears staged codecs, frees the still-live parser, rolls back + restores capability */
					}
				}
				/* Narrow audio to the negotiated set, but PRESERVE this-SDP video.
				 * Config video was pre-cleared before the loop, so (local_cap & VIDEO_MASK)
				 * is ONLY the video a preceding m=video block already added (video-first
				 * case) — never stale config video. Audio-first/no-video cases leave it 0. */
				pvt->capability = (local_cap & offered) | (local_cap & AST_FORMAT_VIDEO_MASK);
				if (pvt->capability == 0) {
					ast_log(LOG_WARNING, "Sofia: No common codec with peer; falling back to local capability\n");
					pvt->capability = local_cap;
				}

				/* Step 5: codec map built; DEFER the install into pvt->rtp to the commit
				 * phase (after every reject gate) so a rejected SDP never overwrites the
				 * established codec map. */
				staged_audio_valid = 1;

				if (pvt->owner && (pvt->capability & AST_FORMAT_AUDIO_MASK)) {
					format_t chosen = ast_codec_choose(&pvt->prefs,
						pvt->capability & AST_FORMAT_AUDIO_MASK, 1);
					if (!chosen) {
						chosen = ast_best_codec(pvt->capability & AST_FORMAT_AUDIO_MASK);
					}
					if (chosen) {
						/* DEFER applying the channel native format (o->nativeformats +
						 * ast_set_read/write_format — irreversible) to the commit phase so a
						 * rejected SDP never reformats an established channel. The
						 * ref+lock+revalidate dance moves with it. */
						staged_chosen_audio = chosen;
						staged_chosen_audio_valid = 1;
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
				format_t offered = 0;
				int noncodec = 0;
				sdp_rtpmap_t *rm;
				sdp_list_t *vfmt;
				int have_remote;

				/* Same uninitialized-sockaddr guard as the audio
				 * leg. Video is optional, so on an unparseable c= with no NAT
				 * fallback we leave the existing video remote untouched (never
				 * hand garbage to the RTP engine) and still negotiate codecs. */
				have_remote = ast_sockaddr_parse(&remote, addr, 0);
				if (have_remote) {
					ast_sockaddr_set_port(&remote, media->m_port);
				}
				/* NAT override (chan_sip parity): mirror audio-side reasoning
				 * for video — SDP c= from a NAT'd peer typically leaks the
				 * private LAN IP; use peer->src_addr instead. */
				if (pvt->peer
				    && (pvt->peer->nat & (SOFIA_NAT_FORCE_RPORT | SOFIA_NAT_COMEDIA))
				    && !ast_sockaddr_isnull(&pvt->peer->src_addr)) {
					struct ast_sockaddr nat_remote = pvt->peer->src_addr;
					ast_sockaddr_set_port(&nat_remote, media->m_port);
					remote = nat_remote;
					have_remote = 1;
				}
				if (have_remote) {
					ast_rtp_instance_set_remote_address(pvt->vrtp, &remote);
				} else {
					ast_log(LOG_NOTICE, "Sofia: unparseable video media address '%s' in SDP — leaving video remote unchanged\n", addr);
				}

				ast_rtp_codecs_payloads_clear(&staged_video_codecs, NULL);

				for (vfmt = media->m_format; vfmt; vfmt = vfmt->l_next) {
					int pt = atoi(vfmt->l_text);
					ast_rtp_codecs_payloads_set_m_type(&staged_video_codecs, NULL, pt);
				}
				for (rm = media->m_rtpmaps; rm; rm = rm->rm_next) {
					if (rm->rm_encoding) {
						int rc = ast_rtp_codecs_payloads_set_rtpmap_type_rate(
							&staged_video_codecs, NULL, rm->rm_pt, "video",
							(char *)rm->rm_encoding, 0, rm->rm_rate);
						if (rc)
							ast_rtp_codecs_payloads_unset(&staged_video_codecs, NULL, rm->rm_pt);
					}
				}

				ast_rtp_codecs_payload_formats(&staged_video_codecs, &offered, &noncodec);
				if (offered & AST_FORMAT_VIDEO_MASK) {
					pvt->capability |= offered & AST_FORMAT_VIDEO_MASK;
				}
				/* Video codec map built — DEFER the install into pvt->vrtp to the
				 * commit phase. staged_video_valid implies pvt->vrtp exists (this
				 * block is gated on it). */
				staged_video_valid = 1;
			}
		} else if (media->m_type == sdp_media_image && media->m_port != 0) {
			/* T.38 fax UDPTL handling (chan_sip parity). sofia-sip natively types
			 * m=image media via the sdp_media_image / sdp_proto_udptl enums, so we
			 * ride typed enum dispatch rather than sscanf'ing the raw m= line.
			 *
			 * This block populates pvt->t38_their_parms from the peer's offer
			 * attributes, lazy-creates pvt->udptl, sets the UDPTL peer addr, and
			 * transitions pvt->t38_state to SOFIA_T38_PEER_REINVITE on first valid
			 * detect (committed past the reject gates below).
			 *
			 * RFC 5347 §2.5.2: T.38 attribute names are parsed case-insensitively;
			 * sofia-sip preserves the name+value as-given, so we lowercase a
			 * concatenated "name:value" buffer for sscanf matches. */
			sdp_attribute_t *a;
			sdp_connection_t *conn = media->m_connections;
			char addr[128];

			/* Verify proto is UDPTL via sofia-sip native enum */
			if (media->m_proto != sdp_proto_udptl) {
				ast_log(LOG_WARNING, "Sofia: ignoring m=image media with non-UDPTL proto\n");
				continue;
			}
			image_active_seen = 1;	/* a live UDPTL T.38 image leg is present this parse */

			if (!conn && sdp->sdp_connection) {
				conn = sdp->sdp_connection;
			}
			if (!conn || !conn->c_address) {
				continue;
			}

			/* Lazy-create UDPTL session (chan_sip parity, fresh-bind): a separate
			 * UDPTL socket, NOT reusing the audio RTP port. Reused across
			 * re-INVITEs; destroyed in sofia_pvt_destructor. NULL sched/io. */
			if (!pvt->udptl) {
				struct ast_sockaddr bindaddr;
				ast_sockaddr_parse(&bindaddr, sofia_cfg.bindaddr, 0);
				pvt->udptl = ast_udptl_new_with_bindaddr(NULL, NULL, 0, &bindaddr);
				if (!pvt->udptl) {
					ast_log(LOG_WARNING, "Sofia: failed to allocate UDPTL session for T.38 (peer offer ignored)\n");
					continue;
				}
				/* Attach UDPTL fd to channel fds[5] for sofia_read fd-5 dispatch
				 * (chan_sip parity). Covers the re-INVITE-arriving-after-channel-exists
				 * ordering (sofia_new only attaches if udptl pre-existed at channel-alloc).
				 * DEFER the fds[5] attach to the commit phase: it runs ONLY inside the
				 * udptl create block, so it is a was_new-only side-effect (a pre-existing
				 * udptl already had fds[5] wired). On reject the was_new udptl is destroyed,
				 * so no fd is ever wired. */
				t38_stage_fds5 = 1;
			}

			/* Set UDPTL peer address (chan_sip parity). Symmetric-RTP UDPTL
			 * destination gate: when peer has NAT (force_rport OR comedia) AND
			 * t38pt_usertpsource=yes, override the UDPTL DESTINATION with the RTP
			 * remote address (audio's actual seen endpoint, solving NAT for T.38
			 * fax over NAT'd peers); UDPTL PORT is always taken from m=image
			 * regardless. Without this gate NAT'd t38pt_usertpsource=yes peers get
			 * the WRONG UDPTL destination and fax fails. */
			snprintf(addr, sizeof(addr), "%s", conn->c_address);
			{
				/* The usertpsource branch fills `remote` from the (already-validated)
				 * audio RTP remote; the else-branch parses the image c= and MUST check
				 * the result — ast_sockaddr_parse() leaves `remote` untouched on failure.
				 * On an unparseable c= leave the UDPTL peer unchanged rather than set a
				 * garbage destination. */
				struct ast_sockaddr remote;
				int have_remote = 1;
				if (pvt->peer && pvt->peer->t38pt_usertpsource &&
				    (pvt->peer->nat & (SOFIA_NAT_FORCE_RPORT | SOFIA_NAT_COMEDIA)) &&
				    pvt->rtp) {
					ast_rtp_instance_get_remote_address(pvt->rtp, &remote);
				} else {
					have_remote = ast_sockaddr_parse(&remote, addr, 0);
				}
				if (have_remote) {
					ast_sockaddr_set_port(&remote, media->m_port);
					ast_udptl_set_peer(pvt->udptl, &remote);
				} else {
					ast_log(LOG_NOTICE, "Sofia: unparseable T.38 media address '%s' in SDP — leaving UDPTL peer unchanged\n", addr);
				}
			}

			/* Reset their_parms before parsing each new offer (chan_sip parity).
			 * EC defaults to NONE. */
			if (pvt->t38_state != SOFIA_T38_ENABLED) {
				memset(&pvt->t38_their_parms, 0, sizeof(pvt->t38_their_parms));
				ast_udptl_set_error_correction_scheme(pvt->udptl, UDPTL_ERROR_CORRECTION_NONE);
			}

			/* Walk a=T38Fax* attributes (chan_sip parity): 8 attributes (5 mandatory
			 * + 3 optional bare-flag). RFC 5347 §2.5.2 case-insensitive parsing via the
			 * lowercase concatenation buffer. */
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
					/* Apply per-peer override (chan_sip parity) */
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

			/* LOAD-BEARING — read peer-advertised max_ifp into pvt->t38_max_ifp.
			 * Without it, real-fax negotiation rejects on every call (chan_sip
			 * forces T38_DISABLED when parameters->max_ifp == 0). Used by
			 * sofia_change_t38_state via ast_udptl_get_far_max_ifp(pvt->udptl). */
			pvt->t38_max_ifp = ast_udptl_get_far_max_ifp(pvt->udptl);

			/* State transition: T38_DISABLED → T38_PEER_REINVITE on first detect
			 * (chan_sip parity). sofia_change_t38_state queues an
			 * AST_CONTROL_T38_PARAMETERS frame, tags the UDPTL session with the
			 * channel name, and populates parameters.max_ifp. A 5s reINVITE timeout
			 * is armed via ast_sched_thread_add + sofia_t38_abort; the pvt ref is
			 * transferred to the scheduler and the abort callback drops it. */
			if (pvt->t38_state == SOFIA_T38_DISABLED) {
				/* DEFER the state advance (sofia_change_t38_state queues a REQUEST_NEGOTIATE
				 * frame), the 5s t38id abort timer, AND the fax redirect to the commit phase.
				 * t38_state stays DISABLED through the loop, so the post-loop withdraw check
				 * reads the PRE-parse state, and a rejected SDP fires NONE of these. The whole
				 * fax redirect (faxdetect gating + exten/ctx + ast_exists_extension) is
				 * evaluated at commit under the channel lock, not here. */
				t38_stage_enter_reinvite = 1;
			}
		}
	}

	/* A re-INVITE that WITHDRAWS the image stream (m=image port 0, or no image m=
	 * line at all) must return T.38 to DISABLED — otherwise the fax state stays
	 * stuck active (chan_sip resets on udptlportno==-1). If no live UDPTL image leg
	 * was seen this parse but T.38 is in a peer-established active state, disable it
	 * and cancel the pending re-INVITE timeout. */
	if (!image_active_seen && pvt->t38_state >= SOFIA_T38_PEER_REINVITE) {
		/* DEFER the T.38 withdraw (state→DISABLED queues a frame + cancels the t38id timer)
		 * to the commit phase, so a rejected SDP does not disable an established fax.
		 * Mutually exclusive with t38_stage_enter_reinvite (advance implies image_active_seen,
		 * which makes this !image_active_seen test false). */
		t38_stage_withdraw = 1;
	}

	sdp_parser_free(parser);
	parser = NULL;	/* NULL so the sdp_reject label's free is a no-op for the post-loop rejects */

	/* SRTP policy enforcement (chan_sip parity) */
	if (audio_secure_offered && !processed_crypto_audio) {
		ast_log(LOG_NOTICE, "Sofia: SDP rejected — m=audio RTP/SAVP without valid a=crypto\n");
		goto sdp_reject;
	}
	if (video_secure_offered && !processed_crypto_video) {
		ast_log(LOG_NOTICE, "Sofia: SDP rejected — m=video RTP/SAVP without valid a=crypto\n");
		goto sdp_reject;
	}
	if (pvt->peer && pvt->peer->encryption) {
		if (audio_offered && !audio_secure_offered) {
			ast_log(LOG_NOTICE, "Sofia: SDP rejected — peer '%s' requires encryption, audio offer is plain RTP/AVP\n",
				pvt->peer->name);
			goto sdp_reject;
		}
		if (video_offered && !video_secure_offered) {
			ast_log(LOG_NOTICE, "Sofia: SDP rejected — peer '%s' requires encryption, video offer is plain RTP/AVP\n",
				pvt->peer->name);
			goto sdp_reject;
		}
	}

	/* Every reject gate has now passed — THIS is the only place active SRTP is (re-)keyed,
	 * committing the crypto staged during the media loop. So a re-INVITE that would have
	 * been rejected never touched the live SRTP. sdp_crypto_commit returns 0 (ok), -1
	 * (failed BEFORE any live mutation — safe to reject) or -2 (activation failed AFTER a
	 * possible live mutation). We may ONLY 488 on a -1 from a stream that has not yet gone
	 * live (committed_any==0); once any stream is live, or a commit may have mutated live
	 * media (-2), we must accept rather than leave the media corrupt-AND-rejected. */
	{
		int committed_any = 0;
		/* sdp_crypto_commit: 1 = committed live, 0 = no-op (nothing staged), -1 = failed
		 * before any live mutation (safe to reject), -2 = activation failed after a
		 * possible live mutation (must not reject). committed_any tracks ONLY a real live
		 * commit (a 0 no-op must NOT set it). */
		if (pvt->srtp && pvt->srtp->crypto) {
			int crc = sdp_crypto_commit(pvt->srtp->crypto, pvt->rtp);
			if (crc == 1) {
				committed_any = 1;
			} else if (crc == -2) {
				committed_any = 1;
				ast_log(LOG_WARNING, "Sofia: audio SRTP activation failed after a possible live mutation — accepting SDP to avoid a corrupt-and-rejected state\n");
			} else if (crc == -1) {	/* pre-activation failure, nothing live touched */
				ast_log(LOG_NOTICE, "Sofia: SDP rejected — audio SRTP commit failed before activation\n");
				goto sdp_reject;
			}
			/* crc == 0: no-op (nothing staged) — committed_any unchanged */
		}
		if (pvt->vsrtp && pvt->vsrtp->crypto) {
			int crc = sdp_crypto_commit(pvt->vsrtp->crypto, pvt->vrtp);
			if (crc == 1) {
				committed_any = 1;
			} else if (crc == -2) {
				committed_any = 1;
				ast_log(LOG_WARNING, "Sofia: video SRTP activation failed after a possible live mutation — accepting SDP\n");
			} else if (crc == -1) {
				if (!committed_any) {	/* nothing went live yet: safe to reject */
					ast_log(LOG_NOTICE, "Sofia: SDP rejected — video SRTP commit failed before activation\n");
					goto sdp_reject;
				}
				/* a stream already went live: cannot reject without corrupting it */
				ast_log(LOG_WARNING, "Sofia: video SRTP commit failed but audio is already live — accepting SDP (video without SRTP)\n");
			}
			/* crc == 0: no-op */
		}
	}

	/* COMMIT: every reject gate — including the SRTP commit above, the LAST reject point —
	 * has passed. Install the staged codec maps into the live RTP instances now. A rejected
	 * SDP returned via sdp_reject before reaching here, so it never overwrote them. (Remote
	 * addresses use snapshot-restore; irreversible side-effects are deferred below.) */
	if (staged_audio_valid) {
		ast_rtp_codecs_payloads_copy(&staged_audio_codecs,
			ast_rtp_instance_get_codecs(pvt->rtp), pvt->rtp);
	}
	if (staged_video_valid && pvt->vrtp) {
		ast_rtp_codecs_payloads_copy(&staged_video_codecs,
			ast_rtp_instance_get_codecs(pvt->vrtp), pvt->vrtp);
	}
	ast_rtp_codecs_payloads_clear(&staged_audio_codecs, NULL);
	ast_rtp_codecs_payloads_clear(&staged_video_codecs, NULL);

	/* COMMIT — ONE consolidated channel ref+lock+revalidate dance applying the deferred
	 * side-effects in the EXACT original temporal order: under the channel lock, audio native
	 * format → udptl fds[5] attach → THEN the T.38 state-change (sofia_change_t38_state queues
	 * the REQUEST_NEGOTIATE frame, which MUST come AFTER fds[5] so app_fax/res_fax sees the
	 * UDPTL fd) → arm/cancel the t38id timer → snapshot the fax-redirect inputs from the locked
	 * channel; THEN release the channel lock and run ast_exists_extension + FAXEXTEN setvar +
	 * ast_async_goto on the ref-pinned owner (they take their own channel/pbx/contexts locking,
	 * so the channel lock must be dropped first). Only reached after every reject gate passes.
	 * Advance and withdraw are mutually exclusive (advance implies image_active_seen, suppressing
	 * withdraw). fds[5] is gated on t38_stage_fds5, set ONLY in the udptl create block (was_new) —
	 * a pre-existing udptl already had fds[5] wired. sofia_change_t38_state under the held channel
	 * lock is recursive-safe (ast_queue_frame re-locks). */
	if (staged_chosen_audio_valid || t38_stage_fds5 || t38_stage_enter_reinvite || t38_stage_withdraw) {
		struct ast_channel *o = pvt->owner;
		if (o) {
			char fax_context[AST_MAX_CONTEXT] = "";
			char fax_exten[AST_MAX_EXTENSION] = "";
			const char *fax_cid = NULL;	/* ast_strdupa, no truncation */
			int do_fax = 0;
			ast_channel_ref(o);
			ast_channel_lock(o);
			if (pvt->owner == o) {
				if (staged_chosen_audio_valid) {
					o->nativeformats =
						(o->nativeformats & ~AST_FORMAT_AUDIO_MASK) | staged_chosen_audio;
					ast_set_read_format(o, staged_chosen_audio);
					ast_set_write_format(o, staged_chosen_audio);
				}
				if (t38_stage_fds5 && pvt->udptl) {
					o->fds[5] = ast_udptl_fd(pvt->udptl);
				}
				if (t38_stage_enter_reinvite) {
					/* frame AFTER the fds[5] attach above */
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
					/* snapshot the fax-redirect inputs while locked (chan_sip parity:
					 * peer faxdetect=t38 + a "fax" extension exists + not already at "fax") */
					if (pvt->peer && (pvt->peer->faxdetect_mode & SOFIA_FAX_DETECT_T38)
					    && strcmp(o->exten, "fax")) {
						ast_copy_string(fax_context, S_OR(o->macrocontext, o->context), sizeof(fax_context));
						ast_copy_string(fax_exten, o->exten, sizeof(fax_exten));
						if (o->caller.id.number.valid && o->caller.id.number.str) {
							/* ast_strdupa under the lock — stack-duped, valid until this
							 * function returns; no truncation of a long caller ID (matches the
							 * original direct-pointer pass to ast_exists_extension). */
							fax_cid = ast_strdupa(o->caller.id.number.str);
						}
						do_fax = 1;
					}
				} else if (t38_stage_withdraw) {
					sofia_change_t38_state(pvt, SOFIA_T38_DISABLED);
					if (pvt->t38id != -1 && sofia_sched) {
						if (ast_sched_thread_del(sofia_sched, pvt->t38id) == 0) {
							ao2_ref(pvt, -1);
						}
						pvt->t38id = -1;
					}
				}
			}
			ast_channel_unlock(o);
			/* dialplan ops AFTER the unlock, on the ref-pinned o (no raw pvt->owner re-read) */
			if (do_fax) {
				if (ast_exists_extension(o, fax_context, "fax", 1, fax_cid)) {
					ast_verbose(VERBOSE_PREFIX_2 "Sofia: redirecting '%s' to fax extension due to peer T.38 re-INVITE\n",
						o->name);
					pbx_builtin_setvar_helper(o, "FAXEXTEN", fax_exten);
					if (ast_async_goto(o, fax_context, "fax", 1)) {
						ast_log(LOG_NOTICE, "Sofia: T.38 reINVITE detected — failed async goto fax extension on '%s'\n",
							o->name);
					}
				} else {
					ast_log(LOG_NOTICE, "Sofia: T.38 reINVITE detected but no fax extension on '%s'\n",
						o->name);
				}
			}
			ast_channel_unref(o);
		} else if (t38_stage_withdraw) {
			/* No owner: sofia_change_t38_state would NO-OP — it does `chan = pvt->owner; if
			 * (!chan) return;` BEFORE writing pvt->t38_state, so the original
			 * left t38_state STALE at PEER_REINVITE on a no-owner withdraw. Set the
			 * state DIRECTLY to DISABLED so a withdrawn image leg never leaves
			 * stale T.38 state (no frame is queued — there is no channel to notify). Then cancel a
			 * pending t38id timer (scheduler-ref cleanup). */
			pvt->t38_state = SOFIA_T38_DISABLED;
			if (pvt->t38id != -1 && sofia_sched) {
				if (ast_sched_thread_del(sofia_sched, pvt->t38id) == 0) {
					ao2_ref(pvt, -1);
				}
				pvt->t38id = -1;
			}
		}
	}

	return 0;

sdp_reject:
	/* Single reject-cleanup. Every reject jumps here so a rejected SDP NEVER leaves
	 * pvt->capability mutated. parser is freed here if still owned (it is NULL'd after the
	 * in-loop sdp_parser_free, so the post-loop rejects do not double-free; the in-loop audio
	 * reject reaches here with parser still live). SRTP staging is rolled back exactly once;
	 * capability is restored to its pre-parse value. */
	if (parser) {
		sdp_parser_free(parser);
	}
	sofia_sdp_stage_rollback(pvt, audio_srtp_was_new, video_srtp_was_new);
	pvt->capability = orig_capability;
	/* Restore the live media state the loop may have mutated before this reject. The codec-map
	 * copies and the irreversible side-effects are deferred past the gates, so they were never
	 * applied on a reject and need no restore here. Restoring an unchanged value (reject before
	 * the mutation) is a harmless no-op. had_vrtp/had_udptl guard instances that only exist
	 * after a lazy create this parse. */
	pvt->t38_their_parms = orig_t38_their_parms;
	pvt->t38_max_ifp = orig_t38_max_ifp;
	ast_rtp_instance_set_remote_address(pvt->rtp, &orig_audio_remote);
	if (had_vrtp) {
		ast_rtp_instance_set_remote_address(pvt->vrtp, &orig_video_remote);
	}
	if (had_udptl) {
		/* Restore a PRE-EXISTING udptl's peer + EC scheme + far_max_datagram (a was_new udptl is
		 * destroyed below instead). The EC/datagram setters take the value-faithful getter
		 * snapshots captured before the loop. */
		ast_udptl_set_peer(pvt->udptl, &orig_udptl_peer);
		ast_udptl_set_error_correction_scheme(pvt->udptl, orig_udptl_ec);
		ast_udptl_set_far_max_datagram(pvt->udptl, orig_udptl_far_datagram);
	}
	/* Discard the staged codec maps — on a reject they were NEVER copied into the live RTP
	 * instances (the commit copy is past this label), so there is nothing to restore; just free
	 * them. Clearing an empty/unbuilt map is a safe no-op. */
	ast_rtp_codecs_payloads_clear(&staged_audio_codecs, NULL);
	ast_rtp_codecs_payloads_clear(&staged_video_codecs, NULL);
	/* If pvt->vrtp was LAZILY CREATED this parse (!had_vrtp but now non-NULL), a rejected SDP must
	 * not leave a stray video RTP instance — destroy it (mirrors the SRTP was_new rollback). Placed
	 * AFTER sofia_sdp_stage_rollback above so a was_new vsrtp is torn down first (sofia_srtp_destroy
	 * frees only the srtp/crypto, never derefs pvt->vrtp). The m=video lazy create wires no channel
	 * fd, so destroy + NULL is the complete cleanup. Mutually exclusive with the had_vrtp restore
	 * above (that branch only runs for a PRE-existing vrtp). */
	if (!had_vrtp && pvt->vrtp) {
		ast_rtp_instance_destroy(pvt->vrtp);
		pvt->vrtp = NULL;
	}
	/* Destroy a udptl LAZILY CREATED this parse (!had_udptl but now non-NULL). The fds[5] channel
	 * attach was DEFERRED to commit, so on a reject it was never wired — destroy + NULL is the
	 * complete cleanup (mirrors the vrtp/SRTP was_new rollback). Mutually exclusive with the
	 * had_udptl peer/EC/datagram restore above (that runs only for a pre-existing udptl). */
	if (!had_udptl && pvt->udptl) {
		ast_udptl_destroy(pvt->udptl);
		pvt->udptl = NULL;
	}
	return -1;
}

static struct ast_channel *sofia_new(struct sofia_pvt *pvt, int state, const char *linkedid)
{
	struct ast_channel *chan;

	if (!pvt) {
		return NULL;
	}

	/* ast_channel_alloc 5th arg is the CDR accountcode: pass pvt->accountcode
	 * (populated via dialog inheritance from peer->accountcode), NOT the SIP auth
	 * user. chan_sip parity. */
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

	/* fd-5 attach for UDPTL packet read (chan_sip parity). pvt->udptl is
	 * typically NULL here for inbound INVITE (lazy-created by sofia_parse_sdp on
	 * m=image); both orderings covered: (a) udptl pre-existing → wire here;
	 * (b) created later → sofia_parse_sdp lazy-create site sets owner->fds[5]. */
	if (pvt->udptl) {
		chan->fds[5] = ast_udptl_fd(pvt->udptl);
	}

	chan->tech_pvt = pvt;

	if (pvt->peer) {
		/* reload-UAF fix: on the OUTBOUND path (sofia_request_call, PBX
		 * thread) these pvt->peer reads race the reload writer
		 * (sofia_parse_peer_config on sofia_thread) which frees the peer
		 * stringfield pool under peer->lock. (The inbound caller runs on
		 * sofia_thread and cannot race the writer, but taking the lock there is
		 * harmless/uncontended.) Hold peer->lock across the freeable-stringfield
		 * reads (language/cid_tag/parkinglot) and release before the chanvars
		 * loop, whose pbx_builtin_setvar_helper takes the CHANNEL lock and must
		 * not run under peer->lock. peer->lock is recursive, so this is safe
		 * regardless of caller hold-state. */
		ast_mutex_lock(&pvt->peer->lock);
		chan->callgroup = pvt->peer->callgroup;
		chan->pickupgroup = pvt->peer->pickupgroup;
		/* Per-peer audio locale → ast_channel.language (chan_sip parity). Empty
		 * peer->language leaves chan->language at the gabpbx-core default. */
		if (!ast_strlen_zero(pvt->peer->language)) {
			ast_string_field_set(chan, language, pvt->peer->language);
		}
		/* Per-peer cid_tag → ast_channel.caller.id.tag (chan_sip parity).
		 * ast_party_id.tag is an Asterisk-internal channel-side identifier, NOT a
		 * SIP From-tag (sofia-sip auto-generates that per RFC 3261 §8.1.1.3). */
		if (!ast_strlen_zero(pvt->peer->cid_tag)) {
			chan->caller.id.tag = ast_strdup(pvt->peer->cid_tag);
		}
		/* Per-peer AMA flags → ast_channel.amaflags (chan_sip parity), gated on
		 * non-zero so the channel-core default is preserved when peer has none. */
		if (pvt->peer->amaflags) {
			chan->amaflags = pvt->peer->amaflags;
		}
		/* Per-peer parking-lot → ast_channel.parkinglot (chan_sip parity), gated
		 * on non-empty so the channel-core default is preserved when empty. */
		if (!ast_strlen_zero(pvt->peer->parkinglot)) {
			ast_string_field_set(chan, parkinglot, pvt->peer->parkinglot);
		}
		/* All freeable peer stringfields read above; release peer->lock before the
		 * chanvars loop below, whose pbx_builtin_setvar_helper takes the channel
		 * lock (must not nest under peer->lock to preserve channel->peer order). */
		ast_mutex_unlock(&pvt->peer->lock);
		/* Apply peer->chanvars to the channel (chan_sip parity). setvar entries
		 * become regular channel-vars; header entries (__SIPADDHEADERpre%2d=
		 * Name: value) become inherited channel-vars consumed by
		 * sofia_build_addheader_str which emits them as SIPTAG_HEADER_STR. */
		if (pvt->peer->chanvars) {
			/* reload-UAF fix: the reload writer (sofia_parse_peer_config on
			 * sofia_thread) frees peer->chanvars via ast_variables_destroy under
			 * peer->lock and rebuilds it, while this runs on the PBX/dialing
			 * thread. Deep-copy the list under peer->lock, then apply the copy
			 * lock-free — we cannot hold peer->lock across pbx_builtin_setvar_helper
			 * (it takes the channel lock, inverting channel->peer). */
			struct ast_variable *vcopy = NULL, *vtail = NULL, *src, *n;
			ast_mutex_lock(&pvt->peer->lock);
			for (src = pvt->peer->chanvars; src; src = src->next) {
				n = ast_variable_new(src->name, src->value, "");
				if (!n) {
					break;
				}
				if (vtail) {
					vtail->next = n;
				} else {
					vcopy = n;
				}
				vtail = n;
			}
			ast_mutex_unlock(&pvt->peer->lock);
			for (n = vcopy; n; n = n->next) {
				pbx_builtin_setvar_helper(chan, n->name, n->value);
			}
			ast_variables_destroy(vcopy);
		}
	}

	return chan;
}

/* Forward declarations used by sofia_pvt_destructor for the hmagic UAF
 * closure on pvt-bound handles (definitions live further down). */
int sofia_dispatch_to_root_thread(void (*callback)(void *), void *data);
static void sofia_nh_destroy_cleanup(void *arg);

static void sofia_pvt_destructor(void *obj)
{
	struct sofia_pvt *pvt = obj;

	sofia_pvt_clear_active_contact(pvt);

	/* Destructor catchall call-counter DEC — race-recovery for orphaned pvts
	 * (e.g. alloc-fail before any other DEC site fired). Flag-gated idempotency
	 * keeps multi-site safe. Must run BEFORE the peer ao2_ref drop below — the
	 * counter helper needs pvt->peer. */
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

	/* hmagic UAF closure for pvt-bound handles — same discipline as the
	 * peer-bound handles below. pvt->nh was bound to pvt via nua_handle()
	 * auto-bind, nua_handle_bind() on an inbound INVITE, or fork winner-pick
	 * handle transfer; in all cases nh->nh_magic points at pvt.
	 *
	 * This destructor can run on any thread (wherever the last ao2 ref drops).
	 * nua_handle_destroy is async: it posts an rdestroy su_msg and returns; the
	 * real teardown happens later on sofia_thread. Between post and destroy,
	 * sofia-sip may deliver an in-flight event for this handle (late ACK,
	 * retransmit, in-dialog CANCEL) into sofia_event_callback, which would deref
	 * nh->nh_magic and find a freed pvt. nua_handle_bind(nh, NULL) is synchronous
	 * (just writes a pointer, no I/O) and runs here BEFORE the destroy dispatch,
	 * so any event in the window reads hmagic == NULL and the `if (hmagic)` gates
	 * in sofia_event_callback short-circuit cleanly.
	 *
	 * The destroy is dispatched via sofia_dispatch_to_root_thread so it always
	 * runs on sofia_thread. If dispatch fails (sofia_root torn down, su_msg OOM)
	 * we log and leak the handle instead of crashing; leaks clear on restart. */
	if (pvt->nh) {
		nua_handle_t *nh = pvt->nh;
		pvt->nh = NULL;
		nua_handle_bind(nh, NULL);
		if (sofia_dispatch_to_root_thread(sofia_nh_destroy_cleanup, nh) < 0) {
			ast_log(LOG_NOTICE,
				"Sofia: pvt destructor — sofia_thread dispatch failed for "
				"pvt->nh; leaking handle (cleared on next gabpbx restart)\n");
		}
	}

	/* DSP detect cleanup. Place BEFORE pvt->rtp destroy (DSP holds no rtp ref,
	 * but ordering preserves chan_sip convention). NULL-safe. */
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

	/* UDPTL session teardown (chan_sip parity). Place AFTER rtp/vrtp/srtp/vsrtp
	 * destroy + BEFORE home unref. NULL-safe. t38id sched-cancel: if cancel
	 * succeeds the callback never runs, so drop the ref taken at
	 * ast_sched_thread_add to balance it; if the callback already ran, t38id is
	 * -1 and sched_thread_del is a no-op (race-safe del-or-fire dichotomy). */
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

	/* Explicit init for non-zero-default T.38 fields. t38_state matches
	 * SOFIA_T38_DISABLED=0 by zero-init (explicit here for intent); t38id MUST be
	 * the -1 sentinel ("no scheduler entry pending" — distinct from valid ID 0). */
	pvt->t38_state = SOFIA_T38_DISABLED;
	pvt->t38id = -1;
	pvt->defer_bye_sched_id = -1;

	/* Default OUR T.38 capabilities (chan_sip parity). version=0 (T.38 v0 per
	 * RFC 3362; negotiation MIN-clamps with peer). rate=14400 (highest bit-rate
	 * we offer). rate_management=TRANSFERRED_TCF (RFC 3362 default). max_ifp /
	 * max_datagram left zero — the UDPTL stack supplies defaults. */
	pvt->t38_our_parms.version = 0;
	pvt->t38_our_parms.rate = AST_T38_RATE_14400;
	pvt->t38_our_parms.rate_management = AST_T38_RATE_MANAGEMENT_TRANSFERRED_TCF;

	return pvt;
}

/* Forward declarations (definitions live further down). */
int sofia_dispatch_to_root_thread(void (*callback)(void *), void *data);
static void transmit_mwi_notify_for_peer(struct sofia_peer *peer);
static void sofia_format_outboundproxy(struct sofia_peer *peer, char *buf, size_t len);
/* Outbound INVITE From/Contact/SDP-c= builders (chan_sip parity). sofia_resolve_ourip
 * mirrors ast_sip_ouraddrfor (kernel routing + externaddr remap). */
static void sofia_resolve_ourip(struct sofia_pvt *pvt, const struct ast_sockaddr *target);
static void sofia_build_from(struct sofia_pvt *pvt, char *buf, size_t len);
static struct ast_channel *sofia_find_bridged_channel(struct sofia_pvt *op);
/* dnsmgr update callback — arg order (old, new, data) per dnsmgr.h dns_update_func. */
static void sofia_on_dns_update_peer(struct ast_sockaddr *old, struct ast_sockaddr *new, void *data);
static void sofia_build_contact(struct sofia_pvt *pvt, char *buf, size_t len);
/* Outbound RPID/PAI/Privacy emitter + shared identity-resolution helper. */
static int sofia_resolve_identity(struct sofia_pvt *pvt, char **lid_num_out,
                                   char **lid_name_out, int *lid_pres_out,
                                   char *fromdomain_buf, size_t fromdomain_len);
static int sofia_add_rpid(struct sofia_pvt *pvt, char *header_buf, size_t header_len);
/* Outbound Diversion emitter (RFC 5806). */
static int sofia_add_diversion(struct sofia_pvt *pvt, char *header_buf, size_t header_len);
/* Inbound RPID/PAI/Privacy parsers. sofia_check_privacy_id walks sip->sip_privacy;
 * sofia_get_pai/sofia_get_rpid walk sip->sip_unknown by header name. All three are
 * trust-gated on peer->trustrpid. */
static int sofia_check_privacy_id(sip_t const *sip);
static int sofia_get_pai(struct sofia_pvt *pvt, sip_t const *sip);
static int sofia_get_rpid(struct sofia_pvt *pvt, sip_t const *sip);
/* Inbound Diversion parser — walks sip->sip_unknown for "Diversion" by name. */
static int sofia_change_redirecting_info(struct sofia_pvt *pvt, struct ast_channel *owner, sip_t const *sip);

/* MWI re-NOTIFY cross-thread dispatch carrier. mwi_event_cb fires on the
 * event-bus thread; nua_notify must run on sofia_thread (same-thread-as-create).
 * The peer ref is TRANSFERRED to the callback (event_cb takes +1, dispatch
 * carries, callback drops). */
struct mwi_dispatch_data {
	struct sofia_peer *peer;	/* +1 ref TRANSFERRED — callback drops */
};

/* Cleanup helper for mwi_dispatch_data. Safe on any thread; does no nua ops
 * (only ao2 ref drop + ast_free). Called on both the callback success path and
 * the dispatch-failure path. */
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

/* Callback dispatched to sofia_thread by mwi_event_cb. Calls
 * transmit_mwi_notify_for_peer (which re-fetches counts on this thread for
 * freshest state) then frees the dispatch carrier. */
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

/* Destructor cleanup callback — issues a final terminated NOTIFY + destroys nh.
 * Runs on sofia_thread via sofia_dispatch_to_root_thread. Carries ONLY nh (no
 * peer ref): the destructor runs after the peer's last unref, so peer cannot be
 * kept alive across the dispatch; cleanup never touches peer fields. */
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

/* Generic deferred nua_handle_destroy — runs on sofia_thread. Used by the peer
 * destructor for peer->nh (outbound REGISTER) and peer->qualify_nh (OPTIONS).
 * Unlike mwi_handle_cleanup it emits no terminal NOTIFY — these handles carry no
 * subscription dialog. The handle MUST already be detached from its owning struct
 * (caller NULLs the field first) so sofia-sip cannot deliver events back to a
 * freed peer via nh->hmagic. */
static void sofia_nh_destroy_cleanup(void *arg)
{
	nua_handle_t *nh = arg;
	if (!nh) {
		return;
	}
	nua_handle_destroy(nh);
}

/* AST_EVENT_MWI callback fired by gabpbx core on mailbox state change. Runs on
 * the event-bus thread; nua_notify must happen on sofia_thread, so dispatch via
 * sofia_dispatch_to_root_thread. userdata is the peer captured at subscribe time.
 * Quick-exit when no active subscription; TOCTOU safety comes from
 * transmit_mwi_notify_for_peer's nh re-check under peer->lock. */
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

/* Parse one mailbox spec ("mbox" or "mbox@context") and append to
 * peer->mailboxes, then subscribe to AST_EVENT_MWI for it. Caller holds peer->lock
 * (or peer is being built pre-insertion). spec is NOT consumed/owned. */
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

	/* Subscribe to AST_EVENT_MWI for this mailbox+context; peer is the userdata. */
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

/* Parse a "mbox1@ctx1,mbox2@ctx2" comma-separated list. Spec is COPIED (not
 * consumed); each comma-segment becomes a separate sofia_mailbox entry. */
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

/* Unsubscribe all of a peer's AST_EVENT_MWI subscriptions while the peer is STILL
 * ALIVE (refcount > 0). The event dispatcher holds the subs RDLOCK across
 * mwi_event_cb and ast_event_unsubscribe takes the WRLOCK, so after this returns no
 * mwi_event_cb is in-flight or can fire for this peer — closing the destructor
 * resurrection UAF (a cb doing ao2_ref(peer,+1) on a refcount-0 peer mid-destroy).
 * MUST be called on every peer-removal path BEFORE the final ao2_ref(peer,-1) so the
 * destructor's own drain is a no-op (it stays as an idempotent backstop). Does NOT
 * free the mailbox nodes (the destructor still does that). No peer->lock needed: the
 * mailbox list is only mutated at build time on a fresh peer. */
static void sofia_peer_drain_mwi(struct sofia_peer *peer)
{
	struct sofia_mailbox *mb;
	if (!peer) {
		return;
	}
	AST_LIST_TRAVERSE(&peer->mailboxes, mb, list) {
		if (mb->event_sub) {
			mb->event_sub = ast_event_unsubscribe(mb->event_sub);
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
	/* contactpermit/contactdeny ACL chain. */
	if (peer->contactha) {
		ast_free_ha(peer->contactha);
		peer->contactha = NULL;
	}
	/* directmediapermit/directmediadeny ACL chain. */
	if (peer->directmediaha) {
		ast_free_ha(peer->directmediaha);
		peer->directmediaha = NULL;
	}
	/* peer->chanvars linked-list (setvar + header entries). */
	if (peer->chanvars) {
		ast_variables_destroy(peer->chanvars);
		peer->chanvars = NULL;
	}
	/* Defensive dnsmgr release for orphan paths (peer->dnsmgr still set at
	 * refcount=0 means a path did ao2_ref(-1) but missed ast_dnsmgr_release).
	 * Normal path: reload-sweep releases THEN drops the ref, so the destructor
	 * sees NULL. NO ao2_ref(-1) here — already inside the destructor. */
	if (peer->dnsmgr) {
		ast_dnsmgr_release(peer->dnsmgr);
		peer->dnsmgr = NULL;
	}
	/* Drain mailbox list — unsubscribe (synchronous; waits for any in-flight
	 * mwi_event_cb to finish) BEFORE ast_free, closing the race against
	 * concurrent event-bus delivery. */
	while ((mb = AST_LIST_REMOVE_HEAD(&peer->mailboxes, list))) {
		if (mb->event_sub) {
			mb->event_sub = ast_event_unsubscribe(mb->event_sub);
		}
		ast_free(mb);
	}

	/* Clean up active MWI subscription. nh ownership passes to mwi_handle_cleanup
	 * on sofia_thread (nua_handle_destroy is same-thread-as-create). NO peer ref
	 * taken (we are IN the destructor at refcount 0). On dispatch failure leak the
	 * nh (cleared on restart).
	 *
	 * CRITICAL — detach hmagic before the async destroy. The destructor may run
	 * off sofia_thread, and the destroy is dispatched to run LATER; between this
	 * destructor freeing the peer and that destroy, sofia-sip could deliver an
	 * event into sofia_event_callback that derefs nh->hmagic → the freed peer.
	 * nua_handle_bind(nh, NULL) is synchronous (no I/O) and runs BEFORE the
	 * dispatch, so any event in the window reads hmagic == NULL and the
	 * `if (hmagic)` gates in sofia_event_callback handle it gracefully. */
	if (peer->mwi_subscription_handle) {
		nua_handle_t *nh = peer->mwi_subscription_handle;
		peer->mwi_subscription_handle = NULL;
		nua_handle_bind(nh, NULL);
		if (sofia_dispatch_to_root_thread(mwi_handle_cleanup, nh) < 0) {
			ast_log(LOG_NOTICE,
				"Sofia MWI: peer %s destructor — sofia_thread dispatch failed; "
				"leaking nh (cleared on next gabpbx restart)\n", peer->name);
		}
	}
	/* Outbound REGISTER handle (peer->nh) and qualify OPTIONS handle
	 * (peer->qualify_nh). Same same-thread-as-create constraint: nua_handle_destroy
	 * MUST run on sofia_thread. The normal sweep path destroys these synchronously
	 * before dropping the container ref (destructor then sees NULL); these
	 * defensive branches catch orphan paths where the ref drops without sweep
	 * (e.g. realtime cache rebuild while a register/qualify is in flight).
	 * nua_handle_bind(nh, NULL) detaches hmagic before the async destroy — see the
	 * MWI-handle comment above for the UAF rationale. */
	if (peer->nh) {
		nua_handle_t *nh = peer->nh;
		peer->nh = NULL;
		nua_handle_bind(nh, NULL);
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
		nua_handle_bind(nh, NULL);
		if (sofia_dispatch_to_root_thread(sofia_nh_destroy_cleanup, nh) < 0) {
			ast_log(LOG_NOTICE,
				"Sofia: peer %s destructor — sofia_thread dispatch failed for "
				"peer->qualify_nh; leaking handle (cleared on next gabpbx "
				"restart)\n", peer->name);
		}
	}
	ast_string_field_free_memory(peer);
}

/* Async DNS-update callback fired by res_dnsmgr.so when peer->host resolves to a
 * new IP. Signature (old, new, data) — arg order is critical (chan_sip parity).
 * Updates peer->src_addr under peer->lock (callback runs on the res_dnsmgr thread,
 * racing lock-protected readers). Emits an AMI DnsManagerUpdate event.
 *
 * Race-safety: the peer ref is bumped at registration so the callback safely
 * accesses peer even mid-destroy. Cleanup contract: reload-sweep MUST call
 * ast_dnsmgr_release (synchronous; waits for in-flight callbacks) BEFORE the
 * dnsmgr-held ao2_ref(peer, -1). */
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

/* Register async DNS lookup at peer-load conclusion (chan_sip parity). Skip if
 * peer->host is an IP literal (no DNS needed) or empty/dynamic. Caller must invoke
 * AFTER host is finalized but BEFORE ao2_link publishes the peer. */
static void sofia_dnsmgr_setup_peer(struct sofia_peer *peer)
{
	struct ast_sockaddr probe;

	if (!peer || ast_strlen_zero(peer->host) || !strcasecmp(peer->host, "dynamic")) {
		return;
	}
	if (peer->dnsmgr) {
		return; /* already registered (idempotent for reload paths) */
	}
	/* IP-literal pre-check — no DNS needed. Still copy the parsed address into
	 * peer->src_addr so downstream consumers (sofia_find_peer_by_ip IP-fallback,
	 * SDP externaddr substitution) have a populated "where to reach this peer".
	 * Without this, static host=<ip-literal> trunks leave src_addr zero: IP-based
	 * peer match misses them (inbound INVITE → 401) and the SDP c= line stays at
	 * the bound 0.0.0.0 (no audio). */
	if (ast_sockaddr_parse(&probe, peer->host, PARSE_PORT_FORBID)) {
		ast_sockaddr_copy(&peer->src_addr, &probe);
		return;
	}
	/* Bump the peer ref for callback-time-safe access; the reload-sweep path
	 * decrements it via an explicit ao2_ref(-1) after ast_dnsmgr_release. */
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

/* Config-derived defaults shared by a freshly allocated peer (sofia_peer_alloc)
 * AND an existing peer re-parsed on reload (sofia_parse_peer_config cache-hit).
 * Applying the WHOLE default set uniformly is what makes a per-peer key the
 * operator REMOVED revert to its [general] default on reload instead of sticking
 * at the stale value.
 *
 * Notable points:
 *  - Inherited stringfields (srtpcipher/disallowed_methods/subscribecontext/moh*)
 *    are set UNCONDITIONALLY via S_OR(default,""), not "only if non-empty"; the
 *    conditional form would leave a stale per-peer value on reload when the global
 *    default is empty. Behaviour-identical for a new peer (empty stays empty).
 *  - EXCLUDES runtime/structural anchors handled by the caller: ao2 alloc,
 *    string-field init, mutex, name, the peer->contacts container, the
 *    is_realtime/is_register_line/_reload_marked flags, and the captured
 *    locked_user_agent anchor (preserved across reload when lockuseragent stays
 *    on — clearing it would open a re-capture window).
 *
 * Called under peer->lock in the reload path; the global contact_ha dup below
 * takes sofia_contactha_lock, a LEAF (never held while acquiring peer->lock), so
 * peer->lock -> contactha_lock has no inversion. */
static void sofia_peer_set_defaults(struct sofia_peer *peer)
{
	ast_string_field_set(peer, context, sofia_cfg.context);
	peer->type = 0;
	peer->port = DEFAULT_SIP_PORT;
	peer->transport = SOFIA_TRANSPORT_UDP;
	ast_sockaddr_setnull(&peer->defaddr);
	peer->maxcallbitrate = sofia_cfg.default_maxcallbitrate;
	peer->amaflags = 0;
	peer->subscribemwi = 0;
	peer->preferred_codec_only = sofia_cfg.default_preferred_codec_only;
	peer->ignoresdpversion = sofia_cfg.default_ignoresdpversion;
	peer->promiscredir = sofia_cfg.default_promiscredir;
	peer->autoframing = sofia_cfg.default_autoframing;
	peer->faxdetect_mode = sofia_cfg.default_faxdetect_mode;
	peer->t38pt_udptl = 0;
	peer->t38_ec_mode = SOFIA_T38_EC_FEC;
	peer->t38_maxdatagram = sofia_cfg.default_t38_maxdatagram;
	peer->t38pt_usertpsource = 0;
	peer->timer_b = sofia_cfg.default_timer_b;
	peer->timer_t1 = sofia_cfg.default_timer_t1;
	peer->allowoverlap_mode = sofia_cfg.default_allowoverlap_mode;
	peer->progressinband = sofia_cfg.default_progressinband;
	peer->rtptimeout = sofia_cfg.default_rtptimeout;
	peer->rtpholdtimeout = sofia_cfg.default_rtpholdtimeout;
	peer->rtpkeepalive = sofia_cfg.default_rtpkeepalive;
	peer->expiresecs = sofia_cfg.default_expiry > 0 ? sofia_cfg.default_expiry : DEFAULT_EXPIRY;
	peer->capability = sofia_cfg.capability;
	peer->prefs = sofia_cfg.prefs;
	peer->dtmfmode = SOFIA_DTMF_RFC2833;
	peer->directmedia = 0;
	peer->nat = SOFIA_NAT_FORCE_RPORT;
	peer->busy_on_active = sofia_cfg.busy_on_active;
	peer->max_contacts = sofia_cfg.max_contacts ? sofia_cfg.max_contacts : 6;
	peer->encryption = 0;
	ast_string_field_set(peer, srtpcipher, S_OR(sofia_cfg.default_srtpcipher, ""));
	peer->session_timers = sofia_cfg.default_session_timers;
	peer->session_expires = sofia_cfg.default_session_expires;
	peer->session_minse = sofia_cfg.default_session_minse;
	peer->session_refresher = sofia_cfg.default_session_refresher;
	peer->callingpres = sofia_cfg.default_callingpres;
	peer->sendrpid = sofia_cfg.default_sendrpid;
	peer->trustrpid = sofia_cfg.default_trustrpid;
	peer->call_limit = sofia_cfg.default_call_limit;
	peer->busy_level = sofia_cfg.default_busy_level;
	peer->allowtransfer = sofia_cfg.default_allowtransfer;
	peer->allowsubscribe = sofia_cfg.default_allowsubscribe;
	peer->publish = 0;	/* outbound PUBLISH opt-in; reset each (re)build so a removed publish=yes clears */
	peer->gruu = 0;		/* GRUU opt-in; reset each (re)build so a removed gruu=yes clears on reload */
	peer->buggymwi = 0;
	peer->lockuseragent = 0;
	ast_string_field_set(peer, lockuseragent_prefixes, "");
	peer->usereqphone = sofia_cfg.default_usereqphone;
	peer->maxforwards = sofia_cfg.default_max_forwards;
	ast_string_field_set(peer, disallowed_methods, S_OR(sofia_cfg.disallowed_methods, ""));
	/* Re-inherit the global contact ACL (matches new-peer semantics — the per-peer
	 * contactpermit/deny parser appends to this afterwards). reload-UAF: contact_ha is
	 * a freeable global; serialize the read against the reload writer. */
	ast_rwlock_rdlock(&sofia_contactha_lock);
	if (sofia_cfg.contact_ha) {
		peer->contactha = ast_duplicate_ha_list(sofia_cfg.contact_ha);
	}
	ast_rwlock_unlock(&sofia_contactha_lock);
	ast_string_field_set(peer, subscribecontext, S_OR(sofia_cfg.default_subscribecontext, ""));
	ast_string_field_set(peer, language, sofia_cfg.default_language);
	ast_string_field_set(peer, parkinglot, sofia_cfg.default_parkinglot);
	ast_string_field_set(peer, mohinterpret, S_OR(sofia_cfg.default_mohinterpret, ""));
	ast_string_field_set(peer, mohsuggest, S_OR(sofia_cfg.default_mohsuggest, ""));
	peer->qualifyfreq = 60;
	/* Security fields reset on reload so a stale md5secret/insecure cannot survive. */
	ast_string_field_set(peer, md5secret, "");
	peer->insecure = 0;
	peer->qualify = 0;
	/* Default these to ""/0 so a removed per-peer key reverts on reload. The empty
	 * values keep the parser's "inherit at use-time" semantics (outboundproxy falls
	 * back to sofia_cfg.outboundproxy; qualifytimeout=0 lets the qualify=yes parser
	 * apply the default when qualify is (re)enabled). */
	ast_string_field_set(peer, forceddiversion, "");
	ast_string_field_set(peer, callbackextension, "");
	ast_string_field_set(peer, accountcode, "");
	ast_string_field_set(peer, cid_name, "");
	ast_string_field_set(peer, cid_num, "");
	ast_string_field_set(peer, cid_tag, "");
	ast_string_field_set(peer, outboundproxy, "");
	peer->callgroup = 0;
	peer->pickupgroup = 0;
	peer->qualifytimeout = 0;
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
	ast_mutex_init(&peer->lock);
	/* All config-derived defaults live in sofia_peer_set_defaults so the reload
	 * cache-hit path re-applies the identical set. */
	sofia_peer_set_defaults(peer);
	/* Runtime/structural anchors NOT defaulted by the helper: the captured
	 * registration anchor stays empty on a fresh peer. */
	peer->locked_user_agent[0] = '\0';
	peer->is_realtime = 0;
		peer->is_register_line = 0;
	peer->_reload_marked = 0;
	peer->contacts = ao2_container_alloc(13, contact_hash_fn, contact_cmp_fn);
	if (!peer->contacts) {
		ao2_ref(peer, -1);
		return NULL;
	}

	return peer;
}

/* Auto-add (onoff=1) or remove (onoff=0) dialplan extensions for a peer when its
 * registration/qualify state transitions (chan_sip parity). Wired at 4 sites:
 * REGISTER-success, wildcard unregister, expiry-driven unregister, and qualify
 * state-transition (additionally gated on sofia_cfg.regextenonqualify).
 *
 * Features: outer gate on regcontext (empty = no-op); multi-extension via strsep
 * "&"; per-ext @context override; peer->name fallback when regexten is empty;
 * idempotent add/remove (existence-checked) so repeats don't duplicate or error.
 * Emits an AMI RegextenOnQualifyTransition event per add/remove.
 *
 * chan_sip's cleanup_stale_contexts reload sweep is intentionally NOT mirrored —
 * chan_sofia is non-unloadable; operators changing regcontext restart instead. */
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

/* Inbound REGISTER expires bounds enforcement (chan_sip parity): max_expiry
 * silently caps; min_expiry rejects with 423 Interval Too Brief + Min-Expires
 * header (RFC 3261 §10.2.8); expires==0 (unregister) bypasses bounds. Emits an
 * AMI RegisterIntervalRejected event on the reject path.
 *
 * Returns 0 = accept (with *expires bounded to max_expiry if exceeded);
 *         -1 = reject (helper has emitted 423 + AMI; caller MUST return). */
static int sofia_check_register_expiry(nua_t *nua, nua_handle_t *nh,
		struct sofia_peer *peer, int *expires)
{
	char min_str[16];

	if (!expires || *expires == 0) {
		/* unregister bypass (chan_sip parity) */
		return 0;
	}
	if (*expires > sofia_cfg.max_expiry) {
		/* silent cap (chan_sip parity) */
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

/* Create a static presence-hint extension at peer-load time (chan_sip parity):
 * pairs regexten + subscribecontext into a PRIORITY_HINT extension tracking peer
 * presence via DEVICE_STATE(). Notes:
 *   - Hint device is "SIP/<peer->name>" (chan_sofia uses peer->name everywhere,
 *     where chan_sip uses peer->username).
 *   - 2 callsites via the source arg ("realtime" / "config"), with the registrar
 *     string differing ("realtime_peer" / "sofia_config_peer") so `core show
 *     hints` shows hint origin.
 *   - Emits an AMI HintCreated event on every install.
 *
 * KNOWN LIMITATION: no removal counterpart — hints persist for the module
 * lifetime (chan_sofia is non-unloadable); operator restart to clean up. */
static void sofia_create_peer_hint(struct sofia_peer *peer, const char *source)
{
	struct ast_context *hintcontext;
	char hintsip[AST_MAX_EXTENSION + 5];
	const char *registrar;

	if (!peer || ast_strlen_zero(peer->subscribecontext) || ast_strlen_zero(peer->regexten)) {
		return; /* both fields required (chan_sip parity) */
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

static void sofia_apply_peer_variables(struct sofia_peer *peer, struct ast_variable *v, int overlay)
{
	/* Per-peer header counter — each header= entry gets a unique
	 * __SIPADDHEADERpre%2d= channel-var name. Resets per peer-build. */
	int headercount = 0;
	for (; v; v = v->next) {
		if (!strcasecmp(v->name, "encryption") && ast_strlen_zero(v->value)) {
			peer->encryption = 0;
			continue;
		}
		if (ast_strlen_zero(v->value)) continue;
		/* sipregs overlay guard (overlay != 0): this same function is run a
		 * SECOND time on the SAME peer struct to overlay registration-state
		 * columns from the sipregs table on top of the sippeers parse.  Every
		 * branch below is replace-in-place EXCEPT the list-typed ones —
		 * permit/deny + contact and directmedia ACL chains (ast_append_ha),
		 * setvar/header (sofia_add_var), and mailbox (AST_LIST_INSERT_TAIL +
		 * a per-mailbox AST_EVENT_MWI subscription) — which APPEND.  Re-running
		 * those on the overlay pass would duplicate the entries already built
		 * from sippeers (and register a SECOND, never-coalesced MWI
		 * subscription per mailbox).  Those columns belong in sippeers
		 * exclusively (operator contract documented at the overlay call site),
		 * so skip them here rather than double-appending.  Skipping (not
		 * resetting) preserves the sippeers-parsed entries intact when sipregs
		 * legitimately omits these columns. */
		if (overlay
				&& (!strcasecmp(v->name, "permit") || !strcasecmp(v->name, "deny")
					|| !strcasecmp(v->name, "contactpermit") || !strcasecmp(v->name, "contactdeny")
					|| !strcasecmp(v->name, "directmediapermit") || !strcasecmp(v->name, "directmediadeny")
					|| !strcasecmp(v->name, "setvar") || !strcasecmp(v->name, "header")
					|| !strcasecmp(v->name, "mailbox"))) {
			continue;
		}
		if (!strcasecmp(v->name, "secret") || !strcasecmp(v->name, "password")) {
			ast_string_field_set(peer, secret, v->value);
			/* Warn when both secret= and md5secret= are set (md5secret wins);
			 * this site fires when secret= comes after md5secret= in config. */
			if (!ast_strlen_zero(peer->md5secret) && !ast_strlen_zero(v->value)) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' has BOTH secret= and "
					"md5secret= set — md5secret takes precedence (chan_sip.c"
					":15415-16 parity); recommend operator unset secret= to "
					"remove ambiguity\n", peer->name);
			}
		} else if (!strcasecmp(v->name, "md5secret")) {
			/* Pre-hashed MD5(user:realm:secret) digest secret (chan_sip parity):
			 * when set, used directly as a1_hash, bypassing the cleartext path, and
			 * takes PRECEDENCE over peer->secret. */
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
		} else if (!strcasecmp(v->name, "forceddiversion")) {
			/* CLI-forward compliance: per-trunk redirecting DID forced into the
			 * outbound Diversion header on forwarded calls. See sofia_add_diversion. */
			ast_string_field_set(peer, forceddiversion, v->value);
		} else if (!strcasecmp(v->name, "callerid")) {
			ast_string_field_set(peer, callerid, v->value);
		} else if (!strcasecmp(v->name, "regexten")) {
			ast_string_field_set(peer, regexten, v->value);
		} else if (!strcasecmp(v->name, "callbackextension")) {
			/* Per-peer callback extension (chan_sip parity); stored on peer for
			 * CLI/AMI display + reload-time access. */
			ast_string_field_set(peer, callbackextension, v->value);
		} else if (!strcasecmp(v->name, "setvar")) {
			/* Append to peer->chanvars (chan_sip parity). */
			peer->chanvars = sofia_add_var(v->value, peer->chanvars);
		} else if (!strcasecmp(v->name, "header")) {
			/* Encode as a __SIPADDHEADERpre%2d= channel-var (double-underscore
			 * inheritance prefix); sofia_build_addheader_str later absorbs it via the
			 * "SIPADDHEADER" prefix match → SIPTAG_HEADER_STR. */
			char tmp[4096];
			snprintf(tmp, sizeof(tmp), "__SIPADDHEADERpre%2d=%s", ++headercount, v->value);
			peer->chanvars = sofia_add_var(tmp, peer->chanvars);
		} else if (!strcasecmp(v->name, "subscribecontext")) {
			/* Per-peer SUBSCRIBE dispatch context override (chan_sip parity). */
			ast_string_field_set(peer, subscribecontext, v->value);
		} else if (!strcasecmp(v->name, "accountcode")) {
			/* Per-peer CDR billing-tag → channel->accountcode (chan_sip parity);
			 * truncated to AST_MAX_ACCOUNT_CODE at CDR-write time. */
			ast_string_field_set(peer, accountcode, v->value);
		} else if (!strcasecmp(v->name, "disallowed_methods")) {
			/* disallowed_methods (chan_sip parity) — parse-compat string storage;
			 * dynamic NUTAG_ALLOW enforcement deferred. */
			ast_string_field_set(peer, disallowed_methods, v->value);
		} else if (!strcasecmp(v->name, "maxforwards")) {
			/* RFC 3261 §20.22 Max-Forwards initial value (chan_sip parity):
			 * sscanf %30d + 1-255 bounds-check + clamp-to-default on invalid. */
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
			/* Mirror the config-file parser so a realtime sippeers row with a NUMERIC
			 * qualify=<ms> is honored instead of silently disabled (a plain
			 * ast_true() would read "5000" as OFF, dropping trunk monitoring). */
			if (ast_true(v->value)) {
				peer->qualify = 1;
				peer->qualifyfreq = sofia_cfg.default_qualifyfreq > 0 ?
					sofia_cfg.default_qualifyfreq : DEFAULT_QUALIFYFREQ;
				peer->qualifytimeout = sofia_cfg.default_qualifytimeout > 0 ?
					sofia_cfg.default_qualifytimeout : DEFAULT_QUALIFYTIMEOUT;
			} else if (strcasecmp(v->value, "no")) {	/* numeric: qualify on, timeout=value */
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
			if (peer->qualifyfreq <= 0) peer->qualifyfreq = DEFAULT_QUALIFYFREQ;
		} else if (!strcasecmp(v->name, "qualifytimeout")) {
			peer->qualifytimeout = atoi(v->value);
			if (peer->qualifytimeout <= 0) peer->qualifytimeout = DEFAULT_QUALIFYTIMEOUT;
		} else if (!strcasecmp(v->name, "directmedia")
				|| !strcasecmp(v->name, "canreinvite")) {
			/* canreinvite= accepted as an alias for directmedia= (chan_sip parity)
			 * so legacy configs migrate without rewrite. */
			peer->directmedia = ast_true(v->value);
		} else if (!strcasecmp(v->name, "busy_on_active")) {
			peer->busy_on_active = ast_true(v->value);
		} else if (!strcasecmp(v->name, "max_contacts")) {
			peer->max_contacts = sofia_clamp_max_contacts(atoi(v->value), peer->name);
		} else if (!strcasecmp(v->name, "encryption")) {
			peer->encryption = ast_true(v->value);
		} else if (!strcasecmp(v->name, "srtpcipher")) {
			/* Comma-separated SRTP suite preference for outbound a=crypto:N (RFC 4568
			 * §6.1). Typo warnings happen at emit time, not parse time (operator may
			 * name a suite a future res_srtp release supports). */
			ast_string_field_set(peer, srtpcipher, v->value);
		} else if (!strcasecmp(v->name, "session-timers")) {
			/* Session timers (RFC 4028): originate/accept/refuse map to enum. */
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
			/* Per-peer default presentation override (chan_sip parity). */
			int p = ast_parse_caller_presentation(v->value);
			peer->callingpres = (p < 0) ? AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED : p;
		} else if (!strcasecmp(v->name, "sendrpid")) {
			/* Outbound RPID/PAI emission mode (chan_sip parity): no/pai/rpid. */
			if (!strcasecmp(v->value, "pai")) peer->sendrpid = 1;
			else if (!strcasecmp(v->value, "rpid")) peer->sendrpid = 2;
			else peer->sendrpid = 0;
		} else if (!strcasecmp(v->name, "trustrpid")) {
			/* Trust inbound PAI/RPID (chan_sip parity). */
			peer->trustrpid = ast_true(v->value);
		} else if (!strcasecmp(v->name, "callcounter")) {
			/* yes → unlimited counter participation (INT_MAX); no → disable. */
			peer->call_limit = ast_true(v->value) ? INT_MAX : 0;
		} else if (!strcasecmp(v->name, "call-limit") || !strcasecmp(v->name, "call_limit")) {
			/* call-limit canonical; call_limit accepted as an alias. */
			peer->call_limit = atoi(v->value);
			if (peer->call_limit < 0) peer->call_limit = 0;
		} else if (!strcasecmp(v->name, "busylevel")) {
			/* Soft-cap: outbound returns BUSY (486) when inUse >= busy_level. */
			peer->busy_level = atoi(v->value);
			if (peer->busy_level < 0) peer->busy_level = 0;
		} else if (!strcasecmp(v->name, "mailbox")) {
			/* Comma-separated mbox@ctx list (no @ defaults context to "default"). */
			sofia_peer_parse_mailboxes(peer, v->value);
		} else if (!strcasecmp(v->name, "outboundproxy")) {
			/* Per-peer outbound proxy override. Empty = unset; empty + a global
			 * sofia_cfg.outboundproxy means inherit the general default at use time. */
			ast_string_field_set(peer, outboundproxy, v->value);
		} else if (!strcasecmp(v->name, "mohinterpret")) {
			/* Per-peer MOH class for hold-MOH (chan_sip parity). */
			ast_string_field_set(peer, mohinterpret, v->value);
		} else if (!strcasecmp(v->name, "mohsuggest")) {
			/* Per-peer mohsuggest, inbound direction (chan_sip parity);
			 * outbound Alert-Info signaling deferred. */
			ast_string_field_set(peer, mohsuggest, v->value);
		} else if (!strcasecmp(v->name, "language")) {
			/* Per-peer audio locale → ast_channel.language (chan_sip parity). */
			ast_string_field_set(peer, language, v->value);
		} else if (!strcasecmp(v->name, "parkinglot")) {
			/* Per-peer parking-lot routing → ast_channel.parkinglot (chan_sip parity). */
			ast_string_field_set(peer, parkinglot, v->value);
		} else if (!strcasecmp(v->name, "defaultip")) {
			/* Per-peer defaultip (chan_sip parity). On resolve-fail, warn + leave
			 * defaddr null (keep the peer); chan_sip hard-fails the whole alloc. */
			if (!ast_strlen_zero(v->value) && ast_get_ip(&peer->defaddr, v->value)) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' defaultip='%s' could not be resolved; ignoring\n",
					peer->name, v->value);
				ast_sockaddr_setnull(&peer->defaddr);
			}
		} else if (!strcasecmp(v->name, "maxcallbitrate")) {
			/* atoi + clamp-negative-to-default (chan_sip parity). */
			peer->maxcallbitrate = atoi(v->value);
			if (peer->maxcallbitrate < 0) {
				peer->maxcallbitrate = sofia_cfg.default_maxcallbitrate;
			}
		} else if (!strcasecmp(v->name, "amaflags")) {
			/* ast_cdr_amaflags2int + warn-and-skip on invalid (chan_sip parity);
			 * preserves the channel-core default at sofia_new on parse-fail. */
			int format = ast_cdr_amaflags2int(v->value);
			if (format < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid AMA Flags '%s'; ignoring\n",
					peer->name, v->value);
			} else {
				peer->amaflags = format;
			}
		} else if (!strcasecmp(v->name, "subscribemwi")) {
			/* Parse-compat only — chan_sofia is SUBSCRIBE-only for MWI; there is no
			 * unsolicited MWI NOTIFY, so behavior matches subscribemwi=yes regardless.
			 * subscribemwi=no emits an honest LOG_NOTICE. */
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
			/* chan_sip parity. */
			peer->preferred_codec_only = ast_true(v->value);
		} else if (!strcasecmp(v->name, "ignoresdpversion")) {
			/* Parse-compat only — chan_sofia processes every SDP unconditionally. */
			peer->ignoresdpversion = ast_true(v->value);
		} else if (!strcasecmp(v->name, "promiscredir")) {
			/* Parse-compat only — chan_sofia has no nua_r_redirect handler. */
			peer->promiscredir = ast_true(v->value);
		} else if (!strcasecmp(v->name, "autoframing")) {
			/* Parse-compat only — the sofia_parse_sdp ptime gate is not wired yet. */
			peer->autoframing = ast_true(v->value);
		} else if (!strcasecmp(v->name, "timerb")) {
			/* sscanf %30d + clamp-to-default on invalid or <200ms (chan_sip parity). */
			int tmp_b;
			if ((sscanf(v->value, "%30d", &tmp_b) != 1) || tmp_b < 200) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid timerb '%s' (< 200ms or non-integer); using default %d\n",
					peer->name, v->value, sofia_cfg.default_timer_b);
				peer->timer_b = sofia_cfg.default_timer_b;
			} else {
				peer->timer_b = tmp_b;
			}
		} else if (!strcasecmp(v->name, "timert1")) {
			/* sscanf %30d; on invalid or < max(200, t1min) → warn + fall back to
			 * sofia_cfg.t1min (chan_sip-faithful floor: t1min, not default_timer_t1). */
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
			/* Per-peer T.38 enable + EC mode + MaxDatagram (chan_sip parity).
			 * Comma-separated: yes|no|fec|redundancy|none[,maxdatagram=N]; `yes`
			 * defaults EC to FEC. */
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
			/* Symmetric-RTP UDPTL destination override, boolean (chan_sip parity). */
			peer->t38pt_usertpsource = ast_true(v->value) ? 1 : 0;
		} else if (!strcasecmp(v->name, "allowoverlap")) {
			/* Tri-state (chan_sip parity): yes → YES; "dtmf" → DTMF; else → NO. */
			if (ast_true(v->value)) {
				peer->allowoverlap_mode = SOFIA_OVERLAP_YES;
			} else if (!strcasecmp(v->value, "dtmf")) {
				peer->allowoverlap_mode = SOFIA_OVERLAP_DTMF;
			} else {
				peer->allowoverlap_mode = SOFIA_OVERLAP_NO;
			}
		} else if (!strcasecmp(v->name, "progressinband")) {
			/* Tri-state (chan_sip parity): yes → YES; "never" → NEVER; else → NO. */
			if (ast_true(v->value)) {
				peer->progressinband = SOFIA_PROG_INBAND_YES;
			} else if (strcasecmp(v->value, "never")) {
				peer->progressinband = SOFIA_PROG_INBAND_NO;
			} else {
				peer->progressinband = SOFIA_PROG_INBAND_NEVER;
			}
		} else if (!strcasecmp(v->name, "rtptimeout")) {
			/* sscanf %30d + warn + clamp-to-global on invalid (chan_sip parity). */
			if ((sscanf(v->value, "%30d", &peer->rtptimeout) != 1) || peer->rtptimeout < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid rtptimeout '%s'; using default\n",
					peer->name, v->value);
				peer->rtptimeout = sofia_cfg.default_rtptimeout;
			}
		} else if (!strcasecmp(v->name, "rtpholdtimeout")) {
			/* sscanf %30d + warn + clamp-to-global on invalid (chan_sip parity). */
			if ((sscanf(v->value, "%30d", &peer->rtpholdtimeout) != 1) || peer->rtpholdtimeout < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid rtpholdtimeout '%s'; using default\n",
					peer->name, v->value);
				peer->rtpholdtimeout = sofia_cfg.default_rtpholdtimeout;
			}
		} else if (!strcasecmp(v->name, "rtpkeepalive")) {
			/* sscanf %30d + warn + clamp-to-global on invalid (chan_sip parity). */
			if ((sscanf(v->value, "%30d", &peer->rtpkeepalive) != 1) || peer->rtpkeepalive < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid rtpkeepalive '%s'; using default\n",
					peer->name, v->value);
				peer->rtpkeepalive = sofia_cfg.default_rtpkeepalive;
			}
		} else if (!strcasecmp(v->name, "callerid")) {
			/* ast_callerid_split → cid_name + cid_num (chan_sip parity). */
			char cid_name_buf[80] = "", cid_num_buf[80] = "";
			ast_callerid_split(v->value, cid_name_buf, sizeof(cid_name_buf),
				cid_num_buf, sizeof(cid_num_buf));
			ast_string_field_set(peer, cid_name, cid_name_buf);
			ast_string_field_set(peer, cid_num, cid_num_buf);
		} else if (!strcasecmp(v->name, "fullname")
				|| !strcasecmp(v->name, "cid_name")) {
			/* fullname (chan_sip parity); cid_name is a chan_sofia alias. */
			ast_string_field_set(peer, cid_name, v->value);
		} else if (!strcasecmp(v->name, "trunkname")) {
			/* trunkname clears cid_name (chan_sip parity). */
			ast_string_field_set(peer, cid_name, "");
		} else if (!strcasecmp(v->name, "cid_number")) {
			/* chan_sip parity. */
			ast_string_field_set(peer, cid_num, v->value);
		} else if (!strcasecmp(v->name, "cid_tag")) {
			/* chan_sip parity. */
			ast_string_field_set(peer, cid_tag, v->value);
		} else if (!strcasecmp(v->name, "callgroup")) {
			peer->callgroup = ast_get_group(v->value);
		} else if (!strcasecmp(v->name, "allowtransfer")) {
			/* ast_true → OPENFORALL/CLOSED (chan_sip parity). */
			peer->allowtransfer = ast_true(v->value) ? TRANSFER_OPENFORALL : TRANSFER_CLOSED;
		} else if (!strcasecmp(v->name, "allowsubscribe")) {
			/* Gates inbound SUBSCRIBE per-peer (chan_sip parity). */
			peer->allowsubscribe = ast_true(v->value);
		} else if (!strcasecmp(v->name, "gruu")) {
			/* Advertise a stable +sip.instance on this peer's outbound REGISTER. */
			peer->gruu = ast_true(v->value);
		} else if (!strcasecmp(v->name, "publish")) {
			/* outbound PUBLISH (RFC 3903): opt this peer's hint state into central-server publication. */
			peer->publish = ast_true(v->value);
		} else if (!strcasecmp(v->name, "buggymwi")) {
			/* a buggy SIP stack MWI workaround (chan_sip parity) — gates the
			 * Voice-Message " (0/0)" suffix at transmit_mwi_notify_for_peer. */
			peer->buggymwi = ast_true(v->value);
		} else if (!strcasecmp(v->name, "lockuseragent")) {
			/* chan_sip parity; ast_true generic semantic (yes/no/0/1/true/false). */
			peer->lockuseragent = ast_true(v->value);
		} else if (!strcasecmp(v->name, "lockuseragent_prefixes")) {
			/* Comma-separated User-Agent prefix allowlist consulted by
			 * sofia_check_lockuseragent when lockuseragent=yes. Stored verbatim;
			 * tokenization/match happens at REGISTER-time (config-load stays O(1) and
			 * the list is editable via `sip reload` / realtime UPDATE). */
			ast_string_field_set(peer, lockuseragent_prefixes, v->value);
		} else if (!strcasecmp(v->name, "usereqphone")) {
			/* RFC 3966 telephone-uri ;user=phone for E.164 via PSTN gateways
			 * (chan_sip parity). */
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
			/* ast_append_ha(v->name + 7, ...) skips the "contact" prefix (chan_sip
			 * parity). Separate ACL chain from peer->ha (source-IP). */
			int ha_error = 0;
			if (!ast_strlen_zero(v->value)) {
				peer->contactha = ast_append_ha(v->name + 7, v->value, peer->contactha, &ha_error);
			}
			if (ha_error) {
				ast_log(LOG_ERROR, "Sofia: bad %s line for peer '%s': %s\n",
					v->name, peer->name, v->value);
			}
		} else if (!strcasecmp(v->name, "directmediapermit") || !strcasecmp(v->name, "directmediadeny")) {
			/* ast_append_ha(v->name + 11, ...) skips the "directmedia" prefix
			 * (chan_sip parity); the remaining "permit"/"deny" is the sense. Applied
			 * cross-leg at sofia_get_rtp_peer. */
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
			/* Accepted but not applied (drop-in compat). chan_sofia does not gate
			 * per-peer inbound transport: the chan_sip check_request_transport
			 * allowlist runs after accept + parse + peer lookup, so it is policy not
			 * attack-surface reduction. Accepted transports are set per-listener via
			 * [general] *bindaddr, and per-Contact transport is derived from the
			 * Contact URL scheme at REGISTER-time. Legacy transport=udp[,tcp] rows are
			 * safe to leave in place. */
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

	sofia_apply_peer_variables(peer, var, 0);
	ast_variables_destroy(var);

	/* sipregs overlay (chan_sip parity): when extconfig wires `sipregs => …`,
	 * registration state (ipaddr/port/regseconds/fullcontact/etc.) lives in
	 * sipregs, not sippeers. Sequential dual-load; the second application is
	 * idempotent (skip-on-empty + field-replace). A NULL sipregs result (peer not
	 * yet registered) just continues with sippeers-only data.
	 *
	 * Operator contract — sipregs SHOULD carry only registration-state columns.
	 * The list-typed columns (permit/deny, contact/directmedia ACLs, setvar=,
	 * header=) belong in sippeers exclusively; in sipregs they would re-run the
	 * append-style parser on the SAME struct and silently duplicate entries (and
	 * register a second, never-coalesced MWI subscription per mailbox). The overlay
	 * pass passes overlay=1 so those append-only columns are skipped (not reset),
	 * preserving the sippeers-parsed lists when sipregs omits them. */
	if (ast_check_realtime("sipregs")) {
		struct ast_variable *regvar = ast_load_realtime("sipregs", "name", name, SENTINEL);
		if (regvar) {
			sofia_apply_peer_variables(peer, regvar, 1);
			ast_variables_destroy(regvar);
		}
	}

	peer->is_realtime = 1;
	/* Publish the peer into the container FIRST, then create the side effects.
	 * sofia_find_peer holds ao2_lock(peers) across the whole realtime build, so
	 * concurrent cache-miss builds for the same name are already serialised — link-
	 * first does not reintroduce a duplicate-build race. The win: on an ao2_link OOM
	 * nothing has been created yet, so there is no orphan hint / dnsmgr entry /
	 * contact_ha rule to unwind — just drain MWI, drop the build ref, fail. */
	if (!ao2_link(peers, peer)) {
		sofia_peer_drain_mwi(peer);
		ao2_ref(peer, -1);
		return NULL;
	}

	/* Create the static presence-hint extension (chan_sip parity). Runs AFTER
	 * ao2_link (link-first) so an OOM never leaves an orphan hint. */
	sofia_create_peer_hint(peer, "realtime");

	/* Register async DNS lookup if peer->host is a hostname (chan_sip parity).
	 * Runs AFTER ao2_link so it is never set up on an OOM publish-failure path. */
	sofia_dnsmgr_setup_peer(peer);

	/* dynamic_exclude_static [general] (chan_sip parity), at realtime peer-build
	 * conclusion. */
	if (sofia_cfg.dynamic_exclude_static && !ast_strlen_zero(peer->host)
			&& strcasecmp(peer->host, "dynamic")) {
		struct ast_sockaddr static_addr;
		if (ast_sockaddr_parse(&static_addr, peer->host, 0)) {
			int ha_error = 0;
			ast_rwlock_wrlock(&sofia_contactha_lock);
			sofia_cfg.contact_ha = ast_append_ha("deny",
				ast_sockaddr_stringify_addr(&static_addr),
				sofia_cfg.contact_ha, &ha_error);
			ast_rwlock_unlock(&sofia_contactha_lock);
			if (ha_error) {
				ast_log(LOG_ERROR,
					"Sofia: dynamic_exclude_static — bad addr for realtime static peer '%s' (%s)\n",
					peer->name, peer->host);
			}
		}
	}

	/* If this runtime-added realtime peer allows subscribe, flip the global derived
	 * flag (one-way, chan_sip parity). Already-TRUE short-circuits cheaply. */
	if (peer->allowsubscribe) {
		sofia_cfg.allowsubscribe = 1;
	}

	return peer;
}

/* Lookup-key shim for ao2_find(peers, &key, OBJ_POINTER): mirrors struct
 * sofia_peer's leading layout (AST_DECLARE_STRING_FIELDS emits the pool pointer
 * FIRST, then 'name' — the first string field, at offset 8) so peer_hash_fn /
 * peer_cmp_fn, which only read ->name, see the lookup name at the right offset
 * without allocating a full peer.  Keep in sync with struct sofia_peer @1339. */
struct sofia_peer_key {
	struct ast_string_field_pool *__field_mgr_pool;
	const char *name;
};

static int peer_hash_fn(const void *obj, int flags)
{
	const struct sofia_peer *peer = obj;

	return ast_str_case_hash(peer->name);
}

static int peer_cmp_fn(void *obj, void *arg, int flags)
{
	struct sofia_peer *peer = obj;
	struct sofia_peer *match = arg;	/* &sofia_peer_key — layout-compatible for ->name */

	return strcasecmp(peer->name, match->name) ? 0 : (CMP_MATCH | CMP_STOP);
}

struct sofia_peer *sofia_find_peer(const char *name)
{
	struct sofia_peer *found = NULL;

	/* Atomically check the in-memory cache and, on miss, build via realtime —
	 * BOTH under ao2_lock(peers) so two concurrent misses for the same name
	 * cannot both run sofia_find_peer_realtime and link duplicate peers (ao2_link
	 * does not refuse duplicates by name, so callers enforce uniqueness here).
	 *
	 * Holding the lock through the realtime DB query briefly serialises cache-miss
	 * work; the alternative (optimistic build + post-lock dup-check) would need the
	 * same serialisation anyway. Cache hits (the common case) never take the
	 * realtime path. ao2 container locks are recursive, so helpers invoked under
	 * the lock (sofia_create_peer_hint, sofia_dnsmgr_setup_peer) that re-enter ao2
	 * on the same container do not deadlock. */
	ao2_lock(peers);

	{
		struct sofia_peer_key key = { .name = name };

		found = ao2_find(peers, &key, OBJ_POINTER);
	}

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
 * for trunk gateways whose From-user is the caller-ID number, not the peer
 * name (e.g. a carrier softswitch sending From: <sip:NNNNNNNNN@…> while the peer
 * is configured as [trunk_example] host=203.0.113.10). Matches peer->src_addr
 * (set both by dnsmgr for static host=<ip> peers and by REGISTER for dynamic
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
			/* Static host=<ip-literal> peers never get src_addr populated
			 * (sofia_dnsmgr_setup_peer returns early at its IP-literal pre-check),
			 * so parse it on-the-fly here. */
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

/* Direct media: ast_rtp_glue plumbing, guarded by a single reinvite_pending flag. */

static enum ast_rtp_glue_result sofia_get_rtp_peer(struct ast_channel *chan,
		struct ast_rtp_instance **instance)
{
	struct sofia_pvt *pvt;

	if (!chan || !(pvt = chan->tech_pvt) || !pvt->rtp) {
		return AST_RTP_GLUE_RESULT_FORBID;
	}

	ao2_ref(pvt->rtp, +1);
	*instance = pvt->rtp;

	/* Direct media incompatible with SRTP — disclosing this leg's SRTP key to a
	 * remote endpoint via re-INVITE would defeat the encryption. Force LOCAL relay
	 * whenever SRTP is active, regardless of NAT or peer->directmedia (chan_sip
	 * parity). */
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
	/* Cross-leg directmedia ACL — apply the BRIDGE PARTNER's directmediaha against
	 * THIS leg's RTP remote addr (chan_sip parity).
	 *
	 * Defensive fall-throughs (NULL bridged-chan, non-sofia partner, NULL
	 * partner->peer, NULL directmediaha) all allow REMOTE, per chan_sip's
	 * NULL-passthrough. */
	{
		struct ast_channel *bridged_chan = sofia_find_bridged_channel(pvt);
		if (bridged_chan && bridged_chan->tech == &sofia_tech) {
			/* The +1 ref from sofia_find_bridged_channel keeps the partner CHANNEL
			 * alive but NOT its tech_pvt/peer — a concurrent sofia_hangup(partner)
			 * frees the partner pvt, so reading bridged_pvt->peer then locking it is a
			 * UAF. Pin the partner's peer UNDER the partner channel lock (trylock to
			 * avoid ABBA against THIS leg's held channel lock; on contention fall
			 * through to REMOTE), then hold an ao2 ref so bpeer survives the unlock. */
			struct sofia_peer *bpeer = NULL;
			if (!ast_channel_trylock(bridged_chan)) {
				struct sofia_pvt *bridged_pvt = bridged_chan->tech_pvt;
				bpeer = (bridged_pvt && bridged_pvt->peer) ? bridged_pvt->peer : NULL;
				if (bpeer) {
					ao2_ref(bpeer, +1);
				}
				ast_channel_unlock(bridged_chan);
			}
			if (bpeer) {
				/* reload-UAF: the bridge partner's peer->directmediaha is an
				 * ast_ha LIST that sofia_parse_peer_config frees (ast_free_ha
				 * + NULL) under peer->lock during a reload. A pointer can't be
				 * snapshotted, so HOLD bpeer->lock across the ast_apply_ha
				 * consume. peer->name is a freeable unbounded stringfield —
				 * snapshot it under the same lock for the debug line. */
				int denied = 0;
				char l_name[256];
				struct ast_sockaddr them = { { 0, }, };
				ast_rtp_instance_get_remote_address(pvt->rtp, &them);
				ast_mutex_lock(&bpeer->lock);
				if (bpeer->directmediaha &&
					ast_apply_ha(bpeer->directmediaha, &them) == AST_SENSE_DENY) {
					denied = 1;
					ast_copy_string(l_name, bpeer->name, sizeof(l_name));
				}
				ast_mutex_unlock(&bpeer->lock);
				ao2_ref(bpeer, -1);
				if (denied) {
					ast_debug(2, "Sofia: get_rtp_peer LOCAL — direct media to %s denied by bridge-partner '%s' directmedia ACL\n",
						ast_sockaddr_stringify(&them), l_name);
					ast_channel_unref(bridged_chan);	/* T3: helper returns a +1 ref */
					return AST_RTP_GLUE_RESULT_LOCAL;
				}
			}
		}
		if (bridged_chan) {
			ast_channel_unref(bridged_chan);	/* T3: helper returns a +1 ref */
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

/* Compute session-timer (RFC 4028) NUTAG values for a peer + direction. chan_sofia
 * computes config-derived integers; sofia-sip handles the wire mechanics
 * (Session-Expires header, auto-refresh scheduling, 422 Min-SE rejection).
 *
 * Returns 3 values via out-params:
 *   *out_st_seconds: -1 = skip NUTAG_SESSION_TIMER (don't initiate); 0 = explicit
 *                    disable (REFUSE); N = NUTAG_SESSION_TIMER(N).
 *   *out_min_se:     0 = skip NUTAG_MIN_SE; N = NUTAG_MIN_SE(N).
 *   *out_refresher:  -1 = skip (let negotiation decide); else nua_*_refresher.
 *
 * Mode mapping (chan_sip parity):
 *   OFF       -> all skip.
 *   ACCEPT    -> outbound: no session_timer + publish min_se.
 *                inbound:  set session_timer (200-OK echoes Session-Expires) + min_se.
 *   ORIGINATE -> outbound: session_timer + min_se + refresher per peer config.
 *                inbound:  same as ACCEPT (we are UAS).
 *   REFUSE    -> NUTAG_SESSION_TIMER(0): disables OUR origination only; sofia-sip
 *                still ACCEPTS a peer-offered Session-Expires, so inbound = ACCEPT. */
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
	/* RFC 3261 §20.22 — every outbound request needs a Max-Forwards header. */
	char mf_str[8];
	int mf = (pvt && pvt->peer) ? pvt->peer->maxforwards : sofia_cfg.default_max_forwards;
	snprintf(mf_str, sizeof(mf_str), "%d", mf);

	if (!pvt || !pvt->nh || !sofia_generate_sdp(pvt, sdp_buf, sizeof(sdp_buf))) {
		/* Nothing was sent — release the reinvite gate so a future bridge tick can
		 * retry (the directmedia marshal pre-sets reinvite_pending before dispatching
		 * here; without this clear a guard-fail would leave it stuck). */
		if (pvt) {
			pvt->reinvite_pending = 0;
		}
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

/* The directmedia re-INVITE must run on sofia_thread, NOT the bridge thread that
 * invokes .update_peer. sofia_set_rtp_peer stashes the new redirip + sets
 * reinvite_pending under pvt->lock and dispatches this with a +1 pvt ref; here we
 * re-lock pvt and run sofia_send_reinvite on sofia_thread. */
static void sofia_directmedia_reinvite_root(void *data)
{
	struct sofia_pvt *pvt = data;

	ast_mutex_lock(&pvt->lock);
	/* REVALIDATE the guards the bridge thread checked before dispatch — hangup can
	 * run in between, and sofia_hangup can leave pvt->nh non-NULL while moving the
	 * dialog DOWN, so without this we could send a late re-INVITE after BYE/CANCEL
	 * teardown began. Clear the gate and bail if the call is gone / not up / nh dropped. */
	if (pvt->alreadygone || pvt->state != SOFIA_DIALOG_STATE_UP || !pvt->nh) {
		pvt->reinvite_pending = 0;
		ast_mutex_unlock(&pvt->lock);
		ao2_ref(pvt, -1);
		return;
	}
	sofia_send_reinvite(pvt);
	ast_mutex_unlock(&pvt->lock);
	ao2_ref(pvt, -1);
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
	/* Marshal the re-INVITE onto sofia_thread. Set reinvite_pending so a concurrent
	 * bridge tick takes the "already pending" gate above rather than dispatching
	 * again, take a +1 pvt ref, drop pvt->lock, then dispatch. On dispatch failure
	 * clear reinvite_pending + drop the ref. */
	pvt->reinvite_pending = 1;
	ao2_ref(pvt, +1);
	ast_mutex_unlock(&pvt->lock);
	if (sofia_dispatch_to_root_thread(sofia_directmedia_reinvite_root, pvt) < 0) {
		ast_mutex_lock(&pvt->lock);
		pvt->reinvite_pending = 0;
		ast_mutex_unlock(&pvt->lock);
		ao2_ref(pvt, -1);
	}
	return 0;
}

static struct ast_rtp_glue sofia_rtp_glue = {
	.type = SOFIA_CHANNEL_TYPE,
	.get_rtp_info = sofia_get_rtp_peer,
	.get_vrtp_info = sofia_get_vrtp_peer,
	.update_peer = sofia_set_rtp_peer,
	.get_codec = sofia_get_codec,
};

/* Dialplan apps: SIPAddHeader / SIPRemoveHeader / SIPDtmfMode (chan_sip parity).
 * Storage uses channel variables __SIPADDHEADERnn; the outbound INVITE iterates
 * chan->varshead and appends each as SIPTAG_HEADER_STR. */
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

/* Sanitize a string for use inside a SIP quoted display-name. Drops the two
 * characters that terminate or escape a quoted-string (" and \) plus any control
 * character (incl. CR/LF), so the resulting "name" <sip:...> token is always
 * well-formed. A display name carrying one of these characters (e.g. inherited
 * verbatim from a caller's From or a dialplan-set CallerID) would otherwise make
 * the assembled From / Remote-Party-ID / P-Asserted-Identity unparseable, and
 * sofia-sip then rejects the entire outbound request. The display name is
 * cosmetic, so dropping the offending bytes is safe and cannot itself produce a
 * malformed header. */
static void sofia_quoted_name_sanitize(char *s)
{
	char *r, *w;
	if (!s) {
		return;
	}
	for (r = w = s; *r; r++) {
		unsigned char c = (unsigned char)*r;
		if (c == '"' || c == '\\' || c < 0x20 || c == 0x7f) {
			continue;
		}
		*w++ = *r;
	}
	*w = '\0';
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
		/* A SIPAddHeader value must be exactly one header line. An embedded or
		 * trailing CR/LF (a stray terminator, or a value copied verbatim from an
		 * inbound header) would make the assembled SIPTAG_HEADER_STR unparseable,
		 * and sofia-sip then rejects the ENTIRE INVITE (nua_client internal error,
		 * zero packets sent). Emit only the first line; drop anything from the
		 * first CR/LF onward. This also closes a header-injection vector. */
		size_t vlen = strcspn(value, "\r\n");
		if (vlen == 0) {
			continue;
		}
		if (vlen < strlen(value) && sofia_debug) {
			ast_log(LOG_NOTICE, "Sofia: stripped embedded CR/LF from SIPAddHeader value\n");
		}
		int written = snprintf(out_buf + used, out_len - used, "%.*s\r\n", (int)vlen, value);
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

	/* Outbound counter increment + 486 enforcement, BEFORE any state transition.
	 * AST_CAUSE_USER_BUSY maps to 486 Busy Here. No-op when the peer is unconfigured
	 * (call_limit=0 + busy_level=0). */
	if (sofia_update_call_counter(pvt, SOFIA_INC_CALL_RINGING) == -1) {
		ast->hangupcause = AST_CAUSE_USER_BUSY;
		return -1;
	}

	/* Pick callingpres from channel.caller.id, then let a configured peer override
	 * win (operator trust-but-verify over channel state). */
	pvt->callingpres = ast_party_id_presentation(&ast->caller.id);
	if (pvt->peer && pvt->peer->callingpres) {
		pvt->callingpres = pvt->peer->callingpres;
	}
	/* Write the resolved presentation back onto the channel so dialplan reads +
	 * outbound RPID emission share a consistent source-of-truth (sofia_new ran
	 * earlier with the default; this is the real value). */
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
		int posted_any = 0;   /* #1: set once any child actually reaches nua_invite */

		ci = ao2_iterator_init(pvt->peer->contacts, 0);
		while ((c = ao2_iterator_next(&ci))) {
			time_t c_exp;
			/* Snapshot the mutable expires under the contact lock (a concurrent
			 * REGISTER refresh rewrites it). */
			ao2_lock(c);
			c_exp = c->expires;
			ao2_unlock(c);
			if (c_exp > now)
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
			/* fork->master is dereferenced by fork-child event handlers on
			 * sofia_thread AFTER the caller may have hung up the master on the
			 * channel thread. Anchor the master pvt's lifetime with an ao2 ref so it
			 * can't be freed under those cross-thread derefs; the ref is released
			 * (and fork->master cleared) in sofia_hangup's is_fork_master block, the
			 * master's single teardown point. Not a ref cycle: the master holds
			 * pvt->fork, but sofia_hangup drops the fork->master ref first. */
			fork->master = pvt;
			ao2_ref(pvt, +1);
			fork->fork_start = now;
			ast_mutex_unlock(&fork->lock);

			pvt->fork = fork;
			pvt->is_fork_master = 1;
			/* Master has no nh — INVITEs go through child handles */

			ci = ao2_iterator_init(pvt->peer->contacts, 0);
			while ((c = ao2_iterator_next(&ci))) {
				struct sofia_pvt *child;
				char ruri[256];
				time_t c_exp;

				/* Snapshot expires under the contact lock (refresh race). */
				ao2_lock(c);
				c_exp = c->expires;
				ao2_unlock(c);
				if (c_exp <= now) {
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
				/* Inherit the master's resolved outbound identity so forked INVITEs
				 * carry the real caller's data, not peer defaults: the scalar fields
				 * here, and (only across the header builders below) a temporary
				 * child->owner alias for the owner-derived caller-id / redirecting. */
				child->callingpres = pvt->callingpres;
				ast_sockaddr_copy(&child->ourip, &pvt->ourip);

				/* Build RURI targeting this specific contact. c->host may be
				 * unbracketed IPv6 from REGISTER Contact parsing — the helper wraps
				 * it per RFC 3261 §19.1.2. */
				{
					char hbuf[80];
					char c_transport[8];
					snprintf(ruri, sizeof(ruri), "sip:%s@%s:%d", pvt->exten,
						sofia_uri_format_host(c->host, hbuf, sizeof(hbuf)),
						c->port);
					/* Fork each branch over its own contact's transport
					 * (snapshot the refresh-mutable field). */
					ao2_lock(c);
					ast_copy_string(c_transport, c->transport, sizeof(c_transport));
					ao2_unlock(c);
					sofia_uri_append_transport(ruri, sizeof(ruri), c_transport);
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
					/* Each fork-child needs independent crypto keys (RFC 4568). Hard-fail
					 * per child on alloc errors → skip nua_invite for this contact; others
					 * may still succeed. If ALL fail, child_count stays 0 and the caller
					 * gets 503 via the fork-empty path. No silent downgrade. */
					if (pvt->peer->encryption) {
						/* Per-peer cipher list (or [general] fallback) drives the
						 * multi-cipher a=crypto:N offer; NULL = legacy single line.
						 * reload-UAF: peer->srtpcipher is freeable under peer->lock by the
						 * reload writer, so snapshot it under peer->lock and keep the
						 * sdp_crypto_* calls OUTSIDE the lock. LOCK ORDER channel -> peer. */
						char l_srtpcipher[256];
						const char *cipher_list;
						l_srtpcipher[0] = '\0';
						ast_mutex_lock(&pvt->peer->lock);
						if (!ast_strlen_zero(pvt->peer->srtpcipher)) {
							ast_copy_string(l_srtpcipher, pvt->peer->srtpcipher, sizeof(l_srtpcipher));
						}
						ast_mutex_unlock(&pvt->peer->lock);
						cipher_list = !ast_strlen_zero(l_srtpcipher) ? l_srtpcipher
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
						/* The fork-child INVITE needs From + Contact too. The child
						 * inherits the master's resolved ourip; helpers read its owner's
						 * connected.id (forks share the channel/owner) and the shared
						 * callingpres/sendrpid/peer. */
						char from_buf[256];
						char contact_buf[256];
						char rpid_buf[512];
						char diversion_buf[512];
						/* reload-UAF: the From/identity builders read freeable peer
						 * stringfields (cid_num/fromuser/name/cid_name/fromdomain) that the
						 * reload writer frees under peer->lock. Every call here is pure
						 * string-formatting, so hold child->peer->lock across the whole
						 * builder block. LOCK ORDER channel -> peer (pvt->lock not held). */
						/* Alias the master's channel as the child's owner ONLY across the
						 * identity builders so they read the real caller's connected.id /
						 * redirecting instead of peer defaults. ast_call holds the master
						 * channel lock for all of sofia_call, so this read is safe; it is
						 * reset to NULL below before the child is linked/invited, so no
						 * event ever observes a child owning the channel. */
						child->owner = pvt->owner;
						if (child->peer) {
							ast_mutex_lock(&child->peer->lock);
						}
						sofia_build_from(child, from_buf, sizeof(from_buf));
						sofia_build_contact(child, contact_buf, sizeof(contact_buf));
						sofia_add_rpid(child, rpid_buf, sizeof(rpid_buf));
						/* Outbound Diversion header (RFC 5806) when a redirecting chain is present. */
						sofia_add_diversion(child, diversion_buf, sizeof(diversion_buf));
						if (child->peer) {
							ast_mutex_unlock(&child->peer->lock);
						}
						child->owner = NULL;
						/* Per-child session timers (RFC 4028); sofia-sip auto-handles
						 * refresh re-INVITE scheduling. */
						int st_seconds, st_min_se, st_refresher;
						sofia_session_timer_values(pvt->peer, 1 /* outbound */, &st_seconds, &st_min_se, &st_refresher);
						/* RFC 3261 §20.22 fork-child outbound Max-Forwards. */
						char mf_str_child[8];
						snprintf(mf_str_child, sizeof(mf_str_child), "%d", child->peer ? child->peer->maxforwards : sofia_cfg.default_max_forwards);
						/* Link the child into fork->children + dialogs and count it BEFORE
						 * nua_invite, so an immediate local error/1xx the sofia_thread
						 * dispatches can find the child via sofia_pvt_ref_if_linked. Only
						 * children that reach nua_invite are linked/counted, so one that
						 * failed nh/rtp/crypto setup is never counted — child_count stays exact.
						 *
						 * ao2_link returns NULL on OOM. An INVITE for a child NOT in `dialogs`
						 * (response unroutable → master hangs) or NOT in fork->children
						 * (uncancellable loser) corrupts the fork — require BOTH links before
						 * counting + inviting; undo a partial link and skip the invite on
						 * failure. The child's creation ref is dropped below, freeing the
						 * now-unlinked child. */
						int child_linked = 0;
						if (ao2_link(fork->children, child)) {
							if (ao2_link(dialogs, child)) {
								child_linked = 1;
							} else {
								ao2_unlink(fork->children, child);
							}
						}
						if (child_linked) {
						ast_mutex_lock(&fork->lock);
						fork->child_count++;
						ast_mutex_unlock(&fork->lock);
						posted_any = 1;
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
				}

				if (sofia_debug)
					ast_verbose("Sofia: Fork child %d -> %s (branch=%s)\n",
						branch_idx, ruri, child->fork_branch_id);

				ao2_ref(child, -1);
				branch_idx++;
				ao2_ref(c, -1);
			}
			ao2_iterator_destroy(&ci);

			/* If NO contact was ever invited (every child failed setup), no INVITE is
			 * in flight so no response/all-failed event can arrive — the master would
			 * hang forever. Fail the call now (the core hangs up the leg, sofia_hangup
			 * reclaims the childless fork). posted_any, not a child_count read, is used
			 * deliberately: the case where children WERE posted then all failed fast is
			 * left to the event-driven all-failed HANGUP, not double-signalled here. */
			if (!posted_any) {
				ast_log(LOG_WARNING,
					"Sofia: fork to peer '%s' emitted no INVITE (all contacts failed setup) — failing call\n",
					pvt->peername);
				return -1;
			}

			ast_mutex_lock(&pvt->lock);
			/* A fast fork winner may already have advanced master->state to
			 * UP/RINGING DURING the loop (link-before-invite widened that window). Do
			 * NOT clobber an already-advanced state back to TRYING — a later hangup
			 * would then CANCEL (invalid post-200) instead of BYE, leaving a zombie
			 * answered leg. */
			if (pvt->state != SOFIA_DIALOG_STATE_UP
					&& pvt->state != SOFIA_DIALOG_STATE_RINGING) {
				pvt->state = SOFIA_DIALOG_STATE_TRYING;
			}
			ast_mutex_unlock(&pvt->lock);
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

	/* sofia_rtp_init runs in sofia_request_call BEFORE sofia_new (chan_sip
	 * ordering). Without it, chan->fds[0..3] would be wired with pvt->rtp == NULL
	 * → the bridge poll never sees the outbound RTP read fd → silent one-way audio.
	 * (sofia_rtp_init is idempotent.) */

	/* Enable inband-DTMF detect after RTP setup. dtmfmode/peer were bound in
	 * sofia_request_call; the helper internal-gates on INBAND/AUTO so non-inband
	 * peers pay zero alloc cost. */
	sofia_enable_dsp_detect(pvt);

	/* Outbound encryption setup BEFORE generate_sdp so SAVP + a=crypto land in the
	 * offer. Hard-fail on alloc errors — encryption=yes that we cannot honor must
	 * fail loud (-1 → 503), never silently downgrade. */
	if (pvt->peer && pvt->peer->encryption) {
		/* Per-peer cipher list (or [general] fallback) drives the multi-cipher
		 * a=crypto:N offer; NULL = legacy single line.
		 * reload-UAF: peer->srtpcipher is freeable under peer->lock by the reload
		 * writer, so snapshot it under peer->lock and keep the sdp_crypto_* calls
		 * OUTSIDE the lock. LOCK ORDER channel -> peer (pvt->lock not held). */
		char l_srtpcipher[256];
		const char *cipher_list;
		l_srtpcipher[0] = '\0';
		ast_mutex_lock(&pvt->peer->lock);
		if (!ast_strlen_zero(pvt->peer->srtpcipher)) {
			ast_copy_string(l_srtpcipher, pvt->peer->srtpcipher, sizeof(l_srtpcipher));
		}
		ast_mutex_unlock(&pvt->peer->lock);
		cipher_list = !ast_strlen_zero(l_srtpcipher) ? l_srtpcipher
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

	ast_mutex_lock(&pvt->lock);
	pvt->state = SOFIA_DIALOG_STATE_TRYING;
	ast_mutex_unlock(&pvt->lock);

	has_addheaders = sofia_build_addheader_str(ast, addheader_buf, sizeof(addheader_buf));

	{
		/* Build From + Contact (chan_sip parity). ourip is populated by
		 * sofia_resolve_ourip in sofia_request_call before sofia_call runs. sofia-sip
		 * auto-emits the From-tag; we provide the URI without ;tag=. */
		char from_buf[256];
		char contact_buf[256];
		char rpid_buf[512];
		char diversion_buf[512];
		/* reload-UAF: the From/identity builders read freeable peer stringfields
		 * (cid_num/fromuser/name/cid_name/fromdomain) that the reload writer frees
		 * under peer->lock. Every call here is pure string-formatting, so hold
		 * pvt->peer->lock across the whole builder block. LOCK ORDER channel -> peer. */
		if (pvt->peer) {
			ast_mutex_lock(&pvt->peer->lock);
		}
		sofia_build_from(pvt, from_buf, sizeof(from_buf));
		sofia_build_contact(pvt, contact_buf, sizeof(contact_buf));
		/* Outbound RPID/PAI/Privacy per peer->sendrpid (no-op when 0). */
		sofia_add_rpid(pvt, rpid_buf, sizeof(rpid_buf));
		/* Outbound Diversion header (RFC 5806) when a redirecting chain is present. */
		sofia_add_diversion(pvt, diversion_buf, sizeof(diversion_buf));
		if (pvt->peer) {
			ast_mutex_unlock(&pvt->peer->lock);
		}

		/* Diagnostic: dump the header strings handed to nua_invite. A malformed
		 * value in any of these makes sofia-sip reject the request at construction
		 * (nua_client internal error) before a single packet leaves. Gated on
		 * `sip set debug`. */
		if (sofia_debug) {
			ast_verbose("Sofia: outbound INVITE headers to '%s' from=[%s] contact=[%s] addhdr=[%s] rpid=[%s] diversion=[%s]\n",
				pvt->peer ? pvt->peer->name : "(none)",
				from_buf, contact_buf,
				has_addheaders ? addheader_buf : "",
				rpid_buf, diversion_buf);
		}

		/* Single-contact outbound session timers (RFC 4028). */
		int st_seconds, st_min_se, st_refresher;
		sofia_session_timer_values(pvt->peer, 1 /* outbound */, &st_seconds, &st_min_se, &st_refresher);
		/* RFC 3261 §20.22 outbound Max-Forwards. */
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

/* Outbound text-message sender (SendText / chan_sip parity). Best-effort: the UA
 * replies 405 if MESSAGE is unsupported. RFC 3428 §10 zero-length message is
 * allowed; NULL text is a no-op success. nua_message is in-dialog (pvt->nh already
 * bound from the initial INVITE). Returns 0 on success/no-op, -1 on missing pvt/nh. */
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

	/* Channel-hangup counter DEC. Decrements peer->inUse if this pvt incremented it
	 * (call_inc_done flag-gated for multi-site safety with the BYE handlers +
	 * destructor catchall). */
	sofia_update_call_counter(pvt, SOFIA_DEC_CALL_LIMIT);

	ast_mutex_lock(&pvt->lock);

	/* Fork master hangup — CANCEL all children if no winner yet */
	if (pvt->is_fork_master && pvt->fork) {
		struct sofia_fork *fork = pvt->fork;
		int picked;
		struct sofia_pvt *fork_master;

		/* Clear fork->master under fork->lock and drop the ref taken at fork
		 * creation. A fork-child event still in flight reads fork->master under
		 * fork->lock; once cleared it reads NULL and skips the master deref. The
		 * dropped ref only removes the lifetime anchor — pvt stays alive below via
		 * its alloc/dialogs refs (released at the end of this function). */
		ast_mutex_lock(&fork->lock);
		picked = fork->winner_picked;
		fork_master = fork->master;
		fork->master = NULL;
		ast_mutex_unlock(&fork->lock);

		if (!picked) {
			ao2_callback(fork->children, OBJ_UNLINK | OBJ_MULTIPLE | OBJ_NODATA,
				sofia_fork_cancel_all_cb, NULL);
			ast_verbose("Sofia: Fork master hangup — cancelled all children (%s)\n",
				fork->fork_id);
		}
		/* Post-winner: master has stolen winner's nh, fall through to nua_bye below */

		if (fork_master) {
			ao2_ref(fork_master, -1);
		}
		ao2_ref(fork, -1);
		pvt->fork = NULL;
		pvt->is_fork_master = 0;
	}

	/* defer-bye-on-transfer (chan_sip parity). When the REFER handler armed
	 * defer_bye, the transferer's UA owns the dialog teardown: detach the channel
	 * side here but leave the SIP dialog alive (no nua_bye, no ao2_unlink). The
	 * safety-net timer sofia_defer_bye_cb or the incoming-BYE handler tears the pvt
	 * down later. */
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
	/* sdp_buf is 2048 (not 1024): T.38 emission adds ~250 bytes (m=image + 8
	 * a=T38Fax* attrs) to a worst-case audio+video SDP. At 1024 the emitter would
	 * snprintf-truncate and silently drop trailing attributes. */
	char sdp_buf[2048];

	if (!pvt || !pvt->nh) {
		return -1;
	}

	{
		/* Inbound 200-OK accept-path session timers (RFC 4028). sofia-sip
		 * auto-includes Session-Expires in the 200-OK when the peer's INVITE
		 * carried it and our mode != REFUSE. */
		int st_seconds, st_min_se, st_refresher;
		sofia_session_timer_values(pvt->peer, 0 /* inbound */, &st_seconds, &st_min_se, &st_refresher);
		/* Stamp Contact from the per-leg kernel-routed source address (pvt->ourip),
		 * as the outbound INVITE does. On a wildcard-bound box reachable on more than
		 * one interface, letting sofia-sip auto-generate the Contact picks one
		 * interface for every dialog; a leg whose peer is on the other interface then
		 * gets a Contact it cannot route back to, so the ACK + in-dialog requests
		 * never reach us and the dialog never completes even though media flowed.
		 * pvt->ourip is resolved toward the signaling peer on the inbound INVITE path,
		 * so the Contact host:port always reaches this leg. RFC 3261 §12.1.1 /
		 * §8.1.1.8; chan_sip parity. */
		char contact_buf[256];
		/* reload-UAF: sofia_build_contact reads freeable peer stringfields (fromuser)
		 * that the reload writer frees under peer->lock; this runs on the answer
		 * thread. It is pure string formatting, so hold peer->lock across it. */
		if (pvt->peer) ast_mutex_lock(&pvt->peer->lock);
		sofia_build_contact(pvt, contact_buf, sizeof(contact_buf));
		if (pvt->peer) ast_mutex_unlock(&pvt->peer->lock);
		if (sofia_generate_sdp(pvt, sdp_buf, sizeof(sdp_buf))) {
			nua_respond(pvt->nh, SIP_200_OK,
				TAG_IF(!ast_sockaddr_isnull(&pvt->ourip), SIPTAG_CONTACT_STR(contact_buf)),
				TAG_IF(st_seconds >= 0, NUTAG_SESSION_TIMER(st_seconds)),
				TAG_IF(st_min_se > 0, NUTAG_MIN_SE(st_min_se)),
				TAG_IF(st_refresher >= 0, NUTAG_SESSION_REFRESHER(st_refresher)),
				SIPTAG_CONTENT_TYPE_STR("application/sdp"),
				SIPTAG_PAYLOAD_STR(sdp_buf),
				TAG_END());
		} else {
			nua_respond(pvt->nh, SIP_200_OK,
				TAG_IF(!ast_sockaddr_isnull(&pvt->ourip), SIPTAG_CONTACT_STR(contact_buf)),
				TAG_IF(st_seconds >= 0, NUTAG_SESSION_TIMER(st_seconds)),
				TAG_IF(st_min_se > 0, NUTAG_MIN_SE(st_min_se)),
				TAG_IF(st_refresher >= 0, NUTAG_SESSION_REFRESHER(st_refresher)),
				TAG_END());
		}
	}

	ast_mutex_lock(&pvt->lock);
	pvt->state = SOFIA_DIALOG_STATE_UP;
	ast_mutex_unlock(&pvt->lock);
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
		/* Audio-path DSP processing (chan_sip parity, audio-only — rtcp +
		 * video paths bypass DSP). ast_dsp_process emits AST_FRAME_DTMF on
		 * tone detection, else passes the frame through. DSP is NULL when
		 * neither DTMF nor fax-CNG detection needs it. */
		if (f && pvt->dsp && pvt->owner) {
			f = ast_dsp_process(pvt->owner, pvt->dsp, f);
			/* ast_dsp_process emits AST_FRAME_DTMF subclass 'f' on fax CNG
			 * tone detection. async-goto the channel into the "fax"
			 * extension (chan_sip parity); dialplan SendFAX/ReceiveFAX uses
			 * ast_channel_get_t38_state to trigger a T.38 reINVITE. FAXEXTEN
			 * channel-var carries the original extension for return-on-
			 * fax-end. Gated via pvt->peer->faxdetect_mode. */
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
		/* T.38 UDPTL frame dispatch from fd-5 (chan_sip parity). Returns
		 * AST_FRAME_MODEM frames into core for res_fax/app_fax. NULL-safe —
		 * returns null_frame if pvt->udptl raced to NULL between fd-poll and
		 * read (sofia_hangup + destructor ast_udptl_destroy ordering). */
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

	/* AST_FRAME_MODEM → ast_udptl_write (chan_sip parity). Gated on dialog
	 * UP-state + pvt->udptl non-NULL + t38_state == ENABLED to avoid emitting
	 * UDPTL before negotiation completes; MODEM frames are silently dropped
	 * pre-negotiation (the fax stack re-transmits — UDPTL is two-way so
	 * early-media has no value). */
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
	{
		/* Contact from the per-leg kernel-routed source address; see the note in
		 * sofia_answer. The early dialog target must match the interface that
		 * reaches this leg on a multihomed wildcard bind. */
		char contact_buf[256];
		/* reload-UAF fix: hold peer->lock across sofia_build_contact (reads
		 * freeable peer->fromuser); pure string formatting, runs off sofia_thread. */
		if (pvt->peer) ast_mutex_lock(&pvt->peer->lock);
		sofia_build_contact(pvt, contact_buf, sizeof(contact_buf));
		if (pvt->peer) ast_mutex_unlock(&pvt->peer->lock);
		nua_respond(pvt->nh, SIP_180_RINGING,
			TAG_IF(!ast_sockaddr_isnull(&pvt->ourip), SIPTAG_CONTACT_STR(contact_buf)),
			TAG_END());
	}
		/* progressinband tri-state (chan_sip parity): YES → return -1 to
		 * force core in-band audio playback. NEVER (default) + NO return 0
		 * (SIP-handled, no in-band). KNOWN LIMITATION: NO degrades to NEVER —
		 * chan_sofia lacks SIP_PROGRESS_SENT tracking for chan_sip's
		 * "after-progress-sent in-band" semantic. */
		if (pvt->peer && pvt->peer->progressinband == SOFIA_PROG_INBAND_YES) {
			return -1;
		}
		break;
	case AST_CONTROL_BUSY:
		nua_respond(pvt->nh, SIP_486_BUSY_HERE, TAG_END());
		break;
	case AST_CONTROL_INCOMPLETE:
		/* allowoverlap tri-state (chan_sip parity) for the dialplan-driven
		 * Incomplete-app path. Pre-UP gated. YES → 484 Address Incomplete;
		 * DTMF → wait for inband DTMF (no-op); NO/default → 404 Not Found.
		 * Effective mode = peer->allowoverlap_mode when peer bound, else
		 * sofia_cfg.default_allowoverlap_mode. */
		if (ast->_state != AST_STATE_UP) {
			int overlap_mode = pvt->peer ? pvt->peer->allowoverlap_mode : sofia_cfg.default_allowoverlap_mode;
			switch (overlap_mode) {
			case SOFIA_OVERLAP_YES:
				nua_respond(pvt->nh, SIP_484_ADDRESS_INCOMPLETE, TAG_END());
				break;
			case SOFIA_OVERLAP_DTMF:
				/* Just wait for inband DTMF digits (chan_sip parity). */
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
		/* prematuremedia: INVERTED-SEMANTIC chan_sip quirk preserved — when
		 * prematuremediafilter is TRUE (filter ON, default), 183 Session
		 * Progress is SUPPRESSED even on an explicit dialplan Progress() call.
		 * The operator key "prematuremedia=yes" reads counter-intuitively but
		 * matches chan_sip drop-in compat exactly. */
		if (!sofia_cfg.prematuremediafilter) {
			/* chan_sip parity: emit 183 Session Progress WITH an SDP body so
			 * the INVITE offer is properly answered at the early-media stage.
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
			/* Contact from the per-leg kernel-routed source address; see the note
			 * in sofia_answer. Keeps the early-dialog target on the interface that
			 * reaches this leg on a multihomed wildcard bind. */
			char contact_buf[256];
			/* reload-UAF fix: hold peer->lock across sofia_build_contact (reads
			 * freeable peer->fromuser); pure string formatting, runs off sofia_thread. */
			if (pvt->peer) ast_mutex_lock(&pvt->peer->lock);
			sofia_build_contact(pvt, contact_buf, sizeof(contact_buf));
			if (pvt->peer) ast_mutex_unlock(&pvt->peer->lock);
			if (pvt->rtp && sofia_generate_sdp(pvt, sdp_buf, sizeof(sdp_buf))) {
				nua_respond(pvt->nh, SIP_183_SESSION_PROGRESS,
					TAG_IF(!ast_sockaddr_isnull(&pvt->ourip), SIPTAG_CONTACT_STR(contact_buf)),
					SIPTAG_CONTENT_TYPE_STR("application/sdp"),
					SIPTAG_PAYLOAD_STR(sdp_buf),
					TAG_END());
			} else {
				/* RTP not yet bound — fall back to bodyless 183. Should be rare
				 * in practice: sofia_rtp_init runs in sofia_process_invite
				 * (inbound) and sofia_request_call (outbound) before
				 * AST_CONTROL_PROGRESS can reach the channel. */
				nua_respond(pvt->nh, SIP_183_SESSION_PROGRESS,
					TAG_IF(!ast_sockaddr_isnull(&pvt->ourip), SIPTAG_CONTACT_STR(contact_buf)),
					TAG_END());
			}
		}
		break;
	case AST_CONTROL_ANSWER:
		sofia_answer(ast);
		break;
	case AST_CONTROL_HOLD:
		/* MOH per-peer (chan_sip parity): peer->mohinterpret as interpclass
		 * fallback when data (mohsuggest from upstream bridge) is empty.
		 *
		 * reload-UAF fix: peer->mohinterpret is an unbounded stringfield that
		 * the reload writer (sofia_thread) frees. This path runs on the
		 * bridge/dialplan thread, so the bare read raced the reload. Snapshot
		 * the field under peer->lock, drop the lock, then call ast_moh_start
		 * with the local. peer->lock is NOT held across ast_moh_start because
		 * it may lock the channel (lock-order: never channel under peer->lock). */
		{
			char l_mohinterpret[256] = "";
			if (pvt->peer) {
				ast_mutex_lock(&pvt->peer->lock);
				ast_copy_string(l_mohinterpret, pvt->peer->mohinterpret, sizeof(l_mohinterpret));
				ast_mutex_unlock(&pvt->peer->lock);
			}
			ast_moh_start(ast, data,
				!ast_strlen_zero(l_mohinterpret) ? l_mohinterpret : NULL);
		}
		break;
	case AST_CONTROL_UNHOLD:
		ast_moh_stop(ast);
		break;
	case AST_CONTROL_SRCUPDATE:
		/* RTP source-update (chan_sip parity): fired when the audio source
		 * feeding the channel changes WITHOUT changing identity (e.g. bridge
		 * re-cued after MOH-stop). Set the RTP marker bit to reset packet-stream
		 * state but keep the same SSRC. Must return 0, NOT -1 — core reads -1 as
		 * "driver doesn't handle, drop the indication" and the change never
		 * happens. */
		if (pvt->rtp) {
			ast_rtp_instance_update_source(pvt->rtp);
		}
		break;
	case AST_CONTROL_SRCCHANGE:
		/* RTP source-CHANGED (chan_sip parity): fired when the audio source
		 * itself changes (masquerade swap, bridge transition, file-play start).
		 * Bumps local outbound SSRC + sets marker bit so the far end resets its
		 * jitter-buffer to the new stream. Must return 0, NOT -1: returning -1
		 * dropped the indication, so PSTN gateways kept stale jitter-buffer
		 * state after a REFER blind-transfer swap → one-way silence. */
		if (pvt->rtp) {
			ast_rtp_instance_change_source(pvt->rtp);
		}
		break;
	case -1:
		/* ast_indicate(chan, -1) signals "stop whatever indication you're
		 * doing" (e.g. stop ringing tone). chan_sofia has no pending indication
		 * state; silently succeed without warning (chan_sip parity). */
		break;
	case AST_CONTROL_T38_PARAMETERS:
		/* app_fax / res_fax queue this control frame to drive T.38 negotiation
		 * (chan_sip parity). See sofia_interpret_t38_parameters for the op-table. */
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

/* AST_OPTION_T38_STATE queryoption handler (chan_sip parity). Required by
 * app_fax / res_fax, which call ast_channel_get_t38_state → ast_channel_
 * queryoption(AST_OPTION_T38_STATE). Without this handler no fax stack works
 * on chan_sofia (fax stack sees UNKNOWN/UNAVAILABLE → fax flow rejected). Maps
 * pvt->t38_state to enum ast_t38_state: LOCAL_REINVITE + PEER_REINVITE →
 * NEGOTIATING; ENABLED → NEGOTIATED; default → UNKNOWN. UNAVAILABLE when
 * pvt->peer->t38pt_udptl=0 (T.38 disabled per peer config). pvt->lock held
 * across the state read. */
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
				"Signal=%c\r\nDuration=%u\r\n", digit, duration ? duration : 250);
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
		/* chan_sip parity: no '/' separator — try the "exten@peer" syntax
		 * before falling back to a bare peer name. The part before '@' is the
		 * Request-URI user (extension to dial), the part after is the configured
		 * peer name used for routing — so Dial(SIP/9999#622501314@trunk_eli3)
		 * resolves to peer=trunk_eli3, exten=9999#622501314. Without this, peer
		 * lookup fails on the full string and the call ends in CHANUNAVAIL. If
		 * neither '/' nor '@' is present, treat the whole input as a plain peer
		 * name (no extension). */
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
		/* reload-UAF fix: the reload writer (sofia_thread) frees the peer
		 * stringfield pool under peer->lock when a value grows. This block runs
		 * on the PBX dialing thread and reads many freeable peer stringfields
		 * (context/defaultuser/secret/fromuser/fromdomain/subscribecontext/
		 * accountcode, plus peer->host/outboundproxy inside the helpers below).
		 * Hold peer->lock across the whole field-reading span; release it right
		 * before sofia_resolve_ourip (the only blocking call — DNS + kernel-route
		 * query — which reads no freeable peer stringfield). The span takes no
		 * channel/pvt lock, so it cannot invert channel->pvt->peer; the reload
		 * writer holds peer->lock as a leaf. */
		ast_mutex_lock(&peer->lock);
		ast_string_field_set(pvt, context, peer->context);
		ast_string_field_set(pvt, username, peer->defaultuser);
		ast_string_field_set(pvt, peersecret, peer->secret);
		ast_string_field_set(pvt, fromuser, peer->fromuser);
		ast_string_field_set(pvt, fromdomain, peer->fromdomain);
		pvt->capability = peer->capability;
		pvt->prefs = peer->prefs;
		pvt->dtmfmode = peer->dtmfmode;
		pvt->allowtransfer = peer->allowtransfer; /* inherit peer REFER policy (chan_sip parity) */
		ast_string_field_set(pvt, subscribecontext, peer->subscribecontext); /* inherit peer SUBSCRIBE dispatch context (chan_sip parity) */
		ast_string_field_set(pvt, accountcode, peer->accountcode); /* inherit peer CDR billing-tag (chan_sip parity); propagated to chan->accountcode via sofia_new */
		ao2_ref(peer, +1); pvt->peer = peer;

		{
			char url[256];
			char route_buf[256];

			sofia_resolve_peer_target(peer, exten, url, sizeof(url));
			/* Outbound INVITE Route header from peer/[general] outboundproxy.
			 * Sticky-on-handle: NUTAG_INITIAL_ROUTE_STR at handle-create
			 * persists for subsequent nua_invite/etc on the same handle. */
			sofia_format_outboundproxy(peer, route_buf, sizeof(route_buf));
			/* Resolve our source IP for this peer's reachable address. Used by
			 * sofia_generate_sdp + sofia_build_from/sofia_build_contact below. */
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
				/* Release peer->lock before sofia_resolve_ourip: it blocks on DNS
				 * (ast_sockaddr_resolve) + a kernel route query (ast_ouraddrfor) and
				 * must not run under the peer mutex. All freeable peer stringfields
				 * were already read above; `target` is a local copy and everything
				 * after this point (ruri set from local url, the NAT proxy_url block
				 * reading only peer->nat/src_addr/port, nua_handle) reads no freeable
				 * peer stringfield. */
				ast_mutex_unlock(&peer->lock);
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
			 * carries the peer's LAN IP (e.g. a phone advertising 192.168.x.x
			 * even when registered from 95.23.145.25). NUTAG_PROXY pins all
			 * outgoing dialog messages to peer->src_addr — the registered/
			 * resolved public address — so ACK reaches the phone, suppressing
			 * the 200 OK retransmit loop and unblocking the call. */
			/* Route this sticky dialog proxy through the shared helper: it
			 * applies the same nat/src_addr guards AND appends peer->reg_transport,
			 * so a TCP/TLS NAT peer's ACK/BYE don't default to UDP. Read lock-free
			 * here (peer->lock released above): nat/src_addr/port/reg_transport are
			 * fixed peer struct members, not freeable stringfields. */
			char proxy_url[128] = "";
			sofia_build_nat_proxy_url_from_peer(peer, proxy_url, sizeof(proxy_url));
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

	/* DO NOT REORDER: sofia_rtp_init MUST run BEFORE sofia_new, which wires
	 * chan->fds[0..3] from pvt->rtp/pvt->vrtp — without rtp allocated first the
	 * `if (pvt->rtp)` gate fails, fds stay at the default (-1), the bridge-poll
	 * select never sees the outbound RTP read fd, and incoming trunk audio sits
	 * in the kernel socket buffer forever (silent one-way audio). chan_sip
	 * parity. Inbound (sofia_process_invite) already orders rtp_init before
	 * sofia_new; fork-pick-winner refreshes fds from the stolen rtp post-pick. */
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
	pvt->outgoing = 1; /* outbound dial — sofia_add_rpid reads this for ;party=calling */

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
	if (sdp) {
		sdp_media_t *m;
		/* Inspect the AUDIO media descriptor, not just the first m= line —
		 * when audio is not first (m=image/T.38 or m=video leads), reading
		 * sdp_media->m_mode mis-detects hold. */
		for (m = sdp->sdp_media; m; m = m->m_next) {
			if (m->m_type == sdp_media_audio && m->m_port != 0) {
				if (m->m_mode == sdp_sendonly || m->m_mode == sdp_inactive) {
					hold = 1;
				}
				break;
			}
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
	struct ast_channel *owner = NULL;
	char own_name[80] = "";
	char own_uniqueid[150] = "";
	int old_hold;
	int new_hold;
	int trans;
	int sdp_ok;
	int st_refresh = 0; /* session timers (RFC 4028): uas-refresh discriminator */
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
	trans = (old_hold != new_hold);
	/* DEFER committing pvt->hold_state + peer->onHold until after
	 * sofia_parse_sdp() succeeds: a re-INVITE whose SDP is rejected (488) must
	 * leave the established call's hold accounting unchanged (RFC 3261 §14) —
	 * committing here drifted `sip show inuse` / AMI OnHold and broke the next
	 * re-INVITE's old_hold!=new_hold detection. new_hold/trans are computed now
	 * because the AMI Hold event + MOH queue below fire on the transition; the
	 * commit is deferred to post-parse. */
	/* Re-acquire in canonical channel->pvt order so sofia_parse_sdp's
	 * set_format (and the HOLD/UNHOLD queue below) re-enter a channel lock
	 * we already hold instead of inverting against ast_hangup. Mirrors
	 * chan_sip sip_pvt_lock_full: ref owner, drop pvt, lock channel, relock
	 * pvt, revalidate identity (owner may be swapped by a masquerade or
	 * cleared by a concurrent hangup during the window). */
	for (;;) {
		owner = pvt->owner;
		if (!owner) {
			break;
		}
		ast_channel_ref(owner);
		ast_mutex_unlock(&pvt->lock);
		ast_channel_lock(owner);
		ast_mutex_lock(&pvt->lock);
		if (pvt->owner == owner) {
			break;
		}
		ast_channel_unlock(owner);
		ast_channel_unref(owner);
		owner = NULL;
	}
	if (sip && sip->sip_payload && sip->sip_payload->pl_data) {
		if (sofia_parse_sdp(pvt, sip) < 0) {
			/* In-dialog re-INVITE encryption downgrade — reject 488, leave
			 * the existing crypto context + call up (RFC 3261 §14). */
			ast_mutex_unlock(&pvt->lock);
			if (owner) {
				ast_channel_unlock(owner);
				ast_channel_unref(owner);
			}
			ast_log(LOG_NOTICE, "Sofia: in-dialog re-INVITE rejected — encryption mismatch on '%s'\n",
				pvt->callid ? pvt->callid : "(no-callid)");
			nua_respond(nh, SIP_488_NOT_ACCEPTABLE,
				NUTAG_WITH_THIS(nua), TAG_END());
			return;
		}
	}
	/* The SDP (if any) was accepted — the 488 reject path above already
	 * returned, so a rejected re-INVITE never reaches here. NOW commit the
	 * deferred hold state under the held pvt->lock. The peer->onHold counter
	 * (chan_sip parity) is gated on sofia_cfg.notifyhold (default 0 = freeze
	 * unless operator opts in); the AMI Hold below stays UNCONDITIONAL. */
	pvt->hold_state = new_hold;
	if (trans && pvt->peer && sofia_cfg.notifyhold) {
		ast_atomic_fetchadd_int(&pvt->peer->onHold, new_hold ? +1 : -1);
	}
	if (trans && owner) {
		if (new_hold) {
			/* Peer puts us on hold via re-INVITE sendonly; propagate
			 * peer->mohsuggest to the bridged channel via the AST_CONTROL_HOLD
			 * data param so the other party plays the suggested MOH class
			 * (chan_sip parity). */
			const char *suggest = (pvt->peer && !ast_strlen_zero(pvt->peer->mohsuggest))
				? pvt->peer->mohsuggest : NULL;
			ast_queue_control_data(owner, AST_CONTROL_HOLD,
				S_OR(suggest, NULL),
				suggest ? strlen(suggest) + 1 : 0);
		} else {
			ast_queue_control(owner, AST_CONTROL_UNHOLD);
		}
	}
	sdp_ok = (sofia_generate_sdp(pvt, sdp_buf, sizeof(sdp_buf)) != NULL);
	ast_mutex_unlock(&pvt->lock);
	char contact_buf[256];
	contact_buf[0] = '\0';
	if (owner) {
		/* Snapshot the channel identity under the channel lock so the AMI
		 * events below cannot race a concurrent rename freeing the stringfield
		 * pool after the lock is dropped. */
		ast_copy_string(own_name, owner->name, sizeof(own_name));
		ast_copy_string(own_uniqueid, owner->uniqueid, sizeof(own_uniqueid));
		/* Build the Contact while owner is STILL LOCKED (pvt->owner==owner is
		 * pinned — a concurrent ast_hangup cannot NULL or masquerade-swap it
		 * while we hold the channel lock), so sofia_build_contact's
		 * pvt->owner->connected.id read cannot race a post-unlock hangup. */
		sofia_build_contact(pvt, contact_buf, sizeof(contact_buf));
		ast_channel_unlock(owner);
	} else {
		/* No owner: sofia_build_contact uses the peer fallback (no owner deref). */
		sofia_build_contact(pvt, contact_buf, sizeof(contact_buf));
	}

	if (sdp_ok) {
		/* A re-INVITE 200 OK is a target-refresh response (RFC 3261 §12.2.1.2):
		 * its Contact replaces the peer's stored remote target for this dialog.
		 * Stamp it from the per-leg kernel-routed source address (pvt->ourip),
		 * consistent with the initial 200 OK in sofia_answer, so a hold/resume,
		 * session refresh (RFC 4028) or transfer-driven re-INVITE on a multihomed
		 * wildcard bind does not move the target onto the wrong interface and
		 * silently break subsequent in-dialog requests. See the note in
		 * sofia_answer. */
		nua_respond(nh, SIP_200_OK,
			NUTAG_WITH_THIS(nua),
			TAG_IF(!ast_sockaddr_isnull(&pvt->ourip), SIPTAG_CONTACT_STR(contact_buf)),
			SIPTAG_CONTENT_TYPE_STR("application/sdp"),
			SIPTAG_PAYLOAD_STR(sdp_buf),
			TAG_END());
	} else {
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
	}

	if (trans) {
		ast_verbose("Sofia: in-dialog re-INVITE on '%s' - hold=%d\n",
			pvt->callid ? pvt->callid : "(no-callid)", new_hold);
		if (owner) {
			manager_event(EVENT_FLAG_CALL, "Hold",
				"Status: %s\r\n"
				"Channel: %s\r\n"
				"Uniqueid: %s\r\n",
				new_hold ? "On" : "Off",
				own_name,
				own_uniqueid);
		}
	}

	/* SessionTimerRefresh AMI event for a uas-side refresh fire (peer sent a
	 * refresh re-INVITE; we are the refresher target). Discriminator:
	 * SIPTAG_SESSION_EXPIRES presence on the re-INVITE (st_refresh==1 above). */
	if (st_refresh) {
		/* Write the session-timer fields under pvt->lock — the `sip show
		 * channels` CLI reader reads them under pvt->lock off-thread, so the
		 * writers must take it too (it is not held here). */
		ast_mutex_lock(&pvt->lock);
		pvt->session_negotiated_expires = st_refresh_seconds;
		pvt->session_last_refresh_at = time(NULL);
		ast_mutex_unlock(&pvt->lock);
		manager_event(EVENT_FLAG_CALL, "SessionTimerRefresh",
			"Channel: %s\r\n"
			"Uniqueid: %s\r\n"
			"Peer: Sofia/%s\r\n"
			"SessionExpires: %d\r\n"
			"Refresher: %s\r\n"
			"Direction: uas\r\n",
			own_name,
			own_uniqueid,
			pvt->peername,
			st_refresh_seconds,
			st_refresher_str ? st_refresher_str : "auto");
	}

	if (owner) {
		ast_channel_unref(owner);
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

	/* allowexternaldomains (chan_sip parity): reject INVITE to a non-local SIP
	 * domain when domain_list is non-empty AND the Request-URI domain is not in
	 * domain_list AND !allow_external_domains. */
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
	pvt->outgoing = 0; /* inbound INVITE — sofia_add_rpid reads this for ;party=called */
	/* Capture the peer-requested Session-Expires (RFC 4028) for display. The
	 * 200-OK sent via sofia_answer carries our NUTAG_SESSION_TIMER value
	 * (sofia-sip negotiates it against the peer's request); the value here is
	 * the peer's offer, useful for diagnostics before negotiation completes. */
	if (sip && sip->sip_session_expires) {
		/* session-timer field write under pvt->lock (CLI reader holds it). */
		ast_mutex_lock(&pvt->lock);
		pvt->session_negotiated_expires = sip->sip_session_expires->x_delta;
		ast_mutex_unlock(&pvt->lock);
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

	/* Snapshot inbound INVITE headers BEFORE any 4xx/5xx early-return so
	 * ${SIP_HEADER()} reads the original request even from h-extension. */
	sofia_pvt_snapshot_initreq(pvt, sip);

	/* Capture transport-source for ${SIPCHANINFO(peerip|recvip)} */
	sofia_get_source_addr(sip, &pvt->last_src_addr);

	/* Resolve our per-interface source IP for this inbound dialog. sofia_generate_sdp
	 * and the Contact/From builders fall back to the bound socket address, which on a
	 * box bound to a wildcard address (bindaddr=0.0.0.0) and reachable on more than one
	 * interface yields 0.0.0.0 — so an inbound leg would advertise c=IN IP4 0.0.0.0 and
	 * receive no RTP. Mirror chan_sip, which sets the dialog source address for every
	 * dialog (inbound and outbound): kernel-route toward the signaling peer and adopt
	 * the source address that actually reaches it. Outbound dialogs already do this in
	 * sofia_request_call; this closes the inbound gap. */
	if (!ast_sockaddr_isnull(&pvt->last_src_addr)) {
		sofia_resolve_ourip(pvt, &pvt->last_src_addr);
	}

	/* Capture Request-URI for ${SIPCHANINFO(uri)} on inbound calls (outbound
	 * path sets pvt->ruri at sofia_call time). */
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
			/* shrinkcallerid (chan_sip parity): ast_is_shrinkable_phonenumber
			 * gate + ast_shrink_phone_number strip. Applied BEFORE the
			 * pvt->username + pvt->cid_num assignments so the shrink reflects in
			 * both consumers. Default 1 (TRUE) per chan_sip drop-in. */
			if (sofia_cfg.shrinkcallerid && ast_is_shrinkable_phonenumber(cid_num)) {
				ast_shrink_phone_number(cid_num);
			}
			ast_string_field_set(pvt, username, cid_num);
		}
		if (sip->sip_from->a_display) {
			snprintf(cid_name, sizeof(cid_name), "%.79s", sip->sip_from->a_display);
		}
		/* Seed pvt->cid_num/cid_name from the From header. sofia_get_rpid
		 * (below, after peer bind) overrides these when peer->trustrpid=1 and
		 * PAI/RPID present. */
		ast_string_field_set(pvt, cid_num, cid_num);
		ast_string_field_set(pvt, cid_name, cid_name);
	}

	/* match_auth_username (chan_sip parity): when set, override the peer-lookup
	 * search-key with the Authorization-username (or Proxy-Authorization
	 * fallback) via sofia_pick_auth_username. Overrides cid_num for the
	 * downstream sofia_find_peer(cid_num). Works whenever sip->sip_authorization
	 * arrives (proxy pass-through or INVITE-digest-auth). */
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
	 * sees pvt->peer attached. ACL also runs before SDP parse so banned IPs
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
			 * calls from gateways like a carrier softswitch. */
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
					/* Timing-equalize the ACL-deny path with the auth-401-slow
					 * path: without this jitter, ACL-403-fast vs auth-401-slow is
					 * a peer-existence oracle defeating alwaysauthreject
					 * username-enumeration prevention. */
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
			pvt->allowtransfer = caller_peer->allowtransfer; /* inherit peer REFER policy (chan_sip parity) */
			ast_string_field_set(pvt, subscribecontext, caller_peer->subscribecontext); /* inherit peer SUBSCRIBE dispatch context (chan_sip parity) */
			ast_string_field_set(pvt, accountcode, caller_peer->accountcode); /* inherit peer CDR billing-tag (chan_sip parity); propagated to chan->accountcode via sofia_new */
			ao2_ref(caller_peer, +1); pvt->peer = caller_peer;
			ao2_ref(caller_peer, -1);
		}
	}

	/* INVITE digest auth (closes an auth-bypass gap — chan_sofia previously
	 * accepted ALL inbound INVITEs without challenge). Placement preserves
	 * ACL-before-auth ordering: the caller_peer block above runs ast_apply_ha
	 * first. Pre-auth-mutation discipline: pvt->peer = caller_peer above is
	 * REFCOUNT-only; the PVT-side copies (dtmfmode/context/allowtransfer/...)
	 * are dialog-scoped and the pvt is destroyed if auth fails. NO PEER-side
	 * state mutation may happen pre-auth.
	 *
	 * Three-tier auth dispatch:
	 * (1) force_invite_auth global lockdown — when set, bypasses are DISABLED
	 *     globally; auth required regardless of per-peer insecure=invite.
	 * (2) per-peer SOFIA_INSECURE_INVITE flag — short-circuit bypass for
	 *     trusted-IP trunks, plus an AMI InsecureInviteBypass event (chan_sip
	 *     blanks peersecret silently; chan_sofia flag-checks, no state mutation).
	 * (3) sofia_verify_digest_auth — full digest verification; try
	 *     sip_authorization first, fall back to sip_proxy_authorization.
	 *
	 * Unknown-peer path (cid_num empty OR sofia_find_peer returned NULL):
	 * pvt->peer is NULL; falls to the alwaysauthreject/guest branches below. */
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
			/* Cosmetic bypass trace, gated behind `sip set debug` so production
			 * runs silent on busy trunks; the AMI InsecureInviteBypass event
			 * below stays the auditable surface. */
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
			/* Try sip_authorization first; fall back to sip_proxy_authorization
			 * for a proxy-fronted INVITE (RFC 3261 §22). */
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
		/* alwaysauthreject on an unknown peer (RFC 3261 §22.4 username-
		 * enumeration prevention): emit a challenge with a real-fresh nonce +
		 * dual-algorithm offer + timing-equalization (all inside
		 * sofia_send_auth_challenge). The unknown-peer response is then
		 * indistinguishable from known-peer-bad-password (timing + status +
		 * WWW-Authenticate format). */
		char realm_buf[MAXHOSTNAMELEN];
		const char *realm = sofia_get_realm_for_dialog(sip, realm_buf, sizeof(realm_buf));
		sofia_send_auth_challenge(nua, nh, sip, realm, "INVITE", "UnknownPeer");
		ao2_ref(pvt, -1);
		return;
	} else if (!sofia_cfg.allowguest) {
		/* An unknown/unauthenticated caller with allowguest=no is rejected 403
		 * instead of routing the unauthenticated INVITE to the dialplan
		 * (toll-fraud). alwaysauthreject (above) still challenges first when set;
		 * IP-validated / host=ip peers match non-NULL upstream and never reach
		 * this branch. chan_sip AUTH_SECRET_FAILED → 403 parity. */
		ast_log(LOG_NOTICE, "Sofia: INVITE from unknown peer rejected — allowguest=no\n");
		nua_respond(nh, SIP_403_FORBIDDEN, NUTAG_WITH_THIS(nua), TAG_END());
		ao2_ref(pvt, -1);
		return;
	}

	/* Enable inband DTMF detect after pvt->peer + pvt->dtmfmode are bound (must
	 * run AFTER the caller_peer block — the entry rtp_init forces the RFC2833
	 * default, overridden by peer->dtmfmode here). Helper gates on INBAND/AUTO. */
	sofia_enable_dsp_detect(pvt);

	/* Inbound RPID/PAI/Privacy parsing. Trust-gated by peer->trustrpid;
	 * sofia_get_rpid falls back to sofia_get_pai when Remote-Party-ID is absent.
	 * Peer-side callingpres OVERRIDES received presentation (trust-but-verify).
	 * Apply BEFORE sofia_new so chan->caller.id picks up the values via the
	 * ast_set_callerid below. */
	sofia_get_rpid(pvt, sip);
	if (pvt->peer && pvt->peer->callingpres) {
		pvt->callingpres = pvt->peer->callingpres;
	}

	/* Inbound 480 Temporarily Unavailable call-limit enforcement (chan_sip
	 * parity). The reason text keeps its trailing space VERBATIM — operator
	 * AMI/log scripts pattern-match on the exact string. Single hard-cap on
	 * inbound; busy_level is outbound-only. CallLimitExceeded PeerStatus AMI is
	 * emitted by sofia_update_call_counter. Cleanup: pvt is NOT yet in dialogs
	 * (ao2_link happens after sofia_new), so only the ao2_ref drop is needed;
	 * the destructor DEC is a no-op since call_inc_done stays 0 on rejection. */
	if (sofia_update_call_counter(pvt, SOFIA_INC_CALL_LIMIT) == -1) {
		ast_log(LOG_NOTICE, "Sofia: inbound INVITE from peer '%s' rejected — call_limit %d reached\n",
			pvt->peer->name, pvt->peer->call_limit);
		nua_respond(nh, 480, "Temporarily Unavailable (Call limit) ",
			NUTAG_WITH_THIS(nua), TAG_END());
		ao2_ref(pvt, -1);
		return;
	}

	/* allowoverlap ambiguous-extension MATCHMORE 484 emit (chan_sip parity):
	 * when the extension does NOT exact-match BUT canmatch (partial match) AND
	 * mode == YES → emit 484 Address Incomplete and short-circuit BEFORE
	 * sofia_new (no PBX dispatch for partial extensions). DTMF and NO modes fall
	 * through to standard handling (the PBX 404s if truly absent). NO
	 * SIPTAG_REASON_STR (sofia-sip flips it to 500). Effective mode =
	 * peer->allowoverlap_mode when peer bound, else sofia_cfg.default_allowoverlap_mode.
	 * Cleanup: pvt not yet in dialogs; ao2_ref drop only. */
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
			/* SDP rejected — encryption mismatch. NO SIPTAG_REASON_STR
			 * (sofia-sip flips it to 500). Free srtp/vsrtp explicitly (the
			 * destructor would also catch them, but explicit free is the
			 * discipline). */
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

	/* Apply pvt->cid_num/cid_name + pvt->callingpres to the channel. The pvt
	 * fields are source-of-truth (sofia_get_rpid may have overwritten the
	 * From-header seed). With trustrpid=0 or no RPID/PAI, they hold the
	 * From-header values + the zero-default presentation. */
	if (!ast_strlen_zero(pvt->cid_num)) {
		ast_set_callerid(chan, pvt->cid_num,
			!ast_strlen_zero(pvt->cid_name) ? pvt->cid_name : NULL,
			pvt->cid_num);
		chan->caller.id.number.presentation = pvt->callingpres;
		chan->caller.id.name.presentation = pvt->callingpres;
	}

	/* Inbound Diversion parsing → pvt->owner->redirecting (chan_sip parity).
	 * Always evaluated, no trust-gating. Must run AFTER the pvt->owner = chan
	 * binding so the dialplan vars + redirecting struct land on the channel. */
	sofia_change_redirecting_info(pvt, pvt->owner, sip);

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

	/* nua_i_bye call-counter DEC. Flag-gated so the eventual sofia_hangup DEC
	 * is a no-op (call_inc_done=0). */
	if (op) {
		sofia_update_call_counter(op, SOFIA_DEC_CALL_LIMIT);
	}

	/* REFER transferer-leg BYE arrived as expected (RFC 5589 §6.1). Cancel the
	 * safety-net timer sofia_process_refer armed and unlink the pvt so it gets
	 * collected. The channel side was already detached in sofia_hangup
	 * (op->owner == NULL), so no ast_queue_hangup is needed. */
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

	if (op) {
		/* TOCTOU/UAF fix: snapshot+ref op->owner under op->lock (sofia_hangup
		 * nulls pvt->owner under the same lock on the channel thread), then queue
		 * outside the lock — ast_queue_hangup takes the channel lock, so holding
		 * op->lock across it would invert channel->pvt. The ref pins the channel
		 * across the queue. */
		struct ast_channel *owner;
		ast_mutex_lock(&op->lock);
		owner = op->owner;
		if (owner) {
			ast_channel_ref(owner);
		}
		ast_mutex_unlock(&op->lock);
		if (owner) {
			ast_queue_hangup(owner);
			ast_channel_unref(owner);
		}
	}
}

static void sofia_process_cancel(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	nua_respond(nh, SIP_200_OK, TAG_END());

	if (op) {
		/* TOCTOU/UAF fix: snapshot+ref op->owner under op->lock, queue outside it
		 * (see sofia_process_bye). */
		struct ast_channel *owner;
		ast_mutex_lock(&op->lock);
		owner = op->owner;
		if (owner) {
			ast_channel_ref(owner);
		}
		ast_mutex_unlock(&op->lock);
		if (owner) {
			ast_queue_hangup_with_cause(owner, AST_CAUSE_NORMAL_CLEARING);
			ast_channel_unref(owner);
		}
	}
}

static void sofia_process_options(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	nua_respond(nh, SIP_200_OK,
		SIPTAG_ALLOW_STR("INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER, "
				"SUBSCRIBE, NOTIFY, REFER, MESSAGE, INFO, PRACK"),	/* no PUBLISH (we 405 it) */
		SIPTAG_ACCEPT_STR("application/sdp"),
		TAG_END());
}

/* Append a name/value pair to pvt->initreq_headers (preserves insertion order
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

/* Snapshot the headers of an inbound INVITE so ${SIP_HEADER(name)} can read
 * them later from dialplan. Stores From / To / Call-ID / Contact / Via* /
 * User-Agent / Subject, plus EVERY entry in sip->sip_unknown (catches X-* +
 * P-Asserted-Identity + Remote-Party-ID + Diversion etc. — sofia-sip parks
 * unrecognized headers there). Caller must own pvt. */
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

/* ${SIP_HEADER(name[,N])} — return the Nth (default 1) value of the named header
 * from the snapshot taken at INVITE-arrival time. chan_sip parity: warns +
 * returns -1 on empty arg or non-Sofia channel; empty buf if header absent. */
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

/* autodomain (chan_sip parity): generic domain_list mutator. Adds name to
 * domain_list if non-empty and not already present (duplicate-check via
 * sofia_check_sip_domain). Callsites: the domain= parser + the auto-add sites
 * (bindaddr / tlsbindaddr / wsbindaddr / externaddr / gethostname FQDN). */
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

/* allowexternaldomains (chan_sip parity): generic domain_list walker. Returns 1
 * if domain matches a configured entry in domain_list, else 0. */
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

/* ${CHECKSIPDOMAIN(domain)} — return the domain if it matches one in
 * domain_list, else empty (chan_sip parity). Operators populate the list via
 * sofia.conf [general] domain= entries. */
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

/* Return the first contact in peer->contacts (ao2 ref +1) or NULL. Used by the
 * useragent + fullcontact items in SIPPEER. */
struct sofia_contact *sofia_peer_first_contact(struct sofia_peer *peer)
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

/* ${SIPPEER(peername[,item])} — read a peer config field (chan_sip parity) plus
 * chan_sofia-only items (busy_on_active, max_contacts, qualifyfreq,
 * qualifytimeout, lastms). item defaults to "ip"; unknown item → empty buf + 0. */
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

	/* UAF-vs-reload fix: the reload writer (sofia_thread) frees the peer
	 * stringfield pool under peer->lock when a field grows. host/context/
	 * srtpcipher/callerid/fromuser/fromdomain/accountcode are read below on the
	 * dialplan thread. Hold peer->lock across the whole field-reading region (it
	 * is a leaf here — the contact ao2 ops below take only ao2_lock(c), never
	 * peer->lock); unlock before the ao2_ref(peer,-1). No early returns exist in
	 * this chain, so the single lock/unlock pair cannot leak peer->lock. */
	ast_mutex_lock(&peer->lock);

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
			/* Snapshot the mutable user_agent under the contact lock. */
			ao2_lock(c);
			ast_copy_string(buf, S_OR(c->user_agent, ""), len);
			ao2_unlock(c);
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
	} else if (!strcasecmp(colname, "forceddiversion")) {
		ast_copy_string(buf, peer->forceddiversion, len);
	} else if (!strcasecmp(colname, "accountcode")) {
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
				ao2_lock(c);
				total += c->active_calls;
				ao2_unlock(c);
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

	ast_mutex_unlock(&peer->lock);

	ao2_ref(peer, -1);
	return 0;
}

static struct ast_custom_function sofia_sippeer_function = {
	.name = "SIPPEER",
	.read = func_sofia_sippeer,
};

/* ${SIPCHANINFO(item)} — read current Sofia channel info (chan_sip parity).
 * peerip + recvip are COLLAPSED to last_src_addr (sofia-sip resolves transport
 * source via Via received/rport at INVITE time; the chan_sip SDP-c=-vs-rport
 * distinction is hidden by the NUA layer). */
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
		/* reload-UAF fix: pvt->peer->name is an unbounded stringfield the
		 * reload writer (sofia_thread) frees under peer->lock; pvt->lock does
		 * NOT serialize against that, so snapshot the name under peer->lock
		 * (lock-order leaf, channel->pvt->peer). Guard pvt->peer NULL. */
		if (pvt->peer) {
			char l_peername[256];
			ast_mutex_lock(&pvt->peer->lock);
			ast_copy_string(l_peername, pvt->peer->name, sizeof(l_peername));
			ast_mutex_unlock(&pvt->peer->lock);
			ast_copy_string(buf, l_peername, len);
		}
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
void sofia_get_source_addr(sip_t const *sip, struct ast_sockaddr *addr)
{
	sip_via_t const *via;

	if (!addr)
		return;
	/* Always leave addr in a well-defined state. Callers pass an uninitialized
	 * stack struct ast_sockaddr; on any early return below (no sip, no Via, no
	 * host, or a failed parse) it must be NULL, not garbage, so the ACL / log /
	 * contact src_addr consumers don't read stack junk. */
	ast_sockaddr_setnull(addr);

	if (!sip)
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


/* Parse a Contact URL port to a valid [0,65535], defaulting to 5060 (RFC 3261
 * §19.1.2) on a NULL/empty/non-numeric/out-of-range value. Full-string endptr
 * check so trailing garbage ("8080abc") falls to the default rather than being
 * taken as a numeric prefix. Used at the contact-ACL gate, the stored c->port,
 * AND the canonical contact URI, so the URI ao2 key and c->port always carry
 * the SAME normalized port. */
static int sofia_contact_url_port(const char *url_port)
{
	char *end = NULL;
	long p;

	if (!url_port || !*url_port) {
		return 5060;
	}
	p = strtol(url_port, &end, 10);
	if (end == url_port || *end != '\0' || p < 0 || p > 65535) {
		return 5060;
	}
	return (int)p;
}

static void sofia_contact_uri_from_url(char *buf, size_t len, const url_t *url)
{
	if (!url || !buf) {
		buf[0] = '\0';
		return;
	}
	/* Normalize the port (clamp [0,65535], default 5060) so the URI key matches c->port. */
	snprintf(buf, len, "sip:%s%s%s:%d",
		url->url_user ? url->url_user : "",
		url->url_user ? "@" : "",
		url->url_host ? url->url_host : "",
		sofia_contact_url_port(url->url_port));
}

static int sofia_expire_contacts_cb(void *obj, void *arg, int flags)
{
	struct sofia_contact *c = obj;
	time_t *now = arg;
	/* ignoreregexpire (chan_sip parity): skip cleanup when set, preserving the
	 * last-known contact across short upstream-trunk outages (stable-trunk use
	 * case, e.g. PSTN gateway routing across intermittent network drops). */
	if (sofia_cfg.ignore_regexpire) {
		return 0;
	}
	if (c->expires > 0 && c->expires < *now) {
		ast_verbose("Sofia: Expiring contact %s\n", c->contact_uri);
		return CMP_MATCH;
	}
	return 0;
}

/* Contact-ACL check for ONE Contact URL, factored out so the REGISTER handler
 * can PREFLIGHT every Contact (validate ALL before binding ANY) instead of
 * check-then-bind per Contact — the old single loop left earlier Contacts
 * linked when a LATER Contact tripped the fail-closed ACL (partial-apply, then
 * a 403 for the whole REGISTER). Returns 0 = allowed, -1 = denied; no-op (allow)
 * when no ACL is configured. uri is for the log line only. */
static int sofia_contact_acl_check(struct sofia_peer *peer, const url_t *url, const char *uri)
{
	struct ast_sockaddr contact_addr;
	char addr_buf[128];
	const char *chost;
	int cport;

	if (!sofia_cfg.contact_ha && !peer->contactha) {
		return 0;
	}
	chost = url->url_host ? url->url_host : "0.0.0.0";
	cport = sofia_contact_url_port(url->url_port);	/* clamped [0,65535], default 5060 */
	if (strchr(chost, ':')) {
		snprintf(addr_buf, sizeof(addr_buf), "[%s]:%d", chost, cport);
	} else {
		snprintf(addr_buf, sizeof(addr_buf), "%s:%d", chost, cport);
	}
	if (ast_sockaddr_parse(&contact_addr, addr_buf, 0)) {
		if ((sofia_cfg.contact_ha && ast_apply_ha(sofia_cfg.contact_ha, &contact_addr) != AST_SENSE_ALLOW) ||
		    (peer->contactha && ast_apply_ha(peer->contactha, &contact_addr) != AST_SENSE_ALLOW)) {
			ast_log(LOG_NOTICE, "Sofia: REGISTER from peer '%s' Contact %s rejected by contact-ACL\n",
				peer->name, uri);
			return -1;
		}
	} else {
		/* FAIL CLOSED — ast_sockaddr_parse is numeric-only; a non-IP/malformed Contact host
		 * with an ACL configured is rejected rather than DNS-resolved (no blocking lookup on the
		 * single sofia_thread). Only fires when an ACL is set, so non-ACL peers are unaffected. */
		ast_log(LOG_NOTICE, "Sofia: REGISTER from peer '%s' Contact %s has a non-IP host with contact-ACL configured — rejecting (fail-closed)\n",
			peer->name, uri);
		return -1;
	}
	return 0;
}

static int sofia_update_peer_contacts(struct sofia_peer *peer, sip_t const *sip, int expires,
	struct sofia_register_update *update)
{
	time_t now = time(NULL);
	struct ast_sockaddr src;
	sip_contact_t *m;
	/* Transport of the last contact processed in the registration loop below.
	 * Snapshotted into peer->reg_transport alongside peer->src_addr (both
	 * denormalize the "current registered route"). */
	char reg_transport[8] = "udp";

	/* A wildcard "Contact: *" (url_any) is valid ONLY as the sole Contact with
	 * Expires:0 (RFC 3261 §10.2.2 — bulk unregister). A wildcard with a non-zero
	 * expiry OR mixed with other contacts is malformed → reject the REGISTER
	 * with 400 (caller maps the -2 return). The legitimate Expires:0
	 * sole-wildcard unregister below is unaffected. */
	{
		int has_wildcard = 0, n_contacts = 0;
		for (m = sip->sip_contact; m; m = m->m_next) {
			n_contacts++;
			if (m->m_url->url_type == url_any) {
				has_wildcard = 1;
			}
		}
		if (has_wildcard && (expires != 0 || n_contacts > 1)) {
			return -2;
		}
	}

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
				ast_copy_string(peer->reg_transport, "udp", sizeof(peer->reg_transport));
				if (update) {
					update->wildcard_removed = 1;
					update->contacts_removed = update->contacts_before;
					update->now_registered = 0;
					update->contacts_after = 0;
					sofia_register_update_set_uri(update, "*");
				}
				/* Defer the unregister side-effects (regexten dialplan / PeerStatus
				 * AMI / devstate hint recompute) to the caller AFTER peer->lock is
				 * released — they take the global contexts lock + emit AMI + fan out
				 * BLF, which must not run under the peer mutex. emit_unregister is
				 * mutually exclusive with the registered tail. */
				if (update) {
					update->emit_unregister = 1;
					update->unregister_cause = "Wildcard";
				}
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
		/* Registration / re-registration.
		 * PREFLIGHT the contact-ACL for EVERY Contact before binding ANY, so a later
		 * Contact that trips the fail-closed ACL never leaves earlier Contacts partially
		 * bound (the caller then 403s the whole REGISTER). Deterministic across both loops
		 * (sip->sip_contact is the immutable parsed message; src is computed once), so the
		 * apply loop's all-pass behavior matches the old single loop. */
		for (m = sip->sip_contact; m; m = m->m_next) {
			char uri[256];
			sofia_contact_uri_from_url(uri, sizeof(uri), m->m_url);
			if (sofia_contact_acl_check(peer, m->m_url, uri) < 0) {
				return -1;
			}
		}
		/* Apply loop — every Contact passed the ACL preflight above. */
		for (m = sip->sip_contact; m; m = m->m_next) {
			char uri[256];
			struct sofia_contact *c;

			sofia_contact_uri_from_url(uri, sizeof(uri), m->m_url);

			/* Resolve this Contact's transport from its ;transport= param
			 * (falling back to scheme) ONCE; both branches store it on
			 * c->transport, and the last value seen is snapshotted into
			 * peer->reg_transport after the loop. */
			sofia_contact_transport_from_url(m->m_url, reg_transport, sizeof(reg_transport));

			c = ao2_find(peer->contacts, uri, OBJ_POINTER);
			if (c) {
				/* Refresh existing contact. The mutable fields (expires, src_addr,
				 * user_agent) are read off-thread by BYE-NAT-target / CLI / AMI, so
				 * compare/copy/write them under the contact's own ao2 lock
				 * (peer->lock -> contact lock is the established order). */
				ao2_lock(c);
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
				/* A re-REGISTER from the same user/host/port that switches
				 * transport (e.g. UDP->TCP) lands here; refresh c->transport too
				 * or the stored binding keeps the stale transport and routes over
				 * the wrong one. */
				ast_copy_string(c->transport, reg_transport, sizeof(c->transport));
				if (sip->sip_user_agent && sip->sip_user_agent->g_string)
					ast_copy_string(c->user_agent, sip->sip_user_agent->g_string,
						sizeof(c->user_agent));
				ao2_unlock(c);
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
				c->port = sofia_contact_url_port(m->m_url->url_port);	/* clamped [0,65535], default 5060 */
				/* Store the transport resolved from the Contact's ;transport=
				 * param (the old scheme-only derivation had a dead "tcp" branch —
				 * url_scheme is only ever "sip"/"sips"). */
				ast_copy_string(c->transport, reg_transport, sizeof(c->transport));
				if (sip->sip_user_agent && sip->sip_user_agent->g_string)
					ast_copy_string(c->user_agent, sip->sip_user_agent->g_string,
						sizeof(c->user_agent));
				c->expires = now + expires;
				memcpy(&c->src_addr, &src, sizeof(src));
				ao2_lock(peer->contacts);
				/* LINK the new binding FIRST and evict the oldest AFTERWARDS, so an
				 * ao2_link OOM never costs the phone an existing contact
				 * (eviction-before-link could drop a good binding then fail to store
				 * the new one). ao2_link returns NULL on OOM → the binding was NOT
				 * stored: undo the add accounting and return -3 so the caller answers
				 * 500 instead of a bogus 200 OK with no stored contact. */
				if (!ao2_link(peer->contacts, c)) {
					if (update) {
						update->contacts_added--;
					}
					ao2_unlock(peer->contacts);
					ao2_ref(c, -1);
					return -3;
				}
				if (ao2_container_count(peer->contacts) > peer->max_contacts) {
					/* chan_sip parity: peer at max_contacts and a NEW Contact URI
					 * just arrived. chan_sip replaced the existing binding rather
					 * than reject — mirror that by evicting the earliest-expiry
					 * (LRU) contact, then link the new one. Holding the
					 * peer->contacts lock across the iteration is safe: ao2_iterator
					 * with flags=0 does not re-take the lock. */
					struct ao2_iterator i;
					struct sofia_contact *cand, *oldest = NULL;

					i = ao2_iterator_init(peer->contacts, 0);
					while ((cand = ao2_iterator_next(&i))) {
						if (cand == c) {
							/* Never evict the binding we just linked — a short-TTL new
							 * contact can have the smallest expires and would otherwise
							 * be the LRU victim, re-introducing the "200 OK with no
							 * stored binding" bug. */
							ao2_ref(cand, -1);
							continue;
						}
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
						/* Cosmetic eviction trace, gated by `sip set debug` so
						 * production runs silent. sofia_verbose_register_update
						 * still reports per-REGISTER `contacts_removed` counts. */
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
		/* Snapshot the registration transport beside src_addr so
		 * sofia_resolve_peer_target / the NAT-proxy helpers route a TCP/TLS phone
		 * over the right transport instead of defaulting to UDP. */
		ast_copy_string(peer->reg_transport, reg_transport, sizeof(peer->reg_transport));
	} else {
		peer->registered = 0;
		memset(&peer->src_addr, 0, sizeof(peer->src_addr));
		ast_copy_string(peer->reg_transport, "udp", sizeof(peer->reg_transport));
		if (update && update->was_registered && !update->contacts_removed) {
			update->contacts_removed = update->contacts_before;
		}
		/* Defer the unregister side-effects to the caller after unlock. */
		if (update) {
			update->emit_unregister = 1;
			update->unregister_cause = "Expired";
		}
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
	/* Reject silently-truncated overflow: ast_copy_string truncates raw to
	 * len-1 bytes; without this length-check a malicious 17-char nc could
	 * truncate to 15 chars, passing a smaller value to the nc-monotonic check.
	 * Return NULL on overflow so callers reject 400 (RFC 2617 §3.2.2). */
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

/* Outbound INVITE/request auth: build the sofia-sip credential string for
 * nua_authenticate()/NUTAG_AUTH in the EXACT format auc_credentials() requires:
 *   scheme:"realm":user:pass    — all four fields, realm QUOTED.
 * A 2-field "user:pass" is SILENTLY IGNORED by that parser (realm parses as NULL
 * → returns 0, no credential loaded), so a challenged outbound request never
 * gets an Authorization header. The realm comes from the received 401/407
 * challenge. Returns 0 on success, -1 if the challenge carries no realm OR
 * `secret` is empty (md5secret-only is NOT supported — NUTAG_AUTH needs the
 * cleartext password to compute the digest response).
 *
 * LOCK-FREE by design: the caller passes already-snapshotted `user`/`secret`, so
 * it is reusable from the outbound-INVITE handler (snapshot creds under
 * peer->lock, release, then call with NO lock held) and from the
 * outbound-REGISTER 401/407 branch (already holds peer->lock). `challenge` is
 * any SIP auth header (WWW-/Proxy-Authenticate share au_common+au_params). */
int sofia_format_auth_creds(msg_auth_t const *challenge, const char *user,
		const char *secret, char *buf, size_t len)
{
	msg_auth_t const *au;
	const char *realm = NULL;
	int n;

	if (!challenge || ast_strlen_zero(secret) || !buf || len == 0) {
		return -1;
	}
	/* user + secret are colon-delimited fields in the creds string — a ':' in either corrupts the
	 * format (and is not a valid unescaped SIP digest username/password character). Reject. */
	if (strchr(S_OR(user, ""), ':') || strchr(secret, ':')) {
		return -1;
	}
	/* Pick the Digest-scheme challenge (a header set may carry several schemes)
	 * and take its realm EXACTLY as it appears on the wire — already
	 * double-quoted with internal quotes backslash-escaped — so auc_credentials
	 * gets a byte-faithful quoted realm. Using the raw token (vs unquote +
	 * re-escape) avoids double-escaping an already-escaped realm. */
	for (au = challenge; au; au = au->au_next) {
		if (au->au_scheme && !strcasecmp(au->au_scheme, "Digest")) {
			realm = msg_header_find_param(au->au_common, "realm");
			if (realm) {
				break;
			}
		}
	}
	if (!realm) {
		return -1;	/* no Digest realm in the challenge — cannot target the credential */
	}
	{
		/* require a well-formed quoted-string realm (opening + closing quote, len >= 2). sofia-sip's
		 * header parser already validated it during parsing; this is a defensive belt. */
		size_t rl = strlen(realm);
		if (rl < 2 || realm[0] != '"' || realm[rl - 1] != '"') {
			return -1;
		}
	}
	n = snprintf(buf, len, "Digest:%s:%s:%s", realm, S_OR(user, ""), secret);
	if (n < 0 || n >= (int)len) {
		return -1;	/* truncated → reject rather than feed a malformed credential to NUA */
	}
	return 0;
}

/* match_auth_username (chan_sip parity): peer-lookup search-key picker. When
 * set, uses the Authorization-username (or Proxy-Authorization fallback)
 * instead of the From-username. Shared by sofia_process_register +
 * sofia_process_invite.
 *
 * Returns a pointer into buf (when an auth-username is found) OR fallback_user
 * (when no Authorization/Proxy-Authorization, or the username field is
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

	/* Proxy-Authorization fallback (chan_sip parity). Both
	 * sip_authorization_t and sip_proxy_authorization_t are typedefs of
	 * struct msg_auth_s, so the cast is type-safe. */
	if (sip->sip_proxy_authorization) {
		result = sofia_au_get_unq((sip_authorization_t const *)sip->sip_proxy_authorization,
			"username", buf, len);
		if (result && *result) {
			return result;
		}
	}

	return fallback_user;
}

/* Forward decl for sofia_regen_nonce_locked (defined later, kept adjacent to the
 * nonce-state-management code). */
static void sofia_regen_nonce_locked(struct sofia_peer *peer, char *out_buf, size_t out_len);

/* Constant-time memory comparison for digest hash verification (a plain
 * strncasecmp leaks the expected hash via timing). The volatile accumulator +
 * memory barrier prevent the compiler from short-circuiting the loop and
 * defeating the constant-time guarantee. Returns 0 on match, nonzero on
 * mismatch. */
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

/* Crypto-secure 128-bit nonce via direct /dev/urandom read (a gettimeofday
 * nonce is predictable wall-clock, ~20 bits). Output: 32 hex chars. The EINTR
 * retry loop avoids silently degrading to the fallback when /dev/urandom is
 * available; the fallback (4× ast_random composite, ~96-100 bits) logs a
 * WARNING. Caller passes out_buf with size ≥ 33 (32 hex + null). */
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

/* Digest algorithm dispatch (MD5 / RFC 7616 SHA-256). Challenges emit MD5 first
 * for legacy-client compatibility, SHA-256 second; verification dispatches by
 * the Authorization algorithm=. MD5 is used when the client omits algorithm=
 * (RFC 2069 + RFC 2617 backward-compat). */
#define SOFIA_DIGEST_MD5     0
#define SOFIA_DIGEST_SHA256  1

/* SHA-256 hash wrapper over libcrypto's SHA256(). Output: 64 hex chars + null
 * (caller passes buf size >= 65). Mirrors the ast_md5_hash interface for
 * symmetric use in sofia_compute_a1_hash + sofia_compute_digest. */
static void sofia_sha256_hash(char *out_buf, const char *input)
{
	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256((const unsigned char *)input, strlen(input), digest);
	for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		snprintf(out_buf + (i * 2), 3, "%02x", digest[i]);
	}
}

/* Compute the A1 hash for digest auth. md5secret-precedence (chan_sip parity):
 * when peer->md5secret is set, use it DIRECTLY as a1_hash, bypassing the
 * cleartext-secret path, and it takes precedence over peer->secret when both are
 * set. SHA-256 path: A1 = SHA-256(user:realm:secret) (or md5secret-direct when
 * set). out_hash buffer size: 33 (MD5) / 65 (SHA-256). */
static int sofia_compute_a1_hash(struct sofia_peer *peer, const char *realm,
		int algorithm, char *out_hash)
{
	char *a1_pre = NULL;

	/* md5secret is a pre-computed MD5 hash; a SHA-256 request with md5secret set
	 * is a mismatch — md5secret WAS computed for MD5, and the SHA-256 caller
	 * handles that recovery (re-challenge MD5-only). The dual-set LOG_WARNING is
	 * emitted ONCE at config-load (not per-auth-call, which spammed syslog). */
	if (!ast_strlen_zero(peer->md5secret)) {
		ast_copy_string(out_hash, peer->md5secret, 33);
		return 0;
	}

	/* Hash name:realm:secret over a DYNAMIC buffer so it can NEVER truncate. A
	 * fixed a1_pre[256] silently dropped the secret once strlen(name)+
	 * strlen(realm) reached ~253 (reachable under domainsasrealm with an
	 * attacker-chosen long domain) — the server then hashed MD5("name:realm:"),
	 * which an attacker computes from public values alone = auth bypass, while
	 * legitimate clients were false-rejected. On OOM, PROPAGATE failure (-1) so
	 * the caller rejects (500) instead of continuing with a predictable hash. */
	if (ast_asprintf(&a1_pre, "%s:%s:%s", peer->name, realm, peer->secret) < 0 || !a1_pre) {
		ast_free(a1_pre);	/* defensive — free if non-NULL on the impossible -1+ptr case */
		return -1;
	}
	if (algorithm == SOFIA_DIGEST_SHA256) {
		sofia_sha256_hash(out_hash, a1_pre);
	} else {
		ast_md5_hash(out_hash, a1_pre);
	}
	ast_free(a1_pre);
	return 0;
}

/* Full digest computation per RFC 2617 (MD5) or RFC 7616 (SHA-256). HA1 =
 * sofia_compute_a1_hash; HA2 = hash(method:uri); response =
 * hash(HA1:nonce:nc:cnonce:qop:HA2) for qop=auth, OR hash(HA1:nonce:HA2) for
 * no-qop (RFC 2069). out_hash buffer size: 33 (MD5) / 65 (SHA-256). */
static int sofia_compute_digest(struct sofia_peer *peer, const char *realm,
		const char *method, const char *uri,
		const char *nonce, const char *nc, const char *cnonce,
		const char *qop, int algorithm, char *out_hash)
{
	char a1_hash[65];
	char *a2_pre = NULL;
	char a2_hash[65];
	char resp_pre[1024];

	/* PROPAGATE a digest-compute failure (HA1/HA2 buffer OOM) as -1 so the
	 * caller rejects (500) — never continue with an empty/predictable hash an
	 * attacker could match in the OOM window. */
	if (sofia_compute_a1_hash(peer, realm, algorithm, a1_hash) != 0) {
		return -1;
	}
	/* Dynamic buffer for method:uri — a fixed [256] truncated HA2 when the
	 * client uri (up to ~255) made "METHOD:uri" exceed 256, so the server hashed
	 * a different string and false-rejected every valid request with a long
	 * Request-URI. */
	if (ast_asprintf(&a2_pre, "%s:%s", method, uri) < 0 || !a2_pre) {
		ast_free(a2_pre);	/* defensive free on the impossible -1+ptr case */
		return -1;
	}
	if (algorithm == SOFIA_DIGEST_SHA256) {
		sofia_sha256_hash(a2_hash, a2_pre);
	} else {
		ast_md5_hash(a2_hash, a2_pre);
	}
	ast_free(a2_pre);

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
	return 0;
}

/* Unified digest auth verifier for REGISTER / INVITE / SUBSCRIBE. Returns enum
 * sofia_auth_result. Caller dispatches sip_authorization vs
 * sip_proxy_authorization (REGISTER uses the former; INVITE-via-proxy the latter).
 *
 * Security checks:
 * - realm validation: byte-exact strcmp (RFC 2617 §3.2.1); reject 401-stale on mismatch
 * - truncation: sofia_au_get_unq returns NULL on overflow → reject 400
 * - missing-uri: reject 400 if uri= absent (RFC 2617 §3.2.2)
 * - timing-attack: sofia_ct_memcmp constant-time digest comparison
 * - nonce TTL: reject 401-stale if nonce_issued_at exceeds TTL
 * - nc-replay: reject 401-stale if using_qop && new_nc <= peer->last_nc
 *
 * Caller responsibility:
 * - Acquires + holds a peer ao2 ref for the duration of the call
 * - AUTH_OK → proceed with normal flow
 * - AUTH_CHALLENGE → 401 already emitted; ao2_ref(peer, -1) and return
 * - AUTH_REJECT → 4xx already emitted; ao2_ref(peer, -1) and return
 */

/* Which digest algorithm(s) to OFFER, per the [general] auth_algorithms switch.
 * GLOBAL and uniform for ALL peers: both -> MD5 + SHA-256, md5 -> MD5 only,
 * sha256 -> SHA-256 only. Verification uses the SAME function so it accepts
 * exactly what was offered (anti-downgrade). */
static void sofia_auth_offered(int *want_md5, int *want_sha256)
{
	*want_md5    = (sofia_cfg.auth_algorithms != SOFIA_AUTH_ALG_SHA256);
	*want_sha256 = (sofia_cfg.auth_algorithms != SOFIA_AUTH_ALG_MD5);
}

/* Emit the WWW-Authenticate digest challenge(s) for a 401, per the global
 * [general] auth_algorithms switch. MD5 is listed first (legacy-client
 * compatibility). stale!=0 appends ", stale=true". The caller generates the
 * nonce (under peer->lock for a known peer) and owns any surrounding logging. */
static void sofia_emit_auth_challenge(nua_t *nua, nua_handle_t *nh,
		const char *realm, const char *nonce, int stale)
{
	int want_md5, want_sha256;
	char hdr_md5[256];
	char hdr_sha256[256];
	const char *stale_str = stale ? ", stale=true" : "";

	sofia_auth_offered(&want_md5, &want_sha256);

	if (want_md5) {
		snprintf(hdr_md5, sizeof(hdr_md5),
			"Digest realm=\"%s\", nonce=\"%s\", qop=\"auth\", algorithm=MD5%s",
			realm, nonce, stale_str);
	}
	if (want_sha256) {
		snprintf(hdr_sha256, sizeof(hdr_sha256),
			"Digest realm=\"%s\", nonce=\"%s\", qop=\"auth\", algorithm=SHA-256%s",
			realm, nonce, stale_str);
	}

	if (want_md5 && want_sha256) {
		nua_respond(nh, SIP_401_UNAUTHORIZED,
			SIPTAG_WWW_AUTHENTICATE_STR(hdr_md5),
			SIPTAG_WWW_AUTHENTICATE_STR(hdr_sha256),
			NUTAG_WITH_THIS(nua),
			TAG_END());
	} else if (want_sha256) {
		nua_respond(nh, SIP_401_UNAUTHORIZED,
			SIPTAG_WWW_AUTHENTICATE_STR(hdr_sha256),
			NUTAG_WITH_THIS(nua),
			TAG_END());
	} else {
		nua_respond(nh, SIP_401_UNAUTHORIZED,
			SIPTAG_WWW_AUTHENTICATE_STR(hdr_md5),
			NUTAG_WITH_THIS(nua),
			TAG_END());
	}
}

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
	char expected_hash[65];  /* SHA-256 (64 hex + null); MD5 uses 32+null */

	/* Challenge emission when no Authorization header is present. Offer MD5
	 * first for chan_sip/legacy-client compatibility, then SHA-256 for
	 * clients that can select the stronger RFC 7616 algorithm. */
	if (!au) {
		char nonce[64];
		time_t now_fc = time(NULL);
		int ttl_fc = sofia_cfg.nonce_ttl_seconds > 0 ? sofia_cfg.nonce_ttl_seconds : SOFIA_NONCE_TTL_SEC_DEFAULT;

		/* A first challenge (no Authorization header) is UNVERIFIED — re-use the
		 * peer's live nonce when one exists (within TTL), regenerating only when
		 * empty/expired, so a spoofed first request cannot clobber a victim's
		 * in-flight challenge. */
		ast_mutex_lock(&peer->lock);
		if (ast_strlen_zero(peer->nonce)
				|| (peer->nonce_issued_at && (now_fc - peer->nonce_issued_at) > ttl_fc)) {
			sofia_regen_nonce_locked(peer, nonce, sizeof(nonce));
		} else {
			ast_copy_string(nonce, peer->nonce, sizeof(nonce));
		}
		ast_mutex_unlock(&peer->lock);

		sofia_emit_auth_challenge(nua, nh, realm, nonce, 0);

		if (sofia_debug) {
			int want_md5, want_sha256;
			sofia_auth_offered(&want_md5, &want_sha256);
			ast_verbose("Sofia: Challenging %s from '%s' (nonce=%s, algorithms=%s)\n",
				method, peer->name, nonce,
				(want_md5 && want_sha256) ? "MD5+SHA-256" : (want_sha256 ? "SHA-256" : "MD5"));
		}
		return SOFIA_AUTH_CHALLENGE;
	}

	/* Parse all Authorization parameters. sofia_au_get_unq returns NULL on
	 * overflow → reject 400. */
	auth_realm     = sofia_au_get_unq(au, "realm",     auth_realm_buf,     sizeof(auth_realm_buf));
	auth_nonce     = sofia_au_get_unq(au, "nonce",     auth_nonce_buf,     sizeof(auth_nonce_buf));
	auth_response  = sofia_au_get_unq(au, "response",  auth_response_buf,  sizeof(auth_response_buf));
	auth_uri       = sofia_au_get_unq(au, "uri",       auth_uri_buf,       sizeof(auth_uri_buf));
	auth_nc        = sofia_au_get_unq(au, "nc",        auth_nc_buf,        sizeof(auth_nc_buf));
	auth_cnonce    = sofia_au_get_unq(au, "cnonce",    auth_cnonce_buf,    sizeof(auth_cnonce_buf));
	auth_qop       = sofia_au_get_unq(au, "qop",       auth_qop_buf,       sizeof(auth_qop_buf));
	auth_algorithm = sofia_au_get_unq(au, "algorithm", auth_algorithm_buf, sizeof(auth_algorithm_buf));

		/* Algorithm-parameter strict-parse (RFC 7616 §3.3, case-insensitive).
		 * Anti-downgrade: accept ONLY an algorithm that was actually offered (same
		 * sofia_auth_offered() used to build the challenge). A client claiming an
		 * un-offered algorithm — or omitting algorithm= (implies MD5) when MD5 was
		 * not offered — is rejected 400. */
	{
		int want_md5, want_sha256;
		sofia_auth_offered(&want_md5, &want_sha256);

		if (auth_algorithm) {
			if (!strcasecmp(auth_algorithm, "MD5")) {
				if (!want_md5) {
					nua_respond(nh, SIP_400_BAD_REQUEST, NUTAG_WITH_THIS(nua), TAG_END());
					ast_verbose("Sofia: %s auth rejected for '%s' - MD5 not offered (auth_algorithms)\n",
						method, peer->name);
					sofia_blacklist_add_sip(sip, "digest algorithm not offered");
					return SOFIA_AUTH_REJECT;
				}
				algorithm = SOFIA_DIGEST_MD5;
			} else if (!strcasecmp(auth_algorithm, "SHA-256")) {
				if (!want_sha256) {
					nua_respond(nh, SIP_400_BAD_REQUEST, NUTAG_WITH_THIS(nua), TAG_END());
					ast_verbose("Sofia: %s auth rejected for '%s' - SHA-256 not offered (auth_algorithms)\n",
						method, peer->name);
					sofia_blacklist_add_sip(sip, "digest algorithm not offered");
					return SOFIA_AUTH_REJECT;
				}
				algorithm = SOFIA_DIGEST_SHA256;
			} else {
				nua_respond(nh, SIP_400_BAD_REQUEST, NUTAG_WITH_THIS(nua), TAG_END());
				ast_verbose("Sofia: %s auth rejected for '%s' - unknown algorithm '%s'\n",
					method, peer->name, auth_algorithm);
				sofia_blacklist_add_sip(sip, "digest unknown algorithm");
				return SOFIA_AUTH_REJECT;
			}
		} else if (!want_md5) {
			nua_respond(nh, SIP_400_BAD_REQUEST, NUTAG_WITH_THIS(nua), TAG_END());
			ast_verbose("Sofia: %s auth rejected for '%s' - algorithm= required (MD5 not offered)\n",
				method, peer->name);
			sofia_blacklist_add_sip(sip, "digest algorithm required");
			return SOFIA_AUTH_REJECT;
		}
	}
	hash_len_hex = (algorithm == SOFIA_DIGEST_SHA256) ? 64 : 32;

	/* Reject 400 when uri= missing (RFC 2617 §3.2.2). */
	if (!auth_uri) {
		nua_respond(nh, SIP_400_BAD_REQUEST, NUTAG_WITH_THIS(nua), TAG_END());
		ast_verbose("Sofia: %s auth rejected for '%s' - uri= missing\n",
			method, peer->name);
		sofia_blacklist_add_sip(sip, "digest missing uri");
		return SOFIA_AUTH_REJECT;
	}

	/* Reject 401-stale on realm mismatch (RFC 2617 §3.2.1, byte-exact strcmp) —
	 * multi-tenant cross-realm replay prevention. Treat a missing realm as a
	 * mismatch. */
	if (!auth_realm || strcmp(auth_realm, realm) != 0) {
		char chal_nonce[64];
		time_t now_rm = time(NULL);
		int ttl_rm = sofia_cfg.nonce_ttl_seconds > 0 ? sofia_cfg.nonce_ttl_seconds : SOFIA_NONCE_TTL_SEC_DEFAULT;
		/* A realm-mismatched (hence UNVERIFIED) request must NOT clobber the
		 * peer's live in-flight nonce — a spoofed-username probe would otherwise
		 * invalidate the victim's challenge (registration/call-setup DoS).
		 * Re-challenge with the EXISTING nonce when still live; regenerate only
		 * when empty/expired. */
		ast_mutex_lock(&peer->lock);
		if (ast_strlen_zero(peer->nonce)
				|| (peer->nonce_issued_at && (now_rm - peer->nonce_issued_at) > ttl_rm)) {
			sofia_regen_nonce_locked(peer, chal_nonce, sizeof(chal_nonce));
		} else {
			ast_copy_string(chal_nonce, peer->nonce, sizeof(chal_nonce));
		}
		ast_mutex_unlock(&peer->lock);
		sofia_emit_auth_challenge(nua, nh, realm, chal_nonce, 1);
		ast_verbose("Sofia: %s auth realm mismatch for '%s' - expected '%s' got '%s'\n",
			method, peer->name, realm, auth_realm ? auth_realm : "(none)");
		return SOFIA_AUTH_CHALLENGE;
	}

	using_qop = (auth_qop && !strcasecmp(auth_qop, "auth"));

	/* We ALWAYS challenge with qop="auth", so a PRESENT qop that is not exactly
	 * "auth" is malformed / a downgrade — without this it would fall through to
	 * the legacy RFC 2069 no-qop digest, bypassing the nc/cnonce replay tracking
	 * that qop=auth mandates. Check RAW header presence (msg_header_find_param),
	 * not the parsed auth_qop: sofia_au_get_unq returns NULL on an OVERSIZED
	 * value, so an oversized qop would otherwise be misread as "no qop". A
	 * MISSING qop is deliberately still accepted (RFC 2069 compat). */
	if (au && msg_header_find_param(au->au_common, "qop") && !using_qop) {
		nua_respond(nh, SIP_400_BAD_REQUEST, NUTAG_WITH_THIS(nua), TAG_END());
		ast_verbose("Sofia: %s auth rejected for '%s' - unsupported/oversized qop (only qop=auth is offered)\n",
			method, peer->name);
		sofia_blacklist_add_sip(sip, "digest unsupported qop");
		return SOFIA_AUTH_REJECT;
	}

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
		/* RFC 2617 nc is EXACTLY 8 LHEX. Validate the format BEFORE strtoul,
		 * which otherwise accepts a leading '-' ("-1" -> ULONG_MAX -> cast
		 * UINT_MAX) that passes the !=0 guard and poisons peer->last_nc,
		 * self-replay-DoSing the peer until the nonce rotates. The strtoul+endptr
		 * check below stays as belt-and-suspenders. */
		if (strlen(auth_nc) != 8 || strspn(auth_nc, "0123456789abcdefABCDEF") != 8) {
			nua_respond(nh, SIP_400_BAD_REQUEST, NUTAG_WITH_THIS(nua), TAG_END());
			ast_verbose("Sofia: %s auth rejected for '%s' - nc not 8 hex digits: %s\n",
				method, peer->name, auth_nc);
			sofia_blacklist_add_sip(sip, "digest malformed nc");
			return SOFIA_AUTH_REJECT;
		}
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

	/* Split "rotate our nonce" from "the client sent a wrong/old nonce". ROTATE
	 * only when our stored nonce is genuinely dead (empty/expired) or a qop
	 * nc-replay was detected AGAINST THE MATCHING nonce; a request bearing a
	 * NON-matching nonce is re-challenged with the EXISTING live nonce, never
	 * regenerating it — so an unauthenticated/spoofed request cannot DoS a
	 * victim's in-flight challenge by clobbering the single per-peer nonce. */
	{
		time_t now_nr = time(NULL);
		int ttl_nr = sofia_cfg.nonce_ttl_seconds > 0 ? sofia_cfg.nonce_ttl_seconds : SOFIA_NONCE_TTL_SEC_DEFAULT;
		int nonce_dead = ast_strlen_zero(peer->nonce)
			|| (peer->nonce_issued_at && (now_nr - peer->nonce_issued_at) > ttl_nr);
		int nonce_matches = (auth_nonce && !ast_strlen_zero(peer->nonce)
			&& !strcmp(auth_nonce, peer->nonce));
		int nc_replay = (using_qop && nonce_matches && new_nc <= peer->last_nc);

		if (nonce_dead || nc_replay) {
			char fresh_nonce[64];
			sofia_regen_nonce_locked(peer, fresh_nonce, sizeof(fresh_nonce));
			ast_mutex_unlock(&peer->lock);
			sofia_emit_auth_challenge(nua, nh, realm, fresh_nonce, 1);
			if (sofia_debug) {
				ast_verbose("Sofia: %s auth challenge for '%s' - %s; fresh nonce=%s\n",
					method, peer->name, nc_replay ? "nc-replay" : "stale/expired", fresh_nonce);
			}
			return SOFIA_AUTH_CHALLENGE;
		}
		if (!nonce_matches) {
			char chal_nonce[64];
			ast_copy_string(chal_nonce, peer->nonce, sizeof(chal_nonce));
			ast_mutex_unlock(&peer->lock);
			sofia_emit_auth_challenge(nua, nh, realm, chal_nonce, 1);
			if (sofia_debug) {
				ast_verbose("Sofia: %s auth challenge for '%s' - wrong/old nonce; re-challenged with live nonce\n",
					method, peer->name);
			}
			return SOFIA_AUTH_CHALLENGE;
		}
	}

	/* md5secret carries a pre-computed MD5(user:realm:secret) usable ONLY for the
	 * MD5 digest, and it takes PRECEDENCE over peer->secret whenever it is set
	 * (sofia_compute_a1_hash). So ANY peer with md5secret set — with or without a
	 * cleartext secret — cannot satisfy a SHA-256 client; the comparison would
	 * silently fail with 403. Recover by re-challenging MD5 only so the client
	 * retries with the one algorithm this credential can verify. If MD5 is globally
	 * disabled (auth_algorithms=sha256) the configuration is irreconcilable: reject
	 * with a clear 403 + warning rather than offer an un-offered algorithm.
	 * Read md5secret + regen nonce here, under peer->lock (stable). */
	if (algorithm == SOFIA_DIGEST_SHA256 && !ast_strlen_zero(peer->md5secret)) {
		int want_md5, want_sha256;
		sofia_auth_offered(&want_md5, &want_sha256);
		if (want_md5) {
			char fresh_nonce[64];
			char hdr_md5[256];
			/* The nonce already matched + is live (we passed the regen gate) and
			 * the response is NOT yet verified — re-challenge MD5-only with the
			 * EXISTING nonce instead of rotating it pre-credential, so a request
			 * that knows a valid nonce but asks for SHA-256 cannot clobber it. */
			ast_copy_string(fresh_nonce, peer->nonce, sizeof(fresh_nonce));
			ast_mutex_unlock(&peer->lock);
			snprintf(hdr_md5, sizeof(hdr_md5),
				"Digest realm=\"%s\", nonce=\"%s\", qop=\"auth\", algorithm=MD5, stale=true",
				realm, fresh_nonce);
			nua_respond(nh, SIP_401_UNAUTHORIZED,
				SIPTAG_WWW_AUTHENTICATE_STR(hdr_md5),
				NUTAG_WITH_THIS(nua), TAG_END());
			ast_verbose("Sofia: %s for md5secret peer '%s' requested SHA-256 — re-challenging MD5-only\n",
				method, peer->name);
			return SOFIA_AUTH_CHALLENGE;
		}
		ast_mutex_unlock(&peer->lock);
		nua_respond(nh, SIP_403_FORBIDDEN, NUTAG_WITH_THIS(nua), TAG_END());
		ast_log(LOG_WARNING,
			"Sofia: peer '%s' has md5secret but auth_algorithms=sha256 — cannot authenticate "
			"(md5secret is MD5-only); use auth_algorithms=both|md5 or a cleartext secret\n",
			peer->name);
		return SOFIA_AUTH_REJECT;
	}

	/* Compute the expected response. peer->lock held — peer->secret + peer->name
	 * are read-stable across the helper boundary. */
	if (sofia_compute_digest(peer, realm, method, auth_uri,
			peer->nonce, auth_nc, auth_cnonce,
			using_qop ? "auth" : NULL,
			algorithm,
			expected_hash) != 0) {
		/* The digest could not be computed (OOM building HA1/HA2). Reject 500 —
		 * never grant or compare against a partial/empty hash. */
		ast_mutex_unlock(&peer->lock);
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, NUTAG_WITH_THIS(nua), TAG_END());
		ast_verbose("Sofia: %s auth digest-compute failed (OOM) for '%s' — rejecting\n",
			method, peer->name);
		return SOFIA_AUTH_REJECT;
	}

	/* Constant-time digest comparison (sofia_ct_memcmp) over the
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

/* Caller must hold peer->lock. Generates a fresh nonce (via
 * sofia_secure_nonce_gen), records the issue time, resets the nc counter. */
static void sofia_regen_nonce_locked(struct sofia_peer *peer, char *out_buf, size_t out_len)
{
	sofia_secure_nonce_gen(out_buf, out_len);
	ast_string_field_set(peer, nonce, out_buf);
	peer->nonce_issued_at = time(NULL);
	peer->last_nc = 0;
}

/* domainsasrealm (chan_sip parity): when set + domain_list non-empty, check the
 * From-header domain then the To-header domain; if either matches a configured
 * domain, use it as the auth realm. Falls back to sofia_cfg.realm (or "gabpbx")
 * when domainsasrealm is clear, domain_list is empty, or no domain matched.
 * Returns a pointer into the caller-provided buf (matched domain) OR the
 * sofia_cfg.realm/"gabpbx" literal — caller MUST ensure buf outlives all uses. */
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

/* Timing-equalized reject: inject dummy HMAC computation + a jitter delay
 * before emitting a reject, mitigating username-enumeration via a timing oracle
 * across the auth-fail / ACL-deny / unknown-peer paths. Used uniformly at every
 * reject callsite (sofia_send_auth_challenge unknown-peer + the ACL-deny paths).
 *
 * Dummy work: 3× SHA-256 hashes matching the real auth-fail path
 * (sofia_compute_a1_hash + a2 + final response); the volatile sink prevents
 * dead-code elimination. Jitter: 10-50ms randomized.
 *
 * NOTE: the usleep blocks the single sofia_thread, so under a reject-flood DoS
 * throughput is limited to ~33 rejects/sec — the sample config recommends
 * pairing with fail2ban / firewall rate-limiting. (The AMI AuthFailure event is
 * emitted by the callers; GabPBX has no EVENT_FLAG_SECURITY, so EVENT_FLAG_SYSTEM
 * is used, matching the other chan_sofia AMI events.) */
static void sofia_emit_timing_equalized_reject(void)
{
	char dummy_a1[256];
	char dummy_a2[256];
	char dummy_resp[1024];
	char dummy_hash1[65];
	char dummy_hash2[65];
	char dummy_hash3[65];
	volatile char sink;

	/* 3× SHA-256 hashes match the real auth path's compute cost
	 * (sofia_compute_a1_hash + a2 + final). */
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

/* WWW-Authenticate header-injection prevention: validate nonce/realm before
 * emit, rejecting unescaped CR/LF/quote/backslash (RFC 2617 quoted-string
 * rules). Both are generated via controlled paths (hex-only nonce, operator-
 * config realm), so this is defense-in-depth. Returns 1 if safe to embed in a
 * quoted-string, 0 if invalid. */
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

static void sofia_send_auth_challenge(nua_t *nua, nua_handle_t *nh, sip_t const *sip,
		const char *realm, const char *method, const char *reason)
{
	/* Real fresh nonce (not a literal "empty" placeholder) so an attacker cannot
	 * distinguish unknown-peer from known-peer responses, plus the same
	 * algorithm offer as sofia_verify_digest_auth. */
	char fresh_nonce[64];
	struct ast_sockaddr src;
	char addr_buf[80];

	sofia_secure_nonce_gen(fresh_nonce, sizeof(fresh_nonce));

	/* Header-injection defense-in-depth: validate the realm + fresh_nonce
	 * charset before emission (realm is operator-config, nonce is hex-only by
	 * construction). */
	if (!sofia_auth_str_safe(realm) || !sofia_auth_str_safe(fresh_nonce)) {
		ast_log(LOG_WARNING, "Sofia: refusing to emit auth challenge — "
			"unsafe characters in realm or nonce (defense-in-depth)\n");
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR,
			NUTAG_WITH_THIS(nua), TAG_END());
		return;
	}

	/* Timing-equalization: dummy HMAC + jitter to match known-peer-bad-password
	 * timing across all unknown-peer callsites. */
	sofia_emit_timing_equalized_reject();

	/* Unknown-peer challenge — same global offer as everyone else; the
	 * auth_algorithms selection (MD5 first) is applied inside the helper. */
	sofia_emit_auth_challenge(nua, nh, realm, fresh_nonce, 0);

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

/* Emits a SubscribeRejected AMI event at every gate-rejected SUBSCRIBE (global
 * ban or per-peer flag) for NMS subscribe-abuse monitoring. EVENT_FLAG_SYSTEM
 * (GabPBX has no EVENT_FLAG_SECURITY), matching the other chan_sofia AMI events. */
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

/* lockuseragent security gate at REGISTER auth-success (chan_sip parity). When
 * set, locks the peer to a single User-Agent captured at the first successful
 * REGISTER; subsequent REGISTERs with a different UA reject via a 401 silent-
 * challenge (chan_sip AUTH_SECRET_FAILED-equivalent) + an AMI LockUserAgentReject
 * event for NMS UA-spoofing visibility. Called from BOTH sofia_process_register
 * paths (no-secret + auth-OK).
 *
 * Returns 0 = PASS (caller continues), -1 = REJECT (401 + AMI already emitted;
 * caller MUST ao2_ref(peer,-1) and return). */
static int sofia_check_lockuseragent(nua_t *nua, nua_handle_t *nh,
		sip_t const *sip, struct sofia_peer *peer)
{
	const char *current_ua = NULL;
	const char *realm;
	struct ast_sockaddr src;
	char addr_buf[80];
	int prefix_mode = 0;	/* 1 when lockuseragent_prefixes is non-empty — suppresses capture/anchor logic, tags rejection AMI MatchPolicy: prefix-list */

	if (!peer->lockuseragent) {
		return 0;
	}

	if (sip && sip->sip_user_agent && sip->sip_user_agent->g_string) {
		current_ua = sip->sip_user_agent->g_string;
	}

	/* Prefix-list mode: when peer->lockuseragent_prefixes is non-empty, the
	 * operator has pre-declared which UA families may register — skip the
	 * first-REGISTER auto-capture and walk the comma-separated allowlist. Any
	 * prefix that case-insensitively matches the inbound User-Agent passes; no
	 * match falls through to the shared rejection path. Tokenizing per REGISTER
	 * (rare) lets a reload / realtime UPDATE take effect on the next REGISTER
	 * with no restart. An empty list preserves the strict capture-on-first-
	 * REGISTER behaviour (else-branch). */
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

	/* Mismatch — silent 401 challenge (chan_sip AUTH_SECRET_FAILED-equivalent;
	 * attacker cannot distinguish UA-mismatch from bad-secret) + AMI
	 * LockUserAgentReject for NMS visibility. */
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

/* === Phase 1: bounded REGISTER realtime-DB-write offload ===================== */

struct sofia_rtupdate_ctx {
	int registered;          /* selects the registered vs cleared ast_update_realtime shape */
	int syslabel_regserver;  /* 1 => syslabel key is "regserver", 0 => NULL */
	int sysname_null;        /* 1 => sysname value is NULL */
	char table[16];
	char name[256];          /* peer->name is unbounded — char[256] avoids truncating the realtime key */
	char ipaddr[64];
	char port[16];
	char regseconds[24];
	char fullcontact[256];
	char sysname[128];
};

/* The single ast_update_realtime() emitter shared by the inline and the worker paths so
 * both produce byte-identical DB writes (mirrors the original inline blocks verbatim). */
static void sofia_rtupdate_emit(const char *table, const char *name, int registered,
		const char *ipaddr, const char *port, const char *regseconds,
		const char *fullcontact, const char *syslabel, const char *sysname)
{
	if (registered) {
		ast_update_realtime(table, "name", name,
			"ipaddr", ipaddr,
			"port", port,
			"regseconds", regseconds,
			"fullcontact", fullcontact,
			syslabel, sysname,
			SENTINEL);
	} else {
		ast_update_realtime(table, "name", name,
			"ipaddr", "",
			"regseconds", "0",
			"fullcontact", "",
			syslabel, sysname,
			SENTINEL);
	}
}

/* Inline (legacy) path: resolve the args from peer/sip on sofia_thread and write now.
 * Identical behaviour to the original inline blocks; used when the pool is OFF or full. */
static void sofia_rtupdate_inline(struct sofia_peer *peer, sip_t const *sip)
{
	const char *table = ast_check_realtime("sipregs") ? "sipregs" : "sippeers";
	const char *sysname = ast_config_AST_SYSTEM_NAME;
	const char *syslabel = NULL;

	if (ast_strlen_zero(sysname)) {
		sysname = NULL;
	} else if (sofia_cfg.rtsave_sysname) {
		syslabel = "regserver";
	}
	if (peer->registered) {
		char port_str[32], regsec_str[32];
		/* A wildcard "Contact: *" has m_url->url_host == NULL — guard it (m_url itself
		 * is an embedded array, never NULL), mirroring the PeerStatus emit. */
		const char *contact_str = (sip->sip_contact && sip->sip_contact->m_url->url_host) ?
			sip->sip_contact->m_url->url_host : "";
		snprintf(port_str, sizeof(port_str), "%d", ast_sockaddr_port(&peer->src_addr));
		snprintf(regsec_str, sizeof(regsec_str), "%ld", (long)time(NULL));
		sofia_rtupdate_emit(table, peer->name, 1,
			ast_sockaddr_stringify_host(&peer->src_addr),
			port_str, regsec_str, contact_str, syslabel, sysname);
	} else {
		sofia_rtupdate_emit(table, peer->name, 0, "", "", "", "", syslabel, sysname);
	}
}

/* Lane worker: writes the DB row from the snapshot only — zero peer/sip access. */
static int sofia_rtupdate_task_exe(void *data)
{
	struct sofia_rtupdate_ctx *c = data;
	const char *syslabel = c->syslabel_regserver ? "regserver" : NULL;
	const char *sysname = c->sysname_null ? NULL : c->sysname;

	sofia_rtupdate_emit(c->table, c->name, c->registered,
		c->ipaddr, c->port, c->regseconds, c->fullcontact, syslabel, sysname);
	ast_free(c);
	return 0;
}

/* Called on sofia_thread at each realtime-update site.  Pool OFF → inline write.  Pool ON →
 * snapshot everything the worker needs (deep-copying peer->name and the contact host, since
 * the worker must never touch peer/sip) and push it to the lane keyed by peer name.
 *
 * Once the pool is enabled EVERY write for a peer goes through its lane — never an inline
 * bypass — because an inline write runs synchronously on sofia_thread and could overtake a
 * still-queued write for the SAME peer, inverting REGISTER vs de-REGISTER order in the DB.
 * The lane (taskprocessor) queue is the single strict-FIFO path per account; it absorbs a
 * slow DB and drains (threads stay bounded at N).  If the write genuinely cannot be queued
 * (OOM, or the taskprocessor is gone) we log and DROP this update rather than reorder; the
 * next REGISTER refresh re-writes the row. */
static void sofia_rtupdate_submit(struct sofia_peer *peer, sip_t const *sip)
{
	int lane;
	const char *sysname;
	struct sofia_rtupdate_ctx *c;

	if (!sofia_regpool_enabled) {
		sofia_rtupdate_inline(peer, sip);
		return;
	}
	/* unsigned modulo: ast_str_case_hash() can return a negative int (abs(INT_MIN)); with a
	 * non-power-of-two lane count a signed modulo could otherwise yield a negative (OOB) index. */
	lane = (int)(((unsigned int)ast_str_case_hash(peer->name)) % (unsigned int)sofia_regpool_n);
	if (!(c = ast_calloc(1, sizeof(*c)))) {
		ast_log(LOG_WARNING, "Sofia: register_pool OOM — dropped realtime update for peer '%s' (next REGISTER refreshes it)\n", peer->name);
		return;
	}
	c->registered = peer->registered ? 1 : 0;
	ast_copy_string(c->table, ast_check_realtime("sipregs") ? "sipregs" : "sippeers", sizeof(c->table));
	ast_copy_string(c->name, peer->name, sizeof(c->name));
	sysname = ast_config_AST_SYSTEM_NAME;
	if (ast_strlen_zero(sysname)) {
		c->sysname_null = 1;
		c->syslabel_regserver = 0;
	} else {
		c->sysname_null = 0;
		c->syslabel_regserver = sofia_cfg.rtsave_sysname ? 1 : 0;
		ast_copy_string(c->sysname, sysname, sizeof(c->sysname));
	}
	if (c->registered) {
		/* A wildcard "Contact: *" has m_url->url_host == NULL — guard it (m_url itself
		 * is an embedded array, never NULL), mirroring the PeerStatus emit. */
		const char *contact_str = (sip->sip_contact && sip->sip_contact->m_url->url_host) ?
			sip->sip_contact->m_url->url_host : "";
		ast_copy_string(c->ipaddr, ast_sockaddr_stringify_host(&peer->src_addr), sizeof(c->ipaddr));
		snprintf(c->port, sizeof(c->port), "%d", ast_sockaddr_port(&peer->src_addr));
		snprintf(c->regseconds, sizeof(c->regseconds), "%ld", (long)time(NULL));
		ast_copy_string(c->fullcontact, contact_str, sizeof(c->fullcontact));
	}
	if (ast_taskprocessor_push(sofia_regpool[lane], sofia_rtupdate_task_exe, c) < 0) {
		ast_log(LOG_WARNING, "Sofia: register_pool push failed — dropped realtime update for peer '%s' (next REGISTER refreshes it)\n", peer->name);
		ast_free(c);
	}
}

/* Create the lane taskprocessors once (idempotent).  On any lane failure it unwinds and
 * leaves the pool disabled (sofia_regpool_n stays 0 → REGISTER stays fully inline). */
static void sofia_regpool_create(void)
{
	int n, i;

	if (sofia_regpool_n > 0) {
		return;
	}
	if (sofia_cfg.register_pool_workers > 0) {
		n = sofia_cfg.register_pool_workers;
	} else {
		long cpus = sysconf(_SC_NPROCESSORS_ONLN);
		n = (cpus > 0) ? (int)(cpus / 2 + 1) : 2;
	}
	if (n < 2) {
		n = 2;
	}
	if (n > SOFIA_REGPOOL_MAX) {
		n = SOFIA_REGPOOL_MAX;
	}
	for (i = 0; i < n; i++) {
		char tps_name[32];
		snprintf(tps_name, sizeof(tps_name), "sofia/regpool-%02d", i);
		sofia_regpool[i] = ast_taskprocessor_get(tps_name, TPS_REF_DEFAULT);
		if (!sofia_regpool[i]) {
			ast_log(LOG_WARNING, "Sofia: register_pool lane %d failed to create; pool disabled\n", i);
			while (--i >= 0) {
				sofia_regpool[i] = ast_taskprocessor_unreference(sofia_regpool[i]);
			}
			return;
		}
	}
	sofia_regpool_n = n;
	ast_log(LOG_NOTICE, "Sofia: register_pool created with %d lane(s)\n", n);
}

/* Reconcile the pool with config; called at the end of every sofia_apply_config (boot and
 * reload), so register_pool=yes/no toggles the kill-switch at runtime via `sofia reload`. */
static void sofia_regpool_update(void)
{
	if (sofia_cfg.register_pool && sofia_regpool_n == 0) {
		sofia_regpool_create();
	}
	/* register_pool_workers is fixed at first pool creation: taskprocessors cannot be torn
	 * down at runtime (the module also refuses unload), so a changed lane count needs a full
	 * gabpbx restart.  Tell the operator instead of silently ignoring a reload-time change. */
	if (sofia_regpool_n > 0 && sofia_cfg.register_pool_workers > 0
			&& sofia_cfg.register_pool_workers != sofia_regpool_n) {
		ast_log(LOG_NOTICE, "Sofia: register_pool_workers=%d ignored — pool already has %d lane(s); restart gabpbx to change\n",
			sofia_cfg.register_pool_workers, sofia_regpool_n);
	}
	sofia_regpool_enabled = (sofia_cfg.register_pool && sofia_regpool_n > 0);
}

/* Uniform REGISTER outcome logging. On every attempt — success or failure — emit
 * one NOTICE line with the SIP user (AOR) it was attempted for, the source IP, and
 * the User-Agent (to identify the handset/phone model). Source IP comes from
 * sofia_get_source_addr (Via received= / sent-by); the User-Agent from the SIP
 * header. AOR is the peer name (known peer) or the From user (unknown/unmatched). */
static void sofia_log_register_outcome(const char *result, const char *aor, sip_t const *sip)
{
	struct ast_sockaddr src;
	const char *ua = (sip && sip->sip_user_agent && sip->sip_user_agent->g_string)
		? sip->sip_user_agent->g_string : "(unknown)";

	sofia_get_source_addr(sip, &src);
	ast_log(LOG_NOTICE, "Sofia REGISTER %s: user='%s' ip=%s useragent='%s'\n",
		result, S_OR(aor, "(unknown)"), ast_sockaddr_stringify(&src), ua);
}

/* A successful REGISTER is logged only when it CHANGES registration state — a new
 * registration, an unregister, or a contact add/remove/move — not on every routine
 * keepalive refresh (which would flood the log every ~60s per phone). Mirrors the
 * "interesting event" set used by sofia_verbose_register_update. */
static int sofia_register_changed(const struct sofia_register_update *u)
{
	return u && (u->wildcard_removed || u->contacts_removed || u->contacts_added
		|| u->contacts_moved || (u->was_registered != u->now_registered));
}

/* Answer a Contact-less REGISTER — a binding QUERY (RFC 3261 §10.2.3), NOT a
 * (de)registration — with the peer's CURRENT bindings and ZERO registration-state
 * side-effects (no expiry bounds, no lockuseragent capture, no contact mutation,
 * no realtime/regexten/devstate/PeerStatus). Caller must have authenticated/accepted
 * first. Emits a 200 OK whose Contact list echoes the stored contacts (bare 200 with
 * no Contact if none are registered). */
static void sofia_respond_register_query(nua_t *nua, nua_handle_t *nh, struct sofia_peer *peer)
{
	struct ast_str *contacts = ast_str_create(256);
	time_t now = time(NULL);

	if (contacts && peer->contacts) {
		struct ao2_iterator ci = ao2_iterator_init(peer->contacts, 0);
		struct sofia_contact *c;
		while ((c = ao2_iterator_next(&ci))) {
			char uri[256];
			long ttl;
			/* contact_uri is set once at contact creation; expires is refreshed, so
			 * read both under the contact lock. */
			ao2_lock(c);
			ast_copy_string(uri, c->contact_uri, sizeof(uri));
			ttl = (long)(c->expires - now);
			ao2_unlock(c);
			if (ttl < 0) {
				ttl = 0;
			}
			ast_str_append(&contacts, 0, "%s<%s>;expires=%ld",
				ast_str_strlen(contacts) ? ", " : "", uri, ttl);
			ao2_ref(c, -1);
		}
		ao2_iterator_destroy(&ci);
	}
	if (contacts && ast_str_strlen(contacts)) {
		nua_respond(nh, SIP_200_OK,
			SIPTAG_CONTACT_STR(ast_str_buffer(contacts)),
			NUTAG_WITH_THIS(nua), TAG_END());
	} else {
		nua_respond(nh, SIP_200_OK, NUTAG_WITH_THIS(nua), TAG_END());
	}
	ast_free(contacts);
	if (sofia_debug) {
		ast_verbose("Sofia: REGISTER query (no Contact) for peer '%s' — returned current bindings\n",
			peer->name);
	}
}

/* Emit the REGISTER side-effects — dialplan regexten + PeerStatus AMI + BLF/presence
 * devstate — AFTER peer->lock is released (sofia_update_peer_contacts is a pure accumulator
 * recording the intent in `update`). These take the global contexts lock, emit AMI, and fan
 * out BLF, none of which should run under the peer mutex. emit_unregister is MUTUALLY
 * EXCLUSIVE with the registered tail (a wildcard/expiry unregister never also fires
 * PeerStatus Registered). Called by BOTH the no-secret and auth REGISTER 200-OK paths so
 * their side-effects are identical. */
static void sofia_emit_register_side_effects(struct sofia_peer *peer, sip_t const *sip,
		const struct sofia_register_update *update)
{
	if (!peer || !update) {
		return;
	}
	if (update->emit_unregister) {
		register_peer_exten(peer, 0);
		manager_event(EVENT_FLAG_SYSTEM, "PeerStatus",
			"ChannelType: SIP\r\n"
			"Peer: SIP/%s\r\n"
			"PeerStatus: Unregistered\r\n"
			"Cause: %s\r\n",
			peer->name, update->unregister_cause ? update->unregister_cause : "Unregister");
		ast_devstate_changed(AST_DEVICE_UNKNOWN, AST_DEVSTATE_CACHABLE, "SIP/%s", peer->name);
		return;	/* mutually exclusive with the registered tail */
	}
	/* Registered / refresh: regexten + PeerStatus Registered fire on every real 200 OK,
	 * devstate only on an actual registration transition (sofia_register_changed). */
	register_peer_exten(peer, 1);
	if (sofia_register_changed(update)) {
		ast_devstate_changed(AST_DEVICE_UNKNOWN, AST_DEVSTATE_CACHABLE, "SIP/%s", peer->name);
	}
	manager_event(EVENT_FLAG_SYSTEM, "PeerStatus",
		"ChannelType: SIP\r\n"
		"Peer: SIP/%s\r\n"
		"PeerStatus: Registered\r\n"
		"Address: %s\r\n"
		"RegContact: %s\r\n"
		"UserAgent: %s\r\n"
		"Context: %s\r\n",
		peer->name,
		ast_sockaddr_stringify(&update->new_src),	/* use the snapshot, not a post-unlock peer->src_addr read */
		(sip && sip->sip_contact && sip->sip_contact->m_url->url_host) ?
			sip->sip_contact->m_url->url_host : "",
		(sip && sip->sip_user_agent && sip->sip_user_agent->g_string) ?
			sip->sip_user_agent->g_string : "",
		peer->context);
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
	/* domainsasrealm: returns From/To-domain match if domainsasrealm set +
	 * domain_list non-empty; falls back to sofia_cfg.realm. */
	realm = sofia_get_realm_for_dialog(sip, realm_buf, sizeof(realm_buf));

	user = sip->sip_from->a_url->url_user;
	domain = sip->sip_from->a_url->url_host;

	if (sofia_debug) {
		ast_verbose("Sofia: REGISTER from %s@%s\n",
			user ? user : "(null)", domain ? domain : "(null)");
	}

	if (!user) {
		/* Malformed REGISTER (no From user) — emit a bogus nonce challenge then
		 * reject. Honor [general] auth_algorithms for the advertised algorithm so
		 * a sha256-only deployment never advertises MD5, even on this dead path. */
		sofia_emit_auth_challenge(nua, nh, realm, "empty", 0);
		sofia_blacklist_add_sip(sip, "REGISTER missing user");
		return;
	}

	/* match_auth_username (chan_sip parity): when set, override peer-lookup
	 * search-key with Authorization-username (or Proxy-Authorization fallback).
	 * Buffer at function scope so the returned pointer (into buf when auth-username
	 * found) stays valid for downstream sofia_find_peer + diagnostic uses of user. */
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
		sofia_log_register_outcome("REJECT (unknown peer)", user, sip);
		sofia_blacklist_add_sip(sip, "REGISTER unknown peer");
		return;
	}

	/* Per-peer ACL check (permit/deny) — applied BEFORE auth so a banned IP cannot
	 * even probe for valid credentials. */
	if (peer->ha) {
		struct ast_sockaddr src;
		sofia_get_source_addr(sip, &src);
		if (ast_apply_ha(peer->ha, &src) != AST_SENSE_ALLOW) {
			sofia_log_register_outcome("REJECT (ACL)", peer->name, sip);
			nua_respond(nh, SIP_403_FORBIDDEN,
				NUTAG_WITH_THIS(nua), TAG_END());
			sofia_blacklist_add_sip(sip, "REGISTER peer ACL reject");
			ao2_ref(peer, -1);
			return;
		}
	}

	/* If peer has NO credential at all, accept without auth. md5secret is a valid
	 * credential (sofia_verify_digest_auth -> sofia_compute_a1_hash uses it), so a
	 * md5secret-only peer MUST go through the auth path — checking only peer->secret
	 * let such a peer register with zero authentication (Contact hijack). */
	if (ast_strlen_zero(peer->secret) && ast_strlen_zero(peer->md5secret)) {
		/* A Contact-less REGISTER is a binding QUERY — answer with the peer's
		 * current bindings and run NO registration-state side-effects. */
		if (!sip->sip_contact) {
			sofia_respond_register_query(nua, nh, peer);
			ao2_ref(peer, -1);
			return;
		}
		/* Clamp ex_delta (unsigned long) before the int cast: a value > INT_MAX
		 * wraps negative / to 0 (spurious 423 or self-deregister). Real min/max
		 * bounds are applied by sofia_check_register_expiry below. */
		int expires = sip->sip_expires
			? (sip->sip_expires->ex_delta > (unsigned long) INT_MAX ? INT_MAX : (int) sip->sip_expires->ex_delta)
			: DEFAULT_EXPIRY;
		/* Registration TTL bounds + 423 Interval Too Brief (chan_sip parity): bounds
		 * check BEFORE sofia_update_peer_contacts. Helper emits 423 + Min-Expires + AMI
		 * on reject (caller MUST return immediately). */
		if (sofia_check_register_expiry(nua, nh, peer, &expires) < 0) {
			sofia_log_register_outcome("REJECT (interval too brief)", peer->name, sip);
			ao2_ref(peer, -1);
			return;
		}
		/* lockuseragent gate (chan_sip parity): post-auth-success, pre-contact-update.
		 * no-secret path. */
		if (sofia_check_lockuseragent(nua, nh, sip, peer) < 0) {
			sofia_log_register_outcome("REJECT (user-agent lock)", peer->name, sip);
			sofia_blacklist_add_sip(sip, "REGISTER user-agent lock reject");
			ao2_ref(peer, -1);
			return;
		}
		ast_mutex_lock(&peer->lock);
		int rc = sofia_update_peer_contacts(peer, sip, expires, &reg_update);
		ast_mutex_unlock(&peer->lock);
		if (rc == -2) {
			/* Wildcard "Contact: *" with non-zero Expires -> 400 (no-secret path). */
			sofia_log_register_outcome("REJECT (bad wildcard contact)", peer->name, sip);
			nua_respond(nh, SIP_400_BAD_REQUEST, NUTAG_WITH_THIS(nua), TAG_END());
			ao2_ref(peer, -1);
			return;
		}
		if (rc == -3) {
			/* Contact storage failed (ao2_link OOM) — answer 500, not a bogus 200 OK
			 * with no stored binding. */
			sofia_log_register_outcome("REJECT (contact storage failed)", peer->name, sip);
			nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, NUTAG_WITH_THIS(nua), TAG_END());
			ao2_ref(peer, -1);
			return;
		}
		if (rc < 0) {
			ast_verbose("Sofia: REGISTER from peer '%s' rejected with 403 \xe2\x80\x94 too many registered devices (limit=%d)\n",
				peer->name, peer->max_contacts);
			sofia_log_register_outcome("REJECT (max contacts)", peer->name, sip);
			nua_respond(nh, SIP_403_FORBIDDEN,
				NUTAG_WITH_THIS(nua),
				TAG_END());
			ao2_ref(peer, -1);
			return;
		}
		/* rtupdate (chan_sip parity, combined-gate): rtupdate=no skips ALL realtime
		 * DB writes. */
		if (peer->is_realtime && sofia_cfg.peer_rtupdate) {
			/* Offload the realtime DB write to the bounded pool when enabled;
			 * kill-switch OFF runs it inline. */
			sofia_rtupdate_submit(peer, sip);
		}
		/* Echo the GRANTED (clamped/defaulted) expires in the 200 OK so the client
		 * refreshes on the SERVER's schedule. Without it, a value the registrar capped
		 * is invisible to the phone, which keeps its longer requested TTL — the server
		 * binding lapses before the phone re-REGISTERs and inbound calls fail in the
		 * gap. This registrar derives the binding TTL from the top-level Expires. */
		char granted_exp[16];
		snprintf(granted_exp, sizeof(granted_exp), "%d", expires);
		nua_respond(nh, SIP_200_OK,
			SIPTAG_CONTACT(sip->sip_contact),
			SIPTAG_EXPIRES_STR(granted_exp),
			NUTAG_WITH_THIS(nua),
			TAG_END());
		sofia_verbose_register_update(peer, &reg_update);
		if (sofia_register_changed(&reg_update)) {
			sofia_log_register_outcome("OK", peer->name, sip);
		}
		/* Parity: emit the post-success side-effects the auth path runs. */
		sofia_emit_register_side_effects(peer, sip, &reg_update);
		ao2_ref(peer, -1);
		return;
	}

	/* Unified digest verification via sofia_verify_digest_auth (shared by REGISTER /
	 * INVITE / SUBSCRIBE). Helper handles challenge emission (no Authorization header)
	 * + 401-stale + 403 + AUTH_OK paths + constant-time compare + secure nonce gen +
	 * realm-validation + truncation rejection + missing-uri rejection. */
	{
		enum sofia_auth_result auth_res = sofia_verify_digest_auth(peer,
			nua, nh, sip, sip->sip_authorization, "REGISTER", realm);
		if (auth_res != SOFIA_AUTH_OK) {
			if (auth_res == SOFIA_AUTH_REJECT) {
				sofia_log_register_outcome("REJECT (auth)", peer->name, sip);
			}
			ao2_ref(peer, -1);
			return;
		}
	}

	/* Capture the granted expires out here so the 200 OK below (outside the following
	 * block) can echo it. */
	int granted_expires_auth = DEFAULT_EXPIRY;
	{
			/* A Contact-less REGISTER is a binding QUERY (post-auth) — answer with
			 * current bindings, run NO registration-state side-effects. */
			if (!sip->sip_contact) {
				sofia_respond_register_query(nua, nh, peer);
				ao2_ref(peer, -1);
				return;
			}
			/* Clamp ex_delta before the int cast (see no-secret path) — prevents
			 * a >INT_MAX Expires from wrapping to 0/negative. */
			int expires = sip->sip_expires
				? (sip->sip_expires->ex_delta > (unsigned long) INT_MAX ? INT_MAX : (int) sip->sip_expires->ex_delta)
				: DEFAULT_EXPIRY;
			/* Registration TTL bounds + 423 Interval Too Brief (auth-OK path). Helper
			 * emits 423 + Min-Expires + AMI on reject (caller MUST return immediately). */
			if (sofia_check_register_expiry(nua, nh, peer, &expires) < 0) {
				sofia_log_register_outcome("REJECT (interval too brief)", peer->name, sip);
				ao2_ref(peer, -1);
				return;
			}
			granted_expires_auth = expires;	/* capture for the 200 OK echo */
			/* lockuseragent gate (chan_sip parity): post-auth-success, pre-contact-update.
			 * auth-OK path. */
			if (sofia_check_lockuseragent(nua, nh, sip, peer) < 0) {
				sofia_log_register_outcome("REJECT (user-agent lock)", peer->name, sip);
				sofia_blacklist_add_sip(sip, "REGISTER user-agent lock reject");
				ao2_ref(peer, -1);
				return;
			}
			ast_mutex_lock(&peer->lock);
			int rc = sofia_update_peer_contacts(peer, sip, expires, &reg_update);
			ast_mutex_unlock(&peer->lock);
			if (rc == -2) {
				/* Wildcard "Contact: *" with non-zero Expires -> 400. */
				sofia_log_register_outcome("REJECT (bad wildcard contact)", peer->name, sip);
				nua_respond(nh, SIP_400_BAD_REQUEST, NUTAG_WITH_THIS(nua), TAG_END());
				ao2_ref(peer, -1);
				return;
			}
			if (rc == -3) {
				/* Contact storage failed (ao2_link OOM) — answer 500, not a bogus
				 * 200 OK with no stored binding. */
				sofia_log_register_outcome("REJECT (contact storage failed)", peer->name, sip);
				nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, NUTAG_WITH_THIS(nua), TAG_END());
				ao2_ref(peer, -1);
				return;
			}
			if (rc < 0) {
				ast_verbose("Sofia: REGISTER from peer '%s' rejected with 403 \xe2\x80\x94 too many registered devices (limit=%d)\n",
					peer->name, peer->max_contacts);
				sofia_log_register_outcome("REJECT (max contacts)", peer->name, sip);
				nua_respond(nh, SIP_403_FORBIDDEN,
					NUTAG_WITH_THIS(nua),
					TAG_END());
				ao2_ref(peer, -1);
				return;
			}
		}

		/* rtupdate (chan_sip parity, combined-gate): auth-OK path realtime updates. */
		if (peer->is_realtime && sofia_cfg.peer_rtupdate) {
			/* Offload the realtime DB write to the bounded pool when enabled;
			 * kill-switch OFF runs it inline. */
			sofia_rtupdate_submit(peer, sip);
		}

		/* Echo the GRANTED (clamped/defaulted) expires in the 200 OK so the client
		 * refreshes on the SERVER's schedule (see the other REGISTER 200 OK path). */
		char granted_exp[16];
		snprintf(granted_exp, sizeof(granted_exp), "%d", granted_expires_auth);
		nua_respond(nh, SIP_200_OK,
			SIPTAG_CONTACT(sip->sip_contact),
			SIPTAG_EXPIRES_STR(granted_exp),
			NUTAG_WITH_THIS(nua),
			TAG_END());
		sofia_verbose_register_update(peer, &reg_update);
		if (sofia_register_changed(&reg_update)) {
			sofia_log_register_outcome("OK", peer->name, sip);
		}
		/* REGISTER side-effects (regexten + PeerStatus Registered + devstate) are
		 * emitted post-unlock by sofia_emit_register_side_effects, shared with the
		 * no-secret path. */
		sofia_emit_register_side_effects(peer, sip, &reg_update);
		ao2_ref(peer, -1);
}

/* Inbound MESSAGE handler (chan_sip parity). Content-Type validated by
 * strcasecmp full-match (RFC 3261 §7.3.1; sofia-sip-tokenized c_type avoids
 * chan_sip's case-sensitive strncmp + 10-char prefix-truncation that
 * mis-accepts "text/plainXYZ").
 *
 * In-dialog (op->owner): queue AST_FRAME_TEXT + 202 Accepted. Out-of-dialog:
 * 405 Method Not Allowed + LOG_WARNING. */
static void sofia_process_message(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	char buf[1400];
	const char *body = NULL;
	char *bufp;
	struct ast_frame f;

	/* Content-Type validation: text/plain only (case-insensitive full-match per
	 * RFC 3261 §7.3.1; sofia-sip strips ;params so c_type is the canonical
	 * type/subtype only). */
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
	/* Bound the copy by pl_len — sip payload data may contain embedded NULs and is
	 * not guaranteed NUL-terminated, so an ast_copy_string / strlen-based copy could
	 * truncate the body or over-read past pl_data. */
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

	/* In-dialog vs out-of-dialog dispatch.
	 * TOCTOU/UAF: op (the dialog pvt) is pinned by the teardown-race guard
	 * (nua_i_message is in the sofia_pvt_ref_if_linked switch), but op->owner is
	 * nulled by sofia_hangup under op->lock on the channel thread. Snapshot+ref
	 * the owner under op->lock, then ast_queue_frame outside the lock (it takes
	 * the channel lock — holding op->lock across it would invert channel->pvt). */
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
			nua_respond(nh, 202, "Accepted", NUTAG_WITH_THIS(nua), TAG_END());
			return;
		}
	}

	/* Out-of-dialog: 405 + LOG_WARNING (chan_sip parity). */
	ast_log(LOG_WARNING, "Sofia: out-of-dialog MESSAGE dropped (no active call). "
		"Content-Type: %s, Body: '%s'\n",
		sip->sip_content_type->c_type, buf);
	nua_respond(nh, 405, "Method Not Allowed", NUTAG_WITH_THIS(nua), TAG_END());
}

/* Resolve the source IP we present to `target` for outbound INVITE From + Contact +
 * SDP c= line (chan_sip parity):
 *   - kernel routing query (ast_ouraddrfor) gives the OS-chosen source IP for
 *     reaching `target` — closes the bindaddr=0.0.0.0 case
 *   - if sofia_should_use_externaddr(target) → substitute sofia_cfg.externaddr (NAT remap)
 *   - port defaults to sofia_cfg.bindport if unset
 *
 * On entry: target points to the peer's reachable sockaddr (src_addr if
 * registered+dynamic, else constructed from peer->host:port).
 * On exit: pvt->ourip is fully populated (host + port).
 *
 * Inbound flows: not called. pvt->ourip stays zero-initialized; sofia_generate_sdp
 * fallback chain handles the unset case via getsockname() on rtp fd. */
static void sofia_resolve_ourip(struct sofia_pvt *pvt, const struct ast_sockaddr *target)
{
	if (!pvt || !target) {
		return;
	}

	/* Lazy-refresh externhost when the DDNS deadline expired (chan_sip parity).
	 * Re-resolves externhost into externaddr + bumps externexpire. Single re-resolve
	 * site — sofia_should_use_externaddr + sofia_generate_sdp consumers read the
	 * resolved sofia_cfg.externaddr so refresh propagates transparently. */
	if (sofia_cfg.externexpire && time(NULL) >= sofia_cfg.externexpire
			&& !ast_strlen_zero(sofia_cfg.externhost)) {
		struct ast_sockaddr *addrs = NULL;
		/* AST_AF_UNSPEC for dual-stack DNS resolution: an AST_AF_INET hint would
		 * exclude AAAA records, silently failing an AAAA-only externhost (externaddr
		 * stays empty + NAT rewrite never fires). UNSPEC accepts both A + AAAA; first
		 * result captured per RFC 6724 source-address-selection. chan_sip parity. */
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

		/* Per-transport external port substitution (chan_sip parity): UDP keeps
		 * externaddr port (or bindport fallback below); TCP/WS use externtcpport
		 * (externaddr-port fallback when 0); TLS/WSS use externtlsport.
		 *
		 * NOTE: the per-peer transport= parsers silent-accept without writing
		 * peer->transport (it stays SOFIA_TRANSPORT_UDP from sofia_peer_alloc), so the
		 * TCP/TLS branches below are unreachable for normally-configured peers. Kept
		 * structurally for the listener-level paths. For static TCP/TLS peers that
		 * relied on externtcpport/externtlsport here, set the listener port explicitly
		 * via port=<listener-port> or a dedicated TLS-only listener profile. */
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

/* Build outbound INVITE From header URI (chan_sip parity).
 *
 * - Reads pvt->owner->connected.id.number/name.str (NOT cid.cid_num/cid_name
 *   directly; connected.id is the "who is initiating from-our-side" identity).
 * - Privacy honoring: if AST_PRES_RESTRICTION → l="anonymous", n="".
 * - Fallback chain: connected.id missing → peer->fromuser → peer->name → "asterisk".
 * - URI-encoding: ast_uri_encode the user-part — required for # / ? / @ / etc.
 *   (the exten#did@peer form, e.g. 9999#622501314).
 * - Tag: NEVER add ;tag= manually — the sofia-sip nua layer auto-emits the From-tag
 *   as part of dialog state. */
static void sofia_build_from(struct sofia_pvt *pvt, char *buf, size_t len)
{
	char *lid_num = NULL, *lid_name = NULL;
	int lid_pres;
	char fromdomain[128];

	if (!buf || len < 1) {
		return;
	}
	buf[0] = '\0';

	/* Identity resolution + URI-encode + fromdomain delegated to
	 * sofia_resolve_identity (shared with sofia_add_rpid). Presentation source
	 * prefers pvt->callingpres over a connected.id direct read.
	 * sofia_uri_format_host bracket-wraps a raw IPv6 fromdomain per RFC 3261
	 * §19.1.2 (IPv4 + hostname passthrough; idempotent). */
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

	/* Privacy honoring (chan_sip parity): if presentation restricts the number,
	 * From identity becomes anonymous. */
	if ((lid_pres & AST_PRES_RESTRICTION) != AST_PRES_ALLOWED) {
		snprintf(buf, len, "\"Anonymous\" <sip:anonymous@%s>",
			sofia_uri_format_host(fromdomain, fbuf, sizeof(fbuf)));
		return;
	}

	/* usereqphone (chan_sip parity): RFC 3966 ;user=phone parameter on the From URI
	 * when peer has usereqphone set AND lid_num matches the digit-only pattern. */
	if (pvt && pvt->peer && pvt->peer->usereqphone && sofia_user_looks_like_phone(lid_num)) {
		snprintf(buf, len, "\"%s\" <sip:%s@%s;user=phone>", lid_name, lid_num,
			sofia_uri_format_host(fromdomain, fbuf, sizeof(fbuf)));
	} else {
		snprintf(buf, len, "\"%s\" <sip:%s@%s>", lid_name, lid_num,
			sofia_uri_format_host(fromdomain, fbuf, sizeof(fbuf)));
	}
}

/* Build outbound Contact header (chan_sip parity).
 *
 * - User-part fallback: connected.id.number.str → peer->fromuser → peer->name → "asterisk".
 * - Host:port from pvt->ourip (resolved by sofia_resolve_ourip).
 * - URI-encode the user-part (same rationale as sofia_build_from).
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

/* Single source of truth for the outbound identity-resolution chain, shared by
 * sofia_build_from and sofia_add_rpid (chan_sip parity). Reads
 * pvt->owner->connected.id, applies fallback chain (peer->fromuser → peer->name →
 * "asterisk"), URI-encodes user-part, resolves fromdomain (peer->fromdomain →
 * ourip host → sofia_cfg.realm → "gabpbx").
 *
 * On entry: out-pointer params receive pointers into the helper's thread-local
 * scratch (caller copies before the next call); fromdomain_buf is caller-provided.
 * Returns: 0 on success, -1 on no-identity-available.
 *
 * Thread-local scratch is safe because each outbound INVITE site runs to
 * completion on the same thread before another can re-enter.
 *
 * Presentation source: prefers pvt->callingpres if non-zero; falls back to
 * ast_party_id_presentation(connected.id). */
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
		/* cid bundle (chan_sip parity, dialog-inheritance): peer->cid_num is the
		 * base/default when channel connected.id is empty; channel CID via dialplan
		 * CALLERID() overrides it when set. Fallback chain:
		 * connected.id → peer->cid_num → peer->fromuser → peer->name → "asterisk". */
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
	/* cid bundle (chan_sip parity): peer->cid_name fallback before lid_num_src
	 * copy (dialog-inheritance for the cid_name field). */
	if (ast_strlen_zero(lid_name_src) && pvt && pvt->peer
			&& !ast_strlen_zero(pvt->peer->cid_name)) {
		lid_name_src = pvt->peer->cid_name;
	}
	if (ast_strlen_zero(lid_name_src)) {
		lid_name_src = lid_num_src;
	}

	ast_uri_encode(lid_num_src, lid_num_buf, sizeof(lid_num_buf), 0);
	ast_copy_string(lid_name_buf, lid_name_src, sizeof(lid_name_buf));
	/* The display name is stamped verbatim inside a quoted-string by the From /
	 * RPID / PAI builders; strip any character that would break that quoted-string
	 * so a hostile or malformed caller name can never make the outbound request
	 * unparseable. */
	sofia_quoted_name_sanitize(lid_name_buf);

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

/* Outbound RPID/PAI emitter with Privacy: id alongside on AST_PRES_RESTRICTION
 * (chan_sip parity; Privacy header per RFC 3325 §9.3 / RFC 3323).
 *
 * Gated on pvt->peer->sendrpid: 0=no emit, 1=PAI emit, 2=RPID emit.
 * Reads identity via sofia_resolve_identity.
 *
 * PAI branch (sendrpid=1): "P-Asserted-Identity: <sip:user@host>" with anonymous
 * fallback "<sip:anonymous@anonymous.invalid>" on AST_PRES_RESTRICTION, which also
 * emits "Privacy: id" per RFC 3325 §9.3.
 *
 * RPID branch (sendrpid=2): "Remote-Party-ID: \"name\" <sip:user@host>;
 * party=calling/called;privacy=full|off;screen=yes|no" (mapping table below). When
 * privacy=full, also emits "Privacy: id" (RFC 3323).
 *
 * On entry: pvt non-NULL; header_buf points to a writable buffer of header_len
 * bytes (recommend >=512 for combined RPID + Privacy).
 * On exit: header_buf holds the CRLF-separated header(s); empty on no emit.
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
		/* PAI branch (chan_sip parity) */
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

	/* mode == 2: RPID branch — mapping table (chan_sip parity) */
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

/* Maps AST_REDIRECTING_REASON_* enum to a Diversion ;reason= string per RFC 5806
 * §4.4 (chan_sip parity). AST_REDIRECTING_REASON_CALL_FWD_DTE deliberately maps to
 * "unknown" — DTE forwarding has no canonical Diversion reason. */
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

/* Reverse of sofia_reason_code_to_str — Diversion ;reason= param string to enum.
 * Used by the sofia_change_redirecting_info inbound parser. */
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

/* Outbound Diversion header emitter (chan_sip parity; privacy=full|off param).
 *
 * Triggered when pvt->owner->redirecting.from.number is set (call-forward chain
 * from B-side reaches chan_sofia outbound). Emits "Diversion" per RFC 5806 with
 * reason from sofia_reason_code_to_str + privacy parameter derived from
 * AST_PRES_RESTRICTION on the redirecting.from presentation.
 *
 * forceddiversion: if the peer sets forceddiversion=<DID>, the diverting number is
 * OVERRIDDEN with that trunk-owned DID (privacy forced off) so a downstream carrier
 * validates the forwarded call against a number it provisions for this trunk,
 * instead of the relayed redirecting number. Emission still requires a redirect
 * indication (a redirecting-from number OR an explicit REDIRECTING(reason)); a plain
 * non-forwarded call never gets a Diversion. When forceddiversion is empty the
 * behaviour is the legacy data-driven path.
 *
 * On entry: pvt non-NULL; header_buf points to a writable buffer of len bytes.
 * On exit: header_buf holds "Diversion: <value>\r\n" or empty.
 * Returns: 0 on no-emit, 1 on emit. */
static int sofia_add_diversion(struct sofia_pvt *pvt, char *header_buf, size_t header_len)
{
	const char *diverting_number;
	const char *diverting_name = NULL;
	const char *reason;
	const char *privacy_str;
	const char *forced = NULL;
	char fromhost[128];
	int redir_pres;
	int have_redirect;

	if (!header_buf || header_len < 2) {
		return 0;
	}
	header_buf[0] = '\0';

	if (!pvt || !pvt->owner) {
		return 0;
	}

	diverting_number = pvt->owner->redirecting.from.number.str;
	have_redirect = pvt->owner->redirecting.from.number.valid
			&& !ast_strlen_zero(diverting_number);

	/* forceddiversion: when the peer configures a forced redirecting DID, present
	 * THAT trunk-owned number as the diverting party per RFC 5806 — a number the
	 * carrier can validate — instead of whatever the channel's redirecting chain (or
	 * an inbound Diversion) carried. The caller holds pvt->peer->lock across this
	 * whole builder block, so reading the peer stringfield here is reload-UAF-safe
	 * (same lock span as fromdomain below). */
	if (pvt->peer && !ast_strlen_zero(pvt->peer->forceddiversion)) {
		forced = pvt->peer->forceddiversion;
	}

	if (forced) {
		if (!have_redirect
				&& pvt->owner->redirecting.reason == AST_REDIRECTING_REASON_UNKNOWN) {
			/* No redirect marker at all -> direct call, not a desvio. Never
			 * stamp a Diversion on a call that was not forwarded. */
			return 0;
		}
		diverting_number = forced;
		diverting_name = NULL;   /* the configured DID owns no display name */
	} else {
		if (!have_redirect) {
			return 0;
		}
		diverting_name = (pvt->owner->redirecting.from.name.valid
				&& !ast_strlen_zero(pvt->owner->redirecting.from.name.str))
			? pvt->owner->redirecting.from.name.str : NULL;
	}

	/* reason from the channel's redirecting state; a forced diversion with no
	 * explicit reason defaults to unconditional (the desvio default). */
	if (forced && pvt->owner->redirecting.reason == AST_REDIRECTING_REASON_UNKNOWN) {
		reason = "unconditional";
	} else {
		reason = sofia_reason_code_to_str(pvt->owner->redirecting.reason);
	}

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

	/* privacy: for a forced trunk-owned DID we WANT the carrier to see it
	 * (privacy=off) — an anonymous diversion DID defeats the very validation
	 * we are trying to satisfy. For the relayed case, derive from the
	 * redirecting party's presentation (R11-revised: SEPARATE identity from
	 * pvt->callingpres, the outbound caller's presentation). */
	if (forced) {
		privacy_str = "off";
	} else {
		redir_pres = ast_party_id_presentation(&pvt->owner->redirecting.from);
		privacy_str = ((redir_pres & AST_PRES_RESTRICTION) != AST_PRES_ALLOWED) ? "full" : "off";
	}

	/* Sanitize the diverting party before stamping it into the header. The relayed
	 * name/number originate from the inbound-parsed redirecting party
	 * (owner->redirecting.from.*). ast_uri_encode neutralizes the header-injection
	 * vector (CR/LF, and the chars outside the URI-allowed set) on the number, and
	 * sofia_quoted_name_sanitize strips '"' / '\\' / control chars from the display
	 * name so it cannot break out of its quoted-string. This is exactly what the
	 * From / RPID / PAI builders already do (sofia_resolve_identity), so the
	 * diverting party is now handled with the same safety. The forced DID is
	 * operator config (a digit DID — encoding is a no-op), so this is uniformly
	 * safe to apply. */
	char dnum_enc[256];
	char dname_san[256];
	ast_uri_encode(diverting_number, dnum_enc, sizeof(dnum_enc), 0);
	diverting_number = dnum_enc;
	if (!ast_strlen_zero(diverting_name)) {
		ast_copy_string(dname_san, diverting_name, sizeof(dname_san));
		sofia_quoted_name_sanitize(dname_san);
		diverting_name = dname_san;
	}

	if (ast_strlen_zero(diverting_name)) {
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

/* Detect Privacy: id header per RFC 3323 §4.2 (chan_sip parity). Uses sofia-sip
 * native sip->sip_privacy; priv_values is a NULL-terminated msg_param_t array of
 * priv-value tokens; "id" forces caller-id restriction regardless of PAI/RPID URI
 * form. Returns 1 if Privacy: id present, 0 otherwise. */
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

/* Inbound P-Asserted-Identity parser (chan_sip parity).
 *
 * Trust-gated on peer->trustrpid. Walks sip->sip_unknown for "P-Asserted-Identity"
 * by name (robust across sofia-sip versions, no sip_extra.h class-init dependency).
 *
 * Anonymous detection: PAI URI starting "sip:anonymous@anonymous.invalid" forces
 * AST_PRES_PROHIB_USER_NUMBER_NOT_SCREENED. Privacy: id forces the same
 * presentation regardless of PAI URI form.
 *
 * Updates pvt->cid_num + pvt->cid_name + pvt->callingpres; if pvt->owner is already
 * bound, also updates the channel. Returns 1 on update, 0 on no-update or no-PAI. */
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

	/* Format expected: ["display"] <sip:user@host>[;params]. Inline parser —
	 * chan_sip's get_name_and_number is not exposed across modules. This simpler
	 * form covers RFC 3325 §9.1. */
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

/* Inbound Remote-Party-ID parser (chan_sip parity).
 *
 * Trust-gated on peer->trustrpid. Walks sip->sip_unknown for "Remote-Party-ID";
 * if absent, falls back to sofia_get_pai.
 *
 * Parses RPID format: [display-name] LAQUOT addr-spec RAQUOT *(SEMI rpi-token) with
 * ;privacy= + ;screen= mapping. Privacy: id detection same as sofia_get_pai. */
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

		/* Mapping table (chan_sip parity) */
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

	/* Privacy: id forces restriction regardless of RPID ;privacy= form. */
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

/* Inbound Diversion header parser + apply to pvt->owner->redirecting (chan_sip
 * parity).
 *
 * Walks sip->sip_unknown for "Diversion" by name (robust across sofia-sip versions,
 * no sip_extra.h class-init dependency). Extracts redirecting-from name + URI
 * user-part + ;reason= parameter, updates pvt->owner->redirecting struct + dialplan
 * variables __SIPREDIRECTREASON / __SIPRDNISDOMAIN.
 *
 * No trust-gating — Diversion is structural metadata; operator dialplan decides
 * trust via the dialplan variables.
 *
 * On entry: pvt->owner expected non-NULL (caller checks).
 * Returns: 1 on update applied, 0 on no-Diversion-header. */
static int sofia_change_redirecting_info(struct sofia_pvt *pvt, struct ast_channel *owner, sip_t const *sip)
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

	if (!pvt || !owner || !sip) {
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

	/* Extract URI from <...> (chan_sip parity) */
	uri = strchr(tmp, '<');
	if (!uri) {
		return 0;
	}
	uri++;
	end = strchr(uri, '>');
	if (end) {
		*end = '\0';
	}

	/* Split off ;params (chan_sip parity) before scheme strip + user@domain split. */
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
			/* Strip enclosing quotes if present (chan_sip parity). */
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

	/* Apply to owner->redirecting (chan_sip parity). ast_free of existing strs
	 * BEFORE ast_strdup — prevents leak. Hold the CHANNEL lock for
	 * the mutation: the channel thread reads redirecting.from.*.str, and freeing
	 * /reallocating it here without the lock is a data-race/UAF. All callers pass
	 * an owner that is not under pvt->lock (8688 fresh inbound chan, REFER and the
	 * 2xx path snapshot+unlock first), so locking the channel here cannot invert
	 * channel->pvt; channel locks are recursive so pbx_builtin_setvar_helper's
	 * own lock nests safely. */
	ast_channel_lock(owner);
	if (!ast_strlen_zero(redir_num)) {
		ast_free(owner->redirecting.from.number.str);
		owner->redirecting.from.number.str = ast_strdup(redir_num);
		owner->redirecting.from.number.valid = 1;
	}
	if (!ast_strlen_zero(redir_name)) {
		ast_free(owner->redirecting.from.name.str);
		owner->redirecting.from.name.str = ast_strdup(redir_name);
		owner->redirecting.from.name.valid = 1;
	}
	owner->redirecting.reason = reason;

	/* Dialplan variables (chan_sip parity). */
	if (!ast_strlen_zero(reason_str)) {
		pbx_builtin_setvar_helper(owner, "__SIPREDIRECTREASON", reason_str);
	}
	if (!ast_strlen_zero(domain)) {
		pbx_builtin_setvar_helper(owner, "__SIPRDNISDOMAIN", domain);
	}
	ast_channel_unlock(owner);

	return 1;
}

/* Centralized call-counter helper (chan_sip parity).
 *
 * Event semantics:
 * - SOFIA_INC_CALL_LIMIT (inbound INVITE post-auth): bumps inUse only.
 * - SOFIA_INC_CALL_RINGING (outbound dial at sofia_call entry): bumps BOTH
 *   inUse + inRinging atomically.
 * - SOFIA_DEC_CALL_LIMIT (hangup — sofia_hangup, nua_i_bye, nua_r_bye,
 *   sofia_pvt_destructor catchall): decrements inUse if call_inc_done set.
 * - SOFIA_DEC_CALL_RINGING (outbound 200 OK at nua_r_invite): decrements
 *   inRinging if ring_inc_done set (call_inc_done stays — call still in the
 *   inUse pool until hangup).
 *
 * Lock ordering: pvt->lock then ao2_lock(peer). Idempotency via
 * pvt->call_inc_done + ring_inc_done.
 *
 * Emits PeerStatus AMI events: CallLimitExceeded on rejection +
 * CallCountUpdated on increment. TuCloudPBXName + Accountcode placeholders.
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

	/* NOTE: no early-return when call_limit==0 && busy_level==0. The inUse/inRinging
	 * counters must be maintained for EVERY peer so sofia_devicestate can report
	 * concrete RINGING/INUSE/NOT_INUSE (BLF). The call-limit *rejection* and the
	 * PeerStatus AMI emit below stay gated on call_limit/busy_level, so behaviour for
	 * limited peers is unchanged. */

	switch (event) {
	case SOFIA_INC_CALL_LIMIT:
	case SOFIA_INC_CALL_RINGING:
		if (peer->call_limit > 0 && peer->inUse >= peer->call_limit) {
			ast_log(LOG_NOTICE, "Call %s peer '%s' rejected due to usage limit of %d\n",
				(event == SOFIA_INC_CALL_RINGING) ? "to" : "from",
				peer->name, peer->call_limit);

			/* Emit peer->accountcode actual value (chan_sip parity). */
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

		/* Emit peer->accountcode actual value (chan_sip parity).
		 * Gated on call_limit/busy_level: this AMI emit previously only ran for
		 * limited peers (the early-return guarded it); keep it that way now that the
		 * early-return is gone, so non-limit peers don't newly emit it. */
		if (peer->call_limit || peer->busy_level) {
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
		}
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

	/* BLF/presence (chan_sip parity): a call-counter transition changed this peer's
	 * device state — fire a devstate change so the SIP/<peer> hint recomputes and the
	 * watchers' NOTIFYs go out. All locks are released above; snapshot the name under
	 * the peer lock. The call-limit reject path already returned -1, so reaching here
	 * is always a real (or idempotent) INC/DEC transition. */
	{
		char l_name[80];
		ao2_lock(peer);
		ast_copy_string(l_name, peer->name, sizeof(l_name));
		ao2_unlock(peer);
		ast_devstate_changed(AST_DEVICE_UNKNOWN, AST_DEVSTATE_CACHABLE, "SIP/%s", l_name);
	}
	return 0;
}

/* Normalize an outboundproxy spec into a canonical Route URI. Resolves inheritance
 * (peer overrides [general]) + 3-form acceptance (bare host / host:port / full
 * sip:URI) + defensive ;lr append.
 *
 * On entry: buf points to a writable buffer of at least len bytes.
 * On exit: buf is empty if no proxy applies; else holds the canonical
 * "sip:HOST[:PORT];lr" or "sips:..." form.
 *
 * Caller pattern: TAG_IF(buf[0], NUTAG_INITIAL_ROUTE_STR(buf))
 *
 * Lock: caller MUST hold peer->lock across this call. A peer ao2 ref does NOT
 * prevent concurrent mutation: the reload writer (on sofia_thread) re-sets
 * peer->outboundproxy via ast_string_field_set, which FREES the old stringfield
 * pool when a value grows — racing a lock-free read here even while a ref is held.
 * Of the two callers, only sofia_request_call races the reload (PBX dialing thread)
 * and now holds peer->lock; sofia_do_register runs once at module load (before any
 * reload can be dispatched to sofia_thread), so it is safe without the lock. */
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

	/* Inheritance chain: peer override > [general] default > none */
	if (!ast_strlen_zero(peer->outboundproxy)) {
		spec = peer->outboundproxy;
	} else if (!ast_strlen_zero(sofia_cfg.outboundproxy)) {
		spec = sofia_cfg.outboundproxy;
	} else {
		return;
	}

	/* Form detection */
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

/* Build + send MWI NOTIFY to a peer's active subscriber. Aggregates inbox counts
 * across all peer->mailboxes; emits a single Messages-Waiting + Message-Account +
 * Voice-Message body per RFC 3842. Caller MUST own a peer ref AND must have verified
 * peer->mwi_subscription_handle is non-NULL before calling.
 *
 * Lock discipline: takes peer->lock internally for the mailbox traversal + field
 * reads; releases before nua_notify. Caller must NOT hold peer->lock at entry.
 *
 * Runs on sofia_thread. */
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
	/* Snapshot the mailbox specs (mb->mailbox/context are fixed 80-byte arrays)
	 * under peer->lock, then count OUTSIDE the lock: ast_app_inboxcount2 dispatches
	 * to the voicemail backend (IMAP/ODBC network I/O or a filesystem dir-scan) of
	 * unbounded latency, and holding peer->lock across it stalls every other
	 * peer->lock holder for that peer. Matches the snapshot-first idiom used
	 * elsewhere; the MWI 1-cap means the per-peer mailbox count is small. */
	{
		char mboxes[32][160];
		int nmb = 0, i;
		AST_LIST_TRAVERSE(&peer->mailboxes, mb, list) {
			if (nmb >= (int) ARRAY_LEN(mboxes)) {
				break;
			}
			snprintf(mboxes[nmb], sizeof(mboxes[nmb]), "%s@%s", mb->mailbox, mb->context);
			nmb++;
		}
		/* NOTE: fromdomain copies the POINTER (aliases peer->fromdomain's pool),
		 * dereferenced after the unlock — safe because every caller runs on
		 * sofia_thread, serialised against the reload writer (same thread) that
		 * would free the old stringfield pool. */
		fromdomain = !ast_strlen_zero(peer->fromdomain) ? peer->fromdomain : sofia_cfg.realm;
		ast_mutex_unlock(&peer->lock);

		for (i = 0; i < nmb; i++) {
			int new_msgs = 0, old_msgs = 0, urgent_msgs = 0;
			if (ast_app_inboxcount2(mboxes[i], &urgent_msgs, &new_msgs, &old_msgs) == 0) {
				total_new    += new_msgs;
				total_old    += old_msgs;
				total_urgent += urgent_msgs;
			}
		}
	}

	body = ast_str_create(256);
	if (!body) {
		ast_log(LOG_WARNING, "Sofia MWI: ast_str_create failed for peer %s\n", peer->name);
		return;
	}

	vmexten    = !ast_strlen_zero(sofia_cfg.vmexten) ? sofia_cfg.vmexten : "asterisk";
	notifymime = !ast_strlen_zero(sofia_cfg.notifymime) ? sofia_cfg.notifymime
		: "application/simple-message-summary";

	/* RFC 3842 body (chan_sip parity). */
	ast_str_append(&body, 0, "Messages-Waiting: %s\r\n",
		total_new ? "yes" : "no");
	ast_str_append(&body, 0, "Message-Account: sip:%s@%s\r\n",
		vmexten, fromdomain);
	/* buggymwi (chan_sip parity): some SIP stacks reject Voice-Message lines
	 * containing the "(0/0)" tally suffix. Per-peer buggymwi=yes omits the suffix
	 * as a workaround. Default (suffix included) is RFC 3842-compliant. */
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

/* MWI SUBSCRIBE handler. Accepts in-dialog SUBSCRIBE Event:message-summary,
 * identifies the mailbox-owner peer via the To URI user-part, enforces a
 * 1-subscription-per-peer cap by terminating any existing subscription before
 * assigning the new nh.
 *
 * Uses the nua_notifier API — sofia-sip handles dialog state + Subscription-State
 * auto-emission per RFC 6665.
 *
 * Lock-ordering discipline: peer->lock is held ONLY while mutating peer fields
 * (mailbox-empty check, swap mwi_subscription_handle, capture old handle to local).
 * All nua_* ops happen AFTER releasing peer->lock to avoid nesting peer->lock under
 * sofia-sip internal locks.
 *
 * Runs on sofia_thread. */
/* Reap a SUBSCRIBE server handle on a NON-ACCEPTED path (final reject OR 401
 * challenge). sofia-sip NEVER auto-reaps an APPL_METHOD SUBSCRIBE handle; sofia-sip's
 * own nua_publish.c documents the analog: an incoming request not associated with an
 * existing dialog creates a new handle, and "if the handle nh is not bound, you should
 * probably destroy it after responding." A 401 establishes no dialog, so the
 * challenged handle is orphaned and the authed re-SUBSCRIBE arrives as a FRESH handle —
 * destroying the 401 handle is safe. Detach any hmagic first (UAF guard), then destroy.
 * Accept paths (nua_notifier) own the handle and must NOT call this. */
static void sofia_subscribe_reject_reap(nua_handle_t *nh)
{
	/* Reap ONLY a fresh, UNBOUND APPL_METHOD SUBSCRIBE handle. An in-dialog re-SUBSCRIBE can arrive
	 * on an EXISTING handle BOUND (hmagic non-NULL) to a sofia_pvt or a presence/MWI sub — that
	 * handle is OWNED by its object and must NOT be destroyed here: a bind(NULL)+destroy would both
	 * detach the owner's hmagic AND free a handle the owner still references → UAF the
	 * call/subscription. nua_publish.c:484: "IF THE HANDLE nh IS NOT BOUND, you should probably
	 * destroy it." (Codex v1 NO-GO: bound-handle guard.) For an unbound handle (magic NULL) there is
	 * no owner and no stale hmagic, so a plain destroy is safe — no bind(NULL) needed. */
	if (!nh || nua_handle_magic(nh) != NULL) {
		return;
	}
	nua_handle_destroy(nh);
}

static void sofia_process_mwi_subscribe(nua_t *nua, nua_handle_t *nh,
		struct sofia_pvt *op, sip_t const *sip, tagi_t tags[])
{
	struct sofia_peer *peer;
	const char *to_user;
	nua_handle_t *old_nh = NULL;

	/* To URI user-part identifies the mailbox-owning peer */
	if (!sip || !sip->sip_to || !sip->sip_to->a_url || !sip->sip_to->a_url->url_user) {
		nua_respond(nh, SIP_404_NOT_FOUND, NUTAG_WITH_THIS(nua), TAG_END());
		sofia_subscribe_reject_reap(nh);	/* reap the challenge handle */
		return;
	}
	to_user = sip->sip_to->a_url->url_user;

	peer = sofia_find_peer(to_user);
	if (!peer) {
		if (sofia_cfg.alwaysauthreject) {
			/* sofia_get_realm_for_dialog (chan_sip get_realm parity). */
			char realm_buf[MAXHOSTNAMELEN];
			const char *realm = sofia_get_realm_for_dialog(sip, realm_buf, sizeof(realm_buf));
			ast_log(LOG_NOTICE, "Sofia MWI: SUBSCRIBE for unknown peer '%s' — 401 challenge (alwaysauthreject)\n", to_user);
			sofia_send_auth_challenge(nua, nh, sip, realm, "SUBSCRIBE", "UnknownPeer");
		} else {
			ast_log(LOG_NOTICE, "Sofia MWI: SUBSCRIBE for unknown peer '%s' — 404\n", to_user);
			nua_respond(nh, SIP_404_NOT_FOUND, NUTAG_WITH_THIS(nua), TAG_END());
		}
		sofia_subscribe_reject_reap(nh);	/* reap on both the 401-challenge and the 404 branch */
		return;
	}

	/* allowsubscribe per-peer gate (chan_sip parity): when peer->allowsubscribe is
	 * FALSE, reject with the verbatim "403 Forbidden (policy)" string (operator
	 * scripts pattern-match the exact text including parens). */
	if (!peer->allowsubscribe) {
		ast_log(LOG_NOTICE,
			"Sofia MWI: SUBSCRIBE for peer '%s' rejected by allowsubscribe=no — 403\n",
			peer->name);
		nua_respond(nh, 403, "Forbidden (policy)",
			NUTAG_WITH_THIS(nua), TAG_END());
		sofia_emit_subscribe_rejected(sip, peer->name, "message-summary",
			"AllowSubscribeClosed");
		ao2_ref(peer, -1);
		sofia_subscribe_reject_reap(nh);	/* reap the challenge handle */
		return;
	}

	/* Digest-authenticate the MWI SUBSCRIBE for a credentialed peer (parity with
	 * REGISTER/INVITE). Without this a known peer's mailbox could be subscribed by
	 * anyone — leaking voicemail counts and delivering unsolicited NOTIFYs. Gate
	 * only when the peer actually has a credential; credential-less peers stay open
	 * exactly as the no-secret REGISTER accept path. The verifier emits the 401
	 * challenge / 4xx itself (caller just returns on any result != OK). */
	if (!ast_strlen_zero(peer->secret) || !ast_strlen_zero(peer->md5secret)) {
		char realm_buf[MAXHOSTNAMELEN];
		const char *realm = sofia_get_realm_for_dialog(sip, realm_buf, sizeof(realm_buf));
		enum sofia_auth_result auth_res = sofia_verify_digest_auth(peer,
			nua, nh, sip, sip->sip_authorization, "SUBSCRIBE", realm);
		if (auth_res != SOFIA_AUTH_OK) {
			ao2_ref(peer, -1);
			sofia_subscribe_reject_reap(nh);	/* reap the 401/4xx challenge handle */
			return;
		}
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
		sofia_subscribe_reject_reap(nh);	/* reap the challenge handle */
		return;
	}

	/* 1-cap: capture existing handle (if any) for terminate-old; assign new. */
	old_nh = peer->mwi_subscription_handle;
	peer->mwi_subscription_handle = nh;

	ast_mutex_unlock(&peer->lock);

	/* All peer-state mutations done; safe to do nua_* ops without peer->lock. */
	/* Only terminate+destroy a DIFFERENT prior handle. On an in-dialog refresh
	 * old_nh == nh (same handle), and destroying it here would tear down the very
	 * subscription we are about to use (self-UAF + broken refresh). */
	if (old_nh && old_nh != nh) {
		nua_notify(old_nh,
			SIPTAG_EVENT_STR("message-summary"),
			SIPTAG_SUBSCRIPTION_STATE_STR("terminated;reason=deactivated"),
			TAG_END());
		/* Detach hmagic from the old handle before destroying it.  We are
		 * already on sofia_thread, so the destroy is effectively serialised
		 * against event dispatch — but the bind(NULL) is still the right
		 * discipline: a late event arriving for old_nh between the destroy
		 * dispatch and its execution would otherwise reach
		 * sofia_event_callback with magic = peer (peer is still alive — we
		 * just swapped peer->mwi_subscription_handle to the new nh) and
		 * the callback would treat the stale subscription as if it were
		 * current.  The nh-mismatch checks in the callback (peer->
		 * mwi_subscription_handle != old_nh) catch this in practice, but
		 * detaching the magic up-front makes the invariant explicit and
		 * mirrors the discipline used by the peer destructor. */
		nua_handle_bind(old_nh, NULL);
		nua_handle_destroy(old_nh);
	}

	/* Refresh on the SAME handle — sofia-sip's notifier already auto-answers the
	 * re-SUBSCRIBE (202 + re-armed expiry), so we must NOT re-issue nua_notifier on
	 * it (and we already skipped the destroy above); just push a fresh MWI NOTIFY
	 * body for the refreshed subscription. */
	if (old_nh == nh) {
		transmit_mwi_notify_for_peer(peer);
		if (sofia_debug) {
			ast_verbose("Sofia MWI: SUBSCRIBE refresh for peer '%s'\n", peer->name);
		}
		ao2_ref(peer, -1);
		return;
	}

	/* Bind nh as nua_notifier — sofia-sip opens the server-side dialog +
	 * auto-emits Subscription-State. The RFC 6665 §4.4.1 initial NOTIFY body
	 * follows via transmit_mwi_notify_for_peer. */
	{
		char expires_buf[16];
		int expiry = sofia_cfg.mwi_expiry > 0 ? sofia_cfg.mwi_expiry : 3600;
		snprintf(expires_buf, sizeof(expires_buf), "%d", expiry);
		nua_notifier(nh,
			SIPTAG_EVENT_STR("message-summary"),
			SIPTAG_EXPIRES_STR(expires_buf),
			TAG_END());
	}

	/* RFC 6665 §4.4.1 — initial NOTIFY immediately after accepting SUBSCRIBE.
	 * Already on sofia_thread; transmit takes peer->lock internally for mailbox
	 * traversal (we released peer->lock above). */
	transmit_mwi_notify_for_peer(peer);

	if (sofia_debug) {
		ast_verbose("Sofia MWI: SUBSCRIBE accepted for peer '%s'\n", peer->name);
	}

	ao2_ref(peer, -1);
	/* nh ownership: the peer->mwi_subscription_handle field holds the borrowed
	 * pointer; cleanup is via sofia_peer_destructor (cross-thread dispatch since
	 * the destructor may run off sofia_thread). */
}

/* =========================================================================
 *  Presence / BLF (dialog-info + presence) inbound SUBSCRIBE -> NOTIFY
 *
 *  Fills the hole left by the legacy auto-202 stub: a watcher (e.g. ext 210
 *  with a BLF key for 211) SUBSCRIBEs to Event: dialog / presence; we register
 *  a hint watcher with the gabpbx core (ast_extension_state_add_destroy — this
 *  is what makes `core show hints` count the Watcher) and push a NOTIFY with
 *  the watched extension's state every time it changes.
 *
 *  Lifecycle is owned by sofia-sip's notifier state machine (nua_notifier /
 *  NUTAG_SUBSTATE), exactly like the MWI path: the library manages the server
 *  dialog, Subscription-State, expiry, refresh re-SUBSCRIBE and the terminating
 *  NOTIFY — we never hand-roll timers the way chan_sip does.
 *
 *  Threading (concurrency doctrine): every nua_* call and every mutation of
 *  presence_subs / sub->* happens on sofia_thread. The core fires
 *  sofia_presence_state_cb on its device_state taskprocessor (no PBX locks
 *  held); that callback ONLY snapshots {state} + bumps a ref + marshals to
 *  sofia_thread via sofia_dispatch_to_root_thread. No new thread is created.
 *  This mirrors mwi_event_cb -> mwi_notify_callback verbatim.
 *
 *  Improvement over chan_sip: a detailed, subscription-scoped AMI event
 *  (SofiaPresenceState) is emitted on every NOTIFY push — chan_sip is silent on
 *  that plane and the core's generic ExtensionStatus carries no watcher
 *  dimension. ========================================================== */

#define MAX_PRESENCE_SUB_BUCKETS 1009		/* prime; one entry per active watcher dialog */
#define SOFIA_PRESENCE_DEFAULT_EXPIRY 3600	/* used when the SUBSCRIBE omits Expires */
#define SOFIA_PRESENCE_SWEEP_MS 5000		/* expiry-sweep timer interval (ms) */
#define SOFIA_PRESENCE_EXPIRY_GRACE 5		/* seconds past expires_at before a stale sub is swept */

enum sofia_sub_format {
	SOFIA_SUB_DIALOG_INFO = 0,	/* application/dialog-info+xml (BLF) */
	SOFIA_SUB_PIDF,			/* application/pidf+xml */
	SOFIA_SUB_XPIDF,		/* application/xpidf+xml (Polycom/MSN) */
	SOFIA_SUB_CPIM_PIDF,		/* application/cpim-pidf+xml */
};

/* One active watcher subscription. ao2-managed. Keyed by the LOGICAL pair
 * (watcher peer, watched exten, context) — NOT by nh — so a re-SUBSCRIBE on a
 * fresh dialog (phone reboot) REPLACES the prior subscription instead of leaking
 * a watcher, and an Expires:0 terminates it (MWI-style replace; sofia-sip does
 * not reliably reuse the handle for in-dialog refresh/unsub). Mutated only on
 * sofia_thread. */
struct sofia_presence_sub {
	char subkey[200];			/* "peername|exten|context" — container key */
	nua_handle_t *nh;			/* subscription dialog handle (NOT bound as hmagic;
						 * correlated via sofia_presence_find_by_nh) */
	char exten[AST_MAX_EXTENSION];		/* watched extension (To user) */
	char context[AST_MAX_CONTEXT];		/* hint lookup context */
	char entity[256];			/* watched resource URI: sip:exten@domain */
	char peername[80];			/* subscriber peer name (From user) for AMI */
	char watcher_addr[64];			/* subscriber source addr for AMI */
	char nat_proxy[128];			/* NUTAG_PROXY target (sip:src-ip:port) for NAT
						 * (force_rport/comedia) watchers — routes NOTIFY to the
						 * registered public source (SBC) not the private Contact,
						 * else every NOTIFY 408s. Empty for non-NAT peers. */
	char event[16];				/* "dialog" or "presence" (NOTIFY Event hdr) */
	enum sofia_sub_format format;		/* negotiated body type */
	int stateid;				/* ast_extension_state_add_destroy id (-1 = none) */
	int laststate;				/* last AST_EXTENSION_* pushed */
	uint32_t version;			/* monotonic dialog-info version= counter */
	int expires;				/* granted subscription lifetime (seconds) */
	time_t expires_at;			/* absolute expiry, for Subscription-State expires= */
	int terminated;				/* set on sofia_thread at teardown (idempotency) */
};

static struct ao2_container *presence_subs;	/* keyed by subkey; created in load_module */
static su_timer_t *presence_expiry_timer;	/* recurring sweep on sofia_thread (see load) */

/* dispatch carrier: state-change cb (device_state thread) -> sofia_thread */
struct sofia_presence_dispatch {
	struct sofia_presence_sub *sub;		/* +1 ref TRANSFERRED — callback drops */
	int state;				/* snapshot of AST_EXTENSION_* at fire time */
};

static int presence_sub_hash_fn(const void *obj, int flags)
{
	const struct sofia_presence_sub *sub = obj;	/* full sub or {.subkey} shim */
	return ast_str_hash(sub->subkey);
}

static int presence_sub_cmp_fn(void *obj, void *arg, int flags)
{
	struct sofia_presence_sub *sub = obj;
	struct sofia_presence_sub *match = arg;		/* {.subkey} shim */
	return strcmp(sub->subkey, match->subkey) ? 0 : (CMP_MATCH | CMP_STOP);
}

static void presence_sub_destructor(void *obj)
{
	/* Nothing to free: all fields are inline and the nua handle is destroyed
	 * explicitly on sofia_thread in sofia_presence_teardown (this destructor may
	 * run on any thread, so it must NOT touch nua_*). */
	(void) obj;
}

/* forward decls (mutual recursion: state_cb -> dispatch -> teardown -> state_cb fn-ptr) */
static int sofia_presence_state_cb(char *context, char *exten,
		enum ast_extension_states state, void *data);
static void sofia_presence_teardown(struct sofia_presence_sub *sub, int send_terminated);

/* State map (chan_sip parity). local_state: 0=open 1=inuse 2=closed. */
void sofia_presence_state_map(int state, const char **statestring,
		const char **pidfstate, const char **pidfnote, int *local_state)
{
	*statestring = "terminated";
	*pidfstate = "--";
	*pidfnote = "Ready";
	*local_state = 0;	/* NOTIFY_OPEN */

	switch (state) {
	case (AST_EXTENSION_RINGING | AST_EXTENSION_INUSE):
		*statestring = "early";  *local_state = 1; *pidfstate = "busy"; *pidfnote = "Ringing"; break;
	case AST_EXTENSION_RINGING:
		*statestring = "early";  *local_state = 1; *pidfstate = "busy"; *pidfnote = "Ringing"; break;
	case AST_EXTENSION_INUSE:
		*statestring = "confirmed"; *local_state = 1; *pidfstate = "busy"; *pidfnote = "On the phone"; break;
	case AST_EXTENSION_BUSY:
		*statestring = "confirmed"; *local_state = 2; *pidfstate = "busy"; *pidfnote = "On the phone"; break;
	case AST_EXTENSION_UNAVAILABLE:
		*statestring = "terminated"; *local_state = 2; *pidfstate = "away"; *pidfnote = "Unavailable"; break;
	case AST_EXTENSION_ONHOLD:
		*statestring = "confirmed"; *local_state = 2; *pidfstate = "busy"; *pidfnote = "On hold"; break;
	case AST_EXTENSION_NOT_INUSE:
	default:
		break;
	}
}

static const char *sofia_presence_mime(enum sofia_sub_format f)
{
	switch (f) {
	case SOFIA_SUB_DIALOG_INFO: return "application/dialog-info+xml";
	case SOFIA_SUB_PIDF:        return "application/pidf+xml";
	case SOFIA_SUB_XPIDF:       return "application/xpidf+xml";
	case SOFIA_SUB_CPIM_PIDF:   return "application/cpim-pidf+xml";
	}
	return "application/dialog-info+xml";
}

/* Build the NOTIFY body for sub->format (chan_sip parity) + the "all hinted
 * devices unavailable => offline" override. exten is XML-escaped. */
static void sofia_presence_build_body(struct ast_str **buf, const struct sofia_presence_sub *sub, int state)
{
	const char *statestring, *pidfstate, *pidfnote;
	int local_state;
	char hint[AST_MAX_EXTENSION];
	char exten_esc[AST_MAX_EXTENSION * 6];		/* *6: ast_xml_escape worst-case (&quot;) expansion */
	char entity_esc[sizeof(sub->entity) * 6];

	sofia_presence_state_map(state, &statestring, &pidfstate, &pidfnote, &local_state);

	/* If every hinted device is unregistered, override to offline (chan_sip parity).
	 * The override can ONLY flip an "open" (idle) presentation to "closed", so run
	 * the ast_get_hint (process-global contexts rdlock) + per-device scan ONLY when
	 * local_state is currently open — i.e. skip it for the in-use/closed states
	 * (INUSE/RINGING/BUSY/ONHOLD/UNAVAILABLE) where it can never change the result.
	 * This keeps the global lock + device scan off the in-call NOTIFY fan-out. */
	if (local_state == 0 && ast_get_hint(hint, sizeof(hint), NULL, 0, NULL, sub->context, sub->exten)) {
		char *h = hint, *one;
		int total = 0, unavail = 0;
		while ((one = strsep(&h, "&"))) {
			total++;
			if (ast_device_state(one) == AST_DEVICE_UNAVAILABLE) {
				unavail++;
			}
		}
		if (total > 0 && total == unavail) {
			local_state = 2;	/* closed */
			pidfstate = "away";
			pidfnote = "Not online";
		}
	}

	ast_xml_escape(sub->exten, exten_esc, sizeof(exten_esc));
	/* entity is built from the remote To header (sip:to_user@to_host) — escape it
	 * too before it goes into XML attributes/elements. */
	ast_xml_escape(sub->entity, entity_esc, sizeof(entity_esc));

	switch (sub->format) {
	case SOFIA_SUB_XPIDF:
	case SOFIA_SUB_CPIM_PIDF:
		ast_str_append(buf, 0,
			"<?xml version=\"1.0\"?>\n"
			"<!DOCTYPE presence PUBLIC \"-//IETF//DTD RFCxxxx XPIDF 1.0//EN\" \"xpidf.dtd\">\n"
			"<presence>\n");
		ast_str_append(buf, 0, "<presentity uri=\"%s;method=SUBSCRIBE\" />\n", entity_esc);
		ast_str_append(buf, 0, "<atom id=\"%s\">\n", exten_esc);
		ast_str_append(buf, 0, "<address uri=\"%s;user=ip\" priority=\"0.800000\">\n", entity_esc);
		ast_str_append(buf, 0, "<status status=\"%s\" />\n",
			(local_state == 0) ? "open" : (local_state == 1) ? "inuse" : "closed");
		ast_str_append(buf, 0, "<msnsubstatus substatus=\"%s\" />\n",
			(local_state == 0) ? "online" : (local_state == 1) ? "onthephone" : "offline");
		ast_str_append(buf, 0, "</address>\n</atom>\n</presence>\n");
		break;
	case SOFIA_SUB_PIDF:
		ast_str_append(buf, 0,
			"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n"
			"<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" \n"
			"xmlns:pp=\"urn:ietf:params:xml:ns:pidf:person\"\n"
			"xmlns:es=\"urn:ietf:params:xml:ns:pidf:rpid:status:rpid-status\"\n"
			"xmlns:ep=\"urn:ietf:params:xml:ns:pidf:rpid:rpid-person\"\n"
			"entity=\"%s\">\n", entity_esc);
		ast_str_append(buf, 0, "<pp:person><status>\n");
		if (pidfstate[0] != '-') {
			ast_str_append(buf, 0, "<ep:activities><ep:%s/></ep:activities>\n", pidfstate);
		}
		ast_str_append(buf, 0, "</status></pp:person>\n");
		ast_str_append(buf, 0, "<note>%s</note>\n", pidfnote);
		ast_str_append(buf, 0, "<tuple id=\"%s\">\n", exten_esc);
		ast_str_append(buf, 0, "<contact priority=\"1\">%s</contact>\n", entity_esc);
		if (pidfstate[0] == 'b') {
			ast_str_append(buf, 0, "<status><basic>open</basic></status>\n");
		} else {
			ast_str_append(buf, 0, "<status><basic>%s</basic></status>\n",
				(local_state != 2) ? "open" : "closed");
		}
		ast_str_append(buf, 0, "</tuple>\n</presence>\n");
		break;
	case SOFIA_SUB_DIALOG_INFO:
	default:
		ast_str_append(buf, 0, "<?xml version=\"1.0\"?>\n");
		ast_str_append(buf, 0,
			"<dialog-info xmlns=\"urn:ietf:params:xml:ns:dialog-info\" "
			"version=\"%u\" state=\"full\" entity=\"%s\">\n",
			sub->version, entity_esc);
		if (state & AST_EXTENSION_RINGING) {
			ast_str_append(buf, 0, "<dialog id=\"%s\" direction=\"recipient\">\n", exten_esc);
		} else {
			ast_str_append(buf, 0, "<dialog id=\"%s\">\n", exten_esc);
		}
		ast_str_append(buf, 0, "<state>%s</state>\n", statestring);
		if (state == AST_EXTENSION_ONHOLD) {
			ast_str_append(buf, 0,
				"<local>\n<target uri=\"%s\">\n"
				"<param pname=\"+sip.rendering\" pvalue=\"no\"/>\n"
				"</target>\n</local>\n", entity_esc);
		}
		ast_str_append(buf, 0, "</dialog>\n</dialog-info>\n");
		break;
	}
}

/* Emit one NOTIFY for sub at the given state, plus the detailed AMI event.
 * Runs on sofia_thread. terminate=1 sets Subscription-State: terminated (final
 * NOTIFY); otherwise sofia-sip auto-fills active;expires per the notifier. */
static void sofia_presence_emit_notify(struct sofia_presence_sub *sub, int state, int terminate)
{
	struct ast_str *body;
	const char *statestring, *pidfstate, *pidfnote, *mime;
	const char *prevstr, *curstr;
	int local_state;

	if (!sub || !sub->nh) {
		return;
	}
	body = ast_str_create(640);
	if (!body) {
		return;
	}

	prevstr = ast_extension_state2str(sub->laststate);
	sub->version++;
	sub->laststate = state;

	mime = sofia_presence_mime(sub->format);
	sofia_presence_build_body(&body, sub, state);

	/* Subscription-State is MANDATORY per RFC 6665 §8.2.1. We compose it
	 * explicitly (active;expires=N / terminated) — with the nua_respond+nua_notify
	 * server idiom sofia-sip does not auto-add it. NUTAG_SUBSTATE keeps sofia-sip's
	 * own subscription-usage state machine (expiry timer, nua_r_notify on timeout)
	 * in sync. */
	{
		char ss[64];
		int remaining = (int) (sub->expires_at - time(NULL));
		if (remaining < 0) {
			remaining = 0;
		}
		if (terminate) {
			ast_copy_string(ss, "terminated;reason=timeout", sizeof(ss));
		} else {
			snprintf(ss, sizeof(ss), "active;expires=%d", remaining);
		}
		nua_notify(sub->nh,
			SIPTAG_EVENT_STR(sub->event),
			NUTAG_SUBSTATE(terminate ? nua_substate_terminated : nua_substate_active),
			SIPTAG_SUBSCRIPTION_STATE_STR(ss),
			SIPTAG_CONTENT_TYPE_STR(mime),
			SIPTAG_PAYLOAD_STR(ast_str_buffer(body)),
			/* Route the NOTIFY to the NAT-learned source (the SBC) for
			 * force_rport/comedia watchers — no-op (empty) for non-NAT peers, where
			 * sofia-sip uses the normal dialog target. */
			TAG_IF(sub->nat_proxy[0], NUTAG_PROXY(sub->nat_proxy)),
			TAG_END());
	}

	ast_free(body);

	/* Subscription-scoped AMI event — richer than chan_sip (silent) and than the
	 * core's watcher-less ExtensionStatus. */
	sofia_presence_state_map(state, &statestring, &pidfstate, &pidfnote, &local_state);
	curstr = ast_extension_state2str(state);
	manager_event(EVENT_FLAG_CALL, "SofiaPresenceState",
		"Watcher: SIP/%s\r\n"
		"WatcherAddr: %s\r\n"
		"Exten: %s\r\n"
		"Context: %s\r\n"
		"PrevState: %s\r\n"
		"State: %s\r\n"
		"StateCode: %d\r\n"
		"DialogState: %s\r\n"
		"Format: %s\r\n"
		"SubscriptionState: %s\r\n"
		"Version: %u\r\n",
		sub->peername, sub->watcher_addr, sub->exten, sub->context,
		prevstr, curstr, state, statestring, mime,
		terminate ? "terminated" : "active", sub->version);

	if (sofia_debug) {
		ast_verbose("Sofia presence: NOTIFY %s state=%s watcher=SIP/%s exten=%s@%s v=%u\n",
			mime, curstr, sub->peername, sub->exten, sub->context, sub->version);
	}
}

/* sofia_thread: drop a watcher subscription. Idempotent. If send_terminated,
 * emit a final NOTIFY with Subscription-State: terminated before destroying. */
static void sofia_presence_teardown(struct sofia_presence_sub *sub, int send_terminated)
{
	if (!sub || sub->terminated) {
		return;
	}
	sub->terminated = 1;
	if (send_terminated && sub->nh) {
		struct ast_str *body = ast_str_create(640);
		if (body) {
			sub->version++;
			sofia_presence_build_body(&body, sub, AST_EXTENSION_NOT_INUSE);
			nua_notify(sub->nh,
				SIPTAG_EVENT_STR(sub->event),
				NUTAG_SUBSTATE(nua_substate_terminated),
				SIPTAG_SUBSCRIPTION_STATE_STR("terminated;reason=timeout"),
				SIPTAG_CONTENT_TYPE_STR(sofia_presence_mime(sub->format)),
				SIPTAG_PAYLOAD_STR(ast_str_buffer(body)),
				TAG_IF(sub->nat_proxy[0], NUTAG_PROXY(sub->nat_proxy)),	/* NAT route */
				TAG_END());
			ast_free(body);
		}
	}
	if (sub->stateid > -1) {
		ast_extension_state_del(sub->stateid, sofia_presence_state_cb);	/* fires destroy_cb -> drops reg ref */
		sub->stateid = -1;
	}
	if (presence_subs) {
		ao2_unlink(presence_subs, sub);		/* drops container ref */
	}
	if (sub->nh) {
		nua_handle_bind(sub->nh, NULL);		/* defensive: presence subs are never bound as
							 * hmagic (correlation is by container iteration),
							 * but clear any binding before destroy regardless */
		nua_handle_destroy(sub->nh);
		sub->nh = NULL;
	}
}

/* sofia_thread: marshaled target of the device-state callback. */
static void sofia_presence_notify_dispatch_cb(void *arg)
{
	struct sofia_presence_dispatch *d = arg;
	struct sofia_presence_sub *sub;

	if (!d) {
		return;
	}
	sub = d->sub;
	if (sub && !sub->terminated && sub->nh) {
		if (d->state == AST_EXTENSION_REMOVED || d->state == AST_EXTENSION_DEACTIVATED) {
			/* hint went away: final NOTIFY + teardown (chan_sip cb_extensionstate parity) */
			sofia_presence_emit_notify(sub, AST_EXTENSION_UNAVAILABLE, 1);
			sofia_presence_teardown(sub, 0);	/* terminated NOTIFY already sent above */
		} else {
			sofia_presence_emit_notify(sub, d->state, 0);
		}
	}
	if (sub) {
		ao2_ref(sub, -1);	/* drop dispatch ref */
	}
	ast_free(d);
}

/* device_state taskprocessor thread (NOT sofia_thread): snapshot + marshal only. */
static int sofia_presence_state_cb(char *context, char *exten,
		enum ast_extension_states state, void *data)
{
	struct sofia_presence_sub *sub = data;
	struct sofia_presence_dispatch *d;

	if (!sub) {
		return 0;
	}
	d = ast_calloc(1, sizeof(*d));
	if (!d) {
		return 0;
	}
	ao2_ref(sub, +1);	/* dispatch ref (TRANSFER) */
	d->sub = sub;
	d->state = (int) state;
	if (sofia_dispatch_to_root_thread(sofia_presence_notify_dispatch_cb, d) < 0) {
		ao2_ref(sub, -1);
		ast_free(d);
	}
	return 0;
}

/* core destroy callback: drops the registration's +1 ref on the sub. */
static void sofia_presence_sub_destroy_cb(int id, void *data)
{
	struct sofia_presence_sub *sub = data;
	if (sub) {
		ao2_ref(sub, -1);
	}
}

/* Type-safe correlation of a notifier handle -> its subscription, for the
 * expiry path (nua_r_notify terminated). Iterates the (small) container rather
 * than dereferencing hmagic as a presence sub. Returns +1-reffed sub or NULL. */
static struct sofia_presence_sub *sofia_presence_find_by_nh(nua_handle_t *nh)
{
	struct ao2_iterator it;
	struct sofia_presence_sub *sub, *found = NULL;

	if (!presence_subs || !nh) {
		return NULL;
	}
	it = ao2_iterator_init(presence_subs, 0);
	while ((sub = ao2_iterator_next(&it))) {
		if (sub->nh == nh) {
			found = sub;	/* keep the +1 ref */
			break;
		}
		ao2_ref(sub, -1);
	}
	ao2_iterator_destroy(&it);
	return found;
}

/* Did sofia-sip mark this NOTIFY transaction as terminating the subscription? */
static int sofia_substate_terminated(tagi_t tags[])
{
	int substate = nua_substate_active;
	if (tags) {
		tl_gets(tags, NUTAG_SUBSTATE_REF(substate), TAG_END());
	}
	return substate == nua_substate_terminated;
}

/* Periodic expiry sweep — runs on sofia_thread via a su_timer on sofia_root.
 *
 * sofia-sip does NOT arm a server-side expiry timer for subscriptions the app
 * accepts with nua_respond() (only its own auto-/nua_notifier-responded ones),
 * so a watcher that stops refreshing (phone reboot / network loss, no explicit
 * Expires:0) would otherwise leak forever. We own expiry ourselves — chan_sip
 * parity (sip_scheddestroy). Watchers that refresh keep pushing expires_at into
 * the future; only genuinely stale ones (now >= expires_at + grace) are torn
 * down (with a final terminated NOTIFY). Collect-then-teardown so we never
 * mutate the container mid-iteration. */
static void sofia_presence_expiry_sweep(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg)
{
	struct ao2_iterator it;
	struct sofia_presence_sub *sub;
	struct sofia_presence_sub *expired[64];
	int n = 0, i;
	time_t now;

	if (!presence_subs) {
		return;
	}
	now = time(NULL);
	it = ao2_iterator_init(presence_subs, 0);
	while ((sub = ao2_iterator_next(&it))) {
		if (!sub->terminated && sub->expires_at > 0
				&& now >= sub->expires_at + SOFIA_PRESENCE_EXPIRY_GRACE
				&& n < (int) ARRAY_LEN(expired)) {
			expired[n++] = sub;	/* keep the iterator's +1 ref for teardown below */
		} else {
			ao2_ref(sub, -1);
		}
	}
	ao2_iterator_destroy(&it);

	for (i = 0; i < n; i++) {
		if (sofia_debug) {
			ast_verbose("Sofia presence: expiring stale watcher SIP/%s -> %s@%s (no refresh)\n",
				expired[i]->peername, expired[i]->exten, expired[i]->context);
		}
		sofia_presence_teardown(expired[i], 1);	/* terminated NOTIFY + destroy */
		ao2_ref(expired[i], -1);
	}
}

/* Outbound PUBLISH (RFC 3903) is implemented in channels/sofia/sofia_publish.c. */

/* tech.devicestate: tell the gabpbx core the state of SIP/<peer> so hints over
 * SIP/<peer> reflect registration + call-limit. STRICT-IMPROVEMENT contract: the
 * core uses our concrete result and SKIPS the generic channel scan (devicestate.c
 * _ast_device_state: "if (res != AST_DEVICE_UNKNOWN) return res"). So we return a
 * concrete value ONLY where we add information the generic channel scan cannot
 * derive — offline (not registered), on-hold, and call-limit BUSY — and return
 * AST_DEVICE_UNKNOWN otherwise so the proven generic scan still decides
 * INUSE/RINGING/NOT_INUSE during calls. Cache-only peer lookup (NEVER realtime —
 * a realtime load here would defeat rtautoclear, chan_sip.c:27787 parity). */
static int sofia_devicestate(void *data)
{
	char *dev, *at;
	struct sofia_peer_key key = { .__field_mgr_pool = NULL, .name = NULL };
	struct sofia_peer *peer;
	int res = AST_DEVICE_UNKNOWN;

	dev = ast_strdupa(data ? (const char *) data : "");
	if ((at = strchr(dev, '@'))) {
		dev = at + 1;
	}
	if (ast_strlen_zero(dev) || !peers) {
		return AST_DEVICE_UNKNOWN;
	}

	key.name = dev;
	peer = ao2_find(peers, &key, OBJ_POINTER);	/* cache-only */
	if (!peer) {
		return AST_DEVICE_UNKNOWN;		/* unknown device -> let core decide */
	}

	ast_mutex_lock(&peer->lock);
	/* Reachable = a peer with a known address. chan_sofia stores the canonical
	 * "where to reach this peer" in peer->src_addr for BOTH the dynamic-registered
	 * source (set at REGISTER, zeroed at unregister) AND the static host=<ip> /
	 * dnsmgr-resolved address (sofia_dnsmgr_setup_peer). peer->addr is never
	 * written in chan_sofia, so it must NOT be consulted here (doing so pinned
	 * static host=<ip> peers to UNAVAILABLE). defaddr is the dynamic defaultip=
	 * fallback. Otherwise the peer is offline. */
	if (!peer->registered
			&& ast_sockaddr_isnull(&peer->src_addr)
			&& ast_sockaddr_isnull(&peer->defaddr)) {
		res = AST_DEVICE_UNAVAILABLE;		/* unreachable -> offline (generic can't know) */
	} else if (peer->onHold) {
		res = AST_DEVICE_ONHOLD;
	} else if (peer->inRinging) {
		/* chan_sip sip_devicestate parity: a ringing leg -> RINGING (or RINGINUSE
		 * when some legs are already up). This is what lights the BLF on an inbound
		 * call. */
		res = (peer->inRinging == peer->inUse) ? AST_DEVICE_RINGING : AST_DEVICE_RINGINUSE;
	} else if (peer->call_limit && peer->inUse >= peer->call_limit) {
		res = AST_DEVICE_BUSY;
	} else if (peer->call_limit && peer->busy_level && peer->inUse >= peer->busy_level) {
		res = AST_DEVICE_BUSY;
	} else if (peer->inUse) {
		res = AST_DEVICE_INUSE;			/* an active call -> BLF red */
	} else if (peer->qualify && peer->peer_status == PEER_UNREACHABLE) {
		/* chan_sofia has no maxms; use the qualify result instead (Codex): a
		 * registered peer that fails qualify is unreachable -> offline. */
		res = AST_DEVICE_UNAVAILABLE;
	} else {
		/* Registered and reachable with no call: report a CONCRETE NOT_INUSE
		 * (available -> BLF green), matching chan_sip. Returning UNKNOWN here left
		 * the BLF dark because, although the core would then channel-scan, the hint
		 * only recomputes on a devstate change event — which sofia_update_call_counter
		 * now fires on every call transition. */
		res = AST_DEVICE_NOT_INUSE;
	}
	ast_mutex_unlock(&peer->lock);

	ao2_ref(peer, -1);
	return res;
}

/* Event: dialog / presence handler. Runs on sofia_thread. */
static void sofia_process_presence_subscribe(nua_t *nua, nua_handle_t *nh,
		struct sofia_pvt *op, sip_t const *sip, tagi_t tags[])
{
	struct sofia_peer *peer;
	struct sofia_presence_sub *sub;
	const char *from_user, *to_user, *event;
	const char *to_host;
	char l_context[AST_MAX_CONTEXT];
	char l_peername[80];
	char l_proxy[128] = "";			/* NAT proxy target for the NOTIFY (empty = none) */
	char l_exten[AST_MAX_EXTENSION];	/* bounded copy of To-user — keeps subkey consistent with sub->exten */
	char subkey[200];
	char hint[AST_MAX_EXTENSION];
	struct ast_sockaddr src = { {0,} };	/* zero-init: sofia_get_source_addr leaves it untouched if no Via */
	int firststate;
	int expires;

	event = (sip && sip->sip_event && sip->sip_event->o_type) ? sip->sip_event->o_type : "dialog";

	/* To URI = watched resource; From URI = subscriber. */
	if (!sip || !sip->sip_to || !sip->sip_to->a_url || !sip->sip_to->a_url->url_user
			|| !sip->sip_from || !sip->sip_from->a_url || !sip->sip_from->a_url->url_user) {
		nua_respond(nh, SIP_404_NOT_FOUND, NUTAG_WITH_THIS(nua), TAG_END());
		sofia_subscribe_reject_reap(nh);	/* reap the challenge handle */
		return;
	}
	to_user = sip->sip_to->a_url->url_user;
	to_host = sip->sip_to->a_url->url_host;
	from_user = sip->sip_from->a_url->url_user;

	/* Identify the subscriber peer (gating + context source). */
	peer = sofia_find_peer(from_user);
	if (!peer) {
		if (sofia_cfg.alwaysauthreject) {
			char realm_buf[MAXHOSTNAMELEN];
			const char *realm = sofia_get_realm_for_dialog(sip, realm_buf, sizeof(realm_buf));
			sofia_send_auth_challenge(nua, nh, sip, realm, "SUBSCRIBE", "UnknownPeer");
		} else {
			ast_log(LOG_NOTICE, "Sofia presence: SUBSCRIBE from unknown peer '%s' — 404\n", from_user);
			nua_respond(nh, SIP_404_NOT_FOUND, NUTAG_WITH_THIS(nua), TAG_END());
		}
		sofia_subscribe_reject_reap(nh);	/* reap on both the 401-challenge and the 404 branch */
		return;
	}

	if (!peer->allowsubscribe) {
		ast_log(LOG_NOTICE,
			"Sofia presence: SUBSCRIBE from peer '%s' rejected by allowsubscribe=no — 403\n",
			peer->name);
		nua_respond(nh, 403, "Forbidden (policy)", NUTAG_WITH_THIS(nua), TAG_END());
		sofia_emit_subscribe_rejected(sip, peer->name, event, "AllowSubscribeClosed");
		ao2_ref(peer, -1);
		sofia_subscribe_reject_reap(nh);	/* reap the challenge handle */
		return;
	}

	/* Digest-authenticate the presence/BLF SUBSCRIBE for a credentialed peer (same
	 * rationale as the MWI path): otherwise anyone could watch any extension's
	 * call/presence state without authenticating and receive its NOTIFYs. Gate only
	 * when the subscriber peer has a credential; the verifier emits the 401/4xx. */
	if (!ast_strlen_zero(peer->secret) || !ast_strlen_zero(peer->md5secret)) {
		char realm_buf[MAXHOSTNAMELEN];
		const char *realm = sofia_get_realm_for_dialog(sip, realm_buf, sizeof(realm_buf));
		enum sofia_auth_result auth_res = sofia_verify_digest_auth(peer,
			nua, nh, sip, sip->sip_authorization, "SUBSCRIBE", realm);
		if (auth_res != SOFIA_AUTH_OK) {
			ao2_ref(peer, -1);
			sofia_subscribe_reject_reap(nh);	/* reap the 401/4xx challenge handle */
			return;
		}
	}

	/* Resolve hint context + snapshot peer name: peer subscribecontext > peer
	 * context > "default". Snapshot reload-mutable stringfields under peer->lock. */
	ast_mutex_lock(&peer->lock);
	if (!ast_strlen_zero(peer->subscribecontext)) {
		ast_copy_string(l_context, peer->subscribecontext, sizeof(l_context));
	} else if (!ast_strlen_zero(peer->context)) {
		ast_copy_string(l_context, peer->context, sizeof(l_context));
	} else {
		ast_copy_string(l_context, "default", sizeof(l_context));
	}
	ast_copy_string(l_peername, peer->name, sizeof(l_peername));
	/* Build the NAT proxy target from peer->src_addr while the peer is locked +
	 * reffed. For nat=force_rport/comedia watchers this is the registered public
	 * source (the SBC); the presence NOTIFYs are then routed there via NUTAG_PROXY
	 * instead of the watcher's unreachable private Contact (which makes every NOTIFY
	 * time out 408). Empty for non-NAT peers, so the TAG_IF below is a no-op and
	 * sofia-sip uses the normal dialog target. */
	sofia_build_nat_proxy_url_from_peer(peer, l_proxy, sizeof(l_proxy));
	ast_mutex_unlock(&peer->lock);
	ao2_ref(peer, -1);
	peer = NULL;

	/* The watched extension must have a dialplan hint, else nothing to watch. */
	if (!ast_get_hint(hint, sizeof(hint), NULL, 0, NULL, l_context, to_user)) {
		ast_log(LOG_NOTICE,
			"Sofia presence: no hint for %s@%s (watcher SIP/%s) — 404\n",
			to_user, l_context, l_peername);
		nua_respond(nh, SIP_404_NOT_FOUND, NUTAG_WITH_THIS(nua), TAG_END());
		sofia_subscribe_reject_reap(nh);	/* reap the challenge handle */
		return;
	}

	/* Logical key: at most ONE subscription per (watcher, watched-exten, context).
	 * A re-SUBSCRIBE on a fresh dialog (phone reboot) or an Expires:0 unsubscribe
	 * is correlated here — NOT by nh, which sofia-sip does not reliably reuse. */
	ast_copy_string(l_exten, to_user, sizeof(l_exten));	/* bound the wire To-user up front */
	snprintf(subkey, sizeof(subkey), "%s|%s|%s", l_peername, l_exten, l_context);
	/* Expires: ex_delta is unsigned long; clamp to our max before the int cast so
	 * a pathological value > INT_MAX cannot wrap negative and be misread as an
	 * unsubscribe (expires <= 0). */
	if (!sip || !sip->sip_expires) {
		expires = SOFIA_PRESENCE_DEFAULT_EXPIRY;
	} else if (sip->sip_expires->ex_delta > (unsigned long) SOFIA_PRESENCE_DEFAULT_EXPIRY) {
		expires = SOFIA_PRESENCE_DEFAULT_EXPIRY;
	} else {
		expires = (int) sip->sip_expires->ex_delta;
	}

	/* Replace/terminate any existing subscription for this key. */
	{
		struct sofia_presence_sub keyobj;
		struct sofia_presence_sub *old;
		memset(&keyobj, 0, sizeof(keyobj));
		ast_copy_string(keyobj.subkey, subkey, sizeof(keyobj.subkey));
		old = ao2_find(presence_subs, &keyobj, OBJ_POINTER);

		if (expires <= 0) {
			/* Unsubscribe. sofia-sip delivers this on a fresh handle (verified:
			 * not the notifier handle), so accept it and send the terminating
			 * NOTIFY (RFC 6665 — 200 + final NOTIFY). nua_respond alone (no
			 * notifier) makes the stack emit a spurious 500. */
			const char *norm = (!strcasecmp(event, "dialog") || !strcasecmp(event, "dialog-info"))
				? "dialog" : "presence";
			int nh_is_old = (old && old->nh == nh);
			nua_respond(nh, SIP_200_OK, NUTAG_WITH_THIS(nua),
				SIPTAG_EXPIRES_STR("0"), TAG_END());
			nua_notify(nh,
				SIPTAG_EVENT_STR(norm),
				NUTAG_SUBSTATE(nua_substate_terminated),
				SIPTAG_SUBSCRIPTION_STATE_STR("terminated;reason=timeout"),
				TAG_END());
			if (old) {
				sofia_presence_teardown(old, 0);	/* destroys old->nh */
				ao2_ref(old, -1);
			}
			/* Reap the fresh server handle sofia-sip created for this unsubscribe
			 * (SUBSCRIBE is an APPL_METHOD — the stack will not auto-destroy it),
			 * unless teardown already freed it (old->nh == nh). MWI discipline. */
			if (!nh_is_old) {
				sofia_subscribe_reject_reap(nh);	/* guarded reap of the fresh unbound unsubscribe handle */
			}
			if (sofia_debug) {
				ast_verbose("Sofia presence: UNSUBSCRIBE — watcher SIP/%s -> %s@%s\n",
					l_peername, to_user, l_context);
			}
			return;
		}

		if (old) {
			if (old->nh == nh) {
				/* True in-dialog refresh on the same handle. SUBSCRIBE is an
				 * APPL_METHOD so sofia-sip will NOT auto-answer it — we MUST
				 * nua_respond(202) (else the watcher retransmits then drops the
				 * subscription at the first refresh). Extend the lifetime, then
				 * re-emit current state. */
				char eb[16];
				int st;
				old->expires = expires;
				old->expires_at = time(NULL) + expires;
				ast_copy_string(old->nat_proxy, l_proxy, sizeof(old->nat_proxy));	/* refresh NAT route (source may have moved) */
				snprintf(eb, sizeof(eb), "%d", expires);
				nua_respond(nh, SIP_202_ACCEPTED, NUTAG_WITH_THIS(nua),
					SIPTAG_EXPIRES_STR(eb), TAG_END());
				st = ast_extension_state(NULL, old->context, old->exten);
				sofia_presence_emit_notify(old, st, 0);
				ao2_ref(old, -1);
				return;
			}
			/* Stale dialog (new handle): drop the old watcher, create fresh below. */
			sofia_presence_teardown(old, 0);
			ao2_ref(old, -1);
		}
	}

	/* Allocate + populate the new subscription object. */
	sub = ao2_alloc(sizeof(*sub), presence_sub_destructor);
	if (!sub) {
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, NUTAG_WITH_THIS(nua), TAG_END());
		sofia_subscribe_reject_reap(nh);	/* reap the challenge handle */
		return;
	}
	sub->nh = nh;
	sub->stateid = -1;
	sub->laststate = -10;	/* "unknown" so the first NOTIFY always reflects a transition */
	sub->version = 0;
	sub->expires = expires;
	sub->expires_at = time(NULL) + expires;
	sub->terminated = 0;
	ast_copy_string(sub->subkey, subkey, sizeof(sub->subkey));
	ast_copy_string(sub->exten, l_exten, sizeof(sub->exten));
	ast_copy_string(sub->context, l_context, sizeof(sub->context));
	ast_copy_string(sub->peername, l_peername, sizeof(sub->peername));
	ast_copy_string(sub->nat_proxy, l_proxy, sizeof(sub->nat_proxy));	/* NAT NOTIFY route */
	snprintf(sub->entity, sizeof(sub->entity), "sip:%s@%s", to_user,
		!ast_strlen_zero(to_host) ? to_host : (!ast_strlen_zero(sofia_cfg.realm) ? sofia_cfg.realm : "localhost"));
	sofia_get_source_addr(sip, &src);
	ast_copy_string(sub->watcher_addr, ast_sockaddr_stringify(&src), sizeof(sub->watcher_addr));

	/* Event package -> body format + NOTIFY Event header. dialog -> dialog-info;
	 * presence -> pidf/xpidf/cpim by Accept. */
	if (!strcasecmp(event, "dialog") || !strcasecmp(event, "dialog-info")) {
		sub->format = SOFIA_SUB_DIALOG_INFO;
		ast_copy_string(sub->event, "dialog", sizeof(sub->event));
	} else {
		sip_accept_t *ac = sip->sip_accept;
		sub->format = SOFIA_SUB_PIDF;
		for (; ac; ac = ac->ac_next) {
			if (ac->ac_type && !strcasecmp(ac->ac_type, "application/xpidf+xml")) {
				sub->format = SOFIA_SUB_XPIDF; break;
			} else if (ac->ac_type && !strcasecmp(ac->ac_type, "application/cpim-pidf+xml")) {
				sub->format = SOFIA_SUB_CPIM_PIDF; break;
			} else if (ac->ac_type && !strcasecmp(ac->ac_type, "application/dialog-info+xml")) {
				sub->format = SOFIA_SUB_DIALOG_INFO; break;
			}
		}
		ast_copy_string(sub->event,
			sub->format == SOFIA_SUB_DIALOG_INFO ? "dialog" : "presence", sizeof(sub->event));
	}

	/* Link into the registry (container holds the ref; drop our creation ref). */
	if (!ao2_link(presence_subs, sub)) {
		/* ao2_link returns NULL on OOM -> sub is NOT in presence_subs, so
		 * refresh/unsubscribe/expiry could never find it. Do NOT go on to register a
		 * core hint watcher + leak the handle behind an untracked subscription: reject
		 * 500 and tear the handle down here (presence subs are not hmagic-bound; this
		 * runs on sofia_thread). */
		ast_log(LOG_WARNING, "Sofia presence: ao2_link failed for %s@%s — rejecting 500\n",
			sub->exten, sub->context);
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, NUTAG_WITH_THIS(nua), TAG_END());
		sofia_subscribe_reject_reap(nh);	/* guarded reap (presence subs are not hmagic-bound) */
		ao2_ref(sub, -1);	/* creation ref */
		return;
	}

	/* Register the hint watcher with the core. The +1 ref is owned by the
	 * registration and dropped by sofia_presence_sub_destroy_cb. THIS is what
	 * makes `core show hints` count the Watcher. */
	ao2_ref(sub, +1);
	sub->stateid = ast_extension_state_add_destroy(sub->context, sub->exten,
		sofia_presence_state_cb, sofia_presence_sub_destroy_cb, sub);
	if (sub->stateid < 0) {
		ast_log(LOG_WARNING, "Sofia presence: ast_extension_state_add_destroy failed for %s@%s\n",
			sub->exten, sub->context);
		ao2_ref(sub, -1);	/* undo the registration ref we pre-took */
		ao2_unlink(presence_subs, sub);
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, NUTAG_WITH_THIS(nua), TAG_END());
		/* Tear the handle down on this failure arm too. The presence-sub destructor
		 * is a deliberate no-op (handles are destroyed explicitly on sofia_thread),
		 * so without this the nua_handle leaks when add_destroy fails. */
		sofia_subscribe_reject_reap(nh);	/* guarded reap (presence subs are not hmagic-bound) */
		ao2_ref(sub, -1);	/* creation ref */
		return;
	}

	/* Accept the SUBSCRIBE with a 2xx (sofia-sip server idiom: nua_respond +
	 * NUTAG_WITH_THIS binds the response to THIS pending SUBSCRIBE transaction —
	 * nua_notifier does NOT answer the request and leaves it to fail 500 at
	 * teardown, per sofia-sip tests/test_simple.c). Then push the initial NOTIFY
	 * (RFC 6665 §4.4.1); NUTAG_SUBSTATE makes sofia-sip own Subscription-State +
	 * expiry/refresh. */
	{
		char expires_buf[16];
		snprintf(expires_buf, sizeof(expires_buf), "%d", expires);
		nua_respond(nh, SIP_202_ACCEPTED, NUTAG_WITH_THIS(nua),
			SIPTAG_EXPIRES_STR(expires_buf), TAG_END());
	}

	firststate = ast_extension_state(NULL, sub->context, sub->exten);
	sofia_presence_emit_notify(sub, firststate, 0);

	ao2_ref(sub, -1);	/* drop creation ref; container + registration hold it */

	if (sofia_debug) {
		ast_verbose("Sofia presence: SUBSCRIBE accepted — watcher SIP/%s -> %s@%s (%s)\n",
			l_peername, sub->exten, sub->context, sofia_presence_mime(sub->format));
	}
}

static void sofia_process_subscribe(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	const char *event = NULL;

	if (sip && sip->sip_event && sip->sip_event->o_type) {
		event = sip->sip_event->o_type;
	}


	/* allowsubscribe global ban gate (chan_sip parity): when sofia_cfg.allowsubscribe
	 * (DERIVED) is FALSE, NO peer allows subscriptions; reject upfront before any
	 * peer-lookup or event-routing. Keep the verbatim "403 Forbidden (policy)" string
	 * (operator AMI/log scripts pattern-match the exact text including parens). */
	if (!sofia_cfg.allowsubscribe) {
		nua_respond(nh, 403, "Forbidden (policy)",
			NUTAG_WITH_THIS(nua), TAG_END());
		sofia_emit_subscribe_rejected(sip, NULL,
			S_OR(event, "(missing)"), "AllowSubscribeClosed");
		sofia_subscribe_reject_reap(nh);	/* reap the APPL_METHOD handle */
		return;
	}

	/* Split by Event package: message-summary -> MWI handler; presence/dialog ->
	 * the presence handler below; anything else -> 489 Bad Event. */
	if (event && !strcasecmp(event, "message-summary")) {
		sofia_process_mwi_subscribe(nua, nh, op, sip, tags);
		return;
	}

	/* presence / dialog (BLF) -> the extension-state notifier path. */
	if (event && (!strcasecmp(event, "dialog") || !strcasecmp(event, "dialog-info")
			|| !strcasecmp(event, "presence"))) {
		sofia_process_presence_subscribe(nua, nh, op, sip, tags);
		return;
	}

	/* An unsupported Event package -> 489 Bad Event + Allow-Events (RFC 6665 §4.3),
	 * NOT a phantom 202 that establishes a subscription we never serve (which also
	 * leaked the APPL_METHOD handle). The packages a watcher can actually use are
	 * message-summary, presence, dialog, dialog-info. Then reap the handle (sofia-sip
	 * never auto-reaps it). */
	ast_log(LOG_NOTICE, "Sofia: SUBSCRIBE Event=%s unsupported — 489 Bad Event\n",
		S_OR(event, "(missing)"));
	sofia_emit_subscribe_rejected(sip, NULL, S_OR(event, "(missing)"), "BadEvent");
	nua_respond(nh, SIP_489_BAD_EVENT,
		NUTAG_WITH_THIS(nua),
		SIPTAG_ALLOW_EVENTS_STR("presence, dialog, dialog-info, message-summary"),
		TAG_END());
	sofia_subscribe_reject_reap(nh);
}

static void sofia_process_notify(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	if (sofia_debug)
		ast_verbose("Sofia: Received NOTIFY\n");
	nua_respond(nh, SIP_200_OK, TAG_END());
}

/* 3-method bridged-channel finder, used by the REFER ATTENDED + BLIND paths.
 *
 * Methods (try in order):
 *  (1) ast_bridged_channel(op->owner)     — _bridge pointer
 *  (2) BRIDGEPEER channel-var name lookup — set by ast_bridge_call
 *  (3) dialogs container walk by linkedid — the other Sofia leg
 *
 * Returns a +1-REFFED ast_channel (or NULL); the CALLER must ast_channel_unref()
 * it when done. */
static struct ast_channel *sofia_find_bridged_channel(struct sofia_pvt *op)
{
	struct ast_channel *bridged = NULL;
	const char *bridgepeer_name = NULL;
	struct ast_channel *self;

	if (!op) {
		return NULL;
	}

	/* Snapshot+ref op->owner ONCE under op->lock and use the pinned local for all
	 * three methods below. A lock-free re-read at each method would race sofia_hangup,
	 * which NULLs pvt->owner under op->lock then frees the channel — a NULL-deref / UAF
	 * reachable off sofia_thread via sofia_process_refer. The pin holds the channel
	 * alive for the whole lookup. */
	ast_mutex_lock(&op->lock);
	self = op->owner;
	if (self) {
		ast_channel_ref(self);
	}
	ast_mutex_unlock(&op->lock);
	if (!self) {
		return NULL;
	}

	/* Returns a +1-REFFED channel (or NULL) — the CALLER must ast_channel_unref()
	 * it when done. The old "borrowed pointer kept alive by the bridge partner"
	 * contract was a UAF: a REFER/hangup dissolves exactly that bridge, so the
	 * borrowed channel could be freed while the caller still derefs it
	 * (ast_async_goto / tech_pvt). */

	/* Method 1: _bridge pointer (borrowed → take a ref) */
	bridged = ast_bridged_channel(self);
	if (bridged) {
		ast_channel_ref(bridged);
		if (sofia_debug) {
			ast_verbose("Sofia: bridged-finder method 1 (_bridge): %s\n", bridged->name);
		}
		ast_channel_unref(self);
		return bridged;
	}

	/* Method 2: BRIDGEPEER channel-var (ast_channel_get_by_name_prefix already +1's
	 * it — KEEP that ref and hand it to the caller). */
	bridgepeer_name = pbx_builtin_getvar_helper(self, "BRIDGEPEER");
	if (bridgepeer_name && !ast_strlen_zero(bridgepeer_name)) {
		bridged = ast_channel_get_by_name_prefix(bridgepeer_name, strlen(bridgepeer_name));
		if (bridged) {
			if (sofia_debug) {
				ast_verbose("Sofia: bridged-finder method 2 (BRIDGEPEER=%s): %s\n",
					bridgepeer_name, bridged->name);
			}
			ast_channel_unref(self);
			return bridged;	/* already +1 */
		}
	}

	/* Method 3: dialogs linkedid walk (sibling Sofia leg). Read each sibling's
	 * owner ONCE under its pvt->lock and ref it there (the sibling's sofia_hangup
	 * nulls p->owner under p->lock then frees the channel). */
	{
		struct ao2_iterator it = ao2_iterator_init(dialogs, 0);
		struct sofia_pvt *p;
		const char *my_linkedid = self->linkedid;
		while ((p = ao2_iterator_next(&it))) {
			if (p != op && my_linkedid) {
				struct ast_channel *po;
				ast_mutex_lock(&p->lock);
				po = p->owner;
				if (po && po->linkedid && !strcmp(po->linkedid, my_linkedid)) {
					bridged = ast_channel_ref(po);
				}
				ast_mutex_unlock(&p->lock);
			}
			ao2_ref(p, -1);
			if (bridged) {
				if (sofia_debug) {
					ast_verbose("Sofia: bridged-finder method 3 (linkedid=%s): %s\n",
						my_linkedid, bridged->name);
				}
				break;
			}
		}
		ao2_iterator_destroy(&it);
	}

	ast_channel_unref(self);
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

/* Forward-decl the pvt validator (defined below near sofia_event_callback) —
 * sofia_local_attended_transfer uses it to pin the nua_handle_by_replaces() result
 * (native RFC 3891 full-identifier match). */
static struct sofia_pvt *sofia_pvt_ref_if_linked(nua_hmagic_t *hmagic);

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

	/* RFC 3891 §3: match the FULL dialog identifier — Call-ID + to-tag (== our LOCAL
	 * tag) + from-tag (== the REMOTE tag) — via sofia-sip's native
	 * nua_handle_by_replaces() instead of a Call-ID-only scan, which could land on the
	 * WRONG forked dialog (same Call-ID, different tags). Convert the matched handle to
	 * our pvt with nua_handle_magic() and PIN it with sofia_pvt_ref_if_linked, which
	 * also validates the hmagic really is a live dialog pvt (a peer/presence-sub handle
	 * is not in `dialogs` and yields NULL). Runs on sofia_thread (REFER handler), so
	 * the nua_* dialog lookup is in-thread. A valid Replaces MUST carry both tags and
	 * sofia-sip's nta_leg_by_replaces() requires them, so an untagged Replaces is
	 * declined for a LOCAL match (the caller falls back to remote attended behaviour). */
	target_pvt = NULL;
	if (!ast_strlen_zero(replaces->to_tag) && !ast_strlen_zero(replaces->from_tag)) {
		su_home_t tmphome[1] = { SU_HOME_INIT(tmphome) };
		char rstr[600];
		sip_replaces_t *r;
		nua_handle_t *rnh;

		snprintf(rstr, sizeof(rstr), "%s;to-tag=%s;from-tag=%s",
			replaces->callid, replaces->to_tag, replaces->from_tag);
		r = sip_replaces_make(tmphome, rstr);
		rnh = r ? nua_handle_by_replaces(sofia_nua, r) : NULL;
		if (rnh) {
			target_pvt = sofia_pvt_ref_if_linked(nua_handle_magic(rnh));
			nua_handle_unref(rnh);	/* nua_handle_by_replaces() returns a +1 handle ref */
		}
		su_home_deinit(tmphome);
	}
	if (!target_pvt || target_pvt == transferer) {
		if (target_pvt) {
			ao2_ref(target_pvt, -1);	/* self-match (shouldn't happen) — release */
		}
		return 1; /* Not local; caller may fall back to remote attended behavior. */
	}

	/* TOCTOU/UAF fix: ref each owner UNDER its pvt->lock (sofia_hangup nulls
	 * pvt->owner under that lock on the channel thread, then the core frees the
	 * channel). Snapshot the two owners SEQUENTIALLY — never hold two pvt->locks at
	 * once — so there is no pvt-vs-pvt lock-ordering hazard. */
	ast_mutex_lock(&transferer->lock);
	transferer_chan = transferer->owner ? ast_channel_ref(transferer->owner) : NULL;
	ast_mutex_unlock(&transferer->lock);
	if (!transferer_chan) {
		ao2_ref(target_pvt, -1);
		return -1;
	}
	ast_mutex_lock(&target_pvt->lock);
	target_chan = target_pvt->owner ? ast_channel_ref(target_pvt->owner) : NULL;
	ast_mutex_unlock(&target_pvt->lock);
	if (!target_chan) {
		ast_log(LOG_WARNING, "Sofia: attended transfer Replaces call '%s' has no owner channel\n",
			replaces->callid);
		ast_channel_unref(transferer_chan);
		ao2_ref(target_pvt, -1);
		return -1;
	}
	transferee_chan = sofia_ref_bridged_channel(transferer_chan);
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

/* RFC 3515 NOTIFY-sipfrag transfer-progress (chan_sip parity): emits NOTIFY
 * message/sipfrag to the transferer (REFER originator) signaling progress + final
 * outcome. sipfrag status strings used by the 3 callsites in sofia_process_refer:
 *   - "180 Ringing" (terminate=FALSE) — in-progress
 *   - "200 OK" (terminate=TRUE) — terminal success
 *   - "503 Service Unavailable ..." (terminate=TRUE) — transferee leg unavailable
 *
 * terminate=0 → in-progress (NUTAG_SUBSTATE active); terminate=1 → terminal
 * (NUTAG_SUBSTATE terminated;reason=noresource).
 *
 * Also emits an AMI ReferProgress event at every NOTIFY (Channel + Peer + Status +
 * Direction) for NMS visibility. */
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

	{
		/* TOCTOU/UAF fix: op->owner is nulled by sofia_hangup under op->lock on
		 * the channel thread; snapshot the name under op->lock (owner non-NULL
		 * under the lock => the channel is still alive, as the ref drop happens
		 * after sofia_hangup nulls owner) before emitting the AMI event. */
		char ev_name[128] = "";
		ast_mutex_lock(&op->lock);
		if (op->owner) {
			ast_copy_string(ev_name, op->owner->name, sizeof(ev_name));
		}
		ast_mutex_unlock(&op->lock);
		manager_event(EVENT_FLAG_SYSTEM, "ReferProgress",
			"Channel: %s\r\n"
			"Peer: SIP/%s\r\n"
			"Status: %s\r\n"
			"Direction: %s\r\n",
			ev_name,
			op->peername ? op->peername : "",
			sipfrag_status,
			terminate ? "terminal" : "in-progress");
	}
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

	/* allowexternaldomains (chan_sip parity): reject REFER targeting a non-local
	 * SIP domain when domain_list non-empty AND the Refer-To domain is not in it
	 * AND !allow_external_domains. */
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

	/* allowtransfer (chan_sip parity): when the dialog (or its peer) has
	 * allowtransfer=no, reject the REFER with 603 Declined (policy) — exact string
	 * kept (operator AMI/log scripts pattern-match it). Early return BEFORE 202
	 * Accepted (the transfer body is never accepted nor processed). Plus an AMI
	 * TransferRejected event for real-time REFER-abuse monitoring. */
	if (op && op->allowtransfer == TRANSFER_CLOSED) {
		nua_respond(nh, 603, "Declined (policy)",
			NUTAG_WITH_THIS(nua),
			TAG_END());
		{
			/* TOCTOU/UAF fix: snapshot owner name+uniqueid under op->lock
			 * (sofia_hangup nulls op->owner under the same lock) before the AMI
			 * emit; the prior code double-loaded op->owner unlocked. */
			char ev_name[128] = "";
			char ev_uniqueid[150] = "";
			ast_mutex_lock(&op->lock);
			if (op->owner) {
				ast_copy_string(ev_name, op->owner->name, sizeof(ev_name));
				ast_copy_string(ev_uniqueid, op->owner->uniqueid, sizeof(ev_uniqueid));
			}
			ast_mutex_unlock(&op->lock);
			manager_event(EVENT_FLAG_CALL, "TransferRejected",
				"Channel: %s\r\n"
				"Uniqueid: %s\r\n"
				"Peer: SIP/%s\r\n"
				"ReferTo: %s\r\n"
				"Reason: AllowTransferClosed\r\n",
				ev_name,
				ev_uniqueid,
				op->peername ? op->peername : "",
				refer_to ? refer_to : "");
		}
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

	/* TOCTOU/UAF fix: snapshot+ref op->owner under op->lock for the whole transfer
	 * body. sofia_hangup (channel thread) nulls pvt->owner under op->lock then the
	 * core frees the channel; this handler derefs the owner across blocking ops
	 * (redirecting mutation, ast_queue_hangup, the bridged-finder, ast_async_goto),
	 * so the +1 ref pins the channel for the duration. Use the local `owner`, not
	 * op->owner, for every direct deref below. Must be released on every exit. */
	{
	struct ast_channel *owner;
	ast_mutex_lock(&op->lock);
	owner = op->owner;
	if (owner) {
		ast_channel_ref(owner);
	}
	ast_mutex_unlock(&op->lock);
	if (!owner) {
		ast_log(LOG_WARNING, "Sofia: REFER — owner gone before transfer\n");
		return;
	}

	/* REFER may carry a Diversion header for transfer-source attribution. Update
	 * the redirecting chain before transfer dispatch so the child Dial inherits it. */
	sofia_change_redirecting_info(op, owner, sip);

	if (is_attended) {
		int attended_res;

		attended_res = sofia_local_attended_transfer(op, &replaces);
		if (attended_res == 0) {
			sofia_send_refer_notify(op, "200 OK", 1);
			ast_queue_hangup(owner);
			ast_channel_unref(owner);
			return;
		} else if (attended_res < 0) {
			sofia_send_refer_notify(op, "486 Busy Here", 1);
			ast_channel_unref(owner);
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
	 * down channel state the bridged-finder relies on (the finder walks
	 * op->owner's vars/linkedid) AND the NOTIFY emit needs op->nh + op->owner
	 * state alive for AMI ReferProgress event Channel + Peer fields.
	 *
	 * RFC 3515 NOTIFY message/sipfrag transfer-progress is emitted at 3 sites via
	 * sofia_send_refer_notify:
	 *  - "180 Ringing" before ast_async_goto (in-progress)
	 *  - "200 OK" after ast_async_goto (terminal success)
	 *  - "503 Service Unavailable (cant handle one-legged xfers)" when bridged
	 *    NULL (terminal failure; exact paren-tail kept for chan_sip parity). */
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
			/* RFC 3515: terminal NOTIFY after redirect dispatched. ast_async_goto is
			 * async-fire-and-forget; operator semantic = REFER successfully accepted + routed
			 * (chan_sip parking parity). */
			sofia_send_refer_notify(op, "200 OK", 1);

			/* chan_sip parity (SIP_DEFER_BYE_ON_TRANSFER): "Do not hangup call, the
			 * other side does that when we say 200 OK". RFC 5589 §6.1 — after the
			 * terminal NOTIFY 200 OK, the transferer's UA owns the dialog teardown via BYE.
			 * Issuing our own nua_bye now would race the pending terminal NOTIFY
			 * inside sofia-sip and silently drop it, leaving the UA stuck on a
			 * dialog with no audio (observed against MicroSIP 3.21.4).
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
			 * Exact paren-tail kept for operator-script grep compat. */
			sofia_send_refer_notify(op, "503 Service Unavailable (cant handle one-legged xfers)", 1);
			/* No bridged peer to redirect — tear the transferer leg down
			 * immediately (chan_sip parity: failure path does not defer the BYE). */
			ast_queue_hangup(owner);
		}
		if (bridged) {
			ast_channel_unref(bridged);	/* T3: helper now returns a +1 ref */
		}
	}
	ast_channel_unref(owner);
	}
}

static void sofia_process_info(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	const char *content_type = NULL;
	const char *body = NULL;
	char bodybuf[1024];			/* pl_len-bounded NUL-terminated body copy */
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
		/* Copy into a pl_len-bounded NUL-terminated buffer — the payload may contain
		 * NULs / not be NUL-terminated, and the strstr/atol parsing below assumes a
		 * C string. */
		size_t n = sip->sip_payload->pl_len;
		if (n >= sizeof(bodybuf)) {
			n = sizeof(bodybuf) - 1;
		}
		memcpy(bodybuf, sip->sip_payload->pl_data, n);
		bodybuf[n] = '\0';
		body = bodybuf;
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
			long d;
			dur += strlen("Duration=");
			d = atol(dur);
			/* Clamp to a sane DTMF length so a hostile/garbage Duration (negative
			 * -> huge when stored unsigned, or absurdly large) can never become an
			 * unreasonable f.len. A valid value passes through unchanged. */
			if (d < 0) {
				d = 0;
			} else if (d > 10000) {
				d = 10000;
			}
			duration = (unsigned int) d;
		}
	}
	/* application/dtmf: single digit in body */
	else if (strstr(content_type, "application/dtmf")) {
		digit = body[0];
	}

	if (digit && digit != ' ') {
		/* TOCTOU/UAF fix: snapshot+ref op->owner under op->lock (sofia_hangup nulls
		 * pvt->owner under the same lock on the channel thread, then the core frees
		 * the channel); ast_queue_frame takes the channel lock so queue outside
		 * op->lock with the +1 ref pinning the channel. Mirrors sofia_process_bye. */
		struct ast_channel *owner;
		struct ast_frame f = {
			.frametype = AST_FRAME_DTMF_BEGIN,
			.subclass.integer = digit,
			.src = __PRETTY_FUNCTION__,
		};
		ast_mutex_lock(&op->lock);
		owner = op->owner;
		if (owner) {
			ast_channel_ref(owner);
		}
		ast_mutex_unlock(&op->lock);
		if (owner) {
			ast_queue_frame(owner, &f);

			f.frametype = AST_FRAME_DTMF_END;
			f.len = duration;
			ast_queue_frame(owner, &f);
			ast_channel_unref(owner);
		}

		if (sofia_debug)
			ast_verbose("Sofia: Received DTMF '%c' via SIP INFO (duration=%u)\n", digit, duration);
	}
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
		struct ast_channel *owner;
		ast_mutex_lock(&op->lock);
		op->state = SOFIA_DIALOG_STATE_UP;
		owner = op->owner;
		if (owner) {
			/* Pin the owner across sofia_parse_sdp (UAF fix): the late-offer ACK
			 * path took no ref, so a concurrent sofia_hangup could free the channel
			 * while sofia_parse_sdp mutates its format state. */
			ast_channel_ref(owner);
		}
		ast_mutex_unlock(&op->lock);
		/* For late-offer INVITEs (no SDP in INVITE), the ACK may carry SDP */
		if (sip && sip->sip_payload && sip->sip_payload->pl_data && op->rtp) {
			sofia_parse_sdp(op, sip);
			if (sofia_debug)
				ast_verbose("Sofia: ACK with SDP, remote RTP set\n");
		}
		if (owner) {
			ast_channel_unref(owner);
		}
	}
}

/* Pointer-equality predicate for sofia_peer_ref_if_linked. Deliberately does NOT
 * touch peer->name (so it is safe even if `obj` were mid-free) — only the struct
 * pointer is compared. */
static int sofia_peer_ptr_cmp_cb(void *obj, void *arg, int flags)
{
	return (obj == arg) ? (CMP_MATCH | CMP_STOP) : 0;
}

/* Return a +1 ref to `target` IFF it is still linked in the `peers` container, else
 * NULL. Pointer-safe revalidation for peer-magic event handlers (the qualify OPTIONS
 * response) which would otherwise deref a peer that `sip prune realtime` freed on the
 * CLI thread (the nua_r_options handler runs on sofia_thread but the prune does not).
 * MUST NOT use ao2_find(..., OBJ_POINTER): the peers hash/cmp callbacks deref
 * peer->name, which would itself touch freed memory. ao2_callback with our
 * pointer-only predicate iterates under the container lock and returns the matched
 * object +1-reffed, so the peer cannot be unlinked+freed mid-scan. */
static struct sofia_peer *sofia_peer_ref_if_linked(struct sofia_peer *target)
{
	if (!target || !peers) {
		return NULL;
	}
	return ao2_callback(peers, 0, sofia_peer_ptr_cmp_cb, target);
}

void sofia_qualify_peer(struct sofia_peer *peer)
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

/* Defined here so sofia_qualify_thread can marshal a per-peer qualify onto
 * sofia_thread via sofia_dispatch_to_root_thread, like the AMI SIPqualify. */

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
			/* nua_handle()/nua_options() must run on sofia_thread (same-thread-as-create),
			 * NOT this aux qualify pthread — marshal the qualify via
			 * sofia_dispatch_to_root_thread, exactly like the AMI SIPqualify action. Evaluate
			 * the due predicate AND set the gate under peer->lock (the same lock that guards
			 * qualify_nh): gate on !qualify_pending (a dispatch is queued but its callback has
			 * not run) AND !qualify_nh (a prior OPTIONS is still in flight) so a slow
			 * sofia_thread does not enqueue a no-op root callback every second. */
			int do_dispatch = 0;
			ast_mutex_lock(&peer->lock);
			if (peer->qualify && peer->registered && !peer->qualify_pending && !peer->qualify_nh) {
				time_t now = time(NULL);
				int freq = peer->qualifyfreq > 0 ? peer->qualifyfreq : DEFAULT_QUALIFYFREQ;
				if (peer->peer_status == PEER_UNREACHABLE) {
					freq = DEFAULT_FREQ_NOTOK;
				}
				if ((now - peer->last_qualify.tv_sec) >= freq) {
					peer->qualify_pending = 1;
					do_dispatch = 1;
				}
			}
			ast_mutex_unlock(&peer->lock);

			if (do_dispatch) {
				struct sipqualifypeer_data *qd = ast_calloc(1, sizeof(*qd));
				if (qd) {
					qd->peer = peer;
					qd->clear_pending = 1;	/* timer owns the gate */
					ao2_ref(peer, +1);	/* dispatch ref; sipqualifypeer_callback drops it */
					if (sofia_dispatch_to_root_thread(sipqualifypeer_callback, qd) < 0) {
						ast_mutex_lock(&peer->lock);
						peer->qualify_pending = 0;
						ast_mutex_unlock(&peer->lock);
						ao2_ref(peer, -1);
						ast_free(qd);
					}
				} else {
					ast_mutex_lock(&peer->lock);
					peer->qualify_pending = 0;
					ast_mutex_unlock(&peer->lock);
				}
			}
			ao2_ref(peer, -1);
		}
		ao2_iterator_destroy(&i);
	}

	return NULL;
}

/* Teardown-race guard: re-validate a dialog-event hmagic against the dialogs
 * container and return a +1-reffed pvt (or NULL).
 *
 * sofia_event_callback receives the dialog pvt as a raw nh->nh_magic backpointer
 * with no reference. sofia_hangup runs concurrently on the channel/PBX thread
 * and frees the pvt (ao2_unlink(dialogs)+ao2_ref(-1)); the destructor's
 * nua_handle_bind(nh,NULL) only neutralizes events dispatched AFTER it runs, not
 * one already executing here that has already latched hmagic. Looking the
 * address up under the dialogs container lock closes that window: if sofia_hangup
 * already unlinked the pvt we get NULL (skip the event), otherwise we take a +1
 * ref that pins the struct for the whole dispatch. dialog_hash_fn / dialog_cmp_fn
 * use only the POINTER VALUE (never deref), so passing a possibly-dangling hmagic
 * is safe AND ao2_find's OBJ_POINTER fast-path hashes that value to a single
 * bucket — O(1) instead of scanning every bucket. */
static int dialog_hash_fn(const void *obj, int flags)
{
	/* Hash the pointer VALUE only — never dereference (hmagic may dangle). Mask off the
	 * sign bit so the result is ALWAYS non-negative: this fork's legacy astobj2 abs()es
	 * the hash on the LINK path but NOT on the FIND/UNLINK (OBJ_POINTER) path, so a negative
	 * value (common for PIE/heap pointers) would miss the single-bucket fast path and fall
	 * back to a full n_buckets scan — the O(n) the container was sized to avoid. */
	return (int) (((uintptr_t) obj >> 5) & 0x7fffffff);
}

static int dialog_cmp_fn(void *obj, void *arg, int flags)
{
	return (obj == arg) ? (CMP_MATCH | CMP_STOP) : 0;
}

static struct sofia_pvt *sofia_pvt_ref_if_linked(nua_hmagic_t *hmagic)
{
	if (!hmagic) {
		return NULL;
	}
	return ao2_find(dialogs, hmagic, OBJ_POINTER);
}

/* Sentinel hmagic for AMI SIPnotify one-shot handles. Its ADDRESS is a unique value
 * that can never equal a heap sofia_pvt / sofia_peer / sofia_presence_sub pointer, so
 * sofia_event_callback can recognise the app-owned out-of-dialog NOTIFY handle (which
 * sofia-sip never auto-reaps) purely by pointer equality and destroy it when the NOTIFY
 * transaction reaches its final response. NON-const so the nua_hmagic_t* cast does not
 * discard a qualifier. */
char sofia_sipnotify_sentinel;

/* GRUU (gruu=yes): build the +sip.instance Contact-header parameter for a peer's
 * outbound REGISTER — `+sip.instance="<urn:uuid:...>"` (RFC 5626 §4.1). The URN is a
 * stable UUID derived from the server EID + the peer name (deterministic across
 * restarts, unique per peer). Emitted via NUTAG_M_FEATURES (a direct Contact-param
 * append) at every REGISTER site — NOT NUTAG_INSTANCE, which would spin up the sofia
 * outbound engine and emit unwanted validation/keepalive OPTIONS. buf is set to ""
 * when the peer has gruu off, so callers can pass it under TAG_IF(peer->gruu, ...). */
static void sofia_build_instance_feature(const struct sofia_peer *peer, char *buf, size_t len)
{
	char seed[128], hash[33], eidstr[32] = "";

	if (!peer->gruu) {
		buf[0] = '\0';
		return;
	}
	ast_eid_to_str(eidstr, sizeof(eidstr), &ast_eid_default);
	snprintf(seed, sizeof(seed), "gabpbx-sofia-instance:%s:%s", eidstr, S_OR(peer->name, ""));
	ast_md5_hash(hash, seed);	/* 32 lowercase hex chars; format the 128-bit digest as a UUID */
	snprintf(buf, len, "+sip.instance=\"<urn:uuid:%.8s-%.4s-%.4s-%.4s-%.12s>\"",
		hash, hash + 8, hash + 12, hash + 16, hash + 20);
}

static void sofia_event_callback(nua_event_t event, int status, char const *phrase,
		nua_t *nua, nua_magic_t *magic,
		nua_handle_t *nh, nua_hmagic_t *hmagic,
		sip_t const *sip, tagi_t tags[])
{
	struct sofia_pvt *pvt = (struct sofia_pvt *)hmagic;
	/* When hmagic is a dialog pvt, dialog_pvt holds a re-validated +1 ref that
	 * keeps the struct alive for the whole dispatch (released at function exit).
	 * Peer-magic events (REGISTER/qualify/MWI) won't be found in dialogs, leaving
	 * dialog_pvt NULL — they re-cast hmagic to sofia_peer locally and never touch
	 * the pvt local, so that is correct. */
	struct sofia_pvt *dialog_pvt = NULL;
	const char *event_name = nua_event_name(event);

	/* AMI SIPnotify one-shot handle — recognised by its sentinel hmagic. Destroy the
	 * app-owned out-of-dialog NOTIFY handle once the transaction reaches a final response
	 * (sofia-sip never auto-reaps it; NOTIFY is a non-INVITE transaction so the single
	 * final nua_r_notify carries status>=200 — 200/481, or 408 on timeout; provisional/retry
	 * reports status 100). Handled HERE, before the debug logging, the blacklist switch and
	 * the dialog teardown-race ref guard, so the pvt/peer/presence-sub dispatch never sees
	 * the sentinel. dialog_pvt is still NULL here, so the early return skips no ref cleanup.
	 * nua_handle_destroy is legal here because this callback and sipnotify_callback both run
	 * on sofia_thread (same-thread rule). */
	if (hmagic == SOFIA_SIPNOTIFY_HMAGIC) {
		if (event == nua_r_notify && status >= 200) {
			if (sofia_debug) {
				ast_verbose("Sofia SIPnotify: NOTIFY final response %d %s — destroying one-shot handle\n",
					status, phrase);
			}
			nua_handle_destroy(nh);
		}
		return;
	}

	/* outbound PUBLISH (RFC 3903): the generic method responses for publication handles route here
	 * (constant sentinel, never a live pvt/peer/sub pointer) before any dialog dispatch. The specific
	 * publication is found by nh. */
	if (hmagic == SOFIA_PUBLICATION_HMAGIC) {
		if (event == nua_r_method) {
			sofia_publication_handle_response(status, phrase, nh, sip);
		}
		return;
	}

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

	/* Teardown-race guard for the in-dialog request/response events whose hmagic
	 * is unambiguously the dialog pvt and which deref pvt->owner / mutate pvt
	 * concurrently with sofia_hangup on the channel thread (in-dialog INVITE/
	 * REFER/INFO/ACK/BYE/CANCEL requests + the terminated event + INVITE/BYE/
	 * CANCEL responses). Re-validate the hmagic against dialogs and use a
	 * +1-reffed pvt so the struct cannot be freed mid-dispatch; if sofia_hangup
	 * already unlinked it, pvt becomes NULL and the per-handler `if (pvt)` guards
	 * skip cleanly. Other events (peer-magic REGISTER/qualify/MWI, fresh inbound
	 * INVITE with NULL hmagic) keep the original raw-hmagic path unchanged. The
	 * ref is released at the single function-exit drop below; the only early
	 * return (blacklist) is above this point, so no leak path exists. */
	switch (event) {
	case nua_i_invite:
	case nua_i_refer:
	case nua_i_info:
	case nua_i_ack:
	case nua_i_terminated:
	case nua_i_bye:
	case nua_i_cancel:
	case nua_i_message:
	case nua_i_error:
	case nua_r_invite:
	case nua_r_bye:
	case nua_r_cancel:
		dialog_pvt = sofia_pvt_ref_if_linked(hmagic);
		pvt = dialog_pvt;
		break;
	default:
		break;
	}

	switch (event) {
	case nua_i_invite:
		/* hmagic non-NULL means the nh has an existing dialog usage — treat as re-INVITE.
		 * NULL hmagic = fresh inbound INVITE → original sofia_process_invite path.
		 * pvt is now the +1-reffed live dialog (or NULL) from the teardown-race guard.
		 * If hmagic was set but the dialog was torn down concurrently (pvt unlinked by
		 * sofia_hangup), respond 481 rather than spawning a fresh dialog on the dying
		 * handle (which sofia_process_invite would do via nua_handle_bind). */
		if (pvt) {
			sofia_process_reinvite(pvt, nua, nh, sip);
		} else if (hmagic) {
			nua_respond(nh, 481, "Call/Transaction Does Not Exist",
				NUTAG_WITH_THIS(nua), TAG_END());
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
	/* No nua_i_publish dispatch — PUBLISH is not APPL_METHOD'd, so the stack rejects it
	 * (405/501) and never delivers nua_i_publish here. */
	case nua_i_prack:
		sofia_process_prack(nua, nh, pvt, sip, tags);
		break;
	case nua_i_ack:
		sofia_process_ack(nua, nh, pvt, sip, tags);
		break;

	case nua_r_register: {
		/* Pin the peer for the whole handler with the A8 ref-if-linked idiom — a late
		 * REGISTER response on sofia_thread races `sip prune realtime peer` on the CLI
		 * thread, and the 200 branch reads peer fields outside peer->lock, so the REF
		 * (not just the lock) is load-bearing. NULL => peer unlinked/freed: nothing to do. */
		struct sofia_peer *peer = hmagic ? sofia_peer_ref_if_linked((struct sofia_peer *)hmagic) : NULL;
		ast_verbose("Sofia: REGISTER response %d %s\n", status, phrase);
		if (status == 200) {
			if (sip && sip->sip_contact) {
				int expires = DEFAULT_EXPIRY;
				if (sip->sip_expires && sip->sip_expires->ex_delta) {
					/* Clamp the unsigned ex_delta before the int cast — > INT_MAX wraps
					 * negative and corrupts reg_expiry. */
					expires = sip->sip_expires->ex_delta > (unsigned long) INT_MAX
						? INT_MAX : (int) sip->sip_expires->ex_delta;
				} else if (sip->sip_contact->m_expires) {
					long e = strtol(sip->sip_contact->m_expires, NULL, 10);
					expires = (e < 0 || e > INT_MAX) ? DEFAULT_EXPIRY : (int) e;
				}
				if (expires < 0) {
					expires = DEFAULT_EXPIRY;
				}
				ast_verbose("Sofia: Registration OK, expires=%d\n", expires);
				if (peer) {
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
						/* rtupdate (chan_sip parity): the outbound REGISTER response realtime update is gated by
						 * the combined is_realtime && peer_rtupdate check. */
						if (peer->is_realtime && sofia_cfg.peer_rtupdate) {
							/* rtsavesysname (chan_sip parity): inline 2-var setup for the regserver column. */
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
			if (peer) {
				char www_creds[512] = "";
				char proxy_creds[512] = "";
				int have_www = 0, have_proxy = 0;
				char uri[256];

				ast_mutex_lock(&peer->lock);

				/* registerattempts (chan_sip parity): when register_attempts > 0 AND the
				 * peer has reached the cap, give up on auth-challenge re-register to
				 * prevent runaway authentication storms. */
				if (sofia_cfg.register_attempts > 0 && peer->reg_attempts >= sofia_cfg.register_attempts) {
					ast_log(LOG_NOTICE, "Sofia: Registration attempts exhausted for peer '%s' (reg_attempts=%d cap=%d) — giving up\n",
						peer->name, peer->reg_attempts, sofia_cfg.register_attempts);
					ast_mutex_unlock(&peer->lock);
					ao2_ref(peer, -1);
					break;
				}

				/* Build the FULL sofia-sip credential format Digest:"realm":user:secret for
				 * EACH challenge present (a 2-field "user:secret" is silently rejected by
				 * auc_credentials → the challenged REGISTER would carry no Authorization
				 * header). A single response may carry both WWW- and Proxy-Authenticate; feed
				 * both. Lock-free helper, called under the peer->lock we already hold. */
				if (sip->sip_www_authenticate && sofia_format_auth_creds(sip->sip_www_authenticate,
						peer->defaultuser, peer->secret, www_creds, sizeof(www_creds)) == 0) {
					have_www = 1;
				}
				if (sip->sip_proxy_authenticate && sofia_format_auth_creds(sip->sip_proxy_authenticate,
						peer->defaultuser, peer->secret, proxy_creds, sizeof(proxy_creds)) == 0) {
					have_proxy = 1;
				}
				/* Bracket-wrap IPv6 host per RFC 3261 §19.1.2 — peer->host may be a raw
				 * operator-config IPv6 literal (e.g. host=2001:db8::1). Idempotent. */
				{
					char hbuf[80];
					snprintf(uri, sizeof(uri), "sip:%s@%s:%d", peer->defaultuser,
						sofia_uri_format_host(peer->host, hbuf, sizeof(hbuf)),
						peer->port);
				}

				ast_verbose("Sofia: Responding to auth challenge for %s\n", peer->name);

				/* maxforwards: RFC 3261 §20.22 Max-Forwards on the outbound REGISTER. */
				char mf_str_reg[8];
				char instance_feature_reg[120];
				snprintf(mf_str_reg, sizeof(mf_str_reg), "%d", peer->maxforwards);
				/* GRUU: keep the +sip.instance advertisement across the auth-challenge
				 * re-REGISTER too, so the registered binding carries the instance. */
				sofia_build_instance_feature(peer, instance_feature_reg, sizeof(instance_feature_reg));
				/* callbackextension (chan_sip parity, auth-challenge re-REGISTER): when the
				 * peer has callbackextension set, override the Contact URL username via
				 * NUTAG_M_USERNAME. */
				nua_register(peer->nh,
					NUTAG_URL(uri),
					SIPTAG_FROM_STR(uri),
					TAG_IF(have_www, NUTAG_AUTH(www_creds)),
					TAG_IF(have_proxy, NUTAG_AUTH(proxy_creds)),
					SIPTAG_MAX_FORWARDS_STR(mf_str_reg),
					TAG_IF(!ast_strlen_zero(peer->callbackextension),
						NUTAG_M_USERNAME(peer->callbackextension)),
					TAG_IF(peer->gruu, NUTAG_M_FEATURES(instance_feature_reg)),
					TAG_END());

				peer->reg_attempts++;
				ast_mutex_unlock(&peer->lock);
			}
		} else if (status >= 300) {
			ast_verbose("Sofia: Registration failed %d %s\n", status, phrase);
			if (peer) {
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
		if (peer) {
			ao2_ref(peer, -1);
		}
		break;
	}
	case nua_r_invite:
		if (sofia_debug)
			ast_verbose("Sofia: INVITE response %d %s\n", status, phrase);
		/* Capability feature #1 — OUTBOUND INVITE auth. Answer a 401/407 challenge from an upstream
		 * trunk by feeding the peer's credentials to NUA, which restarts the INVITE (carrying its
		 * original SDP) with an Authorization / Proxy-Authorization header (RFC 3261 §22). MUST be
		 * reactive: sofia-sip loads NUTAG_AUTH credentials only after a challenge has created nh_auth
		 * (a proactive NUTAG_AUTH on the initial nua_invite never applies). Matches chan_sip's reactive
		 * handle_response_invite. Scoped to the non-forked dialog (a fork child's 401/407 is treated as
		 * a branch failure below). BOUNDED to a few attempts per dialog so SEQUENTIAL WWW+Proxy
		 * challenges (401 then 407) both get answered, while wrong creds still can't drive an endless
		 * challenge loop. md5secret-only peers are unsupported (NUTAG_AUTH needs the cleartext
		 * password). User/secret are snapshotted with ast_strdupa (no fixed-buffer truncation). */
		if (pvt && sip && !pvt->is_fork_child && !pvt->is_fork_master
				&& (status == 401 || status == 407) && pvt->outbound_invite_auth_attempts < 3) {
			struct sofia_peer *auth_peer = NULL;
			const char *ch_user = "";
			const char *ch_secret = "";
			char www_creds[512] = "";
			char proxy_creds[512] = "";
			int have_www = 0, have_proxy = 0;

			ast_mutex_lock(&pvt->lock);
			pvt->outbound_invite_auth_attempts++;
			if (pvt->peer) {
				ao2_ref(pvt->peer, +1);
				auth_peer = pvt->peer;
			}
			ast_mutex_unlock(&pvt->lock);
			if (auth_peer) {
				ast_mutex_lock(&auth_peer->lock);
				ch_user = ast_strdupa(!ast_strlen_zero(auth_peer->defaultuser)
					? auth_peer->defaultuser : auth_peer->name);
				ch_secret = ast_strdupa(S_OR(auth_peer->secret, ""));
				ast_mutex_unlock(&auth_peer->lock);
				ao2_ref(auth_peer, -1);
			}
			/* A single response may carry BOTH a WWW-Authenticate (endpoint/registrar) AND a
			 * Proxy-Authenticate (proxy) challenge — build a credential for EACH present one and feed
			 * both to NUA in one nua_authenticate call (Codex refinement). */
			if (!ast_strlen_zero(ch_secret)) {
				if (sip->sip_www_authenticate && sofia_format_auth_creds(
						sip->sip_www_authenticate, ch_user, ch_secret, www_creds, sizeof(www_creds)) == 0) {
					have_www = 1;
				}
				if (sip->sip_proxy_authenticate && sofia_format_auth_creds(
						sip->sip_proxy_authenticate, ch_user, ch_secret, proxy_creds, sizeof(proxy_creds)) == 0) {
					have_proxy = 1;
				}
			}
			if (have_www || have_proxy) {
				/* runs on sofia_thread; no lock held — restart the INVITE with the digest(s) */
				nua_authenticate(nh,
					TAG_IF(have_www, NUTAG_AUTH(www_creds)),
					TAG_IF(have_proxy, NUTAG_AUTH(proxy_creds)),
					TAG_END());
				ast_log(LOG_NOTICE,
					"Sofia: outbound INVITE challenged (%d) — re-sending with %s%s%s credentials\n",
					status, have_www ? "WWW" : "", (have_www && have_proxy) ? "+" : "",
					have_proxy ? "Proxy" : "");
				break;	/* NUA restarts the request; stop processing this challenge response */
			}
			ast_log(LOG_NOTICE,
				"Sofia: outbound INVITE challenged (%d) but no usable cleartext credential — call will fail\n",
				status);
		}
		/* Session timers (RFC 4028): capture the negotiated Session-Expires on every
		 * 200 OK (initial + refresh); `sip show channels` reads
		 * pvt->session_negotiated_expires at any dialog-state. The SessionTimerRefresh
		 * AMI event fires only on REFRESH (dialog already UP at response-arrival). */
		if (pvt && status == 200 && sip && sip->sip_session_expires) {
			int already_up;
			char own_name[80];
			char own_uniqueid[150];
			own_name[0] = '\0';
			own_uniqueid[0] = '\0';
			ast_mutex_lock(&pvt->lock);
			already_up = (pvt->state == SOFIA_DIALOG_STATE_UP);
			pvt->session_negotiated_expires = sip->sip_session_expires->x_delta;
			pvt->session_last_refresh_at = time(NULL);
			if (pvt->owner) {
				ast_copy_string(own_name, pvt->owner->name, sizeof(own_name));
				ast_copy_string(own_uniqueid, pvt->owner->uniqueid, sizeof(own_uniqueid));
			}
			ast_mutex_unlock(&pvt->lock);
			if (already_up) {
				/* uac-refresh AMI emit. */
				manager_event(EVENT_FLAG_CALL, "SessionTimerRefresh",
					"Channel: %s\r\n"
					"Uniqueid: %s\r\n"
					"Peer: Sofia/%s\r\n"
					"SessionExpires: %d\r\n"
					"Refresher: %s\r\n"
					"Direction: uac\r\n",
					own_name,
					own_uniqueid,
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
				struct sofia_pvt *m;
				/* Snapshot + ref fork->master under fork->lock so the master pvt
				 * cannot be freed by a concurrent sofia_hangup on the channel
				 * thread. owner is then read/used under master->lock — sofia_hangup
				 * NULLs owner under the same lock, so we either see a live owner
				 * (ref-pinned ast_channel via the queued frame) or NULL and skip. */
				ast_mutex_lock(&fork->lock);
				first = (fork->state == FORK_PRE_RING);
				if (first) fork->state = FORK_RINGING;
				m = fork->master;
				if (m) {
					ao2_ref(m, +1);
				}
				ast_mutex_unlock(&fork->lock);
				if (m) {
					/* ABBA fix: ast_queue_control/ast_setstate re-lock the channel,
					 * so snapshot+ref m->owner UNDER m->lock, DROP m->lock, then
					 * queue on the reffed owner — never hold m->lock (pvt) across a
					 * fresh channel lock (would invert channel->pvt vs ast_hangup ->
					 * sofia_hangup). Mirrors sofia_fork_pick_winner @2532-2543. */
					struct ast_channel *m_owner;
					ast_mutex_lock(&m->lock);
					m_owner = m->owner;
					if (m_owner) {
						ast_channel_ref(m_owner);
					}
					ast_mutex_unlock(&m->lock);
					if (m_owner) {
						if (status == 183) {
							ast_queue_control(m_owner, AST_CONTROL_PROGRESS);
						} else {
							ast_queue_control(m_owner, AST_CONTROL_RINGING);
						}
						ast_setstate(m_owner, AST_STATE_RINGING);
						ast_channel_unref(m_owner);
					}
					ao2_ref(m, -1);
				}
				if (sofia_debug)
					ast_verbose("Sofia: Fork child %s -> %d %s (first=%d)\n",
						pvt->fork_branch_id, status, phrase, first);
			} else if (status >= 200 && status < 300) {
				int rc = sofia_fork_pick_winner(fork, pvt, sip);
				if (rc != 0) {
					/* This 2xx is rejected (encryption/SDP mismatch, or another
					 * branch already won). CANCEL is invalid once the INVITE is
					 * >= 200 (sofia-sip returns 481 "No transaction to CANCEL"), so
					 * tear the answered branch down with BYE (NUA auto-ACKs then
					 * BYEs), then run the shared dead-child accounting — which was
					 * previously skipped here, leaving child_count inflated. */
					nua_bye(pvt->nh, TAG_END());
					sofia_fork_child_failed(fork, pvt);
				}
			} else if (status >= 300) {
				int remaining = sofia_fork_child_failed(fork, pvt);
				if (sofia_debug)
					ast_verbose("Sofia: Fork child %s failed %d %s (remaining=%d)\n",
						pvt->fork_branch_id, status, phrase, remaining);
			}
			break;
		}
		if (pvt && pvt->reinvite_pending && status >= 200) {
			/* Direct media re-INVITE response — call is already up.
			 * pvt->reinvite_pending and pvt->redirip are shared with the gabpbx
			 * bridge thread (sofia_set_rtp_peer); guard with pvt->lock. */
			int rejected = (status >= 300);
			int has_sdp = (!rejected && sip && sip->sip_payload && sip->sip_payload->pl_data);
			int sdp_rc = 0;		/* R7 C4: capture sofia_parse_sdp() on the 2xx */
			int reverted_to_relay = 0;	/* R7 C4: the revert re-INVITE actually fired (vs guard-skipped) */
			struct ast_channel *owner = NULL;
			ast_mutex_lock(&pvt->lock);
			/* Re-acquire in canonical channel->pvt order so sofia_parse_sdp's
			 * set_format re-enters a channel lock we already hold instead of
			 * inverting against ast_hangup. Mirrors chan_sip sip_pvt_lock_full:
			 * ref owner, drop pvt, lock channel, relock pvt, revalidate identity
			 * (owner may be swapped by a masquerade or cleared by a concurrent
			 * hangup during the window). */
			for (;;) {
				owner = pvt->owner;
				if (!owner) {
					break;
				}
				ast_channel_ref(owner);
				ast_mutex_unlock(&pvt->lock);
				ast_channel_lock(owner);
				ast_mutex_lock(&pvt->lock);
				if (pvt->owner == owner) {
					break;
				}
				ast_channel_unlock(owner);
				ast_channel_unref(owner);
				owner = NULL;
			}
			pvt->reinvite_pending = 0;
			if (rejected) {
				/* Peer refused (488 Not Acceptable etc); revert to PBX relay. */
				memset(&pvt->redirip, 0, sizeof(pvt->redirip));
			} else if (has_sdp) {
				/* 2xx — peer accepted; SDP tells us where they will send. */
				sdp_rc = sofia_parse_sdp(pvt, sip);
			}
			/* Unlock the owner channel BEFORE the possible relay re-INVITE so
			 * sofia_send_reinvite runs under pvt->lock ALONE — matching the normal
			 * directmedia-reinvite lock profile and minimizing the lock-held window across
			 * nua_invite. */
			if (owner) {
				/* Release the channel LOCK now (so the relay re-INVITE runs under pvt->lock alone),
				 * but KEEP the owner ref — the unref is DEFERRED until after pvt->lock is dropped,
				 * because dropping the last ref here could run the channel destructor under pvt->lock. */
				ast_channel_unlock(owner);
			}
			if (!rejected && has_sdp && sdp_rc < 0
			    && !pvt->alreadygone && pvt->state == SOFIA_DIALOG_STATE_UP && pvt->nh) {
				/* A 2xx is FINAL — we cannot 488 it. The directmedia answer was unusable
				 * (sofia_parse_sdp rejected it; pvt media state is left unchanged on a reject), so
				 * revert to PBX relay: clear redirip so sofia_generate_sdp builds a relay SDP, and send
				 * a fresh non-directmedia re-INVITE to bring media back through the PBX. Guarded against
				 * a teardown race by the same !alreadygone && state==UP && nh gate
				 * sofia_directmedia_reinvite_root uses, so a 2xx arriving during hangup never fires a
				 * late re-INVITE. sofia_send_reinvite sets reinvite_pending so a stray bridge tick
				 * cannot race a second re-INVITE; sofia-sip sequences it after the 2xx is ACKed. */
				memset(&pvt->redirip, 0, sizeof(pvt->redirip));
				sofia_send_reinvite(pvt);
				reverted_to_relay = 1;
			}
			ast_mutex_unlock(&pvt->lock);
			if (owner) {
				/* unref AFTER pvt->lock is dropped. */
				ast_channel_unref(owner);
				owner = NULL;
			}
			if (rejected) {
				ast_log(LOG_NOTICE, "Sofia: directmedia re-INVITE rejected on '%s' (%d %s) — staying in relay mode\n",
					pvt->callid ? pvt->callid : "(no-callid)", status, phrase ? phrase : "");
			} else if (reverted_to_relay) {
				ast_log(LOG_WARNING, "Sofia: directmedia re-INVITE 2xx had an unusable SDP on '%s' — reverted to relay\n",
					pvt->callid ? pvt->callid : "(no-callid)");
			} else if (has_sdp && sdp_rc < 0) {
				/* unusable SDP but the call was no longer UP (teardown race) — the revert was
				 * correctly skipped; nothing to do, the call is going down. */
				ast_log(LOG_NOTICE, "Sofia: directmedia re-INVITE 2xx had an unusable SDP on '%s' but the call is no longer up — not reverting\n",
					pvt->callid ? pvt->callid : "(no-callid)");
			} else if (has_sdp) {
				ast_verbose("Sofia: directmedia re-INVITE accepted on '%s'\n",
					pvt->callid ? pvt->callid : "(no-callid)");
			}
			break;
		}
		if (pvt) {
			struct ast_channel *owner = NULL;
			if (status == 180) {
				ast_mutex_lock(&pvt->lock);
				pvt->state = SOFIA_DIALOG_STATE_RINGING;
				owner = pvt->owner;
				if (owner) ast_channel_ref(owner);
				ast_mutex_unlock(&pvt->lock);
				if (sip && sip->sip_payload && sip->sip_payload->pl_data) {
					sofia_parse_sdp(pvt, sip);
				}
				if (owner) {
					ast_queue_control(owner, AST_CONTROL_RINGING);
					ast_setstate(owner, AST_STATE_RINGING);
					ast_channel_unref(owner);
					owner = NULL;
				}
			} else if (status == 183) {
				ast_mutex_lock(&pvt->lock);
				owner = pvt->owner;
				if (owner) ast_channel_ref(owner);
				ast_mutex_unlock(&pvt->lock);
				if (sip && sip->sip_payload && sip->sip_payload->pl_data) {
					sofia_parse_sdp(pvt, sip);
				}
				if (owner) {
					ast_queue_control(owner, AST_CONTROL_PROGRESS);
					ast_setstate(owner, AST_STATE_RINGING);
					ast_channel_unref(owner);
					owner = NULL;
				}
			} else if (status == 200) {
				/* RFC 3261 §13.2.2.4 / RFC 6026: a 200 OK for an INVITE we have already abandoned (a
				 * forking proxy sent 486 Busy Here and then 200 OK on the same dialog, or we already
				 * hung up the leg) must be ACKed and then BYEd, not turned into an answered call.
				 * Dropping it leaves the UAS retransmitting its 200 OK for 64*T1 with a ghost media leg.
				 * This only fires if the late 2xx is still delivered, i.e. the pvt / nua handle survived
				 * the orphan window. The handle is released in sofia_pvt_destructor when the last pvt ref
				 * drops (RFC 6026 Timer M = 64*T1). */
				ast_mutex_lock(&pvt->lock);
				if (pvt->alreadygone || !pvt->owner) {
					ast_mutex_unlock(&pvt->lock);
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
				owner = pvt->owner;
				ast_channel_ref(owner);
				ast_mutex_unlock(&pvt->lock);

				int sdp_rc = 0;
				if (sip && sip->sip_payload && sip->sip_payload->pl_data) {
					sdp_rc = sofia_parse_sdp(pvt, sip);
				}
				/* The final 2xx may carry Diversion if a downstream proxy redirected.
				 * Update the redirecting chain on the master/originating channel. */
				sofia_change_redirecting_info(pvt, owner, sip);
				/* Outbound ringing transition complete on 200 OK: decrement inRinging
				 * (the call stays in the inUse pool, decremented at hangup). */
				sofia_update_call_counter(pvt, SOFIA_DEC_CALL_RINGING);
				if (sdp_rc < 0) {
					/* Peer's 200 OK answer failed encryption policy (no a=crypto echo, downgraded to AVP,
					 * or invalid crypto). Tear down — BYE peer + queue HANGUP to channel. */
					ast_log(LOG_NOTICE, "Sofia: outbound 200 OK rejected — encryption mismatch in answer (peer=%s)\n",
						pvt->peer ? pvt->peer->name : "<unknown>");
					nua_bye(nh, TAG_END());
					ast_queue_control(owner, AST_CONTROL_HANGUP);
					ast_channel_unref(owner);
					owner = NULL;
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
				ast_mutex_lock(&pvt->lock);
				pvt->state = SOFIA_DIALOG_STATE_UP;
				ast_mutex_unlock(&pvt->lock);
				ast_queue_control(owner, AST_CONTROL_ANSWER);
				ast_setstate(owner, AST_STATE_UP);
				/* Set active contact for single-contact outbound path */
				if (pvt->peer && !pvt->is_fork_child && !pvt->fork && !ast_strlen_zero(pvt->ruri)) {
					const char *at = strchr(pvt->ruri, '@');
					if (at) {
						char rhost[64] = "";
						int rport = 5060;
						sofia_split_hostport_from_uri(at + 1, rhost, sizeof(rhost), &rport);	/* R6 #5: IPv6-aware */
						struct sofia_contact *contact = sofia_peer_find_contact_by_host_port(pvt->peer, rhost, rport);
						if (contact) {
							sofia_pvt_set_active_contact(pvt, contact);
							ao2_ref(contact, -1);
						}
					}
				}
				ast_channel_unref(owner);
				owner = NULL;
			} else if (status == 484) {
				/* allowoverlap (chan_sip parity, outbound 484 response): ALLOWOVERLAP_YES propagates
				 * AST_CAUSE_INVALID_NUMBER_FORMAT (484 native semantic); NO/DTMF propagates
				 * AST_CAUSE_UNALLOCATED (404 semantic — hides overlap-dial reality from the caller).
				 * Effective mode = peer when bound, else sofia_cfg.default_allowoverlap_mode. */
				/* Mark the dialog gone BEFORE the channel hangup races, so a late 2xx
				 * (RFC 3261 §16.7-violating proxy) can be ACK+BYE'd by the orphan guard at the
				 * status==200 branch above (chan_sip parity: sip_alreadygone after the final-response switch). */
				ast_mutex_lock(&pvt->lock);
				sofia_alreadygone(pvt);
				owner = pvt->owner;
				if (owner) ast_channel_ref(owner);
				ast_mutex_unlock(&pvt->lock);
				if (owner) {
					int overlap_mode = pvt->peer ? pvt->peer->allowoverlap_mode : sofia_cfg.default_allowoverlap_mode;
					ast_queue_hangup_with_cause(owner,
						(overlap_mode == SOFIA_OVERLAP_YES)
							? AST_CAUSE_INVALID_NUMBER_FORMAT
							: AST_CAUSE_UNALLOCATED);
					ast_channel_unref(owner);
					owner = NULL;
				}
			} else if (status >= 300) {
				/* Mark the dialog gone for the same reason as the 484 branch above: a forking proxy may
				 * relay a non-2xx final and then a 2xx on the same transaction (RFC 3261 §16.7 violation).
				 * Setting alreadygone here lets the status==200 orphan guard recognise the late 2xx and
				 * emit ACK+BYE per RFC 3261 §13.2.2.4 / RFC 6026 instead of dropping it silently. */
				ast_mutex_lock(&pvt->lock);
				sofia_alreadygone(pvt);
				owner = pvt->owner;
				if (owner) ast_channel_ref(owner);
				ast_mutex_unlock(&pvt->lock);
				if (owner) {
					ast_queue_control(owner, AST_CONTROL_HANGUP);
					ast_channel_unref(owner);
					owner = NULL;
				}
			}
		}
		break;
	case nua_r_bye:
		if (sofia_debug)
			ast_verbose("Sofia: BYE response %d %s\n", status, phrase);
		/* nua_r_bye DEC site (defensive — sofia_hangup usually already fired DEC, but the
		 * flag-gated idempotency keeps multi-site safe). */
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
			/* Revalidate the peer hmagic against the peers container and pin it with a +1 ref
			 * before any deref — `sip prune realtime` can free this peer on the CLI thread while
			 * the OPTIONS response is in flight. If it is already gone, drop the stale response.
			 * The ref is released before the case breaks below. */
			struct sofia_peer *peer = sofia_peer_ref_if_linked((struct sofia_peer *)hmagic);
			int pingtime;
			if (!peer) {
				if (sofia_debug)
					ast_verbose("Sofia: OPTIONS response for a pruned/freed peer (hmagic=%p) — dropped\n",
						(void *)hmagic);
				break;
			}
			pingtime = ast_tvdiff_ms(ast_tvnow(), peer->qualify_sent);
			/* Compute the new status + snapshot what the blocking bookkeeping needs UNDER
			 * peer->lock, then RELEASE the lock and do manager_event / ast_devstate_changed /
			 * register_peer_exten (dialplan contexts rwlock) / nua_handle_destroy OUTSIDE it. This
			 * avoids nesting peer->lock over the contexts rwlock (the file's only such inversion) +
			 * a long blocking hold of peer->lock, matching the REGISTER-success path. The peer
			 * cannot be freed across the unlock: reload's mark-and-sweep runs on sofia_thread, the
			 * same thread as this handler, so they are serialised. */
			int transitioned = 0, do_regexten_add = 0, do_regexten_remove = 0, l_lastms = -1;
			const char *new_name = "";
			char l_name[256] = "";
			nua_handle_t *old_qnh = NULL;

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
					transitioned = 1;
					new_name =
						peer->peer_status == PEER_REACHABLE ? "Reachable" :
						peer->peer_status == PEER_LAGGED ? "Lagged" : "Unreachable";
					l_lastms = peer->lastms;
					ast_copy_string(l_name, peer->name, sizeof(l_name));
					if (sofia_cfg.regextenonqualify) {
						if (peer->peer_status == PEER_REACHABLE) {
							do_regexten_add = 1;
						} else if (peer->peer_status == PEER_UNREACHABLE) {
							do_regexten_remove = 1;
						}
					}
				}
			}
			if (peer->qualify_nh) {
				/* Detach hmagic before destroying the previous qualify cycle's
				 * handle (see the MWI re-subscribe rationale): bind(NULL) is
				 * synchronous + thread-safe so it stays under the lock; the
				 * nua_handle_destroy is moved outside. */
				old_qnh = peer->qualify_nh;
				peer->qualify_nh = NULL;
				nua_handle_bind(old_qnh, NULL);
			}
			/* Reset qualify_sent so next cycle calculates fresh pingtime */
			memset(&peer->qualify_sent, 0, sizeof(peer->qualify_sent));
			peer->last_qualify = ast_tvnow();
			ast_mutex_unlock(&peer->lock);

			/* Blocking / contexts-rwlock / nua_* bookkeeping, OUTSIDE peer->lock. */
			if (transitioned) {
				ast_verbose("Sofia: Peer '%s' is now %s (%dms)\n", l_name, new_name, l_lastms);
				manager_event(EVENT_FLAG_SYSTEM, "PeerStatus",
					"ChannelType: SIP\r\n"
					"Peer: SIP/%s\r\n"
					"PeerStatus: %s\r\n"
					"Time: %d\r\n",
					l_name, new_name, l_lastms);
				/* BLF/presence: reachability changed -> re-evaluate hint. */
				ast_devstate_changed(AST_DEVICE_UNKNOWN, AST_DEVSTATE_CACHABLE, "SIP/%s", l_name);
				/* regextenonqualify: ADD on REACHABLE, REMOVE on UNREACHABLE (LAGGED fires neither).
				 * Gated on regextenonqualify; the helper further gates on regcontext non-empty. */
				if (do_regexten_add) {
					register_peer_exten(peer, 1);
				} else if (do_regexten_remove) {
					register_peer_exten(peer, 0);
				}
			}
			if (old_qnh) {
				nua_handle_destroy(old_qnh);
			}
			ao2_ref(peer, -1);	/* drop the revalidation ref */
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
		/* Expiry/terminate of a presence subscription: sofia-sip auto-sends the
		 * final NOTIFY and reports nua_substate_terminated here. Correlate to the
		 * watcher by handle (type-safe iteration) and free it. */
		if (sofia_substate_terminated(tags)) {
			struct sofia_presence_sub *psub = sofia_presence_find_by_nh(nh);
			if (psub) {
				sofia_presence_teardown(psub, 0);
				ao2_ref(psub, -1);
			}
		}
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
			ast_mutex_lock(&pvt->lock);
			pvt->state = SOFIA_DIALOG_STATE_DOWN;
			ast_mutex_unlock(&pvt->lock);
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

	/* Release the teardown-race guard ref taken for in-dialog request/response
	 * events (NULL for every other event). Single drop — the only early return
	 * (blacklist) is above the ref acquisition, so this is reached on all paths
	 * that took the ref. */
	if (dialog_pvt) {
		ao2_ref(dialog_pvt, -1);
	}
}

/* feature #6: forward decl — defined near the config parser, used at nua_create below. */
static unsigned sofia_tls_min_version_mask(const char *v);

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

	/* Per-transport URLs passed as separate sofia-sip tags (NUTAG_URL + NUTAG_SIPS_URL +
	 * NUTAG_WS_URL + NUTAG_WSS_URL). Comma-concatenation into NUTAG_URL is rejected by the
	 * sofia-sip URL parser. */
	{
		char udp_url[128];
		char tls_url[128] = "";
		char ws_url[128]  = "";
		char wss_url[128] = "";
		int needs_cert;

		/* IPv6 bind: listener bind URLs bracket-wrap an IPv6 host (RFC 3261 §19.1.2) via
		 * sofia_uri_format_host. Operator config bindaddr=`::` (dual-stack) or `2001:db8::1`
		 * (literal) gets bracket-wrapped; IPv4 literals + hostnames pass through unchanged.
		 * Wildcard `*` (no-bindaddr fallback) passes through (no `:` so the helper is a no-op). */
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

		/* feature #5: warn on a pingpong-without-keepalive misconfig — it is silently ignored
		 * (the gate below only applies PINGPONG alongside KEEPALIVE) since a pong is only
		 * expected after a ping. */
		if (sofia_cfg.tcp_pingpong_ms > 0 && sofia_cfg.tcp_keepalive_ms == 0) {
			ast_log(LOG_WARNING, "Sofia: tcp_pingpong is set but tcp_keepalive is 0 — pingpong needs "
				"keepalive to send the ping, so it is ignored. Set tcp_keepalive to enable both.\n");
		}

		sofia_nua = nua_create(sofia_root,
			sofia_event_callback,
			NULL,
			NUTAG_URL(udp_url),
			TAG_IF(tls_url[0], NUTAG_SIPS_URL(tls_url)),
			TAG_IF(ws_url[0],  NUTAG_WS_URL(ws_url)),
			TAG_IF(wss_url[0], NUTAG_WSS_URL(wss_url)),
			TAG_IF(needs_cert && !ast_strlen_zero(sofia_cfg.tlscertfile),
				NUTAG_CERTIFICATE_DIR(sofia_cfg.tlscertfile)),
			/* Opt-in peer-certificate verification. Default OFF keeps sofia-sip's TPTLS_VERIFY_NONE
			 * (no handshake change). With tlsverify=yes the OUTGOING (client-side) server certificate
			 * chain + subject + validity date are verified against the CA material in tlscertfile —
			 * closes the silent accept-any-cert MITM exposure on outbound TLS/WSS trunks/registrations. */
			TAG_IF(needs_cert && sofia_cfg.tlsverify,
				TPTAG_TLS_VERIFY_POLICY(TPTLS_VERIFY_SUBJECTS_OUT)),
			TAG_IF(needs_cert && sofia_cfg.tlsverify,
				TPTAG_TLS_VERIFY_DATE(1)),
			/* feature #6: TLS-listener hardening (opt-in; affects the TLS listener only — the WSS
			 * listener builds its own SSL_CTX and ignores these). Each is applied only when the
			 * operator set it, so an unset knob keeps sofia-sip's default (no behavior change). */
			TAG_IF(needs_cert && !ast_strlen_zero(sofia_cfg.tls_ciphers),
				TPTAG_TLS_CIPHERS(sofia_cfg.tls_ciphers)),
			TAG_IF(needs_cert && !ast_strlen_zero(sofia_cfg.tls_min_version),
				TPTAG_TLS_VERSION(sofia_tls_min_version_mask(sofia_cfg.tls_min_version))),
			TAG_IF(needs_cert && sofia_cfg.tls_verify_depth > 0,
				TPTAG_TLS_VERIFY_DEPTH((unsigned)sofia_cfg.tls_verify_depth)),
			NUTAG_MEDIA_ENABLE(0),
			NUTAG_ALLOW("INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, REFER, MESSAGE, INFO, PRACK"),
			NUTAG_APPL_METHOD("REGISTER"),
			NUTAG_ALLOW_EVENTS("presence"),
			NUTAG_ALLOW_EVENTS("dialog"),
			NUTAG_ALLOW_EVENTS("message-summary"),
			NUTAG_ALLOW_EVENTS("refer"),
			NUTAG_ALLOW_EVENTS("presence.winfo"),
			NUTAG_M_USERNAME("*"),
			SIPTAG_EXPIRES_STR("3600"),
			/* timert1 (RFC 3261 §17.1.1.1): NTATAG_SIP_T1 is the T1 retransmission interval (ms;
			 * default 500), used by request retransmission timers A and E (UDP) and response
			 * retransmission timer G. NOT the t1min minimum-bound (sofia_cfg.t1min is consumed
			 * separately as the per-peer parser fallback floor). Wired from
			 * sofia_cfg.default_timer_t1 (500ms, chan_sip-faithful per DEFAULT_TIMER_T1), NOT
			 * sofia_cfg.t1min — affects ALL SIP transactions globally. */
			NTATAG_SIP_T1(sofia_cfg.default_timer_t1),
			/* timerb: NTATAG_SIP_T1X64 at nua_create caps the INVITE transaction timeout at
			 * default_timer_b ms (RFC 3261 §17.1.1.2). */
			TAG_IF(sofia_cfg.default_timer_b,
				NTATAG_SIP_T1X64(sofia_cfg.default_timer_b)),
			/* tos/cos: TPTAG_TOS at nua_create applies the SIP-listener-side TOS via setsockopt at
			 * the UDP/TCP transport level. */
			TAG_IF(sofia_cfg.tos_sip, TPTAG_TOS((int)sofia_cfg.tos_sip)),
			/* feature #5: application-level connection keepalive. TPTAG_KEEPALIVE sends a periodic
			 * CRLF on an idle connection-oriented transport to hold the NAT binding open (so an
			 * inbound request still reaches a TCP-registered phone); TCP-only — sofia-sip's TLS/WS
			 * vtables do not drive this timer. TPTAG_PINGPONG treats the connection as dead if no
			 * pong follows the keepalive within the window. Both default OFF (opt-in via [general]
			 * tcp_keepalive / tcp_pingpong, seconds). Socket-level SO_KEEPALIVE is already on by
			 * default (sofia-sip ~30s). */
			TAG_IF(sofia_cfg.tcp_keepalive_ms > 0, TPTAG_KEEPALIVE((unsigned)sofia_cfg.tcp_keepalive_ms)),
			/* pingpong is meaningless without keepalive (no ping -> no pong is ever expected), so it is
			 * applied only alongside keepalive (Codex); a pingpong-without-keepalive config is warned
			 * about at parse time. */
			TAG_IF(sofia_cfg.tcp_keepalive_ms > 0 && sofia_cfg.tcp_pingpong_ms > 0,
				TPTAG_PINGPONG((unsigned)sofia_cfg.tcp_pingpong_ms)),
			/* useragent: SIPTAG_USER_AGENT_STR at nua_create installs the User-Agent + Server
			 * header value; sofia-sip emits it on every outbound request + response automatically.
			 * Empty-string default skips the tag via TAG_IF (sofia-sip falls back to its default). */
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
		NUTAG_ALLOW("INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, REFER, MESSAGE, INFO, PRACK"),
		TAG_END());

	/* Add methods to appl_method one at a time */
	nua_set_params(sofia_nua, NUTAG_APPL_METHOD("REGISTER"), TAG_END());
	nua_set_params(sofia_nua, NUTAG_APPL_METHOD("SUBSCRIBE"), TAG_END());
	/* PUBLISH is intentionally NOT application-handled — there is no RFC 3903 event-state
	 * server here, so the stack itself rejects an inbound PUBLISH (405/501) instead of a
	 * stub answering a false 200 OK (and leaking the un-reaped APPL_METHOD handle). */
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

	/* Presence/BLF expiry sweep. sofia-sip does not auto-expire app-responded
	 * (nua_respond) subscriptions, so we run our own recurring teardown of stale
	 * watchers. The su_timer fires on THIS thread (sofia_thread) — the single
	 * owner of presence_subs and all nua_* — so no cross-thread dispatch needed. */
	presence_expiry_timer = su_timer_create(su_root_task(sofia_root), SOFIA_PRESENCE_SWEEP_MS);
	if (presence_expiry_timer) {
		su_timer_set_for_ever(presence_expiry_timer, sofia_presence_expiry_sweep, NULL);
	} else {
		ast_log(LOG_WARNING, "Sofia presence: expiry sweep timer create failed — stale "
			"subscriptions will only clear on explicit unsubscribe\n");
	}

	/* Outbound PUBLISH (RFC 3903): on sofia_thread (the nua_* owner), create a publication
	 * per publish=yes peer (each is SCHEDULED, not sent inline) and arm the ~1 Hz sweep that
	 * drives all PUBLISH emission. Feature is OFF unless publish_server is set.
	 * RELOAD LIFECYCLE: this is the STARTUP create pass. A later `sip reload` reconciles the
	 * live publication set in sofia_publications_reconcile (also on sofia_thread) — adding new
	 * publish=yes peers, unpublishing dropped ones, rebuilding when publish_server/domain/
	 * expires change. No restart is needed for PUBLISH config; only a listener change is. */
	sofia_publications_start();

	su_root_run(sofia_root);

	if (presence_expiry_timer) {
		su_timer_destroy(presence_expiry_timer);
		presence_expiry_timer = NULL;
	}

	/* Outbound PUBLISH teardown — on sofia_thread, after the event loop ends: unpublish + destroy
	 * every publication handle, then stop the refresh timer. */
	sofia_publications_stop();

	/* Ownership-correct teardown. su_root_destroy enforces same-thread-as-su_root_create
	 * (sofia-sip internal assert; cross-thread destroy aborts via __assert_fail).
	 * unload_module signals us via nua_shutdown + su_root_break + pthread_join; we destroy
	 * here in our own thread context so the assert never fires. Order: nua_destroy first
	 * (drops the NUA event-loop registrations), then su_root_destroy (event loop dead,
	 * structures freed), then su_deinit (process-wide cleanup paired with su_init() above). */
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

		/* reload-UAF fix: peer->name and peer->host are unbounded stringfields the reload writer
		 * (sofia_parse_peer_config on sofia_thread) frees/reallocates under peer->lock. Snapshot
		 * them into locals while holding peer->lock, then drop the lock before the blocking
		 * ast_cli. 256 is generous (the fields are unbounded) to avoid the truncation class the
		 * show_peer l_name[256] fix addressed. */
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
		{
			/* Snapshot everything we print under pvt->lock, then release the lock BEFORE the
			 * (potentially blocking) ast_cli write — chan_sip's _sip_show_peer idiom. callid/peername
			 * are AST_STRING_FIELDs that other threads reassign under pvt->lock, so they must be
			 * copied into local buffers rather than printed by pointer after the unlock. The
			 * Session-Timer column shows N/M = seconds-since-last-refresh / negotiated Session-Expires;
			 * (none) = no session timer active for this call. */
			char callid_buf[256];
			char peername_buf[256];
			char st_buf[24];

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
			if (pvt->session_negotiated_expires > 0) {
				time_t since = pvt->session_last_refresh_at
					? (time(NULL) - pvt->session_last_refresh_at) : 0;
				snprintf(st_buf, sizeof(st_buf), "%lds/%ds",
					(long)since, pvt->session_negotiated_expires);
			} else {
				ast_copy_string(st_buf, "(none)", sizeof(st_buf));
			}
			ast_copy_string(callid_buf, S_OR(pvt->callid, ""), sizeof(callid_buf));
			ast_copy_string(peername_buf, S_OR(pvt->peername, ""), sizeof(peername_buf));
			ast_mutex_unlock(&pvt->lock);

			ast_cli(a->fd, "%-40s %-20s %-10s %-15s\n",
				callid_buf,
				peername_buf,
				state_str,
				st_buf);
		}
		count++;
		ao2_ref(pvt, -1);
	}
	ao2_iterator_destroy(&i);

	ast_cli(a->fd, "%d active sofia channel%s\n", count, count != 1 ? "s" : "");
	return CLI_SUCCESS;
}

#define SOFIA_CLI_PEER_RULE_WIDTH 78
#define SOFIA_CLI_PEER_LABEL_WIDTH 20

/* Peer-dump output is assembled into an ast_str under peer->lock, then emitted with a
 * single blocking ast_cli/astman_append AFTER the lock is dropped. These helpers
 * therefore append into *out instead of writing to an fd; every call site lives inside
 * sofia_cli_show_peer. */
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

/* Forward decl: peer-name tab-completion helper (defined later, used by the CLI_GENERATE
 * case below so "sip show peer <TAB>" lists the peers in RAM, chan_sip parity).
 * only_realtime=0 => offer every peer. */
static char *complete_sofia_peer(const char *word, int state, int only_realtime);

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
	struct ast_str *buf;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show peer";
		e->usage = "Usage: sip show peer <name>\n"
			   "       Show detailed info for a Sofia-SIP peer\n";
		return NULL;
	case CLI_GENERATE:
		/* "sip show peer <name>": complete the peer name (token 3) from the peers in RAM, by
		 * prefix. chan_sip parity. */
		if (a->pos == 3) {
			return complete_sofia_peer(a->word, a->n, 0);
		}
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

	/* Assemble all output here while holding peer->lock, then emit it with a single blocking
	 * ast_cli AFTER the unlock. Allocate before locking and bail if allocation fails so we
	 * never hold the lock with nowhere to write. */
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
	sofia_cli_peer_line(&buf, "Expires", "%ds", peer->expiresecs);
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
	sofia_cli_peer_line(&buf, "Codecs", "%s", ast_strlen_zero(codec_buf) ? "(default)" : codec_buf);
	sofia_cli_peer_line(&buf, "Max call BR", "%d kbps", peer->maxcallbitrate);

	sofia_cli_peer_section(&buf, "Limits and features");
	sofia_cli_peer_line(&buf, "Busy on active", "%s", AST_CLI_YESNO(peer->busy_on_active));
	sofia_cli_peer_line(&buf, "Max contacts", "%d (used: %d)", peer->max_contacts, contacts_used);
	/* allowtransfer (chan_sip parity): REFER policy display. */
	sofia_cli_peer_line(&buf, "Transfer mode", "%s", sofia_transfer_mode_str(peer->allowtransfer));
	/* lockuseragent (chan_sip parity): plus the current locked UA string for inspection. */
	sofia_cli_peer_line(&buf, "Lock user-agent", "%s", AST_CLI_YESNO(peer->lockuseragent));
	if (peer->lockuseragent && peer->locked_user_agent[0]) {
		sofia_cli_peer_line(&buf, "Locked UA", "%s", peer->locked_user_agent);
	}
	if (peer->lockuseragent && !ast_strlen_zero(peer->lockuseragent_prefixes)) {
		sofia_cli_peer_line(&buf, "UA prefixes", "%s", peer->lockuseragent_prefixes);
	}
	/* language (chan_sip parity): per-peer audio locale display. */
	sofia_cli_peer_line(&buf, "Language", "%s", ast_strlen_zero(peer->language) ? "(none)" : peer->language);
	/* defaultip (chan_sip parity): Defaddr->IP display. */
	sofia_cli_peer_line(&buf, "Default IP", "%s", ast_sockaddr_stringify(&peer->defaddr));
	/* amaflags (chan_sip parity): via ast_cdr_flags2str. */
	sofia_cli_peer_line(&buf, "AMA flags", "%s", ast_cdr_flags2str(peer->amaflags));
	/* subscribemwi (chan_sip parity): yes/no display. */
	sofia_cli_peer_line(&buf, "Subscribe MWI", "%s", AST_CLI_YESNO(peer->subscribemwi));
	/* preferred_codec_only (chan_sip parity): yes/no display. */
	sofia_cli_peer_line(&buf, "Preferred codec", "%s", AST_CLI_YESNO(peer->preferred_codec_only));
	/* ignoresdpversion (chan_sip parity): parse-compat-only (chan_sofia processes every
	 * SDP unconditionally). */
	sofia_cli_peer_line(&buf, "Ignore SDP ver", "%s", AST_CLI_YESNO(peer->ignoresdpversion));
	/* promiscredir (chan_sip parity): parse-compat-only (no nua_r_redirect handler). */
	sofia_cli_peer_line(&buf, "Promisc redir", "%s", AST_CLI_YESNO(peer->promiscredir));
	/* autoframing (chan_sip parity): parse-compat-only (ptime gate not wired today). */
	sofia_cli_peer_line(&buf, "Auto framing", "%s", AST_CLI_YESNO(peer->autoframing));
	/* faxdetect per-peer display: the runtime mode used by DSP CNG detection and peer T.38
	 * reINVITE detection. */
	sofia_cli_peer_line(&buf, "Fax detect", "%s",
		peer->faxdetect_mode == SOFIA_FAX_DETECT_NONE ? "no" :
		peer->faxdetect_mode == SOFIA_FAX_DETECT_BOTH ? "yes (cng,t38)" :
		peer->faxdetect_mode == SOFIA_FAX_DETECT_CNG ? "cng" : "t38");
	sofia_cli_peer_section(&buf, "Fax and T.38");
	/* 5-field T.38 display (chan_sip parity): support enable + EC mode + MaxDatagram +
	 * t38pt_usertpsource + per-peer overrides, for operator visibility into T.38 policy. */
	sofia_cli_peer_line(&buf, "T38 support", "%s", AST_CLI_YESNO(peer->t38pt_udptl));
	sofia_cli_peer_line(&buf, "T38 EC mode", "%s",
		peer->t38_ec_mode == SOFIA_T38_EC_REDUNDANCY ? "Redundancy" :
		peer->t38_ec_mode == SOFIA_T38_EC_FEC ? "FEC" : "None");
	sofia_cli_peer_line(&buf, "T38 max datagram", "%d", peer->t38_maxdatagram);
	sofia_cli_peer_line(&buf, "T38 RTP source", "%s", AST_CLI_YESNO(peer->t38pt_usertpsource));
	sofia_cli_peer_section(&buf, "Timers and RTP");
	/* timerb (chan_sip parity): NTATAG_SIP_T1X64 wired at nua_create. */
	sofia_cli_peer_line(&buf, "Timer B", "%d", peer->timer_b);
	/* timert1 (chan_sip parity): NTATAG_SIP_T1 wired at nua_create. */
	sofia_cli_peer_line(&buf, "Timer T1", "%d", peer->timer_t1);
	/* allowoverlap (chan_sip parity): tri-state Yes / No / DTMF (DTMF falls through). */
	sofia_cli_peer_line(&buf, "Overlap dial", "%s", sofia_allowoverlap_str(peer->allowoverlap_mode));
	/* rtp-timeout bundle (chan_sip parity): 3 fields for operator visibility into
	 * RTP-timeout enforcement. */
	sofia_cli_peer_line(&buf, "RTP timeout", "%d", peer->rtptimeout);
	sofia_cli_peer_line(&buf, "RTP hold timeout", "%d", peer->rtpholdtimeout);
	sofia_cli_peer_line(&buf, "RTP keepalive", "%d", peer->rtpkeepalive);
	sofia_cli_peer_section(&buf, "Routing and dialplan");
	/* parkinglot (chan_sip parity). */
	sofia_cli_peer_line(&buf, "Parking lot", "%s", ast_strlen_zero(peer->parkinglot) ? "(none)" : peer->parkinglot);
	/* usereqphone (chan_sip parity): 3-state inheritance display (peer-set / from [general]
	 * / default off). */
	if (peer->usereqphone) {
		int from_general = sofia_cfg.default_usereqphone && peer->usereqphone == sofia_cfg.default_usereqphone;
		sofia_cli_peer_line(&buf, "User=Phone", "yes%s", from_general ? " (from [general])" : "");
	} else {
		sofia_cli_peer_line(&buf, "User=Phone", "no");
	}
	/* accountcode (chan_sip parity): CDR billing tag, shown only when set. */
	if (!ast_strlen_zero(peer->accountcode)) {
		sofia_cli_peer_line(&buf, "Account code", "%s", peer->accountcode);
	}
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
		/* outboundproxy display: peer-set value if any, else inherit-marker if
		 * sofia_cfg.outboundproxy non-empty, else (none). */
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
		/* MOH Interpret + MOH Suggest display (chan_sip parity). MOH Suggest shows the stored
		 * value but today only signals INBOUND direction (peer-puts-us-on-hold propagates
		 * suggest to the bridged channel); OUTBOUND Alert-Info on a chan_sofia HOLD re-INVITE is
		 * deferred (chan_sofia does not issue outbound HOLD re-INVITE today). */
		sofia_cli_peer_line(&buf, "MOH interpret", "%s",
			ast_strlen_zero(peer->mohinterpret) ? "(none)" : peer->mohinterpret);
		sofia_cli_peer_line(&buf, "MOH suggest", "%s",
			ast_strlen_zero(peer->mohsuggest) ? "(none)" : peer->mohsuggest);
	}
	{
		/* SRTP cipher preference display: 3-state inheritance (peer-set / from [general] / default). */
		if (!ast_strlen_zero(peer->srtpcipher)) {
			sofia_cli_peer_line(&buf, "SRTP cipher", "%s", peer->srtpcipher);
		} else if (!ast_strlen_zero(sofia_cfg.default_srtpcipher)) {
			sofia_cli_peer_line(&buf, "SRTP cipher", "%s (from [general])", sofia_cfg.default_srtpcipher);
		} else {
			sofia_cli_peer_line(&buf, "SRTP cipher", "(default AES_CM_128_HMAC_SHA1_80)");
		}
	}
	sofia_cli_peer_section(&buf, "Session and identity headers");
	/* Session timers (RFC 4028): 4-line display (chan_sip parity). */
	sofia_cli_peer_line(&buf, "Session timers", "%s", st_mode_str);
	sofia_cli_peer_line(&buf, "Session expires", "%d", peer->session_expires);
	sofia_cli_peer_line(&buf, "Session Min-SE", "%d", peer->session_minse);
	sofia_cli_peer_line(&buf, "Session refresher", "%s", st_refresher_str);
	/* RPID/PAI/Privacy display. ast_named_caller_presentation maps the int to a canonical string. */
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
	/* regexten display-gate (chan_sip parity): the RegExten line is shown only when
	 * regcontext is set (the register_peer_exten mechanism is actually active), not merely
	 * when peer->regexten is set. */
	if (!ast_strlen_zero(sofia_cfg.regcontext) && !ast_strlen_zero(peer->regexten)) {
		sofia_cli_peer_line(&buf, "Reg ext", "%s", peer->regexten);
	}
	/* callbackextension (chan_sip parity): shown only when set. */
	if (!ast_strlen_zero(peer->callbackextension)) {
		sofia_cli_peer_line(&buf, "Callback ext", "%s", peer->callbackextension);
	}
	/* setvar + header display (chan_sip parity): iterate peer->chanvars. header= entries
	 * appear with the __SIPADDHEADERpre%2d= prefix. */
	if (peer->chanvars) {
		struct ast_variable *var;
		for (var = peer->chanvars; var; var = var->next) {
			sofia_cli_peer_line(&buf, "Variable", "%s = %s", var->name, var->value);
		}
	}
	/* subscribecontext (chan_sip parity): 3-state inheritance display. KNOWN LIMITATION:
	 * value is displayed but the pivot effect awaits the presence/dialog event-package handler. */
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
		sofia_cli_peer_line(&buf, "Insecure", "%s", ins[0] ? ins : "no");
	}

	/* ACL detail (was: just yes/no) */
	if (peer->ha) {
		sofia_cli_peer_line(&buf, "ACL", "yes");
		sofia_print_ha_lines(&buf, peer->ha);
	} else {
		sofia_cli_peer_line(&buf, "ACL", "no");
	}
	/* contactpermit/contactdeny (chan_sip parity). */
	sofia_cli_peer_line(&buf, "Contact ACL", "%s", peer->contactha ? "yes" : "no");
	/* directmediapermit/directmediadeny (chan_sip parity). */
	sofia_cli_peer_line(&buf, "Direct media ACL", "%s", peer->directmediaha ? "yes" : "no");
	/* dnsmgr (chan_sip parity): Y/N display. */
	sofia_cli_peer_line(&buf, "DNS managed", "%s", peer->dnsmgr ? "yes" : "no");

	sofia_cli_peer_section(&buf, "Registration");
	/* Source: where the peer definition came from. */
	sofia_cli_peer_line(&buf, "Source", "%s", source_str);
	/* Outbound register state — only meaningful when this peer is a register target */
	if (!ast_strlen_zero(peer->secret)
		&& !ast_strlen_zero(peer->host)
		&& strcasecmp(peer->host, "dynamic") != 0) {
		sofia_cli_peer_line(&buf, "Outbound reg", "target=%s:%d expiry=%lds attempts=%d",
			peer->host, peer->port,
			peer->reg_expiry > 0 ? (long)(peer->reg_expiry - time(NULL)) : 0,
			peer->reg_attempts);
	}

	if (!ast_sockaddr_isnull(&peer->src_addr)) {
		sofia_cli_peer_line(&buf, "Source addr", "%s", ast_sockaddr_stringify(&peer->src_addr));
	}

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
			const char *src;

			/* Snapshot the mutable contact fields (active_calls, expires, src_addr — a concurrent
			 * REGISTER refresh rewrites them) under the contact lock, then use the snapshots for a
			 * consistent test+print. Lock order: peer->lock (already held) -> contact lock. */
			char ua_buf[256];
			ao2_lock(c);
			ttl = (long)(c->expires - now);
			ast_copy_string(src_buf, !ast_sockaddr_isnull(&c->src_addr) ?
				ast_sockaddr_stringify(&c->src_addr) : "(unknown)", sizeof(src_buf));
			ast_copy_string(ua_buf, c->user_agent[0] ? c->user_agent : "(none)", sizeof(ua_buf));
			active_calls = c->active_calls;
			ao2_unlock(c);
			src = src_buf;

			snprintf(ttl_buf, sizeof(ttl_buf), "%lds", ttl > 0 ? ttl : 0);
			if (active_calls > 0) {
				snprintf(contact_status, sizeof(contact_status),
					"IN-CALL:%d", active_calls);
			} else {
				ast_copy_string(contact_status, "IDLE", sizeof(contact_status));
			}
			snprintf(contact_label, sizeof(contact_label), "Contact %d URI", idx++);
			sofia_cli_peer_line(&buf, contact_label, "%s", c->contact_uri);
			sofia_cli_peer_subline(&buf, "State", "%s", contact_status);
			sofia_cli_peer_subline(&buf, "TTL", "%s", ttl_buf);
			sofia_cli_peer_subline(&buf, "Source", "%s", src);
			sofia_cli_peer_subline(&buf, "User-Agent", "%s", ua_buf);
			ao2_ref(c, -1);
		}
		ao2_iterator_destroy(&ci);
	} else {
		sofia_cli_peer_line(&buf, "Contacts", "(none)");
	}
	ast_mutex_unlock(&peer->lock);

	/* Single blocking write AFTER the lock is dropped. Literal "%s" — peer data
	 * may contain '%'. */
	ast_cli(a->fd, "%s", ast_str_buffer(buf));
	ast_free(buf);

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

/* sip show inuse (chan_sip parity): FORMAT strings + header + row format kept verbatim
 * (operator scripts pattern-match the column alignment). Default shows only peers with
 * call_limit>0; "all" shows every peer (call_limit==0 → "N/A" in Limit). chan_sofia
 * also includes peers with busy_level>0 or active counters (inUse/inRinging/onHold>0) —
 * strictly more inclusive than chan_sip, no script breakage. */
static char *sofia_cli_show_inuse(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
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
		/* peer->name is an UNBOUNDED freeable stringfield: the reload writer
		 * (sofia_parse_peer_config on sofia_thread) frees the old stringfield pool under
		 * peer->lock, NOT under ao2_lock(peer). Snapshot the name under peer->lock to serialize
		 * against that free and avoid a UAF. */
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
		/* Decide under the ao2 lock, RELEASE it, then do the blocking ast_cli —
		 * l_name/iused/ilimits are already local snapshots, so the lock is not held across the write. */
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

/* `sip show settings`: show global Sofia-SIP [general] config values (chan_sip-parity
 * command name). */
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
	/* TLS/WS/WSS listener bind-port visibility: "(disabled)" when port == 0, else the port. */
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
	/* ignoresdpversion (chan_sip parity): parse-compat-only display (chan_sofia processes
	 * every SDP unconditionally). */
	ast_cli(a->fd, "  Ignore SDP sess. ver.:  %s\n", AST_CLI_YESNO(sofia_cfg.default_ignoresdpversion));
	/* progressinband (chan_sip parity): Never/Yes/No tri-state. NEVER + YES are exact; NO
	 * degrades to NEVER. */
	ast_cli(a->fd, "  Progress inband:        %s\n",
		sofia_cfg.default_progressinband == SOFIA_PROG_INBAND_NEVER ? "Never" :
		sofia_cfg.default_progressinband == SOFIA_PROG_INBAND_YES ? "Yes" : "No");
	/* subscribe_network_change_event: runtime CLI exposure for operator visibility.
	 * Parse-compat-only (delegated to sofia-sip + dnsmgr; no behavioral effect). */
	ast_cli(a->fd, "  Network change subscribe: %s\n",
		AST_CLI_YESNO(sofia_cfg.subscribe_network_change_event));
	/* rtsavesysname (chan_sip parity): the sofia_process_register ast_update_realtime sites
	 * include the regserver column when set + AST_SYSTEM_NAME non-empty. */
	ast_cli(a->fd, "  Save sys. name:         %s\n", AST_CLI_YESNO(sofia_cfg.rtsave_sysname));
	/* rtupdate (chan_sip parity): the combined gate at the sofia_process_register paths skips
	 * ALL ast_update_realtime when clear. */
	ast_cli(a->fd, "  Update:                 %s\n", AST_CLI_YESNO(sofia_cfg.peer_rtupdate));
	/* rtcachefriends (chan_sip parity): parse-compat-only (the ao2 peer registry always
	 * caches all peers regardless of the flag). */
	ast_cli(a->fd, "  Cache Friends:          %s\n", AST_CLI_YESNO(sofia_cfg.rtcachefriends));
	/* rtautoclear (chan_sip parity): two-piece display (seconds + Enabled|Disabled).
	 * Parse-compat-only (the ao2 registry has no peer-level auto-clear). */
	ast_cli(a->fd, "  Auto Clear:             %d (%s)\n", sofia_cfg.rtautoclear,
		sofia_cfg.rtautoclear_enabled ? "Enabled" : "Disabled");
	/* domainsasrealm (chan_sip parity): wired via sofia_get_realm_for_dialog at the 3
	 * auth-challenge callsites. */
	ast_cli(a->fd, "  Use domains as realms:  %s\n", AST_CLI_YESNO(sofia_cfg.domainsasrealm));
	/* allowexternaldomains (chan_sip parity): wired via sofia_check_sip_domain at the
	 * INVITE/REFER gates. */
	ast_cli(a->fd, "  Call to non-local dom.: %s\n", AST_CLI_YESNO(sofia_cfg.allow_external_domains));
	/* autodomain: runtime CLI exposure for operator visibility (chan_sip does not display it). */
	ast_cli(a->fd, "  Auto Domain:            %s\n", AST_CLI_YESNO(sofia_cfg.autodomain));
	/* promiscredir (chan_sip parity): parse-compat-only (no nua_r_redirect handler). */
	ast_cli(a->fd, "  Allow promisc. redir.:  %s\n", AST_CLI_YESNO(sofia_cfg.default_promiscredir));
	/* matchexternaddrlocally: runtime CLI exposure for operator visibility. Parse-compat-only
	 * (sofia_should_use_externaddr signature divergence). */
	ast_cli(a->fd, "  Match extern locally:   %s\n", AST_CLI_YESNO(sofia_cfg.matchexternaddrlocally));
	/* autoframing (chan_sip parity): parse-compat-only (the sofia_parse_sdp ptime gate is
	 * not wired today). */
	ast_cli(a->fd, "  Auto-Framing:           %s\n", AST_CLI_YESNO(sofia_cfg.default_autoframing));
	/* faxdetect (chan_sip-style): 4-state display. Fax-CNG + T.38 detection are wired. */
	ast_cli(a->fd, "  Fax Detect:             %s\n",
		sofia_cfg.default_faxdetect_mode == SOFIA_FAX_DETECT_NONE ? "no" :
		sofia_cfg.default_faxdetect_mode == SOFIA_FAX_DETECT_BOTH ? "cng,t38" :
		sofia_cfg.default_faxdetect_mode == SOFIA_FAX_DETECT_CNG ? "cng" : "t38");
	/* [general] T.38 default MaxDatagram (chan_sip parity): sentinel -1 displays as
	 * "(default 200)". */
	if (sofia_cfg.default_t38_maxdatagram > 0) {
		ast_cli(a->fd, "  T.38 MaxDatagram:       %d\n", sofia_cfg.default_t38_maxdatagram);
	} else {
		ast_cli(a->fd, "  T.38 MaxDatagram:       (default 200)\n");
	}
	/* mwiexpiry: runtime CLI exposure for operator visibility (chan_sip does not display it). */
	ast_cli(a->fd, "  MWI expiry:             %d\n", sofia_cfg.mwi_expiry);
	/* timerb (chan_sip parity): NTATAG_SIP_T1X64 is wired at nua_create. */
	ast_cli(a->fd, "  Timer B:                %d\n", sofia_cfg.default_timer_b);
	/* timert1 (chan_sip parity): NTATAG_SIP_T1 is wired at nua_create. */
	ast_cli(a->fd, "  Timer T1:               %d\n", sofia_cfg.default_timer_t1);
	/* allowoverlap (chan_sip parity). */
	ast_cli(a->fd, "  Allow overlap dialing:  %s\n", sofia_allowoverlap_str(sofia_cfg.default_allowoverlap_mode));
	/* SRTP per-suite fresh-key option (chan_sofia-only; no chan_sip equivalent). */
	ast_cli(a->fd, "  SRTP per-suite keys:    %s\n", AST_CLI_YESNO(sofia_cfg.srtp_per_suite_keys));
	/* Force INVITE auth (chan_sofia-only operator-policy global security override). */
	ast_cli(a->fd, "  Force INVITE auth:      %s\n", AST_CLI_YESNO(sofia_cfg.force_invite_auth));
	/* Auth algorithms (RFC 7616): static "MD5, SHA-256" reports the verifier
	 * capabilities; challenges are sent MD5-first and may omit SHA-256 for md5secret-only peers. */
	ast_cli(a->fd, "  Auth algorithms:        MD5, SHA-256\n");

	/* Outbound PUBLISH (RFC 3903) — the credential password is REDACTED (Codex non-secret). */
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

/* Forward decl so the `sip reload` CLI alias can invoke the same config-reread path the
 * .reload hook uses. Full definition is at sofia_load_config() below. */
static int sofia_load_config(int reload);
static int sofia_reload_request_sync(char *errmsg, size_t errmsglen, int timeout_ms);

/* chan_sip-parity `sip reload` CLI alias. Equivalent to `module reload chan_sofia.so`:
 * both go through sofia_reload_request_sync, which posts the work onto sofia_thread (the
 * NUA event loop) via sofia_dispatch_to_root_thread. Running the reload there eliminates
 * the UAF races on sofia_cfg.localha / sofia_cfg.contact_ha and the peer->chanvars UAF
 * that the historical "run on the caller's thread" model carried. Listener-config changes
 * are detected and refused with a clear error. No SIP traffic is paused beyond the brief
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

/* sip prune realtime tab-completion helper (chan_sip parity): walk the peers ao2
 * container with optional realtime filter; return ast_strdup(peer->name) on the N-th match
 * for state==N. only_realtime==0 matches all peers; ==1 matches realtime peers only. */
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

		/* reload-UAF: peer->name is an unbounded stringfield the reload writer frees under
		 * peer->lock; snapshot it (and is_realtime) under peer->lock before matching. peer->lock
		 * is a leaf here (no channel/pvt lock held). */
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


/* sip prune realtime (chan_sip parity): operator cache-flush command. When an operator
 * edits a peer's config via SQL, this flushes the in-memory cached realtime peer so the
 * next access reloads fresh values. Single-container (chan_sofia has no peers_by_ip). */
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
			/* Single-pass ao2_iterator + manual ao2_unlink + counter (simpler than chan_sip's
			 * two-phase mark+sweep, which it needs for cross-container peers_by_ip; chan_sofia has
			 * none). ao2 allows unlink during iteration since the iterator holds its own ref. */
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
				/* Release the per-peer dnsmgr handle and drop the +1 ref sofia_dnsmgr_setup_peer bumped
				 * BEFORE the ao2_unlink below drops the container ref. Without this, the dnsmgr-held ref
				 * keeps the peer refcount >= 1 after unlink, so sofia_peer_destructor never runs — the
				 * peer struct AND the live res_dnsmgr callback registration both leak (the orphaned
				 * callback would keep firing sofia_on_dns_update_peer against an unlinked peer). Same
				 * ast_dnsmgr_release THEN ao2_ref(-1) pairing as the reload sweep. Not under peer->lock:
				 * ast_dnsmgr_release is synchronous and blocks on the dnsmgr entry-list lock until any
				 * in-flight sofia_on_dns_update_peer (which takes peer->lock) returns, so taking
				 * peer->lock here would deadlock. */
				if (pi->dnsmgr) {
					ast_dnsmgr_release(pi->dnsmgr);
					pi->dnsmgr = NULL;
					ao2_ref(pi, -1);
				}
				/* Drop the dialplan presence hint this realtime peer created (registrar "realtime_peer"
				 * — what sofia_create_peer_hint stamps for the "realtime" source), if any. The reload
				 * sweep uses "sofia_config_peer" AND skips realtime peers, so it never reclaims these.
				 * Without this the PRIORITY_HINT survives the prune pointing at a SIP/<name> whose struct
				 * is gone. Operates on the dialplan, not peer->lock — same discipline as the sweep. */
				{
					/* Snapshot the freeable stringfields under pi->lock (leaf lock) before use; this CLI
					 * thread otherwise reads them racing the reload worker freeing the stringfield pool. */
					char l_sub[AST_MAX_CONTEXT], l_rex[AST_MAX_EXTENSION];
					ast_mutex_lock(&pi->lock);
					ast_copy_string(l_sub, pi->subscribecontext, sizeof(l_sub));
					ast_copy_string(l_rex, pi->regexten, sizeof(l_rex));
					ast_mutex_unlock(&pi->lock);
					if (!ast_strlen_zero(l_sub) && !ast_strlen_zero(l_rex)) {
						ast_context_remove_extension(l_sub, l_rex, PRIORITY_HINT, "realtime_peer");
					}
				}
				/* Unsubscribe MWI events before the final unref so the destructor's post-refcount-0
				 * drain can't resurrect the peer via a concurrent mwi_event_cb. */
				sofia_peer_drain_mwi(pi);
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
					/* Release the per-peer dnsmgr handle + drop its +1 ref BEFORE the ao2_unlink drops the
					 * container ref, else the dnsmgr-held ref pins the peer at refcount >= 1 and the
					 * destructor never runs — leaking the peer struct and the orphaned res_dnsmgr callback.
					 * ast_dnsmgr_release is synchronous so no peer->lock is taken here (see multi-prune comment). */
					if (peer->dnsmgr) {
						ast_dnsmgr_release(peer->dnsmgr);
						peer->dnsmgr = NULL;
						ao2_ref(peer, -1);
					}
					/* Drop the realtime-peer dialplan presence hint (registrar "realtime_peer") BEFORE
					 * unlinking, else it dangles pointing at SIP/<name> whose struct is gone. Same
					 * dialplan-only discipline as the reload sweep. */
					{
						/* Snapshot under peer->lock (leaf) before use — racing the reload worker's
						 * stringfield-pool free. */
						char l_sub[AST_MAX_CONTEXT], l_rex[AST_MAX_EXTENSION];
						ast_mutex_lock(&peer->lock);
						ast_copy_string(l_sub, peer->subscribecontext, sizeof(l_sub));
						ast_copy_string(l_rex, peer->regexten, sizeof(l_rex));
						ast_mutex_unlock(&peer->lock);
						if (!ast_strlen_zero(l_sub) && !ast_strlen_zero(l_rex)) {
							ast_context_remove_extension(l_sub, l_rex, PRIORITY_HINT, "realtime_peer");
						}
					}
					/* Drain MWI subscriptions before the final unref (see the multi-prune branch). */
					sofia_peer_drain_mwi(peer);
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


/* `sip show registry`: list this server's OUTBOUND trunk registrations (the `register =>`
 * synthetic peers, peer->is_register_line) + their state (chan_sip parity; the CLI
 * companion to AMI SofiaShowRegistry). Snapshot each row UNDER peer->lock, release, THEN
 * ast_cli (which can block on a slow console). */

static char *sofia_cli_show_registry(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
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

/* `sip unregister <peer>` — force-expire a dynamic peer's INBOUND registration (chan_sip parity) so the
 * phone must re-register. Concurrency doctrine exception: this mutates registration state from the CLI
 * thread (normally sofia_thread-owned), justified because the writes are simple field/ao2 ops (not nua_*
 * or state-machine transitions), peer->lock serializes against the sofia_thread expiry sweep / REGISTER
 * apply, and the AMI/devstate/hint side-effects are deferred to AFTER the unlock. Pure LOCAL state clear
 * — no de-REGISTER is sent. In-RAM peers only: a realtime peer's binding lives in the DB (untouched). */
static char *sofia_cli_unregister(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
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
	/* Reject an OUTBOUND register => trunk: such a peer ALSO carries registered=1/reg_expiry for its
	 * OWN upstream registration, so clearing it here would mark the trunk down and zero its refresh.
	 * `sip unregister` is only for a dynamic peer's INBOUND binding. */
	if (peer->is_register_line) {
		ast_mutex_unlock(&peer->lock);
		ast_cli(a->fd, "Peer '%s' is an outbound registration (register =>); "
			"'sip unregister' applies to inbound peer registrations.\n", a->argv[2]);
		ao2_ref(peer, -1);
		return CLI_SUCCESS;
	}
	was_registered = peer->registered;
	/* Clear if there is anything to clear — registered, OR stale contacts left when the flag is
	 * already 0 (defensive: an inconsistent state still gets fully cleaned). */
	had_contacts = ao2_container_count(peer->contacts) > 0;
	did_clear = was_registered || had_contacts;
	if (did_clear) {
		/* Unconditional contacts clear (NULL ao2 callback matches all) — NOT sofia_expire_contacts_cb,
		 * which only matches already-expired contacts and would leave the live bindings a
		 * force-unregister must remove. */
		ao2_callback(peer->contacts, OBJ_UNLINK | OBJ_NODATA | OBJ_MULTIPLE, NULL, NULL);
		peer->registered = 0;
		memset(&peer->src_addr, 0, sizeof(peer->src_addr));
		ast_copy_string(peer->reg_transport, "udp", sizeof(peer->reg_transport));
		peer->expire = 0;
		peer->reg_expiry = 0;
	}
	ast_mutex_unlock(&peer->lock);

	if (did_clear) {
		/* Fire the registration side-effects AFTER the unlock — same path natural expiry uses
		 * (regexten cleanup + AMI PeerStatus Unregistered + devstate/BLF). sip=NULL is safe: the
		 * emit_unregister branch never dereferences it. */
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

static struct ast_cli_entry cli_sofia[] = {
	AST_CLI_DEFINE(sofia_cli_show_peers, "List Sofia-SIP peers"),
	AST_CLI_DEFINE(sofia_cli_show_registry, "List outbound SIP trunk registrations"),
	AST_CLI_DEFINE(sofia_cli_show_publications, "List outbound PUBLISH presentities"),
	AST_CLI_DEFINE(sofia_cli_unregister, "Force-expire a SIP peer's inbound registration"),
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

	/* Find-or-alloc, like sofia_parse_peer_config does for [section] peers. Without this, every reload
	 * that re-parses a `register =>` line would ao2_link a SECOND struct with the same name: ao2_link
	 * inserts unconditionally and never calls cmp_fn, so duplicates by name are silently allowed, then
	 * mark-and-sweep races to remove the OLD struct while the NEW survives and sofia_find_peer returns
	 * whichever ao2 put first — unpredictable. */
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
			if (!ao2_link(peers, peer)) {
				/* OOM — drain MWI before the destructor (register=> peers carry no
				 * mailbox= so this is normally a no-op). */
				sofia_peer_drain_mwi(peer);
			} else {
				ast_verbose("Sofia: register=> peer '%s' created (target %s:%d)\n",
					user, host, port);
			}
		}
		ao2_ref(peer, -1);
	}
}

/* Parse a SECONDS config value into milliseconds, overflow-safe. Returns 0 (OFF) on empty / non-numeric
 * / <= 0; caps at 86400 s (1 day) so the * 1000 can never overflow int. Shared by the live parser and
 * the reload-listener-change detector so both interpret the knob identically. */
static int sofia_cfg_seconds_to_ms(const char *val)
{
	char *end;
	long s;

	if (ast_strlen_zero(val)) {
		return 0;
	}
	/* strtol (not sscanf %d) so overflow is detected via errno BEFORE any cap and trailing garbage is
	 * rejected via endptr. */
	errno = 0;
	s = strtol(val, &end, 10);
	if (errno != 0 || end == val || s <= 0) {
		return 0;
	}
	while (*end == ' ' || *end == '\t') {
		end++;
	}
	if (*end != '\0') {
		return 0;	/* trailing garbage (e.g. "30abc") -> OFF */
	}
	if (s > 86400) {
		s = 86400;	/* cap at 1 day so s * 1000 cannot overflow int */
	}
	return (int)(s * 1000);
}

/* Is this a recognized tls_min_version string? */
static int sofia_tls_min_version_valid(const char *v)
{
	return !strcmp(v, "1.0") || !strcmp(v, "1.1") || !strcmp(v, "1.2") || !strcmp(v, "1.3");
}

/* Strict parse for tls_verify_depth — strtol + errno + endptr; rejects overflow / trailing garbage /
 * non-positive -> 0 (sofia default); caps at 100. */
static int sofia_cfg_verify_depth(const char *val)
{
	char *end;
	long d;

	if (ast_strlen_zero(val)) {
		return 0;
	}
	errno = 0;
	d = strtol(val, &end, 10);
	if (errno != 0 || end == val || *end != '\0' || d <= 0) {
		return 0;
	}
	return (d > 100) ? 100 : (int)d;
}

/* Map a (validated) friendly "1.0".."1.3" minimum-TLS-version to a TPTAG_TLS_VERSION enable-bitmask =
 * that protocol AND every higher one. tport_tls.c disables each protocol whose bit is NOT set; TLS1.3 is
 * not in that disable list so it is always enabled. Hence "1.3" -> 0 (only TLS1.3 left on). Callers MUST
 * gate on the source string being non-empty, since 0 is also the "unset" value. */
static unsigned sofia_tls_min_version_mask(const char *v)
{
	if (!strcmp(v, "1.1")) {
		return TPTLS_VERSION_TLSv1_1 | TPTLS_VERSION_TLSv1_2;
	}
	if (!strcmp(v, "1.2")) {
		return TPTLS_VERSION_TLSv1_2;
	}
	if (!strcmp(v, "1.3")) {
		return 0;
	}
	/* "1.0" (and, defensively, anything the parser let through) -> TLS1.0/1.1/1.2 all enabled. */
	return TPTLS_VERSION_TLSv1 | TPTLS_VERSION_TLSv1_1 | TPTLS_VERSION_TLSv1_2;
}

static void sofia_parse_general_config(struct ast_config *cfg)
{
	struct ast_variable *v;

	for (v = ast_variable_browse(cfg, "general"); v; v = v->next) {
		if (!strcasecmp(v->name, "bindaddr")) {
			ast_copy_string(sofia_cfg.bindaddr, v->value, sizeof(sofia_cfg.bindaddr));
		} else if (!strcasecmp(v->name, "bindport") || !strcasecmp(v->name, "udpbindaddr")) {
			/* IPv6-aware host:port split on a LOCAL copy — never mutate v->value, and
			 * don't truncate a bracketed IPv6 like [2001:db8::1]:5060 at its first colon. */
			char hpbuf[128];
			ast_copy_string(hpbuf, v->value, sizeof(hpbuf));
			if (hpbuf[0] == '[') {				/* [IPv6]:port */
				char *end = strchr(hpbuf, ']');
				if (end) {
					char *port = (end[1] == ':') ? end + 2 : NULL;
					*end = '\0';
					ast_copy_string(sofia_cfg.bindaddr, hpbuf + 1, sizeof(sofia_cfg.bindaddr));
					if (port && *port) {
						sofia_cfg.bindport = atoi(port);
					}
				}
			} else {
				char *first = strchr(hpbuf, ':');
				char *last = strrchr(hpbuf, ':');
				if (first && first == last) {		/* exactly one colon: host:port */
					*first = '\0';
					ast_copy_string(sofia_cfg.bindaddr, hpbuf, sizeof(sofia_cfg.bindaddr));
					sofia_cfg.bindport = atoi(first + 1);
				} else if (first) {			/* multiple colons: bare IPv6, no port */
					ast_copy_string(sofia_cfg.bindaddr, hpbuf, sizeof(sofia_cfg.bindaddr));
				} else {				/* no colon: a bare port (legacy bindport) */
					sofia_cfg.bindport = atoi(hpbuf);
				}
			}
		} else if (!strcasecmp(v->name, "port")) {
			sofia_cfg.bindport = atoi(v->value);
		} else if (!strcasecmp(v->name, "tlsbindaddr")) {
			ast_copy_string(sofia_cfg.tlsbindaddr, v->value, sizeof(sofia_cfg.tlsbindaddr));
		} else if (!strcasecmp(v->name, "tlsbindport")) {
			sofia_cfg.tlsbindport = atoi(v->value);
		} else if (!strcasecmp(v->name, "tlscertfile") || !strcasecmp(v->name, "tlscertdir")) {
			ast_copy_string(sofia_cfg.tlscertfile, v->value, sizeof(sofia_cfg.tlscertfile));
		} else if (!strcasecmp(v->name, "tlsverify") || !strcasecmp(v->name, "tlsverifyserver")) {
			/* Opt-in TLS peer-certificate verification (default OFF). When enabled, outbound
			 * TLS/WSS connections validate the server cert chain + subject against the
			 * configured CA material (tlscertfile dir). */
			sofia_cfg.tlsverify = ast_true(v->value);
		} else if (!strcasecmp(v->name, "tls_ciphers")) {
			/* OpenSSL cipher list for the TLS listener (TPTAG_TLS_CIPHERS). */
			ast_copy_string(sofia_cfg.tls_ciphers, v->value, sizeof(sofia_cfg.tls_ciphers));
		} else if (!strcasecmp(v->name, "tls_min_version")) {
			/* Minimum TLS version (1.0/1.1/1.2/1.3). An
			 * unrecognized value warns and leaves the knob unset (sofia default) rather than
			 * silently mapping to bitmask 0. */
			if (sofia_tls_min_version_valid(v->value)) {
				ast_copy_string(sofia_cfg.tls_min_version, v->value, sizeof(sofia_cfg.tls_min_version));
			} else {
				ast_log(LOG_WARNING, "Sofia: ignoring tls_min_version='%s' (expected 1.0, 1.1, 1.2 or 1.3)\n",
					v->value);
			}
		} else if (!strcasecmp(v->name, "tls_verify_depth")) {
			/* Max cert-chain depth (TPTAG_TLS_VERIFY_DEPTH); 0/invalid -> sofia default.
			 * Warn on a non-empty-but-invalid value, for symmetry with tls_min_version. */
			sofia_cfg.tls_verify_depth = sofia_cfg_verify_depth(v->value);
			if (!ast_strlen_zero(v->value) && sofia_cfg.tls_verify_depth == 0) {
				ast_log(LOG_WARNING, "Sofia: ignoring tls_verify_depth='%s' (expected a positive integer)\n",
					v->value);
			}
		} else if (!strcasecmp(v->name, "publish_server")) {
			/* outbound PUBLISH (RFC 3903): central ESC URI; empty = feature OFF. */
			ast_copy_string(sofia_cfg.publish_server, v->value, sizeof(sofia_cfg.publish_server));
		} else if (!strcasecmp(v->name, "publish_expires")) {
			/* strict strtol + bounds, parity with the other recent knobs. */
			char *end;
			long e;
			errno = 0;
			e = strtol(v->value, &end, 10);
			if (errno != 0 || end == v->value || *end != '\0' || e <= 0) {
				sofia_cfg.publish_expires = 0;	/* invalid -> default applied at use */
			} else {
				sofia_cfg.publish_expires = (e > SOFIA_PUBLISH_MAX_EXPIRES) ? SOFIA_PUBLISH_MAX_EXPIRES : (int) e;
			}
		} else if (!strcasecmp(v->name, "publish_domain")) {
			ast_copy_string(sofia_cfg.publish_domain, v->value, sizeof(sofia_cfg.publish_domain));
		} else if (!strcasecmp(v->name, "publish_username")) {
			ast_copy_string(sofia_cfg.publish_username, v->value, sizeof(sofia_cfg.publish_username));
		} else if (!strcasecmp(v->name, "publish_password")) {
			ast_copy_string(sofia_cfg.publish_password, v->value, sizeof(sofia_cfg.publish_password));
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
		} else if (!strcasecmp(v->name, "tcp_keepalive")) {
			/* CRLF keepalive interval in SECONDS (chan_sip parity); stored as
			 * ms for TPTAG_KEEPALIVE. Overflow-safe; 0/negative/non-numeric -> OFF. */
			sofia_cfg.tcp_keepalive_ms = sofia_cfg_seconds_to_ms(v->value);
		} else if (!strcasecmp(v->name, "tcp_pingpong")) {
			/* pong-timeout in SECONDS; stored ms for TPTAG_PINGPONG. 0 -> OFF. */
			sofia_cfg.tcp_pingpong_ms = sofia_cfg_seconds_to_ms(v->value);
		} else if (!strcasecmp(v->name, "useragent")) {
			/* Operator override of the User-Agent header value (chan_sip parity); empty string
			 * ALLOWED — wire-in skips SIPTAG_USER_AGENT_STR via
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
			/* Default SRTP cipher list inherited
			 * by sofia_peer_alloc when peer omits the key. Both default_srtpcipher and bare
			 * srtpcipher accepted in [general]. */
			ast_copy_string(sofia_cfg.default_srtpcipher, v->value, sizeof(sofia_cfg.default_srtpcipher));
		} else if (!strcasecmp(v->name, "srtp_per_suite_keys")) {
			/* SRTP per-suite-fresh-key option: offer a distinct key per crypto suite
			 * (no chan_sip equivalent: it has no multi-suite SRTP offer mechanism).
			 * [general]-only (no per-peer override). Default 0 = shared-key mode. */
			sofia_cfg.srtp_per_suite_keys = ast_true(v->value);
			sofia_srtp_per_suite_keys = sofia_cfg.srtp_per_suite_keys;
		} else if (!strcasecmp(v->name, "force_invite_auth")) {
			/* When set, ALL inbound INVITEs require digest auth regardless of per-peer
			 * insecure=invite config. Operator security-lockdown switch — no chan_sip
			 * equivalent. [general]-only (policy is global). */
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
		} else if (!strcasecmp(v->name, "auth_algorithms")) {
			/* Which digest algorithm(s) to OFFER in the WWW-Authenticate challenge.
			 * both (default) = MD5 + SHA-256; md5 = MD5 only; sha256 = SHA-256 only.
			 * Verification then accepts exactly what was offered for the peer
			 * (anti-downgrade). Invalid value falls back to both with LOG_WARNING. */
			if (!strcasecmp(v->value, "both") || !strcasecmp(v->value, "md5+sha256")) {
				sofia_cfg.auth_algorithms = SOFIA_AUTH_ALG_BOTH;
			} else if (!strcasecmp(v->value, "md5")) {
				sofia_cfg.auth_algorithms = SOFIA_AUTH_ALG_MD5;
			} else if (!strcasecmp(v->value, "sha256") || !strcasecmp(v->value, "sha-256")) {
				sofia_cfg.auth_algorithms = SOFIA_AUTH_ALG_SHA256;
			} else {
				ast_log(LOG_WARNING, "Sofia: invalid auth_algorithms '%s' "
					"(use both|md5|sha256); using default both\n", v->value);
				sofia_cfg.auth_algorithms = SOFIA_AUTH_ALG_BOTH;
			}
		} else if (!strcasecmp(v->name, "session-timers")) {
			/* RFC 4028 session timers: [general] default; chan_sip parity. */
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
			/* Default presentation for peers that omit callingpres=.
			 * Reuses ast_parse_caller_presentation. */
			int p = ast_parse_caller_presentation(v->value);
			sofia_cfg.default_callingpres = (p < 0) ? AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED : p;
		} else if (!strcasecmp(v->name, "sendrpid")) {
			/* default outbound RPID/PAI emission mode. */
			if (!strcasecmp(v->value, "pai")) sofia_cfg.default_sendrpid = 1;
			else if (!strcasecmp(v->value, "rpid")) sofia_cfg.default_sendrpid = 2;
			else sofia_cfg.default_sendrpid = 0;
		} else if (!strcasecmp(v->name, "trustrpid")) {
			/* default trust on inbound PAI/RPID. */
			sofia_cfg.default_trustrpid = ast_true(v->value);
		} else if (!strcasecmp(v->name, "callcounter")) {
			/* default callcounter shorthand. */
			sofia_cfg.default_call_limit = ast_true(v->value) ? INT_MAX : 0;
		} else if (!strcasecmp(v->name, "call-limit") || !strcasecmp(v->name, "call_limit")) {
			/* default cap inherited by sofia_peer_alloc. */
			sofia_cfg.default_call_limit = atoi(v->value);
			if (sofia_cfg.default_call_limit < 0) sofia_cfg.default_call_limit = 0;
		} else if (!strcasecmp(v->name, "busylevel")) {
			/* default busy-level inherited by sofia_peer_alloc. */
			sofia_cfg.default_busy_level = atoi(v->value);
			if (sofia_cfg.default_busy_level < 0) sofia_cfg.default_busy_level = 0;
		} else if (!strcasecmp(v->name, "default_allowtransfer") || !strcasecmp(v->name, "allowtransfer")) {
			/* post-T56 allowtransfer per-peer parity (2026-04-27): default REFER policy
			 * inherited by sofia_peer_alloc when peer omits the key. Both default_allowtransfer
			 * and bare allowtransfer accepted in [general] (chan_sip MOH-style leniency).
			 * chan_sip parity at chan_sip.c:29587 verbatim binary parser. */
			sofia_cfg.default_allowtransfer = ast_true(v->value) ? TRANSFER_OPENFORALL : TRANSFER_CLOSED;
		} else if (!strcasecmp(v->name, "allowsubscribe")) {
			/* [general] inheritance default for new peers (chan_sip parity, default TRUE);
			 * the derived sofia_cfg.allowsubscribe global ban-all flag is computed by
			 * sofia_post_config_derive_allowsubscribe at config-load conclusion. */
			sofia_cfg.default_allowsubscribe = ast_true(v->value);
		} else if (!strcasecmp(v->name, "regcontext")) {
			/* Master switch — empty disables the entire register_peer_exten mechanism. Names
			 * the dialplan context where extensions get auto-added on REGISTER + auto-removed
			 * on unregister. chan_sip's cleanup_stale_contexts on regcontext-value-change across
			 * reload intentionally not mirrored — chan_sofia is non-unloadable; operators restart
			 * for regcontext value changes. */
			ast_copy_string(sofia_cfg.regcontext, v->value, sizeof(sofia_cfg.regcontext));
		} else if (!strcasecmp(v->name, "regextenonqualify")) {
			/* Couples regexten add/remove to qualify state transitions — extension auto-added
			 * when peer transitions INTO REACHABLE / auto-removed when INTO UNREACHABLE.
			 * Default 0 (FALSE) per chan_sip parity. */
			sofia_cfg.regextenonqualify = ast_true(v->value);
		} else if (!strcasecmp(v->name, "subscribecontext")) {
			/* [general] default subscribecontext inherited by sofia_peer_alloc (chan_sip parity).
			 * KNOWN LIMITATION: pivot-site override at sofia_process_subscribe deferred (no
			 * dialplan-dispatch infrastructure for SUBSCRIBE today); field parsed + persisted +
			 * displayed for drop-in chan_sip config-parse compat. */
			ast_copy_string(sofia_cfg.default_subscribecontext, v->value, sizeof(sofia_cfg.default_subscribecontext));
		} else if (!strcasecmp(v->name, "maxexpiry") || !strcasecmp(v->name, "maxexpirey")) {
			/* Registration TTL bound + 423 Interval Too Brief (chan_sip parity). Typo-tolerant
			 * dual-acceptance (historical maxexpirey + corrected maxexpiry). Clamp invalid
			 * values to DEFAULT_MAX_EXPIRY. */
			sofia_cfg.max_expiry = atoi(v->value);
			if (sofia_cfg.max_expiry < 1) {
				sofia_cfg.max_expiry = DEFAULT_MAX_EXPIRY;
			}
		} else if (!strcasecmp(v->name, "minexpiry") || !strcasecmp(v->name, "minexpirey")) {
			/* Registration TTL bound (chan_sip parity); typo-tolerant dual-acceptance. */
			sofia_cfg.min_expiry = atoi(v->value);
			if (sofia_cfg.min_expiry < 1) {
				sofia_cfg.min_expiry = DEFAULT_MIN_EXPIRY;
			}
		} else if (!strcasecmp(v->name, "defaultexpiry") || !strcasecmp(v->name, "defaultexpirey")) {
			/* Registration TTL bound (chan_sip parity); typo-tolerant dual-acceptance.
			 * Dual-scope: [general] defaultexpiry inherited by peer->expiresecs at sofia_peer_alloc;
			 * existing per-peer expiresecs/defaultexpiry alias at sofia_parse_peer_config KEPT for
			 * legacy chan_sofia operators (KNOWN DIVERGENCE from chan_sip [general]-only — documented
			 * in sofia.conf.sample). */
			sofia_cfg.default_expiry = atoi(v->value);
			if (sofia_cfg.default_expiry < 1) {
				sofia_cfg.default_expiry = DEFAULT_DEFAULT_EXPIRY;
			}
		} else if (!strcasecmp(v->name, "usereqphone")) {
			/* [general] default inherited by sofia_peer_alloc (chan_sip parity).
			 * RFC 3966 telephone-uri ;user=phone parameter for E.164 numbers via PSTN gateways. */
			sofia_cfg.default_usereqphone = ast_true(v->value);
		} else if (!strcasecmp(v->name, "maxforwards")) {
			/* [general] default inherited by sofia_peer_alloc (chan_sip parity);
			 * sscanf %30d + 1-255 bounds-check + clamp-to-default. */
			if (sscanf(v->value, "%30d", &sofia_cfg.default_max_forwards) != 1
				|| sofia_cfg.default_max_forwards < 1 || 255 < sofia_cfg.default_max_forwards) {
				ast_log(LOG_WARNING, "Sofia: '%s' is not a valid [general] maxforwards value — using default %d\n",
					v->value, DEFAULT_MAX_FORWARDS);
				sofia_cfg.default_max_forwards = DEFAULT_MAX_FORWARDS;
			}
		} else if (!strcasecmp(v->name, "t1min")) {
			/* RFC 3261 §17.1.1.2 T1 retry-timer minimum bound (milliseconds).
			 * Defensive minimum 10ms — values below cause spurious retransmission storms
			 * (chan_sofia minimum guard; chan_sip accepts any int). */
			int v_int = 0;
			if (sscanf(v->value, "%30d", &v_int) != 1 || v_int < 10) {
				ast_log(LOG_WARNING, "Sofia: '%s' is not a valid [general] t1min value (minimum 10ms) — using default %d\n",
					v->value, DEFAULT_T1MIN);
				sofia_cfg.t1min = DEFAULT_T1MIN;
			} else {
				sofia_cfg.t1min = v_int;
			}
		} else if (!strcasecmp(v->name, "relaxdtmf")) {
			/* DSP_DIGITMODE_RELAXDTMF flag toggle for poor-quality line DTMF detection
			 * (relaxes threshold; trades sensitivity for false-positive tolerance). */
			sofia_cfg.relaxdtmf = ast_true(v->value);
		} else if (!strcasecmp(v->name, "prematuremedia")) {
			/* INVERTED-SEMANTIC chan_sip quirk preserved:
			 * operator-key "prematuremedia=yes" → variable TRUE → filter ON → 183 Session
			 * Progress SUPPRESSED. operator-key "prematuremedia=no" → variable FALSE →
			 * filter OFF → 183 ALLOWED. Default TRUE (chan_sip parity). */
			sofia_cfg.prematuremediafilter = ast_true(v->value);
		} else if (!strcasecmp(v->name, "registertimeout")) {
			/* atoi + clamp-to-default if <1 (chan_sip parity). Application-level
			 * scheduled-retry interval seconds. */
			sofia_cfg.register_timeout = atoi(v->value);
			if (sofia_cfg.register_timeout < 1) {
				sofia_cfg.register_timeout = DEFAULT_REGISTRATION_TIMEOUT;
			}
		} else if (!strcasecmp(v->name, "registerattempts")) {
			/* atoi direct (no clamp; 0=unlimited) (chan_sip parity). Application-level
			 * scheduled-retry attempt-cap. */
			sofia_cfg.register_attempts = atoi(v->value);
		} else if (!strcasecmp(v->name, "directrtpsetup")) {
			/* Experimental feature (default DISABLED) (chan_sip parity).
			 * PARSE-COMPAT-ONLY: field parsed + stored; full-feature early-RTP-bridge wire-in
			 * deferred (no operator driver; chan_sip itself defaults DISABLED). */
			sofia_cfg.directrtpsetup = ast_true(v->value);
		} else if (!strcasecmp(v->name, "alwaysauthreject")) {
			/* Security-critical RFC 3261 §22.4 username-enumeration prevention —
			 * drives REGISTER unknown-peer + MWI SUBSCRIBE unknown-mailbox to emit
			 * 401 challenge instead of 403/404 disclosure. Default TRUE (chan_sip parity). */
			sofia_cfg.alwaysauthreject = ast_true(v->value);
		} else if (!strcasecmp(v->name, "compactheaders")) {
			/* PARSE-COMPAT-ONLY: sofia-sip native compact-emit gate ABSENT
			 * (verified across nta_tag.h + nua_tag.h + sip_tag.h); field parsed +
			 * stored + reload-clean for chan_sip drop-in compat; full-feature
			 * compact-emit DEFERRED until upstream sofia-sip exposes native gate. */
			sofia_cfg.compactheaders = ast_true(v->value);
		} else if (!strcasecmp(v->name, "disallowed_methods")) {
			/* Comma-separated SIP method names (chan_sip parity).
			 * PARSE-COMPAT-ONLY string-storage shortcut (avoids porting mark_parsed_methods +
			 * SIP_METHOD_* constants). Dynamic NUTAG_ALLOW generation per-handle DEFERRED. */
			ast_copy_string(sofia_cfg.disallowed_methods, v->value, sizeof(sofia_cfg.disallowed_methods));
		} else if (!strcasecmp(v->name, "contactpermit") || !strcasecmp(v->name, "contactdeny")) {
			/* chan_sip parity: ast_append_ha(v->name + 7, ...) skips "contact" prefix;
			 * remaining "permit" or "deny" passed as sense. */
			int ha_error = 0;
			if (!ast_strlen_zero(v->value)) {
				ast_rwlock_wrlock(&sofia_contactha_lock);
				sofia_cfg.contact_ha = ast_append_ha(v->name + 7, v->value, sofia_cfg.contact_ha, &ha_error);
				ast_rwlock_unlock(&sofia_contactha_lock);
			}
			if (ha_error) {
				ast_log(LOG_ERROR, "Sofia: bad %s [general] entry: %s\n", v->name, v->value);
			}
		} else if (!strcasecmp(v->name, "srvlookup")) {
			sofia_cfg.srvlookup = ast_true(v->value);
		} else if (!strcasecmp(v->name, "domain")) {
			/* Append local SIP domain for CHECKSIPDOMAIN. Multi-line allowed.
			 * sofia_domain_list_add centralizes mutation + duplicate-check via
			 * sofia_check_sip_domain. */
			sofia_domain_list_add(v->value);
		} else if (!strcasecmp(v->name, "outboundproxy")) {
			/* Default outbound proxy for outbound INVITE + REGISTER.
			 * Per-peer outboundproxy= overrides this. Accepts bare host / host:port / sip:URI;
			 * normalized to "sip:HOST[:PORT];lr" by sofia_format_outboundproxy at use time. */
			ast_copy_string(sofia_cfg.outboundproxy, v->value, sizeof(sofia_cfg.outboundproxy));
		} else if (!strcasecmp(v->name, "default_mohinterpret") || !strcasecmp(v->name, "mohinterpret")) {
			/* Default MOH interpret class — peers without explicit mohinterpret inherit at sofia_peer_alloc (chan_sip parity). Both default_mohinterpret and bare mohinterpret accepted. */
			ast_copy_string(sofia_cfg.default_mohinterpret, v->value, sizeof(sofia_cfg.default_mohinterpret));
		} else if (!strcasecmp(v->name, "default_mohsuggest") || !strcasecmp(v->name, "mohsuggest")) {
			/* default mohsuggest (chan_sip parity). */
			ast_copy_string(sofia_cfg.default_mohsuggest, v->value, sizeof(sofia_cfg.default_mohsuggest));
		} else if (!strcasecmp(v->name, "language")) {
			/* [general] default language (chan_sip parity), inherited by sofia_peer_alloc
			 * when peer omits language= per-peer. */
			ast_copy_string(sofia_cfg.default_language, v->value, sizeof(sofia_cfg.default_language));
		} else if (!strcasecmp(v->name, "parkinglot")) {
			/* [general] parkinglot (chan_sip parity). Operators set empty to restore
			 * chan_sofia silent-baseline; non-empty becomes inheritance default for new peers. */
			ast_copy_string(sofia_cfg.default_parkinglot, v->value, sizeof(sofia_cfg.default_parkinglot));
		} else if (!strcasecmp(v->name, "ignoreregexpire")) {
			/* chan_sip parity. When yes, expired contacts preserved across short
			 * upstream-trunk outages (stable-trunk use case). */
			sofia_cfg.ignore_regexpire = ast_true(v->value);
		} else if (!strcasecmp(v->name, "maxcallbitrate")) {
			/* chan_sip parity: atoi + clamp-negative-to-default (384). Inherited by
			 * sofia_peer_alloc when peer omits the key. */
			sofia_cfg.default_maxcallbitrate = atoi(v->value);
			if (sofia_cfg.default_maxcallbitrate < 0) {
				sofia_cfg.default_maxcallbitrate = 384;
			}
		} else if (!strcasecmp(v->name, "match_auth_username")) {
			/* chan_sip parity. When yes, peer-lookup uses Authorization-username (or
			 * Proxy-Authorization) instead of From-username (sofia_pick_auth_username). */
			sofia_cfg.match_auth_username = ast_true(v->value);
		} else if (!strcasecmp(v->name, "legacy_useroption_parsing")) {
			/* chan_sip parity. PARSE-COMPAT-ONLY (sofia-sip library-feature absent);
			 * full-feature URI per-component semicolon-strip DEFERRED until upstream
			 * sofia-sip exposes a hook. */
			sofia_cfg.legacy_useroption_parsing = ast_true(v->value);
		} else if (!strcasecmp(v->name, "shrinkcallerid")) {
			/* chan_sip parity: ast_true/ast_false tri-state + LOG_WARNING on invalid
			 * (preserves current value on parse-fail). */
			if (ast_true(v->value)) {
				sofia_cfg.shrinkcallerid = 1;
			} else if (ast_false(v->value)) {
				sofia_cfg.shrinkcallerid = 0;
			} else {
				ast_log(LOG_WARNING, "Sofia: shrinkcallerid value '%s' is not valid; ignoring\n",
					v->value);
			}
		} else if (!strcasecmp(v->name, "notifyhold")) {
			/* chan_sip parity. Gates peer->onHold counter atomic update. */
			sofia_cfg.notifyhold = ast_true(v->value);
		} else if (!strcasecmp(v->name, "notifyringing")) {
			/* chan_sip parity. PARSE-COMPAT-ONLY — chan_sofia presence/dialog-info NOTIFY
			 * infrastructure ABSENT; flag effect-deferred until landed. */
			sofia_cfg.notifyringing = ast_true(v->value);
		} else if (!strcasecmp(v->name, "dynamic_exclude_static")
				|| !strcasecmp(v->name, "dynamic_excludes_static")) {
			/* chan_sip parity: dual-key parser (dynamic_exclude_static +
			 * dynamic_excludes_static both accepted). Security hardening flag. */
			sofia_cfg.dynamic_exclude_static = ast_true(v->value);
		} else if (!strcasecmp(v->name, "autocreatepeer")) {
			/* chan_sip parity. PARSE-COMPAT-ONLY — chan_sofia design refuses to auto-create
			 * unknown peers (security-stronger via alwaysauthreject). */
			sofia_cfg.autocreatepeer = ast_true(v->value);
		} else if (!strcasecmp(v->name, "preferred_codec_only")) {
			/* chan_sip parity (SIP_PAGE2_PREFERRED_CODEC → chan_sofia int). */
			sofia_cfg.default_preferred_codec_only = ast_true(v->value);
		} else if (!strcasecmp(v->name, "ignoresdpversion")) {
			/* chan_sip parity. PARSE-COMPAT-ONLY — chan_sofia processes every SDP
			 * unconditionally. */
			sofia_cfg.default_ignoresdpversion = ast_true(v->value);
		} else if (!strcasecmp(v->name, "promiscredir")) {
			/* chan_sip parity. PARSE-COMPAT-ONLY — chan_sofia nua_r_redirect handler
			 * ABSENT (sofia-sip NUTAG_AUTO_TARGET verified ABSENT). */
			sofia_cfg.default_promiscredir = ast_true(v->value);
		} else if (!strcasecmp(v->name, "autoframing")) {
			/* chan_sip parity (global_autoframing, SEPARATE from the per-peer parser).
			 * PARSE-COMPAT-ONLY — chan_sofia sofia_parse_sdp ptime gate not wired today. */
			sofia_cfg.default_autoframing = ast_true(v->value);
		} else if (!strcasecmp(v->name, "timerb")) {
			/* chan_sip parity, but CORRECTS a chan_sip parser bug: chan_sip parses
			 * `atoi(v->value)` yet only assigns global_timer_b in the `< 500`
			 * invalid-value branch — valid values >= 500 are parsed but never assigned,
			 * so timerb has NO effect (stays at default 32000ms). We add the missing
			 * `else` to assign valid values. Wire-in via NTATAG_SIP_T1X64 at nua_create.
			 * sofia_timerb_set tracks "set" for the Timer B vs T1*64 cross-validation. */
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
			/* chan_sip parity, but adds parse-time validation chan_sip lacks: chan_sip
			 * uses bare `global_t1 = atoi(v->value)` with no parse-time range check (so
			 * timert1=0 or negative passes silently). We add sscanf %30d + < 200 clamp +
			 * LOG_WARNING + clamp-to-DEFAULT_TIMER_T1 (500). sofia_timert1_set tracks "set"
			 * for the cross-validation. */
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
			/* [general] default T38FaxMaxDatagram override (chan_sip parity).
			 * Sentinel -1 semantic: positive 0+ = explicit override; -1 = use
			 * SOFIA_T38_MAXDATAGRAM_BUILTIN (200). Inherited by sofia_peer_alloc into
			 * peer->t38_maxdatagram when peer omits per-peer maxdatagram=N sub-option of
			 * t38pt_udptl. Both `t38_maxdatagram` and `global_t38_maxdatagram` accepted. */
			int x;
			if (sscanf(v->value, "%30d", &x) == 1) {
				sofia_cfg.default_t38_maxdatagram = x;
			} else {
				ast_log(LOG_WARNING, "Sofia: invalid [general] %s value '%s' (expected integer)\n",
					v->name, v->value);
			}
		} else if (!strcasecmp(v->name, "allowoverlap")) {
			/* chan_sip parity: tri-state parser. ast_true → YES; "dtmf" → DTMF;
			 * else → NO. Default YES (drop-in critical default). */
			if (ast_true(v->value)) {
				sofia_cfg.default_allowoverlap_mode = SOFIA_OVERLAP_YES;
			} else if (!strcasecmp(v->value, "dtmf")) {
				sofia_cfg.default_allowoverlap_mode = SOFIA_OVERLAP_DTMF;
			} else {
				sofia_cfg.default_allowoverlap_mode = SOFIA_OVERLAP_NO;
			}
		} else if (!strcasecmp(v->name, "progressinband")) {
			/* chan_sip parity: tri-state. ast_true → YES; non-"never" → NO; "never" → NEVER.
			 * Partial wire-in at sofia_indicate AST_CONTROL_RINGING. */
			if (ast_true(v->value)) {
				sofia_cfg.default_progressinband = SOFIA_PROG_INBAND_YES;
			} else if (strcasecmp(v->value, "never")) {
				sofia_cfg.default_progressinband = SOFIA_PROG_INBAND_NO;
			} else {
				sofia_cfg.default_progressinband = SOFIA_PROG_INBAND_NEVER;
			}
		} else if (!strcasecmp(v->name, "subscribe_network_change_event")) {
			/* chan_sip parity: tri-state (ast_true → 1; ast_false → 0; else LOG_WARNING +
			 * skip). PARSE-COMPAT-ONLY (chan_sofia delegates network-change handling to
			 * sofia-sip + dnsmgr). */
			if (ast_true(v->value)) {
				sofia_cfg.subscribe_network_change_event = 1;
			} else if (ast_false(v->value)) {
				sofia_cfg.subscribe_network_change_event = 0;
			} else {
				ast_log(LOG_WARNING, "Sofia: subscribe_network_change_event value '%s' is not valid at line %d.\n",
					v->value, v->lineno);
			}
		} else if (!strcasecmp(v->name, "rtsavesysname")) {
			/* chan_sip parity. Wire-in at the sofia_process_register ast_update_realtime
			 * callsites mirrors chan_sip's realtime_update_peer pattern. */
			sofia_cfg.rtsave_sysname = ast_true(v->value);
		} else if (!strcasecmp(v->name, "rtupdate")) {
			/* chan_sip parity. Wire-in via the combined gate at the sofia_process_register
			 * `if (peer->is_realtime)` blocks (chan_sip combined-gate pattern). */
			sofia_cfg.peer_rtupdate = ast_true(v->value);
		} else if (!strcasecmp(v->name, "register_pool")) {
			/* Phase 1: offload realtime REGISTER DB writes to a bounded taskprocessor
			 * pool (default OFF).  Takes effect on reload — the kill-switch toggle. */
			sofia_cfg.register_pool = ast_true(v->value);
		} else if (!strcasecmp(v->name, "register_pool_workers")) {
			sofia_cfg.register_pool_workers = atoi(v->value);
		} else if (!strcasecmp(v->name, "rtcachefriends")) {
			/* chan_sip parity. PARSE-COMPAT-ONLY — chan_sofia's ao2 peer registry is
			 * intrinsically equivalent to rtcachefriends=yes (always caches all peers). */
			sofia_cfg.rtcachefriends = ast_true(v->value);
		} else if (!strcasecmp(v->name, "rtautoclear")) {
			/* chan_sip parity: two-phase parser. Numeric > 0 sets seconds; flag enabled
			 * when numeric > 0 OR ast_true("yes"). PARSE-COMPAT-ONLY — chan_sofia ao2
			 * registry has no peer-level auto-clear infra. */
			int i = atoi(v->value);
			if (i > 0) {
				sofia_cfg.rtautoclear = i;
			} else {
				i = 0;
			}
			sofia_cfg.rtautoclear_enabled = (i || ast_true(v->value)) ? 1 : 0;
		} else if (!strcasecmp(v->name, "domainsasrealm")) {
			/* chan_sip parity. Wired via sofia_get_realm_for_dialog at the auth-challenge
			 * callsites (chan_sip get_realm semantic). */
			sofia_cfg.domainsasrealm = ast_true(v->value);
		} else if (!strcasecmp(v->name, "allowexternaldomains")) {
			/* chan_sip parity. Wired via sofia_check_sip_domain at the
			 * sofia_process_invite/refer gate callsites. */
			sofia_cfg.allow_external_domains = ast_true(v->value);
		} else if (!strcasecmp(v->name, "autodomain")) {
			/* chan_sip parity. Wired via sofia_domain_list_add at the auto-add callsites;
			 * auto-add fires at sofia_load_config conclusion (chan_sip pattern). */
			sofia_cfg.autodomain = ast_true(v->value);
		} else if (!strcasecmp(v->name, "matchexternaddrlocally")
		           || !strcasecmp(v->name, "matchexterniplocally")) {
			/* chan_sip parity: dual-key acceptance (both spellings parsed identically).
			 * PARSE-COMPAT-ONLY — sofia_should_use_externaddr signature diverges (peer_addr
			 * only; future-fix path documented in sample.conf). */
			sofia_cfg.matchexternaddrlocally = ast_true(v->value);
		} else if (!strcasecmp(v->name, "rtptimeout")) {
			/* chan_sip parity: sscanf %30d + LOG_WARNING + clamp-to-0 on invalid. */
			if ((sscanf(v->value, "%30d", &sofia_cfg.default_rtptimeout) != 1)
					|| sofia_cfg.default_rtptimeout < 0) {
				ast_log(LOG_WARNING, "Sofia: '%s' is not a valid RTP timeout; using default 0\n", v->value);
				sofia_cfg.default_rtptimeout = 0;
			}
		} else if (!strcasecmp(v->name, "rtpholdtimeout")) {
			/* chan_sip parity (rtp-timeout bundle). */
			if ((sscanf(v->value, "%30d", &sofia_cfg.default_rtpholdtimeout) != 1)
					|| sofia_cfg.default_rtpholdtimeout < 0) {
				ast_log(LOG_WARNING, "Sofia: '%s' is not a valid RTP hold timeout; using default 0\n", v->value);
				sofia_cfg.default_rtpholdtimeout = 0;
			}
		} else if (!strcasecmp(v->name, "rtpkeepalive")) {
			/* chan_sip parity (rtp-timeout bundle). */
			if ((sscanf(v->value, "%30d", &sofia_cfg.default_rtpkeepalive) != 1)
					|| sofia_cfg.default_rtpkeepalive < 0) {
				ast_log(LOG_WARNING, "Sofia: '%s' is not a valid RTP keepalive; using default 0\n", v->value);
				sofia_cfg.default_rtpkeepalive = 0;
			}
		} else if (!strcasecmp(v->name, "tos_sip")) {
			/* chan_sip parity: ast_str2tos + LOG_WARNING-on-invalid.
			 * Wired via TPTAG_TOS at nua_create. */
			if (ast_str2tos(v->value, &sofia_cfg.tos_sip)) {
				ast_log(LOG_WARNING, "Sofia: invalid tos_sip value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "tos_audio")) {
			/* chan_sip parity. Wired via ast_rtp_instance_set_qos at sofia_rtp_init. */
			if (ast_str2tos(v->value, &sofia_cfg.tos_audio)) {
				ast_log(LOG_WARNING, "Sofia: invalid tos_audio value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "tos_video")) {
			/* chan_sip parity. Wired via ast_rtp_instance_set_qos at sofia_rtp_init. */
			if (ast_str2tos(v->value, &sofia_cfg.tos_video)) {
				ast_log(LOG_WARNING, "Sofia: invalid tos_video value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "tos_text")) {
			/* chan_sip parity. PARSE-COMPAT-ONLY (chan_sofia text-RTP infrastructure
			 * ABSENT — no pvt->trtp). */
			if (ast_str2tos(v->value, &sofia_cfg.tos_text)) {
				ast_log(LOG_WARNING, "Sofia: invalid tos_text value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "cos_sip")) {
			/* chan_sip parity. PARSE-COMPAT-ONLY (sofia-sip TPTAG_COS verified ABSENT in
			 * tport_tag.h; full-feature DEFERRED until upstream surfaces it). */
			if (ast_str2cos(v->value, &sofia_cfg.cos_sip)) {
				ast_log(LOG_WARNING, "Sofia: invalid cos_sip value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "cos_audio")) {
			/* chan_sip parity. Wired via ast_rtp_instance_set_qos. */
			if (ast_str2cos(v->value, &sofia_cfg.cos_audio)) {
				ast_log(LOG_WARNING, "Sofia: invalid cos_audio value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "cos_video")) {
			/* chan_sip parity. Wired via ast_rtp_instance_set_qos. */
			if (ast_str2cos(v->value, &sofia_cfg.cos_video)) {
				ast_log(LOG_WARNING, "Sofia: invalid cos_video value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "cos_text")) {
			/* chan_sip parity. PARSE-COMPAT-ONLY (chan_sofia text-RTP infrastructure
			 * ABSENT — no pvt->trtp). */
			if (ast_str2cos(v->value, &sofia_cfg.cos_text)) {
				ast_log(LOG_WARNING, "Sofia: invalid cos_text value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "mwi_from")) {
			/* MWI From-header default; empty -> peer->fromdomain or sofia_cfg.realm fallback */
			ast_copy_string(sofia_cfg.mwi_from, v->value, sizeof(sofia_cfg.mwi_from));
		} else if (!strcasecmp(v->name, "notifymime")
				|| !strcasecmp(v->name, "notifymimetype")) {
			/* MWI NOTIFY Content-Type; default application/simple-message-summary (RFC 3842).
			 * "notifymimetype" is the chan_sip key; "notifymime" is the chan_sofia alias. */
			ast_copy_string(sofia_cfg.notifymime, v->value, sizeof(sofia_cfg.notifymime));
		} else if (!strcasecmp(v->name, "vmexten")) {
			/* voicemail user-part for Message-Account URI; default "asterisk" */
			ast_copy_string(sofia_cfg.vmexten, v->value, sizeof(sofia_cfg.vmexten));
		} else if (!strcasecmp(v->name, "mwi_expiry")
		           || !strcasecmp(v->name, "mwiexpiry")
		           || !strcasecmp(v->name, "mwiexpirey")) {
			/* MWI subscription default expiry seconds; default 3600 (chan_sip parity).
			 * Accepts 3 spellings: "mwi_expiry" + chan_sip "mwiexpiry"/"mwiexpirey".
			 * clamp-to-default-on-invalid (< 1 → 3600). */
			sofia_cfg.mwi_expiry = atoi(v->value);
			if (sofia_cfg.mwi_expiry < 1) {
				sofia_cfg.mwi_expiry = 3600;
			}
		} else if (!strcasecmp(v->name, "externaddr") || !strcasecmp(v->name, "externhost")) {
			/* chan_sip distinguishes externaddr=IP from externhost=NAME; we accept
			 * both keys. Detect value type via ast_sockaddr_parse: if it parses as
			 * IP, store as static externaddr (no refresh); else treat as hostname
			 * (set externhost + resolve + arm externexpire for lazy-refresh), so a
			 * hostname in the externaddr key still works. */
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
				/* reload-UAF fix: serialize the append+publish against
				 * channel-thread readers of sofia_cfg.localha. */
				ast_rwlock_wrlock(&sofia_localha_lock);
				na = ast_append_ha("d", v->value, sofia_cfg.localha, &ha_error);
				if (na) {
					sofia_cfg.localha = na;
				}
				ast_rwlock_unlock(&sofia_localha_lock);
				if (!na) {
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
	/* Find-or-alloc: only a NEWLY allocated peer is ao2_link()ed at the end of
	 * this function. ao2_link inserts unconditionally (never dedups), so
	 * re-linking a surviving config peer on every `sip reload` would add a
	 * duplicate node plus a leaked container ref per reload. */
	int new_alloc = 0;
	int locked = 0;
	/* Per-peer header counter — each header= entry gets a unique
	 * __SIPADDHEADERpre%2d= channel-var name; resets per peer build (chan_sip parity). */
	int headercount = 0;

	peer = sofia_find_peer(cat);
	if (!peer) {
		peer = sofia_peer_alloc(cat);
		if (!peer) {
			return;
		}
		new_alloc = 1;
	} else {
		/* Release any existing per-peer dnsmgr handle BEFORE the reset below
		 * wipes/re-parses host=. sofia_dnsmgr_setup_peer short-circuits if
		 * peer->dnsmgr is set, so without releasing, a host= change on reload
		 * leaves the dnsmgr registered for the OLD host (keeping its +1 ao2 ref
		 * and drifting peer->src_addr to the wrong host); the re-parse tail then
		 * re-registers fresh. MUST run OUTSIDE peer->lock: ast_dnsmgr_release is
		 * synchronous and blocks on the dnsmgr entry-list lock until any in-flight
		 * sofia_on_dns_update_peer (which takes peer->lock) completes, so releasing
		 * under peer->lock would deadlock the res_dnsmgr refresh thread. */
		if (peer->dnsmgr) {
			ast_dnsmgr_release(peer->dnsmgr);
			peer->dnsmgr = NULL;
			ao2_ref(peer, -1);
		}
		/* Hold peer->lock across the ENTIRE reset + repopulate + defaults window
		 * (released after the defaulting block below). The repopulate loop's
		 * ast_string_field_set calls free the old stringfield pool when a value
		 * grows, so peer->lock readers (sofia_sched/reg/qualify threads, show_peer /
		 * SIPpeers dumps) must be serialized behind the whole mutation or they can
		 * deref a freed/torn field. Readers take peer->lock as a leaf, so widening
		 * cannot invert. Carve-outs kept OUTSIDE the lock: ast_dnsmgr_release above
		 * and sofia_dnsmgr_setup_peer / sofia_create_peer_hint / ao2_link below
		 * (heavy global locks). The lock is taken only on this cache-hit path; a
		 * fresh peer is not findable until ao2_link — tracked by `locked`. */
		/* ABBA deadlock fix: drop the existing dialplan hint extension BEFORE taking
		 * peer->lock. ast_context_remove_extension takes the global contexts lock
		 * (conlock), giving peer->lock -> conlock; the dialplan/core reload path runs
		 * the reverse (conlock -> ast_add_hint -> sofia_devicestate -> peer->lock), so
		 * a concurrent `sip reload` + `dialplan reload` would deadlock the sofia_thread.
		 * This is the reload writer (sole mutator), so the OLD subscribecontext/regexten
		 * are stable to snapshot here unlocked to locate the extension to remove; the
		 * fresh hint is re-added by sofia_create_peer_hint at the end. Without the
		 * remove, regexten= changes leak the old hint / accumulate duplicates. */
		if (!ast_strlen_zero(peer->subscribecontext) && !ast_strlen_zero(peer->regexten)) {
			char old_subctx[AST_MAX_CONTEXT];
			char old_regexten[AST_MAX_EXTENSION];
			ast_copy_string(old_subctx, peer->subscribecontext, sizeof(old_subctx));
			ast_copy_string(old_regexten, peer->regexten, sizeof(old_regexten));
			ast_context_remove_extension(old_subctx, old_regexten, PRIORITY_HINT, "sofia_config_peer");
		}
		ast_mutex_lock(&peer->lock);
		locked = 1;
		/* Reset ACL chains so the permit/deny parsers below append onto a
		 * fresh list instead of stacking on the previous load's rules — else
		 * each reload grows peer->ha (and contactha/directmediaha) linearly. */
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
		/* Drain the mailbox list — sofia_peer_parse_mailboxes appends without
		 * dedup, so each reload would accumulate mailbox structs (each holding an
		 * ast_event_subscribe handle). Unsubscribe synchronously (waits for any
		 * in-flight mwi_event_cb, closing the event-bus delivery race) then free. */
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
		/* On peer reload, free prior chanvars before re-parsing (mirrors the
		 * string-field reset above). */
		if (peer->chanvars) {
			ast_variables_destroy(peer->chanvars);
			peer->chanvars = NULL;
		}
		/* Re-apply the COMPLETE config-default set, not just the security subset, so
		 * a REMOVED per-peer key reverts to its [general] default instead of retaining
		 * the prior load's value (else a stale md5secret keeps authenticating the OLD
		 * password, a removed insecure=invite keeps INVITE auth off → toll-fraud, etc.).
		 * Same helper sofia_peer_alloc uses, called under the peer->lock already held
		 * (contact_ha duped under sofia_contactha_lock, a verified LEAF). Runs AFTER the
		 * ha/contactha/directmediaha frees above so the contact_ha re-inherit is leak-free;
		 * the per-peer permit/deny parsers below then append. */
		sofia_peer_set_defaults(peer);
		/* peer->lock stays held through the repopulate loop; released after the
		 * defaulting block below. */
	}

	/* Clear the reload-sweep mark: this peer survived the new config and
	 * must not be swept at the end of the reload worker. */
	peer->_reload_marked = 0;

	for (v = ast_variable_browse(cfg, cat); v; v = v->next) {
		if (!strcasecmp(v->name, "secret") || !strcasecmp(v->name, "password")) {
			ast_string_field_set(peer, secret, v->value);
			/* Warn when both secret= and md5secret= are set (fires when secret=
			 * comes after md5secret= in config order); md5secret takes precedence. */
			if (!ast_strlen_zero(peer->md5secret) && !ast_strlen_zero(v->value)) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' has BOTH secret= and "
					"md5secret= set — md5secret takes precedence (chan_sip.c"
					":15415-16 parity); recommend operator unset secret= to "
					"remove ambiguity\n", peer->name);
			}
		} else if (!strcasecmp(v->name, "md5secret")) {
			/* Pre-hashed MD5(user:realm:secret) digest secret (chan_sip parity):
			 * when set, used directly as a1_hash, bypassing the cleartext-secret
			 * path, and takes PRECEDENCE over peer->secret. The dual-set warning
			 * fires here at config-time (once at load, not per-auth-call). */
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
		} else if (!strcasecmp(v->name, "forceddiversion")) {
			/* CLI-forward compliance: per-trunk redirecting DID forced into the
			 * outbound Diversion header on forwarded calls. See sofia_add_diversion. */
			ast_string_field_set(peer, forceddiversion, v->value);
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
			ast_string_field_set(peer, callbackextension, v->value);
		} else if (!strcasecmp(v->name, "setvar")) {
			/* Per-peer channel variable (chan_sip parity). */
			peer->chanvars = sofia_add_var(v->value, peer->chanvars);
		} else if (!strcasecmp(v->name, "header")) {
			/* Per-peer custom SIP header (chan_sip parity): stored as a
			 * __SIPADDHEADERpre channel-var that sofia_build_addheader_str
			 * absorbs via prefix matching at sofia_call. */
			char tmp[4096];
			snprintf(tmp, sizeof(tmp), "__SIPADDHEADERpre%2d=%s", ++headercount, v->value);
			peer->chanvars = sofia_add_var(tmp, peer->chanvars);
		} else if (!strcasecmp(v->name, "subscribecontext")) {
			ast_string_field_set(peer, subscribecontext, v->value);
		} else if (!strcasecmp(v->name, "accountcode")) {
			/* CDR billing-tag (chan_sip parity). */
			ast_string_field_set(peer, accountcode, v->value);
		} else if (!strcasecmp(v->name, "disallowed_methods")) {
			/* PARSE-COMPAT-ONLY string-storage. */
			ast_string_field_set(peer, disallowed_methods, v->value);
		} else if (!strcasecmp(v->name, "maxforwards")) {
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
			/* "canreinvite" is the legacy chan_sip alias for directmedia. */
			peer->directmedia = ast_true(v->value);
		} else if (!strcasecmp(v->name, "busy_on_active")) {
			peer->busy_on_active = ast_true(v->value);
		} else if (!strcasecmp(v->name, "max_contacts")) {
			peer->max_contacts = sofia_clamp_max_contacts(atoi(v->value), peer->name);
		} else if (!strcasecmp(v->name, "encryption")) {
			peer->encryption = ast_true(v->value);
		} else if (!strcasecmp(v->name, "srtpcipher")) {
			/* SRTP suite preference; lenient WARN-on-typo happens at
			 * sdp_crypto_offer_list emit time, not here. */
			ast_string_field_set(peer, srtpcipher, v->value);
		} else if (!strcasecmp(v->name, "session-timers")) {
			/* Session timers (RFC 4028). */
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
			/* Per-peer default presentation override (chan_sip parity). */
			int p = ast_parse_caller_presentation(v->value);
			peer->callingpres = (p < 0) ? AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED : p;
		} else if (!strcasecmp(v->name, "sendrpid")) {
			/* Outbound RPID/PAI emission mode. */
			if (!strcasecmp(v->value, "pai")) peer->sendrpid = 1;
			else if (!strcasecmp(v->value, "rpid")) peer->sendrpid = 2;
			else peer->sendrpid = 0;
		} else if (!strcasecmp(v->name, "trustrpid")) {
			/* Trust inbound PAI/RPID. */
			peer->trustrpid = ast_true(v->value);
		} else if (!strcasecmp(v->name, "callcounter")) {
			/* chan_sip parity shorthand. */
			peer->call_limit = ast_true(v->value) ? INT_MAX : 0;
		} else if (!strcasecmp(v->name, "call-limit") || !strcasecmp(v->name, "call_limit")) {
			peer->call_limit = atoi(v->value);
			if (peer->call_limit < 0) peer->call_limit = 0;
		} else if (!strcasecmp(v->name, "busylevel")) {
			/* chan_sip parity soft-cap. */
			peer->busy_level = atoi(v->value);
			if (peer->busy_level < 0) peer->busy_level = 0;
		} else if (!strcasecmp(v->name, "mailbox")) {
			/* Comma-separated mbox@ctx list (no @ defaults to context "default"). */
			sofia_peer_parse_mailboxes(peer, v->value);
		} else if (!strcasecmp(v->name, "outboundproxy")) {
			/* Per-peer outbound proxy override. Empty = unset (no Route); if empty
			 * and sofia_cfg.outboundproxy is set, the general default applies. */
			ast_string_field_set(peer, outboundproxy, v->value);
		} else if (!strcasecmp(v->name, "mohinterpret")) {
			/* Per-peer MOH class for hold-MOH (chan_sip parity). */
			ast_string_field_set(peer, mohinterpret, v->value);
		} else if (!strcasecmp(v->name, "mohsuggest")) {
			/* INBOUND-direction mohsuggest (chan_sip parity); OUTBOUND Alert-Info deferred. */
			ast_string_field_set(peer, mohsuggest, v->value);
		} else if (!strcasecmp(v->name, "language")) {
			/* Per-peer audio-locale, propagated to ast_channel.language at
			 * sofia_new (chan_sip parity). */
			ast_string_field_set(peer, language, v->value);
		} else if (!strcasecmp(v->name, "parkinglot")) {
			/* Per-peer parking-lot routing, propagated to ast_channel.parkinglot
			 * at sofia_new (chan_sip parity). */
			ast_string_field_set(peer, parkinglot, v->value);
		} else if (!strcasecmp(v->name, "defaultip")) {
			/* chan_sip parity. On resolve-fail we WARN + leave defaddr null
			 * (preserve the peer); chan_sip instead drops the whole peer. */
			if (!ast_strlen_zero(v->value) && ast_get_ip(&peer->defaddr, v->value)) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' defaultip='%s' could not be resolved; ignoring\n",
					peer->name, v->value);
				ast_sockaddr_setnull(&peer->defaddr);
			}
		} else if (!strcasecmp(v->name, "maxcallbitrate")) {
			/* chan_sip parity; clamp-negative-to-default. */
			peer->maxcallbitrate = atoi(v->value);
			if (peer->maxcallbitrate < 0) {
				peer->maxcallbitrate = sofia_cfg.default_maxcallbitrate;
			}
		} else if (!strcasecmp(v->name, "amaflags")) {
			/* chan_sip parity; WARN + skip on invalid, preserving the peer
			 * (channel-core default applies at sofia_new). */
			int format = ast_cdr_amaflags2int(v->value);
			if (format < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid AMA Flags '%s'; ignoring\n",
					peer->name, v->value);
			} else {
				peer->amaflags = format;
			}
		} else if (!strcasecmp(v->name, "subscribemwi")) {
			/* chan_sip parity, PARSE-COMPAT-ONLY: chan_sofia is SUBSCRIBE-only by
			 * design, so subscribemwi=yes is a drop-in and subscribemwi=no emits an
			 * operator-honest LOG_NOTICE. KNOWN LIMITATION: no unsolicited MWI NOTIFY. */
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
			/* chan_sip parity. */
			peer->preferred_codec_only = ast_true(v->value);
		} else if (!strcasecmp(v->name, "ignoresdpversion")) {
			/* PARSE-COMPAT-ONLY (chan_sip parity): chan_sofia processes every SDP
			 * unconditionally (KNOWN LIMITATION). */
			peer->ignoresdpversion = ast_true(v->value);
		} else if (!strcasecmp(v->name, "promiscredir")) {
			/* PARSE-COMPAT-ONLY (chan_sip parity): nua_r_redirect handler ABSENT
			 * (KNOWN LIMITATION). */
			peer->promiscredir = ast_true(v->value);
		} else if (!strcasecmp(v->name, "autoframing")) {
			/* PARSE-COMPAT-ONLY (chan_sip parity): sofia_parse_sdp ptime gate not
			 * wired today (KNOWN LIMITATION). */
			peer->autoframing = ast_true(v->value);
		} else if (!strcasecmp(v->name, "timerb")) {
			/* chan_sip parity: sscanf %30d, clamp to default if invalid or < 200. */
			int tmp_b;
			if ((sscanf(v->value, "%30d", &tmp_b) != 1) || tmp_b < 200) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid timerb '%s' (< 200ms or non-integer); using default %d\n",
					peer->name, v->value, sofia_cfg.default_timer_b);
				peer->timer_b = sofia_cfg.default_timer_b;
			} else {
				peer->timer_b = tmp_b;
			}
		} else if (!strcasecmp(v->name, "timert1")) {
			/* chan_sip parity: sscanf %30d; on invalid or < 200 or < t1min fall back
			 * to t1min (chan_sip-faithful floor, not default_timer_t1). */
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
			/* chan_sip parity: per-peer T.38 enable + EC mode + MaxDatagram override.
			 * Comma-separated: yes|no|fec|redundancy|none[,maxdatagram=N]; `yes`
			 * defaults EC = FEC. Parser only stores fields. */
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
			/* chan_sip parity: symmetric-RTP UDPTL destination override (boolean). */
			peer->t38pt_usertpsource = ast_true(v->value) ? 1 : 0;
		} else if (!strcasecmp(v->name, "allowoverlap")) {
			/* chan_sip parity: tri-state yes/dtmf/no. */
			if (ast_true(v->value)) {
				peer->allowoverlap_mode = SOFIA_OVERLAP_YES;
			} else if (!strcasecmp(v->value, "dtmf")) {
				peer->allowoverlap_mode = SOFIA_OVERLAP_DTMF;
			} else {
				peer->allowoverlap_mode = SOFIA_OVERLAP_NO;
			}
		} else if (!strcasecmp(v->name, "progressinband")) {
			/* chan_sip parity: tri-state yes/no/never. Partial wire-in at
			 * sofia_indicate AST_CONTROL_RINGING. */
			if (ast_true(v->value)) {
				peer->progressinband = SOFIA_PROG_INBAND_YES;
			} else if (strcasecmp(v->value, "never")) {
				peer->progressinband = SOFIA_PROG_INBAND_NO;
			} else {
				peer->progressinband = SOFIA_PROG_INBAND_NEVER;
			}
		} else if (!strcasecmp(v->name, "rtptimeout")) {
			/* chan_sip parity: sscanf %30d; clamp to global default on invalid. */
			if ((sscanf(v->value, "%30d", &peer->rtptimeout) != 1) || peer->rtptimeout < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid rtptimeout '%s'; using default\n",
					peer->name, v->value);
				peer->rtptimeout = sofia_cfg.default_rtptimeout;
			}
		} else if (!strcasecmp(v->name, "rtpholdtimeout")) {
			/* chan_sip parity. */
			if ((sscanf(v->value, "%30d", &peer->rtpholdtimeout) != 1) || peer->rtpholdtimeout < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid rtpholdtimeout '%s'; using default\n",
					peer->name, v->value);
				peer->rtpholdtimeout = sofia_cfg.default_rtpholdtimeout;
			}
		} else if (!strcasecmp(v->name, "rtpkeepalive")) {
			/* chan_sip parity. */
			if ((sscanf(v->value, "%30d", &peer->rtpkeepalive) != 1) || peer->rtpkeepalive < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid rtpkeepalive '%s'; using default\n",
					peer->name, v->value);
				peer->rtpkeepalive = sofia_cfg.default_rtpkeepalive;
			}
		} else if (!strcasecmp(v->name, "callerid")) {
			/* chan_sip parity: ast_callerid_split -> cid_name + cid_num. */
			char cid_name_buf[80] = "", cid_num_buf[80] = "";
			ast_callerid_split(v->value, cid_name_buf, sizeof(cid_name_buf),
				cid_num_buf, sizeof(cid_num_buf));
			ast_string_field_set(peer, cid_name, cid_name_buf);
			ast_string_field_set(peer, cid_num, cid_num_buf);
		} else if (!strcasecmp(v->name, "fullname")
				|| !strcasecmp(v->name, "cid_name")) {
			/* fullname (chan_sip parity) + cid_name alias (chan_sip absent). */
			ast_string_field_set(peer, cid_name, v->value);
		} else if (!strcasecmp(v->name, "trunkname")) {
			/* chan_sip parity: trunkname clears cid_name. */
			ast_string_field_set(peer, cid_name, "");
		} else if (!strcasecmp(v->name, "cid_number")) {
			/* chan_sip parity. */
			ast_string_field_set(peer, cid_num, v->value);
		} else if (!strcasecmp(v->name, "cid_tag")) {
			/* chan_sip parity. */
			ast_string_field_set(peer, cid_tag, v->value);
		} else if (!strcasecmp(v->name, "callgroup")) {
			peer->callgroup = ast_get_group(v->value);
		} else if (!strcasecmp(v->name, "allowtransfer")) {
			/* chan_sip parity (config-file branch; mirrors the realtime branch). */
			peer->allowtransfer = ast_true(v->value) ? TRANSFER_OPENFORALL : TRANSFER_CLOSED;
		} else if (!strcasecmp(v->name, "allowsubscribe")) {
			/* chan_sip parity (config-file branch; mirrors the realtime branch). */
			peer->allowsubscribe = ast_true(v->value);
		} else if (!strcasecmp(v->name, "gruu")) {
			/* GRUU Phase 1: config-file branch (sibling of the realtime branch). */
			peer->gruu = ast_true(v->value);
		} else if (!strcasecmp(v->name, "publish")) {
			/* outbound PUBLISH (RFC 3903): config-file branch mirrors the realtime
			 * branch, else static-peer publish=yes is silently dropped. */
			peer->publish = ast_true(v->value);
		} else if (!strcasecmp(v->name, "buggymwi")) {
			/* chan_sip parity (config-file branch; mirrors the realtime branch). */
			peer->buggymwi = ast_true(v->value);
		} else if (!strcasecmp(v->name, "lockuseragent")) {
			/* config-file branch; mirrors the realtime branch (chan_sip is
			 * realtime-only here). */
			peer->lockuseragent = ast_true(v->value);
		} else if (!strcasecmp(v->name, "lockuseragent_prefixes")) {
			/* config-file branch; mirrors the realtime branch. */
			ast_string_field_set(peer, lockuseragent_prefixes, v->value);
		} else if (!strcasecmp(v->name, "usereqphone")) {
			/* config-file branch; mirrors the realtime branch. */
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
			/* chan_sip parity: ast_append_ha(v->name + 7, ...) skips "contact".
			 * Separate ACL chain from peer->ha (source-IP). */
			int ha_error = 0;
			if (!ast_strlen_zero(v->value)) {
				peer->contactha = ast_append_ha(v->name + 7, v->value, peer->contactha, &ha_error);
			}
			if (ha_error) {
				ast_log(LOG_ERROR, "Sofia: bad %s line for peer '%s': %s\n",
					v->name, peer->name, v->value);
			}
		} else if (!strcasecmp(v->name, "directmediapermit") || !strcasecmp(v->name, "directmediadeny")) {
			/* chan_sip parity: ast_append_ha(v->name + 11, ...) skips "directmedia";
			 * remaining "permit"/"deny" is the sense. Applied cross-leg at
			 * sofia_get_rtp_peer (single gate). */
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
			/* Silently accept for chan_sip drop-in template compatibility; not applied
			 * to peer->transport. Transports are controlled per-listener at [general]
			 * bind addresses and per-Contact at REGISTER-time. */
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

	/* All freeable fields are now repopulated and defaulted; release the reload
	 * mutation lock.  Everything below (hint creation, dnsmgr setup, ao2_link)
	 * must run unlocked.  Note: a defaultip=<hostname> resolves via blocking
	 * ast_get_ip inside the widened window (rare, bounded; the common IP literal
	 * is non-blocking). */
	/* sofia_peer_set_defaults reset the lockuseragent CONFIG flag but left the
	 * captured locked_user_agent registration anchor (runtime state).  Now that
	 * the new config is applied, clear the anchor only if lockuseragent ended up
	 * disabled, else a reload would drop the locked UA and let a different
	 * User-Agent re-capture it on the next REGISTER.  Under the held peer->lock. */
	if (locked) {
		if (!peer->lockuseragent) {
			peer->locked_user_agent[0] = '\0';
		}
		ast_mutex_unlock(&peer->lock);
	}

	/* config-file peer hint creation (chan_sip fires only at realtime load);
	 * useful for non-realtime deployments.  Origin tagged via the "config"
	 * source arg -> "sofia_config_peer" registrar (visible in core show hints). */
	/* Link the newly allocated peer FIRST, before the hint/dnsmgr/global-ACL
	 * side effects below, so an ao2_link OOM never orphans them around an
	 * unlinked peer.  A surviving reload peer is already in the container
	 * (re-linking would duplicate the node and leak a ref), so only a new_alloc
	 * peer is linked here. */
	if (new_alloc) {
		if (!ao2_link(peers, peer)) {
			/* OOM — drain MWI before the peer's final unref reaches the destructor,
			 * drop the build ref and bail without creating any side effect to orphan. */
			sofia_peer_drain_mwi(peer);
			ao2_ref(peer, -1);
			return;
		}
	}

	sofia_create_peer_hint(peer, "config");

	/* register async DNS lookup for config-file peers. */
	sofia_dnsmgr_setup_peer(peer);

	/* chan_sip parity: when the flag is set and the peer has a static IP literal,
	 * append a deny rule to the global contact_ha so subsequent REGISTERs from
	 * that address are rejected. */
	if (sofia_cfg.dynamic_exclude_static && !ast_strlen_zero(peer->host)
			&& strcasecmp(peer->host, "dynamic")) {
		struct ast_sockaddr static_addr;
		if (ast_sockaddr_parse(&static_addr, peer->host, 0)) {
			int ha_error = 0;
			ast_rwlock_wrlock(&sofia_contactha_lock);
			sofia_cfg.contact_ha = ast_append_ha("deny",
				ast_sockaddr_stringify_addr(&static_addr),
				sofia_cfg.contact_ha, &ha_error);
			ast_rwlock_unlock(&sofia_contactha_lock);
			if (ha_error) {
				ast_log(LOG_ERROR,
					"Sofia: dynamic_exclude_static — bad addr for static peer '%s' (%s)\n",
					peer->name, peer->host);
			}
		}
	}

	ao2_ref(peer, -1);
}

/* chan_sip parity: sofia_cfg.allowsubscribe = TRUE if any peer flag-allows.
 * Pre-derive FALSE, then an ao2_callback sweep flips it TRUE on the first
 * allowing peer.  One-way flip: once TRUE, stays TRUE for the module lifetime.
 *
 * Called at sofia_load_config conclusion (initial + reload).  Runtime-added
 * realtime peers set sofia_cfg.allowsubscribe=1 inline, so no full sweep is
 * needed (already-TRUE short-circuits). */
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
	/* Default User-Agent e.g. "GABpbx PBX 2.7.1"; [general] useragent= overrides. */
	snprintf(sofia_cfg.useragent, sizeof(sofia_cfg.useragent), "%s %s",
		DEFAULT_USERAGENT, ast_get_version());
	sofia_cfg.allowguest = 1;
	/* feature #5: connection keepalive OFF by default (opt-in). Reset here so a reload that removes
	 * the knob reverts to OFF. Socket-level SO_KEEPALIVE remains on via sofia-sip's own default. */
	sofia_cfg.tcp_keepalive_ms = 0;
	sofia_cfg.tcp_pingpong_ms = 0;
	/* feature #6: TLS hardening knobs unset by default (opt-in; reset so a reload that removes them
	 * reverts to sofia-sip's defaults). */
	sofia_cfg.tls_ciphers[0] = '\0';
	sofia_cfg.tls_min_version[0] = '\0';
	sofia_cfg.tls_verify_depth = 0;
	/* outbound PUBLISH (RFC 3903) off by default (publish_server empty = feature OFF). */
	sofia_cfg.publish_server[0] = '\0';
	sofia_cfg.publish_expires = 0;
	sofia_cfg.publish_domain[0] = '\0';
	sofia_cfg.publish_username[0] = '\0';
	sofia_cfg.publish_password[0] = '\0';
	sofia_cfg.busy_on_active = 0;
	sofia_cfg.max_contacts = 6;
	sofia_cfg.encryption = 0;
	/* empty default = sdp_crypto.c hardcoded fallback (AES_CM_128_HMAC_SHA1_80). */
	sofia_cfg.default_srtpcipher[0] = '\0';
	/* SRTP per-suite-fresh-key option: default 0 = shared-key mode. Module-scope
	 * mirror reset adjacent for sdp_crypto.c extern visibility. */
	sofia_cfg.srtp_per_suite_keys = 0;
	sofia_srtp_per_suite_keys = 0;
	/* default 0 = chan_sip parity (per-peer insecure=invite bypass remains active).
	 * force_invite_auth=yes activates the global digest-auth lockdown override. */
	sofia_cfg.force_invite_auth = 0;
	/* Default 0 = use SOFIA_NONCE_TTL_SEC_DEFAULT (3600s).
	 * Operator override via [general] nonce_ttl_seconds=N. */
	sofia_cfg.nonce_ttl_seconds = 0;
	/* Built-in default BOTH = offer MD5 + SHA-256. Operator selects via [general]
	 * auth_algorithms = both|md5|sha256 (the shipped sofia.conf sets md5). */
	sofia_cfg.auth_algorithms = SOFIA_AUTH_ALG_BOTH;
	/* session timers (RFC 4028): chan_sip-parity defaults. */
	sofia_cfg.default_session_timers = SESSION_TIMERS_ACCEPT; /* honor inbound; no initiate */
	sofia_cfg.default_session_expires = 1800;                  /* RFC 4028 §4 typical */
	sofia_cfg.default_session_minse = 90;                      /* RFC 4028 §3 floor */
	sofia_cfg.default_session_refresher = SESSION_REFRESHER_AUTO;
	/* chan_sip parity ("Merrily accept all transfers by default"). */
	sofia_cfg.default_allowtransfer = TRANSFER_OPENFORALL;
	/* per-peer allowsubscribe default TRUE (chan_sip parity). The DERIVED global
	 * sofia_cfg.allowsubscribe ban-all flag starts FALSE and is flipped TRUE by
	 * sofia_post_config_derive_allowsubscribe if any peer ends up allowing
	 * (post-config-load sweep instead of per-peer-build duplication). */
	sofia_cfg.default_allowsubscribe = 1;
	sofia_cfg.allowsubscribe = 0;
	/* empty regcontext = mechanism disabled (chan_sip parity); regextenonqualify default FALSE. */
	sofia_cfg.regcontext[0] = '\0';
	sofia_cfg.regextenonqualify = 0;
	/* empty default (chan_sip parity). */
	sofia_cfg.default_subscribecontext[0] = '\0';
	/* registration TTL bounds + 423 Interval Too Brief (chan_sip parity, 60/3600/120).
	 * Operators override via [general] minexpiry/maxexpiry/defaultexpiry. */
	sofia_cfg.min_expiry     = DEFAULT_MIN_EXPIRY;
	sofia_cfg.max_expiry     = DEFAULT_MAX_EXPIRY;
	sofia_cfg.default_expiry = DEFAULT_DEFAULT_EXPIRY;
	/* opt in via [general] usereqphone=yes or per-peer override. */
	sofia_cfg.default_usereqphone = 0;
	/* RFC 3261 §20.22 default 70 (chan_sip parity). */
	sofia_cfg.default_max_forwards = DEFAULT_MAX_FORWARDS;
	/* RFC 3261 §17.1.1.2 minimum bound, default 100ms (chan_sip parity). */
	sofia_cfg.t1min = DEFAULT_T1MIN;
	/* chan_sip parity. */
	sofia_cfg.relaxdtmf = 0;
	sofia_cfg.prematuremediafilter = 1;
	/* chan_sip parity: register_timeout=20s; register_attempts=0 (unlimited). */
	sofia_cfg.register_timeout = DEFAULT_REGISTRATION_TIMEOUT;
	sofia_cfg.register_attempts = 0;
	/* chan_sip parity, default FALSE. PARSE-COMPAT-ONLY — experimental, effect-deferred. */
	sofia_cfg.directrtpsetup = 0;
	/* chan_sip parity, default TRUE. Critical security default: RFC 3261 §22.4
	 * username-enumeration prevention active out-of-the-box. */
	sofia_cfg.alwaysauthreject = 1;
	/* chan_sip parity, default FALSE. PARSE-COMPAT-ONLY — sofia-sip native compact-emit
	 * gate absent; field parsed + stored but no behavioral effect today. */
	sofia_cfg.compactheaders = 0;
	/* empty default (divergence from chan_sip SIP_UNKNOWN bitmask —
	 * chan_sofia uses sofia-sip NUTAG_APPL_METHOD for unknown-method gating). */
	sofia_cfg.disallowed_methods[0] = '\0';
	/* contactpermit/contactdeny: clear ACL chain on each load (chan_sip parity). */
	ast_rwlock_wrlock(&sofia_contactha_lock);
	if (sofia_cfg.contact_ha) {
		ast_free_ha(sofia_cfg.contact_ha);
		sofia_cfg.contact_ha = NULL;
	}
	ast_rwlock_unlock(&sofia_contactha_lock);
	/* MWI defaults (RFC 3842 + chan_sip parity). */
	sofia_cfg.mwi_from[0] = '\0';
	ast_copy_string(sofia_cfg.notifymime, "application/simple-message-summary", sizeof(sofia_cfg.notifymime));
	ast_copy_string(sofia_cfg.vmexten, "asterisk", sizeof(sofia_cfg.vmexten));
	sofia_cfg.mwi_expiry = 3600;
	/* outboundproxy default empty — operator opts in via [general] or per-peer. */
	sofia_cfg.outboundproxy[0] = '\0';
	/* empty default = no language override (chan_sip parity); gabpbx-core default used. */
	sofia_cfg.default_language[0] = '\0';
	/* parkinglot default "default" (chan_sip parity). Behavior change from the prior
	 * chan_sofia silent-empty baseline; set [general] parkinglot= empty to restore it. */
	ast_copy_string(sofia_cfg.default_parkinglot, "default", sizeof(sofia_cfg.default_parkinglot));
	/* default FALSE (chan_sip parity). When 0, expired contacts removed normally
	 * by sofia_expire_contacts_cb periodic ao2_callback. */
	sofia_cfg.ignore_regexpire = 0;
	/* maxcallbitrate default 384 kbps (chan_sip parity) — every video SDP emits b=CT:384.
	 * Behavior change from the prior chan_sofia no-b=CT baseline; set maxcallbitrate=0 to
	 * restore it. Audio-only unaffected (b=CT gated inside if (needvideo) block). */
	sofia_cfg.default_maxcallbitrate = 384;
	/* chan_sip parity, default FALSE. */
	sofia_cfg.match_auth_username = 0;
	/* chan_sip parity, default FALSE. PARSE-COMPAT-ONLY. */
	sofia_cfg.legacy_useroption_parsing = 0;
	/* chan_sip parity, default 1. Behavior change from the prior chan_sofia
	 * no-normalization baseline. */
	sofia_cfg.shrinkcallerid = 1;
	/* chan_sip parity, default FALSE. Gates the peer->onHold counter update at the
	 * sofia_process_reinvite hold transition; AMI Hold emission is unconditional. */
	sofia_cfg.notifyhold = 0;
	/* chan_sip parity, default TRUE. PARSE-COMPAT-ONLY — effect-deferred until
	 * presence/dialog-info NOTIFY infrastructure landed. */
	sofia_cfg.notifyringing = 1;
	/* chan_sip parity, default FALSE. Security hardening: peer-build wire-in appends
	 * static peer IPs as deny rules to sofia_cfg.contact_ha. */
	sofia_cfg.dynamic_exclude_static = 0;
	/* chan_sip parity, default FALSE. PARSE-COMPAT-ONLY — chan_sofia refuses to
	 * auto-create unknown peers (security-stronger via alwaysauthreject). */
	sofia_cfg.autocreatepeer = 0;
	/* chan_sip parity, default FALSE. Inherited by sofia_peer_alloc; codec-list-narrowing
	 * wired at sofia_generate_sdp, direction-symmetric. */
	sofia_cfg.default_preferred_codec_only = 0;
	/* chan_sip parity, default NEVER (no in-band audio with a provisional response).
	 * Partial wire-in at sofia_indicate AST_CONTROL_RINGING for the YES state. */
	sofia_cfg.default_progressinband = SOFIA_PROG_INBAND_NEVER;
	/* chan_sip parity, default FALSE. PARSE-COMPAT-ONLY — chan_sofia nua_r_redirect
	 * handler absent; no behavioral effect. */
	sofia_cfg.default_promiscredir = 0;
	/* chan_sip parity, default FALSE. PARSE-COMPAT-ONLY — sofia_parse_sdp ptime gate
	 * not wired today. */
	sofia_cfg.default_autoframing = 0;
	/* chan_sip parity, default NONE. When enabled, covers DSP CNG detection and
	 * peer T.38 reINVITE detection. */
	sofia_cfg.default_faxdetect_mode = SOFIA_FAX_DETECT_NONE;
	/* T38FaxMaxDatagram override sentinel -1 (chan_sip parity): -1 = "use built-in
	 * 200-byte default". Operator overrides via [general] t38_maxdatagram=N or per-peer
	 * t38pt_udptl=...,maxdatagram=N. */
	sofia_cfg.default_t38_maxdatagram = SOFIA_T38_MAXDATAGRAM_SENTINEL;
	/* chan_sip parity, default 32000ms (= 64 * DEFAULT_TIMER_T1). Wire-in via
	 * NTATAG_SIP_T1X64 at nua_create. */
	sofia_cfg.default_timer_b = 32000;
	/* chan_sip parity, default 500ms. Wire-in via NTATAG_SIP_T1(default_timer_t1) at
	 * nua_create. */
	sofia_cfg.default_timer_t1 = 500;
	/* cross-validation flags: clear at config-load start; set when the respective
	 * [general] key is parsed; consumed at the timer cross-validation below. */
	sofia_timerb_set = 0;
	sofia_timert1_set = 0;
	/* chan_sip parity, default YES. Behavior change from the prior chan_sofia baseline
	 * (no overlap-dial at all). Wire-in active at 3 sites (sofia_process_invite +
	 * sofia_indicate AST_CONTROL_INCOMPLETE + nua_r_invite 484). */
	sofia_cfg.default_allowoverlap_mode = SOFIA_OVERLAP_YES;
	/* chan_sip parity, default TRUE. PARSE-COMPAT-ONLY — chan_sofia delegates
	 * network-change handling to sofia-sip sres_resolver + per-peer dnsmgr. */
	sofia_cfg.subscribe_network_change_event = 1;
	/* chan_sip parity, default FALSE. Wire-in at the sofia_process_register
	 * ast_update_realtime callsites; NULL-key pair no-op when the flag is clear. */
	sofia_cfg.rtsave_sysname = 0;
	/* chan_sip parity, default TRUE. Gates the realtime peer updates in
	 * sofia_process_register. */
	sofia_cfg.peer_rtupdate = 1;
	/* Phase 1 register pool: default OFF (dark launch) + auto lane count. */
	sofia_cfg.register_pool = 0;
	sofia_cfg.register_pool_workers = 0;
	/* chan_sip parity, default FALSE. PARSE-COMPAT-ONLY — chan_sofia ao2 registry
	 * always caches all peers; no behavioral effect. */
	sofia_cfg.rtcachefriends = 0;
	/* chan_sip parity, default 120s + disabled. PARSE-COMPAT-ONLY — chan_sofia ao2
	 * registry has no peer-level auto-clear. */
	sofia_cfg.rtautoclear = 120;
	sofia_cfg.rtautoclear_enabled = 0;
	/* chan_sip parity, default FALSE. Wired at 3 auth-challenge callsites via
	 * sofia_get_realm_for_dialog (leverages the domain_list). */
	sofia_cfg.domainsasrealm = 0;
	/* chan_sip parity, default TRUE (permissive). Special-case auto-set wired at the
	 * end of sofia_load_config (safety net). */
	sofia_cfg.allow_external_domains = 1;
	/* chan_sip parity, default FALSE. Auto-add fires at sofia_load_config conclusion
	 * AFTER the allowexternaldomains special-case (order: allowexternaldomains first
	 * → autodomain auto-add second → both honored). */
	sofia_cfg.autodomain = 0;
	/* chan_sip parity, default FALSE. PARSE-COMPAT-ONLY — sofia_should_use_externaddr
	 * signature divergence. */
	sofia_cfg.matchexternaddrlocally = 0;
	/* Reset the externaddr/externhost NAT bundle + localnet here so a REMOVED
	 * externaddr=/externhost=/externport= line doesn't silently keep the stale public
	 * IP/port on reload (calls would advertise the old NAT address).
	 * sofia_parse_general_config below repopulates only what the new config carries.
	 * localha (the live ACL) is freed+rebuilt below; localnet is its display/storage
	 * twin. externexpire/externrefresh are the DDNS lazy-refresh pair — clear the
	 * deadline, restore the 10s default interval. */
	sofia_cfg.externaddr[0] = '\0';
	sofia_cfg.externhost[0] = '\0';
	sofia_cfg.externtcpport = 0;
	sofia_cfg.externtlsport = 0;
	sofia_cfg.externexpire = 0;
	sofia_cfg.externrefresh = 10;
	sofia_cfg.localnet[0] = '\0';
	/* rtp-timeout bundle: chan_sip parity, default 0 (disabled). Inherited by
	 * sofia_peer_alloc; sofia_rtp_init wires set_timeout/set_hold_timeout/set_keepalive
	 * when non-zero. */
	sofia_cfg.default_rtptimeout = 0;
	sofia_cfg.default_rtpholdtimeout = 0;
	sofia_cfg.default_rtpkeepalive = 0;
	/* tos/cos bundle: chan_sip parity, default 0 (no QoS markings). RTP audio/video
	 * wired via ast_rtp_instance_set_qos; tos_sip via TPTAG_TOS at nua_create.
	 * cos_sip + tos_text + cos_text are PARSE-COMPAT-ONLY (sofia-sip TPTAG_COS absent +
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
	/* reload-UAF fix: serialize the free+NULL against channel-thread readers
	 * of sofia_cfg.localha (sofia_should_use_externaddr). */
	ast_rwlock_wrlock(&sofia_localha_lock);
	ast_free_ha(sofia_cfg.localha);
	sofia_cfg.localha = NULL;
	ast_rwlock_unlock(&sofia_localha_lock);

	sofia_parse_general_config(cfg);

	for (cat = ast_category_browse(cfg, NULL); cat; cat = ast_category_browse(cfg, cat)) {
		if (!strcasecmp(cat, "general") || !strcasecmp(cat, "authentication")) {
			continue;
		}
		sofia_parse_peer_config(cat, cfg);
	}

	/* Post-config-load timer cross-validation (chan_sip parity). Order matters —
	 * fires BEFORE nua_create reads sofia_cfg.default_timer_t1/default_timer_b. */
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

	/* autodomain (chan_sip parity): auto-add system listening-addresses + FQDN to
	 * domain_list (bindaddr + tlsbindaddr + wsbindaddr + externaddr + gethostname()).
	 * Order matters — fires BEFORE the allowexternaldomains special-case below so the
	 * gating logic sees the auto-added domains as "domain_list non-empty". */
	if (sofia_cfg.autodomain) {
		char temp[MAXHOSTNAMELEN];
		/* bindaddr IP — primary listener (skip wildcard 0.0.0.0) */
		if (!ast_strlen_zero(sofia_cfg.bindaddr)
		    && strcmp(sofia_cfg.bindaddr, "0.0.0.0") != 0) {
			sofia_domain_list_add(sofia_cfg.bindaddr);
		}
		/* TLS bindaddr IP if configured */
		if (!ast_strlen_zero(sofia_cfg.tlsbindaddr)
		    && strcmp(sofia_cfg.tlsbindaddr, "0.0.0.0") != 0) {
			sofia_domain_list_add(sofia_cfg.tlsbindaddr);
		}
		/* WS bindaddr IP if configured */
		if (!ast_strlen_zero(sofia_cfg.wsbindaddr)
		    && strcmp(sofia_cfg.wsbindaddr, "0.0.0.0") != 0) {
			sofia_domain_list_add(sofia_cfg.wsbindaddr);
		}
		/* externaddr IP if configured (NAT traversal) */
		if (!ast_strlen_zero(sofia_cfg.externaddr)) {
			sofia_domain_list_add(sofia_cfg.externaddr);
		}
		/* gethostname() FQDN — system hostname */
		if (!gethostname(temp, sizeof(temp))) {
			sofia_domain_list_add(temp);
		}
	}

	/* allowexternaldomains safety net (chan_sip parity): if disabled BUT no domain=
	 * entries are configured, auto-revert to allow + warn (no point disabling external
	 * with no local domains). autodomain auto-add above already counts toward the
	 * domain_list non-empty check. */
	if (!sofia_cfg.allow_external_domains && AST_LIST_EMPTY(&domain_list)) {
		ast_log(LOG_WARNING, "Sofia: allowexternaldomains=no but no domain= entries configured; reverting to allow=yes\n");
		sofia_cfg.allow_external_domains = 1;
	}

	/* Derive the global allowsubscribe = TRUE if any peer flag-allows (chan_sip parity,
	 * done as one centralized sweep). */
	sofia_post_config_derive_allowsubscribe();

	/* Phase 1: create/toggle the bounded REGISTER pool per config (boot + reload). */
	sofia_regpool_update();

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

		/* Operator-tuned interval between register-retry passes (chan_sip parity).
		 * Default 20s; the > 0 guard defends against a bad config. */
		sleep(sofia_cfg.register_timeout > 0 ? sofia_cfg.register_timeout : DEFAULT_REGISTRATION_TIMEOUT);

		if (!sofia_nua) {
			break;
		}

		now = time(NULL);
		i = ao2_iterator_init(peers, 0);
		while ((peer = ao2_iterator_next(&i))) {
			/* Evaluate the whole register-retry gate under peer->lock so the
			 * pre-check sees the same values the response handler writes under
			 * the lock (peer->nh / reg_expiry / reg_attempts at the nua_r_register
			 * sites, peer->secret/host at reload).  Previously the nh/expiry/
			 * secret/host/attempts reads happened lock-free, racing those
			 * writers. */
			ast_mutex_lock(&peer->lock);
			if (peer->nh && peer->reg_expiry > 0 &&
			    !ast_strlen_zero(peer->secret) &&
			    strcasecmp(peer->host, "dynamic") != 0 &&
			    /* attempt-cap gate (chan_sip parity): skip when register_attempts > 0
			     * AND the peer has reached the cap. */
			    (sofia_cfg.register_attempts == 0 || peer->reg_attempts < sofia_cfg.register_attempts) &&
			    now >= peer->reg_expiry) {
				char uri[256];
				/* bracket-wrap IPv6 host */
				char hbuf[80];
				snprintf(uri, sizeof(uri), "sip:%s@%s:%d",
					peer->defaultuser,
					sofia_uri_format_host(peer->host, hbuf, sizeof(hbuf)),
					peer->port);
				if (sofia_debug)
					ast_verbose("Sofia: Re-registering %s\n", uri);
				/* RFC 3261 §20.22 outbound REGISTER refresh. */
				char mf_str_reregister[8];
				char instance_feature_rereg[120];
				snprintf(mf_str_reregister, sizeof(mf_str_reregister), "%d", peer->maxforwards);
				/* GRUU Phase 1: re-advertise +sip.instance on the refresh REGISTER too. */
				sofia_build_instance_feature(peer, instance_feature_rereg, sizeof(instance_feature_rereg));
				/* callbackextension: NUTAG_M_USERNAME override on the re-REGISTER,
				 * matching the initial-register and auth-challenge sites. */
				nua_register(peer->nh,
					NUTAG_URL(uri),
					SIPTAG_FROM_STR(uri),
					SIPTAG_MAX_FORWARDS_STR(mf_str_reregister),
					TAG_IF(!ast_strlen_zero(peer->callbackextension),
						NUTAG_M_USERNAME(peer->callbackextension)),
					TAG_IF(peer->gruu, NUTAG_M_FEATURES(instance_feature_rereg)),
					TAG_END());
				peer->reg_expiry = now + 60;
			}
			ast_mutex_unlock(&peer->lock);
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
				/* bracket-wrap IPv6 host */
				char hbuf[80];

				snprintf(uri, sizeof(uri), "sip:%s@%s:%d",
					peer->defaultuser,
					sofia_uri_format_host(peer->host, hbuf, sizeof(hbuf)),
					peer->port);

				/* Outbound REGISTER Route header from peer/[general] outboundproxy.
				 * Sticky-on-handle: re-register reuses the existing handle's route until
				 * the next destroy+recreate cycle. */
				sofia_format_outboundproxy(peer, route_buf, sizeof(route_buf));

				if (peer->nh) {
					/* Detach hmagic before destroying the previous register cycle's
					 * handle.  We're on sofia_thread and peer is alive, so this is not a
					 * UAF — but a late 401/200 for the previous REGISTER on the old
					 * peer->nh would reach sofia_event_callback with magic = peer and
					 * re-enter the register state machine against a stale handle.
					 * bind(NULL) makes the old handle inert so the `if (hmagic)` gates
					 * short-circuit any late event. */
					nua_handle_t *old_rnh = peer->nh;
					peer->nh = NULL;
					nua_handle_bind(old_rnh, NULL);
					nua_handle_destroy(old_rnh);
				}

				/* GRUU Phase 1 (gruu=yes): advertise a stable +sip.instance on the REGISTER Contact so
				 * a GRUU-capable registrar can mint a pub-gruu. Advertisement only — see
				 * sofia_build_instance_feature (NUTAG_M_FEATURES, not the outbound engine). */
				char instance_feature[120];
				sofia_build_instance_feature(peer, instance_feature, sizeof(instance_feature));

				peer->nh = nua_handle(sofia_nua, peer,
					NUTAG_URL(uri),
					SIPTAG_TO_STR(uri),
					TAG_IF(route_buf[0], NUTAG_INITIAL_ROUTE_STR(route_buf)),
					TAG_IF(peer->gruu, NUTAG_M_FEATURES(instance_feature)),
					TAG_END());

				/* RFC 3261 §20.22 outbound REGISTER. */
				char mf_str_initreg[8];
				snprintf(mf_str_initreg, sizeof(mf_str_initreg), "%d", peer->maxforwards);
				/* callbackextension: NUTAG_M_USERNAME drives the Contact URL username
				 * at initial-register time. */
				nua_register(peer->nh,
					NUTAG_URL(uri),
					SIPTAG_FROM_STR(uri),
					SIPTAG_MAX_FORWARDS_STR(mf_str_initreg),
					TAG_IF(!ast_strlen_zero(peer->callbackextension),
						NUTAG_M_USERNAME(peer->callbackextension)),
					TAG_IF(peer->gruu, NUTAG_M_FEATURES(instance_feature)),
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

/* Cross-thread dispatch helper — post a callback to run on sofia_thread (where
 * sofia_root was created). AMI handlers run on a separate manager thread; nua_handle
 * ops MUST run on sofia_thread per sofia-sip's same-thread-as-create contract
 * (su_root_destroy + nua_handle ops assert it). The msg is sent via su_msg_send;
 * sofia_root's run loop picks it up and invokes sofia_dispatch_handler.
 *
 * Caller responsibility: data lifetime must outlast the dispatch (typical pattern:
 * heap-allocate, callback frees). NULL data is allowed if the callback ignores it.
 *
 * Returns 0 on success, -1 on failure. Does NOT block — queues and returns. */

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

int sofia_dispatch_to_root_thread(void (*callback)(void *), void *data)
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
 *  Listener-config changes (the 12 fields baked into nua_create at
 *  sofia_thread startup — bindaddr, bindport, tlsbindaddr, tlsbindport,
 *  tlscertfile, tlsverify, wsbindaddr, wsbindport, wssbindaddr,
 *  wssbindport, timert1, timerb) are pre-validated BEFORE any sofia_cfg mutation:
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
	/* Owned, ref-counted message buffer.  The worker writes the reason
	 * here under req->mutex; the caller copies it out under req->mutex
	 * after the wait returns.  Never a borrowed caller-stack pointer —
	 * on timeout the caller frame unwinds while the worker still holds a
	 * ref, so the destination must live inside the ref-protected struct. */
	char        errmsg[256];
};

static void sofia_reload_req_destructor(void *obj)
{
	struct sofia_reload_req *req = obj;
	ast_cond_destroy(&req->cond);
	ast_mutex_destroy(&req->mutex);
}

/* Compare the 12 listener-baked fields in the freshly-parsed cfg against
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
	/* The listeners are baked at nua_create and only a restart rebinds them, so this
	 * guard warns when the new file's EFFECTIVE listener config differs from what is
	 * running. Comparing each PRESENT key against live sofia_cfg would miss a REMOVED
	 * listener key (e.g. a deleted tlsbindport=) — it would read as "no change" even
	 * though a restart would drop that listener. So instead build a SCRATCH listener
	 * config from compiled defaults + only the listener keys the new file still carries
	 * — mirroring sofia_parse_general_config exactly, including the udpbindaddr
	 * host:port split, the tlscertdir / tlsverifyserver aliases, and the
	 * t1min/timerb/timert1 cross-validation — then compare that effective state to live
	 * sofia_cfg. A removed key now surfaces as default-vs-live. A flat {key, default}
	 * table can't do this because of the aliases and because t1min canonically rewrites
	 * the effective timer_t1/b. */
	struct {
		char bindaddr[128];
		int bindport;
		char tlsbindaddr[64];
		int tlsbindport;
		char tlscertfile[256];
		char wsbindaddr[64];
		int wsbindport;
		char wssbindaddr[64];
		int wssbindport;
		int tlsverify;
		char tls_ciphers[256];	/* feature #6: a change forces a listener recreate (TLS ctx is built at listener create) */
		char tls_min_version[8];
		int tls_verify_depth;
		int t1min;
		int timer_t1;
		int timer_b;
		int tcp_keepalive_ms;	/* feature #5: a change forces a listener recreate (TPTAG set at nua_create) */
		int tcp_pingpong_ms;
	} s;
	int timert1_set = 0, timerb_set = 0;
	struct ast_variable *v;
	char buf[256];
	int changed = 0;
	int written = 0;

	buf[0] = '\0';

	/* Compiled defaults — identical to a fresh module load: sofia_apply_config's
	 * explicit resets for bindaddr/bindport/t1min/timers, and static-zero/empty for
	 * the TLS/WS fields it leaves at their initial value. Using fresh defaults (rather
	 * than live sofia_cfg) is exactly what lets a removed key be detected. */
	ast_copy_string(s.bindaddr, DEFAULT_BINDADDR, sizeof(s.bindaddr));
	s.bindport = DEFAULT_SIP_PORT;
	s.tlsbindaddr[0] = '\0';
	s.tlsbindport = 0;
	s.tlscertfile[0] = '\0';
	s.wsbindaddr[0] = '\0';
	s.wsbindport = 0;
	s.wssbindaddr[0] = '\0';
	s.wssbindport = 0;
	s.tlsverify = 0;
	s.tls_ciphers[0] = '\0';	/* feature #6: defaults match the live-parser defaults */
	s.tls_min_version[0] = '\0';
	s.tls_verify_depth = 0;
	s.t1min = DEFAULT_T1MIN;
	s.timer_t1 = 500;
	s.timer_b = 32000;
	s.tcp_keepalive_ms = 0;	/* feature #5: default OFF (matches the live-parser default) */
	s.tcp_pingpong_ms = 0;

	for (v = ast_variable_browse(cfg, "general"); v; v = v->next) {
		if (!strcasecmp(v->name, "bindaddr")) {
			ast_copy_string(s.bindaddr, v->value, sizeof(s.bindaddr));
		} else if (!strcasecmp(v->name, "bindport") || !strcasecmp(v->name, "udpbindaddr")) {
			/* IPv6-aware host:port split on a LOCAL copy — mirrors
			 * sofia_parse_general_config so a bracketed [2001:db8::1]:5060 is not
			 * truncated at its first colon. */
			char hpbuf[128];
			ast_copy_string(hpbuf, v->value, sizeof(hpbuf));
			if (hpbuf[0] == '[') {
				char *end = strchr(hpbuf, ']');
				if (end) {
					char *port = (end[1] == ':') ? end + 2 : NULL;
					*end = '\0';
					ast_copy_string(s.bindaddr, hpbuf + 1, sizeof(s.bindaddr));
					if (port && *port) {
						s.bindport = atoi(port);
					}
				}
			} else {
				char *first = strchr(hpbuf, ':');
				char *last = strrchr(hpbuf, ':');
				if (first && first == last) {
					*first = '\0';
					ast_copy_string(s.bindaddr, hpbuf, sizeof(s.bindaddr));
					s.bindport = atoi(first + 1);
				} else if (first) {
					ast_copy_string(s.bindaddr, hpbuf, sizeof(s.bindaddr));
				} else {
					s.bindport = atoi(hpbuf);
				}
			}
		} else if (!strcasecmp(v->name, "port")) {
			s.bindport = atoi(v->value);
		} else if (!strcasecmp(v->name, "tlsbindaddr")) {
			ast_copy_string(s.tlsbindaddr, v->value, sizeof(s.tlsbindaddr));
		} else if (!strcasecmp(v->name, "tlsbindport")) {
			s.tlsbindport = atoi(v->value);
		} else if (!strcasecmp(v->name, "tlscertfile") || !strcasecmp(v->name, "tlscertdir")) {
			ast_copy_string(s.tlscertfile, v->value, sizeof(s.tlscertfile));
		} else if (!strcasecmp(v->name, "tcp_keepalive")) {
			s.tcp_keepalive_ms = sofia_cfg_seconds_to_ms(v->value);
		} else if (!strcasecmp(v->name, "tcp_pingpong")) {
			s.tcp_pingpong_ms = sofia_cfg_seconds_to_ms(v->value);
		} else if (!strcasecmp(v->name, "tlsverify") || !strcasecmp(v->name, "tlsverifyserver")) {
			s.tlsverify = ast_true(v->value);
		} else if (!strcasecmp(v->name, "tls_ciphers")) {
			ast_copy_string(s.tls_ciphers, v->value, sizeof(s.tls_ciphers));
		} else if (!strcasecmp(v->name, "tls_min_version")) {
			/* mirror the live parser: only store a recognized value (else it stays unset). */
			if (sofia_tls_min_version_valid(v->value)) {
				ast_copy_string(s.tls_min_version, v->value, sizeof(s.tls_min_version));
			}
		} else if (!strcasecmp(v->name, "tls_verify_depth")) {
			s.tls_verify_depth = sofia_cfg_verify_depth(v->value);
		} else if (!strcasecmp(v->name, "wsbindaddr")) {
			ast_copy_string(s.wsbindaddr, v->value, sizeof(s.wsbindaddr));
		} else if (!strcasecmp(v->name, "wsbindport")) {
			s.wsbindport = atoi(v->value);
		} else if (!strcasecmp(v->name, "wssbindaddr")) {
			ast_copy_string(s.wssbindaddr, v->value, sizeof(s.wssbindaddr));
		} else if (!strcasecmp(v->name, "wssbindport")) {
			s.wssbindport = atoi(v->value);
		} else if (!strcasecmp(v->name, "t1min")) {
			int v_int = 0;
			if (sscanf(v->value, "%30d", &v_int) != 1 || v_int < 10) {
				s.t1min = DEFAULT_T1MIN;
			} else {
				s.t1min = v_int;
			}
		} else if (!strcasecmp(v->name, "timerb")) {
			int tmp_b = atoi(v->value);
			if (tmp_b < 500) {
				s.timer_b = s.t1min * 64;
			} else {
				s.timer_b = tmp_b;
			}
			timerb_set = 1;
		} else if (!strcasecmp(v->name, "timert1")) {
			int tmp_t1;
			if ((sscanf(v->value, "%30d", &tmp_t1) != 1) || tmp_t1 < 200) {
				s.timer_t1 = 500;
			} else {
				s.timer_t1 = tmp_t1;
			}
			timert1_set = 1;
		}
	}

	/* Same post-parse timer cross-validation as sofia_apply_config so the EFFECTIVE
	 * (not raw) timer_t1/timer_b are compared. t1min is itself a timer input here even
	 * though it is not a listener key on its own: it floors timer_t1 and seeds the
	 * timerb< 500 fallback, so a changed t1min can shift the effective timers (and thus
	 * the NTATAG_SIP_T1/T1X64 baked at nua_create) — that is why it is parsed into the
	 * scratch above. timerb= is order-sensitive on t1min in the real parser too; t1min
	 * appears before timerb in practice and the < 500 branch already used s.t1min. */
	if (s.timer_t1 < s.t1min) {
		s.timer_t1 = s.t1min;
	}
	if (s.timer_b < s.timer_t1 * 64) {
		if (timerb_set && timert1_set) {
			/* warn-only in the real parser — no value rewrite */
		} else if (timerb_set) {
			s.timer_t1 = s.timer_b / 64;
			if (s.timer_t1 < s.t1min) {
				s.timer_t1 = s.t1min;
				s.timer_b = s.timer_t1 * 64;
			}
		} else {
			s.timer_b = s.timer_t1 * 64;
		}
	}

	/* Compare effective scratch vs live sofia_cfg; name each changed knob. */
#define SOFIA_LISTENER_FLAG(_name) do { \
		if (written < (int)sizeof(buf) - 24) { \
			written += snprintf(buf + written, sizeof(buf) - written, "%s%s", written ? "," : "", (_name)); \
		} \
		changed = 1; \
	} while (0)
#define SOFIA_LISTENER_CMP_STR(_field, _name) do { \
		if (strcmp(sofia_cfg._field, s._field) != 0) { SOFIA_LISTENER_FLAG(_name); } \
	} while (0)
#define SOFIA_LISTENER_CMP_INT(_field, _name) do { \
		if (sofia_cfg._field != s._field) { SOFIA_LISTENER_FLAG(_name); } \
	} while (0)

	SOFIA_LISTENER_CMP_STR(bindaddr, "bindaddr");
	SOFIA_LISTENER_CMP_INT(bindport, "bindport");
	SOFIA_LISTENER_CMP_STR(tlsbindaddr, "tlsbindaddr");
	SOFIA_LISTENER_CMP_INT(tlsbindport, "tlsbindport");
	SOFIA_LISTENER_CMP_STR(tlscertfile, "tlscertfile");
	SOFIA_LISTENER_CMP_STR(wsbindaddr, "wsbindaddr");
	SOFIA_LISTENER_CMP_INT(wsbindport, "wsbindport");
	SOFIA_LISTENER_CMP_STR(wssbindaddr, "wssbindaddr");
	SOFIA_LISTENER_CMP_INT(wssbindport, "wssbindport");
	/* feature #5: the keepalive TPTAGs are set at nua_create, so a change needs the listeners recreated. */
	SOFIA_LISTENER_CMP_INT(tcp_keepalive_ms, "tcp_keepalive");
	SOFIA_LISTENER_CMP_INT(tcp_pingpong_ms, "tcp_pingpong");
	/* scratch field names diverge here (s.timer_t1 vs sofia_cfg.default_timer_t1). */
	if (sofia_cfg.default_timer_t1 != s.timer_t1) {
		SOFIA_LISTENER_FLAG("timert1");
	}
	if (sofia_cfg.default_timer_b != s.timer_b) {
		SOFIA_LISTENER_FLAG("timerb");
	}
	if (!!sofia_cfg.tlsverify != !!s.tlsverify) {
		SOFIA_LISTENER_FLAG("tlsverify");
	}
	/* feature #6: TLS-hardening knobs are baked into the TLS context at listener create, so a change
	 * needs the listeners recreated. Compare the version as a STRING (its mask 0 for "1.3" collides
	 * with unset). */
	SOFIA_LISTENER_CMP_STR(tls_ciphers, "tls_ciphers");
	SOFIA_LISTENER_CMP_STR(tls_min_version, "tls_min_version");
	SOFIA_LISTENER_CMP_INT(tls_verify_depth, "tls_verify_depth");

#undef SOFIA_LISTENER_CMP_INT
#undef SOFIA_LISTENER_CMP_STR
#undef SOFIA_LISTENER_FLAG

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
	/* Unsubscribe MWI before this swept peer's final unref (the OBJ_UNLINK caller
	 * drops the container ref next), so the destructor's post-refcount-0 drain can't
	 * resurrect the peer via a concurrent mwi_event_cb. */
	sofia_peer_drain_mwi(peer);
	/* Drop the dialplan hint extension this peer created, if any.  The registrar
	 * string matches what sofia_create_peer_hint passed, so we remove only our own. */
	if (!ast_strlen_zero(peer->subscribecontext) && !ast_strlen_zero(peer->regexten)) {
		ast_context_remove_extension(peer->subscribecontext,
			peer->regexten, PRIORITY_HINT, "sofia_config_peer");
	}
	/* Release the dnsmgr entry FIRST, and drop the ao2 ref sofia_dnsmgr_setup_peer
	 * bumped for callback safety.  Otherwise the destructor never runs: dnsmgr's held
	 * ref keeps refcount >= 1 even after ao2_unlink drops the container's ref.
	 * ast_dnsmgr_release is synchronous — it waits for in-flight callbacks holding the
	 * peer pointer to finish, so there is no UAF window when ao2_unlink runs next. */
	if (peer->dnsmgr) {
		ast_dnsmgr_release(peer->dnsmgr);
		peer->dnsmgr = NULL;
		ao2_ref(peer, -1);
	}
	/* Destroy the REGISTER + qualify-OPTIONS handles synchronously HERE — the sweep
	 * callback runs on sofia_thread (via the reload worker), so nua_handle_destroy's
	 * same-thread-as-create constraint is satisfied without a dispatch.
	 * nua_handle_bind(nh, NULL) before each destroy detaches sofia-sip's hmagic
	 * backpointer so any late event sees NULL and the destructor's defensive branches
	 * skip.  Done under peer->lock to honor the per-peer mutation contract (mutually
	 * exclusive with the reg/qualify aux threads that read peer->nh/qualify_nh under
	 * it).  nua_handle_bind/destroy are non-blocking async posts (no I/O, no peer->lock
	 * re-entry), so holding peer->lock across them is safe (recursive mutex). */
	ast_mutex_lock(&peer->lock);
	if (peer->nh) {
		nua_handle_t *nh = peer->nh;
		peer->nh = NULL;
		nua_handle_bind(nh, NULL);
		nua_handle_destroy(nh);
	}
	if (peer->qualify_nh) {
		nua_handle_t *nh = peer->qualify_nh;
		peer->qualify_nh = NULL;
		nua_handle_bind(nh, NULL);
		nua_handle_destroy(nh);
	}
	ast_mutex_unlock(&peer->lock);
	ast_log(LOG_NOTICE, "Sofia: peer '%s' removed by reload sweep "
		"(no longer present in sofia.conf)\n", peer->name);
	/* CMP_MATCH tells ao2_callback to ao2_unlink this entry.  The destructor runs on
	 * the final ref drop (now reachable because dnsmgr's ref was released above) and
	 * frees contactha, ha, directmediaha, contacts, chanvars, mailboxes, etc. */
	return CMP_MATCH;
}

/* Release the per-peer dnsmgr handle and drop the +1 ref sofia_dnsmgr_setup_peer
 * bumped for EVERY peer, unconditionally (no _reload_marked / is_realtime gate, unlike
 * sofia_peer_sweep_cb).  Used only by the load_module err_cleanup path: there the
 * peers container ref is about to be dropped, but a dnsmgr-registered peer holds an
 * extra ref that would keep refcount >= 1 after that drop, so the destructor would
 * never run and the peer + res_dnsmgr entry would leak.  Does NOT take peer->lock:
 * ast_dnsmgr_release blocks on the dnsmgr entry-list lock until any in-flight
 * sofia_on_dns_update_peer (which takes peer->lock) returns, so taking peer->lock here
 * would deadlock.  Invoked from err_cleanup AFTER sofia_thread is joined, but
 * ast_dnsmgr_release touches only res_dnsmgr's list, so it is safe regardless of
 * sofia_root/sofia_nua state. */
static int sofia_peer_dnsmgr_release_cb(void *obj, void *arg, int flags)
{
	struct sofia_peer *peer = obj;
	/* Unsubscribe MWI unconditionally (a peer may have mailboxes but no dnsmgr) so the
	 * destructor's post-refcount-0 drain can't resurrect one via a concurrent
	 * mwi_event_cb. */
	sofia_peer_drain_mwi(peer);
	if (peer->dnsmgr) {
		ast_dnsmgr_release(peer->dnsmgr);
		peer->dnsmgr = NULL;
		ao2_ref(peer, -1);
	}
	return 0;
}

/* Forward declaration for the worker.  Body defined alongside the
 * sync-invoker further down. */
static void sofia_reload_worker(void *data);

/* Synchronous reload invoker — called from CLI / AMI / .reload hook.
 * Posts the request into sofia_thread's event queue via
 * sofia_dispatch_to_root_thread, then blocks on a condvar (with a
 * 30-second deadline) until the worker signals completion.  Returns 0
 * on success or -1 on failure (the worker records the specific reason
 * in req->errmsg, which the caller copies into its own errmsg buffer
 * before returning).
 *
 * Refcount discipline: the request struct is ao2_alloc'd with initial
 * refcount 1 (caller's).  Before dispatch we ao2_ref(req,+1) for the
 * worker.  On dispatch failure we drop both refs.  After cond_timedwait
 * returns (whether by signal or timeout), the caller drops its ref.
 * The worker drops its ref at the very end of its body.  Whichever
 * runs last frees the struct via the destructor — safe under timeout
 * because cond/mutex AND the errmsg buffer all live inside the
 * ref-protected struct.  The caller never hands its stack buffer to the
 * detached worker: the worker writes req->errmsg under req->mutex, and
 * the caller copies it out under req->mutex, so a timed-out caller frame
 * can unwind without leaving the worker a dangling stack pointer. */
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
	req->errmsg[0] = '\0';

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
			/* Worker may never run / may still be running.  Write the
			 * reason into req->errmsg (the ref-protected struct buffer)
			 * rather than the caller's stack: on timeout this frame
			 * unwinds while the worker still holds a ref and could
			 * otherwise write into a defunct stack buffer. */
			if (req->errmsg[0] == '\0') {
				snprintf(req->errmsg, sizeof(req->errmsg),
					"reload timed out after %d ms (sofia_thread busy)", timeout_ms);
			}
			break;
		}
	}
	result = req->done ? req->result : -1;
	/* Copy the worker's message out while still holding req->mutex, so the
	 * read is serialized against the worker's write at signal_done. */
	if (errmsg && errmsglen > 0) {
		ast_copy_string(errmsg, req->errmsg, errmsglen);
	}
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

	/* Snapshot the outbound-PUBLISH config BEFORE sofia_apply_config resets sofia_cfg, so the
	 * post-apply reconcile can tell whether the ESC target/domain/TTL changed (full rebuild) or only
	 * the publish=yes peer set changed (incremental mark-and-sweep). */
	{
		char pub_server_was[sizeof(sofia_cfg.publish_server)];
		char pub_domain_was[sizeof(sofia_cfg.publish_domain)];
		int pub_expires_was = sofia_cfg.publish_expires;
		ast_copy_string(pub_server_was, sofia_cfg.publish_server, sizeof(pub_server_was));
		ast_copy_string(pub_domain_was, sofia_cfg.publish_domain, sizeof(pub_domain_was));

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

		/* Outbound-PUBLISH reload-reconciliation: peers are now reconciled and we are on sofia_thread,
		 * so add/remove/rebuild publications to match the new config (no restart needed). */
		sofia_publications_reconcile(
			strcmp(pub_server_was, sofia_cfg.publish_server) != 0
			|| strcmp(pub_domain_was, sofia_cfg.publish_domain) != 0
			|| pub_expires_was != sofia_cfg.publish_expires);
	}

	ast_config_destroy(cfg);
	result = 0;

signal_done:
	ast_mutex_lock(&req->mutex);
	req->done = 1;
	req->result = result;
	if (local_errmsg[0] != '\0') {
		ast_copy_string(req->errmsg, local_errmsg, sizeof(req->errmsg));
	}
	ast_cond_signal(&req->cond);
	ast_mutex_unlock(&req->mutex);
	ao2_ref(req, -1);   /* drop worker's ref */
}

/* AMI Action SIPpeers — list every peer (one PeerEntry event per peer, plus a final
 * PeerlistComplete with ListItems count; chan_sip parity). Filters out
 * is_register_line==1 entries (outbound-register peers surfaced via SIPshowregistry). */
void sipqualifypeer_callback(void *data)
{
	struct sipqualifypeer_data *d = data;
	if (d) {
		if (d->peer) {
			sofia_qualify_peer(d->peer);
			/* Only a TIMER dispatch (clear_pending=1) releases the gate — an AMI manual
			 * qualify (clear_pending=0) must NOT clear a timer dispatch's qualify_pending,
			 * or it would let the aux thread re-enqueue early. Cleared under peer->lock
			 * (same lock the timer set it under). The OPTIONS handle stays gated
			 * separately via peer->qualify_nh until its response/timeout. */
			if (d->clear_pending) {
				ast_mutex_lock(&d->peer->lock);
				d->peer->qualify_pending = 0;
				ast_mutex_unlock(&d->peer->lock);
			}
			ao2_ref(d->peer, -1);
		}
		ast_free(d);
	}
}


static int load_module(void)
{
	int rc = AST_MODULE_LOAD_SUCCESS;
	int sofia_thread_started = 0;

	ast_verbose("Sofia-SIP channel loading...\n");

	/* Container allocation.  Each is independent — check individually so
	 * an OOM on the second or third doesn't leak the first two.  The
	 * `goto err_cleanup` ladder at the bottom of the function unwinds in
	 * reverse-construction order. */
	peers = ao2_container_alloc(MAX_PEER_BUCKETS, peer_hash_fn, peer_cmp_fn);
	if (!peers) {
		ast_log(LOG_ERROR, "Unable to create Sofia peers container\n");
		rc = AST_MODULE_LOAD_FAILURE;
		goto err_cleanup;
	}
	dialogs = ao2_container_alloc(MAX_DIALOG_BUCKETS, dialog_hash_fn, dialog_cmp_fn);
	if (!dialogs) {
		ast_log(LOG_ERROR, "Unable to create Sofia dialogs container\n");
		rc = AST_MODULE_LOAD_FAILURE;
		goto err_cleanup;
	}
	if (sofia_blacklist_init()) {
		ast_log(LOG_ERROR, "Unable to create Sofia blacklist container\n");
		rc = AST_MODULE_LOAD_FAILURE;
		goto err_cleanup;
	}
	presence_subs = ao2_container_alloc(MAX_PRESENCE_SUB_BUCKETS,
		presence_sub_hash_fn, presence_sub_cmp_fn);
	if (!presence_subs) {
		ast_log(LOG_ERROR, "Unable to create Sofia presence subscriptions container\n");
		rc = AST_MODULE_LOAD_FAILURE;
		goto err_cleanup;
	}

	/* outbound PUBLISH (RFC 3903): one publication per publish=yes peer. */
	if (sofia_publications_init()) {
		ast_log(LOG_ERROR, "Unable to create Sofia publications container\n");
		rc = AST_MODULE_LOAD_FAILURE;
		goto err_cleanup;
	}

	if (sofia_load_config(0)) {
		ast_log(LOG_ERROR, "Unable to load config %s\n", SOFIA_CONFIG);
		rc = AST_MODULE_LOAD_DECLINE;
		goto err_cleanup;
	}

	if (!ast_rtp_engine_srtp_is_registered()) {
		ast_log(LOG_WARNING, "Sofia: res_srtp not loaded — encryption support disabled\n");
		sofia_cfg.encryption = 0;
	}

	if (ast_pthread_create(&sofia_thread, NULL, sofia_thread_func, NULL)) {
		ast_log(LOG_ERROR, "Failed to create Sofia event thread\n");
		rc = AST_MODULE_LOAD_FAILURE;
		goto err_cleanup;
	}
	sofia_thread_started = 1;

	/* Wait for the thread to create NUA */
	{
		int retries = 50;
		while (!sofia_nua && retries-- > 0) {
			usleep(100000);
		}
		if (!sofia_nua) {
			ast_log(LOG_ERROR, "Sofia NUA failed to initialize\n");
			rc = AST_MODULE_LOAD_FAILURE;
			goto err_cleanup;
		}
	}

	if (ast_channel_register(&sofia_tech)) {
		ast_log(LOG_ERROR, "Unable to register channel type '%s'\n", SOFIA_CHANNEL_TYPE);
		rc = AST_MODULE_LOAD_FAILURE;
		goto err_cleanup;
	}

	ast_rtp_glue_register(&sofia_rtp_glue);

	/* Register UDPTL protocol callbacks after RTP glue. The get callback
	 * exposes active T.38 UDPTL sessions; the set callback is intentionally
	 * a no-op while chan_sofia keeps UDPTL relayed through the PBX. */
	ast_udptl_proto_register(&sofia_udptl);

	/* Managed scheduler thread for the T.38 5s reINVITE timeout (sofia_t38_abort).
	 * On failure, log + continue — the T.38 timer is disabled but other paths work
	 * (arm sites null-check sofia_sched). */
	sofia_sched = ast_sched_thread_create();
	if (!sofia_sched) {
		ast_log(LOG_WARNING, "Sofia: ast_sched_thread_create failed — T.38 5s reINVITE timeout disabled\n");
	}

	ast_register_application_xml(app_dtmfmode, sofia_app_dtmfmode);
	ast_register_application_xml(app_sipaddheader, sofia_app_addheader);
	ast_register_application_xml(app_sipremoveheader, sofia_app_removeheader);

	/* ${SIP_HEADER(name[,N])} dialplan function */
	ast_custom_function_register(&sofia_sip_header_function);
	/* ${CHECKSIPDOMAIN(domain)} dialplan function */
	ast_custom_function_register(&sofia_check_sipdomain_function);
	/* ${SIPPEER(peer[,item])} dialplan function */
	ast_custom_function_register(&sofia_sippeer_function);
	/* ${SIPCHANINFO(item)} dialplan function */
	ast_custom_function_register(&sofia_sipchaninfo_function);

	/* AMI Action SIPpeers */
	ast_manager_register_xml("SIPpeers",
		EVENT_FLAG_SYSTEM | EVENT_FLAG_REPORTING, manager_sofia_show_peers);
	/* AMI Action SIPshowpeer */
	ast_manager_register_xml("SIPshowpeer",
		EVENT_FLAG_SYSTEM | EVENT_FLAG_REPORTING, manager_sofia_show_peer);
	/* AMI Action SIPqualifypeer (uses sofia_dispatch_to_root_thread) */
	ast_manager_register_xml("SIPqualifypeer",
		EVENT_FLAG_SYSTEM | EVENT_FLAG_REPORTING, manager_sofia_qualify_peer);
	/* AMI Action SIPshowregistry */
	ast_manager_register_xml("SIPshowregistry",
		EVENT_FLAG_SYSTEM | EVENT_FLAG_REPORTING, manager_sofia_show_registry);
	/* AMI Action SIPnotify (uses sofia_dispatch_to_root_thread) */
	ast_manager_register_xml("SIPnotify",
		EVENT_FLAG_SYSTEM, manager_sofia_notify);

	ast_cli_register_multiple(cli_sofia, ARRAY_LEN(cli_sofia));

	sofia_do_register();

	ast_pthread_create(&sofia_reg_thread, NULL, sofia_reg_thread_func, NULL);

	ast_pthread_create(&sofia_qualify_tid, NULL, sofia_qualify_thread, NULL);

	ast_verbose("Sofia-SIP channel driver loaded successfully\n");

	return AST_MODULE_LOAD_SUCCESS;

err_cleanup:
	/* Reverse-order unwind for module-load failures.  Only reachable when
	 * `rc != AST_MODULE_LOAD_SUCCESS` was set above.  Each cleanup step
	 * is guarded against not-yet-constructed state so a failure at any
	 * point in load_module can `goto err_cleanup` safely.
	 *
	 * The runtime unload path (`unload_module` below) is intentionally a
	 * no-op for live modules (chan_sofia doesn't support runtime unload), so
	 * this is the ONLY cleanup discipline that runs on a failed load.
	 * Without it, partial state (containers, parsed
	 * peers/domain_list, ACLs, the started sofia_thread) would leak on
	 * every failed load attempt — and AST_MODULE_LOAD_DECLINE lets
	 * gabpbx retry the load later, so a stuck DECLINE loop would
	 * accumulate the leak. */

	if (sofia_thread_started) {
		/* sofia_thread may still be running (waiting on su_root_create /
		 * nua_create) or already exited (if those calls failed).  In
		 * either case, pthread_join is safe.  Signal the event loop to
		 * exit first if it is alive. */
		if (sofia_nua) {
			nua_shutdown(sofia_nua);
		}
		if (sofia_root) {
			su_root_break(sofia_root);
		}
		pthread_join(sofia_thread, NULL);
		/* sofia_thread_func sets sofia_nua/sofia_root globally; do not
		 * NULL them here — the thread itself tears them down on exit. */
	}

	/* domain_list — populated by sofia_parse_general_config during
	 * sofia_load_config.  Drain to prevent leak on retry-after-DECLINE. */
	{
		struct sofia_domain *d;
		AST_LIST_LOCK(&domain_list);
		while ((d = AST_LIST_REMOVE_HEAD(&domain_list, list))) {
			ast_free(d);
		}
		AST_LIST_UNLOCK(&domain_list);
	}

	/* ACLs — sofia_parse_general_config may have allocated localha and
	 * contact_ha; release both unconditionally (ast_free_ha is NULL-safe). */
	ast_free_ha(sofia_cfg.localha);
	sofia_cfg.localha = NULL;
	if (sofia_cfg.contact_ha) {
		ast_free_ha(sofia_cfg.contact_ha);
		sofia_cfg.contact_ha = NULL;
	}

	/* Containers — their destructors release any peers/dialogs/blacklist
	 * entries the config-parse populated. */
	sofia_blacklist_destroy();
	if (presence_subs) {
		/* Empty at load-failure time (watcher subs are only created by inbound
		 * SUBSCRIBE, which cannot run during load). */
		ao2_ref(presence_subs, -1);
		presence_subs = NULL;
	}
	sofia_publications_destroy();
	if (dialogs) {
		ao2_ref(dialogs, -1);
		dialogs = NULL;
	}
	if (peers) {
		/* Release every peer's dnsmgr handle (and the +1 ref
		 * sofia_dnsmgr_setup_peer bumped) BEFORE dropping the container
		 * ref.  sofia_apply_config already ran sofia_dnsmgr_setup_peer for
		 * each peer with a hostname host= during the parse that preceded
		 * this failure; that extra ref would otherwise keep each such peer
		 * at refcount >= 1 after the container-ref drop below, so
		 * sofia_peer_destructor would never run and the peer struct +
		 * res_dnsmgr entry would leak (compounded across DECLINE retries). */
		ao2_callback(peers, OBJ_NODATA, sofia_peer_dnsmgr_release_cb, NULL);
		ao2_ref(peers, -1);
		peers = NULL;
	}

	return rc;
}

static int unload_module(void)
{
	ast_verbose("Sofia-SIP channel unloading...\n");

	ast_rtp_glue_unregister(&sofia_rtp_glue);
	/* Defensive UDPTL protocol unregister (symmetric with load_module register).
	 * unload returns -1 below before any teardown runs, so this is documentation-only
	 * at runtime. ast_sched_thread_destroy reaps the managed thread + sched_context. */
	ast_udptl_proto_unregister(&sofia_udptl);
	if (sofia_sched) {
		sofia_sched = ast_sched_thread_destroy(sofia_sched);
	}
	ast_unregister_application(app_dtmfmode);
	ast_unregister_application(app_sipaddheader);
	ast_unregister_application(app_sipremoveheader);
	/* Dialplan function + AMI action unregisters below are all defensive — the unload
	 * body returns -1 before they run at runtime. */
	ast_custom_function_unregister(&sofia_sip_header_function);
	ast_custom_function_unregister(&sofia_check_sipdomain_function);
	ast_custom_function_unregister(&sofia_sippeer_function);
	ast_custom_function_unregister(&sofia_sipchaninfo_function);
	ast_manager_unregister("SIPpeers");
	ast_manager_unregister("SIPshowpeer");
	ast_manager_unregister("SIPqualifypeer");
	ast_manager_unregister("SIPshowregistry");
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

	/* chan_sofia does NOT support runtime unload.
	 *
	 * Three independent thread-discipline issues make a clean unload impossible without
	 * a deeper refactor than the operational benefit warrants:
	 *
	 *   (1) sofia-sip's su_root_destroy() asserts on same-thread-as-su_root_create
	 *       (SIGABRT under su_root_destroy called from the CLI thread).
	 *
	 *   (2) sofia_reg_thread + sofia_qualify_tid leak past dlclose with sleep(30) +
	 *       sleep(1) granularity even after pthread_join.
	 *
	 *   (3) libsofia-sip-ua spawns its OWN internal worker threads (su_base_port_run
	 *       in its tport thread pool) that aren't reaped by su_root_destroy — observed
	 *       still live after a clean unload+load.
	 *
	 * Operators already restart gabpbx for any chan_sofia config change (the reload
	 * path uses sofia_load_config + module reload, not unload), so refusing unload is
	 * correctness-preserving.
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
	/* contactpermit/contactdeny: final cleanup at module-unload (chan_sip parity). */
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
	sofia_blacklist_destroy();
	if (presence_subs) {
		ao2_ref(presence_subs, -1);
		presence_subs = NULL;
	}
	sofia_publications_destroy();

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
