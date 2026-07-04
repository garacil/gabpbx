/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * GABPBX was first created in 2008 by
 * Germán Luis Aracil Boned <garacilb@gmail.com>.
 *
 * GABPBX as a project is based on Asterisk.
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
 * DROP-IN chan_sip COMPATIBILITY POLICY
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
 *                            CHECKSIPDOMAIN  (chan_sip-parity
 *                            names, drop-in for existing dialplans).
 *   - AMI actions:           SIPpeers / SIPshowpeer / SIPqualifypeer /
 *                            SIPshowregistry / SIPnotify  (chan_sip-parity
 *                            names).
 *   - AMI events:            PeerStatus / Registry / Hold  (chan_sip-parity
 *                            names).
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
 * chan_sofia LOCKING & CONCURRENCY INVARIANT (authoritative; every inline
 * "LOCK ORDER" note cites this block).
 *
 * THREAD MODEL. A SINGLE sofia_thread (the sofia-sip su_root loop) runs ALL
 * SIP signaling (every nua_* callback + the sofia_process_* handlers) AND
 * config reload (dispatched onto it via sofia_dispatch_to_root_thread), so it
 * OWNS all mutable peer/dialog signaling state; two paths both on sofia_thread
 * are serialized for free. Everyone else (channel/PBX/bridge tech callbacks,
 * dialplan, CLI/AMI, ast_sched timers, reg/qualify aux threads, dnsmgr) only
 * READS and must do so under a lock.
 * RACE DISCRIMINATOR: a race exists only if at least one party runs OFF
 * sofia_thread — state each party's thread when reasoning about a lock.
 *
 * LOCK ORDER (HARD, never invert):
 *     channel-lock  ->  pvt->lock  ->  peer-family (ao2_lock(peer) / peer->lock)
 * peer->lock is a dedicated ast_mutex_t field, DISTINCT from ao2_lock(peer).
 * channel locks and the ast_mutex_t locks are RECURSIVE (self-reentry safe).
 * The reload writer (sofia_parse_peer_config) holds peer->lock as a LEAF, so
 * widening a reader's peer->lock hold cannot invert against it.
 * fork->lock (winner/children/count/state) is a sub-lock taken UNDER pvt->lock
 * (master->lock -> fork->lock, per sofia_hangup) and never co-held with
 * peer-family, so it is unordered against peer->lock.
 *
 * GLOBAL config lists have dedicated rwlocks (both leaves): sofia_localha_lock
 * guards sofia_cfg.localha, sofia_contactha_lock guards sofia_cfg.contact_ha
 * (both freed+rebuilt by reload while read off-thread).
 *
 * SNAPSHOT IDIOM (mandatory for any FREEABLE peer/owner data touched off
 * sofia_thread; ast_string_field_set frees the old pool on growth, so a
 * lock-free off-thread read is a use-after-free):
 *   - stringfields/lists: under peer->lock, copy into a local (UNBOUNDED ->
 *     size >= 256) or deep-copy, release, then use the local.
 *   - owner/channel: ref under pvt->lock, drop pvt->lock, ast_channel_lock,
 *     re-lock pvt->lock, REVALIDATE pvt->owner==owner, unref on every path.
 *   - NEVER hold pvt->lock/peer->lock across a channel-locking or blocking
 *     call (nua_*, su_*, DNS, ast_moh_start, pbx_*, ast_cli, ast_request).
 *
 * DIALOG TEARDOWN RACE. An in-dialog nua_i_* / nua_r_* event carries the dialog
 * pvt as hmagic, but sofia_hangup can free it concurrently. Mitigation:
 * sofia_event_callback re-validates hmagic against the dialogs container and
 * pins a +1 ref for the whole dispatch (sofia_pvt_ref_if_linked); per-handler
 * `if (pvt)` guards and op->owner snapshots cover the rest.
 * ===================================================================== */

#include "gabpbx.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>  /* regcomp/regexec for `like <pattern>` in sip prune realtime CLI */
#include <unistd.h>
#include <sys/stat.h>		/* stat()/S_ISDIR: resolve tlscertfile dir-vs-file for the cert-dir aliasing */
#include <fcntl.h>
#include <errno.h>
#include <openssl/sha.h>  /* RFC 7616 SHA-256 digest auth: libcrypto's SHA256() — core SHA256* symbols are not exported to modules */
#include <openssl/hmac.h> /* HMAC-SHA256 for the stateless self-validating digest nonce (s1.ts.rand.hmac) */
#include <openssl/evp.h>  /* EVP_sha256() for HMAC() */
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
#include "gabpbx/event.h"  /* AST_EVENT_MWI subscribe/unsubscribe */
#include "gabpbx/linkedlists.h"
#include "gabpbx/astobj2.h"
#include "gabpbx/devicestate.h"
#include "gabpbx/threadstorage.h"
#include "gabpbx/rtp_engine.h"
#include "gabpbx/dsp.h"  /* inbound inband-DTMF / fax-CNG tone detection */
#include "gabpbx/dnsmgr.h"  /* async hostname-tracking for host=hostname peers */
#include "gabpbx/udptl.h"  /* T.38 fax UDPTL + struct ast_control_t38_parameters */
#include "gabpbx/sched.h"  /* ast_sched_thread for the sofia_t38_abort 5s reINVITE timeout */
#include "gabpbx/causes.h"
#include "gabpbx/acl.h"
#include "gabpbx/musiconhold.h"
#include "gabpbx/ast_version.h"  /* ast_get_version() for the User-Agent default */
#include "gabpbx/paths.h"        /* ast_config_AST_SYSTEM_NAME for regserver column */

#include "sofia/include/srtp.h"
#include "sofia/include/sdp_crypto.h"
#include "sofia/include/chan_sofia_internal.h"
#include "sofia/include/sofia_blacklist.h"
#include "sofia/include/sofia_publish.h"
#include "sofia/include/sofia_ami.h"
#include "sofia/include/sofia_cli.h"
#include "sofia/include/sofia_presence.h"
#include "sofia/include/sofia_sdp.h"
#include "sofia/include/sofia_t38.h"
#include "sofia/include/sofia_message.h"
#include "sofia/include/sofia_transfer.h"
#include "sofia/include/sofia_subscribe.h"
#include "sofia/include/sofia_history.h"
#include "sofia/include/sofia_datachannel.h"  /* WebRTC DataChannel (usrsctp) — foundation */

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
#include <sofia-sip/tport_tag.h>	/* TPTAG_TOS for SIP-listener-side TOS */

#define SOFIA_CONFIG "sofia.conf"

#define DEFAULT_CONTEXT "default"
#define DEFAULT_BINDADDR "0.0.0.0"
#define DEFAULT_SIP_PORT 5060
#define DEFAULT_EXPIRY 120
/* Registration TTL bounds + 423 Interval Too Brief (chan_sip parity). */
#define DEFAULT_MIN_EXPIRY      60
#define DEFAULT_MAX_EXPIRY      3600
#define DEFAULT_DEFAULT_EXPIRY  120
/* RFC 3261 §20.22 Max-Forwards default. */
#define DEFAULT_MAX_FORWARDS    70
/* RFC 3261 §17.1.1.2 T1 minimum; 100ms (chan_sip parity, vs RFC default 500ms). */
#define DEFAULT_T1MIN           100
/* Effective minimum TLS floor when no tls_min_version= is configured (enables TLS 1.2 + 1.3).
 * Used at BOTH the load-time seed and the reload-check scratch seed so the two can never drift. */
#define DEFAULT_TLS_MIN_VERSION "1.2"
/* Outbound REGISTER scheduled-retry interval, seconds. */
#define DEFAULT_REGISTRATION_TIMEOUT 20
/* User-Agent / Server header base; composed with ast_get_version() at load. */
#define DEFAULT_USERAGENT       "GABpbx PBX"

/* T.38 FaxMaxDatagram: sentinel -1 = use the 200-byte built-in; else override. */
#define SOFIA_T38_MAXDATAGRAM_SENTINEL  -1
#define SOFIA_T38_MAXDATAGRAM_BUILTIN   200

/* T.38 reINVITE abort timeout: without it, a peer that never acks the 200 OK
 * leaves us stuck in T38_PEER_REINVITE forever. */
/* REFER transferer-leg BYE deferral (RFC 5589 §6.1): after our terminal NOTIFY
 * 200 OK we expect the transferer's UA to BYE us; if it doesn't within this
 * window we BYE ourselves so the dialog doesn't leak. 32s = chan_sip parity. */
#define SOFIA_DEFER_BYE_TIMEOUT_MS  32000
/* Hash-table bucket caps for carrier scale (primes → even ao2 distribution). */
#define MAX_PEER_BUCKETS 65521    /* prime (largest < 2^16) for the by-NAME peers table. Headroom so the
                                   * load factor stays tiny; prime keeps the hash well distributed. ~1 MiB
                                   * bucket array, calloc'd (lazy zero pages when sparse), kept for life. */
#define MAX_PEER_IPPORT_BUCKETS 16381  /* prime (largest < 2^14); the by-IP:port fast index holds ONLY
                                   * static-host trunks (few), so it is sized ~8x smaller than the by-name
                                   * table. ~256 KiB. */
#define MAX_DIALOG_BUCKETS 32749  /* concurrent-dialog headroom */
/* Digest-auth nonce TTL fallback when sofia_cfg.nonce_ttl_seconds is unset (=0).
 * Aligned with the registration max so refreshes don't trigger stale=true. */
#define SOFIA_NONCE_TTL_SEC_DEFAULT 3600
#define SOFIA_NONCE_TTL_SEC_LEGACY  300  /* migration reference */

#define DEFAULT_QUALIFYFREQ   60
#define DEFAULT_QUALIFYTIMEOUT 3
#define DEFAULT_FREQ_NOTOK    10



struct sofia_config sofia_cfg;

	su_root_t *sofia_root;
	nua_t *sofia_nua;
	static pthread_t sofia_thread;
	static pthread_t sofia_reg_thread;
	static pthread_t sofia_qualify_tid;
	/* T.38 reINVITE 5s-timeout sched thread; NULL until load_module gates the
	 * t38id arm sites. */
	struct ast_sched_thread *sofia_sched;

int sofia_debug;
int sofia_forkdebug;	/* B1: WebRTC/fork lifecycle debug ("sip set debug fork on"): pure logging, default OFF, ZERO behavior change. Correlates to res_rtp's ICE logs by rtp=%p (=pvt->rtp). */
int sofia_dtmflog;	/* "sip set debug dtmf on": NOTICE per received DTMF digit (RFC2833/INFO/inband) so operators see keypresses in CLI+messages; default OFF, pure logging (chan_sip parity, but its own toggle). */
/* Fork/flow lifecycle trace — the ONLY window into the mixed UDP+WSS fork teardown (CAUSA_RAIZ);
 * res_rtp cannot see the nh/rtp/fd steal or the REGISTER-flow drop. Logging only, never datapath. */
#define SOFIA_FORKDBG(fmt, ...) do { if (sofia_forkdebug) { ast_verbose("FORKDBG " fmt "\n", ##__VA_ARGS__); } } while (0)
/* Copy a SIP URI into buf, REDACTING a "user:password@" userinfo password (RFC 3261 §19.1.1 permits a
 * cleartext URI password) so the fork/flow debug honors the no-secrets invariant. host:port/params kept. */
static const char *sofia_uri_redact(const char *uri, char *buf, size_t buflen)
{
	const char *at, *scheme, *pw;
	if (ast_strlen_zero(uri)) {
		ast_copy_string(buf, "(none)", buflen);
		return buf;
	}
	at = strchr(uri, '@');
	scheme = strchr(uri, ':');					/* end of the "sip"/"sips" scheme */
	pw = (at && scheme && scheme < at) ? memchr(scheme + 1, ':', at - (scheme + 1)) : NULL;
	if (pw) {							/* sip:user:PASSWORD@host -> sip:user:***@host */
		snprintf(buf, buflen, "%.*s:***%s", (int)(pw - uri), uri, at);
	} else {
		ast_copy_string(buf, uri, buflen);
	}
	return buf;
}
char sofia_debug_filter[64];
int sofia_debug_match(const char *peer_name, const char *src_ip);
/* Set when the respective [general] key is parsed; consumed at config end for
 * the Timer B vs T1*64 cross-validation. */
static int sofia_timerb_set;
static int sofia_timert1_set;
/* Module-scope mirror of sofia_cfg.srtp_per_suite_keys; extern-visible to
 * sdp_crypto.c (NOT static). */
int sofia_srtp_per_suite_keys;

struct ao2_container *peers;
/* B: O(1) by-IP+port index of cached peers (perf). Immutable entries (struct sofia_peer_ipport), each
 * holding a +1 peer ref, keyed by IP+port. Lock order: NEVER hold ao2_lock(peers) while touching it. */
static struct ao2_container *peers_by_ipport;
static struct ao2_container *dialogs;
static struct sofia_peer *sofia_peer_ref_if_linked(struct sofia_peer *target);	/* fwd: +1 ref iff still linked in `peers` */

/* Accessor for the dialogs container so split modules (e.g. sofia_history.c's CLI handlers) can
 * iterate live dialogs without the container leaving this translation unit's ownership. */
struct ao2_container *sofia_dialogs_container(void)
{
	return dialogs;
}

/* Bounded REGISTER realtime-DB-write offload pool (kill-switch, default OFF).
 * Offloads the slow blocking ast_update_realtime() writes off sofia_thread so
 * signalling stays responsive under a registration storm with a slow DB. Lanes
 * are keyed by peer name so writes for one account stay FIFO-ordered (a
 * de-REGISTER can never overtake a prior REGISTER). */
#define SOFIA_REGPOOL_MAX 16
static struct ast_taskprocessor *sofia_regpool[SOFIA_REGPOOL_MAX];
static int sofia_regpool_n;                 /* active lane count (0 = not created) */
static int sofia_regpool_enabled;           /* runtime gate: config ON && lanes created */
/* Guards GLOBAL sofia_cfg.localha (channel-thread SDP build reads it while
 * reload frees+rebuilds it on sofia_thread). */
AST_RWLOCK_DEFINE_STATIC(sofia_localha_lock);
/* Guards GLOBAL sofia_cfg.contact_ha; like localha, but ALSO read+appended
 * off-thread by sofia_peer_alloc on the realtime peer-build path. */
AST_RWLOCK_DEFINE_STATIC(sofia_contactha_lock);


/* Local SIP domains for ${CHECKSIPDOMAIN()}; from [general] domain= lines. */
struct sofia_domain {
	char domain[80];
	AST_LIST_ENTRY(sofia_domain) list;
};
static AST_LIST_HEAD_STATIC(domain_list, sofia_domain);

static const char *sofia_pick_auth_username(sip_t const *sip,
		const char *fallback_user, char *buf, size_t len);

struct sofia_peer;
struct sofia_pvt; /* fwd decl — sofia_send_auth_challenge below threads a pvt* to pin (deferred-reject race fence) */
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

static void sofia_emit_timing_equalized_reject(void);
static void sofia_send_auth_challenge(nua_t *nua, nua_handle_t *nh, sip_t const *sip,
		const char *realm, const char *method, const char *reason,
		struct sofia_pvt *pvt_ref, int reap_handle_on_fire);
static void sofia_emit_auth_challenge(nua_t *nua, nua_handle_t *nh,
		const char *realm, const char *nonce, int stale);

/* ===================================================================
 *  Async timing-equalized reject (anti-enumeration jitter, NON-blocking)
 *
 *  The reject jitter (401 auth-fail vs 403 ACL-deny vs unknown-peer) used to be a
 *  blocking usleep(10-50ms) on the single sofia_thread, so a reject flood parked the
 *  dispatcher and capped signalling at ~33 req/s (a self-DoS timing oracle). Instead we
 *  keep the cheap deterministic dummy-SHA work but defer the actual response with a
 *  ONE-SHOT su_timer armed on su_root_task(sofia_root) (the SAME pattern as
 *  sofia_presence.c / sofia_transfer.c). The timer fires ON sofia_thread, so the
 *  nua_respond() inside the callback obeys sofia-sip's same-thread-as-create contract.
 *
 *  Lifetime/lock-order: every armed ctx is on g_delay_reject_list, guarded by that
 *  AST_LIST_HEAD_STATIC's own lock. The list lock is NEVER held across a nua_* call:
 *  the callback unlinks under the lock, releases it, THEN does nua_respond/AMI/unref/free;
 *  the scheduler builds+arms the timer first and only takes the lock to insert. The ctx
 *  pins its nua_handle_t with nua_handle_ref() so the handle cannot vanish before the
 *  timer fires; unref happens in the callback (or in the unload sweep). On module unload
 *  the sofia_thread teardown (after su_root_run returns, before nua_destroy) cancels +
 *  destroys every pending timer and frees its ctx, so a firing timer can never deref freed
 *  code/handles.
 * =================================================================== */
#define SOFIA_DELAY_REJECT_MAX        512   /* global hard cap of in-flight delayed rejects */
#define SOFIA_DELAY_REJECT_PER_SRC    12    /* soft per-source-addr cap (anti single-source hog) */

enum sofia_delay_reject_kind {
	SOFIA_DELAY_REJECT_401_CHALLENGE = 0,   /* unknown-peer 401 + WWW-Authenticate + AMI AuthFailure */
	SOFIA_DELAY_REJECT_403_FORBIDDEN = 1,   /* INVITE ACL-deny 403 */
};

struct sofia_delay_reject_ctx {
	enum sofia_delay_reject_kind kind;
	nua_t *nua;                  /* the NUA agent (for NUTAG_WITH_THIS); not refcounted, outlives the timer */
	nua_handle_t *nh;            /* pinned via nua_handle_ref() at schedule, unref at fire/sweep */
	su_timer_t *timer;           /* the armed one-shot; the callback destroys its OWN fired timer */
	/* Residual-race fences (HIGH): nua_handle_ref pins the handle MEMORY but NOT
	 * the NTA incoming server request, so destroying the fresh pvt/handle right after scheduling
	 * dispatches nua_handle_destroy -> nta_incoming_destroy, which auto-sends an immediate 500 that
	 * races ahead of (and usually preempts) our 10-50ms timer. These two fields make the deferred
	 * cleanup happen AFTER we send, on every emit path: */
	struct sofia_pvt *pvt_ref;   /* INVITE paths: an extra ao2 ref (NULL unless set) holding the pvt
	                              * — and thus the bound handle + its NTA server request — alive until
	                              * we emit; dropped at fire/immediate/failure/unload. */
	int reap_handle_on_fire;     /* unbound-SUBSCRIBE paths: reap the orphaned (UNBOUND) server handle
	                              * AFTER we emit the deferred 401 (sofia_subscribe_reject_reap), so the
	                              * timer wins the race against nta_incoming_destroy's immediate 500. */
	/* 401 path snapshot (sip_t* is freed after the event callback returns — copy everything): */
	char realm[128];
	char nonce[64];
	char method[32];
	char reason[64];
	char src_addr[80];           /* RemoteAddr for the AMI AuthFailure event */
	AST_LIST_ENTRY(sofia_delay_reject_ctx) list;
};

/* Pending armed-reject list; the head's built-in lock guards the list AND the counters.
 * It is the ONLY lock for this subsystem and is never held across any nua_* call. */
static AST_LIST_HEAD_STATIC(g_delay_reject_list, sofia_delay_reject_ctx);
static int g_delay_reject_count;     /* in-flight pending count (guarded by g_delay_reject_list lock) */

static void sofia_delay_reject_schedule(enum sofia_delay_reject_kind kind,
		nua_t *nua, nua_handle_t *nh,
		const char *realm, const char *nonce,
		const char *method, const char *reason,
		const struct ast_sockaddr *src,
		struct sofia_pvt *pvt_ref, int reap_handle_on_fire);
static void sofia_delay_reject_shutdown(void);
static void sofia_subscribe_reject_reap(nua_handle_t *nh);



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

/* MWI per-peer mailbox node; defined before struct sofia_peer (which embeds the
 * list head). */

/* Split "name=value", create ast_variable, LIFO list-prepend (setvar/header
 * parsers). NULL value (no '=') → list returned unchanged. */
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




/* Centralized call-counter helper. Returns -1 on rejection. Lock order: pvt->lock
 * then ao2_lock(peer); idempotent via call_inc_done/ring_inc_done; emits PeerStatus
 * AMI itself. */
enum sofia_call_event {
	SOFIA_INC_CALL_LIMIT,    /* inbound INVITE accepted */
	SOFIA_INC_CALL_RINGING,  /* outbound dial dispatched */
	SOFIA_DEC_CALL_LIMIT,    /* inbound or outbound hangup */
	SOFIA_DEC_CALL_RINGING,  /* outbound 200 OK received */
};
static int sofia_update_call_counter(struct sofia_pvt *pvt, enum sofia_call_event event);
/* MicroSIP(SIP-video)<->WebRTC video-passthrough fix: set the inbound caller leg's video_answer_mask to
 * the video codec(s) the answered far leg accepted (defined near sofia_find_bridged_channel — sofia_tech,
 * dialogs and the canonical lock order are in scope there). SDP-only: never mutates capability/nativeformats. */
static struct ast_channel *sofia_find_inbound_sibling_by_linkedid(struct sofia_pvt *answered);
static void sofia_set_caller_video_mask_from_answered(struct sofia_pvt *answered);

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

/* Derive the registration transport from a Contact URL (RFC 3261 §19.1.1): an
 * explicit ;transport= wins, else sips: → tls, else udp. Writes a lowercase
 * token (udp/tcp/tls/ws/wss) into out (>= 8 bytes); unknown/oversized → udp. */
static void sofia_contact_transport_from_url(const url_t *url, char *out, size_t outlen)
{
	char buf[16] = "";

	ast_copy_string(out, "udp", outlen);
	if (!url) {
		return;
	}
	if (url->url_params) {
		/* url_param returns the value length (0 if absent); reject oversized. */
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

/* Override the contact-derived transport with the ACTUAL WebSocket transport from the top Via sent-protocol
 * (RFC 7118 5: WS = plain WebSocket, WSS = secure WebSocket). A WebSocket UA (e.g. SIP.js) sends a synthetic
 * Contact (RFC 7118 - it cannot know its local address) with NO ;transport, so sofia_contact_transport_from_url
 * defaults it to "udp" - but the REGISTER physically arrived over WS/WSS, and the stored contact transport
 * must reflect that (the protocol is decided by HOW the request arrives, not the Contact URI param). Used for
 * outbound media-profile selection AND the ws/wss contact-rebind relaxation. Only touches WS/WSS; udp/tcp/tls
 * keep the Contact ;transport / sips semantics (the request-URI target transport for ordinary SIP). */
static void sofia_register_transport_from_via(sip_via_t const *via, char *out, size_t outlen)
{
	if (!via || !via->v_protocol || !out) {
		return;
	}
	if (strstr(via->v_protocol, "WSS") || strstr(via->v_protocol, "wss")) {
		ast_copy_string(out, "wss", outlen);
	} else if (strstr(via->v_protocol, "WS") || strstr(via->v_protocol, "ws")) {
		ast_copy_string(out, "ws", outlen);
	}
}

/* The AUTHORITATIVE transport of the request being processed: the protocol of the actual sofia-sip tport it
 * was DELIVERED on (the real connection), not text the UA wrote in Contact/Via. This is how the protocol must
 * be decided - a WebSocket arrives on the ws/wss listener, it can never be "udp". Returns "" (out[0]='\0') if
 * the tport is not reachable (caller then falls back to the Via/Contact derivation). Call only from inside a
 * nua event callback on sofia_thread, where nua_current_request() is the message being handled. */
static void sofia_incoming_transport(nua_t *nua, char *out, size_t outlen)
{
	nta_agent_t *agent;
	msg_t *msg;
	tport_t *tp;

	if (out && outlen) {
		out[0] = '\0';
	} else {
		return;
	}
	if (!nua) {
		return;
	}
	agent = nua_get_agent(nua);
	msg = nua_current_request(nua);
	if (!agent || !msg) {
		return;
	}
	tp = tport_delivered_by(nta_agent_tports(agent), msg);
	if (tp) {
		const tp_name_t *tpn = tport_name(tp);
		if (tpn && tpn->tpn_proto && (!strcasecmp(tpn->tpn_proto, "udp") || !strcasecmp(tpn->tpn_proto, "tcp")
				|| !strcasecmp(tpn->tpn_proto, "tls") || !strcasecmp(tpn->tpn_proto, "ws")
				|| !strcasecmp(tpn->tpn_proto, "wss"))) {
			ast_copy_string(out, tpn->tpn_proto, outlen);
		}
	}
}

/* Append ;transport= so an outbound request to a TCP/TLS/WS/WSS-registered phone routes
 * over the transport it registered on (sofia-sip otherwise defaults to UDP). tcp/tls/ws/wss
 * act; udp/empty/unknown are no-ops. For ws/wss this is REQUIRED: NTA selects the WS/WSS transport
 * from the URI param (RFC 7118) and the tport pool REUSES the accepted WebSocket connection the
 * client registered on (TPTAG_REUSE default; a browser is a WS client and only listens on that
 * persistent connection — without ;transport=wss the RURI defaults to UDP and the INVITE is sent to
 * the WS source port as UDP, which never reaches the browser → no ringing). Scheme is NOT
 * rewritten to sips: — ";transport=tls"/";transport=wss" alone selects the transport. */
void sofia_uri_append_transport(char *url, size_t len, const char *transport)
{
	size_t cur;

	if (!url || ast_strlen_zero(transport)) {
		return;
	}
	if (strcasecmp(transport, "tcp") && strcasecmp(transport, "tls")
			&& strcasecmp(transport, "ws") && strcasecmp(transport, "wss")) {
		return;
	}
	cur = strlen(url);
	if (cur < len) {
		snprintf(url + cur, len - cur, ";transport=%s", transport);
	}
}

/* Map a SOFIA_TRANSPORT_* bitmask to its lowercase ;transport= token (udp for unknown/default). */
const char *sofia_transport_name(int transport)
{
	switch (transport) {
	case SOFIA_TRANSPORT_TCP: return "tcp";
	case SOFIA_TRANSPORT_TLS: return "tls";
	case SOFIA_TRANSPORT_WS:  return "ws";
	case SOFIA_TRANSPORT_WSS: return "wss";
	default:                  return "udp";
	}
}

/* Build the outbound-REGISTER request URI (and the matching To/From URI) for a peer:
 * sip:defaultuser@host:port plus the peer's configured ;transport= so a tls/tcp/ws/wss
 * trunk's REGISTER routes over that transport instead of sofia-sip's default UDP. The
 * append helper is a no-op for udp/empty/unknown, so plain UDP peers stay byte-identical.
 * Mirrors the INVITE path (sofia_uri_append_transport + sofia_transport_name). Caller
 * serializes peer->host/port/defaultuser/transport (peer->lock or the load/reg thread). */
static void sofia_build_register_uri(struct sofia_peer *peer, char *out, size_t len)
{
	char hbuf[80];	/* IPv6-bracket-wrap (RFC 3261 §19.1.2); helper is idempotent */

	snprintf(out, len, "sip:%s@%s:%d", peer->defaultuser,
		sofia_uri_format_host(peer->host, hbuf, sizeof(hbuf)), peer->port);
	sofia_uri_append_transport(out, len, sofia_transport_name(peer->transport));
}

/* Build a NAT-traversal proxy URL from peer->src_addr for outbound in-dialog
 * messages when peer has nat=force_rport (or comedia). Without it sofia-sip
 * routes the 2xx-ACK/BYE to the dialog remote_target (the Contact's unroutable
 * private LAN IP for a NAT'd phone) and it never arrives. peer->src_addr = the
 * registered public source. Returns 1 if filled, 0 if no NAT routing needed.
 *
 * Locking: nat/src_addr/port/reg_transport are mutated UNDER peer->lock by the
 * REGISTER handler (sofia_process_register_update) and the dnsmgr callback
 * (sofia_on_dns_update_peer). Called off sofia_thread from the call/hangup paths,
 * so a lock-free read could tear the ~136-byte src_addr / reg_transport against a
 * concurrent re-REGISTER or DNS update and build a malformed NUTAG_PROXY. Snapshot
 * the fields under peer->lock into locals, then build off-lock — mirroring the
 * sibling sofia_pvt_build_nat_target_url which snapshots under the contact lock.
 * peer->lock is recursive, so the one caller already holding it (sofia presence
 * SUBSCRIBE NOTIFY path) re-enters safely. const cast: the fields are logically
 * mutable, only the lock acquisition needs a non-const pointer. */
static int sofia_build_nat_proxy_url_from_peer(const struct sofia_peer *peer,
                                                char *buf, size_t len)
{
	char host_buf[80];
	struct ast_sockaddr src;
	char reg_transport[8];
	int nat;
	int peer_port;
	int port;

	if (!peer || !buf || len < 16) {
		return 0;
	}
	buf[0] = '\0';

	ast_mutex_lock(&((struct sofia_peer *)peer)->lock);
	nat = peer->nat;
	src = peer->src_addr;
	peer_port = peer->port;
	ast_copy_string(reg_transport, peer->reg_transport, sizeof(reg_transport));
	ast_mutex_unlock(&((struct sofia_peer *)peer)->lock);

	/* WS/WSS: a WebSocket client always registers a placeholder Contact host (SIP.js .invalid / TEST-NET,
	 * RFC 7118 §8.1) and is reachable ONLY over its accepted WSS connection — so in-dialog ACK/BYE MUST be
	 * proxy-routed to its real registered source (peer->src_addr) over WSS, exactly like a NAT'd phone, even
	 * without an explicit nat=force_rport. Otherwise the BYE goes to the unroutable placeholder and the UA
	 * never tears down (caller stuck "call in progress"). */
	if (!(nat & (SOFIA_NAT_FORCE_RPORT | SOFIA_NAT_COMEDIA))
			&& strcasecmp(reg_transport, "ws")
			&& strcasecmp(reg_transport, "wss")) {
		return 0;
	}
	if (ast_sockaddr_isnull(&src)) {
		return 0;
	}

	port = ast_sockaddr_port(&src);
	if (!port) {
		port = peer_port ? peer_port : 5060;
	}

	snprintf(buf, len, "sip:%s:%d",
		sofia_uri_format_host(ast_sockaddr_stringify_host(&src),
			host_buf, sizeof(host_buf)),
		port);
	/* Route the proxy over the registered transport, else sofia-sip opens a fresh
	 * UDP flow and the in-dialog request is lost. */
	sofia_uri_append_transport(buf, len, reg_transport);
	return 1;
}

/* Build a NAT-traversal proxy URL from a SPECIFIC contact's learned source (c->src_addr), for the
 * initial outbound INVITE to that contact (single-live + fork paths). chan_sip parity: keep the
 * (private) Contact in the Request-URI and route the PACKET to the public rport source via
 * NUTAG_PROXY (sofia-sip routes the initial request to the default proxy regardless of the R-URI).
 * Returns 1 if filled, 0 if no NAT routing override is needed (not NAT/ws-wss, src unknown, or src
 * already == the Contact host:port). Snapshots the refresh-mutable contact fields under ao2_lock(c)
 * and the peer nat flag under peer->lock, mirroring the sibling helpers. */
int sofia_build_contact_proxy_url(const struct sofia_peer *peer, struct sofia_contact *c,
                                         char *buf, size_t len)
{
	char host_buf[80];
	struct ast_sockaddr src;
	char transport[8];
	char chost[80];
	int cport, nat, port;

	if (!peer || !c || !buf || len < 16) {
		return 0;
	}
	buf[0] = '\0';

	ast_mutex_lock(&((struct sofia_peer *)peer)->lock);
	nat = peer->nat;
	ast_mutex_unlock(&((struct sofia_peer *)peer)->lock);

	ao2_lock(c);
	src = c->src_addr;
	ast_copy_string(transport, c->transport, sizeof(transport));
	ast_copy_string(chost, c->host, sizeof(chost));
	cport = c->port;
	ao2_unlock(c);

	/* Only for a NAT peer (force_rport/comedia) or a WebSocket contact; src must be learned. */
	if (!(nat & (SOFIA_NAT_FORCE_RPORT | SOFIA_NAT_COMEDIA))
			&& strcasecmp(transport, "ws") && strcasecmp(transport, "wss")) {
		return 0;
	}
	if (ast_sockaddr_isnull(&src)) {
		return 0;
	}
	/* No override if the learned source already equals the Contact host:port (no NAT rewrite). */
	if (cport == ast_sockaddr_port(&src)
			&& !strcasecmp(chost, ast_sockaddr_stringify_host(&src))) {
		return 0;
	}
	port = ast_sockaddr_port(&src);
	if (!port) {
		port = cport ? cport : 5060;
	}
	snprintf(buf, len, "sip:%s:%d",
		sofia_uri_format_host(ast_sockaddr_stringify_host(&src), host_buf, sizeof(host_buf)),
		port);
	sofia_uri_append_transport(buf, len, transport);
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
		/* No active_contact — e.g. an INBOUND WSS caller leg: the SIP.js placeholder Contact host
		 * (192.0.2.x) never matched a registered contact by host, so active_contact stayed NULL. Fall back
		 * to the peer-level src_addr proxy so an in-dialog ACK/BYE to a placeholder-Contact WSS UA still
		 * routes over its real WSS connection (else the BYE hits the unroutable placeholder and the caller
		 * stays "call in progress"). */
		return pvt->peer ? sofia_build_nat_proxy_url_from_peer(pvt->peer, buf, len) : 0;
	}
	/* Snapshot contact's mutable src_addr + transport under its ao2 lock — a
	 * concurrent REGISTER refresh rewrites them, so an unlocked read could route
	 * the BYE to a torn/wrong target. port/host/contact_uri are set once (safe). */
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
	sofia_uri_append_transport(buf, len, transport);
	return 1;
}

/* Build sip:user@host:port for a peer. Dynamic / force_rport peers resolve to
 * their last REGISTER src_addr; static-host peers keep their configured host:port. */
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

void sofia_resolve_peer_target(struct sofia_peer *peer, const char *user,
		char *out_url, size_t out_len)
{
	const char *target_host = peer->host;
	int target_port = peer->port;
	char addr_buf[128];
	/* The registered-source branch carries a learned transport (peer->reg_transport);
	 * a static host now routes over its configured transport= (peer->transport),
	 * applied below via sofia_transport_name. */
	int routed_via_registration = 0;

	if (peer->registered && !ast_sockaddr_isnull(&peer->src_addr)
		&& ((peer->nat & SOFIA_NAT_FORCE_RPORT)
			|| !strcasecmp(peer->host, "dynamic"))) {
		ast_copy_string(addr_buf, ast_sockaddr_stringify_host(&peer->src_addr), sizeof(addr_buf));
		target_host = addr_buf;
		target_port = ast_sockaddr_port(&peer->src_addr);
		routed_via_registration = 1;
	} else if (!strcasecmp(peer->host, "dynamic") && !ast_sockaddr_isnull(&peer->defaddr)) {
		/* defaultip fallback: unregistered host=dynamic peer → route to defaultip
		 * (the src_addr branch above wins once it registers). */
		ast_copy_string(addr_buf, ast_sockaddr_stringify_host(&peer->defaddr), sizeof(addr_buf));
		target_host = addr_buf;
		if (ast_sockaddr_port(&peer->defaddr)) {
			target_port = ast_sockaddr_port(&peer->defaddr);
		}
	}
	{
		char hbuf[80];	/* IPv6-bracket-wrap (RFC 3261 §19.1.2); helper is idempotent */
		snprintf(out_url, out_len, "sip:%s@%s:%d", user ? user : "",
			sofia_uri_format_host(target_host, hbuf, sizeof(hbuf)), target_port);
	}
	if (routed_via_registration) {
		sofia_uri_append_transport(out_url, out_len, peer->reg_transport);
	} else {
		/* Static host: route over the peer's configured transport= (tls/tcp/ws/wss). Without the
		 * ;transport= param sofia-sip defaults the RURI to UDP, so a static TLS trunk silently went
		 * out over UDP; udp/unknown is a no-op in the helper, so plain UDP peers are unaffected. */
		sofia_uri_append_transport(out_url, out_len, sofia_transport_name(peer->transport));
	}
	/* usereqphone: append ;user=phone when set AND the user-part is a phone number. */
	if (peer->usereqphone && sofia_user_looks_like_phone(user)) {
		size_t cur = strlen(out_url);
		const char *suffix = ";user=phone";
		size_t suffix_len = strlen(suffix);
		if (cur + suffix_len < out_len) {
			memcpy(out_url + cur, suffix, suffix_len + 1);
		}
	}
}

/*
 * Build the outbound RURI for a SPECIFIC registered contact (per-contact routing),
 * the single source of truth shared by the fork loop and the single-live-contact
 * request path. Snapshots the refresh-mutable contact fields under ao2_lock(c), then:
 *   - for ws/wss with a non-null src_addr, targets the registered Via source
 *     (c->src_addr) — a SIP.js WS/WSS Contact host is a TEST-NET placeholder
 *     (192.0.2.x / .invalid) and a WebSocket client is reachable ONLY over its
 *     accepted connection; sofia-sip reuses that tport once ;transport=wss is
 *     appended (RFC 7118; mirrors sofia_resolve_peer_target);
 *   - otherwise targets c->host:c->port;
 *   - formats "sip:user@host:port" (IPv6-bracket-wrapped, RFC 3261 §19.1.2) and
 *     appends the contact's transport.
 * When path_support is set and path_out is provided, also copies this contact's
 * stored RFC 3327 Path (ready "<uri;lr>,..." Route value) for pre-loading on the
 * INVITE. Lock order: takes ONLY the contact ao2 lock (the caller must not hold it).
 */
void sofia_build_contact_ruri(struct sofia_contact *c, const char *user,
	char *out, size_t outlen, int path_support, char *path_out, size_t path_outlen)
{
	char hbuf[80];
	char c_transport[8];
	char c_host[128];
	int c_port;

	if (!c || !out || !outlen)
		return;

	ao2_lock(c);
	ast_copy_string(c_transport, c->transport, sizeof(c_transport));
	if ((!strcasecmp(c_transport, "ws") || !strcasecmp(c_transport, "wss"))
			&& !ast_sockaddr_isnull(&c->src_addr)) {
		ast_copy_string(c_host, ast_sockaddr_stringify_host(&c->src_addr), sizeof(c_host));
		c_port = ast_sockaddr_port(&c->src_addr);
	} else {
		ast_copy_string(c_host, c->host, sizeof(c_host));
		c_port = c->port;
	}
	if (path_support && path_out && path_outlen) {
		ast_copy_string(path_out, c->path, path_outlen);	/* RFC 3327 */
	}
	ao2_unlock(c);

	snprintf(out, outlen, "sip:%s@%s:%d", user ? user : "",
		sofia_uri_format_host(c_host, hbuf, sizeof(hbuf)),
		c_port);
	sofia_uri_append_transport(out, outlen, c_transport);
}

/*
 * Select the peer's SINGLE unexpired (expires > now) registered contact, iff EXACTLY ONE exists,
 * returning it with a +1 ref the caller must release. Also reports total binding count + unexpired
 * count so the caller distinguishes: unexpired==1 → route it; unexpired>1 → fork; total>0 &&
 * unexpired==0 → registration expired (CHANUNAVAIL on a dynamic peer, NOT the stale aggregate);
 * total==0 → never registered (unchanged). Lock order: iterates the contacts container + takes
 * per-contact ao2 locks; the caller must NOT hold peer->lock (mirrors the post-release Path lookup).
 */
/* A binding is routable only while its granted Contact expiry is still in the future (RFC 3261 soft
 * state, §10.3): registrations expire unless refreshed by a re-REGISTER before the interval elapses.
 * ignoreregexpire keeps an expired contact in the container for CLI/BLF/rebind visibility, but it is
 * NOT routable — the phone must re-REGISTER. Honors any negotiated expiry (120/300/3600s) with no tuning. */
static int sofia_contact_is_unexpired(time_t expires, time_t now)
{
	return expires > now;
}

static struct sofia_contact *sofia_peer_select_single_live_contact(struct sofia_peer *peer,
	int *unexpired_out, int *total_out)
{
	struct ao2_iterator ci;
	struct sofia_contact *c, *winner = NULL;
	int unexpired = 0, total = 0;
	time_t now = time(NULL);

	if (unexpired_out)
		*unexpired_out = 0;
	if (total_out)
		*total_out = 0;
	if (!peer || !peer->contacts)
		return NULL;

	ci = ao2_iterator_init(peer->contacts, 0);
	while ((c = ao2_iterator_next(&ci))) {
		time_t c_exp;
		ao2_lock(c);
		c_exp = c->expires;
		ao2_unlock(c);
		total++;
		if (sofia_contact_is_unexpired(c_exp, now)) {	/* RFC 3261 soft state: expiry alone, any transport */
			unexpired++;
			if (unexpired == 1) {
				winner = c;	/* keep this ref as the sole-unexpired candidate */
				ao2_ref(winner, +1);
			}
		}
		ao2_ref(c, -1);
	}
	ao2_iterator_destroy(&ci);

	if (unexpired_out)
		*unexpired_out = unexpired;
	if (total_out)
		*total_out = total;

	if (unexpired != 1) {
		/* 0 → caller decides (host=dynamic && total>0 → CHANUNAVAIL, else aggregate); >1 → fork. Drop candidate. */
		if (winner) {
			ao2_ref(winner, -1);
			winner = NULL;
		}
	}
	return winner;
}

/* Contact lookup by source address (inbound traffic). */
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
		/* Compare mutable src_addr under the contact lock (REGISTER refresh races). */
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

/* Rebind lookup #1 (RFC 5626): an existing contact bound to the same +sip.instance. With a reg-id, require
 * the SAME reg-id - distinct reg-ids are distinct concurrent flows that MUST coexist; an instance with no
 * reg-id matches by instance alone. Returns the match with a +1 ref. Caller holds peer->lock. */
static struct sofia_contact *sofia_peer_find_contact_by_instance(struct sofia_peer *peer,
	const char *instance_id, int reg_id)
{
	struct ao2_iterator ci;
	struct sofia_contact *c, *found = NULL;
	if (!peer || !peer->contacts || ast_strlen_zero(instance_id))
		return NULL;
	ci = ao2_iterator_init(peer->contacts, 0);
	while ((c = ao2_iterator_next(&ci))) {
		int match;
		ao2_lock(c);
		match = (c->instance_id[0] && !strcasecmp(c->instance_id, instance_id)
			&& (reg_id == 0 || c->reg_id == reg_id));
		ao2_unlock(c);
		if (match) {
			found = c;	/* keep the iterator ref */
			break;
		}
		ao2_ref(c, -1);
	}
	ao2_iterator_destroy(&ci);
	return found;
}

/* Rebind lookup #2 (RFC 3261 10.2): an instance-LESS existing contact with the same REGISTER Call-ID and
 * transport - a legacy rotator keeps its Call-ID across renewals while its source port / Contact URI churn.
 * Only matches instance-less contacts (the RFC 5626 tier owns instance-bearing ones); gated at the call
 * site to instance-less single-Contact REGISTERs. Returns +1 ref. Caller holds peer->lock. */
static struct sofia_contact *sofia_peer_find_contact_by_callid(struct sofia_peer *peer,
	const char *call_id, const char *transport)
{
	struct ao2_iterator ci;
	struct sofia_contact *c, *found = NULL;
	if (!peer || !peer->contacts || ast_strlen_zero(call_id))
		return NULL;
	ci = ao2_iterator_init(peer->contacts, 0);
	while ((c = ao2_iterator_next(&ci))) {
		int match;
		ao2_lock(c);
		match = (c->instance_id[0] == '\0' && c->call_id[0] && !strcmp(c->call_id, call_id)
			&& !strcasecmp(c->transport, S_OR(transport, "")));
		ao2_unlock(c);
		if (match) {
			found = c;
			break;
		}
		ao2_ref(c, -1);
	}
	ao2_iterator_destroy(&ci);
	return found;
}

/* Rebind lookup (no-id fallback, RFC 5626 spirit): when the Contact carries NO stable id (no +sip.instance,
 * no usable Call-ID), match an instance-LESS existing contact of the SAME DEVICE by source IP (host only -
 * the NAT-mapped port rotates) + same transport + same User-Agent. Deliberately does NOT use the Contact
 * user: a WebSocket UA (SIP.js) sends a synthetic RANDOM Contact (RFC 7118 .invalid / RFC 5737 host) so it is
 * not a device key, and within one AOR a normal UA's Contact user just equals the AOR (so it discriminates
 * nothing). For nat/force_rport, single-Contact REGISTERs only (gated at the call site). Returns +1 ref;
 * caller holds peer->lock. Inherent limit: two identical (same IP+transport+UA+AOR) instance-less devices
 * collapse to one binding - RFC 5626 4.1 requires the UA to send +sip.instance to be distinguished;
 * max_contacts caps anything else. */
static struct sofia_contact *sofia_peer_find_contact_nat_fallback(struct sofia_peer *peer,
	const struct ast_sockaddr *src, const char *transport, const char *user_agent)
{
	struct ao2_iterator ci;
	struct sofia_contact *c, *found = NULL;
	if (!peer || !peer->contacts || !src || ast_strlen_zero(user_agent))
		return NULL;
	ci = ao2_iterator_init(peer->contacts, 0);
	while ((c = ao2_iterator_next(&ci))) {
		int match;
		ao2_lock(c);
		match = (c->instance_id[0] == '\0'
			&& ast_sockaddr_cmp_addr(&c->src_addr, src) == 0
			&& !strcasecmp(c->transport, S_OR(transport, ""))
			/* c->user_agent is stored truncated to its 64-byte buffer (SIP.js UA is ~108 chars), so compare
			 * only up to the stored length - a full-vs-truncated strcasecmp would never match. */
			&& c->user_agent[0] && !strncasecmp(c->user_agent, user_agent, sizeof(c->user_agent) - 1));
		ao2_unlock(c);
		if (match) {
			found = c;
			break;
		}
		ao2_ref(c, -1);
	}
	ao2_iterator_destroy(&ci);
	return found;
}

/* Rebind an EXISTING contact onto a renewed registration that arrived with a new Contact URI / source
 * (the same device rotated its NAT port). contact_uri is the ao2 hash/cmp key (contact_hash_fn/cmp_fn), so
 * it MUST be re-keyed: unlink under the OLD uri, mutate, relink under the NEW uri (the sofia_peer_ipport_reindex
 * pattern). The SAME object is kept, so an active call's pvt->active_contact pointer + ao2 ref + active_calls
 * all survive (a port move on a live call is exactly what we want). Caller holds peer->lock, which serializes
 * per-peer REGISTER processing (no concurrent rebind for this peer). `c` carries the finder's +1 ref (caller
 * drops it). old_src_out (optional) receives the pre-rebind src_addr for move accounting. Returns 0, or -1 if
 * the relink fails (OOM) - fail-closed: the stale binding is gone, but NO duplicate is created (better than the
 * fork-to-stale-port bug). */
static int sofia_contact_rebind(struct sofia_peer *peer, struct sofia_contact *c,
	const char *new_uri, const char *host, int port, const char *transport,
	const char *user_agent, const struct ast_sockaddr *src, const char *pathstr,
	const char *instance_id, int reg_id, const char *call_id, time_t expires_at,
	struct ast_sockaddr *old_src_out)
{
	ao2_unlink(peer->contacts, c);	/* remove under the OLD contact_uri (still the live key) */
	ao2_lock(c);
	if (old_src_out) {
		ast_sockaddr_copy(old_src_out, &c->src_addr);
	}
	ast_copy_string(c->contact_uri, new_uri, sizeof(c->contact_uri));	/* the re-key, safe while unlinked */
	if (host) {
		ast_copy_string(c->host, host, sizeof(c->host));
	}
	c->port = port;
	ast_copy_string(c->transport, transport, sizeof(c->transport));
	if (!ast_strlen_zero(user_agent)) {
		ast_copy_string(c->user_agent, user_agent, sizeof(c->user_agent));
	}
	ast_copy_string(c->path, pathstr, sizeof(c->path));
	c->expires = expires_at;
	c->last_register = time(NULL);	/* diagnostic timestamp: this contact just (re)bound (Last-REGISTER gauge) */
	memcpy(&c->src_addr, src, sizeof(*src));
	ast_copy_string(c->instance_id, instance_id ? instance_id : "", sizeof(c->instance_id));
	c->reg_id = reg_id;
	ast_copy_string(c->call_id, call_id ? call_id : "", sizeof(c->call_id));
	ao2_unlock(c);
	if (!ao2_link(peer->contacts, c)) {	/* relink under the NEW contact_uri */
		ast_log(LOG_WARNING, "Sofia: contact rebind relink failed for peer '%s' (uri=%s) - "
			"binding dropped (fail-closed, no duplicate)\n", peer->name, new_uri);
		return -1;
	}
	if (sofia_debug) {
		ast_verbose("Sofia: Rebound contact for peer '%s' -> %s (same device, renewed flow)\n",
			peer->name, new_uri);
	}
	return 0;
}

/* Contact lookup by host:port (outbound traffic). */
static struct sofia_contact *sofia_peer_find_contact_by_host_port(struct sofia_peer *peer,
	const char *host, int port)
{
	struct ao2_iterator ci;
	struct sofia_contact *c, *found = NULL;
	if (!peer || !peer->contacts || !host)
		return NULL;
	/* Pass 1: exact Contact host:port — the common udp/tcp/tls case (c->host is the real routable host). */
	ci = ao2_iterator_init(peer->contacts, 0);
	while ((c = ao2_iterator_next(&ci))) {
		if (c->port == port && strcasecmp(c->host, host) == 0) {
			found = c;
			break;
		}
		ao2_ref(c, -1);
	}
	ao2_iterator_destroy(&ci);
	if (found) {
		return found;
	}
	/* Pass 2: match the registered src_addr. A WSS/NAT peer's Contact host is a placeholder (SIP.js
	 * .invalid / TEST-NET, RFC 7118 §8.1) or a private LAN IP, so an outbound request whose host:port was
	 * built from the registered src_addr never matches c->host in pass 1 — leaving active_contact
	 * NULL, which broke in-dialog ACK/BYE NAT routing (the caller never learned the call ended → 15s RTP
	 * timeout). Pass 1 wins whenever the Contact host is routable, so this is zero-regression for udp/tcp/tls.
	 * With multiple contacts the src_addr is unique per registration, so only the right one matches.
	 * src_addr is refresh-mutable → read under the contact lock. */
	ci = ao2_iterator_init(peer->contacts, 0);
	while ((c = ao2_iterator_next(&ci))) {
		int match;
		ao2_lock(c);
		match = (ast_sockaddr_port(&c->src_addr) == port
			&& !strcasecmp(ast_sockaddr_stringify_host(&c->src_addr), host));
		ao2_unlock(c);
		if (match) {
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

/*! \brief 1 when the peer is outside localnet (WAN) and externaddr is configured. */
int sofia_should_use_externaddr(const struct ast_sockaddr *peer_addr)
{
	int res;
	if (ast_strlen_zero(sofia_cfg.externaddr))
		return 0;
	/* sofia_cfg.localha is a freeable global rebuilt by reload on sofia_thread;
	 * this runs on the channel thread. rdlock the NULL-check + walk together (leaf). */
	ast_rwlock_rdlock(&sofia_localha_lock);
	res = !sofia_cfg.localha ? 1
		: (ast_apply_ha(sofia_cfg.localha, peer_addr) == AST_SENSE_ALLOW);
	ast_rwlock_unlock(&sofia_localha_lock);
	return res;
}

/* Bracket-wrap an IPv6 literal host for a SIP URI (RFC 3261 §19.1.2); IPv4 /
 * hostnames / already-bracketed input pass through (idempotent). Returns out_buf. */
const char *sofia_uri_format_host(const char *host, char *out_buf, size_t out_len)
{
	if (!host || !*host) {
		if (out_buf && out_len > 0) {
			out_buf[0] = '\0';
		}
		return out_buf;
	}
	/* IPv6 literal = contains ':' AND not already bracketed. */
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
	fork->children = ao2_container_alloc(11, fork_branch_hash_fn, fork_branch_cmp_fn); /* prime */
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


/* ao2_callback: cancel + unlink every fork child EXCEPT the winner (passed via arg).
 * Returns CMP_MATCH to drive OBJ_UNLINK from fork->children. */
static int sofia_fork_cancel_loser_cb(void *obj, void *arg, int flags)
{
	struct sofia_pvt *child = obj;
	struct sofia_pvt *winner = arg;
	if (child == winner) {
		return 0;
	}
	SOFIA_FORKDBG("cancel-loser branch=%s child_nh=%p child_rtp=%p is_webrtc=%d",
		child->fork_branch_id, (void *)child->nh, (void *)child->rtp, child->is_webrtc);
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
	const char *reason = arg;	/* Q.850 Reason from the master hangup (RFC 3326), or NULL */
	SOFIA_FORKDBG("cancel-all branch=%s child_nh=%p child_rtp=%p is_webrtc=%d reason=%s",
		child->fork_branch_id, (void *)child->nh, (void *)child->rtp, child->is_webrtc,
		S_OR(reason, "(none)"));
	if (child->nh) {
		nua_cancel(child->nh,
			TAG_IF(!ast_strlen_zero(reason), SIPTAG_REASON_STR(reason)),
			TAG_END());
	}
	ao2_unlink(dialogs, child);
	return CMP_MATCH;
}

/* IPv6-aware host:port split for a "host[:port]" tail: a bracketed
 * [2001:db8::1]:5060 is NOT split at an inner colon. Fills host (bracket-stripped,
 * clamped to hostlen) and *port; strips trailing ;params / '>' in the no-port branch. */
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
			if (port && end[1] == ':') {
				*port = atoi(end + 2);
			}
			return;
		}
		/* no closing ']' — fall through to copy raw */
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
		if (port) {
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

/* Keep a chan_sofia channel's media fds (slots 0..3) a derived cache of the live
 * pvt->rtp/vrtp: set the live fds, and CLEAR (-1) any slot whose instance is absent.
 * A bundled WebRTC winner has no separate pvt->vrtp, so slots 2/3 MUST be cleared —
 * otherwise the closed pre-alloc video fds linger and, being POLLNVAL/always-ready,
 * win the classic last-ready-wins channel poll over the live audio fd, so the winner's
 * audio/STUN socket is never serviced and ICE/DTLS never completes ("fork-winner no
 * audio"). Also corrects a masquerade that copied the clone's stale fds wholesale.
 * Caller holds the channel lock with a stable pvt (channel->pvt order); does NOT wake
 * the bridge — call sites already do (fork: AST_CONTROL_ANSWER; fixup: the masquerade). */
static void sofia_sync_media_fds(struct ast_channel *chan, struct sofia_pvt *pvt)
{
	if (!chan || !pvt) {
		return;
	}
	ast_channel_set_fd(chan, 0, pvt->rtp ? ast_rtp_instance_fd(pvt->rtp, 0) : -1);
	ast_channel_set_fd(chan, 1, pvt->rtp ? ast_rtp_instance_fd(pvt->rtp, 1) : -1);
	/* Slots 2/3 carry video ONLY for a separate (non-bundled) vrtp. A bundled winner's
	 * video rides pvt->rtp, so 2/3 must stay -1. The webrtc_video_bundled guard also keeps
	 * this correct if the helper is ever called before a transient bundled vrtp is torn
	 * down (e.g. from an SDP-commit path). */
	ast_channel_set_fd(chan, 2, (pvt->vrtp && !pvt->webrtc_video_bundled) ? ast_rtp_instance_fd(pvt->vrtp, 0) : -1);
	ast_channel_set_fd(chan, 3, (pvt->vrtp && !pvt->webrtc_video_bundled) ? ast_rtp_instance_fd(pvt->vrtp, 1) : -1);
}

static int sofia_fork_pick_winner(struct sofia_fork *fork, struct sofia_pvt *child, sip_t const *sip)
{
	struct sofia_pvt *master;

	/* Validate the child's answer SDP BEFORE claiming winner: on encryption-policy
	 * failure return -1 (caller treats it as a loser; siblings may still answer with
	 * valid crypto). Outside fork->lock — parse_sdp touches only child + sip. */
	if (sip && sip->sip_payload && sip->sip_payload->pl_data) {
		if (sofia_parse_sdp(child, sip, 0 /* answer: fork child 200 OK */) < 0) {
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
	/* Claim winner AND snapshot+ref the master under the same fork->lock hold. A
	 * concurrent master sofia_hangup NULLs fork->master; if already gone, treat
	 * this child as a loser (return -1). The +1 ref pins the master for the
	 * steal/answer mutation below against the channel thread. */
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
	SOFIA_FORKDBG("winner branch=%s child_nh=%p child_rtp=%p child_webrtc=%d master=%p",
		child->fork_branch_id, (void *)child->nh, (void *)child->rtp, child->is_webrtc, (void *)master);

	/* All master-pvt mutation runs under master->lock (serialized vs sofia_hangup).
	 * Taken AFTER fork->lock is released to preserve the master->lock -> fork->lock
	 * order sofia_hangup uses. */
	ast_mutex_lock(&master->lock);

	/* Destroy the pre-allocated master->nh (never sent an INVITE in fork mode)
	 * before stealing the winner's handle, else it + its su_home arena leak.
	 * bind(NULL) first neutralizes any in-flight event for it. */
	if (master->nh) {
		nua_handle_t *old_nh = master->nh;
		master->nh = NULL;
		nua_handle_bind(old_nh, NULL);
		nua_handle_destroy(old_nh);
	}
	master->nh = child->nh;
	child->nh = NULL;
	nua_handle_bind(master->nh, master);

	/* Inherit the winner child's o= session identity so the first master re-INVITE
	 * keeps the same sess-id (RFC 3264 §8 in-dialog session identity). */
	master->sess_id = child->sess_id;
	master->sess_version = child->sess_version;

	/* Set master's active contact from the winner child's ruri (RFC 3261 §12.2.1.1 /
	 * §16.12: in-dialog BYE/ACK must route to the actual 2xx target). In a
	 * 1->2-contact REGISTER-vs-call race the master may carry a STALE request-time
	 * active_contact (sofia_request_call selected a single live contact before the
	 * REGISTER added the second and pushed us onto the fork path). sofia_pvt_set_active_contact
	 * short-circuits when already-set, so without clearing first the winner's contact
	 * is dropped and the in-dialog BYE/ACK (sofia_pvt_build_nat_target_url reads
	 * pvt->active_contact) + per-contact active_calls/busy_on_active accounting stay
	 * charged to the wrong (stale) contact — a NAT/WSS peer then never gets the BYE
	 * (zombie leg until RTP timeout). REPLACE: clear the stale one (decrements its
	 * active_calls) so the winner's set takes. Under master->lock; the clear/set only
	 * touch the contact ao2 lock (leaf), consistent with the lock order. */
	if (master->peer && !ast_strlen_zero(child->ruri)) {
		const char *at = strchr(child->ruri, '@');
		if (at) {
			char rhost[64] = "";
			int rport = 5060;
			sofia_split_hostport_from_uri(at + 1, rhost, sizeof(rhost), &rport);	/* IPv6-aware */
			struct sofia_contact *contact = sofia_peer_find_contact_by_host_port(master->peer, rhost, rport);
			if (contact) {
				sofia_pvt_clear_active_contact(master);	/* drop any stale request-time contact so the winner's set takes */
				sofia_pvt_set_active_contact(master, contact);
				ao2_ref(contact, -1);
			}
		}
	}

	/* Destroy the pre-allocated master->rtp/vrtp before the winner-steal, else the
	 * pre-fork instances leak. Stop RTCP/DTLS refs first (sofia_rtp_stop_destroy) so the socket closes. */
	sofia_rtp_stop_destroy(&master->rtp);
	sofia_rtp_stop_destroy(&master->vrtp);
	master->rtp = child->rtp;
	child->rtp = NULL;
	master->vrtp = child->vrtp;
	child->vrtp = NULL;
	SOFIA_FORKDBG("rtp-steal master_nh=%p master_rtp=%p master_vrtp=%p (rtp=%p = res_rtp inst join key)",
		(void *)master->nh, (void *)master->rtp, (void *)master->vrtp, (void *)master->rtp);

	/* Steal the winner's SRTP contexts; losers' contexts free via their destructors. */
	master->srtp = child->srtp;
	child->srtp = NULL;
	master->vsrtp = child->vsrtp;
	child->vsrtp = NULL;

	/* Carry the WebRTC pvt state that BELONGS
	 * to the just-stolen rtp/vrtp/srtp instances onto master. Otherwise a forked WebRTC(-video) winner keeps
	 * the media instances but master->is_webrtc stays 0 and master->capability/mids/tls-ids are unset, so a
	 * later master re-INVITE/hold would emit plain RTP/AVP on a DTLS-SRTP leg and lose video. */
	master->is_webrtc = child->is_webrtc;
	ast_string_field_set(master, outbound_proxy, child->outbound_proxy);	/* NAT: keep routing master re-INVITEs to the winner contact's public source */
	master->webrtc_offerer = child->webrtc_offerer;
	master->webrtc_bundle = child->webrtc_bundle;	/* sofia_generate_sdp emits the session a=group:BUNDLE only when is_webrtc && webrtc_bundle — a forked winner must keep it */
	master->webrtc_answer_applied = child->webrtc_answer_applied;
	master->webrtc_video_offerer = child->webrtc_video_offerer;
	master->webrtc_video_answer_applied = child->webrtc_video_answer_applied;
	master->webrtc_video_accepted = child->webrtc_video_accepted;
	master->webrtc_video_bundled = child->webrtc_video_bundled;	/* BUNDLE: video-on-audio-transport flag travels to the fork winner */
	master->webrtc_mid_ext_id = child->webrtc_mid_ext_id;	/* BUNDLE: the negotiated MID extmap id travels too */
	master->capability = child->capability;
	/* H264 fmtp relay: the winner child negotiated the H264 config with the browser — carry it to master
	 * so a later master re-INVITE/answer keeps advertising the same profile-level-id/packetization-mode. */
	master->h264_fmtp_valid = child->h264_fmtp_valid;
	master->h264_pmode = child->h264_pmode;
	ast_copy_string(master->h264_fmtp, child->h264_fmtp, sizeof(master->h264_fmtp));
	ast_copy_string(master->webrtc_mid, child->webrtc_mid, sizeof(master->webrtc_mid));
	ast_copy_string(master->webrtc_tls_id, child->webrtc_tls_id, sizeof(master->webrtc_tls_id));
	ast_copy_string(master->webrtc_video_mid, child->webrtc_video_mid, sizeof(master->webrtc_video_mid));
	ast_copy_string(master->webrtc_video_tls_id, child->webrtc_video_tls_id, sizeof(master->webrtc_video_tls_id));
	/* Stream identity MUST survive the steal: the child generated cname/msid for the initial offer
	 * (RFC 7022 cname persistence / RFC 8830 track continuity). Without these the master regenerates
	 * BOTH at its first re-INVITE answer — the browser sees a brand-new remote stream mid-call and
	 * drops the old track (post-unhold black video on the fork-winner leg). */
	ast_copy_string(master->webrtc_cname, child->webrtc_cname, sizeof(master->webrtc_cname));
	ast_copy_string(master->webrtc_msid, child->webrtc_msid, sizeof(master->webrtc_msid));

	/* WebRTC DataChannel fork-steal: the DataChannel transport rides the just-stolen
	 * master->rtp (its engine cb_data already moved with the rtp instance above), so we only MOVE the
	 * dc pointer child->master + the negotiated DataChannel fields, then REPOINT dc->pvt to master (no re-attach).
	 * Mirrors the webrtc_* steal. sofia_dc_set_pvt is a no-op stub without usrsctp. */
	master->dc = child->dc;
	child->dc = NULL;
	master->dc_offered = child->dc_offered;
	master->dc_accepted = child->dc_accepted;
	master->dc_offerer = child->dc_offerer;		/* OFFER-side: the winner child provisioned its own outbound DataChannel offer; carry the emit/answer-apply state */
	master->dc_answer_applied = child->dc_answer_applied;
	master->dc_sctp_port = child->dc_sctp_port;
	master->dc_max_message_size = child->dc_max_message_size;
	ast_copy_string(master->dc_mid, child->dc_mid, sizeof(master->dc_mid));
	if (master->dc) {
		sofia_dc_set_pvt(master->dc, master);
	}

	/* Compute the stolen-RTP fds here (master->rtp/vrtp stable under master->lock)
	 * but DEFER writing owner->fds[] until below under the channel lock, else it
	 * races ast_do_masquerade's fd swap. */
	int win_fd[4] = { -1, -1, -1, -1 };
	if (master->rtp) {
		win_fd[0] = ast_rtp_instance_fd(master->rtp, 0);
		win_fd[1] = ast_rtp_instance_fd(master->rtp, 1);
		if (master->vrtp) {
			win_fd[2] = ast_rtp_instance_fd(master->vrtp, 0);
			win_fd[3] = ast_rtp_instance_fd(master->vrtp, 1);
		}
	}

	/* Snapshot+ref owner under master->lock, set state, drop the lock, THEN
	 * queue/setstate — never reach a fresh channel lock while holding master->lock
	 * (canonical channel->pvt order vs sofia_hangup). */
	struct ast_channel *m_owner = master->owner;
	if (m_owner) {
		ast_channel_ref(m_owner);
	}
	master->state = SOFIA_DIALOG_STATE_UP;
	ast_mutex_unlock(&master->lock);

	if (m_owner) {
		/* Write the stolen-RTP fds under the channel lock (canonical channel->pvt
		 * order) — serializes with ast_do_masquerade's fds[] swap. */
		if (win_fd[0] >= 0) {
			ast_channel_lock(m_owner);
			ast_mutex_lock(&master->lock);
			/* Revalidate: a masquerade could have swapped master->owner since we
			 * dropped master->lock; write fds[] only if m_owner is still it. */
			if (master->owner == m_owner) {
				/* Install the winner's media fds as a derived cache of the stolen
				 * rtp/vrtp, clearing the stale bundle-video slots that would otherwise
				 * mask the audio fd. The AST_CONTROL_ANSWER queued below wakes the poll. */
				sofia_sync_media_fds(m_owner, master);
				SOFIA_FORKDBG("fd-move m_owner=%p fds=[%d,%d,%d,%d] (masquerade-gate HIT)",
					(void *)m_owner, win_fd[0], win_fd[1], win_fd[2], win_fd[3]);
				/* The winner's answer was parsed on the owner-LESS fork child, so the non-fork
				 * set_format path (sofia_parse_sdp) never applied the negotiated codec — master->owner
				 * keeps sofia_new's pre-fork ULAW read/write format. Apply the winner-negotiated audio
				 * format now, mirroring that path (same channel lock, master->owner==m_owner revalidated),
				 * so a winner that negotiated a non-ULAW codec drives the owner's read/write format instead
				 * of relying on bridge translation to mask it. Audio-scoped: video native format is handled
				 * by the SDP-only answer mask + the WebRTC nativeformats sync. */
				if (master->capability & AST_FORMAT_AUDIO_MASK) {
					format_t chosen_audio = ast_codec_choose(&master->prefs,
						master->capability & AST_FORMAT_AUDIO_MASK, 1);
					if (!chosen_audio) {
						chosen_audio = ast_best_codec(master->capability & AST_FORMAT_AUDIO_MASK);
					}
					if (chosen_audio) {
						m_owner->nativeformats =
							(m_owner->nativeformats & ~AST_FORMAT_AUDIO_MASK) | chosen_audio;
						ast_set_read_format(m_owner, chosen_audio);
						ast_set_write_format(m_owner, chosen_audio);
					}
				}
			} else {
				SOFIA_FORKDBG("fd-move SKIPPED m_owner=%p master_owner=%p (masquerade swapped owner)",
					(void *)m_owner, (void *)master->owner);
			}
			ast_mutex_unlock(&master->lock);
			ast_channel_unlock(m_owner);
		}
		/* Before answering the caller, mask its answer video to what THIS fork winner accepted
		 * (master->capability holds the stolen winner video) — chan_sofia does not transcode video.
		 * SDP-only (video_answer_mask); does not touch the caller channel's nativeformats. */
		sofia_set_caller_video_mask_from_answered(master);
		ast_queue_control(m_owner, AST_CONTROL_ANSWER);
		ast_setstate(m_owner, AST_STATE_UP);
		ast_channel_unref(m_owner);
	}

	ast_verbose("Sofia: Fork winner picked - branch %s for peer '%s' (%s)\n",
		child->fork_branch_id, master->peername, fork->fork_id);

	/* Fork winner answered (2xx): the master's outbound ring is over — decrement inRinging
	 * so the peer BLF moves RINGING -> INUSE. Mirrors the non-fork 200 OK path (~15108); the
	 * call stays in the inUse pool until hangup. Without this the fork case only cleared the
	 * ring at pvt teardown (the destructor catchall), so BLF showed RINGING for the whole
	 * answered call. master->lock is released here; the counter helper takes its own locks and
	 * clears ring_inc_done so the catchall never double-decrements. */
	sofia_update_call_counter(master, SOFIA_DEC_CALL_RINGING);

	/* Release the master lifetime ref taken under fork->lock above. */
	ao2_ref(master, -1);

	/* Cancel + unlink all losing siblings. */
	ao2_callback(fork->children, OBJ_UNLINK | OBJ_MULTIPLE | OBJ_NODATA,
		sofia_fork_cancel_loser_cb, child);

	/* Winner's resources are now on master; unlink the empty shell. */
	ao2_unlink(dialogs, child);
	ao2_unlink(fork->children, child);

	return 0;
}

/* A fork child failed/was rejected: drop the live count, unlink from both
 * containers, and if it was the last branch with no winner, queue HANGUP on the
 * master. SIP teardown is the CALLER's job. Returns the remaining live count.
 * sofia_thread only. */
static int sofia_fork_child_failed(struct sofia_fork *fork, struct sofia_pvt *pvt)
{
	int empty, picked, remaining;
	struct sofia_pvt *m;
	ast_mutex_lock(&fork->lock);
	fork->child_count--;
	ao2_unlink(fork->children, pvt);
	ast_mutex_unlock(&fork->lock);
	ao2_unlink(dialogs, pvt);
	/* Snapshot+ref fork->master under fork->lock so the HANGUP can't race a
	 * concurrent master sofia_hangup into a UAF. */
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
			/* Snapshot+ref m->owner under m->lock, drop it, then queue HANGUP
			 * (never hold m->lock across the channel lock). */
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
/* Outbound text-message via nua_message (best-effort: UA replies 405 if unsupported). */
static int sofia_send_text(struct ast_channel *ast, const char *text);
static int sofia_indicate(struct ast_channel *ast, int condition, const void *data, size_t datalen);
static int sofia_queryoption(struct ast_channel *chan, int option, void *data, int *datalen);
static int sofia_setoption(struct ast_channel *chan, int option, void *data, int datalen);
static int sofia_check_sip_domain(const char *domain);
static int sofia_fixup(struct ast_channel *oldchan, struct ast_channel *newchan);
static int sofia_send_digit_begin(struct ast_channel *ast, char digit);
static int sofia_send_digit_end(struct ast_channel *ast, char digit, unsigned int duration);
static const char *sofia_get_callid(struct ast_channel *ast);
static int sofia_devicestate(void *data);	/* BLF/presence: report SIP/<peer> device state to the core */

/* Non-static: the WebRTC DataChannel relay (sofia_datachannel.c) compares a bridged channel's
 * ->tech against this to confirm a far leg is a Sofia channel (declared in chan_sofia_internal.h). */
struct ast_channel_tech sofia_tech = {
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
	.setoption = sofia_setoption,
	.queryoption = sofia_queryoption,
	.transfer = sofia_transfer,
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

/* T.38 fax UDPTL protocol registration. .type="SIP" matches chan_sip (the
 * mutual-exclusive load prevents a .type collision). set_udptl_peer is a no-op
 * so chan_sofia keeps UDPTL in the PBX media path (no direct peer relay). */
static struct ast_udptl *sofia_get_udptl_peer(struct ast_channel *chan);
static int sofia_set_udptl_peer(struct ast_channel *chan, struct ast_udptl *udptl);

static struct ast_udptl_protocol sofia_udptl = {
	.type = "SIP",
	.get_udptl_info = sofia_get_udptl_peer,
	.set_udptl_peer = sofia_set_udptl_peer,
};

static struct ast_udptl *sofia_get_udptl_peer(struct ast_channel *chan)
{
	/* Return pvt->udptl once t38_state >= PEER_REINVITE (which implies udptl
	 * allocated); else NULL. State + udptl read under pvt->lock. */
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
	/* No direct UDPTL transfer; return success so the core keeps the PBX relay. */
	(void)chan;
	(void)udptl;
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
 * Caller must ensure pvt->rtp is bound (bound after rtp_init in
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

/* DTMF effective-mode helpers (chan_sip parity for the property/AUTO/DSP apply path).
 * pvt->dtmfmode is the CONFIGURED/admin mode; pvt->dtmf_effective is the per-negotiation
 * RUNTIME mode (equal to dtmfmode until an AUTO offer is resolved at SDP-parse). Read
 * pvt->dtmf_effective — never pvt->dtmfmode — from the send/DSP/property paths. */
int sofia_dtmf_wants_rfc2833(const struct sofia_pvt *pvt)
{
	/* Telephone-event (RFC 2833/4733) is offered/used when the effective mode is RFC2833,
	 * when it is still-unresolved AUTO (we offer telephone-event and resolve on the answer),
	 * or on ANY WebRTC leg — browsers always carry DTMF as telephone-event over RTP regardless
	 * of the configured peer mode, so a mis-set WebRTC peer must not lose browser DTMF. */
	return pvt->dtmf_effective == SOFIA_DTMF_RFC2833
		|| pvt->dtmf_effective == SOFIA_DTMF_AUTO
		|| pvt->is_webrtc;
}

/* Apply AST_RTP_PROPERTY_DTMF from the effective mode (consumed by the native-LOCAL bridge /
 * directmedia DTMF-compat path in res_rtp_gabpbx.c). NULL-safe on pvt->rtp: outbound binds the
 * mode before sofia_rtp_init (rtp_init re-applies), inbound creates rtp before the peer mode is
 * known (call again after the peer bind). Idempotent — ast_rtp_instance_set_prop just stores a bit. */
static void sofia_dtmf_apply_property(struct sofia_pvt *pvt)
{
	if (pvt && pvt->rtp) {
		ast_rtp_instance_set_prop(pvt->rtp, AST_RTP_PROPERTY_DTMF,
			sofia_dtmf_wants_rfc2833(pvt) ? 1 : 0);
	}
}

/* True when the effective mode needs inband DTMF digit detection: INBAND, or AUTO not yet
 * resolved (we keep detecting inband until the SDP answer resolves AUTO to RFC2833). */
static int sofia_dtmf_wants_inband(const struct sofia_pvt *pvt)
{
	return pvt->dtmf_effective == SOFIA_DTMF_INBAND
		|| pvt->dtmf_effective == SOFIA_DTMF_AUTO;
}

/* g2 — authoritative DTMF re-apply from the effective mode: RTP property + engine dtmf mode +
 * the shared audio DSP (digit-detect AND fax-CNG live in ONE ast_dsp instance). Recomputes the
 * full feature set so an AUTO->RFC2833 resolution drops digit-detect WITHOUT losing fax-CNG.
 *
 * Thread-safety: sofia_read() calls ast_dsp_process(pvt->dsp) on the channel thread holding NO
 * pvt->lock. ast_dsp_set_features is a plain int store (main/dsp.c) — safe against a concurrent
 * reader — but ast_dsp_free is a UAF. So reconfigure NEVER frees the DSP while a channel owner
 * exists (a re-INVITE re-negotiation): it neutralises (features 0) instead and leaves the free to
 * sofia_pvt_destructor. A clean free is only taken before the channel exists (call setup). A newly
 * allocated DSP is fully configured BEFORE its pointer is published, so a reader never sees a
 * half-set-up instance. Idempotent. */
void sofia_dtmf_reconfigure(struct sofia_pvt *pvt)
{
	int mode_inband;
	int want_digit;
	int fax_cng;
	int features;

	if (!pvt || !pvt->rtp) {
		return;
	}

	ast_rtp_instance_set_prop(pvt->rtp, AST_RTP_PROPERTY_DTMF,
		sofia_dtmf_wants_rfc2833(pvt) ? 1 : 0);
	/* Engine dtmf mode tracks the NEGOTIATED mode; the AST_OPTION_DIGIT_DETECT override only
	 * gates the DSP digit-detect FEATURE (g4), not how the RTP engine reads/writes DTMF. */
	mode_inband = sofia_dtmf_wants_inband(pvt);
	want_digit = mode_inband && !pvt->dtmf_detect_off;
	ast_rtp_instance_dtmf_mode_set(pvt->rtp,
		mode_inband ? AST_RTP_DTMF_MODE_INBAND : AST_RTP_DTMF_MODE_RFC2833);

	fax_cng = (pvt->peer && (pvt->peer->faxdetect_mode & SOFIA_FAX_DETECT_CNG)) ? 1 : 0;
	features = (want_digit ? DSP_FEATURE_DIGIT_DETECT : 0)
		| (fax_cng ? DSP_FEATURE_FAX_DETECT : 0);

	if (pvt->dsp) {
		if (!features && !pvt->owner) {
			sofia_disable_dsp_detect(pvt);	/* no reader yet — a clean free is safe at setup */
			return;
		}
		ast_dsp_set_features(pvt->dsp, features);	/* in-place; never free under a live sofia_read */
		if (want_digit) {
			ast_dsp_set_digitmode(pvt->dsp, DSP_DIGITMODE_DTMF |
				(sofia_cfg.relaxdtmf ? DSP_DIGITMODE_RELAXDTMF : 0));
		}
		return;
	}

	if (features) {
		struct ast_dsp *d = ast_dsp_new();
		if (!d) {
			return;
		}
		ast_dsp_set_features(d, features);
		if (want_digit) {
			ast_dsp_set_digitmode(d, DSP_DIGITMODE_DTMF |
				(sofia_cfg.relaxdtmf ? DSP_DIGITMODE_RELAXDTMF : 0));
		}
		pvt->dsp = d;	/* publish last: an atomic pointer store, fully configured */
	}
}

/* Fully release a (WebRTC) RTP instance and NULL the caller's pointer. ast_rtp_instance_destroy() is only
 * an ao2_ref(instance,-1); on a WebRTC leg the RTCP scheduler (res_rtp_gabpbx.c:~2810) and the DTLS
 * retransmit timer (res_rtp_gabpbx.c:~675) each hold their OWN +1 ref, so a bare destroy drops only the
 * pvt's ref — the engine destructor never runs and the UDP socket stays open (fd/socket leak → later calls
 * degrade). Stop RTCP first (ast_rtp_instance_stop releases its ref) and the DTLS timer (dtls->stop →
 * dtls_srtp_stop_timeout_timer releases its ref), THEN destroy. pjsip/chan_sip parity (stop before destroy). */
void sofia_rtp_stop_destroy(struct ast_rtp_instance **inst)
{
	struct ast_rtp_instance *i = inst ? *inst : NULL;
	struct ast_rtp_engine_dtls *dtls;

	if (!i) {
		return;
	}
	ast_rtp_instance_stop(i);		/* releases the RTCP/RED sched ao2 ref */
	if ((dtls = ast_rtp_instance_get_dtls(i))) {
		dtls->stop(i);			/* stops the DTLS retransmit timer + releases its ao2 ref */
	}
	ast_rtp_instance_destroy(i);		/* final ao2_ref(-1) → engine destructor closes the socket */
	*inst = NULL;
}

static int sofia_rtp_init(struct sofia_pvt *pvt)
{
	struct ast_sockaddr addr;

	if (pvt->rtp) {
		return 0;
	}

	ast_sockaddr_parse(&addr, sofia_cfg.bindaddr, 0);
	/* Crash fix: ALWAYS give the RTP instance the module-global sofia_sched context when
	 * it exists — NOT gated on pvt->peer->webrtc. Inbound INVITEs create the RTP instance BEFORE the peer
	 * is resolved (sofia_rtp_init precedes the pvt->peer assignment), so a peer->webrtc gate here is
	 * racy/false for real inbound calls and would leave a WebRTC leg with rtp->sched==NULL, segfaulting
	 * the DTLS retransmit timer (ast_sched_add_variable(NULL)). The sched is only a stored pointer for a
	 * plain call: non-WebRTC never arms a DTLS timer, and audio RTCP/RED only schedule when rtp->rtcp /
	 * rtp->red are non-NULL (which chan_sofia never enables for plain audio) — zero load, zero regression.
	 * set_configuration is the instance-level fail-closed proof (returns -1 on a NULL sched). */
	if (sofia_sched) {
		pvt->rtp = ast_rtp_instance_new("gabpbx",
			ast_sched_thread_get_context(sofia_sched), &addr, NULL);
	} else {
		pvt->rtp = ast_rtp_instance_new("gabpbx", NULL, &addr, NULL);
	}
	if (!pvt->rtp) {
		ast_log(LOG_ERROR, "Failed to create RTP instance for Sofia\n");
		return -1;
	}

	ast_rtp_instance_set_prop(pvt->rtp, AST_RTP_PROPERTY_NAT, 1);
	ast_rtp_instance_dtmf_mode_set(pvt->rtp, AST_RTP_DTMF_MODE_RFC2833);
	/* g3: advertise DTMF-property from the effective mode (outbound already bound dtmfmode;
	 * inbound is still default RFC2833 here and re-applies after the peer bind). */
	sofia_dtmf_apply_property(pvt);

	if (!pvt->vrtp && (pvt->capability & AST_FORMAT_VIDEO_MASK)
	    && !((pvt->is_webrtc || pvt->webrtc_offerer) && pvt->peer && pvt->peer->webrtc_video_bundle)) {	/* BUNDLE: a WebRTC/offerer leg with the knob rides video on pvt->rtp — no 2nd socket. The inbound answerer (is_webrtc==0 here, pre-parse) still creates it and it is dropped at the parse-commit. Knob off => byte-identical. */
		/* Same sched provisioning as the audio instance (crash fix) — a future WebRTC video leg needs it. */
		pvt->vrtp = ast_rtp_instance_new("gabpbx",
			sofia_sched ? ast_sched_thread_get_context(sofia_sched) : NULL, &addr, NULL);
		if (pvt->vrtp) {
			ast_rtp_instance_set_prop(pvt->vrtp, AST_RTP_PROPERTY_RTCP, 1);
		}
	}

	/* tos/cos [general] parity: chan_sip parity at
	 * chan_sip.c:5888 verbatim — apply audio QoS markings (TOS/DSCP at L3 +
	 * 802.1p CoS at L2) to RTP audio instance via gabpbx-core API
	 * ast_rtp_instance_set_qos (rtp_engine.h:1311). Same for video on pvt->vrtp.
	 * tos/cos values are unsigned int; ast_rtp_instance_set_qos signature accepts
	 * int — cast for API conformance. tos_audio/tos_video are applied on reload. */
	if (sofia_cfg.tos_audio || sofia_cfg.cos_audio) {
		ast_rtp_instance_set_qos(pvt->rtp, (int)sofia_cfg.tos_audio,
			(int)sofia_cfg.cos_audio, "Sofia RTP audio");
	}
	if (pvt->vrtp && (sofia_cfg.tos_video || sofia_cfg.cos_video)) {
		ast_rtp_instance_set_qos(pvt->vrtp, (int)sofia_cfg.tos_video,
			(int)sofia_cfg.cos_video, "Sofia RTP video");
	}

	/* rtp-timeout per-peer parity: chan_sip parity at
	 * chan_sip.c:5862-5864 + L5880-5882 verbatim — apply per-peer RTP timeouts +
	 * keepalive via gabpbx-core APIs (rtp_engine.h:1671/1689/1707). Each non-zero
	 * value enables the respective behavior on the RTP instance: rtptimeout drops
	 * stream after N seconds with no inbound RTP; rtpholdtimeout same but for
	 * on-hold state; rtpkeepalive sends periodic keepalive packets.
	 * rtptimeout/rtpholdtimeout are applied on reload. */
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

/* Bounded SDP-fragment appender: append src to dst only if it fully fits (room
 * for the NUL), else return -1. Callers OR the result into an `overflow` flag. */


/* Parse one inbound a=crypto. Returns 1 on accept (srtp staged), 0 on
 * reject/unsupported. Lazy-allocates *srtp on first valid line; on failure rolls
 * back only a context THIS call created (see was_new). sofia-sip strips the
 * "crypto:" prefix the sdp_crypto.c parser expects, so re-prefix it. */

/* On ANY sofia_parse_sdp reject: drop staged-but-uncommitted crypto and roll back
 * an SRTP context THIS parse created, so a rejected re-INVITE leaves live media
 * unchanged. audio_was_new/video_was_new = the context didn't exist before. */


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

	/* fd-5 attach for UDPTL: wire here if udptl pre-exists, else the
	 * sofia_parse_sdp lazy-create site sets owner->fds[5]. */
	if (pvt->udptl) {
		chan->fds[5] = ast_udptl_fd(pvt->udptl);
	}

	chan->tech_pvt = pvt;

	if (pvt->peer) {
		/* Outbound (PBX thread) these reads race the reload writer freeing the
		 * peer stringfield pool, so hold peer->lock across the freeable reads
		 * (language/cid_tag/parkinglot); release before the chanvars loop, whose
		 * pbx_builtin_setvar_helper takes the channel lock (channel->peer order). */
		ast_mutex_lock(&pvt->peer->lock);
		chan->callgroup = pvt->peer->callgroup;
		chan->pickupgroup = pvt->peer->pickupgroup;
		if (!ast_strlen_zero(pvt->peer->language)) {
			ast_string_field_set(chan, language, pvt->peer->language);
		}
		/* cid_tag = Asterisk-internal channel-side tag, NOT a SIP From-tag. */
		if (!ast_strlen_zero(pvt->peer->cid_tag)) {
			chan->caller.id.tag = ast_strdup(pvt->peer->cid_tag);
		}
		if (pvt->peer->amaflags) {
			chan->amaflags = pvt->peer->amaflags;
		}
		if (!ast_strlen_zero(pvt->peer->parkinglot)) {
			ast_string_field_set(chan, parkinglot, pvt->peer->parkinglot);
		}
		ast_mutex_unlock(&pvt->peer->lock);
		/* Apply peer->chanvars: setvar → channel-vars; header entries
		 * (__SIPADDHEADERpre%2d=) → inherited vars emitted as SIPTAG_HEADER_STR. */
		if (pvt->peer->chanvars) {
			/* Deep-copy under peer->lock (reload frees+rebuilds the list), then
			 * apply the copy lock-free (setvar takes the channel lock). */
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

int sofia_dispatch_to_root_thread(void (*callback)(void *), void *data);
static void sofia_nh_destroy_cleanup(void *arg);

static void sofia_pvt_destructor(void *obj)
{
	struct sofia_pvt *pvt = obj;

	/* SIP history: snapshot this completed call into the retained ring (for post-hangup inspection),
	 * then free the live ring. Runs once with no other refs (ao2 destructor), BEFORE the stringfields
	 * (callid/peername) are released below. No-op unless the call was recording. */
	sofia_history_retain(pvt);
	sofia_history_free(pvt);

	/* Safety net: a pending outbound REFER must be failed + its timer freed before the
	 * pvt is released. In practice refer_pending is already 0 here (an armed timer holds
	 * a +1 pvt ref, so the destructor cannot run while a transfer is in flight), but the
	 * hook is idempotent and a no-op when nothing is pending. */
	sofia_transfer_cleanup(pvt);

	sofia_pvt_clear_active_contact(pvt);

	/* Catchall call-counter DEC for orphaned pvts (flag-gated idempotency). Must run
	 * BEFORE the peer ao2_ref drop — the counter helper needs pvt->peer. */
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

	/* hmagic UAF closure for pvt->nh (nh->nh_magic points at pvt). The destructor
	 * runs on any thread and nua_handle_destroy is async, so an in-flight event
	 * could deref a freed pvt; nua_handle_bind(nh, NULL) (synchronous) runs FIRST so
	 * any event in the window reads hmagic == NULL and the gates short-circuit. The
	 * destroy is dispatched to sofia_thread; on dispatch failure we log + leak. */
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

	/* DSP cleanup before pvt->rtp destroy (chan_sip ordering convention). NULL-safe. */
	sofia_disable_dsp_detect(pvt);

	/* WebRTC DataChannel teardown — BEFORE ast_rtp_instance_destroy(pvt->rtp). sofia_dc_detach
	 * clears the engine appdata cb FIRST (instance-lock barrier, anti-UAF), so it MUST
	 * run while pvt->rtp is still live; destroying the rtp first would leave the cb pointing at freed
	 * state. No-op stub without usrsctp; NULL-safe (dc is NULL on a non-DataChannel leg). */
#ifdef HAVE_USRSCTP
	if (pvt->dc) {
		sofia_dc_detach(pvt->dc);
		pvt->dc = NULL;
	}
#endif

	/* stop RTCP + DTLS timer (each holds an ao2 ref) BEFORE destroy, else the engine destructor never
	 * runs and the UDP socket leaks — the root cause of "first call good, later calls degrade". */
	sofia_rtp_stop_destroy(&pvt->rtp);
	sofia_rtp_stop_destroy(&pvt->vrtp);

	if (pvt->srtp) {
		sofia_srtp_destroy(pvt->srtp);
		pvt->srtp = NULL;
	}

	if (pvt->vsrtp) {
		sofia_srtp_destroy(pvt->vsrtp);
		pvt->vsrtp = NULL;
	}

	/* UDPTL teardown (after rtp/srtp, before home unref). t38id sched-cancel: a
	 * successful cancel means the callback never runs, so drop its ref; if it
	 * already ran, t38id is -1 and del is a no-op (race-safe del-or-fire). */
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
	/* Snapshot the global history gate into the dialog (chan_sip parity): a call started with history
	 * on stays recorded even if the operator toggles the global off before this call ends. */
	pvt->do_history = sofia_record_history;
	pvt->state = SOFIA_DIALOG_STATE_DOWN;
	pvt->home = su_home_new(sizeof(*pvt->home));

	/* t38id MUST be the -1 sentinel ("no scheduler entry" — distinct from ID 0). */
	pvt->t38_state = SOFIA_T38_DISABLED;
	pvt->t38id = -1;
	pvt->defer_bye_sched_id = -1;

	/* RFC 3264 answer-direction: -1 sentinel = "no offer staged" (sdp_inactive==0 would
	 * otherwise mean an unset field emits a=inactive). Staged in sofia_parse_sdp. */
	pvt->offered_audio_mode = -1;
	pvt->offered_video_mode = -1;

	/* Default OUR T.38 caps: v0 (RFC 3362; negotiation MIN-clamps), rate 14400,
	 * TRANSFERRED_TCF; max_ifp/datagram left zero (UDPTL supplies defaults). */
	pvt->t38_our_parms.version = 0;
	pvt->t38_our_parms.rate = AST_T38_RATE_14400;
	pvt->t38_our_parms.rate_management = AST_T38_RATE_MANAGEMENT_TRANSFERRED_TCF;

	return pvt;
}

/* Forward declarations (definitions live further down). */
int sofia_dispatch_to_root_thread(void (*callback)(void *), void *data);
static void transmit_mwi_notify_for_peer(struct sofia_peer *peer);
void sofia_format_outboundproxy(struct sofia_peer *peer, char *buf, size_t len);
/* sofia_resolve_ourip mirrors ast_sip_ouraddrfor (kernel routing + externaddr remap). */
static void sofia_resolve_ourip(struct sofia_pvt *pvt, const struct ast_sockaddr *target);
static void sofia_build_from(struct sofia_pvt *pvt, char *buf, size_t len);
/* Non-static: reused by the WebRTC DataChannel relay (sofia_datachannel.c) to resolve the bridged
 * far leg (+1-reffed channel). Declared in chan_sofia_internal.h. */
struct ast_channel *sofia_find_bridged_channel(struct sofia_pvt *op);
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
/* Inbound RPID/PAI/Privacy parsers; all trust-gated on peer->trustrpid. */
static int sofia_check_privacy_id(sip_t const *sip);
static int sofia_get_pai(struct sofia_pvt *pvt, sip_t const *sip);
static int sofia_get_rpid(struct sofia_pvt *pvt, sip_t const *sip);
/* Inbound Diversion parser — walks sip->sip_unknown for "Diversion" by name. */
static int sofia_change_redirecting_info(struct sofia_pvt *pvt, struct ast_channel *owner, sip_t const *sip);

/* MWI re-NOTIFY cross-thread dispatch carrier: mwi_event_cb fires on the event-bus
 * thread, nua_notify must run on sofia_thread. The peer +1 ref is TRANSFERRED
 * (event_cb takes, dispatch carries, callback drops). */
/* fwd: defined later (chan_sofia.c) — referenced by mwi_notify_callback + the register paths above
 * their definitions. */
static void transmit_unsolicited_mwi_for_peer(struct sofia_peer *peer);
static void sofia_register_initial_mwi(struct sofia_peer *peer);

struct mwi_dispatch_data {
	struct sofia_peer *peer;	/* +1 ref TRANSFERRED — callback drops */
	int unsolicited;		/* 0 = solicited re-NOTIFY on the active sub; 1 = unsolicited push */
};

/* Free the carrier; safe on any thread (ao2 unref + ast_free, no nua ops). */
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

/* sofia_thread callback (from mwi_event_cb): re-NOTIFY then free the carrier. */
static void mwi_notify_callback(void *arg)
{
	struct mwi_dispatch_data *d = arg;
	if (!d) {
		return;
	}
	if (d->peer) {
		if (d->unsolicited) {
			transmit_unsolicited_mwi_for_peer(d->peer);
		} else {
			transmit_mwi_notify_for_peer(d->peer);
		}
	}
	mwi_dispatch_data_free(d);
}

/* sofia_thread cleanup: final terminated NOTIFY + destroy nh. Carries ONLY nh (the
 * destructor runs after the peer's last unref). */
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

/* Generic deferred nua_handle_destroy on sofia_thread (peer->nh / qualify_nh; no
 * terminal NOTIFY). The handle MUST already be detached (caller NULLs the field)
 * so no event reaches a freed peer via nh->hmagic. */
static void sofia_nh_destroy_cleanup(void *arg)
{
	nua_handle_t *nh = arg;
	if (!nh) {
		return;
	}
	nua_handle_destroy(nh);
}

/* AST_EVENT_MWI callback (event-bus thread): dispatch a re-NOTIFY to sofia_thread.
 * Quick-exit with no active subscription; TOCTOU safety is in
 * transmit_mwi_notify_for_peer's nh re-check under peer->lock. */
static void mwi_event_cb(const struct ast_event *event, void *userdata)
{
	struct sofia_peer *peer = userdata;
	struct mwi_dispatch_data *d;
	int unsolicited = 0;

	if (!event || !peer) {
		return;
	}

	if (!peer->mwi_subscription_handle) {
		/* No active inbound subscription. Push an UNSOLICITED NOTIFY only when subscribemwi=no AND the
		 * peer is registered (chan_sip parity); the sofia_thread callback re-checks registered under
		 * peer->lock. Otherwise there is nothing to do (solicited-only or no contact). */
		if (peer->subscribemwi != 0 || !peer->registered) {
			if (sofia_debug) {
				ast_debug(2, "Sofia MWI: peer %s event ignored "
					"(no subscriber; unsolicited off or not registered)\n", peer->name);
			}
			return;
		}
		unsolicited = 1;
	}

	d = ast_calloc(1, sizeof(*d));
	if (!d) {
		ast_log(LOG_WARNING, "Sofia MWI: ast_calloc failed for peer %s\n", peer->name);
		return;
	}

	/* TRANSFER ref: take +1 here, dispatch carries, callback drops. */
	ao2_ref(peer, +1);
	d->peer = peer;
	d->unsolicited = unsolicited;

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
void sofia_peer_drain_mwi(struct sofia_peer *peer)
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

/* sofia_thread trampoline (F1a): tear down a removed peer's outbound MWI watcher, then free the heap
 * name. Dispatched from sofia_peer_destructor so the teardown runs on the thread that owns mwisubs. */
static void sofia_subscribe_peer_gone_cb(void *data)
{
	char *name = data;

	sofia_subscribe_on_peer_gone(name);
	sofia_eventsub_on_peer_gone(name);
	ast_free(name);
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
	if (peer->contactha) {
		ast_free_ha(peer->contactha);
		peer->contactha = NULL;
	}
	if (peer->directmediaha) {
		ast_free_ha(peer->directmediaha);
		peer->directmediaha = NULL;
	}
	if (peer->chanvars) {
		ast_variables_destroy(peer->chanvars);
		peer->chanvars = NULL;
	}
	/* Defensive dnsmgr release for orphan paths (a path missed ast_dnsmgr_release). drop_ref=0:
	 * the object is already being reclaimed (refcount 0), so the dnsmgr +1 ref is long gone. */
	sofia_peer_release_dnsmgr(peer, 0);
	/* Unsubscribe (synchronous; waits for in-flight mwi_event_cb) BEFORE ast_free,
	 * closing the race against concurrent event-bus delivery. */
	while ((mb = AST_LIST_REMOVE_HEAD(&peer->mailboxes, list))) {
		if (mb->event_sub) {
			mb->event_sub = ast_event_unsubscribe(mb->event_sub);
		}
		ast_free(mb);
	}

	/* F1a: tear down this peer's OUTBOUND MWI watcher (sofia_subscribe.c) on sofia_thread so it
	 * neither leaks nor blocks a same-named re-create (e.g. after `sip prune realtime`). strdup the
	 * name because the peer is being freed; the trampoline frees it. */
	{
		char *gone_name = ast_strdup(peer->name);

		if (gone_name && sofia_dispatch_to_root_thread(sofia_subscribe_peer_gone_cb, gone_name) < 0) {
			/* Same convention as the inbound-MWI dispatch above: log + accept the deferral. */
			ast_log(LOG_NOTICE, "Sofia MWI-SUBSCRIBE: peer %s destructor — sofia_thread dispatch "
				"failed; watcher teardown deferred to next reload/restart\n", peer->name);
			ast_free(gone_name);
		}
	}

	/* Destroy the MWI subscription on sofia_thread; nua_handle_bind(nh, NULL)
	 * detaches hmagic synchronously first so an event in the freed-peer window reads
	 * NULL (same UAF contract as pvt->nh). */
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
	/* Defensive destroy of peer->nh (REGISTER) + qualify_nh (OPTIONS) for orphan
	 * paths; same sofia_thread + hmagic-detach UAF contract as above. */
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
	/* Destroy peer->lock (inited in sofia_peer_alloc). Safe here: the destructor only runs at
	 * refcount 0, the dnsmgr +1 ref is already dropped (so sofia_on_dns_update_peer cannot be
	 * mid-flight on peer->lock), and the last lock user in this destructor is the defensive
	 * sofia_peer_release_dnsmgr above. */
	ast_mutex_destroy(&peer->lock);
	ast_string_field_free_memory(peer);
}

/* res_dnsmgr callback (res_dnsmgr thread) when peer->host resolves anew: updates
 * peer->src_addr under peer->lock. The peer ref is held until reload-sweep calls
 * ast_dnsmgr_release (waits for in-flight callbacks). */
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
	sofia_peer_ipport_reindex(peer);	/* B: re-key on the freshly resolved address (peer->lock released) */

	ast_verbose("Sofia: dnsmgr — peer '%s' resolved %s -> %s\n",
		peer->name, old_buf, new_buf);

	manager_event(EVENT_FLAG_SYSTEM, "DnsManagerUpdate",
		"Peer: SIP/%s\r\n"
		"OldAddr: %s\r\n"
		"NewAddr: %s\r\n",
		peer->name, old_buf, new_buf);
}

/* Atomically detach + release peer->dnsmgr. Several sites did the check-then-release-then-NULL unlocked:
 * two concurrent releasers (two `sip prune realtime`, or prune vs the reload sweep vs the peer reset)
 * could both observe a non-NULL peer->dnsmgr and double-release the entry + double-drop the dnsmgr +1
 * peer ref (premature destruction). Detach the pointer to a local under peer->lock so only one caller
 * wins it, then release OUTSIDE the lock — ast_dnsmgr_release blocks on the dnsmgr list lock until any
 * in-flight sofia_on_dns_update_peer (which holds peer->lock) returns, so releasing under peer->lock
 * would deadlock. drop_ref = 1 drops the +1 ref the lookup took (all live paths); pass 0 only from the
 * destructor, where the object is already being reclaimed. Callers must NOT hold peer->lock. */
void sofia_peer_release_dnsmgr(struct sofia_peer *peer, int drop_ref)
{
	struct ast_dnsmgr_entry *dnsmgr;

	ast_mutex_lock(&peer->lock);
	dnsmgr = peer->dnsmgr;
	peer->dnsmgr = NULL;
	ast_mutex_unlock(&peer->lock);

	if (dnsmgr) {
		ast_dnsmgr_release(dnsmgr);
		if (drop_ref) {
			ao2_ref(peer, -1);
		}
	}
}

/* Register async DNS lookup at peer-load conclusion (skip IP-literal/empty/dynamic
 * host); invoke AFTER host is finalized. */
static void sofia_dnsmgr_setup_peer(struct sofia_peer *peer)
{
	struct ast_sockaddr probe;

	if (!peer || ast_strlen_zero(peer->host) || !strcasecmp(peer->host, "dynamic")) {
		return;
	}
	if (peer->dnsmgr) {
		return; /* already registered (idempotent for reload paths) */
	}
	/* IP-literal: no DNS, but seed peer->src_addr so IP match + SDP c= work (else
	 * static host=<ip> trunks → 401 + no audio). */
	if (ast_sockaddr_parse(&probe, peer->host, PARSE_PORT_FORBID)) {
		ast_mutex_lock(&peer->lock);		/* the by-IP index snapshots src_addr under peer->lock */
		ast_sockaddr_copy(&peer->src_addr, &probe);
		ast_mutex_unlock(&peer->lock);
		return;
	}
	/* Bump the peer ref for callback-safe access; reload-sweep drops it after
	 * ast_dnsmgr_release. */
	ao2_ref(peer, +1);
	if (ast_dnsmgr_lookup_cb(peer->host, &peer->src_addr, &peer->dnsmgr, NULL,
			sofia_on_dns_update_peer, peer)) {
		ast_log(LOG_WARNING, "Sofia: dnsmgr lookup failed for peer '%s' host='%s'\n",
			peer->name, peer->host);
		ao2_ref(peer, -1);
		return;
	}
	if (!peer->dnsmgr) {
		/* dnsmgr disabled system-wide; release the speculative ref. */
		ao2_ref(peer, -1);
	}
}

/* Config-derived defaults applied to a fresh peer AND re-applied on reload, so a
 * removed per-peer key reverts to its [general] default instead of sticking stale.
 * Excludes runtime/structural anchors (handled by the caller). Called under
 * peer->lock; the contact_ha dup takes the LEAF sofia_contactha_lock (no inversion). */
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
	peer->nat = sofia_cfg.default_nat;	/* inherit [general] nat (chan_sip parity); per-peer nat= overrides after */
	peer->busy_on_active = sofia_cfg.busy_on_active;
	peer->max_contacts = sofia_cfg.max_contacts ? sofia_cfg.max_contacts : 6;
	peer->encryption = 0;
	peer->webrtc = sofia_cfg.webrtc;	/* inherit [general] webrtc (the ENABLE); per-peer webrtc= overrides. The media profile is chosen by the target transport, not this flag - sofia_offer_effective_webrtc */
	peer->datachannel = sofia_cfg.datachannel;	/* inherit [general] datachannel; per-peer datachannel= overrides */
	peer->webrtc_video_bundle = sofia_cfg.webrtc_video_bundle;	/* inherit [general]; per-peer webrtc_video_bundle= overrides */
	peer->flowclose_emit_unregister = sofia_cfg.flowclose_emit_unregister;	/* RFC 5626 flow-close: inherit [general]; per-peer flowclose_emit_unregister= overrides */
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
	peer->publish = 0;	/* outbound PUBLISH opt-in */
	peer->gruu = 0;		/* GRUU opt-in */
	peer->use_gruu_contact = 1;	/* GRUU: use a learned pub-gruu as the dialog Contact (default yes; gated by gruu) */
	peer->use_service_route = 0;	/* Service-Route (RFC 3608): opt-in (applying it diverts outbound routing) */
	peer->path_support = 0;		/* Path (RFC 3327): opt-in (accepting Path is a trust decision) */
	peer->rel100 = 0;		/* 100rel/PRACK (RFC 3262): reliable non-183 provisionals, opt-in */
	peer->sip_outbound = 0;		/* RFC 5626 SIP Outbound: opt-in (advertise outbound + reg-id) */
	peer->sip_outbound_active = 0;	/* runtime: set from the REGISTER 2xx Require: outbound */
	peer->flow_timer = 0;		/* runtime: Flow-Timer learned from the REGISTER 2xx */
	peer->buggymwi = 0;
	peer->lockuseragent = 0;
	ast_string_field_set(peer, lockuseragent_prefixes, "");
	peer->usereqphone = sofia_cfg.default_usereqphone;
	peer->maxforwards = sofia_cfg.default_max_forwards;
	ast_string_field_set(peer, disallowed_methods, S_OR(sofia_cfg.disallowed_methods, ""));
	/* Re-inherit the global contact ACL (contact_ha is a freeable global —
	 * serialize against the reload writer). */
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
	/* ""/0 so a removed per-peer key reverts on reload (inherit-at-use-time). */
	ast_string_field_set(peer, forceddiversion, "");
	ast_string_field_set(peer, message_context, "");
	ast_string_field_set(peer, mwi_subscribe, "");
	ast_string_field_set(peer, subscribe_event, "");
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
	sofia_peer_set_defaults(peer);
	/* Runtime/structural anchors NOT defaulted by the helper. */
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

/* Auto-add (onoff=1) / remove (onoff=0) regcontext dialplan extensions on a peer's
 * register/qualify transition. Multi-ext via "&", per-ext @context, name fallback,
 * idempotent. (chan_sip's cleanup_stale_contexts sweep is not mirrored.) */
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
			*context++ = '\0';
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

/* Inbound REGISTER expires bounds (chan_sip parity, RFC 3261 §10.2.8): max_expiry
 * silently caps; min_expiry rejects with 423 + Min-Expires; expires==0 bypasses.
 * Returns 0 = accept (*expires bounded); -1 = reject (423+AMI emitted; caller
 * MUST return). */
static int sofia_check_register_expiry(nua_t *nua, nua_handle_t *nh,
		struct sofia_peer *peer, int *expires)
{
	char min_str[16];

	if (!expires || *expires == 0) {
		return 0;
	}
	if (*expires > sofia_cfg.max_expiry) {
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

/* RFC 3261 §10.3 requested expiry for ONE Contact binding: the per-Contact ;expires= parameter takes
 * PRECEDENCE (it is the most specific); else the caller's `fallback` (the Expires header value, else the
 * local default). A malformed / out-of-range Contact ;expires= is treated as 3600 (RFC 3261 §10.2.1) — NOT 0,
 * which would be an unintended de-register; the value is clamped to INT_MAX before the min/max clamp + 423. */
static int sofia_contact_requested_expiry(sip_contact_t const *m, int fallback)
{
	if (m && m->m_expires) {
		char *end = NULL;
		long v;
		errno = 0;
		v = strtol(m->m_expires, &end, 10);
		if (end == m->m_expires || *end != '\0' || errno == ERANGE || v < 0) {
			return 3600;	/* malformed / out-of-range -> RFC 3261 §10.2.1 one hour (then min/max clamp) */
		}
		return v > INT_MAX ? INT_MAX : (int) v;
	}
	return fallback;
}

/* Append "<uri>;expires=<ttl>, ..." for every current binding of `peer` to *contacts (RFC 3261 §10.3:
 * the 200-OK MUST enumerate the bindings with the GRANTED per-Contact expires). ao2-iterates peer->contacts
 * (thread-safe via the container + per-contact lock; safe with or without peer->lock held). Reused by the
 * REGISTER query response and the register 200-OK so each Contact shows its granted TTL. */
static void sofia_append_reg_contacts(struct sofia_peer *peer, struct ast_str **contacts)
{
	struct ao2_iterator ci;
	struct sofia_contact *c;
	time_t now = time(NULL);
	if (!*contacts || !peer->contacts) {
		return;
	}
	ci = ao2_iterator_init(peer->contacts, 0);
	while ((c = ao2_iterator_next(&ci))) {
		char uri[256];
		long ttl;
		ao2_lock(c);	/* expires refreshed concurrently — read under the contact lock */
		ast_copy_string(uri, c->contact_uri, sizeof(uri));
		ttl = (long)(c->expires - now);
		ao2_unlock(c);
		if (ttl < 0) {
			ttl = 0;
		}
		ast_str_append(contacts, 0, "%s<%s>;expires=%ld",
			ast_str_strlen(*contacts) ? ", " : "", uri, ttl);
		ao2_ref(c, -1);
	}
	ao2_iterator_destroy(&ci);
}

/* Remove the per-token PRIORITY_HINT extensions for a regexten spec ("ext1[@ctx]&ext2[@ctx]...").
 * Splits exactly like sofia_create_peer_hint (default context = subscribecontext, per-token @context
 * override) so MULTI-token hints are fully reclaimed (a verbatim remove of "a&b" would orphan the
 * per-token hints). registrar must match the creator ("sofia_config_peer" static / "realtime_peer"
 * realtime). Exported for the realtime CLI prune path (sofia_cli.c). Does NOT create contexts. */
void sofia_remove_peer_hints(const char *regexten, const char *subscribecontext, const char *registrar)
{
	char multi[256];
	char *stringp, *ext, *ctx;

	if (ast_strlen_zero(regexten) || ast_strlen_zero(subscribecontext)) {
		return;
	}
	ast_copy_string(multi, regexten, sizeof(multi));
	stringp = multi;
	while ((ext = strsep(&stringp, "&"))) {
		const char *ctxname = subscribecontext;

		if (ast_strlen_zero(ext)) {
			continue;
		}
		if ((ctx = strchr(ext, '@'))) {
			*ctx++ = '\0';
			if (ast_strlen_zero(ext) || ast_strlen_zero(ctx)) {
				continue;
			}
			ctxname = ctx;
		}
		ast_context_remove_extension(ctxname, ext, PRIORITY_HINT, registrar);
	}
}

/* Parse an insecure= value into SOFIA_INSECURE_* flags — chan_sip set_insecure_flags parity
 * (channels/chan_sip.c:28047): comma-separated, ORDER-INDEPENDENT + case-insensitive, with a
 * per-token whitespace trim so "port,invite", "invite,port", "port, invite" and "very" all parse.
 * "no"/false/"" → 0. Replaces the old exact-string match that silently yielded insecure=0 for any
 * non-canonical ordering/spacing (losing the insecure=invite auth bypass + insecure=port IP match). */
static int sofia_parse_insecure(const char *value)
{
	char buf[64];
	char *word, *next;
	int flags = 0;

	if (ast_strlen_zero(value) || ast_false(value)) {
		return 0;
	}
	ast_copy_string(buf, value, sizeof(buf));
	next = buf;
	while ((word = strsep(&next, ","))) {
		word = ast_strip(word);
		if (!strcasecmp(word, "port")) {
			flags |= SOFIA_INSECURE_PORT;
		} else if (!strcasecmp(word, "invite")) {
			flags |= SOFIA_INSECURE_INVITE;
		} else if (!strcasecmp(word, "very")) {
			flags |= SOFIA_INSECURE_PORT | SOFIA_INSECURE_INVITE;	/* legacy "very" alias */
		} else if (!ast_strlen_zero(word)) {
			ast_log(LOG_WARNING, "Sofia: unknown insecure mode '%s'\n", word);
		}
	}
	return flags;
}

/* Parse sendrpid= into chan_sofia's int model (0=none / 1=PAI / 2=RPID, consumed by sofia_add_rpid).
 * chan_sip parity (chan_sip.c:28125-28133): "pai"→PAI, "rpid"→RPID, any ast_true alias→RPID, else off. */
static int sofia_parse_sendrpid(const char *value)
{
	char buf[24];
	char *t;

	if (ast_strlen_zero(value)) {
		return 0;
	}
	ast_copy_string(buf, value, sizeof(buf));
	t = ast_strip(buf);	/* trim BEFORE compare so " pai " / " yes " (padded realtime/config) are honored */
	if (!strcasecmp(t, "pai")) {
		return 1;
	}
	if (!strcasecmp(t, "rpid")) {
		return 2;
	}
	if (ast_true(t)) {
		return 2;	/* yes/true/on/1/y/t → Remote-Party-ID (chan_sip ast_true→RPID) */
	}
	return 0;
}

/* Parse directmedia= (and the canreinvite alias) into chan_sofia's plain enable int. chan_sip parity
 * (chan_sip.c:28177-28201): ast_true→enable, ast_false→disable, else the keyword tokens
 * update/nonat/outgoing each ENABLE direct media. chan_sofia has no nonat/outgoing/update sub-mode
 * (directmedia is a plain enable gate, chan_sofia.c sofia_get_rtp_peer), so all three keywords map to
 * enable=1 — do NOT invent sub-flags; unknown tokens warn. */
static int sofia_parse_directmedia(const char *value)
{
	char buf[64];
	char *word, *next, *val;
	int enabled = 0;

	if (ast_strlen_zero(value)) {
		return 0;
	}
	ast_copy_string(buf, value, sizeof(buf));
	val = ast_strip(buf);	/* trim BEFORE ast_true/ast_false so " yes " / " no " are honored */
	if (ast_true(val)) {
		return 1;
	}
	if (ast_false(val)) {
		return 0;
	}
	next = val;
	while ((word = strsep(&next, ","))) {
		word = ast_strip(word);
		if (!strcasecmp(word, "update") || !strcasecmp(word, "nonat")
				|| !strcasecmp(word, "outgoing")) {
			enabled = 1;
		} else if (!ast_strlen_zero(word)) {
			ast_log(LOG_WARNING, "Sofia: unknown directmedia mode '%s'\n", word);
		}
	}
	return enabled;
}

/* Parse nat= into chan_sofia's SOFIA_NAT_* bitmask. chan_sip parity (chan_sip.c:28163-28176): default
 * force_rport; "no"/false→0; "yes"→force_rport+comedia; "comedia"→comedia. Adapted + immune:
 * comma-tokenized (force_rport/rport/comedia in ANY order, whitespace-trimmed) per chan_sofia's
 * documented "nat=force_rport,comedia"; an unrecognized value defaults to FORCE_RPORT (chan_sip's
 * safety posture — never silently 0/no-NAT on a typo). */
static int sofia_parse_nat(const char *value)
{
	char buf[64];
	char *word, *next, *val;
	int flags = 0, seen = 0;

	if (ast_strlen_zero(value)) {
		return SOFIA_NAT_FORCE_RPORT;	/* unset → chan_sip default */
	}
	ast_copy_string(buf, value, sizeof(buf));
	val = ast_strip(buf);	/* trim BEFORE ast_false/"yes" so " no " / " yes " are honored */
	if (ast_false(val)) {
		return 0;	/* "no"/false → no NAT */
	}
	if (!strcasecmp(val, "yes")) {
		return SOFIA_NAT_FORCE_RPORT | SOFIA_NAT_COMEDIA;
	}
	next = val;
	while ((word = strsep(&next, ","))) {
		word = ast_strip(word);
		if (!strcasecmp(word, "force_rport") || !strcasecmp(word, "rport")) {
			flags |= SOFIA_NAT_FORCE_RPORT;
			seen = 1;
		} else if (!strcasecmp(word, "comedia")) {
			flags |= SOFIA_NAT_COMEDIA;
			seen = 1;
		} else if (!ast_strlen_zero(word)) {
			ast_log(LOG_WARNING, "Sofia: unknown nat mode '%s'\n", word);
		}
	}
	return seen ? flags : SOFIA_NAT_FORCE_RPORT;	/* typo/unknown → force_rport, not 0 */
}

/* Parse transport= into a single SOFIA_TRANSPORT_* (the peer's outbound default = first listed token,
 * chan_sip parity chan_sip.c:28720+). Immune: whitespace-trimmed (ast_strip) so "transport= tls" /
 * "tls , udp" no longer silently downgrade to UDP. Exact match after trim (chan_sofia supports ws/wss;
 * reject garbage prefixes). Unknown/"udp" → UDP. Shared by peer transport= and publish_transport=. */
static int sofia_parse_transport(const char *value)
{
	char buf[24];
	char *first, *comma, *t;

	if (ast_strlen_zero(value)) {
		return SOFIA_TRANSPORT_UDP;
	}
	ast_copy_string(buf, value, sizeof(buf));
	first = buf;
	if ((comma = strchr(first, ','))) {
		*comma = '\0';	/* first listed transport = the outbound default */
	}
	t = ast_strip(first);
	if (!strcasecmp(t, "tls")) {
		return SOFIA_TRANSPORT_TLS;
	}
	if (!strcasecmp(t, "tcp")) {
		return SOFIA_TRANSPORT_TCP;
	}
	if (!strcasecmp(t, "ws")) {
		return SOFIA_TRANSPORT_WS;
	}
	if (!strcasecmp(t, "wss")) {
		return SOFIA_TRANSPORT_WSS;
	}
	return SOFIA_TRANSPORT_UDP;	/* "udp" + unknown → UDP */
}

/* Parse dtmfmode= into SOFIA_DTMF_*. chan_sip parity (chan_sip.c:28146-28162): rfc2833/inband/info/
 * shortinfo/auto (case-insensitive); an unknown value warns and falls back to rfc2833 (not a silent
 * no-op). Whitespace-trimmed for immunity. */
static int sofia_parse_dtmfmode(const char *value)
{
	char buf[24];
	char *t;

	if (ast_strlen_zero(value)) {
		return SOFIA_DTMF_RFC2833;
	}
	ast_copy_string(buf, value, sizeof(buf));
	t = ast_strip(buf);
	if (!strcasecmp(t, "rfc2833")) {
		return SOFIA_DTMF_RFC2833;
	}
	if (!strcasecmp(t, "inband")) {
		return SOFIA_DTMF_INBAND;
	}
	if (!strcasecmp(t, "info")) {
		return SOFIA_DTMF_INFO;
	}
	if (!strcasecmp(t, "shortinfo")) {
		return SOFIA_DTMF_SHORTINFO;
	}
	if (!strcasecmp(t, "auto")) {
		return SOFIA_DTMF_AUTO;
	}
	ast_log(LOG_WARNING, "Sofia: unknown dtmf mode '%s', using rfc2833\n", value);
	return SOFIA_DTMF_RFC2833;
}

/* Parse callingpres= into an AST presentation int. chan_sip parity (chan_sip.c:28891-28894): a named
 * value via ast_parse_caller_presentation, else a raw numeric (atoi) fallback. Whitespace-trimmed for
 * immunity (" prohib " must not fail the lookup and silently fall to atoi=0 = allowed). */
static int sofia_parse_callingpres(const char *value)
{
	char buf[64];
	char *t;
	int p;

	if (ast_strlen_zero(value)) {
		return AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED;
	}
	ast_copy_string(buf, value, sizeof(buf));
	t = ast_strip(buf);
	p = ast_parse_caller_presentation(t);
	return (p < 0) ? atoi(t) : p;	/* numeric fallback, chan_sip parity */
}

/* Install a PRIORITY_HINT extension per regexten token (ext1[@ctx]&ext2[@ctx]...) tracking peer
 * presence via DEVICE_STATE("SIP/<name>"). Splits on '&' with optional per-token @context (default
 * subscribecontext) — same grammar as the regcontext routing + outbound PUBLISH, so BLF, REGISTER
 * routing and PUBLISH agree on the token set. source only picks the registrar string. Removal is the
 * symmetric sofia_remove_peer_hints() (called from reload/sweep/realtime-prune). */
static void sofia_create_peer_hint(struct sofia_peer *peer, const char *source)
{
	char multi[256];
	char *stringp, *ext, *ctx;
	char hintsip[AST_MAX_EXTENSION + 5];
	const char *registrar;

	if (!peer || ast_strlen_zero(peer->subscribecontext) || ast_strlen_zero(peer->regexten)) {
		return; /* both fields required */
	}
	snprintf(hintsip, sizeof(hintsip), "SIP/%s", peer->name);
	registrar = (source && !strcmp(source, "realtime")) ? "realtime_peer" : "sofia_config_peer";

	ast_copy_string(multi, peer->regexten, sizeof(multi));
	stringp = multi;
	while ((ext = strsep(&stringp, "&"))) {
		const char *ctxname = peer->subscribecontext;
		struct ast_context *hintcontext;

		if (ast_strlen_zero(ext)) {
			continue;
		}
		if ((ctx = strchr(ext, '@'))) {
			*ctx++ = '\0';
			if (ast_strlen_zero(ext) || ast_strlen_zero(ctx)) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' regexten token has an empty exten/context — skipped\n",
					peer->name);
				continue;
			}
			ctxname = ctx;
		}
		hintcontext = ast_context_find_or_create(NULL, NULL, ctxname, "chan_sofia");
		if (!hintcontext) {
			ast_log(LOG_WARNING, "Sofia: failed to find_or_create hint context '%s' for peer '%s'\n",
				ctxname, peer->name);
			continue;
		}
		ast_add_extension2(hintcontext, 0, ext, PRIORITY_HINT, NULL, NULL,
			hintsip, NULL, NULL, registrar);
		manager_event(EVENT_FLAG_SYSTEM, "HintCreated",
			"Peer: SIP/%s\r\n"
			"Extension: %s\r\n"
			"Context: %s\r\n"
			"HintDevice: %s\r\n"
			"Source: %s\r\n",
			peer->name, ext, ctxname, hintsip,
			source ? source : "unknown");
	}
}

/* Parse one ast_variable chain into peer fields. overlay=1 (sipregs pass) skips the
 * append-style list columns (ACLs/setvar/header/mailbox) to avoid duplication. */
static void sofia_apply_peer_variables(struct sofia_peer *peer, struct ast_variable *v, int overlay)
{
	/* Unique __SIPADDHEADERpre%2d= var name per header= entry. */
	int headercount = 0;
	/* C (NAT realtime parity): capture the registration source (sipregs ipaddr/port) to restore
	 * peer->src_addr after the loop, so outbound INVITEs to a NAT'd peer route to the public source
	 * right after a realtime reload (before the peer re-REGISTERs). */
	char reg_ipaddr[64] = "";
	int reg_port = 0;
	for (; v; v = v->next) {
		if (!strcasecmp(v->name, "encryption") && ast_strlen_zero(v->value)) {
			peer->encryption = 0;
			continue;
		}
		if (ast_strlen_zero(v->value)) continue;
		/* Overlay pass: skip append-style columns (ACLs/setvar/header/mailbox) —
		 * re-running would duplicate the sippeers entries (and double-sub MWI).
		 * Skip (not reset) preserves the sippeers lists when sipregs omits them. */
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
			/* Warn when both secret= and md5secret= are set (md5secret wins). */
			if (!ast_strlen_zero(peer->md5secret) && !ast_strlen_zero(v->value)) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' has BOTH secret= and "
					"md5secret= set — md5secret takes precedence (chan_sip.c"
					":15415-16 parity); recommend operator unset secret= to "
					"remove ambiguity\n", peer->name);
			}
		} else if (!strcasecmp(v->name, "md5secret")) {
			/* Pre-hashed MD5(user:realm:secret): used directly as a1_hash, takes
			 * PRECEDENCE over peer->secret. */
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
			/* Per-trunk redirecting DID forced into the outbound Diversion header. */
			ast_string_field_set(peer, forceddiversion, v->value);
		} else if (!strcasecmp(v->name, "message_context")) {
			/* Per-peer override for inbound out-of-dialog MESSAGE dialplan dispatch. */
			ast_string_field_set(peer, message_context, v->value);
		} else if (!strcasecmp(v->name, "mwi_subscribe")) {
			/* Outbound MWI watcher: <localmailbox>[@context]. SUBSCRIBE this trunk for
			 * Event: message-summary and inject the result into the local MWI cache. */
			ast_string_field_set(peer, mwi_subscribe, v->value);
		} else if (!strcasecmp(v->name, "subscribe_event")) {
			/* Generic outbound SUBSCRIBE (RFC 6665): <event>[;<accept-mime>][;<expires>]. */
			ast_string_field_set(peer, subscribe_event, v->value);
		} else if (!strcasecmp(v->name, "callerid")) {
			/* Keep the raw string (CLI/AMI display + the realtime callerid helper) AND split it into
			 * cid_num/cid_name (chan_sip.c:28779-28784 parity) — those are the functional fields read
			 * by apply_peer_callerid and sofia_resolve_identity. The duplicate split-only handler later
			 * in this same else-if chain was dead code (this "callerid" always matched here first). */
			char cid_name_buf[80] = "", cid_num_buf[80] = "";
			ast_string_field_set(peer, callerid, v->value);
			ast_callerid_split(v->value, cid_name_buf, sizeof(cid_name_buf), cid_num_buf, sizeof(cid_num_buf));
			ast_string_field_set(peer, cid_name, cid_name_buf);
			ast_string_field_set(peer, cid_num, cid_num_buf);
		} else if (!strcasecmp(v->name, "regexten")) {
			ast_string_field_set(peer, regexten, v->value);
		} else if (!strcasecmp(v->name, "publish_exten")) {
			/* Outbound PUBLISH: explicit exten(s) to publish (overrides regexten/name as the source). */
			ast_string_field_set(peer, publish_exten, v->value);
		} else if (!strcasecmp(v->name, "callbackextension")) {
			ast_string_field_set(peer, callbackextension, v->value);
		} else if (!strcasecmp(v->name, "setvar")) {
			peer->chanvars = sofia_add_var(v->value, peer->chanvars);
		} else if (!strcasecmp(v->name, "header")) {
			/* Encode as an inheritable __SIPADDHEADERpre%2d= var; later emitted by
			 * sofia_build_addheader_str as SIPTAG_HEADER_STR. */
			char tmp[4096];
			snprintf(tmp, sizeof(tmp), "__SIPADDHEADERpre%2d=%s", ++headercount, v->value);
			peer->chanvars = sofia_add_var(tmp, peer->chanvars);
		} else if (!strcasecmp(v->name, "subscribecontext")) {
			ast_string_field_set(peer, subscribecontext, v->value);
		} else if (!strcasecmp(v->name, "accountcode")) {
			ast_string_field_set(peer, accountcode, v->value);
		} else if (!strcasecmp(v->name, "disallowed_methods")) {
			/* parse-compat storage; dynamic NUTAG_ALLOW enforcement deferred. */
			ast_string_field_set(peer, disallowed_methods, v->value);
		} else if (!strcasecmp(v->name, "maxforwards")) {
			/* RFC 3261 §20.22 Max-Forwards: 1-255 bounds, clamp-to-default on invalid. */
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
			reg_port = peer->port;	/* C: in the sipregs overlay this is the registration source port */
		} else if (!strcasecmp(v->name, "ipaddr")) {
			/* C: registration source IP (sipregs column); applied to peer->src_addr after the loop */
			ast_copy_string(reg_ipaddr, v->value, sizeof(reg_ipaddr));
		} else if (!strcasecmp(v->name, "insecure")) {
			peer->insecure = sofia_parse_insecure(v->value);
		} else if (!strcasecmp(v->name, "dtmfmode")) {
			peer->dtmfmode = sofia_parse_dtmfmode(v->value);
		} else if (!strcasecmp(v->name, "qualify")) {
			/* Mirror the config-file parser: a numeric qualify=<ms> must be honored,
			 * not read as OFF by ast_true() (would drop trunk monitoring). */
			if (ast_true(v->value)) {
				peer->qualify = 1;
				peer->qualifyfreq = sofia_cfg.default_qualifyfreq > 0 ?
					sofia_cfg.default_qualifyfreq : DEFAULT_QUALIFYFREQ;
				peer->qualifytimeout = sofia_cfg.default_qualifytimeout > 0 ?
					sofia_cfg.default_qualifytimeout : DEFAULT_QUALIFYTIMEOUT;
			} else if (strcasecmp(v->value, "no")) {	/* numeric: on, timeout=value */
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
			/* canreinvite= = directmedia= alias (legacy-config compat). */
			peer->directmedia = sofia_parse_directmedia(v->value);
		} else if (!strcasecmp(v->name, "busy_on_active")) {
			peer->busy_on_active = ast_true(v->value);
		} else if (!strcasecmp(v->name, "max_contacts")) {
			peer->max_contacts = sofia_clamp_max_contacts(atoi(v->value), peer->name);
		} else if (!strcasecmp(v->name, "encryption")) {
			peer->encryption = ast_true(v->value);
		} else if (!strcasecmp(v->name, "webrtc")) {
			peer->webrtc = ast_true(v->value);	/* WebRTC ENABLE (DTLS-SRTP + ICE-lite + rtcp-mux); the per-contact/static transport picks the actual profile (sofia_offer_effective_webrtc) */
		} else if (!strcasecmp(v->name, "datachannel")) {
			peer->datachannel = ast_true(v->value);	/* accept the WebRTC m=application (RFC 8841 SCTP); requires webrtc=yes + usrsctp */
		} else if (!strcasecmp(v->name, "webrtc_video_bundle")) {
			peer->webrtc_video_bundle = ast_true(v->value);	/* BUNDLE WebRTC video onto the audio transport (RFC 8843); requires webrtc=yes; consumed during BUNDLE video staging */
		} else if (!strcasecmp(v->name, "flowclose_emit_unregister")) {
			peer->flowclose_emit_unregister = ast_true(v->value);	/* RFC 5626 flow-close: yes = emit unregister side-effects on flow close; no (default) = silent removal */
		} else if (!strcasecmp(v->name, "srtpcipher")) {
			/* SRTP suite preference for outbound a=crypto:N (RFC 4568 §6.1); typo
			 * warnings deferred to emit time (a future res_srtp may add the suite). */
			ast_string_field_set(peer, srtpcipher, v->value);
		} else if (!strcasecmp(v->name, "session-timers")) {
			/* RFC 4028: originate/accept/refuse → enum. */
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
			peer->callingpres = sofia_parse_callingpres(v->value);
		} else if (!strcasecmp(v->name, "sendrpid")) {
			/* Outbound RPID/PAI emission: no/pai/rpid/yes (yes→rpid, chan_sip parity). */
			peer->sendrpid = sofia_parse_sendrpid(v->value);
		} else if (!strcasecmp(v->name, "trustrpid")) {
			peer->trustrpid = ast_true(v->value);
		} else if (!strcasecmp(v->name, "callcounter")) {
			/* yes → unlimited (INT_MAX); no → disable. */
			peer->call_limit = ast_true(v->value) ? INT_MAX : 0;
		} else if (!strcasecmp(v->name, "call-limit") || !strcasecmp(v->name, "call_limit")) {
			peer->call_limit = atoi(v->value);
			if (peer->call_limit < 0) peer->call_limit = 0;
		} else if (!strcasecmp(v->name, "busylevel")) {
			/* Soft-cap: outbound returns BUSY (486) when inUse >= busy_level. */
			peer->busy_level = atoi(v->value);
			if (peer->busy_level < 0) peer->busy_level = 0;
		} else if (!strcasecmp(v->name, "mailbox")) {
			/* Comma-separated mbox@ctx list (no @ → context "default"). */
			sofia_peer_parse_mailboxes(peer, v->value);
		} else if (!strcasecmp(v->name, "outboundproxy")) {
			/* Empty = unset; empty + a global default = inherit at use time. */
			ast_string_field_set(peer, outboundproxy, v->value);
		} else if (!strcasecmp(v->name, "mohinterpret")) {
			ast_string_field_set(peer, mohinterpret, v->value);
		} else if (!strcasecmp(v->name, "mohsuggest")) {
			/* inbound direction only; outbound Alert-Info signaling deferred. */
			ast_string_field_set(peer, mohsuggest, v->value);
		} else if (!strcasecmp(v->name, "language")) {
			ast_string_field_set(peer, language, v->value);
		} else if (!strcasecmp(v->name, "parkinglot")) {
			ast_string_field_set(peer, parkinglot, v->value);
		} else if (!strcasecmp(v->name, "defaultip")) {
			/* On resolve-fail, warn + leave defaddr null (chan_sip hard-fails alloc). */
			if (!ast_strlen_zero(v->value) && ast_get_ip(&peer->defaddr, v->value)) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' defaultip='%s' could not be resolved; ignoring\n",
					peer->name, v->value);
				ast_sockaddr_setnull(&peer->defaddr);
			}
		} else if (!strcasecmp(v->name, "maxcallbitrate")) {
			peer->maxcallbitrate = atoi(v->value);
			if (peer->maxcallbitrate < 0) {
				peer->maxcallbitrate = sofia_cfg.default_maxcallbitrate;
			}
		} else if (!strcasecmp(v->name, "amaflags")) {
			/* warn-and-skip on invalid (preserves the channel-core default). */
			int format = ast_cdr_amaflags2int(v->value);
			if (format < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid AMA Flags '%s'; ignoring\n",
					peer->name, v->value);
			} else {
				peer->amaflags = format;
			}
		} else if (!strcasecmp(v->name, "subscribemwi")) {
			/* chan_sip parity: subscribemwi=yes => SUBSCRIBE-only (MWI only on an active
			 * subscription dialog); subscribemwi=no (default) => also PUSH unsolicited MWI NOTIFY to
			 * a registered peer that has a mailbox= but does not subscribe. */
			peer->subscribemwi = ast_true(v->value);
		} else if (!strcasecmp(v->name, "preferred_codec_only")) {
			peer->preferred_codec_only = ast_true(v->value);
		} else if (!strcasecmp(v->name, "ignoresdpversion")) {
			/* Parse-compat only — chan_sofia processes every SDP unconditionally. */
			peer->ignoresdpversion = ast_true(v->value);
		} else if (!strcasecmp(v->name, "promiscredir")) {
			/* Parse-compat only — chan_sofia has no nua_r_redirect handler. */
			peer->promiscredir = ast_true(v->value);
		} else if (!strcasecmp(v->name, "autoframing")) {
			/* Parse-compatibility only — the sofia_parse_sdp ptime gate is not implemented yet. */
			peer->autoframing = ast_true(v->value);
		} else if (!strcasecmp(v->name, "timerb")) {
			/* clamp-to-default on invalid or <200ms. */
			int tmp_b;
			if ((sscanf(v->value, "%30d", &tmp_b) != 1) || tmp_b < 200) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid timerb '%s' (< 200ms or non-integer); using default %d\n",
					peer->name, v->value, sofia_cfg.default_timer_b);
				peer->timer_b = sofia_cfg.default_timer_b;
			} else {
				peer->timer_b = tmp_b;
			}
		} else if (!strcasecmp(v->name, "timert1")) {
			/* invalid or < max(200, t1min) → fall back to t1min (the chan_sip floor,
			 * not default_timer_t1). */
			int tmp_t1;
			if ((sscanf(v->value, "%30d", &tmp_t1) != 1) || tmp_t1 < 200 || tmp_t1 < sofia_cfg.t1min) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid timert1 '%s' (< 200ms or < t1min %d); using t1min floor\n",
					peer->name, v->value, sofia_cfg.t1min);
				peer->timer_t1 = sofia_cfg.t1min;
			} else {
				peer->timer_t1 = tmp_t1;
			}
		} else if (!strcasecmp(v->name, "faxdetect")) {
			/* yes → cng+t38, no → none, or a comma-separated cng/t38 set. */
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
			/* Per-peer T.38 enable + EC mode + MaxDatagram. Comma-separated
			 * yes|no|fec|redundancy|none[,maxdatagram=N]; yes defaults EC to FEC. */
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
			/* symmetric-RTP UDPTL destination override (boolean). */
			peer->t38pt_usertpsource = ast_true(v->value) ? 1 : 0;
		} else if (!strcasecmp(v->name, "allowoverlap")) {
			/* Tri-state: yes → YES; "dtmf" → DTMF; else → NO. */
			if (ast_true(v->value)) {
				peer->allowoverlap_mode = SOFIA_OVERLAP_YES;
			} else if (!strcasecmp(v->value, "dtmf")) {
				peer->allowoverlap_mode = SOFIA_OVERLAP_DTMF;
			} else {
				peer->allowoverlap_mode = SOFIA_OVERLAP_NO;
			}
		} else if (!strcasecmp(v->name, "progressinband")) {
			/* Tri-state: yes → YES; "never" → NEVER; else → NO. */
			if (ast_true(v->value)) {
				peer->progressinband = SOFIA_PROG_INBAND_YES;
			} else if (strcasecmp(v->value, "never")) {
				peer->progressinband = SOFIA_PROG_INBAND_NO;
			} else {
				peer->progressinband = SOFIA_PROG_INBAND_NEVER;
			}
		} else if (!strcasecmp(v->name, "rtptimeout")) {
			/* clamp-to-global on invalid. */
			if ((sscanf(v->value, "%30d", &peer->rtptimeout) != 1) || peer->rtptimeout < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid rtptimeout '%s'; using default\n",
					peer->name, v->value);
				peer->rtptimeout = sofia_cfg.default_rtptimeout;
			}
		} else if (!strcasecmp(v->name, "rtpholdtimeout")) {
			/* clamp-to-global on invalid. */
			if ((sscanf(v->value, "%30d", &peer->rtpholdtimeout) != 1) || peer->rtpholdtimeout < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid rtpholdtimeout '%s'; using default\n",
					peer->name, v->value);
				peer->rtpholdtimeout = sofia_cfg.default_rtpholdtimeout;
			}
		} else if (!strcasecmp(v->name, "rtpkeepalive")) {
			/* clamp-to-global on invalid. */
			if ((sscanf(v->value, "%30d", &peer->rtpkeepalive) != 1) || peer->rtpkeepalive < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid rtpkeepalive '%s'; using default\n",
					peer->name, v->value);
				peer->rtpkeepalive = sofia_cfg.default_rtpkeepalive;
			}
		} else if (!strcasecmp(v->name, "fullname")
				|| !strcasecmp(v->name, "cid_name")) {
			/* cid_name is a chan_sofia alias for fullname. */
			ast_string_field_set(peer, cid_name, v->value);
		} else if (!strcasecmp(v->name, "trunkname")) {
			/* trunkname clears cid_name. */
			ast_string_field_set(peer, cid_name, "");
		} else if (!strcasecmp(v->name, "cid_number")) {
			ast_string_field_set(peer, cid_num, v->value);
		} else if (!strcasecmp(v->name, "cid_tag")) {
			ast_string_field_set(peer, cid_tag, v->value);
		} else if (!strcasecmp(v->name, "callgroup")) {
			peer->callgroup = ast_get_group(v->value);
		} else if (!strcasecmp(v->name, "allowtransfer")) {
			peer->allowtransfer = ast_true(v->value) ? TRANSFER_OPENFORALL : TRANSFER_CLOSED;
		} else if (!strcasecmp(v->name, "allowsubscribe")) {
			/* Gates inbound SUBSCRIBE per-peer. */
			peer->allowsubscribe = ast_true(v->value);
		} else if (!strcasecmp(v->name, "gruu")) {
			/* Advertise a stable +sip.instance on this peer's outbound REGISTER. */
			peer->gruu = ast_true(v->value);
			if (!peer->gruu) {	/* gruu turned off -> drop any learned GRUU (else it lingers hidden) */
				ast_string_field_set(peer, pub_gruu, "");
				ast_string_field_set(peer, temp_gruu, "");
			}
		} else if (!strcasecmp(v->name, "use_gruu_contact")) {
			peer->use_gruu_contact = ast_true(v->value);	/* Interop kill-switch */
		} else if (!strcasecmp(v->name, "service_route")) {
			peer->use_service_route = ast_true(v->value);	/* RFC 3608: pre-load the registrar's Service-Route on outbound INVITEs (opt-in) */
			if (!peer->use_service_route) {	/* knob turned off -> drop any learned route (no stale routing) */
				ast_string_field_set(peer, service_route, "");
			}
		} else if (!strcasecmp(v->name, "path")) {
			peer->path_support = ast_true(v->value);	/* RFC 3327: accept + use the device's Path (opt-in) */
			if (!peer->path_support) {	/* drop stored Paths so a re-enable can't resurrect a stale route */
				sofia_peer_clear_contact_paths(peer);
			}
		} else if (!strcasecmp(v->name, "rel100")) {
			peer->rel100 = ast_true(v->value);	/* RFC 3262: reliable non-183 provisionals (opt-in) */
		} else if (!strcasecmp(v->name, "sip_outbound")) {
			peer->sip_outbound = ast_true(v->value);	/* RFC 5626: advertise outbound + reg-id on REGISTER (opt-in) */
		} else if (!strcasecmp(v->name, "publish")) {
			/* outbound PUBLISH (RFC 3903): opt hint state into central publication. */
			peer->publish = ast_true(v->value);
		} else if (!strcasecmp(v->name, "buggymwi")) {
			/* Cisco buggy-stack workaround: gates the Voice-Message " (0/0)" suffix. */
			peer->buggymwi = ast_true(v->value);
		} else if (!strcasecmp(v->name, "lockuseragent")) {
			peer->lockuseragent = ast_true(v->value);
		} else if (!strcasecmp(v->name, "lockuseragent_prefixes")) {
			/* User-Agent prefix allowlist for sofia_check_lockuseragent; stored
			 * verbatim, tokenized/matched at REGISTER-time. */
			ast_string_field_set(peer, lockuseragent_prefixes, v->value);
		} else if (!strcasecmp(v->name, "usereqphone")) {
			/* RFC 3966 ;user=phone for E.164 via PSTN gateways. */
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
			/* v->name + 7 skips the "contact" prefix. Separate ACL chain from
			 * peer->ha (source-IP). */
			int ha_error = 0;
			if (!ast_strlen_zero(v->value)) {
				peer->contactha = ast_append_ha(v->name + 7, v->value, peer->contactha, &ha_error);
			}
			if (ha_error) {
				ast_log(LOG_ERROR, "Sofia: bad %s line for peer '%s': %s\n",
					v->name, peer->name, v->value);
			}
		} else if (!strcasecmp(v->name, "directmediapermit") || !strcasecmp(v->name, "directmediadeny")) {
			/* v->name + 11 skips the "directmedia" prefix. Applied cross-leg at
			 * sofia_get_rtp_peer. */
			int ha_error = 0;
			peer->directmediaha = ast_append_ha(v->name + 11, v->value, peer->directmediaha, &ha_error);
			if (ha_error) {
				ast_log(LOG_ERROR, "Sofia: bad directmedia %s line for peer '%s': %s\n",
					v->name, peer->name, v->value);
			}
		} else if (!strcasecmp(v->name, "nat")) {
			/* An empty value (e.g. an empty realtime nat column) INHERITS the [general] default
			 * already set at sofia_peer_alloc, rather than forcing force_rport. */
			if (!ast_strlen_zero(v->value))
				peer->nat = sofia_parse_nat(v->value);
		} else if (!strcasecmp(v->name, "expiresecs")) {
			peer->expiresecs = atoi(v->value);
		} else if (!strcasecmp(v->name, "transport")) {
			/* Store the configured transport so OUTBOUND requests to a STATIC peer route over it.
			 * sofia-sip otherwise defaults the RURI to UDP, so transport=tls/tcp/ws/wss to a static
			 * host (e.g. an external TLS (SIPS) trunk) silently went out over UDP.
			 * This sets only the peer's outbound default; INBOUND transport is still governed by the
			 * [general] *bindaddr listeners and the REGISTER Contact scheme (no inbound allowlist implied).
			 * chan_sip parity: a comma-list (e.g. transport=tls,udp) uses the first/preferred token. */
			peer->transport = sofia_parse_transport(v->value);
		} else if (!strcasecmp(v->name, "allow")) {
			ast_parse_allow_disallow(&peer->prefs, &peer->capability, v->value, 1);
		} else if (!strcasecmp(v->name, "disallow")) {
			ast_parse_allow_disallow(&peer->prefs, &peer->capability, v->value, 0);
		}
	}
	if (ast_strlen_zero(peer->host)) ast_string_field_set(peer, host, "dynamic");
	if (ast_strlen_zero(peer->context)) ast_string_field_set(peer, context, sofia_cfg.context);
	if (ast_strlen_zero(peer->defaultuser)) ast_string_field_set(peer, defaultuser, peer->name);
	/* C (NAT realtime parity, mirrors chan_sip restoring peer->addr): if the realtime row carries a
	 * registration source (sipregs ipaddr/port), seed peer->src_addr + mark registered so an outbound
	 * INVITE to a NAT'd peer routes to the PUBLIC source (via NUTAG_PROXY) immediately after a reload,
	 * before the peer re-REGISTERs. Without this, src_addr is NULL after load and routing falls back to
	 * the private Contact (the bug). Only when ipaddr is present (a live registration exists).
	 * NOTE: regseconds-expiry refinement (drop a stale binding) is a tracked follow-up. */
	if (!ast_strlen_zero(reg_ipaddr)) {
		struct ast_sockaddr probe;
		memset(&probe, 0, sizeof(probe));
		if (ast_sockaddr_parse(&probe, reg_ipaddr, 0) && !ast_sockaddr_isnull(&probe)) {
			ast_sockaddr_set_port(&probe, reg_port ? reg_port : 5060);
			ast_sockaddr_copy(&peer->src_addr, &probe);
			peer->registered = 1;
		}
	}
}

/* Build a realtime peer from the DB WITHOUT linking it into the peers container.
 * Runs entirely OUTSIDE ao2_lock(peers): the file's locking invariant (~:104-105)
 * forbids holding a lock across the blocking realtime DB query (ast_load_realtime).
 * The peers container lock is the single global gate for EVERY inbound INVITE/
 * REGISTER/SUBSCRIBE/OPTIONS + devicestate query, so holding it across the DB query
 * lets a slow/hung realtime DB stall ALL peer lookups (remotely amplifiable by
 * flooding lookups for non-cached usernames).
 *
 * PARSE-ONLY (FIX2 rework): this builder performs the realtime DB/sipregs PARSE and
 * nothing else. It takes NO extra refs and registers NO global side effects — no
 * dnsmgr setup (which would take an EXTRA peer ref that pins the refcount and stops
 * the destructor from running, see the reload rule ~:15468-15475), no
 * dynamic_exclude_static append to the global contact_ha, no allowsubscribe flip,
 * no dialplan hint. Those side effects MUST run only AFTER the peer wins ao2_link,
 * in the same link-first order the config path uses (~:14590-14625) — done by the
 * caller sofia_find_peer below. That way a double-build-dedup LOSER or an ao2_link
 * OOM has NOTHING to unwind: a plain ao2_ref(built,-1) takes the refcount to 0 and
 * the destructor fully frees this parse-only build. */
/* prevar != NULL: build from a CALLER-OWNED variable list already loaded by another lookup (the
 * realtime-by-addr path passes its winning by-IP row) — skip the by-name DB query and do NOT free
 * prevar (the caller frees it exactly once). prevar == NULL: load by name + free here, as before.
 * sofia_apply_peer_variables is copy-only, so the source list is safe to free after the build. */
static struct sofia_peer *sofia_find_peer_realtime_build(const char *name, struct ast_variable *prevar)
{
	struct ast_variable *var;
	struct sofia_peer *peer;

	var = prevar ? prevar : ast_load_realtime("sippeers", "name", name, SENTINEL);
	if (!var) return NULL;

	peer = sofia_peer_alloc(name);
	if (!peer) {
		if (!prevar) ast_variables_destroy(var);
		return NULL;
	}

	sofia_apply_peer_variables(peer, var, 0);
	if (!prevar) ast_variables_destroy(var);

	/* sipregs overlay (chan_sip parity): when extconfig wires `sipregs => …`,
	 * registration state lives in sipregs, not sippeers. Sequential dual-load with
	 * overlay=1 so the append-style list columns are skipped (see
	 * sofia_apply_peer_variables); NULL sipregs (not yet registered) just continues. */
	if (ast_check_realtime("sipregs")) {
		struct ast_variable *regvar = ast_load_realtime("sipregs", "name", name, SENTINEL);
		if (regvar) {
			sofia_apply_peer_variables(peer, regvar, 1);
			ast_variables_destroy(regvar);
		}
	}

	peer->is_realtime = 1;

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

/* ===== B: O(1) by-IP+port peer index (peers_by_ipport) =====
 * The NAME-hashed `peers` container makes a by-IP lookup an O(N) scan; with ~10k cached peers that runs
 * on every inbound by-IP INVITE. This index makes the COMMON case (a peer whose source IP+port matches a
 * registered/configured key) O(1); wildcard (insecure=port), connection-oriented and port-drift cases
 * MISS and fall through to the existing ranked O(N) scan in sofia_find_peer_by_ip (so correctness is
 * unchanged). Entries are IMMUTABLE (key in the entry, +1 peer ref); a peer address change is
 * unindex(old)+index(new). HARD invariant: never hold ao2_lock(peers) while touching this index. */
struct sofia_peer_ipport {
	struct ast_sockaddr key;	/* IP+port */
	struct sofia_peer *peer;	/* +1 ref, released by peer_ipport_destructor */
};

/* Serializes reindex/unindex so a REGISTER (sofia_thread) and a dnsmgr callback (res_dnsmgr thread)
 * can't interleave into a duplicate/orphan entry. Held ONLY around the index mutation. */
AST_MUTEX_DEFINE_STATIC(peers_ipport_lock);

static int peer_ipport_hash_fn(const void *obj, int flags)
{
	const struct sofia_peer_ipport *e = obj;
	/* Hash canonical "IP:port" so 10 phones behind ONE NAT IP land in DISTINCT buckets (true O(1)). */
	return ast_str_hash(ast_sockaddr_stringify(&e->key));
}

static int peer_ipport_cmp_fn(void *obj, void *arg, int flags)
{
	const struct sofia_peer_ipport *e = obj, *match = arg;

	if (ast_sockaddr_cmp(&e->key, &match->key)) {	/* full IP+port compare */
		return 0;
	}
	/* A non-NULL match->peer narrows to that peer's own entry (exact removal); NULL matches any. */
	if (match->peer && e->peer != match->peer) {
		return 0;
	}
	return CMP_MATCH | CMP_STOP;
}

static void peer_ipport_destructor(void *obj)
{
	struct sofia_peer_ipport *e = obj;

	if (e->peer) {
		ao2_ref(e->peer, -1);
	}
}

/* Indexable IP+port key for a peer (CALLER HOLDS peer->lock). The by-IP:port fast index is SPECIALIZED:
 * it indexes ONLY trunks identified by their source IP, i.e. peers with a STATIC host (host != dynamic) -
 * an IP literal, or an FQDN whose dnsmgr-resolved address is in src_addr. A registered phone
 * (host=dynamic) is identified by username/digest, NEVER by source IP, so it is NOT indexed here (it is
 * served by the ranked O(N) scan, which the by-name path means phones almost never reach). This keeps the
 * fast index a 1:1 trunk identity map, avoids shared-NAT duplicate keys, and closes the risk of a phone
 * being mis-identified as an insecure=invite trunk. Returns 1 if indexable (concrete IP + non-zero port),
 * else 0 (the peer is served by the O(N) fallback). */
static int sofia_peer_ipport_make_key_locked(struct sofia_peer *peer, struct ast_sockaddr *key)
{
	struct ast_sockaddr parsed;
	int port;

	ast_sockaddr_setnull(key);
	/* host=dynamic (or unset) -> registered phone -> NEVER in the by-IP fast index. */
	if (ast_strlen_zero(peer->host) || !strcasecmp(peer->host, "dynamic")) {
		return 0;
	}
	if (ast_sockaddr_parse(&parsed, peer->host, PARSE_PORT_FORBID)) {
		ast_sockaddr_copy(key, &parsed);		/* host=<IP literal> */
	} else if (!ast_sockaddr_isnull(&peer->src_addr)) {
		ast_sockaddr_copy(key, &peer->src_addr);	/* host=<FQDN> resolved by dnsmgr */
	} else if (!ast_sockaddr_isnull(&peer->defaddr)) {
		ast_sockaddr_copy(key, &peer->defaddr);
	} else {
		return 0;					/* unresolved FQDN trunk -> O(N) fallback */
	}
	port = ast_sockaddr_port(key);
	if (!port) {
		port = peer->port;
		ast_sockaddr_set_port(key, port);
	}
	return port != 0;
}

/* Sync peers_by_ipport with the peer's CURRENT key: drop the old entry (if the key changed or vanished)
 * and add the new one. Idempotent + serialized. Caller must NOT hold ao2_lock(peers) or peer->lock.
 * Call at every stabilization point (post-link, post-REGISTER, post-dnsmgr, post-reload). */
void sofia_peer_ipport_reindex(struct sofia_peer *peer)
{
	struct ast_sockaddr newkey;
	struct sofia_peer_ipport srch;
	int want, was;

	if (!peers_by_ipport || !peer) {
		return;
	}
	ast_mutex_lock(&peers_ipport_lock);
	ast_mutex_lock(&peer->lock);
	want = sofia_peer_ipport_make_key_locked(peer, &newkey);
	was = peer->ipport_indexed;
	if (was && want && !ast_sockaddr_cmp(&peer->ipport_key, &newkey)) {
		ast_mutex_unlock(&peer->lock);			/* unchanged */
		ast_mutex_unlock(&peers_ipport_lock);
		return;
	}
	ast_sockaddr_copy(&srch.key, &peer->ipport_key);	/* OLD key (for removal) */
	srch.peer = peer;
	peer->ipport_indexed = 0;
	if (want) {
		ast_sockaddr_copy(&peer->ipport_key, &newkey);
	} else {
		ast_sockaddr_setnull(&peer->ipport_key);
	}
	ast_mutex_unlock(&peer->lock);

	if (was) {
		ao2_find(peers_by_ipport, &srch, OBJ_POINTER | OBJ_UNLINK | OBJ_NODATA);	/* drop old (+ its peer ref) */
	}
	if (want) {
		/* NEVER store a DUPLICATE key: keep the fast index strictly 1:1 so the O(1) first-match is
		 * always unambiguous (no wrong-trunk identity, no insecure=invite mis-gate). THIS peer's own
		 * old entry was already dropped above (if `was`), so any entry present at newkey now belongs to
		 * a DIFFERENT trunk -> leave this one OUT of the fast index; sofia_find_peer_by_ip serves it via
		 * the ranked O(N) scan. All under peers_ipport_lock, so the probe+link is atomic. */
		struct sofia_peer_ipport probe = { .peer = NULL };
		struct sofia_peer_ipport *dup;
		ast_sockaddr_copy(&probe.key, &newkey);
		dup = ao2_find(peers_by_ipport, &probe, OBJ_POINTER);
		if (dup) {
			ao2_ref(dup, -1);
			ast_mutex_lock(&peer->lock);
			ast_sockaddr_setnull(&peer->ipport_key);	/* not indexed -> clear so reindex retries cleanly */
			peer->ipport_indexed = 0;
			ast_mutex_unlock(&peer->lock);
			ast_log(LOG_NOTICE, "Sofia: '%s' shares IP:port with an already-indexed trunk - left out of "
				"the by-IP fast index (ranked O(N) fallback applies)\n", peer->name);
		} else {
			struct sofia_peer_ipport *e = ao2_alloc(sizeof(*e), peer_ipport_destructor);
			if (e) {
				ast_sockaddr_copy(&e->key, &newkey);
				ao2_ref(peer, +1);
				e->peer = peer;
				if (ao2_link(peers_by_ipport, e)) {
					ast_mutex_lock(&peer->lock);
					peer->ipport_indexed = 1;	/* mark indexed ONLY on a successful link */
					ast_mutex_unlock(&peer->lock);
				} else {
					/* OOM link: leave ipport_indexed = 0 so the NEXT reindex retries (no false indexed
					 * state that the unchanged-key fast-return would then skip forever). */
					ast_log(LOG_WARNING, "Sofia: peers_by_ipport link failed for '%s' — by-IP lookup uses the O(N) scan\n",
						peer->name);
				}
				ao2_ref(e, -1);				/* drop our alloc ref (frees e + the manual peer +1 on link-fail) */
			}
		}
	}
	ast_mutex_unlock(&peers_ipport_lock);
}

/* Remove the peer's index entry (if any). MUST run BEFORE ao2_unlink(peers, peer) / destroy: the entry
 * pins a peer ref, so a missed unindex leaks the peer (its destructor never runs). */
void sofia_peer_ipport_unindex(struct sofia_peer *peer)
{
	struct sofia_peer_ipport srch;

	if (!peers_by_ipport || !peer) {
		return;
	}
	ast_mutex_lock(&peers_ipport_lock);
	ast_mutex_lock(&peer->lock);
	if (!peer->ipport_indexed) {
		ast_mutex_unlock(&peer->lock);
		ast_mutex_unlock(&peers_ipport_lock);
		return;
	}
	ast_sockaddr_copy(&srch.key, &peer->ipport_key);
	srch.peer = peer;
	peer->ipport_indexed = 0;
	ast_sockaddr_setnull(&peer->ipport_key);
	ast_mutex_unlock(&peer->lock);
	ao2_find(peers_by_ipport, &srch, OBJ_POINTER | OBJ_UNLINK | OBJ_NODATA);
	ast_mutex_unlock(&peers_ipport_lock);
}

/* O(1) lookup. The index hands back a candidate; we take a SAFE +1 ref iff the peer is still linked in
 * `peers` (sofia_peer_ref_if_linked) and REVALIDATE its live key still equals `src` under peer->lock —
 * so a stale entry (missed reindex / race) is non-routing and the caller falls back to the O(N) scan.
 * Returns +1-reffed peer or NULL. Caller must NOT hold ao2_lock(peers). */
static struct sofia_peer *sofia_peer_ipport_lookup(const struct ast_sockaddr *src)
{
	struct sofia_peer_ipport srch, *e;
	struct sofia_peer *peer, *live;
	struct ast_sockaddr curkey;
	int ok;

	if (!peers_by_ipport || !src || ast_sockaddr_isnull(src)) {
		return NULL;
	}
	ast_sockaddr_copy(&srch.key, src);
	srch.peer = NULL;					/* any peer at this IP+port */
	e = ao2_find(peers_by_ipport, &srch, OBJ_POINTER);
	if (!e) {
		return NULL;
	}
	peer = e->peer;
	live = sofia_peer_ref_if_linked(peer);			/* +1 iff still in `peers` */
	ao2_ref(e, -1);
	if (!live) {
		return NULL;
	}
	ast_mutex_lock(&live->lock);
	ok = sofia_peer_ipport_make_key_locked(live, &curkey) && !ast_sockaddr_cmp(&curkey, src);
	ast_mutex_unlock(&live->lock);
	if (!ok) {
		ao2_ref(live, -1);				/* stale → O(N) fallback */
		return NULL;
	}
	return live;
}

static struct sofia_peer *sofia_find_peer_impl(const char *name, struct ast_variable *prevar)
{
	struct sofia_peer *found = NULL;
	struct sofia_peer *built = NULL;	/* my fresh unlinked realtime build (NULL on cache hit / no realtime) */
	int built_realtime = 0;	/* set when THIS call linked a NEW realtime peer -> create its hint after unlock */
	struct sofia_peer_key key = { .name = name };

	/* Fast path: cache hit under the peers lock. The container lock is the single
	 * global gate for EVERY inbound INVITE/REGISTER/SUBSCRIBE/OPTIONS + devicestate
	 * query, so it MUST NOT be held across the realtime DB query or the DNS lookup
	 * (file invariant ~:104-105) — a slow/hung DB or resolver would otherwise stall
	 * ALL peer lookups, remotely amplifiable by flooding non-cached usernames. */
	ao2_lock(peers);
	found = ao2_find(peers, &key, OBJ_POINTER);
	ao2_unlock(peers);

	if (found) {
		return found;
	}

	if (!ast_check_realtime("sippeers")) {
		return NULL;
	}

	/* Cache miss: build the realtime peer WITHOUT the container lock (the blocking realtime DB
	 * query happens here, off the global gate). PARSE-ONLY: DNS + the dnsmgr ref + the global
	 * contact_ha rule + allowsubscribe all run POST-LINK below, so a lost-race/OOM build has
	 * nothing to unwind. */
	built = sofia_find_peer_realtime_build(name, prevar);
	if (!built) {
		return NULL;
	}

	/* Re-take the lock ONLY for the brief re-find / link. Concurrent-double-build
	 * race: another thread may have built+linked a same-named peer while we were
	 * unlocked (ao2_link does not refuse duplicates by name, so we dedup here). If
	 * one is now present, DROP our fresh build and use theirs; else link ours. */
	ao2_lock(peers);
	found = ao2_find(peers, &key, OBJ_POINTER);
	if (found) {
		/* Lost the double-build race — discard our fresh build and use theirs. The build
		 * is PARSE-ONLY (no dnsmgr ref, no global ACL/allowsubscribe side effect — those
		 * are deferred until AFTER ao2_link below), so there is NOTHING to unwind: this
		 * single ao2_ref(built,-1) drives the refcount to 0 and the destructor frees it. */
		ao2_unlock(peers);
		sofia_peer_drain_mwi(built);
		ao2_ref(built, -1);
		return found;
	}
	if (!ao2_link(peers, built)) {
		/* OOM on link — nothing published, no side effect registered yet (the dnsmgr ref,
		 * the contact_ha deny rule and allowsubscribe all run only after a SUCCESSFUL link
		 * below). Nothing to unwind: this ao2_ref(built,-1) takes the refcount to 0. */
		ao2_unlock(peers);
		sofia_peer_drain_mwi(built);
		ao2_ref(built, -1);
		return NULL;
	}
	ao2_unlock(peers);

	/* We linked it: 'built' carries the +1 ref we return; the container holds its own
	 * +1 from ao2_link. */
	found = built;
	built_realtime = 1;	/* fresh link: create the hint below, after the peers lock is dropped */
	if (sofia_debug) {
		ast_verbose("Sofia: Peer '%s' found via realtime\n", name);
	}

	/* Side effects run LINK-FIRST (mirrors the config path ~:14590-14625): only after a
	 * successful ao2_link, and only on the fresh-link path (cache hits + double-build
	 * losers never re-run them). Order = hint -> dnsmgr -> dynamic_exclude_static, the
	 * same order the config path uses. The peer is already ao2_link'd and 'found' holds a
	 * +1 ref, so it is alive throughout. Because these are deferred to AFTER the link, a
	 * losing/OOM build above carried NONE of them and was freed by a plain ao2_ref(-1).
	 *
	 * (1) Dialplan hint — ABBA fix (P1, preserved): created OUTSIDE ao2_lock(peers).
	 * sofia_create_peer_hint takes conlock (find_or_create + add_extension); doing it
	 * under the peers lock would invert against the dialplan-merge conlock->peers leg. */
	if (built_realtime) {
		sofia_create_peer_hint(found, "realtime");

		/* (2) DNS for host=<hostname> peers — synchronous, MUST stay outside the peers
		 * lock. Takes an EXTRA peer ref pinned until the reload sweep's ast_dnsmgr_release
		 * (~:15468-15475); registering it only here (post-link) is exactly why a losing
		 * build had nothing to unwind. Idempotent; sets peer->src_addr / peer->dnsmgr. */
		sofia_dnsmgr_setup_peer(found);

		/* (3) dynamic_exclude_static [general] (chan_sip parity): a static-IP realtime
		 * peer appends a deny rule to the GLOBAL contact_ha so later REGISTERs from that
		 * address are rejected. Deferred here so a lost-race build never leaves a stale
		 * global deny rule behind. The append takes only the LEAF sofia_contactha_lock. */
		if (sofia_cfg.dynamic_exclude_static && !ast_strlen_zero(found->host)
				&& strcasecmp(found->host, "dynamic")) {
			struct ast_sockaddr static_addr;
			if (ast_sockaddr_parse(&static_addr, found->host, 0)) {
				int ha_error = 0;
				ast_rwlock_wrlock(&sofia_contactha_lock);
				sofia_cfg.contact_ha = ast_append_ha("deny",
					ast_sockaddr_stringify_addr(&static_addr),
					sofia_cfg.contact_ha, &ha_error);
				ast_rwlock_unlock(&sofia_contactha_lock);
				if (ha_error) {
					ast_log(LOG_ERROR,
						"Sofia: dynamic_exclude_static — bad addr for realtime static peer '%s' (%s)\n",
						found->name, found->host);
				}
			}
		}

		/* (4) allowsubscribe: if this runtime-added realtime peer allows subscribe, flip
		 * the global derived flag (one-way, chan_sip parity). Already-TRUE short-circuits. */
		if (found->allowsubscribe) {
			sofia_cfg.allowsubscribe = 1;
		}
		/* B: index the freshly-linked peer by IP+port (dnsmgr set src_addr above); peers lock already
		 * released. Idempotent. Cache-hit / lost-race paths returned earlier (already indexed). */
		sofia_peer_ipport_reindex(found);
	}

	return found;
}

/* Public realtime peer lookup (cache → by-name realtime build). All external callers
 * (AMI/CLI/INVITE/REGISTER/SUBSCRIBE/MESSAGE) use this; the realtime-by-addr path calls
 * sofia_find_peer_impl directly to build from its already-fetched by-IP row (chan_sip parity). */
struct sofia_peer *sofia_find_peer(const char *name)
{
	return sofia_find_peer_impl(name, NULL);
}

/* Cache-only peer lookup: ao2_find on the in-memory container ONLY, never the realtime DB fallback that
 * sofia_find_peer() takes on a miss. Required where a realtime reload would be WRONG — e.g. the MWI
 * watcher peer-gone guard (sofia_subscribe_on_peer_gone), which must NOT resurrect a peer that
 * `sip prune realtime` just unlinked (that only unlinks the cache; the DB row survives). +1 ref or NULL. */
struct sofia_peer *sofia_find_peer_cached(const char *name)
{
	struct sofia_peer_key key = { .name = name };

	if (ast_strlen_zero(name) || !peers) {
		return NULL;
	}
	return ao2_find(peers, &key, OBJ_POINTER);
}

/* chan_sip parity: IP-based fallback peer match.
 * Used by sofia_process_invite after the From-username lookup fails — typical
 * for trunk gateways whose From-user is the caller-ID number, not the peer
 * name (e.g. a carrier softswitch sending From: <sip:USER@…> while the peer
 * is configured as [mytrunk] host=192.0.2.10). Matches peer->src_addr
 * (set both by dnsmgr for static host=<ip> peers and by REGISTER for dynamic
 * peers) or, if that is unset, peer->defaddr. Ranked, EXACT-FIRST (chan_sip peer_ipcmp_cb
 * spirit, chan_sip.c:31326-31339): an exact IP+port match wins outright; else the highest-ranked IP
 * match - a wildcard (insecure=port, or connection-oriented TCP/TLS/WS/WSS whose source port is the
 * ephemeral connection port) outranks a merely drifted UDP source port. So a same-IP peer whose port
 * matches is never shadowed by an earlier wildcard one (multi-peer-behind-one-NAT), and a lone drifted
 * UDP peer still resolves via the low-rank fallback (backward-compatible). */
static struct sofia_peer *sofia_find_peer_by_ip(const struct ast_sockaddr *src)
{
	struct ao2_iterator i;
	struct sofia_peer *peer, *found = NULL, *best = NULL;
	int best_score = 0;	/* 3=exact IP+port, 2=wildcard (insecure=port/conn-oriented/unknown), 1=IP-only port drift */

	if (!src || ast_sockaddr_isnull(src)) {
		return NULL;
	}

	/* B: O(1) by-IP+port fast path. A hit (revalidated under peer->lock) returns immediately; any miss —
	 * wildcard insecure=port, connection-oriented, port drift, or an unindexed/stale entry — falls
	 * through to the ranked O(N) scan below (unchanged correctness). */
	if ((found = sofia_peer_ipport_lookup(src))) {
		return found;
	}

	i = ao2_iterator_init(peers, 0);
	while ((peer = ao2_iterator_next(&i))) {
		struct ast_sockaddr parsed;
		struct ast_sockaddr snap_src;
		struct ast_sockaddr snap_defaddr;
		char snap_host[MAXHOSTNAMELEN];
		int snap_insecure, snap_port, snap_transport;
		char snap_reg_transport[8];
		const struct ast_sockaddr *candidate = NULL;
		/* src_addr/host/defaddr are rewritten under peer->lock by the dnsmgr callback
		 * (sofia_on_dns_update_peer) off the res_dnsmgr thread and by the reload writer;
		 * snapshot ALL THREE under peer->lock before the compare so this IP-trunk-
		 * identification path (which gates insecure=invite) can't read a torn ast_sockaddr
		 * nor a freed host stringfield mid-update. */
		ast_mutex_lock(&peer->lock);
		snap_src = peer->src_addr;
		snap_defaddr = peer->defaddr;
		ast_copy_string(snap_host, peer->host, sizeof(snap_host));
		snap_insecure = peer->insecure;
		snap_port = peer->port;
		snap_transport = peer->transport;
		ast_copy_string(snap_reg_transport, peer->reg_transport, sizeof(snap_reg_transport));
		ast_mutex_unlock(&peer->lock);
		if (!ast_sockaddr_isnull(&snap_src)) {
			candidate = &snap_src;
		} else if (!ast_strlen_zero(snap_host)
		           && strcasecmp(snap_host, "dynamic")
		           && ast_sockaddr_parse(&parsed, snap_host, PARSE_PORT_FORBID)) {
			/* Static host=<ip-literal> peers never get src_addr populated
			 * (sofia_dnsmgr_setup_peer returns early at its IP-literal pre-check),
			 * so parse it on-the-fly here. */
			candidate = &parsed;
		} else if (!ast_sockaddr_isnull(&snap_defaddr)) {
			candidate = &snap_defaddr;
		}
		if (candidate && !ast_sockaddr_cmp_addr(candidate, src)) {
			/* IP matched. chan_sip peer_ipcmp_cb parity (chan_sip.c:31326-31339):
			 *  - connection-oriented transports (TCP/TLS/WS/WSS): the source port is the ephemeral
			 *    connection port, so match IP-only (chan_sip skips the port test, :31326-31329);
			 *  - insecure=port: IP-only (a trunk that may send from any port);
			 *  - else UDP: require the source PORT to match. Expected port = the candidate's
			 *    learned/registered source port; a static host=<ip> candidate carries none, so fall
			 *    back to the configured peer port; an unknown (0) expected port stays IP-only. */
			int conn_oriented;
			int expected_port = ast_sockaddr_port(candidate);
			if (expected_port == 0) {
				expected_port = snap_port;
			}
			if (candidate == &snap_src) {
				/* registered/learned source → the registration-route transport (paired with src_addr) */
				conn_oriented = !strcasecmp(snap_reg_transport, "tcp")
						|| !strcasecmp(snap_reg_transport, "tls")
						|| !strcasecmp(snap_reg_transport, "ws")
						|| !strcasecmp(snap_reg_transport, "wss");
			} else {
				/* static host=<ip> / defaddr → the configured transport enum */
				conn_oriented = (snap_transport & (SOFIA_TRANSPORT_TCP | SOFIA_TRANSPORT_TLS
						| SOFIA_TRANSPORT_WS | SOFIA_TRANSPORT_WSS)) != 0;
			}
			/* Rank the IP match (exact-FIRST, so a same-IP peer whose port matches wins over a
			 * wildcard one = correct multi-peer-behind-one-NAT disambiguation):
			 *   3 = exact IP+port (the strongest - take it and stop);
			 *   2 = wildcard: insecure=port (any port), connection-oriented (TCP/TLS/WS/WSS, whose
			 *       source port is the ephemeral connection port), or unknown expected port - a strong
			 *       fallback;
			 *   1 = a UDP source port that simply drifted from the registered rport - the weakest
			 *       fallback, kept for backward-compat with the old IP-only behaviour (chan_sip rejects).
			 * Keep the HIGHEST-ranked candidate; an exact (3) wins outright. */
			int score;
			if (expected_port != 0 && expected_port == ast_sockaddr_port(src)) {
				score = 3;
			} else if ((snap_insecure & SOFIA_INSECURE_PORT) || conn_oriented
					|| expected_port == 0) {
				score = 2;
			} else {
				score = 1;
			}
			if (score == 3) {
				found = peer;	/* exact IP+port - wins outright */
				break;
			}
			if (score > best_score) {
				if (best) {
					ao2_ref(best, -1);	/* replace the previous lower-ranked fallback */
				}
				best = peer;	/* hold this peer's +1 ref; skip the drop below */
				best_score = score;
				continue;
			}
		}
		ao2_ref(peer, -1);
	}
	ao2_iterator_destroy(&i);
	if (found) {
		if (best) {
			ao2_ref(best, -1);	/* an exact IP+port match won - release the held fallback */
		}
		return found;
	}
	return best;	/* no exact IP+port - the highest-ranked IP fallback (or NULL) */
}

/* Minimal negative-cache for the realtime-by-IP fallback below: a tiny fixed ring of
 * recently-missed source IPs so an inbound-INVITE flood from unknown IPs cannot hammer
 * the realtime database backend (each distinct source IP is otherwise a fresh DB query).
 * Short TTL so a stale miss self-heals once a peer is added in realtime (no explicit
 * reload-clear in v1). */
#define SOFIA_RTLOOKUP_NEG_SIZE 32
#define SOFIA_RTLOOKUP_NEG_TTL  10   /* seconds a missed source IP stays suppressed */
static struct { char ip[48]; time_t ts; } sofia_rtlookup_neg[SOFIA_RTLOOKUP_NEG_SIZE];
AST_MUTEX_DEFINE_STATIC(sofia_rtlookup_neg_lock);

static int sofia_rtlookup_neg_check(const char *ip)
{
	time_t now = time(NULL);
	int i, hit = 0;
	ast_mutex_lock(&sofia_rtlookup_neg_lock);
	for (i = 0; i < SOFIA_RTLOOKUP_NEG_SIZE; i++) {
		if (sofia_rtlookup_neg[i].ts && (now - sofia_rtlookup_neg[i].ts) < SOFIA_RTLOOKUP_NEG_TTL
				&& !strcmp(sofia_rtlookup_neg[i].ip, ip)) {
			hit = 1;
			break;
		}
	}
	ast_mutex_unlock(&sofia_rtlookup_neg_lock);
	return hit;
}

static void sofia_rtlookup_neg_add(const char *ip)
{
	time_t now = time(NULL), oldest = now + 1;
	int i, slot = 0;
	ast_mutex_lock(&sofia_rtlookup_neg_lock);
	for (i = 0; i < SOFIA_RTLOOKUP_NEG_SIZE; i++) {
		if (!sofia_rtlookup_neg[i].ts || (now - sofia_rtlookup_neg[i].ts) >= SOFIA_RTLOOKUP_NEG_TTL) {
			slot = i;   /* empty/expired slot — reuse it */
			break;
		}
		if (sofia_rtlookup_neg[i].ts < oldest) {
			oldest = sofia_rtlookup_neg[i].ts;
			slot = i;   /* else evict the oldest */
		}
	}
	ast_copy_string(sofia_rtlookup_neg[slot].ip, ip, sizeof(sofia_rtlookup_neg[slot].ip));
	sofia_rtlookup_neg[slot].ts = now;
	ast_mutex_unlock(&sofia_rtlookup_neg_lock);
}

/* Realtime IP-trunk fallback — chan_sip realtime_peer_by_addr parity (channels/chan_sip.c:5504).
 * An inbound INVITE from a type=peer host=<ip> realtime trunk carries the caller-ID (NOT the peer
 * name) in From, so sofia_find_peer(cid) and the in-memory sofia_find_peer_by_ip both miss while the
 * trunk is not yet cached → alwaysauthreject 401s a legitimate trunk. Resolve the peer NAME from the
 * DB by source IP+port, then build/link/cache the peer DIRECTLY from that by-IP row via
 * sofia_find_peer_impl (chan_sip realtime_peer parity, chan_sip.c:5606-5607 — NOT a by-name re-query,
 * which a custom backend may answer differently) so EVERY subsequent INVITE resolves in memory via
 * sofia_find_peer_by_ip. Synchronous like the
 * by-name realtime path and likewise OFF the peers lock (the lock-across-DB invariant ~:104-105); a
 * short negative-cache bounds an unknown-IP flood against the realtime database backend. */
static struct sofia_peer *sofia_find_peer_realtime_by_addr(const struct ast_sockaddr *src)
{
	struct ast_variable *var, *v;
	struct sofia_peer *peer;
	const char *name = NULL;
	const char *step = NULL;	/* which by-IP step matched, for the debug trace */
	char ipbuf[48], portbuf[8], namebuf[80];

	if (!src || ast_sockaddr_isnull(src) || !ast_check_realtime("sippeers")) {
		return NULL;
	}
	ast_copy_string(ipbuf, ast_sockaddr_stringify_addr(src), sizeof(ipbuf));
	ast_copy_string(portbuf, ast_sockaddr_stringify_port(src), sizeof(portbuf));

	if (sofia_rtlookup_neg_check(ipbuf)) {
		return NULL;
	}

	/* chan_sip realtime_peer_by_addr parity (channels/chan_sip.c:5512-5532), 4 steps:
	 *   1) static host  + exact source port    2) registered ipaddr + exact source port
	 *   3) static host  + insecure~port         4) registered ipaddr + insecure~port
	 * Steps 3-4 cover insecure=port trunks whose DB port column is empty or differs from the
	 * inbound source port (some realtime IP-trunks have an empty port column). The realtime
	 * driver turns a field name that contains a space into a bare SQL operator
	 * (res_config_pgsql.c:872), so "insecure LIKE","%port%" yields  insecure LIKE '%port%'  in the
	 * WHERE — one ast_load_realtime, no multientry. No wide insecure sipregs scan
	 * (chan_sip.c:5355-5405): that is the DoS-amplifiable path we deliberately omit. */
	var = ast_load_realtime("sippeers", "host", ipbuf, "port", portbuf, SENTINEL);
	if (var) {
		step = "host+port";
	} else if ((var = ast_load_realtime("sippeers", "ipaddr", ipbuf, "port", portbuf, SENTINEL))) {
		step = "ipaddr+port";
	} else if ((var = ast_load_realtime("sippeers", "host", ipbuf, "insecure LIKE", "%port%", SENTINEL))) {
		step = "host+insecure~port";
	} else if ((var = ast_load_realtime("sippeers", "ipaddr", ipbuf, "insecure LIKE", "%port%", SENTINEL))) {
		step = "ipaddr+insecure~port";
	}
	if (!var) {
		sofia_rtlookup_neg_add(ipbuf);
		return NULL;
	}

	for (v = var; v; v = v->next) {
		if (!strcasecmp(v->name, "name")) {
			name = v->value;
			break;
		}
	}
	if (ast_strlen_zero(name)) {
		ast_variables_destroy(var);
		sofia_rtlookup_neg_add(ipbuf);
		return NULL;
	}
	ast_copy_string(namebuf, name, sizeof(namebuf));
	if (sofia_debug) {
		ast_verbose("Sofia: realtime IP-trunk '%s' matched by %s (source %s:%s) — building from the by-IP row\n",
			namebuf, step ? step : "?", ipbuf, portbuf);
	}

	/* chan_sip realtime_peer parity (chan_sip.c:5606-5607 build_peer(var)): build/link/cache the peer
	 * DIRECTLY from the by-IP row we already hold — do NOT re-query by name. A custom realtime backend
	 * can return the trunk by source IP but NOT by name (some realtime backends key the lookup
	 * differently — e.g. a function-backed view), so the old
	 * by-name re-load lost the match → unknown-peer 401. sofia_find_peer_impl's build is copy-only and
	 * never frees `var` (cache-hit/lost-race/OOM included), so WE free it exactly once, here. */
	peer = sofia_find_peer_impl(namebuf, var);
	ast_variables_destroy(var);
	return peer;
}

/* ast_rtp_glue plumbing; direct-media re-INVITE guarded by reinvite_pending. */

static enum ast_rtp_glue_result sofia_get_rtp_peer(struct ast_channel *chan,
		struct ast_rtp_instance **instance)
{
	struct sofia_pvt *pvt;

	if (!chan || !(pvt = chan->tech_pvt) || !pvt->rtp) {
		return AST_RTP_GLUE_RESULT_FORBID;
	}

	ao2_ref(pvt->rtp, +1);
	*instance = pvt->rtp;

	/* SRTP / DTLS-SRTP active → force LOCAL relay. directmedia would bridge this leg's encrypted media to a
	 * possibly non-DTLS peer or disclose the SRTP key via re-INVITE. DTLS-SRTP (WebRTC) keys live in the
	 * engine instance, NOT pvt->srtp/vsrtp, so is_webrtc must be checked explicitly (review fix). */
	if (pvt->srtp || pvt->vsrtp || pvt->is_webrtc) {
		ast_debug(2, "Sofia: get_rtp_peer LOCAL (SRTP/DTLS active, direct media inhibited)\n");
		return AST_RTP_GLUE_RESULT_LOCAL;
	}
	if (!pvt->peer || !pvt->peer->directmedia) {
		return AST_RTP_GLUE_RESULT_LOCAL;
	}
	/* NAT → force LOCAL (peers behind NAT advertise unreachable private addrs). */
	if (pvt->peer->nat & (SOFIA_NAT_FORCE_RPORT | SOFIA_NAT_COMEDIA)) {
		return AST_RTP_GLUE_RESULT_LOCAL;
	}
	/* Cross-leg directmedia ACL — apply the BRIDGE PARTNER's directmediaha against
	 * THIS leg's RTP remote addr. Defensive fall-throughs all allow REMOTE. */
	{
		struct ast_channel *bridged_chan = sofia_find_bridged_channel(pvt);
		if (bridged_chan && bridged_chan->tech == &sofia_tech) {
			/* UAF: the helper's +1 keeps the partner CHANNEL alive but not its
			 * pvt/peer (concurrent sofia_hangup frees them). Pin bpeer UNDER the
			 * partner channel lock (trylock to avoid ABBA vs our held channel lock;
			 * contention → REMOTE) + an ao2 ref so it survives the unlock. */
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
				/* reload-UAF: directmediaha is an ast_ha LIST freed under
				 * peer->lock on reload — can't snapshot a pointer, so HOLD
				 * bpeer->lock across ast_apply_ha (and the name snapshot). */
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

/* Compute config-derived session-timer (RFC 4028) NUTAG values; sofia-sip handles
 * the wire mechanics. Out-params:
 *   *out_st_seconds: -1 skip / 0 explicit-disable (REFUSE) / N NUTAG_SESSION_TIMER(N).
 *   *out_min_se:     0 skip / N NUTAG_MIN_SE(N).
 *   *out_refresher:  -1 skip (let negotiation decide) / else nua_*_refresher.
 * Mode mapping: OFF→all skip; ACCEPT→outbound min_se only, inbound st+min_se;
 * ORIGINATE→outbound st+min_se+refresher, inbound = ACCEPT; REFUSE→st(0) disables
 * OUR origination only (sofia still ACCEPTS a peer-offered Session-Expires). */
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

/* Send an in-dialog re-INVITE. LOCK: caller MUST hold pvt->lock (reads redirip,
 * writes reinvite_pending; both also touched by the sofia event-loop thread). */
static void sofia_send_reinvite(struct sofia_pvt *pvt)
{
	char sdp_buf[4096];	/* WebRTC video (multi-PT rtcp-fb + ICE candidates) can exceed 2048 → SDP dropped fail-closed; RFC 8843/6184 headroom */
	char mf_str[8];	/* RFC 3261 §20.22 Max-Forwards */
	char gruu_contact[1024] = "";	/* sized for an opaque GRUU (RFC 5627) */
	int have_gruu = 0;
	int mf = sofia_cfg.default_max_forwards;

	if (!pvt || !pvt->nh || !sofia_generate_sdp(pvt, sdp_buf, sizeof(sdp_buf), 0 /* offer */)) {
		/* Nothing sent — release the reinvite gate (pre-set by the directmedia
		 * marshal) so a guard-fail doesn't leave it stuck. */
		if (pvt) {
			pvt->reinvite_pending = 0;
		}
		return;
	}
	/* GRUU: a re-INVITE is a target-refresh request (RFC 5627 §4.4 / RFC 3261 §12.2) so it
	 * carries the GRUU Contact too. Snapshot maxforwards + the GRUU Contact under peer->lock (order is
	 * pvt->peer; canonical), then RELEASE before nua_invite — never hold peer->lock across the stack. */
	if (pvt->peer) {
		ast_mutex_lock(&pvt->peer->lock);
		mf = pvt->peer->maxforwards;
		have_gruu = sofia_gruu_dialog_contact(pvt->peer, gruu_contact, sizeof(gruu_contact));
		ast_mutex_unlock(&pvt->peer->lock);
	}
	snprintf(mf_str, sizeof(mf_str), "%d", mf);

	pvt->reinvite_pending = 1;
	nua_invite(pvt->nh,
		SIPTAG_CONTENT_TYPE_STR("application/sdp"),
		SIPTAG_PAYLOAD_STR(sdp_buf),
		SIPTAG_MAX_FORWARDS_STR(mf_str),
		TAG_IF(!ast_strlen_zero(pvt->outbound_proxy), NUTAG_PROXY(pvt->outbound_proxy)),	/* NAT: re-INVITE to the learned public source (operation-level) */
		TAG_IF(have_gruu, SIPTAG_CONTACT_STR(gruu_contact)),
		TAG_END());
	ast_verbose("Sofia: directmedia re-INVITE sent on '%s' -> %s:%d\n",
		pvt->callid ? pvt->callid : "(no-callid)",
		ast_sockaddr_stringify_host(&pvt->redirip),
		ast_sockaddr_port(&pvt->redirip));
}

/* Runs the directmedia re-INVITE on sofia_thread (dispatched by sofia_set_rtp_peer
 * with a +1 pvt ref; the re-INVITE must not run on the bridge thread). */
static void sofia_directmedia_reinvite_root(void *data)
{
	struct sofia_pvt *pvt = data;

	ast_mutex_lock(&pvt->lock);
	/* REVALIDATE the pre-dispatch guards — hangup can run in between (leaving nh
	 * non-NULL while the dialog moves DOWN), so a late re-INVITE could slip out
	 * after teardown began. Clear the gate and bail if gone / not up / nh dropped. */
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
	/* Read the bridged peer's RTP target before pvt->lock (instance is core-owned). */
	if (instance) {
		ast_rtp_instance_get_remote_address(instance, &new_redirip);
	}

	ast_mutex_lock(&pvt->lock);
	if (pvt->alreadygone) {
		ast_mutex_unlock(&pvt->lock);
		return 0;
	}
	/* Defensive: core only calls this post-answer, but guard pre-negotiation callers. */
	if (pvt->state != SOFIA_DIALOG_STATE_UP) {
		ast_mutex_unlock(&pvt->lock);
		return 0;
	}
	/* Re-INVITE in flight: update target, don't fire a second; the response handler
	 * picks up the new redirip on the next bridge tick. */
	if (pvt->reinvite_pending) {
		ast_sockaddr_copy(&pvt->redirip, &new_redirip);
		ast_mutex_unlock(&pvt->lock);
		return 0;
	}
	/* Only fire when the target actually changes. */
	if (!ast_sockaddr_cmp(&new_redirip, &pvt->redirip)) {
		ast_mutex_unlock(&pvt->lock);
		return 0;
	}
	ast_sockaddr_copy(&pvt->redirip, &new_redirip);
	/* Marshal onto sofia_thread: set reinvite_pending (so a concurrent tick takes the
	 * gate above), +1 pvt ref, drop the lock, dispatch. On failure undo both. */
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

/* Dialplan apps SIPAddHeader/SIPRemoveHeader/SIPDtmfMode. Headers are stashed in
 * __SIPADDHEADERnn channel vars; the outbound INVITE emits each as SIPTAG_HEADER_STR. */
static const char *app_dtmfmode = "SIPDtmfMode";
static const char *app_sipaddheader = "SIPAddHeader";
static const char *app_sipremoveheader = "SIPRemoveHeader";

static int sofia_app_dtmfmode(struct ast_channel *chan, const char *data)
{
	struct sofia_pvt *pvt;
	const char *mode = data;

	if (ast_strlen_zero(mode)) {
		ast_log(LOG_WARNING, "SIPDtmfMode requires argument: rfc2833 / info / shortinfo / inband / auto\n");
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
	/* Shared parser: trims, accepts rfc2833/info/shortinfo/inband/auto, unknown → rfc2833 + warn. */
	pvt->dtmfmode = sofia_parse_dtmfmode(mode);
	/* g6: a mid-call SIPDtmfMode() must re-sync the RUNTIME state, not just the configured mode.
	 * Reset dtmf_effective from the new configured mode; for auto resolve immediately from the
	 * already-negotiated codec map (telephone-event present?) when RTP is up, else leave it
	 * unresolved for the next SDP commit. Then re-apply property + engine dtmf mode + DSP.
	 * Held under pvt->lock; pvt->owner is this channel so reconfigure never frees the DSP. */
	pvt->dtmf_effective = pvt->dtmfmode;
	if (pvt->dtmfmode == SOFIA_DTMF_AUTO && pvt->rtp) {
		format_t offered = 0;
		int noncodec = 0;
		ast_rtp_codecs_payload_formats(ast_rtp_instance_get_codecs(pvt->rtp), &offered, &noncodec);
		pvt->dtmf_effective = (noncodec & AST_RTP_DTMF) ? SOFIA_DTMF_RFC2833 : SOFIA_DTMF_INBAND;
	}
	sofia_dtmf_reconfigure(pvt);
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

/* Sanitize a SIP quoted display-name: drop " \ and control chars (incl. CR/LF) so
 * the "name" <sip:...> token can't make From/RPID/PAI unparseable (sofia-sip would
 * then reject the whole request). The display name is cosmetic, so dropping is safe. */
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

/* Concatenate the channel's __SIPADDHEADER* vars into out_buf as CRLF-separated
 * header lines for SIPTAG_HEADER_STR. Returns 1 if any were added, else 0. */
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
		/* Emit only the first line — an embedded CR/LF would make the whole
		 * SIPTAG_HEADER_STR unparseable (sofia rejects the entire INVITE) and is a
		 * header-injection vector. */
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

/* Effective WebRTC for an OUTBOUND offer. peer->webrtc (per-peer or inherited from [general]) is ONLY the
 * enable/permission; the actual media profile is ALWAYS decided by the TARGET's physical transport. So one
 * account used from several phones at once is served per-contact: a ws/wss target gets DTLS-SRTP
 * (UDP/TLS/RTP/SAVPF), a udp/tls target gets RTP/AVP (or RTP/SAVP with SDES). DTLS-SRTP is NEVER offered to
 * a non-ws/wss target - a plain phone cannot answer that transport profile and rejects it 406/488 (RFC 3264
 * sec 6.1 / RFC 5764 sec 8) - not even when webrtc=yes is set explicitly. target_transport is the per-contact
 * registration transport for a registered peer, or the configured transport= for a static/no-contact peer.
 * Mirrors the per-endpoint model of the canonical chan_sip and PJSIP SDP builders. (To force DTLS-SRTP over a
 * non-ws transport - exotic DTLS-SRTP-over-UDP, RFC 5763 - a separate explicit force knob would be needed,
 * never webrtc=yes, so it cannot poison a shared dynamic account's udp/tls phones.) */
static int sofia_transport_is_ws(const char *t)
{
	return t && (!strcasecmp(t, "ws") || !strcasecmp(t, "wss"));
}

static int sofia_offer_effective_webrtc(const struct sofia_peer *peer, const char *target_transport)
{
	return peer && peer->webrtc && sofia_transport_is_ws(target_transport);
}

static int sofia_call(struct ast_channel *ast, char *dest, int timeout)
{
	struct sofia_pvt *pvt = ast->tech_pvt;
	char sdp_buf[4096];	/* WebRTC video (multi-PT rtcp-fb + ICE candidates) can exceed 2048 → SDP dropped fail-closed; RFC 8843/6184 headroom */
	char addheader_buf[2048];
	int has_addheaders;

	if (!pvt) {
		ast_log(LOG_ERROR, "Sofia call: no pvt\n");
		return -1;
	}

	/* SIP history: apply the capture filter (source = our caller-id number, destination = dial string). */
	pvt->do_history = sofia_history_should_record(S_OR(ast->caller.id.number.str, ""), S_OR(dest, ""));
	sofia_append_history(pvt, "Tx INVITE", "to %s", S_OR(dest, ""));

	/* Outbound counter + 486 enforcement BEFORE any state transition (USER_BUSY →
	 * 486). No-op when call_limit=0 + busy_level=0. */
	if (sofia_update_call_counter(pvt, SOFIA_INC_CALL_RINGING) == -1) {
		ast->hangupcause = AST_CAUSE_USER_BUSY;
		return -1;
	}

	/* callingpres from channel.caller.id, then let a configured peer override win. */
	pvt->callingpres = ast_party_id_presentation(&ast->caller.id);
	if (pvt->peer && pvt->peer->callingpres) {
		pvt->callingpres = pvt->peer->callingpres;
	}
	/* Write the resolved presentation back so dialplan reads + RPID emission agree. */
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
				S_OR(pvt->peername, "unknown"));
			ast_queue_control(ast, AST_CONTROL_BUSY);
			return 0;
		}
	}

	/* Check if peer has multiple live contacts for forking */
	if (pvt->peer && pvt->peer->contacts) {
		int live = 0;		/* unexpired (expires>now) count — the availability signal (RFC 3261 soft state) */
		int total = 0;		/* total bindings present — for the all-expired no-route guard */
		time_t now = time(NULL);
		struct ao2_iterator ci;
		struct sofia_contact *c;
		int posted_any = 0;   /* #1: set once any child actually reaches nua_invite */
		int peer_is_dynamic = 0;

		ci = ao2_iterator_init(pvt->peer->contacts, 0);
		while ((c = ao2_iterator_next(&ci))) {
			time_t c_exp;
			/* Snapshot the mutable expires under the contact lock (a concurrent
			 * REGISTER refresh rewrites it). */
			ao2_lock(c);
			c_exp = c->expires;
			ao2_unlock(c);
			total++;
			if (sofia_contact_is_unexpired(c_exp, now))
				live++;
			ao2_ref(c, -1);
		}
		ao2_iterator_destroy(&ci);

		ast_mutex_lock(&pvt->peer->lock);
		peer_is_dynamic = !strcasecmp(pvt->peer->host, "dynamic");
		ast_mutex_unlock(&pvt->peer->lock);

		/* All-expired no-route guard. request_call classified contacts, but a binding can cross its expiry
		 * between there and here. When NOTHING is unexpired now and request_call did NOT pin a single per-contact
		 * route (!active_contact — it had seen live>1 and left the peer-aggregate URI), do NOT route to the stale
		 * peer->src_addr aggregate (RFC 3261 soft state: expired = unavailable). Fail. Dynamic-only — a static
		 * peer always keeps its configured target; total==0 (never registered) keeps existing behavior. */
		if (live == 0 && total > 0 && !pvt->active_contact && peer_is_dynamic) {
			ast_log(LOG_NOTICE, "Sofia: peer '%s' registration expired at call time - %d contact(s), 0 unexpired - no route\n",
				S_OR(pvt->peername, "unknown"), total);
			return -1;
		}

		if (live > 1) {
			/* Forking mode — one child per live contact. */
			struct sofia_fork *fork;
			int branch_idx = 0;

			fork = sofia_fork_alloc();
			if (!fork) {
				ast_log(LOG_ERROR, "Sofia: fork alloc failed\n");
				return -1;
			}

			ast_mutex_lock(&fork->lock);
			/* fork->master is derefed by child handlers on sofia_thread after the
			 * caller may have hung up the master. Anchor its lifetime with an ao2 ref
			 * (released + cleared in sofia_hangup's is_fork_master block). Not a cycle:
			 * sofia_hangup drops the fork->master ref first. */
			fork->master = pvt;
			ao2_ref(pvt, +1);
			fork->fork_start = now;
			ast_mutex_unlock(&fork->lock);

			pvt->fork = fork;
			pvt->is_fork_master = 1;
			/* Master has no nh — INVITEs go through child handles. */

			ci = ao2_iterator_init(pvt->peer->contacts, 0);
			while ((c = ao2_iterator_next(&ci))) {
				struct sofia_pvt *child;
				char ruri[256];
				time_t c_exp;

				/* Snapshot expires under the contact lock (refresh race). */
				ao2_lock(c);
				c_exp = c->expires;
				ao2_unlock(c);
				if (!sofia_contact_is_unexpired(c_exp, now)) {
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

				/* Copy dial parameters from master. */
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
				child->dtmf_effective = pvt->dtmf_effective;	/* inherit the master's runtime mode; child rtp_init applies the property */
				child->dtmf_detect_off = pvt->dtmf_detect_off;	/* inherit any runtime DIGIT_DETECT suspend (complete runtime-state clone) */
				child->peer = pvt->peer;
				ao2_ref(child->peer, +1);
				/* children never own the ast_channel. Inherit the master's resolved
				 * outbound identity (scalars here; a temporary owner alias across the
				 * header builders below) so forked INVITEs carry the real caller. */
				child->callingpres = pvt->callingpres;
				ast_sockaddr_copy(&child->ourip, &pvt->ourip);
				char child_path[1024] = "";	/* RFC 3327 Path of THIS contact, pre-loaded as Route on its forked INVITE */

				/* Build RURI for this contact via the shared per-contact builder
				 * (single source of truth with the single-live-contact request path):
				 * snapshots c->transport/src_addr/host/port under ao2_lock(c), routes
				 * ws/wss to c->src_addr (BUG 2 / WSS fork), appends the transport, and
				 * copies this contact's RFC 3327 Path. c->host may be unbracketed IPv6 —
				 * the helper wraps it (RFC 3261 §19.1.2). */
				sofia_build_contact_ruri(c, pvt->exten, ruri, sizeof(ruri),
					(child->peer && child->peer->path_support), child_path, sizeof(child_path));
				ast_string_field_set(child, ruri, ruri);
				/* B (chan_sip parity): keep the (private) Contact in the RURI above; route THIS
				 * child's INVITE packet to the contact's learned PUBLIC src via NUTAG_PROXY (the fork
				 * path previously set no proxy, so NAT'd UDP forked contacts went to the private RURI). */
				char child_proxy_url[128] = "";
				sofia_build_contact_proxy_url(child->peer, c, child_proxy_url, sizeof(child_proxy_url));
				/* NAT: apply the next-hop proxy at the child nua_invite OPERATION level (below), not at
				 * nua_handle (ineffective for the initial INVITE in this sofia-sip fork). Stash on the child;
				 * sofia_fork_pick_winner copies it onto master so later master re-INVITEs keep routing here. */
				ast_string_field_set(child, outbound_proxy, child_proxy_url);

				/* Create handle auto-bound to child. */
				if (sofia_nua) {
					child->nh = nua_handle(sofia_nua, child,
						NUTAG_URL(ruri),
						SIPTAG_TO_STR(ruri),
						TAG_IF(child_path[0], NUTAG_INITIAL_ROUTE_STR(child_path)),	/* RFC 3327 Path as Route */
						TAG_IF(child->peer && child->peer->gruu, NUTAG_SUPPORTED("gruu")),	/* RFC 5627 §4.4 */
						TAG_END());
				}

				/* Init RTP + (if encryption=yes) per-child SRTP, then SDP. */
				if (child->nh && sofia_rtp_init(child) == 0) {
					int crypto_ok = 1;
					/* Each fork child gets its own DTLS cert + ICE creds for an
					 * independent WebRTC offer (mirrors the per-child SDES keys below).
					 * child->rtp exists from sofia_rtp_init(child) above. Mutually
					 * exclusive with the per-child a=crypto block. Fail per child (skip
					 * its INVITE); if ALL children fail, the fork-empty path → 503. */
					/* effective WebRTC for THIS child's contact = webrtc enabled AND this contact registered over
					 * ws/wss; a udp/tls contact -> RTP/AVP (even with webrtc=yes, global or explicit). Snapshot
					 * c->transport under the contact lock (mirrors the c->expires snapshot above). This is what
					 * serves one account from several phones at once: DTLS to the wss child, RTP/AVP to the udp/tls child. */
					int want_webrtc;
					{
						char tgt_transport[8] = "";
						ao2_lock(c);
						ast_copy_string(tgt_transport, c->transport, sizeof(tgt_transport));
						ao2_unlock(c);
						want_webrtc = sofia_offer_effective_webrtc(pvt->peer, tgt_transport);
						if (sofia_forkdebug) {
							char rbuf[256];
							SOFIA_FORKDBG("child branch=%s idx=%d nh=%p rtp=%p transport=%s want_webrtc=%d ruri=%s",
								child->fork_branch_id, branch_idx, (void *)child->nh, (void *)child->rtp,
								tgt_transport, want_webrtc, sofia_uri_redact(ruri, rbuf, sizeof(rbuf)));
						}
					}
					if (want_webrtc) {
						if (sofia_webrtc_provision_offer(child)) {
							ast_log(LOG_ERROR, "Sofia: fork-child %d WebRTC offer provisioning failed (peer '%s')\n",
								branch_idx, S_OR(pvt->peername, "unknown"));
							crypto_ok = 0;
						}
					} else
					/* Each child needs independent crypto keys (RFC 4568). Hard-fail per
					 * child → skip its INVITE; if ALL fail, the fork-empty path → 503.
					 * No silent downgrade. */
					if (pvt->peer->encryption) {
						/* Cipher list (peer or [general] fallback); NULL = legacy single line.
						 * reload-UAF: snapshot srtpcipher under peer->lock, sdp_crypto_* calls
						 * OUTSIDE the lock. LOCK ORDER channel -> peer. */
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
								branch_idx, S_OR(pvt->peername, "unknown"));
							if (child->srtp) { sofia_srtp_destroy(child->srtp); child->srtp = NULL; }
							crypto_ok = 0;
						}
						if (crypto_ok && child->vrtp) {
							child->vsrtp = sofia_srtp_alloc();
							if (!child->vsrtp || !(child->vsrtp->crypto = sdp_crypto_setup())
									|| sdp_crypto_offer_list(child->vsrtp->crypto, cipher_list) < 0) {
								ast_log(LOG_ERROR, "Sofia: fork-child %d video crypto setup failed (peer '%s')\n",
									branch_idx, S_OR(pvt->peername, "unknown"));
								if (child->vsrtp) { sofia_srtp_destroy(child->vsrtp); child->vsrtp = NULL; }
								sofia_srtp_destroy(child->srtp); child->srtp = NULL;
								crypto_ok = 0;
							}
						}
					}
					if (crypto_ok) {
						char from_buf[256];
						char contact_buf[1024];	/* sized for an opaque GRUU Contact (RFC 5627), not just sip:user@host */
						char rpid_buf[512];
						char diversion_buf[512];
						/* reload-UAF: the identity builders read freeable peer
						 * stringfields freed under peer->lock; all are pure formatting,
						 * so hold child->peer->lock across the block. LOCK ORDER channel
						 * -> peer. Alias the master's channel as the child's owner ONLY
						 * here (reset to NULL before link/invite) so the builders read the
						 * real caller's connected.id; ast_call holds the master lock. */
						child->owner = pvt->owner;
						if (child->peer) {
							ast_mutex_lock(&child->peer->lock);
						}
						sofia_build_from(child, from_buf, sizeof(from_buf));
						sofia_build_contact(child, contact_buf, sizeof(contact_buf));
						sofia_add_rpid(child, rpid_buf, sizeof(rpid_buf));
						/* Diversion (RFC 5806) when a redirecting chain is present. */
						sofia_add_diversion(child, diversion_buf, sizeof(diversion_buf));
						if (child->peer) {
							ast_mutex_unlock(&child->peer->lock);
						}
						child->owner = NULL;
						/* Per-child session timers (RFC 4028). */
						int st_seconds, st_min_se, st_refresher;
						sofia_session_timer_values(pvt->peer, 1 /* outbound */, &st_seconds, &st_min_se, &st_refresher);
						/* RFC 3261 §20.22 Max-Forwards. */
						char mf_str_child[8];
						snprintf(mf_str_child, sizeof(mf_str_child), "%d", child->peer ? child->peer->maxforwards : sofia_cfg.default_max_forwards);
						/* Link into fork->children + dialogs and count BEFORE nua_invite so
						 * an immediate local error/1xx can find the child via
						 * sofia_pvt_ref_if_linked; only invited children are counted, so
						 * child_count stays exact. Require BOTH links (NOT-in-dialogs →
						 * unroutable response; NOT-in-children → uncancellable loser); undo a
						 * partial link and skip the invite on OOM. */
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
						if (sofia_generate_sdp(child, sdp_buf, sizeof(sdp_buf), 0 /* offer */)) {
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
								TAG_IF(!ast_strlen_zero(child->outbound_proxy), NUTAG_PROXY(child->outbound_proxy)),	/* NAT: steer this child INVITE to the contact public source (operation-level) */
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
								TAG_IF(!ast_strlen_zero(child->outbound_proxy), NUTAG_PROXY(child->outbound_proxy)),	/* NAT: steer this child INVITE to the contact public source (operation-level) */
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

			/* No contact invited → no event can arrive → master would hang forever.
			 * Fail now. posted_any (not child_count) is deliberate: children posted
			 * then failed fast are handled by the event-driven all-failed HANGUP. */
			if (!posted_any) {
				ast_log(LOG_WARNING,
					"Sofia: fork to peer '%s' emitted no INVITE (all contacts failed setup) — failing call\n",
					pvt->peername);
				return -1;
			}

			ast_mutex_lock(&pvt->lock);
			/* A fast winner may already have advanced master->state during the loop.
			 * Don't clobber UP/RINGING back to TRYING — a later hangup would then
			 * CANCEL (invalid post-200) instead of BYE, leaving a zombie answered leg. */
			if (pvt->state != SOFIA_DIALOG_STATE_UP
					&& pvt->state != SOFIA_DIALOG_STATE_RINGING) {
				pvt->state = SOFIA_DIALOG_STATE_TRYING;
			}
			ast_mutex_unlock(&pvt->lock);
			if (sofia_debug)
				ast_verbose("Sofia: Forking %d INVITEs to peer '%s' (%s)\n",
					branch_idx, pvt->peername, fork->fork_id);

			/* Enable inband-DTMF/fax-CNG DSP on the master too (fork parity with the
			 * single-contact path below): forked media is masqueraded into the master pvt
			 * and sofia_read runs ast_dsp_process on it, so without this a forked call to an
			 * INBAND/AUTO or faxdetect=cng peer would have no detection. Idempotent +
			 * self-gating, so non-inband/non-fax forking peers pay zero cost. */
			sofia_enable_dsp_detect(pvt);

			return 0;
		}
	}

	/* Single-contact path (original behavior). */
	if (!pvt->nh) {
		ast_log(LOG_ERROR, "Sofia call: no handle\n");
		return -1;
	}

	/* Enable inband-DTMF detect after RTP setup; internal-gated on INBAND/AUTO so
	 * non-inband peers pay zero alloc cost. */
	sofia_enable_dsp_detect(pvt);

	/* Outbound WebRTC offer - provision DTLS(actpass)+ICE-lite BEFORE generate_sdp so the emitter produces a
	 * UDP/TLS/RTP/SAVPF offer carrying our fingerprint + ufrag/pwd + host candidate. Mutually exclusive with
	 * the SDES a=crypto block below (a WebRTC leg never offers a=crypto). We offer WebRTC media ONLY when
	 * sofia_offer_effective_webrtc is true = webrtc enabled AND the target transport is ws/wss. A udp/tls
	 * target (even with webrtc=yes, global or explicit) is NOT WebRTC (a DTLS-SRTP offer would 406/488) -> it
	 * falls through to plain RTP/AVP below; webrtc=yes is only the enable, the transport picks the profile.
	 * The single live contact was selected + ref'd in sofia_request_call (pvt->active_contact), so snapshot
	 * its transport under the contact lock; when no contact is set fall back
	 * to the peer's learned reg_transport (under peer->lock), and for a static non-registering peer whose
	 * reg_transport is empty to the CONFIGURED transport= (see below) - the same transport used to route the
	 * call to a static host, so the offer profile matches the outbound transport. Fail closed
	 * for a real WebRTC target: provisioning failure aborts rather than silently downgrading. */
	int want_webrtc = 0;
	{
		char tgt_transport[8] = "";
		if (pvt->active_contact) {
			ao2_lock(pvt->active_contact);
			ast_copy_string(tgt_transport, pvt->active_contact->transport, sizeof(tgt_transport));
			ao2_unlock(pvt->active_contact);
		} else if (pvt->peer) {
			ast_mutex_lock(&pvt->peer->lock);
			ast_copy_string(tgt_transport, pvt->peer->reg_transport, sizeof(tgt_transport));
			ast_mutex_unlock(&pvt->peer->lock);
			/* Static (non-registering) peer: reg_transport is empty (only written at REGISTER), so fall
			 * back to the CONFIGURED transport - a static ws/wss WebRTC trunk that inherited [general]
			 * webrtc still offers DTLS-SRTP, while a static udp trunk stays RTP/AVP. peer->transport is
			 * set at config-parse time and not mutated at runtime, so it is safe to read lock-free. */
			if (ast_strlen_zero(tgt_transport)) {
				ast_copy_string(tgt_transport, sofia_transport_name(pvt->peer->transport), sizeof(tgt_transport));
			}
		}
		want_webrtc = sofia_offer_effective_webrtc(pvt->peer, tgt_transport);
	}
	if (want_webrtc) {
		if (sofia_webrtc_provision_offer(pvt)) {
			ast_log(LOG_ERROR, "Sofia: WebRTC peer '%s' but WebRTC offer provisioning failed - aborting call\n",
				S_OR(pvt->peername, "unknown"));
			return -1;
		}
	} else
	/* Outbound encryption setup BEFORE generate_sdp (SAVP + a=crypto in the offer).
	 * Hard-fail on alloc errors (-1 → 503); never silently downgrade. */
	if (pvt->peer && pvt->peer->encryption) {
		/* Cipher list (peer or [general] fallback); NULL = legacy single line.
		 * reload-UAF: snapshot srtpcipher under peer->lock, sdp_crypto_* calls
		 * OUTSIDE the lock. LOCK ORDER channel -> peer. */
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
				S_OR(pvt->peername, "unknown"));
			if (pvt->srtp) { sofia_srtp_destroy(pvt->srtp); pvt->srtp = NULL; }
			return -1;
		}
		if (sdp_crypto_offer_list(pvt->srtp->crypto, cipher_list) < 0) {
			ast_log(LOG_ERROR, "Sofia: sdp_crypto_offer failed for peer '%s'\n", S_OR(pvt->peername, "unknown"));
			sofia_srtp_destroy(pvt->srtp); pvt->srtp = NULL;
			return -1;
		}
		if (pvt->vrtp) {
			pvt->vsrtp = sofia_srtp_alloc();
			if (!pvt->vsrtp || !(pvt->vsrtp->crypto = sdp_crypto_setup())
					|| sdp_crypto_offer_list(pvt->vsrtp->crypto, cipher_list) < 0) {
				ast_log(LOG_ERROR, "Sofia: video crypto setup failed for peer '%s'\n", S_OR(pvt->peername, "unknown"));
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
		/* sofia-sip auto-emits the From-tag; we provide the URI without ;tag=. */
		char from_buf[256];
		char contact_buf[1024];	/* sized for an opaque GRUU Contact (RFC 5627), not just sip:user@host */
		char rpid_buf[512];
		char diversion_buf[512];
		/* reload-UAF: the identity builders read freeable peer stringfields freed
		 * under peer->lock; all are pure formatting, so hold pvt->peer->lock across
		 * the block. LOCK ORDER channel -> peer. */
		if (pvt->peer) {
			ast_mutex_lock(&pvt->peer->lock);
		}
		sofia_build_from(pvt, from_buf, sizeof(from_buf));
		sofia_build_contact(pvt, contact_buf, sizeof(contact_buf));
		/* RPID/PAI/Privacy per peer->sendrpid (no-op when 0). */
		sofia_add_rpid(pvt, rpid_buf, sizeof(rpid_buf));
		/* Diversion (RFC 5806) when a redirecting chain is present. */
		sofia_add_diversion(pvt, diversion_buf, sizeof(diversion_buf));
		if (pvt->peer) {
			ast_mutex_unlock(&pvt->peer->lock);
		}

		if (sofia_debug) {
			ast_verbose("Sofia: outbound INVITE headers to '%s' from=[%s] contact=[%s] addhdr=[%s] rpid=[%s] diversion=[%s]\n",
				S_OR(pvt->peername, "(none)"),
				from_buf, contact_buf,
				has_addheaders ? addheader_buf : "",
				rpid_buf, diversion_buf);
		}

		/* Outbound session timers (RFC 4028). */
		int st_seconds, st_min_se, st_refresher;
		sofia_session_timer_values(pvt->peer, 1 /* outbound */, &st_seconds, &st_min_se, &st_refresher);
		/* RFC 3261 §20.22 Max-Forwards. */
		char mf_str_call[8];
		snprintf(mf_str_call, sizeof(mf_str_call), "%d", pvt->peer ? pvt->peer->maxforwards : sofia_cfg.default_max_forwards);
		/* NAT: the 200-OK Contact carries a LAN IP, so sofia's auto-ACK would be
		 * unroutable — disable it and emit a manual ACK with NUTAG_PROXY in the
		 * nua_r_invite 200 handler. */
		char nat_proxy_probe[128];
		int needs_manual_ack = sofia_build_nat_proxy_url_from_peer(pvt->peer,
			nat_proxy_probe, sizeof(nat_proxy_probe));
		if (sofia_generate_sdp(pvt, sdp_buf, sizeof(sdp_buf), 0 /* offer */)) {
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
				TAG_IF(!ast_strlen_zero(pvt->outbound_proxy), NUTAG_PROXY(pvt->outbound_proxy)),	/* NAT: steer the INVITE packet to the learned public source (operation-level; a handle-level proxy is ineffective for the initial INVITE in this sofia-sip fork) */
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
				TAG_IF(!ast_strlen_zero(pvt->outbound_proxy), NUTAG_PROXY(pvt->outbound_proxy)),	/* NAT: steer the INVITE packet to the learned public source (operation-level; a handle-level proxy is ineffective for the initial INVITE in this sofia-sip fork) */
				SIPTAG_MAX_FORWARDS_STR(mf_str_call),
				TAG_END());
		}
	}

	return 0;
}

/* Outbound text-message sender (SendText). In-dialog MESSAGE (RFC 3428); NULL text
 * = no-op success. Returns 0 on success/no-op, -1 on missing pvt/nh. */
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

	if (!pvt) {
		return -1;
	}
	/* Egress capability gate. chan_sofia does not transcode video, so never emit a video codec the
	 * negotiated peer did not accept. allowed = capability & VIDEO, further narrowed by video_answer_mask
	 * when set (the SIP-video<->WebRTC intersection). Needed because ast_write() does NOT check
	 * nativeformats and ast_rtp_codecs_payload_code() falls back to static_RTP_PT (a stale PT would
	 * otherwise egress). frame->subclass.codec==0 (control/no-codec) passes through untouched. */
	if (frame->subclass.codec) {
		format_t allowed = pvt->capability & AST_FORMAT_VIDEO_MASK;
		if (pvt->video_answer_mask) {
			allowed &= pvt->video_answer_mask;
		}
		if (!(frame->subclass.codec & allowed)) {
			return 0;
		}
	}
	/* BUNDLE (RFC 8843): a bundled WebRTC leg carries video on the AUDIO transport (pvt->rtp) and has NO
	 * pvt->vrtp (dropped at the parse-commit / never created). res_rtp's ast_rtp_raw_write muxes the video
	 * onto pvt->rtp (v_ssrc/v_seqno/v_lastts + the MID header extension), so route the egress frame there —
	 * else gabpbx->browser video is silently dropped (RX still works, arriving on pvt->rtp fd0). */
	if (pvt->webrtc_video_bundled) {
		return pvt->rtp ? ast_rtp_instance_write(pvt->rtp, frame) : -1;
	}
	if (!pvt->vrtp) {
		return -1;
	}
	return ast_rtp_instance_write(pvt->vrtp, frame);
}

/* Record that a final response was already sent to the inbound UAS INVITE, so a
 * later pre-answer sofia_hangup does not emit a second (hangupcause-mapped) final.
 * Takes pvt->lock (the setters run on the channel/SIP thread; sofia_hangup reads it
 * under the same lock). MUST NOT be called with pvt->lock already held. */
static void sofia_mark_uas_final_sent(struct sofia_pvt *pvt)
{
	if (!pvt) {
		return;
	}
	ast_mutex_lock(&pvt->lock);
	pvt->uas_final_sent = 1;
	ast_mutex_unlock(&pvt->lock);
}

/* Map an Asterisk hangup cause to the SIP failure status a UAS uses to reject an
 * unanswered inbound INVITE (chan_sip hangup_cause2sip parity). Returns the SIP
 * status code, or 0 when the cause has no SIP mapping — the caller then falls back
 * to 603 Decline (chan_sip's default for an unmapped cause). */
static int sofia_hangup_cause2sip(int cause)
{
	switch (cause) {
	case AST_CAUSE_UNALLOCATED:
	case AST_CAUSE_NO_ROUTE_DESTINATION:
	case AST_CAUSE_NO_ROUTE_TRANSIT_NET:
		return 404;
	case AST_CAUSE_CONGESTION:
	case AST_CAUSE_SWITCH_CONGESTION:
		return 503;
	case AST_CAUSE_NO_USER_RESPONSE:
		return 408;
	case AST_CAUSE_NO_ANSWER:
	case AST_CAUSE_UNREGISTERED:
		return 480;
	case AST_CAUSE_CALL_REJECTED:
		return 403;
	case AST_CAUSE_NUMBER_CHANGED:
		return 410;
	case AST_CAUSE_NORMAL_UNSPECIFIED:
		return 480;
	case AST_CAUSE_INVALID_NUMBER_FORMAT:
		return 484;
	case AST_CAUSE_USER_BUSY:
		return 486;
	case AST_CAUSE_FAILURE:
		return 500;
	case AST_CAUSE_FACILITY_REJECTED:
		return 501;
	case AST_CAUSE_CHAN_NOT_IMPLEMENTED:
		return 503;
	case AST_CAUSE_DESTINATION_OUT_OF_ORDER:
		return 502;
	case AST_CAUSE_BEARERCAPABILITY_NOTAVAIL:
		return 488;
	default:
		return 0;
	}
}

static int sofia_hangup(struct ast_channel *ast)
{
	struct sofia_pvt *pvt = ast->tech_pvt;
	char reason_buf[160] = "";
	/* Q.850 Reason header (RFC 3326) for the BYE/CANCEL we send — built once from the channel's
	 * final hangup cause (set by the core before sofia_hangup). Gated by [general] use_q850_reason. */
	int have_reason;

	if (!pvt) {
		return -1;
	}
	have_reason = (sofia_cfg.use_q850_reason
		&& sofia_reason_build(ast->hangupcause, reason_buf, sizeof(reason_buf)));

	sofia_append_history(pvt, "Hangup", "cause %d %s", ast->hangupcause,
		ast_cause2str(ast->hangupcause));

	/* Fail a pending outbound REFER + disarm its timer so Transfer() never blocks past
	 * teardown (queues AST_CONTROL_TRANSFER=FAILED if pending). Off-thread-safe (it
	 * marshals the su_timer ops onto sofia_thread). No-op if no transfer is pending. */
	sofia_transfer_cleanup(pvt);

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
				sofia_fork_cancel_all_cb, have_reason ? reason_buf : NULL);
			ast_verbose("Sofia: Fork master hangup — cancelled all children (%s)\n",
				fork->fork_id);
		}
		/* Post-winner: master stole winner's nh, fall through to nua_bye below. */

		if (fork_master) {
			ao2_ref(fork_master, -1);
		}
		ao2_ref(fork, -1);
		pvt->fork = NULL;
		pvt->is_fork_master = 0;
	}

	/* defer-bye-on-transfer: detach the channel side but leave the SIP dialog alive
	 * (no nua_bye/unlink) — sofia_defer_bye_cb or the incoming BYE tears it down. */
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
				TAG_IF(have_reason, SIPTAG_REASON_STR(reason_buf)),	/* RFC 3326 Q.850 */
				TAG_END());
		} else if (!pvt->outgoing) {
			/* Inbound (UAS) INVITE not yet answered: reject with a FINAL response whose
			 * status is mapped from the channel hangupcause (chan_sip hangup_cause2sip
			 * parity) — NOT CANCEL, which is a UAC method for one's OWN outbound INVITE.
			 * A bare nua_respond binds to the pending INVITE server transaction by default
			 * (NULL phrase -> sofia stamps the standard reason phrase). Skip when a final
			 * was already sent (Busy/Congestion/Incomplete via sofia_indicate, or the
			 * PBX-start failure) so we never emit a double final response. pvt->lock is
			 * held here, so the uas_final_sent read+set is synchronized with the setters. */
			if (!pvt->uas_final_sent) {
				int st = sofia_hangup_cause2sip(ast->hangupcause);
				if (st <= 0) {
					st = 603;	/* Decline — chan_sip default for an unmapped cause */
				}
				nua_respond(pvt->nh, st, NULL,
					TAG_IF(have_reason, SIPTAG_REASON_STR(reason_buf)),	/* RFC 3326 Q.850 */
					TAG_END());
				pvt->uas_final_sent = 1;
			}
		} else {
			nua_cancel(pvt->nh,
				TAG_IF(have_reason, SIPTAG_REASON_STR(reason_buf)),	/* RFC 3326 Q.850 */
				TAG_END());
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
	/* 2048 (not 1024): T.38 emission adds ~250 bytes that would otherwise truncate. */
	char sdp_buf[4096];	/* WebRTC video (multi-PT rtcp-fb + ICE candidates) can exceed 2048 → SDP dropped fail-closed; RFC 8843/6184 headroom */

	if (!pvt || !pvt->nh) {
		return -1;
	}

	sofia_append_history_code(pvt, 200, "Tx 200", "answer to INVITE (200 OK)");

	{
		/* Inbound 200-OK accept-path session timers (RFC 4028). */
		int st_seconds, st_min_se, st_refresher;
		sofia_session_timer_values(pvt->peer, 0 /* inbound */, &st_seconds, &st_min_se, &st_refresher);
		/* Stamp Contact from the per-leg kernel-routed source (pvt->ourip): on a
		 * multihomed wildcard bind, sofia's auto-Contact would pick one interface for
		 * every dialog → a leg on another interface gets an unroutable Contact and the
		 * dialog never completes. RFC 3261 §12.1.1/§8.1.1.8. */
		char contact_buf[1024];	/* sized for an opaque GRUU Contact (RFC 5627), not just sip:user@host */
		/* reload-UAF: hold peer->lock across sofia_build_contact (reads freeable
		 * fromuser); pure formatting on the answer thread. */
		if (pvt->peer) ast_mutex_lock(&pvt->peer->lock);
		sofia_build_contact(pvt, contact_buf, sizeof(contact_buf));
		if (pvt->peer) ast_mutex_unlock(&pvt->peer->lock);
		if (sofia_generate_sdp(pvt, sdp_buf, sizeof(sdp_buf), 1 /* answer */)) {
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

	/* Activate the RTP instance AFTER the 200 OK is dispatched (the browser
	 * starts ICE only once it has our answer). For a WebRTC leg this arms the
	 * ICE/DTLS state machine; the authenticated USE-CANDIDATE path also fires DTLS,
	 * so an early/duplicate activate is a no-op. Harmless for plain SIP. */
	if (pvt->is_webrtc && pvt->rtp) {
		ast_rtp_instance_activate(pvt->rtp);
	}
	if (pvt->is_webrtc && pvt->webrtc_video_accepted && pvt->vrtp) {
		ast_rtp_instance_activate(pvt->vrtp);	/* arm the non-BUNDLE video ICE/DTLS state machine (mirrors the audio rtp) */
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
		/* Audio-path DSP (DTMF + fax-CNG); NULL when neither is needed. */
		if (f && pvt->dsp && pvt->owner) {
			f = ast_dsp_process(pvt->owner, pvt->dsp, f);
			/* DSP emits DTMF subclass 'f' on fax CNG → async-goto into the "fax"
			 * extension (FAXEXTEN var saves the original for return). Gated on
			 * faxdetect_mode. */
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
		/* Operator-visible DTMF logging ("sip set debug dtmf on"): NOTICE the completed digit received via
		 * RFC 2833 (from the RTP read) or inband (from ast_dsp_process) so keypresses show in the CLI +
		 * messages. DTMF_END only (logged once, not on BEGIN); skip the fax-CNG 'f' marker handled above.
		 * SIP INFO-mode DTMF is logged in sofia_process_info. Pure logging, gated, default OFF. */
		if (sofia_dtmflog && f && f->frametype == AST_FRAME_DTMF_END
				&& f->subclass.integer != 'f') {
			ast_log(LOG_NOTICE, "Sofia: DTMF '%c' received via %s on %s\n",
				(int)f->subclass.integer,
				pvt->dtmf_effective == SOFIA_DTMF_INBAND ? "inband" : "RFC2833",
				ast->name);
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
		/* T.38 UDPTL from fd-5 → AST_FRAME_MODEM. NULL-safe vs a teardown race
		 * (pvt->udptl → NULL between fd-poll and read). */
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

	/* AST_FRAME_MODEM → ast_udptl_write, gated on UP + udptl + t38 ENABLED. Pre-
	 * negotiation MODEM frames are dropped (the fax stack re-transmits). */
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
		/* Contact from pvt->ourip; see sofia_answer. reload-UAF: hold peer->lock
		 * across sofia_build_contact (reads freeable fromuser). */
		char contact_buf[1024];	/* sized for an opaque GRUU Contact (RFC 5627), not just sip:user@host */
		if (pvt->peer) ast_mutex_lock(&pvt->peer->lock);
		sofia_build_contact(pvt, contact_buf, sizeof(contact_buf));
		if (pvt->peer) ast_mutex_unlock(&pvt->peer->lock);
		nua_respond(pvt->nh, SIP_180_RINGING,
			TAG_IF(!ast_sockaddr_isnull(&pvt->ourip), SIPTAG_CONTACT_STR(contact_buf)),
			TAG_END());
	}
		/* progressinband (chan_sip.c AST_CONTROL_RINGING parity, chan_sip.c:7639-7645):
		 *   YES   → always force core in-band ringback (-1);
		 *   NO    → in-band ONLY once a 183 was already sent (progress_sent), so early
		 *           media keeps flowing; otherwise plain 180 out-of-band (break);
		 *   NEVER → always 180 out-of-band, never in-band (break).
		 * NO is now a real distinct state instead of collapsing onto NEVER. */
		if (pvt->peer && pvt->peer->progressinband == SOFIA_PROG_INBAND_YES) {
			return -1;
		}
		if (pvt->peer && pvt->peer->progressinband == SOFIA_PROG_INBAND_NO && pvt->progress_sent) {
			return -1;
		}
		break;
	case AST_CONTROL_BUSY:
		{
			char rb[128] = "";	/* RFC 3326 Q.850 Reason (chan_sip parity); status->cause map */
			int hr = sofia_cfg.use_q850_reason && sofia_reason_build_for_status(486, rb, sizeof(rb));
			nua_respond(pvt->nh, SIP_486_BUSY_HERE, TAG_IF(hr, SIPTAG_REASON_STR(rb)), TAG_END());
		}
		sofia_mark_uas_final_sent(pvt);
		break;
	case AST_CONTROL_INCOMPLETE:
		/* allowoverlap, pre-UP only: YES → 484; DTMF → wait (no-op); NO/default → 404. */
		if (ast->_state != AST_STATE_UP) {
			int overlap_mode = pvt->peer ? pvt->peer->allowoverlap_mode : sofia_cfg.default_allowoverlap_mode;
			switch (overlap_mode) {
			case SOFIA_OVERLAP_YES:
				{
					char rb[128] = "";
					int hr = sofia_cfg.use_q850_reason && sofia_reason_build_for_status(484, rb, sizeof(rb));
					nua_respond(pvt->nh, SIP_484_ADDRESS_INCOMPLETE, TAG_IF(hr, SIPTAG_REASON_STR(rb)), TAG_END());
				}
				sofia_mark_uas_final_sent(pvt);
				break;
			case SOFIA_OVERLAP_DTMF:
				/* wait for inband DTMF digits. */
				break;
			default:
				{
					char rb[128] = "";
					int hr = sofia_cfg.use_q850_reason && sofia_reason_build_for_status(404, rb, sizeof(rb));
					nua_respond(pvt->nh, SIP_404_NOT_FOUND, TAG_IF(hr, SIPTAG_REASON_STR(rb)), TAG_END());
				}
				sofia_mark_uas_final_sent(pvt);
				break;
			}
		}
		break;
	case AST_CONTROL_CONGESTION:
		{
			char rb[128] = "";
			int hr = sofia_cfg.use_q850_reason && sofia_reason_build_for_status(503, rb, sizeof(rb));
			nua_respond(pvt->nh, SIP_503_SERVICE_UNAVAILABLE, TAG_IF(hr, SIPTAG_REASON_STR(rb)), TAG_END());
		}
		sofia_mark_uas_final_sent(pvt);
		break;
	case AST_CONTROL_PROGRESS:
		/* prematuremedia: INVERTED-SEMANTIC chan_sip quirk preserved — filter TRUE
		 * (default) SUPPRESSES 183 even on an explicit dialplan Progress(); the
		 * "prematuremedia=yes" key reads counter-intuitively but matches drop-in. */
		if (!sofia_cfg.prematuremediafilter) {
			/* Emit 183 WITH an SDP body so the INVITE offer is answered at the
			 * early-media stage. Without SDP, when the UAC PRACKs the reliable 183
			 * (sofia auto-adds 100rel if Supported), sofia fires a spurious empty 200
			 * OK and the UAC BYEs on no media. Including SDP settles offer/answer in
			 * the 183 (NUTAG_MEDIA_ENABLE(0) reads the body from the response), so the
			 * 200 no longer fires and PRACK is RFC-3262-correct. */
			char sdp_buf[4096];	/* WebRTC video (multi-PT rtcp-fb + ICE candidates) can exceed 2048 → SDP dropped fail-closed; RFC 8843/6184 headroom */
			/* Contact from pvt->ourip (see sofia_answer); reload-UAF: hold peer->lock
			 * across sofia_build_contact (reads freeable fromuser). */
			char contact_buf[1024];	/* sized for an opaque GRUU Contact (RFC 5627), not just sip:user@host */
			if (pvt->peer) ast_mutex_lock(&pvt->peer->lock);
			sofia_build_contact(pvt, contact_buf, sizeof(contact_buf));
			if (pvt->peer) ast_mutex_unlock(&pvt->peer->lock);
			if (pvt->rtp && sofia_generate_sdp(pvt, sdp_buf, sizeof(sdp_buf), 1 /* answer */)) {
				nua_respond(pvt->nh, SIP_183_SESSION_PROGRESS,
					TAG_IF(!ast_sockaddr_isnull(&pvt->ourip), SIPTAG_CONTACT_STR(contact_buf)),
					SIPTAG_CONTENT_TYPE_STR("application/sdp"),
					SIPTAG_PAYLOAD_STR(sdp_buf),
					TAG_END());
			} else {
				/* RTP not yet bound — bodyless 183 (rare; rtp_init runs earlier). */
				nua_respond(pvt->nh, SIP_183_SESSION_PROGRESS,
					TAG_IF(!ast_sockaddr_isnull(&pvt->ourip), SIPTAG_CONTACT_STR(contact_buf)),
					TAG_END());
			}
			pvt->progress_sent = 1;	/* chan_sip SIP_PROGRESS_SENT parity: a 183 went out (see RINGING) */
		}
		break;
	case AST_CONTROL_ANSWER:
		sofia_answer(ast);
		break;
	case AST_CONTROL_HOLD:
		/* MOH: peer->mohinterpret as interpclass fallback when data is empty.
		 * reload-UAF: snapshot mohinterpret under peer->lock, then call
		 * ast_moh_start WITHOUT the lock (it may lock the channel — never channel
		 * under peer->lock). */
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
		/* Source changed WITHOUT identity change: marker bit, same SSRC. Must
		 * return 0, not -1 (core reads -1 as "unhandled" and drops it). */
		if (pvt->rtp) {
			ast_rtp_instance_update_source(pvt->rtp);
		}
		break;
	case AST_CONTROL_SRCCHANGE:
		/* Source itself changed (masquerade/transfer): bump SSRC + marker so the
		 * far end resets its jitter-buffer. Must return 0, not -1 (a -1 here caused
		 * one-way silence after a REFER blind-transfer swap). */
		if (pvt->rtp) {
			ast_rtp_instance_change_source(pvt->rtp);
		}
		break;
	case AST_CONTROL_VIDUPDATE:
		/* Keyframe request relayed from the bridged peer (its RTCP PSFB PLI/FIR or legacy FUR,
		 * forwarded by ast_generic_bridge / the rtp_engine local bridge): transmit an RTCP PSFB
		 * PLI toward OUR video sender via the engine. Bundled WebRTC video rides pvt->rtp;
		 * separate-transport WebRTC video rides pvt->vrtp — same discriminator as
		 * sofia_sync_media_fds (vrtp && !webrtc_video_bundled). A NON-WebRTC video leg gets the request
		 * as SIP INFO application/media_control+xml picture_fast_update (RFC 5168, chan_sip parity
		 * chan_sip.c:7723-7728 / add_vidupdate) so a legacy SIP video phone (MicroSIP) sends a fresh
		 * keyframe — without it the far (browser) side that just requested the keyframe stays black.
		 * MUST return 0, not -1, so the core does not log "Don't know how to indicate condition 18". */
		if (pvt->is_webrtc) {
			if (pvt->webrtc_video_bundled && pvt->rtp) {
				ast_rtp_instance_video_update(pvt->rtp);
			} else if (pvt->vrtp && !pvt->webrtc_video_bundled) {
				ast_rtp_instance_video_update(pvt->vrtp);
			}
		} else if (pvt->vrtp && pvt->nh) {
			/* Mirrors the outbound DTMF INFO path (nua_info inline on the channel thread). */
			nua_info(pvt->nh,
				SIPTAG_CONTENT_TYPE_STR("application/media_control+xml"),
				SIPTAG_PAYLOAD_STR("<?xml version=\"1.0\" encoding=\"utf-8\" ?>"
					"<media_control><vc_primitive><to_encoder><picture_fast_update/>"
					"</to_encoder></vc_primitive></media_control>"),
				TAG_END());
		}
		break;
	case -1:
		/* "stop indication" — chan_sofia has no pending state; succeed silently. */
		break;
	case AST_CONTROL_T38_PARAMETERS:
		/* res_fax queues this to drive T.38 negotiation; see
		 * sofia_interpret_t38_parameters for the op-table. */
		if (datalen != sizeof(struct ast_control_t38_parameters)) {
			ast_log(LOG_ERROR, "Sofia: AST_CONTROL_T38_PARAMETERS datalen mismatch (got %zu expected %zu)\n",
				datalen, sizeof(struct ast_control_t38_parameters));
			return -1;
		}
		{
			/* >0 = the dispatcher recorded LOCAL_REINVITE and we must SEND the outbound
			 * T.38 (m=image) re-INVITE. Reuse the directmedia re-INVITE marshaling: it
			 * runs sofia_send_reinvite on sofia_thread under pvt->lock (the re-INVITE
			 * must NOT run on the bridge/channel thread), and sofia_generate_sdp now
			 * emits m=image because pvt->udptl is set. The LOCAL_REINVITE → ENABLED
			 * transition happens when the answer's m=image is parsed (sofia_parse_sdp
			 * commit). */
			int t38_rc;
			ast_mutex_lock(&pvt->lock);
			t38_rc = sofia_interpret_t38_parameters(pvt, (const struct ast_control_t38_parameters *)data);
			ast_mutex_unlock(&pvt->lock);
			if (t38_rc < 0) {
				return -1;
			}
			if (t38_rc > 0) {
				ao2_ref(pvt, +1);	/* dispatch ref; sofia_directmedia_reinvite_root drops it */
				if (sofia_dispatch_to_root_thread(sofia_directmedia_reinvite_root, pvt) < 0) {
					ao2_ref(pvt, -1);
					ast_log(LOG_WARNING, "Sofia: failed to dispatch outbound T.38 re-INVITE on '%s'\n", ast->name);
				}
			}
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
	/* Repair: a masquerade may have copied the clone's stale fds over newchan; re-derive
	 * the media fds from the live rtp/vrtp so the bridge polls the correct sockets. */
	sofia_sync_media_fds(newchan, pvt);
	ast_mutex_unlock(&pvt->lock);

	sofia_set_rtp_peer(newchan, NULL, NULL, NULL, 0, 0);
	return 0;
}

/* AST_OPTION_T38_STATE queryoption handler — required by res_fax. Maps
 * pvt->t38_state → ast_t38_state (LOCAL/PEER_REINVITE → NEGOTIATING; ENABLED →
 * NEGOTIATED; default UNKNOWN; UNAVAILABLE when peer t38pt_udptl=0). pvt->lock
 * held across the read. */
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
	case AST_OPTION_DIGIT_DETECT:
		/* g4: report whether we are actively detecting inband DTMF digits — effective mode is
		 * inband/unresolved-auto AND the core has not suspended detection. chan_sip parity
		 * (queryoption AST_OPTION_DIGIT_DETECT). */
		{
			char *cp = (char *) data;
			if (!cp || !datalen || *datalen < 1) {	/* defensive: 1-byte result buffer required */
				break;
			}
			ast_mutex_lock(&pvt->lock);
			*cp = (sofia_dtmf_wants_inband(pvt) && !pvt->dtmf_detect_off) ? 1 : 0;
			ast_mutex_unlock(&pvt->lock);
			res = 0;
		}
		break;
	default:
		/* Other options not supported — return -1 so core can fall back to
		 * defaults or signal unsupported. */
		break;
	}
	return res;
}

/* g4 — channel setoption. Only AST_OPTION_DIGIT_DETECT is handled (chan_sip parity,
 * sip_setoption): the core enables/disables inband DTMF digit detection at runtime (e.g. for
 * native-bridge DTMF features). Meaningful only when the effective mode uses inband (INBAND or
 * unresolved AUTO). The override sets pvt->dtmf_detect_off and is applied via the fax-safe
 * sofia_dtmf_reconfigure (never frees the shared DSP under a live owner; fax-CNG preserved) and
 * persists across a later re-INVITE reconfigure. Default rfc2833 short-circuits to -1 (ENOSYS). */
static int sofia_setoption(struct ast_channel *chan, int option, void *data, int datalen)
{
	int res = -1;
	struct sofia_pvt *pvt;

	if (!chan) {
		return -1;
	}
	pvt = chan->tech_pvt;
	if (!pvt) {
		return -1;
	}

	switch (option) {
	case AST_OPTION_DIGIT_DETECT:
		if (!data || datalen < 1) {	/* defensive: payload is a 1-byte enable flag */
			break;
		}
		ast_mutex_lock(&pvt->lock);
		if (sofia_dtmf_wants_inband(pvt)) {
			char *cp = (char *) data;
			pvt->dtmf_detect_off = *cp ? 0 : 1;
			sofia_dtmf_reconfigure(pvt);
			res = 0;
		}
		ast_mutex_unlock(&pvt->lock);
		break;
	default:
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

	switch (pvt->dtmf_effective) {	/* g2: the RUNTIME mode (AUTO resolved to RFC2833/INBAND at SDP) */
	case SOFIA_DTMF_RFC2833:
	case SOFIA_DTMF_AUTO:
		if (pvt->rtp) {
			ast_rtp_instance_dtmf_begin(pvt->rtp, digit);
		}
		break;
	case SOFIA_DTMF_INFO:
	case SOFIA_DTMF_SHORTINFO:
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

	switch (pvt->dtmf_effective) {	/* g2: the RUNTIME mode (AUTO resolved to RFC2833/INBAND at SDP) */
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
	case SOFIA_DTMF_SHORTINFO:
		/* chan_sip "shortinfo" parity (add_digit mode 1, chan_sip.c:11720-11747): SIP INFO with
		 * Content-Type application/dtmf and a numeric event body ("<event>\r\n"): 0-9 -> 0-9,
		 * * -> 10, # -> 11, A-D/a-d -> 12-15; an unmapped char -> warn + skip (improves on chan_sip,
		 * which transmits a spurious event 0). */
		if (pvt->nh) {
			char info_body[16];
			int event;
			if ('0' <= digit && digit <= '9') {
				event = digit - '0';
			} else if (digit == '*') {
				event = 10;
			} else if (digit == '#') {
				event = 11;
			} else if ('A' <= digit && digit <= 'D') {
				event = 12 + digit - 'A';
			} else if ('a' <= digit && digit <= 'd') {
				event = 12 + digit - 'a';
			} else {
				/* Improvement over chan_sip add_digit (chan_sip.c:11738) which transmits a
				 * spurious event 0 for an unmapped char: warn and skip instead. */
				ast_log(LOG_WARNING, "Sofia: shortinfo DTMF: unhandled digit '%c', not sending\n", digit);
				break;
			}
			snprintf(info_body, sizeof(info_body), "%d\r\n", event);
			nua_info(pvt->nh,
				SIPTAG_CONTENT_TYPE_STR("application/dtmf"),
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
		/* No '/': try "exten@peer" (user before '@' = extension, after = peer), so
		 * Dial(SIP/9999@trunk) → peer=trunk, exten=9999. Neither → whole = peer. */
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

	/* H264 fmtp relay: snapshot the caller (requestor) leg's negotiated H264 config into locals HERE,
	 * BEFORE taking peer->lock — the requestor pvt lock must never nest under peer->lock (doctrine order is
	 * channel→pvt→peer). No peer lock is held yet, so a brief requestor pvt lock is order-safe. */
	int rq_h264_valid = 0;
	int rq_h264_pmode = 0;
	char rq_h264_fmtp[160] = "";
	if (requestor) {
		/* Canonical channel→pvt order: lock the requestor channel, then its pvt, to read the caller's
		 * negotiated H264 config. No peer lock is held here, so this is order-clean. */
		struct ast_channel *rq_chan = (struct ast_channel *)requestor;
		ast_channel_lock(rq_chan);
		if (rq_chan->tech == &sofia_tech && rq_chan->tech_pvt) {
			struct sofia_pvt *rq = rq_chan->tech_pvt;
			ast_mutex_lock(&rq->lock);
			if (rq->h264_fmtp_valid) {
				rq_h264_valid = 1;
				rq_h264_pmode = rq->h264_pmode;
				ast_copy_string(rq_h264_fmtp, rq->h264_fmtp, sizeof(rq_h264_fmtp));
			}
			ast_mutex_unlock(&rq->lock);
		}
		ast_channel_unlock(rq_chan);
	}

	if (peer) {
		int peer_is_dynamic = 0;

		/* reload-UAF: hold peer->lock across the whole freeable-stringfield read
		 * span (runs on the PBX dialing thread vs the reload writer); release it
		 * right before sofia_resolve_ourip (the only blocking call, reads no
		 * freeable field). Takes no channel/pvt lock → no inversion. */
		ast_mutex_lock(&peer->lock);
		ast_string_field_set(pvt, context, peer->context);
		ast_string_field_set(pvt, username, peer->defaultuser);
		ast_string_field_set(pvt, peersecret, peer->secret);
		ast_string_field_set(pvt, fromuser, peer->fromuser);
		ast_string_field_set(pvt, fromdomain, peer->fromdomain);
		pvt->capability = peer->capability;
		pvt->prefs = peer->prefs;
		/* Video passthrough (no transcode): OFFER the callee only the VIDEO codecs the CALLER can produce.
		 * `format` carries the requestor's caps incl. its video mask (main/channel.c preserves videoformat
		 * and passes it here); peer->capability inherits [general]'s video, so without this the callee may
		 * answer a codec the caller can't send/recv (e.g. MicroSIP picking H263-1998 vs a WebRTC H264/VP8
		 * caller) → no/garbled video. Intersect only the video bits; audio/text untouched. Zero requestor
		 * video ⇒ no m=video offered (chan_sip jointcapability parity). Must run BEFORE sofia_rtp_init
		 * (which creates vrtp only if the resulting capability still has video). */
		pvt->capability = (pvt->capability & ~AST_FORMAT_VIDEO_MASK)
			| (pvt->capability & format & AST_FORMAT_VIDEO_MASK);
		/* H264 fmtp relay (RFC 6184 §8.2.2): carry the caller's negotiated H264 config (snapshotted into
		 * rq_h264_* BEFORE peer->lock — see above — to avoid a peer→pvt lock inversion) into THIS outbound
		 * offer so the callee is offered the SAME profile-level-id/packetization-mode; else a SIP video
		 * phone answers a mode the WebRTC caller cannot produce and video is garbled/undecodable. */
		if (rq_h264_valid) {
			ast_copy_string(pvt->h264_fmtp, rq_h264_fmtp, sizeof(pvt->h264_fmtp));
			pvt->h264_pmode = rq_h264_pmode;
			pvt->h264_fmtp_valid = 1;
		}
		pvt->dtmfmode = peer->dtmfmode;
		pvt->dtmf_effective = pvt->dtmfmode;	/* runtime = configured until AUTO resolves at SDP; rtp_init (below) applies the property */
		pvt->allowtransfer = peer->allowtransfer;
		ast_string_field_set(pvt, subscribecontext, peer->subscribecontext);
		ast_string_field_set(pvt, accountcode, peer->accountcode); /* → chan->accountcode via sofia_new */
		ao2_ref(peer, +1); pvt->peer = peer;
		/* GRUU co-req: snapshot gruu under peer->lock; used for NUTAG_SUPPORTED("gruu") on
		 * the call handle below (RFC 5627 §4.4: advertise Supported: gruu in requests we generate). */
		int peer_gruu = peer->gruu;
		peer_is_dynamic = !strcasecmp(peer->host, "dynamic");

		{
			char url[256];
			char route_buf[256];
			char sr_buf[1024] = "";	/* RFC 3608 Service-Route (opt-in), pre-loaded after outboundproxy */
			char path_buf[1024] = "";	/* RFC 3327 Path of the registered contact (opt-in), pre-loaded as Route */
			struct ast_sockaddr sel_src;	/* the selected binding's src_addr — picks WHICH contact's Path */
			int sel_ok = 0;
			char contact_proxy_url[128] = "";	/* B: contact-level NAT proxy for the single-live path */

			sofia_resolve_peer_target(peer, exten, url, sizeof(url));
			/* Outbound Route from outboundproxy; sticky-on-handle via
			 * NUTAG_INITIAL_ROUTE_STR. */
			sofia_format_outboundproxy(peer, route_buf, sizeof(route_buf));
			/* Service-Route (RFC 3608 §6.1): snapshot under peer->lock (still held here) and apply it
			 * as a SECOND Route after outboundproxy on the INVITE handle below. Gated on the LIVE knob
			 * + an active registration (§6.1: a learned route is only valid while registered), so a
			 * disabled knob never sends a stale route; empty otherwise. */
			if (peer->use_service_route && peer->registered) {
				ast_copy_string(sr_buf, peer->service_route, sizeof(sr_buf));
			}
			/* Resolve our source IP toward this peer (for SDP + From/Contact). */
			{
				struct ast_sockaddr target;
				if (peer->registered && !ast_sockaddr_isnull(&peer->src_addr)) {
					target = peer->src_addr;
					sel_src = peer->src_addr;	/* the binding the RURI routes to -> its Path below */
					sel_ok = 1;
				} else {
					char target_url[128];
					snprintf(target_url, sizeof(target_url), "%s:%d",
						!ast_strlen_zero(peer->host) ? peer->host : "127.0.0.1",
						peer->port ? peer->port : 5060);
					ast_sockaddr_parse(&target, target_url, 0);
				}
				/* Release peer->lock before sofia_resolve_ourip (blocks on DNS +
				 * kernel route; reads no freeable field — target is a local copy). */
				ast_mutex_unlock(&peer->lock);
				sofia_resolve_ourip(pvt, &target);
			}
			/* Path (RFC 3327, path=yes): pre-load THIS registered contact's stored Path as a Route so
			 * the INVITE traverses the edge proxy back to the device. Done after the peer->lock release
			 * to avoid nesting the contacts-container lock under peer->lock. */
			if (peer->path_support && sel_ok) {
				struct sofia_contact *fc = sofia_peer_find_contact_by_addr(peer, &sel_src);
				if (fc) {
					ao2_lock(fc);
					ast_copy_string(path_buf, fc->path, sizeof(path_buf));
					ao2_unlock(fc);
					ao2_ref(fc, -1);
				}
			}
			/* Single-live-contact override (PER-CONTACT routing). sofia_resolve_peer_target
			 * above routes via the PEER-aggregate src_addr/reg_transport, which is WRONG for a
			 * peer whose live binding is per-contact (e.g. a WebRTC peer registered over WSS with
			 * a SIP.js .invalid Contact host — the live transport is c->src_addr/wss). When the
			 * peer has EXACTLY ONE live contact, rebuild url + Path from THAT contact using the
			 * same builder the fork uses, so the nua_handle below targets the real binding. EXACTLY ONE
			 * unexpired contact overrides here; unexpired>1 falls to the fork; a host=dynamic peer with
			 * total>0 && unexpired==0 FAILS (CHANUNAVAIL, below); total==0 keeps the peer-aggregate url. Done after the
			 * peer->lock release (the selector locks the contacts container + per-contact ao2). */
			{
				int n_unexpired = 0, n_total = 0;
				struct sofia_contact *single = sofia_peer_select_single_live_contact(peer, &n_unexpired, &n_total);
				if (single) {
					sofia_build_contact_ruri(single, exten, url, sizeof(url),
						peer->path_support, path_buf, sizeof(path_buf));
					sofia_pvt_set_active_contact(pvt, single);	/* in-dialog BYE/ACK route + call accounting */
					/* B (chan_sip parity): keep the (private) Contact in the RURI above; route the
					 * INVITE packet to the contact's learned PUBLIC src via a contact-level NUTAG_PROXY
					 * (preferred over the peer-aggregate proxy below). Empty if not NAT / src unknown. */
					sofia_build_contact_proxy_url(peer, single, contact_proxy_url, sizeof(contact_proxy_url));
					ao2_ref(single, -1);
				} else if (n_total > 0 && n_unexpired == 0 && peer_is_dynamic) {
					/* Registration EXPIRED — no re-REGISTER before the granted Contact expiry (RFC 3261 §10.3
					 * soft state). ignoreregexpire keeps the contact for CLI/BLF/rebind, but an expired binding
					 * is NOT routable: do NOT fall through to the peer-aggregate src_addr below (the SAME stale
					 * flow — it would half-connect the call to a dead device). Fail (CHANUNAVAIL). Pure expiry,
					 * transport-independent (UDP + WSS), any negotiated expiry (120/300/3600s). n_unexpired>1 forks
					 * in sofia_call (single==NULL, guard false → fork path); n_total==0 (never registered) and
					 * static peers (host != dynamic) keep existing aggregate behavior. Cleanup mirrors the
					 * sofia_pvt_alloc fail: drop the local sofia_find_peer ref + destroy the half-built pvt (not
					 * yet linked to dialogs; its destructor releases pvt->peer). peer->lock already released. */
					ast_log(LOG_NOTICE, "Sofia: peer '%s' registration expired - %d contact(s), 0 unexpired - no route (CHANUNAVAIL)\n",
						peername, n_total);
					ao2_ref(peer, -1);
					ao2_ref(pvt, -1);
					*cause = AST_CAUSE_NO_ROUTE_DESTINATION;
					return NULL;
				}
			}
			ast_string_field_set(pvt, ruri, url);
			if (sofia_debug) {
				ast_verbose("Sofia: Outbound call to peer %s, RURI=%s%s%s\n",
					peername, url,
					route_buf[0] ? ", Route=" : "",
					route_buf[0] ? route_buf : "");
			}

			/* NAT in-dialog routing override: for a NATed peer the 200-OK Contact
			 * carries a LAN IP, so sofia's auto ACK/BYE would be unroutable.
			 * NUTAG_PROXY pins dialog messages to peer->src_addr (the helper also
			 * appends reg_transport so TCP/TLS doesn't default to UDP). The helper
			 * snapshots nat/src_addr/port/reg_transport under peer->lock itself —
			 * those fields are rewritten under peer->lock by REGISTER/dnsmgr. */
			char proxy_url[128] = "";
			sofia_build_nat_proxy_url_from_peer(peer, proxy_url, sizeof(proxy_url));
			/* B: a contact-level proxy (single-live path) takes precedence over the peer-aggregate one. The
			 * NAT next-hop proxy MUST be applied at the nua_invite OPERATION level (the call/re-INVITE below),
			 * NOT at nua_handle creation: a handle-level NUTAG_PROXY does NOT steer the initial INVITE in this
			 * sofia-sip fork (only the in-dialog ACK/BYE, which pass it per-operation, reach the public src).
			 * Stash it on the pvt so sofia_call's nua_invite (and any re-INVITE) route to the public source. */
			const char *eff_proxy = contact_proxy_url[0] ? contact_proxy_url : proxy_url;
			ast_string_field_set(pvt, outbound_proxy, eff_proxy);
			if (sofia_nua) {
				pvt->nh = nua_handle(sofia_nua, pvt,
					NUTAG_URL(url),
					SIPTAG_TO_STR(url),
					TAG_IF(route_buf[0], NUTAG_INITIAL_ROUTE_STR(route_buf)),
					TAG_IF(sr_buf[0], NUTAG_INITIAL_ROUTE_STR(sr_buf)),	/* RFC 3608 Service-Route, after outboundproxy */
					TAG_IF(path_buf[0], NUTAG_INITIAL_ROUTE_STR(path_buf)),	/* RFC 3327 Path of the registered contact */
					TAG_IF(peer_gruu, NUTAG_SUPPORTED("gruu")),	/* RFC 5627 §4.4 */
					TAG_END());
				if (!pvt->nh) {
					ast_log(LOG_WARNING, "Sofia: nua_handle NULL for outbound call to peer '%s' (url=%s)\n",
						peername, url);
				}
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

	/* DO NOT REORDER: sofia_rtp_init MUST precede sofia_new, which wires
	 * chan->fds[0..3] from pvt->rtp — without rtp first, fds stay -1, the bridge
	 * poll never sees the RTP fd, and audio is silently one-way. */
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
	pvt->outgoing = 1; /* sofia_add_rpid reads this for ;party=calling */

	return chan;
}

/* Detect peer hold direction from offered SDP (RFC 3264 §5.1).
 * Returns 1 if peer is asking us to hold (a=sendonly or a=inactive on m=audio),
 * 0 if normal (a=sendrecv or default). Uses pvt->home as the parser arena. */

/* Handle an in-dialog re-INVITE (hold/unhold/codec renegotiation/session refresh).
 * Distinguished from the initial INVITE by non-NULL hmagic on the bound nh. */
static void sofia_process_reinvite(struct sofia_pvt *pvt, nua_t *nua,
		nua_handle_t *nh, sip_t const *sip)
{
	char sdp_buf[4096];	/* WebRTC video (multi-PT rtcp-fb + ICE candidates) can exceed 2048 → SDP dropped fail-closed; RFC 8843/6184 headroom */
	struct ast_channel *owner = NULL;
	char own_name[80] = "";
	char own_uniqueid[150] = "";
	int old_hold;
	int new_hold;
	int trans;
	int sdp_ok;
	int st_refresh = 0; /* RFC 4028 uas-refresh discriminator */
	int st_refresh_seconds = 0;
	const char *st_refresher_str = NULL;
	/* Session-Expires on an inbound re-INVITE = uas-side refresh fire. */
	if (sip && sip->sip_session_expires) {
		st_refresh = 1;
		st_refresh_seconds = sip->sip_session_expires->x_delta;
		st_refresher_str = sip->sip_session_expires->x_refresher; /* NULL if absent */
	}

	if (!pvt) {
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
		return;
	}

	ast_mutex_lock(&pvt->lock);
	old_hold = pvt->hold_state;
	new_hold = sofia_sdp_extract_hold(sip, pvt->home);
	trans = (old_hold != new_hold);
	/* DEFER committing hold_state + peer->onHold until sofia_parse_sdp succeeds: a
	 * rejected (488) re-INVITE must leave hold accounting unchanged (RFC 3261 §14).
	 * new_hold/trans are computed now for the AMI/MOH below.
	 * Re-acquire in canonical channel->pvt order (sip_pvt_lock_full idiom): ref
	 * owner, drop pvt, lock channel, relock pvt, revalidate identity (a masquerade
	 * or hangup may swap/clear owner in the window). */
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
		if (sofia_parse_sdp(pvt, sip, 1 /* offer: in-dialog re-INVITE */) < 0) {
			/* Encryption downgrade — reject 488, leave the live call up (RFC 3261 §14). */
			ast_mutex_unlock(&pvt->lock);
			if (owner) {
				ast_channel_unlock(owner);
				ast_channel_unref(owner);
			}
			ast_log(LOG_NOTICE, "Sofia: in-dialog re-INVITE rejected — encryption mismatch on '%s'\n",
				pvt->callid ? pvt->callid : "(no-callid)");
			{
				char rb[128] = "";	/* RFC 3326 Q.850 Reason (chan_sip parity); sofia_cfg read is lock-free */
				int hr = sofia_cfg.use_q850_reason && sofia_reason_build_for_status(488, rb, sizeof(rb));
				nua_respond(nh, SIP_488_NOT_ACCEPTABLE,
					NUTAG_WITH_THIS(nua), TAG_IF(hr, SIPTAG_REASON_STR(rb)), TAG_END());
			}
			return;
		}
	}
	/* SDP accepted — commit the deferred hold state. peer->onHold is gated on
	 * notifyhold (default 0); the AMI Hold below is UNCONDITIONAL. */
	pvt->hold_state = new_hold;
	if (trans && pvt->peer && sofia_cfg.notifyhold) {
		ast_atomic_fetchadd_int(&pvt->peer->onHold, new_hold ? +1 : -1);
	}
	if (trans && owner) {
		if (new_hold) {
			/* Propagate peer->mohsuggest to the bridged channel via the
			 * AST_CONTROL_HOLD data param (suggested MOH class). */
			const char *suggest = (pvt->peer && !ast_strlen_zero(pvt->peer->mohsuggest))
				? pvt->peer->mohsuggest : NULL;
			ast_queue_control_data(owner, AST_CONTROL_HOLD,
				S_OR(suggest, NULL),
				suggest ? strlen(suggest) + 1 : 0);
		} else {
			ast_queue_control(owner, AST_CONTROL_UNHOLD);
		}
	}
	sdp_ok = (sofia_generate_sdp(pvt, sdp_buf, sizeof(sdp_buf), 1 /* answer */) != NULL);
	ast_mutex_unlock(&pvt->lock);
	char contact_buf[1024];	/* sized for an opaque GRUU Contact (RFC 5627), not just sip:user@host */
	contact_buf[0] = '\0';
	/* GRUU + reload-UAF: hold peer->lock across sofia_build_contact (reads the pub_gruu /
	 * fromuser stringfields). Order is channel->peer here (pvt->lock already released above). */
	if (pvt->peer) {
		ast_mutex_lock(&pvt->peer->lock);
	}
	if (owner) {
		/* Snapshot identity + build Contact while owner is STILL LOCKED, so the
		 * connected.id read + AMI events can't race a post-unlock rename/hangup. */
		ast_copy_string(own_name, owner->name, sizeof(own_name));
		ast_copy_string(own_uniqueid, owner->uniqueid, sizeof(own_uniqueid));
		sofia_build_contact(pvt, contact_buf, sizeof(contact_buf));
		ast_channel_unlock(owner);
	} else {
		/* No owner: Contact uses the peer fallback (no owner deref). */
		sofia_build_contact(pvt, contact_buf, sizeof(contact_buf));
	}
	if (pvt->peer) {
		ast_mutex_unlock(&pvt->peer->lock);
	}

	if (sdp_ok) {
		/* A re-INVITE 200 OK is a target-refresh response (RFC 3261 §12.2.1.2);
		 * stamp Contact from pvt->ourip (see sofia_answer) so a multihomed bind
		 * doesn't move the target onto the wrong interface. */
		nua_respond(nh, SIP_200_OK,
			NUTAG_WITH_THIS(nua),
			TAG_IF(!ast_sockaddr_isnull(&pvt->ourip), SIPTAG_CONTACT_STR(contact_buf)),
			SIPTAG_CONTENT_TYPE_STR("application/sdp"),
			SIPTAG_PAYLOAD_STR(sdp_buf),
			TAG_END());
		/* This re-INVITE may have armed a fresh vrtp in sofia_parse_sdp (the non-BUNDLE video arm step) for an
		 * added/updated video, but — unlike sofia_answer — never activated it. For an a=setup:passive video
		 * offer our DTLS role is ACTIVE and the ClientHello only fires on activate, so video DTLS would never
		 * start. Activate now the 200 OK is out, mirroring sofia_answer; a duplicate activate is a no-op. */
		if (pvt->is_webrtc && pvt->webrtc_video_accepted && pvt->vrtp) {
			ast_rtp_instance_activate(pvt->vrtp);
		}
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

	/* SessionTimerRefresh AMI event for a uas-side refresh fire. */
	if (st_refresh) {
		/* Session-timer fields are read under pvt->lock by `sip show channels`
		 * off-thread, so write them under it (not held here). */
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

/* Handle an inbound in-dialog UPDATE (RFC 3311) — media renegotiation / hold / session-timer refresh
 * with NO dialog-state transition. Mirrors sofia_process_reinvite's validate-then-commit SDP path
 * (R7 doctrine: a rejected offer must not mutate live media), with two UPDATE-specific differences:
 * (1) RFC 3311 §5.2 / RFC 3261 §14.2 glare — if we already have an offer in flight (reinvite_pending),
 *     reject the incoming offer with 491 Request Pending;
 * (2) RFC 3311 §5.1 — a no-SDP UPDATE is a target-refresh, answered with a 200 OK carrying NO body.
 * The 200 carries a GRUU-aware target-refresh Contact (reuses sofia_build_contact). UPDATE is
 * NUTAG_APPL_METHOD'd, so the stack hands it here instead of auto-answering (chan_sofia owns SDP). */
static void sofia_process_update(struct sofia_pvt *pvt, nua_t *nua,
		nua_handle_t *nh, sip_t const *sip)
{
	char sdp_buf[4096];	/* WebRTC video (multi-PT rtcp-fb + ICE candidates) can exceed 2048 → SDP dropped fail-closed; RFC 8843/6184 headroom */
	struct ast_channel *owner = NULL;
	char own_name[80] = "";
	char own_uniqueid[150] = "";
	int old_hold = 0, new_hold = 0, trans = 0;
	int has_offer = (sip && sip->sip_payload && sip->sip_payload->pl_data);
	int sdp_ok = 0;
	int st_refresh = 0;
	int st_refresh_seconds = 0;
	const char *st_refresher_str = NULL;

	/* Session-Expires on an inbound UPDATE = uas-side refresh fire (RFC 4028 allows UPDATE refresh). */
	if (sip && sip->sip_session_expires) {
		st_refresh = 1;
		st_refresh_seconds = sip->sip_session_expires->x_delta;
		st_refresher_str = sip->sip_session_expires->x_refresher; /* NULL if absent */
	}

	if (!pvt) {
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, NUTAG_WITH_THIS(nua), TAG_END());
		return;
	}

	ast_mutex_lock(&pvt->lock);
	/* (1) Glare: an offer WE sent is still awaiting its answer — RFC 3311 §5.2 / RFC 3261 §14.2. */
	if (has_offer && pvt->reinvite_pending) {
		ast_mutex_unlock(&pvt->lock);
		nua_respond(nh, SIP_491_REQUEST_PENDING, NUTAG_WITH_THIS(nua), TAG_END());
		return;
	}
	/* (1b) Early-dialog SDP UPDATE: v1 has no early-media O/A tracking, so reject an offer before the
	 * dialog is confirmed — RFC 3311 §5.2 received-offer overlap = 500 + Retry-After (1s, in 0–10s).
	 * A no-SDP early UPDATE is a pure target-refresh and continues to a 200 below. */
	if (has_offer && pvt->state != SOFIA_DIALOG_STATE_UP) {
		ast_mutex_unlock(&pvt->lock);
		nua_respond(nh, 500, "Overlapping Offer/Answer",
			NUTAG_WITH_THIS(nua),
			SIPTAG_RETRY_AFTER_STR("1"),
			TAG_END());
		return;
	}
	/* Re-acquire owner in canonical channel->pvt order (sofia_process_reinvite idiom). */
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
	if (has_offer) {
		old_hold = pvt->hold_state;
		new_hold = sofia_sdp_extract_hold(sip, pvt->home);
		trans = (old_hold != new_hold);
		/* Preflight (R7): we can only answer if media exists (sofia_generate_sdp needs pvt->rtp);
		 * check BEFORE sofia_parse_sdp, which commits. */
		if (!pvt->rtp) {
			ast_mutex_unlock(&pvt->lock);
			if (owner) {
				ast_channel_unlock(owner);
				ast_channel_unref(owner);
			}
			nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, NUTAG_WITH_THIS(nua), TAG_END());
			return;
		}
		if (sofia_parse_sdp(pvt, sip, 1 /* offer: UPDATE with SDP */) < 0) {
			/* Unacceptable offer — reject 488, leave the live call untouched (RFC 3261 §14). */
			ast_mutex_unlock(&pvt->lock);
			if (owner) {
				ast_channel_unlock(owner);
				ast_channel_unref(owner);
			}
			ast_log(LOG_NOTICE, "Sofia: in-dialog UPDATE rejected — SDP not acceptable on '%s'\n",
				pvt->callid ? pvt->callid : "(no-callid)");
			{
				char rb[128] = "";	/* RFC 3326 Q.850 Reason (chan_sip parity) */
				int hr = sofia_cfg.use_q850_reason && sofia_reason_build_for_status(488, rb, sizeof(rb));
				nua_respond(nh, SIP_488_NOT_ACCEPTABLE, NUTAG_WITH_THIS(nua), TAG_IF(hr, SIPTAG_REASON_STR(rb)), TAG_END());
			}
			return;
		}
		/* Offer accepted — commit the deferred hold state + MOH (same as re-INVITE). */
		pvt->hold_state = new_hold;
		if (trans && pvt->peer && sofia_cfg.notifyhold) {
			ast_atomic_fetchadd_int(&pvt->peer->onHold, new_hold ? +1 : -1);
		}
		if (trans && owner) {
			if (new_hold) {
				const char *suggest = (pvt->peer && !ast_strlen_zero(pvt->peer->mohsuggest))
					? pvt->peer->mohsuggest : NULL;
				ast_queue_control_data(owner, AST_CONTROL_HOLD,
					S_OR(suggest, NULL), suggest ? strlen(suggest) + 1 : 0);
			} else {
				ast_queue_control(owner, AST_CONTROL_UNHOLD);
			}
		}
		sdp_ok = (sofia_generate_sdp(pvt, sdp_buf, sizeof(sdp_buf), 1 /* answer */) != NULL);
	}
	ast_mutex_unlock(&pvt->lock);

	char contact_buf[1024];	/* GRUU-aware target-refresh Contact (RFC 3311 §5.1) */
	contact_buf[0] = '\0';
	if (pvt->peer) {
		ast_mutex_lock(&pvt->peer->lock);
	}
	if (owner) {
		ast_copy_string(own_name, owner->name, sizeof(own_name));
		ast_copy_string(own_uniqueid, owner->uniqueid, sizeof(own_uniqueid));
		sofia_build_contact(pvt, contact_buf, sizeof(contact_buf));
		ast_channel_unlock(owner);
	} else {
		sofia_build_contact(pvt, contact_buf, sizeof(contact_buf));
	}
	if (pvt->peer) {
		ast_mutex_unlock(&pvt->peer->lock);
	}

	/* Reflect the peer's session-timer policy on the 2xx (RFC 4028 — UPDATE is a valid refresh method),
	 * mirroring sofia_answer; otherwise sofia-sip would stamp its default 1800/120 handle prefs. */
	int st_seconds, st_min_se, st_refresher;
	sofia_session_timer_values(pvt->peer, 0 /* inbound */, &st_seconds, &st_min_se, &st_refresher);

	if (has_offer) {
		if (sdp_ok) {
			nua_respond(nh, SIP_200_OK,
				NUTAG_WITH_THIS(nua),
				TAG_IF(!ast_sockaddr_isnull(&pvt->ourip), SIPTAG_CONTACT_STR(contact_buf)),
				TAG_IF(st_seconds >= 0, NUTAG_SESSION_TIMER(st_seconds)),
				TAG_IF(st_min_se > 0, NUTAG_MIN_SE(st_min_se)),
				TAG_IF(st_refresher >= 0, NUTAG_SESSION_REFRESHER(st_refresher)),
				SIPTAG_CONTENT_TYPE_STR("application/sdp"),
				SIPTAG_PAYLOAD_STR(sdp_buf),
				TAG_END());
			/* Like the re-INVITE path — activate the freshly armed vrtp after the 200 OK so an
			 * added-video UPDATE actually starts video DTLS (ACTIVE role fires its ClientHello on activate).
			 * Mirrors sofia_answer; a duplicate activate is a no-op. */
			if (pvt->is_webrtc && pvt->webrtc_video_accepted && pvt->vrtp) {
				ast_rtp_instance_activate(pvt->vrtp);
			}
		} else {
			nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, NUTAG_WITH_THIS(nua), TAG_END());
		}
	} else {
		/* (2) RFC 3311 §5.1: a no-SDP UPDATE is a target-refresh — 200 OK with NO body. */
		nua_respond(nh, SIP_200_OK,
			NUTAG_WITH_THIS(nua),
			TAG_IF(!ast_sockaddr_isnull(&pvt->ourip), SIPTAG_CONTACT_STR(contact_buf)),
			TAG_IF(st_seconds >= 0, NUTAG_SESSION_TIMER(st_seconds)),
			TAG_IF(st_min_se > 0, NUTAG_MIN_SE(st_min_se)),
			TAG_IF(st_refresher >= 0, NUTAG_SESSION_REFRESHER(st_refresher)),
			TAG_END());
	}

	if (trans) {
		ast_verbose("Sofia: in-dialog UPDATE on '%s' - hold=%d\n",
			pvt->callid ? pvt->callid : "(no-callid)", new_hold);
		if (owner) {
			manager_event(EVENT_FLAG_CALL, "Hold",
				"Status: %s\r\n"
				"Channel: %s\r\n"
				"Uniqueid: %s\r\n",
				new_hold ? "On" : "Off", own_name, own_uniqueid);
		}
	}

	/* SessionTimerRefresh AMI for a uas-side refresh fire via UPDATE (mirrors the re-INVITE path).
	 * Gated on a 2xx: a non-2xx UPDATE leaves session parameters unchanged (RFC 3311 §5.3), so an
	 * offer that failed to answer (500) must NOT bump the negotiated session timer. */
	if (st_refresh && (!has_offer || sdp_ok)) {
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
			own_name, own_uniqueid, pvt->peername, st_refresh_seconds,
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

	/* allowexternaldomains: reject INVITE to a non-local domain when domain_list is
	 * non-empty, the RURI domain is not in it, and !allow_external_domains. */
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
	/* SIP history: apply the capture filter now the call identity is known (source = From-user,
	 * destination = To/Request-URI user), then record the fresh inbound INVITE (this dialog has no
	 * central-hook pvt yet). do_history was provisionally the global at pvt creation; refine it here. */
	{
		const char *h_src = (sip && sip->sip_from && sip->sip_from->a_url)
			? S_OR(sip->sip_from->a_url->url_user, "") : "";
		const char *to_u = (sip && sip->sip_to && sip->sip_to->a_url)
			? S_OR(sip->sip_to->a_url->url_user, "") : "";
		/* Destination = both the To-user AND the Request-URI user (RFC 3261 §8.2.2.1: the R-URI is the
		 * resource to process the request). A routed INVITE can carry To=AOR but R-URI=the real exten. */
		const char *ru_u = (sip && sip->sip_request && sip->sip_request->rq_url)
			? S_OR(sip->sip_request->rq_url->url_user, "") : "";
		char h_dst[160];

		snprintf(h_dst, sizeof(h_dst), "%s %s", to_u, ru_u);
		pvt->do_history = sofia_history_should_record(h_src, h_dst);
	}
	if (sip && sip->sip_from && sip->sip_from->a_url) {
		sofia_append_history(pvt, "Rx INVITE", "from %s@%s",
			S_OR(sip->sip_from->a_url->url_user, ""), S_OR(sip->sip_from->a_url->url_host, ""));
	} else {
		sofia_append_history(pvt, "Rx INVITE", "fresh inbound");
	}
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
	pvt->dtmf_effective = pvt->dtmfmode;	/* default until the caller-peer bind (below) overrides */

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
			/* shrinkcallerid: strip before the username + cid_num assignments
			 * below so both reflect it. Default TRUE. */
			if (sofia_cfg.shrinkcallerid && ast_is_shrinkable_phonenumber(cid_num)) {
				ast_shrink_phone_number(cid_num);
			}
			ast_string_field_set(pvt, username, cid_num);
		}
		if (sip->sip_from->a_display) {
			snprintf(cid_name, sizeof(cid_name), "%.79s", sip->sip_from->a_display);
		}
		/* Seed cid_num/cid_name from From; sofia_get_rpid overrides later when
		 * peer->trustrpid=1 and PAI/RPID present. */
		ast_string_field_set(pvt, cid_num, cid_num);
		ast_string_field_set(pvt, cid_name, cid_name);
	}

	/* match_auth_username: override the peer-lookup key with the Authorization
	 * username (or Proxy-Authorization fallback) for the downstream find_peer. */
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

	/* Peer lookup + ACL run BEFORE sofia_parse_sdp so the encryption-policy check
	 * sees pvt->peer and banned IPs never trigger SRTP key generation. */
	{
		struct sofia_peer *caller_peer = NULL;
		if (cid_num[0]) {
			caller_peer = sofia_find_peer(cid_num);
			/* chan_sip FINDUSERS-then-FINDPEERS parity (chan_sip.c:16990-16997): only a type=user/friend
			 * may be identified by the From-user NAME. A type=peer whose name collides with the caller-ID
			 * (an inbound IP-trunk INVITE whose From-user equals a local extension that is itself a
			 * type=peer) must NOT match by name; it would steal
			 * the call and trigger a digest challenge the trunk can't answer. Drop it so the source-IP
			 * lookup below identifies the real sender (chan_sip matches peers by IP, users by name). */
			if (caller_peer && !(caller_peer->type & SOFIA_TYPE_USER)) {
				if (sofia_debug) {
					ast_verbose("Sofia: INVITE From-user '%s' matched a type=peer (not a user); discarding for source-IP match\n",
						cid_num);
				}
				ao2_ref(caller_peer, -1);
				caller_peer = NULL;
			}
		}
		if (!caller_peer) {
			/* From-username lookup failed → fall back to source-IP match so
			 * host=<ip> trunks (whose From-user is the caller-ID, not the peer name)
			 * are identified; else alwaysauthreject would 401 a trunk that can't answer. */
			struct ast_sockaddr src;
			sofia_get_source_addr(sip, &src);
			caller_peer = sofia_find_peer_by_ip(&src);
			if (!caller_peer) {
				/* Not cached in memory: resolve a not-yet-loaded realtime IP-trunk by its
				 * source IP+port (chan_sip realtime_peer_by_addr parity) so insecure=invite
				 * trunks defined only in realtime can place inbound calls. */
				caller_peer = sofia_find_peer_realtime_by_addr(&src);
			}
		}
		if (caller_peer) {
			if (caller_peer->ha) {
				struct ast_sockaddr src;
				sofia_get_source_addr(sip, &src);
				if (ast_apply_ha(caller_peer->ha, &src) != AST_SENSE_ALLOW) {
					ast_log(LOG_NOTICE, "Sofia: INVITE from %s rejected by peer '%s' ACL\n",
						ast_sockaddr_stringify(&src), caller_peer->name);
					/* Timing-equalize the ACL-deny vs auth-401-slow path, else
					 * ACL-403-fast is a peer-existence oracle defeating
					 * alwaysauthreject. The cheap dummy HMAC runs INLINE; the 403
					 * itself is deferred 10-50ms ASYNCHRONOUSLY (NON-blocking — the
					 * dispatcher is not parked). We snapshot nh/nua and pin the handle
					 * inside the scheduler, so we can drop OUR caller_peer/pvt refs and
					 * return immediately; the timer sends the 403 on sofia_thread.
					 *
					 * RESIDUAL-RACE FENCE: nua_handle_ref pins the handle MEMORY but not
					 * its NTA server request, so our ao2_ref(pvt,-1) below would run the
					 * destructor -> nua_handle_destroy -> nta_incoming_destroy auto-500,
					 * racing ahead of our timer. Pass `pvt` as pvt_ref so the scheduler
					 * takes an ADDITIONAL ao2 ref keeping the pvt (and thus the bound
					 * handle + its server request) alive until the 403 is queued; that
					 * extra ref is dropped at fire/immediate/failure/unload. */
					sofia_emit_timing_equalized_reject();
					sofia_delay_reject_schedule(SOFIA_DELAY_REJECT_403_FORBIDDEN,
						nua, nh, NULL, NULL, NULL, NULL, &src, pvt, 0);
					ao2_ref(caller_peer, -1);
					ao2_ref(pvt, -1);
					return;
				}
			}
			pvt->dtmfmode = caller_peer->dtmfmode;
			pvt->dtmf_effective = pvt->dtmfmode;	/* runtime = configured until AUTO resolves at SDP */
			sofia_dtmf_apply_property(pvt);		/* g3: rtp exists (rtp_init ran above); re-apply now the peer mode is bound */
			pvt->prefs = caller_peer->prefs;
			if (!ast_strlen_zero(caller_peer->context)) {
				ast_string_field_set(pvt, context, caller_peer->context);
			}
			pvt->allowtransfer = caller_peer->allowtransfer;
			ast_string_field_set(pvt, subscribecontext, caller_peer->subscribecontext);
			ast_string_field_set(pvt, accountcode, caller_peer->accountcode); /* → chan->accountcode via sofia_new */
			ao2_ref(caller_peer, +1); pvt->peer = caller_peer;
			ao2_ref(caller_peer, -1);
			/* GRUU co-req (RFC 5627 §4.4): advertise Supported: gruu on the responses we
			 * generate to this inbound INVITE from a GRUU peer. gruu is an int (benign lock-free read);
			 * nua adds the handle Supported pref to responses that lack one. */
			if (pvt->peer && pvt->peer->gruu) {
				nua_set_hparams(nh, NUTAG_SUPPORTED("gruu"), TAG_END());
			}
			/* 100rel/PRACK (RFC 3262): when rel100=yes, send NON-183 provisionals (180 Ringing etc.)
			 * RELIABLY to this peer — NUTAG_EARLY_MEDIA makes nua add Require: 100rel + RSeq and await
			 * the PRACK (sofia's native reliable-response machinery; sofia_process_prack 200s it). The
			 * 183 early-media is already reliable when the caller advertises 100rel. */
			if (pvt->peer && pvt->peer->rel100) {
				nua_set_hparams(nh, NUTAG_EARLY_MEDIA(1), TAG_END());
			}
		}
	}

	/* INVITE digest auth (ACL-before-auth ordering preserved; pre-auth state is
	 * refcount + dialog-scoped only, no peer mutation). Three tiers:
	 * (1) force_invite_auth — global lockdown, auth required regardless of insecure=invite.
	 * (2) per-peer insecure=invite — bypass for trusted-IP trunks + AMI InsecureInviteBypass.
	 * (3) sofia_verify_digest_auth — sip_authorization, falling back to proxy_authorization.
	 * Unknown peer (NULL): falls to the alwaysauthreject/guest branches below. */
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
			/* auth_required stays 1. */
		} else if (pvt->peer->insecure & SOFIA_INSECURE_INVITE) {
			struct ast_sockaddr src;
			char addr_buf[80];
			sofia_get_source_addr(sip, &src);
			ast_copy_string(addr_buf, ast_sockaddr_stringify(&src), sizeof(addr_buf));
			/* Cosmetic bypass trace (debug-gated); AMI InsecureInviteBypass below
			 * is the auditable surface. */
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
		/* No credential at all (neither secret nor md5secret) -> accept without auth,
		 * matching the REGISTER (chan_sofia.c:8597) and SUBSCRIBE (chan_sofia.c:10053)
		 * guards. Without this short-circuit a credential-less peer's INVITE still ran
		 * through sofia_verify_digest_auth and logged/behaved as 'authenticated' — net
		 * access is identical (the documented no-secret behavior), but the digest path's
		 * accounting is misleading. md5secret IS a credential, so a md5secret-only peer
		 * still takes the digest path below. Cosmetic/consistency — no privilege boundary
		 * crossed. */
		if (auth_required
				&& ast_strlen_zero(pvt->peer->secret)
				&& ast_strlen_zero(pvt->peer->md5secret)) {
			if (sofia_debug) {
				ast_verbose("Sofia: INVITE from peer '%s' accepted without auth — "
					"no secret/md5secret configured\n", pvt->peer->name);
			}
			auth_required = 0;
		}
		if (auth_required) {
			char realm_buf[MAXHOSTNAMELEN];
			const char *realm = sofia_get_realm_for_dialog(sip, realm_buf, sizeof(realm_buf));
			/* sip_authorization, falling back to proxy_authorization (RFC 3261 §22). */
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
		/* Unknown peer: challenge (fresh nonce + timing-equalized) so the response
		 * is indistinguishable from known-peer-bad-password (RFC 3261 §22.4).
		 *
		 * RESIDUAL-RACE FENCE: nh is bound to this fresh pvt, so our ao2_ref(pvt,-1)
		 * below would run the destructor -> nua_handle_destroy -> nta_incoming_destroy
		 * auto-500, racing ahead of the deferred 401 timer. Pass `pvt` as pvt_ref so the
		 * scheduler takes an ADDITIONAL ao2 ref pinning the pvt (and its bound handle +
		 * NTA server request) until the 401 is queued; dropped at fire/immediate/failure/
		 * unload. No reap flag — the handle is BOUND, the pvt owns its destruction. */
		char realm_buf[MAXHOSTNAMELEN];
		const char *realm = sofia_get_realm_for_dialog(sip, realm_buf, sizeof(realm_buf));
		sofia_send_auth_challenge(nua, nh, sip, realm, "INVITE", "UnknownPeer", pvt, 0);
		ao2_ref(pvt, -1);
		return;
	} else if (!sofia_cfg.allowguest) {
		/* allowguest=no: 403 an unknown caller rather than route it to the dialplan
		 * (toll-fraud). IP-validated peers matched non-NULL upstream and skip this. */
		ast_log(LOG_NOTICE, "Sofia: INVITE from unknown peer rejected — allowguest=no\n");
		nua_respond(nh, SIP_403_FORBIDDEN, NUTAG_WITH_THIS(nua), TAG_END());
		ao2_ref(pvt, -1);
		return;
	}

	/* Enable inband DTMF after pvt->dtmfmode is bound; gates on INBAND/AUTO. */
	sofia_enable_dsp_detect(pvt);

	/* Inbound RPID/PAI/Privacy (trust-gated by peer->trustrpid; PAI fallback). Before sofia_new so
	 * chan->caller.id picks it up via ast_set_callerid below. */
	int rpid_updated = sofia_get_rpid(pvt, sip);

	/* apply_peer_callerid (chan_sip.c:17113-17124 parity): when no trusted RPID/PAI was accepted,
	 * force the matched peer's configured caller-id (cid_num / cid_name / callingpres) onto the call,
	 * overriding the inbound From seeded above. Each field is applied only when non-empty/non-zero, and
	 * all three are gated on !rpid exactly like chan_sip (a trusted RPID/PAI wins). Default on (chan_sip).
	 * Peer stringfields are freeable → snapshot under peer->lock (leaf; owner not yet allocated). */
	if (sofia_cfg.apply_peer_callerid && !rpid_updated && pvt->peer) {
		char pc_num[80] = "", pc_name[80] = "";
		int pc_pres;
		ast_mutex_lock(&pvt->peer->lock);
		ast_copy_string(pc_num, S_OR(pvt->peer->cid_num, ""), sizeof(pc_num));
		ast_copy_string(pc_name, S_OR(pvt->peer->cid_name, ""), sizeof(pc_name));
		pc_pres = pvt->peer->callingpres;
		ast_mutex_unlock(&pvt->peer->lock);
		if (!ast_strlen_zero(pc_num)) {
			if (sofia_cfg.shrinkcallerid && ast_is_shrinkable_phonenumber(pc_num)) {
				ast_shrink_phone_number(pc_num);
			}
			ast_string_field_set(pvt, cid_num, pc_num);
		}
		if (!ast_strlen_zero(pc_name)) {
			ast_string_field_set(pvt, cid_name, pc_name);
		}
		if (pc_pres) {
			pvt->callingpres = pc_pres;
		}
	}

	/* Inbound call-limit enforcement → 480. The reason text trailing space is
	 * VERBATIM (operator scripts pattern-match it). pvt not yet in dialogs → only
	 * the ao2_ref drop on reject (destructor DEC is a no-op, call_inc_done=0). */
	if (sofia_update_call_counter(pvt, SOFIA_INC_CALL_LIMIT) == -1) {
		ast_log(LOG_NOTICE, "Sofia: inbound INVITE from peer '%s' rejected — call_limit %d reached\n",
			pvt->peer->name, pvt->peer->call_limit);
		{
			char rb[128] = "";	/* RFC 3326 Q.850 Reason (chan_sip parity) */
			int hr = sofia_cfg.use_q850_reason && sofia_reason_build_for_status(480, rb, sizeof(rb));
			nua_respond(nh, 480, "Temporarily Unavailable (Call limit) ",
				NUTAG_WITH_THIS(nua), TAG_IF(hr, SIPTAG_REASON_STR(rb)), TAG_END());
		}
		ao2_ref(pvt, -1);
		return;
	}

	/* allowoverlap=YES + partial (canmatch but not exact) extension → 484 before
	 * sofia_new. DTMF/NO fall through (the PBX 404s if truly absent). pvt not yet in
	 * dialogs → ao2_ref drop. */
	{
		int overlap_mode = pvt->peer ? pvt->peer->allowoverlap_mode : sofia_cfg.default_allowoverlap_mode;
		if (overlap_mode == SOFIA_OVERLAP_YES
		    && !ast_strlen_zero(pvt->exten)
		    && !ast_exists_extension(NULL, pvt->context, pvt->exten, 1, S_OR(pvt->cid_num, NULL))
		    && ast_canmatch_extension(NULL, pvt->context, pvt->exten, 1, S_OR(pvt->cid_num, NULL))) {
			char rb[128] = "";	/* RFC 3326 Q.850 Reason (chan_sip parity) */
			int hr = sofia_cfg.use_q850_reason && sofia_reason_build_for_status(484, rb, sizeof(rb));
			ast_log(LOG_NOTICE, "Sofia: inbound INVITE exten '%s'@'%s' partial-match — 484 Address Incomplete (overlap=yes)\n",
				pvt->exten, pvt->context);
			nua_respond(nh, SIP_484_ADDRESS_INCOMPLETE,
				NUTAG_WITH_THIS(nua), TAG_IF(hr, SIPTAG_REASON_STR(rb)), TAG_END());
			ao2_ref(pvt, -1);
			return;
		}
	}

	/* Reject unknown inbound destinations before channel/PBX alloc; in the default
	 * context count it as a blacklist failure. */
	if (!ast_strlen_zero(pvt->exten)
	    && !ast_exists_extension(NULL, pvt->context, pvt->exten, 1, S_OR(pvt->cid_num, NULL))
	    && !ast_canmatch_extension(NULL, pvt->context, pvt->exten, 1, S_OR(pvt->cid_num, NULL))) {
		ast_log(LOG_NOTICE, "Sofia: call from '%s' to extension '%s' rejected because extension not found in context '%s'\n",
			S_OR(pvt->cid_num, pvt->peername), pvt->exten, pvt->context);
		if (!strcasecmp(pvt->context, sofia_cfg.context)) {
			sofia_blacklist_add_sip(sip, "INVITE unknown extension in default context");
		}
		sofia_update_call_counter(pvt, SOFIA_DEC_CALL_LIMIT);
		{
			/* RFC 3326 Q.850 Reason on the 404 reject (chan_sip parity). A well-formed
			 * SIPTAG_REASON_STR is delivered as a Reason header on a UAS reject response. */
			char reason_buf[128] = "";
			int have_reason = sofia_cfg.use_q850_reason
				&& sofia_reason_build_for_status(404, reason_buf, sizeof(reason_buf));
			nua_respond(nh, SIP_404_NOT_FOUND, NUTAG_WITH_THIS(nua),
				TAG_IF(have_reason, SIPTAG_REASON_STR(reason_buf)), TAG_END());
		}
		ao2_ref(pvt, -1);
		return;
	}

	if (sip->sip_payload && sip->sip_payload->pl_data) {
		if (sofia_parse_sdp(pvt, sip, 1 /* offer: initial inbound INVITE */) < 0) {
			/* Encryption/codec mismatch → 488. RFC 3326 Q.850 Reason (chan_sip parity).
			 * Free srtp/vsrtp explicitly. */
			char rb[128] = "";
			int hr = sofia_cfg.use_q850_reason && sofia_reason_build_for_status(488, rb, sizeof(rb));
			ast_log(LOG_NOTICE, "Sofia: 488 reject — encryption mismatch (peer=%s, peer_encryption=%d)\n",
				pvt->peer ? pvt->peer->name : "<unknown>",
				pvt->peer ? pvt->peer->encryption : 0);
			nua_respond(nh, SIP_488_NOT_ACCEPTABLE,
				NUTAG_WITH_THIS(nua), TAG_IF(hr, SIPTAG_REASON_STR(rb)), TAG_END());
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

	/* comedia: prefill the RTP remote from the SIP source. For a WebRTC leg this is the INITIAL/provisional
	 * remote so DTLS/media has a destination BEFORE the ICE connectivity check latches; the res_rtp
	 * authenticated-STUN latch (LATCH-ALWAYS) then CORRECTS it to the real ICE-validated media source. This
	 * mirrors FreeSWITCH, which prefills the WebRTC remote from the highest-priority SDP ICE candidate and lets
	 * the STUN latch correct it (switch_core_media.c check_ice / activate_rtp -> switch_rtp change_ice_dest),
	 * and it disables comedia ONLY because that candidate prefill already ran. WITHOUT a prefill, audio-only
	 * WebRTC is DEAF until the first STUN (empirically confirmed: dropping this made it deaf; video
	 * masked it via extra ICE activity). So comedia MUST run for WebRTC too — the latch owns the final tuple. */
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

	/* Set active contact by matching source addr to peer contacts. */
	if (pvt->peer) {
		struct ast_sockaddr src;
		sofia_get_source_addr(sip, &src);
		struct sofia_contact *contact = sofia_peer_find_contact_by_addr(pvt->peer, &src);
		if (contact) {
			sofia_pvt_set_active_contact(pvt, contact);
			ao2_ref(contact, -1);
		}
	}

	/* No explicit 100 Trying here: the SIP stack's transaction layer already auto-sends one the instant
	 * the INVITE server transaction is created (immediate), so a manual nua_respond(SIP_100_TRYING) only
	 * added a redundant duplicate 100 on the wire. The stack's automatic (and earlier) 100 is the
	 * legitimate one. */

	chan = sofia_new(pvt, AST_STATE_RING, NULL);
	if (!chan) {
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
		ao2_ref(pvt, -1);
		return;
	}

	pvt->owner = chan;

	/* Apply pvt->cid_num/cid_name/callingpres to the channel (pvt is
	 * source-of-truth; sofia_get_rpid may have overwritten the From seed). */
	if (!ast_strlen_zero(pvt->cid_num)) {
		ast_set_callerid(chan, pvt->cid_num,
			!ast_strlen_zero(pvt->cid_name) ? pvt->cid_name : NULL,
			pvt->cid_num);
		chan->caller.id.number.presentation = pvt->callingpres;
		chan->caller.id.name.presentation = pvt->callingpres;
	}

	/* Inbound Diversion → pvt->owner->redirecting. After the pvt->owner=chan
	 * binding so the vars land on the channel. */
	sofia_change_redirecting_info(pvt, pvt->owner, sip);

	ao2_link(dialogs, pvt);

	if (ast_pbx_start(chan)) {
		ast_log(LOG_ERROR, "Failed to start PBX on incoming Sofia call\n");
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
		/* A final (500) was just sent to the inbound INVITE; mark it so the ast_hangup
		 * below (which re-enters sofia_hangup pre-answer) does not emit a second final. */
		sofia_mark_uas_final_sent(pvt);
		ast_hangup(chan);
	}
}

static void sofia_process_bye(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	/* Do NOT respond here: BYE is NOT in our NUTAG_APPL_METHOD set, so sofia-sip's nua stack ALWAYS sends
	 * the 200 OK to a BYE itself (nua_server.c:382-384; nua_i_bye carries the already-sent status,
	 * nua_session.c:3933-3966). nua_i_bye is purely informational. A manual nua_respond() here targets an
	 * already-finalized transaction -> no-op or the 500 "Responding to a Non-Existing Request" /
	 * "Already Sent Final Response" path (nua_server.c:432-440). RFC 3261 §15.1.2: a BYE MUST get a 2xx —
	 * the stack does it. (FreeSWITCH keeps manual BYE behind #ifdef MANUAL_BYE, off by default.) */

	/* Call-counter DEC (flag-gated so the eventual sofia_hangup DEC is a no-op). */
	if (op) {
		sofia_update_call_counter(op, SOFIA_DEC_CALL_LIMIT);
	}

	/* Expected REFER transferer-leg BYE (RFC 5589 §6.1): cancel the safety-net
	 * timer + unlink. Channel side already detached in sofia_hangup. */
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
		/* Q.850 Reason (RFC 3326): map a received Reason: Q.850;cause=N to the AST hangup cause so
		 * the CDR reflects the real reason. 0 (none/off) keeps the channel's existing cause. */
		int q850 = (sofia_cfg.use_q850_reason && sip) ? sofia_reason_parse_cause(sip->sip_reason) : 0;
		/* TOCTOU/UAF: snapshot+ref op->owner under op->lock, queue outside it
		 * (ast_queue_hangup locks the channel → holding op->lock would invert). */
		struct ast_channel *owner;
		ast_mutex_lock(&op->lock);
		owner = op->owner;
		if (owner) {
			ast_channel_ref(owner);
		}
		ast_mutex_unlock(&op->lock);
		if (owner) {
			if (q850) {
				ast_queue_hangup_with_cause(owner, q850);
			} else {
				ast_queue_hangup(owner);
			}
			ast_channel_unref(owner);
		}
	}
}

static void sofia_process_cancel(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	/* Do NOT respond here: CANCEL is NOT in our NUTAG_APPL_METHOD set, so sofia-sip's nua stack answers
	 * the CANCEL (200) AND sends 487 to the cancelled INVITE itself (nua_server.c:382-384;
	 * nua_session.c:2718-2751). nua_i_cancel is informational (carries the already-sent 200 status). A
	 * manual nua_respond() here double-responds an already-finalized transaction (500 "Responding to a
	 * Non-Existing Request"). RFC 3261 §9.2: the CANCEL is answered + the INVITE gets 487 — the stack
	 * does both. (FreeSWITCH's nua_i_cancel does bookkeeping only, no nua_respond.) */

	if (op) {
		/* Q.850 Reason (RFC 3326): use a received cause as the hangup cause, else NORMAL_CLEARING. */
		int q850 = (sofia_cfg.use_q850_reason && sip) ? sofia_reason_parse_cause(sip->sip_reason) : 0;
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
			ast_queue_hangup_with_cause(owner, q850 ? q850 : AST_CAUSE_NORMAL_CLEARING);
			ast_channel_unref(owner);
		}
	}
}

static void sofia_process_options(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	nua_respond(nh, SIP_200_OK,
		SIPTAG_ALLOW_STR("INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER, "
				"SUBSCRIBE, NOTIFY, REFER, MESSAGE, INFO, PRACK, UPDATE"),	/* no PUBLISH (we 405 it) */
		SIPTAG_ACCEPT_STR("application/sdp"),
		TAG_END());
}

/* Append to pvt->initreq_headers, preserving wire order so SIP_HEADER(name, N)
 * returns the Nth occurrence. */
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

/* Snapshot inbound INVITE headers for dialplan ${SIP_HEADER(name)}: From/To/
 * Call-ID/Contact/Via/User-Agent/Subject + every sip_unknown entry (X-*, PAI,
 * RPID, Diversion — sofia parks unrecognized headers there). Caller owns pvt. */
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

/* Add name to domain_list if non-empty and not already present. */
static void sofia_domain_list_add(const char *name)
{
	struct sofia_domain *d;

	if (ast_strlen_zero(name)) {
		return;
	}
	if (sofia_check_sip_domain(name)) {
		return;
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

/* Returns 1 if domain matches a configured domain_list entry, else 0. */
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

/* ${CHECKSIPDOMAIN(domain)} — the domain if it is in domain_list, else empty. */
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

/* ${SIPPEER(peername[,item])} — read a peer config field; item defaults to "ip",
 * unknown item → empty buf + 0. */
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

	/* reload-UAF: hold peer->lock across the whole freeable-stringfield read region
	 * (runs on the dialplan thread). Leaf here (contact ops take only ao2_lock(c));
	 * unlock before ao2_ref(peer,-1). No early returns → no leak. */
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
	} else if (!strcasecmp(colname, "message_context")) {
		ast_copy_string(buf, peer->message_context, len);
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

/* ${SIPCHANINFO(item)} — current Sofia channel info. peerip + recvip both map to
 * last_src_addr (the NUA layer hides the chan_sip SDP-c=-vs-rport distinction). */
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
		/* Snapshot peer->name under peer->lock (reload-UAF; pvt->lock doesn't cover it). */
		if (pvt->peer) {
			char l_peername[256];
			ast_mutex_lock(&pvt->peer->lock);
			ast_copy_string(l_peername, pvt->peer->name, sizeof(l_peername));
			ast_mutex_unlock(&pvt->peer->lock);
			ast_copy_string(buf, l_peername, len);
		}
	} else if (!strcasecmp(data, "t38passthrough")) {
		/* Not exposed via SIPCHANINFO yet; reports 0 for compatibility. */
		ast_copy_string(buf, "0", len);
	}
	/* unknown item -> empty buf + return 0 (chan_sip parity) */
	ast_mutex_unlock(&pvt->lock);
	return 0;
}

static struct ast_custom_function sofia_sipchaninfo_function = {
	.name = "SIPCHANINFO",
	.read = func_sofia_sipchaninfo,
};

/* Source IP:port from an inbound SIP message (Via received/rport). Always nulls
 * addr on every early return so callers never read stack garbage. */
void sofia_get_source_addr(sip_t const *sip, struct ast_sockaddr *addr)
{
	sip_via_t const *via;

	if (!addr)
		return;
	ast_sockaddr_setnull(addr);

	if (!sip)
		return;

	via = sip->sip_via;
	if (!via)
		return;

	if (via->v_received) {
		const char *src_port = via->v_rport ? via->v_rport : via->v_port;
		char addr_str[256];
		/* IPv6 literals MUST be bracketed before ast_sockaddr_parse (RFC 3261 §19.1.2 /
		 * RFC 5952): an unbracketed "fe80::1:5060" is ambiguous (the colons run together),
		 * yielding a wrong/empty addr that corrupts the blacklist key + host= ACL match. */
		if (strchr(via->v_received, ':')) {
			snprintf(addr_str, sizeof(addr_str), "[%s]:%s",
				via->v_received, src_port ? src_port : "5060");
		} else {
			snprintf(addr_str, sizeof(addr_str), "%s:%s",
				via->v_received, src_port ? src_port : "5060");
		}
		ast_sockaddr_parse(addr, addr_str, 0);
		if (sofia_debug)
			ast_verbose("Sofia: source addr (via received): %s\n", addr_str);
	} else {
		const char *host = via->v_host;
		const char *port = via->v_rport ? via->v_rport : via->v_port;
		char addr_str[256];
		if (!host)
			return;
		/* Same IPv6 bracketing for the Via host branch. */
		if (strchr(host, ':')) {
			snprintf(addr_str, sizeof(addr_str), "[%s]:%s", host, port ? port : "5060");
		} else {
			snprintf(addr_str, sizeof(addr_str), "%s:%s", host, port ? port : "5060");
		}
		ast_sockaddr_parse(addr, addr_str, 0);
		if (sofia_debug)
			ast_verbose("Sofia: source addr (via host): %s\n", addr_str);
	}
}


/* Parse a Contact URL port to [0,65535], default 5060 (RFC 3261 §19.1.2) on
 * NULL/empty/non-numeric/out-of-range. Shared so ACL/c->port/URI key normalize alike. */
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
	/* Normalize the port so the URI key matches c->port. */
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
	/* ignoreregexpire (chan_sip parity): keep last-known contact across short
	 * upstream-trunk outages. */
	if (sofia_cfg.ignore_regexpire) {
		return 0;
	}
	if (c->expires > 0 && c->expires < *now) {
		ast_verbose("Sofia: Expiring contact %s\n", c->contact_uri);
		return CMP_MATCH;
	}
	return 0;
}

/* Contact-ACL check for ONE Contact URL (REGISTER preflights every Contact).
 * Returns 0 = allowed, -1 = denied; allows when no ACL is configured. */
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
	cport = sofia_contact_url_port(url->url_port);
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
		/* FAIL CLOSED: ast_sockaddr_parse is numeric-only; reject a non-IP host
		 * rather than do a blocking DNS lookup on the single sofia_thread. */
		ast_log(LOG_NOTICE, "Sofia: REGISTER from peer '%s' Contact %s has a non-IP host with contact-ACL configured — rejecting (fail-closed)\n",
			peer->name, uri);
		return -1;
	}
	return 0;
}

/* ============ RFC 5626 Complement B: flow-close contact cleanup, via sofia's BUILT-IN registrar watch ========
 * sofia-sip's nua_registrar_server_preprocess (libsofia-sip-ua/nua/nua_registrar.c) already arms a tport_pend on
 * the connection a connection-oriented (tcp/tls/ws/wss) REGISTER physically arrived on - ON THE STACK THREAD that
 * owns the tports - gated on tport_is_tcp, and on connection CLOSE fires nua_i_media_error on that REGISTER handle,
 * which nua MARSHALS to sofia_thread. We never touch any tport_* from chan_sofia (the event thread); we only own
 * the REGISTER handle lifecycle and react to the marshalled event (RFC 5626 6). An earlier design that called
 * tport_pend/tport_by_name from sofia_process_register was cross-thread-unsafe (sofia_thread is the nua EVENT
 * thread, NOT the tport-owning stack thread) and has been removed.
 *
 * We retain the REGISTER handle ONLY for a SUCCESSFUL, SINGLE-Contact, connection-oriented binding (multi-Contact
 * REGISTERs and udp fall back to expiry + max_contacts - one handle must never be claimed by several contacts).
 * The handle is tracked in a global ao2 registry KEYED BY THE HANDLE POINTER; no nh_magic is bound, so the
 * media_error handler does a type-safe pointer-membership lookup and never dereferences an untyped hmagic. The
 * contact stores reg_nh and is the SOLE dropper: on supersede (refresh/rebind) and on every removal path via the
 * contact destructor, the registry entry is unlinked and the handle destroyed (deferred to sofia_thread) - exactly
 * once. media_error only UNLINKS the matched contact (-> destructor drops the handle). Orphaned registrar handles
 * (the 401-challenge / multi-Contact / non-stored ones, which the built-in watch also arms with hmagic=NULL) are
 * destroyed when their own media_error fires, so none leak. */

#define SOFIA_REGFLOW_BUCKETS 4093		/* prime */
static struct ao2_container *sofia_regflow_handles;	/* nua_handle_t* (offset 0) -> {peer_name, contact_uri} */
static volatile int sofia_regflow_shutdown;		/* set after su_root_run() returns: do not dispatch destroys to a stopped root */

struct sofia_regflow_entry {
	nua_handle_t *nh;		/* KEY at offset 0: the retained REGISTER handle */
	char peer_name[128];		/* re-locate the peer via sofia_find_peer_cached() on close */
	char contact_uri[256];		/* re-locate the binding in peer->contacts */
	unsigned int dropping:1;	/* destroy queued: the entry stays linked until the task runs (under the entry ao2 lock) */
};

static int sofia_regflow_hash(const void *obj, int flags)
{
	/* obj is a real entry on link, or a stack key {nh} on a find; nh at offset 0 makes both work. */
	return (int) (((uintptr_t) ((const struct sofia_regflow_entry *) obj)->nh) >> 4);
}
static int sofia_regflow_cmp(void *obj, void *arg, int flags)
{
	const struct sofia_regflow_entry *e = obj, *key = arg;
	return (e->nh == key->nh) ? (CMP_MATCH | CMP_STOP) : 0;
}

static int sofia_transport_is_connection_oriented(const char *t)
{
	return t && (!strcasecmp(t, "tcp") || !strcasecmp(t, "tls")
		|| !strcasecmp(t, "ws") || !strcasecmp(t, "wss"));
}

/* Deferred (sofia_thread) destroy of a retained REGISTER handle. Runs once per entry: UNLINK the registry entry
 * HERE (not in drop), so that during the dispatch window a duplicate nua_i_media_error for the same handle still
 * finds the entry (marked `dropping`) and is consumed without an orphan-destroy -> no double free. No nh_magic is
 * bound, so this is just the handle destroy; it must not run inside the handle's own event callback, hence deferred. */
static void sofia_regflow_destroy_task(void *data)
{
	struct sofia_regflow_entry *e = data;
	if (sofia_regflow_handles) {
		ao2_unlink(sofia_regflow_handles, e);	/* drop the container ref now that the duplicate window is closing */
	}
	nua_handle_destroy(e->nh);
	ao2_ref(e, -1);					/* TASK ref -> may free e */
}

/* Drop a retained REGISTER handle: mark its entry `dropping` and queue the destroy task (which unlinks + destroys
 * exactly once). The entry stays in the registry until the task runs (so a duplicate media_error is consumed, not
 * orphan-destroyed). ANY thread (the contact destructor may run off sofia_thread). At/after shutdown the root is
 * stopped: leave the entry for sofia_regflow_teardown_all() / nua_destroy(). Idempotent per entry. */
static void sofia_regflow_drop(nua_handle_t *nh)
{
	struct sofia_regflow_entry key, *e;
	int queue = 0;
	if (!nh || !sofia_regflow_handles) {
		return;
	}
	key.nh = nh;
	if (!(e = ao2_find(sofia_regflow_handles, &key, OBJ_POINTER))) {
		return;					/* not tracked by us (link failed / already torn down) */
	}
	ao2_lock(e);
	if (!e->dropping) {
		e->dropping = 1;
		ao2_ref(e, +1);				/* TASK ref: pin e (and its registry slot) until the task runs */
		queue = 1;
	}
	ao2_unlock(e);
	if (sofia_forkdebug) {
		char cbuf[256];
		SOFIA_FORKDBG("regflow-drop nh=%p peer=%s contact=%s will_teardown=%d shutdown=%d",
			(void *)nh, e->peer_name, sofia_uri_redact(e->contact_uri, cbuf, sizeof(cbuf)),
			queue, sofia_regflow_shutdown);
	}
	ao2_ref(e, -1);					/* finder */
	if (!queue) {
		return;					/* another drop already owns the teardown */
	}
	if (sofia_regflow_shutdown) {
		/* root stopped: leave the entry for sofia_regflow_teardown_all() / nua_destroy() (expected, silent). */
		ao2_lock(e);
		e->dropping = 0;
		ao2_unlock(e);
		ao2_ref(e, -1);				/* undo task ref */
		return;
	}
	if (sofia_dispatch_to_root_thread(sofia_regflow_destroy_task, e) < 0) {
		ast_log(LOG_WARNING, "Sofia flow-watch: handle-destroy dispatch failed; reaped at teardown\n");
		ao2_lock(e);
		e->dropping = 0;
		ao2_unlock(e);
		ao2_ref(e, -1);				/* undo task ref */
	}
}

/* Retain this REGISTER handle as the flow-watch owner of contact `c`, superseding any previous handle. sofia_thread
 * under peer->lock. ONLY a SUCCESSFUL single-Contact connection-oriented binding (one handle must never be claimed
 * by several contacts; the built-in watch only arms tport_is_tcp transports). */
static void sofia_regflow_attach(struct sofia_peer *peer, struct sofia_contact *c, nua_handle_t *nh,
	const char *reg_transport, int single_contact)
{
	struct sofia_regflow_entry *e;

	if (!nh || !single_contact || !sofia_regflow_handles
			|| !sofia_transport_is_connection_oriented(reg_transport)) {
		return;					/* udp / multi-Contact / no handle: rely on expiry + max_contacts */
	}
	if (c->reg_nh == nh) {
		return;					/* this REGISTER transaction already owns the contact */
	}
	e = ao2_alloc(sizeof(*e), NULL);
	if (!e) {
		return;					/* fail-safe: no watch -> expiry cleans up */
	}
	e->nh = nh;
	ast_copy_string(e->peer_name, peer->name, sizeof(e->peer_name));
	ast_copy_string(e->contact_uri, c->contact_uri, sizeof(e->contact_uri));
	if (c->reg_nh) {
		sofia_regflow_drop(c->reg_nh);		/* supersede: tear down the previous handle */
		c->reg_nh = NULL;			/* unpublish the old before linking the new */
	}
	if (!ao2_link(sofia_regflow_handles, e)) {
		ao2_ref(e, -1);				/* link failed (OOM) -> free the entry, leave the contact unwatched */
		return;					/* reg_nh stays NULL -> expiry fallback (no dangling reg_nh) */
	}
	ao2_ref(e, -1);					/* the container holds the ref */
	c->reg_nh = nh;					/* publish ONLY after a successful link */
	if (sofia_debug) {
		ast_verbose("Sofia: flow-watch attached nh=%p to contact %s\n", (void *) nh, c->contact_uri);
	}
}

/* The single free-path hook: drop the retained REGISTER handle when the contact's last ref goes (any thread). */
static void sofia_contact_destructor(void *obj)
{
	struct sofia_contact *c = obj;
	if (c->reg_nh) {
		nua_handle_t *nh = c->reg_nh;
		c->reg_nh = NULL;			/* refcount 0 here -> exclusively owned; no lock needed */
		sofia_regflow_drop(nh);
	}
}

/* After su_root_run() returns (before nua_destroy): clear every retained reg_nh reachable from `peers` and drop
 * its registry entry, so the later off-thread contact destructors do not dispatch to a stopped root. nua_destroy()
 * reaps the handles. A peer still pinned by an in-call pvt is not walked (bounded process-exit residual). */
static void sofia_regflow_teardown_all(void)
{
	struct ao2_iterator pi;
	struct sofia_peer *peer;
	if (!peers) {
		return;
	}
	pi = ao2_iterator_init(peers, 0);
	while ((peer = ao2_iterator_next(&pi))) {
		struct ao2_iterator ci;
		struct sofia_contact *c;
		ast_mutex_lock(&peer->lock);
		ci = ao2_iterator_init(peer->contacts, 0);
		while ((c = ao2_iterator_next(&ci))) {
			if (c->reg_nh) {
				struct sofia_regflow_entry key, *e;
				if (sofia_regflow_handles) {
					key.nh = c->reg_nh;
					if ((e = ao2_find(sofia_regflow_handles, &key, OBJ_POINTER))) {
						ao2_unlink(sofia_regflow_handles, e);
						ao2_ref(e, -1);
					}
				}
				c->reg_nh = NULL;	/* nua_destroy() reaps the handle */
			}
			ao2_ref(c, -1);
		}
		ao2_iterator_destroy(&ci);
		ast_mutex_unlock(&peer->lock);
		ao2_ref(peer, -1);
	}
	ao2_iterator_destroy(&pi);
}

/* RFC 3261 §10.3 de-register ONE Contact binding (its requested expiry is 0): find the matching binding —
 * exact URI, else RFC 5626 +sip.instance/reg-id, else a single-Contact Call-ID, else the NAT src-IP+UA
 * fallback (a rotator may de-register with a CHANGED Contact URI/source) — and unlink it. `n_contacts` is the
 * REGISTER's Contact count (gates the single-Contact-only tiers). Caller holds peer->lock. Shared by the
 * global Expires:0 de-register loop and the per-Contact ;expires=0 case in the binding loop. */
static void sofia_deregister_one_contact(struct sofia_peer *peer, sip_t const *sip, sip_contact_t const *m,
	const char *real_transport, const struct ast_sockaddr *src, int n_contacts,
	struct sofia_register_update *update)
{
	char uri[256];
	char in_instance[128];
	int in_reg_id;
	const char *in_call_id;
	struct sofia_contact *c;

	sofia_contact_uri_from_url(uri, sizeof(uri), m->m_url);
	sofia_contact_parse_instance(m, in_instance, sizeof(in_instance), &in_reg_id);
	in_call_id = (sip->sip_call_id && sip->sip_call_id->i_id) ? sip->sip_call_id->i_id : "";

	c = ao2_find(peer->contacts, uri, OBJ_POINTER);
	if (!c) {
		char dtransport[16];
		if (!ast_strlen_zero(real_transport)) {
			ast_copy_string(dtransport, real_transport, sizeof(dtransport));	/* authoritative: the delivering tport */
		} else {
			sofia_contact_transport_from_url(m->m_url, dtransport, sizeof(dtransport));
			sofia_register_transport_from_via(sip->sip_via, dtransport, sizeof(dtransport));	/* fallback: Via, then Contact */
		}
		if (in_instance[0]) {
			c = sofia_peer_find_contact_by_instance(peer, in_instance, in_reg_id);
		} else {
			if (n_contacts == 1) {
				c = sofia_peer_find_contact_by_callid(peer, in_call_id, dtransport);
			}
			if (!c && (peer->nat & SOFIA_NAT_FORCE_RPORT) && n_contacts == 1
					&& sip->sip_user_agent && sip->sip_user_agent->g_string
					&& !ast_strlen_zero(sip->sip_user_agent->g_string)) {
				c = sofia_peer_find_contact_nat_fallback(peer, src, dtransport,
					sip->sip_user_agent->g_string);
			}
		}
	}
	if (c) {
		if (update) {
			update->contacts_removed++;
			sofia_register_update_set_uri(update, uri);
		}
		ao2_unlink(peer->contacts, c);	/* by OBJECT: a rotated de-register's matched key differs from `uri` */
		if (sofia_debug)
			ast_verbose("Sofia: Unlinked contact %s\n", c->contact_uri);
		ao2_ref(c, -1);
	}
}

/* Apply a REGISTER's Contact bindings to the peer. Caller holds peer->lock.
 * Returns 0 ok, -1 ACL-denied, -2 malformed wildcard, -3 OOM. Unregister
 * side-effects are deferred to the caller via *update (see emit_unregister). */
static int sofia_update_peer_contacts(struct sofia_peer *peer, sip_t const *sip, int expires,
	struct sofia_register_update *update, const char *real_transport, nua_handle_t *nh)
{
	time_t now = time(NULL);
	struct ast_sockaddr src;
	sip_contact_t *m;
	char reg_transport[8] = "udp";	/* last contact's transport → peer->reg_transport */
	/* Path (RFC 3327, path=yes): serialized ONCE below — after the wildcard check and once we know at least
	 * one concrete Contact will BIND (positive per-Contact expiry) — before any contact mutation; on overflow
	 * reject the whole REGISTER (-1 -> 500). Empty unless path=yes and a Path is present. */
	char pathstr[1024] = "";

	/* "Contact: *" is valid only as the sole Contact with Expires:0 (RFC 3261
	 * §10.2.2 bulk unregister); else malformed → -2 (400). */
	int single_contact = 0;	/* exactly one concrete Contact → eligible for the RFC 5626 flow-watch (one handle ↔ one contact) */
	int has_wildcard = 0;
	{
		int n_contacts = 0;
		for (m = sip->sip_contact; m; m = m->m_next) {
			n_contacts++;
			if (m->m_url->url_type == url_any) {
				has_wildcard = 1;
			}
		}
		if (has_wildcard && (expires != 0 || n_contacts > 1)) {
			return -2;
		}
		single_contact = (n_contacts == 1 && !has_wildcard);
	}

	sofia_get_source_addr(sip, &src);
	if (update) {
		memset(update, 0, sizeof(*update));
		update->was_registered = peer->registered;
		update->contacts_before = ao2_container_count(peer->contacts);
		ast_sockaddr_copy(&update->old_src, &peer->src_addr);
		ast_sockaddr_copy(&update->new_src, &src);
	}

	/* Wildcard bulk unregister ("Contact: *" — validated above to require a global Expires:0). */
	if (has_wildcard) {
		ao2_callback(peer->contacts, OBJ_UNLINK | OBJ_NODATA | OBJ_MULTIPLE, NULL, NULL);
		peer->registered = 0;
		memset(&peer->src_addr, 0, sizeof(peer->src_addr));
		ast_copy_string(peer->reg_transport, "udp", sizeof(peer->reg_transport));
		if (update) {
			update->wildcard_removed = 1;
			update->contacts_removed = update->contacts_before;
			update->now_registered = 0;
			update->contacts_after = 0;
			sofia_register_update_set_uri(update, "*");
			/* Defer unregister side-effects to the caller post-unlock (contexts lock + AMI + BLF). */
			update->emit_unregister = 1;
			update->unregister_cause = "Wildcard";
		}
		return 0;
	}

	/* RFC 3261 §10.3: process EVERY concrete Contact per-Contact (in the apply loop below) — a Contact
	 * ;expires>0 BINDS even under a global Expires:0 header (the Contact param wins), and a Contact
	 * ;expires=0 de-registers THAT binding. The apply loop does both (contact_expires==0 ->
	 * sofia_deregister_one_contact, >0 -> bind/refresh/rebind). Path (RFC 3327): serialize ONCE now that at
	 * least one concrete Contact will BIND (a pure de-register never serializes/rejects a Path — you must
	 * always be able to de-register). */
	{
		int any_bind = 0;
		for (m = sip->sip_contact; m; m = m->m_next) {
			if (sofia_contact_requested_expiry(m, expires) > 0) {
				any_bind = 1;
				break;
			}
		}
		if (peer->path_support && any_bind && sip->sip_path
				&& sofia_route_serialize(sip->sip_path, pathstr, sizeof(pathstr)) != 0) {
			return -4;	/* Path too long to store -> reject the REGISTER (500) */
		}
	}
	{
		/* Preflight the contact-ACL for every Contact that will BIND before binding ANY, so a later
		 * fail-closed Contact never leaves earlier ones partially bound. A per-Contact de-register
		 * (effective expiry 0) is NEVER ACL-gated (RFC 3261 §10.3): you must always be able to unregister,
		 * even from a source contact-ha would reject. */
		for (m = sip->sip_contact; m; m = m->m_next) {
			char uri[256];
			if (sofia_contact_requested_expiry(m, expires) <= 0) {
				continue;	/* de-register: skip the contact-ACL */
			}
			sofia_contact_uri_from_url(uri, sizeof(uri), m->m_url);
			if (sofia_contact_acl_check(peer, m->m_url, uri) < 0) {
				return -1;
			}
		}
		/* RFC 3261 allows several Contacts in one REGISTER; a same-UA multi-Contact REGISTER shares
		 * Call-ID + transport, so the legacy Call-ID rebind tier is restricted to single-Contact REGISTERs
		 * (the instance + NAT-src-IP tiers are unaffected). */
		int n_contacts = 0;
		for (m = sip->sip_contact; m; m = m->m_next) {
			n_contacts++;
		}
		/* Apply loop. */
		for (m = sip->sip_contact; m; m = m->m_next) {
			char uri[256];
			struct sofia_contact *c;
			char in_instance[128];
			int in_reg_id;
			const char *in_call_id;
			/* RFC 3261 §10.3 per-Contact granted TTL: this Contact's ;expires= param (if any) takes
			 * precedence, else the REGISTER-level fallback (Expires header / local default), capped at
			 * max_expiry (min already 423-checked per-Contact in sofia_process_register). This is what
			 * stores a "Contact: <...>;expires=300" as 300, not the 120 default. */
			int contact_expires = sofia_contact_requested_expiry(m, expires);
			if (contact_expires > sofia_cfg.max_expiry) {
				contact_expires = sofia_cfg.max_expiry;
			}
			if (contact_expires <= 0) {
				/* RFC 3261 §10.3: a per-Contact ;expires=0 removes THAT specific binding — an explicit
				 * de-register (SIP.js unregister sends a single Contact ;expires=0 with no Expires header, so
				 * the fallback is non-zero and it lands here, not the global Expires:0 branch). Handles mixed
				 * REGISTERs atomically: zero-expiry Contacts remove, positive ones bind/refresh. */
				sofia_deregister_one_contact(peer, sip, m, real_transport, &src, n_contacts, update);
				continue;
			}

			sofia_contact_uri_from_url(uri, sizeof(uri), m->m_url);

			/* Device identity for rebind-on-renewal: RFC 5626 +sip.instance/reg-id (if present), the
			 * REGISTER Call-ID (RFC 3261 10.2, stable per UA boot cycle), and the Contact user. */
			sofia_contact_parse_instance(m, in_instance, sizeof(in_instance), &in_reg_id);
			in_call_id = (sip->sip_call_id && sip->sip_call_id->i_id) ? sip->sip_call_id->i_id : "";

			/* Last Contact ;transport= seen is snapshotted into reg_transport
			 * after the loop. */
			/* Transport is decided by HOW the REGISTER physically ARRIVES, not by text the UA wrote in
			 * Contact/Via: use the protocol of the actual delivering tport (the real connection). A WebSocket
			 * UA (SIP.js) sends a synthetic Contact with no ;transport, so the text would default to "udp"
			 * though it arrived over ws/wss; the real transport drives outbound routing/media profile AND the
			 * ws/wss contact-rebind relaxation. (No "wss" SIP-URI param exists; ;transport=ws/wss is re-derived
			 * outbound from this stored transport.) */
			if (!ast_strlen_zero(real_transport)) {
				ast_copy_string(reg_transport, real_transport, sizeof(reg_transport));	/* authoritative: the delivering tport */
			} else {
				/* Fallback when the tport is unreachable: Contact ;transport, then the Via sent-protocol. */
				sofia_contact_transport_from_url(m->m_url, reg_transport, sizeof(reg_transport));
				sofia_register_transport_from_via(sip->sip_via, reg_transport, sizeof(reg_transport));
			}

			c = ao2_find(peer->contacts, uri, OBJ_POINTER);
			if (c) {
				/* Refresh: mutable fields are read off-thread, so write under the
				 * contact's ao2 lock (peer->lock -> c lock). */
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
				c->expires = now + contact_expires;
				c->last_register = now;	/* diagnostic timestamp: contact refresh (Last-REGISTER gauge) */
				memcpy(&c->src_addr, &src, sizeof(src));
				/* Refresh transport too: a same-URI re-REGISTER may switch it. */
				ast_copy_string(c->transport, reg_transport, sizeof(c->transport));
				if (sip->sip_user_agent && sip->sip_user_agent->g_string)
					ast_copy_string(c->user_agent, sip->sip_user_agent->g_string,
						sizeof(c->user_agent));
				ast_copy_string(c->path, pathstr, sizeof(c->path));	/* RFC 3327 Path (empty if none/off) */
				ast_copy_string(c->instance_id, in_instance, sizeof(c->instance_id));
				c->reg_id = in_reg_id;
				ast_copy_string(c->call_id, in_call_id, sizeof(c->call_id));
				ao2_unlock(c);
				/* RFC 5626 flow-close: a same-URI refresh may arrive on a NEW connection (TCP/WSS
				 * reconnect) -> disarm the stale watch + arm on the new tport (no-op if unchanged). */
				sofia_regflow_attach(peer, c, nh, reg_transport, single_contact);
				ao2_ref(c, -1);
				if (sofia_debug)
					ast_verbose("Sofia: Refreshed contact %s (expires in %ds)\n", uri, expires);
			} else {
				/* Same device that rotated its source port / Contact URI (NAT)? Rebind the existing binding
				 * instead of accumulating a duplicate. Key priority: RFC 5626 +sip.instance(+reg-id); else a
				 * legacy single-Contact rotator by Call-ID + transport; else a conservative NAT src-IP match.
				 * An instance present but unmatched is a genuinely new flow - do NOT fall to the lower tiers
				 * (they could collapse a distinct reg-id flow). */
				struct sofia_contact *match = NULL;
				if (in_instance[0]) {
					match = sofia_peer_find_contact_by_instance(peer, in_instance, in_reg_id);
				} else {
					if (n_contacts == 1) {
						match = sofia_peer_find_contact_by_callid(peer, in_call_id, reg_transport);
					}
					/* No id (no instance, no matching Call-ID): match the same device by source-IP + transport
					 * + User-Agent. Single-Contact REGISTERs only (a multi-Contact no-id reg has no safe identity). */
					if (!match && (peer->nat & SOFIA_NAT_FORCE_RPORT) && n_contacts == 1
							&& sip->sip_user_agent && sip->sip_user_agent->g_string
							&& !ast_strlen_zero(sip->sip_user_agent->g_string)) {
						match = sofia_peer_find_contact_nat_fallback(peer, &src, reg_transport,
							sip->sip_user_agent->g_string);
					}
				}
				if (match) {
					struct ast_sockaddr old_src;
					int rc = sofia_contact_rebind(peer, match, uri, m->m_url->url_host,
						sofia_contact_url_port(m->m_url->url_port), reg_transport,
						(sip->sip_user_agent ? sip->sip_user_agent->g_string : NULL),
						&src, pathstr, in_instance, in_reg_id, in_call_id, now + contact_expires, &old_src);
					/* Only count the move + (re)arm the flow-watch when the relink SUCCEEDED. On rc<0 the binding
					 * was unlinked and is about to drop its finder ref (fail-closed); watching an unlinked contact
					 * would be wrong (v1.3.5 discipline). */
					if (rc == 0 && update) {
						update->contacts_refreshed++;	/* a MOVE, not an add -> bypasses evict-oldest */
						if (ast_sockaddr_cmp(&old_src, &src)) {
							update->contacts_moved++;
							sofia_register_update_set_uri(update, uri);
							ast_sockaddr_copy(&update->changed_old_src, &old_src);
							ast_sockaddr_copy(&update->new_src, &src);
						}
					}
					/* RFC 5626 flow-close: URI/tport may have changed -> disarm old watch, arm new (no-op if same).
					 * ONLY on a successful relink (rc==0) — never arm a watch on the fail-closed unlinked contact. */
					if (rc == 0) {
						sofia_regflow_attach(peer, match, nh, reg_transport, single_contact);
					}
					ao2_ref(match, -1);	/* drop the finder ref (rebind kept the object linked, or fail-closed) */
					continue;		/* rebound (or fail-closed); never alloc a duplicate */
				}
				/* New contact. */
				c = ao2_alloc(sizeof(*c), sofia_contact_destructor);
				if (!c) continue;
				if (update) {
					update->contacts_added++;
					sofia_register_update_set_uri(update, uri);
					ast_sockaddr_copy(&update->new_src, &src);
				}
				ast_copy_string(c->contact_uri, uri, sizeof(c->contact_uri));
				if (m->m_url->url_host)
					ast_copy_string(c->host, m->m_url->url_host, sizeof(c->host));
				c->port = sofia_contact_url_port(m->m_url->url_port);
				ast_copy_string(c->transport, reg_transport, sizeof(c->transport));
				if (sip->sip_user_agent && sip->sip_user_agent->g_string)
					ast_copy_string(c->user_agent, sip->sip_user_agent->g_string,
						sizeof(c->user_agent));
				c->expires = now + contact_expires;
				c->last_register = now;	/* diagnostic timestamp: new contact (Last-REGISTER gauge) */
				memcpy(&c->src_addr, &src, sizeof(src));
				ast_copy_string(c->path, pathstr, sizeof(c->path));	/* RFC 3327 Path (empty if none/off) */
				ast_copy_string(c->instance_id, in_instance, sizeof(c->instance_id));
				c->reg_id = in_reg_id;
				ast_copy_string(c->call_id, in_call_id, sizeof(c->call_id));
				ao2_lock(peer->contacts);
				/* Link FIRST, evict oldest AFTER, so an OOM never drops an existing
				 * binding (NULL = OOM: undo accounting, return -3/500). */
				if (!ao2_link(peer->contacts, c)) {
					if (update) {
						update->contacts_added--;
					}
					ao2_unlock(peer->contacts);
					ao2_ref(c, -1);
					return -3;
				}
				if (ao2_container_count(peer->contacts) > peer->max_contacts) {
					/* Over max_contacts → evict earliest-expiry (LRU) rather than
					 * reject. Iterating under the held contacts lock is safe. */
					struct ao2_iterator i;
					struct sofia_contact *cand, *oldest = NULL;

					i = ao2_iterator_init(peer->contacts, 0);
					while ((cand = ao2_iterator_next(&i))) {
						if (cand == c) {
							/* Never evict the binding we just linked. */
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
						/* Cosmetic eviction trace, gated by `sip set debug`. */
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
				/* RFC 5626 flow-close: watch this binding's connection for close (no-op unless
				 * connection-oriented). Under peer->lock; c is linked + we still hold the local ref. */
				sofia_regflow_attach(peer, c, nh, reg_transport, single_contact);
				ao2_ref(c, -1);
				if (sofia_debug)
					ast_verbose("Sofia: New contact %s for peer '%s'\n", uri, peer->name);
			}
		}
	}

	/* Opportunistic expiry sweep */
	ao2_callback(peer->contacts, OBJ_UNLINK | OBJ_NODATA | OBJ_MULTIPLE,
		sofia_expire_contacts_cb, &now);

	/* Update legacy src_addr from the newest contact + the registered flag. */
	if (ao2_container_count(peer->contacts) > 0) {
		peer->registered = 1;
		peer->expire = expires;
		memcpy(&peer->src_addr, &src, sizeof(peer->src_addr));
		/* Snapshot transport beside src_addr so NAT-proxy resolution routes a
		 * TCP/TLS phone instead of defaulting to UDP. */
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
	/* Reject (NULL) rather than silently truncate, so a too-long nc can't slip
	 * past the nc-monotonic check; caller answers 400 (RFC 2617 §3.2.2). */
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

/* Build the NUTAG_AUTH credential string for an outbound request in the exact
 * format auc_credentials() needs: Digest:"realm":user:pass (a 2-field form is
 * silently ignored). realm comes from the 401/407 challenge. Returns 0 ok, -1 if
 * no realm or empty secret (md5secret-only unsupported — needs cleartext).
 * Lock-free: caller passes snapshotted user/secret. */
int sofia_format_auth_creds(msg_auth_t const *challenge, const char *user,
		const char *secret, char *buf, size_t len)
{
	msg_auth_t const *au;
	const char *realm = NULL;
	int n;

	if (!challenge || ast_strlen_zero(secret) || !buf || len == 0) {
		return -1;
	}
	/* A ':' in user/secret would corrupt the colon-delimited creds format. */
	if (strchr(S_OR(user, ""), ':') || strchr(secret, ':')) {
		return -1;
	}
	/* Take the Digest realm verbatim off the wire (already quoted+escaped) so
	 * auc_credentials gets a byte-faithful realm without double-escaping. */
	for (au = challenge; au; au = au->au_next) {
		if (au->au_scheme && !strcasecmp(au->au_scheme, "Digest")) {
			realm = msg_header_find_param(au->au_common, "realm");
			if (realm) {
				break;
			}
		}
	}
	if (!realm) {
		return -1;
	}
	{
		/* Defensive: require a well-formed quoted-string realm. */
		size_t rl = strlen(realm);
		if (rl < 2 || realm[0] != '"' || realm[rl - 1] != '"') {
			return -1;
		}
	}
	n = snprintf(buf, len, "Digest:%s:%s:%s", realm, S_OR(user, ""), secret);
	if (n < 0 || n >= (int)len) {
		return -1;	/* truncated → reject */
	}
	return 0;
}

/* match_auth_username (chan_sip parity): pick the peer-lookup key — the
 * Authorization-username (Proxy-Authorization fallback) when present, else
 * fallback_user. Returned pointer is borrowed (into buf or fallback_user). */
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

	/* Proxy-Authorization fallback; the cast is type-safe (both are msg_auth_s). */
	if (sip->sip_proxy_authorization) {
		result = sofia_au_get_unq((sip_authorization_t const *)sip->sip_proxy_authorization,
			"username", buf, len);
		if (result && *result) {
			return result;
		}
	}

	return fallback_user;
}

/* Constant-time compare for digest hashes (avoids a timing oracle). The volatile
 * accumulator + barrier stop the compiler short-circuiting. 0 = match. */
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

/* Digest algorithm selector (MD5 / RFC 7616 SHA-256); MD5 when algorithm= absent. */
#define SOFIA_DIGEST_MD5     0
#define SOFIA_DIGEST_SHA256  1

/* SHA-256 wrapper over libcrypto, mirroring ast_md5_hash. Output: 64 hex + null. */
static void sofia_sha256_hash(char *out_buf, const char *input)
{
	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256((const unsigned char *)input, strlen(input), digest);
	for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		snprintf(out_buf + (i * 2), 3, "%02x", digest[i]);
	}
}

/* HA1 = hash(user:realm:secret), or md5secret used directly when set (chan_sip
 * parity; md5secret wins over secret). out_hash size: 33 (MD5) / 65 (SHA-256). */
static int sofia_compute_a1_hash(struct sofia_peer *peer, const char *realm,
		int algorithm, char *out_hash)
{
	char *a1_pre = NULL;

	/* md5secret is a precomputed MD5; a SHA-256 request with it set is a
	 * mismatch the caller recovers (re-challenge MD5-only). */
	if (!ast_strlen_zero(peer->md5secret)) {
		ast_copy_string(out_hash, peer->md5secret, 33);
		return 0;
	}

	/* DYNAMIC buffer so a long user+realm (domainsasrealm) can never truncate the
	 * secret — a fixed buffer would hash MD5("user:realm:") = auth bypass. On OOM
	 * propagate -1 so the caller rejects (500), never a predictable hash.
	 * A1 = unq(username):unq(realm):passwd (RFC 2617 §3.2.2.2 / RFC 7616 §3.4.2): the digest
	 * username is the peer's CONFIGURED username (defaultuser — set by `username=`/`defaultuser=`,
	 * falling back to the section name), NOT the section name, so a peer whose section name differs
	 * from its auth username (username= set to a value other than the section name) verifies. The caller required
	 * the Authorization username == this value (anti-impersonation), so name and value agree. */
	if (ast_asprintf(&a1_pre, "%s:%s:%s",
			!ast_strlen_zero(peer->defaultuser) ? peer->defaultuser : peer->name,
			realm, peer->secret) < 0 || !a1_pre) {
		ast_free(a1_pre);
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

/* Full digest response (RFC 2617 MD5 / RFC 7616 SHA-256): response =
 * hash(HA1:nonce:nc:cnonce:qop:HA2), or hash(HA1:nonce:HA2) for no-qop (RFC
 * 2069). out_hash size: 33 (MD5) / 65 (SHA-256). */
static int sofia_compute_digest(struct sofia_peer *peer, const char *realm,
		const char *method, const char *uri,
		const char *nonce, const char *nc, const char *cnonce,
		const char *qop, int algorithm, char *out_hash)
{
	char a1_hash[65];
	char *a2_pre = NULL;
	char a2_hash[65];
	char resp_pre[1024];

	if (sofia_compute_a1_hash(peer, realm, algorithm, a1_hash) != 0) {
		return -1;	/* OOM -> reject (500), never a predictable hash */
	}
	/* Dynamic buffer: a fixed one would truncate HA2 for long Request-URIs. */
	if (ast_asprintf(&a2_pre, "%s:%s", method, uri) < 0 || !a2_pre) {
		ast_free(a2_pre);
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

/* Which digest algorithm(s) to offer, per [general] auth_algorithms. Verify uses
 * the same selector -> accepts exactly what was offered (anti-downgrade). */
static void sofia_auth_offered(int *want_md5, int *want_sha256)
{
	*want_md5    = (sofia_cfg.auth_algorithms != SOFIA_AUTH_ALG_SHA256);
	*want_sha256 = (sofia_cfg.auth_algorithms != SOFIA_AUTH_ALG_MD5);
}

/* Build the MD5 WWW-Authenticate challenge value, honoring [general] auth_qop. This is the single
 * choke point for MD5 challenge formatting (used by both the generic challenge and the md5secret
 * SHA-256->MD5 recovery re-challenge). stale!=0 appends ", stale=true".
 *   auth_qop=yes -> RFC 2617/7616 form:  Digest realm=..., nonce=..., qop="auth", algorithm=MD5
 *   auth_qop=no  -> chan_sip legacy RFC 2069 form (byte order per chan_sip transmit_response_with_auth,
 *                   NO qop -> no nc/cnonce replay protection): Digest algorithm=MD5, realm=..., nonce=... */
static void sofia_build_md5_challenge(char *buf, size_t sz, const char *realm,
		const char *nonce, int stale)
{
	const char *stale_str = stale ? ", stale=true" : "";

	if (sofia_cfg.auth_qop) {
		snprintf(buf, sz, "Digest realm=\"%s\", nonce=\"%s\", qop=\"auth\", algorithm=MD5%s",
			realm, nonce, stale_str);
	} else {
		snprintf(buf, sz, "Digest algorithm=MD5, realm=\"%s\", nonce=\"%s\"%s",
			realm, nonce, stale_str);
	}
}

/* Emit the WWW-Authenticate 401 challenge(s) per auth_algorithms (MD5 first for
 * legacy clients). stale!=0 appends ", stale=true". Caller generates the nonce. */
static void sofia_emit_auth_challenge(nua_t *nua, nua_handle_t *nh,
		const char *realm, const char *nonce, int stale)
{
	int want_md5, want_sha256;
	char hdr_md5[256];
	char hdr_sha256[256];
	const char *stale_str = stale ? ", stale=true" : "";

	sofia_auth_offered(&want_md5, &want_sha256);

	if (want_md5) {
		sofia_build_md5_challenge(hdr_md5, sizeof(hdr_md5), realm, nonce, stale);
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

/* ===== Stateless digest nonce + per-nonce replay cache =====
 * Replaces the per-peer single-nonce + monotonic-nc model that 401-looped concurrent INVITEs from a
 * multi-call phone: a REGISTER nc=1 advanced the SHARED peer->last_nc, so a later INVITE legitimately
 * starting at nc=1 on the same live nonce tripped the nc-replay gate -> 401 stale -> rotation cascaded
 * across the peer's concurrent transactions -> loop -> the outbound INVITE never completed (chan_sip,
 * which uses no-qop + a per-dialog nonce, was unaffected). Now: the nonce is FRESH per challenge and
 * SELF-VALIDATING (HMAC-SHA256/128 over s1:ts:rand:realm:method:scope keyed by a per-process secret), and
 * nc replay is tracked PER NONCE in a bounded leaf-locked cache, updated ONLY AFTER a valid digest (so
 * unauthenticated floods cannot fill it). RFC 2617 warns strict per-peer nonce tracking breaks
 * pipelined/concurrent requests; this scopes the replay state to a single challenge. Applies only when
 * qop is in use (auth_qop=yes, or a client that sends qop anyway); auth_qop=no is RFC 2069 (no nc). */

static unsigned char sofia_nonce_secret[32];	/* HMAC key; random, per module load */

/* Fill buf with crypto-random bytes (/dev/urandom; ast_random fallback w/ WARNING). */
static void sofia_rand_bytes(unsigned char *buf, size_t n)
{
	int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		size_t got = 0;
		while (got < n) {
			ssize_t r = read(fd, buf + got, n - got);
			if (r < 0) { if (errno == EINTR) continue; break; }
			if (r == 0) break;
			got += (size_t)r;
		}
		close(fd);
		if (got == n) return;
	}
	ast_log(LOG_WARNING, "Sofia: /dev/urandom unavailable; ast_random fallback for %zu bytes (degraded entropy)\n", n);
	for (size_t i = 0; i < n; i++) buf[i] = (unsigned char)(ast_random() & 0xff);
}

/* One-time module-load init of the nonce HMAC secret (before sofia_thread accepts SIP). */
static void sofia_nonce_secret_init(void)
{
	sofia_rand_bytes(sofia_nonce_secret, sizeof(sofia_nonce_secret));
}

/* lower-hex of n bytes into out (>= 2n+1). */
static void sofia_hex_encode(const unsigned char *in, size_t n, char *out)
{
	static const char h[] = "0123456789abcdef";
	for (size_t i = 0; i < n; i++) { out[i * 2] = h[in[i] >> 4]; out[i * 2 + 1] = h[in[i] & 0xf]; }
	out[n * 2] = '\0';
}

/* HMAC-SHA256(secret, msg) truncated to 128 bits -> 32 lower-hex into out (>= 33). */
static void sofia_nonce_hmac(const char *msg, char *out_hex)
{
	unsigned char mac[SHA256_DIGEST_LENGTH];
	unsigned int maclen = 0;
	HMAC(EVP_sha256(), sofia_nonce_secret, (int)sizeof(sofia_nonce_secret),
		(const unsigned char *)msg, strlen(msg), mac, &maclen);
	sofia_hex_encode(mac, 16, out_hex);	/* 128-bit truncation: enough for an online challenge token */
}

/* Build a FRESH stateless nonce: s1.<ts_hex>.<rand_hex>.<hmac_hex>. scope = peer name (or "*" for an
 * unknown-peer challenge). Does NOT touch peer state. out >= 96. */
static void sofia_make_auth_nonce(const char *scope, const char *realm, const char *method,
		char *out, size_t outlen)
{
	char ts_hex[24], rand_hex[33], hmac_hex[33], msg[640];
	unsigned char rnd[16];

	snprintf(ts_hex, sizeof(ts_hex), "%llx", (unsigned long long)time(NULL));
	sofia_rand_bytes(rnd, sizeof(rnd));
	sofia_hex_encode(rnd, sizeof(rnd), rand_hex);
	/* NOTE: deliberately NOT bound to source IP in v1. pjsip binds to the TRUE packet source
	 * (rdata->pkt_info.src_name); chan_sofia's only source helper is Via-derived (received/rport),
	 * and binding the nonce to that could false-stale legit NAT/proxy/TCP/WS traffic - the exact bug
	 * class this fix removes. Replay is covered by the per-nonce nc cache. Source-IP binding is a v2
	 * "s2" option IF/when reliable packet-source metadata is plumbed in (IP only, never port). */
	snprintf(msg, sizeof(msg), "s1:%s:%s:%s:%s:%s", ts_hex, rand_hex,
		realm ? realm : "", method ? method : "", scope ? scope : "*");
	sofia_nonce_hmac(msg, hmac_hex);
	snprintf(out, outlen, "s1.%s.%s.%s", ts_hex, rand_hex, hmac_hex);
}

/* Validate a returned nonce statelessly. Recomputes the HMAC for `scope`, then "*" (so an unknown-peer
 * challenge that became a known peer on the authenticated retry still validates). Returns:
 *   0 = valid HMAC + within TTL (issue_ts out), 1 = valid HMAC but expired/future (stale), -1 = invalid. */
static int sofia_validate_auth_nonce(const char *nonce, const char *scope, const char *realm,
		const char *method, time_t *issue_ts)
{
	char ts_hex[24], rand_hex[40], hmac_hex[40], msg[640], want_hex[33];
	unsigned long long ts;
	int ttl;
	time_t now;

	if (!nonce) return -1;
	if (sscanf(nonce, "s1.%23[0-9a-fA-F].%39[0-9a-fA-F].%39[0-9a-fA-F]", ts_hex, rand_hex, hmac_hex) != 3) {
		return -1;
	}
	if (strlen(hmac_hex) != 32) {
		return -1;	/* our HMAC is exactly 128-bit (32 hex) */
	}
	snprintf(msg, sizeof(msg), "s1:%s:%s:%s:%s:%s", ts_hex, rand_hex,
		realm ? realm : "", method ? method : "", scope ? scope : "*");
	sofia_nonce_hmac(msg, want_hex);
	if (sofia_ct_memcmp(want_hex, hmac_hex, 32) != 0) {
		snprintf(msg, sizeof(msg), "s1:%s:%s:%s:%s:*", ts_hex, rand_hex,
			realm ? realm : "", method ? method : "");
		sofia_nonce_hmac(msg, want_hex);
		if (sofia_ct_memcmp(want_hex, hmac_hex, 32) != 0) {
			return -1;	/* bad HMAC: forged/foreign nonce */
		}
	}
	ts = strtoull(ts_hex, NULL, 16);
	if (issue_ts) *issue_ts = (time_t)ts;
	ttl = sofia_cfg.nonce_ttl_seconds > 0 ? sofia_cfg.nonce_ttl_seconds : SOFIA_NONCE_TTL_SEC_DEFAULT;
	now = time(NULL);
	if ((time_t)ts > now + 2) return 1;		/* future (clock skew/forged) -> stale */
	if (now - (time_t)ts > ttl) return 1;		/* expired -> stale */
	return 0;
}

/* Per-nonce replay entry (bounded leaf-locked cache, keyed by the nonce string). `nonce` MUST be the
 * FIRST member: this ao2 (era-1.8 API) has no OBJ_SEARCH_KEY, so a key-find passes the nonce string as
 * `arg`/`obj` and the hash casts it to this struct and reads offset 0 (the chan_sofia contact_uri pattern). */
struct sofia_nonce_replay {
	char nonce[96];		/* offset 0 - see above */
	unsigned int max_nc;
	time_t issue_ts;
};
static struct ao2_container *sofia_nonce_cache;
#define SOFIA_NONCE_CACHE_MAX 65536
#define SOFIA_NONCE_CACHE_BUCKETS 16381	/* prime */

static int sofia_nonce_cache_hash(const void *obj, int flags)
{
	/* obj is a real entry on link, or the nonce string on a key-find; nonce[] at offset 0 makes both work. */
	return ast_str_hash(((const struct sofia_nonce_replay *)obj)->nonce);
}
static int sofia_nonce_cache_cmp(void *obj, void *arg, int flags)
{
	const struct sofia_nonce_replay *e = obj;
	const char *key = arg;	/* a key-find passes the nonce string */
	return strcmp(e->nonce, key) ? 0 : CMP_MATCH;
}

/* Drop entries older than now-ttl (issue_ts based). Returns count removed. */
static void sofia_nonce_cache_prune(void)
{
	struct ao2_iterator it;
	struct sofia_nonce_replay *e;
	int ttl = sofia_cfg.nonce_ttl_seconds > 0 ? sofia_cfg.nonce_ttl_seconds : SOFIA_NONCE_TTL_SEC_DEFAULT;
	time_t cutoff = time(NULL) - ttl;

	if (!sofia_nonce_cache) return;
	it = ao2_iterator_init(sofia_nonce_cache, 0);
	while ((e = ao2_iterator_next(&it))) {
		if (e->issue_ts < cutoff) {
			ao2_unlink(sofia_nonce_cache, e);
		}
		ao2_ref(e, -1);
	}
	ao2_iterator_destroy(&it);
}

/* Last resort when full after prune: unlink the single oldest entry (availability-biased). */
static void sofia_nonce_cache_evict_oldest(void)
{
	struct ao2_iterator it;
	struct sofia_nonce_replay *e, *oldest = NULL;

	if (!sofia_nonce_cache) return;
	it = ao2_iterator_init(sofia_nonce_cache, 0);
	while ((e = ao2_iterator_next(&it))) {
		if (!oldest || e->issue_ts < oldest->issue_ts) {
			if (oldest) ao2_ref(oldest, -1);
			oldest = e;	/* keep ref */
		} else {
			ao2_ref(e, -1);
		}
	}
	ao2_iterator_destroy(&it);
	if (oldest) {
		ao2_unlink(sofia_nonce_cache, oldest);
		ao2_ref(oldest, -1);
	}
}

/* Per-nonce nc replay gate, called ONLY after a valid digest (so bogus auth never inserts).
 * Returns 0 = accept (recorded/advanced), 1 = replay (nc <= the max already seen for this nonce).
 * ao2 is leaf-locked; never called while holding peer->lock. */
static int sofia_nonce_replay_check(const char *nonce, unsigned int nc, time_t issue_ts)
{
	struct sofia_nonce_replay *e;

	if (!sofia_nonce_cache || ast_strlen_zero(nonce)) return 0;	/* defensive: never block a call */

	e = ao2_find(sofia_nonce_cache, (char *)nonce, OBJ_POINTER);	/* key-find: nonce string -> struct offset 0 */
	if (e) {
		int replay;
		ao2_lock(e);
		if (nc > e->max_nc) { e->max_nc = nc; replay = 0; } else { replay = 1; }
		ao2_unlock(e);
		ao2_ref(e, -1);
		return replay;
	}

	/* New nonce -> bound the cache before inserting. */
	if (ao2_container_count(sofia_nonce_cache) >= SOFIA_NONCE_CACHE_MAX) {
		sofia_nonce_cache_prune();
		if (ao2_container_count(sofia_nonce_cache) >= SOFIA_NONCE_CACHE_MAX) {
			sofia_nonce_cache_evict_oldest();
		}
	}
	e = ao2_alloc(sizeof(*e), NULL);
	if (!e) return 0;	/* OOM -> don't block the call */
	ast_copy_string(e->nonce, nonce, sizeof(e->nonce));
	e->max_nc = nc;
	e->issue_ts = issue_ts;
	ao2_link(sofia_nonce_cache, e);
	ao2_ref(e, -1);
	return 0;
}

/* Unified digest verifier (REGISTER/INVITE/SUBSCRIBE). Caller holds a peer ao2 ref
 * across the call. On CHALLENGE/REJECT the 401/4xx is already emitted; caller
 * ao2_ref(peer,-1)s on every return. */
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
	char auth_username_buf[128] = "";
	const char *auth_realm;
	const char *auth_nonce;
	const char *auth_response;
	const char *auth_uri;
	const char *auth_nc;
	const char *auth_cnonce;
	const char *auth_qop;
	const char *auth_algorithm;
	const char *auth_username;
	int using_qop;
	unsigned int new_nc = 0;
	time_t nonce_issue_ts = 0;	/* issue time parsed from the validated stateless nonce; fed to the per-nonce replay cache */
	int algorithm = SOFIA_DIGEST_MD5;  /* RFC 2617 backward-compat default */
	int hash_len_hex;
	char expected_hash[65];  /* SHA-256 (64 hex + null); MD5 uses 32+null */
	/* REGISTER is an idempotent re-bind: phones legitimately resend nc=00000001 on every refresh
	 * (chan_sip tolerated this; common multi-vendor phone behavior — nearly every REGISTER sends nc=1).
	 * Exempt REGISTER from the nc-replay nonce rotation so a VALID digest is never 401-stale-looped.
	 * Strict nc-replay is KEPT for non-idempotent methods (INVITE/MESSAGE/...) where a replay has
	 * real effect (duplicate call/message). RFC 2617 §nonce-reuse is server policy w/ interop cost;
	 * stale=true (RFC 7616 §3.3) is for a STALE nonce, never a live nonce + valid REGISTER digest. */
	int register_method = method && !strcasecmp(method, "REGISTER");

	/* No Authorization header: challenge with a FRESH stateless nonce (s1.ts.rand.hmac; no peer nonce state). */
	if (!au) {
		char nonce[96];
		sofia_make_auth_nonce(peer->name, realm, method, nonce, sizeof(nonce));
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

	/* sofia_au_get_unq returns NULL on overflow. */
	auth_realm     = sofia_au_get_unq(au, "realm",     auth_realm_buf,     sizeof(auth_realm_buf));
	auth_nonce     = sofia_au_get_unq(au, "nonce",     auth_nonce_buf,     sizeof(auth_nonce_buf));
	auth_response  = sofia_au_get_unq(au, "response",  auth_response_buf,  sizeof(auth_response_buf));
	auth_uri       = sofia_au_get_unq(au, "uri",       auth_uri_buf,       sizeof(auth_uri_buf));
	auth_nc        = sofia_au_get_unq(au, "nc",        auth_nc_buf,        sizeof(auth_nc_buf));
	auth_cnonce    = sofia_au_get_unq(au, "cnonce",    auth_cnonce_buf,    sizeof(auth_cnonce_buf));
	auth_qop       = sofia_au_get_unq(au, "qop",       auth_qop_buf,       sizeof(auth_qop_buf));
	auth_algorithm = sofia_au_get_unq(au, "algorithm", auth_algorithm_buf, sizeof(auth_algorithm_buf));
	auth_username  = sofia_au_get_unq(au, "username",  auth_username_buf,  sizeof(auth_username_buf));

		/* Anti-downgrade (RFC 7616 §3.3, case-insensitive): accept ONLY an offered
		 * algorithm; missing algorithm= implies MD5, rejected 400 if MD5 not offered. */
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

	/* uri= required (RFC 2617 §3.2.2). */
	if (!auth_uri) {
		nua_respond(nh, SIP_400_BAD_REQUEST, NUTAG_WITH_THIS(nua), TAG_END());
		ast_verbose("Sofia: %s auth rejected for '%s' - uri= missing\n",
			method, peer->name);
		sofia_blacklist_add_sip(sip, "digest missing uri");
		return SOFIA_AUTH_REJECT;
	}

	/* digest-uri MUST agree with the Request-URI (RFC 2617 §3.2.2.5 / RFC 7616 §3.4.4).
	 * The uri= directive is folded into H(A2), so a credential captured for one target
	 * cannot be replayed at another only if the SERVER also verifies the binding. Compare
	 * the client's uri= against the actual Request-URI structurally (scheme/user/host/port,
	 * default-port + case aware via url_cmp) — tolerant of URI params/ordering the proxy may
	 * have rewritten, strict on the identity that binds the credential to the target. */
	if (sip && sip->sip_request && sip->sip_request->rq_url) {
		su_home_t uhome[1] = { SU_HOME_INIT(uhome) };
		url_t *client_uri = url_make(uhome, auth_uri);
		int uri_mismatch = (!client_uri || url_cmp(client_uri, sip->sip_request->rq_url) != 0);
		su_home_deinit(uhome);
		if (uri_mismatch) {
			char ruri_str[256] = "";
			su_home_t rhome[1] = { SU_HOME_INIT(rhome) };
			char *rs = url_as_string(rhome, sip->sip_request->rq_url);
			if (rs) {
				ast_copy_string(ruri_str, rs, sizeof(ruri_str));
			}
			su_home_deinit(rhome);
			nua_respond(nh, SIP_400_BAD_REQUEST, NUTAG_WITH_THIS(nua), TAG_END());
			ast_verbose("Sofia: %s auth rejected for '%s' - digest uri='%s' does not match Request-URI '%s'\n",
				method, peer->name, auth_uri, ruri_str);
			sofia_blacklist_add_sip(sip, "digest uri mismatch");
			return SOFIA_AUTH_REJECT;
		}
	}

	/* Realm mismatch → 401-stale (RFC 2617 §3.2.1, byte-exact; missing realm = mismatch).
	 * Cross-realm replay prevention. */
	if (!auth_realm || strcmp(auth_realm, realm) != 0) {
		char chal_nonce[96];
		/* Fresh stateless nonce (no peer nonce state to clobber). */
		sofia_make_auth_nonce(peer->name, realm, method, chal_nonce, sizeof(chal_nonce));
		sofia_emit_auth_challenge(nua, nh, realm, chal_nonce, 1);
		ast_verbose("Sofia: %s auth realm mismatch for '%s' - expected '%s' got '%s'\n",
			method, peer->name, realm, auth_realm ? auth_realm : "(none)");
		return SOFIA_AUTH_CHALLENGE;
	}

	using_qop = (auth_qop && !strcasecmp(auth_qop, "auth"));

	/* When auth_qop=yes we challenge qop="auth", so a PRESENT non-"auth" qop is a downgrade:
	 * accepting it falls through to RFC 2069 no-qop digest, bypassing nc/cnonce
	 * replay tracking. (With auth_qop=no we challenge no-qop already; this reject still
	 * guards against a client offering a bogus non-"auth" qop.) Check RAW header presence
	 * (oversized qop → auth_qop NULL → would misread as "no qop"). MISSING qop is still
	 * accepted (RFC 2069 compat). */
	if (au && msg_header_find_param(au->au_common, "qop") && !using_qop) {
		nua_respond(nh, SIP_400_BAD_REQUEST, NUTAG_WITH_THIS(nua), TAG_END());
		ast_verbose("Sofia: %s auth rejected for '%s' - unsupported/oversized qop (only qop=auth is offered)\n",
			method, peer->name);
		sofia_blacklist_add_sip(sip, "digest unsupported qop");
		return SOFIA_AUTH_REJECT;
	}

	/* RFC 2617 §3.2.2: qop present requires nc + cnonce. */
	if (auth_qop && (!auth_nc || !auth_cnonce)) {
		nua_respond(nh, SIP_400_BAD_REQUEST, NUTAG_WITH_THIS(nua), TAG_END());
		ast_verbose("Sofia: %s auth rejected for '%s' - qop without nc/cnonce\n",
			method, peer->name);
		sofia_blacklist_add_sip(sip, "digest malformed qop");
		return SOFIA_AUTH_REJECT;
	}

	if (using_qop) {
		char *endptr = NULL;
		/* nc is EXACTLY 8 LHEX (RFC 2617). Validate format BEFORE strtoul, which
		 * accepts "-1" -> ULONG_MAX -> UINT_MAX, passing !=0 and poisoning
		 * peer->last_nc (self-replay-DoS until nonce rotates). */
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

	/* Stateless nonce validation (replaces the per-peer nonce_dead/nonce_matches/nc_replay model):
	 * pure HMAC + TTL, no peer lock. Invalid (forged/foreign) or expired -> re-challenge fresh (stale). */
	{
		int nv = sofia_validate_auth_nonce(auth_nonce, peer->name, realm, method, &nonce_issue_ts);
		if (nv != 0) {
			char fresh[96];
			sofia_make_auth_nonce(peer->name, realm, method, fresh, sizeof(fresh));
			sofia_emit_auth_challenge(nua, nh, realm, fresh, 1);
			if (sofia_debug) {
				ast_verbose("Sofia: %s auth for '%s' - %s nonce; re-challenged\n",
					method, peer->name, nv < 0 ? "invalid" : "expired");
			}
			return SOFIA_AUTH_CHALLENGE;
		}
	}

	ast_mutex_lock(&peer->lock);

	/* RFC 2617 §3.2.2.2 / RFC 7616 §3.4.2: HA1 = unq(username):realm:passwd, where username is the
	 * one in the Authorization header. Require it to equal the peer's CONFIGURED digest username
	 * (defaultuser — what `username=`/`defaultuser=` set, falling back to the section name) BEFORE
	 * computing/accepting any HA1 (incl. md5secret), so a peer matched by From/IP/To cannot
	 * authenticate as a different username with this peer's secret (anti-impersonation). The username
	 * is not a secret -> plain compare; a missing username is a malformed digest (400). */
	{
		const char *expected_user = !ast_strlen_zero(peer->defaultuser) ? peer->defaultuser : peer->name;
		if (!auth_username || strcmp(auth_username, expected_user) != 0) {
			char snap_name[80], snap_exp[128];
			int missing = !auth_username;
			ast_copy_string(snap_name, peer->name, sizeof(snap_name));
			ast_copy_string(snap_exp, expected_user, sizeof(snap_exp));
			ast_mutex_unlock(&peer->lock);
			if (missing) {
				nua_respond(nh, SIP_400_BAD_REQUEST, NUTAG_WITH_THIS(nua), TAG_END());
				ast_verbose("Sofia: %s auth rejected for '%s' - username= missing\n", method, snap_name);
				sofia_blacklist_add_sip(sip, "digest missing username");
			} else {
				nua_respond(nh, SIP_403_FORBIDDEN, NUTAG_WITH_THIS(nua), TAG_END());
				ast_verbose("Sofia: %s auth rejected for '%s' - username '%s' != configured '%s'\n",
					method, snap_name, auth_username, snap_exp);
				sofia_blacklist_add_sip(sip, "digest username mismatch");
			}
			return SOFIA_AUTH_REJECT;
		}
	}

	/* (The per-peer nonce_dead/nonce_matches/nc_replay block was removed: the nonce is now validated
	 * statelessly above (HMAC+TTL), and nc replay is enforced per-nonce AFTER the digest verify below.) */

	/* md5secret is a pre-computed MD5(user:realm:secret), MD5-only, and takes
	 * precedence over peer->secret — so an md5secret peer cannot satisfy a SHA-256
	 * client (silent 403). Recover by re-challenging MD5-only. If MD5 is globally
	 * disabled (auth_algorithms=sha256) the config is irreconcilable: 403 + warn.
	 * Runs under peer->lock. */
	if (algorithm == SOFIA_DIGEST_SHA256 && !ast_strlen_zero(peer->md5secret)) {
		int want_md5, want_sha256;
		sofia_auth_offered(&want_md5, &want_sha256);
		if (want_md5) {
			char fresh_nonce[96];
			char hdr_md5[256];
			char pname[80];
			/* Re-challenge MD5-only with a FRESH stateless nonce (snapshot the name, drop the lock
			 * before the urandom read inside sofia_make_auth_nonce). */
			ast_copy_string(pname, peer->name, sizeof(pname));
			ast_mutex_unlock(&peer->lock);
			sofia_make_auth_nonce(pname, realm, method, fresh_nonce, sizeof(fresh_nonce));
			sofia_build_md5_challenge(hdr_md5, sizeof(hdr_md5), realm, fresh_nonce, /*stale=*/1);
			nua_respond(nh, SIP_401_UNAUTHORIZED,
				SIPTAG_WWW_AUTHENTICATE_STR(hdr_md5),
				NUTAG_WITH_THIS(nua), TAG_END());
			ast_verbose("Sofia: %s for md5secret peer '%s' requested SHA-256 — re-challenging MD5-only\n",
				method, pname);
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

	/* Compute expected response under peer->lock (secret/name read-stable). The nonce folded into the
	 * response is the client's auth_nonce (already HMAC+TTL validated above), NOT a per-peer stored nonce. */
	if (sofia_compute_digest(peer, realm, method, auth_uri,
			auth_nonce, auth_nc, auth_cnonce,
			using_qop ? "auth" : NULL,
			algorithm,
			expected_hash) != 0) {
		/* OOM building HA1/HA2 → 500; never compare against a partial hash. */
		ast_mutex_unlock(&peer->lock);
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, NUTAG_WITH_THIS(nua), TAG_END());
		ast_verbose("Sofia: %s auth digest-compute failed (OOM) for '%s' — rejecting\n",
			method, peer->name);
		return SOFIA_AUTH_REJECT;
	}

	/* Constant-time compare over hash_len_hex (32 MD5 / 64 SHA-256). */
	if (!auth_response || sofia_ct_memcmp(auth_response, expected_hash, hash_len_hex) != 0) {
		ast_mutex_unlock(&peer->lock);
		nua_respond(nh, SIP_403_FORBIDDEN, NUTAG_WITH_THIS(nua), TAG_END());
		ast_verbose("Sofia: %s auth failed for '%s' - bad response\n",
			method, peer->name);
		sofia_blacklist_add_sip(sip, "digest bad response");
		return SOFIA_AUTH_REJECT;
	}

	/* Digest is VALID. Drop the peer lock, then enforce nc replay PER NONCE in the leaf-locked cache
	 * (never under peer->lock). REGISTER is idempotent (a phone's nc=1 refresh) -> exempt; no-qop has
	 * no nc to track. A valid-but-replayed nc (<= the max already recorded for THIS nonce) -> 401 stale
	 * + a fresh nonce; a legit client re-auths once. NO per-peer nonce/nc state is touched, so a phone's
	 * concurrent transactions never stale each other (the production loop is gone). Insertion happens only
	 * here (post-valid-digest), so an unauthenticated flood can never fill the cache. */
	ast_mutex_unlock(&peer->lock);

	if (using_qop && !register_method) {
		if (sofia_nonce_replay_check(auth_nonce, new_nc, nonce_issue_ts)) {
			char fresh_nonce[96];
			sofia_make_auth_nonce(peer->name, realm, method, fresh_nonce, sizeof(fresh_nonce));
			sofia_emit_auth_challenge(nua, nh, realm, fresh_nonce, 1);
			if (sofia_debug) {
				ast_verbose("Sofia: %s auth for '%s' - valid but nc replay on this nonce; re-challenged\n",
					method, peer->name);
			}
			return SOFIA_AUTH_CHALLENGE;
		}
	}

	return SOFIA_AUTH_OK;
}

/* Out-of-dialog MESSAGE digest gate (RFC 3428): a MESSAGE from a configured, credentialed
 * peer must pass the SAME challenge/verify as INVITE before reaching the dialplan — otherwise
 * the From-user is trusted unauthenticated. Exported for sofia_message.c (the static verifier
 * + enum stay private to this TU).
 *
 *   peer == NULL  -> guest sender; nothing to authenticate here (caller applies allowguest).
 *   peer w/o creds -> nothing to verify; proceed.
 *   peer w/ creds  -> challenge/verify; on non-OK the 401/4xx is already emitted.
 *
 * Returns 0 = proceed (authenticated or no creds); nonzero = a response was sent, STOP
 * (caller must reap the out-of-dialog handle). The pbx_authorization fallback mirrors the
 * INVITE path (RFC 3261 §22). */
int sofia_message_authenticate(struct sofia_peer *peer, nua_t *nua, nua_handle_t *nh,
		sip_t const *sip)
{
	char realm_buf[MAXHOSTNAMELEN];
	const char *realm;
	sip_authorization_t const *au;
	enum sofia_auth_result auth_res;
	int has_creds;

	if (!peer) {
		return 0;	/* guest: caller's allowguest policy decides */
	}

	ast_mutex_lock(&peer->lock);
	has_creds = !ast_strlen_zero(peer->secret) || !ast_strlen_zero(peer->md5secret);
	ast_mutex_unlock(&peer->lock);

	if (!has_creds) {
		return 0;	/* peer matched but has no shared secret to verify against */
	}

	realm = sofia_get_realm_for_dialog(sip, realm_buf, sizeof(realm_buf));
	au = sip->sip_authorization
		? sip->sip_authorization
		: (sip_authorization_t const *)sip->sip_proxy_authorization;
	auth_res = sofia_verify_digest_auth(peer, nua, nh, sip, au, "MESSAGE", realm);
	return (auth_res == SOFIA_AUTH_OK) ? 0 : 1;
}

/* Identify + authenticate the sender of an out-of-dialog MESSAGE (RFC 3261 §22 parity with
 * INVITE/REGISTER). The sender is keyed by the digest Authorization username, NOT the From-user — in a
 * numeric-extension deployment the From-user is the dialed number while the peer/auth name differs, so a
 * From-user lookup would fail and leave no trustworthy subscribecontext. Flow: pick the auth username
 * (falls back to From-user), find the peer, verify the digest; challenge an unknown/unauthenticated
 * sender (alwaysauthreject parity) so the UA re-sends with Authorization and is then identified by the
 * auth username. Returns the authenticated peer (ao2 +1, caller releases) with *challenged=0; on a
 * 401/4xx it reaps the out-of-dialog handle and returns NULL with *challenged=1; an anonymous, un-
 * challenged sender returns NULL with *challenged=0 (caller's guest policy decides). sofia_thread. */
struct sofia_peer *sofia_message_authenticate_sender(nua_t *nua, nua_handle_t *nh, sip_t const *sip,
		int *challenged)
{
	const char *from_user = NULL;
	char auth_user_buf[128];
	const char *auth_user;
	struct sofia_peer *peer;

	if (challenged) {
		*challenged = 0;
	}
	if (sip && sip->sip_from && sip->sip_from->a_url) {
		from_user = sip->sip_from->a_url->url_user;
	}
	auth_user = sofia_pick_auth_username(sip, from_user, auth_user_buf, sizeof(auth_user_buf));
	peer = (!ast_strlen_zero(auth_user)) ? sofia_find_peer(auth_user) : NULL;

	/* Source-IP ACL (peer->ha) BEFORE the digest, parity with INVITE/REGISTER/SUBSCRIBE. On deny, drop
	 * the peer and fall to the unknown-peer challenge below (401) rather than 403, so peer existence is
	 * not leaked (anti-enumeration). sofia_thread: peer->ha is stable during processing. */
	if (peer && peer->ha) {
		struct ast_sockaddr src;
		sofia_get_source_addr(sip, &src);
		if (ast_apply_ha(peer->ha, &src) != AST_SENSE_ALLOW) {
			char realm_buf[MAXHOSTNAMELEN];
			const char *realm = sofia_get_realm_for_dialog(sip, realm_buf, sizeof(realm_buf));
			ast_log(LOG_NOTICE, "Sofia: MESSAGE from %s rejected by peer '%s' ACL\n",
				ast_sockaddr_stringify(&src), peer->name);
			ao2_ref(peer, -1);
			/* TERMINAL: challenge (401, anti-enumeration) and stop — never fall through to the guest
			 * message_context path, else a denied peer could inject under allowguest=yes. */
			sofia_send_auth_challenge(nua, nh, sip, realm, "MESSAGE", "ACLDenied", NULL, 1);
			if (challenged) {
				*challenged = 1;
			}
			return NULL;
		}
	}

	if (peer) {
		if (sofia_message_authenticate(peer, nua, nh, sip)) {
			/* verifier already emitted the 401/4xx; reap the fresh out-of-dialog handle */
			ao2_ref(peer, -1);
			if (nua_handle_magic(nh) == NULL) {
				nua_handle_destroy(nh);
			}
			if (challenged) {
				*challenged = 1;
			}
			return NULL;
		}
		return peer;	/* authenticated; caller releases */
	}

	if (sofia_cfg.alwaysauthreject) {
		char realm_buf[MAXHOSTNAMELEN];
		const char *realm = sofia_get_realm_for_dialog(sip, realm_buf, sizeof(realm_buf));
		sofia_send_auth_challenge(nua, nh, sip, realm, "MESSAGE", "UnknownPeer", NULL, 1);
		if (challenged) {
			*challenged = 1;
		}
		return NULL;
	}
	return NULL;	/* guest; caller's allowguest policy decides */
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

/* Timing-equalized reject: inject dummy HMAC computation, mitigating
 * username-enumeration via a timing oracle across the auth-fail / ACL-deny /
 * unknown-peer paths. The cheap, deterministic SHA work runs INLINE on
 * sofia_thread; the 10-50ms jitter delay that masks residual timing variance is
 * now done ASYNCHRONOUSLY (see sofia_delay_reject_schedule) so the dispatcher is
 * never parked — a reject flood no longer self-DoSes signalling.
 *
 * Dummy work: 3× SHA-256 hashes matching the real auth-fail path
 * (sofia_compute_a1_hash + a2 + final response); the volatile sink prevents
 * dead-code elimination. (The AMI AuthFailure event is emitted on the 401 path;
 * GabPBX has no EVENT_FLAG_SECURITY, so EVENT_FLAG_SYSTEM is used, matching the
 * other chan_sofia AMI events.) */
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
}

/* Emit the AMI AuthFailure for an unknown-peer 401 (from snapshotted ctx fields). */
static void sofia_delay_reject_emit_authfailure(const struct sofia_delay_reject_ctx *ctx)
{
	manager_event(EVENT_FLAG_SYSTEM, "AuthFailure",
		"Peer: SIP/UNKNOWN\r\n"
		"Method: %s\r\n"
		"Reason: %s\r\n"
		"RemoteAddr: %s\r\n"
		"ChannelType: SIP\r\n",
		ctx->method[0] ? ctx->method : "UNKNOWN",
		ctx->reason[0] ? ctx->reason : "UnknownPeer",
		ctx->src_addr);
}

/* Emit the final response NOW (no delay). Runs ON sofia_thread (both the timer-fire
 * path and the overload/failure immediate path). Does NOT touch the pending list or
 * the nua_handle ref — the caller owns that bookkeeping. */
static void sofia_delay_reject_emit_now(const struct sofia_delay_reject_ctx *ctx)
{
	if (ctx->kind == SOFIA_DELAY_REJECT_401_CHALLENGE) {
		sofia_emit_auth_challenge(ctx->nua, ctx->nh, ctx->realm, ctx->nonce, 0);
		sofia_delay_reject_emit_authfailure(ctx);
	} else {
		nua_respond(ctx->nh, SIP_403_FORBIDDEN,
			NUTAG_WITH_THIS(ctx->nua), TAG_END());
	}
}

/* Deferred-cleanup fence (the residual-race fix). Runs ON sofia_thread AFTER the final
 * 401/403 has been queued (emit-first ordering). Drops the optional pvt pin and reaps the
 * optional unbound SUBSCRIBE handle. ORDER matters:
 *   1) emit (done by the caller, BEFORE this) so nua_respond queues the final response,
 *   2) ao2_ref(pvt_ref,-1) — releasing the pvt may run its destructor which dispatches
 *      nua_handle_destroy -> nta_incoming_destroy; but the final response is already queued,
 *      so the auto-500 is suppressed (the request is answered),
 *   3) sofia_subscribe_reject_reap(nh) for the unbound-handle case — same reasoning: the
 *      deferred 401 is queued first, so reaping no longer races an immediate 500 ahead of us.
 * Both fields are no-ops when unset, so every emit path (timer/immediate/failure/unload) can
 * call this uniformly. The nh unref (the original handle pin) is NOT done here — callers do
 * it after, since the unload sweep never reaps (it emits nothing). */
static void sofia_delay_reject_deferred_cleanup(struct sofia_delay_reject_ctx *ctx)
{
	if (ctx->pvt_ref) {
		ao2_ref(ctx->pvt_ref, -1);
		ctx->pvt_ref = NULL;
	}
	if (ctx->reap_handle_on_fire) {
		ctx->reap_handle_on_fire = 0;
		sofia_subscribe_reject_reap(ctx->nh);
	}
}

/* One-shot su_timer callback — fires ON sofia_thread (the su_root task), 10-50ms after
 * scheduling. Unlink the ctx under the list lock (lock NOT held across any nua_* call),
 * then emit the final 401/403 + AMI FIRST, then run the deferred cleanup (drop the pvt pin /
 * reap the unbound handle AFTER the response is queued — the residual-race fence), destroy our
 * OWN fired timer, drop the pinned handle ref, and free the ctx. Mirrors
 * sofia_transfer_timeout's self-destroy discipline. */
static void sofia_delay_reject_fire(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg)
{
	struct sofia_delay_reject_ctx *ctx = (struct sofia_delay_reject_ctx *)arg;

	(void)magic;
	if (!ctx) {
		return;
	}

	/* Unlink first (so the unload sweep cannot also touch this ctx), drop the
	 * global counter, then release the lock BEFORE any nua_* op. */
	AST_LIST_LOCK(&g_delay_reject_list);
	AST_LIST_REMOVE(&g_delay_reject_list, ctx, list);
	if (g_delay_reject_count > 0) {
		g_delay_reject_count--;
	}
	AST_LIST_UNLOCK(&g_delay_reject_list);

	sofia_delay_reject_emit_now(ctx);          /* 1) emit 401/403 FIRST */
	sofia_delay_reject_deferred_cleanup(ctx);  /* 2) THEN drop pvt_ref / 3) reap unbound handle */

	su_timer_destroy(t);          /* our own just-fired timer */
	nua_handle_unref(ctx->nh);    /* release the pin taken at schedule */
	ast_free(ctx);
}

/* Schedule an async delayed reject (the timing-equalized jitter, NON-blocking). Runs ON
 * sofia_thread (every callsite is inside a nua event handler). The dummy SHA work has
 * already run inline at the callsite.
 *
 * Overload FUSE: a global hard cap (SOFIA_DELAY_REJECT_MAX) plus a soft per-source cap
 * bounds in-flight timers; on exceed -> emit IMMEDIATELY (no delay), trading the timing
 * oracle for availability (the blacklist path still applies). FAILURE POLICY: if ctx
 * alloc / nua_handle_ref / su_timer_create / su_timer_set fails -> emit IMMEDIATELY +
 * WARN; NEVER fall back to a blocking sleep.
 *
 * src is the request source addr (for the per-source fuse + the 401 AMI RemoteAddr). */
static void sofia_delay_reject_schedule(enum sofia_delay_reject_kind kind,
		nua_t *nua, nua_handle_t *nh,
		const char *realm, const char *nonce,
		const char *method, const char *reason,
		const struct ast_sockaddr *src,
		struct sofia_pvt *pvt_ref, int reap_handle_on_fire)
{
	struct sofia_delay_reject_ctx *ctx;
	struct sofia_delay_reject_ctx *iter;
	su_duration_t delay_ms;
	int over_cap = 0;
	int per_src = 0;
	char src_buf[80] = "";

	if (src) {
		ast_copy_string(src_buf, ast_sockaddr_stringify(src), sizeof(src_buf));
	}

	/* Take the scheduler-owned +1 on the pvt pin NOW, before ANY path that runs deferred_cleanup:
	 * the caller drops its OWN ref right after we return, so THIS ref is what keeps the pvt + its
	 * bound handle + NTA server request alive until we emit. Every deferred_cleanup path (timer fire,
	 * overcap, alloc/ref/timer failure, unload) drops exactly this one ref. (Without it the
	 * doc claimed this ref but the code never took it = a dangling raw pointer / under-unref UAF.) */
	if (pvt_ref) {
		ao2_ref(pvt_ref, +1);
	}

	/* Build the ctx snapshot first (off-lock). On alloc failure -> emit immediately, then run
	 * the same deferred cleanup (drop the caller's pvt pin / reap the unbound handle) so neither
	 * the pvt ref nor the reap is leaked/skipped on this path. The stack ctx carries pvt_ref +
	 * reap_handle_on_fire so the shared cleanup helper does the right thing. */
	ctx = ast_calloc(1, sizeof(*ctx));
	if (!ctx) {
		struct sofia_delay_reject_ctx stackctx = { 0 };
		ast_log(LOG_WARNING, "Sofia: delayed-reject ctx alloc failed — emitting %s immediately\n",
			kind == SOFIA_DELAY_REJECT_401_CHALLENGE ? "401" : "403");
		stackctx.kind = kind;
		stackctx.nua = nua;
		stackctx.nh = nh;
		stackctx.pvt_ref = pvt_ref;
		stackctx.reap_handle_on_fire = reap_handle_on_fire;
		if (realm)  ast_copy_string(stackctx.realm, realm, sizeof(stackctx.realm));
		if (nonce)  ast_copy_string(stackctx.nonce, nonce, sizeof(stackctx.nonce));
		if (method) ast_copy_string(stackctx.method, method, sizeof(stackctx.method));
		if (reason) ast_copy_string(stackctx.reason, reason, sizeof(stackctx.reason));
		ast_copy_string(stackctx.src_addr, src_buf, sizeof(stackctx.src_addr));
		sofia_delay_reject_emit_now(&stackctx);
		sofia_delay_reject_deferred_cleanup(&stackctx);
		return;
	}
	ctx->kind = kind;
	ctx->nua = nua;
	ctx->nh = nh;
	ctx->pvt_ref = pvt_ref;
	ctx->reap_handle_on_fire = reap_handle_on_fire;
	if (realm)  ast_copy_string(ctx->realm, realm, sizeof(ctx->realm));
	if (nonce)  ast_copy_string(ctx->nonce, nonce, sizeof(ctx->nonce));
	if (method) ast_copy_string(ctx->method, method, sizeof(ctx->method));
	if (reason) ast_copy_string(ctx->reason, reason, sizeof(ctx->reason));
	ast_copy_string(ctx->src_addr, src_buf, sizeof(ctx->src_addr));

	/* FUSE check under the list lock (counters guarded by it). No nua_* under this lock. */
	AST_LIST_LOCK(&g_delay_reject_list);
	if (g_delay_reject_count >= SOFIA_DELAY_REJECT_MAX) {
		over_cap = 1;
	} else if (src_buf[0]) {
		AST_LIST_TRAVERSE(&g_delay_reject_list, iter, list) {
			if (!strcmp(iter->src_addr, src_buf) && ++per_src >= SOFIA_DELAY_REJECT_PER_SRC) {
				over_cap = 1;
				break;
			}
		}
	}
	AST_LIST_UNLOCK(&g_delay_reject_list);

	if (over_cap) {
		/* Overload: prefer availability over the timing oracle — respond now, then run the
		 * deferred cleanup (drop pvt_ref / reap the unbound handle), same as the timer would. */
		sofia_delay_reject_emit_now(ctx);
		sofia_delay_reject_deferred_cleanup(ctx);
		ast_free(ctx);
		return;
	}

	/* Pin the handle so it cannot vanish before the timer fires. */
	if (!nua_handle_ref(nh)) {
		ast_log(LOG_WARNING, "Sofia: delayed-reject nua_handle_ref failed — emitting immediately\n");
		sofia_delay_reject_emit_now(ctx);
		sofia_delay_reject_deferred_cleanup(ctx);
		ast_free(ctx);
		return;
	}

	/* Jitter 10-50ms = 10 + random(0..39) ms, matching the former blocking sleep window. */
	delay_ms = (su_duration_t)(10 + (ast_random() % 40));
	ctx->timer = su_timer_create(su_root_task(sofia_root), delay_ms);
	if (!ctx->timer) {
		ast_log(LOG_WARNING, "Sofia: delayed-reject su_timer_create failed — emitting immediately\n");
		sofia_delay_reject_emit_now(ctx);
		sofia_delay_reject_deferred_cleanup(ctx);
		nua_handle_unref(nh);
		ast_free(ctx);
		return;
	}

	/* Publish into the pending list BEFORE arming so a same-thread fire (su_root is
	 * single-threaded, so the timer can only fire after we return, but keep the
	 * invariant tight) always finds the ctx linked. */
	AST_LIST_LOCK(&g_delay_reject_list);
	AST_LIST_INSERT_HEAD(&g_delay_reject_list, ctx, list);
	g_delay_reject_count++;
	AST_LIST_UNLOCK(&g_delay_reject_list);

	if (su_timer_set(ctx->timer, sofia_delay_reject_fire, ctx) < 0) {
		ast_log(LOG_WARNING, "Sofia: delayed-reject su_timer_set failed — emitting immediately\n");
		AST_LIST_LOCK(&g_delay_reject_list);
		AST_LIST_REMOVE(&g_delay_reject_list, ctx, list);
		if (g_delay_reject_count > 0) {
			g_delay_reject_count--;
		}
		AST_LIST_UNLOCK(&g_delay_reject_list);
		su_timer_destroy(ctx->timer);
		sofia_delay_reject_emit_now(ctx);
		sofia_delay_reject_deferred_cleanup(ctx);
		nua_handle_unref(nh);
		ast_free(ctx);
		return;
	}
	/* Armed: the timer callback (sofia_delay_reject_fire) now owns the ctx, the handle
	 * ref and the timer; it will respond, unref, destroy + free in 10-50ms. */
}

/* Cancel + destroy every pending delayed-reject timer and free its ctx. MUST run on
 * sofia_thread (the su_root task) during module teardown, BEFORE nua_destroy /
 * su_root_destroy, so a firing timer can never deref freed code or a destroyed handle.
 * We do NOT emit the deferred responses (the stack is going away). The list lock is held
 * only to detach the batch; su_timer_destroy + nua_handle_unref + free run off-lock. */
static void sofia_delay_reject_shutdown(void)
{
	struct sofia_delay_reject_ctx *ctx;

	for (;;) {
		AST_LIST_LOCK(&g_delay_reject_list);
		ctx = AST_LIST_REMOVE_HEAD(&g_delay_reject_list, list);
		if (ctx && g_delay_reject_count > 0) {
			g_delay_reject_count--;
		}
		AST_LIST_UNLOCK(&g_delay_reject_list);
		if (!ctx) {
			break;
		}
		if (ctx->timer) {
			su_timer_destroy(ctx->timer);   /* cancels the pending one-shot */
		}
		/* Same deferred cleanup as a fire, minus the (suppressed) emit: drop the pvt pin and
		 * reap the unbound handle so we never leak the pvt ref nor orphan the server handle on
		 * the teardown path. Runs on sofia_thread BEFORE nua_destroy, so reap is safe here. */
		sofia_delay_reject_deferred_cleanup(ctx);
		nua_handle_unref(ctx->nh);
		ast_free(ctx);
	}
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

/* Shared 401 challenge helper (INVITE / REGISTER / SUBSCRIBE). Each caller threads its OWN
 * correct deferred cleanup through into the scheduler so the timer can win the race against
 * nta_incoming_destroy's auto-500 (the residual-race fix):
 *   - pvt_ref          : INVITE unknown-peer path — an extra ao2 ref on the fresh pvt to pin
 *                        the bound handle + its NTA server request until we emit; the caller
 *                        MUST NOT have dropped its OWN ref expecting destruction yet (it does so
 *                        after this returns), this is an ADDITIONAL pin the scheduler owns.
 *   - reap_handle_on_fire : SUBSCRIBE unknown-peer path — the server handle is UNBOUND (no pvt),
 *                        so instead of pinning we reap it (sofia_subscribe_reject_reap) AFTER the
 *                        deferred 401 is queued. The SUBSCRIBE callers MUST NOT reap immediately.
 *   - REGISTER         : passes NULL + 0 — its handle is neither pvt-bound here nor reaped, so it
 *                        is unaffected (the destructor/auto-reap machinery does not apply). */
static void sofia_send_auth_challenge(nua_t *nua, nua_handle_t *nh, sip_t const *sip,
		const char *realm, const char *method, const char *reason,
		struct sofia_pvt *pvt_ref, int reap_handle_on_fire)
{
	/* Real fresh nonce (not a literal "empty" placeholder) so an attacker cannot
	 * distinguish unknown-peer from known-peer responses, plus the same
	 * algorithm offer as sofia_verify_digest_auth. */
	char fresh_nonce[96];
	struct ast_sockaddr src;

	/* SAME stateless nonce format as the verifier, scope "*" (unknown peer): the nonce SHAPE no longer
	 * leaks known-vs-unknown, and the verifier's wildcard fallback validates it on the authenticated retry. */
	sofia_make_auth_nonce("*", realm, method, fresh_nonce, sizeof(fresh_nonce));

	/* Header-injection defense-in-depth: validate the realm + fresh_nonce
	 * charset before emission (realm is operator-config, nonce is hex-only by
	 * construction). */
	if (!sofia_auth_str_safe(realm) || !sofia_auth_str_safe(fresh_nonce)) {
		struct sofia_delay_reject_ctx tmp = { 0 };
		ast_log(LOG_WARNING, "Sofia: refusing to emit auth challenge — "
			"unsafe characters in realm or nonce (defense-in-depth)\n");
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR,
			NUTAG_WITH_THIS(nua), TAG_END());
		/* This early return never reaches the scheduler, so we must still run the caller's
		 * deferred cleanup HERE (after the explicit 500 is queued): drop the pvt pin / reap the
		 * unbound handle, else the pvt ref leaks or the handle is orphaned. */
		tmp.nh = nh;
		/* No scheduler ref was taken here (we bypassed the scheduler), and the 500 was emitted
		 * SYNCHRONOUSLY above while the caller still owns pvt - so do NOT drop a pvt ref here (the
		 * caller drops its own after we return). Keep only the unbound-SUBSCRIBE reap. */
		tmp.pvt_ref = NULL;
		tmp.reap_handle_on_fire = reap_handle_on_fire;
		sofia_delay_reject_deferred_cleanup(&tmp);
		return;
	}

	/* Timing-equalization: the cheap deterministic dummy HMAC runs INLINE here to
	 * match known-peer-bad-password compute cost across all unknown-peer callsites. */
	sofia_emit_timing_equalized_reject();

	sofia_get_source_addr(sip, &src);

	/* The 10-50ms jitter + the actual 401 challenge + the AMI AuthFailure are deferred
	 * ASYNCHRONOUSLY onto a su_timer (NON-blocking — the dispatcher is not parked). The
	 * challenge is rebuilt in the timer callback from the snapshotted realm+nonce (same
	 * global MD5/SHA-256 offer as everyone else, applied inside sofia_emit_auth_challenge).
	 * Under overload (fuse tripped) or scheduling failure, it is emitted immediately. */
	sofia_delay_reject_schedule(SOFIA_DELAY_REJECT_401_CHALLENGE,
		nua, nh, realm, fresh_nonce,
		method ? method : "UNKNOWN", reason ? reason : "UnknownPeer", &src,
		pvt_ref, reap_handle_on_fire);
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
		/* REGISTER: no pvt pin and no reap — the REGISTER server handle is neither
		 * pvt-bound here nor reaped by us, so it is unaffected by the residual-race fence. */
		sofia_send_auth_challenge(nua, nh, sip, realm, "REGISTER", "UserAgentMismatch", NULL, 0);
	}

	sofia_get_source_addr(sip, &src);
	ast_copy_string(addr_buf, ast_sockaddr_stringify(&src), sizeof(addr_buf));

	/* current_ua is the raw inbound User-Agent header — copy into a mutable buffer
	 * and drop CR/LF/control chars before it reaches manager_event (which does no
	 * embedded-CRLF stripping) so a stray CR/LF can't inject forged AMI lines. */
	char ua_buf[256];
	ast_copy_string(ua_buf, current_ua ? current_ua : "", sizeof(ua_buf));
	sofia_quoted_name_sanitize(ua_buf);

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
		ua_buf,
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

/* === Bounded REGISTER realtime-DB-write offload ===================== */

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

/* Create the lane taskprocessors once (idempotent). Any lane failure unwinds and leaves
 * the pool disabled (sofia_regpool_n stays 0 -> REGISTER stays inline). */
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

/* Reconcile the pool with config (called from sofia_apply_config); register_pool=yes/no
 * toggles the kill-switch at runtime via `sofia reload`. */
static void sofia_regpool_update(void)
{
	if (sofia_cfg.register_pool && sofia_regpool_n == 0) {
		sofia_regpool_create();
	}
	/* Lane count is fixed at first creation (taskprocessors can't be torn down at runtime);
	 * a changed worker count needs a restart, so warn rather than silently ignore it. */
	if (sofia_regpool_n > 0 && sofia_cfg.register_pool_workers > 0
			&& sofia_cfg.register_pool_workers != sofia_regpool_n) {
		ast_log(LOG_NOTICE, "Sofia: register_pool_workers=%d ignored — pool already has %d lane(s); restart gabpbx to change\n",
			sofia_cfg.register_pool_workers, sofia_regpool_n);
	}
	sofia_regpool_enabled = (sofia_cfg.register_pool && sofia_regpool_n > 0);
}

/* Emit one NOTICE per REGISTER attempt (success or failure): AOR, source IP, User-Agent. */
static void sofia_log_register_outcome(const char *result, const char *aor, sip_t const *sip)
{
	struct ast_sockaddr src;
	const char *ua = (sip && sip->sip_user_agent && sip->sip_user_agent->g_string)
		? sip->sip_user_agent->g_string : "(unknown)";

	sofia_get_source_addr(sip, &src);
	ast_log(LOG_NOTICE, "Sofia REGISTER %s: user='%s' ip=%s useragent='%s'\n",
		result, S_OR(aor, "(unknown)"), ast_sockaddr_stringify(&src), ua);
}

/* True when a REGISTER changed binding state (not a routine keepalive refresh); gates the
 * success log so phones don't flood it every ~60s. */
static int sofia_register_changed(const struct sofia_register_update *u)
{
	return u && (u->wildcard_removed || u->contacts_removed || u->contacts_added
		|| u->contacts_moved || (u->was_registered != u->now_registered));
}

/* Answer a Contact-less REGISTER — a binding QUERY (RFC 3261 §10.2.3) — with a 200 OK
 * echoing current bindings and ZERO registration-state side-effects. Caller authenticates first. */
static void sofia_respond_register_query(nua_t *nua, nua_handle_t *nh, struct sofia_peer *peer)
{
	struct ast_str *contacts = ast_str_create(256);

	if (contacts) {
		sofia_append_reg_contacts(peer, &contacts);	/* per-binding "<uri>;expires=<ttl>" */
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

/* Emit REGISTER side-effects (regexten + PeerStatus AMI + BLF devstate) AFTER peer->lock is
 * released — they take the contexts lock / emit AMI / fan out BLF, none safe under the peer
 * mutex. emit_unregister is mutually exclusive with the registered tail. Shared by both the
 * no-secret and auth 200-OK paths. */
void sofia_emit_register_side_effects(struct sofia_peer *peer, sip_t const *sip,
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
	char real_transport[16];

	if (!sip || !sip->sip_from) {
		nua_respond(nh, SIP_400_BAD_REQUEST, NUTAG_WITH_THIS(nua), TAG_END());
		return;
	}
	/* Authoritative transport from the actual delivering tport (the real connection), threaded into the
	 * contact store so ws/wss WebSocket registrations are not mis-stored as udp from a synthetic Contact. */
	sofia_incoming_transport(nua, real_transport, sizeof(real_transport));
	if (sofia_debug) {
		ast_verbose("Sofia: REGISTER incoming transport (real tport): '%s'\n",
			ast_strlen_zero(real_transport) ? "(unknown - fallback to Via/Contact)" : real_transport);
	}
	realm = sofia_get_realm_for_dialog(sip, realm_buf, sizeof(realm_buf));

	user = sip->sip_from->a_url->url_user;
	domain = sip->sip_from->a_url->url_host;

	if (sofia_debug) {
		ast_verbose("Sofia: REGISTER from %s@%s\n",
			user ? user : "(null)", domain ? domain : "(null)");
	}

	if (!user) {
		/* Malformed REGISTER (no From user): bogus challenge then reject. Honors
		 * auth_algorithms so a sha256-only deployment never advertises MD5. */
		sofia_emit_auth_challenge(nua, nh, realm, "empty", 0);
		sofia_blacklist_add_sip(sip, "REGISTER missing user");
		return;
	}

	/* match_auth_username (chan_sip parity): override the peer-lookup key with the
	 * Authorization username. Buffer at function scope so the returned pointer stays valid. */
	char auth_user_buf[128];
	if (sofia_cfg.match_auth_username) {
		user = sofia_pick_auth_username(sip, user, auth_user_buf, sizeof(auth_user_buf));
	}

	peer = sofia_find_peer(user);
	if (!peer) {
		if (sofia_cfg.alwaysauthreject) {
			/* REGISTER: no pvt pin / no reap — unaffected by the residual-race fence. */
			sofia_send_auth_challenge(nua, nh, sip, realm, "REGISTER", "UnknownPeer", NULL, 0);
			ast_verbose("Sofia: REGISTER from unknown peer '%s' — 401 challenge (alwaysauthreject)\n", user);
		} else {
			nua_respond(nh, SIP_403_FORBIDDEN, NUTAG_WITH_THIS(nua), TAG_END());
			ast_verbose("Sofia: Registration rejected for unknown peer '%s'\n", user);
		}
		sofia_log_register_outcome("REJECT (unknown peer)", user, sip);
		sofia_blacklist_add_sip(sip, "REGISTER unknown peer");
		return;
	}

	/* Per-peer ACL, BEFORE auth so a banned IP can't probe for valid credentials. */
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

	/* Path (RFC 3327 §5.3): a path=yes peer whose REGISTER carries a Path but did NOT advertise
	 * Supported: path means an intermediary inserted the Path without UA support -> reject with 420
	 * Bad Extension + Unsupported: path (RFC 3327 §7 interception-risk posture). Gated on path=yes. */
	if (peer->path_support && sip->sip_path && !sip_has_feature(sip->sip_supported, "path")) {
		sofia_log_register_outcome("REJECT (Path without Supported)", peer->name, sip);
		nua_respond(nh, 420, "Bad Extension",
			NUTAG_WITH_THIS(nua),
			SIPTAG_UNSUPPORTED_STR("path"),
			TAG_END());
		ao2_ref(peer, -1);
		return;
	}

	/* No credential at all (neither secret nor md5secret) -> accept without auth.
	 * md5secret IS a credential, so a md5secret-only peer MUST take the auth path below. */
	if (ast_strlen_zero(peer->secret) && ast_strlen_zero(peer->md5secret)) {
		/* Contact-less REGISTER = binding QUERY, no state side-effects. */
		if (!sip->sip_contact) {
			sofia_respond_register_query(nua, nh, peer);
			ao2_ref(peer, -1);
			return;
		}
		/* RFC 3261 §10.3: `expires` here is the FALLBACK for a Contact that carries no ;expires= param of its
		 * own (the Expires header value, else the local default). The actual per-Contact requested/granted TTL
		 * is computed in sofia_update_peer_contacts (the Contact ;expires= param takes precedence). Clamp
		 * ex_delta before the int cast (>INT_MAX would wrap). */
		int expires = sip->sip_expires
			? (sip->sip_expires->ex_delta > (unsigned long) INT_MAX ? INT_MAX : (int) sip->sip_expires->ex_delta)
			: peer->expiresecs;	/* configured default (defaultexpirey) when the UA omits BOTH Contact ;expires and the Expires header */
		/* Per-Contact 423 Interval Too Brief: reject the WHOLE REGISTER if ANY non-zero Contact's requested
		 * expiry is below min_expiry (RFC 3261 §10.3; the helper bypasses 0 = de-register + emits 423/Min-Expires). */
		{
			sip_contact_t const *cm;
			for (cm = sip->sip_contact; cm; cm = cm->m_next) {
				int req = sofia_contact_requested_expiry(cm, expires);
				if (sofia_check_register_expiry(nua, nh, peer, &req) < 0) {
					sofia_log_register_outcome("REJECT (interval too brief)", peer->name, sip);
					ao2_ref(peer, -1);
					return;
				}
			}
		}
		/* lockuseragent gate (chan_sip parity). */
		if (sofia_check_lockuseragent(nua, nh, sip, peer) < 0) {
			sofia_log_register_outcome("REJECT (user-agent lock)", peer->name, sip);
			sofia_blacklist_add_sip(sip, "REGISTER user-agent lock reject");
			ao2_ref(peer, -1);
			return;
		}
		ast_mutex_lock(&peer->lock);
		int rc = sofia_update_peer_contacts(peer, sip, expires, &reg_update, real_transport, nh);
		ast_mutex_unlock(&peer->lock);
		sofia_peer_ipport_reindex(peer);	/* B: re-key on the REGISTER's learned src_addr (lock released; cheap when unchanged) */
		if (rc == -4) {	/* Path serialization overflow -> reject; never bind without the route vector (RFC 3327). */
			nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, NUTAG_WITH_THIS(nua), TAG_END());
			ao2_ref(peer, -1);
			return;
		}
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
		/* rtupdate=no skips all realtime DB writes (chan_sip parity). */
		if (peer->is_realtime && sofia_cfg.peer_rtupdate) {
			sofia_rtupdate_submit(peer, sip);
		}
		/* RFC 3261 §10.3: enumerate the bindings with their GRANTED per-Contact expires (not an echo of the
		 * request Contact + one global Expires — which would show the requested value while Expires shows a
		 * cap). The top-level Expires is a representative (the primary Contact's granted TTL) for UAs that read it. */
		struct ast_str *rsp_contacts = ast_str_create(256);
		char granted_exp[16];
		int granted_top = 0;	/* representative top-level Expires: FIRST Contact with a positive granted TTL */
		{	/* skip leading ;expires=0 de-registers so a mixed REGISTER that still BINDS never advertises Expires:0 */
			sip_contact_t const *tc;
			for (tc = sip->sip_contact; tc; tc = tc->m_next) {
				int req = sofia_contact_requested_expiry(tc, expires);
				if (req > 0) { granted_top = req; break; }
			}
		}
		if (granted_top > sofia_cfg.max_expiry) {
			granted_top = sofia_cfg.max_expiry;
		}
		snprintf(granted_exp, sizeof(granted_exp), "%d", granted_top);
		if (rsp_contacts) {
			sofia_append_reg_contacts(peer, &rsp_contacts);
		}
		nua_respond(nh, SIP_200_OK,
			TAG_IF(rsp_contacts && ast_str_strlen(rsp_contacts),
				SIPTAG_CONTACT_STR(rsp_contacts && ast_str_strlen(rsp_contacts) ? ast_str_buffer(rsp_contacts) : "")),
			SIPTAG_EXPIRES_STR(granted_exp),
			TAG_IF(peer->path_support && sip->sip_path, SIPTAG_PATH(sip->sip_path)),	/* RFC 3327 §5.3 echo */
			NUTAG_WITH_THIS(nua),
			TAG_END());
		ast_free(rsp_contacts);
		sofia_verbose_register_update(peer, &reg_update);
		if (sofia_register_changed(&reg_update)) {
			sofia_log_register_outcome("OK", peer->name, sip);
		}
		sofia_emit_register_side_effects(peer, sip, &reg_update);
		/* Initial unsolicited MWI (chan_sip parity): a (re)registered peer with a mailbox= +
		 * subscribemwi=no gets its current MWI pushed now, without subscribing. */
		sofia_register_initial_mwi(peer);
		ao2_ref(peer, -1);
		return;
	}

	/* Digest verification (shared with INVITE/SUBSCRIBE): helper emits the challenge /
	 * 401-stale / 403 and handles constant-time compare, nonce gen, realm validation. */
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

	/* Captured out here so the 200 OK below the block can echo it. */
	int granted_expires_auth = DEFAULT_EXPIRY;
	{
			/* Contact-less REGISTER = binding QUERY (post-auth), no state side-effects. */
			if (!sip->sip_contact) {
				sofia_respond_register_query(nua, nh, peer);
				ao2_ref(peer, -1);
				return;
			}
			/* RFC 3261 §10.3: `expires` = the FALLBACK for a Contact with no ;expires= param (the Expires
			 * header value, else the local default); the per-Contact granted TTL is computed in
			 * sofia_update_peer_contacts (the Contact ;expires= param takes precedence). */
			int expires = sip->sip_expires
				? (sip->sip_expires->ex_delta > (unsigned long) INT_MAX ? INT_MAX : (int) sip->sip_expires->ex_delta)
				: peer->expiresecs;	/* configured default when the UA omits BOTH Contact ;expires and the Expires header */
			/* Per-Contact 423 Interval Too Brief: reject the whole REGISTER if ANY non-zero Contact is below min. */
			{
				sip_contact_t const *cm;
				for (cm = sip->sip_contact; cm; cm = cm->m_next) {
					int req = sofia_contact_requested_expiry(cm, expires);
					if (sofia_check_register_expiry(nua, nh, peer, &req) < 0) {
						sofia_log_register_outcome("REJECT (interval too brief)", peer->name, sip);
						ao2_ref(peer, -1);
						return;
					}
				}
			}
			granted_expires_auth = expires;	/* fallback; the 200 OK enumerates per-binding granted expires */
			/* lockuseragent gate (chan_sip parity). */
			if (sofia_check_lockuseragent(nua, nh, sip, peer) < 0) {
				sofia_log_register_outcome("REJECT (user-agent lock)", peer->name, sip);
				sofia_blacklist_add_sip(sip, "REGISTER user-agent lock reject");
				ao2_ref(peer, -1);
				return;
			}
			ast_mutex_lock(&peer->lock);
			int rc = sofia_update_peer_contacts(peer, sip, expires, &reg_update, real_transport, nh);
			ast_mutex_unlock(&peer->lock);
			sofia_peer_ipport_reindex(peer);	/* B: re-key on the REGISTER's learned src_addr (lock released; cheap when unchanged) */
			if (rc == -4) {	/* Path serialization overflow -> reject; never bind without the route vector (RFC 3327). */
				nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, NUTAG_WITH_THIS(nua), TAG_END());
				ao2_ref(peer, -1);
				return;
			}
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

		/* rtupdate=no skips all realtime DB writes (chan_sip parity). */
		if (peer->is_realtime && sofia_cfg.peer_rtupdate) {
			sofia_rtupdate_submit(peer, sip);
		}

		/* RFC 3261 §10.3 per-binding granted expires (see the other REGISTER 200 OK path). */
		struct ast_str *rsp_contacts = ast_str_create(256);
		char granted_exp[16];
		int granted_top = 0;	/* representative top-level Expires: FIRST Contact with a positive granted TTL */
		{	/* skip leading ;expires=0 de-registers so a mixed REGISTER that still BINDS never advertises Expires:0 */
			sip_contact_t const *tc;
			for (tc = sip->sip_contact; tc; tc = tc->m_next) {
				int req = sofia_contact_requested_expiry(tc, granted_expires_auth);
				if (req > 0) { granted_top = req; break; }
			}
		}
		if (granted_top > sofia_cfg.max_expiry) {
			granted_top = sofia_cfg.max_expiry;
		}
		snprintf(granted_exp, sizeof(granted_exp), "%d", granted_top);
		if (rsp_contacts) {
			sofia_append_reg_contacts(peer, &rsp_contacts);
		}
		nua_respond(nh, SIP_200_OK,
			TAG_IF(rsp_contacts && ast_str_strlen(rsp_contacts),
				SIPTAG_CONTACT_STR(rsp_contacts && ast_str_strlen(rsp_contacts) ? ast_str_buffer(rsp_contacts) : "")),
			SIPTAG_EXPIRES_STR(granted_exp),
			TAG_IF(peer->path_support && sip->sip_path, SIPTAG_PATH(sip->sip_path)),	/* RFC 3327 §5.3 echo */
			NUTAG_WITH_THIS(nua),
			TAG_END());
		ast_free(rsp_contacts);
		sofia_verbose_register_update(peer, &reg_update);
		if (sofia_register_changed(&reg_update)) {
			sofia_log_register_outcome("OK", peer->name, sip);
		}
		sofia_emit_register_side_effects(peer, sip, &reg_update);
		/* Initial unsolicited MWI after an AUTHENTICATED register (the other 200 path is no-auth). */
		sofia_register_initial_mwi(peer);
		ao2_ref(peer, -1);
}

/* Resolve the source IP+port presented to `target` for outbound INVITE From/Contact/SDP
 * c= (chan_sip parity): kernel route (ast_ouraddrfor) -> externaddr if NAT -> bindport
 * fallback. Populates pvt->ourip. Not called on inbound (sofia_generate_sdp covers that). */
static void sofia_resolve_ourip(struct sofia_pvt *pvt, const struct ast_sockaddr *target)
{
	if (!pvt || !target) {
		return;
	}

	/* Lazy-refresh externhost (DDNS) when its deadline expired (chan_sip parity). */
	if (sofia_cfg.externexpire && time(NULL) >= sofia_cfg.externexpire
			&& !ast_strlen_zero(sofia_cfg.externhost)) {
		struct ast_sockaddr *addrs = NULL;
		/* AST_AF_UNSPEC so an AAAA-only externhost resolves (an INET hint would drop AAAA);
		 * first result per RFC 6724. chan_sip parity. */
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
		/* Route query failed — fall back to bindaddr (better than 0.0.0.0 on the wire). */
		ast_sockaddr_parse(&pvt->ourip, sofia_cfg.bindaddr, PARSE_PORT_FORBID);
	}
	if (sofia_should_use_externaddr(target)
			&& !ast_strlen_zero(sofia_cfg.externaddr)) {
		ast_sockaddr_parse(&pvt->ourip, sofia_cfg.externaddr, PARSE_PORT_FORBID);

		/* Per-transport external port (chan_sip parity): TCP->externtcpport,
		 * TLS->externtlsport, UDP keeps externaddr/bindport.
		 * NOTE: the transport= parse now writes peer->transport, so the TCP/TLS
		 * externport branches are live for static TCP/TLS peers. */
		if (pvt->peer) {
			switch (pvt->peer->transport) {
			case SOFIA_TRANSPORT_TCP:
				if (sofia_cfg.externtcpport) {
					ast_sockaddr_set_port(&pvt->ourip, sofia_cfg.externtcpport);
				} else if (ast_sockaddr_port(&pvt->ourip)) {
				}
				break;
			case SOFIA_TRANSPORT_TLS:
				if (sofia_cfg.externtlsport) {
					ast_sockaddr_set_port(&pvt->ourip, sofia_cfg.externtlsport);
				}
				break;
			case SOFIA_TRANSPORT_UDP:
			default:
				break;
			}
		}
	}
	if (ast_sockaddr_port(&pvt->ourip) == 0) {
		ast_sockaddr_set_port(&pvt->ourip,
			sofia_cfg.bindport ? sofia_cfg.bindport : 5060);
	}
}

/* Build the outbound INVITE From URI (chan_sip parity). Identity + privacy + URI-encoding
 * come from sofia_resolve_identity. Never append ;tag= manually — nua emits the From-tag. */
static void sofia_build_from(struct sofia_pvt *pvt, char *buf, size_t len)
{
	char *lid_num = NULL, *lid_name = NULL;
	int lid_pres;
	char fromdomain[128];

	if (!buf || len < 1) {
		return;
	}
	buf[0] = '\0';

	/* sofia_uri_format_host bracket-wraps a raw IPv6 fromdomain per RFC 3261 §19.1.2. */
	char fbuf[80];
	if (sofia_resolve_identity(pvt, &lid_num, &lid_name, &lid_pres,
			fromdomain, sizeof(fromdomain)) < 0) {
		/* No identity — degrade to anonymous (still a valid From URI). */
		snprintf(buf, len, "\"Anonymous\" <sip:anonymous@%s>",
			sofia_uri_format_host(
				!ast_strlen_zero(sofia_cfg.realm) ? sofia_cfg.realm : "gabpbx",
				fbuf, sizeof(fbuf)));
		return;
	}

	/* fromuser override (chan_sip.c:12900-12901 parity): a configured peer fromuser overrides
	 * the URI user part of the outbound From. chan_sip applies it AFTER the privacy branch, so it
	 * wins in BOTH allowed and restricted presentation. Only the URI user is overridden — the
	 * display name and presentation are untouched, and RPID/PAI are NOT affected (chan_sip add_rpid
	 * never consumes fromuser). URI-encode into a local scratch buffer since lid_num arrived
	 * pre-encoded from sofia_resolve_identity. */
	const char *final_user = lid_num;
	char fromuser_enc[128];
	int have_fromuser = (pvt && pvt->peer && !ast_strlen_zero(pvt->peer->fromuser));
	if (have_fromuser) {
		ast_uri_encode(pvt->peer->fromuser, fromuser_enc, sizeof(fromuser_enc), 0);
		final_user = fromuser_enc;
	}

	/* Privacy: a restricted presentation makes the From anonymous (chan_sip.c:12876-12881 parity):
	 * display "Anonymous", domain "anonymous.invalid" (FROMDOMAIN_INVALID), URI user "anonymous" —
	 * but a configured fromuser still overrides the user part (chan_sip.c:12900). */
	if ((lid_pres & AST_PRES_RESTRICTION) != AST_PRES_ALLOWED) {
		snprintf(buf, len, "\"Anonymous\" <sip:%s@anonymous.invalid>",
			have_fromuser ? final_user : "anonymous");
		return;
	}

	/* usereqphone (chan_sip parity): add RFC 3966 ;user=phone when set and the FINAL From user is
	 * numeric (test the override result, not the stale callerid — a non-numeric fromuser must not
	 * inherit ;user=phone from a numeric callerid). */
	if (pvt && pvt->peer && pvt->peer->usereqphone && sofia_user_looks_like_phone(final_user)) {
		snprintf(buf, len, "\"%s\" <sip:%s@%s;user=phone>", lid_name, final_user,
			sofia_uri_format_host(fromdomain, fbuf, sizeof(fbuf)));
	} else {
		snprintf(buf, len, "\"%s\" <sip:%s@%s>", lid_name, final_user,
			sofia_uri_format_host(fromdomain, fbuf, sizeof(fbuf)));
	}
}

/* Build the outbound Contact header (chan_sip parity): <sip:user@host:port>, host:port from
 * pvt->ourip, user-part URI-encoded with the same fallback chain as sofia_build_from. */
static void sofia_build_contact(struct sofia_pvt *pvt, char *buf, size_t len)
{
	const char *user = NULL;
	char encoded_user[160];
	char host_port[128];

	if (!buf || len < 1) {
		return;
	}
	buf[0] = '\0';

	/* GRUU: if this peer has a usable learned pub-gruu, use it verbatim as the dialog
	 * Contact (RFC 5627 §4.4) and skip the legacy <sip:user@ourip> build. Caller holds peer->lock. */
	if (pvt && pvt->peer && sofia_gruu_dialog_contact(pvt->peer, buf, len)) {
		return;
	}

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

/* Resolve outbound identity (num/name/pres/fromdomain); returns 0, -1 on no-identity.
 * Out-pointers reference per-thread scratch; caller copies before the next call. */
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
		/* Fallback when connected.id is empty: peer cid_num -> fromuser. chan_sip parity NEVER uses the
		 * peer/section name as a From identity (that would leak the auth/account name); the global
		 * [general] callerid (default_callerid) below is the final fallback (chan_sip initreqprep). */
		if (!ast_strlen_zero(pvt->peer->cid_num)) {
			lid_num_src = pvt->peer->cid_num;
		} else if (!ast_strlen_zero(pvt->peer->fromuser)) {
			lid_num_src = pvt->peer->fromuser;
		}
	}
	if (ast_strlen_zero(lid_num_src)) {
		lid_num_src = !ast_strlen_zero(sofia_cfg.default_callerid) ? sofia_cfg.default_callerid : "gabpbx";
	}
	if (ast_strlen_zero(lid_name_src) && pvt && pvt->peer
			&& !ast_strlen_zero(pvt->peer->cid_name)) {
		lid_name_src = pvt->peer->cid_name;
	}
	if (ast_strlen_zero(lid_name_src)) {
		lid_name_src = lid_num_src;
	}

	ast_uri_encode(lid_num_src, lid_num_buf, sizeof(lid_num_buf), 0);
	ast_copy_string(lid_name_buf, lid_name_src, sizeof(lid_name_buf));
	/* Strip chars that would break the quoted-string the From/RPID/PAI builders
	 * stamp this name into (hostile/malformed caller name -> unparseable request). */
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

/* Emit outbound P-Asserted-Identity / Remote-Party-ID, gated on peer->sendrpid
 * (0=none, 1=PAI, 2=RPID); adds Privacy: id on restriction per RFC 3325 §9.3 / 3323.
 * Returns 0/1/2 (emit mode); header_buf >=512 recommended. */
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

/* AST_REDIRECTING_REASON_* -> Diversion ;reason= string (RFC 5806 §4.4).
 * CALL_FWD_DTE -> "unknown": DTE forwarding has no canonical Diversion reason. */
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

/* Diversion ;reason= string -> enum (reverse of sofia_reason_code_to_str). */
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

/* Emit outbound Diversion (RFC 5806) when the call was forwarded. Returns 0/1 (emit).
 * peer->forceddiversion overrides the diverting number with a trunk-owned DID
 * (privacy off) so a carrier validates against a number it provisions; emission still
 * requires a redirect indication, so a plain non-forwarded call never gets one. */
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

	/* Caller holds pvt->peer->lock across this whole builder, so reading the peer
	 * stringfield here is reload-UAF-safe (same span as fromdomain below). */
	if (pvt->peer && !ast_strlen_zero(pvt->peer->forceddiversion)) {
		forced = pvt->peer->forceddiversion;
	}

	if (forced) {
		if (!have_redirect
				&& pvt->owner->redirecting.reason == AST_REDIRECTING_REASON_UNKNOWN) {
			/* No redirect marker -> direct call; never stamp a Diversion on it. */
			return 0;
		}
		diverting_number = forced;
		diverting_name = NULL;
	} else {
		if (!have_redirect) {
			return 0;
		}
		diverting_name = (pvt->owner->redirecting.from.name.valid
				&& !ast_strlen_zero(pvt->owner->redirecting.from.name.str))
			? pvt->owner->redirecting.from.name.str : NULL;
	}

	/* Forced diversion with no explicit reason defaults to unconditional. */
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

	/* Forced DID: privacy=off (the carrier must see it). Relayed: derive from the
	 * redirecting party's presentation, NOT pvt->callingpres. */
	if (forced) {
		privacy_str = "off";
	} else {
		redir_pres = ast_party_id_presentation(&pvt->owner->redirecting.from);
		privacy_str = ((redir_pres & AST_PRES_RESTRICTION) != AST_PRES_ALLOWED) ? "full" : "off";
	}

	/* Sanitize the (inbound-parsed) diverting party against header injection:
	 * uri-encode the number, quoted-string-sanitize the name. Same as the
	 * From/RPID/PAI builders; a no-op on a forced digit DID. */
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

/* Returns 1 if a Privacy: id token is present (RFC 3323 §4.2). */
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

/* Inbound P-Asserted-Identity parser, trust-gated on peer->trustrpid. Updates
 * pvt->cid_num/cid_name/callingpres (and the channel if owner is bound).
 * anonymous@anonymous.invalid or Privacy: id forces caller-id restriction.
 * Returns 1 on update, 0 otherwise. */
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

	/* Inline parser for ["display"] <sip:user@host>[;params] (RFC 3325 §9.1);
	 * chan_sip's get_name_and_number is not exposed across modules. */
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

/* Inbound Remote-Party-ID parser, trust-gated on peer->trustrpid; falls back to
 * sofia_get_pai when absent. Maps ;privacy= + ;screen= to callingpres. */
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

/* Inbound Diversion parser -> owner->redirecting + dialplan vars
 * __SIPREDIRECTREASON / __SIPRDNISDOMAIN. No trust-gating (structural metadata;
 * operator dialplan decides trust). Returns 1 on update, 0 on no-header. */
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

	uri = strchr(tmp, '<');
	if (!uri) {
		return 0;
	}
	uri++;
	end = strchr(uri, '>');
	if (end) {
		*end = '\0';
	}

	/* Split off ;params before scheme strip + user@domain split. */
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
			/* Strip enclosing quotes if present. */
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

	/* Hold the CHANNEL lock for the mutation: the channel thread reads
	 * redirecting.from.*.str, so freeing/reallocating it unlocked is a UAF.
	 * Callers pass an owner not under pvt->lock, so this cannot invert channel->pvt;
	 * channel locks are recursive (setvar_helper's own lock nests). */
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

	if (!ast_strlen_zero(reason_str)) {
		pbx_builtin_setvar_helper(owner, "__SIPREDIRECTREASON", reason_str);
	}
	if (!ast_strlen_zero(domain)) {
		pbx_builtin_setvar_helper(owner, "__SIPRDNISDOMAIN", domain);
	}
	ast_channel_unlock(owner);

	return 1;
}

/* Centralized inUse/inRinging counter. INC_CALL_LIMIT bumps inUse; INC_CALL_RINGING
 * bumps both; DEC_* decrement (idempotent via pvt->call_inc_done/ring_inc_done).
 * Lock order: pvt->lock then ao2_lock(peer). Emits PeerStatus AMI.
 * Returns 0, or -1 on call rejection (caller emits 480 inbound / 486 outbound). */
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
	case SOFIA_INC_CALL_RINGING: {
		/* SNAPSHOT IDIOM (UAF/TOCTOU fix). The OUTBOUND path (sofia_call -> SOFIA_INC_CALL_RINGING)
		 * runs OFF sofia_thread, so a concurrent reload writer (ast_string_field_set under peer->lock)
		 * can free peer->context / peer->accountcode mid-read = UAF, and the bare peer->inUse limit
		 * test was an unlocked TOCTOU vs the increment below. Fix: (1) snapshot the freeable fields +
		 * src_addr + the int knobs under peer->lock into locals; (2) take the limit DECISION atomically
		 * with the increment under ao2_lock(peer) (the same lock the counters live under). The two
		 * locks are NOT co-held (peer->lock then released, then ao2_lock) — no new lock-order edge. */
		char l_name[80];
		char l_context[AST_MAX_CONTEXT];
		char l_accountcode[256];	/* UNBOUNDED stringfield -> >=256 (SNAPSHOT IDIOM); emit value verbatim, no truncation */
		char l_address[64] = "";
		int l_call_limit;
		int l_busy_level;
		int inUse_snap, inRinging_snap;
		int rejected = 0;

		ast_mutex_lock(&peer->lock);
		ast_copy_string(l_name, peer->name, sizeof(l_name));
		ast_copy_string(l_context, peer->context, sizeof(l_context));
		ast_copy_string(l_accountcode, S_OR(peer->accountcode, ""), sizeof(l_accountcode));
		if (!ast_sockaddr_isnull(&peer->src_addr)) {
			ast_copy_string(l_address, ast_sockaddr_stringify(&peer->src_addr), sizeof(l_address));
		}
		l_call_limit = peer->call_limit;
		l_busy_level = peer->busy_level;
		ast_mutex_unlock(&peer->lock);

		/* Decision + increment under ONE critical section: read inUse and (if allowed) bump it
		 * atomically so a parallel call cannot slip past the limit between the test and the bump. */
		ast_mutex_lock(&pvt->lock);
		ao2_lock(peer);
		if (l_call_limit > 0 && peer->inUse >= l_call_limit) {
			rejected = 1;
		} else {
			if (event == SOFIA_INC_CALL_RINGING && !pvt->ring_inc_done) {
				peer->inRinging++;
				pvt->ring_inc_done = 1;
			}
			if (!pvt->call_inc_done) {
				peer->inUse++;
				pvt->call_inc_done = 1;
			}
		}
		inUse_snap = peer->inUse;
		inRinging_snap = peer->inRinging;
		ao2_unlock(peer);
		ast_mutex_unlock(&pvt->lock);

		if (rejected) {
			ast_log(LOG_NOTICE, "Call %s peer '%s' rejected due to usage limit of %d\n",
				(event == SOFIA_INC_CALL_RINGING) ? "to" : "from",
				l_name, l_call_limit);
			/* Emit peer->accountcode actual value (chan_sip parity) — all from the snapshot. */
			manager_event(EVENT_FLAG_SYSTEM, "PeerStatus",
				"ChannelType: SIP\r\n"
				"Peer: SIP/%s\r\n"
				"PeerStatus: CallLimitExceeded\r\n"
				"Address: %s\r\n"
				"Context: %s\r\n"
				"Accountcode: %s\r\n"
				"ActiveCalls: %d\r\n"
				"RingingCalls: %d\r\n"
				"CallLimit: %d\r\n"
				"Event: CALL_REJECTED\r\n",
				l_name, l_address, l_context, l_accountcode,
				inUse_snap, inRinging_snap, l_call_limit);
			return -1;
		}

		/* Emit peer->accountcode actual value (chan_sip parity).
		 * Gated on call_limit/busy_level: this AMI emit previously only ran for
		 * limited peers (the early-return guarded it); keep it that way now that the
		 * early-return is gone, so non-limit peers don't newly emit it. All from the snapshot. */
		if (l_call_limit || l_busy_level) {
			manager_event(EVENT_FLAG_SYSTEM, "PeerStatus",
				"ChannelType: SIP\r\n"
				"Peer: SIP/%s\r\n"
				"PeerStatus: CallCountUpdated\r\n"
				"Address: %s\r\n"
				"Context: %s\r\n"
				"Accountcode: %s\r\n"
				"ActiveCalls: %d\r\n"
				"RingingCalls: %d\r\n"
				"CallLimit: %d\r\n"
				"Event: %s\r\n",
				l_name, l_address, l_context, l_accountcode,
				inUse_snap, inRinging_snap, l_call_limit,
				event == SOFIA_INC_CALL_RINGING ? "INC_CALL_RINGING" : "INC_CALL_LIMIT");
		}
		break;
	}

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

	/* BLF/presence (chan_sip parity): fire a devstate change so the SIP/<peer> hint
	 * recomputes. All locks released above; snapshot the name under the peer lock. */
	{
		char l_name[80];
		ao2_lock(peer);
		ast_copy_string(l_name, peer->name, sizeof(l_name));
		ao2_unlock(peer);
		ast_devstate_changed(AST_DEVICE_UNKNOWN, AST_DEVSTATE_CACHABLE, "SIP/%s", l_name);
	}
	return 0;
}

/* Normalize an outboundproxy spec (peer overrides [general]) into a canonical
 * "sip:HOST[:PORT];lr" Route URI; buf empty if no proxy applies. Accepts bare host /
 * host:port / full sip:URI. Caller MUST hold peer->lock (reload writer may free the
 * stringfield pool even with a ref held; sofia_do_register is load-time exempt). */
void sofia_format_outboundproxy(struct sofia_peer *peer, char *buf, size_t len)
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

	if (!ast_strlen_zero(peer->outboundproxy)) {
		spec = peer->outboundproxy;
	} else if (!ast_strlen_zero(sofia_cfg.outboundproxy)) {
		spec = sofia_cfg.outboundproxy;
	} else {
		return;
	}

	has_scheme = (!strncasecmp(spec, "sip:", 4) || !strncasecmp(spec, "sips:", 5));
	has_lr = (strstr(spec, ";lr") != NULL);

	if (has_scheme) {
		snprintf(buf, len, "%s%s", spec, has_lr ? "" : ";lr");
	} else {
		snprintf(buf, len, "sip:%s;lr", spec);
	}
}

/* Build + send one RFC 3842 MWI NOTIFY (aggregated inbox counts) to a peer's active
 * subscriber. Runs on sofia_thread. Caller owns a peer ref; takes peer->lock
 * internally (caller must NOT hold it) and releases before nua_notify. */
/* Build the RFC 3842 simple-message-summary body for a peer's mailboxes. Snapshots the mailbox specs +
 * fromdomain/buggymwi under peer->lock, then counts OFF the lock (ast_app_inboxcount2 does unbounded
 * backend I/O — IMAP/ODBC/dir-scan). Returns a new ast_str (NULL on failure); new_out and old_out get
 * the totals for logging. Caller must NOT hold peer->lock. Shared by the solicited + unsolicited NOTIFY. */
static struct ast_str *sofia_build_mwi_body(struct sofia_peer *peer, int *new_out, int *old_out)
{
	struct sofia_mailbox *mb;
	struct ast_str *body;
	int total_new = 0, total_old = 0;
	const char *vmexten;
	char mboxes[32][160];
	char l_fromdomain[256];
	int nmb = 0, i, l_buggymwi;

	if (!peer) {
		return NULL;
	}
	ast_mutex_lock(&peer->lock);
	AST_LIST_TRAVERSE(&peer->mailboxes, mb, list) {
		if (nmb >= (int) ARRAY_LEN(mboxes)) {
			break;
		}
		snprintf(mboxes[nmb], sizeof(mboxes[nmb]), "%s@%s", mb->mailbox, mb->context);
		nmb++;
	}
	/* Snapshot the unbounded stringfield + the flag into locals (the reload writer can free/rewrite
	 * peer->fromdomain under the lock; never deref it after unlock). */
	ast_copy_string(l_fromdomain,
		!ast_strlen_zero(peer->fromdomain) ? peer->fromdomain : S_OR(sofia_cfg.realm, "gabpbx"),
		sizeof(l_fromdomain));
	l_buggymwi = peer->buggymwi;
	ast_mutex_unlock(&peer->lock);

	for (i = 0; i < nmb; i++) {
		int new_msgs = 0, old_msgs = 0, urgent_msgs = 0;
		if (ast_app_inboxcount2(mboxes[i], &urgent_msgs, &new_msgs, &old_msgs) == 0) {
			total_new += new_msgs;
			total_old += old_msgs;
		}
	}

	if (!(body = ast_str_create(256))) {
		ast_log(LOG_WARNING, "Sofia MWI: ast_str_create failed for peer %s\n", peer->name);
		return NULL;
	}
	vmexten = !ast_strlen_zero(sofia_cfg.vmexten) ? sofia_cfg.vmexten : "asterisk";
	/* RFC 3842 body (chan_sip parity). */
	ast_str_append(&body, 0, "Messages-Waiting: %s\r\n", total_new ? "yes" : "no");
	ast_str_append(&body, 0, "Message-Account: sip:%s@%s\r\n", vmexten, l_fromdomain);
	/* buggymwi=yes omits the "(0/0)" suffix some stacks reject (default = RFC 3842). */
	ast_str_append(&body, 0, "Voice-Message: %d/%d%s\r\n", total_new, total_old, l_buggymwi ? "" : " (0/0)");

	if (new_out) {
		*new_out = total_new;
	}
	if (old_out) {
		*old_out = total_old;
	}
	return body;
}

/* SOLICITED MWI re-NOTIFY: emit on the peer's active inbound-SUBSCRIBE dialog handle. No-op without an
 * active subscription. sofia_thread only. */
static void transmit_mwi_notify_for_peer(struct sofia_peer *peer)
{
	struct ast_str *body;
	const char *notifymime;
	int total_new = 0, total_old = 0;
	nua_handle_t *nh;

	if (!peer) {
		return;
	}
	ast_mutex_lock(&peer->lock);
	nh = peer->mwi_subscription_handle;
	ast_mutex_unlock(&peer->lock);
	if (!nh) {
		return;
	}
	if (!(body = sofia_build_mwi_body(peer, &total_new, &total_old))) {
		return;
	}
	notifymime = !ast_strlen_zero(sofia_cfg.notifymime) ? sofia_cfg.notifymime
		: "application/simple-message-summary";
	nua_notify(nh,
		SIPTAG_EVENT_STR("message-summary"),
		SIPTAG_CONTENT_TYPE_STR(notifymime),
		SIPTAG_PAYLOAD_STR(ast_str_buffer(body)),
		TAG_END());
	if (sofia_debug) {
		ast_verbose("Sofia MWI: solicited NOTIFY for peer '%s' (new=%d old=%d)\n",
			peer->name, total_new, total_old);
	}
	ast_free(body);
}

/* UNSOLICITED MWI NOTIFY (RFC 3842, chan_sip subscribemwi=no parity): push message-summary to a
 * registered peer that has NOT subscribed, via a one-shot out-of-dialog handle to its registered
 * contact. Sent with nua_method NOTIFY (NOT nua_notify): this sofia-sip fork compiles out the notifier
 * client methods and the NUTAG_NEWSUB usage path is #if 0, so an out-of-dialog nua_notify is rejected
 * locally with 481; the generic-method path delivers it. Subscription-State: active is set explicitly.
 * The handle carries SOFIA_SIPNOTIFY_HMAGIC so the one-shot reap destroys it on the final nua_r_method
 * response. sofia_thread only. */
static void transmit_unsolicited_mwi_for_peer(struct sofia_peer *peer)
{
	struct ast_str *body;
	const char *notifymime;
	char target[300];
	char defaultuser[256];
	int registered, total_new = 0, total_old = 0;
	nua_handle_t *nh;

	if (!peer) {
		return;
	}
	ast_mutex_lock(&peer->lock);
	registered = peer->registered;
	ast_copy_string(defaultuser,
		!ast_strlen_zero(peer->defaultuser) ? peer->defaultuser : peer->name, sizeof(defaultuser));
	ast_mutex_unlock(&peer->lock);
	if (!registered) {
		return;		/* no registered contact to push to */
	}

	sofia_resolve_peer_target(peer, defaultuser, target, sizeof(target));
	if (ast_strlen_zero(target)) {
		return;
	}
	if (!(body = sofia_build_mwi_body(peer, &total_new, &total_old))) {
		return;
	}
	notifymime = !ast_strlen_zero(sofia_cfg.notifymime) ? sofia_cfg.notifymime
		: "application/simple-message-summary";

	nh = nua_handle(sofia_nua, SOFIA_SIPNOTIFY_HMAGIC, NUTAG_URL(target), TAG_END());
	if (nh) {
		/* nua_method NOTIFY — NOT nua_notify. This sofia-sip fork compiles out the notifier client
		 * methods (nua_notify_client_methods are all NULL) and the NUTAG_NEWSUB usage-creation path is
		 * #if 0, so an out-of-dialog nua_notify is rejected LOCALLY with 481 and never reaches the wire.
		 * The generic-method path sends the NOTIFY on the wire (the same mechanism outbound PUBLISH uses);
		 * the response arrives as nua_r_method, reaped by the SOFIA_SIPNOTIFY_HMAGIC one-shot reap. */
		nua_method(nh,
			NUTAG_METHOD("NOTIFY"),
			SIPTAG_EVENT_STR("message-summary"),
			SIPTAG_SUBSCRIPTION_STATE_STR("active"),
			SIPTAG_CONTENT_TYPE_STR(notifymime),
			SIPTAG_PAYLOAD_STR(ast_str_buffer(body)),
			TAG_END());
		if (sofia_debug) {
			ast_verbose("Sofia MWI: unsolicited NOTIFY for peer '%s' -> %s (new=%d old=%d)\n",
				peer->name, target, total_new, total_old);
		}
	}
	ast_free(body);
}

/* On a successful REGISTER, push the initial unsolicited MWI for a peer that has a mailbox= and
 * subscribemwi=no (chan_sip parity). Called from BOTH register-200 paths (no-auth + authenticated) on
 * sofia_thread, after the 200 OK + side-effects. No-op for solicited-only (subscribemwi=yes) or
 * mailbox-less peers; transmit_unsolicited re-checks registered under peer->lock. */
static void sofia_register_initial_mwi(struct sofia_peer *peer)
{
	int want_mwi;

	if (!peer) {
		return;
	}
	ast_mutex_lock(&peer->lock);
	/* Skip the unsolicited push when the phone has an ACTIVE inbound MWI subscription — it already gets
	 * solicited NOTIFYs on that dialog; pushing here too would double-notify a subscribed phone on every
	 * re-REGISTER. (The mwi_event_cb change path already gates on this.) */
	want_mwi = (peer->subscribemwi == 0 && !AST_LIST_EMPTY(&peer->mailboxes)
		&& !peer->mwi_subscription_handle);
	ast_mutex_unlock(&peer->lock);
	if (want_mwi) {
		transmit_unsolicited_mwi_for_peer(peer);
	}
}

/* Reap a SUBSCRIBE server handle on a NON-ACCEPTED path (final reject OR 401
 * challenge). sofia-sip never auto-reaps an APPL_METHOD SUBSCRIBE handle; a reject
 * establishes no dialog so the handle is orphaned (the authed re-SUBSCRIBE arrives
 * fresh). Accept paths (nua_notifier) own the handle and must NOT call this. */
static void sofia_subscribe_reject_reap(nua_handle_t *nh)
{
	/* Reap ONLY a fresh, UNBOUND handle. A BOUND handle (hmagic != NULL) is owned by
	 * its sofia_pvt / presence / MWI sub — destroying it here would UAF that object. */
	if (!nh || nua_handle_magic(nh) != NULL) {
		return;
	}
	nua_handle_destroy(nh);
}

/* MWI SUBSCRIBE handler (Event:message-summary). Identifies the mailbox-owner peer
 * via the To user-part, enforces a 1-subscription-per-peer cap, binds nh as a
 * nua_notifier. Runs on sofia_thread; holds peer->lock only while mutating peer
 * fields, never across nua_* ops. */
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
			/* RESIDUAL-RACE FENCE: nh is UNBOUND (no pvt). Reaping it NOW (the old code)
			 * dispatches nua_handle_destroy -> nta_incoming_destroy auto-500, racing ahead of
			 * the deferred 401 timer. Defer the reap: pass reap_handle_on_fire=1 so the timer
			 * emits the 401 FIRST, then reaps. The immediate reap below is taken ONLY on the
			 * 404 branch. */
			sofia_send_auth_challenge(nua, nh, sip, realm, "SUBSCRIBE", "UnknownPeer", NULL, 1);
		} else {
			ast_log(LOG_NOTICE, "Sofia MWI: SUBSCRIBE for unknown peer '%s' — 404\n", to_user);
			nua_respond(nh, SIP_404_NOT_FOUND, NUTAG_WITH_THIS(nua), TAG_END());
			sofia_subscribe_reject_reap(nh);	/* immediate reap — 404 branch (no deferred 401) */
		}
		return;
	}

	/* Per-peer source-IP ACL, BEFORE the allowsubscribe/digest gates (chan_sip parity, chan_sip.c
	 * :17020 applies peer->ha unconditionally before auth). REGISTER (peer->ha @8084) and INVITE
	 * (caller_peer->ha @5549) apply the same gate; without it a credential-less peer is watchable by
	 * spoofing the To/From user-part from a denied IP. RFC 6665. */
	if (peer->ha) {
		struct ast_sockaddr src;
		sofia_get_source_addr(sip, &src);
		if (ast_apply_ha(peer->ha, &src) != AST_SENSE_ALLOW) {
			ast_log(LOG_NOTICE, "Sofia MWI: SUBSCRIBE for peer '%s' rejected by peer ACL\n",
				peer->name);
			nua_respond(nh, SIP_403_FORBIDDEN, NUTAG_WITH_THIS(nua), TAG_END());
			ao2_ref(peer, -1);
			sofia_subscribe_reject_reap(nh);	/* reap the challenge handle */
			return;
		}
	}

	/* allowsubscribe=no gate (chan_sip parity). The "403 Forbidden (policy)" string is
	 * verbatim — operator scripts pattern-match the exact text. */
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

	/* Digest-auth a credentialed peer's MWI SUBSCRIBE (else anyone could subscribe its
	 * mailbox). Credential-less peers stay open; the verifier emits the 401/4xx itself. */
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

	/* Only terminate+destroy a DIFFERENT prior handle: on an in-dialog refresh
	 * old_nh == nh and destroying it would tear down the live subscription (self-UAF). */
	if (old_nh && old_nh != nh) {
		nua_notify(old_nh,
			SIPTAG_EVENT_STR("message-summary"),
			SIPTAG_SUBSCRIPTION_STATE_STR("terminated;reason=deactivated"),
			TAG_END());
		/* Detach hmagic before destroy: a late event for old_nh would otherwise
		 * reach sofia_event_callback with magic = peer (still alive) and act on a
		 * stale subscription. Mirrors the peer-destructor discipline. */
		nua_handle_bind(old_nh, NULL);
		nua_handle_destroy(old_nh);
	}

	/* Refresh on the SAME handle: sofia-sip already auto-answered the re-SUBSCRIBE, so
	 * do NOT re-issue nua_notifier — just push a fresh MWI NOTIFY body. */
	if (old_nh == nh) {
		transmit_mwi_notify_for_peer(peer);
		if (sofia_debug) {
			ast_verbose("Sofia MWI: SUBSCRIBE refresh for peer '%s'\n", peer->name);
		}
		ao2_ref(peer, -1);
		return;
	}

	/* Bind nh as nua_notifier (opens the dialog + auto-emits Subscription-State). */
	{
		char expires_buf[16];
		int expiry = sofia_cfg.mwi_expiry > 0 ? sofia_cfg.mwi_expiry : 3600;
		snprintf(expires_buf, sizeof(expires_buf), "%d", expiry);
		nua_notifier(nh,
			SIPTAG_EVENT_STR("message-summary"),
			SIPTAG_EXPIRES_STR(expires_buf),
			TAG_END());
	}

	/* RFC 6665 §4.4.1 initial NOTIFY (transmit takes peer->lock internally). */
	transmit_mwi_notify_for_peer(peer);

	if (sofia_debug) {
		ast_verbose("Sofia MWI: SUBSCRIBE accepted for peer '%s'\n", peer->name);
	}

	ao2_ref(peer, -1);
	/* nh is borrowed via peer->mwi_subscription_handle; cleaned up in sofia_peer_destructor. */
}

/* Presence/BLF SUBSCRIBE->NOTIFY engine is in channels/sofia/sofia_presence.c. */


/* Outbound PUBLISH (RFC 3903) is implemented in channels/sofia/sofia_publish.c. */

/* tech.devicestate for SIP/<peer>. The core uses a concrete result and skips its
 * generic channel scan (devicestate.c: "if (res != UNKNOWN) return res"), so return
 * concrete only where we add info the scan can't derive (offline/on-hold/BUSY) and
 * UNKNOWN otherwise. Cache-only peer lookup — NEVER realtime (would defeat
 * rtautoclear; chan_sip.c:27787 parity). */
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
		return AST_DEVICE_UNKNOWN;
	}

	ast_mutex_lock(&peer->lock);
	/* Reachable = known address: peer->src_addr holds it for BOTH the registered
	 * source AND the static host=<ip>/dnsmgr address; peer->addr is never written so
	 * must NOT be consulted (pinned static peers to UNAVAILABLE). defaddr = defaultip=
	 * fallback. None set -> offline. */
	if (!peer->registered
			&& ast_sockaddr_isnull(&peer->src_addr)
			&& ast_sockaddr_isnull(&peer->defaddr)) {
		res = AST_DEVICE_UNAVAILABLE;
	} else if (peer->onHold) {
		res = AST_DEVICE_ONHOLD;
	} else if (peer->inRinging) {
		/* chan_sip parity: ringing leg -> RINGING (RINGINUSE if some legs already up). */
		res = (peer->inRinging == peer->inUse) ? AST_DEVICE_RINGING : AST_DEVICE_RINGINUSE;
	} else if (peer->call_limit && peer->inUse >= peer->call_limit) {
		res = AST_DEVICE_BUSY;
	} else if (peer->call_limit && peer->busy_level && peer->inUse >= peer->busy_level) {
		res = AST_DEVICE_BUSY;
	} else if (peer->inUse) {
		res = AST_DEVICE_INUSE;
	} else if (peer->qualify && peer->peer_status == PEER_UNREACHABLE) {
		/* No maxms in chan_sofia; a registered peer that fails qualify is offline. */
		res = AST_DEVICE_UNAVAILABLE;
	} else {
		/* Registered+reachable, no call: concrete NOT_INUSE (BLF green). UNKNOWN left
		 * the BLF dark since the hint only recomputes on a devstate change event. */
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
			/* RESIDUAL-RACE FENCE: nh is UNBOUND. Defer the reap (reap_handle_on_fire=1) so the
			 * timer emits the 401 FIRST, then reaps — else an immediate reap dispatches
			 * nta_incoming_destroy's auto-500 ahead of our deferred 401. The immediate reap below
			 * is taken ONLY on the 404 branch. */
			sofia_send_auth_challenge(nua, nh, sip, realm, "SUBSCRIBE", "UnknownPeer", NULL, 1);
		} else {
			ast_log(LOG_NOTICE, "Sofia presence: SUBSCRIBE from unknown peer '%s' — 404\n", from_user);
			nua_respond(nh, SIP_404_NOT_FOUND, NUTAG_WITH_THIS(nua), TAG_END());
			sofia_subscribe_reject_reap(nh);	/* immediate reap — 404 branch (no deferred 401) */
		}
		return;
	}

	/* Per-peer source-IP ACL, BEFORE the allowsubscribe/digest gates (chan_sip parity, chan_sip.c
	 * :17020 applies peer->ha unconditionally before auth). REGISTER (peer->ha @8084) and INVITE
	 * (caller_peer->ha @5549) apply the same gate; without it a credential-less peer is watchable by
	 * spoofing the From user-part from a denied IP. RFC 6665. */
	if (peer->ha) {
		struct ast_sockaddr ha_src;
		sofia_get_source_addr(sip, &ha_src);
		if (ast_apply_ha(peer->ha, &ha_src) != AST_SENSE_ALLOW) {
			ast_log(LOG_NOTICE, "Sofia presence: SUBSCRIBE from peer '%s' rejected by peer ACL\n",
				peer->name);
			nua_respond(nh, SIP_403_FORBIDDEN, NUTAG_WITH_THIS(nua), TAG_END());
			ao2_ref(peer, -1);
			sofia_subscribe_reject_reap(nh);	/* reap the challenge handle */
			return;
		}
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

	/* Digest-authenticate the SUBSCRIBE for a credentialed peer (MWI-path rationale):
	 * else anyone could watch any extension's state. Verifier emits the 401/4xx. */
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
	/* NAT proxy target (built under peer->lock): for nat watchers the NOTIFYs route
	 * to the registered public source via NUTAG_PROXY instead of the unreachable
	 * private Contact (else every NOTIFY 408s). Empty for non-NAT peers. */
	sofia_build_nat_proxy_url_from_peer(peer, l_proxy, sizeof(l_proxy));
	ast_mutex_unlock(&peer->lock);
	ao2_ref(peer, -1);
	peer = NULL;

	/* The watched extension must have a dialplan hint, else nothing to watch. A watcher subscribing to an
	 * exten with no hint is a NORMAL/expected condition (not an error), so this is debug-only — at NOTICE it
	 * floods the log on every such SUBSCRIBE. Visible with `sip set debug on`. */
	if (!ast_get_hint(hint, sizeof(hint), NULL, 0, NULL, l_context, to_user)) {
		if (sofia_debug) {
			ast_verbose("Sofia presence: no hint for %s@%s (watcher SIP/%s) — 404\n",
				to_user, l_context, l_peername);
		}
		nua_respond(nh, SIP_404_NOT_FOUND, NUTAG_WITH_THIS(nua), TAG_END());
		sofia_subscribe_reject_reap(nh);	/* reap the challenge handle */
		return;
	}

	/* Logical key: at most ONE sub per (watcher, watched-exten, context). Correlates a
	 * re-SUBSCRIBE on a fresh dialog / Expires:0 unsubscribe here — NOT by nh, which
	 * sofia-sip does not reliably reuse. */
	ast_copy_string(l_exten, to_user, sizeof(l_exten));
	snprintf(subkey, sizeof(subkey), "%s|%s|%s", l_peername, l_exten, l_context);
	/* Clamp ex_delta before the int cast: > INT_MAX wraps negative and would read as
	 * an unsubscribe (expires <= 0). */
	if (!sip || !sip->sip_expires) {
		expires = SOFIA_PRESENCE_DEFAULT_EXPIRY;
	} else if (sip->sip_expires->ex_delta > (unsigned long) SOFIA_PRESENCE_DEFAULT_EXPIRY) {
		expires = SOFIA_PRESENCE_DEFAULT_EXPIRY;
	} else {
		expires = (int) sip->sip_expires->ex_delta;
	}

	/* Min-Expires floor (RFC 6665 §4.2.1: the notifier MAY return 423 Interval Too Brief).
	 * Mirrors the REGISTER path (sofia_check_register_expiry) so an authenticated watcher
	 * requesting Expires:1 can't force ~1 Hz re-auth + re-NOTIFY + AMI churn. Reuse the
	 * operator's configured registration floor (sofia_cfg.min_expiry) for a single, consistent
	 * knob. expires <= 0 is the unsubscribe path below — never floored. */
	if (expires > 0 && expires < sofia_cfg.min_expiry) {
		char min_str[16];
		snprintf(min_str, sizeof(min_str), "%d", sofia_cfg.min_expiry);
		nua_respond(nh, 423, "Interval Too Brief",
			SIPTAG_MIN_EXPIRES_STR(min_str),
			NUTAG_WITH_THIS(nua),
			TAG_END());
		sofia_subscribe_reject_reap(nh);	/* reap the challenge handle (MWI discipline) */
		if (sofia_debug) {
			ast_verbose("Sofia presence: SUBSCRIBE Expires:%d below min %d — 423 Interval Too Brief "
				"(watcher SIP/%s -> %s@%s)\n",
				expires, sofia_cfg.min_expiry, l_peername, to_user, l_context);
		}
		return;
	}

	/* Replace/terminate any existing subscription for this key. */
	{
		struct sofia_presence_sub keyobj;
		struct sofia_presence_sub *old;
		memset(&keyobj, 0, sizeof(keyobj));
		ast_copy_string(keyobj.subkey, subkey, sizeof(keyobj.subkey));
		old = ao2_find(presence_subs, &keyobj, OBJ_POINTER);

		if (expires <= 0) {
			/* Unsubscribe (delivered on a fresh handle, not the notifier): accept +
			 * send terminating NOTIFY (RFC 6665 — 200 + final NOTIFY). nua_respond
			 * alone makes the stack emit a spurious 500. */
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
			/* Reap the fresh APPL_METHOD handle (stack won't auto-destroy it), unless
			 * teardown already freed it (old->nh == nh). MWI discipline. */
			if (!nh_is_old) {
				sofia_subscribe_reject_reap(nh);
			}
			if (sofia_debug) {
				ast_verbose("Sofia presence: UNSUBSCRIBE — watcher SIP/%s -> %s@%s\n",
					l_peername, to_user, l_context);
			}
			return;
		}

		if (old) {
			if (old->nh == nh) {
				/* In-dialog refresh on the same handle. SUBSCRIBE is APPL_METHOD so
				 * we MUST nua_respond(202) (else the watcher retransmits then drops
				 * the sub). Extend lifetime, re-emit state. */
				char eb[16];
				int st;
				old->expires = expires;
				old->expires_at = time(NULL) + expires;
				ast_copy_string(old->nat_proxy, l_proxy, sizeof(old->nat_proxy));	/* source may have moved */
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
	sub->laststate = -10;	/* "unknown" -> first NOTIFY always reflects a transition */
	sub->version = 0;
	sub->expires = expires;
	sub->expires_at = time(NULL) + expires;
	sub->terminated = 0;
	ast_copy_string(sub->subkey, subkey, sizeof(sub->subkey));
	ast_copy_string(sub->exten, l_exten, sizeof(sub->exten));
	ast_copy_string(sub->context, l_context, sizeof(sub->context));
	ast_copy_string(sub->peername, l_peername, sizeof(sub->peername));
	ast_copy_string(sub->nat_proxy, l_proxy, sizeof(sub->nat_proxy));
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

	/* Link into the registry (container holds the ref). On OOM the sub is untracked
	 * (refresh/unsubscribe/expiry could never find it) — reject 500 and reap the
	 * handle here rather than leak it behind a hint watcher. */
	if (!ao2_link(presence_subs, sub)) {
		ast_log(LOG_WARNING, "Sofia presence: ao2_link failed for %s@%s — rejecting 500\n",
			sub->exten, sub->context);
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, NUTAG_WITH_THIS(nua), TAG_END());
		sofia_subscribe_reject_reap(nh);
		ao2_ref(sub, -1);	/* creation ref */
		return;
	}

	/* Register the hint watcher with the core (the +1 ref is owned by the registration,
	 * dropped by sofia_presence_sub_destroy_cb). This makes `core show hints` count it. */
	ao2_ref(sub, +1);
	sub->stateid = ast_extension_state_add_destroy(sub->context, sub->exten,
		sofia_presence_state_cb, sofia_presence_sub_destroy_cb, sub);
	if (sub->stateid < 0) {
		ast_log(LOG_WARNING, "Sofia presence: ast_extension_state_add_destroy failed for %s@%s\n",
			sub->exten, sub->context);
		ao2_ref(sub, -1);	/* undo the registration ref we pre-took */
		ao2_unlink(presence_subs, sub);
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, NUTAG_WITH_THIS(nua), TAG_END());
		/* Reap the handle here too — the destructor is a deliberate no-op (handles
		 * destroyed explicitly on sofia_thread), so otherwise it leaks. */
		sofia_subscribe_reject_reap(nh);
		ao2_ref(sub, -1);	/* creation ref */
		return;
	}

	/* Accept with 2xx (server idiom: nua_respond + NUTAG_WITH_THIS binds the response
	 * to THIS pending transaction — nua_notifier does not answer it). Then push the
	 * initial NOTIFY (RFC 6665 §4.4.1); NUTAG_SUBSTATE makes sofia-sip own
	 * Subscription-State + expiry/refresh. */
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


	/* allowsubscribe global ban gate (chan_sip parity): reject upfront before any
	 * peer-lookup. Keep the verbatim "403 Forbidden (policy)" string (operator scripts
	 * pattern-match it). */
	if (!sofia_cfg.allowsubscribe) {
		nua_respond(nh, 403, "Forbidden (policy)",
			NUTAG_WITH_THIS(nua), TAG_END());
		sofia_emit_subscribe_rejected(sip, NULL,
			S_OR(event, "(missing)"), "AllowSubscribeClosed");
		sofia_subscribe_reject_reap(nh);
		return;
	}

	/* Route by Event package: message-summary -> MWI; presence/dialog -> presence
	 * handler; anything else -> 489 Bad Event. */
	if (event && !strcasecmp(event, "message-summary")) {
		sofia_process_mwi_subscribe(nua, nh, op, sip, tags);
		return;
	}

	if (event && (!strcasecmp(event, "dialog") || !strcasecmp(event, "dialog-info")
			|| !strcasecmp(event, "presence"))) {
		sofia_process_presence_subscribe(nua, nh, op, sip, tags);
		return;
	}

	/* Unsupported Event -> 489 Bad Event + Allow-Events (RFC 6665 §4.3), not a phantom
	 * 202 for a sub we never serve. Then reap the handle (sofia-sip never auto-reaps it). */
	ast_log(LOG_NOTICE, "Sofia: SUBSCRIBE Event=%s unsupported — 489 Bad Event\n",
		S_OR(event, "(missing)"));
	sofia_emit_subscribe_rejected(sip, NULL, S_OR(event, "(missing)"), "BadEvent");
	nua_respond(nh, SIP_489_BAD_EVENT,
		NUTAG_WITH_THIS(nua),
		SIPTAG_ALLOW_EVENTS_STR("presence, dialog, dialog-info, message-summary"),
		TAG_END());
	sofia_subscribe_reject_reap(nh);
}

/* Forward-decl the pvt validator (defined below near sofia_event_callback) so the NOTIFY
 * refer hook can re-validate/pin pvt by handle magic. */
static struct sofia_pvt *sofia_pvt_ref_if_linked(nua_hmagic_t *hmagic);

static void sofia_process_notify(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	if (sofia_debug)
		ast_verbose("Sofia: Received NOTIFY\n");

	/* Outbound MWI SUBSCRIBE (a watcher): a message-summary NOTIFY on one of OUR SUBSCRIBE
	 * dialogs. Checked FIRST (before the transfer hook and presence/MWI dispatch). The check
	 * is pvt-free — it only reads nua_handle_magic — and 200-OKs internally when it consumes. */
	if (sofia_subscribe_on_notify(nh, nua, sip)) {
		return;
	}
	/* Generic outbound SUBSCRIBE (RFC 6665) watcher: a NOTIFY on one of OUR generic SUBSCRIBE dialogs
	 * (distinct sentinel from the MWI watcher). Surfaces it as the AMI event SofiaEventNotify;
	 * 200-OKs internally when it consumes. */
	if (sofia_eventsub_on_notify(nh, nua, sip)) {
		return;
	}

	/* refer-event NOTIFY (outbound transfer progress). The event callback does NOT pin
	 * pvt for nua_i_notify (op is the raw hmagic), so re-validate/pin by the handle magic.
	 * If sofia_transfer_on_notify consumes it, still 200-OK and return — do not fall
	 * through to presence/MWI handling. */
	{
		struct sofia_pvt *rp = sofia_pvt_ref_if_linked(nh ? nua_handle_magic(nh) : NULL);
		int consumed = 0;
		if (rp) {
			consumed = sofia_transfer_on_notify(rp, sip);
			ao2_ref(rp, -1);
		}
		if (consumed) {
			nua_respond(nh, SIP_200_OK, NUTAG_WITH_THIS(nua), TAG_END());
			return;
		}
	}

	nua_respond(nh, SIP_200_OK, NUTAG_WITH_THIS(nua), TAG_END());
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
struct ast_channel *sofia_find_bridged_channel(struct sofia_pvt *op)
{
	struct ast_channel *bridged = NULL;
	struct ast_channel *self;
	/* BRIDGEPEER is a channel name (<= AST_CHANNEL_NAME); linkedid is a uniqueid (name +
	 * suffix). Copy both UNDER the self lock into locals (mirrors the twin
	 * sofia_dc_pair_bridged ~:10695-10741): their backing store (channel var storage /
	 * the linkedid string field) is only stable while self is locked, and Methods 2/3 run
	 * AFTER we unlock self — a post-unlock read of self->linkedid / BRIDGEPEER would race
	 * a concurrent masquerade/rename freeing it. */
	char bridgepeer_copy[AST_CHANNEL_NAME];
	char linkedid_copy[AST_CHANNEL_NAME + 64];

	if (!op) {
		return NULL;
	}

	/* Snapshot+ref op->owner ONCE under op->lock; use the pinned local for all three
	 * methods. A lock-free re-read at each method would race sofia_hangup (NULLs
	 * pvt->owner under op->lock then frees the channel) — UAF off sofia_thread. */
	ast_mutex_lock(&op->lock);
	self = op->owner;
	if (self) {
		ast_channel_ref(self);
	}
	ast_mutex_unlock(&op->lock);
	if (!self) {
		return NULL;
	}

	/* WITH self LOCKED do ONLY the lock-internal work — Method 1 (the ast_bridged_channel
	 * contract) and copying BRIDGEPEER + linkedid into locals for Methods 2/3.
	 *
	 * Method 1: _bridge pointer (borrowed → take a ref).
	 * ast_bridged_channel() contract (channel.h:2318-2327): off the owning thread
	 * (this runs on sofia_thread via sofia_process_refer, and on the rtp_glue path)
	 * 'self' MUST be locked BEFORE the call and stay locked WHILE the borrowed result
	 * is used — channel.c reads self->_bridge then derefs bridged->tech, and a
	 * concurrent masquerade/hangup can repoint/free self->_bridge between the read and
	 * our use (torn-pointer/UAF on a blind/attended REFER). So lock self, +1-ref the
	 * borrowed _bridge under the lock (the ref then keeps it alive independently),
	 * then unlock — mirroring the twin sofia_dc_pair_bridged Method 1. Channel locks
	 * are recursive, so a caller already holding self's lock (sofia_get_rtp_peer) is
	 * safe; self is the top of the lock order (no pvt/peer lock is held here). */
	bridgepeer_copy[0] = '\0';
	linkedid_copy[0] = '\0';
	ast_channel_lock(self);
	bridged = ast_bridged_channel(self);
	if (bridged) {
		ast_channel_ref(bridged);
	} else {
		/* Method 1 missed: COPY the inputs Methods 2/3 need so they can run OFF the self
		 * lock (Method 2 takes the channels CONTAINER lock — channel.h:1319-1322 mandates
		 * container-before-channel, so it must NOT run under a channel lock). */
		const char *bridgepeer_name = pbx_builtin_getvar_helper(self, "BRIDGEPEER");
		if (!ast_strlen_zero(bridgepeer_name)) {
			ast_copy_string(bridgepeer_copy, bridgepeer_name, sizeof(bridgepeer_copy));
		}
		if (self->linkedid) {
			ast_copy_string(linkedid_copy, self->linkedid, sizeof(linkedid_copy));
		}
	}
	ast_channel_unlock(self);
	if (bridged) {
		if (sofia_debug) {
			ast_verbose("Sofia: bridged-finder method 1 (_bridge): %s\n", bridged->name);
		}
		ast_channel_unref(self);
		return bridged;
	}

	/* Method 2: BRIDGEPEER channel-var (ast_channel_get_by_name_prefix already +1's
	 * it — KEEP that ref and hand it to the caller). Run OFF the self lock (it takes the
	 * channels container lock) against the COPY taken above. */
	if (!ast_strlen_zero(bridgepeer_copy)) {
		bridged = ast_channel_get_by_name_prefix(bridgepeer_copy, strlen(bridgepeer_copy));
		if (bridged) {
			if (sofia_debug) {
				ast_verbose("Sofia: bridged-finder method 2 (BRIDGEPEER=%s): %s\n",
					bridgepeer_copy, bridged->name);
			}
			ast_channel_unref(self);
			return bridged;	/* already +1 */
		}
	}

	/* Method 3: dialogs linkedid walk (sibling Sofia leg). Self is unlocked; compare
	 * against the COPIED linkedid. Read+ref each sibling's owner under its pvt->lock
	 * (its sofia_hangup nulls p->owner then frees it). */
	if (!ast_strlen_zero(linkedid_copy)) {
		struct ao2_iterator it = ao2_iterator_init(dialogs, 0);
		struct sofia_pvt *p;
		while ((p = ao2_iterator_next(&it))) {
			if (p != op) {
				struct ast_channel *po;
				ast_mutex_lock(&p->lock);
				po = p->owner;
				if (po && po->linkedid && !strcmp(po->linkedid, linkedid_copy)) {
					bridged = ast_channel_ref(po);
				}
				ast_mutex_unlock(&p->lock);
			}
			ao2_ref(p, -1);
			if (bridged) {
				if (sofia_debug) {
					ast_verbose("Sofia: bridged-finder method 3 (linkedid=%s): %s\n",
						linkedid_copy, bridged->name);
				}
				break;
			}
		}
		ao2_iterator_destroy(&it);
	}

	ast_channel_unref(self);
	return bridged;
}

/* Locate the INBOUND caller Sofia channel that shares this answered leg's linkedid.
 *
 * Unlike sofia_find_bridged_channel() Method 3 (returns the FIRST owned linkedid sibling — could be
 * another OUTBOUND B-leg in a multi-sibling Dial), this CONTINUES the dialogs walk until an INBOUND
 * (!p->outgoing) Sofia-owned sibling with the same linkedid — the A-leg caller. Returns a +1-reffed
 * channel (caller unrefs) or NULL. Used by the SIP-video<->WebRTC video-mask fix. */
static struct ast_channel *sofia_find_inbound_sibling_by_linkedid(struct sofia_pvt *answered)
{
	struct ast_channel *self;
	char linkedid_copy[AST_CHANNEL_NAME + 64];
	struct ast_channel *found = NULL;
	struct ao2_iterator it;
	struct sofia_pvt *p;

	if (!answered) {
		return NULL;
	}
	/* Snapshot+ref the answered leg's owner under its pvt lock (sofia_hangup NULLs owner then frees it),
	 * then copy the linkedid under the channel lock — mirrors sofia_find_bridged_channel's discipline. */
	ast_mutex_lock(&answered->lock);
	self = answered->owner;
	if (self) {
		ast_channel_ref(self);
	}
	ast_mutex_unlock(&answered->lock);
	if (!self) {
		return NULL;
	}
	linkedid_copy[0] = '\0';
	ast_channel_lock(self);
	if (self->linkedid) {
		ast_copy_string(linkedid_copy, self->linkedid, sizeof(linkedid_copy));
	}
	ast_channel_unlock(self);
	ast_channel_unref(self);
	if (ast_strlen_zero(linkedid_copy)) {
		return NULL;
	}

	it = ao2_iterator_init(dialogs, 0);
	while ((p = ao2_iterator_next(&it))) {
		if (p != answered) {
			struct ast_channel *po;
			ast_mutex_lock(&p->lock);
			po = p->owner;
			if (!p->outgoing && po && po->tech == &sofia_tech
					&& po->linkedid && !strcmp(po->linkedid, linkedid_copy)) {
				found = ast_channel_ref(po);
			}
			ast_mutex_unlock(&p->lock);
		}
		ao2_ref(p, -1);
		if (found) {
			break;
		}
	}
	ao2_iterator_destroy(&it);
	return found;
}

/* MicroSIP(SIP-video)<->WebRTC video fix (SDP-only, no channel-state mutation). chan_sofia relays video
 * WITHOUT transcoding, so the inbound caller leg must answer ONLY the video codec(s) the answered far leg
 * accepted. Instead of narrowing capability/nativeformats (core/glue-watched -> mid-call re-INVITE -> the
 * hold-500 storm -> call drop), we record the accepted set in the caller pvt's private video_answer_mask;
 * the SDP emitters apply it as an effective video filter. Called on the answered outbound/fork-winner pvt,
 * right before the caller's ANSWER is queued, when NO channel/pvt lock is held. Lock order: answered->lock
 * (snapshot only, released) then caller channel -> caller pvt (canonical). No peer lock. */
static void sofia_set_caller_video_mask_from_answered(struct sofia_pvt *answered)
{
	format_t answered_video;
	int answered_h264_valid;
	int answered_h264_pmode;
	char answered_h264_fmtp[160];
	struct ast_channel *caller_chan;
	struct sofia_pvt *caller_pvt;

	if (!answered) {
		return;
	}
	ast_mutex_lock(&answered->lock);
	answered_video = answered->capability & AST_FORMAT_VIDEO_MASK;
	answered_h264_valid = answered->h264_fmtp_valid;
	answered_h264_pmode = answered->h264_pmode;
	ast_copy_string(answered_h264_fmtp, answered->h264_fmtp, sizeof(answered_h264_fmtp));
	ast_mutex_unlock(&answered->lock);

	caller_chan = sofia_find_inbound_sibling_by_linkedid(answered);
	if (!caller_chan) {
		return;
	}
	ast_channel_lock(caller_chan);
	caller_pvt = caller_chan->tech_pvt;
	if (caller_pvt && caller_chan->tech == &sofia_tech) {
		ast_mutex_lock(&caller_pvt->lock);
		if (caller_pvt->owner == caller_chan && !caller_pvt->outgoing
				&& (caller_pvt->capability & AST_FORMAT_VIDEO_MASK)) {
			format_t common_video = (caller_pvt->capability & AST_FORMAT_VIDEO_MASK) & answered_video;
			if (common_video) {
				/* Constrain the caller's answer video to the shared set (SDP-only). */
				caller_pvt->video_answer_mask = common_video;
				/* H264 fmtp relay: if H264 is the shared codec, the caller 200 OK must advertise the
				 * SAME H264 config the far leg accepted (RFC 6184 §8.2.2) — copy it cross-leg. Only when
				 * the far leg actually carried an a=fmtp (non-empty): a far leg that sent H264 with NO
				 * fmtp (e.g. a legacy softswitch) must NOT clobber the caller's own parsed config. */
				if ((common_video & AST_FORMAT_H264) && answered_h264_valid
						&& !ast_strlen_zero(answered_h264_fmtp)) {
					ast_copy_string(caller_pvt->h264_fmtp, answered_h264_fmtp, sizeof(caller_pvt->h264_fmtp));
					caller_pvt->h264_pmode = answered_h264_pmode;
					caller_pvt->h264_fmtp_valid = 1;
				}
				ast_verbose("Sofia: caller '%s' video answer masked to far-leg accepted (0x%llx)\n",
					caller_chan->name, (unsigned long long)common_video);
			} else {
				/* No shared video codec (e.g. the callee picked H263-1998 vs a WebRTC H264/VP8 caller).
				 * Leave the mask unset: emitting an EMPTY m=video is malformed and the peer BYEs the
				 * call. Video simply mismatches (no image) but the CALL SURVIVES. The real remedy is
				 * offering the callee only the caller's codecs (outbound video narrowing). */
				ast_verbose("Sofia: caller '%s' and far leg share NO video codec; mask left unset (call preserved)\n",
					caller_chan->name);
			}
		}
		ast_mutex_unlock(&caller_pvt->lock);
	}
	ast_channel_unlock(caller_chan);
	ast_channel_unref(caller_chan);
}

/* ===================================================================================
 * DataChannel far-leg pairing — sofia_dc_pair_bridged
 * ===================================================================================
 *
 * The load-bearing cross-leg primitive for the WebRTC DataChannel relay. It runs on the
 * shared "sofia-datachannel" worker lane — OUTSIDE the owning channel thread — so the
 * ast_bridged_channel() locking contract (channel.h:2318-2327) applies: the channel passed
 * to ast_bridged_channel() MUST be locked before the call AND while its result is used.
 *
 * This is a self-contained, contract-correct rewrite of what sofia_dc_get_bridged_dc()
 * used to do via sofia_find_bridged_channel() + raw reads. The whole channel-walk + far-pvt
 * resolution lives HERE so sofia_pvt internals, sofia_tech, and the canonical lock order
 * (channel -> pvt -> peer) are all in scope.
 *
 * FINAL LOCK / REF SEQUENCE (the NO-ABBA, NO-INVERSION proof):
 *   1. self_pvt->lock          : snapshot+ref self_pvt->owner (self_chan), then UNLOCK pvt.
 *                                 (sofia_hangup NULLs pvt->owner under pvt->lock then frees the
 *                                 channel — the ref+revalidate window is what keeps self_chan alive.)
 *   2. ast_channel_lock(self_chan) : WITH self LOCKED, do ONLY two lock-internal things: (a) Method 1
 *                                 — ast_bridged_channel(self_chan), the live _bridge pointer, +1-ref
 *                                 the result if any (channel-container-free, the contract requires
 *                                 self locked); and (b) COPY the BRIDGEPEER channel var and
 *                                 self_chan->linkedid into local fixed buffers. Then UNLOCK self.
 *                                 We may BLOCK on self's OWN lock — no ABBA: we hold nothing else
 *                                 here (the worker lane runs off the instance lock) and drop self's
 *                                 lock before touching any far channel or the channels container.
 *   2b. (NO channel lock held)  : Method 2 + Method 3 run OFF the self lock. Method 2 =
 *                                 ast_channel_get_by_name_prefix(copied BRIDGEPEER) — this takes the
 *                                 global `channels` CONTAINER lock via ast_channel_get_full/ao2_find
 *                                 (main/channel.c). channel.h:1319-1322 mandates container-BEFORE-
 *                                 channel (inverse paths: ast_change_name @ main/channel.c:6234,
 *                                 masquerade @ main/channel.c:6610 lock the container THEN a channel),
 *                                 so it MUST NOT run with self_chan (a channel) locked — that would be
 *                                 a channel->container ABBA. Method 3 = the dialogs linkedid walk over
 *                                 the copied linkedid, also with no self lock held.
 *   3. ast_channel_trylock(far_chan) : NEVER block on the FAR channel (the ABBA defense) — on
 *                                 contention drop. Read far->tech / far->tech_pvt only under this.
 *                                 Confirm far->tech == &sofia_tech and far != self (pointer compare).
 *   4. far_pvt->lock           : take it (channel -> pvt order) before reading + ao2_ref'ing
 *                                 far_pvt->dc; then RELEASE far_pvt->lock, far_chan's lock, and the
 *                                 far_chan ref. Return the +1 dc with NO lock held — the caller
 *                                 usrsctp_sendv's off every lock.
 *
 * NO-INVERSION: the only re-entrancy of the caller's later usrsctp_sendv is the global output cb,
 * which takes the engine INSTANCE lock (never a channel/pvt lock); we hold neither on return.
 */
void *sofia_dc_pair_bridged(struct sofia_pvt *self_pvt, void *self_dc)
{
	struct ast_channel *self_chan;
	struct ast_channel *far_chan = NULL;
	void *far_dc = NULL;
	/* BRIDGEPEER is a channel name (<= AST_CHANNEL_NAME); linkedid is a uniqueid (name + suffix).
	 * Copy both under the self lock into generous local buffers — their backing store (channel var
	 * storage / the linkedid string field) is only stable while self_chan is locked, and Methods 2/3
	 * run AFTER we unlock self (review fix). */
	char bridgepeer_copy[AST_CHANNEL_NAME];
	char linkedid_copy[AST_CHANNEL_NAME + 64];

	if (!self_pvt) {
		return NULL;
	}

	/* First: pin self_pvt->owner under self_pvt->lock (anti-UAF vs sofia_hangup). */
	ast_mutex_lock(&self_pvt->lock);
	self_chan = self_pvt->owner;
	if (self_chan) {
		ast_channel_ref(self_chan);
	}
	ast_mutex_unlock(&self_pvt->lock);
	if (!self_chan) {
		return NULL;
	}

	/* Next, WITH self LOCKED do ONLY the lock-internal work — Method 1 (ast_bridged_channel
	 * contract) and copying BRIDGEPEER + linkedid into locals. We take NO channel-container lock
	 * here: ast_channel_get_by_name_prefix (Method 2) takes the channels container and would invert
	 * the documented container->channel order (channel.h:1319-1322) if called under a channel lock,
	 * so it is deferred to the next stage below, off the self lock. */
	bridgepeer_copy[0] = '\0';
	linkedid_copy[0] = '\0';
	ast_channel_lock(self_chan);

	/* Method 1: the live _bridge pointer (ast_bridged_channel returns a borrowed ref → take one).
	 * It reads self_chan->_bridge only — no container lock — so it is safe under the self lock. */
	far_chan = ast_bridged_channel(self_chan);
	if (far_chan) {
		ast_channel_ref(far_chan);
	} else {
		/* Method 1 missed: copy the inputs Methods 2/3 need so we can run them OFF the self lock. */
		const char *bridgepeer_name = pbx_builtin_getvar_helper(self_chan, "BRIDGEPEER");
		if (!ast_strlen_zero(bridgepeer_name)) {
			ast_copy_string(bridgepeer_copy, bridgepeer_name, sizeof(bridgepeer_copy));
		}
		if (self_chan->linkedid) {
			ast_copy_string(linkedid_copy, self_chan->linkedid, sizeof(linkedid_copy));
		}
	}
	ast_channel_unlock(self_chan);

	/* With NO channel lock held (review fix), Methods 2 and 3 both
	 * touch the global channels container (Method 2 directly via ast_channel_get_by_name_prefix;
	 * Method 3 via the dialogs container + per-sibling pvt locks). They MUST run with self_chan
	 * UNLOCKED to honor channel.h:1319-1322 (container BEFORE channel, never channel->container). */

	/* Method 2: the BRIDGEPEER channel var (ast_channel_get_by_name_prefix already +1's it). It takes
	 * the channels CONTAINER lock internally — hence run here, off the self lock, to avoid the
	 * channel->container ABBA vs ast_change_name/masquerade. */
	if (!far_chan && !ast_strlen_zero(bridgepeer_copy)) {
		far_chan = ast_channel_get_by_name_prefix(bridgepeer_copy, strlen(bridgepeer_copy));
	}

	/* Method 3: dialogs linkedid walk (sibling sofia leg) — only if 1+2 found nothing. Self is
	 * unlocked; we compare against the COPIED linkedid (self_chan still refed) and ref each sibling's
	 * owner under ITS pvt->lock (channel -> pvt order; the sibling's sofia_hangup NULLs p->owner then
	 * frees it). No self/channel lock is held while we take the dialogs + sibling-pvt locks. */
	if (!far_chan && !ast_strlen_zero(linkedid_copy)) {
		struct ao2_iterator it = ao2_iterator_init(dialogs, 0);
		struct sofia_pvt *p;
		while ((p = ao2_iterator_next(&it))) {
			if (p != self_pvt) {
				struct ast_channel *po;
				ast_mutex_lock(&p->lock);
				po = p->owner;
				if (po && po->linkedid && !strcmp(po->linkedid, linkedid_copy)) {
					far_chan = ast_channel_ref(po);
				}
				ast_mutex_unlock(&p->lock);
			}
			ao2_ref(p, -1);
			if (far_chan) {
				break;
			}
		}
		ao2_iterator_destroy(&it);
	}

	if (!far_chan) {
		ast_channel_unref(self_chan);
		return NULL;
	}

	/* Self-loop guard (pathological leg bridged to itself): pointer compare only, never deref. */
	if (far_chan == self_chan) {
		ast_channel_unref(far_chan);
		ast_channel_unref(self_chan);
		return NULL;
	}
	ast_channel_unref(self_chan);	/* self_chan no longer needed past the identity check */

	/* Then trylock the FAR channel (NEVER block — the ABBA defense). On contention, drop. */
	if (ast_channel_trylock(far_chan)) {
		ast_channel_unref(far_chan);
		return NULL;
	}

	/* DataChannel relay is sofia<->sofia only — read tech/tech_pvt ONLY under the far channel lock. */
	if (far_chan->tech == &sofia_tech) {
		struct sofia_pvt *far_pvt = far_chan->tech_pvt;
		if (far_pvt && far_pvt != self_pvt) {
			/* Finally take far_pvt->lock (channel -> pvt order) before reading + ao2_ref'ing dc. */
			ast_mutex_lock(&far_pvt->lock);
			if (far_pvt->dc && (void *)far_pvt->dc != self_dc) {
				far_dc = far_pvt->dc;
				ao2_ref(far_dc, +1);	/* survive the far leg's hangup racing us */
			}
			ast_mutex_unlock(&far_pvt->lock);
		}
	}

	ast_channel_unlock(far_chan);	/* release ALL channel locks BEFORE returning to the sender */
	ast_channel_unref(far_chan);
	return far_dc;
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
	/* BRIDGEPEER is a channel name (<= AST_CHANNEL_NAME). Copy it UNDER the owner lock —
	 * its backing store (channel var storage) is only stable while owner is locked, and
	 * the get_by_name_prefix lookup runs AFTER we unlock. */
	char bridgepeer_copy[AST_CHANNEL_NAME];

	if (!owner) {
		return NULL;
	}

	/* ast_bridged_channel() contract (channel.h:2318-2327): this runs OFF the owning
	 * thread (sofia_thread, via sofia_local_attended_transfer ~:11018-11019), so 'owner'
	 * MUST be locked BEFORE the call and stay locked WHILE the borrowed _bridge result is
	 * used. Lock owner, +1-ref the borrowed _bridge under the lock (the ref then keeps it
	 * alive independently), and copy BRIDGEPEER into a local for the post-unlock lookup —
	 * mirroring the twin sofia_dc_pair_bridged + sofia_find_bridged_channel Method 1.
	 * 'owner' is the top of the lock order; the caller already released its pvt->lock
	 * before calling this (~:11003/:11010). */
	bridgepeer_copy[0] = '\0';
	ast_channel_lock(owner);
	bridged = ast_bridged_channel(owner);
	if (bridged) {
		ast_channel_ref(bridged);
	} else {
		const char *bridgepeer_name = pbx_builtin_getvar_helper(owner, "BRIDGEPEER");
		if (!ast_strlen_zero(bridgepeer_name)) {
			ast_copy_string(bridgepeer_copy, bridgepeer_name, sizeof(bridgepeer_copy));
		}
	}
	ast_channel_unlock(owner);
	if (bridged) {
		return bridged;
	}

	/* BRIDGEPEER fallback: run OFF the owner lock (ast_channel_get_by_name_prefix takes
	 * the channels container lock — channel.h:1319-1322 mandates container-before-channel)
	 * against the copy. It already +1's the result. */
	if (!ast_strlen_zero(bridgepeer_copy)) {
		bridged = ast_channel_get_by_name_prefix(bridgepeer_copy, strlen(bridgepeer_copy));
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

	/* RFC 3891 §3: match the FULL dialog identifier (Call-ID + to-tag + from-tag) via
	 * native nua_handle_by_replaces() — a Call-ID-only scan could land on the WRONG
	 * forked dialog. Convert via nua_handle_magic() + pin with sofia_pvt_ref_if_linked
	 * (which also validates it is a live dialog pvt). Runs on sofia_thread. An untagged
	 * Replaces is declined for a LOCAL match (caller falls back to remote attended). */
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

	/* Ref each owner UNDER its pvt->lock (sofia_hangup nulls pvt->owner then frees it).
	 * Snapshot the two owners SEQUENTIALLY — never hold two pvt->locks at once. */
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

/* RFC 3515 NOTIFY message/sipfrag transfer-progress to the transferer (chan_sip
 * parity). terminate=0 -> in-progress (substate active); terminate=1 -> terminal
 * (substate terminated;reason=noresource). Also emits AMI ReferProgress. */
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
		/* Snapshot owner name under op->lock (sofia_hangup nulls op->owner under it)
		 * before the AMI emit. */
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
		/* Attended transfer = Replaces param in the Refer-To URI headers. */
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

	/* allowtransfer=no (chan_sip parity): reject with 603 Declined (policy) — exact
	 * string kept (operator scripts match it) — BEFORE the 202. Plus AMI
	 * TransferRejected for REFER-abuse monitoring. */
	if (op && op->allowtransfer == TRANSFER_CLOSED) {
		nua_respond(nh, 603, "Declined (policy)",
			NUTAG_WITH_THIS(nua),
			TAG_END());
		{
			/* Snapshot owner name+uniqueid under op->lock (sofia_hangup nulls
			 * op->owner under it) before the AMI emit. */
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

	/* Snapshot+ref op->owner under op->lock for the whole transfer body — the handler
	 * derefs it across blocking ops (ast_queue_hangup, bridged-finder, ast_async_goto)
	 * and sofia_hangup could null+free it otherwise. Use the local `owner` below; must
	 * be released on every exit. */
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

	/* REFER may carry Diversion: update the redirecting chain before dispatch so the
	 * child Dial inherits it. */
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

		/* chan_sip parity (get_refer_info, chan_sip.c:16799): a BLIND transfer must
		 * gate the Refer-To against the dialplan before redirecting — `attendedtransfer
		 * || ast_exists_extension(...)`. Attended (incl. the remote-attended fallback that
		 * reaches here) always passes; a blind REFER to a non-existent extension is refused
		 * with a terminal failure NOTIFY instead of ast_async_goto'ing the transferee into a
		 * dead context. Same priority-1 form used throughout this file (chan_sip.c:16799). */
		if (!is_attended
				&& !ast_exists_extension(NULL, op->context, refer_to, 1, NULL)) {
			ast_log(LOG_WARNING, "Sofia: Blind REFER to non-existent extension %s@%s — refusing transfer\n",
				refer_to, op->context);
			/* RFC 3515: terminal failure NOTIFY (404) so the transferer's UA learns the
			 * transfer was rejected; tear the transferer leg down (failure path). */
			sofia_send_refer_notify(op, "404 Not Found", 1);
			ast_queue_hangup(owner);
			ast_channel_unref(owner);
			return;
		}

		/* Blind transfer + remote attended-transfer fallback: redirect the transferee
		 * (held leg) to the Refer-To extension via ast_async_goto.
		 *
		 * Order critical: ast_queue_hangup MUST run AFTER find-bridged + ast_async_goto
		 * + all NOTIFY emissions — hanging up op->owner tears down state the
	 * bridged-finder and the AMI ReferProgress emit rely on. The 503 paren-tail is
	 * kept verbatim for chan_sip parity. */
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
			/* chan_sip parity: the transferer
			 * often holds before REFER, so unhold the transferee before redirecting
			 * (before ast_async_goto keeps the indication on the real channel
			 * through masquerades). */
			ast_indicate(bridged, AST_CONTROL_UNHOLD);
			ast_async_goto(bridged, op->context, refer_to, 1);
			/* RFC 3515: terminal NOTIFY after the (fire-and-forget) redirect. */
			sofia_send_refer_notify(op, "200 OK", 1);

			/* SIP_DEFER_BYE_ON_TRANSFER (chan_sip / RFC 5589 §6.1): after the terminal
			 * NOTIFY 200 OK the transferer's UA owns the dialog teardown via BYE. Our own
			 * nua_bye now would race+drop the pending NOTIFY (UA stuck, no audio — observed
			 * vs MicroSIP). So set defer_bye (sofia_hangup skips its nua_bye) and arm
			 * a SOFIA_DEFER_BYE_TIMEOUT_MS safety-net timer in case the UA never BYEs us. */
			ast_mutex_lock(&op->lock);
			if (sofia_sched && op->defer_bye_sched_id == -1) {
				op->defer_bye = 1;
				ao2_ref(op, +1);
				op->defer_bye_sched_id = ast_sched_thread_add(sofia_sched,
					SOFIA_DEFER_BYE_TIMEOUT_MS, sofia_defer_bye_cb, op);
				if (op->defer_bye_sched_id < 0) {
					/* sched_add failed — drop the speculative ref, fall back to
					 * the natural sofia_hangup nua_bye path. */
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
			/* RFC 3515: terminal failure NOTIFY when bridged-finder NULL (paren-tail
			 * kept for operator-script grep compat). */
			sofia_send_refer_notify(op, "503 Service Unavailable (cant handle one-legged xfers)", 1);
			/* No bridged peer — tear the transferer leg down now (failure path does
			 * not defer the BYE). */
			ast_queue_hangup(owner);
		}
		if (bridged) {
			ast_channel_unref(bridged);	/* helper returns a +1 ref */
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
	char sigbuf[64] = "";			/* extracted DTMF signal VALUE (may be numeric "10" or literal "*") */
	unsigned int duration = 250;

	/* Bind the 200 OK to THIS INFO server transaction (NUTAG_WITH_THIS). A bare nua_respond() lets sofia
	 * pick the handle's "current" request, which after the INVITE completes can be a stale/gone transaction
	 * -> "Responding to a Non-Existing Request" -> the 200 never reaches the sender -> it retransmits the
	 * INFO until Timer F (32s) and tears the call down. MicroSIP sends application/media_control+xml
	 * (picture_fast_update) once video is up, so this bit the whole call. */
	nua_respond(nh, SIP_200_OK, NUTAG_WITH_THIS(nua), TAG_END());

	if (!sip || !op || !op->owner) {
		return;
	}

	if (sip->sip_content_type) {
		content_type = sip->sip_content_type->c_type;
	}

	if (sip->sip_payload && sip->sip_payload->pl_data) {
		/* pl_len-bounded NUL-terminated copy — the payload may not be NUL-terminated
		 * and the strstr/atol parsing below assumes a C string. */
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

	/* Video keyframe request bridge (RFC 5168, chan_sip parity chan_sip.c:20062-20066): a legacy SIP video
	 * endpoint (e.g. MicroSIP) asks the remote encoder for a fast-update via INFO
	 * application/media_control+xml (picture_fast_update). Surface it as AST_CONTROL_VIDUPDATE on our
	 * channel so the core bridge relays it to the far leg — which turns it into an RTCP PLI/FIR to a WebRTC
	 * browser (or another INFO to a legacy leg). Without this, the far leg never sends a fresh keyframe and
	 * the SIP phone's picture stays black/frozen. (The 200 OK was already sent above.) */
	if (!strncasecmp(content_type, "application/media_control+xml", 29)) {
		/* Snapshot+ref op->owner under op->lock (sofia_hangup nulls+frees it off this thread), mirroring
		 * the DTMF INFO path below — avoids a queue-onto-freed-channel UAF. */
		struct ast_channel *vu_owner;
		ast_mutex_lock(&op->lock);
		vu_owner = op->owner;
		if (vu_owner) {
			ast_channel_ref(vu_owner);
		}
		ast_mutex_unlock(&op->lock);
		if (vu_owner) {
			ast_queue_control(vu_owner, AST_CONTROL_VIDUPDATE);
			ast_channel_unref(vu_owner);
		}
		return;
	}

	/* g5 — DTMF INFO parity with chan_sip handle_request_info (chan_sip.c:19968-20060).
	 * The signal VALUE may be a literal (* # ! A-D) OR a numeric telephone-event code
	 * (0-9, 10=*, 11=#, 12-15=A-D, 16=FLASH). The previous code took only body[0], so a
	 * two-digit numeric like "10" (=*) arrived as '1' and event 16 (flash) was silent. */
	if (!strcasecmp(content_type, "application/dtmf-relay")
	    || !strcasecmp(content_type, "application/vnd.nortelnetworks.digits")) {
		/* dtmf-relay (Cisco) / Nortel: value in a Signal= field, or the Nortel short form d=. */
		const char *fld = strstr(body, "Signal=");
		const char *dur = strstr(body, "Duration=");
		if (fld) {
			fld += strlen("Signal=");
		} else if ((fld = strstr(body, "d="))) {
			fld += strlen("d=");
		}
		if (fld) {
			size_t i = 0;
			while (*fld == ' ') fld++;
			while (fld[i] && fld[i] != '\r' && fld[i] != '\n' && i < sizeof(sigbuf) - 1) {
				sigbuf[i] = fld[i];
				i++;
			}
			sigbuf[i] = '\0';
		}
		if (dur) {
			long d;
			dur += strlen("Duration=");
			d = atol(dur);
			/* Clamp to a sane DTMF length (hostile/garbage Duration). */
			if (d < 0) {
				d = 0;
			} else if (d > 10000) {
				d = 10000;
			}
			duration = (unsigned int) d;
		}
	} else if (!strcasecmp(content_type, "application/dtmf")) {
		/* application/dtmf: the whole body IS the signal value (first line). */
		size_t i = 0;
		while (body[i] && body[i] != '\r' && body[i] != '\n' && i < sizeof(sigbuf) - 1) {
			sigbuf[i] = body[i];
			i++;
		}
		while (i > 0 && sigbuf[i - 1] == ' ') i--;	/* trim trailing spaces */
		sigbuf[i] = '\0';
	} else {
		return;	/* not a DTMF INFO content-type (already 200 OK'd above) */
	}

	if (ast_strlen_zero(sigbuf)) {
		return;	/* empty signal — 200 OK already sent */
	}

	{
		unsigned int event;
		int is_flash = 0;
		char out_digit = '\0';

		if (sigbuf[0] == '*') {
			event = 10;
		} else if (sigbuf[0] == '#') {
			event = 11;
		} else if (sigbuf[0] == '!') {
			event = 16;	/* hook flash */
		} else if ('A' <= sigbuf[0] && sigbuf[0] <= 'D') {
			event = 12 + sigbuf[0] - 'A';
		} else if ('a' <= sigbuf[0] && sigbuf[0] <= 'd') {
			event = 12 + sigbuf[0] - 'a';
		} else if (sscanf(sigbuf, "%30u", &event) != 1 || event > 16) {
			ast_log(LOG_WARNING, "Sofia: unable to convert DTMF INFO signal '%s' to a valid event\n", sigbuf);
			return;
		}

		if (event == 16) {
			is_flash = 1;
		} else if (event < 10) {
			out_digit = '0' + event;
		} else if (event == 10) {
			out_digit = '*';
		} else if (event == 11) {
			out_digit = '#';
		} else {
			out_digit = 'A' + (event - 12);
		}

		/* Snapshot+ref op->owner under op->lock (sofia_hangup nulls+frees it), then
		 * queue OUTSIDE op->lock. Mirrors sofia_process_bye. */
		struct ast_channel *owner;
		ast_mutex_lock(&op->lock);
		owner = op->owner;
		if (owner) {
			ast_channel_ref(owner);
		}
		ast_mutex_unlock(&op->lock);
		if (owner) {
			if (is_flash) {
				struct ast_frame f = {
					.frametype = AST_FRAME_CONTROL,
					.subclass.integer = AST_CONTROL_FLASH,
					.src = __PRETTY_FUNCTION__,
				};
				ast_queue_frame(owner, &f);
				if (sofia_dtmflog)
					ast_log(LOG_NOTICE, "Sofia: DTMF FLASH received via SIP INFO on %s\n", owner->name);
				else if (sofia_debug)
					ast_verbose("Sofia: Received DTMF FLASH via SIP INFO\n");
			} else {
				struct ast_frame f = {
					.frametype = AST_FRAME_DTMF_BEGIN,
					.subclass.integer = out_digit,
					.src = __PRETTY_FUNCTION__,
				};
				ast_queue_frame(owner, &f);
				f.frametype = AST_FRAME_DTMF_END;
				f.len = duration;
				ast_queue_frame(owner, &f);
				/* "sip set debug dtmf on" → operator-visible NOTICE (CLI + messages); else the legacy
				 * sofia_debug verbose. Same log family as the RFC2833/inband path in sofia_read. */
				if (sofia_dtmflog)
					ast_log(LOG_NOTICE, "Sofia: DTMF '%c' received via SIP INFO on %s\n", out_digit, owner->name);
				else if (sofia_debug)
					ast_verbose("Sofia: Received DTMF '%c' via SIP INFO (duration=%u)\n", out_digit, duration);
			}
			ast_channel_unref(owner);
		}
	}
}

static void sofia_process_prack(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	if (sofia_debug)
		ast_verbose("Sofia: Received PRACK\n");
	/* Bind the 200 to THIS PRACK server transaction (RFC 3262 section 3: a matching PRACK MUST get a 2xx).
	 * A bare nua_respond() has a no-tag fallback ONLY for INVITE (sofia nua_server.c) — during a 100rel
	 * PRACK callback the INVITE server request is still on the handle (already marked pracked), so the
	 * bare 200 can select the INVITE and answer it prematurely (no SDP), or emit 500 "Responding to a
	 * Non-Existing Request". NUTAG_WITH_THIS targets the current event's request = the PRACK. (FreeSWITCH
	 * binds app responses the same way, NUTAG_WITH_THIS_MSG.) */
	nua_respond(nh, SIP_200_OK, NUTAG_WITH_THIS(nua), TAG_END());
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
			/* Pin the owner across sofia_parse_sdp (UAF fix): a concurrent
			 * sofia_hangup could free it while parse mutates its format state. */
			ast_channel_ref(owner);
		}
		ast_mutex_unlock(&op->lock);
		/* For late-offer INVITEs (no SDP in INVITE), the ACK may carry SDP */
		if (sip && sip->sip_payload && sip->sip_payload->pl_data && op->rtp) {
			/* Hold the channel lock across the SDP commit so lazy UDPTL/T.38
			 * creation and media-format updates cannot race channel-thread
			 * readers. owner is ref-pinned above; recursive channel locking is
			 * safe if the parser re-enters channel setters. */
			if (owner) {
				ast_channel_lock(owner);
			}
			sofia_parse_sdp(op, sip, 0 /* answer: ACK late-offer answer to our 200 OK */);
			if (owner) {
				ast_channel_unlock(owner);
			}
			if (sofia_debug)
				ast_verbose("Sofia: ACK with SDP, remote RTP set\n");
		}
		if (owner) {
			ast_channel_unref(owner);
		}
	}
}

/* Pointer-equality predicate for sofia_peer_ref_if_linked. Never touches peer->name
 * (safe even if `obj` is mid-free) — compares the struct pointer only. */
static int sofia_peer_ptr_cmp_cb(void *obj, void *arg, int flags)
{
	return (obj == arg) ? (CMP_MATCH | CMP_STOP) : 0;
}

/* Return a +1 ref to `target` IFF still linked in `peers`, else NULL. Pointer-safe
 * revalidation for peer-magic handlers (qualify OPTIONS response) racing `sip prune
 * realtime` on the CLI thread. MUST NOT use ao2_find(OBJ_POINTER) — the peers hash/cmp
 * deref peer->name (freed memory); ao2_callback with the pointer-only predicate
 * iterates under the container lock and returns the match +1-reffed. */
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

	/* Skip if a qualify is already in flight. */
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

/* Aux pthread: per-second sweep that marshals each due peer's qualify onto
 * sofia_thread (nua_* must run there), like the AMI SIPqualify. */
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
			/* nua_* must run on sofia_thread, so marshal via dispatch. Evaluate the
			 * due predicate AND set the gate under peer->lock (guards qualify_nh):
			 * gate on !qualify_pending && !qualify_nh so a slow sofia_thread does not
			 * enqueue a no-op root callback every second. */
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
					ao2_ref(peer, +1);	/* dispatch ref; callback drops it */
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

/* dialogs container hash/cmp using only the POINTER VALUE (never deref), so a
 * possibly-dangling hmagic is safe and ao2_find(OBJ_POINTER) is O(1). This backs the
 * teardown-race guard sofia_pvt_ref_if_linked: re-validating a raw hmagic under the
 * container lock returns NULL if sofia_hangup already unlinked the pvt, else a +1 ref
 * pinning it for the dispatch. */
static int dialog_hash_fn(const void *obj, int flags)
{
	/* Mask the sign bit so the hash is ALWAYS non-negative: this fork's astobj2 abs()es
	 * the hash on LINK but NOT on FIND/UNLINK (OBJ_POINTER), so a negative value would
	 * miss the single-bucket fast path and fall back to a full scan. */
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

/* Sentinel hmagic for AMI SIPnotify one-shot handles: its ADDRESS can never equal a
 * heap pvt/peer/sub pointer, so sofia_event_callback recognises the app-owned
 * out-of-dialog NOTIFY handle by pointer equality. NON-const so the nua_hmagic_t* cast
 * does not discard a qualifier. */
char sofia_sipnotify_sentinel;

static void sofia_event_callback(nua_event_t event, int status, char const *phrase,
		nua_t *nua, nua_magic_t *magic,
		nua_handle_t *nh, nua_hmagic_t *hmagic,
		sip_t const *sip, tagi_t tags[])
{
	struct sofia_pvt *pvt = (struct sofia_pvt *)hmagic;
	/* For dialog events dialog_pvt holds a re-validated +1 ref pinning the pvt for the
	 * whole dispatch (released at function exit). Peer-magic events leave it NULL and
	 * re-cast hmagic to sofia_peer locally. */
	struct sofia_pvt *dialog_pvt = NULL;
	const char *event_name = nua_event_name(event);

	/* SIPnotify / unsolicited-MWI one-shot handle (sentinel hmagic): destroy the app-owned
	 * out-of-dialog NOTIFY handle on its final response (sofia-sip never auto-reaps it). The NOTIFY is
	 * sent via nua_method (this fork rejects an out-of-dialog nua_notify locally with 481), so the final
	 * response arrives as nua_r_method; nua_r_notify is kept for safety. Handled before the
	 * blacklist/teardown-guard switches so the dispatch never sees the sentinel. nua_handle_destroy is
	 * legal — same-thread rule. */
	if (hmagic == SOFIA_SIPNOTIFY_HMAGIC) {
		if ((event == nua_r_method || event == nua_r_notify) && status >= 200) {
			if (sofia_debug) {
				ast_verbose("Sofia SIPnotify: NOTIFY final response %d %s — destroying one-shot handle\n",
					status, phrase);
			}
			nua_handle_destroy(nh);
		}
		return;
	}

	/* Outbound PUBLISH (RFC 3903): generic-method responses for publication handles
	 * route here (sentinel hmagic) before any dialog dispatch; publication found by nh. */
	if (hmagic == SOFIA_PUBLICATION_HMAGIC) {
		if (event == nua_r_method) {
			sofia_publication_handle_response(status, phrase, nh, sip);
		}
		return;
	}

	/* RFC 5626 flow-close (Complement B): sofia's built-in registrar watch fires nua_i_media_error on a REGISTER
	 * handle when its connection-oriented binding's connection closes (armed on the stack thread, marshalled here
	 * to sofia_thread). We look the handle up BY POINTER in our registry (type-safe: never dereference an untyped
	 * hmagic). A hit -> a tracked binding: UNLINK the matched contact (the contact destructor is the SOLE handle
	 * dropper -> no double free). A miss with hmagic==NULL -> an orphaned registrar handle (401-challenge /
	 * multi-Contact / non-stored, which the built-in watch also armed) -> destroy it so it does not leak. A miss
	 * with a bound hmagic -> a session/media error: fall through to normal handling. */
	if (event == nua_i_media_error) {
		struct sofia_regflow_entry key, *e = NULL;
		SOFIA_FORKDBG("media-error nh=%p status=%d phrase=%s (registry-check follows; a HIT below = a tracked REGISTER flow closed)",
			(void *)nh, status, S_OR(phrase, ""));
		if (sofia_regflow_handles) {
			key.nh = nh;
			e = ao2_find(sofia_regflow_handles, &key, OBJ_POINTER);	/* +1 finder, pointer-membership */
		}
		if (e) {
			char pname[128], uri[256];
			struct sofia_peer *peer;
			int dropping;
			ao2_lock(e);
			dropping = e->dropping;
			ao2_unlock(e);
			if (dropping) {
				/* A drop is already in flight for this handle (its destroy task will run). Consume this
				 * (possibly duplicate) event without acting -> no orphan-destroy, no double free. */
				ao2_ref(e, -1);				/* finder */
				return;
			}
			ast_copy_string(pname, e->peer_name, sizeof(pname));
			ast_copy_string(uri, e->contact_uri, sizeof(uri));
			ao2_ref(e, -1);					/* finder (registry keeps its ref until the drop task) */
			peer = sofia_find_peer_cached(pname);		/* +1 or NULL (cache-only) */
			if (peer) {
				struct sofia_contact *c;
				int became_empty = 0, emit_unregister = 0;
				ast_mutex_lock(&peer->lock);
				c = ao2_find(peer->contacts, uri, OBJ_POINTER);	/* +1 finder */
				if (c) {
					if (c->reg_nh == nh) {		/* still the current binding for this handle */
						ao2_unlink(peer->contacts, c);	/* -> contact destructor drops reg_nh (sole dropper) */
						if (sofia_forkdebug) {
							char ubuf[256];
							SOFIA_FORKDBG("media-error REMOVED contact %s of peer %s (nh=%p) — this browser leg is now de-registered",
								sofia_uri_redact(uri, ubuf, sizeof(ubuf)), pname, (void *)nh);
						}
						if (sofia_debug) {
							ast_verbose("Sofia: flow closed (connection gone) - removed contact %s of peer %s\n",
								uri, pname);
						}
						if (ao2_container_count(peer->contacts) == 0) {
							peer->registered = 0;
							memset(&peer->src_addr, 0, sizeof(peer->src_addr));
							ast_copy_string(peer->reg_transport, "udp", sizeof(peer->reg_transport));
							peer->expire = 0;
							peer->reg_expiry = 0;
							became_empty = 1;
							emit_unregister = peer->flowclose_emit_unregister;	/* policy under lock */
						}
					}
					ao2_ref(c, -1);			/* finder */
				}
				ast_mutex_unlock(&peer->lock);
				if (became_empty) {
					/* Internal routing state is ALWAYS corrected regardless of policy. */
					sofia_peer_ipport_reindex(peer);
					/* External unregister side-effects only when flowclose_emit_unregister=yes;
					 * default (no) stays silent so a browser F5 does not flap the BLF. NOT under peer->lock. */
					if (emit_unregister) {
						struct sofia_register_update upd = { 0 };
						upd.emit_unregister = 1;
						upd.unregister_cause = "Flow closed";
						sofia_emit_register_side_effects(peer, NULL, &upd);	/* sip=NULL safe */
					}
				}
				ao2_ref(peer, -1);
			}
			return;						/* consumed our tracked handle's event */
		}
		if (!hmagic) {
			/* Registry MISS + NULL hmagic = a never-tracked orphaned registrar handle (the 401-challenge /
			 * multi-Contact / non-stored REGISTER, which the built-in watch also armed) whose connection just
			 * closed. We bind no hmagic to handles we track (they live in sofia_regflow_handles) and bind a pvt
			 * to every session handle, so a NULL-hmagic non-registry handle is reapable -> destroy it (no leak). */
			nua_handle_destroy(nh);
			return;
		}
		/* bound hmagic -> session/media error: not ours, fall through. */
	}

	/* Debug-gated event logging for peer/ip filter modes. */
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
	case nua_i_update:
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
		/* Shared-NAT self-DoS fix: EXEMPT in-dialog requests from the blacklist drop. The gate is
		 * IP-only (sofia_blacklist_check_sip), so behind a shared/carrier NAT one abuser drives the
		 * public IP to the block threshold and then co-located LEGIT phones' in-dialog BYE/CANCEL/ACK
		 * get dropped -> hung channels leaking call slots. A request that resolves to an EXISTING live
		 * dialog (hmagic links into the dialogs container) is, by definition, on an already-established
		 * call we accepted — never a brute-force vector — so let it through. Out-of-dialog / new
		 * transactions (REGISTER, fresh INVITE [NULL hmagic], out-of-dialog SUBSCRIBE/MESSAGE/OPTIONS/
		 * PUBLISH, peer-magic events) do NOT resolve to a dialog and stay fully gated. Runs on
		 * sofia_thread (single dispatcher), so this find+release cannot race a concurrent hangup, and
		 * the teardown-guard switch below re-finds the ref it needs. */
		{
			struct sofia_pvt *indialog = sofia_pvt_ref_if_linked(hmagic);
			if (indialog) {
				ao2_ref(indialog, -1);	/* exempt: in-dialog request on a live call */
			} else if (sofia_blacklist_check_sip(sip)) {
				return;
			}
		}
		break;
	default:
		break;
	}

	/* Teardown-race guard for in-dialog events whose hmagic is the dialog pvt and which
	 * deref/mutate it concurrently with sofia_hangup: re-validate against dialogs and use
	 * a +1-reffed pvt (NULL if already unlinked -> per-handler `if (pvt)` skips). Peer-magic
	 * and fresh-INVITE (NULL hmagic) events keep the raw-hmagic path. Released at the single
	 * function-exit drop. */
	switch (event) {
	case nua_i_invite:
	case nua_i_update:
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

	/* SIP history: record this inbound dialog event against the VALIDATED dialog pvt (one central hook
	 * for re-INVITE/UPDATE/BYE/CANCEL/INFO/REFER/ACK/terminated + the r_* responses). Gated on
	 * dialog_pvt — NOT the raw hmagic `pvt`, which for peer-magic events (OPTIONS/REGISTER) is a
	 * sofia_peer, not a sofia_pvt. A fresh inbound INVITE has no pvt yet (NULL hmagic) —
	 * sofia_process_invite records its own "Rx INVITE". No-op unless the call is recording. */
	if (dialog_pvt) {
		if (status) {
			sofia_append_history_code(dialog_pvt, status, "Rx", "%s %d %s",
				event_name, status, S_OR(phrase, ""));
		} else {
			sofia_append_history(dialog_pvt, "Rx", "%s", event_name);
		}
	}

	switch (event) {
	case nua_i_invite:
		/* hmagic set = existing dialog usage -> re-INVITE; NULL = fresh inbound INVITE.
		 * If hmagic was set but the dialog was torn down concurrently (pvt NULL), respond
		 * 481 rather than spawning a fresh dialog on the dying handle. */
		if (pvt) {
			sofia_process_reinvite(pvt, nua, nh, sip);
		} else if (hmagic) {
			nua_respond(nh, 481, "Call/Transaction Does Not Exist",
				NUTAG_WITH_THIS(nua), TAG_END());
		} else {
			sofia_process_invite(nua, nh, pvt, sip, tags);
		}
		break;
	case nua_i_update:
		/* In-dialog UPDATE (RFC 3311) — media renegotiation / hold / session-timer refresh.
		 * UPDATE is always in-dialog; pvt NULL = the dialog is gone -> 481. APPL_METHOD'd so the
		 * stack delivers it here (with MEDIA_ENABLE 0 / no soa it would otherwise mis-answer). */
		if (pvt) {
			sofia_process_update(pvt, nua, nh, sip);
		} else {
			nua_respond(nh, 481, "Call/Transaction Does Not Exist",
				NUTAG_WITH_THIS(nua), TAG_END());
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
	/* No nua_i_publish case — PUBLISH is not APPL_METHOD'd, so the stack rejects it. */
	case nua_i_prack:
		sofia_process_prack(nua, nh, pvt, sip, tags);
		break;
	case nua_i_ack:
		sofia_process_ack(nua, nh, pvt, sip, tags);
		break;

	case nua_r_register: {
		/* Pin the peer (ref-if-linked) for the whole handler — a late REGISTER response
		 * races `sip prune realtime` and the 200 branch reads peer fields outside
		 * peer->lock, so the REF (not just the lock) is load-bearing. NULL = freed. */
		struct sofia_peer *peer = hmagic ? sofia_peer_ref_if_linked((struct sofia_peer *)hmagic) : NULL;
		ast_verbose("Sofia: REGISTER response %d %s\n", status, phrase);
		if (status == 200) {
			if (sip && sip->sip_contact) {
				int expires = DEFAULT_EXPIRY;
				if (sip->sip_expires && sip->sip_expires->ex_delta) {
					/* Clamp ex_delta before the int cast — > INT_MAX wraps negative. */
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
						/* rtupdate (chan_sip parity): gated by is_realtime && peer_rtupdate. */
						if (peer->is_realtime && sofia_cfg.peer_rtupdate) {
							/* rtsavesysname (chan_sip parity): regserver column setup. */
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
						/* Outbound MWI SUBSCRIBE (a watcher): now that this trunk is
						 * registered, start (idempotently) its message-summary watcher
						 * if mwi_subscribe is configured. No-op otherwise. */
						sofia_subscribe_on_registered(peer);
						sofia_eventsub_on_registered(peer);
						/* GRUU: learn the pub-gruu/temp-gruu the registrar minted for
						 * our +sip.instance (RFC 5627 §5.2). No-op unless gruu=yes. */
						sofia_gruu_consume(peer, sip);
					}
				}
				/* Service-Route (RFC 3608 §6.1): keyed to the LATEST 2xx REGISTER, not only a 200
				 * carrying a Contact — so a 2xx with no Service-Route reliably clears the stored
				 * route. Self-no-ops when peer is NULL or service_route=no. */
				sofia_service_route_store(peer, sip);
				/* RFC 5626 SIP Outbound: record Require: outbound confirmation + Flow-Timer from the
				 * 2xx (no-op unless sip_outbound=yes). Global tcp_keepalive feeds the keepalive warn. */
				sofia_outbound_consume(peer, sip, sofia_cfg.tcp_keepalive_ms);
			} else if (status == 401 || status == 407) {
			if (peer) {
				char www_creds[512] = "";
				char proxy_creds[512] = "";
				int have_www = 0, have_proxy = 0;
				char uri[256];

				ast_mutex_lock(&peer->lock);

				/* Outbound REGISTER is opt-in: only a [general] `register =>` line
				 * sets is_register_line. A static challenge-auth trunk (secret + static
				 * host, NO register=>) must NOT re-REGISTER on a 401/407 — refuse here so
				 * a spurious challenge can't drive an auth loop. */
				if (!peer->is_register_line) {
					ast_mutex_unlock(&peer->lock);
					ao2_ref(peer, -1);
					break;
				}

				/* registerattempts (chan_sip parity): at the cap, give up the
				 * auth-challenge re-register to prevent runaway auth storms. */
				if (sofia_cfg.register_attempts > 0 && peer->reg_attempts >= sofia_cfg.register_attempts) {
					ast_log(LOG_NOTICE, "Sofia: Registration attempts exhausted for peer '%s' (reg_attempts=%d cap=%d) — giving up\n",
						peer->name, peer->reg_attempts, sofia_cfg.register_attempts);
					ast_mutex_unlock(&peer->lock);
					ao2_ref(peer, -1);
					break;
				}

				/* Build the FULL Digest:"realm":user:secret cred for EACH challenge
				 * present (a 2-field "user:secret" is silently rejected by auc_credentials).
				 * One response may carry both WWW- and Proxy-Authenticate; feed both. */
				if (sip->sip_www_authenticate && sofia_format_auth_creds(sip->sip_www_authenticate,
						peer->defaultuser, peer->secret, www_creds, sizeof(www_creds)) == 0) {
					have_www = 1;
				}
				if (sip->sip_proxy_authenticate && sofia_format_auth_creds(sip->sip_proxy_authenticate,
						peer->defaultuser, peer->secret, proxy_creds, sizeof(proxy_creds)) == 0) {
					have_proxy = 1;
				}
				/* sip:user@host:port + ;transport= for tls/tcp/ws/wss (UDP no-op). */
				sofia_build_register_uri(peer, uri, sizeof(uri));

				ast_verbose("Sofia: Responding to auth challenge for %s\n", peer->name);

				/* maxforwards: RFC 3261 §20.22 Max-Forwards on the REGISTER. */
				char mf_str_reg[8];
				char instance_feature_reg[120];
				snprintf(mf_str_reg, sizeof(mf_str_reg), "%d", peer->maxforwards);
				/* GRUU: keep the +sip.instance advertisement on the re-REGISTER too. */
				sofia_build_instance_feature(peer, instance_feature_reg, sizeof(instance_feature_reg), peer->sip_outbound);
				/* callbackextension (chan_sip parity): override the Contact username. */
				nua_register(peer->nh,
					NUTAG_URL(uri),
					SIPTAG_FROM_STR(uri),
					TAG_IF(have_www, NUTAG_AUTH(www_creds)),
					TAG_IF(have_proxy, NUTAG_AUTH(proxy_creds)),
					SIPTAG_MAX_FORWARDS_STR(mf_str_reg),
					TAG_IF(!ast_strlen_zero(peer->callbackextension),
						NUTAG_M_USERNAME(peer->callbackextension)),
					TAG_IF(peer->gruu || peer->sip_outbound, NUTAG_M_FEATURES(instance_feature_reg)),
					TAG_IF(peer->sip_outbound, NUTAG_SUPPORTED("outbound, path")),	/* RFC 5626 §4.2.1 */
					TAG_END());

				peer->reg_attempts++;
				ast_mutex_unlock(&peer->lock);
			}
		} else if (status >= 300) {
			ast_verbose("Sofia: Registration failed %d %s\n", status, phrase);
			if (peer) {
				ast_mutex_lock(&peer->lock);
				peer->registered = 0;
				/* GRUU: do NOT clear learned GRUUs on a non-2xx REGISTER — RFC 5627 §4.2: a failed
				 * request does not remove/invalidate a previously provided GRUU (a transient failed
				 * refresh can arrive while the binding is still valid). They are cleared instead by the
				 * consume path on a 2xx that returns no GRUU (de-registration / not re-issued). */
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
		/* OUTBOUND INVITE auth (RFC 3261 §22): answer a 401/407 from an upstream trunk by
		 * feeding peer creds to NUA, which restarts the INVITE. MUST be reactive — NUTAG_AUTH
		 * applies only after a challenge created nh_auth (chan_sip handle_response_invite parity).
		 * Non-forked only (a fork child's challenge is a branch failure). BOUNDED so sequential
		 * WWW+Proxy challenges both get answered without an endless loop. md5secret-only peers
		 * unsupported (NUTAG_AUTH needs cleartext). */
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
			/* One response may carry both WWW- and Proxy-Authenticate — build a cred for
			 * each and feed both in one nua_authenticate call. */
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
				/* on sofia_thread, no lock held — restart the INVITE with the digest(s) */
				nua_authenticate(nh,
					TAG_IF(have_www, NUTAG_AUTH(www_creds)),
					TAG_IF(have_proxy, NUTAG_AUTH(proxy_creds)),
					TAG_END());
				ast_log(LOG_NOTICE,
					"Sofia: outbound INVITE challenged (%d) — re-sending with %s%s%s credentials\n",
					status, have_www ? "WWW" : "", (have_www && have_proxy) ? "+" : "",
					have_proxy ? "Proxy" : "");
				break;	/* NUA restarts the request */
			}
			ast_log(LOG_NOTICE,
				"Sofia: outbound INVITE challenged (%d) but no usable cleartext credential — call will fail\n",
				status);
		}
		/* Session timers (RFC 4028): capture negotiated Session-Expires on every 200 OK.
		 * The SessionTimerRefresh AMI event fires only on REFRESH (dialog already UP). */
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
				/* Snapshot+ref fork->master under fork->lock (a concurrent sofia_hangup
				 * could free it); owner then read+reffed under master->lock. */
				ast_mutex_lock(&fork->lock);
				first = (fork->state == FORK_PRE_RING);
				if (first) fork->state = FORK_RINGING;
				m = fork->master;
				if (m) {
					ao2_ref(m, +1);
				}
				ast_mutex_unlock(&fork->lock);
				if (m) {
					/* ABBA fix: ast_queue_control/ast_setstate re-lock the channel, so
					 * snapshot+ref m->owner under m->lock, DROP it, then queue — never
					 * hold pvt->lock across a fresh channel lock. */
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
					/* This 2xx is rejected (crypto/SDP mismatch, or another branch
					 * won). CANCEL is invalid once >= 200, so tear the answered branch
					 * down with BYE, then run the shared dead-child accounting. */
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
			/* Direct-media re-INVITE response (call already up). reinvite_pending +
			 * redirip are shared with the bridge thread; guard with pvt->lock. */
			int rejected = (status >= 300);
			int has_sdp = (!rejected && sip && sip->sip_payload && sip->sip_payload->pl_data);
			int sdp_rc = 0;
			int reverted_to_relay = 0;	/* the revert re-INVITE actually fired (vs guard-skipped) */
			struct ast_channel *owner = NULL;
			ast_mutex_lock(&pvt->lock);
			/* Re-acquire in canonical channel->pvt order so sofia_parse_sdp's set_format
			 * re-enters a channel lock we already hold (chan_sip sip_pvt_lock_full idiom):
			 * ref owner, drop pvt, lock channel, relock pvt, revalidate identity. */
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
				/* Peer refused; revert to PBX relay. */
				memset(&pvt->redirip, 0, sizeof(pvt->redirip));
				/* FIX 1: a REFUSED/timed-out outbound T.38 (LOCAL_REINVITE) re-INVITE
				 * must not leave T.38 stuck — transition to DISABLED so res_fax gets
				 * AST_T38_REFUSED and falls back (chan_sip parity). Channel lock held
				 * here (re-acquire loop above), so sofia_change_t38_state is safe. */
				if (owner && pvt->t38_state == SOFIA_T38_LOCAL_REINVITE) {
					sofia_change_t38_state(pvt, SOFIA_T38_DISABLED);
				}
			} else if (has_sdp) {
				sdp_rc = sofia_parse_sdp(pvt, sip, 0 /* answer: directmedia/T38 re-INVITE 2xx */);
			}
			if (owner) {
				/* Release the channel LOCK now (so the relay re-INVITE runs under
				 * pvt->lock alone) but KEEP the ref — the unref is DEFERRED past the
				 * pvt->lock drop (dropping the last ref here could run the channel
				 * destructor under pvt->lock). */
				ast_channel_unlock(owner);
			}
			if (!rejected && has_sdp && sdp_rc < 0
			    && !pvt->alreadygone && pvt->state == SOFIA_DIALOG_STATE_UP && pvt->nh) {
				/* A 2xx is FINAL — can't 488 it. The directmedia answer was unusable
				 * (pvt media left unchanged on reject), so revert to PBX relay: clear
				 * redirip + send a fresh non-directmedia re-INVITE. Same teardown gate
				 * as sofia_directmedia_reinvite_root. */
				memset(&pvt->redirip, 0, sizeof(pvt->redirip));
				sofia_send_reinvite(pvt);
				reverted_to_relay = 1;
			}
			ast_mutex_unlock(&pvt->lock);
			if (owner) {
				ast_channel_unref(owner);	/* unref AFTER pvt->lock dropped */
				owner = NULL;
			}
			if (rejected) {
				ast_log(LOG_NOTICE, "Sofia: directmedia re-INVITE rejected on '%s' (%d %s) — staying in relay mode\n",
					pvt->callid ? pvt->callid : "(no-callid)", status, phrase ? phrase : "");
			} else if (reverted_to_relay) {
				ast_log(LOG_WARNING, "Sofia: directmedia re-INVITE 2xx had an unusable SDP on '%s' — reverted to relay\n",
					pvt->callid ? pvt->callid : "(no-callid)");
			} else if (has_sdp && sdp_rc < 0) {
				/* Unusable SDP but the call was no longer UP (teardown race) — revert
				 * correctly skipped. */
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
					/* FIX 4: hold the channel lock across the parse (mirrors the
					 * directmedia 2xx + inbound re-INVITE paths) so the lazy udptl
					 * create + T.38 setters don't race the channel-thread readers
					 * (sofia_read/write/get_udptl). Recursive mutex → the parse commit
					 * re-locking the same channel is safe. */
					if (owner) ast_channel_lock(owner);
					sofia_parse_sdp(pvt, sip, 0 /* answer: 180 early media */);
					if (owner) ast_channel_unlock(owner);
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
					/* FIX 4: channel lock across the parse (see status==180). */
					if (owner) ast_channel_lock(owner);
					sofia_parse_sdp(pvt, sip, 0 /* answer: 183 progress */);
					if (owner) ast_channel_unlock(owner);
				}
				if (owner) {
					ast_queue_control(owner, AST_CONTROL_PROGRESS);
					ast_setstate(owner, AST_STATE_RINGING);
					ast_channel_unref(owner);
					owner = NULL;
				}
			} else if (status == 200) {
				/* RFC 3261 §13.2.2.4 / RFC 6026: a 200 OK for an INVITE we already
				 * abandoned (forking proxy sent non-2xx then 2xx, or we hung up) must be
				 * ACK+BYE'd, not answered — else the UAS retransmits for 64*T1 with a
				 * ghost media leg. Only reached if the pvt/handle survived the orphan
				 * window (released in sofia_pvt_destructor, RFC 6026 Timer M = 64*T1). */
				ast_mutex_lock(&pvt->lock);
				if (pvt->alreadygone || !pvt->owner) {
					ast_mutex_unlock(&pvt->lock);
					char orphan_proxy_url[128];
					ast_log(LOG_NOTICE,
						"Sofia: orphan 200 OK on terminated INVITE %s: ACK + BYE per RFC 3261 13.2.2.4\n",
						pvt->callid ? pvt->callid : "(no-callid)");
					/* sofia-sip auto-ACKs unless AUTOACK(0) (NAT peer); then ACK here. The BYE needs the
					 * SAME proxy override (WSS/NAT placeholder Contact) or it hits the unroutable remote
					 * target and the orphan dialog is never torn down. */
					if (sofia_build_nat_proxy_url_from_peer(pvt->peer, orphan_proxy_url, sizeof(orphan_proxy_url))) {
						nua_ack(nh, NUTAG_PROXY(orphan_proxy_url), TAG_END());
						nua_bye(nh, NUTAG_PROXY(orphan_proxy_url), TAG_END());
					} else {
						nua_bye(nh, TAG_END());
					}
					break;
				}
				owner = pvt->owner;
				ast_channel_ref(owner);
				ast_mutex_unlock(&pvt->lock);

				int sdp_rc = 0;
				if (sip && sip->sip_payload && sip->sip_payload->pl_data) {
					/* FIX 4: hold the channel lock across the parse (mirrors the
					 * directmedia 2xx + inbound re-INVITE paths) so the lazy udptl
					 * create + T.38 setters (and the FIX 1b LOCAL_REINVITE → ENABLED
					 * commit) don't race the channel-thread readers
					 * (sofia_read/write/get_udptl). owner is non-NULL here (orphan guard
					 * above). Recursive mutex → the parse commit re-locking is safe. */
					ast_channel_lock(owner);
					sdp_rc = sofia_parse_sdp(pvt, sip, 0 /* answer: final 2xx to our INVITE */);
					ast_channel_unlock(owner);
				}
				/* The final 2xx may carry Diversion (downstream redirect). */
				sofia_change_redirecting_info(pvt, owner, sip);
				/* Outbound ringing done on 200 OK: decrement inRinging (call stays in
				 * the inUse pool until hangup). */
				sofia_update_call_counter(pvt, SOFIA_DEC_CALL_RINGING);
				if (sdp_rc < 0) {
					/* The answer failed encryption policy — tear down (BYE + HANGUP). */
					ast_log(LOG_NOTICE, "Sofia: outbound 200 OK rejected — encryption mismatch in answer (peer=%s)\n",
						pvt->peer ? pvt->peer->name : "<unknown>");
					nua_bye(nh, TAG_END());
					ast_queue_control(owner, AST_CONTROL_HANGUP);
					ast_channel_unref(owner);
					owner = NULL;
					break;
				}
				/* NAT-aware manual ACK (chan_sip parity): for nat peers auto-ACK was
				 * disabled (NUTAG_AUTOACK(0)); ACK with NUTAG_PROXY at peer->src_addr
				 * so it bypasses the LAN-IP Contact (else the phone retransmits 200 OK). */
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
				/* Mask the inbound caller's answer video to what THIS outbound leg accepted before
				 * answering the caller — chan_sofia does not transcode video (single-contact path; the
				 * fork path does the same in sofia_fork_pick_winner). SDP-only; no-op if the caller is
				 * not a Sofia inbound leg or shares the codec already. */
				sofia_set_caller_video_mask_from_answered(pvt);
				ast_queue_control(owner, AST_CONTROL_ANSWER);
				ast_setstate(owner, AST_STATE_UP);
				/* Set active contact for the single-contact outbound path. Skip if already
				 * set at request time (sofia_request_call now selects the single live contact
				 * up front for per-contact WSS routing) — avoids a spurious "already set"
				 * warning + redundant lookup; still covers legacy peer-aggregate single calls. */
				if (pvt->peer && !pvt->active_contact && !pvt->is_fork_child && !pvt->fork && !ast_strlen_zero(pvt->ruri)) {
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
				/* allowoverlap (chan_sip parity, outbound 484): YES propagates
				 * AST_CAUSE_INVALID_NUMBER_FORMAT (484); NO/DTMF propagates
				 * AST_CAUSE_UNALLOCATED (404). Effective mode = peer else default.
				 * Mark the dialog gone first so a late 2xx is ACK+BYE'd by the orphan
				 * guard above (chan_sip sip_alreadygone parity). */
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
				/* Mark the dialog gone (same reason as the 484 branch): lets the
				 * status==200 orphan guard ACK+BYE a late 2xx per RFC 3261 §16.7. */
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
		/* nua_r_bye DEC site (defensive; flag-gated idempotency makes it multi-site safe). */
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
		/* Qualify response — hmagic is the peer. */
		if (hmagic) {
			/* Revalidate+pin the peer (ref-if-linked) before any deref — `sip prune
			 * realtime` can free it while the OPTIONS response is in flight. NULL ->
			 * drop the stale response. Ref released before the case breaks. */
			struct sofia_peer *peer = sofia_peer_ref_if_linked((struct sofia_peer *)hmagic);
			int pingtime;
			if (!peer) {
				if (sofia_debug)
					ast_verbose("Sofia: OPTIONS response for a pruned/freed peer (hmagic=%p) — dropped\n",
						(void *)hmagic);
				break;
			}
			pingtime = ast_tvdiff_ms(ast_tvnow(), peer->qualify_sent);
			/* Compute status + snapshot under peer->lock, then RELEASE and do
			 * manager_event / ast_devstate_changed / register_peer_exten (contexts
			 * rwlock) / nua_handle_destroy OUTSIDE it — avoids nesting peer->lock over
			 * the contexts rwlock. The peer can't be freed across the unlock (reload's
			 * sweep is on sofia_thread, serialised with this handler). */
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
				/* Detach hmagic before destroying the prior qualify handle:
				 * bind(NULL) is synchronous so stays under the lock; the destroy
				 * is moved outside. */
				old_qnh = peer->qualify_nh;
				peer->qualify_nh = NULL;
				nua_handle_bind(old_qnh, NULL);
			}
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
				/* regextenonqualify: ADD on REACHABLE, REMOVE on UNREACHABLE (LAGGED neither). */
				if (do_regexten_add) {
					register_peer_exten(peer, 1);
				} else if (do_regexten_remove) {
					register_peer_exten(peer, 0);
				}
			}
			if (old_qnh) {
				nua_handle_destroy(old_qnh);
			}
			ao2_ref(peer, -1);	/* revalidation ref */
		}
		break;
	case nua_r_message:
		if (sofia_debug)
			ast_verbose("Sofia: MESSAGE response %d %s\n", status, phrase);
		sofia_message_reap_outbound(nh, status);
		break;
	case nua_r_subscribe:
		/* Outbound MWI SUBSCRIBE (a watcher) response — reactive digest auth + status handling.
		 * Returns 1 (break) when nh is one of our MWISUB handles. */
		if (sofia_subscribe_on_subscribe_response(nh, sip, status))
			break;
		/* Generic outbound SUBSCRIBE (RFC 6665) watcher response (distinct sentinel). */
		if (sofia_eventsub_on_subscribe_response(nh, sip, status))
			break;
		if (sofia_debug)
			ast_verbose("Sofia: SUBSCRIBE response %d %s\n", status, phrase);
		break;
	case nua_r_notify:
		if (sofia_debug)
			ast_verbose("Sofia: NOTIFY response %d %s\n", status, phrase);
		/* Presence sub expiry/terminate: sofia-sip auto-sends the final NOTIFY and
		 * reports nua_substate_terminated here. Correlate by handle and free it. */
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
		/* The REFER request's own response. The event callback does NOT pin pvt for
		 * nua_r_refer, so re-validate/pin by the handle magic ourselves. >=300 fails
		 * the pending outbound transfer (sofia_transfer_on_refer_response). */
		{
			struct sofia_pvt *rp = sofia_pvt_ref_if_linked(nh ? nua_handle_magic(nh) : NULL);
			if (rp) {
				sofia_transfer_on_refer_response(rp, status);
				ao2_ref(rp, -1);
			}
		}
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

	/* Release the teardown-race guard ref (NULL for non-dialog events). */
	if (dialog_pvt) {
		ao2_ref(dialog_pvt, -1);
	}
}

/* feature #6: forward decl — defined near the config parser, used at nua_create below. */
static unsigned sofia_tls_min_version_mask(const char *v);

/* One-shot: apply the SIP-capture config (HEP stream + file dump) once the su_root event loop is RUNNING.
 * Applying it synchronously right after nua_create (before su_root_run) sets the TPTAG_CAPT/DUMP param but the
 * capture socket / dump FILE* never actually opens — the tports are not serviced until the loop runs — so
 * config-driven capture silently did nothing until a CLI re-arm. This callback fires INSIDE su_root_run (loop
 * live, tports operational) and self-destroys. */
static su_timer_t *sofia_capture_apply_timer;
static void sofia_capture_apply_deferred(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg)
{
	sofia_apply_capture();
	su_timer_destroy(t);
	if (t == sofia_capture_apply_timer)
		sofia_capture_apply_timer = NULL;
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

	/* Per-transport URLs as separate tags (NUTAG_URL/SIPS_URL/WS_URL/WSS_URL) — the
	 * URL parser rejects comma-concatenation into NUTAG_URL. */
	{
		char udp_url[128];
		char tls_url[128] = "";
		char ws_url[128]  = "";
		char wss_url[128] = "";
		char cert_dir[256] = "";	/* the DIRECTORY handed to sofia-sip (NUTAG_CERTIFICATE_DIR); derived
						 * from tlscertfile (its dirname when tlscertfile names a file). */
		int needs_cert;

		/* IPv6 bind: bracket-wrap an IPv6 host (RFC 3261 §19.1.2); IPv4/hostnames/`*`
		 * pass through unchanged. */
		char hbuf_udp[80], hbuf_tls[80], hbuf_ws[80], hbuf_wss[80];
		snprintf(udp_url, sizeof(udp_url), "sip:%s:%d",
			sofia_uri_format_host(
				ast_strlen_zero(sofia_cfg.bindaddr) ? "*" : sofia_cfg.bindaddr,
				hbuf_udp, sizeof(hbuf_udp)),
			sofia_cfg.bindport);
		if (sofia_cfg.tls_enable && sofia_cfg.tlsbindport > 0) {
			/* Explicit transport=tls forces TLS-only: without it, sips: enumerates
			 * both TLS+WSS on the same port and the WSS bind fails. */
			snprintf(tls_url, sizeof(tls_url), "sips:%s:%d;transport=tls",
				sofia_uri_format_host(
					ast_strlen_zero(sofia_cfg.tlsbindaddr) ? "*" : sofia_cfg.tlsbindaddr,
					hbuf_tls, sizeof(hbuf_tls)),
				sofia_cfg.tlsbindport);
		}
		if (sofia_cfg.ws_enable && sofia_cfg.wsbindport > 0) {
			snprintf(ws_url, sizeof(ws_url), "sip:%s:%d;transport=ws",
				sofia_uri_format_host(
					ast_strlen_zero(sofia_cfg.wsbindaddr) ? "*" : sofia_cfg.wsbindaddr,
					hbuf_ws, sizeof(hbuf_ws)),
				sofia_cfg.wsbindport);
		}
		if (sofia_cfg.wss_enable && sofia_cfg.wssbindport > 0) {
			snprintf(wss_url, sizeof(wss_url), "sips:%s:%d;transport=wss",
				sofia_uri_format_host(
					ast_strlen_zero(sofia_cfg.wssbindaddr) ? "*" : sofia_cfg.wssbindaddr,
					hbuf_wss, sizeof(hbuf_wss)),
				sofia_cfg.wssbindport);
		}

		/* Cert-dir resolution + sofia-name aliasing (external cert-manager integration).
		 * sofia-sip opens FIXED filenames inside a cert DIRECTORY (NUTAG_CERTIFICATE_DIR):
		 * agent.pem + cafile.pem for TLS (tport_type_tls.c:226-233); wss.pem, or
		 * wss.key+wss.crt + ca-bundle.crt, for WSS (tport_type_ws.c:357-376). An external cert
		 * manager names the real files differently (e.g. <host>.pem / gabpbx.pem / ca.crt), so:
		 *   - tlscertfile may be the cert DIR or the real cert+key FILE; cert_dir = its dirname when
		 *     it is a regular file, else tlscertfile as-is.
		 *   - when a sofia-expected name is missing in cert_dir, soft-link it to the real file the
		 *     operator configured (agent.pem -> tlscertfile, cafile.pem -> tlscafile), then derive the
		 *     WSS names from the TLS ones (wss.pem -> agent.pem, ca-bundle.crt -> cafile.pem).
		 * Idempotent; only creates a MISSING name, never renames/overwrites the manager's own files. */
		if (!ast_strlen_zero(sofia_cfg.tlscertfile)) {
			struct stat st;
			const char *real_cert = NULL;
			ast_copy_string(cert_dir, sofia_cfg.tlscertfile, sizeof(cert_dir));
			if (stat(sofia_cfg.tlscertfile, &st) == 0 && !S_ISDIR(st.st_mode)) {
				/* tlscertfile is the real cert FILE: agent.pem links to it; cert_dir = its dirname. */
				char *slash = strrchr(cert_dir, '/');
				real_cert = sofia_cfg.tlscertfile;
				if (slash == cert_dir) {
					cert_dir[1] = '\0';			/* file directly under "/" */
				} else if (slash) {
					*slash = '\0';
				} else {
					ast_copy_string(cert_dir, ".", sizeof(cert_dir));	/* bare filename -> CWD */
				}
			}

			/* Only materialize aliases when a cert-bearing listener is actually effective. */
			if (tls_url[0] || wss_url[0]) {
				char agent[600], cafile[600], wss_pem[600], ca_bundle[600];
				snprintf(agent,     sizeof(agent),     "%s/agent.pem",     cert_dir);
				snprintf(cafile,    sizeof(cafile),    "%s/cafile.pem",    cert_dir);
				snprintf(wss_pem,   sizeof(wss_pem),   "%s/wss.pem",       cert_dir);
				snprintf(ca_bundle, sizeof(ca_bundle), "%s/ca-bundle.crt", cert_dir);
				/* agent.pem -> the real cert+key file (only when tlscertfile named a file). */
				if (real_cert && access(agent, R_OK) != 0) {
					if (symlink(real_cert, agent) != 0) {
						ast_log(LOG_WARNING, "Sofia: could not soft-link %s -> %s (%s); TLS/WSS may be disabled\n",
							agent, real_cert, strerror(errno));
					} else {
						ast_log(LOG_NOTICE, "Sofia: soft-linked %s -> %s for sofia-sip\n", agent, real_cert);
					}
				}
				/* cafile.pem -> the real CA file (tlscafile). */
				if (!ast_strlen_zero(sofia_cfg.tlscafile) && access(cafile, R_OK) != 0) {
					if (symlink(sofia_cfg.tlscafile, cafile) != 0) {
						ast_log(LOG_WARNING, "Sofia: could not soft-link %s -> %s (%s); TLS verify/WSS may be disabled\n",
							cafile, sofia_cfg.tlscafile, strerror(errno));
					} else {
						ast_log(LOG_NOTICE, "Sofia: soft-linked %s -> %s for sofia-sip\n", cafile, sofia_cfg.tlscafile);
					}
				}
				/* WSS names from the TLS ones (only when the WSS listener is effective). */
				if (wss_url[0]) {
					if (access(wss_pem, R_OK) != 0 && access(agent, R_OK) == 0
							&& symlink(agent, wss_pem) != 0) {
						ast_log(LOG_WARNING, "Sofia: could not soft-link %s -> %s (%s); WSS may fail\n",
							wss_pem, agent, strerror(errno));
					}
					if (access(ca_bundle, R_OK) != 0 && access(cafile, R_OK) == 0
							&& symlink(cafile, ca_bundle) != 0) {
						ast_log(LOG_WARNING, "Sofia: could not soft-link %s -> %s (%s); WSS may fail\n",
							ca_bundle, cafile, strerror(errno));
					}
				}
			}
		}

		/* Cert-availability immunity (chan_sip.c:30207-30224 parity): a TLS/WSS listener whose
		 * certificate material is absent or unreadable makes sofia-sip's primary transport init
		 * return -1, so nua_create() returns NULL and the WHOLE driver fails to load (UDP
		 * included). Pre-validate the exact files sofia-sip will open under the resolved cert dir
		 * (cert_dir, passed as NUTAG_CERTIFICATE_DIR); if a secure listener has no
		 * usable cert, log an ERROR and DROP only that listener so UDP/TCP/WS keep serving. An
		 * empty tlscertfile is treated as "no cert" here (raw sofia-sip would fall back to
		 * $HOME/.sip/auth, never what an operator wants for a system service).
		 * TLS (tport_type_tls.c:226-233): key=agent.pem|tls.pem AND CA=cafile.pem|tls.pem.
		 * WSS (tport_type_ws.c:357-371): wss.pem, OR wss.key+wss.crt+ca-bundle.crt. */
		if (tls_url[0]) {
			const char *dir = cert_dir;
			char p[512];
			int key_ok = 0, ca_ok = 0;
			if (!ast_strlen_zero(dir)) {
				snprintf(p, sizeof(p), "%s/agent.pem", dir); key_ok = (access(p, R_OK) == 0);
				if (!key_ok) { snprintf(p, sizeof(p), "%s/tls.pem", dir); key_ok = (access(p, R_OK) == 0); }
				snprintf(p, sizeof(p), "%s/cafile.pem", dir); ca_ok = (access(p, R_OK) == 0);
				if (!ca_ok) { snprintf(p, sizeof(p), "%s/tls.pem", dir); ca_ok = (access(p, R_OK) == 0); }
			}
			if (!(key_ok && ca_ok)) {
				ast_log(LOG_ERROR, "Sofia: TLS listener configured (tlsbindport=%d) but no usable certificate in '%s' "
					"(need agent.pem or tls.pem, plus cafile.pem or tls.pem); disabling the TLS listener "
					"(set tlsenable=no to silence). UDP/TCP/WS keep serving.\n",
					sofia_cfg.tlsbindport, ast_strlen_zero(dir) ? "(tlscertfile unset)" : dir);
				tls_url[0] = '\0';
			}
		}
		if (wss_url[0]) {
			const char *dir = cert_dir;
			char p[512];
			int wss_ok = 0;
			if (!ast_strlen_zero(dir)) {
				snprintf(p, sizeof(p), "%s/wss.pem", dir);
				wss_ok = (access(p, R_OK) == 0);
				if (!wss_ok) {
					char k[512], c[512];
					snprintf(k, sizeof(k), "%s/wss.key", dir);
					snprintf(c, sizeof(c), "%s/wss.crt", dir);
					snprintf(p, sizeof(p), "%s/ca-bundle.crt", dir);
					wss_ok = (access(k, R_OK) == 0 && access(c, R_OK) == 0 && access(p, R_OK) == 0);
				}
			}
			if (!wss_ok) {
				ast_log(LOG_ERROR, "Sofia: WSS listener configured (wssbindport=%d) but no usable certificate in '%s' "
					"(need wss.pem, or wss.key+wss.crt+ca-bundle.crt); disabling the WSS listener "
					"(set wssenable=no to silence). UDP/TCP/WS keep serving.\n",
					sofia_cfg.wssbindport, ast_strlen_zero(dir) ? "(tlscertfile unset)" : dir);
				wss_url[0] = '\0';
			}
		}

		/* Recompute AFTER any degrade so NUTAG_CERTIFICATE_DIR + the TLS hardening tags are only
		 * applied when a cert-bearing listener actually survives. */
		needs_cert = (tls_url[0] || wss_url[0]);

		ast_debug(1, "Creating NUA: udp=%s tls=%s ws=%s wss=%s cert_dir=%s\n",
			udp_url, tls_url[0] ? tls_url : "(none)",
			ws_url[0] ? ws_url : "(none)",
			wss_url[0] ? wss_url : "(none)",
			needs_cert ? cert_dir : "(none)");

		/* Warn on pingpong-without-keepalive: it is silently ignored (pingpong is only
		 * applied alongside keepalive below). */
		if (sofia_cfg.tcp_pingpong_ms > 0 && sofia_cfg.tcp_keepalive_ms == 0) {
			ast_log(LOG_WARNING, "Sofia: tcp_pingpong is set but tcp_keepalive is 0 — pingpong needs "
				"keepalive to send the ping, so it is ignored. Set tcp_keepalive to enable both.\n");
		}

		/* mTLS: combine the per-direction verify flags into ONE policy bitmask — SUBJECTS_OUT for
		 * outbound server-cert checks (tlsverify), SUBJECTS_IN for inbound client-cert checks
		 * (tlsverifyclient); both -> SUBJECTS_ALL; 0 -> no verification (sofia default). TLS listener
		 * only (WSS builds its own SSL_CTX). */
		unsigned tls_verify_policy = (sofia_cfg.tlsverify ? TPTLS_VERIFY_SUBJECTS_OUT : 0)
			| (sofia_cfg.tlsverifyclient ? TPTLS_VERIFY_SUBJECTS_IN : 0);

		sofia_nua = nua_create(sofia_root,
			sofia_event_callback,
			NULL,
			NUTAG_URL(udp_url),
			TAG_IF(tls_url[0], NUTAG_SIPS_URL(tls_url)),
			TAG_IF(ws_url[0],  NUTAG_WS_URL(ws_url)),
			TAG_IF(wss_url[0], NUTAG_WSS_URL(wss_url)),
			TAG_IF(needs_cert && !ast_strlen_zero(cert_dir),
				NUTAG_CERTIFICATE_DIR(cert_dir)),
			/* Opt-in peer-cert verification (default OFF = sofia-sip TPTLS_VERIFY_NONE).
			 * tlsverify=yes verifies the outbound server cert chain+subject+date against
			 * tlscertfile — closes the accept-any-cert MITM hole on the outbound TLS transport
			 * (WSS builds its own SSL_CTX and is not governed by these TPTAG_TLS_* knobs). */
			/* Combined TLS verify policy: tlsverify -> verify the SERVER cert (outbound,
			 * SUBJECTS_OUT); tlsverifyclient -> verify the CLIENT cert (inbound mTLS, SUBJECTS_IN);
			 * both -> SUBJECTS_ALL. One bitmask (the flags ORed in tls_verify_policy above). */
			TAG_IF(needs_cert && tls_verify_policy,
				TPTAG_TLS_VERIFY_POLICY(tls_verify_policy)),
			TAG_IF(needs_cert && tls_verify_policy,
				TPTAG_TLS_VERIFY_DATE(1)),
			/* TLS-listener hardening (opt-in; TLS listener only — WSS builds its own
			 * SSL_CTX). Each applied only when set, so an unset knob keeps the default. */
			TAG_IF(needs_cert && !ast_strlen_zero(sofia_cfg.tls_ciphers),
				TPTAG_TLS_CIPHERS(sofia_cfg.tls_ciphers)),
			TAG_IF(needs_cert && !ast_strlen_zero(sofia_cfg.tls_min_version),
				TPTAG_TLS_VERSION(sofia_tls_min_version_mask(sofia_cfg.tls_min_version))),
			TAG_IF(needs_cert && sofia_cfg.tls_verify_depth > 0,
				TPTAG_TLS_VERIFY_DEPTH((unsigned)sofia_cfg.tls_verify_depth)),
			NUTAG_MEDIA_ENABLE(0),
			NUTAG_ALLOW("INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, REFER, MESSAGE, INFO, PRACK, UPDATE"),
			NUTAG_APPL_METHOD("REGISTER"),
			NUTAG_ALLOW_EVENTS("presence"),
			NUTAG_ALLOW_EVENTS("dialog"),
			NUTAG_ALLOW_EVENTS("message-summary"),
			NUTAG_ALLOW_EVENTS("refer"),
			NUTAG_ALLOW_EVENTS("presence.winfo"),
			NUTAG_M_USERNAME("*"),
			SIPTAG_EXPIRES_STR("3600"),
			/* timert1 (RFC 3261 §17.1.1.1): T1 retransmission interval (ms), global.
			 * From default_timer_t1 (500ms), NOT t1min (the per-peer parser floor). */
			NTATAG_SIP_T1(sofia_cfg.default_timer_t1),
			/* timerb (RFC 3261 §17.1.1.2): caps the INVITE transaction timeout. */
			TAG_IF(sofia_cfg.default_timer_b,
				NTATAG_SIP_T1X64(sofia_cfg.default_timer_b)),
			/* RFC 3581 / force_rport (always): the NTA stamps rport=<actual source port> onto every
			 * inbound request Via and routes the response there, even when the UA omits ;rport.
			 * Without it (sofia default sa_server_rport=1 = honor only if present) a NAT'd UA that
			 * sends no rport gets its 401/200 routed to the Via sent-by port instead of the
			 * NAT-mapped source, so it never registers. Stamping rport before chan_sofia reads the
			 * message also makes sofia_get_source_addr learn the real source, fixing contact
			 * src_addr / NAT routing. Global is correct (source == Via for a non-NAT UA) and is
			 * standard SIP-server behaviour; per-peer cannot affect the first 401 (sent before the
			 * peer config is consulted). */
			NTATAG_SERVER_RPORT(2),
			/* tos/cos: SIP-listener TOS via setsockopt. */
			TAG_IF(sofia_cfg.tos_sip, TPTAG_TOS((int)sofia_cfg.tos_sip)),
			/* App-level keepalive: TPTAG_KEEPALIVE sends a periodic CRLF on an idle
			 * connection-oriented transport to hold the NAT binding (TCP-only — TLS/WS
			 * vtables ignore it). TPTAG_PINGPONG marks the connection dead if no pong
			 * follows. Both default OFF (opt-in, seconds). */
			TAG_IF(sofia_cfg.tcp_keepalive_ms > 0, TPTAG_KEEPALIVE((unsigned)sofia_cfg.tcp_keepalive_ms)),
			/* pingpong needs keepalive (no ping -> no pong), so applied only alongside it. */
			TAG_IF(sofia_cfg.tcp_keepalive_ms > 0 && sofia_cfg.tcp_pingpong_ms > 0,
				TPTAG_PINGPONG((unsigned)sofia_cfg.tcp_pingpong_ms)),
			/* useragent: installs the User-Agent + Server header value. Empty default
			 * skips the tag (sofia-sip falls back to its own). */
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
		NUTAG_ALLOW("INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, REFER, MESSAGE, INFO, PRACK, UPDATE"),
		TAG_END());

	/* Add methods to appl_method one at a time */
	nua_set_params(sofia_nua, NUTAG_APPL_METHOD("REGISTER"), TAG_END());
	nua_set_params(sofia_nua, NUTAG_APPL_METHOD("SUBSCRIBE"), TAG_END());
	/* PUBLISH is NOT APPL_METHOD'd — no RFC 3903 server here, so the stack rejects an
	 * inbound PUBLISH (405/501) rather than a stub leaking a 200 OK + un-reaped handle. */
	nua_set_params(sofia_nua, NUTAG_APPL_METHOD("NOTIFY"), TAG_END());
	nua_set_params(sofia_nua, NUTAG_APPL_METHOD("INFO"), TAG_END());
	/* UPDATE (RFC 3311): APPL_METHOD so the stack delivers nua_i_update to us. With MEDIA_ENABLE(0)
	 * (no soa) the stack cannot run the UPDATE offer/answer, so chan_sofia owns the SDP (sofia_process_update). */
	nua_set_params(sofia_nua, NUTAG_APPL_METHOD("UPDATE"), TAG_END());
	nua_set_params(sofia_nua, NUTAG_APPL_METHOD("REFER"), TAG_END());
	/* MESSAGE (RFC 3428): APPL_METHOD so chan_sofia owns the FINAL response (401 challenge / native relay
	 * 202-480 / dialplan) — without it the stack auto-answers 200 OK before our app can challenge or relay. */
	nua_set_params(sofia_nua, NUTAG_APPL_METHOD("MESSAGE"), TAG_END());

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

	/* Apply the SIP-capture config (HEP stream + file dump). MUST be DEFERRED into the running su_root loop:
	 * applying it here (before su_root_run below) sets the param but never opens the capture socket/dump FILE*
	 * (the tports are not serviced until the loop runs), so config-driven capture did nothing at boot until a
	 * CLI re-arm. A short one-shot su_timer fires it inside su_root_run. (`sip reload` + the CLI subcommands
	 * already run with the loop live, so they apply directly.) */
	sofia_capture_apply_timer = su_timer_create(su_root_task(sofia_root), 500);
	if (sofia_capture_apply_timer) {
		if (su_timer_set(sofia_capture_apply_timer, sofia_capture_apply_deferred, NULL) < 0) {
			su_timer_destroy(sofia_capture_apply_timer);
			sofia_capture_apply_timer = NULL;
			sofia_apply_capture();	/* fallback: a possibly-early apply beats none */
		}
	} else {
		sofia_apply_capture();	/* fallback */
	}

	/* Presence/BLF expiry sweep (su_timer on THIS sofia_thread): sofia-sip does not
	 * auto-expire nua_respond()-accepted subs, so we tear down stale watchers ourselves. */
	sofia_presence_start();

	/* Outbound PUBLISH (RFC 3903) STARTUP pass on sofia_thread: create a publication per
	 * publish=yes peer (scheduled, not inline) + arm the ~1 Hz emission sweep. OFF unless
	 * publish_server is set. A later `sip reload` reconciles via
	 * sofia_publications_reconcile (no restart needed for PUBLISH config). */
	sofia_publications_start();

	/* Outbound MWI SUBSCRIBE (a watcher) STARTUP pass on sofia_thread: subscribe each
	 * mwi_subscribe= static-host peer for Event: message-summary. register=> trunks also
	 * (re)start via sofia_subscribe_on_registered after their REGISTER 200. A later
	 * `sip reload` reconciles via sofia_subscribe_reconcile. */
	sofia_subscribe_start();
	sofia_eventsub_start();

	sofia_regflow_shutdown = 0;	/* RFC 5626 flow-close: the root is live for the duration of su_root_run */
	su_root_run(sofia_root);

	/* RFC 5626 flow-close: the root is stopping — mark it so any off-thread contact destructor does not
	 * dispatch a handle-destroy to a dead root, then clear every retained reg_nh reachable from `peers`
	 * (nua_destroy below reaps the handles). */
	sofia_regflow_shutdown = 1;
	sofia_regflow_teardown_all();

	/* Async timing-equalized rejects: cancel + destroy every still-pending one-shot
	 * timer and free its ctx (dropping the pinned nua_handle ref) BEFORE nua_destroy /
	 * su_root_destroy below, so a firing timer can never deref freed code or a destroyed
	 * handle. Runs on THIS thread (the su_root task), matching the timer's fire thread. */
	sofia_delay_reject_shutdown();

	sofia_presence_stop();

	/* Outbound PUBLISH teardown (sofia_thread, after the loop ends). */
	sofia_publications_stop();
	sofia_history_destroy();

	/* Outbound MWI SUBSCRIBE watcher teardown (sofia_thread, before nua_destroy). */
	sofia_subscribe_stop();
	sofia_eventsub_stop();

	/* Ownership-correct teardown — su_root_destroy MUST run on the creating thread
	 * (sofia-sip asserts; cross-thread aborts). unload_module signals us via
	 * nua_shutdown + su_root_break + pthread_join. Order: nua_destroy, su_root_destroy,
	 * su_deinit (paired with su_init() above). */
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
			/* Snapshot under pvt->lock, then release before the blocking ast_cli.
			 * callid/peername are stringfields other threads reassign under the lock.
			 * Session-Timer column = seconds-since-refresh / negotiated Session-Expires
			 * (or (none)). */
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

/* `sip show channel <call-id-prefix>` — detailed state for ONE active channel (chan_sip parity).
 * Prefix-match the Call-ID, snapshot all fields under pvt->lock, emit after the lock drops. */
static char *sofia_cli_show_channel(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct sofia_pvt *pvt;
	struct ao2_iterator i;
	char callid[256] = "", peer[256] = "", user[256] = "", fromu[256] = "", fromd[256] = "", ruri[256] = "";
	int st = -1, outgoing = 0, has_rtp = 0, has_vrtp = 0, t38 = 0, hold = 0, has_srtp = 0, sess_exp = 0, found = 0;
	const char *state_str;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show channel";
		e->usage = "Usage: sip show channel <call-id-prefix>\n"
			   "       Show detailed state for one active Sofia-SIP channel (Call-ID prefix match).\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;	/* Call-IDs are dynamic — no completion in v1 */
	}
	if (a->argc != 4) {
		return CLI_SHOWUSAGE;
	}
	if (!dialogs) {
		ast_cli(a->fd, "No active channels.\n");
		return CLI_SUCCESS;
	}
	i = ao2_iterator_init(dialogs, 0);
	while (!found && (pvt = ao2_iterator_next(&i))) {
		ast_mutex_lock(&pvt->lock);
		if (!ast_strlen_zero(pvt->callid)
				&& !strncasecmp(pvt->callid, a->argv[3], strlen(a->argv[3]))) {
			ast_copy_string(callid, S_OR(pvt->callid, ""), sizeof(callid));
			ast_copy_string(peer, S_OR(pvt->peername, ""), sizeof(peer));
			ast_copy_string(user, S_OR(pvt->username, ""), sizeof(user));
			ast_copy_string(fromu, S_OR(pvt->fromuser, ""), sizeof(fromu));
			ast_copy_string(fromd, S_OR(pvt->fromdomain, ""), sizeof(fromd));
			ast_copy_string(ruri, S_OR(pvt->ruri, ""), sizeof(ruri));
			st = pvt->state;
			outgoing = pvt->outgoing;
			has_rtp = !!pvt->rtp;
			has_vrtp = !!pvt->vrtp;
			has_srtp = !!pvt->srtp;
			t38 = pvt->t38_state;
			hold = pvt->hold_state;
			sess_exp = pvt->session_negotiated_expires;
			found = 1;
		}
		ast_mutex_unlock(&pvt->lock);
		ao2_ref(pvt, -1);
	}
	ao2_iterator_destroy(&i);

	if (!found) {
		ast_cli(a->fd, "No active channel with Call-ID prefix '%s'.\n", a->argv[3]);
		return CLI_SUCCESS;
	}
	switch (st) {
	case SOFIA_DIALOG_STATE_DOWN: state_str = "Down"; break;
	case SOFIA_DIALOG_STATE_TRYING: state_str = "Trying"; break;
	case SOFIA_DIALOG_STATE_RINGING: state_str = "Ringing"; break;
	case SOFIA_DIALOG_STATE_UP: state_str = "Up"; break;
	default: state_str = "Unknown"; break;
	}
	ast_cli(a->fd, "  Call-ID       : %s\n", callid);
	ast_cli(a->fd, "  Peer          : %s\n", peer);
	ast_cli(a->fd, "  Username      : %s\n", user);
	ast_cli(a->fd, "  From          : %s@%s\n", fromu, fromd);
	ast_cli(a->fd, "  Request-URI   : %s\n", ruri);
	ast_cli(a->fd, "  State         : %s\n", state_str);
	ast_cli(a->fd, "  Direction     : %s\n", outgoing ? "outbound" : "inbound");
	ast_cli(a->fd, "  Audio RTP     : %s\n", has_rtp ? "yes" : "no");
	ast_cli(a->fd, "  Video RTP     : %s\n", has_vrtp ? "yes" : "no");
	ast_cli(a->fd, "  SRTP          : %s\n", has_srtp ? "yes" : "no");
	ast_cli(a->fd, "  On hold       : %s\n", hold ? "yes" : "no");
	ast_cli(a->fd, "  T.38 state    : %d\n", t38);
	if (sess_exp > 0) {
		ast_cli(a->fd, "  Session-Timer : %ds\n", sess_exp);
	}
	return CLI_SUCCESS;
}

/* `sip show channelstats` — per-channel audio RTP stats (chan_sip parity). The dialog iterator holds a
 * +1 ref on each pvt while reading, so the pvt stays alive; pvt->rtp is only destroyed/replaced under
 * pvt->lock (fork-winner promotion) or freed in the pvt destructor, so reading it here under pvt->lock is
 * safe; ast_rtp_instance_get_stats is called under pvt->lock with lock order pvt->rtp, matching
 * the read path channel->pvt->rtp. Fork children are skipped, as in show channels. */
static char *sofia_cli_show_channelstats(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct sofia_pvt *pvt;
	struct ao2_iterator i;
	int count = 0;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show channelstats";
		e->usage = "Usage: sip show channelstats\n"
			   "       Per-channel audio RTP statistics (tx/rx packets, loss, jitter).\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}
	if (a->argc != 3) {
		return CLI_SHOWUSAGE;
	}
	ast_cli(a->fd, "%-40s %-16s %8s %8s %8s %8s %10s\n",
		"Call-ID", "Peer", "TxPkt", "RxPkt", "TxLost", "RxLost", "RxJitter");
	if (!dialogs) {
		return CLI_SUCCESS;
	}
	i = ao2_iterator_init(dialogs, 0);
	while ((pvt = ao2_iterator_next(&i))) {
		char callid[256] = "", peer[256] = "";
		struct ast_rtp_instance_stats stats;
		int have = 0;

		if (pvt->is_fork_child) {
			ao2_ref(pvt, -1);
			continue;
		}
		ast_mutex_lock(&pvt->lock);
		ast_copy_string(callid, S_OR(pvt->callid, ""), sizeof(callid));
		ast_copy_string(peer, S_OR(pvt->peername, ""), sizeof(peer));
		if (pvt->rtp && ast_rtp_instance_get_stats(pvt->rtp, &stats, AST_RTP_INSTANCE_STAT_ALL) == 0) {
			have = 1;
		}
		ast_mutex_unlock(&pvt->lock);
		if (have) {
			ast_cli(a->fd, "%-40s %-16s %8u %8u %8u %8u %10.3f\n",
				callid, peer, stats.txcount, stats.rxcount, stats.txploss, stats.rxploss,
				stats.rxjitter);
			count++;
		}
		ao2_ref(pvt, -1);
	}
	ao2_iterator_destroy(&i);
	ast_cli(a->fd, "%d channel%s with RTP\n", count, count != 1 ? "s" : "");
	return CLI_SUCCESS;
}



/* Peer-dump helpers: append into *out (assembled under peer->lock, emitted once after
 * the lock drops). All call sites live in sofia_cli_show_peer. */


/* Forward decl: peer-name tab-completion helper (defined later). only_realtime=0 =>
 * offer every peer. */


int sofia_debug_match(const char *peer_name, const char *src_ip)
{
	if (sofia_debug == 1)
		return 1;
	if (sofia_debug == 2 && peer_name && !strcasecmp(peer_name, sofia_debug_filter))
		return 1;
	if (sofia_debug == 3 && src_ip && !strcmp(src_ip, sofia_debug_filter))
		return 1;
	return 0;
}

/* sip show inuse (chan_sip parity): column format kept verbatim (operator scripts match
 * the alignment). Default shows call_limit>0; "all" shows every peer. Also includes
 * peers with busy_level/active counters > 0 (more inclusive than chan_sip). */

/* `sip show settings`: dump the global [general] config values. */



/* `sip reload` CLI alias (== `module reload chan_sofia.so`): both go through
 * sofia_reload_request_sync, which posts the work onto sofia_thread — eliminating the UAF
 * races on localha/contact_ha/peer->chanvars the old caller-thread model carried.
 * Listener-config changes are detected and refused. */

/* Peer-name tab-completion: return ast_strdup(peer->name) on the N-th prefix match for
 * state==N. only_realtime==1 matches realtime peers only. */


/* sip prune realtime (chan_sip parity): flush the cached realtime peer(s) so the next
 * access reloads from SQL. Single-container (chan_sofia has no peers_by_ip). */


/* `sip show registry`: list OUTBOUND trunk registrations (register => peers,
 * peer->is_register_line) + state. Snapshot each row UNDER peer->lock, then ast_cli (may block). */

/* `sip unregister <peer>` — force-expire a dynamic peer's INBOUND registration so it must re-register.
 * Doctrine exception: mutates registration state from the CLI thread (not sofia_thread); safe because the
 * writes are simple field/ao2 ops, peer->lock serializes vs the expiry sweep / REGISTER apply, and the
 * side-effects are deferred AFTER the unlock. LOCAL clear only (no de-REGISTER sent); realtime DB binding
 * untouched. */

/* `sip show hashstats` — ao2 hash-table usage + collision distribution for the chan_sofia
 * containers, so the live hash spread (buckets/load/maxchain/collisions/chi2) can be inspected
 * (e.g. to confirm the ast_str_hash distribution on real data). Read-only diagnostic:
 * ao2_container_stats() walks each container's buckets under its own lock when invoked. */
static char *sofia_cli_show_hashstats(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct {
		const char *name;
		struct ao2_container *c;
	} tbls[] = {
		{ "peers",        peers },
		{ "peers_by_ip",  peers_by_ipport },	/* B: the O(1) by-IP+port index */
		{ "dialogs",      dialogs },
		{ "blacklist",    sofia_blacklist_container() },
		{ "eventsub",     sofia_eventsub_container() },
		{ "publications", sofia_publications_container() },
		{ "presence",     sofia_presence_container() },
		{ "mwisubs",      sofia_mwisubs_container() },
	};
	int i;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show hashstats";
		e->usage =
			"Usage: sip show hashstats\n"
			"       Show chan_sofia ao2 hash-table usage and collision distribution:\n"
			"       buckets, entries, load factor, occupied buckets, longest chain,\n"
			"       collisions (entries-occupied), and chi2/df (~1.0 = ideal spread).\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	ast_cli(a->fd, "%-14s %8s %8s %7s %9s %9s %11s %8s\n",
		"Table", "buckets", "entries", "load", "occupied", "maxchain", "collisions", "chi2/df");
	for (i = 0; i < (int) ARRAY_LEN(tbls); i++) {
		struct ao2_container_stats st;

		if (!tbls[i].c) {
			ast_cli(a->fd, "%-14s %8s\n", tbls[i].name, "(inactive)");
			continue;
		}
		ao2_container_stats(tbls[i].c, &st);
		ast_cli(a->fd, "%-14s %8d %8d %7.2f %9d %9d %11d %8.3f\n",
			tbls[i].name, st.n_buckets, st.elements, st.load,
			st.occupied, st.max_chain, st.collisions, st.chi2_df);
	}
	return CLI_SUCCESS;
}

static struct ast_cli_entry cli_sofia[] = {
	AST_CLI_DEFINE(sofia_cli_show_peers, "List Sofia-SIP peers"),
	AST_CLI_DEFINE(sofia_cli_show_hashstats, "Show ao2 hash-table usage and collisions"),
	AST_CLI_DEFINE(sofia_cli_show_registry, "List outbound SIP trunk registrations"),
	AST_CLI_DEFINE(sofia_cli_show_publications, "List outbound PUBLISH presentities"),
	AST_CLI_DEFINE(sofia_cli_unregister, "Force-expire a SIP peer's inbound registration"),
	AST_CLI_DEFINE(sofia_cli_qualify_peer, "Send an on-demand OPTIONS qualify to a peer"),
	AST_CLI_DEFINE(sofia_cli_notify, "Send a sip_notify.conf NOTIFY to peers"),
	AST_CLI_DEFINE(sofia_cli_show_channels, "List active Sofia-SIP channels"),
	AST_CLI_DEFINE(sofia_cli_show_channel, "Show one Sofia-SIP channel in detail"),
	AST_CLI_DEFINE(sofia_cli_show_channelstats, "Per-channel RTP statistics"),
	AST_CLI_DEFINE(sofia_cli_set_history, "Enable/disable per-call SIP history recording"),
	AST_CLI_DEFINE(sofia_cli_show_history, "Show a call's recorded SIP history"),
	AST_CLI_DEFINE(sofia_cli_clear_history, "Clear retained SIP call histories"),
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

	/* userpart@hostpart */
	hostpart = strchr(buf, '@');
	if (!hostpart) {
		ast_log(LOG_WARNING, "Sofia: Invalid register=> format (missing @): %s\n", value);
		return;
	}
	*hostpart++ = '\0';
	userpart = buf;

	/* user[:secret] */
	user = userpart;
	secret = strchr(userpart, ':');
	if (secret) {
		*secret++ = '\0';
	}

	/* host[:port] */
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

	/* Find-or-alloc (ao2_link never dedups), else each reload re-parsing this line would link a
	 * duplicate same-name struct. */
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
				/* OOM — drain MWI before the destructor (normally a no-op for register=> peers). */
				sofia_peer_drain_mwi(peer);
			} else {
				ast_verbose("Sofia: register=> peer '%s' created (target %s:%d)\n",
					user, host, port);
				sofia_peer_ipport_reindex(peer);	/* B: index by host:port (parity with the O(N) scan) */
			}
		} else {
			sofia_peer_ipport_reindex(peer);	/* B: existing register-line peer re-keyed after a reload target change */
		}
		ao2_ref(peer, -1);
	}
}

/* Parse a SECONDS config value to ms, overflow-safe. 0 (OFF) on empty/non-numeric/<= 0; caps at 86400s
 * (1 day) so * 1000 can't overflow int. Shared by the live parser + the reload-listener-change detector. */
static int sofia_cfg_seconds_to_ms(const char *val)
{
	char *end;
	long s;

	if (ast_strlen_zero(val)) {
		return 0;
	}
	/* strtol so overflow is caught via errno and trailing garbage via endptr. */
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

/* Strict parse for tls_verify_depth; overflow/garbage/non-positive -> 0 (sofia default); caps at 100. */
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

/* Map a validated "1.0".."1.3" min-TLS-version to a TPTAG_TLS_VERSION enable-bitmask (that protocol +
 * every higher one). TLS1.3 is never in tport_tls.c's disable list, so "1.3" -> 0. GOTCHA: 0 also means
 * "unset" — callers MUST gate on the source string being non-empty. */
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
	/* "1.0" (and defensively anything else) -> TLS1.0/1.1/1.2 all enabled. */
	return TPTLS_VERSION_TLSv1 | TPTLS_VERSION_TLSv1_1 | TPTLS_VERSION_TLSv1_2;
}

static void sofia_parse_general_config(struct ast_config *cfg)
{
	struct ast_variable *v;

	for (v = ast_variable_browse(cfg, "general"); v; v = v->next) {
		if (!strcasecmp(v->name, "bindaddr")) {
			ast_copy_string(sofia_cfg.bindaddr, v->value, sizeof(sofia_cfg.bindaddr));
		} else if (!strcasecmp(v->name, "bindport") || !strcasecmp(v->name, "udpbindaddr")) {
			/* IPv6-aware host:port split on a LOCAL copy — never mutate v->value, don't truncate
			 * a bracketed [2001:db8::1]:5060 at its first colon. */
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
		} else if (!strcasecmp(v->name, "tlsenable")) {
			/* Explicit opt-out for the TLS listener; honored even when tlsbindport>0 (chan_sip parity,
			 * chan_sip.c:120). Default ON in the compiled defaults above. */
			sofia_cfg.tls_enable = ast_true(v->value);
		} else if (!strcasecmp(v->name, "blacklist_ban")) {
			/* Minutes an offending IP stays blocked / its failure counter is remembered (fail2ban
			 * model); 0 = disable banning entirely. Default 24h. Applied live on `sofia reload`. */
			sofia_blacklist_set_ban_minutes(atoi(v->value));
		} else if (!strcasecmp(v->name, "tlscertfile") || !strcasecmp(v->name, "tlscertdir")) {
			ast_copy_string(sofia_cfg.tlscertfile, v->value, sizeof(sofia_cfg.tlscertfile));
		} else if (!strcasecmp(v->name, "tlscafile")) {
			/* Optional real CA file; soft-linked to <certdir>/cafile.pem at NUA create so sofia-sip
			 * (which opens the fixed name cafile.pem) finds it without renaming cert-server files. */
			ast_copy_string(sofia_cfg.tlscafile, v->value, sizeof(sofia_cfg.tlscafile));
		} else if (!strcasecmp(v->name, "tlsverify") || !strcasecmp(v->name, "tlsverifyserver")) {
			/* Opt-in TLS peer-cert verification (default OFF): validate the server cert chain +
			 * subject against the configured CA material (tlscertfile dir). */
			sofia_cfg.tlsverify = ast_true(v->value);
		} else if (!strcasecmp(v->name, "tlsverifyclient")) {
			/* mutual TLS: verify the CLIENT cert on the inbound TLS listener (opt-in). */
			sofia_cfg.tlsverifyclient = ast_true(v->value);
		} else if (!strcasecmp(v->name, "tls_ciphers")) {
			/* OpenSSL cipher list for the TLS listener (TPTAG_TLS_CIPHERS). */
			ast_copy_string(sofia_cfg.tls_ciphers, v->value, sizeof(sofia_cfg.tls_ciphers));
		} else if (!strcasecmp(v->name, "tls_min_version")) {
			/* Min TLS version 1.0/1.1/1.2/1.3; unrecognized warns + leaves unset (else it would
			 * silently map to bitmask 0). */
			if (sofia_tls_min_version_valid(v->value)) {
				ast_copy_string(sofia_cfg.tls_min_version, v->value, sizeof(sofia_cfg.tls_min_version));
			} else {
				ast_log(LOG_WARNING, "Sofia: ignoring tls_min_version='%s' (expected 1.0, 1.1, 1.2 or 1.3)\n",
					v->value);
			}
		} else if (!strcasecmp(v->name, "tls_verify_depth")) {
			/* Max cert-chain depth (TPTAG_TLS_VERIFY_DEPTH); 0/invalid -> sofia default + warn. */
			sofia_cfg.tls_verify_depth = sofia_cfg_verify_depth(v->value);
			if (!ast_strlen_zero(v->value) && sofia_cfg.tls_verify_depth == 0) {
				ast_log(LOG_WARNING, "Sofia: ignoring tls_verify_depth='%s' (expected a positive integer)\n",
					v->value);
			}
		} else if (!strcasecmp(v->name, "publish_server")) {
			/* outbound PUBLISH (RFC 3903): central ESC URI; empty = feature OFF. */
			ast_copy_string(sofia_cfg.publish_server, v->value, sizeof(sofia_cfg.publish_server));
		} else if (!strcasecmp(v->name, "publish_expires")) {
			char *end;
			long e;
			errno = 0;
			e = strtol(v->value, &end, 10);
			if (errno != 0 || end == v->value || *end != '\0' || e <= 0) {
				sofia_cfg.publish_expires = 0;	/* default applied at use */
			} else {
				sofia_cfg.publish_expires = (e > SOFIA_PUBLISH_MAX_EXPIRES) ? SOFIA_PUBLISH_MAX_EXPIRES : (int) e;
			}
		} else if (!strcasecmp(v->name, "publish_domain")) {
			ast_copy_string(sofia_cfg.publish_domain, v->value, sizeof(sofia_cfg.publish_domain));
		} else if (!strcasecmp(v->name, "publish_username")) {
			ast_copy_string(sofia_cfg.publish_username, v->value, sizeof(sofia_cfg.publish_username));
		} else if (!strcasecmp(v->name, "publish_password")) {
			ast_copy_string(sofia_cfg.publish_password, v->value, sizeof(sofia_cfg.publish_password));
		} else if (!strcasecmp(v->name, "publish_format")) {
			/* Outbound PUBLISH body format: dialog-info (RFC 4235, default) or pidf (RFC 3863 presence). */
			if (!strcasecmp(v->value, "pidf")) {
				sofia_cfg.publish_format = SOFIA_SUB_PIDF;
			} else if (!strcasecmp(v->value, "dialog-info") || !strcasecmp(v->value, "dialog")) {
				sofia_cfg.publish_format = SOFIA_SUB_DIALOG_INFO;
			} else {
				ast_log(LOG_WARNING, "Sofia: invalid publish_format '%s' (use dialog-info|pidf); keeping dialog-info\n",
					v->value);
				sofia_cfg.publish_format = SOFIA_SUB_DIALOG_INFO;
			}
		} else if (!strcasecmp(v->name, "publish_transport")) {
			/* ;transport= appended to the PUBLISH R-URI so a tls/tcp/ws/wss ESC is reached over that
			 * transport (sofia-sip otherwise defaults a bare sip:exten@host:port R-URI to UDP). Validate
			 * against the same tokens as a peer's transport=; invalid -> udp + warn. udp = no-op.
			 * Whitespace-trimmed for immunity (" tls" must not silently downgrade to udp). */
			char ptbuf[16], *pt;
			ast_copy_string(ptbuf, v->value, sizeof(ptbuf));
			pt = ast_strip(ptbuf);
			if (!strcasecmp(pt, "udp") || !strcasecmp(pt, "tcp")
					|| !strcasecmp(pt, "tls") || !strcasecmp(pt, "ws")
					|| !strcasecmp(pt, "wss")) {
				ast_copy_string(sofia_cfg.publish_transport, pt, sizeof(sofia_cfg.publish_transport));
			} else {
				ast_log(LOG_WARNING, "Sofia: invalid publish_transport '%s' (use udp|tcp|tls|ws|wss); using udp\n",
					v->value);
				ast_copy_string(sofia_cfg.publish_transport, "udp", sizeof(sofia_cfg.publish_transport));
			}
		} else if (!strcasecmp(v->name, "wsbindaddr")) {
			ast_copy_string(sofia_cfg.wsbindaddr, v->value, sizeof(sofia_cfg.wsbindaddr));
		} else if (!strcasecmp(v->name, "wsbindport")) {
			sofia_cfg.wsbindport = atoi(v->value);
		} else if (!strcasecmp(v->name, "wsenable")) {
			/* Explicit opt-out for the plaintext WS listener (honored even when wsbindport>0). */
			sofia_cfg.ws_enable = ast_true(v->value);
		} else if (!strcasecmp(v->name, "wssbindaddr")) {
			ast_copy_string(sofia_cfg.wssbindaddr, v->value, sizeof(sofia_cfg.wssbindaddr));
		} else if (!strcasecmp(v->name, "wssbindport")) {
			sofia_cfg.wssbindport = atoi(v->value);
		} else if (!strcasecmp(v->name, "wssenable")) {
			/* Explicit opt-out for the secure WSS listener (honored even when wssbindport>0). */
			sofia_cfg.wss_enable = ast_true(v->value);
		} else if (!strcasecmp(v->name, "context")) {
			ast_copy_string(sofia_cfg.context, v->value, sizeof(sofia_cfg.context));
		} else if (!strcasecmp(v->name, "realm")) {
			ast_copy_string(sofia_cfg.realm, v->value, sizeof(sofia_cfg.realm));
		} else if (!strcasecmp(v->name, "callerid")) {
			/* [general] callerid = default outbound From identity (chan_sip default_callerid parity,
			 * chan_sip.c:29766-29767) used only when no channel/peer/fromuser caller-ID resolves. */
			ast_copy_string(sofia_cfg.default_callerid, v->value, sizeof(sofia_cfg.default_callerid));
		} else if (!strcasecmp(v->name, "tcp_keepalive")) {
			/* CRLF keepalive SECONDS (chan_sip parity) -> ms for TPTAG_KEEPALIVE; 0 -> OFF. */
			sofia_cfg.tcp_keepalive_ms = sofia_cfg_seconds_to_ms(v->value);
		} else if (!strcasecmp(v->name, "tcp_pingpong")) {
			/* pong-timeout SECONDS -> ms for TPTAG_PINGPONG; 0 -> OFF. */
			sofia_cfg.tcp_pingpong_ms = sofia_cfg_seconds_to_ms(v->value);
		} else if (!strcasecmp(v->name, "useragent")) {
			/* User-Agent override (chan_sip parity); empty ALLOWED — the implementation skips
			 * SIPTAG_USER_AGENT_STR so sofia-sip uses its library default. */
			ast_copy_string(sofia_cfg.useragent, v->value, sizeof(sofia_cfg.useragent));
			ast_debug(1, "Sofia: Setting SIP channel User-Agent to %s\n", sofia_cfg.useragent);
		} else if (!strcasecmp(v->name, "allowguest")) {
			sofia_cfg.allowguest = ast_true(v->value);
		} else if (!strcasecmp(v->name, "busy_on_active")) {
			sofia_cfg.busy_on_active = ast_true(v->value);
		} else if (!strcasecmp(v->name, "nat")) {
			/* [general] nat default inherited by peers without their own nat= (chan_sip parity).
			 * force_rport is SIP-response routing only (RFC 3581); media symmetric is comedia-only. */
			sofia_cfg.default_nat = sofia_parse_nat(v->value);
		} else if (!strcasecmp(v->name, "max_contacts")) {
			sofia_cfg.max_contacts = sofia_clamp_max_contacts(atoi(v->value), "general");
		} else if (!strcasecmp(v->name, "encryption")) {
			sofia_cfg.encryption = ast_true(v->value);
		} else if (!strcasecmp(v->name, "webrtc")) {
			sofia_cfg.webrtc = ast_true(v->value);	/* WebRTC general default */
		} else if (!strcasecmp(v->name, "datachannel")) {
			sofia_cfg.datachannel = ast_true(v->value);	/* WebRTC DataChannel general default; per-peer datachannel= overrides */
		} else if (!strcasecmp(v->name, "webrtc_video_bundle")) {
			sofia_cfg.webrtc_video_bundle = ast_true(v->value);	/* WebRTC video BUNDLE general default; per-peer webrtc_video_bundle= overrides */
		} else if (!strcasecmp(v->name, "flowclose_emit_unregister")) {
			sofia_cfg.flowclose_emit_unregister = ast_true(v->value);	/* RFC 5626 flow-close general default; per-peer overrides */
		} else if (!strcasecmp(v->name, "sip_capture_address")) {
			/* Live SIP trace: HOST:PORT of a Homer/sipcapture (HEP) server; empty = OFF. UDP only.
			 * Applied to the tport layer via TPTAG_CAPT once the NUA agent is up (sofia_apply_capture). */
			ast_copy_string(sofia_cfg.sip_capture_address, v->value, sizeof(sofia_cfg.sip_capture_address));
		} else if (!strcasecmp(v->name, "sip_capture_hep")) {
			int hv = atoi(v->value);
			if (hv < 1 || hv > 3) {
				ast_log(LOG_WARNING, "Sofia: invalid sip_capture_hep '%s' (use 1|2|3); using 3\n", v->value);
				hv = 3;
			}
			sofia_cfg.sip_capture_hep = hv;
		} else if (!strcasecmp(v->name, "sip_capture_id")) {
			sofia_cfg.sip_capture_id = atoi(v->value);
		} else if (!strcasecmp(v->name, "sip_capture_file")) {
			/* Append every DECRYPTED SIP message to this file (TPTAG_DUMP); empty = OFF. */
			ast_copy_string(sofia_cfg.sip_capture_file, v->value, sizeof(sofia_cfg.sip_capture_file));
		} else if (!strcasecmp(v->name, "default_srtpcipher") || !strcasecmp(v->name, "srtpcipher")) {
			/* Default SRTP cipher list inherited by sofia_peer_alloc; both spellings accepted. */
			ast_copy_string(sofia_cfg.default_srtpcipher, v->value, sizeof(sofia_cfg.default_srtpcipher));
		} else if (!strcasecmp(v->name, "srtp_per_suite_keys")) {
			/* Offer a distinct key per crypto suite (no chan_sip equivalent). [general]-only.
			 * Default 0 = shared-key mode. */
			sofia_cfg.srtp_per_suite_keys = ast_true(v->value);
			sofia_srtp_per_suite_keys = sofia_cfg.srtp_per_suite_keys;
		} else if (!strcasecmp(v->name, "force_invite_auth")) {
			/* Require digest auth on ALL inbound INVITEs, ignoring per-peer insecure=invite.
			 * Security-lockdown switch (no chan_sip equivalent). [general]-only. */
			sofia_cfg.force_invite_auth = ast_true(v->value);
		} else if (!strcasecmp(v->name, "nonce_ttl_seconds")) {
			/* Nonce staleness TTL; default 3600s. Invalid -> SOFIA_NONCE_TTL_SEC_DEFAULT + warn. */
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
			/* Digest algorithm(s) OFFERED in WWW-Authenticate: both (MD5+SHA-256) / md5 / sha256.
			 * Verification accepts exactly what was offered (anti-downgrade). Invalid -> both + warn. */
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
		} else if (!strcasecmp(v->name, "auth_qop")) {
			/* no (default) = chan_sip legacy no-qop MD5 challenge (RFC 2069, no nc/cnonce replay
			 * protection); yes = RFC 2617/7616 qop="auth". MD5 challenge form only; SHA-256 keeps qop. */
			sofia_cfg.auth_qop = ast_true(v->value);
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
			/* Default presentation for peers that omit callingpres=. */
			sofia_cfg.default_callingpres = sofia_parse_callingpres(v->value);
		} else if (!strcasecmp(v->name, "sendrpid")) {
			sofia_cfg.default_sendrpid = sofia_parse_sendrpid(v->value);
		} else if (!strcasecmp(v->name, "trustrpid")) {
			sofia_cfg.default_trustrpid = ast_true(v->value);
		} else if (!strcasecmp(v->name, "callcounter")) {
			sofia_cfg.default_call_limit = ast_true(v->value) ? INT_MAX : 0;
		} else if (!strcasecmp(v->name, "call-limit") || !strcasecmp(v->name, "call_limit")) {
			sofia_cfg.default_call_limit = atoi(v->value);
			if (sofia_cfg.default_call_limit < 0) sofia_cfg.default_call_limit = 0;
		} else if (!strcasecmp(v->name, "busylevel")) {
			sofia_cfg.default_busy_level = atoi(v->value);
			if (sofia_cfg.default_busy_level < 0) sofia_cfg.default_busy_level = 0;
		} else if (!strcasecmp(v->name, "default_allowtransfer") || !strcasecmp(v->name, "allowtransfer")) {
			/* Default REFER policy inherited by sofia_peer_alloc; both spellings accepted. */
			sofia_cfg.default_allowtransfer = ast_true(v->value) ? TRANSFER_OPENFORALL : TRANSFER_CLOSED;
		} else if (!strcasecmp(v->name, "allowsubscribe")) {
			/* Per-peer inheritance default (chan_sip parity, default TRUE). The derived global
			 * ban-all flag is computed by sofia_post_config_derive_allowsubscribe. */
			sofia_cfg.default_allowsubscribe = ast_true(v->value);
		} else if (!strcasecmp(v->name, "regcontext")) {
			/* Master switch — empty disables register_peer_exten. Names the dialplan context for
			 * REGISTER-driven extension add/remove. (regcontext value changes need a restart.) */
			ast_copy_string(sofia_cfg.regcontext, v->value, sizeof(sofia_cfg.regcontext));
		} else if (!strcasecmp(v->name, "regextenonqualify")) {
			/* Couple regexten add/remove to qualify REACHABLE/UNREACHABLE transitions. Default FALSE. */
			sofia_cfg.regextenonqualify = ast_true(v->value);
		} else if (!strcasecmp(v->name, "subscribecontext")) {
			/* Default subscribecontext inherited by sofia_peer_alloc. KNOWN LIMITATION: per-site
			 * override at sofia_process_subscribe deferred (no SUBSCRIBE dialplan dispatch yet). */
			ast_copy_string(sofia_cfg.default_subscribecontext, v->value, sizeof(sofia_cfg.default_subscribecontext));
		} else if (!strcasecmp(v->name, "message_context")) {
			/* [general] default context for inbound out-of-dialog MESSAGE -> dialplan; empty = SIP SIMPLE messaging OFF. */
			ast_copy_string(sofia_cfg.message_context, v->value, sizeof(sofia_cfg.message_context));
		} else if (!strcasecmp(v->name, "message_autorelay")) {
			/* native peer-to-peer MESSAGE relay (hint -> registered contact); default on. */
			sofia_cfg.message_autorelay = ast_true(v->value);
		} else if (!strcasecmp(v->name, "maxexpiry") || !strcasecmp(v->name, "maxexpirey")) {
			/* Registration TTL bound + 423 Interval Too Brief; typo-tolerant dual-spelling. */
			sofia_cfg.max_expiry = atoi(v->value);
			if (sofia_cfg.max_expiry < 1) {
				sofia_cfg.max_expiry = DEFAULT_MAX_EXPIRY;
			}
		} else if (!strcasecmp(v->name, "minexpiry") || !strcasecmp(v->name, "minexpirey")) {
			/* Registration TTL bound; typo-tolerant dual-spelling. */
			sofia_cfg.min_expiry = atoi(v->value);
			if (sofia_cfg.min_expiry < 1) {
				sofia_cfg.min_expiry = DEFAULT_MIN_EXPIRY;
			}
		} else if (!strcasecmp(v->name, "defaultexpiry") || !strcasecmp(v->name, "defaultexpirey")) {
			/* Registration TTL bound; typo-tolerant dual-spelling. Also accepted per-peer at
			 * sofia_parse_peer_config (KNOWN DIVERGENCE from chan_sip [general]-only). */
			sofia_cfg.default_expiry = atoi(v->value);
			if (sofia_cfg.default_expiry < 1) {
				sofia_cfg.default_expiry = DEFAULT_DEFAULT_EXPIRY;
			}
		} else if (!strcasecmp(v->name, "usereqphone")) {
			/* Default inherited by sofia_peer_alloc — RFC 3966 ;user=phone for E.164 via PSTN. */
			sofia_cfg.default_usereqphone = ast_true(v->value);
		} else if (!strcasecmp(v->name, "maxforwards")) {
			/* Default inherited by sofia_peer_alloc; 1-255 bounds + clamp-to-default. */
			if (sscanf(v->value, "%30d", &sofia_cfg.default_max_forwards) != 1
				|| sofia_cfg.default_max_forwards < 1 || 255 < sofia_cfg.default_max_forwards) {
				ast_log(LOG_WARNING, "Sofia: '%s' is not a valid [general] maxforwards value — using default %d\n",
					v->value, DEFAULT_MAX_FORWARDS);
				sofia_cfg.default_max_forwards = DEFAULT_MAX_FORWARDS;
			}
		} else if (!strcasecmp(v->name, "t1min")) {
			/* RFC 3261 §17.1.1.2 T1 retry-timer minimum (ms). Defensive 10ms floor — below that
			 * causes retransmission storms (chan_sofia guard; chan_sip accepts any int). */
			int v_int = 0;
			if (sscanf(v->value, "%30d", &v_int) != 1 || v_int < 10) {
				ast_log(LOG_WARNING, "Sofia: '%s' is not a valid [general] t1min value (minimum 10ms) — using default %d\n",
					v->value, DEFAULT_T1MIN);
				sofia_cfg.t1min = DEFAULT_T1MIN;
			} else {
				sofia_cfg.t1min = v_int;
			}
		} else if (!strcasecmp(v->name, "relaxdtmf")) {
			/* DSP_DIGITMODE_RELAXDTMF toggle for poor-quality-line DTMF (relaxes threshold). */
			sofia_cfg.relaxdtmf = ast_true(v->value);
		} else if (!strcasecmp(v->name, "prematuremedia")) {
			/* INVERTED-SEMANTIC chan_sip quirk: yes -> filter ON -> 183 SUPPRESSED;
			 * no -> filter OFF -> 183 ALLOWED. Default TRUE. */
			sofia_cfg.prematuremediafilter = ast_true(v->value);
		} else if (!strcasecmp(v->name, "registertimeout")) {
			/* Scheduled-retry interval seconds; clamp-to-default if < 1. */
			sofia_cfg.register_timeout = atoi(v->value);
			if (sofia_cfg.register_timeout < 1) {
				sofia_cfg.register_timeout = DEFAULT_REGISTRATION_TIMEOUT;
			}
		} else if (!strcasecmp(v->name, "registerattempts")) {
			/* Scheduled-retry attempt-cap; 0 = unlimited. */
			sofia_cfg.register_attempts = atoi(v->value);
		} else if (!strcasecmp(v->name, "directrtpsetup")) {
			/* parse-compatibility only (default DISABLED): early-RTP-bridge not implemented. */
			sofia_cfg.directrtpsetup = ast_true(v->value);
		} else if (!strcasecmp(v->name, "alwaysauthreject")) {
			/* Security-critical RFC 3261 §22.4 username-enumeration prevention —
			 * drives REGISTER unknown-peer + MWI SUBSCRIBE unknown-mailbox to emit
			 * 401 challenge instead of 403/404 disclosure. Default TRUE (chan_sip parity). */
			sofia_cfg.alwaysauthreject = ast_true(v->value);
		} else if (!strcasecmp(v->name, "compactheaders")) {
			/* parse-compatibility only: sofia-sip native compact-emit gate ABSENT; effect deferred. */
			sofia_cfg.compactheaders = ast_true(v->value);
		} else if (!strcasecmp(v->name, "disallowed_methods")) {
			/* parse-compatibility only string-storage; dynamic NUTAG_ALLOW generation deferred. */
			ast_copy_string(sofia_cfg.disallowed_methods, v->value, sizeof(sofia_cfg.disallowed_methods));
		} else if (!strcasecmp(v->name, "contactpermit") || !strcasecmp(v->name, "contactdeny")) {
			/* ast_append_ha(v->name + 7, ...) skips "contact"; remainder is the permit/deny sense. */
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
			/* Append a local SIP domain for CHECKSIPDOMAIN (multi-line, dedup'd). */
			sofia_domain_list_add(v->value);
		} else if (!strcasecmp(v->name, "outboundproxy")) {
			/* Default outbound proxy for INVITE + REGISTER (per-peer overrides). Accepts bare host /
			 * host:port / sip:URI; normalized by sofia_format_outboundproxy at use. */
			ast_copy_string(sofia_cfg.outboundproxy, v->value, sizeof(sofia_cfg.outboundproxy));
		} else if (!strcasecmp(v->name, "default_mohinterpret") || !strcasecmp(v->name, "mohinterpret")) {
			/* Default MOH interpret class inherited by sofia_peer_alloc; both spellings accepted. */
			ast_copy_string(sofia_cfg.default_mohinterpret, v->value, sizeof(sofia_cfg.default_mohinterpret));
		} else if (!strcasecmp(v->name, "default_mohsuggest") || !strcasecmp(v->name, "mohsuggest")) {
			ast_copy_string(sofia_cfg.default_mohsuggest, v->value, sizeof(sofia_cfg.default_mohsuggest));
		} else if (!strcasecmp(v->name, "language")) {
			/* Default language inherited by sofia_peer_alloc. */
			ast_copy_string(sofia_cfg.default_language, v->value, sizeof(sofia_cfg.default_language));
		} else if (!strcasecmp(v->name, "parkinglot")) {
			/* Default parkinglot inherited by new peers; empty restores the silent baseline. */
			ast_copy_string(sofia_cfg.default_parkinglot, v->value, sizeof(sofia_cfg.default_parkinglot));
		} else if (!strcasecmp(v->name, "ignoreregexpire")) {
			/* When yes, preserve expired contacts across short upstream-trunk outages. */
			sofia_cfg.ignore_regexpire = ast_true(v->value);
		} else if (!strcasecmp(v->name, "maxcallbitrate")) {
			/* Inherited by sofia_peer_alloc; clamp-negative-to-default (384). */
			sofia_cfg.default_maxcallbitrate = atoi(v->value);
			if (sofia_cfg.default_maxcallbitrate < 0) {
				sofia_cfg.default_maxcallbitrate = 384;
			}
		} else if (!strcasecmp(v->name, "match_auth_username")) {
			/* When yes, peer-lookup uses the Authorization username (sofia_pick_auth_username). */
			sofia_cfg.match_auth_username = ast_true(v->value);
		} else if (!strcasecmp(v->name, "legacy_useroption_parsing")) {
			/* parse-compatibility only: URI per-component semicolon-strip deferred. */
			sofia_cfg.legacy_useroption_parsing = ast_true(v->value);
		} else if (!strcasecmp(v->name, "shrinkcallerid")) {
			/* Tri-state; invalid warns + preserves current value. */
			if (ast_true(v->value)) {
				sofia_cfg.shrinkcallerid = 1;
			} else if (ast_false(v->value)) {
				sofia_cfg.shrinkcallerid = 0;
			} else {
				ast_log(LOG_WARNING, "Sofia: shrinkcallerid value '%s' is not valid; ignoring\n",
					v->value);
			}
		} else if (!strcasecmp(v->name, "apply_peer_callerid")) {
			/* yes (default) = chan_sip parity: force matched-peer callerid on inbound when no trusted
			 * RPID/PAI; no = keep the inbound From user as caller-ID. */
			sofia_cfg.apply_peer_callerid = ast_true(v->value);
		} else if (!strcasecmp(v->name, "notifyhold")) {
			/* Gates the peer->onHold counter update. */
			sofia_cfg.notifyhold = ast_true(v->value);
		} else if (!strcasecmp(v->name, "use_q850_reason")) {
			/* Q.850 Reason header (RFC 3326) on BYE/CANCEL, both directions. */
			sofia_cfg.use_q850_reason = ast_true(v->value);
		} else if (!strcasecmp(v->name, "notifyringing")) {
			/* parse-compatibility only: effect deferred until presence/dialog-info NOTIFY lands. */
			sofia_cfg.notifyringing = ast_true(v->value);
		} else if (!strcasecmp(v->name, "dynamic_exclude_static")
				|| !strcasecmp(v->name, "dynamic_excludes_static")) {
			/* Security hardening; both spellings accepted. */
			sofia_cfg.dynamic_exclude_static = ast_true(v->value);
		} else if (!strcasecmp(v->name, "autocreatepeer")) {
			/* parse-compatibility only: chan_sofia refuses to auto-create unknown peers. */
			sofia_cfg.autocreatepeer = ast_true(v->value);
		} else if (!strcasecmp(v->name, "preferred_codec_only")) {
			sofia_cfg.default_preferred_codec_only = ast_true(v->value);
		} else if (!strcasecmp(v->name, "ignoresdpversion")) {
			/* Implemented (o= version stickiness, RFC 3264 §8): no (default) honors the SDP o= version
			 * (a re-offer with the same origin + unchanged version is a no-op, preserving the
			 * learned media/NAT remote); yes forces reprocessing of every inbound SDP. */
			sofia_cfg.default_ignoresdpversion = ast_true(v->value);
		} else if (!strcasecmp(v->name, "promiscredir")) {
			/* parse-compatibility only: nua_r_redirect handler ABSENT. */
			sofia_cfg.default_promiscredir = ast_true(v->value);
		} else if (!strcasecmp(v->name, "autoframing")) {
			/* parse-compatibility only: sofia_parse_sdp ptime gate not implemented. */
			sofia_cfg.default_autoframing = ast_true(v->value);
		} else if (!strcasecmp(v->name, "timerb")) {
			/* CORRECTS a chan_sip bug: chan_sip only assigns global_timer_b in the invalid
			 * (< 500) branch, so valid values never take effect. We add the missing else.
			 * Implemented via NTATAG_SIP_T1X64; sofia_timerb_set feeds the timer cross-validation. */
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
			/* Adds parse-time validation chan_sip lacks: < 200 clamps to DEFAULT_TIMER_T1 (500) + warn.
			 * sofia_timert1_set feeds the timer cross-validation. */
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
			/* yes -> cng+t38, no -> none, or a comma-separated cng/t38 set. */
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
			/* Default T38FaxMaxDatagram override inherited by sofia_peer_alloc. Sentinel -1 = use
			 * SOFIA_T38_MAXDATAGRAM_BUILTIN (200); both spellings accepted. */
			int x;
			if (sscanf(v->value, "%30d", &x) == 1) {
				sofia_cfg.default_t38_maxdatagram = x;
			} else {
				ast_log(LOG_WARNING, "Sofia: invalid [general] %s value '%s' (expected integer)\n",
					v->name, v->value);
			}
		} else if (!strcasecmp(v->name, "allowoverlap")) {
			/* Tri-state yes/dtmf/no; default YES (drop-in critical). */
			if (ast_true(v->value)) {
				sofia_cfg.default_allowoverlap_mode = SOFIA_OVERLAP_YES;
			} else if (!strcasecmp(v->value, "dtmf")) {
				sofia_cfg.default_allowoverlap_mode = SOFIA_OVERLAP_DTMF;
			} else {
				sofia_cfg.default_allowoverlap_mode = SOFIA_OVERLAP_NO;
			}
		} else if (!strcasecmp(v->name, "progressinband")) {
			/* Tri-state yes/no/never. Partial implementation at sofia_indicate AST_CONTROL_RINGING. */
			if (ast_true(v->value)) {
				sofia_cfg.default_progressinband = SOFIA_PROG_INBAND_YES;
			} else if (strcasecmp(v->value, "never")) {
				sofia_cfg.default_progressinband = SOFIA_PROG_INBAND_NO;
			} else {
				sofia_cfg.default_progressinband = SOFIA_PROG_INBAND_NEVER;
			}
		} else if (!strcasecmp(v->name, "subscribe_network_change_event")) {
			/* parse-compatibility only (network-change handled by sofia-sip + dnsmgr); invalid warns. */
			if (ast_true(v->value)) {
				sofia_cfg.subscribe_network_change_event = 1;
			} else if (ast_false(v->value)) {
				sofia_cfg.subscribe_network_change_event = 0;
			} else {
				ast_log(LOG_WARNING, "Sofia: subscribe_network_change_event value '%s' is not valid at line %d.\n",
					v->value, v->lineno);
			}
		} else if (!strcasecmp(v->name, "rtsavesysname")) {
			/* Implemented at the sofia_process_register ast_update_realtime callsites. */
			sofia_cfg.rtsave_sysname = ast_true(v->value);
		} else if (!strcasecmp(v->name, "rtupdate")) {
			/* Gates the realtime peer updates in sofia_process_register. */
			sofia_cfg.peer_rtupdate = ast_true(v->value);
		} else if (!strcasecmp(v->name, "register_pool")) {
			/* Kill-switch: offload realtime REGISTER DB writes to a bounded pool
			 * (default OFF). Takes effect on reload. */
			sofia_cfg.register_pool = ast_true(v->value);
		} else if (!strcasecmp(v->name, "register_pool_workers")) {
			sofia_cfg.register_pool_workers = atoi(v->value);
		} else if (!strcasecmp(v->name, "rtcachefriends")) {
			/* parse-compatibility only: the ao2 registry already caches all peers. */
			sofia_cfg.rtcachefriends = ast_true(v->value);
		} else if (!strcasecmp(v->name, "rtautoclear")) {
			/* parse-compatibility only: no peer-level auto-clear infra. Numeric > 0 sets seconds; flag
			 * enabled when numeric > 0 OR ast_true. */
			int i = atoi(v->value);
			if (i > 0) {
				sofia_cfg.rtautoclear = i;
			} else {
				i = 0;
			}
			sofia_cfg.rtautoclear_enabled = (i || ast_true(v->value)) ? 1 : 0;
		} else if (!strcasecmp(v->name, "domainsasrealm")) {
			/* Implemented via sofia_get_realm_for_dialog at the auth-challenge callsites. */
			sofia_cfg.domainsasrealm = ast_true(v->value);
		} else if (!strcasecmp(v->name, "allowexternaldomains")) {
			/* Implemented via sofia_check_sip_domain at the invite/refer gates. */
			sofia_cfg.allow_external_domains = ast_true(v->value);
		} else if (!strcasecmp(v->name, "autodomain")) {
			/* Auto-add fires at sofia_load_config conclusion. */
			sofia_cfg.autodomain = ast_true(v->value);
		} else if (!strcasecmp(v->name, "matchexternaddrlocally")
		           || !strcasecmp(v->name, "matchexterniplocally")) {
			/* parse-compatibility only (sofia_should_use_externaddr signature diverges); both spellings. */
			sofia_cfg.matchexternaddrlocally = ast_true(v->value);
		} else if (!strcasecmp(v->name, "rtptimeout")) {
			if ((sscanf(v->value, "%30d", &sofia_cfg.default_rtptimeout) != 1)
					|| sofia_cfg.default_rtptimeout < 0) {
				ast_log(LOG_WARNING, "Sofia: '%s' is not a valid RTP timeout; using default 0\n", v->value);
				sofia_cfg.default_rtptimeout = 0;
			}
		} else if (!strcasecmp(v->name, "rtpholdtimeout")) {
			if ((sscanf(v->value, "%30d", &sofia_cfg.default_rtpholdtimeout) != 1)
					|| sofia_cfg.default_rtpholdtimeout < 0) {
				ast_log(LOG_WARNING, "Sofia: '%s' is not a valid RTP hold timeout; using default 0\n", v->value);
				sofia_cfg.default_rtpholdtimeout = 0;
			}
		} else if (!strcasecmp(v->name, "rtpkeepalive")) {
			if ((sscanf(v->value, "%30d", &sofia_cfg.default_rtpkeepalive) != 1)
					|| sofia_cfg.default_rtpkeepalive < 0) {
				ast_log(LOG_WARNING, "Sofia: '%s' is not a valid RTP keepalive; using default 0\n", v->value);
				sofia_cfg.default_rtpkeepalive = 0;
			}
		} else if (!strcasecmp(v->name, "tos_sip")) {
			/* Implemented via TPTAG_TOS at nua_create. */
			if (ast_str2tos(v->value, &sofia_cfg.tos_sip)) {
				ast_log(LOG_WARNING, "Sofia: invalid tos_sip value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "tos_audio")) {
			/* Implemented via ast_rtp_instance_set_qos. */
			if (ast_str2tos(v->value, &sofia_cfg.tos_audio)) {
				ast_log(LOG_WARNING, "Sofia: invalid tos_audio value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "tos_video")) {
			/* Implemented via ast_rtp_instance_set_qos. */
			if (ast_str2tos(v->value, &sofia_cfg.tos_video)) {
				ast_log(LOG_WARNING, "Sofia: invalid tos_video value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "tos_text")) {
			/* parse-compatibility only: text-RTP infra absent (no pvt->trtp). */
			if (ast_str2tos(v->value, &sofia_cfg.tos_text)) {
				ast_log(LOG_WARNING, "Sofia: invalid tos_text value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "cos_sip")) {
			/* parse-compatibility only: sofia-sip TPTAG_COS absent. */
			if (ast_str2cos(v->value, &sofia_cfg.cos_sip)) {
				ast_log(LOG_WARNING, "Sofia: invalid cos_sip value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "cos_audio")) {
			/* Implemented via ast_rtp_instance_set_qos. */
			if (ast_str2cos(v->value, &sofia_cfg.cos_audio)) {
				ast_log(LOG_WARNING, "Sofia: invalid cos_audio value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "cos_video")) {
			/* Implemented via ast_rtp_instance_set_qos. */
			if (ast_str2cos(v->value, &sofia_cfg.cos_video)) {
				ast_log(LOG_WARNING, "Sofia: invalid cos_video value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "cos_text")) {
			/* parse-compatibility only: text-RTP infra absent (no pvt->trtp). */
			if (ast_str2cos(v->value, &sofia_cfg.cos_text)) {
				ast_log(LOG_WARNING, "Sofia: invalid cos_text value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "mwi_from")) {
			/* MWI From-header default; empty -> peer->fromdomain or sofia_cfg.realm fallback */
			ast_copy_string(sofia_cfg.mwi_from, v->value, sizeof(sofia_cfg.mwi_from));
		} else if (!strcasecmp(v->name, "notifymime")
				|| !strcasecmp(v->name, "notifymimetype")) {
			/* MWI NOTIFY Content-Type; default application/simple-message-summary (RFC 3842);
			 * both spellings accepted. */
			ast_copy_string(sofia_cfg.notifymime, v->value, sizeof(sofia_cfg.notifymime));
		} else if (!strcasecmp(v->name, "vmexten")) {
			/* voicemail user-part for Message-Account URI; default "asterisk" */
			ast_copy_string(sofia_cfg.vmexten, v->value, sizeof(sofia_cfg.vmexten));
		} else if (!strcasecmp(v->name, "mwi_expiry")
		           || !strcasecmp(v->name, "mwiexpiry")
		           || !strcasecmp(v->name, "mwiexpirey")) {
			/* MWI subscription default expiry seconds; default 3600; 3 spellings; < 1 -> 3600. */
			sofia_cfg.mwi_expiry = atoi(v->value);
			if (sofia_cfg.mwi_expiry < 1) {
				sofia_cfg.mwi_expiry = 3600;
			}
		} else if (!strcasecmp(v->name, "externaddr") || !strcasecmp(v->name, "externip")
				|| !strcasecmp(v->name, "externhost")) {
			/* Accept all three keys (externip is the chan_sip name, alias of externaddr).
			 * ast_sockaddr_parse detects the value type: a literal IP stores as static externaddr
			 * (no refresh); else treat as hostname (resolve + arm externexpire for lazy-refresh), so a
			 * hostname in externaddr=/externip= still works. */
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
		} else if (!strcasecmp(v->name, "recordhistory")) {
			/* recordhistory (chan_sip parity): boot default for per-call SIP history recording. A
			 * runtime 'sip set history' toggle persists across a reload UNLESS this knob re-applies. */
			sofia_record_history = ast_true(v->value);
		} else if (!strcasecmp(v->name, "media_address")) {
			/* media_address (chan_sip parity): advertise this address in the SDP c=/o= instead of the
			 * kernel-routed source (the RTP still binds bindaddr — advertise-only). Validate as an IP and
			 * store ADDRESS-ONLY (a stray port would emit a malformed "c=IN IP4 host:port"); reject + warn
			 * + leave off on an invalid value, like chan_sip's PARSE_ADDR. */
			struct ast_sockaddr ma;
			if (ast_sockaddr_parse(&ma, v->value, PARSE_PORT_IGNORE)) {
				/* stringify_addr_remote (NOT _host) gives the SDP-form address: an IPv6 stays UNbracketed
				 * (c=IN IP6 2001:db8::1), where stringify_host would emit the invalid [2001:db8::1]. */
				ast_copy_string(sofia_cfg.media_address, ast_sockaddr_stringify_addr_remote(&ma),
					sizeof(sofia_cfg.media_address));
			} else {
				ast_log(LOG_WARNING, "Sofia: ignoring media_address='%s' (not a valid IP address)\n",
					v->value);
			}
		} else if (!strcasecmp(v->name, "localnet")) {
			ast_copy_string(sofia_cfg.localnet, v->value, sizeof(sofia_cfg.localnet));
			{
				int ha_error = 0;
				struct ast_ha *na;
				/* reload-UAF: serialize the append vs channel-thread readers of sofia_cfg.localha. */
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
	/* Find-or-alloc: only a NEW peer is ao2_link()ed at the end (ao2_link never dedups, so
	 * re-linking a surviving peer each reload would duplicate the node + leak a ref). */
	int new_alloc = 0;
	int locked = 0;
	/* RFC 5626/5627: snapshot gruu/sip_outbound BEFORE the reload reset (sofia_peer_set_defaults zeroes
	 * them) so the tail can tell whether a toggle needs the REGISTER handle rebuilt. */
	int old_gruu = 0, old_sip_outbound = 0;
	/* Per-peer header= counter for the unique __SIPADDHEADERpre%2d= var name. */
	int headercount = 0;

	peer = sofia_find_peer(cat);
	if (!peer) {
		peer = sofia_peer_alloc(cat);
		if (!peer) {
			return;
		}
		new_alloc = 1;
	} else {
		/* Release the existing dnsmgr handle BEFORE the reset re-parses host= (else a host=
		 * change leaves dnsmgr registered for the OLD host + keeps its +1 ref; the tail
		 * re-registers fresh). The helper detaches under peer->lock then releases outside it
		 * (below we take peer->lock for the whole reset — this runs before that). */
		sofia_peer_release_dnsmgr(peer, 1);
		/* Hold peer->lock across the ENTIRE reset + repopulate + defaults window. The
		 * ast_string_field_set calls free the old stringfield pool when a value grows, so
		 * peer->lock readers (sched/reg/qualify, show_peer / SIPpeers) must serialize behind
		 * the whole mutation. Readers take peer->lock as a leaf, so widening cannot invert.
		 * dnsmgr/hint/ao2_link stay OUTSIDE (heavy global locks). `locked` tracks this path. */
		/* ABBA fix: drop the dialplan hint BEFORE taking peer->lock — ast_context_remove_extension
		 * takes conlock (peer->lock -> conlock), but the dialplan reload path runs the reverse
		 * (conlock -> ast_add_hint -> sofia_devicestate -> peer->lock). We are the sole mutator, so
		 * the OLD subscribecontext/regexten are stable to snapshot unlocked. */
		if (!ast_strlen_zero(peer->subscribecontext) && !ast_strlen_zero(peer->regexten)) {
			char old_subctx[AST_MAX_CONTEXT];
			char old_regexten[256];	/* a multi-token regexten SPEC, not one exten — match the 256 the splitter uses */
			ast_copy_string(old_subctx, peer->subscribecontext, sizeof(old_subctx));
			ast_copy_string(old_regexten, peer->regexten, sizeof(old_regexten));
			sofia_remove_peer_hints(old_regexten, old_subctx, "sofia_config_peer");
		}
		ast_mutex_lock(&peer->lock);
		locked = 1;
		/* Reset ACL chains so the permit/deny parsers append onto a fresh list, else each
		 * reload grows peer->ha (and contactha/directmediaha) linearly. */
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
		/* Drain the mailbox list (parse appends without dedup, so each reload would accumulate
		 * mailbox structs + their event subs). Unsubscribe synchronously (waits for any in-flight
		 * mwi_event_cb) then free. */
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
		ast_string_field_set(peer, publish_exten, "");
		/* Free prior chanvars before re-parsing (mirrors the string-field reset). */
		if (peer->chanvars) {
			ast_variables_destroy(peer->chanvars);
			peer->chanvars = NULL;
		}
		/* Snapshot the OLD advertisement knobs before the reset zeroes them; the tail compares the final
		 * parsed values to decide whether the REGISTER handle must be rebuilt (RFC 5626/5627). */
		old_gruu = peer->gruu;
		old_sip_outbound = peer->sip_outbound;
		/* Re-apply the COMPLETE default set so a REMOVED per-peer key reverts to its [general]
		 * default rather than keeping the prior value (else a stale md5secret authenticates the
		 * OLD password, a removed insecure=invite keeps auth off -> toll-fraud). Under the held
		 * peer->lock; runs AFTER the ACL frees so the contact_ha re-inherit is leak-free. */
		sofia_peer_set_defaults(peer);
	}

	/* Survived the new config -> must not be swept. */
	peer->_reload_marked = 0;

	for (v = ast_variable_browse(cfg, cat); v; v = v->next) {
		if (!strcasecmp(v->name, "secret") || !strcasecmp(v->name, "password")) {
			ast_string_field_set(peer, secret, v->value);
			/* Warn on both secret= + md5secret= set (md5secret takes precedence). */
			if (!ast_strlen_zero(peer->md5secret) && !ast_strlen_zero(v->value)) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' has BOTH secret= and "
					"md5secret= set — md5secret takes precedence (chan_sip.c"
					":15415-16 parity); recommend operator unset secret= to "
					"remove ambiguity\n", peer->name);
			}
		} else if (!strcasecmp(v->name, "md5secret")) {
			/* Pre-hashed MD5(user:realm:secret): used directly as a1_hash, takes PRECEDENCE
			 * over peer->secret. */
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
		} else if (!strcasecmp(v->name, "message_context")) {
			/* Per-peer override for inbound out-of-dialog MESSAGE dialplan dispatch. */
			ast_string_field_set(peer, message_context, v->value);
		} else if (!strcasecmp(v->name, "mwi_subscribe")) {
			/* Outbound MWI watcher: <localmailbox>[@context]. SUBSCRIBE this trunk for
			 * Event: message-summary and inject the result into the local MWI cache. */
			ast_string_field_set(peer, mwi_subscribe, v->value);
		} else if (!strcasecmp(v->name, "subscribe_event")) {
			/* Generic outbound SUBSCRIBE (RFC 6665): <event>[;<accept-mime>][;<expires>]. */
			ast_string_field_set(peer, subscribe_event, v->value);
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
			/* Keep raw (CLI/AMI display) AND split into cid_num/cid_name (chan_sip.c:28779-28784
			 * parity) — the functional fields. The duplicate split-only handler later in this
			 * chain was dead code (this "callerid" always matched here first). */
			char cid_name_buf[80] = "", cid_num_buf[80] = "";
			ast_string_field_set(peer, callerid, v->value);
			ast_callerid_split(v->value, cid_name_buf, sizeof(cid_name_buf), cid_num_buf, sizeof(cid_num_buf));
			ast_string_field_set(peer, cid_name, cid_name_buf);
			ast_string_field_set(peer, cid_num, cid_num_buf);
		} else if (!strcasecmp(v->name, "regexten")) {
			ast_string_field_set(peer, regexten, v->value);
		} else if (!strcasecmp(v->name, "publish_exten")) {
			/* Outbound PUBLISH: explicit exten(s) to publish (overrides regexten/name as the source). */
			ast_string_field_set(peer, publish_exten, v->value);
		} else if (!strcasecmp(v->name, "callbackextension")) {
			ast_string_field_set(peer, callbackextension, v->value);
		} else if (!strcasecmp(v->name, "setvar")) {
			peer->chanvars = sofia_add_var(v->value, peer->chanvars);
		} else if (!strcasecmp(v->name, "header")) {
			/* Custom SIP header stored as a __SIPADDHEADERpre var that
			 * sofia_build_addheader_str absorbs by prefix at sofia_call. */
			char tmp[4096];
			snprintf(tmp, sizeof(tmp), "__SIPADDHEADERpre%2d=%s", ++headercount, v->value);
			peer->chanvars = sofia_add_var(tmp, peer->chanvars);
		} else if (!strcasecmp(v->name, "subscribecontext")) {
			ast_string_field_set(peer, subscribecontext, v->value);
		} else if (!strcasecmp(v->name, "accountcode")) {
			ast_string_field_set(peer, accountcode, v->value);
		} else if (!strcasecmp(v->name, "disallowed_methods")) {
			/* parse-compatibility only string-storage. */
			ast_string_field_set(peer, disallowed_methods, v->value);
		} else if (!strcasecmp(v->name, "maxforwards")) {
			if (sscanf(v->value, "%30d", &peer->maxforwards) != 1
				|| peer->maxforwards < 1 || 255 < peer->maxforwards) {
				ast_log(LOG_WARNING, "Sofia: '%s' is not a valid maxforwards value for peer '%s' — using default %d\n",
					v->value, peer->name, sofia_cfg.default_max_forwards);
				peer->maxforwards = sofia_cfg.default_max_forwards;
			}
		} else if (!strcasecmp(v->name, "insecure")) {
			peer->insecure = sofia_parse_insecure(v->value);
		} else if (!strcasecmp(v->name, "dtmfmode")) {
			peer->dtmfmode = sofia_parse_dtmfmode(v->value);
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
			/* canreinvite = legacy alias for directmedia. */
			peer->directmedia = sofia_parse_directmedia(v->value);
		} else if (!strcasecmp(v->name, "busy_on_active")) {
			peer->busy_on_active = ast_true(v->value);
		} else if (!strcasecmp(v->name, "max_contacts")) {
			peer->max_contacts = sofia_clamp_max_contacts(atoi(v->value), peer->name);
		} else if (!strcasecmp(v->name, "encryption")) {
			peer->encryption = ast_true(v->value);
		} else if (!strcasecmp(v->name, "webrtc")) {
			peer->webrtc = ast_true(v->value);	/* WebRTC ENABLE (DTLS-SRTP + ICE-lite + rtcp-mux); the per-contact/static transport picks the actual profile (sofia_offer_effective_webrtc) */
		} else if (!strcasecmp(v->name, "datachannel")) {
			peer->datachannel = ast_true(v->value);	/* accept the WebRTC m=application (RFC 8841 SCTP); requires webrtc=yes + usrsctp */
		} else if (!strcasecmp(v->name, "webrtc_video_bundle")) {
			peer->webrtc_video_bundle = ast_true(v->value);	/* BUNDLE WebRTC video onto the audio transport (RFC 8843); requires webrtc=yes; consumed during BUNDLE video staging */
		} else if (!strcasecmp(v->name, "flowclose_emit_unregister")) {
			peer->flowclose_emit_unregister = ast_true(v->value);	/* RFC 5626 flow-close: yes = emit unregister side-effects on flow close; no (default) = silent removal */
		} else if (!strcasecmp(v->name, "srtpcipher")) {
			/* SRTP suite preference; typo WARN happens at sdp_crypto_offer_list emit, not here. */
			ast_string_field_set(peer, srtpcipher, v->value);
		} else if (!strcasecmp(v->name, "session-timers")) {
			/* RFC 4028. */
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
			peer->callingpres = sofia_parse_callingpres(v->value);
		} else if (!strcasecmp(v->name, "sendrpid")) {
			peer->sendrpid = sofia_parse_sendrpid(v->value);
		} else if (!strcasecmp(v->name, "trustrpid")) {
			peer->trustrpid = ast_true(v->value);
		} else if (!strcasecmp(v->name, "callcounter")) {
			peer->call_limit = ast_true(v->value) ? INT_MAX : 0;
		} else if (!strcasecmp(v->name, "call-limit") || !strcasecmp(v->name, "call_limit")) {
			peer->call_limit = atoi(v->value);
			if (peer->call_limit < 0) peer->call_limit = 0;
		} else if (!strcasecmp(v->name, "busylevel")) {
			peer->busy_level = atoi(v->value);
			if (peer->busy_level < 0) peer->busy_level = 0;
		} else if (!strcasecmp(v->name, "mailbox")) {
			/* Comma-separated mbox@ctx list (no @ defaults to context "default"). */
			sofia_peer_parse_mailboxes(peer, v->value);
		} else if (!strcasecmp(v->name, "outboundproxy")) {
			/* Empty = unset; if empty and sofia_cfg.outboundproxy is set, the general default applies. */
			ast_string_field_set(peer, outboundproxy, v->value);
		} else if (!strcasecmp(v->name, "mohinterpret")) {
			ast_string_field_set(peer, mohinterpret, v->value);
		} else if (!strcasecmp(v->name, "mohsuggest")) {
			/* INBOUND-direction only; OUTBOUND Alert-Info deferred. */
			ast_string_field_set(peer, mohsuggest, v->value);
		} else if (!strcasecmp(v->name, "language")) {
			ast_string_field_set(peer, language, v->value);
		} else if (!strcasecmp(v->name, "parkinglot")) {
			ast_string_field_set(peer, parkinglot, v->value);
		} else if (!strcasecmp(v->name, "defaultip")) {
			/* On resolve-fail WARN + leave defaddr null (preserve the peer; chan_sip drops it). */
			if (!ast_strlen_zero(v->value) && ast_get_ip(&peer->defaddr, v->value)) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' defaultip='%s' could not be resolved; ignoring\n",
					peer->name, v->value);
				ast_sockaddr_setnull(&peer->defaddr);
			}
		} else if (!strcasecmp(v->name, "maxcallbitrate")) {
			peer->maxcallbitrate = atoi(v->value);
			if (peer->maxcallbitrate < 0) {
				peer->maxcallbitrate = sofia_cfg.default_maxcallbitrate;
			}
		} else if (!strcasecmp(v->name, "amaflags")) {
			/* WARN + skip on invalid (channel-core default applies at sofia_new). */
			int format = ast_cdr_amaflags2int(v->value);
			if (format < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid AMA Flags '%s'; ignoring\n",
					peer->name, v->value);
			} else {
				peer->amaflags = format;
			}
		} else if (!strcasecmp(v->name, "subscribemwi")) {
			/* chan_sip parity: yes => SUBSCRIBE-only; no (default) => also push unsolicited MWI. */
			peer->subscribemwi = ast_true(v->value);
		} else if (!strcasecmp(v->name, "preferred_codec_only")) {
			peer->preferred_codec_only = ast_true(v->value);
		} else if (!strcasecmp(v->name, "ignoresdpversion")) {
			/* Implemented (o= version stickiness, RFC 3264 §8): no (default) honors the o= version;
			 * yes forces reprocessing of every inbound SDP. Overrides the [general] default. */
			peer->ignoresdpversion = ast_true(v->value);
		} else if (!strcasecmp(v->name, "promiscredir")) {
			/* parse-compatibility only: nua_r_redirect handler ABSENT. */
			peer->promiscredir = ast_true(v->value);
		} else if (!strcasecmp(v->name, "autoframing")) {
			/* parse-compatibility only: sofia_parse_sdp ptime gate not implemented. */
			peer->autoframing = ast_true(v->value);
		} else if (!strcasecmp(v->name, "timerb")) {
			/* sscanf %30d; clamp to default if invalid or < 200. */
			int tmp_b;
			if ((sscanf(v->value, "%30d", &tmp_b) != 1) || tmp_b < 200) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid timerb '%s' (< 200ms or non-integer); using default %d\n",
					peer->name, v->value, sofia_cfg.default_timer_b);
				peer->timer_b = sofia_cfg.default_timer_b;
			} else {
				peer->timer_b = tmp_b;
			}
		} else if (!strcasecmp(v->name, "timert1")) {
			/* sscanf %30d; on invalid / < 200 / < t1min fall back to t1min (not default_timer_t1). */
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
			 * comma-separated cng/t38 set. The runtime implementation handles DSP
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
			/* Per-peer T.38 enable + EC mode + MaxDatagram. Comma-separated
			 * yes|no|fec|redundancy|none[,maxdatagram=N]; yes defaults EC = FEC. */
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
			/* symmetric-RTP UDPTL destination override (boolean). */
			peer->t38pt_usertpsource = ast_true(v->value) ? 1 : 0;
		} else if (!strcasecmp(v->name, "allowoverlap")) {
			/* tri-state yes/dtmf/no. */
			if (ast_true(v->value)) {
				peer->allowoverlap_mode = SOFIA_OVERLAP_YES;
			} else if (!strcasecmp(v->value, "dtmf")) {
				peer->allowoverlap_mode = SOFIA_OVERLAP_DTMF;
			} else {
				peer->allowoverlap_mode = SOFIA_OVERLAP_NO;
			}
		} else if (!strcasecmp(v->name, "progressinband")) {
			/* tri-state yes/no/never. Partial implementation at sofia_indicate AST_CONTROL_RINGING. */
			if (ast_true(v->value)) {
				peer->progressinband = SOFIA_PROG_INBAND_YES;
			} else if (strcasecmp(v->value, "never")) {
				peer->progressinband = SOFIA_PROG_INBAND_NO;
			} else {
				peer->progressinband = SOFIA_PROG_INBAND_NEVER;
			}
		} else if (!strcasecmp(v->name, "rtptimeout")) {
			if ((sscanf(v->value, "%30d", &peer->rtptimeout) != 1) || peer->rtptimeout < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid rtptimeout '%s'; using default\n",
					peer->name, v->value);
				peer->rtptimeout = sofia_cfg.default_rtptimeout;
			}
		} else if (!strcasecmp(v->name, "rtpholdtimeout")) {
			if ((sscanf(v->value, "%30d", &peer->rtpholdtimeout) != 1) || peer->rtpholdtimeout < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid rtpholdtimeout '%s'; using default\n",
					peer->name, v->value);
				peer->rtpholdtimeout = sofia_cfg.default_rtpholdtimeout;
			}
		} else if (!strcasecmp(v->name, "rtpkeepalive")) {
			if ((sscanf(v->value, "%30d", &peer->rtpkeepalive) != 1) || peer->rtpkeepalive < 0) {
				ast_log(LOG_WARNING, "Sofia: peer '%s' invalid rtpkeepalive '%s'; using default\n",
					peer->name, v->value);
				peer->rtpkeepalive = sofia_cfg.default_rtpkeepalive;
			}
		} else if (!strcasecmp(v->name, "fullname")
				|| !strcasecmp(v->name, "cid_name")) {
			ast_string_field_set(peer, cid_name, v->value);
		} else if (!strcasecmp(v->name, "trunkname")) {
			/* trunkname clears cid_name. */
			ast_string_field_set(peer, cid_name, "");
		} else if (!strcasecmp(v->name, "cid_number")) {
			ast_string_field_set(peer, cid_num, v->value);
		} else if (!strcasecmp(v->name, "cid_tag")) {
			ast_string_field_set(peer, cid_tag, v->value);
		} else if (!strcasecmp(v->name, "callgroup")) {
			peer->callgroup = ast_get_group(v->value);
		} else if (!strcasecmp(v->name, "allowtransfer")) {
			peer->allowtransfer = ast_true(v->value) ? TRANSFER_OPENFORALL : TRANSFER_CLOSED;
		} else if (!strcasecmp(v->name, "allowsubscribe")) {
			peer->allowsubscribe = ast_true(v->value);
		} else if (!strcasecmp(v->name, "gruu")) {
			peer->gruu = ast_true(v->value);
			if (!peer->gruu) {	/* gruu turned off -> drop any learned GRUU (else it lingers hidden) */
				ast_string_field_set(peer, pub_gruu, "");
				ast_string_field_set(peer, temp_gruu, "");
			}
		} else if (!strcasecmp(v->name, "use_gruu_contact")) {
			peer->use_gruu_contact = ast_true(v->value);	/* Interop kill-switch */
		} else if (!strcasecmp(v->name, "service_route")) {
			peer->use_service_route = ast_true(v->value);	/* RFC 3608: pre-load the registrar's Service-Route on outbound INVITEs (opt-in) */
			if (!peer->use_service_route) {	/* knob turned off -> drop any learned route (no stale routing) */
				ast_string_field_set(peer, service_route, "");
			}
		} else if (!strcasecmp(v->name, "path")) {
			peer->path_support = ast_true(v->value);	/* RFC 3327: accept + use the device's Path (opt-in) */
			if (!peer->path_support) {	/* drop stored Paths so a re-enable can't resurrect a stale route */
				sofia_peer_clear_contact_paths(peer);
			}
		} else if (!strcasecmp(v->name, "rel100")) {
			peer->rel100 = ast_true(v->value);	/* RFC 3262: reliable non-183 provisionals (opt-in) */
		} else if (!strcasecmp(v->name, "sip_outbound")) {
			peer->sip_outbound = ast_true(v->value);	/* RFC 5626: advertise outbound + reg-id on REGISTER (opt-in) */
		} else if (!strcasecmp(v->name, "publish")) {
			/* outbound PUBLISH (RFC 3903); mirrors the realtime branch. */
			peer->publish = ast_true(v->value);
		} else if (!strcasecmp(v->name, "buggymwi")) {
			peer->buggymwi = ast_true(v->value);
		} else if (!strcasecmp(v->name, "lockuseragent")) {
			peer->lockuseragent = ast_true(v->value);
		} else if (!strcasecmp(v->name, "lockuseragent_prefixes")) {
			ast_string_field_set(peer, lockuseragent_prefixes, v->value);
		} else if (!strcasecmp(v->name, "usereqphone")) {
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
			/* Skips "contact" (+7); separate ACL chain from peer->ha (source-IP). */
			int ha_error = 0;
			if (!ast_strlen_zero(v->value)) {
				peer->contactha = ast_append_ha(v->name + 7, v->value, peer->contactha, &ha_error);
			}
			if (ha_error) {
				ast_log(LOG_ERROR, "Sofia: bad %s line for peer '%s': %s\n",
					v->name, peer->name, v->value);
			}
		} else if (!strcasecmp(v->name, "directmediapermit") || !strcasecmp(v->name, "directmediadeny")) {
			/* Skips "directmedia" (+11); applied cross-leg at sofia_get_rtp_peer. */
			int ha_error = 0;
			peer->directmediaha = ast_append_ha(v->name + 11, v->value, peer->directmediaha, &ha_error);
			if (ha_error) {
				ast_log(LOG_ERROR, "Sofia: bad directmedia %s line for peer '%s': %s\n",
					v->name, peer->name, v->value);
			}
		} else if (!strcasecmp(v->name, "nat")) {
			/* An empty value (e.g. an empty realtime nat column) INHERITS the [general] default
			 * already set at sofia_peer_alloc, rather than forcing force_rport. */
			if (!ast_strlen_zero(v->value))
				peer->nat = sofia_parse_nat(v->value);
		} else if (!strcasecmp(v->name, "expiresecs") || !strcasecmp(v->name, "defaultexpiry")) {
			peer->expiresecs = atoi(v->value);
		} else if (!strcasecmp(v->name, "transport")) {
			/* Outbound transport for a static config-file peer (realtime twin: sofia_apply_peer_variables).
			 * Without it a static TLS/TCP/WS/WSS host's RURI defaults to UDP; inbound stays per-listener
			 * ([general] bind addrs) + per-Contact at REGISTER-time. Comma-list uses the first token. */
			peer->transport = sofia_parse_transport(v->value);
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

	/* Fields repopulated + defaulted; release the mutation lock. Everything below
	 * (hint/dnsmgr/ao2_link) runs unlocked.
	 *
	 * sofia_peer_set_defaults reset the lockuseragent CONFIG flag but left the captured
	 * locked_user_agent anchor (runtime state). Clear the anchor only if lockuseragent ended up
	 * disabled, else a reload would let a different UA re-capture it on the next REGISTER. */
	if (locked) {
		if (!peer->lockuseragent) {
			peer->locked_user_agent[0] = '\0';
		}
		/* RFC 5626/5627: a reload that toggled gruu/sip_outbound left the surviving peer->nh advertising
		 * the OLD set (NUTAG_SUPPORTED only merges on a handle) — mark it for rebuild on the next refresh.
		 * And drop runtime advertisement state when the knob ended up off (line removed or set no). */
		if (peer->nh && (old_gruu != peer->gruu || old_sip_outbound != peer->sip_outbound)) {
			peer->reg_handle_dirty = 1;
		}
		if (!peer->gruu) {
			ast_string_field_set(peer, pub_gruu, "");
			ast_string_field_set(peer, temp_gruu, "");
		}
		if (!peer->sip_outbound) {
			peer->sip_outbound_active = 0;
			peer->flow_timer = 0;
		}
		ast_mutex_unlock(&peer->lock);
	}

	/* Link the new peer FIRST (before the hint/dnsmgr/global-ACL side effects) so an ao2_link
	 * OOM never orphans them around an unlinked peer. A surviving reload peer is already in the
	 * container, so only a new_alloc peer is linked here. */
	if (new_alloc) {
		if (!ao2_link(peers, peer)) {
			/* OOM — drain MWI before the destructor, then bail without orphaning a side effect. */
			sofia_peer_drain_mwi(peer);
			ao2_ref(peer, -1);
			return;
		}
	}

	/* "config" source -> "sofia_config_peer" registrar (visible in core show hints). */
	sofia_create_peer_hint(peer, "config");

	sofia_dnsmgr_setup_peer(peer);
	sofia_peer_ipport_reindex(peer);	/* B: index by IP+port after the config build (covers reload re-key) */

	/* dynamic_exclude_static: a static-IP peer appends a deny rule to the global contact_ha so
	 * later REGISTERs from that address are rejected. */
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

/* sofia_cfg.allowsubscribe = TRUE if any peer flag-allows (one-way flip, stays TRUE).
 * ao2_callback sweep at sofia_load_config conclusion; runtime realtime peers set it inline. */
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

/* Live SIP tracing state (sofia-sip built-in tport capture). Off by default; when on, captures EVERY
 * SIP message DECRYPTED on recv+sent for udp/tcp/tls/ws/wss — including the SDP (WebRTC signalling). */
static int sofia_capture_on;	/* HEP capture (TPTAG_CAPT) currently applied to the tport layer */
static int sofia_dump_on;	/* file dump (TPTAG_DUMP) currently applied to the tport layer */

/* Push the live SIP-capture state (from sofia_cfg) onto the sofia-sip transport layer:
 *   sip_capture_address -> TPTAG_CAPT("udp:HOST:PORT;hep=N;capture_id=ID") = HEP stream to Homer/sipcapture;
 *   sip_capture_file    -> TPTAG_DUMP(path) = append every decrypted message to a file.
 * sofia-sip's capture socket is non-blocking (tport_logging.c), so this never stalls the stack thread.
 * Empty = OFF, and we only actively disable when it was previously on, so the default-off path never opens
 * a socket/file (zero overhead). No-op before the NUA agent exists. Invoked at startup (after nua_create)
 * and at the end of sofia_apply_config (covers `sip reload`); also driven by the CLI subcommands. */
void sofia_apply_capture(void)
{
	tport_t *tports;

	if (!sofia_nua) {
		return;
	}
	tports = nta_agent_tports(nua_get_agent(sofia_nua));
	if (!tports) {
		return;
	}

	/* DUMP first, and with TPTAG_CAPT(NULL) in the SAME set. sofia-sip's tport_open_log() re-seeds its
	 * local `capt` from mr_capt_name (tport_logging.c:124) and, for an unchanged already-open capture,
	 * early-returns (165-166) BEFORE the dump fopen (302-324) -- so a plain TPTAG_DUMP applied while an
	 * HEP capture is active never opens the file. Supplying TPTAG_CAPT(NULL) alongside overwrites that
	 * pre-seed to NULL (tl_gets picks the last matching tag), so the capture block is skipped entirely
	 * and the dump-open is reached. It also drops the capture socket, which the capture step below
	 * re-opens on top (no DUMP tag there, so mr_dump_file is left intact). */
	if (!ast_strlen_zero(sofia_cfg.sip_capture_file)) {
		/* /dev/null reset: sofia-sip's dump same-name check compares only the NAME, so re-applying the
		 * same path would skip fopen(); the name change forces the real path to (re)open. */
		tport_set_params(tports, TPTAG_CAPT(NULL), TPTAG_DUMP("/dev/null"), TAG_END());
		tport_set_params(tports, TPTAG_CAPT(NULL), TPTAG_DUMP(sofia_cfg.sip_capture_file), TAG_END());
		sofia_dump_on = 1;
		sofia_capture_on = 0;	/* the CAPT(NULL) above closed the capture socket; re-applied below if configured */
		ast_log(LOG_NOTICE, "Sofia: SIP message dump -> file %s\n", sofia_cfg.sip_capture_file);
	} else if (sofia_dump_on) {
		/* sofia-sip has no dump-off tag; redirecting to /dev/null closes (flushes) the operator's file.
		 * CAPT(NULL) here too so the dump closes regardless of capture state; capture re-applied below. */
		tport_set_params(tports, TPTAG_CAPT(NULL), TPTAG_DUMP("/dev/null"), TAG_END());
		sofia_dump_on = 0;
		sofia_capture_on = 0;
		ast_log(LOG_NOTICE, "Sofia: SIP message dump disabled\n");
	}

	/* CAPT after: (re-)open the HEP socket on top. No DUMP tag here, so tport_open_log leaves mr_dump_file
	 * untouched (its dump block is skipped when dump==NULL) -- an already-open dump file stays open. */
	if (!ast_strlen_zero(sofia_cfg.sip_capture_address)) {
		char url[192];
		int hep = (sofia_cfg.sip_capture_hep >= 1 && sofia_cfg.sip_capture_hep <= 3)
			? sofia_cfg.sip_capture_hep : 3;
		int id = sofia_cfg.sip_capture_id > 0 ? sofia_cfg.sip_capture_id : 200;
		snprintf(url, sizeof(url), "udp:%s;hep=%d;capture_id=%d",
			sofia_cfg.sip_capture_address, hep, id);
		/* Reset first: sofia-sip's tport_open_log short-circuits when the CAPT url is unchanged AND a
		 * socket already exists, so an earlier apply that set the name but failed to open the socket
		 * would block every retry. TPTAG_CAPT(NULL) zeroes mr_capt_sock -> the next set always reopens. */
		tport_set_params(tports, TPTAG_CAPT(NULL), TAG_END());
		tport_set_params(tports, TPTAG_CAPT(url), TAG_END());
		sofia_capture_on = 1;
		ast_log(LOG_NOTICE, "Sofia: SIP capture -> HEPv%d UDP %s (capture_id=%d)\n",
			hep, sofia_cfg.sip_capture_address, id);
	} else if (sofia_capture_on) {
		tport_set_params(tports, TPTAG_CAPT(NULL), TAG_END());	/* NULL closes the capture socket */
		sofia_capture_on = 0;
		ast_log(LOG_NOTICE, "Sofia: SIP capture disabled\n");
	}
}

/* CLI-thread-safe SIP-capture change: MARSHAL the apply onto sofia_thread.
 * sofia_apply_capture() runs tport_set_params(TPTAG_DUMP/CAPT), which closes/reopens the SHARED tport
 * mr_dump_file (FILE*) + mr_capt_sock (sofia-sip tport_logging.c) that sofia_thread writes to per message
 * with NO locking — applying it from the CLI thread races that write (FILE* use-after-free / wrong-fd
 * capture / tport corruption), and violates the doctrine (sofia_thread owns mutable signaling state).
 * FreeSWITCH routes siptrace/capture through nua_set_params, which sofia marshals onto the stack thread
 * the same way. The startup su_timer + `sofia reload` already run on sofia_thread and keep the direct call.
 * The task carries a COPY of the new value; the root callback commits sofia_cfg + applies, all on
 * sofia_thread. Returns 0 on dispatch, -1 on failure (caller reports the CLI error). */
struct sofia_capture_task {
	int is_hep;		/* 1 = HEP capture address, 0 = file dump path */
	char value[512];	/* new path / host:port; "" = disable */
};
static void sofia_apply_capture_root(void *data)
{
	struct sofia_capture_task *t = data;
	if (t->is_hep) {
		ast_copy_string(sofia_cfg.sip_capture_address, t->value, sizeof(sofia_cfg.sip_capture_address));
	} else {
		ast_copy_string(sofia_cfg.sip_capture_file, t->value, sizeof(sofia_cfg.sip_capture_file));
	}
	sofia_apply_capture();
	ast_free(t);
}
int sofia_apply_capture_from_cli(int is_hep, const char *value)
{
	struct sofia_capture_task *t = ast_calloc(1, sizeof(*t));
	if (!t) {
		return -1;
	}
	t->is_hep = is_hep;
	if (value) {
		ast_copy_string(t->value, value, sizeof(t->value));
	}
	if (sofia_dispatch_to_root_thread(sofia_apply_capture_root, t) < 0) {
		ast_free(t);
		return -1;
	}
	return 0;
}

/* Apply the tport TPTAG_LOG toggle on the sofia_thread. tport_set_params mutates the SHARED
 * nta/tport stack state, so — like the capture toggle above — it must NOT be called from the CLI
 * thread; sofia_apply_log_from_cli marshals here. */
static void sofia_apply_log_root(void *data)
{
	int on = *(int *)data;
	ast_free(data);
	if (sofia_nua) {
		tport_set_params(nta_agent_tports(nua_get_agent(sofia_nua)), TPTAG_LOG(on), TAG_END());
	}
}

int sofia_apply_log_from_cli(int on)
{
	int *val = ast_malloc(sizeof(*val));
	if (!val) {
		return -1;
	}
	*val = on;
	if (sofia_dispatch_to_root_thread(sofia_apply_log_root, val) < 0) {
		ast_free(val);
		return -1;
	}
	return 0;
}

/* Apply a parsed sofia.conf to the live sofia_cfg + peers state. Shared by the init path
 * (sofia_load_config) and the reload worker. Caller owns cfg — do NOT destroy here. Returns 0,
 * or -1 on a hard failure that leaves live state partially mutated (caller logs + bails). */
static int sofia_apply_config(struct ast_config *cfg)
{
	char *cat;

	/* Drain the global domain_list before re-populating it, else a domain removed from
	 * sofia.conf would stay allowed until unload (stale + a security concern). No-op on init. */
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
	/* chan_sip DEFAULT_CALLERID parity (sip.h:200) — fallback From identity, never the peer name. */
	ast_copy_string(sofia_cfg.default_callerid, "gabpbx", sizeof(sofia_cfg.default_callerid));
	/* Default User-Agent e.g. "GABpbx PBX 2.7.1"; [general] useragent= overrides. */
	snprintf(sofia_cfg.useragent, sizeof(sofia_cfg.useragent), "%s %s",
		DEFAULT_USERAGENT, ast_get_version());
	sofia_cfg.allowguest = 1;
	/* connection keepalive OFF by default (opt-in). */
	sofia_cfg.tcp_keepalive_ms = 0;
	sofia_cfg.tcp_pingpong_ms = 0;
	/* TLS hardening knobs unset by default (opt-in). */
	sofia_cfg.tls_ciphers[0] = '\0';
	sofia_cfg.tls_min_version[0] = '\0';
	sofia_cfg.tls_verify_depth = 0;
	/* Transport enable flags default ON (1): a listener is built when (enable && bindport>0), so a
	 * config that only sets the bindports keeps its current behavior; tlsenable/wsenable/wssenable=no
	 * is the explicit opt-out (honored even when the bindport is set). chan_sip parity. */
	sofia_cfg.tls_enable = 1;
	sofia_cfg.ws_enable = 1;
	sofia_cfg.wss_enable = 1;
	/* Local anti-abuse blacklist ban/decay window resets to its 24h default each (re)load;
	 * sofia.conf `blacklist_ban` (in minutes) overrides it below. */
	sofia_blacklist_set_ban_minutes(-1);
	/* Optional real CA file (soft-linked to <certdir>/cafile.pem at NUA create); empty by default. */
	sofia_cfg.tlscafile[0] = '\0';
	/* outbound PUBLISH (RFC 3903) off by default (publish_server empty = feature OFF). */
	sofia_cfg.publish_server[0] = '\0';
	sofia_cfg.publish_expires = 0;
	sofia_cfg.publish_domain[0] = '\0';
	sofia_cfg.publish_username[0] = '\0';
	sofia_cfg.publish_password[0] = '\0';
	sofia_cfg.publish_format = SOFIA_SUB_DIALOG_INFO;
	sofia_cfg.publish_transport[0] = '\0';	/* empty -> udp at use (no-op append), so existing configs stay byte-identical */
	sofia_cfg.busy_on_active = 0;
	sofia_cfg.default_nat = SOFIA_NAT_FORCE_RPORT;	/* [general] nat default; force_rport = chan_sip parity, preserves behavior when [general] nat is unset */
	sofia_cfg.max_contacts = 6;
	sofia_cfg.encryption = 0;
	/* WebRTC (DTLS-SRTP + ICE-lite + rtcp-mux) is OFF by default; [general] webrtc=yes opts in and
	 * per-peer webrtc= overrides. RESET here in the compiled-default block so a `sip reload` that DROPS
	 * webrtc=yes from [general] actually disables it — without this the live sofia_cfg.webrtc stayed
	 * sticky across a reload (peers re-inherit it in sofia_peer_set_defaults; an explicit peer webrtc= still wins). */
	sofia_cfg.webrtc = 0;
	/* WebRTC DataChannel general default OFF; RESET here so a `sip reload` that DROPS
	 * datachannel=yes from [general] actually disables it (mirrors sofia_cfg.webrtc above). An
	 * explicit per-peer datachannel= still wins. */
	sofia_cfg.datachannel = 0;
	/* RFC 5626 flow-close: general default OFF (silent removal); an omitted [general] reverts on `sip reload`. */
	sofia_cfg.flowclose_emit_unregister = 0;
	/* empty default = sdp_crypto.c fallback (AES_CM_128_HMAC_SHA1_80). */
	sofia_cfg.default_srtpcipher[0] = '\0';
	/* default 0 = shared-key mode. Module-scope mirror reset for sdp_crypto.c extern visibility. */
	sofia_cfg.srtp_per_suite_keys = 0;
	sofia_srtp_per_suite_keys = 0;
	/* default 0 = per-peer insecure=invite bypass active; force_invite_auth=yes locks it down. */
	sofia_cfg.force_invite_auth = 0;
	/* default 0 = use SOFIA_NONCE_TTL_SEC_DEFAULT (3600s). */
	sofia_cfg.nonce_ttl_seconds = 0;
	/* default BOTH = offer MD5 + SHA-256 (shipped sofia.conf sets md5). */
	sofia_cfg.auth_algorithms = SOFIA_AUTH_ALG_BOTH;
	/* default 0 = chan_sip legacy no-qop MD5 challenge (RFC 2069, no replay protection);
	 * auth_qop=yes restores the RFC 2617/7616 qop="auth" form. */
	sofia_cfg.auth_qop = 0;
	/* session timers (RFC 4028). */
	sofia_cfg.default_session_timers = SESSION_TIMERS_ACCEPT; /* honor inbound; no initiate */
	sofia_cfg.default_session_expires = 1800;                  /* RFC 4028 §4 typical */
	sofia_cfg.default_session_minse = 90;                      /* RFC 4028 §3 floor */
	sofia_cfg.default_session_refresher = SESSION_REFRESHER_AUTO;
	sofia_cfg.default_allowtransfer = TRANSFER_OPENFORALL;
	/* per-peer allowsubscribe default TRUE; the derived global ban-all flag starts FALSE and is
	 * flipped by sofia_post_config_derive_allowsubscribe. */
	sofia_cfg.default_allowsubscribe = 1;
	sofia_cfg.allowsubscribe = 0;
	/* empty regcontext = mechanism disabled. */
	sofia_cfg.regcontext[0] = '\0';
	sofia_cfg.regextenonqualify = 0;
	sofia_cfg.default_subscribecontext[0] = '\0';
	sofia_cfg.message_context[0] = '\0';   /* SIP SIMPLE messaging OFF by default (opt-in). */
	sofia_cfg.message_autorelay = 1;       /* native peer-to-peer MESSAGE relay ON by default. */
	/* registration TTL bounds + 423 Interval Too Brief (60/3600/120). */
	sofia_cfg.min_expiry     = DEFAULT_MIN_EXPIRY;
	sofia_cfg.max_expiry     = DEFAULT_MAX_EXPIRY;
	sofia_cfg.default_expiry = DEFAULT_DEFAULT_EXPIRY;
	sofia_cfg.default_usereqphone = 0;
	/* RFC 3261 §20.22 default 70. */
	sofia_cfg.default_max_forwards = DEFAULT_MAX_FORWARDS;
	/* RFC 3261 §17.1.1.2 minimum bound, default 100ms. */
	sofia_cfg.t1min = DEFAULT_T1MIN;
	sofia_cfg.relaxdtmf = 0;
	sofia_cfg.prematuremediafilter = 1;
	/* register_timeout=20s; register_attempts=0 (unlimited). */
	sofia_cfg.register_timeout = DEFAULT_REGISTRATION_TIMEOUT;
	sofia_cfg.register_attempts = 0;
	/* parse-compatibility only — experimental, effect-deferred. */
	sofia_cfg.directrtpsetup = 0;
	/* default TRUE: RFC 3261 §22.4 username-enumeration prevention active out-of-the-box. */
	sofia_cfg.alwaysauthreject = 1;
	/* parse-compatibility only — native compact-emit gate absent. */
	sofia_cfg.compactheaders = 0;
	/* empty default (chan_sofia uses NUTAG_APPL_METHOD for unknown-method gating). */
	sofia_cfg.disallowed_methods[0] = '\0';
	/* clear the contactpermit/contactdeny ACL chain on each load. */
	ast_rwlock_wrlock(&sofia_contactha_lock);
	if (sofia_cfg.contact_ha) {
		ast_free_ha(sofia_cfg.contact_ha);
		sofia_cfg.contact_ha = NULL;
	}
	ast_rwlock_unlock(&sofia_contactha_lock);
	/* MWI defaults (RFC 3842). */
	sofia_cfg.mwi_from[0] = '\0';
	ast_copy_string(sofia_cfg.notifymime, "application/simple-message-summary", sizeof(sofia_cfg.notifymime));
	ast_copy_string(sofia_cfg.vmexten, "asterisk", sizeof(sofia_cfg.vmexten));
	sofia_cfg.mwi_expiry = 3600;
	sofia_cfg.outboundproxy[0] = '\0';
	/* Default minimum TLS to 1.2 (enables TLS 1.2 + 1.3). Sofia's tport default when TPTAG_TLS_VERSION is left
	 * unset is TLS 1.3-ONLY, which rejects the many SIP endpoints that cap at TLS 1.2 — the server aborts the
	 * ClientHello with a protocol_version alert and the registration/handshake never completes. A deployment
	 * can still pin a stricter floor with tls_min_version=1.3. */
	ast_copy_string(sofia_cfg.tls_min_version, DEFAULT_TLS_MIN_VERSION, sizeof(sofia_cfg.tls_min_version));
	sofia_cfg.default_language[0] = '\0';
	/* default "default"; behavior change from the silent-empty baseline (parkinglot= empty restores). */
	ast_copy_string(sofia_cfg.default_parkinglot, "default", sizeof(sofia_cfg.default_parkinglot));
	/* default FALSE: expired contacts removed by sofia_expire_contacts_cb. */
	sofia_cfg.ignore_regexpire = 0;
	/* default 384 kbps — every video SDP emits b=CT:384 (maxcallbitrate=0 restores no-b=CT). */
	sofia_cfg.default_maxcallbitrate = 384;
	sofia_cfg.match_auth_username = 0;
	/* parse-compatibility only. */
	sofia_cfg.legacy_useroption_parsing = 0;
	/* default 1; behavior change from the no-normalization baseline. */
	sofia_cfg.shrinkcallerid = 1;
	/* default 1 = chan_sip parity: force matched-peer callerid on inbound when no trusted RPID/PAI. */
	sofia_cfg.apply_peer_callerid = 1;
	/* gates the peer->onHold counter update; AMI Hold emission is unconditional. */
	sofia_cfg.notifyhold = 0;
	sofia_cfg.use_q850_reason = 0;	/* RFC 3326 Q.850 Reason on BYE/CANCEL + INVITE rejects; opt-in (chan_sip parity) */
	/* parse-compatibility only — effect deferred until presence/dialog-info NOTIFY lands. */
	sofia_cfg.notifyringing = 1;
	/* Security hardening: peer-build appends static IPs as deny rules to contact_ha. */
	sofia_cfg.dynamic_exclude_static = 0;
	/* parse-compatibility only — refuses to auto-create unknown peers. */
	sofia_cfg.autocreatepeer = 0;
	/* codec-list-narrowing implemented at sofia_generate_sdp, direction-symmetric. */
	sofia_cfg.default_preferred_codec_only = 0;
	/* default NEVER. Partial implementation at sofia_indicate AST_CONTROL_RINGING (YES state). */
	sofia_cfg.default_progressinband = SOFIA_PROG_INBAND_NEVER;
	/* parse-compatibility only — nua_r_redirect handler absent. */
	sofia_cfg.default_promiscredir = 0;
	/* parse-compatibility only — sofia_parse_sdp ptime gate not implemented. */
	sofia_cfg.default_autoframing = 0;
	/* default NONE; covers DSP CNG + peer T.38 reINVITE detection. */
	sofia_cfg.default_faxdetect_mode = SOFIA_FAX_DETECT_NONE;
	/* T38FaxMaxDatagram sentinel -1 = use built-in 200-byte default. */
	sofia_cfg.default_t38_maxdatagram = SOFIA_T38_MAXDATAGRAM_SENTINEL;
	/* default 32000ms (= 64 * DEFAULT_TIMER_T1); implemented via NTATAG_SIP_T1X64. */
	sofia_cfg.default_timer_b = 32000;
	/* default 500ms; implemented via NTATAG_SIP_T1. */
	sofia_cfg.default_timer_t1 = 500;
	/* cleared here; set when the key is parsed; consumed at the timer cross-validation below. */
	sofia_timerb_set = 0;
	sofia_timert1_set = 0;
	/* default YES; implemented at 3 sites (process_invite + indicate INCOMPLETE + nua_r_invite 484). */
	sofia_cfg.default_allowoverlap_mode = SOFIA_OVERLAP_YES;
	/* parse-compatibility only — network-change handled by sofia-sip + per-peer dnsmgr. */
	sofia_cfg.subscribe_network_change_event = 1;
	/* Implemented at the sofia_process_register ast_update_realtime callsites. */
	sofia_cfg.rtsave_sysname = 0;
	/* Gates the realtime peer updates in sofia_process_register. */
	sofia_cfg.peer_rtupdate = 1;
	/* Register pool: default OFF + auto lane count. */
	sofia_cfg.register_pool = 0;
	sofia_cfg.register_pool_workers = 0;
	/* parse-compatibility only — the ao2 registry always caches all peers. */
	sofia_cfg.rtcachefriends = 0;
	/* parse-compatibility only — no peer-level auto-clear. */
	sofia_cfg.rtautoclear = 120;
	sofia_cfg.rtautoclear_enabled = 0;
	/* Implemented at the auth-challenge callsites via sofia_get_realm_for_dialog. */
	sofia_cfg.domainsasrealm = 0;
	/* default TRUE; safety-net auto-set at the end of sofia_load_config. */
	sofia_cfg.allow_external_domains = 1;
	/* Auto-add fires at sofia_load_config conclusion, AFTER the allowexternaldomains special-case. */
	sofia_cfg.autodomain = 0;
	/* parse-compatibility only — sofia_should_use_externaddr signature diverges. */
	sofia_cfg.matchexternaddrlocally = 0;
	/* Reset the externaddr/externhost NAT bundle + localnet so a REMOVED line doesn't keep the
	 * stale public IP/port (calls would advertise the old NAT address). localha is freed+rebuilt
	 * below; externexpire/externrefresh are the DDNS lazy-refresh pair. */
	sofia_cfg.externaddr[0] = '\0';
	sofia_cfg.externhost[0] = '\0';
	sofia_cfg.externtcpport = 0;
	sofia_cfg.externtlsport = 0;
	sofia_cfg.externexpire = 0;
	sofia_cfg.externrefresh = 10;
	sofia_cfg.localnet[0] = '\0';
	sofia_cfg.media_address[0] = '\0';
	/* Live SIP tracing: default OFF. Cleared before the re-parse so a reload that REMOVES the option
	 * disables capture (empty address/file = OFF; hep/id back to defaults). */
	sofia_cfg.sip_capture_address[0] = '\0';
	sofia_cfg.sip_capture_file[0] = '\0';
	sofia_cfg.sip_capture_hep = 3;
	sofia_cfg.sip_capture_id = 200;
	/* rtp-timeout bundle: default 0 (disabled); sofia_rtp_init wires set_*timeout when non-zero. */
	sofia_cfg.default_rtptimeout = 0;
	sofia_cfg.default_rtpholdtimeout = 0;
	sofia_cfg.default_rtpkeepalive = 0;
	/* tos/cos bundle: default 0 (no QoS). tos_sip via TPTAG_TOS; audio/video via set_qos.
	 * cos_sip + tos_text + cos_text are parse-compatibility only (TPTAG_COS + text-RTP absent). */
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
	/* reload-UAF: serialize the free+NULL vs channel-thread readers of sofia_cfg.localha. */
	ast_rwlock_wrlock(&sofia_localha_lock);
	ast_free_ha(sofia_cfg.localha);
	sofia_cfg.localha = NULL;
	ast_rwlock_unlock(&sofia_localha_lock);

	sofia_parse_general_config(cfg);

	/* Push the (possibly changed) SIP-capture config onto the tport layer. No-op on the initial load
	 * (sofia_nua not yet created — the startup path applies it after nua_create); on `sip reload` this
	 * enables/disables/retargets the HEP capture + file dump live. */
	sofia_apply_capture();

	for (cat = ast_category_browse(cfg, NULL); cat; cat = ast_category_browse(cfg, cat)) {
		if (!strcasecmp(cat, "general") || !strcasecmp(cat, "authentication")) {
			continue;
		}
		sofia_parse_peer_config(cat, cfg);
	}

	/* Timer cross-validation. Order matters — BEFORE nua_create reads the timers. */
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

	/* autodomain: auto-add listening-addresses + FQDN to domain_list. Order matters —
	 * BEFORE the allowexternaldomains special-case so it sees domain_list as non-empty. */
	if (sofia_cfg.autodomain) {
		char temp[MAXHOSTNAMELEN];
		if (!ast_strlen_zero(sofia_cfg.bindaddr)
		    && strcmp(sofia_cfg.bindaddr, "0.0.0.0") != 0) {
			sofia_domain_list_add(sofia_cfg.bindaddr);
		}
		if (!ast_strlen_zero(sofia_cfg.tlsbindaddr)
		    && strcmp(sofia_cfg.tlsbindaddr, "0.0.0.0") != 0) {
			sofia_domain_list_add(sofia_cfg.tlsbindaddr);
		}
		if (!ast_strlen_zero(sofia_cfg.wsbindaddr)
		    && strcmp(sofia_cfg.wsbindaddr, "0.0.0.0") != 0) {
			sofia_domain_list_add(sofia_cfg.wsbindaddr);
		}
		if (!ast_strlen_zero(sofia_cfg.externaddr)) {
			sofia_domain_list_add(sofia_cfg.externaddr);
		}
		if (!gethostname(temp, sizeof(temp))) {
			sofia_domain_list_add(temp);
		}
	}

	/* allowexternaldomains safety net: if disabled but no domain= entries, revert to allow + warn. */
	if (!sofia_cfg.allow_external_domains && AST_LIST_EMPTY(&domain_list)) {
		ast_log(LOG_WARNING, "Sofia: allowexternaldomains=no but no domain= entries configured; reverting to allow=yes\n");
		sofia_cfg.allow_external_domains = 1;
	}

	sofia_post_config_derive_allowsubscribe();

	/* Create/toggle the bounded REGISTER pool per config. */
	sofia_regpool_update();

	return 0;
}

/* Init-path wrapper: load sofia.conf and hand it to sofia_apply_config. Only called from
 * load_module(); the reload path goes through sofia_reload_request_sync. `reload` is always 0
 * on a clean init (1 would short-circuit on FILEUNCHANGED). */
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

static void sofia_peer_recreate_register_handle(struct sofia_peer *peer);	/* defined below sofia_reg_thread_func */

static void *sofia_reg_thread_func(void *data)
{
	while (sofia_nua) {
		struct ao2_iterator i;
		struct sofia_peer *peer;
		time_t now;

		/* Interval between register-retry passes; default 20s, > 0 guards a bad config. */
		sleep(sofia_cfg.register_timeout > 0 ? sofia_cfg.register_timeout : DEFAULT_REGISTRATION_TIMEOUT);

		if (!sofia_nua) {
			break;
		}

		now = time(NULL);
		i = ao2_iterator_init(peers, 0);
		while ((peer = ao2_iterator_next(&i))) {
			/* Evaluate the whole gate under peer->lock so the pre-check sees the same
			 * values the response handler / reload write under it (nh / reg_expiry /
			 * reg_attempts / secret / host). */
			ast_mutex_lock(&peer->lock);
			if (peer->is_register_line &&
			    peer->nh && peer->reg_expiry > 0 &&
			    !ast_strlen_zero(peer->secret) &&
			    strcasecmp(peer->host, "dynamic") != 0 &&
			    /* attempt-cap: skip when register_attempts > 0 and the cap is reached. */
			    (sofia_cfg.register_attempts == 0 || peer->reg_attempts < sofia_cfg.register_attempts) &&
			    now >= peer->reg_expiry) {
				char uri[256];
				/* sip:user@host:port + ;transport= (UDP no-op); opt-in via is_register_line. */
				sofia_build_register_uri(peer, uri, sizeof(uri));
				if (sofia_debug)
					ast_verbose("Sofia: Re-registering %s\n", uri);
				/* RFC 3261 §20.22 outbound REGISTER refresh. */
				char mf_str_reregister[8];
				char instance_feature_rereg[120];
				snprintf(mf_str_reregister, sizeof(mf_str_reregister), "%d", peer->maxforwards);
				/* GRUU: re-advertise +sip.instance. */
				sofia_build_instance_feature(peer, instance_feature_rereg, sizeof(instance_feature_rereg), peer->sip_outbound);
				/* A reload that toggled gruu/sip_outbound left stale merged Supported/M_FEATURES on
				 * peer->nh (NUTAG_SUPPORTED only merges); rebuild the handle with the CURRENT tags before
				 * this refresh so a disabled knob stops advertising (RFC 5626/5627). */
				if (peer->reg_handle_dirty) {
					sofia_peer_recreate_register_handle(peer);
					peer->reg_handle_dirty = 0;
				}
				/* callbackextension: NUTAG_M_USERNAME override (as at initial register). */
				nua_register(peer->nh,
					NUTAG_URL(uri),
					SIPTAG_FROM_STR(uri),
					SIPTAG_MAX_FORWARDS_STR(mf_str_reregister),
					TAG_IF(!ast_strlen_zero(peer->callbackextension),
						NUTAG_M_USERNAME(peer->callbackextension)),
					TAG_IF(peer->gruu || peer->sip_outbound, NUTAG_M_FEATURES(instance_feature_rereg)),
					TAG_IF(peer->sip_outbound, NUTAG_SUPPORTED("outbound, path")),	/* RFC 5626 §4.2.1 */
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

/* Build/rebuild a peer's outbound-REGISTER handle (peer->nh) from its CURRENT config: detach + destroy
 * any prior handle (so a late 401/200 can't re-enter the register state machine against the stale
 * handle) and create a fresh one carrying the current GRUU/SIP-Outbound advertisement tags. Used at load
 * (sofia_do_register) and when a reload toggled gruu/sip_outbound (reg_handle_dirty) — NUTAG_SUPPORTED
 * merges on a handle, so a stale outbound/gruu advertisement can only be dropped by recreating peer->nh.
 * Reads peer fields the caller already serializes; runs on the load/reg thread (nua_handle posts to
 * sofia_thread). */
static void sofia_peer_recreate_register_handle(struct sofia_peer *peer)
{
	char uri[256], route_buf[256], instance_feature[120];

	sofia_build_register_uri(peer, uri, sizeof(uri));
	sofia_format_outboundproxy(peer, route_buf, sizeof(route_buf));
	sofia_build_instance_feature(peer, instance_feature, sizeof(instance_feature), peer->sip_outbound);

	if (peer->nh) {
		nua_handle_t *old_rnh = peer->nh;
		peer->nh = NULL;
		nua_handle_bind(old_rnh, NULL);
		nua_handle_destroy(old_rnh);
	}
	peer->nh = nua_handle(sofia_nua, peer,
		NUTAG_URL(uri),
		SIPTAG_TO_STR(uri),
		TAG_IF(route_buf[0], NUTAG_INITIAL_ROUTE_STR(route_buf)),
		TAG_IF(peer->gruu || peer->sip_outbound, NUTAG_M_FEATURES(instance_feature)),
		TAG_IF(peer->sip_outbound, NUTAG_SUPPORTED("outbound, path")),	/* RFC 5626 §4.2.1 */
		TAG_IF(peer->gruu, NUTAG_SUPPORTED("gruu")),	/* RFC 5627 §4.1 */
		TAG_END());
}

static void sofia_do_register(void)
{
	struct ao2_iterator i;
	struct sofia_peer *peer;
	char uri[256];

	i = ao2_iterator_init(peers, 0);
	while ((peer = ao2_iterator_next(&i))) {
		if (peer->type == SOFIA_TYPE_FRIEND || peer->type == SOFIA_TYPE_PEER) {
			/* Outbound REGISTER is opt-in: ONLY a [general] `register =>` line sets
			 * is_register_line. A static challenge-auth trunk (secret + static host but
			 * NO register=> line) is a UAS-style peer — it must NOT be sent a REGISTER. */
			if (peer->is_register_line &&
			    !ast_strlen_zero(peer->secret) &&
			    !ast_strlen_zero(peer->host) &&
			    strcasecmp(peer->host, "dynamic") != 0) {
				/* sip:user@host:port + ;transport= for tls/tcp/ws/wss (UDP no-op). */
				sofia_build_register_uri(peer, uri, sizeof(uri));

				/* Detach+destroy any stale handle and create a fresh one carrying the current
				 * GRUU/SIP-Outbound advertisement tags — single source of truth for the tag set,
				 * shared with the reload-dirty rebuild path. */
				sofia_peer_recreate_register_handle(peer);

				/* The same +sip.instance/reg-id advertisement also rides the REGISTER request below. */
				char instance_feature[120];
				sofia_build_instance_feature(peer, instance_feature, sizeof(instance_feature), peer->sip_outbound);

				/* RFC 3261 §20.22 outbound REGISTER. */
				char mf_str_initreg[8];
				snprintf(mf_str_initreg, sizeof(mf_str_initreg), "%d", peer->maxforwards);
				/* callbackextension: NUTAG_M_USERNAME drives the Contact URL username. */
				nua_register(peer->nh,
					NUTAG_URL(uri),
					SIPTAG_FROM_STR(uri),
					SIPTAG_MAX_FORWARDS_STR(mf_str_initreg),
					TAG_IF(!ast_strlen_zero(peer->callbackextension),
						NUTAG_M_USERNAME(peer->callbackextension)),
					TAG_IF(peer->gruu || peer->sip_outbound, NUTAG_M_FEATURES(instance_feature)),
					TAG_IF(peer->sip_outbound, NUTAG_SUPPORTED("outbound, path")),	/* RFC 5626 §4.2.1 */
					TAG_END());

				if (sofia_debug) {
					ast_verbose("Sofia: Registering %s\n", uri);
				}
			}
		}
		ao2_ref(peer, -1);
	}
	ao2_iterator_destroy(&i);
}

/* Post a callback to run on sofia_thread (where sofia_root was created). nua_handle ops MUST run
 * there per sofia-sip's same-thread-as-create contract. Caller: data lifetime must outlast the
 * dispatch (heap-allocate, callback frees); NULL ok if ignored. Returns 0/-1; does NOT block. */
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
 *  Reload work is dispatched ONTO sofia_thread (the NUA event loop) via
 *  sofia_dispatch_to_root_thread, so the single consumer of sofia_cfg / peers /
 *  peer->fields is blocked inside the worker and there is no concurrent reader —
 *  the old in-caller-thread path had real UAF races (localha / contact_ha freed
 *  mid-iteration, chanvars destroyed without peer->lock). The CLI caller posts and
 *  blocks on a condvar with a 30s deadline.
 *
 *  Listener-baked fields (12 fields fixed at nua_create — bindaddr/port, tls*, ws*,
 *  timert1/timerb) are pre-validated BEFORE any sofia_cfg mutation: any diff aborts
 *  with a clear error, since silently recreating the NUA listener would either lie or
 *  kill every active call + TLS connection.
 *
 *  Stale peers (removed from sofia.conf) are mark-and-swept inside the worker:
 *  marked before re-parsing, unmarked per parsed [section], swept at the end.
 *  Realtime peers are exempt (per-lookup lifecycle, not file-driven).
 * ========================================================================= */

AST_MUTEX_DEFINE_STATIC(sofia_reload_lock);

/* Forward decl: the apply-config helper shared by load_module and the reload worker. */
static int sofia_apply_config(struct ast_config *cfg);

struct sofia_reload_req {
	ast_mutex_t mutex;
	ast_cond_t  cond;
	int         done;
	int         result;     /* 0 = OK, -1 = error */
	/* Worker writes the reason here under req->mutex; caller copies it out under req->mutex.
	 * Lives inside the ref-protected struct — on timeout the caller frame unwinds while the
	 * worker still holds a ref, so a borrowed stack pointer would dangle. */
	char        errmsg[256];
};

static void sofia_reload_req_destructor(void *obj)
{
	struct sofia_reload_req *req = obj;
	ast_cond_destroy(&req->cond);
	ast_mutex_destroy(&req->mutex);
}

/* Compare the listener-baked fields in cfg against live sofia_cfg. Returns 1 if any differs
 * (reload refused), 0 if all match. Does NOT mutate sofia_cfg. On change, fills `errmsg` with the
 * comma-separated changed keys. */
static int sofia_reload_listener_changed(struct ast_config *cfg,
		char *errmsg, size_t errmsglen)
{
	/* Build a SCRATCH listener config from compiled defaults + only the listener keys the new
	 * file carries (mirroring sofia_parse_general_config: udpbindaddr split, the tlscertdir /
	 * tlsverifyserver aliases, t1min/timerb/timert1 cross-validation), then compare to live
	 * sofia_cfg. This catches a REMOVED key (surfaces as default-vs-live) — a per-present-key
	 * compare would miss it. A flat {key, default} table can't, because of the aliases and
	 * because t1min canonically rewrites the effective timers. */
	struct {
		char bindaddr[128];
		int bindport;
		char tlsbindaddr[64];
		int tlsbindport;
		int tls_enable;		/* tlsenable=; a change forces a listener recreate (gate baked into nua_create) */
		char tlscertfile[256];
		char tlscafile[256];	/* a change forces a listener recreate (cafile.pem alias rebuilt at NUA create) */
		char wsbindaddr[64];
		int wsbindport;
		int ws_enable;		/* wsenable=; a change forces a listener recreate */
		char wssbindaddr[64];
		int wssbindport;
		int wss_enable;		/* wssenable=; a change forces a listener recreate */
		int tlsverify;
		int tlsverifyclient;	/* mTLS toggle; a change forces a listener recreate */
		char tls_ciphers[256];	/* a change forces a listener recreate (TLS ctx built at listener create) */
		char tls_min_version[8];
		int tls_verify_depth;
		int t1min;
		int timer_t1;
		int timer_b;
		int tcp_keepalive_ms;	/* a change forces a listener recreate (TPTAG set at nua_create) */
		int tcp_pingpong_ms;
	} s;
	int timert1_set = 0, timerb_set = 0;
	struct ast_variable *v;
	char buf[256];
	int changed = 0;
	int written = 0;

	buf[0] = '\0';

	/* Compiled defaults (identical to a fresh load). Using fresh defaults rather than live
	 * sofia_cfg is exactly what lets a removed key be detected. */
	ast_copy_string(s.bindaddr, DEFAULT_BINDADDR, sizeof(s.bindaddr));
	s.bindport = DEFAULT_SIP_PORT;
	s.tlsbindaddr[0] = '\0';
	s.tlsbindport = 0;
	s.tls_enable = 1;
	s.tlscertfile[0] = '\0';
	s.tlscafile[0] = '\0';
	s.wsbindaddr[0] = '\0';
	s.wsbindport = 0;
	s.ws_enable = 1;
	s.wssbindaddr[0] = '\0';
	s.wssbindport = 0;
	s.wss_enable = 1;
	/* NOTE: blacklist_ban is NOT a listener key and is applied by sofia_apply_config (which resets to the
	 * 24h default then re-applies) ONLY when the reload proceeds — this compare-only function must not touch
	 * the live blacklist, else a REFUSED reload (listener change → restart required) would still mutate it. */
	s.tlsverify = 0;
	s.tlsverifyclient = 0;
	s.tls_ciphers[0] = '\0';
	/* Must mirror the EFFECTIVE load-time default: sofia_apply_config clears tls_min_version first, then
	 * seeds it to DEFAULT_TLS_MIN_VERSION later — so the final effective default is 1.2, not empty. If
	 * this scratch started empty, a config with no tls_min_version= line would read live="1.2" vs
	 * scratch="" and every reload would flag a phantom listener change, refusing reload until a restart. */
	ast_copy_string(s.tls_min_version, DEFAULT_TLS_MIN_VERSION, sizeof(s.tls_min_version));
	s.tls_verify_depth = 0;
	s.t1min = DEFAULT_T1MIN;
	s.timer_t1 = 500;
	s.timer_b = 32000;
	s.tcp_keepalive_ms = 0;
	s.tcp_pingpong_ms = 0;

	for (v = ast_variable_browse(cfg, "general"); v; v = v->next) {
		if (!strcasecmp(v->name, "bindaddr")) {
			ast_copy_string(s.bindaddr, v->value, sizeof(s.bindaddr));
		} else if (!strcasecmp(v->name, "bindport") || !strcasecmp(v->name, "udpbindaddr")) {
			/* IPv6-aware host:port split (mirrors sofia_parse_general_config). */
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
		} else if (!strcasecmp(v->name, "tlsenable")) {
			s.tls_enable = ast_true(v->value);
		} else if (!strcasecmp(v->name, "tlscertfile") || !strcasecmp(v->name, "tlscertdir")) {
			ast_copy_string(s.tlscertfile, v->value, sizeof(s.tlscertfile));
		} else if (!strcasecmp(v->name, "tlscafile")) {
			ast_copy_string(s.tlscafile, v->value, sizeof(s.tlscafile));
		} else if (!strcasecmp(v->name, "tcp_keepalive")) {
			s.tcp_keepalive_ms = sofia_cfg_seconds_to_ms(v->value);
		} else if (!strcasecmp(v->name, "tcp_pingpong")) {
			s.tcp_pingpong_ms = sofia_cfg_seconds_to_ms(v->value);
		} else if (!strcasecmp(v->name, "tlsverify") || !strcasecmp(v->name, "tlsverifyserver")) {
			s.tlsverify = ast_true(v->value);
		} else if (!strcasecmp(v->name, "tlsverifyclient")) {
			s.tlsverifyclient = ast_true(v->value);
		} else if (!strcasecmp(v->name, "tls_ciphers")) {
			ast_copy_string(s.tls_ciphers, v->value, sizeof(s.tls_ciphers));
		} else if (!strcasecmp(v->name, "tls_min_version")) {
			/* mirror the live parser: only store a recognized value. */
			if (sofia_tls_min_version_valid(v->value)) {
				ast_copy_string(s.tls_min_version, v->value, sizeof(s.tls_min_version));
			}
		} else if (!strcasecmp(v->name, "tls_verify_depth")) {
			s.tls_verify_depth = sofia_cfg_verify_depth(v->value);
		} else if (!strcasecmp(v->name, "wsbindaddr")) {
			ast_copy_string(s.wsbindaddr, v->value, sizeof(s.wsbindaddr));
		} else if (!strcasecmp(v->name, "wsbindport")) {
			s.wsbindport = atoi(v->value);
		} else if (!strcasecmp(v->name, "wsenable")) {
			s.ws_enable = ast_true(v->value);
		} else if (!strcasecmp(v->name, "wssbindaddr")) {
			ast_copy_string(s.wssbindaddr, v->value, sizeof(s.wssbindaddr));
		} else if (!strcasecmp(v->name, "wssbindport")) {
			s.wssbindport = atoi(v->value);
		} else if (!strcasecmp(v->name, "wssenable")) {
			s.wss_enable = ast_true(v->value);
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

	/* Same timer cross-validation as sofia_apply_config so the EFFECTIVE (not raw) timers are
	 * compared. t1min is parsed into the scratch because it floors timer_t1 and seeds the
	 * timerb < 500 fallback, so a changed t1min shifts the effective timers baked at nua_create. */
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
	SOFIA_LISTENER_CMP_INT(tls_enable, "tlsenable");
	SOFIA_LISTENER_CMP_STR(tlscertfile, "tlscertfile");
	SOFIA_LISTENER_CMP_STR(tlscafile, "tlscafile");
	SOFIA_LISTENER_CMP_STR(wsbindaddr, "wsbindaddr");
	SOFIA_LISTENER_CMP_INT(wsbindport, "wsbindport");
	SOFIA_LISTENER_CMP_INT(ws_enable, "wsenable");
	SOFIA_LISTENER_CMP_STR(wssbindaddr, "wssbindaddr");
	SOFIA_LISTENER_CMP_INT(wssbindport, "wssbindport");
	SOFIA_LISTENER_CMP_INT(wss_enable, "wssenable");
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
	if (!!sofia_cfg.tlsverifyclient != !!s.tlsverifyclient) {
		SOFIA_LISTENER_FLAG("tlsverifyclient");
	}
	/* Compare tls_min_version as a STRING (its mask 0 for "1.3" collides with unset). */
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

/* Mark-and-sweep for reloading the peers container: mark sets a transient flag on every peer,
 * the re-parse clears it for survivors, sweep ao2_unlinks the still-marked (disappeared)
 * non-realtime peers. Realtime peers are skipped (per-lookup lifecycle). */
static int sofia_peer_mark_cb(void *obj, void *arg, int flags)
{
	struct sofia_peer *peer = obj;
	peer->_reload_marked = 1;
	return 0;
}

/* Deferred dialplan-hint removal node. ABBA fix (see sofia_peer_sweep_cb): the sweep runs UNDER the
 * peers ao2-container lock, but sofia_remove_peer_hints -> ast_context_remove_extension takes conlock,
 * giving peers->conlock. The reverse leg (dialplan merge wrlock_contexts -> ast_extension_state2 ->
 * sofia_devicestate -> ao2_find(peers)) is conlock->peers, so removing the hint inside the callback is
 * an ABBA deadlock. The callback instead COLLECTS bounded copies of each swept peer's hint spec into
 * this list, and the caller drains it AFTER the container lock is released. */
struct sofia_swept_hint {
	AST_LIST_ENTRY(sofia_swept_hint) list;
	char regexten[256];		/* a multi-token regexten SPEC — matches the 256 the splitter uses */
	char subscribecontext[AST_MAX_CONTEXT];
};
AST_LIST_HEAD_NOLOCK(sofia_swept_hint_list, sofia_swept_hint);

static int sofia_peer_sweep_cb(void *obj, void *arg, int flags)
{
	struct sofia_peer *peer = obj;
	struct sofia_swept_hint_list *hints = arg;	/* deferred hint-removal accumulator (may be NULL) */
	if (!peer->_reload_marked || peer->is_realtime) {
		return 0;
	}
	/* Drain MWI before the final unref so the destructor's drain can't resurrect the peer. */
	sofia_peer_drain_mwi(peer);
	/* ABBA fix: do NOT remove the dialplan hint here — we run UNDER the peers container lock and
	 * sofia_remove_peer_hints takes conlock (peers->conlock inverts the dialplan-merge conlock->peers
	 * leg). Snapshot the hint spec into the caller's list; the caller removes it after the container
	 * lock is dropped. (registrar matches sofia_create_peer_hint = "sofia_config_peer".) */
	if (hints && !ast_strlen_zero(peer->subscribecontext) && !ast_strlen_zero(peer->regexten)) {
		struct sofia_swept_hint *h = ast_calloc(1, sizeof(*h));
		if (h) {
			ast_copy_string(h->regexten, peer->regexten, sizeof(h->regexten));
			ast_copy_string(h->subscribecontext, peer->subscribecontext, sizeof(h->subscribecontext));
			AST_LIST_INSERT_HEAD(hints, h, list);
		} else {
			/* OOM: do NOT remove the hint here - that takes conlock UNDER the peers lock, the exact
			 * peers->conlock ABBA this fix removes. Log + leave the stale BLF hint;
			 * the next reload / CLI cleanup reaps it. A leaked hint is strictly better than reintroducing
			 * the deadlock on the OOM path. */
			ast_log(LOG_WARNING, "Sofia: OOM deferring hint removal for swept peer '%s' (exten %s@%s); "
				"stale BLF hint left for the next reload\n",
				peer->name, peer->regexten, peer->subscribecontext);
		}
	}
	/* Release dnsmgr + drop its +1 ref FIRST, else the destructor never runs (its ref pins
	 * refcount >= 1 after ao2_unlink). Atomic detach-under-lock + release-outside (the helper
	 * takes peer->lock briefly, before the reg/qualify teardown below re-takes it). */
	sofia_peer_release_dnsmgr(peer, 1);
	/* Destroy the REGISTER + qualify handles synchronously — this runs on sofia_thread, so
	 * the same-thread-as-create constraint holds. bind(NULL) before each destroy detaches
	 * hmagic so late events skip. Under peer->lock vs the reg/qualify aux readers; bind/destroy
	 * are non-blocking posts, so holding the lock is safe. */
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
	/* CMP_MATCH -> ao2_unlink; the destructor (now reachable) frees the ACLs/contacts/chanvars/etc. */
	return CMP_MATCH;
}

/* Release dnsmgr + drop its +1 ref for EVERY peer unconditionally (no mark/realtime gate, unlike
 * sofia_peer_sweep_cb). Used only by load_module's err_cleanup: the container ref is about to drop,
 * but a dnsmgr ref would pin refcount >= 1 and leak the peer + res_dnsmgr entry. sofia_peer_release_dnsmgr
 * detaches under peer->lock then releases OUTSIDE it (ast_dnsmgr_release blocks on the dnsmgr list lock
 * vs the peer->lock-taking callback). Safe after sofia_thread is joined — it touches only res_dnsmgr's list. */
static int sofia_peer_dnsmgr_release_cb(void *obj, void *arg, int flags)
{
	struct sofia_peer *peer = obj;
	/* Drain MWI unconditionally (a peer may have mailboxes but no dnsmgr). */
	sofia_peer_drain_mwi(peer);
	sofia_peer_release_dnsmgr(peer, 1);
	return 0;
}

/* Forward decl; body further down. */
static void sofia_reload_worker(void *data);

/* Synchronous reload invoker (CLI / AMI / .reload hook). Posts the request onto sofia_thread,
 * then blocks on a condvar with a 30s deadline. Returns 0/-1 (the worker records the reason in
 * req->errmsg, copied out before returning).
 *
 * Refcount: req is ao2_alloc'd refcount 1 (caller's); +1 for the worker before dispatch; both
 * dropped on dispatch failure. The worker drops its ref at the end of its body; whichever runs
 * last frees the struct. Safe under timeout because cond/mutex + errmsg all live in the
 * ref-protected struct (the worker writes req->errmsg under req->mutex, the caller copies it out
 * under req->mutex — never a borrowed caller stack pointer). */
int sofia_reload_request_sync(char *errmsg, size_t errmsglen, int timeout_ms)
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
			/* Write the reason into req->errmsg (ref-protected struct, not the caller's stack
			 * which unwinds on timeout while the worker still holds a ref). */
			if (req->errmsg[0] == '\0') {
				snprintf(req->errmsg, sizeof(req->errmsg),
					"reload timed out after %d ms (sofia_thread busy)", timeout_ms);
			}
			break;
		}
	}
	result = req->done ? req->result : -1;
	/* Copy the worker's message out under req->mutex (serialized vs its write at signal_done). */
	if (errmsg && errmsglen > 0) {
		ast_copy_string(errmsg, req->errmsg, errmsglen);
	}
	ast_mutex_unlock(&req->mutex);

	ao2_ref(req, -1);  /* drop caller's ref; worker drops its own when it runs */
	ast_mutex_unlock(&sofia_reload_lock);
	return result;
}

/* The actual reload work — runs on sofia_thread (the single consumer of sofia_cfg / peers /
 * peer->fields), now blocked here, so there is no concurrent reader: ast_ha lists can be freed and
 * sofia_cfg overwritten in-place. Per-peer mutations still take peer->lock vs the aux threads
 * (sched / reg / qualify) that read peer state from outside sofia_thread. */
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

	/* Mark every peer; survivors clear their mark in sofia_parse_peer_config, the rest are swept. */
	ao2_callback(peers, OBJ_NODATA, sofia_peer_mark_cb, NULL);

	/* Snapshot the outbound-PUBLISH config BEFORE sofia_apply_config resets sofia_cfg, so the
	 * reconcile can tell ESC-target/domain/TTL change (full rebuild) from a publish=yes peer-set
	 * change (incremental). */
	{
		char pub_server_was[sizeof(sofia_cfg.publish_server)];
		char pub_domain_was[sizeof(sofia_cfg.publish_domain)];
		char pub_transport_was[sizeof(sofia_cfg.publish_transport)];
		int pub_expires_was = sofia_cfg.publish_expires;
		enum sofia_sub_format pub_format_was = sofia_cfg.publish_format;
		ast_copy_string(pub_server_was, sofia_cfg.publish_server, sizeof(pub_server_was));
		ast_copy_string(pub_domain_was, sofia_cfg.publish_domain, sizeof(pub_domain_was));
		ast_copy_string(pub_transport_was, sofia_cfg.publish_transport, sizeof(pub_transport_was));

		if (sofia_apply_config(cfg) < 0) {
			/* Don't sweep — a partial parse could remove live peers it didn't reach. */
			snprintf(local_errmsg, sizeof(local_errmsg),
				"sofia_apply_config failed — see log; no peers swept");
			ast_config_destroy(cfg);
			goto signal_done;
		}

		/* Sweep peers that disappeared from sofia.conf. ABBA fix: the sweep callback runs UNDER the
		 * peers container lock and CANNOT remove dialplan hints there (conlock inversion). It collects
		 * each swept peer's hint spec into swept_hints; we drain that list (removing the hints) AFTER
		 * ao2_callback returns and the container lock is released. */
		{
			struct sofia_swept_hint_list swept_hints = AST_LIST_HEAD_NOLOCK_INIT_VALUE;
			struct sofia_swept_hint *h;
			/* B: unindex the marked peers from peers_by_ipport BEFORE the OBJ_UNLINK sweep, via an
			 * iterator (whose body does NOT hold the peers lock) so we never index while holding peers.
			 * A missed unindex would leak the peer (the entry pins a +1 ref). */
			{
				struct ao2_iterator si = ao2_iterator_init(peers, 0);
				struct sofia_peer *sp;
				while ((sp = ao2_iterator_next(&si))) {
					if (sp->_reload_marked && !sp->is_realtime) {
						sofia_peer_ipport_unindex(sp);
					}
					ao2_ref(sp, -1);
				}
				ao2_iterator_destroy(&si);
			}
			ao2_callback(peers, OBJ_NODATA | OBJ_UNLINK | OBJ_MULTIPLE,
				sofia_peer_sweep_cb, &swept_hints);
			/* Container lock released — now safe to take conlock (peers no longer held). */
			while ((h = AST_LIST_REMOVE_HEAD(&swept_hints, list))) {
				sofia_remove_peer_hints(h->regexten, h->subscribecontext, "sofia_config_peer");
				ast_free(h);
			}
		}

		/* Outbound-PUBLISH reconcile: add/remove/rebuild publications to match the new config. */
		sofia_publications_reconcile(
			strcmp(pub_server_was, sofia_cfg.publish_server) != 0
			|| strcmp(pub_domain_was, sofia_cfg.publish_domain) != 0
			|| pub_expires_was != sofia_cfg.publish_expires
			/* a publish_transport change must rebuild: the transport is baked into pub->target's R-URI
			 * (built once at publication-create), so an existing pub->nh keeps the old transport otherwise. */
			|| strcmp(pub_transport_was, sofia_cfg.publish_transport) != 0
			/* a format change must full-rebuild: RFC 3903 keys ESC state by Event package + ETag, so
			 * we teardown the old (old Event + old ETag) and re-PUBLISH fresh with no If-Match. */
			|| pub_format_was != sofia_cfg.publish_format);

		/* Outbound MWI-SUBSCRIBE reconcile: add/remove watchers to match the new config. */
		sofia_subscribe_reconcile();
		sofia_eventsub_reconcile();
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

/* sofia_thread-dispatched SIPqualifypeer worker: qualify the peer, then conditionally clear the gate. */
void sipqualifypeer_callback(void *data)
{
	struct sipqualifypeer_data *d = data;
	if (d) {
		if (d->peer) {
			sofia_qualify_peer(d->peer);
			/* Only a TIMER dispatch (clear_pending=1) releases the gate; an AMI manual qualify
			 * must NOT clear a timer's qualify_pending or the aux thread re-enqueues early.
			 * Under peer->lock (same lock the timer set it under). */
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

/* Manual (AMI/CLI) on-demand qualify: alloc a dispatch + hand it to sofia_thread (where nua_options
 * runs). ALWAYS consumes the caller's peer +1 ref — transferred to the callback on success (return 0),
 * dropped on failure (return -1). clear_pending=0 so a manual qualify never touches the timer's
 * qualify_pending gate. Shared by manager_sofia_qualify_peer + the `sip qualify peer` CLI. */
int sofia_qualify_peer_async(struct sofia_peer *peer)
{
	struct sipqualifypeer_data *d;

	if (!peer) {
		return -1;
	}
	if (!(d = ast_calloc(1, sizeof(*d)))) {
		ao2_ref(peer, -1);
		return -1;
	}
	d->peer = peer;		/* TRANSFER the caller's +1 ref */
	d->clear_pending = 0;
	if (sofia_dispatch_to_root_thread(sipqualifypeer_callback, d) < 0) {
		ao2_ref(peer, -1);
		ast_free(d);
		return -1;
	}
	return 0;
}


static int load_module(void)
{
	int rc = AST_MODULE_LOAD_SUCCESS;
	int sofia_thread_started = 0;

	ast_verbose("Sofia-SIP channel loading...\n");

	/* Digest auth: init the per-process HMAC secret + the per-nonce replay cache (stateless-nonce model).
	 * Secret first, before sofia_thread accepts SIP. The cache is non-fatal (the replay check no-ops if
	 * it is absent — a call is never blocked by a missing cache). */
	sofia_nonce_secret_init();
	sofia_nonce_cache = ao2_container_alloc(SOFIA_NONCE_CACHE_BUCKETS, sofia_nonce_cache_hash, sofia_nonce_cache_cmp);

	/* Container allocation — checked individually; the err_cleanup ladder unwinds in reverse. */
	peers = ao2_container_alloc(MAX_PEER_BUCKETS, peer_hash_fn, peer_cmp_fn);
	if (!peers) {
		ast_log(LOG_ERROR, "Unable to create Sofia peers container\n");
		rc = AST_MODULE_LOAD_FAILURE;
		goto err_cleanup;
	}
	ao2_container_register("sofia/peers", peers);
	/* B: the O(1) by-IP+port index (perf). Non-fatal if it fails — the lookup just no-ops and every
	 * by-IP lookup uses the O(N) ranked scan. */
	peers_by_ipport = ao2_container_alloc(MAX_PEER_IPPORT_BUCKETS, peer_ipport_hash_fn, peer_ipport_cmp_fn);
	/* RFC 5626 flow-close registry (nh-keyed). Non-fatal: a NULL container degrades to expiry/max_contacts
	 * cleanup (sofia_regflow_attach no-ops when the container is NULL). */
	sofia_regflow_handles = ao2_container_alloc(SOFIA_REGFLOW_BUCKETS, sofia_regflow_hash, sofia_regflow_cmp);
	dialogs = ao2_container_alloc(MAX_DIALOG_BUCKETS, dialog_hash_fn, dialog_cmp_fn);
	if (!dialogs) {
		ast_log(LOG_ERROR, "Unable to create Sofia dialogs container\n");
		rc = AST_MODULE_LOAD_FAILURE;
		goto err_cleanup;
	}
	ao2_container_register("sofia/dialogs", dialogs);
	if (sofia_blacklist_init()) {
		ast_log(LOG_ERROR, "Unable to create Sofia blacklist container\n");
		rc = AST_MODULE_LOAD_FAILURE;
		goto err_cleanup;
	}
	if (sofia_presence_init()) {
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

	sofia_history_init();

	/* outbound MWI SUBSCRIBE (a watcher): one subscription per mwi_subscribe= peer. */
	if (sofia_subscribe_init()) {
		ast_log(LOG_ERROR, "Unable to create Sofia MWI-subscribe container\n");
		rc = AST_MODULE_LOAD_FAILURE;
		goto err_cleanup;
	}

	/* generic outbound SUBSCRIBE (RFC 6665): one subscription per subscribe_event= peer. */
	if (sofia_eventsub_init()) {
		ast_log(LOG_ERROR, "Unable to create Sofia event-subscribe container\n");
		rc = AST_MODULE_LOAD_FAILURE;
		goto err_cleanup;
	}

	/* WebRTC DataChannel (usrsctp) transport — foundation. Non-fatal: a failure (or a
	 * build without usrsctp) just leaves m=application unsupported (the SDP keeps it port-0). */
	if (sofia_dc_init()) {
		ast_log(LOG_WARNING, "Sofia: WebRTC DataChannel init failed — datachannels disabled\n");
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

	/* UDPTL callbacks (after RTP glue): get exposes active T.38 sessions; set is a no-op
	 * while UDPTL stays relayed through the PBX. */
	ast_udptl_proto_register(&sofia_udptl);

	/* Scheduler thread for the T.38 5s reINVITE timeout. On failure, log + continue
	 * (T.38 timer disabled; arm sites null-check sofia_sched). */
	sofia_sched = ast_sched_thread_create();
	if (!sofia_sched) {
		ast_log(LOG_WARNING, "Sofia: ast_sched_thread_create failed — T.38 5s reINVITE timeout disabled\n");
	}

	ast_register_application_xml(app_dtmfmode, sofia_app_dtmfmode);
	ast_register_application_xml(app_sipaddheader, sofia_app_addheader);
	ast_register_application_xml(app_sipremoveheader, sofia_app_removeheader);
	ast_register_application(app_sofiasendmessage, sofia_app_sendmessage,
		"Send an out-of-dialog SIP MESSAGE (SIP SIMPLE)",
		"SofiaSendMessage(<peer-or-uri>,<body>[,<from>])\n"
		"  Sends a SIP SIMPLE instant message out of dialog via chan_sofia.\n"
		"  <peer-or-uri>: a configured peer name, or a sip:/sips: URI.\n"
		"  <from>: optional From URI; defaults to the peer identity.\n");
	ast_register_application(app_sofiatransfer, sofia_app_transfer,
		"Transfer a call via SIP REFER",
		"SofiaTransfer(<refer-to>[,<replaces>])\n"
		"  Sends an outbound SIP REFER (blind, or attended when <replaces> is given).\n"
		"  <refer-to>: a configured peer name, a sip:/sips: URI, or a bare extension.\n"
		"  <replaces>: optional dialog for an attended transfer (\"callid;to-tag=X;from-tag=Y\").\n");

	/* Dialplan functions: SIP_HEADER / CHECKSIPDOMAIN / SIPPEER / SIPCHANINFO. */
	ast_custom_function_register(&sofia_sip_header_function);
	ast_custom_function_register(&sofia_check_sipdomain_function);
	ast_custom_function_register(&sofia_sippeer_function);
	ast_custom_function_register(&sofia_sipchaninfo_function);

	ast_manager_register_xml("SIPpeers",
		EVENT_FLAG_SYSTEM | EVENT_FLAG_REPORTING, manager_sofia_show_peers);
	ast_manager_register_xml("SIPshowpeer",
		EVENT_FLAG_SYSTEM | EVENT_FLAG_REPORTING, manager_sofia_show_peer);
	ast_manager_register_xml("SIPqualifypeer",
		EVENT_FLAG_SYSTEM | EVENT_FLAG_REPORTING, manager_sofia_qualify_peer);
	ast_manager_register_xml("SIPshowregistry",
		EVENT_FLAG_SYSTEM | EVENT_FLAG_REPORTING, manager_sofia_show_registry);
	ast_manager_register_xml("SIPnotify",
		EVENT_FLAG_SYSTEM, manager_sofia_notify);
	ast_manager_register_xml("SofiaMessageSend", EVENT_FLAG_SYSTEM, manager_sofia_messagesend);

	ast_cli_register_multiple(cli_sofia, ARRAY_LEN(cli_sofia));

	sofia_do_register();

	/* Auxiliary service threads: check the create result and, on failure, WARN and mark the
	 * tid AST_PTHREADT_NULL so a later shutdown join never touches an invalid handle. These
	 * are not load-critical (the module still services calls), so a failure warns rather than
	 * failing the load — unlike the primary sofia_thread above. */
	if (ast_pthread_create(&sofia_reg_thread, NULL, sofia_reg_thread_func, NULL)) {
		ast_log(LOG_WARNING, "Sofia: failed to start the outbound REGISTER refresh thread — outbound registrations will not auto-refresh\n");
		sofia_reg_thread = AST_PTHREADT_NULL;
	}

	if (ast_pthread_create(&sofia_qualify_tid, NULL, sofia_qualify_thread, NULL)) {
		ast_log(LOG_WARNING, "Sofia: failed to start the peer qualify keepalive thread — peer qualify (OPTIONS) will not run\n");
		sofia_qualify_tid = AST_PTHREADT_NULL;
	}

	ast_verbose("Sofia-SIP channel driver loaded successfully\n");

	return AST_MODULE_LOAD_SUCCESS;

err_cleanup:
	/* Reverse-order unwind for load failures, each step guarded against not-yet-constructed
	 * state. unload_module is a no-op (no runtime unload), so this is the ONLY cleanup on a
	 * failed load — without it a DECLINE-retry loop accumulates leaks. */

	if (sofia_thread_started) {
		/* sofia_thread may be running or already exited; pthread_join is safe either way.
		 * Signal the event loop to exit first if alive. */
		if (sofia_nua) {
			nua_shutdown(sofia_nua);
		}
		if (sofia_root) {
			su_root_break(sofia_root);
		}
		pthread_join(sofia_thread, NULL);
		/* The thread tears down sofia_nua/sofia_root on exit; do not NULL them here. */
	}

	/* AFTER the join (the only history user, sofia_thread, is now gone) — idempotent: drops the
	 * retained-history ring + rwlock if init ran. */
	sofia_history_destroy();

	/* domain_list — drain to prevent leak on retry-after-DECLINE. */
	{
		struct sofia_domain *d;
		AST_LIST_LOCK(&domain_list);
		while ((d = AST_LIST_REMOVE_HEAD(&domain_list, list))) {
			ast_free(d);
		}
		AST_LIST_UNLOCK(&domain_list);
	}

	/* ACLs — release both unconditionally (ast_free_ha is NULL-safe). */
	ast_free_ha(sofia_cfg.localha);
	sofia_cfg.localha = NULL;
	if (sofia_cfg.contact_ha) {
		ast_free_ha(sofia_cfg.contact_ha);
		sofia_cfg.contact_ha = NULL;
	}

	/* Containers — destructors release any peers/dialogs/blacklist the parse populated. */
	sofia_blacklist_destroy();
	sofia_presence_destroy();
	sofia_publications_destroy();
	sofia_subscribe_destroy();
	sofia_eventsub_destroy();
	/* WebRTC DataChannel — drop the init ref (idempotent if init never ran / no usrsctp). */
	sofia_dc_finish();
	if (dialogs) {
		ao2_ref(dialogs, -1);
		dialogs = NULL;
	}
	if (peers_by_ipport) {
		/* B: drop the index FIRST — each entry holds a +1 peer ref; releasing them before the peers
		 * container lets the peer dnsmgr-release + ref-drop below free the peers cleanly. */
		ao2_ref(peers_by_ipport, -1);
		peers_by_ipport = NULL;
	}
	if (sofia_regflow_handles) {
		/* RFC 5626 flow-close registry: teardown_all() cleared the peer-reachable entries on the sofia
		 * thread before nua_destroy; drop the container ref now. */
		ao2_ref(sofia_regflow_handles, -1);
		sofia_regflow_handles = NULL;
	}
	if (peers) {
		/* Release every peer's dnsmgr handle + its +1 ref BEFORE dropping the container ref,
		 * else that ref pins each hostname-host peer at refcount >= 1 and leaks it + its
		 * res_dnsmgr entry (compounded across DECLINE retries). */
		ao2_callback(peers, OBJ_NODATA, sofia_peer_dnsmgr_release_cb, NULL);
		ao2_ref(peers, -1);
		peers = NULL;
	}
	if (sofia_nonce_cache) {
		ao2_ref(sofia_nonce_cache, -1);
		sofia_nonce_cache = NULL;
	}

	return rc;
}

static int unload_module(void)
{
	ast_verbose("Sofia-SIP channel unloading...\n");

	/* chan_sofia does NOT support runtime unload — three thread-discipline issues make a clean unload
	 * impossible without a deeper refactor:
	 *   (1) su_root_destroy() asserts on same-thread-as-su_root_create (SIGABRT from the CLI thread).
	 *   (2) sofia_reg_thread + sofia_qualify_tid leak past dlclose (sleep(30)/sleep(1) granularity).
	 *   (3) libsofia-sip-ua spawns its own tport worker threads not reaped by su_root_destroy.
	 * REFUSE THE UNLOAD IMMEDIATELY, BEFORE any unregister/destroy: the GabPBX loader (main/loader.c
	 * :567-574) does NOT roll back a failed unload — a nonzero return just fails the operation and leaves
	 * the module flagged running. Any teardown done here would therefore leave chan_sofia "loaded" but
	 * GUTTED (sofia_sched destroyed, channel tech / RTP glue / CLI / AMI / apps unregistered), so it can
	 * create no channels and live calls' scheduled DTLS/RTCP timers UAF the freed sched — until a full
	 * restart. Operators restart gabpbx for config changes (the reload path uses module reload, not
	 * unload). FreeSWITCH parity: mod_sofia stops its queues/threads before su_deinit — the safe
	 * choreography chan_sofia cannot do today, so it must fail before touching any state.
	 * NB: AST_FORCE_HARD can still dlclose after a failed unload by loader design (restart-only). */
	ast_log(LOG_NOTICE,
		"chan_sofia does not support runtime unload — restart gabpbx for config changes\n");
	return -1;

	/* ---- Everything below is intentionally UNREACHABLE (kept to show the original teardown shape for a
	 * future clean-unload attempt). It MUST NOT run: see the refusal above. ---- */
	ast_rtp_glue_unregister(&sofia_rtp_glue);
	/* Defensive (unload returns -1 below before any teardown runs at runtime). */
	ast_udptl_proto_unregister(&sofia_udptl);
	if (sofia_sched) {
		sofia_sched = ast_sched_thread_destroy(sofia_sched);
	}
	ast_unregister_application(app_dtmfmode);
	ast_unregister_application(app_sipaddheader);
	ast_unregister_application(app_sipremoveheader);
	ast_unregister_application(app_sofiasendmessage);
	ast_unregister_application(app_sofiatransfer);
	ast_manager_unregister("SofiaMessageSend");
	/* The unregisters below are defensive (the body returns -1 before they run at runtime). */
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

	/* chan_sofia does NOT support runtime unload — three thread-discipline issues make a clean
	 * unload impossible without a deeper refactor:
	 *   (1) su_root_destroy() asserts on same-thread-as-su_root_create (SIGABRT from the CLI thread).
	 *   (2) sofia_reg_thread + sofia_qualify_tid leak past dlclose (sleep(30)/sleep(1) granularity).
	 *   (3) libsofia-sip-ua spawns its own tport worker threads not reaped by su_root_destroy.
	 * Operators restart gabpbx for config changes (the reload path uses module reload, not unload).
	 */
	ast_log(LOG_NOTICE,
		"chan_sofia does not support runtime unload — restart gabpbx for config changes\n");
	return -1;

	/* dead code below (kept to show the original teardown shape for a future clean-unload attempt):
	 *
	 *   if (sofia_nua) nua_shutdown(sofia_nua);
	 *   if (sofia_root) { su_root_break(sofia_root); pthread_join(sofia_thread, NULL); }
	 *   if (sofia_reg_thread != AST_PTHREADT_NULL) pthread_join(sofia_reg_thread, NULL);
	 *   if (sofia_qualify_tid != AST_PTHREADT_NULL) pthread_join(sofia_qualify_tid, NULL);
	 *   ast_free_ha(...); ao2_ref(peers, -1); ao2_ref(dialogs, -1);
	 */

	ast_free_ha(sofia_cfg.localha);
	sofia_cfg.localha = NULL;
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
	sofia_presence_destroy();
	sofia_publications_destroy();
	sofia_subscribe_destroy();
	sofia_eventsub_destroy();
	/* WebRTC DataChannel — last init ref → usrsctp_finish(). Reached only by a
	 * future clean-unload; the live module returns -1 above. Matches the load_module init pairing. */
	sofia_dc_finish();

	return 0;
}

/* .reload hook (module reload chan_sofia.so) — same sofia_reload_request_sync path as the
 * `sip reload` CLI alias (thread-safe reload-on-sofia_thread, 30s deadline, listener-change
 * refusal, mark-and-sweep). Returns 0/-1. */
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
