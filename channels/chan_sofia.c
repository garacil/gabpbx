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
#include <fcntl.h>
#include <errno.h>
#include <openssl/sha.h>  /* RFC 7616 SHA-256 digest auth: libcrypto's SHA256() — core SHA256* symbols are not exported to modules */
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
#define MAX_PEER_BUCKETS 65521    /* ~50k peers at load factor < 1 */
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
static struct ao2_container *dialogs;

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
		const char *realm, const char *method, const char *reason);



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

/* Append ;transport= so an outbound request to a TCP/TLS-registered phone routes
 * over the transport it registered on (sofia-sip otherwise defaults to UDP). Only
 * tcp/tls act; udp/empty/unknown/ws/wss are no-ops. Scheme is NOT rewritten to
 * sips: — ";transport=tls" alone selects TLS. */
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

/* Build a NAT-traversal proxy URL from peer->src_addr for outbound in-dialog
 * messages when peer has nat=force_rport (or comedia). Without it sofia-sip
 * routes the 2xx-ACK/BYE to the dialog remote_target (the Contact's unroutable
 * private LAN IP for a NAT'd phone) and it never arrives. peer->src_addr = the
 * registered public source. Returns 1 if filled, 0 if no NAT routing needed. */
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
	/* Route the proxy over the registered transport, else sofia-sip opens a fresh
	 * UDP flow and the in-dialog request is lost. */
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
	/* Only the registered-source branch carries a learned transport; a static host
	 * stays UDP. */
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

/* Contact lookup by host:port (outbound traffic). */
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

static int sofia_fork_pick_winner(struct sofia_fork *fork, struct sofia_pvt *child, sip_t const *sip)
{
	struct sofia_pvt *master;

	/* Validate the child's answer SDP BEFORE claiming winner: on encryption-policy
	 * failure return -1 (caller treats it as a loser; siblings may still answer with
	 * valid crypto). Outside fork->lock — parse_sdp touches only child + sip. */
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

	/* Set master's active contact from the winner child's ruri. */
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

	/* Destroy the pre-allocated master->rtp/vrtp before the winner-steal, else the
	 * pre-fork instances leak. */
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

	/* Steal the winner's SRTP contexts; losers' contexts free via their destructors. */
	master->srtp = child->srtp;
	child->srtp = NULL;
	master->vsrtp = child->vsrtp;
	child->vsrtp = NULL;

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
	pvt->state = SOFIA_DIALOG_STATE_DOWN;
	pvt->home = su_home_new(sizeof(*pvt->home));

	/* t38id MUST be the -1 sentinel ("no scheduler entry" — distinct from ID 0). */
	pvt->t38_state = SOFIA_T38_DISABLED;
	pvt->t38id = -1;
	pvt->defer_bye_sched_id = -1;

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
static void sofia_format_outboundproxy(struct sofia_peer *peer, char *buf, size_t len);
/* sofia_resolve_ourip mirrors ast_sip_ouraddrfor (kernel routing + externaddr remap). */
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
/* Inbound RPID/PAI/Privacy parsers; all trust-gated on peer->trustrpid. */
static int sofia_check_privacy_id(sip_t const *sip);
static int sofia_get_pai(struct sofia_pvt *pvt, sip_t const *sip);
static int sofia_get_rpid(struct sofia_pvt *pvt, sip_t const *sip);
/* Inbound Diversion parser — walks sip->sip_unknown for "Diversion" by name. */
static int sofia_change_redirecting_info(struct sofia_pvt *pvt, struct ast_channel *owner, sip_t const *sip);

/* MWI re-NOTIFY cross-thread dispatch carrier: mwi_event_cb fires on the event-bus
 * thread, nua_notify must run on sofia_thread. The peer +1 ref is TRANSFERRED
 * (event_cb takes, dispatch carries, callback drops). */
struct mwi_dispatch_data {
	struct sofia_peer *peer;	/* +1 ref TRANSFERRED — callback drops */
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
		transmit_mwi_notify_for_peer(d->peer);
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
	/* Defensive dnsmgr release for orphan paths (a path missed ast_dnsmgr_release). */
	if (peer->dnsmgr) {
		ast_dnsmgr_release(peer->dnsmgr);
		peer->dnsmgr = NULL;
	}
	/* Unsubscribe (synchronous; waits for in-flight mwi_event_cb) BEFORE ast_free,
	 * closing the race against concurrent event-bus delivery. */
	while ((mb = AST_LIST_REMOVE_HEAD(&peer->mailboxes, list))) {
		if (mb->event_sub) {
			mb->event_sub = ast_event_unsubscribe(mb->event_sub);
		}
		ast_free(mb);
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

	ast_verbose("Sofia: dnsmgr — peer '%s' resolved %s -> %s\n",
		peer->name, old_buf, new_buf);

	manager_event(EVENT_FLAG_SYSTEM, "DnsManagerUpdate",
		"Peer: SIP/%s\r\n"
		"OldAddr: %s\r\n"
		"NewAddr: %s\r\n",
		peer->name, old_buf, new_buf);
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
		ast_sockaddr_copy(&peer->src_addr, &probe);
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
	peer->publish = 0;	/* outbound PUBLISH opt-in */
	peer->gruu = 0;		/* GRUU opt-in */
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

/* Install a PRIORITY_HINT extension (regexten + subscribecontext) tracking peer
 * presence via DEVICE_STATE("SIP/<name>"). source only picks the registrar string.
 * LIMITATION: no removal — hints persist for the module lifetime. */
static void sofia_create_peer_hint(struct sofia_peer *peer, const char *source)
{
	struct ast_context *hintcontext;
	char hintsip[AST_MAX_EXTENSION + 5];
	const char *registrar;

	if (!peer || ast_strlen_zero(peer->subscribecontext) || ast_strlen_zero(peer->regexten)) {
		return; /* both fields required */
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

/* Parse one ast_variable chain into peer fields. overlay=1 (sipregs pass) skips the
 * append-style list columns (ACLs/setvar/header/mailbox) to avoid duplication. */
static void sofia_apply_peer_variables(struct sofia_peer *peer, struct ast_variable *v, int overlay)
{
	/* Unique __SIPADDHEADERpre%2d= var name per header= entry. */
	int headercount = 0;
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
		} else if (!strcasecmp(v->name, "callerid")) {
			ast_string_field_set(peer, callerid, v->value);
		} else if (!strcasecmp(v->name, "regexten")) {
			ast_string_field_set(peer, regexten, v->value);
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
			peer->directmedia = ast_true(v->value);
		} else if (!strcasecmp(v->name, "busy_on_active")) {
			peer->busy_on_active = ast_true(v->value);
		} else if (!strcasecmp(v->name, "max_contacts")) {
			peer->max_contacts = sofia_clamp_max_contacts(atoi(v->value), peer->name);
		} else if (!strcasecmp(v->name, "encryption")) {
			peer->encryption = ast_true(v->value);
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
			int p = ast_parse_caller_presentation(v->value);
			peer->callingpres = (p < 0) ? AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED : p;
		} else if (!strcasecmp(v->name, "sendrpid")) {
			/* Outbound RPID/PAI emission: no/pai/rpid. */
			if (!strcasecmp(v->value, "pai")) peer->sendrpid = 1;
			else if (!strcasecmp(v->value, "rpid")) peer->sendrpid = 2;
			else peer->sendrpid = 0;
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
			/* Parse-compat only — chan_sofia is SUBSCRIBE-only MWI (no unsolicited
			 * NOTIFY); behaves as subscribemwi=yes regardless. =no emits a LOG_NOTICE. */
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
		} else if (!strcasecmp(v->name, "callerid")) {
			/* ast_callerid_split → cid_name + cid_num. */
			char cid_name_buf[80] = "", cid_num_buf[80] = "";
			ast_callerid_split(v->value, cid_name_buf, sizeof(cid_name_buf),
				cid_num_buf, sizeof(cid_num_buf));
			ast_string_field_set(peer, cid_name, cid_name_buf);
			ast_string_field_set(peer, cid_num, cid_num_buf);
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
		} else if (!strcasecmp(v->name, "publish")) {
			/* outbound PUBLISH (RFC 3903): opt hint state into central publication. */
			peer->publish = ast_true(v->value);
		} else if (!strcasecmp(v->name, "buggymwi")) {
			/* a buggy SIP stack workaround: gates the Voice-Message " (0/0)" suffix. */
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
			/* Accepted but not applied (drop-in compat). Per-peer inbound transport is
			 * not gated (chan_sip's check_request_transport allowlist is policy, not
			 * attack-surface reduction); transports come from [general] *bindaddr and
			 * the Contact URL scheme at REGISTER-time. Legacy rows are safe to leave. */
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
	/* Publish FIRST, side-effects after (link-first): sofia_find_peer holds
	 * ao2_lock(peers) across the build so concurrent same-name builds are already
	 * serialised. On ao2_link OOM nothing is created yet → no orphan to unwind. */
	if (!ao2_link(peers, peer)) {
		sofia_peer_drain_mwi(peer);
		ao2_ref(peer, -1);
		return NULL;
	}

	/* These side-effects run AFTER ao2_link (link-first) so an OOM leaves no orphan. */
	sofia_create_peer_hint(peer, "realtime");
	sofia_dnsmgr_setup_peer(peer);

	/* dynamic_exclude_static [general] (chan_sip parity). */
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

	/* SRTP active → force LOCAL relay (directmedia would disclose this leg's SRTP
	 * key to the remote endpoint via re-INVITE). */
	if (pvt->srtp || pvt->vsrtp) {
		ast_debug(2, "Sofia: get_rtp_peer LOCAL (SRTP active, direct media inhibited)\n");
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
	char sdp_buf[2048];
	char mf_str[8];	/* RFC 3261 §20.22 Max-Forwards */
	int mf = (pvt && pvt->peer) ? pvt->peer->maxforwards : sofia_cfg.default_max_forwards;
	snprintf(mf_str, sizeof(mf_str), "%d", mf);

	if (!pvt || !pvt->nh || !sofia_generate_sdp(pvt, sdp_buf, sizeof(sdp_buf))) {
		/* Nothing sent — release the reinvite gate (pre-set by the directmedia
		 * marshal) so a guard-fail doesn't leave it stuck. */
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
				child->peer = pvt->peer;
				ao2_ref(child->peer, +1);
				/* children never own the ast_channel. Inherit the master's resolved
				 * outbound identity (scalars here; a temporary owner alias across the
				 * header builders below) so forked INVITEs carry the real caller. */
				child->callingpres = pvt->callingpres;
				ast_sockaddr_copy(&child->ourip, &pvt->ourip);

				/* Build RURI for this contact. c->host may be unbracketed IPv6 —
				 * the helper wraps it (RFC 3261 §19.1.2). */
				{
					char hbuf[80];
					char c_transport[8];
					snprintf(ruri, sizeof(ruri), "sip:%s@%s:%d", pvt->exten,
						sofia_uri_format_host(c->host, hbuf, sizeof(hbuf)),
						c->port);
					/* Fork each branch over its contact's transport (snapshot the
					 * refresh-mutable field). */
					ao2_lock(c);
					ast_copy_string(c_transport, c->transport, sizeof(c_transport));
					ao2_unlock(c);
					sofia_uri_append_transport(ruri, sizeof(ruri), c_transport);
				}
				ast_string_field_set(child, ruri, ruri);

				/* Create handle auto-bound to child. */
				if (sofia_nua) {
					child->nh = nua_handle(sofia_nua, child,
						NUTAG_URL(ruri),
						SIPTAG_TO_STR(ruri),
						TAG_END());
				}

				/* Init RTP + (if encryption=yes) per-child SRTP, then SDP. */
				if (child->nh && sofia_rtp_init(child) == 0) {
					int crypto_ok = 1;
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
						char from_buf[256];
						char contact_buf[256];
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
		/* sofia-sip auto-emits the From-tag; we provide the URI without ;tag=. */
		char from_buf[256];
		char contact_buf[256];
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
				pvt->peer ? pvt->peer->name : "(none)",
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
				sofia_fork_cancel_all_cb, NULL);
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
	/* 2048 (not 1024): T.38 emission adds ~250 bytes that would otherwise truncate. */
	char sdp_buf[2048];

	if (!pvt || !pvt->nh) {
		return -1;
	}

	{
		/* Inbound 200-OK accept-path session timers (RFC 4028). */
		int st_seconds, st_min_se, st_refresher;
		sofia_session_timer_values(pvt->peer, 0 /* inbound */, &st_seconds, &st_min_se, &st_refresher);
		/* Stamp Contact from the per-leg kernel-routed source (pvt->ourip): on a
		 * multihomed wildcard bind, sofia's auto-Contact would pick one interface for
		 * every dialog → a leg on another interface gets an unroutable Contact and the
		 * dialog never completes. RFC 3261 §12.1.1/§8.1.1.8. */
		char contact_buf[256];
		/* reload-UAF: hold peer->lock across sofia_build_contact (reads freeable
		 * fromuser); pure formatting on the answer thread. */
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
		char contact_buf[256];
		if (pvt->peer) ast_mutex_lock(&pvt->peer->lock);
		sofia_build_contact(pvt, contact_buf, sizeof(contact_buf));
		if (pvt->peer) ast_mutex_unlock(&pvt->peer->lock);
		nua_respond(pvt->nh, SIP_180_RINGING,
			TAG_IF(!ast_sockaddr_isnull(&pvt->ourip), SIPTAG_CONTACT_STR(contact_buf)),
			TAG_END());
	}
		/* progressinband: YES → -1 (force core in-band); NEVER/NO → 0. LIMITATION:
		 * NO degrades to NEVER (no SIP_PROGRESS_SENT tracking). */
		if (pvt->peer && pvt->peer->progressinband == SOFIA_PROG_INBAND_YES) {
			return -1;
		}
		break;
	case AST_CONTROL_BUSY:
		nua_respond(pvt->nh, SIP_486_BUSY_HERE, TAG_END());
		break;
	case AST_CONTROL_INCOMPLETE:
		/* allowoverlap, pre-UP only: YES → 484; DTMF → wait (no-op); NO/default → 404. */
		if (ast->_state != AST_STATE_UP) {
			int overlap_mode = pvt->peer ? pvt->peer->allowoverlap_mode : sofia_cfg.default_allowoverlap_mode;
			switch (overlap_mode) {
			case SOFIA_OVERLAP_YES:
				nua_respond(pvt->nh, SIP_484_ADDRESS_INCOMPLETE, TAG_END());
				break;
			case SOFIA_OVERLAP_DTMF:
				/* wait for inband DTMF digits. */
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
			char sdp_buf[2048];
			/* Contact from pvt->ourip (see sofia_answer); reload-UAF: hold peer->lock
			 * across sofia_build_contact (reads freeable fromuser). */
			char contact_buf[256];
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
				/* RTP not yet bound — bodyless 183 (rare; rtp_init runs earlier). */
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

	if (peer) {
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
		pvt->dtmfmode = peer->dtmfmode;
		pvt->allowtransfer = peer->allowtransfer;
		ast_string_field_set(pvt, subscribecontext, peer->subscribecontext);
		ast_string_field_set(pvt, accountcode, peer->accountcode); /* → chan->accountcode via sofia_new */
		ao2_ref(peer, +1); pvt->peer = peer;

		{
			char url[256];
			char route_buf[256];

			sofia_resolve_peer_target(peer, exten, url, sizeof(url));
			/* Outbound Route from outboundproxy; sticky-on-handle via
			 * NUTAG_INITIAL_ROUTE_STR. */
			sofia_format_outboundproxy(peer, route_buf, sizeof(route_buf));
			/* Resolve our source IP toward this peer (for SDP + From/Contact). */
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
				/* Release peer->lock before sofia_resolve_ourip (blocks on DNS +
				 * kernel route; reads no freeable field — target is a local copy). */
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

			/* NAT in-dialog routing override: for a NATed peer the 200-OK Contact
			 * carries a LAN IP, so sofia's auto ACK/BYE would be unroutable.
			 * NUTAG_PROXY pins dialog messages to peer->src_addr (the helper also
			 * appends reg_transport so TCP/TLS doesn't default to UDP). Lock-free:
			 * nat/src_addr/port/reg_transport are fixed members. */
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
	char sdp_buf[2048];
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
		if (sofia_parse_sdp(pvt, sip) < 0) {
			/* Encryption downgrade — reject 488, leave the live call up (RFC 3261 §14). */
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
	sdp_ok = (sofia_generate_sdp(pvt, sdp_buf, sizeof(sdp_buf)) != NULL);
	ast_mutex_unlock(&pvt->lock);
	char contact_buf[256];
	contact_buf[0] = '\0';
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
		}
		if (!caller_peer) {
			/* From-username lookup failed → fall back to source-IP match so
			 * host=<ip> trunks (whose From-user is the caller-ID, not the peer name)
			 * are identified; else alwaysauthreject would 401 a trunk that can't answer. */
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
					/* Timing-equalize the ACL-deny vs auth-401-slow path, else
					 * ACL-403-fast is a peer-existence oracle defeating
					 * alwaysauthreject. */
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
			pvt->allowtransfer = caller_peer->allowtransfer;
			ast_string_field_set(pvt, subscribecontext, caller_peer->subscribecontext);
			ast_string_field_set(pvt, accountcode, caller_peer->accountcode); /* → chan->accountcode via sofia_new */
			ao2_ref(caller_peer, +1); pvt->peer = caller_peer;
			ao2_ref(caller_peer, -1);
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
		 * is indistinguishable from known-peer-bad-password (RFC 3261 §22.4). */
		char realm_buf[MAXHOSTNAMELEN];
		const char *realm = sofia_get_realm_for_dialog(sip, realm_buf, sizeof(realm_buf));
		sofia_send_auth_challenge(nua, nh, sip, realm, "INVITE", "UnknownPeer");
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

	/* Inbound RPID/PAI/Privacy (trust-gated by peer->trustrpid; PAI fallback).
	 * Peer-side callingpres OVERRIDES received presentation. Before sofia_new so
	 * chan->caller.id picks it up via ast_set_callerid below. */
	sofia_get_rpid(pvt, sip);
	if (pvt->peer && pvt->peer->callingpres) {
		pvt->callingpres = pvt->peer->callingpres;
	}

	/* Inbound call-limit enforcement → 480. The reason text trailing space is
	 * VERBATIM (operator scripts pattern-match it). pvt not yet in dialogs → only
	 * the ao2_ref drop on reject (destructor DEC is a no-op, call_inc_done=0). */
	if (sofia_update_call_counter(pvt, SOFIA_INC_CALL_LIMIT) == -1) {
		ast_log(LOG_NOTICE, "Sofia: inbound INVITE from peer '%s' rejected — call_limit %d reached\n",
			pvt->peer->name, pvt->peer->call_limit);
		nua_respond(nh, 480, "Temporarily Unavailable (Call limit) ",
			NUTAG_WITH_THIS(nua), TAG_END());
		ao2_ref(pvt, -1);
		return;
	}

	/* allowoverlap=YES + partial (canmatch but not exact) extension → 484 before
	 * sofia_new. DTMF/NO fall through (the PBX 404s if truly absent). No
	 * SIPTAG_REASON_STR (sofia flips it to 500). pvt not yet in dialogs → ao2_ref drop. */
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
		nua_respond(nh, SIP_404_NOT_FOUND, NUTAG_WITH_THIS(nua), TAG_END());
		ao2_ref(pvt, -1);
		return;
	}

	if (sip->sip_payload && sip->sip_payload->pl_data) {
		if (sofia_parse_sdp(pvt, sip) < 0) {
			/* Encryption mismatch → 488 (no SIPTAG_REASON_STR; sofia flips it to
			 * 500). Free srtp/vsrtp explicitly. */
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

	/* comedia: override the SDP-derived RTP remote with the SIP source. */
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

	nua_respond(nh, SIP_100_TRYING, TAG_END());

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
		ast_hangup(chan);
	}
}

static void sofia_process_bye(nua_t *nua, nua_handle_t *nh, struct sofia_pvt *op,
		sip_t const *sip, tagi_t tags[])
{
	nua_respond(nh, SIP_200_OK, TAG_END());

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

/* Apply a REGISTER's Contact bindings to the peer. Caller holds peer->lock.
 * Returns 0 ok, -1 ACL-denied, -2 malformed wildcard, -3 OOM. Unregister
 * side-effects are deferred to the caller via *update (see emit_unregister). */
static int sofia_update_peer_contacts(struct sofia_peer *peer, sip_t const *sip, int expires,
	struct sofia_register_update *update)
{
	time_t now = time(NULL);
	struct ast_sockaddr src;
	sip_contact_t *m;
	char reg_transport[8] = "udp";	/* last contact's transport → peer->reg_transport */

	/* "Contact: *" is valid only as the sole Contact with Expires:0 (RFC 3261
	 * §10.2.2 bulk unregister); else malformed → -2 (400). */
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
		for (m = sip->sip_contact; m; m = m->m_next) {
			if (m->m_url->url_type == url_any) {
				/* Wildcard — clear all contacts. */
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
				/* Defer unregister side-effects to the caller post-unlock (they
				 * take the contexts lock + AMI + BLF, not under peer->lock). */
				if (update) {
					update->emit_unregister = 1;
					update->unregister_cause = "Wildcard";
				}
				return 0;
				}
			}
		/* Specific contact(s) de-registration. */
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
		/* Preflight the contact-ACL for EVERY Contact before binding ANY, so a
		 * later fail-closed Contact never leaves earlier ones partially bound. */
		for (m = sip->sip_contact; m; m = m->m_next) {
			char uri[256];
			sofia_contact_uri_from_url(uri, sizeof(uri), m->m_url);
			if (sofia_contact_acl_check(peer, m->m_url, uri) < 0) {
				return -1;
			}
		}
		/* Apply loop. */
		for (m = sip->sip_contact; m; m = m->m_next) {
			char uri[256];
			struct sofia_contact *c;

			sofia_contact_uri_from_url(uri, sizeof(uri), m->m_url);

			/* Last Contact ;transport= seen is snapshotted into reg_transport
			 * after the loop. */
			sofia_contact_transport_from_url(m->m_url, reg_transport, sizeof(reg_transport));

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
				c->expires = now + expires;
				memcpy(&c->src_addr, &src, sizeof(src));
				/* Refresh transport too: a same-URI re-REGISTER may switch it. */
				ast_copy_string(c->transport, reg_transport, sizeof(c->transport));
				if (sip->sip_user_agent && sip->sip_user_agent->g_string)
					ast_copy_string(c->user_agent, sip->sip_user_agent->g_string,
						sizeof(c->user_agent));
				ao2_unlock(c);
				ao2_ref(c, -1);
				if (sofia_debug)
					ast_verbose("Sofia: Refreshed contact %s (expires in %ds)\n", uri, expires);
			} else {
				/* New contact. */
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
				c->port = sofia_contact_url_port(m->m_url->url_port);
				ast_copy_string(c->transport, reg_transport, sizeof(c->transport));
				if (sip->sip_user_agent && sip->sip_user_agent->g_string)
					ast_copy_string(c->user_agent, sip->sip_user_agent->g_string,
						sizeof(c->user_agent));
				c->expires = now + expires;
				memcpy(&c->src_addr, &src, sizeof(src));
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

static void sofia_regen_nonce_locked(struct sofia_peer *peer, char *out_buf, size_t out_len);

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

/* Crypto-secure 128-bit nonce from /dev/urandom -> 32 hex chars. Falls back to
 * an ast_random composite (with a WARNING) only if urandom is unavailable.
 * out_buf size >= 33. */
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

	/* DYNAMIC buffer so a long name+realm (domainsasrealm) can never truncate the
	 * secret — a fixed buffer would hash MD5("name:realm:") = auth bypass. On OOM
	 * propagate -1 so the caller rejects (500), never a predictable hash. */
	if (ast_asprintf(&a1_pre, "%s:%s:%s", peer->name, realm, peer->secret) < 0 || !a1_pre) {
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

	/* No Authorization header: challenge. Offer MD5 first (legacy compat), then SHA-256 (RFC 7616). */
	if (!au) {
		char nonce[64];
		time_t now_fc = time(NULL);
		int ttl_fc = sofia_cfg.nonce_ttl_seconds > 0 ? sofia_cfg.nonce_ttl_seconds : SOFIA_NONCE_TTL_SEC_DEFAULT;

		/* UNVERIFIED first request: reuse the peer's live nonce, regen only if empty/expired,
		 * so a spoof cannot clobber a victim's in-flight challenge. */
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

	/* sofia_au_get_unq returns NULL on overflow. */
	auth_realm     = sofia_au_get_unq(au, "realm",     auth_realm_buf,     sizeof(auth_realm_buf));
	auth_nonce     = sofia_au_get_unq(au, "nonce",     auth_nonce_buf,     sizeof(auth_nonce_buf));
	auth_response  = sofia_au_get_unq(au, "response",  auth_response_buf,  sizeof(auth_response_buf));
	auth_uri       = sofia_au_get_unq(au, "uri",       auth_uri_buf,       sizeof(auth_uri_buf));
	auth_nc        = sofia_au_get_unq(au, "nc",        auth_nc_buf,        sizeof(auth_nc_buf));
	auth_cnonce    = sofia_au_get_unq(au, "cnonce",    auth_cnonce_buf,    sizeof(auth_cnonce_buf));
	auth_qop       = sofia_au_get_unq(au, "qop",       auth_qop_buf,       sizeof(auth_qop_buf));
	auth_algorithm = sofia_au_get_unq(au, "algorithm", auth_algorithm_buf, sizeof(auth_algorithm_buf));

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

	/* Realm mismatch → 401-stale (RFC 2617 §3.2.1, byte-exact; missing realm = mismatch).
	 * Cross-realm replay prevention. */
	if (!auth_realm || strcmp(auth_realm, realm) != 0) {
		char chal_nonce[64];
		time_t now_rm = time(NULL);
		int ttl_rm = sofia_cfg.nonce_ttl_seconds > 0 ? sofia_cfg.nonce_ttl_seconds : SOFIA_NONCE_TTL_SEC_DEFAULT;
		/* UNVERIFIED: reuse the live nonce, regen only if empty/expired, so a
		 * spoofed-username probe cannot DoS the victim's in-flight challenge. */
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

	/* We always challenge qop="auth", so a PRESENT non-"auth" qop is a downgrade:
	 * accepting it falls through to RFC 2069 no-qop digest, bypassing nc/cnonce
	 * replay tracking. Check RAW header presence (oversized qop → auth_qop NULL →
	 * would misread as "no qop"). MISSING qop is still accepted (RFC 2069 compat). */
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

	ast_mutex_lock(&peer->lock);

	/* ROTATE the nonce only when dead (empty/expired) or a qop nc-replay against
	 * the MATCHING nonce. A NON-matching nonce is re-challenged with the existing
	 * live nonce, never regenerated — so a spoof cannot clobber the per-peer nonce. */
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

	/* md5secret is a pre-computed MD5(user:realm:secret), MD5-only, and takes
	 * precedence over peer->secret — so an md5secret peer cannot satisfy a SHA-256
	 * client (silent 403). Recover by re-challenging MD5-only. If MD5 is globally
	 * disabled (auth_algorithms=sha256) the config is irreconcilable: 403 + warn.
	 * Runs under peer->lock. */
	if (algorithm == SOFIA_DIGEST_SHA256 && !ast_strlen_zero(peer->md5secret)) {
		int want_md5, want_sha256;
		sofia_auth_offered(&want_md5, &want_sha256);
		if (want_md5) {
			char fresh_nonce[64];
			char hdr_md5[256];
			/* Nonce matched + live + response not yet verified: re-challenge MD5-only
			 * with the EXISTING nonce so a SHA-256-asking request cannot clobber it. */
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

	/* Compute expected response under peer->lock (secret/name read-stable). */
	if (sofia_compute_digest(peer, realm, method, auth_uri,
			peer->nonce, auth_nc, auth_cnonce,
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
	time_t now = time(NULL);

	if (contacts && peer->contacts) {
		struct ao2_iterator ci = ao2_iterator_init(peer->contacts, 0);
		struct sofia_contact *c;
		while ((c = ao2_iterator_next(&ci))) {
			char uri[256];
			long ttl;
			/* expires is refreshed concurrently — read both under the contact lock. */
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

	if (!sip || !sip->sip_from) {
		nua_respond(nh, SIP_400_BAD_REQUEST, TAG_END());
		return;
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

	/* No credential at all (neither secret nor md5secret) -> accept without auth.
	 * md5secret IS a credential, so a md5secret-only peer MUST take the auth path below. */
	if (ast_strlen_zero(peer->secret) && ast_strlen_zero(peer->md5secret)) {
		/* Contact-less REGISTER = binding QUERY, no state side-effects. */
		if (!sip->sip_contact) {
			sofia_respond_register_query(nua, nh, peer);
			ao2_ref(peer, -1);
			return;
		}
		/* Clamp ex_delta before the int cast: >INT_MAX would wrap negative/0
		 * (spurious 423 or self-deregister). Real bounds applied below. */
		int expires = sip->sip_expires
			? (sip->sip_expires->ex_delta > (unsigned long) INT_MAX ? INT_MAX : (int) sip->sip_expires->ex_delta)
			: DEFAULT_EXPIRY;
		/* TTL bounds + 423 Interval Too Brief; helper emits 423/Min-Expires/AMI on reject. */
		if (sofia_check_register_expiry(nua, nh, peer, &expires) < 0) {
			sofia_log_register_outcome("REJECT (interval too brief)", peer->name, sip);
			ao2_ref(peer, -1);
			return;
		}
		/* lockuseragent gate (chan_sip parity). */
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
		/* rtupdate=no skips all realtime DB writes (chan_sip parity). */
		if (peer->is_realtime && sofia_cfg.peer_rtupdate) {
			sofia_rtupdate_submit(peer, sip);
		}
		/* Echo the GRANTED expires in the 200 OK so the phone refreshes on the server's
		 * (possibly capped) schedule, not its longer requested TTL. */
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
		sofia_emit_register_side_effects(peer, sip, &reg_update);
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
			/* Clamp ex_delta before the int cast (see no-secret path). */
			int expires = sip->sip_expires
				? (sip->sip_expires->ex_delta > (unsigned long) INT_MAX ? INT_MAX : (int) sip->sip_expires->ex_delta)
				: DEFAULT_EXPIRY;
			/* TTL bounds + 423 Interval Too Brief; helper emits 423/Min-Expires/AMI on reject. */
			if (sofia_check_register_expiry(nua, nh, peer, &expires) < 0) {
				sofia_log_register_outcome("REJECT (interval too brief)", peer->name, sip);
				ao2_ref(peer, -1);
				return;
			}
			granted_expires_auth = expires;	/* capture for the 200 OK echo */
			/* lockuseragent gate (chan_sip parity). */
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

		/* rtupdate=no skips all realtime DB writes (chan_sip parity). */
		if (peer->is_realtime && sofia_cfg.peer_rtupdate) {
			sofia_rtupdate_submit(peer, sip);
		}

		/* Echo the GRANTED expires in the 200 OK (see the other REGISTER 200 OK path). */
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
		sofia_emit_register_side_effects(peer, sip, &reg_update);
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
		 * NOTE: per-peer transport= never writes peer->transport (stays UDP), so the
		 * TCP/TLS branches are dead for normal peers; kept for listener-level paths. */
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

	/* Privacy: a restricted presentation makes the From anonymous (chan_sip parity). */
	if ((lid_pres & AST_PRES_RESTRICTION) != AST_PRES_ALLOWED) {
		snprintf(buf, len, "\"Anonymous\" <sip:anonymous@%s>",
			sofia_uri_format_host(fromdomain, fbuf, sizeof(fbuf)));
		return;
	}

	/* usereqphone (chan_sip parity): add RFC 3966 ;user=phone when set and lid_num is numeric. */
	if (pvt && pvt->peer && pvt->peer->usereqphone && sofia_user_looks_like_phone(lid_num)) {
		snprintf(buf, len, "\"%s\" <sip:%s@%s;user=phone>", lid_name, lid_num,
			sofia_uri_format_host(fromdomain, fbuf, sizeof(fbuf)));
	} else {
		snprintf(buf, len, "\"%s\" <sip:%s@%s>", lid_name, lid_num,
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
		/* Fallback when connected.id is empty: cid_num -> fromuser -> name -> "asterisk". */
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
	/* Snapshot mailbox specs under peer->lock, then count OUTSIDE the lock:
	 * ast_app_inboxcount2 does unbounded backend I/O (IMAP/ODBC/dir-scan). */
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
		/* fromdomain aliases peer->fromdomain's pool, used after unlock — safe:
		 * all callers run on sofia_thread, serialised vs the reload writer. */
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
	/* buggymwi=yes omits the "(0/0)" suffix some stacks reject (default = RFC 3842). */
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
			sofia_send_auth_challenge(nua, nh, sip, realm, "SUBSCRIBE", "UnknownPeer");
		} else {
			ast_log(LOG_NOTICE, "Sofia MWI: SUBSCRIBE for unknown peer '%s' — 404\n", to_user);
			nua_respond(nh, SIP_404_NOT_FOUND, NUTAG_WITH_THIS(nua), TAG_END());
		}
		sofia_subscribe_reject_reap(nh);	/* reap on both the 401-challenge and the 404 branch */
		return;
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

	/* The watched extension must have a dialplan hint, else nothing to watch. */
	if (!ast_get_hint(hint, sizeof(hint), NULL, 0, NULL, l_context, to_user)) {
		ast_log(LOG_NOTICE,
			"Sofia presence: no hint for %s@%s (watcher SIP/%s) — 404\n",
			to_user, l_context, l_peername);
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
			nua_respond(nh, SIP_200_OK, TAG_END());
			return;
		}
	}

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

	/* Method 3: dialogs linkedid walk (sibling Sofia leg). Read+ref each sibling's
	 * owner under its pvt->lock (its sofia_hangup nulls p->owner then frees it). */
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
			 * vs MicroSIP 3.21.4). So set defer_bye (sofia_hangup skips its nua_bye) and arm
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
			/* Clamp to a sane DTMF length (hostile/garbage Duration). */
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
		/* Snapshot+ref op->owner under op->lock (sofia_hangup nulls+frees it), then
		 * queue OUTSIDE op->lock. Mirrors sofia_process_bye. */
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
			/* Pin the owner across sofia_parse_sdp (UAF fix): a concurrent
			 * sofia_hangup could free it while parse mutates its format state. */
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

/* GRUU (gruu=yes): build the +sip.instance Contact param for a peer's REGISTER
 * (RFC 5626 §4.1). URN = stable UUID from server EID + peer name. Emitted via
 * NUTAG_M_FEATURES (NOT NUTAG_INSTANCE, which spins up the outbound engine). buf="" when
 * gruu off, so callers use TAG_IF(peer->gruu, ...). */
static void sofia_build_instance_feature(const struct sofia_peer *peer, char *buf, size_t len)
{
	char seed[128], hash[33], eidstr[32] = "";

	if (!peer->gruu) {
		buf[0] = '\0';
		return;
	}
	ast_eid_to_str(eidstr, sizeof(eidstr), &ast_eid_default);
	snprintf(seed, sizeof(seed), "gabpbx-sofia-instance:%s:%s", eidstr, S_OR(peer->name, ""));
	ast_md5_hash(hash, seed);	/* 32 hex chars formatted as a UUID below */
	snprintf(buf, len, "+sip.instance=\"<urn:uuid:%.8s-%.4s-%.4s-%.4s-%.12s>\"",
		hash, hash + 8, hash + 12, hash + 16, hash + 20);
}

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

	/* AMI SIPnotify one-shot handle (sentinel hmagic): destroy the app-owned
	 * out-of-dialog NOTIFY handle on its final response (sofia-sip never auto-reaps it).
	 * Handled before the blacklist/teardown-guard switches so the dispatch never sees
	 * the sentinel. nua_handle_destroy is legal — same-thread rule. */
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

	/* Outbound PUBLISH (RFC 3903): generic-method responses for publication handles
	 * route here (sentinel hmagic) before any dialog dispatch; publication found by nh. */
	if (hmagic == SOFIA_PUBLICATION_HMAGIC) {
		if (event == nua_r_method) {
			sofia_publication_handle_response(status, phrase, nh, sip);
		}
		return;
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

	/* Teardown-race guard for in-dialog events whose hmagic is the dialog pvt and which
	 * deref/mutate it concurrently with sofia_hangup: re-validate against dialogs and use
	 * a +1-reffed pvt (NULL if already unlinked -> per-handler `if (pvt)` skips). Peer-magic
	 * and fresh-INVITE (NULL hmagic) events keep the raw-hmagic path. Released at the single
	 * function-exit drop. */
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
					}
				}
			} else if (status == 401 || status == 407) {
			if (peer) {
				char www_creds[512] = "";
				char proxy_creds[512] = "";
				int have_www = 0, have_proxy = 0;
				char uri[256];

				ast_mutex_lock(&peer->lock);

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
				/* Bracket-wrap an IPv6 host literal (RFC 3261 §19.1.2). Idempotent. */
				{
					char hbuf[80];
					snprintf(uri, sizeof(uri), "sip:%s@%s:%d", peer->defaultuser,
						sofia_uri_format_host(peer->host, hbuf, sizeof(hbuf)),
						peer->port);
				}

				ast_verbose("Sofia: Responding to auth challenge for %s\n", peer->name);

				/* maxforwards: RFC 3261 §20.22 Max-Forwards on the REGISTER. */
				char mf_str_reg[8];
				char instance_feature_reg[120];
				snprintf(mf_str_reg, sizeof(mf_str_reg), "%d", peer->maxforwards);
				/* GRUU: keep the +sip.instance advertisement on the re-REGISTER too. */
				sofia_build_instance_feature(peer, instance_feature_reg, sizeof(instance_feature_reg));
				/* callbackextension (chan_sip parity): override the Contact username. */
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
			} else if (has_sdp) {
				sdp_rc = sofia_parse_sdp(pvt, sip);
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
					/* sofia-sip auto-ACKs unless AUTOACK(0) (NAT peer); then ACK here. */
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
				ast_queue_control(owner, AST_CONTROL_ANSWER);
				ast_setstate(owner, AST_STATE_UP);
				/* Set active contact for the single-contact outbound path. */
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
		int needs_cert;

		/* IPv6 bind: bracket-wrap an IPv6 host (RFC 3261 §19.1.2); IPv4/hostnames/`*`
		 * pass through unchanged. */
		char hbuf_udp[80], hbuf_tls[80], hbuf_ws[80], hbuf_wss[80];
		snprintf(udp_url, sizeof(udp_url), "sip:%s:%d",
			sofia_uri_format_host(
				ast_strlen_zero(sofia_cfg.bindaddr) ? "*" : sofia_cfg.bindaddr,
				hbuf_udp, sizeof(hbuf_udp)),
			sofia_cfg.bindport);
		if (sofia_cfg.tlsbindport > 0) {
			/* Explicit transport=tls forces TLS-only: without it, sips: enumerates
			 * both TLS+WSS on the same port and the WSS bind fails. */
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

		/* WSS needs WSS-named cert files (wss.pem + ca-bundle.crt per
		 * tport_type_ws.c:357-376); TLS uses agent.pem + cafile.pem. Auto-alias the
		 * missing WSS files from the TLS ones. Idempotent. */
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

		/* Warn on pingpong-without-keepalive: it is silently ignored (pingpong is only
		 * applied alongside keepalive below). */
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
			/* Opt-in peer-cert verification (default OFF = sofia-sip TPTLS_VERIFY_NONE).
			 * tlsverify=yes verifies the outbound server cert chain+subject+date against
			 * tlscertfile — closes the accept-any-cert MITM hole on outbound TLS/WSS. */
			TAG_IF(needs_cert && sofia_cfg.tlsverify,
				TPTAG_TLS_VERIFY_POLICY(TPTLS_VERIFY_SUBJECTS_OUT)),
			TAG_IF(needs_cert && sofia_cfg.tlsverify,
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
			NUTAG_ALLOW("INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, REFER, MESSAGE, INFO, PRACK"),
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
		NUTAG_ALLOW("INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, REFER, MESSAGE, INFO, PRACK"),
		TAG_END());

	/* Add methods to appl_method one at a time */
	nua_set_params(sofia_nua, NUTAG_APPL_METHOD("REGISTER"), TAG_END());
	nua_set_params(sofia_nua, NUTAG_APPL_METHOD("SUBSCRIBE"), TAG_END());
	/* PUBLISH is NOT APPL_METHOD'd — no RFC 3903 server here, so the stack rejects an
	 * inbound PUBLISH (405/501) rather than a stub leaking a 200 OK + un-reaped handle. */
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

	/* Presence/BLF expiry sweep (su_timer on THIS sofia_thread): sofia-sip does not
	 * auto-expire nua_respond()-accepted subs, so we tear down stale watchers ourselves. */
	sofia_presence_start();

	/* Outbound PUBLISH (RFC 3903) STARTUP pass on sofia_thread: create a publication per
	 * publish=yes peer (scheduled, not inline) + arm the ~1 Hz emission sweep. OFF unless
	 * publish_server is set. A later `sip reload` reconciles via
	 * sofia_publications_reconcile (no restart needed for PUBLISH config). */
	sofia_publications_start();

	su_root_run(sofia_root);

	sofia_presence_stop();

	/* Outbound PUBLISH teardown (sofia_thread, after the loop ends). */
	sofia_publications_stop();

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
			}
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
		} else if (!strcasecmp(v->name, "tlscertfile") || !strcasecmp(v->name, "tlscertdir")) {
			ast_copy_string(sofia_cfg.tlscertfile, v->value, sizeof(sofia_cfg.tlscertfile));
		} else if (!strcasecmp(v->name, "tlsverify") || !strcasecmp(v->name, "tlsverifyserver")) {
			/* Opt-in TLS peer-cert verification (default OFF): validate the server cert chain +
			 * subject against the configured CA material (tlscertfile dir). */
			sofia_cfg.tlsverify = ast_true(v->value);
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
			/* CRLF keepalive SECONDS (chan_sip parity) -> ms for TPTAG_KEEPALIVE; 0 -> OFF. */
			sofia_cfg.tcp_keepalive_ms = sofia_cfg_seconds_to_ms(v->value);
		} else if (!strcasecmp(v->name, "tcp_pingpong")) {
			/* pong-timeout SECONDS -> ms for TPTAG_PINGPONG; 0 -> OFF. */
			sofia_cfg.tcp_pingpong_ms = sofia_cfg_seconds_to_ms(v->value);
		} else if (!strcasecmp(v->name, "useragent")) {
			/* User-Agent override (chan_sip parity); empty ALLOWED — wire-in skips
			 * SIPTAG_USER_AGENT_STR so sofia-sip uses its library default. */
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
			int p = ast_parse_caller_presentation(v->value);
			sofia_cfg.default_callingpres = (p < 0) ? AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED : p;
		} else if (!strcasecmp(v->name, "sendrpid")) {
			if (!strcasecmp(v->value, "pai")) sofia_cfg.default_sendrpid = 1;
			else if (!strcasecmp(v->value, "rpid")) sofia_cfg.default_sendrpid = 2;
			else sofia_cfg.default_sendrpid = 0;
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
			/* PARSE-COMPAT-ONLY (default DISABLED): early-RTP-bridge wire-in deferred. */
			sofia_cfg.directrtpsetup = ast_true(v->value);
		} else if (!strcasecmp(v->name, "alwaysauthreject")) {
			/* Security-critical RFC 3261 §22.4 username-enumeration prevention —
			 * drives REGISTER unknown-peer + MWI SUBSCRIBE unknown-mailbox to emit
			 * 401 challenge instead of 403/404 disclosure. Default TRUE (chan_sip parity). */
			sofia_cfg.alwaysauthreject = ast_true(v->value);
		} else if (!strcasecmp(v->name, "compactheaders")) {
			/* PARSE-COMPAT-ONLY: sofia-sip native compact-emit gate ABSENT; effect deferred. */
			sofia_cfg.compactheaders = ast_true(v->value);
		} else if (!strcasecmp(v->name, "disallowed_methods")) {
			/* PARSE-COMPAT-ONLY string-storage; dynamic NUTAG_ALLOW generation deferred. */
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
			/* PARSE-COMPAT-ONLY: URI per-component semicolon-strip deferred. */
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
		} else if (!strcasecmp(v->name, "notifyhold")) {
			/* Gates the peer->onHold counter update. */
			sofia_cfg.notifyhold = ast_true(v->value);
		} else if (!strcasecmp(v->name, "notifyringing")) {
			/* PARSE-COMPAT-ONLY: effect deferred until presence/dialog-info NOTIFY lands. */
			sofia_cfg.notifyringing = ast_true(v->value);
		} else if (!strcasecmp(v->name, "dynamic_exclude_static")
				|| !strcasecmp(v->name, "dynamic_excludes_static")) {
			/* Security hardening; both spellings accepted. */
			sofia_cfg.dynamic_exclude_static = ast_true(v->value);
		} else if (!strcasecmp(v->name, "autocreatepeer")) {
			/* PARSE-COMPAT-ONLY: chan_sofia refuses to auto-create unknown peers. */
			sofia_cfg.autocreatepeer = ast_true(v->value);
		} else if (!strcasecmp(v->name, "preferred_codec_only")) {
			sofia_cfg.default_preferred_codec_only = ast_true(v->value);
		} else if (!strcasecmp(v->name, "ignoresdpversion")) {
			/* PARSE-COMPAT-ONLY: chan_sofia processes every SDP unconditionally. */
			sofia_cfg.default_ignoresdpversion = ast_true(v->value);
		} else if (!strcasecmp(v->name, "promiscredir")) {
			/* PARSE-COMPAT-ONLY: nua_r_redirect handler ABSENT. */
			sofia_cfg.default_promiscredir = ast_true(v->value);
		} else if (!strcasecmp(v->name, "autoframing")) {
			/* PARSE-COMPAT-ONLY: sofia_parse_sdp ptime gate not wired. */
			sofia_cfg.default_autoframing = ast_true(v->value);
		} else if (!strcasecmp(v->name, "timerb")) {
			/* CORRECTS a chan_sip bug: chan_sip only assigns global_timer_b in the invalid
			 * (< 500) branch, so valid values never take effect. We add the missing else.
			 * Wire-in via NTATAG_SIP_T1X64; sofia_timerb_set feeds the timer cross-validation. */
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
			/* Tri-state yes/no/never. Partial wire-in at sofia_indicate AST_CONTROL_RINGING. */
			if (ast_true(v->value)) {
				sofia_cfg.default_progressinband = SOFIA_PROG_INBAND_YES;
			} else if (strcasecmp(v->value, "never")) {
				sofia_cfg.default_progressinband = SOFIA_PROG_INBAND_NO;
			} else {
				sofia_cfg.default_progressinband = SOFIA_PROG_INBAND_NEVER;
			}
		} else if (!strcasecmp(v->name, "subscribe_network_change_event")) {
			/* PARSE-COMPAT-ONLY (network-change handled by sofia-sip + dnsmgr); invalid warns. */
			if (ast_true(v->value)) {
				sofia_cfg.subscribe_network_change_event = 1;
			} else if (ast_false(v->value)) {
				sofia_cfg.subscribe_network_change_event = 0;
			} else {
				ast_log(LOG_WARNING, "Sofia: subscribe_network_change_event value '%s' is not valid at line %d.\n",
					v->value, v->lineno);
			}
		} else if (!strcasecmp(v->name, "rtsavesysname")) {
			/* Wired at the sofia_process_register ast_update_realtime callsites. */
			sofia_cfg.rtsave_sysname = ast_true(v->value);
		} else if (!strcasecmp(v->name, "rtupdate")) {
			/* Gates the realtime peer updates in sofia_process_register. */
			sofia_cfg.peer_rtupdate = ast_true(v->value);
		} else if (!strcasecmp(v->name, "register_pool")) {
			/* Phase 1 kill-switch: offload realtime REGISTER DB writes to a bounded pool
			 * (default OFF). Takes effect on reload. */
			sofia_cfg.register_pool = ast_true(v->value);
		} else if (!strcasecmp(v->name, "register_pool_workers")) {
			sofia_cfg.register_pool_workers = atoi(v->value);
		} else if (!strcasecmp(v->name, "rtcachefriends")) {
			/* PARSE-COMPAT-ONLY: the ao2 registry already caches all peers. */
			sofia_cfg.rtcachefriends = ast_true(v->value);
		} else if (!strcasecmp(v->name, "rtautoclear")) {
			/* PARSE-COMPAT-ONLY: no peer-level auto-clear infra. Numeric > 0 sets seconds; flag
			 * enabled when numeric > 0 OR ast_true. */
			int i = atoi(v->value);
			if (i > 0) {
				sofia_cfg.rtautoclear = i;
			} else {
				i = 0;
			}
			sofia_cfg.rtautoclear_enabled = (i || ast_true(v->value)) ? 1 : 0;
		} else if (!strcasecmp(v->name, "domainsasrealm")) {
			/* Wired via sofia_get_realm_for_dialog at the auth-challenge callsites. */
			sofia_cfg.domainsasrealm = ast_true(v->value);
		} else if (!strcasecmp(v->name, "allowexternaldomains")) {
			/* Wired via sofia_check_sip_domain at the invite/refer gates. */
			sofia_cfg.allow_external_domains = ast_true(v->value);
		} else if (!strcasecmp(v->name, "autodomain")) {
			/* Auto-add fires at sofia_load_config conclusion. */
			sofia_cfg.autodomain = ast_true(v->value);
		} else if (!strcasecmp(v->name, "matchexternaddrlocally")
		           || !strcasecmp(v->name, "matchexterniplocally")) {
			/* PARSE-COMPAT-ONLY (sofia_should_use_externaddr signature diverges); both spellings. */
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
			/* Wired via TPTAG_TOS at nua_create. */
			if (ast_str2tos(v->value, &sofia_cfg.tos_sip)) {
				ast_log(LOG_WARNING, "Sofia: invalid tos_sip value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "tos_audio")) {
			/* Wired via ast_rtp_instance_set_qos. */
			if (ast_str2tos(v->value, &sofia_cfg.tos_audio)) {
				ast_log(LOG_WARNING, "Sofia: invalid tos_audio value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "tos_video")) {
			/* Wired via ast_rtp_instance_set_qos. */
			if (ast_str2tos(v->value, &sofia_cfg.tos_video)) {
				ast_log(LOG_WARNING, "Sofia: invalid tos_video value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "tos_text")) {
			/* PARSE-COMPAT-ONLY: text-RTP infra absent (no pvt->trtp). */
			if (ast_str2tos(v->value, &sofia_cfg.tos_text)) {
				ast_log(LOG_WARNING, "Sofia: invalid tos_text value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "cos_sip")) {
			/* PARSE-COMPAT-ONLY: sofia-sip TPTAG_COS absent. */
			if (ast_str2cos(v->value, &sofia_cfg.cos_sip)) {
				ast_log(LOG_WARNING, "Sofia: invalid cos_sip value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "cos_audio")) {
			/* Wired via ast_rtp_instance_set_qos. */
			if (ast_str2cos(v->value, &sofia_cfg.cos_audio)) {
				ast_log(LOG_WARNING, "Sofia: invalid cos_audio value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "cos_video")) {
			/* Wired via ast_rtp_instance_set_qos. */
			if (ast_str2cos(v->value, &sofia_cfg.cos_video)) {
				ast_log(LOG_WARNING, "Sofia: invalid cos_video value '%s'; refer to QoS documentation\n", v->value);
			}
		} else if (!strcasecmp(v->name, "cos_text")) {
			/* PARSE-COMPAT-ONLY: text-RTP infra absent (no pvt->trtp). */
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
		} else if (!strcasecmp(v->name, "externaddr") || !strcasecmp(v->name, "externhost")) {
			/* Accept both keys. ast_sockaddr_parse detects the value type: a literal IP stores as
			 * static externaddr (no refresh); else treat as hostname (resolve + arm externexpire
			 * for lazy-refresh), so a hostname in externaddr= still works. */
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
		 * re-registers fresh). OUTSIDE peer->lock — ast_dnsmgr_release blocks on the dnsmgr
		 * entry-list lock until any in-flight sofia_on_dns_update_peer (peer->lock) completes. */
		if (peer->dnsmgr) {
			ast_dnsmgr_release(peer->dnsmgr);
			peer->dnsmgr = NULL;
			ao2_ref(peer, -1);
		}
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
			char old_regexten[AST_MAX_EXTENSION];
			ast_copy_string(old_subctx, peer->subscribecontext, sizeof(old_subctx));
			ast_copy_string(old_regexten, peer->regexten, sizeof(old_regexten));
			ast_context_remove_extension(old_subctx, old_regexten, PRIORITY_HINT, "sofia_config_peer");
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
		/* Free prior chanvars before re-parsing (mirrors the string-field reset). */
		if (peer->chanvars) {
			ast_variables_destroy(peer->chanvars);
			peer->chanvars = NULL;
		}
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
			/* canreinvite = legacy alias for directmedia. */
			peer->directmedia = ast_true(v->value);
		} else if (!strcasecmp(v->name, "busy_on_active")) {
			peer->busy_on_active = ast_true(v->value);
		} else if (!strcasecmp(v->name, "max_contacts")) {
			peer->max_contacts = sofia_clamp_max_contacts(atoi(v->value), peer->name);
		} else if (!strcasecmp(v->name, "encryption")) {
			peer->encryption = ast_true(v->value);
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
			int p = ast_parse_caller_presentation(v->value);
			peer->callingpres = (p < 0) ? AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED : p;
		} else if (!strcasecmp(v->name, "sendrpid")) {
			if (!strcasecmp(v->value, "pai")) peer->sendrpid = 1;
			else if (!strcasecmp(v->value, "rpid")) peer->sendrpid = 2;
			else peer->sendrpid = 0;
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
			/* chan_sofia is SUBSCRIBE-only by design: subscribemwi=yes is a drop-in,
			 * subscribemwi=no emits an honest NOTICE. KNOWN LIMITATION: no unsolicited MWI NOTIFY. */
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
			peer->preferred_codec_only = ast_true(v->value);
		} else if (!strcasecmp(v->name, "ignoresdpversion")) {
			/* PARSE-COMPAT-ONLY: every SDP is processed unconditionally. */
			peer->ignoresdpversion = ast_true(v->value);
		} else if (!strcasecmp(v->name, "promiscredir")) {
			/* PARSE-COMPAT-ONLY: nua_r_redirect handler ABSENT. */
			peer->promiscredir = ast_true(v->value);
		} else if (!strcasecmp(v->name, "autoframing")) {
			/* PARSE-COMPAT-ONLY: sofia_parse_sdp ptime gate not wired. */
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
			/* tri-state yes/no/never. Partial wire-in at sofia_indicate AST_CONTROL_RINGING. */
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
		} else if (!strcasecmp(v->name, "callerid")) {
			/* ast_callerid_split -> cid_name + cid_num. */
			char cid_name_buf[80] = "", cid_num_buf[80] = "";
			ast_callerid_split(v->value, cid_name_buf, sizeof(cid_name_buf),
				cid_num_buf, sizeof(cid_num_buf));
			ast_string_field_set(peer, cid_name, cid_name_buf);
			ast_string_field_set(peer, cid_num, cid_num_buf);
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
			/* Silently accepted for drop-in compat; transports are per-listener ([general] bind
			 * addrs) and per-Contact at REGISTER-time, not per-peer. */
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
	/* outbound PUBLISH (RFC 3903) off by default (publish_server empty = feature OFF). */
	sofia_cfg.publish_server[0] = '\0';
	sofia_cfg.publish_expires = 0;
	sofia_cfg.publish_domain[0] = '\0';
	sofia_cfg.publish_username[0] = '\0';
	sofia_cfg.publish_password[0] = '\0';
	sofia_cfg.busy_on_active = 0;
	sofia_cfg.max_contacts = 6;
	sofia_cfg.encryption = 0;
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
	/* PARSE-COMPAT-ONLY — experimental, effect-deferred. */
	sofia_cfg.directrtpsetup = 0;
	/* default TRUE: RFC 3261 §22.4 username-enumeration prevention active out-of-the-box. */
	sofia_cfg.alwaysauthreject = 1;
	/* PARSE-COMPAT-ONLY — native compact-emit gate absent. */
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
	sofia_cfg.default_language[0] = '\0';
	/* default "default"; behavior change from the silent-empty baseline (parkinglot= empty restores). */
	ast_copy_string(sofia_cfg.default_parkinglot, "default", sizeof(sofia_cfg.default_parkinglot));
	/* default FALSE: expired contacts removed by sofia_expire_contacts_cb. */
	sofia_cfg.ignore_regexpire = 0;
	/* default 384 kbps — every video SDP emits b=CT:384 (maxcallbitrate=0 restores no-b=CT). */
	sofia_cfg.default_maxcallbitrate = 384;
	sofia_cfg.match_auth_username = 0;
	/* PARSE-COMPAT-ONLY. */
	sofia_cfg.legacy_useroption_parsing = 0;
	/* default 1; behavior change from the no-normalization baseline. */
	sofia_cfg.shrinkcallerid = 1;
	/* gates the peer->onHold counter update; AMI Hold emission is unconditional. */
	sofia_cfg.notifyhold = 0;
	/* PARSE-COMPAT-ONLY — effect deferred until presence/dialog-info NOTIFY lands. */
	sofia_cfg.notifyringing = 1;
	/* Security hardening: peer-build appends static IPs as deny rules to contact_ha. */
	sofia_cfg.dynamic_exclude_static = 0;
	/* PARSE-COMPAT-ONLY — refuses to auto-create unknown peers. */
	sofia_cfg.autocreatepeer = 0;
	/* codec-list-narrowing wired at sofia_generate_sdp, direction-symmetric. */
	sofia_cfg.default_preferred_codec_only = 0;
	/* default NEVER. Partial wire-in at sofia_indicate AST_CONTROL_RINGING (YES state). */
	sofia_cfg.default_progressinband = SOFIA_PROG_INBAND_NEVER;
	/* PARSE-COMPAT-ONLY — nua_r_redirect handler absent. */
	sofia_cfg.default_promiscredir = 0;
	/* PARSE-COMPAT-ONLY — sofia_parse_sdp ptime gate not wired. */
	sofia_cfg.default_autoframing = 0;
	/* default NONE; covers DSP CNG + peer T.38 reINVITE detection. */
	sofia_cfg.default_faxdetect_mode = SOFIA_FAX_DETECT_NONE;
	/* T38FaxMaxDatagram sentinel -1 = use built-in 200-byte default. */
	sofia_cfg.default_t38_maxdatagram = SOFIA_T38_MAXDATAGRAM_SENTINEL;
	/* default 32000ms (= 64 * DEFAULT_TIMER_T1); wire-in via NTATAG_SIP_T1X64. */
	sofia_cfg.default_timer_b = 32000;
	/* default 500ms; wire-in via NTATAG_SIP_T1. */
	sofia_cfg.default_timer_t1 = 500;
	/* cleared here; set when the key is parsed; consumed at the timer cross-validation below. */
	sofia_timerb_set = 0;
	sofia_timert1_set = 0;
	/* default YES; wire-in at 3 sites (process_invite + indicate INCOMPLETE + nua_r_invite 484). */
	sofia_cfg.default_allowoverlap_mode = SOFIA_OVERLAP_YES;
	/* PARSE-COMPAT-ONLY — network-change handled by sofia-sip + per-peer dnsmgr. */
	sofia_cfg.subscribe_network_change_event = 1;
	/* Wired at the sofia_process_register ast_update_realtime callsites. */
	sofia_cfg.rtsave_sysname = 0;
	/* Gates the realtime peer updates in sofia_process_register. */
	sofia_cfg.peer_rtupdate = 1;
	/* Phase 1 register pool: default OFF + auto lane count. */
	sofia_cfg.register_pool = 0;
	sofia_cfg.register_pool_workers = 0;
	/* PARSE-COMPAT-ONLY — the ao2 registry always caches all peers. */
	sofia_cfg.rtcachefriends = 0;
	/* PARSE-COMPAT-ONLY — no peer-level auto-clear. */
	sofia_cfg.rtautoclear = 120;
	sofia_cfg.rtautoclear_enabled = 0;
	/* Wired at the auth-challenge callsites via sofia_get_realm_for_dialog. */
	sofia_cfg.domainsasrealm = 0;
	/* default TRUE; safety-net auto-set at the end of sofia_load_config. */
	sofia_cfg.allow_external_domains = 1;
	/* Auto-add fires at sofia_load_config conclusion, AFTER the allowexternaldomains special-case. */
	sofia_cfg.autodomain = 0;
	/* PARSE-COMPAT-ONLY — sofia_should_use_externaddr signature diverges. */
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
	/* rtp-timeout bundle: default 0 (disabled); sofia_rtp_init wires set_*timeout when non-zero. */
	sofia_cfg.default_rtptimeout = 0;
	sofia_cfg.default_rtpholdtimeout = 0;
	sofia_cfg.default_rtpkeepalive = 0;
	/* tos/cos bundle: default 0 (no QoS). tos_sip via TPTAG_TOS; audio/video via set_qos.
	 * cos_sip + tos_text + cos_text are PARSE-COMPAT-ONLY (TPTAG_COS + text-RTP absent). */
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

	/* Phase 1: create/toggle the bounded REGISTER pool per config. */
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
			if (peer->nh && peer->reg_expiry > 0 &&
			    !ast_strlen_zero(peer->secret) &&
			    strcasecmp(peer->host, "dynamic") != 0 &&
			    /* attempt-cap: skip when register_attempts > 0 and the cap is reached. */
			    (sofia_cfg.register_attempts == 0 || peer->reg_attempts < sofia_cfg.register_attempts) &&
			    now >= peer->reg_expiry) {
				char uri[256];
				char hbuf[80];	/* bracket-wrap IPv6 host */
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
				/* GRUU Phase 1: re-advertise +sip.instance. */
				sofia_build_instance_feature(peer, instance_feature_rereg, sizeof(instance_feature_rereg));
				/* callbackextension: NUTAG_M_USERNAME override (as at initial register). */
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
				char hbuf[80];	/* bracket-wrap IPv6 host */

				snprintf(uri, sizeof(uri), "sip:%s@%s:%d",
					peer->defaultuser,
					sofia_uri_format_host(peer->host, hbuf, sizeof(hbuf)),
					peer->port);

				/* Outbound REGISTER Route from peer/[general] outboundproxy; sticky-on-handle. */
				sofia_format_outboundproxy(peer, route_buf, sizeof(route_buf));

				if (peer->nh) {
					/* Detach hmagic before destroying the previous handle: a late 401/200 on
					 * the old peer->nh would otherwise re-enter the register state machine
					 * against a stale handle. bind(NULL) makes it inert so the `if (hmagic)`
					 * gates short-circuit. */
					nua_handle_t *old_rnh = peer->nh;
					peer->nh = NULL;
					nua_handle_bind(old_rnh, NULL);
					nua_handle_destroy(old_rnh);
				}

				/* GRUU Phase 1 (gruu=yes): advertise a stable +sip.instance on the Contact so a
				 * GRUU-capable registrar can mint a pub-gruu. Advertisement only. */
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
				/* callbackextension: NUTAG_M_USERNAME drives the Contact URL username. */
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
		char tlscertfile[256];
		char wsbindaddr[64];
		int wsbindport;
		char wssbindaddr[64];
		int wssbindport;
		int tlsverify;
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
	s.tlscertfile[0] = '\0';
	s.wsbindaddr[0] = '\0';
	s.wsbindport = 0;
	s.wssbindaddr[0] = '\0';
	s.wssbindport = 0;
	s.tlsverify = 0;
	s.tls_ciphers[0] = '\0';
	s.tls_min_version[0] = '\0';
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
	SOFIA_LISTENER_CMP_STR(tlscertfile, "tlscertfile");
	SOFIA_LISTENER_CMP_STR(wsbindaddr, "wsbindaddr");
	SOFIA_LISTENER_CMP_INT(wsbindport, "wsbindport");
	SOFIA_LISTENER_CMP_STR(wssbindaddr, "wssbindaddr");
	SOFIA_LISTENER_CMP_INT(wssbindport, "wssbindport");
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

static int sofia_peer_sweep_cb(void *obj, void *arg, int flags)
{
	struct sofia_peer *peer = obj;
	if (!peer->_reload_marked || peer->is_realtime) {
		return 0;
	}
	/* Drain MWI before the final unref so the destructor's drain can't resurrect the peer. */
	sofia_peer_drain_mwi(peer);
	/* Drop our own dialplan hint (registrar matches sofia_create_peer_hint). */
	if (!ast_strlen_zero(peer->subscribecontext) && !ast_strlen_zero(peer->regexten)) {
		ast_context_remove_extension(peer->subscribecontext,
			peer->regexten, PRIORITY_HINT, "sofia_config_peer");
	}
	/* Release dnsmgr + drop its +1 ref FIRST, else the destructor never runs (its ref pins
	 * refcount >= 1 after ao2_unlink). ast_dnsmgr_release is synchronous (waits for in-flight
	 * callbacks), so no UAF window when ao2_unlink runs next. */
	if (peer->dnsmgr) {
		ast_dnsmgr_release(peer->dnsmgr);
		peer->dnsmgr = NULL;
		ao2_ref(peer, -1);
	}
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
 * but a dnsmgr ref would pin refcount >= 1 and leak the peer + res_dnsmgr entry. NOT under peer->lock
 * (ast_dnsmgr_release blocks on the dnsmgr list lock vs the peer->lock-taking callback). Safe after
 * sofia_thread is joined — it touches only res_dnsmgr's list. */
static int sofia_peer_dnsmgr_release_cb(void *obj, void *arg, int flags)
{
	struct sofia_peer *peer = obj;
	/* Drain MWI unconditionally (a peer may have mailboxes but no dnsmgr). */
	sofia_peer_drain_mwi(peer);
	if (peer->dnsmgr) {
		ast_dnsmgr_release(peer->dnsmgr);
		peer->dnsmgr = NULL;
		ao2_ref(peer, -1);
	}
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
		int pub_expires_was = sofia_cfg.publish_expires;
		ast_copy_string(pub_server_was, sofia_cfg.publish_server, sizeof(pub_server_was));
		ast_copy_string(pub_domain_was, sofia_cfg.publish_domain, sizeof(pub_domain_was));

		if (sofia_apply_config(cfg) < 0) {
			/* Don't sweep — a partial parse could remove live peers it didn't reach. */
			snprintf(local_errmsg, sizeof(local_errmsg),
				"sofia_apply_config failed — see log; no peers swept");
			ast_config_destroy(cfg);
			goto signal_done;
		}

		/* Sweep peers that disappeared from sofia.conf. */
		ao2_callback(peers, OBJ_NODATA | OBJ_UNLINK | OBJ_MULTIPLE,
			sofia_peer_sweep_cb, NULL);

		/* Outbound-PUBLISH reconcile: add/remove/rebuild publications to match the new config. */
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


static int load_module(void)
{
	int rc = AST_MODULE_LOAD_SUCCESS;
	int sofia_thread_started = 0;

	ast_verbose("Sofia-SIP channel loading...\n");

	/* Container allocation — checked individually; the err_cleanup ladder unwinds in reverse. */
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

	ast_pthread_create(&sofia_reg_thread, NULL, sofia_reg_thread_func, NULL);

	ast_pthread_create(&sofia_qualify_tid, NULL, sofia_qualify_thread, NULL);

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
	if (dialogs) {
		ao2_ref(dialogs, -1);
		dialogs = NULL;
	}
	if (peers) {
		/* Release every peer's dnsmgr handle + its +1 ref BEFORE dropping the container ref,
		 * else that ref pins each hostname-host peer at refcount >= 1 and leaks it + its
		 * res_dnsmgr entry (compounded across DECLINE retries). */
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
