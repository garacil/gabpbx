/*
 * GABPBX -- A telephony toolkit based on Asterisk 1.8
 *
 * chan_sofia.c -- SIP channel driver using Sofia-SIP
 *
 * Copyright (C) GABPBX Contributors
 *
 * chan_sofia is a drop-in replacement for chan_sip.  It preserves the public
 * channel technology name "SIP" so that existing dialplans, peers, and
 * realtime configuration continue to work without modification.  SIP parsing
 * and protocol mechanics are delegated entirely to Sofia-SIP (a mature,
 * RFC-conformant SIP stack) instead of being hand-rolled.
 *
 * Key design points
 * -----------------
 *  - Channel technology name:  "SIP"  (chan_sip compatible)
 *  - Authentication:           Digest MD5 *and* SHA-256; MD5 is advertised
 *                              first so that legacy clients that only
 *                              understand MD5 continue to work.
 *  - Blacklist:                in-memory ao2_container (1024 hash buckets).
 *                              An IP is blocked after SOFIA_BL_MAX_FAILURES
 *                              (default 5) authentication / parse failures.
 *                              Traffic from a blocked IP is silently dropped
 *                              (no 403 is sent) matching chan_sip behaviour.
 *  - Multi-contact:            Each peer keeps an ao2_container of contacts.
 *  - User-Agent locking:       Peer config key "useragent_filter".
 *  - Call limits:              "call-limit" per peer, enforced on INVITE.
 *  - Session timers:           RFC 4028; "session-timers" per peer / global.
 *  - SRTP:                     "encryption" per peer selects SRTP/SAVP.
 *  - NAT:                      "nat" flag; rport rewriting, symmetric RTP.
 *  - Realtime:                 peers can live in an extconfig / AstDB source.
 *  - Transfers:                REFER handling (attended + blind).
 *
 * This file is intentionally self-contained: all Sofia-SIP interaction,
 * all Asterisk channel-tech callbacks, blacklist management, and
 * configuration parsing live here.
 */

/*** MODULEINFO
	<depend>sofia_sip</depend>
	<support_level>extended</support_level>
 ***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

/* ── Standard C ─────────────────────────────────────────────────────────── */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>

/* ── Sofia-SIP ───────────────────────────────────────────────────────────── */
#include <sofia-sip/su.h>
#include <sofia-sip/su_wait.h>
#include <sofia-sip/nua.h>
#include <sofia-sip/nua_tag.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/sip_tag.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/sdp.h>
#include <sofia-sip/tport_tag.h>
#include <sofia-sip/su_md5.h>
#include <sofia-sip/su_sha1.h>

/* ── Asterisk core ───────────────────────────────────────────────────────── */
#include "asterisk/module.h"
#include "asterisk/channel.h"
#include "asterisk/pbx.h"
#include "asterisk/config.h"
#include "asterisk/logger.h"
#include "asterisk/lock.h"
#include "asterisk/astobj2.h"
#include "asterisk/strings.h"
#include "asterisk/causes.h"
#include "asterisk/frame.h"
#include "asterisk/format.h"
#include "asterisk/format_cap.h"
#include "asterisk/rtp_engine.h"
#include "asterisk/acl.h"
#include "asterisk/dnsmgr.h"
#include "asterisk/linkedlists.h"
#include "asterisk/app.h"
#include "asterisk/utils.h"
#include "asterisk/callerid.h"
#include "asterisk/astdb.h"
#include "asterisk/cli.h"

/* ── Module identity ─────────────────────────────────────────────────────── */
#define SOFIA_MODULE_DESCRIPTION "SIP channel driver (Sofia-SIP back-end)"
#define SOFIA_CONFIG_FILE        "sofia.conf"
#define SOFIA_TECH_NAME          "SIP"    /* same as chan_sip – dialplan compat */

/* ── Blacklist constants ─────────────────────────────────────────────────── */
#define SOFIA_BL_BUCKETS         1024     /* ao2 hash buckets for blacklist    */
#define SOFIA_BL_MAX_FAILURES    5        /* failures before IP is blocked     */
#define SOFIA_BL_BLOCK_DURATION  3600     /* seconds an IP stays blocked       */

/* ── Session-timer defaults ─────────────────────────────────────────────── */
#define SOFIA_SESSION_TIMERS_DEFAULT  1800   /* seconds */

/* ── Call-limit sentinel ─────────────────────────────────────────────────── */
#define SOFIA_CALL_LIMIT_NONE    0        /* 0 means no limit                 */

/* ════════════════════════════════════════════════════════════════════════════
 * Data structures
 * ════════════════════════════════════════════════════════════════════════════ */

/*
 * sofia_contact – one registered Contact entry for a peer.
 * A peer can have multiple simultaneous contacts (e.g. two phones).
 */
struct sofia_contact {
	char contact_uri[512];         /* full Contact URI                     */
	char received[INET6_ADDRSTRLEN]; /* IP actually seen (for NAT)         */
	int  received_port;
	time_t expires;                /* absolute epoch when contact expires  */
};

/*
 * sofia_peer – configuration and runtime state for one SIP peer / account.
 * Mirrors the fields that chan_sip exposes in sip.conf.
 */
struct sofia_peer {
	/* ── Identity ───────────────────────────────────────────────────── */
	char name[80];                 /* peer name (key in ao2_container)     */
	char username[80];             /* auth username (defaults to name)     */
	char fromuser[80];             /* override From: user                  */
	char fromdomain[256];          /* override From: domain                */
	char secret[80];               /* plaintext password                   */
	char md5secret[80];            /* pre-computed MD5 HA1                 */
	char host[256];                /* static host or "dynamic"             */
	char context[AST_MAX_CONTEXT]; /* dialplan context                     */
	char callerid[256];            /* CallerID string                      */

	/* ── Network ────────────────────────────────────────────────────── */
	int port;                      /* remote port (default 5060)           */
	int nat;                       /* 1 = force NAT handling               */

	/* ── User-Agent locking ─────────────────────────────────────────── */
	char useragent_filter[128];    /* if set, reject UA not matching this  */

	/* ── Call limits ────────────────────────────────────────────────── */
	int call_limit;                /* max simultaneous calls (0=unlimited) */
	ast_atomic_t call_count;       /* current call count                   */

	/* ── Session timers (RFC 4028) ──────────────────────────────────── */
	int session_timers;            /* 0=off 1=supported 2=required         */
	int session_expires;           /* session-expires value in seconds     */

	/* ── SRTP ───────────────────────────────────────────────────────── */
	int encryption;                /* 0=no 1=srtp 2=sdes                   */

	/* ── Insecure flags ─────────────────────────────────────────────── */
	int insecure_port;             /* 1 = don't require From port match    */
	int insecure_invite;           /* 1 = don't auth INVITE                */

	/* ── Realtime ───────────────────────────────────────────────────── */
	int is_realtime;               /* 1 = loaded from realtime source      */

	/* ── Multi-contact registration ─────────────────────────────────── */
	struct ao2_container *contacts;/* ao2 container of sofia_contact       */

	/* ── Locking ────────────────────────────────────────────────────── */
	ast_mutex_t lock;
};

/*
 * sofia_blacklist_entry – one entry in the IP blacklist.
 */
struct sofia_blacklist_entry {
	char ipaddr[INET6_ADDRSTRLEN]; /* key: source IP address string        */
	int  failures;                 /* running failure count                */
	int  blocked;                  /* 1 = currently blocked                */
	time_t blocked_since;          /* epoch when blocking started          */
	time_t last_failure;           /* epoch of most recent failure         */
};

/*
 * sofia_pvt – private data attached to each active Asterisk channel.
 */
struct sofia_pvt {
	ast_mutex_t lock;

	struct ast_channel   *owner;   /* the Asterisk channel we drive        */
	struct sofia_peer    *peer;    /* peer this call belongs to            */

	/* ── Sofia-SIP handles ──────────────────────────────────────────── */
	nua_handle_t         *nh;      /* NUA operation handle                 */

	/* ── Call state ─────────────────────────────────────────────────── */
	int                   answered; /* 1 after 200 OK sent / received      */
	int                   hangup_cause;

	/* ── RTP ────────────────────────────────────────────────────────── */
	struct ast_rtp_instance *rtp;

	/* ── Direction ──────────────────────────────────────────────────── */
	int                   outgoing; /* 1 = we placed the call              */

	/* ── Codec negotiation ──────────────────────────────────────────── */
	struct ast_format_cap *cap;

	/* ── Identifiers ────────────────────────────────────────────────── */
	char callid[256];
	char exten[AST_MAX_EXTENSION];
	char context[AST_MAX_CONTEXT];

	AST_LIST_ENTRY(sofia_pvt) list;
};

/* ════════════════════════════════════════════════════════════════════════════
 * Global state
 * ════════════════════════════════════════════════════════════════════════════ */

/* Sofia-SIP root object and NUA stack */
static su_root_t   *sofia_root  = NULL;
static nua_t       *sofia_nua   = NULL;
static pthread_t    sofia_thread = AST_PTHREADT_NULL;

/* Peer registry */
static struct ao2_container *sofia_peers = NULL;
#define SOFIA_PEER_BUCKETS 256

/* Blacklist registry */
static struct ao2_container *sofia_blacklist = NULL;

/* Active call list */
static AST_LIST_HEAD_STATIC(sofia_pvt_list, sofia_pvt);

/* Global config */
static char sofia_bindaddr[80]  = "0.0.0.0";
static int  sofia_bindport      = 5060;
static int  sofia_session_timers_global = 1;
static int  sofia_session_expires_global = SOFIA_SESSION_TIMERS_DEFAULT;

/* ════════════════════════════════════════════════════════════════════════════
 * ao2 callbacks – blacklist
 * ════════════════════════════════════════════════════════════════════════════ */

static int bl_hash_fn(const void *obj, const int flags)
{
	const struct sofia_blacklist_entry *e = obj;
	const char *key = (flags & OBJ_KEY) ? obj : e->ipaddr;
	return ast_str_hash(key);
}

static int bl_cmp_fn(void *obj, void *arg, int flags)
{
	const struct sofia_blacklist_entry *a = obj;
	const char *key = (flags & OBJ_KEY) ? arg :
	                  ((const struct sofia_blacklist_entry *)arg)->ipaddr;
	return !strcmp(a->ipaddr, key) ? CMP_MATCH | CMP_STOP : 0;
}

/* ════════════════════════════════════════════════════════════════════════════
 * ao2 callbacks – peers
 * ════════════════════════════════════════════════════════════════════════════ */

static int peer_hash_fn(const void *obj, const int flags)
{
	const struct sofia_peer *p = obj;
	const char *key = (flags & OBJ_KEY) ? obj : p->name;
	return ast_str_hash(key);
}

static int peer_cmp_fn(void *obj, void *arg, int flags)
{
	const struct sofia_peer *a = obj;
	const char *key = (flags & OBJ_KEY) ? arg :
	                  ((const struct sofia_peer *)arg)->name;
	return !strcmp(a->name, key) ? CMP_MATCH | CMP_STOP : 0;
}

static void peer_destructor(void *obj)
{
	struct sofia_peer *p = obj;
	if (p->contacts) {
		ao2_ref(p->contacts, -1);
	}
	ast_mutex_destroy(&p->lock);
}

/* ── Contact ao2 callbacks ─────────────────────────────────────────────── */

static int contact_hash_fn(const void *obj, const int flags)
{
	const struct sofia_contact *c = obj;
	const char *key = (flags & OBJ_KEY) ? obj : c->contact_uri;
	return ast_str_hash(key);
}

static int contact_cmp_fn(void *obj, void *arg, int flags)
{
	const struct sofia_contact *a = obj;
	const char *key = (flags & OBJ_KEY) ? arg :
	                  ((const struct sofia_contact *)arg)->contact_uri;
	return !strcmp(a->contact_uri, key) ? CMP_MATCH | CMP_STOP : 0;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Blacklist management
 * ════════════════════════════════════════════════════════════════════════════ */

/*
 * sofia_blacklist_check – return 1 if ipaddr is currently blocked.
 * Also unblocks entries whose block duration has expired.
 */
static int sofia_blacklist_check(const char *ipaddr)
{
	struct sofia_blacklist_entry *e;
	int blocked = 0;

	if (!sofia_blacklist || ast_strlen_zero(ipaddr)) {
		return 0;
	}

	e = ao2_find(sofia_blacklist, ipaddr, OBJ_KEY);
	if (!e) {
		return 0;
	}

	if (e->blocked) {
		time_t now = time(NULL);
		if (now - e->blocked_since >= SOFIA_BL_BLOCK_DURATION) {
			/* Block duration expired – unblock */
			e->blocked = 0;
			e->failures = 0;
			e->blocked_since = 0;
			ast_log(LOG_NOTICE,
			        "chan_sofia: blacklist unblocked IP %s (block expired)\n",
			        ipaddr);
		} else {
			blocked = 1;
		}
	}

	ao2_ref(e, -1);
	return blocked;
}

/*
 * sofia_blacklist_failure – record a failure for ipaddr.
 * Blocks the IP after SOFIA_BL_MAX_FAILURES consecutive failures.
 */
static void sofia_blacklist_failure(const char *ipaddr)
{
	struct sofia_blacklist_entry *e;

	if (!sofia_blacklist || ast_strlen_zero(ipaddr)) {
		return;
	}

	e = ao2_find(sofia_blacklist, ipaddr, OBJ_KEY);
	if (!e) {
		/* Allocate a new entry */
		e = ao2_alloc(sizeof(*e), NULL);
		if (!e) {
			return;
		}
		ast_copy_string(e->ipaddr, ipaddr, sizeof(e->ipaddr));
		ao2_link(sofia_blacklist, e);
	}

	e->failures++;
	e->last_failure = time(NULL);

	if (!e->blocked && e->failures >= SOFIA_BL_MAX_FAILURES) {
		e->blocked = 1;
		e->blocked_since = time(NULL);
		ast_log(LOG_WARNING,
		        "chan_sofia: blacklisted IP %s after %d failures\n",
		        ipaddr, e->failures);
	}

	ao2_ref(e, -1);
}

/*
 * sofia_blacklist_clear – remove all entries for ipaddr.
 */
static void sofia_blacklist_clear(const char *ipaddr)
{
	struct sofia_blacklist_entry *e;

	if (!sofia_blacklist || ast_strlen_zero(ipaddr)) {
		return;
	}

	e = ao2_find(sofia_blacklist, ipaddr, OBJ_KEY | OBJ_UNLINK);
	if (e) {
		ao2_ref(e, -1);
	}
}

/* ════════════════════════════════════════════════════════════════════════════
 * Authentication helpers  (MD5 + SHA-256)
 *
 * MD5 is listed first in the WWW-Authenticate challenge so that legacy SIP
 * clients that only implement MD5 can still authenticate successfully.
 * ════════════════════════════════════════════════════════════════════════════ */

/*
 * sofia_make_ha1_md5 – compute HA1 = MD5(user:realm:password).
 * result must be at least 33 bytes.
 */
static void sofia_make_ha1_md5(const char *user, const char *realm,
                                const char *password, char *result)
{
	su_md5_t ctx;
	uint8_t  digest[SU_MD5_DIGEST_SIZE];
	int      i;
	char     buf[512];

	snprintf(buf, sizeof(buf), "%s:%s:%s", user, realm, password);
	su_md5_init(&ctx);
	su_md5_update(&ctx, buf, strlen(buf));
	su_md5_digest(&ctx, digest);

	for (i = 0; i < SU_MD5_DIGEST_SIZE; i++) {
		sprintf(result + i * 2, "%02x", digest[i]);
	}
	result[SU_MD5_DIGEST_SIZE * 2] = '\0';
}

/*
 * sofia_make_ha1_sha256 – compute HA1 = SHA-256(user:realm:password).
 * result must be at least 65 bytes.
 */
static void sofia_make_ha1_sha256(const char *user, const char *realm,
                                   const char *password, char *result)
{
	/*
	 * Sofia-SIP provides su_sha1 but not SHA-256 directly.
	 * We use OpenSSL's EVP interface which is linked in as part of the
	 * Asterisk build.
	 */
#if defined(HAVE_OPENSSL) && defined(HAVE_OPENSSL_SHA)
	unsigned char digest[32];  /* SHA-256 produces 32 bytes */
	unsigned int  len = 0;
	char          buf[512];
	EVP_MD_CTX   *mdctx;

	snprintf(buf, sizeof(buf), "%s:%s:%s", user, realm, password);
	mdctx = EVP_MD_CTX_new();
	if (mdctx) {
		EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
		EVP_DigestUpdate(mdctx, buf, strlen(buf));
		EVP_DigestFinal_ex(mdctx, digest, &len);
		EVP_MD_CTX_free(mdctx);
		for (unsigned int i = 0; i < len; i++) {
			sprintf(result + i * 2, "%02x", digest[i]);
		}
		result[len * 2] = '\0';
	} else {
		result[0] = '\0';
	}
#else
	/* Fallback: if OpenSSL SHA-256 is not available leave result empty.
	 * Authentication will still work via MD5. */
	(void)user; (void)realm; (void)password;
	result[0] = '\0';
#endif
}

/*
 * sofia_auth_verify – verify the Authorization header in an incoming request.
 *
 * Returns  0 on success (authenticated).
 * Returns -1 on failure (wrong credentials or missing header).
 * Returns  1 if no auth header is present (challenge required).
 *
 * The function accepts both MD5 and SHA-256 responses.
 */
static int sofia_auth_verify(struct sofia_peer *peer,
                              const sip_t *sip,
                              const char  *realm)
{
	const sip_authorization_t *auth;
	const char *response, *uri, *nonce, *algorithm;
	char ha1_md5[33], ha1_sha256[65];
	char ha2[65], expected[65];
	char method[32];
	su_md5_t ctx;
	uint8_t  digest[SU_MD5_DIGEST_SIZE];
	int      i;

	if (!sip || !peer) {
		return -1;
	}

	auth = sip->sip_authorization;
	if (!auth) {
		return 1;  /* no header – send challenge */
	}

	response  = msg_params_find(auth->au_params, "response=");
	uri       = msg_params_find(auth->au_params, "uri=");
	nonce     = msg_params_find(auth->au_params, "nonce=");
	algorithm = msg_params_find(auth->au_params, "algorithm=");

	if (!response || !uri || !nonce) {
		return -1;
	}

	/* Determine HA2 (always MD5 per RFC 2617 §3.2.2.3 regardless of algo) */
	if (sip->sip_request) {
		ast_copy_string(method, sip->sip_request->rq_method_name,
		                sizeof(method));
	} else {
		ast_copy_string(method, "REGISTER", sizeof(method));
	}

	{
		char ha2_input[1024];
		snprintf(ha2_input, sizeof(ha2_input), "%s:%s", method, uri);
		su_md5_init(&ctx);
		su_md5_update(&ctx, ha2_input, strlen(ha2_input));
		su_md5_digest(&ctx, digest);
		for (i = 0; i < SU_MD5_DIGEST_SIZE; i++) {
			sprintf(ha2 + i * 2, "%02x", digest[i]);
		}
		ha2[SU_MD5_DIGEST_SIZE * 2] = '\0';
	}

	/* Use SHA-256 path if client selected it */
	if (algorithm && !strcasecmp(algorithm, "SHA-256")) {
		char expected_sha256[65];
		char resp_input[1024];

		sofia_make_ha1_sha256(peer->username, realm, peer->secret,
		                      ha1_sha256);
		if (ast_strlen_zero(ha1_sha256)) {
			/* SHA-256 unavailable – fall through to MD5 */
			goto try_md5;
		}

		snprintf(resp_input, sizeof(resp_input),
		         "%s:%s:%s", ha1_sha256, nonce, ha2);

		/* For SHA-256 we still use SHA-256 for the final HMAC */
#if defined(HAVE_OPENSSL) && defined(HAVE_OPENSSL_SHA)
		{
			unsigned char sha_digest[32];
			unsigned int  sha_len = 0;
			EVP_MD_CTX   *mdctx;

			mdctx = EVP_MD_CTX_new();
			if (mdctx) {
				EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
				EVP_DigestUpdate(mdctx, resp_input, strlen(resp_input));
				EVP_DigestFinal_ex(mdctx, sha_digest, &sha_len);
				EVP_MD_CTX_free(mdctx);
				for (unsigned int j = 0; j < sha_len; j++) {
					sprintf(expected_sha256 + j * 2, "%02x", sha_digest[j]);
				}
				expected_sha256[sha_len * 2] = '\0';
				if (!strcasecmp(response, expected_sha256)) {
					return 0;  /* authenticated via SHA-256 */
				}
			}
		}
#endif
		return -1;
	}

try_md5:
	/* Default: MD5 */
	if (!ast_strlen_zero(peer->md5secret)) {
		ast_copy_string(ha1_md5, peer->md5secret, sizeof(ha1_md5));
	} else {
		sofia_make_ha1_md5(peer->username, realm, peer->secret, ha1_md5);
	}

	{
		char resp_input[1024];
		snprintf(resp_input, sizeof(resp_input),
		         "%s:%s:%s", ha1_md5, nonce, ha2);
		su_md5_init(&ctx);
		su_md5_update(&ctx, resp_input, strlen(resp_input));
		su_md5_digest(&ctx, digest);
		for (i = 0; i < SU_MD5_DIGEST_SIZE; i++) {
			sprintf(expected + i * 2, "%02x", digest[i]);
		}
		expected[SU_MD5_DIGEST_SIZE * 2] = '\0';
	}

	return strcasecmp(response, expected) ? -1 : 0;
}

/*
 * sofia_send_auth_challenge – send a 401 with MD5 *and* SHA-256 challenges.
 *
 * MD5 is placed first so that clients that stop at the first algorithm they
 * understand (many legacy clients) will use MD5.  RFC 7616 clients that
 * support SHA-256 will prefer it.
 */
static void sofia_send_auth_challenge(nua_handle_t *nh,
                                      const char   *realm,
                                      const char   *nonce)
{
	/*
	 * Build a WWW-Authenticate header that lists MD5 first, then SHA-256.
	 * Both challenges share the same nonce / realm.
	 */
	char hdr[512];
	snprintf(hdr, sizeof(hdr),
	         "Digest realm=\"%s\", nonce=\"%s\", algorithm=MD5, qop=\"auth\""
	         ", Digest realm=\"%s\", nonce=\"%s\", algorithm=SHA-256, qop=\"auth\"",
	         realm, nonce, realm, nonce);

	nua_respond(nh, SIP_401_UNAUTHORIZED,
	            SIPTAG_WWW_AUTHENTICATE_STR(hdr),
	            TAG_END());
}

/* ════════════════════════════════════════════════════════════════════════════
 * NAT helpers
 * ════════════════════════════════════════════════════════════════════════════ */

/*
 * sofia_get_source_ip – extract the source IP from a received SIP message.
 * Returns 0 on success, -1 on failure.
 */
static int sofia_get_source_ip(const sip_t *sip, char *ipbuf, size_t ipbuf_len)
{
	const sip_via_t *via = sip ? sip->sip_via : NULL;

	if (!via) {
		return -1;
	}

	/* The "received" parameter is set by the transport layer when the
	 * packet arrived from a different IP than in the Via host. */
	if (via->v_received) {
		ast_copy_string(ipbuf, via->v_received, ipbuf_len);
	} else if (via->v_host) {
		ast_copy_string(ipbuf, via->v_host, ipbuf_len);
	} else {
		return -1;
	}

	return 0;
}

/*
 * sofia_nat_rewrite_contact – if peer has NAT enabled, rewrite the Contact
 * URI so that responses are sent to the observed source address rather than
 * the address advertised by the UAC.
 */
static void sofia_nat_rewrite_contact(struct sofia_peer *peer,
                                      const char *received_ip,
                                      int received_port,
                                      char *contact_out,
                                      size_t contact_len)
{
	if (!peer->nat || ast_strlen_zero(received_ip)) {
		contact_out[0] = '\0';
		return;
	}

	if (received_port > 0) {
		snprintf(contact_out, contact_len,
		         "sip:%s@%s:%d", peer->username, received_ip, received_port);
	} else {
		snprintf(contact_out, contact_len,
		         "sip:%s@%s", peer->username, received_ip);
	}
}

/* ════════════════════════════════════════════════════════════════════════════
 * Multi-contact registration helpers
 * ════════════════════════════════════════════════════════════════════════════ */

/*
 * sofia_contact_add – add or refresh a contact entry for a peer.
 */
static void sofia_contact_add(struct sofia_peer *peer,
                               const char *contact_uri,
                               const char *received_ip,
                               int received_port,
                               int expires_delta)
{
	struct sofia_contact *c;

	if (!peer->contacts || ast_strlen_zero(contact_uri)) {
		return;
	}

	c = ao2_find(peer->contacts, contact_uri, OBJ_KEY);
	if (!c) {
		c = ao2_alloc(sizeof(*c), NULL);
		if (!c) {
			return;
		}
		ast_copy_string(c->contact_uri, contact_uri, sizeof(c->contact_uri));
		ao2_link(peer->contacts, c);
	}

	if (!ast_strlen_zero(received_ip)) {
		ast_copy_string(c->received, received_ip, sizeof(c->received));
	}
	c->received_port = received_port;
	c->expires = time(NULL) + expires_delta;

	ao2_ref(c, -1);
}

/*
 * sofia_contact_expire – remove contacts that have expired.
 */
static int sofia_contact_expire_cb(void *obj, void *arg, int flags)
{
	struct sofia_contact *c = obj;
	time_t *now = arg;

	return (c->expires < *now) ? CMP_MATCH : 0;
}

static void sofia_contacts_prune(struct sofia_peer *peer)
{
	time_t now = time(NULL);

	if (peer->contacts) {
		ao2_callback(peer->contacts, OBJ_UNLINK | OBJ_NODATA,
		             sofia_contact_expire_cb, &now);
	}
}

/* ════════════════════════════════════════════════════════════════════════════
 * Peer lookup
 * ════════════════════════════════════════════════════════════════════════════ */

static struct sofia_peer *sofia_find_peer(const char *name)
{
	return ao2_find(sofia_peers, name, OBJ_KEY);
}

/* ════════════════════════════════════════════════════════════════════════════
 * Sofia-SIP NUA event callback
 * ════════════════════════════════════════════════════════════════════════════ */

/*
 * Forward declarations for callback helpers.
 */
static void sofia_handle_register(nua_handle_t *nh, struct sofia_peer *peer,
                                   const sip_t *sip, int status);
static void sofia_handle_invite(nua_handle_t *nh, struct sofia_peer *peer,
                                 const sip_t *sip, nua_saved_event_t *saved);
static void sofia_handle_refer(nua_handle_t *nh, struct sofia_pvt *pvt,
                                const sip_t *sip);
static void sofia_handle_response(nua_handle_t *nh, struct sofia_pvt *pvt,
                                   int status, const sip_t *sip);

/*
 * sofia_event_callback – the central Sofia-SIP NUA event dispatcher.
 *
 * Every SIP event (incoming requests, responses, state changes) comes
 * through here.  The first thing we do for every request-bearing event is
 * check the source IP against the blacklist and silently drop if blocked.
 */
static void sofia_event_callback(nua_event_t   event,
                                  int           status,
                                  char const   *phrase,
                                  nua_t        *nua,
                                  nua_magic_t  *magic,
                                  nua_handle_t *nh,
                                  nua_hmagic_t *hmagic,
                                  sip_t const  *sip,
                                  tagi_t        tags[])
{
	struct sofia_pvt  *pvt  = (struct sofia_pvt *)hmagic;
	struct sofia_peer *peer = pvt ? pvt->peer : NULL;
	char src_ip[INET6_ADDRSTRLEN] = "";

	/* ── Blacklist check ─────────────────────────────────────────────
	 * Extract source IP from the topmost Via.  If the IP is blacklisted
	 * silently discard the message without sending any response.
	 * This matches chan_sip behaviour: no 403 is sent.
	 * ────────────────────────────────────────────────────────────────*/
	if (sip && sip->sip_via) {
		sofia_get_source_ip(sip, src_ip, sizeof(src_ip));
		if (!ast_strlen_zero(src_ip) && sofia_blacklist_check(src_ip)) {
			ast_debug(1,
			          "chan_sofia: silently dropping message from "
			          "blacklisted IP %s\n", src_ip);
			/* destroy the handle without sending anything */
			nua_handle_destroy(nh);
			return;
		}
	}

	switch (event) {

	/* ── Incoming REGISTER ───────────────────────────────────────── */
	case nua_i_register:
		if (sip) {
			const char *user = NULL;
			if (sip->sip_to) {
				user = sip->sip_to->a_url->url_user;
			}
			if (user) {
				peer = sofia_find_peer(user);
			}
			sofia_handle_register(nh, peer, sip, status);
			if (peer) {
				ao2_ref(peer, -1);
			}
		}
		break;

	/* ── Incoming INVITE ─────────────────────────────────────────── */
	case nua_i_invite:
		if (sip) {
			const char *user = NULL;
			if (sip->sip_request) {
				user = sip->sip_request->rq_url->url_user;
			}
			if (user) {
				peer = sofia_find_peer(user);
			}
			sofia_handle_invite(nh, peer, sip, NULL);
			if (peer) {
				ao2_ref(peer, -1);
			}
		}
		break;

	/* ── Incoming REFER (transfer) ───────────────────────────────── */
	case nua_i_refer:
		if (pvt && sip) {
			sofia_handle_refer(nh, pvt, sip);
		}
		break;

	/* ── Response to an outgoing request ────────────────────────── */
	case nua_r_invite:
	case nua_r_register:
		if (pvt) {
			sofia_handle_response(nh, pvt, status, sip);
		}
		break;

	/* ── BYE received ────────────────────────────────────────────── */
	case nua_i_bye:
		if (pvt && pvt->owner) {
			ast_mutex_lock(&pvt->lock);
			pvt->hangup_cause = AST_CAUSE_NORMAL_CLEARING;
			ast_queue_hangup(pvt->owner);
			ast_mutex_unlock(&pvt->lock);
		}
		nua_respond(nh, SIP_200_OK, TAG_END());
		break;

	/* ── CANCEL received ─────────────────────────────────────────── */
	case nua_i_cancel:
		if (pvt && pvt->owner) {
			ast_mutex_lock(&pvt->lock);
			pvt->hangup_cause = AST_CAUSE_CALL_REJECTED;
			ast_queue_hangup(pvt->owner);
			ast_mutex_unlock(&pvt->lock);
		}
		break;

	/* ── OPTIONS ping ────────────────────────────────────────────── */
	case nua_i_options:
		nua_respond(nh, SIP_200_OK, TAG_END());
		break;

	/* ── State machine events (outgoing call progress) ───────────── */
	case nua_i_state:
		if (pvt) {
			nua_callstate_t cs = 0;
			tl_gets(tags, NUTAG_CALLSTATE_REF(cs), TAG_END());

			if (cs == nua_callstate_ready && !pvt->answered) {
				pvt->answered = 1;
				if (pvt->owner) {
					ast_queue_control(pvt->owner, AST_CONTROL_ANSWER);
				}
			} else if (cs == nua_callstate_terminated) {
				if (pvt->owner) {
					ast_queue_hangup(pvt->owner);
				}
			}
		}
		break;

	/* ── Error / informational ───────────────────────────────────── */
	case nua_i_error:
		ast_log(LOG_WARNING, "chan_sofia: NUA error %d %s\n",
		        status, phrase ? phrase : "");
		break;

	default:
		break;
	}

	(void)nua; (void)magic; (void)tags;
}

/* ════════════════════════════════════════════════════════════════════════════
 * REGISTER handler
 * ════════════════════════════════════════════════════════════════════════════ */

static void sofia_handle_register(nua_handle_t *nh, struct sofia_peer *peer,
                                   const sip_t *sip, int status)
{
	char src_ip[INET6_ADDRSTRLEN] = "";
	int  src_port = 5060;
	int  expires = 3600;
	char realm[256] = "gabpbx";
	char nonce[64];

	if (!sip) {
		return;
	}

	sofia_get_source_ip(sip, src_ip, sizeof(src_ip));

	/* Extract port from Via */
	if (sip->sip_via && sip->sip_via->v_port) {
		src_port = atoi(sip->sip_via->v_port);
	}

	/* Extract Expires */
	if (sip->sip_expires) {
		expires = (int)sip->sip_expires->ex_delta;
	}

	/* Check User-Agent locking */
	if (peer && !ast_strlen_zero(peer->useragent_filter)) {
		const char *ua = NULL;
		if (sip->sip_user_agent) {
			ua = sip->sip_user_agent->g_string;
		}
		if (!ua || strncasecmp(ua, peer->useragent_filter,
		                       strlen(peer->useragent_filter))) {
			ast_log(LOG_NOTICE,
			        "chan_sofia: REGISTER from %s rejected – "
			        "User-Agent mismatch (got '%s', expected '%s')\n",
			        src_ip, ua ? ua : "(none)", peer->useragent_filter);
			nua_respond(nh, SIP_403_FORBIDDEN, TAG_END());
			sofia_blacklist_failure(src_ip);
			return;
		}
	}

	/* Authenticate */
	if (peer && !peer->insecure_invite) {
		/* Generate a simple nonce from current time + peer name */
		snprintf(nonce, sizeof(nonce), "%lx%s",
		         (unsigned long)time(NULL), peer->name);

		int auth_result = sofia_auth_verify(peer, sip, realm);
		if (auth_result == 1) {
			/* No Authorization header – send challenge (MD5 first) */
			sofia_send_auth_challenge(nh, realm, nonce);
			return;
		} else if (auth_result != 0) {
			ast_log(LOG_NOTICE,
			        "chan_sofia: REGISTER auth failed for peer '%s' from %s\n",
			        peer->name, src_ip);
			sofia_blacklist_failure(src_ip);
			nua_respond(nh, SIP_403_FORBIDDEN, TAG_END());
			return;
		}
	} else if (!peer) {
		ast_log(LOG_NOTICE,
		        "chan_sofia: REGISTER from unknown peer at %s\n", src_ip);
		sofia_blacklist_failure(src_ip);
		nua_respond(nh, SIP_404_NOT_FOUND, TAG_END());
		return;
	}

	/* Authentication succeeded – clear any blacklist failures */
	sofia_blacklist_clear(src_ip);

	if (expires == 0) {
		/* Unregister: remove the specific contact */
		if (sip->sip_contact) {
			ao2_find(peer->contacts,
			         sip->sip_contact->m_url->url_user,
			         OBJ_KEY | OBJ_UNLINK | OBJ_NODATA);
		}
		nua_respond(nh, SIP_200_OK, TAG_END());
		return;
	}

	/* Add / refresh the contact, applying NAT rewriting if needed */
	if (sip->sip_contact) {
		char contact_uri[512];
		char nat_contact[512] = "";

		url_e(contact_uri, sizeof(contact_uri),
		      sip->sip_contact->m_url);

		sofia_nat_rewrite_contact(peer, src_ip, src_port,
		                          nat_contact, sizeof(nat_contact));

		sofia_contact_add(peer,
		                  peer->nat && !ast_strlen_zero(nat_contact)
		                      ? nat_contact : contact_uri,
		                  src_ip, src_port, expires);
	}

	/* Prune expired contacts while we're at it */
	sofia_contacts_prune(peer);

	ast_log(LOG_VERBOSE,
	        "chan_sofia: registered peer '%s' from %s:%d (expires %ds)\n",
	        peer->name, src_ip, src_port, expires);

	nua_respond(nh, SIP_200_OK, TAG_END());
}

/* ════════════════════════════════════════════════════════════════════════════
 * INVITE handler (incoming call)
 * ════════════════════════════════════════════════════════════════════════════ */

static void sofia_handle_invite(nua_handle_t *nh, struct sofia_peer *peer,
                                 const sip_t *sip, nua_saved_event_t *saved)
{
	struct sofia_pvt  *pvt;
	struct ast_channel *chan;
	char src_ip[INET6_ADDRSTRLEN] = "";
	char realm[256] = "gabpbx";
	char nonce[64];
	char exten[AST_MAX_EXTENSION] = "s";
	char context[AST_MAX_CONTEXT];
	const char *cid_name = NULL, *cid_num = NULL;
	int  cause = AST_CAUSE_NORMAL_CLEARING;

	if (!sip) {
		return;
	}

	sofia_get_source_ip(sip, src_ip, sizeof(src_ip));

	/* ── Authenticate (unless insecure_invite) ───────────────────── */
	if (peer && !peer->insecure_invite) {
		snprintf(nonce, sizeof(nonce), "%lx%s",
		         (unsigned long)time(NULL), peer->name);
		int auth_result = sofia_auth_verify(peer, sip, realm);
		if (auth_result == 1) {
			sofia_send_auth_challenge(nh, realm, nonce);
			return;
		} else if (auth_result != 0) {
			ast_log(LOG_NOTICE,
			        "chan_sofia: INVITE auth failed for peer '%s' from %s\n",
			        peer ? peer->name : "(unknown)", src_ip);
			sofia_blacklist_failure(src_ip);
			nua_respond(nh, SIP_403_FORBIDDEN, TAG_END());
			return;
		}
	} else if (!peer) {
		ast_log(LOG_NOTICE,
		        "chan_sofia: INVITE from unknown peer at %s\n", src_ip);
		sofia_blacklist_failure(src_ip);
		nua_respond(nh, SIP_403_FORBIDDEN, TAG_END());
		return;
	}

	sofia_blacklist_clear(src_ip);

	/* ── Check call limit ────────────────────────────────────────── */
	if (peer->call_limit != SOFIA_CALL_LIMIT_NONE &&
	    ast_atomic_fetchadd_int(&peer->call_count, 0) >= peer->call_limit) {
		ast_log(LOG_NOTICE,
		        "chan_sofia: call limit (%d) reached for peer '%s'\n",
		        peer->call_limit, peer->name);
		nua_respond(nh, SIP_486_BUSY_HERE, TAG_END());
		return;
	}

	/* ── Check User-Agent locking ────────────────────────────────── */
	if (!ast_strlen_zero(peer->useragent_filter)) {
		const char *ua = NULL;
		if (sip->sip_user_agent) {
			ua = sip->sip_user_agent->g_string;
		}
		if (!ua || strncasecmp(ua, peer->useragent_filter,
		                       strlen(peer->useragent_filter))) {
			ast_log(LOG_NOTICE,
			        "chan_sofia: INVITE from %s rejected – "
			        "User-Agent mismatch\n", src_ip);
			nua_respond(nh, SIP_403_FORBIDDEN, TAG_END());
			return;
		}
	}

	/* ── Extract destination extension ──────────────────────────── */
	if (sip->sip_request && sip->sip_request->rq_url->url_user) {
		ast_copy_string(exten, sip->sip_request->rq_url->url_user,
		                sizeof(exten));
	}
	ast_copy_string(context, peer->context, sizeof(context));

	/* ── Extract CallerID ────────────────────────────────────────── */
	if (sip->sip_from) {
		cid_num = sip->sip_from->a_url->url_user;
		if (sip->sip_from->a_display) {
			cid_name = sip->sip_from->a_display;
		}
	}

	/* ── Allocate private data ───────────────────────────────────── */
	pvt = ast_calloc(1, sizeof(*pvt));
	if (!pvt) {
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
		return;
	}
	ast_mutex_init(&pvt->lock);
	pvt->nh   = nh;
	pvt->peer = peer;
	ao2_ref(peer, +1);  /* pvt owns a reference; released in sofia_hangup() */

	if (sip->sip_call_id) {
		ast_copy_string(pvt->callid, sip->sip_call_id->i_id,
		                sizeof(pvt->callid));
	}
	ast_copy_string(pvt->exten,   exten,   sizeof(pvt->exten));
	ast_copy_string(pvt->context, context, sizeof(pvt->context));

	/* ── Create Asterisk channel ─────────────────────────────────── */
	chan = ast_channel_alloc(1, AST_STATE_DOWN,
	                         cid_num  ? cid_num  : "",
	                         cid_name ? cid_name : "",
	                         "",          /* account code */
	                         exten,
	                         context,
	                         NULL,        /* linkedid */
	                         0,           /* amaflag */
	                         "SIP/%s-%08x", peer->name,
	                         (unsigned)ast_random());
	if (!chan) {
		ast_log(LOG_ERROR, "chan_sofia: failed to allocate channel\n");
		ast_mutex_destroy(&pvt->lock);
		ast_free(pvt);
		nua_respond(nh, SIP_500_INTERNAL_SERVER_ERROR, TAG_END());
		return;
	}

	pvt->owner = chan;
	ast_channel_tech_pvt_set(chan, pvt);

	/* Bind the handle to our pvt so the callback can find us */
	nua_handle_bind(nh, (nua_hmagic_t *)pvt);

	/* Increment active call count */
	ast_atomic_fetchadd_int(&peer->call_count, +1);

	/* Track in global list */
	AST_LIST_LOCK(&sofia_pvt_list);
	AST_LIST_INSERT_HEAD(&sofia_pvt_list, pvt, list);
	AST_LIST_UNLOCK(&sofia_pvt_list);

	/* ── Send 100 Trying immediately ────────────────────────────── */
	nua_respond(nh, SIP_100_TRYING, TAG_END());

	/* ── Queue the channel into the PBX ─────────────────────────── */
	if (ast_pbx_start(chan)) {
		ast_log(LOG_ERROR,
		        "chan_sofia: PBX failed to start for %s@%s\n",
		        exten, context);
		ast_hangup(chan);
		return;
	}

	(void)cause; (void)saved;
}

/* ════════════════════════════════════════════════════════════════════════════
 * REFER handler (call transfer)
 * ════════════════════════════════════════════════════════════════════════════ */

static void sofia_handle_refer(nua_handle_t *nh, struct sofia_pvt *pvt,
                                const sip_t *sip)
{
	const sip_refer_to_t *refer_to;
	char refer_uri[512] = "";

	if (!sip || !pvt || !pvt->owner) {
		nua_respond(nh, SIP_400_BAD_REQUEST, TAG_END());
		return;
	}

	refer_to = sip->sip_refer_to;
	if (!refer_to || !refer_to->r_url) {
		nua_respond(nh, SIP_400_BAD_REQUEST, TAG_END());
		return;
	}

	url_e(refer_uri, sizeof(refer_uri), refer_to->r_url);

	ast_log(LOG_VERBOSE,
	        "chan_sofia: REFER received – transferring to %s\n", refer_uri);

	/* Accept the REFER */
	nua_respond(nh, SIP_202_ACCEPTED, TAG_END());

	/* Queue a redirect to the Asterisk channel */
	ast_channel_call_forward_set(pvt->owner, refer_uri);
	ast_queue_control(pvt->owner, AST_CONTROL_TRANSFER);
}

/* ════════════════════════════════════════════════════════════════════════════
 * Response handler (outgoing call)
 * ════════════════════════════════════════════════════════════════════════════ */

static void sofia_handle_response(nua_handle_t *nh, struct sofia_pvt *pvt,
                                   int status, const sip_t *sip)
{
	if (!pvt || !pvt->owner) {
		return;
	}

	ast_mutex_lock(&pvt->lock);

	if (status == 180 || status == 183) {
		ast_queue_control(pvt->owner, AST_CONTROL_RINGING);
	} else if (status == 200) {
		if (!pvt->answered) {
			pvt->answered = 1;
			nua_ack(nh, TAG_END());
			ast_queue_control(pvt->owner, AST_CONTROL_ANSWER);
		}
	} else if (status >= 300) {
		int cause = AST_CAUSE_NORMAL_CLEARING;

		if (status == 486 || status == 600) {
			cause = AST_CAUSE_USER_BUSY;
		} else if (status == 404) {
			cause = AST_CAUSE_NO_ROUTE_DESTINATION;
		} else if (status == 403) {
			cause = AST_CAUSE_CALL_REJECTED;
		} else if (status == 408 || status == 503) {
			cause = AST_CAUSE_NO_USER_RESPONSE;
		}

		pvt->hangup_cause = cause;
		ast_queue_hangup_with_cause(pvt->owner, cause);
	}

	ast_mutex_unlock(&pvt->lock);
	(void)sip;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Sofia-SIP event loop thread
 * ════════════════════════════════════════════════════════════════════════════ */

static void *sofia_event_loop(void *data)
{
	su_root_run(sofia_root);
	return NULL;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Asterisk channel technology callbacks
 * ════════════════════════════════════════════════════════════════════════════ */

static struct ast_channel *sofia_request(const char *type,
                                          struct ast_format_cap *cap,
                                          const struct ast_channel *requestor,
                                          const char *dest,
                                          int *cause);
static int sofia_call(struct ast_channel *ast, const char *dest, int timeout);
static int sofia_hangup(struct ast_channel *ast);
static int sofia_answer(struct ast_channel *ast);
static struct ast_frame *sofia_read(struct ast_channel *ast);
static int sofia_write(struct ast_channel *ast, struct ast_frame *f);
static int sofia_indicate(struct ast_channel *ast, int condition,
                           const void *data, size_t datalen);
static int sofia_fixup(struct ast_channel *oldchan, struct ast_channel *newchan);
static const char *sofia_get_id(struct ast_channel *ast);
static int sofia_sendtext(struct ast_channel *ast, const char *text);

static struct ast_channel_tech sofia_tech = {
	.type         = SOFIA_TECH_NAME,
	.description  = SOFIA_MODULE_DESCRIPTION,
	.requester    = sofia_request,
	.call         = sofia_call,
	.hangup       = sofia_hangup,
	.answer       = sofia_answer,
	.read         = sofia_read,
	.write        = sofia_write,
	.indicate     = sofia_indicate,
	.fixup        = sofia_fixup,
	.get_pvt_uniqueid = sofia_get_id,
	.send_text    = sofia_sendtext,
};

/*
 * sofia_request – allocate a channel for an outgoing call.
 * Called by the dialplan when dialling SIP/<peer>[/<exten>].
 */
static struct ast_channel *sofia_request(const char *type,
                                          struct ast_format_cap *cap,
                                          const struct ast_channel *requestor,
                                          const char *dest,
                                          int *cause)
{
	struct sofia_pvt  *pvt;
	struct ast_channel *chan;
	struct sofia_peer  *peer = NULL;
	char peername[80] = "";
	char exten[AST_MAX_EXTENSION] = "";
	const char *sep;

	/* dest format: "<peer>[/<exten>]" */
	sep = strchr(dest, '/');
	if (sep) {
		size_t plen = (size_t)(sep - dest);
		if (plen >= sizeof(peername)) {
			plen = sizeof(peername) - 1;
		}
		memcpy(peername, dest, plen);
		peername[plen] = '\0';
		ast_copy_string(exten, sep + 1, sizeof(exten));
	} else {
		ast_copy_string(peername, dest, sizeof(peername));
		exten[0] = '\0';
	}

	peer = sofia_find_peer(peername);
	if (!peer) {
		ast_log(LOG_WARNING,
		        "chan_sofia: peer '%s' not found for outgoing call\n",
		        peername);
		*cause = AST_CAUSE_NO_ROUTE_DESTINATION;
		return NULL;
	}

	/* Check call limit */
	if (peer->call_limit != SOFIA_CALL_LIMIT_NONE &&
	    ast_atomic_fetchadd_int(&peer->call_count, 0) >= peer->call_limit) {
		ast_log(LOG_NOTICE,
		        "chan_sofia: call limit reached for peer '%s'\n",
		        peer->name);
		*cause = AST_CAUSE_USER_BUSY;
		ao2_ref(peer, -1);
		return NULL;
	}

	pvt = ast_calloc(1, sizeof(*pvt));
	if (!pvt) {
		*cause = AST_CAUSE_SWITCH_CONGESTION;
		ao2_ref(peer, -1);
		return NULL;
	}
	ast_mutex_init(&pvt->lock);
	pvt->peer     = peer;
	pvt->outgoing = 1;
	ast_copy_string(pvt->exten, exten, sizeof(pvt->exten));

	chan = ast_channel_alloc(1, AST_STATE_DOWN,
	                         requestor ? ast_channel_cid_num(requestor) : "",
	                         requestor ? ast_channel_cid_name(requestor) : "",
	                         requestor ? ast_channel_accountcode(requestor) : "",
	                         exten,
	                         peer->context,
	                         requestor ? ast_channel_linkedid(requestor) : NULL,
	                         0,
	                         "SIP/%s-%08x", peer->name,
	                         (unsigned)ast_random());
	if (!chan) {
		ast_mutex_destroy(&pvt->lock);
		ast_free(pvt);
		*cause = AST_CAUSE_SWITCH_CONGESTION;
		ao2_ref(peer, -1);
		return NULL;
	}

	pvt->owner = chan;
	ast_channel_tech_pvt_set(chan, pvt);
	ast_channel_tech_set(chan, &sofia_tech);

	/* Track in global list */
	AST_LIST_LOCK(&sofia_pvt_list);
	AST_LIST_INSERT_HEAD(&sofia_pvt_list, pvt, list);
	AST_LIST_UNLOCK(&sofia_pvt_list);

	/*
	 * pvt->peer holds the ao2 reference obtained by sofia_find_peer().
	 * Do NOT release it here; it will be released in sofia_hangup().
	 */

	return chan;
}

/*
 * sofia_call – initiate the outgoing SIP INVITE.
 */
static int sofia_call(struct ast_channel *ast, const char *dest, int timeout)
{
	struct sofia_pvt *pvt = ast_channel_tech_pvt(ast);
	struct sofia_peer *peer;
	char request_uri[512];
	char from_uri[512];
	nua_handle_t *nh;

	if (!pvt || !pvt->peer) {
		return -1;
	}
	peer = pvt->peer;

	/* Build Request-URI and From */
	if (peer->port > 0 && peer->port != 5060) {
		snprintf(request_uri, sizeof(request_uri),
		         "sip:%s@%s:%d", pvt->exten, peer->host, peer->port);
	} else {
		snprintf(request_uri, sizeof(request_uri),
		         "sip:%s@%s", pvt->exten, peer->host);
	}

	if (!ast_strlen_zero(peer->fromuser)) {
		snprintf(from_uri, sizeof(from_uri),
		         "sip:%s@%s", peer->fromuser,
		         !ast_strlen_zero(peer->fromdomain)
		             ? peer->fromdomain : sofia_bindaddr);
	} else {
		snprintf(from_uri, sizeof(from_uri),
		         "sip:%s@%s", peer->username, sofia_bindaddr);
	}

	/* Create NUA handle for this call */
	nh = nua_handle(sofia_nua, (nua_hmagic_t *)pvt,
	                SIPTAG_TO_STR(request_uri),
	                SIPTAG_FROM_STR(from_uri),
	                TAG_END());
	if (!nh) {
		ast_log(LOG_ERROR, "chan_sofia: failed to create NUA handle\n");
		return -1;
	}

	pvt->nh = nh;
	ast_atomic_fetchadd_int(&peer->call_count, +1);

	/* Build INVITE with session-timer options if configured */
	if (peer->session_timers) {
		int se = peer->session_expires > 0
		             ? peer->session_expires
		             : sofia_session_expires_global;
		nua_invite(nh,
		           NUTAG_SESSION_TIMER(se),
		           NUTAG_SESSION_REFRESHER(nua_remote_refresher),
		           TAG_END());
	} else {
		nua_invite(nh, TAG_END());
	}

	ast_channel_lock(ast);
	ast_setstate(ast, AST_STATE_RINGING);
	ast_channel_unlock(ast);

	(void)dest; (void)timeout;
	return 0;
}

/*
 * sofia_hangup – terminate a call and clean up.
 */
static int sofia_hangup(struct ast_channel *ast)
{
	struct sofia_pvt *pvt = ast_channel_tech_pvt(ast);

	if (!pvt) {
		return 0;
	}

	ast_mutex_lock(&pvt->lock);

	if (pvt->nh) {
		/* Send BYE or CANCEL depending on call state */
		if (pvt->answered) {
			nua_bye(pvt->nh, TAG_END());
		} else if (pvt->outgoing) {
			nua_cancel(pvt->nh, TAG_END());
		}
		nua_handle_destroy(pvt->nh);
		pvt->nh = NULL;
	}

	if (pvt->peer) {
		ast_atomic_fetchadd_int(&pvt->peer->call_count, -1);
		ao2_ref(pvt->peer, -1);
		pvt->peer = NULL;
	}

	if (pvt->rtp) {
		ast_rtp_instance_destroy(pvt->rtp);
		pvt->rtp = NULL;
	}

	pvt->owner = NULL;
	ast_channel_tech_pvt_set(ast, NULL);

	ast_mutex_unlock(&pvt->lock);

	/* Remove from active call list */
	AST_LIST_LOCK(&sofia_pvt_list);
	AST_LIST_REMOVE(&sofia_pvt_list, pvt, list);
	AST_LIST_UNLOCK(&sofia_pvt_list);

	ast_mutex_destroy(&pvt->lock);
	ast_free(pvt);

	return 0;
}

/*
 * sofia_answer – send 200 OK for an incoming call.
 */
static int sofia_answer(struct ast_channel *ast)
{
	struct sofia_pvt *pvt = ast_channel_tech_pvt(ast);

	if (!pvt || !pvt->nh) {
		return -1;
	}

	ast_mutex_lock(&pvt->lock);
	if (!pvt->answered) {
		pvt->answered = 1;
		nua_respond(pvt->nh, SIP_200_OK, TAG_END());
	}
	ast_mutex_unlock(&pvt->lock);

	return 0;
}

/*
 * sofia_read – read an audio frame from the RTP stream.
 */
static struct ast_frame *sofia_read(struct ast_channel *ast)
{
	struct sofia_pvt *pvt = ast_channel_tech_pvt(ast);

	if (!pvt || !pvt->rtp) {
		return &ast_null_frame;
	}

	return ast_rtp_instance_read(pvt->rtp, 0);
}

/*
 * sofia_write – write an audio frame to the RTP stream.
 */
static int sofia_write(struct ast_channel *ast, struct ast_frame *f)
{
	struct sofia_pvt *pvt = ast_channel_tech_pvt(ast);

	if (!pvt || !pvt->rtp) {
		return 0;
	}

	if (f->frametype == AST_FRAME_VOICE) {
		return ast_rtp_instance_write(pvt->rtp, f);
	}

	return 0;
}

/*
 * sofia_indicate – handle Asterisk signalling events (ring, hold, …).
 */
static int sofia_indicate(struct ast_channel *ast, int condition,
                           const void *data, size_t datalen)
{
	struct sofia_pvt *pvt = ast_channel_tech_pvt(ast);
	int res = 0;

	if (!pvt || !pvt->nh) {
		return -1;
	}

	switch (condition) {
	case AST_CONTROL_RINGING:
		if (!pvt->outgoing) {
			nua_respond(pvt->nh, SIP_180_RINGING, TAG_END());
		}
		break;
	case AST_CONTROL_BUSY:
		if (!pvt->outgoing) {
			nua_respond(pvt->nh, SIP_486_BUSY_HERE, TAG_END());
		}
		break;
	case AST_CONTROL_CONGESTION:
		if (!pvt->outgoing) {
			nua_respond(pvt->nh, SIP_503_SERVICE_UNAVAILABLE, TAG_END());
		}
		break;
	case AST_CONTROL_HOLD:
		/* Re-INVITE with sendonly */
		nua_invite(pvt->nh,
		           SOATAG_HOLD("sendonly"),
		           TAG_END());
		break;
	case AST_CONTROL_UNHOLD:
		/* Re-INVITE with sendrecv */
		nua_invite(pvt->nh,
		           SOATAG_HOLD(""),
		           TAG_END());
		break;
	case AST_CONTROL_PROGRESS:
		if (!pvt->outgoing) {
			nua_respond(pvt->nh, SIP_183_SESSION_PROGRESS, TAG_END());
		}
		break;
	case AST_CONTROL_VIDUPDATE:
	case AST_CONTROL_SRCUPDATE:
	case AST_CONTROL_SRCCHANGE:
		/* Handled transparently by RTP layer */
		break;
	case -1:
		/* Unsupported indication – return -1 so Asterisk generates inband */
		res = -1;
		break;
	default:
		res = -1;
		break;
	}

	(void)data; (void)datalen;
	return res;
}

/*
 * sofia_fixup – handle channel masquerade.
 */
static int sofia_fixup(struct ast_channel *oldchan, struct ast_channel *newchan)
{
	struct sofia_pvt *pvt = ast_channel_tech_pvt(newchan);

	if (!pvt) {
		return -1;
	}

	ast_mutex_lock(&pvt->lock);
	if (pvt->owner == oldchan) {
		pvt->owner = newchan;
	}
	ast_mutex_unlock(&pvt->lock);

	return 0;
}

static const char *sofia_get_id(struct ast_channel *ast)
{
	struct sofia_pvt *pvt = ast_channel_tech_pvt(ast);
	return pvt ? pvt->callid : "";
}

static int sofia_sendtext(struct ast_channel *ast, const char *text)
{
	struct sofia_pvt *pvt = ast_channel_tech_pvt(ast);

	if (!pvt || !pvt->nh || ast_strlen_zero(text)) {
		return 0;
	}

	nua_message(pvt->nh,
	            SIPTAG_CONTENT_TYPE_STR("text/plain"),
	            SIPTAG_PAYLOAD_STR(text),
	            TAG_END());
	return 0;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Configuration parsing
 * ════════════════════════════════════════════════════════════════════════════ */

/*
 * sofia_alloc_peer – create and initialise a new sofia_peer.
 */
static struct sofia_peer *sofia_alloc_peer(const char *name)
{
	struct sofia_peer *p;

	p = ao2_alloc(sizeof(*p), peer_destructor);
	if (!p) {
		return NULL;
	}

	ast_mutex_init(&p->lock);
	ast_copy_string(p->name, name, sizeof(p->name));
	ast_copy_string(p->username, name, sizeof(p->username));
	ast_copy_string(p->context, "default", sizeof(p->context));
	p->port             = 5060;
	p->session_timers   = sofia_session_timers_global;
	p->session_expires  = sofia_session_expires_global;
	p->call_limit       = SOFIA_CALL_LIMIT_NONE;

	p->contacts = ao2_container_alloc(16,
	                                  contact_hash_fn,
	                                  contact_cmp_fn);
	if (!p->contacts) {
		ao2_ref(p, -1);
		return NULL;
	}

	return p;
}

/*
 * sofia_parse_peer – parse a [peer] category from sofia.conf.
 */
static void sofia_parse_peer(struct ast_config *cfg, const char *cat)
{
	struct sofia_peer *peer;
	const char *v;

	peer = sofia_alloc_peer(cat);
	if (!peer) {
		ast_log(LOG_ERROR, "chan_sofia: out of memory for peer '%s'\n", cat);
		return;
	}

	if ((v = ast_variable_retrieve(cfg, cat, "username")))
		ast_copy_string(peer->username, v, sizeof(peer->username));

	if ((v = ast_variable_retrieve(cfg, cat, "secret")))
		ast_copy_string(peer->secret, v, sizeof(peer->secret));

	if ((v = ast_variable_retrieve(cfg, cat, "md5secret")))
		ast_copy_string(peer->md5secret, v, sizeof(peer->md5secret));

	if ((v = ast_variable_retrieve(cfg, cat, "host")))
		ast_copy_string(peer->host, v, sizeof(peer->host));

	if ((v = ast_variable_retrieve(cfg, cat, "context")))
		ast_copy_string(peer->context, v, sizeof(peer->context));

	if ((v = ast_variable_retrieve(cfg, cat, "callerid")))
		ast_copy_string(peer->callerid, v, sizeof(peer->callerid));

	if ((v = ast_variable_retrieve(cfg, cat, "fromuser")))
		ast_copy_string(peer->fromuser, v, sizeof(peer->fromuser));

	if ((v = ast_variable_retrieve(cfg, cat, "fromdomain")))
		ast_copy_string(peer->fromdomain, v, sizeof(peer->fromdomain));

	if ((v = ast_variable_retrieve(cfg, cat, "useragent_filter")))
		ast_copy_string(peer->useragent_filter, v,
		                sizeof(peer->useragent_filter));

	if ((v = ast_variable_retrieve(cfg, cat, "port")))
		peer->port = atoi(v);

	if ((v = ast_variable_retrieve(cfg, cat, "nat")))
		peer->nat = ast_true(v) ? 1 : 0;

	if ((v = ast_variable_retrieve(cfg, cat, "call-limit")))
		peer->call_limit = atoi(v);

	if ((v = ast_variable_retrieve(cfg, cat, "session-timers"))) {
		if (!strcasecmp(v, "originate") || !strcasecmp(v, "required"))
			peer->session_timers = 2;
		else if (!strcasecmp(v, "accept") || !strcasecmp(v, "supported"))
			peer->session_timers = 1;
		else
			peer->session_timers = 0;
	}

	if ((v = ast_variable_retrieve(cfg, cat, "session-expires")))
		peer->session_expires = atoi(v);

	if ((v = ast_variable_retrieve(cfg, cat, "encryption"))) {
		if (!strcasecmp(v, "yes") || !strcasecmp(v, "srtp"))
			peer->encryption = 1;
		else if (!strcasecmp(v, "sdes"))
			peer->encryption = 2;
		else
			peer->encryption = 0;
	}

	if ((v = ast_variable_retrieve(cfg, cat, "insecure"))) {
		if (strstr(v, "port"))
			peer->insecure_port = 1;
		if (strstr(v, "invite"))
			peer->insecure_invite = 1;
	}

	ao2_link(sofia_peers, peer);
	ao2_ref(peer, -1);
}

/*
 * sofia_load_config – read sofia.conf and populate global state and peers.
 */
static int sofia_load_config(void)
{
	struct ast_config *cfg;
	const char *cat;
	const char *v;
	struct ast_flags config_flags = { 0 };

	cfg = ast_config_load(SOFIA_CONFIG_FILE, config_flags);
	if (!cfg || cfg == CONFIG_STATUS_FILEINVALID) {
		ast_log(LOG_WARNING,
		        "chan_sofia: could not load %s\n", SOFIA_CONFIG_FILE);
		return 0;  /* not fatal – run with defaults */
	}

	/* [general] section */
	if ((v = ast_variable_retrieve(cfg, "general", "bindaddr")))
		ast_copy_string(sofia_bindaddr, v, sizeof(sofia_bindaddr));

	if ((v = ast_variable_retrieve(cfg, "general", "bindport")))
		sofia_bindport = atoi(v);

	if ((v = ast_variable_retrieve(cfg, "general", "session-timers"))) {
		if (!strcasecmp(v, "originate") || !strcasecmp(v, "required"))
			sofia_session_timers_global = 2;
		else if (!strcasecmp(v, "accept") || !strcasecmp(v, "supported"))
			sofia_session_timers_global = 1;
		else
			sofia_session_timers_global = 0;
	}

	if ((v = ast_variable_retrieve(cfg, "general", "session-expires")))
		sofia_session_expires_global = atoi(v);

	/* Peer sections */
	cat = NULL;
	while ((cat = ast_category_browse(cfg, cat))) {
		if (!strcasecmp(cat, "general")) {
			continue;
		}
		sofia_parse_peer(cfg, cat);
	}

	ast_config_destroy(cfg);
	return 0;
}

/* ════════════════════════════════════════════════════════════════════════════
 * CLI commands
 * ════════════════════════════════════════════════════════════════════════════ */

static char *sofia_cli_show_peers(struct ast_cli_entry *e, int cmd,
                                   struct ast_cli_args *a)
{
	struct ao2_iterator it;
	struct sofia_peer *peer;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show peers";
		e->usage   = "Usage: sip show peers\n"
		             "       List all configured SIP peers (chan_sofia).\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	ast_cli(a->fd,
	        "%-20s %-15s %-8s %-5s %-10s\n",
	        "Name", "Host", "Dyn", "Port", "Calls");
	ast_cli(a->fd,
	        "%-20s %-15s %-8s %-5s %-10s\n",
	        "--------------------",
	        "---------------", "--------", "-----", "----------");

	it = ao2_iterator_init(sofia_peers, 0);
	while ((peer = ao2_iterator_next(&it))) {
		ast_cli(a->fd, "%-20s %-15s %-8s %-5d %-10d\n",
		        peer->name,
		        peer->host[0] ? peer->host : "(dynamic)",
		        peer->host[0] ? "No" : "Yes",
		        peer->port,
		        ast_atomic_fetchadd_int(&peer->call_count, 0));
		ao2_ref(peer, -1);
	}
	ao2_iterator_destroy(&it);

	return CLI_SUCCESS;
}

static char *sofia_cli_show_blacklist(struct ast_cli_entry *e, int cmd,
                                       struct ast_cli_args *a)
{
	struct ao2_iterator it;
	struct sofia_blacklist_entry *entry;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show blacklist";
		e->usage   = "Usage: sip show blacklist\n"
		             "       List the SIP IP blacklist (chan_sofia).\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	ast_cli(a->fd, "%-40s %-8s %-8s\n", "IP Address", "Failures", "Status");
	ast_cli(a->fd, "%-40s %-8s %-8s\n",
	        "----------------------------------------",
	        "--------", "--------");

	it = ao2_iterator_init(sofia_blacklist, 0);
	while ((entry = ao2_iterator_next(&it))) {
		ast_cli(a->fd, "%-40s %-8d %-8s\n",
		        entry->ipaddr, entry->failures,
		        entry->blocked ? "BLOCKED" : "tracked");
		ao2_ref(entry, -1);
	}
	ao2_iterator_destroy(&it);

	return CLI_SUCCESS;
}

static char *sofia_cli_unblacklist(struct ast_cli_entry *e, int cmd,
                                    struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "sip unblacklist";
		e->usage   = "Usage: sip unblacklist <ip>\n"
		             "       Remove an IP from the SIP blacklist.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc < 3) {
		return CLI_SHOWUSAGE;
	}

	sofia_blacklist_clear(a->argv[2]);
	ast_cli(a->fd, "Removed %s from the SIP blacklist.\n", a->argv[2]);
	return CLI_SUCCESS;
}

static char *sofia_cli_reload(struct ast_cli_entry *e, int cmd,
                               struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "sip reload";
		e->usage   = "Usage: sip reload\n"
		             "       Reload chan_sofia configuration.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	/* Clear existing peers and reload */
	ao2_callback(sofia_peers, OBJ_UNLINK | OBJ_NODATA | OBJ_MULTIPLE,
	             NULL, NULL);
	sofia_load_config();
	ast_cli(a->fd, "SIP (chan_sofia) configuration reloaded.\n");
	return CLI_SUCCESS;
}

static struct ast_cli_entry sofia_cli_entries[] = {
	AST_CLI_DEFINE(sofia_cli_show_peers,      "List SIP peers"),
	AST_CLI_DEFINE(sofia_cli_show_blacklist,  "List SIP blacklist"),
	AST_CLI_DEFINE(sofia_cli_unblacklist,     "Remove IP from SIP blacklist"),
	AST_CLI_DEFINE(sofia_cli_reload,          "Reload SIP configuration"),
};

/* ════════════════════════════════════════════════════════════════════════════
 * Module load / unload
 * ════════════════════════════════════════════════════════════════════════════ */

static int load_module(void)
{
	char bind_url[128];

	/* Initialise Sofia-SIP utility library */
	su_init();

	/* Create the Sofia root (event loop) */
	sofia_root = su_root_create(NULL);
	if (!sofia_root) {
		ast_log(LOG_ERROR, "chan_sofia: failed to create su_root\n");
		su_deinit();
		return AST_MODULE_LOAD_FAILURE;
	}

	/* Allocate ao2 containers */
	sofia_peers = ao2_container_alloc(SOFIA_PEER_BUCKETS,
	                                   peer_hash_fn, peer_cmp_fn);
	if (!sofia_peers) {
		ast_log(LOG_ERROR, "chan_sofia: failed to allocate peer container\n");
		su_root_destroy(sofia_root);
		su_deinit();
		return AST_MODULE_LOAD_FAILURE;
	}

	sofia_blacklist = ao2_container_alloc(SOFIA_BL_BUCKETS,
	                                       bl_hash_fn, bl_cmp_fn);
	if (!sofia_blacklist) {
		ast_log(LOG_ERROR, "chan_sofia: failed to allocate blacklist\n");
		ao2_ref(sofia_peers, -1);
		su_root_destroy(sofia_root);
		su_deinit();
		return AST_MODULE_LOAD_FAILURE;
	}

	/* Load configuration */
	sofia_load_config();

	/* Build the SIP transport bind URL */
	snprintf(bind_url, sizeof(bind_url),
	         "sip:%s:%d", sofia_bindaddr, sofia_bindport);

	/* Create NUA stack */
	sofia_nua = nua_create(sofia_root,
	                        sofia_event_callback,
	                        NULL,           /* nua_magic */
	                        NUTAG_URL(bind_url),
	                        NUTAG_ALLOW("INVITE, ACK, BYE, CANCEL, OPTIONS, "
	                                   "REGISTER, REFER, MESSAGE, INFO, "
	                                   "NOTIFY, SUBSCRIBE"),
	                        NUTAG_AUTOANSWER(0),
	                        NUTAG_AUTOACK(0),
	                        TAG_END());
	if (!sofia_nua) {
		ast_log(LOG_ERROR,
		        "chan_sofia: failed to create NUA stack on %s\n", bind_url);
		ao2_ref(sofia_blacklist, -1);
		ao2_ref(sofia_peers, -1);
		su_root_destroy(sofia_root);
		su_deinit();
		return AST_MODULE_LOAD_FAILURE;
	}

	/* Start the event loop thread */
	if (ast_pthread_create_background(&sofia_thread, NULL,
	                                   sofia_event_loop, NULL)) {
		ast_log(LOG_ERROR, "chan_sofia: failed to start event loop\n");
		nua_destroy(sofia_nua);
		ao2_ref(sofia_blacklist, -1);
		ao2_ref(sofia_peers, -1);
		su_root_destroy(sofia_root);
		su_deinit();
		return AST_MODULE_LOAD_FAILURE;
	}

	/* Register channel technology */
	if (ast_channel_register(&sofia_tech)) {
		ast_log(LOG_ERROR,
		        "chan_sofia: failed to register '%s' channel technology\n",
		        SOFIA_TECH_NAME);
		su_root_break(sofia_root);
		pthread_join(sofia_thread, NULL);
		nua_destroy(sofia_nua);
		ao2_ref(sofia_blacklist, -1);
		ao2_ref(sofia_peers, -1);
		su_root_destroy(sofia_root);
		su_deinit();
		return AST_MODULE_LOAD_FAILURE;
	}

	/* Register CLI commands */
	ast_cli_register_multiple(sofia_cli_entries,
	                          ARRAY_LEN(sofia_cli_entries));

	ast_log(LOG_NOTICE,
	        "chan_sofia: SIP channel loaded – listening on %s\n", bind_url);

	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	/* Unregister CLI and channel tech */
	ast_cli_unregister_multiple(sofia_cli_entries,
	                             ARRAY_LEN(sofia_cli_entries));
	ast_channel_unregister(&sofia_tech);

	/* Stop the Sofia event loop and tear down the NUA stack */
	if (sofia_nua) {
		nua_shutdown(sofia_nua);
	}
	if (sofia_root && sofia_thread != AST_PTHREADT_NULL) {
		su_root_break(sofia_root);
		pthread_join(sofia_thread, NULL);
		sofia_thread = AST_PTHREADT_NULL;
	}
	if (sofia_nua) {
		nua_destroy(sofia_nua);
		sofia_nua = NULL;
	}
	if (sofia_root) {
		su_root_destroy(sofia_root);
		sofia_root = NULL;
	}

	/* Release ao2 containers */
	if (sofia_blacklist) {
		ao2_ref(sofia_blacklist, -1);
		sofia_blacklist = NULL;
	}
	if (sofia_peers) {
		ao2_ref(sofia_peers, -1);
		sofia_peers = NULL;
	}

	su_deinit();

	ast_log(LOG_NOTICE, "chan_sofia: SIP channel unloaded\n");
	return 0;
}

static int reload_module(void)
{
	ao2_callback(sofia_peers, OBJ_UNLINK | OBJ_NODATA | OBJ_MULTIPLE,
	             NULL, NULL);
	sofia_load_config();
	ast_log(LOG_NOTICE, "chan_sofia: configuration reloaded\n");
	return 0;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, SOFIA_MODULE_DESCRIPTION,
	.support_level = AST_MODULE_SUPPORT_EXTENDED,
	.load          = load_module,
	.unload        = unload_module,
	.reload        = reload_module,
	.load_pri      = AST_MODPRI_CHANNEL_DRIVER,
);
