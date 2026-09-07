/*
 * GabPBX -- An open source telephony toolkit.
 *
 * chan_sofia native push sender -- in-process APNs/FCM wake-up transport.
 *
 * WHY THIS FILE EXISTS (operator order 2026-09-07): the script sender lane
 * (sofia_push.c, fork+execv of the .py senders) costs ~1341 ms per push in
 * production -- Python interpreter start-up plus a brand-new TLS handshake to
 * Apple on EVERY send -- and serializes devices (one child at a time, 8 s
 * worst case each). Apple's own guidance is to keep ONE persistent HTTP/2
 * connection and multiplex. This lane does exactly that:
 *
 *   ONE bounded queue + ONE event-driven thread. Producers (the existing
 *   sofia_push.c dispatch, any thread) snapshot the job BY VALUE, append under
 *   the list lock and poke curl_multi_wakeup() -- the only libcurl call that is
 *   documented safe from another thread against a multi handle in use. The
 *   thread runs curl_multi_poll()/curl_multi_perform() with several transfers
 *   in flight at once over persistent connections (CURLPIPE_MULTIPLEX): while
 *   one push waits for Apple, the next is already on the wire. Measured from
 *   .193: full-handshake request 557 ms, warm-connection request 117 ms.
 *
 * THE CONTRACT IS THE SCRIPTS'. Payloads are byte-identical to the deployed
 * send_push_voip.py / send_push.py (json.dumps spacing included) and the
 * result strings are byte-identical too (OK:prod / OK:sandbox / OK / ERR:%d /
 * ERR:prod:%d %s / ERR:sandbox:%d %s), because sofia_push.c's dead-token
 * matcher does prefix/equality matching on them and last_result/push_log
 * display them. Completion is handed back to sofia_push_sender_complete()
 * (implemented in sofia_push.c beside its static consumers) so the record
 * path -- verb line, push_log 'sent', last_result, dead-token purge -- is the
 * same code for both lanes.
 *
 * CREDENTIALS: single source of truth stays the deployed scripts + certs dir.
 * The APNs constants (TEAM_ID / KEY_ID / KEY_FILE / BUNDLE_ID) are parsed out
 * of send_push_voip.py itself, and the FCM service-account path out of
 * send_push.py, at first use in-thread -- zero new config to deploy, zero
 * drift; if either parse fails, that push type reports unhealthy and the
 * dispatcher falls back to the script sender (self-healing retry every 60 s).
 * The APNs ES256 JWT is cached ~50 min (Apple: valid 1 h, never re-sign more
 * often than every 20 min) and the Google OAuth token ~55 min; both caches are
 * touched ONLY by the sender thread, so they need no locks.
 *
 * THREADING DOCTRINE (memory/feedback_chan_sofia_concurrency_doctrine.md):
 * jobs are by-value snapshots (fixed char arrays, zero pointers into pvt/peer);
 * this thread never touches pvt/peer/channel state -- its only re-entry into
 * chan_sofia is sofia_push_sender_complete(), which takes the same leaf locks
 * the script lane's taskprocessor thread already takes. Module refuses runtime
 * unload (chan_sofia.c:21021), so the thread is created once at load and never
 * drained; sofia_push_sender_stop() exists ONLY for the load-failure
 * err_cleanup ladder.
 *
 * curl_global_init() is OWNED by res_curl.so (res/res_curl.c) -- we assert the
 * module is loaded (func_curl.c precedent) and never call it ourselves.
 */

#include "gabpbx.h"
#include "gabpbx/lock.h"
#include "gabpbx/utils.h"
#include "gabpbx/strings.h"
#include "gabpbx/logger.h"
#include "gabpbx/linkedlists.h"
#include "gabpbx/module.h"		/* ast_module_check / ast_load_resource (res_curl ownership) */

#include <sofia-sip/sip.h>		/* chan_sofia_internal.h needs the sofia types */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "include/chan_sofia_internal.h"

#if defined(HAVE_CURL) && defined(HAVE_CRYPTO)
#include <curl/curl.h>
#if defined(CURL_AT_LEAST_VERSION) && CURL_AT_LEAST_VERSION(7, 68, 0)
#define SOFIA_PUSH_NATIVE_BUILD 1	/* curl_multi_poll + curl_multi_wakeup floor */
#endif
#endif

#ifdef SOFIA_PUSH_NATIVE_BUILD

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>

/* ---------- limits (script-lane parity where it matters) ---------- */

#define NATQ_MAX 64			/* own bounded queue: queued + in-flight (NOT the shared sofia_pushdb_depth) */
#define NAT_JOB_BUDGET_MS 8000		/* whole-job wall clock, = SOFIA_PUSH_EXEC_TIMEOUT_MS parity (covers prod->sandbox) */
#define NAT_CONNECT_TIMEOUT_MS 3000
#define NAT_XFER_TIMEOUT_MS 5000
#define NAT_RESULT_MAX 256		/* = SOFIA_PUSH_RESULT_MAX: first line later truncated to last_result[121] */
#define NAT_RESP_MAX 512		/* HTTP response body capture (BadDeviceToken must land in the first 120 B of out) */
#define NAT_BODY_MAX 2048		/* request body (FCM template + \uXXXX-escaped names) */
#define NAT_JWT_MAX 1024		/* ES256 ~230 B, RS256 (2048-bit) ~740 B */
#define NAT_HEALTH_RETRY_S 60		/* creds-class failure: report unhealthy (script fallback) and retry after this */

/* ---------- job ---------- */

enum nat_stage {
	NAT_STAGE_APNS_PROD = 0,
	NAT_STAGE_APNS_SANDBOX,
	NAT_STAGE_OAUTH_WAIT,		/* parked until the shared OAuth transfer lands */
	NAT_STAGE_FCM_SEND,
};

struct nat_job {
	AST_LIST_ENTRY(nat_job) entry;
	/* by-value snapshot from the producer (concurrency doctrine: zero shared pointers) */
	enum sofia_push_purpose purpose;
	int is_voip;
	char token[512];
	char cid_num[80];
	char cid_name[80];
	char callid[64];
	char peername[128];
	char device_id[64];
	/* runtime (sender thread only) */
	enum nat_stage stage;
	struct timeval t0;
	CURL *easy;
	struct curl_slist *hdrs;
	char url[640];
	char body[NAT_BODY_MAX];
	char auth_hdr[NAT_JWT_MAX + 32];
	char resp[NAT_RESP_MAX];
	size_t resp_len;
};

/* ---------- lane state ---------- */

static AST_LIST_HEAD_STATIC(nat_inq, nat_job);	/* producer -> thread; its .lock also guards nat_up/nat_stop */
static AST_LIST_HEAD_NOLOCK_STATIC(nat_oauth_waiters, nat_job);	/* thread-private, no lock needed */

static int nat_depth;			/* atomic queued+in-flight budget (house idiom, sofia_push.c:258-288) */
static pthread_t nat_tid = AST_PTHREADT_NULL;
static CURLM *nat_multi;
static volatile int nat_up;		/* lane usable (thread running, curl ready) */
static volatile int nat_stop;		/* load-failure unwind only */

/* per-type health: 0 = ok/unknown, else epoch until which the type is reported
 * unhealthy (dispatcher falls back to the script sender; self-heals). Written by
 * the sender thread, read by producers -- monotonic time_t, benign race. */
static volatile time_t nat_apns_sick_until;
static volatile time_t nat_fcm_sick_until;

/* ---------- APNs credentials (thread-owned; parsed out of send_push_voip.py) ---------- */

static struct {
	int state;			/* 0 = not loaded, 1 = ok, -1 = failed (retry_at) */
	time_t retry_at;
	char team[24];
	char kid[24];
	char keyfile[256];
	char topic[160];		/* BUNDLE_ID + ".voip" */
	EVP_PKEY *pkey;
	char jwt[NAT_JWT_MAX];
	time_t jwt_at;			/* re-sign after ~50 min; Apple rejects >1 h and throttles <20 min re-signs */
} apns;

/* ---------- FCM credentials (thread-owned; SA path parsed out of send_push.py) ---------- */

static struct {
	int state;
	time_t retry_at;
	char sa_path[256];
	char client_email[256];
	char token_uri[256];
	char project[80];
	EVP_PKEY *pkey;
	/* OAuth access token cache + single-flight transfer state */
	int oauth_state;		/* 0 idle, 1 in flight, 2 valid */
	char access_token[1200];
	time_t oauth_expiry;
	CURL *oauth_easy;
	struct curl_slist *oauth_hdrs;
	char oauth_body[NAT_JWT_MAX + 128];
	char oauth_resp[2048];
	size_t oauth_resp_len;
	struct timeval oauth_t0;
} fcm;

static int nat_oauth_marker;		/* CURLOPT_PRIVATE sentinel for the OAuth transfer */

/* ---------- small helpers ---------- */

/* base64url without padding (JWS): house encoder + RFC 7515 alphabet swap. */
static int nat_b64url(char *dst, size_t dstlen, const unsigned char *src, int srclen)
{
	int n = ast_base64encode_full(dst, src, srclen, (int) dstlen - 1, 0);
	int i, w = 0;

	if (n <= 0) {
		return -1;
	}
	for (i = 0; i < n; i++) {
		char c = dst[i];
		if (c == '+') {
			c = '-';
		} else if (c == '/') {
			c = '_';
		} else if (c == '=') {
			break;
		}
		dst[w++] = c;
	}
	dst[w] = '\0';
	return w;
}

/* JSON string escape, python json.dumps parity INCLUDING ensure_ascii: every
 * non-ASCII codepoint becomes \uXXXX (surrogate pairs above the BMP), control
 * chars become the two-char escapes or \u00XX -- so the native payload is
 * byte-identical to the script's, not merely equivalent. */
static void nat_json_escape(char *dst, size_t dstlen, const char *src)
{
	size_t w = 0;
	const unsigned char *p = (const unsigned char *) src;

	if (!dstlen) {
		return;
	}
	while (*p && w + 13 < dstlen) {	/* worst case one input char -> 12 output bytes (surrogate pair) */
		unsigned char c = *p;
		unsigned int cp = 0;
		int cont = 0;

		if (c == '"' || c == '\\') {
			dst[w++] = '\\';
			dst[w++] = (char) c;
			p++;
			continue;
		}
		if (c >= 0x20 && c < 0x80) {
			dst[w++] = (char) c;
			p++;
			continue;
		}
		if (c < 0x20) {
			switch (c) {
			case '\b': dst[w++] = '\\'; dst[w++] = 'b'; break;
			case '\f': dst[w++] = '\\'; dst[w++] = 'f'; break;
			case '\n': dst[w++] = '\\'; dst[w++] = 'n'; break;
			case '\r': dst[w++] = '\\'; dst[w++] = 'r'; break;
			case '\t': dst[w++] = '\\'; dst[w++] = 't'; break;
			default:
				w += snprintf(dst + w, dstlen - w, "\\u%04x", c);
			}
			p++;
			continue;
		}
		/* UTF-8 decode (2-4 bytes); malformed input emits U+FFFD and resyncs */
		if ((c & 0xe0) == 0xc0) {
			cp = c & 0x1f; cont = 1;
		} else if ((c & 0xf0) == 0xe0) {
			cp = c & 0x0f; cont = 2;
		} else if ((c & 0xf8) == 0xf0) {
			cp = c & 0x07; cont = 3;
		} else {
			cp = 0xfffd; cont = 0;
		}
		p++;
		while (cont > 0 && (*p & 0xc0) == 0x80) {
			cp = (cp << 6) | (*p & 0x3f);
			p++;
			cont--;
		}
		if (cont > 0) {
			cp = 0xfffd;	/* truncated sequence */
		}
		if (cp > 0xffff) {
			unsigned int v = cp - 0x10000;
			w += snprintf(dst + w, dstlen - w, "\\u%04x\\u%04x",
				0xd800 + (v >> 10), 0xdc00 + (v & 0x3ff));
		} else {
			w += snprintf(dst + w, dstlen - w, "\\u%04x", cp);
		}
	}
	dst[w] = '\0';
}

/* Bounded file slurp (config/scripts/SA json are all tiny). Returns malloc'd buf or NULL. */
static char *nat_slurp(const char *path, size_t max)
{
	FILE *f = fopen(path, "r");
	char *buf;
	size_t got;

	if (!f) {
		return NULL;
	}
	if (!(buf = ast_malloc(max + 1))) {
		fclose(f);
		return NULL;
	}
	got = fread(buf, 1, max, f);
	fclose(f);
	buf[got] = '\0';
	return buf;
}

/* Extract a python constant of the form  NAME = "value"  (whitespace-tolerant). */
static int nat_py_const(const char *buf, const char *name, char *out, size_t outlen)
{
	const char *p = buf;
	size_t nlen = strlen(name);

	while ((p = strstr(p, name))) {
		const char *q = p + nlen;
		p += nlen;
		while (*q == ' ' || *q == '\t') q++;
		if (*q != '=') continue;
		q++;
		while (*q == ' ' || *q == '\t') q++;
		if (*q != '"') continue;
		q++;
		{
			size_t w = 0;
			while (*q && *q != '"' && w + 1 < outlen) {
				out[w++] = *q++;
			}
			out[w] = '\0';
			return *q == '"' && w > 0 ? 0 : -1;
		}
	}
	return -1;
}

/* Extract a JSON string field ("name": "value"), unescaping \n \\ \" \/ (the
 * service-account private_key is \n-escaped PEM). Hand-rolled: this tree
 * pre-dates any bundled JSON library. */
static int nat_json_str(const char *buf, const char *name, char *out, size_t outlen)
{
	char pat[64];
	const char *p;

	snprintf(pat, sizeof(pat), "\"%s\"", name);
	if (!(p = strstr(buf, pat))) {
		return -1;
	}
	p += strlen(pat);
	while (*p == ' ' || *p == '\t' || *p == ':') p++;
	if (*p != '"') {
		return -1;
	}
	p++;
	{
		size_t w = 0;
		while (*p && *p != '"' && w + 2 < outlen) {
			if (*p == '\\' && p[1]) {
				p++;
				switch (*p) {
				case 'n': out[w++] = '\n'; break;
				case '\\': out[w++] = '\\'; break;
				case '"': out[w++] = '"'; break;
				case '/': out[w++] = '/'; break;
				case 'r': out[w++] = '\r'; break;
				case 't': out[w++] = '\t'; break;
				default: out[w++] = *p; break;
				}
				p++;
			} else {
				out[w++] = *p++;
			}
		}
		out[w] = '\0';
		return *p == '"' && w > 0 ? 0 : -1;
	}
}

/* ---------- JWT signing (OpenSSL 3.x EVP_DigestSign; nothing in-tree to reuse) ---------- */

static EVP_PKEY *nat_load_pem_key(const char *pem, size_t pemlen)
{
	BIO *bio = BIO_new_mem_buf(pem, (int) pemlen);
	EVP_PKEY *k = NULL;

	if (bio) {
		k = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
		BIO_free(bio);
	}
	return k;
}

/* Sign b64url(header).b64url(claims); ES256 additionally converts the DER
 * ECDSA signature to the raw 64-byte R||S JWS requires. Returns jwt len or -1. */
static int nat_jwt_sign(EVP_PKEY *pkey, int es256, const char *hdr_json, const char *claims_json,
	char *out, size_t outlen)
{
	char input[1024];
	unsigned char sig[512];
	size_t siglen = sizeof(sig);
	char sig64[720];
	int hl, cl, n;
	EVP_MD_CTX *ctx;

	hl = nat_b64url(input, sizeof(input), (const unsigned char *) hdr_json, (int) strlen(hdr_json));
	if (hl < 0 || hl + 2 >= (int) sizeof(input)) {
		return -1;
	}
	input[hl] = '.';
	cl = nat_b64url(input + hl + 1, sizeof(input) - hl - 1,
		(const unsigned char *) claims_json, (int) strlen(claims_json));
	if (cl < 0) {
		return -1;
	}

	if (!(ctx = EVP_MD_CTX_new())) {
		return -1;
	}
	if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1
		|| EVP_DigestSign(ctx, sig, &siglen, (const unsigned char *) input, strlen(input)) != 1) {
		EVP_MD_CTX_free(ctx);
		return -1;
	}
	EVP_MD_CTX_free(ctx);

	if (es256) {
		/* DER SEQUENCE(r, s) -> raw r||s, 32+32 zero-padded (RFC 7518 §3.4) */
		const unsigned char *p = sig;
		ECDSA_SIG *es = d2i_ECDSA_SIG(NULL, &p, (long) siglen);
		unsigned char raw[64];
		const BIGNUM *r, *s;

		if (!es) {
			return -1;
		}
		ECDSA_SIG_get0(es, &r, &s);
		if (BN_bn2binpad(r, raw, 32) != 32 || BN_bn2binpad(s, raw + 32, 32) != 32) {
			ECDSA_SIG_free(es);
			return -1;
		}
		ECDSA_SIG_free(es);
		if (nat_b64url(sig64, sizeof(sig64), raw, 64) < 0) {
			return -1;
		}
	} else {
		if (nat_b64url(sig64, sizeof(sig64), sig, (int) siglen) < 0) {
			return -1;
		}
	}

	n = snprintf(out, outlen, "%s.%s", input, sig64);
	return n > 0 && n < (int) outlen ? n : -1;
}

/* ---------- credential loading (sender thread only) ---------- */

static int nat_apns_ready(void)
{
	time_t now = time(NULL);

	if (apns.state == 1) {
		goto jwt;
	}
	if (apns.state == -1 && now < apns.retry_at) {
		return -1;
	}
	apns.state = -1;
	apns.retry_at = now + NAT_HEALTH_RETRY_S;
	{
		char script[300];
		char bundle[128];
		char *buf;
		char *pem;

		snprintf(script, sizeof(script), "%s/send_push_voip.py", sofia_cfg.push_scripts);
		if (!(buf = nat_slurp(script, 16384))) {
			ast_log(LOG_WARNING, "Sofia PUSH native: cannot read %s - APNs unavailable on this lane (script fallback)\n", script);
			return -1;
		}
		if (nat_py_const(buf, "TEAM_ID", apns.team, sizeof(apns.team))
			|| nat_py_const(buf, "KEY_ID", apns.kid, sizeof(apns.kid))
			|| nat_py_const(buf, "KEY_FILE", apns.keyfile, sizeof(apns.keyfile))
			|| nat_py_const(buf, "BUNDLE_ID", bundle, sizeof(bundle))) {
			ast_free(buf);
			ast_log(LOG_WARNING, "Sofia PUSH native: cannot parse TEAM_ID/KEY_ID/KEY_FILE/BUNDLE_ID out of %s - APNs unavailable on this lane\n", script);
			return -1;
		}
		ast_free(buf);
		snprintf(apns.topic, sizeof(apns.topic), "%s.voip", bundle);
		if (!(pem = nat_slurp(apns.keyfile, 8192))) {
			ast_log(LOG_WARNING, "Sofia PUSH native: cannot read APNs key %s - APNs unavailable on this lane\n", apns.keyfile);
			return -1;
		}
		if (apns.pkey) {
			EVP_PKEY_free(apns.pkey);
		}
		apns.pkey = nat_load_pem_key(pem, strlen(pem));
		ast_free(pem);
		if (!apns.pkey) {
			ast_log(LOG_WARNING, "Sofia PUSH native: APNs key %s did not parse as a PEM private key\n", apns.keyfile);
			return -1;
		}
		apns.state = 1;
		apns.jwt_at = 0;
		ast_verb(2, "Sofia PUSH native: APNs ready (team=%s kid=%s topic=%s)\n", apns.team, apns.kid, apns.topic);
	}
jwt:
	if (!apns.jwt[0] || now - apns.jwt_at > 3000) {	/* ~50 min; never < 20 min (Apple throttling rule) */
		char hdr[128], claims[128];

		snprintf(hdr, sizeof(hdr), "{\"alg\":\"ES256\",\"kid\":\"%s\"}", apns.kid);
		snprintf(claims, sizeof(claims), "{\"iss\":\"%s\",\"iat\":%ld}", apns.team, (long) now);
		if (nat_jwt_sign(apns.pkey, 1, hdr, claims, apns.jwt, sizeof(apns.jwt)) < 0) {
			apns.state = -1;
			apns.retry_at = now + NAT_HEALTH_RETRY_S;
			apns.jwt[0] = '\0';
			ast_log(LOG_WARNING, "Sofia PUSH native: APNs ES256 signing failed - APNs unavailable on this lane\n");
			return -1;
		}
		apns.jwt_at = now;
	}
	return 0;
}

static int nat_fcm_ready(void)
{
	time_t now = time(NULL);

	if (fcm.state == 1) {
		return 0;
	}
	if (fcm.state == -1 && now < fcm.retry_at) {
		return -1;
	}
	fcm.state = -1;
	fcm.retry_at = now + NAT_HEALTH_RETRY_S;
	{
		char script[300];
		char *buf;
		char pem[4096];

		snprintf(script, sizeof(script), "%s/send_push.py", sofia_cfg.push_scripts);
		if (!(buf = nat_slurp(script, 16384))) {
			ast_log(LOG_WARNING, "Sofia PUSH native: cannot read %s - FCM unavailable on this lane (script fallback)\n", script);
			return -1;
		}
		/* the SA path is the first double-quoted string ending in .json */
		{
			const char *p = buf;
			fcm.sa_path[0] = '\0';
			while ((p = strchr(p, '"'))) {
				const char *q = strchr(p + 1, '"');
				if (!q) {
					break;
				}
				if (q - p > 6 && !strncmp(q - 5, ".json", 5) && (size_t)(q - p) < sizeof(fcm.sa_path)) {
					ast_copy_string(fcm.sa_path, p + 1, q - p);
					break;
				}
				p = q + 1;
			}
		}
		ast_free(buf);
		if (!fcm.sa_path[0]) {
			ast_log(LOG_WARNING, "Sofia PUSH native: no service-account .json path found in %s - FCM unavailable on this lane\n", script);
			return -1;
		}
		if (!(buf = nat_slurp(fcm.sa_path, 16384))) {
			ast_log(LOG_WARNING, "Sofia PUSH native: cannot read service account %s - FCM unavailable on this lane\n", fcm.sa_path);
			return -1;
		}
		if (nat_json_str(buf, "client_email", fcm.client_email, sizeof(fcm.client_email))
			|| nat_json_str(buf, "private_key", pem, sizeof(pem))
			|| nat_json_str(buf, "project_id", fcm.project, sizeof(fcm.project))) {
			ast_free(buf);
			ast_log(LOG_WARNING, "Sofia PUSH native: service account %s lacks client_email/private_key/project_id - FCM unavailable on this lane\n", fcm.sa_path);
			return -1;
		}
		if (nat_json_str(buf, "token_uri", fcm.token_uri, sizeof(fcm.token_uri))) {
			ast_copy_string(fcm.token_uri, "https://oauth2.googleapis.com/token", sizeof(fcm.token_uri));
		}
		ast_free(buf);
		if (fcm.pkey) {
			EVP_PKEY_free(fcm.pkey);
		}
		fcm.pkey = nat_load_pem_key(pem, strlen(pem));
		memset(pem, 0, sizeof(pem));	/* key hygiene: don't leave the PEM on the stack */
		if (!fcm.pkey) {
			ast_log(LOG_WARNING, "Sofia PUSH native: private_key in %s did not parse - FCM unavailable on this lane\n", fcm.sa_path);
			return -1;
		}
		fcm.state = 1;
		ast_verb(2, "Sofia PUSH native: FCM ready (project=%s sa=%s)\n", fcm.project, fcm.client_email);
	}
	return 0;
}

/* ---------- curl plumbing ---------- */

static size_t nat_write_cb(char *ptr, size_t size, size_t nmemb, void *ud)
{
	struct nat_job *j = ud;
	size_t n = size * nmemb;
	size_t room = sizeof(j->resp) - 1 - j->resp_len;

	if (n < room) {
		room = n;
	}
	if (room) {
		memcpy(j->resp + j->resp_len, ptr, room);
		j->resp_len += room;
		j->resp[j->resp_len] = '\0';
	}
	return n;	/* always consume: overflow is silently dropped, the marker fits far earlier */
}

static size_t nat_oauth_write_cb(char *ptr, size_t size, size_t nmemb, void *ud)
{
	size_t n = size * nmemb;
	size_t room = sizeof(fcm.oauth_resp) - 1 - fcm.oauth_resp_len;

	(void) ud;
	if (n < room) {
		room = n;
	}
	if (room) {
		memcpy(fcm.oauth_resp + fcm.oauth_resp_len, ptr, room);
		fcm.oauth_resp_len += room;
		fcm.oauth_resp[fcm.oauth_resp_len] = '\0';
	}
	return n;
}

static long nat_budget_left_ms(const struct timeval *t0)
{
	long used = (long) ast_tvdiff_ms(ast_tvnow(), *t0);
	return NAT_JOB_BUDGET_MS - used;
}

/* Common easy-handle setup; timeouts clamped to the job's remaining budget. */
static CURL *nat_easy_new(const char *url, struct curl_slist *hdrs, const char *body,
	curl_write_callback wcb, void *wud, void *priv, long budget_ms)
{
	CURL *e = curl_easy_init();
	long to = budget_ms < NAT_XFER_TIMEOUT_MS ? budget_ms : NAT_XFER_TIMEOUT_MS;
	long cto = budget_ms < NAT_CONNECT_TIMEOUT_MS ? budget_ms : NAT_CONNECT_TIMEOUT_MS;

	if (!e) {
		return NULL;
	}
	curl_easy_setopt(e, CURLOPT_URL, url);
	curl_easy_setopt(e, CURLOPT_NOSIGNAL, 1L);		/* mandatory in a threaded PBX (func_curl precedent) */
	curl_easy_setopt(e, CURLOPT_HTTP_VERSION, (long) CURL_HTTP_VERSION_2TLS);
	curl_easy_setopt(e, CURLOPT_TIMEOUT_MS, to > 100 ? to : 100);
	curl_easy_setopt(e, CURLOPT_CONNECTTIMEOUT_MS, cto > 100 ? cto : 100);
	curl_easy_setopt(e, CURLOPT_POST, 1L);
	curl_easy_setopt(e, CURLOPT_POSTFIELDS, body);		/* job-owned, outlives the transfer */
	curl_easy_setopt(e, CURLOPT_POSTFIELDSIZE, (long) strlen(body));
	if (hdrs) {
		curl_easy_setopt(e, CURLOPT_HTTPHEADER, hdrs);
	}
	curl_easy_setopt(e, CURLOPT_WRITEFUNCTION, wcb);
	curl_easy_setopt(e, CURLOPT_WRITEDATA, wud);
	curl_easy_setopt(e, CURLOPT_PRIVATE, priv);
	curl_easy_setopt(e, CURLOPT_USERAGENT, "gabpbx-push-native/1.0");
	return e;
}

/* ---------- job completion ---------- */

static void nat_job_free(struct nat_job *j)
{
	if (j->easy) {
		curl_multi_remove_handle(nat_multi, j->easy);
		curl_easy_cleanup(j->easy);
		j->easy = NULL;
	}
	if (j->hdrs) {
		curl_slist_free_all(j->hdrs);
		j->hdrs = NULL;
	}
	ast_free(j);
	ast_atomic_fetchadd_int(&nat_depth, -1);
}

static const char *nat_job_label(const struct nat_job *j)
{
	if (j->purpose == SOFIA_PUSH_PURPOSE_REREGISTER) {
		return "native/fcm-rereg";
	}
	return j->is_voip ? "native/apns-voip" : "native/fcm-call";
}

static void nat_job_finish(struct nat_job *j, const char *out)
{
	char redact[64];
	long ms = (long) ast_tvdiff_ms(ast_tvnow(), j->t0);

	sofia_push_sender_complete(j->peername, j->device_id, j->callid, nat_job_label(j),
		sofia_push_redact(j->token, redact, sizeof(redact)), out, ms);
	nat_job_free(j);
}

/* ---------- transfer starters (sender thread only) ---------- */

static void nat_start_apns(struct nat_job *j, int sandbox)
{
	char esc_num[256], esc_name[512];
	long budget = nat_budget_left_ms(&j->t0);

	if (budget <= 0) {
		nat_job_finish(j, "ERR:timeout");
		return;
	}
	if (nat_apns_ready()) {
		nat_apns_sick_until = time(NULL) + NAT_HEALTH_RETRY_S;
		nat_job_finish(j, "ERR:apns-config");
		return;
	}
	j->stage = sandbox ? NAT_STAGE_APNS_SANDBOX : NAT_STAGE_APNS_PROD;
	j->resp_len = 0;
	j->resp[0] = '\0';
	if (j->hdrs) {
		curl_slist_free_all(j->hdrs);
		j->hdrs = NULL;
	}
	snprintf(j->url, sizeof(j->url), "https://%s/3/device/%s",
		sandbox ? "api.sandbox.push.apple.com" : "api.push.apple.com", j->token);
	/* payload byte-identical to send_push_voip.py's json.dumps (default ', '/': ' separators) */
	nat_json_escape(esc_num, sizeof(esc_num), j->cid_num);
	nat_json_escape(esc_name, sizeof(esc_name), j->cid_name);
	snprintf(j->body, sizeof(j->body),
		"{\"uuid\": \"%s\", \"caller\": \"%s\", \"callerName\": \"%s\", \"hasVideo\": \"false\"}",
		j->callid, esc_num, esc_name);
	snprintf(j->auth_hdr, sizeof(j->auth_hdr), "authorization: bearer %s", apns.jwt);
	j->hdrs = curl_slist_append(NULL, j->auth_hdr);
	{
		char h[192];
		snprintf(h, sizeof(h), "apns-topic: %s", apns.topic);
		j->hdrs = curl_slist_append(j->hdrs, h);
	}
	j->hdrs = curl_slist_append(j->hdrs, "apns-push-type: voip");
	j->hdrs = curl_slist_append(j->hdrs, "apns-priority: 10");
	j->hdrs = curl_slist_append(j->hdrs, "apns-expiration: 0");

	if (!(j->easy = nat_easy_new(j->url, j->hdrs, j->body, nat_write_cb, j, j, budget))
		|| curl_multi_add_handle(nat_multi, j->easy) != CURLM_OK) {
		if (j->easy) {
			curl_easy_cleanup(j->easy);
			j->easy = NULL;
		}
		nat_job_finish(j, "ERR:curl-init");
	}
}

static void nat_start_fcm_send(struct nat_job *j)
{
	char esc_a[256], esc_b[512];
	long budget = nat_budget_left_ms(&j->t0);

	if (budget <= 0) {
		nat_job_finish(j, "ERR:timeout");
		return;
	}
	j->stage = NAT_STAGE_FCM_SEND;
	j->resp_len = 0;
	j->resp[0] = '\0';
	if (j->hdrs) {
		curl_slist_free_all(j->hdrs);
		j->hdrs = NULL;
	}
	snprintf(j->url, sizeof(j->url), "https://fcm.googleapis.com/v1/projects/%s/messages:send", fcm.project);
	/* payloads byte-identical to send_push.py / send_push_reregister.py json.dumps */
	if (j->purpose == SOFIA_PUSH_PURPOSE_REREGISTER) {
		nat_json_escape(esc_a, sizeof(esc_a), j->cid_num);	/* username travels in cid_num */
		snprintf(j->body, sizeof(j->body),
			"{\"message\": {\"token\": \"%s\", \"data\": {\"type\": \"reregister\", \"action\": \"refresh_registration\", \"username\": \"%s\"}, "
			"\"android\": {\"priority\": \"HIGH\", \"ttl\": \"120s\"}, "
			"\"apns\": {\"headers\": {\"apns-priority\": \"5\", \"apns-push-type\": \"background\"}, \"payload\": {\"aps\": {\"content-available\": 1}}}}}",
			j->token, esc_a);
	} else {
		nat_json_escape(esc_a, sizeof(esc_a), j->cid_num);
		nat_json_escape(esc_b, sizeof(esc_b), j->cid_name);
		snprintf(j->body, sizeof(j->body),
			"{\"message\": {\"token\": \"%s\", \"data\": {\"type\": \"call\", \"caller\": \"%s\", \"callerName\": \"%s\", \"uuid\": \"%s\", \"hasVideo\": \"false\"}, "
			"\"android\": {\"priority\": \"HIGH\", \"ttl\": \"0s\"}, "
			"\"apns\": {\"headers\": {\"apns-priority\": \"10\", \"apns-push-type\": \"background\"}, \"payload\": {\"aps\": {\"content-available\": 1}}}}}",
			j->token, esc_a, esc_b, j->callid);
	}
	snprintf(j->auth_hdr, sizeof(j->auth_hdr), "Authorization: Bearer %s", fcm.access_token);
	j->hdrs = curl_slist_append(NULL, j->auth_hdr);
	j->hdrs = curl_slist_append(j->hdrs, "Content-Type: application/json");

	if (!(j->easy = nat_easy_new(j->url, j->hdrs, j->body, nat_write_cb, j, j, budget))
		|| curl_multi_add_handle(nat_multi, j->easy) != CURLM_OK) {
		if (j->easy) {
			curl_easy_cleanup(j->easy);
			j->easy = NULL;
		}
		nat_job_finish(j, "ERR:curl-init");
	}
}

/* Single-flight OAuth: first cold FCM job starts it, the rest park on nat_oauth_waiters. */
static void nat_start_oauth(void)
{
	time_t now = time(NULL);
	char hdr[64], claims[640], jwt[NAT_JWT_MAX];

	snprintf(hdr, sizeof(hdr), "{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
	snprintf(claims, sizeof(claims),
		"{\"iss\":\"%s\",\"scope\":\"https://www.googleapis.com/auth/firebase.messaging\",\"aud\":\"%s\",\"iat\":%ld,\"exp\":%ld}",
		fcm.client_email, fcm.token_uri, (long) now, (long) now + 3600);
	if (nat_jwt_sign(fcm.pkey, 0, hdr, claims, jwt, sizeof(jwt)) < 0) {
		fcm.state = -1;
		fcm.retry_at = now + NAT_HEALTH_RETRY_S;
		fcm.oauth_state = 0;
		ast_log(LOG_WARNING, "Sofia PUSH native: OAuth RS256 signing failed - FCM unavailable on this lane\n");
		return;
	}
	snprintf(fcm.oauth_body, sizeof(fcm.oauth_body),
		"grant_type=urn%%3Aietf%%3Aparams%%3Aoauth%%3Agrant-type%%3Ajwt-bearer&assertion=%s", jwt);
	fcm.oauth_resp_len = 0;
	fcm.oauth_resp[0] = '\0';
	fcm.oauth_t0 = ast_tvnow();
	if (fcm.oauth_hdrs) {
		curl_slist_free_all(fcm.oauth_hdrs);
	}
	fcm.oauth_hdrs = curl_slist_append(NULL, "Content-Type: application/x-www-form-urlencoded");
	fcm.oauth_easy = nat_easy_new(fcm.token_uri, fcm.oauth_hdrs, fcm.oauth_body,
		nat_oauth_write_cb, NULL, &nat_oauth_marker, NAT_JOB_BUDGET_MS);
	if (!fcm.oauth_easy || curl_multi_add_handle(nat_multi, fcm.oauth_easy) != CURLM_OK) {
		if (fcm.oauth_easy) {
			curl_easy_cleanup(fcm.oauth_easy);
			fcm.oauth_easy = NULL;
		}
		fcm.oauth_state = 0;
		ast_log(LOG_WARNING, "Sofia PUSH native: OAuth transfer setup failed\n");
		return;
	}
	fcm.oauth_state = 1;
}

/* Route a dequeued (or oauth-released) job to its first/next transfer. */
static void nat_job_route(struct nat_job *j)
{
	if (j->purpose == SOFIA_PUSH_PURPOSE_CALL && j->is_voip) {
		nat_start_apns(j, 0);
		return;
	}
	/* FCM-shaped (fcm call + every reregister) */
	if (nat_fcm_ready()) {
		nat_fcm_sick_until = time(NULL) + NAT_HEALTH_RETRY_S;
		nat_job_finish(j, "ERR:fcm-config");
		return;
	}
	if (fcm.oauth_state == 2 && time(NULL) < fcm.oauth_expiry) {
		nat_start_fcm_send(j);
		return;
	}
	j->stage = NAT_STAGE_OAUTH_WAIT;
	AST_LIST_INSERT_TAIL(&nat_oauth_waiters, j, entry);
	if (fcm.oauth_state != 1) {
		nat_start_oauth();
		if (fcm.oauth_state != 1) {
			/* signing/setup failed synchronously: fail every parked waiter */
			struct nat_job *w;
			while ((w = AST_LIST_REMOVE_HEAD(&nat_oauth_waiters, entry))) {
				nat_job_finish(w, "ERR:oauth-sign");
			}
		}
	}
}

/* ---------- DONE handling ---------- */

static void nat_oauth_done(CURLcode cres)
{
	long code = 0;
	struct nat_job *w;
	char fail[96];

	curl_easy_getinfo(fcm.oauth_easy, CURLINFO_RESPONSE_CODE, &code);
	curl_multi_remove_handle(nat_multi, fcm.oauth_easy);
	curl_easy_cleanup(fcm.oauth_easy);
	fcm.oauth_easy = NULL;
	if (fcm.oauth_hdrs) {
		curl_slist_free_all(fcm.oauth_hdrs);
		fcm.oauth_hdrs = NULL;
	}

	if (cres == CURLE_OK && code == 200
		&& !nat_json_str(fcm.oauth_resp, "access_token", fcm.access_token, sizeof(fcm.access_token))) {
		fcm.oauth_state = 2;
		fcm.oauth_expiry = time(NULL) + 3300;	/* Google issues 3600 s; renew early */
		ast_debug(1, "Sofia PUSH native: OAuth token refreshed (%ld ms)\n",
			(long) ast_tvdiff_ms(ast_tvnow(), fcm.oauth_t0));
		while ((w = AST_LIST_REMOVE_HEAD(&nat_oauth_waiters, entry))) {
			nat_start_fcm_send(w);
		}
		return;
	}

	fcm.oauth_state = 0;
	if (cres != CURLE_OK) {
		snprintf(fail, sizeof(fail), "ERR:oauth:%s", curl_easy_strerror(cres));
	} else {
		snprintf(fail, sizeof(fail), "ERR:oauth:%ld", code);
	}
	nat_fcm_sick_until = time(NULL) + NAT_HEALTH_RETRY_S;
	while ((w = AST_LIST_REMOVE_HEAD(&nat_oauth_waiters, entry))) {
		nat_job_finish(w, fail);
	}
}

static void nat_job_done(struct nat_job *j, CURLcode cres)
{
	long code = 0;
	char out[NAT_RESULT_MAX];

	curl_easy_getinfo(j->easy, CURLINFO_RESPONSE_CODE, &code);
	curl_multi_remove_handle(nat_multi, j->easy);
	curl_easy_cleanup(j->easy);
	j->easy = NULL;

	if (cres != CURLE_OK) {
		/* transport-class failure: parity with the script's uncaught-exception line;
		 * deliberately does NOT match the dead-token patterns. Timeouts map to the
		 * harness string the script lane produces. */
		if (cres == CURLE_OPERATION_TIMEDOUT) {
			nat_job_finish(j, "ERR:timeout");
		} else {
			snprintf(out, sizeof(out), "ERR:%s", curl_easy_strerror(cres));
			nat_job_finish(j, out);
		}
		return;
	}

	if (j->stage == NAT_STAGE_APNS_PROD) {
		if (code == 200) {
			nat_job_finish(j, "OK:prod");
		} else if (code == 400 && strstr(j->resp, "BadDeviceToken")) {
			nat_start_apns(j, 1);	/* dev-signed build: retry against sandbox, script parity */
		} else {
			snprintf(out, sizeof(out), "ERR:prod:%ld %s", code, j->resp);
			nat_job_finish(j, out);
		}
		return;
	}
	if (j->stage == NAT_STAGE_APNS_SANDBOX) {
		if (code == 200) {
			nat_job_finish(j, "OK:sandbox");
		} else {
			snprintf(out, sizeof(out), "ERR:sandbox:%ld %s", code, j->resp);
			nat_job_finish(j, out);
		}
		return;
	}
	/* NAT_STAGE_FCM_SEND */
	if (code == 200) {
		nat_job_finish(j, "OK");
	} else {
		/* EXACT "ERR:%ld", no body: the dead-token matcher does whole-string
		 * equality on ERR:404 / ERR:400 (send_push.py parity). */
		snprintf(out, sizeof(out), "ERR:%ld", code);
		nat_job_finish(j, out);
	}
}

/* ---------- the sender thread ---------- */

static void *nat_thread_run(void *ignore)
{
	(void) ignore;

	while (!nat_stop) {
		struct nat_job *j;
		AST_LIST_HEAD_NOLOCK(, nat_job) batch = AST_LIST_HEAD_NOLOCK_INIT_VALUE;
		int running = 0;
		CURLMsg *msg;
		int pending;

		/* 1) steal the whole inbound queue in one shot (logger.c batch-drain idiom) */
		AST_LIST_LOCK(&nat_inq);
		while ((j = AST_LIST_REMOVE_HEAD(&nat_inq, entry))) {
			AST_LIST_INSERT_TAIL(&batch, j, entry);
		}
		AST_LIST_UNLOCK(&nat_inq);
		while ((j = AST_LIST_REMOVE_HEAD(&batch, entry))) {
			j->t0 = ast_tvnow();
			nat_job_route(j);
		}

		/* 2) drive the transfers */
		curl_multi_perform(nat_multi, &running);
		while ((msg = curl_multi_info_read(nat_multi, &pending))) {
			void *priv = NULL;

			if (msg->msg != CURLMSG_DONE) {
				continue;
			}
			curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &priv);
			if (priv == &nat_oauth_marker) {
				nat_oauth_done(msg->data.result);
			} else if (priv) {
				nat_job_done((struct nat_job *) priv, msg->data.result);
			}
		}

		/* 3) expire OAuth-parked jobs past their whole-job budget */
		{
			struct nat_job *w;
			AST_LIST_TRAVERSE_SAFE_BEGIN(&nat_oauth_waiters, w, entry) {
				if (nat_budget_left_ms(&w->t0) <= 0) {
					AST_LIST_REMOVE_CURRENT(entry);
					nat_job_finish(w, "ERR:timeout");
				}
			}
			AST_LIST_TRAVERSE_SAFE_END;
		}

		/* 4) sleep until network activity, a queue wakeup, or 1 s (budget granularity) */
		curl_multi_poll(nat_multi, NULL, 0, 1000, NULL);
	}

	/* load-failure unwind only: fail nothing loudly, just release resources */
	{
		struct nat_job *j;
		AST_LIST_LOCK(&nat_inq);
		while ((j = AST_LIST_REMOVE_HEAD(&nat_inq, entry))) {
			ast_free(j);
			ast_atomic_fetchadd_int(&nat_depth, -1);
		}
		AST_LIST_UNLOCK(&nat_inq);
		while ((j = AST_LIST_REMOVE_HEAD(&nat_oauth_waiters, entry))) {
			nat_job_free(j);
		}
		if (fcm.oauth_easy) {
			curl_multi_remove_handle(nat_multi, fcm.oauth_easy);
			curl_easy_cleanup(fcm.oauth_easy);
			fcm.oauth_easy = NULL;
		}
	}
	return NULL;
}

/* ---------- public API (decls in chan_sofia_internal.h) ---------- */

int sofia_push_sender_init(void)
{
	curl_version_info_data *vi;

	if (nat_up) {
		return 0;	/* idempotent */
	}
	/* curl_global_init is res_curl.so's job (func_curl.c:764 precedent) -- never call it here */
	if (!ast_module_check("res_curl.so")
		&& ast_load_resource("res_curl.so") != AST_MODULE_LOAD_SUCCESS) {
		ast_log(LOG_WARNING, "Sofia PUSH native: res_curl.so unavailable - native sender disabled (script fallback)\n");
		return -1;
	}
	vi = curl_version_info(CURLVERSION_NOW);
	if (!vi || !(vi->features & CURL_VERSION_HTTP2)) {
		ast_log(LOG_WARNING, "Sofia PUSH native: libcurl lacks HTTP/2 (APNs requires it) - native sender disabled (script fallback)\n");
		return -1;
	}
	if (!(nat_multi = curl_multi_init())) {
		ast_log(LOG_WARNING, "Sofia PUSH native: curl_multi_init failed - native sender disabled\n");
		return -1;
	}
	curl_multi_setopt(nat_multi, CURLMOPT_PIPELINING, (long) CURLPIPE_MULTIPLEX);
	nat_stop = 0;
	if (ast_pthread_create(&nat_tid, NULL, nat_thread_run, NULL)) {
		/* auxiliary-thread policy (chan_sofia.c:20901): warn, mark, run without */
		ast_log(LOG_WARNING, "Sofia PUSH native: sender thread create failed - native sender disabled (script fallback)\n");
		nat_tid = AST_PTHREADT_NULL;
		curl_multi_cleanup(nat_multi);
		nat_multi = NULL;
		return -1;
	}
	nat_up = 1;
	ast_verb(2, "Sofia PUSH native: sender lane up (libcurl %s, HTTP/2 multiplexed, queue cap %d)\n",
		vi->version, NATQ_MAX);
	return 0;
}

void sofia_push_sender_stop(void)
{
	if (nat_tid == AST_PTHREADT_NULL) {
		return;
	}
	AST_LIST_LOCK(&nat_inq);
	nat_up = 0;
	nat_stop = 1;
	AST_LIST_UNLOCK(&nat_inq);
	curl_multi_wakeup(nat_multi);
	pthread_join(nat_tid, NULL);
	nat_tid = AST_PTHREADT_NULL;
	curl_multi_cleanup(nat_multi);
	nat_multi = NULL;
	if (apns.pkey) {
		EVP_PKEY_free(apns.pkey);
		apns.pkey = NULL;
		apns.state = 0;
	}
	if (fcm.pkey) {
		EVP_PKEY_free(fcm.pkey);
		fcm.pkey = NULL;
		fcm.state = 0;
	}
}

int sofia_push_sender_available(void)
{
	return nat_up;
}

int sofia_push_sender_natq_depth(void)
{
	return nat_depth;
}

int sofia_push_sender_submit(enum sofia_push_purpose purpose, const char *push_type,
	const char *token, const char *cid_num, const char *cid_name, const char *callid,
	const char *peername, const char *device_id)
{
	struct nat_job *j;
	int is_voip = purpose == SOFIA_PUSH_PURPOSE_CALL
		&& push_type && !strcasecmp(push_type, "voip");

	if (!nat_up) {
		return 1;	/* lane down: caller falls back to the script sender */
	}
	/* creds-class sickness: report "cannot serve" so the dispatcher uses the script
	 * sender instead of recording an ERR for a push that never left the box */
	if (is_voip && nat_apns_sick_until && time(NULL) < nat_apns_sick_until) {
		return 1;
	}
	if (!is_voip && nat_fcm_sick_until && time(NULL) < nat_fcm_sick_until) {
		return 1;
	}
	if (ast_atomic_fetchadd_int(&nat_depth, +1) >= NATQ_MAX) {
		ast_atomic_fetchadd_int(&nat_depth, -1);
		return -1;	/* full: caller drops (bounded, never degrade a burst into fork/exec) */
	}
	if (!(j = ast_calloc(1, sizeof(*j)))) {
		ast_atomic_fetchadd_int(&nat_depth, -1);
		return -1;
	}
	j->purpose = purpose;
	j->is_voip = is_voip;
	ast_copy_string(j->token, S_OR(token, ""), sizeof(j->token));
	ast_copy_string(j->cid_num, S_OR(cid_num, ""), sizeof(j->cid_num));
	ast_copy_string(j->cid_name, S_OR(cid_name, ""), sizeof(j->cid_name));
	ast_copy_string(j->callid, S_OR(callid, ""), sizeof(j->callid));
	ast_copy_string(j->peername, S_OR(peername, ""), sizeof(j->peername));
	ast_copy_string(j->device_id, S_OR(device_id, ""), sizeof(j->device_id));

	AST_LIST_LOCK(&nat_inq);
	if (!nat_up) {	/* re-check under the lock: stop() clears it under this same lock */
		AST_LIST_UNLOCK(&nat_inq);
		ast_free(j);
		ast_atomic_fetchadd_int(&nat_depth, -1);
		return 1;
	}
	AST_LIST_INSERT_TAIL(&nat_inq, j, entry);
	/* wakeup while still holding the lock: orders it strictly before any stop() teardown */
	curl_multi_wakeup(nat_multi);
	AST_LIST_UNLOCK(&nat_inq);
	return 0;
}

#else /* !SOFIA_PUSH_NATIVE_BUILD: configured without curl/crypto (or libcurl < 7.68) */

int sofia_push_sender_init(void)
{
	ast_log(LOG_NOTICE, "Sofia PUSH native: built without libcurl>=7.68/libcrypto - script sender only\n");
	return -1;
}
void sofia_push_sender_stop(void)
{
}
int sofia_push_sender_available(void)
{
	return 0;
}
int sofia_push_sender_natq_depth(void)
{
	return 0;
}
int sofia_push_sender_submit(enum sofia_push_purpose purpose, const char *push_type,
	const char *token, const char *cid_num, const char *cid_name, const char *callid,
	const char *peername, const char *device_id)
{
	return 1;	/* always "use the script sender" */
}

#endif /* SOFIA_PUSH_NATIVE_BUILD */
