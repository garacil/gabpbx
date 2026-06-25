/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

/*! \file sofia_publish.c
 * \brief chan_sofia outbound PUBLISH / EPA (RFC 3903), split from chan_sofia.c.
 */

#include "gabpbx.h"
#include "gabpbx/astobj2.h"
#include "gabpbx/cli.h"
#include "gabpbx/lock.h"
#include "gabpbx/utils.h"
#include "gabpbx/strings.h"
#include "gabpbx/logger.h"
#include "gabpbx/pbx.h"
#include "gabpbx/channel.h"

#include <sofia-sip/nua.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/su_tag.h>
#include <sofia-sip/sip_tag.h>
#include <sofia-sip/nua_tag.h>
#include <sofia-sip/su_wait.h>
#include <sofia-sip/auth_client.h>

#include "include/chan_sofia_internal.h"
#include "include/sofia_publish.h"

#define SOFIA_PUBLISH_MAX_AUTH 3
#define SOFIA_PUBLISH_SWEEP_MS 1000	/* PUBLISH scheduler tick (next_send granularity) */
#define SOFIA_PUBLISH_MIN_EXPIRES 30	/* floor: a sub-30s TTL cannot be refreshed by the 1Hz sweep */

/* Sentinel hmagic for publication handles - routes generic nua_r_method events to the
 * publication handler before any pvt/peer dispatch. A fixed address, so never confusable
 * with a live pvt/peer/sub pointer (per-object correlation is find_by_nh's job). */
int sofia_publication_sentinel;	/* hmagic identity; HMAGIC macro in sofia_publish.h */

struct sofia_publication {
	char key[AST_MAX_EXTENSION + AST_MAX_CONTEXT + 96];	/* "peer|context|exten" — provably sufficient (Codex) */
	char exten[AST_MAX_EXTENSION];		/* published extension (peer regexten) */
	char context[AST_MAX_CONTEXT];		/* hint lookup context (peer subscribecontext) */
	char entity[256];			/* presentity URI: sip:exten@publish_domain */
	char target[300];			/* PUBLISH Request-URI: sip:exten@publish_domain:<ESC-port>. The R-URI
						 * carries the ESC port so the dialog target is the ESC from the FIRST
						 * request and stays there on refresh (sofia caches the resolved R-URI as
						 * ds_route; a per-request Route header is stripped — nua_client.c:776). The
						 * presentity in To/From/body uses the clean `entity` instead. */
	nua_handle_t *nh;			/* PUBLISH handle; correlated via sofia_publication_find_by_nh */
	char etag[128];				/* SIP-ETag from the last 200 ("" = none yet) */
	int stateid;				/* ast_extension_state_add_destroy id (-1 = none) */
	int laststate;				/* last AST_EXTENSION_* published */
	uint32_t version;			/* dialog-info version= counter */
	enum sofia_sub_format format;		/* body format: DIALOG_INFO (default) or PIDF ([general] publish_format) */
	int expires;				/* configured PUBLISH Expires (seconds) */
	unsigned in_flight:1;			/* a nua_method PUBLISH awaits its nua_r_method */
	time_t next_send;			/* when the sweep should (re)PUBLISH this pub; 0 = not scheduled.
						 * Unifies initial-spread + refresh + state-change + retry on the
						 * single sofia_thread sweep, so 5-10k pubs never thunder-herd. */
	int auth_attempts;			/* bounded reactive-auth counter */
	int terminated;				/* teardown idempotency */
	int _reload_marked;			/* reload mark-and-sweep (mirrors peer->_reload_marked): marked at
						 * reload start, unmarked if the peer still publishes it, swept if not. */
	int last_status;			/* last final nua_r_method status (0 = no response yet) — CLI diag */
};

#define MAX_PUBLICATION_BUCKETS 10007			/* prime; one entry per publish=yes peer — sized for
							 * large deployments (~5000-10000 users, load factor <=1) */
static struct ao2_container *publications;	/* keyed by key; created in load_module */
static su_timer_t *publication_refresh_timer;	/* recurring refresh sweep on sofia_thread */
static void sofia_publication_teardown(struct sofia_publication *pub);	/* fwd: defined after create */
static void sofia_publication_schedule(struct sofia_publication *pub, int base, int span);	/* fwd */
/* ao2 hash: on the composite key string. */
static int publication_hash_fn(const void *obj, int flags)
{
	const struct sofia_publication *p = obj;	/* full pub or {.key} shim */
	return ast_str_hash(p->key);
}
/* ao2 cmp: exact match on the composite key. */
static int publication_cmp_fn(void *obj, void *arg, int flags)
{
	struct sofia_publication *p = obj;
	struct sofia_publication *match = arg;		/* {.key} shim */
	return strcmp(p->key, match->key) ? 0 : (CMP_MATCH | CMP_STOP);
}

static void publication_destructor(void *obj)
{
	/* No nua_* here — the handle is detached + destroyed on sofia_thread at teardown. */
}

/* Find a publication by its nua handle (linear scan); returns it with a +1 ref. */
static struct sofia_publication *sofia_publication_find_by_nh(nua_handle_t *nh)
{
	struct ao2_iterator it;
	struct sofia_publication *p, *found = NULL;

	if (!publications || !nh) {
		return NULL;
	}
	it = ao2_iterator_init(publications, 0);
	while ((p = ao2_iterator_next(&it))) {
		if (p->nh == nh) {
			found = p;	/* keep the +1 ref */
			break;
		}
		ao2_ref(p, -1);
	}
	ao2_iterator_destroy(&it);
	return found;
}

/* SIP Event package for a publication's body format: RFC 4235 dialog-info -> "dialog";
 * RFC 3856 presence (PIDF) -> "presence". RFC 3903 §4.1/§6: the body's content-type must match the
 * Event package, or the ESC rejects it. */
static const char *sofia_publication_event(enum sofia_sub_format f)
{
	return (f == SOFIA_SUB_DIALOG_INFO) ? "dialog" : "presence";
}

/* Build the PUBLISH body via the SHARED presence/dialog-info builder (one source of truth with the
 * NOTIFY path). pub->format selects dialog-info (default) or PIDF. XML-escaping is done inside. */
static void sofia_publication_build_body(struct ast_str **buf, struct sofia_publication *pub, int state)
{
	sofia_presence_build_body_ex(buf, pub->exten, pub->context, pub->entity, pub->version,
		pub->format, state);
}

/* Send a PUBLISH for `pub` reflecting the current hint state (sofia_thread ONLY). removing=1 ->
 * Expires:0 unpublish. Skips if already in flight - the per-handle serialization that stops two
 * concurrent 200s racing the ETag; the sweep retries on the next due tick. */
static void sofia_publication_send(struct sofia_publication *pub, int removing)
{
	struct ast_str *body = NULL;
	char expires_str[16];
	int state;

	if (!pub || !pub->nh || pub->terminated || (pub->in_flight && !removing)) {
		return;
	}

	state = removing ? pub->laststate : ast_extension_state(NULL, pub->context, pub->exten);

	/* Build the body FIRST: only after it succeeds do we consume next_send + advance version,
	 * so an OOM reschedules a retry instead of permanently unscheduling the publication. */
	if (!removing) {
		if (!(body = ast_str_create(256))) {
			sofia_publication_schedule(pub, 5, 5);	/* OOM — short retry; do not consume next_send/version */
			return;
		}
		sofia_publication_build_body(&body, pub, state);
	}

	pub->next_send = 0;		/* consumed — the response (or a state change) reschedules it */
	pub->version++;
	pub->laststate = state;

	snprintf(expires_str, sizeof(expires_str), "%d", removing ? 0 : pub->expires);

	/* app-managed PUBLISH via the generic method path — the body + If-Match + Expires go out verbatim
	 * every call (unlike nua_publish, which strips the body after the first success). */
	nua_method(pub->nh,
		NUTAG_METHOD("PUBLISH"),
		NUTAG_DIALOG(0),	/* generic method, not a dialog: do not create/refresh dialog target state */
		SIPTAG_EVENT_STR(sofia_publication_event(pub->format)),
		TAG_IF(!removing, SIPTAG_CONTENT_TYPE_STR(sofia_presence_mime(pub->format))),
		TAG_IF(!removing && body != NULL, SIPTAG_PAYLOAD_STR(body ? ast_str_buffer(body) : "")),
		TAG_IF(!ast_strlen_zero(pub->etag), SIPTAG_IF_MATCH_STR(pub->etag)),
		SIPTAG_EXPIRES_STR(expires_str),
		TAG_END());

	pub->in_flight = 1;
	ast_free(body);
}

/* Schedule (re)publication: the sweep will send `pub` at the next tick where next_send <= now. Jitter
 * spreads bursts across [0, span) seconds so 5-10k pubs never fire together (opencode/Codex #6). */
static void sofia_publication_schedule(struct sofia_publication *pub, int base, int span)
{
	int jitter = (span > 0) ? (int)(ast_random() % (unsigned)span) : 0;
	pub->next_send = time(NULL) + base + jitter;
}

/* nua_r_method response handler (sofia_thread). ETag/error matrix: 200+ETag store; 200 no-ETag
 * warn+clear; 401/407 reactive auth (bounded); 412 stale->re-init; 423->Min-Expires+retry;
 * other 4xx/5xx keep last good. */
void sofia_publication_handle_response(int status, char const *phrase,
		nua_handle_t *nh, sip_t const *sip)
{
	struct sofia_publication *pub = sofia_publication_find_by_nh(nh);

	if (!pub) {
		return;
	}
	if (status < 200) {
		ao2_ref(pub, -1);	/* provisional — still in flight */
		return;
	}
	pub->last_status = status;	/* final status — recorded for `sip show publications` diagnostics */

	if ((status == 401 || status == 407) && sip) {
		/* Reactive digest auth. sofia_format_auth_creds returns 0 on SUCCESS. Build BOTH WWW + Proxy
		 * creds when present and pass both (one response may carry both challenges). */
		char www_creds[512], proxy_creds[512];
		int have_www = 0, have_proxy = 0;

		if (pub->auth_attempts < SOFIA_PUBLISH_MAX_AUTH && !ast_strlen_zero(sofia_cfg.publish_username)) {
			if (sip->sip_www_authenticate &&
				sofia_format_auth_creds(sip->sip_www_authenticate, sofia_cfg.publish_username,
					sofia_cfg.publish_password, www_creds, sizeof(www_creds)) == 0) {
				have_www = 1;
			}
			if (sip->sip_proxy_authenticate &&
				sofia_format_auth_creds(sip->sip_proxy_authenticate, sofia_cfg.publish_username,
					sofia_cfg.publish_password, proxy_creds, sizeof(proxy_creds)) == 0) {
				have_proxy = 1;
			}
		}
		if (have_www || have_proxy) {
			pub->auth_attempts++;
			nua_authenticate(nh,
				TAG_IF(have_www, NUTAG_AUTH(www_creds)),
				TAG_IF(have_proxy, NUTAG_AUTH(proxy_creds)),
				TAG_END());	/* resends; response returns here */
			ao2_ref(pub, -1);
			return;
		}
		ast_log(LOG_WARNING, "Sofia PUBLISH: auth failed for '%s' (%d %s)\n", pub->key, status, phrase);
		pub->in_flight = 0;
		ao2_ref(pub, -1);
		return;
	}

	pub->in_flight = 0;
	pub->auth_attempts = 0;

	if (status == 200) {
		if (sip && sip->sip_etag && sip->sip_etag->g_string) {
			ast_copy_string(pub->etag, sip->sip_etag->g_string, sizeof(pub->etag));
		} else {
			ast_log(LOG_WARNING, "Sofia PUBLISH: 200 for '%s' has no SIP-ETag (RFC 3903 non-compliant ESC)\n",
				pub->key);
			pub->etag[0] = '\0';
		}
		/* Honor a granted Expires, clamped before the unsigned->int cast can wrap. */
		if (sip && sip->sip_expires && sip->sip_expires->ex_delta > 0
			&& sip->sip_expires->ex_delta <= SOFIA_PUBLISH_MAX_EXPIRES) {
			pub->expires = (int) sip->sip_expires->ex_delta;
		}
		/* Refresh BEFORE expiry, jittered DOWNWARD so next_send always lands strictly below the TTL
		 * (margin scales with the TTL). Skip if next_send was already set while this PUBLISH was in
		 * flight (a state change came in) - let the sweep send the new state. */
		if (pub->next_send == 0 && !pub->terminated) {
			int margin = pub->expires / 10;					/* ~10% headroom */
			if (margin < 5) {
				margin = 5;
			}
			if (pub->expires > 1 && margin > pub->expires - 1) {
				margin = pub->expires - 1;				/* tiny TTL: keep at least 1s of life */
			}
			/* next_send in [latest-margin, latest) where latest = expires-margin, so always < expires. */
			sofia_publication_schedule(pub, (pub->expires - 2 * margin > 1) ? pub->expires - 2 * margin : 1,
				(margin > 1) ? margin : 1);
		}
	} else if (status == 412) {
		pub->etag[0] = '\0';				/* stale ETag — the sweep re-publishes as initial */
		sofia_publication_schedule(pub, 1, 3);
	} else if (status == 423) {
		if (sip && sip->sip_min_expires && sip->sip_min_expires->me_delta <= SOFIA_PUBLISH_MAX_EXPIRES
			&& (int) sip->sip_min_expires->me_delta > pub->expires) {
			pub->expires = (int) sip->sip_min_expires->me_delta;
		}
		sofia_publication_schedule(pub, 1, 3);
	} else {
		ast_log(LOG_WARNING, "Sofia PUBLISH: '%s' got %d %s — backing off, will retry\n",
			pub->key, status, phrase);
		sofia_publication_schedule(pub, 30, 30);	/* error backoff retry */
	}

	ao2_ref(pub, -1);
}

/* dispatch carrier: extension-state cb (device_state thread) -> sofia_thread */
struct sofia_publication_dispatch {
	struct sofia_publication *pub;	/* +1 ref TRANSFERRED — the cb drops it */
};

/* sofia_thread: marshaled target of the extension-state callback. Marks the pub due NOW so the
 * sweep re-PUBLISHes it (serialized through next_send + in_flight; state read at send time). */
static void sofia_publication_dispatch_cb(void *arg)
{
	struct sofia_publication_dispatch *d = arg;

	if (d->pub && !d->pub->terminated) {
		d->pub->next_send = time(NULL);	/* due now */
	}
	ao2_ref(d->pub, -1);
	ast_free(d);
}

/* device_state taskprocessor thread (NOT sofia_thread): marshal only (no nua_*, no pub mutation). */
static int sofia_publication_state_cb(char *context, char *exten,
		enum ast_extension_states state, void *data)
{
	struct sofia_publication *pub = data;
	struct sofia_publication_dispatch *d;

	if (!pub || !publications) {
		return 0;
	}
	if (!(d = ast_calloc(1, sizeof(*d)))) {
		return 0;
	}
	ao2_ref(pub, +1);	/* dispatch ref */
	d->pub = pub;
	if (sofia_dispatch_to_root_thread(sofia_publication_dispatch_cb, d) < 0) {
		ao2_ref(pub, -1);
		ast_free(d);
	}
	return 0;
}

/* core destroy callback: drops the ast_extension_state registration's +1 ref. */
static void sofia_publication_state_destroy_cb(int id, void *data)
{
	struct sofia_publication *pub = data;

	if (pub) {
		ao2_ref(pub, -1);
	}
}

/* Parse publish_server into its host + port (after stripping sip:/sips: and any userinfo — Codex).
 * The host is the publish_domain default; the port is the ESC SIP port for the PUBLISH target R-URI. */
static void sofia_publish_server_hostport(char *host, size_t hlen, int *port)
{
	const char *p = sofia_cfg.publish_server;
	const char *at;

	host[0] = '\0';
	*port = 0;
	if (ast_strlen_zero(p)) {
		return;
	}
	if (!strncasecmp(p, "sip:", 4)) {
		p += 4;
	} else if (!strncasecmp(p, "sips:", 5)) {
		p += 5;
	}
	if ((at = strchr(p, '@'))) {
		p = at + 1;
	}
	sofia_split_hostport_from_uri(p, host, hlen, port);	/* IPv6-aware host + port extraction */
}

/* Create a publication for a publish=yes peer + send the initial PUBLISH (sofia_thread). */
/* Is this presentity entity already published? The same bare extension in two contexts maps to
 * ONE ESC presentity (sip:exten@domain); two publications would clobber each other's ETag and
 * 412-storm (RFC 3903 4.1). First valid hint wins. */
static int sofia_publication_entity_in_use(const char *entity)
{
	struct ao2_iterator it;
	struct sofia_publication *p;
	int found = 0;

	if (!publications) {
		return 0;
	}
	it = ao2_iterator_init(publications, 0);
	while ((p = ao2_iterator_next(&it))) {
		if (!strcmp(p->entity, entity)) {
			found = 1;
			ao2_ref(p, -1);
			break;
		}
		ao2_ref(p, -1);
	}
	ao2_iterator_destroy(&it);
	return found;
}

/* Create + initial-publish ONE (exten, context) presentity. Requires a REAL hint. Key =
 * peer|context|exten; a duplicate key OR a duplicate presentity entity is skipped (412-storm guard). */
static void sofia_publication_create_one(struct sofia_peer *peer, const char *exten,
		const char *context, const char *domain, int create)
{
	struct sofia_publication *pub, tmp;
	char hint[AST_MAX_EXTENSION];
	char entity[256];

	if (ast_strlen_zero(exten) || ast_strlen_zero(context)) {
		return;
	}
	if (!ast_context_find(context) ||
		!ast_get_hint(hint, sizeof(hint), NULL, 0, NULL, context, exten)) {
		ast_log(LOG_WARNING, "Sofia PUBLISH: peer '%s' has no hint for %s@%s — not published\n",
			peer->name, exten, context);
		return;
	}
	/* Key-find FIRST: an existing peer|context|exten is already published - keep it and UNMARK it
	 * (survives the reload sweep) BEFORE the entity-dedup, which only matters for a genuinely new one. */
	if (snprintf(tmp.key, sizeof(tmp.key), "%s|%s|%s", peer->name, context, exten) >= (int) sizeof(tmp.key)) {
		ast_log(LOG_WARNING, "Sofia PUBLISH: composite key too long for peer '%s' %s@%s — skipped\n",
			peer->name, exten, context);
		return;
	}
	if ((pub = ao2_find(publications, &tmp, OBJ_POINTER))) {
		pub->_reload_marked = 0;	/* already published — survives this reload, do not re-create */
		ao2_ref(pub, -1);
		return;
	}
	if (!create) {
		/* unmark-only reconcile pass: do NOT create yet - a stale same-entity pub (about to be swept)
		 * would block it via the entity-dedup. The create-missing pass runs AFTER the sweep. */
		return;
	}
	snprintf(entity, sizeof(entity), "sip:%s@%s", exten, domain);	/* BARE exten, never ext@ctx */
	if (sofia_publication_entity_in_use(entity)) {
		ast_log(LOG_WARNING, "Sofia PUBLISH: presentity %s already published — skipping duplicate "
			"(%s in context %s) to avoid an ETag conflict\n", entity, exten, context);
		return;
	}
	if (!(pub = ao2_alloc(sizeof(*pub), publication_destructor))) {
		return;
	}
	ast_copy_string(pub->key, tmp.key, sizeof(pub->key));
	ast_copy_string(pub->exten, exten, sizeof(pub->exten));
	ast_copy_string(pub->context, context, sizeof(pub->context));
	ast_copy_string(pub->entity, entity, sizeof(pub->entity));
	pub->expires = (sofia_cfg.publish_expires > 0) ? sofia_cfg.publish_expires : SOFIA_PUBLISH_DEFAULT_EXPIRES;
	if (pub->expires < SOFIA_PUBLISH_MIN_EXPIRES) {
		pub->expires = SOFIA_PUBLISH_MIN_EXPIRES;	/* a 1Hz sweep cannot refresh a sub-30s TTL (Codex) */
	}
	pub->stateid = -1;
	pub->etag[0] = '\0';
	pub->format = sofia_cfg.publish_format;	/* dialog-info (default) or PIDF, per [general] publish_format */

	/* RFC 3903 4: the PUBLISH R-URI is the PRESENTITY. We put the ESC's explicit port in the R-URI
	 * (sip:exten@publish_domain:<ESC-port>) so first send AND every refresh hit the ESC. A Route header
	 * routes only the first request - sofia then caches the resolved R-URI (ds_route, nua_client.c:776)
	 * and strips the per-request Route, leaking refreshes to the DNS-default :5060. To/From/body use the
	 * clean presentity `entity` (no port); the ESC normalizes the R-URI host to the same presentity. */
	{
		char eschost[128];
		int escport = 0;
		sofia_publish_server_hostport(eschost, sizeof(eschost), &escport);
		if (escport > 0) {
			snprintf(pub->target, sizeof(pub->target), "sip:%s@%s:%d", exten, domain, escport);
		} else {
			snprintf(pub->target, sizeof(pub->target), "sip:%s@%s", exten, domain);
		}
		/* Same defect class as the INVITE/REGISTER/SUBSCRIBE R-URI: a bare sip:exten@host:port makes
		 * sofia-sip default to UDP, so a tls/tcp/ws/wss ESC was reached over UDP. Append ;transport=
		 * for [general] publish_transport (no-op for udp/empty, so existing configs stay byte-identical). */
		sofia_uri_append_transport(pub->target, sizeof(pub->target),
			sofia_cfg.publish_transport[0] ? sofia_cfg.publish_transport : "udp");
	}
	pub->nh = nua_handle(sofia_nua, SOFIA_PUBLICATION_HMAGIC,
		NUTAG_URL(pub->target),
		SIPTAG_TO_STR(pub->entity),
		SIPTAG_FROM_STR(pub->entity),
		TAG_END());
	if (!pub->nh) {
		ao2_ref(pub, -1);
		return;
	}
	if (!ao2_link(publications, pub)) {	/* container +1 */
		ast_log(LOG_WARNING, "Sofia PUBLISH: ao2_link failed for %s\n", pub->key);
		nua_handle_destroy(pub->nh);
		pub->nh = NULL;
		ao2_ref(pub, -1);
		return;
	}

	ao2_ref(pub, +1);		/* +1 for the extension-state registration (destroy_cb drops it) */
	pub->stateid = ast_extension_state_add_destroy(pub->context, pub->exten,
		sofia_publication_state_cb, sofia_publication_state_destroy_cb, pub);
	if (pub->stateid < 0) {
		/* No state watcher -> the publication can never update; do NOT publish a half-wired pub. */
		ast_log(LOG_WARNING, "Sofia PUBLISH: ast_extension_state_add_destroy failed for %s — not published\n",
			pub->key);
		ao2_ref(pub, -1);		/* undo the registration ref we pre-took */
		sofia_publication_teardown(pub);
		ao2_ref(pub, -1);		/* drop the local alloc ref */
		return;
	}

	/* Spread the initial PUBLISH across [0, min(Expires, 60))s so a large fleet does not thunder-herd. */
	sofia_publication_schedule(pub, 0, (pub->expires < 60 ? pub->expires : 60) ?: 1);

	if (sofia_debug) {
		ast_verbose("Sofia PUBLISH: scheduled %s (%s) -> %s\n",
			pub->entity, pub->key, sofia_cfg.publish_server);
	}
	ao2_ref(pub, -1);		/* drop our local alloc ref (container + registration hold theirs) */
}

/* Create publications for a publish=yes peer - one per regexten extension (ext1&ext2@ctx&...);
 * the peer name is used only when regexten is empty. Per-token @context overrides subscribecontext. */
static void sofia_publication_create_for_peer(struct sofia_peer *peer, int create)
{
	char multi[256], domain[128];
	char *stringp, *tok;

	if (!publications || !peer || !peer->publish || ast_strlen_zero(sofia_cfg.publish_server)) {
		return;
	}
	if (ast_strlen_zero(peer->subscribecontext)) {
		ast_log(LOG_WARNING, "Sofia PUBLISH: peer '%s' has publish=yes but no subscribecontext — skipped\n",
			peer->name);
		return;
	}
	if (!ast_strlen_zero(sofia_cfg.publish_domain)) {
		ast_copy_string(domain, sofia_cfg.publish_domain, sizeof(domain));
	} else {
		int dport = 0;
		sofia_publish_server_hostport(domain, sizeof(domain), &dport);	/* default = publish_server host */
	}
	if (ast_strlen_zero(domain)) {
		ast_log(LOG_WARNING, "Sofia PUBLISH: cannot derive a presentity domain for peer '%s' "
			"(set publish_domain, or put a host in publish_server) — skipped\n", peer->name);
		return;
	}

	/* What to publish: explicit publish_exten overrides; else the regexten hint(s); else the peer name.
	 * Same ext1&ext2@ctx&... grammar either way. publish_exten lets the operator publish a different
	 * presentity than the dialplan regexten (which also CREATES the hint). */
	ast_copy_string(multi, S_OR(peer->publish_exten, S_OR(peer->regexten, peer->name)), sizeof(multi));
	stringp = multi;
	while ((tok = strsep(&stringp, "&"))) {
		char *ctx = strchr(tok, '@');
		const char *context;

		if (ctx) {
			*ctx++ = '\0';			/* split ext@context */
			if (ast_strlen_zero(ctx)) {
				ast_log(LOG_WARNING, "Sofia PUBLISH: peer '%s' regexten token '%s@' has an empty "
					"context — skipped\n", peer->name, tok);
				continue;
			}
			context = ctx;
		} else {
			context = peer->subscribecontext;
		}
		if (ast_strlen_zero(tok)) {
			continue;			/* skip empty token */
		}
		sofia_publication_create_one(peer, tok, context, domain, create);
	}
}

/* Detach + destroy one publication (sofia_thread). The Expires:0 unpublish is BEST-EFFORT: the handle
 * is destroyed right after queueing it (and at shutdown this runs after su_root_run() returns), so it
 * may not reach the wire - acceptable, the ESC expires the soft state by its TTL regardless. */
static void sofia_publication_teardown(struct sofia_publication *pub)
{
	if (!pub || pub->terminated) {
		return;
	}
	pub->terminated = 1;
	if (pub->stateid >= 0) {
		ast_extension_state_del(pub->stateid, sofia_publication_state_cb);	/* fires destroy_cb */
		pub->stateid = -1;
	}
	if (pub->nh) {
		if (!ast_strlen_zero(pub->etag)) {
			nua_method(pub->nh, NUTAG_METHOD("PUBLISH"),
				NUTAG_DIALOG(0),
				SIPTAG_EVENT_STR(sofia_publication_event(pub->format)),
				SIPTAG_IF_MATCH_STR(pub->etag), SIPTAG_EXPIRES_STR("0"), TAG_END());
		}
		nua_handle_destroy(pub->nh);
		pub->nh = NULL;
	}
	ao2_unlink(publications, pub);
}

/* Periodic scheduler tick (sofia_thread su_timer): PUBLISH each due, not-in-flight publication,
 * capped per tick. The single funnel for initial spread, refresh, state-change and retry. */
#define SOFIA_PUBLISH_SWEEP_CAP 200	/* max PUBLISHes emitted per ~1s tick (drains a 5-10k fleet smoothly) */
static void sofia_publication_sweep(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg)
{
	struct ao2_iterator it;
	struct sofia_publication *pub;
	time_t now = time(NULL);
	int sent = 0;

	if (!publications) {
		return;
	}
	/* Each due, not-in-flight pub is published here, capped per tick. */
	it = ao2_iterator_init(publications, 0);
	while ((pub = ao2_iterator_next(&it))) {
		if (!pub->terminated && !pub->in_flight && pub->next_send != 0 && pub->next_send <= now
			&& sent < SOFIA_PUBLISH_SWEEP_CAP) {
			sofia_publication_send(pub, 0);
			sent++;
		}
		ao2_ref(pub, -1);
	}
	ao2_iterator_destroy(&it);
}

/* Reconcile the publication set with the just-applied config on `sip reload` (sofia_thread, which owns
 * publications, so teardown is UAF-safe). config_changed = publish_server/domain/expires/transport/format
 * differs from before the reload (the target/entity/TTL/R-URI-transport formula changed for every pub). */
void sofia_publications_reconcile(int config_changed)
{
	struct ao2_iterator it, pit;
	struct sofia_publication *pub;
	struct sofia_peer *peer;

	if (!publications) {
		return;
	}

	/* publish_server removed or ESC/domain/TTL changed -> tear the whole set down, then (unless the
	 * feature is now off) rebuild from publish=yes peers. */
	if (config_changed || ast_strlen_zero(sofia_cfg.publish_server)) {
		it = ao2_iterator_init(publications, 0);
		while ((pub = ao2_iterator_next(&it))) {
			sofia_publication_teardown(pub);	/* best-effort Expires:0 + handle destroy */
			ao2_ref(pub, -1);
		}
		ao2_iterator_destroy(&it);
		if (ast_strlen_zero(sofia_cfg.publish_server)) {
			return;				/* feature off now — nothing to recreate */
		}
		pit = ao2_iterator_init(peers, 0);
		while ((peer = ao2_iterator_next(&pit))) {
			if (peer->publish) {
				sofia_publication_create_for_peer(peer, 1);
			}
			ao2_ref(peer, -1);
		}
		ao2_iterator_destroy(&pit);
		return;
	}

	/* Incremental - THREE passes so a stale same-entity pub never blocks its replacement:
	 * (1) mark all + UNMARK every pub a publish=yes peer still maps to; (2) SWEEP the still-marked stale
	 * pubs; (3) CREATE the missing ones - by now the stale ones are gone, so entity-dedup cannot block. */
	it = ao2_iterator_init(publications, 0);
	while ((pub = ao2_iterator_next(&it))) {
		pub->_reload_marked = 1;
		ao2_ref(pub, -1);
	}
	ao2_iterator_destroy(&it);

	pit = ao2_iterator_init(peers, 0);		/* pass 1: unmark survivors (create=0) */
	while ((peer = ao2_iterator_next(&pit))) {
		if (peer->publish) {
			sofia_publication_create_for_peer(peer, 0);
		}
		ao2_ref(peer, -1);
	}
	ao2_iterator_destroy(&pit);

	it = ao2_iterator_init(publications, 0);	/* pass 2: sweep stale */
	while ((pub = ao2_iterator_next(&it))) {
		if (pub->_reload_marked && !pub->terminated) {
			sofia_publication_teardown(pub);
		}
		ao2_ref(pub, -1);
	}
	ao2_iterator_destroy(&it);

	pit = ao2_iterator_init(peers, 0);		/* pass 3: create missing (create=1) */
	while ((peer = ao2_iterator_next(&pit))) {
		if (peer->publish) {
			sofia_publication_create_for_peer(peer, 1);
		}
		ao2_ref(peer, -1);
	}
	ao2_iterator_destroy(&pit);
}

/* `sip show publications` snapshot request. The CLI thread dispatches a builder onto sofia_thread (the
 * single owner of the pub set) and waits on this cond; ao2 protects object lifetime but NOT coherent
 * reads of etag/next_send/in_flight/last_status, so those are only ever read on sofia_thread. */
struct sofia_pubsnapshot_req {
	ast_mutex_t mutex;
	ast_cond_t cond;
	int done;
	struct ast_str *out;	/* formatted output, built on sofia_thread; ref-protected (survives a CLI timeout) */
};

static void sofia_pubsnapshot_req_destructor(void *obj)
{
	struct sofia_pubsnapshot_req *req = obj;

	ast_mutex_destroy(&req->mutex);
	ast_cond_destroy(&req->cond);
	ast_free(req->out);
}
/* Format a pub next-send time for the CLI table (in-flight / - / due / Ns). */
static const char *sofia_pub_nextsend_str(struct sofia_publication *pub, time_t now, char *buf, size_t len)
{
	if (pub->in_flight) {
		ast_copy_string(buf, "in-flight", len);
	} else if (pub->next_send == 0) {
		ast_copy_string(buf, "-", len);
	} else if (pub->next_send <= now) {
		ast_copy_string(buf, "due", len);
	} else {
		snprintf(buf, len, "%lds", (long)(pub->next_send - now));
	}
	return buf;
}

/* sofia_thread: build the publications table into req->out, then signal the waiting CLI thread. */
static void sofia_pubsnapshot_build(void *data)
{
	struct sofia_pubsnapshot_req *req = data;
	struct ao2_iterator it;
	struct sofia_publication *pub;
	time_t now = time(NULL);
	int count = 0;

	/* LastState = what we last PUBLISHed; Current = the live hint state now (is the publish stale?). */
	ast_str_set(&req->out, 0, "%-16.16s  %-26.26s  %-11.11s  %-11.11s  %-4s  %-7s  %-9s  %-6s  %s\n",
		"Peer", "Presentity", "LastState", "Current", "ETag", "Expires", "NextSend", "Last", "Target");
	if (publications) {
		it = ao2_iterator_init(publications, 0);
		while ((pub = ao2_iterator_next(&it))) {
			char ns[16], peername[32], laststatus[12], *bar;
			int cur = ast_extension_state(NULL, pub->context, pub->exten);

			ast_copy_string(peername, pub->key, sizeof(peername));	/* peer = key up to first '|' */
			if ((bar = strchr(peername, '|'))) {
				*bar = '\0';
			}
			if (pub->last_status) {
				snprintf(laststatus, sizeof(laststatus), "%d", pub->last_status);
			} else {
				ast_copy_string(laststatus, "-", sizeof(laststatus));	/* not yet published */
			}
			ast_str_append(&req->out, 0, "%-16.16s  %-26.26s  %-11.11s  %-11.11s  %-4s  %-7d  %-9s  %-6s  %.40s\n",
				peername, pub->entity,
				pub->last_status ? ast_extension_state2str(pub->laststate) : "-",	/* last published */
				ast_extension_state2str(cur),					/* current hint state */
				ast_strlen_zero(pub->etag) ? "no" : "yes", pub->expires,
				sofia_pub_nextsend_str(pub, now, ns, sizeof(ns)), laststatus, pub->target);
			count++;
			ao2_ref(pub, -1);
		}
		ao2_iterator_destroy(&it);
	}
	if (count == 0) {
		ast_str_append(&req->out, 0, "%s\n", ast_strlen_zero(sofia_cfg.publish_server)
			? "(outbound PUBLISH is off — publish_server is not set)" : "(no publications)");
	} else {
		ast_str_append(&req->out, 0, "%d publication%s\n", count, count == 1 ? "" : "s");
	}

	ast_mutex_lock(&req->mutex);
	req->done = 1;
	ast_cond_signal(&req->cond);
	ast_mutex_unlock(&req->mutex);
	ao2_ref(req, -1);	/* drop the builder's ref */
}
/* CLI `sip show publications` - dispatches the snapshot builder to sofia_thread and prints it. */
char *sofia_cli_show_publications(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct sofia_pubsnapshot_req *req;
	struct timeval now;
	struct timespec ts;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show publications";
		e->usage =
			"Usage: sip show publications\n"
			"       List the outbound PUBLISH presentities this server maintains on a central\n"
			"       presence server (one per publish=yes peer hint), showing the last published\n"
			"       state and the current hint state, whether an ETag is held, the refresh\n"
			"       interval, time to the next send, and the last result.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}
	if (a->argc != 3) {
		return CLI_SHOWUSAGE;
	}
	if (!(req = ao2_alloc(sizeof(*req), sofia_pubsnapshot_req_destructor))) {
		return CLI_FAILURE;
	}
	ast_mutex_init(&req->mutex);
	ast_cond_init(&req->cond, NULL);
	req->done = 0;
	if (!(req->out = ast_str_create(512))) {
		ao2_ref(req, -1);
		return CLI_FAILURE;
	}

	ao2_ref(req, +1);	/* builder's ref (dropped in sofia_pubsnapshot_build) */
	if (sofia_dispatch_to_root_thread(sofia_pubsnapshot_build, req) < 0) {
		ao2_ref(req, -1);	/* undo the builder ref — it will never run */
		ao2_ref(req, -1);	/* drop the CLI ref */
		ast_cli(a->fd, "Sofia: unable to dispatch the publications snapshot (sofia thread unavailable)\n");
		return CLI_FAILURE;
	}

	now = ast_tvnow();		/* bounded 2s wait so a stuck sofia_thread cannot hang the CLI */
	ts.tv_sec = now.tv_sec + 2;
	ts.tv_nsec = now.tv_usec * 1000;
	ast_mutex_lock(&req->mutex);
	while (!req->done) {
		if (ast_cond_timedwait(&req->cond, &req->mutex, &ts) == ETIMEDOUT) {
			break;
		}
	}
	if (req->done) {
		ast_cli(a->fd, "%s", ast_str_buffer(req->out));
	} else {
		ast_cli(a->fd, "Sofia: publications snapshot timed out (sofia thread busy)\n");
	}
	ast_mutex_unlock(&req->mutex);
	ao2_ref(req, -1);	/* drop the CLI ref (builder still holds one on timeout) */
	return CLI_SUCCESS;
}


/* ---- lifecycle (called from chan_sofia.c) — hand-written to preserve the original behavior ---- */
/* Allocate the publications container. Returns 0 on success. */
int sofia_publications_init(void)
{
	publications = ao2_container_alloc(MAX_PUBLICATION_BUCKETS, publication_hash_fn, publication_cmp_fn);
	return publications ? 0 : -1;
}
/* Release the publications container. */
void sofia_publications_destroy(void)
{
	if (publications) {
		ao2_ref(publications, -1);
		publications = NULL;
	}
}
/* Create publications for all publish=yes peers and start the refresh sweep timer (sofia_thread). */
void sofia_publications_start(void)
{
	struct ao2_iterator pit;
	struct sofia_peer *ppeer;

	if (ast_strlen_zero(sofia_cfg.publish_server) || !publications) {
		return;
	}
	pit = ao2_iterator_init(peers, 0);
	while ((ppeer = ao2_iterator_next(&pit))) {
		if (ppeer->publish) {
			sofia_publication_create_for_peer(ppeer, 1);
		}
		ao2_ref(ppeer, -1);
	}
	ao2_iterator_destroy(&pit);

	publication_refresh_timer = su_timer_create(su_root_task(sofia_root), SOFIA_PUBLISH_SWEEP_MS);
	if (publication_refresh_timer) {
		su_timer_set_for_ever(publication_refresh_timer, sofia_publication_sweep, NULL);
	} else {
		ast_log(LOG_WARNING, "Sofia PUBLISH: sweep timer create failed - publications will not "
			"be sent or refreshed\n");
	}
}
/* Stop the sweep timer and tear down every publication (sofia_thread). Each teardown best-effort sends
 * an Expires:0 unpublish (sofia_publication_teardown), but note the KNOWN, BOUNDED, RFC-COMPLIANT limit
 * (3-way reviewed; operator chose "document, not engineer around it"): on `systemctl stop` chan_sofia's
 * unload_module returns -1 (no runtime unload), so this teardown path does NOT run before SIGKILL; and
 * on a load-failure path nua_shutdown() has already set nua_shutdown_started=1, so nua_signal() rejects
 * the Expires:0 nua_method (silently dropped). Either way the ESC clears the stale state on its own when
 * the soft-state TTL lapses (RFC 3903 §3: PUBLISH is soft-state; §4.5 Expires:0 is for IMMEDIATE removal,
 * not mandated on EPA shutdown). Worst-case staleness at the ESC = publish_expires (default 3600s) after
 * chan_sofia disappears — tolerable for federation; for wallboards set a low publish_expires. */
void sofia_publications_stop(void)
{
	if (publication_refresh_timer) {
		su_timer_destroy(publication_refresh_timer);
		publication_refresh_timer = NULL;
	}
	if (publications) {
		struct ao2_iterator pit = ao2_iterator_init(publications, 0);
		struct sofia_publication *pub;
		while ((pub = ao2_iterator_next(&pit))) {
			sofia_publication_teardown(pub);
			ao2_ref(pub, -1);
		}
		ao2_iterator_destroy(&pit);
	}
}
