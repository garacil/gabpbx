/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

/*! \file sofia_presence.c
 * \brief chan_sofia presence/BLF SUBSCRIBE-NOTIFY engine, split from chan_sofia.c.
 */

#include "gabpbx.h"
#include "gabpbx/astobj2.h"
#include "gabpbx/lock.h"
#include "gabpbx/utils.h"
#include "gabpbx/strings.h"
#include "gabpbx/logger.h"
#include "gabpbx/channel.h"
#include "gabpbx/manager.h"
#include "gabpbx/pbx.h"

#include <sofia-sip/nua.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/su_tag.h>
#include <sofia-sip/sip_tag.h>
#include <sofia-sip/nua_tag.h>

#include "include/chan_sofia_internal.h"
#include "include/sofia_presence.h"

/* Presence/BLF inbound SUBSCRIBE -> NOTIFY engine.
 *  Threading (doctrine): all nua_* and presence_subs / sub->* mutation runs on
 *  sofia_thread. sofia_presence_state_cb fires on the device_state taskprocessor and
 *  only snapshots {state}+ref then marshals to sofia_thread (mirrors mwi_event_cb).
 *  A subscription-scoped AMI event (SofiaPresenceState) is emitted per NOTIFY. */

#define MAX_PRESENCE_SUB_BUCKETS 1009		/* prime; one entry per active watcher dialog */
#define SOFIA_PRESENCE_SWEEP_MS 5000		/* expiry-sweep timer interval (ms) */
#define SOFIA_PRESENCE_EXPIRY_GRACE 5		/* seconds past expires_at before a stale sub is swept */


/* One active watcher subscription. ao2-managed, mutated only on sofia_thread. Keyed
 * by the LOGICAL triple (watcher peer, watched exten, context) — NOT by nh — so a
 * re-SUBSCRIBE on a fresh dialog REPLACES the prior sub instead of leaking a watcher. */

struct ao2_container *presence_subs;	/* keyed by subkey; created in load_module */
struct ao2_container *sofia_presence_container(void) { return presence_subs; }
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

void presence_sub_destructor(void *obj)
{
	/* Nothing to free (fields inline); nh is destroyed on sofia_thread in
	 * sofia_presence_teardown — this destructor may run on any thread, so no nua_*. */
	(void) obj;
}

/* forward decls (mutual recursion: state_cb -> dispatch -> teardown -> state_cb fn-ptr) */
int sofia_presence_state_cb(char *context, char *exten,
		enum ast_extension_states state, void *data);
void sofia_presence_teardown(struct sofia_presence_sub *sub, int send_terminated);

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

const char *sofia_presence_mime(enum sofia_sub_format f)
{
	switch (f) {
	case SOFIA_SUB_DIALOG_INFO: return "application/dialog-info+xml";
	case SOFIA_SUB_PIDF:        return "application/pidf+xml";
	case SOFIA_SUB_XPIDF:       return "application/xpidf+xml";
	case SOFIA_SUB_CPIM_PIDF:   return "application/cpim-pidf+xml";
	}
	return "application/dialog-info+xml";
}

/* Field-based body builder — the SINGLE source of truth for the dialog-info / PIDF / XPIDF / CPIM
 * presence XML, shared by the presence NOTIFY (sofia_presence_build_body wrapper below) AND the
 * outbound PUBLISH (sofia_publish.c). exten + entity are XML-escaped here. Plus the "all hinted
 * devices unavailable => offline" override (chan_sip parity). */
void sofia_presence_build_body_ex(struct ast_str **buf, const char *exten, const char *context,
		const char *entity, uint32_t version, enum sofia_sub_format format, int state)
{
	const char *statestring, *pidfstate, *pidfnote;
	int local_state;
	char hint[AST_MAX_EXTENSION];
	char exten_esc[AST_MAX_EXTENSION * 6];		/* *6: ast_xml_escape worst-case (&quot;) expansion */
	char entity_esc[256 * 6];			/* entity is a URI (<=256); *6 worst-case escape */

	sofia_presence_state_map(state, &statestring, &pidfstate, &pidfnote, &local_state);

	/* If every hinted device is unregistered, override "open" to offline (chan_sip
	 * parity). Only runs when local_state is open — the override can never flip an
	 * in-use/closed state, so the global hint rdlock + device scan stays off that path. */
	if (local_state == 0 && ast_get_hint(hint, sizeof(hint), NULL, 0, NULL, context, exten)) {
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
			/* Redundant today (local_state==0 here implies state_map already set statestring
			 * "terminated" for NOT_INUSE/default) — kept explicit so dialog-info stays "terminated"
			 * on all-offline even if the state_map table changes. */
			statestring = "terminated";
			pidfstate = "away";
			pidfnote = "Not online";
		}
	}

	ast_xml_escape(exten, exten_esc, sizeof(exten_esc));
	/* entity comes from the remote To header — escape before it enters XML. */
	ast_xml_escape(entity, entity_esc, sizeof(entity_esc));

	switch (format) {
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
			version, entity_esc);
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

/* NOTIFY body wrapper — output byte-identical to before (delegates to the shared builder). */
static void sofia_presence_build_body(struct ast_str **buf, const struct sofia_presence_sub *sub, int state)
{
	sofia_presence_build_body_ex(buf, sub->exten, sub->context, sub->entity, sub->version,
		sub->format, state);
}

/* Emit one NOTIFY for sub at the given state, plus the detailed AMI event.
 * Runs on sofia_thread. terminate=1 sets Subscription-State: terminated (final
 * NOTIFY); otherwise sofia-sip auto-fills active;expires per the notifier. */
void sofia_presence_emit_notify(struct sofia_presence_sub *sub, int state, int terminate)
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

	/* Subscription-State (mandatory, RFC 6665 §8.2.1) — composed explicitly because
	 * sofia-sip does not auto-add it for this idiom. NUTAG_SUBSTATE keeps the
	 * library's subscription-usage state machine (expiry timer) in sync. */
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
			/* Route NOTIFY to the NAT-learned source; no-op for non-NAT peers. */
			TAG_IF(sub->nat_proxy[0], NUTAG_PROXY(sub->nat_proxy)),
			TAG_END());
	}

	ast_free(body);

	/* Subscription-scoped AMI event (no chan_sip equivalent). */
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
void sofia_presence_teardown(struct sofia_presence_sub *sub, int send_terminated)
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
		nua_handle_bind(sub->nh, NULL);		/* defensive: presence subs are never hmagic-bound */
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
int sofia_presence_state_cb(char *context, char *exten,
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
void sofia_presence_sub_destroy_cb(int id, void *data)
{
	struct sofia_presence_sub *sub = data;
	if (sub) {
		ao2_ref(sub, -1);
	}
}

/* Correlate a notifier handle -> its subscription by iterating the container
 * (never deref hmagic as a sub). Returns a +1-reffed sub, or NULL. */
struct sofia_presence_sub *sofia_presence_find_by_nh(nua_handle_t *nh)
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
int sofia_substate_terminated(tagi_t tags[])
{
	int substate = nua_substate_active;
	if (tags) {
		tl_gets(tags, NUTAG_SUBSTATE_REF(substate), TAG_END());
	}
	return substate == nua_substate_terminated;
}

/* Periodic expiry sweep on sofia_thread (su_timer): sofia-sip does NOT auto-expire
 * nua_respond()-accepted subscriptions, so we tear down stale watchers ourselves
 * (chan_sip sip_scheddestroy parity). Collect-then-teardown — never mutate the
 * container mid-iteration. */
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
			expired[n++] = sub;	/* keep the iterator's +1 ref for teardown */
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

int sofia_presence_init(void)
{
	presence_subs = ao2_container_alloc(MAX_PRESENCE_SUB_BUCKETS, presence_sub_hash_fn, presence_sub_cmp_fn);
	ao2_container_register("sofia/presence", presence_subs);
	return presence_subs ? 0 : -1;
}

void sofia_presence_destroy(void)
{
	if (presence_subs) {
		ao2_ref(presence_subs, -1);
		presence_subs = NULL;
	}
}

void sofia_presence_start(void)
{
	presence_expiry_timer = su_timer_create(su_root_task(sofia_root), SOFIA_PRESENCE_SWEEP_MS);
	if (presence_expiry_timer) {
		su_timer_set_for_ever(presence_expiry_timer, sofia_presence_expiry_sweep, NULL);
	} else {
		ast_log(LOG_WARNING, "Sofia presence: expiry sweep timer create failed - stale "
			"subscriptions will only clear on explicit unsubscribe\n");
	}
}

void sofia_presence_stop(void)
{
	if (presence_expiry_timer) {
		su_timer_destroy(presence_expiry_timer);
		presence_expiry_timer = NULL;
	}
}
