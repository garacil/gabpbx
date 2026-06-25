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
#include "gabpbx/pbx.h"		/* enum ast_extension_states */
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

struct sofia_pvt;  /* full definition below */

/* Cross-module helpers defined in chan_sofia.c, used by the split-out modules. */
void sofia_get_source_addr(sip_t const *sip, struct ast_sockaddr *addr);
int sofia_dispatch_to_root_thread(void (*callback)(void *), void *data);
int sofia_format_auth_creds(msg_auth_t const *challenge, const char *user, const char *secret, char *buf, size_t len);
void sofia_split_hostport_from_uri(const char *hostport, char *host, size_t hostlen, int *port);
void sofia_presence_state_map(int state, const char **statestring, const char **pidfstate, const char **pidfnote, int *local_state);

/* Globals defined in chan_sofia.c, shared with the split modules. */
#define SOFIA_CHANNEL_TYPE "SIP"
extern struct ao2_container *peers;
extern nua_t *sofia_nua;
extern su_root_t *sofia_root;
extern int sofia_debug;

/* The Sofia channel tech (chan_sofia.c). The WebRTC DataChannel relay (sofia_datachannel.c)
 * compares a bridged channel's ->tech against this to confirm the far leg is a Sofia channel. */
extern struct ast_channel_tech sofia_tech;

/*! \brief Resolve the bridged far leg of \a op, returning a +1-reffed ast_channel (or NULL).
 * Defined in chan_sofia.c; three UAF-safe methods (_bridge / BRIDGEPEER / linkedid walk). Reused
 * by the DataChannel relay's far-leg pairing (sofia_dc_get_bridged_dc). Caller must ast_channel_unref. */
struct ast_channel *sofia_find_bridged_channel(struct sofia_pvt *op);

/*! \brief DataChannel far-leg pairing (the load-bearing cross-leg primitive). Resolve the bridged
 * sofia leg of \a self_pvt and return its DataChannel object (\a struct sofia_datachannel *) +1-reffed
 * (an opaque void* — sofia_datachannel.c knows the type), with NO channel/pvt lock held on return.
 *
 * Returns NULL when there is no bridged sofia leg, the far leg has no DC, on contention (trylock
 * failed — NEVER blocks, the ABBA defense), or on a self-loop. Defined in chan_sofia.c so the whole
 * channel-walk + far-pvt resolution runs where sofia_pvt internals, sofia_tech, and the canonical
 * lock order (channel -> pvt -> peer) are all in scope.
 *
 * Locking contract (channel.h:2318-2327): the far channel is resolved with the
 * SELF channel LOCKED (as ast_bridged_channel() requires outside the owning thread), the far channel is
 * +1-reffed, then self is unlocked; the far channel is ast_channel_trylock'd (never blocked) before its
 * ->tech / ->tech_pvt are read; far_pvt->lock is taken before reading + ao2_ref'ing far_pvt->dc; then
 * all locks/refs are released. The returned dc carries a +1 ref the caller must ao2_ref(-1).
 *
 * \param self_dc the caller's own DataChannel object (for the self != far identity check), or NULL. */
void *sofia_dc_pair_bridged(struct sofia_pvt *self_pvt, void *self_dc);

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
	SESSION_TIMERS_REFUSE    = 3, /* disables OUR origination only —
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
	char path[1024];           /* Path (RFC 3327) the device registered through, as a ready "<uri;lr>,..." Route value pre-loaded on requests we send to this contact. Empty = none. */
};

extern char sofia_sipnotify_sentinel;

#define SOFIA_T38_ABORT_TIMEOUT_MS  5000

struct ast_sched_thread;
extern struct ast_sched_thread *sofia_sched;
int sofia_should_use_externaddr(const struct ast_sockaddr *peer_addr);
void sofia_change_t38_state(struct sofia_pvt *pvt, int new_state);
int sofia_t38_abort(const void *data);
int sofia_interpret_t38_parameters(struct sofia_pvt *pvt, const struct ast_control_t38_parameters *parameters);
int sofia_parse_sdp(struct sofia_pvt *pvt, sip_t const *sip);

/*!
 * \brief A5: provision the local DTLS-SRTP + ICE-lite state for an OUTBOUND WebRTC
 *        OFFER on pvt->rtp, BEFORE sofia_generate_sdp builds the first SDP.
 *
 * Clones the A4 answerer provisioning (sofia_sdp.c WebRTC commit) but with NO
 * received-offer inputs: dtls_cfg.default_setup = ACTPASS (offerer advertises
 * actpass, RFC 5763 §5), ICE role CONTROLLED (lite), ice_lite advertised. The
 * local fingerprint + ufrag/pwd are self-generated by set_configuration / the ICE
 * engine and read back by sofia_generate_sdp via get_fingerprint/get_ufrag/
 * get_password. On success sets pvt->is_webrtc + pvt->webrtc_offerer + seeds
 * webrtc_mid="0"/webrtc_bundle/webrtc_tls_id so the emitter produces a complete
 * WebRTC offer. Does NOT call set_setup() (no remote role yet — keeps get_setup()
 * == ACTPASS so a=setup:actpass is emitted). DOES call ice->start() to arm the STUN
 * responder BEFORE the offer leaves the wire (early-STUN fix; safe with no remote creds,
 * authenticated by our local ufrag/pwd set at ast_rtp_new). v1c also provisions pvt->vrtp
 * (the video offer transport) when the capability has VP8/H264.
 *
 * \retval 0 success (pvt is now a provisioned WebRTC offerer)
 * \retval -1 failure (no dtls/ice/sched, or set_configuration failed) — caller
 *         must fail the call closed (never downgrade a webrtc=yes leg to RTP/AVP).
 */
int sofia_webrtc_provision_offer(struct sofia_pvt *pvt);
char *sofia_generate_sdp(struct sofia_pvt *pvt, char *buf, size_t len);
int sofia_sdp_extract_hold(sip_t const *sip, su_home_t *home);

struct sofia_peer *sofia_find_peer(const char *name);
struct sofia_peer *sofia_find_peer_cached(const char *name);	/* cache-only: no realtime fallback */
/* Normalize peer/[general] outboundproxy into a "sip:HOST[:PORT];lr" Route; buf empty if none.
 * Caller MUST hold peer->lock. Shared by REGISTER + the outbound MWI SUBSCRIBE (sofia_subscribe.c). */
void sofia_format_outboundproxy(struct sofia_peer *peer, char *buf, size_t len);
/* Remove the per-token PRIORITY_HINT extensions for a regexten spec (ext1[@ctx]&ext2...). Splits like
 * the hint creator so multi-token hints are fully reclaimed; registrar matches the creator. */
void sofia_remove_peer_hints(const char *regexten, const char *subscribecontext, const char *registrar);
/* GRUU (RFC 5627/5626), sofia_gruu.c: advertise +sip.instance + consume the registrar's pub/temp-gruu. */
void sofia_build_instance_feature(const struct sofia_peer *peer, char *buf, size_t len, int with_reg_id);
void sofia_outbound_consume(struct sofia_peer *peer, sip_t const *sip, int keepalive_ms);	/* RFC 5626 REGISTER-2xx inspect */
void sofia_gruu_consume(struct sofia_peer *peer, sip_t const *sip);
void sofia_service_route_store(struct sofia_peer *peer, sip_t const *sip);	/* Service-Route RFC 3608, sofia_route.c */
int sofia_route_serialize(sip_route_t const *list, char *buf, size_t len);	/* Path/Service-Route hop list -> Route value; 0 ok, -1 overflow */
void sofia_peer_clear_contact_paths(struct sofia_peer *peer);	/* blank RFC 3327 Path on all contacts (path=no) */
int sofia_reason_build(int hangupcause, char *buf, size_t len);	/* Q.850 Reason RFC 3326, sofia_reason.c */
int sofia_reason_parse_cause(sip_reason_t const *reason);
int sofia_gruu_dialog_contact(const struct sofia_peer *peer, char *buf, size_t len);	/* Phase 2b: GRUU as the dialog Contact */
void sofia_resolve_peer_target(struct sofia_peer *peer, const char *user,
		char *out_url, size_t out_len);
struct sofia_contact *sofia_peer_first_contact(struct sofia_peer *peer);
const char *sofia_uri_format_host(const char *host, char *out_buf, size_t out_len);
void sofia_uri_append_transport(char *url, size_t len, const char *transport);
const char *sofia_transport_name(int transport);
void sofia_qualify_peer(struct sofia_peer *peer);
#define SOFIA_SIPNOTIFY_HMAGIC ((nua_hmagic_t *)&sofia_sipnotify_sentinel)

/*! \brief Outbound MWI SUBSCRIBE (a watcher), in sofia_subscribe.c. The sofia_mwisub object +
 * the SOFIA_MWISUB_HMAGIC sentinel are private to that .c. ALL nua_* run on sofia_thread. */
int sofia_subscribe_init(void);			/* alloc the container (load_module) */
void sofia_subscribe_stop(void);		/* tear down every watcher's handle (Sofia thread, before nua_destroy) */
void sofia_subscribe_destroy(void);		/* drop the container only (after the Sofia thread has stopped) */
void sofia_subscribe_start(void);		/* startup sweep: start a watcher per mwi_subscribe= static-host peer (Sofia thread) */
void sofia_subscribe_reconcile(void);		/* sip reload: add/remove watchers to match the new config (Sofia thread) */
void sofia_subscribe_on_registered(struct sofia_peer *peer);	/* outbound REGISTER 200 -> start the peer's watcher */
int sofia_subscribe_on_subscribe_response(nua_handle_t *nh, sip_t const *sip, int status);	/* nua_r_subscribe; 1 = consumed */
int sofia_subscribe_on_notify(nua_handle_t *nh, nua_t *nua, sip_t const *sip);	/* nua_i_notify; 1 = consumed (200-OK'd) */
void sofia_subscribe_on_peer_gone(const char *peername);	/* peer removed/pruned -> tear down its watcher (Sofia thread) */
/* Generic outbound SUBSCRIBE (RFC 6665) watcher — sofia_eventsub.c (parallel to the MWI watcher above). */
int sofia_eventsub_init(void);
void sofia_eventsub_stop(void);
void sofia_eventsub_destroy(void);
void sofia_eventsub_start(void);
void sofia_eventsub_reconcile(void);
void sofia_eventsub_on_registered(struct sofia_peer *peer);
int sofia_eventsub_on_subscribe_response(nua_handle_t *nh, sip_t const *sip, int status);	/* 1 = consumed */
int sofia_eventsub_on_notify(nua_handle_t *nh, nua_t *nua, sip_t const *sip);	/* 1 = consumed (200-OK'd) */
void sofia_eventsub_on_peer_gone(const char *peername);

struct sipqualifypeer_data {
	struct sofia_peer *peer;	/* +1 ref TRANSFERRED to callback (caller doesn't drop) */
	int clear_pending;		/* 1 = timer dispatch owns peer->qualify_pending (callback clears it); 0 = AMI manual qualify (leaves the timer gate alone) */
};
void sipqualifypeer_callback(void *data);
int sofia_qualify_peer_async(struct sofia_peer *peer);	/* manual qualify: consumes the peer ref; 0 ok, -1 fail */
struct ao2_container *sofia_dialogs_container(void);	/* accessor for the live-dialogs container (split modules) */

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
	/* Accumulated under peer->lock; consumed by sofia_emit_register_side_effects
	 * AFTER unlock (moves the AMI / devstate emissions out from under peer->lock).
	 * emit_unregister is mutually exclusive with the registered tail. */
	int emit_unregister;
	const char *unregister_cause;	/* string literal: "Wildcard" / "Expired" / "CLI" (sip unregister) */
	char changed_uri[256];
	struct ast_sockaddr old_src;
	struct ast_sockaddr new_src;
	struct ast_sockaddr changed_old_src;
};

extern char sofia_debug_filter[64];
int sofia_debug_match(const char *peer_name, const char *src_ip);
int sofia_reload_request_sync(char *errmsg, size_t errmsglen, int timeout_ms);
void sofia_peer_drain_mwi(struct sofia_peer *peer);
void sofia_emit_register_side_effects(struct sofia_peer *peer, sip_t const *sip, const struct sofia_register_update *update);

#define SOFIA_PRESENCE_DEFAULT_EXPIRY 3600	/* used when the SUBSCRIBE omits Expires */

enum sofia_sub_format {
	SOFIA_SUB_DIALOG_INFO = 0,	/* application/dialog-info+xml (BLF) */
	SOFIA_SUB_PIDF,			/* application/pidf+xml */
	SOFIA_SUB_XPIDF,		/* application/xpidf+xml (Polycom/MSN) */
	SOFIA_SUB_CPIM_PIDF,		/* application/cpim-pidf+xml */
};

struct sofia_presence_sub {
	char subkey[200];			/* "peername|exten|context" — container key */
	nua_handle_t *nh;			/* subscription dialog handle (NOT bound as hmagic;
						 * correlated via sofia_presence_find_by_nh) */
	char exten[AST_MAX_EXTENSION];		/* watched extension (To user) */
	char context[AST_MAX_CONTEXT];		/* hint lookup context */
	char entity[256];			/* watched resource URI: sip:exten@domain */
	char peername[80];			/* subscriber peer name (From user) for AMI */
	char watcher_addr[64];			/* subscriber source addr for AMI */
	char nat_proxy[128];			/* NUTAG_PROXY target for NAT watchers — routes NOTIFY to
						 * the public source not the private Contact (else 408s).
						 * Empty for non-NAT peers. */
	char event[16];				/* "dialog" or "presence" (NOTIFY Event hdr) */
	enum sofia_sub_format format;		/* negotiated body type */
	int stateid;				/* ast_extension_state_add_destroy id (-1 = none) */
	int laststate;				/* last AST_EXTENSION_* pushed */
	uint32_t version;			/* monotonic dialog-info version= counter */
	int expires;				/* granted subscription lifetime (seconds) */
	time_t expires_at;			/* absolute expiry, for Subscription-State expires= */
	int terminated;				/* set on sofia_thread at teardown (idempotency) */
};

extern struct ao2_container *presence_subs;
void presence_sub_destructor(void *obj);
void sofia_presence_emit_notify(struct sofia_presence_sub *sub, int state, int terminate);
void sofia_presence_teardown(struct sofia_presence_sub *sub, int send_terminated);
int sofia_presence_state_cb(char *context, char *exten, enum ast_extension_states state, void *data);
void sofia_presence_sub_destroy_cb(int id, void *data);
struct sofia_presence_sub *sofia_presence_find_by_nh(nua_handle_t *nh);
const char *sofia_presence_mime(enum sofia_sub_format f);
/* Shared presence/dialog-info body builder (one source of truth) used by the presence NOTIFY and the
 * outbound PUBLISH (sofia_publish.c). exten + entity are XML-escaped inside. */
void sofia_presence_build_body_ex(struct ast_str **buf, const char *exten, const char *context,
		const char *entity, uint32_t version, enum sofia_sub_format format, int state);
int sofia_substate_terminated(tagi_t tags[]);
int sofia_presence_init(void);
void sofia_presence_destroy(void);
void sofia_presence_start(void);
void sofia_presence_stop(void);

/* Per-peer reachability state (qualify). */
enum sofia_peer_status {
	PEER_UNREACHABLE = -1,
	PEER_UNKNOWN     = 0,
	PEER_REACHABLE   = 1,
	PEER_LAGGED      = 2,
};

/* Per-peer MWI mailbox node + list head (sip show peer walks the list). */
struct ast_event_sub;
struct sofia_mailbox {
	char mailbox[80];
	char context[80];
	struct ast_event_sub *event_sub;	/* AST_EVENT_MWI subscription per mailbox */
	AST_LIST_ENTRY(sofia_mailbox) list;
};
AST_LIST_HEAD_NOLOCK(sofia_mailbox_list, sofia_mailbox);

/* The peer/trunk object — the central chan_sofia data structure, shared with split modules. */
#define SOFIA_FORK_ID_LEN 40

/* Heavy call/dialog-media types embedded as pointers in struct sofia_pvt — forward-declared
 * (their full definitions live in chan_sofia.c / their owning subsystems). */
struct ast_dsp;
struct ast_rtp_instance;
struct ast_udptl;
struct sofia_fork;
struct sofia_srtp;

enum sofia_dialog_state {
	SOFIA_DIALOG_STATE_DOWN,
	SOFIA_DIALOG_STATE_TRYING,
	SOFIA_DIALOG_STATE_RINGING,
	SOFIA_DIALOG_STATE_UP,
};

/* The per-call/dialog object — the central media/signaling state. Shared so the SDP, T.38, register
 * and CLI(show channels) modules can reference it. */
struct sofia_pvt {
	AST_DECLARE_STRING_FIELDS(
		AST_STRING_FIELD(callid);
		AST_STRING_FIELD(exten);
		AST_STRING_FIELD(context);
		AST_STRING_FIELD(subscribecontext);	/* per-call cache of peer->subscribecontext for in-dialog SUBSCRIBE routing */
		AST_STRING_FIELD(accountcode);	/* per-call cache of peer->accountcode for CDR billing-tag — NOT pvt->username (auth-identity, wrong semantic) */
		AST_STRING_FIELD(username);
		AST_STRING_FIELD(peername);
		AST_STRING_FIELD(peersecret);
		AST_STRING_FIELD(fromdomain);
		AST_STRING_FIELD(fromuser);
		AST_STRING_FIELD(uri);
		AST_STRING_FIELD(ruri);
		AST_STRING_FIELD(cid_num);   /* inbound caller-id num; from sip_from, overwritten by PAI/RPID when peer->trustrpid */
		AST_STRING_FIELD(cid_name);  /* inbound caller-id name; same chain as cid_num */
	);
	enum sofia_dialog_state state;
	int dtmfmode;
	int alreadygone;
	int owner_busy;
	struct ast_channel *owner;
	struct sofia_peer *peer;
	nua_handle_t *nh;
	su_home_t *home;
	int refer_pending;            /* 1 = an outbound REFER is in flight on this dialog (Transfer() is blocked waiting for AST_CONTROL_TRANSFER) */
	su_timer_t *refer_timer;      /* outbound-REFER timeout; fires AST_TRANSFER_FAILED so Transfer() never blocks forever (sofia_thread-only) */
	int cseq;
	struct ast_rtp_instance *rtp;
	struct ast_rtp_instance *vrtp;
	format_t capability;
	struct ast_codec_pref prefs;
	int lastinvite;
	ast_mutex_t lock;
	/* Fork fields — NULL/single for the normal (non-forked) call path */
	struct sofia_fork *fork;         /* shared fork object, NULL = no forking */
	int is_fork_master;              /* 1 = this pvt owns the ast_channel in a fork */
	int is_fork_child;               /* 1 = this pvt is a fork child leg */
	char fork_branch_id[SOFIA_FORK_ID_LEN];
	struct sofia_contact *active_contact;  /* contact this call is on (holds ao2 ref) */
	struct ast_sockaddr redirip;     /* directmedia: peer's RTP target; zero = relay through PBX */
	int reinvite_pending;            /* directmedia re-INVITE in flight; gates response handler */
	int outbound_invite_auth_attempts; /* 401/407 answered on this outbound INVITE; bounded vs bad-creds loop */
	unsigned long sess_id;           /* SDP o= session-id, set ONCE per dialog (RFC 4566 §5.2 / RFC 3264 §8: constant across offers/answers) */
	unsigned long sess_version;      /* SDP o= session-version, bumped per generated SDP */
	int hold_state;                  /* 1 = peer holding us (a=sendonly/inactive) */
	struct sofia_srtp *srtp;         /* audio SDES-SRTP context (NULL = plain RTP); freed in destructor */
	struct sofia_srtp *vsrtp;        /* video SDES-SRTP context; freed in destructor */
	struct ast_variable *initreq_headers; /* inbound INVITE headers for ${SIP_HEADER()}; freed in destructor */
	struct ast_sockaddr last_src_addr; /* INVITE transport-source for ${SIPCHANINFO(peerip|recvip)} */
	struct ast_sockaddr ourip; /* kernel-routed source IP for outbound From/Contact + SDP c= (sofia_resolve_ourip) */
	int callingpres; /* AST_PRES_* mask; inherits peer->callingpres */
	int outgoing; /* 1=outbound dial, 0=inbound INVITE; drives RPID ;party=calling/called */
	struct sofia_history *history;	/* SIP history ring (sofia_history.c); lazily allocated, freed in destructor */
	int do_history;			/* per-dialog snapshot of sofia_record_history at creation (chan_sip parity) */
	int history_retained;		/* idempotency net: history already snapshotted into the retained ring */
	int call_inc_done; /* this pvt incremented peer->inUse — idempotency guard for DEC sites */
	int ring_inc_done; /* this pvt incremented peer->inRinging — idempotency guard */
	struct ast_dsp *dsp; /* set by sofia_enable_dsp_detect for inband/auto DTMF or fax-CNG; freed in destructor */

	/* T.38 fax UDPTL state. udptl: per-dialog session, lazily allocated on first
	 * T.38 reINVITE, destroyed in the destructor. t38_state: 4-state machine.
	 * t38id: sofia_t38_abort sched ID (-1 = none); without it a peer that never
	 * acks the 200 OK leaves us stuck in PEER_REINVITE. t38_max_ifp: far-end
	 * advertised — LOAD-BEARING (peer max_ifp==0 forces T38_DISABLED). t38_our/
	 * their_parms: zero-init, filled during negotiation. */
	struct ast_udptl *udptl;
	int t38_state;
	int t38id;
	unsigned int t38_max_ifp;
	int t38_maxdatagram;
	int t38_ec_mode;
	int t38pt_usertpsource;
	struct ast_control_t38_parameters t38_our_parms;
	struct ast_control_t38_parameters t38_their_parms;
	/* RFC 4028 session-timer refresh tracking (sip show channels + AMI
	 * SessionTimerRefresh); populated at refresh-fire. zero = none yet. */
	int session_negotiated_expires; /* negotiated Session-Expires (s); 0 = no timer */
	time_t session_last_refresh_at; /* most recent refresh; 0 = never */
	int allowtransfer; /* per-call REFER policy; inherits peer->allowtransfer; gated at sofia_process_refer */
	/* Blind/attended-transfer BYE deferral (RFC 5589 §6.1): we must not race the
	 * transferer's UA BYE with our own nua_bye, or sofia-sip drops the pending
	 * terminal NOTIFY and the transfer never completes. When set, sofia_hangup
	 * skips its nua_bye; a sched timer (defer_bye_sched_id) BYEs after
	 * SOFIA_DEFER_BYE_TIMEOUT_MS for UAs that don't auto-BYE. Incoming BYE cancels it. */
	int defer_bye;
	int defer_bye_sched_id;
	/* A4 OQ1/M7: this leg negotiated WebRTC (DTLS-SRTP + ICE-lite + rtcp-mux). Set
	 * by sofia_parse_sdp ONLY after the DTLS/ICE commit fully succeeds; read by
	 * sofia_generate_sdp to emit the UDP/TLS/RTP/SAVPF profile + the a= block. */
	unsigned int is_webrtc:1;
	/* A5 OQ-A: this leg is the WebRTC OFFERER (gabpbx dialed a webrtc=yes peer and
	 * built the FIRST SDP as a DTLS-SRTP/ICE-lite OFFER). Provisioned at outbound
	 * call setup (sofia_call) with default_setup=ACTPASS + ICE-lite BEFORE the offer
	 * is generated, then is_webrtc is set so sofia_generate_sdp emits a WebRTC OFFER.
	 * Distinguishes the offerer from the A4 answerer at the answer-parse commit:
	 * when set, the browser's ANSWER applies remote fingerprint/setup/ufrag/pwd/
	 * candidates but DOES NOT re-run set_configuration (our cert + DTLS ctx were
	 * built for the offer and must not be rebuilt). 0 for the A4 answerer path and
	 * for every plain-SIP leg. */
	unsigned int webrtc_offerer:1;
	/* v1c: gabpbx OFFERED video over WebRTC (the video offerer). DISTINCT from webrtc_video_accepted (the
	 * answerer path) — they are mutually exclusive per call. sofia_generate_sdp emits a real m=video when
	 * webrtc_video_accepted OR (webrtc_video_offerer && !webrtc_video_answer_applied), NEVER both. Set in
	 * sofia_webrtc_provision_offer when the effective capability has VP8/H264 and pvt->vrtp already exists
	 * (sofia_rtp_init created it at chan_sofia.c:1421). */
	unsigned int webrtc_video_offerer:1;
	/* A5: remote DTLS/ICE from the browser ANSWER has been applied to the live
	 * engine (set-once; guards a re-INVITE/2nd 18x+200 from re-applying). */
	unsigned int webrtc_answer_applied:1;
	/* A4 interop (RFC 8829 §5.3.1): values echoed into the WebRTC answer SDP.
	 * webrtc_mid: offered audio a=mid token (default "0" if the offer omitted it),
	 *   emitted as m=audio a=mid + the mid inside session a=group:BUNDLE.
	 * webrtc_bundle: offer carried a session-level a=group:BUNDLE (RFC 8843) — gate
	 *   for emitting the answer's session-level a=group:BUNDLE.
	 * webrtc_tls_id: per-DTLS-association stable id, 16 random bytes as 32 hex chars
	 *   (RFC 8842 §5.2); generated ONCE at the WebRTC commit, reused on re-INVITE. */
	char webrtc_mid[64];
	unsigned int webrtc_bundle:1;
	char webrtc_tls_id[40];
	/* A6 multi-m / video over WebRTC (RFC 3264 §6 + RFC 8843): the WebRTC answer MUST carry one m=
	 * line per offered m= line (unaccepted ones reflected at port 0). Recorded at parse, emitted by
	 * sofia_generate_sdp. v1a accepts audio and port-0 reflects ALL non-audio sections (incl. video) so a
	 * browser audio+video+datachannel offer is not rejected for an m-line mismatch; v1b ACCEPTS video on a
	 * separate non-BUNDLE pvt->vrtp transport (its own DTLS/ICE), datachannel stays port-0. */
	char webrtc_video_mid[64];           /* offered m=video a=mid ("" = no video offered) */
	unsigned int webrtc_video_offered:1;
	unsigned int webrtc_video_accepted:1;    /* VP8/H264 intersect + own DTLS/ICE attrs + rtcp-mux + NOT bundle-only */
	/* v1b non-BUNDLE video transport (audit STEP 1): the m=video runs on pvt->vrtp with its OWN
	 * DTLS association + ICE, NOT bundled with the audio transport (RFC 8843 §7 separate-transport). */
	char webrtc_video_tls_id[40];                /* RFC 8842 a=tls-id for the VIDEO association (distinct from webrtc_tls_id) */
	unsigned int webrtc_video_answer_applied:1;  /* one-shot: vrtp DTLS/ICE already armed — do NOT re-arm on a re-INVITE */
	unsigned int webrtc_video_bundle_only:1;     /* offer's m=video carried a=bundle-only (RFC 8843 §7.3.2) → MUST keep video port-0 reflected, cannot move out */
	int webrtc_reject_m_count;
	int webrtc_accepted_video_idx;           /* reject_m index of the accepted video — STEP 6 emits it real, the emit skips ONLY this entry; every OTHER m=video is port-0 reflected (Review HIGH 1:1, RFC 3264 §6 count). -1 = none */
	unsigned int webrtc_reject_overflow:1;   /* >ARRAY_LEN(webrtc_reject_m) non-audio m= offered → emit fails closed (RFC 3264 §6: cannot drop m-lines) */
	struct sofia_webrtc_reject_m {
		char type_name[16];  /* offered m= media-type STRING (sofia m_type_name), echoed verbatim (RFC 3264 §6) */
		char proto[40];      /* m= transport proto-name (a port-0 reflect keeps it; RFC 3264) */
		char fmt[24];        /* first m= format token */
		char mid[64];        /* its a=mid (RFC 8843 — must appear in the answer too) */
	} webrtc_reject_m[6];
	/* Phase 2a WebRTC DataChannel (RFC 8831/8832) transport handle, NULL when this leg has no
	 * negotiated m=application. An opaque ao2 object owned by sofia_datachannel.c (the usrsctp
	 * AF_CONN association bundled on pvt->rtp's DTLS). A plain pointer — no #ifdef needed for the
	 * pointer itself; sofia_dc_attach/detach are no-ops without usrsctp. Wired in Phase 3 (SDP). */
	struct sofia_datachannel *dc;
	/* Phase 3 WebRTC DataChannel SDP negotiation (RFC 8841 m=application). Mirrors the webrtc_video_*
	 * fields: parsed at sofia_parse_sdp, emitted by sofia_generate_sdp. The m=application shares the
	 * AUDIO BUNDLE ICE+DTLS transport (NO new transport) — only the SCTP layer is per-m=application.
	 *   dc_offered:  the browser offered an m=application UDP/DTLS/SCTP webrtc-datachannel section.
	 *   dc_accepted: gabpbx accepted it (datachannel=yes AND webrtc AND HAVE_USRSCTP AND in BUNDLE AND
	 *                the audio WebRTC leg committed) → sofia_dc_attach ran, emit a REAL m=application;
	 *                0 → port-0 reflect it via webrtc_reject_m (exactly like a declined m-line).
	 *   dc_sctp_port: the offer's a=sctp-port (RFC 8841; browser default 5000). Passed to sofia_dc_attach.
	 *   dc_max_message_size: the offer's a=max-message-size (RFC 8841; browser default 262144). 0 = unset.
	 *   dc_mid: the offer's m=application a=mid, echoed in the answer + added to a=group:BUNDLE. */
	unsigned int dc_offered:1;
	unsigned int dc_accepted:1;
	uint16_t dc_sctp_port;
	unsigned int dc_max_message_size;
	char dc_mid[64];
	/* OFFER-side WebRTC DataChannel (we ORIGINATE the m=application to the far leg, e.g. the bridged
	 * callee). DISTINCT from dc_offered/dc_accepted, which are INBOUND-answer-only (a peer offered US a
	 * DC and we accepted). These two own the OUTBOUND offer:
	 *   dc_offerer:       sofia_webrtc_provision_offer emitted an m=application in OUR outbound offer
	 *                     (datachannel=yes peer + usrsctp); sofia_dc_attach already ran (usrsctp starts
	 *                     before the offer leaves). Gates the m=application EMIT + the BUNDLE token +
	 *                     the reject-loop skip alongside dc_accepted. Cleared if the far leg declines.
	 *   dc_answer_applied: the far leg's ANSWER accepted our offered DC (its m=application has a nonzero
	 *                     a=sctp-port AND our dc_mid is a token in its a=group:BUNDLE) → keep pvt->dc.
	 *                     One-shot guard so a re-INVITE/duplicate 2xx does not re-apply. */
	unsigned int dc_offerer:1;
	unsigned int dc_answer_applied:1;
};

struct sofia_peer {
	AST_DECLARE_STRING_FIELDS(
		AST_STRING_FIELD(name);
		AST_STRING_FIELD(secret);
		AST_STRING_FIELD(md5secret);    /* pre-hashed digest secret = MD5(user:realm:secret) as 32-hex string; used directly as a1_hash so config holds no cleartext password (chan_sip parity). Takes PRECEDENCE over peer->secret when both set; LOG_WARNING on dual-set. */
		AST_STRING_FIELD(context);
		AST_STRING_FIELD(host);
		AST_STRING_FIELD(defaultuser);
		AST_STRING_FIELD(fromuser);
		AST_STRING_FIELD(fromdomain);
		AST_STRING_FIELD(regexten);
		AST_STRING_FIELD(publish_exten);	/* outbound PUBLISH: explicit exten(s) to publish (ext1&ext2@ctx&...); overrides regexten/name as the publish source. Empty = use regexten/name. */
		AST_STRING_FIELD(pub_gruu);	/* GRUU Phase 2: public GRUU minted by the registrar for this peer's +sip.instance (RFC 5627 §5.2), learned from the REGISTER 200 Contact. Opaque URI. Empty = none/not-registered. */
		AST_STRING_FIELD(temp_gruu);	/* GRUU Phase 2: temporary GRUU (rotates per refresh). Opaque URI. Empty = none. */
		AST_STRING_FIELD(service_route);	/* Service-Route (RFC 3608) learned from the REGISTER 200 (service_route=yes), as a ready "<uri;lr>,..." Route value pre-loaded on outbound INVITEs to the registrar domain. Empty = none. */
		AST_STRING_FIELD(callbackextension);	/* when registering AS a client to an upstream provider, user-portion of our Contact URI telling upstream which local extension to call back; wired via NUTAG_M_USERNAME at the 3 nua_register sites. Empty = no callback (chan_sip parity). */
		AST_STRING_FIELD(subscribecontext);	/* SUBSCRIBE-method dispatch context override (chan_sip parity); inherits default_subscribecontext when empty. LIMITATION: per-peer dialplan dispatch not yet wired (MWI uses peer->mailboxes; unknown events auto-202). */
		AST_STRING_FIELD(accountcode);	/* CDR billing-tag propagated to channel->accountcode at sofia_new (chan_sip parity); truncated to AST_MAX_ACCOUNT_CODE=20 at CDR-write. Per-peer only (no [general] default). */
		AST_STRING_FIELD(disallowed_methods);	/* comma-separated SIP methods blocked from outbound Allow header (chan_sip parity); inherits sofia_cfg.disallowed_methods when empty. PARSE-COMPAT-ONLY: dynamic NUTAG_ALLOW generation deferred. */
		AST_STRING_FIELD(callerid);
		AST_STRING_FIELD(cid_name);   /* per-peer CID name (chan_sip parity); fallback at sofia_resolve_identity when channel connected.id.name is empty. */
		AST_STRING_FIELD(cid_num);    /* per-peer CID number (chan_sip parity); fallback at sofia_resolve_identity when channel connected.id.number is empty (dialplan CALLERID() overrides). */
		AST_STRING_FIELD(cid_tag);    /* per-peer CID tag (chan_sip parity); overrides sofia-sip auto-generated From-tag at sofia_build_from when set. */
		AST_STRING_FIELD(forceddiversion);  /* per-trunk DID forced into the outbound Diversion header (RFC 5806) on a forwarded call, so the carrier gets a trunk-owned number it can validate. Empty = disabled (legacy data-driven Diversion preserved). Read by sofia_add_diversion under peer->lock. */
		AST_STRING_FIELD(message_context);  /* per-peer override of [general] message_context for inbound out-of-dialog MESSAGE; empty inherits */
		AST_STRING_FIELD(mwi_subscribe);    /* outbound MWI watcher: <localmailbox>[@context]; chan_sofia SUBSCRIBEs this peer (trunk) for Event: message-summary and injects the received MWI into the LOCAL ast_event MWI cache. Empty = off. DISTINCT from the subscribemwi inbound bool. */
		AST_STRING_FIELD(subscribe_event);  /* generic outbound SUBSCRIBE (RFC 6665): <event>[;<accept-mime>][;<expires>]; chan_sofia SUBSCRIBEs this peer (trunk) for an arbitrary event package and surfaces each NOTIFY as the AMI event SofiaEventNotify. Empty = off. Separate from mwi_subscribe (sofia_eventsub.c). */
		AST_STRING_FIELD(nonce);
		AST_STRING_FIELD(outboundproxy);	/* per-peer outbound proxy override; empty = inherit sofia_cfg.outboundproxy or no Route */
		AST_STRING_FIELD(srtpcipher);		/* comma-separated SRTP suite preference; empty = inherit sofia_cfg.default_srtpcipher or sdp_crypto.c default AES_CM_128_HMAC_SHA1_80 */
		AST_STRING_FIELD(mohinterpret);		/* MOH class played when remote puts us on hold; empty = inherit default_mohinterpret or system default */
		AST_STRING_FIELD(mohsuggest);		/* MOH class suggested to the bridged channel when this peer puts us on hold (inbound dir wired; outbound Alert-Info deferred) */
		AST_STRING_FIELD(language);		/* audio language locale propagated to ast_channel.language at sofia_new (chan_sip parity); empty = inherit default_language or core default */
		AST_STRING_FIELD(parkinglot);	/* parking-lot routing propagated to ast_channel.parkinglot at sofia_new (chan_sip parity); empty = inherit default_parkinglot (chan_sip default is "default") */
		AST_STRING_FIELD(lockuseragent_prefixes);	/* comma-separated User-Agent prefix allowlist: with lockuseragent=yes and this non-empty, REGISTER passes if its User-Agent starts (case-insensitive) with ANY listed prefix, bypassing first-REGISTER auto-capture. Empty = strict capture-on-first-REGISTER. For multi-device-per-peer + vendor-family allowlists. */
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
	int encryption;                 /* SDES-SRTP per-peer toggle (0/1); default off; encryption=yes enables */
	int webrtc;                     /* WebRTC per-peer toggle (0/1): DTLS-SRTP + ICE-lite + rtcp-mux; default off; webrtc=yes enables — A4 */
	int datachannel;                /* WebRTC DataChannel per-peer toggle (0/1): accept the offered m=application (RFC 8841 SCTP) on the BUNDLE'd audio DTLS; default off; requires webrtc=yes + a usrsctp build (Phase 3). With it off the m=application is port-0 reflected exactly as today. */
	int callingpres;                /* AST_PRES_* mask; per-peer default presentation (chan_sip parity); default AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED (=0) */
	int sendrpid;                   /* 0=none / 1=PAI / 2=RPID (chan_sip SIP_SENDRPID parity) */
	int trustrpid;                  /* 0/1; trust inbound PAI/RPID (chan_sip SIP_TRUSTRPID parity) */
	int call_limit;                 /* max simultaneous calls; 0=unlimited (chan_sip parity) */
	int inUse;                      /* runtime cached count of active calls; NOT realtime-persisted (chan_sip parity) */
	int inRinging;                  /* runtime cached count of ringing/proceeding calls */
	int onHold;                     /* runtime cached count of on-hold calls; ast_atomic_fetchadd_int at hold transition */
	int busy_level;                 /* soft-cap; outbound returns BUSY (486) when inUse >= busy_level (chan_sip parity) */
	/* session timers (RFC 4028): 4-key per-peer config (chan_sip parity); sofia-sip handles wire mechanics via NUTAG_*. Inherits sofia_cfg.default_session_* at sofia_peer_alloc. */
	int session_timers;             /* SESSION_TIMERS_* mode enum (OFF/ACCEPT/ORIGINATE/REFUSE) (chan_sip parity) */
	int session_expires;            /* Session-Expires seconds (chan_sip parity); default sofia_cfg.default_session_expires=1800 */
	int session_minse;              /* Min-SE seconds (chan_sip parity); default 90 (RFC 4028 §3 floor) */
	int session_refresher;          /* SESSION_REFRESHER_AUTO/UAC/UAS preference (chan_sip parity); mapped to sofia-sip nua_*_refresher at NUTAG emit */
	int allowtransfer;              /* TRANSFER_OPENFORALL/CLOSED REFER gate (chan_sip parity); inherits default_allowtransfer; gated at sofia_process_refer entry */
	int allowsubscribe;             /* 0=block / 1=allow SUBSCRIBE (chan_sip parity); gated at sofia_process_mwi_subscribe (per-peer) + sofia_process_subscribe entry (global). Default inherited from default_allowsubscribe (1). */
	int publish;                    /* outbound PUBLISH (RFC 3903): when 1 and [general] publish_server is set, chan_sofia PUBLISHes this peer's hint (regexten/subscribecontext) dialog-info state to the central server. Default 0. */
	int gruu;                       /* GRUU/RFC 5626: when 1, the outbound REGISTER advertises a stable +sip.instance (urn:uuid from EID+name) so a GRUU-capable registrar can mint a pub-gruu. Default 0 (opt-in). */
	int use_gruu_contact;           /* GRUU Phase 2b (RFC 5627 §4.4): when 1 (default) AND gruu=yes AND a pub-gruu was learned, use it as the outbound dialog Contact. Interop kill-switch: set no to keep advertising/learning but not use it as Contact. Default 1. */
	int use_service_route;          /* Service-Route (RFC 3608): when 1, ingest the registrar's Service-Route from the REGISTER 200 and pre-load it on outbound INVITEs to that domain. Default 0 (opt-in; applying it diverts outbound routing). */
	int path_support;               /* Path (RFC 3327): when 1, as the registrar for this dynamic peer, accept + store the Path from its REGISTER and pre-load it as a Route on requests to its contacts. Default 0 (opt-in; accepting Path is a trust decision, RFC 3327 §7). */
	int rel100;                     /* 100rel/PRACK (RFC 3262): when 1, send NON-183 provisionals (180 Ringing etc.) to this peer RELIABLY (Require: 100rel + RSeq, await PRACK) via NUTAG_EARLY_MEDIA on the inbound handle. The 183 early-media is already reliable when the caller advertises 100rel. Default 0 (opt-in; some UACs mishandle a reliable 180). */
	int sip_outbound;               /* RFC 5626 SIP Outbound (register=> trunks): when 1, the outbound REGISTER advertises Supported: outbound,path + carries a stable +sip.instance and reg-id=1 on the Contact, so the registrar/edge proxy maintains the client-initiated flow. Manual signals (no native outbound engine). Default 0 (opt-in). */
	int sip_outbound_active;        /* RFC 5626 runtime: set when the REGISTER 2xx confirmed outbound (Require: outbound). Informational (shown in sip show peer); not config. */
	int flow_timer;                 /* RFC 5626 Flow-Timer (seconds) learned from the REGISTER 2xx (§4.4); 0 = none advertised. Informational. */
	int reg_handle_dirty;           /* set when a reload toggled gruu/sip_outbound: the surviving REGISTER handle carries merged Supported/M_FEATURES prefs that can only be dropped by rebuilding peer->nh, done on the next refresh. */
	/* Buggy-CISCO MWI fix (chan_sip parity): when set, the Voice-Message: NOTIFY
	 * body line OMITS the trailing " (0/0)" suffix (some Cisco stacks reject it).
	 * Per-peer only (no [general] default); default 0 = standard RFC 3842. */
	int buggymwi;
	/* security: locks peer registration to the single User-Agent captured at first
	 * successful REGISTER; later REGISTERs with a different UA are 401-rejected +
	 * an AMI LockUserAgentReject event fires (anti UA-spoofing). chan_sip parity
	 * (extended to config-file too). Default 0 (FALSE). */
	int lockuseragent;
	/* lockuseragent anchor: User-Agent captured at first successful REGISTER while
	 * lockuseragent=1 (display UA lives separately on sofia_contact). Empty = no
	 * lock captured yet (first registration populates it). */
	char locked_user_agent[64];
	int usereqphone;                /* add RFC 3966 ;user=phone to outbound URIs when the username is digit-only (chan_sip parity); inherits default_usereqphone; used in Request-URI + From-URI builders. */
	int maxforwards;                /* RFC 3261 §20.22 Max-Forwards initial value (1-255; chan_sip parity); inherits default_max_forwards; emitted via SIPTAG_MAX_FORWARDS_STR at outbound nua_* sites. */
	ast_group_t callgroup;          /* call group bitmask (groups 0-63) */
	ast_group_t pickupgroup;        /* pickup group bitmask — call groups this peer can pick up */
	struct ast_variable *chanvars;  /* linked list of per-peer setvar= and header= entries. setvar applied to the channel via pbx_builtin_setvar_helper at sofia_new; header= stored as __SIPADDHEADERpreNN channel-vars that sofia_build_addheader_str injects as SIPTAG_HEADER_STR (chan_sip parity). Iterated directly off the peer (pvt holds an ao2-ref for the channel's lifetime). Freed in sofia_peer_destructor via ast_variables_destroy. */
	struct ast_ha *ha;              /* per-peer permit/deny ACL chain (NULL = no ACL) */
	struct ast_ha *contactha;       /* SEPARATE ACL applied to the Contact-header IP at REGISTER (distinct from peer->ha source-IP ACL): blocks an allowed source registering a disallowed Contact-IP (chan_sip parity). Inherits sofia_cfg.contact_ha. */
	struct ast_dnsmgr_entry *dnsmgr; /* async DNS-tracking handle for peers with host=hostname; NULL when host is an IP-literal or dnsmgr disabled. Callback updates peer->src_addr on DNS change. Lifecycle (UAF-safe): ao2_bump(peer) at registration for a callback-safe ref; release-then-unref BEFORE refcount hits 0 at reload-sweep; defensive ast_dnsmgr_release in the destructor. */
	struct ast_ha *directmediaha;   /* cross-leg direct-media ACL (chan_sip parity): at sofia_get_rtp_peer, the BRIDGE PARTNER's directmediaha is tested against THIS leg's RTP remote addr — "peer X directmediadeny=Y/24" refuses direct media when the other leg's endpoint is in Y/24. Per-peer only. */
	unsigned int last_nc;
	char last_cnonce[128];          /* last accepted qop cnonce (RFC 2617 §3.2.2). The nc-replay check rejects only a byte-identical (nonce,nc,cnonce) resend, so a periodic REGISTER refresh restarting at nc=1 with a FRESH cnonce is NOT mistaken for a replay (without this, the reused per-peer nonce + carried last_nc made nearly every refresh's first authed attempt a false replay → spurious 401 stale=true). Cleared on nonce regen. */
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
	int qualify_pending;             /* 1 = a qualify dispatch onto sofia_thread is in flight; gates the aux-thread timer from piling up duplicates */
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
	/* registration-route transport snapshot (paired with src_addr). Set under
	 * peer->lock from the registering Contact's ;transport= so requests to a
	 * TCP/TLS-registered phone don't silently default to UDP. "udp"/empty -> no
	 * param emitted (UDP fleet byte-identical); ws/wss stored but not yet in RURIs. */
	char reg_transport[8];
	/* SDP video bandwidth ceiling emitted as media-level b=CT:%d (RFC 4566 §5.8),
	 * video media only (chan_sip parity). Default 384 kbps from default_maxcallbitrate;
	 * set maxcallbitrate=0 to suppress the b=CT line. */
	int maxcallbitrate;
	/* CDR AMA-flags (DOCUMENTATION/BILLING/OMIT) propagated to ast_channel.amaflags
	 * at sofia_new, only when non-zero (else channel-core default; chan_sip parity).
	 * Default 0. Per-peer only. */
	int amaflags;
	/* MWI subscription-model gate (chan_sip parity). 0 = no (default) = UNSOLICITED MWI: push a
	 * message-summary NOTIFY to the registered contact on REGISTER + on mailbox change, no SUBSCRIBE
	 * needed. 1 = yes = SUBSCRIBE-only (MWI only on an active inbound MWI subscription). Default 0. */
	int subscribemwi;
	/* flag to treat every inbound SDP as new, ignoring the o-line session-version
	 * (chan_sip parity). PARSE-COMPAT-ONLY: chan_sofia has no session-version tracking
	 * so it ALWAYS behaves as ignoresdpversion=yes — =yes matches, =no is a known
	 * LIMITATION (noted in sample.conf). Default 0. */
	int ignoresdpversion;
	/* flag to honor 3xx Moved-Temporarily redirects via ast_channel.call_forward
	 * (chan_sip parity). PARSE-COMPAT-ONLY: chan_sofia has no nua_r_redirect handler
	 * yet, so 3xx is not followed regardless of this flag (LIMITATION in sample.conf).
	 * Default 0; inherits default_promiscredir. */
	int promiscredir;
	/* flag for SDP codec-ptime auto-detection (chan_sip parity). PARSE-COMPAT-ONLY:
	 * the sofia_parse_sdp autoframing gate is not wired yet, so this has no behavioral
	 * effect today (LIMITATION in sample.conf). Default 0; inherits default_autoframing. */
	int autoframing;
	/* fax CNG-tone detection + T.38 reINVITE trigger mode (none/cng/t38/cng+t38;
	 * chan_sip two-bit encoding). WIRED: CNG enables DSP fax-tone detect; T38
	 * redirects to the fax extension on a peer T.38 reINVITE. */
	int faxdetect_mode;
	/* T.38 fax UDPTL config (chan_sip parity; opt-in via
	 * t38pt_udptl=yes|fec|redundancy|none[,maxdatagram=N]):
	 *   t38pt_udptl: 0=disabled / 1=enabled (t38_ec_mode selects EC mode)
	 *   t38_ec_mode: SOFIA_T38_EC_NONE/_FEC/_REDUNDANCY (parsed from t38pt_udptl=)
	 *   t38_maxdatagram: per-peer FaxMaxDatagram (-1 = inherit default; 0+ = override)
	 *   t38pt_usertpsource: 1 = symmetric-RTP UDPTL destination override.
	 * Inherited at sofia_pvt allocation by sofia_initialize_udptl. */
	int t38pt_udptl;
	int t38_ec_mode;
	int t38_maxdatagram;
	int t38pt_usertpsource;
	/* RFC 3261 §17.1.1.2 INVITE transaction timeout, Timer B = 64*T1 (caps INVITE
	 * retry, then 408). Wired globally via NTATAG_SIP_T1X64 at nua_create; per-peer
	 * dynamic override deferred. NOTE: chan_sip's [general] parser has a bug that
	 * silently ignores valid timerb values — chan_sofia's parser assigns them
	 * correctly. Default 32000ms; inherits default_timer_b. */
	int timer_b;
	/* RFC 3261 §17.1.1.1 T1 retransmission interval (ms) — initial duration for
	 * retransmit timers A/E (UDP) and G (chan_sip parity). Wired globally via
	 * NTATAG_SIP_T1 at nua_create (per-peer dynamic override deferred). NOTE: this
	 * fixed a latent bug where t1min (100ms) was passed as T1, causing 5x
	 * over-aggressive retransmits; T1 must be default_timer_t1, not t1min.
	 * Default 500ms; inherits default_timer_t1. */
	int timer_t1;
	/* tri-state overlap-dial mode (RFC 3261 digit-by-digit dialing; chan_sip parity).
	 * SOFIA_OVERLAP_*: 0=NO (404 on partial match) / 1=YES (default; 484 Address
	 * Incomplete on partial match) / 2=DTMF (stored but falls through to standard
	 * handling — overlap better done via the Incomplete dialplan app). Gated at
	 * sofia_process_invite, sofia_indicate INCOMPLETE, and nua_r_invite 484.
	 * Default YES; inherits default_allowoverlap_mode. */
	int allowoverlap_mode;
	/* tri-state SDP early-media in-band audio control (chan_sip parity).
	 * SOFIA_PROG_INBAND_*: 0=NEVER (default; 180 only) / 1=NO (degrades to NEVER —
	 * no progress_sent tracking) / 2=YES (180 + force in-band audio). Use case:
	 * early-media IVR/announcement before 200 OK. Inherits default_progressinband. */
	int progressinband;
	/* narrow the SDP offer to the single most-preferred joint codec (bandwidth-
	 * constrained / codec-locked trunks; chan_sip parity). chan_sofia applies this
	 * to BOTH offer and response paths (chan_sip narrows response only). Default 0;
	 * inherits default_preferred_codec_only. */
	int preferred_codec_only;
	/* RTP no-traffic detection / dead-call cleanup / keepalive (3-key bundle;
	 * chan_sip parity). Applied via ast_rtp_instance_set_timeout/_hold_timeout/
	 * _keepalive at SDP-process. Default 0 (disabled); inherits default_*. */
	int rtptimeout;
	int rtpholdtimeout;
	int rtpkeepalive;
	/* fallback IP for host=dynamic peers before they register (chan_sip parity):
	 * outbound calls route here until src_addr is learned from a REGISTER. Default
	 * null; used at sofia_resolve_peer_target. */
	struct ast_sockaddr defaddr;
	struct ao2_container *contacts;
	/* MWI per-peer mailbox list (NOLOCK; peer->lock guards). */
	struct sofia_mailbox_list mailboxes;
	nua_handle_t *mwi_subscription_handle; /* NULL until first SUBSCRIBE */
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
	int tcp_keepalive_ms;     /* tcp_keepalive (cfg seconds, stored ms); 0=OFF. App-level CRLF keepalive (TPTAG_KEEPALIVE) holds NAT binding on idle connection-oriented transports. TCP-only (TLS/WS vtables ignore it). */
	int tcp_pingpong_ms;      /* tcp_pingpong (cfg seconds, stored ms); 0=OFF. TPTAG_PINGPONG — connection treated dead if no pong after a keepalive ping. Opt-in (aggressive value can tear down a slow-but-alive link). */
	int allowguest;
	int busy_on_active;
	int max_contacts;
	int encryption;                   /* SDES-SRTP general default (0=off, 1=on); soft-zeroed at load if res_srtp absent */
	int webrtc;                       /* WebRTC general default (0=off,1=on); per-peer webrtc= overrides */
	int datachannel;                  /* WebRTC DataChannel general default (0=off,1=on); per-peer datachannel= overrides. Requires webrtc=yes + a usrsctp build to take effect (Phase 3). */
	char default_srtpcipher[256];     /* srtpcipher: comma-separated cipher preference inherited by peers; empty = sdp_crypto.c default AES_CM_128_HMAC_SHA1_80 */
	int srtp_per_suite_keys;          /* 0 = shared-key (one master_key across all suites in a multi-cipher offer) / 1 = per-suite-fresh-key (independent random key per suite — forensic key separation). [general]-only; no chan_sip equivalent. */
	int force_invite_auth;            /* 0 = chan_sip parity (per-peer insecure=invite bypass active) / 1 = global lockdown: ALL inbound INVITEs require digest auth regardless of insecure=invite. [general]-only security override; logs NOTICE when overriding a peer. */
	int nonce_ttl_seconds;            /* Digest auth nonce TTL override; 0 = SOFIA_NONCE_TTL_SEC_DEFAULT (3600s) */
	int auth_algorithms;              /* SOFIA_AUTH_ALG_BOTH/MD5/SHA256: which digest algo(s) to OFFER in WWW-Authenticate. GLOBAL, no per-peer override. Verification accepts only what was offered (anti-downgrade). Code default BOTH; shipped sofia.conf sets md5. */
	/* session timers (RFC 4028): chan_sip-parity defaults inherited by peers; sofia-sip handles wire mechanics via NUTAG_SESSION_TIMER/MIN_SE/SESSION_REFRESHER. */
	int default_session_timers;       /* SESSION_TIMERS_OFF/ACCEPT/ORIGINATE/REFUSE; default=ACCEPT (honor inbound, no initiate) */
	int default_session_expires;      /* default Session-Expires seconds; chan_sip parity 1800s (RFC 4028 §4) */
	int default_session_minse;        /* default Min-SE seconds; chan_sip parity 90s (RFC 4028 §3 floor) */
	int default_session_refresher;    /* SESSION_REFRESHER_AUTO/UAC/UAS; default=AUTO (negotiation-decided) */
	/* RPID/PAI/Diversion identity-header defaults inherited by peers. */
	int default_callingpres;          /* AST_PRES_* mask; static-zero == AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED */
	int default_sendrpid;             /* 0=none / 1=PAI / 2=RPID */
	int default_trustrpid;            /* 0/1 */
	/* call-limit defaults inherited by peers. */
	int default_call_limit;           /* default cap for peers without explicit call-limit */
	int default_busy_level;           /* default busy_level for peers without explicit busylevel */
	int default_allowtransfer;        /* default REFER policy: TRANSFER_OPENFORALL/CLOSED; default OPENFORALL via static-zero */
	/* allowsubscribe: gates inbound SUBSCRIBE per-peer + global; both sites 403 "Forbidden (policy)". */
	int default_allowsubscribe;       /* [general] inheritance default; default 1 (TRUE) */
	int allowsubscribe;               /* DERIVED global ban-all flag; FALSE only when no peer allows */
	/* regexten: registration-coupled dialplan auto-extension mechanism. */
	char regcontext[AST_MAX_CONTEXT];  /* context for auto-added register extensions (MASTER SWITCH); empty = mechanism disabled */
	int regextenonqualify;             /* couple regexten add/remove to qualify state transitions; default 0 (FALSE) */
	/* default routing context for SUBSCRIBE dispatch, inherited by peers. EFFECT-PENDING: MWI handler uses peer->mailboxes, unknown events auto-202 (no dialplan dispatch yet). */
	char default_subscribecontext[AST_MAX_CONTEXT];
	char message_context[AST_MAX_CONTEXT];  /* [general] default context for out-of-dialog inbound MESSAGE -> dialplan; empty = SIP SIMPLE messaging OFF */
	/* registration TTL bounds ([general]-only); typo-tolerant Xexpiry/Xexpirey parse for chan_sip migration. */
	int min_expiry;     /* default 60s — under this rejects 423 Interval Too Brief + Min-Expires (RFC 3261 §10.2.8) */
	int max_expiry;     /* default 3600s — over this silently caps */
	int default_expiry; /* default 120s — fallback when peer omits expires + for peer->expiresecs */
	int default_usereqphone;    /* RFC 3966 telephone-uri ;user=phone for E.164 via PSTN gateways; default 0 */
	int default_max_forwards;   /* RFC 3261 §20.22 Max-Forwards initial value (0 → 483 Too Many Hops); emitted via SIPTAG_MAX_FORWARDS_STR */
	int t1min;                  /* RFC 3261 §17.1.1.2 minimum allowed Timer T1 (ms); default 100; floor used to validate default_timer_t1 (default_timer_t1 is what is emitted via NTATAG_SIP_T1) */
	/* [general] media-layer policy flags. */
	int relaxdtmf;              /* ast_dsp DSP_DIGITMODE_RELAXDTMF flag; default FALSE */
	int prematuremediafilter;   /* 183 Session Progress gate; default TRUE = filter ON = 183 SUPPRESSED. INVERTED chan_sip quirk: "prematuremedia=yes" → TRUE → suppressed. */
	/* outbound REGISTER application-level scheduled-retry (NOT sofia-sip NUTAG_RETRY_COUNT; via sofia_reg_thread sleep). */
	int register_timeout;  /* seconds between retry attempts; default 20s */
	int register_attempts; /* max scheduled-retry count; 0 = unlimited */
	int directrtpsetup;        /* PARSE-COMPAT-ONLY (early-RTP-bridge not wired); chan_sip itself defaults DISABLED */
	int alwaysauthreject;      /* 1 = unknown REGISTER / unknown-mailbox MWI SUBSCRIBE return 401 (bogus challenge) not 403/404 — anti-enumeration (RFC 3261 §22.4); default TRUE (chan_sip). Each 401 emits AMI AuthFailure (EVENT_FLAG_SYSTEM). */
	int compactheaders;        /* PARSE-COMPAT-ONLY: sofia-sip has no native compact-emit gate. Default 0 (chan_sip). */
	char disallowed_methods[128]; /* PARSE-COMPAT-ONLY string-storage; default empty (sofia-sip NUTAG_APPL_METHOD gates unknown methods natively) */
	struct ast_ha *contact_ha; /* contactpermit/contactdeny; inherited by peers via ast_duplicate_ha_list when peer omits the key */
	int srvlookup;
	int pedantic;
	char externaddr[128];
	/* NAT external-address parity fill. */
	char externhost[256];     /* DDNS hostname; resolved into externaddr at load + lazy-refreshed at sofia_resolve_ourip; empty = no DDNS, externaddr used as-is */
	time_t externexpire;      /* Lazy-refresh deadline; 0 = no DDNS / no refresh */
	int externrefresh;        /* DNS-refresh interval (seconds); default 10 */
	int externtcpport;        /* External TCP port for outbound headers; default 5060 (int for atoi simplicity) */
	int externtlsport;        /* External TLS port; default 5061 */
	char localnet[128];
	char media_address[128];  /* media_address (chan_sip parity): a global media-interface address advertised in the SDP c=/o= INSTEAD of the kernel-routed source. Advertise-only (RTP still binds bindaddr); wins over externaddr, but directmedia redirip still overrides. Empty = off. */
		struct ast_ha *localha;
	int udpport;
	/* T36: optional TLS / WS / WSS listeners */
	char tlsbindaddr[64];
	int  tlsbindport;        /* 0 = disabled; common: 5061 */
	char tlscertfile[256];   /* directory containing agent.pem (combined cert+key) */
	int  tlsverify;          /* verify the peer (server) cert chain on the TLS transport (default 0
	                          * = OFF, sofia-sip default; opt-in, requires a CA bundle). WSS builds
	                          * its own SSL_CTX and is NOT governed by this. */
	int  tlsverifyclient;    /* mutual TLS: verify the CLIENT cert on the INBOUND TLS listener
	                          * (TPTLS_VERIFY_SUBJECTS_IN, ORed with tlsverify's OUT into one policy).
	                          * Default 0 (opt-in; a client without a CA-trusted cert then fails the
	                          * handshake before SIP). WSS excluded (own SSL_CTX). */
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
	enum sofia_sub_format publish_format; /* outbound PUBLISH body: SOFIA_SUB_DIALOG_INFO (default) or SOFIA_SUB_PIDF; [general] publish_format=dialog-info|pidf */
	char wsbindaddr[64];
	int  wsbindport;         /* 0 = disabled; common: 5066 */
	char wssbindaddr[64];
	int  wssbindport;        /* 0 = disabled; common: 7443 */
	/* MWI message-summary defaults (RFC 3842). */
	char mwi_from[80];        /* From header used in MWI NOTIFY; empty -> peer->fromdomain or sofia_cfg.realm fallback */
	char notifymime[80];      /* Content-Type for MWI NOTIFY body; default "application/simple-message-summary" */
	char vmexten[80];         /* Voicemail user-part for Message-Account URI; default "asterisk" */
	int  mwi_expiry;          /* MWI subscription default expiry seconds; default 3600 (RFC 3842/6665). Dual-key parse: mwi_expiry / mwiexpiry / mwiexpirey. Used SERVER-side for outbound NOTIFY Expires. */
	/* outbound proxy default for outbound INVITE + REGISTER. Per-peer outboundproxy= overrides; empty = no Route header injection. */
	char outboundproxy[80];
	/* default MOH classes inherited by peers; char[MAX_MUSICCLASS=80]. */
	char default_mohinterpret[80];
	char default_mohsuggest[80];
	char default_language[MAX_LANGUAGE]; /* default language inherited by peers; empty = gabpbx-core default. MAX_LANGUAGE=40 (matches ast_channel.language). */
	char default_parkinglot[AST_MAX_CONTEXT]; /* default parkinglot inherited by peers; default "default" (chan_sip). Set empty to restore silent baseline. */
	int ignore_regexpire;      /* 1 = keep expired registrations in peer->contacts (preserve last-known contact across short trunk outages). Wired at sofia_expire_contacts_cb. Default 0. */
	int default_maxcallbitrate; /* video bandwidth ceiling inherited by peers; default 384 (negatives clamp back). Emits b=CT line (RFC 4566 §5.8) in video SDP only. */
	int match_auth_username;   /* 1 = match peer by Authorization digest username instead of From (anti-spoofing / multi-identity); default 0 */
	int legacy_useroption_parsing; /* PARSE-COMPAT-ONLY (sofia-sip has no post-parse URI semicolon-strip hook); default 0. chan_sofia URI parsing already RFC 3261-compliant. */
	int shrinkcallerid;        /* 1 = strip leading '+'/parens from CID phone numbers (ast_is_shrinkable_phonenumber); default 1 (chan_sip). Non-phone CIDs unaffected. */
	int notifyhold;            /* 1 = gate peer->onHold counter tracking on this flag; default 0 (chan_sip). AMI Hold remains unconditional. */
	int use_q850_reason;       /* Q.850 Reason header (RFC 3326): when 1, stamp/parse Reason: Q.850;cause=N on BYE/CANCEL. Default 0 (chan_sip parity, opt-in). */
	int notifyringing;         /* PARSE-COMPAT-ONLY (early-vs-confirmed presence gate; dialog-info NOTIFY infra deferred); default 1 (chan_sip) */
	int dynamic_exclude_static; /* 1 = append static-peer addrs to contact_ha as DENY so dynamic peers can't claim static names by Contact-IP spoofing. Default 0. */
	int autocreatepeer;        /* PARSE-COMPAT-ONLY: chan_sofia refuses to auto-create unknown peers (stronger via alwaysauthreject default). Default 0 (chan_sip). */
	int default_preferred_codec_only; /* codec-offer-list narrowing inherited by peers; default 0 (full list) */
	int default_ignoresdpversion; /* PARSE-COMPAT-ONLY (chan_sofia processes every SDP unconditionally); default 0 */
	int default_promiscredir;  /* PARSE-COMPAT-ONLY (no nua_r_redirect 3xx-honor handler); default 0 */
	int default_autoframing;   /* PARSE-COMPAT-ONLY (ptime auto-detect not wired); default 0 */
	int default_faxdetect_mode; /* fax CNG/T.38 detection mode inherited by peers; default NONE(0). Handles DSP CNG + T.38 reINVITE detect when set. */
	int default_t38_maxdatagram; /* T38FaxMaxDatagram override inherited by peers; sentinel -1 = use SOFIA_T38_MAXDATAGRAM_BUILTIN (200) */
	int default_timer_b;       /* RFC 3261 Timer B inherited by peers; default 32000ms (64*T1); via NTATAG_SIP_T1X64 at nua_create */
	int default_timer_t1;      /* RFC 3261 T1 retransmission interval (ms) inherited by peers; default 500ms; via NTATAG_SIP_T1 at nua_create */
	int default_allowoverlap_mode; /* tri-state overlap-dial mode inherited by peers; default YES (SOFIA_OVERLAP_YES=1). DTMF mode is fall-through (chan_sip design). */
	int default_progressinband; /* tri-state early-media in-band audio (SOFIA_PROG_INBAND_*) inherited by peers; default NEVER. NO degrades to NEVER (no SIP_PROGRESS_SENT tracking). */
	int subscribe_network_change_event; /* PARSE-COMPAT-ONLY (sofia-sip sres_resolver + dnsmgr absorb network-change rebinding); default 1 (chan_sip) */
	int rtsave_sysname;        /* 1 = include regserver=AST_SYSTEM_NAME in realtime writes (multi-server deployments). Restores canonical Asterisk behavior (active chan_sip fork dropped it). Default 0. */
	int peer_rtupdate;         /* 1 = propagate registration changes to realtime DB (ast_update_realtime); default 1. rtupdate=no skips ALL realtime writes (cached-realtime, avoids churn). */
	/* Phase 1 bounded REGISTER realtime-DB-write offload pool (kill-switch, default OFF). */
	int register_pool;          /* offload the realtime REGISTER DB writes to a bounded pool */
	int register_pool_workers;  /* lane count; 0 = auto = clamp(ncpu/2+1, 2, 16) */
	int rtcachefriends;        /* PARSE-COMPAT-ONLY: chan_sofia ao2 registry always caches all peers (matches rtcachefriends=YES); default 0. No destroy-after-lookup path. */
	/* rtautoclear: PARSE-COMPAT-ONLY two-piece (no peer-level auto-clear infra; peers persist until reload). Defaults: rtautoclear=120s, _enabled=0. */
	int rtautoclear;
	int rtautoclear_enabled;
	int domainsasrealm;        /* 1 = use From/To domain (if in domain_list) as auth realm in challenge, else sofia_cfg.realm. Default 0. Via sofia_get_realm_for_dialog. */
	int allow_external_domains; /* 0 + domain_list non-empty = reject 403 non-local Request-URI/Refer-To (anti domain-traversal); default 1 (PERMISSIVE). Auto-sets when domain_list empty. */
	int autodomain;            /* 1 = auto-add bindaddr/tls/ws/externaddr + FQDN to domain_list at load (via sofia_domain_list_add); default 0 */
	int matchexternaddrlocally; /* PARSE-COMPAT-ONLY (chan_sofia externaddr logic compares peer not our-IP; not wired); dual-key matchexternaddrlocally/matchexterniplocally; default 0 */
	/* RTP-timeout 3-key bundle defaults inherited by peers; default 0 = disabled (no enforcement). */
	int default_rtptimeout;
	int default_rtpholdtimeout;
	int default_rtpkeepalive;
	/* QoS markings (8-key) for SIP signaling + RTP audio/video/text; default 0 = no markings.
	 * tos_sip via TPTAG_TOS at nua_create; tos/cos audio+video via ast_rtp_instance_set_qos.
	 * cos_sip + tos/cos text = PARSE-COMPAT-ONLY (no TPTAG_COS / no text-RTP infra). */
	unsigned int tos_sip;
	unsigned int tos_audio;
	unsigned int tos_video;
	unsigned int tos_text;
	unsigned int cos_sip;
	unsigned int cos_audio;
	unsigned int cos_video;
	unsigned int cos_text;
	/* User-Agent header (outbound requests) + Server header (responses). Default = DEFAULT_USERAGENT + version;
	 * [general] useragent= overrides. Wired via SIPTAG_USER_AGENT_STR at nua_create (sofia emits on every request). */
	char useragent[AST_MAX_EXTENSION];
		int default_qualify;
		int default_qualifyfreq;
		int default_qualifytimeout;
		format_t capability;
		struct ast_codec_pref prefs;
};

extern struct sofia_config sofia_cfg;

#endif /* CHAN_SOFIA_INTERNAL_H */
