/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

/*! \file sofia_datachannel.c
 * \brief chan_sofia WebRTC DataChannel (RFC 8831/8832) usrsctp transport — DCEP relay.
 *
 * Verified against /usr/include/usrsctp.h and the relevant RFCs.
 *
 * Architecture:
 *   - One usrsctp AF_CONN socket per Sofia leg, bundled on the AUDIO DTLS (pvt->rtp). No new socket.
 *   - The transport rides the RTP-engine seam (include/gabpbx/rtp_engine.h):
 *       inbound:  ast_rtp_instance_set_dtls_appdata_cb -> RX cb fires UNDER ao2_lock(instance)
 *                 -> copy+ref+push to a taskprocessor -> usrsctp_conninput() OFF the instance lock.
 *       outbound: usrsctp GLOBAL output cb -> ast_rtp_instance_dtls_write_appdata(pvt->rtp, ...).
 *   - The usrsctp CONN token is the sofia_datachannel* itself: usrsctp_init's
 *     output cb signature derefs `addr` on every outbound packet, and sofia_datachannel is the
 *     ao2 object whose lifetime WE own (cleared on detach). pvt may be freed first → using pvt as
 *     the token would be a UAF.
 *
 * gabpbx is a MIDDLEBOX, not an endpoint. It terminates
 * TWO independent SCTP associations — one per bridged leg — each with its OWN sofia_datachannel,
 * its OWN DTLS role, its OWN even/odd stream parity. A browser's channel on leg A is re-originated
 * onto leg B with B's parity (so A:sid != B:sid in general): a per-dc stream table + a cross-leg
 * A:sid <-> B:sid mapping is therefore MANDATORY. We DCEP-respond (OPEN -> ACK) on the near leg,
 * proxy a matching OPEN on the far leg, and relay user messages (PPID 51/53/56/57) by sid mapping.
 *
 * CONCURRENCY (the crux) — lock order channel -> pvt -> instance -> peer:
 *   - sofia_dc_engine_rx runs while ao2_lock(instance) is HELD (res_rtp drain loop). It must take
 *     NO locks and call NO usrsctp; it ONLY malloc+memcpy+ao2_ref(dc,+1)+ast_taskprocessor_push.
 *   - sofia_dc_rx_task runs on the shared worker lane with NO instance lock and feeds
 *     usrsctp_conninput(). The synchronous usrsctp receive cb (sofia_dc_sctp_recv_cb) therefore
 *     runs OFF the instance lock, so the DCEP/relay there may safely touch pvt/peer/the far leg.
 *   - The far leg is reached ONLY via sofia_dc_get_bridged_dc(): trylock-the-far-channel (NEVER
 *     block — ABBA defense), ao2_ref the far dc, RELEASE all channel locks, THEN usrsctp_sendv off
 *     every channel lock (no inversion vs the output cb which takes only the instance lock). The
 *     SINGLE shared worker lane serializes A-recv vs B-recv — the load-bearing
 *     invariant of the no-deadlock proof (sharding would break it; see sofia_dc_get_bridged_dc).
 *   - sofia_dc_detach clears the engine cb FIRST (instance-lock barrier in
 *     ast_rtp_instance_set_dtls_appdata_cb) → no RX cb can fire after that returns → no use of the
 *     dc cb_data pointer after we drop the ref (anti-UAF). It then
 *     NULLs dc->pvt, drains the worker lane WHILE the socket is still open, and only THEN ABORT-closes
 *     the SCTP socket (SO_LINGER 0 → SCTP ABORT, no graceful drain) so no lingering usrsctp timer can
 *     fire the output cb against a freed pvt minutes after teardown (the confirmed teardown-UAF core).
 *
 * Scope: notifications (assoc up/down, stream reset, send-failed, shutdown) + the DCEP
 * responder (PPID 50 OPEN -> ACK) + OPEN-proxying onto the far leg + the bidirectional user-message
 * relay (PPID 51/53/56/57) with PR-SCTP policy per channel type. SDP parse/emit is implemented.
 */

#include "gabpbx.h"

#include "include/sofia_datachannel.h"

#ifdef HAVE_USRSCTP

#include "gabpbx/astobj2.h"
#include "gabpbx/channel.h"
#include "gabpbx/lock.h"
#include "gabpbx/logger.h"
#include "gabpbx/module.h"
#include "gabpbx/rtp_engine.h"
#include "gabpbx/taskprocessor.h"
#include "gabpbx/utils.h"

#include "include/chan_sofia_internal.h"

#include <usrsctp.h>

/* RFC 8831 §8 payload protocol identifiers. PPID 50 carries DCEP control (OPEN/ACK); 51/53/56/57
 * carry user data and are relayed across the bridged leg. */
#define SOFIA_DC_PPID_DCEP          50	/* WebRTC DataChannel Establishment Protocol (DCEP) */
#define SOFIA_DC_PPID_STRING        51	/* UTF-8 string */
#define SOFIA_DC_PPID_BINARY        53	/* binary */
#define SOFIA_DC_PPID_STRING_EMPTY  56	/* empty UTF-8 string */
#define SOFIA_DC_PPID_BINARY_EMPTY  57	/* empty binary */

/* DCEP message types (RFC 8832 §5.1/§5.2). */
#define SOFIA_DCEP_OPEN             0x03	/* DATA_CHANNEL_OPEN */
#define SOFIA_DCEP_ACK              0x02	/* DATA_CHANNEL_ACK */
#define SOFIA_DCEP_OPEN_HDR_LEN     12	/* fixed header before the label/protocol strings */

/* DCEP channel types (RFC 8832 §6.1). The 0x80 bit = unordered; the low bits = reliability. */
#define SOFIA_DC_CT_RELIABLE                  0x00
#define SOFIA_DC_CT_RELIABLE_UNORDERED        0x80
#define SOFIA_DC_CT_PARTIAL_REXMIT            0x01
#define SOFIA_DC_CT_PARTIAL_REXMIT_UNORDERED  0x81
#define SOFIA_DC_CT_PARTIAL_TIMED             0x02
#define SOFIA_DC_CT_PARTIAL_TIMED_UNORDERED   0x82
#define SOFIA_DC_CT_UNORDERED_BIT             0x80

/* Relay caps: we advertise a=max-message-size:262144 (sofia_sdp.c) and
 * the relay caps each forwarded message to min(262144, the FAR peer's advertised max). RFC 8841 §6:
 * an absent max-message-size defaults to 65536; an explicit 0 means unbounded (then 262144 binds). */
#define SOFIA_DC_HARD_MAX_MSG       262144u	/* our advertised cap, the absolute relay ceiling */
#define SOFIA_DC_DEFAULT_PEER_MAX   65536u	/* RFC 8841 §6 default when the peer OMITS the attribute */

/* RFC 8841 §6 distinguishes THREE cases for a=max-message-size that we must not conflate.
 * The SDP parse (sofia_sdp.c) records dc_max_message_size, carried to peer_max_msg:
 *   - ABSENT attribute                     => 0 (field reset value) => cap = 65536 (RFC default).
 *   - explicit "0" (UNBOUNDED)             => SOFIA_DC_PEER_MAX_UNBOUNDED => cap = 262144 (hard).
 *   - explicit N                           => N => cap = min(N, 262144).
 * SOFIA_DC_PEER_MAX_UNBOUNDED is defined in sofia_datachannel.h (shared with the SDP parse). */

/* Stream table growth (a small growable list — browsers open a handful). */
#define SOFIA_DC_STREAMS_INIT       8	/* initial capacity; grows by doubling on demand */
#define SOFIA_DC_STREAMS_MAX        1024	/* hard ceiling — refuse OPENs beyond this (DoS guard) */
#define SOFIA_DC_INITMSG_STREAMS    1024	/* SCTP_INITMSG out-streams / max-in-streams request */

#define SOFIA_DC_SID_NONE           0xFFFF	/* "unmapped" sentinel for peer_sid */

/* usrsctp_finish() can return nonzero while associations are still draining;
 * retry briefly on full unload, then give up and log (never a fragile reload dependency). */
#define SOFIA_DC_FINISH_RETRIES     20
#define SOFIA_DC_FINISH_RETRY_US    50000	/* 50 ms */

/* ----- module-global usrsctp init refcount + the shared worker lane ----- */

/* Guards dc_init_count + dc_lane. Library init/finish is rare (load/unload), so a plain mutex
 * is fine; attach/detach take it only to read dc_lane (a const after first init). */
AST_MUTEX_DEFINE_STATIC(dc_global_lock);
static int dc_init_count;			/* usrsctp_init refcount */
static struct ast_taskprocessor *dc_lane;	/* the single shared "sofia-datachannel" lane */

/* ----- the per-leg stream table -----
 *
 * One entry per DataChannel seen/created on THIS leg. local_sid is OUR stream id (parity = our DTLS
 * role); peer_sid is the FAR leg's mapped stream id (cross-leg A:sid <-> B:sid pairing). All fields
 * are owned by + only ever mutated from the single worker lane — the lane
 * serializes every recv cb, so the table needs NO lock of its own. */
struct sofia_dc_stream {
	uint16_t local_sid;		/* this leg's stream id */
	uint16_t peer_sid;		/* the far leg's mapped stream id (SOFIA_DC_SID_NONE = unmapped) */
	uint8_t channel_type;		/* RFC 8832 §6.1 (drives ordering + PR-SCTP policy on relay) */
	uint32_t reliability_param;	/* RFC 8832 §5.1 reliability parameter (host order) */
	unsigned int acked:1;		/* DCEP handshake complete (ACK sent or received) */
	unsigned int local_open:1;	/* 1 = WE sent the OPEN (proxied side); 0 = the peer opened it */
	unsigned int closing:1;		/* a stream reset is in flight; awaiting completion */
	char label[64];			/* RFC 8832 label (v1 cap 63 bytes; OPENs over it are rejected, never truncated) */
	char protocol[64];		/* RFC 8832 protocol (v1 cap 63 bytes; OPENs over it are rejected, never truncated) */
};

/* ----- the per-leg DataChannel transport object (ao2) ----- */

struct sofia_datachannel {
	struct socket *sctp_sock;	/* the usrsctp AF_CONN socket (NULL until attach succeeds) */
	struct sofia_pvt *pvt;		/* RAW back-ref — NOT reffed (avoids an ao2 cycle); repointed in
					 * place on a WebRTC fork-steal. Guarded NULL. */
	uint16_t sctp_port;		/* peer a=sctp-port (RFC 8841); the AF_CONN self-address port */
	uint32_t peer_max_msg;		/* the peer's a=max-message-size (RFC 8841 §6), carried from the SDP
					 * parse: 0 = ABSENT (cap 65536), SOFIA_DC_PEER_MAX_UNBOUNDED = explicit
					 * 0/unbounded (cap 262144), else N (cap min(N, 262144)). See the relay. */
	unsigned int dtls_is_server:1;	/* our per-leg DTLS role → DCEP stream parity
					 * (RFC 8832 §6: client even / server odd). Set at attach from the
					 * engine setup; consumed by the OPEN-proxying (parity selection). */
	unsigned int associated:1;	/* SCTP_COMM_UP seen (set by the recv-cb notification path) */
	uint16_t out_streams;		/* negotiated OUTBOUND stream count (SCTP_COMM_UP sac_outbound_streams);
					 * 0 until associated. Caps sofia_dc_alloc_local_sid so a proxied OPEN
					 * never picks a sid the far peer did not grant. */
	uint16_t in_streams;		/* negotiated INBOUND stream count (sac_inbound_streams; informational) */
	struct sofia_dc_stream *streams;	/* growable table (worker-lane-owned; see above) */
	unsigned int n_streams;		/* live entries in use */
	unsigned int cap_streams;	/* allocated capacity of `streams` */
};

/* RX hand-off event: the bytes copied off the instance lock, carried to the worker lane. */
struct sofia_dc_rx_event {
	struct sofia_datachannel *dc;	/* holds a +1 ao2 ref for the lifetime of the event */
	uint8_t *buf;			/* ast_malloc'd copy of the decrypted DTLS appdata */
	size_t len;
};

/* Forward decls for the callbacks wired below. */
static int sofia_dc_sctp_output(void *addr, void *buf, size_t len, uint8_t tos, uint8_t set_df);
static int sofia_dc_sctp_recv_cb(struct socket *sock, union sctp_sockstore addr, void *data,
	size_t datalen, struct sctp_rcvinfo rcv, int flags, void *ulp_info);
static void sofia_dc_engine_rx(struct ast_rtp_instance *instance, const uint8_t *data,
	size_t len, void *cb_data);
static int sofia_dc_rx_task(void *data);

/* Internals (all worker-lane only unless noted). */
static int sofia_dc_send_on(struct sofia_datachannel *dc, uint16_t sid, uint32_t ppid, int ordered,
	uint8_t channel_type, uint32_t reliability, const void *buf, size_t len);
static struct sofia_dc_stream *sofia_dc_stream_find(struct sofia_datachannel *dc, uint16_t local_sid);
static struct sofia_dc_stream *sofia_dc_stream_add(struct sofia_datachannel *dc, uint16_t local_sid);
static void sofia_dc_stream_remove(struct sofia_datachannel *dc, uint16_t local_sid);
static void sofia_dc_reset_stream(struct sofia_datachannel *dc, uint16_t local_sid);
static struct sofia_datachannel *sofia_dc_get_bridged_dc(struct sofia_datachannel *self_dc);

/* ======================================================================================
 * Module init / finish (refcounted)
 * ====================================================================================== */

int sofia_dc_init(void)
{
	int rc = 0;

	ast_mutex_lock(&dc_global_lock);

	if (dc_init_count > 0) {
		/* Already initialized — just bump the refcount. */
		dc_init_count++;
		ast_mutex_unlock(&dc_global_lock);
		return 0;
	}

	/* usrsctp_init's 2nd arg is the GLOBAL conn output cb (usrsctp.h:894-896):
	 * one function dispatches every outbound packet by its registered `addr` (= a sofia_dc*). The
	 * 1st arg (UDP-encaps port) is 0 — we never use SCTP-over-UDP; everything rides AF_CONN/DTLS. */
	usrsctp_init(0, sofia_dc_sctp_output, NULL);

	/* Tuning: WebRTC datachannels never run over real IP here (AF_CONN only), so disable the
	 * loopback CRC suppression is irrelevant; we DO want the receive/send buffers reasonable and
	 * the explicit-EOR path. Keep tuning minimal and safe; deeper tuning is deferred. */
#ifdef SCTP_DEBUG
	usrsctp_sysctl_set_sctp_debug_on(0);
#endif

	dc_lane = ast_taskprocessor_get("sofia-datachannel", TPS_REF_DEFAULT);
	if (!dc_lane) {
		ast_log(LOG_ERROR, "Sofia: failed to create the DataChannel worker taskprocessor\n");
		/* Roll back the library init so a later retry starts clean. usrsctp_finish() with no
		 * sockets returns 0 immediately. */
		usrsctp_finish();
		rc = -1;
		goto done;
	}

	dc_init_count = 1;
	ast_debug(1, "Sofia: WebRTC DataChannel (usrsctp) initialized\n");

done:
	ast_mutex_unlock(&dc_global_lock);
	return rc;
}

void sofia_dc_finish(void)
{
	int i;

	ast_mutex_lock(&dc_global_lock);

	if (dc_init_count <= 0) {
		ast_mutex_unlock(&dc_global_lock);
		return;
	}

	if (--dc_init_count > 0) {
		/* Still referenced — do NOT tear down the library. */
		ast_mutex_unlock(&dc_global_lock);
		return;
	}

	/* Last reference dropped (module unload). usrsctp_finish() can return nonzero
	 * while associations are still draining — retry briefly, then log and give up. This must only
	 * be reached once every DC has detached (each detach usrsctp_close + deregister). */
	for (i = 0; i < SOFIA_DC_FINISH_RETRIES; i++) {
		if (usrsctp_finish() == 0) {
			break;
		}
		usleep(SOFIA_DC_FINISH_RETRY_US);
	}
	if (i == SOFIA_DC_FINISH_RETRIES) {
		ast_log(LOG_WARNING,
			"Sofia: usrsctp_finish() still busy after %d retries — associations may be leaking\n",
			SOFIA_DC_FINISH_RETRIES);
	}

	if (dc_lane) {
		dc_lane = ast_taskprocessor_unreference(dc_lane);
	}

	ast_debug(1, "Sofia: WebRTC DataChannel (usrsctp) finished\n");
	ast_mutex_unlock(&dc_global_lock);
}

/* ======================================================================================
 * ao2 lifecycle
 * ====================================================================================== */

/*!
 * \brief ABORTIVE close of a usrsctp socket — the anti-teardown-UAF primitive.
 *
 * A plain usrsctp_close() is GRACEFUL: it starts an SCTP SHUTDOWN, the association DRAINS, and the
 * library's internal TIMER thread (user_sctp_timer_iterate -> sctp_handle_tick -> sctp_timeout_handler
 * -> sctp_chunk_output) KEEPS FIRING for that still-draining association — calling the GLOBAL output
 * cb (sofia_dc_sctp_output) for its conn token long AFTER close() returned. usrsctp_close() carries
 * NO completion fence (usrsctp.h:1006-1007), and usrsctp_deregister_address() is NOT a timer/callback
 * barrier either (usrsctp.h:1027-1031) — it merely unhooks the conn-address resolution. A confirmed
 * core (~4 min after the call ended) caught exactly this: the timer fired the output cb for a dc whose
 * pvt back-ref was already a dangling pointer (read as garbage 0x18), SIGSEGV in
 * ast_rtp_instance_dtls_write_appdata.
 *
 * We make the close ABORTIVE by setting SO_LINGER {l_onoff=1, l_linger=0} first: SCTP then emits an
 * ABORT instead of a graceful SHUTDOWN, the association is destroyed IMMEDIATELY at close(), and no
 * lingering association/timer survives to fire the output cb. setsockopt failure is tolerated (the
 * NULL'd pvt back-ref is the belt; the abort is the braces) — log debug and still close.
 *
 * The helper does ONLY the setsockopt + usrsctp_close; the caller deregisters the conn token AFTER.
 */
static void sofia_dc_abort_close(struct socket *s)
{
	struct linger ling;

	if (!s) {
		return;
	}
	memset(&ling, 0, sizeof(ling));
	ling.l_onoff = 1;	/* linger ON ... */
	ling.l_linger = 0;	/* ... for zero seconds == abort, no graceful drain (no lingering timer) */
	if (usrsctp_setsockopt(s, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling)) < 0) {
		ast_debug(1, "Sofia: DataChannel SO_LINGER(abort) failed: %s — closing anyway\n",
			strerror(errno));
	}
	usrsctp_close(s);
}

static void sofia_dc_destructor(void *obj)
{
	struct sofia_datachannel *dc = obj;

	/* By the time the destructor runs the ref is 0, so detach has already cleared the engine cb
	 * and abort-closed/deregistered the socket. This is a belt-and-braces net for an attach that
	 * failed mid-setup and dropped its only ref without going through detach. NULL pvt first (so a
	 * stray output cb resolves NULL and drops), then ABORT-close so no draining-association timer
	 * outlives this destruction to fire the output cb against freed memory.
	 *
	 * Guard the NULL store with ao2_lock(dc) for the same reason as detach STEP (b): on the
	 * failed-attach path the socket may still be open + the token still registered when the ref hits
	 * 0, so a usrsctp timer-driven output cb (which holds NO ao2 ref by design) could be in flight.
	 * The lock makes the store / the cb's dc->pvt read race-free and orders the NULL publication
	 * before this path's abort-close (which then fences usrsctp's timer thread via the TCB lock).
	 * Only the dc lock is held across the bare store — no usrsctp call inside — so no dc-lock ->
	 * usrsctp-lock inversion (same ABBA proof as sofia_dc_sctp_output). */
	ao2_lock(dc);
	dc->pvt = NULL;
	ao2_unlock(dc);
	if (dc->sctp_sock) {
		sofia_dc_abort_close(dc->sctp_sock);
		dc->sctp_sock = NULL;
		usrsctp_deregister_address(dc);
	}
	/* The stream table holds no heap-owned children (label/protocol are inline fixed arrays), so
	 * a single free of the array suffices. Worker-lane-owned, but by destruction time no task can
	 * still reach this dc (the last ref — held only by a queued RX event or detach — has dropped). */
	ast_free(dc->streams);
	dc->streams = NULL;
	/* pvt is a raw back-ref — nothing to free. */
}

/* ======================================================================================
 * Attach / detach
 * ====================================================================================== */

struct sofia_datachannel *sofia_dc_attach(struct sofia_pvt *pvt, uint16_t sctp_port)
{
	struct sofia_datachannel *dc;
	struct socket *s;
	struct sockaddr_conn sconn;
	struct sctp_assoc_value av;
	struct sctp_event ev;
	struct sctp_initmsg initmsg;
	uint32_t on = 1;
	/* The full event set the relay acts on (SEND_FAILED + SHUTDOWN
	 * alongside the existing STREAM_RESET + ASSOC_CHANGE). */
	const uint16_t sub_events[] = {
		SCTP_STREAM_RESET_EVENT, SCTP_ASSOC_CHANGE,
		SCTP_SEND_FAILED_EVENT, SCTP_SHUTDOWN_EVENT,
	};
	uint32_t nodelay = 1;
	uint32_t rcvbuf = SOFIA_DC_HARD_MAX_MSG * 4u;	/* inbound reassembly ceiling, see SO_RCVBUF below */
	unsigned int i;
	struct ast_rtp_engine_dtls *dtls;

	if (!pvt || !pvt->rtp) {
		ast_log(LOG_WARNING, "Sofia: DataChannel attach with no RTP instance\n");
		return NULL;
	}

	/* Must be initialized (load_module did sofia_dc_init). Guard so a stray attach can't
	 * dereference a NULL lane. */
	ast_mutex_lock(&dc_global_lock);
	if (dc_init_count <= 0 || !dc_lane) {
		ast_mutex_unlock(&dc_global_lock);
		ast_log(LOG_WARNING, "Sofia: DataChannel attach before init\n");
		return NULL;
	}
	ast_mutex_unlock(&dc_global_lock);

	dc = ao2_alloc(sizeof(*dc), sofia_dc_destructor);
	if (!dc) {
		return NULL;
	}
	dc->pvt = pvt;			/* raw back-ref */
	dc->sctp_port = sctp_port;
	dc->peer_max_msg = pvt->dc_max_message_size;	/* RFC 8841 a=max-message-size, three-valued:
							 * 0 = ABSENT (relay cap 65536),
							 * SOFIA_DC_PEER_MAX_UNBOUNDED = explicit 0/unbounded
							 * (cap 262144), else N (cap min(N,262144)). Recorded
							 * by the SDP parse before attach (sofia_sdp.c). */

	/* Per-leg DTLS role → DCEP stream parity (RFC 8832 §6: client even, server
	 * odd). Derive from the live engine setup; PASSIVE (answerer) == DTLS server == odd. Stored
	 * now; the OPEN-proxying stream selection consumes it. */
	dtls = ast_rtp_instance_get_dtls(pvt->rtp);
	if (dtls && dtls->get_setup) {
		dc->dtls_is_server = (dtls->get_setup(pvt->rtp) == AST_RTP_DTLS_SETUP_PASSIVE) ? 1 : 0;
	}

	/* The usrsctp conn token IS this dc. Register it before creating the socket
	 * so conninput/output can resolve it. */
	usrsctp_register_address(dc);

	s = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP,
		sofia_dc_sctp_recv_cb, NULL, 0, dc);
	if (!s) {
		ast_log(LOG_ERROR, "Sofia: usrsctp_socket failed for DataChannel: %s\n", strerror(errno));
		usrsctp_deregister_address(dc);
		ao2_ref(dc, -1);
		return NULL;
	}

	/* Enable stream-reset request support (RFC 6525 §6.3.3 — the default is to DENY
	 * a reset request unless this is set). FUTURE_ASSOC applies it to the upcoming connect's assoc. */
	memset(&av, 0, sizeof(av));
	av.assoc_id = SCTP_FUTURE_ASSOC;
	av.assoc_value = SCTP_ENABLE_RESET_STREAM_REQ;
	if (usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &av, sizeof(av)) < 0) {
		ast_log(LOG_WARNING, "Sofia: DataChannel SCTP_ENABLE_STREAM_RESET failed: %s\n",
			strerror(errno));
	}

	/* SCTP_RECVRCVINFO: deliver rcv_sid + rcv_ppid to the recv cb (mandatory — the DCEP/relay demux
	 * keys entirely off rcv.rcv_sid / ntohl(rcv.rcv_ppid)). Without this they arrive zeroed. */
	if (usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_RECVRCVINFO, &on, sizeof(on)) < 0) {
		ast_log(LOG_WARNING, "Sofia: DataChannel SCTP_RECVRCVINFO failed: %s\n", strerror(errno));
	}

	/* SCTP_EXPLICIT_EOR: every send must flag SCTP_EOR to mark the message boundary (we always do —
	 * sofia_dc_send_on sets SCTP_EOR). Matches the usrsctp rtcweb example. */
	if (usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_EXPLICIT_EOR, &on, sizeof(on)) < 0) {
		ast_log(LOG_WARNING, "Sofia: DataChannel SCTP_EXPLICIT_EOR failed: %s\n", strerror(errno));
	}

	/* SCTP_INITMSG: request a generous stream count so a browser opening many channels is not
	 * stream-starved (browsers default to 65535; we bound to a sane SOFIA_DC_INITMSG_STREAMS). The
	 * negotiated count is later read from SCTP_COMM_UP's sac_outbound/inbound_streams. */
	memset(&initmsg, 0, sizeof(initmsg));
	initmsg.sinit_num_ostreams = SOFIA_DC_INITMSG_STREAMS;
	initmsg.sinit_max_instreams = SOFIA_DC_INITMSG_STREAMS;
	if (usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(initmsg)) < 0) {
		ast_log(LOG_WARNING, "Sofia: DataChannel SCTP_INITMSG failed: %s\n", strerror(errno));
	}

	/* Subscribe to the notifications the relay acts on: STREAM_RESET (channel close, RFC 8831 §6.7),
	 * ASSOC_CHANGE (up/down, gates OPEN-proxying), SEND_FAILED + SHUTDOWN (debug/teardown). They
	 * arrive via the recv cb with MSG_NOTIFICATION. Tolerate per-event setsockopt failure. */
	for (i = 0; i < ARRAY_LEN(sub_events); i++) {
		memset(&ev, 0, sizeof(ev));
		ev.se_assoc_id = SCTP_FUTURE_ASSOC;
		ev.se_type = sub_events[i];
		ev.se_on = 1;
		if (usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_EVENT, &ev, sizeof(ev)) < 0) {
			ast_log(LOG_WARNING, "Sofia: DataChannel SCTP_EVENT 0x%04x subscribe failed: %s\n",
				sub_events[i], strerror(errno));
		}
	}

	/* Nagle off — datachannel signaling is small + latency-sensitive. */
	if (usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_NODELAY, &nodelay, sizeof(nodelay)) < 0) {
		ast_log(LOG_WARNING, "Sofia: DataChannel SCTP_NODELAY failed: %s\n", strerror(errno));
	}

	/* SO_RCVBUF: bound the inbound reassembly queue. A hostile post-DTLS peer can otherwise inflate
	 * usrsctp's receive buffer with large interleaved partial messages (the relay only caps the forward
	 * direction). Ceil at 4x our hard message ceiling (262144) so several in-flight max-size messages
	 * fit while the queue stays bounded in-module. Tolerate failure (non-fatal — the recv-cb still
	 * enforces the per-message ceiling). */
	if (usrsctp_setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
		ast_log(LOG_WARNING, "Sofia: DataChannel SO_RCVBUF failed: %s\n", strerror(errno));
	}

	/* Non-blocking: usrsctp_connect returns EINPROGRESS and the association comes up
	 * asynchronously (we drive I/O via conninput/output, never blocking sends). */
	usrsctp_set_non_blocking(s, 1);

	/* AF_CONN self-addressing: bind + connect to a sockaddr_conn whose sconn_addr is THIS dc (the
	 * registered conn token). This is the standard usrsctp WebRTC pattern — the SCTP packets never
	 * touch a real socket; they flow through conninput (in) / the global output cb (out). Both
	 * endpoints use the SAME a=sctp-port (5000 in real Chrome SDP, captures §A/§B). */
	memset(&sconn, 0, sizeof(sconn));
	sconn.sconn_family = AF_CONN;
	sconn.sconn_port = htons(sctp_port);
	sconn.sconn_addr = dc;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__) || defined(__Bitrig__)
	sconn.sconn_len = sizeof(sconn);	/* BSD-family sockaddr_conn carries sconn_len (usrsctp.h:124) */
#endif

	if (usrsctp_bind(s, (struct sockaddr *)&sconn, sizeof(sconn)) < 0) {
		ast_log(LOG_ERROR, "Sofia: usrsctp_bind failed for DataChannel: %s\n", strerror(errno));
		/* ABORT-close (never graceful) so no draining-association timer can fire the output cb for
		 * this token after we drop our only ref — same anti-teardown-UAF rule as detach. */
		sofia_dc_abort_close(s);
		usrsctp_deregister_address(dc);
		ao2_ref(dc, -1);
		return NULL;
	}

	if (usrsctp_connect(s, (struct sockaddr *)&sconn, sizeof(sconn)) < 0 && errno != EINPROGRESS) {
		ast_log(LOG_ERROR, "Sofia: usrsctp_connect failed for DataChannel: %s\n", strerror(errno));
		/* ABORT-close (never graceful) — see the bind-failure path above. */
		sofia_dc_abort_close(s);
		usrsctp_deregister_address(dc);
		ao2_ref(dc, -1);
		return NULL;
	}

	dc->sctp_sock = s;

	/* Wire the engine RX seam LAST — only once the socket exists, so an early packet always has a
	 * socket to feed. After this the engine drain loop delivers DTLS appdata to sofia_dc_engine_rx
	 * (under ao2_lock(instance)). */
	ast_rtp_instance_set_dtls_appdata_cb(pvt->rtp, sofia_dc_engine_rx, dc);

	ast_debug(1, "Sofia: DataChannel attached (sctp_port=%u, dtls_role=%s)\n",
		sctp_port, dc->dtls_is_server ? "server/odd" : "client/even");

	return dc;
}

void sofia_dc_set_pvt(struct sofia_datachannel *dc, struct sofia_pvt *pvt)
{
	if (!dc) {
		return;
	}
	/* WebRTC fork-steal. The DC's transport binding is the engine cb on pvt->rtp,
	 * and that rtp instance is itself moved child->master by the caller's winner-steal BEFORE this
	 * runs, with the cb_data (the dc pointer) carried along unchanged — so NO cb re-registration is
	 * needed. We only repoint the raw back-ref so the output cb + the worker lane resolve dc->pvt to
	 * the surviving master leg. A single aligned-pointer store; the caller holds master->lock and the
	 * call is not yet media-active, so no RX/output is in flight against the old pvt. Take ao2_lock(dc)
	 * for the bare store anyway (the SAME publication lock the output cb + detach +
	 * get_bridged use) so ALL dc->pvt writes/reads share one lock — cheap, and codifies the invariant. */
	ao2_lock(dc);
	dc->pvt = pvt;
	ao2_unlock(dc);
}

void sofia_dc_set_peer_max_msg(struct sofia_datachannel *dc, unsigned int max)
{
	if (!dc) {
		return;
	}
	/* OFFER side: the DC attaches in provision_offer (peer_max_msg = the 262144 default) BEFORE the
	 * answer arrives; the answer parse learns the peer's real a=max-message-size but writes only
	 * pvt->dc_max_message_size, leaving the LIVE dc stale — and the relay caps on far_dc->peer_max_msg.
	 * Push the parsed value (which already encodes the three-valued sentinel: 0=absent,
	 * SOFIA_DC_PEER_MAX_UNBOUNDED=explicit-0/unbounded, else N) into the live dc. A single aligned-word
	 * store, the SAME lock-free discipline as the attach-time write (dc->peer_max_msg = ...) and
	 * sofia_dc_set_pvt: peer_max_msg is an aligned uint32_t, the caller runs on the sofia thread and the
	 * relay reads it on the worker lane — aligned-store atomicity guarantees no torn value. */
	dc->peer_max_msg = max;
}

void sofia_dc_set_dtls_role(struct sofia_datachannel *dc)
{
	struct ast_rtp_engine_dtls *dtls;
	struct sofia_pvt *pvt;

	if (!dc) {
		return;
	}
	/* OFFERER role-latch fix (RFC 8832 §6): at attach time the OFFERER's DTLS role is still ACTPASS
	 * (we offer a=setup:actpass), so dc->dtls_is_server latched 0 = client = EVEN stream parity. The
	 * far leg's ANSWER then FIXES our concrete role (answer a=setup:active -> set_setup maps us to
	 * PASSIVE = DTLS SERVER = ODD parity, RFC 5763 §5). Without recomputing here, alloc_local_sid
	 * (sofia_dc_alloc_local_sid) would still pick EVEN streams the peer rejects, and the inbound OPEN
	 * parity check (sofia_dc_handle_dcep) would flag every legit peer OPEN as wrong-parity -> the
	 * offerer-direction DataChannel silently fails. Re-derive dc->dtls_is_server from the engine's NOW-
	 * concrete setup (the SAME derivation as attach: PASSIVE == server == odd) so both the SID allocation
	 * and the parity check use the corrected role. Must be called AFTER set_setup applied the answer and
	 * BEFORE any worker-lane SID alloc / OPEN parity check (the relay only runs once media is up).
	 *
	 * Read dc->pvt AND write the dtls_is_server bitfield UNDER ao2_lock(dc) - the SAME publication lock
	 * the output cb / set_pvt / detach use for dc->pvt (this was the only dc->pvt
	 * reader outside that lock, and a bitfield store is a non-atomic read-modify-write that could tear
	 * vs a concurrent set_pvt/detach). Nests dc-lock -> instance-lock (get_setup), the SAME order as
	 * sofia_dc_sctp_output, so no new ABBA. */
	ao2_lock(dc);
	pvt = dc->pvt;
	if (pvt && pvt->rtp) {
		dtls = ast_rtp_instance_get_dtls(pvt->rtp);
		if (dtls && dtls->get_setup) {
			dc->dtls_is_server = (dtls->get_setup(pvt->rtp) == AST_RTP_DTLS_SETUP_PASSIVE) ? 1 : 0;
			ast_debug(2, "Sofia: DataChannel DTLS role recomputed from answer -> %s (%s stream parity)\n",
				dc->dtls_is_server ? "server" : "client", dc->dtls_is_server ? "odd" : "even");
		}
	}
	ao2_unlock(dc);
}

/* ----- detach lane-drain barrier ----- */

/*! \brief Shared state for the detach barrier: a no-op task posted to dc_lane that signals on run. */
struct sofia_dc_lane_barrier {
	ast_mutex_t lock;
	ast_cond_t cond;
	int done;
};

/*!
 * \brief The barrier task itself — runs on dc_lane, marks done + signals the waiter, returns.
 *
 * It touches NO dc/pvt/usrsctp state; it only flips the flag. FIFO ordering of the single-threaded
 * dc_lane guarantees every task pushed BEFORE it has already run to completion when this fires.
 */
static int sofia_dc_lane_barrier_task(void *data)
{
	struct sofia_dc_lane_barrier *b = data;

	ast_mutex_lock(&b->lock);
	b->done = 1;
	ast_cond_signal(&b->cond);
	ast_mutex_unlock(&b->lock);
	return 0;
}

void sofia_dc_detach(struct sofia_datachannel *dc)
{
	int had_transport;

	if (!dc) {
		return;
	}

	/* Remember whether this dc was ever wired into the engine/usrsctp before we tear it down: only
	 * an attached dc can have RX events queued on the shared worker lane, so only it needs the
	 * lane-drain barrier below. A never-attached dc (attach failed early) skips the barrier. */
	had_transport = (dc->sctp_sock != NULL) || (dc->pvt && dc->pvt->rtp);

	/* STEP (a) (anti-UAF): clear the engine cb FIRST, WHILE
	 * pvt->rtp is still valid. The setter takes ao2_lock(instance), the SAME lock the RX cb fires
	 * under, so once this returns no sofia_dc_engine_rx can be running or start — the dc cb_data
	 * pointer is no longer reachable from the engine. Events ALREADY queued on the worker lane each
	 * hold their own +1 ao2 ref, so they keep `dc` alive until they run; usrsctp_conninput on a
	 * closed socket is benign. */
	if (dc->pvt && dc->pvt->rtp) {
		ast_rtp_instance_set_dtls_appdata_cb(dc->pvt->rtp, NULL, NULL);
	}

	/* STEP (b) (teardown-UAF fix): NULL the raw back-ref IMMEDIATELY, BEFORE
	 * any usrsctp close/deregister. The output cb (sofia_dc_sctp_output) and sofia_dc_get_bridged_dc
	 * both read dc->pvt and bail on NULL — so a synchronous output cb (e.g. from a final flush) OR a
	 * late timer-driven output cb (the confirmed ~4-min teardown core) now observes NULL and drops
	 * instead of dereferencing a pvt that may already be freed.
	 *
	 * Take ao2_lock(dc) around this store (residual-window fix): the output cb reads
	 * dc->pvt — and writes over pvt->rtp — under the SAME ao2_lock(dc) (see sofia_dc_sctp_output's
	 * header proof). Without the lock the store here and the cb's read were an unsynchronized data
	 * race (UB; no publication barrier), so a TIMER-thread cb could observe a stale non-NULL dc->pvt
	 * AFTER this point and write over a pvt->rtp the destructor is about to free. Under the lock the
	 * NULL is published with a happens-before edge: any cb that acquires the lock AFTER this store
	 * sees NULL and bails, and any cb already inside its critical section finishes its dtls write on
	 * the still-live rtp (the abort-close in STEP (d) then waits out usrsctp's own timer thread via
	 * the TCB lock) BEFORE we release the lock here. We take ONLY the dc lock around the bare store
	 * (NO usrsctp call inside) — so detach never nests dc-lock -> usrsctp-lock, which would invert
	 * the cb's usrsctp-lock -> dc-lock order; no ABBA (full proof in sofia_dc_sctp_output). This
	 * single guarded store is the BELT; the abort-close in STEP (d) is the braces. Must precede the
	 * close so no window exists where the socket is alive but pvt is stale. */
	ao2_lock(dc);
	dc->pvt = NULL;
	ao2_unlock(dc);

	/* STEP (c): DRAIN the shared worker lane NOW, WHILE
	 * dc->sctp_sock is STILL OPEN (before STEP (d) closes/deregisters it).
	 *
	 * Two reasons this barrier must run before the close, not after:
	 *   1. A task that ALREADY snapshotted the old dc->pvt in sofia_dc_get_bridged_dc — i.e. one
	 *      already RUNNING when STEP (b) fired — can still be inside sofia_dc_pair_bridged
	 *      dereferencing that pvt while THIS function returns and the sofia_pvt destructor that called
	 *      us frees the pvt. STEP (b) alone cannot close that window; the barrier does.
	 *   2. An already-queued sofia_dc_rx_task feeds usrsctp_conninput(dc, ...). Draining it here, with
	 *      the socket still open and the token still registered, lets that conninput complete cleanly
	 *      against a live socket rather than racing the close/deregister in STEP (d).
	 *
	 * We post a no-op barrier task to dc_lane and BLOCK until it runs. dc_lane is a single-threaded
	 * FIFO lane (sofia_dc_init: ast_taskprocessor_get), so the barrier task runs ONLY after every
	 * previously-queued task — including any in-flight sofia_dc_rx_task that snapshotted the old pvt —
	 * has run to completion. When it returns here, no task can still hold a stale pvt pointer, so the
	 * destructor may safely free the pvt, and STEP (d) may close the now-quiescent socket.
	 *
	 * SELF-DEADLOCK PROOF (load-bearing, still valid with the barrier moved before the close):
	 * sofia_dc_detach is called only from non-dc_lane threads — the sofia_pvt destructor
	 * (sofia_pvt_destructor, chan_sofia.c, when the pvt ao2 refcount hits 0) and the SDP
	 * answer-decline path (sofia_parse_sdp, sofia_sdp.c, on the sofia/nua thread); grep-verified both
	 * callers. The dc_lane worker holds NO pvt ref (dc->pvt is a RAW back-ref, and the queued
	 * rx_event holds only a +1 dc ref — sofia_dc_engine_rx / sofia_dc_rx_task), so neither the pvt
	 * destructor nor the SDP path can ever run ON the dc_lane thread. Therefore blocking on a barrier
	 * task scheduled BEHIND the lane's current work cannot wait on ourselves: a non-lane thread waits
	 * for the lane to reach the barrier. No self-deadlock. (Moving the barrier earlier does not touch
	 * this argument — it depends only on WHO calls detach, never on socket state.)
	 *
	 * Guarded by had_transport + a non-NULL dc_lane: a never-attached dc queued nothing, and if the
	 * lane is already gone (module finishing) there is nothing left running to drain. */
	if (had_transport) {
		struct ast_taskprocessor *lane;

		ast_mutex_lock(&dc_global_lock);
		lane = dc_lane;
		ast_mutex_unlock(&dc_global_lock);

		if (lane) {
			struct sofia_dc_lane_barrier b;

			ast_mutex_init(&b.lock);
			ast_cond_init(&b.cond, NULL);
			b.done = 0;

			if (ast_taskprocessor_push(lane, sofia_dc_lane_barrier_task, &b) == 0) {
				ast_mutex_lock(&b.lock);
				while (!b.done) {
					ast_cond_wait(&b.cond, &b.lock);
				}
				ast_mutex_unlock(&b.lock);
			} else {
				/* Push failed (lane overflow/shutdown): we could not drain. Any in-flight task
				 * still holds its own +1 dc ref, so `dc` stays alive — but the pvt it may read is
				 * about to be freed. This is the only residual window; log it loudly. In practice
				 * a healthy lane never refuses a push, and shutdown drains the lane separately. */
				ast_log(LOG_WARNING,
					"Sofia: DataChannel detach could not post lane-drain barrier — "
					"a concurrent worker task may briefly observe a freed pvt\n");
			}

			ast_cond_destroy(&b.cond);
			ast_mutex_destroy(&b.lock);
		}
	}

	/* STEP (d): ABORT-close the SCTP socket + deregister the conn token, AFTER pvt is NULL'd (STEP b)
	 * and the lane is drained (STEP c). The abort-close (SO_LINGER 0 then usrsctp_close) makes SCTP
	 * tear the association down at once with an ABORT — no graceful SHUTDOWN, hence no draining
	 * association and no surviving internal timer to fire the output cb minutes later (the teardown
	 * core's root cause). Deregister the token only after the close so no late conninput/output can
	 * resolve it. (The destructor repeats this defensively for the failed-attach path.) */
	if (dc->sctp_sock) {
		sofia_dc_abort_close(dc->sctp_sock);
		dc->sctp_sock = NULL;
		usrsctp_deregister_address(dc);
	}

	/* STEP (e): drop the caller's ref. The object frees when the last queued RX event also releases. */
	ao2_ref(dc, -1);
}

/* ======================================================================================
 * THE SEAM — inbound (engine RX -> taskprocessor -> usrsctp_conninput)
 * ====================================================================================== */

/*!
 * \brief Engine RX callback. Fires UNDER ao2_lock(instance) from res_rtp_gabpbx's DTLS drain loop.
 *
 * LOCK PROOF: the ONLY locks held on entry are channel/pvt/instance (per the
 * documented lock order channel -> pvt -> instance -> peer). This function takes NO additional lock
 * and calls NO usrsctp/pvt/peer/channel API. ast_malloc, memcpy, ao2_ref(+1), and
 * ast_taskprocessor_push are all instance-lock-safe and acquire no chan_sofia lock, so no inversion
 * is possible. All real work (usrsctp_conninput → the synchronous receive cb → DCEP/relay
 * that DOES touch pvt/peer) is deferred to the worker lane, off this lock.
 */
static void sofia_dc_engine_rx(struct ast_rtp_instance *instance, const uint8_t *data,
	size_t len, void *cb_data)
{
	struct sofia_datachannel *dc = cb_data;
	struct sofia_dc_rx_event *ev;

	if (!dc || !data || !len) {
		return;
	}

	ev = ast_malloc(sizeof(*ev));
	if (!ev) {
		return;
	}
	ev->buf = ast_malloc(len);
	if (!ev->buf) {
		ast_free(ev);
		return;
	}
	memcpy(ev->buf, data, len);
	ev->len = len;

	/* Keep `dc` alive across the hand-off even if detach drops the caller ref meanwhile. */
	ao2_ref(dc, +1);
	ev->dc = dc;

	if (ast_taskprocessor_push(dc_lane, sofia_dc_rx_task, ev) < 0) {
		/* Lane gone/overflowed — drop the packet (SCTP retransmits). Release what we took. */
		ao2_ref(dc, -1);
		ast_free(ev->buf);
		ast_free(ev);
	}
}

/*!
 * \brief Worker-lane task: feed the copied bytes into usrsctp, OFF the instance lock.
 *
 * Runs on the shared "sofia-datachannel" lane with NO instance/pvt/peer lock held. usrsctp_conninput
 * may synchronously invoke sofia_dc_sctp_recv_cb (and, on output, the global output cb) — all off the
 * instance lock, which is exactly why DCEP/relay work may safely run from the receive cb.
 */
static int sofia_dc_rx_task(void *data)
{
	struct sofia_dc_rx_event *ev = data;

	/* The conn token registered with usrsctp is the dc itself. Even if the socket
	 * was closed by a concurrent detach, conninput against a closed/deregistered token is benign. */
	usrsctp_conninput(ev->dc, ev->buf, ev->len, 0);

	ast_free(ev->buf);
	ao2_ref(ev->dc, -1);
	ast_free(ev);
	return 0;
}

/* ======================================================================================
 * THE SEAM — outbound (usrsctp GLOBAL output cb -> DTLS write)
 * ====================================================================================== */

/*!
 * \brief usrsctp's GLOBAL output callback (registered in usrsctp_init).
 *
 * \a addr is the registered conn token, i.e. the sofia_datachannel*. usrsctp only
 * invokes this for a registered address, so `addr` is a live dc here; we still guard NULL pvt/rtp
 * (a fork-steal repoints pvt; a torn-down leg may transiently have a NULL rtp). We do not take an
 * ao2 ref: detach deregisters the token (and closes the socket) so usrsctp will not call us with a
 * freed token.
 *
 * --- THE TEARDOWN-UAF FENCE (residual window fix) ---
 * This cb runs on TWO threads: (1) the usrsctp INTERNAL TIMER thread (usrsctp_init spawns it —
 * user_sctp_timer_iterate -> sctp_handle_tick -> sctp_timeout_handler -> sctp_chunk_output ->
 * sctp_lowlevel_chunk_output, under the usrsctp TCB lock, sctp_output.c:4130/5040), and (2) the
 * worker lane synchronously inside usrsctp_sendv/usrsctp_conninput. Either way it derefs dc->pvt
 * then pvt->rtp then writes over pvt->rtp's DTLS.
 *
 * The RESIDUAL race the audit confirmed: a TIMER-thread cb that reads a NON-NULL dc->pvt the instant
 * BEFORE sofia_dc_detach NULLs it, then proceeds to ast_rtp_instance_dtls_write_appdata(pvt->rtp)
 * while the pvt destructor (chan_sofia.c:1820, AFTER detach returns) frees pvt->rtp == UAF. The
 * abort-close in detach STEP (d) fences the TCB-lock chunk-output path (usrsctp_close ->
 * sctp_inpcb_free takes the same TCB lock, so it BLOCKS until any in-flight chunk-output cb releases
 * it — sctp_pcb.c SCTP_TCB_LOCK(asoc) before sctp_free_assoc), but the bare `dc->pvt = NULL` store
 * and this bare `pvt = dc->pvt` read were an UNSYNCHRONIZED data race (UB; no publication barrier),
 * so this cb could observe a stale non-NULL dc->pvt and act on it.
 *
 * THE FIX: take ao2_lock(dc) around BOTH the dc->pvt read AND the dtls write here, and (in detach,
 * STEP (b)) around the dc->pvt = NULL store. This makes the read/write race-free and gives a strict
 * happens-before: once detach has published dc->pvt = NULL under the lock, every cb that later
 * acquires the lock observes NULL and bails. Holding the lock across the dtls write means a cb that
 * DID snapshot a non-NULL pvt completes its write BEFORE it releases the lock — and detach's STEP (b)
 * store cannot interleave; combined with the abort-close fence (which still bounds the cb's lifetime
 * before usrsctp_close returns, hence before the destructor frees rtp), no cb is ever mid-write when
 * rtp is freed. The lock is the BELT (publication ordering + no torn read); the abort-close is the
 * BRACES (lifetime fence). Both are required.
 *
 * ABBA / lock-order proof (load-bearing): the ONLY nesting introduced here is
 *   [usrsctp TCB lock, held by usrsctp on entry] -> ao2_lock(dc) -> ao2_lock(instance)
 * (the instance lock is taken INSIDE ast_rtp_instance_dtls_write_appdata). Detach NEVER takes the dc
 * lock then a usrsctp lock: STEP (b) takes ao2_lock(dc) ONLY around the bare NULL store and releases
 * it BEFORE the abort-close in STEP (d), so detach's order is {ao2_lock(dc) alone} ... then
 * {usrsctp TCB lock alone, via usrsctp_close, NO dc lock held}. No thread ever takes dc-lock then a
 * usrsctp lock, and no thread takes instance-lock then dc-lock (the engine RX cb holds the instance
 * lock but takes no dc lock). Hence no cycle: the dc lock can never deadlock against the usrsctp TCB
 * lock or the instance lock. All dc->pvt publish/read sites take ao2_lock(dc) as the single
 * publication lock: the output cb, detach's NULL store, the destructor, sofia_dc_set_pvt, and the
 * sofia_dc_get_bridged_dc snapshot - the last releases it BEFORE the channel/pvt locks in
 * sofia_dc_pair_bridged, so none nests a foreign lock under dc. (detach's own pre-NULL reads run on
 * the teardown thread while pvt/rtp are still live and race no writer.)
 *
 * \retval 0 always (usrsctp treats nonzero as a fatal transport error; a dropped packet retransmits).
 */
static int sofia_dc_sctp_output(void *addr, void *buf, size_t len, uint8_t tos, uint8_t set_df)
{
	struct sofia_datachannel *dc = addr;
	struct sofia_pvt *pvt;

	(void)tos;
	(void)set_df;

	if (!dc) {
		return 0;
	}

	/* Hold ao2_lock(dc) across the dc->pvt read AND the dtls write (see the header proof). detach
	 * STEP (b) NULLs dc->pvt under this same lock, so we either see the live pvt and finish the write
	 * before detach can publish NULL, or we see NULL (detach already ran) and bail — never a torn or
	 * stale pointer, and never a write racing the rtp free. */
	ao2_lock(dc);
	pvt = dc->pvt;
	if (!pvt || !pvt->rtp) {
		ao2_unlock(dc);
		return 0;
	}
	ast_rtp_instance_dtls_write_appdata(pvt->rtp, buf, len);
	ao2_unlock(dc);
	return 0;
}

/* ======================================================================================
 * Stream table helpers (worker-lane only — no lock)
 * ====================================================================================== */

static struct sofia_dc_stream *sofia_dc_stream_find(struct sofia_datachannel *dc, uint16_t local_sid)
{
	unsigned int i;

	for (i = 0; i < dc->n_streams; i++) {
		if (dc->streams[i].local_sid == local_sid) {
			return &dc->streams[i];
		}
	}
	return NULL;
}

/*! \brief Append a fresh entry for \a local_sid (must not already exist). Grows on demand. */
static struct sofia_dc_stream *sofia_dc_stream_add(struct sofia_datachannel *dc, uint16_t local_sid)
{
	struct sofia_dc_stream *st;

	if (dc->n_streams >= SOFIA_DC_STREAMS_MAX) {
		ast_log(LOG_WARNING, "Sofia: DataChannel stream table full (%u) — refusing sid %u\n",
			dc->n_streams, local_sid);
		return NULL;
	}
	if (dc->n_streams == dc->cap_streams) {
		unsigned int newcap = dc->cap_streams ? dc->cap_streams * 2 : SOFIA_DC_STREAMS_INIT;
		struct sofia_dc_stream *grown = ast_realloc(dc->streams, newcap * sizeof(*grown));
		if (!grown) {
			return NULL;
		}
		dc->streams = grown;
		dc->cap_streams = newcap;
	}
	st = &dc->streams[dc->n_streams++];
	memset(st, 0, sizeof(*st));
	st->local_sid = local_sid;
	st->peer_sid = SOFIA_DC_SID_NONE;
	return st;
}

/*! \brief Drop the entry for \a local_sid (swap-with-last; order is irrelevant). */
static void sofia_dc_stream_remove(struct sofia_datachannel *dc, uint16_t local_sid)
{
	unsigned int i;

	for (i = 0; i < dc->n_streams; i++) {
		if (dc->streams[i].local_sid == local_sid) {
			dc->streams[i] = dc->streams[--dc->n_streams];
			return;
		}
	}
}

/*! \brief Request an OUTGOING stream reset on \a local_sid (RFC 8831 §6.7 channel close / RFC 6525). */
static void sofia_dc_reset_stream(struct sofia_datachannel *dc, uint16_t local_sid)
{
	struct {
		struct sctp_reset_streams srs;
		uint16_t sid;	/* the one-element srs_stream_list[] */
	} req;

	if (!dc || !dc->sctp_sock) {
		return;
	}
	memset(&req, 0, sizeof(req));
	req.srs.srs_assoc_id = SCTP_ALL_ASSOC;
	req.srs.srs_flags = SCTP_STREAM_RESET_OUTGOING;
	req.srs.srs_number_streams = 1;
	req.sid = local_sid;
	if (usrsctp_setsockopt(dc->sctp_sock, IPPROTO_SCTP, SCTP_RESET_STREAMS, &req, sizeof(req)) < 0) {
		ast_debug(2, "Sofia: DataChannel stream %u reset request failed: %s\n",
			local_sid, strerror(errno));
	}
}

/* ======================================================================================
 * Stream-aware send — PR-SCTP policy per channel type
 * ====================================================================================== */

/*!
 * \brief Send one DataChannel message on a specific stream, honoring channel-type semantics.
 *
 * \param sid          the OUTGOING stream id on this leg.
 * \param ppid         the SCTP PPID (RFC 8831 §8); htonl'd onto the wire here.
 * \param ordered      1 = ordered delivery; 0 = SCTP_UNORDERED.
 * \param channel_type RFC 8832 §6.1 — selects the PR-SCTP policy (reliable / rexmit / timed).
 * \param reliability  the channel's reliability parameter (rexmit count or TTL ms).
 *
 * Always sets SCTP_EOR (one application message == one SCTP user message, RFC 8831 §6.6). Uses
 * SCTP_SENDV_SPA so we can attach an sctp_prinfo for the partial-reliability channel types; the
 * reliable types send with SCTP_PR_SCTP_NONE (a no-op policy).
 */
static int sofia_dc_send_on(struct sofia_datachannel *dc, uint16_t sid, uint32_t ppid, int ordered,
	uint8_t channel_type, uint32_t reliability, const void *buf, size_t len)
{
	struct sctp_sendv_spa spa;
	ssize_t rc;

	if (!dc || !dc->sctp_sock) {
		return -1;
	}

	memset(&spa, 0, sizeof(spa));
	spa.sendv_flags = SCTP_SEND_SNDINFO_VALID;
	spa.sendv_sndinfo.snd_sid = sid;
	spa.sendv_sndinfo.snd_ppid = htonl(ppid);
	spa.sendv_sndinfo.snd_flags = SCTP_EOR | (ordered ? 0 : SCTP_UNORDERED);

	/* Map the RFC 8832 channel type to a PR-SCTP policy. The two unordered variants share the low
	 * reliability bits with their ordered twins (the 0x80 bit is ordering, handled above). */
	switch (channel_type & ~SOFIA_DC_CT_UNORDERED_BIT) {
	case SOFIA_DC_CT_PARTIAL_REXMIT:	/* unreliable, bounded retransmits */
		spa.sendv_flags |= SCTP_SEND_PRINFO_VALID;
		spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_RTX;
		spa.sendv_prinfo.pr_value = reliability;
		break;
	case SOFIA_DC_CT_PARTIAL_TIMED:		/* unreliable, time-limited (ms) */
		spa.sendv_flags |= SCTP_SEND_PRINFO_VALID;
		spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_TTL;
		spa.sendv_prinfo.pr_value = reliability;
		break;
	default:				/* SOFIA_DC_CT_RELIABLE — fully reliable */
		spa.sendv_flags |= SCTP_SEND_PRINFO_VALID;
		spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_NONE;
		spa.sendv_prinfo.pr_value = 0;
		break;
	}

	rc = usrsctp_sendv(dc->sctp_sock, buf, len, NULL, 0,
		&spa, sizeof(spa), SCTP_SENDV_SPA, 0);
	if (rc < 0) {
		ast_debug(1, "Sofia: DataChannel send failed (sid=%u ppid=%u len=%zu): %s\n",
			sid, ppid, len, strerror(errno));
		return -1;
	}
	return 0;
}

int sofia_dc_send(struct sofia_datachannel *dc, uint32_t ppid, const void *data, size_t len)
{
	if (!dc || !data) {
		return -1;
	}
	/* Compat wrapper: ordered/reliable on stream 0. Real per-stream relay uses sofia_dc_send_on. */
	return sofia_dc_send_on(dc, 0, ppid, /*ordered=*/1, SOFIA_DC_CT_RELIABLE, 0, data, len);
}

/* ======================================================================================
 * Far-leg pairing — trylock + ref-out + release-before-send
 * ====================================================================================== */

/*!
 * \brief Resolve the bridged leg's DataChannel, +1-reffed, with NO channel lock held on return.
 *
 * This is THE cross-leg primitive (the cross-leg locking primitive). The contract-correct channel-walk +
 * far-pvt resolution lives in chan_sofia.c::sofia_dc_pair_bridged() — where sofia_pvt internals,
 * sofia_tech, and the canonical lock order (channel -> pvt -> peer) are all in scope, and where
 * the ast_bridged_channel() locking contract (channel.h:2318-2327, "lock self before the call AND
 * while the result is used") can be honored: the worker lane runs OUTSIDE the owning channel
 * thread, so a raw ast_bridged_channel(self) without self locked would be a UAF. Here we only
 * snapshot the raw back-ref and delegate.
 *
 * It NEVER blocks on the far channel lock — on contention sofia_dc_pair_bridged returns NULL (a
 * "retry": the caller drops the message and SCTP retransmits / the browser reopens). The caller
 * does usrsctp_sendv AFTER this returns (off every channel lock) then ao2_ref(-1) the result.
 *
 * NO-ABBA proof: sofia_dc_pair_bridged acquires the FAR channel lock by ast_channel_trylock ONLY
 * (never blocking); it may block on SELF's own lock but holds nothing else when it does and drops
 * self's lock before touching far. We hold NO channel/pvt lock here (the worker lane runs off the
 * instance lock), and the far channel lock is released before return — the caller's usrsctp_sendv
 * therefore runs with no channel lock held. far_pvt->lock is taken in channel -> pvt order and
 * released before return.
 *
 * NO-INVERSION proof: the only re-entrancy of usrsctp_sendv is the global output cb
 * (sofia_dc_sctp_output), which takes the engine INSTANCE lock (inside
 * ast_rtp_instance_dtls_write_appdata), never a channel/pvt lock — and we hold neither when the
 * caller sends. The single shared worker lane serializes A-recv vs B-recv, so an
 * A->B sendv never races a B conninput from another thread (the load-bearing invariant; sharding
 * the lane would invalidate this and must re-derive the proof).
 *
 * \retval a +1-reffed far sofia_datachannel* on success (caller must ao2_ref(-1)).
 * \retval NULL when there is no bridged sofia leg, it has no DC, contention (trylock failed), or
 *         a self-loop — the caller drops the in-flight message.
 */
static struct sofia_datachannel *sofia_dc_get_bridged_dc(struct sofia_datachannel *self_dc)
{
	struct sofia_pvt *self_pvt;

	if (!self_dc) {
		return NULL;
	}

	/* Snapshot the raw back-ref ONCE into a local (a fork-steal repoints dc->pvt on
	 * the sofia thread; a single read here avoids observing a torn old/new value mid-relay). The
	 * steal repoints — it does not free the old pvt synchronously — so a stale-but-valid pvt at
	 * worst routes to a leg being torn down → sofia_dc_pair_bridged returns NULL → drop. */
	ao2_lock(self_dc);
	self_pvt = self_dc->pvt;
	ao2_unlock(self_dc);
	if (!self_pvt) {
		return NULL;
	}

	/* Delegate to the contract-correct pairing helper (chan_sofia.c). It does the full lock/ref
	 * dance: self_pvt->lock to pin the owner, self channel LOCKED for ast_bridged_channel, FAR
	 * channel trylock'd, far_pvt->lock for the dc read/ref — and returns a +1 sofia_datachannel*
	 * (an opaque void* there) with NO lock held. */
	return sofia_dc_pair_bridged(self_pvt, self_dc);
}

/* ======================================================================================
 * DCEP (RFC 8832) — strict, unaligned-safe parse + OPEN/ACK + OPEN-proxying
 * ====================================================================================== */

/*! \brief A parsed DATA_CHANNEL_OPEN (fields copied OUT — never a cast over the unaligned buffer). */
struct sofia_dcep_open {
	uint8_t channel_type;
	uint16_t priority;
	uint32_t reliability;
	char label[64];
	char protocol[64];
};

/*! \brief Big-endian helpers (the usrsctp data buffer has no alignment guarantee). */
static uint16_t sofia_dc_get_be16(const uint8_t *p)
{
	return (uint16_t)((p[0] << 8) | p[1]);
}
static uint32_t sofia_dc_get_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/*!
 * \brief Parse a DATA_CHANNEL_OPEN (RFC 8832 §5.1) — strict, bounds-checked, unaligned-safe.
 *
 * v1 caps label and protocol at sizeof(out->label)-1 == 63 bytes each (the fixed inline fields).
 * RFC 8832 §5.1 allows variable-length label/protocol up to 65535 bytes, but we must NEVER silently
 * TRUNCATE: a truncated label/protocol would change the application-visible channel identity that
 * sofia_dc_send_open then mirrors to the far browser. So an OPEN whose
 * label or protocol exceeds the 63-byte v1 cap is REJECTED here (the caller resets the stream on -1,
 * exactly as for a malformed OPEN) rather than proxied with a changed identity.
 *
 * \retval 0 on a well-formed OPEN within the v1 caps (fields copied into \a out, NUL-terminated).
 * \retval -1 on any malformation (short header, length mismatch) OR label/protocol over the v1 cap.
 */
static int sofia_dc_parse_open(const uint8_t *data, size_t datalen, struct sofia_dcep_open *out)
{
	uint16_t label_len, proto_len;

	if (datalen < SOFIA_DCEP_OPEN_HDR_LEN) {
		return -1;
	}
	/* data[0] (== 0x03) already checked by the caller. */
	out->channel_type = data[1];
	out->priority = sofia_dc_get_be16(data + 2);
	out->reliability = sofia_dc_get_be32(data + 4);
	label_len = sofia_dc_get_be16(data + 8);
	proto_len = sofia_dc_get_be16(data + 10);

	/* Exact length match — no overrun, no trailing slack (RFC 8832 §6.4: well-formed or close). */
	if ((size_t)SOFIA_DCEP_OPEN_HDR_LEN + label_len + proto_len != datalen) {
		return -1;
	}

	/* v1 cap: reject rather than truncate — a truncated label/protocol
	 * would mis-mirror the channel identity to the far leg. 63 bytes each (the inline field minus the
	 * NUL). label_len/proto_len < sizeof(field) leaves exactly one byte for the terminator. */
	if (label_len >= sizeof(out->label) || proto_len >= sizeof(out->protocol)) {
		return -1;
	}

	memcpy(out->label, data + SOFIA_DCEP_OPEN_HDR_LEN, label_len);
	out->label[label_len] = '\0';
	memcpy(out->protocol, data + SOFIA_DCEP_OPEN_HDR_LEN + label_len, proto_len);
	out->protocol[proto_len] = '\0';
	return 0;
}

/*! \brief True iff \a channel_type is one of the six RFC 8832 §6.1 legal values. */
static int sofia_dc_channel_type_ok(uint8_t ct)
{
	switch (ct) {
	case SOFIA_DC_CT_RELIABLE:
	case SOFIA_DC_CT_RELIABLE_UNORDERED:
	case SOFIA_DC_CT_PARTIAL_REXMIT:
	case SOFIA_DC_CT_PARTIAL_REXMIT_UNORDERED:
	case SOFIA_DC_CT_PARTIAL_TIMED:
	case SOFIA_DC_CT_PARTIAL_TIMED_UNORDERED:
		return 1;
	default:
		return 0;
	}
}

/*! \brief 1 if \a channel_type uses ordered delivery (the 0x80 bit clear). */
static int sofia_dc_type_ordered(uint8_t ct)
{
	return (ct & SOFIA_DC_CT_UNORDERED_BIT) ? 0 : 1;
}

/*! \brief Send a one-byte DATA_CHANNEL_ACK (0x02) on \a sid (PPID 50, ordered+reliable, RFC 8832 §5.2). */
static void sofia_dc_send_ack(struct sofia_datachannel *dc, uint16_t sid)
{
	uint8_t ack = SOFIA_DCEP_ACK;
	sofia_dc_send_on(dc, sid, SOFIA_DC_PPID_DCEP, /*ordered=*/1, SOFIA_DC_CT_RELIABLE, 0, &ack, 1);
}

/*!
 * \brief Build + send a DATA_CHANNEL_OPEN (0x03) on \a sid mirroring \a o (PPID 50, ordered+reliable).
 * \retval 0 success, -1 on framing/send failure.
 */
static int sofia_dc_send_open(struct sofia_datachannel *dc, uint16_t sid,
	const struct sofia_dcep_open *o)
{
	uint8_t buf[SOFIA_DCEP_OPEN_HDR_LEN + 2 * sizeof(o->label)];
	size_t label_len = strlen(o->label);
	size_t proto_len = strlen(o->protocol);
	size_t off;

	if (SOFIA_DCEP_OPEN_HDR_LEN + label_len + proto_len > sizeof(buf)) {
		return -1;	/* label/protocol already bounded to <64 each by the parse, so this never trips */
	}
	buf[0] = SOFIA_DCEP_OPEN;
	buf[1] = o->channel_type;
	buf[2] = (uint8_t)(o->priority >> 8);
	buf[3] = (uint8_t)(o->priority & 0xff);
	buf[4] = (uint8_t)(o->reliability >> 24);
	buf[5] = (uint8_t)(o->reliability >> 16);
	buf[6] = (uint8_t)(o->reliability >> 8);
	buf[7] = (uint8_t)(o->reliability & 0xff);
	buf[8] = (uint8_t)(label_len >> 8);
	buf[9] = (uint8_t)(label_len & 0xff);
	buf[10] = (uint8_t)(proto_len >> 8);
	buf[11] = (uint8_t)(proto_len & 0xff);
	off = SOFIA_DCEP_OPEN_HDR_LEN;
	memcpy(buf + off, o->label, label_len);
	off += label_len;
	memcpy(buf + off, o->protocol, proto_len);
	off += proto_len;

	return sofia_dc_send_on(dc, sid, SOFIA_DC_PPID_DCEP, /*ordered=*/1, SOFIA_DC_CT_RELIABLE, 0,
		buf, off);
}

/*! \brief Pick the lowest free OUTGOING stream id of OUR parity on \a dc, or SOFIA_DC_SID_NONE. */
static uint16_t sofia_dc_alloc_local_sid(struct sofia_datachannel *dc)
{
	/* RFC 8832 §6: DTLS client opens EVEN streams, DTLS server opens ODD streams. We are the DCEP
	 * initiator on the proxied (far) leg, so we pick OUR parity. */
	uint16_t sid = dc->dtls_is_server ? 1 : 0;
	/* Stop at the NEGOTIATED outbound stream count, never the bare request: if
	 * the peer granted fewer streams than SOFIA_DC_INITMSG_STREAMS, a sid >= dc->out_streams is invalid
	 * and the peer would reject the OPEN. Use min(negotiated, the request cap); before SCTP_COMM_UP
	 * (out_streams == 0) fall back to the request cap — proxy_open only runs once dc->associated. */
	uint16_t limit = dc->out_streams ? dc->out_streams : SOFIA_DC_INITMSG_STREAMS;
	if (limit > SOFIA_DC_INITMSG_STREAMS) {
		limit = SOFIA_DC_INITMSG_STREAMS;
	}

	while (sid < limit) {
		if (!sofia_dc_stream_find(dc, sid)) {
			return sid;
		}
		if (sid > SOFIA_DC_SID_NONE - 2) {
			break;
		}
		sid += 2;
	}
	return SOFIA_DC_SID_NONE;
}

/*!
 * \brief A valid OPEN landed on \a near_dc:near_sid → proxy a matching channel onto the far leg.
 *
 * Cross-leg: resolve the far dc, and if it is COMM_UP, allocate a fresh stream of the FAR
 * leg's parity, send a mirrored OPEN there, and record the A:near_sid <-> far:new_sid mapping on
 * BOTH dcs.
 *
 * Returns 0 ONLY when the far OPEN is queued AND both mappings are set; the caller ACKs the near sid
 * exactly in that case (never ACK an unpaired near stream). Returns -1 on any
 * failure — no bridged DC, far leg not yet associated (the realistic A-before-B DTLS race), far leg
 * out of streams, allocation, or send. On -1 the near side is NOT ACKed and the caller resets the
 * near stream, so the browser sees setup failure and reopens once both legs are associated
 * (drop + browser reopen, now signalled via a missing ACK rather than a silent ACK).
 *
 * \retval 0  far OPEN queued + both mappings set (ACK the near sid).
 * \retval -1 not proxied — do NOT ACK; the caller resets the near stream.
 */
static int sofia_dc_proxy_open(struct sofia_datachannel *near_dc, uint16_t near_sid,
	const struct sofia_dcep_open *o)
{
	struct sofia_datachannel *far_dc;
	struct sofia_dc_stream *near_st;
	struct sofia_dc_stream *far_st;
	uint16_t far_sid;

	far_dc = sofia_dc_get_bridged_dc(near_dc);
	if (!far_dc) {
		ast_debug(2, "Sofia: DataChannel OPEN sid=%u — no bridged DC (no ACK, reset near)\n", near_sid);
		return -1;
	}
	if (!far_dc->associated) {
		ast_debug(2, "Sofia: DataChannel OPEN sid=%u — far leg not yet associated (no ACK, reset near)\n",
			near_sid);
		ao2_ref(far_dc, -1);
		return -1;
	}

	far_sid = sofia_dc_alloc_local_sid(far_dc);
	if (far_sid == SOFIA_DC_SID_NONE) {
		ast_log(LOG_WARNING, "Sofia: DataChannel OPEN sid=%u — far leg out of streams (no ACK)\n",
			near_sid);
		ao2_ref(far_dc, -1);
		return -1;
	}

	far_st = sofia_dc_stream_add(far_dc, far_sid);
	if (!far_st) {
		ao2_ref(far_dc, -1);
		return -1;
	}
	far_st->peer_sid = near_sid;
	far_st->channel_type = o->channel_type;
	far_st->reliability_param = o->reliability;
	far_st->local_open = 1;		/* WE originated this OPEN */
	ast_copy_string(far_st->label, o->label, sizeof(far_st->label));
	ast_copy_string(far_st->protocol, o->protocol, sizeof(far_st->protocol));

	/* Map the near side back to the far stream (the near entry was added by the caller). */
	near_st = sofia_dc_stream_find(near_dc, near_sid);
	if (near_st) {
		near_st->peer_sid = far_sid;
	}

	if (sofia_dc_send_open(far_dc, far_sid, o) < 0) {
		/* Roll back the far mapping + the near pairing; the caller resets the near stream (no ACK). */
		sofia_dc_stream_remove(far_dc, far_sid);
		if (near_st) {
			near_st->peer_sid = SOFIA_DC_SID_NONE;
		}
		ao2_ref(far_dc, -1);
		return -1;
	}

	ast_debug(2, "Sofia: DataChannel proxied OPEN near:sid=%u <-> far:sid=%u (type=0x%02x label='%s')\n",
		near_sid, far_sid, o->channel_type, o->label);
	ao2_ref(far_dc, -1);
	return 0;
}

/*! \brief Handle a PPID-50 DCEP message (OPEN or ACK) arriving on \a dc:sid. */
static void sofia_dc_handle_dcep(struct sofia_datachannel *dc, uint16_t sid,
	const uint8_t *data, size_t datalen)
{
	uint8_t msg_type;
	struct sofia_dcep_open o;
	struct sofia_dc_stream *st;

	if (datalen < 1) {
		ast_debug(1, "Sofia: DataChannel empty DCEP on sid=%u — drop\n", sid);
		return;
	}
	msg_type = data[0];

	if (msg_type == SOFIA_DCEP_ACK) {
		/* The far browser ACKed an OPEN we proxied onto this leg. */
		st = sofia_dc_stream_find(dc, sid);
		if (st) {
			st->acked = 1;
			ast_debug(2, "Sofia: DataChannel ACK on sid=%u (channel fully open)\n", sid);
		} else {
			ast_debug(1, "Sofia: DataChannel ACK on unknown sid=%u — drop\n", sid);
		}
		return;
	}

	if (msg_type != SOFIA_DCEP_OPEN) {
		/* Unknown DCEP message → close the channel (RFC 8832 §6.4). */
		ast_log(LOG_NOTICE, "Sofia: DataChannel unknown DCEP type 0x%02x on sid=%u — reset\n",
			msg_type, sid);
		sofia_dc_reset_stream(dc, sid);
		return;
	}

	/* DATA_CHANNEL_OPEN. Strict parse (copies fields out; never casts the unaligned buffer). */
	if (sofia_dc_parse_open(data, datalen, &o) < 0) {
		ast_log(LOG_NOTICE, "Sofia: DataChannel malformed OPEN on sid=%u (len=%zu) — reset\n",
			sid, datalen);
		sofia_dc_reset_stream(dc, sid);
		return;
	}

	/* Parity: the PEER opened this stream, so its sid parity must match the PEER's DTLS role =
	 * the OPPOSITE of ours (RFC 8832 §6.5). We are server(odd) => peer is client(even), and vice
	 * versa. peer_should_be_even == our dtls_is_server. */
	{
		int sid_even = ((sid & 1) == 0);
		int peer_should_be_even = dc->dtls_is_server ? 1 : 0;
		if (sid_even != peer_should_be_even) {
			ast_log(LOG_NOTICE, "Sofia: DataChannel OPEN sid=%u wrong parity (we are DTLS %s) — reset\n",
				sid, dc->dtls_is_server ? "server" : "client");
			sofia_dc_reset_stream(dc, sid);
			return;
		}
	}

	if (!sofia_dc_channel_type_ok(o.channel_type)) {
		ast_log(LOG_NOTICE, "Sofia: DataChannel OPEN sid=%u bad channel type 0x%02x — reset\n",
			sid, o.channel_type);
		sofia_dc_reset_stream(dc, sid);
		return;
	}

	if (sofia_dc_stream_find(dc, sid)) {
		/* Already-used stream (duplicate OPEN) → close (RFC 8832 §6.5). */
		ast_log(LOG_NOTICE, "Sofia: DataChannel OPEN on already-used sid=%u — reset\n", sid);
		sofia_dc_reset_stream(dc, sid);
		return;
	}

	/* Record the near-side stream (peer-opened). NOT yet acked — we ACK only once the far OPEN is
	 * queued. */
	st = sofia_dc_stream_add(dc, sid);
	if (!st) {
		sofia_dc_reset_stream(dc, sid);
		return;
	}
	st->channel_type = o.channel_type;
	st->reliability_param = o.reliability;
	st->local_open = 0;
	st->acked = 0;
	ast_copy_string(st->label, o.label, sizeof(st->label));
	ast_copy_string(st->protocol, o.protocol, sizeof(st->protocol));

	/* PROXY FIRST, ACK ON SUCCESS. Proxy a matching OPEN onto the far leg;
	 * ACK the near sid (RFC 8832 §5.2) ONLY when proxy_open returned 0 (far OPEN queued + both
	 * mappings set). On proxy failure (no bridged DC, far not associated, out of streams, send fail)
	 * we reset+remove the near stream and send NO ACK, so the browser sees setup failure and reopens
	 * once both legs are associated — never an ACKed near stream with no far peer. */
	if (sofia_dc_proxy_open(dc, sid, &o) == 0) {
		st->acked = 1;
		sofia_dc_send_ack(dc, sid);
	} else {
		sofia_dc_reset_stream(dc, sid);
		sofia_dc_stream_remove(dc, sid);
	}
}

/* ======================================================================================
 * User-message relay (PPID 51/53/56/57) — both directions
 * ====================================================================================== */

static void sofia_dc_relay_user(struct sofia_datachannel *dc, uint16_t sid, uint32_t ppid,
	const uint8_t *data, size_t datalen)
{
	struct sofia_dc_stream *near_st;
	struct sofia_datachannel *far_dc;
	uint16_t far_sid;
	uint8_t far_type;
	uint32_t far_reliability;
	uint32_t cap;
	struct sofia_dc_stream *far_st;

	near_st = sofia_dc_stream_find(dc, sid);
	if (!near_st) {
		/* User data on an unused stream is an error (RFC 8832 §6.6) → close. */
		ast_log(LOG_NOTICE, "Sofia: DataChannel user data on unmapped sid=%u — reset\n", sid);
		sofia_dc_reset_stream(dc, sid);
		return;
	}
	if (near_st->peer_sid == SOFIA_DC_SID_NONE) {
		/* Opened locally but never paired (e.g. far leg was down at OPEN time) → drop (v1). */
		ast_debug(2, "Sofia: DataChannel user data on unpaired sid=%u — drop\n", sid);
		return;
	}
	far_sid = near_st->peer_sid;

	far_dc = sofia_dc_get_bridged_dc(dc);
	if (!far_dc) {
		ast_debug(2, "Sofia: DataChannel relay sid=%u — no bridged DC (drop)\n", sid);
		return;
	}

	/* Cap each forwarded message per RFC 8841 §6, distinguishing ABSENT from explicit 0.
	 * The far peer's advertised max is the FORWARD-direction limit (we send TO the far
	 * leg, so its max-message-size binds):
	 *   - ABSENT (peer_max_msg == 0)                  -> 65536 (the RFC default).
	 *   - explicit 0 / unbounded (PEER_MAX_UNBOUNDED) -> 262144 (our hard ceiling, nothing smaller).
	 *   - explicit N                                  -> min(N, 262144).
	 * usrsctp reassembles, so 256 KB is fine; an oversized message is DROPPED (we must not fragment a
	 * single DataChannel message). */
	if (far_dc->peer_max_msg == 0) {
		cap = SOFIA_DC_DEFAULT_PEER_MAX;			/* absent -> 65536 */
	} else if (far_dc->peer_max_msg == SOFIA_DC_PEER_MAX_UNBOUNDED) {
		cap = SOFIA_DC_HARD_MAX_MSG;			/* explicit 0 / unbounded -> hard cap */
	} else {
		cap = far_dc->peer_max_msg < SOFIA_DC_HARD_MAX_MSG
			? far_dc->peer_max_msg : SOFIA_DC_HARD_MAX_MSG;	/* explicit N -> min(N, 262144) */
	}
	if (datalen > cap) {
		ast_log(LOG_NOTICE, "Sofia: DataChannel message %zu > cap %u on sid=%u — drop\n",
			datalen, cap, sid);
		ao2_ref(far_dc, -1);
		return;
	}

	/* Use the FAR stream's negotiated channel type for ordering + PR-SCTP policy (its OPEN carried
	 * the semantics the far browser expects). Fall back to the near type if the far entry vanished. */
	far_st = sofia_dc_stream_find(far_dc, far_sid);
	if (far_st) {
		far_type = far_st->channel_type;
		far_reliability = far_st->reliability_param;
	} else {
		far_type = near_st->channel_type;
		far_reliability = near_st->reliability_param;
	}

	/* RFC 8832 §6: before the DATA_CHANNEL_ACK (or any message) is seen on the far channel, EVERY
	 * user message MUST be sent ORDERED regardless of the negotiated ordering. gabpbx originates the
	 * far OPEN (sofia_dc_send_on), so this opening-side rule binds the relay too. far_st->acked is
	 * maintained at OPEN/ACK time but was never read here — honor it now: force ordered until the
	 * far ACK has arrived. (If the far stream vanished, far_st is NULL → default ordered, the safe
	 * choice.) The negotiated unordered bit takes over only AFTER the ack. */
	{
		int far_ordered = sofia_dc_type_ordered(far_type) || !far_st || !far_st->acked;

		/* PPID-preserving relay (51->51, 53->53, 56->56, 57->57). The empty-message PPIDs carry a
		 * single zero byte on the wire (RFC 8831 §6.6); pass datalen through unchanged. */
		sofia_dc_send_on(far_dc, far_sid, ppid, far_ordered, far_type,
			far_reliability, data, datalen);
	}

	ao2_ref(far_dc, -1);
}

/* ======================================================================================
 * Notifications — assoc up/down, stream reset, send-failed, shutdown
 * ====================================================================================== */

/*! \brief Drop every stream mapping on \a dc, resetting the paired far streams best-effort. */
static void sofia_dc_drop_all_streams(struct sofia_datachannel *dc)
{
	struct sofia_datachannel *far_dc = NULL;
	unsigned int i;

	/* Resolve the far leg ONCE (it is the same far leg for all of this dc's streams). */
	far_dc = sofia_dc_get_bridged_dc(dc);
	for (i = 0; i < dc->n_streams; i++) {
		uint16_t peer = dc->streams[i].peer_sid;
		if (far_dc && peer != SOFIA_DC_SID_NONE) {
			sofia_dc_reset_stream(far_dc, peer);
			sofia_dc_stream_remove(far_dc, peer);
		}
	}
	if (far_dc) {
		ao2_ref(far_dc, -1);
	}
	dc->n_streams = 0;	/* the table is now empty (entries were swap-removed above as needed) */
}

static void sofia_dc_handle_assoc_change(struct sofia_datachannel *dc,
	const struct sctp_assoc_change *sac)
{
	switch (sac->sac_state) {
	case SCTP_COMM_UP:
		dc->associated = 1;
		/* Record the negotiated stream counts. sofia_dc_alloc_local_sid caps
		 * the OUTBOUND sid at this so a proxied OPEN never picks a stream the peer did not grant. */
		dc->out_streams = sac->sac_outbound_streams;
		dc->in_streams = sac->sac_inbound_streams;
		ast_debug(2, "Sofia: DataChannel association UP (out=%u in=%u streams)\n",
			sac->sac_outbound_streams, sac->sac_inbound_streams);
		break;
	case SCTP_RESTART:
		/* SCTP_RESTART is a DISTINCT state from COMM_UP/COMM_LOST (RFC 6458 §6.1.1, RFC 4960 §5.2.4):
		 * the peer restarted the association — it is UP AGAIN, NOT lost and NOT a fresh COMM_UP. No
		 * COMM_UP follows a restart, so routing it through the DOWN branch (associated=0) would leave
		 * associated PERMANENTLY 0 with no re-up path → every later sofia_dc_proxy_open bails on
		 * !far_dc->associated and the whole DC relay wedges. Keep associated=1, refresh the (possibly
		 * RENEGOTIATED) stream counts from THIS event, and drop the now-stale A:sid<->B:sid mappings: a
		 * restart re-initializes all SCTP streams (RFC 4960 §5.2.4), so the old stream table is invalid.
		 * After the drop the browser re-OPENs its channels and sofia_dc_proxy_open re-pairs them. */
		dc->associated = 1;
		dc->out_streams = sac->sac_outbound_streams;
		dc->in_streams = sac->sac_inbound_streams;
		ast_debug(2, "Sofia: DataChannel association RESTART (out=%u in=%u streams) — UP again, dropping %u stale streams\n",
			sac->sac_outbound_streams, sac->sac_inbound_streams, dc->n_streams);
		sofia_dc_drop_all_streams(dc);
		break;
	case SCTP_COMM_LOST:
	case SCTP_SHUTDOWN_COMP:
	case SCTP_CANT_STR_ASSOC:
		ast_debug(2, "Sofia: DataChannel association DOWN (state=%u) — dropping %u streams\n",
			sac->sac_state, dc->n_streams);
		dc->associated = 0;
		sofia_dc_drop_all_streams(dc);
		break;
	default:
		ast_debug(2, "Sofia: DataChannel assoc-change state=%u (ignored)\n", sac->sac_state);
		break;
	}
}

static void sofia_dc_handle_stream_reset(struct sofia_datachannel *dc,
	const struct sctp_stream_reset_event *evt, size_t len)
{
	size_t list_off = offsetof(struct sctp_stream_reset_event, strreset_stream_list);
	size_t n, k;
	struct sofia_datachannel *far_dc = NULL;

	if (len < list_off) {
		return;
	}
	/* DENIED/FAILED: the request was refused — leave the entries as-is (best effort, no retry). */
	if (evt->strreset_flags & (SCTP_STREAM_RESET_DENIED | SCTP_STREAM_RESET_FAILED)) {
		ast_debug(2, "Sofia: DataChannel stream reset denied/failed (flags=0x%04x)\n",
			evt->strreset_flags);
		return;
	}
	/* Only act on the INCOMING half (the peer closed its outgoing → our incoming). The OUTGOING
	 * confirmation (our own reset completing) needs no cross-leg action. */
	if (!(evt->strreset_flags & SCTP_STREAM_RESET_INCOMING_SSN)) {
		return;
	}

	n = (len - list_off) / sizeof(uint16_t);
	if (n == 0) {
		return;
	}

	far_dc = sofia_dc_get_bridged_dc(dc);
	for (k = 0; k < n; k++) {
		uint16_t sid = evt->strreset_stream_list[k];
		struct sofia_dc_stream *st = sofia_dc_stream_find(dc, sid);
		uint16_t peer;
		if (!st) {
			continue;	/* unknown sid — benign */
		}
		peer = st->peer_sid;
		sofia_dc_stream_remove(dc, sid);	/* the near channel is closed */
		if (far_dc && peer != SOFIA_DC_SID_NONE) {
			/* Mirror the close onto the far leg (RFC 8831 §6.7). */
			sofia_dc_reset_stream(far_dc, peer);
			sofia_dc_stream_remove(far_dc, peer);
		}
		ast_debug(2, "Sofia: DataChannel stream %u reset (mirrored far sid=%u)\n", sid, peer);
	}
	if (far_dc) {
		ao2_ref(far_dc, -1);
	}
}

static void sofia_dc_handle_notification(struct sofia_datachannel *dc,
	const union sctp_notification *n, size_t len)
{
	if (len < sizeof(n->sn_header)) {
		return;
	}
	switch (n->sn_header.sn_type) {
	case SCTP_ASSOC_CHANGE:
		if (len >= sizeof(struct sctp_assoc_change)) {
			sofia_dc_handle_assoc_change(dc, &n->sn_assoc_change);
		}
		break;
	case SCTP_STREAM_RESET_EVENT:
		sofia_dc_handle_stream_reset(dc, &n->sn_strreset_event, len);
		break;
	case SCTP_SEND_FAILED_EVENT:
		ast_debug(2, "Sofia: DataChannel send-failed notification (len=%zu)\n", len);
		break;
	case SCTP_SHUTDOWN_EVENT:
		ast_debug(2, "Sofia: DataChannel shutdown notification — association closing\n");
		dc->associated = 0;
		break;
	default:
		ast_debug(2, "Sofia: DataChannel notification type=0x%04x (ignored)\n",
			n->sn_header.sn_type);
		break;
	}
}

/* ======================================================================================
 * usrsctp per-socket receive callback (DCEP responder + relay)
 * ====================================================================================== */

/*!
 * \brief usrsctp delivers a fully reassembled message (or a notification) here.
 *
 * Runs synchronously inside usrsctp_conninput on the worker lane — NO instance/pvt/channel lock held
 * on entry. usrsctp passes ownership of \a data to us; we MUST free it (system free, not ast_free —
 * usrsctp allocated it) and return 1 (consumed). The single worker lane serializes A-recv vs B-recv,
 * so the stream tables (mutated here + via the far-leg helpers) need no lock.
 *
 * NEVER crash on a hostile peer: every malformed/oversized/unmapped case logs + drops (and resets
 * the offending stream where RFC 8832 requires a channel close).
 */
static int sofia_dc_sctp_recv_cb(struct socket *sock, union sctp_sockstore addr, void *data,
	size_t datalen, struct sctp_rcvinfo rcv, int flags, void *ulp_info)
{
	struct sofia_datachannel *dc = ulp_info;	/* the per-socket ulp ptr = this dc (set at socket()) */
	uint32_t ppid;
	uint16_t sid;

	(void)sock;
	(void)addr;

	if (!data) {
		/* usrsctp signals e.g. EOF / no-data with a NULL buffer. */
		return 1;
	}
	if (!dc) {
		free(data);
		return 1;
	}

	if (flags & MSG_NOTIFICATION) {
		sofia_dc_handle_notification(dc, (const union sctp_notification *)data, datalen);
		free(data);
		return 1;
	}

	ppid = ntohl(rcv.rcv_ppid);
	sid = rcv.rcv_sid;

	/* Inbound message-size ceiling. usrsctp reassembles before delivery here, so a peer that exceeds
	 * our advertised a=max-message-size (262144) has already consumed the reassembly queue — drop it +
	 * reset the offending stream so a hostile peer cannot keep pushing oversized messages. Enforced
	 * in-module on RECEIVE; the relay's forward cap only bounds the send direction. */
	if (datalen > SOFIA_DC_HARD_MAX_MSG) {
		ast_log(LOG_NOTICE, "Sofia: DataChannel inbound message %zu > max %u on sid=%u — drop + reset\n",
			datalen, SOFIA_DC_HARD_MAX_MSG, sid);
		sofia_dc_reset_stream(dc, sid);
		free(data);
		return 1;
	}

	switch (ppid) {
	case SOFIA_DC_PPID_DCEP:
		sofia_dc_handle_dcep(dc, sid, data, datalen);
		break;
	case SOFIA_DC_PPID_STRING:
	case SOFIA_DC_PPID_BINARY:
	case SOFIA_DC_PPID_STRING_EMPTY:
	case SOFIA_DC_PPID_BINARY_EMPTY:
		sofia_dc_relay_user(dc, sid, ppid, data, datalen);
		break;
	default:
		/* Unsupported PPID (incl. the deprecated partial 52/54) → close (RFC 8831 §6.6). */
		ast_log(LOG_NOTICE, "Sofia: DataChannel unsupported PPID=%u on sid=%u — reset\n", ppid, sid);
		sofia_dc_reset_stream(dc, sid);
		break;
	}

	free(data);	/* usrsctp gave us ownership; it was allocated by usrsctp's allocator (malloc). */
	return 1;
}

#endif /* HAVE_USRSCTP */
