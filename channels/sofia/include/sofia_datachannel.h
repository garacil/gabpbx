/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

/*! \file sofia_datachannel.h
 * \brief chan_sofia WebRTC DataChannel (RFC 8831/8832) — usrsctp transport over the BUNDLE'd
 *        audio DTLS association. Public API, Phase 2a FOUNDATION ONLY.
 *
 * Design: one usrsctp AF_CONN socket per Sofia leg, bundled on the AUDIO DTLS (pvt->rtp) — no new
 * socket. The transport rides the Phase-1 engine seam (include/gabpbx/rtp_engine.h):
 *   - inbound:  engine RX cb (ast_rtp_instance_set_dtls_appdata_cb) -> usrsctp_conninput()
 *   - outbound: usrsctp GLOBAL output cb -> ast_rtp_instance_dtls_write_appdata(pvt->rtp, ...)
 *
 * Concurrency (the crux): the engine RX cb fires UNDER ao2_lock(instance)
 * from res_rtp_gabpbx's drain loop. On that lock we do NOTHING but copy+refcount+push to a shared
 * taskprocessor; ALL usrsctp/DCEP/relay work runs on the worker lane with NO instance lock held.
 *
 * SCOPE Phase 2a = FOUNDATION ONLY: module skeleton + usrsctp init/finish + attach/detach + the
 * transport seam handoff + the output cb + stubs. NOT YET (clear TODOs below):
 *   - DCEP protocol parse (PPID 50) + OPEN responder/initiator + OPEN-proxying to the far leg
 *   - the message relay (PPIDs 51/53/56/57)
 *   - SDP parse/emit (a=sctp-port RFC 8841, a=mid, m=application) — Phase 3
 */

#ifndef CHAN_SOFIA_DATACHANNEL_H
#define CHAN_SOFIA_DATACHANNEL_H

#include "gabpbx/autoconfig.h"	/* HAVE_USRSCTP (standard GabPBX mechanism, like HAVE_SRTP) */

#include <stddef.h>
#include <stdint.h>

struct sofia_pvt;

/*! Opaque DataChannel transport handle, one per Sofia leg with a negotiated m=application.
 * It is an ao2 object owned by chan_sofia (NOT a sofia-sip object); the usrsctp AF_CONN
 * conn token registered with usrsctp is the sofia_datachannel* itself. */
struct sofia_datachannel;

/*! \brief Sentinel stored in pvt->dc_max_message_size for an EXPLICIT a=max-message-size:0.
 * RFC 8841 §6 distinguishes three cases that must not be conflated: the
 * attribute ABSENT (field == 0 → relay defaults the cap to 65536); an explicit "0" meaning UNBOUNDED
 * (this sentinel → the relay applies our 262144 hard ceiling); and an explicit N (→ min(N, 262144)).
 * Recorded by the SDP parse (sofia_sdp.c), carried to sofia_datachannel::peer_max_msg, consumed by
 * sofia_dc_relay_user's cap logic. */
#define SOFIA_DC_PEER_MAX_UNBOUNDED 0xFFFFFFFFu

#ifdef HAVE_USRSCTP

/*!
 * \brief One-time (refcounted) usrsctp library + shared taskprocessor init.
 * \retval 0 success (or already initialized — refcounted)
 * \retval -1 failure (usrsctp/taskprocessor not available; DataChannel disabled)
 * \note Call from load_module. The very first call runs usrsctp_init(0, global_output_cb, NULL)
 *       and creates the single shared "sofia-datachannel" worker lane.
 */
int sofia_dc_init(void);

/*!
 * \brief Drop the usrsctp/taskprocessor init refcount; on the last ref (module unload) call
 *        usrsctp_finish() (logging a nonzero rc) and free the worker lane.
 * \note Call from unload_module. Must only fully tear down after every DC has detached.
 */
void sofia_dc_finish(void);

/*!
 * \brief Create + connect a usrsctp AF_CONN association for \a pvt's audio DTLS transport.
 * \param pvt the Sofia leg (must have a live pvt->rtp). Stored as a RAW back-ref (NOT reffed,
 *            to avoid an ao2 cycle; repointed in place on a WebRTC fork-steal).
 * \param sctp_port the peer's a=sctp-port (RFC 8841); the AF_CONN self-address port.
 * \retval the new sofia_datachannel* (caller holds the +1 ao2 ref) on success
 * \retval NULL on failure
 * \note Registers sofia_dc_engine_rx on pvt->rtp; the engine then drains DTLS appdata to us.
 *       NOT wired from SDP yet — Phase 3.
 */
struct sofia_datachannel *sofia_dc_attach(struct sofia_pvt *pvt, uint16_t sctp_port);

/*!
 * \brief Update a live DataChannel's peer_max_msg (RFC 8841 a=max-message-size) AFTER attach.
 * \param dc  the handle (may be NULL — no-op).
 * \param max the new value, already encoding the three-valued sentinel semantics from the SDP parse:
 *            0 = ABSENT (relay caps at 65536), SOFIA_DC_PEER_MAX_UNBOUNDED = explicit 0/unbounded
 *            (relay caps at the 262144 hard ceiling), else N (relay caps at min(N, 262144)).
 * \note The OFFER side attaches the DC in provision (default 262144) BEFORE the answer arrives; the
 *       answer parse learns the peer's real value but only updates pvt->dc_max_message_size — this
 *       setter pushes that into the LIVE dc so the relay's cap (which reads far_dc->peer_max_msg) is
 *       correct. A single aligned-word store, the SAME lock-free discipline as the attach-time write
 *       and sofia_dc_set_pvt (peer_max_msg is an aligned uint32_t; the caller runs on the sofia thread,
 *       the relay reads it on the worker lane — aligned-store atomicity, no torn value).
 */
void sofia_dc_set_peer_max_msg(struct sofia_datachannel *dc, unsigned int max);

/*!
 * \brief Recompute a live DataChannel's DTLS role (→ DCEP stream parity) from the engine's NOW-concrete
 *        a=setup, AFTER the answer fixed it (RFC 8832 §6: DTLS client = even streams, server = odd).
 * \param dc the handle (may be NULL — no-op).
 * \note The OFFERER attaches the DC in provision_offer while our a=setup is still ACTPASS, so dtls_is_server
 *       latches 0 (client/even). The peer's ANSWER then fixes our concrete role (answer a=setup:active →
 *       set_setup maps us to PASSIVE = DTLS server = ODD parity, RFC 5763 §5). Call this from the offerer
 *       DC answer-apply path AFTER dtls->set_setup() applied the answer and BEFORE any worker-lane SID
 *       allocation / inbound OPEN parity check, so sofia_dc_alloc_local_sid + the OPEN parity check both
 *       use the corrected role. Without it gabpbx proxies OPENs on even streams the peer rejects AND flags
 *       every legit peer OPEN as wrong-parity → the offerer-direction DataChannel silently fails. A single
 *       1-bit store, done UNDER ao2_lock(dc) - the same publication lock the output cb / set_pvt / detach use for dc->pvt (the relay reads the role on the worker lane after answer-apply).
 */
void sofia_dc_set_dtls_role(struct sofia_datachannel *dc);

/*!
 * \brief Repoint a DataChannel's raw pvt back-ref to a new owning pvt (WebRTC fork-steal).
 *        The DC is bound to the engine *instance* (cb on pvt->rtp), which is itself stolen
 *        master<-child, so NOTHING is re-registered — we only move the back-ref + the cb_data so the
 *        worker lane resolves dc->pvt->rtp to the surviving master leg. No-op when dc is NULL.
 * \param dc  the handle (moved from child to master by the caller).
 * \param pvt the new owning pvt (the fork master).
 * \note Caller holds master->lock; the DC's bound engine instance must already be the master's pvt->rtp.
 */
void sofia_dc_set_pvt(struct sofia_datachannel *dc, struct sofia_pvt *pvt);

/*!
 * \brief Tear down a DataChannel: clear the engine RX cb FIRST (instance-lock barrier → no more
 *        RX, anti-UAF), then close usrsctp + deregister + drop the ref.
 * \param dc the handle from sofia_dc_attach (may be NULL — no-op).
 */
void sofia_dc_detach(struct sofia_datachannel *dc);

/*!
 * \brief Send an application message out over the DataChannel (usrsctp → DTLS → wire).
 * \param dc the handle.
 * \param ppid the SCTP payload protocol id (RFC 8831 §8: 51 string, 53 binary, ...).
 * \param data payload.
 * \param len payload length.
 * \retval 0 success, -1 on error.
 * \note FOUNDATION: stream/PR-SCTP selection + DCEP framing land with the relay (Phase 2b).
 */
int sofia_dc_send(struct sofia_datachannel *dc, uint32_t ppid, const void *data, size_t len);

#else /* !HAVE_USRSCTP — inline no-op stubs so chan_sofia builds without usrsctp. */

#include "gabpbx/logger.h"

static inline int sofia_dc_init(void) { return 0; }
static inline void sofia_dc_finish(void) { }
static inline struct sofia_datachannel *sofia_dc_attach(struct sofia_pvt *pvt, uint16_t sctp_port)
{
	(void)pvt; (void)sctp_port;
	ast_log(LOG_WARNING, "Sofia: WebRTC DataChannel unsupported (built without usrsctp)\n");
	return NULL;
}
static inline void sofia_dc_set_peer_max_msg(struct sofia_datachannel *dc, unsigned int max)
{
	(void)dc; (void)max;
}
static inline void sofia_dc_set_dtls_role(struct sofia_datachannel *dc) { (void)dc; }
static inline void sofia_dc_set_pvt(struct sofia_datachannel *dc, struct sofia_pvt *pvt)
{
	(void)dc; (void)pvt;
}
static inline void sofia_dc_detach(struct sofia_datachannel *dc) { (void)dc; }
static inline int sofia_dc_send(struct sofia_datachannel *dc, uint32_t ppid,
	const void *data, size_t len)
{
	(void)dc; (void)ppid; (void)data; (void)len;
	return -1;
}

#endif /* HAVE_USRSCTP */

#endif /* CHAN_SOFIA_DATACHANNEL_H */
