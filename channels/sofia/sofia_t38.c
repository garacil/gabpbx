/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

/*! \file sofia_t38.c
 * \brief chan_sofia T.38 fax 4-state machine, split from chan_sofia.c.
 */

#include "gabpbx.h"
#include "gabpbx/channel.h"
#include "gabpbx/frame.h"
#include "gabpbx/udptl.h"
#include "gabpbx/manager.h"
#include "gabpbx/sched.h"
#include "gabpbx/logger.h"
#include "gabpbx/utils.h"

#include <sofia-sip/sip.h>
#include <sofia-sip/nua.h>

#include "include/chan_sofia_internal.h"
#include "include/sofia_t38.h"

/* respond_488_root is used only within this module (interpret_t38_parameters dispatches it). */
static void sofia_t38_respond_488_root(void *data);

/* T.38 4-state machine. Caller holds pvt->lock, and the channel lock when
 * pvt->owner is live. Queues an AST_CONTROL_T38_PARAMETERS frame for 3 of 4
 * states (LOCAL_REINVITE is silent, awaiting the peer response). */
void sofia_change_t38_state(struct sofia_pvt *pvt, int new_state)
{
	int old;
	struct ast_control_t38_parameters parameters = { .request_response = 0 };
	struct ast_channel *chan;

	if (!pvt) {
		return;
	}
	/* Idempotency: re-entering the same state would queue duplicate frames that
	 * app_fax/res_fax may double-process. */
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
		/* silent: wait for the peer response */
		break;
	}

	if (parameters.request_response) {
		ast_queue_control_data(chan, AST_CONTROL_T38_PARAMETERS, &parameters, sizeof(parameters));
	}

	/* Emit AMI T38FaxNegotiation on every transition (EVENT_FLAG_SYSTEM). */
	{
		const char *state_str = "Unknown";
		const char *rr_str = "None";
		const char *rm_str = "transferredTCF";
		const char *ec_str = "None";
		/* Snapshot pvt->peer->name under peer->lock (unbounded stringfield; reload
		 * frees its pool on growth -> a lock-free read would be a crash-UAF). All
		 * three callers respect the channel -> pvt -> peer-family order. */
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
			/* "ChannelType: SIP" for chan_sip compat. */
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

/* T.38 control dispatcher for the sofia_indicate AST_CONTROL_T38_PARAMETERS case
 * (app_fax/res_fax requests). max_ifp==0 is a rejection gate → DISABLED; version
 * is MIN-clamped.
 *
 * RETURN: <0 = error; 0 = handled, nothing further; >0 (1) = the caller must SEND
 * an outbound (LOCAL_REINVITE) T.38 re-INVITE — sofia_indicate marshals
 * sofia_directmedia_reinvite_root onto sofia_thread, which builds the m=image
 * offer (sofia_generate_sdp gates on pvt->udptl) and fires nua_invite. For the
 * inbound (PEER_REINVITE) path the SDP answer is on the existing response path
 * (unchanged). Runs under channel->pvt locks (core tech->indicate already holds
 * the channel lock; the caller takes pvt->lock), so the lazy udptl create, T.38
 * pvt fields, and the pvt->owner->fds[5] attach are serialized with sofia-thread
 * SDP generation while staying safe for channel-thread read/write. */
int sofia_interpret_t38_parameters(struct sofia_pvt *pvt, const struct ast_control_t38_parameters *parameters)
{
	int res = 0;

	/* t38pt_udptl must be enabled on the peer; pvt->udptl may still be NULL on a
	 * gabpbx-ORIGINATED upgrade (no inbound m=image has lazy-created it yet) — the
	 * LOCAL_REINVITE branch below creates it (chan_sip's create_addr_from_peer /
	 * reqprep T.38 setup parity, chan_sip.c:7604). */
	if (!pvt || !pvt->peer || !pvt->peer->t38pt_udptl) {
		return -1;
	}
	/* Every path except the outbound-originate one dereferences pvt->udptl; only the
	 * LOCAL_REINVITE originate (max_ifp>0, state DISABLED) tolerates a NULL udptl. */
	if (!pvt->udptl
	    && !(parameters->request_response == AST_T38_REQUEST_NEGOTIATE
	         && parameters->max_ifp != 0
	         && pvt->t38_state == SOFIA_T38_DISABLED)
	    && !(parameters->request_response == AST_T38_NEGOTIATED
	         && parameters->max_ifp != 0
	         && pvt->t38_state == SOFIA_T38_DISABLED)) {
		return -1;
	}

	switch (parameters->request_response) {
	case AST_T38_NEGOTIATED:
	case AST_T38_REQUEST_NEGOTIATE:
		if (parameters->max_ifp == 0) {
			/* Snapshot PEER_REINVITE BEFORE the DISABLED transition (the change
			 * overwrites t38_state, so testing it after would be dead code). */
			int was_peer_reinvite = (pvt->t38_state == SOFIA_T38_PEER_REINVITE);
			sofia_change_t38_state(pvt, SOFIA_T38_DISABLED);
			/* Cancel the 5s timer + drop its ao2 ref, else a ghost ref leaks. */
			if (was_peer_reinvite && pvt->t38id != -1 && sofia_sched) {
				if (ast_sched_thread_del(sofia_sched, pvt->t38id) == 0) {
					ao2_ref(pvt, -1);
				}
				pvt->t38id = -1;
			}
		} else if (pvt->t38_state == SOFIA_T38_PEER_REINVITE) {
			/* Accepting the peer offer — cancel the 5s timer. */
			if (pvt->t38id != -1 && sofia_sched) {
				if (ast_sched_thread_del(sofia_sched, pvt->t38id) == 0) {
					ao2_ref(pvt, -1);
				}
				pvt->t38id = -1;
			}
			/* Merge our_parms with their_parms. */
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
		} else if (pvt->t38_state != SOFIA_T38_ENABLED) {
			/* app_fax/res_fax (SendFAX/ReceiveFAX/fax gateway) requests an outbound
			 * T.38 upgrade (voice → fax). Originating side: lazy-create the UDPTL
			 * session (no inbound m=image ever did), record LOCAL_REINVITE, and signal
			 * the caller (sofia_indicate) to actually SEND the m=image re-INVITE offer
			 * — chan_sip parity (SIP_NEEDREINVITE → transmit_reinvite_with_sdp,
			 * chan_sip.c:21030; UDPTL setup chan_sip.c:7604). */
			if (!pvt->udptl) {
				struct ast_channel *chan = pvt->owner;	/* channel lock held by tech->indicate */
				struct ast_sockaddr bindaddr;
				ast_sockaddr_parse(&bindaddr, sofia_cfg.bindaddr, 0);
				pvt->udptl = ast_udptl_new_with_bindaddr(NULL, NULL, 0, &bindaddr);
				if (!pvt->udptl) {
					ast_log(LOG_WARNING, "Sofia: failed to allocate UDPTL session for outbound T.38 on '%s' — refusing\n",
						chan ? chan->name : "<no-owner>");
					sofia_change_t38_state(pvt, SOFIA_T38_DISABLED);	/* queues AST_T38_REFUSED */
					return -1;
				}
				/* Local EC scheme from the peer config (SOFIA_T38_EC_* → UDPTL_*),
				 * mirroring the inbound emit. Default FEC matches peer_alloc. */
				switch (pvt->peer->t38_ec_mode) {
				case SOFIA_T38_EC_REDUNDANCY:
					ast_udptl_set_error_correction_scheme(pvt->udptl, UDPTL_ERROR_CORRECTION_REDUNDANCY);
					break;
				case SOFIA_T38_EC_NONE:
					ast_udptl_set_error_correction_scheme(pvt->udptl, UDPTL_ERROR_CORRECTION_NONE);
					break;
				case SOFIA_T38_EC_FEC:
				default:
					ast_udptl_set_error_correction_scheme(pvt->udptl, UDPTL_ERROR_CORRECTION_FEC);
					break;
				}
				/* Wire fds[5] + tag now (channel lock held by tech->indicate; owner ==
				 * chan), mirroring the inbound t38_stage_fds5 attach so we can RX the
				 * answer's IFP once T.38 is ENABLED. */
				if (chan) {
					ast_udptl_set_tag(pvt->udptl, "%s", chan->name);
					chan->fds[5] = ast_udptl_fd(pvt->udptl);
				}
			}
			pvt->t38_our_parms = *parameters;
			ast_udptl_set_local_max_ifp(pvt->udptl, pvt->t38_our_parms.max_ifp);
			sofia_change_t38_state(pvt, SOFIA_T38_LOCAL_REINVITE);
			res = 1;	/* tell sofia_indicate to dispatch the outbound re-INVITE */
		}
		break;
	case AST_T38_TERMINATED:
	case AST_T38_REFUSED:
	case AST_T38_REQUEST_TERMINATE:
		if (pvt->t38_state == SOFIA_T38_PEER_REINVITE) {
			/* Rejecting the peer offer — cancel the 5s timer. */
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
		/* Fax stack asks for the far-end parms — return their_parms via a frame. */
		if (pvt->t38_state == SOFIA_T38_PEER_REINVITE) {
			struct ast_control_t38_parameters reply;
			/* Negotiation acknowledged — cancel the 5s timer. */
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

/* T.38 reINVITE 5s-timeout callback (one-shot; drops the ao2 ref taken at
 * ast_sched_thread_add). The 488 is a nua_* call, so it is marshaled to
 * sofia_thread with a FRESH +1 ref; the state change stays on the sched thread. */
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

int sofia_t38_abort(const void *data)
{
	struct sofia_pvt *pvt = (struct sofia_pvt *)data;
	int do_disable = 0;

	if (!pvt) {
		return 0;
	}

	/* Hold pvt->lock across sofia_change_t38_state (else sofia_hangup could NULL
	 * pvt->owner mid-call). Since that queues a frame under the channel lock, first
	 * ref+lock pvt->owner in canonical channel->pvt order to avoid an ABBA deadlock.
	 * NULL owner → change_t38_state early-returns (safe). */
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
