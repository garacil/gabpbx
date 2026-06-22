/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

/*! \file sofia_sdp.c
 * \brief chan_sofia SDP offer/answer parse + generate, split from chan_sofia.c.
 */

#include "gabpbx.h"
#include "gabpbx/channel.h"
#include "gabpbx/rtp_engine.h"
#include "gabpbx/udptl.h"
#include "gabpbx/dsp.h"
#include "gabpbx/sched.h"
#include "gabpbx/utils.h"
#include "gabpbx/strings.h"
#include "gabpbx/logger.h"
#include "gabpbx/causes.h"
#include "gabpbx/acl.h"

#include <sofia-sip/sip.h>
#include <sofia-sip/su_string.h>
#include <sofia-sip/sdp.h>
#include <sofia-sip/su.h>
#include <sofia-sip/nua.h>

#include "include/chan_sofia_internal.h"
#include "include/srtp.h"
#include "include/sdp_crypto.h"
#include "include/sofia_sdp.h"
#include "include/sofia_history.h"	/* codec-negotiation history markers (SIP history verbose analysis) */

static int sofia_sdp_pt_in_use(const char *list, int pt)
{
	char needle[8];
	const char *p;
	size_t nl;

	if (ast_strlen_zero(list)) {
		return 0;
	}
	snprintf(needle, sizeof(needle), "%d", pt);
	nl = strlen(needle);
	for (p = list; (p = strstr(p, needle)); p += nl) {
		char before = (p == list) ? ' ' : p[-1];
		char after = p[nl];
		if ((before == ' ' || before == '\0') && (after == ' ' || after == '\0')) {
			return 1;
		}
	}
	return 0;
}

static int sofia_sdp_cat(char *dst, size_t dstsize, const char *src)
{
	size_t dlen = strlen(dst);
	size_t slen = strlen(src);
	if (dlen + slen + 1 > dstsize) {
		return -1;
	}
	memcpy(dst + dlen, src, slen + 1);
	return 0;
}

char *sofia_generate_sdp(struct sofia_pvt *pvt, char *buf, size_t len)
{
	struct ast_sockaddr rtp_addr;
	struct ast_sockaddr dest_addr;
	const char *sdp_family;
	char host[128];
	int port;
	/* sockaddr_storage handles AF_INET + AF_INET6 (a sockaddr_in would truncate an
	 * IPv6 getsockname); extraction below dispatches on ss_family. */
	struct sockaddr_storage sin;
	socklen_t sinlen = sizeof(sin);
	char payload_buf[512] = "";
	char rtpmap_buf[2048] = "";
	char tmp_buf[128];
	int first = 1;
	int i;
	format_t fmt;
	format_t emitted = 0;
	int overflow = 0;	/* set if any SDP fragment would overrun its fixed buffer */

	if (!pvt || !pvt->rtp) {
		return NULL;
	}

	/* Local address from the RTP fd; ss_family dispatch handles IPv6. */
	if (getsockname(ast_rtp_instance_fd(pvt->rtp, 0),
			(struct sockaddr *)&sin, &sinlen) == 0) {
		if (sin.ss_family == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&sin;
			inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof(host));
			port = ntohs(sin6->sin6_port);
		} else {
			struct sockaddr_in *sin4 = (struct sockaddr_in *)&sin;
			inet_ntop(AF_INET, &sin4->sin_addr, host, sizeof(host));
			port = ntohs(sin4->sin_port);
		}
	} else {
		ast_rtp_instance_get_local_address(pvt->rtp, &rtp_addr);
		ast_copy_string(host, ast_sockaddr_stringify_host(&rtp_addr), sizeof(host));
		/* getsockname() failed: use the bound port (port=0 would emit "m=audio 0" =
		 * no media, RFC 4566 §5.14). */
		port = ast_sockaddr_port(&rtp_addr);
	}

	/* SDP c= host chain, lowest-to-highest priority (later clauses override):
	 * (1) local RTP addr above, (2) pvt->ourip (outbound kernel-routed source),
	 * (3) externaddr, (4) media_address, (5) directmedia redirip. Inbound: ourip zero → falls to (1). */
	if (pvt && !ast_sockaddr_isnull(&pvt->ourip)) {
		ast_copy_string(host, ast_sockaddr_stringify_host(&pvt->ourip), sizeof(host));
	}

	/* NAT: substitute externaddr when target is outside localnet (no registered gate). */
	if (pvt->peer && !ast_sockaddr_isnull(&pvt->peer->src_addr)
			&& sofia_should_use_externaddr(&pvt->peer->src_addr)
			&& !ast_strlen_zero(sofia_cfg.externaddr)) {
		ast_copy_string(host, sofia_cfg.externaddr, sizeof(host));
	}

	/* media_address (chan_sip parity, get_our_media_address): a global media-interface address advertised
	 * in the SDP c=/o= INSTEAD of the kernel-routed source. A deliberate operator override that wins over
	 * both ourip and the externaddr NAT remap (chan_sip checks it FIRST); only directmedia redirip below
	 * still wins. Advertise-only — the RTP socket still binds bindaddr. Empty = off (no change). */
	if (!ast_strlen_zero(sofia_cfg.media_address)) {
		ast_copy_string(host, sofia_cfg.media_address, sizeof(host));
	}

	/* Direct media: redirect c=/port to the bridged peer's RTP target (set by
	 * sofia_set_rtp_peer); wins over all of the above. */
	if (!ast_sockaddr_isnull(&pvt->redirip)) {
		ast_copy_string(host, ast_sockaddr_stringify_host(&pvt->redirip), sizeof(host));
		port = ast_sockaddr_port(&pvt->redirip);
	}

	/* Iterate codecs in preference order */
	for (i = 0; (fmt = ast_codec_pref_index(&pvt->prefs, i)); i++) {
		int pt;
		const char *enc;
		unsigned int rate;
		int channels = 0;
		if (!(fmt & pvt->capability) || !(fmt & AST_FORMAT_AUDIO_MASK))
			continue;
		pt = ast_rtp_codecs_payload_code(ast_rtp_instance_get_codecs(pvt->rtp), 1, fmt);
		if (pt < 0)
			continue;
		enc = ast_rtp_lookup_mime_subtype2(1, fmt, 0);
		rate = ast_rtp_lookup_sample_rate2(1, fmt);
		if (fmt == AST_FORMAT_OPUS)
			channels = 2;
		if (!first)
			overflow |= sofia_sdp_cat(payload_buf, sizeof(payload_buf), " ");
		snprintf(tmp_buf, sizeof(tmp_buf), "%d", pt);
		overflow |= sofia_sdp_cat(payload_buf, sizeof(payload_buf), tmp_buf);
		first = 0;
		if (channels)
			snprintf(tmp_buf, sizeof(tmp_buf), "a=rtpmap:%d %s/%u/%d\r\n", pt, enc, rate, channels);
		else
			snprintf(tmp_buf, sizeof(tmp_buf), "a=rtpmap:%d %s/%u\r\n", pt, enc, rate);
		overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
		/* fmtp for specific codecs */
		if (fmt == AST_FORMAT_G729A) {
			snprintf(tmp_buf, sizeof(tmp_buf), "a=fmtp:%d annexb=no\r\n", pt);
			overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
		} else if (fmt == AST_FORMAT_OPUS) {
			snprintf(tmp_buf, sizeof(tmp_buf), "a=fmtp:%d useinbandfec=1;usedtx=0\r\n", pt);
			overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
		} else if (fmt == AST_FORMAT_ILBC) {
			snprintf(tmp_buf, sizeof(tmp_buf), "a=fmtp:%d mode=20\r\n", pt);
			overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
		}
		emitted |= fmt;
		/* preferred_codec_only: narrow to the single most-preferred codec. */
		if (pvt->peer && pvt->peer->preferred_codec_only) {
			break;
		}
	}

	/* Fallback: emit remaining capability bits not in prefs (skip if narrowed). */
	for (fmt = 1; fmt && !(pvt->peer && pvt->peer->preferred_codec_only); fmt <<= 1) {
		int pt;
		const char *enc;
		unsigned int rate;
		int channels = 0;
		if (!(fmt & pvt->capability) || !(fmt & AST_FORMAT_AUDIO_MASK) || (fmt & emitted))
			continue;
		pt = ast_rtp_codecs_payload_code(ast_rtp_instance_get_codecs(pvt->rtp), 1, fmt);
		if (pt < 0)
			continue;
		enc = ast_rtp_lookup_mime_subtype2(1, fmt, 0);
		rate = ast_rtp_lookup_sample_rate2(1, fmt);
		if (fmt == AST_FORMAT_OPUS)
			channels = 2;
		if (!first)
			overflow |= sofia_sdp_cat(payload_buf, sizeof(payload_buf), " ");
		snprintf(tmp_buf, sizeof(tmp_buf), "%d", pt);
		overflow |= sofia_sdp_cat(payload_buf, sizeof(payload_buf), tmp_buf);
		first = 0;
		if (channels)
			snprintf(tmp_buf, sizeof(tmp_buf), "a=rtpmap:%d %s/%u/%d\r\n", pt, enc, rate, channels);
		else
			snprintf(tmp_buf, sizeof(tmp_buf), "a=rtpmap:%d %s/%u\r\n", pt, enc, rate);
		overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
		if (fmt == AST_FORMAT_G729A) {
			snprintf(tmp_buf, sizeof(tmp_buf), "a=fmtp:%d annexb=no\r\n", pt);
			overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
		} else if (fmt == AST_FORMAT_OPUS) {
			snprintf(tmp_buf, sizeof(tmp_buf), "a=fmtp:%d useinbandfec=1;usedtx=0\r\n", pt);
			overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
		} else if (fmt == AST_FORMAT_ILBC) {
			snprintf(tmp_buf, sizeof(tmp_buf), "a=fmtp:%d mode=20\r\n", pt);
			overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
		}
		emitted |= fmt;
	}

	/* telephone-event: prefer PT 101, but if a negotiated codec already took it
	 * pick the first free dynamic PT (96..127) to avoid a duplicate payload type. */
	{
		int te_pt = 101;
		if (sofia_sdp_pt_in_use(payload_buf, te_pt)) {
			for (te_pt = 96; te_pt <= 127 && sofia_sdp_pt_in_use(payload_buf, te_pt); te_pt++) {
				;
			}
			if (te_pt > 127) {
				te_pt = 101;	/* no free dynamic PT — collision unavoidable */
			}
		}
		if (!first) {
			overflow |= sofia_sdp_cat(payload_buf, sizeof(payload_buf), " ");
		}
		snprintf(tmp_buf, sizeof(tmp_buf), "%d", te_pt);
		overflow |= sofia_sdp_cat(payload_buf, sizeof(payload_buf), tmp_buf);
		snprintf(tmp_buf, sizeof(tmp_buf), "a=rtpmap:%d telephone-event/8000\r\n", te_pt);
		overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
		snprintf(tmp_buf, sizeof(tmp_buf), "a=fmtp:%d 0-16\r\n", te_pt);
		overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
	}

	/* Local a=crypto for SDES-SRTP (sdp_crypto_attrib returns the full line + CRLF). */
	if (pvt->srtp && pvt->srtp->crypto) {
		const char *a_crypto = sdp_crypto_attrib(pvt->srtp->crypto);
		if (a_crypto) {
			overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), a_crypto);
		}
	}

	/* SDP family: IPv4-mapped (`::ffff:1.2.3.4`) emits "IP4" (RFC 6052 §2.2 /
	 * RFC 4038 §4.2 prefer-IPv4); else IP6 for real IPv6, IP4 otherwise. */
	if (ast_sockaddr_parse(&dest_addr, host, PARSE_PORT_FORBID) &&
	    ast_sockaddr_is_ipv6(&dest_addr) &&
	    !ast_sockaddr_is_ipv4_mapped(&dest_addr)) {
		sdp_family = "IP6";
	} else {
		sdp_family = "IP4";
	}

	/* Assemble audio SDP (m= proto = RTP/SAVP when SRTP active). o= session-id set
	 * ONCE per dialog, version bumped per SDP (RFC 4566 §5.2 / RFC 3264 §8). */
	if (!pvt->sess_id) {
		pvt->sess_id = (unsigned long)time(NULL);
	}
	pvt->sess_version++;
	if (snprintf(buf, len,
		"v=0\r\n"
		"o=- %lu %lu IN %s %s\r\n"
		"s=GABpbx\r\n"
		"c=IN %s %s\r\n"
		"t=0 0\r\n"
		"m=audio %d %s %s\r\n"
		"%s"
		"a=sendrecv\r\n",
		pvt->sess_id, pvt->sess_version,
		sdp_family, host, sdp_family, host, port,
		(pvt->srtp && pvt->srtp->crypto) ? "RTP/SAVP" : "RTP/AVP",
		payload_buf, rtpmap_buf) >= (int)len) {	/* truncated audio SDP */
		overflow = 1;
	}

	/* Video block — only when video capability present and vrtp allocated. */
	if (pvt->vrtp && (pvt->capability & AST_FORMAT_VIDEO_MASK)) {
		struct ast_sockaddr vrtp_addr;
		char vhost[128];
		int vport = 0;
		struct sockaddr_storage vsin;	/* ss_family dispatch for IPv6 */
		socklen_t vsinlen = sizeof(vsin);
		char vpayload_buf[256] = "";
		char vrtpmap_buf[512] = "";
		int vfirst = 1;

		if (getsockname(ast_rtp_instance_fd(pvt->vrtp, 0),
				(struct sockaddr *)&vsin, &vsinlen) == 0) {
			if (vsin.ss_family == AF_INET6) {
				struct sockaddr_in6 *vsin6 = (struct sockaddr_in6 *)&vsin;
				inet_ntop(AF_INET6, &vsin6->sin6_addr, vhost, sizeof(vhost));
				vport = ntohs(vsin6->sin6_port);
			} else {
				struct sockaddr_in *vsin4 = (struct sockaddr_in *)&vsin;
				inet_ntop(AF_INET, &vsin4->sin_addr, vhost, sizeof(vhost));
				vport = ntohs(vsin4->sin_port);
			}
		} else {
			ast_rtp_instance_get_local_address(pvt->vrtp, &vrtp_addr);
			ast_copy_string(vhost, ast_sockaddr_stringify_host(&vrtp_addr), sizeof(vhost));
			/* getsockname() failed: use the bound port (0 → "m=video 0" = no media). */
			vport = ast_sockaddr_port(&vrtp_addr);
		}

		for (i = 0; (fmt = ast_codec_pref_index(&pvt->prefs, i)); i++) {
			int pt;
			const char *enc;
			unsigned int rate;
			if (!(fmt & pvt->capability) || !(fmt & AST_FORMAT_VIDEO_MASK))
				continue;
			pt = ast_rtp_codecs_payload_code(ast_rtp_instance_get_codecs(pvt->vrtp), 1, fmt);
			if (pt < 0)
				continue;
			enc = ast_rtp_lookup_mime_subtype2(1, fmt, 0);
			rate = ast_rtp_lookup_sample_rate2(1, fmt);
			if (!vfirst)
				overflow |= sofia_sdp_cat(vpayload_buf, sizeof(vpayload_buf), " ");
			snprintf(tmp_buf, sizeof(tmp_buf), "%d", pt);
			overflow |= sofia_sdp_cat(vpayload_buf, sizeof(vpayload_buf), tmp_buf);
			vfirst = 0;
			snprintf(tmp_buf, sizeof(tmp_buf), "a=rtpmap:%d %s/%u\r\n", pt, enc, rate);
			overflow |= sofia_sdp_cat(vrtpmap_buf, sizeof(vrtpmap_buf), tmp_buf);
			emitted |= fmt;
		}
		for (fmt = 1; fmt; fmt <<= 1) {
			int pt;
			const char *enc;
			unsigned int rate;
			if (!(fmt & pvt->capability) || !(fmt & AST_FORMAT_VIDEO_MASK) || (fmt & emitted))
				continue;
			pt = ast_rtp_codecs_payload_code(ast_rtp_instance_get_codecs(pvt->vrtp), 1, fmt);
			if (pt < 0)
				continue;
			enc = ast_rtp_lookup_mime_subtype2(1, fmt, 0);
			rate = ast_rtp_lookup_sample_rate2(1, fmt);
			if (!vfirst)
				overflow |= sofia_sdp_cat(vpayload_buf, sizeof(vpayload_buf), " ");
			snprintf(tmp_buf, sizeof(tmp_buf), "%d", pt);
			overflow |= sofia_sdp_cat(vpayload_buf, sizeof(vpayload_buf), tmp_buf);
			vfirst = 0;
			snprintf(tmp_buf, sizeof(tmp_buf), "a=rtpmap:%d %s/%u\r\n", pt, enc, rate);
			overflow |= sofia_sdp_cat(vrtpmap_buf, sizeof(vrtpmap_buf), tmp_buf);
			emitted |= fmt;
		}

		if (pvt->vsrtp && pvt->vsrtp->crypto) {
			const char *va_crypto = sdp_crypto_attrib(pvt->vsrtp->crypto);
			if (va_crypto) {
				overflow |= sofia_sdp_cat(vrtpmap_buf, sizeof(vrtpmap_buf), va_crypto);
			}
		}

		if (!vfirst) {
			int vlen = strlen(buf);
			/* maxcallbitrate: media-level b=CT:%d after m=video (RFC 4566 §5.8). */
			char bw_buf[32] = "";
			if (pvt->peer && pvt->peer->maxcallbitrate > 0) {
				snprintf(bw_buf, sizeof(bw_buf), "b=CT:%d\r\n", pvt->peer->maxcallbitrate);
			}
			if (snprintf(buf + vlen, len - vlen,
				"m=video %d %s %s\r\n"
				"%s"
				"%s"
				"a=sendrecv\r\n",
				vport,
				(pvt->vsrtp && pvt->vsrtp->crypto) ? "RTP/SAVP" : "RTP/AVP",
				vpayload_buf, bw_buf, vrtpmap_buf) >= (int)(len - vlen)) {	/* truncated video SDP */
				overflow = 1;
			}
		}
	}

	/* T.38 fax UDPTL outbound emitter: m=image + a=T38Fax* (5 mandatory + 3 optional
	 * bare-flag attrs, emitted only when the our_parms bit is set). Gated on udptl. */
	if (pvt->udptl) {
		struct ast_sockaddr udptl_local;
		int t38vlen = strlen(buf);
		const char *rate_mgmt_str;
		const char *udpec_str;
		unsigned int max_bitrate;
		unsigned int max_datagram;

		ast_udptl_get_us(pvt->udptl, &udptl_local);

		/* T38MaxBitRate enum→integer (default AST_T38_RATE_14400). */
		switch (pvt->t38_our_parms.rate) {
		case AST_T38_RATE_2400:  max_bitrate = 2400;  break;
		case AST_T38_RATE_4800:  max_bitrate = 4800;  break;
		case AST_T38_RATE_7200:  max_bitrate = 7200;  break;
		case AST_T38_RATE_9600:  max_bitrate = 9600;  break;
		case AST_T38_RATE_12000: max_bitrate = 12000; break;
		case AST_T38_RATE_14400: max_bitrate = 14400; break;
		default:                 max_bitrate = 14400; break;
		}

		/* T38FaxRateManagement default transferredTCF per RFC 3362 */
		switch (pvt->t38_our_parms.rate_management) {
		case AST_T38_RATE_MANAGEMENT_LOCAL_TCF:
			rate_mgmt_str = "localTCF";
			break;
		case AST_T38_RATE_MANAGEMENT_TRANSFERRED_TCF:
		default:
			rate_mgmt_str = "transferredTCF";
			break;
		}

		/* T38FaxUdpEC from the negotiated scheme; NONE → omit the line. */
		switch (ast_udptl_get_error_correction_scheme(pvt->udptl)) {
		case UDPTL_ERROR_CORRECTION_FEC:
			udpec_str = "t38UDPFEC";
			break;
		case UDPTL_ERROR_CORRECTION_REDUNDANCY:
			udpec_str = "t38UDPRedundancy";
			break;
		case UDPTL_ERROR_CORRECTION_NONE:
		default:
			udpec_str = NULL;
			break;
		}

		max_datagram = ast_udptl_get_local_max_datagram(pvt->udptl);

		/* Append m=image + a=T38Fax* attributes (5 mandatory). RFC 4566 §5.14:
		 * m=image port udptl t38 — UDPTL transport per RFC 3362. */
		if (snprintf(buf + t38vlen, len - t38vlen,
			"m=image %d udptl t38\r\n"
			"a=T38FaxVersion:%u\r\n"
			"a=T38MaxBitRate:%u\r\n"
			"a=T38FaxRateManagement:%s\r\n"
			"a=T38FaxMaxDatagram:%u\r\n",
			ast_sockaddr_port(&udptl_local),
			pvt->t38_our_parms.version,
			max_bitrate,
			rate_mgmt_str,
			max_datagram) >= (int)(len - t38vlen)) {	/* truncated T.38 SDP */
			overflow = 1;
		}

		/* 3 optional bare-flag attributes — emit when our_parms bit is set. */
		if (pvt->t38_our_parms.fill_bit_removal) {
			int blen = strlen(buf);
			if (snprintf(buf + blen, len - blen, "a=T38FaxFillBitRemoval\r\n") >= (int)(len - blen)) {
				overflow = 1;
			}
		}
		if (pvt->t38_our_parms.transcoding_mmr) {
			int blen = strlen(buf);
			if (snprintf(buf + blen, len - blen, "a=T38FaxTranscodingMMR\r\n") >= (int)(len - blen)) {
				overflow = 1;
			}
		}
		if (pvt->t38_our_parms.transcoding_jbig) {
			int blen = strlen(buf);
			if (snprintf(buf + blen, len - blen, "a=T38FaxTranscodingJBIG\r\n") >= (int)(len - blen)) {
				overflow = 1;
			}
		}

		/* T38FaxUdpEC emitted only when EC scheme is FEC or Redundancy (NONE = omit). */
		if (udpec_str) {
			int blen = strlen(buf);
			if (snprintf(buf + blen, len - blen, "a=T38FaxUdpEC:%s\r\n", udpec_str) >= (int)(len - blen)) {
				overflow = 1;
			}
		}
	}

	/* Any fragment/final truncation → fail the whole SDP (callers treat NULL as "no SDP"). */
	if (overflow) {
		ast_log(LOG_WARNING, "Sofia: SDP for '%s' exceeded its build buffers (too many codecs/attributes) — emitting no SDP\n",
			S_OR(pvt->callid, "<unknown>"));
		return NULL;
	}

	return buf;
}

static int sofia_process_crypto(struct sofia_pvt *pvt, struct ast_rtp_instance *rtp,
		struct sofia_srtp **srtp, const char *attr)
{
	char *prefixed = NULL;
	/* Only tear down *srtp on failure if THIS call allocated it: an in-dialog
	 * re-INVITE *srtp may be a live, validated context, and rejecting a bad
	 * a=crypto must NOT downgrade active media to plaintext (488 "keep existing
	 * crypto" contract). */
	int was_new = (*srtp == NULL);

	if (!rtp || !attr) {
		return 0;
	}
	if (!*srtp) {
		*srtp = sofia_srtp_alloc();
		if (!*srtp) {
			return 0;
		}
	}
	if (!(*srtp)->crypto) {
		(*srtp)->crypto = sdp_crypto_setup();
		if (!(*srtp)->crypto) {
			if (was_new) {
				sofia_srtp_destroy(*srtp);
				*srtp = NULL;
			}
			return 0;
		}
	}
	/* Build "crypto:<attr>" DYNAMICALLY so a long a=crypto is validated in FULL —
	 * a fixed buffer would truncate, letting sdp_crypto_process validate a different
	 * line than the wire (bypassing tail-param rejection). */
	if (ast_asprintf(&prefixed, "crypto:%s", attr) < 0) {
		/* OOM — fail-closed: reject the offer. */
		if (was_new) {
			sofia_srtp_destroy(*srtp);
			*srtp = NULL;
		}
		return 0;
	}
	/* defer=1 — validate + stage only; the live add_srtp_policy waits for
	 * sdp_crypto_commit() after sofia_parse_sdp's reject gates pass. */
	{
		int rc = sdp_crypto_process((*srtp)->crypto, prefixed, rtp, 1);
		ast_free(prefixed);
		if (rc < 0) {
			if (was_new) {
				sofia_srtp_destroy(*srtp);
				*srtp = NULL;
			}
			return 0;
		}
	}
	(*srtp)->flags |= SRTP_CRYPTO_OFFER_OK;
	return 1;
}

static void sofia_sdp_stage_rollback(struct sofia_pvt *pvt, int audio_was_new, int video_was_new)
{
	if (pvt->srtp && pvt->srtp->crypto) {
		sdp_crypto_clear_staged(pvt->srtp->crypto);
	}
	if (pvt->vsrtp && pvt->vsrtp->crypto) {
		sdp_crypto_clear_staged(pvt->vsrtp->crypto);
	}
	if (audio_was_new && pvt->srtp) {
		sofia_srtp_destroy(pvt->srtp);
		pvt->srtp = NULL;
	}
	if (video_was_new && pvt->vsrtp) {
		sofia_srtp_destroy(pvt->vsrtp);
		pvt->vsrtp = NULL;
	}
}

int sofia_parse_sdp(struct sofia_pvt *pvt, sip_t const *sip)
{
	sdp_parser_t *parser;
	sdp_session_t *sdp;
	sdp_media_t *media;
	const char *sdp_data;
	int audio_offered = 0;
	int video_offered = 0;
	int audio_secure_offered = 0;
	int video_secure_offered = 0;
	int processed_crypto_audio = 0;
	int processed_crypto_video = 0;
	int image_active_seen = 0;	/* a live UDPTL T.38 image leg was present this parse */
	/* Whether THIS parse's a=crypto lazily creates the SRTP context (for reject
	 * rollback). Captured AFTER the !pvt guard below — do not deref pvt here. */
	int audio_srtp_was_new = 0;
	int video_srtp_was_new = 0;

	if (!sip || !pvt || !pvt->rtp) {
		return 0;
	}

	/* Capture whether THIS parse's a=crypto lazily creates the SRTP context (for
	 * reject rollback) and clear stale staged crypto so a prior rejected parse
	 * can't leave a key this one commits. */
	audio_srtp_was_new = (pvt->srtp == NULL);
	video_srtp_was_new = (pvt->vsrtp == NULL);
	if (pvt->srtp && pvt->srtp->crypto) {
		sdp_crypto_clear_staged(pvt->srtp->crypto);
	}
	if (pvt->vsrtp && pvt->vsrtp->crypto) {
		sdp_crypto_clear_staged(pvt->vsrtp->crypto);
	}

	if (!sip->sip_payload || !sip->sip_payload->pl_data) {
		return 0;
	}

	sdp_data = sip->sip_payload->pl_data;
	parser = sdp_parse(pvt->home, sdp_data, sip->sip_payload->pl_len, 0);
	if (!parser) {
		return 0;
	}

	sdp = sdp_session(parser);
	if (!sdp) {
		sdp_parser_free(parser);
		return 0;
	}

	/* Pre-clear config video so only THIS offer's video is re-added (negotiation
	 * is order-independent; the audio block preserves (local_cap & VIDEO_MASK)).
	 * Snapshot capability so every reject path restores it — a rejected SDP must
	 * NOT strip an established call's video. Restored at sdp_reject. */
	format_t orig_capability = pvt->capability;
	pvt->capability &= ~AST_FORMAT_VIDEO_MASK;

	/* Validate-then-commit: snapshot the live media state the loop mutates BEFORE
	 * the reject gates, so a rejected SDP leaves an established call untouched
	 * (RFC 3261 §14). (B) simple pvt fields; (C) RTP/UDPTL remotes. had_vrtp/
	 * had_udptl gate the restore (lazy creates use was_new-rollback instead). */
	struct ast_control_t38_parameters orig_t38_their_parms = pvt->t38_their_parms;	/* (B) */
	unsigned int orig_t38_max_ifp = pvt->t38_max_ifp;				/* (B) */
	struct ast_sockaddr orig_audio_remote;						/* (C) */
	struct ast_sockaddr orig_video_remote;						/* (C) */
	struct ast_sockaddr orig_udptl_peer;						/* (C) */
	enum ast_t38_ec_modes orig_udptl_ec = UDPTL_ERROR_CORRECTION_NONE;		/* (C) */
	unsigned int orig_udptl_far_datagram = 0;					/* (C) */
	int had_vrtp = (pvt->vrtp != NULL);
	int had_udptl = (pvt->udptl != NULL);
	ast_sockaddr_setnull(&orig_audio_remote);
	ast_sockaddr_setnull(&orig_video_remote);
	ast_sockaddr_setnull(&orig_udptl_peer);
	ast_rtp_instance_get_remote_address(pvt->rtp, &orig_audio_remote);
	if (had_vrtp) {
		ast_rtp_instance_get_remote_address(pvt->vrtp, &orig_video_remote);
	}
	if (had_udptl) {
		ast_udptl_get_peer(pvt->udptl, &orig_udptl_peer);
		/* Snapshot the effective EC + far_max_datagram so a reject restores a
		 * pre-existing udptl (getter values are value-faithful, not bit-exact). */
		orig_udptl_ec = ast_udptl_get_error_correction_scheme(pvt->udptl);
		orig_udptl_far_datagram = ast_udptl_get_far_max_datagram(pvt->udptl);
	}

	/* Negotiated codec maps are staged here and copied into pvt->rtp/vrtp only at
	 * commit (after every reject gate), so a rejected SDP never overwrites the
	 * established codec map. staged_*_valid gates the copy, not the clear. */
	struct ast_rtp_codecs staged_audio_codecs;
	struct ast_rtp_codecs staged_video_codecs;
	int staged_audio_valid = 0;
	int staged_video_valid = 0;
	ast_rtp_codecs_payloads_clear(&staged_audio_codecs, NULL);
	ast_rtp_codecs_payloads_clear(&staged_video_codecs, NULL);

	/* The chosen audio native format is applied (o->nativeformats +
	 * ast_set_read/write_format — irreversible) only at commit, so a rejected SDP
	 * never reformats an established channel. */
	format_t staged_chosen_audio = 0;
	int staged_chosen_audio_valid = 0;

	/* T.38 irreversible side-effects are staged here and fired at commit. The udptl
	 * INSTANCE is still created+configured in-loop (was_new-rollback on reject), but
	 * fds[5] attach + state-change/timer/withdraw/async-goto are deferred. Advance
	 * and withdraw are mutually exclusive. */
	int t38_stage_fds5 = 0;			/* attach o->fds[5] = ast_udptl_fd(udptl) at commit (was_new only) */
	int t38_stage_enter_reinvite = 0;	/* sofia_change_t38_state(PEER_REINVITE) + arm t38id at commit */
	int t38_stage_withdraw = 0;		/* sofia_change_t38_state(DISABLED) + cancel t38id at commit */
	/* The fax-redirect inputs are evaluated at COMMIT under the channel lock; only
	 * the advance intent is staged here. */

	for (media = sdp->sdp_media; media; media = media->m_next) {
		if (media->m_type == sdp_media_audio && media->m_port != 0) {
			sdp_attribute_t *a;
			audio_offered = 1;
			if (media->m_proto == sdp_proto_srtp) {
				audio_secure_offered = 1;
			}
			for (a = media->m_attributes; a; a = a->a_next) {
				if (a->a_name && su_casematch(a->a_name, "crypto") && a->a_value) {
					if (sofia_process_crypto(pvt, pvt->rtp, &pvt->srtp, a->a_value)) {
						processed_crypto_audio = 1;
						break;
					}
				}
			}
			char addr[128];
			sdp_connection_t *conn = media->m_connections;

			if (!conn && sdp->sdp_connection) {
				conn = sdp->sdp_connection;
			}

			if (conn && conn->c_address) {
				snprintf(addr, sizeof(addr), "%s", conn->c_address);
			} else {
				continue;
			}

			{
				/* Never feed an uninitialized ast_sockaddr to the RTP engine:
				 * ast_sockaddr_parse() returns 0 WITHOUT writing on a malformed
				 * c=, so track parse success rather than read stack garbage. */
				struct ast_sockaddr remote;
				int have_remote = ast_sockaddr_parse(&remote, addr, 0);
				if (have_remote) {
					ast_sockaddr_set_port(&remote, media->m_port);
				}
				/* NAT override: a NAT'd peer's SDP c= leaks its private LAN IP, so
				 * use peer->src_addr (registered public IP) with the SDP media port
				 * (comedia refines the port on the first inbound packet). */
				if (pvt->peer
				    && (pvt->peer->nat & (SOFIA_NAT_FORCE_RPORT | SOFIA_NAT_COMEDIA))
				    && !ast_sockaddr_isnull(&pvt->peer->src_addr)) {
					struct ast_sockaddr nat_remote = pvt->peer->src_addr;
					ast_sockaddr_set_port(&nat_remote, media->m_port);
					remote = nat_remote;
					have_remote = 1;
				}
				/* Audio is mandatory: a c= we can neither parse nor NAT-override
				 * is malformed SDP -> reject (RFC 3261 §14). Rejected even if a
				 * valid m=image leg exists — distinct from the no-common-CODEC
				 * T.38 carve-out below. */
				if (!have_remote) {
					ast_log(LOG_WARNING, "Sofia: unparseable audio media address '%s' in SDP offer — rejecting\n", addr);
					goto sdp_reject;
				}
				ast_rtp_instance_set_remote_address(pvt->rtp, &remote);
			}

			{
				format_t local_cap = pvt->capability;
				format_t offered = 0;
				int noncodec = 0;
				sdp_rtpmap_t *rm;
				sdp_list_t *fmt;

				/* Re-init the staged map per m=audio block so a (rare) second line
				 * wins last; install into pvt->rtp is deferred to commit. */
				ast_rtp_codecs_payloads_clear(&staged_audio_codecs, NULL);

				/* Step 1: register PTs from m= line */
				for (fmt = media->m_format; fmt; fmt = fmt->l_next) {
					int pt = atoi(fmt->l_text);
					ast_rtp_codecs_payloads_set_m_type(&staged_audio_codecs, NULL, pt);
				}

				/* Step 2: override with a=rtpmap entries (handles dynamic PTs) */
				for (rm = media->m_rtpmaps; rm; rm = rm->rm_next) {
					if (rm->rm_encoding) {
						int rc = ast_rtp_codecs_payloads_set_rtpmap_type_rate(
							&staged_audio_codecs, NULL, rm->rm_pt, "audio",
							(char *)rm->rm_encoding, 0, rm->rm_rate);
						if (rc) {
							ast_rtp_codecs_payloads_unset(&staged_audio_codecs, NULL, rm->rm_pt);
						}
					}
				}

				/* Step 3: extract negotiated formats */
				ast_rtp_codecs_payload_formats(&staged_audio_codecs, &offered, &noncodec);

				/* Step 4: intersect with local capability. No common audio codec →
				 * reject 488 (vs dead audio), UNLESS the SDP also offers a T.38/image
				 * leg (carve-out, m=image handling takes over). */
				if ((local_cap & offered & AST_FORMAT_AUDIO_MASK) == 0) {
					int has_t38 = 0;
					sdp_media_t *mm;
					for (mm = sdp->sdp_media; mm; mm = mm->m_next) {
						if (mm->m_type == sdp_media_image
								&& mm->m_proto == sdp_proto_udptl
								&& mm->m_port != 0) {
							has_t38 = 1;
							break;
						}
					}
					if (!has_t38) {
						sofia_append_history_code(pvt, 488, "SDP", "no common audio codec");
						ast_log(LOG_WARNING, "Sofia: no common audio codec with peer — rejecting (488 Not Acceptable Here)\n");
						goto sdp_reject;
					}
				}
				/* Narrow audio to the negotiated set but PRESERVE this-SDP video.
				 * (local_cap & VIDEO_MASK) is only video a preceding m=video block
				 * added (config video was pre-cleared), never stale config video. */
				pvt->capability = (local_cap & offered) | (local_cap & AST_FORMAT_VIDEO_MASK);
				if (pvt->capability == 0) {
					ast_log(LOG_WARNING, "Sofia: No common codec with peer; falling back to local capability\n");
					pvt->capability = local_cap;
				}

				/* Step 5: map built; install into pvt->rtp deferred to commit. */
				staged_audio_valid = 1;

				if (pvt->owner && (pvt->capability & AST_FORMAT_AUDIO_MASK)) {
					format_t chosen = ast_codec_choose(&pvt->prefs,
						pvt->capability & AST_FORMAT_AUDIO_MASK, 1);
					if (!chosen) {
						chosen = ast_best_codec(pvt->capability & AST_FORMAT_AUDIO_MASK);
					}
					if (chosen) {
						/* Applying the channel native format is deferred to commit
						 * (irreversible) so a reject never reformats the channel. */
						staged_chosen_audio = chosen;
						staged_chosen_audio_valid = 1;
					}
				}
			}
		} else if (media->m_type == sdp_media_video && media->m_port != 0) {
			char addr[128];
			sdp_connection_t *conn = media->m_connections;
			sdp_attribute_t *a;

			video_offered = 1;
			if (media->m_proto == sdp_proto_srtp) {
				video_secure_offered = 1;
			}

			if (!conn && sdp->sdp_connection)
				conn = sdp->sdp_connection;
			if (!conn || !conn->c_address)
				continue;

			snprintf(addr, sizeof(addr), "%s", conn->c_address);

			/* Allocate vrtp on demand when we see m=video */
			if (!pvt->vrtp) {
				struct ast_sockaddr bindaddr;
				ast_sockaddr_parse(&bindaddr, sofia_cfg.bindaddr, 0);
				pvt->vrtp = ast_rtp_instance_new("gabpbx", NULL, &bindaddr, NULL);
				if (pvt->vrtp)
					ast_rtp_instance_set_prop(pvt->vrtp, AST_RTP_PROPERTY_RTCP, 1);
			}

			for (a = media->m_attributes; a; a = a->a_next) {
				if (a->a_name && su_casematch(a->a_name, "crypto") && a->a_value) {
					if (sofia_process_crypto(pvt, pvt->vrtp, &pvt->vsrtp, a->a_value)) {
						processed_crypto_video = 1;
						break;
					}
				}
			}

			if (pvt->vrtp) {
				struct ast_sockaddr remote;
				format_t offered = 0;
				int noncodec = 0;
				sdp_rtpmap_t *rm;
				sdp_list_t *vfmt;
				int have_remote;

				/* Same uninitialized-sockaddr guard as the audio
				 * leg. Video is optional, so on an unparseable c= with no NAT
				 * fallback we leave the existing video remote untouched (never
				 * hand garbage to the RTP engine) and still negotiate codecs. */
				have_remote = ast_sockaddr_parse(&remote, addr, 0);
				if (have_remote) {
					ast_sockaddr_set_port(&remote, media->m_port);
				}
				/* NAT override (chan_sip parity): mirror audio-side reasoning
				 * for video — SDP c= from a NAT'd peer typically leaks the
				 * private LAN IP; use peer->src_addr instead. */
				if (pvt->peer
				    && (pvt->peer->nat & (SOFIA_NAT_FORCE_RPORT | SOFIA_NAT_COMEDIA))
				    && !ast_sockaddr_isnull(&pvt->peer->src_addr)) {
					struct ast_sockaddr nat_remote = pvt->peer->src_addr;
					ast_sockaddr_set_port(&nat_remote, media->m_port);
					remote = nat_remote;
					have_remote = 1;
				}
				if (have_remote) {
					ast_rtp_instance_set_remote_address(pvt->vrtp, &remote);
				} else {
					ast_log(LOG_NOTICE, "Sofia: unparseable video media address '%s' in SDP — leaving video remote unchanged\n", addr);
				}

				ast_rtp_codecs_payloads_clear(&staged_video_codecs, NULL);

				for (vfmt = media->m_format; vfmt; vfmt = vfmt->l_next) {
					int pt = atoi(vfmt->l_text);
					ast_rtp_codecs_payloads_set_m_type(&staged_video_codecs, NULL, pt);
				}
				for (rm = media->m_rtpmaps; rm; rm = rm->rm_next) {
					if (rm->rm_encoding) {
						int rc = ast_rtp_codecs_payloads_set_rtpmap_type_rate(
							&staged_video_codecs, NULL, rm->rm_pt, "video",
							(char *)rm->rm_encoding, 0, rm->rm_rate);
						if (rc)
							ast_rtp_codecs_payloads_unset(&staged_video_codecs, NULL, rm->rm_pt);
					}
				}

				ast_rtp_codecs_payload_formats(&staged_video_codecs, &offered, &noncodec);
				if (offered & AST_FORMAT_VIDEO_MASK) {
					pvt->capability |= offered & AST_FORMAT_VIDEO_MASK;
				}
				/* Map built; install into pvt->vrtp deferred to commit. */
				staged_video_valid = 1;
			}
		} else if (media->m_type == sdp_media_image && media->m_port != 0) {
			/* T.38 fax UDPTL handling: populate t38_their_parms from the offer,
			 * lazy-create pvt->udptl, set the UDPTL peer, and advance to
			 * PEER_REINVITE on first valid detect (deferred past the reject gates).
			 * Attribute names are lowercased for case-insensitive sscanf (RFC 5347
			 * §2.5.2). */
			sdp_attribute_t *a;
			sdp_connection_t *conn = media->m_connections;
			char addr[128];

			if (media->m_proto != sdp_proto_udptl) {
				ast_log(LOG_WARNING, "Sofia: ignoring m=image media with non-UDPTL proto\n");
				continue;
			}
			image_active_seen = 1;	/* a live UDPTL T.38 image leg is present this parse */

			if (!conn && sdp->sdp_connection) {
				conn = sdp->sdp_connection;
			}
			if (!conn || !conn->c_address) {
				continue;
			}

			/* Lazy-create the UDPTL session on its own socket (not the audio RTP
			 * port); reused across re-INVITEs, destroyed in the destructor. */
			if (!pvt->udptl) {
				struct ast_sockaddr bindaddr;
				ast_sockaddr_parse(&bindaddr, sofia_cfg.bindaddr, 0);
				pvt->udptl = ast_udptl_new_with_bindaddr(NULL, NULL, 0, &bindaddr);
				if (!pvt->udptl) {
					ast_log(LOG_WARNING, "Sofia: failed to allocate UDPTL session for T.38 (peer offer ignored)\n");
					continue;
				}
				/* Attach UDPTL fd to channel fds[5] (deferred to commit); was_new-only,
				 * since a pre-existing udptl already had fds[5] wired. */
				t38_stage_fds5 = 1;
			}

			/* Set the UDPTL peer. With NAT + t38pt_usertpsource=yes, override the
			 * destination with the audio RTP remote (the seen endpoint, fixing T.38
			 * over NAT); the port is always taken from m=image. */
			snprintf(addr, sizeof(addr), "%s", conn->c_address);
			{
				/* usertpsource fills `remote` from the validated audio RTP remote;
				 * the else-branch must check ast_sockaddr_parse (leaves `remote`
				 * untouched on failure) — on unparseable c= leave the peer unchanged. */
				struct ast_sockaddr remote;
				int have_remote = 1;
				if (pvt->peer && pvt->peer->t38pt_usertpsource &&
				    (pvt->peer->nat & (SOFIA_NAT_FORCE_RPORT | SOFIA_NAT_COMEDIA)) &&
				    pvt->rtp) {
					ast_rtp_instance_get_remote_address(pvt->rtp, &remote);
				} else {
					have_remote = ast_sockaddr_parse(&remote, addr, 0);
				}
				if (have_remote) {
					ast_sockaddr_set_port(&remote, media->m_port);
					ast_udptl_set_peer(pvt->udptl, &remote);
				} else {
					ast_log(LOG_NOTICE, "Sofia: unparseable T.38 media address '%s' in SDP — leaving UDPTL peer unchanged\n", addr);
				}
			}

			/* Reset their_parms before each new offer (EC defaults to NONE). */
			if (pvt->t38_state != SOFIA_T38_ENABLED) {
				memset(&pvt->t38_their_parms, 0, sizeof(pvt->t38_their_parms));
				ast_udptl_set_error_correction_scheme(pvt->udptl, UDPTL_ERROR_CORRECTION_NONE);
			}

			/* Walk a=T38Fax* attributes (5 mandatory + 3 optional bare-flag). */
			for (a = media->m_attributes; a; a = a->a_next) {
				unsigned int x;
				char s[256];
				char attrib[512];
				char *pos;

				if (!a->a_name) {
					continue;
				}
				if (a->a_value) {
					snprintf(attrib, sizeof(attrib), "%s:%s", a->a_name, a->a_value);
				} else {
					snprintf(attrib, sizeof(attrib), "%s", a->a_name);
				}
				for (pos = attrib; *pos; ++pos) {
					*pos = tolower(*pos);
				}

				if (sscanf(attrib, "t38faxversion:%30u", &x) == 1) {
					pvt->t38_their_parms.version = x;
				} else if (sscanf(attrib, "t38maxbitrate:%30u", &x) == 1 ||
					   sscanf(attrib, "t38faxmaxrate:%30u", &x) == 1) {
					switch (x) {
					case 14400: pvt->t38_their_parms.rate = AST_T38_RATE_14400; break;
					case 12000: pvt->t38_their_parms.rate = AST_T38_RATE_12000; break;
					case 9600:  pvt->t38_their_parms.rate = AST_T38_RATE_9600;  break;
					case 7200:  pvt->t38_their_parms.rate = AST_T38_RATE_7200;  break;
					case 4800:  pvt->t38_their_parms.rate = AST_T38_RATE_4800;  break;
					case 2400:  pvt->t38_their_parms.rate = AST_T38_RATE_2400;  break;
					}
				} else if (sscanf(attrib, "t38faxmaxdatagram:%30u", &x) == 1 ||
					   sscanf(attrib, "t38maxdatagram:%30u", &x) == 1) {
					/* Apply per-peer override (chan_sip parity) */
					if ((pvt->t38_maxdatagram > 0) && ((unsigned int)pvt->t38_maxdatagram > x)) {
						x = (unsigned int)pvt->t38_maxdatagram;
					}
					ast_udptl_set_far_max_datagram(pvt->udptl, x);
				} else if (sscanf(attrib, "t38faxratemanagement:%255s", s) == 1) {
					if (!strcasecmp(s, "localtcf")) {
						pvt->t38_their_parms.rate_management = AST_T38_RATE_MANAGEMENT_LOCAL_TCF;
					} else if (!strcasecmp(s, "transferredtcf")) {
						pvt->t38_their_parms.rate_management = AST_T38_RATE_MANAGEMENT_TRANSFERRED_TCF;
					}
				} else if (sscanf(attrib, "t38faxudpec:%255s", s) == 1) {
					if (!strcasecmp(s, "t38udpredundancy")) {
						ast_udptl_set_error_correction_scheme(pvt->udptl, UDPTL_ERROR_CORRECTION_REDUNDANCY);
					} else if (!strcasecmp(s, "t38udpfec")) {
						ast_udptl_set_error_correction_scheme(pvt->udptl, UDPTL_ERROR_CORRECTION_FEC);
					} else {
						ast_udptl_set_error_correction_scheme(pvt->udptl, UDPTL_ERROR_CORRECTION_NONE);
					}
				} else if (strncmp(attrib, "t38faxfillbitremoval", 20) == 0) {
					pvt->t38_their_parms.fill_bit_removal = 1;
				} else if (strncmp(attrib, "t38faxtranscodingmmr", 20) == 0) {
					pvt->t38_their_parms.transcoding_mmr = 1;
				} else if (strncmp(attrib, "t38faxtranscodingjbig", 21) == 0) {
					pvt->t38_their_parms.transcoding_jbig = 1;
				}
			}

			/* LOAD-BEARING: read peer-advertised max_ifp (max_ifp==0 forces
			 * T38_DISABLED → real fax rejects on every call). */
			pvt->t38_max_ifp = ast_udptl_get_far_max_ifp(pvt->udptl);

			/* Advance DISABLED → PEER_REINVITE on first detect. Deferred to commit
			 * (state stays DISABLED through the loop so the post-loop withdraw check
			 * reads the pre-parse state, and a rejected SDP fires none of it). */
			if (pvt->t38_state == SOFIA_T38_DISABLED) {
				t38_stage_enter_reinvite = 1;
			}
		}
	}

	/* A re-INVITE that withdraws the image stream (m=image port 0 or absent) must
	 * return T.38 to DISABLED, else fax state stays stuck active. Deferred to
	 * commit; mutually exclusive with t38_stage_enter_reinvite. */
	if (!image_active_seen && pvt->t38_state >= SOFIA_T38_PEER_REINVITE) {
		t38_stage_withdraw = 1;
	}

	sdp_parser_free(parser);
	parser = NULL;	/* so sdp_reject's free is a no-op for post-loop rejects */

	/* SRTP policy enforcement */
	if (audio_secure_offered && !processed_crypto_audio) {
		ast_log(LOG_NOTICE, "Sofia: SDP rejected — m=audio RTP/SAVP without valid a=crypto\n");
		goto sdp_reject;
	}
	if (video_secure_offered && !processed_crypto_video) {
		ast_log(LOG_NOTICE, "Sofia: SDP rejected — m=video RTP/SAVP without valid a=crypto\n");
		goto sdp_reject;
	}
	if (pvt->peer && pvt->peer->encryption) {
		if (audio_offered && !audio_secure_offered) {
			ast_log(LOG_NOTICE, "Sofia: SDP rejected — peer '%s' requires encryption, audio offer is plain RTP/AVP\n",
				pvt->peer->name);
			goto sdp_reject;
		}
		if (video_offered && !video_secure_offered) {
			ast_log(LOG_NOTICE, "Sofia: SDP rejected — peer '%s' requires encryption, video offer is plain RTP/AVP\n",
				pvt->peer->name);
			goto sdp_reject;
		}
	}

	/* Every reject gate passed — commit the staged crypto here (the ONLY place live
	 * SRTP is (re-)keyed, so a would-be-rejected re-INVITE never touched it). We may
	 * 488 only on a -1 from a stream not yet live; once a stream is live or a commit
	 * may have mutated live media (-2), we accept rather than leave it corrupt. */
	{
		int committed_any = 0;
		/* sdp_crypto_commit: 1 = committed live, 0 = no-op, -1 = failed before any
		 * live mutation (safe to reject), -2 = failed after a possible live mutation
		 * (must not reject). committed_any tracks ONLY a real live commit. */
		if (pvt->srtp && pvt->srtp->crypto) {
			int crc = sdp_crypto_commit(pvt->srtp->crypto, pvt->rtp);
			if (crc == 1) {
				committed_any = 1;
			} else if (crc == -2) {
				committed_any = 1;
				ast_log(LOG_WARNING, "Sofia: audio SRTP activation failed after a possible live mutation — accepting SDP to avoid a corrupt-and-rejected state\n");
			} else if (crc == -1) {	/* pre-activation failure, nothing live touched */
				ast_log(LOG_NOTICE, "Sofia: SDP rejected — audio SRTP commit failed before activation\n");
				goto sdp_reject;
			}
			/* crc == 0: no-op (nothing staged) — committed_any unchanged */
		}
		if (pvt->vsrtp && pvt->vsrtp->crypto) {
			int crc = sdp_crypto_commit(pvt->vsrtp->crypto, pvt->vrtp);
			if (crc == 1) {
				committed_any = 1;
			} else if (crc == -2) {
				committed_any = 1;
				ast_log(LOG_WARNING, "Sofia: video SRTP activation failed after a possible live mutation — accepting SDP\n");
			} else if (crc == -1) {
				if (!committed_any) {	/* nothing went live yet: safe to reject */
					ast_log(LOG_NOTICE, "Sofia: SDP rejected — video SRTP commit failed before activation\n");
					goto sdp_reject;
				}
				/* a stream already went live: cannot reject without corrupting it */
				ast_log(LOG_WARNING, "Sofia: video SRTP commit failed but audio is already live — accepting SDP (video without SRTP)\n");
			}
			/* crc == 0: no-op */
		}
	}

	/* COMMIT: every reject gate passed. Install the staged codec maps into the live
	 * RTP instances now (a reject returned via sdp_reject before reaching here). */
	if (staged_audio_valid) {
		ast_rtp_codecs_payloads_copy(&staged_audio_codecs,
			ast_rtp_instance_get_codecs(pvt->rtp), pvt->rtp);
		/* SIP history: the SDP is ACCEPTED here (every reject gate passed) — record the negotiated
		 * audio codec NAMES (metadata only, no body) for verbose analysis. */
		if (pvt->capability & AST_FORMAT_AUDIO_MASK) {
			char cbuf[64];
			ast_getformatname_multiple(cbuf, sizeof(cbuf), pvt->capability & AST_FORMAT_AUDIO_MASK);
			sofia_append_history(pvt, "SDP", "audio negotiated: %s", cbuf);
		}
	}
	if (staged_video_valid && pvt->vrtp) {
		ast_rtp_codecs_payloads_copy(&staged_video_codecs,
			ast_rtp_instance_get_codecs(pvt->vrtp), pvt->vrtp);
	}
	ast_rtp_codecs_payloads_clear(&staged_audio_codecs, NULL);
	ast_rtp_codecs_payloads_clear(&staged_video_codecs, NULL);

	/* COMMIT: one ref+lock+revalidate dance applying the deferred side-effects in the
	 * original order — under the channel lock: audio native format → fds[5] attach →
	 * T.38 state-change (the REQUEST_NEGOTIATE frame MUST follow fds[5] so app_fax
	 * sees the UDPTL fd) → arm/cancel t38id → snapshot fax-redirect inputs; THEN drop
	 * the lock and run ast_exists_extension / FAXEXTEN / ast_async_goto (they take
	 * their own locks). Advance and withdraw are mutually exclusive. */
	if (staged_chosen_audio_valid || t38_stage_fds5 || t38_stage_enter_reinvite || t38_stage_withdraw) {
		struct ast_channel *o = pvt->owner;
		if (o) {
			char fax_context[AST_MAX_CONTEXT] = "";
			char fax_exten[AST_MAX_EXTENSION] = "";
			const char *fax_cid = NULL;	/* ast_strdupa, no truncation */
			int do_fax = 0;
			ast_channel_ref(o);
			ast_channel_lock(o);
			if (pvt->owner == o) {
				if (staged_chosen_audio_valid) {
					o->nativeformats =
						(o->nativeformats & ~AST_FORMAT_AUDIO_MASK) | staged_chosen_audio;
					ast_set_read_format(o, staged_chosen_audio);
					ast_set_write_format(o, staged_chosen_audio);
				}
				if (t38_stage_fds5 && pvt->udptl) {
					o->fds[5] = ast_udptl_fd(pvt->udptl);
				}
				if (t38_stage_enter_reinvite) {
					/* frame AFTER the fds[5] attach above */
					sofia_change_t38_state(pvt, SOFIA_T38_PEER_REINVITE);
					if (sofia_sched && pvt->t38id == -1) {
						ao2_ref(pvt, +1);  /* held by scheduler entry */
						pvt->t38id = ast_sched_thread_add(sofia_sched,
							SOFIA_T38_ABORT_TIMEOUT_MS, sofia_t38_abort, pvt);
						if (pvt->t38id < 0) {
							pvt->t38id = -1;
							ao2_ref(pvt, -1);  /* schedule failed; release ref */
						}
					}
					/* Snapshot fax-redirect inputs while locked (faxdetect=t38 +
					 * not already at "fax"). */
					if (pvt->peer && (pvt->peer->faxdetect_mode & SOFIA_FAX_DETECT_T38)
					    && strcmp(o->exten, "fax")) {
						ast_copy_string(fax_context, S_OR(o->macrocontext, o->context), sizeof(fax_context));
						ast_copy_string(fax_exten, o->exten, sizeof(fax_exten));
						if (o->caller.id.number.valid && o->caller.id.number.str) {
							/* ast_strdupa under the lock; valid until function return. */
							fax_cid = ast_strdupa(o->caller.id.number.str);
						}
						do_fax = 1;
					}
				} else if (t38_stage_withdraw) {
					sofia_change_t38_state(pvt, SOFIA_T38_DISABLED);
					if (pvt->t38id != -1 && sofia_sched) {
						if (ast_sched_thread_del(sofia_sched, pvt->t38id) == 0) {
							ao2_ref(pvt, -1);
						}
						pvt->t38id = -1;
					}
				}
			}
			ast_channel_unlock(o);
			/* dialplan ops after the unlock, on the ref-pinned o */
			if (do_fax) {
				if (ast_exists_extension(o, fax_context, "fax", 1, fax_cid)) {
					ast_verbose(VERBOSE_PREFIX_2 "Sofia: redirecting '%s' to fax extension due to peer T.38 re-INVITE\n",
						o->name);
					pbx_builtin_setvar_helper(o, "FAXEXTEN", fax_exten);
					if (ast_async_goto(o, fax_context, "fax", 1)) {
						ast_log(LOG_NOTICE, "Sofia: T.38 reINVITE detected — failed async goto fax extension on '%s'\n",
							o->name);
					}
				} else {
					ast_log(LOG_NOTICE, "Sofia: T.38 reINVITE detected but no fax extension on '%s'\n",
						o->name);
				}
			}
			ast_channel_unref(o);
		} else if (t38_stage_withdraw) {
			/* No owner: sofia_change_t38_state would NO-OP (it does `chan = pvt->owner; if
			 * (!chan) return;` before writing t38_state), leaving state stale at
			 * PEER_REINVITE. Set DISABLED directly + cancel the t38id timer. */
			pvt->t38_state = SOFIA_T38_DISABLED;
			if (pvt->t38id != -1 && sofia_sched) {
				if (ast_sched_thread_del(sofia_sched, pvt->t38id) == 0) {
					ao2_ref(pvt, -1);
				}
				pvt->t38id = -1;
			}
		}
	}

	return 0;

sdp_reject:
	/* Single reject-cleanup: free the parser if still owned (NULL after the in-loop
	 * free, so no double-free), roll back SRTP staging once, restore capability. */
	if (parser) {
		sdp_parser_free(parser);
	}
	sofia_sdp_stage_rollback(pvt, audio_srtp_was_new, video_srtp_was_new);
	pvt->capability = orig_capability;
	/* Restore the live media state the loop may have mutated (codec-map copies and
	 * irreversible side-effects are deferred past the gates, so need no restore).
	 * had_vrtp/had_udptl guard instances that only exist after a lazy create. */
	pvt->t38_their_parms = orig_t38_their_parms;
	pvt->t38_max_ifp = orig_t38_max_ifp;
	ast_rtp_instance_set_remote_address(pvt->rtp, &orig_audio_remote);
	if (had_vrtp) {
		ast_rtp_instance_set_remote_address(pvt->vrtp, &orig_video_remote);
	}
	if (had_udptl) {
		/* Restore a PRE-EXISTING udptl's peer + EC scheme + far_max_datagram (a was_new udptl is
		 * destroyed below instead). The EC/datagram setters take the value-faithful getter
		 * snapshots captured before the loop. */
		ast_udptl_set_peer(pvt->udptl, &orig_udptl_peer);
		ast_udptl_set_error_correction_scheme(pvt->udptl, orig_udptl_ec);
		ast_udptl_set_far_max_datagram(pvt->udptl, orig_udptl_far_datagram);
	}
	/* Discard the staged codec maps — on a reject they were NEVER copied into the live RTP
	 * instances (the commit copy is past this label), so there is nothing to restore; just free
	 * them. Clearing an empty/unbuilt map is a safe no-op. */
	ast_rtp_codecs_payloads_clear(&staged_audio_codecs, NULL);
	ast_rtp_codecs_payloads_clear(&staged_video_codecs, NULL);
	/* If pvt->vrtp was LAZILY CREATED this parse (!had_vrtp but now non-NULL), a rejected SDP must
	 * not leave a stray video RTP instance — destroy it (mirrors the SRTP was_new rollback). Placed
	 * AFTER sofia_sdp_stage_rollback above so a was_new vsrtp is torn down first (sofia_srtp_destroy
	 * frees only the srtp/crypto, never derefs pvt->vrtp). The m=video lazy create wires no channel
	 * fd, so destroy + NULL is the complete cleanup. Mutually exclusive with the had_vrtp restore
	 * above (that branch only runs for a PRE-existing vrtp). */
	if (!had_vrtp && pvt->vrtp) {
		ast_rtp_instance_destroy(pvt->vrtp);
		pvt->vrtp = NULL;
	}
	/* Destroy a udptl LAZILY CREATED this parse (!had_udptl but now non-NULL). The fds[5] channel
	 * attach was DEFERRED to commit, so on a reject it was never wired — destroy + NULL is the
	 * complete cleanup (mirrors the vrtp/SRTP was_new rollback). Mutually exclusive with the
	 * had_udptl peer/EC/datagram restore above (that runs only for a pre-existing udptl). */
	if (!had_udptl && pvt->udptl) {
		ast_udptl_destroy(pvt->udptl);
		pvt->udptl = NULL;
	}
	return -1;
}

int sofia_sdp_extract_hold(sip_t const *sip, su_home_t *home)
{
	sdp_parser_t *parser;
	sdp_session_t *sdp;
	int hold = 0;

	if (!sip || !sip->sip_payload || !sip->sip_payload->pl_data || !home) {
		return 0;
	}
	parser = sdp_parse(home, sip->sip_payload->pl_data, sip->sip_payload->pl_len, 0);
	if (!parser) {
		return 0;
	}
	sdp = sdp_session(parser);
	if (sdp) {
		sdp_media_t *m;
		/* Inspect the AUDIO descriptor, not just the first m= line (a leading
		 * m=image/video would mis-detect hold). */
		for (m = sdp->sdp_media; m; m = m->m_next) {
			if (m->m_type == sdp_media_audio && m->m_port != 0) {
				if (m->m_mode == sdp_sendonly || m->m_mode == sdp_inactive) {
					hold = 1;
				}
				break;
			}
		}
	}
	sdp_parser_free(parser);
	return hold;
}

