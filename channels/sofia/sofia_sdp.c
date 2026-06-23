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

	/* A4 WebRTC answer a= block: emitted into rtpmap_buf so it lands inside the m=audio section.
	 * Single-audio happy path; full BUNDLE/multi-m + a=mid/a=group + a=tls-id are deferred to the e2e
	 * interop pass (resolved against a captured browser offer). The candidate ADDR reuses `host`
	 * (already resolved via ourip/externaddr/media_address above — channel-owned NAT mapping) and `port`
	 * (the live RTP port). a=end-of-candidates: ICE-lite, one host candidate, no trickle (RFC 8838/8829).
	 * Each snprintf is truncation-checked into overflow. */
	if (pvt->is_webrtc) {
		struct ast_rtp_engine_dtls *dtls = ast_rtp_instance_get_dtls(pvt->rtp);
		struct ast_rtp_engine_ice *ice = ast_rtp_instance_get_ice(pvt->rtp);
		const char *lfp = dtls ? dtls->get_fingerprint(pvt->rtp) : NULL;
		const char *lufrag = ice ? ice->get_ufrag(pvt->rtp) : NULL;
		const char *lpwd = ice ? ice->get_password(pvt->rtp) : NULL;

		overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), "a=rtcp-mux\r\n");
		/* a=setup from the engine negotiated DTLS role (audit LOW): we answer active for the
		 * common actpass offer, but a remote setup:active makes the engine passive; advertise the
		 * real role so both sides are never the DTLS client (RFC 5763 s5).
		 * A5: on the OUTBOUND offer leg (webrtc_offerer) get_setup() returns ACTPASS
		 * because sofia_webrtc_provision_offer set default_setup=ACTPASS and did NOT
		 * call set_setup() — so this same code emits a=setup:actpass for the offer with
		 * zero change. The concrete role is fixed from the answer's a=setup later. */
		{
			enum ast_rtp_dtls_setup _os = dtls ? dtls->get_setup(pvt->rtp) : AST_RTP_DTLS_SETUP_ACTIVE;
			const char *_ss = (_os == AST_RTP_DTLS_SETUP_PASSIVE) ? "passive"
				: (_os == AST_RTP_DTLS_SETUP_ACTPASS) ? "actpass" : "active";
			if (snprintf(tmp_buf, sizeof(tmp_buf), "a=setup:%s\r\n", _ss) >= (int)sizeof(tmp_buf)) {
				overflow = 1;
			} else {
				overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
			}
		}
		if (lfp) {
			if (snprintf(tmp_buf, sizeof(tmp_buf), "a=fingerprint:sha-256 %s\r\n", lfp) >= (int)sizeof(tmp_buf)) {
				overflow = 1;
			} else {
				overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
			}
		}
		overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), "a=ice-lite\r\n");
		if (lufrag) {
			if (snprintf(tmp_buf, sizeof(tmp_buf), "a=ice-ufrag:%s\r\n", lufrag) >= (int)sizeof(tmp_buf)) {
				overflow = 1;
			} else {
				overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
			}
		}
		if (lpwd) {
			if (snprintf(tmp_buf, sizeof(tmp_buf), "a=ice-pwd:%s\r\n", lpwd) >= (int)sizeof(tmp_buf)) {
				overflow = 1;
			} else {
				overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
			}
		}
		/* One ICE-lite host candidate from the channel-owned host:port (RFC 8445 host typepref). */
		if (snprintf(tmp_buf, sizeof(tmp_buf), "a=candidate:0 1 UDP 2130706431 %s %d typ host\r\n", host, port) >= (int)sizeof(tmp_buf)) {
			overflow = 1;
		} else {
			overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
		}
		overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), "a=end-of-candidates\r\n");
		/* a=mid: echo the offered media identifier (RFC 5888 §4 / RFC 8829 §5.3.1).
		 * Defaults to "0" (set at the WebRTC commit) so a mid is always present —
		 * required when we also emit session-level a=group:BUNDLE below. */
		if (snprintf(tmp_buf, sizeof(tmp_buf), "a=mid:%s\r\n",
				!ast_strlen_zero(pvt->webrtc_mid) ? pvt->webrtc_mid : "0") >= (int)sizeof(tmp_buf)) {
			overflow = 1;
		} else {
			overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
		}
		/* a=tls-id: stable per-DTLS-association id (RFC 8842 §5.2 / RFC 8829 §5.3.1).
		 * Emitted at media level (valid at both per RFC 8842 §5.2); single audio
		 * m-section so media level is unambiguous. Generated once at the commit. */
		if (!ast_strlen_zero(pvt->webrtc_tls_id)) {
			if (snprintf(tmp_buf, sizeof(tmp_buf), "a=tls-id:%s\r\n", pvt->webrtc_tls_id) >= (int)sizeof(tmp_buf)) {
				overflow = 1;
			} else {
				overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), tmp_buf);
			}
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
	/* A4 interop: session-level a=group:BUNDLE MUST appear in the session section
	 * BEFORE the first m= line (RFC 8843 §1 / RFC 8829 §5.3.1). We build the line
	 * into a local buffer and splice it between t= and m=audio inside the single
	 * session snprintf via a leading "%s" arg (empty string when not WebRTC/no
	 * bundle, so non-WebRTC SDP is byte-identical). The mid in the group MUST
	 * match the m=audio a=mid emitted above (both default to "0"). */
	char group_buf[96] = "";
	if (pvt->is_webrtc && pvt->webrtc_bundle) {
		if (snprintf(group_buf, sizeof(group_buf), "a=group:BUNDLE %s\r\n",
				!ast_strlen_zero(pvt->webrtc_mid) ? pvt->webrtc_mid : "0") >= (int)sizeof(group_buf)) {
			overflow = 1;
			group_buf[0] = '\0';
		}
	}
	if (snprintf(buf, len,
		"v=0\r\n"
		"o=- %lu %lu IN %s %s\r\n"
		"s=GABpbx\r\n"
		"c=IN %s %s\r\n"
		"t=0 0\r\n"
		"%s"
		"m=audio %d %s %s\r\n"
		"%s"
		"a=sendrecv\r\n",
		pvt->sess_id, pvt->sess_version,
		sdp_family, host, sdp_family, host,
		group_buf,
		port,
		pvt->is_webrtc ? "UDP/TLS/RTP/SAVPF"
			: ((pvt->srtp && pvt->srtp->crypto) ? "RTP/SAVP" : "RTP/AVP"),
		payload_buf, rtpmap_buf) >= (int)len) {	/* truncated audio SDP */
		overflow = 1;
	}

	/* Video block — only when video capability present and vrtp allocated. SUPPRESSED on a WebRTC leg
	 * (A4/A5 are AUDIO-ONLY): a plain RTP/AVP m=video in a WebRTC offer/answer (no a=mid/ice/fingerprint,
	 * not in a=group:BUNDLE) makes the browser reject the WHOLE SDP with 488 Not Acceptable Here — this is
	 * the 207<->204 browser-to-browser failure. An audio-only offer/answer is valid (RFC 3264); video-over-
	 * WebRTC is deferred (OQ5). */
	if (!pvt->is_webrtc && pvt->vrtp && (pvt->capability & AST_FORMAT_VIDEO_MASK)) {
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
	/* SUPPRESSED on a WebRTC leg (A4/A5 audio-only): a plain m=image udptl t38 in a WebRTC SDP is the
	 * same mixed-media 488 class as plain video (Codex audit) — no mid/ICE/fingerprint/BUNDLE. T.38 fax
	 * is never active on a browser audio call anyway; gate for completeness. */
	if (!pvt->is_webrtc && pvt->udptl) {
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

/* A5: provision local DTLS(actpass)+ICE-lite for an OUTBOUND WebRTC OFFER. Mirror
 * of the A4 answerer commit (this file's WebRTC commit block) with NO remote
 * inputs: default_setup = ACTPASS, role CONTROLLED, ice_lite advertised. set_setup
 * and ice->start are intentionally NOT called here (no remote role/creds yet). */
int sofia_webrtc_provision_offer(struct sofia_pvt *pvt)
{
	struct ast_rtp_engine_dtls *dtls;
	struct ast_rtp_engine_ice *ice;
	struct ast_rtp_dtls_cfg dtls_cfg = { 0 };

	if (!pvt || !pvt->rtp) {
		return -1;
	}
	if (pvt->is_webrtc) {
		return 0;	/* already provisioned (idempotent for fork/retry) */
	}
	dtls = ast_rtp_instance_get_dtls(pvt->rtp);
	ice = ast_rtp_instance_get_ice(pvt->rtp);
	/* Same fail-closed gate as the A4 commit: vtables are engine-level (always
	 * non-NULL); the real check is sofia_sched, needed for the DTLS retransmit
	 * timer. Without it set_configuration would deref a NULL sched. */
	if (!dtls || !ice || !sofia_sched) {
		ast_log(LOG_WARNING, "Sofia: cannot offer WebRTC to peer '%s' — no scheduler for DTLS timers (sofia_sched=%p dtls=%p ice=%p)\n",
			pvt->peer ? pvt->peer->name : "<unknown>", (void *)sofia_sched, (void *)dtls, (void *)ice);
		return -1;
	}
	dtls_cfg.enabled = 1;
	dtls_cfg.default_setup = AST_RTP_DTLS_SETUP_ACTPASS;	/* A5: offerer advertises actpass (RFC 5763 §5) */
	dtls_cfg.suite = AST_AES_CM_128_HMAC_SHA1_80;
	dtls_cfg.hash = AST_RTP_DTLS_HASH_SHA256;
	dtls_cfg.verify = AST_RTP_DTLS_VERIFY_FINGERPRINT;
	dtls_cfg.ephemeral_cert = 1;
	if (dtls->set_configuration(pvt->rtp, &dtls_cfg)) {
		ast_log(LOG_WARNING, "Sofia: WebRTC offer aborted — DTLS set_configuration failed for peer '%s'\n",
			pvt->peer ? pvt->peer->name : "<unknown>");
		return -1;
	}
	/* NO set_setup() here: keep dtls_setup == ACTPASS so dtls->get_setup() (read by
	 * sofia_generate_sdp) yields actpass. The concrete role is fixed later from the
	 * answer's a=setup via set_setup at the answer-parse commit. */
	if (ice->ice_lite) {
		ice->ice_lite(pvt->rtp);	/* we advertise a=ice-lite */
	}
	ice->set_role(pvt->rtp, AST_RTP_ICE_ROLE_CONTROLLED);	/* idempotent lite clamp */
	/* Arm the STUN responder NOW (ice_active=1), BEFORE the offer leaves the wire. A browser
	 * begins ICE the instant it receives our offer and fires connectivity checks at our
	 * advertised candidate; ice->start() was historically deferred to the answer-parse, leaving
	 * an ice_active==0 DEAD-WINDOW in which ice_handle_stun() silently drops those early checks
	 * (including the nominating USE-CANDIDATE — no retry queue), so ~1/3 of offerer legs never
	 * validated → no DTLS → no audio. Safe with no remote creds yet: the responder authenticates
	 * with our LOCAL ufrag/pwd only (CSPRNG-seeded at ast_rtp_new), never the remote creds; the
	 * answer's set_authentication still runs later. ice->start() only sets ice_active=1, idempotent
	 * with the answer-apply's call. */
	if (ice->start) {
		ice->start(pvt->rtp);
	}

	/* Seed the answer-echo fields so the emit block produces a complete offer.
	 * mid defaults to "0" (JSEP first-mid); we BUNDLE on our own initiative; tls-id
	 * generated once (stable per DTLS association, RFC 8842 §5.2). */
	ast_copy_string(pvt->webrtc_mid, "0", sizeof(pvt->webrtc_mid));
	pvt->webrtc_bundle = 1;
	if (ast_strlen_zero(pvt->webrtc_tls_id)) {
		unsigned char tb[16];
		int ti;
		for (ti = 0; ti < (int)sizeof(tb); ti++) {
			tb[ti] = ast_random() & 0xff;
		}
		for (ti = 0; ti < (int)sizeof(tb); ti++) {
			snprintf(pvt->webrtc_tls_id + ti * 2,
				sizeof(pvt->webrtc_tls_id) - ti * 2, "%02x", tb[ti]);
		}
	}
	pvt->webrtc_offerer = 1;	/* A5 discriminator (set BEFORE is_webrtc) */
	pvt->is_webrtc = 1;		/* gate the emitter — sofia_generate_sdp now emits a WebRTC offer */
	return 0;
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
	/* A4 WebRTC: SAVPF offer detected (only when peer->webrtc). All WebRTC attrs are
	 * PARSE-ONLY-STAGED here and applied to the live DTLS/ICE engine ONCE at the
	 * post-gate commit block, mirroring the SDES validate-then-commit discipline
	 * (OQ2/M5/M7). rtp_engine.h (included at top) brings the dtls/ice types + the
	 * suite enum (via gabpbx/res_srtp.h). */
	int audio_webrtc_offered = 0;
	int audio_savpf_offered = 0;	/* a DTLS (UDP/TLS/) audio media profile was offered (HIGH1) */
	int video_savpf_offered = 0;	/* a DTLS (UDP/TLS/) video media profile was offered (audit HIGH) */
	struct {
		int have_fingerprint;
		int have_setup;
		int have_ice_ufrag;	/* HIGH3: ICE creds tracked separately, both required */
		int have_ice_pwd;
		int have_rtcp_mux;	/* HIGH2: remote a=rtcp-mux required (mux-only engine) */
		enum ast_rtp_dtls_hash fp_hash;
		char fp_value[256];
		enum ast_rtp_dtls_setup remote_setup;
		char ice_ufrag[257];
		char ice_pwd[257];
		int remote_ice_lite;
		struct ast_sockaddr cand[8];	/* host candidates only (typ host); srflx/relay ignored */
		int cand_count;
		/* A4 interop: offered audio a=mid token (RFC 5888 §4) + whether a session-
		 * or media-level a=group:BUNDLE was present (RFC 8843). Echoed back in the
		 * answer's m=audio (a=mid) and at session level (a=group:BUNDLE <mid>). */
		char mid[64];
		int have_mid;
		int have_bundle;	/* a=group:BUNDLE seen (session or media level) */
	} wrtc = { 0 };
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

	/* A4 interop: detect a session-level a=group:BUNDLE (RFC 8843 §1: the group
	 * attribute lives at session level, sdp->sdp_attributes, NOT in any m= block).
	 * sdp_attribute_find walks the session attribute list (sofia-sip sdp.h:96/444).
	 * Only meaningful for a webrtc peer; the media loop also OR-detects a stray
	 * media-level group for tolerant parsing. */
	if (pvt->peer && pvt->peer->webrtc && sdp->sdp_attributes
			&& sdp_attribute_find(sdp->sdp_attributes, "group")) {
		sdp_attribute_t *ga = sdp_attribute_find(sdp->sdp_attributes, "group");
		if (ga && ga->a_value && !strncasecmp(ga->a_value, "BUNDLE", 6)) {
			wrtc.have_bundle = 1;
		}
	}

	for (media = sdp->sdp_media; media; media = media->m_next) {
		if (media->m_type == sdp_media_audio && media->m_port != 0) {
			sdp_attribute_t *a;
			audio_offered = 1;
			if (media->m_proto == sdp_proto_srtp) {
				audio_secure_offered = 1;
			}
			/* A4 OQ2: treat a SAVPF (UDP/TLS/RTP/SAVPF) audio offer as WebRTC ONLY for a
			 * webrtc=yes peer. A non-webrtc peer offering SAVPF leaves this 0 and falls to
			 * the encryption/no-crypto reject path (NOT silently downgraded). */
			/* sofia-sip maps BOTH plain RTP/SAVPF and the WebRTC UDP/TLS/RTP/SAVPF to the same enum
			 * sdp_proto_extended_srtp (261), and UDP/TLS/RTP/AVPF to extended_rtp (262). Key on the
			 * "UDP/TLS/" proto-NAME prefix to POSITIVELY identify the DTLS media profiles so a plain
			 * non-DTLS RTP/SAVPF (AVPF/SDES) offer is not force-rejected (audit MEDIUM + the 262 LOW),
			 * and so the HIGH1 anti-downgrade gate covers any DTLS audio profile. */
			if (media->m_proto_name && !strncasecmp(media->m_proto_name, "UDP/TLS/", 8)) {
				audio_savpf_offered = 1;	/* a DTLS-SRTP audio media profile was offered */
				if (pvt->peer && pvt->peer->webrtc) {
					audio_webrtc_offered = 1;
				}
			}
			for (a = media->m_attributes; a; a = a->a_next) {
				if (!audio_webrtc_offered && a->a_name && su_casematch(a->a_name, "crypto") && a->a_value) {
					if (sofia_process_crypto(pvt, pvt->rtp, &pvt->srtp, a->a_value)) {
						processed_crypto_audio = 1;
						/* SDES: first valid a=crypto wins (byte-identical to pre-A4). A WebRTC
						 * offer carries no a=crypto, so do NOT break — keep walking to stage the
						 * fingerprint/setup/ICE attrs below. */
						if (!audio_webrtc_offered) {
							break;
						}
					}
				} else if (audio_webrtc_offered && a->a_name && a->a_value
						&& su_casematch(a->a_name, "fingerprint")) {
					/* a=fingerprint:<hash> <hex> — only sha-256 accepted (M5/RFC 8122). */
					char fp_alg[32];
					char fp_hex[256];
					if (sscanf(a->a_value, "%31s %255s", fp_alg, fp_hex) == 2
							&& !strcasecmp(fp_alg, "sha-256")) {
						wrtc.fp_hash = AST_RTP_DTLS_HASH_SHA256;
						ast_copy_string(wrtc.fp_value, fp_hex, sizeof(wrtc.fp_value));
						wrtc.have_fingerprint = 1;
					}
				} else if (audio_webrtc_offered && a->a_name && a->a_value
						&& su_casematch(a->a_name, "setup")) {
					/* a=setup:active|passive|actpass — staged VERBATIM (OQ8: A2 maps
					 * remote->our role internally). holdconn intentionally not staged. */
					if (!strcasecmp(a->a_value, "active")) {
						wrtc.remote_setup = AST_RTP_DTLS_SETUP_ACTIVE;
						wrtc.have_setup = 1;
					} else if (!strcasecmp(a->a_value, "passive")) {
						wrtc.remote_setup = AST_RTP_DTLS_SETUP_PASSIVE;
						wrtc.have_setup = 1;
					} else if (!strcasecmp(a->a_value, "actpass")) {
						wrtc.remote_setup = AST_RTP_DTLS_SETUP_ACTPASS;
						wrtc.have_setup = 1;
					}
				} else if (audio_webrtc_offered && a->a_name && a->a_value
						&& su_casematch(a->a_name, "ice-ufrag")) {
					ast_copy_string(wrtc.ice_ufrag, a->a_value, sizeof(wrtc.ice_ufrag));
					wrtc.have_ice_ufrag = 1;
				} else if (audio_webrtc_offered && a->a_name && a->a_value
						&& su_casematch(a->a_name, "ice-pwd")) {
					ast_copy_string(wrtc.ice_pwd, a->a_value, sizeof(wrtc.ice_pwd));
					wrtc.have_ice_pwd = 1;
				} else if (audio_webrtc_offered && a->a_name && a->a_value
						&& su_casematch(a->a_name, "candidate")) {
					/* a=candidate:<foundation> <comp> <transport> <prio> <ip> <port> typ host ...
					 * Stage HOST candidates only (ICE-lite); ignore srflx/relay/tcp. */
					char c_ip[64];
					char c_transport[16];
					unsigned int c_port = 0;
					char c_typ[16] = "";
					if (sscanf(a->a_value, "%*s %*u %15s %*u %63s %u typ %15s",
							c_transport, c_ip, &c_port, c_typ) == 4
							&& !strcasecmp(c_typ, "host")
							&& !strcasecmp(c_transport, "udp")
							&& wrtc.cand_count < (int)(sizeof(wrtc.cand) / sizeof(wrtc.cand[0]))) {
						struct ast_sockaddr ca;
						if (ast_sockaddr_parse(&ca, c_ip, PARSE_PORT_FORBID)) {
							ast_sockaddr_set_port(&ca, c_port);
							wrtc.cand[wrtc.cand_count++] = ca;
						}
					}
				} else if (audio_webrtc_offered && a->a_name
						&& su_casematch(a->a_name, "ice-lite")) {
					wrtc.remote_ice_lite = 1;
				} else if (audio_webrtc_offered && a->a_name
						&& su_casematch(a->a_name, "rtcp-mux")) {
					wrtc.have_rtcp_mux = 1;	/* HIGH2: remote requested mux */
				} else if (audio_webrtc_offered && a->a_name && a->a_value
						&& su_casematch(a->a_name, "mid")) {
					/* a=mid:<token> (RFC 5888 §4) — echoed VERBATIM in the answer
					 * m=audio + session a=group:BUNDLE (RFC 8829 §5.3.1). */
					ast_copy_string(wrtc.mid, a->a_value, sizeof(wrtc.mid));
					wrtc.have_mid = 1;
				} else if (audio_webrtc_offered && a->a_name && a->a_value
						&& su_casematch(a->a_name, "group")
						&& !strncasecmp(a->a_value, "BUNDLE", 6)) {
					wrtc.have_bundle = 1;	/* tolerate a (non-standard) media-level group */
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
			/* Audit HIGH: a m=video DTLS profile (UDP/TLS/RTP/SAVPF|AVPF) must be REJECTED below, never
			 * silently answered RTP/AVP (the same forbidden downgrade HIGH1 closes for audio). A4 is
			 * audio-only / answerer-only; video-over-WebRTC is deferred (OQ5). */
			if (media->m_proto_name && !strncasecmp(media->m_proto_name, "UDP/TLS/", 8)) {
				video_savpf_offered = 1;
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

	/* A4 interop (RFC 3264 §6 / RFC 8829): the current single-audio answer builder
	 * emits exactly one m=audio (+ optional m=video/m=image we already negotiate).
	 * A browser PeerConnection MAY offer extra m= sections we do not negotiate —
	 * most commonly an m=application (SCTP datachannel) section, and sometimes
	 * m=video. RFC 3264 §6 (line 468) requires "For each m= line in the offer,
	 * there MUST be a corresponding m= line in the answer", and a rejected stream
	 * MUST be reflected at port 0 (line 480-481). The current builder does NOT
	 * reflect a non-audio/video/image m= section, so a datachannel-bearing offer
	 * yields an answer with fewer m= lines than the offer — which Chrome/SIP.js
	 * will REJECT (m-line mismatch) even though the audio itself is fine. Full
	 * port-0 reflection of arbitrary extra m= lines is a larger builder refactor;
	 * the minimal step here is to DETECT + log the limitation so an interop
	 * failure is diagnosable rather than silent. Browser-Phone / SIP.js voice
	 * calls (the operator's *69 case) are typically audio-ONLY (no datachannel,
	 * no video) — so this path is expected NOT to trigger for *69. */
	/* Firefox places a=fingerprint / a=setup / a=ice-ufrag / a=ice-pwd at SESSION
	 * level (before the first m=), not per-media, so the media-attribute loop above
	 * leaves the wrtc.have_* flags clear and the WebRTC commit gate would reject the
	 * body. Mirror the session-level BUNDLE lookup at :804: walk sdp->sdp_attributes
	 * with sdp_attribute_find and fill ONLY the fields the media loop left unset,
	 * using the SAME parse logic as the media loop. Gated on audio_webrtc_offered
	 * (set only for a webrtc=yes peer offering UDP/TLS/), so plain SIP is untouched.
	 * Covers BOTH the inbound-offer (A4) and the inbound-answer (A5) bodies. */
	if (audio_webrtc_offered && sdp->sdp_attributes) {
		sdp_attribute_t *sa;
		if (!wrtc.have_fingerprint && (sa = sdp_attribute_find(sdp->sdp_attributes, "fingerprint")) && sa->a_value) {
			char fp_alg[32];
			char fp_hex[256];
			if (sscanf(sa->a_value, "%31s %255s", fp_alg, fp_hex) == 2
					&& !strcasecmp(fp_alg, "sha-256")) {
				wrtc.fp_hash = AST_RTP_DTLS_HASH_SHA256;
				ast_copy_string(wrtc.fp_value, fp_hex, sizeof(wrtc.fp_value));
				wrtc.have_fingerprint = 1;
			}
		}
		if (!wrtc.have_setup && (sa = sdp_attribute_find(sdp->sdp_attributes, "setup")) && sa->a_value) {
			if (!strcasecmp(sa->a_value, "active")) {
				wrtc.remote_setup = AST_RTP_DTLS_SETUP_ACTIVE;
				wrtc.have_setup = 1;
			} else if (!strcasecmp(sa->a_value, "passive")) {
				wrtc.remote_setup = AST_RTP_DTLS_SETUP_PASSIVE;
				wrtc.have_setup = 1;
			} else if (!strcasecmp(sa->a_value, "actpass")) {
				wrtc.remote_setup = AST_RTP_DTLS_SETUP_ACTPASS;
				wrtc.have_setup = 1;
			}
		}
		if (!wrtc.have_ice_ufrag && (sa = sdp_attribute_find(sdp->sdp_attributes, "ice-ufrag")) && sa->a_value) {
			ast_copy_string(wrtc.ice_ufrag, sa->a_value, sizeof(wrtc.ice_ufrag));
			wrtc.have_ice_ufrag = 1;
		}
		if (!wrtc.have_ice_pwd && (sa = sdp_attribute_find(sdp->sdp_attributes, "ice-pwd")) && sa->a_value) {
			ast_copy_string(wrtc.ice_pwd, sa->a_value, sizeof(wrtc.ice_pwd));
			wrtc.have_ice_pwd = 1;
		}
	}

	{
		sdp_media_t *mm;
		int extra_mlines = 0;
		for (mm = sdp->sdp_media; mm; mm = mm->m_next) {
			if (mm->m_type != sdp_media_audio
					&& mm->m_type != sdp_media_video
					&& mm->m_type != sdp_media_image) {
				extra_mlines++;
			}
		}
		if (audio_webrtc_offered && extra_mlines) {
			ast_log(LOG_NOTICE, "Sofia: WebRTC offer for '%s' has %d extra m= section(s) "
				"(e.g. datachannel) the answer does not reflect at port 0 "
				"(RFC 3264 §6) — the browser may reject the answer for an m-line "
				"mismatch; audio-only offers are unaffected\n",
				S_OR(pvt->callid, "<unknown>"), extra_mlines);
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
	/* A4 HIGH1: a SAVPF (UDP/TLS/RTP/SAVPF) audio offer NOT accepted as WebRTC (peer lacks
	 * webrtc=yes) must be REJECTED, never silently answered as RTP/AVP — the browser offered
	 * DTLS-SRTP media (RFC 5764/8827) and an AVP answer cannot establish media. */
	if (audio_savpf_offered && !audio_webrtc_offered) {
		ast_log(LOG_NOTICE, "Sofia: SDP rejected — SAVPF/WebRTC audio offered but peer '%s' is not webrtc=yes\n",
			pvt->peer ? pvt->peer->name : "<unknown>");
		goto sdp_reject;
	}
	/* Audit HIGH: video-over-WebRTC is deferred (A4 is audio-only); reject ANY DTLS video offer rather
	 * than silently answer it RTP/AVP (the audio HIGH1 downgrade defect, mirrored for video). */
	if (video_savpf_offered) {
		ast_log(LOG_NOTICE, "Sofia: SDP rejected — DTLS/WebRTC video offered but A4 is audio-only (peer '%s')\n",
			pvt->peer ? pvt->peer->name : "<unknown>");
		goto sdp_reject;
	}
	/* A5 symmetric anti-downgrade (audit MEDIUM): on a WebRTC OFFERER leg (we sent a DTLS-SRTP offer) the
	 * remote MUST answer with a WebRTC body. A plain RTP/AVP answer (a downgrading B2BUA / non-WebRTC UAS)
	 * leaves audio_webrtc_offered=0 → the A5 answer-apply never arms DTLS/ICE and the call would connect
	 * SILENT. Reject so the 200-OK handler tears it down rather than bridge dead media (mirrors the HIGH1
	 * answerer-side gate). webrtc_answer_applied guards an in-dialog re-INVITE on an established leg. */
	if (pvt->is_webrtc && pvt->webrtc_offerer && !pvt->webrtc_answer_applied && !audio_webrtc_offered) {
		ast_log(LOG_NOTICE, "Sofia: SDP rejected — we offered WebRTC to peer '%s' but the answer is not DTLS-SRTP\n",
			pvt->peer ? pvt->peer->name : "<unknown>");
		goto sdp_reject;
	}
	if (pvt->peer && pvt->peer->encryption) {
		/* M3: accepted DTLS-SRTP (SAVPF + staged fingerprint/setup/ICE) is secure — do NOT
		 * reject a WebRTC leg for lacking a=crypto. SDES a=crypto still satisfies the gate. */
		if (audio_offered && !audio_secure_offered && !audio_webrtc_offered) {
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

	/* A4 WebRTC commit (M5/M6/M7): apply the staged DTLS/ICE exactly ONCE for a FRESH WebRTC leg, in
	 * RFC-5763/5764 order, and set pvt->is_webrtc only on full success (rollback-safe — a reject here
	 * goes to sdp_reject having touched no committed codec map). A re-INVITE on an already-established
	 * WebRTC leg (is_webrtc set) skips re-provisioning so set_configuration never rebuilds the cert /
	 * restarts DTLS mid-call (ICE restart deferred, MED6). No a=crypto on a WebRTC offer, so the SDES
	 * crypto-commit above was a no-op for this leg. */
	/* A5 OFFERER ANSWER-APPLY: when WE offered WebRTC (webrtc_offerer set at
	 * sofia_call), is_webrtc is already 1, so the A4 answerer commit below is
	 * skipped. The browser's ANSWER (same UDP/TLS/ m= proto → audio_webrtc_offered
	 * is set on this body too) carries the remote fingerprint/setup/ICE creds we
	 * must now apply — but set_configuration already ran on the offer side and MUST
	 * NOT be re-run (would rebuild our cert / restart DTLS). Apply the remote params
	 * once, in RFC-5763/5764 order, then start ICE (remote creds are present now) and
	 * activate. Re-INVITE / duplicate 18x+200 are guarded by webrtc_answer_applied. */
	if (audio_webrtc_offered && pvt->is_webrtc && pvt->webrtc_offerer && !pvt->webrtc_answer_applied) {
		struct ast_rtp_engine_dtls *dtls = ast_rtp_instance_get_dtls(pvt->rtp);
		struct ast_rtp_engine_ice *ice = ast_rtp_instance_get_ice(pvt->rtp);
		int i;
		if (!dtls || !ice) {
			ast_log(LOG_WARNING, "Sofia: WebRTC answer apply failed — no dtls/ice engine for peer '%s'\n",
				pvt->peer ? pvt->peer->name : "<unknown>");
			goto sdp_reject;
		}
		/* The ANSWER must carry fingerprint + setup + BOTH ICE creds; a missing-attr
		 * answer cannot establish DTLS-SRTP — reject (the nua_r_invite 200 handler then
		 * tears the call down on sdp_rc<0). */
		if (!wrtc.have_fingerprint || !wrtc.have_setup || !wrtc.have_ice_ufrag
				|| !wrtc.have_ice_pwd || !wrtc.have_rtcp_mux) {
			/* Codex BLOCKER: require a=rtcp-mux in the ANSWER too. Our engine is mux-ONLY (single
			 * socket); RFC 5761 §5.1.1 — an answerer that omits a=rtcp-mux means the offerer MUST NOT
			 * multiplex (separate RTCP), which we cannot do → fail closed. Browsers always mux. */
			ast_log(LOG_NOTICE, "Sofia: SDP rejected — WebRTC ANSWER missing required attrs (fp=%d setup=%d ufrag=%d pwd=%d mux=%d)\n",
				wrtc.have_fingerprint, wrtc.have_setup, wrtc.have_ice_ufrag, wrtc.have_ice_pwd, wrtc.have_rtcp_mux);
			goto sdp_reject;
		}
		/* set_configuration was done on the offer side — do NOT re-run it. Apply the
		 * remote params: fingerprint (trust), setup (maps remote→our concrete DTLS
		 * role: browser answers active → we PASSIVE/server, RFC 5763 §5), remote ICE
		 * ufrag/pwd, then host candidates. */
		dtls->set_fingerprint(pvt->rtp, wrtc.fp_hash, wrtc.fp_value);
		dtls->set_setup(pvt->rtp, wrtc.remote_setup);
		ice->set_authentication(pvt->rtp, wrtc.ice_ufrag, wrtc.ice_pwd);
		for (i = 0; i < wrtc.cand_count; i++) {
			struct ast_rtp_engine_ice_candidate cand = { 0 };
			cand.foundation = "0";
			cand.id = AST_RTP_ICE_COMPONENT_RTP;
			cand.transport = "udp";
			cand.priority = 0;
			cand.address = wrtc.cand[i];
			cand.type = AST_RTP_ICE_CANDIDATE_TYPE_HOST;
			ice->add_remote_candidate(pvt->rtp, &cand);
		}
		if (wrtc.remote_ice_lite && ice->ice_lite) {
			ice->ice_lite(pvt->rtp);
		}
		ice->set_role(pvt->rtp, AST_RTP_ICE_ROLE_CONTROLLED);	/* permanent lite role */
		ice->start(pvt->rtp);	/* remote creds are set now — safe to arm the STUN responder */
		pvt->webrtc_answer_applied = 1;
		/* (5) activate AFTER the remote params are applied; the ICE/DTLS state machine
		 * is armed and the DTLS handshake self-fires from the USE-CANDIDATE STUN path.
		 * A duplicate activate elsewhere is a no-op (A4 OQ6). */
		if (pvt->rtp) {
			ast_rtp_instance_activate(pvt->rtp);
		}
	}

	if (audio_webrtc_offered && !pvt->is_webrtc) {
		struct ast_rtp_engine_dtls *dtls = ast_rtp_instance_get_dtls(pvt->rtp);
		struct ast_rtp_engine_ice *ice = ast_rtp_instance_get_ice(pvt->rtp);
		struct ast_rtp_dtls_cfg dtls_cfg = { 0 };
		int i;

		/* OQ3 fail-closed (Codex): the dtls/ice vtables are ALWAYS non-NULL (engine-level, not
		 * per-instance), so the real provisioning check is sofia_sched. When it is NULL, sofia_rtp_init
		 * created pvt->rtp with a NULL sched and the DTLS retransmit timer
		 * (ast_sched_add_variable(rtp->sched,...)) would deref NULL → reject the WebRTC leg rather than
		 * crash. A webrtc=yes peer offering plain RTP is unaffected — it never reaches this commit. */
		if (!dtls || !ice || !sofia_sched) {
			ast_log(LOG_WARNING, "Sofia: SDP rejected — peer '%s' offered WebRTC but no scheduler to run DTLS timers (sofia_sched=%p dtls=%p ice=%p)\n",
				pvt->peer ? pvt->peer->name : "<unknown>", (void *)sofia_sched, (void *)dtls, (void *)ice);
			goto sdp_reject;
		}
		/* HIGH2/HIGH3: require fingerprint + setup + BOTH ICE creds + rtcp-mux (candidate optional —
		 * ICE-lite learns the peer from the authenticated STUN check, RFC 8445 §2.5). */
		if (!wrtc.have_fingerprint || !wrtc.have_setup || !wrtc.have_ice_ufrag
				|| !wrtc.have_ice_pwd || !wrtc.have_rtcp_mux) {
			ast_log(LOG_NOTICE, "Sofia: SDP rejected — WebRTC offer missing required attrs (fp=%d setup=%d ufrag=%d pwd=%d mux=%d)\n",
				wrtc.have_fingerprint, wrtc.have_setup, wrtc.have_ice_ufrag,
				wrtc.have_ice_pwd, wrtc.have_rtcp_mux);
			goto sdp_reject;
		}

		dtls_cfg.enabled = 1;
		dtls_cfg.default_setup = AST_RTP_DTLS_SETUP_PASSIVE;	/* answerer-only: answer a=setup:passive so the BROWSER is the DTLS client and initiates (RFC 5763 §5 SHOULD; gabpbx-active left the browser silent as the DTLS server → no audio). set_setup(remote actpass) below also maps to PASSIVE. */
		dtls_cfg.suite = AST_AES_CM_128_HMAC_SHA1_80;
		dtls_cfg.hash = AST_RTP_DTLS_HASH_SHA256;
		dtls_cfg.verify = AST_RTP_DTLS_VERIFY_FINGERPRINT;
		dtls_cfg.ephemeral_cert = 1;
		if (dtls->set_configuration(pvt->rtp, &dtls_cfg)) {
			ast_log(LOG_WARNING, "Sofia: SDP rejected — DTLS set_configuration failed for peer '%s'\n",
				pvt->peer ? pvt->peer->name : "<unknown>");
			goto sdp_reject;
		}
		dtls->set_fingerprint(pvt->rtp, wrtc.fp_hash, wrtc.fp_value);
		dtls->set_setup(pvt->rtp, wrtc.remote_setup);	/* verbatim (OQ8: A2 maps remote→our role) */
		ice->set_authentication(pvt->rtp, wrtc.ice_ufrag, wrtc.ice_pwd);
		for (i = 0; i < wrtc.cand_count; i++) {
			struct ast_rtp_engine_ice_candidate cand = { 0 };
			cand.foundation = "0";
			cand.id = AST_RTP_ICE_COMPONENT_RTP;
			cand.transport = "udp";
			cand.priority = 0;
			cand.address = wrtc.cand[i];
			cand.type = AST_RTP_ICE_CANDIDATE_TYPE_HOST;
			ice->add_remote_candidate(pvt->rtp, &cand);
		}
		if (wrtc.remote_ice_lite && ice->ice_lite) {
			ice->ice_lite(pvt->rtp);	/* M6: only when the offer carried a=ice-lite */
		}
		ice->set_role(pvt->rtp, AST_RTP_ICE_ROLE_CONTROLLED);	/* M6: our permanent local role */
		ice->start(pvt->rtp);
		/* A4 interop: persist the offered MID + BUNDLE intent + a stable per-pvt
		 * tls-id onto pvt so sofia_generate_sdp can echo a=mid / a=group:BUNDLE /
		 * a=tls-id in the answer. Mid defaults to "0" when the offer omitted it
		 * (RFC 8829 §5.3.1: emit only when present in the offer; "0" is the JSEP
		 * default first-mid). tls-id: 16 random bytes hex (RFC 8842 §5.2, stable
		 * per DTLS association — generated once here, never on a re-INVITE). */
		ast_copy_string(pvt->webrtc_mid, wrtc.have_mid ? wrtc.mid : "0",
			sizeof(pvt->webrtc_mid));
		pvt->webrtc_bundle = wrtc.have_bundle;
		if (ast_strlen_zero(pvt->webrtc_tls_id)) {
			unsigned char tb[16];
			int ti;
			for (ti = 0; ti < (int)sizeof(tb); ti++) {
				tb[ti] = ast_random() & 0xff;
			}
			for (ti = 0; ti < (int)sizeof(tb); ti++) {
				snprintf(pvt->webrtc_tls_id + ti * 2,
					sizeof(pvt->webrtc_tls_id) - ti * 2, "%02x", tb[ti]);
			}
		}
		pvt->is_webrtc = 1;	/* M7: only here, after full success */
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

