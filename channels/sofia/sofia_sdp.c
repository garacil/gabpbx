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
#include "include/sofia_datachannel.h"	/* Phase 3: sofia_dc_attach for the accepted m=application (RFC 8841) */

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

/* RFC 8843: is \a mid a whitespace-delimited token in an "a=group:BUNDLE <mid> <mid> ..." line?
 * \a group is the captured bundle_group text (starting with the literal "BUNDLE"). Used to accept a
 * bundled m-line by its mid being in the session BUNDLE group (video/DataChannel share one ICE/DTLS transport). */
static int sofia_sdp_mid_in_bundle(const char *group, const char *mid)
{
	char grp[256];
	char *tok, *save = NULL;

	if (ast_strlen_zero(group) || ast_strlen_zero(mid) || strncasecmp(group, "BUNDLE", 6)) {
		return 0;
	}
	ast_copy_string(grp, group, sizeof(grp));
	tok = strtok_r(grp, " \t", &save);	/* the literal "BUNDLE" */
	while ((tok = strtok_r(NULL, " \t", &save))) {
		if (!strcmp(tok, mid)) {
			return 1;
		}
	}
	return 0;
}

/*!
 * \brief Append the accepted/offered WebRTC m=video section to \a buf (v1b/v1c, RFC 8843 §7).
 *
 * The m=video runs on pvt->vrtp's OWN non-BUNDLE transport: its own port + ICE-lite host candidate,
 * fingerprint/setup, a=rtcp-mux, VP8/H264 rtpmap, a=mid + a=tls-id. NOT added to a=group:BUNDLE.
 * Factored out of sofia_generate_sdp so the WebRTC answer can place this section at the video's OFFER
 * slot (RFC 3264 §6 / RFC 8829 §5.3 m-line order). Byte-identical to the former inline STEP 6 block.
 * \a overflow is OR'd with any truncation. The caller guarantees pvt->vrtp + the accept/offer gate.
 */
static void sofia_sdp_emit_webrtc_video(struct sofia_pvt *pvt, char *buf, size_t len,
	const char *host, const char *sdp_family, char *tmp_buf, size_t tmp_buf_size, const char *dir_attr, int *overflow)
{
	struct ast_rtp_engine_dtls *vdtls = ast_rtp_instance_get_dtls(pvt->vrtp);
	struct ast_rtp_engine_ice *vice = ast_rtp_instance_get_ice(pvt->vrtp);
	const char *vfp = vdtls ? vdtls->get_fingerprint(pvt->vrtp) : NULL;
	const char *vufrag = vice ? vice->get_ufrag(pvt->vrtp) : NULL;
	const char *vpwd = vice ? vice->get_password(pvt->vrtp) : NULL;
	enum ast_rtp_dtls_setup vos = vdtls ? vdtls->get_setup(pvt->vrtp) : AST_RTP_DTLS_SETUP_PASSIVE;
	const char *vss = (vos == AST_RTP_DTLS_SETUP_PASSIVE) ? "passive"
		: (vos == AST_RTP_DTLS_SETUP_ACTPASS) ? "actpass" : "active";
	struct ast_sockaddr vla;
	int vport = 0;
	char vpayload_buf[128] = "";
	char vmap_buf[1536] = "";
	int vfirst = 1;
	format_t vf;
	int vblen;

	ast_rtp_instance_get_local_address(pvt->vrtp, &vla);
	vport = ast_sockaddr_port(&vla);
	/* VP8/H264 payload list + rtpmap from the negotiated video capability (90 kHz video clock). The PT
	 * comes from vrtp's codec map: for the ANSWERER it is the BROWSER's offered PT (staged at commit,
	 * RFC 3264 keeps it); for the OFFERER the map is empty so ast_rtp_codecs_payload_code falls back to
	 * the static table (VP8=96, H264=99, rtp_engine.c:187/191). */
	for (vf = 1; vf; vf <<= 1) {
		int vpt;
		const char *venc;
		if (!(vf & pvt->capability) || !(vf & (AST_FORMAT_VP8 | AST_FORMAT_H264))) {
			continue;
		}
		vpt = ast_rtp_codecs_payload_code(ast_rtp_instance_get_codecs(pvt->vrtp), 1, vf);
		if (vpt < 0) {
			continue;
		}
		venc = ast_rtp_lookup_mime_subtype2(1, vf, 0);
		if (ast_strlen_zero(venc)) {
			continue;
		}
		if (!vfirst) {
			*overflow |= sofia_sdp_cat(vpayload_buf, sizeof(vpayload_buf), " ");
		}
		snprintf(tmp_buf, tmp_buf_size, "%d", vpt);
		*overflow |= sofia_sdp_cat(vpayload_buf, sizeof(vpayload_buf), tmp_buf);
		vfirst = 0;
		if (snprintf(tmp_buf, tmp_buf_size, "a=rtpmap:%d %s/90000\r\n", vpt, venc) >= (int)tmp_buf_size) {
			*overflow = 1;
		} else {
			*overflow |= sofia_sdp_cat(vmap_buf, sizeof(vmap_buf), tmp_buf);
		}
		/* RFC 8829 §5.3.1: advertise the keyframe feedback we honor (PSFB PLI RFC 4585 §6.3.1 +
		 * FIR RFC 5104 §4.3.1 inbound -> AST_CONTROL_VIDUPDATE) and send (PLI outbound). Browsers
		 * always offer both on video, so unconditional emission on WebRTC video sections is
		 * correct (FreeSWITCH parity). WebRTC-only: the plain non-WebRTC m=video emitter stays
		 * byte-identical (legacy endpoints use SIP INFO, not RTCP feedback). */
		if (snprintf(tmp_buf, tmp_buf_size, "a=rtcp-fb:%d nack pli\r\na=rtcp-fb:%d ccm fir\r\n", vpt, vpt) >= (int)tmp_buf_size) {
			*overflow = 1;
		} else {
			*overflow |= sofia_sdp_cat(vmap_buf, sizeof(vmap_buf), tmp_buf);
		}
	}
	*overflow |= sofia_sdp_cat(vmap_buf, sizeof(vmap_buf), dir_attr);	/* RFC 3264 §6.1 direction (mirror on answer) */
	*overflow |= sofia_sdp_cat(vmap_buf, sizeof(vmap_buf), "a=rtcp-mux\r\n");
	if (snprintf(tmp_buf, tmp_buf_size, "a=setup:%s\r\n", vss) >= (int)tmp_buf_size) {
		*overflow = 1;
	} else {
		*overflow |= sofia_sdp_cat(vmap_buf, sizeof(vmap_buf), tmp_buf);
	}
	if (vfp) {
		if (snprintf(tmp_buf, tmp_buf_size, "a=fingerprint:sha-256 %s\r\n", vfp) >= (int)tmp_buf_size) {
			*overflow = 1;
		} else {
			*overflow |= sofia_sdp_cat(vmap_buf, sizeof(vmap_buf), tmp_buf);
		}
	}
	*overflow |= sofia_sdp_cat(vmap_buf, sizeof(vmap_buf), "a=ice-lite\r\n");
	if (vufrag) {
		if (snprintf(tmp_buf, tmp_buf_size, "a=ice-ufrag:%s\r\n", vufrag) >= (int)tmp_buf_size) {
			*overflow = 1;
		} else {
			*overflow |= sofia_sdp_cat(vmap_buf, sizeof(vmap_buf), tmp_buf);
		}
	}
	if (vpwd) {
		if (snprintf(tmp_buf, tmp_buf_size, "a=ice-pwd:%s\r\n", vpwd) >= (int)tmp_buf_size) {
			*overflow = 1;
		} else {
			*overflow |= sofia_sdp_cat(vmap_buf, sizeof(vmap_buf), tmp_buf);
		}
	}
	if (snprintf(tmp_buf, tmp_buf_size, "a=candidate:0 1 UDP 2130706431 %s %d typ host\r\n", host, vport) >= (int)tmp_buf_size) {
		*overflow = 1;
	} else {
		*overflow |= sofia_sdp_cat(vmap_buf, sizeof(vmap_buf), tmp_buf);
	}
	*overflow |= sofia_sdp_cat(vmap_buf, sizeof(vmap_buf), "a=end-of-candidates\r\n");
	if (snprintf(tmp_buf, tmp_buf_size, "a=mid:%s\r\n",
		!ast_strlen_zero(pvt->webrtc_video_mid) ? pvt->webrtc_video_mid : "1") >= (int)tmp_buf_size) {
		*overflow = 1;
	} else {
		*overflow |= sofia_sdp_cat(vmap_buf, sizeof(vmap_buf), tmp_buf);
	}
	if (!ast_strlen_zero(pvt->webrtc_video_tls_id)) {
		if (snprintf(tmp_buf, tmp_buf_size, "a=tls-id:%s\r\n", pvt->webrtc_video_tls_id) >= (int)tmp_buf_size) {
			*overflow = 1;
		} else {
			*overflow |= sofia_sdp_cat(vmap_buf, sizeof(vmap_buf), tmp_buf);
		}
	}
	vblen = strlen(buf);
	if (snprintf(buf + vblen, len - vblen,
			"m=video %d UDP/TLS/RTP/SAVPF %s\r\n"
			"c=IN %s %s\r\n"
			"%s",
			vport, vpayload_buf, sdp_family, host, vmap_buf) >= (int)(len - vblen)) {
		*overflow = 1;
	}
}

/* WebRTC source/track identity for our a=ssrc / a=msid lines. Generated ONCE per dialog and SHARED by our
 * audio + video streams so the browser groups them into one MediaStream (RFC 8830). */
static void sofia_webrtc_ensure_ids(struct sofia_pvt *pvt)
{
	if (ast_strlen_zero(pvt->webrtc_cname)) {
		snprintf(pvt->webrtc_cname, sizeof(pvt->webrtc_cname), "%08x%08x",
			(unsigned int)ast_random(), (unsigned int)ast_random());
	}
	if (ast_strlen_zero(pvt->webrtc_msid)) {
		snprintf(pvt->webrtc_msid, sizeof(pvt->webrtc_msid), "%08x%08x%08x%08x",
			(unsigned int)ast_random(), (unsigned int)ast_random(),
			(unsigned int)ast_random(), (unsigned int)ast_random());
	}
}

/* Emit the a=ssrc + a=msid source/track lines for ONE WebRTC stream so the browser can associate our RTP
 * with its m= line by SSRC (RFC 8827 §5.2.1 / RFC 8830 / RFC 8843 §9.2). Without this, strict browsers
 * (WebKit/Safari) receive our RTP but never render it — the one-way-audio / no-video root cause. Mirrors
 * Asterisk pjsip (a=ssrc cname + a=msid) PLUS the FreeSWITCH legacy mslabel/label set for max interop.
 * `track` is "a0" (audio) / "v0" (video). No-op if ssrc==0 (callers must ensure a real SSRC). */
static void sofia_sdp_emit_webrtc_ssrc(char *buf, size_t buflen, unsigned int ssrc,
	const char *cname, const char *msid, const char *track, int *overflow)
{
	char line[160];

	if (!ssrc) {
		return;
	}
	snprintf(line, sizeof(line), "a=msid:%s %s\r\n", msid, track);
	*overflow |= sofia_sdp_cat(buf, buflen, line);
	snprintf(line, sizeof(line), "a=ssrc:%u cname:%s\r\n", ssrc, cname);
	*overflow |= sofia_sdp_cat(buf, buflen, line);
	snprintf(line, sizeof(line), "a=ssrc:%u msid:%s %s\r\n", ssrc, msid, track);
	*overflow |= sofia_sdp_cat(buf, buflen, line);
	snprintf(line, sizeof(line), "a=ssrc:%u mslabel:%s\r\n", ssrc, msid);
	*overflow |= sofia_sdp_cat(buf, buflen, line);
	snprintf(line, sizeof(line), "a=ssrc:%u label:%s%s\r\n", ssrc, msid, track);
	*overflow |= sofia_sdp_cat(buf, buflen, line);
}

/*!
 * \brief Append the BUNDLE'd WebRTC m=video section (RFC 8843 max-bundle) to \a buf.
 *
 * The video shares the AUDIO ICE/DTLS transport, so this section carries NO own ice/fingerprint/setup/
 * tls-id/candidate (all inherited from the audio bundle-tag, RFC 8843 §7.1.3/§7.3.3) — only m=video +
 * payloads + a=rtpmap + a=sendrecv + a=rtcp-mux + a=mid + a=ssrc + the MID extmap. PTs come from pvt->rtp's
 * codec map (the video PTs were merged there at parse/provision; disjoint from audio). BOTH offerer and
 * answerer emit the shared AUDIO port with NO a=bundle-only — the same-port max-bundle form browsers
 * reliably create an inbound video receiver for. The video mid joins a=group:BUNDLE in the caller. No vrtp.
 */
static void sofia_sdp_emit_bundled_video(struct sofia_pvt *pvt, char *buf, size_t len,
	const char *host, const char *sdp_family, char *tmp_buf, size_t tmp_buf_size, int audio_port, const char *dir_attr, int *overflow)
{
	char bvpayload_buf[128] = "";
	char bvmap_buf[1536] = "";
	int bvfirst = 1;
	int bvblen;
	int bvport = audio_port;	/* shared audio port; NO a=bundle-only (port-0 stopped browsers creating a video receiver) */
	format_t bvf;

	for (bvf = 1; bvf; bvf <<= 1) {
		int bvpt;
		const char *bvenc;
		if (!(bvf & pvt->capability) || !(bvf & (AST_FORMAT_VP8 | AST_FORMAT_H264))) {
			continue;
		}
		bvpt = ast_rtp_codecs_payload_code(ast_rtp_instance_get_codecs(pvt->rtp), 1, bvf);	/* PT from the SHARED audio instance */
		if (bvpt < 0) {
			continue;
		}
		bvenc = ast_rtp_lookup_mime_subtype2(1, bvf, 0);
		if (ast_strlen_zero(bvenc)) {
			continue;
		}
		if (!bvfirst) {
			*overflow |= sofia_sdp_cat(bvpayload_buf, sizeof(bvpayload_buf), " ");
		}
		snprintf(tmp_buf, tmp_buf_size, "%d", bvpt);
		*overflow |= sofia_sdp_cat(bvpayload_buf, sizeof(bvpayload_buf), tmp_buf);
		bvfirst = 0;
		if (snprintf(tmp_buf, tmp_buf_size, "a=rtpmap:%d %s/90000\r\n", bvpt, bvenc) >= (int)tmp_buf_size) {
			*overflow = 1;
		} else {
			*overflow |= sofia_sdp_cat(bvmap_buf, sizeof(bvmap_buf), tmp_buf);
		}
		/* RFC 8829 §5.3.1: keyframe feedback we honor (PLI/FIR inbound -> AST_CONTROL_VIDUPDATE)
		 * and send (PLI outbound) for the bundled video PTs — see sofia_sdp_emit_webrtc_video.
		 * WebRTC sections only; the plain m=video emitter is untouched. */
		if (snprintf(tmp_buf, tmp_buf_size, "a=rtcp-fb:%d nack pli\r\na=rtcp-fb:%d ccm fir\r\n", bvpt, bvpt) >= (int)tmp_buf_size) {
			*overflow = 1;
		} else {
			*overflow |= sofia_sdp_cat(bvmap_buf, sizeof(bvmap_buf), tmp_buf);
		}
	}
	*overflow |= sofia_sdp_cat(bvmap_buf, sizeof(bvmap_buf), dir_attr);	/* RFC 3264 §6.1 direction (mirror on answer) */
	*overflow |= sofia_sdp_cat(bvmap_buf, sizeof(bvmap_buf), "a=rtcp-mux\r\n");	/* RTP+RTCP mux on the shared transport */
	if (snprintf(tmp_buf, tmp_buf_size, "a=mid:%s\r\n",
		!ast_strlen_zero(pvt->webrtc_video_mid) ? pvt->webrtc_video_mid : "1") >= (int)tmp_buf_size) {
		*overflow = 1;
	} else {
		*overflow |= sofia_sdp_cat(bvmap_buf, sizeof(bvmap_buf), tmp_buf);
	}
	/* RFC 8827/8830/8843 §9.2: advertise our video source+track so the browser associates our bundled video
	 * RTP (v_ssrc) with THIS m= line and renders it — without this the browser drops it (black video). */
	sofia_webrtc_ensure_ids(pvt);
	{
		struct ast_rtp_instance_stats _sstats = { 0 };
		unsigned int _vssrc = 0;
		if (pvt->rtp && !ast_rtp_instance_get_stats(pvt->rtp, &_sstats, AST_RTP_INSTANCE_STAT_LOCAL_VIDEO_SSRC)) {
			_vssrc = _sstats.local_video_ssrc;
		}
		sofia_sdp_emit_webrtc_ssrc(bvmap_buf, sizeof(bvmap_buf), _vssrc,
			pvt->webrtc_cname, pvt->webrtc_msid, "v0", overflow);
	}
	{	/* RFC 8843 §9 / RFC 8285: the MID hdrext extmap in the bundled video m= line (echo negotiated id / 4) */
		char _em[96];
		snprintf(_em, sizeof(_em), "a=extmap:%d urn:ietf:params:rtp-hdrext:sdes:mid\r\n",
			pvt->webrtc_mid_ext_id > 0 ? pvt->webrtc_mid_ext_id : 4);
		*overflow |= sofia_sdp_cat(bvmap_buf, sizeof(bvmap_buf), _em);
	}
	bvblen = strlen(buf);
	if (snprintf(buf + bvblen, len - bvblen,
			"m=video %d UDP/TLS/RTP/SAVPF %s\r\n"
			"c=IN %s %s\r\n"
			"%s",
			bvport, bvpayload_buf, sdp_family, host, bvmap_buf) >= (int)(len - bvblen)) {
		*overflow = 1;
	}
}

/* RFC 3264 §6.1 answer-direction mirror. Returns the "a=<dir>\r\n" attribute to emit for a
 * media section. When building an OFFER (is_answer=0) we always send sendrecv (chan_sofia has no
 * SIP local-hold-offer path). When building an ANSWER (is_answer=1) we mirror the offered mode:
 * sendonly->recvonly (remote hold; recvonly NOT inactive, so we do not return held SDP and MOH
 * to the far leg still works), recvonly->sendonly, inactive->inactive, sendrecv/unset->sendrecv.
 * offered_mode is a sofia sdp_mode_t; -1 sentinel ("no offer staged") falls through to sendrecv. */
static const char *sofia_answer_dir_attr(int is_answer, int offered_mode)
{
	if (!is_answer) {
		return "a=sendrecv\r\n";
	}
	switch (offered_mode) {
	case sdp_sendonly: return "a=recvonly\r\n";
	case sdp_recvonly: return "a=sendonly\r\n";
	case sdp_inactive: return "a=inactive\r\n";
	default:           return "a=sendrecv\r\n";	/* sdp_sendrecv or -1 unset */
	}
}

char *sofia_generate_sdp(struct sofia_pvt *pvt, char *buf, size_t len, int is_answer)
{
	const char *audio_dir = sofia_answer_dir_attr(is_answer, pvt->offered_audio_mode);
	const char *video_dir = sofia_answer_dir_attr(is_answer, pvt->offered_video_mode);
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

	/* telephone-event (g1): only advertise RFC 2833/4733 when the effective DTMF mode uses it
	 * (rfc2833 / unresolved-auto / any WebRTC leg). dtmfmode=info/inband/shortinfo peers get NO
	 * telephone-event in the offer or answer, so the far end honours the configured mode.
	 * prefer PT 101, but if a negotiated codec already took it pick the first free dynamic
	 * PT (96..127) to avoid a duplicate payload type. */
	if (sofia_dtmf_wants_rfc2833(pvt)) {
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
		/* a=ssrc / a=msid — the browser associates our inbound RTP to its receive track BY SSRC (RFC
		 * 8827 §5.2.1 / RFC 8830 / RFC 8843 §9.2). Without it, strict browsers (Safari/WebKit) receive
		 * our audio but never render it = the one-way-audio root cause. Emitted for OFFER and ANSWER. */
		sofia_webrtc_ensure_ids(pvt);
		{
			struct ast_rtp_instance_stats _sstats = { 0 };
			unsigned int _assrc = 0;
			if (pvt->rtp && !ast_rtp_instance_get_stats(pvt->rtp, &_sstats, AST_RTP_INSTANCE_STAT_LOCAL_SSRC)) {
				_assrc = _sstats.local_ssrc;
			}
			sofia_sdp_emit_webrtc_ssrc(rtpmap_buf, sizeof(rtpmap_buf), _assrc,
				pvt->webrtc_cname, pvt->webrtc_msid, "a0", &overflow);
		}
		if (pvt->webrtc_video_bundled) {	/* RFC 8843 §9 / RFC 8285: the audio m= line also declares the MID hdrext (echo negotiated id / 4) */
			char _em[96];
			snprintf(_em, sizeof(_em), "a=extmap:%d urn:ietf:params:rtp-hdrext:sdes:mid\r\n",
				pvt->webrtc_mid_ext_id > 0 ? pvt->webrtc_mid_ext_id : 4);
			overflow |= sofia_sdp_cat(rtpmap_buf, sizeof(rtpmap_buf), _em);
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
	char group_buf[160] = "";
	if (pvt->is_webrtc && pvt->webrtc_bundle) {
		/* Phase 3: when an m=application was ACCEPTED it shares THIS BUNDLE transport, so its mid joins
		 * the group → "BUNDLE <audio_mid> <dc_mid>" (RFC 8843). Otherwise the group stays audio-only
		 * (byte-identical to pre-Phase-3). The accepted DC mid is dc_mid (always non-empty when accepted). */
		const char *amid = !ast_strlen_zero(pvt->webrtc_mid) ? pvt->webrtc_mid : "0";
		const char *vmid = !ast_strlen_zero(pvt->webrtc_video_mid) ? pvt->webrtc_video_mid : "1";
		/* BUNDLE token list in m-line ORDER: audio [video] [DataChannel] (RFC 8843). The video mid joins ONLY
		 * when its m=video shares this transport (webrtc_video_bundled + accepted-or-offered). dc_accepted = we
		 * accepted an INBOUND DC; dc_offerer = we ORIGINATED it — either way its mid joins the group. */
		int video_in_grp = pvt->webrtc_video_bundled
			&& (pvt->webrtc_video_accepted
				|| (!is_answer && pvt->webrtc_video_offerer && !pvt->webrtc_video_answer_applied));
		int dc_in_grp = (is_answer ? pvt->dc_accepted : pvt->dc_offerer) && !ast_strlen_zero(pvt->dc_mid);
		char grp[200] = "";	/* up to 3 mids (webrtc_video_mid/dc_mid are 64B each); sized for the worst case */
		int gw;
		/* Bounds-checked incremental append (sofia_sdp_cat never overruns): "audio [video] [dc]". */
		sofia_sdp_cat(grp, sizeof(grp), amid);
		if (video_in_grp) {
			sofia_sdp_cat(grp, sizeof(grp), " ");
			sofia_sdp_cat(grp, sizeof(grp), vmid);
		}
		if (dc_in_grp) {
			sofia_sdp_cat(grp, sizeof(grp), " ");
			sofia_sdp_cat(grp, sizeof(grp), pvt->dc_mid);
		}
		gw = snprintf(group_buf, sizeof(group_buf), "a=group:BUNDLE %s\r\n", grp);
		if (gw >= (int)sizeof(group_buf)) {
			overflow = 1;
			group_buf[0] = '\0';
		} else if (!ast_strlen_zero(pvt->webrtc_msid)) {
			/* Session-level WMS (WebRTC MediaStream) semantic naming our a=msid/a=ssrc stream (RFC 8830);
			 * FreeSWITCH emits it so the browser expects our announced tracks. */
			overflow |= sofia_sdp_cat(group_buf, sizeof(group_buf), "a=msid-semantic: WMS ");
			overflow |= sofia_sdp_cat(group_buf, sizeof(group_buf), pvt->webrtc_msid);
			overflow |= sofia_sdp_cat(group_buf, sizeof(group_buf), "\r\n");
		}
	}
	/* The m=audio SECTION (m= line + its a= block + a=sendrecv), built into its own buffer so the WebRTC
	 * answer can place it at the audio's OFFER slot when the offer order is non-canonical (RFC 3264 §6 /
	 * RFC 8829 §5.3 — the answer mirrors the offer's m-line ORDER). For a non-WebRTC leg (and the common
	 * audio-first WebRTC offer) it lands first, byte-identical to before. */
	char audio_m_buf[sizeof(rtpmap_buf) + sizeof(payload_buf) + 128] = "";	/* holds the m=audio line + full payload list + rtpmap block + a=sendrecv */
	if (snprintf(audio_m_buf, sizeof(audio_m_buf),
		"m=audio %d %s %s\r\n"
		"%s"
		"%s",	/* RFC 3264 §6.1 direction: sendrecv on offer, mirror of the offered mode on answer */
		port,
		pvt->is_webrtc ? "UDP/TLS/RTP/SAVPF"
			: ((pvt->srtp && pvt->srtp->crypto) ? "RTP/SAVP" : "RTP/AVP"),
		payload_buf, rtpmap_buf, audio_dir) >= (int)sizeof(audio_m_buf)) {	/* truncated audio SDP */
		overflow = 1;
	}

	if (snprintf(buf, len,
		"v=0\r\n"
		"o=- %lu %lu IN %s %s\r\n"
		"s=GABpbx\r\n"
		"c=IN %s %s\r\n"
		"t=0 0\r\n"
		"%s",
		pvt->sess_id, pvt->sess_version,
		sdp_family, host, sdp_family, host,
		group_buf) >= (int)len) {	/* truncated session-level SDP */
		overflow = 1;
	}

	/* WebRTC ANSWER m-line ORDER (RFC 3264 §6 / RFC 8829 §5.3): when we are ANSWERING a remote offer
	 * (is_answer — the CURRENT transaction role; the permanent webrtc_offerer only records who made the
	 * dialog's INITIAL offer and must not gate this: a mid-call re-INVITE swaps the roles), emit ONE answer m-section per offer m-line, in the OFFER's ORDER, by absolute index. The
	 * accept/reject decisions are UNCHANGED — only the ORDER is fixed so a strict UA (e.g. after a
	 * renegotiation that reordered to audio,application,video) does not abort setRemoteDescription on an
	 * m-line-order mismatch. For each offer slot 0..max:
	 *   - audio slot (webrtc_audio_offer_idx)               → the real m=audio section (audio_m_buf)
	 *   - the accepted video slot (webrtc_accepted_video_idx, if still accepted) → real m=video
	 *   - the accepted DataChannel slot (dc_accepted mid match)                  → real m=application
	 *   - every other offered slot                          → its port-0 reflection IN PLACE
	 * The OFFER-build direction (!is_answer) has NO remote offer to mirror — it uses the canonical
	 * audio,[video],[application] layout below. The non-WebRTC leg also skips this loop. */
	if (pvt->is_webrtc && is_answer) {
		int max_idx = pvt->webrtc_audio_offer_idx;
		int slot;
		int ri;
		for (ri = 0; ri < pvt->webrtc_reject_m_count; ri++) {
			if (pvt->webrtc_reject_m[ri].offer_idx > max_idx) {
				max_idx = pvt->webrtc_reject_m[ri].offer_idx;
			}
		}
		if (pvt->webrtc_reject_overflow) {
			overflow = 1;	/* more non-audio m= offered than we can reflect → fail closed (RFC 3264 §6) */
		}
		/* Safety: an answer MUST always carry the m=audio (it is the accepted BUNDLE transport). If the
		 * parse did not record an audio position this round (webrtc_audio_offer_idx < 0 — abnormal for an
		 * answer, but never drop audio), emit it first so the slot loop only places the non-audio sections.
		 * webrtc_audio_offer_idx >= 0 is the normal case (the answerer always parses the offer first). */
		if (pvt->webrtc_audio_offer_idx < 0) {
			int blen = strlen(buf);
			if (snprintf(buf + blen, len - blen, "%s", audio_m_buf) >= (int)(len - blen)) {
				overflow = 1;
			}
		}
		for (slot = 0; slot <= max_idx; slot++) {
			int blen;
			/* AUDIO slot — the accepted, BUNDLE-tagged transport. */
			if (slot == pvt->webrtc_audio_offer_idx) {
				blen = strlen(buf);
				if (snprintf(buf + blen, len - blen, "%s", audio_m_buf) >= (int)(len - blen)) {
					overflow = 1;
				}
				continue;
			}
			/* Find the offered non-audio section that lives at THIS slot. */
			ri = -1;
			{
				int j;
				for (j = 0; j < pvt->webrtc_reject_m_count; j++) {
					if (pvt->webrtc_reject_m[j].offer_idx == slot) {
						ri = j;
						break;
					}
				}
			}
			if (ri < 0) {
				continue;	/* no section at this slot (e.g. the audio gap) — already handled */
			}
			/* ACCEPTED VIDEO at this slot → real m=video on pvt->vrtp's OWN transport (RFC 8843 §7). The
			 * accepted-video gate is the SAME as the former STEP 6: webrtc_video_accepted (answerer); the
			 * offer-build video branch never reaches here (this loop is is_answer; that one is !is_answer). */
			if (ri == pvt->webrtc_accepted_video_idx && pvt->webrtc_video_accepted) {
				/* BUNDLE: accepted video shares the audio transport → emit from pvt->rtp (no vrtp) at the
				 * audio port; else the legacy separate-transport m=video on pvt->vrtp. */
				if (pvt->webrtc_video_bundled) {
					sofia_sdp_emit_bundled_video(pvt, buf, len, host, sdp_family, tmp_buf, sizeof(tmp_buf), port, video_dir, &overflow);
				} else if (pvt->vrtp) {
					sofia_sdp_emit_webrtc_video(pvt, buf, len, host, sdp_family, tmp_buf, sizeof(tmp_buf), video_dir, &overflow);
				}
				continue;
			}
			/* ACCEPTED DataChannel at this slot → real m=application (RFC 8841), shares the audio BUNDLE. */
			if (pvt->dc_accepted && !ast_strlen_zero(pvt->dc_mid)
					&& !ast_strlen_zero(pvt->webrtc_reject_m[ri].mid)
					&& !strcmp(pvt->webrtc_reject_m[ri].mid, pvt->dc_mid)
					&& pvt->webrtc_reject_m[ri].type_name[0]
					&& !strcasecmp(pvt->webrtc_reject_m[ri].type_name, "application")) {
				blen = strlen(buf);
				if (snprintf(buf + blen, len - blen,
						"m=application %d UDP/DTLS/SCTP webrtc-datachannel\r\n"
						"c=IN %s %s\r\n"
						"a=sctp-port:5000\r\n"
						"a=max-message-size:262144\r\n"
						"a=mid:%s\r\n",
						port, sdp_family, host, pvt->dc_mid) >= (int)(len - blen)) {
					overflow = 1;
				}
				continue;
			}
			/* OTHERWISE — port-0 reflect this offered section IN PLACE (RFC 3264 §6: declined m-line). */
			{
				struct sofia_webrtc_reject_m *r = &pvt->webrtc_reject_m[ri];
				char mid_line[80] = "";
				blen = strlen(buf);
				if (!ast_strlen_zero(r->mid)) {
					snprintf(mid_line, sizeof(mid_line), "a=mid:%s\r\n", r->mid);
				}
				if (snprintf(buf + blen, len - blen, "m=%s 0 %s %s\r\n%s",
						r->type_name, r->proto, r->fmt, mid_line) >= (int)(len - blen)) {
					overflow = 1;
				}
			}
		}
		goto webrtc_m_lines_done;	/* the WebRTC answer m-lines are fully emitted in offer order */
	}

	/* Audio section lands first (non-WebRTC leg, and the WebRTC OFFER-build direction below). */
	{
		int blen = strlen(buf);
		if (snprintf(buf + blen, len - blen, "%s", audio_m_buf) >= (int)(len - blen)) {
			overflow = 1;
		}
	}

	/* WebRTC OFFER-build (!is_answer — current role, NOT the permanent webrtc_offerer): the canonical
	 * audio,[video],[application] layout (there is no
	 * remote offer to mirror). The accepted/offered m=video on pvt->vrtp's OWN transport (RFC 8843 §7),
	 * placed right after m=audio so it matches the standard browser order (audio, video, [application]).
	 * Same accept/offer gate as the former inline STEP 6. */
	if (pvt->is_webrtc && !is_answer
			&& (pvt->webrtc_video_accepted
				|| (pvt->webrtc_video_offerer && !pvt->webrtc_video_answer_applied))) {	/* v1c: answerer-accepted OR offerer-offered */
		/* BUNDLE: emit from pvt->rtp (no vrtp) at the audio port; else the legacy separate-transport m=video. */
		if (pvt->webrtc_video_bundled) {
			sofia_sdp_emit_bundled_video(pvt, buf, len, host, sdp_family, tmp_buf, sizeof(tmp_buf), port, video_dir, &overflow);
		} else if (pvt->vrtp) {
			sofia_sdp_emit_webrtc_video(pvt, buf, len, host, sdp_family, tmp_buf, sizeof(tmp_buf), video_dir, &overflow);
		}
	}

	/* WebRTC OFFER-build m=application (RFC 8841): the ORIGINATED outbound DataChannel (dc_offerer). It
	 * RIDES THE BUNDLE'd audio transport (same port as m=audio; the SCTP runs over the audio DTLS via
	 * usrsctp) with NO own ICE/fingerprint/setup. a=mid joins a=group:BUNDLE (session level above).
	 * dc_offerer required HAVE_USRSCTP (provision_offer's attach is #ifdef'd) → a non-DC build never
	 * emits this. (The answerer's dc_accepted m=application is emitted in the mirror loop above.) */
	if (pvt->is_webrtc && !is_answer && pvt->dc_offerer && !ast_strlen_zero(pvt->dc_mid)) {
		int dblen = strlen(buf);
		if (snprintf(buf + dblen, len - dblen,
				"m=application %d UDP/DTLS/SCTP webrtc-datachannel\r\n"
				"c=IN %s %s\r\n"
				"a=sctp-port:5000\r\n"
				"a=max-message-size:262144\r\n"
				"a=mid:%s\r\n",
				port, sdp_family, host, pvt->dc_mid) >= (int)(len - dblen)) {
			overflow = 1;
		}
	}

webrtc_m_lines_done:
	/* (WebRTC ANSWER m-lines were emitted in offer order by the slot loop above; the OFFER-build leg uses
	 * the canonical layout just above. The former inline STEP 6 (m=video) / A6 (port-0 rejects) / STEP DC
	 * (m=application) blocks now live in those two paths — STEP 6 via sofia_sdp_emit_webrtc_video().) */

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
				"%s",	/* RFC 3264 §6.1 direction: sendrecv on offer, mirror of the offered video mode on answer */
				vport,
				(pvt->vsrtp && pvt->vsrtp->crypto) ? "RTP/SAVP" : "RTP/AVP",
				vpayload_buf, bw_buf, vrtpmap_buf, video_dir) >= (int)(len - vlen)) {	/* truncated video SDP */
				overflow = 1;
			}
		}
	}

	/* T.38 fax UDPTL outbound emitter: m=image + a=T38Fax* (5 mandatory + 3 optional
	 * bare-flag attrs, emitted only when the our_parms bit is set). Gated on udptl AND an ACTIVE t38_state
	 * (!= DISABLED): a refused/failed T.38 leaves pvt->udptl allocated (we keep it, non-destructive), so
	 * without the state gate a later re-INVITE / session-refresh would wrongly re-offer a live m=image.
	 * chan_sip parity: it emits T.38 SDP only when p->udptl && state==T38_LOCAL_REINVITE (chan_sip.c:13222). */
	/* SUPPRESSED on a WebRTC leg (A4/A5 audio-only): a plain m=image udptl t38 in a WebRTC SDP is the
	 * same mixed-media 488 class as plain video — no mid/ICE/fingerprint/BUNDLE. T.38 fax
	 * is never active on a browser audio call anyway; gate for completeness. */
	if (!pvt->is_webrtc && pvt->udptl && pvt->t38_state != SOFIA_T38_DISABLED) {
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
 * inputs: default_setup = ACTPASS, role CONTROLLED, ice_lite advertised. set_setup is
 * NOT called (no remote role yet, so get_setup() stays ACTPASS), but ice->start() IS, to
 * arm the STUN responder before the offer leaves the wire (early-STUN; authenticated by
 * our local ufrag/pwd, safe with no remote creds). v1c also provisions pvt->vrtp here when
 * the capability has VP8/H264 (the video offer transport). */
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
	 * with the answer-apply's call. (The browser-to-browser primary fix.) */
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
	/* v1c: provision the VIDEO transport for the OFFER too, when the effective capability has VP8/H264.
	 * sofia_rtp_init already created pvt->vrtp (chan_sofia.c:1421); we only DTLS/ICE-provision it here,
	 * mirroring the audio rtp above (ACTPASS, ice-lite, role CONTROLLED, ice->start). Fail OPEN for video —
	 * an audio-only WebRTC offer is valid, so a video-provision failure just keeps the audio offer. */
	if (pvt->peer && pvt->peer->webrtc_video_bundle && pvt->webrtc_bundle && pvt->rtp
	    && (pvt->capability & (AST_FORMAT_VP8 | AST_FORMAT_H264))) {
		/* BUNDLE (RFC 8843 max-bundle): video rides the audio ICE/DTLS transport. Register the offered VP8/H264
		 * PTs into pvt->rtp's codec map (disjoint from audio per the static PT table) so the engine classifies
		 * inbound video by PT; mark the leg bundled. NO 2nd DTLS/ICE/tls-id — the vrtp sofia_rtp_init created is
		 * dropped at the answer-parse commit (R2). The engine BUNDLE prop is armed at that commit (rollback-safe).
		 * This is the offer-generation path — the exception where webrtc_video_bundled is set early. */
		format_t bvf;
		for (bvf = 1; bvf; bvf <<= 1) {
			int bvpt;
			if (!(bvf & pvt->capability) || !(bvf & (AST_FORMAT_VP8 | AST_FORMAT_H264))) {
				continue;
			}
			bvpt = ast_rtp_codecs_payload_code(ast_rtp_instance_get_codecs(pvt->rtp), 1, bvf);
			if (bvpt >= 0) {
				ast_rtp_codecs_payloads_set_m_type(ast_rtp_instance_get_codecs(pvt->rtp), pvt->rtp, bvpt);
			}
		}
		ast_copy_string(pvt->webrtc_video_mid, "1", sizeof(pvt->webrtc_video_mid));
		pvt->webrtc_video_offerer = 1;
		pvt->webrtc_video_bundled = 1;
	} else if (pvt->vrtp && (pvt->capability & (AST_FORMAT_VP8 | AST_FORMAT_H264))) {
		struct ast_rtp_engine_dtls *vdtls = ast_rtp_instance_get_dtls(pvt->vrtp);
		struct ast_rtp_engine_ice *vice = ast_rtp_instance_get_ice(pvt->vrtp);
		struct ast_rtp_dtls_cfg vdtls_cfg = { 0 };
		vdtls_cfg.enabled = 1;
		vdtls_cfg.default_setup = AST_RTP_DTLS_SETUP_ACTPASS;	/* offerer advertises actpass (RFC 5763 §5) */
		vdtls_cfg.suite = AST_AES_CM_128_HMAC_SHA1_80;
		vdtls_cfg.hash = AST_RTP_DTLS_HASH_SHA256;
		vdtls_cfg.verify = AST_RTP_DTLS_VERIFY_FINGERPRINT;
		vdtls_cfg.ephemeral_cert = 1;
		if (!vdtls || !vice || !sofia_sched) {
			ast_log(LOG_NOTICE, "Sofia: WebRTC video offer skipped for peer '%s' — no dtls/ice/sched on vrtp (audio-only offer)\n",
				pvt->peer ? pvt->peer->name : "<unknown>");
		} else if (vdtls->set_configuration(pvt->vrtp, &vdtls_cfg)) {
			ast_log(LOG_WARNING, "Sofia: WebRTC video offer skipped for peer '%s' — vrtp DTLS set_configuration failed (audio-only offer)\n",
				pvt->peer ? pvt->peer->name : "<unknown>");
		} else {
			if (vice->ice_lite) {
				vice->ice_lite(pvt->vrtp);	/* we advertise a=ice-lite on the video m-line too */
			}
			vice->set_role(pvt->vrtp, AST_RTP_ICE_ROLE_CONTROLLED);
			if (vice->start) {
				vice->start(pvt->vrtp);	/* arm the video STUN responder before the offer leaves (early-STUN, like audio) */
			}
			ast_copy_string(pvt->webrtc_video_mid, "1", sizeof(pvt->webrtc_video_mid));	/* distinct mid; NOT in a=group:BUNDLE (non-BUNDLE) */
			if (ast_strlen_zero(pvt->webrtc_video_tls_id)) {
				unsigned char vtb[16];
				int vti;
				for (vti = 0; vti < (int)sizeof(vtb); vti++) {
					vtb[vti] = ast_random() & 0xff;
				}
				for (vti = 0; vti < (int)sizeof(vtb); vti++) {
					snprintf(pvt->webrtc_video_tls_id + vti * 2,
						sizeof(pvt->webrtc_video_tls_id) - vti * 2, "%02x", vtb[vti]);
				}
			}
			pvt->webrtc_video_offerer = 1;	/* the emitter now sends a real m=video in the offer */
		}
	}
#ifdef HAVE_USRSCTP
	/* OFFER-side WebRTC DataChannel (RFC 8841): when this peer has datachannel=yes, ORIGINATE an
	 * m=application UDP/DTLS/SCTP webrtc-datachannel in our outbound offer so the far leg negotiates the
	 * SCTP transport, runs sofia_dc_attach on ITS leg, and the relay (sofia_dc_proxy_open) can pair both
	 * DCs back-to-back. Without this the far leg never sees an m=application and never opens a DC. The DC
	 * rides the BUNDLE'd AUDIO DTLS (no new transport): a=mid is the next free BUNDLE token after audio
	 * (mid 0) and, when we also OFFER video (mid 1), after video → "2"; else "1". usrsctp MUST start BEFORE
	 * the offer (sofia_dc_attach binds the AF_CONN association onto pvt->rtp), so attach happens here, not
	 * at the answer. Fail OPEN: an attach failure just drops to an audio(-video)-only offer. */
	if (pvt->peer && pvt->peer->datachannel) {
		const char *dcmid = pvt->webrtc_video_offerer ? "2" : "1";
		ast_copy_string(pvt->dc_mid, dcmid, sizeof(pvt->dc_mid));
		pvt->dc_sctp_port = 5000;
		pvt->dc_max_message_size = 262144;
		pvt->dc_offerer = 1;
		pvt->dc = sofia_dc_attach(pvt, 5000);
		if (!pvt->dc) {
			/* usrsctp/socket failure → offer audio(-video)-only (the m=application is simply not
			 * emitted; the far leg negotiates no DC). Clear the offerer state so the emit/BUNDLE gates
			 * stay off and the answer-apply does not look for a DC that was never offered. */
			ast_log(LOG_WARNING, "Sofia: WebRTC DataChannel offer attach failed for peer '%s' — offering without a DataChannel\n",
				pvt->peer ? pvt->peer->name : "<unknown>");
			pvt->dc_offerer = 0;
			pvt->dc_mid[0] = '\0';
		} else {
			ast_debug(2, "Sofia: WebRTC DataChannel OFFERED to peer '%s' (mid=%s sctp-port=5000 max-message-size=262144) — bundled on the audio DTLS\n",
				pvt->peer ? pvt->peer->name : "<unknown>", pvt->dc_mid);
		}
	}
#endif
	pvt->webrtc_offerer = 1;	/* A5 discriminator (set BEFORE is_webrtc) */
	pvt->is_webrtc = 1;		/* gate the emitter — sofia_generate_sdp now emits a WebRTC offer */
	return 0;
}

/* RFC 3264 §8.3.2: a codec's payload-type mapping must stay stable across renegotiation.
 * A re-INVITE offer may list MANY PTs for the same video codec (browsers offer several H264
 * profile variants); merging them all lets ast_rtp_codecs_payload_code's ascending scan pick
 * a DIFFERENT PT for the answer than the one already negotiated (live case: H264 99 -> 36
 * after hold/unhold), and since our answer carries no video a=fmtp the far browser assumes a
 * possibly different profile for the new PT -> broken decode -> black video. For each video
 * codec that already has a REAL entry in the live map (i.e. was negotiated earlier — the
 * static-table fallback never appears in the map), if the new offer still includes that PT
 * for the same codec, drop every OTHER staged PT of that codec so the negotiated mapping
 * survives the merge and the answer re-emits the same PT. A first negotiation (no live
 * entry) or an offer that dropped the old PT is left untouched (free renegotiation). */
static void sofia_video_pt_keep_negotiated(struct ast_rtp_codecs *staged, struct ast_rtp_codecs *live)
{
	static const format_t vfmts[] = { AST_FORMAT_VP8, AST_FORMAT_H264 };
	size_t i;
	for (i = 0; i < ARRAY_LEN(vfmts); i++) {
		const format_t fmt = vfmts[i];
		int pt_live = -1;
		int p;
		for (p = 0; p < AST_RTP_MAX_PT; p++) {	/* lowest REAL live entry == what the emit used */
			if (live->payloads[p].gabpbx_format && live->payloads[p].code == fmt) {
				pt_live = p;
				break;
			}
		}
		if (pt_live < 0
			|| !staged->payloads[pt_live].gabpbx_format
			|| staged->payloads[pt_live].code != fmt) {
			continue;	/* never negotiated, or the new offer dropped the old PT */
		}
		for (p = 0; p < AST_RTP_MAX_PT; p++) {
			if (p != pt_live && staged->payloads[p].gabpbx_format && staged->payloads[p].code == fmt) {
				ast_rtp_codecs_payloads_unset(staged, NULL, p);
			}
		}
	}
}

int sofia_parse_sdp(struct sofia_pvt *pvt, sip_t const *sip, int current_offer)
{
	sdp_parser_t *parser;
	sdp_session_t *sdp;
	sdp_media_t *media;
	const char *sdp_data;
	int audio_offered = 0;
	int video_offered = 0;
	int audio_secure_offered = 0;
	int video_secure_offered = 0;
	/* RFC 3264 §6.1 answer-direction: capture the offered per-media mode here, commit to
	 * pvt->offered_*_mode ONLY at the success return (past every reject gate). -1 = not offered. */
	int offered_audio_mode = -1;
	int offered_video_mode = -1;
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
	struct sofia_wrtc_attrs {
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
	};
	struct sofia_wrtc_attrs wrtc = { 0 };
	struct sofia_wrtc_attrs video_wrtc = { 0 };	/* v1b: the m=video section's OWN DTLS/ICE attrs (non-BUNDLE) */
	/* Phase 3 (crash fix): a function-scope COPY of the session a=group:BUNDLE value (e.g. "BUNDLE 0 1"),
	 * captured below WHILE the sdp is still alive. The sdp parser is freed at sdp_parser_free() before
	 * the DataChannel accept gate runs, so the gate must NOT dereference sdp->sdp_attributes (use-after-
	 * free — it segfaulted on the first real DataChannel offer). Empty string = no session BUNDLE. */
	char bundle_group[256] = "";
	/* OFFER-side DataChannel answer detect: the far leg's ANSWER carried a nonzero-port m=application
	 * webrtc-datachannel (RFC 3264 §6: port 0 = the answerer DECLINED our offered DC). Set in the recording
	 * loop below; consumed by the DC offerer answer-apply (after sdp_parser_free, so it cannot re-read the
	 * sdp). Independent of pvt->dc_offered (which is INBOUND-offer semantics). */
	int answer_dc_active = 0;
	/* OFFER-side: the far leg's ANSWER carried a VALID a=sctp-port (RFC 8841 §5.1 has NO default — an
	 * absent sctp-port means the answerer is not establishing SCTP). Set ONLY inside the answer
	 * m=application parse when "sp > 0 && sp <= 65535" accepts. A literal pvt->dc_sctp_port != 0 check
	 * cannot stand in for this: sofia_webrtc_provision_offer PRE-SETS pvt->dc_sctp_port=5000 and the
	 * per-SDP reset is SKIPPED on the dc_offerer leg, so the field stays 5000 even when the answer omits
	 * a=sctp-port. The answer-apply requires this flag (alongside dc_in_answer_bundle) before accepting;
	 * absent → the existing decline path (mirrors the inbound accept gate's sctp-port refusal). */
	int answer_dc_port_present = 0;
	int image_active_seen = 0;	/* a live UDPTL T.38 image leg was present this parse */
	/* Whether THIS parse's a=crypto lazily creates the SRTP context (for reject
	 * rollback). Captured AFTER the !pvt guard below — do not deref pvt here. */
	int audio_srtp_was_new = 0;
	int video_srtp_was_new = 0;
	format_t video_offered_fmts = 0;	/* v1b: browser-offered video formats — the accept-gate intersection (STEP 3) */
	int vrtp_stage_fds23 = 0;		/* v1b STEP 8: attach o->fds[2]/[3] at the commit channel-lock when vrtp was lazily created THIS parse (re-INVITE add-video; the initial INVITE wires them in sofia_new) */

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
	int orig_webrtc_video_bundled = pvt->webrtc_video_bundled;	/* BUNDLE: restore on sdp_reject */
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
	int audio_te = 0;		/* g2: the remote's m=audio offered telephone-event (noncodec & AST_RTP_DTMF) — used at commit to resolve dtmfmode=auto */
	int video_is_bundled = 0;	/* BUNDLE: set at the accept-gate when the m=video mid is in a=group:BUNDLE (answerer) */
	char audio_pt_seen[128] = { 0 };	/* BUNDLE PT-uniqueness input: PTs the peer listed in m=audio */
	char video_pt_seen[128] = { 0 };	/* BUNDLE PT-uniqueness input: PTs the peer listed in m=video (check EVERY video PT, not one per format) */
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
	int t38_stage_local_accept = 0;		/* outbound (LOCAL_REINVITE) answer accepted T.38 → ENABLED at commit (FIX 1b) */
	int t38_stage_local_refuse = 0;		/* outbound (LOCAL_REINVITE) answer declined T.38 (no m=image) → DISABLED at commit */
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
			/* Phase 3 (crash fix): COPY the BUNDLE token list now, while the sdp is alive, so the
			 * DataChannel accept gate — which runs AFTER sdp_parser_free() — can test dc_mid membership
			 * without dereferencing the freed sdp->sdp_attributes. */
			ast_copy_string(bundle_group, ga->a_value, sizeof(bundle_group));
		}
	}

	/* Reset per-SDP WebRTC video state — these pvt fields are persistent, so a prior
	 * a=bundle-only offer or a prior acceptance must NOT poison this parse (force permanent port-0). */
	pvt->webrtc_video_bundle_only = 0;
	pvt->webrtc_video_accepted = 0;
	if (current_offer) {
		pvt->webrtc_video_bundled = 0;	/* BUNDLE: when we ANSWER a CURRENT offer we re-derive bundle from THIS offer (current role, NOT the permanent webrtc_offerer); applying an ANSWER to our own offer (current_offer==0) keeps the flag provision_offer set */
	}
	for (media = sdp->sdp_media; media; media = media->m_next) {
		if (media->m_type == sdp_media_audio && media->m_port != 0) {
			sdp_attribute_t *a;
			audio_offered = 1;
			offered_audio_mode = media->m_mode;	/* RFC 3264 §6.1: staged for the answer-direction mirror */
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
						&& su_casematch(a->a_name, "extmap")
						&& strstr(a->a_value, "urn:ietf:params:rtp-hdrext:sdes:mid")) {
					/* RFC 8285/8843 §9: remember the negotiated MID header-extension id so we echo it in our
					 * a=extmap AND stamp it on egressing bundled RTP. Value = "<id>[/dir] <uri> [attrs]". */
					int _mid_id = atoi(a->a_value);
					if (_mid_id > 0 && _mid_id <= 14) {
						pvt->webrtc_mid_ext_id = _mid_id;
					}
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
				    && (pvt->peer->nat & SOFIA_NAT_COMEDIA)
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
					if (pt >= 0 && pt < 128) {
						audio_pt_seen[pt] = 1;	/* BUNDLE PT-uniqueness input */
					}
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
				/* g2: remember whether the peer offered telephone-event (RFC 2833/4733) on
				 * this m=audio, to resolve dtmfmode=auto at the parse commit below. */
				audio_te = (noncodec & AST_RTP_DTMF) ? 1 : 0;

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
			offered_video_mode = media->m_mode;	/* RFC 3264 §6.1: staged for the answer-direction mirror */

			/* v1b STEP 2 — non-BUNDLE WebRTC video: negotiate the m=video on pvt->vrtp with its OWN
			 * DTLS/ICE (RFC 8843 §7 separate transport, NOT bundled with audio). Capture the section's
			 * OWN attrs into video_wrtc, detect a=bundle-only (RFC 8843 §7.3.2 → cannot move out, keep
			 * port-0 reflected), lazy-create vrtp WITH the sched (HIGH1: the legacy create at this site
			 * passed NULL sched → the DTLS retransmit timer would deref NULL), set its remote, stage
			 * VP8/H264. Arming + the accept-gate run post-loop; any miss leaves the video port-0 reflected
			 * (audio-only, NO regression). */
			if (audio_webrtc_offered) {
				sdp_attribute_t *va;
				for (va = media->m_attributes; va; va = va->a_next) {
					if (!va->a_name) {
						continue;
					}
					if (su_casematch(va->a_name, "bundle-only")) {
						pvt->webrtc_video_bundle_only = 1;
					} else if (va->a_value && su_casematch(va->a_name, "fingerprint")) {
						char fp_alg[32];
						char fp_hex[256];
						if (sscanf(va->a_value, "%31s %255s", fp_alg, fp_hex) == 2
								&& !strcasecmp(fp_alg, "sha-256")) {
							video_wrtc.fp_hash = AST_RTP_DTLS_HASH_SHA256;
							ast_copy_string(video_wrtc.fp_value, fp_hex, sizeof(video_wrtc.fp_value));
							video_wrtc.have_fingerprint = 1;
						}
					} else if (va->a_value && su_casematch(va->a_name, "setup")) {
						if (!strcasecmp(va->a_value, "active")) {
							video_wrtc.remote_setup = AST_RTP_DTLS_SETUP_ACTIVE;
							video_wrtc.have_setup = 1;
						} else if (!strcasecmp(va->a_value, "passive")) {
							video_wrtc.remote_setup = AST_RTP_DTLS_SETUP_PASSIVE;
							video_wrtc.have_setup = 1;
						} else if (!strcasecmp(va->a_value, "actpass")) {
							video_wrtc.remote_setup = AST_RTP_DTLS_SETUP_ACTPASS;
							video_wrtc.have_setup = 1;
						}
					} else if (va->a_value && su_casematch(va->a_name, "ice-ufrag")) {
						ast_copy_string(video_wrtc.ice_ufrag, va->a_value, sizeof(video_wrtc.ice_ufrag));
						video_wrtc.have_ice_ufrag = 1;
					} else if (va->a_value && su_casematch(va->a_name, "ice-pwd")) {
						ast_copy_string(video_wrtc.ice_pwd, va->a_value, sizeof(video_wrtc.ice_pwd));
						video_wrtc.have_ice_pwd = 1;
					} else if (va->a_value && su_casematch(va->a_name, "candidate")) {
						char c_ip[64];
						char c_transport[16];
						unsigned int c_port = 0;
						char c_typ[16] = "";
						if (sscanf(va->a_value, "%*s %*u %15s %*u %63s %u typ %15s",
								c_transport, c_ip, &c_port, c_typ) == 4
								&& !strcasecmp(c_typ, "host") && !strcasecmp(c_transport, "udp")
								&& video_wrtc.cand_count < (int)(sizeof(video_wrtc.cand) / sizeof(video_wrtc.cand[0]))) {
							struct ast_sockaddr ca;
							if (ast_sockaddr_parse(&ca, c_ip, PARSE_PORT_FORBID)) {
								ast_sockaddr_set_port(&ca, c_port);
								video_wrtc.cand[video_wrtc.cand_count++] = ca;
							}
						}
					} else if (su_casematch(va->a_name, "ice-lite")) {
						video_wrtc.remote_ice_lite = 1;
					} else if (su_casematch(va->a_name, "rtcp-mux")) {
						video_wrtc.have_rtcp_mux = 1;
					} else if (va->a_value && su_casematch(va->a_name, "mid")) {
						ast_copy_string(pvt->webrtc_video_mid, va->a_value, sizeof(pvt->webrtc_video_mid));
					}
				}
				pvt->webrtc_video_offered = 1;
				/* BUNDLE (RFC 8843): the m=video mid is a token in the session a=group:BUNDLE → it rides the
				 * AUDIO ICE/DTLS transport. Stage its VP8/H264 PTs into staged_video_codecs (merged into pvt->rtp
				 * at the commit copy); NO vrtp, NO separate video remote. Acceptance + the webrtc_video_bundled
				 * flag are finalized at the accept-gate / commit. */
				if (audio_webrtc_offered && pvt->peer && pvt->peer->webrtc_video_bundle && wrtc.have_bundle
				    && media->m_proto_name && !strncasecmp(media->m_proto_name, "UDP/TLS/", 8)
				    && sofia_sdp_mid_in_bundle(bundle_group, pvt->webrtc_video_mid)) {
					format_t bvoffered = 0;
					int bvnoncodec = 0;
					sdp_rtpmap_t *bvrm;
					sdp_list_t *bvfmt;
					ast_rtp_codecs_payloads_clear(&staged_video_codecs, NULL);
					for (bvfmt = media->m_format; bvfmt; bvfmt = bvfmt->l_next) {
						int _vpt = atoi(bvfmt->l_text);
						ast_rtp_codecs_payloads_set_m_type(&staged_video_codecs, NULL, _vpt);
						if (_vpt >= 0 && _vpt < 128) {
							video_pt_seen[_vpt] = 1;	/* every offered video PT (collision input) */
						}
					}
					for (bvrm = media->m_rtpmaps; bvrm; bvrm = bvrm->rm_next) {
						if (bvrm->rm_encoding) {
							if (ast_rtp_codecs_payloads_set_rtpmap_type_rate(&staged_video_codecs, NULL,
									bvrm->rm_pt, "video", (char *)bvrm->rm_encoding, 0, bvrm->rm_rate)) {
								ast_rtp_codecs_payloads_unset(&staged_video_codecs, NULL, bvrm->rm_pt);
							}
						}
					}
					ast_rtp_codecs_payload_formats(&staged_video_codecs, &bvoffered, &bvnoncodec);
					video_offered_fmts = bvoffered & (AST_FORMAT_VP8 | AST_FORMAT_H264);	/* VP8/H264 scope */
					if (video_offered_fmts & orig_capability) {
						staged_video_valid = 1;	/* intersection exists; accept-gate confirms + commit merges into pvt->rtp */
					}
					continue;	/* bundled video staged — skip the separate-transport path below */
				}
				if (pvt->webrtc_video_bundle_only) {
					/* RFC 8843 §7.3.2: a bundle-only section MUST NOT be moved to its own transport —
					 * leave it for the port-0 reflection (this client wants max-bundle; stay audio-only). */
					continue;
				}
				if (!pvt->vrtp) {
					struct ast_sockaddr vbind;
					ast_sockaddr_parse(&vbind, sofia_cfg.bindaddr, 0);
					pvt->vrtp = ast_rtp_instance_new("gabpbx",
						sofia_sched ? ast_sched_thread_get_context(sofia_sched) : NULL, &vbind, NULL);
					if (pvt->vrtp) {
						ast_rtp_instance_set_prop(pvt->vrtp, AST_RTP_PROPERTY_RTCP, 1);	/* rtcp-mux: RTP+RTCP on one fd */
						vrtp_stage_fds23 = 1;	/* STEP 8: a re-INVITE add-video must wire o->fds[2]/[3] at commit */
					}
				}
				if (pvt->vrtp) {
					struct ast_sockaddr vremote;
					sdp_connection_t *vconn = media->m_connections ? media->m_connections : sdp->sdp_connection;
					format_t voffered = 0;
					int vnoncodec = 0;
					sdp_rtpmap_t *vrm;
					sdp_list_t *vfmt2;
					int vhave_remote = 0;

					if (vconn && vconn->c_address) {
						vhave_remote = ast_sockaddr_parse(&vremote, vconn->c_address, 0);
						if (vhave_remote) {
							ast_sockaddr_set_port(&vremote, media->m_port);
						}
					}
					if (pvt->peer && (pvt->peer->nat & SOFIA_NAT_COMEDIA)
							&& !ast_sockaddr_isnull(&pvt->peer->src_addr)) {
						vremote = pvt->peer->src_addr;
						ast_sockaddr_set_port(&vremote, media->m_port);
						vhave_remote = 1;
					}
					if (vhave_remote) {
						ast_rtp_instance_set_remote_address(pvt->vrtp, &vremote);
					}
					ast_rtp_codecs_payloads_clear(&staged_video_codecs, NULL);
					for (vfmt2 = media->m_format; vfmt2; vfmt2 = vfmt2->l_next) {
						ast_rtp_codecs_payloads_set_m_type(&staged_video_codecs, NULL, atoi(vfmt2->l_text));
					}
					for (vrm = media->m_rtpmaps; vrm; vrm = vrm->rm_next) {
						if (vrm->rm_encoding) {
							if (ast_rtp_codecs_payloads_set_rtpmap_type_rate(&staged_video_codecs, NULL,
									vrm->rm_pt, "video", (char *)vrm->rm_encoding, 0, vrm->rm_rate)) {
								ast_rtp_codecs_payloads_unset(&staged_video_codecs, NULL, vrm->rm_pt);
							}
						}
					}
					ast_rtp_codecs_payload_formats(&staged_video_codecs, &voffered, &vnoncodec);
					video_offered_fmts = voffered & (AST_FORMAT_VP8 | AST_FORMAT_H264);	/* v1b VP8-first scope: only VP8/H264, never H261/H263/H263+ */
					/* Review BLOCKER 1: intersect against orig_capability (the pre-:977-clear snapshot), NOT
					 * the already-video-cleared pvt->capability — else the intersection is always 0 (dead code). */
					/* Review LOW: require the m=video DTLS proto (UDP/TLS/RTP/SAVPF|AVPF), mirroring the audio
					 * path (:1065) — never answer a forged plain RTP/AVP video with a UDP/TLS/RTP/SAVPF m-line. */
					if ((video_offered_fmts & orig_capability)
							&& media->m_proto_name && !strncasecmp(media->m_proto_name, "UDP/TLS/", 8)) {
						staged_video_valid = 1;	/* a VP8/H264 intersection exists; install into vrtp at commit */
					}
				}
				continue;	/* WebRTC video handled — skip the legacy non-WebRTC video path below */
			}
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
				    && (pvt->peer->nat & SOFIA_NAT_COMEDIA)
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
				    (pvt->peer->nat & SOFIA_NAT_COMEDIA) &&
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
					/* FIX 2 — apply the per-peer maxdatagram override (chan_sip parity).
					 * Read peer->t38_maxdatagram (the CONFIGURED value, set from
					 * t38pt_udptl=...,maxdatagram=N at chan_sofia.c:2989/:14305), NOT the
					 * never-written pvt->t38_maxdatagram (the pvt is ao2-zeroed → always 0
					 * → this override branch was unreachable dead code). chan_sip copies
					 * relatedpeer->t38_maxdatagram onto the dialog first (chan_sip.c:7610);
					 * here we read the peer directly. The default sentinel (-1) and 0 both
					 * leave the offered value untouched via the >0 guard. */
					int peer_maxdatagram = pvt->peer ? pvt->peer->t38_maxdatagram : 0;
					if ((peer_maxdatagram > 0) && ((unsigned int)peer_maxdatagram > x)) {
						x = (unsigned int)peer_maxdatagram;
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

			/* FIX 3 — T38FaxMaxDatagram is OPTIONAL and commonly omitted. When the
			 * offer/answer omits it, far_max_datagram stays at the -1 sentinel and
			 * calculate_far_max_ifp (main/udptl.c) logs a warning and returns 0, which
			 * propagates to res_fax as max_ifp==0 → T.38 is rejected/disabled + the
			 * warning spams per offer. chan_sip defends identically (chan_sip.c:10196):
			 * if no far max datagram was set, force the udptl DEFAULT_FAX_MAX_DATAGRAM
			 * via set_far_max_datagram(..., 0). */
			if (!ast_udptl_get_far_max_datagram(pvt->udptl)) {
				ast_udptl_set_far_max_datagram(pvt->udptl, 0);	/* 0 → DEFAULT_FAX_MAX_DATAGRAM (400) */
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

	/* A6 multi-m: RECORD every offered non-audio m= section so the answer can port-0 REFLECT it
	 * (RFC 3264 §6: one answer m= per offer m=, unaccepted at port 0) instead of dropping it — a
	 * dropped section makes a browser audio+video+datachannel offer fail with an m-line mismatch.
	 * v1a: audio is the accepted/tagged transport; video + datachannel + image are reflected at port 0
	 * (video acceptance lands next). Recorded on pvt; sofia_generate_sdp emits the reflections. */
	/* v1b STEP 3 — video acceptance gate (answerer-only, non-BUNDLE). Accept the offered m=video onto
	 * pvt->vrtp ONLY when ALL hold: a WebRTC audio session, vrtp allocated, a VP8/H264 intersection with
	 * our configured video capability, the section's OWN DTLS fingerprint + setup + ICE ufrag/pwd +
	 * rtcp-mux (each non-BUNDLE instance is single-component — opncode), and NOT a=bundle-only. Any miss →
	 * webrtc_video_accepted stays 0 and the loop below port-0 reflects the video (audio-only, NO
	 * regression). When accepted, narrow capability's video to exactly the agreed intersection so the
	 * answer advertises only what both sides support. */
	/* BUNDLE (RFC 8843): the m=video mid is in the session a=group:BUNDLE → it shares the audio ICE/DTLS
	 * transport, so accept it on BUNDLE membership (no per-m-line fingerprint/ice/rtcp-mux, no vrtp). */
	video_is_bundled = audio_webrtc_offered && current_offer && pvt->peer && pvt->peer->webrtc_video_bundle
		&& wrtc.have_bundle && sofia_sdp_mid_in_bundle(bundle_group, pvt->webrtc_video_mid);
	pvt->webrtc_video_accepted = audio_webrtc_offered && current_offer	/* v1c POINT 2: this ANSWER transaction only (current_offer==1). The offerer's own-offer video answer (current_offer==0) is owned by the offerer answer-apply below, guarded by !webrtc_video_answer_applied so the two never collide */
		&& staged_video_valid
		&& (video_is_bundled					/* BUNDLE: shares the audio transport (RFC 8843) */
		    || (pvt->vrtp && !pvt->webrtc_video_bundle_only	/* legacy separate transport: own DTLS/ICE attrs */
			&& video_wrtc.have_fingerprint && video_wrtc.have_setup
			&& video_wrtc.have_ice_ufrag && video_wrtc.have_ice_pwd && video_wrtc.have_rtcp_mux))
		&& (video_offered_fmts & orig_capability & AST_FORMAT_VIDEO_MASK);	/* Review BLOCKER 1: orig_capability, not the :977-cleared pvt->capability */
	if (pvt->webrtc_video_accepted) {
		format_t agreed_video = video_offered_fmts & orig_capability & AST_FORMAT_VIDEO_MASK;
		pvt->capability = (pvt->capability & ~((format_t)AST_FORMAT_VIDEO_MASK)) | agreed_video;
		/* pvt->webrtc_video_bundled is NOT set here — it is armed at the COMMIT, past every reject
		 * gate, so a parsed-but-rejected SDP can never leave the flag stale. video_is_bundled carries it. */
	}
	pvt->webrtc_reject_m_count = 0;
	pvt->webrtc_accepted_video_idx = -1;	/* Review HIGH 1:1 — no accepted video recorded yet this parse */
	pvt->webrtc_audio_offer_idx = -1;	/* no audio position recorded yet this parse (answer mirrors offer order, RFC 3264 §6) */
	pvt->webrtc_reject_overflow = 0;
	pvt->webrtc_video_offered = 0;
	pvt->webrtc_video_mid[0] = '\0';
	/* Phase 3 WebRTC DataChannel (RFC 8841): reset the per-SDP m=application state. dc_accepted is
	 * (re)decided at the ACCEPT GATE after the audio commit; the offer's sctp-port/mid/max-message-size
	 * are (re)captured in the loop below. Persistent pvt fields → must clear so a prior offer never
	 * poisons this parse (mirrors the webrtc_video_* reset).
	 *
	 * OFFER-side caveat: dc_offerer / dc_mid / dc_sctp_port / dc_max_message_size are
	 * set by sofia_webrtc_provision_offer at OFFER GENERATION — which has already run by the time we parse
	 * the far leg's ANSWER here. Clearing them would erase the DC we just offered (the answer-apply below
	 * needs dc_mid + dc_offerer to match the far leg's BUNDLE). So on an OFFERER leg we keep dc_offerer /
	 * dc_mid (BUNDLE matching) and dc_sctp_port (harmless — BUG1's accept gate keys on the answer_dc_port_present
	 * local, not this preseeded field); only a NON-offerer parse (a genuine inbound offer) clears the inbound
	 * capture fields. dc_offerer itself is NEVER cleared at parse start — only by the answer-apply when the far
	 * leg declines. dc_answer_applied is a set-once one-shot (like webrtc_answer_applied /
	 * webrtc_video_answer_applied): zero-initialized at pvt alloc, NEVER reset at parse start, so a re-INVITE
	 * does not re-apply the DC answer.
	 *
	 * EXCEPTION (grounded fix, RFC 8841 §6.1): on the OFFERER leg we DO reset dc_max_message_size to 0
	 * before the answer walk. provision_offer preseeded it to 262144 (OUR offered max), but max-message-size is
	 * DIRECTIONAL — the live dc->peer_max_msg must reflect the PEER's limit from the ANSWER. The answer parser
	 * only overwrites when a=max-message-size is PRESENT, so without this reset an answer OMITTING it would leave
	 * the stale 262144 and the relay would cap there instead of the RFC default 64K (absent → 0 sentinel → relay
	 * applies 65536 at sofia_datachannel.c). Resetting to 0 lets a PRESENT attr overwrite and an ABSENT one fall
	 * back correctly — this is exactly what the answer-parser comment below asserts. */
	if (current_offer || !pvt->dc_offerer) {	/* a CURRENT remote offer always re-drives these capture fields (a stale dc_offered/dc_mid from a prior accepted DC must not poison this offer's accept walk); dc_offerer itself and the live pvt->dc are untouched */
		pvt->dc_offered = 0;
		pvt->dc_mid[0] = '\0';
		pvt->dc_sctp_port = 0;
		pvt->dc_max_message_size = 0;
	} else {
		pvt->dc_max_message_size = 0;	/* offerer: keep mid/sctp-port, but let the answer (or its absence) drive the peer max */
	}
	/* dc_accepted: clear only the EMIT decision, NOT the live pvt->dc handle. On a re-INVITE that still
	 * carries the DC the accept gate re-asserts it (idempotent — pvt->dc is non-NULL so we keep it); on
	 * one that DROPS the DC it correctly stays 0 → the answer reflects m=application at port 0. The actual
	 * pvt->dc usrsctp teardown for a withdrawn DC is owned by Phase 2b (the recv-cb stream-reset path) /
	 * the destructor — Phase 3 SDP does not detach mid-dialog. */
	pvt->dc_accepted = 0;
	if (audio_webrtc_offered) {
		sdp_media_t *mm;
		int m_abs_idx = 0;	/* ABSOLUTE offer m-line index (counts EVERY section, incl. audio) so the answer
					 * mirrors offer ORDER (RFC 3264 §6 / RFC 8829 §5.3). */
		for (mm = sdp->sdp_media; mm; mm = mm->m_next, m_abs_idx++) {
			sdp_attribute_t *ma;
			const char *mid = "";
			if (mm->m_type == sdp_media_audio) {
				/* The audio section IS the accepted, tagged BUNDLE transport (emitted as the real m=audio).
				 * Record its ABSOLUTE offer position so the emit can place it at the right slot when the
				 * offer order is non-canonical (e.g. audio,application,video after renegotiation). The FIRST
				 * audio wins (matching the parse above, which keys WebRTC off the first audio section). */
				if (pvt->webrtc_audio_offer_idx < 0) {
					pvt->webrtc_audio_offer_idx = m_abs_idx;
				}
				continue;
			}
			for (ma = mm->m_attributes; ma; ma = ma->a_next) {	/* its a=mid (RFC 8843) */
				if (ma->a_name && su_casematch(ma->a_name, "mid") && ma->a_value) {
					mid = ma->a_value;
					break;
				}
			}
			/* Phase 3 WebRTC DataChannel detect (RFC 8841): an m=application
			 * UDP/DTLS/SCTP webrtc-datachannel section. It REUSES the audio BUNDLE
			 * ICE+DTLS transport (no new transport) — only its SCTP params are read
			 * here (a=sctp-port, a=max-message-size, a=mid). Recorded on pvt; the
			 * accept decision + sofia_dc_attach happen after the audio commit. Still
			 * ALSO recorded in webrtc_reject_m below so a NON-accepted DC is port-0
			 * reflected exactly like any declined m-line. */
			if (mm->m_type == sdp_media_application
					&& mm->m_port != 0	/* RFC 3264: a port-0 m=application is the offerer DECLINING it — not a real offer */
					&& mm->m_proto_name
					&& !strncasecmp(mm->m_proto_name, "UDP/DTLS/SCTP", 13)
					&& mm->m_format && mm->m_format->l_text
					&& !strcasecmp(mm->m_format->l_text, "webrtc-datachannel")) {
				answer_dc_active = 1;	/* OFFER-side: a real (nonzero-port) m=application present in the far leg's answer */
				pvt->dc_offered = 1;
				ast_copy_string(pvt->dc_mid, mid, sizeof(pvt->dc_mid));
				for (ma = mm->m_attributes; ma; ma = ma->a_next) {
					if (!ma->a_name || !ma->a_value) {
						continue;
					}
					if (su_casematch(ma->a_name, "sctp-port")) {
						int sp = atoi(ma->a_value);
						if (sp > 0 && sp <= 65535) {
							pvt->dc_sctp_port = (uint16_t)sp;
							answer_dc_port_present = 1;	/* RFC 8841 §5.1: a VALID a=sctp-port is present in the ANSWER */
						}
					} else if (su_casematch(ma->a_name, "max-message-size")) {
						/* RFC 8841 §6: explicit 0 = UNBOUNDED →
						 * record the sentinel (relay applies the 262144 hard cap, NOT the
						 * 65536 default); explicit N → record N; an ABSENT attribute leaves
						 * the field at its reset 0 (relay default 65536). */
						long mms = atol(ma->a_value);
						if (mms == 0) {
							pvt->dc_max_message_size = SOFIA_DC_PEER_MAX_UNBOUNDED;
						} else if (mms > 0) {
							pvt->dc_max_message_size = (unsigned int)mms;
						}
					}
				}
			}
			if (mm->m_type == sdp_media_video) {
				pvt->webrtc_video_offered = 1;
				ast_copy_string(pvt->webrtc_video_mid, mid, sizeof(pvt->webrtc_video_mid));
				/* Review HIGH 1:1 — mark which reject_m index is the accepted video (STEP 2 stages the LAST
				 * acceptable video, so the last video's index wins); the emit skips exactly this one entry. */
				if (pvt->webrtc_video_accepted && pvt->webrtc_reject_m_count < (int)ARRAY_LEN(pvt->webrtc_reject_m)) {
					pvt->webrtc_accepted_video_idx = pvt->webrtc_reject_m_count;
				}
				/* RECORD the video in reject_m ALWAYS. The real-vs-port0 decision is
				 * deferred to EMIT time (sofia_generate_sdp skips this entry iff webrtc_video_accepted is
				 * STILL true after STEP 5 arming). This guarantees exactly ONE m=video even if STEP 5 arming
				 * fails and drops accepted to 0 — no missing/extra m-line (RFC 3264 §6 exact count). */
			}
			if (pvt->webrtc_reject_m_count < (int)ARRAY_LEN(pvt->webrtc_reject_m)) {
				struct sofia_webrtc_reject_m *r = &pvt->webrtc_reject_m[pvt->webrtc_reject_m_count++];
				if (!ast_strlen_zero(mm->m_type_name)) {
					ast_copy_string(r->type_name, mm->m_type_name, sizeof(r->type_name));
				} else {
					ast_copy_string(r->type_name, (mm->m_type == sdp_media_video) ? "video"
						: (mm->m_type == sdp_media_image) ? "image" : "application", sizeof(r->type_name));
				}
				ast_copy_string(r->proto, mm->m_proto_name ? mm->m_proto_name : "RTP/AVP", sizeof(r->proto));
				ast_copy_string(r->fmt, (mm->m_format && mm->m_format->l_text) ? mm->m_format->l_text : "0", sizeof(r->fmt));
				ast_copy_string(r->mid, mid, sizeof(r->mid));
				r->offer_idx = m_abs_idx;	/* ABSOLUTE offer position → answer mirrors offer order (RFC 3264 §6) */
			} else {
				pvt->webrtc_reject_overflow = 1;
			}
		}
	}

	/* A re-INVITE that withdraws the image stream (m=image port 0 or absent) must
	 * return T.38 to DISABLED, else fax state stays stuck active. Deferred to
	 * commit; mutually exclusive with t38_stage_enter_reinvite. */
	if (!image_active_seen && pvt->t38_state >= SOFIA_T38_PEER_REINVITE) {
		t38_stage_withdraw = 1;
	}

	/* FIX 1b — OUTBOUND (LOCAL_REINVITE) ANSWER-APPLY (RFC 3264 §8: the offerer applies
	 * the answer). We sent a T.38 (m=image) offer and are now parsing the peer's ANSWER
	 * (this body arrives via the directmedia/reinvite 2xx path, or an 18x preview). The
	 * t38_stage_enter_reinvite gate above fires PEER_REINVITE only from DISABLED, and the
	 * withdraw gate is >= PEER_REINVITE, so LOCAL_REINVITE (==1) falls through both —
	 * decide its transition here, deferred to the channel-locked commit:
	 *   - answer ACCEPTED T.38 (a live m=image leg) → ENABLED  (chan_sip.c:10202-10204:
	 *     SDP_T38_ACCEPT && T38_LOCAL_REINVITE → change_t38_state(T38_ENABLED));
	 *   - answer DECLINED T.38 (no/zeroed m=image) → DISABLED (queues AST_T38_REFUSED).
	 * Mutually exclusive with enter_reinvite/withdraw (LOCAL_REINVITE never satisfies
	 * their state gates). */
	if (pvt->t38_state == SOFIA_T38_LOCAL_REINVITE) {
		if (image_active_seen) {
			t38_stage_local_accept = 1;
		} else {
			t38_stage_local_refuse = 1;
		}
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
	/* Audit HIGH (A6 update): reject a DTLS video offer ONLY for a NON-WebRTC audio session. A real WebRTC
	 * audio+video offer now port-0 REFLECTS the video m= section (RFC 3264) instead of 488ing the whole body
	 * (v1b accepts the video). A non-webrtc-audio leg still rejects DTLS video — no silent RTP/AVP downgrade
	 * (the audio HIGH1 defect, mirrored for video). */
	if (video_savpf_offered && !audio_webrtc_offered) {
		ast_log(LOG_NOTICE, "Sofia: SDP rejected — DTLS video offered but the session is not WebRTC audio (peer '%s')\n",
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
			/* Require a=rtcp-mux in the ANSWER too. Our engine is mux-ONLY (single
			 * socket); RFC 5761 §5.1.1 — an answerer that omits a=rtcp-mux means the offerer MUST NOT
			 * multiplex (separate RTCP), which we cannot do → fail closed. Browsers always mux. */
			ast_log(LOG_NOTICE, "Sofia: SDP rejected — WebRTC ANSWER missing required attrs (fp=%d setup=%d ufrag=%d pwd=%d mux=%d)\n",
				wrtc.have_fingerprint, wrtc.have_setup, wrtc.have_ice_ufrag, wrtc.have_ice_pwd, wrtc.have_rtcp_mux);
			goto sdp_reject;
		}
		/* RFC 5763 §5: the ANSWERER MUST use a=setup:active or :passive — NEVER actpass (the
		 * offerer is actpass; only the answer fixes the concrete role). A non-conformant actpass
		 * ANSWER would map (res_rtp_gabpbx.c gabpbx_dtls_set_setup, remote actpass -> our PASSIVE)
		 * to leave BOTH ends DTLS server -> neither sends the ClientHello -> stalled handshake.
		 * Treat it as a negotiation error and fail the media rather than silently going PASSIVE.
		 * Conformant browsers always answer active, so real WebRTC is unaffected. */
		if (wrtc.remote_setup == AST_RTP_DTLS_SETUP_ACTPASS) {
			ast_log(LOG_NOTICE, "Sofia: SDP rejected — WebRTC ANSWER carried a=setup:actpass (RFC 5763 §5: the answerer MUST use active or passive) for peer '%s'\n",
				pvt->peer ? pvt->peer->name : "<unknown>");
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

	/* OFFER-side WebRTC DataChannel ANSWER-APPLY (RFC 8841): when WE offered a DataChannel (dc_offerer set
	 * in sofia_webrtc_provision_offer, sofia_dc_attach already armed pvt->dc), decide from the far leg's
	 * ANSWER whether it accepted. ACCEPT requires BOTH (RFC 8843): the answer carried a nonzero-port
	 * m=application webrtc-datachannel (answer_dc_active — port 0 = declined) AND our dc_mid is a token in
	 * the answer's session a=group:BUNDLE (bundle_group — the COPY captured BEFORE sdp_parser_free; reading
	 * sdp->sdp_attributes here would be the UAF the inbound accept gate's crash taught us). On accept keep
	 * pvt->dc (the relay's far-DC); on decline detach + clear dc_offerer so the emit/BUNDLE gates go off and
	 * the audio(-video) call continues. One-shot via dc_answer_applied (re-INVITE / duplicate 2xx safe). */
	if (audio_webrtc_offered && pvt->dc_offerer && !pvt->dc_answer_applied) {
		int dc_in_answer_bundle = 0;
		/* RFC 8841 §5.1 has no default sctp-port: require the ANSWER carried a VALID a=sctp-port
		 * (answer_dc_port_present) before even checking the BUNDLE — sofia_webrtc_provision_offer leaves
		 * pvt->dc_sctp_port pre-set to 5000 on this dc_offerer leg, so it cannot be the presence test.
		 * Absent → dc_in_answer_bundle stays 0 → the decline path below (detach + dc=NULL + dc_offerer=0),
		 * mirroring the inbound accept gate's sctp-port refusal. */
		if (answer_dc_active && answer_dc_port_present && !ast_strlen_zero(pvt->dc_mid)
				&& !strncasecmp(bundle_group, "BUNDLE", 6)) {
			char grp[256];
			char *tok, *save = NULL;
			ast_copy_string(grp, bundle_group, sizeof(grp));
			tok = strtok_r(grp, " \t", &save);	/* the literal "BUNDLE" */
			while ((tok = strtok_r(NULL, " \t", &save))) {
				if (!strcmp(tok, pvt->dc_mid)) {
					dc_in_answer_bundle = 1;
					break;
				}
			}
		}
		if (dc_in_answer_bundle) {
			pvt->dc_answer_applied = 1;
			/* The DC attached in provision_offer with the 262144 default; the answer parse above learned
			 * the peer's real a=max-message-size into pvt->dc_max_message_size. Push it into the live dc so
			 * the relay's forward-direction cap (which reads far_dc->peer_max_msg) is correct. Pass the value
			 * UNCHANGED — the parse already encoded the RFC 8841 §6 sentinel (0=absent → relay 65536;
			 * SOFIA_DC_PEER_MAX_UNBOUNDED=explicit-0 → relay 262144 hard cap, NOT the 65536 default; else N). */
#ifdef HAVE_USRSCTP
			if (pvt->dc) {
				/* DTLS-role/stream-parity fix (RFC 8832 §6): the DC attached in provision_offer while our
				 * a=setup was still ACTPASS, so dc->dtls_is_server latched 0 (client/even). The answer's
				 * set_setup above (line ~2139) just fixed our CONCRETE role (answer a=setup:active → we
				 * PASSIVE = DTLS server = ODD parity, RFC 5763 §5). Recompute dc->dtls_is_server from the
				 * now-concrete engine setup BEFORE any worker-lane SID allocation / inbound OPEN parity
				 * check, else gabpbx would proxy OPENs on even streams the peer rejects AND flag every
				 * legit peer OPEN as wrong-parity → the offerer-direction DataChannel silently fails. */
				sofia_dc_set_dtls_role(pvt->dc);
				sofia_dc_set_peer_max_msg(pvt->dc, pvt->dc_max_message_size);
			}
#endif
			ast_debug(2, "Sofia: WebRTC DataChannel answer ACCEPTED by peer '%s' (mid=%s) — keeping the bundled SCTP association\n",
				pvt->peer ? pvt->peer->name : "<unknown>", pvt->dc_mid);
		} else {
			/* The far leg declined our DataChannel (port-0 m=application, or no m=application, or our mid
			 * absent from its BUNDLE). Tear down the usrsctp association we pre-armed and stop emitting the
			 * m=application; the audio(-video) call is unaffected. */
			ast_log(LOG_NOTICE, "Sofia: peer '%s' declined our offered WebRTC DataChannel — continuing without it\n",
				pvt->peer ? pvt->peer->name : "<unknown>");
#ifdef HAVE_USRSCTP
			if (pvt->dc) {
				sofia_dc_detach(pvt->dc);
				pvt->dc = NULL;
			}
#endif
			pvt->dc_offerer = 0;
		}
	}

	/* v1c OFFERER VIDEO ANSWER-APPLY: when WE offered video (webrtc_video_offerer), apply the browser's
	 * m=video ANSWER to pvt->vrtp. set_configuration already ran in provision_offer — apply only the remote
	 * params (fp/setup/ICE/candidates), then start + activate. The answer's video codec map is installed into
	 * vrtp by the staged_video_valid commit copy below (so RX maps the browser's PTs, e.g. H264 on 102/125).
	 * STEP 3's accept gate is current-answer-only (current_offer), so this block alone owns the offerer's video and
	 * narrows pvt->capability to the agreed intersection. If the browser rejected video (port 0 / missing attrs
	 * / no VP8-H264 intersection), disable the offerer video and keep the audio call. */
	if (audio_webrtc_offered && pvt->webrtc_video_offerer && !pvt->webrtc_video_answer_applied
			&& pvt->webrtc_video_bundled) {
		/* BUNDLE: our offered video rode the audio ICE/DTLS transport, so the browser's answer carries NO
		 * separate video DTLS/ICE to apply. Accept on the codec intersection only — the engine BUNDLE is armed
		 * at the COMMIT and the vrtp dropped at parse-end (R2). The answer's video mid MUST still be a token in
		 * its a=group:BUNDLE, else a nonconformant separate-transport answer would be wrongly accepted as bundled. */
		format_t agreed_vb = video_offered_fmts & orig_capability & AST_FORMAT_VIDEO_MASK;
		if (staged_video_valid && agreed_vb
				&& sofia_sdp_mid_in_bundle(bundle_group, pvt->webrtc_video_mid)) {
			pvt->capability = (pvt->capability & ~((format_t)AST_FORMAT_VIDEO_MASK)) | agreed_vb;
			pvt->webrtc_video_answer_applied = 1;
		} else {
			ast_log(LOG_NOTICE, "Sofia: WebRTC bundled video answer not usable for peer '%s' — continuing audio-only\n",
				pvt->peer ? pvt->peer->name : "<unknown>");
			pvt->webrtc_video_offerer = 0;
			pvt->webrtc_video_bundled = 0;
			pvt->capability &= ~((format_t)AST_FORMAT_VIDEO_MASK);
			staged_video_valid = 0;
		}
	} else if (audio_webrtc_offered && pvt->webrtc_video_offerer && !pvt->webrtc_video_answer_applied && pvt->vrtp) {
		struct ast_rtp_engine_dtls *vdtls = ast_rtp_instance_get_dtls(pvt->vrtp);
		struct ast_rtp_engine_ice *vice = ast_rtp_instance_get_ice(pvt->vrtp);
		format_t agreed_v = video_offered_fmts & orig_capability & AST_FORMAT_VIDEO_MASK;
		if (vdtls && vice && staged_video_valid
				&& video_wrtc.have_fingerprint && video_wrtc.have_setup
				&& video_wrtc.remote_setup != AST_RTP_DTLS_SETUP_ACTPASS	/* RFC 5763 §5: answerer MUST be active/passive, not actpass — a non-conformant actpass video answer would map to our PASSIVE → both DTLS server → stalled; drop video, keep audio */
				&& video_wrtc.have_ice_ufrag && video_wrtc.have_ice_pwd && video_wrtc.have_rtcp_mux
				&& agreed_v) {
			int vi;
			vdtls->set_fingerprint(pvt->vrtp, video_wrtc.fp_hash, video_wrtc.fp_value);
			vdtls->set_setup(pvt->vrtp, video_wrtc.remote_setup);	/* browser answers active → we PASSIVE (RFC 5763 §5) */
			vice->set_authentication(pvt->vrtp, video_wrtc.ice_ufrag, video_wrtc.ice_pwd);
			for (vi = 0; vi < video_wrtc.cand_count; vi++) {
				struct ast_rtp_engine_ice_candidate vcand = { 0 };
				vcand.foundation = "0";
				vcand.id = AST_RTP_ICE_COMPONENT_RTP;
				vcand.transport = "udp";
				vcand.priority = 0;
				vcand.address = video_wrtc.cand[vi];
				vcand.type = AST_RTP_ICE_CANDIDATE_TYPE_HOST;
				vice->add_remote_candidate(pvt->vrtp, &vcand);
			}
			if (video_wrtc.remote_ice_lite && vice->ice_lite) {
				vice->ice_lite(pvt->vrtp);
			}
			vice->set_role(pvt->vrtp, AST_RTP_ICE_ROLE_CONTROLLED);
			vice->start(pvt->vrtp);	/* remote creds set now — safe to arm the video STUN responder */
			pvt->capability = (pvt->capability & ~((format_t)AST_FORMAT_VIDEO_MASK)) | agreed_v;	/* narrow to the agreed video */
			pvt->webrtc_video_answer_applied = 1;
			ast_rtp_instance_activate(pvt->vrtp);	/* video codec map is installed by the staged_video_valid commit copy below */
		} else {
			/* browser rejected our video (port 0 / missing attrs / no VP8-H264 intersection) — keep audio-only */
			ast_log(LOG_NOTICE, "Sofia: WebRTC video answer not usable for peer '%s' — continuing audio-only\n",
				pvt->peer ? pvt->peer->name : "<unknown>");
			pvt->webrtc_video_offerer = 0;
			pvt->capability &= ~((format_t)AST_FORMAT_VIDEO_MASK);
			staged_video_valid = 0;	/* Review LOW: don't let the staged_video_valid commit copy install a codec map onto a vrtp we never activate for this rejected-video offerer */
		}
	}

	if (audio_webrtc_offered && !pvt->is_webrtc) {
		struct ast_rtp_engine_dtls *dtls = ast_rtp_instance_get_dtls(pvt->rtp);
		struct ast_rtp_engine_ice *ice = ast_rtp_instance_get_ice(pvt->rtp);
		struct ast_rtp_dtls_cfg dtls_cfg = { 0 };
		int i;

		/* OQ3 fail-closed: the dtls/ice vtables are ALWAYS non-NULL (engine-level, not
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

		/* Phase 3 WebRTC DataChannel ACCEPT GATE (RFC 8841). Accept the offered m=application ONLY when
		 * ALL hold; otherwise it stays in webrtc_reject_m and is port-0 reflected (exactly like a declined
		 * m-line). Runs INSIDE the audio-commit block (is_webrtc just set) so "the audio WebRTC leg
		 * committed OK" is guaranteed. The DC shares THIS BUNDLE ICE+DTLS transport — sofia_dc_attach binds
		 * usrsctp onto pvt->rtp; no new transport. Without HAVE_USRSCTP sofia_dc_attach is a no-op stub, so
		 * we keep the m=application port-0 reflected (do not enter the accept path at all).
		 *   1. webrtc=yes (implied: we are in the WebRTC audio commit)
		 *   2. the new datachannel=yes peer/[general] knob (DEFAULT no)
		 *   3. HAVE_USRSCTP (compile-time; the #else stub leg below keeps it port-0)
		 *   4. the offer carried an m=application webrtc-datachannel (dc_offered)
		 *   5. a session-level a=group:BUNDLE was present (we BUNDLE-share one transport)
		 *   6. the DC's a=mid is a token in that a=group:BUNDLE line (RFC 8843 — same transport) */
		if (pvt->dc_offered && pvt->peer && pvt->peer->datachannel && pvt->webrtc_bundle) {
			int dc_in_bundle = 0;
			/* The DC mid must appear as a whitespace-delimited token in "BUNDLE 0 1 ..." (RFC 8843 §5).
			 * CRASH FIX: use bundle_group — the COPY captured above while the sdp was alive. The sdp
			 * parser was freed at sdp_parser_free() before this point, so sdp->sdp_attributes is dangling
			 * here (the original sdp_attribute_find() here was a use-after-free that segfaulted). Empty
			 * dc_mid (or empty bundle_group) never matches — such a DC cannot be BUNDLE'd, so it reflects. */
			if (!ast_strlen_zero(pvt->dc_mid) && !strncasecmp(bundle_group, "BUNDLE", 6)) {
				char grp[256];
				char *tok, *save = NULL;
				ast_copy_string(grp, bundle_group, sizeof(grp));
				tok = strtok_r(grp, " \t", &save);	/* the literal "BUNDLE" */
				while ((tok = strtok_r(NULL, " \t", &save))) {
					if (!strcmp(tok, pvt->dc_mid)) {
						dc_in_bundle = 1;
						break;
					}
				}
			}
			if (dc_in_bundle) {
#ifdef HAVE_USRSCTP
				if (pvt->dc) {
					/* re-INVITE that still carries the DC: keep the live association, just re-assert the
					 * EMIT decision (idempotent — never re-attach, which would leak the prior handle). */
					pvt->dc_accepted = 1;
				} else if (pvt->dc_sctp_port == 0) {
					/* RFC 8841 §5.1: a=sctp-port has NO default value — an absent or zero sctp-port means
					 * the offerer is not actually establishing SCTP. Refuse → port-0 reflect (no 5000
					 * fallback; the m=application stays in webrtc_reject_m so the emit handles it). */
					ast_log(LOG_NOTICE, "Sofia: peer '%s' offered m=application without a valid a=sctp-port — reflecting at port 0\n",
						pvt->peer->name);
				} else {
					uint16_t sp = pvt->dc_sctp_port;
					pvt->dc = sofia_dc_attach(pvt, sp);
					if (pvt->dc) {
						pvt->dc_accepted = 1;
						ast_debug(2, "Sofia: WebRTC DataChannel ACCEPTED for peer '%s' (mid=%s sctp-port=%u max-message-size=%u) — bundled on the audio DTLS\n",
							pvt->peer->name, pvt->dc_mid, (unsigned)sp, pvt->dc_max_message_size);
					} else {
						/* Attach failed (usrsctp/socket) → fall back to a port-0 reflection (the
						 * m=application is still in webrtc_reject_m, so the emit handles it). */
						ast_log(LOG_WARNING, "Sofia: WebRTC DataChannel attach failed for peer '%s' — reflecting m=application at port 0\n",
							pvt->peer->name);
					}
				}
#else
				/* Built without usrsctp: cannot accept. Leave dc_accepted 0 so the m=application
				 * is port-0 reflected via webrtc_reject_m (no behaviour change vs a non-DC build). */
				ast_log(LOG_NOTICE, "Sofia: peer '%s' has datachannel=yes but gabpbx was built without usrsctp — reflecting m=application at port 0\n",
					pvt->peer->name);
#endif
			}
		}
	}

	/* v1b STEP 5 — arm pvt->vrtp's OWN DTLS-SRTP + ICE for the accepted non-BUNDLE video. Mirrors the
	 * audio answerer commit above but targets pvt->vrtp + video_wrtc, with a per-video one-shot guard so a
	 * re-INVITE does not restart the video DTLS handshake. Provisioned ONLY here (after every reject gate)
	 * so a rejected SDP never leaves a half-armed vrtp. a=setup:PASSIVE matches the audio interop choice
	 * (browser is the DTLS client). vsrtp stays NULL — DTLS-SRTP carries no a=crypto. activate happens in
	 * chan_sofia.c after the 200 OK (mirrors the audio rtp). On ANY arming failure → drop to audio-only. */
	if (audio_webrtc_offered && pvt->webrtc_video_accepted && !pvt->webrtc_video_answer_applied
			&& !video_is_bundled && pvt->vrtp) {	/* BUNDLE: bundled video has no own vrtp transport to arm — it rides the audio DTLS/ICE */
		struct ast_rtp_engine_dtls *vdtls = ast_rtp_instance_get_dtls(pvt->vrtp);
		struct ast_rtp_engine_ice *vice = ast_rtp_instance_get_ice(pvt->vrtp);
		struct ast_rtp_dtls_cfg vcfg = { 0 };
		int vi;

		if (!vdtls || !vice || !sofia_sched) {
			ast_log(LOG_WARNING, "Sofia: WebRTC video NOT armed for peer '%s' (sched=%p dtls=%p ice=%p) — video left audio-only\n",
				pvt->peer ? pvt->peer->name : "<unknown>", (void *)sofia_sched, (void *)vdtls, (void *)vice);
			pvt->webrtc_video_accepted = 0;
		} else {
			vcfg.enabled = 1;
			vcfg.default_setup = AST_RTP_DTLS_SETUP_PASSIVE;
			vcfg.suite = AST_AES_CM_128_HMAC_SHA1_80;
			vcfg.hash = AST_RTP_DTLS_HASH_SHA256;
			vcfg.verify = AST_RTP_DTLS_VERIFY_FINGERPRINT;
			vcfg.ephemeral_cert = 1;
			if (vdtls->set_configuration(pvt->vrtp, &vcfg)) {
				ast_log(LOG_WARNING, "Sofia: WebRTC video DTLS set_configuration failed for peer '%s' — video left audio-only\n",
					pvt->peer ? pvt->peer->name : "<unknown>");
				pvt->webrtc_video_accepted = 0;
			} else {
				vdtls->set_fingerprint(pvt->vrtp, video_wrtc.fp_hash, video_wrtc.fp_value);
				vdtls->set_setup(pvt->vrtp, video_wrtc.remote_setup);
				vice->set_authentication(pvt->vrtp, video_wrtc.ice_ufrag, video_wrtc.ice_pwd);
				for (vi = 0; vi < video_wrtc.cand_count; vi++) {
					struct ast_rtp_engine_ice_candidate vcand = { 0 };
					vcand.foundation = "0";
					vcand.id = AST_RTP_ICE_COMPONENT_RTP;
					vcand.transport = "udp";
					vcand.priority = 0;
					vcand.address = video_wrtc.cand[vi];
					vcand.type = AST_RTP_ICE_CANDIDATE_TYPE_HOST;
					vice->add_remote_candidate(pvt->vrtp, &vcand);
				}
				if (video_wrtc.remote_ice_lite && vice->ice_lite) {
					vice->ice_lite(pvt->vrtp);
				}
				vice->set_role(pvt->vrtp, AST_RTP_ICE_ROLE_CONTROLLED);
				vice->start(pvt->vrtp);
				if (ast_strlen_zero(pvt->webrtc_video_tls_id)) {
					unsigned char vtb[16];
					int vti;
					for (vti = 0; vti < (int)sizeof(vtb); vti++) {
						vtb[vti] = ast_random() & 0xff;
					}
					for (vti = 0; vti < (int)sizeof(vtb); vti++) {
						snprintf(pvt->webrtc_video_tls_id + vti * 2,
							sizeof(pvt->webrtc_video_tls_id) - vti * 2, "%02x", vtb[vti]);
					}
				}
				pvt->webrtc_video_answer_applied = 1;
			}
		}
	}

	/* The video gate/arm did NOT accept (no codec intersection, missing attrs, bundle-only,
	 * or an arming failure) → tear down a vrtp this parse LAZILY created, so the audio-only fallback leaves
	 * NO unused live video RTP instance (sofia_new wires fds[2]/[3] whenever pvt->vrtp exists). had_vrtp
	 * guards a pre-existing vrtp (re-INVITE). Mutually exclusive with the sdp_reject rollback below.
	 * Review BLOCKER 2: gate on (audio_webrtc_offered && webrtc_video_offered) so this NEVER collects the
	 * legacy vrtp of a plain (non-WebRTC) SIP audio+video call — that path ALSO lazily creates pvt->vrtp with
	 * webrtc_video_accepted==0 && had_vrtp==0, and destroying it would drop m=video from the legacy answer. */
	if (audio_webrtc_offered && pvt->webrtc_video_offered && !pvt->webrtc_video_accepted && !had_vrtp && pvt->vrtp) {
		sofia_rtp_stop_destroy(&pvt->vrtp);	/* stop RTCP/DTLS refs so the vrtp socket actually closes (no leak) */
		staged_video_valid = 0;
	}
	/* Review LOW: if a WebRTC video offer was NOT accepted (no intersection, missing attrs, bundle-only,
	 * wrong proto, or a STEP 5 arm failure that dropped accepted to 0), clear the provisional video bit STEP 3
	 * may have added to pvt->capability, so sofia_new never publishes a video native format with no vrtp behind
	 * it. Gated on audio_webrtc_offered so a plain (non-WebRTC) legacy audio+video call keeps its video. */
	if (audio_webrtc_offered && !pvt->webrtc_video_accepted
			&& !(pvt->webrtc_video_offerer && pvt->webrtc_video_answer_applied)) {	/* Review BLOCKER: do NOT re-strip the offerer's just-narrowed agreed video — Part 3 set capability + webrtc_video_answer_applied, and webrtc_video_accepted is always 0 for the offerer */
		pvt->capability &= ~((format_t)AST_FORMAT_VIDEO_MASK);
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
		/* g2 — real AUTO: dtmfmode=auto resolves per RFC 3264 to RFC2833 when the peer offered
		 * telephone-event on this m=audio, else INBAND. dtmfmode (configured) stays AUTO so a later
		 * re-INVITE re-resolves; dtmf_effective (runtime) drives send/DSP/property via reconfigure. */
		if (pvt->dtmfmode == SOFIA_DTMF_AUTO) {
			pvt->dtmf_effective = audio_te ? SOFIA_DTMF_RFC2833 : SOFIA_DTMF_INBAND;
			sofia_dtmf_reconfigure(pvt);
			sofia_append_history(pvt, "SDP", "dtmf auto -> %s",
				audio_te ? "rfc2833" : "inband");
		}
	}
	if (staged_video_valid && (video_is_bundled || pvt->webrtc_video_bundled) && pvt->rtp) {
		/* BUNDLE (RFC 8843 §9): merge the negotiated video PTs into the AUDIO instance's codec map (one shared
		 * transport). Guard PT-uniqueness FIRST: the engine demux is PT-BASED, so a video PT colliding with a
		 * real audio PT (audio_pt_seen) would OVERWRITE the audio mapping and corrupt audio — drop video instead
		 * ast_rtp_codecs_payloads_copy merges (keeps audio PTs, adds the disjoint video PTs). */
		int cvpt;
		int pt_collision = 0;
		/* Check EVERY payload type the peer listed in m=video (video_pt_seen) against the m=audio PTs
		 * (audio_pt_seen): ast_rtp_codecs_payloads_copy below merges ALL staged video PTs, so a format
		 * carried on multiple PTs (e.g. two H264 profiles) must have each PT checked — not just the one
		 * ast_rtp_codecs_payload_code returns per format bit. */
		for (cvpt = 0; cvpt < 128 && !pt_collision; cvpt++) {
			if (video_pt_seen[cvpt] && audio_pt_seen[cvpt]) {
				pt_collision = 1;
			}
		}
		if (pt_collision) {
			ast_log(LOG_WARNING, "Sofia: WebRTC bundled video PT collides with an audio PT for peer '%s' — dropping video (audio-only); RFC 8843 requires disjoint BUNDLE PTs\n",
				pvt->peer ? pvt->peer->name : "<unknown>");
			pvt->webrtc_video_bundled = 0;
			pvt->webrtc_video_accepted = 0;
			pvt->capability &= ~((format_t)AST_FORMAT_VIDEO_MASK);
		} else {
			/* PT stability (RFC 3264 §8.3.2): keep the already-negotiated video PT across renegotiation. */
			sofia_video_pt_keep_negotiated(&staged_video_codecs,
				ast_rtp_instance_get_codecs(pvt->rtp));
			ast_rtp_codecs_payloads_copy(&staged_video_codecs,
				ast_rtp_instance_get_codecs(pvt->rtp), pvt->rtp);
			pvt->webrtc_video_bundled = 1;	/* arm the flag HERE, past every reject gate */
		}
	} else if (staged_video_valid && pvt->vrtp) {
		/* PT stability (RFC 3264 §8.3.2): same rule on the separate-transport video instance. */
		sofia_video_pt_keep_negotiated(&staged_video_codecs,
			ast_rtp_instance_get_codecs(pvt->vrtp));
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
	if (staged_chosen_audio_valid || t38_stage_fds5 || t38_stage_enter_reinvite || t38_stage_withdraw || t38_stage_local_accept || t38_stage_local_refuse || vrtp_stage_fds23 || audio_webrtc_offered) {	/* + audio_webrtc_offered so the WebRTC nativeformats/fds sync below is never skipped by an unusual parse with no chosen-audio side effect */
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
				if (vrtp_stage_fds23 && pvt->vrtp) {
					/* v1b STEP 8: a re-INVITE lazily created vrtp AFTER sofia_new ran — wire its fds now
					 * (rtcp-mux: fd0 RTP, fd1 RTCP), mirroring sofia_new's initial-INVITE wiring, else
					 * inbound video on vrtp is never polled and the call is one-way/dead. */
					o->fds[2] = ast_rtp_instance_fd(pvt->vrtp, 0);
					o->fds[3] = ast_rtp_instance_fd(pvt->vrtp, 1);
				}
				if (audio_webrtc_offered) {	/* additional Review MED: sync o->nativeformats video to the negotiated pvt->capability for ANY WebRTC leg — publishes the agreed VP8/H264 on accept/offer-apply, and CLEARS a stale video bit when an OFFERED video was rejected (sofia_new exposed it from the pre-answer vrtp) so the bridge never sees phantom video */
					/* Review MED: a re-INVITE that adds video must publish the agreed VP8/H264 into
					 * o->nativeformats (sofia_new published the pre-video capability), else bridge/format
					 * negotiation never learns this leg accepts video. Same owner lock as the fds above. */
					o->nativeformats = (o->nativeformats & ~AST_FORMAT_VIDEO_MASK)
						| (pvt->capability & AST_FORMAT_VIDEO_MASK);
					if (!(pvt->capability & AST_FORMAT_VIDEO_MASK) || pvt->webrtc_video_bundled) {
						/* Residual / BUNDLE: detach the video fds sofia_new wired from the pre-answer vrtp.
						 * Residual = a rejected/withdrawn offerer video left no negotiated video; BUNDLE (RFC
						 * 8843) = video rides pvt->rtp's fds[0]/[1], so the channel must NOT poll a phantom vrtp
						 * on fds[2]/[3] even though video capability stays set. Detach the channel fds ONLY — the
						 * pre-existing vrtp is destroyed at parse-end, never mid-parse (restore/UAF safety). */
						o->fds[2] = -1;
						o->fds[3] = -1;
					}
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
				} else if (t38_stage_local_accept) {
					/* FIX 1b: our outbound T.38 offer was ACCEPTED — the m=image answer
					 * (their_parms + udptl peer + far_max_ifp) is committed above, so go
					 * ENABLED (queues AST_T38_NEGOTIATED → ast_udptl_write opens, sofia_write
					 * gate at chan_sofia.c). Frame AFTER the fds[5] attach. */
					sofia_change_t38_state(pvt, SOFIA_T38_ENABLED);
				} else if (t38_stage_local_refuse) {
					/* FIX 1b: our outbound T.38 offer was DECLINED (no m=image in the
					 * answer) — back to DISABLED (queues AST_T38_REFUSED so res_fax falls
					 * back). chan_sip parity: change_t38_state(T38_DISABLED). */
					sofia_change_t38_state(pvt, SOFIA_T38_DISABLED);
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
		} else if (t38_stage_withdraw || t38_stage_local_refuse) {
			/* No owner: sofia_change_t38_state would NO-OP (it does `chan = pvt->owner; if
			 * (!chan) return;` before writing t38_state), leaving state stale at
			 * PEER_REINVITE / LOCAL_REINVITE. Set DISABLED directly + cancel the t38id
			 * timer. (t38_stage_local_accept needs a channel to go ENABLED; with no owner
			 * the call is tearing down — the destructor cleans up.) */
			pvt->t38_state = SOFIA_T38_DISABLED;
			if (pvt->t38id != -1 && sofia_sched) {
				if (ast_sched_thread_del(sofia_sched, pvt->t38id) == 0) {
					ao2_ref(pvt, -1);
				}
				pvt->t38id = -1;
			}
		}
	}

	/* BUNDLE (RFC 8843): arm/clear the engine BUNDLE prop + MID header extension on pvt->rtp
	 * HERE — past every reject gate (sdp_reject never reaches this), reflecting the FINAL webrtc_video_bundled.
	 * Then destroy the now-unused separate video RTP instance (a bundled leg rides pvt->rtp's one transport)
	 * with sofia_rtp_stop_destroy so the vrtp socket actually closes (the socket-leak fix). */
	if (audio_webrtc_offered) {
		ast_rtp_instance_set_prop(pvt->rtp, AST_RTP_PROPERTY_BUNDLE, pvt->webrtc_video_bundled ? 1 : 0);
		/* echo the negotiated MID extmap id when present; fall back to 4 only when we originate. */
		ast_rtp_instance_set_mid_extension(pvt->rtp,
			pvt->webrtc_video_bundled ? (pvt->webrtc_mid_ext_id > 0 ? pvt->webrtc_mid_ext_id : 4) : 0,
			!ast_strlen_zero(pvt->webrtc_mid) ? pvt->webrtc_mid : "0",
			!ast_strlen_zero(pvt->webrtc_video_mid) ? pvt->webrtc_video_mid : "1");
	}
	if (pvt->webrtc_video_bundled && pvt->vrtp) {
		sofia_rtp_stop_destroy(&pvt->vrtp);	/* leak-safe destroy (stop RTCP/DTLS refs first) */
	}

	/* RFC 3264 §6.1 answer-direction: commit the offered per-media mode now that every reject
	 * gate has passed (a rejected re-INVITE keeps the prior direction, matching the hold_state
	 * deferral). Only overwrite when this offer actually carried that media (-1 = not offered),
	 * so an audio-only re-INVITE does not wipe the video direction of an ongoing A/V call. */
	if (current_offer && offered_audio_mode != -1) {
		pvt->offered_audio_mode = offered_audio_mode;
	}
	if (current_offer && offered_video_mode != -1) {
		pvt->offered_video_mode = offered_video_mode;
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
	pvt->webrtc_video_bundled = orig_webrtc_video_bundled;	/* BUNDLE: a reject must not leave the bundle flag stale */
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
	pvt->webrtc_video_accepted = 0;	/* v1b STEP 10: a rejected SDP accepts no video (the gate ran before the reject gates) */
	/* If pvt->vrtp was LAZILY CREATED this parse (!had_vrtp but now non-NULL), a rejected SDP must
	 * not leave a stray video RTP instance — destroy it (mirrors the SRTP was_new rollback). Placed
	 * AFTER sofia_sdp_stage_rollback above so a was_new vsrtp is torn down first (sofia_srtp_destroy
	 * frees only the srtp/crypto, never derefs pvt->vrtp). The m=video lazy create wires no channel
	 * fd, so destroy + NULL is the complete cleanup. Mutually exclusive with the had_vrtp restore
	 * above (that branch only runs for a PRE-existing vrtp). */
	if (!had_vrtp && pvt->vrtp) {
		sofia_rtp_stop_destroy(&pvt->vrtp);	/* stop RTCP/DTLS refs so the lazy vrtp socket actually closes (no leak) */
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

