/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * GABPBX was first created in 2008 by
 * Germán Luis Aracil Boned <garacilb@gmail.com>.
 *
 * GABPBX as a project is based on Asterisk.
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 *
 * Existing copyright, authorship, Asterisk/Digium notices,
 * third-party notices, and GPL licensing terms are preserved when present.
 *
 * Ogg Opus file format (RFC 7845): native Opus packets in an Ogg container.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Ogg Opus (RFC 7845) file format: stores and plays native Opus packets.
 *
 * The stream is exposed to the core as AST_FORMAT_OPUS frames, the same way
 * format_g729 exposes raw G.729. The codec translators (codec_opus) do any
 * transcoding, so:
 *   - a recording taken on an Opus leg stores the packets exactly as received;
 *   - a file written from any other format goes through slin -> opus once;
 *   - playback to an Opus endpoint is a passthrough; to anything else the core
 *     builds opus -> slin -> X.
 *
 * Container rules implemented (RFC 7845 unless noted):
 *   §3    the ID header sits alone on the BOS page, the comment header
 *             finishes its own page, one Opus packet per Ogg packet, and a
 *             zero-octet audio packet is malformed;
 *   §4    the granule position counts 48 kHz samples of the packets
 *             completed so far and is never advanced by anything but real
 *             packets (§4.1 MUST);
 *   §5.1  OpusHead: version 1, C = 1, pre-skip = codec look-ahead, input rate 0
 *             (unspecified), output gain 0, channel mapping family 0. Readers
 *             accept family 0, and family 1 with a single stream; anything
 *             else is not a passthrough and is rejected;
 *   §5.2  OpusTags with the vendor string plus ENCODER (and COMMENT) tags;
 *   §6    packets above 7,680 octets (N = 1) are treated as invalid;
 *   §8    every header field is bounds-checked before it is read and
 *             nothing is allocated from lengths found in the file;
 *   RFC 3533  the logical stream always ends with an end-of-stream page.
 *
 * Pre-skip (§4.2 / §7): the value written is the codec look-ahead
 * reported by libopus itself through OPUS_GET_LOOKAHEAD at module load (the
 * opus.h documentation asks applications to query it rather than hard-code
 * it). It is exact for packets produced by codec_opus and, for packets that
 * arrived over RTP, the best available estimate of the remote encoder's delay.
 *
 * Documented deviations (all SHOULD-level clauses aimed at encoders/players):
 *   - a non-zero output gain (§5.1) or pre-skip (§4.2) found in a file
 *     cannot be applied to opaque packets: they are logged and the packets are
 *     delivered unchanged;
 *   - gaps in a real-time capture are not repaired with synthetic PLC packets
 *     (§4.1 SHOULD);
 *   - seeking is a linear rescan from the start (§4.6 recommends bisection),
 *     adequate for prompts and call recordings; seeks land on packet boundaries.
 *
 * \arg File name extension: opus
 * \ingroup formats
 */

/*** MODULEINFO
	<depend>ogg</depend>
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

GABPBX_FILE_VERSION(__FILE__, "$Revision: 1 $")

#include <stdint.h>
#include <ogg/ogg.h>
#include <opus/opus.h>

#include "gabpbx/mod_format.h"
#include "gabpbx/module.h"
#include "gabpbx/utils.h"
#include "gabpbx/ast_version.h"

/*! RFC 7845 §6: "A more reasonable limit is (7,664*N - 2) octets"; N = 1 here, rounded up to
 * the 1,024-octet granularity the RFC itself uses for its 61,440 figure. */
#define OPUS_MAX_PACKET		7680
/*! RFC 7845 §5.1: the identification header is 19 octets for channel mapping family 0. */
#define OPUS_HEAD_LEN		19
/*! RFC 7845 §5.1.1: family 1 appends the stream count, the coupled count and one octet per channel. */
#define OPUS_HEAD_FAMILY1_LEN(c)	(OPUS_HEAD_LEN + 2 + (c))
#define OPUS_MAGIC_LEN		8
#define OPUS_MAGIC_HEAD		"OpusHead"
#define OPUS_MAGIC_TAGS		"OpusTags"
/*! RFC 7845 §5.2: the vendor string identifies the encapsulation implementation. */
#define OPUS_VENDOR_STRING	"GabPBX format_ogg_opus"
#define OGG_READ_CHUNK		4096

/*! Pre-skip written in every OpusHead (48 kHz samples), taken from OPUS_GET_LOOKAHEAD at load time. */
static int opus_preskip;

struct ogg_opus_desc {
	ogg_sync_state oy;		/*!< read side: bytes -> pages */
	ogg_stream_state os;		/*!< pages <-> packets, both directions */
	int writing;
	int stream_ready;		/*!< os is initialised (read side: after the BOS page) */
	int serialno;
	int eos;			/*!< read: the EOS page was seen; write: the EOS page was written */
	unsigned int malformed;		/*!< skipped packets, for rate-limited logging */

	/* read side */
	int channels;			/*!< output channel count C from OpusHead */
	int preskip;			/*!< RFC 7845 §4.2, informational in a passthrough */
	ogg_int64_t pos;		/*!< 48 kHz samples delivered so far (tell) */

	/* write side */
	ogg_int64_t granulepos;		/*!< 48 kHz samples in the packets already handed to libogg */
	ogg_int64_t written;		/*!< 48 kHz samples accepted, held-back packet included (tell) */
	ogg_int64_t packetno;
	int tags_done;			/*!< the comment header has been emitted */
	char *comment;			/*!< COMMENT tag, emitted with the (lazy) comment header */
	int pending_len;		/*!< the last accepted packet is held back so it can carry e_o_s */
	int pending_samples;
	unsigned char pending[OPUS_MAX_PACKET];
};

/* RFC 7845 §5.1 / 5.2: multi-octet header fields are little endian. */
static void put_le16(unsigned char *p, unsigned int v)
{
	p[0] = v & 0xff;
	p[1] = (v >> 8) & 0xff;
}

static void put_le32(unsigned char *p, uint32_t v)
{
	p[0] = v & 0xff;
	p[1] = (v >> 8) & 0xff;
	p[2] = (v >> 16) & 0xff;
	p[3] = (v >> 24) & 0xff;
}

static unsigned int get_le16(const unsigned char *p)
{
	return p[0] | (p[1] << 8);
}

static uint32_t get_le32(const unsigned char *p)
{
	return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

/*! \brief Rate-limited report of a skipped packet: a stream must never be aborted by one bad packet. */
static void malformed_warn(struct ogg_opus_desc *d, const char *what, long bytes)
{
	d->malformed++;
	if (d->malformed <= 3 || !(d->malformed % 1000)) {
		ast_log(LOG_WARNING, "Ogg Opus: skipping %s (%ld octets, %u skipped so far)\n",
			what, bytes, d->malformed);
	}
}

/*! \brief Duration of one Opus packet in 48 kHz samples from its TOC sequence (RFC 6716 §3.1), or 0. */
static int packet_samples(const unsigned char *data, long bytes)
{
	struct ast_frame probe;

	if (bytes < 1 || bytes > OPUS_MAX_PACKET) {
		return 0;
	}
	memset(&probe, 0, sizeof(probe));
	probe.frametype = AST_FRAME_VOICE;
	probe.subclass.codec = AST_FORMAT_OPUS;
	probe.data.ptr = (void *) data;
	probe.datalen = bytes;
	return ast_codec_get_samples(&probe);
}

/* ---------------------------------------------------------------- write side */

static int write_page(FILE *f, const ogg_page *og)
{
	if (fwrite(og->header, 1, og->header_len, f) != (size_t) og->header_len
		|| fwrite(og->body, 1, og->body_len, f) != (size_t) og->body_len) {
		ast_log(LOG_WARNING, "Ogg Opus: fwrite() failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/*! \brief Write out every page libogg has ready; with flush set, force the buffered packets out too. */
static int pages_out(struct ogg_opus_desc *d, FILE *f, int flush)
{
	ogg_page og;

	for (;;) {
		int r = flush ? ogg_stream_flush(&d->os, &og) : ogg_stream_pageout(&d->os, &og);
		if (!r) {
			return 0;
		}
		if (write_page(f, &og)) {
			return -1;
		}
	}
}

/*! \brief RFC 7845 §5.2 comment header. Emitted lazily (first packet or close) so that a stream that
 * never receives audio can still end with an EOS page: the flag then travels on this header. */
static int emit_tags(struct ogg_opus_desc *d, FILE *f, int eos)
{
	const char *vendor = OPUS_VENDOR_STRING;
	char encoder[128];
	char *ctag = NULL;
	const char *tags[2];
	size_t taglen[2];
	size_t vlen = strlen(vendor), total, len;
	unsigned int ntags = 0, i;
	unsigned char *buf, *p;
	ogg_packet op;
	int rc;

	snprintf(encoder, sizeof(encoder), "ENCODER=GabPBX %s", ast_get_version());
	tags[ntags] = encoder;
	taglen[ntags++] = strlen(encoder);
	if (!ast_strlen_zero(d->comment)) {
		len = strlen("COMMENT=") + strlen(d->comment) + 1;
		if ((ctag = ast_malloc(len))) {
			snprintf(ctag, len, "COMMENT=%s", d->comment);
			tags[ntags] = ctag;
			taglen[ntags++] = strlen(ctag);
		}
	}

	total = OPUS_MAGIC_LEN + 4 + vlen + 4;
	for (i = 0; i < ntags; i++) {
		total += 4 + taglen[i];
	}
	if (!(buf = ast_malloc(total))) {
		ast_free(ctag);
		return -1;
	}
	p = buf;
	memcpy(p, OPUS_MAGIC_TAGS, OPUS_MAGIC_LEN);
	p += OPUS_MAGIC_LEN;
	put_le32(p, vlen);
	p += 4;
	memcpy(p, vendor, vlen);
	p += vlen;
	put_le32(p, ntags);
	p += 4;
	for (i = 0; i < ntags; i++) {
		put_le32(p, taglen[i]);
		p += 4;
		memcpy(p, tags[i], taglen[i]);
		p += taglen[i];
	}

	memset(&op, 0, sizeof(op));
	op.packet = buf;
	op.bytes = total;
	op.b_o_s = 0;
	op.e_o_s = eos;
	op.granulepos = 0;	/* RFC 7845 §4: zero on the page where the comment header completes */
	op.packetno = d->packetno++;
	rc = ogg_stream_packetin(&d->os, &op);
	ast_free(buf);
	ast_free(ctag);
	if (rc) {
		ast_log(LOG_ERROR, "Ogg Opus: ogg_stream_packetin() failed for the comment header\n");
		return -1;
	}
	d->tags_done = 1;
	/* RFC 7845 §3: however many pages it spans, the comment header finishes the page it completes on. */
	return pages_out(d, f, 1);
}

/*! \brief Hand the held-back packet to libogg; eos marks it as the last packet of the logical stream. */
static int submit_pending(struct ogg_opus_desc *d, FILE *f, int eos)
{
	ogg_packet op;

	memset(&op, 0, sizeof(op));
	op.packet = d->pending;
	op.bytes = d->pending_len;
	op.b_o_s = 0;
	op.e_o_s = eos;
	d->granulepos += d->pending_samples;	/* RFC 7845 §4: samples completed up to and including this packet */
	op.granulepos = d->granulepos;
	op.packetno = d->packetno++;
	d->pending_len = 0;
	d->pending_samples = 0;
	if (ogg_stream_packetin(&d->os, &op)) {
		ast_log(LOG_ERROR, "Ogg Opus: ogg_stream_packetin() failed\n");
		return -1;
	}
	return pages_out(d, f, eos);
}

/*!
 * \brief Prepare a stream for writing: the RFC 7845 §5.1 identification header goes out at once,
 * alone on the beginning-of-stream page (§3).
 */
static int ogg_opus_rewrite(struct ast_filestream *s, const char *comment)
{
	struct ogg_opus_desc *d = s->_private;
	unsigned char head[OPUS_HEAD_LEN];
	ogg_packet op;

	memset(d, 0, sizeof(*d));
	d->writing = 1;
	if (!ast_strlen_zero(comment)) {
		d->comment = ast_strdup(comment);
	}
	d->serialno = (int) ast_random();
	if (ogg_stream_init(&d->os, d->serialno)) {
		ast_log(LOG_ERROR, "Ogg Opus: ogg_stream_init() failed\n");
		return -1;
	}
	d->stream_ready = 1;

	memcpy(head, OPUS_MAGIC_HEAD, OPUS_MAGIC_LEN);
	head[8] = 1;			/* version */
	head[9] = 1;			/* output channel count C: mono; any Opus stream decodes to mono (§5.1.1) */
	put_le16(head + 10, opus_preskip);	/* pre-skip = codec look-ahead (§4.2, §7) */
	put_le32(head + 12, 0);		/* input sample rate: 0 = unspecified (§5.1 point 5) */
	put_le16(head + 16, 0);		/* output gain, Q7.8 dB */
	head[18] = 0;			/* channel mapping family 0: no mapping table (§5.1.1.1) */

	memset(&op, 0, sizeof(op));
	op.packet = head;
	op.bytes = OPUS_HEAD_LEN;
	op.b_o_s = 1;
	op.e_o_s = 0;
	op.granulepos = 0;		/* §4: zero on the ID header page */
	op.packetno = d->packetno++;
	if (ogg_stream_packetin(&d->os, &op)) {
		ast_log(LOG_ERROR, "Ogg Opus: ogg_stream_packetin() failed for the identification header\n");
		return -1;
	}
	return pages_out(d, s->f, 1);
}

static int ogg_opus_write(struct ast_filestream *fs, struct ast_frame *f)
{
	struct ogg_opus_desc *d = fs->_private;
	int samples;

	if (!d->writing) {
		ast_log(LOG_ERROR, "Ogg Opus: this stream is not set up for writing\n");
		return -1;
	}
	if (f->frametype != AST_FRAME_VOICE) {
		ast_log(LOG_WARNING, "Asked to write non-voice frame!\n");
		return -1;
	}
	if (f->subclass.codec != AST_FORMAT_OPUS) {
		ast_log(LOG_WARNING, "Asked to write non-Opus frame (%s)!\n", ast_getformatname(f->subclass.codec));
		return -1;
	}
	/* RFC 6716 §3.4 [R1] and RFC 7845 §6: drop the packet, keep the recording. */
	if (f->datalen < 1 || f->datalen > OPUS_MAX_PACKET) {
		malformed_warn(d, "a packet with an invalid length", f->datalen);
		return 0;
	}
	/* Duration from the TOC, never from f->samples: the RTP reader fills samples at 48 kHz while the
	 * codec_opus encoder fills it in input-rate units. */
	samples = packet_samples(f->data.ptr, f->datalen);
	if (samples <= 0) {
		malformed_warn(d, "a packet with an invalid TOC sequence", f->datalen);
		return 0;
	}
	if (!d->tags_done && emit_tags(d, fs->f, 0)) {
		return -1;
	}
	if (d->pending_len && submit_pending(d, fs->f, 0)) {
		return -1;
	}
	memcpy(d->pending, f->data.ptr, f->datalen);
	d->pending_len = f->datalen;
	d->pending_samples = samples;
	d->written += samples;
	return 0;
}

/* ----------------------------------------------------------------- read side */

/*!
 * \brief Feed the next page of our logical stream to libogg.
 * \retval 1 a page was submitted
 * \retval 0 end of data (EOS page already seen, or end of file on a truncated stream)
 * \retval -1 error
 */
static int next_page(struct ogg_opus_desc *d, FILE *f)
{
	ogg_page og;

	for (;;) {
		int r = ogg_sync_pageout(&d->oy, &og);

		if (r == 1) {
			if (!d->stream_ready) {
				if (!ogg_page_bos(&og)) {
					ast_log(LOG_WARNING, "Ogg Opus: the first page is not a beginning-of-stream page\n");
					return -1;
				}
				d->serialno = ogg_page_serialno(&og);
				if (ogg_stream_init(&d->os, d->serialno)) {
					ast_log(LOG_ERROR, "Ogg Opus: ogg_stream_init() failed\n");
					return -1;
				}
				d->stream_ready = 1;
			} else if (ogg_page_serialno(&og) != d->serialno) {
				/* A grouped logical stream (RFC 3533 §4) or a chained file. An "Ogg Opus file"
				 * carries exactly one Opus stream per segment (RFC 7845 §9); other streams are ignored. */
				ast_debug(2, "Ogg Opus: ignoring a page of logical stream %d\n", ogg_page_serialno(&og));
				continue;
			}
			if (ogg_stream_pagein(&d->os, &og) < 0) {
				ast_debug(1, "Ogg Opus: ogg_stream_pagein() rejected a page\n");
				continue;
			}
			if (ogg_page_eos(&og)) {
				d->eos = 1;
			}
			return 1;
		}
		if (r == -1) {
			ast_debug(1, "Ogg Opus: out of sync, bytes skipped\n");
			continue;
		}
		/* r == 0: the sync layer needs more bytes */
		if (d->eos) {
			return 0;	/* RFC 7845 §3: nothing follows the end-of-stream page */
		}
		{
			char *buf = ogg_sync_buffer(&d->oy, OGG_READ_CHUNK);
			size_t n;

			if (!buf) {
				ast_log(LOG_ERROR, "Ogg Opus: ogg_sync_buffer() failed\n");
				return -1;
			}
			n = fread(buf, 1, OGG_READ_CHUNK, f);
			if (!n) {
				return 0;	/* end of file: a truncated stream without EOS is tolerated (§3) */
			}
			if (ogg_sync_wrote(&d->oy, n)) {
				ast_log(LOG_ERROR, "Ogg Opus: ogg_sync_wrote() failed\n");
				return -1;
			}
		}
	}
}

/*!
 * \brief Next packet of our logical stream. With peek set the packet is not consumed.
 * The packet memory belongs to libogg and is valid only until the next call.
 * \retval 1 packet available in op
 * \retval 0 end of stream
 * \retval -1 error
 */
static int next_packet(struct ogg_opus_desc *d, FILE *f, ogg_packet *op, int peek)
{
	for (;;) {
		if (d->stream_ready) {
			int r = peek ? ogg_stream_packetpeek(&d->os, op) : ogg_stream_packetout(&d->os, op);

			if (r == 1) {
				return 1;
			}
			if (r == -1) {
				ast_debug(1, "Ogg Opus: gap in the packet sequence (page lost)\n");
				continue;
			}
		}
		{
			int p = next_page(d, f);

			if (p <= 0) {
				return p;
			}
		}
	}
}

/*! \brief Validate the RFC 7845 §5.1 identification header. */
static int parse_opus_head(struct ogg_opus_desc *d, const ogg_packet *op)
{
	const unsigned char *p = op->packet;
	unsigned int version, channels, family, streams = 1, coupled = 0, rate;
	int gain;

	if (op->bytes < OPUS_HEAD_LEN || memcmp(p, OPUS_MAGIC_HEAD, OPUS_MAGIC_LEN)) {
		ast_log(LOG_WARNING, "Ogg Opus: not an Ogg Opus stream (no OpusHead identification header)\n");
		return -1;
	}
	version = p[8];
	/* §5.1 point 2: any minor version of major version 0 (values 0..15) is compatible */
	if (version >> 4) {
		ast_log(LOG_WARNING, "Ogg Opus: incompatible encapsulation version %u\n", version);
		return -1;
	}
	channels = p[9];
	if (!channels) {
		ast_log(LOG_WARNING, "Ogg Opus: a channel count of 0 is invalid (RFC 7845 §5.1)\n");
		return -1;
	}
	d->preskip = get_le16(p + 10);
	rate = get_le32(p + 12);
	gain = (int16_t) get_le16(p + 16);
	family = p[18];
	switch (family) {
	case 0:	/* §5.1.1.1: mono or stereo, one stream, no mapping table */
		if (channels > 2) {
			ast_log(LOG_WARNING, "Ogg Opus: channel mapping family 0 allows 1 or 2 channels, not %u\n", channels);
			return -1;
		}
		break;
	case 1:	/* §5.1.1.2: Vorbis channel order, mapping table required (bounds per §8) */
		if (channels > 8 || op->bytes < OPUS_HEAD_FAMILY1_LEN(channels)) {
			ast_log(LOG_WARNING, "Ogg Opus: invalid channel mapping table for family 1 (%u channels, %ld octets)\n",
				channels, (long) op->bytes);
			return -1;
		}
		streams = p[19];
		coupled = p[20];
		if (!streams || coupled > streams) {
			ast_log(LOG_WARNING, "Ogg Opus: invalid stream counts (N=%u, M=%u)\n", streams, coupled);
			return -1;
		}
		break;
	default:	/* §5.1.1.3 / 5.1.1.4: no defined channel meaning */
		ast_log(LOG_WARNING, "Ogg Opus: unsupported channel mapping family %u\n", family);
		return -1;
	}
	if (streams != 1) {
		ast_log(LOG_WARNING, "Ogg Opus: %u Opus streams per Ogg packet; only single-stream files can be passed through as Opus frames\n",
			streams);
		return -1;
	}
	if (gain) {
		ast_log(LOG_NOTICE, "Ogg Opus: the header output gain of %+.2f dB is not applied in a passthrough (RFC 7845 §5.1)\n",
			gain / 256.0);
	}
	d->channels = channels;
	ast_debug(1, "Ogg Opus: version %u, %u channel(s), family %u, pre-skip %d, input rate %u Hz%s\n",
		version, channels, family, d->preskip, rate,
		d->preskip ? " (pre-skip cannot be applied to opaque packets, RFC 7845 §4.2)" : "");
	return 0;
}

/*! \brief Check the RFC 7845 §5.2 comment header for internal consistency (§8) without copying it. */
static int check_opus_tags(const ogg_packet *op)
{
	const unsigned char *p = op->packet;
	uint32_t bytes, vlen, count, i, pos;

	if (op->bytes < OPUS_MAGIC_LEN + 8 || memcmp(p, OPUS_MAGIC_TAGS, OPUS_MAGIC_LEN)) {
		return -1;
	}
	bytes = op->bytes;
	vlen = get_le32(p + OPUS_MAGIC_LEN);
	if (vlen > bytes - OPUS_MAGIC_LEN - 8) {
		return -1;
	}
	pos = OPUS_MAGIC_LEN + 4 + vlen;
	count = get_le32(p + pos);
	pos += 4;
	/* at least four octets per claimed comment must exist before the count is trusted */
	if (count > (bytes - pos) / 4) {
		return -1;
	}
	for (i = 0; i < count; i++) {
		uint32_t len;

		if (pos + 4 > bytes) {
			return -1;
		}
		len = get_le32(p + pos);
		pos += 4;
		if (len > bytes - pos) {
			return -1;
		}
		pos += len;
	}
	return 0;
}

/*! \brief Consume the two mandatory header packets (RFC 7845 §3); validate them on the first pass only. */
static int read_headers(struct ogg_opus_desc *d, FILE *f, int validate)
{
	ogg_packet op;

	if (next_packet(d, f, &op, 0) != 1) {
		if (validate) {
			ast_log(LOG_WARNING, "Ogg Opus: no identification header found\n");
		}
		return -1;
	}
	if (validate && parse_opus_head(d, &op)) {
		return -1;
	}
	if (next_packet(d, f, &op, 0) != 1) {
		ast_log(LOG_WARNING, "Ogg Opus: no comment header found\n");
		return -1;
	}
	if (validate && check_opus_tags(&op)) {
		ast_log(LOG_WARNING, "Ogg Opus: malformed comment header\n");
		return -1;
	}
	return 0;
}

static int ogg_opus_open(struct ast_filestream *s)
{
	struct ogg_opus_desc *d = s->_private;

	memset(d, 0, sizeof(*d));
	ogg_sync_init(&d->oy);
	/* On failure the core calls close() on this descriptor, which releases the libogg state. */
	return read_headers(d, s->f, 1);
}

static struct ast_frame *ogg_opus_read(struct ast_filestream *s, int *whennext)
{
	struct ogg_opus_desc *d = s->_private;
	ogg_packet op;
	int samples;

	if (d->writing) {
		ast_log(LOG_WARNING, "Ogg Opus: reading is not supported on a stream opened for writing\n");
		return NULL;
	}
	for (;;) {
		if (next_packet(d, s->f, &op, 0) != 1) {
			return NULL;
		}
		/* RFC 7845 §3: a zero-octet audio packet is malformed; §6: oversize packets are invalid. */
		if (op.bytes < 1 || op.bytes > OPUS_MAX_PACKET) {
			malformed_warn(d, "an audio packet with an invalid length", op.bytes);
			continue;
		}
		samples = packet_samples(op.packet, op.bytes);
		if (samples <= 0) {
			malformed_warn(d, "an audio packet with an invalid TOC sequence", op.bytes);
			continue;
		}
		s->fr.frametype = AST_FRAME_VOICE;
		s->fr.subclass.codec = AST_FORMAT_OPUS;
		s->fr.mallocd = 0;
		AST_FRAME_SET_BUFFER(&s->fr, s->buf, AST_FRIENDLY_OFFSET, op.bytes);
		memcpy(s->fr.data.ptr, op.packet, op.bytes);
		/* 48 kHz units: the playback scheduler divides by ast_format_rate(AST_FORMAT_OPUS) = 48000 */
		s->fr.samples = samples;
		*whennext = samples;
		d->pos += samples;
		return &s->fr;
	}
}

/*! \brief Back to the first audio packet: rewind the file and re-read the (already validated) headers. */
static int rewind_stream(struct ogg_opus_desc *d, FILE *f)
{
	if (fseeko(f, 0, SEEK_SET)) {
		ast_log(LOG_WARNING, "Ogg Opus: unable to rewind: %s\n", strerror(errno));
		return -1;
	}
	ogg_sync_reset(&d->oy);
	if (d->stream_ready) {
		ogg_stream_reset_serialno(&d->os, d->serialno);
	}
	d->eos = 0;
	d->pos = 0;
	return read_headers(d, f, 0);
}

/*!
 * \brief Consume whole packets while they fit before target (48 kHz samples); target < 0 consumes all.
 * \return the position reached, or -1 on error
 */
static ogg_int64_t advance_to(struct ogg_opus_desc *d, FILE *f, ogg_int64_t target)
{
	ogg_packet op;

	for (;;) {
		int r = next_packet(d, f, &op, 1);
		int samples;

		if (r < 0) {
			return -1;
		}
		if (r == 0) {
			return d->pos;
		}
		samples = packet_samples(op.packet, op.bytes);
		if (samples > 0 && target >= 0 && d->pos + samples > target) {
			return d->pos;	/* the next packet would overshoot: stay in front of it */
		}
		if (ogg_stream_packetout(&d->os, &op) != 1) {
			return -1;
		}
		if (samples > 0) {
			d->pos += samples;
		}
	}
}

static int ogg_opus_seek(struct ast_filestream *fs, off_t sample_offset, int whence)
{
	struct ogg_opus_desc *d = fs->_private;
	ogg_int64_t target;

	if (d->writing) {
		/* ast_writefile() seeks every new output stream to its end, which is where an Ogg writer already is. */
		if (whence == SEEK_END && sample_offset == 0) {
			return 0;
		}
		ast_debug(1, "Ogg Opus: seeking is not supported on a stream opened for writing\n");
		return -1;
	}
	switch (whence) {
	case SEEK_SET:
		target = sample_offset;
		break;
	case SEEK_CUR:
	case SEEK_FORCECUR:
		target = d->pos + sample_offset;
		break;
	case SEEK_END:
	{
		ogg_int64_t total = advance_to(d, fs->f, -1);

		if (total < 0) {
			return -1;
		}
		target = total - sample_offset;
		break;
	}
	default:
		ast_log(LOG_WARNING, "Ogg Opus: unknown whence %d\n", whence);
		return -1;
	}
	if (target < 0) {
		target = 0;
	}
	if (target < d->pos && rewind_stream(d, fs->f)) {
		return -1;
	}
	return advance_to(d, fs->f, target) < 0 ? -1 : 0;
}

static int ogg_opus_trunc(struct ast_filestream *fs)
{
	ast_debug(1, "Ogg Opus: truncation is not supported on Ogg streams\n");
	return -1;
}

static off_t ogg_opus_tell(struct ast_filestream *fs)
{
	struct ogg_opus_desc *d = fs->_private;

	return (off_t) (d->writing ? d->written : d->pos);
}

static void ogg_opus_close(struct ast_filestream *fs)
{
	struct ogg_opus_desc *d = fs->_private;

	if (d->writing) {
		if (d->stream_ready && !d->eos) {
			/* RFC 3533 / RFC 7845 §3: the logical stream ends with an EOS page. Without audio the flag
			 * travels on the comment header page; otherwise on the held-back last packet. */
			if (!d->tags_done) {
				emit_tags(d, fs->f, d->pending_len ? 0 : 1);
			}
			if (d->pending_len) {
				submit_pending(d, fs->f, 1);
			}
			pages_out(d, fs->f, 1);
			d->eos = 1;
		}
		if (d->stream_ready) {
			ogg_stream_clear(&d->os);
			d->stream_ready = 0;
		}
		ast_free(d->comment);
		d->comment = NULL;
	} else {
		if (d->stream_ready) {
			ogg_stream_clear(&d->os);
			d->stream_ready = 0;
		}
		ogg_sync_clear(&d->oy);
	}
}

static const struct ast_format ogg_opus_f = {
	.name = "ogg_opus",
	.exts = "opus",		/* RFC 7845 §9: the RECOMMENDED extension for Ogg Opus files */
	.format = AST_FORMAT_OPUS,
	.open = ogg_opus_open,
	.rewrite = ogg_opus_rewrite,
	.write = ogg_opus_write,
	.seek = ogg_opus_seek,
	.trunc = ogg_opus_trunc,
	.tell = ogg_opus_tell,
	.read = ogg_opus_read,
	.close = ogg_opus_close,
	.buf_size = OPUS_MAX_PACKET + AST_FRIENDLY_OFFSET,
	.desc_size = sizeof(struct ogg_opus_desc),
};

/*! \brief Ask libopus for the codec delay (RFC 7845 §7: pre-skip = delay_samples). Queried, not
 * hard-coded, as opus.h requires: "the encoder portion of the delay may vary from implementation to
 * implementation, version to version, or even depend on the encoder's initial configuration". */
static int query_preskip(void)
{
	int err = OPUS_OK;
	opus_int32 lookahead = 0;
	OpusEncoder *enc = opus_encoder_create(48000, 1, OPUS_APPLICATION_VOIP, &err);

	if (!enc || err != OPUS_OK) {
		ast_log(LOG_WARNING, "Ogg Opus: cannot create a reference encoder to query the look-ahead (%s); pre-skip 0\n",
			opus_strerror(err));
		return 0;
	}
	if (opus_encoder_ctl(enc, OPUS_GET_LOOKAHEAD(&lookahead)) != OPUS_OK || lookahead < 0 || lookahead > 65535) {
		lookahead = 0;
	}
	opus_encoder_destroy(enc);
	return lookahead;
}

static int load_module(void)
{
	opus_preskip = query_preskip();
	ast_verb(2, "Ogg Opus: pre-skip %d samples (%s look-ahead)\n", opus_preskip, opus_get_version_string());
	if (ast_format_register(&ogg_opus_f)) {
		return AST_MODULE_LOAD_FAILURE;
	}
	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	return ast_format_unregister(ogg_opus_f.name);
}

AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "Ogg Opus audio (RFC 7845)",
	.load = load_module,
	.unload = unload_module,
	.load_pri = AST_MODPRI_APP_DEPEND
);
