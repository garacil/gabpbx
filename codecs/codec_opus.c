/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * GABPBX was first created in 2008 by
 * Germán Luis Aracil Boned <garacilb@gmail.com>.
 *
 * GABPBX as a project is based on Asterisk 1.8 and was later updated
 * to the final stable Asterisk 1.8 release.
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 *
 * Existing copyright, authorship, Asterisk/Digium notices,
 * third-party notices, and GPL licensing terms are preserved when present.
 *
 * Copyright (C) 2025, 7Kas / Tucall VoIP
 *
 * Based on codec_speex.c by Mark Spencer and
 * codec_opus_open_source.c by Lorenzo Miniero
 *
 * See http://www.gabpbx.org for more information about
 * the GABPBX project.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Translate between signed linear and Opus (RFC 7587)
 *
 * \ingroup codecs
 *
 * \extref The Opus library - http://www.opus-codec.org
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

GABPBX_FILE_VERSION(__FILE__, "$Revision: 1 $")

#include <opus/opus.h>

#include "gabpbx/translate.h"
#include "gabpbx/module.h"
#include "gabpbx/config.h"
#include "gabpbx/utils.h"
#include "gabpbx/cli.h"

/* Opus defaults for VoIP use */
#define OPUS_DEFAULT_BITRATE       32000
#define OPUS_DEFAULT_FEC           1
#define OPUS_DEFAULT_DTX           0
#define OPUS_DEFAULT_CHANNELS      1
#define OPUS_DEFAULT_APPLICATION   OPUS_APPLICATION_VOIP

/*
 * Opus operates natively at 48kHz. GabPBX 2.5 primarily uses 8kHz (slinear)
 * and 16kHz (slinear16). The encoder/decoder handle internal resampling:
 *   - Encoder: accepts 8kHz input, internally upsamples to 48kHz for encoding
 *   - Decoder: decodes at requested rate (8kHz or 16kHz)
 * This is handled by libopus transparently.
 */

#define BUFFER_SAMPLES  8000
#define OPUS_FRAME_MS   20

/* Encoder frame sizes at different sample rates */
#define OPUS_FRAME_8K   160   /* 20ms at 8kHz */
#define OPUS_FRAME_16K  320   /* 20ms at 16kHz */

/* Maximum encoded packet size */
#define OPUS_MAX_ENCODED  4000

/* Sample frame data */
#include "gabpbx/slin.h"
#include "ex_opus.h"

/* Codec configuration */
static int opus_bitrate = OPUS_DEFAULT_BITRATE;
static int opus_fec = OPUS_DEFAULT_FEC;
static int opus_dtx = OPUS_DEFAULT_DTX;

/* Usage tracking */
static int encoder_count = 0;
static int decoder_count = 0;

struct opus_coder_pvt {
	void *opus;             /* OpusEncoder or OpusDecoder */
	int sampling_rate;
	int frame_size;         /* samples per frame at working rate */
	int16_t buf[BUFFER_SAMPLES];
};

/* ---- Encoder ---- */

static int opus_enc_new(struct ast_trans_pvt *pvt, int sampling_rate)
{
	struct opus_coder_pvt *opvt = pvt->pvt;
	int status;

	opvt->sampling_rate = sampling_rate;
	opvt->frame_size = sampling_rate * OPUS_FRAME_MS / 1000;

	opvt->opus = opus_encoder_create(sampling_rate, OPUS_DEFAULT_CHANNELS,
		OPUS_DEFAULT_APPLICATION, &status);

	if (status != OPUS_OK) {
		ast_log(LOG_ERROR, "Error creating Opus encoder at %dHz: %s\n",
			sampling_rate, opus_strerror(status));
		return -1;
	}

	/* Limit bandwidth based on input sample rate */
	if (sampling_rate <= 8000) {
		opus_encoder_ctl(opvt->opus, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_NARROWBAND));
	} else if (sampling_rate <= 16000) {
		opus_encoder_ctl(opvt->opus, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_WIDEBAND));
	}

	opus_encoder_ctl(opvt->opus, OPUS_SET_BITRATE(opus_bitrate));
	opus_encoder_ctl(opvt->opus, OPUS_SET_INBAND_FEC(opus_fec));
	opus_encoder_ctl(opvt->opus, OPUS_SET_DTX(opus_dtx));

	ast_atomic_fetchadd_int(&encoder_count, 1);
	ast_debug(3, "Created Opus encoder (%dHz -> opus)\n", sampling_rate);

	return 0;
}

static int lintoop_new(struct ast_trans_pvt *pvt)
{
	return opus_enc_new(pvt, 8000);
}

static int lin16toop_new(struct ast_trans_pvt *pvt)
{
	return opus_enc_new(pvt, 16000);
}

static int lintoop_framein(struct ast_trans_pvt *pvt, struct ast_frame *f)
{
	struct opus_coder_pvt *opvt = pvt->pvt;

	if (pvt->samples + f->samples > BUFFER_SAMPLES) {
		ast_log(LOG_WARNING, "Opus encoder buffer overflow\n");
		return -1;
	}

	memcpy(opvt->buf + pvt->samples, f->data.ptr, f->datalen);
	pvt->samples += f->samples;

	return 0;
}

static struct ast_frame *lintoop_frameout(struct ast_trans_pvt *pvt)
{
	struct opus_coder_pvt *opvt = pvt->pvt;
	int samples = 0;
	int datalen;

	if (pvt->samples < opvt->frame_size) {
		return NULL;
	}

	while (pvt->samples >= opvt->frame_size) {
		datalen = opus_encode(opvt->opus,
			opvt->buf + samples,
			opvt->frame_size,
			pvt->outbuf.uc,
			pvt->t->buf_size);

		samples += opvt->frame_size;
		pvt->samples -= opvt->frame_size;

		if (datalen < 0) {
			ast_log(LOG_ERROR, "Opus encode error: %s\n", opus_strerror(datalen));
			return NULL;
		}
	}

	/* Move leftover samples to front */
	if (pvt->samples) {
		memmove(opvt->buf, opvt->buf + samples, pvt->samples * 2);
	}

	return ast_trans_frameout(pvt, datalen, samples);
}

static void lintoop_destroy(struct ast_trans_pvt *arg)
{
	struct opus_coder_pvt *opvt = arg->pvt;

	if (opvt && opvt->opus) {
		opus_encoder_destroy(opvt->opus);
		opvt->opus = NULL;
		ast_atomic_fetchadd_int(&encoder_count, -1);
	}
}

/* ---- Decoder ---- */

static int optolin_new(struct ast_trans_pvt *pvt, int sampling_rate)
{
	struct opus_coder_pvt *opvt = pvt->pvt;
	int status;

	opvt->sampling_rate = sampling_rate;
	opvt->frame_size = sampling_rate * OPUS_FRAME_MS / 1000;

	opvt->opus = opus_decoder_create(sampling_rate, OPUS_DEFAULT_CHANNELS, &status);

	if (status != OPUS_OK) {
		ast_log(LOG_ERROR, "Error creating Opus decoder at %dHz: %s\n",
			sampling_rate, opus_strerror(status));
		return -1;
	}

	ast_atomic_fetchadd_int(&decoder_count, 1);
	ast_debug(3, "Created Opus decoder (opus -> %dHz)\n", sampling_rate);

	return 0;
}

static int optolin_new8(struct ast_trans_pvt *pvt)
{
	return optolin_new(pvt, 8000);
}

static int optolin_new16(struct ast_trans_pvt *pvt)
{
	return optolin_new(pvt, 16000);
}

static int optolin_framein(struct ast_trans_pvt *pvt, struct ast_frame *f)
{
	struct opus_coder_pvt *opvt = pvt->pvt;
	int16_t *dst = pvt->outbuf.i16;
	int status;
	int frame_size;

	if (f->datalen == 0) {
		/* Packet loss - use PLC */
		frame_size = opvt->frame_size;
		if (pvt->samples + frame_size > BUFFER_SAMPLES) {
			ast_log(LOG_WARNING, "Opus decoder buffer overflow on PLC\n");
			return -1;
		}
		status = opus_decode(opvt->opus, NULL, 0,
			dst + pvt->samples, frame_size, 0);
	} else {
		/* Normal decode */
		frame_size = BUFFER_SAMPLES - pvt->samples;
		if (frame_size <= 0) {
			ast_log(LOG_WARNING, "Opus decoder buffer full\n");
			return -1;
		}
		status = opus_decode(opvt->opus, f->data.ptr, f->datalen,
			dst + pvt->samples, frame_size, 0);
	}

	if (status < 0) {
		ast_log(LOG_ERROR, "Opus decode error: %s\n", opus_strerror(status));
		return -1;
	}

	pvt->samples += status;
	pvt->datalen += status * sizeof(int16_t);

	return 0;
}

static void optolin_destroy(struct ast_trans_pvt *arg)
{
	struct opus_coder_pvt *opvt = arg->pvt;

	if (opvt && opvt->opus) {
		opus_decoder_destroy(opvt->opus);
		opvt->opus = NULL;
		ast_atomic_fetchadd_int(&decoder_count, -1);
	}
}

/* ---- Translator definitions ---- */

/* Opus <-> slinear (8kHz) */
static struct ast_translator opustolin = {
	.name = "opustolin",
	.srcfmt = AST_FORMAT_OPUS,
	.dstfmt = AST_FORMAT_SLINEAR,
	.newpvt = optolin_new8,
	.framein = optolin_framein,
	.destroy = optolin_destroy,
	.sample = opus_sample,
	.desc_size = sizeof(struct opus_coder_pvt),
	.buffer_samples = BUFFER_SAMPLES,
	.buf_size = BUFFER_SAMPLES * 2,
	.native_plc = 1,
};

static struct ast_translator lintoopus = {
	.name = "lintoopus",
	.srcfmt = AST_FORMAT_SLINEAR,
	.dstfmt = AST_FORMAT_OPUS,
	.newpvt = lintoop_new,
	.framein = lintoop_framein,
	.frameout = lintoop_frameout,
	.destroy = lintoop_destroy,
	.sample = slin8_sample,
	.desc_size = sizeof(struct opus_coder_pvt),
	.buffer_samples = BUFFER_SAMPLES,
	.buf_size = OPUS_MAX_ENCODED,
};

/* Opus <-> slinear16 (16kHz) */
static struct ast_translator opustolin16 = {
	.name = "opustolin16",
	.srcfmt = AST_FORMAT_OPUS,
	.dstfmt = AST_FORMAT_SLINEAR16,
	.newpvt = optolin_new16,
	.framein = optolin_framein,
	.destroy = optolin_destroy,
	.sample = opus_sample,
	.desc_size = sizeof(struct opus_coder_pvt),
	.buffer_samples = BUFFER_SAMPLES,
	.buf_size = BUFFER_SAMPLES * 2,
	.native_plc = 1,
};

static struct ast_translator lin16toopus = {
	.name = "lin16toopus",
	.srcfmt = AST_FORMAT_SLINEAR16,
	.dstfmt = AST_FORMAT_OPUS,
	.newpvt = lin16toop_new,
	.framein = lintoop_framein,
	.frameout = lintoop_frameout,
	.destroy = lintoop_destroy,
	.sample = slin16_sample,
	.desc_size = sizeof(struct opus_coder_pvt),
	.buffer_samples = BUFFER_SAMPLES,
	.buf_size = OPUS_MAX_ENCODED,
};

/* ---- Configuration ---- */

static int parse_config(int reload)
{
	struct ast_flags config_flags = { reload ? CONFIG_FLAG_FILEUNCHANGED : 0 };
	struct ast_config *cfg = ast_config_load("codecs.conf", config_flags);
	struct ast_variable *var;
	int res;

	if (cfg == CONFIG_STATUS_FILEMISSING || cfg == CONFIG_STATUS_FILEUNCHANGED || cfg == CONFIG_STATUS_FILEINVALID) {
		return 0;
	}

	for (var = ast_variable_browse(cfg, "opus"); var; var = var->next) {
		if (!strcasecmp(var->name, "bitrate")) {
			res = atoi(var->value);
			if (res >= 6000 && res <= 510000) {
				ast_verb(3, "CODEC OPUS: Setting bitrate to %d bps\n", res);
				opus_bitrate = res;
			} else {
				ast_log(LOG_ERROR, "CODEC OPUS: Bitrate must be 6000-510000\n");
			}
		} else if (!strcasecmp(var->name, "fec")) {
			opus_fec = ast_true(var->value) ? 1 : 0;
			ast_verb(3, "CODEC OPUS: FEC %s\n", opus_fec ? "enabled" : "disabled");
		} else if (!strcasecmp(var->name, "dtx")) {
			opus_dtx = ast_true(var->value) ? 1 : 0;
			ast_verb(3, "CODEC OPUS: DTX %s\n", opus_dtx ? "enabled" : "disabled");
		}
	}

	ast_config_destroy(cfg);
	return 0;
}

/* ---- CLI command ---- */

static char *handle_cli_opus_show(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	switch (cmd) {
	case CLI_INIT:
		e->command = "opus show";
		e->usage =
			"Usage: opus show\n"
			"       Displays Opus codec utilization and settings.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 2) {
		return CLI_SHOWUSAGE;
	}

	ast_cli(a->fd, "Opus codec settings:\n");
	ast_cli(a->fd, "  Bitrate:    %d bps\n", opus_bitrate);
	ast_cli(a->fd, "  FEC:        %s\n", opus_fec ? "enabled" : "disabled");
	ast_cli(a->fd, "  DTX:        %s\n", opus_dtx ? "enabled" : "disabled");
	ast_cli(a->fd, "  Encoders:   %d active\n", encoder_count);
	ast_cli(a->fd, "  Decoders:   %d active\n", decoder_count);

	return CLI_SUCCESS;
}

static struct ast_cli_entry cli_opus[] = {
	AST_CLI_DEFINE(handle_cli_opus_show, "Display Opus codec utilization and settings"),
};

/* ---- Module lifecycle ---- */

static int reload(void)
{
	if (parse_config(1)) {
		return AST_MODULE_LOAD_DECLINE;
	}
	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	int res = 0;

	res |= ast_unregister_translator(&opustolin);
	res |= ast_unregister_translator(&lintoopus);
	res |= ast_unregister_translator(&opustolin16);
	res |= ast_unregister_translator(&lin16toopus);

	ast_cli_unregister_multiple(cli_opus, ARRAY_LEN(cli_opus));

	return res;
}

static int load_module(void)
{
	int res = 0;

	if (parse_config(0)) {
		return AST_MODULE_LOAD_DECLINE;
	}

	res |= ast_register_translator(&opustolin);
	res |= ast_register_translator(&lintoopus);
	res |= ast_register_translator(&opustolin16);
	res |= ast_register_translator(&lin16toopus);

	ast_cli_register_multiple(cli_opus, ARRAY_LEN(cli_opus));

	ast_verb(2, "Opus codec loaded (libopus %s)\n", opus_get_version_string());

	return res;
}

AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_DEFAULT, "Opus Coder/Decoder",
	.load = load_module,
	.unload = unload_module,
	.reload = reload,
);
