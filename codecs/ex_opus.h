/*! \file
 * \brief Opus codec sample frame data
 *
 * Copyright (C) 2025, 7Kas / Tucall VoIP
 *
 * Distributed under the terms of the GNU General Public License
 */

/* A minimal Opus silence frame (20ms, mono, narrowband) */
static uint8_t ex_opus[] = {
	0xf8, 0xff, 0xfe,
};

#define OPUS_SAMPLES 960

static struct ast_frame *opus_sample(void)
{
	static struct ast_frame f = {
		.frametype = AST_FRAME_VOICE,
		.subclass.codec = AST_FORMAT_OPUS,
		.datalen = sizeof(ex_opus),
		.samples = OPUS_SAMPLES,
		.mallocd = 0,
		.offset = 0,
		.src = __PRETTY_FUNCTION__,
		.data.ptr = ex_opus,
	};

	return &f;
}
