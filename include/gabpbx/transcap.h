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
 * Copyright (C) 1999 - 2005, Digium, Inc.
 *
 * Matthew Fredrickson <creslin@digium.com>
 *
 * See http://www.gabpbx.org for more information about
 * the GABPBX project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 * \brief General GABpbx channel transcoding definitions.
 */

#ifndef _GABPBX_TRANSCAP_H
#define _GABPBX_TRANSCAP_H

/* These definitions are taken directly out of libpri.h and used here.
 * DO NOT change them as it will cause unexpected behavior in channels
 * that utilize these fields.
 */

/*! \name AstTranscode General GABpbx channel transcoding definitions.
*/
/*@{ */
#define AST_TRANS_CAP_SPEECH				0x0
#define AST_TRANS_CAP_DIGITAL				0x08
#define AST_TRANS_CAP_RESTRICTED_DIGITAL		0x09
#define AST_TRANS_CAP_3_1K_AUDIO			0x10
#define AST_TRANS_CAP_7K_AUDIO				0x11	/* Depriciated ITU Q.931 (05/1998)*/
#define AST_TRANS_CAP_DIGITAL_W_TONES			0x11
#define AST_TRANS_CAP_VIDEO				0x18
/*@} */

#define IS_DIGITAL(cap)\
	(cap) & AST_TRANS_CAP_DIGITAL ? 1 : 0

#endif /* _GABPBX_TRANSCAP_H */
