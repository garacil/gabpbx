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
 * Mark Spencer <markster@digium.com>
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
 * \brief Persistant data storage (akin to *doze registry)
 */

#ifndef _GABPBX_PRIVACY_H
#define _GABPBX_PRIVACY_H

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

#define AST_PRIVACY_DENY	(1 << 0)		/* Don't bother ringing, send to voicemail */
#define AST_PRIVACY_ALLOW   (1 << 1)		/* Pass directly to me */
#define AST_PRIVACY_KILL	(1 << 2)		/* Play anti-telemarketer message and hangup */
#define AST_PRIVACY_TORTURE	(1 << 3)		/* Send directly to tele-torture */
#define AST_PRIVACY_UNKNOWN (1 << 16)

int ast_privacy_check(char *dest, char *cid);

int ast_privacy_set(char *dest, char *cid, int status);

int ast_privacy_reset(char *dest);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* _GABPBX_PRIVACY_H */
