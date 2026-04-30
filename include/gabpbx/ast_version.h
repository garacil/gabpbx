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
 * Copyright (C) 2008, Digium, Inc.
 *
 * Russell Bryant <russell@digium.com>
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

/*!
 * \file
 * \brief GABpbx version information
 * \author Russell Bryant <russell@digium.com>
 */

#ifndef __AST_VERSION_H
#define __AST_VERSION_H

/*!
 * \brief Retrieve the GABpbx version string.
 */
const char *ast_get_version(void);

/*!
 * \brief Retrieve the numeric GABpbx version
 *
 * Format ABBCC
 * AABB - Major version (1.4 would be 104)
 * CC - Minor version
 *
 * 1.4.17 would be 10417.
 */
const char *ast_get_version_num(void);

#endif /* __AST_VERSION_H */
