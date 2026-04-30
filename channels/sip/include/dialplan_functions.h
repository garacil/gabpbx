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
 * Copyright (C) 2010, Digium, Inc.
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
 * \brief SIP dialplan functions header file
 */

#include "sip.h"

#ifndef _SIP_DIALPLAN_FUNCTIONS_H
#define _SIP_DIALPLAN_FUNCTIONS_H

/*!
 * \brief Channel read dialplan function for SIP
 */
int sip_acf_channel_read(struct ast_channel *chan, const char *funcname, char *preparse, char *buf, size_t buflen);

/*!
 * \brief register dialplan function tests
 */
void sip_dialplan_function_register_tests(void);
/*!
 * \brief unregister dialplan function tests
 */
void sip_dialplan_function_unregister_tests(void);

#endif /* !defined(_SIP_DIALPLAN_FUNCTIONS_H) */
