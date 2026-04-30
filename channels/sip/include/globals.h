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
 * \brief sip global declaration header file
 */

#include "sip.h"

#ifndef _SIP_GLOBALS_H
#define _SIP_GLOBALS_H

extern struct ast_sockaddr bindaddr;     /*!< UDP: The address we bind to */
extern struct sched_context *sched;     /*!< The scheduling context */

/*! \brief Definition of this channel for PBX channel registration */
extern const struct ast_channel_tech sip_tech;

/*! \brief This version of the sip channel tech has no send_digit_begin
 * callback so that the core knows that the channel does not want
 * DTMF BEGIN frames.
 * The struct is initialized just before registering the channel driver,
 * and is for use with channels using SIP INFO DTMF.
 */
extern struct ast_channel_tech sip_tech_info;

#endif /* !defined(SIP_GLOBALS_H) */

