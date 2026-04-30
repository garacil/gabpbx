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
 * Copyright (C) 2007, Digium, Inc.
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
 * \author Russell Bryant <russell@digium.com>
 *
 * \brief Usage of the SAForum AIS (Application Interface Specification)
 *
 * \arg http://www.openais.org/
 */

#ifndef RES_AIS_AIS_H
#define RES_AIS_AIS_H

#include <saAis.h>
#include <saClm.h>
#include <saEvt.h>

extern SaVersionT ais_version;

extern SaClmHandleT  clm_handle;
extern SaEvtHandleT  evt_handle;

int ast_ais_clm_load_module(void);
int ast_ais_clm_unload_module(void);

int ast_ais_evt_load_module(void);
int ast_ais_evt_unload_module(void);

const char *ais_err2str(SaAisErrorT error);

void ast_ais_evt_membership_changed(void);

enum ast_ais_cmd {
	AST_AIS_CMD_EXIT,
	AST_AIS_CMD_MEMBERSHIP_CHANGED,
};

int ast_ais_cmd(enum ast_ais_cmd cmd);

#endif /* RES_AIS_AIS_H */
