/*
 * Copyright (C) 2004-2005 by Objective Systems, Inc.
 *
 * This software is furnished under an open source license and may be 
 * used and copied only in accordance with the terms of this license. 
 * The text of the license may generally be found in the root 
 * directory of this installation in the COPYING file.  It 
 * can also be viewed online at the following URL:
 *
 *   http://www.obj-sys.com/open/license.html
 *
 * Any redistributions of this file including modified versions must 
 * maintain this copyright notice.
 *
 *****************************************************************************/
#ifndef _OO_CHAN_H323_H_
#define _OO_CHAN_H323_H_

#include "gabpbx.h"
#undef PACKAGE_NAME
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#undef PACKAGE_STRING
#undef PACKAGE_BUGREPORT

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/signal.h>

#include "gabpbx/lock.h"
#include "gabpbx/channel.h"
#include "gabpbx/config.h"
#include "gabpbx/logger.h"
#include "gabpbx/module.h"
#include "gabpbx/pbx.h"
#include "gabpbx/utils.h"
#include "gabpbx/options.h"
#include "gabpbx/sched.h"
#include "gabpbx/io.h"
#include "gabpbx/causes.h"
#include "gabpbx/rtp_engine.h"
#include "gabpbx/acl.h"
#include "gabpbx/callerid.h"
#include "gabpbx/file.h"
#include "gabpbx/cli.h"
#include "gabpbx/app.h"
#include "gabpbx/musiconhold.h"
#include "gabpbx/manager.h"
#include "gabpbx/dsp.h"
#include "gabpbx/stringfields.h"
#include "gabpbx/frame_defs.h"
#include "gabpbx/udptl.h"

#include "ootypes.h"
#include "ooUtils.h"
#include "ooCapability.h"
#include "oochannels.h"
#include "ooh323ep.h"
#include "ooh323cDriver.h"
#include "ooCalls.h"
#include "ooq931.h"
#include "ooStackCmds.h"
#include "ooCapability.h"
#include "ooGkClient.h"


struct ooh323_pvt;
struct ooh323_user;
struct ooh323_peer;
/* Helper functions */
struct ooh323_user *find_user(const char * name, const char *ip);
struct ooh323_peer *find_peer(const char * name, int port);
void ooh323_delete_peer(struct ooh323_peer *peer);   

int delete_users(void);
int delete_peers(void);

int ooh323_destroy(struct ooh323_pvt *p);
int reload_config(int reload);
int restart_monitor(void);

int configure_local_rtp(struct ooh323_pvt *p, ooCallData* call);
void setup_rtp_connection(ooCallData *call, const char *remoteIp, 
                          int remotePort);
void close_rtp_connection(ooCallData *call);
struct ast_frame *ooh323_rtp_read
         (struct ast_channel *ast, struct ooh323_pvt *p);

void ooh323_set_write_format(ooCallData *call, int fmt, int txframes);
void ooh323_set_read_format(ooCallData *call, int fmt);

int ooh323_update_capPrefsOrderForCall
   (ooCallData *call, struct ast_codec_pref *prefs);

int ooh323_convertGABpbxCapToH323Cap(format_t cap);

int ooh323_convert_hangupcause_gabpbxToH323(int cause);
int ooh323_convert_hangupcause_h323ToGABpbx(int cause);
int update_our_aliases(ooCallData *call, struct ooh323_pvt *p);

/* h323 msg callbacks */
int ooh323_onReceivedSetup(ooCallData *call, Q931Message *pmsg);
int ooh323_onReceivedDigit(OOH323CallData *call, const char* digit);

void setup_udptl_connection(ooCallData *call, const char *remoteIp, int remotePort);
void close_udptl_connection(ooCallData *call);

EXTERN char *handle_cli_ooh323_reload(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);

#endif
