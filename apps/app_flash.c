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
 *
 * \brief App to flash a DAHDI trunk
 *
 * \author Mark Spencer <markster@digium.com>
 * 
 * \ingroup applications
 */
 
/*** MODULEINFO
	<depend>dahdi</depend>
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

GABPBX_FILE_VERSION(__FILE__, "$Revision: 328209 $")

#include <dahdi/user.h>

#include "gabpbx/lock.h"
#include "gabpbx/file.h"
#include "gabpbx/channel.h"
#include "gabpbx/pbx.h"
#include "gabpbx/module.h"
#include "gabpbx/translate.h"
#include "gabpbx/image.h"

/*** DOCUMENTATION
	<application name="Flash" language="en_US">
		<synopsis>
			Flashes a DAHDI Trunk.
		</synopsis>
		<syntax />
		<description>
			<para>Performs a flash on a DAHDI trunk. This can be used to access features
			provided on an incoming analogue circuit such as conference and call waiting.
			Use with SendDTMF() to perform external transfers.</para>
		</description>
		<see-also>
			<ref type="application">SendDTMF</ref>
		</see-also>
	</application>
 ***/

static char *app = "Flash";

static inline int dahdi_wait_event(int fd)
{
	/* Avoid the silly dahdi_waitevent which ignores a bunch of events */
	int i,j=0;
	i = DAHDI_IOMUX_SIGEVENT;
	if (ioctl(fd, DAHDI_IOMUX, &i) == -1) return -1;
	if (ioctl(fd, DAHDI_GETEVENT, &j) == -1) return -1;
	return j;
}

static int flash_exec(struct ast_channel *chan, const char *data)
{
	int res = -1;
	int x;
	struct dahdi_params dahdip;

	if (strcasecmp(chan->tech->type, "DAHDI")) {
		ast_log(LOG_WARNING, "%s is not a DAHDI channel\n", chan->name);
		return -1;
	}
	
	memset(&dahdip, 0, sizeof(dahdip));
	res = ioctl(chan->fds[0], DAHDI_GET_PARAMS, &dahdip);
	if (!res) {
		if (dahdip.sigtype & __DAHDI_SIG_FXS) {
			x = DAHDI_FLASH;
			res = ioctl(chan->fds[0], DAHDI_HOOK, &x);
			if (!res || (errno == EINPROGRESS)) {
				if (res) {
					/* Wait for the event to finish */
					dahdi_wait_event(chan->fds[0]);
				}
				res = ast_safe_sleep(chan, 1000);
				ast_verb(3, "Flashed channel %s\n", chan->name);
			} else
				ast_log(LOG_WARNING, "Unable to flash channel %s: %s\n", chan->name, strerror(errno));
		} else
			ast_log(LOG_WARNING, "%s is not an FXO Channel\n", chan->name);
	} else
		ast_log(LOG_WARNING, "Unable to get parameters of %s: %s\n", chan->name, strerror(errno));

	return res;
}

static int unload_module(void)
{
	return ast_unregister_application(app);
}

static int load_module(void)
{
	return ast_register_application_xml(app, flash_exec);
}

AST_MODULE_INFO_STANDARD(GABPBX_GPL_KEY, "Flash channel application");

