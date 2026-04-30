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
 * Copyright (C) 2009, Digium, Inc.
 *
 * Joshua Colp <jcolp@digium.com>
 * Andreas 'MacBrody' Brodmann <andreas.brodmann@gmail.com>
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
 * \author Joshua Colp <jcolp@digium.com>
 * \author Andreas 'MacBrody' Broadmann <andreas.brodmann@gmail.com>
 *
 * \brief Multicast RTP Paging Channel
 *
 * \ingroup channel_drivers
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "gabpbx.h"

GABPBX_FILE_VERSION(__FILE__, "$Revision$")

#include <fcntl.h>
#include <sys/signal.h>

#include "gabpbx/lock.h"
#include "gabpbx/channel.h"
#include "gabpbx/config.h"
#include "gabpbx/module.h"
#include "gabpbx/pbx.h"
#include "gabpbx/sched.h"
#include "gabpbx/io.h"
#include "gabpbx/acl.h"
#include "gabpbx/callerid.h"
#include "gabpbx/file.h"
#include "gabpbx/cli.h"
#include "gabpbx/app.h"
#include "gabpbx/rtp_engine.h"
#include "gabpbx/causes.h"

static const char tdesc[] = "Multicast RTP Paging Channel Driver";

/* Forward declarations */
static struct ast_channel *multicast_rtp_request(const char *type, format_t format, const struct ast_channel *requestor, void *data, int *cause);
static int multicast_rtp_call(struct ast_channel *ast, char *dest, int timeout);
static int multicast_rtp_hangup(struct ast_channel *ast);
static struct ast_frame *multicast_rtp_read(struct ast_channel *ast);
static int multicast_rtp_write(struct ast_channel *ast, struct ast_frame *f);

/* Channel driver declaration */
static const struct ast_channel_tech multicast_rtp_tech = {
	.type = "MulticastRTP",
	.description = tdesc,
	.capabilities = -1,
	.requester = multicast_rtp_request,
	.call = multicast_rtp_call,
	.hangup = multicast_rtp_hangup,
	.read = multicast_rtp_read,
	.write = multicast_rtp_write,
};

/*! \brief Function called when we should read a frame from the channel */
static struct ast_frame  *multicast_rtp_read(struct ast_channel *ast)
{
	return &ast_null_frame;
}

/*! \brief Function called when we should write a frame to the channel */
static int multicast_rtp_write(struct ast_channel *ast, struct ast_frame *f)
{
	struct ast_rtp_instance *instance = ast->tech_pvt;

	return ast_rtp_instance_write(instance, f);
}

/*! \brief Function called when we should actually call the destination */
static int multicast_rtp_call(struct ast_channel *ast, char *dest, int timeout)
{
	struct ast_rtp_instance *instance = ast->tech_pvt;

	ast_queue_control(ast, AST_CONTROL_ANSWER);

	return ast_rtp_instance_activate(instance);
}

/*! \brief Function called when we should hang the channel up */
static int multicast_rtp_hangup(struct ast_channel *ast)
{
	struct ast_rtp_instance *instance = ast->tech_pvt;

	ast_rtp_instance_destroy(instance);

	ast->tech_pvt = NULL;

	return 0;
}

/*! \brief Function called when we should prepare to call the destination */
static struct ast_channel *multicast_rtp_request(const char *type, format_t format, const struct ast_channel *requestor, void *data, int *cause)
{
	char *tmp = ast_strdupa(data), *multicast_type = tmp, *destination, *control;
	struct ast_rtp_instance *instance;
	struct ast_sockaddr control_address;
	struct ast_sockaddr destination_address;
	struct ast_channel *chan;
	format_t fmt = ast_best_codec(format);

	ast_sockaddr_setnull(&control_address);

	/* If no type was given we can't do anything */
	if (ast_strlen_zero(multicast_type)) {
		goto failure;
	}

	if (!(destination = strchr(tmp, '/'))) {
		goto failure;
	}
	*destination++ = '\0';

	if ((control = strchr(destination, '/'))) {
		*control++ = '\0';
		if (!ast_sockaddr_parse(&control_address, control,
					PARSE_PORT_REQUIRE)) {
			goto failure;
		}
	}

	if (!ast_sockaddr_parse(&destination_address, destination,
				PARSE_PORT_REQUIRE)) {
		goto failure;
	}

	if (!(instance = ast_rtp_instance_new("multicast", NULL, &control_address, multicast_type))) {
		goto failure;
	}

	if (!(chan = ast_channel_alloc(1, AST_STATE_DOWN, "", "", "", "", "", requestor ? requestor->linkedid : "", 0, "MulticastRTP/%p", instance))) {
		ast_rtp_instance_destroy(instance);
		goto failure;
	}

	ast_rtp_instance_set_remote_address(instance, &destination_address);

	chan->tech = &multicast_rtp_tech;
	chan->nativeformats = fmt;
	chan->writeformat = fmt;
	chan->readformat = fmt;
	chan->rawwriteformat = fmt;
	chan->rawreadformat = fmt;
	chan->tech_pvt = instance;

	return chan;

failure:
	*cause = AST_CAUSE_FAILURE;
	return NULL;
}

/*! \brief Function called when our module is loaded */
static int load_module(void)
{
	if (ast_channel_register(&multicast_rtp_tech)) {
		ast_log(LOG_ERROR, "Unable to register channel class 'MulticastRTP'\n");
		return AST_MODULE_LOAD_DECLINE;
	}

	return AST_MODULE_LOAD_SUCCESS;
}

/*! \brief Function called when our module is unloaded */
static int unload_module(void)
{
	ast_channel_unregister(&multicast_rtp_tech);

	return 0;
}

AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "Multicast RTP Paging Channel",
	.load = load_module,
	.unload = unload_module,
	.load_pri = AST_MODPRI_CHANNEL_DRIVER,
);
