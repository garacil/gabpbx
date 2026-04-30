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
 * Copyright 2021 (C) Germán Aracil Boned
 * contact mail, german@7kas.com
 *
 * app_webrtincoming.c for GABPBX 2.5
 *
*/

#ifdef HAVE_CONFIG_H
#include "confdefs.h"
#endif

#include "gabpbx.h"
#include "gabpbx/module.h"
#include "gabpbx/channel.h"
#include "gabpbx/pbx.h"
#include "gabpbx/lock.h"
#include "gabpbx/app.h"
#include "gabpbx/causes.h"
#include "gabpbx/file.h"
#include "gabpbx/cdr.h"
#include "gabpbx/say.h"
#include "gabpbx/cdr.h"
#include "gabpbx/options.h"
#include "gabpbx/paths.h"

#include <math.h>

GABPBX_FILE_VERSION(__FILE__, "$Revision: 1000 $")

static char *app = "Bot9000";

struct ast_app *goto_app = NULL;
struct ast_app *playback_app = NULL;
struct ast_app *read_app = NULL;
struct ast_app *hangup_app = NULL;
struct ast_app *sipaddheader_app = NULL;
struct ast_app *sipremoveheader_app = NULL;


static int bot9000_gabpbxapp(struct ast_channel *chan, struct ast_app *app, void *data)
{
        int ret;

        if (app)
        {
                ret = pbx_exec(chan, app, data);
        }
        else
        {
                ast_log(LOG_WARNING, "Could not find GABPBX application\n");
                ret = -2;
        }

        return ret;
}

static int bot9000_exec(struct ast_channel *chan, const char *data)
{
	int res = 1;
	struct ast_variable *var = NULL, *vartmp = NULL;
	/* Unused - suppressed for GCC 12 */
	/* struct ast_variable *varb = NULL, *vartmpb = NULL; */
	char *tmp;
	int order = 1;
	const char *dialstatus = NULL;
	char orderstr[256];
	int app = 0;
	char dato[64];
	char text2speech[128];
	/* Unused - suppressed for GCC 12 */
	/*
	int key0 = -1;
	int key1 = -1;
	int key2 = -1;
	int key3 = -1;
	int key4 = -1;
	int key5 = -1;
	int key6 = -1;
	int key7 = -1;
	int key8 = -1;
	int key9 = -1;
	int keyasterisk = -1;
	int keysharp = -1;
	int keynone = -1;
	*/
	int loopifkeynone = -1;
	int readmaxdigits = 1;
	

        sipaddheader_app    = pbx_findapp("SipAddHeader");
        sipremoveheader_app = pbx_findapp("SipRemoveHeader");
        goto_app            = pbx_findapp("Goto");
        playback_app        = pbx_findapp("Playback");
        read_app            = pbx_findapp("Read");
	hangup_app          = pbx_findapp("Hangup");

        AST_DECLARE_APP_ARGS(args,
                AST_APP_ARG(botid);
		AST_APP_ARG(hangup);
        );
	tmp = ast_strdupa(data);
	AST_STANDARD_APP_ARGS(args, tmp);

	if (ast_strlen_zero(args.hangup) && (!ast_strlen_zero(args.botid))) {
		ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] bot9000 Starting (%s)\n", chan->cdr->clisrc, chan->cdr->clidst, args.botid);
		while (1) {
			sprintf(orderstr, "%i", order);
			var = ast_load_realtime("botsdialplan", "botid", args.botid, "priority", orderstr, NULL);
			if (!var)
				break;
			vartmp = var;
			while (var) {
				if (!strcasecmp(var->name, "app")) {
					if (ast_strlen_zero(var->value))
						app = 0;
					else
						app = atoi(var->value);
				} else if (!strcasecmp(var->name, "dato")) {
					ast_copy_string(dato, var->value, sizeof(dato));
				} else if (!strcasecmp(var->name, "text2speech")) {
					ast_copy_string(text2speech, var->value, sizeof(text2speech));
				} else if (!strcasecmp(var->name, "loopifkeynone")) {
					if (ast_strlen_zero(var->value))
						loopifkeynone = -1;
					else
						loopifkeynone = atoi(var->value);
				} else if (!strcasecmp(var->name, "readmaxdigits")) {
					if (ast_strlen_zero(var->value))
						readmaxdigits = 1;
					else
						readmaxdigits = atoi(var->value);
				}
				var = var->next;
			}
			ast_variables_destroy(vartmp);
			char maxreads[256];
			// Execute app
			switch (app) {
				case 0:
					bot9000_gabpbxapp(chan, playback_app, dato);
					if (!ast_strlen_zero(text2speech)) {
						ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] bot9000 text2speech var %s\n", chan->cdr->clisrc, chan->cdr->clidst, text2speech);
						char *t2s = (char *)pbx_builtin_getvar_helper(chan, text2speech);
						ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] bot9000 %s (%s)\n", chan->cdr->clisrc, chan->cdr->clidst, text2speech, t2s);
						
						char *ptr = strtok(t2s, " ");
						char pptr[128];
						while (ptr != NULL) {
							sprintf(pptr, "bot/names/%s", ptr);
							ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] bot9000 %s\n", chan->cdr->clisrc, chan->cdr->clidst, pptr);
							bot9000_gabpbxapp(chan, playback_app, pptr);
							ptr = strtok(NULL, " ");
						}
						text2speech[0] = '\0';
					}
					break;
				case 1:
					sprintf(maxreads, "digits|%s|%i", dato, readmaxdigits);
					bot9000_gabpbxapp(chan, read_app, maxreads);
					break;
				default:
					break;
			}
			order++;
		}
	} else if (chan) {
		dialstatus = pbx_builtin_getvar_helper(chan, "DIALSTATUS");
		if (dialstatus) {
			ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] bot9000 Hangup (%s/%s)\n", chan->cdr->clisrc, chan->cdr->clidst, args.botid, dialstatus);
			ast_update_realtime("botstocall", "number", chan->cdr->clidst, "dialstatus", dialstatus, NULL);
		}
	}

	return res;
}

static int unload_module(void)
{
        int res;

        res = ast_unregister_application(app);

        return res;
}

static int load_module(void)
{
	return ast_register_application_xml(app, bot9000_exec);
}

AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_DEFAULT, "GAB Bot9000 Application",
                .load = load_module,
                .unload = unload_module,
               );

