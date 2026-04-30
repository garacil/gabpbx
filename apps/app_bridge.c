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
 * Copyright (C) Germán Aracil Boned
 * contact mail, german@tecnoxarxa.com
 *
 * app_bridge.c for GABPBX 1.4
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

#include <math.h>

GABPBX_FILE_VERSION(__FILE__, "$Revision: 1000 $")

static char *app = "TuBridge";

#define VAR_SIZE 64

struct bridgecall {
	char *context;
	char *exten;
	char *cid_num;
	char *accountcode;
	char *service;
	char *secret;
	char *cli;
	char *language;
	char *cli_out;
	char *cli_id;
	char *credit;
	char *postpaid;
	int  callback;
	char *callbackdst;
	long id;
};

static const char SERVICE_BRIDGE[]   = "bridge";
/* Unused - suppressed for GCC 12 */
/* static const char SERVICE_CALLBACK[] = "callback"; */
static const char SPOOLDIR[]         = "/var/spool/gabpbx/outgoing";

//#if 0
static int hangup(struct ast_channel *chan, void *data)
{
	struct ast_app *app = NULL;
	int ret;

	app = pbx_findapp("Hangup");
	if (app) {
		ret = pbx_exec(chan, app, data);
	} else {
		ast_log(LOG_ERROR, "Could not find application (Hangup)\n");
		ret = -2;
	}

	return ret;
}
//#endif

static int dial(struct ast_channel *chan, void *data)
{
        struct ast_app *app = NULL;
        int ret;

        app = pbx_findapp("Dial");
        if (app) {
                ret = pbx_exec(chan, app, data);
        } else {
                ast_log(LOG_ERROR, "Could not find application (Dial)\n");
                ret = -2;
        }

        return ret;
}

static void bridge_service(struct ast_channel *chan, struct bridgecall *bc)
{
        char number_to_call[AST_MAX_EXTENSION] = "\0";
        char tech[AST_MAX_EXTENSION] = "\0";
        char secret[8] = "\0";
        struct ast_variable *var = NULL;
        int res = 0;
        double int_part;
        char dec_part[64] = "\0";

	ast_answer(chan);
	sleep(1);

        // Have secret for make calls?
        if (bc->secret) {
                ast_answer(chan);
                sleep(1);
                ast_app_getdata(chan, "vm-password", secret, 4, 60000);
                if (!strcmp(secret,bc->secret)) {
                        if (!strstr(secret, bc->secret)) {
				if (option_verbose > 5)
	                                ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] Wrong password\n", chan->cdr->clisrc, chan->cdr->clidst);
                                return;
                        } else {
                                ast_streamfile(chan, "auth-thankyou", bc->language);
				if (option_verbose > 5)
	                                ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] Password ok\n", chan->cdr->clisrc, chan->cdr->clidst);
                        }
                } else {
			if (option_verbose > 5)
	                        ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] Wrong password\n", chan->cdr->clisrc, chan->cdr->clidst);
                        return;

                }
        }

	var = ast_load_realtime("client", "accountcode", bc->accountcode, NULL);
        if (!var) {
                ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] Accountcode %s not exist\n", chan->cdr->clisrc, chan->cdr->clidst, bc->accountcode);
		ast_variables_destroy(var);
                return;
        }

        while (var) {
                if (!strcasecmp(var->name, "credit")) {
                        bc->credit = ast_strdupa(var->value);
                } else if (!strcasecmp(var->name, "postpaid")) {
                        bc->postpaid = ast_strdupa(var->value);
                }
                var = var->next;
        }
        ast_variables_destroy(var);

        if (!strcasecmp(bc->postpaid, "NO")) {
                if (atof(bc->credit) <= 0) {
                        res = ast_streamfile(chan, "not-enough-credit", chan->language);
                        if (!res)
                                res = ast_waitstream(chan, "");
                        ast_softhangup(chan, AST_SOFTHANGUP_SHUTDOWN);
                        return;
                }
        }

	if (!strcasecmp(bc->cli_out, "NO")) {
		if (!ast_strlen_zero(bc->cli_id))
			ast_set_callerid(chan, bc->cli_id, bc->cli_id, bc->cli_id);
		else
			ast_set_callerid(chan, bc->exten, bc->cid_num, bc->cid_num);
	} else
		ast_set_callerid(chan, bc->cid_num, bc->exten, bc->cid_num);

        do {
                do {
                        ast_copy_string(tech, "LOCAL/", sizeof(tech));
			ast_string_field_set(chan, language, bc->language);
                        if (!ast_app_getdata(chan, "vm-enter-num-to-call", number_to_call, AST_MAX_EXTENSION, 60000)) {
                                ast_play_and_wait(chan, "auth-thankyou");
				if (chan && chan->cdr)
	                                ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] Calling to number %s from %s with context %s and accountcode %s\n", chan->cdr->clisrc, chan->cdr->clidst, number_to_call, bc->cli, chan->context, chan->accountcode);
				else
					ast_verbose(VERBOSE_PREFIX_3 "[|] Calling to number %s from %s with context %s and accountcode %s\n", number_to_call, bc->cli, chan->context, chan->accountcode);
                        } else
                                ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] No number from %s for make call\n", chan->cdr->clisrc, chan->cdr->clidst, bc->cid_num);
                } while (strstr(number_to_call, "*"));
		if (!strcmp(number_to_call, "72536")) {
			res = ast_play_and_wait(chan, "vm-youhave");
			res = ast_say_number(chan, atof(bc->credit), AST_DIGIT_ANYNUM, bc->language, NULL);
			if (!res)
				res = ast_waitstream(chan, "");
			res = ast_play_and_wait(chan, "euros");
			sprintf(dec_part, "%2.0f", (modf(atof(bc->credit), &int_part)*100));
			res = ast_say_number(chan, atof(dec_part), AST_DIGIT_ANY, bc->language, NULL);
			if (!res)
				res = ast_waitstream(chan, "");
			res = ast_play_and_wait(chan, "cents");
			if (!res)
				res = ast_waitstream(chan, "");
		} else if (!ast_strlen_zero(number_to_call)) {
	                strcat(tech, number_to_call);
	                strcat(tech, "@");
	                strcat(tech, chan->context);
	                ast_cdr_update(chan);
	                dial(chan, tech);
		}
        } while (!ast_strlen_zero(number_to_call));
        return;
}

static int bridge_exec(struct ast_channel *chan, const char *data)
{
	int res = 0, nodial = 0;
	struct bridgecall *bc;
	struct ast_variable *var = NULL, *tmpvar = NULL;
	int callbackinprogress = 0;
	char *tmp = NULL;
	long callbackid;
	const char *cbid = NULL;
	char *go = NULL;

	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(options);
	);

	if (!ast_strlen_zero(data))
		tmp = ast_strdupa(data);
	AST_STANDARD_APP_ARGS(args, tmp);
	if (args.options) {
		if (strcasestr(args.options, "nodial")) {
			nodial = 1;
		} else if (strcasestr(args.options, "callback")) {
			callbackinprogress = 1;
			ast_channel_lock(chan);
			cbid = pbx_builtin_getvar_helper(chan, "CALLBACKID");
			ast_channel_unlock(chan);
			if (cbid)
			{
				callbackid = atoi(ast_strdupa(cbid));
				ast_verbose(VERBOSE_PREFIX_3 "CALLBACKID:%li\n", callbackid);
			}
		} else if (strcasestr(args.options, "accountcode")) {
			nodial = 1;
			if (chan && chan->cdr)
				ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] Get accountcode by %s@%s\n", chan->cdr->clisrc, chan->cdr->clidst, \
								chan->caller.id.number.str, chan->context);
			else
				ast_verbose(VERBOSE_PREFIX_3 "[|] Get accountcode by %s@%s\n", chan->caller.id.number.str, chan->context);
			var = ast_load_realtime("sippeers", "callerid", chan->caller.id.number.str, "context", chan->context, NULL);
			if (var) {
				tmpvar = var;
				while (var) {
					if (!strcasecmp(var->name, "accountcode")) {
						if (chan && chan->cdr)
							ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] setting to %s\n", chan->cdr->clisrc, \
									chan->cdr->clidst, ast_strdupa(var->value));
						else
							ast_verbose(VERBOSE_PREFIX_3 "[|] Setting to %s\n", ast_strdupa(var->value));
						ast_string_field_set(chan, accountcode, ast_strdupa(var->value));
						break;
					}
					var = var->next;
				}
				ast_variables_destroy(tmpvar);
				
			}
		}
	}

	if (nodial == 0) {
		if (callbackinprogress == 0)
		{
			var = ast_load_realtime("blacklist", "src", \
				chan->caller.id.number.str, "context", chan->context, NULL);
			if (var) {
				go = NULL;
				tmpvar = var;
	                	while (var) {
	                        	if (!strcasecmp(var->name, "go")) {
        	                	        go = ast_strdupa(var->value);
						break;
                        		}
                        		var = var->next;
				}
	                	ast_variables_destroy(tmpvar);
				if (go) {
					ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] Caller Idnum:%s \
						to destination %s\n", chan->cdr->clisrc, \
						chan->cdr->clidst, chan->caller.id.number.str, go);
					ast_explicit_goto(chan, chan->context, go, 1);
					return res;
				} else
					ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] ERROR Caller \
						Idnum:%s without detinstion\n", chan->cdr->clisrc, \
						chan->cdr->clidst, chan->caller.id.number.str);
			} else
				ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] CLI blacklist not found\n", \
					chan->cdr->clisrc, chan->cdr->clidst);

			var = ast_load_realtime("bridge", "context", chan->context, "cid_num", \
				chan->caller.id.number.str, "cli", chan->cdr->dst, NULL);
		} else
			var = ast_load_realtime("bridge", "id", cbid, NULL);

		if (!var) {
			if (option_verbose > 4) {
				if (chan && chan->cdr)
					ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] Caller Idnum:%s and name:%s \
						do not exist for bridge service.\n", chan->cdr->clisrc, \
						chan->cdr->clidst, chan->caller.id.number.str, \
						chan->caller.id.name.str); 
				else
					ast_verbose(VERBOSE_PREFIX_3 "[|] Caller Idnum:%s and name:%s do \
						not exist for bridge service.\n", chan->caller.id.number.str, \
						chan->caller.id.name.str);
			}
			return res;
		}

	        if (!(bc = calloc(1, sizeof(*bc)))) {
			return res;
		}

		tmpvar = var;
	        while (var) {
	 		if (!strcasecmp(var->name, "context")) {
				bc->context  = ast_strdupa(var->value);
	                } else if (!strcasecmp(var->name, "exten"      )) {
				bc->exten    = ast_strdupa(var->value);
			} else if (!strcasecmp(var->name, "cid_num"    )) {
				bc->cid_num  = ast_strdupa(var->value);
			} else if (!strcasecmp(var->name, "accountcode")) {
		       		bc->accountcode = ast_strdupa(var->value);
			} else if (!strcasecmp(var->name, "service"    )) {
				bc->service  = ast_strdupa(var->value);
			} else if (!strcasecmp(var->name, "secret"     )) {
				bc->secret   = ast_strdupa(var->value);
			} else if (!strcasecmp(var->name, "cli"        )) {
				bc->cli      = ast_strdupa(var->value);
			} else if (!strcasecmp(var->name, "language"   )) {
				bc->language = ast_strdupa(var->value);
			} else if (!strcasecmp(var->name, "cli_out"    )) {
				bc->cli_out = ast_strdupa(var->value);
			} else if (!strcasecmp(var->name, "cli_id"     )) {
				bc->cli_id = ast_strdupa(var->value);
			} else if (!strcasecmp(var->name, "callback"   )) {
				bc->callbackdst = ast_strdupa(var->value);
			} else if  (!strcasecmp(var->name, "id"        )) {
                                bc->id = atoi(ast_strdupa(var->value));
                        }
			var = var->next;
	        }

		ast_string_field_set(chan, language   , bc->language   );
		ast_string_field_set(chan, accountcode, bc->accountcode);

		if (option_verbose > 4)
			ast_verbose(VERBOSE_PREFIX_3 "[%s|%s] %s %s with context %s, exten %s, accountcode \
				%s cli %s language %s (%li)\n", chan->cdr->clisrc, chan->cdr->clidst, \
				bc->service, bc->cid_num, bc->context, bc->exten, chan->accountcode, \
				bc->cli, chan->language, bc->id);

		if ((!strcasecmp(SERVICE_BRIDGE, bc->service)) || (callbackinprogress)) {
			ast_channel_lock(chan);
			pbx_builtin_setvar_helper(chan, "CLIBILLING", bc->cid_num);
			ast_channel_unlock(chan);
			bridge_service(chan, bc);
		} else {
			char tospool[256] = "\0";
			char fname[256] = "\0";
			FILE *f;
			if (!bc->callbackdst)
				bc->callbackdst = bc->cid_num;
			sprintf (tospool, "Account:%s\n" \
                                          "Channel:LOCAL/%s@%s\n" \
                                          "Callerid:%s <%s>\n" \
                                          "MaxRetries:1\n" \
                                          "RetryTime:5\n" \
                                          "WaitTime:60\n" \
					  "Set:CALLBACKID=%li\n" \
					  "Set:CLIBILLING=%s\n" \
                                          "Application:TuBridge\n" \
                                          "Data:callback\n" \
                                          ,bc->accountcode, bc->callbackdst, bc->context, \
						bc->cli_id, bc->cli_id, bc->id, bc->cid_num);
			sprintf(fname, "/%s/%s.callback", SPOOLDIR, chan->uniqueid);
			hangup(chan, "17");
			//ast_softhangup(chan, AST_CAUSE_BUSY);
			f = fopen(fname, "w");
			fprintf(f, tospool);
			fclose(f);
			return -1;
		}

		free(bc);
		if (tmpvar)
			ast_variables_destroy(tmpvar);
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
	return ast_register_application_xml(app, bridge_exec);
}

AST_MODULE_INFO(GABPBX_GPL_KEY, AST_MODFLAG_DEFAULT, "GAB Bridge Application",
                .load = load_module,
                .unload = unload_module,
               );

