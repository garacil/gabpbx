/*
 * GABPBX -- Germán Aracil Boned PBX.
 *
 * Copyright (C) 2008 - present, Germán Luis Aracil Boned <garacilb@gmail.com>
 *
 * Copyleft: GABPBX is free software, distributed under the terms of
 * the GNU General Public License Version 2.
 */

/*! \file sofia_blacklist.c
 * \brief chan_sofia local anti-abuse SIP blacklist (split from chan_sofia.c).
 */

#include "gabpbx.h"
#include "gabpbx/astobj2.h"
#include "gabpbx/cli.h"
#include "gabpbx/lock.h"
#include "gabpbx/utils.h"
#include "gabpbx/netsock2.h"
#include "gabpbx/logger.h"

#include <sofia-sip/sip.h>
#include <sofia-sip/sip_header.h>

#include "include/chan_sofia_internal.h"
#include "include/sofia_blacklist.h"

#define SOFIA_BLACKLIST_BUCKETS 4093	/* prime (~4x the former 1024); prime also drops the only
					 * power-of-2 table, so bucket distribution is robust for any hash. */
#define SOFIA_BLACKLIST_MAX_DEFAULT 1024
#define SOFIA_BLACKLIST_COUNT_DEFAULT 5
#define SOFIA_BLACKLIST_TTL_DEFAULT 86400 /* 24h: a blocked IP stays banned 24h after its last failure, and
                                           * an accumulating counter is forgiven after 24h of inactivity
                                           * (fail2ban model). 0 = never decay/expire. */

struct sofia_blacklist_entry {
	char ip[80];
	int counter;
	time_t first_seen;
	time_t last_seen;
};

static struct ao2_container *sofia_blacklist;
struct ao2_container *sofia_blacklist_container(void) { return sofia_blacklist; }
static int sofia_blacklist_max = SOFIA_BLACKLIST_MAX_DEFAULT;
static int sofia_blacklist_count = SOFIA_BLACKLIST_COUNT_DEFAULT;
static int sofia_blacklist_ttl = SOFIA_BLACKLIST_TTL_DEFAULT;
static int sofia_blacklist_enabled = 1;   /* blacklist_ban=0 turns banning OFF entirely */
AST_MUTEX_DEFINE_STATIC(sofia_blacklist_lock);
/* ao2 hash: case-insensitive on the IP string. */
static int sofia_blacklist_hash_fn(const void *obj, int flags)
{
	const struct sofia_blacklist_entry *entry = obj;

	return ast_str_case_hash(entry->ip);
}
/* ao2 cmp: match by IP, case-insensitive. */
static int sofia_blacklist_cmp_fn(void *obj, void *arg, int flags)
{
	struct sofia_blacklist_entry *entry = obj;
	struct sofia_blacklist_entry *match = arg;

	return !strcasecmp(entry->ip, match->ip) ? (CMP_MATCH | CMP_STOP) : 0;
}
/* Stringify a sockaddr IP (no port) into buf. Returns -1 if addr/buf is unusable. */
static int sofia_blacklist_ip_from_addr(const struct ast_sockaddr *addr, char *buf, size_t len)
{
	const char *ip;

	if (!addr || ast_sockaddr_isnull(addr) || !buf || !len) {
		return -1;
	}

	ip = ast_sockaddr_stringify_addr(addr);
	if (ast_strlen_zero(ip)) {
		return -1;
	}

	ast_copy_string(buf, ip, len);
	return 0;
}
/* Resolve the source IP of a SIP message into buf. */
static int sofia_blacklist_ip_from_sip(sip_t const *sip, char *buf, size_t len)
{
	struct ast_sockaddr src;

	memset(&src, 0, sizeof(src));
	sofia_get_source_addr(sip, &src);
	return sofia_blacklist_ip_from_addr(&src, buf, len);
}
/* Normalize a CLI-supplied IP string (parse+restringify, else copy verbatim). */
static int sofia_blacklist_ip_from_text(const char *text, char *buf, size_t len)
{
	struct ast_sockaddr addr;

	if (ast_strlen_zero(text) || !buf || !len) {
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	if (ast_sockaddr_parse(&addr, text, PARSE_PORT_IGNORE)
			&& sofia_blacklist_ip_from_addr(&addr, buf, len) == 0) {
		return 0;
	}

	ast_copy_string(buf, text, len);
	return 0;
}
/* Record (add=1) and/or test an IP. Returns 1 once it reaches the block threshold (held under sofia_blacklist_lock). */
static int sofia_blacklist_check_ip(const char *ip, int add, const char *reason)
{
	struct sofia_blacklist_entry key;
	struct sofia_blacklist_entry *entry;
	int blocked = 0;
	time_t now = time(NULL);

	if (!sofia_blacklist_enabled || !sofia_blacklist || ast_strlen_zero(ip)) {
		return 0;	/* blacklist_ban=0: banning disabled - never count, never block. */
	}

	memset(&key, 0, sizeof(key));
	ast_copy_string(key.ip, ip, sizeof(key.ip));

	ast_mutex_lock(&sofia_blacklist_lock);
	entry = ao2_find(sofia_blacklist, &key, OBJ_POINTER);
	if (!entry && add) {
		if (ao2_container_count(sofia_blacklist) >= sofia_blacklist_max) {
			/* At cap: evict the oldest-last_seen entry so an attacker rotating IPs past
			 * the cap cannot escape blacklisting (the old "FULL" reject was "first N wins").
			 * O(N) walk, fires only on overflow. */
			struct sofia_blacklist_entry *oldest = NULL;
			struct sofia_blacklist_entry *cand;
			struct ao2_iterator i = ao2_iterator_init(sofia_blacklist, 0);
			while ((cand = ao2_iterator_next(&i))) {
				if (!oldest || cand->last_seen < oldest->last_seen) {
					if (oldest) {
						ao2_ref(oldest, -1);
					}
					oldest = cand;
				} else {
					ao2_ref(cand, -1);
				}
			}
			ao2_iterator_destroy(&i);
			if (oldest) {
				ast_log(LOG_NOTICE,
					"Sofia blacklist at cap (%d) — evicting LRU entry %s "
					"(first_seen=%ld last_seen=%ld counter=%d) to make room\n",
					sofia_blacklist_max, oldest->ip,
					(long)oldest->first_seen, (long)oldest->last_seen,
					oldest->counter);
				ao2_unlink(sofia_blacklist, oldest);
				ao2_ref(oldest, -1);
			} else {
				/* count >= max but the walk found nothing - bail honestly. */
				ast_log(LOG_ERROR,
					"Sofia blacklist at cap (%d) but LRU walk found "
					"nothing to evict — refusing new entry for %s\n",
					sofia_blacklist_max, ip);
				ast_mutex_unlock(&sofia_blacklist_lock);
				return 0;
			}
		}
		entry = ao2_alloc(sizeof(*entry), NULL);
		if (!entry) {
			ast_mutex_unlock(&sofia_blacklist_lock);
			return 0;
		}
		ast_copy_string(entry->ip, ip, sizeof(entry->ip));
		entry->counter = 0;
		entry->first_seen = now;
		entry->last_seen = now;
		ao2_link(sofia_blacklist, entry);
	}
	if (entry) {
		/* Decay-on-inactivity (fail2ban model): if the last counted failure is older
		 * than the TTL, forgive - reset the counter and start a fresh window. A blocked
		 * IP is dropped at the gate (add=0) so last_seen freezes and the ban auto-expires
		 * TTL after the last failure; a live attacker must re-accumulate the threshold. */
		if (sofia_blacklist_ttl > 0 && entry->last_seen > 0
				&& (now - entry->last_seen) > sofia_blacklist_ttl) {
			entry->counter = 0;
			entry->first_seen = now;
		}
		if (add) {
			entry->counter++;
			entry->last_seen = now;
			if (option_debug > 3) {
				ast_log(LOG_DEBUG, "Sofia blacklist host %s counter %d/%d (%s)\n",
					entry->ip, entry->counter, sofia_blacklist_count,
					S_OR(reason, "no reason"));
			}
		}
		blocked = entry->counter >= sofia_blacklist_count;
		ao2_ref(entry, -1);
	}
	ast_mutex_unlock(&sofia_blacklist_lock);

	return blocked;
}
/* Count a failure for the source IP of sip. Returns 1 if it is now blocked. */
int sofia_blacklist_add_sip(sip_t const *sip, const char *reason)
{
	char ip[80];

	if (sofia_blacklist_ip_from_sip(sip, ip, sizeof(ip)) < 0) {
		return 0;
	}

	return sofia_blacklist_check_ip(ip, 1, reason);
}
/* Test-only (no count) whether the source IP of sip is currently blocked. */
int sofia_blacklist_check_sip(sip_t const *sip)
{
	char ip[80];

	if (sofia_blacklist_ip_from_sip(sip, ip, sizeof(ip)) < 0) {
		return 0;
	}

	if (!sofia_blacklist_check_ip(ip, 0, NULL)) {
		return 0;
	}

	return 1;
}
/* CLI `sip show blacklist`. */
char *sofia_cli_show_blacklist(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
#define BLACKLIST_FORMAT "%-39s %-11s %-19s %-19s\n"
	struct ao2_iterator iter;
	struct sofia_blacklist_entry *entry;
	int total = 0;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip show blacklist";
		e->usage =
			"Usage: sip show blacklist\n"
			"       Lists local Sofia-SIP blacklist entries.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (!sofia_blacklist) {
		ast_cli(a->fd, "Blacklist is not initialized\n");
		return CLI_FAILURE;
	}

	ast_cli(a->fd, BLACKLIST_FORMAT, "IP", "Counter", "First seen", "Last seen");
	/* Build all rows into a heap buffer UNDER the lock, then emit with one ast_cli AFTER
	 * releasing it: the auth-failure path on sofia_thread also takes this lock, so a CLI
	 * write held across the iteration would stall signaling. */
	struct ast_str *bl_buf = ast_str_create(2048);
	ast_mutex_lock(&sofia_blacklist_lock);
	iter = ao2_iterator_init(sofia_blacklist, 0);
		while ((entry = ao2_iterator_next(&iter))) {
			char first[32];
			char last[32];
			char counter[32];
			struct ast_tm tm;
			struct timeval tv;

			tv.tv_sec = entry->first_seen;
			tv.tv_usec = 0;
			ast_localtime(&tv, &tm, NULL);
			ast_strftime(first, sizeof(first), "%Y-%m-%d %H:%M:%S", &tm);
			tv.tv_sec = entry->last_seen;
			tv.tv_usec = 0;
			ast_localtime(&tv, &tm, NULL);
			ast_strftime(last, sizeof(last), "%Y-%m-%d %H:%M:%S", &tm);
		snprintf(counter, sizeof(counter), "%d/%d",
			entry->counter, sofia_blacklist_count);

		if (bl_buf) {
			ast_str_append(&bl_buf, 0, BLACKLIST_FORMAT, entry->ip, counter, first, last);
		}
		ao2_ref(entry, -1);
		total++;
	}
	ao2_iterator_destroy(&iter);
	ast_mutex_unlock(&sofia_blacklist_lock);

	if (bl_buf) {
		ast_cli(a->fd, "%s", ast_str_buffer(bl_buf));
		ast_free(bl_buf);
	}
	ast_cli(a->fd, "Total %d/%d\n", total, sofia_blacklist_max);
	return CLI_SUCCESS;
#undef BLACKLIST_FORMAT
}
/* CLI `sip blacklist search <IP>`. */
char *sofia_cli_blacklist_search(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct sofia_blacklist_entry key;
	struct sofia_blacklist_entry *entry;
	char ip[80];

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip blacklist search";
		e->usage =
			"Usage: sip blacklist search <IP>\n"
			"       Search an IP in the local Sofia-SIP blacklist.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 4) {
		return CLI_SHOWUSAGE;
	}
	if (sofia_blacklist_ip_from_text(a->argv[3], ip, sizeof(ip)) < 0) {
		return CLI_SHOWUSAGE;
	}

	memset(&key, 0, sizeof(key));
	ast_copy_string(key.ip, ip, sizeof(key.ip));
	ast_mutex_lock(&sofia_blacklist_lock);
	entry = sofia_blacklist ? ao2_find(sofia_blacklist, &key, OBJ_POINTER) : NULL;
	if (entry) {
		ast_cli(a->fd, "Found IP %s local blacklist (%d/%d)\n",
			entry->ip, entry->counter, sofia_blacklist_count);
		ao2_ref(entry, -1);
	} else {
		ast_cli(a->fd, "IP %s not exist\n", ip);
	}
	ast_mutex_unlock(&sofia_blacklist_lock);

	return CLI_SUCCESS;
}
/* CLI `sip blacklist delete <IP>`. */
char *sofia_cli_blacklist_delete(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct sofia_blacklist_entry key;
	struct sofia_blacklist_entry *entry;
	char ip[80];

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip blacklist delete";
		e->usage =
			"Usage: sip blacklist delete <IP>\n"
			"       Delete an IP from the local Sofia-SIP blacklist.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 4) {
		return CLI_SHOWUSAGE;
	}
	if (sofia_blacklist_ip_from_text(a->argv[3], ip, sizeof(ip)) < 0) {
		return CLI_SHOWUSAGE;
	}

	memset(&key, 0, sizeof(key));
	ast_copy_string(key.ip, ip, sizeof(key.ip));
	ast_mutex_lock(&sofia_blacklist_lock);
	entry = sofia_blacklist ? ao2_find(sofia_blacklist, &key, OBJ_POINTER | OBJ_UNLINK) : NULL;
	if (entry) {
		ast_cli(a->fd, "IP %s delete from local blacklist\n", ip);
		ao2_ref(entry, -1);
	} else {
		ast_cli(a->fd, "IP %s not found\n", ip);
	}
	ast_mutex_unlock(&sofia_blacklist_lock);

	return CLI_SUCCESS;
}
/* ao2 callback: counts and unlinks every entry. */
static int sofia_blacklist_clear_cb(void *obj, void *arg, int flags)
{
	int *count = arg;

	(*count)++;
	return CMP_MATCH;
}
/* CLI `sip blacklist clear`. */
char *sofia_cli_blacklist_clear(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	int deleted = 0;

	switch (cmd) {
	case CLI_INIT:
		e->command = "sip blacklist clear";
		e->usage =
			"Usage: sip blacklist clear\n"
			"       Clear local Sofia-SIP blacklist.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 3) {
		return CLI_SHOWUSAGE;
	}

	ast_mutex_lock(&sofia_blacklist_lock);
	if (sofia_blacklist) {
		ao2_callback(sofia_blacklist, OBJ_UNLINK | OBJ_NODATA | OBJ_MULTIPLE,
			sofia_blacklist_clear_cb, &deleted);
	}
	ast_mutex_unlock(&sofia_blacklist_lock);
	ast_cli(a->fd, "Delete %d items\n", deleted);

	return CLI_SUCCESS;
}

/* Allocate the blacklist container. Returns 0 on success. */
int sofia_blacklist_init(void)
{
	sofia_blacklist = ao2_container_alloc(SOFIA_BLACKLIST_BUCKETS,
		sofia_blacklist_hash_fn, sofia_blacklist_cmp_fn);
	ao2_container_register("sofia/blacklist", sofia_blacklist);
	return sofia_blacklist ? 0 : -1;
}
/* Configure the ban window from sofia.conf `blacklist_ban`, given in MINUTES. Semantics:
 *   minutes  > 0 : banning ON; a blocked IP stays banned (and an accumulating counter is remembered)
 *                  for this many minutes after its last failure. Stored internally in seconds.
 *   minutes == 0 : banning OFF entirely - no IP is ever blocked or counted.
 *   minutes  < 0 : restore the compiled default (24h, ON) - used to reset on (re)load.
 * Called from the [general] config apply (and on reload), so it takes effect without a restart. */
void sofia_blacklist_set_ban_minutes(int minutes)
{
	if (minutes < 0) {
		sofia_blacklist_enabled = 1;
		sofia_blacklist_ttl = SOFIA_BLACKLIST_TTL_DEFAULT;
	} else if (minutes == 0) {
		sofia_blacklist_enabled = 0;
	} else {
		sofia_blacklist_enabled = 1;
		sofia_blacklist_ttl = minutes * 60;
	}
}

/* Release the blacklist container. */
void sofia_blacklist_destroy(void)
{
	if (sofia_blacklist) {
		ao2_ref(sofia_blacklist, -1);
		sofia_blacklist = NULL;
	}
}
