/* -------------------------------------------------------------------------
 * vm_manager --- monitors shared disk.
 *   This applied pingd mechanism to disk monitor.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright (c) 2008 NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 *
 * -------------------------------------------------------------------------
 */

#include <sys/param.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <time.h>
#include <string.h>

#include <vm_connect.h>

#include <crm/common/ipc.h>
#include <crm/common/xml.h>
#include <crm/common/cluster.h>
#include <crm/msg_xml.h>
#include <crm/crm.h>
#include <crm/cib.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#define OPTARGS			"p:c:n:v:DV?"
#define CONFIG_FILE		"/etc/vm-manager.conf"
#define PID_FILE		"/var/run/vm-managerd.pid"

static gboolean vm_manager_reveive_message(GIOChannel *source, GIOCondition condition, gpointer data);
static char * get_attribute_from_cib(const char *attr_name);
static char * convert_attribute(const char *attr_name, char *attr_value);
static int convert_rule_to_int(char *expr);

static int cib_connect(void);
static void cib_connection_destroy(gpointer user_data);
static gboolean cib_reconnect(gpointer data);

static void re_read_config(int nsig);
static int read_config(char *config_file);

static void clean_up(int rc);
static void attr_hash_cleanup(gpointer data);
static void vm_manager_shutdown(int nsig);
static void usage(const char *cmd, int exit_status);

const char *crm_system_name = "vm-managerd";

enum convert_exprs {
	expr_unknown = -1,
	expr_eq = 0,
	expr_ne = 1,
	expr_lt = 2,
	expr_gt = 3,
	expr_lte = 4,
	expr_gte = 5,
};

typedef struct attribute_s
{
	char *name;
	GList *rule_list;
} attribute_t;

typedef struct rule_s
{
	int expr;
	char *conparison;
	char *convert_string;
} rule_t;

GMainLoop*  mainloop = NULL;
GIOChannel*  connect_ch = NULL;
GHashTable *attribute_hash = NULL;

guint timer_id = 0;

crm_node_t *self = NULL;
cib_t *cib = NULL;
char *pid_file = NULL;
char *config_file = NULL;
char *default_attr_name = NULL;
char *default_attr_value = NULL;

static gboolean
connect_to_vmconnect(gpointer data)
{
	int wfd;

	crm_debug_2("connected to vm-connectd.");
	wfd = connect_to(SOCK_PATH, T_MOD_MONITOR);
	if (wfd < 0) {
		return FALSE;
	}
	crm_debug_2("succeeded in connection of vm-connectd.");

	connect_ch = g_io_channel_unix_new(wfd);
	g_io_add_watch(connect_ch, G_IO_IN, vm_manager_reveive_message, NULL);
	
	return TRUE;
}

static gboolean
vm_manager_reveive_message(GIOChannel *source, GIOCondition condition, gpointer data)
{
	char *tmp_buffer = NULL;
	char **msg_array;
	char *attr_value = NULL;
	char *res_value = crm_strdup("");
	int i, rc;
	int sockfd;
	vm_message msg;

	sockfd = g_io_channel_unix_get_fd(source);
	crm_debug_2("server connect socket [%d].", sockfd);
	
	rc = receive_msg(sockfd, &msg);
	if(rc < 0) {
		crm_err("failed to receive message.");
		return TRUE;
	} else if(rc == 1) {
		crm_info("session with the server was disconnected.");
		vm_manager_shutdown(0);
		return FALSE;
	}

	if(msg.info.datalen == 0) {
		crm_warn("The data which had been sent by guest [%d] were empty.",
			msg.info.sock_guest);
		return TRUE;
	}

	msg_array = g_strsplit(msg.data, " ", 0);
	crm_free(msg.data);

	/* tokenを1つずつ処理 */
	for(i = 0; i < g_strv_length(msg_array); i++) {
		crm_debug_2("request [%d][%s]\n", i, msg_array[i]);
		/* tokenが空の場合は無視する */
		if(strlen(msg_array[i]) == 0) {
			crm_debug_2("ignore the empty token.");
			continue;
		}

		attr_value = get_attribute_from_cib(msg_array[i]);

		if(i < g_strv_length(msg_array)-1) {
			tmp_buffer = g_strconcat(res_value, msg_array[i],
					"=", attr_value != NULL ? attr_value : "", ",", NULL);
		} else {
			tmp_buffer = g_strconcat(res_value, msg_array[i],
					"=", attr_value != NULL ? attr_value : "", NULL);
		}

		crm_free(res_value);
		res_value = crm_strdup(tmp_buffer);
		crm_free(tmp_buffer);
		crm_free(attr_value);
		crm_debug_2("result[%s]\n", res_value);
	}

	msg.data = res_value;
	msg.info.datalen = strlen(res_value);
	/* vm-clientに結果を送信 */
	rc = send_msg(sockfd, &msg);
	if(rc < 0) {
		crm_err("failed to send a %s", res_value);
	}

	crm_free(res_value);
	g_strfreev(msg_array);

	return TRUE;
}

/* shutdown用処理 */
static void
vm_manager_shutdown(int nsig)
{
	if (mainloop != NULL && g_main_is_running(mainloop)) {
		g_main_quit(mainloop);
	} else {
		clean_up(LSB_EXIT_OK);
	}

	return;
}

/*
 * CIB解析処理(属性名に対応した属性値取得)
 */
static char *
get_attribute_from_cib(const char *attr_name)
{
	int rc = cib_ok;
	char *attr_value = NULL;
	char *return_string = NULL;

	rc = read_attr(cib, XML_CIB_TAG_STATUS, self->uuid, NULL, NULL,
		attr_name, &attr_value, FALSE);

	if(rc != cib_ok) {
		crm_warn("failed to get attribute %s: %s", attr_name, cib_error2string(rc));
		return NULL;
	}

	return_string = crm_strdup(convert_attribute(attr_name, attr_value));
	crm_free(attr_value);

	/* free after use */
	return return_string;
}

/* CIB再接続処理 */
static gboolean
cib_reconnect(gpointer data)
{
	int rc = cib_ok;

	if(timer_id > 0) {
		g_source_remove(timer_id);
	}

	rc = cib_connect();

	if(rc != cib_ok) {
		timer_id = g_timeout_add(1000, cib_reconnect, NULL);
	}

	return FALSE;
}

/* CIB切断時処理 */
static void
cib_connection_destroy(gpointer user_data)
{
	crm_info("Connection to the CIB terminated");

	if(cib) {
		crm_info("CIB Reconnecting...");
		cib->cmds->signoff(cib);
		timer_id = g_timeout_add(1000, cib_reconnect, NULL);
	}

	return;
}

/* CIB接続処理 */
static int cib_connect(void)
{
	int rc = cib_ok;
	CRM_CHECK(cib != NULL, return cib_missing);

	/* cib接続確認 */
	if(cib->state != cib_connected_query
		&& cib->state != cib_connected_command) {
		crm_debug("Connecting to the CIB");

		rc = cib->cmds->signon(cib, crm_system_name, cib_query);

		if(rc != cib_ok) {
			crm_err("CIB signon failure: %s",
				cib_error2string(rc));
			return rc;
		}

		if(rc == cib_ok) {
			/* CIB切断時に呼び出される関数をセット */
			rc = cib->cmds->set_connection_dnotify(cib, cib_connection_destroy);
			if(rc == cib_NOTSUPPORTED) {
				crm_info("Notification setup failed, won't be able to"
					" reconnect after failure");
				rc = cib_ok;
			}

		}

		if(rc != cib_ok) {
			crm_err("Notification setup failed, could not monitor CIB actions: %s",
				cib_error2string(rc));
			clean_up(LSB_EXIT_GENERIC);
		}
	}

	return rc;
}

static char *
convert_attribute(const char *attr_name, char *attr_value)
{
	int left;
	int right;
	char *check_ptr = NULL;
	attribute_t *attr = NULL;
	GList *list = NULL;

	attr = g_hash_table_lookup(attribute_hash, attr_name);

	/* 該当する変換ルールが存在しなかった */
	if(attr == NULL) {
		crm_debug_2("There was not the conversion rule of %s.", attr_name);
		return attr_value;
	}

	for(list = g_list_first(attr->rule_list);
		list != NULL; list = g_list_next(list)) {

		rule_t *rule = list->data;

		/* 文字列型チェック */
		switch(rule->expr) {
			case expr_eq:
				crm_debug_3("eq expr\n");
				if(safe_str_eq(attr_value, rule->conparison)) {
					return rule->convert_string;
				}
				break;
			case expr_ne:
				crm_debug_3("ne expr\n");
				if(! safe_str_eq(attr_value, rule->conparison)) {
					return rule->convert_string;
				}
				break;
		}

		left = crm_int_helper(attr_value, &check_ptr);
		if(errno != 0 || check_ptr[0] != '\0') {
			continue;
		}
		crm_debug_3("before[%s]/after[%d]\n", attr_value, left);

		right = crm_int_helper(rule->conparison, &check_ptr);
		if(errno != 0 || check_ptr[0] != '\0') {
			continue;
		}
		crm_debug_3("before[%s]/after[%d]\n", rule->conparison, right);

		/* 数値型チェック */
		switch(rule->expr) {
			case expr_lt:
				crm_debug_3("lt expr\n");
				if(left < right) {
					return rule->convert_string;
				}
				break;
			case expr_gt:
				crm_debug_3("gt expr\n");
				if(left > right) {
					return rule->convert_string;
				}
				break;
			case expr_lte:
				crm_debug_3("lte expr\n");
				if(left <= right) {
					return rule->convert_string;
				}
				break;
			case expr_gte:
				crm_debug_3("gte expr\n");
				if(left >= right) {
					return rule->convert_string;
				}
				break;
		}
	}

	crm_debug_2("attribute %s fulfilled no rule.", attr_value);
	return attr_value;
}

static int
convert_rule_to_int(char *expr)
{
	int expr_num = expr_unknown;

	if(safe_str_eq(expr, "eq")) {
		expr_num = expr_eq;
	} else if(safe_str_eq(expr, "ne")) {
		expr_num = expr_ne;
	} else if(safe_str_eq(expr, "lt")) {
		expr_num = expr_lt;
	} else if(safe_str_eq(expr, "gt")) {
		expr_num = expr_gt;
	} else if(safe_str_eq(expr, "lte")) {
		expr_num = expr_lte;
	} else if(safe_str_eq(expr, "gte")) {
		expr_num = expr_gte;
	}

	return expr_num;
}

static void
re_read_config(int nsig)
{
	int rc;

	if(attribute_hash) {
		g_hash_table_destroy(attribute_hash);
	}

	/* configファイル読み込み */
	rc = read_config(config_file);
	if(rc != 0) {
		crm_err("failed to re-read config file.");
		clean_up(LSB_EXIT_GENERIC);
	}

	return;
}

static int
read_config(char *config_file)
{
	int i, j;
	gboolean rc;
	GError *error = NULL;
	gsize groups_length = 0;
	gsize keys_length = 0;
	GKeyFile *conf = g_key_file_new();
	char **groups = NULL;
	char **keys = NULL;
	char *value = NULL;
	char **split_str = NULL;
	attribute_t *attribute = NULL;

	attribute_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, attr_hash_cleanup);
	crm_info("read a configuration file %s", config_file);

	/* configファイル読み込み */
	rc = g_key_file_load_from_file(conf, config_file, G_KEY_FILE_NONE, &error);
	if(rc == FALSE) {
		crm_err("%s: %s", config_file, error->message);
		g_key_file_free(conf);
		g_error_free(error);
		return 1;
	}

	/* セクション情報読み込み */
	groups = g_key_file_get_groups(conf, &groups_length);

	for(i = 0; i < groups_length; i++) {
		crm_debug_2("group [%s]", groups[i]);
		/* 各セクションからkey情報読み込み */
		keys = g_key_file_get_keys(conf, groups[i], &keys_length, &error);
		if(keys == NULL) {
			crm_err("group[%s]: %s", groups[i], error->message);
			g_key_file_free(conf);
			g_error_free(error);
			return 1;
		}

		crm_malloc0(attribute, sizeof(attribute_t));
		attribute->name = crm_strdup(groups[i]);

		for(j = 0; j < keys_length; j++) {
			rule_t *convert_rule = NULL;
			crm_debug_2("group [%s] key [%s]", groups[i], keys[j]);
			crm_malloc0(convert_rule, sizeof(rule_t));

			/* keyに対応した値の読み込み */
			value = g_key_file_get_value(conf, groups[i], keys[j], &error);
			if(value == NULL) {
				crm_err("group[%s]/key[%s]: %s", groups[i], keys[j], error->message);
				g_key_file_free(conf);
				g_error_free(error);
				return 1;
			}

			/* 値を式と変換値に分割 */
			split_str = g_strsplit(value, " ", 2);
			if(g_strv_length(split_str) < 2) {
				crm_warn("unjust rule [%s], ignore this section[%s] key[%s].",
					value, groups[i], keys[j]);
				crm_free(convert_rule);
				goto free;
			}

			convert_rule->expr = convert_rule_to_int(split_str[0]);

			if(convert_rule->expr == expr_unknown) {
				crm_warn("unjust expression [%s], ignore this section[%s] key[%s].",
					split_str[0], groups[i], keys[j]);
				crm_free(convert_rule);
				goto free;
			}

			crm_debug("group [%s] key [%s] value [%s]", groups[i], keys[j], value);
			convert_rule->convert_string = crm_strdup(keys[j]);
			convert_rule->conparison = crm_strdup(split_str[1]);

			attribute->rule_list = g_list_append(attribute->rule_list, convert_rule);
free:
			g_strfreev(split_str);
			crm_free(value);
		}
		g_hash_table_insert(attribute_hash, attribute->name, attribute);
		g_strfreev(keys);
	}

	g_strfreev(groups);
	g_key_file_free(conf);

	return 0;
}

static void
usage(const char *cmd, int exit_status)
{
	FILE *stream;

	stream = exit_status ? stderr : stdout;

	fprintf(stream, "usage: %s [-%s]\n", cmd, OPTARGS);
	fprintf(stream, "    Basic options\n");
	fprintf(stream, "\t--%s (-%c) <filename>\t\tFile in which to store the process' PID\n"
		"\t\t\t\t\t\t* Default=%s\n", "pid-file", 'p', PID_FILE);
	fprintf(stream, "\t--%s (-%c) <filename>\t\tconfig file\n"
		"\t\t\t\t\t\t* Default=%s\n", "config", 'c', CONFIG_FILE);
	fprintf(stream, "\t--%s (-%c) <name>\t\t\tThe name of the attribute to update in CIB.\n", "attr-name", 'n');
	fprintf(stream, "\t--%s (-%c) <value>\t\tThe value of the attribute to update in CIB.\n", "attr-value", 'v');
	fprintf(stream, "\t--%s (-%c) \t\t\tRun in daemon mode\n", "daemonize", 'D');
	fprintf(stream, "\t--%s (-%c) \t\t\t\tRun in verbose mode\n", "verbose", 'V');
	fprintf(stream, "\t--%s (-%c) \t\t\t\tThis text\n", "help", '?');

	fflush(stream);

	clean_up(exit_status);
}

int
main(int argc, char **argv)
{
	int rc;
	gboolean judge;
	int argerr = 0;
	int flag;
	gboolean daemonize = FALSE;
	struct utsname name;
	
#ifdef HAVE_GETOPT_H
	int option_index = 0;
	static struct option long_options[] = {
		/* Top-level Options */
		{"verbose", 0, 0, 'V'},
		{"help", 0, 0, '?'},
		{"pid-file",  1, 0, 'p'},		
		{"config",  1, 0, 'c'},		
		{"attr-name",  1, 0, 'n'},		
		{"attr-value",  1, 0, 'v'},		
		{"daemonize", 0, 0, 'D'},		
		{0, 0, 0, 0}
	};
#endif
	signal(SIGTERM, vm_manager_shutdown);
	signal(SIGINT, vm_manager_shutdown);

	crm_malloc0(self, sizeof(crm_node_t));
	pid_file = crm_strdup(PID_FILE);
	config_file = crm_strdup(CONFIG_FILE);
	crm_system_name = basename(argv[0]);

	
	crm_log_init(basename(argv[0]), LOG_INFO, TRUE, FALSE, argc, argv);

	/* オプション解析 */
	while (1) {
#ifdef HAVE_GETOPT_H
		flag = getopt_long(argc, argv, OPTARGS,
				   long_options, &option_index);
#else
		flag = getopt(argc, argv, OPTARGS);
#endif
		if (flag == -1)
			break;

		switch(flag) {
			case 'V':
				cl_log_enable_stderr(TRUE);
				alter_debug(DEBUG_INC);
				break;
			case 'p':
				crm_free(pid_file);
				pid_file = crm_strdup(optarg);
				break;
			case 'c':
				crm_free(config_file);
				config_file = crm_strdup(optarg);
				break;
			case 'n':
				default_attr_name = crm_strdup(optarg);
				break;
			case 'v':
				default_attr_value = crm_strdup(optarg);
				break;
			case 'D':
				daemonize = TRUE;
				break;
			case '?':
				usage(crm_system_name, LSB_EXIT_GENERIC);
				break;
			default:
				printf ("Argument code 0%o (%c) is not (?yet?) supported\n", flag, flag);
				crm_err("Argument code 0%o (%c) is not (?yet?) supported\n", flag, flag);
				++argerr;
				break;
		}
	}


	if (optind < argc) {
		crm_err("non-option ARGV-elements: ");
		printf ("non-option ARGV-elements: ");
		while (optind < argc) {
			crm_err("%s ", argv[optind]);
			printf("%s ", argv[optind]);
			optind++;
		}
		printf("\n");
		argerr ++;
	}

	if (argerr > 0 || (default_attr_name != NULL && default_attr_value == NULL) ||
		(default_attr_name == NULL && default_attr_value != NULL)) {
		usage(crm_system_name, LSB_EXIT_GENERIC);
	}

	/* デーモン化 */
	crm_make_daemon(crm_system_name, daemonize, pid_file);

	/* CIB接続 */
	cib = cib_new();
	do {
		crm_debug_2("connect to cib.");
		rc = cib_connect();
		if(rc != cib_ok) {
			sleep(1);
		}

	} while(rc == cib_connection);

	/* ユーザー指定の属性をCIBに更新 */
	if(default_attr_name != NULL && default_attr_value != NULL) {
		judge = attrd_lazy_update('U', NULL,
			default_attr_name, default_attr_value, NULL, NULL, 0);
		if(judge == FALSE) {
			crm_err("failed in update of the attribute value.");
			clean_up(LSB_EXIT_GENERIC);
		}
	}

	/* 自ノード名の取得 */
	rc = uname(&name);
	if(rc < 0) {
		crm_perror(LOG_ERR, "uname(2) call failed");
		clean_up(LSB_EXIT_GENERIC);
	}

	self->uname = crm_strdup(name.nodename);
	crm_info("Detected uname: %s", self->uname);

	/* 自ノードのuuid取得 */
	rc = query_node_uuid(cib, self->uname, &self->uuid);
	if(rc != 0) {
		crm_err("failed to get node uuid.");
		clean_up(LSB_EXIT_GENERIC);
	}

	/* configファイル読み込み */
	rc = read_config(config_file);
	if(rc != 0) {
		crm_err("failed to read config file.");
		clean_up(LSB_EXIT_GENERIC);
	}

	/* vm-connectd接続開始 */
	judge = connect_to_vmconnect(NULL);
	if(judge == FALSE) {
		crm_err("failed to connect vm-connectd");
		exit(1);
	}

	crm_info("Starting %s", crm_system_name);

	/* mainloop開始 */
	mainloop = g_main_new(FALSE);
	mainloop_add_signal(SIGTERM, vm_manager_shutdown);
	mainloop_add_signal(SIGINT, vm_manager_shutdown);
	mainloop_add_signal(SIGHUP, re_read_config);
	g_main_run(mainloop);
	
	crm_info("Exiting %s", crm_system_name);
	
	clean_up(LSB_EXIT_OK);

	return 0;
}

/*
 * 終了時クリーンアップ
 */
static void attr_hash_cleanup(gpointer data)
{
	attribute_t *attr = data;
	GList *list = NULL;

        for(list = g_list_first(attr->rule_list);
		list != NULL; list = g_list_next(list)) {
		rule_t *rule = list->data;
		crm_free(rule->conparison);
		crm_free(rule->convert_string);
		crm_free(rule);
	}

	crm_free(attr);

}
static void clean_up(int rc)
{
	gboolean judge;

	crm_info("clean up to %s.", crm_system_name);

	if(cib != NULL) {
		cib->cmds->signoff(cib);
		cib_delete(cib);
	}

	if(attribute_hash) {
		g_hash_table_destroy(attribute_hash);
	}

	if(default_attr_name != NULL && default_attr_value != NULL) {
		judge = attrd_lazy_update('D', NULL, default_attr_name, NULL, NULL, NULL, 0);
		if(judge == FALSE) {
			crm_warn("failed in deletion of the attribute value.");
		}
		crm_free(default_attr_name);
		crm_free(default_attr_value);
	}

	crm_free(pid_file);
	crm_free(config_file);

	if(rc >= 0) {
		exit(rc);
	}

	return;
}

