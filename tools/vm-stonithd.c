/*
 * vm-stonithd : vm-stonith daemon for host.
 *
 * Copyright (C) 2010 NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <libgen.h>
#include <sys/wait.h>
#include <glib.h>
#include <vm_connect.h>
#include <clplumbing/proctrack.h>
#include <clplumbing/cl_signal.h>
#include <crm/cib.h>
#include <crm/pengine/status.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#define OPTARGS "Vc:ie:?"
#define RESULT_OK "OK"
#define RESULT_NG "NG"
#define ATTR_NAME_PREFIX "force_stop-"
#define ATTR_VALUE "true"

enum stonith_op {
	OP_UNKNOWN = 0,
	OP_POWERON,
	OP_POWEROFF,
	OP_RESET,
	OP_STATUS,
	OP_TIMEOUT
};

struct {
	char *opstr;
	enum stonith_op op;
} opmap[] = {
	{"on",		OP_POWERON},
	{"off",		OP_POWEROFF},
	{"reset",	OP_RESET},
	{"status",	OP_STATUS},
	{"timeout",	OP_TIMEOUT},
	{0,		OP_UNKNOWN}
};

struct request_s {
	enum stonith_op op;
	char *arg;
	char *id;
	ProcTrackKillInfo killseq[2];
};

enum rsc_status {
	RS_STARTED = 1,
	RS_STOPPED,
	RS_UNDEFINED,
	RS_GETERROR
};

struct chld_status {
	struct request_s *req;
	char *prev_role;
	char *started_node;
	char *started_uuid;
};

void usage(const char *cmd, int exitcode);
static void chldDied(ProcTrack *p, int status, int signo, int exitcode, int waslogged);
static void chldRegistered(ProcTrack *p);
static const char *chldName(ProcTrack *p);
void sighdr_term(int signo);
void sighdr_term_chld(int signo);
void kill_chld(gpointer key, gpointer value, gpointer userdata);
gboolean do_shutdown(gpointer unused);
void free_chldhash(gpointer data);
const char *op2str(enum stonith_op op);
gboolean connect_vmconnectd(void);
gboolean do_stonith(GIOChannel *channel, GIOCondition condition, gpointer unused);
struct request_s *parse_request(const vm_message *msg);
gboolean stonith_operate(struct chld_status *stat, vm_message *msg);
char *decrypt_data(const char *encrypted_data);
char *read_file(const char *path, int max_bufsize);
gboolean connect_cib(void);
void disconnect_cib(void);
gboolean get_pe_dataset(void);
void free_pe_dataset(void);
enum rsc_status get_rsc_status(const char *rscid, char **started_node, char **started_uuid);
gboolean check_rsc_meta(GHashTable *rsc_meta);
gboolean start_resource(const char *rscid, char **prev_role);
gboolean stop_resource(const char *rscid, char **prev_role, char **started_node, char **started_uuid);
gboolean update_status_attr(char command, const char *rscid, const char *node, const char *uuid);
gboolean set_rsc_role(const char *rscid, const char *value, char **prev_role);
enum cib_errors find_meta_attr(const char *rscid, const char *name, char **id, char **value);

GMainLoop *mainloop = NULL;
GHashTable *chldhash = NULL;
int sockfd = -1;
uint gsourceid = 0;
char *decrypt_cmd = NULL;
gboolean cmd_read_stdin = FALSE;
int cmd_ok_exitcode = 0;
cib_t *cib_conn = NULL;
pe_working_set_t pe_dataset;
struct chld_status chldstat;
int exit_code = 0;


void
usage(const char *cmd, int exitcode)
{
	fprintf(stderr, "usage: %s [options]\n", cmd);
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -%c, --%s\t\t\tThis text\n", '?', "help");
	fprintf(stderr, "  -%c, --%s\t\t\tIncrease the debug output\n", 'V', "verbose");
	fprintf(stderr, "  -%c, --%s\t\tCommand for decrypting encrypted resource ID\n"
		"\t\t\t\t* Required option\n", 'c', "decrypt-cmd");
	fprintf(stderr, "  -%c, --%s\t\tDecrypting command reads encrypted data from"
		" standard input\n", 'i', "cmd-read-stdin");
	fprintf(stderr, "  -%c, --%s\t\tExit code in case the result of decryption"
		" command is OK\n\t\t\t\t* Default=0\n\n", 'e', "cmd-ok-exitcode");
	exit(exitcode);
}

static ProcTrack_ops ChldTrackOps =
{
	chldDied,
	chldRegistered,
	chldName
};

static void
chldDied(ProcTrack *p, int status, int signo, int exitcode, int waslogged)
{
	pid_t pid = proctrack_pid(p);

	crm_debug_2("called..");

	g_hash_table_remove(chldhash, &pid);
	crm_free(p->privatedata);
	reset_proctrack_data(p);
	return;
}

static void
chldRegistered(ProcTrack *p)
{
	crm_debug_2("called..");
	crm_info("Child process %s started (pid=%d)", p->ops->proctype(p), proctrack_pid(p));
	return;
}

static const char *
chldName(ProcTrack *p)
{
	crm_debug_2("called..");
	crm_debug_2("process name: %s", (char*)proctrack_data(p));
	return (char*)proctrack_data(p);
}

void
sighdr_term(int signo)
{
	crm_debug_2("called..");

	g_source_remove(gsourceid);
	g_hash_table_foreach(chldhash, kill_chld, NULL);
	g_timeout_add(1000, do_shutdown, NULL);
	return;
}

#define BOOL2MSGSTR(bool) bool == TRUE ? "Succeed" : "Failed"
void
sighdr_term_chld(int signo)
{
	gboolean ret = TRUE;
	char *msgupd = NULL, *msgdel = NULL;
	struct request_s *req = chldstat.req;

	crm_debug_2("called..");

	/* First, logging the all messages about processing to be performed from now on. */
	if (chldstat.prev_role != NULL) {
		msgupd = g_strdup_printf("update meta attribute: name=%s value=%s of rsc=%s",
				XML_RSC_ATTR_TARGET_ROLE, chldstat.prev_role, req->arg);
		crm_notice("%s", msgupd);
	}
	if (chldstat.started_node != NULL) {
		msgdel = g_strdup_printf("delete attribute: name=%s%s of %s",
				ATTR_NAME_PREFIX, req->arg, chldstat.started_node);
		crm_notice("%s", msgdel);
	}

	/* Then, actually performs. */
	if (chldstat.prev_role != NULL) {
		ret = set_rsc_role(req->arg, chldstat.prev_role, NULL);
		crm_notice("%s : %s", msgupd, BOOL2MSGSTR(ret));
	}
	if (chldstat.started_node != NULL) {
		crm_debug("op=%s, rscid=%s, node=%s",
			op2str(req->op), req->arg, chldstat.started_node);
		gboolean rc = update_status_attr('D', req->arg,
				chldstat.started_node, chldstat.started_uuid);
		if (rc == FALSE) {
			ret = FALSE;
		}
		crm_notice("%s : %s", msgdel, BOOL2MSGSTR(rc));
	}
	disconnect_cib();
	crm_info("Exiting %s child process", crm_system_name);
	exit(ret == TRUE ? 0 : 1);
}

void
kill_chld(gpointer key, gpointer value, gpointer userdata)
{
	pid_t *pid = key;
	struct request_s *req = value;

	crm_debug_2("called..");

	if (userdata != NULL && safe_str_neq(req->id, (char*)userdata)) {
		return;
	}

	crm_info("send SIGTERM to %s process [%s %s] (pid=%d)",
		crm_system_name, op2str(req->op), req->arg, *pid);
	if (CL_KILL(*pid, SIGTERM) < 0) {
		if (errno == ESRCH) {
			return;
		}
		crm_err("kill (%d, %d) failed", *pid, SIGTERM);
	}
	req->killseq[0].mstimeout = 10 * 1000;
	req->killseq[0].signalno = SIGKILL;
	req->killseq[1].mstimeout = 5 * 1000;
	req->killseq[1].signalno = 0;
	SetTrackedProcTimeouts(*pid, req->killseq);
	return;
}

gboolean
do_shutdown(gpointer unused)
{
	crm_debug_2("called..");

	if (g_hash_table_size(chldhash) > 0) {
		crm_debug_2("waiting..");
		return TRUE;
	}
	g_hash_table_destroy(chldhash);
	close(sockfd);
	g_main_loop_quit(mainloop);
	return FALSE;
}

void
free_chldhash(gpointer data)
{
	crm_debug_2("called..");

	crm_free(((struct request_s*)data)->arg);
	crm_free(((struct request_s*)data)->id);
	crm_free(data);
	return;
}

const char *
op2str(enum stonith_op op)
{
	int i;
	for (i = 0; opmap[i].opstr; i++) {
		if (opmap[i].op == op) {
			return opmap[i].opstr;
		}
	}
	return NULL;
}

gboolean
connect_vmconnectd(void)
{
	crm_debug_2("called..");

	sockfd = connect_to(SOCK_PATH, T_MOD_STONITH);
	if (sockfd < 0) {
		return FALSE;
	}
	gsourceid = g_io_add_watch(g_io_channel_unix_new(sockfd), G_IO_IN, do_stonith, NULL);
	return TRUE;
}

gboolean
do_stonith(GIOChannel *channel, GIOCondition condition, gpointer unused)
{
	vm_message msg;
	struct request_s *req;
	pid_t *pid;
	int ret;

	crm_debug_2("called...");

	ret = receive_msg(g_io_channel_unix_get_fd(channel), &msg);
	if (ret < 0) {
		crm_err("receive message failed");
		return TRUE;
	}
	else if (ret == 1) {
		crm_err("connection with vm-connectd was closed");
		g_hash_table_foreach(chldhash, kill_chld, NULL);
		g_timeout_add(1000, do_shutdown, NULL);
		exit_code = 1;
		return FALSE;
	}
	req = parse_request(&msg);
	crm_free(msg.data);
	msg.data = NULL;
	msg.info.datalen = 0;

	if (req->op == OP_TIMEOUT) {
		g_hash_table_foreach(chldhash, kill_chld, req->id);
		free_chldhash(req);
		return TRUE;
	}

	crm_malloc0(pid, sizeof(pid_t));
	*pid = fork();
	if (*pid < 0) {
		crm_err("fork(2) call failed, could not STONITH [op=%s, rsc=%s]",
			op2str(req->op), req->arg);
		free_chldhash(req);
		return TRUE;
	}
	else if (*pid > 0) {
		NewTrackedProc(*pid, 0, PT_LOGVERBOSE,
			g_strconcat(crm_system_name, "-", op2str(req->op), NULL), &ChldTrackOps);
		g_hash_table_insert(chldhash, pid, req);
		return TRUE;
	}
	crm_free(pid);
	setpgid(0, 0);
	g_main_loop_quit(mainloop);
	memset(&chldstat, 0, sizeof(struct chld_status));
	chldstat.req = req;
	CL_SIGNAL(SIGTERM, sighdr_term_chld);
	cl_signal_set_interrupt(SIGTERM, TRUE);
	ret = stonith_operate(&chldstat, &msg);
	disconnect_cib();
	exit(ret == TRUE ? 0 : 1);
}

struct request_s *
parse_request(const vm_message *msg)
{
	struct request_s *req;
	char **args;

	crm_debug_2("called..");

	crm_malloc0(req, sizeof(struct request_s));
	req->op = OP_UNKNOWN;

	args = g_strsplit(msg->data, " ", 0);
	if (g_strv_length(args) >= 1 && args[0] != NULL) {
		int i;
		for (i = 0; opmap[i].opstr; i++) {
			if (safe_str_eq(opmap[i].opstr, args[0])) {
				req->op = opmap[i].op;
				break;
			}
		}
	}
	if (g_strv_length(args) >= 2 && args[1] != NULL) {
		req->arg = decrypt_data(args[1]);
	}
	g_strfreev(args);

	if (msg->info.id[0] != 0) {
		req->id = crm_strdup(msg->info.id);
	}
	crm_info("Request: op=%s, arg=%s", op2str(req->op), req->arg);
	crm_debug("Request: id=%s", req->id);
	return req;
}

#define BOOL2RESULT(bool) bool == TRUE ? RESULT_OK : RESULT_NG
gboolean
stonith_operate(struct chld_status *stat, vm_message *msg)
{
	gboolean ret = FALSE;
	enum rsc_status rstat;
	int rc;

	crm_debug_2("called..");

	switch (stat->req->op) {
	case OP_POWERON:
		ret = start_resource(stat->req->arg, &stat->prev_role);
		break;
	case OP_POWEROFF:
		ret = stop_resource(stat->req->arg, &stat->prev_role,
			&stat->started_node, &stat->started_uuid);
		break;
	case OP_RESET:
		if (stop_resource(stat->req->arg, &stat->prev_role,
			&stat->started_node, &stat->started_uuid) == TRUE) {
			ret = start_resource(stat->req->arg, &stat->prev_role);
		}
		break;
	case OP_STATUS:
		rstat = get_rsc_status(stat->req->arg, NULL, NULL);
		if (rstat == RS_STARTED || rstat == RS_STOPPED) {
			ret = TRUE;
		}
		break;
	default:
		crm_warn("undefined request was received");
		break;
	}
	msg->data = crm_strdup(BOOL2RESULT(ret));
	msg->info.datalen = strlen(msg->data);

	crm_info("Replying: %s", msg->data);
	rc = send_msg(sockfd, msg);
	if (rc < 0) {
		ret = FALSE;
	}
	crm_debug_2("end..");
	return ret;
}

char *
decrypt_data(const char *encrypted_data)
{
	char *buf;
	const uint bufsize = 2048;
	int ret;
	static char *tmpfile = NULL;

	crm_debug_2("called..");

	if (tmpfile == NULL) {
		tmpfile = g_strdup_printf("/tmp/vmstonith.%d", getpid());
	}

	crm_malloc0(buf, bufsize);
	if (cmd_read_stdin == TRUE) {
		sprintf(buf, "echo \"%s\"|%s>%s", encrypted_data, decrypt_cmd, tmpfile);
	}
	else {
		sprintf(buf, "%s \"%s\">%s", decrypt_cmd, encrypted_data, tmpfile);
	}
	crm_debug("decrypt command: %s", buf);

	ret = system(buf);
	if (ret == -1 || !WIFEXITED(ret)) {
		cl_perror("system(3) call failed");
		goto fail;
	}
	ret = WEXITSTATUS(ret);
	crm_debug("command's exit code [%d]", ret);
	if (cmd_ok_exitcode != ret) {
		crm_err("command [%s] failed, exit code %d", buf, ret);
		goto fail;
	}
	crm_debug("decrypt command succeed");

	crm_free(buf);
	buf = read_file(tmpfile, bufsize);
	if (buf == NULL) {
		goto fail;
	}
	if (buf[strlen(buf)-1] == '\n') {
		buf[strlen(buf)-1] = 0;
	}
	crm_debug("decrypted [%s]", buf);
	unlink(tmpfile);
	return buf;
fail:
	unlink(tmpfile);
	crm_free(buf);
	return NULL;
}

char *
read_file(const char *path, int max_bufsize)
{
	int fd;
	char *buf, *p = NULL;
	ssize_t size;

	crm_debug_2("called..");

	fd = open(path, 'r');
	if (fd < 0) {
		cl_perror("open(2) call failed");
		return NULL;
	}
	crm_malloc0(buf, max_bufsize);
	memset(buf, 0, max_bufsize);
	size = read(fd, buf, max_bufsize-1);
	if (size < 0) {
		cl_perror("read(2) call failed");
	}
	close(fd);
	if (size > 0) {
		p = crm_strdup(buf);
		crm_debug_2("read success: %s", p);
	}
	crm_free(buf);
	return p;
}

gboolean
connect_cib(void)
{
	enum cib_errors rc = cib_ok;
	int attempts;

	crm_debug_2("called..");

	if (cib_conn != NULL) {
		return TRUE;
	}
	memset(&pe_dataset, 0, sizeof(pe_working_set_t));

	cib_conn = cib_new();
	if (cib_conn == NULL) {
		crm_err("cib connection initialization failed");
		return FALSE;
	}
	for (attempts = 0; attempts < 20; attempts++) {
		if (attempts) {
			sleep(1);
		}
		crm_debug("connect to cib attempt: %d", attempts+1);
		rc = cib_conn->cmds->signon(cib_conn, crm_system_name, cib_command);
		if (rc == cib_ok) {
			break;
		}
	}
	if (rc != cib_ok) {
		crm_err("failed to signon to cib: %s", cib_error2string(rc));
		return FALSE;
	}
	crm_debug("succeed at connect to cib");
	return TRUE;
}

void
disconnect_cib(void)
{
	crm_debug_2("called..");

	if (cib_conn != NULL) {
		cib_conn->cmds->signoff(cib_conn);
		cib_delete(cib_conn);
		cib_conn = NULL;
	}
	free_pe_dataset();
	return;
}

gboolean
get_pe_dataset(void)
{
	crm_data_t *cib;
	unsigned int loglevel;

	crm_debug_2("called..");

	if (connect_cib() == FALSE) {
		return FALSE;
	}
	free_pe_dataset();
	cib = get_cib_copy(cib_conn);
	set_working_set_defaults(&pe_dataset);
	pe_dataset.input = cib;
	pe_dataset.now = new_ha_date(TRUE);

	/* log output of the level below LOG_ERR is deterred */
	loglevel = get_crm_log_level();
	set_crm_log_level(LOG_ERR);
	cluster_status(&pe_dataset);
	set_crm_log_level(loglevel);

	return TRUE;
}

void
free_pe_dataset(void)
{
	crm_debug_2("called..");

	if (pe_dataset.input == NULL) {
		return;
	}
	free_xml(pe_dataset.input);
	pe_dataset.input = NULL;
	cleanup_calculations(&pe_dataset);
	memset(&pe_dataset, 0, sizeof(pe_working_set_t));
	return;
}

enum rsc_status
get_rsc_status(const char *rscid, char **started_node, char **started_uuid)
{
	resource_t *rsc;

	crm_debug_2("called..");

	if (rscid == NULL) {
		return FALSE;
	}
	if (get_pe_dataset() == FALSE) {
		return RS_GETERROR;
	}

	/* find out from RUNNING resources */
	slist_iter(node, node_t, pe_dataset.nodes, lpc,
		slist_iter(rsc, resource_t, node->details->running_rsc, lpc,
			crm_debug("started rscid [%s]", rsc->id);
			if (safe_str_eq(rscid, rsc->id)) {
				if (check_rsc_meta(rsc->meta) == FALSE) {
					return RS_UNDEFINED;
				}
				if (started_node != NULL && *started_node == NULL) {
					*started_node = crm_strdup(node->details->uname);
					*started_uuid = crm_strdup(node->details->id);
					crm_debug("get started_node: %s (%s)",
						*started_node, *started_uuid);
				}
				return RS_STARTED;
			}
		);
	);

	/* find out from ALL resources */
	rsc = pe_find_resource(pe_dataset.resources, rscid);
	if (rsc != NULL) {
		crm_debug("stopped rscid [%s]", rsc->id);
		if (check_rsc_meta(rsc->meta) == TRUE) {
			return RS_STOPPED;
		}
	}
	return RS_UNDEFINED;
}

gboolean
check_rsc_meta(GHashTable *rsc_meta)
{
	const char *value;

	crm_debug_2("called..");

	value = g_hash_table_lookup(rsc_meta, XML_AGENT_ATTR_CLASS);
	crm_debug("%s=%s", XML_AGENT_ATTR_CLASS, value);
	if (value == NULL || safe_str_neq(value, "ocf")) {
		return FALSE;
	}

	value = g_hash_table_lookup(rsc_meta, XML_AGENT_ATTR_PROVIDER);
	crm_debug("%s=%s", XML_AGENT_ATTR_PROVIDER, value);
	if (value == NULL || safe_str_neq(value, "extra")) {
		return FALSE;
	}

	value = g_hash_table_lookup(rsc_meta, XML_ATTR_TYPE);
	crm_debug("%s=%s", XML_ATTR_TYPE, value);
	if (value == NULL || safe_str_neq(value, "VirtualDomain")) {
		return FALSE;
	}
	return TRUE;
}

gboolean
start_resource(const char *rscid, char **prev_role)
{
	gboolean updated_cib = FALSE;

	crm_debug_2("called..");

	if (rscid == NULL) {
		return FALSE;
	}

check:
	switch (get_rsc_status(rscid, NULL, NULL)) {
	case RS_STARTED:
		crm_info("resource %s started", rscid);
		return TRUE;
	case RS_STOPPED:
		if (updated_cib == FALSE) {
			if (set_rsc_role(rscid, RSC_ROLE_STARTED_S, prev_role) == FALSE) {
				return FALSE;
			}
			updated_cib = TRUE;
		}
		crm_debug_2("waiting..");
		sleep(1);
		goto check;
	default:
		return FALSE;
	}
}

gboolean
stop_resource(const char *rscid, char **prev_role, char **started_node, char **started_uuid)
{
	gboolean updated_cib = FALSE;

	crm_debug_2("called..");

	if (rscid == NULL) {
		return FALSE;
	}

check:
	switch (get_rsc_status(rscid, started_node, started_uuid)) {
	case RS_STARTED:
		if (updated_cib == FALSE) {
			if (update_status_attr('U', rscid, *started_node, *started_uuid) == FALSE) {
				return FALSE;
			}
			if (set_rsc_role(rscid, RSC_ROLE_STOPPED_S, prev_role) == FALSE) {
				update_status_attr('D', rscid, *started_node, *started_uuid);
				return FALSE;
			}
			updated_cib = TRUE;
		}
		crm_debug_2("waiting..");
		sleep(1);
		goto check;
	case RS_STOPPED:
		crm_info("resource %s stopped", rscid);
		if (updated_cib == FALSE) {
			return TRUE;
		}
		return update_status_attr('D', rscid, *started_node, *started_uuid);
	default:
		return FALSE;
	}
}

/*
 * The cluster node attribute is updated for RA which controls a virtual machine.
 */
gboolean
update_status_attr(char command, const char *rscid, const char *node, const char *uuid)
{
	char *name = g_strdup_printf("%s%s", ATTR_NAME_PREFIX, rscid);
	char *value;
	gboolean ret;

	crm_debug_2("called..");

	switch (command) {
	case 'U':
		value = ATTR_VALUE;
		break;
	case 'D':
		value = NULL;
		break;
	default:
		return FALSE;
	}
	crm_info("Update attribute: %s=%s for %s", name, value, node);

	ret = attrd_lazy_update(command, node, name, value, XML_CIB_TAG_STATUS, NULL, NULL);
	if (ret == TRUE) {
		enum cib_errors rc;
		value = NULL;
		while (1) {
			crm_debug_2("waiting..");
			sleep(1);
			rc = read_attr(cib_conn, XML_CIB_TAG_STATUS,
				uuid, NULL, NULL, name, &value, FALSE);
			crm_debug("command [%c], rc [%d], value [%s]", command, rc, value);
			if (rc == cib_ok) {
				if (command == 'U' && !g_strcmp0(value, ATTR_VALUE)) {
					break;
				}
			}
			else if (rc == cib_NOTEXISTS) {
				if (command == 'D') {
					break;
				}
			}
			else {
				ret = FALSE;
				break;
			}
			crm_free(value);
		}
		crm_free(value);
	}
	crm_free(name);
	return ret;
}

/*
 * ref. pacemaker/tools/crm_resource.c
 */
gboolean
set_rsc_role(const char *rscid, const char *value, char **prev_role)
{
	resource_t *rsc;
	char *id = NULL;
	xmlNode *xml_top = NULL, *xml_obj = NULL;
	enum cib_errors rc;
	const char *name = XML_RSC_ATTR_TARGET_ROLE;

	crm_debug_2("called..");

	rsc = pe_find_resource(pe_dataset.resources, rscid);
	if (rsc == NULL) {
		return FALSE;
	}

	rc = find_meta_attr(rscid, name, &id, prev_role);
	if (rc == cib_ok) {
		crm_debug("Found a match for name=%s: id=%s", name, id);
	}
	else if (rc == cib_NOTEXISTS) {
		char *set;
		set = crm_concat(rscid, XML_TAG_META_SETS, '-');
		id = crm_concat(set, name, '-');
		xml_top = create_xml_node(NULL, crm_element_name(rsc->xml));
		crm_xml_add(xml_top, XML_ATTR_ID, rscid);
		xml_obj = create_xml_node(xml_top, XML_TAG_META_SETS);
		crm_xml_add(xml_obj, XML_ATTR_ID, set);
		crm_free(set);

		if (prev_role != NULL && *prev_role == NULL) {
			*prev_role = crm_strdup(RSC_ROLE_STARTED_S);
			crm_debug("get prev_role: %s", *prev_role);
		}
	}
	else {
		return FALSE;
	}

	xml_obj = create_xml_node(xml_obj, XML_CIB_TAG_NVPAIR);
	if (xml_top == NULL) {
		xml_top = xml_obj;
	}
	crm_xml_add(xml_obj, XML_ATTR_ID, id);
	crm_xml_add(xml_obj, XML_NVPAIR_ATTR_NAME, name);
	crm_xml_add(xml_obj, XML_NVPAIR_ATTR_VALUE, value);
	crm_log_xml(LOG_INFO, "Update", xml_top);

	rc = cib_conn->cmds->modify(cib_conn, XML_CIB_TAG_RESOURCES, xml_top, cib_sync_call);
	if (rc != cib_ok) {
		crm_err("failed to modify to cib: %s", cib_error2string(rc));
	}
	free_xml(xml_top);
	crm_free(id);
	return rc == cib_ok ? TRUE : FALSE;
}

/*
 * ref. pacemaker/tools/crm_resource.c
 */
enum cib_errors
find_meta_attr(const char *rscid, const char *name, char **id, char **value)
{
	char *xpath;
	xmlNode *xml_search = NULL;
	const char *p;
	enum cib_errors rc;

	crm_debug_2("called..");

	xpath = g_strdup_printf("%s/*[@id=\"%s\"]/%s/nvpair[@name=\"%s\"]",
		get_object_path("resources"), rscid, XML_TAG_META_SETS, name);
	crm_debug("query=%s", xpath);

	rc = cib_conn->cmds->query(cib_conn, xpath, &xml_search,
		cib_sync_call | cib_scope_local | cib_xpath);
	if (rc != cib_ok) {
		if (rc != cib_NOTEXISTS) {
			crm_err("failed to query to cib: %s", cib_error2string(rc));
		}
		crm_free(xpath);
		return rc;
	}
	crm_log_xml_debug(xml_search, "Match");

	p = crm_element_value(xml_search, XML_ATTR_ID);
	if (p != NULL) {
		*id = crm_strdup(p);
	}
	if (value != NULL && *value == NULL) {
		p = crm_element_value(xml_search, XML_NVPAIR_ATTR_VALUE);
		if (p != NULL) {
			*value = crm_strdup(p);
			crm_debug("get prev_value: %s", *value);
		}
	}
	crm_free(xpath);
	free_xml(xml_search);
	return rc;
}

int
main(int argc, char **argv)
{
	int argerr = 0, flag;
#ifdef HAVE_GETOPT_H
	int opt_idx = 0;
	static struct option long_opts[] = {
		{"verbose",		0, 0, 'V'},
		{"decrypt-cmd",		1, 0, 'c'},
		{"cmd-read-stdin",	0, 0, 'i'},
		{"cmd-ok-exitcode",	1, 0, 'e'},
		{"help",		0, 0, '?'},
		{0, 0, 0, 0}
	};
#endif
	crm_log_init(basename(argv[0]), LOG_INFO, TRUE, FALSE, argc, argv);
	mainloop_add_signal(SIGTERM, sighdr_term);
	mainloop_add_signal(SIGINT, sighdr_term);
	set_sigchld_proctrack(G_PRIORITY_HIGH, 10 * DEFAULT_MAXDISPATCHTIME);

	while (1) {
#ifdef HAVE_GETOPT_H
		flag = getopt_long(argc, argv, OPTARGS, long_opts, &opt_idx);
#else
		flag = getopt(argc, argv, OPTARGS);
#endif
		if (flag == -1) {
			break;
		}
		switch (flag) {
		case 'V':
			cl_log_enable_stderr(TRUE);
			alter_debug(DEBUG_INC);
			break;
		case 'c':
			crm_debug("decrypt-cmd: [%s]", optarg);
			decrypt_cmd = crm_strdup(optarg);
			break;
		case 'i':
			cmd_read_stdin = TRUE;
			break;
		case 'e':
			crm_debug("cmd-ok-exitcode: [%s]", optarg);
			cmd_ok_exitcode = crm_parse_int(optarg, "-1");
			if (cmd_ok_exitcode < 0) {
				fprintf(stderr,
					"Invalid exit code is specified. [%s]\n", optarg);
				argerr++;
			}
			break;
		case '?':
			usage(crm_system_name, 1);
			break;
		default:
			fprintf(stderr, "Argument code 0%o (%c) is not (?yet?) supported",
				flag, flag);
			argerr++;
			break;
		}
	}

	if (optind < argc) {
		fprintf(stderr, "non-option ARGV-elements: ");
		while (optind < argc) {
			fprintf(stderr, "%s", argv[optind++]);
		}
		fprintf(stderr, "\n");
		argerr++;
	}
	if (argerr || decrypt_cmd == NULL || decrypt_cmd[0] == 0) {
		usage(crm_system_name, 1);
	}
	chldhash = g_hash_table_new_full(g_str_hash, g_int_equal, g_free, free_chldhash);

	if (connect_vmconnectd() == FALSE) {
		crm_info("Exiting %s", crm_system_name);
		return 1;
	}
	mainloop = g_main_loop_new(NULL, FALSE);
	crm_info("Starting %s", crm_system_name);
	g_main_loop_run(mainloop);
	crm_info("Exiting %s", crm_system_name);
	return exit_code;
}
