/*
 * vm_connectd : Daemon program which communicates between host and guest.
 *
 * Copyright (C) 2010 NIPPON TELEGRAPH AND TELEPHONE CORPORATION
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
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <libgen.h>
#include <glib.h>
#include <gio/gio.h>
#include <vm_connect.h>
#include <crm/crm.h>
#include <crm/common/util.h>
#include <crm/cib.h>

GMainLoop *mainloop = NULL;
GFileMonitor *monitor = NULL;
const char *sock_dir = NULL;
cib_t *cib_conn = NULL;
gboolean need_shutdown = FALSE;
GHashTable *guest_hash = NULL;
GIOChannel *hostch = NULL;
int listen_sock;
int local_sock;
int evid;

extern int sock_host;		/* lib/vm_connect.c */
extern gboolean on_host;	/* lib/vm_connect.c */
extern GHashTable *io_watch;	/* lib/vm_connect.c */

typedef struct guest_s {
	char *id;
	char *name;
	char *conf_path;
	char *sock_path;
	GIOChannel *ioch;
	int *sockfd;
	guint *sourceid;
	int reconnect_timer;
	gboolean connected;
} guest_t;

static void
file_monitor_callback(GFileMonitor *monitor, GFile *file, GFile *other,
	GFileMonitorEvent event_type, gchar *unused);
static int connect_to_host(const char *port);
static int connect_to_guest(guest_t *guest);

static void
free_guest_info(gpointer data)
{
	guest_t *guest = (guest_t *)data;

	crm_free(guest->id);
	crm_free(guest->name);
	crm_free(guest->conf_path);
	crm_free(guest->sock_path);
	crm_free(guest);

	return;
}

static void
close_to_hash_socket(gpointer sockfd, gpointer sourceid, gpointer user_data)
{
	crm_debug_3("close to socket %p[%d]", sockfd, *(int*)sockfd);
	close(*(int*)sockfd);

	return;
}

static void
vm_connectd_shutdown(int nsig)
{
	crm_debug_2("called..");

	need_shutdown = TRUE;

	close(listen_sock);
	unlink(SOCK_PATH);

	g_hash_table_foreach(io_watch, close_to_hash_socket, NULL);
	g_hash_table_destroy(io_watch);

	if(on_host) {
		g_hash_table_destroy(guest_hash);
	}

	if(mainloop != NULL && g_main_loop_is_running(mainloop)) {
		g_main_loop_quit(mainloop);
	} else {
		exit(0);
	}

	return;
}

static void
vm_connectd_cib_connection_destroy(gpointer user_data)
{
	crm_debug_2("called..");
	if(need_shutdown) {
		crm_info("Connection to the CIB terminated...");
	} else {
		crm_err("Connection to the CIB terminated...");
		exit(1);
	}

	return;
}

static int
cib_connect(void *user_data)
{
	enum cib_errors rc = cib_not_connected;
	int attempts = 0;
	int max_retry = 20;
	gboolean was_err = FALSE;

	crm_debug_2("called..");
	cib_conn = cib_new();

	while(rc != cib_ok) {
		attempts++;
		crm_debug("CIB signon attempt %d.", attempts);
		rc = cib_conn->cmds->signon(cib_conn, "vm-connectd", cib_command);

		if(rc != cib_ok && attempts >= max_retry) {
			crm_err("Signon to CIB failed: %s", cib_error2string(rc));
			was_err = TRUE;
			break;
		}
		sleep(1);
	}

	crm_info("Connected to the CIB after %d signon attempts.", attempts);

	if(was_err == FALSE) {
		rc = cib_conn->cmds->set_connection_dnotify(
			cib_conn, vm_connectd_cib_connection_destroy);
		if(rc != cib_ok) {
			crm_err("Could not set dnotify callback.");
			was_err = TRUE;
		}
	}

	if(was_err) {
		crm_err("Aborting startup.");
		return -1;
	}

	return 0;
}

static GFileMonitor *
set_file_monitor(const char *monitor_path)
{
	GFile *gfile = NULL;
	GError *error = NULL;
	GFileMonitor *gfile_monitor = NULL;

	crm_debug_2("called..");
	/* set socket file monitor */
	g_type_init();

	gfile = g_file_new_for_path(monitor_path);
	gfile_monitor = g_file_monitor(gfile, G_FILE_MONITOR_NONE, NULL, &error);

	if(gfile_monitor == NULL) {
		crm_err("g_file_monitor() failed: [%s].", error->message);
		return NULL;
	}

	g_signal_connect(gfile_monitor, "changed", G_CALLBACK(file_monitor_callback), NULL);

	return gfile_monitor;
}

static gboolean
reconnect_to_guest(gpointer data)
{
	int rc;
	guest_t *guest = (guest_t *)data;

	crm_debug_2("called..");
	rc = connect_to_guest(guest);
	if(rc <= 0) {
		guest->reconnect_timer = 0;
		return FALSE;
	}

	return TRUE;
}

static void
guest_connection_destroy_notify(gpointer data)
{
	guest_t *guest = data;

	crm_debug_2("called..");
	guest->connected = FALSE;

	return;
}

static int
connect_to_guest(guest_t *guest)
{
	int rc, ret;
	struct sockaddr_un addr;

	crm_debug_2("called..");

	if(guest->connected == FALSE) {
		guest->sockfd = g_new(int, 1);
		*guest->sockfd = socket(PF_UNIX, SOCK_STREAM|SOCK_NONBLOCK, 0);
		if (*guest->sockfd < 0) {
			crm_perror(LOG_ERR, "socket(2) call failed:");
			crm_free(guest->sockfd);
			return -1;
		}

		crm_debug_3("connecting to [%s]", guest->sock_path);
		memset(&addr, 0, sizeof(struct sockaddr_un));
		addr.sun_family = AF_UNIX;
		g_strlcpy(addr.sun_path, guest->sock_path, sizeof(addr.sun_path)-1);

		rc = connect(*guest->sockfd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un));
		if (rc < 0) {
			if(errno == EAGAIN) {
				ret = 1;
				goto failed;
			} else if(errno == ENOENT) {
				crm_info("socket of guest [%s] is not yet made.", guest->name);
			} else if(errno == ECONNREFUSED){
				crm_info("socket file is exist, but a guest [%s] does not started.",
					guest->name);
			} else {
				crm_perror(LOG_ERR, "connect(2) call failed:");
			}
			ret = -1;
			goto failed;
		}

		guest->connected = TRUE;
		guest->sourceid = g_new(guint, 1);
		guest->ioch = g_io_channel_unix_new(*guest->sockfd);
		g_io_channel_set_flags(guest->ioch, !G_IO_FLAG_NONBLOCK, NULL);
		/* ゲストからのメッセージ待ち受けハンドラ設定 */
		*guest->sourceid = g_io_add_watch_full(guest->ioch,
				G_PRIORITY_DEFAULT, G_IO_IN|G_IO_ERR|G_IO_HUP,
				on_msg_arrived, guest, guest_connection_destroy_notify);
		crm_debug_4("create guest [%s] io watch source id [%d].",
			guest->name, *guest->sourceid);
		g_hash_table_insert(io_watch, guest->sockfd, guest->sourceid);
		crm_info("succeeded in connection to guest [%s] socket [%d].",
			guest->name, *guest->sockfd);
		/* live migration対応 */
		send_message(*guest->sockfd, T_MIGRATION_OCCURRED, NULL, NULL);

		return 0;
	}
	crm_debug_3("already connected guest [%s] socket [%d].", guest->name, *guest->sockfd);
	return 0;

failed:
	close(*guest->sockfd);
	crm_free(guest->sockfd);
	return ret;
}

static char *
optimize_path(const char *path)
{
	char *return_path = NULL;
	int i, j=0;
	gboolean flg = FALSE;

	if(path == NULL) {
		return NULL;
	}

	crm_malloc0(return_path, strlen(path)+1);
	for(i=0;i<strlen(path);i++) {
		if(path[i] == '/') {
			if(flg) continue;
			flg = TRUE;
		} else {
			flg = FALSE;
		}
		return_path[j++] = path[i];
	}
	crm_debug_3("optimized path[%s]", return_path);

	return return_path;
}

static void
parse_libvirt_conf(gpointer key, gpointer value, gpointer user_data)
{
	int rc;
	guest_t *guest = (guest_t *)value;
	char *sock_path = NULL;
	xmlNode *conf_root = NULL;
	xmlNode *device_root = NULL;
	xmlNode *name_root = NULL;
	xmlNode *target_node = NULL;
	xmlNode *source_node = NULL;

	crm_debug_3("parse to guest config [%s].", guest->conf_path);
	conf_root = filename2xml(guest->conf_path);
	if(conf_root == NULL) {
		crm_err("failed to convert a file into XML [%s].", guest->conf_path);
		return;
	}

	/* search guest name */
	name_root = find_xml_node(conf_root, "name", FALSE);
	if(name_root == NULL || name_root->children == NULL) {
		crm_err("failed in the getting of the name of guest [%s] config file [%s].",
			(char *)key, guest->conf_path);
		goto end;
	}

	crm_free(guest->name);
	guest->name = g_strdup((const char*)name_root->children->content);
	crm_debug_3("guest name [%s].", guest->name);

	/*
	 * search guest socket path
	 */
	device_root = find_xml_node(conf_root, "devices", FALSE);
	if(device_root == NULL) {
		crm_err("guest [%s] does not have setting of device.", guest->name);
		goto end;
	}

	crm_free(guest->sock_path);
	xml_child_iter_filter(device_root, channel, "channel",
		target_node = find_xml_node(channel, "target", FALSE);
		/* excludes you anything other than <target name=vmconnectd> */
		if(safe_str_neq(SCD_NAME, crm_element_value(target_node, "name"))) {
			crm_debug_3("target [%s] which this channel has is not [%s].",
				crm_element_value(target_node, "name"), SCD_NAME);
			continue;
		}

		/* When multiple effective sock_path are set; an error */
		if(guest->sock_path != NULL) {
			crm_err("multiple channels for vm-connectd are set");
			goto end;
		}

		source_node = find_xml_node(channel, "source", FALSE);
		sock_path = optimize_path(crm_element_value(source_node, "path"));
		if(sock_path == NULL) {
			crm_err("guest resource [%s] does not have an effective socket path [%s].",
				(char *)key, guest->conf_path);
			goto end;
		}

		/* check guest directory path */
		if(g_ascii_strncasecmp(sock_dir, sock_path, strlen(sock_dir)) != 0) {
			crm_err("not the socket path [%s] of the guest in a setting directory [%s].",
				sock_path, sock_dir);
			goto end;
		} else if(g_strrstr(sock_path+strlen(sock_dir), "/") != NULL) {
			crm_err("not the socket path [%s] of the guest in a setting directory [%s].",
				sock_path, sock_dir);
			goto end;
		}

		guest->sock_path = crm_strdup(sock_path);
		crm_debug_3("socket file path [%s].", guest->sock_path);
		crm_free(sock_path);
	);

	/* connect to guest socket */
	if(guest->sock_path != NULL) {
		rc = connect_to_guest(guest);
		if(rc > 0 && guest->reconnect_timer == 0) {
			crm_info("guest [%s] tries connection again.", guest->name);
			guest->reconnect_timer = g_timeout_add(1000, reconnect_to_guest, guest);
			crm_debug_3("guest reconnect timer [%d].", guest->reconnect_timer);
		}
	}

end:
	crm_free(sock_path);
	free_xml(conf_root);
	return;
}

static int
create_guest_info_for_cib(void)
{
	guest_t *guest = NULL;
	const char *conf_path = NULL;
	xmlNode *cib_copy = NULL;
	xmlNode *resources = NULL;
	xmlNode *attr_set = NULL;

	crm_debug_2("called..");
	cib_copy = get_cib_copy(cib_conn);
	if(cib_copy == NULL) {
		crm_err("failed to get cib copy.");
		return -1;
	}

	resources = get_object_root(XML_CIB_TAG_RESOURCES, cib_copy);
	if(resources == NULL) {
		crm_err("failed to get resources node.");
		free_xml(cib_copy);
		return -1;
	}

	xml_child_iter_filter(resources, resource, XML_CIB_TAG_RESOURCE,
		/* VirtualDomain RA search */
		if(safe_str_neq("VirtualDomain", crm_element_value(resource, XML_ATTR_TYPE))) {
			continue;
		}
		attr_set = find_xml_node(resource, XML_TAG_ATTR_SETS, FALSE);
		xml_child_iter_filter(attr_set, param, XML_CIB_TAG_NVPAIR,
			if(safe_str_neq(crm_element_value(param, XML_NVPAIR_ATTR_NAME), "config")) {
				continue;
			}
			guest = g_hash_table_lookup(guest_hash, ID(resource));
			conf_path = crm_element_value(param, XML_NVPAIR_ATTR_VALUE);
			if(guest == NULL) {
				/* create new guest info */
				crm_malloc0(guest, sizeof(guest_t));
				guest->id = crm_strdup(ID(resource));
				guest->conf_path = crm_strdup(conf_path);
				g_hash_table_insert(guest_hash, guest->id, guest);
			} else {
				if(safe_str_eq(conf_path, guest->conf_path)) {
					crm_debug_3("already store guest config path %s.",
						guest->conf_path);
					continue;
				}
				crm_free(guest->conf_path);
				guest->conf_path = crm_strdup(conf_path);
			}
		);
	);

	g_hash_table_foreach(guest_hash, parse_libvirt_conf, NULL);
	free_xml(cib_copy);

	return 0;
}

static void
file_monitor_callback(GFileMonitor *monitor, GFile *file, GFile *other,
	GFileMonitorEvent event_type, gchar *unused)
{
	gchar *path = g_file_get_path(file);
	time_t timer = time(NULL);
	struct tm *date = localtime(&timer);
	char timestr[128];
	int rc;

	crm_debug_2("called..");
	strftime(timestr, sizeof(timestr)-1, "%H:%M:%S - ", date);

	switch (event_type) {
		case G_FILE_MONITOR_EVENT_CREATED:
			crm_debug_3("%s[%s] : CREATED.", timestr, path);
			/* GUEST INFO RECHECK */
			rc = create_guest_info_for_cib();
			if(rc < 0) {
				crm_err("failed to create guest information.");
			}
			break;
		default:
			break;
	}
	crm_free(path);

	return;
}

static int
connect_to_host(const char *port)
{
	int fd;

	crm_debug_2("called..");
	/* open host connection */
	fd = open(port, O_RDWR|O_NONBLOCK);
	if(fd < 0) {
		crm_perror(LOG_ERR, "No port found %s:", port);
		return -1;
	}

	/* set io watch event */
	hostch = g_io_channel_unix_new(fd);
	evid = g_io_add_watch_full(hostch, G_PRIORITY_DEFAULT, G_IO_IN|G_IO_ERR|G_IO_HUP,
		on_msg_arrived, NULL, NULL); 
	crm_info("create host socket [%d] io watch event id [%d].", fd, evid);

	return fd;
}

static struct crm_option long_options[] = {
	/* Top-level Options */
	{"type",	1, 0, 't', "\tset the type of the domain to carry out in \"host\" or \"guest\""},
	{"daemonize",	0, 0, 'D', "\tRun in daemon mode"},
	{"pid-file",	1, 0, 'p', "\tFile in which to store the process' PID"},
	{"sock-dir",	1, 0, 'd', "\tSocket file directory"},
	{"verbose",	0, 0, 'V', "\t\tIncrease debug output"},
	{"help",	0, 0, '?', "\t\tThis text"},
	{0, 0, 0, 0}
};

static gboolean
detect_connection_client(GIOChannel *channel, GIOCondition condition, gpointer unused)
{
	crm_debug_2("called..");
	if(g_main_context_find_source_by_id(NULL, evid) == NULL) {
		crm_info("reconnect it to a host.");
		sock_host = connect_to_host(SCD_PATH "/" SCD_NAME);
		return TRUE;
	}
	crm_debug_3("already connected to the host.");

	return TRUE;
}

int
main(int argc, char **argv)
{
	int argerr = 0;
	int option_index = 0;
	int flag;
	int rc;
	const char *domain_type = NULL;
	const char *pid_file = NULL;
	gboolean daemonize = FALSE;
	pid_file = "/var/run/vm-connectd.pid";
	sock_dir = GUEST_SOCKDIR;

	signal(SIGINT, vm_connectd_shutdown);
	signal(SIGTERM, vm_connectd_shutdown);
	signal(SIGPIPE, SIG_IGN);
	crm_log_init(basename(argv[0]), LOG_INFO, TRUE, FALSE, argc, argv);
	crm_set_options("Dp:d:V?t:", "-t [host|guest] [Options]", long_options,
			"This daemon performs a host, communication"
			" between guests with serial communication.");

	/* option */
	while (1) {
		flag = crm_get_option(argc, argv,  &option_index);
		if (flag == -1)
			break;

		switch(flag) {
			case 'D':
				daemonize = TRUE;
				break;
			case 'p':
				pid_file = optarg;
				break;
			case 'd':
				sock_dir = optarg;
				break;
			case 'V':
				cl_log_enable_stderr(TRUE);
				alter_debug(DEBUG_INC);
				break;
			case '?':
				crm_help(flag, LSB_EXIT_OK);
				break;
			case 't':
				domain_type = optarg;
				break;
			default:
				printf("Argument code 0%o (%c) is not (?yet?) supported\n",
					flag, flag);
				crm_err("Argument code 0%o (%c) is not (?yet?) supported",
					flag, flag);
				++argerr;
				break;
		}
	}

	if (optind < argc) {
		crm_err("non-option ARGV-elements: ");
		printf("non-option ARGV-elements: ");
		while (optind < argc) {
			crm_err("%s ", argv[optind]);
			printf("%s ", argv[optind++]);
		}
		printf("\n");
	}

	if (argerr) {
		crm_help(flag, LSB_EXIT_GENERIC);
	}

	if(safe_str_neq("host", domain_type) && safe_str_neq("guest", domain_type)) {
		crm_err("There was not the setting of the type.");
		crm_help(flag, LSB_EXIT_GENERIC);
	}

	crm_make_daemon(crm_system_name, daemonize, pid_file);

	/* create daemon socket */
	listen_sock = listen_to(SOCK_PATH);
	if(listen_sock < 0) {
		crm_err("failed to create listen socket.");
		exit(1);
	}

	if(safe_str_eq("host", domain_type)) {
		char *tmp = NULL;
		tmp = g_strjoin("", sock_dir, "/", NULL);
		sock_dir = optimize_path(tmp);
		g_free(tmp);
		/* create guest hash */
		guest_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
							NULL, free_guest_info);

		rc = cib_connect(NULL);
		if(rc < 0) {
			crm_err("failed to connect to cib.");
			exit(1);
		}

		rc = create_guest_info_for_cib();
		if(rc < 0) {
			crm_err("failed to create guest information.");
			exit(1);
		}

		set_file_monitor(sock_dir);

	} else if(safe_str_eq("guest", domain_type)) {
		on_host = FALSE;
		sock_host = connect_to_host(SCD_PATH "/" SCD_NAME);
		if(sock_host < 0) {
			crm_err("failed to connect to host.");
			exit(1);
		}

		g_io_add_watch_full(g_io_channel_unix_new(listen_sock),
					G_PRIORITY_DEFAULT, G_IO_IN|G_IO_HUP,
					detect_connection_client, NULL, NULL);

	}

	mainloop = g_main_loop_new(NULL, FALSE);
	mainloop_add_signal(SIGTERM, vm_connectd_shutdown);
	mainloop_add_signal(SIGINT, vm_connectd_shutdown);
	
	crm_info("Starting.");
	g_main_loop_run(mainloop);

	if(cib_conn) {
		cib_conn->cmds->signoff(cib_conn);
		cib_delete(cib_conn);
	}

	crm_info("Exitting.");
	return 0;
}

