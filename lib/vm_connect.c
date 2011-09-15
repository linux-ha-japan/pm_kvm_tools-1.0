/*
 * vm_connect : Communication routines for the pm_kvm_tools.
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

#include <stdio.h>
#include <unistd.h>
#include <sys/un.h>
#include <errno.h>
#include <crm/crm.h>
#include <vm_connect.h>

GHashTable *io_watch;		/* GHashTable indexed by sockfd */
int sock_server[2];		/* endpoints with server process */
int sock_host;			/* endpoint with host */
gboolean on_host = TRUE;

static void
vm_connect_free(gpointer free_obj)
{
	g_free(free_obj);
	free_obj = NULL;

	return;
}

static int
deliver_msg(int sockfd, const vm_message *msg)
{
	ssize_t size;
	gpointer tmpmsg;

	crm_debug_2("called..");
	crm_malloc0(tmpmsg, sizeof(msginfo)+msg->info.datalen+1);
	memcpy(tmpmsg, msg, sizeof(msginfo));
	memcpy(tmpmsg+sizeof(msginfo), msg->data, msg->info.datalen);
	size = write(sockfd, tmpmsg, sizeof(msginfo)+msg->info.datalen);
	crm_free(tmpmsg);
	if (size < 0) {
		cl_perror("write(2) call failed");
		return -1;
	}
	return 0;
}

gboolean
on_msg_arrived(GIOChannel *channel, GIOCondition condition, gpointer unused)
{
	int sockfd;
	int rc;
	crm_debug_2("called..");
	crm_debug_3("condition is [%d]", condition);
	sockfd = g_io_channel_unix_get_fd(channel);
	crm_debug_3("on message socket [%d]", sockfd);

	if (condition & G_IO_IN) {
		vm_message msg;

		rc = receive_msg(sockfd, &msg);
		if (rc < 0 || rc == 1) {
			g_io_channel_unref(channel);
			return FALSE;
		}

		rc = 0;
		if (on_host) {
			if (msg.info.sock_guest) {
				/* send to guest */
				crm_debug("deliver msg socket [%d] => socket [%d]",
					sockfd, msg.info.sock_guest);
				rc = deliver_msg(msg.info.sock_guest, &msg);
				if(rc < 0) {
					/* ゲストへの配送に失敗 */
					crm_err("failed to deliver message to guest socket [%d]",
						msg.info.sock_guest);
				}
			}
			else {
				if (msg.info.sock_client) {
					/* send to client on host */
					msg.info.sock_guest = sockfd;
					/*
					 * 対象のクライアントが接続されていない場合再送を要求
					 * ゲストとの接続は保持
					 */
					if(sock_server[msg.info.type] == 0) {
						crm_err("client is not connected");
						crm_free(msg.data);
						msg.info.datalen = 0;
						msg.info.type = T_CLIENT_NOT_CONNECT;
						rc = deliver_msg(msg.info.sock_guest, &msg);
						return TRUE;
					}
					crm_debug("deliver msg socket [%d] => socket [%d]",
						sockfd, sock_server[msg.info.type]);
					rc = deliver_msg(sock_server[msg.info.type], &msg);
					if(rc < 0) {
						/* ホスト上のクライアントへの配送に失敗 */
						crm_err("failed to deliver message to client [%d]"
							" on the host", sock_server[msg.info.type]);
					}
				}
				else {
					/* クライアントが接続してきたとき */
					sock_server[msg.info.type] = sockfd;
					switch(msg.info.type) {
						case T_MOD_MONITOR:
							crm_info("vm-managerd is connected.");
							break;
						case T_MOD_STONITH:
							crm_info("vm-stonithd is connected.");
							break;
						default:
							break;
					}
				}
			}
		}
		else {
			/*
			 * on guest
			 */
			if (msg.info.type == T_MIGRATION_OCCURRED) {
				on_migration_occurred();
				return TRUE;
			}
			if (msg.info.sock_client) {
				/* send to client on guest */
				crm_debug("deliver msg socket [%d] => socket [%d]",
					sockfd, msg.info.sock_client);
				rc = deliver_msg(msg.info.sock_client, &msg);
				if(rc < 0) {
					/*
					 * ゲスト上のクライアントへの配送に失敗
					 */
					crm_debug("failed to deliver message to client [%d]"
						" on the guest", msg.info.sock_client);
				}
			}
			else {
				msg.info.sock_client = sockfd;
				/* send to hypervisor */
				crm_debug("deliver msg socket [%d] => socket [%d]",
					sockfd, sock_host);
				rc = deliver_msg(sock_host, &msg);
				if(rc < 0) {
					/* ホストへの配送に失敗 */
					crm_err("failed to deliver message to host socket [%d]",
						sock_host);
				}
			}
		}
		crm_free(msg.data);

	}
	else if (condition & G_IO_ERR) {
		crm_debug_3("G_IO_ERR");
	}
	else if (condition & G_IO_HUP) {
		crm_debug_3("G_IO_HUP");
		if(!on_host) {
			on_migration_occurred();
		}
		crm_info("close connection with the socket [%d].", sockfd);
		close(sockfd);
		g_io_channel_unref(channel);
		return FALSE;
	}

	return TRUE;
}

/*
 * called when there is message to receive.
 */
static gboolean
on_listen(GIOChannel *channel, GIOCondition condition, gpointer unused)
{
	crm_debug_2("called...");

	if (condition & G_IO_IN) {
		int *sockfd = g_new(int, 1);
		struct sockaddr_un addr;
		socklen_t addrlen = sizeof(addr);
		guint *sourceid = g_new(guint, 1);

		*sockfd = accept(g_io_channel_unix_get_fd(channel),
				(struct sockaddr*)&addr, &addrlen);
		if (*sockfd < 0) {
			cl_perror("accept(2) call failed");
			return TRUE;
		}
		crm_debug_3("accept a client connection, socket [%d] on %s",
			*sockfd, on_host ? "host" : "guest");
		*sourceid = g_io_add_watch_full(g_io_channel_unix_new(*sockfd),
				G_PRIORITY_DEFAULT, G_IO_IN|G_IO_ERR|G_IO_HUP,
				on_msg_arrived, NULL, NULL);
		crm_debug_4("insert io watch source id [%d]", *sourceid);
		g_hash_table_insert(io_watch, sockfd, sourceid);
	}
	else if (condition & G_IO_HUP) {
		crm_debug_3("G_IO_HUP");
	}
	return TRUE;
}

/*
 * create socket and listen for waiting message.
 */
int
listen_to(const char *sock_path)
{
	int sockfd;
	int rc;
	struct sockaddr_un addr;

	crm_debug_2("called..");

	sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) {
		cl_perror("socket(2) call failed");
		return -1;
	}
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	g_strlcpy(addr.sun_path, sock_path, sizeof(addr.sun_path)-1);

	unlink(sock_path);
	rc = bind(sockfd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un));
	if (rc < 0) {
		cl_perror("bind(2) call failed");
		goto cleanup_close;
	}
	rc = listen(sockfd, SOMAXCONN);
	if (rc < 0) {
		cl_perror("listen(2) call failed");
		goto cleanup_close;
	}

	/* create source for socket and add to the mainloop */
	g_io_add_watch_full(g_io_channel_unix_new(sockfd),
		G_PRIORITY_DEFAULT, G_IO_IN|G_IO_HUP, on_listen, NULL, NULL);

	io_watch = g_hash_table_new_full(g_int_hash, g_int_equal, vm_connect_free, vm_connect_free);
	return sockfd;

cleanup_close:
	close(sockfd);
	return -1;
}

int
connect_to(const char *sock_path, msgtype type)
{
	int sockfd;
	int rc;
	struct sockaddr_un addr;

	crm_debug_2("called..");

	sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) {
		cl_perror("socket(2) call failed");
		return -1;
	}
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	g_strlcpy(addr.sun_path, sock_path, sizeof(addr.sun_path)-1);

	rc = connect(sockfd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un));
	if (rc < 0) {
		cl_perror("connect(2) call failed");
		close(sockfd);
		return -1;
	}

	/* デーモンからの接続時ソケットをタイプ別にsock_serverに保存 */
	if (on_host == TRUE) {
		rc = send_message(sockfd, type, NULL, NULL);
		if (rc < 0) {
			close(sockfd);
			return -1;
		}
	}
	return sockfd;
}

int
send_message(int sockfd, msgtype type, const char *msgid, const char *data)
{
	vm_message msg;

	crm_debug_2("called..");

	memset(&msg, 0, sizeof(vm_message));
	msg.info.type = type;
	if (msgid) {
		g_strlcpy(msg.info.id, msgid, sizeof(msg.info.id)-1);
	}
	if (data) {
		msg.info.datalen = strlen(data);
		msg.data = (char*)data;
	}
	return deliver_msg(sockfd, &msg);
}

int
send_msg(int sockfd, const vm_message *msg)
{
	crm_debug_2("called..");
	return deliver_msg(sockfd, msg);
}

/*
 * Returns array of pointer [msg->data], call free() after use.
 * return:
 *	 0: success - message was received
 *	 1: if socket was closed
 *	 2: if message (LiveMigration occurred) was received
 *	-1: if system call error occurred
 */
int
receive_msg(int sockfd, vm_message *msg)
{
	int rc, i;

	crm_debug_2("called..");

	memset(msg, 0, sizeof(vm_message));

	rc = read(sockfd, msg, sizeof(msginfo));
	if (rc < 0) {
		cl_perror("read(2) call failed");
		return -1;
	}
	else if (rc == 0) {
		/* EOF -> closed socket */
		for(i=0; i<2; i++) {
			/* remove client socket info */
			if(sock_server[i] == sockfd) {
				sock_server[i] = 0;
			}
		}

		/* close client socket */
		close(sockfd);
		crm_debug("closed socket [%d]", sockfd);

		if (io_watch != NULL) {
			gpointer sourceid = g_hash_table_lookup(io_watch, (gpointer*)&sockfd);
			if (sourceid != NULL) {
				crm_debug_4("remove io watch source id [%d]", *(guint*)sourceid);
				g_source_remove(*(guint*)sourceid);
				g_hash_table_remove(io_watch, (gpointer*)&sockfd);
			}
		}
		return 1;
	}
	crm_debug_3("read(%d, hdr): [%d:%s:%u]",
		sockfd, msg->info.type, msg->info.id, msg->info.datalen);
	if (msg->info.type == T_MIGRATION_OCCURRED || msg->info.type == T_CLIENT_NOT_CONNECT)
		return 2;
	if (msg->info.datalen > 0) {
		crm_malloc0(msg->data, msg->info.datalen+1);
		rc = read(sockfd, msg->data, msg->info.datalen);
		if (rc < 0) {
			cl_perror("read(2) call failed");
			g_free(msg->data);
			return -1;
		}
		crm_debug_3("read(%d, data): [%s]", sockfd, msg->data);
	}
	return 0;
}

static void
send_migration_occurred(gpointer key, gpointer value, gpointer unused)
{
	crm_debug_2("called..");

	send_message(*(int*)key, T_MIGRATION_OCCURRED, NULL, NULL);
	return;
}

/*
 * this function which should be called when connection with host is lost
 * (SIGHUP) on guest.
 */
void
on_migration_occurred(void)
{
	crm_debug_2("called..");

	crm_debug_3("io_watch's size: %d", g_hash_table_size(io_watch));
	g_hash_table_foreach(io_watch, send_migration_occurred, NULL);
	return;
}

