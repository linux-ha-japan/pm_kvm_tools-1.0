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

#ifndef VM_CONNECT_H
#define VM_CONNECT_H

#include <config.h>
#include <glib.h>

#define SOCK_PATH		"/var/run/vmconnectd.sock"
#define GUEST_SOCKDIR		"/var/lib/libvirt/qemu"
#define SCD_PATH		"/dev/virtio-ports"
#define SCD_NAME		"vmconnectd"

typedef enum msgtype_s {	/* sequence of elements has to start from 0 */
	T_MOD_MONITOR = 0,	/* status monitor (server) module */
	T_MOD_STONITH,		/* STONITH function (server) module */
	T_MIGRATION_OCCURRED,
	T_CLIENT_NOT_CONNECT
} msgtype;

typedef struct msginfo_s
{
	msgtype type;
	char id[64];		/* message ID */
	int sock_client;	/* endpoint with client process */
	int sock_guest;		/* endpoint with guest */
	guint datalen;
} msginfo;

typedef struct vm_message_s
{
	msginfo info;
	char *data;
} vm_message;

int listen_to(const char *sock_path);
int connect_to(const char *sock_path, msgtype type);
int send_message(int sockfd, msgtype type, const char *msgid, const char *data);
int send_msg(int sockfd, const vm_message *msg);
int receive_msg(int sockfd, vm_message *msg);
void on_migration_occurred(void);
gboolean on_msg_arrived(GIOChannel *channel, GIOCondition condition, gpointer unused);

#endif /* VM_CONNECT_H */
