/*
 * vm_connect : Simple program which communicates between vm_connectd.
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
#include <unistd.h>
#include <libgen.h>
#include <crm/crm.h>
#include <vm_connect.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

extern gboolean on_host;	/* lib/vm_connect.c */

#define OPTARGS "t:i:R:r:Vq?"

static void
usage(const char *cmd, int exitstatus)
{
	fprintf(stderr, "\nusage: %s -t type command\n", cmd);
	fprintf(stderr, "\n  Request data is sent to host(server process) via vm-connectd process\n");

	fprintf(stderr, "\nnecessary options:\n");
	fprintf(stderr, "  -%c, --%s=value\t\tSpecify 'monitor' OR 'stonith'\n", 't', "type");

	fprintf(stderr, "\ncommands:\n");
	fprintf(stderr, "  -%c, --%s=value\t\tRequest to server process, and receive result\n",
		'r', "request");
	fprintf(stderr, "  -%c, --%s=value\tRequest to server process\n",
		'R', "request-only");

	fprintf(stderr, "\noptions:\n");
	fprintf(stderr, "  -%c, --%s=value\t\tSpecify request ID\n", 'i', "reqid");
	fprintf(stderr, "  -%c, --%s\t\t\tIncrease the debug output\n", 'V', "verbose");
	fprintf(stderr, "  -%c, --%s\t\t\tControl the output of log\n", 'q', "quiet");
	fprintf(stderr, "  -%c, --%s\t\t\tThis text\n", '?', "help");

	fprintf(stderr, "\n");
	exit(exitstatus);
}

int
main(int argc, char **argv)
{
	msgtype type = -1;
	char *request = NULL;
	gboolean request_only = FALSE;
	char *reqid = NULL;
	int loglevel = LOG_INFO;
	gboolean verbose = FALSE;
	gboolean quiet = FALSE;
	int argerr = 0, flag;
#ifdef HAVE_GETOPT_H
	int opt_idx = 0;
	static struct option long_opts[] = {
		{"type",		1, 0, 't'},
		{"request",		1, 0, 'r'},
		{"request-only",	1, 0, 'R'},
		{"reqid",		1, 0, 'i'},
		{"verbose",		0, 0, 'V'},
		{"quiet",		0, 0, 'q'},
		{"help",		0, 0, '?'},
		{0, 0, 0, 0}
	};
#endif
	int sockfd, rc, ret = 0;
	vm_message msg;

	while (1) {
#ifdef HAVE_GETOPT_H
		flag = getopt_long(argc, argv, OPTARGS, long_opts, &opt_idx);
#else
		flag = getopt(argc, argv, OPTARGS);
#endif
		if (flag == -1)
			break;
		switch (flag) {
		case 't':
			if (safe_str_eq(optarg, "monitor"))
				type = T_MOD_MONITOR;
			else if (safe_str_eq(optarg, "stonith"))
				type = T_MOD_STONITH;
			break;
		case 'r':
			request = crm_strdup(optarg);
			break;
		case 'R':
			request_only = TRUE;
			request = crm_strdup(optarg);
			break;
		case 'i':
			reqid = crm_strdup(optarg);
			break;
		case 'V':
			loglevel++;
			verbose = TRUE;
			break;
		case 'q':
			quiet = TRUE;
			break;
		case '?':
			usage(basename(argv[0]), LSB_EXIT_GENERIC);
			break;
		default:
			fprintf(stderr, "Argument code 0%o (%c) is not (?yet?) supported",
				flag, flag);
			argerr++;
			break;
		}
	}

	if (!quiet)
		crm_log_init(basename(argv[0]), loglevel, TRUE, verbose, argc, argv);
	else
		crm_log_init(basename(argv[0]), loglevel, TRUE, verbose, 0, NULL);

	if (optind < argc) {
		fprintf(stderr, "non-option ARGV-elements: ");
		while (optind < argc)
			fprintf(stderr, "%s", argv[optind++]);
		fprintf(stderr, "\n");
		argerr++;
	}
	if (argerr || type == -1 || !request)
		usage(crm_system_name, LSB_EXIT_GENERIC);

	on_host = FALSE;
	if ((sockfd = connect_to(SOCK_PATH, 0)) < 0)
		return 1;
	if (send_message(sockfd, type, reqid, request) < 0) {
		ret = 1;
		goto end;
	}
	if (request_only == TRUE)
		goto end;

	while (1) {
		rc = receive_msg(sockfd, &msg);
		if (rc == 0) {
			if (reqid && safe_str_neq(reqid, msg.info.id)) {
				crm_info("request ID (%s) is unmatch : %s", reqid, msg.info.id);
				continue;
			}
			else {
				fprintf(stdout, "%s\n", msg.data);
				goto end;
			}
		}
		else if (rc == 2) {
			/* migration occurred.. */
			ret = 2;
			goto end;
		}
		ret = 1;
		goto end;
	}
end:
	close(sockfd);
	return ret;
}
