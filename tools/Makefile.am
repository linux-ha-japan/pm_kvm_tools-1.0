MAINTAINERCLEANFILES	= Makefile.in

INCLUDES		= -I/usr/include/pacemaker \
			  -I/usr/include/glib-2.0 \
			  -I$(libdir)/glib-2.0/include \
			  -I/usr/include/libxml2

sbin_PROGRAMS		= vm-connectd vm-connect vm-managerd vm-stonithd

vm_connectd_SOURCES	= vm-connectd.c
vm_connectd_LDADD	= $(top_builddir)/lib/libvmconnect.la \
			  -lgio-2.0 \
			  -lcrmcommon \
			  -lcib

vm_connect_SOURCES	= vm-connect.c
vm_connect_LDADD	= $(top_builddir)/lib/libvmconnect.la

vm_managerd_SOURCES	= vm-managerd.c
vm_managerd_LDADD	= $(top_builddir)/lib/libvmconnect.la \
			  -lcrmcommon \
			  -lcrmcluster \
			  -lcib \
			  -lxml2

vm_stonithd_SOURCES	= vm-stonithd.c
vm_stonithd_LDADD	= $(top_builddir)/lib/libvmconnect.la \
			  -lcib \
			  -lpe_status \
			  -lncurses

AM_CFLAGS		= -Wall -Werror
