MAINTAINERCLEANFILES	= Makefile.in

INCLUDES		= -I/usr/include/pacemaker \
			  -I/usr/include/glib-2.0 \
			  -I$(libdir)/glib-2.0/include \
			  -I/usr/include/libxml2

lib_LTLIBRARIES		= libvmconnect.la
libvmconnect_la_SOURCES	= vm_connect.c
libvmconnect_la_LDFLAGS	= -version-info 1:0:0
libvmconnect_la_LDFLAGS += -lplumb -lcrmcommon

AM_CFLAGS		= -Wall -Werror -fPIC
