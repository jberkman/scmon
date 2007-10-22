# -*- Makefile -*-
sbin_PROGRAMS += scmon

scmon_SOURCES :=				\
	monitor/scmon.c				\
	monitor/scdbuspk11monitor.c		\
	monitor/scdbuspk11monitor.h		\
	monitor/scerror.c			\
	monitor/scerror.h			\
	monitor/scinotify.c			\
	monitor/scinotify.h			\
	monitor/sclog.c				\
	monitor/sclog.h				\
	monitor/scnss.c				\
	monitor/scnss.h				\
	monitor/scnssmonitor.c			\
	monitor/scnssmonitor.h			\
	monitor/scpk11monitor-forks.c		\
	monitor/scpk11monitor-threads.c		\
	monitor/scpk11monitor.h

scmon_CFLAGS :=					\
	$(MONITOR_CFLAGS)			\
	-I$(top_srcdir)/monitor			\
	-I$(top_builddir)/monitor		\
	-DSCMON_THREADED=1

scmon_LDADD := $(MONITOR_LIBS) # $(top_builddir)/libgpcsc.la

monitor/scdbuspk11monitor.c: monitor/com.novell.Pkcs11Monitor-server.h

monitor/com.novell.Pkcs11Monitor-server.h: monitor/com.novell.Pkcs11Monitor.interface monitor/Makefile.inc
	@dbus-binding-tool --prefix=pk11_monitor --mode=glib-server $< > $@.tmp
	@if ! cmp $@.tmp $@ >/dev/null 2>/dev/null ; then				   \
		echo "dbus-binding-tool --prefix=pk11_monitor --mode=glib-server $< > $@"; \
		mv -f $@.tmp $@;							   \
	fi
	@rm -f $@.tmp

CLEANFILES += monitor/com.novell.Pkcs11Monitor-server.h

dbussystemdir = $(sysconfdir)/dbus-1/system.d
dbussystem_DATA := monitor/com.novell.Pkcs11Monitor.conf

dbusservicedir = $(datadir)/dbus-1/services
dbusservice_DATA := monitor/com.novell.Pkcs11Monitor.service

EXTRA_DIST +=					    \
	monitor/com.novell.Pkcs11Monitor.conf	    \
	monitor/com.novell.Pkcs11Monitor.interface  \
	monitor/com.novell.Pkcs11Monitor.service.in

monitor/all: scmon
monitor/clean: clean
