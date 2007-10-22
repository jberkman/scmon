# -*- Makefile -*-
bin_PROGRAMS += scmon-client

scmon_client_SOURCES :=			\
	listener/scmon-client.c

scmon_client_CFLAGS :=				\
	$(LISTENER_CFLAGS)			\
	-I$(top_srcdir)/listener		\
	-I$(top_builddir)/listener

scmon_client_LDADD := $(LISTENER_LIBS)

listener/scmon-client.c: listener/com.novell.Pkcs11Monitor-client.h

listener/com.novell.Pkcs11Monitor-client.h: monitor/com.novell.Pkcs11Monitor.interface listener/Makefile.inc
	@dbus-binding-tool --prefix=pk11_listener --mode=glib-client $< > $@.tmp
	@if ! cmp $@.tmp $@ >/dev/null 2>/dev/null ; then				    \
		echo "dbus-binding-tool --prefix=pk11_listener --mode=glib-client $< > $@"; \
		mv -f $@.tmp $@;							    \
	fi
	@rm -f $@.tmp

CLEANFILES += listener/com.novell.Pkcs11Monitor-client.h

listener/all: scmon-client
listener/clean: clean
