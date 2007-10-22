# -*- Makefile -*-

EXTRA_DIST += init/scmon.sle

initdir := $(sysconfdir)/init.d

init/scmon: init/scmon.$(INIT_EXT)
	cp $< $@

CLEANFILES += init/scmon

if INSTALL_INIT_FILES
init_SCRIPTS = init/scmon

install-data-hook::
	@if test x$$UID = x0 -a x$$DESTDIR = x ; then \
		echo "chkconfig --add scmon" ;	      \
		chkconfig --add scmon ;		      \
	fi

init/all: init/scmon
else
init/all:
endif
init/clean: clean
