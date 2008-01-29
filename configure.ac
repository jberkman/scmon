#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([scmon], [0.4], [http://code.google.com/p/scmon/issues/list])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([monitor/scmon.c])
AC_CONFIG_HEADER([config.h])

# Honor aclocal flags
ACLOCAL="$ACLOCAL $ACLOCAL_FLAGS"

AC_ARG_ENABLE(kernel-workaround, 
  [  --enable-kernel-workaround],
  AC_DEFINE(NEED_KERNEL_FD_WORKAROUND, 1, [Define if you need the FD workaround]))

# Checks for packages
GLIB_REQUIRED_VERSION=2.7.0
NSS_REQUIRED_VERSION=3.11
DBUS_REQUIRED_VERSION=0.60

PKG_CHECK_MODULES(MONITOR,
	gobject-2.0 >= $GLIB_REQUIRED_VERSION
	gthread-2.0 >= $GLIB_REQUIRED_VERSION
	nss >= $NSS_REQUIRED_VERSION
	dbus-glib-1 >= $DBUS_REQUIRED_VERSION)
AC_SUBST(MONITOR_CFLAGS)
AC_SUBST(MONITOR_LIBS)

PKG_CHECK_MODULES(LISTENER,
	dbus-glib-1 >= $DBUS_REQUIRED_VERSION)
AC_SUBST(LISTENER_CFLAGS)
AC_SUBST(LISTENER_LIBS)

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_LIBTOOL

# Make libtool use --silent when --silent is passed to make
changequote(,)dnl
LIBTOOL="${LIBTOOL} \$(shell echo \"\$(MFLAGS)\" | awk '/^[^ ]*s/ { print \"--silent\" }')"
changequote([,])dnl

# Checks for libraries.

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h limits.h stdlib.h string.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_FORK
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([strerror strtol])

AC_MSG_CHECKING([which init style to use])
INIT_EXT=
if grep "SUSE Linux Enterprise" /etc/SuSE-release >/dev/null 2>/dev/null ; then
	AC_MSG_RESULT([SUSE Linux Enterprise])
	INIT_EXT="sle"
elif grep "openSUSE" /etc/SuSE-release >/dev/null 2>/dev/null ; then
	AC_MSG_RESULT([openSUSE])
	INIT_EXT="sle"
elif grep "SUSE LINUX" /etc/SuSE-release >/dev/null 2>/dev/null ; then
	AC_MSG_RESULT([SuSE Linux])
	INIT_EXT="sle"
else
	AC_MSG_RESULT([Unknown; no init files will be installed])
fi
AC_SUBST(INIT_EXT)
AM_CONDITIONAL(INSTALL_INIT_FILES, test x$INIT_EXT != x)

# taken from gnome-screensaver
REAL_PREFIX=
if test "x$prefix" = "xNONE"; then
  REAL_PREFIX=$ac_default_prefix
else
  REAL_PREFIX=$prefix
fi

## temporarily change prefix and exec_prefix
old_prefix=$prefix
prefix=$REAL_PREFIX

if test "x$exec_prefix" = xNONE ; then
   REAL_EXEC_PREFIX=$REAL_PREFIX
else
   REAL_EXEC_PREFIX=$exec_prefix
fi
old_exec_prefix=$exec_prefix
exec_prefix=$REAL_EXEC_PREFIX

## eval everything
LOCALSTATEDIR_TMP="$localstatedir"
EXPANDED_LOCALSTATEDIR=`eval echo $LOCALSTATEDIR_TMP`
AC_SUBST(EXPANDED_LOCALSTATEDIR)

SYSCONFDIR_TMP="$sysconfdir"
EXPANDED_SYSCONFDIR=`eval echo $SYSCONFDIR_TMP`
AC_SUBST(EXPANDED_SYSCONFDIR)

BINDIR_TMP="$bindir"
EXPANDED_BINDIR=`eval echo $BINDIR_TMP`
AC_SUBST(EXPANDED_BINDIR)

SBINDIR_TMP="$sbindir"
EXPANDED_SBINDIR=`eval echo $SBINDIR_TMP`
AC_SUBST(EXPANDED_SBINDIR)

LIBDIR_TMP="$libdir"
EXPANDED_LIBDIR=`eval echo $LIBDIR_TMP`
AC_SUBST(EXPANDED_LIBDIR)

DATADIR_TMP="$datadir"
EXPANDED_DATADIR=`eval echo $DATADIR_TMP`
AC_SUBST(EXPANDED_DATADIR)

## put prefix and exec_prefix back
prefix=$old_prefix
exec_prefix=$old_exec_prefix

AC_CONFIG_FILES([
Makefile
init/Makefile
listener/Makefile
monitor/Makefile
monitor/com.novell.Pkcs11Monitor.service
scmon.spec
])
AC_OUTPUT
