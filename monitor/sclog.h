/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

/*
 * Copyright (C) 2006 Ray Strode <rstrode@redhat.com>
 * Copyright (C) 2007 Novell, Inc.
 */

/*
 * AUTHORS: Ray Strode <rstrode@redhat.com>
 *          jacob berkman <jberkman@novell.com>
 */
#ifndef SC_LOG_H
#define SC_LOG_H

#include <stdio.h>
#include <glib/gmessages.h>
#include <glib/gerror.h>

#define SC_LOG_ERROR (sc_log_error_quark ())
GQuark sc_log_error_quark (void);

typedef enum {
    SC_LOG_ERROR_GENERIC = 0,
} ScLogError;

int sc_log_add_fd (int fd, GError **);
int sc_log_add_file_name (const char *filename, GError **);
void sc_log_use_syslog (gboolean torf);

void sc_log (const gchar    *log_domain,
             GLogLevelFlags  log_level,
             const gchar    *file,
             guint           line,
             const gchar    *function,
             const gchar    *format,
             ...) G_GNUC_PRINTF (6, 7);

#if defined (__GNUC__) && (__GNUC__ > 3) || (__GNUC__ == 3 && (__GNUC_MINOR__ >= 2))
#define SC_FUNCTION __func__
#elif defined (__GNUC__) && (__GNUC__ < 3)
#define SC_FUNCTION __FUNCTION__
#else
#define SC_FUNCTION ""
#endif

#ifdef G_HAVE_ISO_VARARGS
#define sc_error(...)    sc_log (G_LOG_DOMAIN,                          \
                                 G_LOG_LEVEL_ERROR,                     \
                                 __FILE__, __LINE__, SC_FUNCTION,       \
                                 __VA_ARGS__)
#define sc_message(...)  sc_log (G_LOG_DOMAIN,                          \
                                 G_LOG_LEVEL_MESSAGE,                   \
                                 __FILE__, __LINE__, SC_FUNCTION,       \
                                 __VA_ARGS__)
#define sc_critical(...) sc_log (G_LOG_DOMAIN,                          \
                                 G_LOG_LEVEL_CRITICAL,                  \
                                 __FILE__, __LINE__, SC_FUNCTION,       \
                                 __VA_ARGS__)
#define sc_warning(...)  sc_log (G_LOG_DOMAIN,                          \
                                 G_LOG_LEVEL_WARNING,                   \
                                 __FILE__, __LINE__, SC_FUNCTION,       \
                                 __VA_ARGS__)
#define sc_debug(...)    sc_log (G_LOG_DOMAIN,                          \
                                 G_LOG_LEVEL_DEBUG,                     \
                                 __FILE__, __LINE__, SC_FUNCTION,       \
                                 __VA_ARGS__)
#elif defined(G_HAVE_GNUC_VARARGS)
#define sc_error(format...)      sc_log (G_LOG_DOMAIN,                  \
                                         G_LOG_LEVEL_ERROR,             \
                                         __FILE__, __LINE__, SC_FUNCTION, \
                                         format)
#define sc_message(format...)    sc_log (G_LOG_DOMAIN,                  \
                                         G_LOG_LEVEL_MESSAGE,           \
                                         __FILE__, __LINE__, SC_FUNCTION, \
                                         format)
#define sc_critical(format...)   sc_log (G_LOG_DOMAIN,                  \
                                         G_LOG_LEVEL_CRITICAL,          \
                                         __FILE__, __LINE__, SC_FUNCTION, \
                                         format)
#define sc_warning(format...)    sc_log (G_LOG_DOMAIN,                  \
                                         G_LOG_LEVEL_WARNING,           \
                                         __FILE__, __LINE__, SC_FUNCTION, \
                                         format)
#define sc_debug(format...)      sc_log (G_LOG_DOMAIN,                  \
                                         G_LOG_LEVEL_DEBUG,             \
                                         __FILE__, __LINE__, SC_FUNCTION, \
                                         format)
#else   /* no varargs macros */
#define sc_error g_error
#define sc_message g_message
#define sc_critical g_critical
#define sc_warning g_warning
#define sc_debug g_debug
#endif  /* !__GNUC__ */

#if 1
#define SC_ENTER (sc_debug ("ENTER"))
#define SC_EXIT (sc_debug ("EXIT"))
#define SC_HASLOCK (sc_debug ("HAS LOCK"))
#define SC_LOCKED (sc_debug ("ALREADY LOCKED"))
#else
#define SC_ENTER
#define SC_EXIT
#define SC_HASLOC
#define SC_LOCKED
#endif

#endif /* SC_LOG_H */
