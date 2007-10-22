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
 * Copyright (C) 2007 Novell, Inc.
 */

/*
 * AUTHORS: jacob berkman <jberkman@novell.com>
 */
#ifndef SC_ERROR_H
#define SC_ERROR_H

#include <stdarg.h>
#include <glib/gerror.h>

#include "sclog.h"

void sc_set_error_full (GError     **err,
                        GQuark       domain,
                        gint         code,
                        const gchar *file,
                        guint        line,
                        const gchar *function,
                        const gchar *format,
                        ...) G_GNUC_PRINTF (7, 8);

#ifdef G_HAVE_ISO_VARARGS
#define sc_set_error(err, domain, code, ...) sc_set_error_full (err, domain, code, __FILE__, __LINE__, SC_FUNCTION, __VA_ARGS__)
#elif defined (G_HAVE_GNUC_VARARGS)
#define sc_set_error(err, domain, code, format...) sc_set_error_full (err, domain, code, __FILE__, __LINE__, SC_FUNCTION, format)
#else /* no varargs macros */
#define sc_set_error g_set_error
#endif

#endif /* SC_ERROR_H */
