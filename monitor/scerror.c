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
#include "config.h"

#include "scerror.h"

#include <glib/gmem.h>
#include <glib/gstrfuncs.h>
#include <glib/gutils.h>
#include <string.h>

void
sc_set_error_full (GError     **err,
                   GQuark       domain,
                   gint         code,
                   const gchar *file,
                   guint        line,
                   const gchar *function,
                   const gchar *format,
                   ...)
{
    va_list args;
    gchar *s;
    const gchar *file2;

    if (!err) {
        return;
    }

    va_start (args, format);
    s = g_strdup_vprintf (format, args);
    va_end (args);

    file2 = strrchr (file, G_DIR_SEPARATOR);
    g_set_error (err, domain, code, "%s:%d:%s: %s", file2 ? file2 + 1 : "???", line, function, s);
    g_free (s);
}
