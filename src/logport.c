/*
   Log and info output ports for Guile.

   This file is part of GNU Anubis.
   Copyright (C) 2003-2024 The Anubis Team.

   GNU Anubis is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 3 of the License, or (at your
   option) any later version.

   GNU Anubis is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with GNU Anubis.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "headers.h"
#include "extern.h"
#include "rcfile.h"

#ifdef WITH_GUILE

static scm_t_port_type *scm_anubis_log_port_type;

#define GET_LOG_PORT(x) ((struct anubis_log_port *) SCM_STREAM (x))

enum { PORT_LOG_INFO, PORT_LOG_ERROR };

struct anubis_log_port {
  int type;
  int flag; /* For error ports: -1 if error, >=0 if warning;
	       For info ports: verbosity level */
};

static size_t
log_port_write (SCM port, SCM src, size_t start, size_t count)
{
  struct anubis_log_port *lp = GET_LOG_PORT (port);
  signed char *str = SCM_BYTEVECTOR_CONTENTS (src) + start;
  int n = count;
  if (str[n-1] == '\n')
    n--;
  switch (lp->type)
    {
    case PORT_LOG_INFO:
      info (lp->flag, "%*.*s", n, n, str);
      break;

    case PORT_LOG_ERROR:
      if (lp->flag == -1)
	anubis_error (0, 0, "%*.*s", n, n, str);
      else
	anubis_warning (0, "%*.*s", n, n, str);
      break;
    }
  return count;
}

static int
log_port_print (SCM exp, SCM port, scm_print_state *pstate)
{
  scm_puts ("#<Anubis log port>", port);
  return 1;
}

void
guile_init_anubis_log_port (void)
{
  scm_anubis_log_port_type = scm_make_port_type ("anubis-log",
						 NULL, log_port_write);
  scm_set_port_print (scm_anubis_log_port_type, log_port_print);
  scm_set_port_needs_close_on_gc (scm_anubis_log_port_type, 1);
}    

static SCM
_make_anubis_log_port (int type, int flag)
{
  struct anubis_log_port *lp;

  lp = scm_gc_typed_calloc (struct anubis_log_port);
  lp->type = type;
  lp->flag = flag;
  return scm_c_make_port (scm_anubis_log_port_type,
			  SCM_WRTNG | SCM_BUFLINE, (scm_t_bits) lp);
}

SCM
guile_make_anubis_error_port (int err)
{
  return _make_anubis_log_port (PORT_LOG_ERROR, err);
}

SCM
guile_make_anubis_info_port (void)
{
  return _make_anubis_log_port (PORT_LOG_INFO, NORMAL);
}
  
#endif
