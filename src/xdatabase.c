/*
   xdatabase.c

   This file is part of GNU Anubis.
   Copyright (C) 2004-2024 The Anubis Team.

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

void
xdatabase_capability (ANUBIS_SMTP_REPLY reply)
{
  if (!smtp_reply_has_capa (reply, "XDATABASE", NULL))
    smtp_reply_add_line (reply, "XDATABASE");
}

static FILE *
make_temp_file (char *rcname, char **name)
{
  struct stringbuf sb = STRINGBUF_INITIALIZER;
  struct timeval tv;
  char *p;
  FILE *fp;
  int save_umask;

  gettimeofday (&tv, NULL);
  stringbuf_printf (&sb, "%s.%s.%lu.%lu.%lu.tmp",
		    rcname,
		    get_localname (),
		    tv.tv_sec, tv.tv_usec,
		    (unsigned long) getpid ());

  p = *name = stringbuf_finish (&sb);

  save_umask = umask (077);
  fp = fopen (p, "w");
  if (!fp)
    anubis_error (0, errno, _("Cannot open temporary file %s: %s"),
		  p, strerror (errno));

  umask (save_umask);
  return fp;
}

#define ERROR_PREFIX "450-anubisrc:"

static void
_xdb_error_printer (void *data,
		    struct rc_loc *loc,
		    const char *pfx,
		    const char *fmt, va_list ap)
{
  struct stringbuf *sb = data;
  int n;

  stringbuf_add_string (sb, ERROR_PREFIX);
  /* FIXME: column? */
  stringbuf_printf (sb, "%lu", (unsigned long)loc->line);
  if (topt & T_LOCATION_COLUMN)
    {
      stringbuf_printf (sb, ".%lu", (unsigned long)loc->column);
    }
  stringbuf_add_string (sb, ": ");
  if (pfx)
    {
      stringbuf_printf (sb, "%s: ", pfx);
    }
  stringbuf_vprintf (sb, fmt, ap);
  stringbuf_add (sb, CRLF, 2);
}

static void
xupload (void)
{
  char *tempname;
  FILE *tempfile;
  char *line = NULL;
  size_t size = 0;
  RC_SECTION *sec;
  char *rcname;
  struct stringbuf sb = STRINGBUF_INITIALIZER;

  rcname = user_rcfile_name ();
  tempfile = make_temp_file (rcname, &tempname);
  if (!tempfile)
    {
      swrite (SERVER, remote_client,
	      "450 Failed to create temporary file\r\n");
      free (rcname);
      return;
    }

  swrite (SERVER, remote_client,
	  "354 Enter configuration settings, end with \".\" on a line by itself\r\n");

  while (recvline (SERVER, remote_client, &line, &size) > 0)
    {
      remcrlf (line);
      if (strcmp (line, ".") == 0)	/* EOM */
	break;
      fputs (line, tempfile);
      fputc ('\n', tempfile);
    }
  free (line);  

  fclose (tempfile);

  /* Parse it */
  sec = rc_parse_ep (tempname, _xdb_error_printer, &sb);
  if (!sec)
    {
      char *errmsg = stringbuf_finish (&sb);
      swrite (SERVER, remote_client, "450-Configuration update failed" CRLF);
      swrite (SERVER, remote_client, errmsg);
      swrite (SERVER, remote_client, "450 Please fix and submit again" CRLF);
      unlink (tempname);
    }
  else
    {
      rc_section_list_destroy (&sec);
      if (rename (tempname, rcname))
	{
	  anubis_error (0, errno, _("Cannot rename %s to %s"),
			tempname, rcname);
	  swrite (SERVER, remote_client, "450 Cannot rename file" CRLF);
	}
      else
	{
	  open_rcfile (CF_CLIENT);
	  process_rcfile (CF_CLIENT);

	  swrite (SERVER, remote_client,
		  "250 Configuration update accepted" CRLF);
	}
    }
  free (rcname);
  stringbuf_free (&sb);
}

static void
xremove (void)
{
  char *rcname = user_rcfile_name ();
  if (unlink (rcname) && errno != ENOENT)
    {
      anubis_error (0, errno, _("Cannot unlink %s"), rcname);
      swrite (SERVER, remote_client, "450 Cannot unlink file" CRLF);
    }
  swrite (SERVER, remote_client, "250 Configuration settings dropped" CRLF);
  free (rcname);
}

static void
xexamine (void)
{
  char *rcname = user_rcfile_name ();
  int fd = open (rcname, O_RDONLY);
  if (fd == -1)
    {
      if (errno == ENOENT)
	swrite (SERVER, remote_client,
		"300 Configuration file does not exist" CRLF);
      else
	{
	  anubis_error (0, errno, _("Cannot open %s"), rcname);
	  swrite (SERVER, remote_client, "450 Cannot open file" CRLF);
	}
    }
  else
    {
      unsigned char *digest;
      char const *err;
      int rc;
      
      rc = anubis_md5_file (fd, &digest, &err);
      close (fd);
      if (rc)
	{
	  anubis_error (0, 0, _("Can't compute md5 hash of %s: %s"), rcname,
			err);
	  swrite (SERVER, remote_client, "450 Cannot compute hash" CRLF);
	}
      else
	{
	  swrite (SERVER, remote_client, "250 ");
	  swrite (SERVER, remote_client, (char*) digest);
	  swrite (SERVER, remote_client, CRLF);
	  free (digest);
	}
    }
  free (rcname);
}

static void
xerror (char *p)
{
  swrite (SERVER, remote_client, "501 XDATABASE syntax error\r\n");
}

/* Input: command string (lowercase)
   Return value: 0 -- not processed (the command will be passed to the
                 remote SMTP server.
                 1 -- processed (successfully or not) and replied to */

int
xdatabase (char *command)
{
  char *p;

  if (!command)
    return 0;

  remcrlf (command);
  for (p = command; *p && isspace (*p); p++)
    ;

  if (strcmp (p, "upload") == 0)
    xupload ();
  else if (strcmp (p, "remove") == 0)
    xremove ();
  else if (strcmp (p, "examine") == 0)
    xexamine ();
  else
    xerror (p);

  return 1;
}
