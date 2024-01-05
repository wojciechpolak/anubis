/*
   ident.c

   This file is part of GNU Anubis.
   Copyright (C) 2001-2024 The Anubis Team.

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

/***********************
 IDENT protocol support
************************/

char *identd_keyfile_name;

static int
ident_extract_username (char const *reply, char **pusername)
{
  struct wordsplit ws = { .ws_delim = ":" };
  int wsflags = WRDSF_NOVAR | WRDSF_NOCMD | WRDSF_DELIM | WRDSF_WS;
  int result = 1;
  
  if (wordsplit (reply, &ws, wsflags))
    {
      anubis_error (0, 0, _("wordsplit failed: %s"), wordsplit_strerror (&ws));
    }
  else if (ws.ws_wordc == 4 && strcmp (ws.ws_wordv[1], "USERID") == 0)
    {
      *pusername = xstrdup (ws.ws_wordv[3]);
      result = 0;
    }
  wordsplit_free (&ws);
  return result;
}

int
auth_ident (struct sockaddr_in *addr, char **ret_user)
{
  struct servent *sp;
  struct sockaddr_in ident;
  char *buf = NULL;
  char inetd_buf[LINEBUFFER];
  size_t size = 0;
  int sd = 0;
  int rc;
  NET_STREAM str;
  size_t nbytes;
  char *user;
  int ulen;
  
  if ((sd = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
      anubis_error (0, errno, _("IDENT: socket() failed"));
      return 0;
    }
  memcpy (&ident, addr, sizeof (ident));
  sp = getservbyname ("auth", "tcp");
  if (sp)
    ident.sin_port = sp->s_port;
  else
    ident.sin_port = htons (113);	/* default IDENT port number */

  if (connect (sd, (struct sockaddr *) &ident, sizeof (ident)) < 0)
    {
      anubis_error (0, errno, _("IDENT: connect() failed"));
      close_socket (sd);
      return 0;
    }
  net_create_stream (&str, sd);

  info (VERBOSE, _("IDENT: connected to %s:%u"),
	inet_ntoa (ident.sin_addr), ntohs (ident.sin_port));

  snprintf (inetd_buf, sizeof inetd_buf,
	    "%u , %u" CRLF, ntohs (addr->sin_port), session.anubis_port);

  if ((rc = stream_write (str, inetd_buf, strlen (inetd_buf), &nbytes)))
    {
      anubis_error (0, 0,
		    _("IDENT: stream_write() failed: %s."),
		    stream_strerror (str, rc));
      net_close_stream (&str);
      return 0;
    }
  if (recvline (CLIENT, str, &buf, &size) == 0)
    {
      anubis_error (0, 0,
		    _("IDENT: recvline() failed: %s."),
		    stream_strerror (str, rc));
      net_close_stream (&str);
      return 0;
    }
  net_close_stream (&str);

  remcrlf (buf);
  if (ident_extract_username (buf, &user))
    {
      info (VERBOSE, _("IDENT: incorrect data."));
      free (buf);
      return 0;
    }
  free (buf);

  /******************************
   IDENTD DES decryption support
  *******************************/
  ulen = strlen (user);
  if (ulen > 2 && user[0] == '[' && user[ulen-1] == ']')
    {
      char *s;
      
      s = idecrypt_username (user + 1, ulen - 2);
      free (user);
      if (s != NULL)
	{
	  user = s;
	  info (VERBOSE, _("IDENT: data encrypted with DES"));
	}
      else
	{
	  info (VERBOSE, _("IDENT: incorrect data (DES deciphered)."));
	  *ret_user = NULL;
          return 0;
	}
    }
  *ret_user = user;
  info (VERBOSE, _("IDENT: resolved remote user to %s."), user);
  return 1;			/* success */
}

/* EOF */
