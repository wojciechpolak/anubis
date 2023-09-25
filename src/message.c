/*
   message.c

   This file is part of GNU Anubis.
   Copyright (C) 2003-2023 The Anubis Team.

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

struct message_struct
{
  char id[MSGIDBOUND];          /* Message ID */
  ANUBIS_LIST commands;	        /* Associative list of SMTP commands */
  ANUBIS_LIST header;		/* Associative list of RFC822 headers */
  ANUBIS_LIST mime_hdr;	        /* List of lines before the first boundary
				   marker */
  char *body;			/* Message body */
  char *boundary;		/* Additional data */
};


#define IDSEQLEN      60
#define IDTIMLEN      62

/* Create new message ID. IDBUF must be at least MSGIDBOUND bytes long */
char *
create_msgid (char *idbuf)
{
  time_t t;
  struct tm *tm;
  static const char xchr[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  static unsigned seq = 0;

  time (&t);
  tm = gmtime (&t);
  idbuf[0] = xchr[tm->tm_year % IDSEQLEN];
  idbuf[1] = xchr[tm->tm_mon];
  idbuf[2] = xchr[tm->tm_mday];
  idbuf[3] = xchr[tm->tm_hour];
  idbuf[4] = xchr[tm->tm_min % IDTIMLEN];
  idbuf[5] = xchr[tm->tm_sec % IDTIMLEN];
  idbuf[6] = xchr[seq / IDSEQLEN];
  idbuf[7] = xchr[seq % IDSEQLEN];
  snprintf(&idbuf[8], sizeof(idbuf) - 8, "%06lu",
	   (unsigned long) getpid ());
  seq++;
  if (seq >= IDSEQLEN * IDSEQLEN)
    seq = 0;
  return idbuf;
}


MESSAGE 
message_new ()
{
  MESSAGE msg = xzalloc (sizeof (*msg));
  msg->header = list_create ();
  msg->commands = list_create ();
  create_msgid (msg->id);
  return msg;
}

void
message_reset (MESSAGE msg)
{
  destroy_assoc_list (&msg->commands);
  destroy_assoc_list (&msg->header);
  destroy_string_list (&msg->mime_hdr);

  free (msg->body);
  free (msg->boundary);

  memset (msg, 0, sizeof (*msg));
  create_msgid (msg->id);
  msg->header = list_create ();
  msg->commands = list_create ();
}  

/* FIXME: Implement copy-on-write */
void
message_free (MESSAGE msg)
{
  destroy_assoc_list (&msg->commands);
  destroy_assoc_list (&msg->header);
  destroy_string_list (&msg->mime_hdr);

  free (msg->body);
  free (msg->boundary);
  free (msg);
}

MESSAGE
message_dup (MESSAGE msg)
{
  MESSAGE newmsg = message_new ();
  newmsg->commands = assoc_list_dup (msg->commands);
  newmsg->header = assoc_list_dup (msg->header);
  msg->mime_hdr = string_list_dup (msg->mime_hdr);
  
  newmsg->body = msg->body ? xstrdup (msg->body): NULL;
  newmsg->boundary = msg->boundary ? xstrdup (msg->boundary) : NULL;
  return newmsg;
}


static char *
expand_ampersand (char *value, char *old_value)
{
  char *p;

  p = strchr (value, '&');
  if (!p)
    {
      free (old_value);
      p = strdup (value);
    }
  else
    {
      struct stringbuf sb = STRINGBUF_INITIALIZER;
      int old_length = strlen (old_value);

      for (; *value; value++)
	{
	  switch (*value)
	    {
	    case '\\':
	      value++;
	      if (*value != '&')
		stringbuf_add_char (&sb, '\\');
	      stringbuf_add_char (&sb, *value);
	      break;
	    case '&':
	      stringbuf_add (&sb, old_value, old_length);
	      break;
	    default:
	      stringbuf_add_char (&sb, *value);
	    }
	}
      p = stringbuf_finish (&sb);
    }
  return p;
}


ANUBIS_LIST 
message_get_header (MESSAGE msg)
{
  return msg->header;
}

void
message_add_header (MESSAGE msg, char *hdr, char *value)
{
  ASSOC *asc = xmalloc (sizeof (*asc));
  asc->key = strdup (hdr);
  asc->value = strdup (value);
  list_append (msg->header, asc);
}

void
message_remove_headers (MESSAGE msg, RC_REGEX *regex)
{
  ASSOC *asc;
  ITERATOR itr;

  itr = iterator_create (msg->header);
  for (asc = iterator_first (itr); asc; asc = iterator_next (itr))
    {
      char **rv;
      int rc;

      if (anubis_regex_match (regex, asc->key, &rc, &rv))
	{
	  list_remove (msg->header, asc, NULL);
	  assoc_free (asc);
	}
      if (rc)
	argv_free (rv);
    }
  iterator_destroy (&itr);
}

void
message_replace_header (MESSAGE msg, ANUBIS_LIST list)
{
  destroy_assoc_list (&msg->header);
  msg->header = list;
}

void
message_modify_headers (MESSAGE msg, RC_REGEX *regex, char *key2,
			char *value)
{
  ASSOC *asc;
  ITERATOR itr;

  itr = iterator_create (msg->header);
  for (asc = iterator_first (itr); asc; asc = iterator_next (itr))
    {
      char **rv;
      int rc;

      if (asc->key && anubis_regex_match (regex, asc->key, &rc, &rv))
	{
	  if (key2)
	    {
	      free (asc->key);
	      if (rc)
		asc->key = substitute (key2, rv);
	      else
		asc->key = strdup (key2);
	    }
	  if (value)
	    {
	      asc->value = expand_ampersand (value, asc->value);
	    }
	}
      if (rc)
	argv_free (rv);
    }
  iterator_destroy (&itr);
}

void
message_modify_command (MESSAGE msg, RC_REGEX *regex, char *key,
			char *value)
{
  char **rv;
  int rc;
  ASSOC *asc = list_tail_item (msg->commands);

  if (!asc)
    return;

  if (asc->key && anubis_regex_match (regex, asc->key, &rc, &rv))
    {
      if (key)
	{
	  free (asc->key);
	  if (rc)
	    asc->key = substitute (key, rv);
	  else
	    asc->key = strdup (key);
	}
      if (value)
	asc->value = expand_ampersand (value, asc->value);
    }
  if (rc)
    argv_free (rv);
}


const char *
message_id (MESSAGE msg)
{
  return msg->id;
}

const char *
message_get_body (MESSAGE msg)
{
  return msg->body;
}

void
message_add_body (MESSAGE msg, char *key, char *value)
{
  if (!key)
    {
      msg->body = xrealloc (msg->body,
			    strlen (msg->body) + strlen (value) + 1);
      strcat (msg->body, value);
    }
  else
    {
     /*FIXME*/
    }
}

void
message_replace_body (MESSAGE msg, char *body)
{
  free (msg->body);
  msg->body = body;
}

void
message_modify_body (MESSAGE msg, RC_REGEX *regex, char *value)
{
  if (!value)
    value = "";
  if (!regex)
    {
      int len = strlen (value);

      xfree (msg->body);
      if (len > 0 && value[len - 1] != '\n')
	{
	  msg->body = xmalloc (len + 2);
	  strcpy (msg->body, value);
	  msg->body[len] = '\n';
	  msg->body[len + 1] = 0;
	}
      else
	msg->body = strdup (value);
    }
  else
    {
      char *start, *end;
      struct stringbuf sb = STRINGBUF_INITIALIZER;

      start = msg->body;
      while (start && *start)
	{
	  char *newp;

	  end = strchr (start, '\n');
	  if (end)
	    *end = 0;

	  newp = anubis_regex_replace (regex, start, value);

	  if (newp)
	    {
	      if (stringbuf_len (&sb) == 0)
		{
		  stringbuf_add (&sb, msg->body, start - msg->body);
		}
	      stringbuf_add_string (&sb, newp);
	      stringbuf_add_char (&sb, '\n');
	      xfree (newp);
	    }
	  else if (stringbuf_len (&sb) > 0)
	    {
	      stringbuf_add_string (&sb, start);
	      stringbuf_add_char (&sb, '\n');
	    }
	  if (end)
	    *end++ = '\n';
	  start = end;
	}

      if (stringbuf_len (&sb) > 0)
	{
	  free (msg->body);
	  msg->body = stringbuf_finish (&sb);
	}
    }
}

void
message_proc_body (MESSAGE msg, int (*proc) (char **, char *, void *),
		   void *param)
{
  char *buf;
  int rc = proc (&buf, msg->body, param);
  if (rc < 0)
    return;
  if (rc > 0)
    xfree (msg->body);
  msg->body = buf;
}

void
message_external_proc (MESSAGE msg, char **argv)
{
  int rc = 0;
  char *extbuf = 0;
  extbuf = exec_argv (&rc, NULL, argv, msg->body, 0, 0);
  if (rc != -1 && extbuf)
    {
      xfree (msg->body);
      msg->body = extbuf;
    }
}

ANUBIS_LIST 
message_get_commands (MESSAGE msg)
{
  return msg->commands;
}

void
message_add_command (MESSAGE msg, ASSOC *p)
{
  list_append (msg->commands, p);
}

const char *
message_get_boundary (MESSAGE msg)
{
  return msg->boundary;
}
  
void
message_replace_boundary (MESSAGE msg, char *boundary)
{
  free (msg->boundary);
  msg->boundary = boundary;
}

ANUBIS_LIST 
message_get_mime_header (MESSAGE msg)
{
  return msg->mime_hdr;
}

void
message_append_mime_header (MESSAGE msg, const char *buf)
{
  if (!msg->mime_hdr)
    msg->mime_hdr = list_create ();
  list_append (msg->mime_hdr, xstrdup (buf));
}

/* EOF */
