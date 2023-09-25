/*
   gsasl.c

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


/* Basic I/O Functions */

struct anubis_gsasl_stream
{
  Gsasl_session *sess_ctx; /* Context */
  struct stringbuf sb;
  NET_STREAM stream;
};

static const char *
_gsasl_strerror (void *ignored_data, int rc)
{
  return gsasl_strerror (rc);
}

int
write_chunk (void *data, char *start, char *end)
{
  struct anubis_gsasl_stream *s = data;
  size_t chunk_size = end - start + 1;
  size_t len;
  size_t wrsize;
  char *buf = NULL;

  len = 0;
  gsasl_encode (s->sess_ctx, start, chunk_size, &buf, &len);

  wrsize = 0;
  do
    {
      size_t sz;
      int rc = stream_write (s->stream, buf + wrsize, len - wrsize,
			     &sz);
      if (rc)
	{
	  if (rc == EINTR)
	    continue;
	  free (buf);
	  return rc;
	}
      wrsize += sz;
    }
  while (wrsize < len);

  free (buf);

  return 0;
}

int
stringbuf_writelines (struct stringbuf *s, const char *iptr, size_t isize,
		      int (*wr) (void *data, char *start, char *end),
		      void *data,
		      size_t *nbytes)
{
  if (s->len > 2)
    {
      char *start, *end;
      
      for (start = s->base,
	     end = memchr (start, '\n', s->base + s->len - start);
	   end && end < s->base + s->len;
	   start = end + 1,
	     end = memchr (start, '\n', s->base + s->len - start))
	if (end[-1] == '\r')
	  {
	    int rc = wr (data, start, end);
	    if (rc)
	      return rc;
	  }

      if (start > s->base)
	{
	  if (start < s->base + s->len)
	    {
	      int rest = s->base + s->len - start;
	      memmove (s->base, start, rest);
	      s->len = rest;
	    }
	  else 
	    s->len = 0;
	}
    }

  if (nbytes)
    *nbytes = isize;
  return 0;
}

static int
_gsasl_write (void *sd, const char *data, size_t size, size_t * nbytes)
{
  struct anubis_gsasl_stream *s = sd;
  int rc = stringbuf_add (&s->sb, data, size);
  if (rc)
    return rc;

  return stringbuf_writelines (&s->sb, data, size, write_chunk, s, nbytes);
}

static int
_gsasl_read (void *sd, char *data, size_t size, size_t * nbytes)
{
  struct anubis_gsasl_stream *s = sd;
  int rc;
  char *bufp = NULL;
  size_t len = 0;

  do
    {
      char buf[80];
      size_t sz;

      rc = stream_read (s->stream, buf, sizeof (buf), &sz);
      if (rc)
	{
	  if (rc == EINTR)
	    continue;
	  return rc;
	}

      rc = stringbuf_add (&s->sb, buf, sz);
      if (rc)
	return rc;

      rc = gsasl_decode (s->sess_ctx,
			 stringbuf_value (&s->sb),
			 stringbuf_len (&s->sb), &bufp, &len);
    }
  while (rc == GSASL_NEEDS_MORE);

  if (rc != GSASL_OK)
    return rc;

  if (len > size)
    {
      memcpy (data, bufp, size);
      stringbuf_reset (&s->sb);
      stringbuf_add (&s->sb, bufp + size, len - size);
      len = size;
    }
  else
    {
      stringbuf_reset (&s->sb);
      memcpy (data, bufp, len);
    }
  if (nbytes)
    *nbytes = len;

  free (bufp);
  return 0;
}

static int
_gsasl_close (void *sd)
{
  struct anubis_gsasl_stream *s = sd;

  stream_close (s->stream);
  return 0;
}

static int
_gsasl_destroy (void *sd)
{
  struct anubis_gsasl_stream *s = sd;
  if (s->sess_ctx)
    gsasl_finish (s->sess_ctx);
  stringbuf_free (&s->sb);
  free (sd);
  return 0;
}

static void
gsasl_nomem (void)
{
  anubis_error (EXIT_FAILURE, 0, "%s", _("Not enough memory"));
}

void
install_gsasl_stream (Gsasl_session *sess_ctx, NET_STREAM *stream)
{
  struct anubis_gsasl_stream *s = xmalloc (sizeof *s);

  s->sess_ctx = sess_ctx;
  stringbuf_init (&s->sb, gsasl_nomem);
  s->stream = *stream;

  stream_create (stream);
  stream_set_io (*stream, s,
		 _gsasl_read, _gsasl_write,
		 _gsasl_close, _gsasl_destroy, _gsasl_strerror);
}
