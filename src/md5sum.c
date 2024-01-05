/*
   md5sum.c

   This file is part of GNU Anubis.
   Copyright (C) 2023-2024 The Anubis Team.

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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

static const char xlet[] = "0123456789ABCDEF";

/* Convert @var{input} from binary to hex representation.

   Output should be at least 2*inlen + 1 bytes long
 */
static void
string_bin_to_hex (unsigned char *output, unsigned char *input, int inlen)
{
  int i;

  for (i = 0; i < inlen; i++)
    {
      output[i << 1] = xlet[input[i] >> 4];
      output[(i << 1) + 1] = xlet[input[i] & 0x0f];
    }
  output[i << 1] = 0;
}

int
anubis_md5_file (int fd, unsigned char **out_digest, char const **err)
{
  unsigned char buf[BUFSIZ];
  gnutls_hash_hd_t dig;
  unsigned char *digest, *out;  
  int rc;
  size_t len;
  
  rc = gnutls_hash_init (&dig, GNUTLS_DIG_MD5);
  if (rc != GNUTLS_E_SUCCESS)
    {
      if (err)
	*err = gnutls_strerror (rc);
      return -1;
    }

  for (;;)
    {
      int nread = read (fd, buf, sizeof buf);
      if (nread == 0)
	break;
      else if (nread == -1)
	{
	  if (err)
	    *err = strerror (errno);
	  gnutls_hash_deinit (dig, NULL);
	  return -1;
	}
      rc = gnutls_hash (dig, buf, nread);
      if (rc != GNUTLS_E_SUCCESS)
	{
	  if (err)
	    *err = gnutls_strerror (rc);
	  gnutls_hash_deinit (dig, NULL);
	  return -1;
	}
    }

  len = gnutls_hash_get_len (GNUTLS_DIG_MD5);
  digest = malloc (len);
  if (!digest)
    {
      if (err)
	*err = strerror (errno);
      gnutls_hash_deinit (dig, NULL);
      return -1;
    }
  gnutls_hash_deinit (dig, digest);
  out = malloc (2 * len + 1);
  if (!out)
    {
      if (err)
	*err = strerror (errno);
      free (digest);
      return -1;
    }
  string_bin_to_hex (out, digest, len);
  free (digest);
  *out_digest = out;
  return 0;
}

      

  
