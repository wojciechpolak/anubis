/*
   Read password from stdin.
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
#include "headers.h"
#include <fcntl.h>
#include <termios.h>

#define MAX_PASS_SIZE BUFSIZ

#ifndef TCSASOFT
# define TCSASOFT 0
#endif

int
anubis_getpass (char const *prompt, char **pass)
{
  char passbuf[MAX_PASS_SIZE];
  int len;
  struct termios t, echo_state;
  int rc, res;
  int fd = fileno (stdin);
    
  rc = tcgetattr (fd, &t);
  if (rc)
    return -1;

  echo_state = t;

  t.c_lflag &= ~(ECHO | ISIG);
  rc = tcsetattr (fd, TCSAFLUSH | TCSASOFT, &t);
  if (rc)
    return -1;

  if (prompt)
    fputs (prompt, stdout);
  fflush (stdout);
  
  if (fgets (passbuf, sizeof (passbuf), stdin) == 0)
    res = errno;
  else
    {
      len = strlen (passbuf);
      if (len == 0 || passbuf[len-1] != '\n')
	res = E2BIG;
      else
	{
	  res = 0;
	  passbuf[len-1] = 0;
	}
    }
  fputc ('\n', stdout);
  
  rc = tcsetattr (fd, TCSAFLUSH | TCSASOFT, &echo_state);
  if (rc)
    abort ();

  if (res)
    {
      errno = res;
      return -1;
    }

  *pass = xstrdup (passbuf);
  return 0;
}
 

		  
		
  
  
  
