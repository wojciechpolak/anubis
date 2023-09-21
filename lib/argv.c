#include <config.h>
#include <stdlib.h>
#include <xalloc.h>
#include <wordsplit/wordsplit.h>

void
argv_free (char **argv)
{
  if (argv)
    {
      size_t i;
      for (i = 0; argv[i]; i++)
	free (argv[i]);
      free (argv);
    }
}

/* Take a argv an make string separated by ' '.  */

char *
argv_string (char **argv)
{
  char *buffer = NULL;
  size_t bufcap = 0;
  size_t buflen = 0;
  int i;

  if (!argv)
    return NULL;
  for (i = 0; argv[i]; i++)
    {
      size_t len, wlen;
      int quote;

      len = wlen = wordsplit_c_quoted_length (argv[i], 0, &quote);
      if (quote)
	wlen += 2;
      if (i)
	wlen++;
      wlen++;

      while (buflen + wlen >= bufcap)
	buffer = x2nrealloc (buffer, &bufcap, 1);

      if (i)
	buffer[buflen++] = ' ';

      if (quote)
	buffer[buflen++] = '"';
      wordsplit_c_quote_copy (buffer + buflen, argv[i], 0);
      buflen += len;
      if (quote)
	buffer[buflen++] = '"';
     }
  return buffer;
}
    
