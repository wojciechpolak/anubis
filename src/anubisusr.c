/*
   anubisusr.c
   
   Copyright (C) 2004, 2005, 2007, 2008 The Anubis Team.

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

#include <anubisusr.h>

#ifdef HAVE_TLS
char *tls_cafile;
int enable_tls = 1;
#endif /* HAVE_TLS */

char *progname;

char *smtp_host = "localhost";
int smtp_port = 24;
char *rcfile_name = NULL;
char *netrc_name = NULL;
struct obstack input_stk;

int verbose;

#define VDETAIL(n,s) do { if (verbose>=(n)) printf s; } while(0)

struct smtp_reply
{
  int code;			/* Reply code */
  char *base;			/* Pointer to the start of the reply string */
  int argc;			/* Number of arguments in the parsed reply */
  char **argv;			/* Parsed reply */
};

struct smtp_reply smtp_capa;

void error (const char *, ...);
int send_line (char *buf);
int smtp_get_reply (struct smtp_reply *repl);
void smtp_free_reply (struct smtp_reply *repl);
static void smtp_quit (void);

#define R_CONT     0x8000
#define R_CODEMASK 0xfff

void
error (const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);
  fprintf (stderr, "%s: ", progname);
  vfprintf (stderr, fmt, ap);
  fprintf (stderr, "\n");
  va_end (ap);
}


/* Basic I/O */

NET_STREAM iostream;


#ifdef HAVE_TLS

void
info (int mode, const char *fmt, ...)
{
  va_list ap;

  if (verbose == 0)
    return;
  va_start (ap, fmt);
  vfprintf (stderr, fmt, ap);
  va_end (ap);
  fprintf (stderr, "\n");
}

void
anubis_error (int exit_code, int error_code, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);
  fprintf (stderr, "%s: ", progname);
  vfprintf (stderr, fmt, ap);
  if (error_code)
    fprintf (stderr, ": %s", strerror (error_code));
  fprintf (stderr, "\n");
  va_end (ap);
}

void
starttls (void)
{
  struct smtp_reply reply;

  VDETAIL (1, (_("Starting TLS negotiation\n")));
  send_line ("STARTTLS");
  smtp_get_reply (&reply);
  if (reply.code != 220)
    {
      error (_("Server rejected TLS negotiation"));
      exit (1);
    }
  iostream = start_ssl_client (iostream, tls_cafile, verbose > 2);
  if (!iostream)
    {
      error (_("TLS negotiation failed"));
      smtp_quit ();
      exit (1);
    }
}
#endif /* HAVE_TLS */


/* Auxiliary functions */
char *
skipws (char *str)
{
  while (*str && isspace (*(u_char *) str))
    str++;
  return str;
}

char *
skipword (char *str)
{
  while (*str && !isspace (*(u_char *) str))
    str++;
  return str;
}

/* FIXME: Move to the library and unify with hostname_error() */
const char *
h_error_string (int ec)
{
  static struct h_err_tab
  {
    int code;
    char *descr;
  }
   *ep, h_err_tab[] =
  {
    { HOST_NOT_FOUND, N_("No such host is known in the database.") },
    { TRY_AGAIN, N_("Temporary error. Try again later.") },
    { NO_RECOVERY, N_("Non-recoverable error") },
    { NO_ADDRESS, N_("No Internet address is associated with the name") },
    { 0, 0 }
  };

  for (ep = h_err_tab; ep->descr; ep++)
    if (ep->code == ec)
      return gettext (ep->descr);
  return gettext ("Unknown error");
};

/* FIXME: move to the library. Modify connect_directly_to() to use it */
int
parse_host (char *host, int port, struct sockaddr_in *addr)
{
  struct hostent *hp = gethostbyname (host);

  if (!hp)
    {
      error (_("Cannot resolve %s: %s"), host, h_error_string (h_errno));
      return -1;
    }
  addr->sin_family = AF_INET;
  addr->sin_port = htons (port);

  if (hp->h_length != sizeof addr->sin_addr.s_addr)
    {
      error (_("Cannot resolve %s: received illegal address length (%d)"),
	     host, hp->h_length);
      return -1;
    }
  memcpy (&addr->sin_addr.s_addr, hp->h_addr, sizeof addr->sin_addr.s_addr);
  return 0;
}


/* GSASL mechanisms */

static ANUBIS_LIST *auth_mech_list;

void
add_mech (char *arg)
{
  if (!auth_mech_list)
    auth_mech_list = list_create ();
  list_append (auth_mech_list, arg);
}


/* Capability handling */

int
find_capa (struct smtp_reply *repl, const char *name, const char *value)
{
  int i;
  for (i = 0; i < repl->argc; i++)
    {
      char *p = skipword (repl->argv[i]);
      if (strncmp (name, repl->argv[i], p - repl->argv[i]) == 0)
	{
	  if (value)
	    {
	      int j, argc;
	      char **argv;
	      int rc = 0;

	      if ((rc = argcv_get (repl->argv[i], "", NULL, &argc, &argv)))
		{
		  error (_("argcv_get failed: %s"), strerror (rc));
		  return 1;
		}
	      rc = 1;
	      for (j = 0; rc == 1 && j < argc; j++)
		if (strcmp (argv[j], value) == 0)
		  rc = 0;
	      argcv_free (argc, argv);
	      return rc;
	    }
	  return 0;
	}
    }
  return 1;
}

static int
name_cmp (void *item, void *data)
{
  return strcmp (item, data);
}

char *
find_capa_v (struct smtp_reply *repl, const char *name, ANUBIS_LIST * list)
{
  int i;
  for (i = 0; i < repl->argc; i++)
    {
      char *p = skipword (repl->argv[i]);
      if (strncmp (name, repl->argv[i], p - repl->argv[i]) == 0)
	{
	  int rc, j, argc;
	  char **argv;
	  char *rv = NULL;

	  if ((rc = argcv_get (repl->argv[i], "", NULL, &argc, &argv)))
	    {
	      error (_("argcv_get failed: %s"), strerror (rc));
	      return NULL;
	    }

	  if (!list)
	    {
	      if (argv[1])
		rv = strdup (argv[1]);
	    }
	  else
	    {
	      for (j = 0; !rv && j < argc; j++)
		rv = list_locate (list, argv[j], name_cmp);
	    }
	  argcv_free (argc, argv);
	  return rv;
	}
    }
  return NULL;
}


/* I/O functions */
int
send_line (char *buf)
{
  size_t size = strlen (buf);
  size_t n;
  int rc;

  VDETAIL (2, ("C: %s\n", buf));

  rc = stream_write (iostream, buf, size, &n);
  if (rc)
    {
      error (_("write failed: %s"), stream_strerror (iostream, rc));
      return rc;
    }
  rc = stream_write (iostream, CRLF, 2, &n);
  if (rc)
    error (_("write failed: %s"), stream_strerror (iostream, rc));
  return rc;
}

int
smtp_get_reply (struct smtp_reply *repl)
{
  char *buf = NULL;
  size_t bufsize = 0;
  char *p;
  int i;
  int cont = 0;

  memset (repl, 0, sizeof *repl);
  do
    {
      size_t n;
      int rc = stream_getline (iostream, &buf, &bufsize, &n);

      if (rc)
	{
	  error (_("read failed: %s"), stream_strerror (iostream, rc));
	  exit (1);
	}

      VDETAIL (2, ("S: %*.*s", (int) n, (int) n, buf));
      if (!cont)
	{
	  int code;
	  if (n < 4)
	    break;
	  code = strtoul (buf, &p, 0);
	  if (p - buf != 3 || (*p != '-' && *p != ' '))
	    {
	      error (_("Unexpected reply from server: %s"), buf);
	      abort ();
	    }
	  if (repl->code == 0)
	    repl->code = code;
	  else if (repl->code != code)
	    {
	      error (_("Unexpected reply code from server: %d"), code);
	      abort ();
	    }
	}

      if (buf[n - 1] == '\n')
	{
	  cont = 0;
	  n--;
	  if (buf[n - 1] == '\r')
	    n--;
	  buf[n++] = 0;
	  if (n - 4 && buf[4])
	    obstack_grow (&input_stk, buf + 4, n - 4);
	  else
	    obstack_grow (&input_stk, "\r", 2);
	  repl->argc++;
	}
      else
	{
	  cont = 1;
	  obstack_grow (&input_stk, buf, n);
	}
    }
  while (cont || *p == '-');
  free (buf);
  obstack_1grow (&input_stk, 0);
  repl->base = obstack_finish (&input_stk);

  repl->argv = xmalloc ((repl->argc + 1) * sizeof (repl->argv[0]));
  for (i = 0, p = repl->base; p[0]; p += strlen (p) + 1, i++)
    {
      if (p[0] == '\r')
	p[0] = 0;
      repl->argv[i] = p;
    }
  repl->argv[i] = NULL;
  return 0;
}

void
smtp_free_reply (struct smtp_reply *repl)
{
  obstack_free (&input_stk, repl->base);
  memset (repl, 0, sizeof *repl);
}

void
smtp_print_reply (FILE * fp, struct smtp_reply *repl)
{
  int i;
  for (i = 0; i < repl->argc; i++)
    fprintf (fp, "%s\n", repl->argv[i]);
  fflush (fp);
}


void
smtp_ehlo (int xelo)
{
  struct smtp_reply repl;

  send_line (xelo ? "XELO localhost" : "EHLO localhost");
  smtp_get_reply (&repl);
  if (repl.code != 250)
    {
      error (_("Server refused handshake"));
      smtp_print_reply (stderr, &repl);
      exit (1);
    }
  smtp_capa = repl;
}


struct auth_args
{
  char *anon_token;
  char *authorization_id;
  char *authentication_id;
  char *password;
  char *service;
  char *hostname;
  char *service_name;
  char *passcode;
  char *qop;
  char *realm;
};

struct auth_args auth_args;

void
assign_string (char **pstring, const char *value)
{
  if (*pstring)
    free (*pstring);
  *pstring = strdup (value);
}

/* Compare two hostnames. Return 0 if they have the same address type,
   address length *and* at least one of the addresses of A matches
   B */
int
hostcmp (const char *a, const char *b)
{
  struct hostent *hp = gethostbyname (a);
  char **addrlist;
  char *dptr;
  char **addr;
  size_t i, count;
  size_t entry_length;
  int entry_type;

  if (!hp)
    return 1;

  for (count = 1, addr = hp->h_addr_list; *addr; addr++)
    count++;
  addrlist = xmalloc (count * (sizeof *addrlist + hp->h_length)
		      - hp->h_length);
  dptr = (char *) (addrlist + count);
  for (i = 0; i < count - 1; i++)
    {
      memcpy (dptr, hp->h_addr_list[i], hp->h_length);
      addrlist[i] = dptr;
      dptr += hp->h_length;
    }
  addrlist[i] = NULL;
  entry_length = hp->h_length;
  entry_type = hp->h_addrtype;

  hp = gethostbyname (b);
  if (!hp || entry_length != hp->h_length || entry_type != hp->h_addrtype)
    {
      free (addrlist);
      return 1;
    }

  for (addr = addrlist; *addr; addr++)
    {
      char **p;

      for (p = hp->h_addr_list; *p; p++)
	{
	  if (memcmp (*addr, *p, entry_length) == 0)
	    {
	      free (addrlist);
	      return 0;
	    }
	}
    }
  free (addrlist);
  return 1;
}

/* Parse traditional .netrc file. Set up auth_args fields in accordance with
   it. */
void
parse_netrc (const char *filename)
{
  FILE *fp;
  char *buf = NULL;
  size_t n = 0;
  int def_argc = 0;
  char **def_argv = NULL;
  char **p_argv = NULL;
  int line = 0;

  fp = fopen (filename, "r");
  if (!fp)
    {
      if (errno != ENOENT)
	{
	  error (_("Cannot open configuration file %s: %s"),
		 filename, strerror (errno));
	}
      return;
    }
  else
    VDETAIL (1, (_("Opening configuration file %s...\n"), filename));

  while (getline (&buf, &n, fp) > 0 && n > 0)
    {
      int rc;
      char *p;
      size_t len;
      int argc;
      char **argv;

      line++;
      len = strlen (buf);
      if (len > 1 && buf[len - 1] == '\n')
	buf[len - 1] = 0;
      p = skipws (buf);
      if (*p == 0 || *p == '#')
	continue;

      if ((rc = argcv_get (buf, "", "#", &argc, &argv)))
	{
	  error (_("argcv_get failed: %s"), strerror (rc));
	  return;
	}
      
      if (strcmp (argv[0], "machine") == 0)
	{
	  if (hostcmp (argv[1], smtp_host) == 0)
	    {
	      VDETAIL (1, (_("Found matching line %d\n"), line));

	      if (def_argc)
		argcv_free (def_argc, def_argv);
	      def_argc = argc;
	      def_argv = argv;
	      p_argv = argv + 2;
	      break;
	    }
	}
      else if (strcmp (argv[0], "default") == 0)
	{
	  VDETAIL (1, (_("Found default line %d\n"), line));

	  if (def_argc)
	    argcv_free (def_argc, def_argv);
	  def_argc = argc;
	  def_argv = argv;
	  p_argv = argv + 1;
	}
      else
	{
	  VDETAIL (1, (_("Ignoring unrecognized line %d\n"), line));
	  argcv_free (argc, argv);
	}
    }
  fclose (fp);
  free (buf);

  if (!p_argv)
    VDETAIL (1, (_("No matching line found\n")));
  else
    {
      while (*p_argv)
	{
	  if (!p_argv[1])
	    {
	      error (_("%s:%d: incomplete sentence"), filename, line);
	      break;
	    }
	  if (strcmp (*p_argv, "login") == 0)
	    {
	      assign_string (&auth_args.authentication_id, p_argv[1]);
	      assign_string (&auth_args.authorization_id, p_argv[1]);
	    }
	  else if (strcmp (*p_argv, "password") == 0)
	    assign_string (&auth_args.password, p_argv[1]);
	  p_argv += 2;
	}
      argcv_free (def_argc, def_argv);
    }
}

char *
get_input (const char *prompt)
{
  char *buf = NULL;
  size_t n;

  printf ("%s", prompt);
  fflush (stdout);
  getline (&buf, &n, stdin);

  n = strlen (buf);
  if (n > 1 && buf[n - 1] == '\n')
    buf[n - 1] = 0;
  return buf;
}

static int
callback (Gsasl *ctx, Gsasl_session *sctx, Gsasl_property prop)
{
  int rc = GSASL_OK;

  switch (prop)
    {
    case GSASL_PASSWORD:
      if (auth_args.password == NULL)
	auth_args.password = getpass (_("Password: "));

      if (auth_args.password == NULL)
	return GSASL_AUTHENTICATION_ERROR;
      gsasl_property_set (sctx, prop, auth_args.password);
      break;

    case GSASL_SERVICE:
      if (auth_args.service == NULL)
	auth_args.service = get_input (_("GSSAPI service name: "));
      if (auth_args.service == NULL)
	return GSASL_AUTHENTICATION_ERROR;
      gsasl_property_set (sctx, prop, auth_args.service);
      break;

    case GSASL_REALM:
      if (auth_args.realm == NULL)
	auth_args.realm = get_input (_("Client realm: "));
      if (auth_args.realm == NULL)
	return GSASL_AUTHENTICATION_ERROR;
      gsasl_property_set (sctx, prop, auth_args.realm);
      break;

    case GSASL_HOSTNAME:
      if (auth_args.hostname == NULL)
	auth_args.hostname = get_input (_("Hostname of server: "));
      if (auth_args.hostname == NULL)
	return GSASL_AUTHENTICATION_ERROR;
      gsasl_property_set (sctx, prop, auth_args.hostname);
      break;

    case GSASL_ANONYMOUS_TOKEN:
      if (auth_args.anon_token == NULL)
	auth_args.anon_token = get_input (_("Anonymous token: "));
      if (auth_args.anon_token == NULL)
	return GSASL_AUTHENTICATION_ERROR;
      gsasl_property_set (sctx, prop, auth_args.anon_token);
      break;

    case GSASL_AUTHID:
      if (auth_args.authentication_id == NULL)
	auth_args.authentication_id = get_input (_("Authentication ID: "));
      if (auth_args.authentication_id == NULL)
	return GSASL_AUTHENTICATION_ERROR;
      gsasl_property_set (sctx, prop, auth_args.authentication_id);
      break;

    case GSASL_AUTHZID:
      if (auth_args.authorization_id == NULL)
	auth_args.authorization_id = get_input (_("Authorization ID: "));
      if (auth_args.authorization_id == NULL)
	return GSASL_AUTHENTICATION_ERROR;
      gsasl_property_set (sctx, prop, auth_args.authorization_id);
      break;

    case GSASL_PASSCODE:
      if (auth_args.passcode == NULL)
	auth_args.passcode = getpass (_("Passcode: "));
      if (auth_args.passcode == NULL)
	return GSASL_AUTHENTICATION_ERROR;
      gsasl_property_set (sctx, prop, auth_args.passcode);
      break;

    default:
      rc = GSASL_NO_CALLBACK;
      error (_("Unsupported callback property %d"), prop);
      break;
    }

  return rc;
}

void
smtp_quit (void)
{
  struct smtp_reply repl;
  send_line ("QUIT");
  smtp_get_reply (&repl);
  smtp_free_reply (&repl);	/* There's no use checking */
}


/* GSASL Authentication */

int
do_gsasl_auth (Gsasl *ctx, char *mech)
{
  char *output;
  int rc;
  Gsasl_session *sess_ctx = NULL;
  struct smtp_reply repl;
  char buf[LINEBUFFER + 1];

  snprintf (buf, sizeof buf, "AUTH %s", mech);
  send_line (buf);

  rc = gsasl_client_start (ctx, mech, &sess_ctx);
  if (rc != GSASL_OK)
    {
      error (_("SASL gsasl_client_start: %s"), gsasl_strerror (rc));
      exit (1);
    }

  output = NULL;
  memset (&repl, 0, sizeof repl);
  smtp_get_reply (&repl);
  if (repl.code != 334)
    {
      error (_("GSASL handshake aborted"));
      smtp_print_reply (stderr, &repl);
      exit (1);
    }

  do
    {
      rc = gsasl_step64 (sess_ctx, repl.base, &output);
      if (rc != GSASL_NEEDS_MORE && rc != GSASL_OK)
	break;

      send_line (output);

      if (rc == GSASL_OK)
	break;
      smtp_free_reply (&repl);
      smtp_get_reply (&repl);
      if (repl.code != 334)
	{
	  error (_("GSASL handshake aborted"));
	  smtp_print_reply (stderr, &repl);
	  exit (1);
	}
    }
  while (rc == GSASL_NEEDS_MORE);

  free (output);

  if (rc != GSASL_OK)
    {
      error (_("GSASL error: %s"), gsasl_strerror (rc));
      exit (1);
    }

  smtp_free_reply (&repl);
  smtp_get_reply (&repl);

  if (repl.code == 334)
    {
      /* Additional data. Do we need it? */
      smtp_free_reply (&repl);
      smtp_get_reply (&repl);
    }

  if (repl.code != 235)
    {
      error (_("Authentication failed"));
      smtp_print_reply (stderr, &repl);
      smtp_quit ();
      exit (1);
    }

  VDETAIL (1, (_("Authentication successful\n")));

  if (sess_ctx)
    install_gsasl_stream (sess_ctx, &iostream);

  return 0;
}

void
smtp_auth (void)
{
  Gsasl *ctx;
  char *mech;
  int rc;

  mech = find_capa_v (&smtp_capa, "AUTH", auth_mech_list);
  if (!mech)
    {
      error (_("No suitable authentication mechanism found"));
      smtp_quit ();
      exit (1);
    }
  VDETAIL (1, (_("Selected authentication mechanism: %s\n"), mech));

  rc = gsasl_init (&ctx);
  if (rc != GSASL_OK)
    {
      error (_("cannot initialize libgsasl: %s"), gsasl_strerror (rc));
      smtp_quit ();
      exit (1);
    }

  gsasl_callback_set (ctx, callback);

  do_gsasl_auth (ctx, mech);
}


const char *
get_home_dir (void)
{
  static char *home;

  if (!home)
    {
      struct passwd *pwd = getpwuid (getuid ());
      if (pwd)
	home = pwd->pw_dir;
      else
	home = getenv ("HOME");

      if (!home)
	{
	  error (_("What is your home directory?"));
	  exit (1);
	}
    }
  return home;
}

/* Auxiliary functions */
char *
rc_name (void)
{
  char *rc;
  const char *home;

  if (rcfile_name)
    return rcfile_name;
  
  home = get_home_dir ();
  rc = xmalloc (strlen (home) + 1 + sizeof DEFAULT_LOCAL_RCFILE);
  strcpy (rc, home);
  strcat (rc, "/");
  strcat (rc, DEFAULT_LOCAL_RCFILE);
  return rc;
}

#define CMP_UNCHANGED 0
#define CMP_CHANGED   1
#define CMP_ERROR     2

int
diff (char *file, struct smtp_reply *repl)
{
  unsigned char sample[MD5_DIGEST_BYTES];
  unsigned char digest[MD5_DIGEST_BYTES];
  int len;
  int fd = open (file, O_RDONLY);
  if (fd == -1)
    {
      error (_("Cannot open file %s: %s"), file, strerror (errno));
      return CMP_ERROR;
    }
  anubis_md5_file (digest, fd);
  close (fd);

  len = strlen (repl->argv[0]);
  if (len != sizeof digest * 2)
    {
      error (_("Invalid MD5 digest: %s"), repl->argv[0]);
      return CMP_ERROR;
    }
  string_hex_to_bin (sample, repl->argv[0], len);

  return memcmp (digest, sample, sizeof digest) == 0 ?
                 CMP_UNCHANGED : CMP_CHANGED;
}

void
smtp_upload (char *rcname)
{
  FILE *fp;
  struct smtp_reply repl;
  char *buf = NULL;
  size_t n;

  fp = fopen (rcname, "r");
  if (!fp)
    {
      error (_("Cannot open file %s: %s"), rcname, strerror (errno));
      return;
    }

  VDETAIL (1, (_("Uploading %s\n"), rcname));

  send_line ("XDATABASE UPLOAD");
  smtp_get_reply (&repl);
  if (repl.code != 354)
    {
      error (_("UPLOAD failed"));
      smtp_print_reply (stderr, &repl);
      fclose (fp);
      return;
    }
  smtp_free_reply (&repl);

  while (getline (&buf, &n, fp) > 0 && n > 0)
    {
      size_t len = strlen (buf);
      if (len && buf[len - 1] == '\n')
	buf[len - 1] = 0;
      send_line (buf);
    }
  send_line (".");

  fclose (fp);
  smtp_get_reply (&repl);
  if (repl.code != 250)
    {
      smtp_print_reply (stderr, &repl);
      return;
    }
  smtp_free_reply (&repl);
}



/* Main entry points */
int
synch (void)
{
  int fd;
  int rc;
  struct sockaddr_in addr;
  struct smtp_reply repl;
  char *rcname;

  obstack_init (&input_stk);
#ifdef HAVE_TLS
  init_ssl_libs ();
#endif

  VDETAIL (1, (_("Using remote SMTP %s:%d\n"), smtp_host, smtp_port));
  if (parse_host (smtp_host, smtp_port, &addr))
    return 1;

  if ((fd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    {
      error (_("Cannot create socket: %s"), strerror (errno));
      return 1;
    }

  if (connect (fd, (struct sockaddr *) &addr, sizeof (addr)) == -1)
    {
      error (_("Could not connect to %s:%u: %s."),
	     smtp_host, smtp_port, strerror (errno));
      return -1;
    }

  stream_create (&iostream);
  stream_set_io (iostream, (void *) fd, NULL, NULL, NULL, NULL, NULL);

  smtp_get_reply (&repl);
  if (repl.code != 220)
    {
      error (_("Server refused connection"));
      smtp_print_reply (stderr, &repl);
      return 1;
    }
  smtp_free_reply (&repl);

  smtp_ehlo (1);

#ifdef HAVE_TLS
  if (enable_tls && find_capa (&smtp_capa, "STARTTLS", NULL) == 0)
    {
      starttls ();
      smtp_ehlo (0);
    }
#endif

  smtp_auth ();
  /* Get the capabilities */
  smtp_ehlo (0);

  if (find_capa (&smtp_capa, "XDATABASE", NULL))
    {
      error (_("Remote party does not reveal XDATABASE capability"));
      smtp_quit ();
      return 1;
    }

  
  send_line ("XDATABASE EXAMINE");
  smtp_get_reply (&repl);
  switch (repl.code)
    {
    case 300:
      rcname = rc_name ();
      rc = CMP_CHANGED;
      break;
	
    case 250:
      rcname = rc_name ();
      rc = diff (rcname, &repl);
      break;
      
    default:
      error (_("EXAMINE failed"));
      smtp_print_reply (stderr, &repl);
      smtp_quit ();
      return 1;
    }

  if (rc == CMP_CHANGED)
    {
      VDETAIL (1, (_("File changed\n")));
      smtp_upload (rcname);
    }
  else
    VDETAIL (1, (_("File NOT changed\n")));

  smtp_quit ();
  return 0;
}


#define NETRC_NAME ".netrc"
void
read_netrc (void)
{
  if (netrc_name)
    parse_netrc (netrc_name);
  else
    {
      const char *home = get_home_dir ();
      char *netrc = xmalloc (strlen (home) + 1 + sizeof NETRC_NAME);
      strcpy (netrc, home);
      strcat (netrc, "/");
      strcat (netrc, NETRC_NAME);
      parse_netrc (netrc);
      free (netrc);
    }
}

void
xalloc_die ()
{
  error ("%s", _("Not enough memory"));
  exit (1);
}

int
main (int argc, char **argv)
{
  int index;
  
  progname = strrchr (argv[0], '/');
  if (!progname)
    progname = argv[0];
  else
    progname++;

  usr_get_options (argc, argv, &index);

  argc -= optind;
  argv += optind;

  if (argc > 1)
    {
      error (_("Too many arguments. Try anubisusr --help for more info."));
      exit (1);
    }

  if (argc == 1)
    {
      char *p;

      smtp_host = argv[0];
      p = strchr (smtp_host, ':');
      if (p)
	{
	  unsigned long n;
	  *p++ = 0;
	  n = strtoul (p, &p, 0);
	  if (n > USHRT_MAX)
	    {
	      error (_("Port value too big"));
	      exit (1);
	    }
	  smtp_port = n;
	}
    }

  read_netrc ();
  return synch ();
}

/* EOF */

