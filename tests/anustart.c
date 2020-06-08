/*
  NAME
    anustart - test anubis in daemon mode
    
  SYNOPSIS
    anustart ANU_OPTIONS -- COMMAND ARGS ...

  DESCRIPTION
    Starts two programs: anubis -S -b PORT with additional options from
    ANU_OPTIONS, and COMMAND with ARGS.  PORT is selected as the first
    unused TCP port in range 1025-65535.  Environment variable ANUBIS_PORT
    is set to the selected value.  When anubis is up and running, it sends
    the SIGUSR1 to anustart, which then starts COMMAND with ARGS and waits
    for it to terminate.  Then, it shuts down anubis and exits with the exit
    code from COMMAND.  If anubis fails to respond within 5 seconds, or
    COMMAND fails to terminate within that amount of time, both are killed
    and anustart exits with code 3.

  EXIT STATUS
    0
        Success.
    1
        Failure.
    2
        Command line usage error.
    3   
        Timeout waiting for anubis to respond.
    4
        Anubis terminated prematurely.

    Another value means error code from COMMAND.

  LICENSE
    This file is part of GNU Anubis testsuite.
    Copyright (C) 2003-2020 The Anubis Team.

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
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

char const *progname;

/* Exit codes */
enum
  {
    EX_OK = 0,
    EX_ERROR = 1,
    EX_USAGE = 2,
    EX_TIMEOUT = 3,
    EX_ANUTERM = 4
  };


static int 
open_socket (int *p_local_port, int max_port)
{
  int fd;
  int true = 1;
  struct sockaddr_in sin;
  int local_port;
  
  memset (&sin, 0, sizeof (sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  
  fd = socket (AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    {
      fprintf (stderr, "%s: can't open socket: %d\n", progname, errno);
      return -1;
    }

  setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &true, sizeof (true));

  local_port = *p_local_port;
  while (++local_port < max_port)
    {
      sin.sin_port = htons((unsigned short)local_port);
      if (bind (fd, (struct sockaddr *)&sin, sizeof (sin)) == 0)
	{
	  *p_local_port = local_port;
	  return fd;
	}
    }

  fprintf (stderr, "%s: no free port\n", progname);
  close (fd);
  fd = -1;
  return fd;
}

pid_t
runcom (char *prog, char **argv, char *out, char *err)
{
  pid_t pid;
  int fd_out, fd_err;

  if (out)
    {
      fd_out = open (out, O_WRONLY|O_CREAT|O_TRUNC, 0666);
	if (!fd_out)
	  {
	    fprintf (stderr, "%s: can't open %s: %s\n",
		     progname, out, strerror(errno));
	    exit (EX_ERROR);
	  }
    }
  else
    fd_out = -1;
  if (err)
    {
      fd_err = open (err, O_WRONLY|O_CREAT|O_TRUNC, 0666);
      if (!fd_err)
	{
	  fprintf (stderr, "%s: can't open %s: %s\n",
		   progname, err, strerror(errno));
	  exit (EX_ERROR);
	}
    }
  else
    fd_err = -1;

  pid = fork ();
  if (pid == -1)
    {
      perror ("fork");
      exit (EX_ERROR);
    }

  if (pid > 0)
    return pid;

  /* Child */
  switch (fd_out)
    {
    case -1:
    case 1:
      break;
      
    default:
      if (dup2 (fd_out, 1) == -1)
	{
	  perror ("dup2");
	  exit (EX_ERROR);
	}
      close (fd_out);
    }
    
  switch (fd_err)
    {
    case -1:
    case 1:
      break;
      
    default:
      if (dup2 (fd_err, 2) == -1)
	{
	  perror ("dup2");
	  exit (EX_ERROR);
	}
      close (fd_err);
    }

  execvp (prog ? prog : argv[0], argv);
  perror (argv[0]);
  _exit (127);
}

int volatile signum;

void
sighan (int sig)
{
  signum = sig;
}

int
main (int argc, char **argv)
{
  int i, j;
  int fd;
  char **argv_buf;
  char **anu_argv;
  char **com_argv;
  int local_port = 1024;
  int max_port = USHRT_MAX;
  struct sigaction act;
  sigset_t sigs, oldsigs;
  int timeout = 5;
  enum
  {
   ASTATE_INITIAL,
   ASTATE_RUNNING,
   ASTATE_CHLDEXIT,
   ASTATE_STOP
  } state = ASTATE_INITIAL;
  int exit_code;
  pid_t anu_pid, com_pid;
  char portbuf[sizeof("localhost:65535")];
  
  progname = argv[0]; 

  /* Split command line */
  anu_argv = argv;
  
  for (i = 0; i < argc; i++)
    if (strcmp (argv[i], "--") == 0)
      break;

  if (i == argc)
    {
      fprintf (stderr, "%s: no command given\n", progname);
      return EX_USAGE;
    }

  /*
   * . 1 extra slots for the -S option in anubis command line.
   * . 1 slot for the terminating NULL in the user command.
   */
  argv_buf = calloc (argc + 3, sizeof (argv_buf[0]));
  argv_buf[0] = "anubis";
  for (j = 1; j < i; j++)
    argv_buf[j] = argv[j];
  argv_buf[i++] = "-S";
  argv_buf[i++] = NULL;

  anu_argv = argv_buf;
  com_argv = argv_buf + i;
  
  /* Now, j points to "--" */
  while (++j < argc)
    {
      argv_buf[i++] = argv[j];
    }
  argv_buf[i] = NULL;

  fd = open_socket (&local_port, max_port);
  if (fd == -1)
    return EX_ERROR;

  if (fd != 3)
    {
      if (dup2 (fd, 3))
	{
	  fprintf (stderr, "%s: can't open socket at fd 3\n", progname);
	  return EX_ERROR;
	}
    }

  snprintf (portbuf, sizeof (portbuf), "%d", local_port);
  setenv ("ANUBIS_PORT", portbuf, 1);
  
  /* Install signals */
  act.sa_flags = 0;
  sigemptyset (&act.sa_mask);
  act.sa_handler = sighan;

  sigaction (SIGCHLD, &act, NULL);
  sigaction (SIGALRM, &act, NULL);
  sigaction (SIGUSR1, &act, NULL);

  sigemptyset (&sigs);
  sigaddset (&sigs, SIGCHLD);
  sigaddset (&sigs, SIGALRM);
  sigaddset (&sigs, SIGUSR1);
  sigprocmask (SIG_BLOCK, &sigs, &oldsigs);

  anu_pid = runcom (anu_argv[0], anu_argv, NULL, NULL);

  /* Set timeout */
  alarm (timeout);
  
  state = ASTATE_INITIAL;
  while (state != ASTATE_STOP)
    {
      pid_t pid;
      int status;
	    
      sigsuspend (&oldsigs);
      switch (signum)
	{
	case SIGUSR1:
	  /* Start command */
	  com_pid = runcom (NULL, com_argv, NULL, NULL);
	  state = ASTATE_RUNNING;
	  break;

	case SIGCHLD:
	  while ((pid = waitpid ((pid_t)-1, &status, WNOHANG)) > 0)
	    {
	      if (pid == anu_pid)
		{
		  anu_pid = -1;
		  switch (state)
		    {
		    case ASTATE_INITIAL:
		      exit_code = EX_ANUTERM;
		      state = ASTATE_STOP;
		      break;
		      
		    case ASTATE_RUNNING:
		      kill (com_pid, SIGTERM);
		      exit_code = EX_ANUTERM;
		      state = ASTATE_CHLDEXIT;
		      break;
		      
		    case ASTATE_CHLDEXIT:
		      state = ASTATE_STOP;
		      break;
		      
		    default:
		      abort ();
		    }
		}
	      else if (pid == com_pid)
		{
		  com_pid = -1;
		  switch (state)
		    {
		    case ASTATE_RUNNING:
		      kill (anu_pid, SIGTERM);
		      exit_code = WEXITSTATUS (status);
		      state = ASTATE_CHLDEXIT;
		      break;
		      
		    case ASTATE_CHLDEXIT:
		      state = ASTATE_STOP;
		      break;
		      
		    default:
		      abort ();
		    }
		}
	    }
	  break;

	case SIGALRM:
	  state = ASTATE_STOP;
	  exit_code = EX_TIMEOUT;
	}
    }
  
  return exit_code;
}

