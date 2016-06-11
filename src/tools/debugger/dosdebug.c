/*
 * DOSEMU debugger,  1995 Max Parke <mhp@light.lightlink.com>
 *
 * This is file dosdebug.c
 *
 * Terminal client for DOSEMU debugger v0.2
 * by Hans Lermen <lermen@elserv.ffm.fgan.de>
 * It uses /var/run/dosemu.dbgXX.PID for connections.
 *
 * The switch-console code is from Kevin Buhr <buhr@stat.wisc.edu>
 */

#include "config.h"
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>	/* for struct timeval */
#include <time.h>	/* for CLOCKS_PER_SEC */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "utilities.h"

#define DOSEMU_SKT "dosemu.dbg"
#define DOSEMU_SKT_MAX 10

#define MHP_BUFFERSIZE 8192

#define FOREVER ((((unsigned int)-1) >> 1) / CLOCKS_PER_SEC)
#define KILL_TIMEOUT 2

int kill_timeout=FOREVER;
int fd;

int running;
const char *prompt = "dosdebug> ";


static int find_dosemu_sockets(char **sktnames, int max)
{
  FILE *fp;
  char buf[1024], *p;
  int len, found, i, isdup;

  if ((fp = fopen("/proc/net/unix", "r")) == NULL)
    return 0;

  // 00000000: 00000003 00000000 00000000 0001 03 25219 @/tmp/.X11-unix/X0
  for (found=0;found < max;/* */) {
    if (fgets(buf, sizeof(buf), fp) == NULL) {
      fclose(fp);
      break;
    }
    buf[sizeof(buf)-1] = '\0';

    len = strlen(buf);
    if (buf[len-1] == '\n') {
      buf[len-1] = '\0';
    }

    p = strstr(buf, DOSEMU_SKT);
    for (/* */; p >= buf; p--) {
      if (*p == ' ') {
        for (isdup = 0,i = 0; i < found; i++) { /* check for a duplicate */
          if (strcmp(sktnames[i], p+1) == 0) {
            isdup = 1;
          }
        }
        if (!isdup) {
          sktnames[found] = strdup(p+1);
          found++;
        }
        break;
      }
    }
  }
  return found;
}


#if 0
static int switch_console(char new_console)
{
  int newvt;
  int vt;

  if ((new_console < '1') || (new_console > '8')) {
    fprintf(stderr,"wrong console number\n");
    return -1;
  }

  newvt = new_console & 15;
  vt = open( "/dev/tty1", O_RDONLY );
  if( vt == -1 ) {
    perror("open(/dev/tty1)");
    return -1;
  }
  if( ioctl( vt, VT_ACTIVATE, newvt ) ) {
    perror("ioctl(VT_ACTIVATE)");
    return -1;
  }
  if( ioctl( vt, VT_WAITACTIVE, newvt ) ) {
    perror("ioctl(VT_WAITACTIVE)");
    return -1;
  }

  close(vt);
  return 0;
}
#endif

/*
 * Callback function called for each line when accept-line executed, EOF
 * seen, or EOF character read.
 */
static void handle_console_input (char *line)
{
  static char *last_cmd = NULL;
  int len;

  /* Can use ^D (stty eof) or `quit' to exit. */
  if (line == NULL || !strcmp(line, "quit")) {
    fputs("\nquit\n", rl_outstream);
    fflush(rl_outstream);
    running = 0;
  } else {
    if (*line) {
      add_history(line);
      if (last_cmd)
        free(last_cmd);
      last_cmd = strdup(line);
    } else {
      if (last_cmd) {
        free(line);
        line = strdup(last_cmd);
      }
    }

    len = strlen(line);

#if 0
    if (!strncmp(line, "console ", 8) && len > 8) {
      switch_console(line[8]);
      free(line);
      return;
    }
#endif
    if (!strcmp(line, "kill")) {
      kill_timeout=KILL_TIMEOUT;
    }
    if (write(fd, line, len) != len) {
      fprintf(stderr, "write to socket failed\n");
    }
    free(line);
  }
}


/* returns 0: done, 1: more to do */
static int handle_dbg_input(int *retval)
{
  char buf[MHP_BUFFERSIZE], *p;
  int n;

  do {
    n=read(fd, buf, sizeof(buf));
  } while (n < 0 && errno == EAGAIN);
  if (n > 0) {
    if ((p=memchr(buf,1,n))!=NULL) /* dosemu signalled us to quit - eek! */
      n=p-buf;

    fputs("\n", rl_outstream);
    fwrite(buf, 1, n, rl_outstream);
    fflush(rl_outstream);
    rl_on_new_line();
    rl_redisplay();

    if (p != NULL) {
      *retval = 0;
      return 0;
    }
  }
  if (n == 0) {
    *retval = 1;
    return 0;
  }
  return 1;
}


int main (int argc, char **argv)
{
  struct timeval timeout;
  int numfds;
  int fdrl;
  fd_set readfds;
  pid_t dospid;
  struct sockaddr_un local;
  socklen_t len;
  char *sktname;
  char *sktnames[DOSEMU_SKT_MAX];
  int num, i;
  struct ucred ucred;
  socklen_t uclen;
  char msg[MHP_BUFFERSIZE];
  int retval;

  if(argc > 1) {                                   /* socket name supplied */
    sktname = strdup(argv[1]);
  } else {                                       /* attempt to discover it */
    num = find_dosemu_sockets(sktnames, DOSEMU_SKT_MAX);
    if (num > 1) {
      fprintf(stderr, "Multiple dosemu processes found, please choose one\n");
      for (i=0; i<num; i++) {
        fprintf(stderr, "  %s\n", sktnames[i]);
        free(sktnames[i]);
      }
      return 0;
    }
    if (num == 0) {
      fprintf(stderr, "No dosemu process found, dosdebug not available\n");
      return 1;
    }
    sktname = sktnames[0];
  }

  fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  local.sun_family = AF_UNIX;
  strncpy(local.sun_path, sktname, sizeof(local.sun_path)-1);
  local.sun_path[sizeof(local.sun_path)-1] = '\0';
  len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(local.sun_path);
  free(sktname);

  if (local.sun_path[0] == '@') { /* linux abstract socket */
    local.sun_path[0] = '\0';
    len--;
  }

  if (connect(fd, (struct sockaddr *)&local, len) == -1) {
    fprintf(stderr, "Can't connect socket, dosdebug not available\n");
    return 2;
  }

  // get dospid
  uclen = sizeof(struct ucred);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &uclen) == -1) {
    fprintf(stderr, "Can't get dosemu.bin pid, kill via signal not available\n");
    dospid = 0;
  } else {
    dospid = ucred.pid;
    fprintf(stderr, "Dosemu.bin pid is %d\n", dospid);
  }

  /* Install the readline handler. */
  rl_callback_handler_install(prompt, handle_console_input);

  // check connection, banner expected
  num = recv(fd, &msg, MHP_BUFFERSIZE, 0);
  if (num < 0) {
    fprintf(stderr, "Can't communicate with dosemu, do you have permission?\n");
    rl_callback_handler_remove();
    return 3;
  }
  fwrite(msg, 1, num, rl_outstream);
  fflush(rl_outstream);

  if (send(fd, "r0\n", 3, MSG_NOSIGNAL|MSG_EOR) != 3) {
    fprintf(stderr, "Can't write to dosemu, do you have permission?\n");
    rl_callback_handler_remove();
    return 3;
  }

  FD_ZERO(&readfds);

  fdrl = fileno(rl_instream);

  for (running=1, retval=0; running; /* */) {
    FD_SET(fd, &readfds);
    FD_SET(fdrl, &readfds);
    timeout.tv_sec=kill_timeout;
    timeout.tv_usec=0;
    numfds=select(((fd > fdrl) ? fd : fdrl) + 1, /* max number of fds to scan */
                   &readfds,
                   NULL /*no writefds*/,
                   NULL /*no exceptfds*/, &timeout);
    if (numfds > 0) {
      if (FD_ISSET(fdrl, &readfds))
        rl_callback_read_char();

      if (FD_ISSET(fd, &readfds))
        if (!handle_dbg_input(&retval))
          break;

    } else {
      if (kill_timeout != FOREVER) {
        if (kill_timeout > KILL_TIMEOUT) {
          if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &uclen) != -1) {
            fprintf(stderr, "...oh dear, have to do kill SIGKILL\n");
            if (dospid > 0) {
              kill(dospid, SIGKILL);
              fprintf(stderr, "dosemu process (pid %d) was killed\n", dospid);
            } else {
              fprintf(stderr, "we have no valid pid for dosemu, kill manually\n");
            }
          }
          else
            fprintf(stderr, "dosdebug terminated, dosemu process (pid %d) is killed\n", dospid);
          retval = 1;
          break;
        }
        fprintf(stderr, "no reaction, trying kill SIGTERM\n");
        if (dospid > 0) {
          kill(dospid, SIGTERM);
        } else {
          fprintf(stderr, "we have no valid pid for dosemu, kill manually\n");
        }
        kill_timeout += KILL_TIMEOUT;
      }
    }
  }
  rl_crlf();
  rl_callback_handler_remove();
  return retval;
}
