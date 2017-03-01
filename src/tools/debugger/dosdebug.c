/*
 * DOSEMU debugger,  1995 Max Parke <mhp@light.lightlink.com>
 *
 * This is file dosdebug.c
 *
 * Terminal client for DOSEMU debugger v0.2
 * by Hans Lermen <lermen@elserv.ffm.fgan.de>
 * It uses /var/run/dosemu.dbgXX.PID for connections.
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

// for readline completion

typedef struct {
  char *name;         /* User printable name of the function. */
  rl_icpfunc_t *func; /* Function to call */
  char *doc;          /* Documentation for this function.  */
} COMMAND;

static rl_icpfunc_t db_help;
static rl_icpfunc_t db_quit;
static rl_icpfunc_t db_kill;

static COMMAND cmds[] = {
    {"r", NULL, "                      show regs\n"},
    {"r32", NULL, "                    show regs in 32 bit format\n"},
    {"e", NULL,
     "ADDR val [val ..]\n"
     "                        modify memory (0-1Mb), previous addr for ADDR='-'\n"
     "                        val can be: a hex val (in case of 'e') or decimal\n"
     "                        (in case of 'ed')\n"
     "                        With 'ed' also a hexvalue in form of 0xFF is\n"
     "                        allowed and can be mixed,\n"
     "                        val can also be a character constant (e.g. 'a') or\n"
     "                        a string (\" abcdef \")\n"
     "                        val can also be any register symbolic and has the\n"
     "                        size of that register.\n"
     "                        Except for strings and registers, val can be\n"
     "                        suffixed by\n"
     "                        W(word size) or L (long size), default size is\n"
     "                        byte.\n"},
    {"d", NULL, "ADDR SIZE             dump memory (no limit)\n"},
    {"dump", NULL, "ADDR SIZE FILE     dump memory to file (binary)\n"},
    {"u", NULL, "ADDR SIZE             unassemble memory (no limit)\n"},
    {"g", NULL, "                      go (if stopped)\n"},
    {"stop", NULL, "                   stop (if running)\n"},
    {"mode", NULL, "0|1|2|+d|-d        set mode (0=SEG16, 1=LIN32, 2=UNIX32)\n"
                   "                        for u and d commands\n"},
    {"t", NULL, "                      single step\n"},
    {"ti", NULL, "                     single step into interrupt\n"},
    {"tc", NULL,
     "                     single step, loop forever until key pressed\n"},
    {"bl", NULL, "                     list active breakpoints\n"},
    {"bp", NULL, "ADDR                 set int3 style breakpoint\n"},
    {"bc", NULL, "n                    clear breakpoint #n (as listed by bl)\n"},
    {"bpint", NULL, "xx                set breakpoint on INT xx\n"},
    {"bcint", NULL, "xx                clear breakpoint on INT xx\n"},
    {"bpintd", NULL, "xx [ax]          set breakpoint on DPMI INT xx [ax]\n"},
    {"bcintd", NULL, "xx [ax]          clear breakpoint on DPMI INT xx [ax]\n"},
    {"bpload", NULL,
     "                 stop at start of next loaded DOS program\n"},
    {"bplog", NULL,
     "REGEX             set breakpoint on logoutput using regex\n"},
    {"bclog", NULL,
     "REGEX             clear breakpoint on logoutput using regex\n"},
    {"rmapfile", NULL,
     "[FILE]         (re)read a dosemu.map ('nm' format) file\n"},
    {"rusermap", NULL,
     "org FILE       read microsoft linker format .MAP file 'fn'\n"
     "                        code origin = 'org'.\n"},
    {"ldt", NULL,
     "sel lines           dump ldt from selector 'sel' for 'lines'\n"},
    {"log", NULL,
     "[FLAGS]             get/set debug-log flags (e.g 'log +M-k')\n"},
    {"kill", db_kill, "                   Kill the dosemu process\n"},
    {"quit", db_quit, "                   Quit the debug session\n"},
    {"help", db_help, "                   Show this help\n"},
    {"?", db_help, "                      Synonym for help\n"},
    {"", NULL, "<ENTER>                Repeats previous command\n"},
    {NULL, NULL, NULL}};


static COMMAND *find_cmd(char *name) {
  int i;
  char *tmp, *p;

  tmp = strdup(name);
  if(!tmp)
    return NULL;

  p = strchr(tmp, ' ');
  if(p)
    *p = '\0';

  for (i = 0; cmds[i].name; i++)
    if (strcmp(tmp, cmds[i].name) == 0) {
      free(tmp);
      return (&cmds[i]);
    }

  free(tmp);
  return NULL;
}

static char *db_cmd_generator(const char *text, int state) {
  static int list_index, len;
  char *name;

  /* If this is a new word to complete, initialize index to 0 and save the
   * length of TEXT for efficiency */
  if (!state) {
    list_index = 0;
    len = strlen(text);
  }

  /* Return the next name which partially matches from the command list. */
  while ((name = cmds[list_index].name)) {
    list_index++;

    if (strncmp(name, text, len) == 0)
      return strdup(name);
  }

  return NULL;
}

static char **db_completion(const char *text, int start, int end)
{
  char **matches = NULL;

  /* If this word is at the start of the line, then it is a command to
   * complete. Otherwise it is the name of a file in the current directory.
   */
  if (start == 0)
    matches = rl_completion_matches(text, db_cmd_generator);

  return matches;
}

static int db_help(char *line) {
  int i;

  fputs("\n", rl_outstream);
  for (i = 0; cmds[i].name; i++) {
    if (cmds[i].doc)
      fprintf(rl_outstream, "%s %s", cmds[i].name, cmds[i].doc);
  }

  fflush(rl_outstream);
  return 0;
}

static int db_quit(char *line) {
  fputs("\nquit\n", rl_outstream);
  fflush(rl_outstream);
  running = 0;
  return 0;
}

static int db_kill(char *line) {
  kill_timeout = KILL_TIMEOUT;
  return 0;
}

/*
 * Callback function called for each line when accept-line executed, EOF
 * seen, or EOF character read.
 */
static void handle_console_input (char *line)
{
  static char *last_line = NULL;
  int len;
  COMMAND *cmd;

  if (!line) {
    db_quit(line);
    return;
  }

  /* Check if command valid */
  cmd = find_cmd(line);
  if(!cmd) {
    fprintf(stderr, "Command '%s' not implemented\n", line);
    free(line);
    return;
  }

  /* Update or use history */
  if (*line) {
    add_history(line);
    if (last_line)
      free(last_line);
    last_line = strdup(line);
    if ((strncmp(last_line, "d ", 2) == 0) || (strncmp(last_line, "u ", 2) == 0))
      last_line[1] = '\0';
  } else {
    free(line);
    if (!last_line) {
      return;
    }
    cmd = find_cmd(last_line);
    if(!cmd) {
      free(last_line);
      last_line = NULL;
      return;
    }
    line = strdup(last_line);
  }

  /* Maybe it's implemented locally */
  if (cmd->func) {
    cmd->func(line);
    free(line);
    return;
  }

  /* Pass to dosemu */
  len = strlen(line);
  if (write(fd, line, len) != len) {
    fprintf(stderr, "Write to socket failed\n");
  }
  free(line);
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

  /* so that we can use conditional ~/.inputrc commands */
  rl_readline_name = "dosdebug";

  /* Install the readline completion function */
  rl_attempted_completion_function = db_completion;

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
