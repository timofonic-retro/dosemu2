/*
 * DOSEMU debugger,  1995 Max Parke <mhp@light.lightlink.com>
 *
 * This is file mhpdbg.c
 *
 * changes: ( for details see top of file mhpdbgc.c )
 *
 *   07Jul96 Hans Lermen <lermen@elserv.ffm.fgan.de>
 *   19May96 Max Parke <mhp@lightlink.com>
 *   16Sep95 Hans Lermen <lermen@elserv.ffm.fgan.de>
 *   08Jan98 Hans Lermen <lermen@elserv.ffm.fgan.de>
 */

#include "config.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include <assert.h>

#include "bitops.h"
#include "emu.h"
#include "cpu.h"
#include "bios.h"
#include "coopth.h"
#include "dpmi.h"
#include "timers.h"
#include "dosemu_config.h"
#include "sig.h"
#define MHP_PRIVATE
#include "mhpdbg.h"

#define USE_ABSTRACT_SOCKETS 1

#define DOSEMU_SKT "dosemu.dbg"

struct mhpdbg mhpdbg;
unsigned long dosdebug_flags;

static void vmhp_printf(const char *fmt, va_list args);
static void mhp_poll(void);
static void mhp_puts(char*);
void mhp_putc(char);

static char mhp_banner[] = {
  "\nDOSEMU Debugger V0.6 connected\n"
  "- type ? to get help on commands -\n"
};
struct mhpdbgc mhpdbgc ={0};

static int listener_fd;

/********/
/* CODE */
/********/

static void mhp_puts(char* s)
{
  for (;;) {
    if (*s == 0x00)
      break;
    mhp_putc (*s++);
  }
}

void mhp_putc(char c1)
{
#if 0
   if (c1 == '\n') {
      mhpdbg.sendbuf[mhpdbg.sendptr] = '\r';
      if (mhpdbg.sendptr < SRSIZE-1)
	 mhpdbg.sendptr++;
   }
#endif
   mhpdbg.sendbuf[mhpdbg.sendptr] = c1;
   if (mhpdbg.sendptr < SRSIZE-1)
      mhpdbg.sendptr++;

}

void mhp_send(void)
{
  if (mhpdbg.sendptr) {
    if (mhpdbg.tracefd != -1)
      write(mhpdbg.tracefd, mhpdbg.sendbuf, mhpdbg.sendptr);

    if ((mhpdbg.fd != -1) && (!traceloop))
      write(mhpdbg.fd, mhpdbg.sendbuf, mhpdbg.sendptr);

    mhpdbg.sendptr = 0;
  }
}

void mhp_close(void)
{
   if (mhpdbg.fd == -1) return;
   if (mhpdbg.active) {
     mhp_putc(1); /* tell debugger terminal to also quit */
     mhp_send();
   }
   remove_from_io_select(mhpdbg.fd);
   close(mhpdbg.fd);
   mhpdbg.fd = -1;
   mhpdbg.active = 0;

   mhpdbg.sendptr = 0;
   mhpdbg.nbytes = 0;
}

static int wait_for_debug_terminal = 0;

int vmhp_log_intercept(int flg, const char *fmt, va_list args)
{
  if (mhpdbg.active <= 1) return 0;
  if (flg) {
    if (dosdebug_flags & DBGF_LOG_TO_DOSDEBUG) {
      vmhp_printf(fmt, args);
      mhp_send();
    }
    if (dosdebug_flags & DBGF_LOG_TO_BREAK){
      mhp_regex(fmt, args);
    }
  }
  return 0;
}

static void mhp_input_async(void *arg)
{
  mhp_input();
}

static void mhp_accept_async(void *arg)
{
  size_t num;

  mhpdbg.fd = accept(listener_fd, NULL, NULL);
  if (mhpdbg.fd < 0) {
    fprintf(stderr, "Can't accept on socket, dosdebug not available\n");
    return;
  }

#ifdef USE_ABSTRACT_SOCKETS

  struct ucred ucred;
  socklen_t uclen = sizeof(struct ucred);

  if (getsockopt(mhpdbg.fd, SOL_SOCKET, SO_PEERCRED, &ucred, &uclen) == -1) {
    fprintf(stderr, "Can't get client credentials, dosdebug not available\n");
    shutdown(mhpdbg.fd, SHUT_RDWR);
    close(mhpdbg.fd);
    mhpdbg.fd = -1;
    return;
  }

  if (!((ucred.uid == 0) || ucred.uid == getuid())) {
    fprintf(stderr, "Incorrect client credentials, dosdebug not available\n");
    shutdown(mhpdbg.fd, SHUT_RDWR);
    close(mhpdbg.fd);
    mhpdbg.fd = -1;
    return;
  }

#endif

  add_to_io_select(mhpdbg.fd, mhp_input_async, NULL);

  num = send(mhpdbg.fd, mhp_banner, strlen(mhp_banner), MSG_EOR);
  if (num != strlen(mhp_banner))
    fprintf(stderr, "Short write of dosdebug banner\n");
}


static void mhp_init(void)
{
  struct sockaddr_un local;
  socklen_t len;
  pid_t pid = getpid();

  listener_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  mhpdbg.fd = -1;
  mhpdbg.tracefd = -1;

  local.sun_family = AF_UNIX;

#ifdef USE_ABSTRACT_SOCKETS

  snprintf(local.sun_path, sizeof(local.sun_path)-1, "@%s.%d",
           DOSEMU_SKT, pid);
  local.sun_path[sizeof(local.sun_path)-1] = '\0';
  len = offsetof(struct sockaddr_un, sun_path) + strlen(local.sun_path);
  local.sun_path[0] = '\0';

  fprintf(stderr, "socket name is @%s\n", local.sun_path+1);

#else

  snprintf(local.sun_path, sizeof(local.sun_path)-1, "/var/run/user/%d/%s.%d",
           getuid(), DOSEMU_SKT, pid);
  local.sun_path[sizeof(local.sun_path)-1] = '\0';
  len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(local.sun_path);

  fprintf(stderr, "socket name is %s\n", local.sun_path);

#endif

  if (bind(listener_fd, (struct sockaddr *)&local, len) == -1) {
    fprintf(stderr, "Can't bind socket, dosdebug not available\n");
    return;
  }

  if (listen(listener_fd, 1) == -1) {
    fprintf(stderr, "Can't listen on socket, dosdebug not available\n");
    return;
  }

  mhpdbg.active = 0;
  mhpdbg.sendptr = 0;

  add_to_io_select(listener_fd, mhp_accept_async, NULL);

  memset(&mhpdbg.intxxtab, 0, sizeof(mhpdbg.intxxtab));
  memset(&mhpdbgc.intxxalt, 0, sizeof(mhpdbgc.intxxalt));

  if (dosdebug_flags) {
    /* don't fiddle with select, just poll until the terminal
     * comes up to send the first input
     */
     mhpdbg.nbytes = -1;
     wait_for_debug_terminal = 1;
     mhp_input();
     mhpdbgc.stopped = 1;
  }
}

void mhp_input()
{
  struct iovec iov[1];
  struct msghdr msgh;
  struct cmsghdr *h;

/* Size of the cmsg including one file descriptor */
#define CMSG_SIZE CMSG_SPACE(sizeof(int))
  char cmsgbuf[CMSG_SIZE];

  if (mhpdbg.fd == -1)
    return;

  iov[0].iov_base = mhpdbg.recvbuf;
  iov[0].iov_len = sizeof(mhpdbg.recvbuf);

  msgh.msg_name = NULL;
  msgh.msg_namelen = 0;

  msgh.msg_iov = iov;
  msgh.msg_iovlen = 1;

  msgh.msg_control = cmsgbuf;
  msgh.msg_controllen = CMSG_SIZE;
  msgh.msg_flags = 0;

  mhpdbg.nbytes = recvmsg(mhpdbg.fd, &msgh, 0);
  if (mhpdbg.nbytes == -1)
    return;

  /* if we received a file descriptor save it for subsequent assignment */
  h = CMSG_FIRSTHDR(&msgh);
  if (h && h->cmsg_len == CMSG_LEN(sizeof(int)) &&
      h->cmsg_level == SOL_SOCKET && h->cmsg_type == SCM_RIGHTS) {
    mhpdbg.recvfd = ((int *)CMSG_DATA(h))[0];
  }

  if (mhpdbg.nbytes == 0 && !wait_for_debug_terminal) {
    if (mhpdbgc.stopped) {
      mhp_cmd("g");
      mhp_send();
    }
    mhpdbg.active = 0;
    return;
  }

  if (!mhpdbg.active) {
    mhpdbg.active = 1; /* 1 = new session */
  }
}

static void mhp_poll_loop(void)
{
   static int in_poll_loop;
   char *ptr, *ptr1;
   if (in_poll_loop) {
      error("mhp_poll_loop() reentered\n");
      return;
   }
   in_poll_loop++;
   for (;;) {
      int ostopped;
      handle_signals();
      /* hack: set stopped to 1 to not allow DPMI to run */
      ostopped = mhpdbgc.stopped;
      mhpdbgc.stopped = 1;
      coopth_run();
      mhpdbgc.stopped = ostopped;
      /* NOTE: if there is input on mhpdbg.fd, as result of handle_signals
       *       io_select() is called and this then calls mhp_input.
       *       ( all clear ? )
       */
      if (mhpdbg.nbytes <= 0) {
         if (traceloop && mhpdbgc.stopped) {
           mhpdbg.nbytes=strlen(loopbuf);
           memcpy(mhpdbg.recvbuf,loopbuf,mhpdbg.nbytes+1);
         }
         else {
          if (mhpdbgc.stopped) {
            usleep(JIFFIE_TIME/10);
            continue;
          }
          else break;
        }
      } else {
        if (traceloop) {
          traceloop = 0;
          loopbuf[0] = '\0';
          mhpdbg.nbytes = snprintf(mhpdbg.recvbuf, sizeof mhpdbg.recvbuf, "t");
        }
      }
      if ((mhpdbg.recvbuf[0] == 'q') && (mhpdbg.recvbuf[1] <= ' ')) {
        if (mhpdbgc.stopped) {
          mhp_cmd("g");
          mhp_send();
        }
        mhp_close();
        break;
      }
      mhpdbg.recvbuf[mhpdbg.nbytes] = 0x00;
      ptr = (char *)mhpdbg.recvbuf;
      while (ptr && *ptr) {
	ptr1 = strsep(&ptr, "\r\n");
	if (!ptr1)
	  ptr1 = ptr;
	if (!ptr1)
	  break;
        mhp_cmd(ptr1);
        mhp_send();
      }
      mhpdbg.nbytes = 0;
   }
   in_poll_loop--;
}

static void mhp_pre_vm86(void)
{
    if (isset_TF()) {
	if (mhpdbgc.trapip != mhp_getcsip_value()) {
	    mhpdbgc.trapcmd = 0;
	    mhpdbgc.stopped = 1;
	    mhp_poll();
	}
    }
}

static void mhp_poll(void)
{

  if (!mhpdbg.active) {
     mhpdbg.nbytes = 0;
     return;
  }

  if (mhpdbg.active == 1) {
    /* new session has started */
    mhpdbg.active++;

    mhp_cmd("rmapfile");
    mhp_send();
    mhp_poll_loop();
  }
  if (mhpdbgc.want_to_stop) {
    mhpdbgc.stopped = 1;
    mhpdbgc.want_to_stop = 0;
  }
  if (mhpdbgc.stopped) {
      if (dosdebug_flags & DBGF_LOG_TEMPORARY) {
         dosdebug_flags &= ~DBGF_LOG_TEMPORARY;
	 mhp_cmd("log off");
      }
      mhp_cmd("r0");
      mhp_send();
  }
  mhp_poll_loop();
}

static void mhp_boot(void)
{

  if (!wait_for_debug_terminal) {
     mhpdbg.nbytes = 0;
     return;
  }

  wait_for_debug_terminal = 0;
  mhp_poll_loop();
  mhpdbgc.want_to_stop = 1;
}

void mhp_intercept_log(char *flags, int temporary)
{
   char buf[255];
   sprintf(buf, "log %s", flags);
   mhp_cmd(buf);
   mhp_cmd("log on");
   if (temporary)
      dosdebug_flags |= DBGF_LOG_TEMPORARY;
}

void mhp_intercept(char *msg, char *logflags)
{
   if (!mhpdbg.active || (mhpdbg.fd == -1)) return;
   mhpdbgc.stopped = 1;
   mhpdbgc.want_to_stop = 0;
   traceloop = 0;
   mhp_printf(msg);
   mhp_cmd("r0");
   mhp_send();
   if (!(dosdebug_flags & DBGF_IN_LEAVEDOS)) {
     if (in_dpmi_pm())
       dpmi_return_request();
     if (logflags)
       mhp_intercept_log(logflags, 1);
     return;
   }
   mhp_poll_loop();
}

void mhp_exit_intercept(int errcode)
{
   char buf[255];
   if (!errcode || !mhpdbg.active || (mhpdbg.fd == -1) ) return;

   sprintf(buf, "\n****\nleavedos(%d) called, at termination point of DOSEMU\n****\n\n", errcode);
   dosdebug_flags |= DBGF_IN_LEAVEDOS;
   mhp_intercept(buf, NULL);
}

int mhp_revectored(int inum)
{
    return test_bit(inum, mhpdbgc.intxxalt);
}

unsigned int mhp_debug(enum dosdebug_event code, unsigned int parm1, unsigned int parm2)
{
  int rtncd = 0;
#if 0
  return rtncd;
#endif
  mhpdbgc.currcode = code;
  mhp_bpclr();
  switch (DBG_TYPE(mhpdbgc.currcode)) {
  case DBG_INIT:
	  mhp_init();
	  break;
  case DBG_BOOT:
	  mhp_boot();
	  break;
  case DBG_INTx:
	  if (!mhpdbg.active)
	     break;
	  if (test_bit(DBG_ARG(mhpdbgc.currcode), mhpdbg.intxxtab)) {
	    if ((mhpdbgc.bpload==1) && (DBG_ARG(mhpdbgc.currcode) == 0x21) && (LWORD(eax) == 0x4b00) ) {

	      /* mhpdbgc.bpload_bp=((long)SREG(cs) << 4) +LWORD(eip); */
	      mhpdbgc.bpload_bp = SEGOFF2LINEAR(SREG(cs), LWORD(eip));
	      if (mhp_setbp(mhpdbgc.bpload_bp)) {
		mhp_printf("bpload: intercepting EXEC\n", SREG(cs), REG(eip));
		/*
		mhp_cmd("r");
		mhp_cmd("d ss:sp 30h");
		*/

		mhpdbgc.bpload++;
		mhpdbgc.bpload_par=MK_FP32(BIOSSEG,(long)DBGload_parblock-(long)bios_f000);
		MEMCPY_2UNIX(mhpdbgc.bpload_par, SEGOFF2LINEAR(SREG(es), LWORD(ebx)), 14);
		MEMCPY_2UNIX(mhpdbgc.bpload_cmdline, PAR4b_addr(commandline_ptr), 128);
		MEMCPY_2UNIX(mhpdbgc.bpload_cmd, SEGOFF2LINEAR(SREG(ds), LWORD(edx)), 128);
		SREG(es)=BIOSSEG;
		LWORD(ebx)=(void *)mhpdbgc.bpload_par - MK_FP32(BIOSSEG, 0);
		LWORD(eax)=0x4b01; /* load, but don't execute */
	      }
	      else {
		mhp_printf("bpload: ??? #1\n");
		mhp_cmd("r");

	        mhpdbgc.bpload_bp=0;
	        mhpdbgc.bpload=0;
	      }
	      if (!--mhpdbgc.int21_count) {
	        volatile register int i=0x21; /* beware, set_bit-macro has wrong constraints */
	        clear_bit(i, mhpdbg.intxxtab);
	        if (test_bit(i, mhpdbgc.intxxalt)) {
	          clear_bit(i, mhpdbgc.intxxalt);
	          reset_revectored(i, &vm86s.int_revectored);
	        }
	      }
	    }
	    else {
	      if ((DBG_ARG(mhpdbgc.currcode) != 0x21) || !mhpdbgc.bpload ) {
	        mhpdbgc.stopped = 1;
	        if (parm1)
	          LWORD(eip) -= 2;
	        mhpdbgc.int_handled = 0;
	        mhp_poll();
	        if (mhpdbgc.int_handled)
	          rtncd = 1;
	        else if (parm1)
	          LWORD(eip) += 2;
	      }
	    }
	  }
	  break;
  case DBG_INTxDPMI:
	  if (!mhpdbg.active) break;
          mhpdbgc.stopped = 1;
          dpmi_mhp_intxxtab[DBG_ARG(mhpdbgc.currcode) & 0xff] &= ~2;
	  break;
  case DBG_TRAP:
	  if (!mhpdbg.active)
	     break;
	  if (DBG_ARG(mhpdbgc.currcode) == 1) { /* single step */
                  switch (mhpdbgc.trapcmd) {
		  case 2: /* t command -- step until IP changes */
			  if (mhpdbgc.trapip == mhp_getcsip_value())
				  break;
			  /* no break */
		  case 1: /* ti command */
			  mhpdbgc.trapcmd = 0;
			  rtncd = 1;
			  mhpdbgc.stopped = 1;
			  break;
		  }

		  if (traceloop && mhp_bpchk(mhp_getcsip_value())) {
			  traceloop = 0;
			  loopbuf[0] = '\0';
		  }
	  }

	  if (DBG_ARG(mhpdbgc.currcode) == 3) { /* int3 (0xCC) */
		  int ok=0;
		  unsigned int csip=mhp_getcsip_value() - 1;
		  if (mhpdbgc.bpload_bp == csip ) {
		    /* mhp_cmd("r"); */
		    mhp_clearbp(mhpdbgc.bpload_bp);
		    mhp_modify_eip(-1);
		    if (mhpdbgc.bpload == 2) {
		      mhp_printf("bpload: INT3 caught\n");
		      SREG(cs)=BIOSSEG;
		      LWORD(eip)=(long)DBGload-(long)bios_f000;
		      mhpdbgc.trapcmd = 1;
		      mhpdbgc.bpload = 0;
		    }
		  }
		  else {
		    if ((ok=mhp_bpchk( csip))) {
			  mhp_modify_eip(-1);
		    }
		    else {
		      if ((ok=test_bit(3, mhpdbg.intxxtab))) {
		        /* software programmed INT3 */
		        mhp_modify_eip(-1);
		        mhp_cmd("r");
		        mhp_modify_eip(+1);
		      }
		    }
		  }
		  if (ok) {
		    mhpdbgc.trapcmd = 0;
		    rtncd = 1;
		    mhpdbgc.stopped = 1;
		  }
	  }
	  break;
  case DBG_PRE_VM86:
	  mhp_pre_vm86();
	  break;
  case DBG_POLL:
	  mhp_poll();
	  break;
  case DBG_GPF:
	  if (!mhpdbg.active)
	     break;
	  mhpdbgc.stopped = 1;
	  mhp_poll();
	  break;
  default:
	  break;
  }
  if (mhpdbg.active) mhp_bpset();
  return rtncd;
}

static void vmhp_printf(const char *fmt, va_list args)
{
  char frmtbuf[SRSIZE];

  vsprintf(frmtbuf, fmt, args);

  mhp_puts(frmtbuf);
}

void mhp_printf(const char *fmt,...)
{
  va_list args;

  va_start(args, fmt);
  vmhp_printf(fmt, args);
  va_end(args);
}

int mhpdbg_is_stopped(void)
{
  return mhpdbgc.stopped;
}
