/*
 * DOSEMU debugger,  1995 Max Parke <mhp@light.lightlink.com>
 *
 * (c) Copyright 1995-1996, Max H. Parke under the terms of the
 *     GNU Public License, incorporated herein by reference
 *
 * This is file mhpdbgc.c
 *
 * changes:
 *
 *   10Jul96 Hans Lermen <lermen@elserv.ffm.fgan.de>
 *           next round of DPMI support:
 *           - new modes for mode command: +d, -d
 *             ( defaults to having DPMI enabled )
 *           - now can single step through DPMI-client
 *           - now can set breakpoints in DPMI-client
 *           - now has DPMI-INTx type breakpoints with matching for AX
 *           - fixed disassembler and addresses to reflect
 *             segmented protected mode (linear mode wasn't useable for DPMI)
 *           - ldt commando now skips NULL-entries.
 *
 *   19May96 Max Parke <mhp@lightlink.com>
 *           - added a little support for DPMI:
 *               - new 'ldt' command
 *               - if '#' as first char of addresses, use LDT to lookup
 *           - changed default 'd' command length to 128 bytes
 *           - changed handling of "previous" d and u commands
 *           - fix a warning on sprintf
 *
 *   16Sep95 Hans Lermen <lermen@elserv.ffm.fgan.de>
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <regex.h>

#include "bitops.h"
#include "emu.h"
#include "cpu.h"
#include "timers.h"
#include "dpmi.h"
#include "int.h"
#include "utilities.h"
#include "dosemu_config.h"
#include "hma.h"
#include "dis8086.h"

#define MHP_PRIVATE
#include "mhpdbg.h"

#define makeaddr(x,y) ((((unsigned int)x) << 4) + (unsigned int)y)

/* prototypes */
static unsigned int mhp_getadr(char *, unsigned int *, unsigned int *, unsigned int *, unsigned int *);
static void mhp_regs  (int, char *[]);
static void mhp_r0    (int, char *[]);
static void mhp_dump    (int, char *[]);
static void mhp_disasm  (int, char *[]);
static void mhp_go      (int, char *[]);
static void mhp_stop    (int, char *[]);
static void mhp_trace   (int, char *[]);
static void mhp_tracec  (int, char *[]);
static void mhp_tracefileopen (int, char *[]);
static void mhp_tracefileclose(int, char *[]);
static void mhp_regs32  (int, char *[]);
static void mhp_bp      (int, char *[]);
static void mhp_bc      (int, char *[]);
static void mhp_bl      (int, char *[]);
static void mhp_bpint   (int, char *[]);
static void mhp_bcint   (int, char *[]);
static void mhp_bpintd  (int, char *[]);
static void mhp_bcintd  (int, char *[]);
static void mhp_bpload  (int, char *[]);
static void mhp_rmapfile(int, char *[]);
static void mhp_mode    (int, char *[]);
static void mhp_rusermap(int, char *[]);
static void mhp_kill    (int, char *[]);
static void mhp_help    (int, char *[]);
static void mhp_enter   (int, char *[]);
static void mhp_print_ldt       (int, char *[]);
static void mhp_debuglog (int, char *[]);
static void mhp_dump_to_file (int, char *[]);
static void mhp_bplog   (int, char *[]);
static void mhp_bclog   (int, char *[]);
static void print_log_breakpoints(void);

/* static data */
static unsigned int linmode = 0;
static unsigned int codeorg = 0;

static unsigned int dpmimode=1, saved_dpmimode=1;
#define IN_DPMI  (in_dpmi_pm() && dpmimode)

static char lastd[32];
static char lastu[32];
static char lastldt[32];

static struct symbol_entry symbol_table[MAXSYM];
static unsigned int last_symbol = 0;
static unsigned long addrmax;

static struct symbl2_entry symbl2_table[MAXSYM];
static unsigned int last_symbol2 = 0;
static unsigned int symbl2_org = 0;
/* static unsigned int symbl2_end = 0; */

static int trapped_bp=-1, trapped_bp_;

int traceloop=0;
char loopbuf[4] = "";

/* constants */
static const struct cmd_db cmdtab[] = {
   {"r0",            mhp_r0},
   {"r" ,            mhp_regs},
   {"e",             mhp_enter},
   {"ed",            mhp_enter},
   {"d",             mhp_dump},
   {"u",             mhp_disasm},
   {"g",             mhp_go},
   {"stop",          mhp_stop},
   {"mode",          mhp_mode},
   {"t",             mhp_trace},
   {"ti",            mhp_trace},
   {"tc",            mhp_tracec},
   {"tfo",           mhp_tracefileopen},
   {"tfc",           mhp_tracefileclose},
   {"r32",           mhp_regs32},
   {"bp",            mhp_bp},
   {"bc",            mhp_bc},
   {"bl",            mhp_bl},
   {"bpint",         mhp_bpint},
   {"bcint",         mhp_bcint},
   {"bpintd",        mhp_bpintd},
   {"bcintd",        mhp_bcintd},
   {"bpload",        mhp_bpload},
   {"bplog",         mhp_bplog},
   {"bclog",         mhp_bclog},
   {"rmapfile",      mhp_rmapfile},
   {"rusermap",      mhp_rusermap},
   {"kill",          mhp_kill},
   {"?",             mhp_help},
   {"ldt",           mhp_print_ldt},
   {"log",           mhp_debuglog},
   {"dump",          mhp_dump_to_file},
   {"",              NULL}
};

static const char help_page[]=
  "q                      Quit the debug session\n"
  "kill                   Kill the dosemu process\n"
  "r                      list regs\n"
  "e/ed ADDR val [val ..] modify memory (0-1Mb), previous addr for ADDR='-'\n"
  /* val can be: a hex val (in case of 'e') or decimal (in case of 'ed')
   * With 'ed' also a hexvalue in form of 0xFF is allowed and can be mixed,
   * val can also be a character constant (e.g. 'a') or a string ("abcdef"),
   * val can also be any register symbolic and has the size of that register.
   * Except for strings and registers, val can be suffixed by
   * W(word size) or L (long size), default size is byte.
   */
  "d ADDR SIZE            dump memory (no limit)\n"
  "u ADDR SIZE            unassemble memory (no limit)\n"
  "g                      go (if stopped)\n"
  "stop                   stop (if running)\n"
  "mode 0|1|2|+d|-d       set mode (0=SEG16, 1=LIN32, 2=UNIX32)\n"
  "                       for u and d commands\n"
  "t                      single step\n"
  "ti                     single step into interrupt\n"
  "tc                     single step, loop forever until key pressed\n"
  "tfo FILE               capture traces to a file\n"
  "tfc                    close the trace file\n"
  "r32                    dump regs in 32 bit format\n"
  "bp addr                set int3 style breakpoint\n"
  "bc n                   clear breakpoint #n (as listed by bl)\n"
  "bpint/bcint xx         set/clear breakpoint on INT xx\n"
  "bpintd/bcintd xx [ax]  set/clear breakpoint on DPMI INT xx [ax]\n"
  "bpload                 stop at start of next loaded DOS program\n"
  "bl                     list active breakpoints\n"
  "bplog/bclog regex      set/clear breakpoint on logoutput using regex\n"
  "rusermap org fn        read microsoft linker format .MAP file 'fn'\n"
  "                       code origin = 'org'.\n"
  "rmapfile [file]        (re)read a dosemu.map ('nm' format) file\n"
  "ldt sel lines          dump ldt starting at selector 'sel' for 'lines'\n"
  "log [flags]            get/set debug-log flags (e.g 'log +M-k')\n"
  "dump ADDR SIZE FILE    dump a piece of memory to file\n"
  "<ENTER>                repeats previous command\n";

/********/
/* CODE */
/********/

#define AXLIST_SIZE  32
static unsigned long mhp_axlist[AXLIST_SIZE];
static int axlist_count=0;


/* simple ASCII only toupper, this to avoid problems with the dotless i
   and here we only need to match the register si with SI etc. */
static unsigned char toupper_ascii(unsigned char c)
{
  if (c >= 'a' && c <= 'z')
    return c - ('a' - 'A');
  return c;
}

int mhp_getaxlist_value(int v, int mask)
{
  int i;
  for (i=0; i < axlist_count; i++) {
    if (!((v ^ mhp_axlist[i]) & mask)) return i;
  }
  return -1;
}

static void mhp_delaxlist_value(int v, int mask)
{
  int i,j;

  for (i=0,j=0; i < axlist_count; i++) {
    if (((v ^ mhp_axlist[i]) & mask)) {
      mhp_axlist[j] = mhp_axlist[i];
      j++;
    }
  }
  axlist_count = j;
}

static int mhp_addaxlist_value(int v)
{
  if (mhp_getaxlist_value(v, -1) >= 0) return 1;
  if (axlist_count < (AXLIST_SIZE-1)) {
    mhp_axlist[axlist_count++]=v;
    return 1;
  }
  return 0;
}

static char * getname(unsigned int addr)
{
   int i;
   if ((addr < 0x100000) || (addr > addrmax))
      return(NULL);
   for (i=0; i < last_symbol; i++) {
      if (symbol_table[i].addr == addr)
         return(symbol_table[i].name);
   }
   return(NULL);
}

static char * getname2(unsigned int seg, unsigned int off)
{
   int i;
   for (i=0; i < last_symbol2; i++) {
      if ((symbl2_table[i].seg == seg) &&
          (symbl2_table[i].off == off))
         return(symbl2_table[i].name);
   }
   return(NULL);
}

static char * getname2u(unsigned int addr)
{
   int i;
   for (i=0; i < last_symbol2; i++) {
      if (addr == makeaddr(symbl2_table[i].seg, symbl2_table[i].off))
         return(symbl2_table[i].name);
   }
   return(NULL);
}

static unsigned int getaddr(const char *n1, unsigned int *v1)
{
   int i;
   if (strlen(n1) == 0)
      return 0;
   for (i=0; i < last_symbol; i++) {
      if (strcmp(symbol_table[i].name, n1) == 0) {
         *v1 = symbol_table[i].addr;
         return 1;
      }
   }
   return 0;
}

static unsigned int lookup(char *n1, unsigned int *v1, unsigned int *s1, unsigned int *o1)
{
   int i;
   if (!strlen(n1))
      return 0;
   for (i=0; i < last_symbol2; i++) {
      if (!strcmp(symbl2_table[i].name, n1)) {
         *s1=symbl2_table[i].seg;
         *o1=symbl2_table[i].off;
         *v1 = makeaddr(*s1, *o1);
         return 1;
      }
   }
   return 0;
}

static void mhp_rusermap(int argc, char *argv[])
{
  FILE * ifp;
  char bytebuf[IBUFS];
  unsigned long org;
  unsigned int  seg;
  unsigned int  off;

  char * srchfor = "  Address         Publics by Value";

  if (argc < 3) {
     mhp_printf("syntax: rusermap <org> <file>\n");
     return;
  }

  sscanf(argv[1], "%lx", &org);
  symbl2_org = org;

  ifp = fopen(argv[2], "r");
  if (!ifp) {
     mhp_printf("unable to open map file %s\n", argv[2]);
     return;
  }
  mhp_printf("reading map file %s\n", argv[2]);
  last_symbol2 = 0;
  for(;;) {
     if(!fgets(bytebuf, sizeof (bytebuf), ifp)) {
        mhp_printf("error: could not find following in %s:\n%s\n",
                   argv[2], srchfor);
        return;
     }
     if (!strlen(bytebuf))
        continue;
     if (!memcmp(bytebuf, srchfor, strlen(srchfor)))
        break;
  }
  for(;;) {
     if(!fgets(bytebuf, sizeof (bytebuf), ifp))
        break;
     if(bytebuf[5] != ':')
        continue;
     if(bytebuf[12] != ' ')
        continue;
     bytebuf[5] = ' ';
     sscanf(&bytebuf[1], "%x %x", &seg, &off);
     symbl2_table[last_symbol2].seg  = seg + (symbl2_org >> 4);
     symbl2_table[last_symbol2].off  = off;
     symbl2_table[last_symbol2].type = ' ';
     sscanf(&bytebuf[17], "%s", (char *)&symbl2_table[last_symbol2].name);
     last_symbol2++;
  }
  fclose(ifp);
  if (!last_symbol2) {
    mhp_printf("failed to read symbols from map file\n");
    return;
  }
/*symbl2_end = symbl2_table[last_symbol2-1].addr;*/
  mhp_printf("%d symbol(s) processed\n", last_symbol2);
  mhp_printf("highest address %04x:%04x(%s)\n",
             symbl2_table[last_symbol2-1].seg,
             symbl2_table[last_symbol2-1].off,
             symbl2_table[last_symbol2-1].name);

}

static void mhp_rmapfile(int argc, char *argv[])
{
  FILE * ifp = NULL;
  char bytebuf[IBUFS];
  unsigned long a1;
  char *map_fname = DOSEMU_MAP_PATH;

  if (argc >= 2) {
    map_fname = argv[1];
  }
  if (map_fname == NULL && dosemu_proc_self_exe != NULL) {
    /* try to get symbols on the fly */
    map_fname = malloc(strlen(dosemu_proc_self_exe) + 60);
    strcpy(map_fname, "nm ");
    strcat(map_fname, dosemu_proc_self_exe);
    strcat(map_fname, " | grep -v '\\(compiled\\)\\|\\(\\.o$\\)\\|\\( a \\)' | sort");
    ifp = popen(map_fname, "r");
  } else if (map_fname != NULL) {
    ifp = fopen(map_fname, "r");
  }
  if (!ifp) {
     mhp_printf("unable to open map file %s\n", map_fname);
     return;
  }
  mhp_printf("Reading map file %s\n", map_fname);
  last_symbol = 0;
  while (last_symbol < MAXSYM) {
     if(!fgets(bytebuf, sizeof (bytebuf), ifp))
        break;
     if (!strlen(bytebuf) || !isxdigit((unsigned char)*bytebuf))
        continue;
      /* recent versions of nm put out the address in long long
       * format, with 16 digits: we can't rely on absolute offsets.
       */
      sscanf(bytebuf, "%lx %c %40s", &a1, &symbol_table[last_symbol].type,
              (char *)&symbol_table[last_symbol].name);
#ifdef __ELF__
     if (a1 < 0x00000001) continue;
#else
     if (a1 < 0x20000000)
        continue;
     if (a1 > 0x28000000)
        break;
#endif
     symbol_table[last_symbol].addr = a1;
     last_symbol++;
  }
  if (map_fname != argv[1] && map_fname != DOSEMU_MAP_PATH) {
    pclose(ifp);
    free(map_fname);
  }
  else
    fclose(ifp);
  if (!last_symbol) {
    mhp_printf("failed to read symbols from map file\n");
    return;
  }
  addrmax = symbol_table[last_symbol-1].addr;
  mhp_printf("%d symbol(s) processed\n", last_symbol);
  mhp_printf("highest address %08lx(%s)\n", addrmax, getname(addrmax));
}

enum {
   _SSr, _CSr, _DSr, _ESr, _FSr, _GSr,
   _AXr, _BXr, _CXr, _DXr, _SIr, _DIr, _BPr, _SPr, _IPr, _FLr,
  _EAXr,_EBXr,_ECXr,_EDXr,_ESIr,_EDIr,_EBPr,_ESPr,_EIPr
};

static int last_decode_symreg;

static int decode_symreg(char *regn)
{
  static char reg_syms[]="SS  CS  DS  ES  FS  GS  "
			 "AX  BX  CX  DX  SI  DI  BP  SP  IP  FL  "
 			 "EAX EBX ECX EDX ESI EDI EBP ESP EIP ";
  char rn[5], *s;
  int n;

  last_decode_symreg = -1;
  if (!isalpha(*regn))
	return -1;
  s=rn; n=0; rn[4]=0;
  while (n<4)
  {
	*s++=(isalpha(*regn)? toupper_ascii(*regn++): ' '); n++;
  }
  if (!(s = strstr(reg_syms, rn)))
	return -1;
  last_decode_symreg = ((s-reg_syms) >> 2);
  return last_decode_symreg;
}

static unsigned long mhp_getreg(char * regn)
{
  if (IN_DPMI) return dpmi_mhp_getreg(decode_symreg(regn));
  else switch (decode_symreg(regn)) {
    case _SSr: return SREG(ss);
    case _CSr: return SREG(cs);
    case _DSr: return SREG(ds);
    case _ESr: return SREG(es);
    case _FSr: return SREG(fs);
    case _GSr: return SREG(gs);
    case _AXr: return LWORD(eax);
    case _BXr: return LWORD(ebx);
    case _CXr: return LWORD(ecx);
    case _DXr: return LWORD(edx);
    case _SIr: return LWORD(esi);
    case _DIr: return LWORD(edi);
    case _BPr: return LWORD(ebp);
    case _SPr: return LWORD(esp);
    case _IPr: return LWORD(eip);
    case _FLr: return get_FLAGS(REG(eflags));
    case _EAXr: return REG(eax);
    case _EBXr: return REG(ebx);
    case _ECXr: return REG(ecx);
    case _EDXr: return REG(edx);
    case _ESIr: return REG(esi);
    case _EDIr: return REG(edi);
    case _EBPr: return REG(ebp);
    case _ESPr: return REG(esp);
    case _EIPr: return REG(eip);
  }
  return -1;
}


static void mhp_setreg(char * regn, unsigned long val)
{
  if (IN_DPMI) {
    dpmi_mhp_setreg(decode_symreg(regn),val);
    return;
  }
  else switch (decode_symreg(regn)) {
    case _SSr: SREG(ss) = val; break;
    case _CSr: SREG(cs) = val; break;
    case _DSr: SREG(ds) = val; break;
    case _ESr: SREG(es) = val; break;
    case _FSr: SREG(fs) = val; break;
    case _GSr: SREG(gs) = val; break;
    case _AXr: LWORD(eax) = val; break;
    case _BXr: LWORD(ebx) = val; break;
    case _CXr: LWORD(ecx) = val; break;
    case _DXr: LWORD(edx) = val; break;
    case _SIr: LWORD(esi) = val; break;
    case _DIr: LWORD(edi) = val; break;
    case _BPr: LWORD(ebp) = val; break;
    case _SPr: LWORD(esp) = val; break;
    case _IPr: LWORD(eip) = val; break;
    case _FLr: set_FLAGS(val); break;
    case _EAXr: REG(eax) = val; break;
    case _EBXr: REG(ebx) = val; break;
    case _ECXr: REG(ecx) = val; break;
    case _EDXr: REG(edx) = val; break;
    case _ESIr: REG(esi) = val; break;
    case _EDIr: REG(edi) = val; break;
    case _EBPr: REG(ebp) = val; break;
    case _ESPr: REG(esp) = val; break;
    case _EIPr: REG(eip) = val; break;
  }
}


static void mhp_go(int argc, char * argv[])
{
   unfreeze_dosemu();
   if (!mhpdbgc.stopped) {
      mhp_printf("already in running state\n");
   } else {
      dpmi_mhp_setTF(0);
      clear_TF();
      if (mhpdbgc.saved_if)
         set_IF();
      mhpdbgc.stopped = 0;
   }
}

static void mhp_r0(int argc, char * argv[])
{
   if (trapped_bp == -2) trapped_bp=trapped_bp_;
   else trapped_bp=-1;
   mhp_regs(argc,argv);
}

static void mhp_stop(int argc, char * argv[])
{
   if (mhpdbgc.stopped) {
      mhp_printf("already in stopped state\n");
   } else {
      mhpdbgc.saved_if = isset_IF();
      clear_IF();
      mhpdbgc.stopped = 1;
      mhp_cmd("r0");
   }
}

static void mhp_trace(int argc, char * argv[])
{
   if (!mhpdbgc.stopped) {
      mhp_printf("must be in stopped state\n");
   } else {
      mhpdbgc.stopped = 0;
      if (dpmi_active())
        dpmi_mhp_setTF(1);
      set_TF();

      if (!strcmp(argv[0], "ti")) {
	mhpdbgc.trapcmd = 1;
      } else {
	mhpdbgc.trapcmd = 2;
      }

      mhpdbgc.trapip = mhp_getcsip_value();

      if (!in_dpmi_pm()) {
	unsigned char *csp = SEG_ADR((unsigned char *), cs, ip);
	switch (csp[0]) {
	case 0xcd:
	    if (mhpdbgc.trapcmd != 1)
		break;
	    LWORD(eip) += 2;
	    do_int(csp[1]);
	    set_TF();
	    mhpdbgc.stopped = 1;
	    mhpdbgc.int_handled = 1;
	    mhp_cmd("r0");
	    break;
	case 0xcf:
	    LWORD(eip) += 1;
	    fake_iret();
	    set_TF();
	    mhpdbgc.stopped = 1;
	    mhp_cmd("r0");
	    break;
	}
      }
   }
}

static void mhp_tracec(int argc, char *argv[])
{
  if (!mhpdbgc.stopped) {
    mhp_printf("must be in stopped state\n");
    return;
  }

  if (mhpdbg.tracefd == -1) {
    mhp_printf("must have tracefile defined\n");
    return;
  }

  mhp_printf("press any key to stop tracing\n");
  mhp_send();

  mhp_trace(argc, argv);
  traceloop = 1;
  strcpy(loopbuf, "t");
}

static void mhp_tracefileopen(int argc, char *argv[])
{
  if (mhpdbg.tracefd != -1) {
    mhp_printf("tracefile already open\n");
    return;
  }

  if (mhpdbg.recvfd == -1) {
    mhp_printf("tracefile descriptor invalid\n");
    return;
  }

  /* grab the file descriptor */
  mhpdbg.tracefd = mhpdbg.recvfd;
  mhpdbg.recvfd = -1;

  if (argc > 1)
    mhp_printf("tracefile name is '%s'\n", argv[1]);
  else
    mhp_printf("tracefile opened\n");
}

static void mhp_tracefileclose(int argc, char *argv[])
{
  mhpdbg.tracefd = -1;
  mhp_printf("tracefile has been closed\n");
}

static void mhp_dump(int argc, char * argv[])
{
   unsigned int nbytes;
   unsigned int seekval;
   int i,i2;
   unsigned int buf = 0;
   unsigned int seg;
   unsigned int off;
   unsigned int limit;
   int data32=0;
   int unixaddr;
   unsigned char c;

   if (argc > 1) {
      if (!mhp_getadr(argv[1], &seekval, &seg, &off, &limit)) {
         mhp_printf("Invalid ADDR\n");
         return;
      }
      strcpy(lastd, argv[1]);
   } else {
      if (!strlen(lastd)) {
         mhp_printf("No previous \'d\' command\n");
         return;
      }
      if (!mhp_getadr(lastd, &seekval, &seg, &off, &limit)) {
         mhp_printf("Invalid ADDR\n");
         return;
      }
   }
   buf = seekval;

   if (argc > 2)
      sscanf(argv[2], "%x", &nbytes);
   else
      nbytes = 128;

   if ((nbytes == 0) || (nbytes > 256))
      nbytes = 128;

#if 0
   mhp_printf( "seekval %08lX nbytes:%d\n", seekval, nbytes);
#else
   mhp_printf( "\n");
#endif
   if (IN_DPMI && seg) data32=dpmi_mhp_get_selector_size(seg);
   unixaddr = linmode == 2 && seg == 0 && limit == 0xFFFFFFFF;
   for (i=0; i<nbytes; i++) {
      if ((i&0x0f) == 0x00) {
         if (seg != 0 || limit != 0xFFFFFFFF) {
            if (data32) mhp_printf("%s%04x:%08x ", IN_DPMI?"#":"" ,seg, off+i);
            else mhp_printf("%s%04x:%04x ", IN_DPMI?"#":"" ,seg, off+i);
         }
	 else if (unixaddr)
            mhp_printf( "%#08x ", seekval+i);
	 else
            mhp_printf( "%08X ", seekval+i);
      }
      if (unixaddr)
	c = UNIX_READ_BYTE((uintptr_t)buf+i);
      else
	c = READ_BYTE(buf+i);
      mhp_printf( "%02X ", c);
      if ((i&0x0f) == 0x0f) {
         mhp_printf( " ");
         for (i2=i-15;i2<=i;i2++){
	    if (unixaddr)
	       c = UNIX_READ_BYTE((uintptr_t)buf+i2);
	    else
	       c = READ_BYTE(buf+i2);
	    c &= 0x7F;
	    if (c >= 0x20) {
	       mhp_printf( "%c", c);
            } else {
               mhp_printf( "%c", '.');
            }
         }
         mhp_printf( "\n");
      }
   }

   if (seg != 0 || limit != 0xFFFFFFFF) {
      if ((lastd[0] == '#') || (IN_DPMI)) {
         sprintf(lastd, "#%x:%x", seg, off+i);
      } else {
         sprintf(lastd, "%x:%x", seg, off+i);
      }
   } else if (unix) {
      sprintf(lastd, "%#x", seekval + i);
   } else {
      sprintf(lastd, "%x", seekval + i);
   }
}

static void mhp_dump_to_file(int argc, char * argv[])
{
   unsigned int nbytes;
   unsigned int seekval;
   const unsigned char *buf = 0;
   unsigned int seg;
   unsigned int off;
   unsigned int limit=0;
   int fd;

   if (argc <= 3) {
      mhp_printf("USAGE: dump <addr> <size> <filesname>\n");
      return;
   }

   if (!mhp_getadr(argv[1], &seekval, &seg, &off, &limit)){
      mhp_printf("Invalid ADDR\n");
      return;
   }

   if (linmode == 2 && seg == 0 && limit == 0xFFFFFFFF)
     buf = (const unsigned char *)(uintptr_t)seekval;
   else
     buf = LINEAR2UNIX(seekval);
   sscanf(argv[2], "%x", &nbytes);
   if (nbytes == 0) {
      mhp_printf("invalid size\n");
      return;
   }

   fd = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC, 00775);

   if (fd < 0) {
      mhp_printf("cannot open/create file %s\n%s\n", argv[3], strerror(errno));
      return;
   }
   if (write(fd, buf, nbytes) != nbytes) {
      mhp_printf("write error: %s\n", strerror(errno));
   }
   close(fd);
}

static void mhp_mode(int argc, char * argv[])
{
   if (argc >=2) {
     if (argv[1][0] == '0') linmode = 0;
     if (argv[1][0] == '1') linmode = 1;
     if (argv[1][0] == '2') linmode = 2;
     if (!strcmp(argv[1],"+d")) dpmimode=saved_dpmimode=1;
     if (!strcmp(argv[1],"-d")) dpmimode=saved_dpmimode=0;
   }
   mhp_printf ("current mode: %s, dpmi %s%s\n",
     linmode==2?"unix32":linmode?"lin32":"seg16", dpmimode?"enabled":"disabled",
     dpmimode!=saved_dpmimode ? (saved_dpmimode?"[default enabled]":"[default disabled]"):"");
   return;
}

static void mhp_disasm(int argc, char * argv[])
{
   int rc;
   unsigned int nbytes;
   unsigned int org;
   unsigned int seekval;
   int def_size;
   unsigned int bytesdone;
   int i;
   unsigned int buf = 0;
   char bytebuf[IBUFS];
   char frmtbuf[IBUFS];
   unsigned int seg;
   unsigned int off;
   unsigned int refseg;
   unsigned int ref;
   unsigned int limit;
   int segmented = (linmode == 0);

   if (argc > 1) {
      if (!mhp_getadr(argv[1], &seekval, &seg, &off, &limit)) {
         mhp_printf("Invalid ADDR\n");
         return;
      }
      strcpy(lastu, argv[1]);
   } else {
      if (!strlen(lastu)) {
         mhp_printf("No previous \'u\' command\n");
         return;
      }
      if (!mhp_getadr(lastu, &seekval, &seg, &off, &limit)) {
         mhp_printf("Invalid ADDR\n");
         return;
      }
   }

   if (argc > 2) {
      if ((argv[2][0] == 'l') || (argv[2][0] == 'L'))
         sscanf(&argv[2][1], "%x", &nbytes);
      else
         sscanf(argv[2], "%x", &nbytes);
   } else {
      nbytes = 32;
   }

   if ((nbytes == 0) || (nbytes > 256))
      nbytes = 32;

#if 0
   mhp_printf( "seekval %08X nbytes:%d\n", seekval, nbytes);
#else
   mhp_printf( "\n");
#endif

   if (IN_DPMI) {
     def_size = (dpmi_mhp_get_selector_size(seg)? 3:0);
     segmented =1;
   }
   else {
     if (seekval < (a20 ? 0x10fff0 : 0x100000)) def_size = (linmode? 3:0);
     else if (lastu[0] == '#')
        def_size = 0;
     else def_size = 3;
   }
   if (linmode == 2) {
     if (seg != 0 || limit != 0xFFFFFFFF)
       seekval += (uintptr_t)mem_base;
     def_size |= 4;
   }
   rc=0;
   buf = seekval;
   org = codeorg ? codeorg : seekval;

   for (bytesdone = 0; bytesdone < nbytes; bytesdone += rc) {
       if (def_size&4) {
          if (getname(org+bytesdone))
             mhp_printf ("%s:\n", getname(org+bytesdone));
       } else if (segmented) {
          if (getname2(seg,off+bytesdone))
             mhp_printf ("%s:\n", getname2(seg,off));
       }
       refseg = seg;
       rc = dis_8086(buf+bytesdone, frmtbuf, def_size, &ref,
                  (IN_DPMI ? dpmi_mhp_getselbase(refseg) : refseg * 16));
       for (i=0;i<rc;i++) {
	   if(def_size&4)
	     sprintf(&bytebuf[i*2], "%02X", UNIX_READ_BYTE((uintptr_t)buf+bytesdone+i) );
	   else
	     sprintf(&bytebuf[i*2], "%02X", READ_BYTE(buf+bytesdone+i) );
           bytebuf[(i*2)+2] = 0x00;
       }
       if (segmented) {
          char *x=(IN_DPMI ? "#" : "");
          if (def_size) {
            mhp_printf( "%s%04x:%08x %-16s %s", x, seg, off+bytesdone, bytebuf, frmtbuf);
          }
          else mhp_printf( "%s%04x:%04x %-16s %s", x, seg, off+bytesdone, bytebuf, frmtbuf);
          if ((ref) && (getname2u(ref)))
             mhp_printf ("(%s)", getname2u(ref));
       } else {
	  if (def_size&4)
	     mhp_printf( "%#08x: %-16s %s", org+bytesdone, bytebuf, frmtbuf);
	  else
	     mhp_printf( "%08x: %-16s %s", org+bytesdone, bytebuf, frmtbuf);
          if ((ref) && (getname(ref)))
             mhp_printf ("(%s)", getname(ref));
       }
       mhp_printf( "\n");
   }

   if (segmented) {
      if ((lastu[0] == '#') || (IN_DPMI)) {
         sprintf(lastu, "#%x:%x", seg, off+bytesdone);
      } else {
         sprintf(lastu, "%x:%x", seg, off+bytesdone);
      }
   } else {
      sprintf(lastu, "%x", seekval + bytesdone);
   }
}

enum {
  V_NONE=0, V_BYTE=1, V_WORD=2, V_DWORD=4, V_STRING=8
};

static int get_value(unsigned long *v, char *s, int base)
{
   int len = strlen(s);
   int t;
   char *tt;
   char *wl = " WL";

   if (!len) return V_NONE;
   t = (unsigned char)s[len-1];
   if (len >2) {
     /* check for string value */
     if (t == '"' && s[0] == '"') {
       s[len-1] = 0;
       return V_STRING;
     }
   }
   if ((tt = strchr(wl, toupper_ascii(t))) !=0) {
     len--;
     s[len] = 0;
     t = (int)(tt - wl) << 1;
   }
   else t = V_NONE;
   if (len >2) {
     if (s[len-1] == '\'' && s[0] == '\'') {
       *v = 0;
       len -=2;
       if (len > sizeof(*v)) len = sizeof(*v);
       strncpy((char *)v, s+1, len);
       if (t != V_NONE) return t;
       if (len <  2) return V_BYTE;
       if (len <  4) return V_WORD;
       return V_DWORD;
     }
   }
   *v = mhp_getreg(s);
   if (last_decode_symreg >=0) {
     if (last_decode_symreg < _EAXr) return V_WORD;
     return V_DWORD;
   }
   *v = strtoul(s,0,base);
   if (t == V_NONE) return V_BYTE;
   return t;
}

static void mhp_enter(int argc, char * argv[])
{
   int size;
   static unsigned int zapaddr = -1;
   unsigned int seg, off;
   unsigned long val;
   unsigned int limit;
   char *arg;
   int base = 16;

   if (argc < 3)
      return;

   if (!strcmp(argv[1],"-")) {
     if (zapaddr == -1) {
        mhp_printf("Address invalid, no previous 'e' command with address\n");
        return;
     }
   } else {
     if (!mhp_getadr(argv[1], &zapaddr, &seg, &off, &limit)) {
        mhp_printf("Address invalid\n");
        return;
     }
   }

   if ((a20 ?0x10fff0 : 0x100000) < zapaddr) {
      mhp_printf("Address invalid\n");
      return;
   }
   if (!strcmp(argv[0], "ed")) base = 0;
   argv += 2;
   while ((arg = *argv) != 0) {
      size = get_value(&val, arg, base);
      switch (size) {
        case V_BYTE:
        case V_WORD:
        case V_DWORD: {
          MEMCPY_2DOS(zapaddr, &val, size);
          zapaddr += size;
          break;
        }
        case V_STRING: {
          size = strlen(arg+1);
          MEMCPY_2DOS(zapaddr, arg+1, size);
          zapaddr += size;
          break;
        }
      }
      argv++;
   }
}

static unsigned int mhp_getadr(char *a1, unsigned int *v1, unsigned int *s1, unsigned int *o1, unsigned int *lim)
{
   static char buffer[0x10000];
   char * srchp;
   unsigned int seg1;
   unsigned int off1;
   unsigned long ul1;
   int selector = 0;
   int use_ldt = IN_DPMI;
   unsigned int * lp;
   unsigned int base_addr, limit;

   *lim = 0xFFFFFFFF;

   if (use_ldt) selector = 1;
   if (*a1 == '#') {
      selector = 1;
      *lim = 0;
      a1 ++;
   }
   if(*a1 == '*') {
      if (use_ldt) {
        dpmi_mhp_getcseip(&seg1,&off1);
        *lim = 0;
        selector=2;
      }
      else {
        *v1 = makeaddr(SREG(cs), LWORD(eip));
        *s1 = SREG(cs);
        *o1 = LWORD(eip);
        *lim = 0xFFFF;
        return 1;
      }
   }
   if (selector != 2) {
     if(*a1 == '$') {
        if (use_ldt) {
          dpmi_mhp_getssesp(&seg1,&off1);
          *lim = 0;
          selector=2;
        }
        else {
          *v1 = makeaddr(SREG(ss), LWORD(esp));
          *s1 = SREG(ss);
          *o1 = LWORD(esp);
          *lim = 0xFFFF;
          return 1;
        }
     }
     if (selector != 2) {
       if (lookup(a1, v1, s1, o1)) {
          return 1;
       }
       if (getaddr(a1, v1)) {
          *s1 = (*v1 >> 4);
          *o1 = (*v1 & 0b00001111);
          return 1;
       }
       if (!(srchp = strchr(a1, ':'))) {
          char *endptr;

          ul1 = strtoul(a1, &endptr, 16);
          if ((endptr == a1) || (*endptr != '\0')) // no chars or trailing rubbish
             return 0;
          *v1 = ul1;
          *s1 = (ul1 >> 4);
          *o1 = (ul1 & 0b00001111);
          return 1;
       }
       if ( (seg1 = mhp_getreg(a1)) == -1) {
               *srchp = ' ';
               sscanf(a1, "%x", &seg1);
               *srchp = ':';
       }
       if ( (off1 = mhp_getreg(srchp+1)) == -1) {
               sscanf(srchp+1, "%x", &off1);
       }
     }
   }
   *s1 = seg1;
   *o1 = off1;

   if (!selector) {
      *v1 = makeaddr(seg1, off1);
      *lim = 0xFFFF;
      return 1;
   }

   if (!(seg1 & 0x4)) {
     mhp_printf("GDT selectors not supported yet\n");
     return 0;
   }

   if (get_ldt(buffer) < 0) {
     mhp_printf("error getting ldt\n");
     return 0;
   }

   lp = (unsigned int *) buffer;
   lp += (seg1 & 0xFFF8) >> 2;

   base_addr = (*lp >> 16) & 0x0000FFFF;
   limit = *lp & 0x0000FFFF;
   lp++;
   /* Second 32 bits of descriptor */
   base_addr |= (*lp & 0xFF000000) | ((*lp << 16) & 0x00FF0000);
   limit |= (*lp & 0x000F0000);
   if (*lp & 0x00800000) limit <<= 12;

   if ((limit == 0) && (base_addr == 0)) {
     mhp_printf("selector %x appears to be invalid\n", seg1);
     return 0;
   }

   if (off1 >= limit) {
     mhp_printf("offset %x exceeds segment limit %x\n", off1, limit);
     return 0;
   }

   *v1 = base_addr + off1;
   *lim = limit - off1;
   return 1;
}

int mhp_setbp(unsigned int seekval)
{
   int i1;
   for (i1=0; i1 < MAXBP; i1++) {
      if (   mhpdbgc.brktab[i1].brkaddr == seekval
          && mhpdbgc.brktab[i1].is_valid) {
         mhp_printf( "Duplicate breakpoint, nothing done\n");
         return 0;
      }
   }
   for (i1=0; i1 < MAXBP; i1++) {
      if (!mhpdbgc.brktab[i1].is_valid) {
         if (i1==trapped_bp) trapped_bp=-1;
         mhpdbgc.brktab[i1].brkaddr = seekval;
	 mhpdbgc.brktab[i1].is_valid = 1;
         mhpdbgc.brktab[i1].is_dpmi = IN_DPMI;
         return 1;
      }
   }
   mhp_printf( "Breakpoint table full, nothing done\n");
   return 0;
}

int mhp_clearbp(unsigned int seekval)
{
   int i1;
   for (i1=0; i1 < MAXBP; i1++) {
      if (   mhpdbgc.brktab[i1].brkaddr == seekval
          && mhpdbgc.brktab[i1].is_valid) {
         if (i1==trapped_bp) trapped_bp=-1;
         mhpdbgc.brktab[i1].brkaddr = 0;
         mhpdbgc.brktab[i1].is_valid = 0;
         return 1;
      }
   }
   return 0;
}

static int check_for_stopped(void)
{
   if (!mhpdbgc.stopped) {
     mhp_printf("need to be in 'stopped' state for this command\n");
     mhp_send();
   }
   return mhpdbgc.stopped;
}

static void mhp_bp(int argc, char * argv[])
{
   unsigned int seekval;
   unsigned int seg;
   unsigned int off;
   unsigned int limit;

   if (!check_for_stopped())
      return;

   if (argc < 2) {
      mhp_printf("location argument required\n");
      return;
   }

   if (!mhp_getadr(argv[1], &seekval, &seg, &off, &limit)) {
      mhp_printf("Invalid ADDR\n");
      return;
   }

   mhp_setbp(seekval);
}

static void mhp_bl(int argc, char * argv[])
{
   int i1;

   mhp_printf( "Breakpoints:\n");
   for (i1=0; i1 < MAXBP; i1++) {
      if (mhpdbgc.brktab[i1].is_valid) {
         mhp_printf( "%d: %08lx\n", i1, mhpdbgc.brktab[i1].brkaddr);
      }
   }
   mhp_printf( "Interrupts: ");
   for (i1=0; i1 < 256; i1++) {
      if (test_bit(i1, mhpdbg.intxxtab)) {
         mhp_printf( "%02x ", i1);
      }
   }
   mhp_printf( "\nDPMI Interrupts:");
   for (i1=0; i1 < 256; i1++) {
     if (dpmi_mhp_intxxtab[i1]) {
       mhp_printf( " %02x", i1);
       if (dpmi_mhp_intxxtab[i1] & 0x80) {
         int i,j=0;
         mhp_printf("[");
         for (i=0; i < axlist_count; i++) {
           if ((mhp_axlist[i] >>16) == i1) {
             if (j)  mhp_printf(",");
             mhp_printf("%x",mhp_axlist[i] & 0xffff);
             j++;
           }
         }
         mhp_printf("]");
       }
     }
   }
   mhp_printf( "\n");
   if (mhpdbgc.bpload) mhp_printf("bpload active\n");
   print_log_breakpoints();
   return;
}

static void mhp_bc(int argc, char * argv[])
{
   int i1;

   if (argc <2) return;
   if (!check_for_stopped()) return;
   if (!sscanf(argv[1], "%d", &i1)) {
     mhp_printf( "Invalid breakpoint number\n");
     return;
   }
   if (!mhpdbgc.brktab[i1].is_valid) {
         mhp_printf( "No breakpoint %d, nothing done\n", i1);
         return;
   }
   mhpdbgc.brktab[i1].brkaddr = 0;
   mhpdbgc.brktab[i1].is_valid = 0;
   return;
}

static void mhp_bpint(int argc, char * argv[])
{
   int i1;

   if (argc <2) return;
   if (!check_for_stopped()) return;
   sscanf(argv[1], "%x", &i1);
   if (test_bit(i1, mhpdbg.intxxtab)) {
         mhp_printf( "Duplicate BPINT %02x, nothing done\n", i1);
         return;
   }
   set_bit(i1, mhpdbg.intxxtab);
   if (!test_bit(i1, &vm86s.int_revectored)) {
      set_bit(i1, mhpdbgc.intxxalt);
      set_revectored(i1, &vm86s.int_revectored);
   }
   if (i1 == 0x21) mhpdbgc.int21_count++;
   return;
}

static void mhp_bcint(int argc, char * argv[])
{
   int i1;

   if (argc <2) return;
   if (!check_for_stopped()) return;
   sscanf(argv[1], "%x", &i1);
   if (!test_bit(i1, mhpdbg.intxxtab)) {
         mhp_printf( "No BPINT %02x, nothing done\n", i1);
         return;
   }
   clear_bit(i1, mhpdbg.intxxtab);
   if (test_bit(i1, mhpdbgc.intxxalt)) {
      clear_bit(i1, mhpdbgc.intxxalt);
      reset_revectored(i1, &vm86s.int_revectored);
   }
   if (i1 == 0x21) mhpdbgc.int21_count--;
   return;
}

static void mhp_bpintd(int argc, char * argv[])
{
   int i1,v1=0;

   if (argc <2) return;
   if (!check_for_stopped()) return;
   sscanf(argv[1], "%x", &i1);
   i1 &= 0xff;
   if (argc >2) {
     sscanf(argv[2], "%x", &v1);
     v1 = (v1 &0xffff) | (i1<<16);
   }
   if ((!v1 && dpmi_mhp_intxxtab[i1]) || (mhp_getaxlist_value(v1,-1) >=0)) {
     if (v1)  mhp_printf( "Duplicate BPINTD %02x %04x, nothing done\n", i1, v1 & 0xffff);
     else mhp_printf( "Duplicate BPINTD %02x, nothing done\n", i1);
     return;
   }
   if (!dpmi_mhp_intxxtab[i1]) dpmi_mhp_intxxtab[i1]=7;
   if (v1) {
     if (mhp_addaxlist_value(v1)) dpmi_mhp_intxxtab[i1] |= 0x80;
   }
   return;
}

static void mhp_bcintd(int argc, char * argv[])
{
   int i1,v1=0;

   if (argc <2) return;
   if (!check_for_stopped()) return;
   sscanf(argv[1], "%x", &i1);
   i1 &= 0xff;
   if (argc >2) {
     sscanf(argv[2], "%x", &v1);
     v1 = (v1 &0xffff) | (i1<<16);
   }

   if ((!dpmi_mhp_intxxtab[i1]) || (v1 && (mhp_getaxlist_value(v1,-1) <0))) {
     if (v1)  mhp_printf( "No BPINTD %02x %04x, nothing done\n", i1, v1 & 0xffff);
     else mhp_printf( "No BPINTD %02x, nothing done\n", i1);
     return;
   }
   if (v1) {
     mhp_delaxlist_value(v1,-1);
     if (mhp_getaxlist_value(i1<<16,0xff0000) <0) dpmi_mhp_intxxtab[i1]=0;
   }
   else {
     mhp_delaxlist_value(i1<<16,0xff0000);
     dpmi_mhp_intxxtab[i1]=0;
   }
   return;
}

static void mhp_bpload(int argc, char * argv[])
{
   if (!check_for_stopped()) return;
   if (mhpdbgc.bpload) {
     mhp_printf("load breakpoint already pending\n");
     return;
   }
   mhpdbgc.bpload=1;
   {
     volatile register int i=0x21; /* beware, set_bit-macro has wrong constraints */
     set_bit(i, mhpdbg.intxxtab);
     if (!test_bit(i, &vm86s.int_revectored)) {
          set_bit(i, mhpdbgc.intxxalt);
          set_revectored(i, &vm86s.int_revectored);
     }
   }
   mhpdbgc.int21_count++;
   return;
}

static void mhp_regs(int argc, char * argv[])
{
  unsigned long newval;
  int i;
  if (argc == 3) {
     if (!mhpdbgc.stopped) {
        mhp_printf("Must be in stopped state\n");
        return;
     }
     sscanf(argv[2], "%lx", &newval);
     i= strlen(argv[1]);
     do  argv[1][i] = toupper_ascii(argv[1][i]); while (i--);
     mhp_setreg(argv[1], newval);
     if (newval == mhp_getreg(argv[1]))
        mhp_printf("reg %s changed to %04x\n", argv[1], mhp_getreg(argv[1]) );
     return;
  }
  if (DBG_TYPE(mhpdbgc.currcode) == DBG_INTx)
     mhp_printf( "INT 0x%02X, ", DBG_ARG(mhpdbgc.currcode));
  if (DBG_TYPE(mhpdbgc.currcode) == DBG_INTxDPMI)
     mhp_printf( "INT 0x%02X in DPMI, ", DBG_ARG(mhpdbgc.currcode) & 0xff);
  if (DBG_TYPE(mhpdbgc.currcode) == DBG_TRAP) {
     if (DBG_ARG(mhpdbgc.currcode)==1) mhp_printf( "Trap %d, ", DBG_ARG(mhpdbgc.currcode));
     else {
       if (mhpdbgc.bpload_bp==3) {
         mhpdbgc.bpload_bp=0;
         mhp_printf("At entry of program %s\n", mhpdbgc.bpload_cmd);
         if (mhpdbgc.bpload_cmdline[0]) {
           mhpdbgc.bpload_cmdline[mhpdbgc.bpload_cmdline[0]+1]=0;
           mhp_printf("command line: %s\n", mhpdbgc.bpload_cmdline+1);
         }
         else mhp_printf(" (empty command line)\n");
       }
       else mhp_printf( "Trap %d, ", DBG_ARG(mhpdbgc.currcode));
     }
  }
  if (DBG_TYPE(mhpdbgc.currcode) == DBG_GPF)
     mhp_printf( "General Protection Fault, ");

 if (!traceloop)
  mhp_printf( "system state: %s%s%s%s\n",
#ifdef X86_EMULATOR
       config.cpuemu > 1 ? "emulated," : "",
#else
       "",
#endif
       mhpdbgc.stopped ? "stopped" : "running",
       IN_DPMI ? " in DPMI" : (dpmi_active()?" in real mode while in DPMI":""),
       IN_DPMI ?(dpmi_mhp_getcsdefault()?"-32bit":"-16bit") : "");

  if (!dpmi_mhp_regs()) {
    mhp_printf("AX=%04x  BX=%04x  CX=%04x  DX=%04x",
                LWORD(eax), LWORD(ebx), LWORD(ecx), LWORD(edx));
    mhp_printf("  SI=%04x  DI=%04x  SP=%04x  BP=%04x",
                LWORD(esi), LWORD(edi), LWORD(esp), LWORD(ebp));
    mhp_printf("\nDS=%04x  ES=%04x  FS=%04x  GS=%04x  FL=%08x",
                SREG(ds), SREG(es), SREG(fs), SREG(gs), REG(eflags));
    mhp_printf("\nCS:IP=%04x:%04x       SS:SP=%04x:%04x\n",
                SREG(cs), LWORD(eip), SREG(ss), LWORD(esp));
  }
  mhp_cmd("u * 1");
}

static void mhp_regs32(int argc, char * argv[])
{
  if (DBG_TYPE(mhpdbgc.currcode) == DBG_INTx)
     mhp_printf( "\nInterrupt 0x%02X", DBG_ARG(mhpdbgc.currcode));
  if (DBG_TYPE(mhpdbgc.currcode) == DBG_TRAP)
     mhp_printf( "\nTrap 0x%02X", DBG_ARG(mhpdbgc.currcode));
  if (DBG_TYPE(mhpdbgc.currcode) == DBG_GPF)
     mhp_printf( "\nGeneral Protection Fault");

  mhp_printf("\nEAX: %08lx EBX: %08lx ECX: %08lx EDX: %08lx VFLAGS(h): %08lx",
              REG(eax), REG(ebx), REG(ecx), REG(edx), (unsigned long)vflags);

  mhp_printf("\nESI: %08lx EDI: %08lx EBP: %08lx",
              REG(esi), REG(edi), REG(ebp));

  mhp_printf(" DS: %04x ES: %04x FS: %04x GS: %04x\n",
              SREG(ds), SREG(es), SREG(fs), SREG(gs));

  mhp_printf(" CS: %04x IP: %04x SS: %04x SP: %04x\n",
              SREG(cs), LWORD(eip), SREG(ss), LWORD(esp));
}

static void mhp_kill(int argc, char * argv[])
{
  mhp_cmd("r0");
  mhp_printf("\ndosemu killed via debug terminal\n");
  mhp_send();
#if 0
  mhp_putc(1); /* tell debugger terminal to also quit */
  mhp_send();
#endif
  mhp_close();
  if (dosdebug_flags & DBGF_IN_LEAVEDOS) dosdebug_flags &= ~DBGF_IN_LEAVEDOS;
  else leavedos(1);
}

static void mhp_help(int argc, char * argv[])
{
  mhp_printf("%s\n",help_page);
}

void mhp_bpset(void)
{
   int i1;
   dpmimode=saved_dpmimode;

   for (i1=0; i1 < MAXBP; i1++) {
      if (mhpdbgc.brktab[i1].is_valid) {
         if (mhpdbgc.brktab[i1].is_dpmi && !dpmi_active()) {
           mhpdbgc.brktab[i1].brkaddr = 0;
           mhpdbgc.brktab[i1].is_valid = 0;
           mhp_printf("Warning: cleared breakpoint %d because not in DPMI\n",i1);
           continue;
         }
         mhpdbgc.brktab[i1].opcode = READ_BYTE(mhpdbgc.brktab[i1].brkaddr);
         if (i1!=trapped_bp) WRITE_BYTE(mhpdbgc.brktab[i1].brkaddr, 0xCC);
      }
   }
   return;
}

void mhp_bpclr(void)
{
   int i1;

   for (i1=0; i1 < MAXBP; i1++) {
      if (mhpdbgc.brktab[i1].is_valid) {
         if (mhpdbgc.brktab[i1].is_dpmi && !dpmi_active()) {
           mhpdbgc.brktab[i1].brkaddr = 0;
           mhpdbgc.brktab[i1].is_valid = 0;
           mhp_printf("Warning: cleared breakpoint %d because not in DPMI\n",i1);
           continue;
         }
         if( READ_BYTE(mhpdbgc.brktab[i1].brkaddr) != 0xCC) {
            if (i1!=trapped_bp) mhpdbgc.brktab[i1].brkaddr = 0;
            continue;
         }
         WRITE_BYTE(mhpdbgc.brktab[i1].brkaddr, mhpdbgc.brktab[i1].opcode);
      }
   }
   saved_dpmimode=dpmimode;
   return;
}


int mhp_bpchk(unsigned int a1)
{
   int i1;

   for (i1=0; i1 < MAXBP; i1++) {
      if (mhpdbgc.brktab[i1].brkaddr == a1) {
        dpmimode=mhpdbgc.brktab[i1].is_dpmi;
        trapped_bp_=i1;
        trapped_bp=-2;
        return 1;
      }
   }
   return 0;
}

int mhp_getcsip_value()
{
  unsigned int val, seg, off, limit;

  if (IN_DPMI) {
    mhp_getadr("cs:eip", &val, &seg, &off, &limit); // Can't fail!
    return val;
  } else
    return (SREG(cs) << 4) + LWORD(eip);
}

void mhp_modify_eip(int delta)
{
  if (IN_DPMI) dpmi_mhp_modify_eip(delta);
  else LWORD(eip) +=delta;
}


void mhp_cmd(const char * cmd)
{
   call_cmd(cmd, MAXARG, cmdtab, mhp_printf);
}

static void mhp_print_ldt(int argc, char * argv[])
{
  static char buffer[0x10000];
  unsigned int *lp, *lp_=(unsigned int *)ldt_buffer;
  unsigned int base_addr, limit;
  int type, type2, i;
  unsigned int seg;
  int lines=0, cache_mismatch;
  enum{Abit=0x100};

  if (get_ldt(buffer) < 0) {
    mhp_printf("error getting ldt\n");
    return;
  }

  if (argc > 1) {
     if (IN_DPMI && isalpha(argv[1][0])) {
       int rnum=decode_symreg(argv[1]);
       if (rnum <0) {
         mhp_printf("wrong register name\n");
         return;
       }
       seg=dpmi_mhp_getreg(rnum);
       sprintf(lastldt, "%x", seg);
       lines=1;
     }
     else {
       sscanf (argv[1], "%x", &seg);
       strcpy(lastldt, argv[1]);
     }
  } else {
     if (!strlen(lastldt)) {
        seg=0;
     }
     sscanf (lastldt, "%x", &seg);
  }
  if (!lines || (argc > 2) ) {
    if (argc > 2) sscanf (argv[2], "%d", &lines);
    else lines = 16;
  }

  lp = (unsigned int *) buffer;
  lp += (seg & 0xFFF8) >> 2;
  lp_ += (seg & 0xFFF8) >> 2;

  for (i=(seg & 0xFFF8); i< 0x10000; i+=8,lp++, lp_+=2) {
    cache_mismatch = (lp[0] != lp_[0]) || ((lp[1]|Abit) != (lp_[1]|Abit));
    if ((lp[0] && lp[1]) ||  cache_mismatch) {
        if (--lines <0) break;
        base_addr = (*lp >> 16) & 0x0000FFFF;
        limit = *lp & 0x0000FFFF;
        lp++;
        /* Second 32 bits of descriptor */
        base_addr |= (*lp & 0xFF000000) | ((*lp << 16) & 0x00FF0000);
        limit |= (*lp & 0x000F0000);
        type = (*lp >> 8)  & 0x000000FF;
        type2= (*lp >> 20) & 0x0000000F;
        if (type2 & 0x08)
           limit *= 4096;
        if (type & 0x10)
           mhp_printf ("%04x: %08x %08x %s%d %d %c%c%c%c%c %p%s\n",
              i | 0x07,
              base_addr,
              limit,
              (type & 0x08) ? "Code" : "Data",
              (type2 & 0x04) ? 32 : 16,
              (type >> 5) & 0x03,
              (type >> 7) ? 'P' : ' ',
              (type & 4)?((type & 8)?'C':'E'):' ',
              (type & 2)?((type & 8)?'R':'W'):' ',
              (type & 1)?'A':' ',
              (lp_[1] &Abit)?'a':' ',
	      MEM_BASE32(base_addr),
              cache_mismatch ?" (cache mismatch)":"");
        else
           mhp_printf ("%04x: %08x %08x System(%02x)%s\n",
              i, base_addr, limit, type,
              cache_mismatch ?" (cache mismatch)":"");
    }
    else lp++;
  }
  sprintf (lastldt, "%x", i);
}

static void mhp_debuglog(int argc, char * argv[])
{
   char buf[256];
   if (argc >1) {
     if (!strcmp(argv[1], "on")) {
       dosdebug_flags |= DBGF_INTERCEPT_LOG | DBGF_LOG_TO_DOSDEBUG;
       return;
     }
     if (!strcmp(argv[1], "off")) {
       dosdebug_flags &= ~DBGF_LOG_TO_DOSDEBUG;
       if (!(dosdebug_flags & DBGF_LOG_TO_BREAK))
         dosdebug_flags &= ~DBGF_INTERCEPT_LOG;
       return;
     }
     SetDebugFlagsHelper(argv[1]);
   }
   if (argc <=1) {
     GetDebugFlagsHelper(buf, 0);
     mhp_printf ("current Debug-log flags:\n%s\n", buf);
   }
}

#define MAX_REGEX		8
static regex_t *rxbuf[MAX_REGEX] = {0};
static char *rxpatterns[MAX_REGEX] = {0};
static int num_regex = 0;
static int num_logbp = 0;

static int get_free_regex_buf(void)
{
  int i;
  for (i=0; i <num_regex; i++) {
    if (!rxbuf[i]) return i;
  }
  if (num_regex >= MAX_REGEX) return -1;
  i = num_regex;
  num_regex++;
  rxbuf[i] = 0;
  rxpatterns[i] =0;
  return i;
}

static void free_regex(int number)
{
  if ((unsigned)number >= MAX_REGEX) return;
  if (!rxbuf[number]) return;
  regfree(rxbuf[number]);
  if (rxpatterns[number]) free(rxpatterns[number]);
  free(rxbuf[number]);
  rxbuf[number] = 0;
  rxpatterns[number] = 0;
}

static char *trimm_string_arg(char *arg)
{
  int len;

  if (!arg || !arg[0]) return 0;
  len = strlen(arg);
  if (     (arg[0] == '"' && arg[len-1] == '"')
        || (arg[0] == '\'' && arg[len-1] == '\'')) {
    arg[len-1] = 0;
    return arg+1;
  }
  return arg;
}

static void print_log_breakpoints(void)
{
   int rx;

   num_logbp = 0;
   for (rx=0; rx <num_regex; rx++) {
     if (rxbuf[rx]) {
       mhp_printf("log breakpoint %d: %s\n", rx, rxpatterns[rx]);
       mhp_send();
       num_logbp++;
     }
   }
   if (!num_logbp) {
     mhp_printf("no log breakpoint active\n");
   }
}


static void mhp_bplog(int argc, char * argv[])
{
   int rx, errcode;
   char buf[1024];
   char *s;

   if (argc >1) {
     if (!check_for_stopped()) return;
     argv++;
     buf[0] = 0;
     while (*argv) {
       s = trimm_string_arg(*argv);
       if (s) strcat(buf, s);
       argv++;
     }
     if (!buf[0]) {
       mhp_printf ("no valid regular expression defined\n");
       return;
     }
     rx = get_free_regex_buf();
     if (rx <0) {
       mhp_printf ("to many log breakpoints, use bclog to free one\n");
       return;
     }
     rxpatterns[rx] = strdup(buf);
     rxbuf[rx] = malloc(sizeof(regex_t));
     if (!rxbuf[rx]) {
       mhp_printf ("out of memory\n");
       return;
     }
     errcode = regcomp(rxbuf[rx], rxpatterns[rx], REG_NOSUB);
     if (errcode) {
        regerror(errcode, rxbuf[rx], buf, sizeof(buf));
        mhp_printf ("%s\n", buf);
        free_regex(rx);
        return;
     }
     /* ...puh, all that work just for generating a pattern :-)
      * now we enable the 'break point' by intercepting the log
      */
     dosdebug_flags |= DBGF_INTERCEPT_LOG | DBGF_LOG_TO_BREAK;
   }
   /* atleast print all active brakepoints */
   print_log_breakpoints();
}

static void mhp_bclog(int argc, char * argv[])
{
   int rx;

   if (argc >1) {
     if (!check_for_stopped()) return;
     rx = atoi(argv[1]);
     if (((unsigned)rx >= MAX_REGEX) || !rxbuf[rx]) {
       mhp_printf("log break point not existing\n", rx);
       return;
     }
     free_regex(rx);
   }
   print_log_breakpoints();
   if (!num_logbp) {
     dosdebug_flags &= ~DBGF_LOG_TO_BREAK;
     if (!(dosdebug_flags & DBGF_LOG_TO_DOSDEBUG)) {
       dosdebug_flags &= DBGF_INTERCEPT_LOG;
     }
   }
}

static int mhp_check_regex(char *line)
{
   int rx, hit;
   if (!num_logbp) return 0;  /* we should not come here */
   for (rx=0; rx <num_regex; rx++) {
     if (rxbuf[rx]) {
       hit = regexec(rxbuf[rx], line, 0, 0, 0) == 0;
       if (hit) {
         mhp_printf("log break point %d hit: >%s<\n",rx,line);
         mhp_send();
       }
       if (hit) return 1;
     }
   }
   return 0;
}

static char lbuf[1024];
static int lbufi = 0;

void mhp_regex(const char *fmt, va_list args)
{
  int i, hit;
  char *s;

  if (!(dosdebug_flags & DBGF_LOG_TO_BREAK)) return;
  lbufi += vsprintf(lbuf+lbufi, fmt, args);
  hit = 0;
  i = 0;
  do {
    s = strchr(lbuf+i, '\n');
    if (s) {
      *s = 0;
      hit = mhp_check_regex(lbuf+i);
      i = (s - lbuf)+1;
      if (hit) break;
    }
  } while (s);
  if (i) {
    memcpy(lbuf, lbuf+i, lbufi-i+1);
    lbufi -= i;
    if (hit) {
      mhpdbgc.want_to_stop = 1;
    }
  }
}

