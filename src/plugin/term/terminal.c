/*
 * (C) Copyright 1992, ..., 2014 the "DOSEMU-Development-Team".
 *
 * for details see file COPYING in the DOSEMU distribution
 */

/*
 * video/terminal.c - contains the video-functions for terminals
 *
 * This module has been extensively updated by Mark Rejhon at:
 * ag115@freenet.carleton.ca.
 *
 * Please send patches and bugfixes for this module to the above Email
 * address.  Thanks!
 *
 * Now, who can write a VGA emulator for SVGALIB and X? :-)
 */

/* Both FAST and NCURSES support has been replaced by calls to the SLang
 * screen management routines.  Now, METHOD_FAST and METHOD_NCURSES are both
 * synonyms for SLang.  The result is a dramatic increase in speed and the
 * code size has dropped by a factor of three.
 * The slang library is available from amy.tch.harvard.edu in pub/slang.
 * John E. Davis (Nov 17, 1994).
 */

/* Some notes about how various versions of the SLang library are used,
 * and UTF8. Right now (May 2005) there are three SLangs in mainstream use:
 * a) slang 1.4.x
 * b) slang 1.4.x + utf8 patch
 * c) slang 2.0
 *
 * a) works with 8 bit character sets, but not with utf8
 *    workarounds: upgrade to 2.0 or don't use utf8
 * b) works with 8 bit and utf8, but has problems when the external
 *    charset=cp437 (*)
 * c) is ideal. It works, no problems.
 *
 * (*): b) ignores the setting of SLsmg_Display_Eight_Bit.
 * any character between 0x80 and 0x9f is not displayed.
 * in any case $_external_charset="cp437" is rarely necessary, perhaps
 * only if you like to use an xterm with the vga font (but then, why not
 * use xdosemu?)
 *
 * On the Linux console in non-utf8 mode a special trick is used to
 * be able to display almost all cp437 characters: a reconstruction
 * of the "alternate character string" that takes advantage of the
 * fact that ACS=cp437 here. All cp437 characters with unicode>=256
 * are placed in this table.
 */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <limits.h>
#include <termios.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <slang.h>

#include "bios.h"
#include "emu.h"
#include "memory.h"
#include "video.h"
#include "serial.h"
#include "keyboard/keyboard.h"
#include "keyboard/keyb_clients.h"
#include "env_term.h"
#include "translate/translate.h"
#include "translate/dosemu_charset.h"
#include "vgaemu.h"
#include "vgatext.h"
#include "render.h"
#include "dos2linux.h"
#include "sig.h"

struct text_system Text_term;
static struct video_system Video_term;

/* The interpretation of the DOS attributes depend upon if the adapter is
 * color or not.
 * If color:
 *   Bit: 0   Foreground blue
 *   Bit: 1   Foreground green
 *   Bit: 2   Foreground red
 *   Bit: 3   Foreground bold (intensity bit)
 *   Bit: 4   Background blue
 *   Bit: 5   Background green
 *   Bit: 6   Background red
 *   Bit: 7   blinking bit  (see below)
 *
 * and if mono bits 3 and 7 have the same interpretation.  However, the
 * Foreground and Background bits have a different interpretation:
 *
 *    Foreground   Background    Interpretation
 *      111          000           Normal white on black
 *      000          111           Reverse video (white on black)
 *      000          000           Invisible characters
 *      001          000           Underline
 *     anything else is invalid.
 */

static int BW_Attribute_Map[256];
static int Color_Attribute_Map[256];

static int *Attribute_Map;
/* if negative, char is invisible */

/* The layout of one charset element is:
   mb0 mb1 mb2 len
   as we never need more than 3 characters to represent a DOS character
   in any multibyte charset that SLang supports (utf8);
   this allows an efficient memcpy of 4 (gcc makes that "mov") followed
   by an increase by len bytes of the buffer pointer in the draw_string
   routine
   mb1 != 0 in utf8 mode means that mb1 is in the alternate character set.
 */
static unsigned char The_Charset[256][4];
static int slang_update (void);
static void term_write_nchars_8bit(unsigned char *text, int len, Bit8u attr);
static void term_write_nchars_utf8(unsigned char *text, int len, Bit8u attr);
static void (*term_write_nchars)(unsigned char *, int, Bit8u) = term_write_nchars_utf8;

/* I think this is what is assumed. */
static int Rows = 25;
static int Columns = 80;

/* sliding window for terminals < 25 lines */
static int DOSemu_Terminal_Scroll_Min = 0;

static int text_updated;
static pthread_mutex_t upd_mtx = PTHREAD_MUTEX_INITIALIZER;

static void get_screen_size (void)
{
  struct winsize ws;		/* buffer for TIOCSWINSZ */

   SLtt_Screen_Rows = 0;
   SLtt_Screen_Cols = 0;
   if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) >= 0)
     {
        if (ws.ws_row > MAX_LINES || ws.ws_col > MAX_COLUMNS)
	  {
	    error("Screen size is too large: %dx%d, max is %dx%d\n",
		  ws.ws_col, ws.ws_row, MAX_COLUMNS, MAX_LINES);
	    leavedos(0x63);
	  }
	SLtt_Screen_Rows = ws.ws_row;
	SLtt_Screen_Cols = ws.ws_col;
     }
   if ((SLtt_Screen_Rows <= 0)
       || (SLtt_Screen_Cols <= 0))
     {
	SLtt_Screen_Cols = 80;
	SLtt_Screen_Rows = 24;
     }
   Rows = SLtt_Screen_Rows;
   Columns = SLtt_Screen_Cols;
   if (Rows < 25) {
       printf("Note that DOS needs 25 lines. You might want to enlarge your\n");
       printf("window before starting dosemu.\n\n");
   }
//   if (Rows < 25) Rows = 25;
   vga.text_width = Columns;
   vga.scan_len = 2 * Columns;
   vga.text_height = Rows;
}

/* bitmap of cp437 characters < 32 that are always control characters
   according to the Linux kernel */
#define CTRL_ALWAYS 0x0800f501
static t_unicode acs_to_uni[128];

/* construct an easy lookup array to figure out the relationship
   between vt100 (acs) characters and unicode.
   If the acs charset is the same as cp437 (as it is on the Linux
   console) we replace the terminal acs lookup string with something
   that can reach all the funny characters; there are around 100
   of them
*/
static void construct_acs_table(void)
{
	struct char_set *charset;
	struct char_set_state state;
	char *smacs = SLtt_tgetstr ("as");
	char *smpch = SLtt_tgetstr ("S2");
	t_unicode uni;

	if (smacs && smpch && strcmp(smacs, smpch) == 0) {
		int i, j = 1;
		char *cp437_acs = malloc(128*2);
		charset = lookup_charset("cp437");
		for (i = 1; i < 256; i++) {
			unsigned char c = i;
			if ((c >= ' ') || !((CTRL_ALWAYS >> c) & 1)) {
				init_charset_state(&state, charset);
				charset_to_unicode(&state, &uni, &c, 1);
				if (uni >= 256) {
					cp437_acs[(j-1)*2] = j;
					cp437_acs[(j-1)*2+1] = c;
					acs_to_uni[j] = uni;
					j++;
				}
				cleanup_charset_state(&state);
			}
		}
		cp437_acs[(j-1)*2] = '\0';
		SLtt_Graphics_Char_Pairs = strdup(cp437_acs);
		free(cp437_acs);
	} else if (SLtt_Graphics_Char_Pairs) {
		char *p;
		charset = lookup_charset("vt100");
		for (p = SLtt_Graphics_Char_Pairs; *p; p += 2) {
			init_charset_state(&state, charset);
			charset_to_unicode(&state, &uni, (unsigned char *)p, 1);
			if (uni >= 256) {
				acs_to_uni[(unsigned char)p[0]] = uni;
			}
			cleanup_charset_state(&state);
		}
	}
}

/* check if c is an approximation of uni */
static int uni_approx(struct char_set *charset, t_unicode uni, unsigned char c)
{
        struct char_set_state state;
        t_unicode u;
        size_t result;

        init_charset_state(&state, charset);
        result = charset_to_unicode(&state, &u, &c, 1);
        cleanup_charset_state(&state);
        return (result == 1 && u != uni);
}

static void set_char_set (void)
{
	struct char_set *term_charset, *display_charset;
	/* For now neither encoding can be a stateful encoding... */
	/* The video charset can never be a stateful encoding
	 * it is a hardware limitation.
	 */
	struct char_set_state term_state;
	struct char_set_state display_state;
	int i;

	term_charset = trconfig.output_charset;
	display_charset = trconfig.video_mem_charset;

	/* Initial don't allow the high control characters. */
	SLsmg_Display_Eight_Bit = 0xA0;
	/* Build the translate tables */
	v_printf("mapping internal characters to terminal characters:\n");
	for(i= 0; i <= 0xff; i++) {
		unsigned char buff[MB_LEN_MAX + 1];
		t_unicode uni;
		size_t result;

		init_charset_state(&term_state, term_charset);
		init_charset_state(&display_state, display_charset);

		buff[0] = i;
		buff[1] = '\0';
		result = charset_to_unicode(&display_state, &uni, buff, 1);
		result = unicode_to_charset(&term_state, uni, buff, MB_LEN_MAX);
		if (result < 1 || result >= 4)
			result = 1;
		buff[3] = result;
		if (result == 1 && SLtt_Graphics_Char_Pairs && uni >= 0x100 &&
		    uni_approx(term_charset, uni, buff[0])) {
			char *p;
			for (p = SLtt_Graphics_Char_Pairs; *p; p += 2)
				if (acs_to_uni[(unsigned char)p[0]] == uni) {
					buff[1] = p[0];
					break;
				}
		}
		memcpy(The_Charset + i, buff, 4);
		v_printf("mapping: %x -> %04x -> %.*s (len=%zu,acs=%x)\n", i, uni,
			 (int)result, buff, result, result == 1 && buff[1] ? buff[1] : 0);

		/* If we have any non control charcters in 0x80 - 0x9f
		 * set up  the slang code up so we can send them.
		 */
		if (result > 1 || (buff[0] >= 0x80 && buff[0] <= 0x9f
		    && (((uni >= 0x20) && (uni < 0x80)) || (uni > 0x9f)))) {
			/* Allow us to use chars 0x80 to 0x9F */
			SLsmg_Display_Eight_Bit = 0x80;
		}

		cleanup_charset_state(&term_state);
		cleanup_charset_state(&display_state);
	}
	/* Slang should filter out the control sequences for us...
	 * So don't worry about characters 0x00 - 0x1f && 0x80 - 0x9f
	 */
}

int using_xterm(void)
{
   char *term = getenv("TERM");

   if (term == NULL)
      return 0;

   return !strncmp("xterm", term, 5) ||
           !strncmp("rxvt", term, 4) ||
           !strcmp("dtterm", term);
}

static int term_change_config(unsigned item, void *buf)
{
   static char title_appname[TITLE_APPNAME_MAXLEN];

   switch (item) {
   case CHG_TITLE_APPNAME:
   {
      mbstate_t unix_state;
      int i;
      char *tmp_ptr;
      char s[strlen(buf) + 1];

      memset(&unix_state, 0, sizeof unix_state);
      for (i = 0, tmp_ptr = buf ; *tmp_ptr; tmp_ptr++) {
	t_unicode symbol;
	symbol = dos_to_unicode_table[(unsigned char)*tmp_ptr];
	/* apparently xterm does not like UTF-8 in the window title...
	   force iso8859-1
	 */
	s[i++] = symbol > 0xff ? '?' : symbol;
      }
      s[i] = '\0';
      snprintf (title_appname, TITLE_APPNAME_MAXLEN, "%s", s);
      if (config.xterm_title && config.xterm_title[0]) {
	size_t len = strlen(config.xterm_title) + i + 1;
	char p[len];
	SLtt_write_string("\x1b]2;");
	snprintf(p, len, config.xterm_title, s);
	SLtt_write_string(p);
	SLtt_write_string("\7");
      }
      return 0;
   }
   case GET_TITLE_APPNAME:
      snprintf (buf, TITLE_APPNAME_MAXLEN, "%s", title_appname);
      return 0;
   }
   return 100;
}

static void sigwinch(struct sigcontext *scp, siginfo_t *si)
{
  get_screen_size();
}

#if SLANG_VERSION < 20000 || defined(USE_RELAYTOOL)
/* replacement function to deal with old slangs */
static int slutf8_enable(int mode)
{
#ifdef USE_RELAYTOOL
  if (SLang_Version >= 20000)
    return SLutf8_enable(mode);
#endif

  if (mode != -1)
    return mode;
  return MB_CUR_MAX > 1;
}
#else
#define slutf8_enable(mode) SLutf8_enable(mode)
#endif

/* The following initializes the terminal.  This should be called at the
 * startup of DOSEMU if it's running in terminal mode.
 */
static int terminal_initialize(void)
{
   SLtt_Char_Type sltt_attr, fg, bg, attr, color_sltt_attr, bw_sltt_attr;
   int is_color = config.term_color;
   int rotate[8];
   struct termios buf;

   v_printf("VID: terminal_initialize() called \n");

   /* This maps (r,g,b) --> (b,g,r) */
   rotate[0] = 0; rotate[1] = 4;
   rotate[2] = 2; rotate[3] = 6;
   rotate[4] = 1; rotate[5] = 5;
   rotate[6] = 3; rotate[7] = 7;

   if(no_local_video!=1) {
     Video_term.update_screen = slang_update;
   }
   else
     Video_term.update_screen = NULL;

   if (using_xterm())
     Video_term.change_config = term_change_config;

   term_init();

   get_screen_size ();

   /* respond to resize events unless we're running on the Linux console
      with raw keyboard: then SIGWINCH = SIG_RELEASE ! */
   if (!config.console_keyb) {
     registersig(SIGWINCH, sigwinch);
   }

   if (isatty(STDOUT_FILENO) && tcgetattr(STDOUT_FILENO, &buf) == 0 &&
       (buf.c_cflag & CSIZE) == CS8 &&
       !getenv("LANG") && !getenv("LC_CTYPE") && !getenv("LC_ALL") &&
       strstr("default", trconfig.output_charset->names[0]) && !config.quiet)
     printf(
     "You did not specify a locale (using the LANG, LC_CTYPE, or LC_ALL\n"
     "environment variable, e.g., en_US) or did not specify an explicit set for\n"
     "$_external_char_set in ~/.dosemurc or dosemu.conf.\n"
     "Non-ASCII characters (\"extended ASCII\") are not displayed correctly.\n");

   /* initialize VGA emulator */
   vga.text_width = Columns;
   vga.scan_len = 2 * Columns;
   vga.text_height = Rows;
   register_text_system(&Text_term);

#if SLANG_VERSION < 20000 || defined(USE_RELAYTOOL)
#ifdef USE_RELAYTOOL
   if (SLang_Version < 20000)
#endif
     SLtt_Use_Blink_For_ACS = 1;
#endif
   SLtt_Blink_Mode = 1;

   SLtt_Use_Ansi_Colors = is_color;

   if (is_color) Attribute_Map = Color_Attribute_Map;
   else Attribute_Map = BW_Attribute_Map;

   if (!slutf8_enable(
	strstr("utf8", trconfig.output_charset->names[0]) ? 1 :
	strstr("default", trconfig.output_charset->names[0]) ? -1 : 0)) {
      construct_acs_table();
      term_write_nchars = term_write_nchars_8bit;
   }

   for (attr = 0; attr < 256; attr++)
     {
	BW_Attribute_Map[attr] = Color_Attribute_Map[attr] = attr;
#if 1   /* As Jim Powers <powers@dtedi.wpafb.af.mil> reported,
	 * this leads to pure "black and white" on dumb terminals.
	 * Commenting out the below statement results in getting visual
	 * attributes on dumb terminal, but produces an invers screen image.
	 * Forcing a configuration for a monochrome video adapter
	 * (config.cardtype = CARD_MDA) solves this problem, but leads to
	 * other problems.
	 * ... have think more deeply about this.  --Hans
	 */
	BW_Attribute_Map[attr] = 0;
#endif

	sltt_attr = 0;
	if (attr & 0x80) sltt_attr |= SLTT_BLINK_MASK;
	if (attr & 0x08) sltt_attr |= SLTT_BOLD_MASK;

	bw_sltt_attr = color_sltt_attr = sltt_attr;

	bg = (attr >> 4) & 0x07;
	fg = (attr & 0x07);

	/* color information */
	color_sltt_attr |= (rotate[bg] << 16) | (rotate[fg] << 8);
	SLtt_set_color_object (attr, color_sltt_attr);

	/* Monochrome information */
	if ((fg == 0x01) && (bg == 0x00)) bw_sltt_attr |= SLTT_ULINE_MASK;
	if (bg & 0x7) bw_sltt_attr |= SLTT_REV_MASK;
	else if (fg == 0)
	  {
	     /* Invisible */
	     BW_Attribute_Map [attr] = -attr;
	  }

	SLtt_set_mono (attr, NULL, bw_sltt_attr);
     }

   /* object 0 is special.  It is normal video.  Lets fix that now. */
   BW_Attribute_Map[0x7] = Color_Attribute_Map[0x7] = 0;
   BW_Attribute_Map[0] = Color_Attribute_Map[0] = 7;

   SLtt_set_color_object (0, 0x000700);
   SLtt_set_mono (0, NULL, 0x000700);
   SLtt_set_color_object (7, 0);
   SLtt_set_mono (7, NULL, 0);

   set_char_set ();

#if SLANG_VERSION < 10000
   if (!SLsmg_init_smg ())
#else
   if (SLsmg_init_smg() == -1)
#endif
   {
	 error ("Unable to initialize SMG routines.");
	 leavedos(32);
   }
   SLsmg_cls ();

   text_gain_focus();

   return 0;
}

static void terminal_close (void)
{
   v_printf("VID: terminal_close() called\n");
   SLsmg_gotorc (SLtt_Screen_Rows - 1, 0);
   SLtt_set_cursor_visibility(1);
   SLsmg_refresh ();
   SLsmg_reset_smg ();
   putc ('\n', stdout);
   term_close();
}

#if 0 /* unused -- Bart */
static void v_write(int fd, unsigned char *ch, int len)
{
  if (!config.console_video)
    DOS_SYSCALL(write(fd, ch, len));
  else
    error("(video) v_write deferred for console_video\n");
}
#endif

static char *Help[] =
{
   "NOTE: The '^@' defaults to Ctrl-^, see dosemu.conf 'terminal {escchar}' .",
   "Function Keys:",
   "    F1: ^@1      F2: ^@2 ...  F9: ^@9    F10: ^@0   F11: ^@-   F12: ^@=",
   "Key Modifiers:",
#ifdef USE_OLD_SLANG_KBD
   "    ^@s : SHIFT KEY        ^@S : STICKY SHIFT KEY",
   "    ^@a : ALT KEY          ^@A : STICKY ALT KEY",
   "    ^@c : CTRL KEY         ^@C : STICKY CTRL KEY",
   "  Note: To cancel the sticky key, press the sticky key again.",
   "  Examples:",
   "    Pressing ^@s followed by ^@3 results in SHIFT-F3.",
   "    Pressing ^@C Up Up Up ^@C results in Ctrl-Up Ctrl-Up Ctrl-Up.",
#else
   "    Normal:  ^@s SHIFT KEY, ^@a ALT KEY, ^@c CTRL KEY, ^@g ALTGR KEY",
   "    Sticky:  ^@S SHIFT KEY, ^@A ALT KEY, ^@C CTRL KEY, ^@G ALTGR KEY",
   "Substitute keys:",
   "    ^@K0 Insert, ^@K7 Home, ^@K3 PgDn, ^@Kd Delete, ^@Kp PrtScn, etc.",
   "Notes:",
   "    The numbers are the same as those on the key on the numeric keypad.",
   "    To cancel the sticky key, press it again or use ^@ Space.",
   "Examples:",
   "    Pressing ^@s followed by ^@3 results in SHIFT-F3.",
   "    Pressing ^@C Up Up Up ^@C results in Ctrl-Up Ctrl-Up Ctrl-Up.",
   "    Pressing ^@c ^@K1  results in Ctrl-End",
#endif
   "Miscellaneous:",
   "    ^@^R : Redraw display      ^@^L : Redraw the display.",
   "    ^@^Z : Suspend dosemu      ^@b  : Select BEST monochrome mode.",
   "    ^@ Up Arrow: Force the top of DOS screen to be displayed.",
   "    ^@ Dn Arrow: Force the bottom of DOS screen to be displayed.",
   "    ^@ Space: Reset Sticky keys and Panning to automatic panning mode.",
   "    ^@? or ^@h:  Show this help screen.",
   "    ^@^@:  Send the ^@ character to dos.",
#ifdef USE_OLD_SLANG_KBD
   " The default panning mode is such that the cursor will always remain visible.",
#endif
   "",
   "PRESS THE SPACE BAR TO CONTINUE---------",
   NULL
};

static void show_help (void)
{
   int i;
   char *s;
   SLsmg_cls ();

   i = 0;
   while ((s = Help[i]) != NULL)
     {
	if (*s)
	  {
	     SLsmg_gotorc (i, 0);
	     SLsmg_write_string (s);
	  }
	i++;
     }
   dirty_text_screen();
   SLsmg_refresh ();
}




/* global variables co and li determine the size of the screen.  Also, use
 * the short pointers prev_screen and screen_adr for updating the screen.
 */
static int slang_update (void)
{
   int changed, imin, cursor_row, cursor_col, cursor_vis;

   static int last_row, last_col, last_vis = -1, help_showing;
   static const char *last_prompt = NULL;

   SLtt_Blink_Mode = (vga.attr.data[0x10] & 0x8) != 0;

   if (DOSemu_Slang_Show_Help)
     {
	if (help_showing == 0) show_help ();
	help_showing = 1;
	return 1;
     }
   help_showing = 0;

   cursor_row = (vga.crtc.cursor_location - vga.display_start) / vga.scan_len;
   cursor_col = ((vga.crtc.cursor_location - vga.display_start) % vga.scan_len) / 2;
   imin = Rows - SLtt_Screen_Rows;
   if (((DOSemu_Terminal_Scroll == 0) &&
	(cursor_row < SLtt_Screen_Rows))
       || (DOSemu_Terminal_Scroll == -1))
     {
	imin = 0;
     }

   pthread_mutex_lock(&upd_mtx);
   changed = text_updated;
   text_updated = 0;
   pthread_mutex_unlock(&upd_mtx);
   vga.text_width = Columns;
   vga.scan_len = 2 * Columns;
   vga.text_height = Rows;
   if (imin != DOSemu_Terminal_Scroll_Min) {
      DOSemu_Terminal_Scroll_Min = imin;
      redraw_text_screen();
   }

   cursor_vis = (vga.crtc.cursor_shape.w & 0x6000) ? 0 : 1;
   if (last_vis != cursor_vis) {
	SLtt_set_cursor_visibility(cursor_vis);
	last_vis = cursor_vis;
	changed = 1;
   }

   if (changed || (last_col != cursor_col) || (last_row != cursor_row)
       || (DOSemu_Keyboard_Keymap_Prompt != last_prompt))
     {
	if (DOSemu_Keyboard_Keymap_Prompt != NULL)
	  {
	     last_row = SLtt_Screen_Rows - 1;
	     SLsmg_gotorc (last_row, 0);
	     last_col = strlen (DOSemu_Keyboard_Keymap_Prompt);
	     SLsmg_set_color (0);
	     SLsmg_write_nchars ((char *)DOSemu_Keyboard_Keymap_Prompt, last_col);
	     dirty_text_screen();

	     if (*DOSemu_Keyboard_Keymap_Prompt == '[')
	       {
		  /* Sticky */
		  last_row = cursor_row - imin;
		  last_col = cursor_col;
	       }
	     else last_col -= 1;
	  }
	else
	  {
	     last_row = cursor_row - imin;
	     last_col = cursor_col;
	  }

	SLsmg_gotorc (last_row, last_col);
	SLsmg_refresh ();
	last_prompt = DOSemu_Keyboard_Keymap_Prompt;
     }
   return 1;
}

static void term_write_nchars_8bit(unsigned char *text, int len, Bit8u attr)
{
   char buf[len + 1];
   char *bufp;
   unsigned char *text_end;

   text_end = text + len;

#if SLANG_VERSION < 20000 || defined(USE_RELAYTOOL)
#ifdef USE_RELAYTOOL
   if(SLang_Version < 20000) {
#endif
   /* switch off blinking for bright backgrounds */
   if ((attr & 0x80) && !(vga.attr.data[0x10] & 0x8)) {
      attr &= ~0x80;
      SLsmg_set_color (Attribute_Map[attr]);
   }
   SLtt_Use_Blink_For_ACS = (attr & 0x80) >> 7;
   /* we can't use the ACS when blinking */
   if (SLtt_Use_Blink_For_ACS) {
      for (bufp = buf; text < text_end; bufp++, text++)
         *bufp = The_Charset[*text][0];
      SLsmg_write_nchars(buf, bufp - buf);
      SLsmg_refresh ();
      return;
   }
#ifdef USE_RELAYTOOL
   }
#endif
#endif

   while (text < text_end) {
      for (bufp = buf; text < text_end; bufp++, text++) {
	 if (The_Charset[*text][1] != '\0') break;
         *bufp = The_Charset[*text][0];
      }
      SLsmg_write_nchars(buf, bufp - buf);
      if (text >= text_end) break;
      /* print ACS characters */
      for (bufp = buf; text < text_end; bufp++, text++) {
	 unsigned char ch = The_Charset[*text][1];
	 if (ch == '\0') break;
         *bufp = ch;
      }
      SLsmg_set_char_set(1);
      SLsmg_write_nchars(buf, bufp - buf);
      SLsmg_set_char_set(0);
   }
}

static void term_write_nchars_utf8(unsigned char *text, int len, Bit8u attr)
{
   char buf[(len + 1) * 3];
   char *bufp;
   unsigned char *text_end = text + len;

   for (bufp = buf; text < text_end; bufp += bufp[3], text++)
      memcpy(bufp, The_Charset + *text, 4);
   SLsmg_write_nchars(buf, bufp - buf);
}

static void term_draw_string(void *opaque, int x, int y, unsigned char *text,
    int len, Bit8u attr)
{
   int this_obj = Attribute_Map[attr];

   y -= DOSemu_Terminal_Scroll_Min;
   if (y < 0 || y >= SLtt_Screen_Rows) return;
   SLsmg_gotorc (y, x);
   SLsmg_set_color (abs(this_obj));

   /* take care of invisible character */
   if (this_obj < 0) {
      char buf[len];
      memset(buf, ' ', len);
      SLsmg_write_nchars(buf, len);
   } else
      term_write_nchars(text, len, attr);

   pthread_mutex_lock(&upd_mtx);
   text_updated++;
   pthread_mutex_unlock(&upd_mtx);
}

void dos_slang_redraw (void)
{
   redraw_text_screen();
   SLsmg_refresh ();
}

void dos_slang_suspend (void)
{
   /*
   terminal_close();
   keyboard_close();

   terminal_initialize();
   keyboard_init();
    */
}


void dos_slang_smart_set_mono (void)
{
   int i, max_attr;
   unsigned int attr_count [256], max_count;
   register unsigned short *s, *smax;

   Attribute_Map = BW_Attribute_Map;
   s = (unsigned short *)(vga.mem.base + vga.display_start);
   smax = s + Rows * Columns;

   for (i = 0; i < 256; i++) attr_count[i] = 0;

   while (s < smax)
     {
	attr_count[*s >> 8] += 1;
	s++;
     }

   max_attr = 0;
   max_count = 0;

   for (i = 0; i < 256; i++)
     {
	Attribute_Map[i] = 1;
	if (attr_count[i] > max_count)
	  {
	     max_attr = i;
	     max_count = attr_count[i];
	  }
     }

   SLtt_normal_video ();

   Attribute_Map [max_attr] = 0;
   SLtt_Use_Ansi_Colors = 0;

   SLtt_set_mono (1, NULL, SLTT_REV_MASK);
   SLtt_set_mono (0, NULL, 0);
   dirty_text_screen();
   set_char_set ();
}

static void term_draw_text_cursor(void *opaque, int x, int y, Bit8u attr,
    int first, int last, Boolean focus)
{
}

#define term_setmode NULL

static struct video_system Video_term = {
   NULL,
   terminal_initialize,
   NULL,
   NULL,
   terminal_close,
   term_setmode,
   slang_update,
   NULL,
   NULL,
   "term"
};

struct text_system Text_term =
{
   term_draw_string,
   NULL,
   term_draw_text_cursor,
   NULL,
};

CONSTRUCTOR(static void init(void))
{
   register_video_client(&Video_term);
}
