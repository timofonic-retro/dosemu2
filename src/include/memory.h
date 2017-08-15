/* memory.h - general constants/functions for memory, addresses, etc.
 *    for Linux DOS emulator, Robert Sanders, gt8134b@prism.gatech.edu
 */
#ifndef MEMORY_H
#define MEMORY_H

/* split segment 0xf000 into two region, 0xf0000 to 0xf7fff is read-write */
/*                                       0xf8000 to 0xfffff is read-only  */
/* so put anything need read-write into BIOSSEG and anything read-only */
/* to ROMBIOSSEG  */

#ifndef BIOSSEG
#define BIOSSEG		0xf000
#endif

#define ROM_BIOS_SELFTEST	0xe05b
#define ROM_BIOS_EXIT		0xe2b0

#define GET_RETCODE_HELPER	0xe2c6

#define INT09_SEG	BIOSSEG
#define INT09_OFF	0xe987		/* for 100% IBM compatibility */
#define INT09_ADD	((INT09_SEG << 4) + INT09_OFF)

/* The packet driver has some code in this segment which needs to be */
/* at BIOSSEG.  therefore use BIOSSEG and compensate for the offset. */
/* Memory required is about 2000 bytes, beware! */
#define PKTDRV_SEG	(BIOSSEG)
#define PKTDRV_OFF	0xf140
#define PKTDRV_ADD	((PKTDRV_SEG << 4) + PKTDRV_OFF)

#define LFN_HELPER_SEG	BIOSSEG
#define LFN_HELPER_OFF	0xf230
#define LFN_HELPER_ADD	((LFN_HELPER_SEG << 4) + LFN_HELPER_OFF)

/* don't change these for now, they're hardwired! */
#define Mouse_SEG       (BIOSSEG-1)
#define Mouse_ROUTINE_OFF  (0xe2e0+0x10)
#define Mouse_INT_OFF	(INT_OFF(0x33) + 0x10)
#define Mouse_ROUTINE  ((Mouse_SEG << 4)+Mouse_ROUTINE_OFF)

#define EOI_OFF         0xf100
#define EOI2_OFF        0xf110

/* intercept-stub for dosdebugger (catches INT21/AX=4B00 */
#define DBGload_SEG BIOSSEG
#define DBGload_OFF 0xf330

#define DOSEMU_LMHEAP_SEG  BIOSSEG
#define DOSEMU_LMHEAP_OFF  0x4000
#define DOSEMU_LMHEAP_SIZE 0x8000

#ifndef ROMBIOSSEG
#define ROMBIOSSEG	0xf800
#endif

#define IRET_SEG	ROMBIOSSEG
#define IRET_OFF	0x62df

/* EMS origin must be at 0 */
#define EMS_SEG		(ROMBIOSSEG+0x100)
#define EMS_OFF		0x0000
#define EMS_ADD		((EMS_SEG << 4) + EMS_OFF)

#define EMM_SEGMENT             (config.ems_frame)

#define IPX_SEG		ROMBIOSSEG
#define IPX_OFF		0x6310
#define IPX_ADD		((IPX_SEG << 4) + IPX_OFF)

#define INT08_SEG	ROMBIOSSEG
#define INT08_OFF	0x7ea5
#define INT08_ADD	((INT08_SEG << 4) + INT08_OFF)

#define INT70_SEG	ROMBIOSSEG
#define INT70_OFF	0x63f0
#define INT70_ADD	((INT70_SEG << 4) + INT70_OFF)

/* IRQ9->IRQ2 default redirector */
#define INT71_SEG	ROMBIOSSEG
#define INT71_OFF	0x7ee7
#define INT71_ADD	((INT71_SEG << 4) + INT71_OFF)

#define INT75_SEG	ROMBIOSSEG
#define INT75_OFF	0x7e98
#define INT75_ADD	((INT75_SEG << 4) + INT75_OFF)

#define INT1E_SEG	ROMBIOSSEG
#define INT1E_OFF	0x6fc7
#define INT41_SEG	ROMBIOSSEG
#define INT41_OFF	0x6401
#define INT46_SEG	ROMBIOSSEG
#define INT46_OFF	0x6420

#define INT42HOOK_SEG	ROMBIOSSEG
#define INT42HOOK_OFF	0x7065
#define INT42HOOK_ADD	((INT42HOOK_SEG << 4) + INT42HOOK_OFF)

#define POSTHOOK_ADD	((BIOSSEG << 4) + ROM_BIOS_SELFTEST)

/* int10 watcher for mouse support */
/* This was in BIOSSEG (a) so we could write old_int10,
 * when it made a difference...
 */
#define INT10_WATCHER_SEG	ROMBIOSSEG
#define INT10_WATCHER_OFF	0x6330
#ifdef X86_EMULATOR
#define CPUEMU_WATCHER_SEG	ROMBIOSSEG
#define CPUEMU_WATCHER_OFF	0x6390
#define CPUEMUI10_ADD		((CPUEMU_WATCHER_SEG << 4) +\
				  CPUEMU_WATCHER_OFF + 11)
#endif

/* This inline interrupt is used for FCB open calls */
#define FCB_HLP_SEG	ROMBIOSSEG
#define FCB_HLP_OFF	0x6320
#define FCB_HLP_ADD	((INTE7_SEG << 4) + INTE7_OFF)

#define DPMI_SEG	ROMBIOSSEG
#define DPMI_OFF	0x4800		/* need at least 512 bytes */
#define DPMI_ADD	((DPMI_SEG << 4) + DPMI_OFF)

#define DOS_LONG_READ_SEG BIOSSEG
#define DOS_LONG_READ_OFF 0xF400
#define DOS_LONG_WRITE_SEG BIOSSEG
#define DOS_LONG_WRITE_OFF 0xF4A0

#define INT_RVC_SEG BIOSSEG
#define INT_RVC_21_OFF 0xF500
#define INT_RVC_2f_OFF 0xF580

#define XMSControl_SEG  ROMBIOSSEG
#define XMSControl_OFF  0x4C40
#define XMSControl_ADD  ((XMSControl_SEG << 4)+XMSControl_OFF+5)

/* For int15 0xc0 */
#define ROM_CONFIG_SEG  BIOSSEG
#define ROM_CONFIG_OFF  0xe6f5
#define ROM_CONFIG_ADD	((ROM_CONFIG_SEG << 4) + ROM_CONFIG_OFF)

/*
 * HLT block
 */
#define BIOS_HLT_BLK_SEG   0xfc00
#define BIOS_HLT_BLK       (BIOS_HLT_BLK_SEG << 4)
#define BIOS_HLT_BLK_SIZE  0x00800

#define EMSControl_SEG  BIOS_HLT_BLK_SEG
#define IPXEsrEnd_SEG   BIOS_HLT_BLK_SEG
#define PKTRcvCall_SEG  BIOS_HLT_BLK_SEG

#define VBIOS_START	(SEGOFF2LINEAR(config.vbios_seg,0))
/*#define VBIOS_SIZE	(64*1024)*/
#define VBIOS_SIZE	(config.vbios_size)
#define GFX_CHARS	0xffa6e
#define GFXCHAR_SIZE	1400

/* Memory adresses for all common video adapters */

#define MDA_PHYS_TEXT_BASE  0xB0000
#define MDA_VIRT_TEXT_BASE  0xB0000

#define CGA_PHYS_TEXT_BASE  0xB8000
#define CGA_VIRT_TEXT_BASE  0xB8000

#define EGA_PHYS_TEXT_BASE  0xB8000
#define EGA_VIRT_TEXT_BASE  0xB8000

#define VGA_PHYS_TEXT_BASE  0xB8000
#define VGA_VIRT_TEXT_BASE  0xB8000
#define VGA_TEXT_SIZE       0x8000

#define CO      80 /* A-typical screen width */
#define LI      25 /* Normal rows on a screen */
#define TEXT_SIZE(co,li) (((co*li*2)|0xff)+1)

#define VMEM_BASE 0xA0000
#define VMEM_SIZE 0x20000
#define GRAPH_BASE 0xA0000
#define GRAPH_SIZE 0x10000

#define BIOS_DATA_SEG   (0x400)	/* for absolute adressing */

/* Correct HMA size is 64*1024 - 16, but IPC seems not to like this
   hence I would consider that those 16 missed bytes get swapped back
   and forth and may cause us grief - a BUG */
#define HMASIZE (64*1024)
#define LOWMEM_SIZE 0x100000
#define EXTMEM_SIZE ((unsigned)(config.ext_mem << 10))

#ifndef __ASSEMBLER__

#include "types.h"
#include <assert.h>

u_short INT_OFF(u_char i);
#define CBACK_SEG BIOS_HLT_BLK_SEG
extern Bit16u CBACK_OFF;

/* memcheck memory conflict finder definitions */
int  memcheck_addtype(unsigned char map_char, char *name);
void memcheck_reserve(unsigned char map_char, size_t addr_start, size_t size);
void memcheck_init(void);
int  memcheck_isfree(size_t addr_start, size_t size);
int  memcheck_findhole(size_t *start_addr, size_t min_size, size_t max_size);
int memcheck_is_reserved(size_t addr_start, size_t size,
	unsigned char map_char);
void memcheck_dump(void);
void memcheck_type_init(void);
extern struct system_memory_map *system_memory_map;
extern size_t system_memory_map_size;
void *dosaddr_to_unixaddr(unsigned int addr);
void *physaddr_to_unixaddr(unsigned int addr);
//void *lowmemp(const unsigned char *ptr);

/* This is the global mem_base pointer: *all* memory is with respect
   to this base. It is normally set to 0 but with mmap_min_addr
   restrictions it can be non-zero. Non-zero values block vm86 but at least
   give NULL pointer protection.
*/
extern unsigned char *mem_base;

#define LINP(a) ((unsigned char *)(uintptr_t)(a))
typedef uint32_t dosaddr_t;
static inline unsigned char *MEM_BASE32(dosaddr_t a)
{
    uint32_t off = (uint32_t)(uintptr_t)(mem_base + a);
    return LINP(off);
}
static inline dosaddr_t DOSADDR_REL(const unsigned char *a)
{
    return (a - mem_base);
}

/* lowmem_base points to a shared memory image of the area 0--1MB+64K.
   It does not have any holes or mapping for video RAM etc.
   The difference is that the mirror image is not read or write protected so
   DOSEMU writes will not be trapped. This allows easy interference with
   simx86, NULL page protection, and removal of the VGA protected memory
   access hack.

   It is set "const" to help GCC optimize accesses. In reality it is set only
   once, at startup
*/
extern char *lowmem_base;

#define UNIX_READ_BYTE(addr)		(*(Bit8u *) (addr))
#define UNIX_WRITE_BYTE(addr, val)	(*(Bit8u *) (addr) = (val) )
#define UNIX_READ_WORD(addr)		(*(Bit16u *) (addr))
#define UNIX_WRITE_WORD(addr, val)	(*(Bit16u *) (addr) = (val) )
#define UNIX_READ_DWORD(addr)		(*(Bit32u *) (addr))
#define UNIX_WRITE_DWORD(addr, val)	(*(Bit32u *) (addr) = (val) )

#define LOWMEM(addr) ((void *)(&lowmem_base[addr]))

#define LOWMEM_READ_BYTE(addr)		UNIX_READ_BYTE(LOWMEM(addr))
#define LOWMEM_WRITE_BYTE(addr, val)	UNIX_WRITE_BYTE(LOWMEM(addr), val)
#define LOWMEM_READ_WORD(addr)		UNIX_READ_WORD(LOWMEM(addr))
#define LOWMEM_WRITE_WORD(addr, val)	UNIX_WRITE_WORD(LOWMEM(addr), val)
#define LOWMEM_READ_DWORD(addr)		UNIX_READ_DWORD(LOWMEM(addr))
#define LOWMEM_WRITE_DWORD(addr, val)	UNIX_WRITE_DWORD(LOWMEM(addr), val)

static inline void *LINEAR2UNIX(unsigned int addr)
{
	return dosaddr_to_unixaddr(addr);
}

#define READ_BYTE(addr)		UNIX_READ_BYTE(LINEAR2UNIX(addr))
#define WRITE_BYTE(addr, val)	UNIX_WRITE_BYTE(LINEAR2UNIX(addr), val)
#define READ_WORD(addr)		UNIX_READ_WORD(LINEAR2UNIX(addr))
#define WRITE_WORD(addr, val)	UNIX_WRITE_WORD(LINEAR2UNIX(addr), val)
#define READ_DWORD(addr)	UNIX_READ_DWORD(LINEAR2UNIX(addr))
#define WRITE_DWORD(addr, val)	UNIX_WRITE_DWORD(LINEAR2UNIX(addr), val)

#define MEMCPY_2UNIX(unix_addr, dos_addr, n) \
	memcpy((unix_addr), LINEAR2UNIX(dos_addr), (n))

#define MEMCPY_2DOS(dos_addr, unix_addr, n) \
	memcpy(LINEAR2UNIX(dos_addr), (unix_addr), (n))

#define MEMCPY_DOS2DOS(dos_addr1, dos_addr2, n) \
	memcpy(LINEAR2UNIX(dos_addr1), LINEAR2UNIX(dos_addr2), (n))

#define MEMMOVE_DOS2DOS(dos_addr1, dos_addr2, n) \
        memmove(LINEAR2UNIX(dos_addr1), LINEAR2UNIX(dos_addr2), (n))

#define MEMCMP_DOS_VS_UNIX(dos_addr, unix_addr, n) \
	memcmp(LINEAR2UNIX(dos_addr), (unix_addr), (n))

#define MEMSET_DOS(dos_addr, val, n) \
        memset(LINEAR2UNIX(dos_addr), (val), (n))

/* The "P" macros all take valid pointer addresses; the pointers are
   aliased from mem_base to lowmem_base if possible.
   The non-P macros take integers with respect to mem_base or lowmem_base.
   Usually its easiest to deal with integers but some functions accept both
   pointers into DOSEMU data and pointers into DOS space.
 */
#define READ_BYTEP(addr)	READ_BYTE(DOSADDR_REL(addr))
#define WRITE_BYTEP(addr, val)	WRITE_BYTE(DOSADDR_REL(addr), val)
#define READ_WORDP(addr)	READ_WORD(DOSADDR_REL(addr))
#define WRITE_WORDP(addr, val)	WRITE_WORD(DOSADDR_REL(addr), val)
#define READ_DWORDP(addr)	READ_DWORD(DOSADDR_REL(addr))
#define WRITE_DWORDP(addr, val)	WRITE_DWORD(DOSADDR_REL(addr), val)

#define WRITE_P(loc, val) do { \
    Bit8u *__p = (Bit8u *)&loc; \
    switch (sizeof(loc)) { \
    case 1: \
	WRITE_BYTEP(__p, (Bit8u)(val)); \
	break; \
    case 2: \
	WRITE_WORDP(__p, (Bit16u)(val)); \
	break; \
    case 4: \
	WRITE_DWORDP(__p, (Bit32u)(val)); \
	break; \
    default: \
	{ static_assert(sizeof(loc)==1 || sizeof(loc)==2 || sizeof(loc)==4, \
		"WRITE_P: unknown size"); } \
	break; \
    } \
} while(0)

#define READ_BYTE_S(b, s, m)	READ_BYTE(b + offsetof(s, m))
#define READ_WORD_S(b, s, m)	READ_WORD(b + offsetof(s, m))
#define READ_DWORD_S(b, s, m)	READ_DWORD(b + offsetof(s, m))

#define MEMCPY_P2UNIX(unix_addr, dos_addr, n) \
	MEMCPY_2UNIX((unix_addr), DOSADDR_REL(dos_addr), (n))

#define MEMCPY_2DOSP(dos_addr, unix_addr, n) \
	MEMCPY_2DOS(DOSADDR_REL(dos_addr), (unix_addr), (n))

#endif

#endif /* MEMORY_H */
