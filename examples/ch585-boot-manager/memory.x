/* X6b boot manager: 16 KiB at 0x0 owns the reset vector.
 *
 * Slot A/B are documentation only; the boot manager addresses them through
 * the flash driver, not through the linker. `link.x` INCLUDEs this file. */
MEMORY
{
    BOOT      (rwx) : ORIGIN = 0x00000000, LENGTH = 16K
    SLOT_A    (rwx) : ORIGIN = 0x00004000, LENGTH = 216K
    SLOT_B    (rwx) : ORIGIN = 0x0003A000, LENGTH = 216K
    DATAFLASH (rwx) : ORIGIN = 0x00070000, LENGTH = 32K
    /* First 128 B of RAM stay out of every app: BOOT_STATS lives here so the
     * post-jump app cannot zero or overwrite the boot evidence. */
    STATS     (rw)  : ORIGIN = 0x20000000, LENGTH = 128
    SRAM      (rwx) : ORIGIN = 0x20000080, LENGTH = 128K - 128
}

REGION_ALIAS("FLASH", BOOT);

REGION_ALIAS("RAM", SRAM);
REGION_ALIAS("REGION_TEXT", BOOT);
REGION_ALIAS("REGION_RODATA", BOOT);
REGION_ALIAS("REGION_DATA", SRAM);
REGION_ALIAS("REGION_BSS", SRAM);
REGION_ALIAS("REGION_HEAP", SRAM);
REGION_ALIAS("REGION_STACK", SRAM);
