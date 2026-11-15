/* X6b slot layout: 16 KiB reset stub at 0x0, app in slot A at 0x4000.
 *
 * `link.x` INCLUDEs this file, so these regions and the extra SECTIONS block
 * reach the linker before qingke-rt's own script. */
MEMORY
{
    BOOT      (rwx) : ORIGIN = 0x00000000, LENGTH =   16K
    CODEFLASH (rwx) : ORIGIN = 0x00004000, LENGTH =  216K
    DATAFLASH (rwx) : ORIGIN = 0x00070000, LENGTH =   32K
    SRAM      (rwx) : ORIGIN = 0x20000000, LENGTH =  128K
}

REGION_ALIAS("FLASH", CODEFLASH);

REGION_ALIAS("RAM", SRAM);
REGION_ALIAS("REGION_TEXT", CODEFLASH);
REGION_ALIAS("REGION_RODATA", CODEFLASH);
REGION_ALIAS("REGION_DATA", SRAM);
REGION_ALIAS("REGION_BSS", SRAM);
REGION_ALIAS("REGION_HEAP", SRAM);
REGION_ALIAS("REGION_STACK", SRAM);

SECTIONS
{
    .boot_entry :
    {
        KEEP(*(.boot_entry))
    } >BOOT
}
