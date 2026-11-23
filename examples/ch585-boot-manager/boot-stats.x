/* BOOT_STATS sits at the bottom of RAM, outside the boot manager's and every
 * app's REGION_DATA/BSS/STACK, so the runner can read it after the jump. */
SECTIONS
{
    .boot_stats (NOLOAD) :
    {
        KEEP(*(.boot_stats))
    } >STATS
}
