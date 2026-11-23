/* Flash-engine calls must not fetch from CodeFlash while it is unlocked.
 * Keep memcpy/memset in RAM so flash operations stay inside the window. */
SECTIONS
{
    .highcode_mem : ALIGN(4)
    {
        *(.text.memcpy .text.memset)
        *(.text.*compiler_builtins*3mem*)
        . = ALIGN(4);
        _highcode_vma_end = .;
    } >RAM AT>FLASH
}
INSERT AFTER .highcode;
