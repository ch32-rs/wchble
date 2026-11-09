/* Compiler-generated PDU copies are on the same deadline as the radio code.
 * Extend qingke-rt's contiguous startup copy, rather than override memcpy. */
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
