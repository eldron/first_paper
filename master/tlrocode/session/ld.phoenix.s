ENTRY(_start)
STARTUP(crt0.o)
OUTPUT_FORMAT(elf32-tradbigmips)




__DYNAMIC = 0;
PROVIDE (hardware_exit_hook = 0);
PROVIDE (hardware_hazard_hook = 0);
PROVIDE (hardware_init_hook = 0);
PROVIDE (software_init_hook = 0);

PROVIDE (bucket_sizes = 0) ;
PROVIDE ( cc_table_cpu_0 = 0) ;
PROVIDE ( cc_table_cpu_1 = 0) ;
PROVIDE ( cc_table_cpu_2 = 0) ;
PROVIDE ( cc_table_cpu_3 = 0) ;
PROVIDE ( cc_table_cpu_4 = 0) ;
PROVIDE ( cc_table_cpu_5 = 0) ;
PROVIDE ( cc_table_cpu_6 = 0) ;
PROVIDE ( cc_table_cpu_7 = 0) ;
PROVIDE ( cc_table_xgs_0 = 0) ;
PROVIDE ( cc_table_xgs_1 = 0) ;
PROVIDE ( cc_table_gmac = 0) ;
PROVIDE ( cc_table_dma = 0) ;
PROVIDE ( cc_table_sec = 0) ;

PROVIDE ( xls_bucket_sizes = 0) ;
PROVIDE ( xls_cc_table_cpu_0 = 0) ;
PROVIDE ( xls_cc_table_cpu_1 = 0) ;
PROVIDE ( xls_cc_table_xgs_0 = 0) ;
PROVIDE ( xls_cc_table_xgs_1 = 0) ;
PROVIDE ( xls_cc_table_gmac0 = 0) ;
PROVIDE ( xls_cc_table_gmac1 = 0) ;
PROVIDE ( xls_cc_table_cmp = 0) ;
PROVIDE ( xls_cc_table_dma = 0) ;
PROVIDE ( xls_cc_table_sec = 0) ;
PROVIDE ( xls_cc_table_pcie = 0) ;

PHDRS
{
    headers PT_PHDR PHDRS ;
    text PT_LOAD FILEHDR PHDRS ;
    data PT_LOAD ;
    shmem PT_LOAD FLAGS (0x2 | 0x4 | 0x0100000) ;
}

SECTIONS
{
    . = 0x200000 + SIZEOF_HEADERS;
    _loadaddr = .;





    .init :
    {
    PROVIDE(__start = .);
        *(.init)
    } :text

    .text :
    {
        _ftext = . ;
        PROVIDE (eprol = .);
        _shim_reg = . ;
        *(.text)
        *(.text.*)
        *(.gnu.linkonce.t*)
        *(.mips16.fn.*)
        *(.mips16.call.*)
    }

    .fini :
    {
        *(.fini)
    }

    PROVIDE (__etext = .);
    PROVIDE (_etext = .);
    PROVIDE (etext = .);

    .rel.sdata :
    {
        PROVIDE (__runtime_reloc_start = .);
        *(.rel.sdata)
        PROVIDE (__runtime_reloc_stop = .);
    }

    .rodata :
    {
        *(.rdata)
        *(.rodata)
        *(.rodata.*)
        *(.gnu.linkonce.r*)

  PROVIDE (__modules_start = .);
    }





    .data BLOCK(0x200000) :
    {
     _fdata = ABSOLUTE(.);

        *(.data)
        *(.data.*)
        *(.gnu.linkonce.d*)
        . = ALIGN(32);
        _gzip_start = ABSOLUTE(.);
        *(.gzip)
        . = ALIGN(4);
        _gzip_end = ABSOLUTE(.);

        PROVIDE(rmios_symtab = .);
 PROVIDE(rmios_symtab_string_t = .);

    } :data

    .eh_frame :
    {
        KEEP (*(.eh_frame))
    }

    .ctors :
    {
        KEEP (*crtbegin.o(.ctors))






        KEEP (*(EXCLUDE_FILE (*crtend.o) .ctors))
        KEEP (*(SORT(.ctors.*)))
        KEEP (*(.ctors))
    }

    .dtors :
    {
        KEEP (*crtbegin.o(.dtors))
        KEEP (*(EXCLUDE_FILE (*crtend.o) .dtors))
        KEEP (*(SORT(.dtors.*)))
        KEEP (*(.dtors))
    }



    _gp = ALIGN(16) + 0x7ff0;
    __global = _gp;

    .sdata :
    {
        *(.sdata)
        *(.sdata.*)
        *(.gnu.linkonce.s*)
    }

    . = ALIGN (8);

    .lit8 :
    {
        *(.lit8)
    }
    .lit4 :
    {
        *(.lit4)
    }

    . = ALIGN(4);

     _edata = .;
     PROVIDE (edata = .);

     _fbss = .;
    .sbss :
    {
        *(.sbss)
        *(.scommon)
    }
    .bss :
    {
        _bss_start = . ;
        *(.bss)
        *(COMMON)
        . = ALIGN (32 / 8);



        . = ALIGN(8192);


        PROVIDE(__stack = . + 12K - 64);

        . = . + 12K;

        __stack_base = .;


        . = . + 12K*32;

        __stack_end = .;

        . = . + 64;

        *(.thread.info)
        . = ALIGN (32);

        _end = .;
        PROVIDE (end = .);
        . = . + 0x200000;
        PROVIDE(_endaddr = ABSOLUTE(.));
    }

    . = ALIGN(0x200000);

    .rmios.shmem BLOCK(0x200000) :
    {
        *(.rmios.shmem)
  . = ALIGN (8);
        _sheap_start = ABSOLUTE(.);
        . = ALIGN(8);
    } :shmem

    PROVIDE (_sheap_size = 0x400000);

    . = . + 0x400000;
    _sheap_end = .;
    PROVIDE(_program_size = .);

 . = ALIGN(0x200000);

    .execinfo (NOLOAD) :
    {
        LONG(_loadaddr);
        LONG(_program_size);
        LONG(0x400000);
        LONG(_sheap_start);
        QUAD(_loadaddr);
        QUAD(_program_size);
        QUAD(0x400000);
        QUAD(_sheap_start);
    }

    .versioninfo(NOLOAD):
    {

    LONG(0x900d900d);

        LONG(0xc);

 LONG(0x10700);
    }

    .heapinfo (NOLOAD) :
    {
        QUAD(_end);
        QUAD(_endaddr);
        QUAD(_sheap_start);
        QUAD(_sheap_end);
    }







    .debug 0 : { *(.debug) }
    .line 0 : { *(.line) }


    .debug_srcinfo 0 : { *(.debug_srcinfo) }
    .debug_sfnames 0 : { *(.debug_sfnames) }


    .debug_aranges 0 : { *(.debug_aranges) }
    .debug_pubnames 0 : { *(.debug_pubnames) }


    .debug_info 0 : { *(.debug_info) }
    .debug_abbrev 0 : { *(.debug_abbrev) }
    .debug_line 0 : { *(.debug_line) }
    .debug_frame 0 : { *(.debug_frame) }
    .debug_str 0 : { *(.debug_str) }
    .debug_loc 0 : { *(.debug_loc) }
    .debug_macinfo 0 : { *(.debug_macinfo) }


    .debug_weaknames 0 : { *(.debug_weaknames) }
    .debug_funcnames 0 : { *(.debug_funcnames) }
    .debug_typenames 0 : { *(.debug_typenames) }
    .debug_varnames 0 : { *(.debug_varnames) }
}
