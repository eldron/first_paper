ifeq ($(NCA_TGTDIR),)
  NCA_TGTDIR=$(CURDIR)/..
endif
RMIOS_LIB=../rmios_lib
include $(RMIOS_LIB)/scripts/Makefile.mk

mode = kuseg

HEAPSIZE = 0x200000
SHARED_HEAP_SIZE = 0x400000
DATA_SEG_ALIGNMENT = 0x200000


MSGRING_XLS_CFG = msgring_xls.cfg
OUTPUT = ffwds

CFLAGS = -DRMIOS -DXLS -DFFWD -DRMIOS_TLB_REFILL_HANDLER -I $(RMIOS_LIB)/include -I../include \
-funroll-loops -finline-limit=200000 -fomit-frame-pointer -mno-branch-likely -march=xlr -mabi=o64 -Wall \
-G0 -mno-abicalls -fno-pic -fno-common  -O3

CFLAGS += -DDEF_FFWD_DBG
CFLAGS += -DPERF_DBG
CFLAGS += -DDEF_DMA_DBG
CFLAGS += -DCACHE_COMP
CFLAGS += -DDEF_NCA_COUNT
ifeq ($(version),mem_4g)
CFLAGS += -DMEM_4G
endif
ifeq ($(netdev),double_10g)
CFLAGS += -DDOUBLE_10G
endif



OBJS = msgring_xls.o  ffwd_main.o ffwd_input.o


all: $(LINKER_SCRIPT) $(OBJS) 
	$(LD) $(LINKFLAGS) $(LIBRARIES_START) $(OBJS) $(LIBRARIES_END) -o  $(OUTPUT)
	cp ffwds ../install/bin

clean:
	rm -rf *~ $(OBJS) $(OUTPUT) $(LINKER_SCRIPT) msgring_xls.c msgring.c *.d

install: 
	cp -f $(OUTPUT) $(NCA_TGTDIR)/install/bin


	
