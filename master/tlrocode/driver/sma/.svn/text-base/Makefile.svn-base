obj-m := sma.o
sma-objs  := sma_cdev.o sma_netdev.o sma_pciedev.o
subdir-ccflags-y += -I$(NCA_TGTDIR)/include/

KDIR   := /lib/modules/`uname -r`/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
install:
	cp -f *.ko  sma_load sma_unload  $(NCA_TGTDIR)/install/bin
clean:
	make -C $(KDIR) M=$(PWD) clean

