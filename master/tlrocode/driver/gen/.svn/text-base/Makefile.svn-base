KDIR := /lib/modules/`uname -r`/build

obj-m := rmi_pcix_gen_host.o

PWD := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules 
install:
	cp -f *.ko $(NCA_TGTDIR)/install/bin
clean:
	make -C $(KDIR) M=$(PWD) clean
