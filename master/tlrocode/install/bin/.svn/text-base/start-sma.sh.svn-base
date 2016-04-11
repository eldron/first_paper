test -e "/sys/bus/pci/drivers/NCA_PCIE_DRIVER"  && rmmod sma.ko

insmod rmi_pcix_gen_host.ko
./boot_over_pci_app ffwds userapp_os -o -m 0xfffe
#./boot_over_pci_app flash.bin boot_update -f flash.bin
rmmod rmi_pcix_gen_host.ko
sleep 10
./sma_load

ifconfig sma0 192.168.2.100
