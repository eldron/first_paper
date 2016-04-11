#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x14522340, "module_layout" },
	{ 0x4f3bf785, "alloc_pages_current" },
	{ 0xc917223d, "pci_bus_read_config_byte" },
	{ 0xf9a482f9, "msleep" },
	{ 0x6980fe91, "param_get_int" },
	{ 0xd2037915, "dev_set_drvdata" },
	{ 0x3e2e9532, "napi_complete" },
	{ 0xd691cba2, "malloc_sizes" },
	{ 0xa30682, "pci_disable_device" },
	{ 0x865e3dca, "netif_carrier_on" },
	{ 0xf77cb70a, "netif_carrier_off" },
	{ 0x102b9c3, "pci_release_regions" },
	{ 0xff964b25, "param_set_int" },
	{ 0x7d11c268, "jiffies" },
	{ 0x343a1a8, "__list_add" },
	{ 0xaf559063, "pci_set_master" },
	{ 0x27773e78, "alloc_etherdev_mq" },
	{ 0x9f1019bd, "pci_set_dma_mask" },
	{ 0xea147363, "printk" },
	{ 0xe52592a, "panic" },
	{ 0x7bd0a577, "free_netdev" },
	{ 0xdb3b96d5, "register_netdev" },
	{ 0xb4390f9a, "mcount" },
	{ 0xaf8d5e94, "netif_receive_skb" },
	{ 0x521445b, "list_del" },
	{ 0x1902adf, "netpoll_trap" },
	{ 0x2689e860, "netif_napi_add" },
	{ 0x859c6dc7, "request_threaded_irq" },
	{ 0x1615b190, "dev_kfree_skb_any" },
	{ 0x520ee4c8, "pci_find_capability" },
	{ 0x78134fe5, "pci_set_mwi" },
	{ 0x25421969, "__alloc_skb" },
	{ 0x42c8de35, "ioremap_nocache" },
	{ 0xbb0c1c6f, "__napi_schedule" },
	{ 0xd55704ee, "eth_type_trans" },
	{ 0x68f7c535, "pci_unregister_driver" },
	{ 0x2044fa9e, "kmem_cache_alloc_trace" },
	{ 0xe52947e7, "__phys_addr" },
	{ 0x4d7d27b8, "pci_bus_write_config_byte" },
	{ 0x236c8c64, "memcpy" },
	{ 0x6d090f30, "pci_request_regions" },
	{ 0x94a8242d, "pci_disable_msi" },
	{ 0xedc03953, "iounmap" },
	{ 0x5f07b9f3, "__pci_register_driver" },
	{ 0x73618816, "unregister_netdev" },
	{ 0x6a7a886b, "pci_enable_msi_block" },
	{ 0xbc0d78f9, "__netif_schedule" },
	{ 0x207b7e2c, "skb_put" },
	{ 0xa12add91, "pci_enable_device" },
	{ 0x6e9681d2, "dma_ops" },
	{ 0xf20dabd8, "free_irq" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "8C0159210FAF71C49660C24");

static const struct rheldata _rheldata __used
__attribute__((section(".rheldata"))) = {
	.rhel_major = 6,
	.rhel_minor = 4,
};
