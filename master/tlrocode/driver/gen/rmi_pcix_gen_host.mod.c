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
	{ 0x5a34a45c, "__kmalloc" },
	{ 0xd2037915, "dev_set_drvdata" },
	{ 0xd691cba2, "malloc_sizes" },
	{ 0xa30682, "pci_disable_device" },
	{ 0x102b9c3, "pci_release_regions" },
	{ 0xaf559063, "pci_set_master" },
	{ 0xde0bdcff, "memset" },
	{ 0x27773e78, "alloc_etherdev_mq" },
	{ 0xea147363, "printk" },
	{ 0x7bd0a577, "free_netdev" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0xdb3b96d5, "register_netdev" },
	{ 0xb4390f9a, "mcount" },
	{ 0x42c8de35, "ioremap_nocache" },
	{ 0x68f7c535, "pci_unregister_driver" },
	{ 0x2044fa9e, "kmem_cache_alloc_trace" },
	{ 0x37a0cba, "kfree" },
	{ 0x6d090f30, "pci_request_regions" },
	{ 0xedc03953, "iounmap" },
	{ 0x5f07b9f3, "__pci_register_driver" },
	{ 0x73618816, "unregister_netdev" },
	{ 0xeb77efbb, "copy_user_generic" },
	{ 0xde0cf25, "consume_skb" },
	{ 0xa12add91, "pci_enable_device" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "1114B945FDCB996BA9D4DA9");

static const struct rheldata _rheldata __used
__attribute__((section(".rheldata"))) = {
	.rhel_major = 6,
	.rhel_minor = 4,
};
