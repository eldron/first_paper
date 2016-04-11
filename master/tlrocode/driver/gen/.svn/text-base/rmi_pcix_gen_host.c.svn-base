/*********************************************************************

  Copyright 2003-2006 Raza Microelectronics, Inc. (RMI). All rights
  reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in
  the documentation and/or other materials provided with the
  distribution.

  THIS SOFTWARE IS PROVIDED BY Raza Microelectronics, Inc. ``AS IS'' AND
  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL RMI OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
  THE POSSIBILITY OF SUCH DAMAGE.

  *****************************#RMI_2#**********************************/

#include <linux/sched.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/compiler.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/delay.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <linux/completion.h>
#include <linux/crc32.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/atomic.h>
#include <linux/timer.h>
#include <linux/sysctl.h>

//#ifdef CONFIG_RMI_PHOENIX
//#include <asm/rmi/rmi_pcix_gen_host.h>
//#else
#include "rmi_pcix_gen_host.h"
//#endif

#define Message(a,b...) printk("\n[%s]\t"a"\n",__FUNCTION__,##b)
#define ErrorMsg(a,b...) printk("\n[%s]\t"a"\n",__FUNCTION__,##b)
#define RMI_VENDOR_ID 0x182e
#define RMI_DEVICE_ID 0x0000

#define RMI_DRIVER "rmi_pcix_gen_drv"
#define PHNX_MAX_IRQS_SUPPORTED 16
#define PHNX_IMAGE_BUFF_LEN 1024


static int kimage_phnx_xmit(struct sk_buff *skb, struct net_device *dev);
static int kimage_phnx_close(struct net_device *dev);
static int kimage_phnx_open(struct net_device *dev);
static int kimage_phnx_ioctl(struct net_device *dev,struct ifreq *ifr, int cmd);


void phnx_pci_writel(unsigned int  data,unsigned int *addr)
{
    writel(cpu_to_be32(data),addr);
}

void phnx_pci_writeb(unsigned char data, void *addr)
{
    writeb(data,addr);
}

u8 phnx_pci_readl(u8 *base)
{
    return be32_to_cpu(readl(base));
}
 

u8 phnx_pci_readb(u8 *base)
{
    return readb(base);
}


//!网卡驱动私有结构体
struct priv
{
    struct net_device *dev;
    struct net_device_stats stats;
    int port;
    u32 phnx_tx_producer;
    u32 phnx_pending_tx;
    u32 phnx_rx_consumer;
};

//! 网卡驱动描述符
static struct net_device *ndev;

//! 网卡驱动函数指针结构体
static const struct net_device_ops netdev_ops = {
	.ndo_open		= kimage_phnx_open,
	.ndo_stop		= kimage_phnx_close,
	.ndo_start_xmit		= kimage_phnx_xmit,
	.ndo_do_ioctl       =kimage_phnx_ioctl
};

//! 全局变量--PCI 共享内存首地址
static volatile unsigned int *
        rmi_phnx_shared_mem_base_host = NULL;

//! PCI 设备描述符
struct pci_dev *rmi_pdev=NULL;


static int kimage_phnx_xmit(struct sk_buff *skb, struct net_device *dev)
{
	Message("in kimage_phnx_xmit !! BLANK BLANK !! \n");
	dev_kfree_skb(skb);
	return 0;
}

static int kimage_phnx_close(struct net_device *dev)
{
	Message("in close !!! BLANK BLANK !!! \n");
	return 0;
}

static int kimage_phnx_open(struct net_device *dev)
{
	Message("in open !!! BLANK BLANK !!! \n");
	return 0;
}

static int kimage_phnx_ioctl(struct net_device *dev,struct ifreq *ifr, int cmd)
{
	u8 *ptr;
	unsigned long result;
	static unsigned char *kimage_loc ;
	static int phnx_image_len;
	int buff_len;
	int argc;
	int argv_len;
	u8 *arg_buf, *dst;
	int i;

	switch (cmd){
		case SIOCDEVPRIVATE+0x03:
			kimage_loc = (unsigned char *)rmi_phnx_shared_mem_base_host +PCIX_BOOT_FILE_START; //kernel image location;
			phnx_image_len = 0;
			Message("kimage_loc = %p\n", kimage_loc);
			return 0; 

		case SIOCDEVPRIVATE+0x04:
			// send argc + len + args

			result = __copy_from_user((void *)&argc,(void *)ifr->ifr_data,4);
			Message ("ifr->ifr_data = %p\n", ifr->ifr_data);
			if(result > 0){
				ErrorMsg("invalid address frm user space");			
				return -1;
			}	

			result = __copy_from_user((void *)&argv_len,	(void *)(ifr->ifr_data+4),4);
			if(result > 0){
				ErrorMsg("invalid address frm user space");
				return -1;
			}							

			phnx_pci_writel(argc,
			(uint32_t *)((u8 *)rmi_phnx_shared_mem_base_host + 	PCIX_BOOT_ARG_CNT_OFF));

			phnx_pci_writel(argv_len,(uint32_t *)((u8 *)rmi_phnx_shared_mem_base_host +	PCIX_BOOT_ARGS_LEN_OFF));

			arg_buf = kmalloc(argv_len, GFP_KERNEL);
			if(arg_buf == NULL)
				return -ENOMEM;

			__copy_from_user((void *)arg_buf,(void *)(ifr->ifr_data+8), argv_len);

			dst = ((u8 *)rmi_phnx_shared_mem_base_host +	PCIX_BOOT_ARGS_OFF);

			for(i=0; i < argv_len; i++) 
			{
				phnx_pci_writeb(arg_buf[i], dst);
				dst++;
			}

			return 0;

			case SIOCDEVPRIVATE+0x02:

				ptr = (u8 *)kmalloc(PHNX_IMAGE_BUFF_LEN, GFP_KERNEL);
				if (ptr == NULL){
					ErrorMsg(KERN_ERR "Unable to allocate memory !!!\n");
					return -ENOMEM;
				}

				result = __copy_from_user(ptr, ifr->ifr_data, 	PHNX_IMAGE_BUFF_LEN);
				if (result > 0)
					return -EIO;
				buff_len = *((int *)ptr);
				//Message("Got %d bytes Chunk \n", buff_len);

				for(i=0; i < buff_len; i++)
					phnx_pci_writeb(ptr[i+4], kimage_loc+i);

				kimage_loc += buff_len; 
				phnx_image_len += buff_len;

				kfree(ptr);
				if (buff_len < (PHNX_IMAGE_BUFF_LEN-4) ||buff_len == 0){
					Message("File Download completed Total len %d at %p\n", phnx_image_len ,rmi_phnx_shared_mem_base_host);
					phnx_pci_writel(phnx_image_len,	((uint32_t *)rmi_phnx_shared_mem_base_host + 1));
					phnx_pci_writel(0xa5a5a5a5,(uint32_t *) rmi_phnx_shared_mem_base_host);
					//printk("magic = %x\n",phnx_pci_readl((uint32_t *) rmi_phnx_shared_mem_base_host));

				}
				return 0;

				default:
				return -EINVAL;

				}
				return -EINVAL;
}

static struct pci_device_id rmi_id_table[] = {
  {RMI_VENDOR_ID, PCI_ANY_ID, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 },
  {0,}
};

static int rmi_ioctl_phnx_probe(void)
{
	struct priv *priv = NULL;
	int i;
	int ret=0;
	Message("\n%s Called\n",__FUNCTION__);

	ndev = alloc_etherdev(sizeof(struct priv));
	if(!ndev)
	{
		ret = -ENOMEM;
		goto out;
	}

    priv = netdev_priv(ndev);
	priv->dev = ndev;
    ndev->netdev_ops = &netdev_ops;
	strcpy(ndev->name, "phnx_boot0");

	for(i=0; i<6; i++)
	    ndev->dev_addr[i] = i;
	printk("\"phnx_boot0\" Boot Over PCI - interface registered\n");
	register_netdev(ndev);
	return ret;
out:
	ErrorMsg("Returnin Error %d",ret);
	return ret;  
}

static int rmi_phnx_generic_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{  
  int err;
  unsigned long pio_start, pio_end, pio_flags, pio_len;
  rmi_pdev = pdev;
  
  err = pci_enable_device(pdev);
  if (err) 
  {
      ErrorMsg("Cannot enable PCI device.\n");
      return err;
  }

    pio_start = pci_resource_start (pdev, 0);
    pio_end = pci_resource_end (pdev, 0);
    pio_flags = pci_resource_flags (pdev, 0);
    pio_len = pci_resource_len (pdev, 0);
    
  if (!(pio_flags & IORESOURCE_MEM))
  {
    ErrorMsg( "Cannot find proper PCI device " 
	     	    "base address BAR0, aborting.\n");
    err = -ENODEV;
    goto err_out_disable_pdev;
  }
  
  err = pci_request_regions(pdev, RMI_DRIVER);
  if (err)
  {
    ErrorMsg("Cannot obtain PCI resources, aborting.");
    err = -ENODEV;
    goto err_out_disable_pdev;
  }
  
  pci_set_master(pdev);

  rmi_phnx_shared_mem_base_host = (unsigned volatile int *)
			ioremap_nocache(pio_start,pio_len);
			
  if(rmi_phnx_shared_mem_base_host)
  {
    memset(rmi_phnx_shared_mem_base_host, 0, pio_len);

    ErrorMsg("Device Memory Available @ %#x (%d) \n",
    	(uint32_t)(unsigned long)rmi_phnx_shared_mem_base_host,
                     (uint32_t) pio_len);
  }
  else
  {
      ErrorMsg("ioremap_nocache faild.\n");
      err = -ENODEV;
      goto err_out_disable_pdev;
  }

  rmi_ioctl_phnx_probe();
    
err_out_disable_pdev:
    pci_disable_device(pdev);
    pci_set_drvdata(pdev, NULL);
    return err;
}

static void rmi_phnx_generic_remove(struct pci_dev *pdev)
{
    unregister_netdev(ndev);
    free_netdev(ndev);

    iounmap((void *)rmi_phnx_shared_mem_base_host);
    pci_release_regions(pdev);
    pci_disable_device(pdev);
    pci_set_drvdata(pdev, NULL);

    Message("rmmod rmi_pcix_gen_host.ko\n");
    return;     
}

static struct pci_driver rmi_pci_driver = {
  .name = RMI_DRIVER,
  .id_table = rmi_id_table,
  .probe  = rmi_phnx_generic_probe,
  .remove = rmi_phnx_generic_remove,
};

int __init rmi_pcix_gen_init(void)
{
  return pci_register_driver(&rmi_pci_driver);
}

void __exit rmi_pcix_gen_uninit(void)
{
  pci_unregister_driver(&rmi_pci_driver);
}

module_init(rmi_pcix_gen_init);
module_exit(rmi_pcix_gen_uninit);

MODULE_LICENSE("GPL");
