#ifndef __SMA_DRIVER_H__
#define __SMA_DRIVER_H__

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
#include <linux/kthread.h> 
#include <linux/ioctl.h>
#include <linux/cdev.h>
#include <linux/sort.h>

#include "sma_table.h"

#define NCA_PCIE_DRIVER "NCA_PCIE_DRIVER"
#define PFX NCA_PCIE_DRIVER ": "

typedef struct 
{
    struct net_device* ndev;
    struct napi_struct napi; //!< napi结构体
    struct net_device_stats stats;
    u32 port;
}sma_net_drv_info_t;

typedef struct 
{    
    struct cdev         cdev;               //!< 字符设备
    uint32_t            mmap_flag;          //!< MMAP 映射类型(1 = PCI地址映射,2=DMA内存映射)
    uint32_t            mmap_arg;
    uint32_t            huge_page[MAX_NUM_RX_CHANNELS];
}sma_cdev_drv_info_t;

typedef struct 
{    
    struct pci_dev*     pdev ;              //!< PCI 设备指针
    resource_size_t     shm_phys_addr;      //!< PCI 内存物理首地址
    void __iomem *      shm_virt_addr;      //!< PCI 内存映射后的虚拟地址
}sma_pcie_drv_info_t;

typedef struct
{
    sma_net_drv_info_t*     net_drv;
    sma_cdev_drv_info_t     cdev_drv;
    sma_pcie_drv_info_t     pcie_drv;
}sma_driver_info_t;

#define NCA_VENDOR_ID 0x182e
#define NCA_DEVICE_ID 0xabcd


#define MMAP_FLAG_INVALID       0x00
#define MMAP_FLAG_PCIE          0x01
#define MMAP_FLAG_RX_QUEUE      0x02
#define SMA_IOC_MAGIC 'X'
#define SMA_IOC_MMAP_PCIE _IOW(SMA_IOC_MAGIC, 1, uint32_t)
#define SMA_IOC_MMAP_RX_FIFO _IOW(SMA_IOC_MAGIC, 2, uint32_t)

//DMA SKB_BUFF 字节对齐
#define SMA_DMA_ALIGN 4

extern sma_driver_info_t sma_driver_info;

extern ffwd_dma_queue_t * ffwd_dma_queue;
extern ffwd_device_info_t * ffwd_device_info;
extern ffwd_counter_info_t * ffwd_counter_info;
extern entry_state_desc_t * ffwd_session_state_base;
extern entry_state_desc_t * ffwd_udp_state_base;
extern ffwd_mac_entry_desc_t * ffwd_mac_entry_desc_rx ;
extern ffwd_mac_entry_desc_t * ffwd_mac_entry_desc_tx ;
extern ffwd_mac_device_info_t * ffwd_mac_device_info;
extern ffwd_mac_counter_t * ffwd_mac_counter ;

// 12 rx rings
extern ffwd_mac_entry_desc_t * tlro_rx_entry_desc[TLRO_RX_RING_COUNT];

#define DPRINTK(klevel, fmt, args...) \
    printk(KERN_##klevel PFX " %s: " fmt,__func__ , ## args)
    


int sma_cdev_init(sma_driver_info_t * sma_driver_info);
void sma_cdev_release(sma_driver_info_t * sma_driver_info);
int sma_netdev_init( sma_driver_info_t * sma_driver_info );
void sma_netdev_release( sma_driver_info_t * sma_driver_info );




#if 0
#define Message(a,b...) printk("\n[%s]\t"a"\n",__FUNCTION__,##b)
#else
#define Message(a,b...) do {} while(0)
#endif

struct skbnode_s{
	struct list_head node;
	struct sk_buff * skb;
	int offset;
	uint32_t address;
	uint16_t data_len;
};

#endif



