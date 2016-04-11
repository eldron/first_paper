#include "sma_driver.h"


static int timeout = 5 * HZ;
#define ETH_FRAME_LEN 1514    /* Max. octets in frame sans FCS */


static void sma_disable_msi(struct pci_dev * pdev)
{
    //ffwd_mac_device_info->msi_enable = 0;
    //wmb();
    //DPRINTK(DEBUG, "msi irq disable\n");

    unsigned char  byte;
    pci_read_config_byte( pdev, 0x52, &byte );
    byte = byte | 0x1;
    pci_write_config_byte( pdev, 0x52, byte );

}


static void sma_enable_msi(struct pci_dev * pdev)
{
    //ffwd_mac_device_info->msi_enable = 1;
   // wmb();

    //DPRINTK(DEBUG, "msi irq enable\n"); 

    unsigned char  byte;
    pci_read_config_byte( pdev, 0x52, &byte );
    byte = byte & ~( 0x01 );
    pci_write_config_byte( pdev, 0x52, byte );

}

uint8_t link_status;

static irqreturn_t sma_msi_handler( int irq, void* dev_id )
{
    if (link_status != ffwd_mac_device_info->link)
    {
        if (ffwd_mac_device_info->link)
        {
            netif_carrier_on( sma_driver_info.net_drv->ndev );
            netif_wake_queue( sma_driver_info.net_drv->ndev );
            printk( "%s link change up ok\n", sma_driver_info.net_drv->ndev->name );
        }
        else
        {
            netif_carrier_off( sma_driver_info.net_drv->ndev );
            netif_stop_queue( sma_driver_info.net_drv->ndev );
            printk( "%s link change down ok\n", sma_driver_info.net_drv->ndev->name );
        }
        link_status = ffwd_mac_device_info->link;
    }

    if (likely(napi_schedule_prep(&sma_driver_info.net_drv->napi))) 
    {
        sma_disable_msi(sma_driver_info.pcie_drv.pdev);
        __napi_schedule(&sma_driver_info.net_drv->napi);
    }

    return IRQ_HANDLED;
}


int rx_offset = 0;
int tx_offset = 0;
int free_offset = 0;

struct sk_buff * rx_skb_ring[MAC_ENTRY_DESC_NUM];
struct sk_buff * tx_skb_ring[MAC_ENTRY_DESC_NUM];

struct page * rx_page_ring[MAC_ENTRY_DESC_NUM];
struct list_head skblist;
struct list_head free_skblist;

// 12 rx rings, each ring has MAC_ENTRY_DESC_NUM descriptors
int tlro_rx_offset[TLRO_RX_RING_COUNT];
struct sk_buff * tlro_rx_skb_ring[TLRO_RX_RING_COUNT][MAC_ENTRY_DESC_NUM];
struct page * tlro_rx_page_ring[TLRO_RX_RING_COUNT][MAC_ENTRY_DESC_NUM];

void free_skbnode(struct skbnode_s * skbnode){
	list_add_tail((struct list_head *) skbnode, &(free_skblist));
}
struct skbnode_s * get_skbnode(){
	if(free_skblist.next == &(free_skblist)){
		return kmalloc(sizeof(struct skbnode_s), GFP_ATOMIC);
	} else {
		struct list_head * tmp = free_skblist.next;
		list_del(tmp);
		return (struct skbnode_s *) tmp;
	}
}

struct sk_buff * sma_alloc_skb_buff(struct net_device* ndev)
{
    unsigned long align;
    //struct sk_buff * skb = netdev_alloc_skb(ndev, MAC_PKT_SIZE);
    struct sk_buff* skb = __dev_alloc_skb( MAC_PKT_SIZE,GFP_DMA|GFP_ATOMIC);
	if (skb)
	{
	   	skb->dev = ndev;
        if (unlikely((align = (unsigned long) skb->data & (SMA_DMA_ALIGN - 1)))) 
            skb_reserve(skb, SMA_DMA_ALIGN - align);  
	}
    return skb;
}

static inline void print_pkt(uint8_t* data, int len)
{
	int i;
 
	printk("addr %p len %d \n", data, len);
	for (i = 0; i <len; i++) {
		if ((i%4) == 0 && i !=0)
			printk(" ");
		if ((i%32) == 0 && i != 0)
			printk("\n");
		printk("%02x", data[i]);

	}
	printk("\n");
}

static int slro_proc_rx_complete(struct napi_struct * napi, int budget){
	struct net_device * ndev = napi->dev;
	struct pci_dev * pdev = sma_driver_info.pcie_drv.pdev;
	struct sk_buff * skb;
	struct sk_buff * new_skb;
	uint16_t len;
	
	int proc = 0;
	int i;
	for(i = 0;i < TLRO_RX_RING_COUNT;i++){
		while(tlro_rx_entry_desc[i][tlro_rx_offset[i]].state == FIFO_READABLE){
			int offset = tlro_rx_offset[i];
			skb = tlro_rx_skb_ring[i][offset];
			len = tlro_rx_entry_desc[i][offset].len;
			
			new_skb = sma_alloc_skb_buff(ndev);
			if(new_skb == NULL){
				panic("------------------------------------- alloc skb failed\n");
			}
			tlro_rx_skb_ring[i][offset] = new_skb;
			tlro_rx_entry_desc[i][offset].state = FIFO_WRITABLE;
			tlro_rx_entry_desc[i][offset].address = virt_to_phys((void *) new_skb->data);
			offset = (offset + 1) & (MAC_ENTRY_DESC_NUM - 1);
			tlro_rx_offset[i] = offset;
			
			skb->protocol = eth_type_trans(skb, ndev);
			netif_receive_skb(skb);
			proc++;
		}
	}
	
	return proc;
}
static int tlro_proc_rx_complete(struct napi_struct * napi, int budget){
	struct net_device * ndev = napi->dev;
	struct pci_dev * pdev = sma_driver_info.pcie_drv.pdev;
	struct sk_buff * skb;
	struct sk_buff * new_skb;
	uint16_t len;
	
	int proc = 0;
	int i;
	for(i = 0;i < TLRO_RX_RING_COUNT;i++){
		while(tlro_rx_entry_desc[i][tlro_rx_offset[i]].state == FIFO_READABLE){
			int offset = tlro_rx_offset[i];
			skb = tlro_rx_skb_ring[i][offset];
			len = tlro_rx_entry_desc[i][offset].len;
			void * page_addr = page_address(tlro_rx_page_ring[i][offset]);
			
			new_skb = __dev_alloc_skb(128, GFP_ATOMIC);
			if(new_skb == NULL){
				panic("---------------------------------- tlro rx complete: alloc skb failed\n");
			} else {
				new_skb->dev = ndev;
			}
			struct page * newpage = alloc_pages(__GFP_NOWARN | GFP_DMA32, (PAGE_SIZE == 4096) ? 4 : 3);
			if(!newpage){
				panic("----------------------------------- tlro rx complete: failed to alloc new pages\n");
			}
			tlro_rx_page_ring[i][offset] = newpage;
			tlro_rx_skb_ring[i][offset] = new_skb;
			tlro_rx_entry_desc[i][offset].state = FIFO_WRITABLE;
			tlro_rx_entry_desc[i][offset].address = virt_to_phys((void *) page_address(newpage));
			offset = (offset + 1) & (MAC_ENTRY_DESC_NUM - 1);
			tlro_rx_offset[i] = offset;
			
			// set skb for receiving
			memcpy(skb->data, page_addr, ETH_HLEN);
			skb_put(skb, ETH_HLEN);
			skb_shinfo(skb)->nr_frags = (PAGE_SIZE == 4096) ? 16 : 8;
			int count = len / PAGE_SIZE;
			int left = len % PAGE_SIZE;
			int j;
			void * start = page_addr;
			for(j = 0;j < skb_shinfo(skb)->nr_frags;j++){
				skb_shinfo(skb)->frags[j].page_offset = 0;
				skb_shinfo(skb)->frags[j].size = 0;
				skb_shinfo(skb)->frags[j].page = virt_to_page(start);
				start += PAGE_SIZE;
			}
			for(j = 0;j < count;j++){
				skb_shinfo(skb)->frags[j].size = PAGE_SIZE;
			}
			if(left){
				skb_shinfo(skb)->frags[count].size = left;
			}
			skb_shinfo(skb)->frags[0].page_offset += ETH_HLEN;
			skb_shinfo(skb)->frags[0].size -= ETH_HLEN;
			skb->len = len;
			skb->data_len = len - ETH_HLEN;
			skb->truesize += 65536;
			sma_driver_info.net_drv->stats.rx_packets++;
			skb->protocol = eth_type_trans(skb, ndev);

			//数据包传送给上传协议
			netif_receive_skb(skb);
			proc++;
		}
	}
	
	return proc;
}
static int sma_proc_rx_complete(struct napi_struct * napi, int budget){
	struct net_device * ndev = napi->dev;
	struct pci_dev * pdev = sma_driver_info.pcie_drv.pdev;
	struct sk_buff * skb;
	struct sk_buff * new_skb;
	uint16_t len;
	
	int proc = 0;
	while(proc < budget){
		if(ffwd_mac_entry_desc_rx[rx_offset].state != FIFO_READABLE){
			break;
		}
Message("rx_offset = %u, state is FIFO_READABLE\n", rx_offset);
		
		skb = rx_skb_ring[rx_offset];
		len = ffwd_mac_entry_desc_rx[rx_offset].len;
		void * page_addr = page_address(rx_page_ring[rx_offset]);
		
//		print_pkt((uint8_t *) page_addr, len);
		
		new_skb = __dev_alloc_skb(128, GFP_ATOMIC);
		if(new_skb == NULL){
			panic("--------------------------------- rx complete: alloc big skb failed!\n");
		} else {
			new_skb->dev = ndev;
		}
		struct page * newpage = alloc_pages(__GFP_NOWARN | GFP_DMA32, (PAGE_SIZE == 4096) ? 4 : 3);
		if(!newpage){
			panic("-------------------------------- failed to alloc new page\n");
		}
		rx_page_ring[rx_offset] = newpage;
		rx_skb_ring[rx_offset] = new_skb;
		ffwd_mac_entry_desc_rx[rx_offset].state = FIFO_WRITABLE;
		ffwd_mac_entry_desc_rx[rx_offset].address = virt_to_phys((void *) page_address(newpage));
		rx_offset = (rx_offset + 1) & (MAC_ENTRY_DESC_NUM - 1);
	
		// 根据len设置skb
		memcpy(skb->data, page_addr, ETH_HLEN);
		skb_put(skb, ETH_HLEN);
		skb_shinfo(skb)->nr_frags = (PAGE_SIZE == 4096) ? 16 : 8;
		int count = len / PAGE_SIZE;
		int left = len % PAGE_SIZE;
Message("PAGE_SIZE = %d, nr_frags = %d, count = %d, left = %d\n", PAGE_SIZE, skb_shinfo(skb)->nr_frags, count, left);

		int i;
		void * start = page_addr;
		for(i = 0;i < skb_shinfo(skb)->nr_frags;i++){
			skb_shinfo(skb)->frags[i].page_offset = 0;
			skb_shinfo(skb)->frags[i].size = 0;
			skb_shinfo(skb)->frags[i].page = virt_to_page(start);
			start += PAGE_SIZE;
		}
		for(i = 0;i < count;i++){
			skb_shinfo(skb)->frags[i].size = PAGE_SIZE;
		}
		if(left){
			skb_shinfo(skb)->frags[count].size = left;
		}
		skb_shinfo(skb)->frags[0].page_offset += ETH_HLEN;
		skb_shinfo(skb)->frags[0].size -= ETH_HLEN;
		skb->len = len;
		skb->data_len = len - ETH_HLEN;
		skb->truesize += 65536;
		sma_driver_info.net_drv->stats.rx_packets++;
		skb->protocol = eth_type_trans(skb, ndev);

		//数据包传送给上传协议
		netif_receive_skb(skb);
/* */
		proc++;
	}
	
	return proc;
}
//static int 
//sma_proc_rx_complete(struct napi_struct* napi,int budget)
//{
//    struct net_device* ndev = napi->dev;
//    struct pci_dev * pdev = sma_driver_info.pcie_drv.pdev;
//    struct sk_buff* skb , *new_skb;
//    dma_addr_t mapping , phys;
//    uint16_t len;
//
//    int proc = 0;
//    
//    while(proc < budget)
//    { 
//        if(ffwd_mac_entry_desc_rx[rx_offset].state != FIFO_READABLE)
//            break;
//
//        skb = rx_skb_ring[rx_offset];
//        phys = ffwd_mac_entry_desc_rx[rx_offset].address;
//        len = ffwd_mac_entry_desc_rx[rx_offset].len;
//
//        new_skb = sma_alloc_skb_buff(ndev);
//        if(new_skb == NULL)
//            panic("Alloc sk_buff faild\n");
//
//        mapping = pci_map_single(pdev, new_skb->data,
//                MAC_PKT_SIZE, PCI_DMA_FROMDEVICE);
//                
//    	if (pci_dma_mapping_error(pdev, mapping)) {
//    		dev_kfree_skb(new_skb);
//    		panic("pci_dma_mapping_error \n");
//	    }
//	    
//        rx_skb_ring[rx_offset] = new_skb;
//        pci_unmap_addr_set(&ffwd_mac_entry_desc_rx[rx_offset], address, mapping); 
//
//        wmb();
//
//        ffwd_mac_entry_desc_rx[rx_offset].state = FIFO_WRITABLE;
//        rx_offset = (rx_offset + 1 ) & (MAC_ENTRY_DESC_NUM - 1);
//        
//        pci_unmap_single(pdev, phys, MAC_PKT_SIZE, PCI_DMA_FROMDEVICE);
//		skb_put(skb, len);
//
//        sma_driver_info.net_drv->stats.rx_packets++;
//		skb->protocol = eth_type_trans(skb, ndev);
//		//数据包传送给上传协议
//		netif_receive_skb(skb);
//
//		proc++;
//    }
//
//    return proc;
//}

static int
sma_netdev_poll( struct napi_struct* napi, int budget )
{ 
    int proc = 0;
    
    //proc = sma_proc_rx_complete(napi, budget);
    //proc = tlro_proc_rx_complete(napi, budget);
    proc = slro_proc_rx_complete(napi, budget);
    if(proc < budget)
    {
        napi_complete(napi);        
    }
    sma_enable_msi(sma_driver_info.pcie_drv.pdev);

    //printk("poll pktnum = %d\n",proc);
    
    return proc;
   
}

static int sma_netdev_open( struct net_device* dev )
{
    link_status = ffwd_mac_device_info->link;
    
    if (link_status)
    {
        netif_carrier_on( sma_driver_info.net_drv->ndev );
        netif_wake_queue( sma_driver_info.net_drv->ndev );
        printk( "%s link change up ok\n", dev->name );
    }
    else
    {
        netif_carrier_off( sma_driver_info.net_drv->ndev );
        netif_stop_queue( sma_driver_info.net_drv->ndev );
        printk( "%s link change down ok\n", dev->name );
    }  

    napi_enable(&sma_driver_info.net_drv->napi);

    sma_enable_msi(sma_driver_info.pcie_drv.pdev);
    
    printk("%s : link change up ok!\n", dev->name);        		

    return 0;
}

/* netdev_tx_t (*ndo_start_xmit)(struct sk_buff *skb,
*                               struct net_device *dev);
*  Called when a packet needs to be transmitted.
*  Must return NETDEV_TX_OK , NETDEV_TX_BUSY.
*        (can also return NETDEV_TX_LOCKED iff NETIF_F_LLTX)
*  Required can not be NULL.
*/
//static netdev_tx_t sma_netdev_xmit(struct sk_buff * skb, struct net_device * dev){
//	struct pci_dev * pdev = sma_driver_info.pcie_drv.pdev;
//	while(free_offset != tx_offset){
//		Message("------------free_offset = %d\n", free_offset);
//		if(ffwd_mac_entry_desc_tx[free_offset].state != FIFO_DONE){
//			Message("-------------- state is not FIFO_DONE\n");
//			break;
//		} else {
//			Message("-------------- state is FIFO_DONE\n");
//		}
//		if(skblist.next != &(skblist)){
//			Message("------------- skblist not empty\n");
//			// skblist not empty
//			struct skbnode_s * skbnode = (struct skbnode_s *) skblist.next;
//			Message("----------- skbnode->offset = %d\n", skbnode->offset);
//			if(skbnode->offset == free_offset){
//				list_del((struct list_head *) skbnode);
//				if(skbnode->skb){
//					dev_kfree_skb_any(skbnode->skb);
//				}
//				pci_unmap_single(pdev, skbnode->address, ffwd_mac_entry_desc_tx[free_offset].len, DMA_TO_DEVICE);
//				free_skbnode(skbnode);
//				Message("freed a skbnode, free_offset = %d\n", free_offset);
//			}
//		} else {
//			Message("-------------------- empty skblist\n");
//		}
//		ffwd_mac_entry_desc_tx[free_offset].state = FIFO_WRITABLE;
//		free_offset = (free_offset + 1) & (MAC_ENTRY_DESC_NUM - 1);
//		barrier();
//	}
//	
//	if(skb->len > ETH_FRAME_LEN){
//		Message("a big packet, skb->len = %d\n", skb->len);
//		sma_driver_info.net_drv->stats.tx_errors++;
//		dev_kfree_skb_any(skb);
//		return NETDEV_TX_OK;
//	}
//	
//	if(ffwd_mac_entry_desc_tx[tx_offset].state != FIFO_WRITABLE){
//		Message("tx_offset = %u, state is not FIFO_WRITABLE\n", tx_offset);
//		sma_driver_info.net_drv->stats.tx_errors++;
//		dev_kfree_skb_any(skb);
//		return NETDEV_TX_OK;
//	}
//	wmb();
//	
//	Message("physical address of skb->data is %u\n", virt_to_phys(skb->data));
//	if(((uint32_t)virt_to_phys(skb->data)) < ((uint32_t)(1 << 24))){
//		Message("less than 16MB\n");
//	} else if(((uint32_t)virt_to_phys(skb->data)) < ((uint32_t)0xffffffff)){
//		Message("between 16MB and 4GB\n");
//	} else {
//		Message("greater or equal to 4GB\n");
//	}
//	print_pkt(skb->data, skb->len);
//	
//	if(unlikely(((unsigned long) skb->data) & (SMA_DMA_ALIGN - 1))){
//		Message("-----------------tx_offset = %u, need to use skb ring\n", tx_offset);
//		struct sk_buff * dma_skb = tx_skb_ring[tx_offset];
//		memcpy(dma_skb->data, skb->data, skb->len);
//		ffwd_mac_entry_desc_tx[tx_offset].len = skb->len;
//		ffwd_mac_entry_desc_tx[tx_offset].state = FIFO_READABLE;
//		ffwd_mac_entry_desc_tx[tx_offset].address = pci_map_single(pdev, (void *) dma_skb->data, skb->len, DMA_TO_DEVICE);
//		struct skbnode_s * skbnode = get_skbnode();
//		skbnode->skb = NULL;
//		skbnode->offset = tx_offset;
//		skbnode->address = ffwd_mac_entry_desc_tx[tx_offset].address;
//		skbnode->data_len = skb->len;
//		list_add_tail((struct list_head *) skbnode, &(skblist));
//		dev_kfree_skb_any(skb);
//	} else {
//		Message("---------------- no need to use skb ring, tx_offset = %d\n", tx_offset);
//		ffwd_mac_entry_desc_tx[tx_offset].len = skb->len;
//		ffwd_mac_entry_desc_tx[tx_offset].state = FIFO_READABLE;
//		ffwd_mac_entry_desc_tx[tx_offset].address = pci_map_single(pdev, (void *) skb->data, skb->len, DMA_TO_DEVICE);
//		struct skbnode_s * skbnode = get_skbnode();
//		skbnode->skb = skb;
//		skbnode->offset = tx_offset;
//		skbnode->address = ffwd_mac_entry_desc_tx[tx_offset].address;
//		skbnode->data_len = skb->len;
//		list_add_tail((struct list_head *) skbnode, &(skblist));
//	}
//	tx_offset = (tx_offset + 1) & (MAC_ENTRY_DESC_NUM - 1);
//	sma_driver_info.net_drv->stats.tx_packets++;
//	wmb();
//	    
//	dev->trans_start = jiffies;
//	return NETDEV_TX_OK;
//}
static netdev_tx_t sma_netdev_xmit( struct sk_buff* skb, struct net_device* dev )
{
     struct sk_buff* dma_skb;
    struct pci_dev * pdev = sma_driver_info.pcie_drv.pdev;
    
    while (free_offset != tx_offset)
    {
        if (ffwd_mac_entry_desc_tx[free_offset].state != FIFO_DONE )
            break;
        
        //pci_unmap_single( pdev, ffwd_mac_entry_desc_tx[free_offset].address, 
        //        ffwd_mac_entry_desc_tx[free_offset].len, DMA_TO_DEVICE );

        //dev_kfree_skb_any( tx_skb_ring[free_offset]);
        //tx_skb_ring[free_offset] = NULL;
        
        ffwd_mac_entry_desc_tx[free_offset].state = FIFO_WRITABLE;
        free_offset = ( free_offset + 1 ) & ( MAC_ENTRY_DESC_NUM -1 );
        barrier();
    }


    if(skb->len > ETH_FRAME_LEN)
    {
        sma_driver_info.net_drv->stats.tx_errors++;
        dev_kfree_skb_any( skb );
        return NETDEV_TX_OK;
    }
    //printk("data = %p len = %d headlen = %d \n", skb->data, 
    //                            skb->len, skb_headlen(skb));
    if(ffwd_mac_entry_desc_tx[tx_offset].state != FIFO_WRITABLE)
    {
        sma_driver_info.net_drv->stats.tx_errors++;
        dev_kfree_skb_any( skb );
        return NETDEV_TX_OK;
    }
    
	wmb();

    dma_skb = tx_skb_ring[tx_offset];
	memcpy(dma_skb->data,skb->data, skb->len);
	
	
    //tx_skb_ring[tx_offset] = skb;
    ffwd_mac_entry_desc_tx[tx_offset].len = skb->len ;
    //ffwd_mac_entry_desc_tx[tx_offset].address = 
    //    pci_map_single( pdev,(void*)skb->data,skb->len,DMA_TO_DEVICE );  
    ffwd_mac_entry_desc_tx[tx_offset].state = FIFO_READABLE;
    
    //if (pci_dma_mapping_error(pdev, ffwd_mac_entry_desc_tx[tx_offset].address)) 
    //    panic("pci_dma_mapping_error :Phys[%08x]\n",ffwd_mac_entry_desc_tx[tx_offset].address);
    //printk("bus address = %08x phys address = %08x\n",ffwd_mac_entry_desc_tx[tx_offset].address,virt_to_phys((void*)dma_skb->data));
    dev_kfree_skb_any(skb);     
    tx_offset = (tx_offset + 1) & (MAC_ENTRY_DESC_NUM - 1);
    //print_pkt(dma_skb->data,dma_skb->len);
    
    sma_driver_info.net_drv->stats.tx_packets++;
    wmb();
    
    dev->trans_start = jiffies;
    return NETDEV_TX_OK;
}

static int sma_netdev_close( struct net_device* dev )
{
    sma_disable_msi(sma_driver_info.pcie_drv.pdev);
    netif_carrier_off(dev);
    
    napi_disable(&sma_driver_info.net_drv->napi);

    netif_stop_queue( dev );
    
    return 0;
}


static struct net_device_stats * sma_netdev_get_stats(struct net_device* dev)
{
    return &sma_driver_info.net_drv->stats;

}

static void sma_set_multicast_list( struct net_device* netdev )
{
    if (netdev->flags & IFF_PROMISC)
    {
        ffwd_mac_device_info->promisc = 1;
    }
    else
    {
        ffwd_mac_device_info->promisc = 0;
    }    
}


static int sma_netdev_change_mtu(struct net_device* netdev, int new_mtu)
{
    DPRINTK(DEBUG, "not support ndo_change_mtu\r\n");
    return 0;
}



static void sma_netdev_timeout(struct net_device* dev)
{
    DPRINTK(DEBUG, "not support ndo_tx_timeout");
}

static const struct net_device_ops sma_netdev_ops =
{
  .ndo_open = sma_netdev_open,
  .ndo_stop = sma_netdev_close,
  .ndo_start_xmit = sma_netdev_xmit,
  .ndo_get_stats = sma_netdev_get_stats,
  .ndo_tx_timeout = sma_netdev_timeout,
  .ndo_set_multicast_list = sma_set_multicast_list,
  .ndo_change_mtu = sma_netdev_change_mtu
};

int slro_netdev_init_skb_pool(){
	struct net_device * ndev = sma_driver_info.net_drv->ndev;
	struct pci_dev * pdev = sma_driver_info.pcie_drv.pdev;
	struct sk_buff * skb = NULL;
	int i;
	int j;
	// alloc tx skbuffs
	for(i = 0;i < MAC_ENTRY_DESC_NUM;i++){
		skb = sma_alloc_skb_buff(ndev);
		if(skb == NULL){
			panic("------------------------------------- alloc skb failed\n");
		}
		tx_skb_ring[i] = skb;
		ffwd_mac_entry_desc_tx[i].state = FIFO_WRITABLE;
		ffwd_mac_entry_desc_tx[i].address = pci_map_single(pdev, (void *) skb->data, MAC_PKT_SIZE, DMA_TO_DEVICE);
	}
	// alloc rx skbuffs
	// alloc rx skbuffs and pages
	for(i = 0;i < TLRO_RX_RING_COUNT;i++){
		for(j = 0;j < MAC_ENTRY_DESC_NUM;j++){
			tlro_rx_skb_ring[i][j] = NULL;
			tlro_rx_page_ring[i][j] = NULL;
		}
	}
	for(i = 0;i < TLRO_RX_RING_COUNT;i++){
		for(j = 0;j < MAC_ENTRY_DESC_NUM;j++){
			skb = sma_alloc_skb_buff(ndev);
			if(skb == NULL){
				panic("------------------------------------- alloc skb failed\n");
			}
			tlro_rx_skb_ring[i][j] = skb;
			tlro_rx_entry_desc[i][j].state = FIFO_WRITABLE;
			tlro_rx_entry_desc[i][j].address = virt_to_phys((void *) skb->data);
		}
	}
}
int tlro_netdev_init_skb_pool(){
	Message("------------------------- PAGE_SIZE = %d\n", PAGE_SIZE);
	struct net_device * ndev = sma_driver_info.net_drv->ndev;
	struct pci_dev * pdev = sma_driver_info.pcie_drv.pdev;
	
	int pagecount = 0;
	int skbcount = 0;
	struct sk_buff * skb = NULL;
	struct page * newpage = NULL;
	int i;
	int j;
	// alloc tx skbuffs
	for(i = 0;i < MAC_ENTRY_DESC_NUM;i++){
		skb = sma_alloc_skb_buff(ndev);
		if(skb == NULL){
			panic("------------------------------------- alloc skb failed\n");
		}
		tx_skb_ring[i] = skb;
		ffwd_mac_entry_desc_tx[i].state = FIFO_WRITABLE;
		ffwd_mac_entry_desc_tx[i].address = pci_map_single(pdev, (void *) skb->data, MAC_PKT_SIZE, DMA_TO_DEVICE);
	}
	// alloc rx skbuffs and pages
	for(i = 0;i < TLRO_RX_RING_COUNT;i++){
		for(j = 0;j < MAC_ENTRY_DESC_NUM;j++){
			tlro_rx_skb_ring[i][j] = NULL;
			tlro_rx_page_ring[i][j] = NULL;
		}
	}
	for(i = 0;i < TLRO_RX_RING_COUNT;i++){
		for(j = 0;j < MAC_ENTRY_DESC_NUM;j++){
			skb = __dev_alloc_skb(128, GFP_ATOMIC);
			if(skb == NULL){
				panic("---------------------------------------------------alloc big skb failed\n");
			} else {
				skb->dev = ndev;
				skbcount++;
			}
			struct page * newpage = alloc_pages(__GFP_NOWARN | GFP_DMA32, (PAGE_SIZE == 4096) ? 4 : 3);
			if(!newpage){
				panic("-------------------------------------------- failed to alloc page\n");
			} else {
				pagecount++;
			}
			tlro_rx_page_ring[i][j] = newpage;
			tlro_rx_skb_ring[i][j] = skb;
			tlro_rx_entry_desc[i][j].state = FIFO_WRITABLE;
			tlro_rx_entry_desc[i][j].address = virt_to_phys((void *) page_address(newpage));
		}
	}
	
	Message("skbcount = %d, page_count = %d\n", skbcount, pagecount);
	return 0;
}
//int sma_netdev_init_skb_pool(){
//	Message("------------------------ PAGE_SIZE = %d\n", PAGE_SIZE);
//	int i;
//	struct sk_buff * skb;
//	struct net_device * ndev = sma_driver_info.net_drv->ndev;
//	struct pci_dev * pdev = sma_driver_info.pcie_drv.pdev;
//	
//	int pagecount = 0;
//	int skbcount = 0;
//	for(i = 0;i < MAC_ENTRY_DESC_NUM;i++){
//		skb = __dev_alloc_skb(128, GFP_ATOMIC);
//		if(skb == NULL){
//			panic("---------------------------------------------------alloc big skb failed\n");
//		} else {
//			skb->dev = ndev;
//			skbcount++;
//		}
//		struct page * newpage = alloc_pages(__GFP_NOWARN | GFP_DMA32, (PAGE_SIZE == 4096) ? 4 : 3);
//		if(!newpage){
//			panic("-------------------------------------------- failed to alloc page\n");
//		} else {
//			pagecount++;
//		}
//		rx_page_ring[i] = newpage;
//		rx_skb_ring[i] = skb;
//		ffwd_mac_entry_desc_rx[i].state = FIFO_WRITABLE;
//		ffwd_mac_entry_desc_rx[i].address = virt_to_phys((void *) page_address(newpage));
//		
//		skb = sma_alloc_skb_buff(ndev);
//		if(skb == NULL){
//			panic("------------------------------------- alloc skb failed\n");
//		}
//		tx_skb_ring[i] = skb;
//		ffwd_mac_entry_desc_tx[i].state = FIFO_WRITABLE;
//		ffwd_mac_entry_desc_tx[i].address = pci_map_single(pdev, (void *) skb->data, MAC_PKT_SIZE, DMA_TO_DEVICE);
//	}
//	Message("skbcount = %d, pagecount = %d\n", skbcount, pagecount);
//	return 0;
//}
//int sma_netdev_init_skb_pool(void)
//{
//    int i;
//    struct sk_buff* skb;
//    struct net_device* ndev = sma_driver_info.net_drv->ndev;
//    struct pci_dev *pdev = sma_driver_info.pcie_drv.pdev;
//    for(i = 0; i < MAC_ENTRY_DESC_NUM; i++ )
//    {
//        skb = sma_alloc_skb_buff(ndev);
//        if(skb == NULL)
//            panic("Alloc sk_buff faild\n");
//            
//        rx_skb_ring[i] = skb;
//        ffwd_mac_entry_desc_rx[i].state = FIFO_WRITABLE;
//        ffwd_mac_entry_desc_rx[i].address = 
//            pci_map_single(pdev,( void * ) skb->data,MAC_PKT_SIZE,DMA_FROM_DEVICE );  
//
//        skb = sma_alloc_skb_buff(ndev);
//        if(skb == NULL)
//            panic("Alloc sk_buff faild\n");
//        tx_skb_ring[i] = skb ;
//        ffwd_mac_entry_desc_tx[i].state = FIFO_WRITABLE;   
//        ffwd_mac_entry_desc_tx[i].address = 
//            pci_map_single(pdev,( void * ) skb->data,MAC_PKT_SIZE,DMA_TO_DEVICE );  
//        
//    }
//
//    
//    return 0;
//}

int slro_netdev_free_skb_pool(){
	struct net_device * ndev = sma_driver_info.net_drv->ndev;
	struct pci_dev * pdev = sma_driver_info.pcie_drv.pdev;
	
	// free tx skbuffs
	int i = 0;
	for(i = 0;i < MAC_ENTRY_DESC_NUM;i++){
		if(tx_skb_ring[i]){
			pci_unmap_single(pdev, ffwd_mac_entry_desc_tx[i].address, MAC_PKT_SIZE, DMA_TO_DEVICE);
			dev_kfree_skb_any(tx_skb_ring[i]);
		}
	}
	// free rx skbuffs and pages
	int j;
	for(i = 0;i < TLRO_RX_RING_COUNT;i++){
		for(j = 0;j < MAC_ENTRY_DESC_NUM;j++){
			if(tlro_rx_skb_ring[i][j]){
				dev_kfree_skb_any(tlro_rx_skb_ring[i][j]);
			}
		}
	}
}
int tlro_netdev_free_skb_pool(){
	struct net_device * ndev = sma_driver_info.net_drv->ndev;
	struct pci_dev * pdev = sma_driver_info.pcie_drv.pdev;
	
	// free tx skbuffs
	int i = 0;
	for(i = 0;i < MAC_ENTRY_DESC_NUM;i++){
		if(tx_skb_ring[i]){
			pci_unmap_single(pdev, ffwd_mac_entry_desc_tx[i].address, MAC_PKT_SIZE, DMA_TO_DEVICE);
			dev_kfree_skb_any(tx_skb_ring[i]);
		}
	}
	// free rx skbuffs and pages
	int j;
	for(i = 0;i < TLRO_RX_RING_COUNT;i++){
		for(j = 0;j < MAC_ENTRY_DESC_NUM;j++){
			if(tlro_rx_skb_ring[i][j]){
				dev_kfree_skb_any(tlro_rx_skb_ring[i][j]);
			}
			if(tlro_rx_page_ring[i][j]){
				__free_pages(tlro_rx_page_ring[i][j], PAGE_SIZE == 4096 ? 4 : 3);
			}
		}
	}
}
//int sma_netdev_free_skb_pool(void)
//{
//    int i;
//    struct sk_buff* skb;
//    struct net_device* ndev = sma_driver_info.net_drv->ndev;
//    struct pci_dev *pdev = sma_driver_info.pcie_drv.pdev;
//    for(i = 0; i < MAC_ENTRY_DESC_NUM; i++ )
//    {
//        if(rx_skb_ring[i])
//        {
//            pci_unmap_single( pdev, ffwd_mac_entry_desc_rx[i].address, 
//                    MAC_PKT_SIZE, DMA_FROM_DEVICE );
//            dev_kfree_skb_any( rx_skb_ring[i]);
//        }
//        if(tx_skb_ring[i])
//        {
//            pci_unmap_single( pdev, ffwd_mac_entry_desc_tx[i].address, 
//                    MAC_PKT_SIZE, DMA_TO_DEVICE );
//                    
//            dev_kfree_skb_any( tx_skb_ring[i]);
//        }
//    }
//    return 0;
//}


int sma_netdev_init( sma_driver_info_t * driver_info )
{
    int ret = 0;
    sma_net_drv_info_t * net_drv;
    struct net_device* ndev;
    struct pci_dev * pdev;

    pdev = driver_info->pcie_drv.pdev;
    ndev = alloc_etherdev(sizeof(sma_net_drv_info_t));
    if (ndev == NULL)
    {
        DPRINTK(ERR, "Alloc etherdev faild\n" );
        return -1;
    }
    
    net_drv = netdev_priv(ndev);
    driver_info->net_drv = net_drv;

    net_drv->port = 0;
    net_drv->ndev = ndev;
    
    ndev->features &= ~NETIF_F_HIGHDMA;
    ndev->features |= (NETIF_F_IP_CSUM | NETIF_F_NO_CSUM | NETIF_F_HW_CSUM);
    Message("-----------------------------------------------------------------NETIF_F_HIGHDMA bit not set\n");
    strncpy( ndev->name, "sma0", 8 );
    ndev->watchdog_timeo = timeout;
    
    netif_napi_add( ndev, &net_drv->napi, sma_netdev_poll, 64 );
    ndev->netdev_ops = &sma_netdev_ops;
    
    ndev->dev_addr[0] = ffwd_mac_device_info->mac_addr[0];
    ndev->dev_addr[1] = ffwd_mac_device_info->mac_addr[1];
    ndev->dev_addr[2] = ffwd_mac_device_info->mac_addr[2];
    ndev->dev_addr[3] = ffwd_mac_device_info->mac_addr[3];
    ndev->dev_addr[4] = ffwd_mac_device_info->mac_addr[4];
    ndev->dev_addr[5] = ffwd_mac_device_info->mac_addr[5];

    if(register_netdev(ndev))
    {
        DPRINTK(ERR, "Register_netdev faild err %d\n",ret);
        goto free_net_dev;
    } 

    DPRINTK(DEBUG, "register_netdev ok\n" );
    
    if(request_irq(pdev->irq, sma_msi_handler, 0, "sma_pcie", (void *)pdev))
    {
        DPRINTK(ERR, "Request_irq: failed with err %d\n", ret );
        goto free_unregister_netdev;
    }
    
    DPRINTK(DEBUG, "request msi irq ok %d \n",  pdev->irq);

    //sma_netdev_init_skb_pool();
    //tlro_netdev_init_skb_pool();
    slro_netdev_init_skb_pool();
    
    DPRINTK(DEBUG, "Netdevice %s init ok\n", ndev->name );
    
    
    skblist.prev = skblist.next = &(skblist);
    free_skblist.prev = free_skblist.next = &(free_skblist);
    return 0;       

free_unregister_netdev:
    unregister_netdev(ndev);
free_net_dev:
    free_netdev(ndev);

    return -1;
}

void sma_netdev_release( sma_driver_info_t * driver_info )
{
    //sma_netdev_free_skb_pool();
	//tlro_netdev_free_skb_pool();
	slro_netdev_free_skb_pool();

    sma_disable_msi(sma_driver_info.pcie_drv.pdev);
    
    free_irq(driver_info->pcie_drv.pdev->irq, driver_info->pcie_drv.pdev);

    unregister_netdev(driver_info->net_drv->ndev);

    free_netdev(driver_info->net_drv->ndev);
    
    DPRINTK(ERR, "free_netdev\r\n" );
}

