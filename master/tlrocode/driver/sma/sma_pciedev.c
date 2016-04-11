#include "sma_driver.h"

sma_driver_info_t sma_driver_info;

ffwd_dma_queue_t * ffwd_dma_queue = NULL;
ffwd_counter_info_t * ffwd_counter_info = NULL;
ffwd_device_info_t * ffwd_device_info = NULL;
entry_state_desc_t * ffwd_session_state_base = NULL;
entry_state_desc_t * ffwd_udp_state_base = NULL;
ffwd_mac_entry_desc_t * ffwd_mac_entry_desc_rx = NULL;
ffwd_mac_entry_desc_t * ffwd_mac_entry_desc_tx = NULL;
ffwd_mac_device_info_t * ffwd_mac_device_info = NULL;
ffwd_mac_counter_t * ffwd_mac_counter = NULL;

// 12 rx rings
ffwd_mac_entry_desc_t * tlro_rx_entry_desc[TLRO_RX_RING_COUNT];

static struct pci_device_id nca_id_table[] =
{
  {NCA_VENDOR_ID, NCA_DEVICE_ID, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 }, {0,}
};

void sma_xaui_open(ffwd_device_info_t * device_info)
{
    device_info->cmd_type = CMD_XAUI_OPEN;
    device_info->cmd_state = CMD_STATE_NEW;
    while(device_info->cmd_state == CMD_STATE_DONE);
    DPRINTK(DEBUG,"XAUI Interface Open\n");   
}

void sma_xaui_close(ffwd_device_info_t * device_info)
{
    device_info->cmd_type = CMD_XAUI_CLOSE;
    device_info->cmd_state = CMD_STATE_NEW;
    while(device_info->cmd_state == CMD_STATE_DONE);
    msleep(3000);
    
    DPRINTK(DEBUG,"XAUI Interface Close\n");   
}


int sma_pcie_init(struct pci_dev * pdev , sma_driver_info_t * driver_info)
{
    uint32_t val;
    int err;
    sma_pcie_drv_info_t * pci_drv = &driver_info->pcie_drv;
    
    pci_drv->pdev= pdev;
    if(err = pci_enable_device(pdev))
    {
        DPRINTK(ERR,"Enable PCI device faild.\n");
        return -1;
    }

    DPRINTK(DEBUG,"Enable PCI device .\n");
        
    if (!(pci_resource_flags(pdev, 0) & IORESOURCE_MEM ))
    {
        DPRINTK(ERR,"Find PCI device base address BAR 0 faild.\n");
        goto disable_pci_region;
    }     
    
    err = pci_request_regions(pdev, NCA_PCIE_DRIVER);//申请内存资源
    if (err)
    {
        DPRINTK(ERR,"Request PCI resource faild.\n");
        goto disable_pci_region;
    }
    
    DPRINTK(DEBUG,"Request Regions .\n");
    
    pci_set_master( pdev );//设置为总线主DMA
    pci_write_config_byte( pdev, 0x3d, 0x00 );
    pci_read_config_byte( pdev, 0x3d, &val );
    pci_write_config_byte( pdev, 0x05, 0x04 );
    pci_read_config_byte( pdev, 0x05, &val );
    
    err = pci_find_capability(pdev,PCI_CAP_ID_MSI);
    if (!err)
    {
        //查找能力表
        DPRINTK(ERR,"Not Suppoted MSI capable\n" );
        goto free_pci_region;
    }
    
    if (pci_enable_msi(pdev))
    {
        DPRINTK(ERR,"Enable MSI capable Faild\n" );
        goto free_pci_region;
    }
    
    DPRINTK( DEBUG ,"Device is MSI capable irq: %d\n", pdev->irq );
    
    if (pci_set_mwi(pdev))
    {
        DPRINTK(ERR,"Set MWI faild.\n");
        goto free_disable_msi;
    }
    
    pci_drv->shm_phys_addr = pci_resource_start( pdev, 0 );//获取内存资源 bar 0
    pci_drv->shm_virt_addr = ioremap_nocache( 
                    pci_drv->shm_phys_addr ,pci_resource_len( pdev,0 ) );
    
    if(pci_drv->shm_virt_addr == NULL)
    {
        DPRINTK(ERR,"ioremap_nocahe faild.\n");
        goto free_disable_msi;
    }
    
    if(pci_set_dma_mask(pdev, DMA_BIT_MASK(32)))
    {
        DPRINTK(ERR,"Set DMA Mask 32 Failed.\n");
        goto free_io_mem;
    }
    
    DPRINTK(DEBUG,"shm_phys_addr =  %p\n",(void*)pci_drv->shm_phys_addr);
    DPRINTK(DEBUG,"shm_virt_addr =  %p\n", pci_drv->shm_virt_addr);
    DPRINTK(DEBUG,"shm_size =  %lx\n",pci_resource_len( pdev, 0));
    
    return 0;
        
free_io_mem:
    iounmap(pci_drv->shm_virt_addr);
free_disable_msi:
    pci_disable_msi(pdev);
free_pci_region:   
    pci_release_regions(pdev);
disable_pci_region:   
    pci_disable_device(pdev); 

    pci_set_drvdata(pdev, NULL );

    return -1;
}

void sma_pcie_release(sma_driver_info_t * driver_info)
{
    sma_pcie_drv_info_t * pci_drv = &driver_info->pcie_drv;
    
    iounmap(pci_drv->shm_virt_addr); 

    pci_disable_msi(pci_drv->pdev);

    pci_set_drvdata( pci_drv->pdev, NULL );

    pci_release_regions( pci_drv->pdev ); 

    pci_disable_device( pci_drv->pdev );

    DPRINTK(DEBUG,"Release PCIE device\n");     
}

// 12 rx rings, each rx ring has MAC_ENTRY_DESC_NUM descriptors
int tlro_share_mem_init(void * mem, int size){
    uint8_t * start = mem;	
    
	ffwd_device_info = (ffwd_device_info_t*)start;
	DPRINTK(DEBUG,"ffwd_device_info :%p size %d\n", ffwd_device_info, sizeof(ffwd_device_info_t));
	start += sizeof(ffwd_device_info_t);

//	ffwd_dma_queue = (ffwd_dma_queue_t *)start;
//	DPRINTK(DEBUG,"ffwd_dma_queue :%p size %d\n", ffwd_dma_queue, sizeof(ffwd_dma_queue_t) * MAX_NUM_RX_CHANNELS);
//	start += sizeof(ffwd_dma_queue_t) * MAX_NUM_RX_CHANNELS;
	
	ffwd_counter_info = (ffwd_counter_info_t *)start;
	DPRINTK(DEBUG,"ffwd_counter_info : %p size %d sizeof(ffwd_counter_info_t) %d \n",
			ffwd_counter_info, sizeof(ffwd_counter_info_t)*MAXNUM_VCPUS, sizeof(ffwd_counter_info_t));
	start += sizeof(ffwd_counter_info_t)*MAXNUM_VCPUS;
	
	// 12 rx rings
	int i;
	for(i = 0;i < TLRO_RX_RING_COUNT; i++){
		tlro_rx_entry_desc[i] = (ffwd_mac_entry_desc_t *) start;
		start += sizeof(ffwd_mac_entry_desc_t) * MAC_ENTRY_DESC_NUM;
	}
	

	ffwd_mac_entry_desc_rx = (ffwd_mac_entry_desc_t *) start;
	//start += sizeof(ffwd_mac_entry_desc_t) * MAC_ENTRY_DESC_NUM;

    ffwd_mac_entry_desc_tx = (ffwd_mac_entry_desc_t *)start;
    start += sizeof(ffwd_mac_entry_desc_t) * MAC_ENTRY_DESC_NUM;  
    
    ffwd_mac_device_info = (ffwd_mac_device_info_t *)start;
    start += sizeof(ffwd_mac_device_info_t); 

    ffwd_mac_counter = (ffwd_mac_counter_t *)start;
    start += sizeof(ffwd_mac_counter_t); 
    
    if(start > mem + size){
        //DPRINTK(DEBUG,"PCIE Mem Out of Range Start = %p End = %p\n",start, mem+size );
    	Message("pcie shared mem out of range, start now is %p ,end = %p\n", start, mem + size);
    }
    
    return 0;
}
int sma_share_mem_init(void * mem, int size)
{
    uint8_t * start = mem;	
    
	ffwd_device_info = (ffwd_device_info_t*)start;
	DPRINTK(DEBUG,"ffwd_device_info :%p size %d\n", ffwd_device_info, sizeof(ffwd_device_info_t));
	start += sizeof(ffwd_device_info_t);

//	ffwd_dma_queue = (ffwd_dma_queue_t *)start;
//	DPRINTK(DEBUG,"ffwd_dma_queue :%p size %d\n", ffwd_dma_queue, sizeof(ffwd_dma_queue_t) * MAX_NUM_RX_CHANNELS);
//	start += sizeof(ffwd_dma_queue_t) * MAX_NUM_RX_CHANNELS;
	
	ffwd_counter_info = (ffwd_counter_info_t *)start;
	DPRINTK(DEBUG,"ffwd_counter_info : %p size %d sizeof(ffwd_counter_info_t) %d \n",
			ffwd_counter_info, sizeof(ffwd_counter_info_t)*MAXNUM_VCPUS, sizeof(ffwd_counter_info_t));
	start += sizeof(ffwd_counter_info_t)*MAXNUM_VCPUS;

//    //TCP 会话报文dma     buff 状态表
//	ffwd_session_state_base = (entry_state_desc_t*)start;
//	DPRINTK(DEBUG,"ffwd_session_state_base :%p size %d\n", 
//		ffwd_session_state_base, sizeof(entry_state_desc_t) * MAXNUM_SESSION_ENTRY * MAX_NUM_SESSION_CHANNELS);
//	start += sizeof(entry_state_desc_t) * MAXNUM_SESSION_ENTRY * MAX_NUM_SESSION_CHANNELS;
//
//    //UDP 报文dma     buff 状态表
//	ffwd_udp_state_base = (entry_state_desc_t*)start;
//	DPRINTK(DEBUG,"ffwd_udp_state_base :%p size %d\n", 
//		ffwd_udp_state_base, sizeof(entry_state_desc_t) * MAXNUM_UDP_ENTRY );
//		
//	start += sizeof(entry_state_desc_t) * MAXNUM_UDP_ENTRY;

    ffwd_mac_entry_desc_rx = (ffwd_mac_entry_desc_t *)start;
    start += sizeof(ffwd_mac_entry_desc_t) * MAC_ENTRY_DESC_NUM;
    
    ffwd_mac_entry_desc_tx = (ffwd_mac_entry_desc_t *)start;
    start += sizeof(ffwd_mac_entry_desc_t) * MAC_ENTRY_DESC_NUM;  
    
    ffwd_mac_device_info = (ffwd_mac_device_info_t *)start;
    start += sizeof(ffwd_mac_device_info_t); 

    ffwd_mac_counter = (ffwd_mac_counter_t *)start;
    start += sizeof(ffwd_mac_counter_t); 
    
    if(start > mem + size)
        DPRINTK(DEBUG,"PCIE Mem Out of Range Start = %p End = %p\n",start, mem+size );
    
    return 0;
}

static int sma_pcie_probe( struct pci_dev* pdev, const struct pci_device_id* id )
{
    // 初始化PCIE 
    if(sma_pcie_init(pdev, &sma_driver_info) < 0)
        return -ENOMEM;
    
    // PCIE 内存划分
    //sma_share_mem_init(sma_driver_info.pcie_drv.shm_virt_addr,SMA_PCI_MEM_LEN);
    tlro_share_mem_init(sma_driver_info.pcie_drv.shm_virt_addr, SMA_PCI_MEM_LEN);


    // 初始化字符设备驱动
    if(sma_cdev_init(&sma_driver_info) < 0)
        goto release_pcie;
  
    if(sma_netdev_init(&sma_driver_info) < 0)
        goto release_cdev;

    // 打开网络接口
    sma_xaui_open(ffwd_device_info);
    
    DPRINTK(DEBUG,"sma driver install.\n");
    return 0;
    
release_cdev:
    sma_cdev_release(&sma_driver_info);
release_pcie:
    sma_pcie_release(&sma_driver_info);

    return -ENOMEM;
}

static void sma_pcie_remove( struct pci_dev* pdev )
{
    sma_xaui_close(ffwd_device_info);

    sma_netdev_release(&sma_driver_info);
    
    sma_cdev_release(&sma_driver_info);

    sma_pcie_release(&sma_driver_info);

    DPRINTK(DEBUG,"sma driver rmove.\n");
}

static struct pci_driver sma_pcie_driver =
{
  .name = NCA_PCIE_DRIVER,
  .id_table = nca_id_table,
  .probe = sma_pcie_probe,
  .remove = sma_pcie_remove,
};


int __init sma_init( void )
{
    return pci_register_driver( &sma_pcie_driver );
}

void __exit sma_exit( void )
{
    pci_unregister_driver( &sma_pcie_driver );
}


module_init( sma_init );
module_exit( sma_exit );

MODULE_LICENSE( "GPL" );

