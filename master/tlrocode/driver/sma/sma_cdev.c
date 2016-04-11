#include "sma_driver.h"

#define FRAME_SIZE_4MB  (1 <<22 ) 
#define NLM_SCRATCH_PAGE_SIZE (2 * 1024 * 1024)
#define NLM_MIN_ALLOC_SIZE (2 * 1024 * 1024)

#define NCA_CHRDEV_MAJOR 0
#define NCA_NR_DEVS 1    /* nca0 through nca3 */

static int sma_major = NCA_CHRDEV_MAJOR;
static int sma_nr_devs = NCA_NR_DEVS;
static dev_t devno;

module_param( sma_major, int, S_IRUGO );
module_param( sma_nr_devs, int, S_IRUGO );

struct mem_desc
{
    struct mem_desc* next;
    int npages;
};

static int
compare_addresses( const void* a, const void* b )
{
    return *( long * ) a - *( long * ) b;
}

static struct mem_desc*
insert_into_sorted_list( struct mem_desc* list_head, struct mem_desc* element )
{
//    struct mem_desc* prev, * cur;
//
//    if ( !list_head )
//    {
//        return element;
//    }
//
//    prev = NULL;
//    cur = list_head;
//    while ( cur )
//    {
//        if ( element->npages > cur->npages )
//        {
//            if ( prev )
//            {
//                prev->next = element;
//                element->next = cur;
//                return list_head;
//            }
//            else
//            {
//                element->next = cur;
//                return element;
//            }
//        }
//        prev = cur;
//        cur = cur->next;
//    }
//
//    prev->next = element;
//    element->next = NULL;
//    return list_head;
	
	return NULL;
}

static void sma_release_chunks( struct mem_desc* list )
{
//    while ( list )
//    {
//        struct mem_desc* temp = list->next;
//        int i, max;
//        uint64_t page;
//
//        /*NLM_VERB (": Freeing chunk 0x%lx, npages %d \n", (uint64_t)virt_to_phys ((void *)list), list->npages);*/
//        max = list->npages;
//        page = ( uint64_t ) virt_to_phys( list );
//
//        for ( i = 0; i < max; i++ )
//        {
//            free_pages( ( uint64_t ) phys_to_virt( page ) , get_order( FRAME_SIZE_4MB) );   
//            page += FRAME_SIZE_4MB;
//        }
//
//        list = temp;
//    }
}

static int sma_alloc_chunks( struct mem_desc** result , int block_num , int block_size)
{
//    uint64_t* page_table, memory, prev, start;
//    int max_index, npages;
//    int i, j, frame_cnt_old = 0, frame_cnt_new = 0, all_blocks = 0;
//    int page_threshold, total_pages_alloced, total_pages_rec;
//    struct mem_desc* good_list, * free_list;
//
//    *result = NULL;
//    //分配2MB 用做页表. 为什么只分配2MB做页表？有大小限制么？
//    page_table = ( uint64_t * )
//                 __get_free_pages( __GFP_NOWARN,
//                                   get_order( NLM_SCRATCH_PAGE_SIZE ) );
//    if ( !page_table )
//    {
//        return -ENOMEM;
//    }
//    
//    free_list = NULL;
//    good_list = NULL;
//    total_pages_alloced = 0;
//    total_pages_rec = 0;
//
//restart : 
//
//    memset( page_table, 0, NLM_SCRATCH_PAGE_SIZE );
//    //2MB 内存能存放的最大索引数量(256K)
//    max_index = NLM_SCRATCH_PAGE_SIZE / sizeof( uint64_t );
//
//    /* We will ignore any contigious chunks below 4 MB */
//    //2M/4K = 512
//    page_threshold = ( NLM_MIN_ALLOC_SIZE ) / PAGE_SIZE;
//
//    //分配256K 个页面
//    for ( i = 0; i < max_index; i++ )
//    {
//        memory = __get_free_pages( __GFP_NOWARN | GFP_DMA32, 10);
//        if ( !memory )
//        {
//            break;
//        }
//
//        total_pages_alloced++;
//        page_table[i] = virt_to_phys( ( void * ) memory );
//    } 
//
//    /* sort the 4MB pages' address. */
//    sort( page_table, i, sizeof( uint64_t ), compare_addresses, NULL );
//
//    /* check the continuity. */
//    start = prev = page_table[0];
//    npages = 0;
//    for ( j = 1; j <= i; j++ )
//    {
//        memory = page_table[j];
//        /* if the required blocks are get, then insert the last to the free_list. */
//        if (( ( prev + FRAME_SIZE_4MB) == memory ) && (all_blocks != block_num))
//        {
//            npages++;
//            prev = memory;
//        }
//        else
//        {
//            /* If npages is below our threshold, put the set of
//               pages into a free list */
//            //出现不连续的内存页面
//
//            if ( npages < page_threshold ) //page_threshold = 512
//            {
//                struct mem_desc* segment = ( struct mem_desc* )
//                                           phys_to_virt( start );
//                segment->next = free_list;
//                /* npages indicates that this segment has 'npages' page. */
//                segment->npages = ++npages;
//                free_list = segment;
//            }
//            //DPRINTK(ERR,"insert the list to free. free_list(0x%x)", free_list);
//
//            prev = start = memory;
//            npages = 0;
//        }       
//
//        /* get a block of continous memory of 64MB. insert it into the good_list. */
//        if (((block_size/FRAME_SIZE_4MB) == npages))
//        {
//            ++frame_cnt_new;
//            struct mem_desc* segment = ( struct mem_desc* )(phys_to_virt( start ));
//            segment->next = NULL;
//            segment->npages = npages;
//            good_list = insert_into_sorted_list( good_list, segment );
//            prev = start = memory;
//            npages = 0;
//            ++all_blocks;
//        }
//    }
//
//    /* 看good_list和free_list中的page个数与总的分配个数是否一致，不一致则返回错误。 */
//    /* We have exhausted the whole RAM, lets see what we got */
//    {
//        struct mem_desc* ptr = good_list;
//        while ( ptr )
//        {
//            total_pages_rec += ptr->npages;
//            /*
//            DPRINTK(DEBUG,  ": Good chunk phys:0x%lx, vir:0x%lx ,npages %d\n",
//                     ( uint64_t ) virt_to_phys( ptr ),
//                     ( uint64_t ) ptr,
//                     ptr->npages );*/
//            ptr = ptr->next;
//        }
//        ptr = free_list;
//        while ( ptr )
//        {
//            total_pages_rec += ptr->npages;
//            ptr = ptr->next;
//        }
//        sma_release_chunks( free_list );
//        free_list = NULL;
//        if (all_blocks != block_num)
//        {
//            sma_release_chunks( good_list );
//            DPRINTK(ERR,"There is not enough memory for sma. all_blocks(%d)\n", all_blocks);
//            return -ENOMEM;
//        }
//    }
//
//    if ( total_pages_alloced != total_pages_rec)
//    {
//        DPRINTK(ERR,": Total pages allocated %d, manipulated %d do not match\n",
//                 total_pages_alloced,
//                 total_pages_rec );
//        return -EFAULT;
//    }
//    
//    DPRINTK(DEBUG,": Total pages allocated %d\n",
//             total_pages_alloced);
//
//    free_pages( ( uint64_t ) page_table, get_order( NLM_SCRATCH_PAGE_SIZE ) );
//    *result = good_list;
//    return 0;
	
	return 0;
}

void sma_huge_page_free(void *mem , int block_num , int block_size )
{
//    int i ,j, k;
//    uint64_t page ,phys_base;
//    
//    for ( i = 0; i < block_num; i++ )
//    {
//        phys_base = sma_driver_info.cdev_drv.huge_page[i];
//        for (j = 0; j < block_size/FRAME_SIZE_4MB; j++)
//        {
//            page = phys_base;
//            for (k = 0; k < FRAME_SIZE_4MB / PAGE_SIZE ; k++)
//            {
//                ClearPageReserved( virt_to_page( phys_to_virt( page) ) );           
//                page += PAGE_SIZE;
//            }
//            free_pages( ( uint64_t ) phys_to_virt( phys_base ) , get_order( FRAME_SIZE_4MB) );   
//            phys_base += FRAME_SIZE_4MB;
//        }
//        
//    }
}

int sma_huge_page_alloc( void *mem , int block_num , int block_size)
{
//    int i , j;
//    struct mem_desc* chunklist = NULL;
//
//    //分配64M连续内存块
//    if(sma_alloc_chunks(&chunklist, block_num, block_size))
//    {
//        sma_release_chunks(chunklist);
//        return -1;
//    }
//  
//    //Reserver Page     
//    for(i = 0; i < block_num; i++)
//    {
//        void * virt_addr = chunklist;
//        chunklist = chunklist->next;
//        sma_driver_info.cdev_drv.huge_page[i] = (uint32_t)virt_to_phys(virt_addr);
//        DPRINTK(ERR,"mem[%d]=%08x\n",i,sma_driver_info.cdev_drv.huge_page[i]);
//        for (j = 0; j < block_size / PAGE_SIZE; j++)
//        {           
//            SetPageReserved(virt_to_page(virt_addr));
//            virt_addr += PAGE_SIZE;
//        } 
//
//          
//    }
//  
//    return 0;
	
	return 0;
}

static int sma_chrdev_mmap( struct file* filep, struct vm_area_struct* vma )
{
//    sma_cdev_drv_info_t * cdev_drv = &sma_driver_info.cdev_drv;
//    sma_pcie_drv_info_t * pcie_drv = &sma_driver_info.pcie_drv;
//    
//    u64 offset = vma->vm_pgoff << PAGE_SHIFT;
//    u64 shm_addr;
//    u64 shm_size;
//    u64 shm_pfn_addr;
//    u64 size = 0;
//
//    if ( cdev_drv->mmap_flag == MMAP_FLAG_PCIE)
//    {
//        shm_addr = pcie_drv->shm_phys_addr;
//        shm_size = SMA_PCI_MEM_LEN;
//        shm_pfn_addr = ( ( uint64_t ) shm_addr >> PAGE_SHIFT );
//    }
//    else if(cdev_drv->mmap_flag == MMAP_FLAG_RX_QUEUE)
//    {
//        //接收队列0-8
//        if(cdev_drv->mmap_arg >= MAX_NUM_RX_CHANNELS)
//        {
//            DPRINTK(ERR,"mmap rx queue invalid arg=[%u].\n",cdev_drv->mmap_arg);
//            return -EINVAL; 
//        }
//        shm_addr =cdev_drv->huge_page[cdev_drv->mmap_arg];
//        shm_size = RX_FIFO_SIZE;
//        shm_pfn_addr = ( ( uint64_t ) shm_addr >> PAGE_SHIFT );
//    }
//    else
//    {
//        DPRINTK(ERR,
//            "invalid mmap_flag =[0x%x].\n",cdev_drv->mmap_flag);
//        return -EINVAL;
//    }
//
//    DPRINTK(DEBUG,
//    "MMap shm_addr=%#llx, shm_size=%llx,"
//    "offset = %llx, vm_start=%lx,vm_flags=%lx, vm_page_prot=%lx\n",
//             shm_addr,
//             shm_size,
//             offset,
//             vma->vm_start,
//             vma->vm_flags,
//             pgprot_val( vma->vm_page_prot ) );
//
//    if ( !shm_addr )
//        return -ENXIO;
//
//    //保证该地址必须是页首地址
//    if ( shm_addr & ( PAGE_SIZE - 1 ) )
//    {
//        DPRINTK(ERR, "mmap to invalid address [%#llx]\n",shm_addr );
//        return -EINVAL;
//    }
//
//    if ( offset >= shm_size )
//        return -ESPIPE;
//
//    if ( vma->vm_flags & VM_LOCKED )
//        return -EPERM;
//
//    size = vma->vm_end - vma->vm_start;
//
//    if ( remap_pfn_range( vma,vma->vm_start,shm_pfn_addr,size,vma->vm_page_prot ))
//        return -EAGAIN;
//
//    cdev_drv->mmap_flag = MMAP_FLAG_INVALID;
//
//    return 0;
	
	return 0;
}


int sma_chrdev_ioctl( struct inode* inode,
                  struct file* filp,
                  unsigned int cmd,
                  unsigned long arg )
{
//    sma_cdev_drv_info_t * cdev_drv = &sma_driver_info.cdev_drv;
//
//    cdev_drv->mmap_arg = arg;
//
//    switch(cmd)
//    {
//        case SMA_IOC_MMAP_PCIE:
//            cdev_drv->mmap_flag = MMAP_FLAG_PCIE;
//            break;
//        case SMA_IOC_MMAP_RX_FIFO:
//            cdev_drv->mmap_flag = MMAP_FLAG_RX_QUEUE;
//            break;
//        default:
//            cdev_drv->mmap_flag = MMAP_FLAG_INVALID;
//            break;
//    }
//
//    DPRINTK(DEBUG,"mmap_flag[%x] mmap_arg[%x]\n", 
//            cdev_drv->mmap_flag ,cdev_drv->mmap_arg);
//    return 0;
	
	return 0;
}

int
sma_chrdev_open( struct inode* inode, struct file* filp )
{
   //struct nca_device_info * nca_device_ptr = &nca_device;
   //filp->private_data = &nca_device_ptr->cdev;

   return 0;
}
int
sma_chrdev_release( struct inode* inode, struct file* filp )
{
    //filp->private_data = NULL;
    return 0;
}

static const struct file_operations sma_chrdev_fops =
{
  .owner = THIS_MODULE,
  .ioctl = sma_chrdev_ioctl,
  .mmap = sma_chrdev_mmap,
  .open =sma_chrdev_open,
  .release = sma_chrdev_release,
};

int sma_cdev_init(sma_driver_info_t * driver_info)
{
//    int ret;
//    int queue;
//    
//    sma_cdev_drv_info_t * cdev_drv = &driver_info->cdev_drv;
//    DPRINTK(ERR,"%s-%d pci_drv->pdev=%p\n",__FILE__,__LINE__,sma_driver_info.pcie_drv.pdev);
//    
//
//    if(sma_huge_page_alloc(cdev_drv->huge_page,MAX_NUM_RX_CHANNELS, RX_FIFO_SIZE) < 0)
//    {
//        DPRINTK(ERR,"Alloc Huge Page Failed.\n");
//        return -1;
//    }
//
//    if (sma_major )
//    {
//       devno = MKDEV( sma_major, 0 );
//       ret = register_chrdev_region( devno, sma_nr_devs, "sma" );
//    }
//    else
//    {
//       ret = alloc_chrdev_region( &devno, 0, sma_nr_devs, "sma" );
//       sma_major = MAJOR( devno );
//    }
//
//    if(ret < 0)
//    {
//        DPRINTK(ERR,"Alloc chrdev region Failed.\n");
//        goto free_huge_pages;
//    }
//
//    cdev_init( &cdev_drv->cdev, &sma_chrdev_fops );
//    cdev_drv->cdev.owner = THIS_MODULE;
//    cdev_drv->cdev.ops = &sma_chrdev_fops;
//    ret = cdev_add( &cdev_drv->cdev, devno, 1 );
//    if (ret)
//    {
//       DPRINTK(ERR,"ErrID %d Adding nca_chardev", ret);
//       goto free_chrdev_region;
//    }
//    
//    for(queue = 0; queue < MAX_NUM_RX_CHANNELS; queue++)
//    {
//        ffwd_dma_queue[queue].rx_dma_base = htonl(cdev_drv->huge_page[queue]);
//        ffwd_dma_queue[queue].rx_enable = 0;
//        ffwd_dma_queue[queue].rx_reset = 0;
//    }
//
//    
//    DPRINTK(DEBUG,"Chrdev major %d, num devs %d\n", sma_major, sma_nr_devs );
//
//    return 0; 
//
//free_chrdev_region:
//    unregister_chrdev_region(devno, sma_nr_devs );
//    
//free_huge_pages:
//    sma_huge_page_free(cdev_drv->huge_page,MAX_NUM_RX_CHANNELS, RX_FIFO_SIZE);
//
//    return -1;
	
	return 0;
}

void sma_cdev_release(sma_driver_info_t * driver_info)
{
//    cdev_del(&driver_info->cdev_drv.cdev);
//    unregister_chrdev_region( devno, sma_nr_devs );
//
//    sma_huge_page_free(driver_info->cdev_drv.huge_page,MAX_NUM_RX_CHANNELS, RX_FIFO_SIZE);
//
//    DPRINTK(DEBUG,"release char device.\n");
}

