#include <printk.h>
#include <assert.h>
#include "mips-exts.h"
#include <traps.h>
#include "msgring.h"
#include <system.h>
#include "gmac.h"
#include "pci.h"
#include "mac.h"
#include "bridge.h"
#include "net_config.h"
#include "classifier.h"
#include "i2c.h"
#include "device.h"
#include "ffwd_msg.h"
#include "ffwd_debug.h"
#include "sma_table.h"


#define DEFAULT_TIME_VALUE      2
int ffwd_dbg_level __shared_memory__ = 1;

uint64_t time_out __shared_memory__;
uint64_t now __shared_memory__;

int core_id;
int thread_id;
int process_id;

//流表BUCKET 基地址总共65536
struct stlc_hlist_head *session_bkt;
session_desc_t *session_desc_head;

spinlock_t   ffwd_init_lock    __shared_memory__;
volatile int ffwd_init_done  __shared_memory__;
spinlock_t session_channel_lock[MAX_NUM_RX_CHANNELS] __shared_memory__;


struct stlc_list_head free_packets_list = STLC_LIST_HEAD_INIT(free_packets_list);/* 用于gmac0接收包，每个cpu都分配 */
struct stlc_list_head big_packets_list = STLC_LIST_HEAD_INIT(big_packets_list);/* 用于接收主机发送的包，每个cpu都分配 */
struct stlc_list_head ack_packets_list = STLC_LIST_HEAD_INIT(ack_packets_list);/* 用于发送ack包，每个cpu都分配 */
struct stlc_list_head dma_count_list = STLC_LIST_HEAD_INIT(dma_count_list);/* 用于记录dma包的个数，每个cpu都分配 */
struct stlc_list_head dma_data_list = STLC_LIST_HEAD_INIT(dma_data_list);/* 用于记录dma包的数据指针 */
struct stlc_list_head free_dma_count_list = STLC_LIST_HEAD_INIT(free_dma_count_list);
u16 dma_count = 0;
struct stlc_list_head free_dma_msg_list = STLC_LIST_HEAD_INIT(free_dma_msg_list);
struct stlc_list_head dma_msg_list __shared_memory__;
spinlock_t dma_msg_list_lock __shared_memory__;

struct stlc_hlist_head * session_buckets;/* 用于tcp会话，每个cpu都分配 */
struct stlc_list_head session_desc_list_head = STLC_LIST_HEAD_INIT(session_desc_list_head);/* 用于tcp会话， 每个cpu都分配 */
spinlock_t rx_desc_lock __shared_memory__;
volatile int rx_offset __shared_memory__;
volatile int tx_offset __shared_memory__;
volatile u32 descid __shared_memory__;
volatile u32 packet_id __shared_memory__;

spinlock_t   my_classifier_init_lock  __shared_memory__;
volatile int my_classifier_init_done  __shared_memory__;
// for dma load balancing
struct stlc_list_head free_dma_balance_list[TLRO_RX_RING_COUNT] __shared_memory__;
struct stlc_list_head dma_balance_list[TLRO_RX_RING_COUNT] __shared_memory__;
spinlock_t dma_balance_list_lock[TLRO_RX_RING_COUNT] __shared_memory__;
spinlock_t free_dma_balance_list_lock[TLRO_RX_RING_COUNT] __shared_memory__;
int dma_balance_rx_offset[TLRO_RX_RING_COUNT] __shared_memory__;
spinlock_t dma_balance_init_lock __shared_memory__;
volatile int dma_balance_init_flag __shared_memory__;

int tlro_rx_offset;// allocate for each thread

//通过线程id号索引绑定的cpu free bucket
u8 igrid_to_bucket[MAXNUM_VCPU] =
{
	0,1,2,3,		/* bucket of core0 thread 0~3 */
	8, 9, 10, 11,   /* bucket of core1 thread 4~7 */
	16, 17, 18, 19, /* bucket of core2 thread 8~11 */
	24, 25, 26, 27, /* bucket of core3 thread 12~15 */
};

struct stlc_list_head dma_list = STLC_LIST_HEAD_INIT(dma_list);

void pcie_msgring_init()
{
	phoenix_reg_t *pcie_mmio = 0;
	phoenix_reg_t *bmmio = 0;
	int i;
	int msgring_stnid_pcie_0 = PCIE_RX_BUCKET_ID;
	int	msgring_stnid_pcie_1 = PCIE_TX_BUCKET_ID;

	pcie_mmio = phoenix_io_mmio(PHOENIX_IO_PCIE_0_OFFSET);
	bmmio = phoenix_io_mmio(PHOENIX_IO_BRIDGE_OFFSET);
	
	pcie_mmio[PCIE_MSG_BUCKET0_SIZE] = xls_bucket_sizes.bucket[msgring_stnid_pcie_0];
	printk("\n %p PCIE_MSG_BUCKET0_SIZE %d\n",&pcie_mmio[PCIE_MSG_BUCKET0_SIZE],pcie_mmio[PCIE_MSG_BUCKET0_SIZE]);

	pcie_mmio[PCIE_MSG_BUCKET1_SIZE] = xls_bucket_sizes.bucket[msgring_stnid_pcie_1];
	printk("\n %p PCIE_MSG_BUCKET1_SIZE %d\n",&pcie_mmio[PCIE_MSG_BUCKET1_SIZE],pcie_mmio[PCIE_MSG_BUCKET1_SIZE]);

	for(i=0;i<128;i++) 
	{
		pcie_mmio[CC_CPU0_0 + i] = xls_cc_table_pcie.counters[i>>3][i&0x07];
	}	
}

//pcie内存空间共有32M
void * get_pcie_shared_mem()
{
	/* Setup the descriptor pointers 
	* Currently 1MB of region is reserved for shared memory starting 
	* from 160MB = 0x0a000000. This region is accessed using KSEG1 addresses
	* as this should be uncached.
	* */
	phoenix_reg_t *pcie_mmio = 0;
	phoenix_reg_t *bmmio = 0;
	unsigned char * start;
	pcie_mmio = phoenix_io_mmio(PHOENIX_IO_PCIE_0_OFFSET);
	bmmio = phoenix_io_mmio(PHOENIX_IO_BRIDGE_OFFSET);
	/* Set the defeature bit in B0 to strip MSB in the pci_address */
	bmmio[59] |= 0x2;
	/* Use 0x8000000000ULL and above for PCI addresses in XLR memory map */
	bmmio[BRIDGE_PCIXMEM_BAR] = 0x8000ffff;
	start = (unsigned char *)pcie_mmio[28];
	//printk("XLS PCIE base = %p\n", start);
	start = (unsigned char *)((unsigned long)start << 16);
	start = (unsigned char *)((unsigned long)start | 0x80000000);
	if(process_id == 4)
		printk("pid %02d XLS PCIE shared mem base = %p\n", process_id, start);
	//printk("\nBRIDGE PCIeMEM BAR REG ADDR %#x and Value Is %#x\n",
        //   (unsigned int)&bmmio[0x42], bmmio[0x42]);
	
	//printk("start addr = %p val %x\n", start, *(u32*)(start+1024));

	return start;

}

ffwd_dma_queue_t * ffwd_dma_queue = NULL;
ffwd_device_info_t * ffwd_device_info = NULL;
ffwd_counter_info_t * ffwd_counter_info = NULL;
entry_state_desc_t * ffwd_session_state_base = NULL;
entry_state_desc_t * ffwd_udp_state_base = NULL;
ffwd_mac_entry_desc_t * ffwd_mac_entry_desc_rx = NULL;
ffwd_mac_entry_desc_t * ffwd_mac_entry_desc_tx = NULL;
ffwd_mac_device_info_t * ffwd_mac_device_info = NULL;
ffwd_mac_counter_t * ffwd_mac_counter = NULL;

// 32 rx rings
ffwd_mac_entry_desc_t * tlro_rx_entry_desc[TLRO_RX_RING_COUNT];

struct stlc_list_head mac_pkt_pool;

void tlro_init_shared_mem(){
	uint8_t * mem = (uint8_t *) get_pcie_shared_mem();	
    uint8_t * start = mem;
    
	ffwd_device_info = (ffwd_device_info_t*)start;
	if(process_id == 4)
		FFWD_DBG(FFWD_DBG_DEBUG, "ffwd_device_info :%p size %d\n", ffwd_device_info, sizeof(ffwd_device_info_t));
	start += sizeof(ffwd_device_info_t);
	
	ffwd_counter_info = (ffwd_counter_info_t *)start;
	if(process_id == 4)
		FFWD_DBG(FFWD_DBG_DEBUG,"ffwd_counter_info : %p size %d sizeof(ffwd_counter_info_t) %d \n",
			ffwd_counter_info, sizeof(ffwd_counter_info_t)*MAXNUM_VCPUS, sizeof(ffwd_counter_info_t));
	start += sizeof(ffwd_counter_info_t)*MAXNUM_VCPUS;
	
	int i;
	for(i = 0;i < TLRO_RX_RING_COUNT;i++){
		tlro_rx_entry_desc[i] = (ffwd_mac_entry_desc_t *) start;
		start += sizeof(ffwd_mac_entry_desc_t) * MAC_ENTRY_DESC_NUM;
	}
	
	ffwd_mac_entry_desc_rx = (ffwd_mac_entry_desc_t *) start;
	//start += sizeof(ffwd_mac_entry_desc_t) * MAC_ENTRY_DESC_NUM;
	
    ffwd_mac_entry_desc_tx = (ffwd_mac_entry_desc_t *) start;
    start += sizeof(ffwd_mac_entry_desc_t) * MAC_ENTRY_DESC_NUM;  
    
    ffwd_mac_device_info = (ffwd_mac_device_info_t *) start;
    start += sizeof(ffwd_mac_device_info_t); 

    ffwd_mac_counter = (ffwd_mac_counter_t *) start;
    start += sizeof(ffwd_mac_counter_t); 

    ffwd_device_info->timeout_value = DEFAULT_TIME_VALUE;
    time_out = ffwd_device_info->timeout_value * CPU_SPEED;
    
    assert(start < mem + 32 * 1024 *1024);
}
//void setup_pcie_shared_mem()
//{
//	uint8_t * mem = (uint8_t *)get_pcie_shared_mem();	
//    uint8_t * start = mem;
//    
//	ffwd_device_info = (ffwd_device_info_t*)start;
//	if(process_id == 4)
//		FFWD_DBG(FFWD_DBG_DEBUG, "ffwd_device_info :%p size %d\n", ffwd_device_info, sizeof(ffwd_device_info_t));
//	start += sizeof(ffwd_device_info_t);
//
////	ffwd_dma_queue = (ffwd_dma_queue_t *)start;
////	if(process_id == 4)
////		FFWD_DBG(FFWD_DBG_DEBUG,"ffwd_dma_queue :%p size %d\n", 
////		ffwd_dma_queue, sizeof(ffwd_dma_queue_t) * MAX_NUM_RX_CHANNELS);
////	start += sizeof(ffwd_dma_queue_t) * MAX_NUM_RX_CHANNELS;
//	
//	ffwd_counter_info = (ffwd_counter_info_t *)start;
//	if(process_id == 4)
//		FFWD_DBG(FFWD_DBG_DEBUG,"ffwd_counter_info : %p size %d sizeof(ffwd_counter_info_t) %d \n",
//			ffwd_counter_info, sizeof(ffwd_counter_info_t)*MAXNUM_VCPUS, sizeof(ffwd_counter_info_t));
//	start += sizeof(ffwd_counter_info_t)*MAXNUM_VCPUS;
//
////    //TCP 会话报文dma     buff 状态表
////	ffwd_session_state_base = (entry_state_desc_t*)start;
////	if(process_id == 4)
////		FFWD_DBG(FFWD_DBG_DEBUG,"ffwd_session_state_base :%p size %d\n", 
////		ffwd_session_state_base, sizeof(entry_state_desc_t) * MAXNUM_SESSION_ENTRY * MAX_NUM_SESSION_CHANNELS);
////	start += sizeof(entry_state_desc_t) * MAXNUM_SESSION_ENTRY * MAX_NUM_SESSION_CHANNELS;
////
////    //UDP 报文dma     buff 状态表
////	ffwd_udp_state_base = (entry_state_desc_t*)start;
////	if(process_id == 4)
////		FFWD_DBG(FFWD_DBG_DEBUG,"ffwd_udp_state_base :%p size %d\n", 
////		ffwd_udp_state_base, sizeof(entry_state_desc_t) * MAXNUM_UDP_ENTRY );
////		
////	start += sizeof(entry_state_desc_t) * MAXNUM_UDP_ENTRY;
//
//    ffwd_mac_entry_desc_rx = (ffwd_mac_entry_desc_t *)start;
//    start += sizeof(ffwd_mac_entry_desc_t) * MAC_ENTRY_DESC_NUM;
//    
//    ffwd_mac_entry_desc_tx = (ffwd_mac_entry_desc_t *)start;
//    start += sizeof(ffwd_mac_entry_desc_t) * MAC_ENTRY_DESC_NUM;  
//    
//    ffwd_mac_device_info = (ffwd_mac_device_info_t *)start;
//    start += sizeof(ffwd_mac_device_info_t); 
//
//    ffwd_mac_counter = (ffwd_mac_counter_t *)start;
//    start += sizeof(ffwd_mac_counter_t); 
//
//    ffwd_device_info->timeout_value = DEFAULT_TIME_VALUE;
//    time_out = ffwd_device_info->timeout_value * CPU_SPEED;
//    
//    assert(start < mem + 32 * 1024 *1024);
//
//}

// network init function
void my_xlr_classifier_init(classifier_config *classifier_conf) {
	int i = 0;

	// ensure that init happens only once, even if all threads call this function
	spin_lock (&my_classifier_init_lock);

	if (!my_classifier_init_done) {
		// configure gmac classifier
		if ( classifier_conf->classify_gmac.enable ) {
			// classification method
			init_prsr_cfg(p_prsr_cfg);
			p_prsr_cfg->use_hash        =  (classifier_conf->classify_gmac.ttable_mode == USE_HASH) ;
			 p_prsr_cfg->use_proto       =  (classifier_conf->classify_gmac.ttable_mode == USE_L3L4) ;
			p_prsr_cfg->use_global_port =  (classifier_conf->classify_gmac.ttable_mode == USE_PORT) ;
			p_prsr_cfg->crc_hash_poly = 127 ; 
			p_prsr_cfg->parse_depth = 8 ; 
			p_prsr_cfg->poly_mask = 0x7f ; 

			// setup l2 table
			init_l2_table(p_l2_t);
			for ( i = 0 ; i < 4 ; i ++ ) {
				p_l2_t->entry[i].l2_proto             = L2_ETH ;
				p_l2_t->entry[i].extraHdrProtoSize    = classifier_conf->classify_gmac.len_0;
				p_l2_t->entry[i].extraHdrProtoOffset  = classifier_conf->classify_gmac.offset_0;
				p_l2_t->entry[i].extraHdrSize         = 0;
				p_l2_t->entry[i].proto_offset         = classifier_conf->classify_gmac.offset_l3_prot;
			}

			// setup the l3 table
			setup_l3_ctable(&(classifier_conf->classify_gmac)) ;

			// setup the l4 table
			setup_l4_ctable(&(classifier_conf->classify_gmac)) ;

			// save all classifier structure for gmac
			save_parser_tables(&parser_tables_gmac) ;
		}
	}
	my_classifier_init_done =1;
	spin_unlock(&my_classifier_init_lock);
}
void config_xls_net()
{
	net_conf_gmac.packet_mem_start = (char *)PKT_BASE;
	net_conf_gmac.packet_mem_size = (unsigned long long)PKT_BUF_SIZE;
	net_conf_gmac.gmac_free_descriptors_0  = 128 * 4;
    net_conf_gmac.gmac1_free_descriptors_0 = (NCA_SPILL_ENTRIES - 128 -1) * 4;
    net_conf_gmac.gmac0_pde_mask_0 = 0x80; /* mask for core 0~3 */
	net_conf_gmac.gmac0_pde_mask_1 = 0x0; /* mask for core 4~7 */
	net_conf_gmac.gmac1_pde_mask_0 = 0xf0f0f000; /* mask for core 0~3. */
	net_conf_gmac.gmac1_pde_mask_1 = 0x0; /* mask for core 4~7 */
	net_conf_gmac.gmac0 = 1;
	net_conf_gmac.gmac1 = 0;
	net_conf_gmac.gmac2 = 0;
	net_conf_gmac.gmac3 = 0;
	net_conf_gmac.gmac4 = 1;
	net_conf_gmac.gmac5 = 0;
	net_conf_gmac.gmac6 = 0;
	net_conf_gmac.gmac7 = 0;
	net_conf_gmac.rgmii_mode = 0;
	net_conf_gmac.gmac0_xaui = 1;
	net_conf_gmac.gmac4_xaui = 1;
	net_conf_gmac.xgmac0 = 0;
	net_conf_gmac.xgmac1 = 0;

	xlr_net_init(&net_conf_gmac);
	//xlr_classifier_init(&classifier_conf_gmac);
	my_xlr_classifier_init(&classifier_conf_gmac);
	ttable_setup_mask(0xfff0, 1, &(classifier_conf_gmac.classify_gmac), &(parser_tables_gmac));
	xlr_classifier_update(&classifier_conf_gmac,&net_conf_gmac);
	
    rmi_xaui_close(0);
	rmi_xaui_close(4);
}


void init_session_desc_list(char *begin, u32 buf_size)
{
	u32 len = 0;
	session_desc_t *tmp;
	
	while (len < buf_size)
	{
		tmp = (session_desc_t*)(begin+len);
		tmp->next = session_desc_head;
		session_desc_head = tmp;
		len += SESSION_DESC_SIZE;
		if((u32)tmp > PKT_BASE)
		{
			printk("pid%02d: tmp %p..............\n\n", process_id, tmp);
			while(1);
		}
		
	}

}

int ffwd_mac_pkt_pool_init(void * mem , int size)
{
	mac_packet_t *pkt;
	
    STLC_INIT_LIST_HEAD(&mac_pkt_pool);

	while(size >= MAC_PKT_SIZE)
	{
		pkt = (mac_packet_t *)(mem);
		stlc_list_add_tail(&pkt->list, &mac_pkt_pool);

		mem += MAC_PKT_SIZE;
		size -= MAC_PKT_SIZE;
	}
	
	return 0;
}

int ffwd_flow_table_init(void * mem, int size)
{
    int i;
	//分配BUCKET
	session_bkt = (struct stlc_hlist_head *)mem;
	mem += (MAXNUM_FLOW_BUCKET * sizeof(struct stlc_hlist_head));
    size -= (MAXNUM_FLOW_BUCKET * sizeof(struct stlc_hlist_head));
    
	//初始化BUCKET
	for (i = 0; i < MAXNUM_FLOW_BUCKET; i++ )
		STLC_INIT_HLIST_HEAD(&session_bkt[i]);

	//初始化流表会话结点
	mem = (uint8_t *)( SESSION_BKT_BASE + SESSION_BKT_SIZE );	
	init_session_desc_list(mem, size);

	while (size >= SESSION_DESC_SIZE)
	{
		session_desc_t * session_desc = (session_desc_t*)(mem);
		session_desc->next = session_desc_head;
		session_desc_head = session_desc;
		
		mem += SESSION_DESC_SIZE;
		size -= SESSION_DESC_SIZE;	
	}
}

#define PACKET_S_COUNT 65536
#define SESSION_BUCKETS_COUNT 65536
#define TLRO_DESC_COUNT 65536
//#define ACK_PACKETS_COUNT 0x000fffff
#define DMA_BALANCE_MSG_COUNT 65536
#define MAC_PKT_COUNT 256
void my_ffwd_init(){
	printf("my ffwd init begined\n");
	u8 * begin;
	int i;
	
	// GMAC1发送数据内存池
	ffwd_mac_pkt_pool_init((void *) MAC_PKT_BASE, MAC_PKT_SIZE * MAC_PKT_COUNT);
	
	// PACKET_S_COUNT * 16 packet_s, then SESSION_BUCKETS_COUNT * 16 session buckets, then TLRO_DESC_COUNT * 16 session descriptors
	begin = (u8 *) MAC_PKT_BASE;
	begin = begin + MAC_PKT_SIZE * MAC_PKT_COUNT + process_id * PACKET_S_COUNT * sizeof(struct packet_s);
	free_packets_list.next = free_packets_list.prev = &(free_packets_list);
	for(i = 0;i < PACKET_S_COUNT;i++){
		struct packet_s * p = (struct packet_s *) begin;
		begin += sizeof(struct packet_s);
		stlc_list_add_tail((struct stlc_list_head *) p, &(free_packets_list));
	}
	
	begin = (u8 *) MAC_PKT_BASE;
	begin = begin + MAC_PKT_SIZE * MAC_PKT_COUNT + 16 * PACKET_S_COUNT * sizeof(struct packet_s) + process_id * SESSION_BUCKETS_COUNT * sizeof(struct stlc_hlist_head);
	session_buckets = (struct stlc_hlist_head *) begin;
	for(i = 0;i < SESSION_BUCKETS_COUNT;i++){
		STLC_INIT_HLIST_HEAD(&(session_buckets[i]));
	}
	
	begin = (u8 *) MAC_PKT_BASE;
	begin = begin + MAC_PKT_SIZE * MAC_PKT_COUNT + 16 * PACKET_S_COUNT * sizeof(struct packet_s) + 16 * SESSION_BUCKETS_COUNT * sizeof(struct stlc_hlist_head) + 
			process_id * TLRO_DESC_COUNT * sizeof(struct tlro_desc);
	STLC_INIT_LIST_HEAD(&(session_desc_list_head));
	for(i = 0;i < TLRO_DESC_COUNT;i++){
		struct tlro_desc * desc = (struct tlro_desc *) begin;
		// init desc
		desc->active = 0;
		desc->ip_total_len = 0;
		desc->key.sip = 0;
		desc->key.dip = 0;
		desc->key.sport = 0;
		desc->key.dport = 0;
		desc->packets.next = desc->packets.prev = &(desc->packets);
		desc->packets_count = 0;
		desc->pid = 0;
		desc->tcp_ack = 0;
		desc->tcp_next_seq = 0;
		desc->tcp_rcv_tsecr = 0;
		desc->tcp_rcv_tsval = 0;
		desc->tcp_saw_tstamp = 0;
		desc->tcp_window = 0;
		desc->tick = 0;
		desc->nd_hlist.next = NULL;
		desc->nd_hlist.pprev = NULL;
		descid++;
		
		stlc_list_add_tail((struct stlc_list_head *) desc, &(session_desc_list_head));
		begin += sizeof(struct tlro_desc);
	}
	
	// dma load balance msg
	spin_lock(&dma_balance_init_lock);
	if(!dma_balance_init_flag){
		begin = (u8 *) MAC_PKT_BASE;
		begin = begin + MAC_PKT_SIZE * MAC_PKT_COUNT + 16 * PACKET_S_COUNT * sizeof(struct packet_s) + 16 * SESSION_BUCKETS_COUNT * sizeof(struct stlc_hlist_head) + 
				16 * TLRO_DESC_COUNT * sizeof(struct tlro_desc);
		for(i = 0;i < TLRO_RX_RING_COUNT;i++){
			free_dma_balance_list[i].prev = free_dma_balance_list[i].next = &(free_dma_balance_list[i]);
			dma_balance_list[i].prev = dma_balance_list[i].next = &(dma_balance_list[i]);
			dma_balance_rx_offset[i] = 0;
		}
		int j;
		for(i = 0;i < TLRO_RX_RING_COUNT;i++){
			for(j = 0;j < DMA_BALANCE_MSG_COUNT;j++){
				struct dma_balance_msg_s * msg = (struct dma_balance_msg_s *) begin;
				stlc_list_add_tail(&(msg->node), &(free_dma_balance_list[i]));
				begin += sizeof(struct dma_balance_msg_s);
			}
		}
		
		dma_balance_init_flag = 1;
	}
	spin_unlock(&dma_balance_init_lock);
	
	begin = (u8 *) MAC_PKT_BASE;
	begin = begin + MAC_PKT_SIZE * MAC_PKT_COUNT + 16 * PACKET_S_COUNT * sizeof(struct packet_s) + 16 * SESSION_BUCKETS_COUNT * sizeof(struct stlc_hlist_head) + 
			16 * TLRO_DESC_COUNT * sizeof(struct tlro_desc) + TLRO_RX_RING_COUNT * DMA_BALANCE_MSG_COUNT * sizeof(struct dma_balance_msg_s);
	u32 ack_packets_count = ((u32)PKT_BASE - (u32) begin) / 16 / sizeof(struct ack_packet_s);
	begin = begin + process_id * ack_packets_count * sizeof(struct ack_packet_s);
	for(i = 0;i < ack_packets_count;i++){
		struct ack_packet_s * ack_packet = (struct ack_packet_s *) begin;
		stlc_list_add_tail(&(ack_packet->node), &ack_packets_list);
		begin += sizeof(struct ack_packet_s);
	}
	
	printk("my ffwd init ended, begin = %u\n", (u32) begin);
	if(begin < ((u8 *) 0x20000000)){
		printk("not over 0x20000000\n");
	} else {
		printk("over 0x20000000\n");
	}
}
//void ffwd_init(){
//	u8 * begin;
//	int i;
//	
//	// GMAC1发送数据内存池
//	ffwd_mac_pkt_pool_init((void *) MAC_PKT_BASE, MAC_PKT_SIZE * MAC_ENTRY_DESC_NUM);
//	
//	// 先放256 * 16个packet_s, 再放65536 * 16个session buckets, session descriptors
//	begin = (u8 *) MAC_PKT_BASE;
//	begin = begin + MAC_PKT_SIZE * MAC_ENTRY_DESC_NUM + process_id * 256 * sizeof(struct packet_s);
//	STLC_INIT_LIST_HEAD(&(free_packets_list));
//	for(i = 0;i < 256;i++){
//		struct packet_s * p = (struct packet_s *) (begin);
//		begin += sizeof(struct packet_s);
//		p->id = packet_id;
//		packet_id++;
//		stlc_list_add_tail((struct stlc_list_head *) p, &(free_packets_list));
//	}
//	
//	begin = (u8 *) MAC_PKT_BASE;
//	begin = begin + MAC_PKT_SIZE * MAC_ENTRY_DESC_NUM + 16 * 256 * sizeof(struct packet_s) + process_id * 65536 * sizeof(struct stlc_hlist_head);
//	session_buckets = (struct stlc_hlist_head *) begin;
//	for(i = 0;i < 65536;i++){
//		STLC_INIT_HLIST_HEAD(&(session_buckets[i]));
//	}
//	
//	begin = (u8 *) MAC_PKT_BASE;
//	begin = begin + MAC_PKT_SIZE * MAC_ENTRY_DESC_NUM + 16 * 256 * sizeof(struct packet_s) + 16 * 65536 * sizeof(struct stlc_hlist_head) + process_id * 65536 * sizeof(struct tlro_desc);
//	STLC_INIT_LIST_HEAD(&(session_desc_list_head));
//	for(i = 0;i < 65536;i++){
//		struct tlro_desc * desc = (struct tlro_desc *) begin;
//		// init desc
//		desc->active = 0;
//		desc->ip_total_len = 0;
//		desc->key.sip = 0;
//		desc->key.dip = 0;
//		desc->key.sport = 0;
//		desc->key.dport = 0;
//		desc->packets.next = desc->packets.prev = &(desc->packets);
//		desc->packets_count = 0;
//		desc->pid = 0;
//		desc->tcp_ack = 0;
//		desc->tcp_next_seq = 0;
//		desc->tcp_rcv_tsecr = 0;
//		desc->tcp_rcv_tsval = 0;
//		desc->tcp_saw_tstamp = 0;
//		desc->tcp_window = 0;
//		desc->tick = 0;
//		desc->nd_hlist.next = NULL;
//		desc->nd_hlist.pprev = NULL;
////		desc->id = descid;
//		descid++;
//		
//		stlc_list_add_tail((struct stlc_list_head *) desc, &(session_desc_list_head));
//		begin += sizeof(struct tlro_desc);
//	}
//	
//	// ack packets
//	begin = (u8 *) MAC_PKT_BASE;
//	begin = begin + MAC_PKT_SIZE * MAC_ENTRY_DESC_NUM + 16 * 256 * sizeof(struct packet_s) + 16 * 65536 * sizeof(struct stlc_hlist_head) + 16 * 65536 * sizeof(struct tlro_desc) +
//			process_id * 100 * sizeof(struct ack_packet_s);
//	ack_packets_list.next = ack_packets_list.prev = &ack_packets_list;
//	for(i = 0;i < 100;i++){
//		struct ack_packet_s * ack_packet = (struct ack_packet_s *) begin;
//		stlc_list_add_tail(&(ack_packet->node), &ack_packets_list);
//		begin += sizeof(struct ack_packet_s);
//	}
//	// dma_count_s
//	begin = (u8 *) MAC_PKT_BASE;
//	begin = begin + MAC_PKT_SIZE * MAC_ENTRY_DESC_NUM + 16 * 256 * sizeof(struct packet_s) + 16 * 65536 * sizeof(struct stlc_hlist_head) + 16 * 65536 * sizeof(struct tlro_desc) +
//			16 * 100 * sizeof(struct ack_packet_s) + process_id * 100 * sizeof(struct dma_count_s);
//	free_dma_count_list.prev = free_dma_count_list.next = &free_dma_count_list;
//	for(i = 0;i < 100;i++){
//		struct dma_count_s * dma_count = (struct dma_count_s *) begin;
//		stlc_list_add_tail(&(dma_count->node), &free_dma_count_list);
//		begin += sizeof(struct dma_count_s);
//	}
//	// dma_msg_s
//	begin = (u8 *) MAC_PKT_BASE;
//	begin = begin + MAC_PKT_SIZE * MAC_ENTRY_DESC_NUM + 16 * 256 * sizeof(struct packet_s) + 16 * 65536 * sizeof(struct stlc_hlist_head) + 16 * 65536 * sizeof(struct tlro_desc) +
//			16 * 100 * sizeof(struct ack_packet_s) + 16 * 100 * sizeof(struct dma_count_s) + process_id * 100 * sizeof(struct dma_msg_s);
//	free_dma_msg_list.prev = free_dma_msg_list.next = &free_dma_msg_list;
//	for(i = 0;i < 100;i++){
//		struct dma_msg_s * dma_msg = (struct dma_msg_s *) begin;
//		stlc_list_add_tail(&(dma_msg->node), &free_dma_msg_list);
//		begin += sizeof(struct dma_msg_s);
//	}
//	// for dma load balancing
//	for(i = 0;i < TLRO_RX_RING_COUNT;i++){
//		free_dma_balance_list[i].prev = free_dma_balance_list[i].next = &(free_dma_balance_list[i]);
//		dma_balance_list[i].prev = dma_balance_list[i].next = &(dma_balance_list[i]);
//		dma_balance_rx_offset[i] = 0;
//	}
//	begin = (u8 *) MAC_PKT_BASE;
//	begin = begin + MAC_PKT_SIZE * MAC_ENTRY_DESC_NUM + 16 * 256 * sizeof(struct packet_s) + 16 * 65536 * sizeof(struct stlc_hlist_head) + 16 * 65536 * sizeof(struct tlro_desc) + 
//			16 * 100 * sizeof(struct ack_packet_s) + 16 * 100 * sizeof(struct dma_count_s) + 16 * 100 * sizeof(struct dma_msg_s);
//	int j;
//	for(i = 0;i < TLRO_RX_RING_COUNT;i++){
//		for(j = 0;j < 100;j++){
//			struct dma_balance_msg_s * msg = (struct dma_balance_msg_s *) begin;
//			stlc_list_add_tail(&(msg->node), &(free_dma_balance_list[i]));
//			begin += sizeof(struct dma_balance_msg_s);
//		}
//	}
//	
//	if(begin < ((u8 *) 0x10000000)){
//		printk("not over 0x10000000\n");
//	} else {
//		printk("over 0x10000000\n");
//	}
//	
//	// 0x10000000 开始256MB放big packets
//	begin = (u8 *) SESSION_BKT_BASE;
//	u32 big_pkt_size = (sizeof(struct big_packet) / 2048 + 1) * 2048;
//	FFWD_DBG(0, "big_pkt_size = %u\n", big_pkt_size);
//	u32 big_pkt_num_th = 256 * 1024 * 1024 / 16 / big_pkt_size;
//	FFWD_DBG(0, "big_pkt_num_th = %u\n", big_pkt_num_th);
//	begin = begin + process_id * big_pkt_num_th * big_pkt_size;
//	for(i = 0;i < big_pkt_num_th;i++){
//		struct big_packet * p = (struct big_packet *) begin;
//		stlc_list_add_tail((struct stlc_list_head *) p, &(big_packets_list));
//		begin += big_pkt_size;
//	}
//}

//void ffwd_init()
//{
//	u8 * begin;
//	int i;
//
//	//初始化通信口tx 数据包内存池
//    ffwd_mac_pkt_pool_init((void *)MAC_PKT_BASE, MAC_PKT_SIZE * MAC_ENTRY_DESC_NUM);
//
//	//会话节点哈希表
//	begin = (u8*)SESSION_BKT_BASE;
//	begin = begin + (process_id * MAXNUM_FLOW_BUCKET * sizeof(struct stlc_hlist_head));//每个线程分配一份
//	session_bkt = (struct stlc_hlist_head *)begin;
//	for (i=0; i<MAXNUM_FLOW_BUCKET; i++)
//	{
//		STLC_INIT_HLIST_HEAD(&session_bkt[i]);
//	}
//	if (process_id == 4)
//		printk( "pid%02d: begin %p session_bucket: %p session_bkt_size 0x%x\n", 
//			process_id, begin, session_bkt, SESSION_BKT_SIZE);
//	
//	//会话节点
//	begin = (u8*)(SESSION_BKT_BASE + SESSION_BKT_SIZE);
//	if (process_id == 4)
//		printk( "pid%02d: session desc base %p\n", process_id, begin);
//	begin = begin +(process_id * MAXNUM_SESSION_DESC_TH * SESSION_DESC_SIZE);
//	init_session_desc_list(begin, MAXNUM_SESSION_DESC_TH * SESSION_DESC_SIZE);
//	if (process_id == 15)
//		printk( "pid%02d: begin %p size: %#x\n", process_id, begin, MAXNUM_SESSION_DESC_TH * SESSION_DESC_SIZE);
//	
//}

void config_xls_mac()
{
    phoenix_reg_t *mmio = phoenix_io_mmio(PHOENIX_IO_GMAC_0_OFFSET);
    
    ffwd_mac_device_info->mac_addr[0] = (boot1_info->mac_addr >> 40) & 0xff;
    ffwd_mac_device_info->mac_addr[1] = (boot1_info->mac_addr >> 32) & 0xff;
    ffwd_mac_device_info->mac_addr[2] = (boot1_info->mac_addr >> 24) & 0xff;
    ffwd_mac_device_info->mac_addr[3] = (boot1_info->mac_addr >> 16) & 0xff;
    ffwd_mac_device_info->mac_addr[4] = (boot1_info->mac_addr >> 8) & 0xff;
    ffwd_mac_device_info->mac_addr[5] = (boot1_info->mac_addr >> 0) & 0xff;

    printk("gmac0 MAC:%02x-%02x-%02x-%02x-%02x-%02x\n",
        ffwd_mac_device_info->mac_addr[0],
        ffwd_mac_device_info->mac_addr[1],
        ffwd_mac_device_info->mac_addr[2],
        ffwd_mac_device_info->mac_addr[3],
        ffwd_mac_device_info->mac_addr[4],
        ffwd_mac_device_info->mac_addr[5]);
        
	phoenix_write_reg(mmio, G_MAC_ADDR0_0,
        ((ffwd_mac_device_info->mac_addr[5]<<24)|(ffwd_mac_device_info->mac_addr[4]<<16)
         |(ffwd_mac_device_info->mac_addr[3]<<8)|(ffwd_mac_device_info->mac_addr[2]))
        );
        
    phoenix_write_reg(mmio, G_MAC_ADDR0_1,
          ((ffwd_mac_device_info->mac_addr[1]<<24)|(ffwd_mac_device_info->mac_addr[0]<<16)));

    turn_on_filtering(mmio);
}

void sys_init()
{
	process_id = processor_id();
	thread_id = phnx_thr_id();
	core_id = phnx_cpu_id();
	rx_offset = tx_offset = 0;
	tlro_rx_offset = 0;

	trap_init();
  	init_irq();
  	sti();

	if (((process_id & 0x3) == 0) || (process_id == 1)) {//every core need config message ring	
		message_ring_cpu_init();
	}

	//系统自身所占堆栈空间为0120000000 --> 0127ffffff 
	setup_kseg2_tlb(0xc0000000, 0x80000000, 0x20000000); //512M 0x8000_0000--0xAAFF_FFFF(688M) 接口缓存报文
	setup_kseg2_tlb(0xe0000000, 0xa0000000, 0x20000000); //512M 0xAB10_0000--0xBF0F_FFFF(320M) spill 地址
	setup_tlb(0x8000000, 0xe0000000, 0x4000000);   //128M
	setup_tlb(0x10000000, 0xe8000000, 0x4000000);   //128M
	setup_tlb(0x18000000, 0xf0000000, 0x4000000);   //128M 这384M会话节点用

	setup_tlb(0x20000000, 0x20000000, 0x10000000); //512M
	setup_tlb(0x40000000, 0x40000000, 0x10000000); //512M
	setup_tlb(0x60000000, 0x60000000, 0x10000000); //512M 1536M接口缓存报文

	spin_lock (&ffwd_init_lock);
	//setup_pcie_shared_mem();
	tlro_init_shared_mem();	
	if (!ffwd_init_done) 
	{
		printk("pid %02d net initing ...\n", process_id);
		rmi_xaui_close(0);
		rmi_xaui_close(4);
		pcie_msgring_init();
		/*网口初始化*/
		config_xls_net();
		config_xls_mac();
		printk("pid %02d net init ok\n", process_id);

		
		// added on 4.9
		descid = 0;
		packet_id = 0;
		dma_msg_list.prev = dma_msg_list.next = &dma_msg_list;
	}
	ffwd_init_done = 1;
	spin_unlock (&ffwd_init_lock);

	//ffwd_init();
	my_ffwd_init();
}


int main(int argc, char *argv[])
{	
	FFWD_DBG(0, "----------------------------------- changed ffwd_init(), setup_pcie_shared_mem(), init_skb_pool() and rx_complete()  ------------------\n");
	sys_init();
	
	switch(process_id)
	{
		case 1:
			FFWD_DBG(0, "-------------------------------------edited ffwd_mac_scan()--------------------------------\n");
			//ffwd_scan_task();
			//scan_task_pipeline();
			//scan_task_dmaqueue();
			scan_task_dma_load_balance();
			break;
	    case 2:
	    	FFWD_DBG(0, "-------------------------------------- edited ffwd_mac_tx()-------------------\n");
	        tlro_mac_tx();
	    	//simple_mac_tx();
	        break;
	    case 3:
//	        ffwd_mac_rx(); 
	    	FFWD_DBG(0, "------------------------------------- deleted ffwd_mac_rx()------\n");
	        break;
		default:
			//ffwd_session_task();
			//session_task_multi_rxring();
			session_task_dma_load_balance();
			//session_task_pipeline();
			//session_task_dmaqueue();
			//session_task_asy();
			//simple_rx();
			//simple_rx_asy();
			//simple_receive_multi_rxring();
			//simple_receive_dma_load_balance();
	}
	return 0;
}
