#include "mm.h"
#include "byteorder.h"
#include "cache.h"
#include <gmac.h>
#include "ffwd_msg.h"
#include "ffwd_debug.h"
#include "ffwd.h"
#include "stlc_list.h"
#include "mdio.h"

#include <parser.h>

session_desc_t *dma_node;

dma_pkt_t dma_pkt_array[MAX_SESSION_PKT];
dma_pkt_t * dma_pkt_array_ptr;

u32 channel_offset[MAX_NUM_RX_CHANNELS] __shared_memory__;
//接收队列暂停标志
uint8_t rx_queue_pause[MAX_NUM_RX_CHANNELS] __shared_memory__;
//分发向量
int pde_vc[128] __shared_memory__;

//接收队列暂停标志
ffwd_counter_info_t *counter_base;

/* For traffic rate. */
uint32_t nowtime = 0;
uint32_t lasttime = 0;

static inline session_desc_t *session_node_malloc()
{
	session_desc_t *tmp;

	tmp = session_desc_head;
	if (tmp) {		
		session_desc_head = tmp->next;		
		tmp->next = NULL;
		FFWD_DBG(FFWD_DBG_DEBUG, "malloc session node %p\n", tmp);
	} 	
	return tmp;
}
static inline void session_node_free(session_desc_t *p)
{
	p->next = session_desc_head;
	session_desc_head = p;
}

void ffwd_pde_vc_update()
{
    int count = 0;
    int pos = 0;

    uint8_t mask = ffwd_device_info->pde_mask;

    // 0-7 bit 表示通道号,8bit表示更新
    if(ffwd_device_info->pde_reset)
    {
        printk("set pde_mask = %02x\n", mask);
        while(count < 128)
        {
            if((mask >> pos) & 0x1)
            {
                pde_vc[count] = pos;
                count += 1;
            }
            pos = (pos + 1) & (MAX_NUM_SESSION_CHANNELS - 1); 
        }
        ffwd_device_info->pde_reset = 0;
        
    }
}


#define MAC_PKT_SIZE 2048

static inline void ffwd_mac_interrupt_host(void)
{
	phoenix_reg_t *pcie_ctrl_mmio = 0;
    uint32_t val = 0;

	pcie_ctrl_mmio = phoenix_io_mmio(PHOENIX_IO_PCIE_1_OFFSET);
    FFWD_DBG(FFWD_DBG_DEBUG, "Trigger an MSI to the host\n");

	/* Trigger an MSI to the host */
     pcie_ctrl_mmio[0x07] = 0x01;
	 pcie_ctrl_mmio[0x06] = 0x20;

    do
    {
    	val = pcie_ctrl_mmio[0x07];
    }while(!val);
}

mac_packet_t * ffwd_alloc_mac_pkt()
{
	if(!stlc_list_empty(&mac_pkt_pool))
	{	
	    mac_packet_t *pkt = stlc_list_first_entry(&mac_pkt_pool, mac_packet_t, list);
		stlc_list_del(&(pkt->list));
		return pkt;
	}
	return NULL;
}

static inline void ffwd_free_mac_pkt(u64 msg, int srcid)
{
	mac_packet_t *pkt = (mac_packet_t *)((u32)phys_to_virt((u32)GET_RX_MSG_DATA(msg)) & MASK_2K_ALIGN);
	stlc_list_add_tail(&pkt->list, &mac_pkt_pool);

	FFWD_DBG(FFWD_DBG_DEBUG,"free xmit mac_packet= %p\n", pkt);
}

int ffwd_mac_rx()
{	
    uint8_t*    recv_data;
	uint16_t    pkt_len;
	uint32_t    daddr; 
	uint32_t    ret;
	
	uint32_t    srcid;
	uint64_t    msg;
	
    int recv_bkt = BUCKET_RCV_PKT;

	printk("pid%02d: starting mac rx task recv_bkt = %d\n", process_id,recv_bkt);
	
	while(1)
	{	
		if (ffwd_message_receive_fast_1(recv_bkt, srcid, msg) != 0)
			continue;

		FFWD_DBG(FFWD_DBG_DEBUG,"srcid %u recv msg %llx\n", srcid, msg);
				
		recv_data = (uint8_t* )phys_to_virt(( uint32_t )GET_RX_MSG_DATA(msg));
		pkt_len = GET_RX_MSG_LEN(msg) - CRC_SIZE;

		if (ffwd_mac_entry_desc_rx[rx_offset].state == FIFO_WRITABLE)
		{
			daddr = __swab32(ffwd_mac_entry_desc_rx[rx_offset].address);
		} 
		else
		{
		    FFWD_DBG(FFWD_DBG_DEBUG,"FIFO Not FIFO_WRITABLE ffwd_mac_entry_desc_rx[%d].state = %d\n",rx_offset,
		    ffwd_mac_entry_desc_rx[rx_offset].state);
		    SMA_COUNTER_INC(gmac0_rx_dropped_packets);
			goto cleanup;
		}
		
		FFWD_DBG(FFWD_DBG_DEBUG, "send paddr %llx, len %u to dma %u\n", virt_to_phys(recv_data), pkt_len, PCIE_RX_BUCKET_ID);
		ffwd_msg_send_to_dma(1, igrid_to_bucket[process_id], virt_to_phys(recv_data), daddr,pkt_len, 1, PCIE_RX_BUCKET_ID);
		
		ret = wait_dma_rsp_msg();
		if (ret == 0)
		{
            ffwd_mac_counter->rx_packets++;
            ffwd_mac_counter->rx_bytes += pkt_len;
            ffwd_mac_entry_desc_rx[rx_offset].len = __swab16(pkt_len);
			ffwd_mac_entry_desc_rx[rx_offset].state = FIFO_READABLE;	
            SMA_COUNTER_INC(gmac0_rx_packets);

			//if(ffwd_mac_device_info->msi_enable)
			//print_pkt(recv_data,pkt_len);
			
			ffwd_mac_interrupt_host();
			    
			rx_offset = (rx_offset + 1) & (MAC_ENTRY_DESC_NUM -1);
			barrier();
		}
cleanup:
		msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID,virt_to_phys(recv_data));			
		barrier();
		message_send_block_fast_1(0,MSGRNG_STNID_GMAC0_FR, msg);
	}
    return 0;
}

static inline uint16_t add_one_complement_sum(uint16_t * a, int len){
	register uint16_t answer;
	register int sum = 0;
	register int i;
	for(i = 0;i < len;i++){
		sum += a[i];
	}
	/*
	* add back carry outs from top 16 bits to low 16 bits
	*/
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = sum;// truncate to 16 bits
	return answer;
}
static inline uint16_t one_complement_sum(uint16_t * addr, int len){
	register int nleft = len;
	register uint16_t * w = addr;
	register uint16_t answer;
	register int sum = 0;

	while (nleft > 1){
			sum += *w++;
			nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += *(uint8_t *) w;

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = sum;// truncate to 16 bits
	return answer;
}
static inline uint16_t check_sum(uint16_t * addr, int len)
{
	register int nleft = len;
	register uint16_t * w = addr;
	register uint16_t answer;
	register int sum = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += *(uint8_t *) w;

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
//	FFWD_DBG(0, "before not operation, sum = %d\n", sum);
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

static inline uint16_t tcp_checksum(PsdHeader * psd_header, uint16_t * addr, int len){
	register int left = sizeof(PsdHeader);
	register uint16_t * w = (uint16_t *) psd_header;
	register uint16_t answer;
	register int sum = 0;
	
	while(left > 1){
		sum += *w++;
		left -=2;
	}
	
	left = len;
	w = addr;
	while(left > 1){
		sum += *w++;
		left -= 2;
	}
	if(left == 1){
		sum += *(uint8_t *)w;
	}
	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
//	FFWD_DBG(0, "before not operation, sum = %d\n", sum);
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

int simple_mac_tx(){
	int free_bkt = BUCKET_RCV_RSP;
	mac_packet_t *pkt;
	u64 msg;
	u16 len;
	u32 addr;
	u32 srcid;
	int flag = 1;
	int met = 0;
	
	printk("pid%02d: starting simple mac tx task recv_bkt = %d\n", process_id,free_bkt);
	while(1)
	{
	
		if (ffwd_message_receive_fast_1(free_bkt, srcid, msg) == 0)
		{
			FFWD_DBG(FFWD_DBG_DEBUG, "recv srcid %u free back msg.\n", srcid);
//			ASSERT((srcid == MSGRNG_STNID_GMAC0));
			if(srcid == MSGRNG_STNID_GMAC1){
				FFWD_DBG(0, "---------------------------------- received GMAC1 free back message\n");
			}
			ASSERT(srcid == MSGRNG_STNID_GMAC1);
			ffwd_free_mac_pkt(msg, srcid);
			continue;
		}

		if (ffwd_mac_entry_desc_tx[tx_offset].state == FIFO_READABLE)//需要传输
		{
			len = __swab16(ffwd_mac_entry_desc_tx[tx_offset].len);
			addr = __swab32(ffwd_mac_entry_desc_tx[tx_offset].address);

			pkt = ffwd_alloc_mac_pkt();
			if(pkt == NULL)
			    continue;
			    
			//pkt->len = len;

		    //printk("data_ptr = %p\n",pkt->data);
			ffwd_msg_send_to_dma(TRUE, igrid_to_bucket[process_id], addr, 
				virt_to_phys(pkt->data), len, 1, PCIE_TX_BUCKET_ID);
			wait_dma_rsp_msg();
			
            barrier();
                        
            FFWD_DBG(0, "tx_offset = %d\n", tx_offset);
//		    print_pkt(pkt->data,len);
		    struct ether_header * ethhdr = (struct ether_header *) pkt->data;
		    if(ethhdr->ether_type == ETHERTYPE_IP){
		    	struct ip * ipheader = (struct ip *) (pkt->data + SIZEOF_ETHERHEADER);
		    	if(ipheader->ip_p == IPPROTO_TCP){
		    		struct tcphdr * tcpheader = (struct tcphdr *) (pkt->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
		    		u32 payload_len = TCP_PAYLOAD_LENGTH(ipheader, tcpheader);
		    		FFWD_DBG(0, "------------ sending a tcp packet, sip = %u, dip = %u, sport = %u, dport = %u\n", ipheader->ip_src, ipheader->ip_dst, tcpheader->th_sport, tcpheader->th_dport);
		    		// calculate tcp checksum
		    		PsdHeader psd_header;
		    		psd_header.saddr = ipheader->ip_src;
		    		psd_header.daddr = ipheader->ip_dst;
		    		psd_header.mbz = 0;
		    		psd_header.ptcl = 6;
		    		psd_header.tcpl = ipheader->ip_len - ipheader->ip_hl * 4;
		    		tcpheader->th_sum = 0;
		    		tcpheader->th_sum = tcp_checksum(&psd_header, tcpheader, ipheader->ip_len - ipheader->ip_hl * 4);
		    	}
		    	// calculate ip checksum
		    	ipheader->ip_sum = 0;
		    	ipheader->ip_sum = check_sum(ipheader, ipheader->ip_hl * 4);
		    }
			ffwd_mac_counter->tx_packets++;
			ffwd_mac_counter->tx_bytes += len;
//			ffwd_mac_entry_desc_tx[tx_offset].state = FIFO_WRITABLE;
			ffwd_mac_entry_desc_tx[tx_offset].state = FIFO_DONE;
			tx_offset = (tx_offset + 1) & (MAC_ENTRY_DESC_NUM - 1);
			msg = FMN_MAKE_TX_MSG(FMN_MSG_EOF, igrid_to_bucket[process_id], len, virt_to_phys(pkt->data));

            FFWD_DBG(FFWD_DBG_DEBUG, "xmit entry[%d] = %d , len = %d ,address = %08x\n",
                tx_offset,ffwd_mac_entry_desc_tx[tx_offset].state,len,addr);
            //printk("xmit entry[%d] = %d , len = %d ,address = %08x\n",
            //    tx_offset,ffwd_mac_entry_desc_tx[tx_offset].state,len,addr);
			barrier();
			
//			if (ffwd_message_send_1(MSGRNG_STNID_GMAC0_TX0, msg))
			if(flag){
				if(ffwd_message_send_1(MSGRNG_STNID_GMAC1_TX0, msg)){
					SMA_COUNTER_INC(gmac0_tx_dropped_packets);
					FFWD_DBG(FFWD_DBG_DEBUG, "send faild\n");
				} else {
					SMA_COUNTER_INC(gmac0_tx_packets);
					FFWD_DBG(FFWD_DBG_DEBUG, "send ok\n");
				}
			}
		}
	}
    return 0;
}
int tlro_mac_tx()
{
	int free_bkt = BUCKET_RCV_RSP;
	mac_packet_t *pkt;
	u64 msg;
	u16 len;
	u32 addr;
	u32 srcid;
	int flag = 1;
	int met = 0;
	
	printk("pid%02d: starting tlro mac tx task recv_bkt = %d\n", process_id,free_bkt);
	
	while(1)
	{
	
		if (ffwd_message_receive_fast_1(free_bkt, srcid, msg) == 0)
		{
			FFWD_DBG(FFWD_DBG_DEBUG, "recv srcid %u free back msg.\n", srcid);
//			ASSERT((srcid == MSGRNG_STNID_GMAC0));
			if(srcid == MSGRNG_STNID_GMAC1){
				FFWD_DBG(0, "---------------------------------- received GMAC1 free back message\n");
			}
			ASSERT(srcid == MSGRNG_STNID_GMAC1);
			ffwd_free_mac_pkt(msg, srcid);
			continue;
		}

		if (ffwd_mac_entry_desc_tx[tx_offset].state == FIFO_READABLE)//需要传输
		{
			len = __swab16(ffwd_mac_entry_desc_tx[tx_offset].len);
			addr = __swab32(ffwd_mac_entry_desc_tx[tx_offset].address);

			pkt = ffwd_alloc_mac_pkt();
			if(pkt == NULL)
			    continue;
			    
			//pkt->len = len;

		    //printk("data_ptr = %p\n",pkt->data);
			ffwd_msg_send_to_dma(TRUE, igrid_to_bucket[process_id], addr, 
				virt_to_phys(pkt->data), len, 1, PCIE_TX_BUCKET_ID);
			wait_dma_rsp_msg();
			
            barrier();
                        
            FFWD_DBG(0, "tx_offset = %d\n", tx_offset);
//		    print_pkt(pkt->data,len);
		    struct ether_header * ethhdr = (struct ether_header *) pkt->data;
		    if(ethhdr->ether_type == ETHERTYPE_IP){
		    	struct ip * ipheader = (struct ip *) (pkt->data + SIZEOF_ETHERHEADER);
		    	if(ipheader->ip_p == IPPROTO_TCP){
		    		struct tcphdr * tcpheader = (struct tcphdr *) (pkt->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
		    		u32 payload_len = TCP_PAYLOAD_LENGTH(ipheader, tcpheader);
		    		FFWD_DBG(0, "------------ sending a tcp packet, sip = %u, dip = %u, sport = %u, dport = %u\n", ipheader->ip_src, ipheader->ip_dst, tcpheader->th_sport, tcpheader->th_dport);
//		    		if(tcpheader->th_flags & TH_SYN){
//		    			FFWD_DBG(0, "SYN bit set\n");
//		    		}
//		    		if(tcpheader->th_flags & TH_FIN){
//		    			FFWD_DBG(0, "FIN bit set\n");
//		    		}
//		    		if(tcpheader->th_flags & TH_ACK){
//		    			FFWD_DBG(0, "ACK bit set, ack = %u\n", tcpheader->th_ack);
//		    		}
		    		
		    		// change tcp mss size, make client send data faster
		    		if(tcpheader->th_off > TCPH_LEN_WO_OPTIONS){
		    			u8 * tmp = (u8 *) (tcpheader + 1);
		    			if(*tmp == 2){
		    				u16 * mss = (u16 *) (tmp + 2);
		    				*mss = 0xffff;
		    			}
		    		}
		    		// change tcp window size, make client send data faster
		    		tcpheader->th_win = 0xffff;
		    		// disable timestamp option
		    		if(tcpheader->th_off > TCPH_LEN_WO_OPTIONS){
		    			u8 * tmp = (u8 *) (tcpheader + 1);
		    			while(1){
		    				if(*tmp == 0){
		    					// end of options
		    					break;
		    				} else if(*tmp == 1){
		    					// nop 
		    					tmp += 1;
		    				} else if(*tmp == 2){
		    					// MSS option
		    					tmp += 4;
		    				} else if(*tmp == 3){
		    					// window size scale option
		    					tmp += 3;
		    				} else if(*tmp == 8){
		    					// time stamp option
		    					int i = 0;
		    					for(i = 0;i < 10;i++){
		    						*tmp = 1;
		    						tmp++;
		    					}
		    					break;
		    				} else {
		    					u8 len = *(tmp + 1);
		    					tmp += len;
		    				}
		    			}
		    		}
//		    		if((tcpheader->th_flags & TH_SYN) || (tcpheader->th_flags & TH_FIN) || (tcpheader->th_flags & TH_RST)){
//		    			flag = 1;
//		    		} else if((tcpheader->th_flags & TH_ACK) && payload_len == 0){
//		    			if(met){
//		    				flag = 0;
//		    			} else {
//		    				flag = 1;
//		    				met = 1;
//		    			}
//		    		} else {
//		    			flag = 1;
//		    		}
		    		// calculate tcp checksum
		    		PsdHeader psd_header;
		    		psd_header.saddr = ipheader->ip_src;
		    		psd_header.daddr = ipheader->ip_dst;
		    		psd_header.mbz = 0;
		    		psd_header.ptcl = 6;
		    		psd_header.tcpl = ipheader->ip_len - ipheader->ip_hl * 4;
		    		tcpheader->th_sum = 0;
		    		tcpheader->th_sum = tcp_checksum(&psd_header, tcpheader, ipheader->ip_len - ipheader->ip_hl * 4);
		    	}
		    	// calculate ip checksum
		    	ipheader->ip_sum = 0;
		    	ipheader->ip_sum = check_sum(ipheader, ipheader->ip_hl * 4);
		    }
			ffwd_mac_counter->tx_packets++;
			ffwd_mac_counter->tx_bytes += len;
//			ffwd_mac_entry_desc_tx[tx_offset].state = FIFO_WRITABLE;
			ffwd_mac_entry_desc_tx[tx_offset].state = FIFO_DONE;
			tx_offset = (tx_offset + 1) & (MAC_ENTRY_DESC_NUM - 1);
			msg = FMN_MAKE_TX_MSG(FMN_MSG_EOF, igrid_to_bucket[process_id], len, virt_to_phys(pkt->data));

            FFWD_DBG(FFWD_DBG_DEBUG, "xmit entry[%d] = %d , len = %d ,address = %08x\n",
                tx_offset,ffwd_mac_entry_desc_tx[tx_offset].state,len,addr);
            //printk("xmit entry[%d] = %d , len = %d ,address = %08x\n",
            //    tx_offset,ffwd_mac_entry_desc_tx[tx_offset].state,len,addr);
			barrier();
			
			if(flag){
				if(ffwd_message_send_1(MSGRNG_STNID_GMAC1_TX0, msg)){
					SMA_COUNTER_INC(gmac0_tx_dropped_packets);
					FFWD_DBG(FFWD_DBG_DEBUG, "send faild\n");
				} else {
					SMA_COUNTER_INC(gmac0_tx_packets);
					FFWD_DBG(FFWD_DBG_DEBUG, "send ok\n");
				}
			}
		}
	}
    return 0;
}

static inline void print_session_node(session_desc_t *node)
{
	xls_packet_t *tmp = node->req_pkt_head;
	FFWD_DBG(FFWD_DBG_DEBUG,"req direction: ------------------------------\n");
	while(tmp)
	{
		FFWD_DBG(FFWD_DBG_DEBUG,"NO: %02u [seq: 0x%x, nseq: 0x%x, ack: %10x, flag 0x%02x]\n", 
			tmp->de_num, tmp->seq, tmp->nseq, tmp->ack, tmp->th_flags);
		tmp = tmp->next_pkt;
	}
	FFWD_DBG(FFWD_DBG_DEBUG, "\n");
	
	tmp = node->rsp_pkt_head;
	FFWD_DBG(FFWD_DBG_DEBUG,"rsp direction: ------------------------------\n");
	while(tmp)
	{
		FFWD_DBG(FFWD_DBG_DEBUG,"NO: %02u [seq: 0x%x, nseq: 0x%x, ack: %10x flag 0x%02x]\n", 
			tmp->de_num, tmp->seq, tmp->nseq, tmp->ack, tmp->th_flags);
		tmp = tmp->next_pkt;
	}
	FFWD_DBG(FFWD_DBG_DEBUG,"\n");
}

static inline void print_merged_session_node(session_desc_t *node)
{
	xls_packet_t *tmp = node->pkt;
	FFWD_DBG(FFWD_DBG_DEBUG,"merged session relation: ------------------------------\n");
	while(tmp)
	{
		FFWD_DBG(FFWD_DBG_DEBUG,"NO: %02u [seq: 0x%x, nseq: 0x%x, ack: %10x flag 0x%02x], pay_len: %d\n", 
			tmp->de_num, tmp->seq, tmp->nseq, tmp->ack, tmp->th_flags, tmp->data_len);
		tmp = tmp->next_pkt;
	}
	FFWD_DBG(FFWD_DBG_DEBUG,"\n");
}

void ffwd_drop_session_node(session_desc_t *node)
{
	xls_packet_t *tmp = node->pkt;

	while(tmp)
	{
		drop_session_pkt(tmp);
		tmp = tmp->next_pkt;
	}

	session_node_free(node);
}

static inline void ffwd_recv_time_out_msg(u8 code, u64 msg);
void ffwd_session_dma_done();

static inline int dma_resp(u64 msg)
{
	uint32_t pcie_err=0 ;
	uint32_t iob_err=0 ;
	uint32_t msg_err=0 ;
	uint32_t flush=0 ;
	uint32_t tag_id=0 ;

	tag_id   = (msg) & 0x3ff;
	pcie_err = (msg >> 10) & 0x1;
	iob_err  = (msg >> 11) & 0x1;
	msg_err  = (msg >> 12) & 0x1;
	flush    = (msg >> 13) & 0x1;

	if ( (pcie_err > 0) || (iob_err > 0) || (msg_err > 0) || (flush > 0) ) 
	{
		FFWD_DBG(FFWD_DBG_ERR,"Error bit set for return msg tagId:0x%x  pcie_err:0x%x iob_err:0x%x msg_err:0x%x flush:0x%x \n",
	           tag_id, pcie_err, iob_err, msg_err, flush);
		return -1;
	}
	return 0;
}

int wait_dma_rsp_msg()
{
	int recv_bucket = BUCKET_RCV_RSP;
  	int srcid = 0;
	u64 msg = 0;

	while(1)
	{
		//msgrng_wait(1 << recv_bucket);	//调试用
		if(ffwd_message_receive_fast_1(recv_bucket, srcid, msg))
			continue;
		if (srcid == PCIE_RX_BUCKET_ID)
		{
			FFWD_DBG(FFWD_DBG_DEBUG, "recv dma rsp msg, srcid %d\n", srcid);
			return dma_resp(msg);
		}
		else if (srcid == MSGRNG_STNID_GMAC0 || srcid == MSGRNG_STNID_GMAC1)
		{
			FFWD_DBG(FFWD_DBG_DEBUG,"recv free back msg..............\n");
		}
		else if (srcid == MSGRNG_STNID_CPU0)
		{
			FFWD_DBG(FFWD_DBG_DEBUG, "recv timeout msg, srcid %d\n", srcid);
			//ffwd_recv_time_out_msg(0, msg);
		}
		else
		{
			FFWD_DBG(FFWD_DBG_ERR, "recv unkown msg, srcid %d\n", srcid);
			return ERROR;
		}
	}
	
}

void static inline ffwd_msg_build_dma(int is_return, int return_bucket, struct msgrng_msg *msgsend,
           uint64_t src_addr, uint64_t dest_addr, unsigned int tid, int len)
{
        msgsend->msg0 = src_addr;
        msgsend->msg0 |= ((uint64_t)tid)  <<40;
        msgsend->msg0 |= (uint64_t)return_bucket <<50;
        msgsend->msg0 |= (u64)is_return <<57;
        msgsend->msg0 |= 0ULL <<58;
  /*      if (tid &0x1)
          msgsend->msg0 |= 0ULL <<59;
        else */
        msgsend->msg0 |= 1ULL <<59;
        msgsend->msg0 |= 0ULL <<60;

        msgsend->msg1 = (unsigned long)dest_addr;
        msgsend->msg1 |= ((unsigned long long) len << 40);
        msgsend->msg1 |= 0ULL<<60;
        msgsend->msg1 |= 0ULL<<62;
        msgsend->msg1 |= 0ULL<<63;

}

static __inline__ int ffwd_msg_send_to_dma(int is_return, int fr_stid, 
         uint64_t src_paddr, uint64_t dest_paddr, unsigned int len, 
	 int trans_id, int channel)
{
	struct msgrng_msg msg;
	int stid ;
	uint32_t dest;
	int ret;
	int i = 0;

	//dma_set_inform_src(SIMPLE_XFER, 1);
	ASSERT(len);

#if 0
	stid = dma_make_desc_tx(fr_stid, &msg, SIMPLE_XFER,
	                      src_paddr, dest_paddr, trans_id, len);
#endif
	ffwd_msg_build_dma(is_return, fr_stid, &msg, src_paddr, dest_paddr, 
		  				trans_id, len);
	stid = channel;
	/* Send the packet to DMA */
	/* Note: We need to send only two words for dma simple_xfer */
	//while (message_send(2, MSGRNG_CODE_DMA, stid, &msg));
	dest = (1<<16)|(stid);
//	while(message_push(dest, &msg));
	while(i<2048)
	{
		i++;
		ret = message_push(dest, &msg);
		if(ret == 0)
			break;
	}
	if (ret)
		FFWD_DBG(FFWD_DBG_ERR,"send msg0 %llx msg1 %llx to stid %d error no %d\n", msg.msg0, msg.msg0, stid, ret);
	else
		FFWD_DBG(FFWD_DBG_DEBUG,"send msg %llx msg1 %llx to stid %d OK, fr_stid %d \n", msg.msg0, msg.msg1, stid, fr_stid);

	return ret;
}

#define MHASH_GOLDEN_RATIO	0x9e3779b9
#define session_hash(key) \
(((key)->dip^(key)->sip^(key)->sport^(key)->dport^MHASH_GOLDEN_RATIO) & (MAXNUM_FLOW_BUCKET -1))


//需要比较上下行两个方向
static inline int __pkt_session_cmp(session_desc_t *node, session_key_t *key)
{   
	FFWD_DBG(FFWD_DBG_DEBUG,"dip,sip,dport,sport : node[0x%08x: 0x%08x: 0x%04x: 0x%04x], key[0x%08x: 0x%08x: 0x%04x: 0x%04x]\n",
		node->key.dip, node->key.sip,node->key.dport, node->key.sport, key->dip,  key->sip, key->dport, key->sport);
    if (node->key.dip== key->dip 
    	&& node->key.sip== key->sip 
    	&& node->key.dport== key->dport
    	&& node->key.sport== key->sport)
    {
        return 0;
    } 
	else if (node->key.dip== key->sip 
				&& node->key.sip== key->dip 
				&& node->key.dport== key->sport
				&& node->key.sport== key->dport)
    {
		return 0;
	}
	
    return -1;
}

//会话节点的比较只需要比较一个方向
static inline int __session_cmp(session_desc_t *node, session_key_t *key)
{   
	FFWD_DBG(FFWD_DBG_DEBUG,"dip,sip,dport,sport- node[0x%08x: 0x%08x: 0x%04x: 0x%04x], key[0x%08x: 0x%08x: 0x%04x: 0x%04x]\n",
		node->key.dip, node->key.sip,node->key.dport, node->key.sport, key->dip,  key->sip, key->dport, key->sport);
    if (node->key.dip== key->dip 
    	&& node->key.sip== key->sip 
    	&& node->key.dport== key->dport
    	&& node->key.sport== key->sport)
    {
        return 0;
    } 
	
    return -1;
}

//note 需要加锁
static inline session_desc_t *pkt_find_session_node(xls_packet_t *pkt)
{
    session_desc_t *node = NULL;
    struct stlc_hlist_node *tmp = NULL;

	spin_lock((spinlock_t *)&(session_bkt[pkt->hash].lock));
    stlc_hlist_for_each_entry(node, tmp, &(session_bkt[pkt->hash]), nd_hlist)
    {
        if (0 == __pkt_session_cmp(node, &pkt->key))
        {
        	FFWD_DBG(FFWD_DBG_DEBUG, "find node %p\n", node);
        	spin_unlock((spinlock_t *)&(session_bkt[pkt->hash].lock));
            return node;
        }
    }
	spin_unlock((spinlock_t *)&(session_bkt[pkt->hash].lock));
    return NULL;
}

//note 需要加锁
static inline session_desc_t *session_node_del(session_desc_t *entry)
{
    session_desc_t *node = NULL;
    struct stlc_hlist_node *tmp = NULL;

	spin_lock((spinlock_t *)&(session_bkt[entry->hash].lock));
    stlc_hlist_for_each_entry(node, tmp, &(session_bkt[entry->hash]), nd_hlist)
    {
        if (0 == __session_cmp(node, &entry->key))
        {
        	FFWD_DBG(FFWD_DBG_DEBUG, "find and del node %p\n", node);
        	stlc_hlist_del(&(node->nd_hlist));
        	spin_unlock((spinlock_t *)&(session_bkt[entry->hash].lock));
            return node;
        }
    }
	spin_unlock((spinlock_t *)&(session_bkt[entry->hash].lock));
    return NULL;
}

session_desc_t * session_node_create( xls_packet_t *pkt)
{
	session_desc_t *node;
	u32 hash = pkt->hash;

	node = session_node_malloc();
	if (node == NULL)
		return NULL;
	memset(node,0,sizeof(session_desc_t));

	node->key.dip = pkt->key.dip;
	node->key.sip = pkt->key.sip;
	node->key.dport = pkt->key.dport;
	node->key.sport = pkt->key.sport;
	node->protocol = pkt->protocol;
	node->hash = pkt->hash;
	node->pid = process_id;
	node->timer_tick = now;
	
	spin_lock((spinlock_t *)&(session_bkt[hash].lock));
    stlc_hlist_add_head(&(node->nd_hlist), &(session_bkt[hash]));
    spin_unlock((spinlock_t *)&(session_bkt[hash].lock));
    SMA_COUNTER_INC(gmac1_active_sessions);

    return node;
}

//合并同一会话上下行报文
static inline void merge_two_diections_pkt(session_desc_t *node)
{
	xls_packet_t *cp = NULL;
	xls_packet_t *sp =NULL;
	xls_packet_t *tmp = NULL, *head = NULL;

	ASSERT(node);
	
	cp= node->req_pkt_head;
	sp = node->rsp_pkt_head;

	if (cp && !sp)          
	{
	    //下行报文为空,合并后的报文直接指向上行
		node->pkt = cp;
		return ;
	}
	else if (!cp && sp)
	{	
	    //上行报文为空,合并后的报文直接指向下行
	    node->pkt = sp;
		return ;
	}
	else if (cp && sp)
	{
		if (cp->ack > sp->seq)//选择头节点
		{
			head = tmp = sp;
			sp = sp->next_pkt;
		}
		else 
		{
			head = tmp = cp;
			cp = cp->next_pkt;
		}
	}
	else 
	{
	    //上下行报文都为空
		node->pkt = NULL;
		return;
	}

	while(cp && sp)
	{
		if (cp->ack > sp->seq)//下行在前
		{
			tmp->next_pkt = sp;
			tmp = sp;
			sp = sp->next_pkt;
		}
		else
		{
			tmp->next_pkt = cp;
			tmp = cp;
			cp = cp->next_pkt;
		}
	}

	if (tmp != NULL)
		tmp->next_pkt = cp ? cp : sp;

	node->pkt = head;
}

static inline void insert_pkt2session(xls_packet_t *pkt,session_desc_t *node)
{
	xls_packet_t *tmp;
	
	if (pkt->data_len == 0||pkt->th_flags & (TH_FIN|TH_RST))
		goto cleanup;

	node->pkt_num += 1;
	node->total_paylen += pkt->data_len;

#if 1
	if (pkt->direction == REQ_DIRECT)
	{
		tmp = node->req_pkt_tail;
		if (tmp == NULL)//如果当前方向还未插入报文,直接插入当前报文为此方向头报文
		{
			node->req_pkt_head = node->req_pkt_tail = pkt;
			return;
		}
		else if (tmp->seq < pkt->seq)//当前报文序列号大于会话节点尾报文的序列号，直接插入在尾部(顺序报文都是这种情况))
		{
			tmp->next_pkt = pkt;
			node->req_pkt_tail = pkt;
			FFWD_DBG(FFWD_DBG_DEBUG,"pkt->seq %d tail seq %d\n", pkt->seq, tmp->seq);
			return ;
		}
		else if (tmp->seq == pkt->seq)
		{
		    //重传报文
			node->pkt_num -= 1;
			node->total_paylen -= pkt->data_len;
			goto cleanup;
		}
		else//如果当前报文序列号小于会话节点尾报文的序列号，需要从链表头按序插入(乱序情况)
		{
		    //乱序报文
			tmp = node->req_pkt_head;
			if (tmp->seq > pkt->seq)//比头报文序列号还小，替换头报文
			{
				pkt->next_pkt = tmp;
				node->req_pkt_head = pkt;
				return;
			}
		}
	}
	else
	{
		tmp = node->rsp_pkt_tail;
		if (tmp == NULL)//如果当前方向还未插入报文,直接插入当前报文为此方向头报文
		{
			node->rsp_pkt_head = node->rsp_pkt_tail = pkt;
			return;
		}
		else if (tmp->seq < pkt->seq)//当前报文序列号大于会话节点尾报文的序列号，直接插入在尾部(顺序报文都是这种情况))
		{
			tmp->next_pkt = pkt;
			node->rsp_pkt_tail = pkt;
			FFWD_DBG(FFWD_DBG_DEBUG,"pkt->seq %d tail seq %d\n", pkt->seq, tmp->seq);
			return ;
		}
		else if (tmp->seq == pkt->seq)
		{
			node->pkt_num -= 1;
			node->total_paylen -= pkt->data_len;
			goto cleanup;
		}
		else//如果当前报文序列号小于会话节点尾报文的序列号，需要从链表头按序插入(乱序情况)
		{
			tmp = node->rsp_pkt_head;
			if (tmp->seq > pkt->seq)//比头报文序列号还小，替换头报文
			{
				pkt->next_pkt = tmp;
				node->rsp_pkt_head = pkt;
				return;
			}
		}
	}

	//在链表中间插入的情况
	while(tmp->next_pkt)
	{
		if (tmp->next_pkt->seq > pkt->seq)
		{
			if (tmp->seq == pkt->seq)
			{
				node->pkt_num -= 1;
				node->total_paylen -= pkt->data_len;
				goto cleanup;
			}
			else 
			{
				pkt->next_pkt = tmp->next_pkt;
				tmp->next_pkt = pkt;
				break;
			}
		}
		else
			tmp = tmp->next_pkt;	
	}

	if (tmp->next_pkt == NULL)
	{
	    //ffwd_dbg_level = 4;
		FFWD_DBG(FFWD_DBG_ERR, "error: can't insert into session node seq = %08x\n",pkt->seq);
		print_session_node(node);
		//ffwd_dbg_level = 1;
		goto cleanup;
	}
#endif 
	return;
cleanup:
	SMA_COUNTER_INC(gmac1_session_dis_packets);
	drop_session_pkt(pkt);
	return;
}

//TCP 通道处理函数
void ffwd_session_pkt_input(xls_packet_t *pkt)
{
    //不带数据且不是会话结束标志的报文丢弃
	if (pkt->data_len == 0 && (pkt->th_flags & (TH_FIN|TH_RST)) == 0)
 		goto cleanup;

	session_desc_t *session_desc = NULL;

	session_desc = pkt_find_session_node(pkt);
	if (session_desc == NULL)//会话节点为空
	{ 
	    //当会话不存在时,首包为FIN 、RST 报文不建立会话
	    if ( pkt->data_len == 0)
	        goto cleanup;
 
		session_desc = session_node_create(pkt);
		if (session_desc == NULL)//如果创建会话节点失败，需要将报文丢弃
		{
			//printk("assert(0) session_node_create faild %p\n", session_desc);
			goto cleanup;
		}
		
		//约定会话第一个报文为上行，是客户端发出的
		pkt->direction = REQ_DIRECT;
		session_desc->req_pkt_head = pkt;
		session_desc->req_pkt_tail = pkt;
		session_desc->pkt_num = 1;
		session_desc->total_paylen = pkt->data_len;

		return;

	}
	else //存在当前会话,需要插入
	{
	    session_desc->timer_tick = now;

		/*判断报文上下行方向和结束标志*/
		if(pkt->key.dip == session_desc->key.dip)
		{
			pkt->direction = REQ_DIRECT;
			if (pkt->th_flags & TH_FIN)
				session_desc->c_fin = TRUE;        
		    else if (pkt->th_flags & TH_RST)
                session_desc->rst = TRUE;
		}
		else
		{
			pkt->direction = RSP_DIRECT;
			if (pkt->th_flags & TH_FIN)
				session_desc->s_fin = TRUE;
			else if (pkt->th_flags & TH_RST)
                session_desc->rst = TRUE;
		}
		
		insert_pkt2session(pkt, session_desc);//存在结束标志的空报文

        if(session_desc->rst ||(session_desc->c_fin && session_desc->s_fin) )
        {
            FFWD_DBG(FFWD_DBG_DEBUG, " session finished(FIN|RST) upload..\n");
      
            session_desc->stop_sec = 1;
            //print_session_node(session_desc);
			session_desc = session_node_del(session_desc);
			//ASSERT(session_desc);
			if (session_desc == NULL)
				return;
			merge_two_diections_pkt(session_desc);
			//print_merged_session_node(session_desc);	
			SMA_COUNTER_DEC(gmac1_active_sessions);
			stlc_list_add_tail(&session_desc->nd_list, &dma_list);
			return;
        }
        //printf("%s,%d\n",__FUNCTION__,__LINE__);
		//预留1600字节防止越界
		if ((session_desc->total_paylen + session_desc->pkt_num * sizeof(dma_pkt_t) 
				+ sizeof(dma_hdr_t) + 1700 >= PKT_SESSION_SIZE )||
				session_desc->pkt_num >= MAX_SESSION_PKT)//会话完成
		{
		    FFWD_DBG(FFWD_DBG_DEBUG, "Payload 8K  |packet 1024   upload..\n");
			//print_session_node(session_desc);
			session_desc = session_node_del(session_desc);
			//ASSERT(session_desc);
			if (session_desc == NULL)
				return;
			merge_two_diections_pkt(session_desc);
			//print_merged_session_node(session_desc);	
			SMA_COUNTER_DEC(gmac1_active_sessions);
			
			stlc_list_add_tail(&session_desc->nd_list, &dma_list);
			return;
		}

		return;
	}
 cleanup:
	SMA_COUNTER_INC(gmac1_session_dis_packets);
	drop_session_pkt(pkt);
	return;
	
}

//超时消息低32位为节点地址，有可能此节点已经删除，需要再次查找哈希表确认
static inline void ffwd_recv_time_out_msg(u8 code, u64 msg)
{
	session_desc_t *node = (session_desc_t *)(u32)msg;
	
    FFWD_DBG(FFWD_DBG_DEBUG, " session timeout upload..\n");
	node = session_node_del(node);
	if(node == NULL)
		return;
	print_session_node(node);
	merge_two_diections_pkt(node);
	print_merged_session_node(node);
	SMA_COUNTER_DEC(gmac1_active_sessions);
	
	if (node->pkt == NULL || node->total_paylen == 0)//如果节点没有数据报文，不应该插入到提交队列
	{
		ffwd_drop_session_node(node);
		return;
	}
	//ffwd_upload_session_pkts(node);
	stlc_list_add_tail(&node->nd_list, &dma_list);
}

//! 会话版本的UDP通道处理函数
void ffwd_udp_pkt_input(xls_packet_t *pkt, u32 ch_id)
{
	dma_hdr_t *sess_node;
	dma_pkt_t *pkt_node;
	entry_state_desc_t*rx_desc;
	u32 index;
	u32 daddr;
	u32 ret;
	
	if(rx_queue_pause[ch_id] == 0)
    {		
        FFWD_DBG(FFWD_DBG_DEBUG, "dma_dropped_udp\n");
        SMA_COUNTER_INC(gmac1_dma_dropped_udp);
        return;
    }

	if ((ffwd_dma_queue+ ch_id)->rx_dma_base == 0)
	{
	    SMA_COUNTER_INC(gmac1_dma_dropped_udp);
		return;
    }
    
	rx_desc = ffwd_udp_state_base+ ch_id * sizeof(entry_state_desc_t) * MAXNUM_UDP_ENTRY;
	spin_lock(&session_channel_lock[ch_id]);
	index = channel_offset[ch_id];
	if (rx_desc[index].state == FIFO_WRITABLE)
	{
		channel_offset[ch_id] = (index + 1) & MAXNUM_UDP_ENTRY_MASK;
	}
	else 
	{
		SMA_COUNTER_INC(gmac1_dma_dropped_udp);
		spin_unlock(&session_channel_lock[ch_id]);
		FFWD_DBG(FFWD_DBG_DEBUG, "channel[%d] full, status[%d] %d\n", 
			ch_id, index, rx_desc[index].state);
		return;//直接返回无需释放，还需要后续处理
	}
	spin_unlock(&session_channel_lock[ch_id]);
	daddr = (ffwd_dma_queue + ch_id)->rx_dma_base + index * PKT_UDP_SIZE + DMA_OFFSET;
	FFWD_DBG(FFWD_DBG_DEBUG, "channel %d daddr %#x, status[%d] %d\n", 
		ch_id, daddr, index, rx_desc[index].state);
		
	sess_node = (dma_hdr_t *)(pkt->pkt_data + PKT_RESERVE_SIZE - sizeof(dma_hdr_t));
	memset((void *)sess_node, 0, sizeof(dma_hdr_t));

	barrier();

	//构建struct dma_hdr_t
	sess_node->sip = __swab32(pkt->key.sip);
	sess_node->dip = __swab32(pkt->key.dip);
	sess_node->sport = __swab16(pkt->key.sport);
	sess_node->dport= __swab16(pkt->key.dport);
	sess_node->protocol= __swab16(pkt->protocol);
	sess_node->total_paylen = __swab16(pkt->pkt_len);
	sess_node->pkt_num= __swab16(1);
	sess_node->teid = __swab32(pkt->teid);
	
	//构建struct dma_pkt_t
	pkt_node = (dma_pkt_t *)(pkt->pkt_data + PKT_RESERVE_SIZE + pkt->pkt_len);
	
	pkt_node->sequence= __swab32(pkt->seq);
	pkt_node->ack_seq = __swab32(pkt->ack);
	pkt_node->payload_len = __swab16(pkt->data_len);
	pkt_node->data_offset = 0;
	pkt_node->direction= __swab16(pkt->direction);
    pkt_node->smac = __swab64(pkt->smac);
    pkt_node->dmac = __swab64(pkt->dmac);

	ffwd_msg_send_to_dma(TRUE, igrid_to_bucket[process_id], virt_to_phys(sess_node), 
			daddr, pkt->pkt_len + sizeof(dma_hdr_t) + sizeof(dma_pkt_t), 1, PCIE_RX_BUCKET_ID);
	ret = wait_dma_rsp_msg();
	if (ret == 0)
	{
		SMA_COUNTER_INC(gmac1_dma_udp);
		rx_desc[index].state = FIFO_READABLE;
		FFWD_DBG(FFWD_DBG_DEBUG, "channel %d, status[%d] %d\n", 
			ch_id, index, rx_desc[index].state );
	}
	return;
}


void ffwd_recv_session_msg(u32 srcid, u64 msg)
{
    xls_packet_t *pkt;
    u8 *recv_data;
    struct ip *iph;
    struct tcphdr *tcp_hdr;
    struct udphdr *udp_hdr;
    struct ether_header * eth_hdr;
    u16 ether_type;

    
    recv_data = (u8*)phys_to_virt((u32)GET_RX_MSG_DATA(msg));
    pkt = (xls_packet_t *)((u32)recv_data & MASK_2K_ALIGN);
    //预取到cache
    prefetch(Pref_Prep_For_Store, pkt);
    ((u64 *)pkt)[0] = 0;
    ((u64 *)pkt)[1] = 0;
    ((u64 *)pkt)[2] = 0;
    ((u64 *)pkt)[3] = 0;
    ((u64 *)pkt)[4] = 0;
    ((u64 *)pkt)[5] = 0;
    ((u64 *)pkt)[6] = 0;
    ((u64 *)pkt)[7] = 0;

    barrier();
#if 0
    if (GET_RX_MSG_LEN(msg) < 64 || IS_RX_MSG_ERROR(msg))
    {
        FFWD_DBG(FFWD_DBG_INFO, "pkt len too short...\n");
        goto cleanup;
    }
#endif
    pkt->data = recv_data;
    pkt->pkt_len = pkt->data_len = GET_RX_MSG_LEN(msg) - CRC_SIZE;

    //RX 统计pps bps 
    SMA_COUNTER_INC(gmac1_rx_packets);
    SMA_COUNTER_COUNT(gmac1_rx_bytes, (pkt->pkt_len + CRC_SIZE));

    //printk("pid %02d  addr %p len %u \n", process_id, recv_data, pkt->pkt_len);
    dump_mem_info(pkt->pkt_data+PKT_RESERVE_SIZE, pkt->pkt_len);
    
   	eth_hdr = (struct ether_header *)(pkt->data);
	pkt->smac = *(u64*)(eth_hdr->ether_shost)&0xffffffffffff0000ULL;
	pkt->dmac = *(u64*)(eth_hdr->ether_dhost)&0xffffffffffff0000ULL;
    pkt->data += 12; 
    pkt->data_len -= 12; 

    // 多层VLAN 标签解析
    while (*((uint16_t *) pkt->data) == ETHERTYPE_8021Q)
    {
        pkt->data += 4;
        pkt->data_len -= 4;
    }
    
    ether_type = *(uint16_t *) pkt->data ;
    pkt->data += 2;
    pkt->data_len -= 2; 

    if(ether_type != ETHERTYPE_IP)
        goto cleanup;

    //data已经指向ip header
    iph = (struct ip *)(pkt->data);
    if ((pkt->data_len < IP_HLEN)
        || (iph->ip_v != 4)
        || (iph->ip_hl < 5))
    {
        goto cleanup;
    }
    
    if ((pkt->data_len < iph->ip_len) || (pkt->data_len < (iph->ip_hl << 2)))
    {       
        goto cleanup;
    }
    

    if (pkt->data_len > iph->ip_len)//帧填充
    {
        FFWD_DBG(FFWD_DBG_DEBUG, "pkt %p trim data_len %d ip_len %d\n", pkt, pkt->data_len, iph->ip_len);
        pkt->pkt_len -= (pkt->data_len - iph->ip_len);//报文总长度需要减去帧填充长度
        pkt->data_len = iph->ip_len;
        FFWD_DBG(FFWD_DBG_DEBUG, "pkt %p after trim pkt_len %d data_len %d ip_len %d\n", 
            pkt, pkt->pkt_len, pkt->data_len, iph->ip_len);
    }
    
    if((iph->ip_off & IP_OFFMASK )||(iph->ip_off & IP_MF))
    {
        goto cleanup;
    }
    pkt->key.sip = iph->ip_src;
    pkt->key.dip = iph->ip_dst;
    pkt->protocol = iph->ip_p;

	//pkt->teid = iph->ip_sum |(iph->ip_ttl<<16)|(iph->ip_tos<<24);

    pkt->data += iph->ip_hl << 2;//skip ip header
    pkt->data_len -= iph->ip_hl << 2;
    
    
    
    if(iph->ip_p == IPPROTO_UDP)
    {
        udp_hdr = (struct udphdr *)(pkt->data);
        pkt->key.sport= udp_hdr->uh_sport;
        pkt->key.dport = udp_hdr->uh_dport;
        pkt->seq = 0;
        pkt->ack = 0;
        pkt->data += sizeof(struct udphdr);//skip udp header
        pkt->data_len -= sizeof(struct udphdr);
        SMA_COUNTER_INC(gmac1_udp_packets);
        
        pkt->hash = session_hash(&(pkt->key));
        FFWD_DBG(FFWD_DBG_DEBUG, "pkt %p data %p pkt_len %u data_len %u hash %#x seq %x, nseq %x\n", 
            pkt, pkt->data, pkt->pkt_len, pkt->data_len, pkt->hash, pkt->seq, pkt->nseq);

        ffwd_udp_pkt_input(pkt, CHANNEL_UDP);
        
        SMA_COUNTER_DEC(gmac1_session_dis_packets);
        goto cleanup;
    }
    else if(iph->ip_p == IPPROTO_TCP)
    {
        tcp_hdr = (struct tcp_hdr*)(pkt->data);
        if (tcp_hdr->th_off < 5 
            || pkt->data_len < (tcp_hdr->th_off<<2)
            || pkt->data_len < 20)
        {
            FFWD_DBG(FFWD_DBG_INFO, "tcp header len error ...\n");
            //print_pkt(pkt->pkt_data+PKT_RESERVE_SIZE, pkt->pkt_len);
            goto cleanup;
        }

        pkt->data += tcp_hdr->th_off << 2;//skip tcp header, data指针已经指向tcp payload
        pkt->data_len -= tcp_hdr->th_off << 2;
        pkt->key.sport = tcp_hdr->th_sport;
        pkt->key.dport = tcp_hdr->th_dport;

        
        pkt->th_flags = tcp_hdr->th_flags;
        pkt->seq = tcp_hdr->th_seq;
        pkt->nseq = pkt->seq + pkt->data_len;//date_len 需要除去tcp header(syn报文需要+1?)
        if (pkt->th_flags & TH_SYN)
            pkt->nseq += 1;
        pkt->ack= tcp_hdr->th_ack;
        SMA_COUNTER_INC(gmac1_tcp_packets);   
        

        pkt->hash = session_hash(&(pkt->key));
        FFWD_DBG(FFWD_DBG_DEBUG, "pkt %p data %p pkt_len %u data_len %u hash %#x seq %x, nseq %x\n", 
            pkt, pkt->data, pkt->pkt_len, pkt->data_len, pkt->hash, pkt->seq, pkt->nseq);

        ffwd_session_pkt_input(pkt);
        return ;
    }
    else 
    {
        FFWD_DBG(FFWD_DBG_DEBUG, "not tcp/udp pkt, drop...\n");
        SMA_COUNTER_INC(gmac1_dropped_packets);
        goto cleanup;
    }   
 cleanup:
    //FFWD_DBG(FFWD_DBG_DEBUG, "unkown ethernet type : 0x%04x\n", ethhdr->ether_type);
    SMA_COUNTER_INC(gmac1_session_dis_packets);
    drop_session_pkt(pkt);
    return;
    
}


int set_session_desc_for_dma(session_desc_t *node)
{
	entry_state_desc_t * rx_desc;
	u8 ch_id;
	u32 daddr;
	u32 index;
	
    ch_id = pde_vc[node->hash & 127];

	if(rx_queue_pause[ch_id] == 0)
    {
        SMA_COUNTER_INC(gmac1_dma_dropped_session);
        return ERROR;
    }
  
	rx_desc = ffwd_session_state_base + ch_id * sizeof(entry_state_desc_t) * MAXNUM_SESSION_ENTRY;
	spin_lock(&session_channel_lock[ch_id]);
	index = channel_offset[ch_id];
	if (rx_desc[index].state == FIFO_WRITABLE)
	{
		channel_offset[ch_id] = (index + 1) & (MAXNUM_SESSION_ENTRY -1);
	}
	else 
	{
		SMA_COUNTER_INC(gmac1_dma_dropped_session);
		spin_unlock(&session_channel_lock[ch_id]);
		FFWD_DBG(FFWD_DBG_DEBUG, "channel[%d] full, status[%d] %d\n", 
			ch_id, index, rx_desc[index].state);
		return ERROR;
	}
	spin_unlock(&session_channel_lock[ch_id]);
	daddr = (ffwd_dma_queue + ch_id)->rx_dma_base + index * PKT_SESSION_SIZE + DMA_OFFSET;	

	node->dma_base = daddr;//保存dma地址
	node->dma_in = index;
	node->rx_desc = rx_desc;
	node->dma_pkt = node->pkt;
	barrier();
	
	FFWD_DBG(FFWD_DBG_DEBUG, "channel[%d]: pkt->dma_base_addr %#x, status[%d] %d, new offset %u\n", 
		ch_id, node->dma_base, index, rx_desc[index].state, channel_offset[ch_id]);
	return OK;
}


void ffwd_dma_task()
{
	dma_hdr_t *node;
	
	if (dma_node == NULL)//如果当前提交节点为空(节点提交完必须置空)，从提交链表里取第一个节点，如果提交链表为空，则返回
	{	
	    
		if(stlc_list_empty(&dma_list))
		{
		    //DMA 会话列表为空直接返回 
		    return;
		}
		//从DMA 会话列表获取第一条会话
		dma_node = stlc_list_first_entry(&dma_list, session_desc_t,nd_list);
		if (set_session_desc_for_dma(dma_node) < 0)
		{
		    //如果没有取得dma目的地址(可能fifo满)，将提交节点置空，返回不提交
			stlc_list_del(&(dma_node->nd_list));//从提交链表里删除
			ffwd_drop_session_node(dma_node);
			barrier();
			dma_node = NULL;//注意必须将当前提交节点置为空,以提交下一个会话节点
			return;
		}
		
		ASSERT(dma_node->dma_base);
		ASSERT(dma_node->dma_pkt);
		ASSERT(dma_node->pkt_num);
		ASSERT(dma_node->total_paylen);
		stlc_list_del(&(dma_node->nd_list));//从提交链表里删除

        dma_pkt_array_ptr = dma_pkt_array;
        dma_node->dma_total_paylen = 0;
		//构造会话节点信息并提交
		node = (dma_hdr_t *)(dma_node->dma_pkt->pkt_data + PKT_RESERVE_SIZE - sizeof(dma_hdr_t));//第一个报文预留的64字节
		node->sip = __swab32(dma_node->key.sip);
		node->dip = __swab32(dma_node->key.dip);
		node->sport = __swab16(dma_node->key.sport);
		node->dport = __swab16(dma_node->key.dport);
		node->protocol = __swab16(dma_node->protocol);
		node->stop_sec = __swab16(dma_node->stop_sec);
		node->total_paylen = __swab16(dma_node->total_paylen);
        node->pkt_num = __swab16(dma_node->pkt_num);
        node->hash = __swab32(dma_node->hash);
		node->teid = __swab32(dma_node->teid);

        barrier();
		FFWD_DBG(FFWD_DBG_DEBUG, "dma dma_hdr_t total_paylen %u  Host_ADDR = %08x\n",
		                node->total_paylen,dma_node->dma_base);
		ffwd_msg_send_to_dma(0, igrid_to_bucket[process_id], virt_to_phys(node), 
			            dma_node->dma_base, sizeof(dma_hdr_t), 1, PCIE_RX_BUCKET_ID);
	    
		dma_node->dma_base += sizeof(dma_hdr_t);
	    return;
	}

	if (dma_node->dma_pkt)
	{	
		FFWD_DBG(FFWD_DBG_DEBUG, "dma pkt_num %u current pkt(NO:%u) , host_addr %08x\n",
			dma_node->pkt_num, dma_node->dma_pkt->de_num, dma_node->dma_base);

        barrier();
            
		ffwd_msg_send_to_dma(1, igrid_to_bucket[process_id], virt_to_phys((void *)(dma_node->dma_pkt->data)), 
		    dma_node->dma_base,dma_node->dma_pkt->data_len, 1, PCIE_RX_BUCKET_ID);
		wait_dma_rsp_msg();
		
        dma_pkt_array_ptr->sequence= __swab32(dma_node->dma_pkt->seq);
		dma_pkt_array_ptr->ack_seq = __swab32(dma_node->dma_pkt->ack);
		dma_pkt_array_ptr->payload_len = __swab16(dma_node->dma_pkt->data_len);
		dma_pkt_array_ptr->direction= __swab16(dma_node->dma_pkt->direction);
        dma_pkt_array_ptr->data_offset = __swab32(dma_node->dma_total_paylen);
        dma_pkt_array_ptr->smac = __swab64(dma_node->dma_pkt->smac);
        dma_pkt_array_ptr->dmac = __swab64(dma_node->dma_pkt->dmac);
		dma_pkt_array_ptr++;

		dma_node->dma_total_paylen +=  dma_node->dma_pkt->data_len;
		dma_node->dma_base += dma_node->dma_pkt->data_len;
		dma_node->dma_pkt = dma_node->dma_pkt->next_pkt;
		
		return;
	}
	else
	{
	    //提交各个报文的描述结构
		ffwd_msg_send_to_dma(1, igrid_to_bucket[process_id], virt_to_phys(dma_pkt_array), dma_node->dma_base,
						dma_node->pkt_num * sizeof(dma_pkt_t), 1, PCIE_RX_BUCKET_ID);
		wait_dma_rsp_msg();
	
	    SMA_COUNTER_INC(gmac1_dma_session);
		dma_node->rx_desc[dma_node->dma_in].state = FIFO_READABLE;
		FFWD_DBG(FFWD_DBG_DEBUG, "DMA Finished rx_desc[%u].state = %u\n",
		    dma_node->dma_in,dma_node->rx_desc[dma_node->dma_in].state);
		ffwd_drop_session_node(dma_node);
		barrier();
		dma_node = NULL;//注意必须将当前提交节点置为空,以提交下一个会话节点
	
		return;
	}
}

static inline void ffwd_free_time_out_msg(u64 msg)
{
	session_desc_t *node = (session_desc_t *)(u32)msg;

	node = session_node_del(node);
	if(node == NULL)
		return;
	ffwd_drop_session_node(node);
}
/*
 * insert a freed packet back to the free packets list
 */
void inline free_packet(struct packet_s * p){
//	FFWD_DBG(0, "free packet called, packet id = %u\n", p->id);
	stlc_list_add(&(p->node), &free_packets_list);
//	FFWD_DBG(0, "free packet finished, packet id = %u\n", p->id);
}

/*
 * get a free packet from the double linked free packets list
 */
struct packet_s * get_free_packet(){
	struct packet_s * result;
	if(free_packets_list.next == &free_packets_list){
		result = NULL;
	} else {
		struct stlc_list_head * tmp = free_packets_list.next;
		stlc_list_del(free_packets_list.next);
//		if(tmp == free_packets_list.next){
//			FFWD_DBG(0, "node not deleted from free packets list\n");
//		} else {
//			FFWD_DBG(0, "node deleted from free packets list\n");
//		}
		result = (struct packet_s *) tmp;
//		FFWD_DBG(0, "packet id = %u\n", result->id);
	}
	return result;
}

/* 
 * free a big packet
 */
void inline free_big_packet(struct big_packet * p){
	stlc_list_add(&(p->node), &big_packets_list);
}

/*
 * get a big packet
 */
struct big_packet * get_big_packet(){
	struct big_packet * result = NULL;
	if(big_packets_list.next == &big_packets_list){
		result = NULL;
	} else {
		result = (struct big_packet *) big_packets_list.next;
		stlc_list_del(big_packets_list.next);
	}
	return result;
}

void inline dma_pkt_asy(u8 * data, u16 len){
	spin_lock(&rx_desc_lock);
	u32 daddr;
	if(ffwd_mac_entry_desc_rx[rx_offset].state == FIFO_WRITABLE){
		FFWD_DBG(0, "state is FIFO_WRITABLE\n");
		if(free_dma_count_list.next == &free_dma_count_list){
			FFWD_DBG(0, "free dma count list is empty!\n");
		} else {
			struct dma_count_s * tmp = (struct dma_count_s *) free_dma_count_list.next;
			tmp->data = data;
			stlc_list_del(free_dma_count_list.next);
			stlc_list_add_tail(&(tmp->node), &(dma_data_list));
			
			tmp = (struct dma_count_s *) free_dma_count_list.next;
			tmp->count = 1;
			tmp->len = len;
			tmp->offset = rx_offset;
			stlc_list_del(free_dma_count_list.next);
			stlc_list_add_tail(&(tmp->node), &(dma_count_list));
			daddr = __swab32(ffwd_mac_entry_desc_rx[rx_offset].address);
			ffwd_msg_send_to_dma(1, igrid_to_bucket[process_id], virt_to_phys(data), daddr, len, 1, PCIE_RX_BUCKET_ID);
			rx_offset = (rx_offset + 1) & (MAC_ENTRY_DESC_NUM -1);
		}
	} else {
		ffwd_mac_counter->rx_dropped++;
		FFWD_DBG(0, "state is not FIFO_WRITABLE, rx_dropped = %d\n", ffwd_mac_counter->rx_dropped);
	}
	spin_unlock(&rx_desc_lock);
}

static void inline dma_pkt_load_balance(u8 * data, u16 len){
	// add dma balance msg to dma_balance_list, then wait for dma return
	int idx = process_id - FIRST_SESSION_THREAD;
	if(free_dma_balance_list[idx].next != &(free_dma_balance_list[idx])){
		FFWD_DBG(0, "free_dma_balance_list[%d] is not empty\n", idx);
		if(tlro_rx_entry_desc[idx][dma_balance_rx_offset[idx]].state == FIFO_WRITABLE){
			FFWD_DBG(0, "tlro_rx_entry_desc[%d][%d] state is FIFO_WRITABLE\n", idx, dma_balance_rx_offset[idx]);
			
			spin_lock(&(free_dma_balance_list_lock[idx]));
			struct dma_balance_msg_s * bmsg = (struct dma_balance_msg_s *) (free_dma_balance_list[idx].next);
			stlc_list_del(&(bmsg->node));
			spin_unlock(&(free_dma_balance_list_lock[idx]));
			
			bmsg->data = data;
			bmsg->len = len;
			bmsg->daddr = __swab32(tlro_rx_entry_desc[idx][dma_balance_rx_offset[idx]].address);
			spin_lock(&(dma_balance_list_lock[idx]));
			stlc_list_add_tail(&(bmsg->node), &(dma_balance_list[idx]));
			spin_unlock(&(dma_balance_list_lock[idx]));
			
			u32 ret = wait_dma_rsp_msg();
			if(ret == 0){
				tlro_rx_entry_desc[idx][dma_balance_rx_offset[idx]].len = __swab16(len);
				tlro_rx_entry_desc[idx][dma_balance_rx_offset[idx]].state = FIFO_READABLE;
				FFWD_DBG(0, "dma packet to host succeeded\n");
				
				ffwd_mac_interrupt_host();
				dma_balance_rx_offset[idx] = (dma_balance_rx_offset[idx] + 1) & (MAC_ENTRY_DESC_NUM - 1);
				barrier();
			} else {
				FFWD_DBG(0, "dma packet to host failed\n");
				printk("process %d: dma packet to host failed\n", process_id);
			}
		} else {
			FFWD_DBG(0, "tlro_rx_entry_desc[%d][%d] state is not FIFO_WRITABLE\n", idx, dma_balance_rx_offset[idx]);
			printk("process %d: tlro rx entry desc[%d][%d] state is not FIFO_WRITABLE\n", process_id, idx, dma_balance_rx_offset[idx]);
		}
	} else {
		FFWD_DBG(0, "free_dma_balance_list[%d] is empty!\n", idx);
		printk("process %d: free dma balance list is empty!\n", process_id);
	}
}

void dma_pkt_multi_rxring(u8 * data, u16 len){
	u32 daddr;
	FFWD_DBG(0, "tlro_rx_offset = %d\n", tlro_rx_offset);
	int idx = process_id - FIRST_SESSION_THREAD;
	if(tlro_rx_entry_desc[idx][tlro_rx_offset].state == FIFO_WRITABLE){
		FFWD_DBG(0, "state is FIFO_WRITABLE\n");
		daddr = __swab32(tlro_rx_entry_desc[idx][tlro_rx_offset].address);
		ffwd_msg_send_to_dma(1, igrid_to_bucket[process_id], virt_to_phys(data), daddr, len, 1, PCIE_RX_BUCKET_ID);
		u32 ret = wait_dma_rsp_msg();
		if(ret == 0){
			tlro_rx_entry_desc[idx][tlro_rx_offset].len = __swab16(len);
			tlro_rx_entry_desc[idx][tlro_rx_offset].state = FIFO_READABLE;
			FFWD_DBG(0, "dma packet to host succeed\n");
			
			ffwd_mac_interrupt_host();
			tlro_rx_offset = (tlro_rx_offset + 1) & (MAC_ENTRY_DESC_NUM - 1);
			barrier();
		} else {
			FFWD_DBG(0, "dma packet to host failed\n");
		}
	} else {
		FFWD_DBG(0, "state is not FIFO_WRITABLE\n");
	}
}
void dma_pkt(u8 * data, u16 len){
	spin_lock(&rx_desc_lock);
	FFWD_DBG(0, "locked rx_desc_lock\n");
	u32 daddr;
	FFWD_DBG(0, "rx_offset = %u\n", rx_offset);
	if(ffwd_mac_entry_desc_rx[rx_offset].state == FIFO_WRITABLE){
		FFWD_DBG(0, "state is FIFO_WRITABLE\n");
		daddr = __swab32(ffwd_mac_entry_desc_rx[rx_offset].address);
		ffwd_msg_send_to_dma(1, igrid_to_bucket[process_id], virt_to_phys(data), daddr, len, 1, PCIE_RX_BUCKET_ID);
		u32 ret = wait_dma_rsp_msg();
		if(ret == 0){
			ffwd_mac_counter->rx_packets++;
			ffwd_mac_counter->rx_bytes += len;
			ffwd_mac_entry_desc_rx[rx_offset].len = __swab16(len);
			ffwd_mac_entry_desc_rx[rx_offset].state = FIFO_READABLE;
			FFWD_DBG(0, "dma packet succeed, rx_packets = %d\n", ffwd_mac_counter->rx_packets);
										
			ffwd_mac_interrupt_host();
										    
			rx_offset = (rx_offset + 1) & (MAC_ENTRY_DESC_NUM -1);
			barrier();
		} else {
			ffwd_mac_counter->rx_dropped++;
			FFWD_DBG(0, "dma packet failed, rx_dropped = %d\n", ffwd_mac_counter->rx_dropped);
		}
	} else {
		ffwd_mac_counter->rx_dropped++;
		FFWD_DBG(0, "state is not FIFO_WRITABLE, rx_dropped = %d\n", ffwd_mac_counter->rx_dropped);
	}
	spin_unlock(&rx_desc_lock);
	FFWD_DBG(0, "unlocked rx_desc_lock\n");
}

/*
 * checks if a packet matches a tcp session descriptor
 * return 1 if matches, return 0 instead
 */
int tlro_check_tcp_conn(struct tlro_desc * desc, struct ip * ipheader, struct tcphdr * tcpheader){
	if(desc->key.sip == ipheader->ip_src &&
			desc->key.dip == ipheader->ip_dst &&
			desc->key.sport == tcpheader->th_sport &&
			desc->key.dport == tcpheader->th_dport){
		return 1;
	} else {
		return 0;
	}
}
static inline struct tlro_desc * find_session_node(struct packet_s * p){
	struct tlro_desc * node = NULL;
	struct stlc_hlist_node * tmp = NULL;
	stlc_hlist_for_each_entry(node, tmp, &(session_buckets[p->hash]), nd_hlist){
		if(node->active){
			struct ip * ipheader = (struct ip *) (p->data + SIZEOF_ETHERHEADER);
			struct tcphdr * tcpheader = (struct tcphdr *) (p->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
			if(tlro_check_tcp_conn(node, ipheader, tcpheader)){
//				FFWD_DBG(0, "sip = %u, dip = %u, sport = %u, dport = %u\n", node->key.sip, node->key.dip, node->key.sport, node->key.dport);
//				FFWD_DBG(0, "physical address of desc is %u\n", virt_to_phys(node));
				return node;
			}
		}
	}
	return NULL;
}

// called when after flush aggregated packets, but tcp connection remains
static void inline reset_session_desc(struct tlro_desc * desc){
	desc->ip_total_len = 0;
	desc->packets.next = desc->packets.prev = &(desc->packets);
	desc->packets_count = 0;
}

// called when when received FIN packet and tcp connection is tared down
static void inline free_session_desc(struct tlro_desc * desc){
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
	stlc_hlist_del(&(desc->nd_hlist));
	stlc_list_add(&(desc->node), &session_desc_list_head);
}

static struct tlro_desc * get_session_desc(){
	struct tlro_desc * result = NULL;
	if(session_desc_list_head.next == &session_desc_list_head){
		return NULL;
	} else {
		struct stlc_list_head * tmp = session_desc_list_head.next;
		stlc_list_del(tmp);
		result = (struct tlro_desc *) tmp;
		result->active = 1;
		return result;
	}
}
void print_desc(struct tlro_desc * desc){
	if(desc){
//		FFWD_DBG(0, "physical address of desc is %u, id = %u\n", virt_to_phys(desc), desc->id);
		FFWD_DBG(0, "active = %d\n ip_total_len = %u\n sip = %u, dip = %u, sport = %u, dport = %u\n pid = %d\n ack = %u, next_seq = %u, rcv_tsecr = %u, rcv_tsval = %u\n saw_stamp = %u window = %u, tick = %u\n", 
				desc->active, 
				desc->ip_total_len, 
				desc->key.sip,
				desc->key.dip,
				desc->key.sport,
				desc->key.dport,
				desc->pid,
				desc->tcp_ack,
				desc->tcp_next_seq,
				desc->tcp_rcv_tsecr,
				desc->tcp_rcv_tsval,
				desc->tcp_saw_tstamp,
				desc->tcp_window,
				desc->tick);
		FFWD_DBG(0, "packets count = %u\n", desc->packets_count);
		if(desc->packets.next == &(desc->packets)){
			FFWD_DBG(0, "packets list is empty\n");
		} else {
			FFWD_DBG(0, "packets list is not empty\n");
		}
	} else {
		FFWD_DBG(0, "pointer is NULL\n");
	}
}

void print_prepad(struct prepad_struct * pre){
	FFWD_DBG(0, "seq no = %u, use bucket = %u, bucket = %u, ip header checksum valid = %u, tcp checksum valid = %u\n",
			get_seq_no(pre),
			get_use_bucket(pre),
			get_bucket(pre),
			get_ip_header_csum_valid(pre),
			get_l4_csum_valid(pre));
	FFWD_DBG(0, "extract 0 = %u, extract 1 = %u, extract 2 = %u, extract 3 = %u\n",
			get_extract_0(pre),
			get_extract_1(pre),
			get_extract_2(pre),
			get_extract_3(pre));
}

void tlro_flush_dmaqueue(struct tlro_desc * desc){
	FFWD_DBG(0, "---------------------------------------------------------------------- tlro_flush_dmaqueue called\n");
	if(desc->active == 0){
		FFWD_DBG(0, "desc not active\n");
		return;
	}
	
	if(desc->packets_count){
		if(desc->packets_count > 1){
			/* update tcp and ip header */
			// record packets' payload data one complement sum
			u16 a[100];
			int i = 0;
			struct stlc_list_head * tmp = desc->packets.next;
			while(tmp != &(desc->packets)){
				a[i] = ((struct packet_s *) tmp)->data_sum;
				i++;
				tmp = tmp->next;
			}
			FFWD_DBG(0, "i = %d, packets count = %u\n", i, desc->packets_count);
						
			/*
			* set tcp header
			* set sequence number to the first packet's sequence number
			* set ack to the last packet's ack
			* set window size to the last packet's window size
			* set checksum
			* set tcp_rcv_tsecr if timestamp option enabled
			* set ip header
			* set 16 bit total length
			* set 16 bit checksum
			*/
			struct packet_s * first = (struct packet_s *) desc->packets.next;
			struct ip * ipheader = (struct ip *) (first->data + SIZEOF_ETHERHEADER);
			struct tcphdr * tcpheader = (struct tcphdr *) (first->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
			tcpheader->th_ack = desc->tcp_ack;
			tcpheader->th_win = desc->tcp_window;
			if(desc->tcp_saw_tstamp){
				u32 * opt = (u32 *) (tcpheader + 1);
				*(opt + 2) = desc->tcp_rcv_tsecr;
			}
			ipheader->ip_len = desc->ip_total_len;
			PsdHeader psd_header;
			psd_header.saddr = ipheader->ip_src;
			psd_header.daddr = ipheader->ip_dst;
			psd_header.mbz = 0;
			psd_header.ptcl = 6;
			psd_header.tcpl = ipheader->ip_len - ipheader->ip_hl * 4;
			a[i] = one_complement_sum((u16 *) (&psd_header), sizeof(PsdHeader));
			i++;
			tcpheader->th_sum = 0;
			a[i] = one_complement_sum((u16 *) (tcpheader), tcpheader->th_off * 4);
			i++;
			tcpheader->th_sum = ~add_one_complement_sum(a, i);
			ipheader->ip_sum = 0;
			ipheader->ip_sum = check_sum(first->data + SIZEOF_ETHERHEADER, 20);
		}
		
		// send msg with code packets_count and virtual address of the first packet to host
		struct packet_s * first = (struct packet_s *) (desc->packets.next);
		stlc_list_del(&(desc->packets));
		u64 msg = (((u64) desc->pid) << 32) | ((u64) (u32) first);
		if(free_dma_msg_list.next == &free_dma_msg_list){
			FFWD_DBG(0, "free dma msg list is empty!\n");
		} else {
			struct dma_msg_s * dmamsg = (struct dma_msg_s *) free_dma_msg_list.next;
			dmamsg->code = desc->packets_count;
			dmamsg->pid = process_id;
			dmamsg->msg = msg;
			stlc_list_del(free_dma_msg_list.next);
			spin_lock(&dma_msg_list_lock);
			stlc_list_add_tail(&(dmamsg->node), &dma_msg_list);
			spin_unlock(&dma_msg_list_lock);
		}
	} else {
		FFWD_DBG(0, "desc empty packets list\n");
	}
	reset_session_desc(desc);
	FFWD_DBG(0, "---------------------------------------------------------------------- tlro flush dmaqueue finished\n");
}
// TCP报文乱序重组时不拷贝数据，将多次DMA任务交给scan process进行
void tlro_flush_pipeline(struct tlro_desc * desc){
	FFWD_DBG(0, "---------------------------------------------------------------------- tlro_flush_pipeline called\n");
	if(desc->active == 0){
		FFWD_DBG(0, "desc not active\n");
		return;
	}
	
	if(desc->packets_count){
		if(desc->packets_count > 1){
			/* update tcp and ip header */
			// record packets' payload data one complement sum
			u16 a[100];
			int i = 0;
			struct stlc_list_head * tmp = desc->packets.next;
			while(tmp != &(desc->packets)){
				a[i] = ((struct packet_s *) tmp)->data_sum;
				i++;
				tmp = tmp->next;
			}
			FFWD_DBG(0, "i = %d, packets count = %u\n", i, desc->packets_count);
						
			/*
			* set tcp header
			* set sequence number to the first packet's sequence number
			* set ack to the last packet's ack
			* set window size to the last packet's window size
			* set checksum
			* set tcp_rcv_tsecr if timestamp option enabled
			* set ip header
			* set 16 bit total length
			* set 16 bit checksum
			*/
			struct packet_s * first = (struct packet_s *) desc->packets.next;
			struct ip * ipheader = (struct ip *) (first->data + SIZEOF_ETHERHEADER);
			struct tcphdr * tcpheader = (struct tcphdr *) (first->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
			tcpheader->th_ack = desc->tcp_ack;
			tcpheader->th_win = desc->tcp_window;
			if(desc->tcp_saw_tstamp){
				u32 * opt = (u32 *) (tcpheader + 1);
				*(opt + 2) = desc->tcp_rcv_tsecr;
			}
			ipheader->ip_len = desc->ip_total_len;
			PsdHeader psd_header;
			psd_header.saddr = ipheader->ip_src;
			psd_header.daddr = ipheader->ip_dst;
			psd_header.mbz = 0;
			psd_header.ptcl = 6;
			psd_header.tcpl = ipheader->ip_len - ipheader->ip_hl * 4;
			a[i] = one_complement_sum((u16 *) (&psd_header), sizeof(PsdHeader));
			i++;
			tcpheader->th_sum = 0;
			a[i] = one_complement_sum((u16 *) (tcpheader), tcpheader->th_off * 4);
			i++;
			tcpheader->th_sum = ~add_one_complement_sum(a, i);
			ipheader->ip_sum = 0;
			ipheader->ip_sum = check_sum(first->data + SIZEOF_ETHERHEADER, 20);
		}
		
		// send msg with code packets_count and virtual address of the first packet to host
		struct packet_s * first = (struct packet_s *) (desc->packets.next);
		stlc_list_del(&(desc->packets));
		u64 msg = (((u64) desc->pid) << 32) | ((u64) (u32) first);
		if(ffwd_message_send_code_1(desc->packets_count, igrid_to_bucket[1], msg) != 0){
			FFWD_DBG(0, "send msg to scan process failed\n");
		} else {
			FFWD_DBG(0, "send msg to scan process succeed\n");
		}
	} else {
		FFWD_DBG(0, "desc empty packets list\n");
	}
	reset_session_desc(desc);
	FFWD_DBG(0, "---------------------------------------------------------------------- tlro flush pipeline finished\n");
}
void tlro_flush_asy(struct tlro_desc * desc){
	FFWD_DBG(0, "---------------------------------------------------------------------- tlro flush asy called\n");
	if(desc->active == 0){
		FFWD_DBG(0, "desc not active\n");
		return;
	}
	
	if(desc->packets_count){
		if(desc->packets_count == 1){
			// only one packet
			FFWD_DBG(0, "only one packet\n");
			struct packet_s * first = (struct packet_s *) desc->packets.next;
			dma_pkt_asy(first->data, first->len);
			stlc_list_del(&(first->node));
			free_packet(first);
		} else {
			// update tcp and ip header
			// record packets' payload data one complement sum
			u16 a[100];
			int i = 0;
			struct stlc_list_head * tmp = desc->packets.next;
			while(tmp != &(desc->packets)){
				a[i] = ((struct packet_s *) tmp)->data_sum;
				i++;
				tmp = tmp->next;
			}
			FFWD_DBG(0, "i = %d, packets count = %u\n", i, desc->packets_count);
			
			/*
			* set tcp header
			* set sequence number to the first packet's sequence number
			* set ack to the last packet's ack
			* set window size to the last packet's window size
			* set checksum
			* set tcp_rcv_tsecr if timestamp option enabled
			* set ip header
			* set 16 bit total length
			* set 16 bit checksum
			*/
			struct packet_s * first = (struct packet_s *) desc->packets.next;
			struct ip * ipheader = (struct ip *) (first->data + SIZEOF_ETHERHEADER);
			struct tcphdr * tcpheader = (struct tcphdr *) (first->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
			tcpheader->th_ack = desc->tcp_ack;
			tcpheader->th_win = desc->tcp_window;
			if(desc->tcp_saw_tstamp){
				u32 * opt = (u32 *) (tcpheader + 1);
				*(opt + 2) = desc->tcp_rcv_tsecr;
			}
			ipheader->ip_len = desc->ip_total_len;
			PsdHeader psd_header;
			psd_header.saddr = ipheader->ip_src;
			psd_header.daddr = ipheader->ip_dst;
			psd_header.mbz = 0;
			psd_header.ptcl = 6;
			psd_header.tcpl = ipheader->ip_len - ipheader->ip_hl * 4;
			a[i] = one_complement_sum((u16 *) (&psd_header), sizeof(PsdHeader));
			i++;
			tcpheader->th_sum = 0;
			a[i] = one_complement_sum((u16 *) (tcpheader), tcpheader->th_off * 4);
			i++;
			tcpheader->th_sum = ~add_one_complement_sum(a, i);
			ipheader->ip_sum = 0;
			ipheader->ip_sum = check_sum(first->data + SIZEOF_ETHERHEADER, 20);
			
			// only need to dma the first packet
			if(free_dma_count_list.next == &free_dma_count_list){
				FFWD_DBG(0, "free dma count list is empty!\n");
			} else {
				struct dma_count_s * tmp = (struct dma_count_s *) free_dma_count_list.next;
				tmp->data = first->data;
				stlc_list_del(free_dma_count_list.next);
				stlc_list_add_tail(&(tmp->node), &(dma_data_list));
				
				tmp = (struct dma_count_s *) free_dma_count_list.next;
				tmp->count = desc->packets_count;
				tmp->len = desc->ip_total_len + SIZEOF_ETHERHEADER;
				tmp->offset = desc->rxoffset;
				stlc_list_del(free_dma_count_list.next);
				stlc_list_add_tail(&(tmp->node), &(dma_count_list));
			}
			u32 base = __swab32(ffwd_mac_entry_desc_rx[desc->rxoffset].address);
			ffwd_msg_send_to_dma(1, igrid_to_bucket[process_id], virt_to_phys(first->data), base, first->len, 1, PCIE_RX_BUCKET_ID);
			// free packets
			while(desc->packets.next != &(desc->packets)){
				tmp = (struct stlc_list_head *) desc->packets.next;
				stlc_list_del(tmp);
				stlc_list_add_tail(tmp, &free_packets_list);
			}
		}
	} else {
		FFWD_DBG(0, "desc empty packets list\n");
	}
	
	reset_session_desc(desc);
	FFWD_DBG(0, "---------------------------------------------------------------------- tlro flush asy finished\n");
}

void tlro_flush_dma_load_balance(struct tlro_desc * desc){
	FFWD_DBG(0, "---------------------------------------------------------------------- tlro flush dma load balance called\n");
	if(desc->active == 0){
		FFWD_DBG(0, "desc not active\n");
		return;
	}
	
	if(desc->packets_count){
		FFWD_DBG(0, "desc packet list not empty\n");
		if(desc->packets_count == 1){
			// only one packet
			FFWD_DBG(0, "only one packet\n");
			struct packet_s * first = (struct packet_s *) desc->packets.next;
			dma_pkt_load_balance(first->data, first->len);
			u64 msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(first->data));
			message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
			stlc_list_del(&(first->node));
			free_packet(first);
		} else {
			// record packets' payload data one complement sum
			u16 a[100];
			int i = 0;
			struct stlc_list_head * tmp = desc->packets.next;
			while(tmp != &(desc->packets)){
				a[i] = ((struct packet_s *) tmp)->data_sum;
				i++;
				tmp = tmp->next;
			}
			FFWD_DBG(0, "i = %d, packets count = %u\n", i, desc->packets_count);
			
			/*
			* set tcp header
			* set sequence number to the first packet's sequence number
			* set ack to the last packet's ack
			* set window size to the last packet's window size
			* set checksum
			* set tcp_rcv_tsecr if timestamp option enabled
			* set ip header
			* set 16 bit total length
			* set 16 bit checksum
			*/
			struct packet_s * first = (struct packet_s *) desc->packets.next;
			struct ip * ipheader = (struct ip *) (first->data + SIZEOF_ETHERHEADER);
			struct tcphdr * tcpheader = (struct tcphdr *) (first->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
			tcpheader->th_ack = desc->tcp_ack;
			tcpheader->th_win = desc->tcp_window;
//			if(desc->tcp_saw_tstamp){
//				u32 * opt = (u32 *) (tcpheader + 1);
//				*(opt + 2) = desc->tcp_rcv_tsecr;
//			}
			ipheader->ip_len = desc->ip_total_len;
			PsdHeader psd_header;
			psd_header.saddr = ipheader->ip_src;
			psd_header.daddr = ipheader->ip_dst;
			psd_header.mbz = 0;
			psd_header.ptcl = 6;
			psd_header.tcpl = ipheader->ip_len - ipheader->ip_hl * 4;
			a[i] = one_complement_sum((u16 *) (&psd_header), sizeof(PsdHeader));
			i++;
			tcpheader->th_sum = 0;
			a[i] = one_complement_sum((u16 *) (tcpheader), tcpheader->th_off * 4);
			i++;
			tcpheader->th_sum = ~add_one_complement_sum(a, i);
			ipheader->ip_sum = 0;
			ipheader->ip_sum = check_sum(first->data + SIZEOF_ETHERHEADER, 20);
			
			// dma packets
			FFWD_DBG(0, "tlro_rx_offset = %d\n", tlro_rx_offset);
			int idx = process_id - FIRST_SESSION_THREAD;
			if(tlro_rx_entry_desc[idx][dma_balance_rx_offset[idx]].state == FIFO_WRITABLE){
				FFWD_DBG(0, "tlro_rx_entry_desc[%d][%d] state is FIFO_WRITABLE\n", idx, dma_balance_rx_offset[idx]);
				u32 base = __swab32(tlro_rx_entry_desc[idx][dma_balance_rx_offset[idx]].address);
				u32 len = 0;
				int flag = 1;
				
				// dma the first packet
				if(free_dma_balance_list[idx].next != &(free_dma_balance_list[idx])){
					FFWD_DBG(0, "free_dma_balance_list[%d] is not empty\n", idx);
					spin_lock(&(free_dma_balance_list_lock[idx]));
					struct dma_balance_msg_s * bmsg = (struct dma_balance_msg_s *) (free_dma_balance_list[idx].next);
					stlc_list_del(&(bmsg->node));
					spin_unlock(&(free_dma_balance_list_lock[idx]));
					
					bmsg->data = first->data;
					bmsg->len = first->len;
					bmsg->daddr = base;
					
					spin_lock(&(dma_balance_list_lock[idx]));
					stlc_list_add_tail(&(bmsg->node), &(dma_balance_list[idx]));
					spin_unlock(&(dma_balance_list_lock[idx]));
					
					u32 ret = wait_dma_rsp_msg();
					if(ret != 0){
						flag = 0;
						FFWD_DBG(0, "dma packet failed\n");
					}
					len += first->len;
					// free packet data memory
					u64 msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(first->data));
					message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
					// free packet_s data structure
					stlc_list_del(&(first->node));
					free_packet(first);
					
					// dma other packets' data
					while(desc->packets.next != &(desc->packets)){
						first = (struct packet_s *) desc->packets.next;
						ipheader = (struct ip *) (first->data + SIZEOF_ETHERHEADER);
						tcpheader = (struct tcphdr *) (first->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
						u16 payload_len = TCP_PAYLOAD_LENGTH(ipheader, tcpheader);
						u8 * payload_data = first->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4 + tcpheader->th_off * 4;
						
						if(free_dma_balance_list[idx].next != &(free_dma_balance_list[idx])){
							FFWD_DBG(0, "free_dma_balance_list[%d] is not empty\n", idx);
							spin_lock(&(free_dma_balance_list_lock[idx]));
							bmsg = (struct dma_balance_msg_s *) (free_dma_balance_list[idx].next);
							stlc_list_del(&(bmsg->node));
							spin_unlock(&(free_dma_balance_list_lock[idx]));
							
							bmsg->data = payload_data;
							bmsg->len = payload_len;
							bmsg->daddr = base + len;
							
							spin_lock(&(dma_balance_list_lock[idx]));
							stlc_list_add_tail(&(bmsg->node), &(dma_balance_list[idx]));
							spin_unlock(&(dma_balance_list_lock[idx]));
							
							ret = wait_dma_rsp_msg();
							if(ret != 0){
								flag = 0;
								FFWD_DBG(0, "dma packet failed\n");
							}
							len += payload_len;
							// free packet data memory
							u64 msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(first->data));
							message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
							// free packet_s data structure
							stlc_list_del(&(first->node));
							free_packet(first);
						} else {
							FFWD_DBG(0, "free_dma_balance_list[%d] is empty!\n", idx);
							printk("process %d: free dma balance list is empty!\n", process_id, idx);
							flag = 0;
						}
					}
				} else {
					FFWD_DBG(0, "free_dma_balance_list[%d] is empty\n", idx);
					printk("process %d: free dma balance list[%d] is empty\n", process_id, idx);
					flag = 0;
				}
				if(flag){
					tlro_rx_entry_desc[idx][dma_balance_rx_offset[idx]].state = FIFO_READABLE;
					tlro_rx_entry_desc[idx][dma_balance_rx_offset[idx]].len = __swab16(len);
					
					ffwd_mac_interrupt_host();
					dma_balance_rx_offset[idx] = (dma_balance_rx_offset[idx] + 1) & (MAC_ENTRY_DESC_NUM - 1);
					barrier();
				} else {
					FFWD_DBG(0, "flag is 0, dma big packet failed\n");
					printk("process %d: flag is 0, dma big packet failed\n", process_id);
				}
			} else {
				FFWD_DBG(0, "tlro_rx_entry_desc[%d][%d] state is not FIFO_WRITABLE\n", idx, dma_balance_rx_offset[idx]);
				printk("process %d: tlro rx entry desc[%d][%d] state is not FIFO WRITABLE, flush failed\n", process_id, idx, dma_balance_rx_offset[idx]);
			}
		}
	} else {
		FFWD_DBG(0, "desc empty packets list\n");
	}
	
	reset_session_desc(desc);
	FFWD_DBG(0, "---------------------------------------------------------------------- tlro flush dma load balance finished\n");
}
void tlro_flush_multi_rxring(struct tlro_desc * desc){
	FFWD_DBG(0, "---------------------------------------------------------------------- tlro flush multi rxring called\n");
	if(desc->active == 0){
		FFWD_DBG(0, "desc not active\n");
		return;
	}
	
	if(desc->packets_count){
		FFWD_DBG(0, "desc packet list not empty\n");
		if(desc->packets_count == 1){
			// only one packet
			FFWD_DBG(0, "only one packet\n");
			struct packet_s * first = (struct packet_s *) desc->packets.next;
			dma_pkt_multi_rxring(first->data, first->len);
			u64 msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(first->data));
			message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
			stlc_list_del(&(first->node));
			free_packet(first);
		} else {
			// record packets' payload data one complement sum
			u16 a[100];
			int i = 0;
			struct stlc_list_head * tmp = desc->packets.next;
			while(tmp != &(desc->packets)){
				a[i] = ((struct packet_s *) tmp)->data_sum;
				i++;
				tmp = tmp->next;
			}
			FFWD_DBG(0, "i = %d, packets count = %u\n", i, desc->packets_count);
			
			/*
			* set tcp header
			* set sequence number to the first packet's sequence number
			* set ack to the last packet's ack
			* set window size to the last packet's window size
			* set checksum
			* set tcp_rcv_tsecr if timestamp option enabled
			* set ip header
			* set 16 bit total length
			* set 16 bit checksum
			*/
			struct packet_s * first = (struct packet_s *) desc->packets.next;
			struct ip * ipheader = (struct ip *) (first->data + SIZEOF_ETHERHEADER);
			struct tcphdr * tcpheader = (struct tcphdr *) (first->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
			tcpheader->th_ack = desc->tcp_ack;
			tcpheader->th_win = desc->tcp_window;
//			if(desc->tcp_saw_tstamp){
//				u32 * opt = (u32 *) (tcpheader + 1);
//				*(opt + 2) = desc->tcp_rcv_tsecr;
//			}
			ipheader->ip_len = desc->ip_total_len;
			PsdHeader psd_header;
			psd_header.saddr = ipheader->ip_src;
			psd_header.daddr = ipheader->ip_dst;
			psd_header.mbz = 0;
			psd_header.ptcl = 6;
			psd_header.tcpl = ipheader->ip_len - ipheader->ip_hl * 4;
			a[i] = one_complement_sum((u16 *) (&psd_header), sizeof(PsdHeader));
			i++;
			tcpheader->th_sum = 0;
			a[i] = one_complement_sum((u16 *) (tcpheader), tcpheader->th_off * 4);
			i++;
			tcpheader->th_sum = ~add_one_complement_sum(a, i);
			ipheader->ip_sum = 0;
			ipheader->ip_sum = check_sum(first->data + SIZEOF_ETHERHEADER, 20);
			
			// dma packets
			FFWD_DBG(0, "tlro_rx_offset = %d\n", tlro_rx_offset);
			int idx = process_id - FIRST_SESSION_THREAD;
			if(tlro_rx_entry_desc[idx][tlro_rx_offset].state == FIFO_WRITABLE){
				FFWD_DBG(0, "state is FIFO_WRITABLE\n");
				u32 base = __swab32(tlro_rx_entry_desc[idx][tlro_rx_offset].address);
				u32 len = 0;
				
				// dma the first packet
				ffwd_msg_send_to_dma(1, igrid_to_bucket[process_id], virt_to_phys(first->data), base, first->len, 1, PCIE_RX_BUCKET_ID);
				u32 ret = wait_dma_rsp_msg();
				int flag = 1;
				if(ret != 0){
					flag = 0;
					FFWD_DBG(0, "dma packet failed\n");
				}
				len += first->len;
				// free packet data memory
				u64 msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(first->data));
				message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
				// free packet_s data structure
				stlc_list_del(&(first->node));
				free_packet(first);
				
				// dma other packets' data
				while(desc->packets.next != &(desc->packets)){
					first = (struct packet_s *) desc->packets.next;
					ipheader = (struct ip *) (first->data + SIZEOF_ETHERHEADER);
					tcpheader = (struct tcphdr *) (first->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
					u16 payload_len = TCP_PAYLOAD_LENGTH(ipheader, tcpheader);
					u8 * payload_data = first->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4 + tcpheader->th_off * 4;
					ffwd_msg_send_to_dma(1, igrid_to_bucket[process_id], virt_to_phys(payload_data), base + len, payload_len, 1, PCIE_RX_BUCKET_ID);
					ret = wait_dma_rsp_msg();
					if(ret != 0){
						flag = 0;
						FFWD_DBG(0, "dma packet failed\n");
					}
					len += payload_len;
					// free packet data memory
					u64 msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(first->data));
					message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
					// free packet_s data structure
					stlc_list_del(&(first->node));
					free_packet(first);
				}
				if(flag){
					tlro_rx_entry_desc[idx][tlro_rx_offset].len = __swab16(len);
					tlro_rx_entry_desc[idx][tlro_rx_offset].state = FIFO_READABLE;
					
					ffwd_mac_interrupt_host();
					tlro_rx_offset = (tlro_rx_offset + 1) & (MAC_ENTRY_DESC_NUM - 1);
					barrier();
				} else {
					FFWD_DBG(0, "flag is 0, dma big packet failed\n");
				}
			} else {
				FFWD_DBG(0, "state is not FIFO_WRITABLE\n");
			}
		}
	} else {
		FFWD_DBG(0, "desc empty packets list\n");
	}
	
	reset_session_desc(desc);
	FFWD_DBG(0, "---------------------------------------------------------------------- tlro flush multi rxring finished\n");
}
// TCP报文乱序重组时不拷贝数据，多次DMA
void tlro_flush(struct tlro_desc * desc){
	FFWD_DBG(0, "---------------------------------------------------------------------- tlro flush called\n");
	if(desc->active == 0){
		FFWD_DBG(0, "desc not active\n");
		return;
	}
	
	if(desc->packets_count){
		FFWD_DBG(0, "desc packet list not empty\n");
		if(desc->packets_count == 1){
			// only one packet
			FFWD_DBG(0, "only one packet\n");
			struct packet_s * first = (struct packet_s *) desc->packets.next;
			dma_pkt(first->data, first->len);
			u64 msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(first->data));
			message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
			stlc_list_del(&(first->node));
			free_packet(first);
		} else {
			// record packets' payload data one complement sum
			u16 a[100];
			int i = 0;
			struct stlc_list_head * tmp = desc->packets.next;
			while(tmp != &(desc->packets)){
				a[i] = ((struct packet_s *) tmp)->data_sum;
				i++;
				tmp = tmp->next;
			}
			FFWD_DBG(0, "i = %d, packets count = %u\n", i, desc->packets_count);
			
			/*
			* set tcp header
			* set sequence number to the first packet's sequence number
			* set ack to the last packet's ack
			* set window size to the last packet's window size
			* set checksum
			* set tcp_rcv_tsecr if timestamp option enabled
			* set ip header
			* set 16 bit total length
			* set 16 bit checksum
			*/
			struct packet_s * first = (struct packet_s *) desc->packets.next;
			struct ip * ipheader = (struct ip *) (first->data + SIZEOF_ETHERHEADER);
			struct tcphdr * tcpheader = (struct tcphdr *) (first->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
			tcpheader->th_ack = desc->tcp_ack;
			tcpheader->th_win = desc->tcp_window;
			if(desc->tcp_saw_tstamp){
				u32 * opt = (u32 *) (tcpheader + 1);
				*(opt + 2) = desc->tcp_rcv_tsecr;
			}
			ipheader->ip_len = desc->ip_total_len;
			PsdHeader psd_header;
			psd_header.saddr = ipheader->ip_src;
			psd_header.daddr = ipheader->ip_dst;
			psd_header.mbz = 0;
			psd_header.ptcl = 6;
			psd_header.tcpl = ipheader->ip_len - ipheader->ip_hl * 4;
			a[i] = one_complement_sum((u16 *) (&psd_header), sizeof(PsdHeader));
			i++;
			tcpheader->th_sum = 0;
			a[i] = one_complement_sum((u16 *) (tcpheader), tcpheader->th_off * 4);
			i++;
			tcpheader->th_sum = ~add_one_complement_sum(a, i);
			ipheader->ip_sum = 0;
			ipheader->ip_sum = check_sum(first->data + SIZEOF_ETHERHEADER, 20);
			
			// dma packets
			spin_lock(&rx_desc_lock);
			FFWD_DBG(0, "locked rx_desc lock\n");
			FFWD_DBG(0, "rx_offset = %u\n", rx_offset);
			if(ffwd_mac_entry_desc_rx[rx_offset].state == FIFO_WRITABLE){
				FFWD_DBG(0, "state is FIFO_WRITABLE\n");
				u32 base = __swab32(ffwd_mac_entry_desc_rx[rx_offset].address);
				u32 len = 0;
				
				// dma the first packet
				ffwd_msg_send_to_dma(1, igrid_to_bucket[process_id], virt_to_phys(first->data), base, first->len, 1, PCIE_RX_BUCKET_ID);
				u32 ret = wait_dma_rsp_msg();
				int flag = 1;
				if(ret != 0){
					flag = 0;
					FFWD_DBG(0, "dma packet failed\n");
				}
				len += first->len;
				// free packet data memory
				u64 msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(first->data));
				message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
				// free packet_s data structure
				stlc_list_del(&(first->node));
				free_packet(first);
				
				// dma other packets' data
				while(desc->packets.next != &(desc->packets)){
					first = (struct packet_s *) desc->packets.next;
					ipheader = (struct ip *) (first->data + SIZEOF_ETHERHEADER);
					tcpheader = (struct tcphdr *) (first->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
					u16 payload_len = TCP_PAYLOAD_LENGTH(ipheader, tcpheader);
					u8 * payload_data = first->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4 + tcpheader->th_off * 4;
					ffwd_msg_send_to_dma(1, igrid_to_bucket[process_id], virt_to_phys(payload_data), base + len, payload_len, 1, PCIE_RX_BUCKET_ID);
					ret = wait_dma_rsp_msg();
					if(ret != 0){
						flag = 0;
						FFWD_DBG(0, "dma packet failed\n");
					}
					len += payload_len;
					// free packet data memory
					u64 msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(first->data));
					message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
					// free packet_s data structure
					stlc_list_del(&(first->node));
					free_packet(first);
				}
				if(flag){
					ffwd_mac_counter->rx_packets++;
					ffwd_mac_counter->rx_bytes += len;
					ffwd_mac_entry_desc_rx[rx_offset].len = __swab16(len);
					ffwd_mac_entry_desc_rx[rx_offset].state = FIFO_READABLE;
					FFWD_DBG(0, "dma packets succeed, rx_packets = %d\n", ffwd_mac_counter->rx_packets);
															
					ffwd_mac_interrupt_host();
															    
					rx_offset = (rx_offset + 1) & (MAC_ENTRY_DESC_NUM -1);
					barrier();
				} else {
					FFWD_DBG(0, "flag is 0, dma packets failed\n");
				}
			} else {
				ffwd_mac_counter->rx_dropped++;
				FFWD_DBG(0, "state is not FIFO_WRITABLE, rx_dropped = %d\n", ffwd_mac_counter->rx_dropped);
			}
			spin_unlock(&rx_desc_lock);
			FFWD_DBG(0, "unlocked rx_desc_lock\n");
		}
	} else {
		FFWD_DBG(0, "desc empty packets list\n");
	}
	
//	free_session_desc(desc);
	reset_session_desc(desc);
	FFWD_DBG(0, "---------------------------------------------------------------------- tlro flush finished\n");
}
// TCP报文乱序重组时拷贝数据
void tlro_flush_simple(struct tlro_desc * desc){
	FFWD_DBG(0, "tlro flush simple called\n");
	if(desc->active == 0){
		FFWD_DBG(0, "desc not active\n");
		return;
	}
	
	if(desc->packets.next != &(desc->packets)){
		FFWD_DBG(0, "desc packet list not empty\n");
		if(desc->packets.next->next == &(desc->packets)){
			// only one packet
			FFWD_DBG(0, "only one packet\n");
			struct packet_s * first = (struct packet_s *) desc->packets.next;
			dma_pkt(first->data, first->len);
			u64 msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(first->data));
			message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
			stlc_list_del(&(first->node));
			free_packet(first);
		} else {
			struct big_packet * p = get_big_packet();
			if(!p){
				FFWD_DBG(0, "can not get big packet!\n");
				return;
			} else {
				FFWD_DBG(0, "got big packet\n");
			}
			
			// record packets' payload data one complement sum
			u16 a[100];
			int i = 0;
			struct stlc_list_head * tmp = desc->packets.next;
			while(tmp != &(desc->packets)){
				a[i] = ((struct packet_s *) tmp)->data_sum;
				i++;
				tmp = tmp->next;
			}
			if(i != desc->packets_count){
				FFWD_DBG(0, "bug in recording packets's payload data one complement sum\n");
			}
			
			// copy the first packet's data
			p->len = 0;
			struct packet_s * first = (struct packet_s *) desc->packets.next;
			memcpy(p->data, first->data, first->len);
			p->len += first->len;
			struct ip * ipheader = NULL;
			struct tcphdr * tcpheader = NULL;
//			ipheader = (struct ip *) (first->data + SIZEOF_ETHERHEADER);
//			tcpheader = (struct tcphdr *) (first->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
//			FFWD_DBG(0, "before data copy, tcpheader length = %u, ipheader length = %u\n", tcpheader->th_off * 4, ipheader->ip_hl * 4);
//			ipheader = (struct ip *) (p->data + SIZEOF_ETHERHEADER);
//			tcpheader = (struct tcphdr *) (p->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
//			FFWD_DBG(0, "after data copy, tcpheader length = %u, ip header length = %u\n", tcpheader->th_off * 4, ipheader->ip_hl * 4);
			
			// free packet data memory
			u64 msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(first->data));
			message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
			// free packet_s data structure
			stlc_list_del(&(first->node));
			free_packet(first);
			// copy the other packets' data
			while(desc->packets.next != &(desc->packets)){
				first = (struct packet_s *) desc->packets.next;
				ipheader = (struct ip *) (first->data + SIZEOF_ETHERHEADER);
				tcpheader = (struct tcphdr *) (first->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
				u16 payload_len = TCP_PAYLOAD_LENGTH(ipheader, tcpheader);
				u8 * payload_data = first->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4 + tcpheader->th_off * 4;
				memcpy(p->data + p->len, payload_data, payload_len);
				p->len += payload_len;
				// free packet data memory
				msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(first->data));
				message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
				FFWD_DBG(FFWD_DBG_DEBUG, "sent GMAC0_FR msg after dma packet to host\n");
				// free packet_s data structure
				stlc_list_del(&(first->node));
				free_packet(first);
			}
			
			/*
			 * set tcp header
			 * set sequence number to the first packet's sequence number
			 * set ack to the last packet's ack
			 * set window size to the last packet's window size
			 * set checksum
			 * set tcp_rcv_tsecr if timestamp option enabled
			 * set ip header
			 * set 16 bit total length
			 * set 16 bit checksum
			 */
			ipheader = (struct ip *) (p->data + SIZEOF_ETHERHEADER);
			tcpheader = (struct tcphdr *) (p->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
			tcpheader->th_ack = desc->tcp_ack;
			FFWD_DBG(0, "before set window, tcp header length = %u\n", tcpheader->th_off * 4);
			tcpheader->th_win = desc->tcp_window;
			FFWD_DBG(0, "after set window, tcp header length = %u\n", tcpheader->th_off * 4);
			if(desc->tcp_saw_tstamp){
				u32 * opt = (u32 *) (tcpheader + 1);
				*(opt + 2) = desc->tcp_rcv_tsecr;
			}
			ipheader->ip_len = desc->ip_total_len;
			PsdHeader psd_header;
			psd_header.saddr = ipheader->ip_src;
			psd_header.daddr = ipheader->ip_dst;
			psd_header.mbz = 0;
			psd_header.ptcl = 6;
			psd_header.tcpl = ipheader->ip_len - ipheader->ip_hl * 4;
			u16 checksum;
//			tcpheader->th_sum = 0;/* set 0 for calculation */
//			checksum = tcp_checksum(&psd_header, p->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4, ipheader->ip_len - ipheader->ip_hl * 4);
//			tcpheader->th_sum = checksum;
			
//			FFWD_DBG(0, "old calculated tcp checksum = %u\n", checksum);
			FFWD_DBG(0, "ip total length = %u, ip header length = %u, tcp header length = %u\n", ipheader->ip_len, ipheader->ip_hl * 4, tcpheader->th_off * 4);
			
			a[i] = one_complement_sum((u16 *) (&psd_header), sizeof(PsdHeader));
			i++;
			tcpheader->th_sum = 0;
			a[i] = one_complement_sum((u16 *) (tcpheader), tcpheader->th_off * 4);
			i++;
			checksum = ~add_one_complement_sum(a, i);
			FFWD_DBG(0, "new calculated tcp checksum = %u\n", checksum);
			tcpheader->th_sum = checksum;
			
			ipheader->ip_sum = 0;
			checksum = check_sum(p->data + SIZEOF_ETHERHEADER, 20);
			ipheader->ip_sum = checksum;
			
			// dma the big packet to host
			FFWD_DBG(0, "dma the big packet to host\n");
			dma_pkt(p->data, p->len);
			free_big_packet(p);
		}
	} else {
		FFWD_DBG(0, "desc empty packet list\n");
	}
	
//	free_session_desc(desc);
	reset_session_desc(desc);
	FFWD_DBG(0, "tlro flush simple finished\n");
}

/*
 * Basic tcp checks whether packet is suitable for LRO
 * return 1 if suitable, return 0 instead
 */
static int tlro_check_packet(struct packet_s * p, struct tlro_desc * desc){
	struct ip * ipheader = (struct ip *) (p->data + SIZEOF_ETHERHEADER);
	struct tcphdr * tcpheader = (struct tcphdr *) (p->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
	
	/* check ip header, do not aggregate padded frames */
	if(ipheader->ip_len != p->len - SIZEOF_ETHERHEADER){
		FFWD_DBG(0, "------------------- padded ip frame\n");
		return 0;
	}
	
	u8 flags = tcpheader->th_flags;
	if(flags & TH_FIN){
		FFWD_DBG(0, "------------ fin set\n");
		return 0;
	} else if(flags & TH_SYN){
		FFWD_DBG(0, "------------ syn set\n");
		return 0;
	} else if(flags & TH_RST){
		FFWD_DBG(0, "----------- RST set\n");
		return 0;
	} else if(flags & TH_URG){
		FFWD_DBG(0, "------------- urgent bit set\n");
		return 0;
	} else if(!(flags & TH_ACK)){
		FFWD_DBG(0, "------------------ ack not set\n");
		return 0;
	}
	
//	if(TCP_PAYLOAD_LENGTH(ipheader, tcpheader) == 0){
//		FFWD_DBG(0, "-------------------- tcp payload length = 0\n");
//		return 0;
//	}
	if(ipheader->ip_hl != IPH_LEN_WO_OPTIONS){
		FFWD_DBG(0, "------------------- ip header with options\n");
		return 0;
	}
	
	if(INET_ECN_is_ce(ipheader->ip_tos)){
		FFWD_DBG(0, "INET_ECN_is_ce\n");
		return 0;
	}
	if(tcpheader->th_off != TCPH_LEN_WO_OPTIONS && tcpheader->th_off != TCPH_LEN_W_TIMESTAMP){
		FFWD_DBG(0, "tcp header length = %d\n", tcpheader->th_off * 4);
		return 0;
	}
	
	/* check tcp options, only timestamp allowed */
	if(tcpheader->th_off == TCPH_LEN_W_TIMESTAMP){
		FFWD_DBG(0, "header with timestamp option\n");
		u32 * topt = (u32 *) (tcpheader + 1);
		if(*topt != ((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) | (TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP)){
			FFWD_DBG(0, "kind and len values not correct\n");
			return 0;
		}
		/* timestamp should be in right order */
		++topt;
		if(desc && ((signed int) (*topt - desc->tcp_rcv_tsval)) < 0){
			FFWD_DBG(0, "timestamp not in right order\n");
			return 0;
		}
		/* timestamp reply should not be 0 */
		++topt;
		if(*topt == 0){
			FFWD_DBG(0, "timestamp reply is 0\n");
			return 0;
		}
	}
	
	return 1;
}

/*
 * send ack for received tcp data packets
 */
void inline send_ack(struct packet_s * p, struct tlro_desc * desc){
	if(ack_packets_list.next == &(ack_packets_list)){
		FFWD_DBG(0, "---------------------------------------- ack packets list empty!!\n");
		printk("process %d: ack packets list empty!\n", process_id);
	} else {
		struct ack_packet_s * ack_packet = (struct ack_packet_s *) (ack_packets_list.next);
		stlc_list_del(&(ack_packet->node));
		struct ether_header * etherheader1 = (struct ether_header *) (p->data);
		struct ip * ipheader1 = (struct ip *) (p->data + SIZEOF_ETHERHEADER);
		struct tcphdr * tcpheader1 = (struct tcphdr *) (p->data + SIZEOF_ETHERHEADER + ipheader1->ip_hl * 4);
		struct ether_header * etherheader = (struct ether_header *) (ack_packet->data);
		struct ip * ipheader = (struct ip *) (ack_packet->data + SIZEOF_ETHERHEADER);
		struct tcphdr * tcpheader = (struct tcphdr *) (ack_packet->data + 34);
		
		/*
		 * construct the ack packet
		 * ETHER HEADER: switch SMAC and DMAC, set ether_type to 0x0800
		 * IP HEADER: 
		 * 		set 4 bits version to 4
		 * 		set 4 bits header length to 5
		 * 		set 8 bits TOS to 0
		 * 		set 16 bits total length to 40 or 52
		 * 		set 16 bits id to 0
		 * 		set 3 bits flag and 13 bits offset to 0x4000
		 * 		set 8 bits TTL and 8 bits protocol to 0x4006
		 * 		set 16 bits checksum
		 * 		switch SIP and DIP
		 * TCP HEADER:
		 * 		switch sport and dport
		 * 		set 32 bits sequence number to desc->tcp_ack
		 * 		set 32 bits ack to p->sequence + TCP_PAYLOAD_LENGTH
		 * 		set 4 bits header length and 6 bits reserved and 6 bits flags to 0x5010 or 0x8010
		 * 		set 16 bits checksum
		 * 		set 16 bits emergency pointer to 0
		 */
		etherheader->ether_type = 0x0800;
		memcpy(etherheader->ether_dhost, etherheader1->ether_shost, 6);
		memcpy(etherheader->ether_shost, etherheader1->ether_dhost, 6);
		
		FFWD_DBG(0, "smac of received packet is:%02x %02x %02x %02x %02x %02x\n", 
				etherheader1->ether_shost[0],
				etherheader1->ether_shost[1],
				etherheader1->ether_shost[2],
				etherheader1->ether_shost[3],
				etherheader1->ether_shost[4],
				etherheader1->ether_shost[5]);
		FFWD_DBG(0, "dmac of received packet is:%02x %02x %02x %02x %02x%02x\n",
				etherheader1->ether_dhost[0],
				etherheader1->ether_dhost[1],
				etherheader1->ether_dhost[2],
				etherheader1->ether_dhost[3],
				etherheader1->ether_dhost[4],
				etherheader1->ether_dhost[5]);
		
		ipheader->ip_v = 4;
		ipheader->ip_hl = 5;
		ipheader->ip_tos = 0;
		if(desc->tcp_saw_tstamp){
			ipheader->ip_len = 52;
		} else {
			ipheader->ip_len = 40;
		}
		ipheader->ip_id = 0;
		ipheader->ip_off = 0x4000;
		ipheader->ip_ttl = 64;
		ipheader->ip_p = 6;
		ipheader->ip_src = ipheader1->ip_dst;
		ipheader->ip_dst = ipheader1->ip_src;
		ipheader->ip_sum = 0;
		ipheader->ip_sum = check_sum(ipheader, 20);
		
		tcpheader->th_sport = tcpheader1->th_dport;
		tcpheader->th_dport = tcpheader1->th_sport;
		tcpheader->th_seq = desc->tcp_ack;
		tcpheader->th_ack = tcpheader1->th_seq + TCP_PAYLOAD_LENGTH(ipheader1, tcpheader1);
		if(desc->tcp_saw_tstamp){
			tcpheader->th_off = 8;
			u32 * topt = (u32 *) (tcpheader + 1);
			u32 * topt1 = (u32 *) (tcpheader1 + 1);
			*topt = ((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) | (TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP);// set kind and len values
			*(topt + 1) = (*(topt1 + 2)) + 1;// set ack packet's timestamp to received packet's timestamp reply + 1
			*(topt + 2) = desc->ts_recent;// set ack packet's timestamp reply to ts_recent
		} else {
			tcpheader->th_off = 5;
		}
		tcpheader->th_flags = 16;
		tcpheader->th_win = 0xffff;
		tcpheader->th_urp = 0;
		tcpheader->th_sum = 0;
		PsdHeader psdheader;
		psdheader.saddr = ipheader->ip_src;
		psdheader.daddr = ipheader->ip_dst;
		psdheader.mbz = 0;
		psdheader.ptcl = 6;
		if(desc->tcp_saw_tstamp){
			psdheader.tcpl = 32;
			tcpheader->th_sum = tcp_checksum(&psdheader, tcpheader, 32);
		} else {
			psdheader.tcpl = 20;
			tcpheader->th_sum = tcp_checksum(&psdheader, tcpheader, 20);
		}
		
//		print_pkt(ack_packet->data, 54);
		
		// send to GMAC1 for transmission
		u64 msg;
		if(desc->tcp_saw_tstamp){
			msg = FMN_MAKE_TX_MSG(FMN_MSG_EOF, igrid_to_bucket[process_id], 66, virt_to_phys(ack_packet->data));
		} else {
			msg = FMN_MAKE_TX_MSG(FMN_MSG_EOF, igrid_to_bucket[process_id], 54, virt_to_phys(ack_packet->data));
		}
		if(ffwd_message_send_1(MSGRNG_STNID_GMAC1_TX0, msg)){
			SMA_COUNTER_INC(gmac0_tx_dropped_packets);
			FFWD_DBG(0, "send ack packet faild\n");
		} else {
			SMA_COUNTER_INC(gmac0_tx_packets);
			FFWD_DBG(0, "send ack packet ok\n");
		}
	}
}

void tlro_receive_packet_dmaqueue(struct packet_s * p){
	struct ip * ipheader = (struct ip *) (p->data + SIZEOF_ETHERHEADER);
	struct tcphdr * tcpheader = (struct tcphdr *) (p->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
	struct session_key key;
	key.sip = ipheader->ip_src;
	key.dip = ipheader->ip_dst;
	key.sport = tcpheader->th_sport;
	key.dport = tcpheader->th_dport;
	p->hash = session_hash(&key);
	FFWD_DBG(0, "src ip = %u, dst ip = %u, src port = %u, dst port = %u, tcp sequence number of the packet is %u\n", 
			key.sip, 
			key.dip,
			key.sport,
			key.dport,
			tcpheader->th_seq);
	
	struct tlro_desc * desc = find_session_node(p);
	if(desc){
		FFWD_DBG(0, "---------------------------- found desc, desc->tcp_next_seq = %u, tcp sequence number of the packet is %u\n", 
				desc->tcp_next_seq, 
				tcpheader->th_seq);
		if((tcpheader->th_flags & TH_ACK) && TCP_PAYLOAD_LENGTH(ipheader, tcpheader) == 0){
			// ack packet with no tcp data, probably because of tcp connection establishment, dma to host
			// send msg with code 0 and virtual address to scan process
			FFWD_DBG(0, "ack packet with no tcp data, probably because of tcp connection establishment, dma to host\n");
			if(desc->tcp_saw_tstamp){
				u32 * topt = (u32 *) (tcpheader + 1);
				desc->ts_recent = *(topt + 1);
			}
			FFWD_DBG(0, "dma packet data to host, send msg to scan process\n");
			u64 msg = (((u64) p->len) <<  32) | ((u64) (u32) p->data);
			if(free_dma_msg_list.next == &free_dma_msg_list){
				FFWD_DBG(0, "free dma msg list is empty!\n");
			} else {
				struct dma_msg_s * dmamsg = (struct dma_msg_s *) free_dma_msg_list.next;
				dmamsg->code = 0;
				dmamsg->pid = process_id;
				dmamsg->msg = msg;
				stlc_list_del(free_dma_msg_list.next);
				spin_lock(&dma_msg_list_lock);
				stlc_list_add_tail(&(dmamsg->node), &dma_msg_list);
				spin_unlock(&dma_msg_list_lock);
			}
			free_packet(p);
			return;
		}
		if(tlro_check_packet(p, desc) && desc->tcp_next_seq == tcpheader->th_seq){
			/* add packet to session descriptor, check if we need to flush the session descriptor */
			send_ack(p, desc);
			u32 tcp_data_len = TCP_PAYLOAD_LENGTH(ipheader, tcpheader);
			if(desc->packets_count == 0){
				// the first packet
				desc->ip_total_len = ipheader->ip_len;
			} else {
				desc->ip_total_len += tcp_data_len;
			}
			desc->tcp_next_seq += tcp_data_len;
			desc->tcp_window = tcpheader->th_win;
			desc->tcp_ack = tcpheader->th_ack;
			/* do not update tcp_rcv_tsval, would not work with PAWS */
			if(desc->tcp_saw_tstamp){
				u32 * topt = (u32 *) (tcpheader + 1);
				desc->tcp_rcv_tsecr = *(topt + 2);
				desc->ts_recent = *(topt + 1);
			}
			stlc_list_add_tail(&(p->node), &(desc->packets));
			FFWD_DBG(0, "------- tcp sequence number matched, added packet to list, ip total length = %d, tcp payload length = %d\n", desc->ip_total_len, tcp_data_len);
			desc->packets_count++;
			/* update desc's tick */
			desc->tick = read_32bit_cp0_register(CP0_COUNT);
			
			if(desc->ip_total_len > 0xffff - 1460){
				FFWD_DBG(0, "ip total length = %d, flush desc\n", desc->ip_total_len);
				/* flush the session descriptor */
				tlro_flush_dmaqueue(desc);
			}
		} else {
			FFWD_DBG(0, "tcp sequence number does not match, flush desc, dma packet to host\n");
			// flush the session descriptor
			tlro_flush_dmaqueue(desc);
			if((tcpheader->th_flags & TH_FIN) || (tcpheader->th_flags & TH_RST)){
				free_session_desc(desc);
			}
			
			// dma the packet to host, send msg with code 0 and virtual address to scan process
			FFWD_DBG(0, "dma packet data to host, send msg to scan process\n");
			u64 msg = (((u64) p->len) <<  32) | ((u64) (u32) p->data);
			if(free_dma_msg_list.next == &free_dma_msg_list){
				FFWD_DBG(0, "free dma msg list is empty!\n");
			} else {
				struct dma_msg_s * dmamsg = (struct dma_msg_s *) free_dma_msg_list.next;
				dmamsg->code = 0;
				dmamsg->pid = process_id;
				dmamsg->msg = msg;
				stlc_list_del(free_dma_msg_list.next);
				spin_lock(&dma_msg_list_lock);
				stlc_list_add_tail(&(dmamsg->node), &dma_msg_list);
				spin_unlock(&dma_msg_list_lock);
			}
			free_packet(p);
		}
	} else {
		FFWD_DBG(0, "------------------- not found desc\n");
		if(tcpheader->th_flags & TH_SYN){
			FFWD_DBG(0, "syn flag set, initialize desc\n");
			desc = get_session_desc();
			if(desc){
				desc->active = 1;
				desc->tick = read_32bit_cp0_register(CP0_COUNT);
				desc->pid = process_id;
				stlc_hlist_add_head(&(desc->nd_hlist), &(session_buckets[p->hash]));
						
				desc->ip_total_len = 0;
				desc->key = key;
				STLC_INIT_LIST_HEAD(&(desc->packets));
				desc->packets_count = 0;
				desc->tcp_ack = tcpheader->th_ack;
				desc->tcp_next_seq = tcpheader->th_seq + 1;// syn consumes one sequence number
				desc->tcp_window = tcpheader->th_win;
				if(tcpheader->th_off == 8){
					/* options with and with only timestamp */
					u32 * ptr = (u32 *) (tcpheader + 1);
					desc->tcp_saw_tstamp = 1;
					desc->tcp_rcv_tsval = *(ptr + 1);
					desc->tcp_rcv_tsecr = *(ptr + 2);
					desc->ts_recent = *(ptr + 1);
				}
				print_desc(desc);
			} else {
				FFWD_DBG(0, "-------------------- failed to get desc, dma packet to host\n");
			}
		} else {
			FFWD_DBG(0, "---------------------- this should not happen, packet not suitable for large receive offload, dma packet to host\n");
		}
		// dma packet data to host, send msg with code 0 and virtual address of data to scan process
		FFWD_DBG(0, "dma packet data to host, send msg to scan process\n");
		u64 msg = (((u64) p->len) <<  32) | ((u64) (u32) p->data);
		if(free_dma_msg_list.next == &free_dma_msg_list){
			FFWD_DBG(0, "free dma msg list is empty!\n");
		} else {
			struct dma_msg_s * dmamsg = (struct dma_msg_s *) free_dma_msg_list.next;
			dmamsg->code = 0;
			dmamsg->pid = process_id;
			dmamsg->msg = msg;
			stlc_list_del(free_dma_msg_list.next);
			spin_lock(&dma_msg_list_lock);
			stlc_list_add_tail(&(dmamsg->node), &dma_msg_list);
			spin_unlock(&dma_msg_list_lock);
		}
		free_packet(p);
	}
}
void tlro_receive_packet_pipeline(struct packet_s * p){
	struct ip * ipheader = (struct ip *) (p->data + SIZEOF_ETHERHEADER);
	struct tcphdr * tcpheader = (struct tcphdr *) (p->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
	struct session_key key;
	key.sip = ipheader->ip_src;
	key.dip = ipheader->ip_dst;
	key.sport = tcpheader->th_sport;
	key.dport = tcpheader->th_dport;
	p->hash = session_hash(&key);
	FFWD_DBG(0, "src ip = %u, dst ip = %u, src port = %u, dst port = %u, tcp sequence number of the packet is %u\n", 
			key.sip, 
			key.dip,
			key.sport,
			key.dport,
			tcpheader->th_seq);
	
	struct tlro_desc * desc = find_session_node(p);
	if(desc){
		FFWD_DBG(0, "---------------------------- found desc, desc->tcp_next_seq = %u, tcp sequence number of the packet is %u\n", 
				desc->tcp_next_seq, 
				tcpheader->th_seq);
		if((tcpheader->th_flags & TH_ACK) && TCP_PAYLOAD_LENGTH(ipheader, tcpheader) == 0){
			// ack packet with no tcp data, probably because of tcp connection establishment, dma to host
			// send msg with code 0 and virtual address to scan process
			FFWD_DBG(0, "ack packet with no tcp data, probably because of tcp connection establishment, dma to host\n");
			if(desc->tcp_saw_tstamp){
				u32 * topt = (u32 *) (tcpheader + 1);
				desc->ts_recent = *(topt + 1);
			}
			FFWD_DBG(0, "dma packet data to host, send msg to scan process\n");
			u64 msg = (((u64) p->len) <<  32) | ((u64) (u32) p->data);
			if(ffwd_message_send_code_1(0, igrid_to_bucket[1], msg) != 0){
				FFWD_DBG(0, "send msg to scan process failed\n");
			} else {
				FFWD_DBG(0, "send msg to scan process succeed\n");
			}
			free_packet(p);
			return;
		}
		if(tlro_check_packet(p, desc) && desc->tcp_next_seq == tcpheader->th_seq){
			/* add packet to session descriptor, check if we need to flush the session descriptor */
			send_ack(p, desc);
			u32 tcp_data_len = TCP_PAYLOAD_LENGTH(ipheader, tcpheader);
			if(desc->packets_count == 0){
				// the first packet
				desc->ip_total_len = ipheader->ip_len;
			} else {
				desc->ip_total_len += tcp_data_len;
			}
			desc->tcp_next_seq += tcp_data_len;
			desc->tcp_window = tcpheader->th_win;
			desc->tcp_ack = tcpheader->th_ack;
			/* do not update tcp_rcv_tsval, would not work with PAWS */
			if(desc->tcp_saw_tstamp){
				u32 * topt = (u32 *) (tcpheader + 1);
				desc->tcp_rcv_tsecr = *(topt + 2);
				desc->ts_recent = *(topt + 1);
			}
			stlc_list_add_tail(&(p->node), &(desc->packets));
			FFWD_DBG(0, "------- tcp sequence number matched, added packet to list, ip total length = %d, tcp payload length = %d\n", desc->ip_total_len, tcp_data_len);
			desc->packets_count++;
			/* update desc's tick */
			desc->tick = read_32bit_cp0_register(CP0_COUNT);
			
			if(desc->ip_total_len > 0xffff - 1460){
				FFWD_DBG(0, "ip total length = %d, flush desc\n", desc->ip_total_len);
				/* flush the session descriptor */
				tlro_flush_pipeline(desc);
			}
		} else {
			FFWD_DBG(0, "tcp sequence number does not match, flush desc, dma packet to host\n");
			// flush the session descriptor
			tlro_flush_pipeline(desc);
			if((tcpheader->th_flags & TH_FIN) || (tcpheader->th_flags & TH_RST)){
				free_session_desc(desc);
			}
			
			// dma the packet to host, send msg with code 0 and virtual address to scan process
			FFWD_DBG(0, "dma packet data to host, send msg to scan process\n");
			u64 msg = (((u64) p->len) <<  32) | ((u64) (u32) p->data);
			if(ffwd_message_send_code_1(0, igrid_to_bucket[1], msg) != 0){
				FFWD_DBG(0, "send msg to scan process failed\n");
			} else {
				FFWD_DBG(0, "send msg to scan process succeed\n");
			}
			free_packet(p);
		}
	} else {
		FFWD_DBG(0, "------------------- not found desc\n");
		if(tcpheader->th_flags & TH_SYN){
			FFWD_DBG(0, "syn flag set, initialize desc\n");
			desc = get_session_desc();
			if(desc){
				desc->active = 1;
				desc->tick = read_32bit_cp0_register(CP0_COUNT);
				desc->pid = process_id;
				stlc_hlist_add_head(&(desc->nd_hlist), &(session_buckets[p->hash]));
						
				desc->ip_total_len = 0;
				desc->key = key;
				STLC_INIT_LIST_HEAD(&(desc->packets));
				desc->packets_count = 0;
				desc->tcp_ack = tcpheader->th_ack;
				desc->tcp_next_seq = tcpheader->th_seq + 1;// syn consumes one sequence number
				desc->tcp_window = tcpheader->th_win;
				if(tcpheader->th_off == 8){
					/* options with and with only timestamp */
					u32 * ptr = (u32 *) (tcpheader + 1);
					desc->tcp_saw_tstamp = 1;
					desc->tcp_rcv_tsval = *(ptr + 1);
					desc->tcp_rcv_tsecr = *(ptr + 2);
					desc->ts_recent = *(ptr + 1);
				}
				print_desc(desc);
			} else {
				FFWD_DBG(0, "-------------------- failed to get desc, dma packet to host\n");
			}
		} else {
			FFWD_DBG(0, "---------------------- this should not happen, packet not suitable for large receive offload, dma packet to host\n");
		}
		// dma packet data to host, send msg with code 0 and virtual address of data to scan process
		FFWD_DBG(0, "dma packet data to host, send msg to scan process\n");
		u64 msg = (((u64) p->len) <<  32) | ((u64) (u32) p->data);
		if(ffwd_message_send_code_1(0, igrid_to_bucket[1], msg) != 0){
			FFWD_DBG(0, "send msg to scan process failed\n");
		} else {
			FFWD_DBG(0, "send msg to scan process succeed\n");
		}
		free_packet(p);
	}
}
void tlro_receive_packet_asy(struct packet_s * p){
	struct ip * ipheader = (struct ip *) (p->data + SIZEOF_ETHERHEADER);
	struct tcphdr * tcpheader = (struct tcphdr *) (p->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
	u8 * payload_data = p->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4 + tcpheader->th_off * 4;
	struct session_key key;
	key.sip = ipheader->ip_src;
	key.dip = ipheader->ip_dst;
	key.sport = tcpheader->th_sport;
	key.dport = tcpheader->th_dport;
	p->hash = session_hash(&key);
	FFWD_DBG(0, "src ip = %u, dst ip = %u, src port = %u, dst port = %u, tcp sequence number of the packet is %u\n", 
			key.sip, 
			key.dip,
			key.sport,
			key.dport,
			tcpheader->th_seq);
	if(tcpheader->th_off == 8){
		u32 * topt = (u32 *) (tcpheader + 1);
		++topt;
		FFWD_DBG(0, "tsval = %u\n", *topt);
	}
		
	struct tlro_desc * desc = find_session_node(p);
	if(desc){
		FFWD_DBG(0, "---------------------------- found desc, desc->tcp_next_seq = %u, tcp sequence number of the packet is %u\n", 
				desc->tcp_next_seq, 
				tcpheader->th_seq);
		if((tcpheader->th_flags & TH_ACK) && TCP_PAYLOAD_LENGTH(ipheader, tcpheader) == 0){
			// ack packet with no tcp data, probably because of tcp connection establishment, dma to host
			FFWD_DBG(0, "ack packet with no tcp data, probably because of tcp connection establishment, dma to host\n");
			if(desc->tcp_saw_tstamp){
				u32 * topt = (u32 *) (tcpheader + 1);
				desc->ts_recent = *(topt + 1);
			}
			dma_pkt_asy(p->data, p->len);
			free_packet(p);
			return;
		}
		if(tlro_check_packet(p, desc) && desc->tcp_next_seq == tcpheader->th_seq){
			/* add packet to session descriptor, check if we need to flush the session descriptor */
			send_ack(p, desc);
			u32 tcp_data_len = TCP_PAYLOAD_LENGTH(ipheader, tcpheader);
			if(desc->packets_count == 0){
				// the first packet
				desc->ip_total_len = ipheader->ip_len;
			} else {
				// pre dma payload data to host
				if(desc->packets_count == 1){
					// for pre dma payload data to host
					desc->rxoffset = rx_offset;
					rx_offset = (rx_offset + 1) & (MAC_ENTRY_DESC_NUM -1);
				}
				struct dma_count_s * tmp = (struct dma_count_s *) free_dma_count_list.next;
				stlc_list_del(free_dma_count_list.next);
				stlc_list_add_tail(&(tmp->node), &dma_data_list);
				tmp->data = p->data;
				u32 daddr = __swab32(ffwd_mac_entry_desc_rx[desc->rxoffset].address);
				ffwd_msg_send_to_dma(1, igrid_to_bucket[process_id], virt_to_phys(payload_data), daddr + SIZEOF_ETHERHEADER + desc->ip_total_len, tcp_data_len, 1, PCIE_RX_BUCKET_ID);
				
				desc->ip_total_len += tcp_data_len;
			}
			desc->tcp_next_seq += tcp_data_len;
			desc->tcp_window = tcpheader->th_win;
			desc->tcp_ack = tcpheader->th_ack;
			/* do not update tcp_rcv_tsval, would not work with PAWS */
			if(desc->tcp_saw_tstamp){
				u32 * topt = (u32 *) (tcpheader + 1);
				desc->tcp_rcv_tsecr = *(topt + 2);
				desc->ts_recent = *(topt + 1);
			}
			stlc_list_add_tail(&(p->node), &(desc->packets));
			FFWD_DBG(0, "------- tcp sequence number matched, added packet to list, ip total length = %d, tcp payload length = %d\n", desc->ip_total_len, tcp_data_len);
			desc->packets_count++;
			/* update desc's tick */
			desc->tick = read_32bit_cp0_register(CP0_COUNT);
			
			if(desc->ip_total_len > 0xffff - 1460){
				FFWD_DBG(0, "ip total length = %d, flush desc\n", desc->ip_total_len);
				/* flush the session descriptor */
				tlro_flush_asy(desc);
			}
		} else {
			FFWD_DBG(0, "tcp sequence number does not match, flush desc, dma packet to host\n");
			// flush the session descriptor
			tlro_flush_asy(desc);
			if((tcpheader->th_flags & TH_FIN) || (tcpheader->th_flags & TH_RST)){
				printk("saw FIN flag, dma_count = %u, desc->packets_count = %u", dma_count, desc->packets_count);
				free_session_desc(desc);
			}
			/* dma the packet to host */
			dma_pkt_asy(p->data, p->len);
			free_packet(p);
		}
	} else {
		FFWD_DBG(0, "------------------- not found desc\n");
		if(tcpheader->th_flags & TH_SYN){
			FFWD_DBG(0, "syn flag set, initialize desc\n");
			desc = get_session_desc();
			if(desc){
				desc->active = 1;
				desc->tick = read_32bit_cp0_register(CP0_COUNT);
				desc->pid = process_id;
				stlc_hlist_add_head(&(desc->nd_hlist), &(session_buckets[p->hash]));
				
				desc->ip_total_len = 0;
				desc->key = key;
				STLC_INIT_LIST_HEAD(&(desc->packets));
				desc->packets_count = 0;
				desc->tcp_ack = tcpheader->th_ack;
				desc->tcp_next_seq = tcpheader->th_seq + 1;// syn consumes one sequence number
				desc->tcp_window = tcpheader->th_win;
				if(tcpheader->th_off == 8){
						/* options with and with only timestamp */
						u32 * ptr = (u32 *) (tcpheader + 1);
						desc->tcp_saw_tstamp = 1;
						desc->tcp_rcv_tsval = *(ptr + 1);
						desc->tcp_rcv_tsecr = *(ptr + 2);
						desc->ts_recent = *(ptr + 1);
				}
				print_desc(desc);
			} else {
				FFWD_DBG(0, "-------------------- failed to get desc, dma packet to host\n");
			}
		} else {
			FFWD_DBG(0, "---------------------- this should not happen, packet not suitable for large receive offload, dma packet to host\n");
		}
		/* dma the packet to host */
		dma_pkt_asy(p->data, p->len);
		free_packet(p);
	}
}

void tlro_receive_packet_dma_load_balance(struct packet_s * p){
	struct ip * ipheader = (struct ip *) (p->data + SIZEOF_ETHERHEADER);
	struct tcphdr * tcpheader = (struct tcphdr *) (p->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
	struct session_key key;
	key.sip = ipheader->ip_src;
	key.dip = ipheader->ip_dst;
	key.sport = tcpheader->th_sport;
	key.dport = tcpheader->th_dport;
	p->hash = session_hash(&key);
	FFWD_DBG(0, "src ip = %u, dst ip = %u, src port = %u, dst port = %u, tcp sequence number of the packet is %u\n", 
			key.sip, 
			key.dip,
			key.sport,
			key.dport,
			tcpheader->th_seq);
	
	struct tlro_desc * desc = find_session_node(p);
	if(desc){
		FFWD_DBG(0, "---------------------------- found desc, desc->tcp_next_seq = %u, tcp sequence number of the packet is %u\n", 
				desc->tcp_next_seq, 
				tcpheader->th_seq);
		if((tcpheader->th_flags & TH_ACK) && TCP_PAYLOAD_LENGTH(ipheader, tcpheader) == 0){
			// ack packet with no tcp data, probably because of tcp connection establishment, dma to host
			FFWD_DBG(0, "ack packet with no tcp data, probably because of tcp connection establishment, dma to host\n");
			dma_pkt_load_balance(p->data, p->len);
			u64 msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(p->data));
			message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
			free_packet(p);
			return;
		}
		if(tlro_check_packet(p, desc) && desc->tcp_next_seq == tcpheader->th_seq){
			/* add packet to session descriptor, check if we need to flush the session descriptor */
			send_ack(p, desc);
			u32 tcp_data_len = TCP_PAYLOAD_LENGTH(ipheader, tcpheader);
			if(desc->packets_count == 0){
				// the first packet
				desc->ip_total_len = ipheader->ip_len;
			} else {
				desc->ip_total_len += tcp_data_len;
			}
			desc->tcp_next_seq += tcp_data_len;
			desc->tcp_window = tcpheader->th_win;
			desc->tcp_ack = tcpheader->th_ack;
			stlc_list_add_tail(&(p->node), &(desc->packets));
			FFWD_DBG(0, "------- tcp sequence number matched, added packet to list, ip total length = %d, tcp payload length = %d\n", desc->ip_total_len, tcp_data_len);
			desc->packets_count++;
			/* update desc's tick */
			desc->tick = read_32bit_cp0_register(CP0_COUNT);
			
			if(desc->ip_total_len > 0xffff - 1460){
				FFWD_DBG(0, "ip total length = %d, flush desc\n", desc->ip_total_len);
				/* flush the session descriptor */
				tlro_flush_dma_load_balance(desc);
			}
		} else {
			FFWD_DBG(0, "tcp sequence number does not match, flush desc, dma packet to host\n");
			// flush the session descriptor
			tlro_flush_dma_load_balance(desc);
			if((tcpheader->th_flags & TH_FIN) || (tcpheader->th_flags & TH_RST)){
				free_session_desc(desc);
			}
			
			/* dma the packet to host */
			dma_pkt_load_balance(p->data, p->len);
			u64 msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(p->data));
			message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
			free_packet(p);
		}
	} else {
		FFWD_DBG(0, "------------------- not found desc\n");
		if(tcpheader->th_flags & TH_SYN){
			FFWD_DBG(0, "syn flag set, initialize desc\n");
			desc = get_session_desc();
			if(desc){
				desc->active = 1;
				desc->tick = read_32bit_cp0_register(CP0_COUNT);
				desc->pid = process_id;
				stlc_hlist_add_head(&(desc->nd_hlist), &(session_buckets[p->hash]));
				
				desc->ip_total_len = 0;
				desc->key = key;
				STLC_INIT_LIST_HEAD(&(desc->packets));
				desc->packets_count = 0;
				desc->tcp_ack = tcpheader->th_ack;
				desc->tcp_next_seq = tcpheader->th_seq + 1;// syn consumes one sequence number
				desc->tcp_window = tcpheader->th_win;
				// disable timestamp
				desc->tcp_saw_tstamp = 0;
				print_desc(desc);
			} else {
				FFWD_DBG(0, "-------------------- failed to get desc, dma packet to host\n");
				printk("process %d: failed to get desc, dma packet to host\n");
			}
		} else {
			FFWD_DBG(0, "---------------------- this should not happen, packet not suitable for large receive offload, dma packet to host\n");
		}
		/* dma the packet to host */
		dma_pkt_load_balance(p->data, p->len);
		u64 msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(p->data));
		message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
		free_packet(p);
	}
}
void tlro_receive_packet_multi_rxring(struct packet_s * p){
	struct ip * ipheader = (struct ip *) (p->data + SIZEOF_ETHERHEADER);
	struct tcphdr * tcpheader = (struct tcphdr *) (p->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
	struct session_key key;
	key.sip = ipheader->ip_src;
	key.dip = ipheader->ip_dst;
	key.sport = tcpheader->th_sport;
	key.dport = tcpheader->th_dport;
	p->hash = session_hash(&key);
	FFWD_DBG(0, "src ip = %u, dst ip = %u, src port = %u, dst port = %u, tcp sequence number of the packet is %u\n", 
			key.sip, 
			key.dip,
			key.sport,
			key.dport,
			tcpheader->th_seq);
	
	struct tlro_desc * desc = find_session_node(p);
	if(desc){
		FFWD_DBG(0, "---------------------------- found desc, desc->tcp_next_seq = %u, tcp sequence number of the packet is %u\n", 
				desc->tcp_next_seq, 
				tcpheader->th_seq);
		if((tcpheader->th_flags & TH_ACK) && TCP_PAYLOAD_LENGTH(ipheader, tcpheader) == 0){
			// ack packet with no tcp data, probably because of tcp connection establishment, dma to host
			FFWD_DBG(0, "ack packet with no tcp data, probably because of tcp connection establishment, dma to host\n");
//			if(desc->tcp_saw_tstamp){
//				u32 * topt = (u32 *) (tcpheader + 1);
//				desc->ts_recent = *(topt + 1);
//			}
			dma_pkt_multi_rxring(p->data, p->len);
			u64 msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(p->data));
			message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
			free_packet(p);
			return;
		}
		if(tlro_check_packet(p, desc) && desc->tcp_next_seq == tcpheader->th_seq){
			/* add packet to session descriptor, check if we need to flush the session descriptor */
			send_ack(p, desc);
			u32 tcp_data_len = TCP_PAYLOAD_LENGTH(ipheader, tcpheader);
			if(desc->packets_count == 0){
				// the first packet
				desc->ip_total_len = ipheader->ip_len;
			} else {
				desc->ip_total_len += tcp_data_len;
			}
			desc->tcp_next_seq += tcp_data_len;
			desc->tcp_window = tcpheader->th_win;
			desc->tcp_ack = tcpheader->th_ack;
//			/* do not update tcp_rcv_tsval, would not work with PAWS */
//			if(desc->tcp_saw_tstamp){
//				u32 * topt = (u32 *) (tcpheader + 1);
//				desc->tcp_rcv_tsecr = *(topt + 2);
//				desc->ts_recent = *(topt + 1);
//			}
			stlc_list_add_tail(&(p->node), &(desc->packets));
			FFWD_DBG(0, "------- tcp sequence number matched, added packet to list, ip total length = %d, tcp payload length = %d\n", desc->ip_total_len, tcp_data_len);
			desc->packets_count++;
			/* update desc's tick */
			desc->tick = read_32bit_cp0_register(CP0_COUNT);
			
			if(desc->ip_total_len > 0xffff - 1460){
				FFWD_DBG(0, "ip total length = %d, flush desc\n", desc->ip_total_len);
				/* flush the session descriptor */
				tlro_flush_multi_rxring(desc);
			}
		} else {
			FFWD_DBG(0, "tcp sequence number does not match, flush desc, dma packet to host\n");
			// flush the session descriptor
			tlro_flush_multi_rxring(desc);
			if((tcpheader->th_flags & TH_FIN) || (tcpheader->th_flags & TH_RST)){
				free_session_desc(desc);
			}
			
			/* dma the packet to host */
			dma_pkt_multi_rxring(p->data, p->len);
			u64 msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(p->data));
			message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
			free_packet(p);
		}
	} else {
		FFWD_DBG(0, "------------------- not found desc\n");
		if(tcpheader->th_flags & TH_SYN){
			FFWD_DBG(0, "syn flag set, initialize desc\n");
			desc = get_session_desc();
			if(desc){
				desc->active = 1;
				desc->tick = read_32bit_cp0_register(CP0_COUNT);
				desc->pid = process_id;
				stlc_hlist_add_head(&(desc->nd_hlist), &(session_buckets[p->hash]));
				
				desc->ip_total_len = 0;
				desc->key = key;
				STLC_INIT_LIST_HEAD(&(desc->packets));
				desc->packets_count = 0;
				desc->tcp_ack = tcpheader->th_ack;
				desc->tcp_next_seq = tcpheader->th_seq + 1;// syn consumes one sequence number
				desc->tcp_window = tcpheader->th_win;
				// disable timestamp
				desc->tcp_saw_tstamp = 0;
				print_desc(desc);
			} else {
				FFWD_DBG(0, "-------------------- failed to get desc, dma packet to host\n");
			}
		} else {
			FFWD_DBG(0, "---------------------- this should not happen, packet not suitable for large receive offload, dma packet to host\n");
		}
		/* dma the packet to host */
		dma_pkt_multi_rxring(p->data, p->len);
		u64 msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(p->data));
		message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
		free_packet(p);
	}
}
/*
 * receive a small tcp packet, ip and tcp checksum should be correct
 * check if the packet is suitable for lro
 * a simple version, only aggregate in order tcp packets
 */
void tlro_receive_packet(struct packet_s * p){
	struct ip * ipheader = (struct ip *) (p->data + SIZEOF_ETHERHEADER);
	struct tcphdr * tcpheader = (struct tcphdr *) (p->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
	struct session_key key;
	key.sip = ipheader->ip_src;
	key.dip = ipheader->ip_dst;
	key.sport = tcpheader->th_sport;
	key.dport = tcpheader->th_dport;
	p->hash = session_hash(&key);
	FFWD_DBG(0, "src ip = %u, dst ip = %u, src port = %u, dst port = %u, tcp sequence number of the packet is %u\n", 
			key.sip, 
			key.dip,
			key.sport,
			key.dport,
			tcpheader->th_seq);
	if(tcpheader->th_off == 8){
		u32 * topt = (u32 *) (tcpheader + 1);
		++topt;
		FFWD_DBG(0, "tsval = %u\n", *topt);
	}
		
	struct tlro_desc * desc = find_session_node(p);
	if(desc){
		FFWD_DBG(0, "---------------------------- found desc, desc->tcp_next_seq = %u, tcp sequence number of the packet is %u\n", 
				desc->tcp_next_seq, 
				tcpheader->th_seq);
		if((tcpheader->th_flags & TH_ACK) && TCP_PAYLOAD_LENGTH(ipheader, tcpheader) == 0){
			// ack packet with no tcp data, probably because of tcp connection establishment, dma to host
			FFWD_DBG(0, "ack packet with no tcp data, probably because of tcp connection establishment, dma to host\n");
			if(desc->tcp_saw_tstamp){
				u32 * topt = (u32 *) (tcpheader + 1);
				desc->ts_recent = *(topt + 1);
			}
			dma_pkt(p->data, p->len);
			u64 msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(p->data));
			message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
			free_packet(p);
			return;
		}
		if(tlro_check_packet(p, desc) && desc->tcp_next_seq == tcpheader->th_seq){
			/* add packet to session descriptor, check if we need to flush the session descriptor */
			send_ack(p, desc);
			u32 tcp_data_len = TCP_PAYLOAD_LENGTH(ipheader, tcpheader);
			if(desc->packets_count == 0){
				// the first packet
				desc->ip_total_len = ipheader->ip_len;
			} else {
				desc->ip_total_len += tcp_data_len;
			}
			desc->tcp_next_seq += tcp_data_len;
			desc->tcp_window = tcpheader->th_win;
			desc->tcp_ack = tcpheader->th_ack;
			/* do not update tcp_rcv_tsval, would not work with PAWS */
			if(desc->tcp_saw_tstamp){
				u32 * topt = (u32 *) (tcpheader + 1);
				desc->tcp_rcv_tsecr = *(topt + 2);
				desc->ts_recent = *(topt + 1);
			}
			stlc_list_add_tail(&(p->node), &(desc->packets));
			FFWD_DBG(0, "------- tcp sequence number matched, added packet to list, ip total length = %d, tcp payload length = %d\n", desc->ip_total_len, tcp_data_len);
			desc->packets_count++;
			/* update desc's tick */
			desc->tick = read_32bit_cp0_register(CP0_COUNT);
			
			if(desc->ip_total_len > 0xffff - 1460){
				FFWD_DBG(0, "ip total length = %d, flush desc\n", desc->ip_total_len);
				/* flush the session descriptor */
				tlro_flush(desc);
			}
		} else {
			FFWD_DBG(0, "tcp sequence number does not match, flush desc, dma packet to host\n");
			// flush the session descriptor
			tlro_flush(desc);
			if((tcpheader->th_flags & TH_FIN) || (tcpheader->th_flags & TH_RST)){
				free_session_desc(desc);
			}
			
			/* dma the packet to host */
			dma_pkt(p->data, p->len);
			u64 msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(p->data));
			message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
			free_packet(p);
		}
	} else {
		FFWD_DBG(0, "------------------- not found desc\n");
		if(tcpheader->th_flags & TH_SYN){
			FFWD_DBG(0, "syn flag set, initialize desc\n");
			desc = get_session_desc();
			if(desc){
				desc->active = 1;
				desc->tick = read_32bit_cp0_register(CP0_COUNT);
				desc->pid = process_id;
				stlc_hlist_add_head(&(desc->nd_hlist), &(session_buckets[p->hash]));
				
				desc->ip_total_len = 0;
				desc->key = key;
				STLC_INIT_LIST_HEAD(&(desc->packets));
				desc->packets_count = 0;
				desc->tcp_ack = tcpheader->th_ack;
				desc->tcp_next_seq = tcpheader->th_seq + 1;// syn consumes one sequence number
				desc->tcp_window = tcpheader->th_win;
//				if(tcpheader->th_off == 8){
//						/* options with and with only timestamp */
//						u32 * ptr = (u32 *) (tcpheader + 1);
//						desc->tcp_saw_tstamp = 1;
//						desc->tcp_rcv_tsval = *(ptr + 1);
//						desc->tcp_rcv_tsecr = *(ptr + 2);
//						desc->ts_recent = *(ptr + 1);
//				}
				desc->tcp_saw_tstamp = 0;
				print_desc(desc);
			} else {
				FFWD_DBG(0, "-------------------- failed to get desc, dma packet to host\n");
			}
		} else {
			FFWD_DBG(0, "---------------------- this should not happen, packet not suitable for large receive offload, dma packet to host\n");
		}
		/* dma the packet to host */
		dma_pkt(p->data, p->len);
		u64 msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(p->data));
		message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
		free_packet(p);
	}
}

void session_task_dmaqueue(){
	u64 msg;
	u32 srcid;
	u32 size;
	u32 code;
	int recv_bkt = BUCKET_RCV_PKT;
	int free_bkt = BUCKET_RCV_RSP;
	
	FFWD_DBG(0, "process id %d starting session dmaqueue task, recv_bkt = %d, free_bkt = %d\n", process_id, recv_bkt, free_bkt);
	while(1){
		if(message_receive_fast_1(free_bkt, size, code, srcid, msg) == 0){
			if(srcid == MSGRNG_STNID_CPU0){
				FFWD_DBG(0, "code = %u\n", code);
				if(code == TLRO_TIMEOUT_CODE){
					// received timeout message, todo flush desc
					FFWD_DBG(0, "received timeout message\n");
				} else if(code == 0xff){
					// received virtual address of struct dma_msg_s *
					FFWD_DBG(0, "received virtual address of struct dma_msg_s *\n");
					struct dma_msg_s * dmamsg = (struct dma_msg_s *) ((u32) msg);
					stlc_list_add_tail(&(dmamsg->node), &free_dma_msg_list);
				} else {
					// received virtual address of struct packet_s *, code is the number of packets, free the packets
					FFWD_DBG(0, "received virtual address of struct packet_s\n");
					struct packet_s * p = (struct packet_s *) ((u32) msg);
					int i;
					struct packet_s * tmp;
					for(i = 0;i < code - 1;i++){
						tmp = (struct packet_s *) p->node.next;
						stlc_list_del(&(tmp->node));
						free_packet(tmp);
					}
					free_packet(p);
				}
			} else if(srcid == PCIE_RX_BUCKET_ID){
				FFWD_DBG(0, "received dma respond message, but this should not happen\n");
			} else if(srcid == MSGRNG_STNID_GMAC1){
				FFWD_DBG(0, "received GMAC1 free back message\n");
				struct stlc_list_head * node = (struct stlc_list_head *) (phys_to_virt((u32) GET_RX_MSG_DATA(msg)) - sizeof(struct stlc_list_head));
				stlc_list_add_tail(node, &ack_packets_list);
			} else {
				FFWD_DBG(0, "received unknown message\n");
			}
			
			continue;
		}
		
		if(message_receive_fast_1(recv_bkt, size, code, srcid, msg) == 0){
			if(srcid == MSGRNG_STNID_GMAC1){
				SMA_COUNTER_INC(gmac1_rx_packets);
				FFWD_DBG(0, "-------------------------------------------------gmac1_rx_packets[%d] = %u\n", process_id, ffwd_counter_info[process_id].gmac1_rx_packets);
												
				u8 * recv_data = (u8 *) phys_to_virt((u32) GET_RX_MSG_DATA(msg));
				u16 len = GET_RX_MSG_LEN(msg) - CRC_SIZE;
				FFWD_DBG(0, "message length = %u\n", GET_RX_MSG_LEN(msg));
				
				struct ether_header * ethhdr = (struct ether_header *) recv_data;
				if(ethhdr->ether_type == ETHERTYPE_IP){
					// ip packet
					FFWD_DBG(0, "received an ip packet, length = %d\n", len);
					struct ip * iphdr = (struct ip *) (recv_data + SIZEOF_ETHERHEADER);
					FFWD_DBG(0, "ip header length = %d, ip total length = %d\n", iphdr->ip_hl * 4, iphdr->ip_len);
					if(check_sum(iphdr, iphdr->ip_hl * 4) == 0){
						FFWD_DBG(0, "ip checksum correct\n");
						if((iphdr->ip_off & IP_DF) || (iphdr->ip_off == 0)){
							// not fragmented ip packet
							FFWD_DBG(0, "not fragmented ip packet\n");
							if(iphdr->ip_p == IPPROTO_TCP){
								// tcp packet
								FFWD_DBG(0, "not fragmented tcp packet\n");
								PsdHeader psd_header;
								psd_header.saddr = iphdr->ip_src;
								psd_header.daddr = iphdr->ip_dst;
								psd_header.mbz = 0;
								psd_header.ptcl = 6;
								psd_header.tcpl = iphdr->ip_len - iphdr->ip_hl * 4;
								struct tcphdr * tcpheader = (struct tcphdr *) (recv_data + SIZEOF_ETHERHEADER + iphdr->ip_hl * 4);
								u16 payload_length = TCP_PAYLOAD_LENGTH(iphdr, tcpheader);
								FFWD_DBG(0, "sequence number of the packet is %u, ack number of the packet is %u, payload length = %u\n", tcpheader->th_seq, tcpheader->th_ack, payload_length);
								if(/* hardware check tcp checksum */ 1){
									// tcp checksum correct, handle tcp large receive offload
									FFWD_DBG(0, "------------- TCP checksum correct, handle tcp large receive offload\n");
									struct packet_s * pkt = get_free_packet();
									FFWD_DBG(0, "got packet_s, packet id = %u\n", pkt->id);
									pkt->data = recv_data;
									pkt->len = len;
									// calculate tcp payload data's one complement sum
									u16 a[3];
									a[0] = ~(tcpheader->th_sum);
									tcpheader->th_sum = 0;
									u16 tcpheader_sum = one_complement_sum((u16 *) tcpheader, tcpheader->th_off * 4);
									u16 psdheader_sum = one_complement_sum((u16 *) (&psd_header), sizeof(PsdHeader));
									a[1] = ~tcpheader_sum;
									a[2] = ~psdheader_sum;
									pkt->data_sum = add_one_complement_sum(a, 3);
									tcpheader->th_sum = ~(a[0]);
									
									tlro_receive_packet_dmaqueue(pkt);
								} else {
									// tcp checksum not correct, drop packet
									FFWD_DBG(0, "tcp checksum not correct! Drop the packet\n");
									// free GMAC1 received data
									msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
									message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
								}
							} else {
								// not tcp packet
								// send msg with code 0 and virtual address of received data to scan process
								FFWD_DBG(0, "not fragmented non tcp packet, dma to host, send msg to scan process\n");
								msg = (((u64) len) <<  32) | ((u64) (u32) recv_data);
								if(free_dma_msg_list.next == &free_dma_msg_list){
									FFWD_DBG(0, "free dma msg list is empty!\n");
								} else {
									struct dma_msg_s * dmamsg = (struct dma_msg_s *) free_dma_msg_list.next;
									dmamsg->code = 0;
									dmamsg->pid = process_id;
									dmamsg->msg = msg;
									stlc_list_del(free_dma_msg_list.next);
									spin_lock(&dma_msg_list_lock);
									stlc_list_add_tail(&(dmamsg->node), &dma_msg_list);
									spin_unlock(&dma_msg_list_lock);
								}
							}
						} else {
							// fragmented ip packet, dma the packet to host
							// send msg with code 0 and virtual address of received data to scan process
							FFWD_DBG(0, "dma fragmented ip packet to host, send msg to scan process\n");
							msg = (((u64) len) <<  32) | ((u64) (u32) recv_data);
							if(free_dma_msg_list.next == &free_dma_msg_list){
								FFWD_DBG(0, "free dma msg list is empty!\n");
							} else {
								struct dma_msg_s * dmamsg = (struct dma_msg_s *) free_dma_msg_list.next;
								dmamsg->code = 0;
								dmamsg->pid = process_id;
								dmamsg->msg = msg;
								stlc_list_del(free_dma_msg_list.next);
								spin_lock(&dma_msg_list_lock);
								stlc_list_add_tail(&(dmamsg->node), &dma_msg_list);
								spin_unlock(&dma_msg_list_lock);
							}
						}
					} else {
						// ip checksum not correct, drop packet
						FFWD_DBG(0, "ip checksum not correct! Drop the packet\n");
						// free GMAC1 received data
						msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
						message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
					}
				} else {
					// dma the non ip packet to host, send msg with code 0 and virtual address of received data to scan process
					FFWD_DBG(0, "dma the non ip packet to host, send msg to scan process\n");
					msg = (((u64) len) <<  32) | ((u64) (u32) recv_data);
					if(free_dma_msg_list.next == &free_dma_msg_list){
						FFWD_DBG(0, "free dma msg list is empty!\n");
					} else {
						struct dma_msg_s * dmamsg = (struct dma_msg_s *) free_dma_msg_list.next;
						dmamsg->code = 0;
						dmamsg->pid = process_id;
						dmamsg->msg = msg;
						stlc_list_del(free_dma_msg_list.next);
						spin_lock(&dma_msg_list_lock);
						stlc_list_add_tail(&(dmamsg->node), &dma_msg_list);
						spin_unlock(&dma_msg_list_lock);
					}
				}
			} else {
				FFWD_DBG(0, "receive packet error, stnid = %d\n", srcid);
			}
		}
	}
}
void session_task_pipeline(){
	u64 msg;
	u32 srcid;
	u32 size;
	u32 code;
	int recv_bkt = BUCKET_RCV_PKT;
	int free_bkt = BUCKET_RCV_RSP;
	
	FFWD_DBG(0, "process id %d starting session pipeline task, recv_bkt = %d, free_bkt = %d\n", process_id, recv_bkt, free_bkt);
	while(1){
		if(message_receive_fast_1(free_bkt, size, code, srcid, msg) == 0){
			if(srcid == MSGRNG_STNID_CPU0){
				if(code == TLRO_TIMEOUT_CODE){
					// received timeout message, todo flush desc
					FFWD_DBG(0, "received timeout message\n");
				} else {
					// received virtual address of struct packet_s *, code is the number of packets, free the packets
					FFWD_DBG(0, "received virtual address of struct packet_s\n");
					struct packet_s * p = (struct packet_s *) ((u32) msg);
					int i;
					struct packet_s * tmp;
					for(i = 0;i < code - 1;i++){
						tmp = (struct packet_s *) p->node.next;
						stlc_list_del(&(tmp->node));
						free_packet(tmp);
					}
					free_packet(p);
				}
			} else if(srcid == PCIE_RX_BUCKET_ID){
				FFWD_DBG(0, "received dma respond message, but this should not happen\n");
			} else if(srcid == MSGRNG_STNID_GMAC1){
				FFWD_DBG(0, "received GMAC1 free back message\n");
				struct stlc_list_head * node = (struct stlc_list_head *) (phys_to_virt((u32) GET_RX_MSG_DATA(msg)) - sizeof(struct stlc_list_head));
				stlc_list_add_tail(node, &ack_packets_list);
			} else {
				FFWD_DBG(0, "received unknown message\n");
			}
			
			continue;
		}
		
		if(message_receive_fast_1(recv_bkt, size, code, srcid, msg) == 0){
			if(srcid == MSGRNG_STNID_GMAC1){
				SMA_COUNTER_INC(gmac1_rx_packets);
				FFWD_DBG(0, "-------------------------------------------------gmac1_rx_packets[%d] = %u\n", process_id, ffwd_counter_info[process_id].gmac1_rx_packets);
												
				u8 * recv_data = (u8 *) phys_to_virt((u32) GET_RX_MSG_DATA(msg));
				u16 len = GET_RX_MSG_LEN(msg) - CRC_SIZE;
				FFWD_DBG(0, "message length = %u\n", GET_RX_MSG_LEN(msg));
				
				struct ether_header * ethhdr = (struct ether_header *) recv_data;
				if(ethhdr->ether_type == ETHERTYPE_IP){
					// ip packet
					FFWD_DBG(0, "received an ip packet, length = %d\n", len);
					struct ip * iphdr = (struct ip *) (recv_data + SIZEOF_ETHERHEADER);
					FFWD_DBG(0, "ip header length = %d, ip total length = %d\n", iphdr->ip_hl * 4, iphdr->ip_len);
					if(check_sum(iphdr, iphdr->ip_hl * 4) == 0){
						FFWD_DBG(0, "ip checksum correct\n");
						if((iphdr->ip_off & IP_DF) || (iphdr->ip_off == 0)){
							// not fragmented ip packet
							FFWD_DBG(0, "not fragmented ip packet\n");
							if(iphdr->ip_p == IPPROTO_TCP){
								// tcp packet
								FFWD_DBG(0, "not fragmented tcp packet\n");
								PsdHeader psd_header;
								psd_header.saddr = iphdr->ip_src;
								psd_header.daddr = iphdr->ip_dst;
								psd_header.mbz = 0;
								psd_header.ptcl = 6;
								psd_header.tcpl = iphdr->ip_len - iphdr->ip_hl * 4;
								struct tcphdr * tcpheader = (struct tcphdr *) (recv_data + SIZEOF_ETHERHEADER + iphdr->ip_hl * 4);
								u16 payload_length = TCP_PAYLOAD_LENGTH(iphdr, tcpheader);
								FFWD_DBG(0, "sequence number of the packet is %u, ack number of the packet is %u, payload length = %u\n", tcpheader->th_seq, tcpheader->th_ack, payload_length);
								if(/* hardware check tcp checksum */ 1){
									// tcp checksum correct, handle tcp large receive offload
									FFWD_DBG(0, "------------- TCP checksum correct, handle tcp large receive offload\n");
									struct packet_s * pkt = get_free_packet();
									FFWD_DBG(0, "got packet_s, packet id = %u\n", pkt->id);
									pkt->data = recv_data;
									pkt->len = len;
									// calculate tcp payload data's one complement sum
									u16 a[3];
									a[0] = ~(tcpheader->th_sum);
									tcpheader->th_sum = 0;
									u16 tcpheader_sum = one_complement_sum((u16 *) tcpheader, tcpheader->th_off * 4);
									u16 psdheader_sum = one_complement_sum((u16 *) (&psd_header), sizeof(PsdHeader));
									a[1] = ~tcpheader_sum;
									a[2] = ~psdheader_sum;
									pkt->data_sum = add_one_complement_sum(a, 3);
									tcpheader->th_sum = ~(a[0]);
									
									tlro_receive_packet_pipeline(pkt);
								} else {
									// tcp checksum not correct, drop packet
									FFWD_DBG(0, "tcp checksum not correct! Drop the packet\n");
									// free GMAC1 received data
									msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
									message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
								}
							} else {
								// not tcp packet
								// send msg with code 0 and virtual address of received data to scan process
								FFWD_DBG(0, "not fragmented non tcp packet, dma to host, send msg to scan process\n");
								msg = (((u64) len) <<  32) | ((u64) (u32) recv_data);
								if(ffwd_message_send_code_1(0, igrid_to_bucket[1], msg) != 0){
									FFWD_DBG(0, "send msg to scan process failed\n");
								} else {
									FFWD_DBG(0, "send msg to scan process succeed\n");
								}
							}
						} else {
							// fragmented ip packet, dma the packet to host
							// send msg with code 0 and virtual address of received data to scan process
							FFWD_DBG(0, "dma fragmented ip packet to host, send msg to scan process\n");
							msg = (((u64) len) <<  32) | ((u64) (u32) recv_data);
							if(ffwd_message_send_code_1(0, igrid_to_bucket[1], msg) != 0){
								FFWD_DBG(0, "send msg to scan process failed\n");
							} else {
								FFWD_DBG(0, "send msg to scan process succeed\n");
							}
						}
					} else {
						// ip checksum not correct, drop packet
						FFWD_DBG(0, "ip checksum not correct! Drop the packet\n");
						// free GMAC1 received data
						msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
						message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
					}
				} else {
					// dma the non ip packet to host, send msg with code 0 and virtual address of received data to scan process
					FFWD_DBG(0, "dma the non ip packet to host, send msg to scan process\n");
					msg = (((u64) len) <<  32) | ((u64) (u32) recv_data);
					if(ffwd_message_send_code_1(0, igrid_to_bucket[1], msg) != 0){
						FFWD_DBG(0, "send msg to scan process failed\n");
					} else {
						FFWD_DBG(0, "send msg to scan process succeed\n");
					}
				}
			} else {
				FFWD_DBG(0, "receive packet error, stnid = %d\n", srcid);
			}
		}
	}
}
void session_task_asy(){
	u64 msg;
	u32 srcid;
	u32 size;
	u32 code;
	int recv_bkt = BUCKET_RCV_PKT;
	int free_bkt = BUCKET_RCV_RSP;
	struct dma_count_s * tmp = NULL;
	dma_count = 0;
	dma_data_list.next = dma_data_list.prev = &dma_data_list;
	dma_count_list.next = dma_count_list.prev = &dma_count_list;
	FFWD_DBG(0, "process id %d starting session asy task, recv_bkt = %d, free_bkt = %d\n", process_id, recv_bkt, free_bkt);
	while(1){
		if(message_receive_fast_1(free_bkt, size, code, srcid, msg) == 0){
			if(srcid == MSGRNG_STNID_CPU0){
				FFWD_DBG(0, "received timeout message\n");
				// todo handle timeout
			} else if(srcid == PCIE_RX_BUCKET_ID){
				FFWD_DBG(0, "received dma respond message\n");
				if(dma_resp(msg) == 0){
					dma_count++;
					FFWD_DBG(0, "dma_count = %u\n", dma_count);
					if(dma_data_list.next != &dma_data_list){
						tmp = (struct dma_count_s *) dma_data_list.next;
						// free GMAC1 received data
						msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(tmp->data));
						message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
						stlc_list_del(dma_data_list.next);
						stlc_list_add_tail((struct stlc_list_head *) tmp, &free_dma_count_list);
					}
					if(dma_count_list.next != &dma_count_list){
						tmp = (struct dma_count_s *) dma_count_list.next;
						FFWD_DBG(0, "tmp->count = %u\n", tmp->count);
						if(dma_count >= tmp->count){
							// dma a hole packet completed
							ffwd_mac_counter->rx_packets++;
							ffwd_mac_counter->rx_bytes += tmp->len;
							ffwd_mac_entry_desc_rx[tmp->offset].len = __swab16(tmp->len);
							ffwd_mac_entry_desc_rx[tmp->offset].state = FIFO_READABLE;
							FFWD_DBG(0, "dma aggregated big packet succeed, rx_packets = %d\n", ffwd_mac_counter->rx_packets);
																						
							ffwd_mac_interrupt_host();
							barrier();
							dma_count -= tmp->count;
							stlc_list_del(dma_count_list.next);
							stlc_list_add_tail((struct stlc_list_head *) tmp, &free_dma_count_list);
						}
					}
				} else {
					FFWD_DBG(0, "===================================== dma packet failed!\n");
				}
			} else if(srcid == MSGRNG_STNID_GMAC1){
				FFWD_DBG(0, "received GMAC1 free back message\n");
				struct stlc_list_head * node = (struct stlc_list_head *) (phys_to_virt((u32) GET_RX_MSG_DATA(msg)) - sizeof(struct stlc_list_head));
				stlc_list_add_tail(node, &ack_packets_list);
			} else {
				FFWD_DBG(0, "received unknown message\n");
			}
			continue;
		}
		
		if(message_receive_fast_1(recv_bkt, size, code, srcid, msg) == 0){
			if(srcid == MSGRNG_STNID_GMAC1){
				SMA_COUNTER_INC(gmac1_rx_packets);
				FFWD_DBG(0, "-------------------------------------------------gmac1_rx_packets[%d] = %u\n", process_id, ffwd_counter_info[process_id].gmac1_rx_packets);
								
				u8 * recv_data = (u8 *) phys_to_virt((u32) GET_RX_MSG_DATA(msg));
				u16 len = GET_RX_MSG_LEN(msg) - CRC_SIZE;
				FFWD_DBG(0, "message length = %u\n", GET_RX_MSG_LEN(msg));
				
				struct ether_header * ethhdr = (struct ether_header *) recv_data;
				if(ethhdr->ether_type == ETHERTYPE_IP){
					// ip packet
					FFWD_DBG(0, "received an ip packet, length = %d\n", len);
					struct ip * iphdr = (struct ip *) (recv_data + SIZEOF_ETHERHEADER);
					FFWD_DBG(0, "ip header length = %d, ip total length = %d\n", iphdr->ip_hl * 4, iphdr->ip_len);
					if(check_sum(iphdr, iphdr->ip_hl * 4) == 0){
						FFWD_DBG(0, "ip checksum correct\n");
						if((iphdr->ip_off & IP_DF) || (iphdr->ip_off == 0)){
							// not fragmented ip packet
							FFWD_DBG(0, "not fragmented ip packet\n");
							if(iphdr->ip_p == IPPROTO_TCP){
								// tcp packet
								FFWD_DBG(0, "not fragmented tcp packet\n");
								PsdHeader psd_header;
								psd_header.saddr = iphdr->ip_src;
								psd_header.daddr = iphdr->ip_dst;
								psd_header.mbz = 0;
								psd_header.ptcl = 6;
								psd_header.tcpl = iphdr->ip_len - iphdr->ip_hl * 4;
								struct tcphdr * tcpheader = (struct tcphdr *) (recv_data + SIZEOF_ETHERHEADER + iphdr->ip_hl * 4);
								u16 payload_length = TCP_PAYLOAD_LENGTH(iphdr, tcpheader);
								FFWD_DBG(0, "sequence number of the packet is %u, ack number of the packet is %u, payload length = %u\n", tcpheader->th_seq, tcpheader->th_ack, payload_length);
								if(/* hardware check tcp checksum */ 1){
									// tcp checksum correct, handle tcp large receive offload
									FFWD_DBG(0, "------------- TCP checksum correct, handle tcp large receive offload\n");
									struct packet_s * pkt = get_free_packet();
									FFWD_DBG(0, "got packet_s, packet id = %u\n", pkt->id);
									pkt->data = recv_data;
									pkt->len = len;
									// calculate tcp payload data's one complement sum
									u16 a[3];
									a[0] = ~(tcpheader->th_sum);
									tcpheader->th_sum = 0;
									u16 tcpheader_sum = one_complement_sum((u16 *) tcpheader, tcpheader->th_off * 4);
									u16 psdheader_sum = one_complement_sum((u16 *) (&psd_header), sizeof(PsdHeader));
									a[1] = ~tcpheader_sum;
									a[2] = ~psdheader_sum;
									pkt->data_sum = add_one_complement_sum(a, 3);
									tcpheader->th_sum = ~(a[0]);
									
									tlro_receive_packet_asy(pkt);
								} else {
									// tcp checksum not correct, drop packet
									FFWD_DBG(0, "tcp checksum not correct! Drop the packet\n");
									// free GMAC1 received data
									msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
									message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
								}
							} else {
								// not tcp packet
								FFWD_DBG(0, "not fragmented non tcp packet, dma to host\n");
								dma_pkt_asy(recv_data, len);
							}
						} else {
							// fragmented ip packet, dma the packet to host
							FFWD_DBG(0, "dma fragmented ip packet to host\n");
							dma_pkt_asy(recv_data, len);
						}
					} else {
						// ip checksum not correct, drop packet
						FFWD_DBG(0, "ip checksum not correct! Drop the packet\n");
						// free GMAC1 received data
						msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
						message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
					}
				} else {
					// dma the non ip packet to host
					FFWD_DBG(0, "dma the non ip packet to host\n");
					dma_pkt_asy(recv_data, len);
				}
			} else {
				FFWD_DBG(0, "receive packet error, stnid = %d\n", srcid);
			}
		}
	}
}

void simple_receive_dma_load_balance(){
	u64 msg;
	u32 srcid;
	u32 size;
	u32 code;
	int recv_bkt = BUCKET_RCV_PKT;
	int free_bkt = BUCKET_RCV_RSP;
	
	FFWD_DBG(0, "process id %d starting simple receive dma load balance, recv_bkt = %d, free_bkt = %d\n", process_id, recv_bkt, free_bkt);
	while(1){
		if(message_receive_fast_1(free_bkt, size, code, srcid, msg) == 0){
			if(srcid == MSGRNG_STNID_CPU0){
				FFWD_DBG(0, "received timeout message\n");
				// todo handle timeout
				continue;
			} else if(srcid == PCIE_RX_BUCKET_ID){
				FFWD_DBG(0, "received dma respond message\n");
				continue;
			} else if(srcid == MSGRNG_STNID_GMAC1){
				FFWD_DBG(0, "received GMAC1 free back message, but this should not happen\n");
			} else {
				FFWD_DBG(0, "received unknown message\n");
				continue;
			}
		}
		
		if(message_receive_fast_1(recv_bkt, size, code, srcid, msg) == 0){
			if(srcid == MSGRNG_STNID_GMAC1){
				SMA_COUNTER_INC(gmac1_rx_packets);
				FFWD_DBG(0, "-------------------------------------------------gmac1_rx_packets[%d] = %u\n", process_id, ffwd_counter_info[process_id].gmac1_rx_packets);
								
				u8 * recv_data = (u8 *) phys_to_virt((u32) GET_RX_MSG_DATA(msg));
				u16 len = GET_RX_MSG_LEN(msg) - CRC_SIZE;
				FFWD_DBG(0, "message length = %u\n", GET_RX_MSG_LEN(msg));
				
				struct ether_header * ethhdr = (struct ether_header *) (recv_data);
				if(ethhdr->ether_type == ETHERTYPE_IP){
					struct ip * ipheader = (struct ip *) (recv_data + SIZEOF_ETHERHEADER);
					if(ipheader->ip_p == IPPROTO_TCP){
						struct tcphdr * tcpheader = (struct tcphdr *) (recv_data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
						FFWD_DBG(0, "sport = %u, dport = %u\n", tcpheader->th_sport, tcpheader->th_dport);
					}
				}
				// dma the packet to host
				FFWD_DBG(0, "dma packet to host\n");
				dma_pkt_load_balance(recv_data, len);
				// free GMAC1 received data
				msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
				message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
			} else {
				FFWD_DBG(0, "receive packet error, stnid = %d\n", srcid);
			}
		}
	}
}
void simple_receive_multi_rxring(){
	u64 msg;
	u32 srcid;
	u32 size;
	u32 code;
	int recv_bkt = BUCKET_RCV_PKT;
	int free_bkt = BUCKET_RCV_RSP;
	
	FFWD_DBG(0, "process id %d starting simple receive task multi rxring, recv_bkt = %d, free_bkt = %d\n", process_id, recv_bkt, free_bkt);
	while(1){
		if(message_receive_fast_1(free_bkt, size, code, srcid, msg) == 0){
			if(srcid == MSGRNG_STNID_CPU0){
				FFWD_DBG(0, "received timeout message\n");
				// todo handle timeout
				continue;
			} else if(srcid == PCIE_RX_BUCKET_ID){
				FFWD_DBG(0, "received dma respond message\n");
				continue;
			} else if(srcid == MSGRNG_STNID_GMAC1){
				FFWD_DBG(0, "received GMAC1 free back message, but this should not happen\n");
			} else {
				FFWD_DBG(0, "received unknown message\n");
				continue;
			}
		}
		if(message_receive_fast_1(recv_bkt, size, code, srcid, msg) == 0){
			if(srcid == MSGRNG_STNID_GMAC1){
				SMA_COUNTER_INC(gmac1_rx_packets);
				FFWD_DBG(0, "-------------------------------------------------gmac1_rx_packets[%d] = %u\n", process_id, ffwd_counter_info[process_id].gmac1_rx_packets);
								
				u8 * recv_data = (u8 *) phys_to_virt((u32) GET_RX_MSG_DATA(msg));
				u16 len = GET_RX_MSG_LEN(msg) - CRC_SIZE;
				FFWD_DBG(0, "message length = %u\n", GET_RX_MSG_LEN(msg));
				
				struct ether_header * ethhdr = (struct ether_header *) (recv_data);
				if(ethhdr->ether_type == ETHERTYPE_IP){
					struct ip * ipheader = (struct ip *) (recv_data + SIZEOF_ETHERHEADER);
					if(ipheader->ip_p == IPPROTO_TCP){
						struct tcphdr * tcpheader = (struct tcphdr *) (recv_data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
						FFWD_DBG(0, "sport = %u, dport = %u\n", tcpheader->th_sport, tcpheader->th_dport);
					}
				}
				// dma the packet to host
				FFWD_DBG(0, "dma the non ip packet to host\n");
				dma_pkt_multi_rxring(recv_data, len);
				// free GMAC1 received data
				msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
				message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
			} else {
				FFWD_DBG(0, "receive packet error, stnid = %d\n", srcid);
			}
		}
	}
}

void session_task_dma_load_balance(){
	u64 msg;
	u32 srcid;
	u32 size;
	u32 code;
	int recv_bkt = BUCKET_RCV_PKT;
	int free_bkt = BUCKET_RCV_RSP;
	
	FFWD_DBG(0, "process id %d starting session task dma load balance, recv_bkt = %d, free_bkt = %d\n", process_id, recv_bkt, free_bkt);
	while(1){
		if(message_receive_fast_1(free_bkt, size, code, srcid, msg) == 0){
			if(srcid == MSGRNG_STNID_CPU0){
				FFWD_DBG(0, "received timeout message\n");
				// todo handle timeout
				continue;
			} else if(srcid == PCIE_RX_BUCKET_ID){
				FFWD_DBG(0, "received dma respond message\n");
				continue;
			} else if(srcid == MSGRNG_STNID_GMAC1){
				FFWD_DBG(0, "received GMAC1 free back message\n");
				struct stlc_list_head * node = (struct stlc_list_head *) (phys_to_virt((u32) GET_RX_MSG_DATA(msg)) - sizeof(struct stlc_list_head));
				stlc_list_add_tail(node, &ack_packets_list);
			} else {
				FFWD_DBG(0, "received unknown message\n");
				continue;
			}
		}
		
		if(message_receive_fast_1(recv_bkt, size, code, srcid, msg) == 0){
			if(srcid == MSGRNG_STNID_GMAC1){
				SMA_COUNTER_INC(gmac1_rx_packets);
				FFWD_DBG(0, "-------------------------------------------------gmac1_rx_packets[%d] = %u\n", process_id, ffwd_counter_info[process_id].gmac1_rx_packets);
								
				u8 * recv_data = (u8 *) phys_to_virt((u32) GET_RX_MSG_DATA(msg));
				u16 len = GET_RX_MSG_LEN(msg) - CRC_SIZE;
				FFWD_DBG(0, "message length = %u\n", GET_RX_MSG_LEN(msg));
				
				struct ether_header * ethhdr = (struct ether_header *) recv_data;
				if(ethhdr->ether_type == ETHERTYPE_IP){
					// ip packet
					FFWD_DBG(0, "received an ip packet, length = %d\n", len);
					struct ip * iphdr = (struct ip *) (recv_data + SIZEOF_ETHERHEADER);
					FFWD_DBG(0, "ip header length = %d, ip total length = %d\n", iphdr->ip_hl * 4, iphdr->ip_len);
					if(check_sum(iphdr, iphdr->ip_hl * 4) == 0){
						FFWD_DBG(0, "ip checksum correct\n");
						if((iphdr->ip_off & IP_DF) || (iphdr->ip_off == 0)){
							// not fragmented ip packet
							FFWD_DBG(0, "not fragmented ip packet\n");
							if(iphdr->ip_p == IPPROTO_TCP){
								// tcp packet
								FFWD_DBG(0, "not fragmented tcp packet\n");
								PsdHeader psd_header;
								psd_header.saddr = iphdr->ip_src;
								psd_header.daddr = iphdr->ip_dst;
								psd_header.mbz = 0;
								psd_header.ptcl = 6;
								psd_header.tcpl = iphdr->ip_len - iphdr->ip_hl * 4;
								struct tcphdr * tcpheader = (struct tcphdr *) (recv_data + SIZEOF_ETHERHEADER + iphdr->ip_hl * 4);
								u16 payload_length = TCP_PAYLOAD_LENGTH(iphdr, tcpheader);
								FFWD_DBG(0, "sequence number of the packet is %u, ack number of the packet is %u, payload length = %u\n", tcpheader->th_seq, tcpheader->th_ack, payload_length);
								if(/*tcp_checksum(&psd_header, recv_data + SIZEOF_ETHERHEADER + iphdr->ip_hl * 4, iphdr->ip_len - iphdr->ip_hl * 4) == 0*/ 1){
									// tcp checksum correct, handle tcp large receive offload
									FFWD_DBG(0, "------------- TCP checksum correct, handle tcp large receive offload\n");
									struct packet_s * pkt = get_free_packet();
									if(pkt){
										FFWD_DBG(0, "got packet_s, packet id = %u\n", pkt->id);
										pkt->data = recv_data;
										pkt->len = len;
										// calculate tcp payload data's one complement sum
										u16 a[3];
										a[0] = ~(tcpheader->th_sum);
										tcpheader->th_sum = 0;
										u16 tcpheader_sum = one_complement_sum((u16 *) tcpheader, tcpheader->th_off * 4);
										u16 psdheader_sum = one_complement_sum((u16 *) (&psd_header), sizeof(PsdHeader));
										a[1] = ~tcpheader_sum;
										a[2] = ~psdheader_sum;
										pkt->data_sum = add_one_complement_sum(a, 3);
										tcpheader->th_sum = ~(a[0]);
										
										tlro_receive_packet_dma_load_balance(pkt);
									} else {
										printk("process %d: get free packet failed\n", process_id);
									}
								} else {
									// tcp checksum not correct, drop packet
									FFWD_DBG(0, "tcp checksum not correct! Drop the packet\n");
									// free GMAC1 received data
									msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
									message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
								}
							} else {
								// not tcp packet
								FFWD_DBG(0, "not fragmented non tcp packet, dma to host\n");
								dma_pkt_load_balance(recv_data, len);
								// free GMAC1 received data
								msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
								message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
							}
						} else {
							// fragmented ip packet, dma the packet to host
							FFWD_DBG(0, "dma fragmented ip packet to host\n");
							dma_pkt_load_balance(recv_data, len);
							// free GMAC1 received data
							msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
							message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
						}
					} else {
						// ip checksum not correct, drop packet
						FFWD_DBG(0, "ip checksum not correct! Drop the packet\n");
						// free GMAC1 received data
						msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
						message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
					}
				} else {
					// dma the non ip packet to host
					FFWD_DBG(0, "dma the non ip packet to host\n");
					dma_pkt_load_balance(recv_data, len);
					// free GMAC1 received data
					msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
					message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
				}
			} else {
				FFWD_DBG(0, "receive packet error, stnid = %d\n", srcid);
			}
		}
	}
}
void session_task_multi_rxring(){
	u64 msg;
	u32 srcid;
	u32 size;
	u32 code;
	int recv_bkt = BUCKET_RCV_PKT;
	int free_bkt = BUCKET_RCV_RSP;
	
	FFWD_DBG(0, "process id %d starting session task multi rxring, recv_bkt = %d, free_bkt = %d\n", process_id, recv_bkt, free_bkt);
	while(1){
		if(message_receive_fast_1(free_bkt, size, code, srcid, msg) == 0){
			if(srcid == MSGRNG_STNID_CPU0){
				FFWD_DBG(0, "received timeout message\n");
				// todo handle timeout
				continue;
			} else if(srcid == PCIE_RX_BUCKET_ID){
				FFWD_DBG(0, "received dma respond message\n");
				continue;
			} else if(srcid == MSGRNG_STNID_GMAC1){
				FFWD_DBG(0, "received GMAC1 free back message\n");
				struct stlc_list_head * node = (struct stlc_list_head *) (phys_to_virt((u32) GET_RX_MSG_DATA(msg)) - sizeof(struct stlc_list_head));
				stlc_list_add_tail(node, &ack_packets_list);
			} else {
				FFWD_DBG(0, "received unknown message\n");
				continue;
			}
		}
		
		if(message_receive_fast_1(recv_bkt, size, code, srcid, msg) == 0){
			if(srcid == MSGRNG_STNID_GMAC1){
				SMA_COUNTER_INC(gmac1_rx_packets);
				FFWD_DBG(0, "-------------------------------------------------gmac1_rx_packets[%d] = %u\n", process_id, ffwd_counter_info[process_id].gmac1_rx_packets);
								
				u8 * recv_data = (u8 *) phys_to_virt((u32) GET_RX_MSG_DATA(msg));
				u16 len = GET_RX_MSG_LEN(msg) - CRC_SIZE;
				FFWD_DBG(0, "message length = %u\n", GET_RX_MSG_LEN(msg));
				
				struct ether_header * ethhdr = (struct ether_header *) recv_data;
				if(ethhdr->ether_type == ETHERTYPE_IP){
					// ip packet
					FFWD_DBG(0, "received an ip packet, length = %d\n", len);
					struct ip * iphdr = (struct ip *) (recv_data + SIZEOF_ETHERHEADER);
					FFWD_DBG(0, "ip header length = %d, ip total length = %d\n", iphdr->ip_hl * 4, iphdr->ip_len);
					if(check_sum(iphdr, iphdr->ip_hl * 4) == 0){
						FFWD_DBG(0, "ip checksum correct\n");
						if((iphdr->ip_off & IP_DF) || (iphdr->ip_off == 0)){
							// not fragmented ip packet
							FFWD_DBG(0, "not fragmented ip packet\n");
							if(iphdr->ip_p == IPPROTO_TCP){
								// tcp packet
								FFWD_DBG(0, "not fragmented tcp packet\n");
								PsdHeader psd_header;
								psd_header.saddr = iphdr->ip_src;
								psd_header.daddr = iphdr->ip_dst;
								psd_header.mbz = 0;
								psd_header.ptcl = 6;
								psd_header.tcpl = iphdr->ip_len - iphdr->ip_hl * 4;
								struct tcphdr * tcpheader = (struct tcphdr *) (recv_data + SIZEOF_ETHERHEADER + iphdr->ip_hl * 4);
								u16 payload_length = TCP_PAYLOAD_LENGTH(iphdr, tcpheader);
								FFWD_DBG(0, "sequence number of the packet is %u, ack number of the packet is %u, payload length = %u\n", tcpheader->th_seq, tcpheader->th_ack, payload_length);
								if(/*tcp_checksum(&psd_header, recv_data + SIZEOF_ETHERHEADER + iphdr->ip_hl * 4, iphdr->ip_len - iphdr->ip_hl * 4) == 0*/ !(tcpheader->th_ack == 1 && payload_length == 0)){
									// tcp checksum correct, handle tcp large receive offload
									FFWD_DBG(0, "------------- TCP checksum correct, handle tcp large receive offload\n");
									struct packet_s * pkt = get_free_packet();
									FFWD_DBG(0, "got packet_s, packet id = %u\n", pkt->id);
									pkt->data = recv_data;
									pkt->len = len;
									// calculate tcp payload data's one complement sum
									u16 a[3];
									a[0] = ~(tcpheader->th_sum);
									tcpheader->th_sum = 0;
									u16 tcpheader_sum = one_complement_sum((u16 *) tcpheader, tcpheader->th_off * 4);
									u16 psdheader_sum = one_complement_sum((u16 *) (&psd_header), sizeof(PsdHeader));
									a[1] = ~tcpheader_sum;
									a[2] = ~psdheader_sum;
									pkt->data_sum = add_one_complement_sum(a, 3);
									tcpheader->th_sum = ~(a[0]);
									
									tlro_receive_packet_multi_rxring(pkt);
								} else {
									// tcp checksum not correct, drop packet
									FFWD_DBG(0, "tcp checksum not correct! Drop the packet\n");
									// free GMAC1 received data
									msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
									message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
								}
							} else {
								// not tcp packet
								FFWD_DBG(0, "not fragmented non tcp packet, dma to host\n");
								dma_pkt_multi_rxring(recv_data, len);
								// free GMAC1 received data
								msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
								message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
							}
						} else {
							// fragmented ip packet, dma the packet to host
							FFWD_DBG(0, "dma fragmented ip packet to host\n");
							dma_pkt_multi_rxring(recv_data, len);
							// free GMAC1 received data
							msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
							message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
						}
					} else {
						// ip checksum not correct, drop packet
						FFWD_DBG(0, "ip checksum not correct! Drop the packet\n");
						// free GMAC1 received data
						msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
						message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
					}
				} else {
					// dma the non ip packet to host
					FFWD_DBG(0, "dma the non ip packet to host\n");
					dma_pkt_multi_rxring(recv_data, len);
					// free GMAC1 received data
					msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
					message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
				}
			} else {
				FFWD_DBG(0, "receive packet error, stnid = %d\n", srcid);
			}
		}
	}
}
void ffwd_session_task(){
	u64 msg;
	u32 srcid;
	u32 size;
	u32 code;
	int recv_bkt = BUCKET_RCV_PKT;
	int free_bkt = BUCKET_RCV_RSP;
	
	FFWD_DBG(0, "process id %d starting session task, recv_bkt = %d, free_bkt = %d\n", process_id, recv_bkt, free_bkt);
	while(1){
		if(message_receive_fast_1(free_bkt, size, code, srcid, msg) == 0){
			if(srcid == MSGRNG_STNID_CPU0){
				FFWD_DBG(0, "received timeout message\n");
				// todo handle timeout
				continue;
			} else if(srcid == PCIE_RX_BUCKET_ID){
				FFWD_DBG(0, "received dma respond message\n");
				continue;
			} else if(srcid == MSGRNG_STNID_GMAC1){
				FFWD_DBG(0, "received GMAC1 free back message\n");
				struct stlc_list_head * node = (struct stlc_list_head *) (phys_to_virt((u32) GET_RX_MSG_DATA(msg)) - sizeof(struct stlc_list_head));
				stlc_list_add_tail(node, &ack_packets_list);
			} else {
				FFWD_DBG(0, "received unknown message\n");
				continue;
			}
		}
		
		if(message_receive_fast_1(recv_bkt, size, code, srcid, msg) == 0){
			if(srcid == MSGRNG_STNID_GMAC1){
				SMA_COUNTER_INC(gmac1_rx_packets);
				FFWD_DBG(0, "-------------------------------------------------gmac1_rx_packets[%d] = %u\n", process_id, ffwd_counter_info[process_id].gmac1_rx_packets);
								
				u8 * recv_data = (u8 *) phys_to_virt((u32) GET_RX_MSG_DATA(msg));
				u16 len = GET_RX_MSG_LEN(msg) - CRC_SIZE;
				FFWD_DBG(0, "message length = %u\n", GET_RX_MSG_LEN(msg));
				
				struct ether_header * ethhdr = (struct ether_header *) recv_data;
				if(ethhdr->ether_type == ETHERTYPE_IP){
					// ip packet
					FFWD_DBG(0, "received an ip packet, length = %d\n", len);
					struct ip * iphdr = (struct ip *) (recv_data + SIZEOF_ETHERHEADER);
					FFWD_DBG(0, "ip header length = %d, ip total length = %d\n", iphdr->ip_hl * 4, iphdr->ip_len);
					if(check_sum(iphdr, iphdr->ip_hl * 4) == 0){
						FFWD_DBG(0, "ip checksum correct\n");
						if((iphdr->ip_off & IP_DF) || (iphdr->ip_off == 0)){
							// not fragmented ip packet
							FFWD_DBG(0, "not fragmented ip packet\n");
							if(iphdr->ip_p == IPPROTO_TCP){
								// tcp packet
								FFWD_DBG(0, "not fragmented tcp packet\n");
								PsdHeader psd_header;
								psd_header.saddr = iphdr->ip_src;
								psd_header.daddr = iphdr->ip_dst;
								psd_header.mbz = 0;
								psd_header.ptcl = 6;
								psd_header.tcpl = iphdr->ip_len - iphdr->ip_hl * 4;
								struct tcphdr * tcpheader = (struct tcphdr *) (recv_data + SIZEOF_ETHERHEADER + iphdr->ip_hl * 4);
								u16 payload_length = TCP_PAYLOAD_LENGTH(iphdr, tcpheader);
								FFWD_DBG(0, "sequence number of the packet is %u, ack number of the packet is %u, payload length = %u\n", tcpheader->th_seq, tcpheader->th_ack, payload_length);
								if(/*tcp_checksum(&psd_header, recv_data + SIZEOF_ETHERHEADER + iphdr->ip_hl * 4, iphdr->ip_len - iphdr->ip_hl * 4) == 0*/ !(tcpheader->th_ack == 1 && payload_length == 0)){
									// tcp checksum correct, handle tcp large receive offload
									FFWD_DBG(0, "------------- TCP checksum correct, handle tcp large receive offload\n");
									struct packet_s * pkt = get_free_packet();
									FFWD_DBG(0, "got packet_s, packet id = %u\n", pkt->id);
									pkt->data = recv_data;
									pkt->len = len;
									// calculate tcp payload data's one complement sum
									u16 a[3];
									a[0] = ~(tcpheader->th_sum);
									tcpheader->th_sum = 0;
									u16 tcpheader_sum = one_complement_sum((u16 *) tcpheader, tcpheader->th_off * 4);
									u16 psdheader_sum = one_complement_sum((u16 *) (&psd_header), sizeof(PsdHeader));
									a[1] = ~tcpheader_sum;
									a[2] = ~psdheader_sum;
									pkt->data_sum = add_one_complement_sum(a, 3);
									tcpheader->th_sum = ~(a[0]);
									
									tlro_receive_packet(pkt);
								} else {
									// tcp checksum not correct, drop packet
									FFWD_DBG(0, "tcp checksum not correct! Drop the packet\n");
									// free GMAC1 received data
									msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
									message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
								}
							} else {
								// not tcp packet
								FFWD_DBG(0, "not fragmented non tcp packet, dma to host\n");
								dma_pkt(recv_data, len);
								// free GMAC1 received data
								msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
								message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
							}
						} else {
							// fragmented ip packet, dma the packet to host
							FFWD_DBG(0, "dma fragmented ip packet to host\n");
							dma_pkt(recv_data, len);
							// free GMAC1 received data
							msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
							message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
						}
					} else {
						// ip checksum not correct, drop packet
						FFWD_DBG(0, "ip checksum not correct! Drop the packet\n");
						// free GMAC1 received data
						msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
						message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
					}
				} else {
					// dma the non ip packet to host
					FFWD_DBG(0, "dma the non ip packet to host\n");
					dma_pkt(recv_data, len);
					// free GMAC1 received data
					msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
					message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
				}
			} else {
				FFWD_DBG(0, "receive packet error, stnid = %d\n", srcid);
			}
		}
	}
}

void simple_rx_asy(){
	u64 msg;
	u32 srcid;
	u32 size;
	u32 code;
	int recv_bkt = BUCKET_RCV_PKT;
	int free_bkt = BUCKET_RCV_RSP;
	int dma_count = 0;
	struct dma_count_s * tmp = NULL;
	
	FFWD_DBG(0, "process id %d starting session task, recv_bkt = %d, free_bkt = %d\n", process_id, recv_bkt, free_bkt);
	while(1){
		if(message_receive_fast_1(free_bkt, size, code, srcid, msg) == 0){
			if(srcid == MSGRNG_STNID_CPU0){
				FFWD_DBG(0, "received timeout message\n");
				// todo handle timeout
			} else if(srcid == PCIE_RX_BUCKET_ID){
				if(dma_count_list.next != (&dma_count_list)){
					if(dma_resp(msg) == 0){
						if(dma_data_list.next != &(dma_data_list)){
							tmp = (struct dma_count_s *) dma_data_list.next;
							// send free back message to GMAC1_FR
							msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(tmp->data));
							message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
							stlc_list_del(dma_data_list.next);
							stlc_list_add_tail(&(tmp->node), &free_dma_count_list);
						}
						dma_count++;
						tmp = (struct dma_count_s *) dma_count_list.next;
						if(dma_count == tmp->count){
							// dma a hole packet completed
							ffwd_mac_counter->rx_packets++;
							ffwd_mac_counter->rx_bytes += tmp->len;
							ffwd_mac_entry_desc_rx[tmp->offset].len = __swab16(tmp->len);
							ffwd_mac_entry_desc_rx[tmp->offset].state = FIFO_READABLE;
							FFWD_DBG(0, "dma packets succeed, rx_packets = %d\n", ffwd_mac_counter->rx_packets);
																						
							ffwd_mac_interrupt_host();
							barrier();
							dma_count = 0;
							stlc_list_del(dma_count_list.next);
							stlc_list_add_tail((struct stlc_list_head *) tmp, &free_dma_count_list);
						}
					} else {
						FFWD_DBG(0, "===================================== dma packet failed!\n");
					}
				}
			} else {
				FFWD_DBG(0, "received unknown message\n");
			}
			continue;
		}
		
		if(message_receive_fast_1(recv_bkt, size, code, srcid, msg) == 0){
			if(srcid == MSGRNG_STNID_GMAC1){
				SMA_COUNTER_INC(gmac1_rx_packets);
				FFWD_DBG(0, "-------------------------------------------------gmac1_rx_packets[%d] = %u\n", process_id, ffwd_counter_info[process_id].gmac1_rx_packets);
				
				u8 * recv_data = (u8 *) phys_to_virt((u32) GET_RX_MSG_DATA(msg));
				u16 len = GET_RX_MSG_LEN(msg) - CRC_SIZE;
				dma_pkt_asy(recv_data, len);
			} else {
				FFWD_DBG(0, "receive packet error, stnid = %d\n", srcid);
			}
		}
	}
}

void simple_rx(){
	u64 msg;
	u32 srcid;
	u32 size;
	u32 code;
	int recv_bkt = BUCKET_RCV_PKT;
	int free_bkt = BUCKET_RCV_RSP;
	
	FFWD_DBG(0, "process id %d starting session task, recv_bkt = %d, free_bkt = %d\n", process_id, recv_bkt, free_bkt);
	while(1){
		if(message_receive_fast_1(free_bkt, size, code, srcid, msg) == 0){
			if(srcid == MSGRNG_STNID_CPU0){
				FFWD_DBG(0, "received timeout message\n");
				// todo handle timeout
				continue;
			} else if(srcid == PCIE_RX_BUCKET_ID){
				FFWD_DBG(0, "received dma respond message\n");
				continue;
			} else {
				FFWD_DBG(0, "received unknown message\n");
				continue;
			}
		}
		
		if(message_receive_fast_1(recv_bkt, size, code, srcid, msg) == 0){
			if(srcid == MSGRNG_STNID_GMAC1){
				SMA_COUNTER_INC(gmac1_rx_packets);
				FFWD_DBG(0, "-------------------------------------------------gmac1_rx_packets[%d] = %u\n", process_id, ffwd_counter_info[process_id].gmac1_rx_packets);
				
				u8 * recv_data = (u8 *) phys_to_virt((u32) GET_RX_MSG_DATA(msg));
				//u16 len = GET_RX_MSG_LEN(msg) - CRC_SIZE - sizeof(struct prepad_struct);/* BUG!!! 接收长度为MTU的包时，len少14字节，数据最后10字节变0*/
				u16 len = GET_RX_MSG_LEN(msg) - CRC_SIZE;
//				struct prepad_struct * pre = (struct prepad_struct *) (recv_data);
//				recv_data += sizeof(struct prepad_struct);
//				print_prepad(pre);
				
				spin_lock(&rx_desc_lock);
				FFWD_DBG(0, "locked rx_desc_lock\n");
				u32 daddr;
				FFWD_DBG(0, "rx_offset = %u\n", rx_offset);
				if(ffwd_mac_entry_desc_rx[rx_offset].state == FIFO_WRITABLE){
					FFWD_DBG(0, "state is FIFO_WRITABLE\n");
					daddr = __swab32(ffwd_mac_entry_desc_rx[rx_offset].address);
					ffwd_msg_send_to_dma(1, igrid_to_bucket[process_id], virt_to_phys(recv_data), daddr, len, 1, PCIE_RX_BUCKET_ID);
					u32 ret = wait_dma_rsp_msg();
					if(ret == 0){
//						ffwd_mac_counter->rx_packets++;
//					    ffwd_mac_counter->rx_bytes += len;
					    ffwd_mac_entry_desc_rx[rx_offset].len = __swab16(len);
					    ffwd_mac_entry_desc_rx[rx_offset].state = FIFO_READABLE;
					    FFWD_DBG(0, "dma packet succeed, rx_packets = %d\n", ffwd_mac_counter->rx_packets);
//					    print_pkt(recv_data, len);
								
						ffwd_mac_interrupt_host();
								    
						rx_offset = (rx_offset + 1) & (MAC_ENTRY_DESC_NUM -1);
						barrier();
					} else {
						ffwd_mac_counter->rx_dropped++;
						FFWD_DBG(0, "dma packet failed, rx_dropped = %d\n", ffwd_mac_counter->rx_dropped);
					}
				} else {
					ffwd_mac_counter->rx_dropped++;
					FFWD_DBG(0, "state is not FIFO_WRITABLE, rx_dropped = %d\n", ffwd_mac_counter->rx_dropped);
				}
				//msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data - sizeof(struct prepad_struct)));
				msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(recv_data));
				barrier();
				message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
				spin_unlock(&rx_desc_lock);
				FFWD_DBG(0, "unlocked rx_desc_lock\n");
			} else {
				FFWD_DBG(0, "receive packet error, stnid = %d\n", srcid);
			}
		}
	}
}

////拼包口接收报文入口
//void ffwd_session_task()
//{
//	u64 msg;
//	u32 srcid, size, code;
//	int recv_bkt = BUCKET_RCV_PKT;
//	int free_bkt = BUCKET_RCV_RSP;
//
//	printk("pid%02d: starting session task... free_bkt = %d recv_bkt = %d\n", process_id,free_bkt,recv_bkt);
//
//	while(1)
//	{
////		ffwd_dma_task();//执行dma调度
////		
////		if (message_receive_fast_1(free_bkt, size, code, srcid, msg) == 0) 
////		{
////			if (srcid == MSGRNG_STNID_CPU0) 
////			{
////				FFWD_DBG(FFWD_DBG_DEBUG,"srcid %u recv code %u time out msg %llx\n", srcid, code, msg);
////				ffwd_recv_time_out_msg(code, msg);
////			} 
////			else if (srcid == PCIE_RX_BUCKET_ID)//收到dma返回消息
////			{
////				FFWD_DBG(FFWD_DBG_ERR,"srcid %u recv dma rsp msg %llx\n", srcid, msg);
////				continue;
////
////			}
////			else 
////			{
////				FFWD_DBG(FFWD_DBG_ERR,"srcid %u recv unkown msg %llx\n", srcid, msg);
////				continue;
////			}
////			continue;
////		}
//		
//		if (message_receive_fast_1(recv_bkt, size, code, srcid, msg) == 0)
//		{
//			switch (srcid) 
//    		{
//    			case MSGRNG_STNID_GMAC1://拼包口
//    				//ffwd_recv_session_msg(srcid, msg);
//    				SMA_COUNTER_INC(gmac1_rx_packets);
//    				FFWD_DBG(0, "-------------------------------------------------gmac1_rx_packets = %u\n", ffwd_counter_info[process_id].gmac1_rx_packets);
//    				continue;
//    			default:
//    				FFWD_DBG(FFWD_DBG_ERR, "pid %d: rcv error from %d\r\n", process_id, srcid);
//    				ASSERT(0);
//    		}
//		}
//
////		/* Calculate the rx rate. ycy. 2014.12.18 */
////		nowtime = read_32bit_cp0_register(CP0_COUNT);
////		if ((nowtime - lasttime) >= (CPU_SPEED))
////		{
////			ffwd_counter_info[process_id].gmac1_count_time = (nowtime - lasttime);
////			/* rx_bytes + 20 bytes' lead code. */
////			ffwd_counter_info[process_id].gmac1_bps = (uint64_t)((CPU_SPEED*8*((float)((ffwd_counter_info[process_id].gmac1_rx_bytes - ffwd_counter_info[process_id].gmac1_last_bytes) + 
////				(ffwd_counter_info[process_id].gmac1_rx_packets - ffwd_counter_info[process_id].gmac1_last_packets) * 20))) /
////				(ffwd_counter_info[process_id].gmac1_count_time));
////
////			ffwd_counter_info[process_id].gmac1_pps = (uint64_t)((CPU_SPEED*((float)(ffwd_counter_info[process_id].gmac1_rx_packets - ffwd_counter_info[process_id].gmac1_last_packets))) /
////				(ffwd_counter_info[process_id].gmac1_count_time));
////
////			lasttime = nowtime;
////			ffwd_counter_info[process_id].gmac1_last_bytes = ffwd_counter_info[process_id].gmac1_rx_bytes;
////			ffwd_counter_info[process_id].gmac1_last_packets = ffwd_counter_info[process_id].gmac1_rx_packets;
////		}
//	}
//	printk("pid%02d: thread exit\n",process_id);
//	return;
//	
//}

void ffwd_queue_reset_check()
{
    int queue;
    
    for( queue = 0; queue < MAX_NUM_RX_CHANNELS ; queue++)
    {    
        if(ffwd_dma_queue[queue].rx_reset == 1)
        {
            //rx_dma_base[queue] = dma_queue->rx_dma_base;
            
            rx_queue_pause[queue] = 0;
            channel_offset[queue] = 0;
            ffwd_dma_queue[queue].rx_reset = 2;
            printf("reset queue %d rx_queue_pause = %d channel_offset =%u rx_reset=%u %08x\n",
                queue,rx_queue_pause[queue],channel_offset[queue],ffwd_dma_queue[queue].rx_reset
                ,ffwd_dma_queue[queue].rx_dma_base);
            barrier();
        }
        else if(ffwd_dma_queue[queue].rx_reset == 3)
        {
            rx_queue_pause[queue] = 1;
            ffwd_dma_queue[queue].rx_reset = 0;
            printf("queue %d open rx_queue_pause=%d channel_offset =%u rx_reset=%d\n",
                queue,rx_queue_pause[queue],channel_offset[queue],ffwd_dma_queue[queue].rx_reset);
            barrier();
        }
    }
}

void ffwd_link_status()
{
//	phoenix_reg_t * mmio = phoenix_io_mmio(PHOENIX_IO_GMAC_0_OFFSET);
	phoenix_reg_t * mmio = phoenix_io_mmio(PHOENIX_IO_GMAC_4_OFFSET);
	uint8_t status = (xmdio_read(mmio,1,0,1)&0x4)&(xmdio_read(mmio,3,0,1)&0x4)&(xmdio_read(mmio,4,0,1)&0x4);
	
//	FFWD_DBG(0, "------------------------------ link status = %u\n", status);
	if(status != ffwd_mac_device_info->link)
	{
		ffwd_mac_device_info->link = status;
		ffwd_mac_interrupt_host();
		FFWD_DBG(0, "----------------------- link status changed, status = %u\n", status);
	}
		
}
static uint8_t promisc_mode = 0;

void ffwd_promisc_status()
{
//	phoenix_reg_t *mmio = phoenix_io_mmio(PHOENIX_IO_GMAC_0_OFFSET);
	phoenix_reg_t * mmio = phoenix_io_mmio(PHOENIX_IO_GMAC_4_OFFSET);
	
	if (promisc_mode != ffwd_mac_device_info->promisc)
	{
//		FFWD_DBG(0, "----------------------------------------------- promisc status changed\n");
		
		promisc_mode = ffwd_mac_device_info->promisc;
		if (ffwd_mac_device_info->promisc)
		{
			turn_off_filtering(mmio);
			printk("gmac0 open promisc mode\n");
		}
		else
		{
			turn_on_filtering(mmio);
			printk("gmac0 close promisc mode\n");
		}

	    barrier();
	}
}

void scan_task_dmaqueue(){
	FFWD_DBG(0, "process id %u starting scan_task_dmaqueue\n");
	u64 msg;
	u32 tick1;
	u32 tick2;
	int recv_bkt = BUCKET_RCV_PKT;
	int free_bkt = BUCKET_RCV_RSP;
	
	tick1 = read_32bit_cp0_register(CP0_COUNT);
	int openflag = 0;
	while(1){
		tick2 = read_32bit_cp0_register(CP0_COUNT);
		if(tick2 - tick1 >= CPU_SPEED){
			if(ffwd_device_info->cmd_state == CMD_STATE_NEW){
				if(ffwd_device_info->cmd_type == CMD_XAUI_OPEN){
					rmi_xaui_open(0);
					rmi_xaui_open(4);
					openflag = 1;
				}
				if(ffwd_device_info->cmd_type == CMD_XAUI_CLOSE){
					rmi_xaui_close(0);
						rmi_xaui_close(4);
				}
				ffwd_device_info->cmd_state = CMD_STATE_DONE;   
			}
			
			ffwd_link_status();
			tick1 = tick2;
		}
		
		while(openflag){
			spin_lock(&dma_msg_list_lock);
			if(dma_msg_list.next == &dma_msg_list){
				spin_unlock(&dma_msg_list_lock);
			} else {
				struct dma_msg_s * dmamsg = (struct dma_msg_s *) dma_msg_list.next;
				stlc_list_del(dma_msg_list.next);
				spin_unlock(&dma_msg_list_lock);
				/*
				 * received msg from session_task_pipeline processes
				 * code 0: msg is (len | virtual address of packet data), dma packet data, send free message to GMAC1_FR
				 * code packets_count: msg is (processid | virtual address of the first struct packet_s *), dma packets' data, send free message to GMAC1_FR,
				 * send msg with code packets_count and virtual address of the first struct packet_s * back to process
				 */
				FFWD_DBG(0, "received dma msg, code = %u\n", dmamsg->code);
				if(dmamsg->code == 0){
					u32 len = (u32) (dmamsg->msg >> 32);
					void * data = (void *) (u32) (dmamsg->msg & 0x00000000ffffffff);
					u32 daddr;
					FFWD_DBG(0, "rx_offset = %u\n", rx_offset);
					if(ffwd_mac_entry_desc_rx[rx_offset].state == FIFO_WRITABLE){
						FFWD_DBG(0, "state is FIFO_WRITABLE\n");
						daddr = __swab32(ffwd_mac_entry_desc_rx[rx_offset].address);
						ffwd_msg_send_to_dma(1, igrid_to_bucket[process_id], virt_to_phys(data), daddr, len, 1, PCIE_RX_BUCKET_ID);
						u32 ret = wait_dma_rsp_msg();
						if(ret == 0){
							ffwd_mac_counter->rx_packets++;
							ffwd_mac_counter->rx_bytes += len;
							ffwd_mac_entry_desc_rx[rx_offset].len = __swab16(len);
							ffwd_mac_entry_desc_rx[rx_offset].state = FIFO_READABLE;
							FFWD_DBG(0, "dma packet succeed, rx_packets = %d\n", ffwd_mac_counter->rx_packets);
														
							ffwd_mac_interrupt_host();
															
							rx_offset = (rx_offset + 1) & (MAC_ENTRY_DESC_NUM -1);
							barrier();
						} else {
							ffwd_mac_counter->rx_dropped++;
							FFWD_DBG(0, "dma packet failed, rx_dropped = %d\n", ffwd_mac_counter->rx_dropped);
						}
					} else {
						ffwd_mac_counter->rx_dropped++;
						FFWD_DBG(0, "state is not FIFO_WRITABLE, rx_dropped = %d\n", ffwd_mac_counter->rx_dropped);
					}
					msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(data));
					message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
				} else {
					u32 pid = (u32) (dmamsg->msg >> 32);
					struct packet_s * first = (struct packet_s *) (u32) (dmamsg->msg & 0x00000000ffffffff);
					struct packet_s * tmp = NULL;
					if(ffwd_mac_entry_desc_rx[rx_offset].state == FIFO_WRITABLE){
						FFWD_DBG(0, "state is FIFO_WRITABLE\n");
						u32 base = __swab32(ffwd_mac_entry_desc_rx[rx_offset].address);
						u32 len = 0;
						
						// dma the first packet
						ffwd_msg_send_to_dma(1, igrid_to_bucket[process_id], virt_to_phys(first->data), base, first->len, 1, PCIE_RX_BUCKET_ID);
						u32 ret = wait_dma_rsp_msg();
						int flag = 1;
						if(ret != 0){
							flag = 0;
							FFWD_DBG(0, "dma packet failed\n");
						}
						len += first->len;
						
						if(dmamsg->code > 1){
							int i;
							tmp = (struct packet_s *) (first->node.next);
							for(i = 0;i < dmamsg->code - 1;i++){
								struct ip * ipheader = (struct ip *) (tmp->data + SIZEOF_ETHERHEADER);
								struct tcphdr * tcpheader = (struct tcphdr *) (tmp->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
								u32 payload_len = TCP_PAYLOAD_LENGTH(ipheader, tcpheader);
								u8 * payload_data = tmp->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4 + tcpheader->th_off * 4;
								ffwd_msg_send_to_dma(1, igrid_to_bucket[process_id], virt_to_phys(payload_data), base + len, payload_len, 1, PCIE_RX_BUCKET_ID);
								ret = wait_dma_rsp_msg();
								if(ret != 0){
									flag = 0;
									FFWD_DBG(0, "dma packet failed\n");
								}
								len += payload_len;
								tmp = (struct packet_s *) (tmp->node.next);
							}
						}
						if(flag){
							ffwd_mac_counter->rx_packets++;
							ffwd_mac_counter->rx_bytes += len;
							ffwd_mac_entry_desc_rx[rx_offset].len = __swab16(len);
							ffwd_mac_entry_desc_rx[rx_offset].state = FIFO_READABLE;
							FFWD_DBG(0, "dma packets succeed, rx_packets = %d\n", ffwd_mac_counter->rx_packets);
																					
							ffwd_mac_interrupt_host();
																						
							rx_offset = (rx_offset + 1) & (MAC_ENTRY_DESC_NUM -1);
							barrier();
						} else {
							FFWD_DBG(0, "flag is 0, dma packets failed\n");
						}
					} else {
						ffwd_mac_counter->rx_dropped++;
						FFWD_DBG(0, "state is not FIFO_WRITABLE, rx_dropped = %d\n", ffwd_mac_counter->rx_dropped);
					}
					
					// send free msg to GMAC1_FR
					tmp = first;
					int i;
					for(i = 0;i < dmamsg->code;i++){
						msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(tmp->data));
						message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
						tmp = (struct packet_s *) (tmp->node.next);
					}
					
					// send msg with code packets_count and virtual address of the first struct packet_s * back to process
					msg = ((u64) (u32) first);
					if(ffwd_message_send_code_1(dmamsg->code, igrid_to_bucket[pid], msg) != 0){
						FFWD_DBG(0, "send msg to scan process failed\n");
					} else {
						FFWD_DBG(0, "send msg to scan process succeed\n");
					}
				}
				// send msg with code 0xff and virtual address of dmamsg back to session task process
				msg = ((u64) (u32) dmamsg);
				if(ffwd_message_send_code_1(0xff, igrid_to_bucket[dmamsg->pid], msg) != 0){
					FFWD_DBG(0, "send msg to scan process failed\n");
				} else {
					FFWD_DBG(0, "send msg to scan process succeed\n");
				}
			}
		}
	}
}

void scan_task_dma_load_balance(){
	FFWD_DBG(0, "process id %u starting scan_task_pipeline\n", process_id);
	u64 msg;
	u32 srcid;
	u32 size;
	u32 code;
	u32 tick1;
	u32 tick2;
	int recv_bkt = BUCKET_RCV_PKT;
	int free_bkt = BUCKET_RCV_RSP;
	
	tick1 = read_32bit_cp0_register(CP0_COUNT);
	int openflag = 0;
	int idx = 0;
	while(1){
		tick2 = read_32bit_cp0_register(CP0_COUNT);
		if(tick2 - tick1 >= CPU_SPEED){
			if(ffwd_device_info->cmd_state == CMD_STATE_NEW){
				if(ffwd_device_info->cmd_type == CMD_XAUI_OPEN){
					rmi_xaui_open(0);
					rmi_xaui_open(4);
					openflag = 1;
				}
				if(ffwd_device_info->cmd_type == CMD_XAUI_CLOSE){
					rmi_xaui_close(0);
						rmi_xaui_close(4);
				}
				ffwd_device_info->cmd_state = CMD_STATE_DONE;   
			}
			
			ffwd_link_status();
			tick1 = tick2;
		}
		
		while(openflag){
			if(dma_balance_list[idx].next != &(dma_balance_list[idx])){
				spin_lock(&(dma_balance_list_lock[idx]));
				struct dma_balance_msg_s * bmsg = (struct dma_balance_msg_s *) (dma_balance_list[idx].next);
				stlc_list_del(dma_balance_list[idx].next);
				spin_unlock(&(dma_balance_list_lock[idx]));
				
				FFWD_DBG(0, "dma_balance_rx_offset[%d] = %d\n", idx, dma_balance_rx_offset[idx]);
				ffwd_msg_send_to_dma(1, igrid_to_bucket[idx + FIRST_SESSION_THREAD], virt_to_phys(bmsg->data), bmsg->daddr, bmsg->len, 1, PCIE_RX_BUCKET_ID);
				
				spin_lock(&(free_dma_balance_list_lock[idx]));
				stlc_list_add_tail(&(bmsg->node), &(free_dma_balance_list[idx]));
				spin_unlock(&(free_dma_balance_list_lock[idx]));
			}
			idx = (idx + 1) % TLRO_RX_RING_COUNT;
		}
	}
}
void scan_task_pipeline(){
	FFWD_DBG(0, "process id %u starting scan_task_pipeline\n");
	u64 msg;
	u32 srcid;
	u32 size;
	u32 code;
	u32 tick1;
	u32 tick2;
	int recv_bkt = BUCKET_RCV_PKT;
	int free_bkt = BUCKET_RCV_RSP;
	
	tick1 = read_32bit_cp0_register(CP0_COUNT);
	int openflag = 0;
	while(1){
		tick2 = read_32bit_cp0_register(CP0_COUNT);
		if(tick2 - tick1 >= CPU_SPEED){
			if(ffwd_device_info->cmd_state == CMD_STATE_NEW){
				if(ffwd_device_info->cmd_type == CMD_XAUI_OPEN){
					rmi_xaui_open(0);
					rmi_xaui_open(4);
					openflag = 1;
				}
				if(ffwd_device_info->cmd_type == CMD_XAUI_CLOSE){
					rmi_xaui_close(0);
						rmi_xaui_close(4);
				}
				ffwd_device_info->cmd_state = CMD_STATE_DONE;   
			}
			
			ffwd_link_status();
			tick1 = tick2;
		}
		
		while(openflag){
			if(message_receive_fast_1(free_bkt, size, code, srcid, msg) == 0){
				if((srcid == MSGRNG_STNID_CPU1) || (srcid == MSGRNG_STNID_CPU2) || (srcid == MSGRNG_STNID_CPU3)){
					/*
					 * received msg from session_task_pipeline processes
					 * code 0: msg is (len | virtual address of packet data), dma packet data, send free message to GMAC1_FR
					 * code packets_count: msg is (processid | virtual address of the first struct packet_s *), dma packets' data, send free message to GMAC1_FR,
					 * send msg with code packets_count and virtual address of the first struct packet_s * back to process
					 */
					FFWD_DBG(0, "received dma task message, code = %u\n", code);
					if(code == 0){
						u32 len = (u32) (msg >> 32);
						void * data = (void *) (u32) (msg & 0x00000000ffffffff);
						u32 daddr;
						FFWD_DBG(0, "rx_offset = %u\n", rx_offset);
						if(ffwd_mac_entry_desc_rx[rx_offset].state == FIFO_WRITABLE){
							FFWD_DBG(0, "state is FIFO_WRITABLE\n");
							daddr = __swab32(ffwd_mac_entry_desc_rx[rx_offset].address);
							ffwd_msg_send_to_dma(1, igrid_to_bucket[process_id], virt_to_phys(data), daddr, len, 1, PCIE_RX_BUCKET_ID);
							u32 ret = wait_dma_rsp_msg();
							if(ret == 0){
								ffwd_mac_counter->rx_packets++;
								ffwd_mac_counter->rx_bytes += len;
								ffwd_mac_entry_desc_rx[rx_offset].len = __swab16(len);
								ffwd_mac_entry_desc_rx[rx_offset].state = FIFO_READABLE;
								FFWD_DBG(0, "dma packet succeed, rx_packets = %d\n", ffwd_mac_counter->rx_packets);
															
								ffwd_mac_interrupt_host();
																
								rx_offset = (rx_offset + 1) & (MAC_ENTRY_DESC_NUM -1);
								barrier();
							} else {
								ffwd_mac_counter->rx_dropped++;
								FFWD_DBG(0, "dma packet failed, rx_dropped = %d\n", ffwd_mac_counter->rx_dropped);
							}
						} else {
							ffwd_mac_counter->rx_dropped++;
							FFWD_DBG(0, "state is not FIFO_WRITABLE, rx_dropped = %d\n", ffwd_mac_counter->rx_dropped);
						}
						msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(data));
						message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
					} else {
						u32 pid = (u32) (msg >> 32);
						struct packet_s * first = (struct packet_s *) (u32) (msg & 0x00000000ffffffff);
						struct packet_s * tmp = NULL;
						if(ffwd_mac_entry_desc_rx[rx_offset].state == FIFO_WRITABLE){
							FFWD_DBG(0, "state is FIFO_WRITABLE\n");
							u32 base = __swab32(ffwd_mac_entry_desc_rx[rx_offset].address);
							u32 len = 0;
							
							// dma the first packet
							ffwd_msg_send_to_dma(1, igrid_to_bucket[process_id], virt_to_phys(first->data), base, first->len, 1, PCIE_RX_BUCKET_ID);
							u32 ret = wait_dma_rsp_msg();
							int flag = 1;
							if(ret != 0){
								flag = 0;
								FFWD_DBG(0, "dma packet failed\n");
							}
							len += first->len;
							
							if(code > 1){
								int i;
								tmp = (struct packet_s *) (first->node.next);
								for(i = 0;i < code - 1;i++){
									struct ip * ipheader = (struct ip *) (tmp->data + SIZEOF_ETHERHEADER);
									struct tcphdr * tcpheader = (struct tcphdr *) (tmp->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4);
									u32 payload_len = TCP_PAYLOAD_LENGTH(ipheader, tcpheader);
									u8 * payload_data = tmp->data + SIZEOF_ETHERHEADER + ipheader->ip_hl * 4 + tcpheader->th_off * 4;
									ffwd_msg_send_to_dma(1, igrid_to_bucket[process_id], virt_to_phys(payload_data), base + len, payload_len, 1, PCIE_RX_BUCKET_ID);
									ret = wait_dma_rsp_msg();
									if(ret != 0){
										flag = 0;
										FFWD_DBG(0, "dma packet failed\n");
									}
									len += payload_len;
									tmp = (struct packet_s *) (tmp->node.next);
								}
							}
							if(flag){
								ffwd_mac_counter->rx_packets++;
								ffwd_mac_counter->rx_bytes += len;
								ffwd_mac_entry_desc_rx[rx_offset].len = __swab16(len);
								ffwd_mac_entry_desc_rx[rx_offset].state = FIFO_READABLE;
								FFWD_DBG(0, "dma packets succeed, rx_packets = %d\n", ffwd_mac_counter->rx_packets);
																						
								ffwd_mac_interrupt_host();
																							
								rx_offset = (rx_offset + 1) & (MAC_ENTRY_DESC_NUM -1);
								barrier();
							} else {
								FFWD_DBG(0, "flag is 0, dma packets failed\n");
							}
						} else {
							ffwd_mac_counter->rx_dropped++;
							FFWD_DBG(0, "state is not FIFO_WRITABLE, rx_dropped = %d\n", ffwd_mac_counter->rx_dropped);
						}
						
						// send free msg to GMAC1_FR
						tmp = first;
						int i;
						for(i = 0;i < code;i++){
							msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID, virt_to_phys(tmp->data));
							message_send_block_fast_1(0, MSGRNG_STNID_GMAC1_FR, msg);
							tmp = (struct packet_s *) (tmp->node.next);
						}
						
						// send msg with code packets_count and virtual address of the first struct packet_s * back to process
						msg = ((u64) (u32) first);
						if(ffwd_message_send_code_1(code, igrid_to_bucket[pid], msg) != 0){
							FFWD_DBG(0, "send msg to scan process failed\n");
						} else {
							FFWD_DBG(0, "send msg to scan process succeed\n");
						}
					}
				} else if(srcid == PCIE_RX_BUCKET_ID){
					FFWD_DBG(0, "received dma respond message, but this should not happen\n");
				} else {
					FFWD_DBG(0, "received unknown message, this should not happen\n");
				}
			}
		}
	}
}
void ffwd_scan_task()
{
	u64 msg;
	int i;
	u32 start, tick=0, start2 = 0, tick2 = 0;
	
//	//由于0号线程用于bootloader shell暂时没有启用，分配的哈希桶未能做初始化，因此不能对此空间扫描 
//	struct stlc_hlist_head *base = (struct stlc_hlist_head *)(SESSION_BKT_BASE + MAXNUM_FLOW_BUCKET * sizeof(struct stlc_hlist_head));
//	struct stlc_hlist_node *tmp = NULL, *tmp2 = NULL;
//	session_desc_t *entry = NULL;

	//printk("pid %02d : starting scan task, time_out %llx base %p\n", process_id, time_out, base);
	now = 0;

	tick2 = start = read_32bit_cp0_register(CP0_COUNT);
	while(1)
	{
		tick = read_32bit_cp0_register(CP0_COUNT) ;
		now += (tick-start);
		start = tick;

//		for (i=0; i<MAXNUM_FLOW_BUCKET * (MAXNUM_VCPU-1); i++) //session node desc
//		{
//			spin_lock((spinlock_t *)&(base[i].lock));
//			stlc_hlist_for_each_entry_safe(entry, tmp, tmp2, &base[i], nd_hlist) 
//			{
//				if (now - entry->timer_tick >= time_out)
//				{
//					if (entry->timeout == FALSE) 
//					{
//						msg = FMN_MAKE_TIME_OUT_MSG(entry);
//						barrier();
//		
//						if (ffwd_message_send_code_1(FMN_MSG_CODE_TIMEOUT, igrid_to_bucket[entry->pid], msg) != 0) 
//						{
//							FFWD_DBG(FFWD_DBG_DEBUG, "pid %02d send to bkt %u err  msg %16llx\n", process_id,igrid_to_bucket[entry->pid], msg);
//						} 
//						else 
//						{
//							entry->timeout = TRUE;
//							//FFWD_DBG(FFWD_DBG_DEBUG, "pid %02d send to bkt %u ok  msg %16llx\n", process_id,igrid_to_bucket[entry->pid], msg);
//						}
//					}
//				}
//			}
//			spin_unlock((spinlock_t *)&(base[i].lock));
//		}

		tick2 = read_32bit_cp0_register(CP0_COUNT);

		if (tick2 - start2 >= CPU_SPEED)
		{
		    if(ffwd_device_info->cmd_state == CMD_STATE_NEW)
		    {
		        if(ffwd_device_info->cmd_type == CMD_XAUI_OPEN)
		        {
		            rmi_xaui_open(0);
		            rmi_xaui_open(4);
		        }    
		        if(ffwd_device_info->cmd_type == CMD_XAUI_CLOSE)
		        {
		            rmi_xaui_close(0);
		            rmi_xaui_close(4);
                }
		        ffwd_device_info->cmd_state = CMD_STATE_DONE;   
		    }

//            //流超时时间
//            if(ffwd_device_info->timeout_value != time_out/CPU_SPEED)
//            {
//                time_out = ffwd_device_info->timeout_value * CPU_SPEED;
//                printk("session timeout value %d (s)\r\n",time_out/CPU_SPEED);
//            }

//            ffwd_promisc_status();
            
			ffwd_link_status();
//            //接收队列分发向量检查
//            ffwd_pde_vc_update();
//
//			ffwd_queue_reset_check();
			
			start2 = tick2;

//            phoenix_reg_t *mmio = phoenix_io_mmio(PHOENIX_IO_GMAC_4_OFFSET);
//            uint32_t rx = phoenix_read_reg(mmio,G_RPKT);
//            uint32_t tx = phoenix_read_reg(mmio,G_TPKT);
//            printk("rx packet(%u) tx packet(%u)\n",rx,tx); 
            
             
		}
		
	}
	printk("pid%02d: thread exit\n",process_id);
}


