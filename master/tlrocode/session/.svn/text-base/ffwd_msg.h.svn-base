#ifndef __FFWD_MSG_H__
#define __FFWD_MSG_H__
#include "msgring.h"

#include "ffwd.h"

extern int core_id;
extern int thread_id;
extern int process_id;

 
#define PCIE_RX_BUCKET_ID 64
#define PCIE_TX_BUCKET_ID 65

#define BUCKET_RCV_PKT ((process_id & 0x3) + 4)
#define BUCKET_RCV_RSP (process_id & 0x3)

//#define CP_BUCKET_ID MSGRNG_STNID_GMACTX0
#define CRC_SIZE 4

#define FMN_MSG_EOF 1
#define FMN_MSG_NOEOF 0
#define FMN_MSG_NOFREE_FBID 127

#define FMN_MSG_CODE_TIMEOUT 1

#define SET_TX_MSG_EOF(eof) (((u64)eof << 63))
#define SET_TX_MSG_FBID(fbid) (((u64)fbid << 54))
#define SET_TX_MSG_LEN(len) (((u64)len << 40))
#define SET_TX_MSG_ADDR(addr) (((u64)(u32)(addr)))

#define GET_RX_MSG_DATA(msg) ((u64)msg & 0x0000000fffffffe0ULL)
#define GET_RX_MSG_PORT(msg) ((u64)msg & 0xf)
#define GET_RX_MSG_LEN(msg) (((u64)msg >> 40) & 0x3fff)
#define IS_RX_MSG_ERROR(msg) ((msg)&((u64)1<<62))


#define FMN_MAKE_TX_MSG(eof, fbid, len, addr)\
	SET_TX_MSG_EOF((eof)) | SET_TX_MSG_FBID((fbid)) | SET_TX_MSG_LEN((len)) | SET_TX_MSG_ADDR((addr))

#define FMN_MAKE_FREE_MSG(fbid, addr)\
	SET_TX_MSG_EOF(FMN_MSG_EOF) | SET_TX_MSG_FBID((fbid)) | SET_TX_MSG_ADDR((addr))

#define FMN_MAKE_FREE_IN_MSG(addr) SET_TX_MSG_ADDR((addr))

#define FMN_MAKE_TIME_OUT_MSG(addr) SET_TX_MSG_ADDR((addr))


#define ffwd_message_receive_fast(bucket, size, srcid, msg0, msg1, msg2, msg3)      \
        ( { unsigned int _status=0, _tmp=0;                     \
           msgrng_receive(bucket);                              \
           while ( (_status=msgrng_read_status()) & 0x08) ;     \
           _tmp = _status & 0x30;                               \
           if (likely(!_tmp)) {                                 \
                 (size)=((_status & 0xc0)>>6)+1;                \
                 (srcid)=(_status & 0x7f0000)>>16;               \
                 (msg0)=msgrng_load_rx_msg0();                  \
                 (msg1)=msgrng_load_rx_msg1();                  \
                 (msg2)=msgrng_load_rx_msg2();                  \
                 (msg3)=msgrng_load_rx_msg3();                  \
                 _tmp=0;                                        \
                }                                               \
           _tmp;                                                \
        } )

#define ffwd_message_receive_fast_1(bucket, srcid, msg0)      \
        ( { unsigned int _status=0, _tmp=0;                     \
           msgrng_receive(bucket);                              \
           while ( (_status=msgrng_read_status()) & 0x08) ;     \
           _tmp = _status & 0x30;                               \
           if (likely(!_tmp)) {                                 \
                 (srcid)=(_status & 0x7f0000)>>16;               \
                 (msg0)=msgrng_load_rx_msg0();                  \
                 _tmp=0;                                        \
                }                                               \
           _tmp;                                                \
        } )

static inline int ffwd_message_send_code_1(u32 code, unsigned int stid, u64 msg)
{
	unsigned long long  status = 0;
	//unsigned int  cp0_status = read_c0_status();
	int i=0;
	unsigned int dest = 0;

	dest = (code<<8)|(stid);
	msgrng_load_tx_msg0(msg);

	for(i=0;i<128;i++) {
		msgrng_send(dest);
		/* Check the status */
		status = msgrng_read_status();
		status = status & 0x7;
		if (status & 0x6) {
		 	continue;
		} else 
			break;
	}
	if (i==128) {
		FFWD_DBG(FFWD_DBG_DEBUG, "Unable to send msg to %u code %llx \n", stid, (status & 0x6));
		return status & 0x6;
	}

	return 0;
}

static inline int ffwd_message_send_1(unsigned int stid, u64 msg)			       
{
	unsigned long long  status = 0;
	//unsigned int  cp0_status = read_c0_status();
	unsigned int dest = 0;
	int i=0;

	barrier();

	status = msgrng_read_status();

	msgrng_load_tx_msg0(msg);

	dest = stid;

#ifdef MSGRING_DUMP_MESSAGES
	dbg_msg("Sending msg<%llx> to dest = %x\n", 
		msg, dest);
#endif
	

	for(i=0;i<MAX_MSGSND_TRIES;i++) {
		msgrng_send(dest);
		/* Check the status */
		status = msgrng_read_status();
		status = status & 0x7;
		if (status & 0x6) {
		  /* either previous send failed or no credits
		   * return error
		   */		  
		  continue;
		}
		else break;
	}
	if (i==MAX_MSGSND_TRIES) {
		//dbg_msg("Unable to send msg to %Lx\n", dest);
		return status & 0x6;
	}

	return 0;
}

static inline void drop_session_pkt(xls_packet_t *pkt)
{
	u64 msg;

	SMA_COUNTER_INC(gmac1_free_packets);
	msg = FMN_MAKE_FREE_MSG(FMN_MSG_NOFREE_FBID,virt_to_phys(pkt->pkt_data+PKT_RESERVE_SIZE));			
	FFWD_DBG(FFWD_DBG_DEBUG,"fbid: %d, free NO %u addr %x\r\n", MSGRNG_STNID_GMAC1_FR, pkt->de_num, (u32)virt_to_phys(pkt->pkt_data+PKT_RESERVE_SIZE));
	barrier();
	message_send_block_fast_1(0,MSGRNG_STNID_GMAC1_FR, msg);
	return;
}

#endif
