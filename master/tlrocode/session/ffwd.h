#ifndef __FFWD_H__
#define __FFWD_H__

#include "sma_table.h"
#include "sma.h"
#include "ffwd_debug.h"
#include "stlc_list.h"

#define OK (0)
#define ERROR (-1)


/* th_flags */
#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20

#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */


#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#define	ETHERTYPE_8021Q	    0x8100	/*802.1Q protocol*/

#define IPPROTO_UDP     17
#define IPPROTO_TCP     6


struct ip
{
    uint32_t	ip_v : 4,			/* version */
                ip_hl : 4,		/* header length */
                ip_tos : 8,		/* type of service */
                ip_len : 16;		/* total length */
    uint16_t	ip_id;			/* identification */
    uint16_t	ip_off;			/* fragment offset field */
    uint8_t	    ip_ttl;			/* time to live */
    uint8_t	    ip_p;			/* protocol */
    uint16_t	ip_sum;			/* checksum */
    uint32_t    ip_src;
    uint32_t    ip_dst;	/* source and dest address */
};

struct tcphdr
{
    uint16_t th_sport;		/* source port */
    uint16_t th_dport;		/* destination port */
    uint32_t th_seq;			/* sequence number */
    uint32_t th_ack;			/* acknowledgement number */
    uint32_t th_off : 4,		/* data offset */
    th_x2 : 4,		/* (unused) */
    th_flags : 8,
    th_win : 16;		/* window */
    uint16_t th_sum;			/* checksum */
    uint16_t th_urp;			/* urgent pointer */
} __attribute__((aligned(1)));

struct udphdr
{
    uint16_t uh_sport;       /* source port */
    uint16_t uh_dport;       /* destination port */
    uint16_t uh_ulen;      /* udp length */
    uint16_t uh_sum;         /* udp checksum */
} __attribute__((aligned(1)));

struct	ether_header
{
    uint8_t ether_dhost[6];
    uint8_t ether_shost[6];
    uint16_t ether_type;
};

typedef struct session_key_s
{
	u32 sip;
	u32 dip;
	u16 sport;
	u16 dport;
}session_key_t;

//xls_packet_t 数据结构必须填充64字节否则出错
typedef struct xls_packet_s
{
	u8* data;
	u16 pkt_len;    //报文总长度
	u16 data_len;   //报文数据部分长度
	session_key_t key;
	u16 protocol;
	u8  direction;
	u8  th_flags;
	u16 hash; //28 最大为65536
	uint16_t de_num;
    uint32_t teid;
	u32 seq;//udp=0
	u32 nseq;//= seq + data_len 用于seq与ack都相等时比较报文的先后
	u32 ack;//udp=0
	struct xls_packet_s *next_pkt;	

	u64 smac;//本报文的实际smac
	u64 dmac;//本报文的实际dmac 
	u8 pkt_data[0];//指向以太帧头前预留的64字节
}xls_packet_t;

#define IP_HLEN	sizeof(struct ip)

#define REQ_DIRECT 0
#define RSP_DIRECT 1
#define PKT_RESERVE_SIZE 64 //预留以填充dma描述

typedef struct session_node_s
{
	session_key_t key;
	uint16_t protocol; //这里改变了，由8变为16
	uint16_t stop_sec;//会话结束时置1，否则为0，这里位置移到这里了
	uint16_t pkt_num;// 这里也由8变成16
	uint16_t total_paylen;
	uint32_t hash;//
    uint32_t teid;
	int pid;
	xls_packet_t *pkt;//合并上下行后首个报文描述符地址
	xls_packet_t *req_pkt_head;//首个上行报文描述符地址
	xls_packet_t *rsp_pkt_head;//首个下行报文描述符地址
	
	xls_packet_t *req_pkt_tail;//最后一个上行报文描述符地址
	xls_packet_t *rsp_pkt_tail;//最后一个下行报文描述符地址
	xls_packet_t *pkt_tail;//最后一个报文描述符地址

	xls_packet_t *req_drop_head;//需丢弃的上行报文描述符地址
	xls_packet_t *rsp_drop_head;//需丢弃的下行报文描述符地址
	xls_packet_t *req_drop_tail;//需丢弃的上行报文描述符地址
	xls_packet_t *rsp_drop_tail;//需丢弃的下行报文描述符地址
  
	u8 c_fin;//上行结束标志(fin 或者rst标志)
	u8 s_fin;//下行结束标志(如果上下行都结束了，认为这个会话完成)
    u8 rst;

	u8 timeout;
	//uint32_t cip_hash;//客户端ip 分流hash
	u64 timer_tick;//插入到流表的时间点s
	
	u32 dma_base;//dma pkt 提交基地址
	u32 dma_in;//dma通道写索引值 
	entry_state_desc_t * rx_desc;
	xls_packet_t *dma_pkt;//当前正在提交的pkt
	u32 dma_total_paylen;//当前提交的数据长度

	struct stlc_list_head nd_list;//提交链接下一个会话节点 
	struct stlc_hlist_node nd_hlist;//流表节点 
	struct session_node_s *next;//链接下一个会话节点
}__attribute__ ((aligned (256)))  session_desc_t;


typedef struct mac_packet_s
{
	struct stlc_list_head list;//提交链接下一个节点 
    uint32_t len;
    uint8_t pad[20];
	uint8_t data[0];
	
}mac_packet_t;


#define CPU_SPEED	800000000ULL
#define MAXNUM_VCPU 16
#define MASK_2K_ALIGN 0xfffff800

extern int core_id;
extern int thread_id;
extern int process_id;

extern ffwd_dma_queue_t * ffwd_dma_queue ;
extern ffwd_device_info_t * ffwd_device_info ;
extern entry_state_desc_t * ffwd_session_state_base ;
extern entry_state_desc_t * ffwd_udp_state_base ;
extern ffwd_counter_info_t * ffwd_counter_info;

extern ffwd_mac_entry_desc_t * ffwd_mac_entry_desc_rx;
extern ffwd_mac_entry_desc_t * ffwd_mac_entry_desc_tx;
extern ffwd_mac_device_info_t * ffwd_mac_device_info;
extern ffwd_mac_counter_t * ffwd_mac_counter;
extern struct stlc_list_head mac_pkt_pool;

// 32 rx rings
extern ffwd_mac_entry_desc_t * tlro_rx_entry_desc[TLRO_RX_RING_COUNT];

extern struct stlc_hlist_head *session_bkt;
extern session_desc_t *session_desc_head;

extern spinlock_t   ffwd_init_lock    __shared_memory__;
extern volatile int ffwd_init_done  __shared_memory__;
extern spinlock_t session_channel_lock[MAX_NUM_RX_CHANNELS] __shared_memory__;
extern u32 channel_offset[MAX_NUM_RX_CHANNELS] __shared_memory__;

extern u8 igrid_to_bucket[];
extern u64 time_out __shared_memory__;
extern u64 now __shared_memory__;

extern struct stlc_list_head dma_list;


#define SESSION_BKT_BASE 0x10000000
#define MAXNUM_FLOW_BUCKET 65536
#define SESSION_BKT_SIZE (MAXNUM_FLOW_BUCKET * sizeof(struct stlc_hlist_head) *MAXNUM_VCPU)
#define SESSION_DESC_SIZE 256
#define MAXNUM_SESSION_DESC_TH ((256*1024*1024 - SESSION_BKT_SIZE)/SESSION_DESC_SIZE/MAXNUM_VCPU) //会话描述符总大小为256M

#define SMA_COUNTER_INC(what) ffwd_counter_info[process_id].what++
#define SMA_COUNTER_DEC(what) ffwd_counter_info[process_id].what--
#define SMA_COUNTER_COUNT(what, len) ffwd_counter_info[process_id].what += len







extern struct stlc_list_head free_packets_list;
extern struct stlc_list_head big_packets_list;
extern struct stlc_list_head ack_packets_list;
extern struct stlc_list_head dma_count_list;
extern struct stlc_list_head dma_data_list;
extern struct stlc_list_head free_dma_count_list;
extern u16 dma_count;
extern struct stlc_list_head free_dma_msg_list;
extern struct stlc_list_head dma_msg_list;
extern spinlock_t dma_msg_list_lock;

extern struct stlc_hlist_head * session_buckets;/* 用于tcp会话，每个cpu都分配 */
extern struct stlc_list_head session_desc_list_head;/* 用于tcp会话， 每个cpu都分配 */
extern spinlock_t rx_desc_lock;
extern volatile int rx_offset;
extern volatile int tx_offset;

extern int tlro_rx_offset;// allocate for each thread

// for dma load balancing
extern struct stlc_list_head free_dma_balance_list[TLRO_RX_RING_COUNT] __shared_memory__;
extern struct stlc_list_head dma_balance_list[TLRO_RX_RING_COUNT] __shared_memory__;
extern spinlock_t dma_balance_list_lock[TLRO_RX_RING_COUNT] __shared_memory__;
extern spinlock_t free_dma_balance_list_lock[TLRO_RX_RING_COUNT] __shared_memory__;
extern int dma_balance_rx_offset[TLRO_RX_RING_COUNT] __shared_memory__;

struct tx_desc_s{
	u8 state;
	u16 len;
	u32 addr;/* dma bus address */
	u32 sn;/* serial number for a packet */
};

struct rx_desc_s{
	u8 state;
	u64 skb_reserve;
	u16 data_len;
	u32 phy_addr;
};

struct session_key {
	u32 sip;
	u32 dip;
	u16 sport;
	u16 dport;
};/*
 * for receiving packets from GMAC0
 */
struct packet_s {
	struct stlc_list_head node;/* convenient for type cast */
	u32 len;/* total packet length, not including ether header and CRC size */
	u8 * data;/* starting from ether header */
	u16 hash;
	u16 data_sum;/* tcp payload data's one complement sum */
	u32 id;
};

struct big_packet{
	struct stlc_list_head node;/* convenient for type cast */
	u32 len;/* total packet length, not including ether header and CRC size */
	u8 padding[20];
	//u8 type;
	u8 data[65536 + 14 + 40 + 4];/* starting from ether header */
};

typedef struct //定义TCP伪首部
{
    uint32_t saddr; //源地址
    uint32_t daddr; //目的地址
    char mbz;
    char ptcl; //协议类型
    uint16_t tcpl; //TCP长度
}PsdHeader;

enum {
	INET_ECN_NOT_ECT = 0,
	INET_ECN_ECT_1 = 1,
	INET_ECN_ECT_0 = 2,
	INET_ECN_CE = 3,
	INET_ECN_MASK = 3,
};

static inline int INET_ECN_is_ce(u8 dsfield){
	return (dsfield & INET_ECN_MASK) == INET_ECN_CE;
}

#define IPH_LEN_WO_OPTIONS 5 /* ip header with out options */
#define TCPH_LEN_WO_OPTIONS 5/* tcp header without options */
#define TCPH_LEN_W_TIMESTAMP 8/* tcp header with timestamp */

#define MAX_TLRO_DESC_NUM 65536

/*
 * TCP Large Receive Offload descriptor for a tcp session
 */
struct tlro_desc {
	struct stlc_list_head node;/* convenient for type cast */
	struct stlc_hlist_node nd_hlist;/* in case of hash collision*/
	struct stlc_list_head packets;/* received tcp packets list, empty head node of the list */
	struct session_key key;
	u32 tcp_rcv_tsecr;
	u32 tcp_rcv_tsval;
	u32 tcp_ack;
	u32 tcp_next_seq;
	u16 ip_total_len;
	u16 tcp_saw_tstamp;/* time stamps enabled */
	u32 ts_recent;// 
	u16 tcp_window;
	int pid;/* processor id 0-15 */
	u8 active;
	u32 tick;
	u32 packets_count;/* the number of packets in the packets list */
//	u32 id;
	u32 rxoffset;
};

struct ack_packet_s{
	struct stlc_list_head node;
	u8 data[66];// 14 + 20 + 32, with timestamp option
};

struct dma_count_s{
	struct stlc_list_head node;
	u16 len;
	u16 count;
	u32 offset;
	u8 * data;
};

struct dma_msg_s{
	struct stlc_list_head node;
	u8 code;
	u32 pid;
	u64 msg;
};

struct dma_balance_msg_s{
	struct stlc_list_head node;
	u8 * data;
	u16 len;
	u32 daddr;
};

#define sysTimerClkFreq	800000000ULL
#define SIZEOF_ETHERHEADER      14
#define SIZEOF_CRC 4	

#define	TCPOPT_EOL			0
#define	TCPOPT_NOP			1
#define	TCPOPT_MAXSEG			2
#define TCPOLEN_MAXSEG			4
#define TCPOPT_WINDOW			3
#define TCPOLEN_WINDOW			3
#define TCPOPT_SACK_PERMITTED		4		/* Experimental */
#define TCPOLEN_SACK_PERMITTED		2
#define TCPOPT_SACK			5		/* Experimental */
#define TCPOPT_TIMESTAMP		8
#define TCPOLEN_TIMESTAMP		10
#define TCPOLEN_TSTAMP_APPA		(TCPOLEN_TIMESTAMP+2) /* appendix A */
#define TCPOLEN_SIGNATURE		18
#define TCPOPT_SIGNATURE		19
#define TCP_HDR_LEN(tcph) (tcph->th_off << 2)
#define IP_HDR_LEN(iph) (iph->ip_hl << 2)
#define TCP_PAYLOAD_LENGTH(iph, tcph) \
	(iph->ip_len - IP_HDR_LEN(iph) - TCP_HDR_LEN(tcph))

#define TLRO_TIMEOUT_CODE 0
#endif
