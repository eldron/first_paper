/**
 * @mainpage 项目简介
 *
 * @section intro_sec Introduction
 *
 * SMA (Session Management Accelerator) 是一种进行会话管理加速的卡
 * 主要用于降低服务器在进行协议还原时会话管理的计算负载.
 * SMA能够对TCP 流执行顺序整理、重传报文清理等工作,
 * 将以一个完整会话提交分析服务器,
 * 从而显著提高分析服务器的性能.
 * 另外，SMA能够对报文进行多元组固定域的过滤,
 * 衰减服务器不关心的流量.
 * 同时SMA能够对重组的报文进行多核分流,
 * 从而使得多个流可以被多个服务器核并发处理.
 * 测试表明,采用SMA进行会话管理可以提高双CPU服务器2倍以上的性能.
 * SMA系列卡采用PCI-E接口与服务器相连接,
 * 通过DMA将重组后的数据块直接导入到服务器内存.
 *
 *
 * @section install_sec Installation
 *  TCP 数据格式
 *  ----------------------------------------------------------------------------------------------------
 *  |dma_hdr_t|dma_pkt_t|payload_1|dma_pkt_t|payload_2|........|dma_pkt_t|上行包头|dma_pkt_t|下行包头|
 *  ----------------------------------------------------------------------------------------------------
 * 
 *  UDP 数据格式
 *  -------------------------------------
 *  |dma_hdr_t|完整以太帧|dma_pkt_t|
 *  -------------------------------------
 *
 * @subsection step1 Step 1: 解压安装包
 *  tar -zxvf sma.tar.gz
 *
 *@subsection step2 Step 2: 运行start_sma.sh 脚本
 *  cd install/bin/
 *  ./start_sma.sh
 *
 *@subsection step3 Step 3: 运行 程序
 *  ../examples/pkt_recive --debug
 */
 
#ifndef __SMA_H__
#define __SMA_H__

#include <stdint.h>

#ifdef  __cplusplus
extern "C" {
#endif

typedef enum 
{
	CHANNEL_SESSION0 = 0,
	CHANNEL_SESSION1 = 1,
	CHANNEL_SESSION2,
	CHANNEL_SESSION3,
	CHANNEL_SESSION4,
	CHANNEL_SESSION5,
	CHANNEL_SESSION6,
	CHANNEL_SESSION7,
	CHANNEL_UDP,
	CHANNEL_MAX
} sma_queue_id_t;

typedef struct 
{
    uint64_t    gmac0_rx_packets;
	uint64_t    gmac0_rx_dropped_packets;
	uint64_t    gmac0_tx_packets;
	uint64_t    gmac0_tx_dropped_packets;
	
	uint64_t	gmac1_rx_packets; 	    //!< 网卡接收报文数
	uint64_t	gmac1_rx_bytes; 	        //!< 网卡接收字节数
    uint64_t    gmac1_free_packets;      //!< 网卡释放报文数
    uint64_t    gmac1_free_bytes;        //!< 网卡释放字节数
    uint64_t    gmac1_dropped_packets;   //!< 网卡丢弃异常报文数
    uint64_t    gmac1_dropped_bytes;     //!< 网卡丢弃异常报文字节数
	uint64_t    gmac1_dma_session;         //!< 已提交会话个数
	uint64_t    gmac1_dma_udp;             //!< DMA 队列接收UDP 报文数
	uint64_t    gmac1_dma_dropped_session;    //!< DMA 队列丢弃TCP 数据块数
	uint64_t    gmac1_dma_dropped_udp;        //!< DMA 队列丢弃UDP 报文数

	uint64_t    gmac1_tcp_packets;	        //!< 网卡接收tcp报文数
	uint64_t    gmac1_tcp_bytes;		        //!< 网卡接收tcp报文字节数
	uint64_t    gmac1_udp_packets;	        //!< 网卡接收udp报文数
	uint64_t    gmac1_udp_bytes;		        //!< 网卡接收udp报文字节数
	
    uint64_t    gmac1_session_dis_packets;    //!< 无需还原的数据包、畸形包、ack等
	uint64_t    gmac1_active_sessions;	    //!< 当前活跃会话数 

	uint64_t	gmac1_bps;               //!< 网卡当前bps
	uint64_t	gmac1_pps;               //!< 网卡当前pps
	uint64_t	gmac1_last_bytes;
	uint64_t	gmac1_last_packets;
	float		gmac1_count_time;

}sma_counter_t;

//! 自定义DMA 头部数据结构 (主机序)
typedef struct 
{
    uint32_t sip;             //!< 源IP 地址
    uint32_t dip;             //!< 目的IP 地址
    uint16_t sport;           //!< 源端口
    uint16_t dport;           //!< 目的端口
    uint16_t protocol;        //!< 协议号
    uint16_t stop_sec;        //!< 会话结束标志,当收到双向FIN报文后置为1,当收到单向RST报文后置1,
    uint16_t pkt_num;         //!< 数据包个数
    uint16_t total_paylen;    //!< 还原后的会话总长度
    uint32_t hash;            //!< 五元组hash值
    uint32_t teid;            //!< 保留
    uint32_t pppoe_sess_id;   //!< 保留
    uint16_t pppoe_protocol;  //!< 保留
    uint16_t pppoe_paylen;    //!< 保留
    uint16_t vlan_id;         //!< 保留
    uint16_t vlan_type;       //!< 保留
}dma_hdr_t ;

//! 单个数据包的长度和方向数据结构(主机序)
typedef struct 
{
    uint32_t sequence;        //!< SEQ 序列号
    uint32_t ack_seq;         //!< ACK 序列号
    int32_t data_offset;      //!< 拼包后本报文payload相对于第一个报文的偏移
    uint16_t payload_len;     //!< 本报文的有效payload长度
    uint16_t direction;       //!< 方向0 表示上行 1表示下行
    uint64_t smac;            //!< 本报文的实际smac，低6字节
    uint64_t dmac;            
}dma_pkt_t ;

typedef struct session_node {
  uint64_t prev_ptr;
  uint64_t next_ptr;
  uint64_t head_work;//
  uint64_t tail_work;/* */
  int32_t  block_index;
  int32_t  update;//会话最后更新时间
  dma_hdr_t dma_hdr;
} session_node_t ;

//计算struct中指定member的offset
#define genoffset(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

//DMA时，会话头dma_hdr_t信息从本块开始偏移DMA_OFFSET字节后存放
#define DMA_OFFSET  genoffset(session_node_t, dma_hdr)

/**
* @fn int sma_init(char *device_name)
* @brief 初始化设备文件.
* @param device_name 设备文件名.
* @return 成功返回0, 失败返回-1.
*/
int sma_init(char *device_name);
/**
* @fn void sma_exit()
* @brief 退出sma, 在程序退出时调用, 与sma_init成对调用.
*/
void sma_exit();

/**
* @fn int sma_queue_open(char *device_name, int queue_id)
* @brief 打开设备文件指定的接收通道,最大支持8通道.
* @param device_name 设备文件名.
* @param queue_id 通道号(范围0-7).
* @return 成功返回queue_id, 失败返回-1.
*/
int sma_queue_open(char *device_name, int queue_id);
/**
* @fn void sma_queue_close(int queue_id)
* @brief 关闭指定的接收通道，报文将不再传送此通道, 与sma_rx_queue_open成对调用.
* @param queue_id 通道号.
*/
void sma_queue_close(int queue_id);

/**
* @fn char *sma_pkt_recv(int queue_id)
* @brief 从指定的通道接收一个报文.
* @param queue_id 通道号.
* @return 成功返回数据包地址, 失败返回NULL.
*/
char *sma_pkt_recv(int queue_id);


/**
* @fn void sma_pkt_free(int queue_id)
* @brief 释放一个数据包 .
* @param queue_id 通道号必须与接收通道号相同.
*/
void sma_pkt_free(int queue_id);


/**
* @fn int sma_set_pde_mask(uint8_t mask)
* @brief 设置通道分发掩码,总共8 个HASH分发通道,
*  当规则对应的分发方式设置成按HASH值分发时,
*  这个值决定了数据包可能会被分发到哪些队列
*  尽量保证这个值和打开的通道一致,否则会出现丢包
*  假如打开了0 1 3 这三个队列,mask设置成00001011 = 11
*/
void sma_set_pde_mask(uint8_t mask);

/**
* @fn void sma_get_counters (ffwd_pkt_counter_t *result)
* @brief 获取SMA接口统计计数和流量统计信息
* @param result 接口流量统计信息查询结果
*/
void sma_get_counters (sma_counter_t *result);

/**
* @fn int sma_set_session_timeout(uint8_t value)
* @brief 设置流表超时时间,取值范围(1-5) 
* @return 成功返回0, 失败返回-1,当设置的值不在取值范围会设置失败
*/
int sma_set_session_timeout(uint8_t value);

#ifdef __cplusplus
}
#endif

#endif//PD_DMA_DATA_H_
