/**
 * @mainpage ��Ŀ���
 *
 * @section intro_sec Introduction
 *
 * SMA (Session Management Accelerator) ��һ�ֽ��лỰ������ٵĿ�
 * ��Ҫ���ڽ��ͷ������ڽ���Э�黹ԭʱ�Ự����ļ��㸺��.
 * SMA�ܹ���TCP ��ִ��˳�������ش���������ȹ���,
 * ����һ�������Ự�ύ����������,
 * �Ӷ�������߷���������������.
 * ���⣬SMA�ܹ��Ա��Ľ��ж�Ԫ��̶���Ĺ���,
 * ˥�������������ĵ�����.
 * ͬʱSMA�ܹ�������ı��Ľ��ж�˷���,
 * �Ӷ�ʹ�ö�������Ա�����������˲�������.
 * ���Ա���,����SMA���лỰ����������˫CPU������2�����ϵ�����.
 * SMAϵ�п�����PCI-E�ӿ��������������,
 * ͨ��DMA�����������ݿ�ֱ�ӵ��뵽�������ڴ�.
 *
 *
 * @section install_sec Installation
 *  TCP ���ݸ�ʽ
 *  ----------------------------------------------------------------------------------------------------
 *  |dma_hdr_t|dma_pkt_t|payload_1|dma_pkt_t|payload_2|........|dma_pkt_t|���а�ͷ|dma_pkt_t|���а�ͷ|
 *  ----------------------------------------------------------------------------------------------------
 * 
 *  UDP ���ݸ�ʽ
 *  -------------------------------------
 *  |dma_hdr_t|������̫֡|dma_pkt_t|
 *  -------------------------------------
 *
 * @subsection step1 Step 1: ��ѹ��װ��
 *  tar -zxvf sma.tar.gz
 *
 *@subsection step2 Step 2: ����start_sma.sh �ű�
 *  cd install/bin/
 *  ./start_sma.sh
 *
 *@subsection step3 Step 3: ���� ����
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
	
	uint64_t	gmac1_rx_packets; 	    //!< �������ձ�����
	uint64_t	gmac1_rx_bytes; 	        //!< ���������ֽ���
    uint64_t    gmac1_free_packets;      //!< �����ͷű�����
    uint64_t    gmac1_free_bytes;        //!< �����ͷ��ֽ���
    uint64_t    gmac1_dropped_packets;   //!< ���������쳣������
    uint64_t    gmac1_dropped_bytes;     //!< ���������쳣�����ֽ���
	uint64_t    gmac1_dma_session;         //!< ���ύ�Ự����
	uint64_t    gmac1_dma_udp;             //!< DMA ���н���UDP ������
	uint64_t    gmac1_dma_dropped_session;    //!< DMA ���ж���TCP ���ݿ���
	uint64_t    gmac1_dma_dropped_udp;        //!< DMA ���ж���UDP ������

	uint64_t    gmac1_tcp_packets;	        //!< ��������tcp������
	uint64_t    gmac1_tcp_bytes;		        //!< ��������tcp�����ֽ���
	uint64_t    gmac1_udp_packets;	        //!< ��������udp������
	uint64_t    gmac1_udp_bytes;		        //!< ��������udp�����ֽ���
	
    uint64_t    gmac1_session_dis_packets;    //!< ���軹ԭ�����ݰ������ΰ���ack��
	uint64_t    gmac1_active_sessions;	    //!< ��ǰ��Ծ�Ự�� 

	uint64_t	gmac1_bps;               //!< ������ǰbps
	uint64_t	gmac1_pps;               //!< ������ǰpps
	uint64_t	gmac1_last_bytes;
	uint64_t	gmac1_last_packets;
	float		gmac1_count_time;

}sma_counter_t;

//! �Զ���DMA ͷ�����ݽṹ (������)
typedef struct 
{
    uint32_t sip;             //!< ԴIP ��ַ
    uint32_t dip;             //!< Ŀ��IP ��ַ
    uint16_t sport;           //!< Դ�˿�
    uint16_t dport;           //!< Ŀ�Ķ˿�
    uint16_t protocol;        //!< Э���
    uint16_t stop_sec;        //!< �Ự������־,���յ�˫��FIN���ĺ���Ϊ1,���յ�����RST���ĺ���1,
    uint16_t pkt_num;         //!< ���ݰ�����
    uint16_t total_paylen;    //!< ��ԭ��ĻỰ�ܳ���
    uint32_t hash;            //!< ��Ԫ��hashֵ
    uint32_t teid;            //!< ����
    uint32_t pppoe_sess_id;   //!< ����
    uint16_t pppoe_protocol;  //!< ����
    uint16_t pppoe_paylen;    //!< ����
    uint16_t vlan_id;         //!< ����
    uint16_t vlan_type;       //!< ����
}dma_hdr_t ;

//! �������ݰ��ĳ��Ⱥͷ������ݽṹ(������)
typedef struct 
{
    uint32_t sequence;        //!< SEQ ���к�
    uint32_t ack_seq;         //!< ACK ���к�
    int32_t data_offset;      //!< ƴ���󱾱���payload����ڵ�һ�����ĵ�ƫ��
    uint16_t payload_len;     //!< �����ĵ���Чpayload����
    uint16_t direction;       //!< ����0 ��ʾ���� 1��ʾ����
    uint64_t smac;            //!< �����ĵ�ʵ��smac����6�ֽ�
    uint64_t dmac;            
}dma_pkt_t ;

typedef struct session_node {
  uint64_t prev_ptr;
  uint64_t next_ptr;
  uint64_t head_work;//
  uint64_t tail_work;/* */
  int32_t  block_index;
  int32_t  update;//�Ự������ʱ��
  dma_hdr_t dma_hdr;
} session_node_t ;

//����struct��ָ��member��offset
#define genoffset(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

//DMAʱ���Ựͷdma_hdr_t��Ϣ�ӱ��鿪ʼƫ��DMA_OFFSET�ֽں���
#define DMA_OFFSET  genoffset(session_node_t, dma_hdr)

/**
* @fn int sma_init(char *device_name)
* @brief ��ʼ���豸�ļ�.
* @param device_name �豸�ļ���.
* @return �ɹ�����0, ʧ�ܷ���-1.
*/
int sma_init(char *device_name);
/**
* @fn void sma_exit()
* @brief �˳�sma, �ڳ����˳�ʱ����, ��sma_init�ɶԵ���.
*/
void sma_exit();

/**
* @fn int sma_queue_open(char *device_name, int queue_id)
* @brief ���豸�ļ�ָ���Ľ���ͨ��,���֧��8ͨ��.
* @param device_name �豸�ļ���.
* @param queue_id ͨ����(��Χ0-7).
* @return �ɹ�����queue_id, ʧ�ܷ���-1.
*/
int sma_queue_open(char *device_name, int queue_id);
/**
* @fn void sma_queue_close(int queue_id)
* @brief �ر�ָ���Ľ���ͨ�������Ľ����ٴ��ʹ�ͨ��, ��sma_rx_queue_open�ɶԵ���.
* @param queue_id ͨ����.
*/
void sma_queue_close(int queue_id);

/**
* @fn char *sma_pkt_recv(int queue_id)
* @brief ��ָ����ͨ������һ������.
* @param queue_id ͨ����.
* @return �ɹ��������ݰ���ַ, ʧ�ܷ���NULL.
*/
char *sma_pkt_recv(int queue_id);


/**
* @fn void sma_pkt_free(int queue_id)
* @brief �ͷ�һ�����ݰ� .
* @param queue_id ͨ���ű��������ͨ������ͬ.
*/
void sma_pkt_free(int queue_id);


/**
* @fn int sma_set_pde_mask(uint8_t mask)
* @brief ����ͨ���ַ�����,�ܹ�8 ��HASH�ַ�ͨ��,
*  �������Ӧ�ķַ���ʽ���óɰ�HASHֵ�ַ�ʱ,
*  ���ֵ���������ݰ����ܻᱻ�ַ�����Щ����
*  ������֤���ֵ�ʹ򿪵�ͨ��һ��,�������ֶ���
*  �������0 1 3 ����������,mask���ó�00001011 = 11
*/
void sma_set_pde_mask(uint8_t mask);

/**
* @fn void sma_get_counters (ffwd_pkt_counter_t *result)
* @brief ��ȡSMA�ӿ�ͳ�Ƽ���������ͳ����Ϣ
* @param result �ӿ�����ͳ����Ϣ��ѯ���
*/
void sma_get_counters (sma_counter_t *result);

/**
* @fn int sma_set_session_timeout(uint8_t value)
* @brief ��������ʱʱ��,ȡֵ��Χ(1-5) 
* @return �ɹ�����0, ʧ�ܷ���-1,�����õ�ֵ����ȡֵ��Χ������ʧ��
*/
int sma_set_session_timeout(uint8_t value);

#ifdef __cplusplus
}
#endif

#endif//PD_DMA_DATA_H_
