#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "sma.h"
#include <sys/time.h>
#include <string.h>
#include <signal.h>
#define DEV_NAME  "/dev/sma0"

pthread_t thread_id[9];

int debug = 0;
static inline void dump_mem_info(uint8_t* msg, uint32_t len)
{
	uint32_t i;
	printf("addr = %p ,len = %d\n", msg,len);
	for (i=0; i<len; i++)
	{
		if ((i%4) == 0 && i !=0)
			printf(" ");
		if ((i%32) == 0 && i != 0)
			printf("  %d\n", i/32-1);
		printf("%02x", msg[i]);

	}
	printf("\n");
}


int exit_flag = 1;

void cleanExit(int sig)
{
    exit_flag = 0;
    printf("exit----------------------------------------\n");
}


void *sma_thread(void *arg)
{
    int i;
	int queue_id;
	char * pkt; 
	dma_hdr_t * dma_hdr;
	dma_pkt_t * dma_pkt;
	printf ("thread : I'm thread CHANNEL%d\n",*(int *)arg);

	queue_id = sma_queue_open(DEV_NAME, *(int *)arg);
	if (queue_id<0) {
		printf("open failed id = %d\n", queue_id);
		return NULL;
	}

	while(exit_flag) 
	{
        
		pkt = sma_pkt_recv(queue_id);
        if(pkt == NULL)
        {
            usleep(0);
            continue;
        }
        
        if(debug)
        {
            dma_hdr = (dma_hdr_t *)pkt;
            pkt += sizeof(dma_hdr_t); 

    
            int total_paylen = dma_hdr->total_paylen;
            int pkt_num = dma_hdr->pkt_num;
            uint32_t hash = dma_hdr->hash;
            uint32_t teid = dma_hdr->teid;
            
            printf("protocol = %d total_paylen = %u pkt_num = %d hash = %08x teid = %08x \r\n",dma_hdr->protocol,dma_hdr->total_paylen,dma_hdr->pkt_num,hash,teid);

            dump_mem_info(pkt, total_paylen);
            pkt += total_paylen;
            
            for(i = 0; i < pkt_num; i++)
            {
                dma_pkt = (dma_pkt_t *)pkt;
                pkt += sizeof(dma_pkt_t);

                printf("pkt_number[%d] seq[%08x] ack_seq[%08x] data_offset[%d] payload_len[%d] direction[%d] smac[%llx] dmac[%llx] \r\n",
                    i,dma_pkt->sequence,dma_pkt->ack_seq,dma_pkt->data_offset,dma_pkt->payload_len,
                    dma_pkt->direction,dma_pkt->smac,dma_pkt->dmac);
            }
        }
        sma_pkt_free(queue_id);
    }

    sma_queue_close(queue_id);
	
}


int main(int argc, char **argv)
{
    int queue_id;
    if(argc > 1)
    {
        if(strcmp(argv[1],"--debug") == 0)
        {
            debug = 1;
        }
    }
    
	if (sma_init(DEV_NAME) < 0) 
	{
		printf("init sma failed!\n");
		return -1;
	}

    //设置收包队列掩码,0xFF = 1111 1111(二进制)
    //表示数据会负载均衡到哪几个通道
    sma_set_pde_mask(0xff);

  /*  
    signal(SIGSEGV, cleanExit);
  	signal(SIGFPE,  cleanExit);
  	signal(SIGTERM, cleanExit);
  	signal(SIGKILL, cleanExit);
  	signal(SIGINT,  cleanExit);
  	signal(SIGABRT, cleanExit);

*/

    int queue_id_arr[9];
    //最大支持8个接收队列
    for(queue_id = 0; queue_id< 9; queue_id++)
    {
        queue_id_arr[queue_id] = queue_id;
        pthread_create(&thread_id[queue_id], NULL, sma_thread, (void*)&queue_id_arr[queue_id]);
    }
  
    for(queue_id = 0; queue_id< 9; queue_id++)
    {
        pthread_join(thread_id[queue_id],NULL);
    }
    
    sma_exit();

	return 0;
}


