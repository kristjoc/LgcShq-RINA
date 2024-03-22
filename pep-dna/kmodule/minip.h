#ifndef _PEPDNA_MINIP_H
#define _PEPDNA_MINIP_H

#ifdef CONFIG_PEPDNA_MINIP
#include <linux/workqueue.h>

#define ETH_ALEN	6
#define ETH_P_MINIP	0x88FF
#define ETH_BROADCAST	{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}
#define SEQ_INIT	1U
#define WINDOW_SIZE	10U
#define MINIP_MTU	1448U
#define MAX_MINIP_RETRY 3U

/**
 * struct minip_hdr - MINIP header
 * @packet_type: MINIP packet type
 * @sdu_len:     SDU length in bytes
 * @conn_id:     hash(src IP, src port, dst IP, dst port)
 * @seq:         sequence number
 * @ack:         acknowledge number
 */
struct minip_hdr {
	u8  packet_type;
	u16 sdu_len;
	u32 conn_id;
	u32 seq;
	u32 ack;
} __attribute__ ((packed));

/**
 * enum minip_packet_type - MINIP packet type
 * @MINIP_CONN_REQUEST:  SYN
 * @MINIP_CONN_RESPONSE: SYN/ACK
 * @MINIP_CONN_DELETE:   FIN
 * @MINIP_CONN_FINISHED: FIN/ACK
 * @MINIP_CONN_DATA:     DATA
 * @MINIP_CONN_ACK:      ACK
 */
enum minip_packet_type {
	MINIP_CONN_REQUEST  = 0x01,
	MINIP_CONN_RESPONSE = 0x02,
	MINIP_CONN_DELETE   = 0x03,
	MINIP_CONN_FINISHED = 0x04,
	MINIP_CONN_DATA     = 0x05,
	MINIP_CONN_ACK      = 0x06,
};

struct rtxq_entry {
	/* unsigned long    time_stamp; */
	struct sk_buff *skb;
	u8 retries;
	struct list_head next;
};

struct rtxqueue {
	int len;
	struct list_head head;
};

struct rtxq {
	spinlock_t       lock;
	struct rtxqueue *queue;
};

int pepdna_minip_conn_response(u32, u8 *);
int pepdna_minip_skb_callback(struct sk_buff *);
void pepdna_minip_handshake(struct work_struct *);
void pepdna_con_i2m_work(struct work_struct *);
void pepdna_con_m2i_work(struct work_struct *);

struct rtxq *rtxq_create(void);
int rtxq_destroy(struct rtxq *);

#endif /* CONFIG_PEPDNA_MINIP */

#endif /* _PEPDNA_MINIP_H */
