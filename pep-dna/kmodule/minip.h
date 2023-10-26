#ifndef _PEPDNA_MINIP_H
#define _PEPDNA_MINIP_H

#ifdef CONFIG_PEPDNA_MINIP
#include <linux/workqueue.h>

#define ETH_ALEN	6
#define ETH_P_MINIP	0x88FF
#define ETH_BROADCAST	{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}

/**
 * struct minip_hdr - MINIP header
 * @packet_type: batman-adv packet type, part of the general header
 * @dst: address of the destination node
 * @orig: address of the source node
 * @conn_id: hash(src IP, src port, dst IP, dst port)
 */
struct minip_hdr {
	__u8  packet_type;
	__u32 conn_id;
} __attribute__ ((packed));

/**
 * enum minip_packet_type - packet type for unicast4addr
 * @MINIP_FLOW_CREATE: M_CREATE
 * @MINIP_FLOW_ACCEPT: M_CREATE_R
 * @MINIP_FLOW_DATA: Data
 */
enum minip_packet_type {
	MINIP_CONN_REQUEST  = 0x01,
	MINIP_CONN_RESPONSE = 0x02,
	MINIP_CONN_DELETE   = 0x03,
	MINIP_CONN_FINISHED = 0x04,
	MINIP_CONN_DATA     = 0x05,
	MINIP_CONN_ACK      = 0x06,
};

int pepdna_minip_conn_response(uint32_t);
int pepdna_minip_skb_callback(struct sk_buff *);
void pepdna_minip_handshake(struct work_struct *);
void pepdna_con_i2m_work(struct work_struct *);
void pepdna_con_m2i_work(struct work_struct *);
#endif /* CONFIG_PEPDNA_MINIP */

#endif /* _PEPDNA_MINIP_H */
