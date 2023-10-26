#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include "minip.h"
#include "core.h"
#include "connection.h"
#include "hash.h"

#ifdef CONFIG_PEPDNA_LOCAL_SENDER
#include <net/ip.h>
#endif

extern char *ifname; /* Declared in 'core.c' */

static int pepdna_con_i2minip_fwd(struct pepdna_con *);
static int pepdna_minip_conn_snd_data(unsigned char *, size_t);

int pepdna_minip_conn_delete(uint32_t conn_id)
{
	/* FIXME */
	struct net_device *dev = dev_get_by_name(&init_net, ifname);
	static uint8_t broadcast[ETH_ALEN] = ETH_BROADCAST;
	static uint16_t proto = ETH_P_MINIP;
	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;
	int hdr_len = sizeof(struct minip_hdr);
	struct minip_hdr *hdr;

	/* skb */
	struct sk_buff* skb = alloc_skb(hdr_len + hlen + tlen, GFP_ATOMIC);
	if (!skb)
		return -1;

	skb_reserve(skb, hlen);
	skb_reset_network_header(skb);
	hdr = skb_put(skb, hdr_len);
	skb->dev = dev;

	/*
	 * Fill the device header for the MINIP frame
	 */
	if (dev_hard_header(skb, dev, proto, dev->broadcast, dev->dev_addr,
			    skb->len) < 0) {
		goto out;
	}

	/*
	 * Fill out the MINIP protocol part
	 */
	hdr->packet_type = MINIP_CONN_DELETE;
	hdr->conn_id = htonl(conn_id);

	skb->protocol = htons(proto);
	skb->no_fcs = 1;
	skb->pkt_type = PACKET_OUTGOING;

	return dev_queue_xmit(skb);
out:
	kfree(skb);
	return -1;
}

int pepdna_minip_conn_response(uint32_t conn_id)
{
	/* FIXME */
	struct net_device *dev = dev_get_by_name(&init_net, ifname);
	static uint8_t broadcast[ETH_ALEN] = ETH_BROADCAST;
	static uint16_t proto = ETH_P_MINIP;
	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;
	int hdr_len = sizeof(struct minip_hdr);
	struct minip_hdr *hdr;

	/* skb */
	struct sk_buff* skb = alloc_skb(hdr_len + hlen + tlen, GFP_ATOMIC);
	if (!skb)
		return -1;
	skb_reserve(skb, hlen);
	skb_reset_network_header(skb);
	hdr = skb_put(skb, hdr_len);
	skb->dev = dev;

	/*
	 * Fill the device header for the MINIP frame
	 */
	if (dev_hard_header(skb, dev, proto, dev->broadcast, dev->dev_addr,
			    skb->len) < 0) {
		goto out;
	}

	/*
	 * Fill out the MINIP protocol part
	 */
	hdr->packet_type = MINIP_CONN_RESPONSE;
	hdr->conn_id = htonl(conn_id);

	skb->protocol = htons(proto);
	skb->no_fcs = 1;
	skb->pkt_type = PACKET_OUTGOING;

	return dev_queue_xmit(skb);
out:
	kfree(skb);
	return -1;
}

static int pepdna_minip_skb_send(unsigned char *buffer, size_t len)
{
	/* FIXME */
	struct net_device *dev = dev_get_by_name(&init_net, ifname);
	static uint8_t broadcast[ETH_ALEN] = ETH_BROADCAST;
	static uint16_t proto = ETH_P_MINIP;
	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;
	int hdr_len = sizeof(struct minip_hdr);
	struct minip_hdr *hdr;

	/* skb */
	struct sk_buff* skb = alloc_skb(len + hdr_len + hlen + tlen, GFP_ATOMIC);
	if (!skb)
		return -1;

	skb_reserve(skb, hlen);
	skb_reset_network_header(skb);
	hdr = skb_put(skb, hdr_len);
	skb_put_data(skb, buffer, len);
	skb->dev = dev;

	/*
	 * Fill the device header for the MINIP frame
	 */
	if (dev_hard_header(skb, dev, proto, dev->broadcast, dev->dev_addr,
			    skb->len) < 0) {
		goto out;
	}

	/*
	 * Fill out the MINIP protocol part
	 */
	hdr->packet_type = MINIP_CONN_DATA;
	hdr->conn_id = htonl(conn_id);

	skb->protocol = htons(proto);
	skb->no_fcs = 1;
	skb->pkt_type = PACKET_OUTGOING;

	return dev_queue_xmit(skb);
out:
	kfree(skb);
	return -1;
}

/*
 * Send buffer over a MINIP flow
 * ------------------------------------------------------------------------- */
static int pepdna_minip_conn_snd_data(unsigned char *buf, size_t len)
{
	size_t left = len;
	size_t max_du_size = 1200;
	size_t copylen	= 0;
	size_t sent = 0;
	int rc	= 0;

	while (left) {
		copylen = min(left, max_du_size);

		if (pepdna_minip_skb_send( buf + sent, copylen)) {
			pep_err("Failed to forward skb to MINIP");
			rc = -EIO;
			goto out;
		}

		left -= copylen;
		sent += copylen;
	}
out:
		return sent ? sent : rc;
}

/*
 * Receiver buffer from a MINIP flow
 * ------------------------------------------------------------------------- */
static int pepdna_minip_conn_rcv_data(struct pepdna_con *con, unsigned char *buf)
{
	skb_pull(con->skb, sizeof(struct minip_hdr));
	buf = (unsigned char *)con->skb->data;
	
}

static int pepdna_minip_conn_request(__be32 saddr, __be16 source, __be32 daddr,
				     __be16 dest, uint32_t conn_id)
{
	/* FIXME */
	struct net_device *dev = dev_get_by_name(&init_net, ifname);
	static uint8_t broadcast[ETH_ALEN] = ETH_BROADCAST;
	static uint16_t proto = ETH_P_MINIP;
	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;
	int hdr_len = sizeof(struct minip_hdr);
	int syn_len = sizeof(struct syn_tuple);
	struct minip_hdr *hdr;
	struct syn_tuple *syn;

	/* skb */
	struct sk_buff* skb = alloc_skb(syn_len + hdr_len + hlen + tlen, GFP_ATOMIC);
	if (!skb)
		return -1;
	skb_reserve(skb, hlen);
	skb_reset_network_header(skb);
	hdr = skb_put(skb, hdr_len);
	syn = skb_put(skb, syn_len);
	skb->dev = dev;

	/*
	 * Fill the device header for the MINIP frame
	 */
	if (dev_hard_header(skb, dev, proto, dev->broadcast, dev->dev_addr,
			    skb->len) < 0) {
		goto out;
	}

	/*
	 * Fill out the MINIP protocol part
	 */
	hdr->packet_type = MINIP_CONN_REQUEST;
	hdr->conn_id = htonl(conn_id);

	syn->saddr = saddr;
	syn->source = source;
	syn->daddr = daddr;
	syn->dest = dest;

	skb->protocol = htons(proto);
	skb->no_fcs = 1;
	skb->pkt_type = PACKET_OUTGOING;

	return dev_queue_xmit(skb);
out:
	kfree(skb);
	return -1;
}

void pepdna_minip_handshake(struct work_struct *work)
{
	struct pepdna_con *con = container_of(work, struct pepdna_con, tcfa_work);
	int rc = 0;

	rc = pepdna_minip_conn_request(con->tuple.saddr, con->tuple.source,
				       con->tuple.daddr, con->tuple.dest,
				       con->hash_conn_id);
	if (rc < 0) {
		pep_err("Failed to send a MINIP connection request");
		pepdna_con_close(con);
	}
}

int pepdna_minip_skb_callback(struct sk_buff *skb)
{
	struct pepdna_con *con = NULL;
	struct syn_tuple *syn  = NULL;
	uint32_t hash_id;

	struct minip_hdr *hdr = (struct minip_hdr *)skb_network_header(skb);

	switch (hdr->packet_type) {
	case MINIP_CONN_REQUEST:
		/* syn = (struct syn_tuple *)kzalloc(sizeof(struct syn_tuple), */
		/* 				  GFP_ATOMIC); */
		/* if (IS_ERR(syn)) { */
		/* 	pep_err("kzalloc"); */
		/* 	return -1; */
		/* } */
		
		skb_pull(skb, sizeof(struct minip_hdr));
		syn = (struct syn_tuple *)skb->data;

		hash_id = pepdna_hash32_rjenkins1_2(syn->saddr, syn->source);
		pep_info("Receiving a MINIP_CONN_REQUEST with cid %u", hash_id);
		con = pepdna_con_alloc(syn, NULL, hash_id, 0ull, 0);
		if (!con) {
			pep_err("pepdna_con_alloc");
			return -1;
		}

		/* 	syn = (struct syn_tuple *)kzalloc(sizeof(struct syn_tuple), */
		/* 					  GFP_ATOMIC); */
		/* 	if (IS_ERR(syn)) { */
	/* 		pep_err("kzalloc"); */
	/* 		return; */
	/* 	} */
	/* 	syn->saddr  = cpu_to_be32(nlmsg->saddr); */
	/* 	syn->source = cpu_to_be16(nlmsg->source); */
	/* 	syn->daddr  = cpu_to_be32(nlmsg->daddr); */
	/* 	syn->dest   = cpu_to_be16(nlmsg->dest); */

	/* 	hash_id = pepdna_hash32_rjenkins1_2(syn->saddr, syn->source); */
	/* 	con = pepdna_con_alloc(syn, NULL, hash_id, 0ull, nlmsg->port_id); */
	/* 	if (!con) */
	/* 		pep_err("pepdna_con_alloc"); */

	/* 	kfree(syn); */
		break;
	case MINIP_CONN_RESPONSE:
		hash_id = ntohl(hdr->conn_id);
		pep_info("Receiving MINIP_CONN_RESPONSE with cid %u", hash_id);

		con = pepdna_con_find(hash_id);
		if (!con) {
			pep_err("Connection not found in Hash table");
			return -1;
		}

		atomic_set(&con->rflag, 1);

		/* At this point, MINIP flow is allocated. Reinject SYN in back
		 * in the stack so that the left TCP connection can be
		 * established. There is no need to set callbacks here for the
		 * left socket as pepdna_tcp_accept() will take care of it.
		 */
		pep_debug("Reinjecting initial SYN back to the stack");
#ifndef CONFIG_PEPDNA_LOCAL_SENDER
		netif_receive_skb(con->skb);
#else
		struct net *net = sock_net(con->server->listener->sk);
		ip_local_out(net, con->server->listener->sk, con->skb);
#endif
	case MINIP_CONN_DATA:
		hash_id = ntohl(hdr->conn_id);
		pep_info("Receiving MINIP_CONN_DATA with cid %u", hash_id);

		con = pepdna_con_find(hash_id);
		if (!con) {
			pep_err("Connection not found in Hash table");
			return -1;
		}

		con->skb = skb;

		/* read_lock_bh(&sk->sk_callback_lock); */
		pepdna_con_get(con);
		if (!queue_work(con->server->r2l_wq, &con->r2l_work)) {
			pepdna_con_put(con);
		}
		/* read_unlock_bh(&sk->sk_callback_lock); */
		break;
	case MINIP_CONN_DELETE:
		break;
	
	case MINIP_CONN_FINISHED:
		break;
	default:
		break;
	}

	return 0;
}

/*
 * Forward data from TCP socket to MINIP flow
 * ------------------------------------------------------------------------- */
static int pepdna_con_i2minip_fwd(struct pepdna_con *con)
{
	struct socket *lsock  = con->lsock;
	unsigned char *buffer = NULL;
	size_t max_buf_size   = 1200;
	int read = 0, sent 0;

	struct msghdr msg = {
		.msg_flags = MSG_DONTWAIT,
	};
	struct kvec vec;

	/* allocate buffer memory */
	buffer = kzalloc(max_buf_size, GFP_KERNEL);
	if (!buffer) {
		pep_err("Failed to alloc buffer");
		return -ENOMEM;
	}
	vec.iov_base = buffer;
	vec.iov_len  = max_buf_size;
	read = kernel_recvmsg(lsock, &msg, &vec, 1, vec.iov_len, MSG_DONTWAIT);
	if (likely(read > 0)) {
		sent = pepdna_minip_conn_snd_data(buffer, read);
		if (sent < 0) {
			pep_err("error forwarding to minip");
			kfree(buffer);
			return -1;
		}
	} else {
		if (read == -EAGAIN || read == -EWOULDBLOCK)
		pep_debug("kernel_recvmsg() returned %d", read);
	}

	kfree(buffer);
	return read;
}

/*
 * Forward data from MINIP flow to TCP socket
 * ------------------------------------------------------------------------- */
static int pepdna_con_minip2i_fwd(struct pepdna_con *con)
{
	struct socket *lsock = con->lsock;
	unsigned char *buffer = NULL;
	int read = 0, sent   = 0;

	read = pepdna_minip_conn_rcv_data(con, buffer);
	if (read <= 0) {
		pep_debug("failed to read MINIP skb");
		return read;
	}

	sent = pepdna_sock_write(lsock, buffer, read);
	if (sent < 0) {
		pep_debug("error forwarding from MINIP flow to socket");
		read = -1;
	}

	return read;
}

/* TCP2MINIP
 * Forward traffic from INTERNET to MINIP
 * ------------------------------------------------------------------------- */
void pepdna_con_i2m_work(struct work_struct *work)
{
	struct pepdna_con *con = container_of(work, struct pepdna_con, l2r_work);
	int rc = 0;

	while (lconnected(con)) {
		if ((rc = pepdna_con_i2minip_fwd(con)) <= 0) {
			if (rc == -EAGAIN) //FIXME Handle -EAGAIN flood
				break;

			/* Send a MINIP_CONN_DELETE to deallocate the flow */
			if (pepdna_conn_delete(con->hash_conn_id) < 0)
				pep_err("Couldn't initiate flow dealloc.");
			pepdna_con_close(con);
		}
	}
	pepdna_con_put(con);
}

/*
 * MINIP2TCP
 * Forward traffic from RINA to INTERNET
 * ------------------------------------------------------------------------- */
void pepdna_con_m2i_work(struct work_struct *work)
{
	struct pepdna_con *con = container_of(work, struct pepdna_con, r2l_work);
	int rc = 0;

	if ((rc = pepdna_con_minip2i_fwd(con)) <= 0) {
		if (rc == -EAGAIN) {
			pep_debug("Flow is not readable %d", rc);
			cond_resched();
		} else {
			atomic_set(&con->rflag, 0);
			pepdna_con_close(con);
		}
	}
	pepdna_con_put(con);
}
