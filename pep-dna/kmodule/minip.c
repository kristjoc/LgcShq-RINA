#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include "minip.h"
#include "core.h"
#include "connection.h"
#include "hash.h"
#include "tcp_utils.h"


#ifdef CONFIG_PEPDNA_LOCAL_SENDER
#include <net/ip.h>
#endif

extern char *ifname; /* Declared in 'core.c' */

static int pepdna_con_i2minip_fwd(struct pepdna_con *);
static int pepdna_minip_conn_snd_data(u32, u32, unsigned char *, size_t);

int pepdna_minip_conn_delete(uint32_t conn_id)
{
	/* FIXME */
	struct net_device *dev = dev_get_by_name(&init_net, ifname);
	static u16 proto = ETH_P_MINIP;
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
	hdr->sdu_len = 0u;
	hdr->conn_id = htonl(conn_id);

	skb->protocol = htons(proto);
	skb->no_fcs = 1;
	skb->pkt_type = PACKET_OUTGOING;

	return dev_queue_xmit(skb);
out:
	kfree(skb);
	return -1;
}

int pepdna_minip_conn_finished(uint32_t conn_id)
{
	/* FIXME */
	struct net_device *dev = dev_get_by_name(&init_net, ifname);
	static u16 proto = ETH_P_MINIP;
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
	hdr->packet_type = MINIP_CONN_FINISHED;
	hdr->sdu_len = 0u;
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
	hdr->sdu_len = 0u;
	hdr->conn_id = htonl(conn_id);
	hdr->seq = htonl(0u);
	hdr->ack = htonl(1u);

	skb->protocol = htons(proto);
	skb->no_fcs = 1;
	skb->pkt_type = PACKET_OUTGOING;

	return dev_queue_xmit(skb);
out:
	kfree(skb);
	return -1;
}

static int pepdna_minip_conn_ack(uint32_t conn_id, uint32_t ack)
{
	/* FIXME */
	struct net_device *dev = dev_get_by_name(&init_net, ifname);
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
	hdr->packet_type = MINIP_CONN_ACK;
	hdr->sdu_len = 0u;
	hdr->conn_id = htonl(conn_id);
	hdr->ack = htonl(ack);

	skb->protocol = htons(proto);
	skb->no_fcs = 1;
	skb->pkt_type = PACKET_OUTGOING;

	return dev_queue_xmit(skb);
out:
	kfree(skb);
	return -1;
}

static int pepdna_minip_skb_send(u32 cid, u32 seq,
				 unsigned char *buf, size_t len)
{
	/* FIXME */
	struct net_device *dev = dev_get_by_name(&init_net, ifname);
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
	skb_put_data(skb, buf, len);
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
	hdr->sdu_len = (u16)len;
	hdr->conn_id = htonl(cid);
	hdr->seq = htonl(seq);

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
static int pepdna_minip_conn_snd_data(u32 cid, u32 seq,
				      unsigned char *buf, size_t len)
{
	size_t left = len;
	size_t mtu = 1465;
	size_t copylen	= 0;
	size_t sent = 0;
	int rc	= 0;

	while (left) {
		copylen = min(left, mtu);

		if (pepdna_minip_skb_send(cid, seq, buf + sent, copylen)) {
			pep_err("Failed to forward skb to MINIP");
			rc = -EIO;
			goto out;
		}

		left -= copylen;
		sent += copylen;
		seq++; // TEST
	}
out:
		return sent ? sent : rc;
}

static int pepdna_minip_conn_request(__be32 saddr, __be16 source,
				     __be32 daddr, __be16 dest,
				     uint32_t conn_id)
{
	/* FIXME */
	struct net_device *dev = dev_get_by_name(&init_net, ifname);
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
	hdr->sdu_len = (u16)syn_len;
	hdr->conn_id = htonl(conn_id);
	hdr->seq = htonl(0u);
	hdr->ack = htonl(0u);

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
		pep_err("error sending a MINIP connection request");
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
		skb_pull(skb, sizeof(struct minip_hdr));
		syn = (struct syn_tuple *)skb->data;

		hash_id = pepdna_hash32_rjenkins1_2(syn->saddr, syn->source);
		pep_debug("Receiving a MINIP_CONN_REQUEST with cid %u", hash_id);
		con = pepdna_con_alloc(syn, NULL, hash_id, 0ull, 0);
		if (!con) {
			pep_err("error allocating a pepdna connection instance");
			return -1;
		}
		con->seq_to_send = con->ack_to_send = con->seq_expected = 1U;
		con->ack_expected = 2U;
		con->go = 1;
		break;
	case MINIP_CONN_RESPONSE:
		hash_id = ntohl(hdr->conn_id);
		pep_debug("Receiving MINIP_CONN_RESPONSE with cid %u", hash_id);

		con = pepdna_con_find(hash_id);
		if (!con) {
			pep_err("connection %u not found", hash_id);
			return -1;
		}

		atomic_set(&con->rflag, 1);
		con->seq_to_send = con->seq_expected = con->ack_to_send = 1U;
		con->ack_expected = 2U;
		con->go = 1;

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
		break;
	case MINIP_CONN_DATA:
		hash_id = ntohl(hdr->conn_id);
		pep_debug("Receiving MINIP data packet with seq %u from cid %u",
			  ntohl(hdr->seq), hash_id);

		con = pepdna_con_find(hash_id);
		if (!con) {
			pep_err("connection %u not found", hash_id);
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
	case MINIP_CONN_ACK:
		hash_id = ntohl(hdr->conn_id);
		pep_debug("Receiving MINIP ack packet with ack %u from cid %u",
			  ntohl(hdr->ack), hash_id);

		con = pepdna_con_find(hash_id);
		if (!con) {
			pep_err("connection %u not found", hash_id);
			return -1;
		}

		if (con->ack_expected == ntohl(hdr->ack)) {
			con->seq_to_send++;
			con->ack_expected++;
			con->go = 1;
			con->lsock->sk->sk_data_ready(con->lsock->sk);
		} else {
			con->go = 0;
		}
		break;
	case MINIP_CONN_DELETE:
		hash_id = ntohl(hdr->conn_id);
		pep_debug("Receiving MINIP_CONN_DELETE with cid %u", hash_id);

		con = pepdna_con_find(hash_id);
		if (!con) {
			pep_err("Connection %u not found", hash_id);
			return -1;
		}

		pepdna_minip_conn_finished(con->hash_conn_id);

		pepdna_con_close(con);
		break;
	case MINIP_CONN_FINISHED:
		hash_id = ntohl(hdr->conn_id);
		pep_debug("Receiving MINIP_CONN_FINISHED with cid %u", hash_id);

		con = pepdna_con_find(hash_id);
		if (!con) {
			pep_err("Connection %u not found", hash_id);
			return -1;
		}

		pepdna_con_close(con);
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
	unsigned char *buff = NULL;
	size_t mtu = 1465;
	int read = 0, sent = 0;

	struct msghdr msg = {
		.msg_flags = MSG_DONTWAIT,
	};
	struct kvec vec;

	/* allocate buffer memory */
	buff = kzalloc(mtu, GFP_KERNEL);
	if (!buff) {
		pep_err("error allocating buffer");
		return -ENOMEM;
	}
	vec.iov_base = buff;
	vec.iov_len  = mtu;

	read = kernel_recvmsg(lsock, &msg, &vec, 1, vec.iov_len, MSG_DONTWAIT);
	pep_debug("read %d bytes from TCP sock", read);
	if (likely(read > 0)) {
		sent = pepdna_minip_conn_snd_data(con->hash_conn_id,
						  con->seq_to_send,
						  buff, read);
		if (sent < 0) {
			pep_err("error forwarding to minip");
			kfree(buff);
			return -1;
		} else {
			con->go = 0;
		}
	} else {
		if (read == -EAGAIN || read == -EWOULDBLOCK) {
			pep_debug("kernel_recvmsg() returned %d", read);
		}
	}

	kfree(buff);
	return read;
}

/*
 * Forward data from MINIP flow to TCP socket
 * ------------------------------------------------------------------------- */
static int pepdna_con_minip2i_fwd(struct pepdna_con *con)
{
	struct socket *lsock = con->lsock;
	struct minip_hdr *hdr;
	unsigned char *buf;
	int read = 0, sent = 0;

	hdr = (struct minip_hdr *)skb_network_header(con->skb);
	read = hdr->sdu_len;

	skb_pull(con->skb, sizeof(struct minip_hdr));
	buf = (unsigned char *)con->skb->data;

	pep_debug("Received MINIP skb with seq %u", ntohl(hdr->seq));

	if (con->seq_expected == ntohl(hdr->seq)) {
		pep_debug("Yesss, skb with seq %u is in order", ntohl(hdr->seq));
		sent = pepdna_sock_write(lsock, buf, read);
		if (sent < 0) {
			pep_debug("error %d forwarding %d bytes from MINIP to TCP",
				  read, sent);
			read = -1;
		} else {
			con->ack_to_send++;
			con->seq_expected++;
		}
	} else {
		pep_debug("Nooo, skb with seq %u is in not in order", ntohl(hdr->seq));
		read = -EAGAIN;
	}

	/* Send an ACK with the expected sequence */
	pep_debug("Sending MINIP_CONN_ACK with ack = %u", con->ack_to_send);
	pepdna_minip_conn_ack(con->hash_conn_id, con->ack_to_send);

	return read;
}

/* TCP2MINIP
 * Forward traffic from INTERNET to MINIP
 * ------------------------------------------------------------------------- */
void pepdna_con_i2m_work(struct work_struct *work)
{
	struct pepdna_con *con = container_of(work, struct pepdna_con, l2r_work);
	int rc = 0;

	while (lconnected(con) && con->go) {
		pep_debug("Good to go and read from TCP");
		if ((rc = pepdna_con_i2minip_fwd(con)) <= 0) {
			if (rc == -EAGAIN) //FIXME Handle -EAGAIN flood
				break;

			/* Send a MINIP_CONN_DELETE to deallocate the flow */
			pep_debug("Sending MINIP_CONN_DELETE with cid %u", con->hash_conn_id);
			if (pepdna_minip_conn_delete(con->hash_conn_id) < 0) {
				pep_err("error sending MINIP_CONN_DELETE");
			}
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
	int rc = pepdna_con_minip2i_fwd(con);

	if (unlikely(rc <= 0)) {
		if (unlikely(rc == -EAGAIN)) {
			pep_debug("Received an unexpected MINIP packet %d", rc);
			/* cond_resched(); */
		} else {
			atomic_set(&con->rflag, 0);
			pepdna_con_close(con);
		}
	}
	pepdna_con_put(con);
}
