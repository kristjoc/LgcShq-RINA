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
static int pepdna_con_minip2i_fwd(struct pepdna_con *, struct sk_buff *);
static int pepdna_minip_conn_snd_data(struct pepdna_con *, unsigned char *, size_t);
static int rtxqueue_push(struct rtxqueue *, struct sk_buff *);

static __u32 skb_seq_get(struct sk_buff *skb)
{
	struct minip_hdr *hdr = (struct minip_hdr *)skb_network_header(skb);

        return ntohl(hdr->seq);
}

static int rtxq_entry_destroy(struct rtxq_entry * entry)
{
	if (!entry)
                return -1;

        kfree_skb(entry->skb);
        list_del(&entry->next);
        kfree(entry);

        return 0;
}

static int rtxqueue_entries_ack(struct rtxqueue *q, u32 ack)
{
	struct rtxq_entry *cur, *n;
	u32 seq;

	list_for_each_entry_safe(cur, n, &q->head, next) {
		seq = skb_seq_get(cur->skb);
		if (seq < ack) {
			pep_debug("Seq num acked: %u. rtxq size %d", seq, q->len);
			rtxq_entry_destroy(cur);
			pep_debug("Deleted seq %u from rtxq", seq);
			q->len--;
		} else
			return 0;
	}

	return 0;
}

static int rtxq_entry_rtx(struct rtxq_entry *entry, u32 seq)
{
	if (entry->retries < MAX_MINIP_RETRY) {
		entry->retries++;
		return dev_queue_xmit(entry->skb);
	} else {
		pep_err("Maximum MINIP retransmissions reached for seq %u", seq);
		return -1;
	}
}

static int rtxqueue_entries_rtx(struct rtxqueue *q, u32 ack)
{
	struct rtxq_entry *cur;
	u32 seq;
	int rc;

	list_for_each_entry(cur, &q->head, next) {
		seq = skb_seq_get(cur->skb);
		if (seq >= ack) {
			if (rtxq_entry_rtx(cur, seq) < 0)
				return -1;
			pep_debug("Retransmitted seq %u from rtxq", seq);
		}
	}

	return 0;
}

int rtxq_rtx(struct rtxq * q,
             u32    seq_num)
{
        if (!q)
                return -1;

        /* rcu_read_lock(); */

        if (rtxqueue_entries_rtx(q->queue, seq_num) < 0)
		return -1;

        /* rtimer_restart(&q->parent->timers.rtx, tr); */

        /* rcu_read_unlock(); */

        return 0;
}

int rtxq_ack(struct rtxq * q,
             u32    seq_num)
{
        if (!q)
                return -1;

        spin_lock_bh(&q->lock);

        rtxqueue_entries_ack(q->queue, seq_num);

        /* rtimer_restart(&q->parent->timers.rtx, tr); */

        spin_unlock_bh(&q->lock);

        return 0;
}

int rtxq_push(struct rtxq * q, struct sk_buff *skb)
{
	int res;

        spin_lock_bh(&q->lock);

        /* is the first transmitted PDU */
        /* rtimer_start(&q->parent->timers.rtx, q->parent->sv->tr); */

        res = rtxqueue_push(q->queue, skb);

        spin_unlock_bh(&q->lock);

        return res;
}

static struct rtxqueue *rtxqueue_create(void)
{
        struct rtxqueue *tmp;

        tmp = kzalloc(sizeof(*tmp), GFP_ATOMIC);
        if (!tmp)
                return NULL;

        INIT_LIST_HEAD(&tmp->head);
	tmp->len = 0;

        return tmp;
}


static void rtxqueue_flush(struct rtxqueue * q)
{
        struct rtxq_entry * cur, * n;

        list_for_each_entry_safe(cur, n, &q->head, next) {
                rtxq_entry_destroy(cur);
		q->len --;
        }
}

static int rtxqueue_destroy(struct rtxqueue * q)
{
        if (!q)
                return -1;

        rtxqueue_flush(q);
        kfree(q);

        return 0;
}

struct rtxq * rtxq_create(void)
{
        struct rtxq * tmp;

        tmp = kzalloc(sizeof(*tmp), GFP_ATOMIC);
        if (!tmp)
                return NULL;

        /* rtimer_init(rtx_timer_func, &dtp->timers.rtx, dtp); */

        tmp->queue = rtxqueue_create();
        if (!tmp->queue) {
                pep_err("Failed to create retransmission queue");
                rtxq_destroy(tmp);
                return NULL;
        }
        spin_lock_init(&tmp->lock);

        return tmp;
}

int rtxq_destroy(struct rtxq * q)
{
	unsigned long flags;

        if (!q)
                return -1;

        spin_lock_irqsave(&q->lock, flags);
        if (q->queue && rtxqueue_destroy(q->queue))
                pep_err("Failed to destroy queue for RTXQ %pK", q->queue);

        spin_unlock_irqrestore(&q->lock, flags);

        kfree(q);

        return 0;
}

static struct rtxq_entry * rtxq_entry_create(struct sk_buff *skb)
{
        struct rtxq_entry *tmp;

        tmp = kzalloc(sizeof(*tmp), GFP_ATOMIC);
        if (!tmp)
                return NULL;

        tmp->skb = skb;
        tmp->retries = 0;

        INIT_LIST_HEAD(&tmp->next);

        return tmp;
}

/* push in seq_num order */
static int rtxqueue_push(struct rtxqueue *q, struct sk_buff *skb)
{
        struct rtxq_entry *tmp, *cur;
        u32 sn = skb_seq_get(skb);

        tmp = rtxq_entry_create(skb);
        if (!tmp)
                return -1;

        /* if (list_empty(&q->head)) { */
        list_add_tail(&tmp->next, &q->head);
	q->len++;
        pep_debug("Pushed PDU with seqnum: %u to rtxq queue", sn);
                /* return 0; */
        /* } */

        /* last = list_last_entry(&q->head, struct rtxq_entry, next); */
        /* if (!last) */
        /*         return -1; */

        /* psn = pci_sequence_number_get(&last->du->pci); */
        /* if (csn == psn) { */
        /*         LOG_ERR("Another PDU with the same seq_num %u, is in " */
        /*                 "the rtx queue!", csn); */
        /*         return -1; */
        /* } */
        /* if (csn > psn) { */
        /*         list_add_tail(&tmp->next, &q->head); */
	/* 	q->len++; */
	/* 	LOG_DBG("Last PDU with seqnum: %u push to rtxq at: %pk", */
        /*                 csn, q); */
        /*         return 0; */
        /* } */

        list_for_each_entry(cur, &q->head, next) {
        	sn = skb_seq_get(cur->skb);
                pep_debug("SKB with seq_num %u is in the rtx queue", sn);
	}
	return 0;
}

/*
 * Send a MINIP_CONN_DELETE packet, a.k.a FIN, to deallocate the MINIP flow
 * -------------------------------------------------------------------------- */
int pepdna_minip_conn_delete(uint32_t conn_id)
{
	/* FIXME */
        struct net_device *dev = dev_get_by_name(&init_net, ifname);
	struct minip_hdr *hdr;
	static u16 proto = ETH_P_MINIP;
	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;
	int hdr_len = sizeof(struct minip_hdr);

	/* skb */
	struct sk_buff* skb = alloc_skb(hdr_len + hlen + tlen, GFP_ATOMIC);
        if (!skb) {
		return -1;
        }

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

/*
 * Send a MINIP_CONN_FINISHED packet, a.k.a FIN/ACK
 * -------------------------------------------------------------------------- */
int pepdna_minip_conn_finished(uint32_t conn_id)
{
	/* FIXME */
	struct net_device *dev = dev_get_by_name(&init_net, ifname);
	struct minip_hdr *hdr;
	static u16 proto = ETH_P_MINIP;
	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;
	int hdr_len = sizeof(struct minip_hdr);

	/* skb */
	struct sk_buff* skb = alloc_skb(hdr_len + hlen + tlen, GFP_ATOMIC);
	if (!skb) {
		return -1;
	}

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
	hdr->seq = htonl(1u);
	hdr->ack = htonl(2u);

	skb->protocol = htons(proto);
	skb->no_fcs = 1;
	skb->pkt_type = PACKET_OUTGOING;

        pep_debug("Sending a MINIP_CONN_RESPONSE with cid %u", conn_id);

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

static int pepdna_minip_skb_send(struct pepdna_con *con,
				 unsigned char *buf, size_t len)
{
	/* FIXME */
	struct net_device *dev = dev_get_by_name(&init_net, ifname);
	struct minip_hdr *hdr;
	static uint16_t proto = ETH_P_MINIP;
	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;
	int hdr_len = sizeof(struct minip_hdr);

	/* skb */
	struct sk_buff* skb = alloc_skb(len + hdr_len + hlen + tlen, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

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
	hdr->conn_id = htonl(con->hash_conn_id);
	hdr->seq = htonl(con->seq_to_send);

	skb->protocol = htons(proto);
	skb->no_fcs = 1;
	skb->pkt_type = PACKET_OUTGOING;

        /* Copy cloned skb to rtx queue */
        struct sk_buff *cskb = skb_clone(skb, GFP_ATOMIC);
        rtxq_push(con->rtxq, cskb);

        pep_debug("Sent skb with sn %u", con->seq_to_send);

	return dev_queue_xmit(skb);
out:
	kfree(skb);

	return -1;
}

/*
 * Send buffer over a MINIP flow
 * ------------------------------------------------------------------------- */
static int pepdna_minip_conn_snd_data(struct pepdna_con *con, unsigned char *buf,
                                      size_t len)
{
	size_t left = len;
	size_t mtu = MINIP_MTU;
	size_t copylen = 0;
	size_t sent = 0;
	int rc	= 0;

	while (left) {
		copylen = min(left, mtu);

                pep_debug("Trying to forward %lu bytes to MINIP", len);
                rc = pepdna_minip_skb_send(con, buf + sent, copylen);
                pep_debug("minip_skb_send() returned %d", rc);

                if (rc < 0) {
			pep_err("error forwarding skb to MINIP");
			rc = -EIO;
			goto out;
                }

		left -= copylen;
                sent += copylen;

                /* Update window */
                con->seq_to_send++;
                if (con->window > 0)
			con->window--;
	}
out:
	return sent ? sent : rc;
}

static int pepdna_minip_conn_request(__be32 saddr, __be16 source,
				     __be32 daddr, __be16 dest,
				     __u32 conn_id)
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
		return -ENOMEM;

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
	hdr->seq = htonl(1u);
	hdr->ack = htonl(1u);

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

        // FIXME
	con->seq_to_send = 2U;
        con->ack_expected = 2U;
        con->ack_to_send = 2U;
	con->seq_expected = 2U;
	con->window = WINDOW_SIZE;
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
                con->ack_expected = 2U; //FIXME
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
		con->ack_expected++; //FIXME
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

                /* FIXME FIXME FIXME FIXME FIXME FIXME */
                int rc = pepdna_con_minip2i_fwd(con, skb);

		if (unlikely(rc <= 0)) {
			if (unlikely(rc == -EAGAIN)) {
				pep_debug("No MINIP data available right now");
			} else {
				atomic_set(&con->rflag, 0);

				/* Send a MINIP_CONN_DELETE to deallocate the flow */
				pep_debug("Sending MINIP_CONN_DELETE with cid %u", con->hash_conn_id);
				if (pepdna_minip_conn_delete(con->hash_conn_id) < 0) {
					pep_err("failed to send MINIP_CONN_DELETE");
				}

				pepdna_con_close(con);
			}
		}

		/* read_lock_bh(&sk->sk_callback_lock); */
		/* pepdna_con_get(con); */
		/* if (!queue_work(con->server->r2l_wq, &con->r2l_work)) { */
		/* 	pepdna_con_put(con); */
		/* } */
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
			pep_debug("ACK %u was expected", ntohl(hdr->ack));

			rtxq_ack(con->rtxq, con->ack_expected);

                        /* Update LWE */
                        con->ack_expected++;

			struct rtxq_entry *cur;
                        list_for_each_entry(cur, &con->rtxq->queue->head, next) {
        			u32 sn = skb_seq_get(cur->skb);
				pep_debug("SKB with seq_num %u is in the rtx queue", sn);
			}
			con->window++;
			con->lsock->sk->sk_data_ready(con->lsock->sk);
                } else {
			/* Retransmit everything until max_seq_sent */
                        u8 twin = con->window;
                        con->window = 0;
                        if (rtxq_rtx(con->rtxq, con->ack_expected - 1) < 0) {
				/* Send a MINIP_CONN_DELETE to deallocate the flow */
				pep_debug("sending MINIP_CONN_DELETE with cid %u", con->hash_conn_id);
				if (pepdna_minip_conn_delete(con->hash_conn_id) < 0) {
					pep_err("failed to send MINIP_CONN_DELETE");
				}
				pepdna_con_close(con);
                        }
                        con->window = twin;
			con->lsock->sk->sk_data_ready(con->lsock->sk);
		}
		break;
	case MINIP_CONN_DELETE:
		hash_id = ntohl(hdr->conn_id);
		pep_debug("receiving MINIP_CONN_DELETE with cid %u", hash_id);

		con = pepdna_con_find(hash_id);
		if (!con) {
			pep_err("connection %u not found", hash_id);
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
	size_t how_much = MINIP_MTU;
	int read = 0, sent = 0;

	if (!con->window) {
		return -EAGAIN;
        } else {
		how_much *= con->window;
        }

	struct msghdr msg = {
		.msg_flags = MSG_DONTWAIT,
	};
	struct kvec vec;

	/* allocate buffer memory */
	buff = kzalloc(how_much, GFP_KERNEL);
	if (!buff) {
		pep_err("failed to allocate buffer");
		return -ENOMEM;
	}
	vec.iov_base = buff;
	vec.iov_len  = how_much;

	read = kernel_recvmsg(lsock, &msg, &vec, 1, vec.iov_len, MSG_DONTWAIT);
	pep_debug("read %d/%u bytes from TCP sock", read, con->window);
	if (likely(read > 0)) {
		sent = pepdna_minip_conn_snd_data(con, buff, read);
		if (sent < 0) {
			pep_err("error forwarding to minip");
			kfree(buff);
			return -1;
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
static int pepdna_con_minip2i_fwd(struct pepdna_con *con, struct sk_buff *skb)
{
	struct socket *lsock = con->lsock;
	struct minip_hdr *hdr;
	unsigned char *buf;
	int read = 0, sent = 0;

	hdr = (struct minip_hdr *)skb_network_header(skb);
	read = hdr->sdu_len;

	skb_pull(skb, sizeof(struct minip_hdr));
	buf = (unsigned char *)skb->data;

	pep_debug("Received MINIP skb with seq %u", ntohl(hdr->seq));

	if (con->seq_expected == ntohl(hdr->seq)) { // FIXME
		pep_debug("Yesss, skb with seq %u is in order", ntohl(hdr->seq));
		sent = pepdna_sock_write(lsock, buf, read);
		if (sent < 0) {
			pep_debug("error %d forwarding %d bytes from MINIP to TCP",
				  read, sent);
			read = -1;
                } else {
			//FIXME
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

	while (lconnected(con)) {
		if ((rc = pepdna_con_i2minip_fwd(con)) <= 0) {
			if (rc == -EAGAIN) { // FIXME Handle -EAGAIN flood
				pep_debug("err %d No TCP data or MINIP window full", rc);
				break;
			}

			/* Send a MINIP_CONN_DELETE to deallocate the flow */
			pep_debug("Sending MINIP_CONN_DELETE with cid %u", con->hash_conn_id);
			if (pepdna_minip_conn_delete(con->hash_conn_id) < 0) {
				pep_err("failed to send MINIP_CONN_DELETE");
			}
			pepdna_con_close(con);
		}
        }
        /* this work is launched with pepdna_con_get() */
	pepdna_con_put(con);
}

/*
 * MINIP2TCP
 * Forward traffic from MINIP to INTERNET
 * ------------------------------------------------------------------------- */
void pepdna_con_m2i_work(struct work_struct *work)
{
	/* struct pepdna_con *con = container_of(work, struct pepdna_con, r2l_work); */
	/* int rc = pepdna_con_minip2i_fwd(con); */

	/* if (unlikely(rc <= 0)) { */
	/* 	if (unlikely(rc == -EAGAIN)) { */
	/* 		pep_debug("Received an unexpected MINIP packet %d", rc); */
	/* 		/\* cond_resched(); *\/ */
	/* 	} else { */
	/* 		atomic_set(&con->rflag, 0); */
	/* 		pepdna_con_close(con); */
	/* 	} */
	/* } */
	/* pepdna_con_put(con); */
}

                /* /\* FIXME FIXME FIXME FIXME FIXME FIXME *\/ */
                /* int rc = pepdna_con_minip2i_fwd(con, skb); */

		/* if (unlikely(rc <= 0)) { */
		/* 	if (unlikely(rc == -EAGAIN)) { */
		/* 		pep_debug("No MINIP data available right now"); */
		/* 	} else { */
		/* 		atomic_set(&con->rflag, 0); */

		/* 		/\* Send a MINIP_CONN_DELETE to deallocate the flow *\/ */
		/* 		pep_debug("Sending MINIP_CONN_DELETE with cid %u", con->hash_conn_id); */
		/* 		if (pepdna_minip_conn_delete(con->hash_conn_id) < 0) { */
		/* 			pep_err("failed to send MINIP_CONN_DELETE"); */
		/* 		} */

		/* 		pepdna_con_close(con); */
		/* 	} */
		/* } */

		/* /\* read_lock_bh(&sk->sk_callback_lock); *\/ */
		/* pepdna_con_get(con); */
		/* if (!queue_work(con->server->r2l_wq, &con->r2l_work)) { */
		/* 	pepdna_con_put(con); */
		/* } */
 		/* /\* read_unlock_bh(&sk->sk_callback_lock); *\/ */
