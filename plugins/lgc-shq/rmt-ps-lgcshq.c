/*
 * LGCSHQ RMT PS
 *
 *    Kr1stj0n C1k0 <kristjoc@uio.no>
 *    Michal Koutenský <koutenmi@fit.vutbr.cz>
 *
 * This program is free software; you can dummyistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/export.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>
#include <net/pkt_sched.h>

#define RINA_PREFIX "lgcshq-rmt-ps"

#include "logs.h"
#include "rds/rmem.h"
#include "rmt-ps.h"
#include "policies.h"

/* parameters */
#define DEFAULT_LIMIT 1000U		// 1000p
#define DEFAULT_INTERVAL PSCHED_NS2TICKS(10 * NSEC_PER_MSEC)	// 10ms
#define DEFAULT_MAXP (8U<<16)/10U	// 0.80
#define DEFAULT_ALPHA (95U<<16)/100U	// 0.95
#define DEFAULT_BANDWIDTH 12500U 	// 100Mbps in bytes/ms
#define DEFAULT_ECN_BITS 1		// 1-bit

struct lgcshq_rmt_ps_data {
        /* Max length of a queue. */
        unsigned int limit;
        /* Measurement interval in psched_time_t ~ u64 */
        psched_time_t interval;
        /* Maximum probability */
        unsigned int maxp;
        /* alpha */
        unsigned int alpha;
        /* bandwidth interface in bytes / sec */
        unsigned int bandwidth;
        /* number of ecn bits to use for marking */
        unsigned int ecn_bits;
        /* variables */
        u64 prob;
        u64 avg_qlen;
        u64 count;
        u32 one_minus_alpha;
        u64 maxp64;
        psched_time_t last;
};

struct lgcshq_rmt_queue {
        struct rfifo*  queue;
        port_id_t      port_id;
};

static void calc_probability(struct lgcshq_rmt_ps_data *data,
                             psched_tdiff_t delta,
                             unsigned int backlog)
{
        u64 avg_qlen = data->avg_qlen;
        u64 count = data->count;
        u64 maxb = (u64)data->bandwidth;
        u32 bmax = 0U;

        count += backlog;	/* current queue length in bytes */
        count <<= 16;

        avg_qlen = (u64)(avg_qlen * data->one_minus_alpha) +
                (u64)(count * data->alpha);

        avg_qlen >>= 16;		/* Now avg_qlen is 16-bit scaled */
        data->avg_qlen = avg_qlen;

        /*                avg_qlen
         * prob = maxp * ----------;	32-bit scaled probability stored in u64
         *                max_bytes
         */

        avg_qlen *= data->maxp;

        /* Calculate the max. number of incoming bytes during the interval */
        maxb *= PSCHED_TICKS2NS(delta);
        do_div(maxb, NSEC_PER_MSEC);
        bmax = (u32)maxb;

        /* Calculate the probability as u64 32-bit scaled */
        do_div(avg_qlen, maxb);

        /* The probability value should not exceed Max. probability */
        if (avg_qlen >= data->maxp64)
                avg_qlen = 0x00000000ffffffff;

        /* Reset count every interval */
        data->count = 0ULL;
        data->last = psched_get_time();

        /* Update prob statistic */
        data->prob = avg_qlen;
}

static bool should_mark(u64 prob)
{
        u64 rand = 0ULL;

        /* Generate a 4 byte = 32-bit random number and store it in u64 */
        get_random_bytes(&rand, 4);

        if (rand < prob)
                return true;

        return false;
}

static struct lgcshq_rmt_queue* lgcshq_queue_create(port_id_t port_id)
{
        struct lgcshq_rmt_queue* tmp;

        tmp = rkzalloc(sizeof(*tmp), GFP_ATOMIC);
        if (!tmp)
                return NULL;

        tmp->queue = rfifo_create_ni();
        if (!tmp->queue) {
                rkfree(tmp);
                return NULL;
        }
        tmp->port_id = port_id;

        return tmp;
}

static int lgcshq_rmt_queue_destroy(struct lgcshq_rmt_queue *q)
{
        if (!q) {
                LOG_ERR("No LGCSHQ RMT Key-queue to destroy...");
                return -1;
        }

        if (q->queue)
                rfifo_destroy(q->queue, (void (*)(void *)) du_destroy);

        rkfree(q);

        return 0;
}

static void * lgcshq_rmt_q_create_policy(struct rmt_ps *ps,
                                         struct rmt_n1_port *port)
{
        struct lgcshq_rmt_queue     *q;
        struct lgcshq_rmt_ps_data   *data;

        if (!ps || !port || !ps->priv) {
                LOG_ERR("LGCSHQ RMT: Wrong input parameters");
                return NULL;
        }

        data = ps->priv;

        q = lgcshq_queue_create(port->port_id);
        if (!q) {
                LOG_ERR("LGCSHQ RMT: Could not create queue for n1_port %u",
                        port->port_id);
                return NULL;
        }

        LOG_DBG("LGCSHQ RMT: Structures for scheduling policies created...");

        return q;
}

static int lgcshq_rmt_q_destroy_policy(struct rmt_ps *ps,
                                       struct rmt_n1_port *port)
{
        struct lgcshq_rmt_queue *q;

        if (!ps || !port) {
                LOG_ERR("LGCSHQ RMT: "
                        "Wrong input parameters for lgcshq_rmt_q_destroy_policy");
                return -1;
        }

        q = port->rmt_ps_queues;
        if (q)
                return lgcshq_rmt_queue_destroy(q);

        return -1;
}

static int lgcshq_rmt_enqueue_policy(struct rmt_ps *ps,
                                     struct rmt_n1_port *port,
                                     struct du * du,
                                     bool must_enqueue)
{
        struct lgcshq_rmt_ps_data *data = ps->priv;
        struct lgcshq_rmt_queue   *q;
        unsigned int qlen;
        pdu_flags_t pci_flags;
        psched_tdiff_t delta;

        if (!ps || !port || !du || !data) {
                LOG_ERR("LGCSHQ RMT: Wrong input parameters"
                        " for lgcshq_rmt_enqueue_policy");
                return RMT_PS_ENQ_ERR;
        }

        q = port->rmt_ps_queues;
        if (!q) {
                LOG_ERR("LGCSHQ RMT: Could not find queue for n1_port %u",
                        port->port_id);
                du_destroy(du);
                return RMT_PS_ENQ_ERR;
        }

        qlen = rfifo_length(q->queue);
        if (qlen >= data->limit) {
                if (pci_type(&du->pci) != PDU_TYPE_MGMT) {
                        du_destroy(du);
                        LOG_INFO("LGCSHQ RMT: PDU dropped, limit (%u) reached...",
                                 data->limit);
                        return RMT_PS_ENQ_DROP;
                }
        }

        data->count += du_len(du);
        delta = psched_get_time() - data->last;

        if (data->interval < delta)
                calc_probability(data, delta, qlen);

        /* Start marking */
        pci_flags = pci_flags_get(&du->pci);

        if (should_mark(data->prob)) {
                pci_flags_set(&du->pci,
                              pci_flags |= PDU_FLAGS_EXPLICIT_CONGESTION);
                LOG_DBG("Queue length is %u, marked PDU with ECN", qlen);
        }
        if (data->ecn_bits >= 2 && should_mark(data->prob)) {
                pci_flags_set(&du->pci,
                              pci_flags |= PDU_FLAGS_EXPLICIT_CONGESTION_2);
                LOG_DBG("Queue length is %u, marked PDU with ECN2", qlen);
        }
        if (data->ecn_bits >= 3 && should_mark(data->prob)) {
                pci_flags_set(&du->pci,
                              pci_flags |= PDU_FLAGS_EXPLICIT_CONGESTION_3);
                LOG_DBG("Queue length is %u, marked PDU with ECN3", qlen);
        }
        if (data->ecn_bits >= 4 && should_mark(data->prob)) {
                pci_flags_set(&du->pci,
                              pci_flags |= PDU_FLAGS_EXPLICIT_CONGESTION_4);
                LOG_DBG("Queue length is %u, marked PDU with ECN4", qlen);
        }
        if (data->ecn_bits >= 5 && should_mark(data->prob)) {
                pci_flags_set(&du->pci,
                              pci_flags |= PDU_FLAGS_EXPLICIT_CONGESTION_5);
                LOG_DBG("Queue length is %u, marked PDU with ECN5", qlen);
        }
        if (data->ecn_bits >= 6 && should_mark(data->prob)) {
                pci_flags_set(&du->pci,
                              pci_flags |= PDU_FLAGS_EXPLICIT_CONGESTION_6);
                LOG_DBG("Queue length is %u, marked PDU with ECN6", qlen);
        }
        if (data->ecn_bits >= 7 && should_mark(data->prob)) {
                pci_flags_set(&du->pci,
                              pci_flags |= PDU_FLAGS_EXPLICIT_CONGESTION_7);
                LOG_DBG("Queue length is %u, marked PDU with ECN7", qlen);
        }

        if (!must_enqueue && rfifo_is_empty(q->queue))
                return RMT_PS_ENQ_SEND;

        rfifo_push_ni(q->queue, du);

        return RMT_PS_ENQ_SCHED;
}

static struct du * lgcshq_rmt_dequeue_policy(struct rmt_ps *ps,
                                             struct rmt_n1_port *port)
{
        struct lgcshq_rmt_queue    *q;
        struct lgcshq_rmt_ps_data  *data = ps->priv;
        struct du *ret_pdu;

        if (!ps || !port || !data) {
                LOG_ERR("Wrong input parameters for red_rmt_dequeue_policy");
                return NULL;
        }

        q = port->rmt_ps_queues;
        if (!q) {
                LOG_ERR("Could not find queue for n1_port %u", port->port_id);
                return NULL;
        }

        ret_pdu = rfifo_pop(q->queue);
        LOG_DBG("LGCSHQ RMT: PDU dequeued...");

        if (!ret_pdu)
                LOG_ERR("Could not dequeue scheduled pdu");

        return ret_pdu;
}

static int lgcshq_rmt_ps_set_policy_set_param(struct ps_base *bps,
                                              const char *name,
                                              const char *value)
{
        struct rmt_ps *ps = container_of(bps, struct rmt_ps, base);
        struct lgcshq_rmt_ps_data *data = ps->priv;
        unsigned long long ullval;
        unsigned int uival;
        int ret;

        (void) ps;

        if (!name) {
                LOG_ERR("Null parameter name");
                return -1;
        }

        if (!value) {
                LOG_ERR("Null parameter value");
                return -1;
        }
        if (strcmp(name, "limit") == 0) {
                ret = kstrtouint(value, 10, &uival);
                if (!ret) {
                        data->limit = uival;
                        LOG_INFO("Queue max occupancy is %u", uival);
                }
        }
        if (strcmp(name, "interval") == 0) {
                ret = kstrtoull(value, 10, &ullval);
                if (!ret) {
                        data->interval = PSCHED_NS2TICKS(ullval * NSEC_PER_MSEC);
                        LOG_INFO("Interval is %llu ms", ullval);
                }
        }
        if (strcmp(name, "maxp") == 0) {
                ret = kstrtouint(value, 10, &uival);
                if (!ret) {
                        data->maxp = uival;
                        LOG_INFO("Scaled maximum probability is %u", uival);
                }
        }
        if (strcmp(name, "alpha") == 0) {
                ret = kstrtouint(value, 10, &uival);
                if (!ret) {
                        data->alpha = uival;
                        LOG_INFO("Scaled alpha value is %u", uival);
                }
        }
        if (strcmp(name, "bandwidth") == 0) {
                ret = kstrtouint(value, 10, &uival);
                if (!ret) {
                        data->bandwidth = uival * 125U; // bytes / ms
                        LOG_INFO("Maximum link capacity is %u Mbps", uival);
                }
        }
        if (strcmp(name, "ecn_bits") == 0) {
                ret = kstrtouint(value, 10, &uival);
                if (!ret && (uival > 0) && (uival < 8)) {
                        data->ecn_bits = uival;
                        LOG_INFO("Using %u ECN bits", uival);
                }
        };

        return 0;
}

static int rmt_ps_load_param(struct rmt_ps *ps, const char *param_name)
{
        struct rmt_config * rmt_cfg;
        struct policy_parm * ps_param;

        rmt_cfg = rmt_config_get(ps->dm);

        if (rmt_cfg) {
                ps_param = policy_param_find(rmt_cfg->policy_set, param_name);
        } else {
                ps_param = NULL;
        }

        if (!ps_param) {
                LOG_WARN("LGCSHQ RMT: No PS param %s specified", param_name);
        } else {
                lgcshq_rmt_ps_set_policy_set_param(&ps->base,
                                                   policy_param_name(ps_param),
                                                   policy_param_value(ps_param));
        }

        return 0;
}

static struct ps_base * rmt_ps_lgcshq_create(struct rina_component *component)
{
        struct rmt *rmt = rmt_from_component(component);
        struct rmt_ps *ps = rkzalloc(sizeof(*ps), GFP_KERNEL);
        struct lgcshq_rmt_ps_data *data;

        if (!ps)
                return NULL;

        data = rkzalloc(sizeof(*data), GFP_KERNEL);
        if (!data) {
                kfree(ps);
                return NULL;
        }
        ps->base.set_policy_set_param = lgcshq_rmt_ps_set_policy_set_param;
        ps->dm = rmt;
        ps->priv = data;

        // set default parameters
        data->limit = DEFAULT_LIMIT;
        data->interval = DEFAULT_INTERVAL;
        data->maxp = DEFAULT_MAXP;
        data->alpha = DEFAULT_ALPHA;
        data->bandwidth = DEFAULT_BANDWIDTH;
        data->ecn_bits = DEFAULT_ECN_BITS;

        //load configuration if available
        rmt_ps_load_param(ps, "limit");
        rmt_ps_load_param(ps, "interval");
        rmt_ps_load_param(ps, "maxp");
        rmt_ps_load_param(ps, "alpha");
        rmt_ps_load_param(ps, "bandwidth");
        rmt_ps_load_param(ps, "ecn_bits");

        // set default variables
        data->avg_qlen = 0ULL;
        data->count = 0ULL;
        data->one_minus_alpha = 65536U - data->alpha;
        data->maxp64 = ((u64)data->maxp) << 16;
        data->last = psched_get_time();

        // set callbacks
        ps->rmt_q_create_policy = lgcshq_rmt_q_create_policy;
        ps->rmt_q_destroy_policy = lgcshq_rmt_q_destroy_policy;
        ps->rmt_enqueue_policy = lgcshq_rmt_enqueue_policy;
        ps->rmt_dequeue_policy = lgcshq_rmt_dequeue_policy;

        LOG_INFO("LGCSHQ RMT: PS loaded, "
                 "limit = %u, "
                 "interval = %u, "
                 "maxp = %u, "
                 "alpha = %u, "
                 "bw = %uMbps, "
                 "ecn_bits = %u",
                 data->limit,
                 (u32)(PSCHED_TICKS2NS(data->interval))/NSEC_PER_MSEC,
                 data->maxp, data->alpha,
                 data->bandwidth/125,
                 data->ecn_bits);

        return &ps->base;
}

static void rmt_ps_lgcshq_destroy(struct ps_base *bps)
{
        struct rmt_ps *ps = container_of(bps, struct rmt_ps, base);

        if (bps)
                rkfree(ps);
}

struct ps_factory rmt_factory = {
        .owner   = THIS_MODULE,
        .create  = rmt_ps_lgcshq_create,
        .destroy = rmt_ps_lgcshq_destroy,
};
