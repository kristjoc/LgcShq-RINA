/*
 * LGCSHQ Policy Set for DTCP
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

#define RINA_PREFIX "lgcshq-dtcp-ps"

#include "rds/rmem.h"
#include "dtcp-ps.h"
#include "logs.h"
#include "policies.h"
#include "tcp_lgc.h"


#define LGCSHQ_ALPHA (5U<<16)/100U	// 0.05
#define ONE (1U<<16)				// 1.0
#define ALMOST_ONE (999U<<16)/1000U	// 0.99
#define ONE_MINUS_ALPHA (95U<<16)/100U	// 0.95
#define DEFAULT_ECN_BITS 1			// 1 bit
#define DEFAULT_LGC_MAX_RATE 100	// 100Mbps
#define DEFAULT_THRESH (8U<<16)/10U // 0.8
#define DEFAULT_MIN_RTT 10000		// 10ms = 10000us
#define DEFAULT_PACKET_SIZE 1484	// MSS + headers

struct lgcshq_dtcp_ps_data {
        uint_t	init_credit;
        uint_t	sshtresh;
        uint_t	samples_received;
        uint_t	ecn_received;
        uint_t	obs_window_size;
        uint_t	lgc_max_rate;
        uint_t  ecn_bits;
        u64	s_max_rate64;
        u64	s_cur_rate64;
        u32	max_rate32;
        u32	rate_thresh;
        u32	min_RTT;
        u32	fraction;
};

static void lgc_update_rate(struct dtcp_ps *ps)
{
        struct lgcshq_dtcp_ps_data *data = ps->priv;

        u64 rate64 = data->s_cur_rate64;
        u64 tmp_rate64 = rate64;
        u64 new_rate64 = 0ULL;
        s64 gr_rate_gradient = 1LL;
        u32 fraction = 0U, gr;

        /* scale marked/acked */
        u32 delivered_ce = data->ecn_received;
        u32 delivered = data->samples_received;
        delivered_ce <<= 16;
        delivered_ce /= max(delivered, 1U);

        /* update fraction */
        if (delivered_ce >= rate_thresh)
                fraction = (ONE_MINUS_ALPHA * data->fraction) + (LGCSHQ_ALPHA * delivered_ce);
        else
                fraction = (ONE_MINUS_ALPHA * data->fraction);

        data->fraction = (fraction >> 16);
        if (data->fraction >= ONE)
                data->fraction = ALMOST_ONE;

        /* At this point, we have a ca->fraction = [0,1) << LGC_SHIFT */

        /* Calculate gradient

         *            - log2(rate/max_rate)    -log2(1-fraction)
         * gradient = --------------------- - ------------------
         *                 log2(phi1)             log2(phi2)
         */

        do_div(tmp_rate64, data->max_rate32);

        u32 first_term = lgc_log_lut_lookup((u32)tmp_rate64);
        u32 second_term = lgc_log_lut_lookup((u32)(ONE - data->fraction));

        s32 gradient = first_term - second_term;

        /* s64 gradient = (s64)((s64)(BIG_ONE) - (s64)(rateo) - (s64)q); */

        gr = lgc_pow_lut_lookup(delivered_ce); /* 16bit scaled */

        /* s32 lgcc_r = (s32)gr; */
        /* if (gr < 12451 && ca->fraction) { */
        /* 	u32 exp = lgc_exp_lut_lookup(ca->fraction); */
        /* 	s64 expRate = (s64)ca->max_rate; */
        /* 	expRate *= exp; */
        /* 	s64 crate = (s64)ca->rate; */
        /* 	s64 delta; */

        /* 	if (expRate > ca->exp_rate && ca->rate < expRate - ca->exp_rate && */
        /* 	    ca->rate < ca->max_rateS) { */
        /* 		delta = expRate - crate; */
        /* 		delta /= ca->max_rate; */
        /* 		lgcc_r = (s32)delta; */
        /* 	} else if (ca->rate > expRate + ca->exp_rate) { */
        /* 		if (gradient < 0) { */
        /* 			delta = crate - expRate; */
        /* 			delta /= ca->max_rate; */
        /* 			lgcc_r = (s32)delta; */
        /* 		} */
        /* 	} else if ( expRate < ca->max_rateS) */
        /* 			lgcc_r = (s32)(984); */
        /* } */
        /* here: */
        gr_rate_gradient *= gr;
        gr_rate_gradient *= rate64;	/* rate: bpms << 16 */
        gr_rate_gradient >>= 16;	/* back to 16-bit scaled */
        gr_rate_gradient *= gradient;

        /* if (ca->flowId == 0) */
        /* 	printk(KERN_INFO "fraction %u",ca->fraction); */

        new_rate64 = (u64)((rate64 << 16) + gr_rate_gradient);
        new_rate64 >>= 16;

        /* new rate shouldn't increase more than twice */
        if (new_rate64 > (rate64 << 1))
                rate64 <<= 1;
        else if (new_rate64 == 0)
                rate64 = 65536U;
        else
                rate64 = new_rate64;

        LOG_DBG("new rate %llu", new_rate64);

        /* Check if the new rate exceeds the link capacity */
        if (rate64 > data->s_max_rate64)
                rate64 = data->s_max_rate64;

        /* lgc_rate can be read from lgc_get_info() without
         * synchro, so we ask compiler to not use rate
         * as a temporary variable in prior operations.
         */
        data->s_cur_rate64 = rate64;
}

/* Calculate cwnd based on current rate and min_RTT
 * cwnd = rate * minRT / mss
 */
static void lgc_set_cwnd(struct dtcp_ps *ps)
{
        struct dtcp * dtcp = ps->dm;
        struct lgcshq_dtcp_ps_data * data = ps->priv;
        u32 cwnd = 0U;
        u64 target64 = (u64)(data->s_cur_rate64 * data->min_RTT);

        target64 >>= 16; // 16 + 10 (USEC_PER_SEC)
        do_div(target64, DEFAULT_PACKET_SIZE * 1000);

        cwnd = max_t(u32, (u32)target64 + 1, 10U);

        target64 = (u64)(cwnd * DEFAULT_PACKET_SIZE * 1000);
        target64 <<= 16; // 16 + 10 (2^10 ~ 1000 (USEC_PER_MSEC))
        do_div(target64, data->min_RTT);

        data->s_cur_rate64 = target64;

        /* Update credit and right window edge */
        dtcp->sv->rcvr_credit = cwnd;
}


static int lgcshq_rcvr_flow_control(struct dtcp_ps * ps, const struct pci * pci)
{
        struct dtcp * dtcp = ps->dm;
        struct lgcshq_dtcp_ps_data * data = ps->priv;

        spin_lock_bh(&dtcp->parent->sv_lock);

        pdu_flags_t pci_flags = pci_flags_get(pci);

        if (data->ecn_bits >= 1) {
                data->samples_received++;
                if (pci_flags & PDU_FLAGS_EXPLICIT_CONGESTION) {
                        /* PDU is ECN-marked, decrease cwnd value */
                        data->ecn_received++;
                }
        }
        if (data->ecn_bits >= 2) {
                data->samples_received++;
                if (pci_flags & PDU_FLAGS_EXPLICIT_CONGESTION_2) {
                        /* PDU is ECN-marked, decrease cwnd value */
                        data->ecn_received++;
                }
        }
        if (data->ecn_bits >= 3) {
                data->samples_received++;
                if (pci_flags & PDU_FLAGS_EXPLICIT_CONGESTION_3) {
                        /* PDU is ECN-marked, decrease cwnd value */
                        data->ecn_received++;
                }
        }
        if (data->ecn_bits >= 4) {
                data->samples_received++;
                if (pci_flags & PDU_FLAGS_EXPLICIT_CONGESTION_4) {
                        /* PDU is ECN-marked, decrease cwnd value */
                        data->ecn_received++;
                }
        }
        if (data->ecn_bits >= 5) {
                data->samples_received++;
                if (pci_flags & PDU_FLAGS_EXPLICIT_CONGESTION_5) {
                        /* PDU is ECN-marked, decrease cwnd value */
                        data->ecn_received++;
                }
        }
        if (data->ecn_bits >= 6) {
                data->samples_received++;
                if (pci_flags & PDU_FLAGS_EXPLICIT_CONGESTION_6) {
                        /* PDU is ECN-marked, decrease cwnd value */
                        data->ecn_received++;
                }
        }
        if (data->ecn_bits >= 7) {
                data->samples_received++;
                if (pci_flags & PDU_FLAGS_EXPLICIT_CONGESTION_7) {
                        /* PDU is ECN-marked, decrease cwnd value */
                        data->ecn_received++;
                }
        }

        /* Update cwnd once every observation window */
        if (data->samples_received >= data->obs_window_size * data->ecn_bits) {
                LOG_DBG("Received %u bits, with %u marked bits in this window",
                        data->samples_received, data->ecn_received);
                lgc_update_rate(ps);
                lgc_set_cwnd(ps);

                data->samples_received = 0;
                data->ecn_received = 0;
                data->obs_window_size = dtcp->sv->rcvr_credit;
        }

        /* applying the TCP rule of not shrinking the window */
        if (dtcp->parent->sv->rcv_left_window_edge +
            dtcp->sv->rcvr_credit > dtcp->sv->rcvr_rt_wind_edge)
                dtcp->sv->rcvr_rt_wind_edge =
                        dtcp->parent->sv->rcv_left_window_edge +
                        dtcp->sv->rcvr_credit;


        LOG_DBG("New credit is %u, # of bits with ECN set %u",
                dtcp->sv->rcvr_credit, data->ecn_received);

        spin_unlock_bh(&dtcp->parent->sv_lock);

        return 0;
}

static int dtcp_ps_set_policy_set_param(struct ps_base * bps, const char * name,
                                        const char * value)
{
        struct dtcp_ps *ps = container_of(bps, struct dtcp_ps, base);
        struct lgcshq_dtcp_ps_data *data = ps->priv;
        int ival = 0;
        int ret = 0;

        (void) ps;

        if (!name) {
                LOG_ERR("Null parameter name");
                return -1;
        }

        if (!value) {
                LOG_ERR("Null parameter value");
                return -1;
        }

        if (strcmp(name, "lgc_max_rate") == 0) {
                ret = kstrtoint(value, 10, &ival);
                if (!ret) {
                        data->lgc_max_rate = ival;
                }
        }

        if (strcmp(name, "rate_thresh") == 0) {
                ret = kstrtoint(value, 10, &ival);
                if (!ret) {
                        data->rate_thresh = ival;
                }
        }

        if (strcmp(name, "min_RTT") == 0) {
                ret = kstrtoint(value, 10, &ival);
                if (!ret) {
                        data->min_RTT = ival * 1000;
                }
        }

        if (strcmp(name, "ecn_bits") == 0) {
                ret = kstrtouint(value, 10, &ival);
                if (!ret && (ival > 0) && (ival < 8)) {
                        data->ecn_bits = ival;
                }
        }

        return 0;
}


static int dtcp_ps_lgcshq_load_param(struct dtcp_ps *ps, const char *param_name)
{
        struct dtcp_config * dtcp_cfg;
        struct policy_parm * ps_param;

        dtcp_cfg = ps->dm->cfg;

        if (dtcp_cfg) {
                ps_param = policy_param_find(dtcp_cfg->dtcp_ps, param_name);
        } else {
                ps_param = NULL;
        }

        if (!ps_param) {
                LOG_WARN("LGCSHQ DTCP: No PS param %s specified", param_name);
        } else {
                dtcp_ps_set_policy_set_param(&ps->base,
                                             policy_param_name(ps_param),
                                             policy_param_value(ps_param));
        }

        return 0;
}

static struct ps_base * dtcp_ps_lgcshq_create(struct rina_component * component)
{
        struct dtcp * dtcp = dtcp_from_component(component);
        struct dtcp_ps * ps = rkzalloc(sizeof(*ps), GFP_KERNEL);
        struct lgcshq_dtcp_ps_data * data = rkzalloc(sizeof(*data), GFP_KERNEL);

        if (!ps || !data || !dtcp) {
                return NULL;
        }

        data->ecn_bits = DEFAULT_ECN_BITS;
        data->lgc_max_rate = DEFAULT_LGC_MAX_RATE;
        data->rate_thresh = DEFAULT_THRESH;
        data->min_RTT = DEFAULT_MIN_RTT;
        data->init_credit = 10;
        data->sshtresh = 0XFFFFFFFF;
        data->samples_received = 0;
        data->ecn_received = 0;
        data->obs_window_size = data->init_credit;
        dtcp->sv->rcvr_credit = data->init_credit;

        ps->base.set_policy_set_param   = dtcp_ps_set_policy_set_param;
        ps->dm                          = dtcp;
        ps->priv                        = data;
        ps->flow_init                   = NULL;
        ps->lost_control_pdu            = NULL;
        ps->rtt_estimator               = NULL;
        ps->retransmission_timer_expiry = NULL;
        ps->received_retransmission     = NULL;
        ps->sender_ack                  = NULL;
        ps->sending_ack                 = NULL;
        ps->receiving_ack_list          = NULL;
        ps->initial_rate                = NULL;
        ps->receiving_flow_control      = NULL;
        ps->update_credit               = NULL;
        ps->rcvr_ack                    = NULL;
        ps->rcvr_flow_control           = lgcshq_rcvr_flow_control;
        ps->rate_reduction              = NULL;
        ps->rcvr_control_ack            = NULL;
        ps->no_rate_slow_down           = NULL;
        ps->no_override_default_peak    = NULL;

        dtcp_ps_lgcshq_load_param(ps, "lgc_max_rate");
        dtcp_ps_lgcshq_load_param(ps, "rate_thresh");
        dtcp_ps_lgcshq_load_param(ps, "min_RTT");
        dtcp_ps_lgcshq_load_param(ps, "ecn_bits");

        data->max_rate32 = data->lgc_max_rate * 125U;
        data->s_max_rate64 = data->max_rate32;
        data->s_max_rate64 <<= 16;
        data->s_cur_rate64 = data->s_max_rate64;
        data->fraction = 0U;

        LOG_INFO("LGC-ShQ DTCP policy created, "
                 "lgc_max_rate = %u, rate_thresh = %u, min_RTT = %u ms, ecn_bits = %u",
                 data->lgc_max_rate, data->rate_thresh, data->min_RTT/USEC_PER_MSEC, data->ecn_bits);

        return &ps->base;
}

static void dtcp_ps_lgcshq_destroy(struct ps_base * bps)
{
        struct dtcp_ps *ps = container_of(bps, struct dtcp_ps, base);

        if (bps) {
                rkfree(ps);
        }
}

struct ps_factory dtcp_factory = {
        .owner   = THIS_MODULE,
        .create  = dtcp_ps_lgcshq_create,
        .destroy = dtcp_ps_lgcshq_destroy,
};
