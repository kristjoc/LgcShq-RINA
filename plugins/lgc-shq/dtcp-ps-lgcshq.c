/*
 * LGCSHQ Policy Set for DTCP
 *
 *    Kr1stj0n C1k0 <kristjoc@uio.no>
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

#include "tcp_lgc.h"


#define LGCSHQ_ALPHA 3277U
#define THRESH 58982U

// TODO: Use sysctl variables for this
static u32 lgc_max_rate = 1000U;

struct lgcshq_dtcp_ps_data {
	uint_t        init_credit;
	uint_t        sshtresh;
	uint_t        sent_total;
	uint_t        ecn_total;
	uint_t        lgcshq_alpha;
	uint_t	      obs_window_size;
	u64 rate;
	u64 max_rateS;
	u32 mrate;
	u32 minRTT;
	u32 fraction;
};

static void lgc_update_rate(struct dtcp_ps *ps)
{
	struct lgcshq_dtcp_ps_data *data = ps->priv;

	u64 rate = data->rate;
	u64 tmprate = data->rate;
	u64 new_rate = 0ULL;
	s64 gr_rate_gradient = 1LL;
	u32 fraction = 0U, gr;

	u32 delivered_ce = data->ecn_total;
	u32 delivered = data->sent_total;
	delivered_ce <<= 16;
	delivered_ce /= max(delivered, 1U);

	if (delivered_ce >= THRESH)
		fraction = (62259U * data->fraction) + (3277U * delivered_ce);
	else
		fraction = (62259U * data->fraction);

	data->fraction = (fraction >> 16);
	if (data->fraction >= 65536U)
		data->fraction = 65470U;

	/* At this point, we have a ca->fraction = [0,1) << LGC_SHIFT */

	/* Calculate gradient

	 *            - log2(rate/max_rate)    -log2(1-fraction)
	 * gradient = --------------------- - ------------------
         *                 log2(phi1)             log2(phi2)
	 */

	if (!data->mrate)
		data->mrate = 125000U; //HERE
	do_div(tmprate, data->mrate);

	u32 first_term = lgc_log_lut_lookup((u32)tmprate);
	u32 second_term = lgc_log_lut_lookup((u32)(65536U - data->fraction));

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
	gr_rate_gradient *= rate;	/* rate: bpms << 16 */
	gr_rate_gradient >>= 16;	/* back to 16-bit scaled */
	gr_rate_gradient *= gradient;

	/* if (ca->flowId == 0) */
	/* 	printk(KERN_INFO "fraction %u",ca->fraction); */

	new_rate = (u64)((rate << 16) + gr_rate_gradient);
	new_rate >>= 16;

	/* new rate shouldn't increase more than twice */
	if (new_rate > (rate << 1))
		rate <<= 1;
	else if (new_rate == 0)
		rate = 65536U;
	else
		rate = new_rate;

	/* Check if the new rate exceeds the link capacity */
	if (rate > data->max_rateS)
		rate = data->max_rateS;

	/* lgc_rate can be read from lgc_get_info() without
	 * synchro, so we ask compiler to not use rate
	 * as a temporary variable in prior operations.
	 */
	data->rate = rate;
}

/* Calculate cwnd based on current rate and minRTT
 * cwnd = rate * minRT / mss
 */
static void lgc_set_cwnd(struct dtcp_ps *ps)
{
	struct dtcp * dtcp = ps->dm;
	struct lgcshq_dtcp_ps_data * data = ps->priv;

	u32 cwnd = 0U;
	u32 minRTT = dtcp->sv->rtt;

	u64 target = (u64)(data->rate * minRTT);
	target >>= 16; // 16 + 10 (USEC_PER_SEC)
	do_div(target, 1500 * 1000);

	cwnd = max_t(u32, (u32)target + 3, 10U);

	target = (u64)(cwnd * 1500 * 1000);
	target <<= 16; // 16 + 10 (2^10 ~ 1000 (USEC_PER_MSEC))
	do_div(target, minRTT);

	data->rate = target;

	/* Update credit and right window edge */
	dtcp->sv->rcvr_credit = cwnd;

	/* applying the TCP rule of not shrinking the window */
	if (dtcp->parent->sv->rcv_left_window_edge + cwnd > dtcp->sv->rcvr_rt_wind_edge)
		dtcp->sv->rcvr_rt_wind_edge =
			dtcp->parent->sv->rcv_left_window_edge + cwnd;
}


static int lgcshq_rcvr_flow_control(struct dtcp_ps * ps, const struct pci * pci)
{
	struct dtcp * dtcp = ps->dm;
	struct lgcshq_dtcp_ps_data * data = ps->priv;

	spin_lock_bh(&dtcp->parent->sv_lock);

	data->sent_total++;
	if ((pci_flags_get(pci) & PDU_FLAGS_EXPLICIT_CONGESTION)) {
		/* PDU is ECN-marked, decrease cwnd value */
		data->ecn_total++;
	}

	/* Update cwnd once every observation window */
	if (data->sent_total >= data->obs_window_size) {
		LOG_DBG("Received %u PDUs, with %u marked PDUs in this window",
			data->sent_total, data->ecn_total);
		lgc_update_rate(ps);
		lgc_set_cwnd(ps);

		data->sent_total = 0;
		data->ecn_total = 0;
		data->obs_window_size = dtcp->sv->rcvr_credit;
	}

	LOG_DBG("New credit is %u, # of PDUs with ECN set %u", dtcp->sv->rcvr_credit,
		data->ecn_total);

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

	/* if (strcmp(name, "shift_g") == 0) { */
	/* 	ret = kstrtoint(value, 10, &ival); */
	/* 	if (!ret) { */
	/* 		data->shift_g = ival; */
	/* 	} */
	/* } */

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

	data->init_credit = 10;
	data->sshtresh = 0XFFFFFFFF;
	data->sent_total = 0;
	data->ecn_total = 0;
	data->obs_window_size = data->init_credit;
	data->mrate = lgc_max_rate * 125U;
	data->max_rateS = (u64)(data->mrate);
	data->rate = 983040000ULL;
	data->minRTT = 1U << 20; // reference minRTT ~1s
	data->fraction = 0U;
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

	LOG_INFO("LGCSHQ DTCP policy created");

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
