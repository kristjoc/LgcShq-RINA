/*
 * KFA (Kernel Flow Allocator)
 *
 *    Francesco Salvestrini <f.salvestrini@nextworks.it>
 *    Miquel Tarzan         <miquel.tarzan@i2cat.net>
 *    Leonardo Bergesio     <leonardo.bergesio@i2cat.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef RINA_PEPKFA_H
#define RINA_PEPKFA_H

#include "common.h"
#include "du.h"
#include "ipcp-factories.h"
#include "iodev.h"

struct kfa {
	spinlock_t		 lock;
	struct pidm             *pidm;
	struct kfa_pmap         *flows;
	struct ipcp_instance    *ipcp;
	struct list_head	 list;
	struct workqueue_struct *flowdelq;

#ifdef CONFIG_DEBUG_FS
	struct dentry *flows_dbg_file;
#endif
};

enum flow_state {
	PORT_STATE_NULL	       = 1,
	PORT_STATE_PENDING,
	PORT_STATE_ALLOCATED,
	PORT_STATE_DEALLOCATED,
	PORT_STATE_DISABLED
};

struct ipcp_flow {
	port_id_t	       port_id;
	enum flow_state	       state;
	struct ipcp_instance * ipc_process;
	struct rfifo         * sdu_ready;
	struct iowaitqs	     * wqs;
	atomic_t	       readers;
	atomic_t	       writers;
	atomic_t	       posters;
	bool		       msg_boundaries;
	struct rina_device   * ip_dev;
};

struct flowdel_data {
	struct kfa *kfa;
	port_id_t  id;
	struct rina_device *ip_dev;
};

struct ipcp_instance_data {
	struct kfa *kfa;
};

#endif /* RINA_PEPKFA_H */
