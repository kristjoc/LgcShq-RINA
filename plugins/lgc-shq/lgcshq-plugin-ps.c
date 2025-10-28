/*
 * LGC-ShQ plugin policy sets (RMT, DTCP)
 *
 *    Kr1stj0n C1k0 <kristjoc@uio.no>
 *
 * This program is free software; you can redistribute it and/or modify
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

#define RINA_PREFIX "lgcshq-plugin"
#define RINA_LGCSHQ_PS_NAME "lgcshq-ps"

#include "logs.h"
#include "rds/rmem.h"
#include "rmt-ps.h"
#include "dtcp-ps.h"

extern struct ps_factory rmt_factory;
extern struct ps_factory dtcp_factory;

static int __init mod_init(void)
{
	int ret;

	strcpy(rmt_factory.name,  RINA_LGCSHQ_PS_NAME);
	strcpy(dtcp_factory.name, RINA_LGCSHQ_PS_NAME);

	ret = rmt_ps_publish(&rmt_factory);
	if (ret) {
		LOG_ERR("Failed to publish RMT policy set factory");
		return -1;
	}

	LOG_INFO("RMT LGCSHQ policy set loaded successfully");

	ret = dtcp_ps_publish(&dtcp_factory);
	if (ret) {
		LOG_ERR("Failed to publish DTCP policy set factory");
		return -1;
	}

	LOG_INFO("DTCP LGCSHQ policy set loaded successfully");

	return 0;
}

static void __exit mod_exit(void)
{
	int ret;

	ret = rmt_ps_unpublish(RINA_LGCSHQ_PS_NAME);
	if (ret) {
		LOG_ERR("Failed to unpublish LGCSHQ RMT policy set factory");
		return;
	}

	LOG_INFO("LGCSHQ RMT policy set unloaded successfully");

	ret = dtcp_ps_unpublish(RINA_LGCSHQ_PS_NAME);
	if (ret) {
		LOG_ERR("Failed to unpublish LGC-ShQ DTCP policy set factory");
		return;
	}

	LOG_INFO("LGC-ShQ DTCP policy set unloaded successfully");
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_AUTHOR("Kr1stj0n C1k0 <kristjoc@uio.no>");
MODULE_LICENSE ("GPL");
MODULE_DESCRIPTION("LGC-ShQ policy sets");
