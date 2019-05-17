/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MULTIAP_AGENT_UTILS_H
#define MULTIAP_AGENT_UTILS_H
#include "multiap_agent.h"
#include <syslog.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <sys/signalfd.h>
#include <sys/stat.h>

extern plfrm_config pltfrm_config;

/* SYSLOG LOGGING PRIORITY LEVELS*/
/*
 * priorities/facilities are encoded into a single 32-bit quantity, where the
 * bottom 3 bits are the priority (0-7) and the top 28 bits are the facility
 * (0-big number).  Both the priorities and the facilities map roughly
 * one-to-one to strings in the syslogd(8) source code.  This mapping is
 * included in this file.
 *
 * priorities (these are ordered)

#define	LOG_EMERG	0	// system is unusable 
#define	LOG_ALERT	1	// action must be taken immediately
#define	LOG_CRIT		2	// critical conditions
#define	LOG_ERR		3	// error conditions
#define	LOG_WARNING	4	// warning conditions
#define	LOG_NOTICE	5	// normal but significant condition
#define	LOG_INFO		6	// informational
#define	LOG_DEBUG	7	// debug-level messages

*/


/*get_workqueue()
Function used to get the avaiable work queue handle from the pool
*/

wq_pool* get_workqueue_handle();

/*
init_workqueue_pool()
Function used for initialising the workqueue pool handle
*/
void init_workqueue_handles();

/*
free_workqueue_handle()
Function used for freeing the used work queue for later use
*/
void free_workqueue_handle(wq_args* data);

/*
register_multiap_logger
Funtion used for registering a specific logging function
*/

//int register_multiap_logger(register_logging_fn);

int platform_init(plfrm_config* config);
int dump_tlv_structure(uint8_t tlv_type, void * tlv_info);
void set_freq_unsupported_by_ctrl(uint8_t freq);
int is_ctrl_discovered();

map_radio_info_t *get_radio_node_from_name(char *radio_name);
typedef struct ap_metrics_data {
    uint8_t radio_count;
    map_radio_info_t **radio_list;
}ap_metrics_data_t;

#endif

#ifdef __cplusplus
}
#endif
