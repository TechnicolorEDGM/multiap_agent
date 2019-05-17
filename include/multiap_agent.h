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

#ifndef MULTIAP_AGENT_H
#define MULTIAP_AGENT_H

#include <stdio.h>
#include <uv.h>
#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include "platform.h"
#include "platform_map.h"
#include "map_data_model.h"
#include "1905_lib.h"
#include "map_tlvs.h"


//###############################################################
//Timer deadline defines for the event loops in the multiap Agent
//###############################################################
//1905 message reading interval 
#define TIMER_1905_READ     500
//Timer interval used for monitoring the 802.11 event changes
#define TIMER_80211_EVENTS  2000
//Timer interval for gathering the data periodically to be buffered
#define TIMER_DATA_GATHER   3000

#define MAX_NUM_OF_WQ       7


#define SOCK_NAME_LEN_MAX 20 

#define ARRAY_LEN(data_struct, struct_definition) (sizeof(data_struct)/sizeof(struct_definition))

#define MAP_CHANNEL_SEL_ACCEPT 0x00
#define MAP_CHANNEL_SEL_DECLINE 0x01
#define MAP_CHANNEL_SEL_VALIDATION_DECLINE 0x02

#define SHIFT_4BIT 0x04
#define REASON_MASK 0x0F

#define PREF_REASON_UNSPECFIED  0
#define PREF_SCORE_0			0
#define PREF_SCORE_15			15


typedef struct _workqueue_args{
	int inuse;
	int wq_num;
	void* wqdata;
}wq_args;

typedef struct _workqueue_pool{
	uv_work_t workq;
	wq_args args;
}wq_pool;


typedef struct _multiapd_handle{
	wq_pool gather_wq[MAX_NUM_OF_WQ];
	void* config_opts;
}mapdhdl;

typedef int handle_1905_t;


extern map_ale_info_t *gmap_agent;

extern handle_1905_t handle_1905;

#endif

#ifdef __cplusplus
}
#endif
