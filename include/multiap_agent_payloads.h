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

#ifndef MULTIAP_AGENT_PAYLOADS_H
#define MULTIAP_AGENT_PAYLOADS_H

#include <stdio.h>
#include <uv.h>
#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include "map_tlvs.h"
#include "mon_platform.h"
#include "map_data_model.h"

#define MAX_TLV_PER_MSG 32
#define MAX_MAP_MSG 32
#define MAX_RETRY_THRESHOLD 10
#define MAX_NO_FREQ_SUPPORTED 2

#define ROLE_1905_REGISTRA 0

#define MAP_ROLE_CONTROLLER 0x00
#define MAP_ROLE_AGENT 0x01
#define MULTIAP_BOTH_CONTROLLER_AGENT 0x02

#define VHT_CAP_MCS_0_7                     0
#define VHT_CAP_MCS_0_8                     1
#define VHT_CAP_MCS_0_9                     2
#define VHT_CAP_MCS_NONE                    3

int map_send_sta_metrics_report(map_handle_t map_handle, int sta_count, map_sta_info_t **sta_list);
int map_stations_assoc_control_apply (uint8_t action, uint8_t *bssid, array_list_t* block_sta_list);
int map_send_1905_ack(map_handle_t *map_handle, array_list_t *sta_list, uint8_t reason_code);
int map_send_autoconfig_search (map_handle_t map_handle, void* index);
int map_send_wsc_m1 (map_handle_t map_handle, void *index);
void map_send_channel_pref_report(uv_work_t *req, int status);
int map_send_channel_select_response(map_handle_t   *map_handle);
void map_process_channel_selection_query(uv_work_t *req, int status);
void map_process_topology_discovery(uv_work_t *req, int status);
void map_parse_transmit_power_tlv(map_handle_t   *map_handle);
int  map_send_operating_channel_report (void * data);
void map_send_ap_capability_report(uv_work_t *req, int status);
int map_send_client_capability_query(map_handle_t *map_handle, uint8_t *sta_mac, uint8_t *bssid);
int map_send_higher_layer_data_msg(map_handle_t *map_handle, uint32_t msg_len, uint32_t protocol, uint8_t *msg_payload);
void map_send_client_capability_report(uv_work_t *req, int status);
void map_send_associated_sta_link_metrics_response(uv_work_t *req, int status);
void map_send_topology_response(uv_work_t *req, int status);
int map_send_topology_notification(map_handle_t map_handle,void *data);
void map_send_ap_metrics (uv_work_t *req, int status);
void map_send_association_control_response(uv_work_t *req, int status);
int  map_send_beacon_metrics_response(map_handle_t map_handle, void *index);
void map_send_beacon_metrics_ack (uv_work_t *req, int status);
void map_higher_layer_data_msg_ack(uv_work_t *req, int status);
int map_send_btm_report(map_handle_t *map_handle, void *data);
void map_unassoc_sta_metrics_ack (uv_work_t *req, int status);
int map_unassoc_sta_metrics_response(map_handle_t map_handle, void *index);
map_radio_info_t * get_radio_for_unassoc_measurement(struct mapUnassocStaMetricsQueryTLV *unassoc_sta_met);
int map_send_topology_query (map_handle_t   *map_handle);
int map_agent_send_steering_complete(map_handle_t *map_handle);
int map_cli_send_ch_pref_report(map_handle_t   *map_handle, struct channel_preference_report *ch_pref_report);

void map_send_link_metrics_report(map_handle_t *map_handle, struct neighbour_link_met_response *link_met_resp);
void map_neighbour_link_met_query_process (uv_work_t *req, int status);

void map_send_unsolicated_channel_pref_report(map_handle_t   *map_handle, map_radio_info_t *radio_node);
#endif

#ifdef __cplusplus
}
#endif
