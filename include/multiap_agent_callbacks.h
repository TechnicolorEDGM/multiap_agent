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

#ifndef MULTIAP_AGENT_CALLBACKS_H
#define MULTIAP_AGENT_CALLBACKS_H

#include "1905_cmdus.h"
#include "map_tlvs.h"

#define MAX_CMDU_PER_SEND 8

#define MCAST_1905_B0 (0x01)
#define MCAST_1905_B1 (0x80)
#define MCAST_1905_B2 (0xC2)
#define MCAST_1905_B3 (0x00)
#define MCAST_1905_B4 (0x00)
#define MCAST_1905_B5 (0x13)

#define MCAST_1905  {MCAST_1905_B0, MCAST_1905_B1, MCAST_1905_B2, MCAST_1905_B3, MCAST_1905_B4, MCAST_1905_B5}

#define STATE_MASK     0x80
#define MAP_STA_ASSOC_EVENT (1<<7)
#define MAX_TARGET_CLASS_LEN  5

#define ATTR_VENDOR_EXTENSION  (0x1049)
#define WFA_ELEM_MAP_EXT_ATTR  (0x06)

/* Flags for MultiAp extension subelement  */
#define MAP_TEAR_DOWN           0x10    /* Bit 4 */
#define MAP_FRONTHAUL_BSS       0x20    /* Bit 5 */
#define MAP_BACKHAUL_BSS        0x40    /* Bit 6 */
#define MAP_BACKHAUL_STA        0x80    /* Bit 7 */

#define ONE_SEC_IN_MS           1000

typedef struct multiap_global_s {
        uint16_t recv_msg_type;
        uint16_t send_msg_type;
        int (*validation_cb) (uint8_t *, struct CMDU * , void *);
        void (*data_gathering) (uv_work_t *);
        void (*send_cb) (uv_work_t *req, int status);
} map_cb_config_t;


void map_configure_radios();

int map_apply_msg_filter (handle_1905_t handle);

int find_gmap_cb_index(uint16_t msg_type);

void get_mcast_macaddr(uint8_t * dest_mac);

int find_gmap_cb_index_from_send_msgtype(uint16_t msg_type);

uint8_t * map_get_tlv_from_cmdu(struct CMDU* cmdu, uint8_t type);

int map_free_cached_m1(map_radio_info_t *radio_node);

int addto_acl_timeout_list(uint16_t mid, uint8_t *bssid, array_list_t *block_sta_list, uint16_t validity_period, struct timespec msg_recvd);

/** @brief This API will return the number of TLV's of particular type found in the CMDU
 *
 *  @param Input -CMDU from which you need TLV count
 *  @param Input -type of TLV for which count is needed
 *  @return Count - 0 or higher
 */
uint8_t map_get_tlv_count_from_cmdu(struct CMDU* cmdu, uint8_t type);

/** @brief This API will return the index of the op_class in the global agent structure
 *
 *  @param Input -radio index to specify the radio to be iterated for op_class
 *  @param Input -op_class to searched for in the radio
 *  @return Index - -EINVAL or actual index
 */
int find_op_class_in_radio(map_radio_info_t* radio_node, uint8_t op_class);

/** @brief This API will update the global agent radio data (gmap_agent_config) with channel pref data
 *
 *  @param Input - Channel pref TLV pointer used to update the global agent radio data
 *  @param Input - radio index for which to update in the global agent radio data
 *  @return 0 
 */
uint8_t update_global_channel_pref_with_controller_updates(struct mapChannelPreferenceTLV *channel_pref, map_radio_info_t *radio_node, uint8_t *reason);

/** @brief This API will Construct a TLV with default preference values
 *
 *  @param Input - Channel pref TLV pointer to be filled with default values
 *  @param Input - radio index from which data can be used to fill the default values
 *  @return 0 
 */
void get_default_channel_pref_tlv(struct mapChannelPreferenceTLV *channel_pref, uint8_t radio_index);

/** @brief This is called to perform data gather and send
 *
 *  This generic callback will be called by 1905 agent when it receives 
 *  any multiap registered message.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param src_iface_name ifname through which cmdu is received
 *  @param index index to global map structure
 *  @return The status code 0-success, -ve for failure
 */
int map_datagather_and_send(uint8_t *src_mac_addr, uint8_t *src_iface_name, int index, struct CMDU *cmdu);

/** @brief This will be generic msg callback registered to 1905.
 *
 *  This generic callback will be called by 1905 agent when it receives 
 *  any multiap registered message.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_read_cb (uint8_t *src_mac_addr, struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for topology discovery.
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_TOPOLOGY_DISCOVERY in global data structure
 *  gmap_cb_config.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_topology_discovery_validation (uint8_t *src_mac_addr,struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for autoconfig response.
 *
 *  This will be assigned as validation_cb for msg type 
 *  CMDU_TYPE_MAP_AUTOCONFIG_RESPONSE in global data structure
 *  gMultiap_data_structure.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_autoconfig_response_validation (uint8_t *src_mac_addr, 
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for autoconfig wsc.
 *
 *  This will be assigned as validation_cb for msg type 
 *  CMDU_TYPE_MAP_AUTOCONFIG_WSC in global data structure
 *  gMultiap_data_structure.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_wsc_m2_validation (uint8_t *src_mac_addr, 
                                      struct CMDU *cmdu, void *context);


/** @brief This will be validation callback for autoconfig renew.
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_MAP_AUTOCONFIG_RENEW in global data structure
 *  gMultiap_data_structure.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
*/
int map_autoconfig_renew_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for client capability query.
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_MAP_CLIENT_CAPABILITY_QUERY in global data structure
 *  gMultiap_data_structure.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_client_capability_query_validation (uint8_t *src_mac_addr, struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for client capability report.
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_MAP_CLIENT_CAPABILITY_REPORT in global data structure
 *  gMultiap_data_structure.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_client_capability_report_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for client association control
 *  request.
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_MAP_CLIENT_ASSOCIATION_CONTROL_REQUEST in global data structure
 *  gMultiap_data_structure.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_client_association_control_request_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for associated sta link metrics query.
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_MAP_ASSOCIATED_STA_LINK_METRICS_QUERY in global data structure
 *  gMultiap_data_structure.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_associated_sta_link_metrics_query_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for topology query.
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_TOPOLOGY_QUERY in global data structure
 *  gMultiap_data_structure.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_topology_query_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for topology response.
 *
 *  This will be assigned as validation_cb for msg type
 *  CMDU_TYPE_TOPOLOGY_RESPONSE in global data structure
 *  gMultiap_data_structure.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_topology_response_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for channel_preference_query.
 *
 *  This will be assigned as validation_cb for msg type 
 *  CMDU_TYPE_MAP_CHANNEL_PREFERENCE_REPORT in global data structure
 *  gMultiap_data_structure.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_channel_pref_validation (uint8_t *src_mac_addr, 
                                  struct CMDU *cmdu, void *context);

/** @brief This will be set callback for btm_request.
 *
 *  This will be trigger a BTM request to the specific STA.
 *
 *  @param work the uv_work argument
 */
void map_apply_btm_request (uv_work_t *work, int status);

/** @brief This will be validation callback for channel_selection_request.
 *
 *  This will be assigned as validation_cb for msg type 
 *  CMDU_TYPE_MAP_CHANNEL_SELECTION_REQUEST in global data structure
 *  gMultiap_data_structure.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_channel_select_validation ( uint8_t *src_mac_addr, struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for ap_policy_config request.
 *
 *  This will be assigned as validation_cb for msg type 
 *  CMDU_TYPE_MAP_MULTI_AP_POLICY_CONFIG_REQUEST in global data structure
 *  gMultiap_data_structure.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_ap_policy_config_validation (uint8_t *src_mac_addr, struct CMDU *cmdu, void *context);

int map_client_steering_validation (uint8_t *src_mac_addr, 
                                      struct CMDU *cmdu, void *context);

/** @brief This will be validation callback for 1905 ack validation.
 *
 *  This will be assigned as validation_cb for msg type 
 *  CMDU_TYPE_MAP_OPERATING_CHANNEL_REPORT in global data structure
 *  gMultiap_data_structure. In this case we will send multiap
 *  unsolicit report and get back ack.
 *
 *  @param src_mac_addr the received payloads source mac address
 *  @param cmdu the received payload structure including
 *  @param context this will be used for lib1905 reference purpose
 *  @return The status code 0-success, -ve for failure
 */
int map_ack_validation (uint8_t *src_mac_addr, struct CMDU *cmdu, void *context);

/** @brief This api is used to get target_radio_id from the payload CMDU.
 * 
 *  This will parse the entire payload structure and extract the radio
 *  for which the response payload need to construct.
 *
 *  @param cmdu payload structure
 *  @param target_radio_id This is output param contains the unique
 *         radio_id for which the response need to be sent. 
 *  @return -ve for failure, 0 for success
 */
int map_get_radioid_from_cmdu (struct CMDU *cmdu, uint8_t *target_radio_id);

/** @brief This api will gather data for channel_preference_report.
 * 
 *  The function will run as uv_thread, do channel_preference data gather. 
 *
 *  @param work uv_work_t
 */
void map_gather_channel_pref_report (uv_work_t * work);

/** @brief This api will gather data for channel_selection_response.
 * 
 *  The function will run as uv_thread, do channel_selection data gather.
 *
 *  @param work uv_work_t
 */
void map_gather_channel_select_response (uv_work_t * work);

/** @brief This api will be triggered if uv poll detects any event.
 *
 * The function is not for generic use, will be called by uv_poll
 *
 * @param uv_poll handle
 * @param status
 * @param event descriptor
 */
void uvpoll_1905read_cb (uv_poll_t* handle, int status, int events);

/** @brief This api do data gathering for device configuration.
 * 
 *  This function will be called from main, to do device data gathering like ap capability.
 *
 *  @param message it will be error message
 *  @param code 
 */
int load_multiap_data(void);

/** @brief This api will initialise multiap_agent and all its threads.
 * 
 *  This function will be called from main, to do device data gathering like ap capability.
 *
 *  @param message it will be error message
 *  @param code 
 */
int multiap_agent_init();

int map_beacon_metrics_query_validation(uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

int map_ap_metrics_query_validation (uint8_t *src_mac_addr, 
                                   struct CMDU *cmdu, void *context);

int init_periodic_timers(uv_loop_t  *loop, uv_timer_t *periodic_timer);


int map_unassoc_sta_metrics_query_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

int map_higher_layer_data_msg_validation (uint8_t *src_mac_addr, struct CMDU *cmdu, void *context);

int set_tx_pwr(char * radio_name, uint8_t current_tx_pwr, uint8_t new_tx_pwr);

int map_neighbour_link_met_query_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context);

int map_send_platform_event(int subcmd, void *data); 
/* These are purely to test vendor specific data and not to be enabled unless for test purposes */
#ifdef TEST_VENDOR_SPECIFIC
int map_vendor_specific_validation (uint8_t *src_mac_addr,
                                               struct CMDU *cmdu, void *context);

typedef struct 
{
	uint8_t 	oui_id[3];
	uint8_t		relay_indicator;
	uint8_t 	ale_mac[MAC_ADDR_LEN];					///< incase if this message has to be transmitted to each ALE, from bottom to up (ie DFS) then 
											///		callee has to pass the 0xff for all octect of the ale_mac. 
											///		the relay_indicator will not be considered if all octect of ale_mac is 0xff
	uint16_t		len;						///< length of the data
	uint8_t		*data;						///< data

}map_ipc_write_1905_ve;

#endif
int  map_combined_infrastructure_validation(uint8_t *src_mac_addr, struct CMDU *cmdu, void *context);
void map_send_combined_infrastructure_metrics_ack(uv_work_t *req, int status);
#endif

#ifdef __cplusplus
}
#endif

