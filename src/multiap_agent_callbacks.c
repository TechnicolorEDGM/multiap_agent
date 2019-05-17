/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "multiap_agent.h"
#include "multiap_agent_callbacks.h"
#include "multiap_agent_utils.h"
#include "multiap_agent_payloads.h"
#include "multiap_agent_retry.h"
#include "1905_tlvs.h"
#include "monitor_task.h"
#include "mon_platform.h"
#include "platform_multiap_get_info.h"
#include "multiap_agent_topology_tree_builder.h"
#include "platform_map.h"
#include "map_data_model_dumper.h"
#include "map_80211.h"
#include "1905_platform.h"
#include "platform_multiap_get_info.h"
#include "map_timer_handler.h"

#ifdef TEST_VENDOR_SPECIFIC
char *vendor_data = "Vendor Specific from agent";
#endif
extern wq_pool* get_workqueue_handle();
extern void free_workqueue_handle(wq_args* data);
extern int operating_channel_pending_in_timer;

static void map_send_aysnc_repsonse(map_handle_t *handle, int status, uint16_t msg_type);
static int agent_store_policy_config(uint8_t tlv_type, void * tlv_info);

int ev_data;
int wq_data;

extern uv_loop_t *loop;
extern uv_async_t async;
extern plfrm_config pltfrm_config;
extern uint8_t agent_search_retry_cnt[MAX_NO_FREQ_SUPPORTED];

map_cb_config_t gmap_cb_config[] = {

    {
         .recv_msg_type          = CMDU_TYPE_TOPOLOGY_DISCOVERY,
         .send_msg_type          = 0,
         .validation_cb          = map_topology_discovery_validation,
         .data_gathering         = NULL,
         .send_cb                = map_process_topology_discovery,
    },
    {
        .recv_msg_type        = CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE,
        .send_msg_type        = CMDU_TYPE_AP_AUTOCONFIGURATION_WSC,
        .validation_cb        = map_autoconfig_response_validation, 
        .data_gathering       = NULL,
    },
    {
        .recv_msg_type        = CMDU_TYPE_AP_AUTOCONFIGURATION_WSC,
        .validation_cb        = map_wsc_m2_validation,
        .data_gathering       = NULL,
        .send_cb              = NULL,
    },
    {
        .recv_msg_type        = CMDU_TYPE_TOPOLOGY_QUERY,
        .send_msg_type        = CMDU_TYPE_TOPOLOGY_RESPONSE,
        .validation_cb        = map_topology_query_validation,
        .data_gathering       = NULL,
        .send_cb              = map_send_topology_response,
    },
    {
        .recv_msg_type        = CMDU_TYPE_TOPOLOGY_RESPONSE,
        .validation_cb        = map_topology_response_validation,
        .data_gathering       = NULL,
        .send_cb              = NULL,
    },
    {
        .recv_msg_type        = CMDU_TYPE_MAP_CHANNEL_PREFERENCE_QUERY,
        .send_msg_type        = CMDU_TYPE_MAP_CHANNEL_PREFERENCE_REPORT,
        .validation_cb        = map_channel_pref_validation,
        .data_gathering       = NULL,
        .send_cb              = map_send_channel_pref_report,
    },
    {
        .recv_msg_type        = CMDU_TYPE_MAP_CHANNEL_SELECTION_REQUEST,
        .send_msg_type        = CMDU_TYPE_MAP_CHANNEL_SELECTION_RESPONSE,
        .validation_cb        = map_channel_select_validation,
        .data_gathering       = NULL,
        .send_cb              = map_process_channel_selection_query,
    },
    {
        .recv_msg_type        = CMDU_TYPE_MAP_CLIENT_STEERING_REQUEST,
        .send_msg_type        = CMDU_TYPE_MAP_ACK,
        .validation_cb        = map_client_steering_validation,
        .send_cb              = map_apply_btm_request,
    },
    {
        .recv_msg_type        = CMDU_TYPE_MAP_MULTI_AP_POLICY_CONFIG_REQUEST,
        .send_msg_type        = CMDU_TYPE_MAP_ACK,
        .validation_cb        = map_ap_policy_config_validation,
        .data_gathering       = NULL,
    },
    {
        .recv_msg_type        = CMDU_TYPE_MAP_AP_CAPABILITY_QUERY,
        .send_msg_type        = CMDU_TYPE_MAP_AP_CAPABILITY_REPORT,
        .validation_cb        = NULL,
        .data_gathering       = NULL,
        .send_cb              = map_send_ap_capability_report,
    },
    {
        .send_msg_type        = CMDU_TYPE_MAP_OPERATING_CHANNEL_REPORT, //##Unsolicated report to controller
        .recv_msg_type        = CMDU_TYPE_MAP_ACK,                      //## Wait for ack after sending report to ctrler
        .validation_cb        = map_ack_validation,
        .data_gathering       = NULL,
        .send_cb              = NULL,
    },
    {
        .send_msg_type        = CMDU_TYPE_AP_AUTOCONFIGURATION_WSC,
        .recv_msg_type        = CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW,
        .validation_cb        = map_autoconfig_renew_validation,
        .data_gathering       = NULL,
    },
    {
        .recv_msg_type        = CMDU_TYPE_MAP_CLIENT_CAPABILITY_QUERY,
        .send_msg_type        = CMDU_TYPE_MAP_CLIENT_CAPABILITY_REPORT,
        .validation_cb        = map_client_capability_query_validation,
        .data_gathering       = NULL,
        .send_cb              = map_send_client_capability_report,
    },
    {
        .recv_msg_type        = CMDU_TYPE_MAP_CLIENT_CAPABILITY_REPORT,
        .validation_cb        = map_client_capability_report_validation,
        .data_gathering       = NULL,
        .send_cb              = NULL,
    },
    {
        .recv_msg_type        = CMDU_TYPE_MAP_AP_METRICS_QUERY,
        .send_msg_type        = CMDU_TYPE_MAP_AP_METRICS_RESPONSE,
        .validation_cb        = map_ap_metrics_query_validation,
        .data_gathering       = NULL,
        .send_cb              = map_send_ap_metrics
    },
    {
        .recv_msg_type        = CMDU_TYPE_MAP_CLIENT_ASSOCIATION_CONTROL_REQUEST,
        .send_msg_type        = CMDU_TYPE_MAP_ACK,
        .validation_cb        = map_client_association_control_request_validation,
        .data_gathering       = NULL,
        .send_cb              = map_send_association_control_response,
    },
    {
        .recv_msg_type        = CMDU_TYPE_MAP_ASSOCIATED_STA_LINK_METRICS_QUERY,
        .send_msg_type        = CMDU_TYPE_MAP_ASSOCIATED_STA_LINK_METRICS_RESPONSE,
        .validation_cb        = map_associated_sta_link_metrics_query_validation,
        .data_gathering       = NULL,
        .send_cb              = map_send_associated_sta_link_metrics_response,
     },
     {
        .recv_msg_type        = CMDU_TYPE_MAP_BEACON_METRICS_QUERY,
        .send_msg_type        = CMDU_TYPE_MAP_ACK,
        .validation_cb        = map_beacon_metrics_query_validation,
        .data_gathering       = NULL,
        .send_cb              = map_send_beacon_metrics_ack,
     },
     {
        .send_msg_type        = CMDU_TYPE_MAP_BEACON_METRICS_RESPONSE,  /* For handling of ack frame (stop retry) */
        .recv_msg_type        = CMDU_TYPE_MAP_ACK,
        .validation_cb        = map_ack_validation,
        .data_gathering       = NULL,
        .send_cb              = NULL,                               
     },
     {
        .recv_msg_type        = CMDU_TYPE_MAP_UNASSOCIATED_STA_LINK_METRICS_QUERY,
        .send_msg_type        = CMDU_TYPE_MAP_ACK,
        .validation_cb        = map_unassoc_sta_metrics_query_validation,
        .send_cb              = map_unassoc_sta_metrics_ack,
     },
     {
        .recv_msg_type        = CMDU_TYPE_MAP_ACK,
        .send_msg_type        = CMDU_TYPE_MAP_UNASSOCIATED_STA_LINK_METRICS_RESPONSE,
        .validation_cb        = NULL,
        .send_cb              = NULL,
     },
     {
         .recv_msg_type       = CMDU_TYPE_MAP_HIGHER_LAYER_DATA,
         .send_msg_type       = CMDU_TYPE_MAP_ACK,
         .validation_cb       = map_higher_layer_data_msg_validation,
         .send_cb             = map_higher_layer_data_msg_ack,
     },
     {
        .recv_msg_type        = CMDU_TYPE_LINK_METRIC_QUERY,
        .send_msg_type        = CMDU_TYPE_LINK_METRIC_RESPONSE,
        .validation_cb        = map_neighbour_link_met_query_validation,
        .send_cb              = map_neighbour_link_met_query_process,
     },
/* The below is purely to test vendor specific data and not to be enabled unless for test purposes */
#ifdef TEST_VENDOR_SPECIFIC
     {
        .recv_msg_type        = CMDU_TYPE_VENDOR_SPECIFIC,
        .send_msg_type        = CMDU_TYPE_VENDOR_SPECIFIC,
        .validation_cb        = map_vendor_specific_validation,
        .send_cb              = NULL,
     },
#endif
     {
        .recv_msg_type        = CMDU_TYPE_MAP_COMBINED_INFRASTRUCTURE_METRICS,
        .send_msg_type        = CMDU_TYPE_MAP_ACK,
        .validation_cb        = map_combined_infrastructure_validation,
        .data_gathering       = NULL,
        .send_cb              = map_send_combined_infrastructure_metrics_ack,
     },
};

void get_mcast_macaddr(uint8_t * dest_mac)
{
    dest_mac[0] = MCAST_1905_B0;
    dest_mac[1] = MCAST_1905_B1;
    dest_mac[2] = MCAST_1905_B2;
    dest_mac[3] = MCAST_1905_B3;
    dest_mac[4] = MCAST_1905_B4;
    dest_mac[5] = MCAST_1905_B5;
}

int map_get_radioid_from_cmdu (struct CMDU *cmdu, uint8_t *target_radio_id)
{
    return 0;
}

map_bss_info_t* get_bss_node_from_interface(char *if_name)
{
    int i = 0;
    int j = 0;

    if (NULL == if_name)
    {
        platform_log(MAP_AGENT,LOG_ERR, "Interface name or radio node is NULL");
        return NULL;
    }

    for (i = 0; i < gmap_agent->num_radios; i++){

        for(j = 0; j < gmap_agent->radio_list[i]->num_bss; j++) {

            if (0 == strncmp(if_name, gmap_agent->radio_list[i]->bss_list[j]->iface_name, MAX_IFACE_NAME_LEN))
                return gmap_agent->radio_list[i]->bss_list[j];
        }
    }

    return NULL;
}

int map_set_radio_state_off(map_radio_info_t *radio_node)
{
    int8_t bss_index = 0;
    if(NULL == radio_node)
    {
        platform_log(MAP_AGENT,LOG_ERR,"radio data passed in NULL\n");
        return 0;
    }
    for(bss_index=0;bss_index<radio_node->num_bss;bss_index++)
    {
        set_bss_state_off(&radio_node->bss_list[bss_index]->state);
    }
    return 1;
}

/** @brief This API will return the index of the op_class in the global agent structure
 *
 *  @param Input -radio index to specify the radio to be iterated for op_class
 *  @param Input -op_class to searched for in the radio
 *  @return Index - -EINVAL or actual index
 */
int find_op_class_in_radio(map_radio_info_t* radio_node, uint8_t op_class)
{
    int i = 0;
	
	if(radio_node != NULL)
	{
	 	for(i=0; i<radio_node->op_class_count;i++)
	 	{
	 		if(op_class == radio_node->op_class_list[i].op_class)
				return i;
	 	}
	}

    platform_log(MAP_AGENT,LOG_ERR, "op_class is not found in gmap_agent");
    return -EINVAL;
}

int map_validate_master_channel_preference(uint8_t channel, uint8_t rclass, struct mapChannelPreferenceTLV *ctrl_channel_pref, uint8_t minpref)
{
    int i = 0 ;
	uint8_t ctrl_ch_count  = 0;
	uint8_t *ctrl_ch_array = NULL;
	uint8_t ctrl_ch_pref   = 0;

    for (i = 0; i<ctrl_channel_pref->numOperating_class; i++) {
	    if(rclass != ctrl_channel_pref->operating_class[i].operating_class)
		    continue;
		break;
	}

	if (i == ctrl_channel_pref->numOperating_class) {
	    /* As per Multiap spec Table 17.2.13, 
             * the “most preferred” score 15 is inferred for all channels / operating 
             * classes that are not specified in the corresponding message.
             * So if radio current oper class is not present in ctrller chanel select,
             * then we assume current channel it is most preferred.
             */
            platform_log(MAP_AGENT,LOG_DEBUG, "%s %d, radio ch %d for operating class %d , is not present in channel pref \n",__func__, __LINE__, channel, rclass);
	    return 1;
	}

	ctrl_ch_count = ctrl_channel_pref->operating_class[i].number_of_channels;
	ctrl_ch_array = ctrl_channel_pref->operating_class[i].channel_num;
	ctrl_ch_pref  = ctrl_channel_pref->operating_class[i].pref_reason >> SHIFT_4BIT;

        platform_log(MAP_AGENT,LOG_DEBUG, "%s %d, ch %d, oper %d \n",__func__, __LINE__, channel, rclass);
	for (int j = 0; j<ctrl_ch_count; j++) {
	    if(channel == ctrl_ch_array[j]) {
		    if(ctrl_ch_pref < minpref) {
                        platform_log(MAP_AGENT,LOG_DEBUG, "%s %d, current ch has less preference\n",__func__, __LINE__);
			return 0;
                    }
		}
	}

        if (ctrl_ch_count == 0) {
            /* As per Multiap spec Table 17.2.13,
             * An empty Channel List field (k=0) indicates that 
             * the indicated Preference applies to all channels in the Operating Class.
             */
             if(ctrl_ch_pref < minpref) {
                   platform_log(MAP_AGENT,LOG_DEBUG, "%s %d, current ch has less preference\n",__func__, __LINE__);
                   return 0;
             }
        }

        platform_log(MAP_AGENT,LOG_DEBUG, "%s %d, current ch has good preference\n",__func__, __LINE__);
	return 1;
}

int set_channel(char * radio_name, uint8_t channel) {

       map_monitor_cmd_t                   cmd = {0};
       platform_cmd_channel_set_t             *channel_info = NULL;
       int                                ret  = 0;

       channel_info = (platform_cmd_channel_set_t * )malloc(sizeof(platform_cmd_channel_set_t));
       if(channel_info == NULL) {
           return -EINVAL;
       }

       channel_info->channel = channel;
       strcpy(channel_info->radio_name, radio_name);

       cmd.cmd    = MAP_MONITOR_SEND_UBUS_DATA_CMD;
       cmd.subcmd = MAP_MONITOR_SET_CHANNEL_METHOD_SUBCMD;
       cmd.param  = (void *)channel_info;

       if(0 != map_monitor_send_cmd(cmd)) {
           platform_log(MAP_AGENT,LOG_ERR, "%s send command to publish methods failed\n", __FUNCTION__);
           free(channel_info);
           ret = -EINVAL;
       }
       return ret;
}

int map_send_platform_event(int subcmd, void *data) 
{
       map_monitor_cmd_t                   cmd = {0};
       int                                 ret  = 0;

       cmd.cmd    = MAP_MONITOR_SEND_UBUS_DATA_CMD;
       cmd.subcmd = subcmd;
       cmd.param  = (void *)data;

       if(0 != map_monitor_send_cmd(cmd)) {
           platform_log(MAP_AGENT,LOG_ERR, "%s send command to publish methods failed\n", __FUNCTION__);
           ret = -EINVAL;
       }
       return ret;
}


int set_tx_pwr(char * radio_name, uint8_t current_tx_pwr, uint8_t new_tx_pwr) {

       platform_cmd_tx_pwr_set_t          *tx_pwr_info = NULL;
       int                                ret  = 0;

       tx_pwr_info = (platform_cmd_tx_pwr_set_t * )malloc(sizeof(platform_cmd_tx_pwr_set_t));
       if(tx_pwr_info == NULL) {
           return -EINVAL;
       }

       tx_pwr_info->new_tx_pwr     = new_tx_pwr;
       tx_pwr_info->current_tx_pwr = current_tx_pwr;

       strcpy(tx_pwr_info->radio_name, radio_name);

       ret = map_send_platform_event(MAP_MONITOR_SET_TX_PWR_METHOD_SUBCMD, tx_pwr_info);
       if(ret < 0)
           free(tx_pwr_info);
      return ret;
}



/** @brief This API will update the global agent radio data (gmap_agent_config) with channel pref data
 *
 *  @param Input - Channel pref TLV pointer used to update the global agent radio data
 *  @param Input - radio index for which to update in the global agent radio data
 *  @return 0 
 */
uint8_t update_global_channel_pref_with_controller_updates(struct mapChannelPreferenceTLV *channel_pref,map_radio_info_t* radio_node, uint8_t *response)
{
    int   i =  0;
    int   j =  0;
    int minpref = 15;
    uint8_t channel = 0, bw = 0;
    uint8_t operating_class = 0;
    uint8_t is_valid = 0;
    char    macstring[64] = {0};
    uint8_t current_channel = radio_node->current_op_channel;

    get_mac_as_str(radio_node->radio_id, (int8_t *)macstring, MAX_MAC_STRING_LEN);

    platform_log(MAP_AGENT,LOG_DEBUG, "%s %d radioid %s, radio_name %s\n",__func__, __LINE__, macstring, radio_node->radio_name);

    current_channel = get_mid_freq(current_channel, radio_node->current_op_class, radio_node->current_bw);

    is_valid = map_validate_master_channel_preference (current_channel, radio_node->current_op_class, channel_pref, 1);
    if (is_valid) {
	/* 
	 * ctrller specified the current channel as just lowest preference, 
	 * not mentioned as non operable, 
	 * so no need to change the channel 
	 */
        platform_log(MAP_AGENT,LOG_DEBUG, "%s %d, NO channel change\n",__func__, __LINE__);
        goto end;
    }

    platform_log(MAP_AGENT,LOG_DEBUG, "%s %d, Yes channel change, radio %s\n",__func__, __LINE__, radio_node->radio_name);
    for (minpref = 15; minpref>0; minpref--) {
        /* 
         * Iterate over all the preferred channels in the radio,
         * and select the one which ctrller show preferrence.
         */
        for (i = 0; i<radio_node->op_class_count; i++) {
            for (j = 0; j<radio_node->op_class_list[i].agent_channel_count; j++) {
                channel = radio_node->op_class_list[i].agent_channel[j];
                operating_class = radio_node->op_class_list[i].op_class;

                platform_log(MAP_AGENT,LOG_DEBUG, "%s %d,radio %s, channel %d, op_class %d, Validate\n",__func__, __LINE__, radio_node->radio_name, channel, operating_class);
                is_valid = map_validate_master_channel_preference(channel, operating_class, channel_pref, minpref);
                if (!is_valid) {
                    /* 
                     * channel rejected, due to ctrller pref of channel less than the "minpref"
                     */
                    platform_log(MAP_AGENT,LOG_DEBUG, "%s %d, radio %s channel %d reject due to ctrl non pref\n",__func__, __LINE__, radio_node->radio_name, channel);
                    continue;
                }
                platform_log(MAP_AGENT,LOG_DEBUG, "%s %d, radio %s channel %d select\n",__func__, __LINE__, radio_node->radio_name, channel);
                break;
            }
   
            if(j < radio_node->op_class_list[i].agent_channel_count) {
                break;
            }
        }
  
        if(i < radio_node->op_class_count) {
               /* we Got the best channel which suits both preference */
            break;
        }
    }

    if(minpref > 0)  {
        get_bw_from_operating_class(operating_class, &bw);
        get_primary_channel_for_midfreq(&channel, bw);
        platform_log(MAP_AGENT,LOG_DEBUG, "%s %d, final channel to set %d for radio %s\n",__func__, __LINE__,channel, radio_node->radio_name);
        set_channel(radio_node->radio_name, channel);
    } else {
        /* 
         * There is no agent operable channel in channel preference tlvs,
         * And hence, reject.
         */
        *response = MAP_CHANNEL_SEL_DECLINE;
        return -EINVAL;
    }

end:
    return 0;
}

/** @brief This API will Construct a TLV with default preference values
 *
 *  @param Input - Channel pref TLV pointer to be filled with default values
 *  @param Input - radio index from which data can be used to fill the default values
 *  @return 0 
 */
void get_default_channel_pref_tlv(struct mapChannelPreferenceTLV *channel_pref, uint8_t radio_index)
{
	int i=0;
	if(channel_pref != NULL)
	{
		memcpy(channel_pref->radio_id, gmap_agent->radio_list[radio_index]->radio_id, MAC_ADDR_LEN);
		channel_pref->numOperating_class = gmap_agent->radio_list[radio_index]->op_class_count;
		for(i=0;i<channel_pref->numOperating_class;i++)
		{
			channel_pref->operating_class[i].operating_class = gmap_agent->radio_list[radio_index]->op_class_list[i].op_class;
			channel_pref->operating_class[i].number_of_channels = 0;
			channel_pref->operating_class[i].pref_reason = PREF_SCORE_15 << 4 | PREF_REASON_UNSPECFIED;
		}
	}
}

void update_interface_type(char *if_list, uint8_t type)
{
    char* delimiters = ",";
    char* token      = NULL;
    char *rest       = NULL;
    map_bss_info_t *bss = NULL;

    if (NULL == if_list) {
        platform_log(MAP_AGENT,LOG_ERR, "Interface list is NULL");
        return;
    }

    token = strtok_r(if_list, delimiters, &rest);
    while (NULL != token)
    {
        bss = get_bss_node_from_interface(token);

        if (NULL != bss) {
            bss->type = type;
        }
        else {
            platform_log(MAP_AGENT,LOG_ERR, "Invalid interface name : %s", token);
        }

        token = strtok_r(NULL, delimiters, &rest);
    }

    return;
}

int map_update_radio_config()
{
    int i, j;

    platform_log(MAP_AGENT,LOG_DEBUG,"map_update_radio_config \n");

    if(-1 == platform_get(MAP_PLATFORM_GET_AP_AUTOCONFIG,NULL,(void *) gmap_agent))
        return -EINVAL;


    platform_log(MAP_AGENT,LOG_DEBUG,"map_update_radio_config DONE \n");
    /* There must be a way to get the channel preference data for those channels that are temporarily not operable in each operating class.
    All channels that are statically not operable are already maintained in the non_op_chnl list and those are not considered. 
    In BRCM "per_chnl_info" ioctl is used to get the channel info and those channels with RADAR/PASSIVE set are considered in this list. 
    For now this list is not updated and count is left 0
    */

    for (i = 0; i < gmap_agent->num_radios; i++)
    {
        platform_get(MAP_PLATFORM_GET_UNASSOC_MEASUREMENT_SUPPORT, gmap_agent->radio_list[i]->radio_name, &gmap_agent->radio_list[i]->state);
        if(is_unassoc_measurement_supported(gmap_agent->radio_list[i]->state)) {
           /* the agent is capable of unassoc measurement */
           gmap_agent->agent_capability.ib_unassociated_sta_link_metrics_supported = 1;
           gmap_agent->agent_capability.oob_unassociated_sta_link_metrics_supported = 1;

        }

        for(j=0; j< gmap_agent->radio_list[i]->op_class_count; j++)
        {
            if(!gmap_agent->radio_list[i]->op_class_list)
            {
                platform_log(MAP_AGENT,LOG_ERR, "%s calloc for op_class_list failed\n", __func__);
                return -EINVAL;
            }

            if ( gmap_agent->radio_list[i]->radio_caps.type == IEEE80211_FREQUENCY_BAND_2_4_GHZ) {
                platform_get (MAP_PLATFORM_GET_2G_CHANNEL_PREF, gmap_agent->radio_list[i]->radio_name, &gmap_agent->radio_list[i]->op_class_list[j]);
            } else {
                platform_get (MAP_PLATFORM_GET_5G_CHANNEL_PREF, gmap_agent->radio_list[i]->radio_name, &gmap_agent->radio_list[i]->op_class_list[j]);
            }

        }

        /*
         * Initialise the memory for caching m1 and its keys
         */
         gmap_agent->radio_list[i]->wsc_data = (lib1905_wscTLV_t*) calloc(1, sizeof(lib1905_wscTLV_t));
         if(gmap_agent->radio_list[i]->wsc_data == NULL) {
             platform_log(MAP_AGENT,LOG_ERR, "%s calloc for wsc_data failed\n", __func__);
             return -EINVAL;
         }
    }

    if (NULL != map_agent_frontahul_list)
        update_interface_type(map_agent_frontahul_list, MAP_FRONTHAUL_BSS);

    if (NULL != map_agent_backhaul_list)
        update_interface_type(map_agent_backhaul_list, MAP_BACKHAUL_BSS);

    return 0;
}


int load_multiap_data()
{
    int ret = 0;
    ret = map_update_radio_config();
    if (ret < 0) {
	 platform_log(MAP_AGENT,LOG_ERR,"map_update_radio_config failed");
         return -EINVAL;
    }
    return 0;
}

int ipc_1905_connect()
{
    int ret;

    lib1905_shutdown(&handle_1905);

    ret = lib1905_connect(&handle_1905, &pltfrm_config.al_fd, MULTIAP_AGENT_MODE);
    while (ret < 0) {
       platform_log(MAP_AGENT,LOG_ERR,"lib1905 connect failed, Retrying..........");
       sleep(2);
       ret = lib1905_connect(&handle_1905, &pltfrm_config.al_fd, MULTIAP_AGENT_MODE);
    }

    return 0;
}

int map_apply_msg_filter (handle_1905_t handle)
{
    int index = 0, count = 0, ret = 0;
    message_filter_t message_filter;

    message_filter.length = 0;
    message_filter.error_cb = NULL;

    for ( index = 0; index< ARRAY_LEN(gmap_cb_config, map_cb_config_t); index ++) {

        message_filter.mf[count].message_type = gmap_cb_config[index].recv_msg_type;

        //##FIXME: Need to add a ack require field in 
        //## map_cb_config_t global data structure
        platform_log(MAP_AGENT,LOG_DEBUG,"%s:%d registeration of 1905 msg_type %d", __func__, __LINE__, 
                                                             message_filter.mf[count].message_type);
        message_filter.mf[count].ack_required = 0;
        message_filter.mf[count].lib1905_cb = map_read_cb;
        message_filter.mf[count].context = NULL;
        count++;
    }
    message_filter.length = count;
    ret = lib1905_register(handle_1905, &message_filter);
    if (ret < 0) {
        platform_log(MAP_AGENT,LOG_ERR,"%s:%d registeration of 1905 msg_type "
                     "failed", __func__, __LINE__);
        return -EINVAL;
    }
    return 0;
}

int find_gmap_cb_index(uint16_t msg_type)
{
    int index = 0;
    for ( index = 0; index < ARRAY_LEN(gmap_cb_config, map_cb_config_t); index ++ ) {
       if (gmap_cb_config[index].recv_msg_type == msg_type)
           break; 
    }

    if ( index >= ARRAY_LEN(gmap_cb_config, map_cb_config_t) ) {
        return -EINVAL;
    }
    return index;
}

int is_1905ack(struct CMDU *cmdu)
{
    return (cmdu->message_type == CMDU_TYPE_MAP_ACK); 
}

int find_gmap_cb_index_from_send_msgtype(uint16_t msg_type)
{
    int index = 0;
    for ( index = 0; index < ARRAY_LEN(gmap_cb_config, map_cb_config_t); index ++ ) {
       if (gmap_cb_config[index].send_msg_type == msg_type)
           break; 
    }

    if ( index >= ARRAY_LEN(gmap_cb_config, map_cb_config_t) ) {
        return -EINVAL;
    }
    return index;
}

int map_datagather_and_send(uint8_t *src_mac_addr, uint8_t *src_iface_name, int index, struct CMDU *cmdu)
{
    wq_pool* p_work_pool  = NULL;
    wq_args* p_args       = NULL;

    if (gmap_cb_config[index].data_gathering == NULL) {
        /*
         * Some payload does not require data_gathering, 
         * but requires send success.
         */
        int        status =  0;
        uv_work_t  req    = {0};
        wq_args    w_args = {0};

        map_handle_t map_handle = {0};

        if(gmap_cb_config[index].send_cb == NULL) {
            if (NULL != cmdu)
                lib1905_cmdu_cleanup(cmdu);
            return 0;
        }

        memcpy (map_handle.dest_addr, src_mac_addr, MAC_ADDR_LEN);
        map_handle.handle_1905   = handle_1905;
        memcpy(map_handle.src_iface_name, src_iface_name, MAX_IFACE_NAME_LEN);
        map_handle.recv_cmdu = cmdu; 
                
        w_args.wqdata    = (void*)&map_handle;
        req.data         = (void*)&w_args;

        gmap_cb_config[index].send_cb(&req, status);

        return 0;
    }

    p_work_pool= get_workqueue_handle();

    if(!p_work_pool) {
        platform_log(MAP_AGENT,LOG_CRIT,"No Work Queue Available ");
        if (cmdu != NULL)
            lib1905_cmdu_cleanup(cmdu);
        return -EINVAL;
    } else {
        p_args=(wq_args*)(&p_work_pool->args);
    }

    p_args->wqdata          = (void*)cmdu;
    p_work_pool->workq.data = (void*)p_args;

    uv_queue_work( loop, ((uv_work_t*)&p_work_pool->workq), 
            gmap_cb_config[index].data_gathering, gmap_cb_config[index].send_cb);

    return 0;

}

int map_read_cb (uint8_t *src_mac_addr, struct CMDU *cmdu, 
                           void *context) {

    int ret   = 0;
    int index = 0;
    uint16_t send_msg_type = 0;
    time_t curtime;

    if (NULL == cmdu)
    {
        platform_log(MAP_AGENT,LOG_ERR,"CMDU Malformed structure.");
        return -1;
    }

    time(&curtime);
    platform_log(MAP_AGENT,LOG_DEBUG, "\nIn func %s:%d, TIME[%s] Received on [%s] mid 0x%x, type %d\n", __func__, __LINE__, ctime(&curtime), cmdu->interface_name, cmdu->message_id, cmdu->message_type);

    if(is_1905ack(cmdu)) {
        /* 
         * If it is Ack message,
         * 1) get the send msg type, to find index point to gmap_cb
         * 2) validate ack using validate_cb from gmap_cb
         * 3) Return success, nothing to do if Ack validation failes.
         */
         if (map_get_send_msgtype(cmdu, &send_msg_type) < 0) {
             return 0;
         }

         platform_log(MAP_AGENT,LOG_DEBUG, "In func %s:%d send msg_type %d \n\n", __func__, __LINE__, send_msg_type);
         index = find_gmap_cb_index_from_send_msgtype(send_msg_type);
         if( index < 0 )
         {
             platform_log(MAP_AGENT,LOG_ERR, "%s %d, msg type %d, not registered in gmap_cb_config"
                                   , __func__, __LINE__, cmdu->message_type);
             lib1905_cmdu_cleanup(cmdu);
             return -EINVAL;
         }


         if ( gmap_cb_config[index].validation_cb != NULL ) {
             ret = gmap_cb_config[index].validation_cb(src_mac_addr,
                                                               cmdu, context);
             if (ret < 0) {
                 platform_log(MAP_AGENT,LOG_ERR, "%s %d, validation failed for "
                                       "msg_type %d", __func__, __LINE__,
                                       cmdu->message_type);
                 lib1905_cmdu_cleanup(cmdu);
                 return -EINVAL;
             }
         }

        update_retry_timer (cmdu->message_id, cmdu->message_type, CHECK_MID);
        return 0;
    }

    index = find_gmap_cb_index(cmdu->message_type);
    if( index < 0 )
    {
        platform_log(MAP_AGENT,LOG_ERR, "msg type %d, not registered in gmap_cb_config"
                                  , cmdu->message_type);
        lib1905_cmdu_cleanup(cmdu);
        return -EINVAL;
    }

    //## Validate the payload
    if ( gmap_cb_config[index].validation_cb != NULL ) {
        ret = gmap_cb_config[index].validation_cb(src_mac_addr,
                                                          cmdu, context);
        if (ret < 0) {
            platform_log(MAP_AGENT,LOG_ERR, "validation failed for "
                                  "msg_type %d", cmdu->message_type);
            lib1905_cmdu_cleanup(cmdu);
            return -EINVAL;
        }
    }

    map_datagather_and_send(src_mac_addr, (uint8_t *)cmdu->interface_name, index, cmdu);

    return 0;

}

int map_ap_metrics_query_validation (uint8_t *src_mac_addr, 
                                   struct CMDU *cmdu, void *context) 
{
    uint8_t *p    = NULL;
    uint8_t index = 0;
    uint8_t no_of_ap_metrics = 0;
    uint8_t *ap_metrics_tlv  = NULL;
    struct mapApMetricsQueryTLV *ap_metrics_query = NULL;

    if ((NULL == cmdu) || (NULL == cmdu->list_of_TLVs))
    {
        platform_log(MAP_AGENT,LOG_ERR,"AP metrics Query Malformed structure.");
        return -EINVAL;
    }

    while((p = cmdu->list_of_TLVs[index]) != NULL) {
       if(*p == TLV_TYPE_AP_METRICS_QUERY) {
           ap_metrics_tlv = p;
           no_of_ap_metrics++;
       }
       index++;
    }
    if ((no_of_ap_metrics != 1) && (index != 1)) {
        platform_log(MAP_AGENT,LOG_ERR, "AP metrics query validation failed\n");
        return -EINVAL;
    }
    ap_metrics_query = (struct mapApMetricsQueryTLV*)ap_metrics_tlv;

    if (NULL == ap_metrics_query){
        platform_log(MAP_AGENT,LOG_ERR, "Ap metrics query is NULL\n");
        return -EINVAL;
    }

    if(!ap_metrics_query->numBss) {
        platform_log(MAP_AGENT,LOG_ERR, "num of bss is 0 in ap metrics query\n");
        return -EINVAL;
    }

    return 0;
}


int map_autoconfig_response_validation (uint8_t *src_mac_addr, 
                                      struct CMDU *cmdu, void *context)
{
    //## FIXME: do proper MID validation
    uint8_t *p;
    uint8_t len = 0;
    uint8_t i   = 0;
    uint8_t supported_role_present    = 0;
    uint8_t freq_band_present         = 0;
    uint8_t supported_service_present = 0;
    uint16_t *radio_state             = NULL;

    struct supportedRoleTLV     *supported_role_tlv      = NULL;
    struct supportedFreqBandTLV *supported_freq_band_tlv = NULL;

    if ((NULL == cmdu) || (NULL == cmdu->list_of_TLVs))
    {
        platform_log(MAP_AGENT,LOG_ERR,"Client Capability Query Malformed structure.");
        return -1;
    }

    while (NULL != (p = cmdu->list_of_TLVs[i]))
    {
        switch (*p)
        {
            case TLV_TYPE_SUPPORTED_ROLE:
            {
                supported_role_present = 1;
                supported_role_tlv = (struct supportedRoleTLV *)p;

                if (supported_role_tlv->role != IEEE80211_ROLE_AP) {
                    platform_log(MAP_AGENT,LOG_ERR, "Supported role is not registrar\n");
                    return -1;
                }
                break;
            }
            case TLV_TYPE_SUPPORTED_FREQ_BAND:
            {
                freq_band_present = 1;
                supported_freq_band_tlv = (struct supportedFreqBandTLV *)p;
                break;
            }
            case TLV_TYPE_SUPPORTED_SERVICE:
            {
                supported_service_present = 1;
                break;
            }
            default:
            {
                platform_log(MAP_AGENT,LOG_ERR,"UNEXPECTED TLV INSIDE CMDU");
                return -1;
            }
        }
        i++;
    }

    if ((1 != supported_role_present) || (1 != freq_band_present) || (1 != supported_service_present))
    {
        platform_log(MAP_AGENT,LOG_ERR,"\nExpected TLVs missing\n");
        return -1;
    }

    for (i = 0; i < gmap_agent->num_radios; i++)
    {
        radio_state = &gmap_agent->radio_list[i]->state;
        if (NULL == radio_state) {
            platform_log(MAP_AGENT,LOG_ERR,"map_radio_state is NULL");
            return -1;
        }

        if(gmap_agent->radio_list[i]->radio_caps.type == supported_freq_band_tlv->freq_band)
        {
            if (1 == is_radio_on(*radio_state))
            {
                if (0 == is_radio_freq_supported(*radio_state))
                {
                    set_radio_state_freq_supported(radio_state);
                }
            }
        }
    }

    memcpy(gmap_agent->iface_mac, src_mac_addr, MAC_ADDR_LEN);
    strncpy(gmap_agent->iface_name, cmdu->interface_name, MAX_IFACE_NAME_LEN);
    len = strnlen(cmdu->interface_name, MAX_IFACE_NAME_LEN);
    gmap_agent->iface_name[len] = '\0';

    platform_set(MAP_PLATFORM_SET_CONTROLLER_INTERFACE_LINK,(void *)gmap_agent->iface_name);

    update_retry_timer (cmdu->message_id, cmdu->message_type, CHECK_MID); 

    return 0; 
}

int map_free_cached_m1(map_radio_info_t *radio_node)
{
    struct  wscKey    *k        = NULL;
    lib1905_wscTLV_t  *wsc_data = NULL;

    if (NULL == radio_node)
        return -1;

    wsc_data = (lib1905_wscTLV_t  *)radio_node->wsc_data;

    if(NULL != wsc_data) {
        k = (struct  wscKey *)wsc_data->wsc_key;

        if(k != NULL) {
            if (k->key) {
                free(k->key);
            }
            wsc_data->wsc_key->key = NULL;
        }

        free(k);
        wsc_data->wsc_key = NULL;

        free(wsc_data->m1.wsc_frame);
        wsc_data->m1.wsc_frame = NULL;
    }

    return 0;
}

int map_unconfigure_all_bss(map_radio_info_t *radio_node)
{
    map_bss_info_t *bss   = NULL;
    int       index = 0;

    platform_log(MAP_AGENT,LOG_DEBUG, "[MAP]: %s %d\n\n",__func__, __LINE__);

    if (NULL == radio_node) {
        platform_log(MAP_AGENT,LOG_ERR,"radio node is NULL");
        return -1;
    }

    for (index = 0; index <radio_node->num_bss; index++) {
        bss = radio_node->bss_list[index];
        set_bss_state_unconfigured(&bss->state);
    }
   return 0;
}

int map_fill_wsc_interface_data (map_radio_info_t *radio_node, wsc_m2_data *wd)
{
    int i   = 0;
    int len = 0;
    map_bss_info_t *bss_node = NULL;

    if ((NULL == radio_node) || (NULL == wd)) {
        platform_log(MAP_AGENT,LOG_ERR, "Input params validation failure for map_fill_wsc_interface_data");
        return -1;
    }

    wd->iface_count = radio_node->num_bss;

    for (i = 0; i < wd->iface_count; i++) {
        bss_node = radio_node->bss_list[i];

        if (NULL == bss_node) {
            platform_log(MAP_AGENT,LOG_ERR, "Bss data is NULL");
            return -1;
        }
        
        
        if(bss_node->supported_sec_modes == NULL)
        {
            platform_log(MAP_AGENT,LOG_ERR, "Supported security Modes data is NULL");
            return -1;
        }
        else
        {
            wd->iface_list[i].supported_security_modes=bss_node->supported_sec_modes;
            memcpy(wd->iface_list[i].bssid, bss_node->bssid, MAC_ADDR_LEN);
            strncpy(wd->iface_list[i].iface_name, bss_node->iface_name, MAX_IFACE_NAME_LEN);
            len = strnlen(wd->iface_list[i].iface_name, MAX_IFACE_NAME_LEN);
            wd->iface_list[i].iface_name[len] = '\0';

            wd->iface_list[i].state = bss_node->state;
            if(bss_node->type == MAP_FRONTHAUL_BSS)
                set_bss_state_fronthaul(&(wd->iface_list[i].state));
            else if(bss_node->type == MAP_BACKHAUL_BSS)
                set_bss_state_backhaul(&(wd->iface_list[i].state));
        }
    }

    return 0;
}

int map_update_bss_config_state (map_radio_info_t *radio_node, wsc_m2_data *wd)
{
    int i = 0;
    int ssid_len = 0;
    map_bss_info_t *bss_node = NULL;
    map_monitor_cmd_t cmd;
    if ((NULL == radio_node) || (NULL == wd)) {
        platform_log(MAP_AGENT,LOG_ERR, "Input params validation failure for map_update_bss_config_state");
        return -1;
    }
    for (i = 0; i < wd->iface_count; i++) {
        bss_node = get_bss(wd->iface_list[i].bssid);

        if (NULL == bss_node) {
            platform_log(MAP_AGENT,LOG_ERR, "bss_node is NULL for interface %s", wd->iface_list[i].iface_name);
            continue;
        }

        if (MAP_BSS_CONFIGURED == (wd->iface_list[i].state & MAP_BSS_CONFIGURED)) {
            set_bss_state_configured(&bss_node->state);

            strncpy((char *)bss_node->ssid, (char *)wd->iface_list[i].ssid, MAX_SSID_LEN);
            ssid_len           = strnlen((char *)bss_node->ssid, MAX_SSID_LEN);
            bss_node->ssid_len = ssid_len;
            bss_node->ssid[ssid_len] = '\0';

            if ( (MAP_BACKHAUL_BSS == (wd->iface_list[i].state & MAP_BACKHAUL_BSS) ) && (MAP_FRONTHAUL_BSS != (wd->iface_list[i].state & MAP_FRONTHAUL_BSS)) && (is_bss_wps_supported(bss_node->state)))
            {
                set_bss_state_wps_unsupported(&bss_node->state);
                platform_log(MAP_AGENT,LOG_DEBUG, " Updated data model for backhaul bss wps state as %d \n", is_bss_wps_supported(bss_node->state));
            }

        }
       else if(MAP_RADIO_TEARDOWN_BIT == (wd->iface_list[i].state & MAP_RADIO_TEARDOWN_BIT)){
          cmd.cmd    = MAP_MONITOR_SEND_UBUS_DATA_CMD;
          cmd.subcmd = MAP_MONITOR_OFF_RADIO_SUB_CMD;
          cmd.param  = (void *) wd->iface_list[i].iface_name;
          if(!map_set_radio_state_off(radio_node))
          {
              platform_log(MAP_AGENT,LOG_ERR, "%s Changing state of radio in data structure failed\n", __FUNCTION__);
          }
          if(0 != map_monitor_send_cmd(cmd)) {
            platform_log(MAP_AGENT,LOG_ERR, "%s send command to publish methods failed\n", __FUNCTION__);
          }
          set_bss_state_unconfigured(&bss_node->state);
        }
        else if((MAP_BSS_TEARDOWN_BIT == (wd->iface_list[i].state & MAP_BSS_TEARDOWN_BIT)) || (!(is_bss_configured(bss_node->state)))){
          cmd.cmd    = MAP_MONITOR_SEND_UBUS_DATA_CMD;
          cmd.subcmd = MAP_MONITOR_OFF_BSS_SUB_CMD;
          cmd.param  = (void *) wd->iface_list[i].iface_name;
          set_bss_state_off(&bss_node->state);
          if(0 != map_monitor_send_cmd(cmd)) {
            platform_log(MAP_AGENT,LOG_ERR, "%s send command to publish methods failed\n", __FUNCTION__);
          }
          set_bss_state_unconfigured(&bss_node->state);
        }
    }
    return 0;
}

int map_wsc_m2_validation (uint8_t *src_mac_addr, 
                                      struct CMDU *cmdu, void *context)
{
    uint8_t                 *tlv         = NULL;
    int                     index        = 0;
    int                     i            = 0;
    int                     j            = 0;
    int                     idx          = 0;
    int                     flag         = 0;
    struct  wscTLV          *M2          = NULL;
    struct  mapApRadioIdTLV *radioId_tlv = NULL;
    lib1905_wscTLV_t        *wsc_data    = NULL;
    uint16_t                *radio_state = NULL;
    map_radio_info_t        *radio_node  = NULL;

    /*
     * Get TLV_TYPE_AP_RADIO_IDENTIFIER Tlv from CMDU
     */

    if ((NULL == cmdu) || (NULL == cmdu->list_of_TLVs)) {
        platform_log(MAP_AGENT,LOG_ERR,"%s :%d CMDU is NULL",__func__, __LINE__);
        return -EINVAL;
    }

    radioId_tlv = (struct mapApRadioIdTLV *)map_get_tlv_from_cmdu (cmdu, TLV_TYPE_AP_RADIO_IDENTIFIER);
    if (radioId_tlv == NULL ) {
        platform_log(MAP_AGENT,LOG_ERR,"%s :%d AP radio Id is missing is NULL",__func__, __LINE__);
        return -EINVAL;
    }

    for (i = 0; i < gmap_agent->num_radios; i++)
    {
        radio_state = &gmap_agent->radio_list[i]->state;
        if (NULL == radio_state) {
            platform_log(MAP_AGENT,LOG_ERR,"map_radio_state is NULL");
            return -EINVAL;
        }

        if (0 == memcmp(radioId_tlv->radioId, gmap_agent->radio_list[i]->radio_id, MAC_ADDR_LEN))
        {
            if (0 == is_radio_freq_unsupported_by_ctrl(*radio_state))
            {
                if ((1 == is_radio_on(*radio_state)) && (1 == is_radio_freq_supported(*radio_state)) &&
                    (1 == is_radio_M1_sent(*radio_state)))
                {
                    break;
                }
            }
        }
    }

    if(i >= gmap_agent->num_radios) {
        platform_log(MAP_AGENT,LOG_ERR,"%s :%d Radio Id not found",__func__, __LINE__);
        return -EINVAL;
    }

    /*
     * Get WSC Tlv from CMDU
     */
    tlv = map_get_tlv_from_cmdu (cmdu, TLV_TYPE_WSC);
    if (tlv == NULL ) {
        platform_log(MAP_AGENT,LOG_ERR,"%s :%d M2 is missing is NULL",__func__, __LINE__);
        return -EINVAL;
    }

	radio_node = get_radio(radioId_tlv->radioId); 
	if(radio_node == NULL) {
        platform_log(MAP_AGENT,LOG_ERR,"%s :%d the radio Id is not present in global struct\n",__func__, __LINE__);
        return -EINVAL;
   }

    wsc_data = (lib1905_wscTLV_t *)radio_node->wsc_data;
    if(wsc_data == NULL) {
        platform_log(MAP_AGENT,LOG_ERR,"%s :%d wsc_data is NULL\n",__func__, __LINE__);
        return -EINVAL;
    }

    /*
     * We will skip MID check in Retry module.
     * Since WSC messages will have unique MID for each messages,
     * it is hopeless to check MID for WSC in Retry.
     */

    if(update_retry_timer (cmdu->message_id, cmdu->message_type, SKIP_MID_CHECK) < 0) {
        platform_log(MAP_AGENT,LOG_ERR,"%s :%d M1 retry failed \n",__func__, __LINE__);
        return -EINVAL;
    }

    if(wsc_data->m1.wsc_frame == NULL) {
        platform_log(MAP_AGENT,LOG_ERR,"%s :%d m1 wsc_frame is NULL\n",__func__, __LINE__);
        goto Cleanup;
    }

    map_unconfigure_all_bss(radio_node);
    if( -1 == map_fill_wsc_interface_data(radio_node, &wsc_data->wd)) {
        platform_log(MAP_AGENT,LOG_ERR,"%s :%d map_fill_wsc_interface_data failed\n",__func__, __LINE__);
        goto Cleanup;
    }

    /* set SSID and PASSWD for each BSSID */
    while (NULL != (tlv = cmdu->list_of_TLVs[index])) {

        if (tlv[0] == TLV_TYPE_WSC) {

            M2 = (struct wscTLV*)tlv;
            wsc_data->m2.tlv_type       = M2->tlv_type;
            wsc_data->m2.wsc_frame_size = M2->wsc_frame_size;
            wsc_data->m2.wsc_frame      = M2->wsc_frame;

            if(lib1905_set(handle_1905, SET_1905_WSCM2TLV, 1, wsc_data)) {
                /* Skip and continue let onboarding happens for other bss*/
                platform_log(MAP_AGENT,LOG_ERR,"%s :%d M2 set failure\n",__func__, __LINE__);
            }
            for (idx = 0; idx < wsc_data->wd.iface_count; idx++) {
                if(MAP_RADIO_TEARDOWN_BIT == (wsc_data->wd.iface_list[idx].state & MAP_RADIO_TEARDOWN_BIT))
                {
                    flag =1;
                }
            }
            if(flag)
                break;
        }
        index++;
    }

    if (-1 == map_update_bss_config_state(radio_node, &wsc_data->wd)) {
        platform_log(MAP_AGENT,LOG_ERR,"%s :%d map_update_bss_config_state failed\n",__func__, __LINE__);
        goto Cleanup;
    }
 
    if((i >= 0) && (i < gmap_agent->num_radios))
        set_radio_state_configured(radio_state);

    map_free_cached_m1(radio_node);

    if (i == (gmap_agent->num_radios-1)) { // At last radio M2 validation,Check if any of radios are unsupported by ctrl. If so, make it as Supported for one more try.
        for (j = 0; j < gmap_agent->num_radios; j++)
        {
            radio_state = &gmap_agent->radio_list[j]->state;
            if (NULL == radio_state) {
                platform_log(MAP_AGENT,LOG_ERR,"map_radio_state is NULL");
                return -EINVAL;
            }
            if (1 == is_radio_freq_unsupported_by_ctrl(*radio_state))
                set_radio_state_freq_supported_by_ctrl(radio_state);
        }
    }
    map_configure_radios();

    return 0;

Cleanup:
    /* Leak Detection Fix */
    map_free_cached_m1(radio_node);
    return -EINVAL;
}

int map_autoconfig_renew_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context)
{
    //## FIXME: do proper MID validation of autoconfig_renew
    int     i;
    uint16_t *radio_state = NULL;
    struct  supportedFreqBandTLV *supported_freqband_tlv = {0};
    struct  alMacAddressTypeTLV  *al_mac_address_tlv     = {0};
    struct  supportedRoleTLV     *supported_role_tlv     = {0};

    if ((NULL == cmdu) || (NULL == cmdu->list_of_TLVs))
    {
        platform_log(MAP_AGENT,LOG_CRIT,"Autoconfiguration Renew Malformed structure.");
        return -1;
    }

    al_mac_address_tlv = (struct  alMacAddressTypeTLV *) map_get_tlv_from_cmdu(cmdu,TLV_TYPE_AL_MAC_ADDRESS_TYPE);
    if(al_mac_address_tlv == NULL)
    {
         platform_log(MAP_AGENT,LOG_ERR, "No Al Mac Address Tlv in Renew message");
         return -1;
    }

    supported_role_tlv = (struct  supportedRoleTLV *) map_get_tlv_from_cmdu(cmdu,TLV_TYPE_SUPPORTED_ROLE);
    if(supported_role_tlv == NULL)
    {
         platform_log(MAP_AGENT,LOG_ERR, "No Supported Role Tlv in Renew messae");
         return -1;
    }

    supported_freqband_tlv = (struct  supportedFreqBandTLV *) map_get_tlv_from_cmdu(cmdu,TLV_TYPE_SUPPORTED_FREQ_BAND);
    if(supported_freqband_tlv == NULL)
    {
        platform_log(MAP_AGENT,LOG_ERR, "No Frequency Band Tlv in Renew message");
        return -1;
    }

    // Irrespective of the frequency band received, M1 shall be sent for all the radios
    // as per section 7.1 in the Multiap specification.
    for (i = 0; i < gmap_agent->num_radios; i++)
    {
        radio_state = &gmap_agent->radio_list[i]->state;
        if (NULL == radio_state) {
            platform_log(MAP_AGENT,LOG_ERR,"map_radio_state is NULL");
            return -1;
        }

        if (0 == is_radio_freq_unsupported_by_ctrl(*radio_state))
        {
            if ((1 == is_radio_on(*radio_state)) && (1 == is_radio_freq_supported(*radio_state)))
            {
                set_radio_state_unconfigured(radio_state);
            }
        }
 	else
	    set_radio_state_freq_supported_by_ctrl(radio_state);
    }

    map_configure_radios();

    return 0;
}


int map_beacon_metrics_query_validation(uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context) {
       uint8_t *p    = NULL;
       uint8_t index = 0;
       uint8_t no_of_beacon_query_tlv = 0;
       uint8_t *beacon_query  = NULL;

       struct mapBeaconMetricsQueryTLV     *beacon_query_tlv  =  NULL;

       if ((NULL == cmdu) || (NULL == cmdu->list_of_TLVs))
       {
           platform_log(MAP_AGENT,LOG_CRIT,"Beacon Metrics Query Malformed structure.");
           return -EINVAL;
       }

        /*
         * get beacon metrics query from cmdu
         */
       while((p = cmdu->list_of_TLVs[index]) != NULL) {
           if(*p == TLV_TYPE_BEACON_METRICS_QUERY) {
               beacon_query = p;
               no_of_beacon_query_tlv++;
           }
           index++;
        }

        if ((no_of_beacon_query_tlv != 1) && (index != 1)) {
            platform_log(MAP_AGENT,LOG_ERR, "beacon metrics query validation failed\n");
            return -EINVAL;
        }

       beacon_query_tlv = (struct mapBeaconMetricsQueryTLV *)beacon_query;
        /*
         * Validate beacon metrics cmdu
         */
        if(beacon_query_tlv->sta_mac == NULL) {
            platform_log(MAP_AGENT,LOG_ERR, "Malformed packet\n");
            return -EINVAL;
        }
       return 0;
}


int map_client_capability_query_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context)
{
    struct mapClientInfoTLV *client_info_tlv = NULL;

    if ((NULL == cmdu) || (NULL == cmdu->list_of_TLVs))
    {
        platform_log(MAP_AGENT,LOG_CRIT,"Client Capability Query Malformed structure.");
        return -1;
    }

    client_info_tlv = (struct mapClientInfoTLV *) map_get_tlv_from_cmdu(cmdu,TLV_TYPE_CLIENT_INFO);
    if(client_info_tlv == NULL)
    {
        platform_log(MAP_AGENT,LOG_ERR, "No Client Info Tlv in CLient Capability Query message");
        return -1;
    }

    return 0;
}

int map_client_capability_report_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context)
{
    // Do proper validation
    return 0;
}

int map_client_association_control_request_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context)
{
    /* TODO: proper MID validation */
    struct mapClientAsociationControlRequestTLV *client_assoc_req_tlv = NULL;

    if ((NULL == cmdu) || (NULL == cmdu->list_of_TLVs))
    {
        platform_log(MAP_AGENT,LOG_ERR,"Client Association Control Request Malformed structure.");
        return -1;
    }

    client_assoc_req_tlv = (struct mapClientAsociationControlRequestTLV *) map_get_tlv_from_cmdu(cmdu,TLV_TYPE_CLIENT_ASSOCIATION_CONTROL_REQUEST);
    if(NULL == client_assoc_req_tlv)
    {
         platform_log(MAP_AGENT,LOG_ERR, "No Client Association Control Request Tlv in Client Association Control message");
         return -1;
    }

    return 0;
}

int map_associated_sta_link_metrics_query_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context)
{
    /* TODO: proper MID vallidation */
    struct mapStaMacAddressTLV *sta_mac_tlv = NULL;

    if ((NULL == cmdu) || (NULL == cmdu->list_of_TLVs))
    {
        platform_log(MAP_AGENT,LOG_CRIT,"Associated STA link metrics Query Malformed structure.");
        return -1;
    }

    sta_mac_tlv = (struct mapStaMacAddressTLV *) map_get_tlv_from_cmdu(cmdu,TLV_TYPE_STA_MAC_ADDRESS);
    if(NULL == sta_mac_tlv) {
        platform_log(MAP_AGENT,LOG_ERR, "No Client Info Tlv in Associated STA link metrics Query message");
        return -1;
    }

    return 0;
}

int find_channel_unassoc_sta_query(struct mapUnassocStaMetricsQueryTLV *unassoc_sta_met, uint8_t channel) {

    for (int i = 0; i<unassoc_sta_met->channel_list_cnt; i++) {
        if(channel == unassoc_sta_met->sta_list[i].channel) {
            return 1;
        }
    }
    return 0;
}

int map_higher_layer_data_msg_validation (uint8_t *src_mac_addr, struct CMDU *cmdu, void *context)
{
    struct mapHigherLayerDataTLV *higher_layer_data_msg = NULL;
    if (NULL == cmdu->list_of_TLVs) {
        platform_log(MAP_AGENT,LOG_CRIT, "Higher layer data message - malformed structure\n");
        return -1;
    }

    higher_layer_data_msg = (struct mapHigherLayerDataTLV *) map_get_tlv_from_cmdu(cmdu, TLV_TYPE_HIGHER_LAYER_DATA_MSG);
    if (NULL == higher_layer_data_msg) {
            platform_log(MAP_AGENT,LOG_ERR,"No valid TLV present in higher layer data CMDU\n");
            return -1;
    }

    platform_log(MAP_AGENT,LOG_DEBUG,"Higher layer data - protocol : %d, payload len - %d\n",
            higher_layer_data_msg->higher_layer_proto, higher_layer_data_msg->tlv_length-1);

    /* If necessary print payload contents here */    

    return 0;
}

int map_unassoc_sta_metrics_query_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context)
{
    struct mapUnassocStaMetricsQueryTLV *unassoc_sta_met = NULL;

    if(gmap_agent->agent_capability.ib_unassociated_sta_link_metrics_supported  == 0 && 
      gmap_agent->agent_capability.oob_unassociated_sta_link_metrics_supported == 0) {
      /* 
       * Agent doesn't support neither inband, nor outof band 
       * unassociated link metrics 
       */
        platform_log(MAP_AGENT,LOG_ERR, "Agent doesn't support neither inband, nor outof band unassociated link metrics");
        return -1;
    }

    if (NULL == cmdu->list_of_TLVs) {
        platform_log(MAP_AGENT,LOG_CRIT,"Associated STA link metrics Query Malformed structure.");
        return -1;
    }

    unassoc_sta_met = (struct mapUnassocStaMetricsQueryTLV *) map_get_tlv_from_cmdu(cmdu, TLV_TYPE_UNASSOCIATED_STA_METRICS_QUERY);
    if(NULL == unassoc_sta_met) {
        platform_log(MAP_AGENT,LOG_ERR, "No unassociated sta metrics query tlv in CMDU\n");
        return -1;
    }


    uint8_t (*sta_mac)[MAC_ADDR_LEN] = NULL;
    for (int i = 0; i<unassoc_sta_met->channel_list_cnt; i++) {
        platform_log(MAP_AGENT,LOG_DEBUG, "%s %d unassocc agent sta_count %d\n",__func__, __LINE__, unassoc_sta_met->sta_list[i].sta_count);
        sta_mac = unassoc_sta_met->sta_list[i].sta_mac;
        for(int j = 0; j< unassoc_sta_met->sta_list[i].sta_count; j++) {
            uint8_t *mac = (uint8_t *)sta_mac;
            platform_log(MAP_AGENT,LOG_DEBUG, "%s %d unassocc agent chan %d, sta_mac %2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx\n",
                                                         __func__, __LINE__, unassoc_sta_met->sta_list[i].channel,
                                                         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
           sta_mac++;
        }
    }

    /*
     * Check if device supports only ib measurement, 
     * and TLV request have oob measurement, so reject.
     */
     if ((gmap_agent->agent_capability.oob_unassociated_sta_link_metrics_supported == 0) 
      && (gmap_agent->agent_capability.ib_unassociated_sta_link_metrics_supported == 1))  {
          map_radio_info_t  *radio_node  = get_radio_for_unassoc_measurement(unassoc_sta_met);
         if (radio_node == NULL) {
            /* We must send an ACK even if we cannot process the request */
            return 0;
         }

         if (find_channel_unassoc_sta_query(unassoc_sta_met, radio_node->current_op_channel)) {
             /* There is alteast one inband measurement query */
             return 0;
         } else {
             /* The measurement request does't have any inband measurement, 
                every thing is oob channels, 
                And we only support iib, so reject 
              */
             return -EINVAL;
         }
     }

     return 0;
}

int map_topology_discovery_validation (uint8_t *src_mac_addr,struct CMDU *cmdu, void *context) {

    int8_t status = 0;
    do {
        if (NULL == cmdu->list_of_TLVs) {
            platform_log(MAP_AGENT,LOG_ERR,"Topology Discovery Malformed structure.");
            ERROR_EXIT(status)
        }
        uint8_t tlv_index        = 0;
        uint8_t al_mac_tlv_found = 0;
        uint8_t tx_mac_tlv_found = 0;

        while (NULL != cmdu->list_of_TLVs[tlv_index])
        {
            switch (*(uint8_t*)cmdu->list_of_TLVs[tlv_index])
            {
                case TLV_TYPE_AL_MAC_ADDRESS_TYPE:
                {
                    al_mac_tlv_found = 1;
                    break;
                }
                case TLV_TYPE_MAC_ADDRESS_TYPE:
                {
                    tx_mac_tlv_found = 1;
                    break;
                }
                default:
                {
                    // Skip the 1905 TLVs
                    break;
                }
            }
            ++tlv_index;
        }

        if((0 == al_mac_tlv_found) || (0 ==tx_mac_tlv_found))
            ERROR_EXIT(status)
    }
    while(0);

    return status;
}


int map_neighbour_link_met_query_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context)
{
     struct linkMetricQueryTLV * link_met_query_tlv = NULL;
     uint8_t empty_mac[MAC_ADDR_LEN] = {0};

     if (cmdu == NULL || cmdu->list_of_TLVs == NULL)
         return -EINVAL;

     link_met_query_tlv = (struct linkMetricQueryTLV *)map_get_tlv_from_cmdu(cmdu, TLV_TYPE_LINK_METRIC_QUERY);
     if(link_met_query_tlv == NULL) {
         return -EINVAL;
     }

     if(link_met_query_tlv->destination != LINK_METRIC_QUERY_TLV_ALL_NEIGHBORS &&
        link_met_query_tlv->destination != LINK_METRIC_QUERY_TLV_SPECIFIC_NEIGHBOR)
        return -EINVAL;

     if ( link_met_query_tlv->destination == LINK_METRIC_QUERY_TLV_SPECIFIC_NEIGHBOR && 
         memcmp(link_met_query_tlv->specific_neighbor, empty_mac, MAC_ADDR_LEN) == 0)
         return -EINVAL;

     if (link_met_query_tlv->link_metrics_type != LINK_METRIC_QUERY_TLV_TX_LINK_METRICS_ONLY &&
        link_met_query_tlv->link_metrics_type != LINK_METRIC_QUERY_TLV_RX_LINK_METRICS_ONLY &&
        link_met_query_tlv->link_metrics_type != LINK_METRIC_QUERY_TLV_BOTH_TX_AND_RX_LINK_METRICS)
        return -EINVAL;


     return 0;
}


int map_topology_query_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context)
{
    return 0;
}

int map_topology_response_validation (uint8_t *src_mac_addr,
                                      struct CMDU *cmdu, void *context)
{
    platform_log(MAP_AGENT,LOG_DEBUG,"Map Topology Response Validation");
    lib1905_set(handle_1905, SET_1905_TOPOLOGY_RESPONSE_CMDU, 1, cmdu);

    return 0;
}

int map_channel_pref_validation (uint8_t *src_mac_addr, 
                                      struct CMDU *cmdu, void *context)
{
    //## FIXME: do proper validation of channel_prefence query
    return 0;
}


int map_channel_select_validation(uint8_t*src_mac_addr
                                    , struct CMDU *cmdu, void *context)
{
    //## FIXME: do proper validation of channel_selection_request
    return 0;
}

int map_ack_validation (uint8_t *src_mac_addr, 
                                      struct CMDU *cmdu, void *context)
{
    //##  FIXME: do proper validation of multiap_ack
    return 0;
}

int map_client_steering_validation (uint8_t *src_mac_addr, 
                                      struct CMDU *cmdu, void *context)
{
    uint8_t *p    = NULL;
    uint8_t index = 0;
    uint8_t no_of_steering_req = 0;
    steering_request_tlv *steering_req = NULL;

    if ((NULL == cmdu) || (NULL == cmdu->list_of_TLVs))
    {
        platform_log(MAP_AGENT,LOG_CRIT,"Client Steering request Malformed structure.");
        return -1;
    }

    while((p = cmdu->list_of_TLVs[index]) != NULL) {
       if(*p == TLV_TYPE_STEERING_REQUEST) {
           steering_req = (steering_request_tlv *)p;
           no_of_steering_req++;
       }
       index++;
    }
    if ((no_of_steering_req != 1) && (NULL == steering_req)) {
        platform_log(MAP_AGENT,LOG_ERR, "steering req query validation failed\n");
        return -EINVAL;
    }

    if(((steering_req->flag & STEERING_REQUEST_MODE_BIT) == REQUEST_MODE_STEERING_MANDATE) && (!steering_req->bssid_count)) {
        platform_log(MAP_AGENT,LOG_ERR, "num of bssid is %d in steering req query",steering_req->bssid_count);
        return -EINVAL;
    }

    return 0;
}

int map_ap_policy_config_validation (uint8_t *src_mac_addr, 
                                      struct CMDU *cmdu, void *context)
{
    uint8_t *p;
    int i=0;
    steering_policy_tlv_t *steering_policy = NULL;
    metric_policy_tlv_t* metric_policy     = NULL;
    map_handle_t map_handle;

    if ((NULL == cmdu) || (NULL == cmdu->list_of_TLVs))
    {
        platform_log(MAP_AGENT,LOG_CRIT,"AP Policy config Malformed structure.");
        return -1;
    }

    while (NULL != (p = cmdu->list_of_TLVs[i])) {
        switch (*p) {
	        case TLV_TYPE_STEERING_POLICY:
	        {
	            steering_policy= (steering_policy_tlv_t*)p; 
	            dump_tlv_structure(TLV_TYPE_STEERING_POLICY,steering_policy);
				if(agent_store_policy_config(TLV_TYPE_STEERING_POLICY,steering_policy)) {
					platform_log(MAP_AGENT,LOG_ERR,"%s TLV_TYPE_STEERING_POLICY agent_store_policy_config failed\n",__FUNCTION__);
				}
	            break;
	        }

	        case TLV_TYPE_METRIC_REPORTING_POLICY:
	        {
	            metric_policy= (metric_policy_tlv_t*)p;
	            dump_tlv_structure(TLV_TYPE_METRIC_REPORTING_POLICY,metric_policy);
				if(agent_store_policy_config(TLV_TYPE_METRIC_REPORTING_POLICY,metric_policy)) {				
					platform_log(MAP_AGENT,LOG_ERR,"%s TLV_TYPE_METRIC_REPORTING_POLICY agent_store_policy_config failed\n",__FUNCTION__);
				}
		    	break;
	        }
	        default:
	        {
	            platform_log(MAP_AGENT,LOG_DEBUG,"Unexpected TLV (%d) type inside CMDU", *p);
		    	break;
	        }
        }
        i++;
    }
/* If there is need for storing this values in UCI, do the necessary action - TBD*/
/* Send the 1905 ACK message from here as itself*/
    map_handle.handle_1905 = handle_1905;
    map_handle.recv_cmdu   = cmdu;
    memcpy (map_handle.dest_addr, src_mac_addr, MAC_ADDR_LEN);
    memcpy (map_handle.src_iface_name, cmdu->interface_name, MAX_IFACE_NAME_LEN);

    map_send_1905_ack(&map_handle, NULL, 0);
    
    return 0;
}


uint8_t * map_get_tlv_from_cmdu(struct CMDU* cmdu, uint8_t type)
{
     uint8_t *p, i=0;

     if ((NULL == cmdu) || (NULL == cmdu->list_of_TLVs)) {
        platform_log(MAP_AGENT,LOG_ERR,"%s : CMDU is NULL",__func__);
        return NULL;
     }

     while (NULL != (p = cmdu->list_of_TLVs[i])) {
         if (*p == type)
             return cmdu->list_of_TLVs[i];
         i++;
     }
     return NULL;
}

/** @brief This API will return the number of TLV's of particular type found in the CMDU
 *
 *  @param Input -CMDU from which you need TLV count
 *  @param Input -type of TLV for which count is needed
 *  @return Count - 0 or higher
 */
uint8_t map_get_tlv_count_from_cmdu(struct CMDU* cmdu, uint8_t type)
{
     uint8_t *p, i=0, count =0;

     if ((NULL == cmdu) || (NULL == cmdu->list_of_TLVs)) {
        platform_log(MAP_AGENT,LOG_ERR,"%s : CMDU is NULL",__func__);
        return 0;
     }

     while (NULL != (p = cmdu->list_of_TLVs[i])) {
         if (*p == type)
             count++;
         i++;
     }
     return count;
}

void map_gather_channel_pref_report (uv_work_t * req)
{

    uint8_t  target_radio_id[MAC_ADDR_LEN] = {0};

    int      ret     = 0; 
    wq_args* p_args  = (wq_args*)req->data;

    struct CMDU *channel_pref_query = NULL; 

    channel_pref_query = (struct CMDU *)p_args->wqdata;
    if(channel_pref_query == NULL) {
       platform_log(MAP_AGENT,LOG_ERR,"%s :%d In data_gathering cmdu is NULL",__func__, __LINE__);
       free_workqueue_handle(p_args); 
       return;
    }

    ret = map_get_radioid_from_cmdu(channel_pref_query, target_radio_id);
    if (ret < 0) {
        platform_log(MAP_AGENT,LOG_ERR,"%s:%d Failed to get Target radio_id", __func__, __LINE__);
        lib1905_cmdu_cleanup(channel_pref_query);
        return;
    }


    //## At this point we dont require cmdu
    //## lets free
    lib1905_cmdu_cleanup(channel_pref_query);
    
    free_workqueue_handle(p_args); 
    p_args->wqdata=(void*)NULL;
    req->data=(void*)p_args;

    return ;
}

void map_gather_channel_select_response (uv_work_t * req)
{
    wq_args* p_args = (wq_args*)req->data;
    int      ret    = 0;

    struct CMDU * channel_selection_req = NULL;
    uint8_t target_radio_id[MAC_ADDR_LEN]          = {0};

    channel_selection_req = (struct CMDU *)p_args->wqdata;
    if ( channel_selection_req == NULL ) {
         platform_log(MAP_AGENT,LOG_ERR,"%s :%d channel_selection_req"
                                  " is null",__func__, __LINE__);
        return;
    }

    ret = map_get_radioid_from_cmdu(channel_selection_req, target_radio_id);
    if (ret < 0) {
        platform_log(MAP_AGENT,LOG_ERR,"%s:%d Failed to get Target radio_id", __func__, __LINE__);
        lib1905_cmdu_cleanup(channel_selection_req);
        return;
    }


    //## FIXME: Add further processing here
    lib1905_cmdu_cleanup(channel_selection_req);
    
    p_args->wqdata=NULL;
    req->data=(void*)p_args;
    
}

int map_is_local_steering_disallowed(uint8_t * mac)
{
    list_iterator_t iterator;
    uint8_t         *local_steer_disallowed_mac = NULL;
    int             ret = -EINVAL;

    memset(&iterator, 0, sizeof(list_iterator_t));

    bind_list_iterator(&iterator, gmap_agent->agent_policy.local_steering_macs_disallowed_list);

    while(1) {
        local_steer_disallowed_mac = (uint8_t *)get_next_list_object(&iterator);
        if(local_steer_disallowed_mac == NULL) 
            break;

        if (memcmp(local_steer_disallowed_mac, mac, MAC_ADDR_LEN) == 0) {
            ret = 0;
            break;
        }
    }
    return ret;
}

int map_is_btm_steering_disallowed(uint8_t * mac)
{
    list_iterator_t iterator;
    uint8_t         *btm_steer_disallowed_mac = NULL;
    int             ret = -EINVAL;

    memset(&iterator, 0, sizeof(list_iterator_t));

    bind_list_iterator(&iterator, gmap_agent->agent_policy.btm_steering_macs_disallowed_list);

    while(1) {
        btm_steer_disallowed_mac = (uint8_t *)get_next_list_object(&iterator);
        if(btm_steer_disallowed_mac == NULL) 
            break;

        if (memcmp(btm_steer_disallowed_mac, mac, MAC_ADDR_LEN) == 0) {
            ret = 0;
            break;
        }
    }
    return ret;
}

int is_btm_supported(uint8_t * mac)
{
	int status = 0;
	map_sta_info_t* sta = NULL;

	sta = get_sta(mac);	
    if(sta == NULL) {			
		platform_log(MAP_AGENT,LOG_ERR, "%s Invalid i/p\n", __func__);
		return -EINVAL;
    }	
	
	status = sta->sta_caps.dot11v_btm_support ? 0 : 1;
	platform_log(MAP_AGENT,LOG_DEBUG, "%s btm support status %d\n",__func__, status);

	return status;
}


int map_get_total_steering_sta(steering_request_tlv *steering_req, uint8_t steer_allowed_stas[][6], uint8_t *steer_allowed_sta_count) {

    uint8_t sta_cnt = 0;
    map_bss_info_t    *bss_node   = NULL;
    list_iterator_t   it          = {0};
    uint8_t           i           = 0;

    if(steering_req->sta_count > 0) {
        for(i = 0; i<steering_req->sta_count; i++) {
            if (get_sta(&steering_req->mac_addr[i][0]) == NULL)
                continue;

            memcpy(&steer_allowed_stas[sta_cnt][0], &steering_req->mac_addr[i][0], MAC_ADDR_LEN);
            sta_cnt++;
        }
    } else {

        /* STA steer for all the sta in the current BSSID */
        bss_node = get_bss(steering_req->bssid);
        if(bss_node == NULL) {
            platform_log(MAP_AGENT,LOG_ERR, "%s bss is not available in device\n",__func__);
            return -EINVAL;
        }

        bind_list_iterator(&it, bss_node->sta_list);
        while(it.iter != NULL) {
            uint8_t* sta_mac = (uint8_t*) get_next_list_object(&it);

            memcpy(&steer_allowed_stas[sta_cnt][0], sta_mac, MAC_ADDR_LEN);
            sta_cnt++;
        }
    }

    *steer_allowed_sta_count = sta_cnt;
    return 0;
}

int map_set_btm_request(uint8_t *tlv)
{

    struct sta_steer_params sta_steer  = {0};

    struct sta_steer_params *legacy_sta_steer_params = NULL, *btm_sta_steer_params = NULL;
    map_monitor_cmd_t                   cmd;
    steering_request_tlv    *steering_req   = (steering_request_tlv *)tlv;
    uint8_t                 legacy_cnt      = 0; 
    uint8_t                 *bssid          = NULL; 
    uint8_t                 btm_cnt         = 0, i = 0;
    uint8_t                 operating_class = 0, channel = 0;
    map_bss_info_t          *bss_node       = NULL;

#define MAX_STEER_STA_LIST_AT_INSTANCE 64
    static uint8_t          steer_allowed_stas[MAX_STEER_STA_LIST_AT_INSTANCE][MAC_ADDR_LEN];
    uint8_t                 steer_allowed_sta_count = 0;

    memset(&sta_steer, 0, sizeof(sta_steer));

    /* 
     * Filter the sta's which are not present 
     * in local steering disallowed list 
     */
    legacy_sta_steer_params = calloc(1, (steering_req->sta_count * sizeof(struct sta_params)) + sizeof(struct sta_steer_params));
    if(legacy_sta_steer_params == NULL) {
       goto cleanup;
    }

    btm_sta_steer_params = calloc(1, (steering_req->sta_count * sizeof(struct sta_params)) + sizeof(struct sta_steer_params));
    if(btm_sta_steer_params == NULL) {
       goto cleanup;
    }

    if (map_get_total_steering_sta(steering_req, steer_allowed_stas, &steer_allowed_sta_count) < 0) {
       goto cleanup;
    }

    bss_node = get_bss(steering_req->bssid);
    if(bss_node != NULL) {
        if(bss_node->btm_steer_request_sta_list == NULL) {
            bss_node->btm_steer_request_sta_list = new_array_list(eListTypeDefault);
        }
    }

    for (i = 0; i < steer_allowed_sta_count; i++) {
            if (get_sta(&steer_allowed_stas[i][0]) == NULL)
                continue;
    
            if((!(steering_req->flag & STEERING_REQUEST_MODE_BIT)) && (map_is_local_steering_disallowed(&steer_allowed_stas[i][0]) == 0))
                continue;
    
            if ((steering_req->bssid_count == 1) || 
               (steering_req->bssid_count < steer_allowed_sta_count )) {
                 bssid           = steering_req->target_bss[0].target_bssid;
                 operating_class = steering_req->target_bss[0].operating_class;
                 channel         = steering_req->target_bss[0].channel_no; 
            } else {
                 bssid           = steering_req->target_bss[i].target_bssid;
                 operating_class = steering_req->target_bss[i].operating_class;
                 channel         = steering_req->target_bss[i].channel_no; 
            }
    
         if((map_is_btm_steering_disallowed(&steer_allowed_stas[i][0])<0) 
              && (is_btm_supported(&steer_allowed_stas[i][0]) == 0)) {
                memcpy(btm_sta_steer_params->sta_info[btm_cnt].sta_mac, 
                           &steer_allowed_stas[i][0], MAC_ADDR_LEN);

                memcpy(btm_sta_steer_params->sta_info[btm_cnt].bssid, 
                                               bssid, MAC_ADDR_LEN);
    
                btm_sta_steer_params->sta_info[btm_cnt].channel         = channel;
                btm_sta_steer_params->sta_info[btm_cnt].operating_class = operating_class;
                /* cache btm steer requested stations */
                if((bss_node != NULL) && (bss_node->btm_steer_request_sta_list != NULL)) {
                    add_sta_to_list(&steer_allowed_stas[i][0],bss_node->btm_steer_request_sta_list);
                }
                btm_cnt++;
            } else {

                /*
                    FIX- [NG-183848] Mark the station as disconnected before legacy steering to apply the ACL
                */
                map_sta_info_t *sta = get_sta(&steer_allowed_stas[i][0]);
                if(sta) {
                    sta->state |= MAP_STA_STEER_IN_PROGRESS;
                    memcpy(sta->steer_target_bssid, bssid, MAC_ADDR_LEN);
                }

                memcpy(legacy_sta_steer_params->sta_info[legacy_cnt].sta_mac, &steer_allowed_stas[i][0], MAC_ADDR_LEN);

                memcpy(legacy_sta_steer_params->sta_info[legacy_cnt].bssid, bssid, MAC_ADDR_LEN);
    
                legacy_sta_steer_params->sta_info[legacy_cnt].channel         = channel;
                legacy_sta_steer_params->sta_info[legacy_cnt].operating_class = operating_class;
                legacy_cnt++;


            }
    }

    if(legacy_cnt > 0) {

		platform_log(MAP_AGENT,LOG_DEBUG, "%s btm not supported staions %d \n",__func__, legacy_cnt);
        legacy_sta_steer_params->sta_count            = legacy_cnt;
        legacy_sta_steer_params->disassociation_timer = steering_req->disassociation_timer;
        legacy_sta_steer_params->abridged_mode        = steering_req->flag & BTM_ABRIDGED_BIT;
        legacy_sta_steer_params->disassoc_imminent    = steering_req->flag & BTM_DISSOC_IMMINENT_BIT;
        
        memcpy(legacy_sta_steer_params->source_bssid, steering_req->bssid, MAC_ADDR_LEN);
       
         /* 
          * steering legacy sta
          */
         cmd.cmd    = MAP_MONITOR_SEND_UBUS_DATA_CMD;
         cmd.subcmd = MAP_MONITOR_LEGACY_STEERING_SUB_CMD;
         cmd.param  = (void *)legacy_sta_steer_params;
       
         if(0 != map_monitor_send_cmd(cmd)) {
             platform_log(MAP_AGENT,LOG_ERR, "%s send command to publish methods failed\n", __FUNCTION__);

             goto cleanup;
         }
    }
    
    if(btm_cnt > 0) {

        btm_sta_steer_params->sta_count               = btm_cnt;
        btm_sta_steer_params->disassociation_timer    = steering_req->disassociation_timer;
        btm_sta_steer_params->abridged_mode           = steering_req->flag & BTM_ABRIDGED_BIT;
        btm_sta_steer_params->disassoc_imminent       = steering_req->flag & BTM_DISSOC_IMMINENT_BIT;
        
        memcpy(btm_sta_steer_params->source_bssid, steering_req->bssid, MAC_ADDR_LEN);
        
         /* 
          * steering btm supported STA
          */
         cmd.cmd    = MAP_MONITOR_SEND_UBUS_DATA_CMD;
         cmd.subcmd = MAP_MONITOR_BTM_STEERING_SUB_CMD;
         cmd.param  = (void *)btm_sta_steer_params;
       
         if(0 != map_monitor_send_cmd(cmd)) {
             if((bss_node != NULL) && (bss_node->btm_steer_request_sta_list != NULL)) {
                 for(int j = 0; j < btm_cnt; j++) {
                     remove_sta_from_list(btm_sta_steer_params->sta_info[j].sta_mac, bss_node->btm_steer_request_sta_list);
                 }
             }
             platform_log(MAP_AGENT,LOG_ERR, "%s send command to publish methods failed\n", __FUNCTION__);
             /*
              * we should not call "goto cleanup" here
              * since "legacy_sta_steer_params" memory ptr
              * has been sent to platform_abstraction
              * it shouldn't be freed here.
              * Hence return.
              */
             if(legacy_cnt <= 0)
                 free(legacy_sta_steer_params);

             free(btm_sta_steer_params);
             return -EINVAL;
         }
    }

    if ((steering_req->flag & STEERING_REQUEST_MODE_BIT) == REQUEST_MODE_STEERING_OPPORTUNITY) {

       /* 
        * check if opportunity window is valid 
        * Try to steer and send steer completion msg
        *
        */
    }

    return 0;
cleanup:

    if (NULL != legacy_sta_steer_params)
        free(legacy_sta_steer_params);

    if (NULL != btm_sta_steer_params)
        free(btm_sta_steer_params);

    return -EINVAL;
}

void map_apply_btm_request (uv_work_t * req, int status)
{
    wq_args                      *p_args =  (wq_args*)req->data;
    struct CMDU         *sta_steer_query = NULL;
    steering_request_tlv  *steer_req_tlv = NULL;
    uint8_t                          ret = 0; 
    uint8_t                            i = 0;
    map_handle_t             *map_handle = NULL;
    map_sta_info_t            *sta       = NULL;
    array_list_t*            disassoc_sta_list   = NULL; /* List of STAs for which error code tlv need to be sent */

    map_handle      = (map_handle_t *)p_args->wqdata;

    if (NULL == map_handle->dest_addr || NULL == map_handle->recv_cmdu || (-1 == map_handle->handle_1905))
    {
        platform_log(MAP_AGENT,LOG_ERR,"Map Handle parameters Validation Failed");
        goto cleanup;
    }


    sta_steer_query = (struct CMDU *)map_handle->recv_cmdu;
    if ( sta_steer_query == NULL ) {
         platform_log(MAP_AGENT,LOG_ERR,"%s :%d sta_steer_query"
                                    " is null",__func__, __LINE__);
         return;
    }

    //## extract the corresponding tlv from cmdu
    steer_req_tlv = (steering_request_tlv *)map_get_tlv_from_cmdu(sta_steer_query, TLV_TYPE_STEERING_REQUEST);
    if (steer_req_tlv == NULL ) {
        platform_log(MAP_AGENT,LOG_ERR,"%s :%d failed to extract steering req tlv",
                                                        __func__, __LINE__);
       p_args->wqdata=NULL;
       goto cleanup;
    }

    p_args->wqdata=NULL;

    disassoc_sta_list = new_array_list(eListTypeDefault);
    if(!disassoc_sta_list)
    {
        platform_log(MAP_AGENT,LOG_ERR, " %s Failed to create associated sta list hashmap\n",__func__);
        goto cleanup;
    }

    for(i = 0; i<steer_req_tlv->sta_count;i++)
    {
       sta = get_sta(&steer_req_tlv->mac_addr[i][0]);

       if ((NULL == sta) || (NULL == sta->bss) ||
           (memcmp(sta->bss->bssid, steer_req_tlv->bssid, MAC_ADDR_LEN) != 0)){
           /* 
            * The control comes here meaning that the sta is either not connected
            * to our device or not connected to the specific bssid metioned in 
            * steering req.
            * Then Add STAs to the dissassoc list 
            */
           if (insert_last_object(disassoc_sta_list, &steer_req_tlv->mac_addr[i][0]) < 0)
           {
               platform_log(MAP_AGENT,LOG_ERR, "Unable to add station to block sta list");
               goto cleanup;
           }
       }
    }

    /* send ack */
   if (map_send_1905_ack(map_handle, disassoc_sta_list, STA_UNASSOCIATED) < 0) {
       goto cleanup;
   }
    
   if ((steer_req_tlv->flag & STEERING_REQUEST_MODE_BIT) == REQUEST_MODE_STEERING_OPPORTUNITY) {
       /* 
        * check if opportunity window is valid 
        * Try to steer and send steer completion msg
        *
        */
        platform_log(MAP_AGENT,LOG_DEBUG, "%s: %d: Steering opportunity request received", __FUNCTION__, __LINE__);
        map_agent_send_steering_complete(map_handle);
   } else {
       //## set the stering UBUS command
       ret = map_set_btm_request((uint8_t *)steer_req_tlv);
       if (ret < 0)
       {
           p_args->wqdata=NULL;
           goto cleanup;
       }
   }

cleanup:

    if(disassoc_sta_list != NULL ) {
       while(remove_last_object(disassoc_sta_list) != NULL);
       delete_array_list(disassoc_sta_list);
    }

    if(sta_steer_query != NULL)
        lib1905_cmdu_cleanup(sta_steer_query);
}

void map_configure_radios()
{
    int  i = 0;
    uint8_t freq = 0;
    uint16_t *radio_state   = NULL;
    map_handle_t map_handle = {0};

    for (i = 0; i < gmap_agent->num_radios; i++)
    {
        radio_state = &gmap_agent->radio_list[i]->state;
        freq = gmap_agent->radio_list[i]->radio_caps.type;

        if (NULL == radio_state) {
            platform_log(MAP_AGENT,LOG_ERR,"map_radio_state is NULL");
            return;
        }

        if (0 == is_radio_freq_unsupported_by_ctrl(*radio_state))
        {
            if (1 == is_radio_on(*radio_state))
            {
                if (1 == is_radio_freq_supported(*radio_state))
                {
                    if (0 == is_radio_configured(*radio_state))
                    {
                        /* Send M1 for the radio */
                        memcpy (map_handle.dest_addr, gmap_agent->iface_mac, MAC_ADDR_LEN);
                        memcpy (map_handle.src_iface_name, gmap_agent->iface_name, MAX_IFACE_NAME_LEN);

                        map_handle.handle_1905 = handle_1905;
                        map_handle.recv_cmdu   = NULL;

                        if(map_send_wsc_m1(map_handle, (void *)i) < 0) {
                            platform_log(MAP_AGENT,LOG_ERR, "map_send_wsc_m1 failed");
                            return;
                        }
                        set_radio_state_M1_sent(radio_state);

                        return;
                    }
                }
                else
                {
                    /* Send Autoconfiguration search for this frequency Band */
                    get_mcast_macaddr(map_handle.dest_addr);
                    map_handle.handle_1905 = handle_1905;
                    map_handle.recv_cmdu   = NULL;

                   if (agent_search_retry_cnt[freq] >= MAX_RETRY_THRESHOLD) {
		       set_freq_unsupported_by_ctrl(freq); // Setting all radio with this freq band as unsupported by ctrl
		       agent_search_retry_cnt[freq] = 0;
                       continue;
                   }

                    if (map_send_autoconfig_search(map_handle, (void *)i) < 0) {
                        platform_log(MAP_AGENT,LOG_ERR, "map_send_autoconfig_search failed");
                    }

                    return;
                }
            }
        }
    }

    if ( 0 == is_ctrl_discovered()) {
        int radio_index = -1;
        for (i = 0; i < gmap_agent->num_radios; i++) {
                radio_state = &gmap_agent->radio_list[i]->state;
                set_radio_state_freq_supported_by_ctrl(radio_state);

                if (1 == is_radio_on(*radio_state) && (radio_index == -1))
                   radio_index = i;
        }

        if (map_send_autoconfig_search(map_handle, (void *)radio_index) < 0) {
                     platform_log(MAP_AGENT,LOG_ERR, "map_send_autoconfig_search failed");
        }

        return;
    }

    platform_log(MAP_AGENT,LOG_DEBUG, "All radios are configured");
    return;
}

int multiap_agent_init()
{
    /* 
     * initial bootup sequence
     */

	/* Get the agent MAC and create the agent node on the hash table */
	uint8_t	agent_mac[MAC_ADDR_LEN];
	char mac_addr[50];
        char threshold[32];

    memset(&mac_addr,0,sizeof(mac_addr));

    platform_get(MAP_PLATFORM_GET_MULTIAP_CONFIG,"agent.default_hysteresis_margin",(void *)threshold);
    pltfrm_config.map_config.default_hysteresis_margin = atoi(threshold);

    if(map_agent_env_macaddress != NULL)
    {
        strncpy(mac_addr, map_agent_env_macaddress, sizeof(mac_addr)-1);
        mac_addr[sizeof(mac_addr)-1] = '\0';
        platform_log(MAP_AGENT,LOG_DEBUG,"MAP_MACADDRESS : %s", mac_addr);

        if(!platform_get_mac_from_string(mac_addr,agent_mac)){
            platform_log(MAP_AGENT,LOG_ERR, "agent_mac failed");
            return -1;
        }

        /*Agent node created */
        gmap_agent = create_ale(agent_mac);

        if(gmap_agent == NULL){
            platform_log(MAP_AGENT,LOG_ERR, "create_ale() failed");
            return -1;
        }

        if(init_agent_topology_tree(agent_mac) < 0)
        {
            platform_log(MAP_AGENT,LOG_ERR, "Agent Topology tree initialisation failed\n");
        }
    }
    else
    {
        platform_log(MAP_AGENT,LOG_ERR, "EMPTY MAP_MACADDRESS");
    }

    if (load_multiap_data() < 0) {
        platform_log(MAP_AGENT,LOG_ERR, "load_multiap_data() failed");
        return -1;
    }

    /* Init 1905 thread
     * This will create 1905_thread and all pcap thread per interface,
     * This will also create server socket IPCs
     */
    //ieee1905_al_init();

    if (ipc_1905_connect() < 0) {
        platform_log(MAP_AGENT,LOG_ERR, "ipc_1905_connect() failed");
        return -1;
    }

    if (map_apply_msg_filter(handle_1905) < 0) {
        platform_log(MAP_AGENT,LOG_ERR,"Initial registration failed");
        return -1;
    }

    map_configure_radios();

    return 0;
}



void uvpoll_1905read_cb (uv_poll_t* handle, int status, int events)
{
    if((status < 0) || (events & UV_DISCONNECT))
    {
        uv_poll_stop(handle);
        if (events & UV_DISCONNECT){
            if (ipc_1905_connect() < 0)
                platform_log(MAP_AGENT,LOG_ERR, "ipc_1905_connect() failed");
        }
    }
    else if (events & UV_READABLE) {
            platform_log(MAP_AGENT,LOG_DEBUG,"New message received");
            if(lib1905_read(handle_1905) < 0)
                platform_log(MAP_AGENT,LOG_ERR, "libread failure");
    }
    return;
}

static int _client_capability_query_cb (map_handle_t *map_handle, client_info_t *client_info)
{
    if (NULL == client_info) {
        platform_log(MAP_AGENT,LOG_ERR, "%s : client data is empty \n", __FUNCTION__);
        return -1;
    }

    //## Client info paramters validation
    if (NULL == client_info->bssid || NULL == client_info->client_mac || NULL == client_info->agent_mac) {
        platform_log(MAP_AGENT,LOG_DEBUG, "%s : Client info parameters are empty \n", __FUNCTION__);
        return -1;
    }

    map_handle->handle_1905 = handle_1905;
    memcpy(map_handle->dest_addr, client_info->agent_mac, MAC_ADDR_LEN);
    map_handle->recv_cmdu   = NULL;

    if(map_send_client_capability_query(map_handle, client_info->client_mac, client_info->bssid)) {
        platform_log(MAP_AGENT,LOG_ERR, "%s map_send_ap_capability_query failed\n", __FUNCTION__);
        return -1;
    }

    return 0;
}

static void print_agentinfo()
{
    print_agent_info_tree();
}

static int agent_store_policy_config(INT8U tlv_type, void * tlv_info)
{
	int ret = 0;
	steering_policy_tlv_t *steering_policy;
	metric_policy_tlv_t *metric_policy;
	uint32_t index = 0;

	platform_log(MAP_AGENT,LOG_DEBUG," %s\n", __FUNCTION__);
	
	if(tlv_info == NULL)
		return 1;

	switch(tlv_type)
	{
		/* previous steering policy and disallowed staion list is cleared every time a new steering policy config tlv is recieved */
		/* Previous list of radios for which the policy is applied is cleared as well */
		case TLV_TYPE_STEERING_POLICY:
		{
			/* todo - validate the radio macs with ap radio macs before proceeding with below logic*/
			platform_log(MAP_AGENT,LOG_DEBUG," storing info from TLV_TYPE_STEERING_POLICY %s\n", __FUNCTION__);
			steering_policy = (steering_policy_tlv_t *)tlv_info;

			/* Clear existing steering disallowed station macs in global structure */
			empty_array_list(gmap_agent->agent_policy.local_steering_macs_disallowed_list);
			empty_array_list(gmap_agent->agent_policy.btm_steering_macs_disallowed_list);

			/* Store new steering policy config from recived tlv */
			gmap_agent->agent_policy.number_of_local_steering_disallowed = steering_policy->number_of_local_steering_disallowed;
			if(gmap_agent->agent_policy.number_of_local_steering_disallowed >= 1) {
				//memcpy(gmap_agent->agent_policy.local_steering_macs, steering_policy->local_steering_macs, steering_policy->number_of_local_steering_disallowed*MAC_ADDR_LEN*sizeof(uint8_t));
				for(index = 0; index < gmap_agent->agent_policy.number_of_local_steering_disallowed; index++)
				{
					if(add_sta_to_list(steering_policy->local_steering_macs + index*MAC_ADDR_LEN,gmap_agent->agent_policy.local_steering_macs_disallowed_list) < 0)
					{
						platform_log(MAP_AGENT,LOG_ERR," %s %d Unable to add station to disallowed list\n", __FUNCTION__, __LINE__);
						break;
					}
				}

				if(index != gmap_agent->agent_policy.number_of_local_steering_disallowed)
				{
					platform_log(MAP_AGENT,LOG_ERR," %s %d Few Stations not added to local steering disallowed list\n", __FUNCTION__, __LINE__);
					ret = 1;
					break;
				}
			} else {
				platform_log(MAP_AGENT,LOG_DEBUG," %s %d No Local Steering Disallowed Stations\n", __FUNCTION__, __LINE__);
			}
			gmap_agent->agent_policy.number_of_btm_steering_disallowed = steering_policy->number_of_btm_steering_disallowed;
			if(gmap_agent->agent_policy.number_of_btm_steering_disallowed >= 1){
				//memcpy(gmap_agent->agent_policy.btm_steering_macs, steering_policy->btm_steering_macs, steering_policy->number_of_btm_steering_disallowed*MAC_ADDR_LEN*sizeof(uint8_t));
				for(index = 0; index < gmap_agent->agent_policy.number_of_btm_steering_disallowed; index++)
				{
					if(add_sta_to_list(steering_policy->btm_steering_macs+ index*MAC_ADDR_LEN,gmap_agent->agent_policy.btm_steering_macs_disallowed_list) < 0)
					{
						platform_log(MAP_AGENT,LOG_ERR," %s %d Unable to add station to disallowed list\n", __FUNCTION__, __LINE__);
						break;
					}
				}

				if(index != gmap_agent->agent_policy.number_of_btm_steering_disallowed)
				{
					platform_log(MAP_AGENT,LOG_ERR," %s %d Few Stations not added to BTM steering disallowed list\n", __FUNCTION__, __LINE__);
					ret = 1;
					break;
				}
				
			} else {
				platform_log(MAP_AGENT,LOG_DEBUG," %s %d No BTM Steering Disallowed Stations\n", __FUNCTION__, __LINE__);
			}
			if((steering_policy->number_of_radio >= 1) && (steering_policy->number_of_radio < MAX_RADIOS_PER_AGENT)) {
				/*store or update policy for radios in the recieved tlv */
				for(int i = 0; i < steering_policy->number_of_radio; i++) {
					map_radio_info_t * radio_node = get_radio(steering_policy->radio_policy[i].radioId);
					if(radio_node != NULL)
					{
						radio_node->radio_policy.steering_policy = steering_policy->radio_policy[i].steering_policy;
						radio_node->radio_policy.rssi_steering_threshold = steering_policy->radio_policy[i].rssi_steering_threshold;
						radio_node->radio_policy.channel_utilization_threshold= steering_policy->radio_policy[i].channel_utilization_threshold;
						platform_log(MAP_AGENT,LOG_DEBUG, "%s TLV_TYPE_STEERING_POLICY storing policy in %d, mac id is %x:%x:%x:%x:%x:%x\n", __FUNCTION__, i, radio_node->radio_id[0], radio_node->radio_id[1], radio_node->radio_id[2], radio_node->radio_id[3], radio_node->radio_id[4], radio_node->radio_id[5]);
						}
					}
				}				
			else {
				platform_log(MAP_AGENT,LOG_ERR," %s %d Invalid Radio Count to apply steering policy\n", __FUNCTION__, __LINE__);
				ret = 1;
			}
			break;
		}

		case TLV_TYPE_METRIC_REPORTING_POLICY:
		{
			/* todo - validate the radio macs with ap radio macs before proceeding with below logic*/
			platform_log(MAP_AGENT,LOG_DEBUG," storing info from TLV_TYPE_METRIC_REPORTING_POLICY %s\n", __FUNCTION__);
			metric_policy = (metric_policy_tlv_t *)tlv_info;

			gmap_agent->agent_policy.metric_reporting_interval = metric_policy->metric_reporting_interval;
			if((metric_policy->number_of_radio >=1) && (metric_policy->number_of_radio < MAX_RADIOS_PER_AGENT)) {
				/*store or update policy for radios in the recieved tlv */
				for(int i = 0; i < metric_policy->number_of_radio; i++) {
					map_radio_info_t * radio_node = get_radio(metric_policy->radio_policy[i].radioId);
					if(radio_node != NULL)
					{
                                                radio_node->radio_policy.report_metrics = 1;
						radio_node->radio_policy.associated_sta_policy = metric_policy->radio_policy[i].associated_sta_policy;
						radio_node->radio_policy.channel_utilization_reporting_threshold = metric_policy->radio_policy[i].channel_utilization_reporting_threshold;
						radio_node->radio_policy.reporting_rssi_threshold = metric_policy->radio_policy[i].reporting_rssi_threshold;
						radio_node->radio_policy.reporting_rssi_margin_override = metric_policy->radio_policy[i].reporting_rssi_margin_override;
						platform_log(MAP_AGENT,LOG_DEBUG, "%s TLV_TYPE_METRIC_REPORTING_POLICY storing policy in %d, mac id is %x:%x:%x:%x:%x:%x\n", __FUNCTION__, i, radio_node->radio_id[0], radio_node->radio_id[1], radio_node->radio_id[2], radio_node->radio_id[3], radio_node->radio_id[4], radio_node->radio_id[5]);
					}
				}
			} else {
				platform_log(MAP_AGENT,LOG_ERR," %s %d Invalid Radio Count to apply metric reporting policy\n", __FUNCTION__, __LINE__);
				ret = 1;
			}
			break;			
		}
		default:
		{
			ret = 1;
			platform_log(MAP_AGENT,LOG_ERR,"Not a steering/metric policy tlv %s\n", __FUNCTION__);
			break;
		}
	}

	return ret;
}

static int is_radio_channel_utilization_exceeded (map_bss_info_t* bss, uint8_t curr_channel_utilization)
{
    int channel_utilization_threshold   = 0;

    if (NULL == bss)
    {
        platform_log(MAP_AGENT,LOG_ERR, "Input validation failed for is_radio_channel_utilization_exceeded");
        return 0;
    }

    channel_utilization_threshold = bss->radio->radio_policy.channel_utilization_reporting_threshold;

    if ((channel_utilization_threshold > 0) && (curr_channel_utilization > channel_utilization_threshold))
            return 1;

    return 0;
}

static int is_station_rssi_threshold_exceeded (map_sta_info_t* sta, map_sta_metrics_t *metrics, uint8_t curr_rssi)
{
    uint8_t reporting_rssi_threshold  = 0;
    uint8_t hysteresis_margin         = 0;
    map_radio_policy_t radio_policy   = {0};

    if ((NULL == sta) || (NULL == metrics))
    {
        platform_log(MAP_AGENT,LOG_ERR, "Sta node is NULL in function %s", __func__);
        return 0;
    }

    if ((NULL == sta->bss) || (NULL == sta->bss->radio))
    {
        platform_log(MAP_AGENT,LOG_ERR, "Station's BSS/RADIO is NULL in function %s", __func__);
        return 0;
    }

    radio_policy =  sta->bss->radio->radio_policy;
    reporting_rssi_threshold = radio_policy.reporting_rssi_threshold;

    if (reporting_rssi_threshold > 0)
    {
        hysteresis_margin = (radio_policy.reporting_rssi_margin_override > 0) ? radio_policy.reporting_rssi_margin_override : pltfrm_config.map_config.default_hysteresis_margin;

        if ((curr_rssi + hysteresis_margin) < reporting_rssi_threshold)
        {
            /* The higher the RCPI values, stronger the signal strength. If it goes below the given RCPI threshold, then report */
            return 1;
        }
    }
    return 0;
}

int is_radio_present_in_list (map_radio_info_t **radio_list, map_radio_info_t *radio_node, int count)
{
    int i = 0;

    if ((NULL == radio_list) || (NULL == radio_node) || (count <= 0))
        return 0;

    for (i = 0; i < count; i++) {
        if (radio_list[i] == radio_node)
            return 1;
    }
    return 0;
}

int is_our_almac(uint8_t *al_mac) {

    if(memcmp(gmap_agent->al_mac, al_mac, MAC_ADDR_LEN) == 0)
        return 1;

    return 0;
}

int compare_remaining_time (void *node1, void *node2)
{
    if (node1 && node2)
    {
        struct timespec curr_time = get_current_time();
        acl_timeout_data_t *acl1  = (acl_timeout_data_t *)node1;
        acl_timeout_data_t *acl2  = (acl_timeout_data_t *)node2;
        uint16_t remaining_time1  = acl1->validity_period - get_clock_diff_secs(curr_time,acl1->msg_recvd_time);
        uint16_t remaining_time2  = acl2->validity_period - get_clock_diff_secs(curr_time,acl2->msg_recvd_time);

        if (remaining_time1 >= remaining_time2)
            return 1;
    }
    return 0;
}

void remove_duplicates_from_list(array_list_t *A, array_list_t *B) {
    if (A && B) {
        list_iterator_t *it =  new_list_iterator(B);
        if(it) {
            while(it->iter)
            {
                uint8_t *sta_mac = (uint8_t *) get_next_list_object(it);
                void *obj = remove_object(A, sta_mac, compare_macaddr);
                if (obj)
                    free(obj);
            }
        }
        free_list_iterator(it);
    }
    return;
}

int addto_acl_timeout_list(uint16_t mid, uint8_t *bssid, array_list_t *block_sta_list, uint16_t validity_period, struct timespec msg_recvd)
{
    acl_timeout_data_t *acl_data      = NULL;
    acl_timeout_data_t *acl_list_item = NULL;
    array_list_t       **acl_list     = NULL;
    list_iterator_t    *it            = NULL;

    if ((NULL == bssid) || (NULL == block_sta_list))
    {
        platform_log(MAP_AGENT,LOG_ERR,"%s: Input parameters validation failed",__func__);
        return -1;
    }

    acl_list = &pltfrm_config.map_config.client_acl_list;

    if (NULL == *acl_list)
    {
        *acl_list = new_array_list(eListTypeDefault);
        if (NULL == *acl_list)
        {
            platform_log(MAP_AGENT,LOG_ERR, "%s : acl_list create failed",__func__);
            return -1;
        }
    }

    acl_data = (acl_timeout_data_t *) calloc (1, sizeof(acl_timeout_data_t));
    if (NULL == acl_data)
    {
        platform_log(MAP_AGENT,LOG_ERR,"%s: acl_data calloc failed",__func__);
        return -1;
    }

    acl_data->mid = mid;
    memcpy(acl_data->bssid, bssid, MAC_ADDR_LEN);
    acl_data->sta_list = block_sta_list;
    acl_data->validity_period = validity_period;
    acl_data->msg_recvd_time = msg_recvd;

    /* First insert at the appropriate position based on expiry time */
    if (-1 == compare_and_insert(*acl_list, acl_data, compare_remaining_time))
    {
        platform_log(MAP_AGENT,LOG_ERR,"\n%s: insert failed",__func__);
        free(acl_data);
        return -1;
    }

    /* Now, we need to remove all the stations that are in the nodes before the
     * inserted node, so for each node till the inserted node is found, remove
     * stations that are present in the newly inserted list*/
    it = new_list_iterator(*acl_list);

    if(it) {
        while(it->iter)
        {
            acl_list_item = (acl_timeout_data_t *) get_next_list_object(it);

            if (NULL != acl_list_item)
            {
                if (acl_list_item->mid == mid)
                    break;

                if (0 == memcmp(acl_list_item->bssid, bssid, MAC_ADDR_LEN))
                {
                    remove_duplicates_from_list(acl_list_item->sta_list, block_sta_list);
                }
            }
        }
        free_list_iterator(it);
    }

    return 0;
}


void check_and_flush_acl_timeout()
{
    acl_timeout_data_t *acl_data  = NULL;
    array_list_t       *acl_list  = NULL;
    struct timespec     curr_time = {0};

    curr_time  = get_current_time();
    acl_list = pltfrm_config.map_config.client_acl_list;

   if (NULL == acl_list)
       return;

   acl_data = (acl_timeout_data_t *) object_at_index (acl_list, 0);
   while (acl_data)
   {
       if (acl_data->validity_period > get_clock_diff_secs(curr_time, acl_data->msg_recvd_time))
           return;
       else
       {
           acl_data = (acl_timeout_data_t *) pop_object(acl_list);
           if (acl_data)
           {
              if (-1 == map_stations_assoc_control_apply(STA_UNBLOCK, acl_data->bssid, acl_data->sta_list))
              {
                  platform_log(MAP_AGENT,LOG_ERR, "%s: map_stations_assoc_control_apply failed for mid %d",__func__,acl_data->mid);
              }
              empty_array_list(acl_data->sta_list);
              delete_array_list(acl_data->sta_list);
              free(acl_data);
           }
       }
       acl_data = (acl_timeout_data_t *) object_at_index (acl_list, 0);
   }
   return;
}

int platform_channel_pref_get(map_radio_info_t *radio_node)
{
      map_monitor_cmd_t                 cmd                = {0};
      platform_channel_pref_cmd_t       *platform_cmd      = NULL;

      platform_cmd = (platform_channel_pref_cmd_t*) malloc (sizeof(platform_channel_pref_cmd_t) + (radio_node->op_class_count * sizeof(map_op_class_t)));
      if(platform_cmd == NULL) {
          return -EINVAL;
      }

      platform_cmd->radio_type = radio_node->radio_caps.type;
      memcpy(platform_cmd->radio_name, radio_node->radio_name, sizeof(platform_cmd->radio_name)); 
      memcpy(platform_cmd->op_class_list, radio_node->op_class_list, 
                           radio_node->op_class_count * sizeof(map_op_class_t));

      platform_cmd->op_class_count = radio_node->op_class_count;

      cmd.cmd    = MAP_MONITOR_SEND_UBUS_DATA_CMD;
      cmd.subcmd = MAP_MONITOR_GET_CHANNEL_PREF_SUBCMD;
      cmd.param  = (void *)platform_cmd;
      if(0 != map_monitor_send_cmd(cmd)) {
          platform_log(MAP_AGENT,LOG_ERR, "%s send command to publish methods failed\n", __FUNCTION__);
          free(platform_cmd);
          return -EINVAL;
      }
      return 0;
}


int is_channels_equal (map_op_class_t* radio_oper_class, map_op_class_t* new_op_class) {

    int i = 0, j = 0;
    for(i = 0; i<radio_oper_class->agent_non_oper_ch_cnt; i++) {
        for (j = 0; j<new_op_class->agent_non_oper_ch_cnt; j++) {
            if (radio_oper_class->agent_non_oper_ch[i] == new_op_class->agent_non_oper_ch[j]) break;
        }

        if(j >= new_op_class->agent_non_oper_ch_cnt) return 0;
    }

    /* all channels in both the operating class are same */
    return 1;
}

int is_channel_pref_change (map_radio_info_t *radio, map_op_class_t *new_op_class_list, uint8_t new_op_class_count) {

    for(int j = 0; j<new_op_class_count; j++) {
        for (int i = 0; i <radio->op_class_count; i++) {

            if (new_op_class_list[j].op_class == radio->op_class_list[i].op_class) {

                if(radio->op_class_list[i].agent_non_oper_ch_cnt != new_op_class_list[j].agent_non_oper_ch_cnt) {    
                return 1;}
                else if ((radio->op_class_list[i].agent_non_oper_ch_cnt == new_op_class_list[j].agent_non_oper_ch_cnt))
                    if ( is_channels_equal(&radio->op_class_list[i], &new_op_class_list[j]) == 0) { 
                        return 1;
                    }
            }
        }
    }
    return 0;
}

void periodic_timer_cb (uv_timer_t *handle)
{
    uint8_t i            = 0;
    uint8_t j            = 0;
    char  *q_obj         = NULL;

    array_list_t *monitor_queue        = NULL;
    monitor_q_handle_t *monitor_q_hdle = NULL;

    monitor_q_hdle = &pltfrm_config.map_config.monitor_q_hdle;
    monitor_queue  = monitor_q_hdle->list_handle;
    if(monitor_queue != NULL) {
        while((q_obj = pop_object(monitor_queue)) != NULL) {
            switch (q_obj[0]) {
                case MAP_MONITOR_CUMULATIVE_BSS_STATS:
                {
                    cum_stats_t*     cum_bss_stats;
                    map_bss_stats_t* bss_node;
                    map_bss_stats_t* bss_list;
                    map_bss_info_t*  hash_bss_node = NULL;
                    uint8_t          ac_index = 0;
                    struct timespec  last_ap_metrics_time;
                    struct timespec  current_time;
                    uint64_t         interval = 0;
                    uint8_t          interval_s = 0;
                    int              channel_utilization_limit_exceeded = 0;
                    int              threshold_count = 0;
                    map_radio_info_t *radio_list[MAX_RADIOS_PER_AGENT] = {NULL};
                    int              send_response = 0;
                    uv_work_t        req    = {0};
                    wq_args          w_args = {0};
                    map_handle_t     map_handle;

                    cum_bss_stats = (cum_stats_t*)q_obj;

                    bss_list = (map_bss_stats_t *)cum_bss_stats->cum_stats;

                    for(i = 0; i<cum_bss_stats->stats_count; i++) {

                       bss_node = &bss_list[i];
                       hash_bss_node = get_bss(bss_node->bssid);
                       if(hash_bss_node == NULL) {
                           platform_log(MAP_AGENT,LOG_ERR, "No hash node for bssid %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
                                                                      bss_node->bssid[0], bss_node->bssid[1],
                                                                      bss_node->bssid[2], bss_node->bssid[3],
                                                                      bss_node->bssid[4], bss_node->bssid[5]);
                           continue;
                       }

                       channel_utilization_limit_exceeded = is_radio_channel_utilization_exceeded(hash_bss_node, bss_node->metrics.channel_utilization);
                       if ((1 == channel_utilization_limit_exceeded) && (0 == is_radio_present_in_list(radio_list, hash_bss_node->radio, threshold_count))) {
                           radio_list[threshold_count++] = hash_bss_node->radio;
                       }

                       hash_bss_node->metrics.channel_utilization = bss_node->metrics.channel_utilization;
                       hash_bss_node->metrics.esp_present         = bss_node->metrics.esp_present;
                       for(ac_index = 0; ac_index<MAX_ACCESS_CATEGORIES; ac_index++) {
                           if (bss_node->metrics.esp_present & (1<<(7 - ac_index))) {
                               memcpy(&hash_bss_node->metrics.esp[ac_index],
                                          &bss_node->metrics.esp[ac_index], sizeof(map_esp_info_t));
                           }
                       }
                    }

                    /*                     
                     * Check if periodic Ap metrics reporting policy is set,
                     * is set, send AP metrics response.
                     */
                    current_time = get_current_time();
                    last_ap_metrics_time = pltfrm_config.map_config.last_ap_metrics_time;

                    interval = get_clock_diff_secs(current_time, last_ap_metrics_time);
                    if (interval >= 0xff)
                        interval_s = 0xff;
                    else
                        interval_s = (uint8_t) interval;

                    if ((gmap_agent->agent_policy.metric_reporting_interval >0) &&
                        (gmap_agent->agent_policy.metric_reporting_interval <= interval_s)) {

                        map_handle.data = NULL;
                        send_response = 1;
                        /* Update periodic timer stamp */
                        pltfrm_config.map_config.last_ap_metrics_time = current_time;
                    }
                    else if (threshold_count > 0) {
                        static ap_metrics_data_t metrics_data = {0};

                        metrics_data.radio_count = threshold_count;
                        metrics_data.radio_list  = (map_radio_info_t **)radio_list;
                        map_handle.data = (void *)&metrics_data;

                        send_response = 1;
                    }

                    if(1 == send_response) {
                        memcpy(map_handle.dest_addr, gmap_agent->iface_mac, 6);
                        map_handle.handle_1905 = handle_1905;
                        map_handle.recv_cmdu   = NULL;
                        memcpy(map_handle.src_iface_name, gmap_agent->iface_name, MAX_IFACE_NAME_LEN);
                
                        w_args.wqdata    = (void*)&map_handle;
                        req.data         = (void*)&w_args;
                        map_send_ap_metrics(&req, 0);
                        
                    }
                    break;
                }

                case MAP_MONITOR_CUMULATIVE_STA_STATS:
                {

                    cum_stats_t*  cum_sta_stats;
                    map_sta_stats_t*       sta_node;
                    map_sta_stats_t*       sta_list;
                    struct map_sta_info_s* hash_sta_node = NULL;
                    map_sta_metrics_t      *metrics      = NULL;
                    int count  = 0;
 
                    cum_sta_stats = (cum_stats_t*)q_obj;
                    sta_list      = (map_sta_stats_t *)cum_sta_stats->cum_stats;

                    struct map_sta_info_s *stations_list[cum_sta_stats->stats_count];
                    for(j = 0; j<cum_sta_stats->stats_count; j++) {

                        sta_node  = &sta_list[j];

                        hash_sta_node = get_sta(sta_node->mac);
                        if(hash_sta_node == NULL) {
                            platform_log(MAP_AGENT,LOG_ERR, "no sta entry in hash exists for sta_mac: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
                                                                                    sta_node->mac[0],sta_node->mac[1],
                                                                                    sta_node->mac[2],sta_node->mac[3],
                                                                                    sta_node->mac[4],sta_node->mac[5]);
                            continue;
                        }

                        if(memcmp(hash_sta_node->bss->bssid, sta_node->bssid, MAC_ADDR_LEN) == 0) {
                            metrics = (map_sta_metrics_t*)object_at_index(hash_sta_node->metrics, 0);

                            if(metrics != NULL) {

                                if(1 == is_station_rssi_threshold_exceeded(hash_sta_node, metrics, sta_node->metrics.link.rssi))
                                {
                                    stations_list[count] = hash_sta_node;
                                    count++;
                                }

                                memcpy(metrics, &sta_node->metrics, sizeof(map_sta_metrics_t));
                                metrics->last_sta_metric_time = cum_sta_stats->measurement_time;
                            }
                        }
                    }

                    if (count > 0)
                    {
                        map_handle_t map_handle = {0};

                        map_handle.handle_1905   = handle_1905;
                        memcpy (map_handle.dest_addr, gmap_agent->iface_mac, MAC_ADDR_LEN);
                        memcpy(map_handle.src_iface_name, gmap_agent->iface_name, MAX_IFACE_NAME_LEN);

                        if (-1 == map_send_sta_metrics_report(map_handle, count, stations_list))
                            platform_log(MAP_AGENT,LOG_ERR, "map_send_sta_metrics_report failed");
                    }

                    break;
                }

                case MAP_MONITOR_BEACON_METRICS_REPORT_EVT:
                {
                    bcn_rprt_timeout_data_t   *cum_beacon_report = (bcn_rprt_timeout_data_t *)q_obj;
                    map_sta_info_t            *sta               =  NULL;
                    beacon_metrics_query_t    *pending_beacon_query = NULL;

                    map_handle_t              map_handle;

                    if (NULL == cum_beacon_report)
                    {
                        platform_log(MAP_AGENT,LOG_ERR, "cum_beacon_report is NULL");
                        break;
                    }

                    sta = get_sta(cum_beacon_report->sta_mac);
                    if(sta ==  NULL) {
                        break;
                    }

                    if (sta->beacon_metrics == NULL) {
                        break;
                    }

                    pending_beacon_query = (beacon_metrics_query_t*)sta->beacon_metrics;
                    if(pending_beacon_query->state != BEACON_QUERY_STATE_ACK_SENT) {
                        break;
                    }

                    if(memcmp(cum_beacon_report->sta_mac, sta->mac, MAC_ADDR_LEN) != 0) {
                        break;
                    }

                    /* prepare  map_handle */
                    memcpy(map_handle.dest_addr, pending_beacon_query->dst_mac, MAC_ADDR_LEN);
                    map_handle.handle_1905 = handle_1905;
                    map_handle.recv_cmdu   = NULL;
                    memcpy(map_handle.src_iface_name, pending_beacon_query->send_iface, MAX_IFACE_NAME_LEN);

                    /* Send the beacon metrics response */
                    map_send_beacon_metrics_response(map_handle, cum_beacon_report);
                    pending_beacon_query->state = BEACON_QUERY_STATE_RESPONSE_SENT;

                    /* 
                     * we will not free(cum_beacon_report) now,
                     * we will deligate the memory authority to retry task
                     * and retry task will free(cum_beacon_report), once
                     * it receives 1905_ack.
                     * so we will continue.
                     */
                    continue;
                }

                 case MAP_MONITOR_WIRELESS_RADIO_CHANNEL_EVT:
                 {
                     radio_channel_event_t *radio_channel = NULL;
            	     map_radio_info_t *radio_node = NULL;
                     map_handle_t map_handle = {0};
                     
                     map_monitor_evt_t *event_info;
 
                     event_info = (map_monitor_evt_t*)q_obj;
    
                     if(NULL != event_info->evt_data) {
                         radio_channel = event_info->evt_data;
                         platform_log(MAP_AGENT,LOG_DEBUG, "%s Channel No  %d \n", __FUNCTION__, radio_channel->channel);

                         platform_log(MAP_AGENT,LOG_DEBUG, "%s %d, %2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx \n",__func__, __LINE__, 
            			                radio_channel->radio_id[0], radio_channel->radio_id[1], 
            			                radio_channel->radio_id[2], radio_channel->radio_id[3], 
            			                radio_channel->radio_id[4], radio_channel->radio_id[5]);
            				 radio_node = get_radio(radio_channel->radio_id);
                         if(radio_node != NULL)
                         {
                         	platform_log(MAP_AGENT,LOG_DEBUG, "%s Radio node updating, tx pwr %d\n", __FUNCTION__, radio_channel->current_tx_pwr);
                             	radio_node->current_tx_pwr = radio_channel->current_tx_pwr;
                                if((radio_channel->channel != radio_node->current_op_channel) || (radio_channel->bandwidth != radio_node->current_bw)) {
                             	    radio_node->current_op_channel = radio_channel->channel;
                                    radio_node->current_bw = radio_channel->bandwidth;
                                    radio_node->current_op_class = radio_channel->op_class;

                                    if(!operating_channel_pending_in_timer) {
                                        map_handle.handle_1905   = handle_1905;
                                        map_handle.recv_cmdu = NULL;
                                        memcpy (map_handle.dest_addr, gmap_agent->iface_mac, MAC_ADDR_LEN);
                                        memcpy (map_handle.src_iface_name, gmap_agent->iface_name, MAX_IFACE_NAME_LEN);
                                        map_send_operating_channel_report((void *)&map_handle);
                                    }
                                } else {

                         	    platform_log(MAP_AGENT,LOG_DEBUG, "%s Radio node update failed since ch is same as prev, old %d, new %d\n", __FUNCTION__, radio_channel->channel, radio_node->current_op_channel);
                                }

                         	printf("%s get preference %d\n", __FUNCTION__, __LINE__);
                                /* Lets fetch the channel preference, might be changed */ 
                               platform_channel_pref_get(radio_node);
                         }
                     }
                     break;
                 }					
    
                 case MAP_MONITOR_SEND_CLIENT_CAPABILITY_QUERY:
                 {
                     client_info_t *client_data = NULL;
                     map_monitor_evt_t *event_info;
                     map_handle_t  map_handle = {0};
                     int           status     =  0;

                     event_info = (map_monitor_evt_t*)q_obj;
                     platform_log(MAP_AGENT,LOG_DEBUG, "%s MAP_MONITOR_SEND_CLIENT_CAPABILITY_QUERY \n", __FUNCTION__);
    
                     client_data = (client_info_t *)event_info->evt_data;
                     if (NULL == client_data) {
                         platform_log(MAP_AGENT,LOG_ERR, "%s : STA mac is empty \n", __FUNCTION__);
                         break;
                     }
                     status  = _client_capability_query_cb(&map_handle, client_data);

                     if(event_info->async_status_response){
                        map_send_aysnc_repsonse(&map_handle, status, CMDU_TYPE_MAP_CLIENT_CAPABILITY_QUERY);
                     }
                     break;
                 }
                 
                 case MAP_MONITOR_HIGHLAYER_DATA_EVENT:
                 {
                     higherlayer_info_t *higherlayer_data = NULL;
                     map_monitor_evt_t *event_info;
                     int status = 0;
                     map_handle_t map_handle         = {0};

                     event_info = (map_monitor_evt_t*)q_obj;

                     higherlayer_data = (higherlayer_info_t *)event_info->evt_data;

                     if (NULL == higherlayer_data)
                     {
                         platform_log(MAP_AGENT,LOG_ERR, "%s : No valid data for high layer query\n",__FUNCTION__);
                         break;
                     }

                     map_handle.handle_1905 = handle_1905;
                     memcpy(map_handle.dest_addr, higherlayer_data->dest_mac, MAC_ADDR_LEN);
                     map_handle.recv_cmdu = NULL;  

                     if(map_send_higher_layer_data_msg(&map_handle, higherlayer_data->payload_len,
                         higherlayer_data->protocol, higherlayer_data->payload_pattern))
                     {
                         platform_log(MAP_AGENT,LOG_ERR, "%s: Higher layer data msg parse failed\n", __FUNCTION__);
                         status = -1;
                     }

                     if(event_info->async_status_response){
                        map_send_aysnc_repsonse(&map_handle, status, CMDU_TYPE_MAP_HIGHER_LAYER_DATA);
                     }
                     break;

                 }
                 case MAP_MONITOR_DEBUG_AGENT_INFO:
                 {
                     platform_log(MAP_AGENT,LOG_INFO,"-------------START AGENT DEBUG--------------------\n");
                     print_agentinfo();
                     break;
                 }
				 case MAP_MONITOR_BTM_REPORT_EVT:
                 {
                     btm_report_event_t *btm_report = NULL;
                     map_monitor_evt_t *event_info;					 
                     map_handle_t map_handle = {0};
                     map_bss_info_t *bss_node = NULL;
                     int8_t status = -1;
					 
                     event_info = (map_monitor_evt_t*)q_obj;
    
                     platform_log(MAP_AGENT,LOG_DEBUG, "%s MAP_MONITOR_BTM_REPORT_EVT \n", __FUNCTION__);
                     btm_report = (btm_report_event_t*)event_info->evt_data;
                     if(NULL == btm_report) {
                         platform_log(MAP_AGENT,LOG_ERR, "%s : btm_report is empty\n", __FUNCTION__);
                         break;
                     }
                     /* prepare  map_handle */
                     memcpy(map_handle.dest_addr, gmap_agent->iface_mac, MAC_ADDR_LEN);
                     map_handle.handle_1905 = handle_1905;
                     map_handle.recv_cmdu   = NULL;
                     memcpy(map_handle.src_iface_name, gmap_agent->iface_name, MAX_IFACE_NAME_LEN); 
                     /* remove station from the list */
                     bss_node = get_bss(btm_report->current_bssid);
                     if((bss_node != NULL) && (bss_node->btm_steer_request_sta_list != NULL)) {
                         status = remove_sta_from_list(btm_report->stn_mac_addr, bss_node->btm_steer_request_sta_list);
                     }
                     if(!status) {
                        platform_log(MAP_AGENT,LOG_DEBUG, "%s Removed station from steer list, sending BTM report\n", __FUNCTION__);
						map_send_btm_report(&map_handle, btm_report);
                     }                                         
                     break;
                 }
                 
                 case MAP_MONITOR_SEND_UNASSOC_STA_METRICS_RESPONSE:
                 {
                     struct unassoc_response *unassoc_response = (struct unassoc_response *)q_obj;
                     map_radio_info_t        *radio_node = NULL;
                     map_handle_t             map_handle;

                     if(unassoc_response != NULL) {
                         radio_node = get_radio_node_from_name(unassoc_response->radio_name);
                         if(radio_node != NULL) {

                         if(radio_node->unassoc_metrics != NULL) {
                             struct unassoc_metrics_info *unassoc_metric_info = radio_node->unassoc_metrics;

                             map_handle.handle_1905 = handle_1905;
                             map_handle.recv_cmdu   = NULL;
                             memcpy(map_handle.dest_addr, unassoc_metric_info->dst_mac, MAC_ADDR_LEN);
                             strncpy(map_handle.src_iface_name, unassoc_metric_info->dst_iface, MAX_IFACE_NAME_LEN);
                             unassoc_response->oper_class = unassoc_metric_info->oper_class;
                             if(map_unassoc_sta_metrics_response(map_handle, unassoc_response) < 0) {
                                 /* 
                                  * we will free here in failure case,
                                  * for success case, free will happen in 
                                  * retry completion_cb will get called once we 
                                  * receive ack from ctrller.
                                  */
                                platform_log(MAP_AGENT,LOG_ERR,"%s: map_unassoc_sta_metrics_response failed\n",__func__);
			        clear_unassoc_measurement(&radio_node->state);
                                free(radio_node->unassoc_metrics);
                                free(unassoc_response);
                                radio_node->unassoc_metrics = NULL;
                             }
                          } else {
                              platform_log(MAP_AGENT,LOG_ERR,"%s: radio_node->unassoc_metrics is NULL",__func__);
                              free(unassoc_response);
                          }
                      } else {
                          platform_log(MAP_AGENT,LOG_ERR,"%s: radio node is NULL",__func__);
                          free(unassoc_response);
                      }
                   }
                   /* 
                    * we dont't want to call map_monitor_free_evt_mem(),
                    * the memory responsibility is given to retry module, will 
                    * free this once response ack from ctrller arrives.
                    */
		   continue;
                 }

                 case MAP_MONITOR_SEND_TOPOLOGY_QUERY:
                 {
                     map_monitor_evt_t *event_info;
                     uint8_t           *dst_mac = NULL;
                     map_handle_t      map_handle = {0};
                     int8_t status = 0;
                     event_info = (map_monitor_evt_t*)q_obj;
    
                     platform_log(MAP_AGENT,LOG_DEBUG, "%s MAP_MONITOR_SEND_TOPOLOGY_QUERY \n", __FUNCTION__);
    
                     dst_mac = (uint8_t *)event_info->evt_data;
                     if (NULL == dst_mac) {
                         platform_log(MAP_AGENT,LOG_ERR, "%s : dst Al mac is empty\n", __FUNCTION__);
                         break;
                     }

                     memcpy(map_handle.dest_addr, dst_mac, MAC_ADDR_LEN);
                     map_handle.handle_1905 = handle_1905;
                     map_handle.recv_cmdu   = NULL;

                     if(is_our_almac(dst_mac)) 
                         break;

                    /* 
                     * As of now we dont have idea, to which interface the dst_ale is connected,
                     * so send to all interface.
                     */
                     strcpy(map_handle.src_iface_name, "all"); 

                     if( 0 != map_send_topology_query(&map_handle)) {
                        status = -1;
                        platform_log(MAP_AGENT,LOG_ERR, "Failed map_send_topology_query in %s", __FUNCTION__);
                     }
                     if(event_info->async_status_response){
                        map_send_aysnc_repsonse(&map_handle, status, CMDU_TYPE_TOPOLOGY_QUERY);
                     }
                     break;

                 }

                 case MAP_MONITOR_SEND_CHANNEL_PREF_REPORT:
                 {
                     map_handle_t      map_handle = {0};
                     struct channel_preference_report *ch_pref_report = NULL;
                     uint8_t empty_mac[MAC_ADDR_LEN] = {0};
                     int8_t status = 0;
                     platform_log(MAP_AGENT,LOG_DEBUG, "%s MAP_MONITOR_SEND_CHANNEL_PREF_REPORT \n", __FUNCTION__);
                     ch_pref_report = (struct channel_preference_report *)q_obj;

                     if(ch_pref_report == NULL || ch_pref_report->al_mac == NULL)
                         break;
    

                     if(memcmp(ch_pref_report->al_mac,  empty_mac, MAC_ADDR_LEN) == 0)
                         /* dst Al mac is empty, we will skip sending channel pref report */
                         break;

                     memcpy(map_handle.dest_addr, ch_pref_report->al_mac, MAC_ADDR_LEN);
                     platform_log(MAP_AGENT,LOG_DEBUG, "%s %d al_mac %2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx\n", __func__, __LINE__, 
                                                                                map_handle.dest_addr[0],
                                                                                map_handle.dest_addr[1],
                                                                                map_handle.dest_addr[2],
                                                                                map_handle.dest_addr[3],
                                                                                map_handle.dest_addr[4],
                                                                                map_handle.dest_addr[5]);
                     map_handle.handle_1905 = handle_1905;
                     map_handle.recv_cmdu   = NULL;

                     if(is_our_almac(ch_pref_report->al_mac)) 
                         break;

                    /* 
                     * As of now we dont have idea, to which interface the dst_ale is connected,
                     * so send to all interface.
                     */
                     strcpy(map_handle.src_iface_name, "all"); 

                     if( 0 != map_cli_send_ch_pref_report(&map_handle, ch_pref_report)) {
                        status = -1;
                        platform_log(MAP_AGENT,LOG_ERR, "Failed map_cli_send_ch_pref_report in %s", __FUNCTION__);
                     }
                     if(ch_pref_report->async_status_response){
                        map_send_aysnc_repsonse(&map_handle, status, CMDU_TYPE_MAP_CHANNEL_PREFERENCE_REPORT);
                     }
                     break;

                 }

                 case MAP_MONITOR_LINK_METRICS_REPORT:
                 {
                     map_handle_t      map_handle = {0};
                     struct neighbour_link_met_response *link_met_resp = (struct neighbour_link_met_response *)q_obj;
                     
                     memcpy(map_handle.dest_addr, link_met_resp->dst_mac, MAC_ADDR_LEN);
                     map_handle.handle_1905 = handle_1905;
                     map_handle.recv_cmdu   = NULL;

                     strcpy(map_handle.src_iface_name, link_met_resp->dst_iface_name); 
                     map_send_link_metrics_report(&map_handle, link_met_resp);

                     break;
                 }

                 case MAP_MONITOR_TX_PWR_CHANGE_REPORT:
                 {
                     platform_cmd_tx_pwr_set_t *tx_pwr_report = (platform_cmd_tx_pwr_set_t *)q_obj;
                     map_radio_info_t          *radio_node    = NULL;

    
                     platform_log(MAP_AGENT,LOG_DEBUG, "%s change tx power event\n", __FUNCTION__);
    
                     if (NULL == tx_pwr_report) {
                         platform_log(MAP_AGENT,LOG_ERR, "%s : tx_pwr_report is empty\n", __FUNCTION__);
                         break;
                     }

                     radio_node = get_radio_node_from_name(tx_pwr_report->radio_name);
                     if (radio_node != NULL) {
                         platform_log(MAP_AGENT,LOG_DEBUG, "%s update current tx power %d\n", __FUNCTION__, tx_pwr_report->current_tx_pwr);
                         radio_node->current_tx_pwr = tx_pwr_report->current_tx_pwr;
                     }
                     break;

                 }

                 case MAP_MONITOR_SEND_CHANNEL_PREF:
                 {
                     map_handle_t      map_handle = {0};
                     platform_channel_pref_cmd_t *platform_cmd = (platform_channel_pref_cmd_t *) q_obj;
                     map_radio_info_t * radio_node = get_radio_node_from_name(platform_cmd->radio_name);
                     if(radio_node != NULL) {
                         if(is_channel_pref_change (radio_node , platform_cmd->op_class_list, platform_cmd->op_class_count)) {
                             memcpy(radio_node->op_class_list, platform_cmd->op_class_list, platform_cmd->op_class_count * sizeof(map_op_class_t));

                             map_handle.handle_1905   = handle_1905;
                             map_handle.recv_cmdu = NULL;
                             memcpy (map_handle.dest_addr, gmap_agent->iface_mac, MAC_ADDR_LEN);
                             memcpy (map_handle.src_iface_name, gmap_agent->iface_name, MAX_IFACE_NAME_LEN);
                             map_send_unsolicated_channel_pref_report(&map_handle, radio_node);
                         }
                     }
                     break;
                 }

                 default:
                 {
                     platform_log(MAP_AGENT,LOG_ERR,"%s invalid event\n", __FUNCTION__);

                     break;
                 }

            }

            /* free up the memory allocated in monitor thread */
            map_monitor_free_evt_mem(q_obj);

        }
    }
    check_and_flush_acl_timeout();
}

int init_periodic_timers(uv_loop_t  *loop, uv_timer_t *periodic_timer)
{
    if(loop == NULL || periodic_timer == NULL) {
        platform_log(MAP_AGENT,LOG_ERR, "Failed to do periodic timer init\n");
        return -1;
    }
    uv_timer_init(loop, periodic_timer);
    uv_timer_start(periodic_timer, periodic_timer_cb, ONE_SEC_IN_MS, ONE_SEC_IN_MS);
    pltfrm_config.map_config.last_ap_metrics_time = get_current_time();

    if (map_init_timer_handler(loop , TIMER_FREQUENCY_ONE_SEC) != 0) {
        platform_log(MAP_AGENT,LOG_ERR, " map_init_timer_handler Failed.\n");
        return -1;
    }

    return 0;
}

static void map_send_aysnc_repsonse(map_handle_t *handle, int status, uint16_t msg_type) {
    map_cli_async_resp_t *ubus_resp = calloc(1,sizeof(map_cli_async_resp_t));
    if(NULL == ubus_resp){
        platform_log(MAP_AGENT,LOG_ERR, "Internal error calloc failed in %s : %d", __func__, __LINE__);
        return;
    }
    const char *status_msg = "Success";
    if(-1 == status) {status_msg = "Failure";}

    strncpy(ubus_resp->status, status_msg, MAX_CLI_ASYNC_STATUS_LEN);
    ubus_resp->msg_type = msg_type;
    ubus_resp->mid      = handle->mid;
    platform_log(MAP_AGENT,LOG_DEBUG, " Status Message : %s, Message type : %d, Message ID : %d ", ubus_resp->status, ubus_resp->msg_type, ubus_resp->mid);
    map_monitor_cmd_t cmd = { MAP_MONITOR_SEND_UBUS_DATA_CMD, MAP_MONITOR_RESPONSE_TO_CLI_SUBCMD, ubus_resp};
    if(0 != map_monitor_send_cmd(cmd)) {
        free(ubus_resp);
    }
}

/* These are purely to test vendor specific data and not to be enabled unless for test purposes */
#ifdef TEST_VENDOR_SPECIFIC
int map_send_vendor_specific(map_ipc_write_1905_ve* vendor_buff,map_handle_t *map_handle)
{
    // Input Parameters Check
    if (NULL == vendor_buff)
    return -1;

    uint16_t    mid               = 0;
    struct      CMDU cmdu         = {0};
    uint8_t     end_of_msg[]      = {0,0,0};
    struct vendorSpecificTLV vendor_tlv = {0};
    uint8_t     *list[3];

    //## init payload CMDU
    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     =  CMDU_TYPE_VENDOR_SPECIFIC;
    cmdu.message_id       =  0;
    cmdu.relay_indicator  =  vendor_buff->relay_indicator;

    vendor_tlv.tlv_type = TLV_TYPE_VENDOR_SPECIFIC;
    memcpy(vendor_tlv.vendorOUI,vendor_buff->oui_id,3);
    vendor_tlv.m_nr = vendor_buff->len;
    vendor_tlv.m = (uint8_t *)vendor_buff->data;

    list[0] = (uint8_t *)&vendor_tlv;
    list[1] = end_of_msg;
    list[2] = NULL;
    cmdu.list_of_TLVs  =  list;

    //strncpy(cmdu.interface_name, "lo", sizeof(cmdu.interface_name));
    strncpy(cmdu.interface_name, map_handle->recv_cmdu->interface_name, MAX_IFACE_NAME_LEN);

    platform_log(MAP_AGENT,LOG_DEBUG, "MAC to send %x:%x \n",vendor_buff->ale_mac[4],vendor_buff->ale_mac[5]);

    if (lib1905_send(handle_1905, &mid, (uint8_t *)vendor_buff->ale_mac, &cmdu)) 
    {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
        goto Failure;
    }
    return 0;

Failure:
    return -1;

}


int map_vendor_specific_validation (uint8_t *src_mac_addr,
                                               struct CMDU *cmdu, void *context)
{
    struct vendorSpecificTLV *vendor_specific_tlv = NULL;
    map_ipc_write_1905_ve vendor_buff = {0};
    uint8_t *p = NULL;
    map_handle_t map_handle;
    
    for ( uint8_t i = 0; NULL != (p = cmdu->list_of_TLVs[i]) ; i++ )  
    {
        switch (*p)
        {
            case TLV_TYPE_VENDOR_SPECIFIC:
            {
                vendor_specific_tlv = (struct vendorSpecificTLV*) p;
                break;
            }
            default:
            {
                platform_log(MAP_AGENT,LOG_ERR,"TODO TLV (%d) type inside CMDU\n", (uint8_t)(*p));
                break;
            }
        }
    }

    if(vendor_specific_tlv)
    {

        platform_log(MAP_AGENT,LOG_DEBUG,"%s SENDING ACK FOR VENDOR MSG \n",__func__);
        /* Send the 1905 ACK message from here as itself*/
        map_handle.handle_1905 = handle_1905;
        map_handle.recv_cmdu   = cmdu;
        memcpy (map_handle.dest_addr, src_mac_addr, MAC_ADDR_LEN);
        memcpy (map_handle.src_iface_name, cmdu->interface_name, MAX_IFACE_NAME_LEN);
        map_send_1905_ack(&map_handle, NULL, 0);

        sleep(2);

        /* Now sending the vendor message for test purposes as well */
        vendor_buff.oui_id[0] = 0x24;
    	vendor_buff.oui_id[1] = 0xF1;
    	vendor_buff.oui_id[2] = 0x28;
    	vendor_buff.relay_indicator = 0;
        memcpy(vendor_buff.ale_mac,src_mac_addr,MAC_ADDR_LEN);
        vendor_buff.len = strlen(vendor_data);
        vendor_buff.data = (uint8_t *)vendor_data;
        platform_log(MAP_AGENT,LOG_DEBUG,"%s SENDING AGENT VENDOR \n",__func__);
        map_send_vendor_specific(&vendor_buff,&map_handle);
        return 0;
    }

    return -1;

}
#endif
int  map_combined_infrastructure_validation(uint8_t *src_mac_addr, struct CMDU *cmdu, void *context)
{
    uint8_t *p    = NULL;
    uint8_t index = 0;

    if ((NULL == cmdu) || (NULL == cmdu->list_of_TLVs))
    {
        platform_log(MAP_AGENT,LOG_CRIT,"Combined link metrics request Malformed structure.");
        return -1;
    }

    while((p = cmdu->list_of_TLVs[index]) != NULL) {
       if((*p != TLV_TYPE_AP_METRICS_RESPONSE) && (*p != TLV_TYPE_TRANSMITTER_LINK_METRIC) 
          && (*p != TLV_TYPE_RECEIVER_LINK_METRIC)) {
        platform_log(MAP_AGENT,LOG_CRIT,"Combined link metrics request Malformed structure.");
        return -1;
       }
       index++;
    }

    return 0;
}
