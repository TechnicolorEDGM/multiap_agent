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
#include "multiap_agent_tlv_helper.h"
#include "platform_map.h"
#include "1905_platform.h"
#include "1905_tlvs.h"
#include "map_topology_tree.h"
#include <time.h>
#include "monitor_task.h"
#include "platform_multiap_get_info.h"
#include "multiap_agent_topology_tree_builder.h"

#define ONE_OCTET   (1)
#define catch_mid(handle_ptr, mid_ptr) (handle_ptr)? ({*mid_ptr = &(handle_ptr->mid);}) : ({})

int operating_channel_pending_in_timer;

uint8_t agent_search_retry_cnt[MAX_NO_FREQ_SUPPORTED];

int get_assoc_request(uint8_t *sta_mac, uint8_t *bssid, uint16_t *assoc_frame_len, uint8_t **assoc_frame)
{
    map_sta_info_t* sta_node = NULL;

    /* Input parameters Validation */
    /*
     * Ignoring validation of assoc_frame since it will be allocated in this function
     */
    if (NULL == sta_mac || NULL == bssid || NULL == assoc_frame_len)
    {
        platform_log(MAP_AGENT,LOG_ERR,"is_sta_connected() input validation failed");
        return -EINVAL;
    }

    sta_node=get_sta(sta_mac);
    if(sta_node != NULL && sta_node->bss != NULL) {
        memcpy(bssid, sta_node->bss->bssid, MAC_ADDR_LEN);
        *assoc_frame    = sta_node->assoc_frame;
        *assoc_frame_len = sta_node->assoc_frame_len;
        return 0;
    }

    platform_log(MAP_AGENT,LOG_DEBUG, "Station is not associated with any of the bss");
    return -EINVAL;
}

int acceptable_channel_pref_check(struct mapChannelPreferenceTLV *ctrl_channel_pref,map_radio_info_t* radio_node, uint8_t *response)
{
    int i = 0;
    int j = 0;
    for (i = 0; i<ctrl_channel_pref->numOperating_class; i++) {
        for(j = 0; j<ctrl_channel_pref->operating_class[i].number_of_channels ;j++)
        {
            if(!is_matching_channel_in_opclass(ctrl_channel_pref->operating_class[i].operating_class,ctrl_channel_pref->operating_class[i].channel_num[j])){
                *response = MAP_CHANNEL_SEL_VALIDATION_DECLINE;
                return 0;
            }
        }
    }
    return 1;
}

int get_error_code_tlv(struct mapErrorCodeTLV *error_code_tlv, uint8_t reason_code, uint8_t *sta_mac)
{
    /* Input Parameters Validation */
    if ((NULL == error_code_tlv) || (NULL == sta_mac) || (reason_code < STA_ASSOCIATED) || (reason_code > STEERING_REJECTED_BY_TARGET))
    {
        platform_log(MAP_AGENT,LOG_ERR, "get_error_code_tlv Input Validation failed");
        return -1;
    }

    error_code_tlv->tlv_type = TLV_TYPE_ERROR;
    error_code_tlv->reason_code = reason_code;
    memcpy(error_code_tlv->sta_mac_addr,sta_mac,MAC_ADDR_LEN);

    return 0;
}

int is_sta_associated_with_agent(uint8_t *sta_mac)
{
    map_sta_info_t* sta_node = NULL;

    if(NULL == sta_mac)
    {
        platform_log(MAP_AGENT,LOG_ERR, "Sta mac is NULL");
        return 0;
    }

    sta_node = get_sta(sta_mac);
    if(NULL != sta_node)
    {
        if (0 == memcmp(sta_node->bss->radio->ale->al_mac, gmap_agent->al_mac, MAC_ADDR_LEN))
            return 1;
    }

    return 0;
}

static int map_get_channel_preference_tlv(struct mapChannelPreferenceTLV *channel_pref, uint8_t index)
{
	uint8_t len = 0, i=0, j=0;
	uint8_t pref_reason =0;
    int tlv_oper_class_index = 0;

	if(channel_pref != NULL)
	{
		channel_pref->tlv_type = TLV_TYPE_CHANNEL_PREFERENCE;
		
		 //## Filling Radio Id here
		memcpy(channel_pref->radio_id, gmap_agent->radio_list[index]->radio_id, MAC_ADDR_LEN);
		len+=MAC_ADDR_LEN;

		//## Initiating total reported operating class number field here
	    channel_pref->numOperating_class = 0;
	    len+=1;

		for(i = 0; i<gmap_agent->radio_list[index]->op_class_count; i++) 
		{
            if(gmap_agent->radio_list[index]->op_class_list[i].agent_non_oper_ch_cnt > 0) 
            {
                //## Updating total reported operating class number field here
                channel_pref->numOperating_class += 1; /*No need to increment len field, we are just updating existing value, not writing new value */
                tlv_oper_class_index = channel_pref->numOperating_class - 1;
            }
            else 
            {
                continue;
            }
			//## filling indidual operating class info here
	        channel_pref->operating_class[tlv_oper_class_index].operating_class = gmap_agent->radio_list[index]->op_class_list[i].op_class;
	        len+=1;
			
			channel_pref->operating_class[tlv_oper_class_index].number_of_channels = gmap_agent->radio_list[index]->op_class_list[i].agent_non_oper_ch_cnt;
	        len+=1;

			for (j=0; j<channel_pref->operating_class[tlv_oper_class_index].number_of_channels; j++)
			{
				channel_pref->operating_class[tlv_oper_class_index].channel_num[j] = gmap_agent->radio_list[index]->op_class_list[i].agent_non_oper_ch[j];

				len+=1;
			}
			pref_reason = (MAP_NON_OPERABLE_DEFAULT_PREF_VAL) | (gmap_agent->radio_list[index]->op_class_list[i].reason);
			channel_pref->operating_class[tlv_oper_class_index].pref_reason = pref_reason;
			len+=1;
		}
		channel_pref->tlv_length = len;
	}

    return 0;

}

static map_radio_info_t* map_get_channel_selection_tlv(struct mapChannelSelectionResponseTLV *channel_sel_resp,struct mapChannelPreferenceTLV *channel_pref,int *ret)
{
        uint8_t response = MAP_CHANNEL_SEL_ACCEPT;
        map_radio_info_t* radio_node = NULL;

        if(channel_sel_resp != NULL && channel_pref != NULL)
        {
            channel_sel_resp->tlv_type = TLV_TYPE_CHANNEL_SELECTION_RESPONSE;
            radio_node = get_radio(channel_pref->radio_id);
            if(radio_node != NULL) {
                memcpy(channel_sel_resp->radio_id, channel_pref->radio_id, MAC_ADDR_LEN);
                if(acceptable_channel_pref_check(channel_pref, radio_node, &response))
                {
                    update_global_channel_pref_with_controller_updates(channel_pref, radio_node, &response);
                    *ret = 0;
                }
                channel_sel_resp->channel_selection_response = response;
                channel_sel_resp->tlv_length = 7;
            }
        }

        return radio_node;
}


static int map_get_oper_channel_tlv(struct mapOperatingChannelReportTLV *oper_channel, uint8_t index)
{
    uint8_t len  = 0;
    int     ret  = -EINVAL;

    uint8_t channel_no = 0;
    map_radio_info_t* radio_node = NULL;

    if(oper_channel != NULL) {

        oper_channel->tlv_type = TLV_TYPE_OPERATING_CHANNEL_REPORT;

        radio_node = gmap_agent->radio_list[index];
        channel_no = radio_node->current_op_channel;

        //## Filling Radio Id here
        memcpy(oper_channel->radio_id, radio_node->radio_id, MAC_ADDR_LEN);
        len+=MAC_ADDR_LEN;

        oper_channel->numOperating_class = 0;

        oper_channel->operating_class[oper_channel->numOperating_class].operating_class = radio_node->current_op_class;
        oper_channel->operating_class[oper_channel->numOperating_class].current_op_channel = channel_no;
        len+=2;

        oper_channel->numOperating_class++;
        /* For number of operating class */
        len+=1;

       oper_channel->current_transmit_power_eirp =  radio_node->current_tx_pwr;

        /* For tx power */
        len+=1;

        oper_channel->tlv_length = len;
        ret = 0 ;
    }

    return ret;
}


static int map_get_ap_basic_cap_tlv(struct mapApBasicCapabilityTLV *ap_basic_cap, uint8_t index)
{

    uint8_t max_bss = 0; 
    uint8_t j=0, eirp=0, op_class=0, len = 0;
    uint8_t total_op_num = 0;
    uint8_t non_op_ch_count = 0;

    ap_basic_cap->tlv_type = TLV_TYPE_AP_RADIO_BASIC_CAPABILITY;

     //## Filling Radio Id here
    memcpy(ap_basic_cap->radioId, gmap_agent->radio_list[index]->radio_id, MAC_ADDR_LEN);
    len+=MAC_ADDR_LEN;

    //## Filling Max bssid here as from global struct 
    max_bss = gmap_agent->radio_list[index]->num_bss;
    ap_basic_cap->max_bss = max_bss;
    len+=1;

    //## Filling Total operating class number here
    total_op_num = gmap_agent->radio_list[index]->op_class_count;
    ap_basic_cap->numOperating_class = total_op_num;
    len+=1;


    //## Iterate over each operating class 
    for (j=0; j<total_op_num; j++) {

        op_class = gmap_agent->radio_list[index]->op_class_list[j].op_class;

        //## filling indidual operating class info here
        ap_basic_cap->operating_class[j].operating_class = op_class;
        len+=1;

        //## Filling EIRP for such operating class
        eirp = gmap_agent->radio_list[index]->op_class_list[j].eirp;
        ap_basic_cap->operating_class[j].eirp = eirp;
        len+=1;

        //## Iterate over non operating channel
        non_op_ch_count = gmap_agent->radio_list[index]->op_class_list[j].static_non_operable_count;
		ap_basic_cap->operating_class[j].number_of_channels = non_op_ch_count;
                 len+=1;

		if(non_op_ch_count > 0)
		{
			memcpy( ap_basic_cap->operating_class[j].channel_num, gmap_agent->radio_list[index]->op_class_list[j].static_non_operable_channel, non_op_ch_count);
             len+=non_op_ch_count;
        }
    }
    ap_basic_cap->tlv_length = len;

    return 0;
}

int map_agent_send_steering_complete(map_handle_t *map_handle)
{
    struct CMDU *cmdu = NULL;
    int if_len = 0;
    uint8_t     end_of_msg[]      = {0,0,0};
    uint8_t     *list[2]          = {end_of_msg,NULL};
    uint16_t       *mid = NULL;

    if ((NULL == map_handle) || (NULL == map_handle->dest_addr) ||
        (-1 == map_handle->handle_1905) || (NULL == map_handle->src_iface_name))
    {
        platform_log(MAP_AGENT,LOG_ERR, "MAP handle parameters validation Failed");
        return -1;
    }
    cmdu = (struct CMDU *) calloc(1,sizeof(struct CMDU));
    if (NULL == cmdu) {
        platform_log(MAP_AGENT,LOG_ERR,"CMDU malloc failed");
        return -1;
    }
    cmdu->message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu->message_type     =  CMDU_TYPE_MAP_STEERING_COMPLETED;
    cmdu->message_id       =  0;
    cmdu->relay_indicator  =  0;
    
    if_len = strlen(map_handle->src_iface_name);
    strncpy(cmdu->interface_name, map_handle->src_iface_name, if_len);
    cmdu->interface_name[if_len] = '\0';

    cmdu->list_of_TLVs  = list;

    if (lib1905_send(map_handle->handle_1905, mid, map_handle->dest_addr, cmdu)<0) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu->message_type);
        return -1;
    }
    return 0;
}

int map_send_1905_ack(map_handle_t *map_handle, array_list_t* sta_list,  uint8_t reason_code)
{
    uint8_t number_of_tlv   = 0;
    uint8_t sta_count       = 0;
    struct  CMDU *cmdu      = NULL;
    struct  CMDU *recv_cmdu = NULL; /* Received Cmdu will be cleaned up by the caller */
    list_iterator_t* it     = NULL;
    uint8_t *sta_mac        = NULL;
    int     i               = 0;
    int     if_len          = 0;
    int     ret             = 0;

    struct mapErrorCodeTLV *error_code_tlv;

    // Map Handle parameters Validation
    if ((NULL == map_handle) || (NULL == map_handle->dest_addr) || (NULL == map_handle->recv_cmdu) ||
        (-1 == map_handle->handle_1905) || (NULL == map_handle->src_iface_name))
    {
        platform_log(MAP_AGENT,LOG_ERR,"Map Handle parameters Validation Failed");
        ret = -1;
        goto Failure;
    }
    recv_cmdu = map_handle->recv_cmdu;

    if (NULL != sta_list)
    {
        sta_count = list_get_size(sta_list);
        number_of_tlv += sta_count;
    }

    /* init payload CMDU */
    cmdu = (struct CMDU *) calloc(1,sizeof(struct CMDU));

    if (NULL == cmdu) {
        platform_log(MAP_AGENT,LOG_ERR,"CMDU malloc failed");
        ret = -1;
        goto Failure;
    }

    cmdu->message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu->message_type     =  CMDU_TYPE_MAP_ACK;
    cmdu->message_id       =  recv_cmdu->message_id;
    cmdu->relay_indicator  =  0;

    if_len = strlen(map_handle->src_iface_name);
    strncpy(cmdu->interface_name, map_handle->src_iface_name, if_len);
    cmdu->interface_name[if_len] = '\0';

    cmdu->list_of_TLVs  =  (uint8_t **)calloc(number_of_tlv+1, sizeof(uint8_t *));
    if(cmdu->list_of_TLVs == NULL) {
        platform_log(MAP_AGENT,LOG_ERR,"%s %d, calloc failed list_of_TLVs", __func__, __LINE__);
        ret = -1;
        goto Failure;
    }

    if (sta_count > 0)
    {
        if ((reason_code < STA_ASSOCIATED) || (reason_code > STEERING_REJECTED_BY_TARGET))
        {
            platform_log(MAP_AGENT,LOG_ERR, "Invalid reason code");
            ret = -1;
            goto Failure;
        }

        it = new_list_iterator(sta_list);
        if(!it)
        {
            ret = -1;
            goto Failure;
        }

        while(it->iter)
        {
            sta_mac = (uint8_t*) get_next_list_object(it);
            if(NULL == sta_mac)
            {
                platform_log(MAP_AGENT,LOG_ERR, "sta_mac is NULL");
                ret = -1;
                goto Failure;
            }

            error_code_tlv = (struct mapErrorCodeTLV *) calloc (1,sizeof(struct mapErrorCodeTLV));
            if (NULL == error_code_tlv)
            {
                platform_log(MAP_AGENT,LOG_ERR, "Malloc failed for error_code_tlv");
                ret = -1;
                goto Failure;
            }

            if (-1 == get_error_code_tlv(error_code_tlv, reason_code, sta_mac))
            {
                platform_log(MAP_AGENT,LOG_ERR, "Get Error Code TLV failed");
                if (NULL != error_code_tlv)
                    free(error_code_tlv);
                ret = -1;
                goto Failure;
            }
            cmdu->list_of_TLVs[i++] = (uint8_t *)error_code_tlv;
            error_code_tlv = NULL;
            sta_mac        = NULL;
        }
        free_list_iterator(it);

        if (i != number_of_tlv)
        {
            platform_log(MAP_AGENT,LOG_ERR, "Count mismatch btwn error code tlvs and sta count");
            ret = -1;
            goto Failure;
        }
    }

    if (lib1905_send(map_handle->handle_1905, &cmdu->message_id, map_handle->dest_addr, cmdu)<0) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu->message_type);
        ret = -1;
        goto Failure;
    }

    goto Exit;

Failure:
    if (NULL != it)
        free_list_iterator(it);

Exit:
    if (NULL != cmdu)
        lib1905_cmdu_cleanup(cmdu);

    return ret;
}

int map_autoconfig_search_completion(void *data) {
    map_configure_radios();
    return 0;
}

int map_send_autoconfig_search(map_handle_t map_handle, void *ptr)
{
    uint8_t     number_of_tlv   = 5;
    uint8_t     relay_indicator = 1;
    uint8_t     freq            = 0;
    char        *radio_iface    = NULL;
    uint8_t     *dst_addr       = NULL;
    struct      CMDU cmdu       = {0};
    struct     CMDU *recv_cmdu  = NULL;
    handle_1905_t handle        = 0;
    uint16_t   mid              = 0;
    int        index            = (int)ptr;

    struct alMacAddressTypeTLV      al_mac_tlv = {0};
    struct searchedRoleTLV          searched_role_tlv = {0};
    struct autoconfigFreqBandTLV    autoconfig_freq_tlv = {0};
    struct mapSupportedServiceTLV   supported_service_tlv = {0};
    struct mapSearchedServiceTLV    searched_service_tlv = {0};

    dst_addr  =  map_handle.dest_addr;
    handle    =  map_handle.handle_1905;
    recv_cmdu =  map_handle.recv_cmdu;

    if((index < 0) || (index >= gmap_agent->num_radios))
    {
        platform_log(MAP_AGENT,LOG_ERR,"Invalid Radio index :%d\n", index);
        goto Failure;
    }
    radio_iface = gmap_agent->radio_list[index]->iface_name;
    freq = gmap_agent->radio_list[index]->radio_caps.type;

    //##Add Al mac address Tlv 
    if(lib1905_get(handle, (lib1905_param_t) GET_1905_ALMACTLV,  NULL , (void *)&al_mac_tlv, NULL)) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d AL_MAC TLV  lib1905_get failed",__func__, __LINE__);
        goto Failure;
    }
    
    //##Add searched Role Tlv SEARCHED_ROLE 
    if (lib1905_get(handle, (lib1905_param_t) GET_1905_SEARCHEDROLETLV,  NULL , (void *)&searched_role_tlv, NULL)){
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d SEARCHED_ROLE TLV lib1905_get failed",__func__, __LINE__);
        goto Failure;
    }

    //## Add Autoconfig Freq band TLV
    if(lib1905_get(handle, (lib1905_param_t) GET_1905_FREQUENCYBANDTLV, NULL, (void *)&autoconfig_freq_tlv, (void *) radio_iface)){
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d FREQUENCY_BAND TLV lib1905_get failed",__func__, __LINE__);
        goto Failure;
    }

    //## Add Supported service TLV
    supported_service_tlv.tlv_type           = TLV_TYPE_SUPPORTED_SERVICE;
    supported_service_tlv.tlv_length         = 2;
    supported_service_tlv.number_of_service  = 1;
    supported_service_tlv.supported_service_array[0] = MAP_ROLE_AGENT;
    

    //## Add Searched service TLV
    searched_service_tlv.tlv_type             = TLV_TYPE_SEARCHED_SERVICE;
    searched_service_tlv.tlv_length           = 2;
    searched_service_tlv.number_of_searched_service = 1;
    searched_service_tlv.searched_service_array[0]  = MAP_ROLE_CONTROLLER;

    //## init payload CMDU
    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     =  CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH;
    cmdu.message_id       =  0;
    cmdu.relay_indicator  =  relay_indicator;
    strncpy(cmdu.interface_name, "all", sizeof(cmdu.interface_name));

    cmdu.list_of_TLVs  =  (uint8_t **)calloc(number_of_tlv+1, sizeof(uint8_t *));
    if(cmdu.list_of_TLVs == NULL) {
       platform_log(MAP_AGENT,LOG_ERR,"%s %d, calloc failed list_of_TLVs", __func__, __LINE__);
        goto Failure;
    }

    cmdu.list_of_TLVs[0] = (uint8_t *)&al_mac_tlv;
    cmdu.list_of_TLVs[1] = (uint8_t *)&searched_role_tlv;
    cmdu.list_of_TLVs[2] = (uint8_t *)&autoconfig_freq_tlv;
    cmdu.list_of_TLVs[3] = (uint8_t *)&supported_service_tlv;
    cmdu.list_of_TLVs[4] = (uint8_t *)&searched_service_tlv;

    if (lib1905_send(handle, &mid, dst_addr, &cmdu)<0) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
        free(cmdu.list_of_TLVs);
        goto Failure;
    }
    {
        /*
         * Debug print with time stamp
         */
        time_t curtime;

        time(&curtime);
        platform_log(MAP_AGENT,LOG_DEBUG, "%s: %d, TIME[%s] sending payload mid 0x%x for msg type %d\n\n",__func__, __LINE__, ctime(&curtime), mid, cmdu.message_type);
    }

    fire_retry_timer (dst_addr, (uint8_t *)"all", CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH,
                      CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE, MAX_RETRY_THRESHOLD, 
                      mid,     6000, map_send_autoconfig_search, map_autoconfig_search_completion, (void *)index);

    agent_search_retry_cnt[freq] += 1; //Incrementing count for each retry
    if(recv_cmdu != NULL)
        lib1905_cmdu_cleanup(recv_cmdu);
    free(cmdu.list_of_TLVs);

    return 0;

Failure:
    if(recv_cmdu != NULL)
        lib1905_cmdu_cleanup(recv_cmdu);
    return -EINVAL;
}

int map_send_wsc_m1 (map_handle_t map_handle, void *ptr)
{
    uint8_t     number_of_tlv   = 2;
    uint8_t     relay_indicator = 0;
    char        *radio_iface    = NULL; 
    struct      CMDU cmdu       = {0};
    lib1905_wscTLV_t  *wsc_data = NULL;
    int         index           = (int)ptr;

    struct mapApBasicCapabilityTLV  ap_basic_cap = {0};

    /* Input Parameters Check */
    if (NULL == map_handle.dest_addr || (-1 == map_handle.handle_1905)) {
        platform_log(MAP_AGENT,LOG_ERR, "Input parameters failed");
        return -1;
    }
    if((index < 0) || (index >= gmap_agent->num_radios))
    {
        platform_log(MAP_AGENT,LOG_ERR,"Invalid Radio index :%d\n", index);
        return -1;
    }
    radio_iface = gmap_agent->radio_list[index]->iface_name;

    wsc_data = (lib1905_wscTLV_t  *)gmap_agent->radio_list[index]->wsc_data;
    if(wsc_data == NULL) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d wsc_data is null\n",__func__, __LINE__);
        return -1;
    }   

    /* Lean Detection Fix*/
    /* Flush previously allocated M1 data for this radio */
    map_free_cached_m1(gmap_agent->radio_list[index]);

    //## Add WSCM1 TLV
    if(lib1905_get(map_handle.handle_1905, (lib1905_param_t) GET_1905_WSCM1TLV, NULL , (void *)wsc_data, (void *) radio_iface)) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d WSC_M1  lib1905_get failed",__func__, __LINE__);
        return -1;
    }

    //## Add AP basic capability TLV
    if(map_get_ap_basic_cap_tlv(&ap_basic_cap, index)<0) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d AP_BASIC_CAP  map_get failed",__func__, __LINE__);
        return -1;
    }

    //## init payload CMDU
    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     =  CMDU_TYPE_AP_AUTOCONFIGURATION_WSC;
    cmdu.message_id       =  0;
    cmdu.relay_indicator  =  relay_indicator;
    strncpy(cmdu.interface_name,  (char *)map_handle.src_iface_name, sizeof(cmdu.interface_name));

    cmdu.list_of_TLVs  =  (uint8_t **)calloc(number_of_tlv+1, sizeof(uint8_t *));
    if(cmdu.list_of_TLVs == NULL) {
       platform_log(MAP_AGENT,LOG_ERR,"calloc failed in init_cmdu");
       return -1;
    }

    cmdu.list_of_TLVs[0] = (uint8_t *)&wsc_data->m1;
    cmdu.list_of_TLVs[1] = (uint8_t *)&ap_basic_cap;

    if (lib1905_send(map_handle.handle_1905, &cmdu.message_id, map_handle.dest_addr, &cmdu)<0) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
        free(cmdu.list_of_TLVs);
        return -1;
    }

    set_radio_state_M1_sent(&gmap_agent->radio_list[index]->state);

    {
        time_t curtime;

        time(&curtime);
        platform_log(MAP_AGENT,LOG_DEBUG, "%s: %d, TIME[%s] sending payload mid 0x%x for msg type %d\n\n",__func__, __LINE__, ctime(&curtime), cmdu.message_id, cmdu.message_type);
    }
   fire_retry_timer (map_handle.dest_addr, (uint8_t *)cmdu.interface_name, CMDU_TYPE_AP_AUTOCONFIGURATION_WSC,
                      CMDU_TYPE_AP_AUTOCONFIGURATION_WSC, 10, 
                      cmdu.message_id,     12000, map_send_wsc_m1, NULL, (void *)index);

    free(cmdu.list_of_TLVs);

    return 0;
}


void map_send_channel_pref_report(uv_work_t *req, int status)
{
    uint8_t         number_of_tlv     = 0;
    uint8_t         relay_indicator   = 0;
    uint8_t         *dst_addr         = NULL;
    struct          CMDU *cmdu        = NULL;
    struct          CMDU *recv_cmdu   = NULL;
    uint16_t        mid               = 0;
    uint8_t         i                 = 0;
    map_handle_t   *map_handle        = NULL;
    handle_1905_t   handle;
    int if_len;

	/* Ideally there are 2 TLV's sent for each radio. But radio operation restriction TLV is not applicable 
	here because getting channel restriction is not supported at all (HW limitation). So that
	TLV is not considered */
    struct mapChannelPreferenceTLV *channel_pref_tlv = NULL;  

    // Input Parameters Validation
    if (NULL == req || NULL == req->data)
    {
        platform_log(MAP_AGENT,LOG_ERR,"Input Parameters Validation");
        goto Cleanup;
    }

    wq_args* p_args = (wq_args*)req->data;

    // Map Handle Validation
    if (NULL == p_args)
    {
        platform_log(MAP_AGENT,LOG_ERR,"Map Handle Validation Failed");
        goto Cleanup;
    }

    map_handle      = (map_handle_t *)p_args->wqdata;

    // Map Handle parameters Validation
    if (NULL == map_handle->dest_addr || NULL == map_handle->recv_cmdu || (-1 == map_handle->handle_1905))
    {
        platform_log(MAP_AGENT,LOG_ERR,"Map Handle parameters Validation Failed");
        goto Cleanup;
    }

    dst_addr        =  map_handle->dest_addr;
    handle          =  map_handle->handle_1905;
    recv_cmdu       =  map_handle->recv_cmdu;

    mid = recv_cmdu->message_id;

	//## init payload CMDU
	cmdu = (struct CMDU *) calloc(1,sizeof(struct CMDU));

	if (NULL == cmdu) {
		platform_log(MAP_AGENT,LOG_ERR,"CMDU malloc failed");
		goto Cleanup;
	}

	cmdu->message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
	cmdu->message_type	   =  CMDU_TYPE_MAP_CHANNEL_PREFERENCE_REPORT;
	cmdu->message_id	   =  mid;
	cmdu->relay_indicator  =  relay_indicator;

	if_len = strlen(map_handle->src_iface_name);
	strncpy(cmdu->interface_name, map_handle->src_iface_name, if_len);
	cmdu->interface_name[if_len] = '\0';

	/*
	* Determine total number of tlvs to allocate memory prior to allocation
	* because it is always better to first determine the count and do a
	* calloc in one-shot rather than counting tlvs on the fly and doing
	* realloc as when we find that the tlv should be added as part of the cmdu
	*/

	//## For Channel Preference TLV
	number_of_tlv += gmap_agent->num_radios;

	cmdu->list_of_TLVs  =  (uint8_t **)calloc(number_of_tlv+1, sizeof(uint8_t *));
    if(cmdu->list_of_TLVs == NULL) {
       platform_log(MAP_AGENT,LOG_ERR,"calloc failed in init_cmdu");
       goto Cleanup;
    }
	
	for (i = 0; i < gmap_agent->num_radios; i++)
    {
        channel_pref_tlv = (struct mapChannelPreferenceTLV *) calloc (1,sizeof(struct mapChannelPreferenceTLV));

		if(channel_pref_tlv == NULL)
		{
			platform_log(MAP_AGENT,LOG_ERR,"calloc failed in init_cmdu");
       		goto Cleanup;
		}

        //## Add Channel Preference TLV
        if (map_get_channel_preference_tlv(channel_pref_tlv, i) < 0)
        {
            platform_log(MAP_AGENT,LOG_ERR,"%s: %d Channel Preference TLV  map_get failed",__func__, __LINE__);
            goto Cleanup;
        }
        else
        {
			cmdu->list_of_TLVs[i]     = (uint8_t *)channel_pref_tlv;
		}
	}

	if (i != number_of_tlv)
		platform_log(MAP_AGENT,LOG_ERR,"%s: %d Count mismatch",__func__, __LINE__);

	cmdu->list_of_TLVs[number_of_tlv]  = 0;

	if (lib1905_send(handle, &mid, dst_addr, cmdu)<0) {
		platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu->message_type);
		goto Cleanup;
	}

	goto Cleanup;

Cleanup:
	if (NULL != recv_cmdu)
		lib1905_cmdu_cleanup(recv_cmdu);

	if (NULL != cmdu)
		lib1905_cmdu_cleanup(cmdu);

	return;
}

int map_get_current_tx_pwr (void   *data)
{
      platform_cmd_tx_pwr_set_t  *tx_pwr_info = NULL;
      int                                ret  = 0;
      char                        *radio_name = NULL;

      if(data == NULL)
          return -EINVAL;

       radio_name = (char *)data;

       tx_pwr_info = (platform_cmd_tx_pwr_set_t * )malloc(sizeof(platform_cmd_tx_pwr_set_t));
       if(tx_pwr_info == NULL) {
           return -EINVAL;
       }

       strcpy(tx_pwr_info->radio_name, radio_name);

       ret = map_send_platform_event(MAP_MONITOR_GET_TX_PWR_METHOD_SUBCMD, tx_pwr_info);
       if(ret < 0)
           free(tx_pwr_info);

      free(radio_name);
      return ret;
}

void map_parse_transmit_power_tlv(map_handle_t   *map_handle)
{
        struct                  CMDU *recv_cmdu   = NULL;
        int                     i                 = 0;
        uint8_t                 *p                = NULL;
        map_radio_info_t        *radio            = NULL;

	// Map Handle parameters Validation
	if ((map_handle != NULL) && (NULL != map_handle->recv_cmdu))
	{
                recv_cmdu = (struct CMDU *) map_handle->recv_cmdu;

                while (NULL != (p = recv_cmdu->list_of_TLVs[i])) {
                    switch (*p) {
                    case TLV_TYPE_TRANSMIT_POWER:
                    {
                            transmit_power_tlv_t *tx_pwr_tlv = (transmit_power_tlv_t*)p;

                            platform_log(MAP_AGENT,LOG_DEBUG, "%s %d\n",__func__ ,__LINE__);
                            radio = get_radio(tx_pwr_tlv->radio_id);
                            if(radio == NULL) break;
                            if(tx_pwr_tlv->transmit_power_eirp == 0) {
                                platform_log(MAP_AGENT,LOG_ERR, "%s %d, Failure: tx_pwr is 0 Failure\n",__func__ ,__LINE__);
                                break;
                            }

                            if(tx_pwr_tlv->transmit_power_eirp == radio->current_tx_pwr) { 
                                platform_log(MAP_AGENT,LOG_DEBUG, "%s %d, Failure: same as current tx power\n",__func__ ,__LINE__);
                                break;
                            }
 
                            platform_log(MAP_AGENT,LOG_DEBUG, "%s %d, radio %s, current_pwr %d, new pwr %d\n",__func__ ,__LINE__, radio->radio_name, radio->current_tx_pwr, tx_pwr_tlv->transmit_power_eirp);
                            set_tx_pwr(radio->radio_name,radio->current_tx_pwr,
                                          tx_pwr_tlv->transmit_power_eirp);

                            execute_after(map_get_current_tx_pwr, strdup(radio->radio_name), ONE_SEC_IN_MS * 10);
                            break;
                     }
                   }
		   i++;
                }
        } else
            platform_log(MAP_AGENT,LOG_ERR,"Map Handle parameters Validation Failed");

        return;
}

void map_process_channel_selection_query(uv_work_t *req, int status)
{
	struct          CMDU *recv_cmdu   = NULL;
	map_handle_t   *map_handle        = NULL;
	
	  // Input Parameters Validation
	if (NULL == req || NULL == req->data)
	{
		platform_log(MAP_AGENT,LOG_ERR,"Input Parameters Validation");
		goto Cleanup;
	}

	wq_args* p_args = (wq_args*)req->data;

	// Map Handle Validation
	if (NULL == p_args)
	{
		platform_log(MAP_AGENT,LOG_ERR,"Map Handle Validation Failed");
		goto Cleanup;
	}

	map_handle      = (map_handle_t *)p_args->wqdata;

	// Map Handle parameters Validation
	if ((NULL == map_handle) || (NULL == map_handle->recv_cmdu))
	{
		platform_log(MAP_AGENT,LOG_ERR,"Map Handle parameters Validation Failed");
		goto Cleanup;
	}

	recv_cmdu       =  map_handle->recv_cmdu;
	 
	/* First send the channel select response */
	if(0 == map_send_channel_select_response(map_handle))
    {
	   /* Parse the transmit power TLV and set accordingly */
	   map_parse_transmit_power_tlv(map_handle);
    }

        map_handle_t   *map_handle_dm        = (map_handle_t   *)calloc(1, sizeof(map_handle_t));
        memcpy(map_handle_dm, map_handle, sizeof(map_handle_t));

        operating_channel_pending_in_timer = 1;
        /* Next send the operating channel report */
        execute_after(map_send_operating_channel_report, (void*)map_handle_dm, 20 * ONE_SEC_IN_MS);

Cleanup:
	if (NULL != recv_cmdu)
	    lib1905_cmdu_cleanup(recv_cmdu);

   return;
}

void map_process_topology_discovery(uv_work_t * req,int status)
{
	struct CMDU  *recv_cmdu   = NULL;
	map_handle_t *map_handle  = NULL;
	uint8_t       tlv_index	  = 0;
	struct alMacAddressTypeTLV *al_mac_tlv		 = NULL;
	struct macAddressTypeTLV   *upstream_mac_tlv = NULL;

	  // Input Parameters Validation
	if (NULL == req || NULL == req->data)
	{
		platform_log(MAP_AGENT,LOG_ERR,"Input Parameters Validation");
		goto Cleanup;
	}

	wq_args* p_args = (wq_args*)req->data;

	// Map Handle Validation
	if (NULL == p_args)
	{
		platform_log(MAP_AGENT,LOG_ERR,"Map Handle Validation Failed");
		goto Cleanup;
	}

	map_handle      = (map_handle_t *)p_args->wqdata;

	// Map Handle parameters Validation
	if ((NULL == map_handle) || (NULL == map_handle->recv_cmdu))
	{
		platform_log(MAP_AGENT,LOG_ERR,"Map Handle parameters Validation Failed");
		goto Cleanup;
	}

	recv_cmdu = map_handle->recv_cmdu;

	while (NULL != recv_cmdu->list_of_TLVs[tlv_index])
	{
		switch (*(uint8_t*)recv_cmdu->list_of_TLVs[tlv_index])
		{
			case TLV_TYPE_AL_MAC_ADDRESS_TYPE:
			{
				al_mac_tlv = (struct alMacAddressTypeTLV*)recv_cmdu->list_of_TLVs[tlv_index];
				break;
			}
			case TLV_TYPE_MAC_ADDRESS_TYPE:
			{
				upstream_mac_tlv = (struct macAddressTypeTLV*) recv_cmdu->list_of_TLVs[tlv_index];
			}
			default:
			{
				// Skip the 1905 TLVs
				break;
			}
		}
		++tlv_index;
	}

	// This will update the topology tree
	map_ale_info_t *ale = get_ale(al_mac_tlv->al_mac_address);
	if(ale == NULL) {
		ale = create_ale(al_mac_tlv->al_mac_address);
		if(ale) {
			map_send_topology_query(map_handle);
		}
		else
			return;
	}

        // Store the last received topology discovery message
        ale->keep_alive_time = get_current_time();

	// Update the topology tree
	map_add_neighbour_of_agent(ale);

	// Update the BSTA interface mac
	memcpy(ale->upstream_local_iface_mac, upstream_mac_tlv->mac_address, MAC_ADDR_LEN);

        // Update Upstream Remote interface mac
        struct interfaceInfo m = {0};
        platform_get(MAP_PLATFORM_GET_INTERFACE_INFO, recv_cmdu->interface_name, (void *)&m);
        memcpy(ale->upstream_remote_iface_mac, m.mac_address, MAC_ADDR_LEN);

        // Update the receiving interface name.
        strncpy(ale->iface_name, recv_cmdu->interface_name, MAX_IFACE_NAME_LEN);

Cleanup:
	if (NULL != recv_cmdu)
		lib1905_cmdu_cleanup(recv_cmdu);

	return;
}
int map_send_channel_select_response(map_handle_t   *map_handle)
{

        uint8_t                               *p                    = NULL;
        struct mapChannelPreferenceTLV        *channel_pref_tlv     = NULL;
        int                                   tlv_cnt               = 0;
        map_radio_info_t                      *radio_node           = NULL;
        struct mapChannelSelectionResponseTLV *channel_sel_resp_tlv = NULL;  
        int ret = -1;
    
        // Map Handle parameters Validation
        if (NULL == map_handle->dest_addr || NULL == map_handle->recv_cmdu || (-1 == map_handle->handle_1905))
        {
            platform_log(MAP_AGENT,LOG_ERR,"Map Handle parameters Validation Failed");
            goto Cleanup;
        }

        uint8_t *list_of_tlv[MAX_RADIOS_PER_AGENT] = {0};
        uint8_t i                                  = 0;
        int     if_len                             = 0;
        struct CMDU                     *recv_cmdu = (struct CMDU*)map_handle->recv_cmdu;
        struct CMDU cmdu = {
	                  .message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013,
	                  .message_type     =  CMDU_TYPE_MAP_CHANNEL_SELECTION_RESPONSE,
	                  .message_id       =  recv_cmdu->message_id,
	                  .relay_indicator  =  0,
                          .list_of_TLVs     =  list_of_tlv,
                        };


        if_len = sizeof(cmdu.interface_name);
	strncpy(cmdu.interface_name, map_handle->src_iface_name, if_len);
	cmdu.interface_name[if_len - 1] = '\0';

        tlv_cnt = 0;

        /* Construct the channel selection response for each channel preference TLV in the channel selection request*/
	while (NULL != (p = recv_cmdu->list_of_TLVs[i])) {
        switch (*p) {
        case TLV_TYPE_CHANNEL_PREFERENCE:
         {
       
             channel_pref_tlv = (struct mapChannelPreferenceTLV *)p; 
             channel_sel_resp_tlv = (struct mapChannelSelectionResponseTLV *) calloc (1,sizeof(struct mapChannelSelectionResponseTLV));
             if(channel_sel_resp_tlv == NULL) {
                 platform_log(MAP_AGENT,LOG_ERR,"calloc failed in init_cmdu");
                 goto Cleanup;
             }

             radio_node = map_get_channel_selection_tlv(channel_sel_resp_tlv, channel_pref_tlv, &ret);
             if (radio_node == NULL) {
                 platform_log(MAP_AGENT,LOG_ERR,"%s: %d Channel Preference TLV  map_get failed",__func__, __LINE__);
                 free(channel_sel_resp_tlv);
                 goto Cleanup;
             }
             cmdu.list_of_TLVs[tlv_cnt++] = (uint8_t *)channel_sel_resp_tlv;
             break;
         }
        }
        i++;
    }

    cmdu.list_of_TLVs[tlv_cnt] = 0;

    if (lib1905_send(map_handle->handle_1905, &cmdu.message_id, map_handle->dest_addr, &cmdu)<0) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
        goto Cleanup;
    }

Cleanup:

   for (i = 0; i<tlv_cnt; i++) {
       free_1905_TLV_structure(cmdu.list_of_TLVs[i]);
   }
   return ret;
}

int map_send_operating_channel_report (void   *data)
{
	/* Operating Channel TLV TBD */
    uint8_t         number_of_tlv     = 0;
    uint8_t         relay_indicator   = 0;
    uint8_t         *dst_addr         = NULL;
    struct          CMDU *cmdu        = NULL;
    uint16_t        mid               = 0;
    uint8_t         i                 = 0;
    handle_1905_t   handle;
    map_handle_t   *map_handle =  (map_handle_t   *)data;
    int if_len;

	/* Ideally there are 2 TLV's sent for each radio. But radio operation restriction TLV is not applicable 
	here because getting channel restriction is not supported at all (HW limitation). So that
	TLV is not considered */
    struct mapOperatingChannelReportTLV *oper_channel_tlv = NULL;  

    // Map Handle parameters Validation
    if (NULL == map_handle->dest_addr || (-1 == map_handle->handle_1905))
{
        platform_log(MAP_AGENT,LOG_ERR,"Map Handle parameters Validation Failed");
        goto Cleanup;
    }

    dst_addr        =  map_handle->dest_addr;
    handle          =  map_handle->handle_1905;

	/* This need not be same message id as channel selection query */
    mid = 0;

	//## init payload CMDU
	cmdu = (struct CMDU *) calloc(1,sizeof(struct CMDU));

	if (NULL == cmdu) {
		platform_log(MAP_AGENT,LOG_ERR,"CMDU malloc failed");
		goto Cleanup;
	}

	cmdu->message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
	cmdu->message_type	   =  CMDU_TYPE_MAP_OPERATING_CHANNEL_REPORT;
	cmdu->message_id	   =  mid;
	cmdu->relay_indicator  =  relay_indicator;

	if_len = strlen(map_handle->src_iface_name);
	strncpy(cmdu->interface_name, map_handle->src_iface_name, if_len);
	cmdu->interface_name[if_len] = '\0';

	/*
	* Determine total number of tlvs to allocate memory prior to allocation
	* because it is always better to first determine the count and do a
	* calloc in one-shot rather than counting tlvs on the fly and doing
	* realloc as when we find that the tlv should be added as part of the cmdu
	*/

	//## For Operating Channel TLV
	number_of_tlv += gmap_agent->num_radios;

	cmdu->list_of_TLVs  =  (uint8_t **)calloc(number_of_tlv+1, sizeof(uint8_t *));
    	if(cmdu->list_of_TLVs == NULL) {
            platform_log(MAP_AGENT,LOG_ERR,"calloc failed in init_cmdu");
       	    goto Cleanup;
        }	

	for (i = 0; i < gmap_agent->num_radios; i++) {
            oper_channel_tlv = (struct mapOperatingChannelReportTLV *) calloc (1,sizeof(struct mapOperatingChannelReportTLV));
            if(oper_channel_tlv == NULL)
            {
                platform_log(MAP_AGENT,LOG_ERR,"calloc failed in init_cmdu");
                goto Cleanup;
            }
    
            //## Add Channel Preference TLV
            if (map_get_oper_channel_tlv(oper_channel_tlv, i) < 0)
            {
                platform_log(MAP_AGENT,LOG_ERR,"%s: %d Channel Preference TLV  map_get failed",__func__, __LINE__);
                free(oper_channel_tlv);
                goto Cleanup;
            }
            else
            {
                  cmdu->list_of_TLVs[i]     = (uint8_t *)oper_channel_tlv;
            }
	}

	if (i != number_of_tlv) {
		printf("%s: %d Count mismatch",__func__, __LINE__);
		platform_log(MAP_AGENT,LOG_ERR,"%s: %d Count mismatch",__func__, __LINE__);
        }

	cmdu->list_of_TLVs[number_of_tlv]  = 0;

	if (lib1905_send(handle, &mid, dst_addr, cmdu)<0) {
		platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu->message_type);
		goto Cleanup;
	}	
	
Cleanup:
	if (NULL != cmdu)
		lib1905_cmdu_cleanup(cmdu);

    operating_channel_pending_in_timer = 0;
    return 0;
}

int inline get_vht_mcs(int count, uint8_t max_supported_stream)
{
  if(count < max_supported_stream)
    return VHT_CAP_MCS_0_9;
  else
    return VHT_CAP_MCS_NONE;
}

void map_send_ap_capability_report(uv_work_t *req, int status)
{
    uint8_t         number_of_tlv     = 1;
    uint8_t         prev_count        = 0;
    uint8_t         relay_indicator   = 0;
    uint8_t         *dst_addr         = NULL;
    struct          CMDU *cmdu        = NULL;
    struct          CMDU *recv_cmdu   = NULL;
    uint16_t        mid               = 0;
    uint8_t         i                 = 0;
    map_handle_t   *map_handle        = NULL;
    handle_1905_t   handle;
    int if_len;
    int counter;

    struct mapAPCapabilityTLV       *ap_capability_tlv        = NULL;  // 2 Bytes
    struct mapApBasicCapabilityTLV  *ap_basic_capability_tlv  = NULL;  // (<= 1991) * n radios Bytes
    struct mapAPHTCapabilityTLV     *ap_ht_capability_tlv     = NULL;  // 8 * n radios Bytes
    struct mapAPVHTCapabilityTLV    *ap_vht_capability_tlv    = NULL;  // 13 * n radios Bytes
    struct mapAPHECapabilityTLV     *ap_he_capability_tlv     = NULL;  // (10 + mcs) * n radios Bytes

    // Input Parameters Validation
    if (NULL == req || NULL == req->data)
    {
        platform_log(MAP_AGENT,LOG_ERR,"Input Parameters Validation");
        goto Cleanup;
    }

    wq_args* p_args = (wq_args*)req->data;

    // Map Handle Validation
    if (NULL == p_args)
    {
        platform_log(MAP_AGENT,LOG_ERR,"Map Handle Validation Failed");
        goto Cleanup;
    }

    map_handle      = (map_handle_t *)p_args->wqdata;

    // Map Handle parameters Validation
    if (NULL == map_handle->dest_addr || NULL == map_handle->recv_cmdu || (-1 == map_handle->handle_1905))
    {
        platform_log(MAP_AGENT,LOG_ERR,"Map Handle parameters Validation Failed");
        goto Cleanup;
    }

    dst_addr        =  map_handle->dest_addr;
    handle          =  map_handle->handle_1905;
    recv_cmdu       =  map_handle->recv_cmdu;

    mid = recv_cmdu->message_id;

    //## init payload CMDU
    cmdu = (struct CMDU *) calloc(1,sizeof(struct CMDU));

    if (NULL == cmdu) {
        platform_log(MAP_AGENT,LOG_ERR,"CMDU malloc failed");
        goto Cleanup;
    }

    cmdu->message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu->message_type     =  CMDU_TYPE_MAP_AP_CAPABILITY_REPORT;
    cmdu->message_id       =  mid;
    cmdu->relay_indicator  =  relay_indicator;

    if_len = strlen(map_handle->src_iface_name);
    strncpy(cmdu->interface_name, map_handle->src_iface_name, if_len);
    cmdu->interface_name[if_len] = '\0';

    /*
     * Determine total number of tlvs to allocate memory prior to allocation
     * because it is always better to first determine the count and do a
     * calloc in one-shot rather than counting tlvs on the fly and doing
     * realloc as when we find that the tlv should be added as part of the cmdu
     */

    //## For AP basic capability TLV
    number_of_tlv += gmap_agent->num_radios;

    for (i = 0; i < gmap_agent->num_radios; i++)
    {
        //## For AP HT Capabilities TLV
        if ((gmap_agent->radio_list[i]->radio_caps.supported_standard == STD_80211_N) ||
                (gmap_agent->radio_list[i]->radio_caps.supported_standard == STD_80211_AN) ||
                (gmap_agent->radio_list[i]->radio_caps.supported_standard == STD_80211_AC) ||
                (gmap_agent->radio_list[i]->radio_caps.supported_standard == STD_80211_ANAC))
        {
            number_of_tlv++;
        }

        //## For AP VHT Capabilities TLV
        if ((gmap_agent->radio_list[i]->radio_caps.supported_standard == STD_80211_AC) ||
            (gmap_agent->radio_list[i]->radio_caps.supported_standard == STD_80211_ANAC))

        {
            number_of_tlv++;
        }

        //## For AP HE Capabilities TLV
        if (gmap_agent->radio_list[i]->radio_caps.supported_standard == STD_80211_AX)
        {
            number_of_tlv++;
        }
    }

    cmdu->list_of_TLVs  =  (uint8_t **)calloc(number_of_tlv+1, sizeof(uint8_t *));
    if(cmdu->list_of_TLVs == NULL) {
       platform_log(MAP_AGENT,LOG_ERR,"calloc failed in init_cmdu");
       goto Cleanup;
    }

    //## Add AP capability TLV
    ap_capability_tlv = (struct mapAPCapabilityTLV *) calloc (1,sizeof(struct mapAPCapabilityTLV));
    if (NULL == ap_capability_tlv)
    {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d Calloc failed for ap_capability_tlv",__func__, __LINE__);
        goto Cleanup;
    }

    ap_capability_tlv->tlv_type                                = TLV_TYPE_AP_CAPABILITY;

    ap_capability_tlv->operating_unsupported_link_metrics      = gmap_agent->agent_capability.ib_unassociated_sta_link_metrics_supported;
    ap_capability_tlv->non_operating_unsupported_link_metrics  = gmap_agent->agent_capability.oob_unassociated_sta_link_metrics_supported;

    ap_capability_tlv->agent_initiated_steering                = 0; //Currently not supported, will add support later
    ap_capability_tlv->reserved                                = 0;

    cmdu->list_of_TLVs[0] = (uint8_t *)ap_capability_tlv;
    prev_count = 1;

    for (i = 0; i < gmap_agent->num_radios; i++)
    {
        ap_basic_capability_tlv = (struct mapApBasicCapabilityTLV *) calloc (1,sizeof(struct mapApBasicCapabilityTLV));
        if (NULL == ap_basic_capability_tlv)
        {
            platform_log(MAP_AGENT,LOG_ERR,"%s: %d Calloc failed for ap_basic_capability_tlv",__func__, __LINE__);
            goto Cleanup;
        }

        //## Add AP basic capability TLV
        if (map_get_ap_basic_cap_tlv(ap_basic_capability_tlv, i) < 0)
        {
            platform_log(MAP_AGENT,LOG_ERR,"%s: %d AP_BASIC_CAP  map_get failed",__func__, __LINE__);
            goto Cleanup;
        }

        else
        {
            cmdu->list_of_TLVs[prev_count++]     = (uint8_t *)ap_basic_capability_tlv;

            if ((gmap_agent->radio_list[i]->radio_caps.supported_standard == STD_80211_N) ||
                (gmap_agent->radio_list[i]->radio_caps.supported_standard == STD_80211_AN) ||
                (gmap_agent->radio_list[i]->radio_caps.supported_standard == STD_80211_AC) ||
                (gmap_agent->radio_list[i]->radio_caps.supported_standard == STD_80211_ANAC))
            {
                //## Add AP HT Capabilities TLV
                ap_ht_capability_tlv = (struct mapAPHTCapabilityTLV *) calloc (1,sizeof(struct mapAPHTCapabilityTLV));
                if (NULL == ap_ht_capability_tlv)
                {
                    platform_log(MAP_AGENT,LOG_ERR,"%s: %d Calloc failed for ap_ht_capability_tlv",__func__, __LINE__);
                    goto Cleanup;
                }

                ap_ht_capability_tlv->tlv_type                 = TLV_TYPE_AP_HT_CAPABILITY;

                memcpy(ap_ht_capability_tlv->radio_id, gmap_agent->radio_list[i]->radio_id, MAC_ADDR_LEN);

                ap_ht_capability_tlv->max_supported_tx_streams = gmap_agent->radio_list[i]->radio_caps.max_tx_spatial_streams-1;
                ap_ht_capability_tlv->max_supported_rx_streams = gmap_agent->radio_list[i]->radio_caps.max_rx_spatial_streams-1;

                ap_ht_capability_tlv->gi_support_20mhz     = gmap_agent->radio_list[i]->radio_caps.sgi_support;

                if (gmap_agent->radio_list[i]->radio_caps.max_bandwidth >= 40)
                {
                    ap_ht_capability_tlv->gi_support_40mhz     = gmap_agent->radio_list[i]->radio_caps.sgi_support;
                    ap_ht_capability_tlv->ht_support_40mhz     = 1;
                }
                cmdu->list_of_TLVs[prev_count++] = (uint8_t *)ap_ht_capability_tlv;
            }

            if ((gmap_agent->radio_list[i]->radio_caps.supported_standard == STD_80211_AC) ||
                (gmap_agent->radio_list[i]->radio_caps.supported_standard == STD_80211_ANAC))

            {
                //## Add AP VHT Capabilities TLV
                ap_vht_capability_tlv = (struct mapAPVHTCapabilityTLV *) calloc (1,sizeof(struct mapAPVHTCapabilityTLV));
                if (NULL == ap_vht_capability_tlv)
                {
                    platform_log(MAP_AGENT,LOG_ERR,"%s: %d Calloc failed for ap_vht_capability_tlv",__func__, __LINE__);
                    goto Cleanup;
                }

                ap_vht_capability_tlv->tlv_type                 = TLV_TYPE_AP_VHT_CAPABILITY;

                memcpy(ap_vht_capability_tlv->radio_id,gmap_agent->radio_list[i]->radio_id,MAC_ADDR_LEN);

                ap_vht_capability_tlv->max_supported_tx_streams = gmap_agent->radio_list[i]->radio_caps.max_tx_spatial_streams-1;
                ap_vht_capability_tlv->max_supported_rx_streams = gmap_agent->radio_list[i]->radio_caps.max_rx_spatial_streams-1;

                ap_vht_capability_tlv->supported_tx_mcs = 0;
                ap_vht_capability_tlv->supported_rx_mcs = 0;

                for (counter = 0;counter<8;counter++ )
                {
                  ap_vht_capability_tlv->supported_tx_mcs |= (get_vht_mcs(counter,gmap_agent->radio_list[i]->radio_caps.max_tx_spatial_streams)<<(counter*2));
                  ap_vht_capability_tlv->supported_rx_mcs |= (get_vht_mcs(counter,gmap_agent->radio_list[i]->radio_caps.max_rx_spatial_streams)<<(counter*2));
                }

                if (gmap_agent->radio_list[i]->radio_caps.max_bandwidth >= 80)
                    ap_vht_capability_tlv->gi_support_80mhz     = gmap_agent->radio_list[i]->radio_caps.sgi_support;

                if (gmap_agent->radio_list[i]->radio_caps.max_bandwidth >= 160) {
                    ap_vht_capability_tlv->gi_support_160mhz    = gmap_agent->radio_list[i]->radio_caps.sgi_support;
                    ap_vht_capability_tlv->support_160mhz       = 1;
                }

                ap_vht_capability_tlv->su_beamformer_capable    = gmap_agent->radio_list[i]->radio_caps.su_beamformer_capable;
                ap_vht_capability_tlv->mu_beamformer_capable    = gmap_agent->radio_list[i]->radio_caps.mu_beamformer_capable;

                cmdu->list_of_TLVs[prev_count++] = (uint8_t *)ap_vht_capability_tlv;
            }

            if (gmap_agent->radio_list[i]->radio_caps.supported_standard == STD_80211_AX)
            {
                //## Add AP HE Capabilities TLV
                ap_he_capability_tlv = (struct mapAPHECapabilityTLV *) calloc (1,sizeof(struct mapAPHECapabilityTLV));
                if (NULL == ap_he_capability_tlv)
                {
                    platform_log(MAP_AGENT,LOG_ERR,"%s: %d Calloc failed for ap_he_capability_tlv",__func__, __LINE__);
                    goto Cleanup;
                }

                ap_he_capability_tlv->tlv_type                  = TLV_TYPE_AP_HE_CAPABILITY;

                memcpy(ap_he_capability_tlv->radio_id,gmap_agent->radio_list[i]->radio_id,MAC_ADDR_LEN);

                //## For now, supported Tx and Rx MCS are not added, if applicable please include

                ap_he_capability_tlv->max_supported_tx_streams = gmap_agent->radio_list[i]->radio_caps.max_tx_spatial_streams-1;
                ap_he_capability_tlv->max_supported_rx_streams = gmap_agent->radio_list[i]->radio_caps.max_rx_spatial_streams-1;

                if (gmap_agent->radio_list[i]->radio_caps.max_bandwidth >= 160)
                    ap_he_capability_tlv->support_160mhz       = 1;

                ap_he_capability_tlv->su_beamformer_capable    = gmap_agent->radio_list[i]->radio_caps.su_beamformer_capable;
                ap_he_capability_tlv->mu_beamformer_capable    = gmap_agent->radio_list[i]->radio_caps.mu_beamformer_capable;

                cmdu->list_of_TLVs[prev_count++] = (uint8_t *)ap_he_capability_tlv;
            }
        }
    }
    if (prev_count != number_of_tlv)
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d Count mismatch",__func__, __LINE__);

    cmdu->list_of_TLVs[number_of_tlv]  = 0;

    if (lib1905_send(handle, &mid, dst_addr, cmdu)<0) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu->message_type);
        goto Cleanup;
    }

    goto Cleanup;

Cleanup:
    if (NULL != recv_cmdu)
        lib1905_cmdu_cleanup(recv_cmdu);

    if (NULL != cmdu)
        lib1905_cmdu_cleanup(cmdu);

    return;
}

int map_send_client_capability_query(map_handle_t *map_handle, uint8_t *sta_mac, uint8_t *bssid)
{
    uint8_t     *dst_addr         = NULL;
    struct CMDU cmdu              = {0};
    uint8_t     end_of_msg[]      = {0,0,0};
    uint8_t     *list[3];

    struct mapClientInfoTLV client_info_tlv = {0}; /* Length - 12 bytes */

    /* Client information validation */
    if(NULL == sta_mac || NULL == bssid) {
        platform_log(MAP_AGENT,LOG_ERR, "Client information validation failed");
        return -1;
    }

    /* Input Parameters Check */
    if (NULL == map_handle->dest_addr || (-1 == map_handle->handle_1905)) {
        platform_log(MAP_AGENT,LOG_ERR, "Map Handle validation failed");
        return -1;
    }
    dst_addr  =  map_handle->dest_addr;

    /* init payload CMDU */
    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     =  CMDU_TYPE_MAP_CLIENT_CAPABILITY_QUERY;
    cmdu.message_id       =  0;
    cmdu.relay_indicator  =  0;

    /* Add Client Info TLV */
    client_info_tlv.tlv_type  = TLV_TYPE_CLIENT_INFO;
    memcpy(client_info_tlv.bssid, bssid, MAC_ADDR_LEN);
    memcpy(client_info_tlv.client_mac, sta_mac, MAC_ADDR_LEN);

    list[0] = (uint8_t *)&client_info_tlv;
    list[1] = end_of_msg;
    list[2] = NULL;

    /* Inorder to avoid malloc for very small memories, stack variables are used. */
    cmdu.list_of_TLVs  = list;

    /* Interface name is all because agent does not know trough which interface the target agent can be reached */
    strncpy(cmdu.interface_name, "all", sizeof(cmdu.interface_name));

    if (lib1905_send(map_handle->handle_1905, &map_handle->mid, dst_addr, &cmdu)) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
        return -1;
    }

    return 0;
}

int map_send_higher_layer_data_msg(map_handle_t *map_handle, uint32_t payload_len, uint32_t protocol, uint8_t *payload)
{
    uint8_t *dst_addr = NULL;
    struct CMDU cmdu = {0};
    uint8_t     *list[2] = {0};

    struct mapHigherLayerDataTLV *higher_layer_info_tlv = NULL;
    
    /* Input Parameters Check */
    if (NULL == map_handle->dest_addr || (-1 == map_handle->handle_1905) || (NULL == map_handle->src_iface_name)) {
        platform_log(MAP_AGENT,LOG_ERR, "Map Handle validation failed");
        return -1;
    }

    dst_addr  =  map_handle->dest_addr;
    
    /* init payload CMDU */
    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     =  CMDU_TYPE_MAP_HIGHER_LAYER_DATA;
    cmdu.message_id       =  0;
    cmdu.relay_indicator  =  0;
    
    higher_layer_info_tlv = calloc(sizeof(higher_layer_data_tlv_t),1);

    if (higher_layer_info_tlv == NULL) {
        platform_log(MAP_AGENT,LOG_ERR, "%s: Memory allocation failure\n", __FUNCTION__);
        goto HL_FAILURE;
    }

   /* Add Higher layer data Info TLV */
    higher_layer_info_tlv->tlv_type    = TLV_TYPE_HIGHER_LAYER_DATA_MSG;
    higher_layer_info_tlv->higher_layer_proto = protocol;
    higher_layer_info_tlv->tlv_length  += ONE_OCTET;
    
    if(payload) {
        
        higher_layer_info_tlv->payload = calloc(sizeof(uint8_t) * payload_len,1);

        if (higher_layer_info_tlv->payload) {
            memcpy(higher_layer_info_tlv->payload, payload, (sizeof(uint8_t))*payload_len);
            higher_layer_info_tlv->tlv_length += (sizeof(uint8_t) * payload_len);
        } else {
             platform_log(MAP_AGENT,LOG_ERR, "%s: Payload Memory allocation failure\n", __FUNCTION__);
             goto HL_FAILURE;
        }
    } else {
        platform_log(MAP_AGENT,LOG_ERR, "%s: Payload is null\n",__FUNCTION__);
    }

    list[0] = (uint8_t *)higher_layer_info_tlv;

    cmdu.list_of_TLVs  = list;
    strncpy(cmdu.interface_name, "all", sizeof(cmdu.interface_name));
    
    if (lib1905_send(map_handle->handle_1905, &map_handle->mid, dst_addr, &cmdu)) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
        goto HL_FAILURE;
    }

    return 0;

HL_FAILURE:
    if(higher_layer_info_tlv) {
        if(higher_layer_info_tlv->payload) {
            free(higher_layer_info_tlv->payload);
            higher_layer_info_tlv->payload = NULL;
        }
        free(higher_layer_info_tlv);
        higher_layer_info_tlv = NULL;
    }
    return -1;

}


void map_send_client_capability_report(uv_work_t *req, int status)
{
    uint8_t     *dst_addr             = NULL;
    uint8_t     *assoc_frame          = NULL; /* NOTE: DO NOT ALLOCATE memory for assoc_frame, since it will allocated in is_sta_valid cb */
    uint16_t    assoc_frame_len       = 0;
    struct      CMDU *recv_cmdu       = NULL;
    map_handle_t *map_handle          = NULL;

#define MAX_TLVS_STA_CAPABILITY_REPORT 5
    struct      CMDU  cmdu;
    uint8_t     *list_of_tlvs[MAX_TLVS_STA_CAPABILITY_REPORT]       = {0};
    uint8_t     error_code;
    uint8_t     sta_present = 1;

    struct mapClientInfoTLV              *client_info_tlv              ;
    struct mapClientCapabilityReportTLV  client_capability_report_tlv ;
    struct mapErrorCodeTLV               error_code_tlv               ;

    /* Input Parameters Validation */
    if (NULL == req || NULL == req->data)
    {
        platform_log(MAP_AGENT,LOG_ERR,"Input Parameters Validation");
        goto Cleanup;
    }
    wq_args* p_args = (wq_args*)req->data;

    /* Map Handle Validation */
    if (NULL == p_args)
    {
        platform_log(MAP_AGENT,LOG_ERR,"Map Handle Validation Failed");
        goto Cleanup;
    }
    map_handle      = (map_handle_t *)p_args->wqdata;

    /* Map Handle parameters Validation - "if" statement is left to right parsing*/
    if (NULL == map_handle || NULL == map_handle->dest_addr || NULL == map_handle->recv_cmdu || (-1 == map_handle->handle_1905))
    {
        platform_log(MAP_AGENT,LOG_ERR,"Map Handle parameters Validation Failed");
        goto Cleanup;
    }
    dst_addr        =  map_handle->dest_addr;
    recv_cmdu       =  map_handle->recv_cmdu;

    if (recv_cmdu == NULL || NULL == recv_cmdu->list_of_TLVs)
    {
        platform_log(MAP_AGENT,LOG_CRIT,"Client Capability Query Malformed structure.");
        goto Cleanup;
    }

    /* init payload CMDU */
    memset(&cmdu, 0, sizeof(struct CMDU));

    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     =  CMDU_TYPE_MAP_CLIENT_CAPABILITY_REPORT;
    cmdu.message_id       =  recv_cmdu->message_id;
    cmdu.relay_indicator  =  0;

    strncpy(cmdu.interface_name, map_handle->src_iface_name, INTERFACE_STR_LEN);

    /* Get Client Info TLV from received query */
    client_info_tlv = (struct mapClientInfoTLV *) map_get_tlv_from_cmdu(recv_cmdu,TLV_TYPE_CLIENT_INFO);
    if (NULL == client_info_tlv)
    {
        platform_log(MAP_AGENT,LOG_ERR, "No Client Info Tlv in CLient Capability Query message");
        goto Cleanup;
    }

    /* Check if the STA is associated with any of the BSS */
    if (get_assoc_request(client_info_tlv->client_mac, client_info_tlv->bssid, &assoc_frame_len, &assoc_frame) < 0) {
        /* STA is not present */
        sta_present = 0;
    }

    cmdu.list_of_TLVs    = list_of_tlvs;

    /* Add Client Info TLV */
    cmdu.list_of_TLVs[0] = (uint8_t *)client_info_tlv;

    memset(&client_capability_report_tlv, 0, sizeof(client_capability_report_tlv));

    client_capability_report_tlv.tlv_type   = TLV_TYPE_CLIENT_CAPABILITY_REPORT;
    client_capability_report_tlv.tlv_length = assoc_frame_len + 1;

    /* Add Client Capability TLV */
    cmdu.list_of_TLVs[1] = (uint8_t *)&client_capability_report_tlv;

    if (0 == assoc_frame_len) {
        /* Error Scenario - either sta not associated or unable to add association frame*/

        client_capability_report_tlv.result_code = FAILURE;

        error_code = (1 == sta_present) ? UNSPECIFIED_FAILURE : STA_UNASSOCIATED;
        if (-1 == get_error_code_tlv(&error_code_tlv, error_code, client_info_tlv->client_mac))
        {
            platform_log(MAP_AGENT,LOG_ERR, "Get Error Code TLV failed");
            goto Cleanup;
        }
        /* Add Error code TLV */
        cmdu.list_of_TLVs[2] = (uint8_t *)&error_code_tlv;
    } else {
        // Succes scenario - STA is associated and able to report client capability
        client_capability_report_tlv.result_code      = SUCCESS;
        client_capability_report_tlv.assoc_frame_len  = assoc_frame_len;
        client_capability_report_tlv.assoc_frame    = assoc_frame;
    }

    if (lib1905_send(map_handle->handle_1905, &cmdu.message_id, dst_addr, &cmdu)<0) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
    }

Cleanup:
    if (NULL != recv_cmdu)
        lib1905_cmdu_cleanup(recv_cmdu);

    return;
}

void map_send_topology_response(uv_work_t *req, int status)
{
    struct   CMDU  cmdu       = {0};
    struct   CMDU *recv_cmdu  = NULL;
    map_handle_t *map_handle  = NULL;
    int      total_sta_count  = 0;
    int      no_of_tlvs       = 0;
    int      tlv_count        = 0;
    int      i                = 0;
    int      neighbor_count   = 0;
    int      non1905_neighbor_count = 0;

#define  BASIC_TLVS_FOR_TOPOLOGY_RESP 4 /*DEVICE INFO + SUPPORTED SERVICE + AP OPERATIONAL + NULL tlv*/

    struct deviceInformationTypeTLV     device_info_tlv        = {0};
    struct deviceBridgingCapabilityTLV  bridge_info_tlv        = {0};
    struct mapSupportedServiceTLV       supported_service_tlv  = {0};
    struct mapApOperationalBssTLV       ap_operational_bss_tlv = {0};
    struct mapAssociatedClientsTLV      assoc_sta_tlv          = {0}; /* Zero or more tlv */
    struct neighborDeviceListTLV        neighbor_1905_tlvs[MAX_INTERFACE_COUNT]    = {0}; /* Zero or more tlv */
    struct non1905NeighborDeviceListTLV non1905_neighbor_tlvs[MAX_INTERFACE_COUNT] = {0}; /* Zero or more tlv */

    /* Input Parameters Validation */
    if (NULL == req || NULL == req->data)
    {
        platform_log(MAP_AGENT,LOG_ERR,"Input Parameters Validation");
        goto Cleanup;
    }
    wq_args* p_args = (wq_args*)req->data;

    /* Map Handle Validation */
    if (NULL == p_args->wqdata)
    {
        platform_log(MAP_AGENT,LOG_ERR,"Map Handle Validation Failed");
        goto Cleanup;
    }
    map_handle = (map_handle_t *)p_args->wqdata;

    /* Map Handle parameters Validation - "if" statement is left to right parsing*/
    if (NULL == map_handle || NULL == map_handle->dest_addr || NULL == map_handle->recv_cmdu || (-1 == map_handle->handle_1905))
    {
        platform_log(MAP_AGENT,LOG_ERR,"Map Handle parameters Validation Failed");
        goto Cleanup;
    }
    recv_cmdu =  map_handle->recv_cmdu;

    if (recv_cmdu == NULL || NULL == recv_cmdu->list_of_TLVs)
    {
        platform_log(MAP_AGENT,LOG_ERR,"Topology Query Malformed structure.");
        goto Cleanup;
    }

    /* init payload CMDU */
    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     =  CMDU_TYPE_TOPOLOGY_RESPONSE;
    cmdu.message_id       =  recv_cmdu->message_id;
    cmdu.relay_indicator  =  0;
    strncpy(cmdu.interface_name, recv_cmdu->interface_name, sizeof(cmdu.interface_name));

    /* Get 1905 device information tlv */
    if (lib1905_get(map_handle->handle_1905, (lib1905_param_t)GET_1905_DEVICE_INFO_TLV, NULL, (void *) &device_info_tlv, NULL)) {
        platform_log(MAP_AGENT,LOG_ERR, "get_device_info_tlv failed");
        goto Cleanup;
    }

    /* Get 1905 bridge capability tlv */
    if (-1 == map_get_bridge_info_tlv(&bridge_info_tlv)) {
        platform_log(MAP_AGENT,LOG_ERR, "get_bridge_capability_tlv failed");
        goto Cleanup;
    }

    /* Get 1905 neighbors tlvs */
    if (-1 == map_get_1905_neighbor_tlvs((struct neighborDeviceListTLV *) &neighbor_1905_tlvs, &neighbor_count)) {
        platform_log(MAP_AGENT,LOG_ERR, "get_1905_neighbor_tlvs failed");
        goto Cleanup;
    }

    /* Get wireless tlvs */
    if (-1 == map_get_wireless_topology_response_tlvs(&ap_operational_bss_tlv, (struct non1905NeighborDeviceListTLV *) &non1905_neighbor_tlvs, &non1905_neighbor_count, &assoc_sta_tlv, &total_sta_count)) {
        platform_log(MAP_AGENT,LOG_ERR, "map_get_wireless_topology_reesponse_tlvs failed");
        goto Cleanup;
    }

    /* Get supported service tlv */
    supported_service_tlv.tlv_type           = TLV_TYPE_SUPPORTED_SERVICE;
    supported_service_tlv.tlv_length         = 2;
    supported_service_tlv.number_of_service  = 1;
    supported_service_tlv.supported_service_array[0] = MAP_ROLE_AGENT;

    /* Intilise list of tlvs */
    no_of_tlvs = BASIC_TLVS_FOR_TOPOLOGY_RESP + neighbor_count + non1905_neighbor_count;

    if (bridge_info_tlv.bridging_tuples_nr > 0) no_of_tlvs++; /*Increment for bridge tlv */
    if (total_sta_count > 0)                    no_of_tlvs++; /*Increment for assoc sta tlv */

    cmdu.list_of_TLVs = (uint8_t **) calloc(1, no_of_tlvs * sizeof(INT8U *));
    if (!cmdu.list_of_TLVs) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d calloc failed\n",__func__, __LINE__);
        goto Cleanup;
    }

    /* Add tlvs inside cmdu */
    cmdu.list_of_TLVs[tlv_count++] = (uint8_t *) &device_info_tlv; /* Device info */

    if (bridge_info_tlv.bridging_tuples_nr > 0) {
        cmdu.list_of_TLVs[tlv_count++] = (uint8_t *) &bridge_info_tlv; /* Bridge info */
    }

    for (i = 0; i < neighbor_count; i++) {
        cmdu.list_of_TLVs[tlv_count++] = (uint8_t *) &neighbor_1905_tlvs[i]; /* 1905 Neighbor tlvs */
    }

    for (i = 0; i < non1905_neighbor_count; i++) {
        cmdu.list_of_TLVs[tlv_count++] = (uint8_t *) &non1905_neighbor_tlvs[i]; /* NON 1905 Neighbor tlvs */
    }

    cmdu.list_of_TLVs[tlv_count++] = (uint8_t *) &supported_service_tlv;  /* Supported Service tlv */
    cmdu.list_of_TLVs[tlv_count++] = (uint8_t *) &ap_operational_bss_tlv; /* AP Operational BSS tlv */

    if(total_sta_count > 0) {
        cmdu.list_of_TLVs[tlv_count++] = (uint8_t *)&assoc_sta_tlv; /* Associated Sta tlv */
    }
    cmdu.list_of_TLVs[tlv_count++] = NULL;

    /* Check for tlv count */
    if (tlv_count != no_of_tlvs) {
        platform_log(MAP_AGENT,LOG_ERR,"\n%s: Tlv count mismatch",__func__);
        goto Cleanup;
    }

    if (lib1905_send(map_handle->handle_1905, &cmdu.message_id, map_handle->dest_addr, &cmdu) < 0) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__,cmdu.message_type);
    }

Cleanup:
    if(NULL != recv_cmdu)
        lib1905_cmdu_cleanup(recv_cmdu);

    /* Free Device Info tlv */
    if (NULL != device_info_tlv.local_interfaces)
        free(device_info_tlv.local_interfaces);

    /* Free Bridge info tlv */
    map_free_bridge_info_tlv (&bridge_info_tlv);

    /* Free 1905 neighbor tlvs */
    for (i = 0; i < neighbor_count; i++) {
        map_free_1905_neighbor_tlv(&neighbor_1905_tlvs[i]);
    }

    /* Free non 1905 neighbor tlvs */
    for (i = 0; i < non1905_neighbor_count; i++) {
        map_free_non1905_neighbor_tlv(&non1905_neighbor_tlvs[i]);
    }

    if (NULL != cmdu.list_of_TLVs)
        free(cmdu.list_of_TLVs);

    return;
}

int map_send_topology_notification(map_handle_t map_handle,void *data)
{
    stn_event_t *stn_event = (stn_event_t *)data;
    uint8_t     number_of_tlv   = 1;
    uint8_t     relay_indicator = 1;
    uint8_t     *dst_addr       = NULL;
    struct      CMDU cmdu       = {0};
    struct     CMDU *recv_cmdu  = NULL;
    handle_1905_t handle        = 0;
    char mac_str[MAX_MAC_STRING_LEN];
    struct alMacAddressTypeTLV      al_mac_tlv = {0};
    struct mapClientAssociationEventTLV client_asso_tlv = {0};
    map_ale_info_t *ale = NULL;
    map_ale_info_t *neighbor_ale = NULL;

    dst_addr  =  map_handle.dest_addr;
    handle    =  map_handle.handle_1905;
    recv_cmdu =  map_handle.recv_cmdu;

    //##Add Al mac address Tlv 
    if(lib1905_get(handle, (lib1905_param_t) GET_1905_ALMACTLV,	NULL , (void *)&al_mac_tlv, NULL)) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d AL_MAC TLV	lib1905_get failed",__func__, __LINE__);
        goto Failure;
    }

    if (NULL != stn_event) {
        //## Add Cient Association event TLV
        client_asso_tlv.tlv_type           = TLV_TYPE_CLIENT_ASSOCIATION_EVENT;
        client_asso_tlv.tlv_length         = 13;
        memcpy(client_asso_tlv.mac, stn_event->mac_addr, MAC_ADDR_LEN);
        memcpy(client_asso_tlv.bssid, stn_event->bssid, MAC_ADDR_LEN);
        client_asso_tlv.association_event = stn_event->association_event;
        number_of_tlv++;
    }

    //## init payload CMDU
    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     =  CMDU_TYPE_TOPOLOGY_NOTIFICATION;
    cmdu.message_id       =  0;
    cmdu.relay_indicator  =  relay_indicator;
    strncpy(cmdu.interface_name, "all", sizeof(cmdu.interface_name));

    cmdu.list_of_TLVs  =  (uint8_t **)calloc(number_of_tlv+1, sizeof(uint8_t *));
    if(cmdu.list_of_TLVs == NULL) {
        platform_log(MAP_AGENT,LOG_ERR,"%s %d, calloc failed list_of_TLVs", __func__, __LINE__);
        goto Failure;
    }

    cmdu.list_of_TLVs[0] = (uint8_t *)&al_mac_tlv;

    if (NULL != stn_event) {
        cmdu.list_of_TLVs[1] = (uint8_t *)&client_asso_tlv;
    }

    if (lib1905_send(handle, 0, dst_addr, &cmdu)) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
        free(cmdu.list_of_TLVs);
        goto Failure;
    }

    get_mac_as_str(dst_addr, (int8_t *)mac_str, MAX_MAC_STRING_LEN);
    platform_log(MAP_AGENT,LOG_DEBUG, "--> CMDU_TYPE_TOPOLOGY_NOTIFICATION-%s", mac_str);
    // Sending topology notification as unicast message to each neighbors
    ale = get_ale(al_mac_tlv.al_mac_address);
    if(ale == NULL)
        goto Failure;

    cmdu.relay_indicator  = 0;
    foreach_neighbors_of(ale, neighbor_ale) {
        if ((neighbor_ale == NULL) || (strcmp(neighbor_ale->iface_name,"lo") == 0))
            continue;

        strncpy(cmdu.interface_name, neighbor_ale->iface_name, sizeof(cmdu.interface_name));
        if (lib1905_send(handle, &cmdu.message_id, neighbor_ale->al_mac, &cmdu)<0) {
            platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for unicast msg type %d",__func__, __LINE__, cmdu.message_type);
            continue;
        }
        get_mac_as_str(neighbor_ale->al_mac, (int8_t *)mac_str, MAX_MAC_STRING_LEN);
        platform_log(MAP_AGENT,LOG_DEBUG, "--> CMDU_TYPE_TOPOLOGY_NOTIFICATION-%s", mac_str);
    }

    if(recv_cmdu != NULL)
        lib1905_cmdu_cleanup(recv_cmdu);
    free(cmdu.list_of_TLVs);

    return 0;

Failure:
    if(recv_cmdu != NULL)
        lib1905_cmdu_cleanup(recv_cmdu);
    return -EINVAL;

}

int build_assoc_sta_link_metrics_tlv(struct mapAssociatedStaLinkMetricsTLV * assoc_sta_link_met, map_sta_metrics_t * metrics) 
{
    /* 
     * As of now history of sta is out of scope, hence
     * reported bss count of sta be always 1
     */
    struct timespec current_time = {0};
    uint64_t interval            = 0;
    uint32_t interval_ms         = 0;

    if ((NULL == assoc_sta_link_met) || (NULL == metrics)) {
        platform_log(MAP_AGENT,LOG_ERR, "Input validation failed for function %s", __func__);
        return -1;
    }

    current_time = get_current_time();
    interval     = get_clock_diff_milli_secs(current_time, metrics->last_sta_metric_time);

    if (interval >= 0xffffffff)
        interval_ms = 0xffffffff;
    else
        interval_ms = (uint32_t) interval;

    assoc_sta_link_met->tlv_type = TLV_TYPE_ASSOCIATED_STA_LINK_METRICS;
    assoc_sta_link_met->reported_bssid_count                =  1;
    assoc_sta_link_met->sta_metrics[0].report_time_interval =  interval_ms;
    assoc_sta_link_met->sta_metrics[0].downlink_data_rate   =  metrics->link.dl_mac_datarate; 
    assoc_sta_link_met->sta_metrics[0].uplink_data_rate     =  metrics->link.ul_mac_datarate;
    assoc_sta_link_met->sta_metrics[0].uplink_rssi          =  metrics->link.rssi;

    return 0;
}

int build_assoc_sta_traffic_stats_tlv(struct mapAssocStaTrafficStatsTLV * assoc_sta_traffic_stats, map_sta_metrics_t * metrics) 
{
     assoc_sta_traffic_stats->tlv_type = TLV_TYPE_ASSOC_STA_TRAFFIC_STATS;
     assoc_sta_traffic_stats->tlv_length = MIN_ASSOC_STA_TRAFFIC_STATS_TLV_LEN;
     assoc_sta_traffic_stats->txbytes = metrics->traffic.txbytes;
     assoc_sta_traffic_stats->rxbytes = metrics->traffic.rxbytes;
     assoc_sta_traffic_stats->txpkts = metrics->traffic.txpkts;
     assoc_sta_traffic_stats->rxpkts   = metrics->traffic.rxpkts;
     assoc_sta_traffic_stats->txpkterrors =  metrics->traffic.txpkterrors;
     assoc_sta_traffic_stats->rxpkterrors =  metrics->traffic.rxpkterrors;
     assoc_sta_traffic_stats->retransmission_cnt =  metrics->traffic.retransmission_cnt;
     return 0;
}


int build_ap_metrics_tlv(struct mapApMetricsResponseTLV *ap_metrics_response, map_bss_info_t * bss_node)
{
     uint8_t i = 0;
     uint16_t sta_count = 0;

      ap_metrics_response->tlv_type = TLV_TYPE_AP_METRICS_RESPONSE;
      memcpy(ap_metrics_response->bssid, bss_node->bssid, ETHER_ADDR_LEN);
      ap_metrics_response->tlv_length = ETHER_ADDR_LEN;

      ap_metrics_response->channel_util = bss_node->metrics.channel_utilization;
      ap_metrics_response->tlv_length += 1;

      sta_count = list_get_size(bss_node->sta_list);

      ap_metrics_response->sta_count = sta_count;
      ap_metrics_response->tlv_length += 2;

      ap_metrics_response->esp_present = bss_node->metrics.esp_present;
      if(bss_node->metrics.esp_present == 0) {
          /* ESP info not found */
          return -EINVAL;
      }
      ap_metrics_response->tlv_length += 1;

      for(i = 0; i<MAX_ACCESS_CATEGORIES; i++) {
         if(bss_node->metrics.esp_present & (1<<(7-i))) {
             memcpy(&ap_metrics_response->esp[i], &bss_node->metrics.esp[i], sizeof(bss_node->metrics.esp[i]));
             ap_metrics_response->tlv_length += 3;
         }
      }

     return 0;
}

void map_build_ap_metrics (map_bss_info_t *bss_node, map_radio_info_t *radio_node, uint8_t **list_of_tlv, struct mapApMetricsResponseTLV *ap_metrics_response,
        struct mapAssocStaTrafficStatsTLV *assoc_sta_traffic_stats, struct mapAssociatedStaLinkMetricsTLV *assoc_sta_link_metrics, 
        uint8_t *sta_traffic_count, uint8_t *sta_link_count, uint8_t *bss_count, uint8_t *no_of_tlv)
{
    map_sta_info_t    *sta_node   = NULL;
    map_sta_metrics_t* metrics    = NULL;

    if(build_ap_metrics_tlv(ap_metrics_response, bss_node) <0) {
        return;
    }

    *list_of_tlv = (uint8_t *)ap_metrics_response;
    (*no_of_tlv)++;
    (*bss_count)++;

    list_iterator_t* it = new_list_iterator(bss_node->sta_list);
    while(it->iter != NULL)
    {
        uint8_t* sta_mac = (uint8_t*) get_next_list_object(it);
        if(sta_mac)
        {
            sta_node = get_sta(sta_mac);
            if(sta_node)
            {
                metrics = (map_sta_metrics_t*)object_at_index(sta_node->metrics, 0);
                if(radio_node->radio_policy.associated_sta_policy & MAP_ASSOC_STA_TRAFFIC_STA_INCLUSION_POLICY) {
                    build_assoc_sta_traffic_stats_tlv(assoc_sta_traffic_stats, metrics);
                    memcpy(assoc_sta_traffic_stats->sta_mac, sta_node->mac, ETHER_ADDR_LEN);
                    *(++list_of_tlv) = (uint8_t *)assoc_sta_traffic_stats;
                    assoc_sta_traffic_stats++;
                    (*no_of_tlv)++;
                    (*sta_traffic_count)++;
                }
                if(radio_node->radio_policy.associated_sta_policy & MAP_ASSOC_STA_LINK_METRICS_INCLUSION_POLICY) {
                    build_assoc_sta_link_metrics_tlv(assoc_sta_link_metrics, metrics);
                    memcpy(assoc_sta_link_metrics->sta_metrics[0].bssid, bss_node->bssid, ETHER_ADDR_LEN);
                    memcpy(assoc_sta_link_metrics->associated_sta_mac, sta_node->mac, ETHER_ADDR_LEN);
                    *(++list_of_tlv) = (uint8_t *)assoc_sta_link_metrics;
                    assoc_sta_link_metrics++;
                    (*no_of_tlv)++;
                    (*sta_link_count)++;
                }
            }
        }
    }
    free_list_iterator(it);
    return;                
}

void map_send_ap_metrics (uv_work_t *req, int status) 
{

    struct CMDU cmdu = {0};
    struct CMDU *recv_cmdu  = NULL;

    uint8_t *list_of_tlv[MAX_STATIONS + MAX_STATIONS + (MAX_BSS_PER_RADIO * MAX_RADIOS_PER_AGENT) + 1] = {0}; /* "+1" for EOF */
                         /* Link metrics + Traffic stats + Ap mterics tlvs */

    static struct mapApMetricsResponseTLV ap_metrics_response[(MAX_BSS_PER_RADIO * MAX_RADIOS_PER_AGENT)] = {{0}};
    static struct mapAssocStaTrafficStatsTLV assoc_sta_traffic_stats[MAX_STATIONS] = {{0}};
    static struct mapAssociatedStaLinkMetricsTLV assoc_sta_link_metrics[MAX_STATIONS] = {{0}};

    uint8_t assoc_traffic_sta_count = 0, assoc_sta_link_met_count = 0;

    uint16_t mid = 0;
    map_radio_info_t  *radio_node = NULL;
    map_bss_info_t    *bss_node   = NULL;
    map_handle_t      *map_handle = NULL;
    wq_args           *w_args     = NULL;

    uint8_t bss_nos = 0;
    uint8_t tlv_count = 0;
    uint8_t i = 0, j = 0, k = 0;

    w_args = (wq_args*)req->data;
    map_handle = w_args->wqdata;

    recv_cmdu =  map_handle->recv_cmdu;

    memset(&cmdu, 0, sizeof(struct CMDU));
    if(recv_cmdu == NULL) {
        /*
         * Cumulative unsolicated Ap metrics response
         */
         uint8_t radio_count = 0;
         ap_metrics_data_t* metrics_data = NULL;
         map_radio_info_t** radio_list   = NULL;

         metrics_data = (ap_metrics_data_t *) map_handle->data;

         if (NULL != metrics_data) {
             radio_count = metrics_data->radio_count;
             radio_list = (map_radio_info_t **) metrics_data->radio_list;
         }
         else {
             radio_count = gmap_agent->num_radios;
             radio_list = (map_radio_info_t **) &gmap_agent->radio_list;
         }

         for (k = 0; k < radio_count; k++) {
             radio_node = radio_list[k];

             if (NULL == radio_node) {
                 platform_log(MAP_AGENT,LOG_DEBUG, "Invalid Radio node");
                 continue;
             }

             if (1 != is_radio_on(radio_node->state)) {
                 platform_log(MAP_AGENT,LOG_DEBUG, "%s Radio off\n", __FUNCTION__);
                 continue;
             }

             if (1 == radio_node->radio_policy.report_metrics) {
                 for (j = 0; j < radio_node->num_bss; j++)
                 {
                    bss_node = radio_node->bss_list[j];
                    if(bss_node != NULL)
                    {
                        if (1 != is_bss_on(bss_node->state)) {
                            platform_log(MAP_AGENT,LOG_DEBUG, "%s Bss is turned off", __FUNCTION__);
                            continue;
                        }
                        uint8_t sta_link_count = 0, sta_traffic_count = 0, bss_count = 0, no_of_tlv = 0;;

                        map_build_ap_metrics(bss_node, radio_node, &list_of_tlv[tlv_count], &ap_metrics_response[bss_nos], &assoc_sta_traffic_stats[assoc_traffic_sta_count],
                            &assoc_sta_link_metrics[assoc_sta_link_met_count], &sta_traffic_count, &sta_link_count,  &bss_count, &no_of_tlv);
                            
                        assoc_traffic_sta_count += sta_traffic_count; 
                        assoc_sta_link_met_count += sta_link_count;
                        bss_nos += bss_count;
                        tlv_count += no_of_tlv;
                    }
                }
            }
        }
    } 
    else 
    {
        struct mapApMetricsQueryTLV  *ap_metrics_query_tlv = NULL;

        ap_metrics_query_tlv = (struct mapApMetricsQueryTLV  *)map_get_tlv_from_cmdu(recv_cmdu, TLV_TYPE_AP_METRICS_QUERY);
        if(ap_metrics_query_tlv == NULL) {
            if (NULL != recv_cmdu)
                lib1905_cmdu_cleanup(recv_cmdu);
            return;
        }

        mid = recv_cmdu->message_id;

        for(i = 0; i< ap_metrics_query_tlv->numBss; i++)
        {
            bss_node = get_bss(&ap_metrics_query_tlv->bssid[i][0]);
            if(bss_node != NULL)
            {
                uint8_t sta_link_count = 0, sta_traffic_count = 0, bss_count = 0, no_of_tlv = 0;
                radio_node = bss_node->radio;
                if(radio_node != NULL)
                {
                    map_build_ap_metrics(bss_node, radio_node, &list_of_tlv[tlv_count], &ap_metrics_response[bss_nos], &assoc_sta_traffic_stats[assoc_traffic_sta_count],
                            &assoc_sta_link_metrics[assoc_sta_link_met_count], &sta_traffic_count, &sta_link_count,  &bss_count, &no_of_tlv);
                                    
                    assoc_traffic_sta_count += sta_traffic_count; 
                    assoc_sta_link_met_count += sta_link_count;
                    bss_nos += bss_count;
                    tlv_count += no_of_tlv;
                }   
            }
            else
                platform_log(MAP_AGENT,LOG_ERR, "Invalid bss!!");   
        }
    }

    if(tlv_count > 0) { 
        cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
        cmdu.message_type     =  CMDU_TYPE_MAP_AP_METRICS_RESPONSE;
        cmdu.message_id       =  mid;
        cmdu.relay_indicator  =  0;
        strncpy(cmdu.interface_name, map_handle->src_iface_name, sizeof(cmdu.interface_name));
        cmdu.list_of_TLVs    = list_of_tlv;

        if (lib1905_send(map_handle->handle_1905, &mid, map_handle->dest_addr, &cmdu)<0) {
            platform_log(MAP_AGENT,LOG_ERR, "lib1905_send_failed for msg type %d\n",CMDU_TYPE_MAP_AP_METRICS_RESPONSE);
        }
    }
    if (NULL != map_handle->recv_cmdu)
        lib1905_cmdu_cleanup(map_handle->recv_cmdu);

    return;
}

int map_stations_assoc_control_apply (uint8_t action, uint8_t *bssid, array_list_t* block_sta_list)
{
    int i               = 0;
    int len             = 0;
    int sta_count       = 0;
    list_iterator_t* it = NULL;
    uint8_t *sta_mac    = NULL;
    client_acl_data_t *acl_data = NULL;
    map_monitor_cmd_t cmd;

    if ((NULL == bssid) || (NULL == block_sta_list))
    {
        platform_log(MAP_AGENT,LOG_ERR, "Input Parameters validation failed for function stations_assoc_control_apply");
        return -1;
    }

    sta_count = list_get_size(block_sta_list);

    if (sta_count > 0)
    {
        len = sizeof(client_acl_data_t) + (sta_count *  sizeof(station_list_t));
        acl_data = (client_acl_data_t *) calloc (1, len);

        if (NULL == acl_data) {
            platform_log(MAP_AGENT,LOG_ERR, "acl_data calloc failed");
            return -1;
        }

        acl_data->sta_count       = sta_count;
        acl_data->block           = action;
        memcpy(acl_data->bssid, bssid, MAC_ADDR_LEN);

        it = new_list_iterator(block_sta_list);
        if(!it) {
            platform_log(MAP_AGENT,LOG_ERR, "new_list_iterator failed");
            free(acl_data);
            return -1;
        }

        while(it->iter)
        {
            sta_mac = (uint8_t*) get_next_list_object(it);
            if(NULL == sta_mac)
            {
                platform_log(MAP_AGENT,LOG_ERR, "sta_mac is NULL");
                free_list_iterator(it);
                free(acl_data);
                return -1;
            }
            memcpy(acl_data->sta_list[i++].sta_mac, sta_mac, MAC_ADDR_LEN);
            sta_mac = NULL;
        }
        free_list_iterator(it);

        cmd.cmd    = MAP_MONITOR_SEND_UBUS_DATA_CMD;
        cmd.subcmd = MAP_MONITOR_CLIENT_ACL_REQUEST_METHOD_SUBCMD;
        cmd.param  = (void *)acl_data;
        if(0 != map_monitor_send_cmd(cmd)) {
            platform_log(MAP_AGENT,LOG_ERR, "%s send command to publish methods failed\n", __FUNCTION__);
            free(acl_data);
            return -1;
        }
    }

    return 0;
}

void map_send_association_control_response(uv_work_t *req, int status)
{
    int i   = 0;
    struct      CMDU *recv_cmdu       = NULL;
    map_handle_t *map_handle          = NULL;
    map_sta_info_t* sta               = NULL;
    array_list_t* associated_sta_list = NULL; /* List of STAs for which error code tlv need to be sent */
    array_list_t* block_sta_list      = NULL; /* List of STAs for which block/unblock has to be done */
    struct timespec curr_time         = get_current_time();

    struct mapClientAsociationControlRequestTLV *client_assoc_req_tlv = NULL;

    /* Input Parameters Validation */
    if (NULL == req || NULL == req->data)
    {
        platform_log(MAP_AGENT,LOG_ERR,"Input Parameters Validation");
        goto Cleanup;
    }
    wq_args* p_args = (wq_args*)req->data;

    /* Map Handle Validation */
    if (NULL == p_args)
    {
        platform_log(MAP_AGENT,LOG_ERR,"Map Handle Validation Failed");
        goto Cleanup;
    }
    map_handle = (map_handle_t *)p_args->wqdata;

    /* Map Handle parameters Validation - "if" statement is left to right parsing*/
    if (NULL == map_handle || NULL == map_handle->dest_addr || NULL == map_handle->recv_cmdu || (-1 == map_handle->handle_1905))
    {
        platform_log(MAP_AGENT,LOG_ERR,"Map Handle parameters Validation Failed");
        goto Cleanup;
    }
    recv_cmdu =  map_handle->recv_cmdu;

    if (NULL == recv_cmdu->list_of_TLVs)
    {
        platform_log(MAP_AGENT,LOG_CRIT,"Client Association Control Request Malformed structure.");
        goto Cleanup;
    }

    client_assoc_req_tlv = (struct mapClientAsociationControlRequestTLV *) map_get_tlv_from_cmdu(recv_cmdu,TLV_TYPE_CLIENT_ASSOCIATION_CONTROL_REQUEST);
    if(NULL == client_assoc_req_tlv)
    {
         platform_log(MAP_AGENT,LOG_ERR, "No Client Association Control Request Tlv in Client Association Control message");
         goto Cleanup;
    }

    /* Should not free this list since it will be used to check timeout, This will be freed once the timeout has expired*/
    block_sta_list = new_array_list(eListTypeDefault);
    if(!block_sta_list)
    {
        platform_log(MAP_AGENT,LOG_ERR, " %s Failed to create block sta list hashmap\n",__func__);
        goto Cleanup;
    }

    /* Will be freed at the end of this function*/
    associated_sta_list = new_array_list(eListTypeDefault);
    if(!associated_sta_list)
    {
        platform_log(MAP_AGENT,LOG_ERR, " %s Failed to create associated sta list hashmap\n",__func__);
        goto Cleanup;
    }

    for (i = 0; i < client_assoc_req_tlv->sta_count; i++)
    {
        /* Check to see if the STA is associated with the BSSID obtained */
        sta = NULL;
        sta = get_sta(client_assoc_req_tlv->sta_list[i].sta_mac);

        if((NULL != sta) && (NULL != sta->bss))
        {
            if ((client_assoc_req_tlv->association_control == STA_BLOCK) &&
                (0 == memcmp(client_assoc_req_tlv->bssid, sta->bss->bssid, MAC_ADDR_LEN)) &&
                (!(sta->state & MAP_STA_STEER_IN_PROGRESS))) // FIX [NG-183848] STA marked as MAP_STA_STEER_IN_PROGRESS is allowed to apply ACL
            {
                if (add_sta_to_list(client_assoc_req_tlv->sta_list[i].sta_mac, associated_sta_list) < 0)
                {
                    platform_log(MAP_AGENT,LOG_ERR, "Unable to add station to associated sta list");
                    goto Cleanup;
                }
                continue;
            }
        }
        if( sta &&  (sta->state & MAP_STA_STEER_IN_PROGRESS))
            platform_log(MAP_AGENT,LOG_DEBUG, "Applying ACL for the STA for which Streeing request is in progress");

        /* Add STAs to the block/unblock list */
        if (add_sta_to_list(client_assoc_req_tlv->sta_list[i].sta_mac, block_sta_list) < 0)
        {
            platform_log(MAP_AGENT,LOG_ERR, "Unable to add station to block sta list");
            goto Cleanup;
        }
    }

    if (-1 == map_send_1905_ack(map_handle, associated_sta_list, STA_ASSOCIATED))
    {
        platform_log(MAP_AGENT,LOG_ERR, "map_send_1905_ack failed");
        goto Cleanup;
    }
    platform_log(MAP_AGENT,LOG_DEBUG, "%s : Client Association Control message received with validity period = %d",__func__,client_assoc_req_tlv->validity_period);

    if (client_assoc_req_tlv->association_control == STA_BLOCK)
    {
        if (-1 == addto_acl_timeout_list(recv_cmdu->message_id, client_assoc_req_tlv->bssid, block_sta_list, client_assoc_req_tlv->validity_period, curr_time))
        {
            platform_log(MAP_AGENT,LOG_ERR, "addto_acl_list_timeout failed");
            if (NULL != block_sta_list) {
                empty_array_list(block_sta_list);
                delete_array_list(block_sta_list);
            }
            goto Cleanup;
        }
    }

    if (-1 == map_stations_assoc_control_apply(client_assoc_req_tlv->association_control, client_assoc_req_tlv->bssid, block_sta_list))
    {
        platform_log(MAP_AGENT,LOG_ERR, "stations_assoc_control_apply failed");
        goto Cleanup;
    }

Cleanup:
    if (NULL != associated_sta_list) {
        empty_array_list(associated_sta_list);
        delete_array_list(associated_sta_list);
    }

    if (NULL != recv_cmdu)
        lib1905_cmdu_cleanup(recv_cmdu);

    return;
}

int map_send_sta_metrics_report(map_handle_t map_handle, int sta_count, map_sta_info_t **sta_list)
{
    struct      CMDU  *cmdu     = NULL;
    map_sta_info_t    *sta_node = NULL;
    map_sta_metrics_t *metrics  = NULL;
    int if_len = 0;
    int ret    = -1;
    int i      = 0;

    struct mapAssociatedStaLinkMetricsTLV *assoc_sta_metrics_tlv = NULL;

    /* Map Handle parameters Validation - "if" statement is left to right parsing*/
    if ((NULL == map_handle.dest_addr) || (NULL == map_handle.src_iface_name) || (-1 == map_handle.handle_1905) || (NULL == sta_list))
    {
        platform_log(MAP_AGENT,LOG_ERR,"Input Validation Failed for function map_send_associated_sta_link_metrics_report");
        goto Cleanup;
    }

    /* init payload CMDU */
    cmdu = (struct CMDU *) calloc(1,sizeof(struct CMDU));

    if (NULL == cmdu) {
        platform_log(MAP_AGENT,LOG_ERR,"CMDU malloc failed");
        goto Cleanup;
    }

    cmdu->message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu->message_type     =  CMDU_TYPE_MAP_ASSOCIATED_STA_LINK_METRICS_RESPONSE;
    cmdu->message_id       =  0;
    cmdu->relay_indicator  =  0;

    strncpy(cmdu->interface_name, map_handle.src_iface_name, MAX_IFACE_LEN);
    if_len = strnlen(cmdu->interface_name, MAX_IFACE_LEN);
    cmdu->interface_name[if_len] = '\0';

    cmdu->list_of_TLVs  =  (uint8_t **)calloc(sta_count+1, sizeof(uint8_t *));
    if(cmdu->list_of_TLVs == NULL) {
       platform_log(MAP_AGENT,LOG_ERR,"calloc failed in init_cmdu");
       goto Cleanup;
    }

    for (i = 0; i < sta_count; i++)
    {
        sta_node = (map_sta_info_t *) sta_list[i];
        if(NULL == sta_node)
        {
            platform_log(MAP_AGENT,LOG_ERR,"sta node is NULL");
            goto Cleanup;
        }

        /*TODO: Allocate based on number of bssids reported */
        assoc_sta_metrics_tlv = (struct mapAssociatedStaLinkMetricsTLV *) calloc (1,sizeof(struct mapAssociatedStaLinkMetricsTLV));
        if (NULL == assoc_sta_metrics_tlv)
        {
            platform_log(MAP_AGENT,LOG_ERR, "Calloc failed for assoc_sta_metrics_tlv");
            goto Cleanup;
        }

        /* Get associated_sta_metrics tlv */
        metrics = (map_sta_metrics_t*)object_at_index(sta_node->metrics, 0);

        if (-1 == build_assoc_sta_link_metrics_tlv(assoc_sta_metrics_tlv, metrics))
        {
            platform_log(MAP_AGENT,LOG_ERR, "build_assoc_sta_link_metrics_tlv failed");
            free(assoc_sta_metrics_tlv);
            goto Cleanup;
        }

        assoc_sta_metrics_tlv->tlv_type = TLV_TYPE_ASSOCIATED_STA_LINK_METRICS;
        memcpy(assoc_sta_metrics_tlv->sta_metrics[0].bssid, sta_node->bss->bssid, ETHER_ADDR_LEN);
        memcpy(assoc_sta_metrics_tlv->associated_sta_mac, sta_node->mac, ETHER_ADDR_LEN);

        cmdu->list_of_TLVs[i] = (uint8_t *) assoc_sta_metrics_tlv;

        sta_node              = NULL;
        assoc_sta_metrics_tlv = NULL;
        metrics               = NULL;
    }

    if (i != sta_count)
    {
        platform_log(MAP_AGENT,LOG_ERR, "Count mismatch in tlvs");
        goto Cleanup;
    }

    if (lib1905_send(map_handle.handle_1905, &cmdu->message_id, map_handle.dest_addr, cmdu) < 0) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu->message_type);
        goto Cleanup;
    }

    ret = 0;

Cleanup:
    if (NULL != cmdu)
        lib1905_cmdu_cleanup(cmdu);

    return ret;
}

void map_send_associated_sta_link_metrics_response(uv_work_t *req, int status)
{
    struct      CMDU *recv_cmdu             = NULL;
    map_handle_t *map_handle                = NULL;
    struct mapStaMacAddressTLV *sta_mac_tlv = NULL;
    struct      CMDU cmdu                   = {0};
    uint8_t     number_of_tlv               = 1; /* Associated STA Link Metrics TLV */
    map_sta_info_t *   sta_node             = NULL;
    map_sta_metrics_t*  metrics             = NULL;
    int sta_present                         = -1;
    int if_len                              = 0;

    struct mapAssociatedStaLinkMetricsTLV assoc_sta_metrics_tlv = {0};
    struct mapErrorCodeTLV                error_code_tlv        = {0};

    /* Input Parameters Validation */
    if (NULL == req || NULL == req->data)
    {
        platform_log(MAP_AGENT,LOG_ERR,"Input Parameters Validation");
        goto Cleanup;
    }
    wq_args* p_args = (wq_args*)req->data;

    /* Map Handle Validation */
    if (NULL == p_args)
    {
        platform_log(MAP_AGENT,LOG_ERR,"Map Handle Validation Failed");
        goto Cleanup;
    }
    map_handle = (map_handle_t *)p_args->wqdata;

    /* Map Handle parameters Validation - "if" statement is left to right parsing*/
    if (NULL == map_handle || NULL == map_handle->dest_addr || NULL == map_handle->recv_cmdu || (-1 == map_handle->handle_1905))
    {
        platform_log(MAP_AGENT,LOG_ERR,"Map Handle parameters Validation Failed");
        goto Cleanup;
    }
    recv_cmdu = map_handle->recv_cmdu;

    if (NULL == recv_cmdu->list_of_TLVs)
    {
        platform_log(MAP_AGENT,LOG_CRIT,"Associated Sta Link metrics Query Malformed structure.");
        goto Cleanup;
    }

    /* Get sta_mac_tlv from received query */
    sta_mac_tlv = (struct mapStaMacAddressTLV *) map_get_tlv_from_cmdu(recv_cmdu,TLV_TYPE_STA_MAC_ADDRESS);
    if(sta_mac_tlv == NULL)
    {
        platform_log(MAP_AGENT,LOG_ERR, "No Client Info Tlv in Associated STA link metrics Query message");
        goto Cleanup;
    }

    if (0 == (sta_present = is_sta_associated_with_agent(sta_mac_tlv->associated_sta_mac)))
        number_of_tlv++;

    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     =  CMDU_TYPE_MAP_ASSOCIATED_STA_LINK_METRICS_RESPONSE;
    cmdu.message_id       =  recv_cmdu->message_id;
    cmdu.relay_indicator  =  0;

    strncpy(cmdu.interface_name, map_handle->src_iface_name, MAX_IFACE_LEN);
    if_len = strnlen(cmdu.interface_name, MAX_IFACE_LEN);
    cmdu.interface_name[if_len] = '\0';

    cmdu.list_of_TLVs  =  (uint8_t **)calloc(number_of_tlv+1, sizeof(uint8_t *));
    if(cmdu.list_of_TLVs == NULL) {
       platform_log(MAP_AGENT,LOG_ERR,"calloc failed in init_cmdu");
       goto Cleanup;
    }

    /* Add Associated STA Link metrics TLV */
    assoc_sta_metrics_tlv.tlv_type = TLV_TYPE_ASSOCIATED_STA_LINK_METRICS;
    memcpy(assoc_sta_metrics_tlv.associated_sta_mac, sta_mac_tlv->associated_sta_mac, ETHER_ADDR_LEN);

    sta_node = get_sta(sta_mac_tlv->associated_sta_mac);
    if(NULL != sta_node)
    {
        metrics = (map_sta_metrics_t*)object_at_index(sta_node->metrics, 0);

        if (-1 == build_assoc_sta_link_metrics_tlv(&assoc_sta_metrics_tlv, metrics))
        {
            platform_log(MAP_AGENT,LOG_ERR, "build_assoc_sta_link_metrics_tlv failed");
            goto Cleanup;
        }

        memcpy(assoc_sta_metrics_tlv.sta_metrics[0].bssid, sta_node->bss->bssid, ETHER_ADDR_LEN);
    }

    cmdu.list_of_TLVs[0] = (uint8_t *) &assoc_sta_metrics_tlv;

    /* Add Error code tlv */
    if (0 == sta_present)
    {
        if (-1 == get_error_code_tlv(&error_code_tlv, STA_UNASSOCIATED, sta_mac_tlv->associated_sta_mac))
        {
            platform_log(MAP_AGENT,LOG_ERR, "Get Error Code TLV failed");
            goto Cleanup;
        }

        cmdu.list_of_TLVs[1] = (uint8_t *) &error_code_tlv;
    }

    if (lib1905_send(map_handle->handle_1905, &cmdu.message_id, map_handle->dest_addr, &cmdu)<0)
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);

Cleanup:
    if (NULL != cmdu.list_of_TLVs)
        free(cmdu.list_of_TLVs);

    if (NULL != recv_cmdu)
        lib1905_cmdu_cleanup(recv_cmdu);

    return;
}


int map_beacon_metrics_completion(void * data) {

    bcn_rprt_timeout_data_t *cum_beacon_report = (bcn_rprt_timeout_data_t *)data;
    array_list_t            *bcon_rprt_list    = NULL;


    if(cum_beacon_report == NULL) return -1;


    bcon_rprt_list = cum_beacon_report->bcon_rprt_list;

    if (bcon_rprt_list != NULL) {
        while (list_get_size(bcon_rprt_list))
            free(remove_last_object(bcon_rprt_list));
 
        delete_array_list(bcon_rprt_list);
    }

    free(cum_beacon_report);
    return 0;
}


int map_send_beacon_metrics_response(map_handle_t map_handle, void *index)
{
    uint8_t     *dst_addr       = NULL;
    struct      CMDU cmdu       = {0};
    handle_1905_t handle        = 0;
    uint16_t   mid              = 0;
    uint8_t    *sta_mac         = NULL;
    int        ret              = -EINVAL;
    int        report_cnt       = 0;
    int        i                = 0;
    list_iterator_t  it         = {0};

    bcn_rprt_timeout_data_t       *cum_beacon_report          = NULL;
    array_list_t                  *bcon_rprt_list             = NULL;

    uint8_t  *list_of_tlv[MAX_TLVS_BEACON_METRICS_REPORT]     = {0};
    beacon_metrics_response_tlv_t *beacon_response_tlv        = NULL;


    dst_addr  =  map_handle.dest_addr;
    handle    =  map_handle.handle_1905;
    
    cum_beacon_report = (bcn_rprt_timeout_data_t *)index; 

    if(cum_beacon_report == NULL) {
        goto Failure;
    }

    bcon_rprt_list = cum_beacon_report->bcon_rprt_list;
    sta_mac        = cum_beacon_report->sta_mac;
    report_cnt     = list_get_size(bcon_rprt_list);
    if( report_cnt < 0 ) {
        goto Failure;
    }

    //## init payload CMDU
    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     =  CMDU_TYPE_MAP_BEACON_METRICS_RESPONSE;
    cmdu.message_id       =  0;
    cmdu.relay_indicator  =  0;
    cmdu.list_of_TLVs     =  list_of_tlv;
    strncpy(cmdu.interface_name, map_handle.src_iface_name,  sizeof(cmdu.interface_name));

    /*
     * Build beacon_response_tlv
     * - sta_mac
     * - status_code
     * - num_of_reports
     * - sequence of 802.11 reports
     */
    beacon_response_tlv = (beacon_metrics_response_tlv_t *)calloc(1, sizeof(beacon_metrics_response_tlv_t) 
                              + (sizeof(map_beacon_report_element_t) * report_cnt));
    if(beacon_response_tlv == NULL) {
        goto Failure;
    }

    beacon_response_tlv->tlv_type = TLV_TYPE_BEACON_METRICS_RESPONSE;

    memcpy(beacon_response_tlv->sta_mac, sta_mac, MAC_ADDR_LEN);
    beacon_response_tlv->tlv_length += MAC_ADDR_LEN;

    beacon_response_tlv->status_code  = report_cnt > 0 ? 
                                        BEACON_REPORT_STATUS_CODE_SUCCESS      : 
                                        BEACON_REPORT_STATUS_CODE_NO_REPORT;
    beacon_response_tlv->tlv_length   += sizeof(beacon_response_tlv->status_code);

    beacon_response_tlv->no_of_reports = report_cnt;
    beacon_response_tlv->tlv_length   += sizeof(beacon_response_tlv->no_of_reports);


    bind_list_iterator(&it, bcon_rprt_list);

    while(it.iter != NULL) {
        map_beacon_report_element_t  *beacon_report = (map_beacon_report_element_t*) get_next_list_object(&it);

        memcpy(&beacon_response_tlv->reports[i], beacon_report, sizeof(map_beacon_report_element_t));
        i++;
    }

    beacon_response_tlv->tlv_length += beacon_response_tlv->no_of_reports * sizeof(map_beacon_report_element_t);

    cmdu.list_of_TLVs[0] = (uint8_t *)beacon_response_tlv;

    if (lib1905_send(handle, &mid, dst_addr, &cmdu)<0) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
        goto Failure;
    }

    fire_retry_timer (dst_addr, (uint8_t *)cmdu.interface_name, CMDU_TYPE_MAP_BEACON_METRICS_RESPONSE,
                      CMDU_TYPE_MAP_ACK, MAX_BEACON_METRICS_RESPONSE_RETRY, 
                      mid, ONE_SEC_IN_MS, map_send_beacon_metrics_response, map_beacon_metrics_completion, index);

    free(beacon_response_tlv);
    return 0;

Failure:
    free(beacon_response_tlv);

    /*
     *Free sta_node
     */

    if (bcon_rprt_list != NULL) {
        while (list_get_size(bcon_rprt_list))
            free(remove_last_object(bcon_rprt_list));
 
        delete_array_list(bcon_rprt_list);
    }

    free(cum_beacon_report);
    return ret;
}


void map_send_beacon_metrics_ack (uv_work_t *req, int status) {

       map_handle_t                         *map_handle       = NULL;
       wq_args                              *w_args           = NULL;
       uint8_t                            *src_mac_addr       = NULL;
       map_monitor_cmd_t                   cmd;
       map_sta_info_t                      *sta               =  NULL;
       struct mapBeaconMetricsQueryTLV     *beacon_query_tlv  =  NULL;
       beacon_metrics_query_t              *beacon_query      =  NULL;
       beacon_metrics_query_t              *monitor_q_node    =  NULL;
       array_list_t                        *sta_list          = NULL; /* List of STAs for which error code tlv need to be sent */
       struct CMDU                         *cmdu              = NULL;

       /* Input Parameters Validation */
       if (NULL == req || NULL == req->data)
       {
           platform_log(MAP_AGENT,LOG_ERR,"Input Parameters Validation");
           goto cleanup;
       }
       w_args = (wq_args*)req->data;

       /* Map Handle Validation */
       if (NULL == w_args)
       {
           platform_log(MAP_AGENT,LOG_ERR,"Map Handle Validation Failed");
           goto cleanup;
       }
       map_handle = (map_handle_t *)w_args->wqdata;

       /* Map Handle parameters Validation - "if" statement is left to right parsing*/
       if (NULL == map_handle || NULL == map_handle->dest_addr || NULL == map_handle->recv_cmdu || (-1 == map_handle->handle_1905))
       {
           platform_log(MAP_AGENT,LOG_ERR,"Map Handle parameters Validation Failed");
           goto cleanup;
       }
       cmdu = map_handle->recv_cmdu;
       src_mac_addr = map_handle->dest_addr;

       if (NULL == cmdu->list_of_TLVs)
       {
           platform_log(MAP_AGENT,LOG_CRIT,"Associated Sta Link metrics Query Malformed structure.");
           goto cleanup;
       }

        /*
         * get beacon metrics query from cmdu 
         */
        beacon_query_tlv = (struct mapBeaconMetricsQueryTLV *) map_get_tlv_from_cmdu(cmdu,TLV_TYPE_BEACON_METRICS_QUERY);
        if(beacon_query_tlv == NULL)
        {
            platform_log(MAP_AGENT,LOG_ERR, "No Client Info Tlv in CLient Capability Query message");
            return;
        }

        /*
         * Validate beacon metrics cmdu
         */ 
        if(beacon_query_tlv->sta_mac == NULL) {
            platform_log(MAP_AGENT,LOG_ERR, "Malformed packet\n");
            return;
        }

        /*
         * send 1905_Ack with proper error code
         */
        sta_list = new_array_list(eListTypeDefault);
        if(!sta_list)
        {
            platform_log(MAP_AGENT,LOG_ERR, " %s Failed to create associated sta list hashmap\n",__func__);
            goto cleanup;
        }

        if (add_sta_to_list(beacon_query_tlv->sta_mac, sta_list) < 0)
        {
            platform_log(MAP_AGENT,LOG_ERR, "Unable to add station to associated sta list");
            goto cleanup;
        }


        sta = get_sta(beacon_query_tlv->sta_mac);
        if(sta ==  NULL) {
            map_send_1905_ack(map_handle, sta_list, STA_UNASSOCIATED);
            goto cleanup;
        }

        map_send_1905_ack(map_handle, sta_list, STA_ASSOCIATED);

       if (sta->beacon_metrics == NULL) {
           goto cleanup;
       }

       /*
        * Only one beacon metrics per sta at one time
        * TODO: Should have timer to clean up when there is no platform event.
        *       For now, allow new query if previous one was longer ago (platform event
                should come in 1 second - see function map_query_beacon_metrics in multiap_agent_metrics.lua)
        */
       beacon_query = (beacon_metrics_query_t*)sta->beacon_metrics;
       if(beacon_query->state == BEACON_QUERY_STATE_ACK_SENT) {
           int last_query = get_clock_diff_secs(get_current_time(), beacon_query->last_query_time);
           if (last_query < BEACON_QUERY_MAX_RESPONSE_TIME) {
               goto cleanup;
           }
       }

       /*
        * create a data structure to be sent to platform abstraction
        * to trigger beacon metrics measurement in station.
        */
       monitor_q_node = (beacon_metrics_query_t *)calloc(1, sizeof(beacon_metrics_query_t) + 
                               (beacon_query_tlv->ap_channel_report_count * sizeof(struct ap_channel_report)));
       if(monitor_q_node ==  NULL) {
           platform_log(MAP_AGENT,LOG_ERR, "%s mallco failed\n",__func__);
           goto cleanup;
       }

       monitor_q_node->channel               = beacon_query_tlv->channel;
       monitor_q_node->report_detail         = beacon_query_tlv->reporting_detail;
       monitor_q_node->operating_class       = beacon_query_tlv->operating_class;

       memcpy(monitor_q_node->sta_mac, beacon_query_tlv->sta_mac, MAC_ADDR_LEN);
       memcpy(monitor_q_node->bssid,   beacon_query_tlv->bssid,   MAC_ADDR_LEN);
       monitor_q_node->ssid_len              = beacon_query_tlv->ssid_len;
       memcpy(monitor_q_node->ssid,    beacon_query_tlv->ssid, beacon_query_tlv->ssid_len);

       memcpy(monitor_q_node->elementIds, beacon_query_tlv->elementIds, 
                                          beacon_query_tlv->element_id_count);

       monitor_q_node->ap_channel_report_count = beacon_query_tlv->ap_channel_report_count;

       memcpy(monitor_q_node->ap_channel_report, beacon_query_tlv->ap_channel_report, 
              beacon_query_tlv->ap_channel_report_count * sizeof(struct ap_channel_report));

       cmd.cmd    = MAP_MONITOR_SEND_UBUS_DATA_CMD;
       cmd.subcmd = MAP_MONITOR_CLIENT_BEACON_METRICS_METHOD_SUBCMD;
       cmd.param  = (void *)monitor_q_node;

       if(0 != map_monitor_send_cmd(cmd)) {
           platform_log(MAP_AGENT,LOG_ERR, "%s send command to publish methods failed\n", __FUNCTION__);
           goto cleanup;
       }


       /*
        * Cache the requested element id, measurement report,
        * channel no, operating class, controller send interface, dst mac.
        *
        * This info will be used while sending the beacon metrics response.
        */
       memcpy(beacon_query, monitor_q_node, sizeof(beacon_metrics_query_t) + 
             (beacon_query_tlv->ap_channel_report_count * sizeof(struct ap_channel_report)));

       strncpy((char *)beacon_query->send_iface, cmdu->interface_name, MAX_IFACE_NAME_LEN);
       memcpy(beacon_query->dst_mac, src_mac_addr, 6);
       beacon_query->state = BEACON_QUERY_STATE_ACK_SENT;
       beacon_query->last_query_time = get_current_time(); 

cleanup:
        if (NULL != sta_list) {
            empty_array_list(sta_list);
            delete_array_list(sta_list);
        }

       if(cmdu != NULL) {
            lib1905_cmdu_cleanup(cmdu);
       }
       return;
}

int map_send_btm_report(map_handle_t *map_handle, void *data)
{
    struct      CMDU  cmdu     = {0};
    uint8_t number_of_tlv = 1;
    uint16_t mid = 0;
    
    steering_btm_report_tlv_t btm_steering_report_tlv = {0};
    btm_report_event_t *btm_report = (btm_report_event_t*)data;
    
    /* Map Handle parameters Validation */
    if ((NULL == map_handle->dest_addr) || (NULL == map_handle->src_iface_name) || (-1 == map_handle->handle_1905) || (NULL == btm_report))
    {
        platform_log(MAP_AGENT,LOG_ERR,"%s Input Validation Failed \n", __FUNCTION__);
        goto Failure;
    }

    cmdu.message_version    =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type       =  CMDU_TYPE_MAP_CLIENT_STEERING_BTM_REPORT;
    cmdu.message_id         =  0;
    cmdu.relay_indicator    =  0;

    strncpy(cmdu.interface_name, map_handle->src_iface_name,  sizeof(cmdu.interface_name));

    /* FIll in tlv values */
    btm_steering_report_tlv.tlv_type = TLV_TYPE_BTM_REPORT; 
    memcpy(btm_steering_report_tlv.bssid, btm_report->current_bssid, MAC_ADDR_LEN); 
    memcpy(btm_steering_report_tlv.sta_mac, btm_report->stn_mac_addr, MAC_ADDR_LEN);
    btm_steering_report_tlv.btm_status_code = btm_report->btm_status;
    if('\0' != btm_report->target_bssid[0]) {
        btm_steering_report_tlv.target_bssid_present = 1;
    }   
    memcpy(btm_steering_report_tlv.target_bssid, btm_report->target_bssid, MAC_ADDR_LEN);
    
    cmdu.list_of_TLVs  =  (uint8_t **)calloc(number_of_tlv+1, sizeof(uint8_t *));
    if(cmdu.list_of_TLVs == NULL) {
        platform_log(MAP_AGENT,LOG_ERR,"%s %d, calloc failed list_of_TLVs", __func__, __LINE__);
        goto Failure;
    }

    cmdu.list_of_TLVs[0] = (uint8_t *)&btm_steering_report_tlv;

    if (lib1905_send(map_handle->handle_1905, &mid, map_handle->dest_addr, &cmdu)<0) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
        goto Failure;
    }
    
    if(NULL != cmdu.list_of_TLVs)
        free(cmdu.list_of_TLVs);
    
    return 0;

Failure:
    
    if(NULL != cmdu.list_of_TLVs)
        free(cmdu.list_of_TLVs);
    
    return -1;
}

struct mapUnassocStaMetricsResponseTLV * get_unassoc_response_tlv(struct unassoc_response *unassoc_response) {

    struct mapUnassocStaMetricsResponseTLV *unassoc_sta_met_resp = NULL;
    uint16_t    tlv_len = 0;
	
    unassoc_sta_met_resp = (struct mapUnassocStaMetricsResponseTLV *) malloc (sizeof(struct mapUnassocStaMetricsResponseTLV) + (sizeof(struct sta_rcpi_list) * (unassoc_response->sta_cnt -1)));
    if(unassoc_sta_met_resp == NULL)
        return NULL;
	
    unassoc_sta_met_resp->tlv_type   = TLV_TYPE_UNASSOCIATED_STA_METRICS_RESPONSE;
	
    unassoc_sta_met_resp->oper_class = unassoc_response->oper_class;
    unassoc_sta_met_resp->sta_cnt    = unassoc_response->sta_cnt;
    tlv_len +=2;

    for (int i = 0; i< unassoc_response->sta_cnt; i++) {
        memcpy(unassoc_sta_met_resp->sta_list[i].sta_mac, unassoc_response->list[i].sta_mac, MAC_ADDR_LEN);
        unassoc_sta_met_resp->sta_list[i].channel    = unassoc_response->list[i].channel;
        unassoc_sta_met_resp->sta_list[i].time_delta = unassoc_response->list[i].age;
        unassoc_sta_met_resp->sta_list[i].rcpi_uplink = unassoc_response->list[i].ulrcpi;
        tlv_len +=12;
    }
	
    unassoc_sta_met_resp->tlv_length = tlv_len;
	
    return unassoc_sta_met_resp;
}


int map_unassoc_metrics_completion (void * data) {

    struct unassoc_response *unassoc_response = (struct unassoc_response *)data;
    map_radio_info_t        *radio_node       = NULL;

    if(unassoc_response != NULL) {
        radio_node = get_radio_node_from_name(unassoc_response->radio_name);
        if(radio_node != NULL) {
            platform_log(MAP_AGENT,LOG_DEBUG,"%s: Freeing unassoc data for radio : %s",__func__,unassoc_response->radio_name);
            clear_unassoc_measurement(&radio_node->state);
            free(radio_node->unassoc_metrics);
            radio_node->unassoc_metrics = NULL;	    
        }
    }

    free(unassoc_response);
    return 0;
}

int map_unassoc_sta_metrics_response(map_handle_t map_handle, void *index) {

    struct CMDU cmdu =
    {
       .message_version = CMDU_MESSAGE_VERSION_1905_1_2013,
       .message_type    = CMDU_TYPE_MAP_UNASSOCIATED_STA_LINK_METRICS_RESPONSE,
       .message_id      = 0,
       .relay_indicator = 0,
    };		

    int ret                     = 0;
    uint16_t   mid              = 0;
    uint8_t *list_of_tlvs[3]    = {0};

    struct mapUnassocStaMetricsResponseTLV *unassoc_sta_met_resp = NULL;
    struct unassoc_response                *unassoc_response     = NULL;

    unassoc_response = (struct unassoc_response *)index;
    if(unassoc_response == NULL) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: unassoc_response is NULL",__func__);
        return -EINVAL;
    }
	
    unassoc_sta_met_resp = get_unassoc_response_tlv(unassoc_response);
    if(unassoc_sta_met_resp == NULL) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: unassoc_sta_met_resp is NULL",__func__);
        return -EINVAL;
    }
	
    cmdu.list_of_TLVs    = list_of_tlvs;
    cmdu.list_of_TLVs[0] = (uint8_t *)unassoc_sta_met_resp;
    strncpy(cmdu.interface_name, map_handle.src_iface_name, MAX_IFACE_LEN);


    if (lib1905_send(map_handle.handle_1905, &mid, map_handle.dest_addr, &cmdu)<0) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
        free(unassoc_sta_met_resp);
	return -EINVAL;
    }

    ret = fire_retry_timer (map_handle.dest_addr, (uint8_t *)cmdu.interface_name, CMDU_TYPE_MAP_UNASSOCIATED_STA_LINK_METRICS_RESPONSE,
                  CMDU_TYPE_MAP_ACK, MAX_BEACON_METRICS_RESPONSE_RETRY,
                  mid, ONE_SEC_IN_MS, map_unassoc_sta_metrics_response, map_unassoc_metrics_completion, index);

    free(unassoc_sta_met_resp);
    return ret;
}

int flush_radio_unassoc_data(map_radio_info_t *radio_node)
{
    struct unassoc_metrics_info *unassoc_metrics_info = NULL;
    map_monitor_cmd_t            cmd                  = {0};
    char                         *radio_name          = NULL;
    int                          last_query           = 0;
    int                          ret                  = -1;

    if (NULL == radio_node)
    {
        platform_log(MAP_AGENT,LOG_ERR,"%s: Radio node id NULL",__func__);
        return ret;
    }

    unassoc_metrics_info = (struct unassoc_metrics_info *) radio_node->unassoc_metrics;
    if (NULL == unassoc_metrics_info) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: unassoc_metrics_info is NULL",__func__);
        return ret;
    }

    last_query = get_clock_diff_secs(get_current_time(), unassoc_metrics_info->last_query_time);

    if (last_query >= UNASSOC_QUERY_MAX_RESPONSE_TIME)
    {
        platform_log(MAP_AGENT,LOG_DEBUG,"%s: Flushing expired data",__func__);

        /* Clear the state in map_data_model */
        clear_unassoc_measurement(&radio_node->state);
        free(radio_node->unassoc_metrics);
        radio_node->unassoc_metrics = NULL;

        /* Clear the data in monitor_task */
        radio_name = strndup(radio_node->radio_name, MAX_RADIO_NAME_LEN);

        cmd.cmd    = MAP_MONITOR_SEND_UBUS_DATA_CMD;
        cmd.subcmd = MAP_MONITOR_UNASSOC_MEASUREMENT_FLUSH_METHOD_SUBCMD;
        cmd.param  = (void *)radio_name;

        if(0 != map_monitor_send_cmd(cmd))
        {
            platform_log(MAP_AGENT,LOG_ERR, "%s send command to publish Unassoc *FLUSH* failed\n", __func__);
            free(radio_name);
        }
        ret = 0;
    }
    return ret;
}

map_radio_info_t * get_radio_for_unassoc_measurement(struct mapUnassocStaMetricsQueryTLV *unassoc_sta_met)
{
    uint16_t         *radio_state = NULL;
    map_radio_info_t *radio_node  = NULL;
    uint8_t           rad_type    = 0;
    int               i           = 0;

    if (unassoc_sta_met->oper_class <= 84 &&
        unassoc_sta_met->oper_class > 0)
    {
        rad_type = IEEE80211_FREQUENCY_BAND_2_4_GHZ;
    }
    else
    {
        rad_type = IEEE80211_FREQUENCY_BAND_5_GHZ;
    }

    /* First look for any radios that doesnot have even one query in progress */
    for (i = 0; i < gmap_agent->num_radios; i++) {

        if(rad_type != gmap_agent->radio_list[i]->radio_caps.type)
            continue;

        radio_state = &gmap_agent->radio_list[i]->state;
        if ((1 == is_radio_on(*radio_state)) &&                          /* This will make sure the radio is ON */
            (1 == is_unassoc_measurement_supported(*radio_state)) &&     /* This will make sure unassoc measurement is supported for radio */
            (0 == is_unassoc_measurement_inprogress(*radio_state)) &&    /* This will make sure unassoc measurement is idle state */
            (gmap_agent->radio_list[i]->unassoc_metrics == NULL))        /* This will make sure, there is no unassoc measurement in progress */
        {
            return gmap_agent->radio_list[i];
        }
    }

    /* If the control reaches here, it means there are no idle radios
       So, we need to find there is any radio whose timeout has expired */
    for (i = 0; i < gmap_agent->num_radios; i++) {

        if(rad_type != gmap_agent->radio_list[i]->radio_caps.type)
            continue;

        radio_state = &gmap_agent->radio_list[i]->state;
        if ((1 == is_radio_on(*radio_state)) &&                          /* This will make sure the radio is ON */
            (1 == is_unassoc_measurement_supported(*radio_state)))       /* This will make sure unassoc measurement is supported for radio */

        {
            if ((1 == is_unassoc_measurement_inprogress(*radio_state)) &&
                (gmap_agent->radio_list[i]->unassoc_metrics != NULL))
            {
                radio_node = gmap_agent->radio_list[i];
                if (0 != flush_radio_unassoc_data (radio_node)) {
                    platform_log(MAP_AGENT,LOG_DEBUG,"There is already a query in progress, and timeout is not done yet");
                    radio_node = NULL;
                }
                else {
                    break;
                }
            }
        }
    }

    return radio_node;
}

uint16_t get_unassoc_sta_count(struct mapUnassocStaMetricsQueryTLV *unassoc_sta_met) {
    uint8_t sta_cnt = 0;
    for (int i = 0; i<unassoc_sta_met->channel_list_cnt; i++) 
	    sta_cnt += unassoc_sta_met->sta_list[i].sta_count;

	return sta_cnt;
}


struct unassoc_platform_cmd *get_unassoc_platform_cmd(struct mapUnassocStaMetricsQueryTLV *unassoc_sta_met, map_radio_info_t  *radio_node) {

    uint16_t sta_cnt = 0;
    struct unassoc_platform_cmd *platform_cmd = NULL;
    uint16_t index   = 0;
    uint8_t  channel = 0;
	
    if(unassoc_sta_met == NULL || radio_node == NULL)
        return NULL;
	
    sta_cnt = get_unassoc_sta_count(unassoc_sta_met);
    if(sta_cnt <= 0)
        return NULL; 
		
    platform_cmd = (struct unassoc_platform_cmd *) malloc(sizeof(struct unassoc_platform_cmd) + (sta_cnt * sizeof(struct measurement_list)));
    if (platform_cmd == NULL) {
        return NULL;
    }
	
    uint8_t (*sta_mac)[MAC_ADDR_LEN] = NULL;
    get_bw_from_operating_class(unassoc_sta_met->oper_class, &platform_cmd->bw);
    for (int i = 0; i<unassoc_sta_met->channel_list_cnt; i++) {
        sta_mac = unassoc_sta_met->sta_list[i].sta_mac;
        channel = unassoc_sta_met->sta_list[i].channel;
        for(int j = 0; j< unassoc_sta_met->sta_list[i].sta_count; j++) {
            uint8_t *mac = (uint8_t *)sta_mac;
            platform_cmd->list[index].channel = channel;
            memcpy(platform_cmd->list[index].mac, mac, MAC_ADDR_LEN);
            strncpy(platform_cmd->radio_name, radio_node->radio_name, MAX_RADIO_NAME_LEN);
            platform_cmd->radio_name[MAX_RADIO_NAME_LEN-1] = '\0';
            index++;
            sta_mac++;
	}
    }
    platform_cmd->cnt = index;
    platform_log(MAP_AGENT,LOG_DEBUG,"station count : %d", platform_cmd->cnt);

    return platform_cmd;
}

void map_higher_layer_data_msg_ack(uv_work_t *req, int status)
{
       map_handle_t                         *map_handle       = NULL;
       wq_args                              *w_args           = NULL;
       
       struct CMDU                         *recv_cmdu              = NULL;
       struct mapHigherLayerDataTLV *higher_layer_data = NULL;
       
       if (NULL == req || NULL == req->data)
       {
           platform_log(MAP_AGENT,LOG_ERR,"Input Parameters Validation");
           goto cleanup;
       }

       w_args       = (wq_args*)req->data;
       map_handle   = w_args->wqdata;

       if (NULL == map_handle || NULL == map_handle->dest_addr || NULL == map_handle->recv_cmdu || (-1 == map_handle->handle_1905))
       {
           platform_log(MAP_AGENT,LOG_ERR,"Map Handle parameters Validation Failed");
           goto cleanup;
       }

       recv_cmdu         = map_handle->recv_cmdu;

/* Already validated the cmdu, so not validating the tlvs here again */
        
        higher_layer_data = (struct mapHigherLayerDataTLV *) map_get_tlv_from_cmdu(recv_cmdu,
        TLV_TYPE_HIGHER_LAYER_DATA_MSG);
        if(NULL == higher_layer_data) {
            platform_log(MAP_AGENT,LOG_ERR, "No higher layer data msg tlv in CMDU\n");
            goto cleanup;
        }

        if (-1 == map_send_1905_ack(map_handle, NULL, -1)) {
            platform_log(MAP_AGENT,LOG_ERR, "map_send_1905_ack failed");
            goto cleanup;
        }

cleanup:
        if(recv_cmdu != NULL) {
            lib1905_cmdu_cleanup(recv_cmdu);
        }
       return;
    
}

void map_unassoc_sta_metrics_ack (uv_work_t *req, int status) {

       map_handle_t                         *map_handle       = NULL;
       wq_args                              *w_args           = NULL;
       uint8_t                            *src_mac_addr       = NULL;
       map_sta_info_t                      *sta               =  NULL;
       array_list_t                        *sta_list          = NULL; /* List of STAs for which error code tlv need to be sent */
       struct CMDU                         *recv_cmdu              = NULL;
       struct mapUnassocStaMetricsQueryTLV *unassoc_sta_met = NULL;


       w_args       = (wq_args*)req->data;
       map_handle   = w_args->wqdata;

       recv_cmdu         = map_handle->recv_cmdu;
       src_mac_addr = map_handle->dest_addr;
        /*
         * get unassoc sta query from cmdu 
         */
        unassoc_sta_met = (struct mapUnassocStaMetricsQueryTLV *) map_get_tlv_from_cmdu(recv_cmdu, TLV_TYPE_UNASSOCIATED_STA_METRICS_QUERY);
        if(NULL == unassoc_sta_met) {
            platform_log(MAP_AGENT,LOG_ERR, "No unassociated sta metrics query tlv in CMDU\n");
            return;
        }

        /*
         * send 1905_Ack with proper error code
         */
        sta_list = new_array_list(eListTypeDefault);
        if(!sta_list)
        {
            platform_log(MAP_AGENT,LOG_ERR, " %s Failed to create associated sta list hashmap\n",__func__);
            goto cleanup;
        }

        uint8_t (*sta_mac)[MAC_ADDR_LEN] = NULL;
        for (int i = 0; i<unassoc_sta_met->channel_list_cnt; i++) {
            sta_mac = unassoc_sta_met->sta_list[i].sta_mac;
            for(int j = 0; j< unassoc_sta_met->sta_list[i].sta_count; j++) {
                uint8_t *mac = (uint8_t *)sta_mac;

               sta = get_sta(mac);
               if(sta != NULL) {
                   if(insert_last_object(sta_list, mac) <0)
                     goto cleanup;
               }
               sta_mac++;
            }
        }

      map_send_1905_ack(map_handle, sta_list, STA_ASSOCIATED);

      /* Send request to platform_abstraction*/
      struct unassoc_metrics_info *unassoc_metrics_info   = NULL;
      struct unassoc_platform_cmd *platform_cmd = NULL;
      map_monitor_cmd_t      cmd                = {0};
      map_radio_info_t       *radio_node        = get_radio_for_unassoc_measurement(unassoc_sta_met);
      
      if(radio_node == NULL) {
          platform_log(MAP_AGENT,LOG_DEBUG,"No free radios");

          /* In this case, send a response with sta count = 0; */
          struct  mapUnassocStaMetricsResponseTLV unassoc_sta_met_resp = {0};
          uint8_t *list_of_tlvs[3]                                     = {0};
          struct  CMDU cmdu =
          {
              .message_version = CMDU_MESSAGE_VERSION_1905_1_2013,
              .message_type    = CMDU_TYPE_MAP_UNASSOCIATED_STA_LINK_METRICS_RESPONSE,
              .message_id      = recv_cmdu->message_id,
              .relay_indicator = 0,
          };

          unassoc_sta_met_resp.tlv_type   = TLV_TYPE_UNASSOCIATED_STA_METRICS_RESPONSE;
          unassoc_sta_met_resp.tlv_length = 2;
          unassoc_sta_met_resp.oper_class = unassoc_sta_met->oper_class;
          unassoc_sta_met_resp.sta_cnt    = 0;

          cmdu.list_of_TLVs    = list_of_tlvs;
          cmdu.list_of_TLVs[0] = (uint8_t *)&unassoc_sta_met_resp;
          strncpy(cmdu.interface_name, map_handle->src_iface_name, MAX_IFACE_LEN);

          if (lib1905_send(map_handle->handle_1905, &cmdu.message_id, map_handle->dest_addr, &cmdu)<0) {
              platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
          }

          goto cleanup;
      }

      set_unassoc_measurement_inprogress(&radio_node->state);

      /*
       * cache the unassoc measurement params 
       * in the radio data structure. This will be used
       * while sending the unassoc response back to the controller.
       */
      unassoc_metrics_info = (struct unassoc_metrics_info * ) calloc(1, sizeof(struct unassoc_metrics_info));
      if (unassoc_metrics_info == NULL) {
          platform_log(MAP_AGENT,LOG_ERR,"\n Calloc failed for unassoc_metrics_info");
          goto cleanup;
      }

      memcpy(unassoc_metrics_info->dst_mac, src_mac_addr, MAC_ADDR_LEN);
      strncpy(unassoc_metrics_info->dst_iface, map_handle->src_iface_name, MAX_IFACE_NAME_LEN);
      unassoc_metrics_info->dst_iface[MAX_IFACE_NAME_LEN-1] = '\0';
      unassoc_metrics_info->oper_class = unassoc_sta_met->oper_class;
      unassoc_metrics_info->last_query_time = get_current_time();

      radio_node->unassoc_metrics = unassoc_metrics_info;

      /*
       * Send platform cmd to monitor thread,
       * this will add a new entry to the unassoc measurement list.
       */

      platform_cmd = get_unassoc_platform_cmd(unassoc_sta_met, radio_node);
      if(platform_cmd == NULL) {
          platform_log(MAP_AGENT,LOG_ERR,"%s: get_unassoc_platform_cmd failed\n",__func__);
          free(unassoc_metrics_info);
          radio_node->unassoc_metrics = NULL;
          goto cleanup;
      }
 
      cmd.cmd    = MAP_MONITOR_SEND_UBUS_DATA_CMD;
      cmd.subcmd = MAP_MONITOR_UNASSOC_MEASUREMENT_REQ_METHOD_SUBCMD;
      cmd.param  = (void *)platform_cmd;
      if(0 != map_monitor_send_cmd(cmd)) {
          platform_log(MAP_AGENT,LOG_ERR, "%s send command to publish methods failed\n", __FUNCTION__);
          free(platform_cmd);
          free(unassoc_metrics_info);
          radio_node->unassoc_metrics = NULL;
      }


cleanup:
       
       if (NULL != sta_list) {
           uint32_t count = list_get_size(sta_list);

           for(int index = 0; index < count; index++) {
              remove_last_object(sta_list);
           }
           delete_array_list(sta_list);
       }

       if(recv_cmdu != NULL) {
            lib1905_cmdu_cleanup(recv_cmdu);
       }
       return;
}


int map_send_topology_query(map_handle_t   *map_handle)
{
    uint8_t         relay_indicator   = 0;
    uint8_t         *dst_addr         = NULL;
    uint16_t        *mid              = NULL;
    handle_1905_t   handle            = 0;
    int if_len;

    struct CMDU     cmdu              = {0};
    uint8_t         *list_of_tlvs[1]  = {0};           /* No other tlvs except for End_of_Tlv */

    // Map Handle parameters Validation
    if (NULL == map_handle->dest_addr || (-1 == map_handle->handle_1905))
{
        platform_log(MAP_AGENT,LOG_ERR,"Map Handle parameters Validation Failed");
        return -1;
    }

    dst_addr        =  map_handle->dest_addr;
    handle          =  map_handle->handle_1905;

    catch_mid(map_handle, &mid);

    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     =  CMDU_TYPE_TOPOLOGY_QUERY;
    cmdu.message_id       =  0;
    cmdu.relay_indicator  =  relay_indicator;

    if_len = strlen(map_handle->src_iface_name);
    strncpy(cmdu.interface_name, map_handle->src_iface_name, if_len);
    cmdu.interface_name[if_len] = '\0';

    cmdu.list_of_TLVs  =  (uint8_t **)list_of_tlvs;

    if (lib1905_send(handle, mid, dst_addr, &cmdu)<0) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
        return -1;
    }

    return 0;
}



int map_cli_send_ch_pref_report(map_handle_t   *map_handle, struct channel_preference_report *ch_pref_report)
{
    uint8_t         relay_indicator   = 0;
    uint8_t         *dst_addr         = NULL;
    uint16_t        *mid              = NULL;
    uint16_t        len               = 0;
    handle_1905_t   handle            = 0;

    static struct mapChannelPreferenceTLV  channel_pref_tlv = {0};  
    struct CMDU     cmdu              = {0};
    uint8_t         *list_of_tlvs[2]  = {0};           /* 1 channel pref_report + 1 End_of_Tlv */

    // Map Handle parameters Validation
    if (NULL == map_handle->dest_addr || (-1 == map_handle->handle_1905))
{
        platform_log(MAP_AGENT,LOG_ERR,"Map Handle parameters Validation Failed");
        return -1;
    }

    dst_addr        =  map_handle->dest_addr;
    handle          =  map_handle->handle_1905;

    catch_mid(map_handle, &mid);

    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type	  =  CMDU_TYPE_MAP_CHANNEL_PREFERENCE_REPORT;
    cmdu.message_id	  =  0;
    cmdu.relay_indicator  =  relay_indicator;

    strncpy(cmdu.interface_name, map_handle->src_iface_name, INTERFACE_STR_LEN);
    cmdu.interface_name[INTERFACE_STR_LEN-1] = '\0';

    cmdu.list_of_TLVs  =  (uint8_t **)list_of_tlvs;


    channel_pref_tlv.tlv_type = TLV_TYPE_CHANNEL_PREFERENCE;
    memcpy (channel_pref_tlv.radio_id, ch_pref_report->radio_id, MAC_ADDR_LEN);

    len+=MAC_ADDR_LEN;
    channel_pref_tlv.numOperating_class = ch_pref_report->numOperating_class;
    len+=1;

    for(int i = 0; i<channel_pref_tlv.numOperating_class; i++) {
        //## filling indidual operating class info here
        channel_pref_tlv.operating_class[i].operating_class = ch_pref_report->operating_class[i].operating_class;
        len+=1;

        channel_pref_tlv.operating_class[i].number_of_channels = ch_pref_report->operating_class[i].number_of_channels;
        len+=1;

        for (int j=0; j<channel_pref_tlv.operating_class[i].number_of_channels; j++) {
            channel_pref_tlv.operating_class[i].channel_num[j] = ch_pref_report->operating_class[i].channel_num[j];

            len+=1;
        }

        channel_pref_tlv.operating_class[i].pref_reason = ch_pref_report->operating_class[i].pref_reason;
        len+=1;
    }
    channel_pref_tlv.tlv_length = len; 

    cmdu.list_of_TLVs[0] = (uint8_t *)&channel_pref_tlv;

    if (lib1905_send(handle, mid, dst_addr, &cmdu)<0) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for channel pref msg of mid %d",__func__, __LINE__, *mid);
        return -1;
    }	

    return 0;
}

neighbour_link_met_platform_cmd_t* 
init_link_met_platform_cmd (struct CMDU* recv_cmdu, int neighbour_cnt, uint8_t *dst_mac, uint8_t req_type)

{
        if (recv_cmdu == NULL || dst_mac == NULL)
            return NULL;

        neighbour_link_met_platform_cmd_t *platform_cmd = (neighbour_link_met_platform_cmd_t *) malloc 
                                                      (sizeof(neighbour_link_met_platform_cmd_t) + 
                                                      (neighbour_cnt * sizeof(struct   neighbour_entry)));
        if(platform_cmd == NULL)
            return NULL;

        platform_cmd->mid = recv_cmdu->message_id;
        memcpy(platform_cmd->dst_mac, dst_mac, MAC_ADDR_LEN);
        strncpy(platform_cmd->dst_iface_name, recv_cmdu->interface_name, 
                                           sizeof(platform_cmd->dst_iface_name));
        platform_cmd->dst_iface_name[sizeof(platform_cmd->dst_iface_name)-1] = '\0';
        platform_cmd->request_type = req_type;
        platform_cmd->neighbour_entry_nr = neighbour_cnt;

        return platform_cmd;
}

int is_requested_neighbour(map_ale_info_t* neighbour_ale, uint8_t *specific_neigh_mac)
{
    if(neighbour_ale == NULL || specific_neigh_mac == NULL)
        return 0;

    return (!memcmp(specific_neigh_mac, neighbour_ale->al_mac, MAC_ADDR_LEN));
}

int fill_link_met_platform_cmd (struct neighbour_entry *neighbour_list, map_ale_info_t* neighbour_ale)
{

    if(neighbour_list == NULL || neighbour_ale == NULL)
        return -EINVAL;

    memcpy(neighbour_list->local_almac, 
                         gmap_agent->al_mac, MAC_ADDR_LEN);

    memcpy(neighbour_list->neighbour_almac, 
                         neighbour_ale->al_mac, MAC_ADDR_LEN);

    memcpy(neighbour_list->neighbour_iface_mac, 
                    neighbour_ale->upstream_local_iface_mac, MAC_ADDR_LEN);

    strncpy(neighbour_list->interface_name, neighbour_ale->iface_name, 
                                                       MAX_IFACE_NAME_LEN);

    neighbour_list->interface_name[MAX_IFACE_NAME_LEN-1] = '\0';

    return 0;
}

neighbour_link_met_platform_cmd_t * get_link_met_platform_cmd(struct CMDU *recv_cmdu, uint8_t *dst_mac )
{
    neighbour_link_met_platform_cmd_t *platform_cmd       = NULL;
    struct linkMetricQueryTLV         *link_met_query_tlv = NULL;
    map_ale_info_t                    *root_ale           = NULL;
    map_ale_info_t                    *neighbour_ale      = NULL;
    char                              mac_str[64]         = {0};
    int                               i                   =  0;
    int                               neighbour_cnt       =  0;

    link_met_query_tlv = (struct linkMetricQueryTLV *)map_get_tlv_from_cmdu(recv_cmdu, TLV_TYPE_LINK_METRIC_QUERY);
    if(link_met_query_tlv == NULL) 
         return NULL;

    int is_specific_neighbour_req = link_met_query_tlv->destination;
 
    root_ale = get_root_ale_node();

    neighbour_cnt = map_get_child_count(root_ale);
    if(neighbour_cnt <= 0) return NULL;

    if(is_specific_neighbour_req) neighbour_cnt = 1;

    platform_cmd = init_link_met_platform_cmd(recv_cmdu, neighbour_cnt, dst_mac, link_met_query_tlv->link_metrics_type);
    if(platform_cmd == NULL)
        return NULL;   

    platform_log(MAP_AGENT,LOG_DEBUG,"--------Preparing link metrics for----------\n");
    if(is_specific_neighbour_req) {
        neighbour_ale = get_ale(link_met_query_tlv->specific_neighbor);
        if(neighbour_ale == NULL) {
            free(platform_cmd);
            return NULL;
        }

        // Convert the MAC into string and print
        get_mac_as_str(neighbour_ale->al_mac, (int8_t *)mac_str, MAX_MAC_STRING_LEN);
        platform_log(MAP_AGENT,LOG_DEBUG,"----------------------------------------------\n");
        platform_log(MAP_AGENT,LOG_DEBUG," Al ENTITY MAC          : %s \n", mac_str);
        platform_log(MAP_AGENT,LOG_DEBUG," RECEIVING INTERFACE    : %s\n", neighbour_ale->iface_name);
        get_mac_as_str(neighbour_ale->upstream_local_iface_mac, (int8_t *)mac_str, MAX_MAC_STRING_LEN);
        platform_log(MAP_AGENT,LOG_DEBUG," REMOTE IFACE MAC       : %s\n", mac_str);
        platform_log(MAP_AGENT,LOG_DEBUG,"----------------------------------------------\n");
  
        fill_link_met_platform_cmd(&platform_cmd->neighbour_list[i], neighbour_ale); 
        i++;
    } else {
        foreach_neighbors_of(root_ale, neighbour_ale)  {
            if(neighbour_ale) {
                // Convert the MAC into string and print
                get_mac_as_str(neighbour_ale->al_mac, (int8_t *)mac_str, MAX_MAC_STRING_LEN);
                platform_log(MAP_AGENT,LOG_DEBUG,"----------------------------------------------\n");
                platform_log(MAP_AGENT,LOG_DEBUG," Al ENTITY MAC          : %s \n", mac_str);
                platform_log(MAP_AGENT,LOG_DEBUG," RECEIVING INTERFACE    : %s\n", neighbour_ale->iface_name);
                get_mac_as_str(neighbour_ale->upstream_local_iface_mac, (int8_t *)mac_str, MAX_MAC_STRING_LEN);
                platform_log(MAP_AGENT,LOG_DEBUG," REMOTE IFACE MAC       : %s\n", mac_str);
                platform_log(MAP_AGENT,LOG_DEBUG,"----------------------------------------------\n");
       
                fill_link_met_platform_cmd(&platform_cmd->neighbour_list[i], neighbour_ale); 
                i++;
            }
        }
    }
    
    platform_cmd->neighbour_entry_nr = i;

    return platform_cmd;
}

int map_send_link_metrics_result_code(map_handle_t *map_handle)
{
    uint8_t     *dst_addr         = NULL;
    struct CMDU *recv_cmdu        = NULL;
    struct CMDU cmdu              = {0};
    uint8_t     *list[2]          = {0};
    struct linkMetricResultCodeTLV    link_met_result_code = {0};

    /* Input Parameters Check */
    if (NULL == map_handle || 
        NULL == map_handle->dest_addr || 
        NULL == map_handle->recv_cmdu || 
       (-1 == map_handle->handle_1905)) {
        platform_log(MAP_AGENT,LOG_ERR, "Map Handle validation failed");
        return -1;
    }

    recv_cmdu    =  map_handle->recv_cmdu;
    dst_addr     =  map_handle->dest_addr;

    /* init payload CMDU */
    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     =  CMDU_TYPE_LINK_METRIC_RESPONSE;
    cmdu.message_id       =  recv_cmdu->message_id;
    cmdu.relay_indicator  =  0;

    link_met_result_code.tlv_type = TLV_TYPE_LINK_METRIC_RESULT_CODE;
    link_met_result_code.result_code = LINK_METRIC_RESULT_CODE_TLV_INVALID_NEIGHBOR; 

    list[0] = (uint8_t *)&link_met_result_code;
    list[1] = NULL;

    cmdu.list_of_TLVs  = list;

    strncpy(cmdu.interface_name, map_handle->src_iface_name, sizeof(cmdu.interface_name));

    if (lib1905_send(map_handle->handle_1905, &cmdu.message_id, dst_addr, &cmdu) < 0) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
        return -1;
    }

    return 0;
}

void map_neighbour_link_met_query_process (uv_work_t *req, int status) {

       map_handle_t                         *map_handle       = NULL;
       wq_args                              *w_args           = NULL;
       uint8_t                              *dst_mac          = NULL;
       struct CMDU                          *recv_cmdu        = NULL;
       map_monitor_cmd_t                    cmd               = {0};
       neighbour_link_met_platform_cmd_t    *platform_cmd     = NULL;
       struct linkMetricQueryTLV         *link_met_query_tlv = NULL;


       w_args       = (wq_args*)req->data;
       map_handle   = w_args->wqdata;

       recv_cmdu    = map_handle->recv_cmdu;
       dst_mac      = map_handle->dest_addr;

      link_met_query_tlv = (struct linkMetricQueryTLV *)map_get_tlv_from_cmdu(recv_cmdu, TLV_TYPE_LINK_METRIC_QUERY);
      if(link_met_query_tlv == NULL) 
         goto cleanup;

      int is_specific_neighbour_req = link_met_query_tlv->destination;

      platform_cmd  = get_link_met_platform_cmd(recv_cmdu, dst_mac);
      if(platform_cmd == NULL) {
          if(is_specific_neighbour_req) map_send_link_metrics_result_code(map_handle);
          goto cleanup;
      }

      cmd.cmd    = MAP_MONITOR_SEND_UBUS_DATA_CMD;
      cmd.subcmd = MAP_MONITOR_GET_NEIGHBOUR_LINK_MET_METHOD_SUBCMD;
      cmd.param  = (void *)platform_cmd;


      if(0 != map_monitor_send_cmd(cmd)) {
          platform_log(MAP_AGENT,LOG_ERR, "%s send command to publish methods failed\n", __FUNCTION__);
          free(platform_cmd);
      }

cleanup:
       
       if(recv_cmdu != NULL) {
            lib1905_cmdu_cleanup(recv_cmdu);
       }
       return;
}


void map_send_link_metrics_report(map_handle_t   *map_handle, struct neighbour_link_met_response *link_met_resp)
{
    uint8_t         relay_indicator   = 0;
    uint8_t         *dst_addr         = NULL;
    uint16_t        mid               = 0;
    handle_1905_t   handle            = 0;

    struct CMDU     cmdu              = {0};

    // Map Handle parameters Validation
    if (NULL == map_handle->dest_addr || (-1 == map_handle->handle_1905))
{
        platform_log(MAP_AGENT,LOG_ERR,"Map Handle parameters Validation Failed");
        return;
    }

    dst_addr        =  map_handle->dest_addr;
    handle          =  map_handle->handle_1905;

    mid = link_met_resp->mid;

    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type	  =  CMDU_TYPE_LINK_METRIC_RESPONSE;
    cmdu.message_id	  =  mid;
    cmdu.relay_indicator  =  relay_indicator;

    strncpy(cmdu.interface_name, map_handle->src_iface_name, INTERFACE_STR_LEN);
    cmdu.interface_name[INTERFACE_STR_LEN-1] = '\0';

    cmdu.list_of_TLVs = link_met_resp->list_of_tlvs;

    if (lib1905_send(handle, &mid, dst_addr, &cmdu)<0) {
        platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for channel pref msg of mid %d",__func__, __LINE__, mid);
    }

    return;
}
void map_send_combined_infrastructure_metrics_ack(uv_work_t *req, int status) {

       map_handle_t                         *map_handle       = NULL;
       wq_args                              *w_args           = NULL;
       struct CMDU                          *recv_cmdu        = NULL;

       /* Input Parameters Validation */
       if (NULL == req || NULL == req->data)
       {
           platform_log(MAP_AGENT,LOG_ERR,"Input Parameters Validation");
           goto cleanup;
       }
       w_args = (wq_args*)req->data;

       /* Map Handle Validation */
       if (NULL == w_args)
       {
           platform_log(MAP_AGENT,LOG_ERR,"Map Handle Validation Failed");
           goto cleanup;
       }
       map_handle = (map_handle_t *)w_args->wqdata;

       /* Map Handle parameters Validation - "if" statement is left to right parsing*/
       if (NULL == map_handle || NULL == map_handle->dest_addr || NULL == map_handle->recv_cmdu || (-1 == map_handle->handle_1905))
       {
           platform_log(MAP_AGENT,LOG_ERR,"Map Handle parameters Validation Failed");
           goto cleanup;
       }

       recv_cmdu = map_handle->recv_cmdu;

       if (-1 == map_send_1905_ack(map_handle, NULL, -1)) {
          platform_log(MAP_AGENT,LOG_ERR, "map_send_1905_ack failed");
          goto cleanup;
       }

cleanup:
         if (NULL != recv_cmdu)
          lib1905_cmdu_cleanup(recv_cmdu);

         return;
}


void map_send_unsolicated_channel_pref_report(map_handle_t   *map_handle, map_radio_info_t *radio_node)
{
	/* Operating Channel TLV TBD */
        uint8_t         number_of_tlv     = 0;
        uint8_t         relay_indicator   = 0;
        uint8_t         *dst_addr         = NULL;
        struct          CMDU  cmdu        = {0};
        uint16_t        mid               = 0;
        uint8_t         i                 = 0;
        handle_1905_t   handle;
        int if_len;


        struct mapChannelPreferenceTLV *channel_pref_tlv = NULL;
    
        // Map Handle parameters Validation
        if (NULL == map_handle->dest_addr || (-1 == map_handle->handle_1905))
        {
            platform_log(MAP_AGENT,LOG_ERR,"Map Handle parameters Validation Failed");
            goto Cleanup;
        }
    
        dst_addr        =  map_handle->dest_addr;
        handle          =  map_handle->handle_1905;
    
            /* This need not be same message id as channel selection query */
        mid = 0;

	cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
	cmdu.message_type     =  CMDU_TYPE_MAP_CHANNEL_PREFERENCE_REPORT;
	cmdu.message_id	      =  mid;
	cmdu.relay_indicator  =  relay_indicator;
	cmdu.list_of_TLVs     =  (uint8_t **)NULL;

	if_len = strlen(map_handle->src_iface_name);
	strncpy(cmdu.interface_name, map_handle->src_iface_name, if_len);
	cmdu.interface_name[if_len] = '\0';

        uint8_t *list_of_tlvs[10] = {0};

	cmdu.list_of_TLVs  =  (uint8_t **)list_of_tlvs;
	
	for (i = 0; i < gmap_agent->num_radios; i++)
        {

            if ((radio_node != NULL) && 
                (memcmp(radio_node->radio_id, gmap_agent->radio_list[i]->radio_id, MAC_ADDR_LEN) != 0)) continue;

            channel_pref_tlv = (struct mapChannelPreferenceTLV *) calloc (1,sizeof(struct mapChannelPreferenceTLV));
            if(channel_pref_tlv == NULL) {
                platform_log(MAP_AGENT,LOG_ERR,"calloc failed in init_cmdu");
                goto Cleanup;
            }

            //## Add Channel Preference TLV
            if (map_get_channel_preference_tlv(channel_pref_tlv, i) < 0)
            {
                platform_log(MAP_AGENT,LOG_ERR,"%s: %d Channel Preference TLV  map_get failed",__func__, __LINE__);
                goto Cleanup;
            }
            else
            {
                cmdu.list_of_TLVs[i]     = (uint8_t *)channel_pref_tlv;
            }

	}

        number_of_tlv = i;
	cmdu.list_of_TLVs[i]  = 0;

	if (lib1905_send(handle, &mid, dst_addr, &cmdu)<0) {
		platform_log(MAP_AGENT,LOG_ERR,"%s: %d send failed for msg type %d",__func__, __LINE__, cmdu.message_type);
	}	
	
Cleanup:
        if(cmdu.list_of_TLVs != NULL) {
            for(i = 0; i<number_of_tlv; i++) {
                free(cmdu.list_of_TLVs[i]);
            }
        }
        return;
}



