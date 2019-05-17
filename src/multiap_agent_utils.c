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
#include "multiap_agent_utils.h"
#include "platform_multiap_get_info.h"

extern mapdhdl gmapd_hdl;
extern unsigned int grun_daemon;

void init_workqueue_handles()
{
    int i;
    for(i=0;i< MAX_NUM_OF_WQ;i++)
    {
        gmapd_hdl.gather_wq[i].args.inuse=0;
        gmapd_hdl.gather_wq[i].args.wq_num=i;
        gmapd_hdl.gather_wq[i].args.wqdata=NULL;
    }
    return;
}

wq_pool* get_workqueue_handle()
{
    int i;
    for(i=0;i< MAX_NUM_OF_WQ;i++)
    {
        if(!gmapd_hdl.gather_wq[i].args.inuse)
        {
            gmapd_hdl.gather_wq[i].args.inuse=1;
            return &(gmapd_hdl.gather_wq[i]);
        }
    }
    platform_log(MAP_AGENT,LOG_CRIT,"Error No Workqueue available for processing");
    return NULL;
}

void free_workqueue_handle(wq_args* data)
{
    data->inuse=0;
    return;
}

void set_freq_unsupported_by_ctrl(uint8_t freq) 
{
   int index = 0;
   uint8_t radio_freq = 0;
   uint16_t *radio_state   = NULL;
   for (index = 0; index < gmap_agent->num_radios; index++)
   {
	radio_state = &gmap_agent->radio_list[index]->state;
	radio_freq = gmap_agent->radio_list[index]->radio_caps.type;
        if (freq == radio_freq)
		set_radio_state_freq_unsupported_by_ctrl(radio_state);
   }
   return;
}

int is_ctrl_discovered()
{
   int i = 0;
   uint16_t *radio_state   = NULL;
   for (i = 0; i < gmap_agent->num_radios; i++)
   {
	radio_state = &gmap_agent->radio_list[i]->state;

	if (NULL == radio_state) {
            platform_log(MAP_AGENT,LOG_ERR,"map_radio_state is NULL");
            return -1;
        }

	if (1 == is_radio_freq_supported(*radio_state))
        	return 1;
   }
   return 0;
}

int platform_init(plfrm_config* config)
{
	openlog("Multiap_agent", 0, LOG_DAEMON);

	//Check if daemonize if enabled , only then enable log in console
	if(grun_daemon == 0)
		config->log_output=log_syslog;

	if(platform_config_load(MAP_PLATFORM_GET_AGENT_CONFIG,config))
		return -1;

	/* Init the hash table to be used by agent */
	if(init_map_datamodel() == -1) {
		platform_log(MAP_AGENT,LOG_ERR, " Failed to initialize the data model");
		return -1;
	}

	if(grun_daemon)
		daemonize(config);

	return 0;
}

int dump_tlv_structure(INT8U tlv_type, void * tlv_info)
{
	steering_policy_tlv_t *steering_policy;
	metric_policy_tlv_t *metric_policy;
	int i=0;
	uint8_t *sta_mac;
	
	if(tlv_info == NULL)
		return 0;

	switch(tlv_type)
	{
		case TLV_TYPE_STEERING_POLICY:
		{
			steering_policy = (steering_policy_tlv_t *)tlv_info;
			platform_log(MAP_AGENT,LOG_DEBUG,"Steering Policy \n");
			platform_log(MAP_AGENT,LOG_DEBUG,"Local Steering Disallowed Count - %d \n", steering_policy->number_of_local_steering_disallowed);
			for(i=0; i<steering_policy->number_of_local_steering_disallowed;i++)
			{
				sta_mac = steering_policy->local_steering_macs + i * MAC_ADDR_LEN;
				platform_log(MAP_AGENT,LOG_DEBUG,"Local Steering Disallowed MAC = %x:%x:%x:%x:%x:%x\n", sta_mac[0],sta_mac[1],sta_mac[2],sta_mac[3],sta_mac[4],sta_mac[5]);
			}
			platform_log(MAP_AGENT,LOG_DEBUG,"BTM Steering Disallowed Count - %d \n", steering_policy->number_of_btm_steering_disallowed);
			for(i=0; i<steering_policy->number_of_btm_steering_disallowed;i++)
			{
				sta_mac = steering_policy->btm_steering_macs+ i * MAC_ADDR_LEN;
				platform_log(MAP_AGENT,LOG_DEBUG,"BTM Steering Disallowed MAC = %x:%x:%x:%x:%x:%x\n", sta_mac[0],sta_mac[1],sta_mac[2],sta_mac[3],sta_mac[4],sta_mac[5]);
			}
			platform_log(MAP_AGENT,LOG_DEBUG,"Radio Count - %d \n", steering_policy->number_of_radio);
			for(i=0; i<steering_policy->number_of_radio;i++)
			{
				platform_log(MAP_AGENT,LOG_DEBUG,"Radio %d ID - %x:%x:%x:%x:%x:%x\n",i,steering_policy->radio_policy[i].radioId[0],steering_policy->radio_policy[i].radioId[1],steering_policy->radio_policy[i].radioId[2],steering_policy->radio_policy[i].radioId[3],steering_policy->radio_policy[i].radioId[4],steering_policy->radio_policy[i].radioId[5]);
				platform_log(MAP_AGENT,LOG_DEBUG,"Radio %d RSSI Threshold - %x \n", i, steering_policy->radio_policy[i].rssi_steering_threshold);
				platform_log(MAP_AGENT,LOG_DEBUG,"Radio %d Channel Utilization Threshold - %x \n", i, steering_policy->radio_policy[i].channel_utilization_threshold);
				platform_log(MAP_AGENT,LOG_DEBUG,"Radio %d Steering - %x \n", i, steering_policy->radio_policy[i].steering_policy);
			}

			break;
		}

		case TLV_TYPE_METRIC_REPORTING_POLICY:
		{
			metric_policy = (metric_policy_tlv_t *)tlv_info;
			platform_log(MAP_AGENT,LOG_DEBUG,"Metric Policy \n");
			platform_log(MAP_AGENT,LOG_DEBUG,"Metric reporting period - %d \n", metric_policy->metric_reporting_interval);
			platform_log(MAP_AGENT,LOG_DEBUG,"Radio Count - %d \n", metric_policy->number_of_radio);
			for(i=0; i<metric_policy->number_of_radio;i++)
			{
				platform_log(MAP_AGENT,LOG_DEBUG,"Radio %d ID - %x:%x:%x:%x:%x:%x\n",i,metric_policy->radio_policy[i].radioId[0],metric_policy->radio_policy[i].radioId[1],metric_policy->radio_policy[i].radioId[2],metric_policy->radio_policy[i].radioId[3],metric_policy->radio_policy[i].radioId[4],metric_policy->radio_policy[i].radioId[5]);
				platform_log(MAP_AGENT,LOG_DEBUG,"Radio %d Associated STA policy - %x \n", i, metric_policy->radio_policy[i].associated_sta_policy);
				platform_log(MAP_AGENT,LOG_DEBUG,"Radio %d Channel Utilization Reporting Threshold - %x \n", i, metric_policy->radio_policy[i].channel_utilization_reporting_threshold);
				platform_log(MAP_AGENT,LOG_DEBUG,"Radio %d Reporting RSSI Threshold - %x \n", i, metric_policy->radio_policy[i].reporting_rssi_threshold);
				platform_log(MAP_AGENT,LOG_DEBUG,"Radio %d Reporting RSSI Margin Override - %x \n", i, metric_policy->radio_policy[i].reporting_rssi_margin_override);
			}
			break;
		}

		default:
			break;

	}
	return 1;
}

map_radio_info_t *get_radio_node_from_name(char *radio_name){
	
	map_radio_info_t *radio_node = NULL;
        int i = 0;
	for (i = 0; i < gmap_agent->num_radios; i++) {
            radio_node = gmap_agent->radio_list[i];
	    if(strncmp(radio_node->radio_name,radio_name,32) == 0) {
			break;
	    }
	}
        if(i>= gmap_agent->num_radios) radio_node = NULL;

    return radio_node;
}
