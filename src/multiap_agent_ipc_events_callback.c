/********** COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE ************
** Copyright (c) 2019 Technicolor                                       *
** - Connected Home Division of Technicolor Group                       *
** - Technicolor Delivery Technologies, SAS                             *
**   and/or Technicolor Connected Home USA, LLC                         *
** - All Rights Reserved                                                *
** Technicolor hereby informs you that certain portions                 *
** of this software module and/or Work are owned by Technicolor         *
** and/or its software providers.                                       *
** Distribution copying and modification of all such work are reserved  *
** to Technicolor and/or its affiliates, and are not permitted without  *
** express written authorization from Technicolor.                      *
** Technicolor is registered trademark and trade name of Technicolor,   *
** and shall not be used in any manner without express written          *
** authorization from Technicolor                                       *
*************************************************************************/

#include <stdint.h>
#include <syslog.h>

#include "multiap_agent_ipc_events_callback.h"
#include "map_events.h"
#include "map_ipc_event_handler.h"
#include "platform_map.h"
#include "multiap_agent_callbacks.h"
#include "multiap_agent_payloads.h"
#include "platform_multiap_get_info.h"
#include "map_retry_handler.h"
#include "map_data_model.h"
#include "1905_lib.h"
#include "map_80211.h"
#include "arraylist.h"

extern map_ale_info_t *gmap_agent;
extern handle_1905_t handle_1905;

static int  map_update_sta_config (stn_event_t *stn_event);
static void map_backhaul_link_state_change_cb (int8_t *state);
static void map_radio_state_change_event (ssid_radio_state_t *radio_data);

static map_event_dispatcher_t map_agent_ipc_event_dispatcher[] = {
    { MAP_MONITOR_STATION_EVT,              map_handler_sta_event },
    { MAP_MONITOR_WIRED_LINK_EVENT ,        map_handle_netlink_event },
    { MAP_MONITOR_WIRELESS_SSID_RADIO_EVT,  map_handle_wireless_ssid_radio_event}
};

int8_t map_init_agent_ipc_events_callback(uv_loop_t *loop) {
    return init_map_ipc_handler(loop, map_agent_ipc_event_dispatcher, 
        sizeof(map_agent_ipc_event_dispatcher)/sizeof(map_event_dispatcher_t));
}
/************************************************************************************************
                                        EVENT CALLBACKS
*************************************************************************************************/

int8_t map_handler_sta_event(map_monitor_evt_t *event) {
    map_handle_t map_handle = {0};
    stn_event_t *stn_event;
    if(NULL == event) {
        platform_log(MAP_AGENT,LOG_ERR, "%s : Received empty event\n", __FUNCTION__);
        return -1;
    }
    platform_log(MAP_AGENT,LOG_INFO, "Received MAP_MONITOR_STATION_EVT");

    stn_event = event->evt_data;
    if(NULL == stn_event) {
        platform_log(MAP_AGENT,LOG_ERR, "%s : Received empty event data\n", __FUNCTION__);
        return -1;
    }
    /* Need to send 1905 handle to actually send the topology notification */
    get_mcast_macaddr(map_handle.dest_addr);

    map_handle.handle_1905   = handle_1905;
    map_handle.recv_cmdu = NULL;

    /* 
    * Update the global multiap data structure about this new sta event.
    * No need to acquire lock, since the access to global data struct 
    * is serial when accessing from uv_run context.
    */
    map_bss_info_t *bss = NULL;
    bss = get_bss(stn_event->bssid);
    if(bss != NULL) {
        map_update_sta_config(stn_event);

        /*Send the Topology notification */
        map_send_topology_notification(map_handle, stn_event);
    }
    return 0;
}

int8_t map_handle_netlink_event(map_monitor_evt_t *event) {
    map_handle_t map_handle = {0};
    map_network_link_evt_data *network_event_info;
    int8_t state = -1;
    uint8_t lib1905_if_event = 0x00;

    if(NULL == event) {
        platform_log(MAP_AGENT,LOG_ERR, "%s : Received empty event\n", __FUNCTION__);
        return -1;
    }
    platform_log(MAP_AGENT,LOG_INFO, "Received MAP_MONITOR_WIRED_LINK_EVENT");

    // Extract the event data
    network_event_info = (map_network_link_evt_data *)event->evt_data;
    if (NULL == network_event_info) {
        platform_log(MAP_AGENT,LOG_ERR, "%s : network_event_info is empty\n", __FUNCTION__);
        return -1;
    }


    platform_log(MAP_AGENT,LOG_INFO,"%s i/f %s, state '%s'\n", __FUNCTION__, network_event_info->if_name, network_event_info->status);

    if (0 == strcmp(network_event_info->status, "up")) {
        state = INTERFACE_STATE_UP;
        lib1905_if_event = LIB_1905_IF_UP_EVENT;               
    } else if (0 == strcmp(network_event_info->status, "down")) {
         state = INTERFACE_STATE_DOWN;
         lib1905_if_event = LIB_1905_IF_DOWN_EVENT;
    } else if (0 == strcmp(network_event_info->status, "new")) {
        lib1905_if_event = LIB_1905_NEW_IF_CREATED_EVENT;
    } else {
         platform_log(MAP_AGENT,LOG_ERR, "%s : unknown link_event: %s for interface: %s \n", __FUNCTION__, network_event_info->if_name, network_event_info->status);
         return -1;
    }

    if(0!= lib1905_notify_event(handle_1905, network_event_info->if_name, lib1905_if_event)) {
        platform_log(MAP_AGENT,LOG_ERR,"%s i/f %s event %x, 1905 notification failed\n", __FUNCTION__, network_event_info->if_name, lib1905_if_event);
        return -1;
    }

    if(strncmp(network_event_info->if_name,gmap_agent->iface_name,MAX_IFACE_NAME_LEN)==0)
    {
        map_backhaul_link_state_change_cb(&state);
    }
    /* Need to send 1905 handle to actually send the topology notification */
    if(strstr(network_event_info->if_name,"eth")!=NULL) 
    {
        get_mcast_macaddr(map_handle.dest_addr);
        map_handle.handle_1905   = handle_1905;
        map_handle.recv_cmdu = NULL;
        /*Send the Topology notification */
        map_send_topology_notification(map_handle,NULL);
    }
    return 0;
}

int8_t map_handle_wireless_ssid_radio_event(map_monitor_evt_t *event) {
    ssid_radio_state_t *radio_data = NULL;

    if(NULL == event) {
        platform_log(MAP_AGENT,LOG_ERR, "%s : Received empty event\n", __FUNCTION__);
        return -1;
    }
    platform_log(MAP_AGENT,LOG_INFO, "Received MAP_MONITOR_WIRELESS_SSID_RADIO_EVT");

    radio_data = (ssid_radio_state_t *)event->evt_data;
    if (NULL == radio_data) {
     platform_log(MAP_AGENT,LOG_ERR, "%s : radio_data is empty\n", __FUNCTION__);
     return -1;
    }

    map_radio_state_change_event(radio_data);

    return 0;
}

/************************************************************************************************
                                        HELPER FUNCTIONS
*************************************************************************************************/
static int map_update_sta_config(stn_event_t *stn_event)
{
    map_sta_info_t *sta_node   = NULL;
    time_t           curtime;
    /*
     * Get the bss_entry from global multiap data structure
     */
     platform_log(MAP_AGENT,LOG_INFO, "%s\n", __func__);
    if(stn_event->association_event == MAP_STA_ASSOC_EVENT)
    {
        // Create a station if it doesn't exist already
        platform_log(MAP_AGENT,LOG_INFO, "%s Create Node\n", __func__);
        sta_node  = create_sta(stn_event->mac_addr, stn_event->bssid);
        if(sta_node == NULL) {
            platform_log(MAP_AGENT,LOG_ERR, "Failed creating/updating the station %s.\n", stn_event->mac_addr);
              return -EINVAL;
        } else {
          /* Update assoc time */
          time(&curtime);
            sta_node->assoc_time = curtime;

            if(list_get_size(sta_node->metrics) == 0) {
                map_sta_metrics_t *sta_metrics = NULL;
                 sta_metrics = (map_sta_metrics_t*)calloc(1, sizeof(map_sta_metrics_t));
                 if(sta_metrics != NULL) {
                     insert_last_object(sta_node->metrics, (void *)sta_metrics);
                 }
             }

             /*FIXME: Allocate only if sta supports beacon metrics reporting */
             sta_node->beacon_metrics = (beacon_metrics_query_t *)calloc(1, sizeof(beacon_metrics_query_t) +
                               (MAX_AP_REPORT_CHANNELS * sizeof(struct ap_channel_report)));
             if(sta_node->beacon_metrics ==  NULL) {
                platform_log(MAP_AGENT,LOG_ERR, "%s mallco failed\n",__func__);
                return -EINVAL;
             }

            sta_node->assoc_frame   = stn_event->assoc_frame;
            sta_node->assoc_frame_len = stn_event->assoc_frame_len;

        if( sta_node->assoc_frame != NULL && sta_node->assoc_frame_len > 0 ) {
            /* update station capabilities from assoc_frame */
            map_80211_parse_assoc_body(&sta_node->sta_caps, sta_node->assoc_frame, sta_node->assoc_frame_len, 
                               sta_node->bss->radio->supported_freq == IEEE80211_FREQUENCY_BAND_5_GHZ, 
                               sta_node->bss->ssid, sta_node->bss->ssid_len);
        }   
            platform_log(MAP_AGENT,LOG_ERR, "\n\n%s %d, assoc_frame_len %d\n",__func__, __LINE__,stn_event->assoc_frame_len);
         }
    } else {
        /* cleanup other STA related parameters */
        sta_node = get_sta(stn_event->mac_addr);

        if(sta_node != NULL) {
            //  Should we remove it immediately or wait for some time before deleting?
            if(-1 == remove_sta(stn_event->mac_addr, stn_event->bssid)) {
                platform_log(MAP_AGENT,LOG_ERR, " Failed to remove the station %s \n", stn_event->mac_addr);
                return -EINVAL;
            }
        }
    }
    return -EINVAL;
}

static void map_backhaul_link_state_change_cb (int8_t *state)
{
    uint16_t *radio_state = NULL;
    uint8_t i = 0;
    if (NULL == state) {
        platform_log(MAP_AGENT,LOG_ERR, "%s : State is empty\n", __FUNCTION__);
        return;
    }

    /*
     * If the link between the controller and the agent is down, start sending
     * autoconfiguration search message, until the controller if found. Once
     * the controller is found, update the link, via which controller was
     * reached, in the UCI, which will be done in the autoconfiguration
     * reponse validation callback.
     */
    if (*state == INTERFACE_STATE_DOWN) {
        for (i = 0; i < gmap_agent->num_radios; i++) {
            radio_state = &gmap_agent->radio_list[i]->state;
            if (NULL == radio_state) {
                platform_log(MAP_AGENT,LOG_ERR,"map_radio_state is NULL");
                return;
            }

            set_radio_state_freq_unsupported(radio_state);
            set_radio_state_unconfigured(radio_state);
            set_radio_state_freq_supported_by_ctrl(radio_state);
        }
        map_configure_radios();
    }

    return;
}

int find_radio_bss_index_from_interface(char *if_name, int8_t* bss_index) {
    int i = 0;
    int j = 0;

    if (NULL == if_name || NULL == bss_index) {
        platform_log(MAP_AGENT,LOG_ERR, "Interface name or BSS index is NULL");
        return -1;
    }

    for (i = 0; i < gmap_agent->num_radios; i++){

        for(j = 0; j < gmap_agent->radio_list[i]->num_bss; j++) {

            if (0 == strncmp(if_name, gmap_agent->radio_list[i]->bss_list[j]->iface_name, MAX_IFACE_NAME_LEN)) {
                *bss_index = j;
                return i;
            }
        }
    }

    return -1;
}

static void map_radio_state_change_event(ssid_radio_state_t *radio_data) {
    map_handle_t map_handle = {0};
    uint16_t *radio_state   = NULL;
    uint16_t *bss_state   = NULL;
    int8_t index, bss_index = 0;

    if (NULL == radio_data) {
        platform_log(MAP_AGENT,LOG_ERR, "%s : Radio Data is empty\n", __FUNCTION__);
        return;
    }

    /* Get the index of the radio in which the interface(BSS) is present */
    index = find_radio_bss_index_from_interface(radio_data->if_name, &bss_index);

    if (index >= 0 && index < gmap_agent->num_radios) {

        radio_state = &gmap_agent->radio_list[index]->state;
        if (NULL == radio_state) {
            platform_log(MAP_AGENT,LOG_ERR,"map_radio_state is NULL");
            return;
        }

        bss_state = &gmap_agent->radio_list[index]->bss_list[bss_index]->state;
        if (NULL == bss_state) {
            platform_log(MAP_AGENT,LOG_ERR,"map_bss_state is NULL");
            return;
        }

        if (radio_data->radio_state != is_radio_on(*radio_state))
        {
            /* Set the radio state with the obtained state */
            if (radio_data->radio_state == 1)
                set_radio_state_on(radio_state);
            else
                set_radio_state_off(radio_state);
            /*
             * Any change in topology, send a topology notification. Also, the controller
             * might not know about this radio if it was switched on after initial
             * onboarding process was over. So tell him, we have got a new radio or lost
             * an exiting radio, so he may update his table accordingly by sending topology
             * query, for which we will send a topology response with current staatus.
             */

            map_handle.handle_1905 = handle_1905;
            map_handle.recv_cmdu   = NULL;
            get_mcast_macaddr(map_handle.dest_addr);

            platform_log(MAP_AGENT,LOG_INFO,"%s:%d Radio state changed, Send Topo Notification \n",__func__, __LINE__);

            map_send_topology_notification(map_handle,NULL);

            if (1 == is_radio_on(*radio_state)) {

                /* If the state of the radio is up, start autoconfiguration process for the
                 * radio. This is done because, we do not know, if the radio was already
                 * configured and then it was turned off, or it did not get configured at
                 * all. So why take risk? Start from autoconfiguration search.
                 */
                set_radio_state_freq_supported_by_ctrl(radio_state);
                map_configure_radios();
            }
            else {

                /* If the state of the radio is down, change the configuration state of the
                 * radio as UNCONFIGURED. This is because, if the radio is switched on, it
                 * needs to start autoconfiguration process, if not already configured.
                 */
                set_radio_state_unconfigured(radio_state);
            }
        }
        if(is_bss_wps_supported(radio_data->bss_state) != is_bss_wps_supported(*bss_state))
        {
            if(is_bss_wps_supported(radio_data->bss_state))
                set_bss_state_wps_supported(bss_state);
            else
                set_bss_state_wps_unsupported(bss_state);
        }

        if(radio_data->bss_state != is_bss_on(*bss_state)) {
            /* Set the radio state with the obtained state */
                if (radio_data->bss_state == 1)
                    set_bss_state_on(bss_state);
                else
                    set_bss_state_off(bss_state);

            /* Any change in BSS state, send a topoloy notification */

            map_handle.handle_1905 = handle_1905;
            map_handle.recv_cmdu   = NULL;
            get_mcast_macaddr(map_handle.dest_addr);

            platform_log(MAP_AGENT,LOG_INFO,"%s:%d BSS state changed, Send Topo Notification \n",__func__, __LINE__);

            map_send_topology_notification(map_handle,NULL);
        }
    }
    else {
        platform_log(MAP_AGENT,LOG_ERR,"Could not find radio index from interface name");
    }

    return;
}
