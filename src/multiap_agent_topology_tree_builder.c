/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "multiap_agent_topology_tree_builder.h"
#include "map_topology_tree.h"
#include "platform_utils.h"
#include "platform_map.h"
#include "map_timer_handler.h"

#include <syslog.h>
#include "string.h"

#define DEAD_ALE_DETECTION_INTERVEL     15
#define TIMEOUT_TO_DECLARE_ALE_AS_DEAD  90

static uint8_t is_agent_alive(map_ale_info_t *ale);
uint8_t map_delete_dead_agent(char* timer_id, void *arg);

int8_t init_agent_topology_tree()
{
    /* Get the Agent MAC and create the
    root node for the topology tree*/
    uint8_t agent_mac[MAC_ADDR_LEN];
    char mac_addr[MAX_MAC_STRING_LEN];

    memset(&mac_addr,0,sizeof(mac_addr));

    if(map_agent_env_macaddress != NULL)
    {
        strncpy(mac_addr, map_agent_env_macaddress, sizeof(mac_addr)-1);
        mac_addr[sizeof(mac_addr)-1] = '\0';

        if(!platform_get_mac_from_string(mac_addr,agent_mac)){
            platform_log(MAP_AGENT,LOG_ERR, "Agent MAC failed");
            return -1;
        }
    }

    if(init_topology_tree(agent_mac) < 0)
    {
        platform_log(MAP_AGENT,LOG_ERR, " %s Failed to create agent topology tree\n",__func__);
        return -1;
    }

    // Register a periodic timer to delete dead agent from data model
    const char* timer_id = "DEAD_ALE_DETECTION_TIMER";
    if( 0 != map_timer_register_callback(DEAD_ALE_DETECTION_INTERVEL, timer_id, NULL, map_delete_dead_agent)) {
        platform_log(MAP_AGENT,LOG_ERR, "Failed tp register DEAD_ALE_DETECTION_TIMER");
    }

    return 0;
}

void map_add_neighbour_of_agent(map_ale_info_t *ale) {
    if(ale)
        topology_tree_insert(get_root_ale_node(), ale);
}

uint8_t map_delete_dead_agent(char* timer_id, void *arg) {
    map_ale_info_t *neighbor_ale = NULL;

    foreach_child_in(get_root_ale_node(), neighbor_ale) {

        if(!is_agent_alive(neighbor_ale)) {

            int8_t mac_str[MAX_MAC_STRING_LEN];
            get_mac_as_str(neighbor_ale->al_mac, mac_str, MAX_MAC_STRING_LEN);
            platform_log(MAP_CONTROLLER,LOG_INFO, "-------------------------------------------");
            platform_log(MAP_CONTROLLER,LOG_INFO, " Deleting ALE : %s from DM",mac_str);
            platform_log(MAP_CONTROLLER,LOG_INFO, "-------------------------------------------");

            remove_ale(neighbor_ale->al_mac);
        }
    }
    return 0;
}

// Checks if the neighbor agent is alive based on reception of topology discovery
static uint8_t is_agent_alive(map_ale_info_t *ale) {
    if(ale) {
        uint64_t no_update_since = get_clock_diff_secs( get_current_time(), ale->keep_alive_time);

        if(TIMEOUT_TO_DECLARE_ALE_AS_DEAD < no_update_since) {
            return 0;
        }
    }
    return 1;
}
