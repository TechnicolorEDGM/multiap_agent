/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "multiap_agent_tlv_helper.h"
#include "map_data_model.h"
#include "arraylist.h"
#include "map_topology_tree.h"
#include "platform_multiap_get_info.h"
#include "1905_platform.h"

int map_get_bridge_info_tlv (struct deviceBridgingCapabilityTLV *bridge_info) {
    int i      = 0;
    int j      = 0;
    int status = 0;
    int br_nr  = 0;
    struct bridge *br = NULL;
    uint8_t empty_str[MAX_IFACE_NAME_LEN] = {0};
    struct interfaceInfo if_info = {0};

    do {
        if (!bridge_info) {
            platform_log(MAP_AGENT,LOG_ERR,"%s : device_info is NULL",__func__);
            break;
        }

        bridge_info->tlv_type = TLV_TYPE_DEVICE_BRIDGING_CAPABILITIES;
        if (-1 == platform_get(MAP_PLATFORM_GET_BRIDGE_INFO, NULL, (void *)&br)) {
            platform_log(MAP_AGENT,LOG_ERR,"%s : platform_get failed for MAP_PLATFORM_GET_BRIDGE_INFO",__func__);
            break;
        }

        if (br) {
            while ((memcmp(br[br_nr].name, empty_str, MAX_IFACE_NAME_LEN) != 0)) {
                br_nr++;

                /* This check is to avoid infinite loop */
                if(br_nr >= MAX_BRIDGES_PER_DEV) {
                    break;
                }
            }
        }
        bridge_info->bridging_tuples_nr = br_nr;

        if (0 == br_nr) {
            bridge_info->bridging_tuples = NULL;
        }
        else {
            bridge_info->bridging_tuples = (struct _bridgingTupleEntries *) calloc(1, sizeof(struct _bridgingTupleEntries) *br_nr);

            for (i = 0; i < br_nr; i++) {
                bridge_info->bridging_tuples[i].bridging_tuple_macs_nr = br[i].bridged_interfaces_nr;

                if (0 == br[i].bridged_interfaces_nr) {
                    bridge_info->bridging_tuples[i].bridging_tuple_macs = NULL;
                }
                else {
                    bridge_info->bridging_tuples[i].bridging_tuple_macs = (struct _bridgingTupleMacEntries *) calloc(1, sizeof(struct _bridgingTupleMacEntries) * br[i].bridged_interfaces_nr);

                    for (j = 0; j < br[i].bridged_interfaces_nr; j++) {
                        if((memcmp(br[i].bridged_interfaces[j], empty_str, MAX_IFACE_NAME_LEN) != 0)) {
                            platform_get(MAP_PLATFORM_GET_INTERFACE_INFO, br[i].bridged_interfaces[j], (void *)&if_info);
                            memcpy(bridge_info->bridging_tuples[i].bridging_tuple_macs[j].mac_address, if_info.mac_address, MAC_ADDR_LEN);
                        }
                    }
                }
            }
        }

        if (br) {
            free(br);
        }
    } while (0);

    return status;
}

void map_free_bridge_info_tlv (struct deviceBridgingCapabilityTLV *bridge_info_tlv) {
    int  i = 0;
    if (bridge_info_tlv) {
        if (bridge_info_tlv->bridging_tuples_nr > 0) {
            for (i = 0; i < bridge_info_tlv->bridging_tuples_nr; i++) {
                if (bridge_info_tlv->bridging_tuples[i].bridging_tuple_macs_nr > 0) {
                    free(bridge_info_tlv->bridging_tuples[i].bridging_tuple_macs);
                }
            }
            free(bridge_info_tlv->bridging_tuples);
        }
    }
    return;
}

int map_get_1905_neighbor_tlvs (struct neighborDeviceListTLV *neighbor_1905_tlvs, int *neighbor_count) {
    int tlv_already_added = 0;
    int status = 0;
    int count  = 0;
    int i      = 0;
    map_ale_info_t* neighbor_ale = NULL;

    do {
        if ((!neighbor_1905_tlvs) || (!neighbor_count)) {
            platform_log(MAP_AGENT,LOG_ERR,"%s : neighbor_tlvs or neighbor_count is NULL",__func__);
            break;
        }

        /* Get 1905 neighbor list */
        foreach_neighbors_of(gmap_agent, neighbor_ale) {
            if (neighbor_ale) {
                for (i = 0; i < count; i++) {
                    /* Check whether the interface is same as an already added interface */
                    if (0 == memcmp(neighbor_1905_tlvs[i].local_mac_address, neighbor_ale->upstream_remote_iface_mac, MAC_ADDR_LEN)) {
                        tlv_already_added = 1;
                        break;
                    }
                }
                if (i < MAX_INTERFACE_COUNT) {
                    struct neighborDeviceListTLV *neigh = (struct neighborDeviceListTLV *) &neighbor_1905_tlvs[i];
                    if (!tlv_already_added) {
                        /* Add a tlv for this new interface */
                        neigh->tlv_type = TLV_TYPE_NEIGHBOR_DEVICE_LIST;
                        memcpy(neigh->local_mac_address, neighbor_ale->upstream_remote_iface_mac, MAC_ADDR_LEN);
                        neigh->neighbors_nr = 0;
                        neigh->neighbors    = (struct _neighborEntries *) calloc(1, sizeof(struct _neighborEntries));
                        count++;
                    }
                    else {
                        /* Tlv for this interface already exits, hence update */
                        neigh->neighbors    = (struct _neighborEntries *) realloc(neigh->neighbors, sizeof(struct _neighborEntries) * (neigh->neighbors_nr+1));
                    }
                    memcpy(neigh->neighbors[neigh->neighbors_nr].mac_address, neighbor_ale->al_mac, MAC_ADDR_LEN);
                    /* TODO :  Fill in bridge existence data */
                    neigh->neighbors[neigh->neighbors_nr].bridge_flag = 0;
                    neigh->neighbors_nr++;
                }
            }
            tlv_already_added = 0;
        }
        *neighbor_count = count;
    } while (0);

    return status;
}

void map_free_1905_neighbor_tlv (struct neighborDeviceListTLV *neighbor_1905_tlv) {
    if (neighbor_1905_tlv) {
        if (neighbor_1905_tlv->neighbors_nr > 0) {
            free(neighbor_1905_tlv->neighbors);
        }
    }
    return;
}

static void map_fill_non1905_neighbor_tlv(struct non1905NeighborDeviceListTLV *non1905_neigh, map_bss_info_t *bss, int sta_count) {
    if (non1905_neigh) {
        non1905_neigh->tlv_type = TLV_TYPE_NON_1905_NEIGHBOR_DEVICE_LIST;
        memcpy (non1905_neigh->local_mac_address, bss->bssid, MAC_ADDR_LEN);
        non1905_neigh->non_1905_neighbors_nr = 0;
        non1905_neigh->non_1905_neighbors    = NULL;
        if (sta_count > 0) {
            non1905_neigh->non_1905_neighbors = (struct _non1905neighborEntries *) calloc (1, sizeof(struct _non1905neighborEntries) * sta_count);
        }
    }
    return;
}

static void map_fill_bssInfo_tlv (struct bssInfo *bss_info, struct bss_info *assoc_bss_info, map_bss_info_t *bss_node) {
    if (bss_info && bss_node && assoc_bss_info) {

        /* Fill Ap operataional BSS tlv */
        memcpy(bss_info->bssid, bss_node->bssid, MAC_ADDR_LEN);
        strncpy((char *)bss_info->ssid, (char* )bss_node->ssid, MAX_SSID_LEN);
        bss_info->ssid[MAX_SSID_LEN - 1] = '\0';
        bss_info->ssid_len = strnlen((char*)bss_info->ssid, MAX_SSID_LEN);

        /*Initialise associated sta tlv */
        memcpy(assoc_bss_info->bssid, bss_node->bssid, MAC_ADDR_LEN);
    }
}

int map_get_wireless_topology_response_tlvs (struct mapApOperationalBssTLV *ap_operational_bss_tlv, struct non1905NeighborDeviceListTLV *non1905_neighbor_tlvs, int *non1905_neighbor_count, struct mapAssociatedClientsTLV *assoc_sta_tlv, int *total_sta_count) {

    struct non1905NeighborDeviceListTLV *non1905_neigh = NULL;
    map_radio_info_t *radio_node     = NULL;
    map_bss_info_t   *bss_node       = NULL;
    map_sta_info_t   *sta_node       = NULL;
    struct radioInfo *radio_info     = NULL;
    struct bssInfo   *bss_info       = NULL;
    struct bss_info  *assoc_bss_info = NULL;
    uint8_t          *sta_mac        = NULL;
    time_t            curtime        = {0};
    int               bss_per_radio  = 0;
    int               neigh_count    = 0;
    int               radio_count    = 0;
    int               bss_count      = 0;
    int               sta_count      = 0;
    int               status         = 0;
    int               i              = 0;
    int               j              = 0;

    do {
        if ((!assoc_sta_tlv) || (!ap_operational_bss_tlv)) {
            platform_log(MAP_AGENT,LOG_ERR, "%s : Input validation failed", __func__);
            break;
        }

        assoc_sta_tlv->tlv_type          = TLV_TYPE_ASSOCIATED_STA_TLV;
        ap_operational_bss_tlv->tlv_type = TLV_TYPE_AP_OPERATIONAL_BSS;

        for (i = 0; i < gmap_agent->num_radios; i++) {
            radio_node  = gmap_agent->radio_list[i];


                radio_info = (struct radioInfo *) &ap_operational_bss_tlv->radioInfo[radio_count];
                memcpy(radio_info->radioId, radio_node->radio_id, MAC_ADDR_LEN);
                ap_operational_bss_tlv->tlv_length += MAC_ADDR_LEN;

                for (j = 0; j < radio_node->num_bss; j++) {
                    bss_node = (map_bss_info_t *) radio_node->bss_list[j];

                    /* Add BSS info only if they up and running */
                    if((bss_node) && (is_bss_on(radio_node->bss_list[j]->state))) {
                        bss_info       = (struct bssInfo *) &radio_info->bss_info[bss_per_radio];
                        assoc_bss_info = (struct bss_info *) &assoc_sta_tlv->bssinfo[bss_count];
                        non1905_neigh  = (struct non1905NeighborDeviceListTLV *) &non1905_neighbor_tlvs[neigh_count];

                        /* Initialize non 1905 neighbor device tlv */
                        map_fill_non1905_neighbor_tlv(non1905_neigh, bss_node, list_get_size(bss_node->sta_list));

                        /* Update Bss info tlv */
                        map_fill_bssInfo_tlv(bss_info, assoc_bss_info, bss_node);
                        ap_operational_bss_tlv->tlv_length += MAC_ADDR_LEN + strlen((char*)bss_info->ssid) + 1;

                        list_iterator_t* it = new_list_iterator(bss_node->sta_list);
                        if (it) {
                            while(NULL != (sta_mac = (uint8_t*)get_next_list_object(it))) {
                                if ((sta_count < MAX_STA_PER_BSS) && (*total_sta_count < MAX_STATIONS)) {

                                    sta_node = get_sta(sta_mac);
                                    if(sta_node) {
                                        memcpy(assoc_bss_info->sta_assoc_time[sta_count].sta_mac, sta_node->mac, MAC_ADDR_LEN);
                                        time(&curtime);
                                        assoc_bss_info->sta_assoc_time[sta_count].since_assoc_time = (uint16_t)difftime(curtime, sta_node->assoc_time);

                                        if (!sta_node->sta_caps.backhaul_sta) {
                                            memcpy(non1905_neigh->non_1905_neighbors[non1905_neigh->non_1905_neighbors_nr].mac_address, sta_mac, MAC_ADDR_LEN);
                                            non1905_neigh->non_1905_neighbors_nr++;
                                        }
                                        sta_count++;
                                        (*total_sta_count)++;
                                    }
                                }
                            }

                            if (sta_count > 0 ) {
                                assoc_bss_info->no_of_sta = sta_count;
                                assoc_sta_tlv->tlv_length += MAC_ADDR_LEN;  /* BSSID length */
                                assoc_sta_tlv->tlv_length += (MAC_ADDR_LEN + 2) * sta_count; /* Mac address + sizeof assoc_time of sta */
                                assoc_sta_tlv->tlv_length += 2;
                                bss_count++;
                            }
                            free_list_iterator(it);
                        }
                        if (non1905_neigh->non_1905_neighbors_nr > 0) {
                            neigh_count++;
                        }
                        else {
                            free(non1905_neigh->non_1905_neighbors);
                        }
                        bss_per_radio++;
                        sta_count = 0;
                    }
                }
                radio_info->no_of_bss = bss_per_radio;
                ap_operational_bss_tlv->tlv_length += 1;
                radio_count++;
                bss_per_radio = 0;
        }
        ap_operational_bss_tlv->tlv_length   += 1;
        assoc_sta_tlv->tlv_length            += 1;
        ap_operational_bss_tlv->no_of_radios = radio_count;
        assoc_sta_tlv->no_of_bss             = bss_count;
        *non1905_neighbor_count              = neigh_count;
    } while (0);

    return status;
}

void map_free_non1905_neighbor_tlv (struct non1905NeighborDeviceListTLV *non1905_neighbor_tlv) {
    if(non1905_neighbor_tlv) {
        if (non1905_neighbor_tlv->non_1905_neighbors_nr > 0) {
            free(non1905_neighbor_tlv->non_1905_neighbors);
        }
    }
    return;
}
