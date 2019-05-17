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
#ifdef __cplusplus
extern "C" {
#endif

#ifndef MULTIAP_AGENT_IPC_EVENTS_CALLBACK_H
#define MULTIAP_AGENT_IPC_EVENTS_CALLBACK_H

#include <uv.h>
#include "map_events.h"

int8_t map_init_agent_ipc_events_callback(uv_loop_t *loop);

/** @brief Callback on receiving event from montor thread.
 *
 *  This will be assigned as event callback for event type
 *  MAP_MONITOR_STATION_EVT in map agent event diapatcher.
 *
 *  @param : Pointer to received event data (map_monitor_evt_t)
 *  @return: None
 */
int8_t map_handler_sta_event(map_monitor_evt_t *event);

/** @brief Callback on receiving event from montor thread.
 *
 *  This will be assigned as event callback for event type
 *  MAP_MONITOR_WIRED_LINK_EVENT in map agent event diapatcher.
 *
 *  @param : Pointer to received event data (map_monitor_evt_t)
 *  @return: None
 */
int8_t map_handle_netlink_event(map_monitor_evt_t *event);

/** @brief Callback on receiving event from montor thread.
 *
 *  This will be assigned as event callback for event type
 *  MAP_MONITOR_WIRELESS_SSID_RADIO_EVT in map agent event diapatcher.
 *
 *  @param : Pointer to received event data (map_monitor_evt_t)
 *  @return: None
 */
int8_t map_handle_wireless_ssid_radio_event(map_monitor_evt_t *event);

#endif

#ifdef __cplusplus
}
#endif

