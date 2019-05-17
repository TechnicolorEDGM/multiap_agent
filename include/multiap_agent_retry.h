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

#ifndef MULTIAP_AGENT_RETRY_H

#define MULTIAP_AGENT_RETRY_H

#define MAX_RETRY_DM 10
#define MAX_RETRY_PER_MSG 5
#define MAX_IFACE_LEN 32

#define SKIP_MID_CHECK 1
#define CHECK_MID      0

typedef struct map_dm_retry {
    uv_timer_t handle;
    time_t     send_time;
    uint16_t   mid;
    uint16_t   send_msg_type;
    uint16_t   resp_msg_type;
    uint8_t    inuse;
    uint8_t    dst_mac[MAC_ADDR_LEN];
    int (*send_cb)(map_handle_t , void* );
    uint8_t    iface_name[MAX_IFACE_LEN];
    uint8_t    retry_count;
    uint8_t    retry_count_threshold;
    void*      data;
    int        (*completion_cb)(void*);
} map_dm_retry_t;

int dump_retry_in_use();
/** @brief This api will get the sender msg type for which the ack is received
 * 
 *  This function willbe called for 1905_ack to find the send msg type
 *
 *  @param struct CMDU *
 */
int map_get_send_msgtype(struct CMDU *cmdu, uint16_t *send_msg_type);

/** @brief This api will initialise all retry_timers in multiap.
 * 
 *  This function will be called from main, to initialise retry_timers in multiap.
 *
 *  @param loop uv_loop *
 */
int init_retry_timers(uv_loop_t  *loop);


/** @brief This api will trigger the retry timer
 * 
 *  This function will be called from send_cb of multiap callback donfig.
 *
 *  @param dst_mac this will be sending payload's dst mac
 *  @param iface_name this will be sending payload's interface_name
 *  @param send_msg_type this will be sending payload's msg type
 *  @param resp_msg_type this will be response payload's msg type
 *  @param msg_id this will be response msg_id(mostly same as send msg_id)
 *  @param timeout_in_ms Retry timer timeout
 *  @param send_cb This will be called for retry send. This will take priority.
 */
int fire_retry_timer (uint8_t *src_mac, uint8_t *iface_name, uint16_t send_msg_type, uint16_t resp_msg_type, 
                      uint8_t retry_threshold, uint16_t msg_id, int timeout_in_ms, int (*send_cb)(map_handle_t, void*), int (*completion_cb)(void * data), void* data);

/** @brief This api will update the retry timer with new mid and time stamp
 * 
 *  This function will be called from map_read_cb()
 *
 *  @param mid new sender mid
 *  @param msg_type this will be response payload's msg type
 */
int update_retry_timer (uint16_t mid, uint16_t msg_type, uint8_t skip_mid_check);

int execute_after ( int (*completion_cb)(void *data), void * data, int delay_time);
#endif

#ifdef __cplusplus
}
#endif

