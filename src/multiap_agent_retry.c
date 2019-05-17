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

static map_dm_retry_t map_retry_dm[MAX_RETRY_DM];

int dump_retry_in_use()
{
    int i = 0;
    for (i = 0; i<MAX_RETRY_DM; i++) {
        if(map_retry_dm[i].inuse == 1) {
           platform_log(MAP_AGENT,LOG_DEBUG, "In use for mtype %s, mid 0x%x\n", (map_retry_dm[i].resp_msg_type == CMDU_TYPE_AP_AUTOCONFIGURATION_WSC) ? "CMDU_TYPE_AP_AUTOCONFIGURATION_WSC" : "CMDU_TYPE_AP_AUTOCONFIGURATION_RESP", map_retry_dm[i].mid);
        }
    }
    return 0;
}

static map_dm_retry_t* check_for_existing_timer(uint16_t send_msg_type, uint16_t resp_msg_type)
{
    int i = 0;

    for (i = 0; i<MAX_RETRY_DM; i++) {
        /*
         * Find retry entry from global retry data_model, 
         * with msg_id as reference
         */
        if (map_retry_dm[i].send_msg_type == send_msg_type && 
            map_retry_dm[i].resp_msg_type == resp_msg_type)
            return &map_retry_dm[i];
    }
    return NULL;
}

static map_dm_retry_t* find_retry_dm_entry(uint16_t mid)
{
    int i = 0;

    for (i = 0; i<MAX_RETRY_DM; i++) {
        /*
         * Find retry entry from global retry data_model, 
         * with msg_id as reference
         */
        if (map_retry_dm[i].mid == mid)
            return &map_retry_dm[i];
    }

    return NULL;
}

int map_get_send_msgtype(struct CMDU *response_cmdu, uint16_t *send_msg_type)
{
    map_dm_retry_t *retry_dm = NULL;
    uint16_t       mid       = 0;

    if((NULL == send_msg_type) || (response_cmdu == NULL))
        return -EINVAL;

    mid = response_cmdu->message_id;

    retry_dm = find_retry_dm_entry(mid);
    if(retry_dm != NULL &&
       response_cmdu->message_type == retry_dm->resp_msg_type)
    {
        *send_msg_type = retry_dm->send_msg_type;
        return 0;
    }
    return -EINVAL;
}

static map_dm_retry_t* find_unused_dm_entry(void)
{
    int i = 0;

    for (i = 0; i<MAX_RETRY_DM; i++) {
        if (!map_retry_dm[i].inuse)
            return &map_retry_dm[i];
    }
    return NULL;
}

static int freeup_retry_timer(map_dm_retry_t *retry_dm)
{

    platform_log(MAP_AGENT,LOG_DEBUG, "%s %d, mid 0x%x, recv type %d\n\n", __func__, __LINE__, retry_dm->mid, retry_dm->resp_msg_type);

    retry_dm->inuse                 = 0;
    retry_dm->mid                   = 0;
    retry_dm->send_msg_type         = 0;
    retry_dm->resp_msg_type         = 0;
    retry_dm->retry_count           = 0;
    retry_dm->retry_count_threshold = 0;
    retry_dm->send_cb               = NULL;
    memset(retry_dm->dst_mac, 0, 6);

    /*
     * Do not reset the handle, it will cause the system unstable
     */
    uv_timer_stop(&retry_dm->handle);
    return 0;
}

int update_retry_timer (uint16_t mid, uint16_t msg_type, uint8_t skip_mid_check)
{
   map_dm_retry_t *retry_dm = NULL;
   time_t         ltime     = time(NULL);
   int            i         = 0; 

   platform_log(MAP_AGENT,LOG_DEBUG, "%s %d, response mid 0x%x, msg_type %d\n", __func__, __LINE__, mid, msg_type);

   retry_dm = find_retry_dm_entry(mid);

   if(retry_dm != NULL) {
      if( msg_type == retry_dm->resp_msg_type) {
         platform_log(MAP_AGENT,LOG_DEBUG, "%s %d, sent payload time_stamp %ld \n", __func__, __LINE__, retry_dm->send_time);
         platform_log(MAP_AGENT,LOG_DEBUG, "timediff from sent,resp %.f sec\n", difftime(ltime, retry_dm->send_time));
         /*
          * Control comes here means we have received 
          * response within 1s
          */
         freeup_retry_timer(retry_dm);
         if(retry_dm->completion_cb != NULL)
             retry_dm->completion_cb(retry_dm->data);

         return 0;
      }
   } else {
       /* 
        * There is no matching MessageId found in retry data model,
        * Check if there is already a retry obj waiting for this message and
        * 1) if no retry obj found, then this might me new CMDU.
        * 2) if retry obj found and skip_mid_check is also not set, then there is MessageId mismatch.
        * 3) if retry obj found and skip_mid_check is set, then stop the retry and call completion_cb();
        */
       for (i = 0; i<MAX_RETRY_DM; i++) {
           if ((map_retry_dm[i].resp_msg_type == msg_type))
              break;
       }
       
        if ((i < MAX_RETRY_DM) && (skip_mid_check)){
            /*
             * Control comes here means we have received response CMDU,
             * and we skip mid validation.
             */
            map_dm_retry_t *retry_obj = &map_retry_dm[i];

            freeup_retry_timer(retry_obj);
            if(retry_obj->completion_cb != NULL)
                retry_obj->completion_cb(retry_dm->data);

        } else if ((i < MAX_RETRY_DM) && (!skip_mid_check)){
            /*
             * Control comes here because, we receive CMDU with different mid than expected,
             * and so we will continue retry.
             */
            platform_log(MAP_AGENT,LOG_DEBUG, "\n %s %d, msg_type mismatch %d mid 0x%x\n", __func__, __LINE__, msg_type, map_retry_dm[i].mid);
            return -EINVAL;
        }
     
   }
   return 0;
}

void retry_timer_cb (uv_timer_t *handle)
{
    int            index         = 0;
    map_dm_retry_t *retry_dm     = NULL;
    uint16_t       send_msg_type = 0;
    uint8_t        dst_mac[6]    = {0};
    uint8_t        src_iface_name[MAX_IFACE_NAME_LEN]    = {0};
    map_handle_t   map_handle    = {0};
    int        (*send_cb)(map_handle_t, void*)  = NULL;

    retry_dm = (map_dm_retry_t *)handle->data; 
    if( retry_dm == NULL || retry_dm->inuse == 0 ) {
        platform_log(MAP_AGENT,LOG_ERR,"%s %d, retry handle not registered\n",__func__, __LINE__);
        return;
    }

    send_msg_type = retry_dm->send_msg_type;
    memcpy(dst_mac, retry_dm->dst_mac, 6);
    memcpy(src_iface_name, retry_dm->iface_name, MAX_IFACE_NAME_LEN);

    if(retry_dm->send_cb != NULL) {
         map_handle.handle_1905   = handle_1905;
         map_handle.recv_cmdu     = NULL;
         memcpy(map_handle.dest_addr, dst_mac, 6);
         memcpy(map_handle.src_iface_name, retry_dm->iface_name, MAX_IFACE_NAME_LEN);
         send_cb = retry_dm->send_cb;
    }

    if(retry_dm->retry_count > retry_dm->retry_count_threshold) {
    /*
     * Retry count reached the threshold count
     * cleanup retry timer.
     */
        freeup_retry_timer(retry_dm);

        if(retry_dm->completion_cb != NULL)
            retry_dm->completion_cb(retry_dm->data);

        return;
    }

    /*
     * Stop retry timer as of now and do not clean, 
     * since the cleanup should happen only when the retry count exceeds threshold
     */
    uv_timer_stop(&retry_dm->handle);
    //freeup_retry_timer(retry_dm);
    if(send_cb != NULL) {
        send_cb(map_handle, (void*) retry_dm->data);
        return;   
    }

    index = find_gmap_cb_index_from_send_msgtype(send_msg_type);
    if( index != -1 ) {
        map_datagather_and_send(dst_mac, src_iface_name, index, NULL);
    }
    return;
}

int fire_retry_timer (uint8_t *dst_mac, uint8_t *iface_name, uint16_t send_msg_type, uint16_t resp_msg_type, 
                      uint8_t retry_threshold, uint16_t msg_id, int timeout_in_ms, int (*send_cb)(map_handle_t, void *), int (*completion_cb)(void *data), void* data)
{
    time_t ltime = time(NULL);
    map_dm_retry_t *retry_dm = NULL;

    if(msg_id <= 0 || 
       resp_msg_type <= 0) {
       platform_log(MAP_AGENT,LOG_ERR,"%s %d, Invalid resp_msg_id, msg_type\n",__func__, __LINE__);
       return -EINVAL;
    }

    /*
     * Check if timer is already running for the same msg type
     */
    retry_dm = check_for_existing_timer(send_msg_type, resp_msg_type);
    if (retry_dm == NULL) {
        /*
         * We make sure only one instance of the timer for the one msg type is running
         */
        platform_log(MAP_AGENT,LOG_DEBUG, "%s %d, Creating new retry instance\n", __func__, __LINE__);
        retry_dm = find_unused_dm_entry();
        if(retry_dm == NULL) {
            platform_log(MAP_AGENT,LOG_ERR,"%s %d, No free retry entry found\n", __func__, __LINE__);
            return -EINVAL;
        }
    } else {
        /*
         * We see the timer is already running for the same msg type.
         * we shall stop it for a while.
         */
         platform_log(MAP_AGENT,LOG_DEBUG, "%s %d, Already a retry instance running\n", __func__, __LINE__);
         uv_timer_stop(&retry_dm->handle);
    }

    platform_log(MAP_AGENT,LOG_DEBUG, "%s %d, send_mtype 0x%x, resp 0x%x, mid 0x%x\n\n", __func__, __LINE__, send_msg_type, resp_msg_type, msg_id);
    /*
     * Update the entry with latest timestamp
     */
    retry_dm->send_time             = ltime;
    retry_dm->mid                   = msg_id;
    retry_dm->resp_msg_type         = resp_msg_type;
    retry_dm->send_msg_type         = send_msg_type;
    retry_dm->send_cb               = send_cb;
    retry_dm->data                  = data;
    retry_dm->completion_cb         = completion_cb;
    retry_dm->retry_count_threshold = retry_threshold;
    retry_dm->retry_count          += 1;
    strncpy((char *)retry_dm->iface_name,(char *)iface_name, MAX_IFACE_LEN);
    memcpy(retry_dm->dst_mac, dst_mac, MAC_ADDR_LEN);

    retry_dm->inuse         = 1;
    uv_timer_start(&retry_dm->handle, retry_timer_cb, timeout_in_ms, timeout_in_ms);
    return 0;
}

void wq_timer_cb (uv_timer_t *handle)
{
    map_dm_retry_t *retry_dm     = NULL;

    retry_dm = (map_dm_retry_t *)handle->data; 
    if( retry_dm == NULL || retry_dm->inuse == 0 ) {
        platform_log(MAP_AGENT,LOG_ERR,"%s %d, retry handle not registered\n",__func__, __LINE__);
        return;
    }


    if(retry_dm->completion_cb != NULL)
        retry_dm->completion_cb(retry_dm->data);

    /*
     * Stop the retry timer
     */
    uv_timer_stop(&retry_dm->handle);
    freeup_retry_timer(retry_dm);

    return;
}


int execute_after ( int (*completion_cb)(void *data), void * data, int delay_time) {
    map_dm_retry_t *retry_dm = NULL;

    retry_dm = find_unused_dm_entry();
    if(retry_dm == NULL) {
        platform_log(MAP_AGENT,LOG_ERR,"%s %d, No free retry entry found\n", __func__, __LINE__);
        return -EINVAL;
    }

    retry_dm->data                  = data;
    retry_dm->completion_cb         = completion_cb;
    retry_dm->inuse                 = 1;

    uv_timer_start(&retry_dm->handle, wq_timer_cb, delay_time, delay_time);

    return 0;
}



int init_retry_timers(uv_loop_t  *loop)
{
    int i = 0;
    for (i = 0; i<MAX_RETRY_DM; i++) {
        uv_timer_init(loop, &map_retry_dm[i].handle);
        map_retry_dm[i].handle.data = (void *)&map_retry_dm[i];

    }
    return 0;
}
