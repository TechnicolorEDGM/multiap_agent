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
#include "multiap_agent_payloads.h"
#include "multiap_agent_ipc_events_callback.h"

#include "multiap_agent_retry.h"
#include "multiap_agent_utils.h"
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#if defined(OPENWRT) && defined(__GLIBC__)
#include <malloc.h>
#endif

#include "monitor_task.h"

#define MGMT_CMDLINE_UBUS "ubus"
#define MGMT_CMDLINE_SOCK "sock"

uv_loop_t *loop;
uv_poll_t uvpoll_handle;
#ifdef OPENWRT
#ifdef __GLIBC__
static uv_signal_t uv_sigusr1;
#endif /* __GLIBC__ */
#endif /* OPENWRT */

mapdhdl gmapd_hdl;

/* New agent node */
map_ale_info_t *gmap_agent = NULL;

unsigned int grun_daemon=0;

plfrm_config pltfrm_config;

handle_1905_t handle_1905;

static void print_usage();
static inline void Err_Argument();
static int monitor_register_events_publish_services();

#ifdef OPENWRT  
#ifdef __GLIBC__
/* Register SIGUSR1 to dump malloc info */
static void uv_sigusr1_handler(uv_signal_t *handle, int signum)
{
    FILE *fp;
    char  fname[128];

    extern const char *__progname;

    snprintf(fname, sizeof(fname), "/tmp/%s.malloc_info", __progname);

    fp = fopen(fname, "w");
    if (fp) {
        malloc_info(0, fp);
        fclose(fp);
    }
}
#endif /* __GLIBC__ */
#endif /* OPENWRT */

static int monitor_register_events_publish_services()
{
	int ret = 0;
	map_monitor_cmd_t cmd;
	
	cmd.cmd = MAP_MONITOR_INIT_DATA_COLLECTION_CMD;
	cmd.subcmd = MAP_MONITOR_BACKHAUL_METRICS_COLLECTION_SUBCMD;	
	ret = map_monitor_send_cmd(cmd);
	if(0 != ret) {
		platform_log(MAP_AGENT,LOG_ERR, "%s send command to start data collection failed\n", __FUNCTION__);
	}

	cmd.cmd = MAP_MONITOR_INIT_DATA_COLLECTION_CMD;
	cmd.subcmd = MAP_MONITOR_AP_METRICS_COLLECTION_SUBCMD;
	ret = map_monitor_send_cmd(cmd);
	if(0 != ret) {
		platform_log(MAP_AGENT,LOG_ERR, "%s send command to start data collection failed\n", __FUNCTION__);
	}

	cmd.cmd = MAP_MONITOR_INIT_DATA_COLLECTION_CMD;
	cmd.subcmd = MAP_MONITOR_STATION_LINK_METRICS_COLLECTION_SUBCMD;
	ret = map_monitor_send_cmd(cmd);
	if(0 != ret) {
		platform_log(MAP_AGENT,LOG_ERR, "%s send command to start data collection failed\n", __FUNCTION__);
	}

	cmd.cmd = MAP_MONITOR_REGISTER_EVENTS_CMD;
	cmd.subcmd = MAP_MONITOR_STATION_EVENTS_SUBCMD;	
	ret = map_monitor_send_cmd(cmd);
	if(0 != ret) {
		platform_log(MAP_AGENT,LOG_ERR, "%s send command to register events failed\n", __FUNCTION__);
	}

	cmd.cmd = MAP_MONITOR_REGISTER_EVENTS_CMD;
	cmd.subcmd = MAP_MONITOR_BTM_REPORT_EVENTS_SUBCMD;
	ret = map_monitor_send_cmd(cmd);
	if(0 != ret) {
		platform_log(MAP_AGENT,LOG_ERR, "%s send command to register events failed\n", __FUNCTION__);
	}

	cmd.cmd = MAP_MONITOR_REGISTER_EVENTS_CMD;
	cmd.subcmd = MAP_MONITOR_WIRELESS_RADIO_EVENTS_SUBCMD;	
	ret = map_monitor_send_cmd(cmd);
	if(0 != ret) {
			platform_log(MAP_AGENT,LOG_ERR, "%s send command to register events failed\n", __FUNCTION__);
	}

	cmd.cmd = MAP_MONITOR_REGISTER_EVENTS_CMD;
        cmd.subcmd = MAP_MONITOR_CLIENT_BEACON_METRICS_METHOD_SUBCMD;
	ret = map_monitor_send_cmd(cmd);
	if(0 != ret) {
	       platform_log(MAP_AGENT,LOG_ERR, "%s send command to register events failed\n", __FUNCTION__);
	}

	cmd.cmd = MAP_MONITOR_PUBLISH_SERVICES_CMD;	
	cmd.subcmd = MAP_MONITOR_TOPOLOGY_QUERY_METHOD_SUBCMD;
	ret = map_monitor_send_cmd(cmd);
	if(0 != ret) {	
		platform_log(MAP_AGENT,LOG_ERR, "%s send command to publish methods failed\n", __FUNCTION__);
	}

        cmd.cmd = MAP_MONITOR_PUBLISH_SERVICES_CMD;
        cmd.subcmd = MAP_MONITOR_SEND_CHANNEL_PREF_REPORT_METHOD_SUBCMD;
        ret = map_monitor_send_cmd(cmd);
        if(0 != ret) {
                platform_log(MAP_AGENT,LOG_ERR, "%s send command to publish methods failed\n", __FUNCTION__);
        }

        cmd.cmd = MAP_MONITOR_PUBLISH_SERVICES_CMD;
        cmd.subcmd = MAP_MONITOR_CLIENT_CAPABILITY_QUERY_METHOD_SUBCMD;
        ret = map_monitor_send_cmd(cmd);
        if(0 != ret) {
                platform_log(MAP_AGENT,LOG_ERR, "%s send command to publish methods failed\n", __FUNCTION__);
        }

        cmd.cmd = MAP_MONITOR_REGISTER_EVENTS_CMD;
        cmd.subcmd = MAP_MONITOR_NETWORK_LINK_EVENTS_SUBCMD;
        ret = map_monitor_send_cmd(cmd);
        if(0 != ret) {
                platform_log(MAP_AGENT,LOG_ERR, "%s send command to register events failed\n", __FUNCTION__);
        }

        cmd.cmd = MAP_MONITOR_REGISTER_EVENTS_CMD;
        cmd.subcmd = MAP_MONITOR_WIRELESS_SSID_EVENTS_SUBCMD;
        ret = map_monitor_send_cmd(cmd);
        if(0 != ret) {
                platform_log(MAP_AGENT,LOG_ERR, "%s send command to register events failed\n", __FUNCTION__);
        }
        
        cmd.cmd = MAP_MONITOR_PUBLISH_SERVICES_CMD;
        cmd.subcmd = MAP_MONITOR_SEND_HIGHERLAYER_DATA_MSG_SUBCMD;
        ret = map_monitor_send_cmd(cmd);
        if(0 != ret) {
                platform_log(MAP_AGENT,LOG_ERR, "%s send command to publish methods failed\n", __FUNCTION__);
        }

        cmd.cmd = MAP_MONITOR_REGISTER_EVENTS_CMD;
        cmd.subcmd = MAP_MONITOR_UNASSOC_MEASUREMENT_RESPONSE_METHOD_SUBCMD;
        ret = map_monitor_send_cmd(cmd);
        if(0 != ret) {
                platform_log(MAP_AGENT,LOG_ERR, "%s send command to register events failed\n", __FUNCTION__);
        }

        cmd.cmd = MAP_MONITOR_PUBLISH_SERVICES_CMD;
	cmd.subcmd = MAP_MONITOR_DEBUG_AGENT_INFO_SUBCMD;
	ret = map_monitor_send_cmd(cmd);
	if(0 != ret) {
			platform_log(MAP_AGENT,LOG_ERR, "%s send command to publish methods failed\n", __FUNCTION__);
	}

	cmd.cmd = MAP_MONITOR_ADD_OBJ_CMD;	
	ret = map_monitor_send_cmd(cmd);
	if(0 != ret) {	
		platform_log(MAP_AGENT,LOG_ERR, "%s send command to add object failed\n", __FUNCTION__);
	}

	return ret;
}

int main(int argc, char *argv[])
{
	int opt;
	int ret=0;
	int num_subargs=0;	

	while( (opt = getopt( argc, argv, "csdf:m:l:" ))!= -1 )
	{
		switch( opt )
		{
			case 'f':
				if( strlen(optarg) > PATH_NAME_MAX )
					Err_Argument();
				else
					pltfrm_config.config_file=optarg;
				break;
			case 'c':
				pltfrm_config.map_config.multiap_opts.is_controller_avail=1;
				break;
			case 'm':
				optind--;
				for( ;optind < argc && *argv[optind] != '-'; optind++)
				{
					if(strcmp(MGMT_CMDLINE_UBUS, argv[optind])== 0)
					{
						pltfrm_config.map_config.multiap_opts.is_mgmt_ubus=1;
						num_subargs+=1;
						break;
					}
					else if(strcmp(MGMT_CMDLINE_SOCK, argv[optind])== 0)
					{
						pltfrm_config.map_config.multiap_opts.is_mgmt_sock=1;
						num_subargs+=1;
					}
					else
					{
						if(pltfrm_config.map_config.multiap_opts.is_mgmt_sock)
						{
							if(strlen(argv[optind]) < SOCK_NAME_LEN_MAX)
								pltfrm_config.mgmt_sock_name=argv[optind];
							else
								num_subargs=0;
						}	
					}

				}
				if(num_subargs ==0 || num_subargs >1)
					Err_Argument();
				break;
			case 's':
				pltfrm_config.log_output=log_stdout;
				break;
			case 'd':
				grun_daemon=1;
				break;
			case 'h':
			case '?':
			default:
				print_usage();
				exit(EXIT_FAILURE);
				break;

			/* You should not actually get here. */
		}
	}

	pltfrm_config.map_config.version = AGENT_VERSION;

	if(platform_init(&pltfrm_config))
	{
		Err_Argument();
	}
#ifndef OPENWRT
	init_signal_handling();
#endif

	loop=malloc(sizeof(uv_loop_t));
	init_workqueue_handles();
	
	uv_loop_init(loop);

#ifdef OPENWRT
#ifdef __GLIBC__
	/* Register SIGUSR1 to dump malloc info */
	uv_signal_init(loop, &uv_sigusr1);
	uv_signal_start(&uv_sigusr1, uv_sigusr1_handler, SIGUSR1);
#endif /* __GLIBC__ */
#endif /* OPENWRT */

	init_retry_timers(loop);
	init_periodic_timers(loop, &pltfrm_config.map_config.periodic_timer);
	if(multiap_agent_init() < 0) {
		platform_log(MAP_AGENT,LOG_ERR, "%s Multiap_agent init failed\n", __FUNCTION__);
	}
	
	if(map_monitor_thread_init(&pltfrm_config.map_config.monitor_q_hdle, MAP_MONITOR_AGENT) < 0) {
		platform_log(MAP_AGENT,LOG_ERR, "%s map_monitor_thread_init failed\n", __FUNCTION__);
	} else {
		platform_log(MAP_AGENT,LOG_DEBUG, "%s map_monitor_thread_init completed\n", __FUNCTION__);
	}
	ret = map_init_agent_ipc_events_callback(loop);
	if(0 != ret){
		platform_log(MAP_AGENT,LOG_ERR, "%s Failed to initialize ipc event callback", __FUNCTION__);
	}

	ret = monitor_register_events_publish_services();
	if(0 != ret) {
		platform_log(MAP_AGENT,LOG_ERR, "%s monitor_register_events_publish_services failed", __FUNCTION__);
	}
	
	uv_poll_init(loop, &uvpoll_handle, pltfrm_config.al_fd);
	uv_poll_start(&uvpoll_handle, (UV_READABLE|UV_DISCONNECT), uvpoll_1905read_cb);
	
	uv_run(loop, UV_RUN_DEFAULT);

#ifdef OPENWRT
#ifdef __GLIBC__
	uv_signal_stop(&uv_sigusr1);
#endif /* __GLIBC__ */
#endif /* OPENWRT */

	uv_loop_close(loop);
	free(loop);
	exit(EXIT_SUCCESS);
}

static inline void Err_Argument()
{
	printf("\n Invalid Arguments");
	print_usage();
	exit(EXIT_FAILURE);
}

static void print_usage()
{
	printf("\n ------MultiAP Agent Daemon-------");
	printf("\n -f 	option to provide non default config file with path");
	printf("\n -c 	Option to mention contoller co-exists with the agent");
	printf("\n -m 	to enable managemnt interface to debugging ");
	printf("\n		<ubus> for ubus based");
	printf("\n		<sock> for socket based followed by <name> of the socket");	
	printf("\n -d 	option to put error logs in console rather than syslog");	
	printf("\n -l 	option to Mention log level for Debugging");
	printf("\n 		<1>Only Critical errors and Exceptions");
	printf("\n 		<2>Info Logs with <1>");
	printf("\n 		<3>Debug Logs with <1> and <2>");
	printf("\n 		<4>Noise Level Logs with packet dumps (Dont use this unless required)");

}
