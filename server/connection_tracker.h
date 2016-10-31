/*
 * connection_tracker.h
 *
 *  Created on: Sep 29, 2016
 *      Author: Daniel Bailey
 */

#ifndef SERVER_CONNECTION_TRACKER_H_
#define SERVER_CONNECTION_TRACKER_H_

#define CMD_BUFSIZE                     256
#define MAX_CONNTRACK_COMMAND_ARGS_LEN  256
#define STANDARD_CMD_OUT_BUFSIZE        4096
#define CONN_ID_BUF_LEN                 21
#define CRITERIA_BUF_LEN                CMD_BUFSIZE - 20

#define CONNMARK_SEARCH_ARGS "-m %"PRIu32" --src %s --sport %d --dst %s --dport %d"

struct connection{
	uint32_t sdp_id;
	char src_ip_str[MAX_IPV4_STR_LEN];
	char dst_ip_str[MAX_IPV4_STR_LEN];
	unsigned int  src_port;
	unsigned int  dst_port;
	time_t start_time;
	time_t end_time;
	uint64_t connection_id;
	struct connection *next;
};
typedef struct connection *connection_t;

struct present_connection_list_node{
	uint32_t sdp_id;
	connection_t conn;
	struct present_connection_list_node *next;
};
typedef struct present_connection_list_node *present_connection_list_node_t;

void destroy_connection_tracker(fko_srv_options_t *opts);
int update_connections(fko_srv_options_t *opts);
int validate_connections(fko_srv_options_t *opts);
int consider_reporting_connections(fko_srv_options_t *opts);

#endif /* SERVER_CONNECTION_TRACKER_H_ */
