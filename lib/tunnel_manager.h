/*
 * tunnel_manager.h
 *
 *  Created on: Jun 27, 2017
 *      Author: Daniel Bailey
 */

#ifndef TUNNEL_MANAGER_H_
#define TUNNEL_MANAGER_H_

#include <uv.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <json-c/json.h>
#include "fko_limits.h"
#include "hash_table.h"

#define ID_TOKEN_BUF_LEN 2048
#define MAX_PIPE_MSG_LEN 65536   // TODO: this is max tcp packet size

#define TUNNEL_PORT 8282
#define TUNNEL_BACKLOG 10

#define NAME_TM_GATEWAY_PIPE "tm_g_pipe"
#define NAME_TM_CLIENT_PIPE "tm_c_pipe"


enum {
    PTR_TO_JSON,
    PTR_TO_STR
};

enum {
    SEND_PTR,
    SEND_STR
};

enum {
    IS_SDP_GATEWAY = 0,
    IS_SDP_CLIENT = 1
};

struct tunneled_service{
    uint32_t service_id;
    uint32_t idp_id;
    char id_token[ID_TOKEN_BUF_LEN];
    struct tunneled_service *next;
};
typedef struct tunneled_service *tunneled_service_t;

struct tunnel_info{
    uint32_t sdp_id;
    char remote_public_ip[MAX_IPV4_STR_LEN];
    char remote_tunnel_ip[MAX_IPV4_STR_LEN];
    unsigned int remote_port;
    uint32_t idp_id;
    char id_token[ID_TOKEN_BUF_LEN];
    tunneled_service_t services_requested;
    tunneled_service_t services_opened;
    uv_tcp_t *handle;
    hash_table_t *containing_tbl;
    time_t created_time;
    struct tunnel_info *next;
};
typedef struct tunnel_info *tunnel_info_t;


struct tunnel_info_node{
    tunnel_info_t tunnel_data;
    struct tunnel_info_node *next;
};
typedef struct tunnel_info_node *tunnel_info_node_t;


struct pipe_client_item{
    uv_pipe_t *handle;
    struct pipe_client_item *next;
};
typedef struct pipe_client_item *pipe_client_item_t;


struct tunnel_manager{
    int is_sdp_client;
    char *pipe_name;
    uv_loop_t *loop;
    uv_pipe_t *tm_pipe;
    pipe_client_item_t pipe_client_list;
    uv_read_cb pipe_read_cb_ptr;
    int tm_sock_fd;
    uv_tcp_t *tm_tcp_server;
    //uv_pipe_t *pipe_to_tm;
    //int read_pipe_to_tunnel_manager;
	//int write_pipe_to_tunnel_manager;
    //int read_pipe_from_tunnel_manager;
	//int write_pipe_from_tunnel_manager;
	hash_table_t *open_tunnel_hash_tbl;
	hash_table_t *requested_tunnel_hash_tbl;
    pthread_mutex_t requested_tunnel_hash_tbl_mutex;
};
typedef struct tunnel_manager *tunnel_manager_t;


typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;


void tunnel_manager_pipe_close_cb(uv_handle_t* handle);
int  tunnel_manager_send_msg(tunnel_manager_t tunnel_mgr, int send_type, 
        uv_stream_t *handle, char *msg);
void tunnel_manager_handle_tunnel_traffic(tunnel_manager_t tunnel_mgr, 
        uint32_t sdp_id, char *packet);

void tunnel_manager_destroy(tunnel_manager_t tunnel_mgr);
int  tunnel_manager_new(int is_sdp_client, int tbl_len, 
        uv_read_cb pipe_read_cb_ptr, tunnel_manager_t *r_tunnel_mgr);
int  tunnel_manager_connect_pipe(tunnel_manager_t tunnel_mgr);
int  tunnel_manager_send_stop(tunnel_manager_t tunnel_mgr);
int  tunnel_manager_submit_client_request(tunnel_manager_t tunnel_mgr, 
        uint32_t sdp_id, char *ip_str);
int  tunnel_manager_find_client_request(tunnel_manager_t tunnel_mgr, 
        uint32_t sdp_id, tunnel_info_t *r_tunnel_data);
int  tunnel_manager_get_peer_addr_and_port(uv_tcp_t *peer, 
        char **ip_str, uint32_t *ip_num, uint32_t *port_num);
void tunnel_manager_close_client_cb(uv_handle_t *handle);
void tunnel_manager_alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
int  tunnel_manager_ptr_2_array(const char* const ptr, char **r_array);
int  tunnel_manager_array_2_ptr(const char* const array, char **r_ptr);
int  tunnel_manager_send_to_tm(tunnel_manager_t tunnel_mgr, void *msg);
int  tunnel_manager_message_make(const char *action, uint32_t sdp_id, char *service_ids_str, 
        uint32_t idp_id, char *id_token, char *packet, char **r_msg);
int  tunnel_manager_process_json_msg(
        json_object *json_msg, 
        int *r_action,
        uint32_t *r_sdp_id,
        uint32_t *r_idp_id,
        uint32_t *r_service_id,
        char **r_id_token,
        char **r_tunnel_ip,
        char **r_packet);
int  tunnel_manager_process_json_msg_string(
        char *msg,
        int *r_action,
        uint32_t *r_sdp_id,
        uint32_t *r_idp_id,
        uint32_t *r_service_id,
        char **r_id_token,
        char **r_tunnel_ip,
        char **r_packet);

#endif /* SERVER_TUNNEL_MANAGER_H_ */
