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
#include <openssl/ssl.h>

#include "hash_table.h"
#include "sdp_ctrl_client.h"
#include "tunnel_common.h"




void tunnel_manager_tcp_close_cb(uv_handle_t* handle);
void tunnel_manager_pipe_close_cb(uv_handle_t* handle);
void tunnel_manager_free_write_req(uv_write_t *req);
void tunnel_manager_write_cb(uv_write_t *req, int status);
int  tunnel_manager_send_pipe_msg(tunnel_manager_t tunnel_mgr, int send_type, 
        uv_stream_t *handle, char *msg);
void tunnel_manager_handle_tunnel_traffic(tunnel_manager_t tunnel_mgr, 
        uint32_t sdp_id, char *packet);

void tunnel_manager_destroy(tunnel_manager_t tunnel_mgr);
int  tunnel_manager_new(
        void *program_options, 
        int is_sdp_client, 
        sdp_ctrl_client_t ctrl_client,
        int tbl_len, 
        uv_read_cb pipe_read_cb_ptr,
        tunnel_msg_in_callback tunnel_msg_in_cb, 
        tunnel_manager_t *r_tunnel_mgr);

int  tunnel_manager_connect_pipe(tunnel_manager_t tunnel_mgr);

int  tunnel_manager_submit_client_request(tunnel_manager_t tunnel_mgr, 
        uint32_t sdp_id, char *ip_str);

int  tunnel_manager_submit_tunnel_record(
        tunnel_record_t r_tunnel_rec, 
        which_table_t which_table);

int  tunnel_manager_find_tunnel_record(
        tunnel_manager_t tunnel_mgr, 
        uint32_t sdp_id,
        char *ip_str,
        uint32_t port,
        which_table_t which_table,
        tunnel_record_t *r_tunnel_rec);

int tunnel_manager_remove_tunnel_record(
        tunnel_record_t tunnel_rec,
        which_table_t which_table);

int  tunnel_manager_get_peer_addr_and_port(uv_tcp_t *peer, 
        char **ip_str, uint32_t *ip_num, uint32_t *port_num);
int  tunnel_manager_ptr_2_array(const char* const ptr, char **r_array);
int  tunnel_manager_array_2_ptr(const char* const array, char **r_ptr);
int  tunnel_manager_send_to_tm(tunnel_manager_t tunnel_mgr, void *msg);
int  tunnel_manager_make_msg(
        const char *action, 
        uint32_t sdp_id, 
        uint32_t service_id, 
        uint32_t idp_id, 
        char *id_token, 
        char *packet, 
        char **r_msg);

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
