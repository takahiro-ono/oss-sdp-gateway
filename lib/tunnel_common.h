/*
 * tunnel_common.h
 *
 *  Created on: Aug 3, 2017
 *      Author: Daniel Bailey
 */

#ifndef TUNNEL_COMMON_H_
#define TUNNEL_COMMON_H_

#include <uv.h>
#include "fko_limits.h"
#include "hash_table.h"
#include "sdp_ctrl_client.h"

#define ID_TOKEN_BUF_LEN 2048

#define TUNNEL_MAX_Q_LEN 20

#define MAX_TUNNEL_CON_ATTEMPTS 5
#define INITIAL_TUNNEL_CON_RETRY_DELAY 1
#define TUNNEL_POST_SPA_DELAY_MS 500

#define TUNNEL_PORT 8282
#define TUNNEL_BACKLOG 10

#define NAME_TM_GATEWAY_PIPE "tm_g_pipe"
#define NAME_TM_CLIENT_PIPE "tm_c_pipe"


typedef enum {
    KEY_DATA_TYPE_SDP_ID,
    KEY_DATA_TYPE_IP_STRING
} key_data_type_t;


typedef enum {
    REQUEST_OR_OPENED_TYPE_REQUEST = 1,
    REQUEST_OR_OPENED_TYPE_OPENED
} request_or_opened_type_t;

typedef enum {
    TM_CON_STATE_DISCONNECTED = 0,
    TM_CON_STATE_CONNECTING,
    TM_CON_STATE_CONNECTED,
    TM_CON_STATE_SECURED
} tm_con_state_t;

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


struct pipe_client_item{
    uv_pipe_t *handle;
    struct pipe_client_item *next;
};
typedef struct pipe_client_item *pipe_client_item_t;


// need the typedef for the function ptr typedef below
typedef struct tunnel_record *tunnel_record_t;


// function ptr to call when a message is ready
typedef void (*tunnel_msg_in_callback)(tunnel_record_t tunnel_rec, char *buf);

struct tunnel_manager{
    int is_sdp_client;
    char *pipe_name;
    uv_loop_t *loop;
    uv_pipe_t *tm_pipe;
    pipe_client_item_t pipe_client_list;
    uv_read_cb pipe_read_cb_ptr;
    tunnel_msg_in_callback tunnel_msg_in_cb;
    int tm_sock_fd;
    uv_tcp_t *tm_tcp_server;
    SSL_CTX *ssl_ctx;
    void *program_options_ptr;
    sdp_ctrl_client_t ctrl_client;
    char *ca_cert_file;
    char *cert_file;
    char *key_file;
    int use_spa;
    char *fwknoprc_file;
    char *fwknop_path;
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


struct tunneled_service{
    uint32_t service_id;
    uint32_t idp_id;
    char id_token[ID_TOKEN_BUF_LEN];
    short int request_sent;
    struct tunneled_service *next;
};
typedef struct tunneled_service *tunneled_service_t;

struct outbound_msg{
    char *msg;
    int length;
    struct outbound_msg *next;
};
typedef struct outbound_msg *outbound_msg_t;

struct tunnel_record{
    uint32_t sdp_id;
    char remote_public_ip[MAX_IPV4_STR_LEN];
    char remote_tunnel_ip[MAX_IPV4_STR_LEN];
    unsigned int remote_port;
    uint32_t idp_id;
    char id_token[ID_TOKEN_BUF_LEN];
    tunneled_service_t services_requested;
    tunneled_service_t services_opened;
    uv_tcp_t *handle;
    SSL* ssl;
    BIO* read_bio;
    BIO* write_bio;
    //char buffer_in[SDP_COM_MAX_MSG_LEN];
    //char buffer_out[SDP_COM_MAX_MSG_LEN];
    //int buffer_in_bytes_pending;
    //int buffer_out_bytes_pending;
    outbound_msg_t outbound_q;
    int outbound_q_len;
    tm_con_state_t con_state;
    int con_attempts;
    time_t next_con_retry_time;
    tunnel_manager_t tunnel_mgr;
    int submitted;
    time_t created_time;
    struct tunnel_record *next;
};



typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;


#endif
