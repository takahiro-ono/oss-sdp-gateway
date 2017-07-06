/*
 * client_tunnel_manager.c
 *
 *  Created on: Jun 27, 2017
 *      Author: Daniel Bailey
 */

#include "fwknop_common.h"
#include "log_msg.h"
#include "tunnel_manager.h"
#include "client_tunnel_manager.h"
#include "control_client.h"


static int tm_said_yes(char *msg)
{
    int rv = FKO_SUCCESS;
    int action;
    uint32_t sdp_id;
    uint32_t idp_id;
    uint32_t service_id;
    char *id_token;
    char *tunnel_ip;
    char *packet;

    if((rv = tunnel_manager_process_json_msg_string(
            msg,
            &action,
            &sdp_id,
            &idp_id,
            &service_id,
            &id_token,
            &tunnel_ip,
            &packet
        )) == FKO_SUCCESS 
        && action == CTRL_ACTION_SERVICE_GRANTED)
    {
        rv = 1;
    }
    else
    {
        rv = 0;
    }

    if(id_token) free(id_token);
    if(tunnel_ip) free(tunnel_ip);
    if(packet) free(packet);

    return rv;
}


// Try to connect to tunnel manager pipe
// If that succeeds, client is already running so just send requests
int ask_tunnel_manager_for_service(uint32_t sdp_id, char *service_ids_str, 
        uint32_t idp_id, char *id_token)
{
    struct sockaddr_un remote;
    struct timeval read_timeout;
    int len = 0;
    char buf[MAX_PIPE_MSG_LEN];
    int bytes_rcvd = 0;
    int sock_fd = 0;
    char *jsonstr_request = NULL;
    int rv = FKO_SUCCESS;

    if(!(sdp_id 
        && service_ids_str 
        && idp_id
        && id_token))
    {
        log_msg(LOG_ERR, "ask_tunnel_manager_for_service() invalid arg provided");
        return FKO_ERROR_UNKNOWN;
    }

    if(strnlen(id_token, ID_TOKEN_BUF_LEN) >= ID_TOKEN_BUF_LEN)
    {
        log_msg(LOG_ERR, "ask_tunnel_manager_for_service() id token longer than %d", ID_TOKEN_BUF_LEN);
        return FKO_ERROR_UNKNOWN;        
    }
    
    if((rv = tunnel_manager_message_make(
            sdp_action_service_request, 
            sdp_id, 
            service_ids_str, 
            idp_id, 
            id_token, 
            NULL,
            &jsonstr_request)) != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to create json string request to send to tunnel manager");
        return rv;
    }

    // since this is an SDP client (not gateway), this pipe is IPC capable
    if ((sock_fd = socket(AF_UNIX, SOCK_STREAM, 1)) == -1) 
    {
        perror("socket");
        free(jsonstr_request);
        return FKO_ERROR_FILESYSTEM_OPERATION;
    }

    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, NAME_TM_CLIENT_PIPE);
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);
    
    // set socket options for read timeout
    read_timeout.tv_sec = 60;
    read_timeout.tv_usec = 0;
    if(setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&read_timeout, sizeof(read_timeout)) < 0)
    {
        perror("Socket Read Timeout Option");
        free(jsonstr_request);
        return FKO_ERROR_FILESYSTEM_OPERATION;
    }


    if (connect(sock_fd, (struct sockaddr *)&remote, len) < 0) 
    {
        perror("connect");
        free(jsonstr_request);
        return FKO_ERROR_FILESYSTEM_OPERATION;
    }

    log_msg(LOG_ALERT, "Connected to tunnel manager's pipe");

    if (send(sock_fd, jsonstr_request, strlen(jsonstr_request), 0) == -1) 
    {
        perror("Main pipe send");
        close(sock_fd);
        free(jsonstr_request);
        return FKO_ERROR_FILESYSTEM_OPERATION;
    }

    free(jsonstr_request);

    if ((bytes_rcvd = recv(sock_fd, buf, MAX_PIPE_MSG_LEN, 0)) < 0) 
    {
        perror("Main pipe recv");
        close(sock_fd);
        return FKO_ERROR_UNKNOWN;
    }

    close(sock_fd);
    
    if(bytes_rcvd == 0)
    {
        log_msg(LOG_ALERT, "Tunnel Manager closed pipe connection without answer");
        return FKO_ERROR_UNKNOWN;
    }
    

    buf[bytes_rcvd] = '\0';
    log_msg(LOG_ALERT, "Message received from Tunnel Manager: %s", buf);
    
    if(!tm_said_yes(buf))
        
    {
        log_msg(LOG_ERR, "Service request failed");
        return FKO_ERROR_UNKNOWN;
    }

    log_msg(LOG_WARNING, "Service request granted");
    return FKO_SUCCESS;
}

static void tm_got_sigint(uv_signal_t *handle, int sig)
{
    uv_stop(handle->loop);
}


static void tm_signal_close_cb(uv_handle_t *handle)
{
    free(handle);
}


static int tm_connect_to_peer(
        tunnel_manager_t tunnel_mgr, 
        uint32_t sdp_id, 
        uint32_t service_id, 
        uint32_t idp_id, 
        char *id_token, 
        uv_tcp_t **handle)
{
    return FKO_ERROR_UNKNOWN;
}

static int tm_send_service_request()
{
    return FKO_ERROR_UNKNOWN;
}


static void tm_handle_service_request(
        tunnel_manager_t tunnel_mgr, 
        uint32_t sdp_id, 
        uint32_t service_id, 
        uint32_t idp_id, 
        char *id_token)
{
    int rv = FKO_SUCCESS;
    uv_tcp_t *handle = NULL;

    // if a tunnel exists, get the handle
    // otherwise set up a new tunnel
    if((rv = tm_connect_to_peer(tunnel_mgr, sdp_id, service_id, idp_id, id_token, &handle)) != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "Tunnel Manager could not connect to peer");
    }

    if((rv = tm_send_service_request()) != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "Tunnel Manager failed to send service request to peer");
    }

    return;
}

static void tm_handle_service_granted(
        tunnel_manager_t tunnel_mgr, 
        uint32_t sdp_id, 
        uint32_t service_id, 
        uint32_t idp_id, 
        char *id_token)
{
    return;

}

static void tm_handle_service_denied(
        tunnel_manager_t tunnel_mgr, 
        uint32_t sdp_id, 
        uint32_t service_id)
{
    return;

}

static void tm_handle_authn_request(
        tunnel_manager_t tunnel_mgr, 
        uint32_t sdp_id, 
        uint32_t service_id, 
        uint32_t idp_id, 
        char *id_token)
{
    return;

}

static void tm_handle_authn_accepted(
        tunnel_manager_t tunnel_mgr, 
        uint32_t sdp_id, 
        char *tunnel_ip)
{
    return;

}

static void tm_handle_authn_rejected(
        tunnel_manager_t tunnel_mgr, 
        uint32_t sdp_id)
{
    return;

}

static void tm_handle_msg(tunnel_manager_t tunnel_mgr, void *msg, int data_type)
{
    int rv = FKO_SUCCESS;
    int action = 0;
    uint32_t sdp_id = 0;
    uint32_t idp_id = 0;
    uint32_t service_id = 0;
    char *id_token = NULL;
    char *tunnel_ip = NULL;
    char *packet = NULL;

    if(data_type == PTR_TO_STR)
    {
        if((rv = tunnel_manager_process_json_msg_string(
                (char*)msg,
                &action,
                &sdp_id,
                &idp_id,
                &service_id,
                &id_token,
                &tunnel_ip,
                &packet
            )) != FKO_SUCCESS)
        {
            log_msg(LOG_ERR, "Received bad control message");
            goto cleanup;
        }
    }
    else
    {
        if((rv = tunnel_manager_process_json_msg(
                (json_object*)msg,
                &action,
                &sdp_id,
                &idp_id,
                &service_id,
                &id_token,
                &tunnel_ip,
                &packet
            )) != FKO_SUCCESS)
        {
            log_msg(LOG_ERR, "Received bad control message");
            goto cleanup;
        }
    }

    // react to message
    switch(action)
    {
        case CTRL_ACTION_SERVICE_REQUEST:
            tm_handle_service_request(tunnel_mgr, sdp_id, service_id, idp_id, id_token);

            // definitely free allocated memory in this case
            break;

        case CTRL_ACTION_SERVICE_GRANTED:
            tm_handle_service_granted(tunnel_mgr, sdp_id, service_id, idp_id, id_token);
            break;

        case CTRL_ACTION_SERVICE_DENIED:
            tm_handle_service_denied(tunnel_mgr, sdp_id, service_id);
            break;

        case CTRL_ACTION_AUTHN_REQUEST:
            tm_handle_authn_request(tunnel_mgr, sdp_id, service_id, idp_id, id_token);
            break;

        case CTRL_ACTION_AUTHN_ACCEPTED:
            tm_handle_authn_accepted(tunnel_mgr, sdp_id, tunnel_ip);
            break;

        case CTRL_ACTION_AUTHN_REJECTED:
            tm_handle_authn_rejected(tunnel_mgr, sdp_id);
            break;

        case CTRL_ACTION_TUNNEL_TRAFFIC:
            tunnel_manager_handle_tunnel_traffic(tunnel_mgr, sdp_id, packet);
            break;

        case CTRL_ACTION_BAD_MESSAGE:
            log_msg(LOG_ERR, "Tunnel manager received notice of a bad message");
            break;

        default:
            log_msg(LOG_ERR, "Received message with unhandled action");

    }

    
cleanup:
    if(id_token) free(id_token);
    if(tunnel_ip) free(tunnel_ip);
    if(packet) free(packet);
    return;
}




static void client_pipe_read_cb(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) 
{
    if (nread > 0) 
    {
        log_msg(LOG_WARNING, "Tunnel manager received pipe message: %s", buf->base);

        tm_handle_msg((tunnel_manager_t)client->data, buf->base, PTR_TO_STR);

        //write_req_t *req = calloc(1, sizeof *req);
        //req->buf = uv_buf_init(buf->base, nread);
        //uv_write((uv_write_t*) req, client, &req->buf, 1, tm_write_cb);

        free(buf->base);
        return;
    }

    if (nread <= 0) 
    {
        if (nread != UV_EOF)
            log_msg(LOG_ERR, "uv read error %s\n", uv_err_name(nread));
        uv_close((uv_handle_t*) client, tunnel_manager_pipe_close_cb);
    }

    free(buf->base);
}



int be_tunnel_manager(fko_cli_options_t *opts)
{
    int rv = 0;
    tunnel_manager_t tunnel_mgr = NULL;
    uv_signal_t *signal_handle = NULL;

    //create the tunnel manager
    if((rv = tunnel_manager_new(
            IS_SDP_CLIENT, HASH_TABLE_LEN, client_pipe_read_cb, &tunnel_mgr
        )) != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] Failed to create tunnel manager");
        return rv;
    }

    opts->tunnel_mgr = tunnel_mgr;

    if((signal_handle = calloc(1, sizeof *signal_handle)) == NULL)
    {
        log_msg(LOG_ERR, "Memory allocation error");
        return FKO_ERROR_MEMORY_ALLOCATION;
    }

    if((rv = uv_signal_init(tunnel_mgr->loop, signal_handle)))
    {
        log_msg(LOG_ERR, "uv_signal_init error: %s", uv_err_name(rv));
        return FKO_ERROR_UNKNOWN;
    }

    if((rv = uv_signal_start(signal_handle, tm_got_sigint, SIGINT)))
    {
        log_msg(LOG_ERR, "uv_signal_start error: %s", uv_err_name(rv));
        return FKO_ERROR_UNKNOWN;
    }

    //start ctrl client
    if((rv = start_control_client(opts)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] Failed to start Ctrl Client thread");
        return rv;
    }

    log_msg(LOG_WARNING, "[+] Ctrl Client thread successfully started");

    //start tunnel manager
    uv_run(tunnel_mgr->loop, UV_RUN_DEFAULT);

    uv_close((uv_handle_t*)signal_handle, tm_signal_close_cb);

    return FKO_SUCCESS;
}


void destroy_tunnel_manager(fko_cli_options_t *opts)
{
    if(opts->tunnel_mgr != NULL)
    {
        log_msg(LOG_WARNING, "Destroying Tunnel Manager...");

        tunnel_manager_destroy(opts->tunnel_mgr);
        opts->tunnel_mgr = NULL;
    
        log_msg(LOG_WARNING, "Tunnel Manager Destroyed");    
    }
    else
    {
        log_msg(LOG_WARNING, "Tunnel Manager not found for destruction");
    }

}

