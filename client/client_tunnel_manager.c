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


static int make_service_request_json_string(char *service_ids_str, 
            uint32_t idp_id, char *id_token, char **r_jsonstr_request)
{
    *r_jsonstr_request = NULL;
    return FKO_SUCCESS;
}


// Try to connect to tunnel manager pipe
// If that succeeds, client is already running so just send requests
// Otherwise, start everything
int ask_tunnel_manager_for_service(char *service_ids_str, uint32_t idp_id, char *id_token)
{
    struct sockaddr_un remote;
    int len = 0;
    char buf[100];
    int bytes_rcvd = 0;
    int sock_fd = 0;
    char *jsonstr_request = NULL;
    int rv = FKO_SUCCESS;
    
    if((rv = make_service_request_json_string(
        service_ids_str, idp_id, id_token, &jsonstr_request
        )) != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to create json string request to send to tunnel manager");
        return rv;
    }

    // if this is an SDP client (not gateway), this pipe is IPC capable
    if ((sock_fd = socket(AF_UNIX, SOCK_STREAM, 1)) == -1) 
    {
        perror("socket");
        return FKO_ERROR_FILESYSTEM_OPERATION;
    }

    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, NAME_TM_CLIENT_PIPE);
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);
    
    if (connect(sock_fd, (struct sockaddr *)&remote, len) < 0) 
    {
        perror("connect");
        return FKO_ERROR_FILESYSTEM_OPERATION;
    }

    log_msg(LOG_ALERT, "Connected to tunnel manager's pipe");

    if (send(sock_fd, jsonstr_request, strlen(jsonstr_request), 0) == -1) 
    {
        perror("Main pipe send");
        close(sock_fd);
        return FKO_ERROR_FILESYSTEM_OPERATION;
    }

    if ((bytes_rcvd = recv(sock_fd, buf, 100, 0)) > 0) 
    {
        buf[bytes_rcvd] = '\0';
        log_msg(LOG_ALERT, "Message received from Tunnel Manager: %s", buf);
        close(sock_fd);
    } 
    else 
    {
        if (bytes_rcvd < 0) 
            perror("Main pipe recv");
        else 
            log_msg(LOG_ALERT, "Tunnel Manager closed pipe connection\n");
        return FKO_ERROR_FILESYSTEM_OPERATION;
    }

    return FKO_SUCCESS;
}

static void got_sigint(uv_signal_t *handle, int sig)
{
    uv_stop(handle->loop);
}


static void signal_close_cb(uv_handle_t *handle)
{
    free(handle);
}


int be_tunnel_manager(fko_cli_options_t *opts)
{
    int rv = 0;
    tunnel_manager_t tunnel_mgr = NULL;
    uv_signal_t *signal_handle = NULL;

    //create the tunnel manager
    if((rv = tunnel_manager_new(0, HASH_TABLE_LEN, &tunnel_mgr)) != FKO_SUCCESS)
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

    if((rv = uv_signal_start(signal_handle, got_sigint, SIGINT)))
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

    uv_close((uv_handle_t*)signal_handle, signal_close_cb);

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

