/*
 * client_tunnel_manager.c
 *
 *  Created on: Jun 27, 2017
 *      Author: Daniel Bailey
 */

#include "fwknop_common.h"
#include "log_msg.h"
#include "tunnel_manager.h"
#include "tunnel_com.h"
#include "client_tunnel_manager.h"
#include "control_client.h"
#include "config_init.h"

static int tm_connect_tunnel(tunnel_info_t tunnel_data);

static void tm_handle_possible_mem_err(int rv)
{
    if(rv == SDP_ERROR_MEMORY_ALLOCATION)
    {
        log_msg(LOG_ERR, "Fatal memory error");
        kill(getpid(), SIGINT);
    }
}

static int tm_said_yes(char *msg)
{
    int rv = SDP_SUCCESS;
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
        )) == SDP_SUCCESS 
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


static int tm_convert_service_id_str(char *slist_str, uint32_t *r_service_id)
{
    int      is_err = 0;
    char     *ndx, *start;
    char     buf[SDP_MAX_SERVICE_ID_STR_LEN] = {0};
    uint32_t service_id = 0;

    start = slist_str;

    for(ndx = start; *ndx != '\0'; ndx++)
    {
        if(*ndx == ',')
        {
            /* Skip over any leading whitespace.
            */
            while(isspace(*start))
                start++;

            if(((ndx-start)+1) >= SDP_MAX_SERVICE_ID_STR_LEN)
            {
                return SDP_ERROR;
            }

            strlcpy(buf, start, (ndx-start)+1);

            if((service_id = strtoul_wrapper(buf, 0,
                UINT32_MAX, NO_EXIT_UPON_ERR, &is_err)) != 0 &&
                is_err == SDP_SUCCESS)
            {
                *r_service_id = service_id;
                return SDP_SUCCESS;
            }

            start = ndx+1;
        }
    }

    /* Skip over any leading whitespace (once again for the last in the list).
    */
    while(isspace(*start))
        start++;

    if(((ndx-start)+1) >= SDP_MAX_SERVICE_ID_STR_LEN)
    {
        return SDP_ERROR;
    }

    strlcpy(buf, start, (ndx-start)+1);

    if((service_id = strtoul_wrapper(buf, 0,
        UINT32_MAX, NO_EXIT_UPON_ERR, &is_err)) != 0 &&
        is_err == SDP_SUCCESS)
    {
        *r_service_id = service_id;
        return SDP_SUCCESS;
    }

    return SDP_ERROR;
}

// Try to connect to tunnel manager pipe
// If that succeeds, client is already running so just send requests
int ask_tunnel_manager_for_service(uint32_t sdp_id, char *service_ids_str, 
        uint32_t idp_id, char *id_token)
{
    struct sockaddr_un remote;
    struct timeval read_timeout;
    int len = 0;
    char buf[SDP_COM_MAX_MSG_LEN];
    int bytes_rcvd = 0;
    int sock_fd = 0;
    char *jsonstr_request = NULL;
    int rv = SDP_SUCCESS;
    uint32_t service_id = 0;

    if(!(sdp_id 
        && service_ids_str 
        && idp_id
        && id_token))
    {
        log_msg(LOG_ERR, "ask_tunnel_manager_for_service() invalid arg provided");
        return SDP_ERROR;
    }

    if(strnlen(id_token, ID_TOKEN_BUF_LEN) >= ID_TOKEN_BUF_LEN)
    {
        log_msg(LOG_ERR, "ask_tunnel_manager_for_service() id token longer than %d", ID_TOKEN_BUF_LEN);
        return SDP_ERROR;        
    }

    if((rv = tm_convert_service_id_str(service_ids_str, &service_id)) != SDP_SUCCESS)
    {
        log_msg(
            LOG_ERR, 
            "ask_tunnel_manager_for_service() failed to get service id from str: %s",
            service_ids_str
        );
        return SDP_ERROR;        
    }
    
    if((rv = tunnel_manager_make_msg(
            sdp_action_service_request, 
            sdp_id, 
            service_id, 
            idp_id, 
            id_token, 
            NULL,
            &jsonstr_request)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to create json string request to send to tunnel manager");
        return rv;
    }

    // since this is an SDP client (not gateway), this pipe is IPC capable
    if ((sock_fd = socket(AF_UNIX, SOCK_STREAM, 1)) == -1) 
    {
        perror("socket");
        free(jsonstr_request);
        return SDP_ERROR_FILESYSTEM_OPERATION;
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
        return SDP_ERROR_FILESYSTEM_OPERATION;
    }


    if (connect(sock_fd, (struct sockaddr *)&remote, len) < 0) 
    {
        perror("connect");
        free(jsonstr_request);
        return SDP_ERROR_FILESYSTEM_OPERATION;
    }

    log_msg(LOG_ALERT, "Connected to tunnel manager's pipe");

    if (send(sock_fd, jsonstr_request, strlen(jsonstr_request), 0) == -1) 
    {
        perror("Main pipe send");
        close(sock_fd);
        free(jsonstr_request);
        return SDP_ERROR_FILESYSTEM_OPERATION;
    }

    free(jsonstr_request);

    if ((bytes_rcvd = recv(sock_fd, buf, SDP_COM_MAX_MSG_LEN, 0)) < 0) 
    {
        perror("Main pipe recv");
        close(sock_fd);
        return SDP_ERROR;
    }

    close(sock_fd);
    
    if(bytes_rcvd == 0)
    {
        log_msg(LOG_ALERT, "Tunnel Manager closed pipe connection without answer");
        return SDP_ERROR;
    }
    

    buf[bytes_rcvd] = '\0';
    log_msg(LOG_ALERT, "Message received from Tunnel Manager: %s", buf);
    
    if(!tm_said_yes(buf))
        
    {
        log_msg(LOG_ERR, "Service request failed");
        return SDP_ERROR;
    }

    log_msg(LOG_WARNING, "Service request granted");
    return SDP_SUCCESS;
}

static void tm_got_sigint(uv_signal_t *handle, int sig)
{
    uv_stop(handle->loop);
}


static void tm_signal_close_cb(uv_handle_t *handle)
{
    free(handle);
}


static int tm_get_service_info(
        tunnel_manager_t tunnel_mgr, 
        uint32_t service_id,
        char **r_gateway_ip,
        uint32_t *r_tunnel_service_port)
{
    int rv = SDP_SUCCESS;
    fko_cli_options_t *orig_opts = NULL;
    fko_cli_options_t tmp_opts;

    if(!tunnel_mgr)
    {
        log_msg(LOG_ERR, "tm_get_service_info() tunnel_mgr arg is NULL");
        return SDP_ERROR;
    }

    if(!tunnel_mgr->program_options_ptr)
    {
        log_msg(LOG_ERR, "tm_get_service_info() tunnel_mgr->program_options_ptr is NULL");
        return SDP_ERROR;
    }

    orig_opts = (fko_cli_options_t*)tunnel_mgr->program_options_ptr;

    if(!service_id)
    {
        log_msg(LOG_ERR, "tm_get_service_info() service_id not provided");
        return SDP_ERROR;
    }

    memset(&tmp_opts, 0, sizeof(fko_cli_options_t));

    // copy rc_file[MAX_PATH_LEN], want to use same rc file that
    // the program was told to use at startup
    strlcpy(tmp_opts.rc_file, orig_opts->rc_file, MAX_PATH_LEN);

    // process_rc_section checks the stanza name arg
    // but also the one set in the options object, 
    // so set use_rc_stanza[MAX_LINE_LEN] and also pass it as a separate arg, 
    // requires that the stanza name in the fwknoprc file is set to the service ID 
    snprintf(tmp_opts.use_rc_stanza, MAX_SERVICE_ID_STR_LEN, "%"PRIu32, service_id);

    // values for the gateway of this service MAY come from the default stanza
    // so gotta get that first, then rerun over the named stanza 
    if((rv = process_rc_section("default", &tmp_opts, 0)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "tm_get_service_info() process_rc_section gave an error");
        return SDP_ERROR;        
    }
    
    // now run against the named stanza, i.e. service ID
    if((rv = process_rc_section(tmp_opts.use_rc_stanza, &tmp_opts, 0)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "tm_get_service_info() process_rc_section gave an error");
        return SDP_ERROR;        
    }
    
    // got_named_stanza should be set if successful
    if(!tmp_opts.got_named_stanza)
    {
        log_msg(LOG_ERR, "tm_get_service_info() did not find the named stanza");
        return SDP_ERROR;        
    }

    // the gateway IP address should now be set 
    if(tmp_opts.spa_server_str[0] == 0x0)
    {
        log_msg(LOG_ERR, "tm_get_service_info() did not find the gateway's IP address");
        return SDP_ERROR;        
    }

    if((*r_gateway_ip = calloc(1, MAX_IPV4_STR_LEN)) == NULL)
    {
        log_msg(LOG_ERR, "Memory allocation error");
        kill(getpid(), SIGINT);
        return SDP_ERROR_MEMORY_ALLOCATION;
    }

    // TODO: Assuming this is an IP string for now, could actually be a URL
    strlcpy(*r_gateway_ip, tmp_opts.spa_server_str, MAX_IPV4_STR_LEN);
    *r_tunnel_service_port = TUNNEL_PORT;

    return SDP_SUCCESS;
}

static void tm_connection_retry_cb(uv_timer_t *timer_handle)
{
    tunnel_info_t tunnel_data = (tunnel_info_t)timer_handle->data;

    uv_timer_stop(timer_handle);
    free(timer_handle);

    if(tunnel_data == NULL)
    {
        log_msg(
            LOG_ERR, 
            "tm_connection_retry_cb() given null tunnel_data, cannot retry connection"
        );
        return;
    }

    tm_connect_tunnel(tunnel_data);
}


static void tm_schedule_connection_retry(tunnel_info_t tunnel_data)
{
    int rv = SDP_SUCCESS;
    uv_timer_t *timer_handle = NULL;
    int retry_delay = 0;

    if(tunnel_data == NULL)
    {
        log_msg(LOG_ERR, "tm_schedule_connection_retry() given null tunnel_data");
        return;
    }

    if(tunnel_data->tunnel_mgr == NULL || tunnel_data->tunnel_mgr->loop == NULL)
    {
        log_msg(LOG_ERR, "tm_schedule_connection_retry() given incomplete tunnel_data");
        return;
    }

    if(tunnel_data->con_attempts >= MAX_TUNNEL_CON_ATTEMPTS)
    {
        log_msg(
            LOG_ERR, 
            "Giving up attempted tunnel connection to %s after %d attempts", 
            tunnel_data->remote_public_ip,
            tunnel_data->con_attempts
        );
        
        tunnel_manager_remove_tunnel_record(tunnel_data);
        
        return;
    }

    if((timer_handle = calloc(1, sizeof *timer_handle)) == NULL)
    {
        log_msg(LOG_ERR, "Fatal memory error");
        kill(getpid(), SIGINT);
        return;
    }

    if((rv = uv_timer_init(tunnel_data->tunnel_mgr->loop, timer_handle)))
    {
        log_msg(LOG_ERR, "tm_schedule_connection_retry() uv_timer_init error: %s", uv_err_name(rv));
        free(timer_handle);
        tunnel_manager_remove_tunnel_record(tunnel_data);
        return;
    }

    timer_handle->data = tunnel_data;

    retry_delay = INITIAL_TUNNEL_CON_RETRY_DELAY * tunnel_data->con_attempts * 1000;

    if((rv = uv_timer_start(timer_handle, tm_connection_retry_cb, retry_delay, 0)))
    {
        log_msg(LOG_ERR, "tm_schedule_connection_retry() uv_timer_start error: %s", uv_err_name(rv));
        free(timer_handle);
        tunnel_manager_remove_tunnel_record(tunnel_data);
    }

    return;
}


static void tm_send_service_request(tunnel_info_t tunnel_data)
{
    int rv = SDP_SUCCESS;
    char *msg = NULL;
    tunnel_manager_t tunnel_mgr = NULL;
    tunneled_service_t service = NULL;
    fko_cli_options_t *cli_opts = NULL;

    log_msg(LOG_WARNING, "tm_send_service_request() entered...");

    if(tunnel_data == NULL)
    {
        log_msg(LOG_ERR, "tm_send_service_request() tunnel_data is null");
        return;
    }

    tunnel_mgr = tunnel_data->tunnel_mgr;
    service = tunnel_data->services_requested;

    if(tunnel_mgr == NULL)
    {
        log_msg(LOG_ERR, "tm_send_service_request() tunnel_data->tunnel_mgr is null");
        return;
    }

    if(service == NULL)
    {
        log_msg(LOG_ERR, "tm_send_service_request() tunnel_data->services_requested is null");
        return;
    }

    if(tunnel_mgr->program_options_ptr == NULL)
    {
        log_msg(LOG_ERR, "Fatal error, tunnel_mgr pointer to program options is NULL");
        kill(getpid(), SIGINT);
        return;
    }

    cli_opts = (fko_cli_options_t*)tunnel_mgr->program_options_ptr;

    if((rv = tunnel_manager_make_msg(
            sdp_action_service_request, 
            cli_opts->sdp_id, 
            service->service_id, 
            service->idp_id, 
            service->id_token, 
            NULL,
            &msg
        )) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to create service request message.");

        tm_handle_possible_mem_err(rv);

        return;
    }

    if((rv = tunnel_com_send_msg(tunnel_data, msg)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to send service request message.");

        free(msg);
        tm_handle_possible_mem_err(rv);
    }
}


static void tm_socket_connected_cb(uv_connect_t *req, int status)
{
    int rv = SDP_SUCCESS;
    uv_tcp_t *handle = NULL;
    tunnel_info_t tunnel_data = NULL;

    log_msg(LOG_WARNING, "socket connection callback reached...");

    if(req == NULL)
    {
        log_msg(LOG_ERR, "Error, connection callback reached without req set");
        return;        
    }

    handle = (uv_tcp_t*)req->handle;
    free(req);
    if(handle == NULL)
    {
        log_msg(LOG_ERR, "Error, connection callback reached without handle set");
        return;
    }

    tunnel_data = (tunnel_info_t)handle->data;

    if(status != 0)
    {
        log_msg(LOG_ERR, "Tunnel connection attempt failed");

        if(!tunnel_data)
        {
            log_msg(LOG_ERR, "Error, connection callback reached without context data");
            free(handle);
            return;
        }

        tm_schedule_connection_retry(tunnel_data);
        return;

    }

    if(!tunnel_data || !tunnel_data->tunnel_mgr)
    {
        log_msg(
            LOG_ERR, 
            "Connection callback reached with successful connection, but no context data"
        );
        uv_close((uv_handle_t*)handle, (uv_close_cb)free);
        return;
    }

    // this handles the initialization of SSL and starts the SSL handshake
    // if any messages are queued up, they'll be sent after the handshake
    if((rv = tunnel_com_finalize_connection(tunnel_data, 1)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "failed to secure connection");
        tm_handle_possible_mem_err(rv);
        tunnel_manager_remove_tunnel_record(tunnel_data);
    }
}

int tm_connect_tunnel(tunnel_info_t tunnel_data)
{
    int rv = SDP_SUCCESS;
    uv_tcp_t *handle = NULL;
    struct sockaddr_in conn_addr;  // not clear if this needs to be on heap
    uv_connect_t *req = NULL; 
    tunnel_manager_t tunnel_mgr = NULL;

    if(tunnel_data == NULL || tunnel_data->tunnel_mgr == NULL)
    {
        log_msg(LOG_ERR, "tm_connect_tunnel() called with incomplete data");
        return SDP_ERROR_UNINITIALIZED;
    }

    tunnel_mgr = (tunnel_manager_t)tunnel_data->tunnel_mgr;

    if(tunnel_mgr->loop == NULL)
    {
        log_msg(LOG_ERR, "loop is null!");
        return SDP_ERROR_UNINITIALIZED;
    }

    // create new handle
    if((handle = calloc(1, sizeof *handle)) == NULL)
    {
        log_msg(LOG_ERR, "Fatal memory error. Aborting.");
        return SDP_ERROR_MEMORY_ALLOCATION;
    }


    if((rv = uv_tcp_init(tunnel_mgr->loop, handle)))
    {
        log_msg(LOG_ERR, "tm_connect_tunnel() failed to init handle: %s", uv_err_name(rv));
        return SDP_ERROR;        
    }

    tunnel_data->handle = handle;
    handle->data = tunnel_data;

    log_msg(LOG_WARNING, "tm_connect_tunnel() tunnel_data set to %p", tunnel_data);
    log_msg(LOG_WARNING, "tm_connect_tunnel() handle set to %p", handle);
    log_msg(LOG_WARNING, "tm_connect_tunnel() handle->data set to %p", handle->data);

    if((rv = uv_ip4_addr(
        tunnel_data->remote_public_ip, tunnel_data->remote_port, &conn_addr)))
    {
        log_msg(LOG_ERR, "tm_connect_tunnel() failed to set ip addr: %s", uv_err_name(rv));
        return SDP_ERROR;                
    }

    tunnel_data->con_state = TM_CON_STATE_CONNECTING;
    tunnel_data->con_attempts++;

    log_msg(LOG_WARNING, 
        "tm_connect_tunnel() calling uv_tcp_connect...");

    if((req = calloc(1, sizeof *req)) == NULL)
    {
        log_msg(LOG_ERR, "Fatal memory error. Aborting.");
        return SDP_ERROR_MEMORY_ALLOCATION;
    }

    if((rv = uv_tcp_connect(
            req, 
            handle, 
            (const struct sockaddr*)&conn_addr, 
            tm_socket_connected_cb)
        ))
    {
        log_msg(
            LOG_ERR, 
            "tm_connect_tunnel() uv_tcp_connect failed: %s", 
            uv_err_name(rv)
        );

        return SDP_ERROR_SOCKET;
    }

    return SDP_SUCCESS;
}

static int tm_start_new_tunnel(
        tunnel_manager_t tunnel_mgr, 
        uint32_t sdp_id, 
        char *gateway_ip,
        uint32_t tunnel_service_port,
        tunnel_info_t *r_tunnel_data)
{
    int rv = SDP_SUCCESS;
    tunnel_info_t tunnel_data = NULL;


    // create new tunnel record
    if((rv = tunnel_manager_create_tunnel_item(
            sdp_id,
            gateway_ip,
            tunnel_service_port,
            NULL,
            tunnel_mgr,
            &tunnel_data
        )) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "tm_start_new_tunnel() failed to create tunnel info item");
        
        tm_handle_possible_mem_err(rv);

        return rv;        
    }

    // if all went well, put it in the hash table
    if((rv = tunnel_manager_submit_tunnel_record(
            tunnel_mgr, 
            (void*)gateway_ip,
            KEY_DATA_TYPE_IP_STRING,
            REQUEST_OR_OPENED_TYPE_REQUEST,
            tunnel_data
            )) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "tm_start_new_tunnel() failed to store tunnel info item");
        tunnel_manager_destroy_tunnel_item(tunnel_data);
        return rv;        
    }

    log_msg(LOG_WARNING, 
        "tm_start_new_tunnel() new tunnel record submitted, time to connect...");

    // time to try connecting
    if((rv = tm_connect_tunnel(tunnel_data)) != SDP_SUCCESS)
    {
        log_msg(
            LOG_ERR, 
            "tm_start_new_tunnel() Failed to start tunnel connection process."
        );

        tunnel_manager_remove_tunnel_record(tunnel_data);

        tm_handle_possible_mem_err(rv);

        return rv;
    }

    *r_tunnel_data = tunnel_data;
    return rv;
}


static void tm_handle_service_request(
        tunnel_manager_t tunnel_mgr, 
        uint32_t sdp_id, 
        uint32_t service_id, 
        uint32_t idp_id, 
        char *id_token)
{
    int rv = SDP_SUCCESS;
    tunnel_info_t tunnel_data = NULL;
    char *gateway_ip = NULL;
    uint32_t tunnel_service_port = 0;
    short int send_request = 0;

    if(tunnel_mgr == NULL)
    {
        log_msg(LOG_ERR, "Error, tunnel_mgr is NULL");
        return;
    }

    // determine where this service is located
    if((rv = tm_get_service_info(tunnel_mgr, service_id, 
            &gateway_ip, &tunnel_service_port)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Tunnel Manager hit an error while looking up service information");
        return;
    }

    if(!(gateway_ip && tunnel_service_port))
    {
        log_msg(LOG_ERR, "Tunnel Manager could not find service information");
        if(gateway_ip) free(gateway_ip);
        return;
    }

    log_msg(LOG_WARNING, "Service ID mapped to %s:%"PRIu32, gateway_ip, tunnel_service_port);

    if((rv = tunnel_manager_find_tunnel_record(
                tunnel_mgr, 
                (void*)gateway_ip,
                KEY_DATA_TYPE_IP_STRING,
                REQUEST_OR_OPENED_TYPE_REQUEST,
                &tunnel_data
        )) == SDP_SUCCESS)
    {
        if(tunnel_data->con_state == TM_CON_STATE_CONNECTED)
        {
            log_msg(
                LOG_WARNING, 
                "An open tunnel exists to %s",
                gateway_ip
            );
        }
        else
        {
            log_msg(
                LOG_WARNING, 
                "A tunnel request exists to %s",
                gateway_ip
            );
        }

    }
    else if((rv = tm_start_new_tunnel(
            tunnel_mgr, 
            sdp_id, 
            gateway_ip,
            tunnel_service_port, 
            &tunnel_data
        )) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Could not start new tunnel to %s", gateway_ip);
        free(gateway_ip);
        return;
    }

    free(gateway_ip);

    // create a new record of the service to be requested
    if((rv = tunnel_manager_add_service_to_tunnel(
            tunnel_data,
            service_id,
            idp_id,
            id_token,
            REQUEST_OR_OPENED_TYPE_REQUEST,
            send_request
        )) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to add requested service to tunnel data.");

        tm_handle_possible_mem_err(rv);

        return;
    }

    // this either sends or queues the request
    // depending on connection state
    tm_send_service_request(tunnel_data);

    return;
}


static void tm_handle_service_granted(
        tunnel_info_t tunnel_data, 
        uint32_t sdp_id, 
        uint32_t service_id, 
        uint32_t idp_id, 
        char *id_token)
{
    return;

}

static void tm_handle_service_denied(
        tunnel_info_t tunnel_data, 
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
        tunnel_info_t tunnel_data, 
        uint32_t sdp_id, 
        char *tunnel_ip)
{
    return;

}

static void tm_handle_authn_rejected(
        tunnel_info_t tunnel_data, 
        uint32_t sdp_id)
{
    return;

}

static void tm_handle_tunnel_traffic_in(
        tunnel_info_t tunnel_data, 
        uint32_t sdp_id, 
        char *packet)
{
    return;
}

void tm_handle_pipe_msg(tunnel_manager_t tunnel_mgr, void *msg, int data_type)
{
    int rv = SDP_SUCCESS;
    int action = 0;
    uint32_t sdp_id = 0;
    uint32_t idp_id = 0;
    uint32_t service_id = 0;
    char *id_token = NULL;
    char *tunnel_ip = NULL;
    char *packet = NULL;

    if(tunnel_mgr == NULL)
    {
        log_msg(LOG_ERR, "tm_handle_pipe_msg() Error, tunnel_mgr is NULL");
        return;
    }

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
            )) != SDP_SUCCESS)
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
            )) != SDP_SUCCESS)
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

        case CTRL_ACTION_AUTHN_REQUEST:
            tm_handle_authn_request(tunnel_mgr, sdp_id, service_id, idp_id, id_token);
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


void client_handle_tunnel_msg(tunnel_info_t tunnel_data, char *msg)
{
    int rv = SDP_SUCCESS;
    int action = 0;
    uint32_t sdp_id = 0;
    uint32_t idp_id = 0;
    uint32_t service_id = 0;
    char *id_token = NULL;
    char *tunnel_ip = NULL;
    char *packet = NULL;
    
    if(!tunnel_data || !tunnel_data->tunnel_mgr)
    {
        log_msg(LOG_ERR, "client_handle_tunnel_msg() Error, context data missing");
        return;
    }

    if((rv = tunnel_manager_process_json_msg_string(
            (char*)msg,
            &action,
            &sdp_id,
            &idp_id,
            &service_id,
            &id_token,
            &tunnel_ip,
            &packet
        )) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "client_handle_tunnel_msg() Received bad tunnel message");
        goto cleanup;
    }

    // react to message
    switch(action)
    {
        case CTRL_ACTION_SERVICE_GRANTED:
            tm_handle_service_granted(tunnel_data, sdp_id, service_id, idp_id, id_token);
            break;

        case CTRL_ACTION_SERVICE_DENIED:
            tm_handle_service_denied(tunnel_data, sdp_id, service_id);
            break;

        case CTRL_ACTION_AUTHN_ACCEPTED:
            tm_handle_authn_accepted(tunnel_data, sdp_id, tunnel_ip);
            break;

        case CTRL_ACTION_AUTHN_REJECTED:
            tm_handle_authn_rejected(tunnel_data, sdp_id);
            break;

        case CTRL_ACTION_TUNNEL_TRAFFIC:
            tm_handle_tunnel_traffic_in(tunnel_data, sdp_id, packet);
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

        tm_handle_pipe_msg((tunnel_manager_t)client->data, buf->base, PTR_TO_STR);

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

    // first get latest tls cert and key
    if(get_updated_credentials_from_controller(opts) != SDP_SUCCESS)
    {
        // failed to run control client, stop here
        //clean_exit(ctx, &options, key, &orig_key_len, hmac_key, &hmac_key_len, EXIT_SUCCESS);
        log_msg(LOG_ERR, "Failed to start control client");
    }

    //create the tunnel manager
    if((rv = tunnel_manager_new(
            (void*)opts, 
            IS_SDP_CLIENT, 
            opts->ctrl_client,
            HASH_TABLE_LEN, 
            client_pipe_read_cb, 
            client_handle_tunnel_msg, 
            &tunnel_mgr
        )) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] Failed to create tunnel manager");
        return rv;
    }

    opts->tunnel_mgr = tunnel_mgr;

    if((signal_handle = calloc(1, sizeof *signal_handle)) == NULL)
    {
        log_msg(LOG_ERR, "Memory allocation error");
        return SDP_ERROR_MEMORY_ALLOCATION;
    }

    if((rv = uv_signal_init(tunnel_mgr->loop, signal_handle)))
    {
        log_msg(LOG_ERR, "uv_signal_init error: %s", uv_err_name(rv));
        return SDP_ERROR;
    }

    if((rv = uv_signal_start(signal_handle, tm_got_sigint, SIGINT)))
    {
        log_msg(LOG_ERR, "uv_signal_start error: %s", uv_err_name(rv));
        return SDP_ERROR;
    }

    //start ctrl client thread
    if((rv = start_control_client(opts)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] Failed to start Ctrl Client thread");
        return rv;
    }

    log_msg(LOG_WARNING, "[+] Ctrl Client thread successfully started");

    //start tunnel manager
    uv_run(tunnel_mgr->loop, UV_RUN_DEFAULT);

    uv_close((uv_handle_t*)signal_handle, tm_signal_close_cb);

    return SDP_SUCCESS;
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

