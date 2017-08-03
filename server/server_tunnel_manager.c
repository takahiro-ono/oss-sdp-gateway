/*
 * server_tunnel_manager.c
 *
 *  Created on: Jun 27, 2017
 *      Author: Daniel Bailey
 */

#include "fwknopd_common.h"
#include "log_msg.h"
#include "tunnel_manager.h"
#include "tunnel_com.h"
#include "server_tunnel_manager.h"

const char *TM_STOP_MSG = "STOP_TM";


//static void tm_on_read(uv_stream_t* handle, ssize_t nread, const uv_buf_t *buf)
//{
//    tunnel_info_t tunnel_data = handle->data;
//    if(tunnel_data == NULL)
//    {
//        log_msg(
//            LOG_ERR, 
//            "[*] ALERT: Received data on tunnel, but can't find associated tunnel data! Disconnecting."
//        );
//
//        uv_close((uv_handle_t*)handle, (uv_close_cb)free);
//        free(buf->base);
//        return;
//    }
//    
//    if (nread < 0) 
//    {
//        if (nread != UV_EOF)
//            log_msg(LOG_ERR, "uv read error %s", uv_err_name(nread));
//
//        log_msg(LOG_INFO, "[*] %"PRIu32" has disconnected", tunnel_data->sdp_id);
//        free(buf->base);
//        tunnel_manager_remove_tunnel_record(tunnel_data);
//
//        return;
//    }
//
//    // show message
//    log_msg(LOG_INFO, "%"PRIu32" said: %s", tunnel_data->sdp_id, buf->base);
//    free(buf->base);
//}

// Write callback
//void on_write(uv_write_t *req, int status) {
//    // Check status
//    if (status < 0) {
//        log_msg(LOG_ERR, "Write failed: %s\n", uv_strerror(status));
//    }
//
//    // Close client handle
//    uv_close((uv_handle_t*)req->handle, tunnel_com_closed_cb);
//
//    // Free request handle
//    free(req);
//}

static void tm_server_close_cb(uv_handle_t *handle)
{
    free(handle);
}

// Callback for new connections
static void tm_new_tunnel_connection_cb(uv_stream_t *server, int status) 
{
    uv_tcp_t *client = NULL;
    //uv_write_t *req = NULL;
    int rv = SDP_SUCCESS;
    char *ip_str = NULL;
    uint32_t ip_num = 0;
    uint32_t port_num = 0;

    tunnel_info_t tunnel_data = NULL;
    uint32_t sdp_id = 55555;

    //char *s = "Hello, World!\n";
    //uv_buf_t bufs[] = {uv_buf_init(s, (unsigned int)strnlen(s, 20))};

    // Check status code, anything under 0 means an error.
    if(status < 0) {
        log_msg(LOG_ERR, "New connection error: %s\n", uv_strerror(status));
        return;
    }

    // Create handle for client
    if((client = calloc(1, sizeof(*client))) == NULL)
    {
        log_msg(LOG_ERR, "Memory error creating uv_tcp_t client handle.");

        // send kill signal for main thread to catch and exit safely
        kill(getpid(), SIGTERM);
        return;
    }

    if((rv = uv_tcp_init(server->loop, client)))
    {
        log_msg(LOG_ERR, "tm_new_tunnel_connection_cb uv_tcp_init error: %s\n", uv_strerror(rv));
        free(client);
        return;
    }

    // Accept new connection
    if((rv = uv_accept(server, (uv_stream_t*) client))) 
    {
        log_msg(LOG_ERR, "uv_accept error: %s", uv_strerror(rv));
        uv_close((uv_handle_t*)client, (uv_close_cb)free);
        return;
    }

    if((rv = tunnel_manager_get_peer_addr_and_port(
        client, &ip_str, &ip_num, &port_num)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] Failed to get peer connection info. Closing connection.");

        //closing client handle
        uv_close((uv_handle_t*)client, (uv_close_cb)free);

    }

    //client->data = ip_str;

    log_msg(
        LOG_INFO, "[+] New tunnel connection received from %s:%d", 
        ip_str, port_num
    );

    // TODO: putting this call here for now to test, function is meant to call
    // when a good SPA packet arrives
    if((rv = tunnel_manager_submit_client_request(
        (tunnel_manager_t)server->data, sdp_id, ip_str
        )) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] tm_new_tunnel_connection_cb failed to create tunnel request");

        if(rv == SDP_ERROR_MEMORY_ALLOCATION)
        {
            log_msg(LOG_ERR, "[*] Fatal memory error. Aborting.");
            uv_close((uv_handle_t*)client, (uv_close_cb)free);
            free(ip_str);
            kill(getpid(), SIGTERM);
            return;
        }
    }

    log_msg(LOG_WARNING, "[+] tm_new_tunnel_connection_cb Successfully stored tunnel request");

    // TODO: perform SSL handshake, that's async so code below will need
    // to become part of the callback for that

    // TODO: what do we do if sdp id already has a tunnel connection
    // yet sent another SPA, disconnect old one?
    // if this one checks out, probably should kill the old one

    // check if we were expecting this connection
    if((rv = tunnel_manager_find_tunnel_record(
                (tunnel_manager_t)server->data, 
                (void*)&sdp_id,
                KEY_DATA_TYPE_SDP_ID,
                REQUEST_OR_OPENED_TYPE_REQUEST,
                &tunnel_data
        )) != SDP_SUCCESS)
    {
        log_msg(
            LOG_ERR, 
            "[*] ALERT: Attempted tunnel connection by unexpected sdp id %"PRIu32
            " from address %s:%d!",
            sdp_id, ip_str, port_num
        );

        uv_close((uv_handle_t*)client, (uv_close_cb)free);
        free(ip_str);
        return;
    }

    if(strncmp(ip_str, tunnel_data->remote_public_ip, MAX_IPV4_STR_LEN))
    {
        log_msg(
            LOG_ERR, 
            "[*] ALERT: Attempted tunnel connection by sdp id %"PRIu32
            " from wrong address %s:%d!",
            sdp_id, ip_str, port_num
        );

        tunnel_manager_remove_tunnel_record(tunnel_data);
        free(ip_str);
        return;            
    }

    free(ip_str);

    client->data = tunnel_data;
    tunnel_data->handle = client;
    tunnel_data->remote_port = (uint32_t)port_num;

    log_msg(
        LOG_WARNING, 
        "[+] Tunnel connection by sdp id %"PRIu32" from %s:%"PRIu32" was expected!",
        tunnel_data->sdp_id, 
        tunnel_data->remote_public_ip,
        tunnel_data->remote_port
    );

    // this handles the initialization of SSL and allows the SSL handshake
    // to be initiated by the client
    if((rv = tunnel_com_finalize_connection(tunnel_data, 0)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "failed to secure connection");
        tunnel_manager_remove_tunnel_record(tunnel_data);
    }

}


static void tm_handle_service_request(
        tunnel_manager_t tunnel_mgr, 
        uint32_t sdp_id, 
        uint32_t service_id, 
        uint32_t idp_id, 
        char *id_token)
{
    //int rv = SDP_SUCCESS;
    //uv_tcp_t *handle = NULL;
    //
    //// if a tunnel exists, get the handle
    //// otherwise set up a new tunnel
    //if((rv = tm_connect_to_peer(tunnel_mgr, sdp_id, service_id, idp_id, id_token, &handle)) != SDP_SUCCESS)
    //{
    //    log_msg(LOG_ERR, "Tunnel Manager could not connect to peer");
    //}
    //
    //if((rv = tm_send_service_request()) != SDP_SUCCESS)
    //{
    //    log_msg(LOG_ERR, "Tunnel Manager failed to send service request to peer");
    //}

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


static void tm_handle_tunnel_traffic_in(
        tunnel_info_t tunnel_data, 
        uint32_t sdp_id, 
        char *packet)
{
    return;
}



static void tm_handle_pipe_msg(tunnel_manager_t tunnel_mgr, void *msg, int data_type)
{
    int rv = SDP_SUCCESS;
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


void gateway_handle_tunnel_msg(tunnel_info_t tunnel_data, char *msg)
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

    log_msg(LOG_INFO, "Tunnel msg from %"PRIu32" said: %s", tunnel_data->sdp_id, msg);

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
        /*
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
        */
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



void *tm_thread_func(void *arg)
{
    fko_srv_options_t *opts = (fko_srv_options_t*)arg;
    uv_tcp_t server;
    struct sockaddr_in addr;
    int rv = 0;

    if(opts->tunnel_mgr == NULL)
    {
        log_msg(LOG_ERR, "Attempted to start Tunnel Manager Thread "
                "without proper initializations. Aborting.");

        // send kill signal for main thread to catch and exit safely
        kill(getpid(), SIGTERM);
        return NULL;
    }

    
    // Construct local address structure
    memset(&addr, 0, sizeof(addr));

    // Convert ipv4 address and port into sockaddr struct
    // ip address '0.0.0.0' means listen on any interface
    uv_ip4_addr("0.0.0.0", TUNNEL_PORT, &addr);

    // Set up tcp handle
    uv_tcp_init(opts->tunnel_mgr->loop, &server);

    server.data = opts->tunnel_mgr;

    // Bind to socket
    uv_tcp_bind(&server, (const struct sockaddr*)&addr, 0);

    // Listen on socket, run tm_new_tunnel_connection_cb() on every new connection
    if((rv = uv_listen((uv_stream_t*) &server, TUNNEL_BACKLOG, tm_new_tunnel_connection_cb)) != 0)
    {
        log_msg(LOG_ERR, "uv_listen error: %s", uv_strerror(rv));
        return NULL;
    }
    
    opts->tunnel_mgr->tm_tcp_server = &server;

    // Start the loop
    uv_run(opts->tunnel_mgr->loop, UV_RUN_DEFAULT);

    uv_close((uv_handle_t*)&server, tm_server_close_cb);

    // Close loop and shutdown
    //uv_loop_close(opts->tunnel_mgr->loop);
    //opts->tunnel_mgr->loop = NULL;

    return NULL;
}


static void gateway_pipe_read_cb(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) 
{
    json_object *msg = NULL;

    log_msg(LOG_DEBUG, "gateway_pipe_read_cb() just called...");

    if (nread > 0) 
    {

        log_msg(LOG_DEBUG, "gateway_pipe_read_cb() got bytes: %d", nread);

        if(nread != sizeof msg)
        {
            log_msg(LOG_ERR, "Tunnel manager received non-pointer message on pipe.");
        }
        else
        {
            log_msg(LOG_DEBUG, "gateway_pipe_read_cb() getting ptr...");

            if(tunnel_manager_array_2_ptr((const char const*)buf->base, (char**)&msg))
            {
                log_msg(LOG_ERR, "Failed to convert received buffer to a pointer address");
                free(buf->base);
                uv_stop(client->loop);       
            }

            free(buf->base);

            log_msg(LOG_DEBUG, "gateway_pipe_read_cb() comparing against stop msg...");

            //is the pointer value pointing to the stop message
            if((char*)msg == TM_STOP_MSG)
            {
                log_msg(LOG_WARNING, "Tunnel manager received stop message from pipe");
                uv_stop(client->loop);
                return;
            }

            log_msg(LOG_WARNING, "Tunnel manager received message from pipe");
            tm_handle_pipe_msg((tunnel_manager_t)client->data, msg, PTR_TO_JSON);

           
            // try to free the msg object
            if(msg != NULL)
            {
                if(json_object_get_type(msg) != json_type_null) 
                    json_object_put(msg);
                else
                    free(msg);
            }

            //tunnel_manager_ptr_2_array((const char* const)reply_str, &ptr);
            //write_req_t *req = calloc(1, sizeof *req);
            //req->buf = uv_buf_init(ptr, sizeof ptr);
            //uv_write((uv_write_t*) req, client, &req->buf, 1, tm_write_cb);

            return;
        }

    }

    if (nread <= 0) 
    {
        if (nread != UV_EOF)
            log_msg(LOG_ERR, "uv read error %s\n", uv_err_name(nread));
        else
            log_msg(LOG_WARNING, "ctrl client closed pipe to tunnel manager");
        uv_close((uv_handle_t*) client, tunnel_manager_pipe_close_cb);
    }

    free(buf->base);
}



int start_tunnel_manager(fko_srv_options_t *opts)
{
    int rv = SDP_SUCCESS;
    int hash_table_len = 0;
    int is_err = 0;
    tunnel_manager_t tunnel_mgr = NULL;

    hash_table_len = strtol_wrapper(opts->config[CONF_ACC_STANZA_HASH_TABLE_LENGTH],
                           MIN_ACC_STANZA_HASH_TABLE_LENGTH,
                           MAX_ACC_STANZA_HASH_TABLE_LENGTH,
                           NO_EXIT_UPON_ERR,
                           &is_err);

    if(is_err != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] var %s value '%s' not in the range %d-%d",
                "ACC_STANZA_HASH_TABLE_LENGTH",
                opts->config[CONF_ACC_STANZA_HASH_TABLE_LENGTH],
                MIN_ACC_STANZA_HASH_TABLE_LENGTH,
                MAX_ACC_STANZA_HASH_TABLE_LENGTH);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    if((rv = tunnel_manager_new(
            (void*)opts,
            IS_SDP_GATEWAY, 
            opts->ctrl_client,
            hash_table_len, 
            gateway_pipe_read_cb, 
            gateway_handle_tunnel_msg,
            &tunnel_mgr
        )) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] Failed to create tunnel manager");
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    opts->tunnel_mgr = tunnel_mgr;

    /*
    if((rv = tunnel_manager_get_pipe(tunnel_mgr, &pipe_to_tm)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] Failed to create tunnel manager");
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }
    */

    if(pthread_create( &(opts->tunnel_mgr_thread), NULL, tm_thread_func, (void*)opts))
    {
        log_msg(LOG_ERR, "Failed to start Tunnel Manager Thread. Aborting.");
        clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
    }
    else
    {
        log_msg(LOG_INFO, "Successfully started Tunnel Manager Thread.");
    }

    if((rv = tunnel_manager_connect_pipe(opts->tunnel_mgr)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] Failed to connect tunnel manager pipe");
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);        
    }

    return rv;
}


static int tm_send_stop_msg_to_me(tunnel_manager_t tunnel_mgr)
{
    char *ptr = NULL;
    int rv = 0;

    log_msg(LOG_DEBUG, "tm_send_stop_msg_to_me() getting ptr address...");

    //stopping the gateway tm, have to send the pointer addr, not the string
    tunnel_manager_ptr_2_array((const char* const)TM_STOP_MSG, &ptr);

    log_msg(LOG_DEBUG, "tm_send_stop_msg_to_me() sending ptr address...");
    
    rv = send(tunnel_mgr->tm_sock_fd, ptr, sizeof(void*), 0);
    free(ptr);

    if (rv == -1) 
    {
        perror("Failed to send stop message to tunnel manager");
        return SDP_ERROR_FILESYSTEM_OPERATION;
    }

    log_msg(LOG_DEBUG, "tm_send_stop_msg_to_me() bytes sent: %d", rv);

    return SDP_SUCCESS;
}



void stop_tunnel_manager(fko_srv_options_t *opts)
{
    log_msg(LOG_DEBUG, "Looking for Tunnel Manager thread to stop...");
    
    // kill thread
    if(opts->tunnel_mgr != NULL)
    {
        if(opts->tunnel_mgr_thread > 0)
        {
            log_msg(LOG_WARNING, "Stopping Tunnel Manager thread now...");
            tm_send_stop_msg_to_me(opts->tunnel_mgr);
            pthread_cancel(opts->tunnel_mgr_thread);
            pthread_join(opts->tunnel_mgr_thread, NULL);
            opts->tunnel_mgr_thread = 0;
            log_msg(LOG_DEBUG, "Tunnel Manager thread stopped");
        }
        else
        {
            log_msg(LOG_WARNING, "Tunnel Manager thread not found");
        }
    }
    else
    {
        log_msg(LOG_WARNING, "Tunnel Manager not found for stopping");
    }
}


void destroy_tunnel_manager(fko_srv_options_t *opts)
{
    // kill thread
    if(opts->tunnel_mgr != NULL)
    {
        log_msg(LOG_WARNING, "Destroying Tunnel Manager...");

        if(opts->tunnel_mgr_thread > 0)
        {
            stop_tunnel_manager(opts);
        }

        tunnel_manager_destroy(opts->tunnel_mgr);
        opts->tunnel_mgr = NULL;
    
        log_msg(LOG_WARNING, "Tunnel Manager Destroyed");    
    }
    else
    {
        log_msg(LOG_WARNING, "Tunnel Manager not found for destruction");
    }

}

