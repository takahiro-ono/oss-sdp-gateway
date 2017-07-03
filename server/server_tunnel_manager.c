/*
 * server_tunnel_manager.c
 *
 *  Created on: Jun 27, 2017
 *      Author: Daniel Bailey
 */

#include "fwknopd_common.h"
#include "log_msg.h"
#include "tunnel_manager.h"
#include "server_tunnel_manager.h"

#define PORT 8282
#define BACKLOG 10


static void on_read(uv_stream_t* handle, ssize_t nread, const uv_buf_t *buf)
{
    tunnel_info_t tunnel_data = handle->data;
    if(tunnel_data == NULL)
    {
        log_msg(
            LOG_ERR, 
            "[*] ALERT: Received data on tunnel, but can't find associated tunnel data! Disconnecting."
        );

        uv_close((uv_handle_t*)handle, tunnel_manager_close_client_cb);
        free(buf->base);
        return;
    }
    
    if (nread < 0) 
    {
        if (nread != UV_EOF)
            log_msg(LOG_ERR, "uv read error %s", uv_err_name(nread));

        // AFTER THE UV_CLOSE, NEVER ACCESS ANY DATA TIED TO THE HANDLE
        // LIKE THE TUNNEL INFO ITEM FOR EXAMPLE 
        log_msg(LOG_INFO, "[*] %"PRIu32" has disconnected", tunnel_data->sdp_id);
        free(buf->base);
        uv_close((uv_handle_t*)handle, tunnel_manager_close_client_cb);

        return;
    }

    // show message
    log_msg(LOG_INFO, "%"PRIu32" said: %s", tunnel_data->sdp_id, buf->base);
    free(buf->base);
}

// Write callback
void on_write(uv_write_t *req, int status) {
    // Check status
    if (status < 0) {
        log_msg(LOG_ERR, "Write failed: %s\n", uv_strerror(status));
    }

    // Close client hanlde
    uv_close((uv_handle_t*)req->handle, tunnel_manager_close_client_cb);

    // Free request handle
    free(req);
}

void server_close_cb(uv_handle_t *handle)
{
    free(handle);
}

// Callback for new connections
void new_tunnel_connection(uv_stream_t *server, int status) {
    uv_tcp_t *client = NULL;
    //uv_write_t *req = NULL;
    int rv = FKO_SUCCESS;
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
        log_msg(LOG_ERR, "new_tunnel_connection uv_tcp_init error: %s\n", uv_strerror(rv));
        free(client);
        return;
    }

    // Accept new connection
    if(uv_accept(server, (uv_stream_t*) client) == 0) {

        if((rv = tunnel_manager_get_peer_addr_and_port(
            client, &ip_str, &ip_num, &port_num)) != FKO_SUCCESS)
        {
            log_msg(LOG_ERR, "[*] Failed to get peer connection info. Closing connection.");

            //closing client handle
            uv_close((uv_handle_t*)client, tunnel_manager_close_client_cb);

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
            )) != FKO_SUCCESS)
        {
            log_msg(LOG_ERR, "[*] new_tunnel_connection failed to create tunnel request");

            if(rv == FKO_ERROR_MEMORY_ALLOCATION)
            {
                log_msg(LOG_ERR, "[*] Fatal memory error. Aborting.");
                uv_close((uv_handle_t*)client, tunnel_manager_close_client_cb);
                free(ip_str);
                kill(getpid(), SIGTERM);
                return;
            }
        }

        log_msg(LOG_WARNING, "[+] new_tunnel_connection Successfully stored tunnel request");

        // TODO: perform SSL handshake, that's async so code below will need
        // to become part of the callback for that


        // check if we were expecting this connection
        if((rv = tunnel_manager_find_client_request(
            (tunnel_manager_t)server->data, sdp_id, &tunnel_data
            )) != FKO_SUCCESS)
        {
            log_msg(
                LOG_ERR, 
                "[*] ALERT: Attempted tunnel connection by unexpected sdp id %"PRIu32
                " from address %s:%d!",
                sdp_id, ip_str, port_num
            );

            uv_close((uv_handle_t*)client, tunnel_manager_close_client_cb);
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

            uv_close((uv_handle_t*)client, tunnel_manager_close_client_cb);
            free(ip_str);
            return;            
        }

        free(ip_str);

        client->data = tunnel_data;
        tunnel_data->handle = client;

        log_msg(
            LOG_WARNING, 
            "[+] Tunnel connection by sdp id %"PRIu32" from address %s was expected!",
            tunnel_data->sdp_id, 
            tunnel_data->remote_public_ip
        );


        // start accepting messages from the client
        if((rv = uv_read_start((uv_stream_t*) client, tunnel_manager_alloc_buffer, on_read)))
        {
            log_msg(LOG_ERR, "new_tunnel_connection uv_read_start error: %s", uv_strerror(rv));

            //closing client handle
            uv_close((uv_handle_t*)client, tunnel_manager_close_client_cb);
        }

        /*
        // Create write request handle
        if((req = malloc(sizeof(*req))) == NULL)
        {
            log_msg(LOG_ERR, "Memory error creating uv_tcp_t client handle.");

            // send kill signal for main thread to catch and exit safely
            kill(getpid(), SIGTERM);
            return;
        }

        memset(req, 0, sizeof(*req));

        // Write and call on_write callback when finished
        rv = uv_write((uv_write_t*)req, (uv_stream_t*)client, bufs, 1, on_write);

        if (rv < 0) {
            log_msg(LOG_ERR, "Write error: %s\n", uv_strerror(rv));
            uv_close((uv_handle_t*)client, tunnel_manager_close_client_cb);
        }
        */
    }
    else 
    {
        // Accept failed, closing client handle
        uv_close((uv_handle_t*)client, tunnel_manager_close_client_cb);
    }

}


void *tunnel_manager_thread_func(void *arg)
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
    uv_ip4_addr("0.0.0.0", PORT, &addr);

    // Set up tcp handle
    uv_tcp_init(opts->tunnel_mgr->loop, &server);

    server.data = opts->tunnel_mgr;

    // Bind to socket
    uv_tcp_bind(&server, (const struct sockaddr*)&addr, 0);

    // Listen on socket, run new_tunnel_connection() on every new connection
    if((rv = uv_listen((uv_stream_t*) &server, BACKLOG, new_tunnel_connection)) != 0)
    {
        log_msg(LOG_ERR, "uv_listen error: %s", uv_strerror(rv));
        return NULL;
    }
    
    opts->tunnel_mgr->tm_tcp_server = &server;

    // Start the loop
    uv_run(opts->tunnel_mgr->loop, UV_RUN_DEFAULT);

    uv_close((uv_handle_t*)&server, server_close_cb);

    // Close loop and shutdown
    //uv_loop_close(opts->tunnel_mgr->loop);
    //opts->tunnel_mgr->loop = NULL;

    return NULL;
}


int start_tunnel_manager(fko_srv_options_t *opts)
{
    int rv = FKO_SUCCESS;
    int hash_table_len = 0;
    int is_err = 0;
    tunnel_manager_t tunnel_mgr = NULL;

    hash_table_len = strtol_wrapper(opts->config[CONF_ACC_STANZA_HASH_TABLE_LENGTH],
                           MIN_ACC_STANZA_HASH_TABLE_LENGTH,
                           MAX_ACC_STANZA_HASH_TABLE_LENGTH,
                           NO_EXIT_UPON_ERR,
                           &is_err);

    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] var %s value '%s' not in the range %d-%d",
                "ACC_STANZA_HASH_TABLE_LENGTH",
                opts->config[CONF_ACC_STANZA_HASH_TABLE_LENGTH],
                MIN_ACC_STANZA_HASH_TABLE_LENGTH,
                MAX_ACC_STANZA_HASH_TABLE_LENGTH);
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    if((rv = tunnel_manager_new(0, hash_table_len, &tunnel_mgr)) != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] Failed to create tunnel manager");
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }

    opts->tunnel_mgr = tunnel_mgr;

    /*
    if((rv = tunnel_manager_get_pipe(tunnel_mgr, &pipe_to_tm)) != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] Failed to create tunnel manager");
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);
    }
    */

    if(pthread_create( &(opts->tunnel_mgr_thread), NULL, tunnel_manager_thread_func, (void*)opts))
    {
        log_msg(LOG_ERR, "Failed to start Tunnel Manager Thread. Aborting.");
        clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
    }
    else
    {
        log_msg(LOG_INFO, "Successfully started Tunnel Manager Thread.");
    }

    if((rv = tunnel_manager_connect_pipe(opts->tunnel_mgr)) != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] Failed to connect tunnel manager pipe");
        clean_exit(opts, NO_FW_CLEANUP, EXIT_FAILURE);        
    }

    return rv;
}


void stop_tunnel_manager(fko_srv_options_t *opts)
{
    log_msg(LOG_DEBUG, "Looking for Tunnel Manager thread to stop...");
    
    // kill thread
    if(opts->tunnel_mgr != NULL)
    {
        if(opts->tunnel_mgr_thread > 0)
        {
            log_msg(LOG_DEBUG, "Stopping Tunnel Manager thread now...");
            tunnel_manager_send_stop(opts->tunnel_mgr);
            pthread_cancel(opts->tunnel_mgr_thread);
            pthread_join(opts->tunnel_mgr_thread, NULL);
            opts->tunnel_mgr_thread = 0;
            log_msg(LOG_DEBUG, "Tunnel Manager thread stopped");
        }
        else
        {
            log_msg(LOG_DEBUG, "Tunnel Manager thread not found");
        }
    }
    else
    {
        log_msg(LOG_DEBUG, "Tunnel Manager not found for stopping");
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

