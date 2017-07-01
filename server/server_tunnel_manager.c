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

// Close client
void close_client(uv_handle_t *handle) {
    // Free client handle after connection has been closed
    free(handle);
}

// Write callback
void on_write(uv_write_t *req, int status) {
    // Check status
    if (status < 0) {
        fprintf(stderr, "Write failed: %s\n", uv_strerror(status));
    }

    // Close client hanlde
    uv_close((uv_handle_t*)req->handle, close_client);

    // Free request handle
    free(req);
}

// Callback for new connections
void new_connection(uv_stream_t *server, int status) {
    uv_tcp_t *client = NULL;
    uv_write_t *req = NULL;
    int rv = FKO_SUCCESS;
    char *s = "Hello, World!\n";
    uv_buf_t bufs[] = {uv_buf_init(s, (unsigned int)strnlen(s, 20))};

    // Check status code, anything under 0 means an error.
    if (status < 0) {
        fprintf(stderr, "New connection error: %s\n", uv_strerror(status));
        return;
    }

    // Create handle for client
    if((client = malloc(sizeof(*client))) == NULL)
    {
        log_msg(LOG_ERR, "Memory error creating uv_tcp_t client handle.");

        // send kill signal for main thread to catch and exit safely
        kill(getpid(), SIGTERM);
        return;
    }

    memset(client, 0, sizeof(*client));
    uv_tcp_init(server->loop, client);

    // Accept new connection
    if (uv_accept(server, (uv_stream_t*) client) == 0) {
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
            fprintf(stderr, "Write error: %s\n", uv_strerror(rv));
            uv_close((uv_handle_t*)client, close_client);
        }
    }
    else 
    {
        // Accept failed, closing client handle
        uv_close((uv_handle_t*)client, close_client);
    }

}


void *tunnel_manager_thread_func(void *arg)
{
    fko_srv_options_t *opts = (fko_srv_options_t*)arg;
    //uv_tcp_t server;
    //struct sockaddr_in addr;
    //int rv = 0;

    if(opts->tunnel_mgr == NULL)
    {
        log_msg(LOG_ERR, "Attempted to start Tunnel Manager Thread "
                "without proper initializations. Aborting.");

        // send kill signal for main thread to catch and exit safely
        kill(getpid(), SIGTERM);
        return NULL;
    }

    /*
    // Construct local address structure
    memset(&addr, 0, sizeof(addr));

    // Convert ipv4 address and port into sockaddr struct
    // ip address '0.0.0.0' means listen on any interface
    uv_ip4_addr("0.0.0.0", PORT, &addr);

    // Set up tcp handle
    uv_tcp_init(loop, &server);

    // Bind to socket
    uv_tcp_bind(&server, (const struct sockaddr*)&addr, 0);

    // Listen on socket, run new_connection() on every new connection
    if((rv = uv_listen((uv_stream_t*) &server, BACKLOG, new_connection)) != 0)
    {
        fprintf(stderr, "Listen error: %s\n", uv_strerror(rv));
        return NULL;
    }
    */

    // Start the loop
    uv_run(opts->tunnel_mgr->loop, UV_RUN_DEFAULT);

    // Close loop and shutdown
    uv_loop_close(opts->tunnel_mgr->loop);
    opts->tunnel_mgr->loop = NULL;

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

    if((rv = tunnel_manager_new(hash_table_len, &tunnel_mgr)) != FKO_SUCCESS)
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
    // kill thread
    if(opts->tunnel_mgr != NULL)
    {
        if(opts->tunnel_mgr_thread > 0)
        {
            pthread_cancel(opts->tunnel_mgr_thread);
            pthread_join(opts->tunnel_mgr_thread, NULL);
            opts->tunnel_mgr_thread = 0;
        }
    }
}


void destroy_tunnel_manager(fko_srv_options_t *opts)
{
    // kill thread
    if(opts->tunnel_mgr != NULL)
    {
        if(opts->tunnel_mgr_thread > 0)
        {
            stop_tunnel_manager(opts);
        }

        tunnel_manager_destroy(opts->tunnel_mgr);
        opts->tunnel_mgr = NULL;
    }
}

