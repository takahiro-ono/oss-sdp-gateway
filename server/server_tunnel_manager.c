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

void *tunnel_manager_thread_func(void *arg)
{
    fko_srv_options_t *opts = (fko_srv_options_t*)arg;

    if(opts->tunnel_mgr == NULL)
    {
        log_msg(LOG_ERR, "Attempted to start Tunnel Manager Thread "
                "without proper initializations. Aborting.");

        // send kill signal for main thread to catch and exit safely
        kill(getpid(), SIGTERM);
        return NULL;
    }

    while(1)
    {
        sleep(1);
    }
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

    if(pthread_create( &(opts->tunnel_mgr_thread), NULL, tunnel_manager_thread_func, (void*)opts))
    {
        log_msg(LOG_ERR, "Failed to start Tunnel Manager Thread. Aborting.");
        clean_exit(opts, FW_CLEANUP, EXIT_FAILURE);
    }
    else
    {
        log_msg(LOG_INFO, "Successfully started Tunnel Manager Thread.");
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

