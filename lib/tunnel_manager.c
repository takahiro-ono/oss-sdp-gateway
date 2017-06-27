/*
 * tunnel_manager.c
 *
 *  Created on: Jun 27, 2017
 *      Author: Daniel Bailey
 */

#include <unistd.h>
#include "fko.h"
#include "sdp_log_msg.h"
#include "bstr_lib.h"
#include "hash_table.h"
#include "tunnel_manager.h"

static void destroy_tunnel_info_item(tunnel_info_t item)
{
    free(item);
}


static void destroy_tunnel_info_list(tunnel_info_t list)
{
    tunnel_info_t this_tunnel = list;
    tunnel_info_t next = NULL;

    while(this_tunnel != NULL)
    {
        next = this_tunnel->next;
        destroy_tunnel_info_item(this_tunnel);
        this_tunnel = next;
    }
}


static void destroy_tunnel_hash_node_cb(hash_table_node_t *node)
{
  if(node->key != NULL) bstr_destroy((bstring)(node->key));
  if(node->data != NULL)
  {
      // this function takes care of all connection nodes (NOT hash table nodes)
      // for this SDP ID, including the very first one
      destroy_tunnel_info_list((tunnel_info_t)(node->data));
  }
}



void tunnel_manager_destroy(tunnel_manager_t tunnel_mgr)
{
    if(tunnel_mgr == NULL) return;

    if(tunnel_mgr->read_pipe_to_tunnel_manager != 0)
        close(tunnel_mgr->read_pipe_to_tunnel_manager);

    if(tunnel_mgr->write_pipe_to_tunnel_manager != 0)
        close(tunnel_mgr->write_pipe_to_tunnel_manager);

    if(tunnel_mgr->read_pipe_from_tunnel_manager != 0)
        close(tunnel_mgr->read_pipe_from_tunnel_manager);

    if(tunnel_mgr->write_pipe_from_tunnel_manager != 0)
        close(tunnel_mgr->write_pipe_from_tunnel_manager);

    if(tunnel_mgr->tunnel_hash_tbl != NULL)
        hash_table_destroy(tunnel_mgr->tunnel_hash_tbl);

    if(tunnel_mgr->waiting_tunnel_hash_tbl != NULL)
        hash_table_destroy(tunnel_mgr->waiting_tunnel_hash_tbl);

    free(tunnel_mgr);
}


int tunnel_manager_new(int tbl_len, tunnel_manager_t *r_tunnel_mgr)
{
    int rv = FKO_SUCCESS;
    tunnel_manager_t tunnel_mgr = NULL;
    int pipe_to_tunnel_manager[2];
    int pipe_from_tunnel_manager[2];

    // allocate memory
    if((tunnel_mgr = calloc(1, sizeof *tunnel_mgr)) == NULL)
        return (FKO_ERROR_MEMORY_ALLOCATION);

    if((rv = pipe(pipe_to_tunnel_manager)) != FKO_SUCCESS)
    {
        log_msg(LOG_ERR,
            "[*] Fatal file system error creating pipe to tunnel manager"
        );
        tunnel_manager_destroy(tunnel_mgr);
        return FKO_ERROR_FILESYSTEM_OPERATION;
    }

    tunnel_mgr->read_pipe_to_tunnel_manager = pipe_to_tunnel_manager[0];
    tunnel_mgr->write_pipe_to_tunnel_manager = pipe_to_tunnel_manager[1];


    if((rv = pipe(pipe_from_tunnel_manager)) != FKO_SUCCESS)
    {
        log_msg(LOG_ERR,
            "[*] Fatal file system error creating pipe to tunnel manager"
        );
        tunnel_manager_destroy(tunnel_mgr);
        return FKO_ERROR_FILESYSTEM_OPERATION;
    }

    tunnel_mgr->read_pipe_from_tunnel_manager = pipe_from_tunnel_manager[0];
    tunnel_mgr->write_pipe_from_tunnel_manager = pipe_from_tunnel_manager[1];

    
    tunnel_mgr->tunnel_hash_tbl = hash_table_create(tbl_len,
            NULL, NULL, destroy_tunnel_hash_node_cb);

    if(tunnel_mgr->tunnel_hash_tbl == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error creating tunnel tracking hash table"
        );
        tunnel_manager_destroy(tunnel_mgr);
        return FKO_ERROR_MEMORY_ALLOCATION;
    }

    tunnel_mgr->waiting_tunnel_hash_tbl = hash_table_create(tbl_len,
            NULL, NULL, destroy_tunnel_hash_node_cb);

    if(tunnel_mgr->waiting_tunnel_hash_tbl == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error creating waiting tunnel tracking hash table"
        );
        tunnel_manager_destroy(tunnel_mgr);
        return FKO_ERROR_MEMORY_ALLOCATION;
    }

    *r_tunnel_mgr = tunnel_mgr;
    return rv;
}
