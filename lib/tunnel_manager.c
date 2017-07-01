/*
 * tunnel_manager.c
 *
 *  Created on: Jun 27, 2017
 *      Author: Daniel Bailey
 */

#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "fko.h"
#include "sdp_log_msg.h"
#include "bstr_lib.h"
#include "hash_table.h"
#include "tunnel_manager.h"


#define NAME_TM_PIPE "tm_pipe"

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

static void remove_sock(tunnel_manager_t tunnel_mgr) 
{
    uv_fs_t req;
    uv_fs_unlink(tunnel_mgr->loop, &req, NAME_TM_PIPE, NULL);
}


void free_write_req(uv_write_t *req) 
{
    write_req_t *wr = (write_req_t*) req;
    free(wr->buf.base);
    free(wr);
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) 
{
  buf->base = calloc(1, suggested_size);
  buf->len = suggested_size;
}

void echo_write(uv_write_t *req, int status) 
{
    if (status < 0) 
    {
        log_msg(LOG_ERR, "uv_write error %s\n", uv_err_name(status));
    }

    free_write_req(req);
}

void echo_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) 
{
    if (nread > 0) 
    {
        log_msg(LOG_INFO, "Tunnel manager received pipe message: %s", buf->base);
        write_req_t *req = calloc(1, sizeof *req);
        req->buf = uv_buf_init(buf->base, nread);
        uv_write((uv_write_t*) req, client, &req->buf, 1, echo_write);
        return;
    }

    if (nread < 0) 
    {
        if (nread != UV_EOF)
            log_msg(LOG_ERR, "uv read error %s\n", uv_err_name(nread));
        uv_close((uv_handle_t*) client, NULL);
    }

    free(buf->base);
}

void on_pipe_connection(uv_stream_t *server, int status) 
{
    if (status == -1) {
        // error!
        return;
    }

    uv_pipe_t *client = calloc(1, sizeof *client);
    uv_pipe_init(server->loop, client, 0);
    if (uv_accept(server, (uv_stream_t*) client) == 0) 
    {
        log_msg(LOG_INFO, "[*] Tunnel Manager received pipe connection");
        uv_read_start((uv_stream_t*) client, alloc_buffer, echo_read);
    }
    else 
    {
        uv_close((uv_handle_t*) client, NULL);
    }
}


void tunnel_manager_destroy(tunnel_manager_t tunnel_mgr)
{
    if(tunnel_mgr == NULL) return;

    if(tunnel_mgr->tm_sock_fd != 0)
        close(tunnel_mgr->tm_sock_fd);

    /*
    if(tunnel_mgr->write_pipe_to_tunnel_manager != 0)
        close(tunnel_mgr->write_pipe_to_tunnel_manager);

    if(tunnel_mgr->read_pipe_from_tunnel_manager != 0)
        close(tunnel_mgr->read_pipe_from_tunnel_manager);

    if(tunnel_mgr->write_pipe_from_tunnel_manager != 0)
        close(tunnel_mgr->write_pipe_from_tunnel_manager);
    */


    /*
    if(tunnel_mgr->pipe_to_tm != NULL)
        free(tunnel_mgr->pipe_to_tm);

    if(tunnel_mgr->pipe_from_tm != NULL)
        free(tunnel_mgr->pipe_from_tm);
    */

    if(tunnel_mgr->loop != NULL)
    {
        remove_sock(tunnel_mgr);
        uv_loop_close(tunnel_mgr->loop);
        //free(tunnel_mgr->loop);
    }

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
    uv_pipe_t *tm_pipe = NULL;

    // allocate memory
    if((tunnel_mgr = calloc(1, sizeof *tunnel_mgr)) == NULL)
        return (FKO_ERROR_MEMORY_ALLOCATION);

    tunnel_mgr->loop = uv_default_loop();
    
    if((tm_pipe = calloc(1, sizeof *tm_pipe)) == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error creating uv_pipe_t tm_pipe"
        );
        tunnel_manager_destroy(tunnel_mgr);
        return FKO_ERROR_MEMORY_ALLOCATION;
    }

    tunnel_mgr->tm_pipe = tm_pipe;
    if((rv = uv_pipe_init(tunnel_mgr->loop, tunnel_mgr->tm_pipe, 0)))
    {
        log_msg(LOG_ERR, "[*] uv_pipe_init error %s\n", uv_err_name(rv));
        tunnel_manager_destroy(tunnel_mgr);
        return FKO_ERROR_FILESYSTEM_OPERATION;
    }

    remove_sock(tunnel_mgr);


    if((rv = uv_pipe_bind(tunnel_mgr->tm_pipe, NAME_TM_PIPE))) 
    {
        log_msg(LOG_ERR, "[*] uv_pipe_bind error %s\n", uv_err_name(rv));
        tunnel_manager_destroy(tunnel_mgr);
        return FKO_ERROR_FILESYSTEM_OPERATION;
    }

    if((rv = uv_listen((uv_stream_t*) tunnel_mgr->tm_pipe, 128, on_pipe_connection))) 
    {
        log_msg(LOG_ERR, "[*] pipe uv_listen error %s\n", uv_err_name(rv));
        tunnel_manager_destroy(tunnel_mgr);
        return FKO_ERROR_FILESYSTEM_OPERATION;
    }

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


int tunnel_manager_connect_pipe(tunnel_manager_t tunnel_mgr)
{
    struct sockaddr_un remote;
    int len = 0;
    char buf[100];
    char str[] = "Hello from main";
    int bytes_rcvd = 0;

    if ((tunnel_mgr->tm_sock_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) 
    {
        perror("socket");
        return FKO_ERROR_FILESYSTEM_OPERATION;
    }

    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, NAME_TM_PIPE);
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);
    
    if (connect(tunnel_mgr->tm_sock_fd, (struct sockaddr *)&remote, len) < 0) 
    {
        perror("connect");
        return FKO_ERROR_FILESYSTEM_OPERATION;
    }

    log_msg(LOG_INFO, "Connected.\n");

    if (send(tunnel_mgr->tm_sock_fd, str, strlen(str), 0) == -1) 
    {
        perror("Main pipe send");
        return FKO_ERROR_FILESYSTEM_OPERATION;
    }

    if ((bytes_rcvd = recv(tunnel_mgr->tm_sock_fd, buf, 100, 0)) > 0) 
    {
        str[bytes_rcvd] = '\0';
        log_msg(LOG_INFO, "Message received: %s", buf);
    } 
    else 
    {
        if (bytes_rcvd < 0) 
            perror("Main pipe recv");
        else 
            log_msg(LOG_INFO, "Tunnel Manager closed pipe connection\n");
        return FKO_ERROR_FILESYSTEM_OPERATION;
    }

    return FKO_SUCCESS;
}

