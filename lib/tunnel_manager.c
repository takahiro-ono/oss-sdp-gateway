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
#include "fko_common.h"
#include "sdp_log_msg.h"
#include "bstr_lib.h"
#include "hash_table.h"
#include "tunnel_manager.h"
#include "sdp_ctrl_client.h"
#include "tunnel_com.h"
#include "tunnel_record.h"


static int tm_add_to_pipe_client_list(tunnel_manager_t tunnel_mgr, uv_pipe_t *handle)
{
    pipe_client_item_t new_guy = NULL;
    pipe_client_item_t ptr = tunnel_mgr->pipe_client_list;

    if((new_guy = calloc(1, sizeof *new_guy)) == NULL)
    {
        return SDP_ERROR_MEMORY_ALLOCATION;
    }

    new_guy->handle = handle;

    if(ptr == NULL)
    {
        tunnel_mgr->pipe_client_list = new_guy;
        log_msg(LOG_WARNING, "Added pipe client to list");
        return SDP_SUCCESS;
    }

    while(ptr->next)
        ptr = ptr->next;

    ptr->next = new_guy;
    log_msg(LOG_WARNING, "Added pipe client to list");
    return SDP_SUCCESS;
}


static int tm_remove_from_pipe_client_list(tunnel_manager_t tunnel_mgr, uv_pipe_t *handle)
{
    pipe_client_item_t ptr = tunnel_mgr->pipe_client_list;
    pipe_client_item_t follower = NULL;

    if(!ptr)
    {
        log_msg(LOG_WARNING, "Pipe client not found for removal");
        return SDP_SUCCESS;
    }

    while(ptr)
    {
        if(ptr->handle == handle)
        {
            if(follower)
                follower->next = ptr->next;
            else
                tunnel_mgr->pipe_client_list = ptr->next;

            free(ptr);
            log_msg(LOG_WARNING, "Removed pipe client from list");
            return SDP_SUCCESS;
        }

        follower = ptr;
        ptr = ptr->next;
    }

    log_msg(LOG_WARNING, "Pipe client not found for removal");
    return SDP_SUCCESS;
}



static int tm_traverse_print_tunnel_recs_cb(hash_table_node_t *node, void *arg)
{
    tunnel_record_print((tunnel_record_t)(node->data));

    return SDP_SUCCESS;
}




static void tm_destroy_open_tunnel_hash_node_cb(hash_table_node_t *node)
{
    log_msg(LOG_WARNING, "Found an open tunnel info hash table node to destroy.");
    if(node->key != NULL) bstr_destroy((bstring)(node->key));

    // don't destroy the data, open table and request table point to the 
    // same data, so the request table handles actual data clean up
}

static void tm_destroy_requested_tunnel_hash_node_cb(hash_table_node_t *node)
{
    log_msg(LOG_WARNING, "Found a requested tunnel info hash table node to destroy.");
    if(node->key != NULL) bstr_destroy((bstring)(node->key));
    if(node->data != NULL)
    {
        tunnel_record_destroy((tunnel_record_t)(node->data));
    }
}

static void tm_remove_sock(tunnel_manager_t tunnel_mgr) 
{
    uv_fs_t req;
    uv_fs_unlink(tunnel_mgr->loop, &req, tunnel_mgr->pipe_name, NULL);
}


void tunnel_manager_tcp_close_cb(uv_handle_t* handle)
{
    free(handle);
}

void tunnel_manager_pipe_close_cb(uv_handle_t* handle)
{
    tm_remove_from_pipe_client_list((tunnel_manager_t)handle->data, (uv_pipe_t*)handle);
    free(handle);
}

static void tm_main_pipe_close_cb(uv_handle_t* handle)
{
    free(handle);
}

static void tm_close_all_pipe_clients(tunnel_manager_t tunnel_mgr)
{
    pipe_client_item_t ptr = tunnel_mgr->pipe_client_list;
    pipe_client_item_t prev = NULL;

    while(ptr)
    {
        uv_close((uv_handle_t*)ptr->handle, tm_main_pipe_close_cb);
        prev = ptr;
        ptr = ptr->next;
        free(prev);
    }

}

void tunnel_manager_free_write_req(uv_write_t *req) 
{
    write_req_t *wr = (write_req_t*) req;
    free(wr->buf.base);
    free(wr);
}

void tunnel_manager_write_cb(uv_write_t *req, int status) 
{
    if (status < 0) 
    {
        log_msg(LOG_ERR, "uv_write error %s\n", uv_err_name(status));
    }

    tunnel_manager_free_write_req(req);
}

int tunnel_manager_send_pipe_msg(tunnel_manager_t tunnel_mgr, int send_type, uv_stream_t *handle, char *msg)
{
    int rv = SDP_SUCCESS;
    char *ptr = NULL;
    int len = 0;
    write_req_t *req = NULL;

    if(send_type == SEND_PTR)
    {
        log_msg(LOG_WARNING, "tm_send_msg() sending message as pointer");

        if((rv = tunnel_manager_ptr_2_array((const char* const)msg, &ptr)) != SDP_SUCCESS)
        {
            log_msg(LOG_ERR, "tm_send_msg() failed to make address array to send pointer");
            return rv;
        }

        len = sizeof(void*);
    }
    else
    {
        log_msg(LOG_WARNING, "tm_send_msg() sending message as json string");
        
        ptr = msg;

        len = strnlen(ptr, SDP_COM_MAX_MSG_LEN);
    }

    if((req = calloc(1, sizeof *req)) == NULL)
    {
        log_msg(LOG_ERR, "tm_send_msg() Fatal memory error");
        if(send_type == SEND_PTR) free(ptr);
        return SDP_ERROR_MEMORY_ALLOCATION;
    }

    req->buf = uv_buf_init(ptr, len);
    
    if((rv = uv_write((uv_write_t*) req, handle, &req->buf, 1, tunnel_manager_write_cb)))
    {
        log_msg(LOG_ERR, "tm_send_msg() uv_write error: %s", uv_err_name(rv));
        return SDP_ERROR;
    }

    return SDP_SUCCESS;
}

void tunnel_manager_handle_tunnel_traffic(
        tunnel_manager_t tunnel_mgr, 
        uint32_t sdp_id, 
        char *packet)
{
    return;

}


static void tm_on_pipe_connection(uv_stream_t *server, int status) 
{
    int rv = SDP_SUCCESS;
    uv_pipe_t *client = NULL;
    tunnel_manager_t tunnel_mgr = (tunnel_manager_t)server->data;

    if (status == -1) {
        // error!
        return;
    }

    if(tunnel_mgr == NULL)
    {
        log_msg(
            LOG_ERR, 
            "Received pipe connection, but pipe server missing tunnel manager data"
        );

        uv_stop(server->loop);
        return;
    }

    if(tunnel_mgr->pipe_read_cb_ptr == NULL)
    {
        log_msg(
            LOG_ERR, 
            "Received pipe connection, but tunnel manager's pipe_read_cb_ptr is not set"
        );

        uv_stop(server->loop);
        return;
    }

    if((client = calloc(1, sizeof *client)) == NULL)
    {
        log_msg(LOG_ERR, "[*] Fatal memory error");
        uv_stop(server->loop);
        return;        
    }

    if((rv = uv_pipe_init(server->loop, client, 0)))
    {
        log_msg(LOG_ERR, "uv_pipe_init error: %s", uv_err_name(rv));
        uv_close((uv_handle_t*) client, tm_main_pipe_close_cb);
        return;
    }

    client->data = tunnel_mgr;
    if((rv = tm_add_to_pipe_client_list(tunnel_mgr, client)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] Fatal memory error");
        uv_close((uv_handle_t*) client, tm_main_pipe_close_cb);
        uv_stop(server->loop);
        return;        
    }

    if (uv_accept(server, (uv_stream_t*) client) == 0) 
    {
        log_msg(LOG_WARNING, "[*] Tunnel Manager received pipe connection");
        uv_read_start((uv_stream_t*) client, 
            tunnel_com_alloc_buffer, 
            tunnel_mgr->pipe_read_cb_ptr);
    }
    else 
    {
        uv_close((uv_handle_t*) client, tm_main_pipe_close_cb);
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
        tm_close_all_pipe_clients(tunnel_mgr);
        
        tm_remove_sock(tunnel_mgr);

        if(tunnel_mgr->tm_pipe != NULL)
        {
            uv_close((uv_handle_t*)tunnel_mgr->tm_pipe, tm_main_pipe_close_cb);
        }

        uv_loop_close(tunnel_mgr->loop);
        //free(tunnel_mgr->loop);
    }

    if(tunnel_mgr->open_tunnel_hash_tbl != NULL)
        hash_table_destroy(tunnel_mgr->open_tunnel_hash_tbl);

    if(tunnel_mgr->requested_tunnel_hash_tbl != NULL)
    {
        if(pthread_mutex_lock(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex)))
        {
            log_msg(LOG_ERR, "Mutex lock error.");
        }
        else
        {
            hash_table_destroy(tunnel_mgr->requested_tunnel_hash_tbl);
            pthread_mutex_unlock(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex));
            pthread_mutex_destroy(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex));
        }
    }

    if(tunnel_mgr->ca_cert_file != NULL)
        free(tunnel_mgr->ca_cert_file);

    if(tunnel_mgr->cert_file != NULL)
        free(tunnel_mgr->cert_file);

    if(tunnel_mgr->key_file != NULL)
        free(tunnel_mgr->key_file);
    
    if(tunnel_mgr->fwknop_path != NULL)
        free(tunnel_mgr->fwknop_path);
    
    if(tunnel_mgr->fwknoprc_file != NULL)
        free(tunnel_mgr->fwknoprc_file);
    
    if(tunnel_mgr->ssl_ctx != NULL)
        SSL_CTX_free(tunnel_mgr->ssl_ctx);

    // free the OpenSSL digests and algorithms
    EVP_cleanup();

    // free the OpenSSL error strings
    ERR_free_strings();

    free(tunnel_mgr);
}


static int tm_ssl_ctx_init(tunnel_manager_t tunnel_mgr)
{
    int rv = SDP_SUCCESS;

    // retrieve the paths to the cred files from the ctrl client
    if((rv = sdp_ctrl_client_get_cred_files(
            tunnel_mgr->ctrl_client,
            &tunnel_mgr->ca_cert_file,
            &tunnel_mgr->cert_file,
            &tunnel_mgr->key_file
        )) != SDP_SUCCESS)
    {
        return rv;
    }

    return tunnel_com_ssl_ctx_init(
            &tunnel_mgr->ssl_ctx, 
            tunnel_mgr->ca_cert_file,
            tunnel_mgr->cert_file,
            tunnel_mgr->key_file);
}


int tunnel_manager_new(
        void *program_options, 
        int is_sdp_client, 
        sdp_ctrl_client_t ctrl_client,
        int tbl_len, 
        uv_read_cb pipe_read_cb_ptr, 
        tunnel_msg_in_callback tunnel_msg_in_cb, 
        tunnel_manager_t *r_tunnel_mgr)
{
    int rv = SDP_SUCCESS;
    tunnel_manager_t tunnel_mgr = NULL;
    uv_pipe_t *tm_pipe = NULL;

    if(!program_options)
    {
        log_msg(LOG_ERR, "tunnel_manager_new() program options pointer not provided");
        return SDP_ERROR;
    }

    if(!tbl_len)
    {
        log_msg(LOG_ERR, "tunnel_manager_new() hash table length not provided");
        return SDP_ERROR;
    }

    if(!pipe_read_cb_ptr)
    {
        log_msg(LOG_ERR, "tunnel_manager_new() pipe read callback function not provided");
        return SDP_ERROR;
    }

    if(!tunnel_msg_in_cb)
    {
        log_msg(LOG_ERR, "tunnel_manager_new() tunnel message in callback function not provided");
        return SDP_ERROR;
    }

    if(!ctrl_client)
    {
        log_msg(LOG_ERR, "tunnel_manager_new() ctrl client pointer not provided");
        return SDP_ERROR;
    }



    // allocate memory
    if((tunnel_mgr = calloc(1, sizeof *tunnel_mgr)) == NULL)
        return (SDP_ERROR_MEMORY_ALLOCATION);

    tunnel_mgr->program_options_ptr = program_options;
    tunnel_mgr->is_sdp_client = is_sdp_client;
    tunnel_mgr->ctrl_client = ctrl_client;
    tunnel_mgr->pipe_name = (is_sdp_client ? NAME_TM_CLIENT_PIPE : NAME_TM_GATEWAY_PIPE);
    tunnel_mgr->pipe_read_cb_ptr = pipe_read_cb_ptr;
    tunnel_mgr->tunnel_msg_in_cb = tunnel_msg_in_cb;


    log_msg(LOG_WARNING, "Tunnel Manager pipe name set to %s", tunnel_mgr->pipe_name);

    tunnel_mgr->loop = uv_default_loop();
    
    if((tm_pipe = calloc(1, sizeof *tm_pipe)) == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error creating uv_pipe_t tm_pipe"
        );
        tunnel_manager_destroy(tunnel_mgr);
        return SDP_ERROR_MEMORY_ALLOCATION;
    }

    if((rv = uv_pipe_init(tunnel_mgr->loop, tm_pipe, 0)))
    {
        log_msg(LOG_ERR, "[*] uv_pipe_init error %s\n", uv_err_name(rv));
        free(tm_pipe);
        tunnel_manager_destroy(tunnel_mgr);
        return SDP_ERROR_FILESYSTEM_OPERATION;
    }

    tunnel_mgr->tm_pipe = tm_pipe;
    tm_pipe->data = tunnel_mgr;
    tm_remove_sock(tunnel_mgr);


    if((rv = uv_pipe_bind(tunnel_mgr->tm_pipe, tunnel_mgr->pipe_name))) 
    {
        log_msg(LOG_ERR, "[*] uv_pipe_bind error %s\n", uv_err_name(rv));
        tunnel_manager_destroy(tunnel_mgr);
        return SDP_ERROR_FILESYSTEM_OPERATION;
    }

    if((rv = uv_listen((uv_stream_t*) tunnel_mgr->tm_pipe, 128, tm_on_pipe_connection))) 
    {
        log_msg(LOG_ERR, "[*] pipe uv_listen error %s\n", uv_err_name(rv));
        tunnel_manager_destroy(tunnel_mgr);
        return SDP_ERROR_FILESYSTEM_OPERATION;
    }


    tunnel_mgr->open_tunnel_hash_tbl = hash_table_create(tbl_len,
        NULL, NULL, tm_destroy_open_tunnel_hash_node_cb);

    if(tunnel_mgr->open_tunnel_hash_tbl == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error creating tunnel tracking hash table"
        );
        tunnel_manager_destroy(tunnel_mgr);
        return SDP_ERROR_MEMORY_ALLOCATION;
    }

    tunnel_mgr->requested_tunnel_hash_tbl = hash_table_create(tbl_len,
        NULL, NULL, tm_destroy_requested_tunnel_hash_node_cb);

    if(tunnel_mgr->requested_tunnel_hash_tbl == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error creating waiting tunnel tracking hash table"
        );
        tunnel_manager_destroy(tunnel_mgr);
        return SDP_ERROR_MEMORY_ALLOCATION;
    }

    pthread_mutex_init(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex), NULL);


    // init the SSL_CTX which is used for all tunnel connections
    if((rv = tm_ssl_ctx_init(tunnel_mgr)) != SDP_SUCCESS)
    {
        tunnel_manager_destroy(tunnel_mgr);
        return rv;
    }


    //if((rv = sdp_ctrl_client_should_use_spa(
    //        ctrl_client, 
    //        &tunnel_mgr->use_spa
    //    )) != SDP_SUCCESS)
    //{
    //    tunnel_manager_destroy(tunnel_mgr);
    //    return rv;
    //}

    if((rv = sdp_ctrl_client_get_rc_path(
            ctrl_client, 
            &tunnel_mgr->fwknoprc_file
        )) != SDP_SUCCESS)
    {
        tunnel_manager_destroy(tunnel_mgr);
        return rv;
    }

    if((rv = sdp_ctrl_client_get_fwknop_path(
            ctrl_client, 
            &tunnel_mgr->fwknop_path
        )) != SDP_SUCCESS)
    {
        tunnel_manager_destroy(tunnel_mgr);
        return rv;
    }


    *r_tunnel_mgr = tunnel_mgr;
    return rv;
}


int tunnel_manager_connect_pipe(tunnel_manager_t tunnel_mgr)
{
    struct sockaddr_un remote;
    int len = 0;
    //char buf[100];
    //char str[] = "Hello from main";
    //int bytes_rcvd = 0;
    //char *msg_for_gate_tm = NULL;
    //char *ptr = NULL;


    
    // if this is an SDP client (not gateway), this pipe is IPC capable
    if ((tunnel_mgr->tm_sock_fd = socket(AF_UNIX, SOCK_STREAM, tunnel_mgr->is_sdp_client)) == -1) 
    {
        perror("socket");
        return SDP_ERROR_FILESYSTEM_OPERATION;
    }

    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, tunnel_mgr->pipe_name);
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);
    
    if (connect(tunnel_mgr->tm_sock_fd, (struct sockaddr *)&remote, len) < 0) 
    {
        perror("connect");
        return SDP_ERROR_FILESYSTEM_OPERATION;
    }

    log_msg(LOG_ALERT, "Connected to tunnel manager's pipe");


    /*
    if(tunnel_mgr->is_sdp_client)
    {

        if (send(tunnel_mgr->tm_sock_fd, str, strlen(str), 0) == -1) 
        {
            perror("Main pipe send");
            return SDP_ERROR_FILESYSTEM_OPERATION;
        }

        if ((bytes_rcvd = recv(tunnel_mgr->tm_sock_fd, buf, 100, 0)) > 0) 
        {
            buf[bytes_rcvd] = '\0';
            log_msg(LOG_ALERT, "Message received from Tunnel Manager: %s", buf);
        } 
        else 
        {
            if (bytes_rcvd < 0) 
                perror("Main pipe recv");
            else 
                log_msg(LOG_ALERT, "Tunnel Manager closed pipe connection\n");
            return SDP_ERROR_FILESYSTEM_OPERATION;
        }
    }
    else
    {
        msg_for_gate_tm = calloc(1, 30);
        snprintf(msg_for_gate_tm, 30, "WHAT'S UP GATEWAY TM!");
        tunnel_manager_ptr_2_array((const char const*)msg_for_gate_tm, &ptr);

        len = send(tunnel_mgr->tm_sock_fd, ptr, sizeof ptr, 0);
        free(ptr);

        if (len == -1) 
        {
            perror("Main pipe send");
            return SDP_ERROR_FILESYSTEM_OPERATION;
        }

        if ((bytes_rcvd = recv(tunnel_mgr->tm_sock_fd, buf, 100, 0)) > 0) 
        {
            if(bytes_rcvd != sizeof(void*))
            {
                log_msg(LOG_ALERT, "Message received from Tunnel Manager is not a pointer");
                return SDP_ERROR_FILESYSTEM_OPERATION;
            }

            tunnel_manager_array_2_ptr((const char* const)buf, &ptr);
            
            log_msg(LOG_ALERT, "Pointer message received from Tunnel Manager: %s", ptr);
            free(ptr);
        } 
        else 
        {
            if (bytes_rcvd < 0) 
                perror("Main pipe recv");
            else 
                log_msg(LOG_ALERT, "Tunnel Manager closed pipe connection\n");
            return SDP_ERROR_FILESYSTEM_OPERATION;
        }

    }
    */

    return SDP_SUCCESS;
}



static bstring tm_tunnel_key_from_sdpid(uint32_t sdp_id)
{
    char id_str[SDP_MAX_CLIENT_ID_STR_LEN] = {0};

    // convert the sdp id integer to a bstring
    snprintf(id_str, SDP_MAX_CLIENT_ID_STR_LEN, "%"PRIu32, sdp_id);
    return bstr_from_cstr(id_str);
}


/*
 *  When a SPA packet arrives, create the tunnel request and 
 *  put in the request hash table so the tunnel manager knows whom to expect
 *  from what IP address.
 */
int tunnel_manager_submit_client_request(
        tunnel_manager_t tunnel_mgr, 
        uint32_t sdp_id,
        char *ip_str
        //uint32_t service_id,
        //uint32_t idp_id,
        //char *id_token
    )
{
    //tunneled_service_t service_requested = NULL;
    tunnel_record_t tunnel_rec = NULL;
    bstring key = NULL;
    int rv = SDP_SUCCESS;

    if(sdp_id == 0 || ip_str == NULL)
    {
        log_msg(LOG_ERR, "[*] tunnel_manager_submit_client_request null or zero value submitted");
        return SDP_ERROR;
    }

    key = tm_tunnel_key_from_sdpid(sdp_id);

    // are there requests for this sdp id in the table already?
    if(pthread_mutex_lock(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex)))
    {
        log_msg(LOG_ERR, "[*] tunnel_manager_submit_client_request Mutex lock error.");
        rv = SDP_ERROR;
        goto cleanup;
    }

    if( (tunnel_rec = hash_table_get(tunnel_mgr->requested_tunnel_hash_tbl, key)) == NULL)
    {

        if((rv = 
            tunnel_record_create(
                sdp_id, 
                ip_str, 
                0, 
                NULL, 
                tunnel_mgr, 
                &tunnel_rec
            )) != SDP_SUCCESS)
        {
            log_msg(
                LOG_ERR, 
                "[*] tunnel_manager_submit_client_request() Failed to create tunnel info item"
            );
            goto cleanup;
        }

        if((rv = 
            hash_table_set(tunnel_mgr->requested_tunnel_hash_tbl, key, tunnel_rec)
            ) != SDP_SUCCESS)
        {
            rv = SDP_ERROR;
            goto cleanup;
        }

        tunnel_rec->submitted = 1;

        pthread_mutex_unlock(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex));

        hash_table_traverse(tunnel_mgr->requested_tunnel_hash_tbl, tm_traverse_print_tunnel_recs_cb, NULL);

        return SDP_SUCCESS; 
    }

    // found a request, update the ip address in case it changed
    memset(tunnel_rec->remote_public_ip, 0, MAX_IPV4_STR_LEN);
    strncpy(tunnel_rec->remote_public_ip, ip_str, MAX_IPV4_STR_LEN);

    pthread_mutex_unlock(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex));

    bstr_destroy(key);
    return SDP_SUCCESS;

cleanup:
    pthread_mutex_unlock(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex));

    if(key)
        bstr_destroy(key);
    if(tunnel_rec)
        tunnel_record_destroy(tunnel_rec);

    return rv;
}


int  tunnel_manager_submit_tunnel_record(
        tunnel_manager_t tunnel_mgr, 
        void *key_data,
        key_data_type_t data_type,
        request_or_opened_type_t which_table,
        tunnel_record_t tunnel_rec)
{
    bstring key = NULL;
    int rv = SDP_ERROR;
    hash_table_t *tbl = NULL;

    if(key_data == NULL)
    {
        log_msg(LOG_ERR, "[*] tunnel_manager_submit_tunnel_record null value key_data submitted");
        return SDP_ERROR;
    }

    if(!tunnel_rec)
    {
        log_msg(LOG_ERR, "[*] tunnel_manager_submit_tunnel_record tunnel data not provided");
        return SDP_ERROR;
    }

    //hash_table_traverse(tunnel_mgr->requested_tunnel_hash_tbl, tm_traverse_print_tunnel_recs_cb, NULL);

    if(data_type == KEY_DATA_TYPE_SDP_ID)
    {
        key = tm_tunnel_key_from_sdpid(*(uint32_t*)key_data);
    }
    else
    {
        key = bstr_from_cstr((char*)key_data);
    }

    if(which_table == REQUEST_OR_OPENED_TYPE_REQUEST)
    {
        tbl = tunnel_mgr->requested_tunnel_hash_tbl;

        // the request table has a mutex on it, unlike the open tunnel table
        if(pthread_mutex_lock(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex)))
        {
            log_msg(LOG_ERR, "[*] tunnel_manager_submit_tunnel_record Mutex lock error.");
            bstr_destroy(key);
            return SDP_ERROR;
        }
    }
    else
    {
        tbl = tunnel_mgr->open_tunnel_hash_tbl;
    }

    if( (rv = hash_table_set(tbl, key, tunnel_rec)) != SDP_SUCCESS)
    {
        if(which_table == REQUEST_OR_OPENED_TYPE_REQUEST)
            pthread_mutex_unlock(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex));

        log_msg(
            LOG_WARNING, 
            "[*] tunnel_manager_submit_tunnel_record() failed to store tunnel record for %s",
            bstr_data(key)
        );

        bstr_destroy(key);

        return SDP_ERROR;
    }

    tunnel_rec->submitted = 1;

    if(which_table == REQUEST_OR_OPENED_TYPE_REQUEST)
        pthread_mutex_unlock(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex));

    log_msg(
        LOG_WARNING, 
        "[+] tunnel_manager_submit_tunnel_record() successfully stored tunnel record for %s",
        bstr_data(key)
    );

    return SDP_SUCCESS;
}


int tunnel_manager_find_tunnel_record(
        tunnel_manager_t tunnel_mgr, 
        void *key_data,
        key_data_type_t data_type,
        request_or_opened_type_t which_table,
        tunnel_record_t *r_tunnel_rec
    )
{
    tunnel_record_t tunnel_rec = NULL;
    bstring key = NULL;
    hash_table_t *tbl = NULL;

    if(key_data == NULL)
    {
        log_msg(LOG_ERR, "[*] tunnel_manager_find_tunnel_record null value key_data submitted");
        return SDP_ERROR;
    }

    log_msg(LOG_WARNING, "entered tunnel_manager_find_tunnel_record");
    
    //hash_table_traverse(tunnel_mgr->requested_tunnel_hash_tbl, tm_traverse_print_tunnel_recs_cb, NULL);

    if(data_type == KEY_DATA_TYPE_SDP_ID)
    {
        key = tm_tunnel_key_from_sdpid(*(uint32_t*)key_data);
    }
    else
    {
        key = bstr_from_cstr((char*)key_data);
    }

    if(which_table == REQUEST_OR_OPENED_TYPE_REQUEST)
    {
        tbl = tunnel_mgr->requested_tunnel_hash_tbl;

        // the request table has a mutex on it, unlike the open tunnel table
        if(pthread_mutex_lock(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex)))
        {
            log_msg(LOG_ERR, "[*] tunnel_manager_find_tunnel_record Mutex lock error.");
            bstr_destroy(key);
            return SDP_ERROR;
        }
    }
    else
    {
        tbl = tunnel_mgr->open_tunnel_hash_tbl;
    }

    if( (tunnel_rec = hash_table_get(tbl, key)) == NULL)
    {
        if(which_table == REQUEST_OR_OPENED_TYPE_REQUEST)
            pthread_mutex_unlock(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex));

        log_msg(
            LOG_WARNING, 
            "[*] tunnel_manager_find_tunnel_record() tunnel record not found for %s",
            bstr_data(key)
        );

        bstr_destroy(key);

        return SDP_ERROR;
    }

    if(which_table == REQUEST_OR_OPENED_TYPE_REQUEST)
        pthread_mutex_unlock(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex));

    log_msg(
        LOG_WARNING, 
        "[+] tunnel_manager_find_tunnel_record() found tunnel record for %s",
        bstr_data(key)
    );

    bstr_destroy(key);

    *r_tunnel_rec = tunnel_rec;
    return SDP_SUCCESS;
}


// delete a tunnel record, removes it from all hash tables if necessary
int tunnel_manager_remove_tunnel_record(tunnel_record_t tunnel_rec)
{
    bstring requested_key = NULL;
    bstring open_key = NULL;
    int requested_rv = SDP_SUCCESS;
    int open_rv = SDP_SUCCESS;
    tunnel_manager_t tunnel_mgr = NULL;

    if(tunnel_rec == NULL)
    {
        log_msg(LOG_ERR, "tunnel_manager_remove_tunnel_record() null value tunnel_rec submitted");
        return SDP_ERROR;
    }

    if(!tunnel_rec->submitted)
    {
        log_msg(LOG_WARNING, "Destroying tunnel item supposedly not in a hash table");

        // record is not in a hash table, just destroy
        tunnel_record_destroy(tunnel_rec);
        return SDP_SUCCESS;
    }
    
    //hash_table_traverse(tunnel_mgr->requested_tunnel_hash_tbl, tm_traverse_print_tunnel_recs_cb, NULL);

    if(tunnel_rec->tunnel_mgr == NULL)
    {
        log_msg(
            LOG_ERR, 
            "tunnel_manager_remove_tunnel_record() tunnel_mgr not set, "
            "can only delete record, not remove from table"
        );
        tunnel_record_destroy(tunnel_rec);
        return SDP_ERROR;
    }

    tunnel_mgr = tunnel_rec->tunnel_mgr;

    if(tunnel_mgr->is_sdp_client)
    {
        requested_key = bstr_from_cstr(tunnel_rec->remote_public_ip);
    }
    else
    {
        requested_key = tm_tunnel_key_from_sdpid(tunnel_rec->sdp_id);
    }

    if(tunnel_rec->remote_tunnel_ip[0])
    {
        open_key = bstr_from_cstr(tunnel_rec->remote_tunnel_ip);
    }

    // the request table has a mutex on it, unlike the open tunnel table
    if(pthread_mutex_lock(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex)))
    {
        log_msg(LOG_ERR, "[*] tunnel_manager_remove_tunnel_record() Mutex lock error.");
        bstr_destroy(requested_key);
        if(open_key) bstr_destroy(open_key);
        return SDP_ERROR;
    }

    log_msg(LOG_WARNING, "Removing tunnel record from requested_tunnel_hash_tbl...");
    requested_rv = hash_table_delete(tunnel_mgr->requested_tunnel_hash_tbl, requested_key);

    if(open_key != NULL)
    {
        log_msg(LOG_WARNING, "Removing tunnel record from open_tunnel_hash_tbl as well...");
        open_rv = hash_table_delete(tunnel_mgr->open_tunnel_hash_tbl, open_key);
    }

    log_msg(
        LOG_WARNING, 
        "Removal return values - requested: %d, opened: %d", 
        requested_rv, 
        open_rv
    );

    pthread_mutex_unlock(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex));

    if( requested_rv != SDP_SUCCESS || open_rv != SDP_SUCCESS)
    {
        log_msg(
            LOG_WARNING, 
            "[*] tunnel_manager_remove_tunnel_record() tunnel record not removed for %s",
            bstr_data(requested_key)
        );

        bstr_destroy(requested_key);
        if(open_key) bstr_destroy(open_key);
        return SDP_ERROR;
    }

    log_msg(
        LOG_WARNING, 
        "[+] tunnel_manager_remove_tunnel_record() removed tunnel record for %s",
        bstr_data(requested_key)
    );

    bstr_destroy(requested_key);
    if(open_key) bstr_destroy(open_key);
    return SDP_SUCCESS;
}


int tunnel_manager_get_peer_addr_and_port(uv_tcp_t *peer, 
                                          char **ip_str, 
                                          uint32_t *ip_num, 
                                          uint32_t *port_num)
{
    int rv = 0;
    struct sockaddr_in name;
    int namelen = sizeof(name);
    char *ip_buf = NULL;

    if((ip_buf = calloc(1, MAX_IPV4_STR_LEN)) == NULL)
    {
        log_msg(LOG_ERR, "[*] Fatal memory error");
        return SDP_ERROR_MEMORY_ALLOCATION;
    }

    if(peer == NULL)
    {
        log_msg(LOG_ERR, "[*] get_peer_addr_and_port() peer handle is null");
        goto cleanup;
    }

    if((rv = uv_tcp_getpeername(peer, (struct sockaddr*) &name, &namelen)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] get_peer_addr_and_port error %s\n", uv_err_name(rv));
        goto cleanup;
    }


    if((rv = uv_inet_ntop(AF_INET, &name.sin_addr, ip_buf, MAX_IPV4_STR_LEN)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] get_peer_addr_and_port error %s\n", uv_err_name(rv));
        goto cleanup;
    }

    *ip_str = ip_buf;
    *ip_num = name.sin_addr.s_addr;
    *port_num = (uint32_t)ntohs(name.sin_port);

    return SDP_SUCCESS;

cleanup:
    if(ip_buf != NULL)
        free(ip_buf);

    return SDP_ERROR;
}


int tunnel_manager_ptr_2_array(const char* const ptr, char **r_array)
{
    int ii;
    uintptr_t ptr_address = (uintptr_t)ptr; 
    char *array = NULL;
    const int addr_len = sizeof(void*);

    if((array = calloc(1, addr_len + 1)) == NULL)
    {
        return 1;
    }

    for(ii = addr_len-1; ii >= 0; ii--)
    {
        array[ii] = ptr_address & 0xff;
        ptr_address >>= 8;
    }
    array[addr_len] = '\0';

    *r_array = array;
    return 0;
}


int tunnel_manager_array_2_ptr(const char* const array, char **r_ptr)
{
    int ii;
    uintptr_t ptr_address = 0; 
    const int addr_len = sizeof(void*);
    int shift = 0;

    for(ii = addr_len-1; ii >= 0; ii--)
    {
        shift = 8*(addr_len - 1 - ii);
        ptr_address |= ((uintptr_t)(unsigned char)array[ii] << shift);
    }

    *r_ptr = (char*)ptr_address;

    return 0;

}


// on the SDP client, json string messages are sent in full over the pipe
// on the SDP gateway, pointers to json objects are sent over the pipe
int tunnel_manager_send_to_tm(tunnel_manager_t tunnel_mgr, void *msg)
{
    //int len = strlen(TM_STOP_MSG);
    char *ptr = NULL;
    int rv = 0;

    if(!tunnel_mgr->is_sdp_client)
    {
        //stopping the gateway tm, have to send the pointer addr, not the string
        tunnel_manager_ptr_2_array((const char* const)msg, &ptr);

        rv = send(tunnel_mgr->tm_sock_fd, ptr, sizeof(void*), 0);
        free(ptr);
    }
    else
    {
        rv = send(tunnel_mgr->tm_sock_fd, (char*)msg, strnlen((char*)msg, SDP_COM_MAX_MSG_LEN), 0);
    }

    if (rv == -1) 
    {
        perror("Failed to send message to tunnel manager");
        return SDP_ERROR_FILESYSTEM_OPERATION;
    }

    return SDP_SUCCESS;
}


int tunnel_manager_make_msg(
        const char *action, 
        uint32_t sdp_id, 
        uint32_t service_id, 
        uint32_t idp_id, 
        char *id_token, 
        char *packet,
        char **r_msg)
{
    char *out_msg = NULL;
    const char *json_string;
    json_object *jout_msg = json_object_new_object();
    json_object *jdata = json_object_new_object();
    int rv = SDP_SUCCESS;
    int msg_len = 0;

    if(action == NULL)
    {  
        log_msg(LOG_ERR, "tunnel_manager_make_msg() action arg is NULL");
        rv = SDP_ERROR;
        goto cleanup;
    }

    if(jout_msg == NULL || jdata == NULL)
    {
        log_msg(LOG_ERR, "Memory allocation error");
        rv = SDP_ERROR_MEMORY_ALLOCATION;
        goto cleanup;
    }

    if(sdp_id)
    {
        json_object_object_add(jdata, sdp_key_sdp_id,     json_object_new_int((int32_t)sdp_id));
    }

    if(idp_id)
    {
        json_object_object_add(jdata, sdp_key_idp_id,     json_object_new_int((int32_t)idp_id));
    }

    if(id_token)
    {
        json_object_object_add(jdata, sdp_key_id_token,   json_object_new_string(id_token));
    }

    // TODO: eventually may need to handle more than one service id
    if(service_id)
    {
        json_object_object_add(jdata, sdp_key_service_id, json_object_new_int((int32_t)service_id));
    }

    if(packet)
    {
        json_object_object_add(jdata, sdp_key_ip_packet,   json_object_new_string(packet));
    }

    json_object_object_add(jout_msg, sdp_key_action,  json_object_new_string(action));
    json_object_object_add(jout_msg, sdp_key_data, jdata);

    // now that jdata is part of jout_msg, do not try to free, it will be freed as part of jout_msg
    jdata = NULL;

    json_string = json_object_to_json_string(jout_msg);
    if((msg_len = strnlen(
            json_string, 
            SDP_COM_MAX_MSG_LEN
        )) >= SDP_COM_MAX_MSG_LEN - SDP_COM_HEADER_LEN)
    {
        log_msg(
            LOG_ERR, 
            "tunnel_manager_make_msg() message exceeds max len %d", 
            SDP_COM_MAX_MSG_LEN - SDP_COM_HEADER_LEN
        );

        rv = SDP_ERROR_INVALID_MSG_LONG;
        goto cleanup;
    }

    if((out_msg = strndup(json_string, msg_len)) == NULL)
    {
        log_msg(LOG_ERR, "Memory allocation error");
        rv = SDP_ERROR_MEMORY_ALLOCATION;
        goto cleanup;
    }

    *r_msg = out_msg;
    rv = SDP_SUCCESS;

cleanup:
    if(jout_msg)
        json_object_put(jout_msg);
    if(jdata)
        json_object_put(jdata);
    return rv;
}


static int tm_get_message_action(json_object *json_msg, int *r_action)
{
    int rv = SDP_ERROR;
    char *action_str = NULL;
    ctrl_action_t action = INVALID_CTRL_ACTION;

    if((rv = sdp_get_json_string_field(sdp_key_action, json_msg, &action_str)) != SDP_SUCCESS)
        return rv;


    if(strncmp(action_str, sdp_action_service_request, strlen(sdp_action_service_request)) == 0)
        action = CTRL_ACTION_SERVICE_REQUEST;

    else if(strncmp(action_str, sdp_action_service_granted, strlen(sdp_action_service_granted)) == 0)
        action = CTRL_ACTION_SERVICE_GRANTED;

    else if(strncmp(action_str, sdp_action_service_denied, strlen(sdp_action_service_denied)) == 0)
        action = CTRL_ACTION_SERVICE_DENIED;

    else if(strncmp(action_str, sdp_action_authn_request, strlen(sdp_action_authn_request)) == 0)
        action = CTRL_ACTION_AUTHN_REQUEST;

    else if(strncmp(action_str, sdp_action_authn_accepted, strlen(sdp_action_authn_accepted)) == 0)
        action = CTRL_ACTION_AUTHN_ACCEPTED;

    else if(strncmp(action_str, sdp_action_authn_rejected, strlen(sdp_action_authn_rejected)) == 0)
        action = CTRL_ACTION_AUTHN_REJECTED;

    else if(strncmp(action_str, sdp_action_tunnel_traffic, strlen(sdp_action_tunnel_traffic)) == 0)
        action = CTRL_ACTION_TUNNEL_TRAFFIC;

    else if(strncmp(action_str, sdp_action_bad_message, strlen(sdp_action_bad_message)) == 0)
        action = CTRL_ACTION_BAD_MESSAGE;

    free(action_str);

    if(action == INVALID_CTRL_ACTION)
        return rv;

    *r_action = (int)action;
    return SDP_SUCCESS;

}



int tunnel_manager_process_json_msg(
        json_object *json_msg, 
        int      *r_action,
        uint32_t *r_sdp_id,
        uint32_t *r_idp_id,
        uint32_t *r_service_id,
        char    **r_id_token,
        char    **r_tunnel_ip,
        char    **r_packet)
{
    json_object *jdata = NULL;
    int      rv         = SDP_SUCCESS;
    int      action     = 0;
    uint32_t sdp_id     = 0;
    uint32_t idp_id     = 0;
    uint32_t service_id = 0;
    char    *id_token   = NULL;
    char    *tunnel_ip  = NULL;
    char    *packet     = NULL;

    if(!json_msg || json_object_get_type(json_msg) == json_type_null)
    {
        log_msg(LOG_ERR, "tunnel_manager_process_json_msg() given bad json message");
        return SDP_ERROR;
    }

    if((rv = tm_get_message_action(json_msg, &action)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "tunnel_manager_process_json_msg() failed to extract action field");
        return SDP_ERROR;
    }

    if( !json_object_object_get_ex(json_msg, sdp_key_data, &jdata))
    {
        log_msg(LOG_ERR, "tunnel_manager_process_json_msg() failed to extract data object");
        return SDP_ERROR;
    }

    if(action == CTRL_ACTION_TUNNEL_TRAFFIC)
    {
        if((rv = sdp_get_json_string_field(sdp_key_ip_packet, jdata, &packet)) != SDP_SUCCESS)
        {
            log_msg(LOG_ERR, "tunnel_manager_process_json_msg() failed to extract ip packet");
        }

        goto cleanup;
    }

    if((rv = sdp_get_json_int_field(sdp_key_sdp_id, jdata, (int*)&sdp_id)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "tunnel_manager_process_json_msg() failed to extract sdp id");
        return SDP_ERROR;        
    }

    if(action == CTRL_ACTION_AUTHN_REJECTED)
    {
        goto cleanup;
    }

    if(action == CTRL_ACTION_AUTHN_ACCEPTED)
    {
        if((rv = sdp_get_json_string_field(sdp_key_tunnel_ip, jdata, &tunnel_ip)) != SDP_SUCCESS)
        {
            log_msg(LOG_ERR, "tunnel_manager_process_json_msg() failed to extract tunnel IP");
        }

        goto cleanup;
    }

    if(action == CTRL_ACTION_AUTHN_REQUEST)
    {
        if((rv = sdp_get_json_int_field(sdp_key_idp_id, jdata, (int*)&idp_id)) != SDP_SUCCESS)
        {
            log_msg(LOG_ERR, "tunnel_manager_process_json_msg() failed to extract IdP id");
            goto cleanup;        
        }

        if((rv = sdp_get_json_string_field(sdp_key_id_token, jdata, &id_token)) != SDP_SUCCESS)
        {
            log_msg(LOG_ERR, "tunnel_manager_process_json_msg() failed to extract id token");
            goto cleanup;        
        }

        goto cleanup;
    }

    if( action == CTRL_ACTION_SERVICE_REQUEST ||
        action == CTRL_ACTION_SERVICE_GRANTED ||
        action == CTRL_ACTION_SERVICE_DENIED )
    {
        if((rv = sdp_get_json_int_field(sdp_key_service_id, jdata, (int*)&service_id)) != SDP_SUCCESS)
        {
            log_msg(LOG_ERR, "tunnel_manager_process_json_msg() failed to extract service id");
            goto cleanup;        
        }

        if(action != CTRL_ACTION_SERVICE_REQUEST)
        {
            goto cleanup;
        }

        if((rv = sdp_get_json_int_field(sdp_key_idp_id, jdata, (int*)&idp_id)) != SDP_SUCCESS)
        {
            log_msg(LOG_ERR, "tunnel_manager_process_json_msg() failed to extract IdP id");
            goto cleanup;        
        }

        if((rv = sdp_get_json_string_field(sdp_key_id_token, jdata, &id_token)) != SDP_SUCCESS)
        {
            log_msg(LOG_ERR, "tunnel_manager_process_json_msg() failed to extract id token");
            goto cleanup;        
        }

        goto cleanup;
    }


cleanup:
    if(rv != SDP_SUCCESS)
    {
        if(id_token) free(id_token);
        if(tunnel_ip) free(tunnel_ip);
        if(packet) free(packet);
        
        return rv;
    }

    *r_action       =  action;
    *r_sdp_id       =  sdp_id;
    *r_idp_id       =  idp_id;
    *r_service_id   =  service_id;    
    *r_id_token     =  id_token;  
    *r_tunnel_ip    =  tunnel_ip;
    *r_packet       =  packet;
    
    return rv;
}


int tunnel_manager_process_json_msg_string(
        char *msg,
        int *r_action,
        uint32_t *r_sdp_id,
        uint32_t *r_idp_id,
        uint32_t *r_service_id,
        char **r_id_token,
        char    **r_tunnel_ip,
        char    **r_packet)
{
    json_object *jmsg = NULL;
    int rv = SDP_SUCCESS;

    if(!msg)
    {
        log_msg(LOG_ERR, "tunnel_manager_process_json_msg_string() null message string given");
        return SDP_ERROR;
    }

    if((jmsg = json_tokener_parse(msg)) == NULL)
    {
        log_msg(LOG_ERR, "Failed to parse json string message");
        return SDP_ERROR;
    }

    rv = tunnel_manager_process_json_msg(
            jmsg, 
            r_action,
            r_sdp_id,
            r_idp_id,
            r_service_id,
            r_id_token,
            r_tunnel_ip,
            r_packet);

    json_object_put(jmsg);

    return rv;
}


