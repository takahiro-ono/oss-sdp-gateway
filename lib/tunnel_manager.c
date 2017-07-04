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
#include "sdp_ctrl_client.h"

const char *TM_STOP_MSG = "STOP_TM";

static void print_tunnel_info_item(tunnel_info_t item)
{
    char req_services[100] = {0};
    char opened_services[100] = {0};
    tunneled_service_t service_ptr = item->services_requested;
    int offset = 0;
    int comma = 0;
    int remainder = 100;

    while(service_ptr && remainder)
    {
        if(comma)
            snprintf(req_services + offset, remainder, ", %"PRIu32, service_ptr->service_id);
        else
        {
            snprintf(req_services + offset, remainder, "%"PRIu32, service_ptr->service_id);
            comma = 1;
        }

        offset = strlen(req_services);
        remainder = 100 - offset;
    }

    service_ptr = item->services_opened;
    offset = 0;
    comma = 0;
    remainder = 100;

    while(service_ptr && remainder)
    {
        if(comma)
            snprintf(opened_services + offset, remainder, ", %"PRIu32, service_ptr->service_id);
        else
        {
            snprintf(opened_services + offset, remainder, "%"PRIu32, service_ptr->service_id);
            comma = 1;
        }

        offset = strlen(opened_services);
        remainder = 100 - offset;
    }

    log_msg(LOG_WARNING,
            "\n"
            "            SDP ID:  %"PRIu32"\n"
            "  remote public ip:  %s\n"
            "  remote tunnel ip:  %s\n"
            "       remote port:  %"PRIu32"\n"
            "requested services:  %s\n"
            "   opened services:  %s\n"
            "              next:  %p\n\n",
            item->sdp_id,
            item->remote_public_ip,
            item->remote_tunnel_ip,
            item->remote_port,
            req_services,
            opened_services,
            item->next );
}


static void print_tunnel_info_list(tunnel_info_t item)
{
    while(item != NULL)
    {
        print_tunnel_info_item(item);
        item = item->next;
    }

    log_msg(LOG_WARNING, "\n");
}


static int traverse_print_tunnel_items_cb(hash_table_node_t *node, void *arg)
{
    print_tunnel_info_list((tunnel_info_t)(node->data));

    return FKO_SUCCESS;
}



static void destroy_tunneled_service_info_item(tunneled_service_t item)
{
    free(item);
}


static void destroy_tunneled_service_list(tunneled_service_t list)
{
    tunneled_service_t this_node = list;
    tunneled_service_t next = NULL;

    while(this_node != NULL)
    {
        next = this_node->next;
        destroy_tunneled_service_info_item(this_node);
        this_node = next;
    }    
}

static void destroy_tunnel_info_item(tunnel_info_t item)
{
    log_msg(LOG_WARNING, "Destroying tunnel info item for SDP ID %"PRIu32, item->sdp_id);

    if(item->services_requested != NULL)
        destroy_tunneled_service_list(item->services_requested);

    if(item->services_opened != NULL)
        destroy_tunneled_service_list(item->services_opened);

    if(item->handle != NULL)
    {
        if(item->handle->data != NULL)
            item->handle->data = NULL;

        log_msg(LOG_WARNING, "Closing handle in tunnel info item for SDP ID %"PRIu32, item->sdp_id);
        uv_close((uv_handle_t*)item->handle, tunnel_manager_close_client_cb);
    }
    else
    {
        log_msg(LOG_WARNING, "No handle found in tunnel info item for SDP ID %"PRIu32, item->sdp_id);
    }

    free(item);
}


static void destroy_tunnel_info_list(tunnel_info_t list)
{
    tunnel_info_t this_node = list;
    tunnel_info_t next = NULL;

    while(this_node != NULL)
    {
        next = this_node->next;
        destroy_tunnel_info_item(this_node);
        this_node = next;
    }
}


static void destroy_tunnel_hash_node_cb(hash_table_node_t *node)
{
    log_msg(LOG_WARNING, "Found a tunnel info hash table node to destroy.");
    if(node->key != NULL) bstr_destroy((bstring)(node->key));
    if(node->data != NULL)
    {
        // this function takes care of all tunnel info nodes (NOT hash table nodes)
        // for this SDP ID, including the very first one
        destroy_tunnel_info_list((tunnel_info_t)(node->data));
    }
}

static void remove_sock(tunnel_manager_t tunnel_mgr) 
{
    uv_fs_t req;
    uv_fs_unlink(tunnel_mgr->loop, &req, tunnel_mgr->pipe_name, NULL);
}


static void pipe_close_cb(uv_handle_t* handle)
{
    free(handle);
}

void free_write_req(uv_write_t *req) 
{
    write_req_t *wr = (write_req_t*) req;
    free(wr->buf.base);
    free(wr);
}

void echo_write(uv_write_t *req, int status) 
{
    if (status < 0) 
    {
        log_msg(LOG_ERR, "uv_write error %s\n", uv_err_name(status));
    }

    free_write_req(req);
}

static void process_msg_from_ctrl(json_object *msg)
{
    return;
}


void gateway_pipe_read_cb(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) 
{
    json_object *msg = NULL;
    char *reply_str = NULL; 
    char *ptr = NULL;

    if (nread > 0) 
    {
        if(nread != sizeof msg)
        {
            log_msg(LOG_ERR, "Tunnel manager received non-pointer message on pipe.");
        }
        else
        {
            if(tunnel_manager_array_2_ptr((const char const*)buf->base, (char**)&msg))
            {
                log_msg(LOG_ERR, "Failed to convert received buffer to a pointer address");
                free(buf->base);
                uv_stop(client->loop);       
            }

            free(buf->base);

            //is the pointer value pointing to the stop message
            if((char*)msg == TM_STOP_MSG)
            {
                log_msg(LOG_WARNING, "Tunnel manager received stop message from pipe");
                uv_stop(client->loop);
                return;
            }

            log_msg(LOG_WARNING, "Tunnel manager received ctrl message from pipe");
            process_msg_from_ctrl(msg);

            //TODO: Get rid of this. Only for a one-time trial
            log_msg(LOG_WARNING, "Tunnel manager received pipe message: %s", (char*)msg);
            free((char*)msg);
            msg = NULL;
            
            // try to free the msg object
            if(msg != NULL && json_object_get_type(msg) != json_type_null) 
                json_object_put(msg);

            // send a reply for fun
            reply_str = calloc(1, 40);
            snprintf(reply_str, 40, "WHAT'S UP GATEWAY MAIN!");
            tunnel_manager_ptr_2_array((const char* const)reply_str, &ptr);
            write_req_t *req = calloc(1, sizeof *req);
            req->buf = uv_buf_init(ptr, sizeof ptr);
            uv_write((uv_write_t*) req, client, &req->buf, 1, echo_write);

            return;
        }

    }

    if (nread < 0) 
    {
        if (nread != UV_EOF)
            log_msg(LOG_ERR, "uv read error %s\n", uv_err_name(nread));
        else
            log_msg(LOG_WARNING, "ctrl client closed pipe to tunnel manager");
        uv_close((uv_handle_t*) client, NULL);
    }

    free(buf->base);
}


static int stop_msg_received(const uv_buf_t *buf)
{
    if(strncmp(buf->base, TM_STOP_MSG, strlen(TM_STOP_MSG)) == 0)
    {
        return 1;
    }

    return 0;
}


void client_pipe_read_cb(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) 
{
    if (nread > 0) 
    {
        if(stop_msg_received(buf))
        {
            log_msg(LOG_WARNING, "Tunnel manager received stop message from pipe");
            free(buf->base);
            uv_stop(client->loop);
            return;
        }

        log_msg(LOG_WARNING, "Tunnel manager received pipe message: %s", buf->base);
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
    int rv = FKO_SUCCESS;
    uv_pipe_t *client = NULL;
    tunnel_manager_t tunnel_mgr = (tunnel_manager_t)server->data;
    uv_read_cb read_cb;

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

    read_cb = (tunnel_mgr->is_sdp_client ? client_pipe_read_cb : gateway_pipe_read_cb);

    if((client = calloc(1, sizeof *client)) == NULL)
    {
        log_msg(LOG_ERR, "[*] Fatal memory error");
        uv_stop(server->loop);
        return;        
    }

    if((rv = uv_pipe_init(server->loop, client, 0)))
    {
        log_msg(LOG_ERR, "uv_pipe_init error: %s", uv_err_name(rv));
        uv_close((uv_handle_t*) client, pipe_close_cb);
    }

    if (uv_accept(server, (uv_stream_t*) client) == 0) 
    {
        log_msg(LOG_WARNING, "[*] Tunnel Manager received pipe connection");
        tunnel_mgr->tm_pipe_client = client;
        uv_read_start((uv_stream_t*) client, tunnel_manager_alloc_buffer, read_cb);
    }
    else 
    {
        uv_close((uv_handle_t*) client, pipe_close_cb);
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
        if(tunnel_mgr->tm_pipe_client != NULL)
        {
            uv_close((uv_handle_t*)tunnel_mgr->tm_pipe_client, pipe_close_cb);
        }

        remove_sock(tunnel_mgr);

        if(tunnel_mgr->tm_pipe != NULL)
        {
            uv_close((uv_handle_t*)tunnel_mgr->tm_pipe, pipe_close_cb);
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

    free(tunnel_mgr);
}


int tunnel_manager_new(int is_sdp_client, int tbl_len, tunnel_manager_t *r_tunnel_mgr)
{
    int rv = FKO_SUCCESS;
    tunnel_manager_t tunnel_mgr = NULL;
    uv_pipe_t *tm_pipe = NULL;

    // allocate memory
    if((tunnel_mgr = calloc(1, sizeof *tunnel_mgr)) == NULL)
        return (FKO_ERROR_MEMORY_ALLOCATION);

    tunnel_mgr->is_sdp_client = is_sdp_client;
    tunnel_mgr->pipe_name = (is_sdp_client ? NAME_TM_CLIENT_PIPE : NAME_TM_GATEWAY_PIPE);
    log_msg(LOG_WARNING, "Tunnel Manager pipe name set to %s", tunnel_mgr->pipe_name);

    tunnel_mgr->loop = uv_default_loop();
    
    if((tm_pipe = calloc(1, sizeof *tm_pipe)) == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error creating uv_pipe_t tm_pipe"
        );
        tunnel_manager_destroy(tunnel_mgr);
        return FKO_ERROR_MEMORY_ALLOCATION;
    }

    if((rv = uv_pipe_init(tunnel_mgr->loop, tm_pipe, 0)))
    {
        log_msg(LOG_ERR, "[*] uv_pipe_init error %s\n", uv_err_name(rv));
        free(tm_pipe);
        tunnel_manager_destroy(tunnel_mgr);
        return FKO_ERROR_FILESYSTEM_OPERATION;
    }

    tunnel_mgr->tm_pipe = tm_pipe;
    tm_pipe->data = tunnel_mgr;
    remove_sock(tunnel_mgr);


    if((rv = uv_pipe_bind(tunnel_mgr->tm_pipe, tunnel_mgr->pipe_name))) 
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


    tunnel_mgr->open_tunnel_hash_tbl = hash_table_create(tbl_len,
        NULL, NULL, destroy_tunnel_hash_node_cb);

    if(tunnel_mgr->open_tunnel_hash_tbl == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error creating tunnel tracking hash table"
        );
        tunnel_manager_destroy(tunnel_mgr);
        return FKO_ERROR_MEMORY_ALLOCATION;
    }

    tunnel_mgr->requested_tunnel_hash_tbl = hash_table_create(tbl_len,
        NULL, NULL, destroy_tunnel_hash_node_cb);

    if(tunnel_mgr->requested_tunnel_hash_tbl == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error creating waiting tunnel tracking hash table"
        );
        tunnel_manager_destroy(tunnel_mgr);
        return FKO_ERROR_MEMORY_ALLOCATION;
    }

    pthread_mutex_init(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex), NULL);

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
    char *msg_for_gate_tm = NULL;
    char *ptr = NULL;


    
    // if this is an SDP client (not gateway), this pipe is IPC capable
    if ((tunnel_mgr->tm_sock_fd = socket(AF_UNIX, SOCK_STREAM, tunnel_mgr->is_sdp_client)) == -1) 
    {
        perror("socket");
        return FKO_ERROR_FILESYSTEM_OPERATION;
    }

    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, tunnel_mgr->pipe_name);
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);
    
    if (connect(tunnel_mgr->tm_sock_fd, (struct sockaddr *)&remote, len) < 0) 
    {
        perror("connect");
        return FKO_ERROR_FILESYSTEM_OPERATION;
    }

    log_msg(LOG_ALERT, "Connected to tunnel manager's pipe");

    if(tunnel_mgr->is_sdp_client)
    {

        if (send(tunnel_mgr->tm_sock_fd, str, strlen(str), 0) == -1) 
        {
            perror("Main pipe send");
            return FKO_ERROR_FILESYSTEM_OPERATION;
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
            return FKO_ERROR_FILESYSTEM_OPERATION;
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
            return FKO_ERROR_FILESYSTEM_OPERATION;
        }

        if ((bytes_rcvd = recv(tunnel_mgr->tm_sock_fd, buf, 100, 0)) > 0) 
        {
            if(bytes_rcvd != sizeof(void*))
            {
                log_msg(LOG_ALERT, "Message received from Tunnel Manager is not a pointer");
                return FKO_ERROR_FILESYSTEM_OPERATION;
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
            return FKO_ERROR_FILESYSTEM_OPERATION;
        }

    }

    return FKO_SUCCESS;
}


int tunnel_manager_send_stop(tunnel_manager_t tunnel_mgr)
{
    int len = strlen(TM_STOP_MSG);
    char *ptr = NULL;
    int rv = 0;

    if(!tunnel_mgr->is_sdp_client)
    {
        //stopping the gateway tm, have to send the pointer addr, not the string
        tunnel_manager_ptr_2_array((const char* const)TM_STOP_MSG, &ptr);

        len = sizeof ptr;

        rv = send(tunnel_mgr->tm_sock_fd, ptr, len, 0);
        free(ptr);
    }
    else
    {
        rv = send(tunnel_mgr->tm_sock_fd, TM_STOP_MSG, len, 0);
    }

    if (rv == -1) 
    {
        perror("Failed to send stop message to tunnel manager");
        return FKO_ERROR_FILESYSTEM_OPERATION;
    }

    return FKO_SUCCESS;
}


static int create_tunneled_service_item(uint32_t service_id,
                                        uint32_t idp_id,
                                        char *id_token,
                                        tunneled_service_t *r_new_guy)
{
    tunneled_service_t new_guy = NULL;

    if((new_guy = calloc(1, sizeof *new_guy)) == NULL)
    {
        log_msg(LOG_ERR, "Memory allocation error");
        return FKO_ERROR_MEMORY_ALLOCATION;
    }

    new_guy->service_id = service_id;
    new_guy->idp_id = idp_id;
    if(id_token)
        strncpy(new_guy->id_token, id_token, ID_TOKEN_BUF_LEN);

    *r_new_guy = new_guy;
    return FKO_SUCCESS;
}



static int add_tunneled_service_to_list(tunneled_service_t *list, tunneled_service_t new_guy)
{
    tunneled_service_t ptr = *list;

    if(*list == NULL)
    {
        *list = new_guy;
        return FKO_SUCCESS;
    }

    while(ptr->next != NULL)
        ptr = ptr->next;

    ptr->next = new_guy;
    return FKO_SUCCESS;
}


static int remove_tunneled_service_from_list(tunneled_service_t *list, 
                                             uint32_t service_id, 
                                             tunneled_service_t *r_item)
{
    tunneled_service_t ptr = *list;
    tunneled_service_t prev = NULL;
    
    if(!ptr)
        return FKO_ERROR_UNKNOWN;

    if(ptr->service_id == service_id)
    {
        *list = ptr->next;
        *r_item = ptr;
        ptr->next = NULL;
        return FKO_SUCCESS;
    }

    while(ptr->next)
    {
        prev = ptr;
        ptr = ptr->next;

        if(ptr->service_id == service_id)
        {
            prev->next = ptr->next;
            *r_item = ptr;
            ptr->next = NULL;
            return FKO_SUCCESS;
        }
    }

    return FKO_ERROR_UNKNOWN;
}


static int find_tunneled_service_in_list(tunneled_service_t *list, 
                                             uint32_t service_id, 
                                             tunneled_service_t *r_item)
{
    tunneled_service_t ptr = *list;
    
    while(ptr)
    {
        if(ptr->service_id == service_id)
        {
            *r_item = ptr;
            return FKO_SUCCESS;
        }

        ptr = ptr->next;
    }

    return FKO_ERROR_UNKNOWN;
}


static int create_tunnel_info_item(uint32_t sdp_id,
                                  tunneled_service_t services_requested,
                                  tunneled_service_t services_opened,
                                  char *remote_public_ip,
                                  char *remote_tunnel_ip,
                                  uint32_t remote_port,
                                  uint32_t idp_id,
                                  char *id_token,
                                  uv_tcp_t *handle,
                                  hash_table_t *containing_tbl,
                                  tunnel_info_t *item)
{
    tunnel_info_t tunnel_data = NULL;

    if((tunnel_data = calloc(1, sizeof *tunnel_data)) == NULL)
    {
        log_msg(LOG_ERR, "Memory allocation error");
        return FKO_ERROR_MEMORY_ALLOCATION;
    }

    tunnel_data->sdp_id = sdp_id;
    tunnel_data->services_requested = services_requested;
    tunnel_data->services_opened = services_opened;
    
    if(remote_public_ip)
        strncpy(tunnel_data->remote_public_ip, remote_public_ip, MAX_IPV4_STR_LEN);

    if(remote_tunnel_ip)
        strncpy(tunnel_data->remote_tunnel_ip, remote_tunnel_ip, MAX_IPV4_STR_LEN);

    tunnel_data->remote_port = remote_port;
    tunnel_data->idp_id = idp_id;

    if(id_token)
        strncpy(tunnel_data->id_token, id_token, ID_TOKEN_BUF_LEN);

    tunnel_data->handle = handle;
    tunnel_data->containing_tbl = containing_tbl;
    tunnel_data->created_time = time(NULL);

    *item = tunnel_data;

    return FKO_SUCCESS;
}

static bstring tunnel_key_from_sdpid(uint32_t sdp_id)
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
    tunnel_info_t tunnel_data = NULL;
    bstring key = NULL;
    int rv = FKO_SUCCESS;

    if(sdp_id == 0 || ip_str == NULL)
    {
        log_msg(LOG_ERR, "[*] tunnel_manager_submit_client_request null or zero value submitted");
        return FKO_ERROR_UNKNOWN;
    }

    key = tunnel_key_from_sdpid(sdp_id);

    // are there requests for this sdp id in the table already?
    if(pthread_mutex_lock(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex)))
    {
        log_msg(LOG_ERR, "[*] tunnel_manager_submit_client_request Mutex lock error.");
        rv = FKO_ERROR_UNKNOWN;
        goto cleanup;
    }

    if( (tunnel_data = hash_table_get(tunnel_mgr->requested_tunnel_hash_tbl, key)) == NULL)
    {

        if((rv = 
            create_tunnel_info_item(
                sdp_id, 
                NULL, 
                NULL, 
                ip_str, 
                NULL, 
                0, 
                0,
                NULL,
                NULL, 
                tunnel_mgr->requested_tunnel_hash_tbl, 
                &tunnel_data
            )) != FKO_SUCCESS)
        {
            log_msg(
                LOG_ERR, 
                "[*] tunnel_manager_submit_client_request() Failed to create tunnel info item"
            );
            goto cleanup;
        }

        if((rv = 
            hash_table_set(tunnel_mgr->requested_tunnel_hash_tbl, key, tunnel_data)
            ) != FKO_SUCCESS)
        {
            rv = FKO_ERROR_UNKNOWN;
            goto cleanup;
        }

        pthread_mutex_unlock(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex));

        hash_table_traverse(tunnel_mgr->requested_tunnel_hash_tbl, traverse_print_tunnel_items_cb, NULL);

        return FKO_SUCCESS; 
    }

    // found a request, update the ip address in case it changed
    memset(tunnel_data->remote_public_ip, 0, MAX_IPV4_STR_LEN);
    strncpy(tunnel_data->remote_public_ip, ip_str, MAX_IPV4_STR_LEN);

    pthread_mutex_unlock(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex));

    bstr_destroy(key);
    return FKO_SUCCESS;

cleanup:
    pthread_mutex_unlock(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex));

    if(key)
        bstr_destroy(key);
    if(tunnel_data)
        destroy_tunnel_info_item(tunnel_data);

    return rv;
}


int tunnel_manager_find_client_request(
        tunnel_manager_t tunnel_mgr, 
        uint32_t sdp_id, 
        tunnel_info_t *r_tunnel_data
    )
{
    tunnel_info_t tunnel_data = NULL;
    bstring key = NULL;
    int rv = FKO_SUCCESS;

    if(sdp_id == 0)
    {
        log_msg(LOG_ERR, "[*] tunnel_manager_find_client_request zero value sdp id submitted");
        return FKO_ERROR_UNKNOWN;
    }

    log_msg(LOG_WARNING, "\nentered tunnel_manager_find_client_request");
    hash_table_traverse(tunnel_mgr->requested_tunnel_hash_tbl, traverse_print_tunnel_items_cb, NULL);

    key = tunnel_key_from_sdpid(sdp_id);

    // are there requests for this sdp id in the table ?
    if(pthread_mutex_lock(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex)))
    {
        log_msg(LOG_ERR, "[*] tunnel_manager_find_client_request Mutex lock error.");
        rv = FKO_ERROR_UNKNOWN;
        goto cleanup;
    }

    if( (tunnel_data = hash_table_get(tunnel_mgr->requested_tunnel_hash_tbl, key)) == NULL)
    {
        log_msg(
            LOG_WARNING, 
            "[*] tunnel_manager_find_client_request client request not found for sdp id %"PRIu32,
            sdp_id
        );

        rv = FKO_ERROR_UNKNOWN;
        goto cleanup;
    }

    log_msg(
        LOG_WARNING, 
        "[+] tunnel_manager_find_client_request found client request for sdp id %"PRIu32,
        sdp_id
    );

    *r_tunnel_data = tunnel_data;

cleanup:
    pthread_mutex_unlock(&(tunnel_mgr->requested_tunnel_hash_tbl_mutex));
    bstr_destroy(key);
    return rv;
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
        return FKO_ERROR_MEMORY_ALLOCATION;
    }

    if(peer == NULL)
    {
        log_msg(LOG_ERR, "[*] get_peer_addr_and_port() peer handle is null");
        goto cleanup;
    }

    if((rv = uv_tcp_getpeername(peer, (struct sockaddr*) &name, &namelen)) != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] get_peer_addr_and_port error %s\n", uv_err_name(rv));
        goto cleanup;
    }


    if((rv = uv_inet_ntop(AF_INET, &name.sin_addr, ip_buf, MAX_IPV4_STR_LEN)) != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] get_peer_addr_and_port error %s\n", uv_err_name(rv));
        goto cleanup;
    }

    *ip_str = ip_buf;
    *ip_num = name.sin_addr.s_addr;
    *port_num = (uint32_t)ntohs(name.sin_port);

    return FKO_SUCCESS;

cleanup:
    if(ip_buf != NULL)
        free(ip_buf);

    return FKO_ERROR_UNKNOWN;
}

// Close client
void tunnel_manager_close_client_cb(uv_handle_t *handle) 
{
    tunnel_info_t tunnel_data = handle->data;
    bstring key = NULL;

    // Free client handle after connection has been closed
    free(handle);
    log_msg(LOG_WARNING, "Freed a tcp client handle");

    if(tunnel_data)
    {
        // don't try to close the handle again
        // when the hash table node gets destroyed below
        tunnel_data->handle = NULL;

        // 'data' points to the hash table tunnel_info_t entry
        // need to remove it from the hash table
        key = tunnel_key_from_sdpid(tunnel_data->sdp_id);
        if(hash_table_delete(tunnel_data->containing_tbl, key))
        {
            log_msg(
                LOG_WARNING, 
                "[*] WARNING: tunnel_manager_close_client_cb "
                "didn't find sdp id %d in hash table to delete",
                tunnel_data->sdp_id
            );

            // so destroy it now instead
            destroy_tunnel_info_item(tunnel_data);
        }
        else
        {
            log_msg(LOG_WARNING, "Just removed the tunnel info node tied to the tcp client handle");
        }

        bstr_destroy(key);
    }
    else
    {
        log_msg(LOG_WARNING, "No tunnel info tied to the tcp client handle");
    }

}


void tunnel_manager_alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) 
{
  buf->base = calloc(1, suggested_size);
  buf->len = suggested_size;
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

        rv = send(tunnel_mgr->tm_sock_fd, ptr, sizeof ptr, 0);
        free(ptr);
    }
    else
    {
        rv = send(tunnel_mgr->tm_sock_fd, (char*)msg, strnlen((char*)msg, MAX_PIPE_MSG_LEN), 0);
    }

    if (rv == -1) 
    {
        perror("Failed to send message to tunnel manager");
        return FKO_ERROR_FILESYSTEM_OPERATION;
    }

    return FKO_SUCCESS;
}
