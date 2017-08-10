/*
 * tunnel_record.c
 *
 *  Created on: Aug 3, 2017
 *      Author: Daniel Bailey
 */


#include "sdp_log_msg.h"
#include "tunnel_record.h"
#include "tunnel_com.h"


static void tr_destroy_tunneled_service_info_item(tunneled_service_t item)
{
    free(item);
}


static void tr_destroy_tunneled_service_list(tunneled_service_t list)
{
    tunneled_service_t this_node = list;
    tunneled_service_t next = NULL;

    while(this_node != NULL)
    {
        next = this_node->next;
        tr_destroy_tunneled_service_info_item(this_node);
        this_node = next;
    }    
}


static int tr_create_tunneled_service_item(
        uint32_t service_id,
        uint32_t idp_id,
        char *id_token,
        short int request_sent,
        tunneled_service_t *r_new_guy)
{
    tunneled_service_t new_guy = NULL;

    if((new_guy = calloc(1, sizeof *new_guy)) == NULL)
    {
        log_msg(LOG_ERR, "Memory allocation error");
        return SDP_ERROR_MEMORY_ALLOCATION;
    }

    new_guy->service_id = service_id;
    new_guy->idp_id = idp_id;
    if(id_token)
        strncpy(new_guy->id_token, id_token, ID_TOKEN_BUF_LEN);
    new_guy->request_sent = request_sent;

    *r_new_guy = new_guy;
    return SDP_SUCCESS;
}



static int tr_add_tunneled_service_to_list(tunneled_service_t *list, tunneled_service_t new_guy)
{
    tunneled_service_t ptr = *list;
    tunneled_service_t prev = NULL;

    if(*list == NULL)
    {
        *list = new_guy;
        return SDP_SUCCESS;
    }

    if(ptr->service_id == new_guy->service_id)
    {
        log_msg(
            LOG_ERR, 
            "Attempted to add service ID %"PRIu32" to service list, but it's already there.",
            new_guy->service_id
        );

        // not really calling this an error
        free(new_guy);
        return SDP_SUCCESS;
    }

    prev = ptr;
    ptr = ptr->next;

    while(ptr != NULL)
    {
        if(ptr->service_id == new_guy->service_id)
        {
            log_msg(
                LOG_ERR, 
                "Attempted to add service ID %"PRIu32" to service list, but it's already there.",
                new_guy->service_id
            );
            
            // not really calling this an error
            free(new_guy);
            return SDP_SUCCESS;
        }

        prev = ptr;
        ptr = ptr->next;
    }

    prev->next = new_guy;
    return SDP_SUCCESS;
}


static int tr_remove_tunneled_service_from_list(tunneled_service_t *list, 
                                             uint32_t service_id, 
                                             tunneled_service_t *r_item)
{
    tunneled_service_t ptr = *list;
    tunneled_service_t prev = NULL;
    
    if(!ptr)
        return SDP_ERROR;

    if(ptr->service_id == service_id)
    {
        *list = ptr->next;
        *r_item = ptr;
        ptr->next = NULL;
        return SDP_SUCCESS;
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
            return SDP_SUCCESS;
        }
    }

    return SDP_ERROR;
}


static int tr_find_tunneled_service_in_list(tunneled_service_t *list, 
                                             uint32_t service_id, 
                                             tunneled_service_t *r_item)
{
    tunneled_service_t ptr = *list;
    
    while(ptr)
    {
        if(ptr->service_id == service_id)
        {
            *r_item = ptr;
            return SDP_SUCCESS;
        }

        ptr = ptr->next;
    }

    return SDP_ERROR;
}


int tunnel_record_add_service(
        tunnel_record_t tunnel_rec,
        uint32_t service_id,
        uint32_t idp_id,
        char *id_token,
        //request_or_opened_type_t which_list,
        short int request_sent)
{
    int rv = SDP_SUCCESS;
    tunneled_service_t new_guy = NULL;

    if(!tunnel_rec)
    {
        log_msg(LOG_ERR, "tunnel_record_add_service() tunnel not provided");
        return SDP_ERROR;
    }

    if(!service_id)
    {
        log_msg(LOG_ERR, "tunnel_record_add_service() service_id not provided");
        return SDP_ERROR;
    }

    //if(!which_list)
    //{
    //    log_msg(LOG_ERR, "tunnel_record_add_service() which list not provided");
    //    return SDP_ERROR;
    //}

    if((rv = tr_create_tunneled_service_item(
            service_id, 
            idp_id, 
            id_token, 
            request_sent, 
            &new_guy)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "tunnel_record_add_service() failed to create service item");
        return rv;
    }

    //if(which_list == REQUEST_OR_OPENED_TYPE_REQUEST)
        rv = tr_add_tunneled_service_to_list(&(tunnel_rec->services_requested), new_guy);
    //else
    //    rv = tr_add_tunneled_service_to_list(&(tunnel_rec->services_opened), new_guy);

    if(rv != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "tunnel_record_add_service() failed to add service to list");
        free(new_guy);
        return rv;
    }

    return SDP_SUCCESS;
}


int tunnel_record_mark_service_opened(
        tunnel_record_t tunnel_rec,
        uint32_t service_id)
{
    int rv = SDP_SUCCESS;
    tunneled_service_t item = NULL;

    if(!tunnel_rec)
    {
        log_msg(LOG_ERR, "tunnel_record_mark_service_opened() tunnel not provided");
        return SDP_ERROR;
    }

    if(!service_id)
    {
        log_msg(LOG_ERR, "tunnel_record_mark_service_opened() service_id not provided");
        return SDP_ERROR;
    }

    if((rv = tr_remove_tunneled_service_from_list(
        &(tunnel_rec->services_requested), service_id, &item)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "tunnel_record_mark_service_opened() service not found in request list");
        return SDP_ERROR;
    }

    if((rv = tr_add_tunneled_service_to_list(
        &(tunnel_rec->services_opened), item)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "tunnel_record_mark_service_opened() failed to add service to list");
        return SDP_ERROR;
    }

    return SDP_SUCCESS;
}


int tunnel_record_mark_service_rejected(
        tunnel_record_t tunnel_rec,
        uint32_t service_id)
{
    int rv = SDP_SUCCESS;
    tunneled_service_t item = NULL;

    if(!tunnel_rec)
    {
        log_msg(LOG_ERR, "tunnel_record_mark_service_opened() tunnel not provided");
        return SDP_ERROR;
    }

    if(!service_id)
    {
        log_msg(LOG_ERR, "tunnel_record_mark_service_opened() service_id not provided");
        return SDP_ERROR;
    }

    if((rv = tr_remove_tunneled_service_from_list(
        &(tunnel_rec->services_requested), service_id, &item)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "tunnel_record_mark_service_opened() service not found in request list");
        return SDP_ERROR;
    }

    return SDP_SUCCESS;
}


void tunnel_record_print(tunnel_record_t item)
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
        service_ptr = service_ptr->next;
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
        service_ptr = service_ptr->next;
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


int tunnel_record_create(
        uint32_t sdp_id,
        char *remote_public_ip,
        uint32_t remote_port,
        uv_tcp_t *handle,
        tunnel_manager_t tunnel_mgr,
        tunnel_record_t *item)
{
    tunnel_record_t tunnel_rec = NULL;

    if((tunnel_rec = calloc(1, sizeof *tunnel_rec)) == NULL)
    {
        log_msg(LOG_ERR, "Memory allocation error");
        return SDP_ERROR_MEMORY_ALLOCATION;
    }

    tunnel_rec->sdp_id = sdp_id;
    
    if(remote_public_ip)
        strncpy(tunnel_rec->remote_public_ip, remote_public_ip, MAX_IPV4_STR_LEN);

    tunnel_rec->remote_port = remote_port;

    tunnel_rec->handle = handle;
    tunnel_rec->tunnel_mgr = tunnel_mgr;
    tunnel_rec->created_time = time(NULL);

    *item = tunnel_rec;

    return SDP_SUCCESS;
}


void tunnel_record_destroy(tunnel_record_t item)
{
    log_msg(
        LOG_WARNING, 
        "Destroying tunnel record for %s:%"PRIu32, 
        item->remote_public_ip, 
        item->remote_port
    );

    if(item->services_requested != NULL)
        tr_destroy_tunneled_service_list(item->services_requested);

    if(item->services_opened != NULL)
        tr_destroy_tunneled_service_list(item->services_opened);

    if(item->handle != NULL)
    {
        //if(item->handle->data != NULL)
        //    item->handle->data = NULL;

        log_msg(
            LOG_WARNING, 
            "Disconnecting tunnel to %s:%"PRIu32, 
            item->remote_public_ip, 
            item->remote_port
        );
        tunnel_com_disconnect(item->handle);
    }
    else
    {
        log_msg(
            LOG_WARNING, 
            "No handle found in tunnel record to %s:%"PRIu32, 
            item->remote_public_ip, 
            item->remote_port
        );
    }

    tunnel_com_destroy_msg_q(item->outbound_q);

    free(item);
}


