/*
 * tunnel_record.h
 *
 *  Created on: Aug 3, 2017
 *      Author: Daniel Bailey
 */

#ifndef TUNNEL_RECORD_H_
#define TUNNEL_RECORD_H_

#include "tunnel_common.h"


int tunnel_record_add_service(
        tunnel_record_t tunnel_rec,
        uint32_t service_id,
        uint32_t idp_id,
        char *id_token,
        //request_or_opened_type_t which_list,
        short int request_sent);

int tunnel_record_mark_service_opened(
        tunnel_record_t tunnel_rec,
        uint32_t service_id);

int tunnel_record_mark_service_rejected(
        tunnel_record_t tunnel_rec,
        uint32_t service_id);


void tunnel_record_print(tunnel_record_t item);

int tunnel_record_create(
        uint32_t sdp_id,
        char *remote_public_ip,
        uint32_t remote_port,
        uv_tcp_t *handle,
        tunnel_manager_t tunnel_mgr,
        tunnel_record_t *item);

void tunnel_record_destroy(tunnel_record_t item);


#endif
