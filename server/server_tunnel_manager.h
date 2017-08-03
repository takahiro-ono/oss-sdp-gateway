/*
 * server_tunnel_manager.h
 *
 *  Created on: Jun 27, 2017
 *      Author: Daniel Bailey
 */

#ifndef SERVER_TUNNEL_MANAGER_H_
#define SERVER_TUNNEL_MANAGER_H_

#include "tunnel_manager.h"

extern const char* TM_STOP_MSG;

void gateway_handle_tunnel_msg(tunnel_record_t tunnel_rec, char *msg);
int start_tunnel_manager(fko_srv_options_t *opts);
void stop_tunnel_manager(fko_srv_options_t *opts);
void destroy_tunnel_manager(fko_srv_options_t *opts);

#endif /* SERVER_TUNNEL_MANAGER_H_ */
