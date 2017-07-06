/*
 * client_tunnel_manager.h
 *
 *  Created on: Jun 27, 2017
 *      Author: Daniel Bailey
 */

#ifndef CLIENT_TUNNEL_MANAGER_H_
#define CLIENT_TUNNEL_MANAGER_H_

#define HASH_TABLE_LEN 20

int ask_tunnel_manager_for_service(uint32_t sdp_id, char *service_ids_str, uint32_t idp_id, char *id_token);
int be_tunnel_manager(fko_cli_options_t *opts);
int try_connecting_to_tunnel_manager(int *is_running, int *tm_sock_fd);
int start_tunnel_manager(fko_cli_options_t *opts);
void stop_tunnel_manager(fko_cli_options_t *opts);
void destroy_tunnel_manager(fko_cli_options_t *opts);

#endif /* CLIENT_TUNNEL_MANAGER_H_ */
