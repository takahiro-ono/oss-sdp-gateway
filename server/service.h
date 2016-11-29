/*
 * service.h
 *
 *  Created on: Nov 26, 2016
 *      Author: Daniel Bailey
 */

#ifndef SERVICE_H_
#define SERVICE_H_

#define PROTO_TCP   6
#define PROTO_UDP   17

int create_service_table(fko_srv_options_t *opts);
void destroy_service_table(fko_srv_options_t *opts);
int process_service_msg(fko_srv_options_t *opts, int action, json_object *jdata);
service_data_t* get_service_data(fko_srv_options_t *opts, uint32_t service_id);
void dump_service_list(fko_srv_options_t *opts);

#endif /* SERVICE_H_ */
