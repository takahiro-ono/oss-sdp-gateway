/*
 * control_client.h
 *
 *  Created on: Jun 29, 2017
 *      Author: Daniel Bailey
 */

#ifndef CONTROL_CLIENT_H_
#define CONTROL_CLIENT_H_

#include "fwknop_common.h"

int get_updated_credentials_from_controller(fko_cli_options_t *opts);
int start_control_client(fko_cli_options_t *opts);
void stop_control_client(fko_cli_options_t *opts);
void destroy_control_client(fko_cli_options_t *opts);

#endif /* CONTROL_CLIENT_H_ */
