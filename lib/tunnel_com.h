/*
 * tunnel_com.h
 *
 *  Created on: Jul 27, 2017
 *      Author: Daniel Bailey
 */

#ifndef TUNNEL_COM_H_
#define TUNNEL_COM_H_

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>


int tunnel_com_ssl_ctx_init(SSL_CTX **ssl_ctx, char* cert_file, char* key_file);

#endif /* TUNNEL_COM_H_ */
