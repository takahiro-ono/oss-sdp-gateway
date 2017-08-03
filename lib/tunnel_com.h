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
#include "tunnel_common.h"


void tunnel_com_ssl_info_callback(const SSL* ssl, int where, int ret);
int  tunnel_com_ssl_verify_callback(int ok, X509_STORE_CTX* store);
void tunnel_com_destroy_msg_q(outbound_msg_t q);
int  tunnel_com_ssl_ctx_init(SSL_CTX **ssl_ctx, char* cert_file, char* key_file);
void tunnel_com_handle_event(tunnel_record_t tunnel_rec);
void tunnel_com_read_cb(uv_stream_t* handle, ssize_t nread, const uv_buf_t *buf);
void tunnel_com_disconnect(uv_tcp_t *handle);
void tunnel_com_alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
int  tunnel_com_send_msg(tunnel_record_t tunnel_rec, char *msg);
int  tunnel_com_finalize_connection(tunnel_record_t tunnel_rec, int is_client);

#endif /* TUNNEL_COM_H_ */
