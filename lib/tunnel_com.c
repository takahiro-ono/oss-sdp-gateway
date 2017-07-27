/*
 * tunnel_com.c
 *
 *  Created on: Jul 27, 2017
 *      Author: Daniel Bailey
 */

#include "sdp_log_msg.h"
#include "tunnel_manager.h"
#include "tunnel_com.h"
#include "sdp_errors.h"



static int tc_ssl_ctx_init(SSL_CTX **ssl_ctx)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    SSL_library_init();

    // Load cryptos, et.al.
    OpenSSL_add_all_algorithms();

    // Bring in and register error messages
    SSL_load_error_strings();

    // Create new client-method instance
    method = TLSv1_2_client_method();

    // Create new context
    ctx = SSL_CTX_new(method);
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        return SDP_ERROR_SSL;
    }

    *ssl_ctx = ctx;
    return SDP_SUCCESS;
}

static int tc_ssl_load_certs(SSL_CTX* ctx, char* cert_file, char* key_file)
{
    // set the local certificate from CertFile
    if ( SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        return SDP_ERROR_CERT;
    }
    // set the private key from KeyFile (may be the same as CertFile)
    if ( SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        return SDP_ERROR_KEY;
    }
    // verify private key
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        log_msg(LOG_ERR, "Private key does not match the public certificate");
        return SDP_ERROR_KEY;
    }

    return SDP_SUCCESS;
}


int tunnel_com_ssl_ctx_init(SSL_CTX **ssl_ctx, char* cert_file, char* key_file)
{
    int rv = SDP_SUCCESS;
    SSL_CTX *ctx = NULL;

    if((rv = tc_ssl_ctx_init(&ctx)) != SDP_SUCCESS)
        return rv;

    if((rv = tc_ssl_load_certs(ctx, cert_file, key_file)) != SDP_SUCCESS)
    {
        SSL_CTX_free(ctx);
        return rv;
    }

    *ssl_ctx = ctx;
    return SDP_SUCCESS;
}