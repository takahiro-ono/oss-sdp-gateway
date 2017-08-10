/*
 * tunnel_com.c
 *
 *  Created on: Jul 27, 2017
 *      Author: Daniel Bailey
 */

#include <unistd.h>
#include "sdp_log_msg.h"
#include "tunnel_manager.h"
#include "tunnel_com.h"
#include "sdp_errors.h"
#include "common.h"



#define WHERE_INFO(ssl, w, flag, msg) { \
    if(w & flag) { \
        log_msg( \
            LOG_WARNING, \
            "%s - %s - %s", \
            msg, \
            SSL_state_string(ssl), \
            SSL_state_string_long(ssl)); \
    }\
} 

// INFO CALLBACK
void tunnel_com_ssl_info_callback(const SSL* ssl, int where, int ret) 
{
    if(ret == 0) 
    {
        printf("tunnel_com_ssl_info_callback, error occured.\n");
        return;
    }
    WHERE_INFO(ssl, where, SSL_CB_LOOP, "LOOP");
    WHERE_INFO(ssl, where, SSL_CB_EXIT, "EXIT");
    WHERE_INFO(ssl, where, SSL_CB_READ, "READ");
    WHERE_INFO(ssl, where, SSL_CB_WRITE, "WRITE");
    WHERE_INFO(ssl, where, SSL_CB_ALERT, "ALERT");
    WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE");
}


int tunnel_com_ssl_verify_callback(int ok, X509_STORE_CTX* store) 
{
    char buf[256];
    X509* err_cert;
    err_cert = X509_STORE_CTX_get_current_cert(store);
    int err = X509_STORE_CTX_get_error(store);
    int depth = X509_STORE_CTX_get_error_depth(store);
    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

    BIO* outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
    X509_NAME* cert_name = X509_get_subject_name(err_cert);
    X509_NAME_print_ex(outbio, cert_name, 0, XN_FLAG_MULTILINE);
    BIO_free_all(outbio);
    log_msg(
        LOG_WARNING, 
        "ssl_verify_callback(), ok: %d, error: %d, depth: %d, name: %s\n", 
        ok, 
        err, 
        depth, 
        buf
    );

    return 1;  // We always return 1, so no verification actually
}


static int tc_new_msg_q_obj(char *msg, outbound_msg_t *r_new_guy)
{
    sdp_header hdr_obj;
    uint32_t msg_len = strnlen(msg, SDP_COM_MAX_MSG_LEN - SDP_COM_HEADER_LEN);
    outbound_msg_t new_guy = NULL;
    char *msg_buf = NULL;

    if(!msg || msg_len < 1)
    {
        log_msg(
            LOG_ERR, 
            "tc_new_msg_q_obj() msg is null or too short"
        );
        return SDP_ERROR_INVALID_MSG_LONG;
    }

    if(msg_len >= SDP_COM_MAX_MSG_LEN - SDP_COM_HEADER_LEN)
    {
        log_msg(
            LOG_ERR, 
            "tc_new_msg_q_obj() msg len %"PRIu32" is greater than max len %d",
            msg_len,
            SDP_COM_MAX_MSG_LEN - SDP_COM_HEADER_LEN
        );
        return SDP_ERROR_INVALID_MSG_LONG;
    }

    if((new_guy = calloc(1, sizeof *new_guy)) == NULL)
    {
        log_msg(LOG_ERR, "Memory allocation error");
        return SDP_ERROR_MEMORY_ALLOCATION;
    }

    if((msg_buf = calloc(1, msg_len + SDP_COM_HEADER_LEN)) == NULL)
    {
        log_msg(LOG_ERR, "Memory allocation error");
        free(new_guy);
        return SDP_ERROR_MEMORY_ALLOCATION;
    }


    hdr_obj.length = (uint32_t)htonl(msg_len);
    memcpy(msg_buf, (char*)&hdr_obj, SDP_COM_HEADER_LEN);
    memcpy(msg_buf + SDP_COM_HEADER_LEN, msg, msg_len);
    free(msg);
    new_guy->msg = msg_buf;
    new_guy->length = msg_len + SDP_COM_HEADER_LEN;
    *r_new_guy = new_guy;
    return SDP_SUCCESS;
}

static void tc_destroy_msg_q_obj(outbound_msg_t obj)
{
    if(obj)
    {
        if(obj->msg)
            free(obj->msg);
        free(obj);
    }
}

void tunnel_com_destroy_msg_q(outbound_msg_t q)
{
    outbound_msg_t next = NULL; 

    while(q)
    {
        next = q->next;
        tc_destroy_msg_q_obj(q);
        q = next;
    }
}

static int tc_add_to_msg_q(outbound_msg_t *q, char *msg)
{
    outbound_msg_t ptr = NULL;
    outbound_msg_t new_guy = NULL;
    int rv = SDP_SUCCESS;

    if((rv = tc_new_msg_q_obj(msg, &new_guy)) != SDP_SUCCESS)
    {
        return rv;
    }

    if(!*q)
    {
        *q = new_guy;
        return SDP_SUCCESS;
    }

    ptr = *q;
    while(ptr->next)
        ptr = ptr->next;

    ptr->next = new_guy;
    return SDP_SUCCESS;
}

static int tc_pop_first_q_msg(outbound_msg_t *q, char **msg, int *len)
{
    outbound_msg_t ptr = *q;

    if(ptr)
    {
        *msg = ptr->msg;
        ptr->msg = NULL;
        *len = ptr->length;
        *q = ptr->next;
        tc_destroy_msg_q_obj(ptr);
        return SDP_SUCCESS;
    }

    return SDP_ERROR;
}

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
    method = TLSv1_2_method();

    // Create new context
    ctx = SSL_CTX_new(method);
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        return SDP_ERROR_SSL;
    }

    SSL_CTX_set_info_callback(ctx, tunnel_com_ssl_info_callback);  // for debugging

    *ssl_ctx = ctx;
    return SDP_SUCCESS;
}

static int tc_ssl_load_certs(SSL_CTX* ctx, char * ca_cert_file, char* cert_file, char* key_file)
{
    // load the CA cert for verification of peer certs
    if(ca_cert_file)
    {
        log_msg(LOG_WARNING, "Setting CA cert for peer cert verification.");
        if ( SSL_CTX_load_verify_locations(ctx, ca_cert_file, NULL) <= 0)
        {
            ERR_print_errors_fp(stderr);
            return SDP_ERROR_CERT;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); //tunnel_com_ssl_verify_callback); 
    }
    else
    {
        log_msg(LOG_WARNING, "WARNING: CA cert not provided for peer cert verification.");
    }
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


int tunnel_com_ssl_ctx_init(SSL_CTX **ssl_ctx, char * ca_cert_file, char* cert_file, char* key_file)
{
    int rv = SDP_SUCCESS;
    SSL_CTX *ctx = NULL;

    if((rv = tc_ssl_ctx_init(&ctx)) != SDP_SUCCESS)
        return rv;

    if((rv = tc_ssl_load_certs(ctx, ca_cert_file, cert_file, key_file)) != SDP_SUCCESS)
    {
        SSL_CTX_free(ctx);
        return rv;
    }

    *ssl_ctx = ctx;
    return SDP_SUCCESS;
}


static void tc_write_to_socket(uv_stream_t *handle, char* buf, size_t len) 
{
    int rv = SDP_SUCCESS;
    write_req_t *req = NULL;

    if(len <= 0) 
    {
        return;
    }

    log_msg(LOG_WARNING, "tc_write_to_socket()...");

    //log_msg(LOG_DEBUG, "tc_write_to_socket() handle set to %p", handle);
    //log_msg(LOG_DEBUG, "tc_write_to_socket() handle->data set to %p", handle->data);

    //log_msg(LOG_DEBUG, "tc_write_to_socket() buf address: %p", buf);
    //log_msg(LOG_DEBUG, "tc_write_to_socket() buf len: %d", len);

    if((req = calloc(1, sizeof *req)) == NULL)
    {
        log_msg(LOG_ERR, "tc_write_to_socket() Fatal memory error");
        kill(getpid(), SIGINT);
        return;
    }

    req->buf = uv_buf_init(buf, len);

    //log_msg(LOG_DEBUG, "tc_write_to_socket() req->buf.base address: %p", req->buf.base);
    //log_msg(LOG_DEBUG, "tc_write_to_socket() req->buf.len: %d", req->buf.len);
    
    if((rv = uv_write((uv_write_t*)req, handle, &req->buf, 1, tunnel_manager_write_cb)))
    {
        log_msg(LOG_ERR, "tc_write_to_socket() uv_write error: %s", uv_err_name(rv));
        tunnel_manager_free_write_req((uv_write_t*)req);
    }
    
}


static void tc_flush_read_bio(tunnel_record_t tunnel_rec) 
{
    char buf[SDP_COM_MAX_MSG_LEN];
    int bytes_read = 0;
    int pending = 0;
    char *ptr = NULL;

    log_msg(LOG_WARNING, "tc_flush_read_bio()...");

    while((pending = BIO_ctrl_pending(tunnel_rec->write_bio)) > 0 &&
        (bytes_read = BIO_read(tunnel_rec->write_bio, buf, sizeof(buf))) > 0) 
    {
        log_msg(LOG_WARNING, "tc_flush_read_bio() BIO read gave %d bytes", bytes_read);

        if((ptr = calloc(1, bytes_read)) == NULL)
        {
            log_msg(LOG_ERR, "tc_flush_read_bio() Memory allocation error");
            kill(getpid(), SIGINT);
            return;
        }

        memcpy(ptr, buf, bytes_read);

        //log_msg(LOG_DEBUG, "tc_flush_read_bio() Ptr address: %p", ptr);

        tc_write_to_socket((uv_stream_t*)tunnel_rec->handle, ptr, bytes_read);
    }
}


static int tc_handle_error(tunnel_record_t tunnel_rec, int result) 
{
    int error = 0;
    char ssl_error_string[SDP_MAX_LINE_LEN];

    error = sdp_com_get_ssl_error(tunnel_rec->ssl, result, ssl_error_string);
    log_msg(LOG_ERR, "SSL error: %d - %s", error, ssl_error_string);
    ERR_print_errors_fp(stderr);

    if(error == SSL_ERROR_WANT_READ)  // wants to read from bio
    {
        tc_flush_read_bio(tunnel_rec);
        return SDP_SUCCESS;
    }
    else if(error == SSL_ERROR_WANT_WRITE)
    {
        return SDP_SUCCESS;
    }

    log_msg(LOG_ERR, "SSL error. Disconnecting.");
    tunnel_manager_remove_tunnel_record(tunnel_rec, WHICH_TABLE_ALL);
    return SDP_ERROR_SSL;
}


static void tc_check_outgoing_application_data(tunnel_record_t tunnel_rec) 
{
    int rv = 0;
    //char header[SDP_COM_HEADER_LEN];
    //sdp_header hdr_obj;
    //char *hdr_obj_ptr = (char*)&hdr_obj;
    int msg_len = 0;
    char *msg = NULL;
    //char dump_buf[20] = {0};
    //int ii = 0;
    //int offset = 0;
    //int remainder = 20;

    log_msg(LOG_WARNING, "tc_check_outgoing_application_data()...");

    if(!tunnel_rec->ssl || !SSL_is_init_finished(tunnel_rec->ssl))
        return;

    while(tunnel_rec->outbound_q_len > 0)
    {

        //if(tunnel_rec->buffer_out_bytes_pending <= 0)
        if(tunnel_rec->outbound_q == NULL)
        {
            // shouldn't happen, but just in case
            tunnel_rec->outbound_q_len = 0;
            return;
        }

        if((rv = tc_pop_first_q_msg(&tunnel_rec->outbound_q, &msg, &msg_len)) != SDP_SUCCESS)
        {
            tunnel_rec->outbound_q_len = 0;
            return;
        }

        tunnel_rec->outbound_q_len--;

        if(msg == NULL)
        {
            log_msg(LOG_ERR, "Error: popped a NULL msg from Q");
            continue;
        }

        if(msg_len <= SDP_COM_HEADER_LEN)
        {
            log_msg(
                LOG_ERR, 
                "Error: popped a non-NULL msg from Q with too short length %d", 
                msg_len
            );
            free(msg);
            continue;
        }

        log_msg(LOG_WARNING, "got an outbound msg from Q");

        log_msg(LOG_WARNING, "msg len is %d", msg_len);

        //hdr_obj.length = htonl(msg_len);

        //log_msg(LOG_WARNING, "outgoing msg_len: %d", msg_len);
        //log_msg(LOG_WARNING, "outgoing hdr_obj.length: %"PRIu32, hdr_obj.length);

        //header[0] = (char)( (msg_len >> 24) & 0xFF );
        //header[1] = (char)( (msg_len >> 16) & 0xFF );
        //header[2] = (char)( (msg_len >> 8) & 0xFF );
        //header[3] = (char)(  msg_len & 0xFF );

        //while(ii < SDP_COM_HEADER_LEN && remainder)
        //{
        //    snprintf(dump_buf+offset, remainder, "%02X ", header[ii]);
        //    offset = strnlen(dump_buf, 20);
        //    remainder = 20 - offset;
        //    ii++;
        //}
        //
        //log_msg(LOG_WARNING, "header buffer: %s", dump_buf);
        //
        //offset = 0;
        //remainder = 20;
        //ii = 0;
        //
        //while(ii < SDP_COM_HEADER_LEN && remainder)
        //{
        //    snprintf(dump_buf+offset, remainder, "%02X ", hdr_obj_ptr[ii]);
        //    offset = strnlen(dump_buf, 20);
        //    remainder = 20 - offset;
        //    ii++;
        //}
        //
        //log_msg(LOG_WARNING, "hdr_obj_ptr  : %s", dump_buf);

        //if((rv = SSL_write(
        //    tunnel_rec->ssl, 
        //    header, 
        //    SDP_COM_HEADER_LEN
        //)) != SDP_COM_HEADER_LEN)
        //{
        //    log_msg(
        //        LOG_ERR, 
        //        "tc_check_outgoing_application_data() header SSL_write error"
        //    );
//
        //    // try flushing bio
        //    tc_handle_error(tunnel_rec, rv);
//
        //    // try one more time
        //    if((rv = SSL_write(
        //        tunnel_rec->ssl, 
        //        header, 
        //        SDP_COM_HEADER_LEN
        //    )) != SDP_COM_HEADER_LEN)
        //    {
        //        log_msg(
        //            LOG_ERR, 
        //            "tc_check_outgoing_application_data() header SSL_write failed twice"
        //        );
        //        free(msg);
        //        tunnel_manager_remove_tunnel_record(tunnel_rec);
        //        return;
        //    }
//
        //}
//
        ////tc_handle_error(tunnel_rec, rv);
        //tc_flush_read_bio(tunnel_rec);


        if((rv = SSL_write(
            tunnel_rec->ssl, 
            msg,
            msg_len
        )) != msg_len)
        {
            log_msg(
                LOG_ERR, 
                "tc_check_outgoing_application_data() SSL_write error"
            );

            // try flushing bio
            if((rv = tc_handle_error(tunnel_rec, rv)) != SDP_SUCCESS)
            {
                free(msg);
                return;
            }

            // try one more time
            if((rv = SSL_write(
                tunnel_rec->ssl, 
                msg,
                msg_len
            )) != msg_len)
            {
                log_msg(
                    LOG_ERR, 
                    "tc_check_outgoing_application_data() SSL_write failed twice"
                );
                free(msg);
                tunnel_manager_remove_tunnel_record(tunnel_rec, WHICH_TABLE_ALL);
                return;
            }

        }

        log_msg(LOG_WARNING, "SSL_write succeeded");
        free(msg);
        tc_flush_read_bio(tunnel_rec);
    }
}


//static int tc_extract_cn_from_line(char *line, char **r_cn)
//{
//    char *cn = NULL;
//    char label[4] = "CN=";
//    char delim[2] = "/";
//    int cn_len = 0;
//    char *field_end = NULL;
//
//    if((cn = strstr(line, label)) == NULL)
//    {
//        log_msg(
//            LOG_ERR, 
//            "tc_extract_cn_from_line() failed to locate label %s in line:\n\t%s", 
//            label,
//            line
//        );
//        return SDP_ERROR_CERT;
//    }
//
//    cn += strnlen(label, 10);
//
//    if((field_end = strstr(cn, delim)) == NULL)
//    {
//        log_msg(
//            LOG_ERR, 
//            "tc_extract_cn_from_line() failed to locate delim %s in line:\n\t%s", 
//            delim,
//            line
//        );
//        return SDP_ERROR_CERT;
//    }
//
//    if((field_end - cn) < 1)
//    {
//        log_msg(
//            LOG_ERR, 
//            "tc_extract_cn_from_line() CN field was empty in line:\n\t%s",
//            line
//        );
//        return SDP_ERROR_CERT;
//    }
//
//    field_end[0] = '\0';
//
//    log_msg(
//        LOG_WARNING, 
//        "tc_extract_cn_from_line() found CN: %s",
//        cn
//    );
//
//    *r_cn = cn;
//    return SDP_SUCCESS;
//}



//static int tc_extract_cert_id(SSL *ssl, uint32_t *r_id)
//{
//    int rv = SDP_SUCCESS;
//    X509 *cert = NULL;
//    char *line = NULL;
//
//    if(ssl == NULL)
//    {
//        log_msg(LOG_ERR, "tc_extract_cert_id() ssl is null");
//        return SDP_ERROR_UNINITIALIZED;
//    }
//
//    if((cert = SSL_get_peer_certificate(ssl)) == NULL)
//    {
//        log_msg(LOG_ERR, "tc_extract_cert_id() SSL_get_peer_certificate failed");
//        return SDP_ERROR_CERT;
//    }
//
//
//    if ( cert != NULL )
//    {
//        rv = SDP_SUCCESS;
//        log_msg(LOG_NOTICE, "Server certificates:");
//        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
//        log_msg(LOG_NOTICE, "Subject: %s", line);
//        free(line);       /* free the malloc'ed string */
//        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
//        log_msg(LOG_NOTICE, "Issuer: %s", line);
//        free(line);       /* free the malloc'ed string */
//        X509_free(cert);     /* free the malloc'ed certificate copy */
//    }
//    else
//    {
//        log_msg(LOG_ERR, "Error: Could not retrieve controller certificate.");
//        rv = SDP_ERROR_SSL_NO_CERT_RECEIVED;
//    }
//
//    return rv;
//}



static int tc_extract_cert_commonname(SSL *ssl, unsigned char **r_cn)
{
    int idx = -1;
    unsigned char *cn = NULL;
    X509 *cert = NULL;
    X509_NAME *name = NULL;
    X509_NAME_ENTRY *entry = NULL;
    int len = 0;

    if(ssl == NULL)
    {
        log_msg(LOG_ERR, "tc_extract_cert_commonname() ssl is null");
        return SDP_ERROR_UNINITIALIZED;
    }

    if((cert = SSL_get_peer_certificate(ssl)) == NULL)
    {
        log_msg(LOG_ERR, "tc_extract_cert_commonname() SSL_get_peer_certificate failed");
        return SDP_ERROR_CERT;
    }

    if((name = X509_get_subject_name(cert)) == NULL)
    {
        log_msg(LOG_ERR, "tc_extract_cert_commonname() X509_get_subject_name failed");
        X509_free(cert);
        return SDP_ERROR_CERT;
    }

    if((idx = X509_NAME_get_index_by_NID(name, NID_commonName, idx)) < 0)
    {
        log_msg(LOG_ERR, "tc_extract_cert_commonname() X509_NAME_get_index_by_NID failed");
        X509_free(cert);
        return SDP_ERROR_CERT;
    }

    if((entry = X509_NAME_get_entry(name, idx)) == NULL)
    {
        log_msg(LOG_ERR, "tc_extract_cert_commonname() X509_NAME_get_entry failed");
        X509_free(cert);
        return SDP_ERROR_CERT;
    }

    if((len = ASN1_STRING_to_UTF8(
            &cn, 
            X509_NAME_ENTRY_get_data(entry)
        )) < 1)
    {
        log_msg(LOG_ERR, "tc_extract_cert_commonname() ASN1_STRING_to_UTF8 failed");
        X509_free(cert);
        return SDP_ERROR_CERT;
    }

    log_msg(LOG_WARNING, "tc_extract_cert_commonname() got common name: %s", cn);
    X509_free(cert);
    *r_cn = cn;
    return SDP_SUCCESS;
}


static int tc_verify_cert_id(tunnel_record_t tunnel_rec)
{
    int rv = SDP_SUCCESS;
    unsigned char *cn = NULL;
    uint32_t cert_id = 0;
    tunnel_record_t requested_tunnel_rec = NULL;

    if(!tunnel_rec || !tunnel_rec->tunnel_mgr)
    {
        log_msg(LOG_ERR, "tunnel_com_handle_event() null context data");

    }


    if((rv = tc_extract_cert_commonname(tunnel_rec->ssl, &cn)) != SDP_SUCCESS)
    {
        log_msg(
            LOG_ERR, 
            "tc_verify_cert_id() failed to extract cert commonname for verification"
        );
        return rv;
    }

    cert_id = strtoul_wrapper((const char*)cn, 0, UINT32_MAX, NO_EXIT_UPON_ERR, &rv);
    OPENSSL_free(cn);

    if(cert_id == 0 || rv != SDP_SUCCESS)
    {
        log_msg(
            LOG_ERR, 
            "tc_verify_cert_id() failed to convert commonname to uint32_t"
        );
        return SDP_ERROR_CERT;
    }


    // TODO: what do we do if sdp id already has a tunnel connection
    // yet sent another SPA, disconnect old one?
    // if this one checks out, probably should kill the old one

    // check if we were expecting this connection
    if((rv = tunnel_manager_find_tunnel_record(
                tunnel_rec->tunnel_mgr, 
                cert_id,
                NULL,
                0,
                WHICH_TABLE_REQUEST,
                &requested_tunnel_rec
        )) != SDP_SUCCESS)
    {
        log_msg(
            LOG_ERR, 
            "[*] ALERT: Attempted tunnel connection by unexpected sdp id %"PRIu32
            " from address %s:%d!",
            cert_id, 
            tunnel_rec->remote_public_ip, 
            tunnel_rec->remote_port
        );

        return SDP_ERROR_CERT;
    }

    if(strncmp(
        requested_tunnel_rec->remote_public_ip, 
        tunnel_rec->remote_public_ip, 
        MAX_IPV4_STR_LEN))
    {
        log_msg(
            LOG_ERR, 
            "[*] ALERT: Attempted tunnel connection by sdp id %"PRIu32
            " from wrong address %s:%"PRIu32"! Expected %s",
            cert_id, 
            tunnel_rec->remote_public_ip, 
            tunnel_rec->remote_port,
            requested_tunnel_rec->remote_public_ip
        );

        return SDP_ERROR;            
    }

    tunnel_rec->sdp_id = cert_id;

    // replace the partial record in the requested_tunnel table
    // with this new, more complete record. The old request
    // record is destroyed in the process
    if((rv = tunnel_manager_submit_tunnel_record(
            tunnel_rec,
            WHICH_TABLE_REQUEST
        )) != SDP_SUCCESS)
    {
        log_msg(
            LOG_ERR, 
            "[*] ERROR: Failed to update requested_tunnel record for SDP ID: %"PRIu32,
            cert_id
        );
        return SDP_ERROR;
    }

    // remove the tunnel record from the new_tunnel table
    tunnel_manager_remove_tunnel_record(tunnel_rec, WHICH_TABLE_NEW);

    log_msg(
        LOG_WARNING, 
        "tc_verify_cert_id() Tunnel connection by sdp id %"PRIu32 
        " from %s:%"PRIu32" was expected!",
        tunnel_rec->sdp_id,
        tunnel_rec->remote_public_ip,
        tunnel_rec->remote_port
    );

    return SDP_SUCCESS;
}


void tunnel_com_handle_event(tunnel_record_t tunnel_rec)
{
    char buf[SDP_COM_MAX_MSG_LEN + 1];
    int rv = 0;
    sdp_header header;
    //char *hdr_obj_ptr = (char*)&header;
    uint32_t data_length = 0;
    //char dump_buf[20] = {0};
    //int ii = 0;
    //int offset = 0;
    //int remainder = 20;

    log_msg(LOG_WARNING, "tunnel_com_handle_event() ...");

    if(!tunnel_rec->tunnel_mgr || !tunnel_rec->tunnel_mgr->tunnel_msg_in_cb)
    {
        log_msg(LOG_ERR, "tunnel_com_handle_event() null context data");

    }

    if(!SSL_is_init_finished(tunnel_rec->ssl)) 
    {
        //log_msg(LOG_DEBUG, "tunnel_com_handle_event() SSL handshake not finished");

        rv = SSL_do_handshake(tunnel_rec->ssl);
        if(rv != 1) 
        {
            log_msg(LOG_WARNING, "tunnel_com_handle_event() SSL_do_handshake error");
            if((rv = tc_handle_error(tunnel_rec, rv)) != SDP_SUCCESS)
            {
                return;
            }
        }
        else  // SSL handshake completed
        {
            log_msg(LOG_WARNING, "tunnel_com_handle_event() handshake completed");

            // now have the client cert, which was verified by the BIO to be valid
            // but still need to check that the client ID matches
            if( !tunnel_rec->tunnel_mgr->is_sdp_client && 
                (rv = tc_verify_cert_id(tunnel_rec)) != SDP_SUCCESS)
            {
                tunnel_manager_remove_tunnel_record(tunnel_rec, WHICH_TABLE_ALL);
                return;
            }
            tunnel_rec->con_state = TM_CON_STATE_SECURED;
            tc_flush_read_bio(tunnel_rec);
        }
        tc_check_outgoing_application_data(tunnel_rec);
    }
    else 
    {
        // already connected, check if there is encrypted data, or we need to send app data
        if((rv = SSL_read(tunnel_rec->ssl, &header, SDP_COM_HEADER_LEN)) < 0)
        {
            if((rv = tc_handle_error(tunnel_rec, rv)) != SDP_SUCCESS)
            {
                return;
            }
            tc_check_outgoing_application_data(tunnel_rec);
            return;
        }
        else if(rv != SDP_COM_HEADER_LEN)
        {
            if((rv = tc_handle_error(tunnel_rec, rv)) != SDP_SUCCESS)
            {
                return;
            }
            tc_check_outgoing_application_data(tunnel_rec);
            return;
        }

        data_length = (uint32_t)ntohl(header.length);

        //while(ii < SDP_COM_HEADER_LEN && remainder)
        //{
        //    snprintf(dump_buf+offset, remainder, "%02X ", hdr_obj_ptr[ii]);
        //    offset = strnlen(dump_buf, 20);
        //    remainder = 20 - offset;
        //    ii++;
        //}
        //
        //log_msg(LOG_WARNING, "header.length: %"PRIu32, header.length);
        //log_msg(LOG_WARNING, "hdr_obj_ptr  : %s", dump_buf);
        //log_msg(LOG_WARNING, "data_length  : %"PRIu32, data_length);


        // got a message size header
        if(data_length > SDP_COM_MAX_MSG_LEN)
        {
            log_msg(
                LOG_ERR, 
                "Inbound msg size %u longer than buffer len %d. Disconnecting.",
                data_length,
                SDP_COM_MAX_MSG_LEN
            );

            // TODO: bail out because we can't handle this yet
            tunnel_manager_remove_tunnel_record(tunnel_rec, WHICH_TABLE_ALL);
            return;
        }

        rv = SSL_read(tunnel_rec->ssl, buf, data_length);
        if(rv < 0) 
        {
            if((rv = tc_handle_error(tunnel_rec, rv)) != SDP_SUCCESS)
            {
                return;
            }
        }
        else if(rv != data_length) 
        {
            log_msg(LOG_ERR, "SSL_read gave %d bytes, expected %u", rv, data_length);
        }
        else
        {
            // got the expected number of bytes, process it
            buf[data_length] = '\0';
            tunnel_rec->tunnel_mgr->tunnel_msg_in_cb(tunnel_rec, buf);

            //memcopy(tunnel_rec->buffer_in, buf, rv);
            //tunnel_rec->buffer_in_bytes_pending = rv;
        }

        tc_check_outgoing_application_data(tunnel_rec);
    }
}

void tunnel_com_read_cb(uv_stream_t* handle, ssize_t nread, const uv_buf_t *buf) 
{
    tunnel_record_t tunnel_rec = (tunnel_record_t)handle->data;
    int rv = 0;
    //char plain_buf[SDP_COM_MAX_MSG_LEN] = {0};

    log_msg(LOG_WARNING, "tunnel_com_read_cb() ...");

    if(nread <= 0)   // disconnected (?)
    { 
        free(buf->base);
        log_msg(LOG_ERR, "tunnel_com_read_cb() called with nread <= 0");

        //rv = SSL_read(tunnel_rec->ssl, plain_buf, sizeof(plain_buf));
        //
        //if(rv < 0) 
        //{
        //    tc_handle_error(tunnel_rec, rv);
        //}
        //else if(rv > 0) 
        //{
        //    memcpy(tunnel_rec->buffer_in, plain_buf, rv);
        //    tunnel_rec->buffer_in_bytes_pending = rv;
        //}

        tunnel_manager_remove_tunnel_record(tunnel_rec, WHICH_TABLE_ALL);
        return;
    }

    //log_msg(LOG_DEBUG, "tunnel_com_read_cb() got %d bytes, writing to BIO...", nread);

    if((rv = BIO_write(tunnel_rec->read_bio, buf->base, nread)) != nread)
    {
        log_msg(
            LOG_ERR, 
            "tunnel_com_read_cb() BIO_write wrote %d bytes, not %d bytes", 
            rv, 
            nread
        );
    }
    free(buf->base);
    tunnel_com_handle_event(tunnel_rec);
}


static void tc_ssl_shutdown(tunnel_record_t tunnel_rec) 
{
    if(!tunnel_rec || !tunnel_rec->ssl)  
    {
        log_msg(
            LOG_ERR, 
            "tc_ssl_shutdown() required data is NULL, cannot perform ssl shutdown"
        );
        return;
    }

    log_msg(LOG_WARNING, "Tearing down SSL object");

    SSL_shutdown(tunnel_rec->ssl);

    SSL_free(tunnel_rec->ssl);
    tunnel_rec->ssl = NULL;   
}


void tunnel_com_disconnect(uv_tcp_t *handle)
{
    tunnel_record_t tunnel_rec = (tunnel_record_t)handle->data;

    // prevent the read callback from firing during shutdown
    uv_read_stop((uv_stream_t*)handle);

    if(tunnel_rec != NULL)
    {
        tc_ssl_shutdown(tunnel_rec); 
        tunnel_rec->handle = NULL;
        tunnel_rec->con_state = TM_CON_STATE_DISCONNECTED;
    }
    else  // no SSL shutdown without tunnel_rec
    {
        log_msg(
            LOG_WARNING, 
            "tunnel_com_disconnect() no tunnel_rec found, closing socket now"
        );
    }

    uv_close((uv_handle_t*)handle, (uv_close_cb)free);
}


void tunnel_com_alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) 
{
  buf->base = calloc(1, suggested_size);
  buf->len = suggested_size;
}



int tunnel_com_send_msg(tunnel_record_t tunnel_rec, char *msg)
{
    int rv = SDP_SUCCESS;
    //int msg_len = 0;

    if(tunnel_rec->outbound_q_len >= TUNNEL_MAX_Q_LEN)
    {
        log_msg(
            LOG_ERR, 
            "Failed to send message, %d messages pending.",
            tunnel_rec->outbound_q_len
        );
        return SDP_ERROR;
    }

    if((rv = tc_add_to_msg_q(&tunnel_rec->outbound_q, msg)) != SDP_SUCCESS)
    {
        return rv;
    }
    tunnel_rec->outbound_q_len++;

    tc_check_outgoing_application_data(tunnel_rec);
    return rv;
}


int tunnel_com_finalize_connection(tunnel_record_t tunnel_rec, int is_client)
{
    int rv = SDP_SUCCESS;

    if(!tunnel_rec->handle)
    {
        log_msg(LOG_ERR, "tunnel_com_secure_connection() handle is null");
        return SDP_ERROR_UNINITIALIZED;
    }

    if(!tunnel_rec->tunnel_mgr)
    {
        log_msg(LOG_ERR, "tunnel_com_secure_connection() tunnel_mgr is null");
        return SDP_ERROR_UNINITIALIZED;
    }

    // socket connection succeeded and we have all the necessary data
    if((tunnel_rec->ssl = SSL_new(tunnel_rec->tunnel_mgr->ssl_ctx)) == NULL)
    {
        log_msg(LOG_ERR, "Failed to create SSL object");
        ERR_print_errors_fp(stderr);
        return SDP_ERROR_SSL;
    }

    tunnel_rec->read_bio = BIO_new(BIO_s_mem());
    tunnel_rec->write_bio = BIO_new(BIO_s_mem());

    if(!tunnel_rec->read_bio || !tunnel_rec->write_bio)
    {
        log_msg(LOG_ERR, "Failed to create SSL BIO");
        return SDP_ERROR_SSL;
    }

    SSL_set_bio(tunnel_rec->ssl, tunnel_rec->read_bio, tunnel_rec->write_bio);

    if(is_client)
    {
        SSL_set_connect_state(tunnel_rec->ssl);
    }
    else
    {
        SSL_set_accept_state(tunnel_rec->ssl);
    }

    if((rv = uv_read_start(
        (uv_stream_t*)tunnel_rec->handle, 
        tunnel_com_alloc_buffer, 
        tunnel_com_read_cb
    )))
    {
        log_msg(LOG_ERR, "uv_read_start error: %s", uv_err_name(rv));
        tunnel_manager_remove_tunnel_record(tunnel_rec, WHICH_TABLE_ALL);
        return SDP_ERROR_CONN_FAIL;
    }

    if(is_client)
    {
        // this actually gets data moving between BIO
        // and socket, after which the rest of the handshake
        // is event-driven
        tunnel_com_handle_event(tunnel_rec);
    }
    return SDP_SUCCESS;
}



