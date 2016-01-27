/*
 *****************************************************************************
 *
 * File:    fko_funcs.c
 *
 * Purpose: General utility functions for libfko
 *
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2014 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *  License (GNU General Public License):
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *****************************************************************************
*/
#include "fko_common.h"
#include "fko.h"
#include "cipher_funcs.h"
#include "base64.h"
#include "digest.h"
#include "dbg.h"

/* Initialize an fko context.
*/
int
fko_new(fko_ctx_t *r_ctx)
{
    fko_ctx_t   ctx = NULL;
    int         res;
    char       *ver;

#if HAVE_LIBFIU
    fiu_return_on("fko_new_calloc", FKO_ERROR_MEMORY_ALLOCATION);
#endif

    ctx = calloc(1, sizeof *ctx);
    if(ctx == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    /* Set default values and state.
     *
     * Note: We initialize the context early so that the fko_set_xxx
     *       functions can operate properly. If there are any problems during
     *       initialization, then fko_destroy() is called which will clean up
     *       the context.
    */
    ctx->initval = FKO_CTX_INITIALIZED;

    /* Set the version string.
    */
    ver = strdup(FKO_PROTOCOL_VERSION);
    if(ver == NULL)
    {
        fko_destroy(ctx);
        ctx = NULL;
        return(FKO_ERROR_MEMORY_ALLOCATION);
    }
    ctx->version = ver;

    /* Rand value.
    */
    res = fko_set_rand_value(ctx, NULL);
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* Username.
    */
    res = fko_set_username(ctx, NULL);
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* Timestamp.
    */
    res = fko_set_timestamp(ctx, 0);
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* Default Digest Type.
    */
    res = fko_set_spa_digest_type(ctx, FKO_DEFAULT_DIGEST);
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* Default Message Type.
    */
    res = fko_set_spa_message_type(ctx, FKO_DEFAULT_MSG_TYPE);
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* Default Encryption Type.
    */
    res = fko_set_spa_encryption_type(ctx, FKO_DEFAULT_ENCRYPTION);
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* Default is Rijndael in CBC mode
    */
    res = fko_set_spa_encryption_mode(ctx, FKO_DEFAULT_ENC_MODE);
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* Default is to use SDP mode
    */
    ctx->disable_sdp_mode = FKO_DEFAULT_DISABLE_SDP_MODE;
    ctx->encoded_sdp_client_id = NULL;
    ctx->encoded_sdp_client_id_len = 0;

#if HAVE_LIBGPGME
    /* Set gpg signature verify on.
    */
    ctx->verify_gpg_sigs = 1;

#endif /* HAVE_LIBGPGME */

    FKO_SET_CTX_INITIALIZED(ctx);

    *r_ctx = ctx;

    return(FKO_SUCCESS);
}

/* Initialize an fko context with external (encrypted/encoded) data.
 * This is used to create a context with the purpose of decoding
 * and parsing the provided data into the context data.
*/
int
fko_new_with_data(fko_ctx_t *r_ctx, const char * const enc_msg,
    const char * const dec_key, const int dec_key_len,
    int encryption_mode, const char * const hmac_key,
    const int hmac_key_len, const int hmac_type, const uint32_t sdp_client_id)
{
    fko_ctx_t   ctx = NULL;
    int         res = FKO_SUCCESS; /* Are we optimistic or what? */
    int         enc_msg_len;

#if HAVE_LIBFIU
    fiu_return_on("fko_new_with_data_msg",
            FKO_ERROR_INVALID_DATA_FUNCS_NEW_ENCMSG_MISSING);
#endif

    if(enc_msg == NULL)
        return(FKO_ERROR_INVALID_DATA_FUNCS_NEW_ENCMSG_MISSING);

#if HAVE_LIBFIU
    fiu_return_on("fko_new_with_data_keylen",
            FKO_ERROR_INVALID_KEY_LEN);
#endif

    if(dec_key_len < 0 || hmac_key_len < 0)
        return(FKO_ERROR_INVALID_KEY_LEN);

    ctx = calloc(1, sizeof *ctx);
    if(ctx == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    // if SDP client ID is nonzero, SDP mode is enabled
    ctx->sdp_client_id = sdp_client_id;
    if(sdp_client_id > 0)
    	ctx->disable_sdp_mode = 0;
    else
    	ctx->disable_sdp_mode = 1;

    enc_msg_len = strnlen(enc_msg, MAX_SPA_ENCODED_MSG_SIZE);

    if(! is_valid_encoded_msg_len(enc_msg_len))
    {
        free(ctx);
        return(FKO_ERROR_INVALID_DATA_FUNCS_NEW_MSGLEN_VALIDFAIL);
    }

    /* First, add the data to the context.
    */
    ctx->encrypted_msg     = strdup(enc_msg);
    ctx->encrypted_msg_len = enc_msg_len;

    if(ctx->encrypted_msg == NULL)
    {
        free(ctx);
        return(FKO_ERROR_MEMORY_ALLOCATION);
    }

    /* Default Encryption Mode (Rijndael in CBC mode)
    */
    ctx->initval = FKO_CTX_INITIALIZED;
    res = fko_set_spa_encryption_mode(ctx, encryption_mode);
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* HMAC digest type
    */
    res = fko_set_spa_hmac_type(ctx, hmac_type);
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* Check HMAC if the access stanza had an HMAC key
    */
    if(hmac_key_len > 0 && hmac_key != NULL)
    {
        res = fko_verify_hmac(ctx, hmac_key, hmac_key_len);
		if(res != FKO_SUCCESS)
		{
			fko_destroy(ctx);
			ctx = NULL;
			return res;
		}
    }

	if(sdp_client_id > 0)
	{
		/* The HMAC has been successfully verified (if it was present)
		 * If this is SDP mode, time to remove the SDP client ID from the packet data
		 * It was already captured much earlier in order to find the right
		 * access rules, but now it needs to be stripped from the buffer.
		 * This will also copy the encoded version of the ID to the
		 * context (really just for certain tests).
		 */
		res = fko_strip_sdp_client_id(ctx);
		if(res != FKO_SUCCESS)
		{
			fko_destroy(ctx);
			ctx = NULL;
			return res;
		}
	}


    /* Consider it initialized here.
    */
    FKO_SET_CTX_INITIALIZED(ctx);

    /* If a decryption key is provided, go ahead and decrypt and decode.
    */
    if(dec_key != NULL)
    {
        res = fko_decrypt_spa_data(ctx, dec_key, dec_key_len);

        if(res != FKO_SUCCESS)
        {
            fko_destroy(ctx);
            ctx = NULL;
            *r_ctx = NULL; /* Make sure the caller ctx is null just in case */
            return(res);
        }
    }

#if HAVE_LIBGPGME
    /* Set gpg signature verify on.
    */
    ctx->verify_gpg_sigs = 1;

#endif /* HAVE_LIBGPGME */

    *r_ctx = ctx;

    return(res);
}

/* Destroy a context and free its resources
*/
int
fko_destroy(fko_ctx_t ctx)
{
    int zero_free_rv = FKO_SUCCESS;

#if HAVE_LIBGPGME
    fko_gpg_sig_t   gsig, tgsig;
#endif

    if(!CTX_INITIALIZED(ctx))
        return(zero_free_rv);

    if(ctx->rand_val != NULL)
        free(ctx->rand_val);

    if(ctx->username != NULL)
        free(ctx->username);

    if(ctx->version != NULL)
        free(ctx->version);

    if(ctx->message != NULL)
        free(ctx->message);

    if(ctx->nat_access != NULL)
        free(ctx->nat_access);

    if(ctx->server_auth != NULL)
        free(ctx->server_auth);

    if(ctx->digest != NULL)
        if(zero_free(ctx->digest, ctx->digest_len) != FKO_SUCCESS)
            zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    if(ctx->raw_digest != NULL)
        if(zero_free(ctx->raw_digest, ctx->raw_digest_len) != FKO_SUCCESS)
            zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    if(ctx->encoded_sdp_client_id != NULL)
        if(zero_free(ctx->encoded_sdp_client_id, ctx->encoded_sdp_client_id_len) != FKO_SUCCESS)
            zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    if(ctx->encoded_msg != NULL)
        if(zero_free(ctx->encoded_msg, ctx->encoded_msg_len) != FKO_SUCCESS)
            zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    if(ctx->encrypted_msg != NULL)
        if(zero_free(ctx->encrypted_msg, ctx->encrypted_msg_len) != FKO_SUCCESS)
            zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    if(ctx->final_msg != NULL)
        if(zero_free(ctx->final_msg, ctx->final_msg_len) != FKO_SUCCESS)
            zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    if(ctx->msg_hmac != NULL)
        if(zero_free(ctx->msg_hmac, ctx->msg_hmac_len) != FKO_SUCCESS)
            zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

#if HAVE_LIBGPGME
    if(ctx->gpg_exe != NULL)
        free(ctx->gpg_exe);

    if(ctx->gpg_home_dir != NULL)
        free(ctx->gpg_home_dir);

    if(ctx->gpg_recipient != NULL)
        free(ctx->gpg_recipient);

    if(ctx->gpg_signer != NULL)
        free(ctx->gpg_signer);

    if(ctx->recipient_key != NULL)
        gpgme_key_unref(ctx->recipient_key);

    if(ctx->signer_key != NULL)
        gpgme_key_unref(ctx->signer_key);

    if(ctx->gpg_ctx != NULL)
        gpgme_release(ctx->gpg_ctx);

    gsig = ctx->gpg_sigs;
    while(gsig != NULL)
    {
        if(gsig->fpr != NULL)
            free(gsig->fpr);

        tgsig = gsig;
        gsig = gsig->next;

        free(tgsig);
    }

#endif /* HAVE_LIBGPGME */

    memset(ctx, 0x0, sizeof(*ctx));

    free(ctx);

    return(zero_free_rv);
}

/* Generate Rijndael and HMAC keys from /dev/random and base64
 * encode them
*/
int
fko_key_gen(char * const key_base64, const int key_len,
        char * const hmac_key_base64, const int hmac_key_len,
        const int hmac_type)
{
    unsigned char key[RIJNDAEL_MAX_KEYSIZE];
    unsigned char hmac_key[SHA512_BLOCK_LEN];
    int klen      = key_len;
    int hmac_klen = hmac_key_len;
    int b64_len   = 0;

    if(key_len == FKO_DEFAULT_KEY_LEN)
        klen = RIJNDAEL_MAX_KEYSIZE;

    if(hmac_key_len == FKO_DEFAULT_KEY_LEN)
    {
        if(hmac_type == FKO_DEFAULT_HMAC_MODE
                || hmac_type == FKO_HMAC_SHA256)
            hmac_klen = SHA256_BLOCK_LEN;
        else if(hmac_type == FKO_HMAC_MD5)
            hmac_klen = MD5_DIGEST_LEN;
        else if(hmac_type == FKO_HMAC_SHA1)
            hmac_klen = SHA1_DIGEST_LEN;
        else if(hmac_type == FKO_HMAC_SHA384)
            hmac_klen = SHA384_BLOCK_LEN;
        else if(hmac_type == FKO_HMAC_SHA512)
            hmac_klen = SHA512_BLOCK_LEN;
    }

    if((klen < 1) || (klen > RIJNDAEL_MAX_KEYSIZE))
        return(FKO_ERROR_INVALID_DATA_FUNCS_GEN_KEYLEN_VALIDFAIL);

    if((hmac_klen < 1) || (hmac_klen > SHA512_BLOCK_LEN))
        return(FKO_ERROR_INVALID_DATA_FUNCS_GEN_HMACLEN_VALIDFAIL);

    get_random_data(key, klen);
    get_random_data(hmac_key, hmac_klen);

    b64_len = b64_encode(key, key_base64, klen);
    if(b64_len < klen)
        return(FKO_ERROR_INVALID_DATA_FUNCS_GEN_KEY_ENCODEFAIL);

    b64_len = b64_encode(hmac_key, hmac_key_base64, hmac_klen);
    if(b64_len < hmac_klen)
        return(FKO_ERROR_INVALID_DATA_FUNCS_GEN_HMAC_ENCODEFAIL);

    return(FKO_SUCCESS);
}

/* Provide an FKO wrapper around base64 encode/decode functions
*/
int
fko_base64_encode(unsigned char * const in, char * const out, int in_len)
{
    return b64_encode(in, out, in_len);
}

int
fko_base64_decode(const char * const in, unsigned char *out)
{
    return b64_decode(in, out);
}

/* Return the fko version
*/
int
fko_get_version(fko_ctx_t ctx, char **version)
{

#if HAVE_LIBFIU
    fiu_return_on("fko_get_version_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(version == NULL)
        return(FKO_ERROR_INVALID_DATA);

#if HAVE_LIBFIU
    fiu_return_on("fko_get_version_val", FKO_ERROR_INVALID_DATA);
#endif

    *version = ctx->version;

    return(FKO_SUCCESS);
}

/* Enable/disable Software Defined Perimeter Mode
 */
int
fko_set_disable_sdp_mode(fko_ctx_t ctx, uint16_t disable_sdp_mode)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    ctx->disable_sdp_mode = disable_sdp_mode;

    return(FKO_SUCCESS);
}

/* Get current setting of disable_sdp_mode
 */
int
fko_get_disable_sdp_mode(fko_ctx_t ctx, uint16_t *disable_sdp_mode)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *disable_sdp_mode = ctx->disable_sdp_mode;

    return(FKO_SUCCESS);
}

/* Set sdp client id
 */
int
fko_set_sdp_client_id(fko_ctx_t ctx, uint32_t sdp_client_id)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    ctx->sdp_client_id = sdp_client_id;

    return(FKO_SUCCESS);
}

/* Get sdp client id
 */
int
fko_get_sdp_client_id(fko_ctx_t ctx, uint32_t *sdp_client_id)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    *sdp_client_id = ctx->sdp_client_id;

    return(FKO_SUCCESS);
}

/* This function is only called if this is SDP mode and
 * HMAC has been successfully verified (if it was present)
 * So it's time to remove the SDP client ID from the packet data
 * It was already captured much earlier in order to find the right
 * access rules, but now it needs to be stripped from the buffer.
 * This will also copy the encoded version of the ID to the
 * context (really just for certain tests).
 */
int
fko_strip_sdp_client_id(fko_ctx_t ctx)
{
	char *tbuf = NULL;
	char *ndx = NULL;
	int res = 0;

	// first store the encoded sdp client id in the context
	tbuf = calloc(1, B64_SDP_CLIENT_ID_STR_LEN + 1);
	if(tbuf == NULL)
	{
		fko_destroy(ctx);
		ctx = NULL;
		return FKO_ERROR_MEMORY_ALLOCATION;
	}

	strncpy(tbuf, ctx->encrypted_msg, B64_SDP_CLIENT_ID_STR_LEN);
	tbuf[B64_SDP_CLIENT_ID_STR_LEN] = '\0';
	res = fko_set_encoded_sdp_client_id(ctx, tbuf);
	free(tbuf);
	tbuf = NULL;

	if(res != FKO_SUCCESS)
	{
		return res;
	}

	// the ID is always 6 bytes
	ndx = ctx->encrypted_msg + B64_SDP_CLIENT_ID_STR_LEN;

	tbuf = strndup(ndx, MAX_SPA_ENCODED_MSG_SIZE);
	if(tbuf == NULL)
	{
		return FKO_ERROR_MEMORY_ALLOCATION;
	}

	free(ctx->encrypted_msg);

	ctx->encrypted_msg = strndup(tbuf, MAX_SPA_ENCODED_MSG_SIZE);

	free(tbuf);

	if(ctx->encrypted_msg == NULL)
	{
		return FKO_ERROR_MEMORY_ALLOCATION;
	}

	ctx->encrypted_msg_len = strnlen(ctx->encrypted_msg, MAX_SPA_ENCODED_MSG_SIZE);

	if(! is_valid_encoded_msg_len(ctx->encrypted_msg_len))
	{
		return(FKO_ERROR_INVALID_DATA_FUNCS_NEW_MSGLEN_VALIDFAIL);
	}

	return FKO_SUCCESS;
}

/* Final update and encoding of data in the context.
 * This does require all requisite fields be properly
 * set.
*/
int
fko_spa_data_final(fko_ctx_t ctx,
    const char * const enc_key, const int enc_key_len,
    const char * const hmac_key, const int hmac_key_len)
{
    char   *tbuf;
    char   *tmp_ptr;
    int     new_msg_len = 0;
    int     res = 0, data_with_hmac_len = 0;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(enc_key_len < 0)
        return(FKO_ERROR_INVALID_KEY_LEN);

    debug("fko_spa_data_final() : calling fko_encrypt_spa_data...");
    res = fko_encrypt_spa_data(ctx, enc_key, enc_key_len);
    if(res != FKO_SUCCESS)
    	return res;
    debug("fko_spa_data_final() : returned from fko_encrypt_spa_data");

    /* Notice we omit the first 10 bytes if Rijndael encryption is
     * used (to eliminate the consistent 'Salted__' string), and
     * in GnuPG mode we eliminate the consistent 'hQ' base64 encoded
     * prefix
    */
    debug("fko_spa_data_final() : calculating tmp_ptr...");
    tmp_ptr = ctx->encrypted_msg;
    if(ctx->encryption_type == FKO_ENCRYPTION_RIJNDAEL)
        tmp_ptr += B64_RIJNDAEL_SALT_STR_LEN;
    else if(ctx->encryption_type == FKO_ENCRYPTION_GPG)
        tmp_ptr += B64_GPG_PREFIX_STR_LEN;
    debug("fko_spa_data_final() : done calculating tmp_ptr");

    /* If this is not SDP mode, just remove the unwanted prefix
     */
    if(ctx->disable_sdp_mode)
    {
    	// need a new buffer to assemble everything
        new_msg_len = strlen(tmp_ptr) + 1;
        if(! is_valid_encoded_msg_len(new_msg_len))
            return(FKO_ERROR_INVALID_DATA_ENCODE_MSGLEN_VALIDFAIL);

        tbuf = calloc(1, new_msg_len);
        if(tbuf == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);

        // make the change
        strlcpy(tbuf, tmp_ptr, new_msg_len);

        /* encrypted_msg needs to
         * be freed before re-assignment.
        */
        free(ctx->encrypted_msg);

        ctx->encrypted_msg = strdup(tbuf);
        free(tbuf);

        ctx->encrypted_msg_len = strnlen(ctx->encrypted_msg, MAX_SPA_ENCODED_MSG_SIZE);
        if(! is_valid_encoded_msg_len(ctx->encrypted_msg_len))
            return(FKO_ERROR_INVALID_DATA_ENCODE_MSGLEN_VALIDFAIL);
    }
    else
    {
        debug("fko_spa_data_final() : calculating new message len, but first...");
        debug("fko_spa_data_final() : sdp client id string len: %d", ctx->encoded_sdp_client_id_len);

    	// remove the unwanted data and insert the SDP client ID at this time
        new_msg_len = ctx->encoded_sdp_client_id_len + strlen(tmp_ptr) + 1;
        if(! is_valid_encoded_msg_len(new_msg_len))
            return(FKO_ERROR_INVALID_DATA_ENCODE_MSGLEN_VALIDFAIL);

        debug("fko_spa_data_final() : calculated message len: %d", new_msg_len);

        tbuf = calloc(1, new_msg_len);
        if(tbuf == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);


        // put 'em together
        debug("fko_spa_data_final() : copying sdp client id string: %s;", ctx->encoded_sdp_client_id);
        debug("fko_spa_data_final() : encrypted_(encoded)_msg: \n\t%s;", ctx->encrypted_msg);
        debug("fko_spa_data_final() : tmp_ptr: \n\t%s;", tmp_ptr);
        strlcpy(tbuf, ctx->encoded_sdp_client_id, new_msg_len);
        debug("fko_spa_data_final() : concatting rest of message...");
        strlcat(tbuf, tmp_ptr, new_msg_len);
        debug("fko_spa_data_final() : tbuf: \n\t%s;", tbuf);

        /* encrypted_msg needs to
         * be freed before re-assignment.
        */
        debug("fko_spa_data_final() : freeing old message string...");
        free(ctx->encrypted_msg);

        debug("fko_spa_data_final() : duplicating new message...");
        ctx->encrypted_msg = strdup(tbuf);
        free(tbuf);

        ctx->encrypted_msg_len = strnlen(ctx->encrypted_msg, MAX_SPA_ENCODED_MSG_SIZE);
        if(! is_valid_encoded_msg_len(ctx->encrypted_msg_len))
            return(FKO_ERROR_INVALID_DATA_ENCODE_MSGLEN_VALIDFAIL);
    }

    /* Now calculate hmac if so configured
    */
    if (ctx->hmac_type != FKO_HMAC_UNKNOWN)
    {
        if(hmac_key_len < 0)
            return(FKO_ERROR_INVALID_KEY_LEN);

        if(hmac_key == NULL)
            return(FKO_ERROR_INVALID_KEY_LEN);

        debug("fko_spa_data_final() : setting HMAC...");
        res = fko_set_spa_hmac(ctx, hmac_key, hmac_key_len);

        if (res == FKO_SUCCESS)
        {
            /* Now that we have the hmac, append it to the
             * encrypted data (which has already been base64-encoded
             * and the trailing '=' chars stripped off).
            */
            data_with_hmac_len
                = ctx->encrypted_msg_len+1+ctx->msg_hmac_len+1;

            debug("fko_spa_data_final() : expanding message buffer...");
            tbuf = realloc(ctx->encrypted_msg, data_with_hmac_len);
            if (tbuf == NULL)
                return(FKO_ERROR_MEMORY_ALLOCATION);

            debug("fko_spa_data_final() : concatting HMAC...");
            strlcat(tbuf, ctx->msg_hmac, data_with_hmac_len);

            ctx->encrypted_msg     = tbuf;
            ctx->encrypted_msg_len = data_with_hmac_len;
        }
    }

    debug("fko_spa_data_final() : exiting function with return value: %d", res);
    return res;
}

/* Return the fko SPA encrypted data.
*/
int
fko_get_spa_data(fko_ctx_t ctx, char **spa_data)
{
#if HAVE_LIBFIU
    fiu_return_on("fko_get_spa_data_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(spa_data == NULL)
        return(FKO_ERROR_INVALID_DATA);

#if HAVE_LIBFIU
    fiu_return_on("fko_get_spa_data_val", FKO_ERROR_INVALID_DATA);
#endif

    /* We expect to have encrypted data to process.  If not, we bail.
    */
    if(ctx->encrypted_msg == NULL || ! is_valid_encoded_msg_len(
                strnlen(ctx->encrypted_msg, MAX_SPA_ENCODED_MSG_SIZE)))
        return(FKO_ERROR_MISSING_ENCODED_DATA);

#if HAVE_LIBFIU
    fiu_return_on("fko_get_spa_data_encoded", FKO_ERROR_MISSING_ENCODED_DATA);
#endif

    *spa_data = ctx->encrypted_msg;

    return(FKO_SUCCESS);
}

/* Set the fko SPA encrypted data.
*/
int
fko_set_spa_data(fko_ctx_t ctx, const char * const enc_msg)
{
    int         enc_msg_len;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    if(enc_msg == NULL)
        return(FKO_ERROR_INVALID_DATA_FUNCS_SET_MSGLEN_VALIDFAIL);

    enc_msg_len = strnlen(enc_msg, MAX_SPA_ENCODED_MSG_SIZE);

    if(! is_valid_encoded_msg_len(enc_msg_len))
        return(FKO_ERROR_INVALID_DATA_FUNCS_SET_MSGLEN_VALIDFAIL);

    if(ctx->encrypted_msg != NULL)
        free(ctx->encrypted_msg);

    /* First, add the data to the context.
    */
    ctx->encrypted_msg = strdup(enc_msg);
    ctx->encrypted_msg_len = enc_msg_len;

    if(ctx->encrypted_msg == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    return(FKO_SUCCESS);
}

#if AFL_FUZZING
/* provide a way to set the encrypted data directly without base64 encoding.
 * This allows direct AFL fuzzing against decryption routines.
*/
int
fko_afl_set_spa_data(fko_ctx_t ctx, const char * const enc_msg, const int enc_msg_len)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    if(enc_msg == NULL)
        return(FKO_ERROR_INVALID_DATA_FUNCS_SET_MSGLEN_VALIDFAIL);

    if(! is_valid_encoded_msg_len(enc_msg_len))
        return(FKO_ERROR_INVALID_DATA_FUNCS_SET_MSGLEN_VALIDFAIL);

    if(ctx->encrypted_msg != NULL)
        free(ctx->encrypted_msg);

    /* Copy the raw encrypted data into the context
    */
    ctx->encrypted_msg = calloc(1, enc_msg_len);
    if(ctx->encrypted_msg == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    memcpy(ctx->encrypted_msg, enc_msg, enc_msg_len);

    ctx->encrypted_msg_len = enc_msg_len;

    return(FKO_SUCCESS);
}
#endif

/***EOF***/
