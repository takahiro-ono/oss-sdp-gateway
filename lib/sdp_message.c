/*
 * sdp_message.c
 *
 *  Created on: Apr 5, 2016
 *      Author: Daniel Bailey
 */

#include "sdp_ctrl_client.h"

#include <unistd.h>
#include <json/json.h>
#include <string.h>
#include "sdp_message.h"
#include "sdp_log_msg.h"

// JSON message strings
const char *sdp_key_subj                = "sdpSubject";
const char *sdp_key_stage               = "stage";
const char *sdp_key_data                = "data";

const char *sdp_subj_keep_alive         = "keepAlive";
const char *sdp_subj_cred_update        = "memberCredentialUpdate";
const char *sdp_subj_gate_full_update   = "gateFullUpdate";
const char *sdp_subj_gate_small_update  = "gateSmallUpdate";
const char *sdp_subj_bad_message        = "badMessage";

const char *sdp_stage_error             = "error";
const char *sdp_stage_fulfilling        = "fulfilling";
const char *sdp_stage_requesting        = "requesting";
const char *sdp_stage_fulfilled         = "fulfilled";
const char *sdp_stage_unfulfilled       = "unfulfilled";



static int sdp_get_json_field(const char *key, json_object *jdata, char **r_field)
{
	json_object *jobj;

	// jdata should be an array containing multiple fields
	// use the key arg to extract a specific field
	if( !json_object_object_get_ex(jdata, key, &jobj))
	{
        log_msg(LOG_ERR, "Failed to find json data field with key: %s", key);
		return SDP_ERROR_INVALID_MSG;
	}

	if(json_object_get_type(jobj) != json_type_string)
	{
        log_msg(LOG_ERR,
        	"Found json data field with key %s BUT field was not json_type_string as expected",
			key);
		return SDP_ERROR_INVALID_MSG;
	}

	if((*r_field = strndup(json_object_get_string(jobj), SDP_MSG_FIELD_MAX_LEN)) == NULL)
	{
		return SDP_ERROR_MEMORY_ALLOCATION;
	}

	log_msg(LOG_DEBUG, "JSON parser extracted field value: %s", *r_field);

	return SDP_SUCCESS;
}

static int sdp_get_message_subject(json_object *jmsg, ctrl_subject_t *r_subject)
{
	int rv = SDP_ERROR_INVALID_MSG;
	char *subject_str = NULL;
	ctrl_subject_t subject = CTRL_SUBJ_NONE;

	if((rv = sdp_get_json_field(sdp_key_subj, jmsg, &subject_str)) != SDP_SUCCESS)
		return rv;

	if(strncmp(subject_str, sdp_subj_keep_alive, strlen(sdp_subj_keep_alive)) == 0)
		subject = CTRL_SUBJ_KEEP_ALIVE;

	else if(strncmp(subject_str, sdp_subj_cred_update, strlen(sdp_subj_cred_update)) == 0)
		subject = CTRL_SUBJ_MEMBER_CREDENTIAL_UPDATE;

	else if(strncmp(subject_str, sdp_subj_gate_full_update, strlen(sdp_subj_gate_full_update)) == 0)
		subject = CTRL_SUBJ_GATE_FULL_UPDATE;

	else if(strncmp(subject_str, sdp_subj_gate_small_update, strlen(sdp_subj_gate_small_update)) == 0)
		subject = CTRL_SUBJ_GATE_SMALL_UPDATE;

	else if(strncmp(subject_str, sdp_subj_bad_message, strlen(sdp_subj_bad_message)) == 0)
		subject = CTRL_SUBJ_BAD_MESSAGE;

	free(subject_str);

	if(subject == CTRL_SUBJ_NONE)
		return rv;

	*r_subject = subject;
	return SDP_SUCCESS;
}

static int sdp_get_message_stage(json_object *jmsg, ctrl_stage_t *r_stage)
{
	int rv = SDP_ERROR_INVALID_MSG;
	char *stage_str = NULL;
	ctrl_stage_t stage = CTRL_STAGE_NONE;

	if((rv = sdp_get_json_field(sdp_key_stage, jmsg, &stage_str)) != SDP_SUCCESS)
		return rv;

	if(strncmp(stage_str, sdp_stage_fulfilling, strlen(sdp_stage_fulfilling)) == 0)
		stage = CTRL_STAGE_FULFILLING;

	else if(strncmp(stage_str, sdp_stage_error, strlen(sdp_stage_error)) == 0)
		stage = SDP_ERROR;

	free(stage_str);

	if(stage == CTRL_STAGE_NONE)
		return rv;

	*r_stage = stage;
	return SDP_SUCCESS;
}


int  sdp_message_make(const char *subject, const char *stage, char **r_out_msg)
{
	char *out_msg = NULL;
	json_object *jout_msg = json_object_new_object();

	if(jout_msg == NULL)
		return SDP_ERROR_MEMORY_ALLOCATION;

	if(subject == NULL)
		return SDP_ERROR_INVALID_MSG;

	json_object_object_add(jout_msg, sdp_key_subj,  json_object_new_string(subject));

	if(stage != NULL)
		json_object_object_add(jout_msg, sdp_key_stage, json_object_new_string(stage));

	out_msg = strndup(json_object_to_json_string(jout_msg), SDP_MSG_MAX_LEN);

	json_object_put(jout_msg);

	if(out_msg == NULL)
		return SDP_ERROR_MEMORY_ALLOCATION;

	*r_out_msg = out_msg;
	return SDP_SUCCESS;
}


int sdp_message_process(const char *msg, ctrl_response_result_t *r_result, void **r_data)
{
	json_object *jmsg, *jdata;
	int rv = SDP_ERROR_INVALID_MSG;
	ctrl_response_result_t result = BAD_RESULT;
	ctrl_subject_t subject = CTRL_SUBJ_NONE;
	ctrl_stage_t stage = CTRL_STAGE_NONE;

	// parse the msg string into json objects
	jmsg = json_tokener_parse(msg);

	// find and interpret the message subject
	if(sdp_get_message_subject(jmsg, &subject) != SDP_SUCCESS)
		goto cleanup;

	// if it's keep alive, nothing else to parse
	if(subject == CTRL_SUBJ_KEEP_ALIVE)
	{
		result = KEEP_ALIVE_FULFILLING;
		goto cleanup;
	}

	// find and interpret message stage field
	if(sdp_get_message_stage(jmsg, &stage) != SDP_SUCCESS)
		goto cleanup;

	// if data field is missing, flunk out
	if( !json_object_object_get_ex(jmsg, sdp_key_data, &jdata))
		goto cleanup;

	log_msg(LOG_DEBUG, "Data portion of controller's message:");
	log_msg(LOG_DEBUG, "%s", json_object_to_json_string_ext(jdata, JSON_C_TO_STRING_PRETTY));


	if(subject == CTRL_SUBJ_MEMBER_CREDENTIAL_UPDATE)
	{
		log_msg(LOG_WARNING, "Received credential update message");

		if(stage == CTRL_STAGE_FULFILLING)
		{
			log_msg(LOG_WARNING, "Controller attempting to update credentials");

			if((rv = sdp_message_parse_cred_fields(jdata, r_data)) != SDP_SUCCESS)
			{
				log_msg(LOG_ERR, "Failed to parse new credential data");
			}
			else
			{
				result = CREDS_FULFILLING;
			}
			//*r_jdata = json_object_get(jdata);
			//result = CREDS_FULFILLING;
		}
		else
		{
			log_msg(LOG_ERR, "Controller not updating credentials");
			result = CREDS_UNFULFILLING;
		}
	}
	else if(subject == CTRL_SUBJ_GATE_FULL_UPDATE)
	{
		log_msg(LOG_WARNING, "Received full gate update message");

		if(stage == CTRL_STAGE_FULFILLING)
		{
			log_msg(LOG_WARNING, "Controller attempting to update entire database");

			/*
			if((rv = sdp_message_parse_full_database_update(jdata, r_data)) != SDP_SUCCESS)
			{
				log_msg(LOG_ERR, "Failed to parse data");
			}
			else
			{
				result = ACCESS_FULFILLING;
			}
			*/
			//*r_jdata = json_object_get(jdata);
			result = ACCESS_FULFILLING;
		}
		else
		{
			log_msg(LOG_ERR, "Controller not updating database");
			result = ACCESS_UNFULFILLING;
		}
	}
	else if(subject == CTRL_SUBJ_GATE_SMALL_UPDATE)
	{
		log_msg(LOG_WARNING, "Received partial gate update message");

		if(stage == CTRL_STAGE_FULFILLING)
		{
			log_msg(LOG_WARNING, "Controller attempting to make partial update to database");

			/*
			if((rv = sdp_message_parse_small_database_update(jdata, r_data)) != SDP_SUCCESS)
			{
				log_msg(LOG_ERR, "Failed to parse data");
			}
			else
			{
				result = SMALL_UPDATE_FULFILLING;
			}
			*/
			//*r_jdata = json_object_get(jdata);
			result = SMALL_UPDATE_FULFILLING;
		}
		else
		{
			log_msg(LOG_ERR, "Controller not updating database");
			result = SMALL_UPDATE_UNFULFILLING;
		}
	}
	else if(subject == CTRL_SUBJ_BAD_MESSAGE)
	{
		result = ERROR_MESSAGE;
		log_msg(LOG_ERR, "Received notice from controller that it received the following bad message:");
		log_msg(LOG_ERR, "%s", json_object_to_json_string_ext(jdata, JSON_C_TO_STRING_PRETTY));
	}


cleanup:

	// free the main json message object
	// if the message was good, jdata already
	// holds a ref to just the data portion
	json_object_put(jmsg);

	if(result != BAD_RESULT)
	{
		*r_result = result;
		rv = SDP_SUCCESS;
	}

	return rv;
}


int sdp_message_parse_cred_fields(json_object *jdata, void **r_creds)
{
	sdp_creds_t creds = NULL;
	int rv = SDP_ERROR_INVALID_MSG;

	if(jdata == NULL)
	{
		log_msg(LOG_ERR, "Trying to parse credential fields, but jdata is NULL");
		return rv;
	}

	// allocate memory
	if((creds = calloc(1, sizeof *creds)) == NULL)
		return (SDP_ERROR_MEMORY_ALLOCATION);

	// extract encryption key
	if((rv = sdp_get_json_field("encryptionKey", jdata, &(creds->encryption_key))) != SDP_SUCCESS)
		goto error;

	// extract hmac key
	if((rv = sdp_get_json_field("hmacKey", jdata, &(creds->hmac_key))) != SDP_SUCCESS)
		goto error;

	// extract tls client cert
	if((rv = sdp_get_json_field("tlsClientCert", jdata, &(creds->tls_client_cert))) != SDP_SUCCESS)
		goto error;

	// extract tls client key
	if((rv = sdp_get_json_field("tlsClientKey", jdata, &(creds->tls_client_key))) != SDP_SUCCESS)
		goto error;

	// if we got here, all is good
	// provide the credentials structure
	*r_creds = (void*)creds;
	return SDP_SUCCESS;

error:
	sdp_message_destroy_creds(creds);
	return rv;
}

void sdp_message_destroy_creds(sdp_creds_t creds)
{
	if(creds == NULL)
		return;

	if(creds->encryption_key != NULL)
		free(creds->encryption_key);

	if(creds->hmac_key != NULL)
		free(creds->hmac_key);

	if(creds->tls_client_cert != NULL)
		free(creds->tls_client_cert);

	if(creds->tls_client_key != NULL)
		free(creds->tls_client_key);

	free(creds);
}


