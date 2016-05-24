/*
 * sdp_message.h
 *
 *  Created on: Apr 5, 2016
 *      Author: Daniel Bailey
 */

#ifndef SDP_MESSAGE_H_
#define SDP_MESSAGE_H_

#include <json/json.h>

typedef enum {
	CTRL_SUBJ_NONE,
	CTRL_SUBJ_KEEP_ALIVE,
	CTRL_SUBJ_MEMBER_CREDENTIAL_UPDATE,
	CTRL_SUBJ_GATE_FULL_UPDATE,
	CTRL_SUBJ_GATE_SMALL_UPDATE,
	CTRL_SUBJ_BAD_MESSAGE
} ctrl_subject_t;

typedef enum {
	CTRL_STAGE_NONE,
	CTRL_STAGE_FULFILLING,
	CTRL_STAGE_ERROR
} ctrl_stage_t;

typedef enum {
	BAD_RESULT,
	KEEP_ALIVE_FULFILLING,
	CREDS_UNFULFILLING,
	CREDS_FULFILLING,
	ACCESS_UNFULFILLING,
	ACCESS_FULFILLING,
	SMALL_UPDATE_FULFILLING,
	SMALL_UPDATE_UNFULFILLING,
	ERROR_MESSAGE
} ctrl_response_result_t;



enum {
	SDP_MSG_MIN_LEN = 26,
	SDP_MSG_FIELD_MAX_LEN = 65536,
	SDP_MSG_MAX_LEN = 65536
};


struct sdp_creds{
    char *encryption_key;
    char *hmac_key;
    char *tls_client_key;
    char *tls_client_cert;
};

typedef struct sdp_creds *sdp_creds_t;

// JSON message strings
extern const char *sdp_key_subj;
extern const char *sdp_key_stage;
extern const char *sdp_key_data;

extern const char *sdp_subj_keep_alive;
extern const char *sdp_subj_cred_update;
extern const char *sdp_subj_gate_full_update;
extern const char *sdp_subj_gate_small_update;
extern const char *sdp_subj_bad_message;

extern const char *sdp_stage_error;
extern const char *sdp_stage_fulfilling;
extern const char *sdp_stage_requesting;
extern const char *sdp_stage_fulfilled;
extern const char *sdp_stage_unfulfilled;

extern const char *sdp_msg_keep_alive;
extern const char *sdp_msg_cred_req;
extern const char *sdp_msg_cred_fulfilled;
extern const char *sdp_msg_cred_unfulfilled;


int  sdp_message_make(const char *subject, const char *stage, char **r_out_msg);
int  sdp_message_process(const char *msg, ctrl_response_result_t *r_result, void **r_data); //json_object **r_jdata);
int  sdp_message_parse_cred_fields(json_object *jdata, void **r_creds);
void sdp_message_destroy_creds(sdp_creds_t creds);


#endif /* SDP_MESSAGE_H_ */
