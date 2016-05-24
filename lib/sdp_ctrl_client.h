/*
 * sdp_ctrl_client.h
 *
 *  Created on: Mar 28, 2016
 *      Author: hydrolucid3
 */

#ifndef SDP_CTRL_CLIENT_H_
#define SDP_CTRL_CLIENT_H_

#include <signal.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include "sdp_com.h"
#include "sdp_errors.h"
#include "sdp_message.h"


extern sig_atomic_t sdp_ctrl_client_got_signal;

extern sig_atomic_t sdp_ctrl_client_got_sighup;
extern sig_atomic_t sdp_ctrl_client_got_sigint;
extern sig_atomic_t sdp_ctrl_client_got_sigterm;
extern sig_atomic_t sdp_ctrl_client_got_sigusr1;
extern sig_atomic_t sdp_ctrl_client_got_sigusr2;
extern sig_atomic_t sdp_ctrl_client_got_sigchld;




#define YES_OR_NO(I) (I == 0 ? "NO" : "YES")

typedef enum {
	SDP_CTRL_CLIENT_STATE_READY,
	SDP_CTRL_CLIENT_STATE_KEEP_ALIVE_REQUESTING,
	SDP_CTRL_CLIENT_STATE_KEEP_ALIVE_UNFULFILLED,
	SDP_CTRL_CLIENT_STATE_CRED_REQUESTING,
	SDP_CTRL_CLIENT_STATE_CRED_FULFILLED,
	SDP_CTRL_CLIENT_STATE_CRED_UNFULFILLED,
	SDP_CTRL_CLIENT_STATE_FULL_UPDATE_REQUESTING,
	SDP_CTRL_CLIENT_STATE_FULL_UPDATE_FULFILLED,
	SDP_CTRL_CLIENT_STATE_FULL_UPDATE_UNFULFILLED,
	SDP_CTRL_CLIENT_STATE_NEED_RECONNECT,
	SDP_CTRL_CLIENT_STATE_TIME_TO_QUIT,
} sdp_ctrl_client_state_t;


struct sdp_ctrl_client{
	char *config_file;
	int   initialized;
	sdp_com_t com;
	int   remain_connected;
	int   foreground;
	int   use_syslog;
	int   verbosity;

	sdp_ctrl_client_state_t client_state;

	int keep_alive_interval;

	time_t initial_conn_time;
	time_t last_contact;
	time_t last_cred_update;
	time_t last_access_update;
	time_t last_req_time;
	time_t last_failed_req_time;
	int cred_update_interval;
	int access_update_interval;
	int max_req_attempts;
	int req_attempts;
	int initial_req_retry_interval;
	int req_retry_interval;
	int pid;
	char *pid_file;
	int pid_lock_fd;
	unsigned int message_queue_len;
};

typedef struct sdp_ctrl_client *sdp_ctrl_client_t;

int  sdp_ctrl_client_new(const char *config_file, const char *fwknoprc_file, sdp_ctrl_client_t *r_client);
void sdp_ctrl_client_destroy(sdp_ctrl_client_t client);
int  sdp_ctrl_client_start(sdp_ctrl_client_t client, pid_t *r_child_pid);
int  sdp_ctrl_client_stop(sdp_ctrl_client_t client);
int  sdp_ctrl_client_restart(sdp_ctrl_client_t client);
int  sdp_ctrl_client_connect(sdp_ctrl_client_t client);
int  sdp_ctrl_client_disconnect(sdp_ctrl_client_t client);
int  sdp_ctrl_client_status(sdp_ctrl_client_t client);
void sdp_ctrl_client_describe(sdp_ctrl_client_t client);
int  sdp_ctrl_client_get_port(sdp_ctrl_client_t client, int *r_port);
int  sdp_ctrl_client_get_addr(sdp_ctrl_client_t client, char **r_addr);
int  sdp_ctrl_client_check_inbox(sdp_ctrl_client_t client);
int  sdp_ctrl_client_request_keep_alive(sdp_ctrl_client_t client);
void sdp_ctrl_client_process_keep_alive(sdp_ctrl_client_t client);
int  sdp_ctrl_client_request_cred_update(sdp_ctrl_client_t client);
int  sdp_ctrl_client_process_cred_update(sdp_ctrl_client_t client, void *credentials);
int  sdp_ctrl_client_consider_keep_alive(sdp_ctrl_client_t client);
int  sdp_ctrl_client_consider_cred_update(sdp_ctrl_client_t client);

#endif /* SDP_CTRL_CLIENT_H_ */
