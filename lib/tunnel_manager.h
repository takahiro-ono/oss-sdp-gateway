/*
 * tunnel_manager.h
 *
 *  Created on: Jun 27, 2017
 *      Author: Daniel Bailey
 */

#ifndef TUNNEL_MANAGER_H_
#define TUNNEL_MANAGER_H_

#include <uv.h>

struct tunnel_info{
    int x;
    struct tunnel_info *next;
};
typedef struct tunnel_info *tunnel_info_t;

struct tunnel_manager{
    uv_loop_t *loop;
    uv_pipe_t *tm_pipe;
    int tm_sock_fd;
    //uv_pipe_t *pipe_to_tm;
    //int read_pipe_to_tunnel_manager;
	//int write_pipe_to_tunnel_manager;
    //int read_pipe_from_tunnel_manager;
	//int write_pipe_from_tunnel_manager;
	hash_table_t *tunnel_hash_tbl;
	hash_table_t *waiting_tunnel_hash_tbl;
};
typedef struct tunnel_manager *tunnel_manager_t;


typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;



void tunnel_manager_destroy(tunnel_manager_t tunnel_mgr);
int tunnel_manager_new(int tbl_len, tunnel_manager_t *r_tunnel_mgr);
int tunnel_manager_connect_pipe(tunnel_manager_t tunnel_mgr);

#endif /* SERVER_TUNNEL_MANAGER_H_ */
