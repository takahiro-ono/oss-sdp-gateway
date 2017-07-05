/*
 * control_client.c
 *
 *  Created on: Jun 29, 2017
 *      Author: Daniel Bailey
 */

//#include "utils.h"
//#include "config_init.h"
#include <json-c/json.h>
#include "fwknop_common.h"
#include "log_msg.h"
#include "sdp_ctrl_client.h"
#include "control_client.h"
#include "fko.h"

/*
static int process_data_msg(fko_cli_options_t *opts, int action, json_object *jdata)
{
    int rv = FKO_SUCCESS;

    if(
        action == CTRL_ACTION_CLIENT_SERVICE_REMOVE  ||
        action == CTRL_ACTION_CLIENT_SERVICE_REFRESH ||
        action == CTRL_ACTION_CLIENT_SERVICE_UPDATE
    )
    {
        rv = process_client_service_msg(opts, action, jdata);

        // arriving here means we got and attempted to process a client service data message
        if(rv != FKO_SUCCESS)
        {
            log_msg(LOG_ERR, "Failed to get client service data from controller.");
            sdp_ctrl_client_send_data_error(opts->ctrl_client);
        }
        else
        {
            if(action == CTRL_ACTION_CLIENT_SERVICE_REFRESH)
                log_msg(LOG_INFO, "Succeeded in retrieving and installing client service configuration");
            else
                log_msg(LOG_INFO, "Succeeded in modifying client service data.");
            sdp_ctrl_client_send_data_ack(opts->ctrl_client, CTRL_ACTION_CLIENT_SERVICE_ACK);
        }
    }

    return rv;
}


static int handle_data_msg(fko_cli_options_t *opts, int action, json_object *jdata)
{
    int rv = FKO_SUCCESS;

    // if a data message is received, process that
    if((rv = process_data_msg(opts, action, jdata)) == FKO_ERROR_MUTEX)
    {
        log_msg(LOG_ERR, "SDP Control Client thread mutex error. Aborting.");

        return rv;
    }
    else if(rv == FKO_ERROR_MEMORY_ALLOCATION)
    {
        log_msg(LOG_ERR, "SDP Control Client thread memory allocation error. Aborting.");

        return rv;
    }
    else if(rv != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "Error processing data from controller. Carrying on.");
        //sdp_ctrl_client_send_data_error(opts->ctrl_client);
    }
    else
    {
        //log_msg(LOG_INFO, "Succeeded in modifying access data.");
        //sdp_ctrl_client_send_access_ack(opts->ctrl_client);

        if(opts->verbose > 1 && opts->foreground)
        {
            dump_service_list(opts);
        }
    }

    return FWKNOPD_SUCCESS;
}
*/


int get_updated_credentials_from_controller(fko_cli_options_t *opts)
{
    int rv = SDP_SUCCESS;
    int action = INVALID_CTRL_ACTION;
    json_object *jdata = NULL;
    time_t stop_time = time(NULL) + 30;

    if(opts == NULL)
    {
        log_msg(LOG_ERR, "fwknop not properly initialized");
        return SDP_ERROR_UNINITIALIZED;
    }

    if((rv = sdp_ctrl_client_new(opts->sdp_ctrl_client_config_file,
                opts->rc_file, opts->foreground, &(opts->ctrl_client))) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Failed to create new SDP ctrl client");
        return rv;
    }

    while(1)
    {
        // connect if necessary
        if(sdp_ctrl_client_connection_status(opts->ctrl_client) == SDP_COM_DISCONNECTED)
        {
            if((rv = sdp_ctrl_client_connect(opts->ctrl_client)) != SDP_SUCCESS)
            {
                return rv;
            }
        }

        // check for incoming messages
        if((rv = sdp_ctrl_client_check_inbox(opts->ctrl_client, &action, (void**)&jdata)) != SDP_SUCCESS)
            return rv;

        // if data was returned, process it
        if(jdata != NULL)
        {
            log_msg(LOG_DEBUG, "sdp_ctrl_client_check_inbox returned management data, processing");

            //rv = process_data_msg(opts, action, jdata);

            if(jdata != NULL && json_object_get_type(jdata) != json_type_null)
            {
                json_object_put(jdata);
                jdata = NULL;
            }
        }

        if(action == CTRL_ACTION_CREDENTIAL_UPDATE)
            return SDP_SUCCESS;
        
        // reset action
        action = INVALID_CTRL_ACTION;

        // do not begin sending requests until controller is ready
        if( !(sdp_ctrl_client_controller_status(opts->ctrl_client)) )
            continue;

        // if new connection or just time, update credentials
        if((rv = sdp_ctrl_client_consider_cred_update(opts->ctrl_client)) != SDP_SUCCESS)
            return rv;

        // watch the time
        if( (time(NULL) > stop_time) )
        {
            // if we timed out, then we did not get the credential update we needed
            log_msg(LOG_ERR, "Failed to get credential update from controller.");
            return SDP_ERROR_CRED_REQ;
        }

        sleep(1);
    }

    return rv;
}



static void *control_client_thread_func(void *arg)
{
    int rv = FKO_SUCCESS;
    int action = INVALID_CTRL_ACTION;
    json_object *jdata = NULL;
    fko_cli_options_t *opts = (fko_cli_options_t*)arg;

    if(opts == NULL ||
       opts->ctrl_client == NULL ||
       opts->ctrl_client->initialized != 1 ||
       opts->tunnel_mgr == NULL)
    {
        log_msg(LOG_ERR, "Attempted to start SDP control client "
                "thread without proper initializations. Aborting.");

        // send kill signal for main thread to catch and exit safely
        kill(getpid(), SIGTERM);
        return NULL;
    }

    //if((rv = tunnel_manager_connect_pipe(opts->tunnel_mgr)) != FKO_SUCCESS)
    //{
    //    log_msg(LOG_ERR, "Ctrl Client failed on attempt to connect to Tunnel Manager");
    //
    //    // send kill signal for main thread to catch and exit safely
    //    kill(getpid(), SIGTERM);
    //    return NULL;
    //}


    while(1)
    {
        // connect if necessary
        if(sdp_ctrl_client_connection_status(opts->ctrl_client) == SDP_COM_DISCONNECTED)
        {
            if((rv = sdp_ctrl_client_connect(opts->ctrl_client)) != SDP_SUCCESS)
            {
                break;
            }

        }

        // check for incoming messages
        if((rv = sdp_ctrl_client_check_inbox(opts->ctrl_client, &action, (void**)&jdata)) != SDP_SUCCESS)
            break;

        // if data was returned, process it
        if(jdata != NULL)
        {
            log_msg(LOG_DEBUG, "sdp_ctrl_client_check_inbox returned data, processing");

            //rv = handle_data_msg(opts, action, jdata);

            if(jdata != NULL && json_object_get_type(jdata) != json_type_null)
            {
                json_object_put(jdata);
                jdata = NULL;
            }

            if(rv != FKO_SUCCESS)
                break;

        }

        // do not begin sending requests until controller is ready
        if( !(sdp_ctrl_client_controller_status(opts->ctrl_client)) )
            continue;

        // if new connection or just time, update credentials
        if((rv = sdp_ctrl_client_consider_cred_update(opts->ctrl_client)) != SDP_SUCCESS)
            break;

        // if built for remote gateway, handle service updates
        //if((rv = sdp_ctrl_client_consider_client_service_refresh(opts->ctrl_client)) != SDP_SUCCESS)
        //    break;

        // is a keep alive due
        if((rv = sdp_ctrl_client_consider_keep_alive(opts->ctrl_client)) != SDP_SUCCESS)
            break;

        sleep(1);
    }

    // send kill signal for main thread to catch and exit safely
    kill(getpid(), SIGTERM);

    return NULL;
}


int start_control_client(fko_cli_options_t *opts)
{
    int rv = SDP_SUCCESS;

    if(opts == NULL)
    {
        log_msg(LOG_ERR, "Attempted to start SDP control client "
                "thread without proper initializations. Aborting.");

        return SDP_ERROR_UNINITIALIZED;
    }

    if(opts->ctrl_client == NULL)
    {
        if((rv = sdp_ctrl_client_new(opts->sdp_ctrl_client_config_file,
                    opts->rc_file, opts->foreground, &(opts->ctrl_client))) != SDP_SUCCESS)
        {
            log_msg(LOG_ERR, "Failed to create new SDP ctrl client");
            return rv;
        }
    }

    sdp_ctrl_client_describe(opts->ctrl_client);

    if((rv = pthread_create( &(opts->ctrl_client_thread), NULL, control_client_thread_func, (void*)opts)) != 0)
    {
        log_msg(LOG_ERR, "Failed to start Control Client Thread. Aborting.");
        return rv;
    }
    else
    {
        log_msg(LOG_INFO, "Successfully started Control Client Thread.");
    }


    return FKO_SUCCESS;

}

void stop_control_client(fko_cli_options_t *opts)
{
    // kill thread
    if(opts->ctrl_client != NULL)
    {
        if(opts->ctrl_client_thread > 0)
        {
            log_msg(LOG_WARNING, "Definitely stopping Control Client thread...");

            pthread_cancel(opts->ctrl_client_thread);
            pthread_join(opts->ctrl_client_thread, NULL);
            opts->ctrl_client_thread = 0;

            log_msg(LOG_WARNING, "Control Client thread stopped");
        }
        else
        {
            log_msg(LOG_WARNING, "Control Client thread not found");
        }
    }    
}


void destroy_control_client(fko_cli_options_t *opts)
{
    // kill thread
    if(opts->ctrl_client != NULL)
    {
        log_msg(LOG_WARNING, "Destroying Control Client...");

        if(opts->ctrl_client_thread > 0)
        {
            log_msg(LOG_WARNING, "Stopping Control Client thread...");

            stop_control_client(opts);
        }
        else
        {
            log_msg(LOG_WARNING, "Control Client thread not found");
        }

        sdp_ctrl_client_destroy(opts->ctrl_client);

        log_msg(LOG_WARNING, "Control Client destroyed");
    }
    else
    {
        log_msg(LOG_WARNING, "Control Client not found");
    }
}


