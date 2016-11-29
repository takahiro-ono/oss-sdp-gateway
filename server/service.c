/*
 * service.c
 *
 *  Created on: Nov 26, 2016
 *      Author: Daniel Bailey
 */

#include <json-c/json.h>
#include "fwknopd_common.h"
#include "log_msg.h"
#include "hash_table.h"
#include "fwknopd_errors.h"
#include "sdp_ctrl_client.h"
#include "bstrlib.h"
#include "service.h"


//static void free_service_data(service_data_t *data)
//{
//
//}


static void destroy_service_hash_node_cb(hash_table_node_t *node)
{
    if(node->key != NULL) bdestroy((bstring)(node->key));
    if(node->data != NULL)
    {
        //free_service_data((service_data_t*)(node->data));
        free(node->data);
    }
}


static int traverse_dump_service_cb(hash_table_node_t *node, void *dest)
{
    service_data_t *service_data = (service_data_t *)(node->data);

    fprintf((FILE*)dest,
        "SERVICE ID:  %"PRIu32"\n"
        "==============================================================\n"
        "             PROTO:  %s\n"
        "              PORT:  %d\n"
        "    NAT IP ADDRESS:  %s\n"
        "          NAT PORT:  %d\n",
        service_data->service_id,
        (service_data->proto == PROTO_TCP) ? "TCP" : "UDP",
        service_data->port,
        (service_data->nat_ip_str[0] == 0) ? "<not set>" : service_data->nat_ip_str,
        service_data->nat_port
    );

    fprintf((FILE*)dest, "\n");

    return 0;
}



// create table
int create_service_table(fko_srv_options_t *opts)
{
    int is_err = 0;
    int hash_table_len = 0;

    hash_table_len = strtol_wrapper(opts->config[CONF_SERVICE_HASH_TABLE_LENGTH],
                           MIN_SERVICE_HASH_TABLE_LENGTH,
                           MAX_SERVICE_HASH_TABLE_LENGTH,
                           NO_EXIT_UPON_ERR,
                           &is_err);

    if(is_err != FKO_SUCCESS)
    {
        // this error should be impossible because the config variable
        // is checked at startup

        log_msg(LOG_ERR, "[*] var %s value '%s' not in the range %d-%d",
                "SERVICE_HASH_TABLE_LENGTH",
                opts->config[CONF_SERVICE_HASH_TABLE_LENGTH],
                MIN_SERVICE_HASH_TABLE_LENGTH,
                MAX_SERVICE_HASH_TABLE_LENGTH);

        return FWKNOPD_ERROR_BAD_CONFIG;
    }

    opts->service_hash_tbl = hash_table_create(hash_table_len,
            NULL, NULL, destroy_service_hash_node_cb);

    if(opts->service_hash_tbl == NULL)
    {
        log_msg(LOG_ERR,
            "[*] Fatal memory allocation error creating service hash table"
        );
        return FKO_ERROR_MEMORY_ALLOCATION;
    }

    return FWKNOPD_SUCCESS;
}


// destroy table
void destroy_service_table(fko_srv_options_t *opts)
{
    if(opts->service_hash_tbl != NULL)
    {
        // lock the hash table mutex
        if(pthread_mutex_lock(&(opts->service_hash_tbl_mutex)))
        {
            log_msg(LOG_ERR, "Mutex lock error.");
        }
        else
        {
            hash_table_destroy(opts->service_hash_tbl);
            opts->service_hash_tbl = NULL;
            pthread_mutex_unlock(&(opts->service_hash_tbl_mutex));
            pthread_mutex_destroy(&(opts->service_hash_tbl_mutex));
        }
    }
}

/* Take a json doc and make service data struct from it
 *
 */
static int make_service_data_from_json(fko_srv_options_t *opts, json_object *jdata, service_data_t **r_service_data)
{
    int rv = SDP_SUCCESS;
    char *tmp = NULL;
    int str_len = 0;
    service_data_t *service_data = calloc(1, sizeof(service_data_t));

    if((rv = sdp_get_json_int_field("service_id", jdata, (int*)&(service_data->service_id))) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Did not find SDP Service ID in service data stanza, invalid service data entry");
        goto cleanup;
    }


    if((rv = sdp_get_json_string_field("proto", jdata, &tmp)) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Did not find service protocol in service data stanza, invalid service data entry");
        goto cleanup;
    }

    if((str_len = strnlen(tmp, MAX_PROTO_STR_LEN+1)) > MAX_PROTO_STR_LEN)
    {
        log_msg(LOG_ERR, "Service protocol string too long, invalid service data entry");
        rv = FWKNOPD_ERROR_BAD_SERVICE_DATA;
        goto cleanup;
    }

    if(strcasecmp(tmp, "tcp") == 0)
        service_data->proto = PROTO_TCP;
    else if(strcasecmp(tmp, "udp") == 0)
        service_data->proto = PROTO_UDP;
    else
    {
        log_msg(LOG_ERR,
            "[*] Invalid protocol in service data entry: %s", tmp);
        goto cleanup;
    }

    free(tmp);
    tmp = NULL;

    if((rv = sdp_get_json_int_field("port", jdata, (int*)&(service_data->port))) != SDP_SUCCESS)
    {
        log_msg(LOG_ERR, "Did not find service port in service data stanza, invalid service data entry");
        goto cleanup;
    }

    if((rv = sdp_get_json_string_field("nat_ip", jdata, &tmp)) != SDP_SUCCESS)
    {
    	// this service stanza has no NAT info, that's no problem
    	rv = SDP_SUCCESS;
    }
    else
    {
        if((str_len = strnlen(tmp, MAX_IPV4_STR_LEN+1)) > MAX_IPV4_STR_LEN)
        {
            log_msg(LOG_ERR, "Service NAT IP string too long, invalid service data entry");
            rv = FWKNOPD_ERROR_BAD_SERVICE_DATA;
            goto cleanup;
        }

        if(str_len < MIN_IPV4_STR_LEN)
        {
            log_msg(LOG_ERR, "Service NAT IP string too short, invalid service data entry");
            rv = FWKNOPD_ERROR_BAD_SERVICE_DATA;
            goto cleanup;
        }

        memcpy(service_data->nat_ip_str, tmp, str_len);
        free(tmp);
        tmp = NULL;

        if((rv = sdp_get_json_int_field("nat_port", jdata, (int*)&(service_data->nat_port))) != SDP_SUCCESS)
        {
            log_msg(LOG_ERR, "Found service NAT IP string, but did not find service nat port in service data stanza, invalid stanza entry");
            goto cleanup;
        }
    }


cleanup:
    if(tmp != NULL)
        free(tmp);

    if(rv != SDP_SUCCESS)
    {
        //free_service_data(service_data);
        free(service_data);
        *r_service_data = NULL;
    }
    else
    {
        *r_service_data = service_data;
    }
    return rv;
}



// modify table
static int modify_service_table(fko_srv_options_t *opts, int service_array_len, json_object *jdata)
{
    int rv = FWKNOPD_SUCCESS;
    int idx = 0;
    int nodes = 0;
    json_object *jservice = NULL;
    bstring key = NULL;
    service_data_t *new_service = NULL;
    char id[SDP_MAX_SERVICE_ID_STR_LEN + 1] = {0};

    // walk through the access array
    for(idx = 0; idx < service_array_len; idx++)
    {
        jservice = json_object_array_get_idx(jdata, idx);
        if((rv = make_service_data_from_json(opts, jservice, &new_service)) != FWKNOPD_SUCCESS)
        {
            if(rv == FKO_ERROR_MEMORY_ALLOCATION)
            {
                log_msg(LOG_ERR, "Memory allocation error while parsing json data, time to die");
                return FKO_ERROR_MEMORY_ALLOCATION;
            }

            log_msg(LOG_ERR, "Failed to parse json service data, attempting to carry on");
            continue;
        }

        // convert the service id integer to a bstring
        snprintf(id, SDP_MAX_SERVICE_ID_STR_LEN, "%"PRIu32, new_service->service_id);
        key = bfromcstr(id);

        if( hash_table_set(opts->service_hash_tbl, key, new_service) != FKO_SUCCESS )
        {
            log_msg(LOG_ERR,
                "Fatal error creating service hash table node"
            );
            bdestroy(key);
            free(new_service);
            return FKO_ERROR_MEMORY_ALLOCATION;
        }

        log_msg(LOG_NOTICE, "Added service entry for Service ID %"PRIu32, new_service->service_id);
        nodes++;
    }

    if(nodes > 0)
    {
        log_msg(LOG_INFO, "Created %d service hash table nodes from %d json stanzas", nodes, service_array_len);
        rv = FWKNOPD_SUCCESS;
    }
    else
        log_msg(LOG_WARNING, "Failed to create any service hash table nodes from %d json stanzas", service_array_len);

    return rv;

}


static void remove_service_data_nodes(hash_table_t *service_tbl, int service_array_len, json_object *jdata)
{
    int rv = FKO_SUCCESS;
    int idx;
    int service_id = 0;
    json_object *jentry = NULL;
    bstring key = NULL;
    char id[SDP_MAX_SERVICE_ID_STR_LEN + 1] = {0};

    // walk through the access array
    for(idx = 0; idx < service_array_len; idx++)
    {
        jentry = json_object_array_get_idx(jdata, idx);
        if((rv = sdp_get_json_int_field("service_id", jentry, &service_id)) != SDP_SUCCESS)
        {
            log_msg(LOG_ERR, "Did not find service_id field in data array entry.");
            continue;
        }

        // convert the service id integer to a bstring
        snprintf(id, SDP_MAX_SERVICE_ID_STR_LEN, "%d", service_id);
        key = bfromcstr(id);

        if( hash_table_delete(service_tbl, key) != FKO_SUCCESS )
        {
            log_msg(LOG_WARNING, "Did not find hash table node with service ID %d to remove. Continuing.", service_id);
        }
        else
        {
            log_msg(LOG_NOTICE, "Removed access stanza for service ID %d from service list.", service_id);
        }

        bdestroy(key);
    }
}


/* Take a json data array from a controller message
 * Alter/recreate the hash table based on the action
 */
int process_service_msg(fko_srv_options_t *opts, int action, json_object *jdata)
{
    int rv = FWKNOPD_SUCCESS;
    int service_array_len = 0;

    if(jdata == NULL || json_object_get_type(jdata) == json_type_null)
    {
        log_msg(LOG_ERR, "process_service_msg(): jdata is invalid");
        return FWKNOPD_ERROR_BAD_MSG;
    }

    service_array_len = json_object_array_length(jdata);
    if(service_array_len <= 0)
    {
        log_msg(LOG_ERR, "Received service message with zero length data array.");
        return FWKNOPD_ERROR_BAD_MSG;
    }

    log_msg(LOG_DEBUG, "jdata contains %d objects", service_array_len);


    // lock the hash table mutex
    if(pthread_mutex_lock(&(opts->service_hash_tbl_mutex)))
    {
        log_msg(LOG_ERR, "Service table mutex lock error.");
        return FWKNOPD_ERROR_MUTEX;
    }

    if(action == CTRL_ACTION_SERVICE_REMOVE)
    {
        if(opts->service_hash_tbl == NULL)
        {
            //table is not initialized, nothing to do
            log_msg(LOG_WARNING, "Received service remove message, but service table not "
                    "initialized. Nothing to do.");
            pthread_mutex_unlock(&(opts->service_hash_tbl_mutex));
            return FWKNOPD_ERROR_UNTIMELY_MSG;
        }

        remove_service_data_nodes(opts->service_hash_tbl, service_array_len, jdata);
        pthread_mutex_unlock(&(opts->service_hash_tbl_mutex));

        return FWKNOPD_SUCCESS;
    }

    // if this is service data refresh, destroy the hash table
    if(action == CTRL_ACTION_SERVICE_REFRESH)
    {
        if(opts->service_hash_tbl != NULL)
        {
            // destroy the table
            hash_table_destroy(opts->service_hash_tbl);
            opts->service_hash_tbl = NULL;
        }
    }

    // create the hash table if necessary
    if(opts->service_hash_tbl == NULL)
    {
        //need to initialize hash table
        if((rv = create_service_table(opts)) != FWKNOPD_SUCCESS)
        {
            pthread_mutex_unlock(&(opts->service_hash_tbl_mutex));
            return rv;
        }
    }

    // control message is either REFRESH or UPDATE
    // in either case, use data array to modify the table
    if((rv = modify_service_table(opts, service_array_len, jdata)) != FWKNOPD_SUCCESS)
    {
        log_msg(LOG_ERR, "modify_service_table was unsuccessful");
    }

    // release lock on the table
    pthread_mutex_unlock(&(opts->service_hash_tbl_mutex));

    return rv;
}


// look up service info
service_data_t* get_service_data(fko_srv_options_t *opts, uint32_t service_id)
{
    bstring key = NULL;
    service_data_t *service_data = NULL;
    char id[SDP_MAX_SERVICE_ID_STR_LEN + 1] = {0};

    // convert the service id integer to a bstring
    snprintf(id, SDP_MAX_SERVICE_ID_STR_LEN, "%"PRIu32, service_id);
    key = bfromcstr(id);

    // lock the hash table mutex
    if(pthread_mutex_lock(&(opts->service_hash_tbl_mutex)))
    {
        log_msg(LOG_ERR, "Service table mutex lock error.");
        bdestroy(key);
        return NULL;
    }

    service_data = hash_table_get(opts->service_hash_tbl, key);

    pthread_mutex_unlock(&(opts->service_hash_tbl_mutex));
    bdestroy(key);

    if( service_data == NULL )
    {
        log_msg(LOG_WARNING,
            "Did not find service hash table node for service id %"PRIu32,
            service_id
        );
    }

    return service_data;
}



void dump_service_list(fko_srv_options_t *opts)
{
    int opened = 0;
    FILE *dest = NULL;

    if(opts->config[CONF_CONFIG_DUMP_OUTPUT_PATH] != NULL &&
       opts->foreground == 0)
    {
        dest = fopen(opts->config[CONF_CONFIG_DUMP_OUTPUT_PATH], "a");
        if(dest == NULL)
        {
            fprintf(stdout, "ERROR opening file for dump_config output: %s\n",
                    opts->config[CONF_CONFIG_DUMP_OUTPUT_PATH]);
            dest = stdout;
        }
        else
        {
            opened = 1;
        }
    }
    else
    {
        dest = stdout;
    }


    fprintf(dest, "Current fwknopd services settings:\n");

    if(strncasecmp(opts->config[CONF_DISABLE_SDP_MODE], "N", 1) == 0)
    {
        if(! opts->service_hash_tbl)
        {
            fprintf(dest, "\n    ** No Service Settings Defined **\n\n");
            return;
        }

        // lock the hash table mutex
        if(pthread_mutex_lock(&(opts->service_hash_tbl_mutex)))
        {
            fprintf(dest, "Mutex lock error.");
            return;
        }

        hash_table_traverse(opts->service_hash_tbl, traverse_dump_service_cb, dest);

        pthread_mutex_unlock(&(opts->service_hash_tbl_mutex));
    }

    fprintf(dest, "\n");
    fflush(dest);

    if(opened)
    {
        fclose(dest);
    }

}  // END dump_service_list

