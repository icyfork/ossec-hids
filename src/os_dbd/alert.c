/* @(#) $Id$ */

/* Copyright (C) 2008 Third Brigade, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


#include "dbd.h"
#include "config/config.h"
#include "rules_op.h"



/** int OS_SelectMaxID(DBConfig *db_config)
 * Selects the maximum ID from the alert table.
 * Returns 0 if not found.
 */
int OS_SelectMaxID(DBConfig *db_config)
{
    int result = 0;
    char sql_query[OS_SIZE_1024];

    memset(sql_query, '\0', OS_SIZE_1024);


    /* Generating SQL */
    snprintf(sql_query, OS_SIZE_1024 -1,
            "SELECT MAX(id) FROM "
            "alert WHERE server_id = '%u'",
            db_config->server_id);


    /* Checking return code. */
    result = osdb_query_select(db_config->conn, sql_query);

    return(result);
}


/** int __DBSelectLocation(char *locaton, DBConfig *db_config)
 * Selects the location ID from the db.
 * Returns 0 if not found.
 */
int __DBSelectLocation(char *location, DBConfig *db_config)
{
    int result = 0;
    char sql_query[OS_SIZE_1024];

    memset(sql_query, '\0', OS_SIZE_1024);


    /* Generating SQL */
    snprintf(sql_query, OS_SIZE_1024 -1,
            "SELECT id FROM "
            "location WHERE name = '%s' AND server_id = '%d' "
            "LIMIT 1",
            location, db_config->server_id);


    /* Checking return code. */
    result = osdb_query_select(db_config->conn, sql_query);

    return(result);
}


/** int __DBInsertLocation(char *location, DBConfig *db_config)
 * Inserts location in to the db.
 */
int __DBInsertLocation(char *location, DBConfig *db_config)
{
    char sql_query[OS_SIZE_1024];
    
    memset(sql_query, '\0', OS_SIZE_1024);

    /* Generating SQL */
    snprintf(sql_query, OS_SIZE_1024 -1,
            "INSERT INTO "
            "location(server_id, name) "
            "VALUES ('%u', '%s')",
            db_config->server_id, location);


    /* Checking return code. */
    if(!osdb_query_insert(db_config->conn, sql_query))
    {
        merror(DB_GENERROR, ARGV0);
    }

    return(0);
}



/** int OS_Alert_InsertDB(DBConfig *db_config)
 * Insert alert into to the db.
 * Returns 1 on success or 0 on error.
 */
int OS_Alert_InsertDB(alert_data *al_data, DBConfig *db_config)
{
    unsigned int s_ip = 0, d_ip = 0, location_id = 0;
    int *loc_id;
    char sql_query[OS_SIZE_2048 +1];


    /* Clearing the memory before insert */
    memset(sql_query, '\0', OS_SIZE_2048 +1);
    

    /* Converting srcip to int */
    if(al_data->srcip)
    {
        struct in_addr net;

        /* Extracting ip address */
        if(inet_aton(al_data->srcip, &net))
        {
            s_ip = net.s_addr;
        }
    }
    d_ip = 0;


    /* Escaping strings */
    osdb_escapestr(al_data->user);
    osdb_escapestr(al_data->log[0]);


    /* We first need to insert the location */
    loc_id = OSHash_Get(db_config->location_hash, al_data->location);
    
    
    /* If we dont have location id, we must select and/or insert in the db */
    if(!loc_id)
    {
        location_id = __DBSelectLocation(al_data->location, db_config);
        if(location_id == 0)
        {
            /* Insert it */
            __DBInsertLocation(al_data->location, db_config);
            location_id = __DBSelectLocation(al_data->location, db_config);
        }

        if(!location_id)
        {
            merror("%s: Unable to insert location: '%s'.", 
                   ARGV0, al_data->location);
            return(0);
        }


        /* Adding to hash */
        os_calloc(1, sizeof(int), loc_id);
        *loc_id = location_id;
        OSHash_Add(db_config->location_hash, al_data->location, loc_id);
    }
    

    /* Inserting data */
    if(db_config->db_type == POSTGDB)
    {
        /* On postgres we need to escape the user field. */
        snprintf(sql_query, OS_SIZE_2048,
                "INSERT INTO "
                "data(id, server_id, \"user\", full_log) "
                "VALUES ('%u', '%u', '%s', '%s') ",
                db_config->alert_id, db_config->server_id, 
                al_data->user, al_data->log[0]);
    }
    else
    {
        snprintf(sql_query, OS_SIZE_2048,
                "INSERT INTO "
                "data(id, server_id, user, full_log) "
                "VALUES ('%u', '%u', '%s', '%s') ",
                db_config->alert_id, db_config->server_id, 
                al_data->user, al_data->log[0]);
    }
    
    
    /* Inserting into the db */
    if(!osdb_query_insert(db_config->conn, sql_query))
    {
        merror(DB_GENERROR, ARGV0);
    }
                                


    /* Generating final SQL */
    snprintf(sql_query, OS_SIZE_2048,
            "INSERT INTO "
            "alert(id,server_id,rule_id,timestamp,location_id,src_ip) "
            "VALUES ('%u', '%u', '%u','%u', '%u', '%lu')",
            db_config->alert_id, db_config->server_id, al_data->rule,
            (unsigned int)time(0), *loc_id, (unsigned long)ntohl(s_ip));


    /* Inserting into the db */
    if(!osdb_query_insert(db_config->conn, sql_query))
    {
        merror(DB_GENERROR, ARGV0);
    }

    
    db_config->alert_id++;
    return(1);
}


/* EOF */