/* @(#) $Id$ */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



#include "shared.h"
#include "os_net/os_net.h"


#include "remoted.h"


/** void HandleSecure() v0.3
 * Handle the secure connections
 */
void HandleSecure()
{
    int agentid;

    char buffer[OS_MAXSTR +1];
    char cleartext_msg[OS_MAXSTR +1];
    char srcip[IPSIZE +1];
    char *tmp_msg;
    char srcmsg[OS_FLSIZE +1];


    int recv_b;

    struct sockaddr_in peer_info;
    socklen_t peer_size;


    /* Send msg init */
    send_msg_init();


    /* Initializing key mutex. */
    keyupdate_init();


    /* Initializing manager */
    manager_init(0);


    /* Creating Ar forwarder thread */
    if(CreateThread(AR_Forward, (void *)NULL) != 0)
    {
        ErrorExit(THREAD_ERROR, ARGV0);
    }

    /* Creating wait_for_msgs thread */
    if(CreateThread(wait_for_msgs, (void *)NULL) != 0)
    {
        ErrorExit(THREAD_ERROR, ARGV0);
    }


    /* Connecting to the message queue
     * Exit if it fails.
     */
    if((logr.m_queue = StartMQ(DEFAULTQUEUE,WRITE)) < 0)
    {
        ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQUEUE);
    }


    verbose(AG_AX_AGENTS, ARGV0, MAX_AGENTS);


    /* Reading authentication keys */
    verbose(ENC_READ, ARGV0);

    OS_ReadKeys(&keys);

    debug1("%s: DEBUG: OS_StartCounter.", ARGV0);
    OS_StartCounter(&keys);
    debug1("%s: DEBUG: OS_StartCounter completed.", ARGV0);


    /* setting up peer size */
    peer_size = sizeof(peer_info);
    logr.peer_size = sizeof(peer_info);


    /* Initializing some variables */
    memset(buffer, '\0', OS_MAXSTR +1);
    memset(cleartext_msg, '\0', OS_MAXSTR +1);
    memset(srcmsg, '\0', OS_FLSIZE +1);
    tmp_msg = NULL;



    /* loop in here */
    while(1)
    {
        /* Receiving message and store in buffer */
        recv_b = recvfrom(logr.sock, buffer, OS_MAXSTR, 0,
                (struct sockaddr *)&peer_info, &peer_size);


        /* Nothing received */
        if(recv_b <= 0)
        {
            continue;
        }


        /* Setting the source address */
        strncpy(srcip, inet_ntoa(peer_info.sin_addr), IPSIZE);
        srcip[IPSIZE] = '\0';



        /* Getting a valid agentid */
        /* ICY: if the first character of buffer is a exclamation (!)
         * the buffer should indicate a dynamic agent. Please note
         * the exclamation is used to indicate negative address.
         *
         * Question: What are being stored in buffer? In the buffer
         * there's the message receive by the server. According to the
         * definition of (OS_IsAllowedIP), the buffer should contain the
         * string of agent_id. So we have two kinds of buffer
         *
         *  (a) !<agent_id>  sender must match the id/address defined globally
         *                   buffer is the <agent_id>
         *  (b) <agent_id>   sender must match address defined in key file.
         *                   buffer isn't used
         *
         * So why are there two different kinds of buffer? Because the
         * sender maynot the agent. The sender may fake the agent_id
         *
         *  (a) sender is the agent per-se
         *  (b) sender isn't the agent per-se
         *
         * I don't know why this is necessary; maybe in a complex setup
         * of OSSEC, a server can process messages and transfer to another
         * server (multiple servers) !?
         *
         *  (a) agent -> sender
         *  (b) agent -> agent -> sender
         *
         * The second case (b) may occur when we can't detect the <agent_id>
         * from received messages (data lost!?)
         *
         * */
        if(buffer[0] == '!')
        {
            tmp_msg = buffer;
            tmp_msg++;


            /* We need to make sure that we have a valid id
             * and that we reduce the recv buffer size.
             */
            while(isdigit((int)*tmp_msg))
            {
                tmp_msg++;
                recv_b--;
            }

            if(*tmp_msg != '!')
            {
                merror(ENCFORMAT_ERROR, __local_name, srcip);
                continue;
            }

            *tmp_msg = '\0';
            tmp_msg++;
            recv_b-=2;

            /* ICY: get the identity number of agent, based on source address */
            agentid = OS_IsAllowedDynamicID(&keys, buffer +1, srcip);
            if(agentid == -1)
            {
                if(check_keyupdate())
                {
                    agentid = OS_IsAllowedDynamicID(&keys, buffer +1, srcip);
                    if(agentid == -1)
                    {
                        merror(ENC_IP_ERROR, ARGV0, srcip);
                        continue;
                    }
                }
                else
                {
                    merror(ENC_IP_ERROR, ARGV0, srcip);
                    continue;
                }
            }
        }
        else
        {
            /* ICY: get agent_id by IP */
            agentid = OS_IsAllowedIP(&keys, srcip);
            if(agentid < 0)
            {
                if(check_keyupdate())
                {
                    agentid = OS_IsAllowedIP(&keys, srcip);
                    if(agentid == -1)
                    {
                        merror(DENYIP_WARN,ARGV0,srcip);
                        continue;
                    }
                }
                else
                {
                    merror(DENYIP_WARN,ARGV0,srcip);
                    continue;
                }
            }
            tmp_msg = buffer;
        }


        /* Decrypting the message */
        tmp_msg = ReadSecMSG(&keys, tmp_msg, cleartext_msg,
                             agentid, recv_b -1);
        if(tmp_msg == NULL)
        {
            /* If duplicated, a warning was already generated */
            continue;
        }


        /* Check if it is a control message */
        if(IsValidHeader(tmp_msg))
        {
            /* We need to save the peerinfo if it is a control msg */
            memcpy(&keys.keyentries[agentid]->peer_info, &peer_info, peer_size);
            keys.keyentries[agentid]->rcvd = time(0);

            save_controlmsg(agentid, tmp_msg);

            continue;
        }


        /* Generating srcmsg */
        snprintf(srcmsg, OS_FLSIZE,"(%s) %s",keys.keyentries[agentid]->name,
                                             keys.keyentries[agentid]->ip->ip);


        /* If we can't send the message, try to connect to the
         * socket again. If it not exit.
         */
        if(SendMSG(logr.m_queue, tmp_msg, srcmsg,
                   SECURE_MQ) < 0)
        {
            merror(QUEUE_ERROR, ARGV0, DEFAULTQUEUE, strerror(errno));

            if((logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE)) < 0)
            {
                ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQUEUE);
            }
        }
    }
}



/* EOF */
