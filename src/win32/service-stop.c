/* @(#) $Id$ */

/* Copyright (C) 2008 Third Brigade, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */
       

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


/* Setup windows after install */
int main(int argc, char **argv)
{
    printf("%s: Attempting to stop ossec.", argv[0]);

    system("net stop OssecSvc");
    
    system("pause");
    return(0);
}