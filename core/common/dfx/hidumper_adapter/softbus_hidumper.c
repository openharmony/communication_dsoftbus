/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdio.h>
#include <string.h>

#include "softbus_error_code.h"
#include "softbus_hidumper_disc.h"
#include "softbus_hidumper_conn.h"
#include "softbus_hidumper_nstack.h"
#include "softbus_hidumper.h"

#define SOFTBUS_DISC_MODULE  "disc"
#define SOFTBUS_CONN_MODULE  "conn"
#define SOFTBUS_BUSCENTER_MODULE  "buscenter"
#define SOFTBUS_TRANS_MODULE  "trans"
#define SOFTBUS_DSTREAM_MODULE  "dstream"
#define SOFTBUS_DFILE_MODULE  "dfile"
#define SOFTBUS_DFINDER_MODULE  "dfinder"
#define SOFTBUS_DMSG_MODULE  "dmsg"

void SoftBusDumpShowHelp(int fd)
{
    dprintf(fd, "Usage: [-h] [disc] [conn] [buscenter] [trans] [dstream] [dfile] [dfinder] [dmsg]\n");
    dprintf(fd, "   -h         List all the module of softbus\n");
    dprintf(fd, "   disc       List all the dump item of disc\n");
    dprintf(fd, "   conn       List all the dump item of conn\n");
    dprintf(fd, "   buscenter  List all the dump item of buscenter\n");
    dprintf(fd, "   trans      List all the dump item of trans\n");
    dprintf(fd, "   dstream    List all the dump item of dstream\n");
    dprintf(fd, "   dfile      List all the dump item of dfile\n");
    dprintf(fd, "   dfinder    List all the dump item of dfinder\n");
    dprintf(fd, "   dmsg       List all the dump item of dmsg\n");
}

void SoftBusDumpErrInfo(int fd, const char *argv)
{
    dprintf(fd, "the command is not exist, please ipnut again!\n");
}

int SoftBusDumpProcess(int fd, int argc, const char **argv)
{
    if (fd <= 0) {
        return SOFTBUS_ERR;
    }
    if (argc == 0 || strcmp(argv[0], "-h")) {
        SoftBusDumpShowHelp(fd);
        return SOFTBUS_OK;
    }

    const char **argvPtr = NULL;
    if (argc == 1) {
        *argvPtr = NULL;
    } else {
        argvPtr = &argv[1];
    }
    int argcNew = argc - 1;
    if (strcmp(argv[0], SOFTBUS_DISC_MODULE) == 0) {
        SoftBusDiscDumpHander(fd, argcNew, argvPtr);
    } else if (strcmp(argv[0], SOFTBUS_CONN_MODULE) == 0) {
        SoftBusConnDumpHander(fd, argcNew, argvPtr);
    } else if (strcmp(argv[0], SOFTBUS_DSTREAM_MODULE) == 0) {
        SoftBusNStackDstreamDumpHander(fd, argcNew, argvPtr);
    }  else if (strcmp(argv[0], SOFTBUS_DFILE_MODULE) == 0) {
        SoftBusNStackDfileDumpHander(fd, argcNew, argvPtr);
    }  else if (strcmp(argv[0], SOFTBUS_DFINDER_MODULE) == 0) {
        SoftBusNStackDumpDfinderHander(fd, argcNew, argvPtr);
    }  else if (strcmp(argv[0], SOFTBUS_DMSG_MODULE) == 0) {
        SoftBusNStackDmsgDumpHander(fd, argcNew, argvPtr);
    } else {
        SoftBusDumpErrInfo(fd, argv[0]);
        SoftBusDumpShowHelp(fd);
    }
    
    return SOFTBUS_OK;
}

