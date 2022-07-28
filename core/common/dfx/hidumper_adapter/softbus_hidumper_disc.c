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
#include "softbus_errcode.h"
#include "softbus_hidumper.h"
#include "softbus_hidumper_disc.h"

#define SOFTBUS_DISC_DUMP_BLEINFOMANGER "BleInfoManager"
#define SOFTBUS_DISC_DUMP_BLEADVERTISER "BleAdvertiser"
#define SOFTBUS_DISC_DUMP_BLELISTENER "BleListener"
#define SOFTBUS_DISC_DUMP_PUBLICMGR "PublicMgr"
#define SOFTBUS_DISC_DUMP_SUBSCRIBEMGR "SubscribeMgr"
#define SOFTBUS_DISC_DUMP_CAPABILITYDATA "CapabilityData"
#define SOFTBUS_DISC_DUMP_LOCALDEVINFO "LocalDevInfo"

static SoftBusDiscDumpCb  *g_DiscDumpCallback[SOFTBUS_DISC_DUMP_VAR_BUTT];
static void SoftBusDumpDiscHelp(int fd)
{
    dprintf(fd, "Usage: hidumper -s 4700 -a disc [Option] \n");
    dprintf(fd, "   Option: [-h] | [-l <BleInfoManager| BleAdvertiser| BleListener| PublicMgr| SubscribeMgr| \
            CapabilityData| LocalDevInfo>]\n");
    dprintf(fd, "   -h         List all the dump item in disc module\n");
    dprintf(fd, "   -l <item>  Dump the item in disc module, item is nesessary\n");
}

int SoftBusRegDiscDumpCb(int varId, SoftBusDiscDumpCb *cb)
{
    if (varId >= SOFTBUS_DISC_DUMP_VAR_BUTT || varId < SOFTBUS_DISC_DUMP_VAR_BLEINFOMANGER || cb == NULL) {
        return SOFTBUS_ERR;
    }
    g_DiscDumpCallback[varId] = cb;
    return SOFTBUS_OK;
}

int SoftBusDiscDumpHander(int fd, int argc, const char **argv)
{
    if (fd < 0 || argc < 0 || argv == NULL) {
        return SOFTBUS_ERR;
    }

    if (argc == 0 || strcmp(argv[0], "-h") == 0) {
        SoftBusDumpDiscHelp(fd);
        return SOFTBUS_OK;
    }

    if (argc == 1 && strcmp(argv[0], "-l") == 0) {
        SoftBusDumpDiscHelp(fd);
        return SOFTBUS_OK;
    }
    int nRet = SOFTBUS_OK;
    if (strcmp(argv[0], "-l") == 0) {
        if (strcmp(argv[1], SOFTBUS_DISC_DUMP_BLEINFOMANGER) == 0) {
            nRet = g_DiscDumpCallback[SOFTBUS_DISC_DUMP_VAR_BLEINFOMANGER](fd);
        } else if (strcmp(argv[1], SOFTBUS_DISC_DUMP_BLEADVERTISER) == 0) {
            nRet = g_DiscDumpCallback[SOFTBUS_DISC_DUMP_VAR_BLEADVERTISER](fd);
        } else if (strcmp(argv[1], SOFTBUS_DISC_DUMP_BLELISTENER) == 0) {
            nRet = g_DiscDumpCallback[SOFTBUS_DISC_DUMP_VAR_BLELISTENER](fd);
        } else if (strcmp(argv[1], SOFTBUS_DISC_DUMP_PUBLICMGR) == 0) {
            nRet = g_DiscDumpCallback[SOFTBUS_DISC_DUMP_VAR_PUBLICMGR](fd);
        } else if (strcmp(argv[1], SOFTBUS_DISC_DUMP_SUBSCRIBEMGR) == 0) {
            nRet = g_DiscDumpCallback[SOFTBUS_DISC_DUMP_VAR_SUBSCRIBEMGR](fd);
        } else if (strcmp(argv[1], SOFTBUS_DISC_DUMP_LOCALDEVINFO) == 0) {
            nRet = g_DiscDumpCallback[SOFTBUS_DISC_DUMP_VAR_LOCALDEVINFO](fd);
        } else if (strcmp(argv[1], SOFTBUS_DISC_DUMP_LOCALDEVINFO) == 0) {
            nRet = g_DiscDumpCallback[SOFTBUS_DISC_DUMP_VAR_LOCALDEVINFO](fd);
        } else {
            SoftBusDumpErrInfo(fd, argv[1]);
            SoftBusDumpDiscHelp(fd);
        }
    }
    return nRet;
}
