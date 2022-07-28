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
#include <string.h>
#include "softbus_errcode.h"
#include "softbus_hidumper.h"
#include "softbus_hidumper_conn.h"

#define SOFTBUS_CONN_DUMP_BLECONNECTLIST "BLEConnectList"
#define SOFTBUS_CONN_DUMP_BLGATTCINFOLIST "BleGattCInfoList"
#define SOFTBUS_CONN_DUMP_BLEGATTSERVICE "BleGattService"
#define SOFTBUS_CONN_DUMP_BRCONNECTLIST "BRConnectList"
#define SOFTBUS_CONN_DUMP_BRPENDINGLIST "BRPendingList"
#define SOFTBUS_CONN_DUMP_TCPCONNECTLIST "TCPConnectList"
#define SOFTBUS_CONN_DUMP_P2PCONNECTINGDEVICE "P2PConnectingDevice"
#define SOFTBUS_CONN_DUMP_P2PCONNECTEDDEVICE "P2PConnecedDevice"

static SoftBusConnDumpCb  *g_ConnDumpCallback[SOFTBUS_CONN_DUMP_VAR_BUTT];

static void SoftBusDumpConnHelp(int fd)
{
    dprintf(fd, "Usage: hidumper -s 4700 -a conn [Option] \n");
    dprintf(fd, "   [-h] | [-l <BLEConnectList| BleGattCInfoList| BleGattService| BRConnectList| BRPendingList| ");
    dprintf(fd, " TCPConnectList| P2PConnectingDevice| P2PConnectedDevice>]\n");
    dprintf(fd, "   -h         List all the dump item in conn module\n");
    dprintf(fd, "   -l <item>  Dump the item in conn module, item is nesessary\n");
}

int SoftBusRegConnDumpCb(int varId, SoftBusConnDumpCb cb)
{
    if (varId >= SOFTBUS_CONN_DUMP_VAR_BUTT || varId < SOFTBUS_CONN_DUMP_VAR_BLECONNECTLIST || cb == NULL) {
        return SOFTBUS_ERR;
    }
    g_ConnDumpCallback[varId] = cb;
    return SOFTBUS_OK;
}

int SoftBusConnDumpHander(int fd, int argc, const char **argv)
{
    if (fd < 0 || argc < 0 || argv == NULL) {
        return SOFTBUS_ERR;
    }
    
    if (argc == 0 || strcmp(argv[0], "-h") == 0) {
        SoftBusDumpConnHelp(fd);
        return SOFTBUS_OK;
    }

    if (argc == 1 && strcmp(argv[0], "-l") == 0) {
        SoftBusDumpConnHelp(fd);
        return SOFTBUS_OK;
    }
    int nRet = SOFTBUS_OK;
    if (strcmp(argv[0], "-l") == 0) {
        if (strcmp(argv[1], SOFTBUS_CONN_DUMP_BLECONNECTLIST) == 0) {
            nRet = g_ConnDumpCallback[SOFTBUS_CONN_DUMP_VAR_BLECONNECTLIST](fd);
        } else if (strcmp(argv[1], SOFTBUS_CONN_DUMP_BLGATTCINFOLIST) == 0) {
            nRet = g_ConnDumpCallback[SOFTBUS_CONN_DUMP_VAR_BLGATTCINFOLIST](fd);
        } else if (strcmp(argv[1], SOFTBUS_CONN_DUMP_BLEGATTSERVICE) == 0) {
            nRet = g_ConnDumpCallback[SOFTBUS_CONN_DUMP_VAR_BLEGATTSERVICE](fd);
        } else if (strcmp(argv[1], SOFTBUS_CONN_DUMP_BRCONNECTLIST) == 0) {
            nRet = g_ConnDumpCallback[SOFTBUS_CONN_DUMP_VAR_BRCONNECTLIST](fd);
        } else if (strcmp(argv[1], SOFTBUS_CONN_DUMP_BRPENDINGLIST) == 0) {
            nRet = g_ConnDumpCallback[SOFTBUS_CONN_DUMP_VAR_BRPENDINGLIST](fd);
        } else if (strcmp(argv[1], SOFTBUS_CONN_DUMP_TCPCONNECTLIST) == 0) {
            nRet = g_ConnDumpCallback[SOFTBUS_CONN_DUMP_VAR_TCPCONNECTLIST](fd);
        } else if (strcmp(argv[1], SOFTBUS_CONN_DUMP_P2PCONNECTINGDEVICE) == 0) {
            nRet = g_ConnDumpCallback[SOFTBUS_CONN_DUMP_VAR_P2PCONNECTINGDEVICE](fd);
        } else if (strcmp(argv[1], SOFTBUS_CONN_DUMP_P2PCONNECTEDDEVICE) == 0) {
            nRet = g_ConnDumpCallback[SOFTBUS_CONN_DUMP_VAR_P2PCONNECTEDDEVICE](fd);
        } else {
            SoftBusDumpErrInfo(fd, argv[1]);
            SoftBusDumpConnHelp(fd);
        }
    }
    return nRet;
}
