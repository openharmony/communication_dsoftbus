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

#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_hidumper.h"
#include "softbus_hidumper_trans.h"
#include "softbus_log.h"
#include "softbus_utils.h"

#define MAX_HELP_INFO_LEN (100)
#define MAX_ID_LEN (10)
#define DEC (10)
#define MODULE_NAME_TRAN "trans"
#define CMD_REGISTED_SESSION_LIST "registed_sessionlist"
#define CMD_CONCURRENT_SESSION_LIST "concurrent_sessionlist"

const char* g_linkTypeList[DUMPER_LANE_LINK_TYPE_BUTT] = {
    "BR",
    "BLE",
    "P2P",
    "wlan",
    "eth",
};

const char* g_dataTypeList[BUSINESS_TYPE_BUTT] = {
    "Message",
    "Byte",
    "File",
    "Stream",
};

typedef struct {
    const char* cmd;
    ShowDumpInfosFunc *showDumpInfosFunc;
}TransHiDumperCmd;

typedef enum {
    TRANS_HIDUMPER_CMD_REGISTED_SESSION_LIST = 0,
    TRANS_HIDUMPER_CMD_CONCURRENT_SESSION_LIST,

    TRANS_HIDUMPER_CMD_BUTT
}TransHiDumperCmdType;

char g_transHelpInfo[MAX_HELP_INFO_LEN];

void InitTranHelpInfo(void)
{
    (void)sprintf_s(g_transHelpInfo, sizeof(g_transHelpInfo), "Usage: -l [%s] [%s]\n",
        CMD_REGISTED_SESSION_LIST, CMD_CONCURRENT_SESSION_LIST);
}

void ShowTransDumpHelperInfo(int fd)
{
    SOFTBUS_DPRINTF(fd, "%s", g_transHelpInfo);
}

ShowDumpInfosFunc g_ShowRegisterSessionInfosFunc = NULL;

void SetShowRegisterSessionInfosFunc(ShowDumpInfosFunc func)
{
    g_ShowRegisterSessionInfosFunc = func;
}

ShowDumpInfosFunc g_ShowRunningSessionInfosFunc = NULL;
void SetShowRunningSessionInfosFunc(ShowDumpInfosFunc func)
{
    g_ShowRunningSessionInfosFunc = func;
}

void SoftBusTransDumpRegisterSession(int fd, const char* pkgName, const char* sessionName,
    int uid, int pid)
{
    char uidArr[MAX_ID_LEN];
    char pidArr[MAX_ID_LEN];
    (void)sprintf_s(uidArr, sizeof(uidArr), "%d", uid);
    (void)sprintf_s(pidArr, sizeof(pidArr), "%d", pid);

    char *uidStr = DataMasking(uidArr, sizeof(uidArr), ID_DELIMITER);
    char *pidStr = DataMasking(pidArr, sizeof(pidArr), ID_DELIMITER);

    SOFTBUS_DPRINTF(fd, "PkgName               : %s\n", pkgName);
    SOFTBUS_DPRINTF(fd, "SessionName           : %s\n", sessionName);
    SOFTBUS_DPRINTF(fd, "PID                   : %s\n", uidStr);
    SOFTBUS_DPRINTF(fd, "UID                   : %s\n", pidStr);

    SoftBusFree(uidStr);
    SoftBusFree(pidStr);
}

void SoftBusTransDumpRunningSession(int fd, TransDumpLaneLinkType type, AppInfo* appInfo)
{
    char *deviceId = DataMasking(appInfo->peerData.deviceId, sizeof(appInfo->peerData.deviceId), ID_DELIMITER);
    char *srcAddr = DataMasking(appInfo->myData.addr, sizeof(appInfo->myData.addr), IP_DELIMITER);
    char *dstAddr = DataMasking(appInfo->peerData.addr, sizeof(appInfo->peerData.addr), IP_DELIMITER);

    SOFTBUS_DPRINTF(fd, "LocalSessionName      : %s\n", appInfo->myData.sessionName);
    SOFTBUS_DPRINTF(fd, "RemoteSessionName     : %s\n", appInfo->peerData.sessionName);
    SOFTBUS_DPRINTF(fd, "PeerDeviceId          : %s\n", deviceId);
    SOFTBUS_DPRINTF(fd, "LinkType              : %s\n", g_linkTypeList[type]);
    SOFTBUS_DPRINTF(fd, "SourceAddress         : %s\n", srcAddr);
    SOFTBUS_DPRINTF(fd, "DestAddress           : %s\n", dstAddr);
    SOFTBUS_DPRINTF(fd, "DataType              : %s\n", g_dataTypeList[appInfo->businessType]);

    SoftBusFree(deviceId);
    SoftBusFree(srcAddr);
    SoftBusFree(dstAddr);
}

static TransHiDumperCmd g_transHiDumperCmdList[TRANS_HIDUMPER_CMD_BUTT] = {
    {CMD_REGISTED_SESSION_LIST, &g_ShowRegisterSessionInfosFunc},
    {CMD_CONCURRENT_SESSION_LIST, &g_ShowRunningSessionInfosFunc}
};

int SoftBusTransDumpHandler(int fd, int argc, const char **argv)
{
    if ((argc != 2) || (strcmp(argv[0], "-l") != 0)) {
        ShowTransDumpHelperInfo(fd);
        return SOFTBUS_OK;
    }

    for (unsigned int i = 0; i < TRANS_HIDUMPER_CMD_BUTT; i++) {
        if (strcmp(argv[1], g_transHiDumperCmdList[i].cmd) == 0) {
            (*g_transHiDumperCmdList[i].showDumpInfosFunc)(fd);
            return SOFTBUS_OK;
        }
    }

    ShowTransDumpHelperInfo(fd);
    return SOFTBUS_OK;
}

void SoftBusTransDumpHandlerInit(void)
{
    InitTranHelpInfo();
    SoftBusRegHiDumperHandler(MODULE_NAME_TRAN, g_transHelpInfo, SoftBusTransDumpHandler);
}