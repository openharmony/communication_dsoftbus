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
#include "softbus_error_code.h"
#include "softbus_hidumper.h"
#include "softbus_hidumper_trans.h"

#define MAX_HELP_INFO_LEN (100)
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
    dprintf(fd, "%s", g_transHelpInfo);
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
    dprintf(fd, "PkgName               : %s\n", pkgName);
    dprintf(fd, "SessionName           : %s\n", sessionName);
    dprintf(fd, "PID                   : %d\n", uid);
    dprintf(fd, "UID                   : %d\n", pid);
}

void SoftBusTransDumpRunningSession(int fd, TransDumpLaneLinkType type, AppInfo* appInfo)
{
    dprintf(fd, "LocalSessionName      : %s\n", appInfo->myData.sessionName);
    dprintf(fd, "RemoteSessionName     : %s\n", appInfo->peerData.sessionName);
    dprintf(fd, "PeerDeviceId          : %s\n", appInfo->peerData.deviceId);
    dprintf(fd, "LinkType              : %s\n", g_linkTypeList[type]);
    dprintf(fd, "SourceAddress         : %s\n", appInfo->myData.addr);
    dprintf(fd, "DestAddress           : %s\n", appInfo->peerData.addr);
    dprintf(fd, "DataType              : %s\n", g_dataTypeList[appInfo->businessType]);
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

void initSoftBusTransDumpHandler(void)
{
    InitTranHelpInfo();
    SoftBusRegHiDumperHandler(MODULE_NAME_TRAN, g_transHelpInfo, SoftBusTransDumpHandler);
}