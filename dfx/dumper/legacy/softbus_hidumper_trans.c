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
#include "legacy/softbus_hidumper_trans.h"

#include <stdio.h>
#include <string.h>

#include "anonymizer.h"
#include "comm_log.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

#define MAX_ID_LEN (10)
#define MODULE_NAME_TRAN "trans"
#define SOFTBUS_TRANS_MODULE_HELP "List all the dump item of trans"

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
    "NotCare",
};

static LIST_HEAD(g_trans_var_list);

int32_t SoftBusRegTransVarDump(const char *dumpVar, SoftBusVarDumpCb cb)
{
    if (dumpVar == NULL || strlen(dumpVar) >= SOFTBUS_DUMP_VAR_NAME_LEN || cb == NULL) {
        COMM_LOGE(COMM_DFX, "SoftBusRegTransVarDump invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    return SoftBusAddDumpVarToList(dumpVar, cb, &g_trans_var_list);
}

void SoftBusTransDumpRegisterSession(int fd, const char* pkgName, const char* sessionName,
    int uid, int pid)
{
    if (fd < 0 || pkgName == NULL || sessionName == NULL || uid < 0 || pid < 0) {
        COMM_LOGE(COMM_DFX, "param is invalid");
        return;
    }

    char uidArr[MAX_ID_LEN] = {0};
    char pidArr[MAX_ID_LEN] = {0};
    char uidStr[MAX_ID_LEN] = {0};
    char pidStr[MAX_ID_LEN] = {0};
    if (sprintf_s(uidArr, MAX_ID_LEN, "%d", uid) < 0 || sprintf_s(pidArr, MAX_ID_LEN, "%d", pid) < 0) {
        COMM_LOGE(COMM_DFX, "set uidArr or pidArr failed");
        return;
    }

    DataMasking(uidArr, MAX_ID_LEN, ID_DELIMITER, uidStr);
    DataMasking(pidArr, MAX_ID_LEN, ID_DELIMITER, pidStr);

    char *tmpPkgName = NULL;
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    Anonymize(pkgName, &tmpPkgName);
    SOFTBUS_DPRINTF(fd, "SessionName           : %s\n", AnonymizeWrapper(tmpName));
    SOFTBUS_DPRINTF(fd, "pkgName           : %s\n", AnonymizeWrapper(tmpPkgName));
    SOFTBUS_DPRINTF(fd, "PID                   : %s\n", uidStr);
    SOFTBUS_DPRINTF(fd, "UID                   : %s\n", pidStr);
    AnonymizeFree(tmpName);
    AnonymizeFree(tmpPkgName);
}

void SoftBusTransDumpRunningSession(int fd, TransDumpLaneLinkType type, AppInfo* appInfo)
{
    if (fd < 0 || type < DUMPER_LANE_BR || type >= DUMPER_LANE_LINK_TYPE_BUTT || appInfo == NULL) {
        COMM_LOGE(COMM_DFX, "param is invalid");
        return;
    }

    char deviceId[DEVICE_ID_SIZE_MAX] = {0};
    char srcAddr[IP_LEN] = {0};
    char dstAddr[IP_LEN] = {0};
    char *localSessionName = NULL;
    char *remoteSessionName = NULL;
    DataMasking(appInfo->peerData.deviceId, DEVICE_ID_SIZE_MAX, ID_DELIMITER, deviceId);
    DataMasking(appInfo->myData.addr, IP_LEN, IP_DELIMITER, srcAddr);
    DataMasking(appInfo->peerData.addr, IP_LEN, IP_DELIMITER, dstAddr);
    Anonymize(appInfo->myData.sessionName, &localSessionName);
    Anonymize(appInfo->peerData.sessionName, &remoteSessionName);
    SOFTBUS_DPRINTF(fd, "LocalSessionName      : %s\n", AnonymizeWrapper(localSessionName));
    SOFTBUS_DPRINTF(fd, "RemoteSessionName     : %s\n", AnonymizeWrapper(remoteSessionName));
    SOFTBUS_DPRINTF(fd, "PeerDeviceId          : %s\n", deviceId);
    SOFTBUS_DPRINTF(fd, "LinkType              : %s\n", g_linkTypeList[type]);
    SOFTBUS_DPRINTF(fd, "SourceAddress         : %s\n", srcAddr);
    SOFTBUS_DPRINTF(fd, "DestAddress           : %s\n", dstAddr);
    SOFTBUS_DPRINTF(fd, "DataType              : %s\n", g_dataTypeList[appInfo->businessType]);
    AnonymizeFree(localSessionName);
    AnonymizeFree(remoteSessionName);
}

static int SoftBusTransDumpHandler(int fd, int argc, const char **argv)
{
    if (fd < 0 || argv == NULL || argc < 0) {
        COMM_LOGE(COMM_DFX, "param is invalid ");
        return SOFTBUS_INVALID_PARAM;
    }
    if (argc == 0 || ((argc == 1) && (strcmp(argv[0], "-h") == 0)) || (argc == 1 && strcmp(argv[0], "-l") == 0)) {
        SoftBusDumpSubModuleHelp(fd, (char *)MODULE_NAME_TRAN, &g_trans_var_list);
        return SOFTBUS_OK;
    }

    int32_t ret = SOFTBUS_OK;
    int32_t isModuleExist = SOFTBUS_DUMP_NOT_EXIST;
    if (argc > 1 && strcmp(argv[0], "-l") == 0) {
        ListNode *item = NULL;
        LIST_FOR_EACH(item, &g_trans_var_list) {
            SoftBusDumpVarNode *itemNode = LIST_ENTRY(item, SoftBusDumpVarNode, node);
            if (strcmp(itemNode->varName, argv[1]) == 0 && itemNode->dumpCallback != NULL) {
                ret = itemNode->dumpCallback(fd);
                isModuleExist = SOFTBUS_DUMP_EXIST;
                break;
            }
        }
        if (isModuleExist == SOFTBUS_DUMP_NOT_EXIST) {
            SoftBusDumpErrInfo(fd, argv[1]);
            SoftBusDumpSubModuleHelp(fd, (char *)MODULE_NAME_TRAN, &g_trans_var_list);
        }
    }
    return ret;
}

int32_t SoftBusTransDumpHandlerInit(void)
{
    int32_t ret = SoftBusRegHiDumperHandler((char*)MODULE_NAME_TRAN, (char*)SOFTBUS_TRANS_MODULE_HELP,
        &SoftBusTransDumpHandler);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_INIT, "SoftBusTransDumpHander regist fail");
    }
    return ret;
}

void SoftBusHiDumperTransDeInit(void)
{
    SoftBusReleaseDumpVar(&g_trans_var_list);
}
