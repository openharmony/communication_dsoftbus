/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "softbus_permission.h"

#include <string.h>
#include <unistd.h>

#include "permission_entry.h"
#include "pms_interface.h"
#include "pms_types.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#define SOFTBUS_PERMISSION_NAME "ohos.permission.DISTRIBUTED_DATASYNC"

#define SHELL_UID 2
#define INVALID_UID (-1)
#define FIRST_APPLICATION_UID 10000

#define PERMISSION_JSON_FILE "/etc/softbus_trans_permission.json"

static int32_t CheckSoftBusSysPermission(int32_t callingUid)
{
    if (CheckPermission(callingUid, SOFTBUS_PERMISSION_NAME) != GRANTED) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "softbus CheckPermission fail");
        return SOFTBUS_PERMISSION_DENIED;
    }
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "CheckSoftBusSysPermission uid:%d success", callingUid);
    return SOFTBUS_OK;
}

static int32_t GetPermType(pid_t callingUid, pid_t callingPid, const char *pkgName)
{
    (void)pkgName;
    if (callingUid == (pid_t)getuid() && callingPid == getpid()) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "self app");
        return SELF_APP;
    }
    if (CheckSoftBusSysPermission(callingUid) == SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "system app");
        return SYSTEM_APP;
    }
    if (callingUid > INVALID_UID && callingUid < FIRST_APPLICATION_UID && callingUid != SHELL_UID) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "native app");
        return NATIVE_APP;
    }
    return SOFTBUS_PERMISSION_DENIED;
}

int32_t TransPermissionInit(void)
{
    return LoadPermissionJson(PERMISSION_JSON_FILE);
}

void TransPermissionDeinit(void)
{
    DeinitPermissionJson();
}

int32_t CheckTransPermission(pid_t callingUid, pid_t callingPid,
    const char *pkgName, const char *sessionName, uint32_t actions)
{
    int32_t permType = GetPermType(callingUid, callingPid, pkgName);
    if (permType < 0) {
        return permType;
    }
    SoftBusPermissionItem *pItem = CreatePermissionItem(permType, callingUid, callingPid, pkgName, actions);
    if (pItem == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = CheckPermissionEntry(sessionName, pItem);
    SoftBusFree(pItem);
    if (ret >= SYSTEM_APP) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_PERMISSION_DENIED;
}

int32_t CheckTransSecLevel(const char *mySessionName, const char *peerSessionName)
{
    if (mySessionName == NULL || peerSessionName == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcmp(mySessionName, peerSessionName) == 0) {
        return SOFTBUS_OK;
    }
    if (!PermIsSecLevelPublic(mySessionName)) {
        return SOFTBUS_PERMISSION_DENIED;
    }
    if (!PermIsSecLevelPublic(peerSessionName)) {
        return SOFTBUS_PERMISSION_DENIED;
    }
    return SOFTBUS_OK;
}

bool CheckDiscPermission(pid_t callingUid, const char *pkgName)
{
    (void)pkgName;
    if (CheckSoftBusSysPermission(callingUid) == SOFTBUS_OK) {
        return true;
    }
    return false;
}

bool CheckBusCenterPermission(pid_t callingUid, const char *pkgName)
{
    (void)pkgName;
    if (CheckSoftBusSysPermission(callingUid) == SOFTBUS_OK) {
        return true;
    }
    return false;
}