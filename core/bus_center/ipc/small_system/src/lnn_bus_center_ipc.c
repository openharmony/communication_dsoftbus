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

#include "lnn_bus_center_ipc.h"

#include <pthread.h>
#include <securec.h>
#include <string.h>

#include "bus_center_client_proxy.h"
#include "bus_center_manager.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_time_sync_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

typedef struct {
    ListNode node;
    char pkgName[PKG_NAME_SIZE_MAX];
    ConnectionAddr addr;
} JoinLnnRequestInfo;

typedef struct {
    ListNode node;
    char pkgName[PKG_NAME_SIZE_MAX];
    char networkId[NETWORK_ID_BUF_LEN];
} LeaveLnnRequestInfo;

typedef struct {
    SoftBusList *joinLNNRequestInfo;
    SoftBusList *leaveLNNRequestInfo;
    pthread_mutex_t lock;
} LNNRequestInfo;

static LNNRequestInfo g_lnnRequestInfo = {
    .joinLNNRequestInfo = NULL,
    .leaveLNNRequestInfo = NULL,
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

static JoinLnnRequestInfo *FindJoinLNNRequest(ConnectionAddr *addr)
{
    JoinLnnRequestInfo *info = NULL;
    SoftBusList *list = g_lnnRequestInfo.joinLNNRequestInfo;

    LIST_FOR_EACH_ENTRY(info, &list->list, JoinLnnRequestInfo, node) {
        if (LnnIsSameConnectionAddr(addr, &info->addr)) {
            return info;
        }
    }
    return NULL;
}

static LeaveLnnRequestInfo *FindLeaveLNNRequest(const char *networkId)
{
    LeaveLnnRequestInfo *info = NULL;
    SoftBusList *list = g_lnnRequestInfo.leaveLNNRequestInfo;

    LIST_FOR_EACH_ENTRY(info, &list->list, LeaveLnnRequestInfo, node) {
        if (strncmp(networkId, info->networkId, strlen(networkId)) == 0) {
            return info;
        }
    }
    return NULL;
}

static bool IsRepeatJoinLNNRequest(const char *pkgName, const ConnectionAddr *addr)
{
    JoinLnnRequestInfo *info = NULL;
    SoftBusList *list = g_lnnRequestInfo.joinLNNRequestInfo;

    LIST_FOR_EACH_ENTRY(info, &list->list, JoinLnnRequestInfo, node) {
        if (strncmp(pkgName, info->pkgName, strlen(pkgName)) != 0) {
            continue;
        }
        if (LnnIsSameConnectionAddr(addr, &info->addr)) {
            return true;
        }
    }
    return false;
}

static int32_t AddJoinLNNInfo(const char *pkgName, const ConnectionAddr *addr)
{
    SoftBusList *list = g_lnnRequestInfo.joinLNNRequestInfo;
    JoinLnnRequestInfo *info = (JoinLnnRequestInfo *)SoftBusMalloc(sizeof(JoinLnnRequestInfo));
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: malloc join LNN JoinLnnRequestInfo");
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&info->node);
    if (strncpy_s(info->pkgName, PKG_NAME_SIZE_MAX, pkgName, strlen(pkgName)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy pkgName fail");
        SoftBusFree(info);
        return SOFTBUS_ERR;
    }
    info->addr = *addr;
    ListAdd(&list->list, &info->node);
    list->cnt++;
    return SOFTBUS_OK;
}

static bool IsRepeatLeaveLNNRequest(const char *pkgName, const char *networkId)
{
    LeaveLnnRequestInfo *info = NULL;
    SoftBusList *list = g_lnnRequestInfo.leaveLNNRequestInfo;
    LIST_FOR_EACH_ENTRY(info, &list->list, LeaveLnnRequestInfo, node) {
        if (strncmp(pkgName, info->pkgName, strlen(pkgName)) != 0) {
            continue;
        }
        if (strncmp(networkId, info->networkId, strlen(networkId)) == 0) {
            return true;
        }
    }
    return false;
}

static int32_t AddLeaveLNNInfo(const char *pkgName, const char *networkId)
{
    SoftBusList *list = g_lnnRequestInfo.leaveLNNRequestInfo;
    LeaveLnnRequestInfo *info = (LeaveLnnRequestInfo *)SoftBusMalloc(sizeof(LeaveLnnRequestInfo));
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: malloc leave LNN LeaveLnnRequestInfo");
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&info->node);
    if (strncpy_s(info->pkgName, PKG_NAME_SIZE_MAX, pkgName, strlen(pkgName)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy pkgName fail");
        SoftBusFree(info);
        return SOFTBUS_ERR;
    }
    if (strncpy_s(info->networkId, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy networkId fail");
        SoftBusFree(info);
        return SOFTBUS_ERR;
    }
    ListAdd(&list->list, &info->node);
    list->cnt++;
    return SOFTBUS_OK;
}

int32_t LnnIpcServerJoin(const char *pkgName, void *addr, uint32_t addrTypeLen)
{
    ConnectionAddr *connAddr = (ConnectionAddr *)addr;

    (void)addrTypeLen;
    if (pkgName == NULL || connAddr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parameters are NULL!\n");
        return SOFTBUS_ERR;
    }
    if (pthread_mutex_lock(&g_lnnRequestInfo.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: LnnIpcServerJoin get lock");
    }
    if (g_lnnRequestInfo.joinLNNRequestInfo == NULL) {
        g_lnnRequestInfo.joinLNNRequestInfo = CreateSoftBusList();
        if (g_lnnRequestInfo.joinLNNRequestInfo == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init fail : joinLNNRequestInfo = null!");
            (void)pthread_mutex_unlock(&g_lnnRequestInfo.lock);
            return false;
        }
    }
    if (IsRepeatJoinLNNRequest(pkgName, connAddr)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "repeat join lnn request from: %s", pkgName);
        (void)pthread_mutex_unlock(&g_lnnRequestInfo.lock);
        return SOFTBUS_ERR;
    }
    int32_t ret = LnnServerJoin(connAddr);
    if (ret == SOFTBUS_OK) {
        ret = AddJoinLNNInfo(pkgName, connAddr);
    }
    if (pthread_mutex_unlock(&g_lnnRequestInfo.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: LnnIpcServerJoin release lock");
    }
    return ret;
}

int32_t LnnIpcServerLeave(const char *pkgName, const char *networkId)
{
    if (pkgName == NULL || networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parameters are NULL!\n");
        return SOFTBUS_ERR;
    }
    if (pthread_mutex_lock(&g_lnnRequestInfo.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: LnnIpcServerLeave get lock");
    }
    if (g_lnnRequestInfo.leaveLNNRequestInfo == NULL) {
        g_lnnRequestInfo.leaveLNNRequestInfo = CreateSoftBusList();
        if (g_lnnRequestInfo.leaveLNNRequestInfo == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init fail : leaveLNNRequestInfo = null!");
            (void)pthread_mutex_unlock(&g_lnnRequestInfo.lock);
            return false;
        }
    }
    if (IsRepeatLeaveLNNRequest(pkgName, networkId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "repeat leave lnn request from: %s", pkgName);
        (void)pthread_mutex_unlock(&g_lnnRequestInfo.lock);
        return SOFTBUS_ERR;
    }
    int32_t ret = LnnServerLeave(networkId);
    if (ret == SOFTBUS_OK) {
        ret = AddLeaveLNNInfo(pkgName, networkId);
    }
    if (pthread_mutex_unlock(&g_lnnRequestInfo.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: LnnIpcServerLeave release lock");
    }
    return ret;
}

int32_t LnnIpcGetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int *infoNum)
{
    (void)pkgName;
    (void)infoTypeLen;
    return LnnGetAllOnlineNodeInfo((NodeBasicInfo **)info, infoNum);
}

int32_t LnnIpcGetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    (void)pkgName;
    (void)infoTypeLen;
    return LnnGetLocalDeviceInfo((NodeBasicInfo *)info);
}

int32_t LnnIpcGetNodeKeyInfo(const char *pkgName, const char *networkId, int key, unsigned char *buf, uint32_t len)
{
    (void)pkgName;
    return LnnGetNodeKeyInfo(networkId, key, buf, len);
}

int32_t LnnIpcStartTimeSync(const char *pkgName, const char *targetNetworkId, int32_t accuracy, int32_t period)
{
    if (pkgName == NULL || targetNetworkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parameters are NULL!\n");
        return SOFTBUS_ERR;
    }
    TimeSyncAccuracy acc = (TimeSyncAccuracy)accuracy;
    TimeSyncPeriod per = (TimeSyncPeriod)period;
    int32_t ret = LnnStartTimeSync(pkgName, targetNetworkId, acc, per);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnStartTimeSync fail from %s", pkgName);
    }
    return ret;
}

int32_t LnnIpcStopTimeSync(const char *pkgName, const char *targetNetworkId)
{
    if (pkgName == NULL || targetNetworkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parameters are NULL!\n");
        return SOFTBUS_ERR;
    }
    int32_t ret = LnnStopTimeSync(pkgName, targetNetworkId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnStopTimeSync fail from %s", pkgName);
    }
    return ret;
}

int32_t LnnIpcNotifyJoinResult(void *addr, uint32_t addrTypeLen, const char *networkId, int32_t retCode)
{
    if (addr == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    ConnectionAddr *connAddr = (ConnectionAddr *)addr;
    JoinLnnRequestInfo *info = NULL;
    SoftBusList *list = g_lnnRequestInfo.joinLNNRequestInfo;
    if (list == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "joinLNNRequestInfo = null!");
        return SOFTBUS_ERR;
    }
    if (pthread_mutex_lock(&g_lnnRequestInfo.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: LnnIpcNotifyJoinResult get lock");
    }
    while ((info = FindJoinLNNRequest(connAddr)) != NULL) {
        ListDelete(&info->node);
        ClientOnJoinLNNResult(info->pkgName, connAddr, addrTypeLen, networkId, retCode);
        --list->cnt;
        SoftBusFree(info);
    }
    if (pthread_mutex_unlock(&g_lnnRequestInfo.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: LnnIpcNotifyJoinResult release lock");
    }
    return SOFTBUS_OK;
}

int32_t LnnIpcNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    if (networkId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    LeaveLnnRequestInfo *info = NULL;
    SoftBusList *list = g_lnnRequestInfo.leaveLNNRequestInfo;
    if (list == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "leaveLNNRequestInfo = null!");
        return SOFTBUS_ERR;
    }
    if (pthread_mutex_lock(&g_lnnRequestInfo.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: LnnIpcNotifyLeaveResult get lock");
    }

    while ((info = FindLeaveLNNRequest(networkId)) != NULL) {
        ListDelete(&info->node);
        ClientOnLeaveLNNResult(info->pkgName, networkId, retCode);
        --list->cnt;
        SoftBusFree(info);
    }
    if (pthread_mutex_unlock(&g_lnnRequestInfo.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: LnnIpcNotifyLeaveResult release lock");
    }
    return SOFTBUS_OK;
}

int32_t LnnIpcNotifyOnlineState(bool isOnline, void *info, uint32_t infoTypeLen)
{
    return ClinetOnNodeOnlineStateChanged(isOnline, info, infoTypeLen);
}

int32_t LnnIpcNotifyBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    return ClinetOnNodeBasicInfoChanged(info, infoTypeLen, type);
}

int32_t LnnIpcNotifyTimeSyncResult(const char *pkgName, const void *info, uint32_t infoTypeLen, int32_t retCode)
{
    if (pkgName == NULL || info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = ClientOnTimeSyncResult(pkgName, info, infoTypeLen, retCode);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ClientOnTimeSyncResult fail from %s", pkgName);
    }
    return ret;
}

void BusCenterServerDeathCallback(const char *pkgName)
{
    (void)pkgName;
}