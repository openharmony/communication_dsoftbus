/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "bus_center_decision_center.h"

#include <stdbool.h>
#include <securec.h>
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_net_builder.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

#define HCI_ERR_BR_CONN_PAGE_TIMEOUT 0x04
#define HCI_ERR_BR_CONN_PEER_NOT_SUPORT_SDP_RECODE 0x54

#define BR_PAGETIMEOUT_OFFLINE_COUNT 4
#define BR_SDP_NOT_SUPORT_OFFLINE_COUNT 2

typedef struct {
    ListNode node;
    ConnectOption option;
    int32_t errorCode;
    uint32_t count;
} ExceptionConnInfo;

typedef struct {
    SoftBusList *connections;
    bool initFlag;
} ExceptionConnMgr;

static ExceptionConnMgr g_exceptionConnMgr;

static void LeaveSpecificBrBleNetwork(const char *addr)
{
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (LnnGetNetworkIdByBtMac(addr, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        LLOGE("networkId not found by addr");
        return;
    }

    int32_t ret = LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_BR);
    if (ret != SOFTBUS_OK) {
        LLOGW("leave br network failed, ret=%d", ret);
    }

    ret = LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_BR);
    if (ret != SOFTBUS_OK) {
        LLOGW("leave ble nework failed, ret=%d", ret);
    }
    LLOGI("leave br and ble network finished");
}

static void HandleBrConnectException(const ConnectOption *option, int32_t errorCode)
{
    if (errorCode != HCI_ERR_BR_CONN_PAGE_TIMEOUT && errorCode != HCI_ERR_BR_CONN_PEER_NOT_SUPORT_SDP_RECODE) {
        return;
    }

    ExceptionConnInfo *target = NULL;
    ExceptionConnInfo *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_exceptionConnMgr.connections->list, ExceptionConnInfo, node) {
        if (StrCmpIgnoreCase(it->option.brOption.brMac, option->brOption.brMac) == 0 &&
            it->errorCode == errorCode) {
            target = it;
            break;
        }
    }

    if (target != NULL) {
        target->count++;
        LLOGD("exception cannect info: errorCode=%d, count=%d", target->errorCode, target->count);
        if ((target->errorCode == HCI_ERR_BR_CONN_PAGE_TIMEOUT && target->count >= BR_PAGETIMEOUT_OFFLINE_COUNT) ||
            (target->errorCode == HCI_ERR_BR_CONN_PEER_NOT_SUPORT_SDP_RECODE &&
            target->count >= BR_SDP_NOT_SUPORT_OFFLINE_COUNT)) {
            LeaveSpecificBrBleNetwork(option->brOption.brMac);
            ListDelete(&target->node);
            SoftBusFree(target);
            g_exceptionConnMgr.connections->cnt--;
        }
        return;
    }

    ExceptionConnInfo *connInfo = SoftBusCalloc(sizeof(ExceptionConnInfo));
    CONN_CHECK_AND_RETURN_LOG(connInfo != NULL, "calloc br conn info failed");
    if (strcpy_s(connInfo->option.brOption.brMac, BT_MAC_LEN, option->brOption.brMac) != EOK) {
        LLOGE("copy address failed");
        SoftBusFree(connInfo);
        return;
    }
    ListInit(&connInfo->node);
    connInfo->option.type = option->type;
    connInfo->option.brOption.sideType = option->brOption.sideType;
    connInfo->errorCode = errorCode;
    connInfo->count = 1;

    LLOGD("exception connect info: errorCode=%d, count=1", errorCode);
    ListAdd(&g_exceptionConnMgr.connections->list, &connInfo->node);
    g_exceptionConnMgr.connections->cnt++;
}

static void ClearBrConnectException(const ConnectOption *option)
{
    ExceptionConnInfo *it = NULL;
    ExceptionConnInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &g_exceptionConnMgr.connections->list, ExceptionConnInfo, node) {
        if (StrCmpIgnoreCase(it->option.brOption.brMac, option->brOption.brMac) == 0) {
            ListDelete(&it->node);
            SoftBusFree(it);
            g_exceptionConnMgr.connections->cnt--;
        }
    }
}

void LnnDCReportConnectException(const ConnectOption *option, int32_t errorCode)
{
    LNN_CHECK_AND_RETURN_LOG(option != NULL, "LnnDCReportConnectException: option is NULL");
    LNN_CHECK_AND_RETURN_LOG(g_exceptionConnMgr.initFlag && g_exceptionConnMgr.connections != NULL,
        "LnnDCReportConnectException: decision center not init yet");
    SoftBusMutexLock(&g_exceptionConnMgr.connections->lock);
    LLOGI("conn type:%d, error code:%d", option->type, errorCode);
    switch (option->type) {
        case CONNECT_BR:
            HandleBrConnectException(option, errorCode);
            break;
        default:
            LLOGW("undefined connection type: %d", option->type);
            break;
    }
    SoftBusMutexUnlock(&g_exceptionConnMgr.connections->lock);
}

void LnnDCClearConnectException(const ConnectOption *option)
{
    LNN_CHECK_AND_RETURN_LOG(option != NULL, "LnnDCClearConnectException: option is NULL");
    LNN_CHECK_AND_RETURN_LOG(g_exceptionConnMgr.initFlag && g_exceptionConnMgr.connections != NULL,
        "LnnDCReportConnectException: decision center not init yet");
    SoftBusMutexLock(&g_exceptionConnMgr.connections->lock);
    LLOGI("conn type:%d", option->type);
    switch (option->type) {
        case CONNECT_BR:
            ClearBrConnectException(option);
            break;
        default:
            LLOGW("undefined connection type: %d", option->type);
            break;
    }
    SoftBusMutexUnlock(&g_exceptionConnMgr.connections->lock);
}

void LnnDCProcessOnlineState(bool isOnline, const NodeBasicInfo *info)
{
    LNN_CHECK_AND_RETURN_LOG(info != NULL, "LnnDCProcessOnlineState: info is NULL");
    LLOGI("state:%s, networkId:%s", (isOnline ? "online" : "offline"), AnonymizesNetworkID(info->networkId));
    if (isOnline) {
        LLOGD("ignore for online");
        return;
    }

    NodeInfo nodeInfo = { 0 };
    if (LnnGetRemoteNodeInfoById(info->networkId, CATEGORY_NETWORK_ID, &nodeInfo) != SOFTBUS_OK) {
        LLOGE("can not get remote nodeinfo by networkId:%s", AnonymizesNetworkID(info->networkId));
        return;
    }
    ConnectOption option = { 0 };
    option.type = CONNECT_BR;
    if (strcpy_s(option.brOption.brMac, BT_MAC_LEN, LnnGetBtMac(&nodeInfo)) == EOK) {
        LnnDCClearConnectException(&option);
    }
}

int32_t InitDecisionCenter()
{
    g_exceptionConnMgr.connections = CreateSoftBusList();
    if (g_exceptionConnMgr.connections == NULL) {
        LLOGE("creat exception conn mgr list failed");
        g_exceptionConnMgr.initFlag = false;
        return SOFTBUS_ERR;
    }
    g_exceptionConnMgr.initFlag = true;
    LLOGE("init ok");
    return SOFTBUS_OK;
}

void DeinitDecisionCenter()
{
    g_exceptionConnMgr.initFlag = false;
    if (g_exceptionConnMgr.connections != NULL) {
        DestroySoftBusList(g_exceptionConnMgr.connections);
        g_exceptionConnMgr.connections = NULL;
    }
    LLOGI("deinit ok");
}