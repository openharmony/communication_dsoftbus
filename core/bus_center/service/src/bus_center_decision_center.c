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

#include "anonymizer.h"
#include "bus_center_manager.h"
#include "lnn_log.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_net_builder.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

#define HCI_ERR_BR_CONN_PAGE_TIMEOUT 0x04
#define HCI_ERR_BR_CONN_PEER_NOT_SUPORT_SDP_RECODE 0x54
#define HCI_ERR_BR_CONN_ACL_RECREATE 0x57

#define BR_PAGETIMEOUT_OFFLINE_COUNT 3
#define BR_SDP_NOT_SUPORT_OFFLINE_COUNT 2

typedef struct {
    ListNode node;
    int32_t errorCode;
    uint32_t count;
    ConnectOption option;
} ExceptionConnInfo;

typedef struct {
    SoftBusList *connections;
    bool initFlag;
} ExceptionConnMgr;

static ExceptionConnMgr g_exceptionConnMgr;

static void LeaveSpecificBrNetwork(const char *addr)
{
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (LnnGetNetworkIdByBtMac(addr, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "networkId not found by addr");
        return;
    }

    int32_t ret = LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_BR);
    if (ret != SOFTBUS_OK) {
        LNN_LOGW(LNN_STATE, "leave br network failed, ret=%{public}d", ret);
    }
    LNN_LOGI(LNN_STATE, "leave br network finished");
}

static void HandleBrConnectException(const ConnectOption *option, int32_t errorCode)
{
    if (errorCode != HCI_ERR_BR_CONN_PAGE_TIMEOUT && errorCode != HCI_ERR_BR_CONN_PEER_NOT_SUPORT_SDP_RECODE &&
        errorCode != HCI_ERR_BR_CONN_ACL_RECREATE) {
        return;
    }
    if (errorCode == HCI_ERR_BR_CONN_ACL_RECREATE) {
        LeaveSpecificBrNetwork(option->brOption.brMac);
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
        LNN_LOGD(LNN_STATE,
            "exception connect info: errorCode=%{public}d, count=%{public}d", target->errorCode, target->count);
        if ((target->errorCode == HCI_ERR_BR_CONN_PAGE_TIMEOUT && target->count >= BR_PAGETIMEOUT_OFFLINE_COUNT) ||
            (target->errorCode == HCI_ERR_BR_CONN_PEER_NOT_SUPORT_SDP_RECODE &&
            target->count >= BR_SDP_NOT_SUPORT_OFFLINE_COUNT)) {
            LeaveSpecificBrNetwork(option->brOption.brMac);
            ListDelete(&target->node);
            SoftBusFree(target);
            g_exceptionConnMgr.connections->cnt--;
        }
        return;
    }

    ExceptionConnInfo *connInfo = SoftBusCalloc(sizeof(ExceptionConnInfo));
    LNN_CHECK_AND_RETURN_LOGE(connInfo != NULL, LNN_STATE, "calloc br conn info failed");
    if (strcpy_s(connInfo->option.brOption.brMac, BT_MAC_LEN, option->brOption.brMac) != EOK) {
        LNN_LOGE(LNN_STATE, "copy address failed");
        SoftBusFree(connInfo);
        return;
    }
    ListInit(&connInfo->node);
    connInfo->option.type = option->type;
    connInfo->option.brOption.sideType = option->brOption.sideType;
    connInfo->errorCode = errorCode;
    connInfo->count = 1;

    LNN_LOGD(LNN_STATE, "exception connect info: errorCode=%{public}d, count=1", errorCode);
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
    LNN_CHECK_AND_RETURN_LOGW(option != NULL, LNN_STATE, "option is NULL");
    LNN_CHECK_AND_RETURN_LOGE(g_exceptionConnMgr.initFlag && g_exceptionConnMgr.connections != NULL,
        LNN_STATE, "decision center not init yet");
    SoftBusMutexLock(&g_exceptionConnMgr.connections->lock);
    LNN_LOGI(LNN_STATE, "connType=%{public}d, errorCode=%{public}d", option->type, errorCode);
    switch (option->type) {
        case CONNECT_BR:
            HandleBrConnectException(option, errorCode);
            break;
        default:
            LNN_LOGW(LNN_STATE, "undefined connType=%{public}d", option->type);
            break;
    }
    SoftBusMutexUnlock(&g_exceptionConnMgr.connections->lock);
}

void LnnDCClearConnectException(const ConnectOption *option)
{
    LNN_CHECK_AND_RETURN_LOGW(option != NULL, LNN_STATE, "option is NULL");
    LNN_CHECK_AND_RETURN_LOGE(g_exceptionConnMgr.initFlag && g_exceptionConnMgr.connections != NULL,
        LNN_STATE, "decision center not init yet");
    SoftBusMutexLock(&g_exceptionConnMgr.connections->lock);
    switch (option->type) {
        case CONNECT_BR:
            ClearBrConnectException(option);
            break;
        default:
            LNN_LOGW(LNN_STATE, "undefined connType=%{public}d", option->type);
            break;
    }
    SoftBusMutexUnlock(&g_exceptionConnMgr.connections->lock);
}

void LnnDCProcessOnlineState(bool isOnline, const NodeBasicInfo *info)
{
    LNN_CHECK_AND_RETURN_LOGW(info != NULL, LNN_STATE, " info is NULL");
    char *anonyNetworkId = NULL;
    Anonymize(info->networkId, &anonyNetworkId);
    LNN_LOGI(LNN_STATE, "onlineState=%{public}s, networkId=%{public}s",
        (isOnline ? "online" : "offline"), AnonymizeWrapper(anonyNetworkId));
    if (isOnline) {
        LNN_LOGD(LNN_LEDGER, "ignore for online");
        AnonymizeFree(anonyNetworkId);
        return;
    }

    NodeInfo nodeInfo = { 0 };
    if (LnnGetRemoteNodeInfoById(info->networkId, CATEGORY_NETWORK_ID, &nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "can not get remote nodeinfo. networkId=%{public}s",
            AnonymizeWrapper(anonyNetworkId));
        AnonymizeFree(anonyNetworkId);
        return;
    }
    AnonymizeFree(anonyNetworkId);
    ConnectOption option = { 0 };
    option.type = CONNECT_BR;
    if (strcpy_s(option.brOption.brMac, BT_MAC_LEN, LnnGetBtMac(&nodeInfo)) == EOK) {
        LnnDCClearConnectException(&option);
    }
}

int32_t InitDecisionCenter(void)
{
    g_exceptionConnMgr.connections = CreateSoftBusList();
    if (g_exceptionConnMgr.connections == NULL) {
        LNN_LOGE(LNN_INIT, "creat exception conn mgr list failed");
        g_exceptionConnMgr.initFlag = false;
        return SOFTBUS_CREATE_LIST_ERR;
    }
    g_exceptionConnMgr.initFlag = true;
    LNN_LOGD(LNN_INIT, "init ok");
    return SOFTBUS_OK;
}

void DeinitDecisionCenter(void)
{
    g_exceptionConnMgr.initFlag = false;
    if (g_exceptionConnMgr.connections != NULL) {
        DestroySoftBusList(g_exceptionConnMgr.connections);
        g_exceptionConnMgr.connections = NULL;
    }
    LNN_LOGD(LNN_INIT, "deinit ok");
}