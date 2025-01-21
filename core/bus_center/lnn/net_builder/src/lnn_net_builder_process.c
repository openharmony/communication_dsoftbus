/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "lnn_net_builder.h"

#include <securec.h>
#include <stdlib.h>
#include <inttypes.h>

#include "anonymizer.h"
#include "auth_common.h"
#include "auth_deviceprofile.h"
#include "auth_interface.h"
#include "auth_request.h"
#include "auth_request.h"
#include "auth_hichain_adapter.h"
#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "common_list.h"
#include "lnn_async_callback_utils.h"
#include "lnn_battery_info.h"
#include "lnn_cipherkey_manager.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_connection_fsm.h"
#include "lnn_deviceinfo_to_profile.h"
#include "lnn_devicename_info.h"
#include "lnn_discovery_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_fast_offline.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_link_finder.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_map.h"
#include "lnn_network_id.h"
#include "lnn_network_info.h"
#include "lnn_network_manager.h"
#include "lnn_node_info.h"
#include "lnn_node_weight.h"
#include "lnn_ohos_account.h"
#include "lnn_p2p_info.h"
#include "lnn_physical_subnet_manager.h"
#include "lnn_sync_info_manager.h"
#include "lnn_sync_item_info.h"
#include "lnn_topo_manager.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_json.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "legacy/softbus_hisysevt_bus_center.h"
#include "softbus_json_utils.h"
#include "softbus_adapter_json.h"
#include "softbus_utils.h"
#include "softbus_wifi_api_adapter.h"
#include "lnn_net_builder.h"
#include "lnn_net_builder_init.h"


#define DEFAULT_PKG_NAME                 "com.huawei.nearby"
#define DEFAULT_MAX_LNN_CONNECTION_COUNT 10

typedef int32_t (*NetBuilderMessageProcess)(const void *para);

LnnConnectionFsm *FindConnectionFsmByRequestId(uint32_t requestId)
{
    LnnConnectionFsm *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &LnnGetNetBuilder()->fsmList, LnnConnectionFsm, node) {
        if (item->connInfo.requestId == requestId) {
            return item;
        }
    }
    return NULL;
}

NodeInfo *FindNodeInfoByRquestId(uint32_t requestId)
{
    LnnConnectionFsm *connFsm = FindConnectionFsmByRequestId(requestId);
    if (connFsm == NULL || connFsm->isDead) {
        LNN_LOGE(LNN_BUILDER, "can not find connection fsm. requestId=%{public}u", requestId);
        return NULL;
    }
    LNN_LOGI(LNN_BUILDER, "find connFsm success");
    if (connFsm->connInfo.nodeInfo == NULL) {
        return NULL;
    }
    return connFsm->connInfo.nodeInfo;
}

LnnConnectionFsm *FindConnectionFsmByAuthHandle(const AuthHandle *authHandle)
{
    LnnConnectionFsm *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &LnnGetNetBuilder()->fsmList, LnnConnectionFsm, node) {
        if (item->connInfo.authHandle.authId == authHandle->authId &&
            item->connInfo.authHandle.type == authHandle->type) {
            return item;
        }
    }
    return NULL;
}

LnnConnectionFsm *FindConnectionFsmByAddr(const ConnectionAddr *addr, bool isShort)
{
    LnnConnectionFsm *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &LnnGetNetBuilder()->fsmList, LnnConnectionFsm, node) {
        if (LnnIsSameConnectionAddr(addr, &item->connInfo.addr, isShort)) {
            return item;
        }
    }
    return NULL;
}

static LnnConnectionFsm *FindConnectionFsmByNetworkId(const char *networkId)
{
    LnnConnectionFsm *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &LnnGetNetBuilder()->fsmList, LnnConnectionFsm, node) {
        if (strcmp(networkId, item->connInfo.peerNetworkId) == 0) {
            return item;
        }
    }
    return NULL;
}

int32_t FindRequestIdByAddr(ConnectionAddr *connetionAddr, uint32_t *requestId)
{
    if (requestId == NULL) {
        LNN_LOGE(LNN_BUILDER, "requestId is null");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnConnectionFsm *connFsm = FindConnectionFsmByAddr(connetionAddr, false);
    if (connFsm == NULL || connFsm->isDead) {
        LNN_LOGE(LNN_BUILDER, "can not find connection fsm by addr");
        return SOFTBUS_NETWORK_NOT_FOUND;
    }
    LNN_LOGD(LNN_BUILDER, "find connFsm success");
    *requestId = connFsm->connInfo.requestId;
    return SOFTBUS_OK;
}

LnnConnectionFsm *StartNewConnectionFsm(const ConnectionAddr *addr, const char *pkgName, bool isNeedConnect)
{
    LnnConnectionFsm *connFsm = NULL;

    if (LnnGetNetBuilder()->connCount >= LnnGetNetBuilder()->maxConnCount) {
        LNN_LOGE(LNN_BUILDER, "current connection num exceeds max limit, connCount=%{public}d",
            LnnGetNetBuilder()->connCount);
        return NULL;
    }
    connFsm = LnnCreateConnectionFsm(addr, pkgName, isNeedConnect);
    if (connFsm == NULL) {
        LNN_LOGE(LNN_BUILDER, "create connection fsm failed");
        return NULL;
    }
    if (LnnStartConnectionFsm(connFsm) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "start connection failed. fsmId=%{public}u", connFsm->id);
        LnnDestroyConnectionFsm(connFsm);
        return NULL;
    }
    SetBeginJoinLnnTime(connFsm);
    ListAdd(&LnnGetNetBuilder()->fsmList, &connFsm->node);
    ++LnnGetNetBuilder()->connCount;
    return connFsm;
}

void CleanConnectionFsm(LnnConnectionFsm *connFsm)
{
    if (connFsm == NULL) {
        LNN_LOGE(LNN_BUILDER, "connection fsm is null");
        return;
    }
    LNN_LOGI(LNN_BUILDER, "connection is cleaned. fsmId=%{public}u", connFsm->id);
    LnnDestroyConnectionFsm(connFsm);
}

void StopConnectionFsm(LnnConnectionFsm *connFsm)
{
    if (LnnStopConnectionFsm(connFsm, CleanConnectionFsm) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "stop connection failed. fsmId=%{public}u", connFsm->id);
    }
    ListDelete(&connFsm->node);
    --LnnGetNetBuilder()->connCount;
}

static int32_t CreatePassiveConnectionFsm(const DeviceVerifyPassMsgPara *msgPara)
{
    LnnConnectionFsm *connFsm = NULL;
    connFsm = StartNewConnectionFsm(&msgPara->addr, DEFAULT_PKG_NAME, true);
    if (connFsm == NULL) {
        LNN_LOGE(LNN_BUILDER, "start new connection fsm fail, authId=%{public}" PRId64, msgPara->authHandle.authId);
        return SOFTBUS_NETWORK_FSM_START_FAIL;
    }
    connFsm->connInfo.authHandle = msgPara->authHandle;
    connFsm->connInfo.nodeInfo = msgPara->nodeInfo;
    connFsm->connInfo.flag |= LNN_CONN_INFO_FLAG_JOIN_PASSIVE;
    LNN_LOGI(LNN_BUILDER, "fsmId=%{public}u start a passive connection fsm, type=%{public}d, authId=%{public}" PRId64,
        connFsm->id, msgPara->authHandle.type, msgPara->authHandle.authId);
    int32_t ret = LnnSendAuthResultMsgToConnFsm(connFsm, SOFTBUS_OK);
    if (ret != SOFTBUS_OK) {
        connFsm->connInfo.nodeInfo = NULL;
        StopConnectionFsm(connFsm);
        LNN_LOGE(LNN_BUILDER, "fsmId=%{public}u post auth result to connection fsm fail, authId=%{public}" PRId64,
            connFsm->id, msgPara->authHandle.authId);
        return ret;
    }
    return SOFTBUS_OK;
}

static bool IsInvalidConnectionFsm(const LnnConnectionFsm *connFsm, const LeaveInvalidConnMsgPara *msgPara)
{
    if (strcmp(msgPara->oldNetworkId, connFsm->connInfo.peerNetworkId) != 0) {
        return false;
    }
    if (connFsm->isDead) {
        LNN_LOGI(LNN_BUILDER, "connection is dead. fsmId=%{public}u", connFsm->id);
        return false;
    }
    if (msgPara->addrType != CONNECTION_ADDR_MAX && msgPara->addrType != connFsm->connInfo.addr.type) {
        LNN_LOGI(LNN_BUILDER,
            "connection type not match. fsmId=%{public}u, msgAddrType=%{public}d, connAddrType=%{public}d", connFsm->id,
            msgPara->addrType, connFsm->connInfo.addr.type);
        return false;
    }
    if ((connFsm->connInfo.flag & LNN_CONN_INFO_FLAG_ONLINE) == 0) {
        LNN_LOGI(LNN_BUILDER, "connection is not online. fsmId=%{public}u", connFsm->id);
        return false;
    }
    if ((connFsm->connInfo.flag & LNN_CONN_INFO_FLAG_INITIATE_ONLINE) != 0) {
        LNN_LOGI(LNN_BUILDER, "connection is already in leaving. fsmId=%{public}u", connFsm->id);
        return false;
    }
    return true;
}

static int32_t ProcessJoinLNNRequest(const void *para)
{
    return TrySendJoinLNNRequest((const JoinLnnMsgPara *)para, true, false);
}

static int32_t ProcessDevDiscoveryRequest(const void *para)
{
    return TrySendJoinLNNRequest((const JoinLnnMsgPara *)para, false, false);
}

static int32_t ProcessCleanConnectionFsm(const void *para)
{
    uint16_t connFsmId;
    LnnConnectionFsm *connFsm = NULL;
    int32_t rc = SOFTBUS_NETWORK_FSM_CLEAN_FAILED;

    if (para == NULL) {
        LNN_LOGW(LNN_BUILDER, "connFsmId is null");
        return SOFTBUS_INVALID_PARAM;
    }
    connFsmId = *(uint16_t *)para;
    do {
        connFsm = FindConnectionFsmByConnFsmId(connFsmId);
        if (connFsm == NULL) {
            LNN_LOGE(LNN_BUILDER, "can not find connection fsm");
            break;
        }
        StopConnectionFsm(connFsm);
        TryInitiateNewNetworkOnline(connFsm);
        TryDisconnectAllConnection(connFsm);
        TryNotifyAllTypeOffline(connFsm);
        TryRemovePendingJoinRequest();
        rc = SOFTBUS_OK;
    } while (false);
    SoftBusFree((void *)para);
    return rc;
}

static int32_t ProcessVerifyResult(const void *para)
{
    int32_t rc;
    LnnConnectionFsm *connFsm = NULL;
    const VerifyResultMsgPara *msgPara = (const VerifyResultMsgPara *)para;

    if (msgPara == NULL) {
        LNN_LOGW(LNN_BUILDER, "para is null");
        return SOFTBUS_INVALID_PARAM;
    }

    do {
        connFsm = FindConnectionFsmByRequestId(msgPara->requestId);
        if (connFsm == NULL || connFsm->isDead) {
            LNN_LOGE(LNN_BUILDER, "can not find connection fsm by request. requestId=%{public}u", msgPara->requestId);
            rc = SOFTBUS_NETWORK_NOT_FOUND;
            break;
        }
        LNN_LOGI(LNN_BUILDER, "[id=%{public}u] connection fsm auth done, type=%{public}d, authId=%{public}"
            PRId64 ", retCode=%{public}d", connFsm->id, msgPara->authHandle.type,
            msgPara->authHandle.authId, msgPara->retCode);
        if (msgPara->retCode == SOFTBUS_OK) {
            if (msgPara->nodeInfo == NULL) {
                LNN_LOGE(LNN_BUILDER, "msgPara node Info is null, stop fsm [id=%{public}u]", connFsm->id);
                StopConnectionFsm(connFsm);
                rc = SOFTBUS_INVALID_PARAM;
                break;
            }
            connFsm->connInfo.authHandle = msgPara->authHandle;
            connFsm->connInfo.nodeInfo = msgPara->nodeInfo;
        }
        rc = LnnSendAuthResultMsgToConnFsm(connFsm, msgPara->retCode);
        if (rc != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "send auth result to connection failed. [id=%{public}u]", connFsm->id);
            connFsm->connInfo.nodeInfo = NULL;
            break;
        }
    } while (false);

    if (rc != SOFTBUS_OK && msgPara->nodeInfo != NULL) {
        SoftBusFree((void *)msgPara->nodeInfo);
    }
    SoftBusFree((void *)msgPara);
    return rc;
}

static int32_t JudgingBleState(uint32_t remote)
{
    uint32_t local;
    int32_t ret = LnnGetLocalNumU32Info(NUM_KEY_NET_CAP, &local);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local num info failed");
        return SOFTBUS_NETWORK_LEDGER_INIT_FAILED;
    }
    if (((local & (1 << BIT_BLE)) == 0) || ((remote & (1 << BIT_BLE)) == 0)) {
        LNN_LOGE(LNN_BUILDER, "can't support BLE, local=%{public}u, remote=%{public}u", local, remote);
        return SOFTBUS_BLUETOOTH_OFF;
    }
    return SOFTBUS_OK;
}

static int32_t ProcessEnhancedP2pDupBle(const DeviceVerifyPassMsgPara *msgPara)
{
    if (JudgingBleState(msgPara->nodeInfo->netCapacity) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "can't support BLE");
        return SOFTBUS_BLUETOOTH_OFF;
    }
    int32_t ret = 0;
    switch (msgPara->authHandle.type) {
        case AUTH_LINK_TYPE_ENHANCED_P2P:
            ret = ProcessBleOnline(msgPara->nodeInfo, &(msgPara->addr), BIT_SUPPORT_ENHANCEDP2P_DUP_BLE);
            break;
        case AUTH_LINK_TYPE_SESSION:
            ret = ProcessBleOnline(msgPara->nodeInfo, &(msgPara->addr), BIT_SUPPORT_SESSION_DUP_BLE);
            AuthRemoveAuthManagerByAuthHandle(msgPara->authHandle);
            break;
        default:
            LNN_LOGE(LNN_BUILDER, "auth type is %{public}d, not support", msgPara->authHandle.type);
            ret = SOFTBUS_FUNC_NOT_SUPPORT;
    }
    return ret;
}

static int32_t ProcessDeviceVerifyPass(const void *para)
{
    int32_t rc;
    LnnConnectionFsm *connFsm = NULL;
    const DeviceVerifyPassMsgPara *msgPara = (const DeviceVerifyPassMsgPara *)para;

    if (msgPara == NULL) {
        LNN_LOGW(LNN_BUILDER, "para is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (msgPara->nodeInfo == NULL) {
        LNN_LOGE(LNN_BUILDER, "msgPara nodeInfo is null");
        SoftBusFree((void *)msgPara);
        return SOFTBUS_INVALID_PARAM;
    }

    if (msgPara->authHandle.type == AUTH_LINK_TYPE_ENHANCED_P2P ||
            msgPara->authHandle.type == AUTH_LINK_TYPE_SESSION) {
        LNN_LOGI(LNN_BUILDER, "auth type is %{public}d, start dup ble.", msgPara->authHandle.type);
        rc = ProcessEnhancedP2pDupBle(msgPara);
        if (msgPara->nodeInfo != NULL) {
            SoftBusFree((void *)msgPara->nodeInfo);
        }
        SoftBusFree((void *)msgPara);
        return rc;
    }

    do {
        connFsm = FindConnectionFsmByAuthHandle(&msgPara->authHandle);
        if (connFsm == NULL || connFsm->isDead) {
            rc = CreatePassiveConnectionFsm(msgPara);
            break;
        }
        if (LnnIsNeedCleanConnectionFsm(msgPara->nodeInfo, msgPara->addr.type)) {
            rc = CreatePassiveConnectionFsm(msgPara);
            break;
        }
        msgPara->nodeInfo->discoveryType = 1 << (uint32_t)LnnConvAddrTypeToDiscType(msgPara->addr.type);
        if (LnnUpdateNodeInfo(msgPara->nodeInfo, msgPara->addr.type) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "LnnUpdateNodeInfo failed");
        }
        LNN_LOGI(LNN_BUILDER, "fsmId=%{public}u connection fsm exist, ignore VerifyPass authId=%{public}" PRId64,
            connFsm->id, msgPara->authHandle.authId);
        rc = SOFTBUS_ALREADY_EXISTED;
    } while (false);

    if (rc != SOFTBUS_OK && msgPara->nodeInfo != NULL) {
        SoftBusFree((void *)msgPara->nodeInfo);
    }
    SoftBusFree((void *)msgPara);
    return rc;
}

static int32_t ProcessDeviceDisconnect(const void *para)
{
    int32_t rc;
    LnnConnectionFsm *connFsm = NULL;
    const AuthHandle *authHandle = (const AuthHandle *)para;

    if (authHandle == NULL) {
        LNN_LOGW(LNN_BUILDER, "auth authHandle is null");
        return SOFTBUS_INVALID_PARAM;
    }

    do {
        connFsm = FindConnectionFsmByAuthHandle(authHandle);
        if (connFsm == NULL || connFsm->isDead) {
            LNN_LOGE(LNN_BUILDER, "can not find connection fsm. authId=%{public}" PRId64, authHandle->authId);
            rc = SOFTBUS_NETWORK_NOT_FOUND;
            break;
        }
        LNN_LOGI(LNN_BUILDER, "fsmId=%{public}u device disconnect, authId=%{public}" PRId64,
            connFsm->id, authHandle->authId);
        rc = LnnSendDisconnectMsgToConnFsm(connFsm);
        if (rc != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "send disconnect to connection failed. fsmId=%{public}u", connFsm->id);
            break;
        }
    } while (false);
    SoftBusFree((void *)authHandle);
    return rc;
}


static int32_t ProcessDeviceNotTrusted(const void *para)
{
    int32_t rc;
    const char *udid = NULL;
    LnnConnectionFsm *item = NULL;
    const char *peerUdid = (const char *)para;

    if (peerUdid == NULL) {
        LNN_LOGW(LNN_BUILDER, "peer udid is null");
        return SOFTBUS_INVALID_PARAM;
    }

    do {
        char networkId[NETWORK_ID_BUF_LEN] = { 0 };
        if (LnnGetNetworkIdByUdid(peerUdid, networkId, sizeof(networkId)) == SOFTBUS_OK) {
            LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_MAX);
            break;
        }
        LIST_FOR_EACH_ENTRY(item, &LnnGetNetBuilder()->fsmList, LnnConnectionFsm, node) {
            udid = LnnGetDeviceUdid(item->connInfo.nodeInfo);
            if (udid == NULL || strcmp(peerUdid, udid) != 0) {
                continue;
            }
            rc = LnnSendNotTrustedToConnFsm(item);
            LNN_LOGI(LNN_BUILDER, "send not trusted msg to connection fsm. fsmId=%{public}u, result=%{public}d",
                item->id, rc);
        }
    } while (false);
    SoftBusFree((void *)peerUdid);
    return SOFTBUS_OK;
}

static int32_t ProcessLeaveLNNRequest(const void *para)
{
    const char *networkId = (const char *)para;
    LnnConnectionFsm *item = NULL;
    int rc = SOFTBUS_NETWORK_NOT_FOUND;

    if (networkId == NULL) {
        LNN_LOGW(LNN_BUILDER, "leave networkId is null");
        return SOFTBUS_INVALID_PARAM;
    }

    LIST_FOR_EACH_ENTRY(item, &LnnGetNetBuilder()->fsmList, LnnConnectionFsm, node) {
        if (strcmp(networkId, item->connInfo.peerNetworkId) != 0 || item->isDead) {
            continue;
        }
        rc = LnnSendLeaveRequestToConnFsm(item);
        if (rc != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "send leave LNN msg to connection failed. fsmId=%{public}u", item->id);
        } else {
            item->connInfo.flag |= LNN_CONN_INFO_FLAG_LEAVE_REQUEST;
            LNN_LOGI(LNN_BUILDER, "send leave LNN msg to connection success. fsmId=%{public}u", item->id);
        }
    }
    if (rc != SOFTBUS_OK) {
        LnnNotifyLeaveResult(networkId, SOFTBUS_NETWORK_REQ_LEAVE_LNN_FAIL);
    }
    SoftBusFree((void *)networkId);
    return rc;
}

static int32_t ProcessSyncOfflineFinish(const void *para)
{
    const char *networkId = (const char *)para;
    LnnConnectionFsm *item = NULL;
    int rc = SOFTBUS_OK;

    if (networkId == NULL) {
        LNN_LOGW(LNN_BUILDER, "sync offline finish networkId is null");
        return SOFTBUS_INVALID_PARAM;
    }
    LIST_FOR_EACH_ENTRY(item, &LnnGetNetBuilder()->fsmList, LnnConnectionFsm, node) {
        if (strcmp(networkId, item->connInfo.peerNetworkId) != 0 || item->isDead) {
            continue;
        }
        rc = LnnSendSyncOfflineFinishToConnFsm(item);
        LNN_LOGI(LNN_BUILDER, "send sync offline msg to connection fsmId=%{public}u, result=%{public}d", item->id, rc);
    }
    SoftBusFree((void *)networkId);
    return rc;
}

static int32_t ProcessLeaveInvalidConn(const void *para)
{
    LnnConnectionFsm *item = NULL;
    int32_t rc = SOFTBUS_OK;
    int32_t count = 0;
    const LeaveInvalidConnMsgPara *msgPara = (const LeaveInvalidConnMsgPara *)para;

    if (msgPara == NULL) {
        LNN_LOGW(LNN_BUILDER, "leave invalid connection msg para is null");
        return SOFTBUS_INVALID_PARAM;
    }
    LIST_FOR_EACH_ENTRY(item, &LnnGetNetBuilder()->fsmList, LnnConnectionFsm, node) {
        if (!IsInvalidConnectionFsm(item, msgPara)) {
            continue;
        }
        // The new connFsm should timeout when following errors occur
        ++count;
        item->connInfo.cleanInfo = (LnnInvalidCleanInfo *)SoftBusMalloc(sizeof(LnnInvalidCleanInfo));
        if (item->connInfo.cleanInfo == NULL) {
            LNN_LOGI(LNN_BUILDER, "malloc invalid clean info failed. fsmId=%{public}u", item->id);
            continue;
        }
        item->connInfo.cleanInfo->addrType = msgPara->addrType;
        if (strncpy_s(item->connInfo.cleanInfo->networkId, NETWORK_ID_BUF_LEN,
            msgPara->newNetworkId, strlen(msgPara->newNetworkId)) != EOK) {
            LNN_LOGE(LNN_BUILDER, "copy new networkId failed. fsmId=%{public}u", item->id);
            rc = SOFTBUS_STRCPY_ERR;
            SoftBusFree(item->connInfo.cleanInfo);
            item->connInfo.cleanInfo = NULL;
            continue;
        }
        rc = LnnSendLeaveRequestToConnFsm(item);
        if (rc == SOFTBUS_OK) {
            item->connInfo.flag |= LNN_CONN_INFO_FLAG_INITIATE_ONLINE;
            item->connInfo.flag |= LNN_CONN_INFO_FLAG_LEAVE_AUTO;
        } else {
            SoftBusFree(item->connInfo.cleanInfo);
            item->connInfo.cleanInfo = NULL;
        }
        LNN_LOGI(
            LNN_BUILDER, "send leave LNN msg to invalid connection. fsmId=%{public}u, result=%{public}d", item->id, rc);
    }
    if (count == 0) {
        InitiateNewNetworkOnline(msgPara->addrType, msgPara->newNetworkId);
    }
    SoftBusFree((void *)msgPara);
    return rc;
}

static int32_t ProcessNodeStateChanged(const void *para)
{
    const ConnectionAddr *addr = (const ConnectionAddr *)para;
    LnnConnectionFsm *connFsm = NULL;
    int32_t rc = SOFTBUS_NETWORK_NOT_FOUND;
    bool isOnline = false;

    if (addr == NULL) {
        LNN_LOGW(LNN_BUILDER, "node state changed msg is null");
        return SOFTBUS_INVALID_PARAM;
    }
    do {
        connFsm = FindConnectionFsmByAddr(addr, false);
        if (connFsm == NULL) {
            LNN_LOGE(LNN_BUILDER, "can't find connection fsm when node online state changed");
            break;
        }
        isOnline = IsNodeOnline(connFsm->connInfo.peerNetworkId);
        TryElectAsMasterState(connFsm->connInfo.peerNetworkId, isOnline);
        if (!IsSupportMasterNodeElect(connFsm->connInfo.version)) {
            LNN_LOGI(LNN_BUILDER, "peer not support master node elect. fsmId=%{public}u", connFsm->id);
            rc = SOFTBUS_OK;
            break;
        }
        rc = isOnline ? TryElectMasterNodeOnline(connFsm) : TryElectMasterNodeOffline(connFsm);
    } while (false);
    SoftBusFree((void *)addr);
    if (isOnline) {
        TryRemovePendingJoinRequest();
    }
    return rc;
}

static int32_t ProcessMasterElect(const void *para)
{
    const ElectMsgPara *msgPara = (const ElectMsgPara *)para;
    LnnConnectionFsm *connFsm = NULL;
    char localMasterUdid[UDID_BUF_LEN] = { 0 };
    int32_t localMasterWeight;
    int32_t compareRet;
    int32_t rc = SOFTBUS_NETWORK_NOT_FOUND;

    if (msgPara == NULL) {
        LNN_LOGW(LNN_BUILDER, "elect msg para is null");
        return SOFTBUS_INVALID_PARAM;
    }
    do {
        connFsm = FindConnectionFsmByNetworkId(msgPara->networkId);
        if (connFsm == NULL || connFsm->isDead) {
            LNN_LOGE(LNN_BUILDER, "can't find connection fsm when receive elect node");
            break;
        }
        if (!IsNodeOnline(connFsm->connInfo.peerNetworkId)) {
            LNN_LOGE(LNN_BUILDER, "peer node is already offline. fsmId=%{public}u", connFsm->id);
            break;
        }
        if (LnnGetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, localMasterUdid, UDID_BUF_LEN) != SOFTBUS_OK ||
            LnnGetLocalNumInfo(NUM_KEY_MASTER_NODE_WEIGHT, &localMasterWeight) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "get local master node info from ledger failed. fsmId=%{public}u", connFsm->id);
            break;
        }
        compareRet = LnnCompareNodeWeight(localMasterWeight, localMasterUdid,
            msgPara->masterWeight, msgPara->masterUdid);
        LNN_LOGI(LNN_BUILDER, "weight compare result: fsmId=%{public}u, result=%{public}d", connFsm->id, compareRet);
        if (compareRet != 0) {
            if (compareRet < 0) {
                UpdateLocalMasterNode(false, msgPara->masterUdid, msgPara->masterWeight);
                SendElectMessageToAll(connFsm->connInfo.peerNetworkId);
            } else {
                rc = SyncElectMessage(connFsm->connInfo.peerNetworkId);
                LNN_LOGI(LNN_BUILDER, "sync elect info to connFsmId=%{public}u, result=%{public}d", connFsm->id, rc);
            }
        }
        rc = SOFTBUS_OK;
    } while (false);
    SoftBusFree((void *)msgPara);
    return rc;
}

static int32_t ProcessLeaveByAddrType(const void *para)
{
    bool *addrType = NULL;
    LnnConnectionFsm *item = NULL;
    int32_t rc;
    bool notify = true;

    if (para == NULL) {
        LNN_LOGW(LNN_BUILDER, "leave by addr type msg para is null");
        return SOFTBUS_INVALID_PARAM;
    }

    addrType = (bool *)para;
    LIST_FOR_EACH_ENTRY(item, &LnnGetNetBuilder()->fsmList, LnnConnectionFsm, node) {
        if (!addrType[item->connInfo.addr.type]) {
            continue;
        }
        // if there are any same addr type, let last one send notify
        notify = false;
        if (item->isDead) {
            continue;
        }
        rc = LnnSendLeaveRequestToConnFsm(item);
        LNN_LOGI(LNN_BUILDER, "leave conn by addr. fsmId=%{public}u, type=%{public}d, rc=%{public}d", item->id,
            item->connInfo.addr.type, rc);
        if (rc == SOFTBUS_OK) {
            item->connInfo.flag |= LNN_CONN_INFO_FLAG_LEAVE_AUTO;
        }
    }
    LNN_LOGD(LNN_BUILDER, "notify=%{public}d, eth=%{public}d, wifi=%{public}d", notify, addrType[CONNECTION_ADDR_ETH],
        addrType[CONNECTION_ADDR_WLAN]);
    if (notify && (addrType[CONNECTION_ADDR_ETH] || addrType[CONNECTION_ADDR_WLAN])) {
        (void)LnnNotifyAllTypeOffline(CONNECTION_ADDR_MAX);
    }
    RemovePendingRequestByAddrType(addrType, CONNECTION_ADDR_MAX);
    SoftBusFree((void *)para);
    return SOFTBUS_OK;
}

static int32_t ProcessLeaveSpecific(const void *para)
{
    const SpecificLeaveMsgPara *msgPara = (const SpecificLeaveMsgPara *)para;
    LnnConnectionFsm *item = NULL;

    if (msgPara == NULL) {
        LNN_LOGW(LNN_BUILDER, "leave specific msg is null");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t rc;
    bool deviceLeave = false;
    LIST_FOR_EACH_ENTRY(item, &LnnGetNetBuilder()->fsmList, LnnConnectionFsm, node) {
        if (strcmp(item->connInfo.peerNetworkId, msgPara->networkId) != 0 ||
            (item->connInfo.addr.type != msgPara->addrType &&
            msgPara->addrType != CONNECTION_ADDR_MAX)) {
            continue;
        }
        deviceLeave = true;
        rc = LnnSendLeaveRequestToConnFsm(item);
        if (rc == SOFTBUS_OK) {
            item->connInfo.flag |= LNN_CONN_INFO_FLAG_LEAVE_AUTO;
        }
        LNN_LOGI(LNN_BUILDER, "send leave LNN msg to connection. fsmId=%{public}u, result=%{public}d", item->id, rc);
    }

    if (deviceLeave) {
        SoftBusFree((void *)msgPara);
        return SOFTBUS_OK;
    }

    do {
        NodeInfo nodeInfo;
        (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
        if (LnnGetRemoteNodeInfoById(msgPara->networkId, CATEGORY_NETWORK_ID, &nodeInfo)) {
            break;
        }

        if (nodeInfo.deviceInfo.deviceTypeId != TYPE_PC_ID ||
            strcmp(nodeInfo.networkId, nodeInfo.deviceInfo.deviceUdid) != 0) {
            break;
        }

        (void)LnnClearDiscoveryType(&nodeInfo, LnnConvAddrTypeToDiscType(msgPara->addrType));
        if (nodeInfo.discoveryType != 0) {
            LNN_LOGI(LNN_BUILDER, "pc without softbus has another discovery type");
            break;
        }

        LNN_LOGI(LNN_BUILDER, "pc without softbus offline");
        DeleteFromProfile(nodeInfo.deviceInfo.deviceUdid);
        LnnRemoveNode(nodeInfo.deviceInfo.deviceUdid);
    } while (false);
    SoftBusFree((void *)msgPara);
    return SOFTBUS_OK;
}

static int32_t ProcessLeaveByAuthId(const void *para)
{
    int32_t rc = SOFTBUS_OK;
    const int64_t *authId = (const int64_t *)para;
    if (authId == NULL) {
        LNN_LOGE(LNN_BUILDER, "authId is null");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnConnectionFsm *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &LnnGetNetBuilder()->fsmList, LnnConnectionFsm, node) {
        if (item->connInfo.authHandle.authId != *authId || item->isDead) {
            continue;
        }
        LNN_LOGI(LNN_BUILDER, "[id=%{public}u]leave reqeust, authId: %{public}" PRId64, item->id, *authId);
        rc = LnnSendLeaveRequestToConnFsm(item);
        if (rc != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "send leaveReqeust to connection fsm[id=%{public}u] failed", item->id);
        }
    }
    SoftBusFree((void *) authId);
    return rc;
}

static NetBuilderMessageProcess g_messageProcessor[MSG_TYPE_BUILD_MAX] = {
    ProcessJoinLNNRequest,
    ProcessDevDiscoveryRequest,
    ProcessCleanConnectionFsm,
    ProcessVerifyResult,
    ProcessDeviceVerifyPass,
    ProcessDeviceDisconnect,
    ProcessDeviceNotTrusted,
    ProcessLeaveLNNRequest,
    ProcessSyncOfflineFinish,
    ProcessNodeStateChanged,
    ProcessMasterElect,
    ProcessLeaveInvalidConn,
    ProcessLeaveByAddrType,
    ProcessLeaveSpecific,
    ProcessLeaveByAuthId,
};

void NetBuilderMessageHandler(SoftBusMessage *msg)
{
    int32_t ret;

    if (msg == NULL) {
        LNN_LOGE(LNN_BUILDER, "msg is null in net builder handler");
        return;
    }
    LNN_LOGI(LNN_BUILDER, "net builder process msg=%{public}d", msg->what);
    if (msg->what >= MSG_TYPE_BUILD_MAX) {
        LNN_LOGE(LNN_BUILDER, "invalid msg type");
        return;
    }
    ret = g_messageProcessor[msg->what](msg->obj);
    LNN_LOGD(LNN_BUILDER, "net builder process msg done, msg=%{public}d, ret=%{public}d", msg->what, ret);
}