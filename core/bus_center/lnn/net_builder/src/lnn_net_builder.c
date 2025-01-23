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
#include "lnn_kv_adapter_wrapper.h"
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
#include "lnn_net_builder_process.h"
#include "lnn_net_builder_init.h"
#include "trans_auth_manager.h"

#define LNN_CONN_CAPABILITY_MSG_LEN      8
#define JSON_KEY_MASTER_UDID             "MasterUdid"
#define JSON_KEY_MASTER_WEIGHT           "MasterWeight"
#define NOT_TRUSTED_DEVICE_MSG_DELAY     5000
#define SHORT_UDID_HASH_STR_LEN          16
#define DEFAULT_PKG_NAME                 "com.huawei.nearby"
#define WAIT_SEND_NOT_TRUST_MSG          200
#define PROOF_INFO_MAX_BUFFER_LEN        (2 * 1024)

static NetBuilder g_netBuilder;
static bool g_watchdogFlag = true;

static Map g_lnnDfxReportMap;
static SoftBusMutex g_lnnDfxReportMutex;
static bool g_lnnDfxReportIsInit = false;

static Map g_lnnDfxPcMap;
static SoftBusMutex g_lnnDfxPcMutex;
static bool g_lnnDfxPcIsInit = false;

void __attribute__((weak)) SfcSyncNodeAddrHandle(const char *networkId, int32_t code)
{
    (void)networkId;
    (void)code;
}

void SetWatchdogFlag(bool flag)
{
    g_watchdogFlag = flag;
}

bool GetWatchdogFlag(void)
{
    return g_watchdogFlag;
}

NetBuilder* LnnGetNetBuilder(void)
{
    return &g_netBuilder;
}
static SoftBusMessage *CreateNetBuilderMessage(int32_t msgType, void *para)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc softbus message failed");
        return NULL;
    }
    msg->what = msgType;
    msg->obj = para;
    msg->handler = &g_netBuilder.handler;
    return msg;
}

int32_t PostBuildMessageToHandler(int32_t msgType, void *para)
{
    SoftBusMessage *msg = CreateNetBuilderMessage(msgType, para);
    if (msg == NULL) {
        LNN_LOGE(LNN_BUILDER, "create softbus message failed");
        return SOFTBUS_MALLOC_ERR;
    }
    g_netBuilder.looper->PostMessage(g_netBuilder.looper, msg);
    return SOFTBUS_OK;
}

bool IsNodeOnline(const char *networkId)
{
    return LnnGetOnlineStateById(networkId, CATEGORY_NETWORK_ID);
}

void UpdateLocalMasterNode(bool isCurrentNode, const char *masterUdid, int32_t weight)
{
    if (LnnSetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, masterUdid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "set local master udid failed");
        return;
    }
    if (LnnSetLocalNumInfo(NUM_KEY_MASTER_NODE_WEIGHT, weight) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "set local master weight failed");
    }
    LnnNotifyMasterNodeChanged(isCurrentNode, masterUdid, weight);
    LNN_LOGI(LNN_BUILDER, "update local master weight. weight=%{public}d", weight);
}

static bool IsNeedSyncElectMsg(const char *networkId)
{
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &nodeInfo) != SOFTBUS_OK) {
        return false;
    }
    return LnnHasDiscoveryType(&nodeInfo, DISCOVERY_TYPE_WIFI);
}

int32_t SyncElectMessage(const char *networkId)
{
    char masterUdid[UDID_BUF_LEN] = { 0 };
    int32_t masterWeight;
    char *data = NULL;
    cJSON *json = NULL;
    int32_t rc;

    if (!IsNeedSyncElectMsg(networkId)) {
        char *anonyNetworkId = NULL;
        Anonymize(networkId, &anonyNetworkId);
        LNN_LOGW(LNN_BUILDER, "no ip networking, dont sync elect msg, networkId=%{public}s",
            AnonymizeWrapper(anonyNetworkId));
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_OK;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, masterUdid, UDID_BUF_LEN) != SOFTBUS_OK ||
        LnnGetLocalNumInfo(NUM_KEY_MASTER_NODE_WEIGHT, &masterWeight) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local master node info failed");
        return SOFTBUS_INVALID_PARAM;
    }
    json = cJSON_CreateObject();
    if (json == NULL) {
        LNN_LOGE(LNN_BUILDER, "create elect json object failed");
        return SOFTBUS_CREATE_JSON_ERR;
    }
    if (!AddStringToJsonObject(json, JSON_KEY_MASTER_UDID, masterUdid) ||
        !AddNumberToJsonObject(json, JSON_KEY_MASTER_WEIGHT, masterWeight)) {
        LNN_LOGE(LNN_BUILDER, "add elect info to json failed");
        cJSON_Delete(json);
        return SOFTBUS_ADD_INFO_TO_JSON_FAIL;
    }
    data = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (data == NULL) {
        LNN_LOGE(LNN_BUILDER, "format elect packet fail");
        return SOFTBUS_CREATE_JSON_ERR;
    }
    rc = LnnSendSyncInfoMsg(LNN_INFO_TYPE_MASTER_ELECT, networkId, (uint8_t *)data, strlen(data) + 1, NULL);
    cJSON_free(data);
    return rc;
}

void SendElectMessageToAll(const char *skipNetworkId)
{
    LnnConnectionFsm *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
        if (skipNetworkId != NULL && strcmp(item->connInfo.peerNetworkId, skipNetworkId) == 0) {
            continue;
        }
        if (!IsNodeOnline(item->connInfo.peerNetworkId)) {
            continue;
        }
        if (SyncElectMessage(item->connInfo.peerNetworkId) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "sync elect info to conn failed. connFsm=%{public}u", item->id);
        }
    }
}

static void FreeJoinLnnMsgPara(const JoinLnnMsgPara *para)
{
    if (para == NULL) {
        return;
    }
    if (para->dupInfo != NULL) {
        SoftBusFree((void *)para->dupInfo);
    }
    SoftBusFree((void *)para);
}

int32_t TrySendJoinLNNRequest(const JoinLnnMsgPara *para, bool needReportFailure, bool isShort)
{
    int32_t ret = SOFTBUS_OK;
    LNN_CHECK_AND_RETURN_RET_LOGW(para != NULL, SOFTBUS_INVALID_PARAM, LNN_BUILDER, "para is NULL");
    DfxRecordLnnServerjoinStart(&para->addr, para->pkgName, needReportFailure);
    isShort = para->isNeedConnect ? false : true;
    LnnConnectionFsm *connFsm = FindConnectionFsmByAddr(&para->addr, isShort);
    if (connFsm == NULL || connFsm->isDead || CheckRemoteBasicInfoChanged(para->dupInfo)) {
        if (TryPendingJoinRequest(para, needReportFailure)) {
            LNN_LOGI(LNN_BUILDER, "join request is pending, peerAddr=%{public}s", LnnPrintConnectionAddr(&para->addr));
            FreeJoinLnnMsgPara(para);
            return SOFTBUS_OK;
        }
        ret = PostJoinRequestToConnFsm(connFsm, para, needReportFailure);
        FreeJoinLnnMsgPara(para);
        return ret;
    }
    connFsm->connInfo.flag |= (needReportFailure ? LNN_CONN_INFO_FLAG_JOIN_REQUEST : LNN_CONN_INFO_FLAG_JOIN_AUTO);
    connFsm->connInfo.infoReport = para->infoReport;
    connFsm->isSession = para->isSession ? true : connFsm->isSession;
    if ((connFsm->connInfo.flag & LNN_CONN_INFO_FLAG_ONLINE) != 0) {
        if (connFsm->connInfo.addr.type == CONNECTION_ADDR_WLAN || connFsm->connInfo.addr.type == CONNECTION_ADDR_ETH) {
            char uuid[UUID_BUF_LEN] = {0};
            (void)LnnConvertDlId(connFsm->connInfo.peerNetworkId, CATEGORY_NETWORK_ID, CATEGORY_UUID,
                uuid, UUID_BUF_LEN);
            (void)AuthFlushDevice(uuid);
        }
        if ((LnnSendJoinRequestToConnFsm(connFsm) != SOFTBUS_OK) && needReportFailure) {
            LNN_LOGE(LNN_BUILDER, "online status, process join lnn request failed");
            LnnNotifyJoinResult((ConnectionAddr *)&para->addr, NULL, SOFTBUS_NETWORK_JOIN_REQUEST_ERR);
        }
        if (para->isSession && para->dupInfo != NULL) {
            LnnNotifyStateForSession(para->dupInfo->deviceInfo.deviceUdid, SOFTBUS_OK);
        }
    }
    LNN_LOGI(LNN_BUILDER, "addr same to before, peerAddr=%{public}s", LnnPrintConnectionAddr(&para->addr));
    ConnectionAddr addr = para->addr;
    if (addr.type != CONNECTION_ADDR_WLAN ||
        !IsNeedWifiReauth(connFsm->connInfo.peerNetworkId, addr.peerUid, MAX_ACCOUNT_HASH_LEN)) {
        LNN_LOGI(LNN_BUILDER, "account not change no need reauth");
        FreeJoinLnnMsgPara(para);
        return SOFTBUS_OK;
    }
    AuthConnInfo authConn;
    uint32_t requestId = AuthGenRequestId();
    (void)LnnConvertAddrToAuthConnInfo(&addr, &authConn);
    DfxRecordLnnAuthStart(&authConn, para, requestId);
    FreeJoinLnnMsgPara(para);
    return AuthStartVerify(&authConn, requestId, LnnGetReAuthVerifyCallback(), AUTH_MODULE_LNN, false);
}

bool NeedPendingJoinRequest(void)
{
    int32_t count = 0;
    LnnConnectionFsm *item = NULL;

    if (g_netBuilder.maxConcurrentCount == 0) { // do not limit concurent
        return false;
    }
    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
        if (item->isDead) {
            continue;
        }
        if ((item->connInfo.flag & LNN_CONN_INFO_FLAG_ONLINE) != 0) {
            continue;
        }
        ++count;
        if (count >= g_netBuilder.maxConcurrentCount) {
            return true;
        }
    }
    return false;
}

static bool IsSamePendingRequest(const PendingJoinRequestNode *request)
{
    PendingJoinRequestNode *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.pendingList, PendingJoinRequestNode, node) {
        if (LnnIsSameConnectionAddr(&item->addr, &request->addr, false) &&
            item->needReportFailure == request->needReportFailure) {
            LNN_LOGD(LNN_BUILDER, "have the same pending join request");
            return true;
        }
    }
    return false;
}

bool TryPendingJoinRequest(const JoinLnnMsgPara *para, bool needReportFailure)
{
    PendingJoinRequestNode *request = NULL;
    if (para == NULL || !para->isNeedConnect) {
        LNN_LOGI(LNN_BUILDER, "no connect online, no need pending");
        return false;
    }
    if (!NeedPendingJoinRequest()) {
        return false;
    }
    request = (PendingJoinRequestNode *)SoftBusCalloc(sizeof(PendingJoinRequestNode));
    if (request == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc pending join request fail, go on it");
        return false;
    }
    ListInit(&request->node);
    request->addr = para->addr;
    request->needReportFailure = needReportFailure;
    if (IsSamePendingRequest(request)) {
        SoftBusFree(request);
        return true;
    }
    ListTailInsert(&g_netBuilder.pendingList, &request->node);
    return true;
}

void RemovePendingRequestByAddrType(const bool *addrType, uint32_t typeLen)
{
    PendingJoinRequestNode *item = NULL;
    PendingJoinRequestNode *next = NULL;

    if (addrType == NULL || typeLen != CONNECTION_ADDR_MAX) {
        LNN_LOGE(LNN_BUILDER, "invalid typeLen=%{public}d", typeLen);
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_netBuilder.pendingList, PendingJoinRequestNode, node) {
        if (!addrType[item->addr.type]) {
            continue;
        }
        ListDelete(&item->node);
        LNN_LOGI(LNN_BUILDER, "clean a pending join request, peerAddr=%{public}s", LnnPrintConnectionAddr(&item->addr));
        SoftBusFree(item);
    }
}

bool IsNeedWifiReauth(const char *networkId, const char *newAccountHash, int32_t len)
{
    if (LnnIsDefaultOhosAccount()) {
        LNN_LOGE(LNN_BUILDER, "local account is default");
        return false;
    }
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &info) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get node info fail");
        return false;
    }
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    LNN_LOGI(LNN_BUILDER, "peer networkId=%{public}s, accountHash:%{public}02x%{public}02x->%{public}02x%{public}02x",
        AnonymizeWrapper(anonyNetworkId), info.accountHash[0], info.accountHash[1],
        newAccountHash[0], newAccountHash[1]);
    AnonymizeFree(anonyNetworkId);
    uint8_t defaultAccountHash[SHA_256_HASH_LEN] = {0};
    const char *defaultUserId = "0";
    if (SoftBusGenerateStrHash((const unsigned char *)defaultUserId, strlen(defaultUserId), defaultAccountHash) !=
        SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "generate default str hash fail");
        return false;
    }
    bool isNullAccount = true;
    for (int32_t i = 0; i < len; ++i) {
        if (newAccountHash[i] != 0) {
            isNullAccount = false;
            break;
        }
    }
    if (isNullAccount || memcmp(newAccountHash, defaultAccountHash, HB_SHORT_ACCOUNT_HASH_LEN) == 0) {
        LNN_LOGE(LNN_BUILDER, "accountHash is null or account is default");
        return false;
    }
    return memcmp(info.accountHash, newAccountHash, HB_SHORT_ACCOUNT_HASH_LEN) != 0;
}

static void BuildLnnEvent(LnnEventExtra *lnnEventExtra, const ConnectionAddr *addr)
{
    if (lnnEventExtra == NULL || addr == NULL) {
        LNN_LOGW(LNN_STATE, "lnnEventExtra or addr is null");
        return;
    }
    switch (addr->type) {
        case CONNECTION_ADDR_BR:
            lnnEventExtra->peerBrMac = addr->info.br.brMac;
            break;
        case CONNECTION_ADDR_BLE:
            lnnEventExtra->peerBleMac = addr->info.ble.bleMac;
            break;
        case CONNECTION_ADDR_WLAN:
            /* fall-through */
        case CONNECTION_ADDR_ETH:
            lnnEventExtra->peerIp = addr->info.ip.ip;
            break;
        default:
            LNN_LOGE(LNN_BUILDER, "unknown param type!");
            break;
    }
}

void DfxRecordLnnServerjoinStart(const ConnectionAddr *addr, const char *packageName, bool needReportFailure)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);

    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    if (packageName != NULL && IsValidString(packageName, PKG_NAME_SIZE_MAX - 1) && strncpy_s(pkgName,
        PKG_NAME_SIZE_MAX, packageName, PKG_NAME_SIZE_MAX - 1) == EOK) {
        extra.callerPkg = pkgName;
    }
    if (addr != NULL) {
        BuildLnnEvent(&extra, addr);
    }
    LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_JOIN_LNN_START, extra);
}

void DfxRecordLnnAuthStart(const AuthConnInfo *connInfo, const JoinLnnMsgPara *para, uint32_t requestId)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    extra.authRequestId = (int32_t)requestId;

    if (connInfo != NULL) {
        extra.authLinkType = connInfo->type;
    }
    if (para != NULL && IsValidString(para->pkgName, PKG_NAME_SIZE_MAX - 1)) {
        extra.callerPkg = para->pkgName;
    }
    LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_AUTH, extra);
}

NodeInfo *DupNodeInfo(const NodeInfo *nodeInfo)
{
    NodeInfo *node = (NodeInfo *)SoftBusCalloc(sizeof(NodeInfo));
    if (node == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc NodeInfo fail");
        return NULL;
    }
    if (memcpy_s(node, sizeof(NodeInfo), nodeInfo, sizeof(NodeInfo)) != EOK) {
        LNN_LOGE(LNN_BUILDER, "copy NodeInfo fail");
        SoftBusFree(node);
        return NULL;
    }
    return node;
}

ConnectionAddrType GetCurrentConnectType(void)
{
    char ifCurrentName[NET_IF_NAME_LEN] = { 0 };
    ConnectionAddrType type = CONNECTION_ADDR_MAX;

    if (LnnGetLocalStrInfo(STRING_KEY_NET_IF_NAME, ifCurrentName, NET_IF_NAME_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "LnnGetLocalStrInfo getCurrentConnectType failed");
        return type;
    }
    if (LnnGetAddrTypeByIfName(ifCurrentName, &type) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "getCurrentConnectType unknown connect type");
    }
    return type;
}

void OnLnnProcessNotTrustedMsgDelay(void *para)
{
    if (para == NULL) {
        LNN_LOGW(LNN_BUILDER, "invalid para");
        return;
    }
    int64_t authSeq[DISCOVERY_TYPE_COUNT] = { 0 };
    NotTrustedDelayInfo *info = (NotTrustedDelayInfo *)para;
    if (!LnnGetOnlineStateById(info->udid, CATEGORY_UDID)) {
        LNN_LOGI(LNN_BUILDER, "device is offline");
        SoftBusFree(info);
        return;
    }
    if (AuthGetLatestAuthSeqList(info->udid, authSeq, DISCOVERY_TYPE_COUNT) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get latest authSeq list fail");
        SoftBusFree(info);
        return;
    }
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (LnnConvertDlId(info->udid, CATEGORY_UDID, CATEGORY_NETWORK_ID, networkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "LnnConvertDlId fail");
        SoftBusFree(info);
        return;
    }
    uint32_t type;
    for (type = DISCOVERY_TYPE_WIFI; type < DISCOVERY_TYPE_P2P; type++) {
        LNN_LOGI(
            LNN_BUILDER, "after 5s, authSeq:%{public}" PRId64 "->%{public}" PRId64, info->authSeq[type], authSeq[type]);
        if (authSeq[type] == info->authSeq[type] && authSeq[type] != 0 && info->authSeq[type] != 0) {
            char *anonyNetworkId = NULL;
            Anonymize(networkId, &anonyNetworkId);
            LNN_LOGI(LNN_BUILDER, "networkId=%{public}s, LnnRequestLeaveSpecificType=%{public}d",
                AnonymizeWrapper(anonyNetworkId), type);
            AnonymizeFree(anonyNetworkId);
            LnnRequestLeaveSpecific(networkId, LnnDiscTypeToConnAddrType((DiscoveryType)type));
            continue;
        }
    }
    SoftBusFree(info);
}

void LnnProcessCompleteNotTrustedMsg(LnnSyncInfoType syncType, const char *networkId,
    const uint8_t *msg, uint32_t len)
{
    if (networkId == NULL || syncType != LNN_INFO_TYPE_NOT_TRUSTED || msg == NULL) {
        LNN_LOGW(LNN_BUILDER, "invalid param");
        return;
    }
    if (!LnnGetOnlineStateById(networkId, CATEGORY_NETWORK_ID)) {
        LNN_LOGI(LNN_BUILDER, "device is offline");
        return;
    }
    JsonObj *json = JSON_Parse((const char *)msg, len);
    if (json == NULL) {
        LNN_LOGE(LNN_BUILDER, "json parse fail");
        return;
    }
    int64_t authSeq[DISCOVERY_TYPE_COUNT] = { 0 };
    (void)JSON_GetInt64FromOject(json, NETWORK_TYPE_WIFI, &authSeq[DISCOVERY_TYPE_WIFI]);
    (void)JSON_GetInt64FromOject(json, NETWORK_TYPE_BLE, &authSeq[DISCOVERY_TYPE_BLE]);
    (void)JSON_GetInt64FromOject(json, NETWORK_TYPE_BR, &authSeq[DISCOVERY_TYPE_BR]);
    JSON_Delete(json);
    int64_t curAuthSeq[DISCOVERY_TYPE_COUNT] = { 0 };
    char udid[UDID_BUF_LEN] = { 0 };
    (void)LnnConvertDlId(networkId, CATEGORY_NETWORK_ID, CATEGORY_UDID, udid, UDID_BUF_LEN);
    if (AuthGetLatestAuthSeqList(udid, curAuthSeq, DISCOVERY_TYPE_COUNT) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get latest authSeq fail");
        return;
    }
    uint32_t type;
    for (type = DISCOVERY_TYPE_WIFI; type < DISCOVERY_TYPE_P2P; type++) {
        LNN_LOGI(LNN_BUILDER, "authSeq:%{public}" PRId64 "->%{public}" PRId64, curAuthSeq[type], authSeq[type]);
        if (authSeq[type] == curAuthSeq[type] && authSeq[type] != 0 && curAuthSeq[type] != 0) {
            if (type == DISCOVERY_TYPE_WIFI) {
                SoftBusSleepMs(WAIT_SEND_NOT_TRUST_MSG);
            }
            char *anonyNetworkId = NULL;
            Anonymize(networkId, &anonyNetworkId);
            LNN_LOGI(LNN_BUILDER, "networkId=%{public}s, LnnRequestLeaveSpecificType=%{public}d",
                AnonymizeWrapper(anonyNetworkId), type);
            AnonymizeFree(anonyNetworkId);
            LnnRequestLeaveSpecific(networkId, LnnDiscTypeToConnAddrType((DiscoveryType)type));
            continue;
        }
    }
}

bool DeletePcNodeInfo(const char *peerUdid)
{
    NodeInfo *localNodeInfo = NULL;
    NodeInfo remoteNodeInfo;
    (void)memset_s(&remoteNodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(peerUdid, CATEGORY_UDID, &remoteNodeInfo)) {
        LNN_LOGE(LNN_BUILDER, "get nodeInfo fail");
        return false;
    }
    if (strcmp(remoteNodeInfo.deviceInfo.deviceUdid, remoteNodeInfo.uuid) != 0) {
        LNN_LOGW(LNN_BUILDER, "isn't pc without softbus");
        return false;
    }
    localNodeInfo = (NodeInfo *)LnnGetLocalNodeInfo();
    if (localNodeInfo == NULL) {
        LNN_LOGE(LNN_BUILDER, "get localinfo fail");
        return false;
    }
    if (remoteNodeInfo.accountId == localNodeInfo->accountId) {
        LNN_LOGI(LNN_BUILDER, "exist sameAccount, don't handle offline");
        return false;
    }
    LNN_LOGI(LNN_BUILDER, "device not trust, delete pc online node");
    DeleteFromProfile(remoteNodeInfo.deviceInfo.deviceUdid);
    LnnRemoveNode(remoteNodeInfo.deviceInfo.deviceUdid);
    return true;
}

const char *SelectUseUdid(const char *peerUdid, const char *lowerUdid)
{
    char *anonyPeerUdid = NULL;
    Anonymize(peerUdid, &anonyPeerUdid);
    if (LnnGetOnlineStateById(peerUdid, CATEGORY_UDID)) {
        LNN_LOGD(LNN_BUILDER, "not trusted device online! peerUdid=%{public}s", AnonymizeWrapper(anonyPeerUdid));
        AnonymizeFree(anonyPeerUdid);
        return peerUdid;
    } else if (LnnGetOnlineStateById(lowerUdid, CATEGORY_UDID)) {
        char *anonyLowerUdid = NULL;
        Anonymize(peerUdid, &anonyLowerUdid);
        LNN_LOGD(LNN_BUILDER, "not trusted device online! peerUdid=%{public}s", AnonymizeWrapper(anonyLowerUdid));
        AnonymizeFree(anonyLowerUdid);
        AnonymizeFree(anonyPeerUdid);
        return lowerUdid;
    } else {
        LNN_LOGW(LNN_BUILDER, "not trusted device not online! peerUdid=%{public}s", AnonymizeWrapper(anonyPeerUdid));
        AnonymizeFree(anonyPeerUdid);
        return NULL;
    }
}

void LnnDeleteLinkFinderInfo(const char *peerUdid)
{
    if (peerUdid == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return;
    }
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (LnnGetNetworkIdByUdid(peerUdid, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get networkId fail.");
        return;
    }

    if (LnnRemoveLinkFinderInfo(networkId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "remove a rpa info fail.");
        return;
    }
}

void PostVerifyResult(uint32_t requestId, int32_t retCode, AuthHandle authHandle, const NodeInfo *info)
{
    VerifyResultMsgPara *para = NULL;
    para = (VerifyResultMsgPara *)SoftBusCalloc(sizeof(VerifyResultMsgPara));
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc verify result msg para fail");
        return;
    }
    para->requestId = requestId;
    para->retCode = retCode;
    if (retCode == SOFTBUS_OK) {
        para->nodeInfo = (info == NULL) ? NULL : DupNodeInfo(info);
        para->authHandle = authHandle;
    }
    if (PostBuildMessageToHandler(MSG_TYPE_VERIFY_RESULT, para) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "post verify result message failed");
        SoftBusFree(para->nodeInfo);
        SoftBusFree(para);
    }
    if (info != NULL && retCode == SOFTBUS_OK) {
        LnnNotifyDeviceVerified(info->deviceInfo.deviceUdid);
    }
}

static void OnVerifyPassed(uint32_t requestId, AuthHandle authHandle, const NodeInfo *info)
{
    LNN_LOGI(LNN_BUILDER, "verify passed. requestId=%{public}u, authId=%{public}" PRId64, requestId, authHandle.authId);
    if (authHandle.type < AUTH_LINK_TYPE_WIFI || authHandle.type >= AUTH_LINK_TYPE_MAX) {
        LNN_LOGE(LNN_BUILDER, "authHandle type error");
        return;
    }
    PostVerifyResult(requestId, SOFTBUS_OK, authHandle, info);
}

static void OnVerifyFailed(uint32_t requestId, int32_t reason)
{
    LNN_LOGI(LNN_BUILDER, "verify failed: requestId=%{public}u, reason=%{public}d", requestId, reason);
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID };
    PostVerifyResult(requestId, reason, authHandle, NULL);
}

static AuthVerifyCallback g_verifyCallback = {
    .onVerifyPassed = OnVerifyPassed,
    .onVerifyFailed = OnVerifyFailed,
};

AuthVerifyCallback *LnnGetVerifyCallback(void)
{
    return &g_verifyCallback;
}

static ConnectionAddr *CreateConnectionAddrMsgPara(const ConnectionAddr *addr)
{
    ConnectionAddr *para = NULL;

    if (addr == NULL) {
        LNN_LOGE(LNN_BUILDER, "addr is null");
        return NULL;
    }
    para = (ConnectionAddr *)SoftBusCalloc(sizeof(ConnectionAddr));
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc connecton addr message fail");
        return NULL;
    }
    *para = *addr;
    return para;
}

static JoinLnnMsgPara *CreateJoinLnnMsgPara(const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport,
    const char *pkgName, bool isNeedConnect)
{
    JoinLnnMsgPara *para = NULL;

    if (addr == NULL || infoReport == NULL || pkgName == NULL) {
        LNN_LOGE(LNN_BUILDER, "create join lnn msg para is null");
        return NULL;
    }
    para = (JoinLnnMsgPara *)SoftBusCalloc(sizeof(JoinLnnMsgPara));
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc connecton addr message fail");
        return NULL;
    }
    if (strcpy_s(para->pkgName, PKG_NAME_SIZE_MAX, pkgName) != EOK) {
        LNN_LOGE(LNN_BUILDER, "copy pkgName fail");
        SoftBusFree(para);
        return NULL;
    }
    para->isNeedConnect = isNeedConnect;
    para->addr = *addr;
    para->infoReport = *infoReport;
    return para;
}

static char *CreateNetworkIdMsgPara(const char *networkId)
{
    char *para = NULL;

    if (networkId == NULL) {
        LNN_LOGE(LNN_BUILDER, "networkId is null");
        return NULL;
    }
    para = (char *)SoftBusMalloc(NETWORK_ID_BUF_LEN);
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc networkId message fail");
        return NULL;
    }
    if (strncpy_s(para, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != EOK) {
        LNN_LOGE(LNN_BUILDER, "copy network id fail");
        SoftBusFree(para);
        return NULL;
    }
    return para;
}

int32_t ConifgLocalLedger(void)
{
    char uuid[UUID_BUF_LEN] = { 0 };
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    unsigned char irk[LFINDER_IRK_LEN] = { 0 };

    // set local networkId and uuid
    if (LnnGenLocalNetworkId(networkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK ||
        LnnGenLocalUuid(uuid, UUID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local id fail");
        return SOFTBUS_NOT_FIND;
    }

    // irk fail should not cause softbus init fail
    if (LnnGenLocalIrk(irk, LFINDER_IRK_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local irk fail");
    }

    LnnSetLocalStrInfo(STRING_KEY_UUID, uuid);
    LnnSetLocalStrInfo(STRING_KEY_NETWORKID, networkId);
    LnnSetLocalByteInfo(BYTE_KEY_IRK, irk, LFINDER_IRK_LEN);
    (void)memset_s(irk, LFINDER_IRK_LEN, 0, LFINDER_IRK_LEN);
    return SOFTBUS_OK;
}

void OnReceiveMasterElectMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
    JsonObj *json = NULL;
    ElectMsgPara *para = NULL;

    LNN_LOGI(LNN_BUILDER, "recv master elect msg, type=%{public}d, len=%{public}d", type, len);
    if (g_netBuilder.isInit == false) {
        LNN_LOGE(LNN_BUILDER, "no init");
        return;
    }
    if (type != LNN_INFO_TYPE_MASTER_ELECT) {
        return;
    }
    json = JSON_Parse((char *)msg, len);
    if (json == NULL) {
        LNN_LOGE(LNN_BUILDER, "parse elect msg json fail");
        return;
    }
    para = (ElectMsgPara *)SoftBusMalloc(sizeof(ElectMsgPara));
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc elect msg para fail");
        JSON_Delete(json);
        return;
    }
    if (!JSON_GetInt32FromOject(json, JSON_KEY_MASTER_WEIGHT, &para->masterWeight) ||
        !JSON_GetStringFromOject(json, JSON_KEY_MASTER_UDID, para->masterUdid, UDID_BUF_LEN)) {
        LNN_LOGE(LNN_BUILDER, "parse master info json fail");
        JSON_Delete(json);
        SoftBusFree(para);
        return;
    }
    JSON_Delete(json);
    if (strcpy_s(para->networkId, NETWORK_ID_BUF_LEN, networkId) != EOK) {
        LNN_LOGE(LNN_BUILDER, "copy network id fail");
        SoftBusFree(para);
        return;
    }
    if (PostBuildMessageToHandler(MSG_TYPE_MASTER_ELECT, para) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "post elect message fail");
        SoftBusFree(para);
    }
}

static int32_t LnnUnpackNodeAddr(const uint8_t *data, uint32_t dataLen, LnnNodeAddr *addr)
{
    cJSON *json = cJSON_Parse((char *)data);
    if (json == NULL) {
        LNN_LOGE(LNN_BUILDER, "json parse failed");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (!GetJsonObjectNumberItem(json, JSON_KEY_NODE_CODE, &addr->code) ||
        !GetJsonObjectStringItem(json, JSON_KEY_NODE_ADDR, addr->nodeAddr, SHORT_ADDRESS_MAX_LEN) ||
        !GetJsonObjectNumberItem(json, JSON_KEY_NODE_PROXY_PORT, &addr->proxyPort) ||
        !GetJsonObjectNumberItem(json, JSON_KEY_NODE_SESSION_PORT, &addr->sessionPort)) {
        LNN_LOGE(LNN_BUILDER, "parse addr info failed");
        cJSON_Delete(json);
        return SOFTBUS_PARSE_JSON_ERR;
    }

    cJSON_Delete(json);
    return SOFTBUS_OK;
}

void OnReceiveNodeAddrChangedMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t size)
{
    if (type != LNN_INFO_TYPE_NODE_ADDR) {
        return;
    }
    uint32_t addrLen = (uint32_t)strnlen((const char *)msg, size);
    if (size == 0 || addrLen != size - 1 || addrLen == 0) {
        return;
    }
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    LNN_LOGI(LNN_BUILDER, "networkId=%{public}s", AnonymizeWrapper(anonyNetworkId));
    AnonymizeFree(anonyNetworkId);

    LnnNodeAddr addr;
    (void)memset_s(&addr, sizeof(LnnNodeAddr), 0, sizeof(LnnNodeAddr));
    if (LnnUnpackNodeAddr(msg, size, &addr) != SOFTBUS_OK) {
        return;
    }

    SfcSyncNodeAddrHandle(networkId, addr.code);

    if (LnnSetDLNodeAddr(networkId, CATEGORY_NETWORK_ID, addr.nodeAddr) != SOFTBUS_OK) {
        return;
    }

    if (addr.proxyPort > 0) {
        (void)LnnSetDLProxyPort(networkId, CATEGORY_NETWORK_ID, addr.proxyPort);
    }

    if (addr.sessionPort > 0) {
        (void)LnnSetDLSessionPort(networkId, CATEGORY_NETWORK_ID, addr.sessionPort);
    }

    if (addr.authPort > 0) {
        (void)LnnSetDLAuthPort(networkId, CATEGORY_NETWORK_ID, addr.authPort);
    }

    LnnNotifyNodeAddressChanged(addr.nodeAddr, networkId, false);
}

int32_t LnnUpdateNodeAddr(const char *addr)
{
    if (addr == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LnnSetLocalStrInfo(STRING_KEY_NODE_ADDR, addr);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "set local node addr failed");
        return ret;
    }

    char localNetworkId[NETWORK_ID_BUF_LEN] = { 0 };
    ret = LnnGetLocalStrInfo(STRING_KEY_NETWORKID, localNetworkId, sizeof(localNetworkId));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local network id failed");
        return SOFTBUS_NETWORK_NOT_FOUND;
    }
    LnnNotifyNodeAddressChanged(addr, localNetworkId, true);

    return SOFTBUS_OK;
}

void UpdateLocalNetCapability(void)
{
    uint32_t oldNetCap = 0;
    if (LnnGetLocalNumU32Info(NUM_KEY_NET_CAP, &oldNetCap) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "get cap from local ledger fail");
        return;
    }
    uint32_t netCapability = oldNetCap;
    int btState = SoftBusGetBtState();
    if (btState == BLE_ENABLE) {
        LNN_LOGI(LNN_INIT, "ble state is on");
        (void)LnnSetNetCapability(&netCapability, BIT_BLE);
    } else if (btState == BLE_DISABLE) {
        LNN_LOGI(LNN_INIT, "ble state is off");
        (void)LnnClearNetCapability(&netCapability, BIT_BLE);
    }

    int brState = SoftBusGetBrState();
    if (brState == BR_ENABLE) {
        (void)LnnSetNetCapability(&netCapability, BIT_BR);
    } else if (brState == BR_DISABLE) {
        (void)LnnClearNetCapability(&netCapability, BIT_BR);
    }

    bool isWifiActive = SoftBusIsWifiActive();
    if (!isWifiActive) {
        (void)LnnClearNetCapability(&netCapability, BIT_WIFI);
        (void)LnnClearNetCapability(&netCapability, BIT_WIFI_24G);
        (void)LnnClearNetCapability(&netCapability, BIT_WIFI_5G);
    } else {
        SoftBusBand band = SoftBusGetLinkBand();
        if (band == BAND_24G) {
            (void)LnnSetNetCapability(&netCapability, BIT_WIFI_24G);
            (void)LnnClearNetCapability(&netCapability, BIT_WIFI_5G);
        } else if (band == BAND_5G) {
            (void)LnnSetNetCapability(&netCapability, BIT_WIFI_5G);
            (void)LnnClearNetCapability(&netCapability, BIT_WIFI_24G);
        } else {
            (void)LnnSetNetCapability(&netCapability, BIT_WIFI_5G);
            (void)LnnSetNetCapability(&netCapability, BIT_WIFI_24G);
        }
    }
    SoftBusWifiDetailState wifiState = SoftBusGetWifiState();
    if (wifiState == SOFTBUS_WIFI_STATE_INACTIVE || wifiState == SOFTBUS_WIFI_STATE_DEACTIVATING) {
        (void)LnnClearNetCapability(&netCapability, BIT_WIFI_P2P);
    }

    if (LnnSetLocalNumInfo(NUM_KEY_NET_CAP, netCapability) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "set cap to local ledger fail");
    }
    LNN_LOGI(LNN_INIT, "local capability change:%{public}u->%{public}u, brState=%{public}d, isWifiActive=%{public}d,",
        oldNetCap, netCapability, brState, isWifiActive);
}

int32_t JoinLnnWithNodeInfo(ConnectionAddr *addr, NodeInfo *info, bool isSession)
{
    if (addr == NULL || info == NULL) {
        LNN_LOGE(LNN_BUILDER, "prepare join with nodeinfo message fail");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnDfxDeviceInfoReport infoReport;
    (void)memset_s(&infoReport, sizeof(LnnDfxDeviceInfoReport), 0, sizeof(LnnDfxDeviceInfoReport));
    JoinLnnMsgPara *para = CreateJoinLnnMsgPara(addr, &infoReport, DEFAULT_PKG_NAME, false);
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "prepare join with nodeinfo create lnn msg para fail");
        return SOFTBUS_MALLOC_ERR;
    }
    para->dupInfo = DupNodeInfo(info);
    if (para->dupInfo == NULL) {
        LNN_LOGE(LNN_BUILDER, "join with nodeinfo dup node info fail");
        SoftBusFree(para);
        return SOFTBUS_MEM_ERR;
    }
    para->isSession = isSession;
    if (PostBuildMessageToHandler(MSG_TYPE_DISCOVERY_DEVICE, para) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "post notify discovery device message failed");
        SoftBusFree(para->dupInfo);
        SoftBusFree(para);
        return SOFTBUS_NETWORK_POST_MSG_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t LnnServerJoin(ConnectionAddr *addr, const char *pkgName)
{
    JoinLnnMsgPara *para = NULL;

    LNN_LOGI(LNN_BUILDER, "enter!");
    if (g_netBuilder.isInit == false) {
        LNN_LOGE(LNN_BUILDER, "no init");
        return SOFTBUS_NO_INIT;
    }
    LnnDfxDeviceInfoReport infoReport;
    (void)memset_s(&infoReport, sizeof(LnnDfxDeviceInfoReport), 0, sizeof(LnnDfxDeviceInfoReport));
    para = CreateJoinLnnMsgPara(addr, &infoReport, pkgName, true);
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "prepare join lnn message fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (PostBuildMessageToHandler(MSG_TYPE_JOIN_LNN, para) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "post join lnn message fail");
        SoftBusFree(para);
        return SOFTBUS_NETWORK_LOOPER_ERR;
    }
    return SOFTBUS_OK;
}

static bool AuthCapabilityIsSupport(char *peerUdid, AuthCapability capaBit)
{
    if (peerUdid == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid peerUdid.");
        return false;
    }
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t ret = LnnRetrieveDeviceInfoByUdid(peerUdid, &nodeInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "retrieve device info fail, peerUdid:%{public}s", peerUdid);
        return false;
    }
    return IsSupportFeatureByCapaBit(nodeInfo.authCapacity, capaBit);
}

static int32_t PostJoinLnnExtMsg(ConnectionAddr *addr, int32_t connId)
{
    LnnDfxDeviceInfoReport infoReport;
    (void)memset_s(&infoReport, sizeof(LnnDfxDeviceInfoReport), 0, sizeof(LnnDfxDeviceInfoReport));
    JoinLnnMsgPara *para = CreateJoinLnnMsgPara(addr, &infoReport, DEFAULT_PKG_NAME, true);
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "prepare join lnn message fail");
        DelConnIdCallbackInfoItem((uint32_t)connId);
        return SOFTBUS_MALLOC_ERR;
    }
    para->isSession = true;
    if (PostBuildMessageToHandler(MSG_TYPE_JOIN_LNN, para) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "post join lnn message fail");
        DelConnIdCallbackInfoItem((uint32_t)connId);
        SoftBusFree(para);
        return SOFTBUS_NETWORK_LOOPER_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnServerJoinExt(ConnectionAddr *addr, LnnServerJoinExtCallBack *callback)
{
    if (callback == NULL || addr == NULL || addr->type != CONNECTION_ADDR_SESSION) {
        LNN_LOGE(LNN_BUILDER, "invalid callback");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_netBuilder.isInit == false) {
        LNN_LOGE(LNN_BUILDER, "no init");
        return SOFTBUS_NO_INIT;
    }
    int32_t connId = 0;
    char peerUdid[UDID_BUF_LEN] = { 0 };
    int32_t ret = TransAuthGetConnIdByChanId(addr->info.session.channelId, &connId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get connId fail");
        return ret;
    }
    ret = TransAuthGetPeerUdidByChanId(addr->info.session.channelId, peerUdid, UDID_BUF_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get peerUdid fail");
        return ret;
    }
    LNN_LOGI(LNN_BUILDER, "addr.type=%{public}d, connId=%{public}d, chanId=%{public}d",
        addr->type, connId, addr->info.session.channelId);
    if (!AuthCapabilityIsSupport(peerUdid, BIT_SUPPORT_SESSION_DUP_BLE)) {
        return SOFTBUS_FUNC_NOT_SUPPORT;
    }
    ret = AddConnIdCallbackInfoItem(addr, callback, (uint32_t)connId, peerUdid);
    if (ret != SOFTBUS_OK) {
        LNN_LOGW(LNN_BUILDER, "add connId callback ret = %{public}d.", ret);
        return (ret == SOFTBUS_ALREADY_EXISTED ? SOFTBUS_OK : ret);
    }

    return PostJoinLnnExtMsg(addr, connId);
}

int32_t LnnServerLeave(const char *networkId, const char *pkgName)
{
    (void)pkgName;
    char *para = NULL;

    LNN_LOGI(LNN_BUILDER, "enter");
    if (g_netBuilder.isInit == false) {
        LNN_LOGE(LNN_BUILDER, "no init");
        return SOFTBUS_NO_INIT;
    }
    para = CreateNetworkIdMsgPara(networkId);
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "prepare leave lnn message fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (PostBuildMessageToHandler(MSG_TYPE_LEAVE_LNN, para) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "post leave lnn message fail");
        SoftBusFree(para);
        return SOFTBUS_NETWORK_LOOPER_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnNotifyDiscoveryDevice(
    const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport, bool isNeedConnect)
{
    JoinLnnMsgPara *para = NULL;
    if (LnnIsConnectionAddrInvalid(addr)) {
        LNN_LOGE(LNN_BUILDER, "invalid connection addr");
        return SOFTBUS_INVALID_PARAM;
    }
    LNN_LOGI(LNN_BUILDER, "notify discovery device enter! peer%{public}s, isNeedConnect=%{public}d",
        addr != NULL ? LnnPrintConnectionAddr(addr) : "", isNeedConnect);
    if (g_netBuilder.isInit == false) {
        LNN_LOGE(LNN_BUILDER, "no init");
        return SOFTBUS_NO_INIT;
    }
    if (infoReport == NULL) {
        LNN_LOGE(LNN_BUILDER, "infoReport is null");
        return SOFTBUS_INVALID_PARAM;
    }
    para = CreateJoinLnnMsgPara(addr, infoReport, DEFAULT_PKG_NAME, isNeedConnect);
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc discovery device message fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (PostBuildMessageToHandler(MSG_TYPE_DISCOVERY_DEVICE, para) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "post notify discovery device message failed");
        SoftBusFree(para);
        return SOFTBUS_NETWORK_POST_MSG_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t LnnRequestLeaveInvalidConn(const char *oldNetworkId, ConnectionAddrType addrType, const char *newNetworkId)
{
    LeaveInvalidConnMsgPara *para = NULL;

    if (g_netBuilder.isInit == false) {
        LNN_LOGE(LNN_BUILDER, "no init");
        return SOFTBUS_NO_INIT;
    }
    para = (LeaveInvalidConnMsgPara *)SoftBusMalloc(sizeof(LeaveInvalidConnMsgPara));
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "prepare leave invalid connection message fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strncpy_s(para->oldNetworkId, NETWORK_ID_BUF_LEN, oldNetworkId, strlen(oldNetworkId)) != EOK ||
        strncpy_s(para->newNetworkId, NETWORK_ID_BUF_LEN, newNetworkId, strlen(newNetworkId)) != EOK) {
        LNN_LOGE(LNN_BUILDER, "copy old networkId or new networkId fail");
        SoftBusFree(para);
        return SOFTBUS_MALLOC_ERR;
    }
    para->addrType = addrType;
    if (PostBuildMessageToHandler(MSG_TYPE_LEAVE_INVALID_CONN, para) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "post leave invalid connection message failed");
        SoftBusFree(para);
        return SOFTBUS_NETWORK_POST_MSG_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t LnnRequestCleanConnFsm(uint16_t connFsmId)
{
    uint16_t *para = NULL;

    if (g_netBuilder.isInit == false) {
        LNN_LOGE(LNN_BUILDER, "no init");
        return SOFTBUS_NO_INIT;
    }
    para = (uint16_t *)SoftBusMalloc(sizeof(uint16_t));
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc clean connection fsm msg failed");
        return SOFTBUS_MALLOC_ERR;
    }
    *para = connFsmId;
    if (PostBuildMessageToHandler(MSG_TYPE_CLEAN_CONN_FSM, para) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "post request clean connectionlnn message failed");
        SoftBusFree(para);
        return SOFTBUS_NETWORK_POST_MSG_FAIL;
    }
    return SOFTBUS_OK;
}

void LnnSyncOfflineComplete(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
    char *para = NULL;

    (void)type;
    (void)msg;
    (void)len;
    if (g_netBuilder.isInit == false) {
        LNN_LOGE(LNN_BUILDER, "no init");
        return;
    }
    para = CreateNetworkIdMsgPara(networkId);
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "prepare notify sync offline message fail");
        return;
    }
    if (PostBuildMessageToHandler(MSG_TYPE_SYNC_OFFLINE_FINISH, para) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "post sync offline finish message failed");
        SoftBusFree(para);
    }
}

int32_t LnnNotifyNodeStateChanged(const ConnectionAddr *addr)
{
    ConnectionAddr *para = NULL;

    if (g_netBuilder.isInit == false) {
        LNN_LOGE(LNN_BUILDER, "no init");
        return SOFTBUS_NO_INIT;
    }
    para = CreateConnectionAddrMsgPara(addr);
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "create node state changed msg failed");
        return SOFTBUS_MALLOC_ERR;
    }
    if (PostBuildMessageToHandler(MSG_TYPE_NODE_STATE_CHANGED, para) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "post node state changed message failed");
        SoftBusFree(para);
        return SOFTBUS_NETWORK_POST_MSG_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t LnnNotifyMasterElect(const char *networkId, const char *masterUdid, int32_t masterWeight)
{
    ElectMsgPara *para = NULL;

    if (g_netBuilder.isInit == false) {
        LNN_LOGE(LNN_BUILDER, "no init");
        return SOFTBUS_NO_INIT;
    }
    if (networkId == NULL || masterUdid == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid elect msg para");
        return SOFTBUS_INVALID_PARAM;
    }
    para = (ElectMsgPara *)SoftBusMalloc(sizeof(ElectMsgPara));
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc elect msg para failed");
        return SOFTBUS_MEM_ERR;
    }
    if (strncpy_s(para->networkId, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != EOK ||
        strncpy_s(para->masterUdid, UDID_BUF_LEN, masterUdid, strlen(masterUdid)) != EOK) {
        LNN_LOGE(LNN_BUILDER, "copy udid and maser udid failed");
        SoftBusFree(para);
        return SOFTBUS_STRCPY_ERR;
    }
    para->masterWeight = masterWeight;
    if (PostBuildMessageToHandler(MSG_TYPE_MASTER_ELECT, para) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "post elect message failed");
        SoftBusFree(para);
        return SOFTBUS_NETWORK_POST_MSG_FAIL;
    }
    return SOFTBUS_OK;
}

/* Note: must called in connection fsm. */
int32_t LnnNotifyAuthHandleLeaveLNN(AuthHandle authHandle)
{
    LnnConnectionFsm *item = NULL;

    if (g_netBuilder.isInit == false) {
        LNN_LOGE(LNN_BUILDER, "no init");
        return SOFTBUS_NO_INIT;
    }

    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
        if (item->isDead) {
            continue;
        }
        if (item->connInfo.authHandle.authId == authHandle.authId &&
            item->connInfo.authHandle.type == authHandle.type) {
            LNN_LOGI(
                LNN_BUILDER, "fsmId=%{public}u connection fsm already use type=%{public}d authId=%{public}" PRId64,
                item->id, authHandle.type, authHandle.authId);
            return SOFTBUS_OK;
        }
    }
    AuthHandleLeaveLNN(authHandle);
    return SOFTBUS_OK;
}

int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen)
{
    if (type == NULL) {
        LNN_LOGE(LNN_BUILDER, "para is null");
        return SOFTBUS_INVALID_PARAM;
    }
    bool *para = NULL;
    if (typeLen != CONNECTION_ADDR_MAX) {
        LNN_LOGE(LNN_BUILDER, "invalid typeLen");
        return SOFTBUS_INVALID_PARAM;
    }
    LNN_LOGD(LNN_BUILDER, "wlan=%{public}d, br=%{public}d, ble=%{public}d, eth=%{public}d", type[CONNECTION_ADDR_WLAN],
        type[CONNECTION_ADDR_BR], type[CONNECTION_ADDR_BLE], type[CONNECTION_ADDR_ETH]);
    if (g_netBuilder.isInit == false) {
        LNN_LOGE(LNN_BUILDER, "no init");
        return SOFTBUS_NO_INIT;
    }
    para = (bool *)SoftBusMalloc(sizeof(bool) * typeLen);
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc leave by addr type msg para failed");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(para, sizeof(bool) * typeLen, type, sizeof(bool) * typeLen) != EOK) {
        LNN_LOGE(LNN_BUILDER, "memcopy para fail");
        SoftBusFree(para);
        return SOFTBUS_MEM_ERR;
    }
    if (PostBuildMessageToHandler(MSG_TYPE_LEAVE_BY_ADDR_TYPE, para) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "post leave by addr type message failed");
        SoftBusFree(para);
        return SOFTBUS_NETWORK_POST_MSG_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType)
{
    SpecificLeaveMsgPara *para = NULL;

    if (networkId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_netBuilder.isInit == false) {
        LNN_LOGE(LNN_BUILDER, "no init");
        return SOFTBUS_NO_INIT;
    }
    para = (SpecificLeaveMsgPara *)SoftBusCalloc(sizeof(SpecificLeaveMsgPara));
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc specific msg fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s(para->networkId, NETWORK_ID_BUF_LEN, networkId) != EOK) {
        LNN_LOGE(LNN_BUILDER, "copy networkId fail");
        SoftBusFree(para);
        return SOFTBUS_STRCPY_ERR;
    }
    para->addrType = addrType;
    if (PostBuildMessageToHandler(MSG_TYPE_LEAVE_SPECIFIC, para) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "post leave specific msg failed");
        SoftBusFree(para);
        return SOFTBUS_NETWORK_POST_MSG_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t LnnNotifyLeaveLnnByAuthHandle(AuthHandle *authHandle)
{
    AuthHandle *para = NULL;
    para = (AuthHandle *)SoftBusMalloc(sizeof(AuthHandle));
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc para fail");
        return SOFTBUS_MALLOC_ERR;
    }
    *para = *authHandle;
    if (PostBuildMessageToHandler(MSG_TYPE_DEVICE_DISCONNECT, para) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "post device disconnect fail");
        SoftBusFree(para);
        return SOFTBUS_NETWORK_POST_MSG_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t LnnNotifyEmptySessionKey(int64_t authId)
{
    int64_t *para = NULL;
    para = (int64_t *)SoftBusMalloc(sizeof(int64_t));
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc para fail");
        return SOFTBUS_MALLOC_ERR;
    }
    *para = authId;
    if (PostBuildMessageToHandler(MSG_TYPE_LEAVE_BY_AUTH_ID, para) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "post empty sessionKey msg fail");
        SoftBusFree(para);
        return SOFTBUS_NETWORK_POST_MSG_FAIL;
    }
    return SOFTBUS_OK;
}

void LnnRequestLeaveAllOnlineNodes(void)
{
    int32_t onlineNum;
    NodeBasicInfo *info;
    char *para = NULL;
    if (LnnGetAllOnlineNodeInfo(&info, &onlineNum) != 0) {
        LNN_LOGE(LNN_BUILDER, "LnnGetAllOnlineNodeInfo failed");
        return;
    }
    if (info == NULL || onlineNum == 0) {
        LNN_LOGW(LNN_BUILDER, "none online node");
        return;
    }
    for (int32_t i = 0; i < onlineNum; i++) {
        para = CreateNetworkIdMsgPara(info[i].networkId);
        if (para == NULL) {
            LNN_LOGE(LNN_BUILDER, "prepare leave lnn message fail");
            break;
        }
        if (PostBuildMessageToHandler(MSG_TYPE_LEAVE_LNN, para) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "post leave lnn message failed");
            SoftBusFree(para);
            break;
        }
    }
    SoftBusFree(info);
}

static bool LnnBleReportExtraMapInit(void)
{
    if (SoftBusMutexInit(&g_lnnDfxReportMutex, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "lnnDfxReport mutex init fail");
        return false;
    }
    LnnMapInit(&g_lnnDfxReportMap);
    g_lnnDfxReportIsInit = true;
    LNN_LOGI(LNN_BUILDER, "lnnDfxReport map init success");
    return true;
}

void AddNodeToLnnBleReportExtraMap(const char *udidHash, const LnnBleReportExtra *bleExtra)
{
    if (!g_lnnDfxReportIsInit || udidHash == NULL || bleExtra == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return;
    }
    if (SoftBusMutexLock(&g_lnnDfxReportMutex) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "SoftBusMutexLock fail");
        return;
    }
    if (LnnMapSet(&g_lnnDfxReportMap, udidHash, bleExtra, sizeof(LnnBleReportExtra)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "LnnMapSet fail");
        (void)SoftBusMutexUnlock(&g_lnnDfxReportMutex);
        return;
    }
    (void)SoftBusMutexUnlock(&g_lnnDfxReportMutex);
}

int32_t GetNodeFromLnnBleReportExtraMap(const char *udidHash, LnnBleReportExtra *bleExtra)
{
    if (!g_lnnDfxReportIsInit || udidHash == NULL || bleExtra == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_lnnDfxReportMutex) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "SoftBusMutexLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LnnBleReportExtra *extra = NULL;
    extra = (LnnBleReportExtra *)LnnMapGet(&g_lnnDfxReportMap, udidHash);
    if (extra == NULL) {
        LNN_LOGE(LNN_BUILDER, "LnnMapGet fail");
        (void)SoftBusMutexUnlock(&g_lnnDfxReportMutex);
        return SOFTBUS_NOT_FIND;
    }
    if (memcpy_s(bleExtra, sizeof(LnnBleReportExtra), extra, sizeof(LnnBleReportExtra)) != EOK) {
        LNN_LOGE(LNN_BUILDER, "memcpy_s extra fail");
        (void)SoftBusMutexUnlock(&g_lnnDfxReportMutex);
        return SOFTBUS_MEM_ERR;
    }
    (void)SoftBusMutexUnlock(&g_lnnDfxReportMutex);
    return SOFTBUS_OK;
}

bool IsExistLnnDfxNodeByUdidHash(const char *udidHash, LnnBleReportExtra *bleExtra)
{
    if (udidHash == NULL || bleExtra == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return false;
    }
    if (!g_lnnDfxReportIsInit && !LnnBleReportExtraMapInit()) {
        LNN_LOGE(LNN_BUILDER, "LnnBleReportExtraMap is not init");
        return false;
    }
    if (GetNodeFromLnnBleReportExtraMap(udidHash, bleExtra) != SOFTBUS_OK) {
        return false;
    }
    char *anonyUdidHash = NULL;
    Anonymize(udidHash, &anonyUdidHash);
    LNN_LOGI(LNN_BUILDER, "device report node is exist, udidHash=%{public}s", AnonymizeWrapper(anonyUdidHash));
    AnonymizeFree(anonyUdidHash);
    return true;
}

void DeleteNodeFromLnnBleReportExtraMap(const char *udidHash)
{
    if (!g_lnnDfxReportIsInit || udidHash == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return;
    }
    if (SoftBusMutexLock(&g_lnnDfxReportMutex) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "SoftBusMutexLock fail");
        return;
    }
    int32_t ret = LnnMapErase(&g_lnnDfxReportMap, udidHash);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "delete item fail, ret=%{public}d", ret);
        (void)SoftBusMutexUnlock(&g_lnnDfxReportMutex);
        return;
    }
    (void)SoftBusMutexUnlock(&g_lnnDfxReportMutex);
}

void ClearLnnBleReportExtraMap(void)
{
    if (!g_lnnDfxReportIsInit) {
        return;
    }
    if (SoftBusMutexLock(&g_lnnDfxReportMutex) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "SoftBusMutexLock fail");
        return;
    }
    LnnMapDelete(&g_lnnDfxReportMap);
    LNN_LOGI(LNN_BUILDER, "ClearLnnBleReportExtraMap succ");
    (void)SoftBusMutexUnlock(&g_lnnDfxReportMutex);
}

void LnnBlePcRestrictMapInit(void)
{
    if (g_lnnDfxPcIsInit) {
        return;
    }
    if (SoftBusMutexInit(&g_lnnDfxPcMutex, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "mutex init fail");
        return;
    }
    LnnMapInit(&g_lnnDfxPcMap);
    g_lnnDfxPcIsInit = true;
    LNN_LOGI(LNN_BUILDER, "map init succ");
    return;
}

void AddNodeToPcRestrictMap(const char *udidHash)
{
    if (!g_lnnDfxPcIsInit || udidHash == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return;
    }
    if (SoftBusMutexLock(&g_lnnDfxPcMutex) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "SoftBusMutexLock fail");
        return;
    }
    uint32_t count = 1;
    if (LnnMapSet(&g_lnnDfxPcMap, udidHash, &count, sizeof(uint32_t)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "LnnMapSet fail");
        (void)SoftBusMutexUnlock(&g_lnnDfxPcMutex);
        return;
    }
    (void)SoftBusMutexUnlock(&g_lnnDfxPcMutex);
    char *anonyUdid = NULL;
    Anonymize(udidHash, &anonyUdid);
    LNN_LOGI(LNN_BUILDER, "add %{public}s to map succ", AnonymizeWrapper(anonyUdid));
    AnonymizeFree(anonyUdid);
}

void ClearPcRestrictMap(void)
{
    if (!g_lnnDfxPcIsInit) {
        return;
    }
    if (SoftBusMutexLock(&g_lnnDfxPcMutex) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "SoftBusMutexLock fail");
        return;
    }
    LnnMapDelete(&g_lnnDfxPcMap);
    LNN_LOGI(LNN_BUILDER, "Clear Map succ");
    (void)SoftBusMutexUnlock(&g_lnnDfxPcMutex);
}

void DeleteNodeFromPcRestrictMap(const char *udidHash)
{
    if (!g_lnnDfxPcIsInit || udidHash == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return;
    }
    if (SoftBusMutexLock(&g_lnnDfxPcMutex) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "SoftBusMutexLock fail");
        return;
    }
    int32_t ret = LnnMapErase(&g_lnnDfxPcMap, udidHash);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "delete item fail, ret=%{public}d", ret);
        (void)SoftBusMutexUnlock(&g_lnnDfxPcMutex);
        return;
    }
    (void)SoftBusMutexUnlock(&g_lnnDfxPcMutex);
    char *anonyUdid = NULL;
    Anonymize(udidHash, &anonyUdid);
    LNN_LOGI(LNN_BUILDER, "delete %{public}s from map succ", AnonymizeWrapper(anonyUdid));
    AnonymizeFree(anonyUdid);
}

int32_t GetNodeFromPcRestrictMap(const char *udidHash, uint32_t *count)
{
    if (!g_lnnDfxPcIsInit || udidHash == NULL || count == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_lnnDfxPcMutex) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "SoftBusMutexLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    uint32_t *tempCount = (uint32_t *)LnnMapGet(&g_lnnDfxPcMap, udidHash);
    if (tempCount == NULL) {
        LNN_LOGE(LNN_BUILDER, "LnnMapGet fail");
        (void)SoftBusMutexUnlock(&g_lnnDfxPcMutex);
        return SOFTBUS_NOT_FIND;
    }
    *count = *tempCount;
    (void)SoftBusMutexUnlock(&g_lnnDfxPcMutex);
    return SOFTBUS_OK;
}

int32_t UpdateNodeFromPcRestrictMap(const char *udidHash)
{
    if (!g_lnnDfxPcIsInit || udidHash == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_lnnDfxPcMutex) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "SoftBusMutexLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    uint32_t *tempCount = (uint32_t *)LnnMapGet(&g_lnnDfxPcMap, udidHash);
    if (tempCount == NULL) {
        LNN_LOGE(LNN_BUILDER, "LnnMapGet fail");
        (void)SoftBusMutexUnlock(&g_lnnDfxPcMutex);
        return SOFTBUS_NOT_FIND;
    }
    *tempCount = ++(*tempCount);
    (void)SoftBusMutexUnlock(&g_lnnDfxPcMutex);
    char *anonyUdid = NULL;
    Anonymize(udidHash, &anonyUdid);
    LNN_LOGI(LNN_BUILDER, "update %{public}s succ count=%{public}u", AnonymizeWrapper(anonyUdid), *tempCount);
    AnonymizeFree(anonyUdid);
    return SOFTBUS_OK;
}

int32_t AuthFailNotifyProofInfo(int32_t errCode, const char *errorReturn, uint32_t errorReturnLen)
{
    if (errorReturn == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (errorReturnLen <= 1 || errorReturnLen >= PROOF_INFO_MAX_BUFFER_LEN) {
        LNN_LOGE(LNN_BUILDER, "invalid errorReturnLen");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnNotifyHichainProofException(errorReturn, errorReturnLen, TYPE_PC_ID, errCode);
    return SOFTBUS_OK;
}

void NotifyForegroundUseridChange(char *networkId, uint32_t discoveryType, bool isChange)
{
    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        LNN_LOGE(LNN_BUILDER, "json is null!");
        return;
    }

    if (!AddStringToJsonObject(json, "networkId", networkId) ||
        !AddNumberToJsonObject(json, "discoverType", discoveryType) ||
        !AddBoolToJsonObject(json, "ischange", isChange)) {
        LNN_LOGE(LNN_BUILDER, "add json failed");
        cJSON_Delete(json);
        return;
    }
    char *msg = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if(msg == NULL) {
        LNN_LOGE(LNN_BUILDER, "msg is null!");
        return;
    }
    LnnNotifyDeviceTrustedChange(DEVICE_FOREGROUND_USERID_CHANGE, msg, strlen(msg));
    cJSON_free(msg);
    LNN_LOGI(LNN_BUILDER, "notify change to service! isChange:%{public}s", isChange ? "true":"false");
}