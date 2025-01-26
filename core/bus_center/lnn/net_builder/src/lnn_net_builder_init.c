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
#include "lnn_oobe_manager.h"
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
#include "trans_channel_manager.h"
#include "lnn_net_builder.h"
#include "lnn_net_builder_process.h"


#define DEFAULT_PKG_NAME                 "com.huawei.nearby"
#define DEFAULT_MAX_LNN_CONNECTION_COUNT 10
#define NOT_TRUSTED_DEVICE_MSG_DELAY     5000


void SetBeginJoinLnnTime(LnnConnectionFsm *connFsm)
{
    connFsm->statisticData.beginJoinLnnTime = LnnUpTimeMs();
}

static void DfxRecordDeviceInfoExchangeEndTime(const NodeInfo *info)
{
    int32_t ret = SOFTBUS_OK;
    uint64_t timeStamp = 0;
    LnnEventExtra extra = { 0 };
    (void)LnnEventExtraInit(&extra);
    LnnTriggerInfo triggerInfo = { 0 };
    GetLnnTriggerInfo(&triggerInfo);
    timeStamp = SoftBusGetSysTimeMs();
    extra.timeLatency = timeStamp - triggerInfo.triggerTime;
    uint8_t hash[UDID_HASH_LEN] = { 0 };
    char *udidHash = (char *)SoftBusCalloc(SHORT_UDID_HASH_HEX_LEN + 1);
    if (udidHash == NULL) {
        LNN_LOGE(LNN_BUILDER, "udidHash calloc fail");
        return;
    }
    ret = SoftBusGenerateStrHash((uint8_t *)info->deviceInfo.deviceUdid, strlen(info->deviceInfo.deviceUdid),
        hash);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "generate udidhash fail. ret=%{public}d", ret);
        SoftBusFree(udidHash);
        return;
    }
    ret = ConvertBytesToHexString(udidHash, HB_SHORT_UDID_HASH_HEX_LEN + 1, hash, HB_SHORT_UDID_HASH_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "convert bytes to string fail. ret=%{public}d", ret);
        SoftBusFree(udidHash);
        return;
    }
    extra.peerUdidHash = udidHash;
    LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_AUTH_DEVICE_INFO_PROCESS, extra);
    SoftBusFree(udidHash);
}

static void OnReAuthVerifyPassed(uint32_t requestId, AuthHandle authHandle, const NodeInfo *info)
{
    LNN_LOGI(LNN_BUILDER, "reAuth verify passed: requestId=%{public}u, authId=%{public}" PRId64,
        requestId, authHandle.authId);
    LNN_CHECK_AND_RETURN_LOGE(info != NULL, LNN_BUILDER, "reAuth verify result error");
    AuthRequest authRequest = { 0 };
    if (GetAuthRequest(requestId, &authRequest) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "auth request not found");
        return;
    }
    ConnectionAddr addr;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    if (!LnnConvertAuthConnInfoToAddr(&addr, &authRequest.connInfo, GetCurrentConnectType())) {
        LNN_LOGE(LNN_BUILDER, "ConvertToConnectionAddr failed");
        return;
    }
    int32_t ret = SoftBusGenerateStrHash((unsigned char *)info->deviceInfo.deviceUdid,
        strlen(info->deviceInfo.deviceUdid), (unsigned char *)addr.info.ble.udidHash);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "gen udidHash fail");
        return;
    }
    LnnConnectionFsm *connFsm = FindConnectionFsmByAddr(&addr, true);
    if (connFsm != NULL && !connFsm->isDead && !LnnIsNeedCleanConnectionFsm(info, addr.type)) {
        if (info != NULL && LnnUpdateGroupType(info) == SOFTBUS_OK && LnnUpdateAccountInfo(info) == SOFTBUS_OK) {
            UpdateProfile(info);
            LnnUpdateRemoteDeviceName(info);
            NodeInfo nodeInfo;
            (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
            (void)LnnGetRemoteNodeInfoById(info->deviceInfo.deviceUdid, CATEGORY_UDID, &nodeInfo);
            UpdateDpSameAccount(nodeInfo.accountId, nodeInfo.deviceInfo.deviceUdid, nodeInfo.userId);
        }
    } else {
        connFsm = StartNewConnectionFsm(&addr, DEFAULT_PKG_NAME, true);
        if (connFsm == NULL) {
            return;
        }
        connFsm->connInfo.authHandle = authHandle;
        connFsm->connInfo.nodeInfo = DupNodeInfo(info);
        connFsm->connInfo.flag |= LNN_CONN_INFO_FLAG_JOIN_AUTO;
        LNN_LOGI(LNN_BUILDER, "fsmId=%{public}u start a connection fsm, authId=%{public}" PRId64,
            connFsm->id, authHandle.authId);
        if (LnnSendAuthResultMsgToConnFsm(connFsm, SOFTBUS_OK) != SOFTBUS_OK) {
            SoftBusFree(connFsm->connInfo.nodeInfo);
            connFsm->connInfo.nodeInfo = NULL;
            StopConnectionFsm(connFsm);
        }
    }
}

static void OnReAuthVerifyFailed(uint32_t requestId, int32_t reason)
{
    LNN_LOGI(LNN_BUILDER, "verify failed. requestId=%{public}u, reason=%{public}d", requestId, reason);
    if (reason >= SOFTBUS_HICHAIN_MIN && reason <= SOFTBUS_HICHAIN_MAX) {
        AuthHandle authHandle = { .authId = AUTH_INVALID_ID };
        PostVerifyResult(requestId, reason, authHandle, NULL);
    }
}

static AuthVerifyCallback g_reAuthVerifyCallback = {
    .onVerifyPassed = OnReAuthVerifyPassed,
    .onVerifyFailed = OnReAuthVerifyFailed,
};

AuthVerifyCallback *LnnGetReAuthVerifyCallback(void)
{
    return &g_reAuthVerifyCallback;
}

void NotifyStateForSession(const ConnectionAddr *addr)
{
    if (addr == NULL) {
        LNN_LOGE(LNN_BUILDER, "addr is null.");
        return;
    }
    ConnIdCbInfo connIdCbInfo;
    (void)memset_s(&connIdCbInfo, sizeof(ConnIdCbInfo), 0, sizeof(ConnIdCbInfo));
    int32_t ret = GetConnIdCbInfoByAddr(addr, &connIdCbInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get connIdCbInfo fail.");
        return ;
    }
    LnnNotifyStateForSession(connIdCbInfo.udid, SOFTBUS_NETWORK_JOIN_REQUEST_ERR);
}

int32_t PostJoinRequestToConnFsm(LnnConnectionFsm *connFsm, const JoinLnnMsgPara *para, bool needReportFailure)
{
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "JoinLnnMsgPara is null");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t rc = SOFTBUS_OK;
    bool isCreate = false;

    if (connFsm == NULL) {
        connFsm = FindConnectionFsmByAddr(&para->addr, false);
    }
    if (connFsm == NULL || connFsm->isDead || CheckRemoteBasicInfoChanged(para->dupInfo)) {
        connFsm = StartNewConnectionFsm(&para->addr, para->pkgName, para->isNeedConnect);
        if (connFsm != NULL) {
            connFsm->connInfo.dupInfo = (para->dupInfo == NULL) ? NULL : DupNodeInfo(para->dupInfo);
        }
        isCreate = true;
    }
    if (connFsm != NULL && para->isSession) {
        connFsm->isSession = true;
    }

    if (connFsm == NULL || LnnSendJoinRequestToConnFsm(connFsm) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "process join lnn request failed");
        if (needReportFailure) {
            LnnNotifyJoinResult((ConnectionAddr *)&para->addr, NULL, SOFTBUS_NETWORK_JOIN_REQUEST_ERR);
            NotifyStateForSession(&para->addr);
        }
        if (connFsm != NULL && isCreate) {
            LnnFsmRemoveMessageByType(&connFsm->fsm, FSM_CTRL_MSG_START);
            ListDelete(&connFsm->node);
            --LnnGetNetBuilder()->connCount;
            LnnDestroyConnectionFsm(connFsm);
        }
        rc = SOFTBUS_NETWORK_JOIN_REQUEST_ERR;
    }
    if (rc == SOFTBUS_OK) {
        connFsm->connInfo.infoReport = para->infoReport;
        connFsm->connInfo.flag |=
            (needReportFailure ? LNN_CONN_INFO_FLAG_JOIN_REQUEST : LNN_CONN_INFO_FLAG_JOIN_AUTO);
        LNN_LOGI(LNN_BUILDER, "infoReport.osType=%{public}d, infoReport.type=%{public}X",
            connFsm->connInfo.infoReport.osType, connFsm->connInfo.infoReport.type);
    }
    return rc;
}

void TryRemovePendingJoinRequest(void)
{
    PendingJoinRequestNode *item = NULL;
    PendingJoinRequestNode *next = NULL;
    JoinLnnMsgPara para;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &LnnGetNetBuilder()->pendingList, PendingJoinRequestNode, node) {
        if (NeedPendingJoinRequest()) {
            return;
        }
        ListDelete(&item->node);
        (void)memset_s(&para, sizeof(JoinLnnMsgPara), 0, sizeof(JoinLnnMsgPara));
        para.isNeedConnect = true;
        para.addr = item->addr;
        if (strcpy_s(para.pkgName, PKG_NAME_SIZE_MAX, DEFAULT_PKG_NAME) != EOK) {
            LNN_LOGE(LNN_BUILDER, "strcpy_s pkgName failed");
            SoftBusFree(item);
            continue;
        }
        if (PostJoinRequestToConnFsm(NULL, &para, item->needReportFailure) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "post pending join request failed");
        }
        LNN_LOGI(
            LNN_BUILDER, "remove a pending join request, peerAddr=%{public}s", LnnPrintConnectionAddr(&item->addr));
        SoftBusFree(item);
        break;
    }
}

void InitiateNewNetworkOnline(ConnectionAddrType addrType, const char *networkId)
{
    LnnConnectionFsm *item = NULL;
    int32_t rc;

    // find target connfsm, then notify it online
    LIST_FOR_EACH_ENTRY(item, &LnnGetNetBuilder()->fsmList, LnnConnectionFsm, node) {
        if (strcmp(networkId, item->connInfo.peerNetworkId) != 0) {
            continue;
        }
        if (item->isDead) {
            continue;
        }
        if (addrType != CONNECTION_ADDR_MAX && addrType != item->connInfo.addr.type) {
            continue;
        }
        rc = LnnSendNewNetworkOnlineToConnFsm(item);
        LNN_LOGI(LNN_INIT, "initiate new network online to connection. fsmId=%{public}u, rc=%{public}d", item->id, rc);
    }
}

void TryInitiateNewNetworkOnline(const LnnConnectionFsm *connFsm)
{
    LnnConnectionFsm *item = NULL;
    LnnInvalidCleanInfo *cleanInfo = connFsm->connInfo.cleanInfo;

    if ((connFsm->connInfo.flag & LNN_CONN_INFO_FLAG_INITIATE_ONLINE) == 0) {
        LNN_LOGI(LNN_INIT, "no need initiate new network online. fsmId=%{public}u", connFsm->id);
        return;
    }
    // let last invalid connfsm notify new network online after it clean
    LIST_FOR_EACH_ENTRY(item, &LnnGetNetBuilder()->fsmList, LnnConnectionFsm, node) {
        if (strcmp(connFsm->connInfo.peerNetworkId, item->connInfo.peerNetworkId) != 0) {
            continue;
        }
        if ((item->connInfo.flag & LNN_CONN_INFO_FLAG_INITIATE_ONLINE) == 0) {
            continue;
        }
        LNN_LOGI(LNN_INIT, "wait last connfsm clean, then initiate new network online. fsmId=%{public}u", connFsm->id);
        return;
    }
    InitiateNewNetworkOnline(cleanInfo->addrType, cleanInfo->networkId);
}

void TryDisconnectAllConnection(const LnnConnectionFsm *connFsm)
{
    LnnConnectionFsm *item = NULL;
    const ConnectionAddr *addr1 = &connFsm->connInfo.addr;
    const ConnectionAddr *addr2 = NULL;
    ConnectOption option;

    // Not really leaving lnn
    if ((connFsm->connInfo.flag & LNN_CONN_INFO_FLAG_ONLINE) == 0) {
        return;
    }
    LIST_FOR_EACH_ENTRY(item, &LnnGetNetBuilder()->fsmList, LnnConnectionFsm, node) {
        addr2 = &item->connInfo.addr;
        if (addr1->type != addr2->type) {
            continue;
        }
        if (addr1->type == CONNECTION_ADDR_BR || addr1->type == CONNECTION_ADDR_BLE) {
            if (strncmp(item->connInfo.addr.info.br.brMac, addr2->info.br.brMac, BT_MAC_LEN) == 0) {
                return;
            }
        } else if (addr1->type == CONNECTION_ADDR_WLAN || addr1->type == CONNECTION_ADDR_ETH) {
            if (strncmp(addr1->info.ip.ip, addr2->info.ip.ip, strlen(addr1->info.ip.ip)) == 0) {
                return;
            }
        }
    }
    if (addr1->type == CONNECTION_ADDR_BR) {
        LNN_LOGI(
            LNN_BUILDER, "not disconnect all connection. fsmId=%{public}u, type=%{public}d", connFsm->id, addr1->type);
        return;
    }
    LNN_LOGI(LNN_BUILDER, "disconnect all connection. fsmId=%{public}u, type=%{public}d", connFsm->id, addr1->type);
    if (LnnConvertAddrToOption(addr1, &option) && CheckAuthChannelIsExit(&option) != SOFTBUS_OK) {
        ConnDisconnectDeviceAllConn(&option);
    }
}

void TryNotifyAllTypeOffline(const LnnConnectionFsm *connFsm)
{
    LnnConnectionFsm *item = NULL;
    const ConnectionAddr *addr1 = &connFsm->connInfo.addr;
    const ConnectionAddr *addr2 = NULL;

    LIST_FOR_EACH_ENTRY(item, &LnnGetNetBuilder()->fsmList, LnnConnectionFsm, node) {
        addr2 = &item->connInfo.addr;
        if (addr1->type == addr2->type) {
            return;
        }
    }
    LNN_LOGI(LNN_BUILDER, "notify all connection offline. fsmId=%{public}u, type=%{public}d", connFsm->id, addr1->type);
    (void)LnnNotifyAllTypeOffline(addr1->type);
}

LnnConnectionFsm *FindConnectionFsmByConnFsmId(uint16_t connFsmId)
{
    LnnConnectionFsm *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &LnnGetNetBuilder()->fsmList, LnnConnectionFsm, node) {
        if (connFsmId == item->id) {
            return item;
        }
    }
    return NULL;
}

int32_t TryElectMasterNodeOnline(const LnnConnectionFsm *connFsm)
{
    char peerMasterUdid[UDID_BUF_LEN] = { 0 };
    char localMasterUdid[UDID_BUF_LEN] = { 0 };
    int32_t localMasterWeight;
    int32_t peerMasterWeight;
    int32_t rc;

    // get local master node info
    if (LnnGetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, localMasterUdid, UDID_BUF_LEN) != SOFTBUS_OK ||
        LnnGetLocalNumInfo(NUM_KEY_MASTER_NODE_WEIGHT, &localMasterWeight) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local master node info from ledger failed");
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    LNN_LOGI(LNN_BUILDER, "local master fsmId=%{public}u, weight=%{public}d", connFsm->id, localMasterWeight);
    if (LnnGetRemoteStrInfo(connFsm->connInfo.peerNetworkId, STRING_KEY_MASTER_NODE_UDID,
        peerMasterUdid, UDID_BUF_LEN) != SOFTBUS_OK ||
        LnnGetRemoteNumInfo(connFsm->connInfo.peerNetworkId, NUM_KEY_MASTER_NODE_WEIGHT,
            &peerMasterWeight) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "peer node info is not found. fsmId=%{public}u", connFsm->id);
        return SOFTBUS_NETWORK_NOT_FOUND;
    }
    LNN_LOGI(LNN_BUILDER, "peer master fsmId=%{public}u, weight=%{public}d", connFsm->id, peerMasterWeight);
    rc = LnnCompareNodeWeight(localMasterWeight, localMasterUdid, peerMasterWeight, peerMasterUdid);
    if (rc >= 0) {
        LNN_LOGI(LNN_BUILDER,
            "online node  weight less than current, no need elect again. fsmId=%{public}u, compareResult=%{public}d",
            connFsm->id, rc);
        return SOFTBUS_OK;
    }
    UpdateLocalMasterNode(false, peerMasterUdid, peerMasterWeight);
    SendElectMessageToAll(connFsm->connInfo.peerNetworkId);
    return SOFTBUS_OK;
}

int32_t TryElectMasterNodeOffline(const LnnConnectionFsm *connFsm)
{
    char localUdid[UDID_BUF_LEN] = { 0 };
    char localMasterUdid[UDID_BUF_LEN] = { 0 };

    if (LnnGetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, localMasterUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local master node info from ledger failed");
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN);
    if (strcmp(localMasterUdid, localUdid) == 0) {
        LNN_LOGI(LNN_BUILDER, "local is master node, no need elect again. fsmId=%{public}u", connFsm->id);
    } else {
        LNN_LOGI(LNN_BUILDER, "maybe master node offline, elect again. fsmId=%{public}u", connFsm->id);
        UpdateLocalMasterNode(true, localUdid, LnnGetLocalWeight());
        SendElectMessageToAll(connFsm->connInfo.peerNetworkId);
    }
    return SOFTBUS_OK;
}

bool IsSupportMasterNodeElect(SoftBusVersion version)
{
    LNN_LOGD(LNN_BUILDER, "SoftBusVersion=%{public}d", version);
    return version >= SOFTBUS_NEW_V1;
}

void TryElectAsMasterState(const char *networkId, bool isOnline)
{
    if (networkId == NULL) {
        LNN_LOGW(LNN_BUILDER, "invalid networkId");
        return;
    }
    if (isOnline) {
        LNN_LOGD(LNN_BUILDER, "restore master state ignore online process");
        return;
    }
    char masterUdid[UDID_BUF_LEN] = { 0 };
    char localUdid[UDID_BUF_LEN] = { 0 };
    if (LnnGetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, masterUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local master node info from ledger failed");
        return;
    }
    const char *peerUdid = LnnConvertDLidToUdid(networkId, CATEGORY_NETWORK_ID);
    if (peerUdid == NULL) {
        char *anonyNetworkId = NULL;
        Anonymize(networkId, &anonyNetworkId);
        LNN_LOGE(LNN_BUILDER, "get invalid peerUdid, networkId=%{public}s", AnonymizeWrapper(anonyNetworkId));
        AnonymizeFree(anonyNetworkId);
        return;
    }
    if (strcmp(masterUdid, peerUdid) != 0) {
        char *anonyPeerUdid = NULL;
        char *anonyMasterUdid = NULL;
        Anonymize(peerUdid, &anonyPeerUdid);
        Anonymize(masterUdid, &anonyMasterUdid);
        LNN_LOGD(LNN_BUILDER, "offline node is not master node. peerUdid=%{public}s, masterUdid=%{public}s",
            AnonymizeWrapper(anonyPeerUdid), AnonymizeWrapper(anonyMasterUdid));
        AnonymizeFree(anonyPeerUdid);
        AnonymizeFree(anonyMasterUdid);
        return;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local udid failed");
        return;
    }
    UpdateLocalMasterNode(true, localUdid, LnnGetLocalWeight());
}

static void DeinitNodeInfoSync(void)
{
    LnnDeinitP2p();
    LnnDeinitNetworkInfo();
    LnnDeinitDevicename();
    LnnDeinitOffline();
    LnnDeinitBatteryInfo();
    LnnDeinitWifiDirect();
}

static void NetBuilderConfigInit(void)
{
    if (SoftbusGetConfig(SOFTBUS_INT_MAX_LNN_CONNECTION_CNT, (unsigned char *)&LnnGetNetBuilder()->maxConnCount,
        sizeof(LnnGetNetBuilder()->maxConnCount)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "get lnn max connection count fail, use default value");
        LnnGetNetBuilder()->maxConnCount = DEFAULT_MAX_LNN_CONNECTION_COUNT;
    }
    if (SoftbusGetConfig(SOFTBUS_INT_LNN_MAX_CONCURRENT_NUM, (unsigned char *)&LnnGetNetBuilder()->maxConcurrentCount,
        sizeof(LnnGetNetBuilder()->maxConcurrentCount)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "get lnn max conncurent count fail, use default value");
        LnnGetNetBuilder()->maxConcurrentCount = 0;
    }
    LNN_LOGD(LNN_INIT, "lnn config count: maxConnCount=%{public}d, maxConcurrentCount=%{public}d",
        LnnGetNetBuilder()->maxConnCount, LnnGetNetBuilder()->maxConcurrentCount);
}

static int32_t InitNodeInfoSync(void)
{
    int32_t rc = LnnInitP2p();
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init lnn p2p fail, rc=%{public}d", rc);
        return rc;
    }
    rc = LnnInitNetworkInfo();
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "LnnInitNetworkInfo fail, rc=%{public}d", rc);
        return rc;
    }
    rc = LnnInitDevicename();
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "LnnInitDeviceName fail, rc=%{public}d", rc);
        return rc;
    }
    rc = LnnInitOffline();
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "LnnInitOffline fail, rc=%{public}d", rc);
        return rc;
    }
    rc = LnnInitBatteryInfo();
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "LnnInitBatteryInfo fail, rc=%{public}d", rc);
        return rc;
    }
    rc = LnnInitCipherKeyManager();
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "LnnInitCipherKeyManager fail, rc=%{public}d", rc);
        return rc;
    }
    rc = LnnInitWifiDirect();
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init lnn wifidirect addr fail, rc=%{public}d", rc);
        return rc;
    }
    return SOFTBUS_OK;
}

static void UpdatePCInfoWithoutSoftbus(void)
{
    int32_t onlineNum = 0;
    NodeBasicInfo *info = NULL;
    if (LnnGetAllOnlineNodeInfo(&info, &onlineNum) != 0) {
        LNN_LOGE(LNN_BUILDER, "LnnGetAllOnlineNodeInfo failed!");
        return;
    }
    if (info == NULL || onlineNum == 0) {
        LNN_LOGW(LNN_BUILDER, "not online node");
        return;
    }
    // mark-- remove pc offline
    SoftBusFree(info);
}

static void AccountStateChangeHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_ACCOUNT_CHANGED) {
        LNN_LOGW(LNN_BUILDER, "invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusAccountState accountState = (SoftBusAccountState)event->status;
    switch (accountState) {
        case SOFTBUS_ACCOUNT_LOG_IN:
            LNN_LOGI(LNN_BUILDER, "ignore SOFTBUS_ACCOUNT_LOG_IN");
            break;
        case SOFTBUS_ACCOUNT_LOG_OUT:
            LNN_LOGI(LNN_BUILDER, "handle SOFTBUS_ACCOUNT_LOG_OUT");
            UpdatePCInfoWithoutSoftbus();
            break;
        default:
            return;
    }
}

static void OnDeviceVerifyPass(AuthHandle authHandle, const NodeInfo *info)
{
    LNN_CHECK_AND_RETURN_LOGE(info != NULL, LNN_BUILDER, "NodeInfo is NULL");
    AuthConnInfo connInfo;
    DeviceVerifyPassMsgPara *para = NULL;
    LNN_LOGI(LNN_BUILDER, "verify passed passively, authId=%{public}" PRId64, authHandle.authId);
    if (authHandle.type < AUTH_LINK_TYPE_WIFI || authHandle.type >= AUTH_LINK_TYPE_MAX) {
        LNN_LOGE(LNN_BUILDER, "authHandle type error");
        return;
    }
    if (AuthGetConnInfo(authHandle, &connInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get AuthConnInfo fail, authId=%{public}" PRId64, authHandle.authId);
        return;
    }
    para = (DeviceVerifyPassMsgPara *)SoftBusMalloc(sizeof(DeviceVerifyPassMsgPara));
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc DeviceVerifyPassMsgPara fail");
        return;
    }

    if (authHandle.type != AUTH_LINK_TYPE_ENHANCED_P2P && authHandle.type != AUTH_LINK_TYPE_SESSION) {
        if (!LnnConvertAuthConnInfoToAddr(&para->addr, &connInfo, GetCurrentConnectType())) {
            LNN_LOGE(LNN_BUILDER, "convert connInfo to addr fail");
            SoftBusFree(para);
            return;
        }
    } else {
        para->addr.type = CONNECTION_ADDR_BR;
        if (strcpy_s(para->addr.info.br.brMac, BT_MAC_LEN, info->connectInfo.macAddr) != EOK) {
            LNN_LOGE(LNN_BUILDER, "copy br mac to addr fail");
        }
    }

    para->authHandle = authHandle;
    para->nodeInfo = DupNodeInfo(info);
    if (para->nodeInfo == NULL) {
        LNN_LOGE(LNN_BUILDER, "dup NodeInfo fail");
        SoftBusFree(para);
        return;
    }
    if (PostBuildMessageToHandler(MSG_TYPE_DEVICE_VERIFY_PASS, para) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "post DEVICE_VERIFY_PASS msg fail");
        SoftBusFree(para->nodeInfo);
        SoftBusFree(para);
    }
    LnnNotifyDeviceVerified(info->deviceInfo.deviceUdid);
    DfxRecordDeviceInfoExchangeEndTime(info);
}

static void OnDeviceDisconnect(AuthHandle authHandle)
{
    if (authHandle.type < AUTH_LINK_TYPE_WIFI || authHandle.type >= AUTH_LINK_TYPE_MAX) {
        LNN_LOGE(LNN_BUILDER, "authHandle type error");
        return;
    }
    AuthHandle *para = NULL;
    para = (AuthHandle *)SoftBusMalloc(sizeof(AuthHandle));
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc DeviceDisconnect para fail");
        return;
    }
    LNN_LOGI(LNN_BUILDER, "auth device disconnect, authId=%{public}" PRId64, authHandle.authId);
    para->authId = authHandle.authId;
    para->type = authHandle.type;
    if (PostBuildMessageToHandler(MSG_TYPE_DEVICE_DISCONNECT, para) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "post DEVICE_DISCONNECT msg fail");
        SoftBusFree(para);
    }
}

static bool IsNeedNotifyOfflineByAdv(const char *udid)
{
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoByKey(udid, &info) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get nodeinfo fail");
        return false;
    }
    if (!IsSupportFeatureByCapaBit(info.authCapacity, BIT_SUPPORT_ADV_OFFLINE)) {
        LNN_LOGI(LNN_BUILDER, "peer device not support notify offline by adv");
        return false;
    }
    if (LnnHasDiscoveryType(&info, DISCOVERY_TYPE_WIFI)) {
        LNN_LOGI(LNN_BUILDER, "wifi online, no need notify offline by adv");
        return false;
    }

    uint32_t local = 0;
    int32_t ret = LnnGetLocalNumU32Info(NUM_KEY_NET_CAP, &local);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "lnnGetLocalNumInfo err, ret=%{public}d, local=%{public}u", ret, local);
        return false;
    }
    if (((local & (1 << BIT_BLE)) == 0) || ((info.netCapacity & (1 << BIT_BLE)) == 0)) {
        LNN_LOGE(LNN_BUILDER, "ble capa disable, local=%{public}u, remote=%{public}u", local, info.netCapacity);
        return false;
    }
    LnnRequestLeaveSpecific(info.networkId, CONNECTION_ADDR_MAX);
    return true;
}

static void OnDeviceNotTrusted(const char *peerUdid)
{
    if (peerUdid == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid udid");
        return;
    }
    uint32_t udidLen = strlen(peerUdid) + 1;
    if (udidLen > UDID_BUF_LEN) {
        LNN_LOGE(LNN_BUILDER, "udid is too long");
        return;
    }
    if (DeletePcNodeInfo(peerUdid)) {
        LNN_LOGI(LNN_BUILDER, "pc without softbus, handle offline");
        return;
    }
    const char *useUdid = NULL;
    char udid[UDID_BUF_LEN] = { 0 };
    if (StringToLowerCase(peerUdid, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        return;
    }
    useUdid = SelectUseUdid(peerUdid, udid);
    if (useUdid == NULL) {
        return;
    }
    LNN_CHECK_AND_RETURN_LOGW(!IsNeedNotifyOfflineByAdv(peerUdid), LNN_BUILDER, "need notify offline by adv");
    NotTrustedDelayInfo *info = (NotTrustedDelayInfo *)SoftBusCalloc(sizeof(NotTrustedDelayInfo));
    LNN_CHECK_AND_RETURN_LOGE(info != NULL, LNN_BUILDER, "malloc NotTrustedDelayInfo fail");
    if (AuthGetLatestAuthSeqList(useUdid, info->authSeq, DISCOVERY_TYPE_COUNT) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get latest AuthSeq list fail");
        SoftBusFree(info);
        return;
    }
    if (strcpy_s(info->udid, UDID_BUF_LEN, useUdid) != EOK) {
        LNN_LOGE(LNN_BUILDER, "copy udid fail");
        SoftBusFree(info);
        return;
    }
    if (LnnSendNotTrustedInfo(info, DISCOVERY_TYPE_COUNT, LnnProcessCompleteNotTrustedMsg) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "send NotTrustedInfo fail");
        OnLnnProcessNotTrustedMsgDelay((void *)info);
        return;
    }
    if (LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), OnLnnProcessNotTrustedMsgDelay,
        (void *)info, NOT_TRUSTED_DEVICE_MSG_DELAY) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "async not trusted msg delay fail");
        SoftBusFree(info);
    }
}

AuthVerifyListener g_verifyListener = {
    .onDeviceVerifyPass = OnDeviceVerifyPass,
    .onDeviceNotTrusted = OnDeviceNotTrusted,
    .onDeviceDisconnect = OnDeviceDisconnect,
};

static void UserSwitchedHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_USER_SWITCHED) {
        LNN_LOGW(LNN_BUILDER, "invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusUserSwitchState userSwitchState = (SoftBusUserSwitchState)event->status;
    bool isDataShareInit = true;
    switch (userSwitchState) {
        case SOFTBUS_USER_SWITCHED:
            LNN_LOGI(LNN_BUILDER, "SOFTBUS_USER_SWITCHED");
            LnnGetDataShareInitResult(&isDataShareInit);
            if (isDataShareInit) {
                RegisterOOBEMonitor(NULL);
            }
            LnnSetUnlockState();
            break;
        default:
            return;
    }
}

static int32_t InitNetBuilderLooper(void)
{
    ListInit(&LnnGetNetBuilder()->fsmList);
    ListInit(&LnnGetNetBuilder()->pendingList);
    LnnGetNetBuilder()->nodeType = NODE_TYPE_L;
    LnnGetNetBuilder()->looper = GetLooper(LOOP_TYPE_DEFAULT);
    if (LnnGetNetBuilder()->looper == NULL) {
        LNN_LOGE(LNN_INIT, "get default looper fail");
        return SOFTBUS_LOOPER_ERR;
    }
    LnnGetNetBuilder()->handler.name = (char *)"NetBuilderHandler";
    LnnGetNetBuilder()->handler.looper = LnnGetNetBuilder()->looper;
    LnnGetNetBuilder()->handler.HandleMessage = NetBuilderMessageHandler;
    LnnGetNetBuilder()->isInit = true;
    LNN_LOGI(LNN_INIT, "init net builder looper success");
    return SOFTBUS_OK;
}

static int32_t InitSyncInfoReg(void)
{
    int32_t rc = LnnRegSyncInfoHandler(LNN_INFO_TYPE_MASTER_ELECT, OnReceiveMasterElectMsg);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "register sync master elect msg fail, rc=%{public}d", rc);
        return rc;
    }
    rc = LnnRegSyncInfoHandler(LNN_INFO_TYPE_NODE_ADDR, OnReceiveNodeAddrChangedMsg);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "register node addr changed msg fail, rc=%{public}d", rc);
        return rc;
    }
    return SOFTBUS_OK;
}
 
int32_t LnnInitNetBuilder(void)
{
    if (LnnGetNetBuilder()->isInit == true) {
        LNN_LOGI(LNN_INIT, "init net builder repeatly");
        return SOFTBUS_OK;
    }
    int32_t rc = LnnInitSyncInfoManager();
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init sync info manager fail, rc=%{public}d", rc);
        return rc;
    }
    LnnInitTopoManager();
    UpdateLocalNetCapability();
    InitNodeInfoSync();
    LnnInitConnIdCallbackManager();
    NetBuilderConfigInit();
    // link finder init fail will not cause softbus init fail
    if (LnnLinkFinderInit() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "link finder init fail");
    }
    rc = RegAuthVerifyListener(&g_verifyListener);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "register auth verify listener fail, rc=%{public}d", rc);
        return rc;
    }
    rc = InitSyncInfoReg();
    if (rc != SOFTBUS_OK) {
        return rc;
    }
    rc = ConifgLocalLedger();
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "config local ledger fail, rc=%{public}d", rc);
        return rc;
    }
    rc = LnnRegisterEventHandler(LNN_EVENT_ACCOUNT_CHANGED, AccountStateChangeHandler);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist account change evt handler fail, rc=%{public}d", rc);
        return rc;
    }
    rc = LnnRegisterEventHandler(LNN_EVENT_USER_SWITCHED, UserSwitchedHandler);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist user switch evt handler fail, rc=%{public}d", rc);
        return rc;
    }
    if (!LnnSubcribeKvStoreService()) {
        LNN_LOGE(LNN_INIT, "regist kv store service fail!");
    }
    return InitNetBuilderLooper();
}


int32_t LnnInitNetBuilderDelay(void)
{
    char udid[UDID_BUF_LEN] = { 0 };
    // set master weight and master udid
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, UDID_BUF_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "get local udid error!");
        return ret;
    }
    LnnSetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, udid);
    LnnSetLocalNumInfo(NUM_KEY_MASTER_NODE_WEIGHT, LnnGetLocalWeight());
    ret = LnnInitFastOffline();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "fast offline init fail!");
        return ret;
    }
    return SOFTBUS_OK;
}

void LnnDeinitNetBuilder(void)
{
    LnnConnectionFsm *item = NULL;
    LnnConnectionFsm *nextItem = NULL;

    if (!LnnGetNetBuilder()->isInit) {
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &LnnGetNetBuilder()->fsmList, LnnConnectionFsm, node) {
        StopConnectionFsm(item);
    }
    LnnUnregSyncInfoHandler(LNN_INFO_TYPE_MASTER_ELECT, OnReceiveMasterElectMsg);
    LnnUnregSyncInfoHandler(LNN_INFO_TYPE_NODE_ADDR, OnReceiveNodeAddrChangedMsg);
    LnnUnregisterEventHandler(LNN_EVENT_ACCOUNT_CHANGED, AccountStateChangeHandler);
    LnnUnregisterEventHandler(LNN_EVENT_USER_SWITCHED, UserSwitchedHandler);
    UnregAuthVerifyListener();
    LnnDeinitTopoManager();
    DeinitNodeInfoSync();
    LnnDeinitFastOffline();
    LnnDeinitSyncInfoManager();
    LnnDeinitConnIdCallbackManager();
    LnnGetNetBuilder()->isInit = false;
}