/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "instant_statistics.h"

#include "bus_center_manager.h"
#include "comm_log.h"
#include "communication_radar.h"
#include "data/link_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane_interface.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_error_code.h"
#include "legacy/softbus_hisysevt_transreporter.h"
#include "softbus_json_utils.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_utils.h"
#include "trans_auth_manager.h"
#include "trans_channel_common.h"
#include "trans_event.h"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_udp_channel_manager.h"
#include "wifi_statistic.h"
#include "bt_statistic.h"
#include "anonymizer.h"

using namespace OHOS::SoftBus;

static constexpr const uint32_t INST_MAX_REMOTE_NUM = 100;
static constexpr const int INST_MAX_CHANNEL_NUM_EACH = 100;

static constexpr const uint32_t UNKNOWN_IP = 0;
static constexpr const uint32_t HML_IP = 1;
static constexpr const uint32_t P2P_IP = 2;
static constexpr const uint32_t WLAN_IP = 3;

static constexpr const int INST_MINUTE_TIME = 60 * 1000;
static constexpr const int INST_DELAY_REGISTER = 0;
using InstAsyncCallbackFunc = void (*)(SoftBusMessage *);

using InstantChannelInfo = struct {
    ListNode node;
    std::string socketName;
    int32_t channelType;
    int32_t appType;
    int32_t laneLinkType;
    int32_t connectType;
    int32_t status;
    bool serverSide;
    int64_t startTime;
};

using InstantRemoteInfo = struct {
    ListNode node;
    uint16_t deviceType;
    std::string udid;
    std::string uuid;
    std::string hmlMac;
    std::string p2pMac;
    std::string hmlIp;
    std::string p2pIp;
    std::string wlanIp;
    std::string bleMac;
    std::string brMac;
    int32_t p2pRole;
    int32_t p2pFreq;
    int32_t hmlFreq;
    int32_t staFreq;
    int32_t p2pLinkState;
    int32_t hmlLinkState;
    uint32_t discoveryType;
    uint32_t netCapability;
    int32_t channelNum;
    ListNode channels;
};

static std::string AnonymizeStr(const std::string &data)
{
    if (data.empty()) {
        return "";
    }
    char *temp = nullptr;
    Anonymize(data.c_str(), &temp);
    std::string result = AnonymizeWrapper(temp);
    AnonymizeFree(temp);
    return result;
}

static void InstPackAndAnonymizeStringIfNotNull(cJSON *json, std::string &str, const char *key, bool isDeviceId)
{
    if (json == NULL || str.empty() || key == NULL) {
        return;
    }
    if (isDeviceId) {
        (void)AddStringToJsonObject(json, key, AnonymizeStr(str).c_str());
    } else {
        (void)AddStringToJsonObject(json, key, AnonymizeStr(str).c_str());
    }
}

static bool InstantIsParaMatch(const std::string &dst, const std::string &src)
{
    if (dst.empty() || src.empty() || dst.compare(src) != 0) {
        return false;
    }
    return true;
}

static int32_t InstSetPeerDeviceIdForRemoteInfo(std::string &dst, const std::string &src)
{
    if (!dst.empty() || src.empty()) {
        return SOFTBUS_INVALID_PARAM;
    }
    dst = src;
    return SOFTBUS_OK;
}

#ifdef DSOFTBUS_FEATURE_CONN_PV1
static void InstUpdateRemoteInfoByInnerLink(InstantRemoteInfo *remoteInfo,
    const InnerLinkBasicInfo &link, const std::string &remoteUuid)
{
    if (remoteInfo == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    if (remoteUuid.empty()) {
        return;
    }
    InstSetPeerDeviceIdForRemoteInfo(remoteInfo->uuid, remoteUuid);
    InnerLink::LinkType linkType = link.linkType;
    if (linkType != InnerLink::LinkType::P2P && linkType != InnerLink::LinkType::HML) {
        return;
    }
    InnerLink::LinkState state = link.state;
    if (linkType == InnerLink::LinkType::P2P) {
        remoteInfo->p2pFreq = link.freq;
        remoteInfo->p2pLinkState = (int32_t)state;
        InstSetPeerDeviceIdForRemoteInfo(remoteInfo->p2pMac, link.remoteBaseMac);
        InstSetPeerDeviceIdForRemoteInfo(remoteInfo->p2pIp, link.remoteIpv4);
    } else if (linkType == InnerLink::LinkType::HML) {
        remoteInfo->hmlFreq = link.freq;
        remoteInfo->hmlLinkState = (int32_t)state;
        InstSetPeerDeviceIdForRemoteInfo(remoteInfo->hmlMac, link.remoteBaseMac);
        InstSetPeerDeviceIdForRemoteInfo(remoteInfo->hmlIp, link.remoteIpv4);
    }
}
#endif

static InstantRemoteInfo *InstCreateAndAddRemoteInfo(SoftBusList *remoteChannelInfoList, bool matched)
{
    if (matched) {
        return NULL;
    }
    if (remoteChannelInfoList->cnt >= INST_MAX_REMOTE_NUM) {
        return NULL;
    }
    InstantRemoteInfo *rInfo = static_cast<InstantRemoteInfo *>(SoftBusCalloc(sizeof(InstantRemoteInfo)));
    if (rInfo == NULL) {
        COMM_LOGE(COMM_DFX, "malloc remote channel info fail");
        return NULL;
    }
    ListInit(&rInfo->node);
    ListInit(&rInfo->channels);
    ListAdd(&remoteChannelInfoList->list, &rInfo->node);
    remoteChannelInfoList->cnt++;
    return rInfo;
}

#ifdef DSOFTBUS_FEATURE_CONN_PV1
static void InstAddRemoteInfoByLinkManager(SoftBusList *remoteChannelInfoList)
{
    std::vector<InnerLinkBasicInfo> links;
    LinkManager::GetInstance().GetAllLinksBasicInfo(links);
    for (const auto &link : links) {
        std::string remoteUuid = link.remoteDeviceId;
        if (remoteUuid.empty()) {
            continue;
        }
        InstantRemoteInfo *rInfo = NULL;
        bool matched = false;
        LIST_FOR_EACH_ENTRY(rInfo, &remoteChannelInfoList->list, InstantRemoteInfo, node) {
            if (InstantIsParaMatch(rInfo->uuid, remoteUuid)) {
                matched = true;
                InstUpdateRemoteInfoByInnerLink(rInfo, link, remoteUuid);
                break;
            }
        }
        rInfo = InstCreateAndAddRemoteInfo(remoteChannelInfoList, matched);
        if (rInfo == NULL) {
            continue;
        }
        InstUpdateRemoteInfoByInnerLink(rInfo, link, remoteUuid);
    }
    links.clear();
}
#endif

static int32_t InstGetIpFromLinkTypeOrConnectType(const InstantRemoteInfo *remoteInfo, int32_t linkType,
    int32_t connectType)
{
    if (remoteInfo == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return UNKNOWN_IP;
    }
    if (linkType == LANE_WLAN_2P4G || linkType == LANE_WLAN_5G || connectType == CONNECT_TCP) {
        return WLAN_IP;
    }
    if (linkType == LANE_P2P || linkType == LANE_P2P_REUSE || connectType == CONNECT_P2P ||
        connectType == CONNECT_P2P_REUSE) {
        return P2P_IP;
    }
    if (linkType == LANE_HML || connectType == CONNECT_HML || connectType == CONNECT_TRIGGER_HML) {
        return HML_IP;
    }
    return UNKNOWN_IP;
}

static bool InstIsMatchSessionConn(const InstantRemoteInfo *rInfo, const SessionConn *conn)
{
    if (rInfo == NULL || conn == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return false;
    }
    if (InstantIsParaMatch(rInfo->uuid, std::string(conn->appInfo.peerData.deviceId))) {
        return true;
    }
    int32_t type = InstGetIpFromLinkTypeOrConnectType(rInfo, conn->appInfo.linkType, conn->appInfo.connectType);
    switch (type) {
        case HML_IP:
            return InstantIsParaMatch(rInfo->hmlIp, conn->appInfo.peerData.addr);
        case P2P_IP:
            return InstantIsParaMatch(rInfo->p2pIp, conn->appInfo.peerData.addr);
        case WLAN_IP:
            return InstantIsParaMatch(rInfo->wlanIp, conn->appInfo.peerData.addr);
        default:
            return false;
    }
}

static std::string GetUdidByTcpChannelInfo(const TcpChannelInfo *conn)
{
    if (conn->channelType == CHANNEL_TYPE_TCP_DIRECT || conn->channelType == CHANNEL_TYPE_PROXY ||
        conn->channelType == CHANNEL_TYPE_UDP) {
        char peerUdid[DEVICE_ID_SIZE_MAX] = { 0 };
        GetRemoteUdidWithNetworkId(conn->peerDeviceId, peerUdid, sizeof(peerUdid));
        return std::string(peerUdid);
    } else if (conn->channelType == CHANNEL_TYPE_AUTH) {
        return std::string(conn->peerDeviceId);
    }
    return "";
}

static bool InstIsMatchTcpChannel(const InstantRemoteInfo *rInfo, const TcpChannelInfo *conn)
{
    if (rInfo == nullptr || conn == nullptr) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return false;
    }
    if (InstantIsParaMatch(rInfo->uuid, GetUdidByTcpChannelInfo(conn))) {
        return true;
    }
    int32_t type = InstGetIpFromLinkTypeOrConnectType(rInfo, conn->linkType, conn->connectType);
    switch (type) {
        case HML_IP:
            return InstantIsParaMatch(rInfo->hmlIp, conn->peerIp);
        case P2P_IP:
            return InstantIsParaMatch(rInfo->p2pIp, conn->peerIp);
        case WLAN_IP:
            return InstantIsParaMatch(rInfo->wlanIp, conn->peerIp);
        default:
            return false;
    }
}

static void InstSetIpForRemoteInfo(InstantRemoteInfo *remoteInfo, const AppInfo *appInfo)
{
    if (remoteInfo == NULL || appInfo == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    int32_t type = InstGetIpFromLinkTypeOrConnectType(remoteInfo, appInfo->linkType, appInfo->connectType);
    switch (type) {
        case HML_IP:
            remoteInfo->hmlIp = appInfo->peerData.addr;
            break;
        case P2P_IP:
            remoteInfo->p2pIp = appInfo->peerData.addr;
            break;
        case WLAN_IP:
            remoteInfo->wlanIp = appInfo->peerData.addr;
            break;
        default:
            break;
    }
}

static void InstSetUdidForRemoteInfoByUuid(InstantRemoteInfo *remoteInfo)
{
    if (remoteInfo == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    NodeInfo nodeInfo = { { 0 } };
    if (LnnGetRemoteNodeInfoById(remoteInfo->uuid.c_str(), CATEGORY_UUID, &nodeInfo) == SOFTBUS_OK) {
        (void)InstSetPeerDeviceIdForRemoteInfo(remoteInfo->udid, nodeInfo.deviceInfo.deviceUdid);
    }
}

static void InstSetUuidForRemoteInfoByUdid(InstantRemoteInfo *remoteInfo)
{
    if (remoteInfo == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    NodeInfo nodeInfo = { { 0 } };
    if (LnnGetRemoteNodeInfoById(remoteInfo->udid.c_str(), CATEGORY_UDID, &nodeInfo) == SOFTBUS_OK) {
        (void)InstSetPeerDeviceIdForRemoteInfo(remoteInfo->uuid, nodeInfo.uuid);
    }
}

static void UpdateRemoteInfoBySessionConn(InstantRemoteInfo *remoteInfo, const SessionConn *conn)
{
    if (remoteInfo == NULL || conn == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    InstSetIpForRemoteInfo(remoteInfo, &conn->appInfo);
    if (InstSetPeerDeviceIdForRemoteInfo(remoteInfo->uuid, conn->appInfo.peerData.deviceId) == SOFTBUS_OK &&
        remoteInfo->udid.empty()) {
        InstSetUdidForRemoteInfoByUuid(remoteInfo);
    }
}

static void UpdateRemoteInfoByTcpChannelInfo(InstantRemoteInfo *remoteInfo, const TcpChannelInfo *conn)
{
    if (remoteInfo == nullptr) {
        COMM_LOGE(COMM_DFX, "param remote info is null");
        return;
    }
    if (conn == nullptr) {
        COMM_LOGE(COMM_DFX, "param conn is null");
        return;
    }
    int32_t type = InstGetIpFromLinkTypeOrConnectType(remoteInfo, conn->linkType, conn->connectType);
    switch (type) {
        case HML_IP:
            remoteInfo->hmlIp = std::string(conn->peerIp);
            break;
        case P2P_IP:
            remoteInfo->p2pIp = std::string(conn->peerIp);
            break;
        case WLAN_IP:
            remoteInfo->wlanIp = std::string(conn->peerIp);
            break;
        default:
            break;
    }
    if (remoteInfo->udid.empty()) {
        remoteInfo->udid = GetUdidByTcpChannelInfo(conn);
    }
}

static InstantChannelInfo *InstCreateAndAddChannelInfo(InstantRemoteInfo *remoteInfo)
{
    if (remoteInfo == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return NULL;
    }
    if (remoteInfo->channelNum >= INST_MAX_CHANNEL_NUM_EACH) {
        return NULL;
    }
    InstantChannelInfo *channelInfo = static_cast<InstantChannelInfo *>(SoftBusCalloc(sizeof(InstantChannelInfo)));
    if (channelInfo == NULL) {
        COMM_LOGE(COMM_DFX, "channel info Calloc fail");
        return NULL;
    }
    ListInit(&channelInfo->node);
    ListAdd(&remoteInfo->channels, &channelInfo->node);
    remoteInfo->channelNum++;
    return channelInfo;
}

static void InstAddSessionConnToRemoteInfo(InstantRemoteInfo *remoteInfo, SessionConn *conn)
{
    if (remoteInfo == NULL || conn == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    InstantChannelInfo *channelInfo = InstCreateAndAddChannelInfo(remoteInfo);
    if (channelInfo == NULL) {
        return;
    }
    channelInfo->serverSide = conn->serverSide;
    channelInfo->laneLinkType = conn->appInfo.linkType;
    channelInfo->connectType = conn->appInfo.connectType;
    channelInfo->startTime = GetSoftbusRecordTimeMillis() - conn->appInfo.timeStart;
    channelInfo->status = static_cast<int32_t>(conn->status);
    channelInfo->channelType = CHANNEL_TYPE_TCP_DIRECT;
    channelInfo->socketName = conn->appInfo.myData.sessionName;
    UpdateRemoteInfoBySessionConn(remoteInfo, conn);
}

static void InstAddTcpChannelInfoToRemoteInfo(InstantRemoteInfo *remoteInfo, TcpChannelInfo *conn)
{
    if (remoteInfo == nullptr || conn == nullptr) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    InstantChannelInfo *channelInfo = InstCreateAndAddChannelInfo(remoteInfo);
    if (channelInfo == nullptr) {
        return;
    }
    channelInfo->serverSide = conn->isServer;
    channelInfo->laneLinkType = conn->linkType;
    channelInfo->connectType = conn->connectType;
    channelInfo->startTime = GetSoftbusRecordTimeMillis() - conn->timeStart;
    channelInfo->channelType = CHANNEL_TYPE_TCP_DIRECT;
    channelInfo->socketName = conn->peerSessionName;
    UpdateRemoteInfoByTcpChannelInfo(remoteInfo, conn);
}

static void InstUpdateRemoteInfoBySessionConn(SoftBusList *remoteChannelInfoList)
{
    SessionConn *item = NULL;
    SoftBusList *sessionList = GetSessionConnList();
    if (sessionList == NULL || GetSessionConnLock() != SOFTBUS_OK) {
        return;
    }
    LIST_FOR_EACH_ENTRY(item, &sessionList->list, SessionConn, node) {
        InstantRemoteInfo *rInfo = NULL;
        bool matched = false;
        LIST_FOR_EACH_ENTRY(rInfo, &remoteChannelInfoList->list, InstantRemoteInfo, node) {
            if (InstIsMatchSessionConn(rInfo, item)) {
                matched = true;
                InstAddSessionConnToRemoteInfo(rInfo, item);
                break;
            }
        }
        rInfo = InstCreateAndAddRemoteInfo(remoteChannelInfoList, matched);
        if (rInfo == NULL) {
            continue;
        }
        InstAddSessionConnToRemoteInfo(rInfo, item);
    }
    ReleaseSessionConnLock();
}

static void InstUpdateRemoteInfoByTcpChannel(SoftBusList *remoteChannelInfoList)
{
    TcpChannelInfo *item = NULL;
    SoftBusList *tcpChannelInfoList = GetTcpChannelInfoList();
    if (tcpChannelInfoList == NULL || GetTcpChannelInfoLock() != SOFTBUS_OK) {
        return;
    }
    LIST_FOR_EACH_ENTRY(item, &tcpChannelInfoList->list, TcpChannelInfo, node) {
        InstantRemoteInfo *rInfo = NULL;
        bool matched = false;
        LIST_FOR_EACH_ENTRY(rInfo, &remoteChannelInfoList->list, InstantRemoteInfo, node) {
            if (InstIsMatchTcpChannel(rInfo, item)) {
                matched = true;
                InstAddTcpChannelInfoToRemoteInfo(rInfo, item);
                break;
            }
        }
        rInfo = InstCreateAndAddRemoteInfo(remoteChannelInfoList, matched);
        if (rInfo == NULL) {
            continue;
        }
        InstAddTcpChannelInfoToRemoteInfo(rInfo, item);
    }
    ReleaseTcpChannelInfoLock();
}

static bool InstIsMatchUdpChannel(const InstantRemoteInfo *rInfo, const UdpChannelInfo *info)
{
    if (rInfo == NULL || info == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return false;
    }
    if (InstantIsParaMatch(rInfo->uuid, info->info.peerData.deviceId)) {
        return true;
    }
    int32_t type = InstGetIpFromLinkTypeOrConnectType(rInfo, info->info.linkType, info->info.connectType);
    switch (type) {
        case HML_IP:
            return InstantIsParaMatch(rInfo->hmlIp, info->info.peerData.addr);
        case P2P_IP:
            return InstantIsParaMatch(rInfo->p2pIp, info->info.peerData.addr);
        case WLAN_IP:
            return InstantIsParaMatch(rInfo->wlanIp, info->info.peerData.addr);
        default:
            return false;
    }
}

static void UpdateRemoteInfoByUdpChannel(InstantRemoteInfo *remoteInfo, const UdpChannelInfo *info)
{
    if (remoteInfo == NULL || info == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    InstSetIpForRemoteInfo(remoteInfo, &info->info);
    if (InstSetPeerDeviceIdForRemoteInfo(remoteInfo->uuid, info->info.peerData.deviceId) == SOFTBUS_OK &&
        remoteInfo->udid.empty()) {
        InstSetUdidForRemoteInfoByUuid(remoteInfo);
    }
}

static void InstAddUdpChannelToRemoteInfo(InstantRemoteInfo *remoteInfo, const UdpChannelInfo *info)
{
    if (remoteInfo == NULL || info == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    InstantChannelInfo *channelInfo = InstCreateAndAddChannelInfo(remoteInfo);
    if (channelInfo == NULL) {
        return;
    }
    channelInfo->serverSide = !info->info.isClient;
    channelInfo->laneLinkType = info->info.linkType;
    channelInfo->connectType = info->info.connectType;
    channelInfo->startTime = GetSoftbusRecordTimeMillis() - info->info.timeStart;
    channelInfo->status = info->status;
    channelInfo->channelType = CHANNEL_TYPE_UDP;
    channelInfo->socketName = info->info.myData.sessionName;
    UpdateRemoteInfoByUdpChannel(remoteInfo, info);
}

static void InstUpdateRemoteInfoByUdpChannel(SoftBusList *remoteChannelInfoList)
{
    UdpChannelInfo *item = NULL;
    SoftBusList *sessionList = GetUdpChannelMgrHead();
    if (sessionList == NULL || GetUdpChannelLock() != SOFTBUS_OK) {
        return;
    }
    LIST_FOR_EACH_ENTRY(item, &sessionList->list, UdpChannelInfo, node) {
        InstantRemoteInfo *rInfo = NULL;
        bool matched = false;
        LIST_FOR_EACH_ENTRY(rInfo, &remoteChannelInfoList->list, InstantRemoteInfo, node) {
            if (InstIsMatchUdpChannel(rInfo, item)) {
                matched = true;
                InstAddUdpChannelToRemoteInfo(rInfo, item);
                break;
            }
        }
        rInfo = InstCreateAndAddRemoteInfo(remoteChannelInfoList, matched);
        if (rInfo == NULL) {
            continue;
        }
        InstAddUdpChannelToRemoteInfo(rInfo, item);
    }
    ReleaseUdpChannelLock();
}

static bool InstIsMatchProxyChannel(const InstantRemoteInfo *rInfo, const ProxyChannelInfo *conn)
{
    if (rInfo == NULL || conn == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return false;
    }

    std::string deviceId = conn->appInfo.appType == APP_TYPE_AUTH ? rInfo->udid : rInfo->uuid;
    return InstantIsParaMatch(deviceId, conn->appInfo.peerData.deviceId);
}

static void UpdateRemoteInfoByProxyChannel(InstantRemoteInfo *remoteInfo, const ProxyChannelInfo *info)
{
    if (remoteInfo == NULL || info == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    if (info->appInfo.appType == APP_TYPE_AUTH) {
        if (InstSetPeerDeviceIdForRemoteInfo(remoteInfo->udid, info->appInfo.peerData.deviceId) == SOFTBUS_OK &&
            remoteInfo->uuid.empty()) {
            InstSetUuidForRemoteInfoByUdid(remoteInfo);
        }
    } else {
        if (InstSetPeerDeviceIdForRemoteInfo(remoteInfo->uuid, info->appInfo.peerData.deviceId) == SOFTBUS_OK &&
            remoteInfo->udid.empty()) {
            InstSetUdidForRemoteInfoByUuid(remoteInfo);
        }
    }
}

static void InstSetDeviceIdByConnId(InstantRemoteInfo *remoteInfo, InstantChannelInfo *channelInfo, uint32_t connId)
{
    if (remoteInfo == NULL || channelInfo == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    ConnectionInfo info;
    (void)memset_s(&info, sizeof(ConnectionInfo), 0, sizeof(ConnectionInfo));
    if (ConnGetConnectionInfo(connId, &info) != SOFTBUS_OK) {
        return;
    }
    if (info.type < CONNECT_TCP || info.type >= CONNECT_TYPE_MAX) {
        return;
    }
    channelInfo->connectType = info.type;
    if (info.type == CONNECT_TCP) {
        (void)InstSetPeerDeviceIdForRemoteInfo(remoteInfo->wlanIp, std::string(info.socketInfo.addr));
    } else if (info.type == CONNECT_BR) {
        (void)InstSetPeerDeviceIdForRemoteInfo(remoteInfo->brMac, std::string(info.brInfo.brMac));
    } else if (info.type == CONNECT_BLE || info.type == CONNECT_BLE_DIRECT) {
        (void)InstSetPeerDeviceIdForRemoteInfo(remoteInfo->bleMac, std::string(info.bleInfo.bleMac));
    }
}

static void SetParamByProxyChannelInfo(InstantRemoteInfo *remoteInfo, InstantChannelInfo *channelInfo,
    const ProxyChannelInfo *info)
{
    if (remoteInfo == NULL || channelInfo == NULL || info == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    channelInfo->serverSide = info->isServer;
    channelInfo->laneLinkType = info->appInfo.linkType;
    channelInfo->connectType = info->appInfo.connectType;
    channelInfo->startTime = GetSoftbusRecordTimeMillis() - info->appInfo.timeStart;
    channelInfo->status = info->status;
    channelInfo->appType = info->appInfo.appType;
    channelInfo->channelType = CHANNEL_TYPE_PROXY;
    channelInfo->socketName = info->appInfo.myData.sessionName;
    UpdateRemoteInfoByProxyChannel(remoteInfo, info);
    InstSetDeviceIdByConnId(remoteInfo, channelInfo, info->connId);
}

static void InstAddProxyChannelToRemoteInfo(InstantRemoteInfo *remoteInfo, const ProxyChannelInfo *info)
{
    if (remoteInfo == NULL || info == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    InstantChannelInfo *channelInfo = InstCreateAndAddChannelInfo(remoteInfo);
    if (channelInfo == NULL) {
        return;
    }
    SetParamByProxyChannelInfo(remoteInfo, channelInfo, info);
}

static void InstUpdateRemoteInfoByProxyChannel(SoftBusList *remoteChannelInfoList)
{
    ProxyChannelInfo *item = NULL;
    SoftBusList *sessionList = GetProxyChannelMgrHead();
    if (sessionList == NULL || GetProxyChannelLock() != SOFTBUS_OK) {
        return;
    }
    LIST_FOR_EACH_ENTRY(item, &sessionList->list, ProxyChannelInfo, node) {
        InstantRemoteInfo *rInfo = NULL;
        bool matched = false;
        LIST_FOR_EACH_ENTRY(rInfo, &remoteChannelInfoList->list, InstantRemoteInfo, node) {
            if (InstIsMatchProxyChannel(rInfo, item)) {
                matched = true;
                InstAddProxyChannelToRemoteInfo(rInfo, item);
                break;
            }
        }
        rInfo = InstCreateAndAddRemoteInfo(remoteChannelInfoList, matched);
        if (rInfo == NULL) {
            continue;
        }
        InstAddProxyChannelToRemoteInfo(rInfo, item);
    }
    ReleaseProxyChannelLock();
}

static bool InstIsMatchAuthChannel(const InstantRemoteInfo *rInfo, const AuthChannelInfo *info)
{
    if (rInfo == NULL || info == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return false;
    }
    return InstantIsParaMatch(rInfo->udid, info->appInfo.peerData.deviceId) ||
        InstantIsParaMatch(rInfo->wlanIp, info->connOpt.socketOption.addr);
}

static void InstUpdateRemoteInfoByAuthChannel(InstantRemoteInfo *remoteInfo, const AuthChannelInfo *info)
{
    if (remoteInfo == NULL || info == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    InstSetPeerDeviceIdForRemoteInfo(remoteInfo->udid, info->appInfo.peerData.deviceId);
    InstSetPeerDeviceIdForRemoteInfo(remoteInfo->wlanIp, info->connOpt.socketOption.addr);
}

static void InstSetParamByAuthChannelInfo(InstantRemoteInfo *remoteInfo, InstantChannelInfo *channelInfo,
    const AuthChannelInfo *info)
{
    if (remoteInfo == NULL || channelInfo == NULL || info == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    channelInfo->serverSide = !info->isClient;
    channelInfo->connectType = CONNECT_TCP;
    channelInfo->startTime = GetSoftbusRecordTimeMillis() - info->appInfo.timeStart;
    channelInfo->channelType = info->appInfo.channelType;
    channelInfo->socketName = info->appInfo.myData.sessionName;
    InstUpdateRemoteInfoByAuthChannel(remoteInfo, info);
}

static void InstAddAuthChannelToRemoteInfo(InstantRemoteInfo *remoteInfo, const AuthChannelInfo *info)
{
    if (remoteInfo == NULL || info == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    InstantChannelInfo *channelInfo = InstCreateAndAddChannelInfo(remoteInfo);
    if (channelInfo == NULL) {
        return;
    }
    InstSetParamByAuthChannelInfo(remoteInfo, channelInfo, info);
}

static void InstUpdateByAuthChannelList(SoftBusList *remoteChannelInfoList)
{
    AuthChannelInfo *item = NULL;
    SoftBusList *sessionList = GetAuthChannelListHead();
    if (sessionList == NULL || GetAuthChannelLock() != SOFTBUS_OK) {
        return;
    }
    LIST_FOR_EACH_ENTRY(item, &sessionList->list, AuthChannelInfo, node) {
        InstantRemoteInfo *rInfo = NULL;
        bool matched = false;
        LIST_FOR_EACH_ENTRY(rInfo, &remoteChannelInfoList->list, InstantRemoteInfo, node) {
            if (InstIsMatchAuthChannel(rInfo, item)) {
                matched = true;
                InstAddAuthChannelToRemoteInfo(rInfo, item);
                break;
            }
        }
        rInfo = InstCreateAndAddRemoteInfo(remoteChannelInfoList, matched);
        if (rInfo == NULL) {
            continue;
        }
        InstAddAuthChannelToRemoteInfo(rInfo, item);
    }
    ReleaseAuthChannelLock();
}

static void InstReleaseRemoteChannelInfoList(SoftBusList *remoteChannelInfoList)
{
    InstantRemoteInfo *item = NULL;
    InstantRemoteInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &remoteChannelInfoList->list, InstantRemoteInfo, node) {
        if (!IsListEmpty(&item->channels)) {
            InstantChannelInfo *channelItem = NULL;
            InstantChannelInfo *channelNext = NULL;
            LIST_FOR_EACH_ENTRY_SAFE(channelItem, channelNext, &item->channels, InstantChannelInfo, node) {
                ListDelete(&channelItem->node);
                SoftBusFree(channelItem);
            }
        }
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    remoteChannelInfoList->cnt = 0;
    DestroySoftBusList(remoteChannelInfoList);
}

static void InstPackRemoteBasicInfo(cJSON *upperJson, InstantRemoteInfo *remoteInfo)
{
    if (upperJson == NULL || remoteInfo == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    cJSON *json = cJSON_CreateObject();
    COMM_CHECK_AND_RETURN_LOGE(json != NULL, COMM_DFX, "cJSON_CreateObject fail");

    (void)AddNumber64ToJsonObject(json, "deviceType", remoteInfo->deviceType);
    InstPackAndAnonymizeStringIfNotNull(json, remoteInfo->udid, "udid", true);
    InstPackAndAnonymizeStringIfNotNull(json, remoteInfo->hmlMac, "hmlMac", false);
    InstPackAndAnonymizeStringIfNotNull(json, remoteInfo->p2pMac, "p2pMac", false);
    InstPackAndAnonymizeStringIfNotNull(json, remoteInfo->bleMac, "bleMac", false);
    InstPackAndAnonymizeStringIfNotNull(json, remoteInfo->brMac, "brMac", false);
    (void)AddNumberToJsonObject(json, "channelNum", remoteInfo->channelNum);
    (void)AddNumberToJsonObject(json, "p2pRole", remoteInfo->p2pRole);
    (void)AddNumberToJsonObject(json, "p2pFreq", remoteInfo->p2pFreq);
    (void)AddNumberToJsonObject(json, "hmlFreq", remoteInfo->hmlFreq);
    (void)AddNumberToJsonObject(json, "staFreq", remoteInfo->staFreq);
    (void)AddNumberToJsonObject(json, "p2pLinkState", remoteInfo->p2pLinkState);
    (void)AddNumberToJsonObject(json, "hmlLinkState", remoteInfo->hmlLinkState);
    (void)AddNumber64ToJsonObject(json, "discoveryType", remoteInfo->discoveryType);
    (void)AddNumber64ToJsonObject(json, "netCapability", remoteInfo->netCapability);

    char *str = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    COMM_CHECK_AND_RETURN_LOGE(str != NULL, COMM_DFX, "cJSON_PrintUnformatted fail");
    cJSON_AddItemToArray(upperJson, cJSON_CreateString(str));
    cJSON_free(str);
}

static void InstPackChannelInfo(cJSON *upperJson, InstantChannelInfo *channelInfo)
{
    if (upperJson == NULL || channelInfo == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    cJSON *channelJson = cJSON_CreateObject();
    COMM_CHECK_AND_RETURN_LOGE(channelJson != NULL, COMM_DFX, "cJSON_CreateObject fail");

    (void)AddStringToJsonObject(channelJson, "socketName", channelInfo->socketName.c_str());
    (void)AddNumberToJsonObject(channelJson, "channelType", channelInfo->channelType);
    (void)AddNumberToJsonObject(channelJson, "appType", channelInfo->appType);
    (void)AddNumberToJsonObject(channelJson, "laneLinkType", channelInfo->laneLinkType);
    (void)AddNumberToJsonObject(channelJson, "connectType", channelInfo->connectType);
    (void)AddNumberToJsonObject(channelJson, "status", channelInfo->status);
    (void)AddBoolToJsonObject(channelJson, "serverSide", channelInfo->serverSide);
    (void)AddNumberToJsonObject(channelJson, "keepTime", channelInfo->startTime);

    char *str = cJSON_PrintUnformatted(channelJson);
    cJSON_Delete(channelJson);
    COMM_CHECK_AND_RETURN_LOGE(str != NULL, COMM_DFX, "cJSON_PrintUnformatted fail");
    cJSON_AddItemToArray(upperJson, cJSON_CreateString(str));
    cJSON_free(str);
}

static void InstPackRemoteInfo(cJSON *json, SoftBusList *remoteChannelInfoList)
{
    if (json == NULL || remoteChannelInfoList == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    InstantRemoteInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &remoteChannelInfoList->list, InstantRemoteInfo, node) {
        cJSON *deviceJson = cJSON_AddArrayToObject(json, "remoteInfo");
        if (deviceJson == NULL) {
            continue;
        }
        InstPackRemoteBasicInfo(deviceJson, item);
        if (!IsListEmpty(&item->channels)) {
            InstantChannelInfo *channelItem = NULL;
            LIST_FOR_EACH_ENTRY(channelItem, &item->channels, InstantChannelInfo, node) {
                InstPackChannelInfo(deviceJson, channelItem);
            }
        }
    }
}

static void InstUpdateRemoteInfoByLnn(InstantRemoteInfo *remoteInfo, NodeBasicInfo *info)
{
    if (remoteInfo == NULL || info == NULL) {
        return;
    }
    NodeInfo nodeInfo = { { 0 } };
    if (LnnGetRemoteNodeInfoById(info->networkId, CATEGORY_NETWORK_ID, &nodeInfo) == SOFTBUS_OK) {
        remoteInfo->udid = std::string(nodeInfo.deviceInfo.deviceUdid);
        remoteInfo->uuid = std::string(nodeInfo.uuid);
        remoteInfo->wlanIp = std::string(nodeInfo.connectInfo.deviceIp);
        remoteInfo->bleMac = std::string(nodeInfo.connectInfo.bleMacAddr);
        remoteInfo->brMac = std::string(nodeInfo.connectInfo.macAddr);
        remoteInfo->p2pRole = nodeInfo.p2pInfo.p2pRole;
        remoteInfo->p2pIp = nodeInfo.p2pInfo.p2pIp;
        remoteInfo->staFreq = nodeInfo.p2pInfo.staFrequency;
        remoteInfo->discoveryType = nodeInfo.discoveryType;
        remoteInfo->netCapability = nodeInfo.netCapacity;
        remoteInfo->deviceType = nodeInfo.deviceInfo.deviceTypeId;
    }
}

static int32_t InstAddRemoteInfoByLnn(SoftBusList *remoteChannelInfoList)
{
    int32_t infoNum;
    NodeBasicInfo *info = NULL;
    int32_t ret = LnnGetAllOnlineNodeInfo(&info, &infoNum);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (info == NULL || infoNum == 0) {
        return SOFTBUS_OK;
    }
    for (int32_t i = 0; i < infoNum; ++i) {
        InstantRemoteInfo *rInfo = InstCreateAndAddRemoteInfo(remoteChannelInfoList, false);
        if (rInfo == NULL) {
            continue;
        }
        InstUpdateRemoteInfoByLnn(rInfo, info + i);
    }
    SoftBusFree(info);
    return SOFTBUS_OK;
}

static void InstGetRemoteInfo(cJSON *json)
{
    if (json == NULL) {
        return;
    }
    SoftBusList *remoteChannelInfoList = CreateSoftBusList();
    if (remoteChannelInfoList == NULL) {
        COMM_LOGE(COMM_DFX, "remoteChannelInfoList init fail");
        return;
    }
    int32_t ret = InstAddRemoteInfoByLnn(remoteChannelInfoList);
    if (ret != SOFTBUS_OK) {
        (void)AddNumberToJsonObject(json, "Bus_center_fault", ret);
    }
    #ifdef DSOFTBUS_FEATURE_CONN_PV1
    InstAddRemoteInfoByLinkManager(remoteChannelInfoList);
    #endif
    InstUpdateRemoteInfoBySessionConn(remoteChannelInfoList);
    InstUpdateRemoteInfoByTcpChannel(remoteChannelInfoList);
    InstUpdateRemoteInfoByUdpChannel(remoteChannelInfoList);
    InstUpdateRemoteInfoByProxyChannel(remoteChannelInfoList);
    InstUpdateByAuthChannelList(remoteChannelInfoList);
    InstPackRemoteInfo(json, remoteChannelInfoList);

    InstReleaseRemoteChannelInfoList(remoteChannelInfoList);
}

static int32_t InstGetAllInfo(int32_t radarId, int32_t errorCode)
{
    cJSON *json = cJSON_CreateObject();
    COMM_CHECK_AND_RETURN_RET_LOGE(json != NULL, SOFTBUS_CREATE_JSON_ERR, COMM_DFX, "cJSON_CreateObject fail");
    (void)AddNumberToJsonObject(json, "radarId", radarId);
    (void)AddNumberToJsonObject(json, "errorCode", errorCode);
    cJSON *remoteDevicesJson = cJSON_AddArrayToObject(json, "remoteDevices");
    if (remoteDevicesJson != NULL) {
        InstGetRemoteInfo(remoteDevicesJson);
    }

    cJSON *wifiJson = cJSON_CreateObject();
    Communication::Softbus::WifiStatistic::GetInstance().GetWifiStatisticInfo(wifiJson);
    (void)cJSON_AddItemToObject(json, "WifiInfo", wifiJson);

    cJSON *btJson = cJSON_CreateObject();
    Communication::Softbus::BtStatistic::GetInstance().GetBtStatisticInfo(btJson);
    (void)cJSON_AddItemToObject(json, "BtInfo", btJson);

    char *info = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    COMM_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_PARSE_JSON_ERR, COMM_DFX, "cJSON_PrintUnformatted fail");

    TransEventExtra extra = {
        .result = EVENT_STAGE_RESULT_OK,
        .trafficStats = info
    };
    TRANS_EVENT(EVENT_SCENE_TRANS_CHANNEL_INSTANT, EVENT_STAGE_TRANS_COMMON_ONE, extra);
    cJSON_free(info);
    return SOFTBUS_OK;
}

static inline SoftBusHandler *CreateHandler(SoftBusLooper *looper, InstAsyncCallbackFunc callback)
{
    static char handlerName[] = "Instant_statistics";
    SoftBusHandler *handler = static_cast<SoftBusHandler *>(SoftBusMalloc(sizeof(SoftBusHandler)));
    if (handler == NULL) {
        COMM_LOGI(COMM_DFX, "create handler failed");
        return NULL;
    }
    handler->looper = looper;
    handler->name = handlerName;
    handler->HandleMessage = callback;
    return handler;
}

static void FreeMessageFunc(SoftBusMessage *msg)
{
    if (msg == NULL) {
        return;
    }
    if (msg->handler != NULL) {
        SoftBusFree(msg->handler);
    }
    SoftBusFree(msg);
}

static SoftBusMessage *CreateMessage(SoftBusLooper *looper, InstAsyncCallbackFunc callback)
{
    SoftBusMessage *msg = static_cast<SoftBusMessage *>(SoftBusMalloc(sizeof(SoftBusMessage)));
    if (msg == NULL) {
        COMM_LOGI(COMM_DFX, "malloc softbus message failed");
        return NULL;
    }
    SoftBusHandler *handler = CreateHandler(looper, callback);
    msg->what = INST_DELAY_REGISTER;
    msg->obj = NULL;
    msg->handler = handler;
    msg->FreeMessage = FreeMessageFunc;
    return msg;
}

static int32_t InstantRegisterMsgDelay(SoftBusLooper *looper, InstAsyncCallbackFunc callback, uint64_t delayMillis)
{
    if ((looper == NULL) || (callback == NULL)) {
        return SOFTBUS_INVALID_PARAM;
    }

    SoftBusMessage *message = CreateMessage(looper, callback);
    if (message == NULL) {
        return SOFTBUS_MEM_ERR;
    }

    looper->PostMessageDelay(looper, message, delayMillis);
    return SOFTBUS_OK;
}

void InstRegister(SoftBusMessage *msg)
{
    if (msg == NULL) {
        (void)InstantRegisterMsgDelay(GetLooper(LOOP_TYPE_DEFAULT), InstRegister, INST_MINUTE_TIME);
    } else {
        struct RadarCallback callback = { 0 };
        callback.resourceNotificationCallback = InstGetAllInfo;
        (void)OHOS::CommunicationRadar::CommunicationRadar::GetInstance().RegisterRadarCallback(callback);
    }
}
