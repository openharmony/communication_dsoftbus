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

#include "wifi_direct_mock.h"
#include <thread>
#include "conn_log.h"
// implement dependencies and redirect request to mock object here
int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->AuthGetDeviceUuid(authId, uuid, size);
}

int32_t AuthPostTransData(AuthHandle authHandle, const AuthTransData *dataInfo)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->AuthPostTransData(authHandle, dataInfo);
}

int32_t RegAuthTransListener(int32_t module, const AuthTransListener *listener)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->RegAuthTransListener(module, listener);
}

WifiErrorCode Hid2dGetChannelListFor5G(int *chanList, int len)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->Hid2dGetChannelListFor5G(chanList, len);
}

WifiErrorCode GetP2pEnableStatus(P2pState* state)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->GetP2pEnableStatus(state);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnGetLocalStrInfo(key, info, len);
}

int32_t LnnSetLocalStrInfo(InfoKey key, const char *info)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnSetLocalStrInfo(key, info);
}

int32_t LnnSetLocalNumInfo(InfoKey key, int32_t info)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnSetLocalNumInfo(key, info);
}

int32_t LnnSyncP2pInfo()
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnSyncP2pInfo();
}

uint64_t LnnGetFeatureCapabilty()
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnGetFeatureCapabilty();
}

bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->IsFeatureSupport(feature, capaBit);
}

int32_t LnnGetRemoteStrInfo(const char *netWorkId, InfoKey key, char *info, uint32_t len)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnGetRemoteStrInfo(netWorkId, key, info, len);
}

int32_t LnnGetRemoteBoolInfo(const char *networkId, InfoKey key, bool *info)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnGetRemoteBoolInfo(networkId, key, info);
}

int32_t AuthStartListeningForWifiDirect(AuthLinkType type, const char *ip,
    int32_t port, ListenerModule *moduleId)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->AuthStartListeningForWifiDirect(type, ip, port, moduleId);
}

int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnGetNetworkIdByUuid(uuid, buf, len);
}

void AuthCloseConn(AuthHandle authHandle)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->AuthCloseConn(authHandle);
}

void AuthStopListeningForWifiDirect(AuthLinkType type, ListenerModule moduleId)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->AuthStopListeningForWifiDirect(type, moduleId);
}

int32_t AuthGetMetaType(int64_t authId, bool *isMetaAuth)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->AuthGetMetaType(authId, isMetaAuth);
}

const char *LnnConvertDLidToUdid(const char *id, IdCategory type)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnConvertDLidToUdid(id, type);
}

uint32_t AuthGenRequestId(void)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->AuthGenRequestId();
}

int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId,
    const AuthConnCallback *callback, bool isMeta)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->AuthOpenConn(info, requestId, callback, isMeta);
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnGetLocalNumInfo(key, info);
}

int32_t LnnGetRemoteNumInfo(const char *netWorkId, InfoKey key, int32_t *info)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnGetRemoteNumInfo(netWorkId, key, info);
}

WifiErrorCode GetLinkedInfo(WifiLinkedInfo *info)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->GetLinkedInfo(info);
}

WifiErrorCode Hid2dGetRecommendChannel(const RecommendChannelRequest *request, RecommendChannelResponse *response)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->Hid2dGetRecommendChannel(request, response);
}

WifiErrorCode Hid2dGetSelfWifiCfgInfo(SelfCfgType cfgType, char cfgData[CFG_DATA_MAX_BYTES], int* getDatValidLen)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->Hid2dGetSelfWifiCfgInfo(cfgType, cfgData, getDatValidLen);
}

int32_t SoftBusBase64Decode(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->SoftBusBase64Decode(dst, dlen, olen, src, slen);
}

WifiErrorCode Hid2dSetPeerWifiCfgInfo(PeerCfgType cfgType, char cfgData[CFG_DATA_MAX_BYTES], int setDataValidLen)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->Hid2dSetPeerWifiCfgInfo(cfgType,
        cfgData, setDataValidLen);
}

WifiErrorCode GetCurrentGroup(WifiP2pGroupInfo* groupInfo)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->GetCurrentGroup(groupInfo);
}

WifiErrorCode Hid2dRequestGcIp(const unsigned char gcMac[MAC_LEN], unsigned int ipAddr[IPV4_ARRAY_LEN])
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->Hid2dRequestGcIp(gcMac, ipAddr);
}

WifiErrorCode Hid2dConfigIPAddr(const char ifName[IF_NAME_LEN], const IpAddrInfo *ipInfo)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->Hid2dConfigIPAddr(ifName, ipInfo);
}

WifiErrorCode Hid2dCreateGroup(const int frequency, FreqType type)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->Hid2dCreateGroup(frequency, type);
}

WifiErrorCode Hid2dConnect(const Hid2dConnectConfig *config)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->Hid2dConnect(config);
}

WifiErrorCode Hid2dSharedlinkIncrease(void)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->Hid2dSharedlinkIncrease();
}

WifiErrorCode Hid2dSharedlinkDecrease(void)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->Hid2dSharedlinkDecrease();
}

WifiErrorCode RemoveGroup()
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->RemoveGroup();
}

WifiErrorCode Hid2dRemoveGcGroup(const char gcIfName[IF_NAME_LEN])
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->Hid2dRemoveGcGroup(gcIfName);
}

int32_t TransProxyPipelineRegisterListener(TransProxyPipelineMsgType type,
    const ITransProxyPipelineListener *listener)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->TransProxyPipelineRegisterListener(type, listener);
}

int32_t TransProxyPipelineGetUuidByChannelId(int32_t channelId, char *uuid, uint32_t uuidLen)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->TransProxyPipelineGetUuidByChannelId(channelId,
        uuid, uuidLen);
}

int32_t TransProxyPipelineSendMessage(
    int32_t channelId, const uint8_t *data, uint32_t dataLen, TransProxyPipelineMsgType type)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->TransProxyPipelineSendMessage(
        channelId, data, dataLen, type);
}

int Hid2dIsWideBandwidthSupported()
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->Hid2dIsWideBandwidthSupported();
}

WifiErrorCode RegisterP2pStateChangedCallback(const P2pStateChangedCallback callback)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::RegisterP2pStateChangedCallback(callback);
}

WifiErrorCode RegisterP2pConnectionChangedCallback(const P2pConnectionChangedCallback callback)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::RegisterP2pConnectionChangedCallback(callback);
}

namespace OHOS::SoftBus {
WifiDirectInterfaceMock::WifiDirectInterfaceMock()
{
    mock.store(this);
}

WifiDirectInterfaceMock::~WifiDirectInterfaceMock()
{
    mock.store(nullptr);
}

WifiErrorCode WifiDirectInterfaceMock::RegisterP2pConnectionChangedCallback(const P2pConnectionChangedCallback callback)
{
    connectionCallback_ = callback;
    return WIFI_SUCCESS;
}

WifiErrorCode WifiDirectInterfaceMock::RegisterP2pStateChangedCallback(const P2pStateChangedCallback callback)
{
    stateCallback_ = callback;
    return WIFI_SUCCESS;
}

WifiErrorCode WifiDirectInterfaceMock::CreateGroupSuccessAction(const int frequency, FreqType type)
{
    auto run = [] () {
        CONN_LOGI(CONN_WIFI_DIRECT, "1");
        WifiP2pLinkedInfo info;
        info.connectState = P2P_CONNECTED;
        connectionCallback_(info);
    };
    std::thread thread(run);
    thread.detach();
    return WIFI_SUCCESS;
}

WifiErrorCode WifiDirectInterfaceMock::CreateGroupFailureAction(const int frequency, FreqType type)
{
    auto run = [] () {
        CONN_LOGI(CONN_WIFI_DIRECT, "2");
        WifiP2pLinkedInfo info;
        info.connectState = P2P_DISCONNECTED;
        connectionCallback_(info);
    };
    std::thread thread(run);
    thread.detach();
    return WIFI_SUCCESS;
}

WifiErrorCode WifiDirectInterfaceMock::CreateGroupTimeOutAction(const int frequency, FreqType type)
{
    auto run = [] () {
        WifiP2pLinkedInfo info;
        info.connectState = P2P_DISCONNECTED;
        sleep(6);
        connectionCallback_(info);
    };
    std::thread thread(run);
    thread.detach();
    return WIFI_SUCCESS;
}

WifiErrorCode WifiDirectInterfaceMock::ConnectSuccessAction(const Hid2dConnectConfig *config)
{
    auto run = [] () {
        CONN_LOGI(CONN_WIFI_DIRECT, "4");
        WifiP2pLinkedInfo info;
        info.connectState = P2P_CONNECTED;
        connectionCallback_(info);
    };
    std::thread thread(run);
    thread.detach();
    return WIFI_SUCCESS;
}

WifiErrorCode WifiDirectInterfaceMock::ConnectFailureAction(const Hid2dConnectConfig *config)
{
    auto run = [] () {
        CONN_LOGI(CONN_WIFI_DIRECT, "5");
        WifiP2pLinkedInfo info;
        info.connectState = P2P_DISCONNECTED;
        connectionCallback_(info);
    };
    std::thread thread(run);
    thread.detach();
    return WIFI_SUCCESS;
}

WifiErrorCode WifiDirectInterfaceMock::ConnectTimeOutAction(const Hid2dConnectConfig *config)
{
    auto run = [] () {
        CONN_LOGI(CONN_WIFI_DIRECT, "6");
        WifiP2pLinkedInfo info;
        info.connectState = P2P_DISCONNECTED;
        sleep(6);
        connectionCallback_(info);
    };
    std::thread thread(run);
    thread.detach();
    return WIFI_SUCCESS;
}

WifiErrorCode WifiDirectInterfaceMock::DestroyGroupSuccessAction()
{
    auto run = [] () {
        CONN_LOGI(CONN_WIFI_DIRECT, "7");
        WifiP2pLinkedInfo info;
        info.connectState = P2P_DISCONNECTED;
        connectionCallback_(info);
    };
    std::thread thread(run);
    thread.detach();
    return WIFI_SUCCESS;
}

WifiErrorCode WifiDirectInterfaceMock::DestroyGroupFailureAction()
{
    auto run = [] () {
        CONN_LOGI(CONN_WIFI_DIRECT, "8");
        WifiP2pLinkedInfo info;
        info.connectState = P2P_CONNECTED;
        connectionCallback_(info);
    };
    std::thread thread(run);
    thread.detach();
    return WIFI_SUCCESS;
}

WifiErrorCode WifiDirectInterfaceMock::DestroyGroupTimeOutAction()
{
    auto run = [] () {
        CONN_LOGI(CONN_WIFI_DIRECT, "lwq 9");
        WifiP2pLinkedInfo info;
        info.connectState = P2P_CONNECTED;
        sleep(17);
        connectionCallback_(info);
    };
    std::thread thread(run);
    thread.detach();
    return WIFI_SUCCESS;
}
}
// namespace OHOS::SoftBus