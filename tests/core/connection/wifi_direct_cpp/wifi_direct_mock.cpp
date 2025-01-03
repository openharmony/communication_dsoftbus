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
#include "conn_log.h"
#include "softbus_adapter_socket.h"
#include <thread>
// implement dependencies and redirect request to mock object here
extern "C" {
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

WifiErrorCode Hid2dGetChannelListFor5G(int32_t *chanList, int32_t len)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->Hid2dGetChannelListFor5G(chanList, len);
}

WifiErrorCode GetP2pEnableStatus(P2pState *state)
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

int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnGetLocalNumU64Info(key, info);
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

int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len)
{
    auto id = std::string(networkId);
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnGetRemoteStrInfo(id, key, info, len);
}

int32_t LnnGetRemoteBoolInfoIgnoreOnline(const char *networkId, InfoKey key, bool *info)
{
    auto id = std::string(networkId);
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnGetRemoteBoolInfoIgnoreOnline(id, key, info);
}

int32_t LnnGetRemoteNumU64Info(const char *networkId, InfoKey key, uint64_t *info)
{
    auto id = std::string(networkId);
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnGetRemoteNumU64Info(id, key, info);
}

bool LnnGetOnlineStateById(const char *id, IdCategory type)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnGetOnlineStateById(id, type);
}

int32_t AuthStartListeningForWifiDirect(AuthLinkType type, const char *ip, int32_t port, ListenerModule *moduleId)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->AuthStartListeningForWifiDirect(type, ip, port, moduleId);
}

int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len)
{
    auto id = std::string(uuid);
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnGetNetworkIdByUuid(id, buf, len);
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

int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->AuthOpenConn(info, requestId, callback, isMeta);
}

void AuthStopListening(AuthLinkType type)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->AuthStopListening(type);
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnGetLocalNumInfo(key, info);
}

int32_t LnnGetRemoteNumInfo(const char *netWorkId, InfoKey key, int32_t *info)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnGetRemoteNumInfo(netWorkId, key, info);
}

int32_t LnnGetLocalPtkByUuid(const char *uuid, char *localPtk, uint32_t len)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnGetLocalPtkByUuid(uuid, localPtk, len);
}

int32_t LnnGetLocalDefaultPtkByUuid(const char *uuid, char *localPtk, uint32_t len)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnGetLocalDefaultPtkByUuid(uuid, localPtk, len);
}

int32_t LnnGetRemoteByteInfo(const char *networkId, InfoKey key, uint8_t *info, uint32_t len)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnGetRemoteByteInfo(networkId, key, info, len);
}

int32_t LnnGetRemoteDefaultPtkByUuid(const char *uuid, char *remotePtk, uint32_t len)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnGetRemoteDefaultPtkByUuid(uuid, remotePtk, len);
}

int32_t SoftBusBase64Encode(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->SoftBusBase64Encode(dst, dlen, olen, src, slen);
}

int32_t LnnGetOsTypeByNetworkId(const char *networkId, int32_t *osType)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->LnnGetOsTypeByNetworkId(networkId, osType);
}

int32_t GetInterfaceIpString(const std::string &interface, std::string &ip)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->GetInterfaceIpString(interface, ip);
}

int IsWifiActive()
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->IsWifiActive();
}

WifiErrorCode GetLinkedInfo(WifiLinkedInfo *info)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->GetLinkedInfo(info);
}

WifiErrorCode Hid2dGetRecommendChannel(const RecommendChannelRequest *request, RecommendChannelResponse *response)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->Hid2dGetRecommendChannel(request, response);
}

WifiErrorCode Hid2dGetSelfWifiCfgInfo(SelfCfgType cfgType, char cfgData[CFG_DATA_MAX_BYTES], int32_t *getDatValidLen)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->Hid2dGetSelfWifiCfgInfo(cfgType, cfgData, getDatValidLen);
}

int32_t SoftBusBase64Decode(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->SoftBusBase64Decode(dst, dlen, olen, src, slen);
}

WifiErrorCode Hid2dSetPeerWifiCfgInfo(PeerCfgType cfgType, char cfgData[CFG_DATA_MAX_BYTES], int32_t setDataValidLen)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->Hid2dSetPeerWifiCfgInfo(
        cfgType, cfgData, setDataValidLen);
}

WifiErrorCode GetCurrentGroup(WifiP2pGroupInfo *groupInfo)
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

WifiErrorCode Hid2dCreateGroup(const int32_t frequency, FreqType type)
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

int32_t TransProxyPipelineRegisterListener(TransProxyPipelineMsgType type, const ITransProxyPipelineListener *listener)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->TransProxyPipelineRegisterListener(type, listener);
}

int32_t TransProxyPipelineGetUuidByChannelId(int32_t channelId, char *uuid, uint32_t uuidLen)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->TransProxyPipelineGetUuidByChannelId(
        channelId, uuid, uuidLen);
}

int32_t TransProxyPipelineSendMessage(
    int32_t channelId, const uint8_t *data, uint32_t dataLen, TransProxyPipelineMsgType type)
{
    return OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->TransProxyPipelineSendMessage(
        channelId, data, dataLen, type);
}

int32_t Hid2dIsWideBandwidthSupported()
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

int32_t Ipv6AddrInToAddr(SoftBusSockAddrIn6 *addrIn6, char *addr, int32_t addrLen)
{
    return SOFTBUS_OK;
}

int32_t Ipv6AddrToAddrIn(SoftBusSockAddrIn6 *addrIn6, const char *ip, uint16_t port)
{
    return SOFTBUS_OK;
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return SOFTBUS_OK;
}

int32_t LnnGetRemoteNodeInfoByKey(const char *key, NodeInfo *info)
{
    return SOFTBUS_OK;
}
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

static void OnConnectSuccessProxy(uint32_t requestId, const struct WifiDirectLink *link)
{
    OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->OnConnectSuccess(requestId, link);
}

static void OnConnectFailureProxy(uint32_t requestId, int32_t reason)
{
    OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->OnConnectFailure(requestId, reason);
}

void WifiDirectInterfaceMock::InjectWifiDirectConnectCallbackMock(WifiDirectConnectCallback &callback)
{
    callback.onConnectSuccess = OnConnectSuccessProxy;
    callback.onConnectFailure = OnConnectFailureProxy;
}

static void OnDisconnectSuccessProxy(uint32_t requestId)
{
    OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->OnDisconnectSuccess(requestId);
}
static void OnDisconnectFailureProxy(uint32_t requestId, int32_t reason)
{
    OHOS::SoftBus::WifiDirectInterfaceMock::GetMock()->OnDisconnectFailure(requestId, reason);
}

void WifiDirectInterfaceMock::InjectWifiDirectDisconnectCallbackMock(WifiDirectDisconnectCallback &callback)
{
    callback.onDisconnectSuccess = OnDisconnectSuccessProxy;
    callback.onDisconnectFailure = OnDisconnectFailureProxy;
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

WifiErrorCode WifiDirectInterfaceMock::CreateGroupSuccessAction(const int32_t frequency, FreqType type)
{
    auto run = []() {
        WifiP2pLinkedInfo info;
        info.connectState = P2P_CONNECTED;
        P2pState state = P2P_STATE_STARTED;
        stateCallback_(state);
        connectionCallback_(info);
    };
    std::thread thread(run);
    thread.detach();
    return WIFI_SUCCESS;
}

WifiErrorCode WifiDirectInterfaceMock::CreateGroupFailureAction(const int32_t frequency, FreqType type)
{
    auto run = []() {
        WifiP2pLinkedInfo info;
        info.connectState = P2P_DISCONNECTED;
        connectionCallback_(info);
    };
    std::thread thread(run);
    thread.detach();
    return WIFI_SUCCESS;
}

WifiErrorCode WifiDirectInterfaceMock::CreateGroupTimeOutAction(const int32_t frequency, FreqType type)
{
    auto run = []() {
        WifiP2pLinkedInfo info;
        info.connectState = P2P_DISCONNECTED;
        sleep(6);
    };
    std::thread thread(run);
    thread.detach();
    return WIFI_SUCCESS;
}

WifiErrorCode WifiDirectInterfaceMock::ConnectSuccessAction(const Hid2dConnectConfig *config)
{
    auto run = []() {
        P2pState state = P2P_STATE_STARTED;
        stateCallback_(state);
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
    auto run = []() {
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
    auto run = []() {
        WifiP2pLinkedInfo info;
        info.connectState = P2P_DISCONNECTED;
        sleep(6);
    };
    std::thread thread(run);
    thread.detach();
    return WIFI_SUCCESS;
}

WifiErrorCode WifiDirectInterfaceMock::DestroyGroupSuccessAction()
{
    auto run = []() {
        P2pState state = P2P_STATE_STARTED;
        stateCallback_(state);
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
    auto run = []() {
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
    auto run = []() {
        WifiP2pLinkedInfo info;
        info.connectState = P2P_CONNECTED;
        sleep(17);
    };
    std::thread thread(run);
    thread.detach();
    return WIFI_SUCCESS;
}

void WifiDirectHidumper::HidumperInit() { }
using Hidumper = std::function<int()>;
void WifiDirectHidumper::Register(const Hidumper &hidumper) { }
} // namespace OHOS::SoftBus
// namespace OHOS::SoftBus
