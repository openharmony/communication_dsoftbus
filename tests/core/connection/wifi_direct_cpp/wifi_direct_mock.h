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

#ifndef WIFI_DIRECT_MOCK_H
#define WIFI_DIRECT_MOCK_H

#include <atomic>
#include <gmock/gmock.h>
#include "auth_interface.h"
#include "bus_center_manager.h"
#include "data/negotiate_message.h"
#include "dfx/wifi_direct_hidumper.h"
#include "kits/c/wifi_device.h"
#include "kits/c/wifi_hid2d.h"
#include "kits/c/wifi_p2p.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_p2p_info.h"
#include "softbus_proxychannel_pipeline.h"
#include "wifi_direct_types.h"

namespace OHOS::SoftBus {
class WifiDirectInterface {
public:
    WifiDirectInterface() = default;
    virtual ~WifiDirectInterface() = default;

    // define dependencies interface here
    virtual int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size) = 0;
    virtual int32_t AuthPostTransData(AuthHandle authHandle, const AuthTransData *dataInfo) = 0;
    virtual int32_t RegAuthTransListener(int32_t module, const AuthTransListener *listener) = 0;
    virtual WifiErrorCode Hid2dGetChannelListFor5G(int32_t *chanList, int32_t len) = 0;
    virtual WifiErrorCode GetP2pEnableStatus(P2pState* state) = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t LnnSetLocalNumInfo(InfoKey key, int32_t info) = 0;
    virtual int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info) = 0;
    virtual int32_t LnnSetLocalStrInfo(InfoKey key, const char *info) = 0;
    virtual int32_t LnnSyncP2pInfo() = 0;
    virtual uint64_t LnnGetFeatureCapabilty() = 0;
    virtual bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit) = 0;

    virtual int32_t LnnGetRemoteStrInfo(const std::string &networkId, InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t LnnGetNetworkIdByUuid(const std::string &uuid, char *buf, uint32_t len) = 0;
    virtual int32_t LnnGetRemoteBoolInfoIgnoreOnline(const std::string &networkId, InfoKey key, bool *info) = 0;
    virtual int32_t LnnGetRemoteNumU64Info(const std::string &networkId, InfoKey key, uint64_t *info) = 0;
    virtual bool LnnGetOnlineStateById(const char *id, IdCategory type) = 0;
    virtual void AuthCloseConn(AuthHandle authHandle) = 0;
    virtual void AuthStopListeningForWifiDirect(AuthLinkType type, ListenerModule moduleId) = 0;
    virtual int32_t AuthStartListeningForWifiDirect(AuthLinkType type, const char *ip,
        int32_t port, ListenerModule *moduleId) = 0;
    virtual int32_t AuthGetMetaType(int64_t authId, bool *isMetaAuth) = 0;
    virtual const char *LnnConvertDLidToUdid(const char *id, IdCategory type) = 0;
    virtual uint32_t AuthGenRequestId(void) = 0;
    virtual int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId,
        const AuthConnCallback *callback, bool isMeta) = 0;
    virtual int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info) = 0;
    virtual int32_t LnnGetRemoteNumInfo(const char *netWorkId, InfoKey key, int32_t *info) = 0;
    virtual int32_t SoftBusBase64Encode(unsigned char *dst, size_t dlen, size_t *olen,
        const unsigned char *src, size_t slen) = 0;
    virtual int32_t LnnGetLocalPtkByUuid(const char *uuid, char *localPtk, uint32_t len) = 0;
    virtual int32_t LnnGetLocalDefaultPtkByUuid(const char *uuid, char *localPtk, uint32_t len) = 0;
    virtual int32_t LnnGetRemoteByteInfo(const char *networkId, InfoKey key, uint8_t *info, uint32_t len) = 0;
    virtual int32_t LnnGetRemoteDefaultPtkByUuid(const char *uuid, char *remotePtk, uint32_t len) = 0;

    // Defines dependencies short-reach interface here
    virtual int IsWifiActive() = 0;
    virtual WifiErrorCode GetLinkedInfo(WifiLinkedInfo *info) = 0;
    virtual WifiErrorCode Hid2dGetRecommendChannel(const RecommendChannelRequest *request,
        RecommendChannelResponse *response) = 0;
    virtual WifiErrorCode Hid2dGetSelfWifiCfgInfo(SelfCfgType cfgType, char cfgData[CFG_DATA_MAX_BYTES],
        int* getDatValidLen) = 0;
    virtual int32_t SoftBusBase64Decode(unsigned char *dst, size_t dlen, size_t *olen,
        const unsigned char *src, size_t slen) = 0;
    virtual WifiErrorCode Hid2dSetPeerWifiCfgInfo(PeerCfgType cfgType, char cfgData[CFG_DATA_MAX_BYTES],
        int32_t setDataValidLen) = 0;
    virtual WifiErrorCode GetCurrentGroup(WifiP2pGroupInfo* groupInfo) = 0;
    virtual WifiErrorCode Hid2dRequestGcIp(const unsigned char gcMac[MAC_LEN],
        unsigned int ipAddr[IPV4_ARRAY_LEN]) = 0;
    virtual WifiErrorCode Hid2dConfigIPAddr(const char ifName[IF_NAME_LEN], const IpAddrInfo *ipInfo) = 0;
    virtual WifiErrorCode Hid2dCreateGroup(const int32_t frequency, FreqType type) = 0;
    virtual WifiErrorCode Hid2dConnect(const Hid2dConnectConfig *config) = 0;
    virtual WifiErrorCode Hid2dSharedlinkIncrease(void) = 0;
    virtual WifiErrorCode Hid2dSharedlinkDecrease(void) = 0;
    virtual WifiErrorCode RemoveGroup() = 0;
    virtual WifiErrorCode Hid2dRemoveGcGroup(const char gcIfName[IF_NAME_LEN]) = 0;
    virtual int32_t Hid2dIsWideBandwidthSupported() = 0;

    virtual int32_t TransProxyPipelineRegisterListener(TransProxyPipelineMsgType type,
        const ITransProxyPipelineListener *listener) = 0;
    virtual int32_t TransProxyPipelineGetUuidByChannelId(int32_t channelId, char *uuid, uint32_t uuidLen) = 0;
    virtual int32_t TransProxyPipelineSendMessage(
        int32_t channelId, const uint8_t *data, uint32_t dataLen, TransProxyPipelineMsgType type) = 0;

    // connect result callback mock stub
    virtual void OnConnectSuccess(uint32_t requestId, const struct WifiDirectLink *link) = 0;
    virtual void OnConnectFailure(uint32_t requestId, int32_t reason) = 0;
    // disconnect result callback mock stub
    virtual void OnDisconnectSuccess(uint32_t requestId) = 0;
    virtual void OnDisconnectFailure(uint32_t requestId, int32_t reason) = 0;
    // proxy negotiate channel mock stub
    virtual int32_t ProxyNegotiateChannelSendMessage(int32_t channelId, const NegotiateMessage &msg) const = 0;
    virtual std::string ProxyNegotiateChannelGetRemoteDeviceId(int32_t channelId) const = 0;
    virtual int32_t LnnGetOsTypeByNetworkId(const char *networkId, int32_t *osType) = 0;
    virtual int32_t GetInterfaceIpString(const std::string &interface, std::string &ip) = 0;
    virtual void HidumpInit() = 0;
    using Hidumper = std::function<int()>;
    virtual void Register(const Hidumper &hidumper) = 0;
};

class WifiDirectInterfaceMock : public WifiDirectInterface {
public:
    static WifiDirectInterfaceMock *GetMock()
    {
        return mock.load();
    }

    WifiDirectInterfaceMock();
    ~WifiDirectInterfaceMock() override;

    // mock dependencies interface here
    // mock dependencies here
    MOCK_METHOD(int32_t, AuthGetDeviceUuid, (int64_t authId, char *uuid, uint16_t size), (override));
    MOCK_METHOD(int32_t, AuthPostTransData, (AuthHandle authHandle, const AuthTransData *dataInfo), (override));
    MOCK_METHOD(int32_t, RegAuthTransListener, (int32_t module, const AuthTransListener *listener), (override));
    MOCK_METHOD(WifiErrorCode, Hid2dGetChannelListFor5G, (int32_t *chanList, int32_t len), (override));
    MOCK_METHOD(WifiErrorCode, GetP2pEnableStatus, (P2pState* state), (override));
    MOCK_METHOD(int32_t, LnnGetLocalStrInfo, (InfoKey, char*, uint32_t), (override));
    MOCK_METHOD(int32_t, LnnGetRemoteStrInfo, (const std::string &networkId, InfoKey key, char *info, uint32_t len),
        (override));
    MOCK_METHOD(int32_t, LnnGetNetworkIdByUuid, (const std::string &, char *, uint32_t), (override));
    MOCK_METHOD(int32_t, LnnGetRemoteBoolInfoIgnoreOnline, (const std::string &, InfoKey, bool *), (override));
    MOCK_METHOD(
        int32_t, LnnGetRemoteNumU64Info, (const std::string &networkId, InfoKey key, uint64_t *info), (override));
    MOCK_METHOD(bool, LnnGetOnlineStateById, (const char *, IdCategory), (override));
    MOCK_METHOD(void, AuthCloseConn, (AuthHandle), (override));
    MOCK_METHOD(void, AuthStopListeningForWifiDirect, (AuthLinkType, ListenerModule), (override));
    MOCK_METHOD(int32_t, AuthStartListeningForWifiDirect,
        (AuthLinkType, const char *, int32_t, ListenerModule *), (override));
    MOCK_METHOD2(AuthGetMetaType, int32_t (int64_t, bool *));
    MOCK_METHOD2(LnnConvertDLidToUdid, const char *(const char *, IdCategory));
    MOCK_METHOD0(AuthGenRequestId, uint32_t ());
    MOCK_METHOD4(AuthOpenConn, int32_t (const AuthConnInfo*, uint32_t, const AuthConnCallback*, bool));
    MOCK_METHOD(void, AuthStopListening, (AuthLinkType));
    MOCK_METHOD2(LnnGetLocalNumInfo, int32_t (InfoKey, int32_t*));
    MOCK_METHOD3(LnnGetRemoteNumInfo, int32_t (const char*, InfoKey, int32_t*));
    MOCK_METHOD(int32_t, SoftBusBase64Encode, (unsigned char *, size_t, size_t *,
        const unsigned char *, size_t), (override));
    MOCK_METHOD3(LnnGetLocalPtkByUuid, int32_t (const char *uuid, char *localPtk, uint32_t len));
    MOCK_METHOD3(LnnGetLocalDefaultPtkByUuid, int32_t (const char *uuid, char *localPtk, uint32_t len));
    MOCK_METHOD4(LnnGetRemoteByteInfo, int32_t (const char *networkId, InfoKey key, uint8_t *info, uint32_t len));
    MOCK_METHOD3(LnnGetRemoteDefaultPtkByUuid, int32_t (const char *uuid, char *remotePtk, uint32_t len));

    MOCK_METHOD2(LnnSetLocalStrInfo, int32_t (InfoKey, const char *));
    MOCK_METHOD2(LnnSetLocalNumInfo, int32_t (InfoKey, int32_t));
    MOCK_METHOD2(LnnGetLocalNumU64Info, int32_t (InfoKey, uint64_t *));
    MOCK_METHOD(int32_t, LnnSyncP2pInfo, (), (override));
    MOCK_METHOD(uint64_t, LnnGetFeatureCapabilty, (), (override));
    MOCK_METHOD(bool, IsFeatureSupport, (uint64_t, FeatureCapability), (override));

    MOCK_METHOD(int, IsWifiActive, (), (override));
    MOCK_METHOD(WifiErrorCode, GetLinkedInfo, (WifiLinkedInfo *), (override));
    MOCK_METHOD(WifiErrorCode, Hid2dGetRecommendChannel,
        (const RecommendChannelRequest *, RecommendChannelResponse *), (override));
    MOCK_METHOD(WifiErrorCode, Hid2dGetSelfWifiCfgInfo, (SelfCfgType, char *, int*), (override));
    MOCK_METHOD(int32_t, SoftBusBase64Decode,
        (unsigned char *, size_t, size_t*, const unsigned char *, size_t), (override));
    MOCK_METHOD(WifiErrorCode, Hid2dSetPeerWifiCfgInfo, (PeerCfgType, char *, int), (override));
    MOCK_METHOD(WifiErrorCode, GetCurrentGroup, (WifiP2pGroupInfo*), (override));
    MOCK_METHOD(WifiErrorCode, Hid2dRequestGcIp, (const unsigned char*, unsigned int*), (override));
    MOCK_METHOD(WifiErrorCode, Hid2dConfigIPAddr, (const char*, const IpAddrInfo *), (override));
    MOCK_METHOD(WifiErrorCode, Hid2dCreateGroup, (const int, FreqType), (override));
    MOCK_METHOD(WifiErrorCode, Hid2dConnect, (const Hid2dConnectConfig *), (override));
    MOCK_METHOD(WifiErrorCode, Hid2dSharedlinkIncrease, (), (override));
    MOCK_METHOD(WifiErrorCode, Hid2dSharedlinkDecrease, (), (override));
    MOCK_METHOD(WifiErrorCode, Hid2dRemoveGcGroup, (const char gcIfName[IF_NAME_LEN]), (override));
    MOCK_METHOD(WifiErrorCode, RemoveGroup, (), (override));
    MOCK_METHOD(int, Hid2dIsWideBandwidthSupported, (), (override));

    MOCK_METHOD(int32_t, TransProxyPipelineRegisterListener,
        (TransProxyPipelineMsgType, const ITransProxyPipelineListener *), (override));
    MOCK_METHOD(int32_t, TransProxyPipelineGetUuidByChannelId, (int32_t, char *, uint32_t), (override));
    MOCK_METHOD(int32_t, TransProxyPipelineSendMessage,
        (int32_t, const uint8_t *, uint32_t, TransProxyPipelineMsgType), (override));

    MOCK_METHOD(void, OnConnectSuccess, (uint32_t requestId, const struct WifiDirectLink *link), (override));
    MOCK_METHOD(void, OnConnectFailure, (uint32_t requestId, int32_t reason), (override));

    MOCK_METHOD(void, OnDisconnectSuccess, (uint32_t requestId), (override));
    MOCK_METHOD(void, OnDisconnectFailure, (uint32_t requestId, int32_t reason), (override));

    MOCK_METHOD(
        int, ProxyNegotiateChannelSendMessage, (int32_t channelId, const NegotiateMessage &msg), (const override));
    MOCK_METHOD(std::string, ProxyNegotiateChannelGetRemoteDeviceId, (int32_t channelId), (const override));
    MOCK_METHOD(int32_t, LnnGetOsTypeByNetworkId, (const char *networkId, int32_t *osType), (override));
    MOCK_METHOD(int32_t, GetInterfaceIpString, (const std::string &interface, std::string &ip), (override));
    MOCK_METHOD(void, HidumpInit, (), (override));
    using Hidumper = std::function<int()>;
    MOCK_METHOD(void, Register, (const Hidumper &hidumper), (override));

    static void InjectWifiDirectConnectCallbackMock(WifiDirectConnectCallback &callback);
    static void InjectWifiDirectDisconnectCallbackMock(WifiDirectDisconnectCallback &callback);

    static WifiErrorCode RegisterP2pStateChangedCallback(const P2pStateChangedCallback callback);
    static WifiErrorCode RegisterP2pConnectionChangedCallback(const P2pConnectionChangedCallback callback);

    static WifiErrorCode CreateGroupSuccessAction(const int32_t frequency, FreqType type);
    static WifiErrorCode CreateGroupFailureAction(const int32_t frequency, FreqType type);
    static WifiErrorCode CreateGroupTimeOutAction(const int32_t frequency, FreqType type);

    static WifiErrorCode ConnectSuccessAction(const Hid2dConnectConfig *config);
    static WifiErrorCode ConnectFailureAction(const Hid2dConnectConfig *config);
    static WifiErrorCode ConnectTimeOutAction(const Hid2dConnectConfig *config);

    static WifiErrorCode DestroyGroupSuccessAction();
    static WifiErrorCode DestroyGroupFailureAction();
    static WifiErrorCode DestroyGroupTimeOutAction();

private:
    static inline std::atomic<WifiDirectInterfaceMock *> mock = nullptr;
    static inline P2pConnectionChangedCallback connectionCallback_ {};
    static inline P2pStateChangedCallback stateCallback_ {};
};

} // namespace OHOS::SoftBus

#endif // WIFI_DIRECT_MOCK_H
