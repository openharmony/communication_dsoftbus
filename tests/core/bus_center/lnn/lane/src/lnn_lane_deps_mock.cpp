/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "lnn_lane_deps_mock.h"
#include "softbus_error_code.h"
#include "softbus_socket.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
const static uint16_t SHA_HASH_LEN = 32;
void *g_laneDepsInterface;
static SoftbusBaseListener g_baseListener = {0};
LaneDepsInterfaceMock::LaneDepsInterfaceMock()
{
    g_laneDepsInterface = reinterpret_cast<void *>(this);
}

LaneDepsInterfaceMock::~LaneDepsInterfaceMock()
{
    g_laneDepsInterface = nullptr;
}

static LaneDepsInterface *GetLaneDepsInterface()
{
    return reinterpret_cast<LaneDepsInterface *>(g_laneDepsInterface);
}

void LaneDepsInterfaceMock::SetDefaultResult(NodeInfo *info)
{
    EXPECT_CALL(*this, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(*this, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(*this, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(*this, SoftBusFrequencyToChannel).WillRepeatedly(Return(1));
    EXPECT_CALL(*this, LnnVisitPhysicalSubnet).WillRepeatedly(Return(true));
    EXPECT_CALL(*this, LnnGetNodeInfoById).WillRepeatedly(Return(nullptr));
    EXPECT_CALL(*this, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(*this, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    ON_CALL(*this, LnnGetLocalNodeInfo).WillByDefault(Return(info));
    ON_CALL(*this, ConnOpenClientSocket).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(*this, AddTrigger).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(*this, LnnGetLocalNumU64Info).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(*this, LnnGetRemoteNumU64Info).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(*this, LnnGetLocalNumU32Info).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(*this, LnnGetRemoteNumU32Info).WillByDefault(Return(SOFTBUS_OK));
}

void LaneDepsInterfaceMock::SetDefaultResultForAlloc(int32_t localNetCap, int32_t remoteNetCap,
    int32_t localFeatureCap, int32_t remoteFeatureCap)
{
    EXPECT_CALL(*this, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localNetCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(*this, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteNetCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(*this, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localNetCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(*this, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteNetCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(*this, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(localFeatureCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(*this, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(remoteFeatureCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(*this, LnnGetRemoteStrInfo).WillRepeatedly(ActionOfGetRemoteStrInfo);
    EXPECT_CALL(*this, SoftBusGenerateStrHash).WillRepeatedly(ActionOfGenerateStrHash);
}

int32_t LaneDepsInterfaceMock::ActionOfGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    (void)str;
    (void)len;
    if (hash == nullptr) {
        GTEST_LOG_(ERROR) << "invalid param";
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcpy_s((char *)hash, SHA_HASH_LEN, "1234567890123456") != EOK) {
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LaneDepsInterfaceMock::ActionOfGetRemoteStrInfo(const char *netWorkId, InfoKey key, char *info, uint32_t len)
{
    (void)netWorkId;
    (void)len;
    if (info == nullptr) {
        GTEST_LOG_(ERROR) << "invalid param";
        return SOFTBUS_INVALID_PARAM;
    }
    char peerUdid[] = "111122223333abcdef";
    char brMac[] = "00:11:22:33:44:55";
    switch (key) {
        case STRING_KEY_BT_MAC:
            if (strncpy_s(info, BT_MAC_LEN, brMac, strlen(brMac)) != EOK) {
                return SOFTBUS_STRCPY_ERR;
            }
            break;
        default:
            if (strncpy_s(info, UDID_BUF_LEN, peerUdid, strlen(peerUdid)) != EOK) {
                return SOFTBUS_STRCPY_ERR;
            }
    }
    return SOFTBUS_OK;
}

int32_t LaneDepsInterfaceMock::ActionOfStartBaseClient(ListenerModule module, const SoftbusBaseListener *listener)
{
    (void)module;
    GTEST_LOG_(INFO) << "ActionOfStartBaseClient enter";
    if (listener == nullptr) {
        GTEST_LOG_(INFO) << "invalid listener";
        return SOFTBUS_OK;
    }
    g_baseListener.onDataEvent = listener->onDataEvent;
    return SOFTBUS_OK;
}

int32_t LaneDepsInterfaceMock::ActionOfAddTrigger(ListenerModule module, int32_t fd, TriggerType trigger)
{
    (void)trigger;
    GTEST_LOG_(INFO) << "ActionOfAddTrigger enter";
    if (g_baseListener.onDataEvent == nullptr) {
        GTEST_LOG_(INFO) << "invalid lane onDataEvent";
        return SOFTBUS_OK;
    }
    return g_baseListener.onDataEvent(module, SOFTBUS_SOCKET_OUT, fd);
}

int32_t LaneDepsInterfaceMock::ActionOfConnOpenFailed(const AuthConnInfo *info, uint32_t requestId,
    const AuthConnCallback *callback, bool isMeta)
{
    callback->onConnOpenFailed(requestId, SOFTBUS_ERR);
    return SOFTBUS_OK;
}

int32_t LaneDepsInterfaceMock::ActionOfConnOpened(const AuthConnInfo *info, uint32_t requestId,
    const AuthConnCallback *callback, bool isMeta)
{
    AuthHandle authHandle = {
        .authId = 0,
        .type = AUTH_LINK_TYPE_P2P,
    };
    callback->onConnOpened(requestId, authHandle);
    return SOFTBUS_OK;
}

extern "C" {
int32_t GetAuthLinkTypeList(const char *networkId, AuthLinkTypeList *linkTypeList)
{
    return GetLaneDepsInterface()->GetAuthLinkTypeList(networkId, linkTypeList);
}

int32_t AuthAllocConn(const char *networkId, uint32_t authRequestId, AuthConnCallback *callback)
{
    return GetLaneDepsInterface()->AuthAllocConn(networkId, authRequestId, callback);
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return GetLaneDepsInterface()->LnnGetRemoteNodeInfoById(id, type, info);
}

bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetLaneDepsInterface()->LnnHasDiscoveryType(info, type);
}

bool LnnGetOnlineStateById(const char *id, IdCategory type)
{
    return GetLaneDepsInterface()->LnnGetOnlineStateById(id, type);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetLaneDepsInterface()->LnnGetLocalStrInfo(key, info, len);
}

int32_t LnnGetRemoteStrInfo(const char *netWorkId, InfoKey key, char *info, uint32_t len)
{
    return GetLaneDepsInterface()->LnnGetRemoteStrInfo(netWorkId, key, info, len);
}

int32_t AuthGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    return GetLaneDepsInterface()->AuthGetPreferConnInfo(uuid, connInfo, isMeta);
}

int32_t AuthGetP2pConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    return GetLaneDepsInterface()->AuthGetP2pConnInfo(uuid, connInfo, isMeta);
}

int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId,
    const AuthConnCallback *callback, bool isMeta)
{
    return GetLaneDepsInterface()->AuthOpenConn(info, requestId, callback, isMeta);
}

int SoftBusFrequencyToChannel(int frequency)
{
    return GetLaneDepsInterface()->SoftBusFrequencyToChannel(frequency);
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return GetLaneDepsInterface()->LnnGetLocalNumInfo(key, info);
}

int32_t LnnGetRemoteNumInfo(const char *netWorkId, InfoKey key, int32_t *info)
{
    return GetLaneDepsInterface()->LnnGetRemoteNumInfo(netWorkId, key, info);
}

int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info)
{
    return GetLaneDepsInterface()->LnnGetLocalNumU32Info(key, info);
}

int32_t LnnGetRemoteNumU32Info(const char *netWorkId, InfoKey key, uint32_t *info)
{
    return GetLaneDepsInterface()->LnnGetRemoteNumU32Info(netWorkId, key, info);
}

NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type)
{
    return GetLaneDepsInterface()->LnnGetNodeInfoById(id, type);
}

const NodeInfo *LnnGetLocalNodeInfo(void)
{
    return GetLaneDepsInterface()->LnnGetLocalNodeInfo();
}

void AuthCloseConn(AuthHandle authHandle)
{
    GetLaneDepsInterface()->AuthCloseConn(authHandle);
}

int32_t AuthSetP2pMac(int64_t authId, const char *p2pMac)
{
    return GetLaneDepsInterface()->AuthSetP2pMac(authId, p2pMac);
}

bool LnnVisitPhysicalSubnet(LnnVisitPhysicalSubnetCallback callback, void *data)
{
    return GetLaneDepsInterface()->LnnVisitPhysicalSubnet(callback, data);
}

const char *LnnConvertDLidToUdid(const char *id, IdCategory type)
{
    return GetLaneDepsInterface()->LnnConvertDLidToUdid(id, type);
}

ConnBleConnection *ConnBleGetConnectionByUdid(const char *addr, const char *udid, BleProtocolType protocol)
{
    return GetLaneDepsInterface()->ConnBleGetConnectionByUdid(addr, udid, protocol);
}

int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info)
{
    return GetLaneDepsInterface()->LnnGetLocalNumU64Info(key, info);
}

int32_t LnnGetRemoteNumU64Info(const char *networkId, InfoKey key, uint64_t *info)
{
    return GetLaneDepsInterface()->LnnGetRemoteNumU64Info(networkId, key, info);
}
int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len)
{
    return GetLaneDepsInterface()->LnnGetNetworkIdByUdid(udid, buf, len);
}
bool AuthDeviceCheckConnInfo(const char *uuid, AuthLinkType type, bool checkConnection)
{
    return GetLaneDepsInterface()->AuthDeviceCheckConnInfo(uuid, type, checkConnection);
}

uint32_t AuthGenRequestId(void)
{
    return GetLaneDepsInterface()->AuthGenRequestId();
}

int32_t AuthPostTransData(AuthHandle authHandle, const AuthTransData *dataInfo)
{
    return GetLaneDepsInterface()->AuthPostTransData(authHandle, dataInfo);
}

int32_t AuthGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo)
{
    return GetLaneDepsInterface()->AuthGetConnInfo(authHandle, connInfo);
}

int32_t AuthGetMetaType(int64_t authId, bool *isMetaAuth)
{
    return GetLaneDepsInterface()->AuthGetMetaType(authId, isMetaAuth);
}

ConnBleConnection *ConnBleGetClientConnectionByUdid(const char *udid, BleProtocolType protocol)
{
    return GetLaneDepsInterface()->ConnBleGetClientConnectionByUdid(udid, protocol);
}

void ConnBleReturnConnection(ConnBleConnection **connection)
{
    GetLaneDepsInterface()->ConnBleReturnConnection(connection);
}

bool ConnBleDirectIsEnable(BleProtocolType protocol)
{
    return GetLaneDepsInterface()->ConnBleDirectIsEnable(protocol);
}

int32_t TransProxyCloseProxyChannel(int32_t channelId)
{
    return GetLaneDepsInterface()->TransProxyCloseProxyChannel(channelId);
}
LaneResource *GetValidLaneResource(LaneResource *resourceItem)
{
    return GetLaneDepsInterface()->GetValidLaneResource(resourceItem);
}

int64_t GetAuthIdByConnInfo(const AuthConnInfo *connInfo)
{
    return GetLaneDepsInterface()->GetAuthIdByConnInfo(connInfo);
}

int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    return GetLaneDepsInterface()->SoftBusGenerateStrHash(str, len, hash);
}

int32_t StartBaseClient(ListenerModule module, const SoftbusBaseListener *listener)
{
    return GetLaneDepsInterface()->StartBaseClient(module, listener);
}

bool CheckActiveConnection(const ConnectOption *option, bool needOccupy)
{
    return GetLaneDepsInterface()->CheckActiveConnection(option, needOccupy);
}

int32_t ConnOpenClientSocket(const ConnectOption *option, const char *bindAddr, bool isNonBlock)
{
    return GetLaneDepsInterface()->ConnOpenClientSocket(option, bindAddr, isNonBlock);
}

int32_t AddTrigger(ListenerModule module, int32_t fd, TriggerType trigger)
{
    return GetLaneDepsInterface()->AddTrigger(module, fd, trigger);
}

int32_t QueryLaneResource(const LaneQueryInfo *queryInfo, const QosInfo *qosInfo)
{
    return GetLaneDepsInterface()->QueryLaneResource(queryInfo, qosInfo);
}

ssize_t ConnSendSocketData(int32_t fd, const char *buf, size_t len, int32_t timeout)
{
    return GetLaneDepsInterface()->ConnSendSocketData(fd, buf, len, timeout);
}

struct WifiDirectManager* GetWifiDirectManager(void)
{
    return GetLaneDepsInterface()->GetWifiDirectManager();
}
}
} // namespace OHOS