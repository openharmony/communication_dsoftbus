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
constexpr char NODE_NETWORK_ID[] = "123456789";

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
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(localNetCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(*this, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remoteNetCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(*this, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(localNetCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(*this, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remoteNetCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(*this, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(localFeatureCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(*this, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remoteFeatureCap), Return(SOFTBUS_OK)));
    EXPECT_CALL(*this, LnnGetRemoteStrInfo).WillRepeatedly(ActionOfGetRemoteStrInfo);
    EXPECT_CALL(*this, SoftBusGenerateStrHash).WillRepeatedly(ActionOfGenerateStrHash);
}

int32_t LaneDepsInterfaceMock::ActionOfLnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len)
{
    (void)udid;
    if (buf == nullptr) {
        GTEST_LOG_(ERROR) << "invalid param";
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcpy_s(buf, len, NODE_NETWORK_ID) != EOK) {
        GTEST_LOG_(ERROR) << "strcpy_s failed";
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
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

int32_t LaneDepsInterfaceMock::socketEvent = SOFTBUS_SOCKET_OUT;
int32_t LaneDepsInterfaceMock::ActionOfAddTrigger(ListenerModule module, int32_t fd, TriggerType trigger)
{
    (void)trigger;
    GTEST_LOG_(INFO) << "ActionOfAddTrigger enter";
    if (g_baseListener.onDataEvent == nullptr) {
        GTEST_LOG_(INFO) << "invalid lane onDataEvent";
        return SOFTBUS_OK;
    }
    return g_baseListener.onDataEvent(module, socketEvent, fd);
}

int32_t LaneDepsInterfaceMock::ActionOfConnOpenFailed(const AuthConnInfo *info, uint32_t requestId,
    const AuthConnCallback *callback, bool isMeta)
{
    callback->onConnOpenFailed(requestId, SOFTBUS_LANE_GUIDE_BUILD_FAIL);
    return SOFTBUS_OK;
}

int32_t LaneDepsInterfaceMock::ActionOfConnOpened(const AuthConnInfo *info, uint32_t requestId,
    const AuthConnCallback *callback, bool isMeta)
{
    AuthHandle authHandle = {
        .authId = 0,
        .type = (info == nullptr) ? AUTH_LINK_TYPE_P2P : info->type,
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

int32_t AuthGetConnInfoByType(const char *uuid, AuthLinkType type, AuthConnInfo *connInfo, bool isMeta)
{
    return GetLaneDepsInterface()->AuthGetConnInfoByType(uuid, type, connInfo, isMeta);
}

int32_t AuthGetP2pConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    return GetLaneDepsInterface()->AuthGetP2pConnInfo(uuid, connInfo, isMeta);
}

int32_t AuthGetHmlConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    return GetLaneDepsInterface()->AuthGetHmlConnInfo(uuid, connInfo, isMeta);
}

int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId,
    const AuthConnCallback *callback, bool isMeta)
{
    return GetLaneDepsInterface()->AuthOpenConn(info, requestId, callback, isMeta);
}

int32_t SoftBusFrequencyToChannel(int32_t frequency)
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

int32_t LnnSetLocalNumU32Info(InfoKey key, uint32_t info)
{
    return GetLaneDepsInterface()->LnnSetLocalNumU32Info(key, info);
}

int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type)
{
    return GetLaneDepsInterface()->LnnSetNetCapability(capability, type);
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

int32_t LnnConvertDlId(const char *srcId, IdCategory srcIdType, IdCategory dstIdType,
    char *dstIdBuf, uint32_t dstIdBufLen)
{
    return GetLaneDepsInterface()->LnnConvertDlId(srcId, srcIdType, dstIdType, dstIdBuf, dstIdBufLen);
}

void AuthDeviceGetLatestIdByUuid(const char *uuid, AuthLinkType type, AuthHandle *authHandle)
{
    GetLaneDepsInterface()->AuthDeviceGetLatestIdByUuid(uuid, type, authHandle);
}

void LnnDumpLocalBasicInfo(void)
{
    GetLaneDepsInterface()->LnnDumpLocalBasicInfo();
}

void LnnDumpOnlineDeviceInfo(void)
{
    GetLaneDepsInterface()->LnnDumpOnlineDeviceInfo();
}

int32_t LnnGetOsTypeByNetworkId(const char *networkId, int32_t *osType)
{
    return GetLaneDepsInterface()->LnnGetOsTypeByNetworkId(networkId, osType);
}

void DeleteNetworkResourceByLaneId(uint64_t laneId)
{
    GetLaneDepsInterface()->DeleteNetworkResourceByLaneId(laneId);
}

int32_t SoftBusGetBtState(void)
{
    return GetLaneDepsInterface()->SoftBusGetBtState();
}

int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return GetLaneDepsInterface()->LnnGetAllOnlineNodeInfo(info, infoNum);
}

void AddNetworkResource(NetworkResource *networkResource)
{
    return GetLaneDepsInterface()->AddNetworkResource(networkResource);
}

int32_t LnnRequestCheckOnlineStatus(const char *networkId, uint64_t timeout)
{
    return GetLaneDepsInterface()->LnnRequestCheckOnlineStatus(networkId, timeout);
}

int32_t AuthCheckMetaExist(const AuthConnInfo *connInfo, bool *isExist)
{
    return GetLaneDepsInterface()->AuthCheckMetaExist(connInfo, isExist);
}
}
} // namespace OHOS