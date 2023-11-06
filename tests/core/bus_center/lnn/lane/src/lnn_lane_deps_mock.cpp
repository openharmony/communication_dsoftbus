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

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_laneDepsInterface;
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

void LaneDepsInterfaceMock::SetDefaultResult()
{
    EXPECT_CALL(*this, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(*this, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(*this, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(*this, SoftBusFrequencyToChannel).WillRepeatedly(Return(1));
    EXPECT_CALL(*this, LnnVisitPhysicalSubnet).WillRepeatedly(Return(true));
    EXPECT_CALL(*this, LnnGetNodeInfoById).WillRepeatedly(Return(nullptr));
    EXPECT_CALL(*this, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(*this, LnnHasDiscoveryType).WillRepeatedly(Return(true));
}

extern "C" {
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

NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type)
{
    return GetLaneDepsInterface()->LnnGetNodeInfoById(id, type);
}

const NodeInfo *LnnGetLocalNodeInfo(void)
{
    return GetLaneDepsInterface()->LnnGetLocalNodeInfo();
}

int32_t P2pLinkGetRequestId(void)
{
    return GetLaneDepsInterface()->P2pLinkGetRequestId();
}

void AuthCloseConn(int64_t authId)
{
    return GetLaneDepsInterface()->AuthCloseConn(authId);
}

int32_t P2pLinkConnectDevice(const P2pLinkConnectInfo *info)
{
    return GetLaneDepsInterface()->P2pLinkConnectDevice(info);
}

int32_t P2pLinkDisconnectDevice(const P2pLinkDisconnectInfo *info)
{
    return GetLaneDepsInterface()->P2pLinkDisconnectDevice(info);
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

int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info)
{
    return GetLaneDepsInterface()->LnnGetLocalNumU64Info(key, info);
}

int32_t LnnGetRemoteNumU64Info(const char *networkId, InfoKey key, uint64_t *info)
{
    return GetLaneDepsInterface()->LnnGetRemoteNumU64Info(networkId, key, info);
}

bool AuthDeviceCheckConnInfo(const char *uuid, AuthLinkType type, bool checkConnection)
{
    return GetLaneDepsInterface()->AuthDeviceCheckConnInfo(uuid, type, checkConnection);
}

uint32_t AuthGenRequestId(void)
{
    return GetLaneDepsInterface()->AuthGenRequestId();
}

int32_t AuthPostTransData(int64_t authId, const AuthTransData *dataInfo)
{
    return GetLaneDepsInterface()->AuthPostTransData(authId, dataInfo);
}

int32_t AuthGetConnInfo(int64_t authId, AuthConnInfo *connInfo)
{
    return GetLaneDepsInterface()->AuthGetConnInfo(authId, connInfo);
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
    return GetLaneDepsInterface()->ConnBleReturnConnection(connection);
}

bool ConnBleDirectIsEnable(BleProtocolType protocol)
{
    return GetLaneDepsInterface()->ConnBleDirectIsEnable(protocol);
}

int32_t TransProxyCloseProxyChannel(int32_t channelId)
{
    return GetLaneDepsInterface()->TransProxyCloseProxyChannel(channelId);
}
LaneResource *LaneResourceIsExist(LaneResource *resourceItem)
{
    return GetLaneDepsInterface()->LaneResourceIsExist(resourceItem);
}
}
} // namespace OHOS