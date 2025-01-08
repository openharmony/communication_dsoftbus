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

#include "lnn_connection_fsm_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_lnnConnNewMock;
LnnConnFsmInterfaceMock::LnnConnFsmInterfaceMock()
{
    g_lnnConnNewMock = reinterpret_cast<void *>(this);
}

LnnConnFsmInterfaceMock::~LnnConnFsmInterfaceMock()
{
    g_lnnConnNewMock = nullptr;
}

static LnnConnFsmInterface *GetLnnConnInterface()
{
    return reinterpret_cast<LnnConnFsmInterface *>(g_lnnConnNewMock);
}

extern "C" {
void LnnNotifyDeviceVerified(const char *udid)
{
    return GetLnnConnInterface()->LnnNotifyDeviceVerified(udid);
}

int32_t SoftBusGetBtState(void)
{
    return GetLnnConnInterface()->SoftBusGetBtState();
}

int32_t LnnGenerateBtMacHash(const char *btMac, int32_t brMacLen, char *brMacHash, int32_t hashLen)
{
    return GetLnnConnInterface()->LnnGenerateBtMacHash(btMac, brMacLen, brMacHash, hashLen);
}

void DeleteFromProfile(const char *udid)
{
    return GetLnnConnInterface()->DeleteFromProfile(udid);
}

void SendDeviceStateToMlps(void *para)
{
    return GetLnnConnInterface()->SendDeviceStateToMlps(para);
}

int32_t LnnUpdateNetworkId(const NodeInfo *newInfo)
{
    return GetLnnConnInterface()->LnnUpdateNetworkId(newInfo);
}

int32_t AuthGetServerSide(int64_t authId, bool *isServer)
{
    return GetLnnConnInterface()->AuthGetServerSide(authId, isServer);
}

int32_t LnnRetrieveDeviceInfo(const char *udid, NodeInfo *deviceInfo)
{
    return GetLnnConnInterface()->LnnRetrieveDeviceInfo(udid, deviceInfo);
}

int32_t LnnRetrieveDeviceInfoByNetworkId(const char *networkId, NodeInfo *info)
{
    return GetLnnConnInterface()->LnnRetrieveDeviceInfo(networkId, info);
}

int32_t AuthRestoreAuthManager(
    const char *udidHash, const AuthConnInfo *connInfo, uint32_t requestId, NodeInfo *nodeInfo, int64_t *authId)
{
    return GetLnnConnInterface()->AuthRestoreAuthManager(udidHash, connInfo, requestId, nodeInfo, authId);
}

int32_t LnnLoadLocalBroadcastCipherKey(void)
{
    return GetLnnConnInterface()->LnnLoadLocalBroadcastCipherKey();
}

int32_t LnnGetLocalBroadcastCipherKey(BroadcastCipherKey *broadcastKey)
{
    return GetLnnConnInterface()->LnnGetLocalBroadcastCipherKey(broadcastKey);
}

int32_t LnnSetLocalByteInfo(InfoKey key, const uint8_t *info, uint32_t len)
{
    return GetLnnConnInterface()->LnnSetLocalByteInfo(key, info, len);
}

int32_t LnnInsertLinkFinderInfo(const char *networkId)
{
    return GetLnnConnInterface()->LnnInsertLinkFinderInfo(networkId);
}

int32_t LnnUpdateGroupType(const NodeInfo *info)
{
    return GetLnnConnInterface()->LnnUpdateGroupType(info);
}

void LnnNotifySingleOffLineEvent(const ConnectionAddr *addr, NodeBasicInfo *basicInfo)
{
    return GetLnnConnInterface()->LnnNotifySingleOffLineEvent(addr, basicInfo);
}

void LnnStopOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType)
{
    return GetLnnConnInterface()->LnnStopOfflineTimingByHeartbeat(networkId, addrType);
}

int32_t LnnGetLocalNodeInfoSafe(NodeInfo *info)
{
    return GetLnnConnInterface()->LnnGetLocalNodeInfoSafe(info);
}

void SetLpKeepAliveState(void *para)
{
    return GetLnnConnInterface()->SetLpKeepAliveState(para);
}

const char *LnnPrintConnectionAddr(const ConnectionAddr *addr)
{
    return GetLnnConnInterface()->LnnPrintConnectionAddr(addr);
}

bool LnnConvertAddrToAuthConnInfo(const ConnectionAddr *addr, AuthConnInfo *connInfo)
{
    return GetLnnConnInterface()->LnnConvertAddrToAuthConnInfo(addr, connInfo);
}

void LnnNotifyStateForSession(char *udid, int32_t retCode)
{
    return GetLnnConnInterface()->LnnNotifyStateForSession(udid, retCode);
}

void AuthRemoveAuthManagerByAuthHandle(AuthHandle authHandle)
{
    return GetLnnConnInterface()->AuthRemoveAuthManagerByAuthHandle(authHandle);
}

DiscoveryType LnnConvAddrTypeToDiscType(ConnectionAddrType type)
{
    return GetLnnConnInterface()->LnnConvAddrTypeToDiscType(type);
}

void LnnNotifyOOBEStateChangeEvent(SoftBusOOBEState state)
{
    return GetLnnConnInterface()->LnnNotifyOOBEStateChangeEvent(state);
}

void LnnNotifyHichainProofException(const char *proofInfo, uint32_t proofLen, uint16_t deviceTypeId, int32_t errCode)
{
    return GetLnnConnInterface()->LnnNotifyHichainProofException(proofInfo, proofLen, deviceTypeId, errCode);
}

void LnnNotifyDeviceTrustedChange(int32_t type, const char *msg, uint32_t msgLen)
{
    return GetLnnConnInterface()->LnnNotifyDeviceTrustedChange(type, msg, msgLen);
}
}
} // namespace OHOS
