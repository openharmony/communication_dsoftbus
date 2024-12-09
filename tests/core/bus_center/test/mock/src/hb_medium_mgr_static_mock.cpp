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

#include "hb_medium_mgr_static_mock.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_hbMediumMgrInterface = nullptr;
HbMediumMgrInterfaceMock::HbMediumMgrInterfaceMock()
{
    g_hbMediumMgrInterface = reinterpret_cast<void *>(this);
}

HbMediumMgrInterfaceMock::~HbMediumMgrInterfaceMock()
{
    g_hbMediumMgrInterface = nullptr;
}

static HbMediumMgrInterface *HbMediumMgrInterface()
{
    return reinterpret_cast<HbMediumMgrInterfaceMock *>(g_hbMediumMgrInterface);
}

extern "C" {
bool IsCloudSyncEnabled(void)
{
    return HbMediumMgrInterface()->IsCloudSyncEnabled();
}

bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit)
{
    return HbMediumMgrInterface()->IsFeatureSupport(feature, capaBit);
}

int32_t AuthFindDeviceKey(const char *udidHash, int32_t keyType, AuthDeviceKeyInfo *deviceKey)
{
    return HbMediumMgrInterface()->AuthFindDeviceKey(udidHash, keyType, deviceKey);
}

bool IsCipherManagerFindKey(const char *udid)
{
    return HbMediumMgrInterface()->IsCipherManagerFindKey(udid);
}

int32_t AuthFindLatestNormalizeKey(const char *udidHash, AuthDeviceKeyInfo *deviceKey, bool clearOldKey)
{
    return HbMediumMgrInterface()->AuthFindLatestNormalizeKey(udidHash, deviceKey, clearOldKey);
}

DiscoveryType LnnConvAddrTypeToDiscType(ConnectionAddrType type)
{
    return HbMediumMgrInterface()->LnnConvAddrTypeToDiscType(type);
}

bool LnnConvertAddrToAuthConnInfo(const ConnectionAddr *addr, AuthConnInfo *connInfo)
{
    return HbMediumMgrInterface()->LnnConvertAddrToAuthConnInfo(addr, connInfo);
}

int32_t SoftBusGetBrState(void)
{
    return HbMediumMgrInterface()->SoftBusGetBrState();
}

int32_t LnnAddRemoteChannelCode(const char *udid, int32_t channelCode)
{
    return HbMediumMgrInterface()->LnnAddRemoteChannelCode(udid, channelCode);
}

int32_t LnnRegistBleHeartbeatMediumMgr(void)
{
    return HbMediumMgrInterface()->LnnRegistBleHeartbeatMediumMgr();
}

int32_t LnnGetDLHeartbeatTimestamp(const char *networkId, uint64_t *timestamp)
{
    return HbMediumMgrInterface()->LnnGetDLHeartbeatTimestamp(networkId, timestamp);
}

int32_t LnnSetDLHeartbeatTimestamp(const char *networkId, const uint64_t timestamp)
{
    return HbMediumMgrInterface()->LnnSetDLHeartbeatTimestamp(networkId, timestamp);
}

int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    return HbMediumMgrInterface()->SoftBusGenerateStrHash(str, len, hash);
}

int32_t ConvertBytesToUpperCaseHexString(char *outBuf, uint32_t outBufLen, const unsigned char *inBuf,
    uint32_t inLen)
{
    return HbMediumMgrInterface()->ConvertBytesToUpperCaseHexString(outBuf, outBufLen, inBuf, inLen);
}

int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen, const unsigned char *inBuf,
    uint32_t inLen)
{
    return HbMediumMgrInterface()->ConvertBytesToHexString(outBuf, outBufLen, inBuf, inLen);
}

bool AuthIsPotentialTrusted(const DeviceInfo *device)
{
    return HbMediumMgrInterface()->AuthIsPotentialTrusted(device);
}

int32_t DecryptUserId(NodeInfo *deviceInfo, uint8_t *advUserId, uint32_t len)
{
    return HbMediumMgrInterface()->DecryptUserId(deviceInfo, advUserId, len);
}
}
} // namespace OHOS
