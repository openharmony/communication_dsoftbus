/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "lnn_distributed_net_ledger_new_mock.h"

using testing::NiceMock;

namespace OHOS {
extern "C" {
void *g_lnnDistributedNetLedgerInterfaceMock;

LnnDistributedNetLedgerInterfaceMock::LnnDistributedNetLedgerInterfaceMock()
{
    g_lnnDistributedNetLedgerInterfaceMock = reinterpret_cast<void *>(this);
}

LnnDistributedNetLedgerInterfaceMock::~LnnDistributedNetLedgerInterfaceMock()
{
    g_lnnDistributedNetLedgerInterfaceMock = nullptr;
}

static LnnDistributedNetLedgerInterfaceMock *GetLnnDistributedNetLedgerInterface()
{
    return reinterpret_cast<LnnDistributedNetLedgerInterfaceMock *>(g_lnnDistributedNetLedgerInterfaceMock);
}

void LnnNotifyBasicInfoChanged(const NodeBasicInfo *info, NodeBasicInfoType type)
{
    GetLnnDistributedNetLedgerInterface()->LnnNotifyBasicInfoChanged(info, type);
}

void Anonymize(const char *in, char **out)
{
    GetLnnDistributedNetLedgerInterface()->Anonymize(in, out);
}

void AnonymizeFree(char *str)
{
    GetLnnDistributedNetLedgerInterface()->AnonymizeFree(str);
}

const char* AnonymizeWrapper(const char* str)
{
    return GetLnnDistributedNetLedgerInterface()->AnonymizeWrapper(str);
}

int32_t SoftBusGenerateStrHash(const uint8_t *str, uint32_t len, uint8_t *hash)
{
    return GetLnnDistributedNetLedgerInterface()->SoftBusGenerateStrHash(str, len, hash);
}

int32_t ConvertBytesToHexString(char *hexStr, uint32_t hexLen, const uint8_t *byte, uint32_t byteLen)
{
    return GetLnnDistributedNetLedgerInterface()->ConvertBytesToHexString(hexStr, hexLen, byte, byteLen);
}

int32_t LnnRetrieveDeviceInfoPacked(const char *udidHash, NodeInfo *deviceInfo)
{
    return GetLnnDistributedNetLedgerInterface()->LnnRetrieveDeviceInfoPacked(udidHash, deviceInfo);
}

int32_t LnnSaveRemoteDeviceInfoPacked(const NodeInfo *info)
{
    return GetLnnDistributedNetLedgerInterface()->LnnSaveRemoteDeviceInfoPacked(info);
}

void LnnDumpRemotePtk(const char *ptk1, const char *ptk2, const char *desc)
{
    GetLnnDistributedNetLedgerInterface()->LnnDumpRemotePtk(ptk1, ptk2, desc);
}

void LnnInsertLinkFinderInfoPacked(const char *networkId)
{
    GetLnnDistributedNetLedgerInterface()->LnnInsertLinkFinderInfoPacked(networkId);
}

void NotifyForegroundUseridChange(const char *networkId, DiscoveryType type, bool isChange)
{
    GetLnnDistributedNetLedgerInterface()->NotifyForegroundUseridChange(networkId, type, isChange);
}

int32_t LnnSetDLConnUserIdCheckSum(const char *networkId, int32_t userIdCheckSum)
{
    return GetLnnDistributedNetLedgerInterface()->LnnSetDLConnUserIdCheckSum(networkId, userIdCheckSum);
}

DiscoveryType ConvertToDiscoveryType(AuthLinkType type)
{
    return GetLnnDistributedNetLedgerInterface()->ConvertToDiscoveryType(type);
}

const NodeInfo *LnnGetLocalNodeInfo(void)
{
    return GetLnnDistributedNetLedgerInterface()->LnnGetLocalNodeInfo();
}

int32_t ConnPreventConnection(const ConnectOption *option, uint32_t timeout)
{
    return GetLnnDistributedNetLedgerInterface()->ConnPreventConnection(option, timeout);
}

void LnnNotifyMigrate(bool isUpgrade, const NodeBasicInfo *info)
{
    GetLnnDistributedNetLedgerInterface()->LnnNotifyMigrate(isUpgrade, info);
}

void UpdateProfile(NodeInfo *info)
{
    GetLnnDistributedNetLedgerInterface()->UpdateProfile(info);
}

void InsertToProfile(NodeInfo *info)
{
    GetLnnDistributedNetLedgerInterface()->InsertToProfile(info);
}

int64_t LnnUpTimeMs(void)
{
    return GetLnnDistributedNetLedgerInterface()->LnnUpTimeMs();
}

int32_t LnnGetLocalNum64Info(InfoKey key, int64_t *info)
{
    return GetLnnDistributedNetLedgerInterface()->LnnGetLocalNum64Info(key, info);
}

int32_t GetActiveOsAccountIds(void)
{
    return GetLnnDistributedNetLedgerInterface()->GetActiveOsAccountIds();
}

bool LnnIsDefaultOhosAccount(void)
{
    return GetLnnDistributedNetLedgerInterface()->LnnIsDefaultOhosAccount();
}

int32_t LnnFindDeviceUdidTrustedInfoFromDb(const char *udid)
{
    return GetLnnDistributedNetLedgerInterface()->LnnFindDeviceUdidTrustedInfoFromDb(udid);
}

bool DpHasAccessControlProfile(const char *udid, bool isUdid, int32_t userId)
{
    return GetLnnDistributedNetLedgerInterface()->DpHasAccessControlProfile(udid, isUdid, userId);
}

void LnnInsertSpecificTrustedDevInfo(const char *udid)
{
    GetLnnDistributedNetLedgerInterface()->LnnInsertSpecificTrustedDevInfo(udid);
}

uint32_t AuthGetGroupType(const char *udid, const char *uuid)
{
    return GetLnnDistributedNetLedgerInterface()->AuthGetGroupType(udid, uuid);
}

DiscoveryType LnnConvAddrTypeToDiscType(ConnectionAddrType type)
{
    return GetLnnDistributedNetLedgerInterface()->LnnConvAddrTypeToDiscType(type);
}
} // extern "C"
} // namespace OHOS
