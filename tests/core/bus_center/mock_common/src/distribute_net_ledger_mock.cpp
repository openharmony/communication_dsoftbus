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

#include "distribute_net_ledger_mock.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_distriLedgerInterface;

DistributeLedgerInterfaceMock::DistributeLedgerInterfaceMock()
{
    g_distriLedgerInterface = reinterpret_cast<void *>(this);
}

DistributeLedgerInterfaceMock::~DistributeLedgerInterfaceMock()
{
    g_distriLedgerInterface = nullptr;
}

static DistributeLedgerInterface *GetDistriLedgerInterface()
{
    return reinterpret_cast<DistributeLedgerInterfaceMock *>(g_distriLedgerInterface);
}

extern "C" {
int32_t LnnGetDLHeartbeatTimestamp(const char *netWorkId, uint64_t *timestamp)
{
    return GetDistriLedgerInterface()->LnnGetDLHeartbeatTimestamp(netWorkId, timestamp);
}

int32_t LnnSetDLHeartbeatTimestamp(const char *netWorkId, const uint64_t timestamp)
{
    return GetDistriLedgerInterface()->LnnSetDLHeartbeatTimestamp(netWorkId, timestamp);
}

int32_t LnnGetRemoteStrInfo(const char *netWorkId, InfoKey key, char *info, uint32_t len)
{
    return GetDistriLedgerInterface()->LnnGetRemoteStrInfo(netWorkId, key, info, len);
}

int32_t LnnGetRemoteNumU32Info(const char *netWorkId, InfoKey key, uint32_t *info)
{
    return GetDistriLedgerInterface()->LnnGetRemoteNumU32Info(netWorkId, key, info);
}

int32_t LnnGetRemoteNumInfo(const char *netWorkId, InfoKey key, int32_t *info)
{
    return GetDistriLedgerInterface()->LnnGetRemoteNumInfo(netWorkId, key, info);
}

int32_t LnnGetRemoteNum16Info(const char *netWorkId, InfoKey key, int16_t *info)
{
    return GetDistriLedgerInterface()->LnnGetRemoteNum16Info(netWorkId, key, info);
}

int32_t LnnGetRemoteBoolInfo(const char *netWorkId, InfoKey key, bool *info)
{
    return GetDistriLedgerInterface()->LnnGetRemoteBoolInfo(netWorkId, key, info);
}

int32_t LnnGetRemoteNumU64Info(const char *netWorkId, InfoKey key, uint64_t *info)
{
    return GetDistriLedgerInterface()->LnnGetRemoteNumU64Info(netWorkId, key, info);
}

int32_t LnnGetRemoteStrInfoByIfnameIdx(const char *netWorkId, InfoKey key, char *info, uint32_t len, int32_t ifIdx)
{
    return GetDistriLedgerInterface()->LnnGetRemoteStrInfoByIfnameIdx(netWorkId, key, info, len, ifIdx);
}

int32_t LnnGetRemoteNumInfoByIfnameIdx(const char *networkId, InfoKey key, int32_t *info, int32_t ifIdx)
{
    return GetDistriLedgerInterface()->LnnGetRemoteNumInfoByIfnameIdx(networkId, key, info, ifIdx);
}

bool LnnGetOnlineStateById(const char *id, IdCategory type)
{
    return GetDistriLedgerInterface()->LnnGetOnlineStateById(id, type);
}

const char *LnnConvertDLidToUdid(const char *id, IdCategory type)
{
    return GetDistriLedgerInterface()->LnnConvertDLidToUdid(id, type);
}

int32_t ConvertBtMacToBinary(const char *strMac, uint32_t strMacLen, uint8_t *binMac, uint32_t binMacLen)
{
    return GetDistriLedgerInterface()->ConvertBtMacToBinary(strMac, strMacLen, binMac, binMacLen);
}

int32_t LnnGetDLSleHbTimestamp(const char *networkId, uint64_t *timestamp)
{
    return GetDistriLedgerInterface()->LnnGetDLSleHbTimestamp(networkId, timestamp);
}

int32_t LnnSetDLSleHbTimestamp(const char *networkId, const uint64_t timestamp)
{
    return GetDistriLedgerInterface()->LnnSetDLSleHbTimestamp(networkId, timestamp);
}
}
} // namespace OHOS