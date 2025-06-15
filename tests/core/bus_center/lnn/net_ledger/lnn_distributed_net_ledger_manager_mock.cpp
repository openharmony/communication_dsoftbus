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

#include "lnn_distributed_net_ledger_manager_mock.h"
#include "lnn_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_lnnNetLedgerManagerInterface;
LnnDistributedNetLedgerManagerInterfaceMock::LnnDistributedNetLedgerManagerInterfaceMock()
{
    g_lnnNetLedgerManagerInterface = reinterpret_cast<void *>(this);
}

LnnDistributedNetLedgerManagerInterfaceMock::~LnnDistributedNetLedgerManagerInterfaceMock()
{
    g_lnnNetLedgerManagerInterface = nullptr;
}

static LnnDistributedNetLedgerManagerInterfaceMock *GetLnnDistributedNetLedgerManagerInterface()
{
    return reinterpret_cast<LnnDistributedNetLedgerManagerInterfaceMock *>(g_lnnNetLedgerManagerInterface);
}

extern "C" {
NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type)
{
    return GetLnnDistributedNetLedgerManagerInterface()->LnnGetNodeInfoById(id, type);
}

int32_t LnnSaveRemoteDeviceInfoPacked(const NodeInfo *deviceInfo)
{
    return GetLnnDistributedNetLedgerManagerInterface()->LnnSaveRemoteDeviceInfoPacked(deviceInfo);
}

int32_t LnnSetWifiDirectAddr(NodeInfo *info, const char *wifiDirectAddr)
{
    return GetLnnDistributedNetLedgerManagerInterface()->LnnSetWifiDirectAddr(info, wifiDirectAddr);
}

int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    return GetLnnDistributedNetLedgerManagerInterface()->SoftBusGenerateStrHash(str, len, hash);
}

int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen)
{
    return GetLnnDistributedNetLedgerManagerInterface()->ConvertBytesToHexString(outBuf, outBufLen, inBuf, inLen);
}

bool LnnIsNodeOnline(const NodeInfo *info)
{
    return GetLnnDistributedNetLedgerManagerInterface()->LnnIsNodeOnline(info);
}

NodeInfo *GetNodeInfoFromMap(const DoubleHashMap *map, const char *id)
{
    return GetLnnDistributedNetLedgerManagerInterface()->GetNodeInfoFromMap(map, id);
}

int32_t LnnRetrieveDeviceInfoByUdidPacked(const char *udid, NodeInfo *deviceInfo)
{
    return GetLnnDistributedNetLedgerManagerInterface()->LnnRetrieveDeviceInfoByUdidPacked(udid, deviceInfo);
}
} // extern "C"
} // namespace OHOS
