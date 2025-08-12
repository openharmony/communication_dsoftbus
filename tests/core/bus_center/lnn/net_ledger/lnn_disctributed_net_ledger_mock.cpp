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

#include "lnn_disctributed_net_ledger_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_lnnDisctributedNetLedgerInterface;
LnnDisctributedNetLedgerInterfaceMock::LnnDisctributedNetLedgerInterfaceMock()
{
    g_lnnDisctributedNetLedgerInterface = reinterpret_cast<void *>(this);
}

LnnDisctributedNetLedgerInterfaceMock::~LnnDisctributedNetLedgerInterfaceMock()
{
    g_lnnDisctributedNetLedgerInterface = nullptr;
}

static LnnDisctributedNetLedgerInterface *GetLnnDisctributedNetLedgerInterface()
{
    return reinterpret_cast<LnnDisctributedNetLedgerInterface *>(g_lnnDisctributedNetLedgerInterface);
}

extern "C" {
int32_t LnnSaveRemoteDeviceInfo(const NodeInfo *deviceInfo)
{
    return GetLnnDisctributedNetLedgerInterface()->LnnSaveRemoteDeviceInfo(deviceInfo);
}
int32_t LnnRetrieveDeviceInfo(const char *udid, NodeInfo *deviceInfo)
{
    return GetLnnDisctributedNetLedgerInterface()->LnnRetrieveDeviceInfo(udid, deviceInfo);
}

int32_t LnnFindDeviceUdidTrustedInfoFromDb(const char *udid)
{
    return GetLnnDisctributedNetLedgerInterface()->LnnFindDeviceUdidTrustedInfoFromDb(udid);
}
}
}
