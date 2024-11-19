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

#include "net_ledger_mock.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_netLedgerMock;
NetLedgerMock::NetLedgerMock()
{
    g_netLedgerMock = reinterpret_cast<void *>(this);
}

NetLedgerMock::~NetLedgerMock()
{
    g_netLedgerMock = nullptr;
}

NetLedgerMock::SetupDefaultResult()
{
    ON_CALL(*this, LnnSetP2pRole).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(*this, LnnSetP2pMac).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(*this, LnnSetP2pGoMac).WillByDefault(Return(SOFTBUS_OK));
    ON_CALL(*this, LnnSetWifiDirectAddr).WillByDefault(Return(SOFTBUS_OK));
}

static NetLedgerInterface *GetNetLedgerInterface()
{
    return reinterpret_cast<NetLedgerInterface *>(g_netLedgerMock);
}

extern "C" {
int32_t LnnSetP2pRole(NodeInfo *info, int32_t role)
{
    return GetNetLedgerInterface()->LnnSetP2pRole(info, role);
}

int32_t LnnSetP2pMac(NodeInfo *info, const char *p2pMac)
{
    return GetNetLedgerInterface()->LnnSetP2pMac(info, p2pMac);
}

int32_t LnnSetP2pGoMac(NodeInfo *info, const char *goMac)
{
    return GetNetLedgerInterface()->LnnSetP2pGoMac(info, goMac);
}

int32_t LnnGetAllOnlineAndMetaNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return GetNetLedgerInterface()->LnnGetAllOnlineAndMetaNodeInfo(info, infoNum);
}

int32_t LnnSetWifiDirectAddr(NodeBasicInfo **info, int32_t *wifiDirectAddr)
{
    return GetNetLedgerInterface()->LnnSetWifiDirectAddr(info, wifiDirectAddr);
}
}
}