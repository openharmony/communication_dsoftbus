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

#include <cstdint>
#include <securec.h>

#include "lnn_net_ledger_common_mock.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_netLedgerCommonInterface;

NetLedgerCommonInterfaceMock::NetLedgerCommonInterfaceMock()
{
    g_netLedgerCommonInterface = reinterpret_cast<void *>(this);
}

NetLedgerCommonInterfaceMock::~NetLedgerCommonInterfaceMock()
{
    g_netLedgerCommonInterface = nullptr;
}

static NetLedgerCommonInterfaceMock *GetNetLedgerCommonInterface()
{
    return reinterpret_cast<NetLedgerCommonInterfaceMock *>(g_netLedgerCommonInterface);
}

extern "C" {
    int32_t LnnSetLocalNumU16Info(InfoKey key, uint16_t info)
    {
        return GetNetLedgerCommonInterface()->LnnSetLocalNumU16Info(key, info);
    }

} // extern "C"
} // namespace OHOS