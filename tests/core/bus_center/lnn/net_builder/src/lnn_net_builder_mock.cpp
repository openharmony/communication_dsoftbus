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

#include "lnn_net_builder_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_lnnNetBuilderInterface;
LnnNetBuilderInterfaceMock::LnnNetBuilderInterfaceMock()
{
    g_lnnNetBuilderInterface = reinterpret_cast<void *>(this);
}

LnnNetBuilderInterfaceMock::~LnnNetBuilderInterfaceMock()
{
    g_lnnNetBuilderInterface = nullptr;
}

static LnnNetBuilderInterface *GetLnnNetBuilderInterface()
{
    return reinterpret_cast<LnnNetBuilderInterface *>(g_lnnNetBuilderInterface);
}

extern "C" {
int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType)
{
    return GetLnnNetBuilderInterface()->LnnRequestLeaveSpecific(networkId, addrType);
}

int32_t LnnSetDLConnUserId(const char *networkId, int32_t userId)
{
    return GetLnnNetBuilderInterface()->LnnSetDLConnUserId(networkId, userId);
}

int32_t LnnSetDLConnUserIdCheckSum(const char *networkId, int32_t userIdCheckSum)
{
    return GetLnnNetBuilderInterface()->LnnSetDLConnUserIdCheckSum(networkId, userIdCheckSum);
}
}
} // namespace OHOS