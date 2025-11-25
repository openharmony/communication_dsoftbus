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

#include "trans_udp_manager_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_transUdpManagerInterface;
TransUdpManagerMock::TransUdpManagerMock()
{
    g_transUdpManagerInterface = reinterpret_cast<void *>(this);
}

TransUdpManagerMock::~TransUdpManagerMock()
{
    g_transUdpManagerInterface = nullptr;
}

static TransUdpManagerInterface *GetTransUdpManagerInterface()
{
    return reinterpret_cast<TransUdpManagerInterface *>(g_transUdpManagerInterface);
}

extern "C" {
int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len)
{
    return GetTransUdpManagerInterface()->LnnGetRemoteStrInfo(networkId, key, info, len);
}
}
} // namespace OHOS
