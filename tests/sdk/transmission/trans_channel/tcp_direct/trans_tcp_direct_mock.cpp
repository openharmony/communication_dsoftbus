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

#include "trans_tcp_direct_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_transTcpDirectInterface;
TransTcpDirectInterfaceMock::TransTcpDirectInterfaceMock()
{
    g_transTcpDirectInterface = reinterpret_cast<void *>(this);
}

TransTcpDirectInterfaceMock::~TransTcpDirectInterfaceMock()
{
    g_transTcpDirectInterface = nullptr;
}

static TransTcpDirectInterface *GetTransTcpDirectInterface()
{
    return reinterpret_cast<TransTcpDirectInterface *>(g_transTcpDirectInterface);
}

extern "C" {
int32_t SoftBusSocketGetError(int32_t socketFd)
{
    return GetTransTcpDirectInterface()->SoftBusSocketGetError(socketFd);
}
int32_t GetErrCodeBySocketErr(int32_t transErrCode)
{
    return GetTransTcpDirectInterface()->GetErrCodeBySocketErr(transErrCode);
}
}
}
