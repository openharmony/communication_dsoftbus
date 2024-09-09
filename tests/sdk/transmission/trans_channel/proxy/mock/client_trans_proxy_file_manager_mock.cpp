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

#include "client_trans_proxy_file_manager_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_clientTransProxyFileManagerInterface;
ClientTransProxyFileManagerInterfaceMock::ClientTransProxyFileManagerInterfaceMock()
{
    g_clientTransProxyFileManagerInterface = reinterpret_cast<void *>(this);
}

ClientTransProxyFileManagerInterfaceMock::~ClientTransProxyFileManagerInterfaceMock()
{
    g_clientTransProxyFileManagerInterface = nullptr;
}

static ClientTransProxyFileManagerInterface *GetClientTransProxyFileManagerInterface()
{
    return reinterpret_cast<ClientTransProxyFileManagerInterface *>(g_clientTransProxyFileManagerInterface);
}

extern "C" {
uint32_t SoftBusLtoHl(uint32_t value)
{
    return GetClientTransProxyFileManagerInterface()->SoftBusLtoHl(value);
}

uint32_t SoftBusHtoLl(uint64_t value)
{
    return GetClientTransProxyFileManagerInterface()->SoftBusHtoLl(value);
}

uint64_t SoftBusLtoHll(uint64_t value)
{
    return GetClientTransProxyFileManagerInterface()->SoftBusLtoHll(value);
}

uint64_t SoftBusHtoLll(uint64_t value)
{
    return GetClientTransProxyFileManagerInterface()->SoftBusHtoLll(value);
}
}
}
