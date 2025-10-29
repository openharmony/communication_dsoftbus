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

#include "trans_bus_center_manager_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_transBusCenterManagerInterface;
TransBusCenterManagerInterfaceMock::TransBusCenterManagerInterfaceMock()
{
    g_transBusCenterManagerInterface = reinterpret_cast<void *>(this);
}

TransBusCenterManagerInterfaceMock::~TransBusCenterManagerInterfaceMock()
{
    g_transBusCenterManagerInterface = nullptr;
}

static TransBusCenterManagerInterface *GetTransBusCenterManagerInterface()
{
    return reinterpret_cast<TransBusCenterManagerInterface *>(g_transBusCenterManagerInterface);
}

extern "C" {
int32_t LnnGetRemoteNumInfo(const char *networkId, InfoKey key, int32_t *info)
{
    return GetTransBusCenterManagerInterface()->LnnGetRemoteNumInfo(networkId, key, info);
}
} /* extern "C" */
} /* namespace OHOS */
