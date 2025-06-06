/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "lnn_kv_store_launch_listener_mock.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_lnnKvStoreLaunchListenerInterface;
LnnKvStoreLaunchListenerInterfaceMock::LnnKvStoreLaunchListenerInterfaceMock()
{
    g_lnnKvStoreLaunchListenerInterface = reinterpret_cast<void *>(this);
}

LnnKvStoreLaunchListenerInterfaceMock::~LnnKvStoreLaunchListenerInterfaceMock()
{
    g_lnnKvStoreLaunchListenerInterface = nullptr;
}

static LnnKvStoreLaunchListenerInterface *GetLnnKvStoreLaunchListenerInterface()
{
    return reinterpret_cast<LnnKvStoreLaunchListenerInterface *>(g_lnnKvStoreLaunchListenerInterface);
}

extern "C" {
void LnnInitCloudSyncModule(void)
{
    return GetLnnKvStoreLaunchListenerInterface()->LnnInitCloudSyncModule();
}
}
} // namespace OHOS