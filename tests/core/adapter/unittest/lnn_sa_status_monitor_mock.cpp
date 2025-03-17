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

#include "lnn_sa_status_monitor_mock.h"
#include "lnn_sa_status_monitor.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_laneDepsInterface;
LnnSaStatusMonitorInterfaceMock::LnnSaStatusMonitorInterfaceMock()
{
    g_laneDepsInterface = reinterpret_cast<void *>(this);
}

LnnSaStatusMonitorInterfaceMock::~LnnSaStatusMonitorInterfaceMock()
{
    g_laneDepsInterface = nullptr;
}

static LnnSaStatusMonitorInterface *GetLnnSaStatusMonitorInterface()
{
    return reinterpret_cast<LnnSaStatusMonitorInterface *>(g_laneDepsInterface);
}

extern "C" {
int32_t LnnAsyncCallbackDelayHelper(
    SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis)
{
    return GetLnnSaStatusMonitorInterface()->LnnAsyncCallbackDelayHelper(looper, callback, para, delayMillis);
}
}
} // namespace OHOS