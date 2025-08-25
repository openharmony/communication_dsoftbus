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

#include "heartbeat_new_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_hbNewMockInterface;
HeartBeatNewInterfaceMock::HeartBeatNewInterfaceMock()
{
    g_hbNewMockInterface = reinterpret_cast<void *>(this);
}

HeartBeatNewInterfaceMock::~HeartBeatNewInterfaceMock()
{
    g_hbNewMockInterface = nullptr;
}

static HeartBeatNewInterface *GetHeartBeatNewInterface()
{
    return reinterpret_cast<HeartBeatNewInterface *>(g_hbNewMockInterface);
}

extern "C" {
int32_t LnnAsyncCallbackDelayHelper(
    SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis)
{
    return GetHeartBeatNewInterface()->LnnAsyncCallbackDelayHelper(looper, callback, para, delayMillis);
}
}
} // namespace OHOS