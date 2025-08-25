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

#include "lnn_async_callback_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_asyncInterface;

LnnAsyncCallbackInterfaceMock::LnnAsyncCallbackInterfaceMock()
{
    g_asyncInterface = reinterpret_cast<void *>(this);
}

LnnAsyncCallbackInterfaceMock::~LnnAsyncCallbackInterfaceMock()
{
    g_asyncInterface = nullptr;
}

static LnnAsyncCallbackInterface *GetAsyncInterface()
{
    return reinterpret_cast<LnnAsyncCallbackInterfaceMock *>(g_asyncInterface);
}

extern "C" {
int32_t LnnAsyncCallbackHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para)
{
    return GetAsyncInterface()->LnnAsyncCallbackHelper(looper, callback, para);
}

int32_t LnnAsyncCallbackDelayHelper(
    SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis)
{
    return GetAsyncInterface()->LnnAsyncCallbackDelayHelper(looper, callback, para, delayMillis);
}
}
} // namespace OHOS