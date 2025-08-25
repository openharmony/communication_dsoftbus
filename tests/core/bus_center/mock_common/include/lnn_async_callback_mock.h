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

#ifndef LNN_ASYNC_CALLBACK_MOCK_H
#define LNN_ASYNC_CALLBACK_MOCK_H

#include <gmock/gmock.h>

#include "lnn_async_callback_utils.h"

namespace OHOS {
class LnnAsyncCallbackInterface {
public:
    LnnAsyncCallbackInterface() {};
    virtual ~LnnAsyncCallbackInterface() {};

    virtual int32_t LnnAsyncCallbackHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para) = 0;
    virtual int32_t LnnAsyncCallbackDelayHelper(
        SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis) = 0;
};

class LnnAsyncCallbackInterfaceMock : public LnnAsyncCallbackInterface {
public:
    LnnAsyncCallbackInterfaceMock();
    ~LnnAsyncCallbackInterfaceMock() override;

    MOCK_METHOD3(LnnAsyncCallbackHelper, int32_t(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para));
    MOCK_METHOD4(LnnAsyncCallbackDelayHelper,
        int32_t(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis));
};
} // namespace OHOS
#endif // AUTH_CONNECTION_MOCK_H