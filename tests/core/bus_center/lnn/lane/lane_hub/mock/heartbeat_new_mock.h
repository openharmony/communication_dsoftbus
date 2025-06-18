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

#ifndef HEARTBEAT_NEW_MOCK_H
#define HEARTBEAT_NEW_MOCK_H

#include <gmock/gmock.h>
#include <regex.h>

#include "message_handler.h"
#include "lnn_async_callback_utils_struct.h"

namespace OHOS {
class HeartBeatNewInterface {
public:
    HeartBeatNewInterface() {};
    virtual ~HeartBeatNewInterface() {};
    virtual int32_t LnnAsyncCallbackDelayHelper(
        SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis) = 0;
};

class HeartBeatNewInterfaceMock : public HeartBeatNewInterface {
public:
    HeartBeatNewInterfaceMock();
    ~HeartBeatNewInterfaceMock() override;
    MOCK_METHOD4(LnnAsyncCallbackDelayHelper, int32_t (SoftBusLooper *, LnnAsyncCallbackFunc, void *, uint64_t));
};

extern "C" {
    int32_t LnnAsyncCallbackDelayHelper(
        SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis);
}
} // namespace OHOS
#endif // HEARTBEAT_NEW_MOCK_H