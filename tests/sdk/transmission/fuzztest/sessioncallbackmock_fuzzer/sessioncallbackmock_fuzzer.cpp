/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "sessioncallbackmock_fuzzer.h"
#include "session_callback_mock.h"
#include "softbus_error_code.h"
#include "session.h"
#include "session_mock.h"
#include <cstddef>
#include <cstdint>

#define SESSION_ID 1

namespace OHOS {
    void InnerOnSessionOpenedTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        int result = SOFTBUS_OK;

        InnerOnSessionOpened(size, result);
    }

    void InnerOnSessionClosedTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }

        InnerOnSessionClosed(size);
    }

    void InnerOnBytesReceivedTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        int sessionId = SESSION_ID;

        InnerOnBytesReceived(sessionId, data, size);
    }

    void InnerOnMessageReceivedTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        int sessionId = SESSION_ID;

        InnerOnMessageReceived(sessionId, data, size);
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::InnerOnSessionOpenedTest(data, size);
    OHOS::InnerOnSessionClosedTest(data, size);
    OHOS::InnerOnBytesReceivedTest(data, size);
    OHOS::InnerOnMessageReceivedTest(data, size);
    return 0;
}
