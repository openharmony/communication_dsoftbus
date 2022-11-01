/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "clienttranssessionservice_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include "dfs_session.h"
#include "session.h"
#include "client_trans_session_service.h"

namespace OHOS {
    void GetSessionKeyTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }

        unsigned int len = *(reinterpret_cast<const uint32_t*>(size));
        int32_t sessionId = *(reinterpret_cast<const int32_t*>(size));
        char tmp = *(reinterpret_cast<const char*>(data));
        GetSessionKey(sessionId, &tmp, len);
    }

    void GetSessionHandleTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        int handle = 1;
        int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
        GetSessionHandle(sessionId, &handle);
    }

    void DisableSessionListenerTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
        DisableSessionListener(sessionId);
    }

    void OpenSessionSyncTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        #define SESSION_NAME_SIZE_MAX 256
        #define DEVICE_ID_SIZE_MAX 65
        #define GROUP_ID_SIZE_MAX 65
        char mySessionName[SESSION_NAME_SIZE_MAX] = "ohos.fuzz.dms.test";
        char peerSessionName[SESSION_NAME_SIZE_MAX] = "ohos.fuzz.dms.test";
        char peerNetworkId[DEVICE_ID_SIZE_MAX] = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
        SessionAttribute attr = {
            .dataType = TYPE_BYTES,
        };
        char groupId[GROUP_ID_SIZE_MAX] = "TEST_GROUP_ID";
        OpenSessionSync(mySessionName, peerSessionName, peerNetworkId, groupId, &attr);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetSessionKeyTest(data, size);
    OHOS::GetSessionHandleTest(data, size);
    OHOS::DisableSessionListenerTest(data, size);
    OHOS::OpenSessionSyncTest(data, size);
    return 0;
}

