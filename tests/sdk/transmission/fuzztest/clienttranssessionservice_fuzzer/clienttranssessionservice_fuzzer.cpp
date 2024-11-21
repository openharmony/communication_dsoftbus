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
#include <securec.h>
#include "dfs_session.h"
#include "session.h"
#include "client_trans_session_service.h"

namespace OHOS {
    void GetSessionKeyTest(const uint8_t* data, size_t size)
    {
        #define SESSION_KEY_LENGTH 32
        if ((data == nullptr) || (size < sizeof(int32_t))) {
            return;
        }
        if (size > SESSION_KEY_LENGTH) {
            return;
        }
        unsigned int len = SESSION_KEY_LENGTH;
        int32_t sessionId = *(reinterpret_cast<const int32_t *>(data));
        char tmp[SESSION_KEY_LENGTH + 1] = {0};
        if (memcpy_s(tmp, sizeof(tmp) - 1, data, size) != EOK) {
            return;
        }
        GetSessionKey(sessionId, tmp, len);
    }

    void GetSessionHandleTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int32_t))) {
            return;
        }
        int32_t handle = 1;
        int32_t sessionId = *(reinterpret_cast<const int32_t *>(data));
        GetSessionHandle(sessionId, &handle);
    }

    void DisableSessionListenerTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int32_t))) {
            return;
        }
        int32_t sessionId = *(reinterpret_cast<const int32_t *>(data));
        DisableSessionListener(sessionId);
    }

    void OpenSessionSyncTest(const uint8_t* data, size_t size)
    {
        #define SESSION_NAME_SIZE_MAX 256
        #define DEVICE_ID_SIZE_MAX 65
        #define GROUP_ID_SIZE_MAX 65
        if (data == nullptr || size >= GROUP_ID_SIZE_MAX) {
            return;
        }
        char mySessionName[SESSION_NAME_SIZE_MAX] = {0};
        char peerSessionName[SESSION_NAME_SIZE_MAX] = {0};
        char peerNetworkId[DEVICE_ID_SIZE_MAX] = {0};
        char groupId[GROUP_ID_SIZE_MAX] = {0};
        SessionAttribute attr = {
            .dataType = TYPE_BYTES,
        };
        if (memcpy_s(mySessionName, SESSION_NAME_SIZE_MAX, data, size) != EOK) {
            return;
        }
        if (memcpy_s(peerSessionName, SESSION_NAME_SIZE_MAX, data, size) != EOK) {
            return;
        }
        if (memcpy_s(peerNetworkId, DEVICE_ID_SIZE_MAX, data, size) != EOK) {
            return;
        }
        if (memcpy_s(groupId, GROUP_ID_SIZE_MAX, data, size) != EOK) {
            return;
        }
        OpenSessionSync(mySessionName, peerSessionName, peerNetworkId, groupId, &attr);
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetSessionKeyTest(data, size);
    OHOS::GetSessionHandleTest(data, size);
    OHOS::DisableSessionListenerTest(data, size);
    OHOS::OpenSessionSyncTest(data, size);
    return 0;
}
