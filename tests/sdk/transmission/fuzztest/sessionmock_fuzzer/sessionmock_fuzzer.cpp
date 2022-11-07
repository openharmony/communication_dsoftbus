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

#include "sessionmock_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include "session_mock.h"
#include "session.h"

namespace OHOS {
    void GetPkgNameInnerTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int32_t))) {
            return;
        }
        int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
        char *tmp = const_cast<char*>(reinterpret_cast<const char*>(data));
        GetPkgNameInner(sessionId, tmp, size);
    }

    void GetPeerDeviceIdInnerTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int32_t))) {
            return;
        }
        int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
        char *tmp = const_cast<char*>(reinterpret_cast<const char*>(data));
        GetPeerDeviceIdInner(sessionId, tmp, size);
    }

    void GetPeerSessionNameInnerTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int32_t))) {
            return;
        }

        int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
        char *tmp = const_cast<char*>(reinterpret_cast<const char*>(data));
        GetPeerSessionNameInner(sessionId, tmp, size);
    }

    void GetMySessionNameInnerTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int32_t))) {
            return;
        }
        int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
        char *tmp = const_cast<char*>(reinterpret_cast<const char*>(data));
        GetMySessionNameInner(sessionId, tmp, size);
    }

    void IsServerSideInnerTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int32_t))) {
            return;
        }
        int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
        int *tmp = const_cast<int*>(reinterpret_cast<const int*>(data));
        IsServerSideInner(sessionId, tmp);
    }

    void GetPeerPidInnerTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int32_t))) {
            return;
        }
        int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
        int *tmp = const_cast<int*>(reinterpret_cast<const int*>(data));
        GetPeerPidInner(sessionId, tmp);
    }

    void GetPeerUidInnerTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int32_t))) {
            return;
        }
        int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
        int *tmp = const_cast<int*>(reinterpret_cast<const int*>(data));
        GetPeerUidInner(sessionId, tmp);
    }

    void SendBytesInnerTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int32_t))) {
            return;
        }
        int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
        char *tmp = const_cast<char*>(reinterpret_cast<const char*>(data));
        SendBytesInner(sessionId, tmp, size);
    }

    void RemovePermissionInnerTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        RemovePermissionInner(nullptr);
    }

    void CloseSessionInnerTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int32_t))) {
            return;
        }
        int sessionId = *(reinterpret_cast<const int32_t*>(data));
        CloseSessionInner(sessionId);
    }

    void OpenSessionInnerTest(const uint8_t* data, size_t size)
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
        char groupId[GROUP_ID_SIZE_MAX] = "TEST_GROUP_ID";
        OpenSessionInner(mySessionName, peerSessionName, peerNetworkId, groupId, size);
    }

    void RemoveSessionServerInnerTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        #define SESSION_NAME_SIZE_MAX 256
        char mySessionName[SESSION_NAME_SIZE_MAX] = "ohos.fuzz.dms.test";
        RemoveSessionServerInner(nullptr, mySessionName);
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetPkgNameInnerTest(data, size);
    OHOS::GetPeerDeviceIdInnerTest(data, size);
    OHOS::GetPeerSessionNameInnerTest(data, size);
    OHOS::GetMySessionNameInnerTest(data, size);
    OHOS::IsServerSideInnerTest(data, size);
    OHOS::GetPeerPidInnerTest(data, size);
    OHOS::GetPeerUidInnerTest(data, size);
    OHOS::SendBytesInnerTest(data, size);
    OHOS::RemovePermissionInnerTest(data, size);
    OHOS::CloseSessionInnerTest(data, size);
    OHOS::OpenSessionInnerTest(data, size);
    OHOS::RemoveSessionServerInnerTest(data, size);
    return 0;
}
