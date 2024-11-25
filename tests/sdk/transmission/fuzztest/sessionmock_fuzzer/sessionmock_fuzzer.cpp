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

#include "securec.h"
#include "session.h"
#include "session_mock.h"
#include <cstddef>
#include <cstdint>

#define SESSION_NAME_SIZE_MAX 256
#define DEVICE_ID_SIZE_MAX    65
#define GROUP_ID_SIZE_MAX     65

namespace OHOS {
void CreateSessionServerInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t) || size >= SESSION_NAME_SIZE_MAX) {
        return;
    }
    char mySessionName[SESSION_NAME_SIZE_MAX] = {0};
    if (memcpy_s(mySessionName, SESSION_NAME_SIZE_MAX, data, size) != EOK) {
        return;
    }
    CreateSessionServerInner(nullptr, mySessionName);
}

void RemoveSessionServerInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t) || size >= SESSION_NAME_SIZE_MAX) {
        return;
    }
    char mySessionName[SESSION_NAME_SIZE_MAX] = {0};
    if (memcpy_s(mySessionName, SESSION_NAME_SIZE_MAX, data, size) != EOK) {
        return;
    }
    RemoveSessionServerInner(nullptr, mySessionName);
}

void OpenSessionInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t) || size >= GROUP_ID_SIZE_MAX) {
        return;
    }
    char mySessionName[SESSION_NAME_SIZE_MAX] = {0};
    char peerSessionName[SESSION_NAME_SIZE_MAX] = {0};
    char peerNetworkId[DEVICE_ID_SIZE_MAX] = {0};
    char groupId[GROUP_ID_SIZE_MAX] = {0};
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
    OpenSessionInner(mySessionName, peerSessionName, peerNetworkId, groupId, size);
}

void CloseSessionInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    int32_t sessionId = *(reinterpret_cast<const int32_t *>(data));
    CloseSessionInner(sessionId);
}

void GrantPermissionInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    int32_t uid = *(reinterpret_cast<const int32_t *>(data));
    int32_t pid = *(reinterpret_cast<const int32_t *>(data));
    GrantPermissionInner(uid, pid, nullptr);
}

void RemovePermissionInnerTest(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;

    RemovePermissionInner(nullptr);
}

void SendBytesInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    int32_t sessionId = *(reinterpret_cast<const int32_t *>(data));
    char *tmp = const_cast<char *>(reinterpret_cast<const char *>(data));
    SendBytesInner(sessionId, tmp, size);
}

void GetPeerUidInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    int32_t sessionId = *(reinterpret_cast<const int32_t *>(data));
    int32_t *tmp = const_cast<int32_t *>(reinterpret_cast<const int32_t *>(data));
    GetPeerUidInner(sessionId, tmp);
}

void GetPeerPidInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    int32_t sessionId = *(reinterpret_cast<const int32_t *>(data));
    int32_t *tmp = const_cast<int32_t *>(reinterpret_cast<const int32_t *>(data));
    GetPeerPidInner(sessionId, tmp);
}

void IsServerSideInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    int32_t sessionId = *(reinterpret_cast<const int32_t *>(data));
    int32_t *tmp = const_cast<int32_t *>(reinterpret_cast<const int32_t *>(data));
    IsServerSideInner(sessionId, tmp);
}

void GetMySessionNameInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    int32_t sessionId = *(reinterpret_cast<const int32_t *>(data));
    char *tmp = const_cast<char *>(reinterpret_cast<const char *>(data));
    GetMySessionNameInner(sessionId, tmp, size);
}

void GetPeerSessionNameInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    int32_t sessionId = *(reinterpret_cast<const int32_t *>(data));
    char *tmp = const_cast<char *>(reinterpret_cast<const char *>(data));
    GetPeerSessionNameInner(sessionId, tmp, size);
}

void GetPeerDeviceIdInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    int32_t sessionId = *(reinterpret_cast<const int32_t *>(data));
    char *tmp = const_cast<char *>(reinterpret_cast<const char *>(data));
    GetPeerDeviceIdInner(sessionId, tmp, size);
}

void GetPkgNameInnerTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    int32_t sessionId = *(reinterpret_cast<const int32_t *>(data));
    char *tmp = const_cast<char *>(reinterpret_cast<const char *>(data));
    GetPkgNameInner(sessionId, tmp, size);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CreateSessionServerInnerTest(data, size);
    OHOS::RemoveSessionServerInnerTest(data, size);
    OHOS::OpenSessionInnerTest(data, size);
    OHOS::CloseSessionInnerTest(data, size);
    OHOS::GrantPermissionInnerTest(data, size);
    OHOS::RemovePermissionInnerTest(data, size);
    OHOS::SendBytesInnerTest(data, size);
    OHOS::GetPeerUidInnerTest(data, size);
    OHOS::GetPeerPidInnerTest(data, size);
    OHOS::IsServerSideInnerTest(data, size);
    OHOS::GetMySessionNameInnerTest(data, size);
    OHOS::GetPeerSessionNameInnerTest(data, size);
    OHOS::GetPeerDeviceIdInnerTest(data, size);
    OHOS::GetPkgNameInnerTest(data, size);
    return 0;
}
