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

#include "clienttranssessionmanager_fuzzer.h"

#include "client_trans_session_manager.h"
#include "session.h"
#include "softbus_trans_def.h"

namespace OHOS {
static int OnSessionOpened(int sessionId, int result)
{
    return 0;
}
static void OnSessionClosed(int sessionId) {}

static void OnBytesReceived(int sessionId, const void* data, unsigned int len) {}

static void OnMessageReceived(int sessionId, const void* data, unsigned int len) {}

static ISessionListener g_sessionlistener = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnBytesReceived = OnBytesReceived,
    .OnMessageReceived = OnMessageReceived,
};

void ClientAddNewSessionTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    const char* testSessionName = reinterpret_cast<const char*>(data);
    SessionInfo session;
    ClientAddNewSession(testSessionName, &session);
}

void ClientAddAuthSessionTest(const uint8_t* data, size_t size)
{
    #define SESSION_NAME_SIZE_MAX 256
    if ((data == nullptr) || (size < SESSION_NAME_SIZE_MAX)) {
        return;
    }
    int32_t sessionId;
    ClientAddAuthSession(nullptr, &sessionId);
}

void ClientDeleteSessionTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
    ClientDeleteSession(sessionId);
}

void ClientGetSessionDataTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
    char* testData = const_cast<char*>(reinterpret_cast<const char*>(data));
    int* testInt = const_cast<int*>(reinterpret_cast<const int*>(data));
    ClientGetSessionDataById(sessionId, testData, size, KEY_SESSION_NAME);
    ClientGetSessionIntegerDataById(sessionId, testInt, KEY_SESSION_NAME);
    ClientGetSessionSide(sessionId);
}

void ClientSetChannelBySessionIdTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
    TransInfo transInfo = {
        .channelId = 0,
        .channelType = 0,
    };

    ClientSetChannelBySessionId(sessionId, &transInfo);
}

void ClientGetSessionCallbackTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
    const char* testSessionName = reinterpret_cast<const char*>(data);

    ClientGetSessionCallbackById(sessionId, &g_sessionlistener);
    ClientGetSessionCallbackByName(testSessionName, &g_sessionlistener);
}

void ClientTransOnLinkDownTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    const char* netWorkId = reinterpret_cast<const char*>(data);
    int32_t routeType = *(reinterpret_cast<const int32_t*>(data));

    ClientTransOnLinkDown(netWorkId, routeType);
}

void ClientRemovePermissionTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    ClientRemovePermission(nullptr);
}

void ClientGetFileConfigInfoByIdTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
    int32_t* fileEncrypt = const_cast<int32_t*>(reinterpret_cast<const int32_t*>(data));
    ClientGetFileConfigInfoById(sessionId, fileEncrypt, fileEncrypt, fileEncrypt);
}

void GetEncryptByChannelIdTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t channelId = *(reinterpret_cast<const int32_t*>(data));
    int32_t channelType = *(reinterpret_cast<const int32_t*>(data));
    int32_t encryp = 0;
    GetEncryptByChannelId(channelId, channelType, &encryp);
}

void ClientGetSessionIdByChannelIdTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t channelId = *(reinterpret_cast<const int32_t*>(data));
    int32_t channelType = *(reinterpret_cast<const int32_t*>(data));
    int32_t sessionId;
    ClientGetSessionIdByChannelId(channelId, channelType, &sessionId);
}

void ClientEnableSessionByChannelIdTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    ChannelInfo channel;
    int32_t sessionId;
    ClientEnableSessionByChannelId(&channel, &sessionId);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::ClientAddNewSessionTest(data, size);
    OHOS::ClientAddAuthSessionTest(data, size);
    OHOS::ClientDeleteSessionTest(data, size);
    OHOS::ClientGetSessionDataTest(data, size);
    OHOS::ClientSetChannelBySessionIdTest(data, size);
    OHOS::ClientGetSessionCallbackTest(data, size);
    OHOS::ClientTransOnLinkDownTest(data, size);
    OHOS::ClientRemovePermissionTest(data, size);
    OHOS::ClientGetFileConfigInfoByIdTest(data, size);
    OHOS::GetEncryptByChannelIdTest(data, size);
    OHOS::ClientGetSessionIdByChannelIdTest(data, size);
    OHOS::ClientEnableSessionByChannelIdTest(data, size);
    return 0;
}
