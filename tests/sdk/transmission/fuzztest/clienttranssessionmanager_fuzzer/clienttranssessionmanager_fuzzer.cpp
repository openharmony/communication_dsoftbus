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
#include "client_trans_socket_manager.h"
#include "fuzz_data_generator.h"
#include "session.h"
#include "softbus_trans_def.h"

namespace OHOS {
static int32_t OnSessionOpened(int32_t sessionId, int32_t result)
{
    return 0;
}
static void OnSessionClosed(int32_t sessionId) {}

static void OnBytesReceived(int32_t sessionId, const void* data, unsigned int len) {}

static void OnMessageReceived(int32_t sessionId, const void* data, unsigned int len) {}

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
    const char* testSessionName = reinterpret_cast<const char *>(data);
    SessionInfo session;
    ClientAddNewSession(testSessionName, &session);
}

void ClientAddAuthSessionTest(const uint8_t* data, size_t size)
{
    #define SESSION_NAME_SIZE_MAX 256
    if ((data == nullptr) || (size < SESSION_NAME_SIZE_MAX)) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t sessionId = 0;
    GenerateInt32(sessionId);
    ClientAddAuthSession(nullptr, &sessionId);
    DataGenerator::Clear();
}

void ClientDeleteSessionTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t sessionId = 0;
    GenerateInt32(sessionId);
    ClientDeleteSession(sessionId);
    DataGenerator::Clear();
}

void ClientGetSessionDataTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t) + sizeof(int))) {
        return;
    }
    uint32_t offset = 0;
    int32_t sessionId = *(reinterpret_cast<const int32_t *>(data));
    offset += sizeof(int32_t);
    char* testData = const_cast<char*>(reinterpret_cast<const char *>(data));
    int* testInt = const_cast<int*>(reinterpret_cast<const int *>(data + offset));
    ClientGetSessionDataById(sessionId, testData, size, KEY_SESSION_NAME);
    ClientGetSessionIntegerDataById(sessionId, testInt, KEY_SESSION_NAME);
    ClientGetSessionSide(sessionId);
}

void ClientSetChannelBySessionIdTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t sessionId = 0;
    GenerateInt32(sessionId);
    TransInfo transInfo = {
        .channelId = 0,
        .channelType = 0,
    };

    ClientSetChannelBySessionId(sessionId, &transInfo);
    DataGenerator::Clear();
}

void ClientGetSessionCallbackTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t sessionId = 0;
    GenerateInt32(sessionId);
    const char* testSessionName = reinterpret_cast<const char *>(data);

    ClientGetSessionCallbackById(sessionId, &g_sessionlistener);
    ClientGetSessionCallbackByName(testSessionName, &g_sessionlistener);
    DataGenerator::Clear();
}

void ClientTransOnLinkDownTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t routeType = 0;
    GenerateInt32(routeType);
    const char* netWorkId = reinterpret_cast<const char *>(data);

    ClientTransOnLinkDown(netWorkId, routeType);
    DataGenerator::Clear();
}

void ClientRemovePermissionTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    ClientRemovePermission(nullptr);
}

void ClientGetFileConfigInfoByIdTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t sessionId = 0;
    int32_t fileEncrypt = 0;
    GenerateInt32(sessionId);
    GenerateInt32(fileEncrypt);
    ClientGetFileConfigInfoById(sessionId, &fileEncrypt, &fileEncrypt, &fileEncrypt);
    DataGenerator::Clear();
}

void GetEncryptByChannelIdTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    int32_t channelType = 0;
    GenerateInt32(channelId);
    GenerateInt32(channelType);
    int32_t encryp = 0;
    GetEncryptByChannelId(channelId, channelType, &encryp);
    DataGenerator::Clear();
}

void ClientGetSessionIdByChannelIdTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    DataGenerator::Write(data, size);
    int32_t channelId = 0;
    int32_t channelType = 0;
    GenerateInt32(channelId);
    GenerateInt32(channelType);
    int32_t sessionId;
    bool isClosing = false;
    ClientGetSessionIdByChannelId(channelId, channelType, &sessionId, isClosing);
    DataGenerator::Clear();
}

void ClientEnableSessionByChannelIdTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    ChannelInfo channel;
    DataGenerator::Write(data, size);
    int32_t sessionId = 0;
    GenerateInt32(sessionId);
    ClientEnableSessionByChannelId(&channel, &sessionId);
    DataGenerator::Clear();
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
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
