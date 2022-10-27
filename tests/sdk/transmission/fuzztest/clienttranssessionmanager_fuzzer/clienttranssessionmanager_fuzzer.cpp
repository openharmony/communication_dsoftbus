/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <cstddef>
#include <cstdint>
#include "session.h"
#include "softbus_utils.h"
#include "client_trans_session_manager.h"
#include "softbus_trans_def.h"

namespace OHOS {
static int OnSessionOpened(int sessionId, int result)
{
    return 0;
}
static void OnSessionClosed(int sessionId) {}

static void OnBytesReceived(int sessionId, const void *data, unsigned int len) {}

static void OnMessageReceived(int sessionId, const void *data, unsigned int len) {}

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
    const char *testSessionName   = "testsessionname";
    SessionInfo session;
    ClientAddNewSession(testSessionName, &session);
}

void ClientAddAuthSessionTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    const char *testSessionName   = "testsessionname";
    int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
    ClientAddAuthSession(testSessionName, &sessionId);
}

void ClientDeleteSessionTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
    ClientDeleteSession(sessionId);
}

void ClientGetSessionDataTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
    ClientGetSessionDataById(sessionId, (char *)data, size, KEY_SESSION_NAME);
    ClientGetSessionIntegerDataById(sessionId, (int *)data, KEY_SESSION_NAME);
    ClientGetSessionSide(sessionId);
}

void ClientSetChannelBySessionIdTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
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
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
    const char *testSessionName   = "testsessionname";

    ClientGetSessionCallbackById(sessionId, &g_sessionlistener);
    ClientGetSessionCallbackByName(testSessionName, &g_sessionlistener);
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
    return 0;
}

