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
#include <benchmark/benchmark.h>
#include <cstring>
#include <ctime>
#include <securec.h>
#include <string>
#include <unordered_set>
#include <unistd.h>
#include "nativetoken_kit.h"
#include "session.h"
#include "softbus_common.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"


namespace OHOS {
const char *g_pkgName = "dms";
char g_sessionName[] = "ohos.distributedschedule.dms.test";
char g_networkid[] = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";

const char *RECV_ROOT_PATH = "/data/";
static bool flag = true;

static void AddPermission()
{
    if (flag) {
        uint64_t tokenId;
        const char *perms[2];
        perms[0] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
        perms[1] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
        NativeTokenInfoParams infoInstance = {
            .dcapsNum = 0,
            .permsNum = 2,
            .aclsNum = 0,
            .dcaps = NULL,
            .perms = perms,
            .acls = NULL,
            .processName = "dms",
            .aplStr = "normal",
        };
        tokenId = GetAccessTokenId(&infoInstance);
        SetSelfTokenID(tokenId);
        OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
        flag = false;
    }
}

int32_t OnSendFileProcess(int32_t sessionId, uint64_t bytesUpload, uint64_t bytesTotal)
{
    return 0;
}

int32_t OnSendFileFinished(int32_t sessionId, const char *firstFile)
{
    return 0;
}

void OnFileTransError(int32_t sessionId)
{}

static IFileSendListener g_fileSendListener = {
    .OnSendFileProcess = OnSendFileProcess,
    .OnSendFileFinished = OnSendFileFinished,
    .OnFileTransError = OnFileTransError,
};

int32_t OnReceiveFileStarted(int32_t sessionId, const char *files, int32_t fileCnt)
{
    return 0;
}

void OnReceiveFileFinished(int32_t sessionId, const char *files, int32_t fileCnt)
{}

int32_t OnReceiveFileProcess(int32_t sessionId, const char *firstFile, uint64_t bytesUpload, uint64_t bytesTotal)
{
    return 0;
}
static const IFileReceiveListener g_fileRecvListener = {
    .OnReceiveFileStarted = OnReceiveFileStarted,
    .OnReceiveFileFinished = OnReceiveFileFinished,
    .OnReceiveFileProcess = OnReceiveFileProcess,
    .OnFileTransError = OnFileTransError,
};

class TransTest : public benchmark::Fixture {
public:
    TransTest()
    {
        Iterations(iterations);
        Repetitions(repetitions);
        ReportAggregatesOnly();
    }
    ~TransTest() override = default;
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(const ::benchmark::State &state) override
    {
        AddPermission();
    }

protected:
    const int32_t repetitions = 3;
    const int32_t iterations = 1000;
};

void TransTest::SetUpTestCase(void)
{}

void TransTest::TearDownTestCase(void)
{}

static int32_t OnSessionOpened(int32_t sessionId, int32_t result)
{
    return 0;
}

static void OnSessionClosed(int32_t sessionId)
{}

static void OnBytesReceived(int32_t sessionId, const void *data, unsigned int len)
{}

static void OnMessageReceived(int32_t sessionId, const void *data, unsigned int len)
{}

static ISessionListener g_sessionlistener = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnBytesReceived = OnBytesReceived,
    .OnMessageReceived = OnMessageReceived,
};


/**
 * @tc.name: CreateSessionServerTestCase
 * @tc.desc: CreateSessionServer Performance Testing
 * @tc.type: FUNC
 * @tc.require: CreateSessionServer normal operation
 */
BENCHMARK_F(TransTest, CreateSessionServerTestCase)(benchmark::State &state)
{
    while (state.KeepRunning()) {
        int32_t ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
        if (ret != 0) {
            state.SkipWithError("CreateSessionServerTestCase failed.");
        }
        state.PauseTiming();
        RemoveSessionServer(g_pkgName, g_sessionName);
        state.ResumeTiming();
    }
}
BENCHMARK_REGISTER_F(TransTest, CreateSessionServerTestCase);

/**
 * @tc.name:RemoveSessionServerTestCase
 * @tc.desc: RemoveSessionServer Performance Testing
 * @tc.type: FUNC
 * @tc.require: RemoveSessionServer normal operation
 */
BENCHMARK_F(TransTest, RemoveSessionServerTestCase)(benchmark::State &state)
{
    while (state.KeepRunning()) {
        state.PauseTiming();
        int32_t ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
        state.ResumeTiming();
        ret = RemoveSessionServer(g_pkgName, g_sessionName);
        if (ret != 0) {
            state.SkipWithError("RemoveSessionServerTestCase failed.");
        }
    }
}
BENCHMARK_REGISTER_F(TransTest, RemoveSessionServerTestCase);

/**
 * @tc.name: SetFileReceiveListenerTestCase
 * @tc.desc: SetFileReceiveListener Performance Testing
 * @tc.type: FUNC
 * @tc.require: SetFileReceiveListener normal operation
 */
BENCHMARK_F(TransTest, SetFileReceiveListenerTestCase)(benchmark::State &state)
{
    while (state.KeepRunning()) {
        state.PauseTiming();
        int32_t ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
        state.ResumeTiming();
        ret = SetFileReceiveListener(g_pkgName, g_sessionName,  &g_fileRecvListener, RECV_ROOT_PATH);
        if (ret != 0) {
            state.SkipWithError("SetFileReceiveListenerTestCase failed");
        }
        state.PauseTiming();
        RemoveSessionServer(g_pkgName, g_sessionName);
    }
}
BENCHMARK_REGISTER_F(TransTest, SetFileReceiveListenerTestCase);

/**
 * @tc.name: SetFileSendListenerTestCase
 * @tc.desc: SetFileSendListener Performance Testing
 * @tc.type: FUNC
 * @tc.require: SetFileSendListener normal operation
 */
BENCHMARK_F(TransTest, SetFileSendListenerTestCase)(benchmark::State &state)
{
    while (state.KeepRunning()) {
        state.PauseTiming();
        int32_t ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
        state.ResumeTiming();
        ret = SetFileSendListener(g_pkgName, g_sessionName,  &g_fileSendListener);
        if (ret != 0) {
            state.SkipWithError("SetFileSendListenerTestCase failed");
        }
        state.PauseTiming();
        RemoveSessionServer(g_pkgName, g_sessionName);
    }
}
BENCHMARK_REGISTER_F(TransTest, SetFileSendListenerTestCase);
} // namespace OHOS

// Run the benchmark
BENCHMARK_MAIN();