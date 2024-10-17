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

#include "test_suite.h"

#include <getopt.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <sys/time.h>
#include <sys/times.h>
#include <ctime>
#include <unistd.h>
#include <cinttypes>

#include "transport/session.h"
#include "softbus_error_code.h"

volatile bool g_sessionEnabled = false;
int32_t g_sessionId = -1;

static int32_t EsOnSessionOpened(int32_t sessionId, int32_t result)
{
    LOG("%s:enter", __func__);
    if (result != SOFTBUS_OK) {
        LOG("%s:OpenSession failed!errCode=%d", __func__, result);
        return 0;
    }
    if (sessionId == g_sessionId) {
        LOG("%s:Session %d opened!", __func__, sessionId);
        g_sessionEnabled = true;
    }
    LOG("%s:Unexpected session %d opened!", __func__, sessionId);
    return 0;
}

static void EsOnSessionClosed(int32_t sessionId)
{
    LOG("%s:enter", __func__);
    if (sessionId == g_sessionId) {
        g_sessionEnabled = false;
        g_sessionId = -1;
    }
}

static int32_t TsOnReceiveFileStarted(int32_t sessionId, const char *files, int32_t fileCnt)
{
    LOG("%s:session=%d, files=%s, count=%d", __func__, sessionId, files, fileCnt);
    return 0;
}

static int32_t TsOnReceiveFileProcess(int32_t sessionId, const char *firstFile,
                                      uint64_t bytesUpload, uint64_t bytesTotal)
{
    LOG("%s:session=%d, firstFile=%s, bytesUpload=%" PRIu64 ", bytesTotal=%" PRIu64, __func__, sessionId, firstFile,
        bytesUpload, bytesTotal);
    return 0;
}
static void TsOnReceiveFileFinished(int32_t sessionId, const char *files, int32_t fileCnt)
{
    LOG("%s:session=%d, files=%s, count=%d", __func__, sessionId, files, fileCnt);
}
static void TsOnFileTransError(int32_t sessionId)
{
    LOG("%s:session=%d", __func__, sessionId);
}

static int32_t ExecTestSuite(void)
{
    static ISessionListener listener = {.OnSessionOpened = EsOnSessionOpened,
        .OnSessionClosed = EsOnSessionClosed,
        .OnBytesReceived = EsOnDataReceived,
        .OnMessageReceived = EsOnDataReceived,
        .OnStreamReceived = EsOnStreamReceived,
        .OnQosEvent = EsOnQosEvent};

    int32_t ret = CreateSessionServer(ECHO_SERVICE_PKGNAME, ECHO_SERVICE_SESSION_NAME, &listener);
    if (ret != SOFTBUS_OK) {
        LOG("%s:create session server failed!ret=%d", __func__, ret);
        return ret;
    }

    static IFileReceiveListener fileRecvListener = {
        .OnReceiveFileStarted = TsOnReceiveFileStarted,
        .OnReceiveFileProcess = TsOnReceiveFileProcess,
        .OnReceiveFileFinished = TsOnReceiveFileFinished,
        .OnFileTransError = TsOnFileTransError,
    };

    ret =
        SetFileReceiveListener(ECHO_SERVICE_PKGNAME, ECHO_SERVICE_SESSION_NAME, &fileRecvListener, "/data/recv_files");
    if (ret != SOFTBUS_OK) {
        LOG("%s:set file receive listener failed! ret=%d", __func__, ret);
        return ret;
    }

    LOG("type x to exit:");
    char c = '0';
    do {
        c = getchar();
    } while (c != 'x');

    ret = RemoveSessionServer(ECHO_SERVICE_PKGNAME, ECHO_SERVICE_SESSION_NAME);
    if (ret != SOFTBUS_OK) {
        LOG("%s: remove session server failed! ret= %d", __func__, ret);
    }

    return ret;
}

int32_t main(int32_t argc, char * const *argv)
{
    LOG("%s:started", __func__);

    int32_t ret = ExecTestSuite();
    if (ret != SOFTBUS_OK) {
        LOG("%s:test failed!ret=%d", __func__, ret);
    }
    return ret;
}
