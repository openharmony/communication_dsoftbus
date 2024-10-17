/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cinttypes>
#include <chrono>
#include <thread>
#include <gtest/gtest.h>
#include "common.h"
#include "session.h"
#include "tmessenger.h"

#define SERVER_IDLE_WAIT_TIME 5

using namespace testing::ext;

namespace OHOS {
std::mutex g_recvMutex;
static std::string g_recvData;

class StreamEncryptServerMt : public testing::Test {
public:
    StreamEncryptServerMt() { }
    ~StreamEncryptServerMt() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void StreamEncryptServerMt::SetUpTestCase(void)
{
    int32_t ret = TestInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TMessenger::GetInstance().Open(PKG_NAME, TEST_NOTIFY_SRV_NAME, "", true);
    ASSERT_EQ(ret, SOFTBUS_OK);
}

void StreamEncryptServerMt::TearDownTestCase(void)
{
    int32_t ret = TestDeInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    TMessenger::GetInstance().Close();
}

void OnBindServer(int32_t socket, PeerSocketInfo info)
{
    LOGI(">> OnBind {socket:%d, name:%s, networkId:%s, pkgName:%s, dataType:%d}", socket, info.name, info.networkId,
        info.pkgName, info.dataType);
}

void OnShutdownServer(int32_t socket, ShutdownReason reason)
{
    LOGI(">> OnOnShutdown {socket:%d, reason:%d}", socket, reason);
}

static void OnStreamReceived(int32_t sessionId, const char *testCaseName, const StreamData *data)
{
    if (sessionId <= 0) {
        LOGI(">> OnStreamReceived, invalid sessionId=%d", sessionId);
        return;
    }

    if (testCaseName == nullptr) {
        LOGI(">> OnStreamReceived, testCaseName is nullptr, sessionId=%d", sessionId);
        return;
    }

    if (data == nullptr) {
        LOGI(">> OnStreamReceived, data is nullptr, sessionId:%d", sessionId);
        return;
    }

    LOGI(">> OnStreamReceived, sessionId:%d", sessionId);
    LOGI(">> OnStreamReceived, testCaseName:%s", testCaseName);
    LOGI(">> OnStreamReceived, buf:%s", (data->buf != NULL ? data->buf : "null"));
    LOGI(">> OnStreamReceived, bufLen:%d", data->bufLen);

    std::lock_guard<std::mutex> lock(g_recvMutex);
    g_recvData = std::string((char *)data->buf, data->bufLen);
}

static void OnStreamReceivedWithNoDataType(
    int32_t socket, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{
    OnStreamReceived(socket, "RawStreamEncryptTestServer001", data);
}

static QosTV g_qosInfo[] = {
    { .qos = QOS_TYPE_MIN_BW,      .value = 80   },
    { .qos = QOS_TYPE_MAX_LATENCY, .value = 4000 },
    { .qos = QOS_TYPE_MIN_LATENCY, .value = 2000 },
};

/*
 * @tc.name: RawStreamEncryptTestServer001
 * @tc.desc: Unencrypted raw stream data transmission test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamEncryptServerMt, RawStreamEncryptTestServer001, TestSize.Level1)
{
    /**
     * @tc.steps: step 1. do not set dataType and create socket by 'Socket' function.
     * @tc.expect: socket greater zero.
     */
    SocketInfo info = {
        .name = (char *)TEST_SESSION_NAME_SRV,
        .pkgName = (char *)PKG_NAME,
    };
    int32_t socket = Socket(info);
    ASSERT_GT(socket, 0);

    ISocketListener listener = {
        .OnBind = OnBindServer,
        .OnShutdown = OnShutdownServer,
        .OnBytes = NULL,
        .OnMessage = NULL,
        .OnStream = OnStreamReceivedWithNoDataType,
        .OnFile = NULL,
        .OnQos = NULL,
    };

    int32_t ret = Listen(socket, g_qosInfo, sizeof(g_qosInfo) / sizeof(g_qosInfo[0]), &listener);
    ASSERT_EQ(ret, SOFTBUS_OK);

    /**
     * @tc.steps: step 3. Register a callback interface for querying.
     */
    TMessenger::GetInstance().RegisterOnQuery([] {
        std::lock_guard<std::mutex> lock(g_recvMutex);
        std::shared_ptr<Response> resp = std::make_shared<Response>(false, g_recvData);
        g_recvData.clear();
        LOGI("isEcrtypr:%d, recvData:%s", resp->isEncrypt_, resp->recvData_.c_str());
        return resp;
    });

    /**
     * @tc.steps: step 4. Waiting for new connections.
     */
    while (true) {
        LOG("waiting ...");
        std::this_thread::sleep_for(std::chrono::seconds(SERVER_IDLE_WAIT_TIME));
    }
    Shutdown(socket);
}

static void OnStreamReceivedWithUnencryptOpt(
    int32_t socket, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{
    OnStreamReceived(socket, "RawStreamEncryptTestServer002", data);
}
/*
 * @tc.name: RawStreamEncryptTestServer002
 * @tc.desc: Unencrypted raw stream data transmission test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamEncryptServerMt, RawStreamEncryptTestServer002, TestSize.Level1)
{
    /**
     * @tc.steps: step 1. set dataType is DATA_TYPE_RAW_STREAM and create socket by 'Socket' function.
     * @tc.expect: socket greater zero.
     */
    SocketInfo info = {
        .name = (char *)TEST_SESSION_NAME_SRV,
        .pkgName = (char *)PKG_NAME,
        .dataType = DATA_TYPE_RAW_STREAM,
    };
    int32_t socket = Socket(info);
    ASSERT_GT(socket, 0);

    ISocketListener listener = {
        .OnBind = OnBindServer,
        .OnShutdown = OnShutdownServer,
        .OnBytes = nullptr,
        .OnMessage = nullptr,
        .OnStream = OnStreamReceivedWithUnencryptOpt,
        .OnFile = nullptr,
        .OnQos = nullptr,
    };

    int32_t ret = Listen(socket, g_qosInfo, sizeof(g_qosInfo) / sizeof(g_qosInfo[0]), &listener);
    ASSERT_EQ(ret, SOFTBUS_OK);

    /**
     * @tc.steps: step 3. Register a callback interface for querying.
     */
    TMessenger::GetInstance().RegisterOnQuery([] {
        std::lock_guard<std::mutex> lock(g_recvMutex);
        std::shared_ptr<Response> resp = std::make_shared<Response>(false, g_recvData);
        g_recvData.clear();
        LOGI("isEcrtypr:%d, recvData:%s", resp->isEncrypt_, resp->recvData_.c_str());
        return resp;
    });

    /**
     * @tc.steps: step 4. Waiting for new connections.
     */
    while (true) {
        LOG("waiting ...");
        std::this_thread::sleep_for(std::chrono::seconds(SERVER_IDLE_WAIT_TIME));
    }
    Shutdown(socket);
}

static void OnStreamReceivedWithEncryptOpt(
    int32_t socket, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{
    OnStreamReceived(socket, "RawStreamEncryptTestServer003", data);
}

/*
 * @tc.name: RawStreamEncryptTestServer003
 * @tc.desc: Unencrypted raw stream data transmission test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamEncryptServerMt, RawStreamEncryptTestServer003, TestSize.Level1)
{
    /**
     * @tc.steps: step 1. set dataType is DATA_TYPE_RAW_STREAM and create socket by 'Socket' function.
     * @tc.expect: socket greater zero.
     */
    SocketInfo info = {
        .name = (char *)TEST_SESSION_NAME_SRV,
        .pkgName = (char *)PKG_NAME,
        .dataType = DATA_TYPE_RAW_STREAM_ENCRYPED,
    };
    int32_t socket = Socket(info);
    ASSERT_GT(socket, 0);

    ISocketListener listener = {
        .OnBind = OnBindServer,
        .OnShutdown = OnShutdownServer,
        .OnBytes = NULL,
        .OnMessage = NULL,
        .OnStream = OnStreamReceivedWithEncryptOpt,
        .OnFile = NULL,
        .OnQos = NULL,
    };

    int32_t ret = Listen(socket, g_qosInfo, sizeof(g_qosInfo) / sizeof(g_qosInfo[0]), &listener);
    ASSERT_EQ(ret, SOFTBUS_OK);

    /**
     * @tc.steps: step 3. Register a callback interface for querying.
     */
    TMessenger::GetInstance().RegisterOnQuery([] {
        std::lock_guard<std::mutex> lock(g_recvMutex);
        std::shared_ptr<Response> resp = std::make_shared<Response>(true, g_recvData);
        g_recvData.clear();
        LOGI("isEcrtypr:%d, recvData:%s", resp->isEncrypt_, resp->recvData_.c_str());
        return resp;
    });

    /**
     * @tc.steps: step 4. Waiting for new connections.
     */
    while (true) {
        LOG("waiting ...");
        std::this_thread::sleep_for(std::chrono::seconds(SERVER_IDLE_WAIT_TIME));
    }
    Shutdown(socket);
}

static int32_t OnSessionOpenedServer(int32_t sessionId, int32_t result)
{
    LOGI(">> OnSessionOpenedServer {sessionId:%d, result=%d", sessionId, result);
    if (sessionId <= 0 || result != SOFTBUS_OK) {
        return result;
    }
    return SOFTBUS_OK;
}

static void OnSessionClosedServer(int32_t sessionId)
{
    LOGI(">> OnSessionClosedServer {sessionId:%d", sessionId);
}

static void OnStreamReceivedWithOldInterface(
    int32_t socket, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{
    OnStreamReceived(socket, "RawStreamEncryptTestServer004", data);
}
/*
 * @tc.name: RawStreamEncryptTestServer004
 * @tc.desc: Use old interace as the server side.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamEncryptServerMt, RawStreamEncryptTestServer004, TestSize.Level1)
{
    /**
     * @tc.steps: step 1. call 'CreateSessionServer' function to start server.
     * @tc.expect: return value is SOFTBUS_OK.
     */
    ISessionListener sessionListener = {
        .OnSessionOpened = OnSessionOpenedServer,
        .OnSessionClosed = OnSessionClosedServer,
        .OnStreamReceived = OnStreamReceivedWithOldInterface,
    };
    int32_t ret = CreateSessionServer(PKG_NAME, TEST_SESSION_NAME_SRV, &sessionListener);
    ASSERT_EQ(ret, SOFTBUS_OK);

    /**
     * @tc.steps: step 2. Register a callback interface for querying.
     */
    TMessenger::GetInstance().RegisterOnQuery([] {
        std::lock_guard<std::mutex> lock(g_recvMutex);
        std::shared_ptr<Response> resp = std::make_shared<Response>(false, g_recvData);
        g_recvData.clear();
        LOGI("isEcrtypr:%d, recvData:%s", resp->isEncrypt_, resp->recvData_.c_str());
        return resp;
    });

    /**
     * @tc.steps: step 3. Waiting for new connections.
     */
    while (true) {
        LOG("waiting ...");
        std::this_thread::sleep_for(std::chrono::seconds(SERVER_IDLE_WAIT_TIME));
    }
    RemoveSessionServer(PKG_NAME, TEST_SESSION_NAME_SRV);
}
} // namespace OHOS