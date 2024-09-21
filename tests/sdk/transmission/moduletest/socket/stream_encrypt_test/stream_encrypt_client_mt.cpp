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
#include <map>
#include <gtest/gtest.h>
#include "common.h"
#include "session.h"
#include "tmessenger.h"

#define WAIT_TIMEOUT 5

using namespace testing::ext;

namespace OHOS {
class StreamEncryptClientMt : public testing::Test {
public:
    StreamEncryptClientMt() { }
    ~StreamEncryptClientMt() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void StreamEncryptClientMt::SetUpTestCase(void)
{
    int32_t ret = TestInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = TMessenger::GetInstance().Open(PKG_NAME, TEST_NOTIFY_NAME, TEST_NOTIFY_SRV_NAME, false);
    ASSERT_EQ(ret, SOFTBUS_OK);
}

void StreamEncryptClientMt::TearDownTestCase(void)
{
    int32_t ret = TestDeInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    TMessenger::GetInstance().Close();
}

void OnShutdownClient(int32_t socket, ShutdownReason reason)
{
    LOGI(">> OnShutdownClient {socket:%d, reason:%d}", socket, reason);
}

static ISocketListener g_listener = {
    .OnBind = nullptr,
    .OnShutdown = OnShutdownClient,
    .OnBytes = nullptr,
    .OnMessage = nullptr,
    .OnStream = nullptr,
    .OnFile = nullptr,
    .OnQos = nullptr,
};

bool IsTestOk(bool isLocalEncrypt, const std::string sendData, const std::shared_ptr<Response> &resp)
{
    if (resp == nullptr) {
        LOGE("the response is null");
        return false;
    }

    bool isPeerEncrypt = resp->isEncrypt_;
    std::string recvData = resp->recvData_;

    LOGI("isLocalEncrypt:%d, sendData:%s", isLocalEncrypt, sendData.c_str());
    LOGI("isPeerEncrypt:%d, recvData:%s", isPeerEncrypt, recvData.c_str());
    if (isLocalEncrypt == isPeerEncrypt) {
        return sendData == recvData;
    } else {
        return sendData != recvData;
    }
}

static int32_t SendStreamExt(int32_t socket)
{
    std::string src = TEST_STREAM_DATA;
    StreamData data = {
        .buf = (char *)(src.c_str()),
        .bufLen = src.size(),
    };
    StreamData ext = { 0 };
    StreamFrameInfo param = { 0 };
    return SendStream(socket, &data, &ext, &param);
}

/*
 * @tc.name: RawStreamEncryptTest001
 * @tc.desc: Unencrypted raw stream data transmission test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamEncryptClientMt, RawStreamEncryptTest001, TestSize.Level1)
{
    /**
     * @tc.steps: step 1. set dataType is DATA_TYPE_RAW_STREAM and create socket by 'Socket' function.
     * @tc.expect: socket greater zero.
     */
    SocketInfo info = {
        .name = (char *)TEST_SESSION_NAME,
        .pkgName = (char *)PKG_NAME,
        .peerName = (char *)TEST_SESSION_NAME_SRV,
        .peerNetworkId = NULL,
        .dataType = DATA_TYPE_RAW_STREAM,
    };
    info.peerNetworkId = WaitOnLineAndGetNetWorkId();
    int32_t socket = Socket(info);
    ASSERT_GT(socket, 0);

    /**
     * @tc.steps: step 2. set Qos data and call 'Bind' function.
     * @tc.expect: 'Bind' function return SOFTBUS_OK.
     */
    QosTV qosInfo[] = {
        {.qos = QOS_TYPE_MIN_BW,       .value = 80  },
        { .qos = QOS_TYPE_MAX_LATENCY, .value = 4000},
        { .qos = QOS_TYPE_MIN_LATENCY, .value = 2000},
        { .qos = QOS_TYPE_RTT_LEVEL, .value = RTT_LEVEL_LOW},
    };
    int32_t ret = Bind(socket, qosInfo, sizeof(qosInfo) / sizeof(qosInfo[0]), &g_listener);
    ASSERT_EQ(ret, SOFTBUS_OK);

    /**
     * @tc.steps: step 3. call 'SendStream' to send unencrypted raw stream data.
     * @tc.expect: 'SendStream' function return SOFTBUS_OK.
     */
    ret = SendStreamExt(socket);
    ASSERT_EQ(ret, SOFTBUS_OK);

    /**
     * @tc.steps: step 4. call 'Wait' function to get test results returned by server side.
     * @tc.expect: 'IsTestOk' function return true.
     */
    std::shared_ptr<Response> resp = TMessenger::GetInstance().QueryResult(WAIT_TIMEOUT);
    bool testResult = IsTestOk(false, TEST_STREAM_DATA, resp);
    ASSERT_TRUE(testResult);

    Shutdown(socket);
}

/*
 * @tc.name: RawStreamEncryptTest002
 * @tc.desc: Encrypted raw stream data transmission test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamEncryptClientMt, RawStreamEncryptTest002, TestSize.Level1)
{
    /**
     * @tc.steps: step 1. set dataType is DATA_TYPE_RAW_STREAM_ENCRYPED and create socket by 'Socket' function.
     * @tc.expect: socket greater zero.
     */
    SocketInfo info = {
        .name = (char *)TEST_SESSION_NAME,
        .pkgName = (char *)PKG_NAME,
        .peerName = (char *)TEST_SESSION_NAME_SRV,
        .peerNetworkId = nullptr,
        .dataType = DATA_TYPE_RAW_STREAM_ENCRYPED,
    };
    info.peerNetworkId = WaitOnLineAndGetNetWorkId();
    int32_t socket = Socket(info);
    ASSERT_GT(socket, 0);

    /**
     * @tc.steps: step 2. set Qos data and call 'Bind' function.
     * @tc.expect: 'Bind' function return SOFTBUS_OK.
     */
    QosTV qosInfo[] = {
        {.qos = QOS_TYPE_MIN_BW,       .value = 80  },
        { .qos = QOS_TYPE_MAX_LATENCY, .value = 4000},
        { .qos = QOS_TYPE_MIN_LATENCY, .value = 2000},
    };
    int32_t ret = Bind(socket, qosInfo, sizeof(qosInfo) / sizeof(qosInfo[0]), &g_listener);
    ASSERT_EQ(ret, SOFTBUS_OK);

    /**
     * @tc.steps: step 3. call 'SendStream' to send encrypted raw stream data.
     * @tc.expect: 'SendStream' function return SOFTBUS_OK.
     */
    ret = SendStreamExt(socket);
    ASSERT_EQ(ret, SOFTBUS_OK);

    /**
     * @tc.steps: step 4. call 'Wait' function to get test results returned by server side.
     * @tc.expect: 'IsTestOk' function return true.
     */
    std::shared_ptr<Response> resp = TMessenger::GetInstance().QueryResult(WAIT_TIMEOUT);
    bool testResult = IsTestOk(true, TEST_STREAM_DATA, resp);
    ASSERT_TRUE(testResult);

    Shutdown(socket);
}

class SessionStateManager {
public:
    static SessionStateManager &GetInstance()
    {
        static SessionStateManager instance;
        return instance;
    }

    void EnableSessionId(int32_t sessionId)
    {
        if (sessionId <= 0) {
            return;
        }

        std::unique_lock<std::mutex> lock(sessionIdMutex_);
        sessionIdMap_.insert({ sessionId, true });
        lock.unlock();
        sessionIdCond_.notify_one();
    }

    void UnenableSessionId(int32_t sessionId)
    {
        if (sessionId <= 0) {
            return;
        }

        std::unique_lock<std::mutex> lock(sessionIdMutex_);
        sessionIdMap_.erase(sessionId);
    }

    bool WaitEnableSession(int32_t sessionId, uint32_t timeout)
    {
        bool isEnable = false;
        std::unique_lock<std::mutex> lock(sessionIdMutex_);
        sessionIdCond_.wait_for(lock, std::chrono::seconds(timeout), [&] {
            auto it = sessionIdMap_.find(sessionId);
            if (it == sessionIdMap_.end()) {
                isEnable = false;
            } else {
                isEnable = it->second;
            }
            return isEnable;
        });
        return isEnable;
    }

private:
    SessionStateManager() = default;
    SessionStateManager(const SessionStateManager &other) = delete;
    SessionStateManager(const SessionStateManager &&other) = delete;
    SessionStateManager &operator=(const SessionStateManager &other) = delete;
    SessionStateManager &operator=(const SessionStateManager &&other) = delete;

    std::mutex sessionIdMutex_;
    std::condition_variable sessionIdCond_;
    std::map<int32_t, bool> sessionIdMap_;
};

static int32_t OnSessionOpened(int32_t sessionId, int32_t result)
{
    LOGI(">> OnSessionOpenedServer {sessionId:%d, result=%d", sessionId, result);
    if (sessionId <= 0 || result != SOFTBUS_OK) {
        LOGE(">> OnSessionOpenedServer, session open failed");
        return result;
    }

    SessionStateManager::GetInstance().EnableSessionId(sessionId);
    return SOFTBUS_OK;
}

static void OnSessionClosed(int32_t sessionId)
{
    LOGI(">> OnSessionClosedServer {sessionId:%d", sessionId);
    SessionStateManager::GetInstance().EnableSessionId(sessionId);
}

/*
 * @tc.name: RawStreamEncryptTest003
 * @tc.desc: Encrypted raw stream data transmission test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamEncryptClientMt, RawStreamEncryptTest003, TestSize.Level1)
{
    /**
     * @tc.steps: step 1. call 'CreateSessionServer' function to create session server.
     * @tc.expect: 'CreateSessionServer' function return SOFTBUS_OK.
     */
    ISessionListener sessionListener = {
        .OnSessionOpened = OnSessionOpened,
        .OnSessionClosed = OnSessionClosed,
    };

    int32_t ret = CreateSessionServer(PKG_NAME, TEST_SESSION_NAME, &sessionListener);
    ASSERT_EQ(ret, SOFTBUS_OK);

    SessionAttribute attr = { 0 };
    attr.dataType = TYPE_STREAM;
    attr.attr.streamAttr.streamType = RAW_STREAM;
    attr.linkTypeNum = 4;
    attr.linkType[0] = LINK_TYPE_WIFI_WLAN_5G;
    attr.linkType[1] = LINK_TYPE_WIFI_WLAN_2G;
    attr.linkType[2] = LINK_TYPE_BR;
    attr.linkType[3] = LINK_TYPE_BLE;
    attr.fastTransData = nullptr;
    attr.fastTransDataSize = 0;

    /**
     * @tc.steps: step 2. call 'OpenSession' function to create session.
     * @tc.expect: 'OpenSession' function return SOFTBUS_OK.
     */
    int32_t sessionId = OpenSession(TEST_SESSION_NAME, TEST_SESSION_NAME_SRV, WaitOnLineAndGetNetWorkId(), "reserved",
        &attr);
    ASSERT_GT(sessionId, 0) << "failed to OpenSession, ret=" << sessionId;

    /**
     * @tc.steps: step 3. call 'WaitEnableSession' function to wait for the session to be opened.
     * @tc.expect: 'WaitEnableSession' function return true.
     */
    bool isEnable = SessionStateManager::GetInstance().WaitEnableSession(sessionId, 10);
    ASSERT_TRUE(isEnable) << "failed to enable session, sessionId" << sessionId;


    /**
     * @tc.steps: step 4. call 'SendStream' function to send unencrypted raw stream data.
     * @tc.expect: 'SendStream' function return SOFTBUS_OK.
     */
    ret = SendStreamExt(sessionId);
    ASSERT_EQ(ret, SOFTBUS_OK);

    /**
     * @tc.steps: step 5. call 'Wait' function to get test results returned by server side.
     * @tc.expect: 'IsTestOk' function return true.
     */
    std::shared_ptr<Response> resp = TMessenger::GetInstance().QueryResult(WAIT_TIMEOUT);
    bool testResult = IsTestOk(false, TEST_STREAM_DATA, resp);
    ASSERT_TRUE(testResult);

    CloseSession(sessionId);
    RemoveSessionServer(PKG_NAME, TEST_SESSION_NAME);
}
} // namespace OHOS