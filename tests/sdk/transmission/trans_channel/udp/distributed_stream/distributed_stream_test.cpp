/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * miscservices under the License is miscservices on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "distributed_stream_test.h"

#include "gtest/gtest.h"
#include <cstring>
#include <iostream>
#include <semaphore.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include "securec.h"
#include "softbus_bus_center.h"
#include "session.h"
#include "softbus_common.h"
#include "softbus_access_token_test.h"
#include "distributed_major.h"

using namespace std;
using namespace testing;
using namespace testing::ext;

#define SLEEP_SEC (1)
#define SLEEP_MS (2)
#define WAIT_MS (16)
#define WAIT_S (2)
#define FPS (60)
#define I_FRAME_TYPE (1)
#define P_FRAME_TYPE (2)
#define MAX_SEND_CNT (1000)

namespace OHOS {

void SetNumebrInStreamData(char *streamData, int32_t i)
{
    string strI = std::to_string(i);
    char len = strI.length();
    streamData[0] = len;
    (void)memcpy_s(streamData + 1, len, strI.c_str(), len);
}

int32_t GetNumebrInStreamData(const char *streamData)
{
    char len = streamData[0];
    string str(streamData + 1, len);

    return std::stoi(str);
}

class DistributeStreamTest : public OHOS::DistributeSystemTest::DistributeTest {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static int32_t OnsessionOpened(int32_t sessionId, int32_t result);
    static int32_t OnCtrlsessionOpened(int32_t sessionId, int32_t result);
    static void OnSessionClosed(int32_t sessionId);
    static void OnStreamReceived(int32_t sessionId, const StreamData *data,
        const StreamData *ext, const StreamFrameInfo *param);
    static void OnBytesReceived(int32_t sessionId, const void *data, unsigned int dataLen);

    void P2pTransTest(bool isRawStream, bool isP2P, int32_t sendCnt, const string &mySessionName,
        const string &peerSessionName);
    void TestSendCommonStream(int32_t sendCnt);
    void TestSendStream(int32_t sendCnt);
    void CloseAllSession(void);
    void OpenAllSession(bool isRawStream, bool isP2P, const string &mySessionName, const string &peerSessionName);
    void OpenCtrlSession(const string &mySessionName, const string &peerSessionName);

    void SendCreateSessionServerMessage();
    void SendRemoveSessionServerMessage();

    static unordered_set<string> networkIdSet_;
    static int32_t contrlSessionId_;
    static unordered_set<int> sessionSet_;
    static sem_t localSem_;

    static time_t startTime[MAX_SEND_CNT];
    static time_t endTime[MAX_SEND_CNT];
    static char sendBytes[BYTES_SIZE];
};

unordered_set<string> DistributeStreamTest::networkIdSet_;
int32_t DistributeStreamTest::contrlSessionId_ = 0;
unordered_set<int> DistributeStreamTest::sessionSet_;
sem_t DistributeStreamTest::localSem_;
time_t DistributeStreamTest::startTime[MAX_SEND_CNT];
time_t DistributeStreamTest::endTime[MAX_SEND_CNT];
char DistributeStreamTest::sendBytes[BYTES_SIZE];

void Wsleep(int32_t count, int32_t usl)
{
    while (count) {
        if (usl == SLEEP_SEC) {
            sleep(1);
        } else {
            usleep(US_PER_MS);
        }
        count--;
    }
}

int32_t DistributeStreamTest::OnsessionOpened(int32_t sessionId, int32_t result)
{
    EXPECT_EQ(result, 0);
    if (result == 0) {
        sessionSet_.insert(sessionId);
    }
    int32_t ret = sem_post(&localSem_);
    EXPECT_EQ(ret, 0);
    return 0;
}

int32_t DistributeStreamTest::OnCtrlsessionOpened(int32_t sessionId, int32_t result)
{
    EXPECT_EQ(result, 0);
    if (result == 0) {
        contrlSessionId_ = sessionId;
    }
    int32_t ret = sem_post(&localSem_);
    EXPECT_EQ(ret, 0);
    return 0;
}

void DistributeStreamTest::OnSessionClosed(int32_t sessionId)
{
    sessionSet_.erase(sessionId);
}

void DistributeStreamTest::OnStreamReceived(int32_t sessionId, const StreamData *data,
    const StreamData *ext, const StreamFrameInfo *param)
{
}

void DistributeStreamTest::OnBytesReceived(int32_t sessionId, const void *data, unsigned int dataLen)
{
    int32_t i = GetNumebrInStreamData(static_cast<const char*>(data));
    if (i < 0) {
        return;
    }
    endTime[i] = GetCurrent();
    unsigned long long timeDiff = (endTime[i] - startTime[i]);
    cout << i << " frame time cost " << timeDiff << "ms" << endl;
}

static ISessionListener g_listener = {
    .OnSessionOpened = DistributeStreamTest::OnsessionOpened,
    .OnSessionClosed = DistributeStreamTest::OnSessionClosed,
    .OnBytesReceived = DistributeStreamTest::OnBytesReceived,
    .OnStreamReceived = DistributeStreamTest::OnStreamReceived
};

static ISessionListener g_ctrllistener = {
    .OnSessionOpened = DistributeStreamTest::OnCtrlsessionOpened,
    .OnSessionClosed = DistributeStreamTest::OnSessionClosed,
    .OnBytesReceived = DistributeStreamTest::OnBytesReceived,
    .OnStreamReceived = DistributeStreamTest::OnStreamReceived
};

void DistributeStreamTest::SetUp()
{
    sessionSet_.clear();
}

void DistributeStreamTest::TearDown()
{
    sessionSet_.clear();
}

void DistributeStreamTest::SetUpTestCase()
{
    SetAccessTokenPermission("distributed_stream_test");

    // 获取在线设备
    NodeBasicInfo *onlineDevices = nullptr;
    int32_t onlineNum;
    int32_t ret = GetAllNodeDeviceInfo(TEST_PKG_NAME.c_str(), &onlineDevices, &onlineNum);
    ASSERT_EQ(ret, 0);
    ASSERT_GT(onlineNum, 0);
    cout << "online devices num : " <<  onlineNum << endl;
    for (int32_t i = 0; i < onlineNum; i++) {
        networkIdSet_.insert(string(onlineDevices[i].networkId));
        cout << "online index " << i << " : " << string(onlineDevices[i].networkId) << endl;
    }
    FreeNodeInfo(onlineDevices);

    ret = sem_init(&localSem_, 0, 0);
    ASSERT_EQ(ret, 0);
}

void DistributeStreamTest::TearDownTestCase()
{
    int32_t ret;
    sessionSet_.clear();

    ret = sem_destroy(&localSem_);
    EXPECT_EQ(ret, 0);

    Wsleep(WAIT_S, SLEEP_SEC);
}

void DistributeStreamTest::TestSendStream(int32_t sendCnt)
{
    if (sendCnt >= MAX_SEND_CNT) {
        return;
    }

    char *sendData = static_cast<char*>(malloc(STREAM_SIZE));
    if (sendData == nullptr) {
        return;
    }

    StreamData extStreamData = {0};
    StreamData streamData = {
        .buf = sendData,
        .bufLen = STREAM_SIZE,
    };
    StreamFrameInfo frame = {0};

    for (auto session : sessionSet_) {
        if (session == contrlSessionId_) {
            continue;
        }

        cout << "send stream, session id = " << session << endl;
        for (int32_t i = 0; i < sendCnt; i++) {
            startTime[i] = GetCurrent();
            SetNumebrInStreamData(sendData, i);
            int32_t ret = SendStream(session, &streamData, &extStreamData, &frame);
            EXPECT_EQ(ret, 0);

            Wsleep(WAIT_MS, SLEEP_MS);
        }
    }

    free(sendData);
    sendData = nullptr;
}

void DistributeStreamTest::TestSendCommonStream(int32_t sendCnt)
{
    char *sendIFrame = static_cast<char*>(malloc(I_FRAME_SIZE));
    if (sendIFrame == nullptr) {
        return;
    }
    char *sendPFrame = static_cast<char*>(malloc(P_FRAME_SIZE));
    if (sendPFrame == nullptr) {
        free(sendIFrame);
        sendIFrame = nullptr;
        return;
    }
    StreamData extStreamData = {0};
    StreamData streamIData = {
        .buf = sendIFrame,
        .bufLen = I_FRAME_SIZE,
    };
    StreamFrameInfo iFrame = {0};
    iFrame.frameType = I_FRAME_TYPE;

    StreamData streamPData = {
        .buf = sendPFrame,
        .bufLen = P_FRAME_SIZE,
    };
    StreamFrameInfo pFrame = {0};
    pFrame.frameType = P_FRAME_TYPE;

    for (auto session : sessionSet_) {
        if (session == contrlSessionId_) {
            continue;
        }

        cout << "send stream, session id = " << session << endl;
        while (sendCnt > 0) {
            startTime[0] = GetCurrent();
            SetNumebrInStreamData(sendIFrame, 0);
            int32_t ret = SendStream(session, &streamIData, &extStreamData, &iFrame);
            EXPECT_EQ(ret, 0);

            Wsleep(WAIT_MS, SLEEP_MS);
            for (int32_t i = 1; i < FPS; i++) {
                startTime[i] = GetCurrent();
                SetNumebrInStreamData(sendPFrame, i);
                ret = SendStream(session, &streamPData, &extStreamData, &pFrame);
                EXPECT_EQ(ret, 0);

                Wsleep(WAIT_MS, SLEEP_MS);
            }
            sendCnt--;
        }
    }

    free(sendIFrame);
    sendIFrame = nullptr;

    free(sendPFrame);
    sendPFrame = nullptr;
}

void DistributeStreamTest::CloseAllSession(void)
{
    for (auto session : sessionSet_) {
        CloseSession(session);
    }
}

void DistributeStreamTest::OpenAllSession(bool isRawStream, bool isP2P,
    const string &mySessionName, const string &peerSessionName)
{
    for (auto networkId : networkIdSet_) {
        SessionAttribute attribute;
        (void)memset_s(&attribute, sizeof(attribute), 0, sizeof(attribute));
        // p2p link type session
        attribute.dataType = TYPE_STREAM;
        attribute.linkTypeNum = 0;
        attribute.linkType[0] = isP2P ? LINK_TYPE_WIFI_P2P : LINK_TYPE_WIFI_WLAN_5G;
        attribute.attr.streamAttr.streamType = isRawStream ? RAW_STREAM : COMMON_VIDEO_STREAM;

        cout << "streamType === " << attribute.attr.streamAttr.streamType << endl;

        int32_t ret = OpenSession(mySessionName.c_str(), peerSessionName.c_str(), networkId.c_str(), "", &attribute);
        ASSERT_GT(ret, 0);

        struct timespec timeout;
        clock_gettime(CLOCK_REALTIME, &timeout);
        timeout.tv_sec += 10;  // 10: over time 10 seconds
        while ((ret = sem_timedwait(&localSem_, &timeout)) == -1 && errno == EINTR) {
            continue;
        }
        if ((ret == -1) && (errno == ETIMEDOUT)) {
            cout << "wait time out22222222" << endl;
        }
        ASSERT_EQ(ret, 0);
    }
}

void DistributeStreamTest::OpenCtrlSession(const string &mySessionName, const string &peerSessionName)
{
    for (auto networkId : networkIdSet_) {
        SessionAttribute attribute;
        (void)memset_s(&attribute, sizeof(attribute), 0, sizeof(attribute));
        // p2p link type session
        attribute.dataType = TYPE_BYTES;
        attribute.linkTypeNum = 0;
        attribute.linkType[0] = LINK_TYPE_WIFI_WLAN_5G;

        int32_t ret = OpenSession(mySessionName.c_str(), peerSessionName.c_str(), networkId.c_str(), "", &attribute);
        ASSERT_GT(ret, 0);

        struct timespec timeout;
        clock_gettime(CLOCK_REALTIME, &timeout);
        timeout.tv_sec += 10;  // 10: over time 10 seconds
        while ((ret = sem_timedwait(&localSem_, &timeout)) == -1 && errno == EINTR) {
            continue;
        }
        if ((ret == -1) && (errno == ETIMEDOUT)) {
            cout << "wait open session time out" << endl;
        }
        ASSERT_EQ(ret, 0);
    }
}

void DistributeStreamTest::SendCreateSessionServerMessage()
{
    string msgbuf = "createSessionServer";
    int32_t ret = SendMessage(DistributeSystemTest::AGENT_NO::ONE, msgbuf, msgbuf.length(),
        [&](const string &returnBuf, int32_t rlen)->bool {
            cout << "receive reply message :" << returnBuf << endl;
            EXPECT_TRUE("ok" == returnBuf);
            int32_t ret = sem_post(&localSem_);
            EXPECT_EQ(ret, 0);
            return true;
        });
    EXPECT_TRUE(ret > 0);

    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += 10;  // 10: over time 10 seconds
    while ((ret = sem_timedwait(&localSem_, &timeout)) == -1 && errno == EINTR) {
        continue;
    }
    if ((ret == -1) && (errno == ETIMEDOUT)) {
        cout << "wait send messgae time out" << endl;
    }
    ASSERT_EQ(ret, 0);
    cout << "SendMessage OK" << endl;
}

void DistributeStreamTest::SendRemoveSessionServerMessage()
{
    string msgbuf = "removeSessionServer";
    int32_t ret = SendMessage(DistributeSystemTest::AGENT_NO::ONE, msgbuf, msgbuf.length(),
        [&](const string &returnBuf, int32_t rlen)->bool {
            cout << "receive reply message :" << returnBuf << endl;
            EXPECT_TRUE("ok" == returnBuf);
            int32_t ret = sem_post(&localSem_);
            EXPECT_EQ(ret, 0);
            return true;
        });
    EXPECT_TRUE(ret > 0);

    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += 10;  // 10: over time 10 seconds
    while ((ret = sem_timedwait(&localSem_, &timeout)) == -1 && errno == EINTR) {
        continue;
    }
    if ((ret == -1) && (errno == ETIMEDOUT)) {
        cout << "wait send messgae time out" << endl;
    }
    ASSERT_EQ(ret, 0);
    cout << "SendMessage OK" << endl;
}

void DistributeStreamTest::P2pTransTest(bool isRawStream, bool isP2P,
    int32_t sendCnt, const string &mySessionName, const string &peerSessionName)
{
    OpenAllSession(isRawStream, isP2P, mySessionName, peerSessionName);
    if (isRawStream) {
        TestSendStream(sendCnt);
    } else {
        TestSendCommonStream(sendCnt);
    }
}

/*
* @tc.name: stream_p2p_trans_test_001
* @tc.desc: open stream p2p link type session, send raw stream, close session test.
* @tc.type: FUNC
* @tc.require: AR000GIIQ3
*/
HWTEST_F(DistributeStreamTest, stream_p2p_trans_test_001, TestSize.Level4)
{
    int32_t ret = CreateSessionServer(TEST_PKG_NAME.c_str(), STREAM_SESSION_NAME.c_str(), &g_listener);
    ASSERT_EQ(ret, 0);
    cout << "pkgName : " << TEST_PKG_NAME << ", sessionName : " << STREAM_SESSION_NAME << endl;

    ret = CreateSessionServer(TEST_PKG_NAME.c_str(), CONTRL_SESSION_NAME.c_str(), &g_ctrllistener);
    ASSERT_EQ(ret, 0);
    cout << "pkgName : " << TEST_PKG_NAME << ", sessionName : " << CONTRL_SESSION_NAME << endl;

    SendCreateSessionServerMessage();
    OpenCtrlSession(CONTRL_SESSION_NAME, CONTRL_SESSION_NAME);
    P2pTransTest(true, true, 60, STREAM_SESSION_NAME, STREAM_SESSION_NAME);

    Wsleep(WAIT_S, SLEEP_SEC);

    CloseAllSession();
    SendRemoveSessionServerMessage();

    ret = RemoveSessionServer(TEST_PKG_NAME.c_str(), STREAM_SESSION_NAME.c_str());
    EXPECT_EQ(ret, 0);

    ret = RemoveSessionServer(TEST_PKG_NAME.c_str(), CONTRL_SESSION_NAME.c_str());
    EXPECT_EQ(ret, 0);
}

/*
* @tc.name: stream_p2p_trans_test_002
* @tc.desc: open stream wifi link type session, send raw stream, close session test.
* @tc.type: FUNC
* @tc.require: AR000GIIQ3
*/
HWTEST_F(DistributeStreamTest, stream_p2p_trans_test_002, TestSize.Level4)
{
    int32_t ret = CreateSessionServer(TEST_PKG_NAME.c_str(), STREAM_SESSION_NAME.c_str(), &g_listener);
    ASSERT_EQ(ret, 0);
    cout << "pkgName : " << TEST_PKG_NAME << ", sessionName : " << STREAM_SESSION_NAME << endl;

    ret = CreateSessionServer(TEST_PKG_NAME.c_str(), CONTRL_SESSION_NAME.c_str(), &g_ctrllistener);
    ASSERT_EQ(ret, 0);
    cout << "pkgName : " << TEST_PKG_NAME << ", sessionName : " << CONTRL_SESSION_NAME << endl;

    SendCreateSessionServerMessage();
    OpenCtrlSession(CONTRL_SESSION_NAME, CONTRL_SESSION_NAME);
    P2pTransTest(true, false, 60, STREAM_SESSION_NAME, STREAM_SESSION_NAME);

    Wsleep(WAIT_S, SLEEP_SEC);

    CloseAllSession();
    SendRemoveSessionServerMessage();

    ret = RemoveSessionServer(TEST_PKG_NAME.c_str(), STREAM_SESSION_NAME.c_str());
    EXPECT_EQ(ret, 0);

    ret = RemoveSessionServer(TEST_PKG_NAME.c_str(), CONTRL_SESSION_NAME.c_str());
    EXPECT_EQ(ret, 0);
}

/*
* @tc.name: stream_p2p_trans_test_003
* @tc.desc: open stream p2p link type session, send common stream, close session test.
* @tc.type: FUNC
* @tc.require: AR000GIIQ3
*/
HWTEST_F(DistributeStreamTest, stream_p2p_trans_test_003, TestSize.Level4)
{
    int32_t ret = CreateSessionServer(TEST_PKG_NAME.c_str(), STREAM_SESSION_NAME.c_str(), &g_listener);
    ASSERT_EQ(ret, 0);
    cout << "pkgName : " << TEST_PKG_NAME << ", sessionName : " << STREAM_SESSION_NAME << endl;

    ret = CreateSessionServer(TEST_PKG_NAME.c_str(), CONTRL_SESSION_NAME.c_str(), &g_ctrllistener);
    ASSERT_EQ(ret, 0);
    cout << "pkgName : " << TEST_PKG_NAME << ", sessionName : " << CONTRL_SESSION_NAME << endl;

    SendCreateSessionServerMessage();
    OpenCtrlSession(CONTRL_SESSION_NAME, CONTRL_SESSION_NAME);
    P2pTransTest(false, true, 20, STREAM_SESSION_NAME, STREAM_SESSION_NAME);

    Wsleep(WAIT_S, SLEEP_SEC);

    CloseAllSession();
    SendRemoveSessionServerMessage();

    ret = RemoveSessionServer(TEST_PKG_NAME.c_str(), STREAM_SESSION_NAME.c_str());
    EXPECT_EQ(ret, 0);

    ret = RemoveSessionServer(TEST_PKG_NAME.c_str(), CONTRL_SESSION_NAME.c_str());
    EXPECT_EQ(ret, 0);
}

/*
* @tc.name: stream_p2p_trans_test_004
* @tc.desc: open stream p2p link type session, send raw stream, close session test.
* @tc.type: FUNC
* @tc.require: AR000GIIQ3
*/
HWTEST_F(DistributeStreamTest, stream_p2p_trans_test_004, TestSize.Level4)
{
    int32_t ret = CreateSessionServer(TEST_PKG_NAME.c_str(), STREAM_SESSION_NAME.c_str(), &g_listener);
    ASSERT_EQ(ret, 0);
    cout << "pkgName : " << TEST_PKG_NAME << ", sessionName : " << STREAM_SESSION_NAME << endl;

    ret = CreateSessionServer(TEST_PKG_NAME.c_str(), CONTRL_SESSION_NAME.c_str(), &g_ctrllistener);
    ASSERT_EQ(ret, 0);
    cout << "pkgName : " << TEST_PKG_NAME << ", sessionName : " << CONTRL_SESSION_NAME << endl;

    SendCreateSessionServerMessage();
    OpenCtrlSession(CONTRL_SESSION_NAME, CONTRL_SESSION_NAME);
    P2pTransTest(false, false, 20, STREAM_SESSION_NAME, STREAM_SESSION_NAME);

    Wsleep(WAIT_S, SLEEP_SEC);

    CloseAllSession();
    SendRemoveSessionServerMessage();

    ret = RemoveSessionServer(TEST_PKG_NAME.c_str(), STREAM_SESSION_NAME.c_str());
    EXPECT_EQ(ret, 0);

    ret = RemoveSessionServer(TEST_PKG_NAME.c_str(), CONTRL_SESSION_NAME.c_str());
    EXPECT_EQ(ret, 0);
}
}

int32_t main(int32_t argc, char *argv[])
{
    OHOS::DistributeSystemTest::g_pDistributetestEnv =
        new OHOS::DistributeSystemTest::DistributeTestEnvironment("major.desc");
    testing::AddGlobalTestEnvironment(OHOS::DistributeSystemTest::g_pDistributetestEnv);
    testing::GTEST_FLAG(output) = "xml:./";
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
