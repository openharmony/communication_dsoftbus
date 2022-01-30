#include "gtest/gtest.h"

#include <cstring>
#include <ctime>
#include <iostream>
#include <semaphore.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include "securec.h"
#include "softbus_bus_center.h"
#include "softbus_test_entry.h"
#include "wifi_p2p.h"
#include "session.h"

using namespace std;

namespace OHOS {
using namespace testing;
using namespace testing::ext;

class P2plinkTransTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static int OnsessionOpened(int sessionId, int result);
    static void OnSessionClosed(int sessionId);
    static void OnStreamReceived(int sessionId, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param);
    static void OnBytesReceived(int sessionId, const void *data, unsigned int dataLen);

    void P2pTransTest(int dataType, int testCnt, const string &mySessionName, const string &peerSessionName,
        int isNeedSuccessRate, int isAbnormal);
    void ServerWait(int waitTime, int testcase);
    void SuccessRateCnt(void);
    void TestSendStream(int sendCnt);
    void CloseAllSession(void);
    void OpenAllSession(int dataType, const string &mySessionName, const string &peerSessionName,
        int isNeedSuccessRate);
    static unordered_set<string> networkIdSet_;
    static const SoftbusTestEntry *testEntryArgs_;
    static int contrlSessionId_;
    static int timeDealySuccessCnt_;
    static unordered_set<int> sessionSet_;
    static sem_t localSem_;
    static bool isTerminal_;
    static int openSessionSuccessCnt_;
};

unordered_set<string> P2plinkTransTest::networkIdSet_;
const SoftbusTestEntry *P2plinkTransTest::testEntryArgs_ = nullptr;
int P2plinkTransTest::contrlSessionId_ = 0;
int P2plinkTransTest::timeDealySuccessCnt_ = 0;
unordered_set<int> P2plinkTransTest::sessionSet_;
sem_t P2plinkTransTest::localSem_;
bool P2plinkTransTest::isTerminal_ = false;
int P2plinkTransTest::openSessionSuccessCnt_ = 0;

int P2plinkTransTest::OnsessionOpened(int sessionId, int result)
{
    cout << "session opened, session id = " << sessionId << ", result = " << result << endl;
    EXPECT_EQ(result, 0);
    if (result == 0) {
        if (sessionId != 1) {
            sessionSet_.insert(sessionId);
            openSessionSuccessCnt_++;
        }
    }
    int ret = sem_post(&localSem_);
    EXPECT_EQ(ret, 0);
    return 0;
}

void P2plinkTransTest::OnSessionClosed(int sessionId)
{
    cout << "onsession closed, session id = " << sessionId << endl;
    if (sessionId != 1) {
        sessionSet_.erase(sessionId);
    }
}

void P2plinkTransTest::OnStreamReceived(int sessionId, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{
    if (data != NULL) {
        printf("stream received, session id = %d, data = %.*s.\n", sessionId, data->bufLen, data->buf);
    }
}

void P2plinkTransTest::OnBytesReceived(int sessionId, const void *data, unsigned int dataLen)
{
    if (data == NULL) {
        return;
    }

    if (!strcmp((const char*)data, TERMINAL_CTRL_MESSAGE.c_str())) {
        isTerminal_ = true;
        cout << "recveive stop contrl message from client test case" << endl;
    }
}

static ISessionListener g_listener = {
    .OnSessionOpened = P2plinkTransTest::OnsessionOpened,
    .OnSessionClosed = P2plinkTransTest::OnSessionClosed,
    .OnBytesReceived = P2plinkTransTest::OnBytesReceived,
    .OnStreamReceived = P2plinkTransTest::OnStreamReceived
};

void P2plinkTransTest::SetUp(void)
{
    sessionSet_.clear();

    timeDealySuccessCnt_ = 0;
    openSessionSuccessCnt_ = 0;
    isTerminal_ = false;
}

void P2plinkTransTest::TearDown(void)
{
    sessionSet_.clear();

    timeDealySuccessCnt_ = 0;
    openSessionSuccessCnt_ = 0;
    isTerminal_ = false;
}

void P2plinkTransTest::SetUpTestCase(void)
{
    int ret;
    // 使能p2p
    P2pState state;
    ret = GetP2pEnableStatus(&state);
    ASSERT_EQ(ret, 0);
    if (state != P2P_STATE_STARTED) {
        ret = EnableP2p();
        ASSERT_EQ(ret, 0);
        sleep(3);
    }

    // 获取在线设备
    NodeBasicInfo *onlineDevices = nullptr;
    int32_t onlineNum;
    ret = GetAllNodeDeviceInfo(TEST_PKG_NAME.c_str(), &onlineDevices, &onlineNum);
    ASSERT_EQ(ret, 0);
    ASSERT_GT(onlineNum, 0);
    cout << "online devices num : " <<  onlineNum << endl;
    for (int i = 0; i < onlineNum; i++) {
        networkIdSet_.insert(string(onlineDevices[i].networkId));
        cout << "online index " << i << " : " << string(onlineDevices[i].networkId) << endl;
    }

    FreeNodeInfo(onlineDevices);
    ret = sem_init(&localSem_, 0, 0);
    ASSERT_EQ(ret, 0);

    // 打开控制通道
    ret = CreateSessionServer(TEST_PKG_NAME.c_str(), CONTRL_SESSION_NAME.c_str(), &g_listener);
    ASSERT_EQ(ret, 0);
    cout << "create contrl session server : " << TEST_PKG_NAME << "sessionName : " << CONTRL_SESSION_NAME << endl;

    // 获取命令行参数
    testEntryArgs_ = GetTestEntry();
    ASSERT_NE(testEntryArgs_, nullptr);

    if (testEntryArgs_->isServer_) {
        ret = sem_wait(&localSem_);
        EXPECT_EQ(ret, 0);
    } else {
        SessionAttribute attribute;
        (void)memset_s(&attribute, sizeof(attribute), 0, sizeof(attribute));
        // p2p link type session
        attribute.dataType = TYPE_BYTES;
        for (auto networkId : networkIdSet_) {
            contrlSessionId_ = OpenSession(CONTRL_SESSION_NAME.c_str(), CONTRL_SESSION_NAME.c_str(), networkId.c_str(), "", &attribute);
            ASSERT_GT(contrlSessionId_, 0);

            struct timespec timeout;
            clock_gettime(CLOCK_REALTIME, &timeout);
            timeout.tv_sec += 10;  // 10: over time 10 seconds
            ret = sem_timedwait(&localSem_, &timeout);
            ASSERT_EQ(ret, 0);
        }
    }
}

void P2plinkTransTest::TearDownTestCase(void)
{
    int ret;
    sessionSet_.clear();

    // 去使能p2p
    ret = DisableP2p();
    EXPECT_EQ(ret, 0);

    ret = sem_destroy(&localSem_);
    EXPECT_EQ(ret, 0);

    CloseSession(contrlSessionId_);
    sleep(2);
}

void P2plinkTransTest::TestSendStream(int sendCnt)
{
    // send stream data
    string data = "stream p2p transmission test!!!!";
    char *sendData = (char *)malloc(data.length() + 1);
    ASSERT_NE(sendData, nullptr);
    int ret = strcpy_s(sendData, data.length() + 1, data.c_str());
    EXPECT_EQ(ret, EOK);
    StreamData extStreamData = {0};
    StreamData streamData = {
        .buf = sendData,
        .bufLen = data.length() + 1,
    };
    StreamFrameInfo frame = {0};

    for (auto session : sessionSet_) {
        cout << "send stream, session id = " << session << endl;
        for (int i = 0; i < sendCnt; i++) {
            int ret = SendStream(session, &streamData, &extStreamData, &frame);
            EXPECT_EQ(ret, 0);
            usleep(10000); // 10000: sleep 10ms
        }
    }

    free(sendData);
    sendData = nullptr;
}

void P2plinkTransTest::CloseAllSession(void)
{
    for (auto session : sessionSet_) {
        if (session != 1) {
            CloseSession(session);
        }
    }
    sleep(2); //2 : 2s, close session time
}

void P2plinkTransTest::OpenAllSession(int dataType, const string &mySessionName, const string &peerSessionName,
    int isNeedSuccessRate)
{
    for (auto networkId : networkIdSet_) {
        SessionAttribute attribute;
        (void)memset_s(&attribute, sizeof(attribute), 0, sizeof(attribute));
        // p2p link type session
        attribute.dataType = dataType;
        attribute.linkTypeNum = 1;
        attribute.linkType[0] = (LinkType)(testEntryArgs_->transLinkType_);
        struct timeval startTimeVal, endTimeVal;
        gettimeofday(&startTimeVal, NULL);

        int ret = OpenSession(mySessionName.c_str(), peerSessionName.c_str(), networkId.c_str(), "", &attribute);

        if (isNeedSuccessRate) {

        } else {
            ASSERT_GT(ret, 0);
        }

        struct timespec timeout;
        clock_gettime(CLOCK_REALTIME, &timeout);
        timeout.tv_sec += 10;  // 10: over time 10 seconds
        ret = sem_timedwait(&localSem_, &timeout);
        ASSERT_EQ(ret, 0);

        if (isNeedSuccessRate) {
            gettimeofday(&endTimeVal, NULL);
            uint64_t delayTime = 1000000 * (endTimeVal.tv_sec - startTimeVal.tv_sec) +
                (endTimeVal.tv_usec - startTimeVal.tv_usec);
            cout << "open session cost time :" << delayTime / 1000 << endl;
            if (delayTime / 1000 <= OPEN_SESSION_DELAY) {
                timeDealySuccessCnt_++;
            }
        }
    }
}

void P2plinkTransTest::P2pTransTest(int dataType, int testCnt, const string &mySessionName, const string &peerSessionName,
    int isNeedSuccessRate, int isAbnormal)
{
    for (int i = 0; i < testCnt; i++) {
        OpenAllSession(dataType, mySessionName, peerSessionName, isNeedSuccessRate);
        if (dataType == TYPE_STREAM) {
            TestSendStream(testEntryArgs_->transNums_);
        }

        if (isAbnormal) {
            cout << "abnormal test, need to wait abnormal operation" << endl;
            int i = 0;
            while (i++ < testEntryArgs_->aliveTime_) {
                sleep(1);
                if (!sessionSet_.size()) {
                    break;
                }
            }
            int size = sessionSet_.size();
            EXPECT_EQ(size, 0);
        } else {
            CloseAllSession();
        }
    }
}

void P2plinkTransTest::ServerWait(int waitTime, int testcase)
{
    cout << "server step into wait state, testcase : " << testcase << endl;
    int ret = sem_wait(&localSem_);
    EXPECT_EQ(ret, 0);
    int i = 0;
    while (i++ < waitTime) {
        sleep(3);
        if (isTerminal_) {
            cout << "quit this testcase : " << testcase << endl;
            break;
        }

        if (testcase == 3 && sessionSet_.empty()) {
            break;
        }
    }

    if (i >= waitTime) {
        ADD_FAILURE();
    }
}

/*
* @tc.name: stream_p2p_trans_test_001
* @tc.desc: open stream p2p link type session, send stream, close session test.
* @tc.type: FUNC
* @tc.require: AR000GIIQ3
*/
HWTEST_F(P2plinkTransTest, stream_p2p_trans_test_001, TestSize.Level4)
{
    int ret = CreateSessionServer(TEST_PKG_NAME.c_str(), STREAM_SESSION_NAME.c_str(), &g_listener);
    ASSERT_EQ(ret, 0);
    cout << "pkgName : " << TEST_PKG_NAME << ", sessionName : " << STREAM_SESSION_NAME << endl;

    ASSERT_NE(testEntryArgs_, nullptr);
    if (testEntryArgs_->isServer_) {
        ServerWait(testEntryArgs_->aliveTime_, 1);
    } else {
        P2pTransTest(TYPE_STREAM, 1, STREAM_SESSION_NAME, STREAM_SESSION_NAME, 0, 0);
        unsigned int dataLen = strlen(TERMINAL_CTRL_MESSAGE.c_str()) + 1;
        ret = SendBytes(contrlSessionId_, TERMINAL_CTRL_MESSAGE.c_str(), dataLen);
        EXPECT_EQ(ret, 0);
        sleep(2);
    }

    ret = RemoveSessionServer(TEST_PKG_NAME.c_str(), STREAM_SESSION_NAME.c_str());
    EXPECT_EQ(ret, 0);
}

void P2plinkTransTest::SuccessRateCnt(void)
{
    EXPECT_GT(openSessionSuccessCnt_, testEntryArgs_->pressureNums_ * 0.95);
    EXPECT_GT(timeDealySuccessCnt_, testEntryArgs_->pressureNums_ * 0.95);
    cout << "open session success rate : " << openSessionSuccessCnt_ << " / " << testEntryArgs_->pressureNums_ << endl;
    cout << "open session time dealy rate : " << timeDealySuccessCnt_ << " / " << testEntryArgs_->pressureNums_ << endl;
}

/*
* @tc.name: stream_p2p_trans_test_002
* @tc.desc: open stream p2p link type session, send stream, close session test, pressure test, default repeat 100 times.
* @tc.type: FUNC
* @tc.require: AR000GIIQ3
*/
HWTEST_F(P2plinkTransTest, stream_p2p_trans_test_002, TestSize.Level4)
{
    int ret = CreateSessionServer(TEST_PKG_NAME.c_str(), STREAM_SESSION_NAME.c_str(), &g_listener);
    ASSERT_EQ(ret, 0);
    cout << "pkgName : " << TEST_PKG_NAME << ", sessionName : " << STREAM_SESSION_NAME << endl;
    ASSERT_NE(testEntryArgs_, nullptr);
    if (testEntryArgs_->isServer_) {
        ServerWait(testEntryArgs_->pressureNums_, 2);
    } else {
        P2pTransTest(TYPE_STREAM, testEntryArgs_->pressureNums_, STREAM_SESSION_NAME, STREAM_SESSION_NAME, 1, 0);
        SuccessRateCnt();
        unsigned int dataLen = strlen(TERMINAL_CTRL_MESSAGE.c_str()) + 1;
        ret = SendBytes(contrlSessionId_, TERMINAL_CTRL_MESSAGE.c_str(), dataLen);
        EXPECT_EQ(ret, 0);
        sleep(2);
    }

    ret = RemoveSessionServer(TEST_PKG_NAME.c_str(), STREAM_SESSION_NAME.c_str());
    EXPECT_EQ(ret, 0);
}

/*
* @tc.name: stream_p2p_trans_test_003
* @tc.desc: open stream p2p link type session, send stream, wifi disconnect, abnormal test.
* @tc.type: FUNC
* @tc.require: AR000GIIQ3
*/
HWTEST_F(P2plinkTransTest, stream_p2p_trans_test_003, TestSize.Level4)
{
    int ret = CreateSessionServer(TEST_PKG_NAME.c_str(), STREAM_SESSION_NAME.c_str(), &g_listener);
    ASSERT_EQ(ret, 0);
    cout << "pkgName : " << TEST_PKG_NAME << ", sessionName : " << STREAM_SESSION_NAME << endl;
    ASSERT_NE(testEntryArgs_, nullptr);
    if (testEntryArgs_->isServer_ == 1) {
        ServerWait(testEntryArgs_->aliveTime_, 3);
    } else {
        P2pTransTest(TYPE_STREAM, 1, STREAM_SESSION_NAME, STREAM_SESSION_NAME, 0, 1);
        unsigned int dataLen = strlen(TERMINAL_CTRL_MESSAGE.c_str()) + 1;
        (void)SendBytes(contrlSessionId_, TERMINAL_CTRL_MESSAGE.c_str(), dataLen);
        sleep(2);
    }
    ret = RemoveSessionServer(TEST_PKG_NAME.c_str(), STREAM_SESSION_NAME.c_str());
    EXPECT_EQ(ret, 0);
}
}
