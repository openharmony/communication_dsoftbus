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

#include "gtest/gtest.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cinttypes>
#include <iostream>
#include <semaphore.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>

#include "common_list.h"
#include "inner_session.h"
#include "securec.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_file_test_entry.h"
#include "softbus_utils.h"

using namespace testing::ext;
using namespace std;
namespace OHOS {

const int32_t SEND_DATA_SIZE_1K = 1024;
const int32_t SEND_DATA_SIZE_4K = 4 * 1024;
const int32_t SEND_DATA_SIZE_1M = 1024 * 1024;
const char *g_testData = "{\"data\":\"open session test!!!\"}";

const char *SFILE_NAME_1K = "/data/file1K.tar";
const char *SFILE_NAME_5M = "/data/file5M.tar";

const char *DFILE_NAME_1K = "file1K.tar";
const char *DFILE_NAME_5M = "file5M.tar";
const char *RECV_ROOT_PATH = "/data/recv/";

typedef struct {
    string mySessionName;
    string peerSessionName;
    int32_t testCnt;
    int32_t sendNum;
    int32_t dataType;
    const char **sfileList;
    const char **dfileList;
    int32_t sfileCnt;
} TransTestInfo;

unordered_set<string> networkIdSet_;
unordered_set<int32_t> sessionSet_;
sem_t localSem_;
int32_t openSessionSuccessCnt_ = 0;
const SoftbusTestEntry *testEntryArgs_ = nullptr;

int32_t WaitDeviceOnline(const char *pkgName)
{
#define GET_LNN_RETRY_COUNT 5
    int32_t onlineRetryCount = 0;
    int32_t ret;
    while (true) {
        NodeBasicInfo *onlineDevices = nullptr;
        int32_t onlineNum = 0;
        ret = GetAllNodeDeviceInfo(pkgName, &onlineDevices, &onlineNum);
        onlineRetryCount++;
        if (onlineRetryCount < GET_LNN_RETRY_COUNT && (ret != SOFTBUS_OK || onlineNum <= 0)) {
            FreeNodeInfo(onlineDevices);
            sleep(5);
            continue;
        }
        cout << "online device num: " << onlineNum << endl;
        for (int32_t i = 0; i < onlineNum; i++) {
            networkIdSet_.insert(string(onlineDevices[i].networkId));
            cout << "online idex " << i << " : " << string(onlineDevices[i].networkId) << endl;
        }
        FreeNodeInfo(onlineDevices);
        break;
    }
    if (!networkIdSet_.empty()) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_TIMOUT;
}

int32_t OnSessionOpened(int32_t sessionId, int32_t result)
{
    cout << "session opened, sesison id = " << sessionId << ", result = " << result << endl;
    if (result == SOFTBUS_OK) {
        sessionSet_.insert(sessionId);
        openSessionSuccessCnt_++;
    }
    sem_post(&localSem_);
    return SOFTBUS_OK;
}

void OnSessionClosed(int32_t sessionId)
{
    cout << "session closed, sesison id = " << sessionId << endl;
    sessionSet_.erase(sessionId);
}

void OnStreamReceived(int32_t sessionId, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
{
    if (data == nullptr) {
        printf("StreamData is null, stream received fail\n");
        return;
    }
    printf("stream received, sessionid[%d], data = %.*s\n", sessionId, data->bufLen, data->buf);
    if (ext == nullptr || ext->buf == nullptr || data->bufLen <= 0) {
        printf("parameters invalid, stream received fail\n");
        return;
    }
    printf("stream received, sessionid[%d], extdata = %.*s\n", sessionId, ext->bufLen, ext->buf);
}

void OnBytesReceived(int32_t sessionId, const void *data, unsigned int len)
{
    if (testEntryArgs_->testSide_ == PASSIVE_OPENSESSION_WAY) {
        SendBytes(sessionId, "{\"received ok\"}", strlen("{\"received ok\"}"));
    }
    printf("bytes received, sessionid[%d], data[%s], dataLen[%u]\n", sessionId, data, len);
}

void OnMessageReceived(int32_t sessionId, const void *data, unsigned int len)
{
    printf("msg received, sessionid[%d], data[%s], dataLen[%u]\n", sessionId, data, len);
}

static ISessionListener g_listener = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnStreamReceived = OnStreamReceived,
    .OnBytesReceived = OnBytesReceived,
    .OnMessageReceived = OnMessageReceived
};

int32_t OnSendFileProcess(int32_t sessionId, uint64_t bytesUpload, uint64_t bytesTotal)
{
    cout << "OnSendFileProcess sessionId = " << sessionId << ", bytesUpload = " <<
        bytesUpload << ", total = " << bytesTotal << endl;
    return 0;
}

int32_t OnSendFileFinished(int32_t sessionId, const char *firstFile)
{
    printf("OnSendFileFinished sessionId = %d, first file = %s\n", sessionId, firstFile);
    return 0;
}

void OnFileTransError(int32_t sessionId)
{
    printf("OnFileTransError sessionId = %d\n", sessionId);
}

static IFileSendListener g_fileSendListener = {
    .OnSendFileProcess = OnSendFileProcess,
    .OnSendFileFinished = OnSendFileFinished,
    .OnFileTransError = OnFileTransError,
};

int32_t OnReceiveFileStarted(int32_t sessionId, const char *files, int32_t fileCnt)
{
    printf("File receive start sessionId = %d, first file = %s, fileCnt = %d\n", sessionId, files, fileCnt);
    return 0;
}

void OnReceiveFileFinished(int32_t sessionId, const char *files, int32_t fileCnt)
{
    printf("File receive finished sessionId = %d, first file = %s, fileCnt = %d\n", sessionId, files, fileCnt);
}

int32_t OnReceiveFileProcess(int32_t sessionId, const char *firstFile, uint64_t bytesUpload, uint64_t bytesTotal)
{
    printf("File receive process sessionId = %d, first file = %s, upload = %" PRIu64 ", total = %" PRIu64 "\n",
        sessionId, firstFile, bytesUpload, bytesTotal);
    return 0;
}
static IFileReceiveListener g_fileRecvListener = {
    .OnReceiveFileStarted = OnReceiveFileStarted,
    .OnReceiveFileFinished = OnReceiveFileFinished,
    .OnReceiveFileProcess = OnReceiveFileProcess,
    .OnFileTransError = OnFileTransError,
};

class AuthSessionTest : public testing::Test {
public:
    AuthSessionTest()
    {}
    ~AuthSessionTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static void Wsleep(uint32_t count, int32_t usl);
    static void ServerWait(int32_t waitTime, int32_t testCase);
    static void OpenAllSession(int32_t dataType, const string &mySessionName, const string &peerSessionName);
    static void TestServerSide(void);

    static void CloseAllSession(void);
    static void TestSendMessage(int32_t sendCnt, const char *data, uint32_t len, bool ex = false);
    static void TestSendBytes(int32_t sendCnt, const char *data, uint32_t len, bool ex = false);

    static void TestSendFile(int32_t sendCnt, const char *sfileList[], const char *dfileList[],
        int32_t cnt, bool ex = false);

    static void TransTestCase001(TransTestInfo &transInfo);
    static void TransTest(TransTestInfo &transInfo, int32_t testDataType, bool ex = false);
    static void *TestSendFileThread(void *arg);
};

void AuthSessionTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    int32_t ret = sem_init(&localSem_, 0, 0);
    ASSERT_EQ(ret, 0);
    testEntryArgs_ = GetTestEntry();
    ASSERT_NE(testEntryArgs_, nullptr);

    networkIdSet_.clear();
    ret = SOFTBUS_TIMOUT;
    if (testEntryArgs_->testSide_ == PASSIVE_OPENSESSION_WAY) {
        ret = WaitDeviceOnline(FILE_TEST_PKG_NAME.c_str());
        ASSERT_EQ(ret, SOFTBUS_OK);
    } else if (testEntryArgs_->testSide_ == ACTIVE_OPENSESSION_WAY) {
        ret = WaitDeviceOnline(FILE_TEST_PKG_NAME.c_str());
        ASSERT_EQ(ret, SOFTBUS_OK);
    } else if (testEntryArgs_->testSide_ == ACTIVE_ANOTHER_OPENSESSION_WAY) {
        ret = WaitDeviceOnline(FILE_TEST_PKG_NAME_DEMO.c_str());
        ASSERT_EQ(ret, SOFTBUS_OK);
    } else {
        ASSERT_EQ(ret, SOFTBUS_OK);
    }
}

void AuthSessionTest::TearDownTestCase(void)
{
    sessionSet_.clear();
    int32_t ret = sem_destroy(&localSem_);
    ASSERT_EQ(ret, 0);
    Wsleep(2, 1);
}

void AuthSessionTest::SetUp(void)
{
    sessionSet_.clear();
    openSessionSuccessCnt_ = 0;
}

void AuthSessionTest::TearDown(void)
{
    sessionSet_.clear();
    openSessionSuccessCnt_ = 0;
}

void AuthSessionTest::Wsleep(uint32_t count, int32_t usl)
{
    while (count) {
        if (usl == 1) {
            sleep(1);
        } else {
            usleep(1000);
        }
        count--;
    }
}
void AuthSessionTest::ServerWait(int32_t waitTime, int32_t testCase)
{
    cout << "waitTime = " << waitTime << endl;
    int32_t ret = sem_wait(&localSem_);
    EXPECT_EQ(ret, 0);
    int32_t i = 0;
    while (i++ < waitTime) {
        Wsleep(4, 1);
        if (testCase == 3 && sessionSet_.empty()) {
            break;
        }
    }
    if (i >= waitTime) {
        ADD_FAILURE();
    }
}

void AuthSessionTest::OpenAllSession(int32_t dataType, const string &mySessionName, const string &peerSessionName)
{
    for (auto networkId : networkIdSet_) {
        SessionAttribute attribute;
        (void)memset_s(&attribute, sizeof(attribute), 0, sizeof(attribute));
        attribute.dataType = dataType;
        int32_t ret = OpenSession(mySessionName.c_str(), peerSessionName.c_str(), networkId.c_str(), "", &attribute);
        ASSERT_GT(ret, 0);
        struct timespec timeout;
        clock_gettime(CLOCK_REALTIME, &timeout);
        timeout.tv_sec += 10;
        while ((ret = sem_timedwait(&localSem_, &timeout)) == -1 && errno == EINTR) {
            cout << "wait interrupted system call" << endl;
            continue;
        }
        ASSERT_EQ(ret, 0);
        if (ret == -1 && errno == ETIMEDOUT) {
            cout << "wait time out" << endl;
        }
    }
}
void AuthSessionTest::CloseAllSession(void)
{
    for (auto session : sessionSet_) {
        CloseSession(session);
        sessionSet_.erase(session);
    }
    Wsleep(2, 1);
}

void AuthSessionTest::TestServerSide(void)
{
    int32_t ret = CreateSessionServer(FILE_TEST_PKG_NAME.c_str(), FILE_SESSION_NAME.c_str(), &g_listener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = CreateSessionServer(FILE_TEST_PKG_NAME.c_str(), FILE_SESSION_NAME_DEMO.c_str(), &g_listener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = SetFileReceiveListener(FILE_TEST_PKG_NAME.c_str(), FILE_SESSION_NAME.c_str(),
        &g_fileRecvListener, RECV_ROOT_PATH);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = SetFileReceiveListener(FILE_TEST_PKG_NAME.c_str(), FILE_SESSION_NAME_DEMO.c_str(),
        &g_fileRecvListener, RECV_ROOT_PATH);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ServerWait(3600, 1);
    ret = RemoveSessionServer(FILE_TEST_PKG_NAME.c_str(), FILE_SESSION_NAME.c_str());
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = RemoveSessionServer(FILE_TEST_PKG_NAME.c_str(), FILE_SESSION_NAME_DEMO.c_str());
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void AuthSessionTest::TestSendMessage(int32_t sendCnt, const char *data, uint32_t len, bool ex)
{
    for (auto session : sessionSet_) {
        cout << "send message, session id = " << session << endl;
        int32_t ret;
        for (int32_t i = 0; i < sendCnt; i++) {
            ret = SendMessage(session, data, len);
            if (ex) {
                ASSERT_NE(ret, SOFTBUS_OK);
            } else {
                if (ret != SOFTBUS_OK && ret != SOFTBUS_TIMOUT) {
                    EXPECT_EQ(ret, SOFTBUS_OK);
                }
                Wsleep(10, 2);
            }
        }
    }
    Wsleep(1, 1);
}
void AuthSessionTest::TestSendBytes(int32_t sendCnt, const char *data, uint32_t len, bool ex)
{
    for (auto session : sessionSet_) {
        cout << "send bytes, session id = " << session << endl;
        int32_t ret;
        for (int32_t i = 0; i < sendCnt; i++) {
            ret = SendBytes(session, data, len);
            if (ex) {
                ASSERT_NE(ret, SOFTBUS_OK);
            } else {
                EXPECT_EQ(ret, SOFTBUS_OK);
                Wsleep(10, 2);
            }
        }
    }
    Wsleep(1, 1);
}
void AuthSessionTest::TestSendFile(int32_t sendCnt, const char *sfileList[], const char *dfileList[],
    int32_t cnt, bool ex)
{
    for (auto session : sessionSet_) {
        cout << "send file, session id = " << session << endl;
        int32_t ret;
        for (int32_t i = 0; i < sendCnt; i++) {
            ret = SendFile(session, sfileList, dfileList, cnt);
            if (ex) {
                ASSERT_NE(ret, SOFTBUS_OK);
            } else {
                EXPECT_EQ(ret, SOFTBUS_OK);
            }
            Wsleep(1, 1);
        }
    }
    Wsleep(5, 1);
}

void AuthSessionTest::TransTest(TransTestInfo &transInfo, int32_t testDataType, bool ex)
{
    cout << "testCnt = " << transInfo.sendNum << endl;
    OpenAllSession(transInfo.dataType, transInfo.mySessionName, transInfo.peerSessionName);
    if (testDataType == TYPE_BYTES) {
        char *data = (char *)malloc(SEND_DATA_SIZE_1M);
        ASSERT_NE(data, nullptr);
        (void)memset_s(data, SEND_DATA_SIZE_1M, 0, SEND_DATA_SIZE_1M);
        ASSERT_NE(data, nullptr);
        int32_t ret = memcpy_s(data, SEND_DATA_SIZE_1M, g_testData, strlen(g_testData));
        EXPECT_EQ(ret, EOK);
        TestSendBytes(transInfo.sendNum, data, ex ? SEND_DATA_SIZE_1M : SEND_DATA_SIZE_4K, ex);
        free(data);
    } else if (testDataType == TYPE_MESSAGE) {
        char *data = (char *)malloc(SEND_DATA_SIZE_1M);
        ASSERT_NE(data, nullptr);
        (void)memset_s(data, SEND_DATA_SIZE_1M, 0, SEND_DATA_SIZE_1M);
        ASSERT_NE(data, nullptr);
        int32_t ret = memcpy_s(data, SEND_DATA_SIZE_1M, g_testData, strlen(g_testData));
        EXPECT_EQ(ret, EOK);
        TestSendMessage(transInfo.sendNum, data, ex ? SEND_DATA_SIZE_1M : SEND_DATA_SIZE_1K, ex);
        free(data);
    } else if (testDataType == TYPE_FILE) {
        TestSendFile(transInfo.sendNum, transInfo.sfileList, transInfo.dfileList, transInfo.sfileCnt, ex);
    } else if (testDataType == TYPE_STREAM) {
        Wsleep(100, 2);
        CloseAllSession();
        return;
    }
    Wsleep(2, 1);
    CloseAllSession();
}

void AuthSessionTest::TransTestCase001(TransTestInfo &transInfo)
{
    cout << "testCnt = " << transInfo.testCnt << endl;
    char *data = (char *)malloc(SEND_DATA_SIZE_1M);
    ASSERT_NE(data, nullptr);
    (void)memset_s(data, SEND_DATA_SIZE_1M, 0, SEND_DATA_SIZE_1M);
    ASSERT_NE(data, nullptr);
    int32_t ret = memcpy_s(data, SEND_DATA_SIZE_1M, g_testData, strlen(g_testData));
    int32_t ret2;
    EXPECT_EQ(ret, EOK);
    OpenAllSession(transInfo.dataType, transInfo.mySessionName, transInfo.peerSessionName);
    for (int32_t i = 0; i < transInfo.testCnt; i++) {
        for (auto session : sessionSet_) {
            cout << "send bytes, session id = " << session << endl;
            for (int32_t j = 0; j < transInfo.sendNum; j++) {
                ret = SendBytes(session, data, SEND_DATA_SIZE_4K);
                ret2 = SendMessage(session, data, SEND_DATA_SIZE_1K);
                EXPECT_EQ(ret, 0);
                if (ret2 != SOFTBUS_OK && ret2 != SOFTBUS_TIMOUT) {
                    EXPECT_EQ(ret2, 0);
                }
            }
        }
    }
    free(data);
    data = nullptr;
    Wsleep(2, 1);
    CloseAllSession();
}

/*
* @tc.name: testSendBytesMessage001
* @tc.desc: test send bytes message, use different session name.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthSessionTest, testSendBytesMessage001, TestSize.Level1)
{
    if (testEntryArgs_->testSide_ == PASSIVE_OPENSESSION_WAY) {
        TestServerSide();
        return;
    }
    if (testEntryArgs_->testSide_ != ACTIVE_OPENSESSION_WAY) {
        return;
    }
    TransTestInfo transInfo = {
        .mySessionName = FILE_SESSION_NAME,
        .peerSessionName = FILE_SESSION_NAME,
        .testCnt = 1,
        .sendNum = testEntryArgs_->transNums_,
        .dataType = TYPE_FILE,
    };
    int32_t ret = CreateSessionServer(FILE_TEST_PKG_NAME.c_str(), transInfo.mySessionName.c_str(), &g_listener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    TransTestCase001(transInfo);
    Wsleep(1, 1);
    ret = RemoveSessionServer(FILE_TEST_PKG_NAME.c_str(), transInfo.mySessionName.c_str());
    EXPECT_EQ(ret, SOFTBUS_OK);
};

/*
* @tc.name: testSendBytesMessage002
* @tc.desc: test send bytes 2 message, use different session name.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthSessionTest, testSendBytesMessage002, TestSize.Level1)
{
    if (testEntryArgs_->testSide_ == PASSIVE_OPENSESSION_WAY) {
        TestServerSide();
        return;
    }
    if (testEntryArgs_->testSide_ != ACTIVE_ANOTHER_OPENSESSION_WAY) {
        return;
    }
    TransTestInfo transInfo = {
        .mySessionName = FILE_SESSION_NAME_DEMO,
        .peerSessionName = FILE_SESSION_NAME_DEMO,
        .testCnt = 1,
        .sendNum = testEntryArgs_->transNums_,
        .dataType = TYPE_FILE,
    };
    int32_t ret = CreateSessionServer(FILE_TEST_PKG_NAME_DEMO.c_str(), transInfo.mySessionName.c_str(), &g_listener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    TransTestCase001(transInfo);
    Wsleep(1, 1);
    ret = RemoveSessionServer(FILE_TEST_PKG_NAME_DEMO.c_str(), transInfo.mySessionName.c_str());
    EXPECT_EQ(ret, SOFTBUS_OK);
};

/*
* @tc.name: testSendFile001
* @tc.desc: test send file, use different pkgname.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthSessionTest, testSendFile001, TestSize.Level1)
{
    if (testEntryArgs_->testSide_ == PASSIVE_OPENSESSION_WAY) {
        TestServerSide();
        return;
    }
    const char *sfileList[10] = {0};
    const char *dfileList[10] = {0};
    sfileList[0] = SFILE_NAME_1K;
    sfileList[1] = SFILE_NAME_5M;
    dfileList[0] = DFILE_NAME_1K;
    dfileList[1] = DFILE_NAME_5M;
    TransTestInfo transInfo = {
        .testCnt = 1,
        .sendNum = 1,
        .dataType = TYPE_FILE,
        .sfileList = sfileList,
        .dfileList = dfileList,
        .sfileCnt = 1,
    };
    std::string pkgName;
    if (testEntryArgs_->testSide_ == ACTIVE_OPENSESSION_WAY) {
        pkgName = FILE_TEST_PKG_NAME;
        transInfo.mySessionName = FILE_SESSION_NAME;
        transInfo.peerSessionName = FILE_SESSION_NAME;
    } else if (testEntryArgs_->testSide_ == ACTIVE_ANOTHER_OPENSESSION_WAY) {
        pkgName = FILE_TEST_PKG_NAME_DEMO;
        transInfo.mySessionName = FILE_SESSION_NAME_DEMO;
        transInfo.peerSessionName = FILE_SESSION_NAME_DEMO;
    } else {
        return;
    }

    int32_t ret = CreateSessionServer(pkgName.c_str(), transInfo.mySessionName.c_str(), &g_listener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = SetFileSendListener(pkgName.c_str(), transInfo.mySessionName.c_str(), &g_fileSendListener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    TransTest(transInfo, TYPE_FILE);
    Wsleep(1, 1);
    ret = RemoveSessionServer(pkgName.c_str(), transInfo.mySessionName.c_str());
    EXPECT_EQ(ret, SOFTBUS_OK);
};

} // namespace OHOS