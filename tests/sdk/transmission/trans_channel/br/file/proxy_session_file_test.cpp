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

const std::string FILE_TEST_PKG_NAME = "com.huawei.plrdtest.dsoftbus";
const std::string FILE_TEST_PKG_NAME_DEMO = "com.huawei.plrdtest.dsoftbus1";
const std::string FILE_SESSION_NAME = "com.huawei.plrdtest.dsoftbus.JtSendFile_10";
const std::string FILE_SESSION_NAME_DEMO = "com.huawei.plrdtest.dsoftbus.JtSendFile_demo";

const int32_t SEND_DATA_SIZE_1K = 1024;
const int32_t SEND_DATA_SIZE_4K = 4 * 1024;
const int32_t SEND_DATA_SIZE_1M = 1024 * 1024;
const char *g_testData = "{\"data\":\"open session test!!!\"}";

const char *SFILE_NAME_ERR = "/data/errFileName";
const char *SFILE_NAME_1K = "/data/file1K.tar";
const char *SFILE_NAME_5M = "/data/file5M.tar";
const char *SFILE_NAME_5M1 = "/data/file5M1.tar";

const char *DFILE_NAME_1K = "file1K.tar";
const char *DFILE_NAME_1K_2 = "file1K_2.tar";
const char *DFILE_NAME_1K_3 = "file1K_3.tar";
const char *DFILE_NAME_5M = "file5M.tar";
const char *DFILE_NAME_5M_2 = "file5M_2.tar";
const char *DFILE_NAME_5M_3 = "file5M_3.tar";
const char *DFILE_NAME_5M1 = "file5M1.tar";
const char *RECV_ROOT_PATH = "/data/recv/";

const int32_t OPEN_SESSION_SEM_WAIT_TIME = 10;

const int32_t WSLEEP_SEC_TYPE = 1;
const int32_t WSLEEP_SEC_UNIT = 1;
const int32_t WSLEEP_COMM_TIME = 2;
const int32_t WSLEEP_SEM_WAIT_TIME = 4;

const int32_t WSLEEP_MSEC_TYPE = 2;
const int32_t WSLEEP_MSEC_UNIT = 1000;
const int32_t WSLEEP_SEND_BYTES_TIME = 10;
const int32_t WSLEEP_PTHREAD_SEND_FILE_WAIT_TIME = 500;
const uint32_t TEST_SEND_FILE_COUNT = 2;

struct TransTestInfo {
    string mySessionName;
    string peerSessionName;
    int32_t testCnt;
    int32_t sendNum;
    int32_t dataType;
    const char **sfileList;
    const char **dfileList;
    int32_t sfileCnt;
};

unordered_set<string> networkIdSet_;
unordered_set<int32_t> sessionSet_;
sem_t localSem_;
int32_t openSessionSuccessCnt_ = 0;
const SoftbusTestEntry *testEntryArgs_ = nullptr;

const int32_t WAIT_ONLINE_TIME = 5;
const int32_t GET_LNN_RETRY_COUNT = 5;
int32_t WaitDeviceOnline(const char *pkgName)
{
    int32_t onlineRetryCount = 0;
    int32_t ret;
    while (true) {
        NodeBasicInfo *onlineDevices = nullptr;
        int32_t onlineNum = 0;
        ret = GetAllNodeDeviceInfo(pkgName, &onlineDevices, &onlineNum);
        onlineRetryCount++;
        if (onlineRetryCount < GET_LNN_RETRY_COUNT && (ret != SOFTBUS_OK || onlineNum <= 0)) {
            FreeNodeInfo(onlineDevices);
            sleep(WAIT_ONLINE_TIME);
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
    cout << "send process id = " << sessionId << ", upload = " << bytesUpload << ", total = " << bytesTotal << endl;
    return 0;
}

int32_t OnSendFileFinished(int32_t sessionId, const char *firstFile)
{
    printf("send finished id = %d, first file = %s\n", sessionId, firstFile);
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
    static void ServerWait(int32_t waitTime);
    static void OpenAllSession(int32_t dataType, const string &mySessionName, const string &peerSessionName);
    static void TestServerSide(void);

    static void CloseAllSession(void);
    static void TestSendMessage(int32_t sendCnt, const char *data, uint32_t len, bool ex = false);
    static void TestSendBytes(int32_t sendCnt, const char *data, uint32_t len, bool ex = false);

    static void TestSendFile(int32_t sendCnt, const char *sfileList[], const char *dfileList[],
        int32_t cnt, bool ex = false);

    static void TransTest(struct TransTestInfo &transInfo, int32_t testDataType, bool ex = false);
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
    Wsleep(WSLEEP_COMM_TIME, WSLEEP_SEC_TYPE);
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
        if (usl == WSLEEP_SEC_TYPE) {
            sleep(WSLEEP_SEC_UNIT);
        } else {
            usleep(WSLEEP_MSEC_UNIT);
        }
        count--;
    }
}
void AuthSessionTest::ServerWait(int32_t waitTime)
{
    cout << "waitTime = " << waitTime << endl;
    int32_t ret = sem_wait(&localSem_);
    EXPECT_EQ(ret, 0);
    int32_t i = 0;
    while (i++ < waitTime) {
        Wsleep(WSLEEP_SEM_WAIT_TIME, WSLEEP_SEC_TYPE);
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
        timeout.tv_sec += OPEN_SESSION_SEM_WAIT_TIME;
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
    }
    sessionSet_.clear();
    Wsleep(WSLEEP_COMM_TIME, WSLEEP_SEC_TYPE);
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
    ServerWait(testEntryArgs_->aliveTime_);
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
                Wsleep(WSLEEP_SEND_BYTES_TIME, WSLEEP_MSEC_TYPE);
            }
        }
    }
    Wsleep(WSLEEP_COMM_TIME, WSLEEP_SEC_TYPE);
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
                Wsleep(WSLEEP_SEND_BYTES_TIME, WSLEEP_MSEC_TYPE);
            }
        }
    }
    Wsleep(WSLEEP_COMM_TIME, WSLEEP_SEC_TYPE);
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
                Wsleep(WSLEEP_COMM_TIME, WSLEEP_SEC_TYPE);
            }
        }
    }
    if (!ex) {
        Wsleep(WSLEEP_COMM_TIME, WSLEEP_SEC_TYPE);
        Wsleep(WSLEEP_COMM_TIME, WSLEEP_SEC_TYPE);
    }
}

void AuthSessionTest::TransTest(struct TransTestInfo &transInfo, int32_t testDataType, bool ex)
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
        Wsleep(WSLEEP_SEND_BYTES_TIME, WSLEEP_MSEC_TYPE);
        CloseAllSession();
        return;
    }
    if (!ex) {
        Wsleep(WSLEEP_COMM_TIME, WSLEEP_SEC_TYPE);
    }
    CloseAllSession();
}

/*
* @tc.name: testSendFile001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthSessionTest, testSendFile001, TestSize.Level1)
{
    if (testEntryArgs_->testSide_ == PASSIVE_OPENSESSION_WAY) {
        TestServerSide();
        return;
    }
    const char *sfileList[10] = {nullptr};
    const char *dfileList[10] = {nullptr};
    sfileList[0] = SFILE_NAME_1K;
    sfileList[1] = SFILE_NAME_5M;
    dfileList[0] = DFILE_NAME_1K;
    dfileList[1] = DFILE_NAME_5M;
    struct TransTestInfo transInfo = {
        .testCnt = 1,
        .sendNum = 1,
        .dataType = TYPE_FILE,
        .sfileList = sfileList,
        .dfileList = dfileList,
        .sfileCnt = 2,
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
    ret = RemoveSessionServer(pkgName.c_str(), transInfo.mySessionName.c_str());
    EXPECT_EQ(ret, SOFTBUS_OK);
};

void *AuthSessionTest::TestSendFileThread(void *arg)
{
    Wsleep(WSLEEP_PTHREAD_SEND_FILE_WAIT_TIME, WSLEEP_MSEC_TYPE);
    cout << "TestSendFileThread start" << endl;
    const char *sfileList[TEST_SEND_FILE_COUNT + 1] = {nullptr};
    const char *dfileList[TEST_SEND_FILE_COUNT + 1] = {nullptr};
    sfileList[0] = SFILE_NAME_1K;
    sfileList[1] = SFILE_NAME_5M;
    dfileList[0] = DFILE_NAME_1K_3;
    dfileList[1] = DFILE_NAME_5M_3;
    TestSendFile(1, sfileList, dfileList, TEST_SEND_FILE_COUNT);
    cout << "TestSendFileThread end" << endl;
    return nullptr;
}
/*
* @tc.name: testSendFile002
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthSessionTest, testSendFile002, TestSize.Level1)
{
    if (testEntryArgs_->testSide_ == PASSIVE_OPENSESSION_WAY) {
        TestServerSide();
        return;
    }
    std::string pkgName;
    std::string mySessionName;
    std::string peerSessionName;
    if (testEntryArgs_->testSide_ == ACTIVE_OPENSESSION_WAY) {
        pkgName = FILE_TEST_PKG_NAME;
        mySessionName = FILE_SESSION_NAME;
        peerSessionName = FILE_SESSION_NAME;
    } else if (testEntryArgs_->testSide_ == ACTIVE_ANOTHER_OPENSESSION_WAY) {
        pkgName = FILE_TEST_PKG_NAME_DEMO;
        mySessionName = FILE_SESSION_NAME_DEMO;
        peerSessionName = FILE_SESSION_NAME_DEMO;
    } else {
        return;
    }

    int32_t ret = CreateSessionServer(pkgName.c_str(), mySessionName.c_str(), &g_listener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = SetFileSendListener(pkgName.c_str(), mySessionName.c_str(), &g_fileSendListener);
    ASSERT_EQ(ret, SOFTBUS_OK);
    const char *sfileList[TEST_SEND_FILE_COUNT + 1] = {nullptr};
    const char *dfileList[TEST_SEND_FILE_COUNT + 1] = {nullptr};
    sfileList[0] = SFILE_NAME_1K;
    sfileList[1] = SFILE_NAME_5M;
    dfileList[0] = DFILE_NAME_1K_2;
    dfileList[1] = DFILE_NAME_5M_2;
    OpenAllSession(TYPE_FILE, mySessionName, peerSessionName);
    pthread_t tid;
    int32_t createPthreadRet = pthread_create(&tid, nullptr, AuthSessionTest::TestSendFileThread, nullptr);
    EXPECT_EQ(createPthreadRet, 0);
    cout << "TestSendFile start" << endl;
    TestSendFile(1, sfileList, dfileList, TEST_SEND_FILE_COUNT);
    cout << "TestSendFile end" << endl;
    if (createPthreadRet == 0 && pthread_join(tid, nullptr) != 0) {
        cout << "join thread error" << endl;
    }
    CloseAllSession();
    ret = RemoveSessionServer(pkgName.c_str(), mySessionName.c_str());
    EXPECT_EQ(ret, SOFTBUS_OK);
};

/*
* @tc.name: testOpenSessionEx001
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AuthSessionTest, testSendFileEx001, TestSize.Level1)
{
    if (testEntryArgs_->testSide_ == PASSIVE_OPENSESSION_WAY) {
        TestServerSide();
        return;
    }
    const char *sfileList[1] = {nullptr};
    const char *dfileList[1] = {nullptr};
    sfileList[0] = SFILE_NAME_ERR;
    dfileList[0] = SFILE_NAME_ERR;
    struct TransTestInfo transInfo = {
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

    TransTest(transInfo, TYPE_FILE, true);

    sfileList[0] = SFILE_NAME_5M1;
    dfileList[0] = DFILE_NAME_5M1;
    TransTest(transInfo, TYPE_FILE, true);

    sfileList[0] = SFILE_NAME_5M1;
    transInfo.dfileList = nullptr;
    TransTest(transInfo, TYPE_FILE, true);

    ret = RemoveSessionServer(pkgName.c_str(), transInfo.mySessionName.c_str());
    EXPECT_EQ(ret, SOFTBUS_OK);
};
} // namespace OHOS