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

#include <cstdio>
#include <cstdlib>
#include <unistd.h>

#include "securec.h"
#include "session.h"
#include "softbus_bus_center.h"
#include "softbus_def.h"
#include "softbus_errcode.h"

#define LOG2_DBG(fmt, ...) printf("DEBUG:%s:%s:%d " fmt "\n", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOG2_INFO(fmt, ...) printf("INFO:%s:%d " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOG2_WARN(fmt, ...) printf("WARN:%s:%d " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOG2_ERR(fmt, ...)  printf("ERROR:%s:%d " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)

namespace {
const int NETWORK_ID_LEN = 65;
const int ARG_NUM = 2;
const int FILE_NUM = 4;

const char *g_testModuleName   = "com.huawei.plrdtest.dsoftbus";
const char *g_testSessionName  = "com.huawei.plrdtest.dsoftbus.JtOnOpenFileSession";
const char *g_testSessionNamE2 = "com.huawei.plrdtest.dsoftbus.JtOpenFileSession";
const char *g_testGroupId = "g_testGroupId";

enum StatusNum {
    TRANS_STATE_NONE = 0,           // 0
    TRANS_STATE_INIT,           // 1
    TRANS_STATE_CREATE_SESSION_SERVER,  // 2
    TRANS_SET_FILE_SEND_LISTENER, // 3
    TRANS_STATE_OPEN,           // 4
    TRANS_STATE_SEND_BYTE,      // 5
    TRANS_STATE_SEND_MESSAGE,   // 6
    TRANS_STATE_SEND_FILE,   // 7
    TRANS_STATE_CLOSE,          // 8
    TRANS_STATE_REMOVE_SESSION_SERVER, // 9
    TRANS_STATE_CREATE_PHONE = 10, // 10
    TRANS_STATE_GET_SESSION_NAME, // 11
    TRANS_STATE_GET_DEVICE_ID, // 12
    TRANS_CLEAR_LOG,
    TRANS_TEST_FIN,

    LNN_STATE_JOINLNN = 20,     // 20
    LNN_STATE_LEAVELNN,         // 21
};

ISessionListener g_sessionlistener;
SessionAttribute g_sessionAttr;
int32_t g_sessionId = -1;
char g_networkId[NETWORK_ID_LEN] = {0};
int32_t g_stateDebug = LNN_STATE_JOINLNN;
}

static void TestChangeDebugState(int32_t state)
{
    g_stateDebug = state;
    LOG2_INFO("change to debug state: %d", state);
}

static void OnLeaveLNNDone(const char *networkId, int32_t retCode)
{
    if (networkId == nullptr) {
        LOG2_ERR("OnLeaveLNNDone error! retCode = %d", retCode);
        return;
    }

    LOG2_INFO("OnLeaveLNNDone enter networdid = %s, retCode = %d", networkId, retCode);
}

static void OnNodeOnline(NodeBasicInfo *info)
{
    if (info == nullptr) {
        return;
    }
    if (strcpy_s(g_networkId, NETWORK_ID_LEN, info->networkId) != EOK) {
        return;
    }
    TestChangeDebugState(TRANS_STATE_CREATE_SESSION_SERVER);
    LOG2_INFO("node online, network id: %s", info->networkId);
}

static void OnNodeOffline(NodeBasicInfo *info)
{
    if (info == nullptr) {
        return;
    }
    LOG2_INFO("node offline, network id: %s", info->networkId);
}

static INodeStateCb g_nodeStateCallback = {
    .events = EVENT_NODE_STATE_ONLINE | EVENT_NODE_STATE_OFFLINE,
    .onNodeOnline = OnNodeOnline,
    .onNodeOffline = OnNodeOffline,
};

static int OnSessionOpened(int sessionId, int result)
{
    LOG2_INFO("############# session opened,sesison id[%d] result[%d]", sessionId, result);
    if (result == SOFTBUS_OK) {
        TestChangeDebugState(TRANS_STATE_SEND_FILE);
    } else {
        TestChangeDebugState(-1);
    }
    return result;
}

static void OnSessionClosed(int sessionId)
{
    LOG2_INFO("session closed, session id = %d", sessionId);
    TestChangeDebugState(TRANS_STATE_REMOVE_SESSION_SERVER);
}

static void OnBytesReceived(int sessionId, const void *data, unsigned int len)
{
    LOG2_INFO("session bytes received, sessionid[%d], dataLen[%u]", sessionId, len);
}

static void OnMessageReceived(int sessionId, const void *data, unsigned int len)
{
    LOG2_INFO("session msg received, sessionid[%d], dataLen[%u]", sessionId, len);
}

static void TestSessionListenerInit(void)
{
    g_sessionlistener.OnSessionOpened = OnSessionOpened;
    g_sessionlistener.OnSessionClosed = OnSessionClosed;
    g_sessionlistener.OnBytesReceived = OnBytesReceived;
    g_sessionlistener.OnMessageReceived = OnMessageReceived;

    g_sessionAttr.dataType = TYPE_FILE;
}

static int OnSendFileProcess(int sessionId, uint64_t bytesUpload, uint64_t bytesTotal)
{
    LOG2_INFO("OnSendFileProcess sessionId = %d, bytesUpload = %" PRIu64 ", total = %" PRIu64 "\n",
        sessionId, bytesUpload, bytesTotal);
    return 0;
}

static int OnSendFileFinished(int sessionId, const char *firstFile)
{
    LOG2_INFO("OnSendFileFinished sessionId = %d, first file = %s\n", sessionId, firstFile);
    TestChangeDebugState(TRANS_STATE_CLOSE);
    return 0;
}

static void OnFileTransError(int sessionId)
{
    LOG2_INFO("OnFileTransError sessionId = %d\n", sessionId);
}

static IFileSendListener g_fileSendListener = {
    .OnSendFileProcess = OnSendFileProcess,
    .OnSendFileFinished = OnSendFileFinished,
    .OnFileTransError = OnFileTransError,
};

static void TestSetFileSendListener(void)
{
    LOG2_INFO("*******************SET FILE SEND LISTENER*************");
    int ret = SetFileSendListener(g_testModuleName, g_testSessionName, &g_fileSendListener);
    LOG2_INFO("SetFileSendListener ret = %d\n", ret);
}

static int TestSendFile(int sessionId)
{
    const char *sfileList[] = {
        "/data/big.tar",
        "/data/richu.jpg",
        "/data/richu-002.jpg",
        "/data/richu-003.jpg",
    };
    int ret = SendFile(sessionId, sfileList, nullptr, FILE_NUM);
    LOG2_INFO("SendFile ret = %d\n", ret);
    return ret;
}

static void TestActiveSendFile(int state)
{
    switch (state) {
        case TRANS_STATE_CREATE_SESSION_SERVER: {
            int ret = CreateSessionServer(g_testModuleName, g_testSessionName, &g_sessionlistener);
            LOG2_INFO("CreateSessionServer ret: %d ", ret);
            if (ret != -986 && ret != SOFTBUS_OK) { // -986: SOFTBUS_SERVER_NAME_REPEATED
                LOG2_ERR("CreateSessionServer ret: %d ", ret);
                return;
            }
            TestSetFileSendListener();
            TestChangeDebugState(TRANS_STATE_OPEN);
            break;
        }
        case TRANS_STATE_OPEN: {
            g_sessionId = OpenSession(g_testSessionName, g_testSessionName, g_networkId, g_testGroupId, &g_sessionAttr);
            if (g_sessionId < 0) {
                LOG2_ERR("OpenSession ret[%d]", g_sessionId);
                return;
            }
            break;
        }
        case TRANS_STATE_SEND_FILE: {
            TestSendFile(g_sessionId);
            TestChangeDebugState(TRANS_TEST_FIN);
            break;
        }
        case TRANS_STATE_CLOSE: {
            CloseSession(g_sessionId);
            g_sessionId = -1;
            TestChangeDebugState(TRANS_STATE_REMOVE_SESSION_SERVER);
            break;
        }
        case TRANS_STATE_REMOVE_SESSION_SERVER: {
            int ret = RemoveSessionServer(g_testModuleName, g_testSessionName);
            if (ret != SOFTBUS_OK) {
                LOG2_ERR("RemoveSessionServer failed, ret %d ", ret);
                return;
            }
            LOG2_INFO("RemoveSessionServer success, ret %d ", ret);
            TestChangeDebugState(LNN_STATE_LEAVELNN);
            break;
        }
        case LNN_STATE_LEAVELNN: {
            LeaveLNN(g_testModuleName, g_networkId, OnLeaveLNNDone);
            TestChangeDebugState(-1);
            break;
        }
        default: {
        }
    }
}

static int OnSessionOpenRecvFile(int sessionId, int result)
{
    LOG2_INFO("############# recv session opened,sesison id[%d] result[%d]", sessionId, result);
    return 0;
}

static int OnReceiveFileStarted(int sessionId, const char *files, int fileCnt)
{
    LOG2_INFO("File receive start sessionId = %d, first file = %s, fileCnt = %d\n", sessionId, files, fileCnt);
    return 0;
}

static void OnReceiveFileFinished(int sessionId, const char *files, int fileCnt)
{
    LOG2_INFO("File receive finished sessionId = %d, first file = %s, fileCnt = %d\n", sessionId, files, fileCnt);
}

static IFileReceiveListener g_fileRecvListener = {
    .OnReceiveFileStarted = OnReceiveFileStarted,
    .OnReceiveFileFinished = OnReceiveFileFinished,
    .OnFileTransError = OnFileTransError,
};

static void TestSetFileRecvListener()
{
    int ret = SetFileReceiveListener(g_testModuleName, g_testSessionNamE2, &g_fileRecvListener, "/data/");
    LOG2_INFO("SetFileRecvListener ret = %d\n", ret);
}

static void TestReceiveFile(int state)
{
    int ret = 0;
    switch (state) {
        case TRANS_STATE_CREATE_SESSION_SERVER: {
            g_sessionlistener.OnSessionOpened = OnSessionOpenRecvFile;
            ret = CreateSessionServer(g_testModuleName, g_testSessionNamE2, &g_sessionlistener);
            LOG2_INFO("CreateSessionServer ret: %d ", ret);
            if (ret != -986 && ret != SOFTBUS_OK) { // -986: SOFTBUS_SERVER_NAME_REPEATED
                LOG2_ERR("CreateSessionServer ret: %d ", ret);
                return;
            }
            TestSetFileRecvListener();
            TestChangeDebugState(TRANS_TEST_FIN);
            break;
        }
        default: {
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc == 1) {
        return -1;
    }
    int testWay = 0;
    if (argc >= ARG_NUM) {
        testWay = atoi(argv[1]);
    }
    TestSessionListenerInit();

    if (RegNodeDeviceStateCb(g_testModuleName, &g_nodeStateCallback) != SOFTBUS_OK) {
        LOG2_ERR("RegNodeDeviceStateCb error!");
        return SOFTBUS_ERR;
    }

    LOG2_INFO("\n$$$$$$$$$ Start transmission.........");
    while (1) {
        sleep(1);
        if (g_stateDebug == TRANS_TEST_FIN) {
            continue;
        }
        if (testWay == 0) {
            TestActiveSendFile(g_stateDebug);
        } else if (testWay == 1) {
            TestReceiveFile(g_stateDebug);
        }
        if (g_stateDebug == -1) {
            break;
        }
    }
    LOG2_INFO("\n############### TEST PASS ###############\n");
    return 0;
}
