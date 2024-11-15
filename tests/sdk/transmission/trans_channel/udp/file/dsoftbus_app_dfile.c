/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "securec.h"
#include "session.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"

#define LOG2_DBG(fmt, ...) printf("DEBUG:%s:%s:%d " fmt "\n", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOG2_INFO(fmt, ...) printf("INFO:%s:%d " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOG2_WARN(fmt, ...) printf("WARN:%s:%d " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOG2_ERR(fmt, ...)  printf("ERROR:%s:%d " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define NETWORK_ID_LEN 65
#define ARG_NUM 2
#define FILE_NUM 4

typedef enum {
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
} StatusNum;

static const char *g_testModuleName    = "com.huawei.plrdtest.dsoftbus";
static const char *g_testSessionName   = "com.huawei.plrdtest.dsoftbus.JtOpenFileSession";
static const char *g_testSessionNameE2 = "com.huawei.plrdtest.dsoftbus.JtOnOpenFileSession";
static const char *g_testGroupId = "g_testGroupId";
static ISessionListener g_sessionlistener;
static SessionAttribute g_sessionAttr;
static int32_t g_sessionId = -1;
static char g_networkId[NETWORK_ID_LEN] = {0};
static int32_t g_stateDebug = LNN_STATE_JOINLNN;

static void TestChangeDebugState(int32_t state)
{
    g_stateDebug = state;
    LOG2_INFO("change to debug state: %d", state);
}

static void OnLeaveLNNDone(const char *networkId, int32_t retCode)
{
    if (networkId == NULL) {
        LOG2_ERR("OnLeaveLNNDone error! retCode = %d", retCode);
        return;
    }

    LOG2_INFO("OnLeaveLNNDone enter networdid = %s, retCode = %d", networkId, retCode);
}

static void OnNodeOnline(NodeBasicInfo *info)
{
    if (info == NULL) {
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
    if (info == NULL) {
        return;
    }
    LOG2_INFO("node offline, network id: %s", info->networkId);
}

static INodeStateCb g_nodeStateCallback = {
    .events = EVENT_NODE_STATE_ONLINE | EVENT_NODE_STATE_OFFLINE,
    .onNodeOnline = OnNodeOnline,
    .onNodeOffline = OnNodeOffline,
};

static int32_t OnSessionOpened(int32_t sessionId, int32_t result)
{
    LOG2_INFO("############# session opened,sesison id[%d] result[%d]", sessionId, result);
    if (result == SOFTBUS_OK) {
        TestChangeDebugState(TRANS_STATE_SEND_FILE);
    } else {
        TestChangeDebugState(-1);
    }
    return result;
}

static void OnSessionClosed(int32_t sessionId)
{
    LOG2_INFO("session closed, session id = %d", sessionId);
    TestChangeDebugState(TRANS_STATE_REMOVE_SESSION_SERVER);
}

static void OnBytesReceived(int32_t sessionId, const void *data, uint32_t len)
{
    (void)data;
    LOG2_INFO("session bytes received, sessionid[%d], dataLen[%u]", sessionId, len);
}

static void OnMessageReceived(int32_t sessionId, const void *data, uint32_t len)
{
    (void)data;
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

static int32_t OnSendFileProcess(int32_t sessionId, uint64_t bytesUpload, uint64_t bytesTotal)
{
    LOG2_INFO("OnSendFileProcess sessionId = %d, bytesUpload = %" PRIu64 ", total = %" PRIu64 "\n",
        sessionId, bytesUpload, bytesTotal);
    return SOFTBUS_OK;
}

static int32_t OnSendFileFinished(int32_t sessionId, const char *firstFile)
{
    LOG2_INFO("OnSendFileFinished sessionId = %d, first file = %s\n", sessionId, firstFile);
    TestChangeDebugState(TRANS_STATE_CLOSE);
    return SOFTBUS_OK;
}

static void OnFileTransError(int32_t sessionId)
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
    int32_t ret = SetFileSendListener(g_testModuleName, g_testSessionName, &g_fileSendListener);
    if (ret != SOFTBUS_OK) {
        LOG2_INFO("SetFileSendListener ret = %d\n", ret);
    } else {
        LOG2_INFO("TestSetFileSendListener ok\n");
    }
}

static int32_t TestSendFile(int32_t sessionId)
{
    const char *sfileList[] = {
        "/data/big.tar",
        "/data/richu.jpg",
        "/data/richu-002.jpg",
        "/data/richu-003.jpg",
    };
    int32_t ret = SendFile(sessionId, sfileList, NULL, FILE_NUM);
    if (ret != SOFTBUS_OK) {
        LOG2_INFO("SendFile ret = %d\n", ret);
    } else {
        LOG2_INFO("SendFile ok\n");
    }
    return ret;
}

static void TestActiveSendFile(int32_t state)
{
    switch (state) {
        case TRANS_STATE_CREATE_SESSION_SERVER:
            int32_t ret = CreateSessionServer(g_testModuleName, g_testSessionName, &g_sessionlistener);
            LOG2_INFO("CreateSessionServer ret: %d", ret);
            if (ret != SOFTBUS_SERVER_NAME_REPEATED && ret != SOFTBUS_OK) {
                LOG2_ERR("CreateSessionServer ret: %d", ret);
                return;
            }
            TestSetFileSendListener();
            TestChangeDebugState(TRANS_STATE_OPEN);
            break;
        case TRANS_STATE_OPEN:
            g_sessionId = OpenSession(g_testSessionName, g_testSessionName, g_networkId, g_testGroupId, &g_sessionAttr);
            if (g_sessionId < 0) {
                LOG2_ERR("OpenSession ret[%d]", g_sessionId);
                return;
            }
            break;
        case TRANS_STATE_SEND_FILE:
            TestSendFile(g_sessionId);
            TestChangeDebugState(TRANS_TEST_FIN);
            break;
        case TRANS_STATE_CLOSE:
            CloseSession(g_sessionId);
            g_sessionId = -1;
            TestChangeDebugState(TRANS_STATE_REMOVE_SESSION_SERVER);
            break;
        case TRANS_STATE_REMOVE_SESSION_SERVER:
            int32_t ret = RemoveSessionServer(g_testModuleName, g_testSessionName);
            if (ret != SOFTBUS_OK) {
                LOG2_ERR("RemoveSessionServer failed, ret = %d", ret);
                return;
            }
            LOG2_INFO("RemoveSessionServer success, ret = %d", ret);
            TestChangeDebugState(LNN_STATE_LEAVELNN);
            break;
        case LNN_STATE_LEAVELNN:
            LeaveLNN(g_networkId, OnLeaveLNNDone);
            TestChangeDebugState(-1);
            break;
        default:
            LOG2_INFO("default: Invalid state");
            break;
    }
}

static int32_t OnSessionOpenRecvFile(int32_t sessionId, int32_t result)
{
    LOG2_INFO("############# recv session opened,sesison id[%d] result[%d]", sessionId, result);
    return SOFTBUS_OK;
}

static int32_t OnReceiveFileStarted(int32_t sessionId, const char *files, int32_t fileCnt)
{
    LOG2_INFO("File receive start sessionId = %d, first file = %s, fileCnt = %d\n", sessionId, files, fileCnt);
    return SOFTBUS_OK;
}

static void OnReceiveFileFinished(int32_t sessionId, const char *files, int32_t fileCnt)
{
    LOG2_INFO("File receive finished sessionId = %d, first file = %s, fileCnt = %d\n", sessionId, files, fileCnt);
}

static IFileReceiveListener g_fileRecvListener  = {
    .OnReceiveFileStarted = OnReceiveFileStarted,
    .OnReceiveFileFinished = OnReceiveFileFinished,
    .OnFileTransError = OnFileTransError,
};

static void TestSetFileRecvListener(void)
{
    int32_t ret = SetFileReceiveListener(g_testModuleName, g_testSessionNameE2, &g_fileRecvListener, "/data/");
    if (ret != SOFTBUS_OK) {
        LOG2_INFO("SetFileReceiveListener ret = %d\n", ret);
    } else {
        LOG2_INFO("SetFileReceiveListener ok\n");
    }
}

static void TestReceiveFile(int32_t state)
{
    switch (state) {
        case TRANS_STATE_CREATE_SESSION_SERVER: {
            g_sessionlistener.OnSessionOpened = OnSessionOpenRecvFile;
            int32_t ret = CreateSessionServer(g_testModuleName, g_testSessionNameE2, &g_sessionlistener);
            LOG2_INFO("CreateSessionServer ret: %d", ret);
            if (ret != SOFTBUS_SERVER_NAME_REPEATED && ret != SOFTBUS_OK) {
                LOG2_ERR("CreateSessionServer ret: %d", ret);
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

int32_t main(int32_t argc, char *argv[])
{
    if (argc == 1) {
        return -1;
    }
    int32_t testWay = 0;
    if (argc >= ARG_NUM) {
        testWay = atoi(argv[1]);
    }
    TestSessionListenerInit();

    if (RegNodeDeviceStateCb(g_testModuleName, &g_nodeStateCallback) != SOFTBUS_OK) {
        LOG2_ERR("RegNodeDeviceStateCb error!");
        return SOFTBUS_DISCOVER_COAP_GET_DEVICE_INFO_FAIL;
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
