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

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "securec.h"
#include "session.h"
#include "softbus_bus_center.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#define TYPE_SEND_BYTE 15
#define TYPE_SEND_MESSAGE 16
#define SLEEP_TIME 15
#define TRANS_UINIT_SIZE 1024
#define TRANS_SIZE_NUM 2
#define TRANS_SIZE_NUM_DOUBLE 4
#define LOOP_COUNT 10
#define NETWORKIDSIZE 100

static int g_succTestCount = 0;
static int g_failTestCount = 0;

static char const *g_pkgName = "com.communication.demo";
static char g_networkId[NETWORKIDSIZE];
static int g_sessionId = 0;
static char *g_contcx = NULL;
static int g_testCount = 0;
char const *g_sessionName = "com.ctrlbustest.JtCreateSessionServerLimit";
char const *g_groupid = "TEST_GROUP_ID";
static bool g_state = true;
static SessionAttribute g_sessionAttr = {
    .dataType = TYPE_BYTES
};
#define TEST_ASSERT_TRUE(ret)  \
    if (ret) {                 \
        LOG_INFO("[test][succ]\n");    \
        g_succTestCount++;       \
    } else {                   \
        LOG_INFO("[test][error]\n");    \
        g_failTestCount++;       \
    }

void Wait();
void Start();

static void OnJoinLNNDone(const ConnectionAddr *addr, const char *networkId, int retCode)
{
    if (addr == NULL) {
        LOG_INFO("[test]OnJoinLNNDone error\n");
        return;
    }
    if (retCode == 0) {
        LOG_INFO("[test]OnJoinLNNDone enter networdid = %s, retCode = %d ip = %s port = %d\r\n",
            networkId, retCode, addr->info.ip.ip, addr->info.ip.port);
    } else {
        LOG_INFO("[test]OnJoinLNNDone failed! networdid = %s, retCode = %d\r\n", networkId, retCode);
    }
    Start();
}

static void OnLeaveLNNDone(const char *networkId, int retCode)
{
    if (retCode == 0) {
        LOG_INFO("[test]OnLeaveLNNDone enter networdid = %s, retCode = %d", networkId, retCode);
    } else {
        LOG_INFO("[test]OnLeaveLNNDone failed! networdid = %s, retCode = %d", networkId, retCode);
    }
}

static void OnNodeOnline(const NodeBasicInfo *info)
{
    return;
}

static void OnNodeOffline(const NodeBasicInfo *info)
{
    return;
}

static INodeStateCb g_nodeStateCallback = {
    .events = EVENT_NODE_STATE_ONLINE | EVENT_NODE_STATE_OFFLINE,
    .onNodeOnline = OnNodeOnline,
    .onNodeOffline = OnNodeOffline,
};

static int JoinNetwork()
{
    Wait();
    LOG_INFO("[test]enter JoinNetwork");
    if (RegNodeDeviceStateCb(g_pkgName, &g_nodeStateCallback) != 0) {
        LOG_INFO("[test]RegNodeDeviceStateCb error!");
        return -1;
    }
    ConnectionAddr addr = {
        .type = CONNECTION_ADDR_ETH,
    };
    if (JoinLNN(g_pkgName, &addr, OnJoinLNNDone) != 0) {
        LOG_INFO("[test]JoinLNN error!");
        return -1;
    }
    g_testCount = 0;
    sleep(SLEEP_TIME);
    return 0;
}

static int LeaveNetWork()
{
    Wait();
    NodeBasicInfo info1;
    int ret = GetLocalNodeDeviceInfo(g_pkgName, &info1);
    if (ret != 0) {
        LOG_INFO("[test]GetLocalNodeDeviceInfo error!");
        return -1;
    }
    LOG_INFO("[test]GetLocalNodeDeviceInfo networkId = %s, typeId = %d, name = %s", info1.networkId, info1.deviceTypeId,
        info1.deviceName);

    if (UnregNodeDeviceStateCb(&g_nodeStateCallback) != 0) {
        LOG_INFO("[test]UnregNodeDeviceStateCb error!");
        return -1;
    }

    if (LeaveLNN(info1.networkId, OnLeaveLNNDone) != 0) {
        LOG_INFO("[test]LeaveLNN error!");
        return -1;
    }
    return 0;
}

static int OnSessionOpened(int sessionId, int result)
{
    LOG_INFO("\n\n\n[test]session opened,sesison id = %d\r\n", sessionId);
    g_sessionId = sessionId;
    TEST_ASSERT_TRUE(g_testCount == 0);
    g_testCount++;
    Start();
    return 0;
}

static void OnSessionClosed(int sessionId)
{
    LOG_INFO("[test]session closed, session id = %d\r\n", sessionId);
}

static void OnBytesReceived(int sessionId, const void *data, unsigned int len)
{
    LOG_INFO("[test]session bytes received, session id = %d data = %s\r\n", sessionId, data);
    TEST_ASSERT_TRUE(g_testCount == 2);
    g_testCount++;
    Start();
}

static void OnMessageReceived(int sessionId, const void *data, unsigned int len)
{
    LOG_INFO("[test]session msg received, session id = %d\r\n", sessionId);
    Start();
}

static ISessionListener g_sessionlistener = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnBytesReceived = OnBytesReceived,
    .OnMessageReceived = OnMessageReceived
};

static int CreateSsAndOpenSession()
{
    int ret;
    Wait();
    g_testCount = 0;
    LOG_INFO("enter CreateSessionServer");
    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    TEST_ASSERT_TRUE(ret == 0);
    if (ret != 0) {
        return ret;
    }
    LOG_INFO("OpenSession g_networkId = %s", g_networkId);
    ret = OpenSession(g_sessionName, g_sessionName, g_networkId, g_groupid, &g_sessionAttr);
    TEST_ASSERT_TRUE(ret == 0);
    if (ret != 0) {
        ret = RemoveSessionServer(g_pkgName, g_sessionName);
        TEST_ASSERT_TRUE(ret == 0);
        Start();
    }
    return ret;
}

static int RemoveSession()
{
    int ret;
    Wait();
    TEST_ASSERT_TRUE(g_testCount == 3);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    TEST_ASSERT_TRUE(ret == 0);
    Start();
    return ret;
}

static int DataSend(int size, int type)
{
    int ret;
    g_contcx = (char *)calloc(1, size * sizeof(char));
    if (memset_s(g_contcx, size, "h", size) != EOK) {
        return SOFTBUS_ERR;
    }
    Wait();
    TEST_ASSERT_TRUE(g_testCount == 1);
    g_testCount++;
    if (type == TYPE_SEND_BYTE) {
        ret = SendBytes(g_sessionId, g_contcx, size);
        TEST_ASSERT_TRUE(ret == 0);
    }
    if (type == TYPE_SEND_MESSAGE) {
        ret = SendMessage(g_sessionId, g_contcx, size);
        TEST_ASSERT_TRUE(ret == 0);
    }
    free(g_contcx);
    return ret;
}

void Wait()
{
    LOG_INFO("[test]Wait enter");
SLEEP:
    sleep(1);
    if (g_state == false) {
        goto SLEEP;
    }
    LOG_INFO("[test]Wait end");
    g_state = false;
}

void Start()
{
    g_state = true;
}

void SetUpTestCase()
{
    LOG_INFO("[Test]SetUp begin\n");
    int ret;
    ret = JoinNetwork();
    TEST_ASSERT_TRUE(ret == 0);
    LOG_INFO("[Test]SetUp end\n");
}

void TearDownTestCase()
{
    LOG_INFO("[Test]TearDown begin\n");
    int ret;
    ret = LeaveNetWork();
    TEST_ASSERT_TRUE(ret == 0);
    LOG_INFO("[Test]TearDown end\n");
}

/**
 * @tc.number : SUB_Softbus_Trans_SendByte_Func_0100
 * @tc.name   : SendByte_数据包大小1B，发送-接收成功
 * @tc.desc   : 测试SendByte发送数据规格
 * @tc.type   : FUNC
 * @tc.size   : MediumTest
 */
void TransFuncTest001(void)
{
    int ret;
    int size = 1;

    ret = CreateSsAndOpenSession();
    TEST_ASSERT_TRUE(ret == 0);
    ret = DataSend(size, TYPE_SEND_BYTE);
    TEST_ASSERT_TRUE(ret == 0);
    ret = RemoveSession();
    TEST_ASSERT_TRUE(ret == 0);
}

/**
 * @tc.number : SUB_Softbus_Trans_SendByte_Func_0200
 * @tc.name   : SendByte_数据包大小2K，发送-接收成功
 * @tc.desc   : 测试SendByte发送数据规格
 * @tc.type   : FUNC
 * @tc.size   : MediumTest
 */
void TransFuncTest002(void)
{
    int ret;
    int size = TRANS_SIZE_NUM * TRANS_UINIT_SIZE;

    ret = CreateSsAndOpenSession();
    TEST_ASSERT_TRUE(ret == 0);
    ret = DataSend(size, TYPE_SEND_BYTE);
    TEST_ASSERT_TRUE(ret == 0);
    ret = RemoveSession();
    TEST_ASSERT_TRUE(ret == 0);
}

/**
 * @tc.number : SUB_Softbus_Trans_SendByte_Func_0300
 * @tc.name   : SendByte_数据包大小Max，发送-接收成功
 * @tc.desc   : 测试SendByte发送数据规格
 * @tc.type   : FUNC
 * @tc.size   : MediumTest
 */
void TransFuncTest003(void)
{
    int ret;
    int size = TRANS_SIZE_NUM_DOUBLE * TRANS_UINIT_SIZE;

    ret = CreateSsAndOpenSession();
    TEST_ASSERT_TRUE(ret == 0);
    ret = DataSend(size, TYPE_SEND_BYTE);
    TEST_ASSERT_TRUE(ret == 0);
    ret = RemoveSession();
    TEST_ASSERT_TRUE(ret == 0);
}

/**
 * @tc.number : SUB_Softbus_Trans_SendMessage_Func_0100
 * @tc.name   : SendMessage_数据包大小1B，发送-接收成功
 * @tc.desc   : 测试SendMessage发送数据规格
 * @tc.type   : FUNC
 * @tc.size   : MediumTest
 */
void TransFuncTest004(void)
{
    int ret;
    int size = 1;

    ret = CreateSsAndOpenSession();
    TEST_ASSERT_TRUE(ret == 0);
    ret = DataSend(size, TYPE_SEND_MESSAGE);
    TEST_ASSERT_TRUE(ret == 0);
    ret = RemoveSession();
    TEST_ASSERT_TRUE(ret == 0);
}

/**
 * @tc.number : SUB_Softbus_Trans_SendMessage_Func_0200
 * @tc.name   : SendMessage_数据包大小1000B，发送-接收成功
 * @tc.desc   : 测试SendMessage发送数据规格
 * @tc.type   : FUNC
 * @tc.size   : MediumTest
 */
void TransFuncTest005(void)
{
    int ret;
    int size = TRANS_UINIT_SIZE;

    ret = CreateSsAndOpenSession();
    TEST_ASSERT_TRUE(ret == 0);
    ret = DataSend(size, TYPE_SEND_MESSAGE);
    TEST_ASSERT_TRUE(ret == 0);
    ret = RemoveSession();
    TEST_ASSERT_TRUE(ret == 0);
}

/**
 * @tc.number : SUB_Softbus_Trans_Session_Func_0100
 * @tc.name   : 1个Client_创建SessionServer_Max个，成功
 * @tc.desc   : 测试会话管理
 * @tc.type   : FUNC
 * @tc.size   : MediumTest
 */
void TransFuncTest006(void)
{
    int ret;
    char sessionNames[8][65] = {"1", "2", "3", "4", "5", "6", "7", "8"};
    for (int i = 0; i < sizeof(sessionNames) / sizeof(sessionNames[]); i++) {
        ret = CreateSessionServer(g_pkgName, sessionNames[i], &g_sessionlistener);
        TEST_ASSERT_TRUE(ret == 0);
    }
    for (int i = 0; i < sizeof(sessionNames) / sizeof(sessionNames[]; i++) {
        ret = RemoveSessionServer(g_pkgName, sessionNames[i]);
        TEST_ASSERT_TRUE(ret == 0);
    }
}

int main(void)
{
    if (scanf_s("%s", g_networkId, NETWORKIDSIZE) < 0) {
        return SOFTBUS_ERR;
    }
    LOG_INFO("g_networkId = %s", g_networkId);
    for (int i = 0; i < LOOP_COUNT; i++) {
        TransFuncTest001();
    }

    LOG_INFO("[test]------------------------------------------------------------");
    LOG_INFO("[test]test number: %d, succ = %d. fail = %d",
        g_failTestCount + g_succTestCount, g_succTestCount, g_failTestCount);
    LOG_INFO("[test]------------------------------------------------------------");
}
