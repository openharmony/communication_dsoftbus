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
#include "softbus_error_code.h"

#define TYPE_SEND_BYTE 15
#define TYPE_SEND_MESSAGE 16
#define SLEEP_TIME 15
#define TRANS_UINIT_SIZE 1024
#define TRANS_SIZE_NUM 2
#define TRANS_SIZE_NUM_DOUBLE 4
#define LOOP_COUNT 10
#define NETWORKIDSIZE 100

static int32_t g_succTestCount = 0;
static int32_t g_failTestCount = 0;

static char const *g_pkgName = "com.communication.demo";
static char g_networkId[NETWORKIDSIZE];
static int32_t g_sessionId = 0;
static char *g_contcx = NULL;
static int32_t g_testCount = 0;
char const *g_sessionName = "com.ctrlbustest.JtCreateSessionServerLimit";
char const *g_groupid = "TEST_GROUP_ID";
static bool g_state = true;
static SessionAttribute g_sessionAttr = {
    .dataType = TYPE_BYTES
};
#define TEST_ASSERT_TRUE(ret)  \
    if (ret) {                 \
        TRANS_LOGI(TRANS_TEST, "[test][succ]");    \
        g_succTestCount++;       \
    } else {                   \
        TRANS_LOGI(TRANS_TEST, "[test][error]");    \
        g_failTestCount++;       \
    }

void Wait();
void Start();

static void OnJoinLNNDone(const ConnectionAddr *addr, const char *networkId, int32_t retCode)
{
    if (addr == NULL) {
        TRANS_LOGI(TRANS_TEST, "[test]OnJoinLNNDone error");
        return;
    }
    if (retCode == 0) {
        TRANS_LOGI(TRANS_TEST,
            "[test]OnJoinLNNDone enter networdId=%{public}s, retCode=%{public}d, ip=%{public}s, port=%{public}d",
            networkId, retCode, addr->info.ip.ip, addr->info.ip.port);
    } else {
        TRANS_LOGI(TRANS_TEST,
            "[test]OnJoinLNNDone failed! networdId=%{public}s, retCode=%{public}d", networkId, retCode);
    }
    Start();
}

static void OnLeaveLNNDone(const char *networkId, int32_t retCode)
{
    if (retCode == 0) {
        TRANS_LOGI(TRANS_TEST,
            "[test]OnLeaveLNNDone enter networdId=%{public}s, retCode=%{public}d", networkId, retCode);
    } else {
        TRANS_LOGI(TRANS_TEST,
            "[test]OnLeaveLNNDone failed! networdId=%{public}s, retCode=%{public}d", networkId, retCode);
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

static int32_t JoinNetwork()
{
    Wait();
    TRANS_LOGI(TRANS_TEST, "[test]enter JoinNetwork");
    if (RegNodeDeviceStateCb(g_pkgName, &g_nodeStateCallback) != 0) {
        TRANS_LOGI(TRANS_TEST, "[test]RegNodeDeviceStateCb error!");
        return -1;
    }
    ConnectionAddr addr = {
        .type = CONNECTION_ADDR_ETH,
    };
    if (JoinLNN(g_pkgName, &addr, OnJoinLNNDone) != 0) {
        TRANS_LOGI(TRANS_TEST, "[test]JoinLNN error!");
        return -1;
    }
    g_testCount = 0;
    sleep(SLEEP_TIME);
    return 0;
}

static int32_t LeaveNetWork()
{
    Wait();
    NodeBasicInfo info1;
    int32_t ret = GetLocalNodeDeviceInfo(g_pkgName, &info1);
    if (ret != 0) {
        TRANS_LOGI(TRANS_TEST, "[test]GetLocalNodeDeviceInfo error!");
        return -1;
    }
    TRANS_LOGI(TRANS_TEST, "[test]GetLocalNodeDeviceInfo networkId=%{public}s, typeId=%{public}d, name=%{public}s",
        info1.networkId, info1.deviceTypeId, info1.deviceName);

    if (UnregNodeDeviceStateCb(&g_nodeStateCallback) != 0) {
        TRANS_LOGI(TRANS_TEST, "[test]UnregNodeDeviceStateCb error!");
        return -1;
    }

    if (LeaveLNN(info1.networkId, OnLeaveLNNDone) != 0) {
        TRANS_LOGI(TRANS_TEST, "[test]LeaveLNN error!");
        return -1;
    }
    return 0;
}

static int32_t OnSessionOpened(int32_t sessionId, int32_t result)
{
    TRANS_LOGI(TRANS_TEST, "[test]session opened, sesisonId=%{public}d", sessionId);
    g_sessionId = sessionId;
    TEST_ASSERT_TRUE(g_testCount == 0);
    g_testCount++;
    Start();
    return 0;
}

static void OnSessionClosed(int32_t sessionId)
{
    TRANS_LOGI(TRANS_TEST, "[test]session closed, sessionId=%{public}d", sessionId);
}

static void OnBytesReceived(int32_t sessionId, const void *data, unsigned int len)
{
    TRANS_LOGI(TRANS_TEST, "[test]session bytes received, sessionId=%{public}d, data=%{public}s", sessionId, data);
    TEST_ASSERT_TRUE(g_testCount == 2);
    g_testCount++;
    Start();
}

static void OnMessageReceived(int32_t sessionId, const void *data, unsigned int len)
{
    TRANS_LOGI(TRANS_TEST, "[test]session msg received, sessionId=%{public}d", sessionId);
    Start();
}

static ISessionListener g_sessionlistener = {
    .OnSessionOpened = OnSessionOpened,
    .OnSessionClosed = OnSessionClosed,
    .OnBytesReceived = OnBytesReceived,
    .OnMessageReceived = OnMessageReceived
};

static int32_t CreateSsAndOpenSession()
{
    int32_t ret;
    Wait();
    g_testCount = 0;
    TRANS_LOGI(TRANS_TEST, "enter CreateSessionServer");
    ret = CreateSessionServer(g_pkgName, g_sessionName, &g_sessionlistener);
    TEST_ASSERT_TRUE(ret == 0);
    if (ret != 0) {
        return ret;
    }
    TRANS_LOGI(TRANS_TEST, "OpenSession g_networkId=%{public}s", g_networkId);
    ret = OpenSession(g_sessionName, g_sessionName, g_networkId, g_groupid, &g_sessionAttr);
    TEST_ASSERT_TRUE(ret == 0);
    if (ret != 0) {
        ret = RemoveSessionServer(g_pkgName, g_sessionName);
        TEST_ASSERT_TRUE(ret == 0);
        Start();
    }
    return ret;
}

static int32_t RemoveSession()
{
    int32_t ret;
    Wait();
    TEST_ASSERT_TRUE(g_testCount == 3);
    ret = RemoveSessionServer(g_pkgName, g_sessionName);
    TEST_ASSERT_TRUE(ret == 0);
    Start();
    return ret;
}

static int32_t DataSend(int32_t size, int32_t type)
{
    int32_t ret;
    g_contcx = (char *)calloc(1, size * sizeof(char));
    if (g_contcx == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    if (memset_s(g_contcx, size, "h", size) != EOK) {
        free(g_contcx);
        return SOFTBUS_MEM_ERR;
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
    g_contcx = NULL;
    return ret;
}

void Wait()
{
    TRANS_LOGI(TRANS_TEST, "[test]Wait enter");
    do {
        sleep(1);
    } while (!g_state);
    TRANS_LOGI(TRANS_TEST, "[test]Wait end");
    g_state = false;
}

void Start()
{
    g_state = true;
}

void SetUpTestCase()
{
    TRANS_LOGI(TRANS_TEST, "[Test]SetUp begin");
    int32_t ret;
    ret = JoinNetwork();
    TEST_ASSERT_TRUE(ret == 0);
    TRANS_LOGI(TRANS_TEST, "[Test]SetUp end");
}

void TearDownTestCase()
{
    TRANS_LOGI(TRANS_TEST, "[Test]TearDown begin");
    int32_t ret;
    ret = LeaveNetWork();
    TEST_ASSERT_TRUE(ret == 0);
    TRANS_LOGI(TRANS_TEST, "[Test]TearDown end");
}

/**
 * @tc.name   : SUB_Softbus_Trans_SendByte_Func_0100
 * @tc.desc   : Test limiation of SendByte
 * @tc.type   : FUNC
 * @tc.size   : MediumTest
 */
void TransFuncTest001(void)
{
    int32_t ret;
    int32_t size = 1;

    ret = CreateSsAndOpenSession();
    TEST_ASSERT_TRUE(ret == 0);
    ret = DataSend(size, TYPE_SEND_BYTE);
    TEST_ASSERT_TRUE(ret == 0);
    ret = RemoveSession();
    TEST_ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name   : SUB_Softbus_Trans_SendByte_Func_0200
 * @tc.desc   : Test up limitation data size of SendByte
 * @tc.type   : FUNC
 * @tc.size   : MediumTest
 */
void TransFuncTest002(void)
{
    int32_t ret;
    int32_t size = TRANS_SIZE_NUM * TRANS_UINIT_SIZE;

    ret = CreateSsAndOpenSession();
    TEST_ASSERT_TRUE(ret == 0);
    ret = DataSend(size, TYPE_SEND_BYTE);
    TEST_ASSERT_TRUE(ret == 0);
    ret = RemoveSession();
    TEST_ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name   : SUB_Softbus_Trans_SendByte_Func_0300
 * @tc.desc   : Test up limitation data size of SendByte
 * @tc.type   : FUNC
 * @tc.size   : MediumTest
 */
void TransFuncTest003(void)
{
    int32_t ret;
    int32_t size = TRANS_SIZE_NUM_DOUBLE * TRANS_UINIT_SIZE;

    ret = CreateSsAndOpenSession();
    TEST_ASSERT_TRUE(ret == 0);
    ret = DataSend(size, TYPE_SEND_BYTE);
    TEST_ASSERT_TRUE(ret == 0);
    ret = RemoveSession();
    TEST_ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name   : SUB_Softbus_Trans_SendMessage_Func_0100
 * @tc.desc   : Test the minimum data size of SendMessage
 * @tc.type   : FUNC
 * @tc.size   : MediumTest
 */
void TransFuncTest004(void)
{
    int32_t ret;
    int32_t size = 1;

    ret = CreateSsAndOpenSession();
    TEST_ASSERT_TRUE(ret == 0);
    ret = DataSend(size, TYPE_SEND_MESSAGE);
    TEST_ASSERT_TRUE(ret == 0);
    ret = RemoveSession();
    TEST_ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name   : SUB_Softbus_Trans_SendMessage_Func_0200
 * @tc.desc   : Test send 1000 Byte data size via function SendMessage
 * @tc.type   : FUNC
 * @tc.size   : MediumTest
 */
void TransFuncTest005(void)
{
    int32_t ret;
    int32_t size = TRANS_UINIT_SIZE;

    ret = CreateSsAndOpenSession();
    TEST_ASSERT_TRUE(ret == 0);
    ret = DataSend(size, TYPE_SEND_MESSAGE);
    TEST_ASSERT_TRUE(ret == 0);
    ret = RemoveSession();
    TEST_ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name   : SUB_Softbus_Trans_Session_Func_0100
 * @tc.desc   : Test the maximum number of sessions that can be create by function CreateSessionServer
 * @tc.type   : FUNC
 * @tc.size   : MediumTest
 */
void TransFuncTest006(void)
{
    int32_t ret;
    char sessionNames[8][65] = {"1", "2", "3", "4", "5", "6", "7", "8"};
    for (int32_t i = 0; i < sizeof(sessionNames) / sizeof(sessionNames[0]); i++) {
        ret = CreateSessionServer(g_pkgName, sessionNames[i], &g_sessionlistener);
        TEST_ASSERT_TRUE(ret == 0);
    }
    for (int32_t i = 0; i < sizeof(sessionNames) / sizeof(sessionNames[0]); i++) {
        ret = RemoveSessionServer(g_pkgName, sessionNames[i]);
        TEST_ASSERT_TRUE(ret == 0);
    }
}

int32_t main(void)
{
    if (scanf_s("%s", g_networkId, NETWORKIDSIZE) < 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    TRANS_LOGI(TRANS_TEST, "g_networkId=%{public}s", g_networkId);
    for (int32_t i = 0; i < LOOP_COUNT; i++) {
        TransFuncTest001();
    }

    TRANS_LOGI(TRANS_TEST, "[test]------------------------------------------------------------");
    TRANS_LOGI(TRANS_TEST, "[test]test number=%{public}d, succ=%{public}d, fail=%{public}d",
        g_failTestCount + g_succTestCount, g_succTestCount, g_failTestCount);
    TRANS_LOGI(TRANS_TEST, "[test]------------------------------------------------------------");
}
