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

#include <securec.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "inner_session.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

#define TICK_TIME 1
#define CREATE_SESSION_CASE 0
#define OPEN_SESSION_CASE 1
#define SEND_DATA_TEST_CASE 2
#define WAIT_OPEN_SESSION_CASE 3

#define TEST_CASE_NUM 10
#define MAXT_WAIT_COUNT 6
#define WIFI_CONFIG_INTERVAL 10
#define TEST_COUNT_INTREVAL 5
#define WAIT_SERVER_READY 5
#define MAX_TEST_COUNT 8
#define NSTACKX_MAX_IP_STRING_LEN 20
#define DISC_TEST_PKG_NAME "com.plrdtest"
static const char *g_testModuleName = DISC_TEST_PKG_NAME;
static const char *g_testSessionName   = "com.plrdtest.dsoftbus";
static ISessionListener g_sessionlistener;
static SessionAttribute g_sessionAttr;
static bool g_successFlag = false;

#define CONN_ADDR_INFO_COUNT 5
static int32_t g_sessionId = -1;
ConnectionAddr g_addrInfo[CONN_ADDR_INFO_COUNT];

static int32_t g_connectCnt = 0;

static int32_t OnSessionOpened(int32_t sessionId, int32_t result)
{
    printf("############# session opened,sesison id[%d] result[%d]\n", sessionId, result);
    if (result == SOFTBUS_OK) {
        if (g_sessionId == -1 || sessionId == g_sessionId) {
            if (g_sessionId == -1) {
                g_connectCnt++;
                g_sessionId = sessionId;
            }
            g_successFlag = true;
        }
    }

    return result;
}

static void OnSessionClosed(int32_t sessionId)
{
    printf("############# session closed, session id = %d\n", sessionId);
    g_sessionId = -1;
    g_successFlag = false;
}

static void OnBytesReceived(int32_t sessionId, const void *data, uint32_t len)
{
    if (g_sessionId == -1 || sessionId == g_sessionId) {
        printf("client bytes received, data[%s], dataLen[%u]\n", (char *)data, len);
    } else {
        printf("server bytes received, sessionid[%d], data[%s], dataLen[%u]\n", sessionId, (char *)data, len);
    }
}

static void OnMessageReceived(int32_t sessionId, const void *data, uint32_t len)
{
    if (g_sessionId == -1 || sessionId == g_sessionId) {
        printf("client msg received, data[%s], dataLen[%u]\n", (char *)data, len);
    } else {
        printf("server msg received, sessionid[%d], data[%s], dataLen[%u]\n", sessionId, (char *)data, len);
    }
}

static void TestSessionListenerInit(void)
{
    g_sessionlistener.OnSessionOpened = OnSessionOpened;
    g_sessionlistener.OnSessionClosed = OnSessionClosed;
    g_sessionlistener.OnBytesReceived = OnBytesReceived;
    g_sessionlistener.OnMessageReceived = OnMessageReceived;
}

static const char *g_testData = "{\n    \"data\":\"open auth session test!!!\"\n}";

static int32_t TestSendBytesData(const char *data, int32_t len)
{
    printf("SendBytes start\n");
    int32_t ret = SendBytes(g_sessionId, data, len);
    if (ret != SOFTBUS_OK) {
        printf("SendBytes failed ret[%d] len[%u]\n", ret, len);
    }
    printf("SendBytes end\n");
    return ret;
}

static int32_t TestSendMessageData(const char *data, int32_t len)
{
    printf("SendMessage start\n");
    int32_t ret = SendMessage(g_sessionId, data, len);
    if (ret != SOFTBUS_OK) {
        printf("SendMessage failed ret[%d] len[%u]\n", ret, len);
    }
    printf("SendMessage end\n");
    return ret;
}

static int32_t TestCreateSessionServer(int32_t testWay)
{
    int32_t state = -1;
    int32_t ret = CreateSessionServer(g_testModuleName, g_testSessionName, &g_sessionlistener);
    printf("CreateSessionServer ret: %d \n", ret);
    if (ret != SOFTBUS_SERVER_NAME_REPEATED && ret != SOFTBUS_OK) {
        printf("CreateSessionServer ret: %d \n", ret);
    } else if (testWay == 1) {
        state = OPEN_SESSION_CASE;
    } else if (testWay == 0) {
        state = WAIT_OPEN_SESSION_CASE;
    }
    return state;
}

static void TestCloseSession(void)
{
    printf("TestCloseSession exit\n");
    if (g_sessionId > 0) {
        CloseSession(g_sessionId);
        g_sessionId = -1;
    }
}

static int32_t TestOpenAuthSession(void)
{
    printf("OpenAuthSession start\n");
    int32_t state = -1;
    g_addrInfo[0].type = CONNECTION_ADDR_BR;
    printf("input macaddr: \n");
    if (scanf_s("%s", g_addrInfo[0].info.br.brMac, BT_MAC_LEN) < 0) {
        printf("input error!\n");
        return OPEN_SESSION_CASE;
    }
    printf("brMac: %s\n", g_addrInfo[0].info.br.brMac);
    g_sessionId = OpenAuthSession(g_testSessionName, &(g_addrInfo[0]), 1, NULL);
    if (g_sessionId < 0) {
        printf("OpenAuthSession ret[%d]", g_sessionId);
    } else {
        state = SEND_DATA_TEST_CASE;
    }
    printf("OpenAuthSession end\n");
    return state;
}

#define SEND_DATA_SIZE_1K 1024
#define SEND_DATA_SIZE_4K (4 * 1024)
#define SEND_DATA_SIZE_40K (40 * 1000 - 8)
#define SEND_DATA_SIZE_64K (64 * 1024)
static int32_t GetSize(char cSize)
{
    int32_t size = SEND_DATA_SIZE_64K + 1;
    if (cSize == '0') {
        size = SEND_DATA_SIZE_1K;
    } else if (cSize == '1') {
        size = SEND_DATA_SIZE_4K;
    } else if (cSize == '2') {
        size = SEND_DATA_SIZE_40K;
    } else if (cSize == '3') {
        size = SEND_DATA_SIZE_40K + 1;
    } else if (cSize == '4') {
        size = SEND_DATA_SIZE_64K;
    }
    return size;
}
static int32_t TestAuthSessionSendData(const char *testData, int32_t count, char cSize)
{
    int32_t waitCnt = 0;
    while (!g_successFlag) {
        printf("wait OpenAuthSession success Cnt: %d *******\n", waitCnt);
        waitCnt++;
        if (waitCnt > count) {
            printf("wait OpenAuthSession success timeout!\n");
            return SOFTBUS_TIMOUT;
        }
        sleep(TICK_TIME);
    }
    int32_t size = GetSize(cSize);
    int32_t sendCnt = 0;
    int32_t ret;
    while (sendCnt < count) {
        printf("******* sendCnt[%d] *******\n", sendCnt);
        ret = TestSendBytesData(testData, size);
        if (size <= SEND_DATA_SIZE_64K) {
            if (ret != SOFTBUS_CONNECTION_ERR_SENDQUEUE_FULL && ret != SOFTBUS_OK) {
                printf("******* TestSendBytesData %d failed *******\n", size);
                return ret;
            }
        } else {
            if (ret == SOFTBUS_OK) {
                printf("******* TestSendBytesData %d failed *******\n", size);
                return SOFTBUS_AUTH_SEND_FAIL;
            }
        }
        sleep(TICK_TIME);
        ret = TestSendMessageData(testData, size);
        if (size <= SEND_DATA_SIZE_4K) {
            if (ret != SOFTBUS_CONNECTION_ERR_SENDQUEUE_FULL && ret != SOFTBUS_OK) {
                printf("******* TestSendMessageData %d failed *******\n", size);
                return ret;
            }
        } else {
            if (ret == SOFTBUS_OK) {
                printf("******* TestSendMessageData %d failed *******\n", size);
                return SOFTBUS_AUTH_SEND_FAIL;
            }
        }
        sendCnt++;
    }
    return SOFTBUS_OK;
}

static void DiscoveryTestEntry(int32_t testWay, int32_t count)
{
    TestSessionListenerInit();
    g_sessionAttr.dataType = TYPE_BYTES;
    int32_t stat = 0;
    char *testData = (char *)SoftBusCalloc(SEND_DATA_SIZE_64K + 1);
    if (testData == NULL) {
        printf("DiscoveryTestEntry malloc failed!\n");
        return;
    }
    if (memcpy_s(testData, SEND_DATA_SIZE_64K + 1, g_testData, strlen(g_testData)) != EOK) {
        printf("memcpy_s g_testData failed!\n");
        SoftBusFree(testData);
        return;
    }
    int32_t ret = SOFTBUS_OK;
    while (true) {
        if (stat == CREATE_SESSION_CASE) {
            stat = TestCreateSessionServer(testWay);
        } else if (stat == OPEN_SESSION_CASE) {
            stat = TestOpenAuthSession();
        } else if (stat == SEND_DATA_TEST_CASE) {
            getchar();
            char cSize;
            printf("data size(0:1K, 1:4K, 2:40000, 3:40001, 4:64K, 5:>64K, q:exit): \n");
            if (scanf_s("%c", &cSize, 1) < 0) {
                printf("input error!\n");
                continue;
            }
            if (cSize == 'q') {
                stat = -1;
                continue;
            }
            ret = TestAuthSessionSendData(testData, count, cSize);
            if (ret != SOFTBUS_OK) {
                stat = -1;
            }
        } else if (stat == WAIT_OPEN_SESSION_CASE && g_connectCnt >= count) {
            stat = -1;
        } else if (stat == -1) {
            TestCloseSession();
            break;
        }
        sleep(TICK_TIME);
    }
    SoftBusFree(testData);
    printf("Test Auth Channel %s!\n", ret == SOFTBUS_OK ? "OK" : "failed");
}

int32_t main(int32_t argc, char *argv[])
{
#define ARGC_NUM 2
    if (argc <= ARGC_NUM) {
        printf("error argc <= 2\n");
        return -1;
    }
    int32_t testWay = atoi(argv[1]);
    int32_t count = atoi(argv[ARGC_NUM]);
    DiscoveryTestEntry(testWay, count);
}
