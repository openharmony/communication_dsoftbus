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

#include "softbus_server_frame.h"

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "lnn_bus_center_ipc.h"
#include "message_handler.h"
#include "softbus_conn_interface.h"
#include "softbus_disc_server.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "softbus_utils.h"
#include "trans_session_manager.h"
#include "trans_session_service.h"

static bool g_isInit = false;

int32_t __attribute__((weak)) ServerStubInit(void)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_WARN, "softbus server stub init(weak function).");
    return SOFTBUS_OK;
}

static void ServerModuleDeinit(void)
{
    DiscServerDeinit();
    ConnServerDeinit();
    TransServerDeinit();
    BusCenterServerDeinit();
    AuthDeinit();
    SoftBusTimerDeInit();
    LooperDeinit();
}

bool GetServerIsInit(void)
{
    return g_isInit;
}

void InitSoftBusServer(void)
{
    SoftbusConfigInit();
    
    if (ServerStubInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "server stub init failed.");
        return;
    }
    if (SoftBusTimerInit() == SOFTBUS_ERR) {
        return;
    }
    if (LooperInit() == -1) {
        return;
    }

    if (ConnServerInit() == SOFTBUS_ERR) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "softbus conn server init failed.");
        goto ERR_EXIT;
    }

    if (TransServerInit() == SOFTBUS_ERR) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "softbus trans server init failed.");
        goto ERR_EXIT;
    }

    if (AuthInit() == SOFTBUS_ERR) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "softbus auth init failed.");
        goto ERR_EXIT;
    }

    if (DiscServerInit() == SOFTBUS_ERR) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "softbus disc server init failed.");
        goto ERR_EXIT;
    }

    if (BusCenterServerInit() == SOFTBUS_ERR) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "softbus buscenter server init failed.");
        goto ERR_EXIT;
    }

    g_isInit = true;
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "softbus framework init success.");
    return;

ERR_EXIT:
    ServerModuleDeinit();
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "softbus framework init failed.");
    return;
}

void ClientDeathCallback(const char *pkgName)
{
    DiscServerDeathCallback(pkgName);
    TransServerDeathCallback(pkgName);
    BusCenterServerDeathCallback(pkgName);
}

#if 1

#include <pthread.h>
#include "ohos_init.h"
extern void testThread(void(*test)(void *arg));
extern void hi_wifi_set_macaddr(char *mac, int len);

char g_networkId[99] = {0};
ISessionListener *g_sessionListener = NULL;
int32_t g_sessionId = -1;
SessionAttribute * g_sessionAttr = NULL;

#define PKGDEMO "com.huawei.ctrlbustest"
#define SESSIONDEMO "com.huawei.ctrlbustest.JtCreateSessionServerLimit"

typedef enum {
    TRANS_STATE_NONE,
    TRANS_STATE_INIT,
    TRANS_STATE_JOIN,
    TRANS_STATE_OPEN,
    TRANS_STATE_SENDBYTE,
    TRANS_STATE_SENDMSG,
    TRANS_STATE_CLOSE,
    TRANS_STATE_LEAVE_LNN,
    TRANS_STATE_DUMP_MEM,
} TransState;

int g_state = TRANS_STATE_NONE;

int TestOnSessionOpened(int sessionId, int result)
{
    g_sessionId = sessionId;
    printf("TestOnSessionOpen %d, %d \r\n", g_sessionId, result);
    return 0;
}

int TestOnSessionClosed(int sessionId, int result)
{
    printf("TestOnSessionClosed");

    if (sessionId == g_sessionId) {
        g_sessionId = -1;
    }
    return 0;
}

void TestOnBytesReceived(int sessionId, const void *data, unsigned int dataLen)
{
    printf("BytesReceived : data : %s, len %d \r\n", data, dataLen);
}

void TestOnMessageReceived(int sessionId, const void *data, unsigned int dataLen)
{
    printf("MessageReceived : data : %s, len %d \r\n", data, dataLen);
}

int32_t TestSessionListenerInit(void)
{
    if (g_sessionListener != NULL) {
        return SOFTBUS_OK;
    }

    g_sessionListener = (ISessionListener *)malloc(sizeof(ISessionListener));
    (void)memset(g_sessionListener, 0, sizeof(ISessionListener));
    g_sessionListener->OnSessionOpened = TestOnSessionOpened;
    g_sessionListener->OnSessionClosed = TestOnSessionClosed;
    g_sessionListener->OnBytesReceived = TestOnBytesReceived;
    g_sessionListener->OnMessageReceived = TestOnMessageReceived;

    g_sessionAttr = (SessionAttribute *)malloc(sizeof(SessionAttribute));
    g_sessionAttr->dataType = TYPE_MESSAGE;
    int ret = CreateSessionServer(PKGDEMO, SESSIONDEMO, g_sessionListener);
    printf ("CreateSessionServer ret %d", ret);
    if (ret != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_OK;
}

void onNodeOnline(NodeBasicInfo *info)
{
    printf ("\r\n onNodeOnline \r\n");
    strcpy(g_networkId, info->networkId);
    g_state = TRANS_STATE_OPEN;
}

void onNodeOffline(NodeBasicInfo *info)
{
    printf ("\r\n onNodeOffline \r\n");
}

static INodeStateCb g_nodeStateCallBack = {
    .events = EVENT_NODE_STATE_ONLINE | EVENT_NODE_STATE_OFFLINE,
    .onNodeOnline = onNodeOnline,
    .onNodeOffline = onNodeOffline,
};

void regDevStatus(void)
{
    int ret = RegNodeDeviceStateCb(PKGDEMO, &g_nodeStateCallBack);
    printf("zrc regDevStatus %d", ret);
}

void closeloopsession(int *sid, int loopcnt)
{
    int i;
    printf("closeloopsession %d \r\n", loopcnt);

    for (i = 0; i < loopcnt; i++) {
        printf("closeloopsession id %d\r\n", sid[i]);
        CloseSession(sid[i]);
        sleep(1);
    }
}

void loopopensessionTask()
{
    char groupid[128] = {0};
    int loopcnt = 1;
    static int sendcnt = 1;
    char data[20] = "1024zrc byte data";
    int i;
    int totalloop = loopcnt;
    int *sid = calloc(1, sizeof(int) * loopcnt);
    sleep(10);

    while (loopcnt != 0) {
        sprintf(groupid, "groupid:%d", rand());

        sid[loopcnt - 1] = OpenSession(SESSIONDEMO, SESSIONDEMO, g_networkId, groupid, g_sessionAttr);

        sleep(3);

        for (i = 0; i < sendcnt; i++) {
            SendMessage(g_sessionId, data, sizeof(data));
            sleep(2);

            SendBytes(g_sessionId, data, sizeof(data));
            sleep(3);
        }
        sleep(3);
        loopcnt --;
    }
    sleep(5);
    closeloopsession(sid, totalloop);
    free(sid);
    return;
}

static void OnleaveLNNDone(const char *networkID, int32_t retCode)
{
    printf("OnleaveLNNDone ret:%d\r\n", retCode);
    g_state = TRANS_STATE_DUMP_MEM;
}

void stateproc(int state)
{
    int ret;
    char data[] = "zrc L0 session send msg data";
    char databyte[] = "zrc L0 session send byte data";
    char groupid[128] = {0};
    static int cnt = 0;
    switch(state) {
        case TRANS_STATE_INIT: {
            sleep(1);
            break;
        }
        case TRANS_STATE_JOIN: {
            break;
        }
        case TRANS_STATE_OPEN: {
            loopopensessionTask();
            break;
        }
        case TRANS_STATE_SENDBYTE: {
            ret = SendBytes(g_sessionId, databyte, sizeof(databyte));
            printf ("SendBytes ret %d \r\n", ret);
            if (ret != SOFTBUS_OK) {
                printf ("SendByte11 ret :%d\r\n", ret);
            }
            break;
        }
        case TRANS_STATE_SENDMSG: {
            ret = SendMessage(g_sessionId, data, sizeof(data));
            printf ("SendMessage ret %d \r\n", ret);
            if (ret != SOFTBUS_OK) {
                printf ("SendMessage111 ret :%d\r\n", ret);
            }
            break;
        }
        case TRANS_STATE_CLOSE : {
            CloseSession(g_sessionId);
            g_sessionId = -1;
            
            break;
        }
        case TRANS_STATE_LEAVE_LNN : {
            sleep(1);
            g_sessionId = -1;
            
            break;
        }
        case TRANS_STATE_DUMP_MEM : {
            sleep(5);
            break;
        }
        default : {
            sleep(5);
            break;
        }
    }
}

void SateProc()
{
    int tmpState;
    while(1) {
        if (g_state != TRANS_STATE_NONE) {
            tmpState = g_state;
            g_state = TRANS_STATE_NONE;
            stateproc(tmpState);
        }
        sleep(1);
    }
}
void test(void *arg)
{
    sleep(8);
    printf("test begin sleep end \r\n");

    InitSoftBusServer();
    sleep(3);
    printf("*************03**************\r\n");
    regDevStatus();
    TestSessionListenerInit();
    SateProc();
}
void testThread(void(*test)(void *arg))
{
    #define MAINLOOP_STACK_SIZE 5120
    pthread_t tid;
    pthread_attr_t threadAttr;

    pthread_attr_init(&threadAttr);
    pthread_attr_setstacksize(&threadAttr, MAINLOOP_STACK_SIZE);
    if (pthread_create(&tid, &threadAttr, test, 0) != 0) 
    {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "pthread_create test error");
        return;
    }
}

void testmain()
{
    char mac[5] = {0x8c, 0x22, 0x33, 0x44, 0x55, 0x33};
    hi_wifi_set_macaddr(mac, sizeof(mac));
    testThread(test);
}

//SYS_SERVICE_INIT_PRI(InitSoftBusServer, 4);
SYS_SERVICE_INIT_PRI(testmain, 4);
#endif