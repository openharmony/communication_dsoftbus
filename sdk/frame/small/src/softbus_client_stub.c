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

#include "bus_center_client_stub.h"
#include "disc_client_stub.h"
#include "iproxy_client.h"
#include "liteipc_adapter.h"
#include "softbus_adapter_timer.h"
#include "softbus_client_context_manager.h"
#include "softbus_client_event_manager.h"
#include "softbus_client_frame_manager.h"
#include "softbus_client_stub_interface.h"
#include "softbus_errcode.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"
#include "softbus_server_proxy.h"
#include "trans_client_stub.h"

#define INVALID_CB_ID 0xFF

static int RegisterServerDeathCb(void);
static unsigned int g_deathCbId = INVALID_CB_ID;
static SvcIdentity g_svcIdentity = {0};

struct SoftBusIpcClientCmd {
    uint32_t code;
    void (*func)(IpcIo *io, const IpcContext *ctx, void *ipcMsg);
};

static struct SoftBusIpcClientCmd g_softBusIpcClientCmdTbl[] = {
    { CLIENT_DISCOVERY_SUCC, ClientOnDiscoverySuccess },
    { CLIENT_DISCOVERY_FAIL, ClientOnDiscoverFailed },
    { CLIENT_DISCOVERY_DEVICE_FOUND, ClientOnDeviceFound },
    { CLIENT_PUBLISH_SUCC, ClientOnPublishSuccess },
    { CLIENT_PUBLISH_FAIL, ClientOnPublishFail },
    { CLIENT_ON_JOIN_RESULT, ClientOnJoinLNNResult },
    { CLIENT_ON_LEAVE_RESULT, ClientOnLeaveLNNResult },
    { CLIENT_ON_NODE_ONLINE_STATE_CHANGED, ClientOnNodeOnlineStateChanged },
    { CLIENT_ON_NODE_BASIC_INFO_CHANGED, ClientOnNodeBasicInfoChanged },
    { CLIENT_ON_TIME_SYNC_RESULT, ClientOnTimeSyncResult },
    { CLIENT_ON_CHANNEL_OPENED, ClientOnChannelOpened },
    { CLIENT_ON_CHANNEL_OPENFAILED, ClientOnChannelOpenfailed },
    { CLIENT_ON_CHANNEL_CLOSED, ClientOnChannelClosed },
    { CLIENT_ON_CHANNEL_MSGRECEIVED, ClientOnChannelMsgreceived },
};

static int ClientIpcInterfaceMsgHandle(const IpcContext *ctx, void *ipcMsg, IpcIo *io, void *arg)
{
    uint32_t code = 0;
    (void)arg;

    if (ipcMsg == NULL || io == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_ERR;
    }

    GetCode(ipcMsg, &code);
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "receive ipc transact code(%u)", code);
    unsigned int num = sizeof(g_softBusIpcClientCmdTbl) / sizeof(struct SoftBusIpcClientCmd);
    for (unsigned int i = 0; i < num; i++) {
        if (code == g_softBusIpcClientCmdTbl[i].code) {
            g_softBusIpcClientCmdTbl[i].func(io, ctx, ipcMsg);
            return SOFTBUS_OK;
        }
    }
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "not support code(%u)", code);
    return SOFTBUS_ERR;
}

static int InnerRegisterService(void)
{
    char clientName[PKG_NAME_SIZE_MAX] = {0};
    if (GetSoftBusClientName(clientName, sizeof(clientName)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "get client name failed");
        return SOFTBUS_ERR;
    }

    struct CommonScvId svcId = {0};
    if (GetClientIdentity(&svcId.handle, &svcId.token, &svcId.cookie, &svcId.ipcCtx) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "get client identity failed");
        return SOFTBUS_ERR;
    }

    while (RegisterService(clientName, &svcId) != SOFTBUS_OK) {
        SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
        continue;
    }

    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "success");
    return SOFTBUS_OK;
}

static void UnregisterServerDeathCb(void)
{
    UnregisterDeathCallback(g_svcIdentity, g_deathCbId);
    g_deathCbId = INVALID_CB_ID;
    g_svcIdentity.handle = 0;
    g_svcIdentity.token = 0;
    g_svcIdentity.cookie = 0;
}

static void *DeathProcTask(void *arg)
{
    (void)arg;
    CLIENT_NotifyObserver(EVENT_SERVER_DEATH, NULL, 0);

    if (InnerRegisterService() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "register service failed");
        return NULL;
    }

    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "\n<< !!! SERVICE (%s) RECOVER !!! >>\n", SOFTBUS_SERVICE);
    CLIENT_NotifyObserver(EVENT_SERVER_RECOVERY, NULL, 0);
    UnregisterServerDeathCb();

    if (RegisterServerDeathCb() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "reg server death cb failed");
        return NULL;
    }

    return NULL;
}

static int StartDeathProcTask(void)
{
    int ret;
    pthread_t tid;
    pthread_attr_t attr;

    ret = pthread_attr_init(&attr);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "pthread_attr_init failed, ret[%d]", ret);
        return SOFTBUS_ERR;
    }

    ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "pthread set detached attr failed, ret[%d]", ret);
        ret = SOFTBUS_ERR;
        goto EXIT;
    }

    ret = pthread_attr_setschedpolicy(&attr, SCHED_RR);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "pthread set sched failed, ret[%d]", ret);
        ret = SOFTBUS_ERR;
        goto EXIT;
    }

    ret = pthread_create(&tid, &attr, DeathProcTask, NULL);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "create DeathProcTask failed, ret[%d]", ret);
        ret = SOFTBUS_ERR;
    }

    ret = SOFTBUS_OK;
EXIT:
    if (pthread_attr_destroy(&attr) != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "destroy pthread attr failed, ret[%d]", ret);
        ret = SOFTBUS_ERR;
    }

    return ret;
}

static int32_t DeathCallback(const IpcContext *ctx, void *ipcMsg, IpcIo *data, void *arg)
{
    (void)ctx;
    (void)ipcMsg;
    (void)data;
    (void)arg;

    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_WARN, "\n<< ATTENTION !!! >> SERVICE (%s) DEAD !!!\n", SOFTBUS_SERVICE);

    if (StartDeathProcTask() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "start death proc task failed");
        return SOFTBUS_ERR;
    } else {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "client start check softbus server...");
    }

    return SOFTBUS_OK;
}

static int RegisterServerDeathCb(void)
{
    g_svcIdentity = SAMGR_GetRemoteIdentity(SOFTBUS_SERVICE, NULL);
    g_deathCbId = INVALID_CB_ID;
    if (RegisterDeathCallback(NULL, g_svcIdentity, DeathCallback, NULL, &g_deathCbId) != EC_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "reg death callback failed");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int ClientStubInit(void)
{
    if (ServerProxyInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "server proxy init failed.");
        return SOFTBUS_ERR;
    }
    SvcIdentity clientIdentity = {0};
    int ret = RegisterIpcCallback(ClientIpcInterfaceMsgHandle, 0, IPC_WAIT_FOREVER, &clientIdentity, NULL);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "register ipc cb failed");
        return SOFTBUS_ERR;
    }
    ret = ClientContextInit();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "client context init failed.");
        return SOFTBUS_ERR;
    }
#ifdef __LINUX__
    SetClientIdentity(clientIdentity.handle, clientIdentity.token, clientIdentity.cookie, clientIdentity.ipcContext);
#else
    SetClientIdentity(clientIdentity.handle, clientIdentity.token, clientIdentity.cookie, NULL);
#endif

    if (InnerRegisterService() != SOFTBUS_OK) {
        ClientContextDeinit();
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "register service failed");
        return SOFTBUS_ERR;
    }

    if (RegisterServerDeathCb() != SOFTBUS_OK) {
        ClientContextDeinit();
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "reg server death cb failed");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}
