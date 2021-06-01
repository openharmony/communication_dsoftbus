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

#include "iproxy_client.h"
#include "samgr_lite.h"
#include "securec.h"
#include "softbus_client_event_manager.h"
#include "softbus_client_frame_manager.h"
#include "softbus_client_weak.h"
#include "softbus_errcode.h"
#include "softbus_interface.h"
#include "softbus_log.h"
#include "softbus_os_interface.h"

#define WAIT_SERVER_READY_INTERVAL 100
#define INVALID_CB_ID 0xFF

static int RegisterServerDeathCb(void);
static unsigned int g_deathCbId = INVALID_CB_ID;
static SvcIdentity g_svcIdentity = {0};

struct SoftBusIpcClientCmd {
    uint32_t code;
    void (*func)(IpcIo *io);
};

static struct SoftBusIpcClientCmd g_softBusIpcClientCmdTbl[] = {
    { CLIENT_ON_CHANNEL_OPENED, ClientIpcOnChannelOpened },
    { CLIENT_ON_CHANNEL_OPENFAILED, ClientIpcOnChannelOpenFailed },
    { CLIENT_ON_CHANNEL_CLOSED, ClientIpcOnChannelClosed },
    { CLIENT_ON_CHANNEL_MSGRECEIVED, ClientIpcOnChannelMsgReceived },
};

static int ClientIpcInterfaceMsgHandle(const IpcContext *ctx, void *ipcMsg, IpcIo *io, void *arg)
{
    uint32_t code = 0;
    (void)ctx;
    (void)arg;

    if (ipcMsg == NULL || io == NULL) {
        LOG_ERR("invalid param");
        return SOFTBUS_ERR;
    }

    GetCode(ipcMsg, &code);
    LOG_INFO("receive ipc transact code(%u)", code);
    unsigned int num = sizeof(g_softBusIpcClientCmdTbl) / sizeof(struct SoftBusIpcClientCmd);
    for (unsigned int i = 0; i < num; i++) {
        if (code == g_softBusIpcClientCmdTbl[i].code) {
            g_softBusIpcClientCmdTbl[i].func(io);
            return SOFTBUS_OK;
        }
    }

    LOG_ERR("not support code(%u)", code);
    return SOFTBUS_ERR;
}

static int RegisterService(void)
{
    char clientName[PKG_NAME_SIZE_MAX] = {0};
    if (GetSoftBusClientName(clientName, sizeof(clientName)) != SOFTBUS_OK) {
        LOG_ERR("get client name failed");
        return SOFTBUS_ERR;
    }

    struct CommonScvId svcId = {0};
    if (GetClientIdentity(&svcId.handle, &svcId.token, &svcId.cookie, &svcId.ipcCtx) != SOFTBUS_OK) {
        LOG_ERR("get client identity failed");
        return SOFTBUS_ERR;
    }

    while (GetServerProvideInterface()->registerService(clientName, &svcId) != SOFTBUS_OK) {
        SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
        continue;
    }

    LOG_INFO("success");
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
    CLIENT_NotifyObserver(EVENT_SERVER_DEATH, NULL, 0);

    if (RegisterService() != SOFTBUS_OK) {
        LOG_ERR("register service failed");
        return NULL;
    }

    LOG_INFO("\n<< !!! SERVICE (%s) RECOVER !!! >>\n", SOFTBUS_SERVICE);
    CLIENT_NotifyObserver(EVENT_SERVER_RECOVERY, NULL, 0);
    UnregisterServerDeathCb();

    if (RegisterServerDeathCb() != SOFTBUS_OK) {
        LOG_ERR("reg server death cb failed");
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
        LOG_ERR("pthread_attr_init failed, ret[%d]", ret);
        return SOFTBUS_ERR;
    }

    ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (ret != 0) {
        LOG_ERR("pthread set detached attr failed, ret[%d]", ret);
        ret = SOFTBUS_ERR;
        goto EXIT;
    }

    ret = pthread_attr_setschedpolicy(&attr, SCHED_RR);
    if (ret != 0) {
        LOG_ERR("pthread set sched failed, ret[%d]", ret);
        ret = SOFTBUS_ERR;
        goto EXIT;
    }

    ret = pthread_create(&tid, &attr, DeathProcTask, NULL);
    if (ret != 0) {
        LOG_ERR("create DeathProcTask failed, ret[%d]", ret);
        ret = SOFTBUS_ERR;
        goto EXIT;
    }

    return SOFTBUS_OK;
EXIT:
    if (pthread_attr_destroy(&attr) != 0) {
        LOG_ERR("destroy pthread attr failed, ret[%d]", ret);
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

    LOG_WARN("\n<< ATTENTION !!! >> SERVICE (%s) DEAD !!!\n", SOFTBUS_SERVICE);

    if (StartDeathProcTask() != SOFTBUS_OK) {
        LOG_ERR("start death proc task failed");
        return SOFTBUS_ERR;
    } else {
        LOG_INFO("client start check softbus server...");
    }

    return SOFTBUS_OK;
}

static int RegisterServerDeathCb(void)
{
    g_svcIdentity = SAMGR_GetRemoteIdentity(SOFTBUS_SERVICE, NULL);
    g_deathCbId = INVALID_CB_ID;
    if (RegisterDeathCallback(NULL, g_svcIdentity, DeathCallback, NULL, &g_deathCbId) != EC_SUCCESS) {
        LOG_ERR("reg death callback failed");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int ClientProvideInterfaceImplInit(void)
{
    SvcIdentity clientIdentity = {0};
    int ret = RegisterIpcCallback(ClientIpcInterfaceMsgHandle, 0, IPC_WAIT_FOREVER, &clientIdentity, NULL);
    if (ret != 0) {
        LOG_ERR("register ipc cb failed");
        return SOFTBUS_ERR;
    }
#ifdef __LINUX__
    SetClientIdentity(clientIdentity.handle, clientIdentity.token, clientIdentity.cookie, clientIdentity.ipcContext);
#else
    SetClientIdentity(clientIdentity.handle, clientIdentity.token, clientIdentity.cookie, NULL);
#endif

    if (RegisterService() != SOFTBUS_OK) {
        LOG_ERR("register service failed");
        return SOFTBUS_ERR;
    }

    if (RegisterServerDeathCb() != SOFTBUS_OK) {
        LOG_ERR("reg server death cb failed");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}