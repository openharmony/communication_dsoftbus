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
#include "comm_log.h"
#include "disc_client_stub.h"
#include "iproxy_client.h"
#include "ipc_skeleton.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_timer.h"
#include "softbus_client_context_manager.h"
#include "softbus_client_event_manager.h"
#include "softbus_client_frame_manager.h"
#include "softbus_client_stub_interface.h"
#include "softbus_errcode.h"
#include "softbus_server_ipc_interface_code.h"
#include "softbus_server_proxy.h"
#include "trans_client_stub.h"

#define INVALID_CB_ID 0xFF

static int RegisterServerDeathCb(void);
static unsigned int g_deathCbId = INVALID_CB_ID;
static SvcIdentity g_svcIdentity = {0};

struct SoftBusIpcClientCmd {
    enum SoftBusFuncId code;
    int32_t (*func)(IpcIo *data, IpcIo *reply);
};

static struct SoftBusIpcClientCmd g_softBusIpcClientCmdTbl[] = {
    { CLIENT_DISCOVERY_SUCC, ClientOnDiscoverySuccess },
    { CLIENT_DISCOVERY_FAIL, ClientOnDiscoverFailed },
    { CLIENT_DISCOVERY_DEVICE_FOUND, ClientOnDeviceFound },
    { CLIENT_PUBLISH_SUCC, ClientOnPublishSuccess },
    { CLIENT_PUBLISH_FAIL, ClientOnPublishFail },
    { CLIENT_ON_JOIN_RESULT, ClientOnJoinLNNResult },
    { CLIENT_ON_JOIN_METANODE_RESULT, ClientOnJoinMetaNodeResult },
    { CLIENT_ON_LEAVE_RESULT, ClientOnLeaveLNNResult },
    { CLIENT_ON_LEAVE_METANODE_RESULT, ClientOnLeaveMetaNodeResult },
    { CLIENT_ON_NODE_ONLINE_STATE_CHANGED, ClientOnNodeOnlineStateChanged },
    { CLIENT_ON_NODE_BASIC_INFO_CHANGED, ClientOnNodeBasicInfoChanged },
    { CLIENT_ON_TIME_SYNC_RESULT, ClientOnTimeSyncResult },
    { CLIENT_ON_PUBLISH_LNN_RESULT, ClientOnPublishLNNResult },
    { CLIENT_ON_REFRESH_LNN_RESULT, ClientOnRefreshLNNResult },
    { CLIENT_ON_REFRESH_DEVICE_FOUND, ClientOnRefreshDeviceFound },
    { CLIENT_ON_CHANNEL_OPENED, ClientOnChannelOpened },
    { CLIENT_ON_CHANNEL_OPENFAILED, ClientOnChannelOpenfailed },
    { CLIENT_ON_CHANNEL_CLOSED, ClientOnChannelClosed },
    { CLIENT_ON_CHANNEL_MSGRECEIVED, ClientOnChannelMsgreceived },
};

static int ClientIpcInterfaceMsgHandle(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    if (data == NULL) {
        COMM_LOGE(COMM_SDK, "invalid param");
        return SOFTBUS_ERR;
    }

    COMM_LOGI(COMM_SDK, "receive ipc transact code. code=%{public}u", code);
    unsigned int num = sizeof(g_softBusIpcClientCmdTbl) / sizeof(struct SoftBusIpcClientCmd);
    for (unsigned int i = 0; i < num; i++) {
        if (code == g_softBusIpcClientCmdTbl[i].code) {
            return g_softBusIpcClientCmdTbl[i].func(data, reply);
        }
    }
    COMM_LOGE(COMM_SDK, "not support code. code=%{public}u", code);
    return SOFTBUS_ERR;
}

static int InnerRegisterService(void)
{
    char *clientName[SOFTBUS_PKGNAME_MAX_NUM] = {0};
    uint32_t clientNameNum = GetSoftBusClientNameList(clientName, SOFTBUS_PKGNAME_MAX_NUM);
    if (clientNameNum == 0) {
        COMM_LOGE(COMM_SDK, "get client name failed");
        return SOFTBUS_ERR;
    }

    struct CommonScvId svcId = {0};
    if (GetClientIdentity(&svcId.handle, &svcId.token, &svcId.cookie) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "get client identity failed");
        for (uint32_t i = 0; i < clientNameNum; i++) {
            SoftBusFree(clientName[i]);
        }
        return SOFTBUS_ERR;
    }
    for (uint32_t i = 0; i < clientNameNum; i++) {
        while (RegisterService(clientName[i], &svcId) != SOFTBUS_OK) {
            SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
        }
        SoftBusFree(clientName[i]);
    }

    COMM_LOGI(COMM_SDK, "InnerRegisterService success");
    return SOFTBUS_OK;
}

static void UnregisterServerDeathCb(void)
{
    RemoveDeathRecipient(g_svcIdentity, g_deathCbId);
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
        COMM_LOGE(COMM_SDK, "register service failed");
        return NULL;
    }

    COMM_LOGI(COMM_SDK, "\n<< !!! SERVICE (%{public}s) RECOVER !!! >>\n", SOFTBUS_SERVICE);
    CLIENT_NotifyObserver(EVENT_SERVER_RECOVERY, NULL, 0);
    UnregisterServerDeathCb();

    if (RegisterServerDeathCb() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "reg server death cb failed");
        return NULL;
    }

    return NULL;
}

static int StartDeathProcTask(void)
{
    int ret;
    SoftBusThreadAttr threadAttr;
    SoftBusThread tid;
    ret = SoftBusThreadAttrInit(&threadAttr);
    if (ret != 0) {
        COMM_LOGE(COMM_SDK, "Thread attr init failed, ret=%{public}d", ret);
        return SOFTBUS_ERR;
    }

    threadAttr.detachState = SOFTBUS_THREAD_DETACH;
    threadAttr.policy = SOFTBUS_SCHED_RR;
    threadAttr.taskName = "OS_deathTsk";
    ret = SoftBusThreadCreate(&tid, &threadAttr, DeathProcTask, NULL);
    if (ret != 0) {
        COMM_LOGE(COMM_SDK, "create DeathProcTask failed, ret=%{public}d", ret);
        return SOFTBUS_ERR;
    }

    return ret;
}

static void DeathCallback(void)
{
    COMM_LOGW(COMM_SDK, "\n<< ATTENTION !!! >> SERVICE (%{public}s) DEAD !!!\n", SOFTBUS_SERVICE);

    if (StartDeathProcTask() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "start death proc task failed");
    }
    COMM_LOGI(COMM_SDK, "client start check softbus server...");
}

static int RegisterServerDeathCb(void)
{
    g_svcIdentity = SAMGR_GetRemoteIdentity(SOFTBUS_SERVICE, NULL);
    g_deathCbId = INVALID_CB_ID;
    if (AddDeathRecipient(g_svcIdentity, DeathCallback, NULL, &g_deathCbId) != EC_SUCCESS) {
        COMM_LOGE(COMM_SDK, "reg death callback failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int ClientStubInit(void)
{
    if (ServerProxyInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "server proxy init failed.");
        return SOFTBUS_ERR;
    }

    static IpcObjectStub objectStub = {
        .func = ClientIpcInterfaceMsgHandle,
        .args = NULL,
        .isRemote = false
    };
    SvcIdentity clientIdentity = {
        .handle = IPC_INVALID_HANDLE,
        .token = SERVICE_TYPE_ANONYMOUS,
        .cookie = (uintptr_t)&objectStub
    };

    int ret = ClientContextInit();
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "client context init failed.");
        return SOFTBUS_ERR;
    }
    SetClientIdentity(clientIdentity.handle, clientIdentity.token, clientIdentity.cookie);
    if (RegisterServerDeathCb() != SOFTBUS_OK) {
        ClientContextDeinit();
        COMM_LOGE(COMM_SDK, "reg server death cb failed");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int ClientRegisterService(const char *pkgName)
{
    struct CommonScvId svcId = {0};
    if (GetClientIdentity(&svcId.handle, &svcId.token, &svcId.cookie) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "get client identity failed");
        return SOFTBUS_ERR;
    }

    while (RegisterService(pkgName, &svcId) != SOFTBUS_OK) {
        SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
    }

    COMM_LOGI(COMM_SDK, "ClientRegisterService success");
    return SOFTBUS_OK;
}
