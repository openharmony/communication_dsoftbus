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
#include <stdlib.h>

#include "iproxy_client.h"
#include "liteipc_adapter.h"
#include "samgr_lite.h"
#include "securec.h"
#include "softbus.h"
#include "softbus_client_weak.h"
#include "softbus_errcode.h"
#include "softbus_interface.h"
#include "softbus_log.h"
#include "softbus_os_interface.h"

#define WAIT_SERVER_READY_INTERVAL 200

static IClientProxy *g_clientProxy = NULL;

static int ClientSimpleResultCb(IOwner owner, int code, IpcIo *reply)
{
    *(int *)owner = IpcIoPopInt32(reply);
    LOG_INFO("retvalue:%d", *(int *)owner);
    return EC_SUCCESS;
}

static int ServerIpcRegisterService(const char *name, const struct CommonScvId *svcId)
{
    if ((svcId == NULL) || (name == NULL)) {
        LOG_ERR("Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    char *data = SoftBusMalloc(MAX_SOFT_BUS_IPC_LEN);
    if (data == NULL) {
        LOG_ERR("malloc failed");
        return SOFTBUS_ERR;
    }
    (void)memset_s(data, MAX_SOFT_BUS_IPC_LEN, 0, MAX_SOFT_BUS_IPC_LEN);

    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 1);
    IpcIoPushString(&request, name);

    SvcIdentity svc = {0};
    svc.handle = svcId->handle;
    svc.token = svcId->token;
    svc.cookie = svcId->cookie;
#ifdef __LINUX__
    svc.ipcContext = svcId->ipcCtx;
#endif
    IpcIoPushSvc(&request, &svc);

    int ret = SOFTBUS_ERR;
    if (g_clientProxy->Invoke(g_clientProxy, MANAGE_REGISTER_SERVICE, &request, &ret,
        ClientSimpleResultCb) != EC_SUCCESS) {
        SoftBusFree(data);
        LOG_INFO("Call back ret(%d)", ret);
        return SOFTBUS_ERR;
    }

    SoftBusFree(data);
    return ret;
}

static IClientProxy *GetClientProxy(void)
{
    IClientProxy *clientProxy = NULL;
    IUnknown *iUnknown = NULL;
    int ret;

    LOG_INFO("start get client proxy");
    while (clientProxy == NULL) {
        iUnknown = SAMGR_GetInstance()->GetDefaultFeatureApi(SOFTBUS_SERVICE);
        if (iUnknown == NULL) {
            SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
            continue;
        }

        ret = iUnknown->QueryInterface(iUnknown, CLIENT_PROXY_VER, (void **)&clientProxy);
        if (ret != EC_SUCCESS || clientProxy == NULL) {
            LOG_ERR("QueryInterface failed [%d]", ret);
            SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
            continue;
        }
    }

    LOG_INFO("get client proxy ok");
    return clientProxy;
}

void __attribute__((weak)) HOS_SystemInit(void)
{
    SAMGR_Bootstrap();
    return;
}

static struct ServerProvideInterface g_serverProvideInterface = {
    .registerService = ServerIpcRegisterService,
    .publishService = ServerIpcPublishService,
    .unPublishService = ServerIpcUnPublishService,
    .createSessionServer = ServerIpcCreateSessionServer,
    .removeSessionServer = ServerIpcRemoveSessionServer,
    .openSession = ServerIpcOpenSession,
    .closeChannel = ServerIpcCloseChannel,
    .sendMessage = ServerIpcSendMessage,
    .startDiscovery = ServerIpcStartDiscovery,
    .stopDiscovery = ServerIpcStopDiscovery,
    .joinLNN = ServerIpcJoinLNN,
    .leaveLNN = ServerIpcLeaveLNN,
};

int ServerProvideInterfaceInit(void)
{
    HOS_SystemInit();
    g_clientProxy = GetClientProxy();
    if (g_clientProxy == NULL) {
        LOG_ERR("get ipc client proxy failed");
        return SOFTBUS_ERR;
    }
    LOG_INFO("ServerProvideInterfaceInit ok");
    return SOFTBUS_OK;
}

struct ServerProvideInterface *GetServerProvideInterface(void)
{
    return &g_serverProvideInterface;
}

void *SoftBusGetClientProxy(void)
{
    return g_clientProxy;
}