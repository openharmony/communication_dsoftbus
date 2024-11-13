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

#include "comm_log.h"
#include "ipc_skeleton.h"
#include "iproxy_client.h"
#include "samgr_lite.h"
#include "softbus_adapter_file.h"
#include "softbus_adapter_timer.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_server_ipc_interface_code.h"
#include "softbus_server_proxy.h"


#define WAIT_SERVER_READY_INTERVAL_COUNT 50

static IClientProxy *g_serverProxy = NULL;
static IClientProxy *g_oldServerProxy = NULL;

static int ClientSimpleResultCb(IOwner owner, int code, IpcIo *reply)
{
    ReadInt32(reply, (int *)owner);
    COMM_LOGI(COMM_SDK, "retvalue=%{public}d", *(int *)owner);
    return EC_SUCCESS;
}

static IClientProxy *GetServerProxy(void)
{
    IClientProxy *clientProxy = NULL;

    COMM_LOGI(COMM_SDK, "start get client proxy");
    int32_t proxyInitCount = 0;
    while (clientProxy == NULL) {
        proxyInitCount++;
        if (proxyInitCount == WAIT_SERVER_READY_INTERVAL_COUNT) {
            COMM_LOGE(COMM_SDK, "frame get server proxy error");
            return NULL;
        }
        IUnknown *iUnknown = SAMGR_GetInstance()->GetDefaultFeatureApi(SOFTBUS_SERVICE);
        if (iUnknown == NULL) {
            SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
            continue;
        }

        int32_t ret = iUnknown->QueryInterface(iUnknown, CLIENT_PROXY_VER, (void **)&clientProxy);
        if (ret != EC_SUCCESS || clientProxy == NULL) {
            COMM_LOGE(COMM_SDK, "QueryInterface failed. ret=%{public}d", ret);
            SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
            continue;
        }
    }

    COMM_LOGI(COMM_SDK, "frame get client proxy ok");
    return clientProxy;
}

int32_t RegisterService(const char *name, const struct CommonScvId *svcId)
{
    COMM_LOGI(COMM_SDK, "server register service client push.");
    if ((svcId == NULL) || (name == NULL)) {
        COMM_LOGE(COMM_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};

    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 1);
    WriteString(&request, name);

    SvcIdentity svc = {0};
    svc.handle = svcId->handle;
    svc.token = svcId->token;
    svc.cookie = svcId->cookie;
    bool value = WriteRemoteObject(&request, &svc);
    if (!value) {
        return SOFTBUS_TRANS_PROXY_WRITEOBJECT_FAILED;
    }

    int ret = SOFTBUS_IPC_ERR;
    if (g_serverProxy->Invoke(g_serverProxy, MANAGE_REGISTER_SERVICE, &request, &ret,
        ClientSimpleResultCb) != EC_SUCCESS) {
        COMM_LOGI(COMM_SDK, "Call back ret=%{public}d", ret);
        return SOFTBUS_IPC_ERR;
    }
    return ret;
}

void __attribute__((weak)) HOS_SystemInit(void)
{
    SAMGR_Bootstrap();
    return;
}

int32_t ServerProxyInit(void)
{
    HOS_SystemInit();
    g_serverProxy = GetServerProxy();
    if (g_serverProxy == NULL) {
        COMM_LOGE(COMM_SDK, "get ipc client proxy failed");
        return SOFTBUS_IPC_ERR;
    }

    if (g_serverProxy == g_oldServerProxy) {
        g_serverProxy = NULL;
        COMM_LOGE(COMM_SDK, "get ipc client proxy is the same as old");
        return SOFTBUS_IPC_ERR;
    }

    COMM_LOGI(COMM_SDK, "ServerProvideInterfaceInit ok");
    return SOFTBUS_OK;
}

int32_t ServerProxyDeInit(void)
{
    g_oldServerProxy = g_serverProxy;
    if (g_serverProxy != NULL) {
        (void)g_serverProxy->Release((IUnknown *)(g_serverProxy));
        g_serverProxy = NULL;
    }

    COMM_LOGI(COMM_SDK, "ServerProxyDeInit ok");
    return SOFTBUS_OK;
}