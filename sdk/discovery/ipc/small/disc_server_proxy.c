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

#include "disc_server_proxy.h"

#include "disc_log.h"
#include "disc_serializer.h"
#include "iproxy_client.h"
#include "samgr_lite.h"
#include "serializer.h"
#include "softbus_adapter_file.h"
#include "softbus_adapter_timer.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_server_ipc_interface_code.h"

#define WAIT_SERVER_READY_INTERVAL_COUNT 50

static IClientProxy *g_serverProxy = NULL;

int32_t DiscServerProxyInit(void)
{
    if (g_serverProxy != NULL) {
        DISC_LOGI(DISC_INIT, "server proxy has initialized.");
        return SOFTBUS_OK;
    }

    DISC_LOGI(DISC_INIT, "disc start get server proxy");
    int32_t proxyInitCount = 0;
    while (g_serverProxy == NULL) {
        proxyInitCount++;
        if (proxyInitCount == WAIT_SERVER_READY_INTERVAL_COUNT) {
            DISC_LOGE(DISC_INIT, "disc get server proxy error");
            return SOFTBUS_ERR;
        }
        IUnknown *iUnknown = SAMGR_GetInstance()->GetDefaultFeatureApi(SOFTBUS_SERVICE);
        if (iUnknown == NULL) {
            SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
            continue;
        }

        int32_t ret = iUnknown->QueryInterface(iUnknown, CLIENT_PROXY_VER, (void **)&g_serverProxy);
        if (ret != EC_SUCCESS || g_serverProxy == NULL) {
            DISC_LOGE(DISC_INIT, "QueryInterface failed. ret=%{public}d", ret);
            SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
            continue;
        }
    }
    DISC_LOGI(DISC_INIT, "disc get server proxy ok");
    return SOFTBUS_OK;
}

void DiscServerProxyDeInit(void)
{
    g_serverProxy = NULL;
}

int ServerIpcPublishService(const char *pkgName, const PublishInfo *info)
{
    DISC_LOGI(DISC_CONTROL, "publish service ipc client push.");
    if (pkgName == NULL || info == NULL) {
        DISC_LOGE(DISC_SDK, "Invalid param:null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        return SOFTBUS_ERR;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    bool ret = WriteString(&request, pkgName);
    if (!ret) {
        DISC_LOGE(DISC_SDK, "Write pkgName failed");
        return SOFTBUS_ERR;
    }
    DiscSerializer serializer = {
        .dataLen = info->dataLen,
        .freq = info->freq,
        .medium = info->medium,
        .mode = info->mode,
        .id.publishId = info->publishId
    };
    PublishSerializer publishSerializer = {
        .commonSerializer = serializer
    };
    ret = WriteRawData(&request, (void*)&publishSerializer, sizeof(PublishSerializer));
    if (!ret) {
        DISC_LOGE(DISC_SDK, "Write publish serializer failed");
        return SOFTBUS_ERR;
    }
    
    ret = WriteString(&request, info->capability);
    if (!ret) {
        DISC_LOGE(DISC_SDK, "Write capability failed");
        return SOFTBUS_ERR;
    }
    if (info->dataLen != 0) {
        ret = WriteString(&request, (const char *)(info->capabilityData));
        if (!ret) {
            DISC_LOGE(DISC_SDK, "Write capability Data failed");
            return SOFTBUS_ERR;
        }
    }
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_PUBLISH_SERVICE, &request, NULL, NULL);
    if (ans != SOFTBUS_OK) {
        DISC_LOGE(DISC_CONTROL, "publish service invoke failed. ans=%{public}d", ans);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int ServerIpcUnPublishService(const char *pkgName, int publishId)
{
    DISC_LOGI(DISC_CONTROL, "unpublish service ipc client push.");
    if (pkgName == NULL) {
        DISC_LOGE(DISC_SDK, "Invalid param:null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        return SOFTBUS_NO_INIT;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    bool ret = WriteString(&request, pkgName);
    if (!ret) {
        DISC_LOGE(DISC_SDK, "Write pkgName failed");
        return SOFTBUS_ERR;
    }

    ret = WriteInt32(&request, publishId);
    if (!ret) {
        DISC_LOGE(DISC_SDK, "Write publishId failed");
        return SOFTBUS_ERR;
    }
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_UNPUBLISH_SERVICE, &request, NULL, NULL);
    if (ans != SOFTBUS_OK) {
        DISC_LOGE(DISC_CONTROL, "unpublish service invoke failed. ans=%{public}d", ans);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int ServerIpcStartDiscovery(const char *pkgName, const SubscribeInfo *info)
{
    DISC_LOGI(DISC_CONTROL, "start discovery ipc client push.");
    if (pkgName == NULL || info == NULL) {
        DISC_LOGE(DISC_SDK, "Invalid param:null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        return SOFTBUS_NO_INIT;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    bool ret = WriteString(&request, pkgName);
    if (!ret) {
        DISC_LOGE(DISC_SDK, "Write pkgName failed");
        return SOFTBUS_ERR;
    }   
    DiscSerializer serializer = {
        .dataLen = info->dataLen,
        .freq = info->freq,
        .medium = info->medium,
        .mode = info->mode,
        .id.subscribeId = info->subscribeId
    };
    SubscribeSerializer subscribeSerializer = {
        .commonSerializer = serializer,
        .isSameAccount = info->isSameAccount,
        .isWakeRemote = info->isWakeRemote
    };
    ret = WriteRawData(&request, (void*)&subscribeSerializer, sizeof(SubscribeSerializer));
    if (!ret) {
        DISC_LOGE(DISC_SDK, "Write SubscribeSerializer failed");
        return SOFTBUS_ERR;
    }
    ret = WriteString(&request, info->capability);
    if (!ret) {
        DISC_LOGE(DISC_SDK, "Write capability failed");
        return SOFTBUS_ERR;
    }   
    if (info->dataLen != 0) {
        ret = WriteString(&request, (const char *)(info->capabilityData));
        if (!ret) {
            DISC_LOGE(DISC_SDK, "Write capabilityData failed");
            return SOFTBUS_ERR;
        } 
    }
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_START_DISCOVERY, &request, NULL, NULL);
    if (ans != SOFTBUS_OK) {
        DISC_LOGE(DISC_CONTROL, "start discovery invoke failed. ans=%{public}d", ans);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int ServerIpcStopDiscovery(const char *pkgName, int subscribeId)
{
    DISC_LOGI(DISC_SDK, "stop discovery ipc client push.");
    if (pkgName == NULL) {
        DISC_LOGE(DISC_SDK, "Invalid param:null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        return SOFTBUS_NO_INIT;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    bool ret = WriteString(&request, pkgName);
    if (!ret) {
        DISC_LOGE(DISC_SDK, "Write pkgName failed");
        return SOFTBUS_ERR;
    }  
    ret = WriteInt32(&request, subscribeId);
    if (!ret) {
        DISC_LOGE(DISC_SDK, "Write subscribeId failed");
        return SOFTBUS_ERR;
    }
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_STOP_DISCOVERY, &request, NULL, NULL);
    if (ans != SOFTBUS_OK) {
        DISC_LOGE(DISC_CONTROL, "stop discovery invoke failed. ans=%{public}d", ans);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}