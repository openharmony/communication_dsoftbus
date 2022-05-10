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

#include "disc_serializer.h"
#include "iproxy_client.h"
#include "samgr_lite.h"
#include "serializer.h"
#include "softbus_adapter_file.h"
#include "softbus_adapter_timer.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"

#define WAIT_SERVER_READY_INTERVAL_COUNT 50

static IClientProxy *g_serverProxy = NULL;

int32_t DiscServerProxyInit(void)
{
    if (g_serverProxy != NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "server proxy has initialized.");
        return SOFTBUS_OK;
    }

    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "disc start get server proxy");
    int32_t proxyInitCount = 0;
    while (g_serverProxy == NULL) {
        proxyInitCount++;
        if (proxyInitCount == WAIT_SERVER_READY_INTERVAL_COUNT) {
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "disc get server proxy error");
            return SOFTBUS_ERR;
        }
        IUnknown *iUnknown = SAMGR_GetInstance()->GetDefaultFeatureApi(SOFTBUS_SERVICE);
        if (iUnknown == NULL) {
            SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
            continue;
        }

        int32_t ret = iUnknown->QueryInterface(iUnknown, CLIENT_PROXY_VER, (void **)&g_serverProxy);
        if (ret != EC_SUCCESS || g_serverProxy == NULL) {
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "QueryInterface failed [%d]", ret);
            SoftBusSleepMs(WAIT_SERVER_READY_INTERVAL);
            continue;
        }
    }
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "disc get server proxy ok");
    return SOFTBUS_OK;
}

void DiscServerProxyDeInit(void)
{
    g_serverProxy = NULL;
}

int ServerIpcPublishService(const char *pkgName, const PublishInfo *info)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "publish service ipc client push.");
    if (pkgName == NULL || info == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        return SOFTBUS_ERR;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, pkgName);
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
    bool ret = WriteRawData(&request, (void*)&publishSerializer, sizeof(PublishSerializer));
    if (!ret) {
        return SOFTBUS_ERR;
    }
    WriteString(&request, info->capability);
    if (info->dataLen != 0) {
        WriteString(&request, (const char *)(info->capabilityData));
    }
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_PUBLISH_SERVICE, &request, NULL, NULL);
    if (ans != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "publish service invoke failed[%d].", ans);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int ServerIpcUnPublishService(const char *pkgName, int publishId)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "unpublish service ipc client push.");
    if (pkgName == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        return SOFTBUS_ERR;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, pkgName);
    WriteInt32(&request, publishId);
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_UNPUBLISH_SERVICE, &request, NULL, NULL);
    if (ans != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "unpublish service invoke failed[%d].", ans);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int ServerIpcStartDiscovery(const char *pkgName, const SubscribeInfo *info)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "start discovery ipc client push.");
    if (pkgName == NULL || info == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        return SOFTBUS_ERR;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, pkgName);
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
    bool ret = WriteRawData(&request, (void*)&subscribeSerializer, sizeof(SubscribeSerializer));
    if (!ret) {
        return SOFTBUS_ERR;
    }
    WriteString(&request, info->capability);
    if (info->dataLen != 0) {
        WriteString(&request, (const char *)(info->capabilityData));
    }
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_START_DISCOVERY, &request, NULL, NULL);
    if (ans != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "start discovery invoke failed[%d].", ans);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int ServerIpcStopDiscovery(const char *pkgName, int subscribeId)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "stop discovery ipc client push.");
    if (pkgName == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverProxy == NULL) {
        return SOFTBUS_ERR;
    }

    uint8_t data[MAX_SOFT_BUS_IPC_LEN] = {0};
    IpcIo request = {0};
    IpcIoInit(&request, data, MAX_SOFT_BUS_IPC_LEN, 0);
    WriteString(&request, pkgName);
    WriteInt32(&request, subscribeId);
    /* asynchronous invocation */
    int32_t ans = g_serverProxy->Invoke(g_serverProxy, SERVER_STOP_DISCOVERY, &request, NULL, NULL);
    if (ans != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "stop discovery invoke failed[%d].", ans);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
