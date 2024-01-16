/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "client_disc_manager.h"

#include "disc_log.h"
#include "disc_server_proxy.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"

typedef struct {
    IPublishCallback publishCb;
    IDiscoveryCallback subscribeCb;
} DiscInfo;

static DiscInfo *g_discInfo = NULL;

int32_t PublishServiceInner(const char *packageName, const PublishInfo *info, const IPublishCallback *cb)
{
    g_discInfo->publishCb = *cb;

    int32_t ret = ServerIpcPublishService(packageName, info);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_SDK, "Server PublishService failed, ret=%{public}d", ret);
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t UnpublishServiceInner(const char *packageName, int32_t publishId)
{
    int32_t ret = ServerIpcUnPublishService(packageName, publishId);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_SDK, "Server UnPublishService failed, ret=%{public}d", ret);
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t StartDiscoveryInner(const char *packageName, const SubscribeInfo *info, const IDiscoveryCallback *cb)
{
    if (packageName == NULL || info == NULL || cb == NULL) {
        DISC_LOGE(DISC_SDK, "invalid parameter:null");
        return SOFTBUS_INVALID_PARAM;
    }
    g_discInfo->subscribeCb = *cb;
    int32_t ret = ServerIpcStartDiscovery(packageName, info);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_SDK, "Server StartDiscovery failed, ret=%{public}d", ret);
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t StopDiscoveryInner(const char *packageName, int32_t subscribeId)
{
    int32_t ret = ServerIpcStopDiscovery(packageName, subscribeId);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_SDK, "Server StopDiscovery failed, ret=%{public}d", ret);
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t DiscClientInit(void)
{
    if (g_discInfo != NULL) {
        SoftBusFree(g_discInfo);
    }
    g_discInfo = (DiscInfo *)SoftBusCalloc(sizeof(DiscInfo));
    if (g_discInfo == NULL) {
        DISC_LOGE(DISC_INIT, "Calloc failed");
        return SOFTBUS_MALLOC_ERR;
    }
    if (DiscServerProxyInit() != SOFTBUS_OK) {
        DISC_LOGE(DISC_INIT, "disc server proxy init failed.");
        SoftBusFree(g_discInfo);
        return SOFTBUS_ERR;
    }
    DISC_LOGI(DISC_INIT, "Init success as client side");
    return SOFTBUS_OK;
}

void DiscClientDeinit(void)
{
    if (g_discInfo == NULL) {
        return;
    }
    SoftBusFree(g_discInfo);
    g_discInfo = NULL;
    DiscServerProxyDeInit();
    DISC_LOGI(DISC_CONTROL, "DeInit success");
}

void DiscClientOnDeviceFound(const DeviceInfo *device)
{
    if (device == NULL) {
        DISC_LOGE(DISC_SDK, "invalid parameter:null");
        return;
    }   
    DISC_LOGI(DISC_SDK, "Sdk OnDeviceFound, capabilityBitmap=%{public}d",
        device->capabilityBitmap[0]);
    if (g_discInfo == NULL) {
        DISC_LOGE(DISC_SDK, "OnDeviceFound callback failed!");
        return;
    }
    g_discInfo->subscribeCb.OnDeviceFound(device);
}

void DiscClientOnDiscoverySuccess(int32_t subscribeId)
{
    DISC_LOGI(DISC_SDK, "Sdk OnDiscoverySuccess, subscribeId=%{public}d", subscribeId);
    if (g_discInfo == NULL) {
        DISC_LOGE(DISC_SDK, "OnDiscoverySuccess callback failed!");
        return;
    }
    g_discInfo->subscribeCb.OnDiscoverySuccess(subscribeId);
}

void DiscClientOnDiscoverFailed(int32_t subscribeId, DiscoveryFailReason failReason)
{
    DISC_LOGI(DISC_SDK, "Sdk OnDiscoverFailed, subscribeId=%{public}d", subscribeId);
    if (g_discInfo == NULL) {
        DISC_LOGE(DISC_SDK, "OnDiscoverFailed callback failed!");
        return;
    }
    g_discInfo->subscribeCb.OnDiscoverFailed(subscribeId, failReason);
}

void DiscClientOnPublishSuccess(int32_t publishId)
{
    DISC_LOGI(DISC_SDK, "Sdk OnPublishSuccess, publishId=%{public}d", publishId);
    if (g_discInfo == NULL) {
        DISC_LOGE(DISC_SDK, "OnPublishSuccess callback failed!");
        return;
    }
    g_discInfo->publishCb.OnPublishSuccess(publishId);
}

void DiscClientOnPublishFail(int32_t publishId, PublishFailReason reason)
{
    DISC_LOGI(DISC_SDK, "Sdk OnPublishFail, publishId=%{public}d", publishId);
    if (g_discInfo == NULL) {
        DISC_LOGE(DISC_SDK, "OnPublishFail callback failed!");
        return;
    }
    g_discInfo->publishCb.OnPublishFail(publishId, reason);
}