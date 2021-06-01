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

#include "softbus_disc_server.h"
#include "softbus_errcode.h"
#include "softbus_interface.h"
#include "softbus_log.h"
#include "softbus_permission.h"
#include "softbus_server_frame.h"

int32_t DiscServerInit(void)
{
    int32_t ret = DiscMgrInit();
    if (ret != SOFTBUS_OK) {
        LOG_ERR("DiscServerInit failed");
        return ret;
    }
    return SOFTBUS_OK;
}

void DiscServerDeinit(void)
{
    DiscMgrDeinit();
}

int32_t DiscIpcPublishService(const char *packageName, const PublishInfo *info)
{
    if (CheckDiscPermission(packageName) != true) {
        LOG_ERR("ServerPublishService no permission!");
        return SOFTBUS_DISCOVER_SERVER_NO_PERMISSION;
    }
    IServerPublishCallback callback;
    callback.OnServerPublishSuccess = (void *)(GetClientProvideInterface()->onPublishSuccess);
    callback.OnServerPublishFail = (void *)(GetClientProvideInterface()->onPublishFail);
    int32_t ret = DiscPublishService(packageName, info, &callback);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("ServerPublishService failed");
        return ret;
    }
    LOG_INFO("ServerPublishService success!");
    return SOFTBUS_OK;
}

int32_t DiscIpcUnPublishService(const char *packageName, int32_t publishId)
{
    if (CheckDiscPermission(packageName) != true) {
        LOG_ERR("ServerUnPublishService no permission!");
        return SOFTBUS_DISCOVER_SERVER_NO_PERMISSION;
    }
    int32_t ret = DiscUnPublishService(packageName, publishId);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("ServerUnPublishService failed");
        return ret;
    }
    LOG_INFO("ServerUnPublishService success!");
    return SOFTBUS_OK;
}

int32_t DiscIpcStartDiscovery(const char *packageName, const SubscribeInfo *info)
{
    if (CheckDiscPermission(packageName) != true) {
        LOG_ERR("ServerStartDiscovery no permission!");
        return SOFTBUS_DISCOVER_SERVER_NO_PERMISSION;
    }
    IServerDiscoveryCallback callback;
    callback.OnServerDeviceFound = (void *)(GetClientProvideInterface()->onDeviceFound);
    callback.OnServerDiscoverySuccess = (void *)(GetClientProvideInterface()->onDiscoverySuccess);
    callback.OnServerDiscoverFailed = (void *)(GetClientProvideInterface()->onDiscoverFailed);
    int32_t ret = DiscStartDiscovery(packageName, info, &callback);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("ServerStartDiscovery failed");
        return ret;
    }
    LOG_INFO("ServerStartDiscovery success!");
    return SOFTBUS_OK;
}

int32_t DiscIpcStopDiscovery(const char *packageName, int32_t subscribeId)
{
    if (CheckDiscPermission(packageName) != true) {
        LOG_ERR("ServerStopDiscovery no permission!");
        return SOFTBUS_DISCOVER_SERVER_NO_PERMISSION;
    }
    int32_t ret = DiscStopDiscovery(packageName, subscribeId);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("ServerStopDiscovery failed");
        return ret;
    }
    LOG_INFO("ServerStopDiscovery success!");
    return SOFTBUS_OK;
}
