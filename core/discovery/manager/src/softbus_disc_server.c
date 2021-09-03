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

#include "disc_client_proxy.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_permission.h"

static IServerDiscInnerCallback g_discInnerCb = {
    .OnServerDeviceFound = ClientIpcOnDeviceFound,
};

static bool g_isCallLnn = true;

int32_t DiscServerInit(void)
{
    int32_t ret = DiscMgrInit();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "DiscServerInit failed");
        return ret;
    }
    return SOFTBUS_OK;
}

void DiscServerDeinit(void)
{
    DiscMgrDeinit();
}

void DiscServerDeathCallback(const char *pkgName)
{
    DiscMgrDeathCallback(pkgName);
}

static int32_t PublishErroCodeProcess(int32_t erroCode)
{
    if (erroCode == SOFTBUS_DISCOVER_MANAGER_INVALID_MEDIUM) {
        return PUBLISH_FAIL_REASON_NOT_SUPPORT_MEDIUM;
    }
    return PUBLISH_FAIL_REASON_INTERNAL;
}

static int32_t DiscoveryErroCodeProcess(int32_t erroCode)
{
    if (erroCode == SOFTBUS_DISCOVER_MANAGER_INVALID_MEDIUM) {
        return DISCOVERY_FAIL_REASON_NOT_SUPPORT_MEDIUM;
    }
    return DISCOVERY_FAIL_REASON_INTERNAL;
}

int32_t DiscIpcPublishService(const char *packageName, const PublishInfo *info)
{
    int32_t ret = DiscPublishService(packageName, info);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "ServerPublishService failed");
        (void)ClientIpcOnPublishFail(packageName, info->publishId, PublishErroCodeProcess(ret));
        return ret;
    }
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "ServerPublishService success!");
    (void)ClientIpcOnPublishSuccess(packageName, info->publishId);
    return SOFTBUS_OK;
}

int32_t DiscIpcUnPublishService(const char *packageName, int32_t publishId)
{
    int32_t ret = DiscUnPublishService(packageName, publishId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "ServerUnPublishService failed");
        return ret;
    }
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "ServerUnPublishService success!");
    return SOFTBUS_OK;
}

int32_t DiscIpcStartDiscovery(const char *packageName, const SubscribeInfo *info)
{
    SetCallLnnStatus(false);
    int32_t ret = DiscStartDiscovery(packageName, info, &g_discInnerCb);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "ServerStartDiscovery failed");
        (void)ClientIpcOnDiscoverFailed(packageName, info->subscribeId, DiscoveryErroCodeProcess(ret));
        return ret;
    }
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "ServerStartDiscovery success!");
    (void)ClientIpcDiscoverySuccess(packageName, info->subscribeId);
    return SOFTBUS_OK;
}

int32_t DiscIpcStopDiscovery(const char *packageName, int32_t subscribeId)
{
    int32_t ret = DiscStopDiscovery(packageName, subscribeId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "ServerStopDiscovery failed");
        return ret;
    }
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "ServerStopDiscovery success!");
    return SOFTBUS_OK;
}

void SetCallLnnStatus(bool flag)
{
    g_isCallLnn = flag;
}

bool GetCallLnnStatus(void)
{
    return g_isCallLnn;
}
