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

#include "disc_client_proxy.h"

#include "client_disc_manager.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

int32_t ClientIpcOnDeviceFound(const char *pkgName, const DeviceInfo *device, const InnerDeviceInfoAddtions *addtions)
{
    (void)pkgName;
    (void)addtions;
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "ondevice found ipc server push.");
    DiscClientOnDeviceFound(device);
    return SOFTBUS_OK;
}

int32_t ClientIpcOnDiscoverFailed(const char *pkgName, int subscribeId, int failReason)
{
    (void)pkgName;
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "on discovery failed callback ipc server push.");
    DiscClientOnDiscoverFailed(subscribeId, (DiscoveryFailReason)failReason);
    return SOFTBUS_OK;
}

int32_t ClientIpcDiscoverySuccess(const char *pkgName, int subscribeId)
{
    (void)pkgName;
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "on discovery success callback ipc server push.");
    DiscClientOnDiscoverySuccess(subscribeId);
    return SOFTBUS_OK;
}

int32_t ClientIpcOnPublishSuccess(const char *pkgName, int publishId)
{
    (void)pkgName;
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "on publish success callback ipc server push.");
    DiscClientOnPublishSuccess(publishId);
    return SOFTBUS_OK;
}

int32_t ClientIpcOnPublishFail(const char *pkgName, int publishId, int reason)
{
    (void)pkgName;
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "on publish failed ipc server push.");
    DiscClientOnPublishFail(publishId, (PublishFailReason)reason);
    return SOFTBUS_OK;
}
