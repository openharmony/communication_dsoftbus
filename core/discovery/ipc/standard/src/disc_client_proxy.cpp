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

#include "disc_client_proxy_standard.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_server_data.h"

using namespace OHOS;

static sptr<DiscClientProxy> GetClientProxy(const char *pkgName)
{
    sptr<IRemoteObject> clientObject = SoftBusServerData::GetInstance().GetSoftbusClientProxy(pkgName);
    sptr<DiscClientProxy> clientProxy = new (std::nothrow) DiscClientProxy(clientObject);
    return clientProxy;
}

int32_t ClientIpcOnDeviceFound(const char *pkgName, const DeviceInfo *device)
{
    sptr<DiscClientProxy> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "softbus client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    clientProxy->OnDeviceFound(device);
    return SOFTBUS_OK;
}

int32_t ClientIpcOnDiscoverFailed(const char *pkgName, int subscribeId, int failReason)
{
    sptr<DiscClientProxy> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "softbus client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    clientProxy->OnDiscoverFailed(subscribeId, failReason);
    return SOFTBUS_OK;
}

int32_t ClientIpcDiscoverySuccess(const char *pkgName, int subscribeId)
{
    sptr<DiscClientProxy> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "softbus client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    clientProxy->OnDiscoverySuccess(subscribeId);
    return SOFTBUS_OK;
}

int32_t ClientIpcOnPublishSuccess(const char *pkgName, int publishId)
{
    sptr<DiscClientProxy> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "softbus client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    clientProxy->OnPublishSuccess(publishId);
    return SOFTBUS_OK;
}

int32_t ClientIpcOnPublishFail(const char *pkgName, int publishId, int reason)
{
    sptr<DiscClientProxy> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "softbus client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    clientProxy->OnPublishFail(publishId, reason);
    return SOFTBUS_OK;
}