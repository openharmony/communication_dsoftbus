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
#include "disc_log.h"
#include "softbus_client_info_manager.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

using namespace OHOS;

static sptr<DiscClientProxy> GetClientProxy(const char *pkgName)
{
    sptr<IRemoteObject> clientObject = SoftbusClientInfoManager::GetInstance().GetSoftbusClientProxy(pkgName);
    sptr<DiscClientProxy> clientProxy = new (std::nothrow) DiscClientProxy(clientObject);
    return clientProxy;
}

int32_t ClientIpcOnDeviceFound(const char *pkgName, const DeviceInfo *device,
    const InnerDeviceInfoAddtions *additions)
{
    sptr<DiscClientProxy> clientProxy = GetClientProxy(pkgName);
    DISC_CHECK_AND_RETURN_RET_LOGE(clientProxy != nullptr, SOFTBUS_ERR, DISC_CONTROL, "client proxy is nullptr");

    clientProxy->OnDeviceFound(device);
    return SOFTBUS_OK;
}

int32_t ClientIpcOnDiscoverFailed(const char *pkgName, int subscribeId, int failReason)
{
    sptr<DiscClientProxy> clientProxy = GetClientProxy(pkgName);
    DISC_CHECK_AND_RETURN_RET_LOGE(clientProxy != nullptr, SOFTBUS_ERR, DISC_CONTROL, "client proxy is nullptr");

    clientProxy->OnDiscoverFailed(subscribeId, failReason);
    return SOFTBUS_OK;
}

int32_t ClientIpcDiscoverySuccess(const char *pkgName, int subscribeId)
{
    sptr<DiscClientProxy> clientProxy = GetClientProxy(pkgName);
    DISC_CHECK_AND_RETURN_RET_LOGE(clientProxy != nullptr, SOFTBUS_ERR, DISC_CONTROL, "client proxy is nullptr");

    clientProxy->OnDiscoverySuccess(subscribeId);
    return SOFTBUS_OK;
}

int32_t ClientIpcOnPublishSuccess(const char *pkgName, int publishId)
{
    sptr<DiscClientProxy> clientProxy = GetClientProxy(pkgName);
    DISC_CHECK_AND_RETURN_RET_LOGE(clientProxy != nullptr, SOFTBUS_ERR, DISC_CONTROL, "client proxy is nullptr");

    clientProxy->OnPublishSuccess(publishId);
    return SOFTBUS_OK;
}

int32_t ClientIpcOnPublishFail(const char *pkgName, int publishId, int reason)
{
    sptr<DiscClientProxy> clientProxy = GetClientProxy(pkgName);
    DISC_CHECK_AND_RETURN_RET_LOGE(clientProxy != nullptr, SOFTBUS_ERR, DISC_CONTROL, "client proxy is nullptr");

    clientProxy->OnPublishFail(publishId, reason);
    return SOFTBUS_OK;
}