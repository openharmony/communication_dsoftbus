/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "general_connection_client_proxy.h"

#include <unistd.h>

#include "conn_log.h"
#include "general_connection_client_proxy_standard.h"
#include "softbus_client_info_manager.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

using namespace OHOS;

static sptr<ConnectionClientProxy> GetClientProxy(const char *pkgName, int32_t pid)
{
    sptr<IRemoteObject> clientObject = SoftbusClientInfoManager::GetInstance().GetSoftbusClientProxy(pkgName, pid);
    sptr<ConnectionClientProxy> clientProxy = new (std::nothrow) ConnectionClientProxy(clientObject);
    if (clientProxy == nullptr) {
        CONN_LOGE(CONN_COMMON, "failed to create ConnectionClientProxy");
        return nullptr;
    }
    return clientProxy;
}

int32_t ClientIpcOnConnectionStateChange(
    const char *pkgName, int32_t pid, uint32_t handle, int32_t state, int32_t reason)
{
    if (pkgName == nullptr) {
        CONN_LOGE(CONN_COMMON, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<ConnectionClientProxy> clientProxy = GetClientProxy(pkgName, pid);
    if (clientProxy == nullptr) {
        CONN_LOGE(CONN_COMMON, "softbus client proxy is nullptr!");
        return SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL;
    }

    return clientProxy->OnConnectionStateChange(handle, state, reason);
}

int32_t ClientIpcOnAcceptConnect(const char *pkgName, int32_t pid, const char *name, uint32_t handle)
{
    if (pkgName == nullptr || name == nullptr) {
        CONN_LOGE(CONN_COMMON, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<ConnectionClientProxy> clientProxy = GetClientProxy(pkgName, pid);
    if (clientProxy == nullptr) {
        CONN_LOGE(CONN_COMMON, "softbus client proxy is nullptr!");
        return SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL;
    }

    return clientProxy->OnAcceptConnect(name, handle);
}

int32_t ClientIpcOnDataReceived(const char *pkgName, int32_t pid, uint32_t handle, const uint8_t *data, uint32_t len)
{
    if (pkgName == nullptr || data == nullptr) {
        CONN_LOGE(CONN_COMMON, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    sptr<ConnectionClientProxy> clientProxy = GetClientProxy(pkgName, pid);
    if (clientProxy == nullptr) {
        CONN_LOGE(CONN_COMMON, "softbus client proxy is nullptr!");
        return SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL;
    }

    return clientProxy->OnDataReceived(handle, data, len);
}
