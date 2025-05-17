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

#include "general_connection_server_proxy.h"
#include "softbus_error_code.h"

int32_t ConnectionServerProxyInit(void)
{
    return SOFTBUS_OK;
}

void ConnectionServerProxyDeInit(void)
{
    return;
}

int32_t ServerIpcCreateServer(const char *pkgName, const char *name)
{
    (void)pkgName;
    (void)name;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ServerIpcRemoveServer(const char *pkgName, const char *name)
{
    (void)pkgName;
    (void)name;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ServerIpcConnect(const char *pkgName, const char *name, const Address *address)
{
    (void)pkgName;
    (void)name;
    (void)address;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ServerIpcDisconnect(uint32_t handle)
{
    (void)handle;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ServerIpcSend(uint32_t handle, const uint8_t *data, uint32_t len)
{
    (void)handle;
    (void)data;
    (void)len;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ServerIpcGetPeerDeviceId(uint32_t handle, char *deviceId, uint32_t len)
{
    (void)handle;
    (void)deviceId;
    (void)len;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}