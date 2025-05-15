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

#include "softbus_error_code.h"

int32_t ClientIpcOnConnectionStateChange(
    const char *pkgName, int32_t pid, uint32_t handle, int32_t state, int32_t reason)
{
    (void)pkgName;
    (void)pid;
    (void)handle;
    (void)state;
    (void)reason;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ClientIpcOnAcceptConnect(const char *pkgName, int32_t pid, const char *name, uint32_t handle)
{
    (void)pkgName;
    (void)pid;
    (void)name;
    (void)handle;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t ClientIpcOnDataReceived(const char *pkgName, int32_t pid, uint32_t handle, const uint8_t *data, uint32_t len)
{
    (void)pkgName;
    (void)pid;
    (void)handle;
    (void)data;
    (void)len;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}
