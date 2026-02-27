/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "general_client_connection.h"

int32_t GeneralRegisterListener(IGeneralListener *listener)
{
    (void)listener;
    return SOFTBUS_OK;
}

int32_t GeneralUnregisterListener(void)
{
    return SOFTBUS_OK;
}

int32_t GeneralCreateServer(const char *pkgName, const char *name)
{
    (void)pkgName;
    (void)name;
    return SOFTBUS_OK;
}

int32_t GeneralRemoveServer(const char *pkgName, const char *name)
{
    (void)pkgName;
    (void)name;
    return SOFTBUS_OK;
}

int32_t GeneralConnect(const char *pkgName, const char *name, const Address *address)
{
    (void)pkgName;
    (void)name;
    (void)address;
    return SOFTBUS_OK;
}

int32_t GeneralDisconnect(uint32_t handle)
{
    (void)handle;
    return SOFTBUS_OK;
}

int32_t GeneralSend(uint32_t handle, const uint8_t *data, uint32_t len)
{
    (void)handle;
    (void)data;
    (void)len;
    return SOFTBUS_OK;
}

int32_t GeneralGetPeerDeviceId(uint32_t handle, char *deviceId, uint32_t len)
{
    (void)handle;
    (void)deviceId;
    (void)len;
    return SOFTBUS_OK;
}

int32_t ConnectionStateChange(uint32_t handle, int32_t state, int32_t reason)
{
    (void)handle;
    (void)state;
    (void)reason;
    return SOFTBUS_OK;
}

int32_t AcceptConnect(const char *name, uint32_t handle)
{
    (void)name;
    (void)handle;
    return SOFTBUS_OK;
}

void DataReceived(uint32_t handle, const uint8_t *data, uint32_t len)
{
    (void)handle;
    (void)data;
    (void)len;
}

void ConnectionDeathNotify(void)
{
    // empty
}