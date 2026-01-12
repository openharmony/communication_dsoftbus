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

#include "softbus_conn_general_connection.h"

static int32_t RegisterListener(const GeneralConnectionListener *listener)
{
    (void)listener;
    return SOFTBUS_OK;
}

static int32_t Connect(const GeneralConnectionParam *param, const char *addr)
{
    (void)param;
    (void)addr;
    return SOFTBUS_OK;
}

static int32_t Send(uint32_t generalHandle, const uint8_t *data, uint32_t dataLen, int32_t pid)
{
    (void)generalHandle;
    (void)data;
    (void)dataLen;
    (void)pid;
    return SOFTBUS_OK;
}

static void Disconnect(uint32_t generalHandle, int32_t pid)
{
    (void)generalHandle;
    (void)pid;
}

static int32_t GetPeerDeviceId(uint32_t generalHandle, char *addr, uint32_t length, uint32_t tokenId, int32_t pid)
{
    (void)generalHandle;
    (void)addr;
    (void)length;
    (void)tokenId;
    (void)pid;
    return SOFTBUS_OK;
}

static int32_t CreateServer(const GeneralConnectionParam *param)
{
    (void)param;
    return SOFTBUS_OK;
}

static void CloseServer(const GeneralConnectionParam *param)
{
    (void)param;
}

static void ClearAllGeneralConnection(const char *pkgName, int32_t pid)
{
    (void)pkgName;
    (void)pid;
}

static GeneralConnectionManager g_manager = {
    .registerListener = RegisterListener,
    .createServer = CreateServer,
    .closeServer = CloseServer,
    .connect = Connect,
    .send = Send,
    .disconnect = Disconnect,
    .getPeerDeviceId = GetPeerDeviceId,
    .cleanupGeneralConnection = ClearAllGeneralConnection,
};

GeneralConnectionManager *GetGeneralConnectionManager(void)
{
    return &g_manager;
}

int32_t InitGeneralConnectionManager(void)
{
    return SOFTBUS_OK;
}