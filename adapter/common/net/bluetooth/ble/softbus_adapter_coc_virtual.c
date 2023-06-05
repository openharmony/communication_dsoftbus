/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "softbus_adapter_coc.h"
#include "softbus_errcode.h"

static int32_t OpenCocServer(CocPsm *cocPsm)
{
    (void)cocPsm;
    return SOFTBUS_OK;
}

static void CloseCocServer(int32_t serverFd)
{
    (void)serverFd;
}

static int32_t CreateCocClient(void)
{
    return SOFTBUS_OK;
}

static void DestroyCocClient(int32_t clientFd)
{
    (void)clientFd;
}

static int32_t Connect(int32_t clientFd, const BT_ADDR mac, int32_t psm)
{
    (void)clientFd;
    (void)mac;
    (void)psm;
    return SOFTBUS_OK;
}

static bool CancelConnect(int32_t clientFd)
{
    (void)clientFd;
    return true;
}

static int32_t DisConnect(int32_t fd)
{
    (void)fd;
    return SOFTBUS_OK;
}

static bool IsConnected(int32_t fd)
{
    (void)fd;
    return true;
}

static int32_t Accept(int32_t serverFd)
{
    (void)serverFd;
    return SOFTBUS_OK;
}

static int32_t Write(int32_t fd, const uint8_t *buf, const int32_t length)
{
    (void)fd;
    (void)buf;
    (void)length;
    return SOFTBUS_OK;
}

static int32_t Read(int32_t fd, uint8_t *buf, const int32_t length)
{
    (void)fd;
    (void)buf;
    (void)length;
    return SOFTBUS_OK;
}

static bool EnableFastCocConnection(int32_t clientFd)
{
    (void)clientFd;
    return true;
}

static bool SetCocPreferredPhy(int32_t clientFd, int32_t txPhy, int32_t rxPhy, int32_t phyOptions)
{
    (void)clientFd;
    (void)txPhy;
    (void)rxPhy;
    (void)phyOptions;
    return true;
}

static bool UpdateCocConnectionParams(int32_t clientFd, int32_t priority)
{
    (void)clientFd;
    (void)priority;
    return true;
}

static int32_t GetRemoteDeviceInfo(int32_t fd, BluetoothRemoteDevice *device)
{
    (void)fd;
    (void)device;
    return SOFTBUS_OK;
}

CocSocketDriver *InitCocSocketDriver()
{
    static CocSocketDriver g_cocSocketDriver = {
        .OpenCocServer = OpenCocServer,
        .CloseCocServer = CloseCocServer,
        .CreateCocClient = CreateCocClient,
        .DestroyCocClient = DestroyCocClient,
        .Connect = Connect,
        .CancelConnect = CancelConnect,
        .DisConnect = DisConnect,
        .IsConnected = IsConnected,
        .Accept = Accept,
        .Write = Write,
        .Read = Read,
        .EnableFastCocConnection = EnableFastCocConnection,
        .SetCocPreferredPhy = SetCocPreferredPhy,
        .UpdateCocConnectionParams = UpdateCocConnectionParams,
        .GetRemoteDeviceInfo = GetRemoteDeviceInfo,
    };
    return &g_cocSocketDriver;
}