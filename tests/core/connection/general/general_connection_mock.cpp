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

#include "general_connection_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_connectionGeneralInterface;
static ConnectCallback g_connectCallback = {0};
static ConnectResult g_connectResult = {0};

GeneralConnectionInterfaceMock::GeneralConnectionInterfaceMock()
{
    g_connectionGeneralInterface = reinterpret_cast<void *>(this);
}

GeneralConnectionInterfaceMock::~GeneralConnectionInterfaceMock()
{
    g_connectionGeneralInterface = nullptr;
}

ConnectCallback *GeneralConnectionInterfaceMock::GetConnectCallbackMock()
{
    return &g_connectCallback;
}

ConnectResult *GeneralConnectionInterfaceMock::GetConnectResultMock()
{
    return &g_connectResult;
}

static GeneralConnectionInterface *GetGeneralConnectionInterface()
{
    return reinterpret_cast<GeneralConnectionInterface *>(g_connectionGeneralInterface);
}

extern "C" {
void ConnBleCancelIdleTimeout(ConnBleConnection *connection)
{
    (void)connection;
    return;
}

void ConnBleReturnConnection(ConnBleConnection **connection)
{
    (void)connection;
    return;
}

int32_t ClientIpcOnConnectionStateChange(
    const char *pkgName, int32_t pid, uint32_t handle, int32_t state, int32_t reason)
{
    (void)pkgName;
    (void)pid;
    (void)handle;
    (void)state;
    (void)reason;
    return SOFTBUS_OK;
}

int32_t ClientIpcOnAcceptConnect(const char *pkgName, int32_t pid, const char *name, uint32_t handle)
{
    (void)pkgName;
    (void)pid;
    (void)name;
    (void)handle;
    return SOFTBUS_OK;
}

int32_t ClientIpcOnDataReceived(const char *pkgName, int32_t pid, uint32_t handle, const uint8_t *data, uint32_t len)
{
    (void)pkgName;
    (void)pid;
    (void)handle;
    (void)data;
    (void)len;
    return SOFTBUS_OK;
}

ConnBleConnection *ConnBleGetConnectionById(uint32_t connectionId)
{
    static ConnBleConnection connection = {
        .featureBitSet = 0,
        .protocol = BLE_COC,
    };

    (void)memcpy_s(connection.networkId, UDID_BUF_LEN, "testNetworkId", UDID_BUF_LEN);
    (void)memcpy_s(connection.udid, UDID_BUF_LEN, "testnetUdid", UDID_BUF_LEN);
    const char *addr = "11:22:33:44:55:66";
    (void)memcpy_s(connection.addr, BT_MAC_LEN, addr, BT_MAC_LEN);
    return &connection;
}

ConnectFuncInterface *ConnInitTcp(const ConnectCallback *callback)
{
    (void)callback;
    return NULL;
}

ConnectFuncInterface *ConnInitBr(const ConnectCallback *callback)
{
    (void)callback;
    return NULL;
}

ConnectFuncInterface *ConnSleInit(const ConnectCallback *callback)
{
    (void)callback;
    return NULL;
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetGeneralConnectionInterface()->LnnGetLocalStrInfo(key, info, len);
}

int32_t BleConnectDeviceMock(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    g_connectResult = *result;
    return GetGeneralConnectionInterface()->BleConnectDeviceMock(option, requestId, result);
}

int32_t ConnBlePostBytesMock(
    uint32_t connectionId, uint8_t *data, uint32_t dataLen, int32_t pid, int32_t flag, int32_t module, int64_t seq)
{
    return GetGeneralConnectionInterface()->ConnBlePostBytesMock(connectionId, data, dataLen, pid, flag, module, seq);
}

ConnectFuncInterface *ConnInitBle(const ConnectCallback *callback)
{
    static ConnectFuncInterface bleFuncInterface = {
        .ConnectDevice = BleConnectDeviceMock,
        .PostBytes = ConnBlePostBytesMock,
    };
    g_connectCallback= *callback;
    return &bleFuncInterface;
}
}
}