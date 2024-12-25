/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "lnn_connection_mock.h"

#include "lnn_log.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_connInterface;
static const int32_t TEST_DATA_LEN = 200;
LnnConnectInterfaceMock::LnnConnectInterfaceMock()
{
    g_connInterface = reinterpret_cast<void *>(this);
}

LnnConnectInterfaceMock::~LnnConnectInterfaceMock()
{
    g_connInterface = nullptr;
}

static LnnConnectInterface *GetConnInterface()
{
    return reinterpret_cast<LnnConnectInterfaceMock *>(g_connInterface);
}

extern "C" {
int32_t ConnGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info)
{
    return GetConnInterface()->ConnGetConnectionInfo(connectionId, info);
}

int32_t ConnSetConnectCallback(ConnModule moduleId, const ConnectCallback *callback)
{
    return GetConnInterface()->ConnSetConnectCallback(moduleId, callback);
}

void ConnUnSetConnectCallback(ConnModule moduleId)
{
    GetConnInterface()->ConnUnSetConnectCallback(moduleId);
}

int32_t ConnConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    return GetConnInterface()->ConnConnectDevice(option, requestId, result);
}

int32_t ConnDisconnectDevice(uint32_t connectionId)
{
    return GetConnInterface()->ConnDisconnectDevice(connectionId);
}

uint32_t ConnGetHeadSize(void)
{
    return GetConnInterface()->ConnGetHeadSize();
}

int32_t ConnPostBytes(uint32_t connectionId, ConnPostData *data)
{
    return GetConnInterface()->ConnPostBytes(connectionId, data);
}

bool CheckActiveConnection(const ConnectOption *option, bool needOccupy)
{
    return GetConnInterface()->CheckActiveConnection(option, needOccupy);
}

int32_t ConnStartLocalListening(const LocalListenerInfo *info)
{
    return GetConnInterface()->ConnStartLocalListening(info);
}

int32_t ConnStopLocalListening(const LocalListenerInfo *info)
{
    return GetConnInterface()->ConnStopLocalListening(info);
}

uint32_t ConnGetNewRequestId(ConnModule moduleId)
{
    return GetConnInterface()->ConnGetNewRequestId(moduleId);
}
void DiscDeviceInfoChanged(InfoTypeChanged type)
{
    return GetConnInterface()->DiscDeviceInfoChanged(type);
}

int32_t ConnUpdateConnection(uint32_t connectionId, UpdateOption *option)
{
    return GetConnInterface()->ConnUpdateConnection(connectionId, option);
}
}

int32_t LnnConnectInterfaceMock::ActionofConnSetConnectCallback(ConnModule moduleId, const ConnectCallback *callback)
{
    (void)moduleId;
    if (callback == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    g_conncallback.OnDataReceived = callback->OnDataReceived;
    g_conncallback.OnConnected = callback->OnConnected;
    g_conncallback.OnDisconnected = callback->OnDisconnected;
    return SOFTBUS_OK;
}

int32_t LnnConnectInterfaceMock::ActionofOnConnectSuccessed(
    const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    (void)option;
    uint32_t connectionId = 196619;
    const ConnectionInfo info = {
        .isAvailable = 1,
        .isServer = 1,
        .type = CONNECT_BR,
        .brInfo.brMac = "11:22:33:44:55:66",
    };
    result->OnConnectSuccessed(requestId, connectionId, &info);
    LNN_LOGI(LNN_TEST, "ActionofConnConnectDevice");
    return SOFTBUS_OK;
}

int32_t LnnConnectInterfaceMock::LnnConnectInterfaceMock::ActionofOnConnectFailed(
    const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    int32_t reason = 0;
    result->OnConnectFailed(requestId, reason);
    LNN_LOGI(LNN_TEST, "ActionofOnConnectFailed");
    return SOFTBUS_OK;
}

int32_t LnnConnectInterfaceMock::ActionofConnGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info)
{
    (void)connectionId;
    info->type = CONNECT_BLE;
    info->isServer = SERVER_SIDE_FLAG;
    info->isAvailable = 1;
    strcpy_s(info->brInfo.brMac, sizeof(info->brInfo.brMac), "11:22:33:44:55:66");
    return SOFTBUS_OK;
}

void LnnConnectInterfaceMock::ActionofConnUnSetConnectCallback(ConnModule moduleId)
{
    (void)moduleId;
}

int32_t LnnConnectInterfaceMock::ActionOfConnPostBytes(uint32_t connectionId, ConnPostData *data)
{
    LNN_LOGI(LNN_TEST, "ActionOfConnPostBytes");
    g_encryptData = data->buf;
    if (strcpy_s(g_encryptData, TEST_DATA_LEN, data->buf) != SOFTBUS_OK) {
        LNN_LOGE(LNN_TEST, "strcpy failed in conn post bytes");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}
} // namespace OHOS