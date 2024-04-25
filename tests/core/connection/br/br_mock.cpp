/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "br_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_connectionBrInterface;
ConnectionBrInterfaceMock::ConnectionBrInterfaceMock()
{
    g_connectionBrInterface = reinterpret_cast<void *>(this);
}

ConnectionBrInterfaceMock::~ConnectionBrInterfaceMock()
{
    g_connectionBrInterface = nullptr;
}

static ConnectionBrInterface *GetConnectionBrInterface()
{
    return reinterpret_cast<ConnectionBrInterface *>(g_connectionBrInterface);
}

int32_t ConnectionBrInterfaceMock::ActionOfSoftbusGetConfig1(ConfigType type, unsigned char *val, uint32_t len)
{
    unsigned char val1[4] =  {'B', 'a'};
    if (memcpy_s((void *)val, sizeof(int32_t), val1, sizeof(val1)) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ConnectionBrInterfaceMock::ActionOfSoftbusGetConfig2(ConfigType type, unsigned char *val, uint32_t len)
{
    unsigned char val1[4] = {1, 0, 0, 0};
    if (memcpy_s((void *)val, sizeof(int32_t), val1, sizeof(val1)) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

extern "C" {
int SoftBusGetBtMacAddr(SoftBusBtAddr *mac)
{
    return GetConnectionBrInterface()->SoftBusGetBtMacAddr(mac);
}

void LnnDCReportConnectException(const ConnectOption *option, int32_t errorCode)
{
    return GetConnectionBrInterface()->LnnDCReportConnectException(option, errorCode);
}

int SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    return GetConnectionBrInterface()->SoftbusGetConfig(type, val, len);
}

SppSocketDriver *InitSppSocketDriver()
{
    return GetConnectionBrInterface()->InitSppSocketDriver();
}

int SoftBusAddBtStateListener(const SoftBusBtStateListener *listener)
{
    return GetConnectionBrInterface()->SoftBusAddBtStateListener(listener);
}

uint32_t ConnGetHeadSize(void)
{
    return GetConnectionBrInterface()->ConnGetHeadSize();
}

int32_t ConnBrOnAckRequest(ConnBrConnection *connection, const cJSON *json)
{
    return GetConnectionBrInterface()->ConnBrOnAckRequest(connection, json);
}

int32_t ConnBrOnAckResponse(ConnBrConnection *connection, const cJSON *json)
{
    return GetConnectionBrInterface()->ConnBrOnAckResponse(connection, json);
}

ConnBleConnection *ConnBleGetConnectionByAddr(const char *addr, ConnSideType side, BleProtocolType protocol)
{
    return GetConnectionBrInterface()->ConnBleGetConnectionByAddr(addr, side, protocol);
}

void ConnBleReturnConnection(ConnBleConnection **connection)
{
    return GetConnectionBrInterface()->ConnBleReturnConnection(connection);
}

void LnnDCClearConnectException(const ConnectOption *option)
{
    return GetConnectionBrInterface()->LnnDCClearConnectException(option);
}

int32_t ConnBrEnqueueNonBlock(const void *msg)
{
    return GetConnectionBrInterface()->ConnBrEnqueueNonBlock(msg);
}

int32_t ConnBrDequeueBlock(void **msg)
{
    return GetConnectionBrInterface()->ConnBrDequeueBlock(msg);
}

int32_t ConnBrCreateBrPendingPacket(uint32_t id, int64_t seq)
{
    return GetConnectionBrInterface()->ConnBrCreateBrPendingPacket(id, seq);
}

void ConnBrDelBrPendingPacket(uint32_t id, int64_t seq)
{
    return GetConnectionBrInterface()->ConnBrDelBrPendingPacket(id, seq);
}

int32_t ConnBrGetBrPendingPacket(uint32_t id, int64_t seq, uint32_t waitMillis, void **data)
{
    return GetConnectionBrInterface()->ConnBrGetBrPendingPacket(id, seq, waitMillis, data);
}

int32_t ConnBrInnerQueueInit(void)
{
    return GetConnectionBrInterface()->ConnBrInnerQueueInit();
}

int32_t ConnBrInitBrPendingPacket(void)
{
    return GetConnectionBrInterface()->ConnBrInitBrPendingPacket();
}

uint32_t ConnGetNewRequestId(ConnModule moduleId)
{
    return GetConnectionBrInterface()->ConnGetNewRequestId(moduleId);
}

int32_t ConnBleKeepAlive(uint32_t connectionId, uint32_t requestId, uint32_t time)
{
    return GetConnectionBrInterface()->ConnBleKeepAlive(connectionId, requestId, time);
}

int32_t ConnBleRemoveKeepAlive(uint32_t connectionId, uint32_t requestId)
{
    return GetConnectionBrInterface()->ConnBleRemoveKeepAlive(connectionId, requestId);
}

int32_t SoftBusThreadCreate(
    SoftBusThread *thread, SoftBusThreadAttr *threadAttr, void *(*threadEntry) (void *), void *arg)
{
    return GetConnectionBrInterface()->SoftBusThreadCreate(thread, threadAttr, threadEntry, arg);
}
}
}
