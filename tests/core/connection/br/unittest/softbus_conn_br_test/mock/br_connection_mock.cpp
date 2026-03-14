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

#include "br_connection_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_brConnectionInterface;
BrConnectionInterfaceMock::BrConnectionInterfaceMock()
{
    g_brConnectionInterface = reinterpret_cast<void *>(this);
}

BrConnectionInterfaceMock::~BrConnectionInterfaceMock()
{
    g_brConnectionInterface = nullptr;
}

static BrConnectionInterface *GetBrConnectionInterface()
{
    return reinterpret_cast<BrConnectionInterface *>(g_brConnectionInterface);
}

int32_t BrConnectionInterfaceMock::ActionOfSoftbusGetConfig1(ConfigType type, unsigned char *val, uint32_t len)
{
    unsigned char val1[4] =  {'B', 'a'};
    if (memcpy_s((void *)val, sizeof(int32_t), val1, sizeof(val1)) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BrConnectionInterfaceMock::ActionOfSoftbusGetConfig2(ConfigType type, unsigned char *val, uint32_t len)
{
    unsigned char val1[4] = {1, 0, 0, 0};
    if (memcpy_s((void *)val, sizeof(int32_t), val1, sizeof(val1)) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

extern "C" {
int32_t SoftBusGetBtMacAddr(SoftBusBtAddr *mac)
{
    return GetBrConnectionInterface()->SoftBusGetBtMacAddr(mac);
}

void LnnDCReportConnectException(const ConnectOption *option, int32_t errorCode)
{
    return GetBrConnectionInterface()->LnnDCReportConnectException(option, errorCode);
}

int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    return GetBrConnectionInterface()->SoftbusGetConfig(type, val, len);
}

SppSocketDriver *InitSppSocketDriver(void)
{
    return GetBrConnectionInterface()->InitSppSocketDriver();
}

int32_t SoftBusAddBtStateListener(const SoftBusBtStateListener *listener, int32_t *listenerId)
{
    return GetBrConnectionInterface()->SoftBusAddBtStateListener(listener, listenerId);
}

uint32_t ConnGetHeadSize(void)
{
    return GetBrConnectionInterface()->ConnGetHeadSize();
}

int32_t ConnBrOnAckRequest(ConnBrConnection *connection, const cJSON *json)
{
    return GetBrConnectionInterface()->ConnBrOnAckRequest(connection, json);
}

int32_t ConnBrOnAckResponse(ConnBrConnection *connection, const cJSON *json)
{
    return GetBrConnectionInterface()->ConnBrOnAckResponse(connection, json);
}

ConnBleConnection *ConnBleGetConnectionByAddr(const char *addr, ConnSideType side, BleProtocolType protocol)
{
    return GetBrConnectionInterface()->ConnBleGetConnectionByAddr(addr, side, protocol);
}

void ConnBleReturnConnection(ConnBleConnection **connection)
{
    return GetBrConnectionInterface()->ConnBleReturnConnection(connection);
}

void LnnDCClearConnectException(const ConnectOption *option)
{
    return GetBrConnectionInterface()->LnnDCClearConnectException(option);
}

int32_t ConnBrEnqueueNonBlock(const void *msg)
{
    return GetBrConnectionInterface()->ConnBrEnqueueNonBlock(msg);
}

int32_t ConnBrDequeueBlock(void **msg)
{
    return GetBrConnectionInterface()->ConnBrDequeueBlock(msg);
}

int32_t ConnBrCreateBrPendingPacket(uint32_t id, int64_t seq)
{
    return GetBrConnectionInterface()->ConnBrCreateBrPendingPacket(id, seq);
}

void ConnBrDelBrPendingPacket(uint32_t id, int64_t seq)
{
    return GetBrConnectionInterface()->ConnBrDelBrPendingPacket(id, seq);
}

void ConnBrDelBrPendingPacketById(uint32_t id)
{
    return GetBrConnectionInterface()->ConnBrDelBrPendingPacketById(id);
}

int32_t ConnBrGetBrPendingPacket(uint32_t id, int64_t seq, uint32_t waitMillis, void **data)
{
    return GetBrConnectionInterface()->ConnBrGetBrPendingPacket(id, seq, waitMillis, data);
}

int32_t ConnBrInnerQueueInit(void)
{
    return GetBrConnectionInterface()->ConnBrInnerQueueInit();
}

void ConnBrInnerQueueDeinit(void)
{
    return GetBrConnectionInterface()->ConnBrInnerQueueDeinit();
}

int32_t ConnBrInitBrPendingPacket(void)
{
    return GetBrConnectionInterface()->ConnBrInitBrPendingPacket();
}

uint32_t ConnGetNewRequestId(ConnModule moduleId)
{
    return GetBrConnectionInterface()->ConnGetNewRequestId(moduleId);
}

int32_t ConnBleKeepAlive(uint32_t connectionId, uint32_t requestId, uint32_t time)
{
    return GetBrConnectionInterface()->ConnBleKeepAlive(connectionId, requestId, time);
}

int32_t ConnBleRemoveKeepAlive(uint32_t connectionId, uint32_t requestId)
{
    return GetBrConnectionInterface()->ConnBleRemoveKeepAlive(connectionId, requestId);
}

int32_t SoftBusThreadCreate(
    SoftBusThread *thread, SoftBusThreadAttr *threadAttr, void *(*threadEntry) (void *), void *arg)
{
    return GetBrConnectionInterface()->SoftBusThreadCreate(thread, threadAttr, threadEntry, arg);
}

int32_t BrHiDumperRegister(void)
{
    return SOFTBUS_OK;
}

struct ConnSlideWindowController *ConnSlideWindowControllerNew(void)
{
    return GetBrConnectionInterface()->ConnSlideWindowControllerNew();
}

void ConnSlideWindowControllerDelete(struct ConnSlideWindowController *self)
{
    GetBrConnectionInterface()->ConnSlideWindowControllerDelete(self);
}

int32_t ConvertBtMacToStr(char *str, uint32_t strLen, const uint8_t *mac, uint32_t macLen)
{
    return GetBrConnectionInterface()->ConvertBtMacToStr(str, strLen, mac, macLen);
}

int32_t ConvertBtMacToBinary(const char *str, uint32_t strLen, uint8_t *mac, uint32_t macLen)
{
    return (int32_t)GetBrConnectionInterface()->ConvertBtMacToBinary(str, strLen, mac, macLen);
}

int32_t ConvertBtMacToU64(const char *str, uint32_t strLen, uint64_t *u64Mac)
{
    return GetBrConnectionInterface()->ConvertBtMacToU64(str, strLen, u64Mac);
}

int32_t ConvertU64MacToStr(uint64_t u64Mac, char *str, uint32_t strLen)
{
    return GetBrConnectionInterface()->ConvertU64MacToStr(u64Mac, str, strLen);
}

void ConvertAnonymizeMacAddress(char *anonymizeAddr, uint32_t anonymizeLen,
    const char *addr, uint32_t addrLen)
{
    GetBrConnectionInterface()->ConvertAnonymizeMacAddress(anonymizeAddr, anonymizeLen, addr, addrLen);
}

int32_t ConnBrTransReadOneFrame(uint32_t connectionId, int32_t socketHandle,
    LimitedBuffer *buffer, uint8_t **outData)
{
    return GetBrConnectionInterface()->ConnBrTransReadOneFrame(connectionId, socketHandle, buffer, outData);
}

int64_t ConnBrPackCtlMessage(BrCtlMessageSerializationContext ctx, uint8_t **data, uint32_t *dataLen)
{
    return GetBrConnectionInterface()->ConnBrPackCtlMessage(ctx, data, dataLen);
}

int32_t ConnBrPostBytes(uint32_t connectionId, uint8_t *data, uint32_t dataLen,
    int32_t pid, int32_t flag, ConnModule module, int64_t seq)
{
    return GetBrConnectionInterface()->ConnBrPostBytes(connectionId, data, dataLen, pid, flag, module, seq);
}

int32_t ConnStartActionAsync(void *ctx, void *(*action)(void *), void (*onClean)(void *))
{
    return GetBrConnectionInterface()->ConnStartActionAsync(ctx, action, onClean);
}

int32_t ConnPostMsgToLooper(SoftBusHandlerWrapper *handler, uint32_t what,
    uint64_t arg1, int64_t arg2, void *obj, uint32_t delayMillis)
{
    return GetBrConnectionInterface()->ConnPostMsgToLooper(handler, what, arg1, arg2, obj, delayMillis);
}

void ConnRemoveMsgFromLooper(SoftBusHandlerWrapper *handler, uint32_t what, uint64_t arg1, void *obj)
{
    GetBrConnectionInterface()->ConnRemoveMsgFromLooper(handler, what, arg1, obj);
}

int32_t ConnNewLimitedBuffer(LimitedBuffer **buffer, int32_t capacity)
{
    return GetBrConnectionInterface()->ConnNewLimitedBuffer(buffer, capacity);
}

void ConnDeleteLimitedBuffer(LimitedBuffer **buffer)
{
    GetBrConnectionInterface()->ConnDeleteLimitedBuffer(buffer);
}

ConnBrConnection *ConnBrGetConnectionById(uint32_t connectionId)
{
    return GetBrConnectionInterface()->ConnBrGetConnectionById(connectionId);
}

ConnBrConnection *ConnBrGetConnectionByAddr(const char *addr, ConnSideType side)
{
    return GetBrConnectionInterface()->ConnBrGetConnectionByAddr(addr, side);
}

void ConnBrReturnConnection(ConnBrConnection **connection)
{
    GetBrConnectionInterface()->ConnBrReturnConnection(connection);
}

int32_t ConnBrSaveConnection(ConnBrConnection *connection)
{
    return GetBrConnectionInterface()->ConnBrSaveConnection(connection);
}

void ConnBrRemoveConnection(ConnBrConnection *connection)
{
    GetBrConnectionInterface()->ConnBrRemoveConnection(connection);
}

int32_t SoftBusMutexLock(SoftBusMutex *mutex)
{
    return GetBrConnectionInterface()->SoftBusMutexLock(mutex);
}

int32_t SoftBusMutexUnlock(SoftBusMutex *mutex)
{
    return GetBrConnectionInterface()->SoftBusMutexUnlock(mutex);
}

int32_t SoftBusMutexInit(SoftBusMutex *mutex, const SoftBusMutexAttr *attr)
{
    return GetBrConnectionInterface()->SoftBusMutexInit(mutex, attr);
}

void SoftBusMutexDestroy(SoftBusMutex *mutex)
{
    GetBrConnectionInterface()->SoftBusMutexDestroy(mutex);
}

void SoftBusSleepMs(uint32_t milliseconds)
{
    GetBrConnectionInterface()->SoftBusSleepMs(milliseconds);
}

SoftBusList *CreateSoftBusList(void)
{
    return GetBrConnectionInterface()->CreateSoftBusList();
}

void DestroySoftBusList(SoftBusList *list)
{
    GetBrConnectionInterface()->DestroySoftBusList(list);
}

SoftBusThread SoftBusThreadGetSelf(void)
{
    return GetBrConnectionInterface()->SoftBusThreadGetSelf();
}

int32_t SoftBusThreadSetName(SoftBusThread thread, const char *name)
{
    return GetBrConnectionInterface()->SoftBusThreadSetName(thread, name);
}
}
}
