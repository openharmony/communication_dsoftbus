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

#ifndef BR_CONNECTION_MOCK_H
#define BR_CONNECTION_MOCK_H

#include "softbus_conn_br_connection.h"
#include "softbus_conn_br_manager.h"
#include "softbus_conn_br_trans.h"

#include <gmock/gmock.h>
#include "cJSON.h"

#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_thread.h"
#include "softbus_config_type.h"
#include "softbus_def.h"

#include "softbus_conn_ble_connection.h"
#include "softbus_conn_common.h"
#include "softbus_conn_flow_control.h"

#define DEFAULT_BR_MTU 990

namespace OHOS {
class BrConnectionInterface {
public:
    BrConnectionInterface() {};
    virtual ~BrConnectionInterface() {};
    virtual int32_t SoftBusGetBtMacAddr(SoftBusBtAddr *mac) = 0;
    virtual void LnnDCReportConnectException(const ConnectOption *option, int32_t errorCode) = 0;
    virtual int32_t SoftBusThreadCreate(
        SoftBusThread *thread, SoftBusThreadAttr *threadAttr, void *(*threadEntry) (void *), void *arg) = 0;
    virtual int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len) = 0;
    virtual SppSocketDriver *InitSppSocketDriver(void) = 0;
    virtual int32_t SoftBusAddBtStateListener(const SoftBusBtStateListener *listener, int32_t *listenerId) = 0;
    virtual uint32_t ConnGetHeadSize(void) = 0;
    virtual int32_t ConnBrOnAckRequest(ConnBrConnection *connection, const cJSON *json) = 0;
    virtual int32_t ConnBrOnAckResponse(ConnBrConnection *connection, const cJSON *json) = 0;
    virtual ConnBleConnection *ConnBleGetConnectionByAddr(
        const char *addr, ConnSideType side, BleProtocolType protocol) = 0;
    virtual void ConnBleReturnConnection(ConnBleConnection **connection) = 0;
    virtual void LnnDCClearConnectException(const ConnectOption *option) = 0;
    virtual int32_t ConnBrEnqueueNonBlock(const void *msg) = 0;
    virtual int32_t ConnBrDequeueBlock(void **msg) = 0;
    virtual int32_t ConnBrCreateBrPendingPacket(uint32_t id, int64_t seq) = 0;
    virtual void ConnBrDelBrPendingPacket(uint32_t id, int64_t seq) = 0;
    virtual void ConnBrDelBrPendingPacketById(uint32_t id) = 0;
    virtual int32_t ConnBrGetBrPendingPacket(uint32_t id, int64_t seq, uint32_t waitMillis, void **data) = 0;
    virtual int32_t ConnBrInnerQueueInit(void) = 0;
    virtual void ConnBrInnerQueueDeinit(void) = 0;
    virtual int32_t ConnBrInitBrPendingPacket(void) = 0;
    virtual uint32_t ConnGetNewRequestId(ConnModule moduleId) = 0;
    virtual int32_t ConnBleKeepAlive(uint32_t connectionId, uint32_t requestId, uint32_t time) = 0;
    virtual int32_t ConnBleRemoveKeepAlive(uint32_t connectionId, uint32_t requestId) = 0;
    virtual int32_t BrHiDumperRegister(void) = 0;
    virtual struct ConnSlideWindowController *ConnSlideWindowControllerNew(void) = 0;
    virtual void ConnSlideWindowControllerDelete(struct ConnSlideWindowController *self) = 0;
    virtual int32_t ConvertBtMacToStr(char *str, uint32_t strLen, const uint8_t *mac, uint32_t macLen) = 0;
    virtual int32_t ConvertBtMacToBinary(const char *str, uint32_t strLen, uint8_t *mac, uint32_t macLen) = 0;
    virtual int32_t ConvertBtMacToU64(const char *str, uint32_t strLen, uint64_t *u64Mac) = 0;
    virtual int32_t ConvertU64MacToStr(uint64_t u64Mac, char *str, uint32_t strLen) = 0;
    virtual void ConvertAnonymizeMacAddress(char *anonymizeAddr, uint32_t anonymizeLen,
        const char *addr, uint32_t addrLen) = 0;
    virtual int32_t ConnBrTransReadOneFrame(uint32_t connectionId, int32_t socketHandle,
        LimitedBuffer *buffer, uint8_t **outData) = 0;
    virtual int64_t ConnBrPackCtlMessage(BrCtlMessageSerializationContext ctx, uint8_t **data, uint32_t *dataLen) = 0;
    virtual int32_t ConnBrPostBytes(uint32_t connectionId, uint8_t *data, uint32_t dataLen,
        int32_t pid, int32_t flag, ConnModule module, int64_t seq) = 0;
    virtual int32_t ConnStartActionAsync(void *ctx, void *(*action)(void *), void (*onClean)(void *)) = 0;
    virtual int32_t ConnPostMsgToLooper(SoftBusHandlerWrapper *handler, uint32_t what,
        uint64_t arg1, int64_t arg2, void *obj, uint32_t delayMillis) = 0;
    virtual void ConnRemoveMsgFromLooper(SoftBusHandlerWrapper *handler, uint32_t what, uint64_t arg1, void *obj) = 0;
    virtual int32_t ConnNewLimitedBuffer(LimitedBuffer **buffer, int32_t capacity) = 0;
    virtual void ConnDeleteLimitedBuffer(LimitedBuffer **buffer) = 0;
    virtual ConnBrConnection *ConnBrGetConnectionById(uint32_t connectionId) = 0;
    virtual ConnBrConnection *ConnBrGetConnectionByAddr(const char *addr, ConnSideType side) = 0;
    virtual void ConnBrReturnConnection(ConnBrConnection **connection) = 0;
    virtual int32_t ConnBrSaveConnection(ConnBrConnection *connection) = 0;
    virtual void ConnBrRemoveConnection(ConnBrConnection *connection) = 0;
    virtual int32_t SoftBusMutexLock(SoftBusMutex *mutex) = 0;
    virtual int32_t SoftBusMutexUnlock(SoftBusMutex *mutex) = 0;
    virtual int32_t SoftBusMutexInit(SoftBusMutex *mutex, const SoftBusMutexAttr *attr) = 0;
    virtual void SoftBusMutexDestroy(SoftBusMutex *mutex) = 0;
    virtual void SoftBusSleepMs(uint32_t milliseconds) = 0;
    virtual SoftBusList *CreateSoftBusList(void) = 0;
    virtual void DestroySoftBusList(SoftBusList *list) = 0;
    virtual SoftBusThread SoftBusThreadGetSelf(void) = 0;
    virtual int32_t SoftBusThreadSetName(SoftBusThread thread, const char *name) = 0;
    virtual int32_t SppDriverUpdatePriority(uint8_t *binaryAddr, int32_t priority) = 0;
    virtual int32_t SppDriverConnect(const char *uuid, uint8_t *binaryAddr,
        BtSocketConnectionCallback *callback) = 0;
    virtual void SppDriverDisConnect(int32_t socketHandle) = 0;
    virtual int32_t SppDriverGetRemoteDeviceInfo(int32_t socketHandle, BluetoothRemoteDevice *remote) = 0;
    virtual int32_t SppDriverOpenSppServer(const char *name, int32_t nameLen, const char *uuid, int32_t security) = 0;
    virtual void SppDriverCloseSppServer(int32_t serverId) = 0;
    virtual int32_t SppDriverAccept(int32_t serverId) = 0;
};

class BrConnectionInterfaceMock : public BrConnectionInterface {
public:
    BrConnectionInterfaceMock();
    ~BrConnectionInterfaceMock() override;
    MOCK_METHOD1(SoftBusGetBtMacAddr, int32_t (SoftBusBtAddr *));
    MOCK_METHOD2(LnnDCReportConnectException, void(const ConnectOption*, int32_t));
    MOCK_METHOD4(SoftBusThreadCreate, int32_t(SoftBusThread *, SoftBusThreadAttr *, void *(void *), void *));
    MOCK_METHOD3(SoftbusGetConfig, int(ConfigType, unsigned char *, uint32_t));
    MOCK_METHOD0(InitSppSocketDriver, SppSocketDriver*());
    MOCK_METHOD2(SoftBusAddBtStateListener, int(const SoftBusBtStateListener *, int32_t *));
    MOCK_METHOD0(ConnGetHeadSize, uint32_t());
    MOCK_METHOD2(ConnBrOnAckRequest, int32_t(ConnBrConnection *, const cJSON *));
    MOCK_METHOD2(ConnBrOnAckResponse, int32_t(ConnBrConnection *, const cJSON *));
    MOCK_METHOD3(ConnBleGetConnectionByAddr, ConnBleConnection *(const char *, ConnSideType, BleProtocolType));
    MOCK_METHOD1(ConnBleReturnConnection, void(ConnBleConnection **));
    MOCK_METHOD1(LnnDCClearConnectException, void(const ConnectOption *));
    MOCK_METHOD1(ConnBrEnqueueNonBlock, int32_t(const void *));
    MOCK_METHOD1(ConnBrDequeueBlock, int32_t(void **));
    MOCK_METHOD2(ConnBrCreateBrPendingPacket, int32_t(uint32_t, int64_t));
    MOCK_METHOD2(ConnBrDelBrPendingPacket, void(uint32_t, int64_t));
    MOCK_METHOD1(ConnBrDelBrPendingPacketById, void(uint32_t));
    MOCK_METHOD4(ConnBrGetBrPendingPacket, int32_t(uint32_t, int64_t, uint32_t, void **));
    MOCK_METHOD0(ConnBrInnerQueueInit, int32_t());
    MOCK_METHOD0(ConnBrInnerQueueDeinit, void());
    MOCK_METHOD0(ConnBrInitBrPendingPacket, int32_t());
    MOCK_METHOD1(ConnGetNewRequestId, uint32_t(ConnModule));
    MOCK_METHOD3(ConnBleKeepAlive, int32_t(uint32_t, uint32_t, uint32_t));
    MOCK_METHOD2(ConnBleRemoveKeepAlive, int32_t(uint32_t, uint32_t));
    MOCK_METHOD(int32_t, BrHiDumperRegister, (), (override));
    MOCK_METHOD0(ConnSlideWindowControllerNew, struct ConnSlideWindowController *());
    MOCK_METHOD1(ConnSlideWindowControllerDelete, void(struct ConnSlideWindowController *));
    MOCK_METHOD4(ConvertBtMacToStr, int32_t(char *, uint32_t, const uint8_t *, uint32_t));
    MOCK_METHOD4(ConvertBtMacToBinary, int32_t(const char *, uint32_t, uint8_t *, uint32_t));
    MOCK_METHOD3(ConvertBtMacToU64, int32_t(const char *, uint32_t, uint64_t *));
    MOCK_METHOD3(ConvertU64MacToStr, int32_t(uint64_t, char *, uint32_t));
    MOCK_METHOD4(ConvertAnonymizeMacAddress, void(char *, uint32_t, const char *, uint32_t));
    MOCK_METHOD4(ConnBrTransReadOneFrame, int32_t(uint32_t, int32_t, LimitedBuffer *, uint8_t **));
    MOCK_METHOD3(ConnBrPackCtlMessage, int64_t(BrCtlMessageSerializationContext, uint8_t **, uint32_t *));
    MOCK_METHOD7(ConnBrPostBytes, int32_t(uint32_t, uint8_t *, uint32_t, int32_t, int32_t, ConnModule, int64_t));
    MOCK_METHOD3(ConnStartActionAsync, int32_t(void *, void *(*)(void *), void (*)(void *)));
    MOCK_METHOD5(ConnPostMsgToLooper, int32_t(SoftBusHandlerWrapper *, uint32_t, uint64_t, int64_t, void *, uint32_t));
    MOCK_METHOD3(ConnRemoveMsgFromLooper, void(SoftBusHandlerWrapper *, uint32_t, uint64_t, void *));
    MOCK_METHOD2(ConnNewLimitedBuffer, int32_t(LimitedBuffer **, int32_t));
    MOCK_METHOD1(ConnDeleteLimitedBuffer, void(LimitedBuffer **));
    MOCK_METHOD1(ConnBrGetConnectionById, ConnBrConnection *(uint32_t));
    MOCK_METHOD2(ConnBrGetConnectionByAddr, ConnBrConnection *(const char *, ConnSideType));
    MOCK_METHOD1(ConnBrReturnConnection, void(ConnBrConnection **));
    MOCK_METHOD1(ConnBrSaveConnection, int32_t(ConnBrConnection *));
    MOCK_METHOD1(ConnBrRemoveConnection, void(ConnBrConnection *));
    MOCK_METHOD1(SoftBusMutexLock, int32_t(SoftBusMutex *));
    MOCK_METHOD1(SoftBusMutexUnlock, int32_t(SoftBusMutex *));
    MOCK_METHOD2(SoftBusMutexInit, int32_t(SoftBusMutex *, const SoftBusMutexAttr *));
    MOCK_METHOD1(SoftBusMutexDestroy, void(SoftBusMutex *));
    MOCK_METHOD1(SoftBusSleepMs, void(uint32_t));
    MOCK_METHOD0(CreateSoftBusList, SoftBusList *());
    MOCK_METHOD1(DestroySoftBusList, void(SoftBusList *));
    MOCK_METHOD0(SoftBusThreadGetSelf, SoftBusThread());
    MOCK_METHOD1(SoftBusThreadSetName, int32_t(SoftBusThread, const char *));
    MOCK_METHOD2(SppDriverUpdatePriority, int32_t(uint8_t *, int32_t));
    MOCK_METHOD3(SppDriverConnect, int32_t(const char *, uint8_t *, BtSocketConnectionCallback *));
    MOCK_METHOD1(SppDriverDisConnect, void(int32_t));
    MOCK_METHOD2(SppDriverGetRemoteDeviceInfo, int32_t(int32_t, BluetoothRemoteDevice *));
    MOCK_METHOD4(SppDriverOpenSppServer, int32_t(const char *, int32_t, const char *, int32_t));
    MOCK_METHOD1(SppDriverCloseSppServer, void(int32_t));
    MOCK_METHOD1(SppDriverAccept, int32_t(int32_t));

    static int32_t ActionOfSoftbusGetConfig1(ConfigType type, unsigned char *val, uint32_t len);
    static int32_t ActionOfSoftbusGetConfig2(ConfigType type, unsigned char *val, uint32_t len);
};
} 
#endif 
