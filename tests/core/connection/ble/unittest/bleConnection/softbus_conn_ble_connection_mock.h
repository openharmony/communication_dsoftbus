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

#ifndef SOFTBUS_CONN_BLE_CONNECTION_MOCK_H
#define SOFTBUS_CONN_BLE_CONNECTION_MOCK_H

#include <atomic>
#include <cstddef>
#include <gmock/gmock.h>

#include "bus_center_info_key.h"
#include "softbus_conn_ble_connection_struct.h"
#include "softbus_conn_common.h"

namespace OHOS::SoftBus {
class BleConnectionTestMockInterface {
public:
    BleConnectionTestMockInterface() = default;
    virtual ~BleConnectionTestMockInterface() = default;

    virtual void *SoftBusCallocHook(std::size_t size) = 0;
    virtual void SoftBusFreeHook(void *ptr) = 0;
    virtual int32_t SoftBusMutexInitHook(SoftBusMutex *mutex, void *attr) = 0;
    virtual void SoftBusMutexDestroyHook(SoftBusMutex *mutex) = 0;
    virtual int32_t SoftBusMutexLockHook(SoftBusMutex *mutex) = 0;
    virtual int32_t SoftBusMutexUnlockHook(SoftBusMutex *mutex) = 0;
    virtual SoftBusList *CreateSoftBusListHook(void) = 0;
    virtual void DestroySoftBusListHook(SoftBusList *list) = 0;
    virtual const BleUnifyInterface *ConnBleGetUnifyInterfaceHook(BleProtocolType protocol) = 0;
    virtual int32_t ConnPostMsgToLooperHook(SoftBusHandlerWrapper *wrapper, int32_t what, uint64_t arg1,
        uint64_t arg2, void *obj, uint64_t delayMillis) = 0;
    virtual void ConnRemoveMsgFromLooperHook(const SoftBusHandlerWrapper *wrapper, int32_t what, uint64_t arg1,
        uint64_t arg2, void *obj) = 0;
    virtual int64_t ConnBlePackCtlMessageHook(BleCtlMessageSerializationContext ctx, uint8_t **outData,
        uint32_t *outLen) = 0;
    virtual int32_t ConnBlePostBytesBytesInnerHook(uint32_t connectionId, uint8_t *data, uint32_t len, int32_t pid,
        int32_t flag, int32_t module, int64_t seq, PostBytesFinishAction postBytesFinishAction) = 0;
    virtual int32_t LnnGetLocalStrInfoHook(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t LnnGetLocalNumInfoHook(InfoKey key, int32_t *info) = 0;
    virtual int32_t LnnGetRemoteStrInfoHook(const char *networkId, InfoKey key, char *info, uint32_t len) = 0;
    virtual bool AddStringToJsonObjectHook(cJSON *json, const char * const string, const char * const value) = 0;
    virtual bool AddNumberToJsonObjectHook(cJSON *json, const char * const string, int32_t num) = 0;
    virtual bool GetJsonObjectStringItemHook(const cJSON *json, const char * const string,
        char *target, uint32_t len) = 0;
    virtual bool GetJsonObjectNumberItemHook(const cJSON *json, const char * const string, int32_t *target) = 0;
    virtual bool GetJsonObjectSignedNumberItemHook(const cJSON *json, const char * const string,
        int32_t *target) = 0;
    virtual bool GetJsonObjectNumber16ItemHook(const cJSON *json, const char * const string, uint16_t *target) = 0;
    virtual ConnBleConnection *ConnBleGetConnectionByIdHook(uint32_t connectionId) = 0;
    virtual void ConnBleReturnConnectionHook(ConnBleConnection **connection) = 0;
    virtual bool IsUnknownDevicePackedHook(const char *addr) = 0;
};

class BleConnectionTestMock : public BleConnectionTestMockInterface {
public:
    static BleConnectionTestMock *GetMock()
    {
        return mock.load();
    }

    BleConnectionTestMock();
    ~BleConnectionTestMock() override;

    MOCK_METHOD(void *, SoftBusCallocHook, (std::size_t size), (override));
    MOCK_METHOD(void, SoftBusFreeHook, (void *ptr), (override));
    MOCK_METHOD(int32_t, SoftBusMutexInitHook, (SoftBusMutex *mutex, void *attr), (override));
    MOCK_METHOD(void, SoftBusMutexDestroyHook, (SoftBusMutex *mutex), (override));
    MOCK_METHOD(int32_t, SoftBusMutexLockHook, (SoftBusMutex *mutex), (override));
    MOCK_METHOD(int32_t, SoftBusMutexUnlockHook, (SoftBusMutex *mutex), (override));
    MOCK_METHOD(SoftBusList *, CreateSoftBusListHook, (), (override));
    MOCK_METHOD(void, DestroySoftBusListHook, (SoftBusList *list), (override));
    MOCK_METHOD(const BleUnifyInterface *, ConnBleGetUnifyInterfaceHook, (BleProtocolType protocol), (override));
    MOCK_METHOD(int32_t, ConnPostMsgToLooperHook, (SoftBusHandlerWrapper *wrapper, int32_t what, uint64_t arg1,
        uint64_t arg2, void *obj, uint64_t delayMillis), (override));
    MOCK_METHOD(void, ConnRemoveMsgFromLooperHook, (const SoftBusHandlerWrapper *wrapper, int32_t what, uint64_t arg1,
        uint64_t arg2, void *obj), (override));
    MOCK_METHOD(int64_t, ConnBlePackCtlMessageHook, (BleCtlMessageSerializationContext ctx, uint8_t **outData,
        uint32_t *outLen), (override));
    MOCK_METHOD(int32_t, ConnBlePostBytesBytesInnerHook, (uint32_t connectionId, uint8_t *data,
        uint32_t len, int32_t pid, int32_t flag, int32_t module,
        int64_t seq, PostBytesFinishAction postBytesFinishAction), (override));
    MOCK_METHOD(int32_t, ConnBlePostBytesInnerHook, (uint32_t connectionId, uint8_t *data, uint32_t len, int32_t pid,
        int32_t flag, int32_t module, int64_t seq, PostBytesFinishAction postBytesFinishAction), ());
    MOCK_METHOD(int32_t, LnnGetLocalStrInfoHook, (InfoKey key, char *info, uint32_t len), (override));
    MOCK_METHOD(int32_t, LnnGetLocalNumInfoHook, (InfoKey key, int32_t *info), (override));
    MOCK_METHOD(int32_t, LnnGetRemoteStrInfoHook, (const char *networkId, InfoKey key, char *info,
        uint32_t len), (override));
    MOCK_METHOD(bool, AddStringToJsonObjectHook, (cJSON *json, const char * const string,
        const char * const value), (override));
    MOCK_METHOD(bool, AddNumberToJsonObjectHook, (cJSON *json, const char * const string, int32_t num), (override));
    MOCK_METHOD(bool, GetJsonObjectStringItemHook, (const cJSON *json, const char * const string, char *target,
        uint32_t len), (override));
    MOCK_METHOD(bool, GetJsonObjectNumberItemHook, (const cJSON *json, const char * const string,
        int32_t *target), (override));
    MOCK_METHOD(bool, GetJsonObjectSignedNumberItemHook, (const cJSON *json, const char * const string,
        int32_t *target), (override));
    MOCK_METHOD(bool, GetJsonObjectNumber16ItemHook, (const cJSON *json, const char * const string,
        uint16_t *target), (override));
    MOCK_METHOD(ConnBleConnection *, ConnBleGetConnectionByIdHook, (uint32_t connectionId), (override));
    MOCK_METHOD(void, ConnBleReturnConnectionHook, (ConnBleConnection **connection), (override));
    MOCK_METHOD(bool, IsUnknownDevicePackedHook, (const char *addr), (override));

private:
    static inline std::atomic<BleConnectionTestMock *> mock = nullptr;
};
} // namespace OHOS::SoftBus

#endif // SOFTBUS_CONN_BLE_CONNECTION_TEST_MOCK_H
