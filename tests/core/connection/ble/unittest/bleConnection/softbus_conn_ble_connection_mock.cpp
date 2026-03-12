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

#include "softbus_conn_ble_connection_mock.h"

#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_conn_ble_manager.h"
#include "softbus_conn_ble_trans.h"
#include "bus_center_manager.h"
#include "softbus_json_utils.h"
#include "ble_protocol_interface_factory.h"
#include "softbus_utils.h"
#include <cstdlib>
#include <cstring>

#undef SoftBusMutexLock
#undef SoftBusMutexUnlock

namespace OHOS::SoftBus {
BleConnectionTestMock::BleConnectionTestMock()
{
    mock.store(this);
}

BleConnectionTestMock::~BleConnectionTestMock()
{
    mock.store(nullptr);
}
}

extern "C" {
void *SoftBusCalloc(uint32_t size)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        return calloc(1, size);
    }
    return mock->SoftBusCallocHook(size);
}

void SoftBusFree(void *ptr)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        free(ptr);
        return;
    }
    mock->SoftBusFreeHook(ptr);
}

int32_t SoftBusMutexInit(SoftBusMutex *mutex, SoftBusMutexAttr *mutexAttr)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        return pthread_mutex_init((pthread_mutex_t *)mutex,
            (pthread_mutexattr_t *)mutexAttr) == 0 ? SOFTBUS_OK : SOFTBUS_ERR;
    }
    return mock->SoftBusMutexInitHook(mutex, mutexAttr);
}

int32_t SoftBusMutexDestroy(SoftBusMutex *mutex)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        pthread_mutex_destroy((pthread_mutex_t *)mutex);
        return SOFTBUS_ERR;
    }
    mock->SoftBusMutexDestroyHook(mutex);
    return SOFTBUS_OK;
}

int32_t SoftBusMutexLock(SoftBusMutex *mutex)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        return pthread_mutex_lock((pthread_mutex_t *)mutex) == 0 ? SOFTBUS_OK : SOFTBUS_ERR;
    }
    return mock->SoftBusMutexLockHook(mutex);
}

int32_t SoftBusMutexUnlock(SoftBusMutex *mutex)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        return pthread_mutex_unlock((pthread_mutex_t *)mutex) == 0 ? SOFTBUS_OK : SOFTBUS_ERR;
    }
    return mock->SoftBusMutexUnlockHook(mutex);
}

SoftBusList *CreateSoftBusList(void)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        SoftBusList *list = (SoftBusList *)malloc(sizeof(SoftBusList));
        if (list != nullptr) {
            ListInit(&list->list);
            SoftBusMutexInit(&list->lock, nullptr);
        }
        return list;
    }
    return mock->CreateSoftBusListHook();
}

void DestroySoftBusList(SoftBusList *list)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        if (list != nullptr) {
            SoftBusMutexDestroy(&list->lock);
            free(list);
        }
        return;
    }
    mock->DestroySoftBusListHook(list);
}

const BleUnifyInterface *ConnBleGetUnifyInterface(BleProtocolType protocol)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        return nullptr;
    }
    return mock->ConnBleGetUnifyInterfaceHook(protocol);
}

int32_t ConnPostMsgToLooper(
    SoftBusHandlerWrapper *wrapper, int32_t what, uint64_t arg1, uint64_t arg2, void *obj, uint64_t delayMillis)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        return SOFTBUS_OK;
    }
    return mock->ConnPostMsgToLooperHook(wrapper, what, arg1, arg2, obj, delayMillis);
}

void ConnRemoveMsgFromLooper(
    const SoftBusHandlerWrapper *wrapper, int32_t what, uint64_t arg1, uint64_t arg2, void *obj)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        return;
    }
    mock->ConnRemoveMsgFromLooperHook(wrapper, what, arg1, arg2, obj);
}

int64_t ConnBlePackCtlMessage(BleCtlMessageSerializationContext ctx, uint8_t **outData,
    uint32_t *outLen)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        return SOFTBUS_OK;
    }
    return mock->ConnBlePackCtlMessageHook(ctx, outData, outLen);
}

int32_t ConnBlePostBytesInner(uint32_t connectionId, uint8_t *data, uint32_t len, int32_t pid,
    int32_t flag, int32_t module, int64_t seq, PostBytesFinishAction postBytesFinishAction)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        return SOFTBUS_OK;
    }
    return mock->ConnBlePostBytesInnerHook(connectionId,
        data, len, pid, flag, module, seq, postBytesFinishAction);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        return SOFTBUS_ERR;
    }
    return mock->LnnGetLocalStrInfoHook(key, info, len);
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        return SOFTBUS_ERR;
    }
    return mock->LnnGetLocalNumInfoHook(key, info);
}

int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        return SOFTBUS_ERR;
    }
    return mock->LnnGetRemoteStrInfoHook(networkId, key, info, len);
}

bool AddStringToJsonObject(cJSON *json, const char * const string, const char * const value)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        return cJSON_AddStringToObject(json, string, value) != nullptr;
    }
    return mock->AddStringToJsonObjectHook(json, string, value);
}

bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        return cJSON_AddNumberToObject(json, string, num) != nullptr;
    }
    return mock->AddNumberToJsonObjectHook(json, string, num);
}

bool GetJsonObjectStringItem(const cJSON *json, const char * const string, char *target, uint32_t len)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        cJSON *item = cJSON_GetObjectItem(json, string);
        if (item == nullptr || !cJSON_IsString(item)) {
            return false;
        }
        const char *value = cJSON_GetStringValue(item);
        if (value == nullptr) {
            return false;
        }
        if (strcpy_s(target, len, value) != EOK) {
            return false;
        }
        return true;
    }
    return mock->GetJsonObjectStringItemHook(json, string, target, len);
}

bool GetJsonObjectNumberItem(const cJSON *json, const char * const string, int32_t *target)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        cJSON *item = cJSON_GetObjectItem(json, string);
        if (item == nullptr || !cJSON_IsNumber(item)) {
            return false;
        }
        *target = (int32_t)cJSON_GetNumberValue(item);
        return true;
    }
    return mock->GetJsonObjectNumberItemHook(json, string, target);
}

bool GetJsonObjectSignedNumberItem(const cJSON *json, const char * const string, int32_t *target)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        cJSON *item = cJSON_GetObjectItem(json, string);
        if (item == nullptr || !cJSON_IsNumber(item)) {
            return false;
        }
        *target = (int32_t)cJSON_GetNumberValue(item);
        return true;
    }
    return mock->GetJsonObjectSignedNumberItemHook(json, string, target);
}

bool GetJsonObjectNumber16Item(const cJSON *json, const char * const string, uint16_t *target)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        cJSON *item = cJSON_GetObjectItem(json, string);
        if (item == nullptr || !cJSON_IsNumber(item)) {
            return false;
        }
        *target = (uint16_t)cJSON_GetNumberValue(item);
        return true;
    }
    return mock->GetJsonObjectNumber16ItemHook(json, string, target);
}

ConnBleConnection *ConnBleGetConnectionById(uint32_t connectionId)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        return nullptr;
    }
    return mock->ConnBleGetConnectionByIdHook(connectionId);
}

void ConnBleReturnConnection(ConnBleConnection **connection)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        return;
    }
    mock->ConnBleReturnConnectionHook(connection);
}

bool IsUnknownDevicePacked(const char *addr)
{
    auto mock = OHOS::SoftBus::BleConnectionTestMock::GetMock();
    if (mock == nullptr) {
        return false;
    }
    return mock->IsUnknownDevicePackedHook(addr);
}
}