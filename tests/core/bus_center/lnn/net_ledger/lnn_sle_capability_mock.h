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

#ifndef LNN_SLE_CAPABILITY_MOCK_H
#define LNN_SLE_CAPABILITY_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "bus_center_manager.h"
#include "g_enhance_adapter_func_pack.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_distributed_net_ledger_struct.h"
#include "lnn_local_net_ledger.h"
#include "lnn_sync_info_manager.h"
#include "softbus_json_utils.h"

namespace OHOS {
class LnnSleCapabilityInterface {
public:
    LnnSleCapabilityInterface() {};
    virtual ~LnnSleCapabilityInterface() {};

    virtual int32_t GetSleRangeCapacityPacked(void) = 0;
    virtual int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info) = 0;
    virtual int32_t LnnUpdateSleCapacityAndVersion(int32_t slecap) = 0;
    virtual bool IsSleEnabledPacked(void) = 0;
    virtual int32_t GetLocalSleAddrPacked(char *sleAddr, uint32_t sleAddrLen) = 0;
    virtual int32_t LnnSetLocalStrInfo(InfoKey key, const char *info) = 0;
    virtual bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num) = 0;
    virtual bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value) = 0;
    virtual cJSON *cJSON_CreateObject() = 0;
    virtual int32_t LnnRegSyncInfoHandler(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler) = 0;
    virtual int32_t SoftBusAddSleStateListenerPacked(const SoftBusSleStateListener *listener, int32_t *listenerId) = 0;
    virtual int32_t LnnSetDLSleRangeInfo(const char *id, IdCategory type, int32_t sleCap, const char *addr) = 0;
};
class LnnSleCapabilityInterfaceMock : public LnnSleCapabilityInterface {
public:
    LnnSleCapabilityInterfaceMock();
    ~LnnSleCapabilityInterfaceMock() override;
    MOCK_METHOD0(GetSleRangeCapacityPacked, int32_t());
    MOCK_METHOD2(LnnGetLocalNumInfo, int32_t(InfoKey key, int32_t *info));
    MOCK_METHOD1(LnnUpdateSleCapacityAndVersion, int32_t(int32_t slecap));
    MOCK_METHOD0(IsSleEnabledPacked, bool());
    MOCK_METHOD2(GetLocalSleAddrPacked, int32_t(char *sleAddr, uint32_t sleAddrLen));
    MOCK_METHOD2(LnnSetLocalStrInfo, int32_t(InfoKey key, const char *info));
    MOCK_METHOD3(AddNumberToJsonObject, bool(cJSON *json, const char * const string, int32_t num));
    MOCK_METHOD3(AddStringToJsonObject, bool(cJSON *json, const char * const string, const char *value));
    MOCK_METHOD0(cJSON_CreateObject, cJSON *());
    MOCK_METHOD2(LnnRegSyncInfoHandler, int32_t(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler));
    MOCK_METHOD2(
        SoftBusAddSleStateListenerPacked, int32_t(const SoftBusSleStateListener *listener, int32_t *listenerId));
    MOCK_METHOD4(LnnSetDLSleRangeInfo, int32_t(const char *id, IdCategory type, int32_t sleCap, const char *addr));
};
} // namespace OHOS
#endif // LNN_SLE_CAPABILITY_MOCK_H
