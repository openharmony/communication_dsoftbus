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

#ifndef NSTACKX_ADAPTER_MOCK_H
#define NSTACKX_ADAPTER_MOCK_H

#include <atomic>
#include <gmock/gmock.h>
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "nstackx.h"

class AdapterInterface {
public:
    virtual int32_t NSTACKX_Init(const NSTACKX_Parameter *parameter) = 0;
    virtual int32_t NSTACKX_RegisterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[]) = 0;
    virtual int32_t NSTACKX_SetFilterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[]) = 0;
    virtual int32_t NSTACKX_SendDiscoveryRsp(const NSTACKX_ResponseSettings *responseSettings) = 0;
    virtual int32_t LnnGetLocalStrInfoByIfnameIdx(InfoKey key, char *info, uint32_t len, int32_t ifIdx) = 0;
};

class AdapterMock : public AdapterInterface {
public:
    static AdapterMock* GetMock()
    {
        return mock.load();
    }

    AdapterMock();
    ~AdapterMock();

    static void InjectDeviceFoundEvent(const NSTACKX_DeviceInfo *deviceInfo, uint32_t deviceCount);

    MOCK_METHOD(int32_t, NSTACKX_Init, (const NSTACKX_Parameter *parameter), (override));
    MOCK_METHOD(int32_t, NSTACKX_RegisterCapability,
        (uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[]), (override));
    MOCK_METHOD(int32_t, NSTACKX_SetFilterCapability,
        (uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[]), (override));
    MOCK_METHOD(int32_t, NSTACKX_SendDiscoveryRsp, (const NSTACKX_ResponseSettings *responseSettings), (override));
    MOCK_METHOD(int32_t, LnnGetLocalStrInfoByIfnameIdx,
        (InfoKey key, char *info, uint32_t len, int32_t ifIdx), (override));

    static int32_t ActionOfNstackInit(const NSTACKX_Parameter *parameter);
    static int32_t ActionOfLnnGetLocalStrInfoByIfnameIdx(InfoKey key, char *info, uint32_t len, int32_t ifIdx);

private:
    static inline std::atomic<AdapterMock*> mock = nullptr;
    static inline NSTACKX_Parameter deviceFoundCallback_;
};

#endif