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

#ifndef BUS_CENTER_MANAGER_MOCK_CPP
#define BUS_CENTER_MANAGER_MOCK_CPP

#include <atomic>
#include <string>
#include <gmock/gmock.h>
#include "bus_center_manager.h"
#include "lnn_device_info.h"
#include "lnn_devicename_info.h"
#include "lnn_ohos_account.h"
#include "lnn_huks_utils.h"

class BusCenterInterface {
public:
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t LnnSetLocalDeviceName(const char *displayName) = 0;
    virtual int32_t LnnConvertDeviceTypeToId(const char *deviceType, uint16_t *typeId) = 0;
    virtual int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len) = 0;
    virtual bool LnnIsDefaultOhosAccount() = 0;
    virtual int32_t LnnEncryptDataByHuks(const struct HksBlob *keyAlias,
        const struct HksBlob *inData, struct HksBlob *outData) = 0;
    virtual int32_t LnnDecryptDataByHuks(const struct HksBlob *keyAlias,
        const struct HksBlob *inData, struct HksBlob *outData) = 0;
    virtual int32_t LnnGenerateRandomByHuks(uint8_t *randomKey, uint32_t len) = 0;
};

class BusCenterMock : public BusCenterInterface {
public:
    static BusCenterMock* GetMock()
    {
        return mock.load();
    }

    BusCenterMock();
    ~BusCenterMock();

    MOCK_METHOD(int32_t, LnnGetLocalStrInfo, (InfoKey key, char *info, uint32_t len), (override));
    MOCK_METHOD(int32_t, LnnSetLocalDeviceName, (const char *displayName), (override));
    MOCK_METHOD(int32_t, LnnConvertDeviceTypeToId, (const char *deviceType, uint16_t *typeId), (override));
    MOCK_METHOD(int32_t, LnnGetLocalByteInfo, (InfoKey key, uint8_t *info, uint32_t len), (override));
    MOCK_METHOD(bool, LnnIsDefaultOhosAccount, (), (override));
    MOCK_METHOD(int32_t, LnnEncryptDataByHuks, (const struct HksBlob *keyAlias,
        const struct HksBlob *inData, struct HksBlob *outData), (override));
    MOCK_METHOD(int32_t, LnnDecryptDataByHuks, (const struct HksBlob *keyAlias,
        const struct HksBlob *inData, struct HksBlob *outData), (override));
    MOCK_METHOD(int32_t, LnnGenerateRandomByHuks, (uint8_t *randomKey, uint32_t len), (override));
    void SetupSuccessStub();

    static int32_t ActionOfLnnGetLocalStrInfo(InfoKey key, char *out, uint32_t outSize);
    static int32_t ActionOfLnnConvertDeviceTypeToId(const char *deviceType, uint16_t *typeId);
    static int32_t ActionOfLnnGetLocalByteInfo(InfoKey key, uint8_t *out, uint32_t outSize);
    static bool ActionOfLnnIsDefaultOhosAccount();

    static inline std::string deviceName = "My Device";
    static inline std::string deviceUDID = "012345670123456701234567012345670123456701234567012345670123456701234567";
    static inline uint8_t accountHash[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };

private:
    static inline std::atomic<BusCenterMock*> mock = nullptr;
};
#endif