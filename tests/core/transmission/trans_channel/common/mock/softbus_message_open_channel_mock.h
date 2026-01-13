/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#ifndef SOFT_MESSAGE_OPEN_CHANNEL_MOCK_H
#define SOFT_MESSAGE_OPEN_CHANNEL_MOCK_H

#include <gmock/gmock.h>
#include "bus_center_info_key_struct.h"
#include "softbus_adapter_crypto.h"
#include "softbus_message_open_channel.h"

namespace OHOS {
class SoftbusMessageOpenChannelInterface {
public:
    SoftbusMessageOpenChannelInterface() {};
    virtual ~SoftbusMessageOpenChannelInterface() {};

    virtual cJSON *cJSON_CreateObject() = 0;
    virtual char *cJSON_PrintUnformatted(const cJSON *json) = 0;
    virtual bool AddNumber16ToJsonObject(cJSON *json, const char *const string, uint16_t num) = 0;
    virtual bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value) = 0;
    virtual bool AddNumberToJsonObject(cJSON *json, const char *const string, int32_t num) = 0;
    virtual int32_t SoftBusBase64Encode(unsigned char *dst, size_t dlen,
        size_t *olen, const unsigned char *src, size_t slen) = 0;
    virtual bool GetJsonObjectNumberItem(const cJSON *json, const char * const string, int32_t *target) = 0;
    virtual bool GetJsonObjectStringItem(
        const cJSON *json, const char * const string, char *target, uint32_t targetLen) = 0;
    virtual bool GetJsonObjectNumber64Item(const cJSON *json, const char * const string, int64_t *target) = 0;
    virtual bool GetJsonObjectInt32Item(const cJSON *json, const char * const string, int32_t *target) = 0;
    virtual bool GetJsonObjectNumber16Item(const cJSON *json, const char * const string, uint16_t *target) = 0;
    virtual int32_t SoftBusBase64Decode(unsigned char *dst, size_t dlen,
        size_t *olen, const unsigned char *src, size_t slen) = 0;
    virtual int32_t LnnGetRemoteNumInfo(const char *networkId, InfoKey key, int32_t *info) = 0;
    virtual int32_t SoftBusEncryptData(AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
        unsigned char *encryptData, uint32_t *encryptLen) = 0;
    virtual int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len) = 0;
    virtual void GetOsTypeByNetworkId(const char *networkId, int32_t *osType) = 0;
    virtual bool GetJsonObjectBoolItem(const cJSON *json, const char * const string, bool *target);
};

class SoftbusMessageOpenChannelInterfaceMock : public SoftbusMessageOpenChannelInterface {
public:
    SoftbusMessageOpenChannelInterfaceMock();
    ~SoftbusMessageOpenChannelInterfaceMock() override;

    MOCK_METHOD0(cJSON_CreateObject, cJSON * ());
    MOCK_METHOD1(cJSON_PrintUnformatted, char *(const cJSON *));
    MOCK_METHOD3(AddNumber16ToJsonObject, bool(cJSON *, const char * const, uint16_t));
    MOCK_METHOD3(AddStringToJsonObject, bool(cJSON *, const char * const, const char *));
    MOCK_METHOD3(AddNumberToJsonObject, bool(cJSON *, const char * const, int32_t));
    MOCK_METHOD5(SoftBusBase64Encode, int32_t (unsigned char *, size_t, size_t *, const unsigned char *, size_t));
    MOCK_METHOD3(GetJsonObjectNumberItem, bool(const cJSON *, const char * const, int32_t *));
    MOCK_METHOD4(
        GetJsonObjectStringItem, bool(const cJSON *, const char * const, char *, uint32_t));
    MOCK_METHOD3(GetJsonObjectNumber64Item, bool(const cJSON *, const char * const, int64_t *));
    MOCK_METHOD3(GetJsonObjectInt32Item, bool(const cJSON *, const char * const, int32_t *));
    MOCK_METHOD3(GetJsonObjectNumber16Item, bool(const cJSON *, const char * const, uint16_t *));
    MOCK_METHOD5(SoftBusBase64Decode, int32_t (unsigned char *, size_t, size_t *, const unsigned char *, size_t));
    MOCK_METHOD3(LnnGetRemoteNumInfo, int32_t (const char *networkId, InfoKey key, int32_t *info));
    MOCK_METHOD5(SoftBusEncryptData, int32_t (AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
        unsigned char *encryptData, uint32_t *encryptLen));
    MOCK_METHOD3(LnnGetNetworkIdByUuid, int32_t (const char *uuid, char *buf, uint32_t len));
    MOCK_METHOD2(GetOsTypeByNetworkId, void (const char *networkId, int32_t *osType));
    MOCK_METHOD3(GetJsonObjectBoolItem, bool (const cJSON *json, const char * const string, bool *target));
};
extern "C" {
    void cJSON_Delete(cJSON *json);
}
} // namespace OHOS
#endif // SOFT_MESSAGE_OPEN_CHANNEL_MOCK_H
