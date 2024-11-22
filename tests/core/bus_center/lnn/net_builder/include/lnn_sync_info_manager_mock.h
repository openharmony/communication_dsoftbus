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

#ifndef LNN_SYNC_INFO_MANAGER_MOCK_H
#define LNN_SYNC_INFO_MANAGER_MOCK_H

#include <gmock/gmock.h>

#include "auth_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "softbus_adapter_json.h"

namespace OHOS {
class LnnSyncInfoManagerInterface {
public:
    virtual JsonObj *JSON_CreateObject() = 0;
    virtual bool JSON_AddInt64ToObject(JsonObj *obj, const char *key, int64_t value) = 0;
    virtual bool JSON_AddInt32ToObject(JsonObj *obj, const char *key, int32_t value) = 0;
    virtual void JSON_Delete(JsonObj *obj) = 0;
    virtual char *JSON_PrintUnformatted(const JsonObj *obj) = 0;
    virtual JsonObj *JSON_Parse(const char *str, uint32_t len) = 0;
    virtual bool JSON_GetInt64FromOject(const JsonObj *obj, const char *key, int64_t *value) = 0;
    virtual int32_t ConvertBytesToHexString(
        char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen);
    virtual bool JSON_GetInt32FromOject(const JsonObj *obj, const char *key, int32_t *value) = 0;
    virtual bool JSON_GetStringFromOject(const JsonObj *obj, const char *key, char *value, uint32_t size) = 0;
    virtual AuthManager *GetAuthManagerByAuthId(int64_t authId) = 0;
    virtual void DelAuthManager(AuthManager *auth, int32_t type) = 0;
    virtual int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len);
    virtual int32_t AuthPostTransData(AuthHandle authHandle, const AuthTransData *dataInfo) = 0;
    virtual int32_t LnnGetRemoteNumU64Info(const char *networkId, InfoKey key, uint64_t *info) = 0;
    virtual int32_t LnnGetRemoteNumU32Info(const char *netWorkId, InfoKey key, uint32_t *info) = 0;
    virtual int32_t GetHmlOrP2pAuthHandle(AuthHandle **authHandle, int32_t *num) = 0;
    virtual bool JSON_AddStringToObject(JsonObj *obj, const char *key, const char *value) = 0;
};

class LnnSyncInfoManagerInterfaceMock : public LnnSyncInfoManagerInterface {
public:
    LnnSyncInfoManagerInterfaceMock();
    ~LnnSyncInfoManagerInterfaceMock();
    MOCK_METHOD0(JSON_CreateObject, JsonObj *());
    MOCK_METHOD3(JSON_AddInt64ToObject, bool(JsonObj *obj, const char *key, int64_t value));
    MOCK_METHOD3(JSON_AddInt32ToObject, bool(JsonObj *obj, const char *key, int32_t value));
    MOCK_METHOD1(JSON_Delete, void(JsonObj *obj));
    MOCK_METHOD1(JSON_PrintUnformatted, char *(const JsonObj *obj));
    MOCK_METHOD2(JSON_Parse, JsonObj *(const char *str, uint32_t len));
    MOCK_METHOD3(JSON_GetInt64FromOject, bool(const JsonObj *obj, const char *key, int64_t *value));
    MOCK_METHOD4(ConvertBytesToHexString,
        int32_t(char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen));
    MOCK_METHOD3(JSON_GetInt32FromOject, bool(const JsonObj *obj, const char *key, int32_t *value));
    MOCK_METHOD4(JSON_GetStringFromOject, bool(const JsonObj *obj, const char *key, char *value, uint32_t size));
    MOCK_METHOD1(GetAuthManagerByAuthId, AuthManager *(int64_t authId));
    MOCK_METHOD2(DelAuthManager, void(AuthManager *auth, int32_t type));
    MOCK_METHOD3(LnnGetNetworkIdByUdid, int32_t(const char *, char *, uint32_t));
    MOCK_METHOD2(AuthPostTransData, int32_t(AuthHandle authHandle, const AuthTransData *dataInfo));
    MOCK_METHOD3(LnnGetRemoteNumU64Info, int32_t(const char *networkId, InfoKey key, uint64_t *info));
    MOCK_METHOD3(LnnGetRemoteNumU32Info, int32_t(const char *, InfoKey, uint32_t *));
    MOCK_METHOD2(GetHmlOrP2pAuthHandle, int32_t(AuthHandle **authHandle, int32_t *num));
    MOCK_METHOD3(JSON_AddStringToObject, bool(JsonObj *obj, const char *key, const char *value));
};
} // namespace OHOS

#endif