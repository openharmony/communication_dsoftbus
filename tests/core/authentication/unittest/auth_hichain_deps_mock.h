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

#ifndef AUTH_HICHAIN_DEPS_MOCK_H
#define AUTH_HICHAIN_DEPS_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "softbus_adapter_json.h"
#include "auth_common.h"
#include "auth_identity_service_adapter.h"
#include "auth_hichain_adapter.h"
#include "auth_session_fsm.h"
#include "bus_center_manager.h"
#include "lnn_async_callback_utils.h"
#include "lnn_connection_fsm.h"
#include "lnn_event.h"
#include "lnn_net_builder.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_timer.h"
#include "softbus_json_utils.h"
#include "softbus_utils.h"

namespace OHOS {
class AuthHichainInterface {
public:
    AuthHichainInterface() {};
    virtual ~AuthHichainInterface() {};

    virtual cJSON *cJSON_CreateObject() = 0;
    virtual bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value) = 0;
    virtual bool AddBoolToJsonObject(cJSON *json, const char * const string, bool value) = 0;
    virtual bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num) = 0;
    virtual char *cJSON_PrintUnformatted(const cJSON *json) = 0;
    virtual int32_t AuthSessionPostAuthData(int64_t authSeq, const uint8_t *data, uint32_t len) = 0;
    virtual void LnnEventExtraInit(LnnEventExtra *extra) = 0;
    virtual void GetLnnTriggerInfo(LnnTriggerInfo *triggerInfo) = 0;
    virtual uint64_t SoftBusGetSysTimeMs(void) = 0;
    virtual AuthFsm *GetAuthFsmByAuthSeq(int64_t authSeq) = 0;
    virtual void ReleaseAuthLock(void) = 0;
    virtual int32_t AuthSessionSaveSessionKey(int64_t authSeq, const uint8_t *key, uint32_t len) = 0;
    virtual int32_t AuthSessionHandleAuthFinish(int64_t authSeq, AclWriteState aclState) = 0;
    virtual const char *GetAuthSideStr(bool isServer) = 0;
    virtual int32_t AuthFailNotifyProofInfo(int32_t errCode, const char *errorReturn, uint32_t errorReturnLen) = 0;
    virtual int32_t LnnAsyncCallbackDelayHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback,
        void *para, uint64_t delayMillis) = 0;
    virtual int32_t AuthSessionHandleAuthError(int64_t authSeq, int32_t reason) = 0;
    virtual int32_t AuthSessionGetUdid(int64_t authSeq, char *udid, uint32_t size) = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash) = 0;
    virtual int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen,
        const unsigned char *inBuf, uint32_t inLen) = 0;
    virtual int32_t GetNodeFromPcRestrictMap(const char *udidHash, uint32_t *count) = 0;
    virtual void DeleteNodeFromPcRestrictMap(const char *udidHash) = 0;
    virtual bool GetJsonObjectStringItem(
        const cJSON *json, const char * const string, char *target, uint32_t targetLen) = 0;
    virtual bool GetJsonObjectNumberItem(const cJSON *json, const char * const string, int32_t *target) = 0;
    virtual int32_t RegChangeListener(const char *appId, DataChangeListener *listener) = 0;
    virtual bool RequireAuthLock(void) = 0;
    virtual int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len) = 0;
    virtual bool JSON_AddStringToObject(JsonObj *obj, const char *key, const char *value) = 0;
    virtual bool JSON_GetStringFromObject(const JsonObj *obj, const char *key, char *value, uint32_t size) = 0;
    virtual int32_t LnnGetLocalNodeInfoSafe(NodeInfo *info) = 0;
    virtual bool LnnIsDefaultOhosAccount(void) = 0;
    virtual int32_t IdServiceQueryCredential(int32_t userId, const char *udidHash, const char *accountidHash,
        bool isSameAccount, char **credList) = 0;
    virtual int32_t AuthIdServiceQueryCredential(int32_t peerUserId, const char *udidHash, const char *accountidHash,
        bool isSameAccount, char **credList) = 0;
    virtual char *IdServiceGetCredIdFromCredList(int32_t userId, const char *credList) = 0;
    virtual char *AuthSessionGetCredId(int64_t authSeq) = 0;
    virtual char *IdServiceGenerateAuthParam(HiChainAuthParam *hiChainParam) = 0;
    virtual int32_t IdServiceAuthCredential(int32_t userId, int64_t authReqId, const char *authParams,
        const DeviceAuthCallback *cb) = 0;
    virtual int32_t IdServiceProcessCredData(int64_t authSeq, const uint8_t *data, uint32_t len,
        DeviceAuthCallback *cb) = 0;
    virtual void IdServiceDestroyCredentialList(char **returnData) = 0;
    virtual int32_t GetActiveOsAccountIds(void) = 0;
    virtual bool IsSKIdInvalid(int32_t sessionKeyId, const char *accountHash, const char *udidShortHash,
        int32_t userId) = 0;
    virtual int32_t IdServiceGetCredTypeByCredId(int32_t userId, const char *credId, int32_t *credType) = 0;
};

class AuthHichainInterfaceMock : public AuthHichainInterface {
public:
    AuthHichainInterfaceMock();
    ~AuthHichainInterfaceMock() override;

    MOCK_METHOD0(cJSON_CreateObject, cJSON * ());
    MOCK_METHOD3(AddStringToJsonObject, bool (cJSON *, const char * const, const char *));
    MOCK_METHOD3(AddBoolToJsonObject, bool (cJSON *, const char * const, bool));
    MOCK_METHOD3(AddNumberToJsonObject, bool (cJSON *, const char * const, int32_t));
    MOCK_METHOD1(cJSON_PrintUnformatted, char *(const cJSON *));
    MOCK_METHOD3(AuthSessionPostAuthData, int32_t (int64_t, const uint8_t *, uint32_t));
    MOCK_METHOD1(LnnEventExtraInit, void (LnnEventExtra *));
    MOCK_METHOD1(GetLnnTriggerInfo, void (LnnTriggerInfo *));
    MOCK_METHOD0(SoftBusGetSysTimeMs, uint64_t (void));
    MOCK_METHOD1(GetAuthFsmByAuthSeq, AuthFsm *(int64_t));
    MOCK_METHOD0(ReleaseAuthLock, void (void));
    MOCK_METHOD3(AuthSessionSaveSessionKey, int32_t (int64_t, const uint8_t *, uint32_t));
    MOCK_METHOD2(AuthSessionHandleAuthFinish, int32_t (int64_t, AclWriteState));
    MOCK_METHOD1(GetAuthSideStr, const char *(bool));
    MOCK_METHOD3(AuthFailNotifyProofInfo, int32_t (int32_t, const char *, uint32_t));
    MOCK_METHOD4(LnnAsyncCallbackDelayHelper, int32_t (SoftBusLooper *, LnnAsyncCallbackFunc, void *, uint64_t));
    MOCK_METHOD2(AuthSessionHandleAuthError, int32_t (int64_t, int32_t));
    MOCK_METHOD3(AuthSessionGetUdid, int32_t (int64_t, char *, uint32_t));
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t (InfoKey, char *, uint32_t));
    MOCK_METHOD3(SoftBusGenerateStrHash, int32_t(const unsigned char *str, uint32_t len, unsigned char *hash));
    MOCK_METHOD4(ConvertBytesToHexString, int32_t (char *, uint32_t, const unsigned char *, uint32_t));
    MOCK_METHOD2(GetNodeFromPcRestrictMap, int32_t (const char *, uint32_t *));
    MOCK_METHOD1(DeleteNodeFromPcRestrictMap, void (const char *));
    MOCK_METHOD4(GetJsonObjectStringItem, bool (const cJSON *, const char * const, char *, uint32_t));
    MOCK_METHOD3(GetJsonObjectNumberItem, bool (const cJSON *, const char * const, int32_t *));
    MOCK_METHOD2(RegChangeListener, int32_t (const char *, DataChangeListener *));
    MOCK_METHOD0(RequireAuthLock, bool (void));
    MOCK_METHOD3(LnnGetLocalByteInfo, int32_t (InfoKey, uint8_t *, uint32_t));
    MOCK_METHOD3(JSON_AddStringToObject, bool (JsonObj *, const char *, const char *));
    MOCK_METHOD4(JSON_GetStringFromObject, bool (const JsonObj *, const char *, char *, uint32_t));
    MOCK_METHOD1(LnnGetLocalNodeInfoSafe, int32_t (NodeInfo *info));
    MOCK_METHOD0(LnnIsDefaultOhosAccount, bool (void));
    MOCK_METHOD5(IdServiceQueryCredential, int32_t (int32_t, const char *, const char *, bool, char **));
    MOCK_METHOD5(AuthIdServiceQueryCredential, int32_t (int32_t, const char *, const char *, bool, char **));
    MOCK_METHOD2(IdServiceGetCredIdFromCredList, char * (int32_t, const char *));
    MOCK_METHOD1(AuthSessionGetCredId, char * (int64_t));
    MOCK_METHOD1(IdServiceGenerateAuthParam, char * (HiChainAuthParam *));
    MOCK_METHOD4(IdServiceAuthCredential, int32_t (int32_t, int64_t, const char *, const DeviceAuthCallback *));
    MOCK_METHOD4(IdServiceProcessCredData, int32_t (int64_t, const uint8_t *, uint32_t, DeviceAuthCallback *));
    MOCK_METHOD1(IdServiceDestroyCredentialList, void (char **));
    MOCK_METHOD0(GetActiveOsAccountIds, int32_t(void));
    MOCK_METHOD4(IsSKIdInvalid, bool (int32_t, const char *, const char *, int32_t));
    MOCK_METHOD3(IdServiceGetCredTypeByCredId, int32_t (int32_t, const char *, int32_t *));
};
} // namespace OHOS
#endif // AUTH_COMMON_MOCK_H
