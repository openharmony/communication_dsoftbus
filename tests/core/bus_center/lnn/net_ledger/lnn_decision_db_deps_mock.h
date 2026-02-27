/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef LNN_DECISION_DB_DEPS_MOCK_H
#define LNN_DECISION_DB_DEPS_MOCK_H

#include <gmock/gmock.h>
#include <securec.h>

#include "auth_deviceprofile.h"
#include "auth_interface.h"
#include "bus_center_event.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_async_callback_utils.h"
#include "lnn_file_utils.h"
#include "lnn_heartbeat_medium_mgr.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_huks_utils.h"
#include "lnn_node_info.h"
#include "lnn_secure_storage_struct.h"
#include "sqlite3_utils.h"
#include "softbus_adapter_file.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

namespace OHOS {
class DecisionDbDepsInterface {
public:
    DecisionDbDepsInterface() {};
    virtual ~DecisionDbDepsInterface() {};

    virtual int32_t LnnGenerateKeyByHuks(struct HksBlob *keyAlias);
    virtual int32_t LnnDeleteKeyByHuks(struct HksBlob *keyAlias);
    virtual int32_t LnnEncryptDataByHuks(
        const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData);
    virtual int32_t LnnDecryptDataByHuks(
        const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData);
    virtual int32_t LnnGenerateRandomByHuks(uint8_t *randomKey, uint32_t len);
    virtual int32_t OpenDatabase(DbContext **ctx);
    virtual int32_t CloseDatabase(DbContext *ctx);
    virtual int32_t CreateTable(DbContext *ctx, TableNameID id);
    virtual int32_t CheckTableExist(DbContext *ctx, TableNameID id, bool *isExist);
    virtual int32_t RemoveRecordByKey(DbContext *ctx, TableNameID id, uint8_t *data);
    virtual int32_t GetRecordNumByKey(DbContext *ctx, TableNameID id, uint8_t *data);
    virtual int32_t EncryptedDb(DbContext *ctx, const uint8_t *password, uint32_t len);
    virtual int32_t UpdateDbPassword(DbContext *ctx, const uint8_t *password, uint32_t len);
    virtual int32_t QueryRecordByKey(
        DbContext *ctx, TableNameID id, uint8_t *data, uint8_t **replyInfo, int32_t infoNum);
    virtual int32_t LnnGetFullStoragePath(LnnFileId id, char *path, uint32_t len);
    virtual int32_t SoftBusReadFullFile(const char *fileName, char *readBuf, uint32_t maxLen);
    virtual int32_t SoftBusWriteFile(const char *fileName, const char *writeBuf, uint32_t len);
    virtual int32_t SoftBusAccessFile(const char *pathName, int32_t mode);
    virtual int32_t LnnAsyncCallbackHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para);
    virtual int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len);
    virtual int32_t ConvertBytesToHexString(
        char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen);
    virtual void LnnNotifyNetworkStateChanged(SoftBusNetworkState state) = 0;
    virtual TrustedReturnType AuthHasTrustedRelation(void) = 0;
    virtual bool IsEnableSoftBusHeartbeat(void) = 0;
    virtual void LnnNotifyHBRepeat(void) = 0;
    virtual void LnnHbClearRecvList(void) = 0;
    virtual int32_t LnnConvertHbTypeToId(LnnHeartbeatType type) = 0;
    virtual bool LnnVisitHbTypeSet(VisitHbTypeCb callback, LnnHeartbeatType *typeSet, void *data) = 0;
    virtual int32_t LnnCeEncryptDataByHuks(
        const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData);
    virtual int32_t LnnCeDecryptDataByHuks(
        const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData);
    virtual int64_t SoftBusGetRealTimeMs(void) = 0;
    virtual int32_t LnnGetLocalNum64Info(InfoKey key, int64_t *info) = 0;
    virtual int32_t LnnSetLocalNum64Info(InfoKey key, int64_t info) = 0;
    virtual int32_t LnnAsyncCallbackDelayHelper(
        SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis) = 0;
    virtual SoftBusLooper *GetLooper(int32_t looper) = 0;
    virtual int32_t LnnSaveDeviceData(const char *data, LnnDataType dataType) = 0;
    virtual int32_t LnnRetrieveDeviceData(LnnDataType dataType, char **data, uint32_t *dataLen) = 0;
    virtual int32_t LnnGetLocalDevInfo(NodeInfo *deviceInfo) = 0;
    virtual int32_t LnnGetAllRemoteDevInfo(NodeInfo **info, int32_t *nums) = 0;
    virtual int32_t LnnSaveLocalDeviceInfo(const NodeInfo *deviceInfo) = 0;
    virtual int32_t LnnSaveRemoteDeviceInfo(const NodeInfo *deviceInfo) = 0;
    virtual int32_t LnnDeleteCeKeyByHuks(struct HksBlob *keyAlias, bool isUnlocked) = 0;
    virtual int32_t LnnGenerateCeKeyByHuks(struct HksBlob *keyAlias, bool isUnlocked) = 0;
    virtual int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info) = 0;
    virtual int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info) = 0;
    virtual int32_t SelectAllAcl(TrustedInfo **trustedInfoArray, uint32_t *num) = 0;
    virtual void LnnNotifyLpMcuInit(SoftBusHbApState state, int32_t strategy) = 0;
};
class DecisionDbDepsInterfaceMock : public DecisionDbDepsInterface {
public:
    DecisionDbDepsInterfaceMock();
    ~DecisionDbDepsInterfaceMock() override;
    MOCK_METHOD1(LnnGenerateKeyByHuks, int32_t(struct HksBlob *));
    MOCK_METHOD1(LnnDeleteKeyByHuks, int32_t(struct HksBlob *));
    MOCK_METHOD3(LnnEncryptDataByHuks, int32_t(const struct HksBlob *, const struct HksBlob *, struct HksBlob *));
    MOCK_METHOD3(LnnDecryptDataByHuks, int32_t(const struct HksBlob *, const struct HksBlob *, struct HksBlob *));
    MOCK_METHOD2(LnnGenerateRandomByHuks, int32_t(uint8_t *, uint32_t));
    MOCK_METHOD1(OpenDatabase, int32_t(DbContext **));
    MOCK_METHOD1(CloseDatabase, int32_t(DbContext *));
    MOCK_METHOD2(CreateTable, int32_t(DbContext *, TableNameID));
    MOCK_METHOD3(CheckTableExist, int32_t(DbContext *, TableNameID, bool *));
    MOCK_METHOD3(RemoveRecordByKey, int32_t(DbContext *, TableNameID, uint8_t *));
    MOCK_METHOD3(GetRecordNumByKey, int32_t(DbContext *, TableNameID, uint8_t *));
    MOCK_METHOD3(EncryptedDb, int32_t(DbContext *, const uint8_t *, uint32_t));
    MOCK_METHOD3(UpdateDbPassword, int32_t(DbContext *, const uint8_t *, uint32_t));
    MOCK_METHOD5(QueryRecordByKey, int32_t(DbContext *, TableNameID, uint8_t *, uint8_t **, int));
    MOCK_METHOD3(LnnGetFullStoragePath, int32_t(LnnFileId, char *, uint32_t));
    MOCK_METHOD3(SoftBusReadFullFile, int32_t(const char *, char *, uint32_t));
    MOCK_METHOD3(SoftBusWriteFile, int32_t(const char *, const char *, uint32_t));
    MOCK_METHOD2(SoftBusAccessFile, int32_t(const char *, int32_t));
    MOCK_METHOD3(LnnAsyncCallbackHelper, int32_t(SoftBusLooper *, LnnAsyncCallbackFunc, void *));
    MOCK_METHOD3(LnnGetLocalByteInfo, int32_t(InfoKey, uint8_t *, uint32_t));
    MOCK_METHOD4(ConvertBytesToHexString, int32_t(char *, uint32_t, const unsigned char *, uint32_t));
    MOCK_METHOD1(LnnNotifyNetworkStateChanged, void(SoftBusNetworkState));
    MOCK_METHOD0(AuthHasTrustedRelation, TrustedReturnType(void));
    MOCK_METHOD0(IsEnableSoftBusHeartbeat, bool(void));
    MOCK_METHOD0(LnnNotifyHBRepeat, void(void));
    MOCK_METHOD0(LnnHbClearRecvList, void(void));
    MOCK_METHOD3(LnnVisitHbTypeSet, bool(VisitHbTypeCb, LnnHeartbeatType *, void *));
    MOCK_METHOD1(LnnConvertHbTypeToId, int32_t(LnnHeartbeatType));
    static int32_t DecisionDbAsyncCallbackHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para);
    MOCK_METHOD3(LnnCeEncryptDataByHuks, int32_t(const struct HksBlob *, const struct HksBlob *, struct HksBlob *));
    MOCK_METHOD3(LnnCeDecryptDataByHuks, int32_t(const struct HksBlob *, const struct HksBlob *, struct HksBlob *));
    MOCK_METHOD0(SoftBusGetRealTimeMs, int64_t(void));
    MOCK_METHOD2(LnnGetLocalNum64Info, int32_t(InfoKey key, int64_t *));
    MOCK_METHOD2(LnnSetLocalNum64Info, int32_t(InfoKey, int64_t));
    MOCK_METHOD4(LnnAsyncCallbackDelayHelper, int32_t(SoftBusLooper *, LnnAsyncCallbackFunc, void *, uint64_t));
    MOCK_METHOD1(GetLooper, SoftBusLooper *(int));
    MOCK_METHOD2(LnnSaveDeviceData, int32_t(const char *, LnnDataType));
    MOCK_METHOD3(LnnRetrieveDeviceData, int32_t(LnnDataType, char **, uint32_t *));
    MOCK_METHOD1(LnnGetLocalDevInfo, int32_t(NodeInfo *));
    MOCK_METHOD2(LnnGetAllRemoteDevInfo, int32_t(NodeInfo **, int32_t *));
    MOCK_METHOD1(LnnSaveLocalDeviceInfo, int32_t(const NodeInfo *));
    MOCK_METHOD1(LnnSaveRemoteDeviceInfo, int32_t(const NodeInfo *));
    MOCK_METHOD2(LnnDeleteCeKeyByHuks, int32_t(struct HksBlob *keyAlias, bool isUnlocked));
    MOCK_METHOD2(LnnGenerateCeKeyByHuks, int32_t(struct HksBlob *, bool));
    MOCK_METHOD2(LnnGetLocalNumInfo, int32_t(InfoKey key, int32_t *info));
    MOCK_METHOD2(LnnGetLocalNumU64Info, int32_t(InfoKey, uint64_t *));
    MOCK_METHOD2(SelectAllAcl, int32_t(TrustedInfo **, uint32_t *));
    MOCK_METHOD2(LnnNotifyLpMcuInit, void(SoftBusHbApState, int32_t));
    static int32_t ActionOfSelectAllAcl(TrustedInfo **trustedInfoArray, uint32_t *num);
};
} // namespace OHOS
#endif // LNN_DECISION_DB_DEPS_MOCK_H
