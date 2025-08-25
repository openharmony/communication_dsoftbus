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

#ifndef LEDGER_MOCK_H
#define LEDGER_MOCK_H

#include <gmock/gmock.h>
#include <securec.h>
#include <cstdlib>
#include "cJSON.h"

#include "bus_center_adapter.h"
#include "bus_center_manager_struct.h"
#include "lnn_connection_fsm_struct.h"
#include "lnn_decision_db_struct.h"
#include "lnn_distributed_net_ledger_struct.h"
#include "lnn_net_builder_struct.h"
#include "lnn_node_info_struct.h"
#include "softbus_adapter_mem.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"

namespace OHOS {
class LedgerInterface {
public:
    LedgerInterface() {};
    virtual ~LedgerInterface() {};

    virtual int32_t LnnGetLocalDeviceInfo(NodeBasicInfo *info) = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len) = 0;
    virtual int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info) = 0;
    virtual NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type) = 0;
    virtual bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type) = 0;
    virtual int32_t LnnGetDLHeartbeatTimestamp(const char *networkId, uint64_t *timestamp) = 0;
    virtual bool LnnGetOnlineStateById(const char *id, IdCategory type) = 0;
    virtual int32_t LnnGetRemoteStrInfo(const char *netWorkId, InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum) = 0;
    virtual int32_t LnnGetTrustedDevInfoFromDb(char **udidArray, uint32_t *num) = 0;
    virtual const char *LnnConvertDLidToUdid(const char *id, IdCategory type) = 0;
    virtual int32_t LnnSetDLHeartbeatTimestamp(const char *networkId, const uint64_t timestamp) = 0;
    virtual int32_t LnnNotifyMasterElect(const char *networkId, const char *masterUdid, int32_t masterWeight) = 0;
    virtual bool GetJsonObjectNumberItem(const cJSON *json, const char * const string, int *target) = 0;
    virtual bool GetJsonObjectNumber64Item(const cJSON *json, const char * const string, int64_t *target) = 0;
    virtual bool AddNumberToJsonObject(cJSON *json, const char * const string, int num) = 0;
    virtual bool AddNumber64ToJsonObject(cJSON *json, const char * const string, int64_t num) = 0;
    virtual int32_t UpdateRecoveryDeviceInfoFromDb(void) = 0;
    virtual void DfxRecordTriggerTime(LnnTriggerReason reason, LnnEventLnnStage stage) = 0;
    virtual int32_t LnnGetRemoteStrInfoByIfnameIdx(const char *netWorkId, InfoKey key, char *info,
        uint32_t len, int32_t ifIdx) = 0;
    virtual int32_t LnnGetLocalNumInfoByIfnameIdx(InfoKey key, int32_t *info, int32_t ifIdx) = 0;
};

class LedgerInterfaceMock : public LedgerInterface {
public:
    LedgerInterfaceMock();
    ~LedgerInterfaceMock() override;

    MOCK_METHOD1(LnnGetLocalDeviceInfo, int32_t(NodeBasicInfo *));
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t(InfoKey, char *, uint32_t));
    MOCK_METHOD3(LnnGetLocalByteInfo, int32_t(InfoKey, uint8_t *, uint32_t));
    MOCK_METHOD2(LnnGetLocalNumInfo, int32_t(InfoKey, int32_t *));
    MOCK_METHOD2(LnnGetNodeInfoById, NodeInfo *(const char *, IdCategory));
    MOCK_METHOD2(LnnHasDiscoveryType, bool(const NodeInfo *, DiscoveryType));
    MOCK_METHOD2(LnnGetDLHeartbeatTimestamp, int32_t(const char *, uint64_t *));
    MOCK_METHOD2(LnnGetOnlineStateById, bool(const char *, IdCategory));
    MOCK_METHOD4(LnnGetRemoteStrInfo, int32_t(const char *, InfoKey, char *, uint32_t));
    MOCK_METHOD2(LnnRequestLeaveSpecific, int32_t(const char *, ConnectionAddrType));
    MOCK_METHOD2(LnnGetAllOnlineNodeInfo, int32_t(NodeBasicInfo **, int32_t *));
    MOCK_METHOD2(LnnGetTrustedDevInfoFromDb, int32_t(char **, uint32_t *));
    MOCK_METHOD2(LnnConvertDLidToUdid, char*(const char *, IdCategory));
    MOCK_METHOD2(LnnSetDLHeartbeatTimestamp, int32_t(const char *, const uint64_t));
    MOCK_METHOD3(LnnNotifyMasterElect, int32_t(const char *, const char *, int32_t));
    MOCK_METHOD3(GetJsonObjectNumberItem, bool(const cJSON *, const char * const, int *));
    MOCK_METHOD3(GetJsonObjectNumber64Item, bool (const cJSON *, const char * const, int64_t *));
    MOCK_METHOD3(AddNumberToJsonObject, bool(cJSON *, const char * const, int));
    MOCK_METHOD0(UpdateRecoveryDeviceInfoFromDb, int32_t(void));
    MOCK_METHOD3(AddNumber64ToJsonObject, bool (cJSON *, const char * const, int64_t));
    MOCK_METHOD2(DfxRecordTriggerTime, void (LnnTriggerReason, LnnEventLnnStage));
    MOCK_METHOD5(LnnGetRemoteStrInfoByIfnameIdx, int32_t(const char *, InfoKey, char *, uint32_t, int32_t));
    MOCK_METHOD3(LnnGetLocalNumInfoByIfnameIdx, int32_t(InfoKey, int32_t *, int32_t));
    static int32_t ActionOfGetTrustedDevInfoFromDb(char **udidArray, uint32_t *num);
    static int32_t ActionOfLnnGetLocalStrInfo(InfoKey key, char *out, uint32_t outSize);
    static int32_t ActofNodeInfo(NodeBasicInfo **info, int32_t *infoNum);

    static inline std::string deviceName = "Device xxxx";
    static inline std::string deviceUDID = "06D1D93A2AED76215FC5EF7D8FCC551045A9DC35F0878A1E2DBA7D2D4FC9B5DA";
    static inline uint8_t accountHash[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };
    static inline std::string localIp = "127.0.0.1";
};

extern "C" {
    int32_t LnnGetLocalDeviceInfo(NodeBasicInfo *info);
    int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len);
    int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len);
    int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info);
    NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type);
    bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type);
    int32_t LnnGetDLHeartbeatTimestamp(const char *networkId, uint64_t *timestamp);
    bool LnnGetOnlineStateById(const char *id, IdCategory type);
    int32_t LnnGetRemoteStrInfo(const char *netWorkId, InfoKey key, char *info, uint32_t len);
    int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType);
    int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum);
    int32_t LnnGetTrustedDevInfoFromDb(char **udidArray, uint32_t *num);
    const char *LnnConvertDLidToUdid(const char *id, IdCategory type);
    int32_t LnnSetDLHeartbeatTimestamp(const char *networkId, const uint64_t timestamp);
    int32_t LnnNotifyMasterElect(const char *networkId, const char *masterUdid, int32_t masterWeight);
    bool GetJsonObjectNumberItem(const cJSON *json, const char * const string, int *target);
    bool GetJsonObjectNumber64Item(const cJSON *json, const char * const string, int64_t *target);
    bool AddNumberToJsonObject(cJSON *json, const char * const string, int num);
    bool AddNumber64ToJsonObject(cJSON *json, const char * const string, int64_t num);
    int32_t UpdateRecoveryDeviceInfoFromDb(void);
    void DfxRecordTriggerTime(LnnTriggerReason reason, LnnEventLnnStage stage);
}
} // namespace OHOS
#endif // LEDGER_MOCK_H