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

#ifndef LNN_NET_LEDGER_DEPS_MOCK_H
#define LNN_NET_LEDGER_DEPS_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "auth_device_common_key.h"
#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "g_enhance_lnn_func_pack.h"
#include "lnn_decision_db.h"
#include "lnn_device_info_recovery.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_event_monitor_impl.h"
#include "lnn_feature_capability_struct.h"
#include "lnn_file_utils.h"
#include "lnn_huks_utils.h"
#include "lnn_init_monitor.h"
#include "lnn_local_net_ledger.h"
#include "lnn_meta_node_ledger.h"
#include "lnn_net_builder.h"
#include "lnn_network_id.h"
#include "lnn_node_info.h"
#include "lnn_p2p_info.h"
#include "softbus_utils.h"

namespace OHOS {
class NetLedgerDepsInterface {
public:
    NetLedgerDepsInterface() {};
    virtual ~NetLedgerDepsInterface() {};

    virtual int32_t LnnInitModuleNotifyWithRetrySync(uint32_t module, ModuleInitCallBack callback,
        uint32_t retry, uint32_t delay) = 0;
    virtual int32_t LnnInitLocalLedger(void) = 0;
    virtual int32_t LnnInitDistributedLedger(void) = 0;
    virtual int32_t LnnInitMetaNodeLedger(void) = 0;
    virtual int32_t LnnInitMetaNodeExtLedger(void) = 0;
    virtual int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info) = 0;
    virtual int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info) = 0;
    virtual int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len) = 0;
    virtual int32_t LnnGetLocalBoolInfo(InfoKey key, bool *info, uint32_t len) = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info) = 0;
    virtual bool IsSupportLpFeature(void) = 0;
    virtual int32_t LnnSetLocalNum64Info(InfoKey key, int64_t info) = 0;
    virtual int32_t LnnGetLocalDevInfo(NodeInfo *deviceInfo) = 0;
    virtual void LnnDumpNodeInfo(const NodeInfo *deviceInfo, const char *log) = 0;
    virtual int32_t LnnSaveLocalDeviceInfo(const NodeInfo *deviceInfo) = 0;
    virtual int32_t LnnSetLocalNumInfo(InfoKey key, int32_t info) = 0;
    virtual int32_t LnnUpdateLocalNetworkId(const void *id) = 0;
    virtual int32_t LnnUpdateLocalDeviceName(const DeviceBasicInfo *info) = 0;
    virtual void LnnNotifyNetworkIdChangeEvent(const char *networkId) = 0;
    virtual int32_t LnnUpdateLocalNetworkIdTime(int64_t time) = 0;
    virtual const NodeInfo *LnnGetLocalNodeInfo(void) = 0;
    virtual void LnnInitDeviceInfoStatusSet(uint32_t module, InitDepsStatus status) = 0;
    virtual void LnnInitSetDeviceInfoReady(void) = 0;
    virtual int32_t LnnLoadLocalDeviceInfo(void) = 0;
    virtual int32_t LnnRemoveStorageConfigPath(LnnFileId id) = 0;
    virtual int32_t LnnUpdateLocalUuidAndIrk(void) = 0;
    virtual void LnnLoadPtkInfo(void) = 0;
    virtual int32_t LnnLoadRemoteDeviceInfo(void) = 0;
    virtual void LoadBleBroadcastKey(void) = 0;
    virtual int32_t LnnLoadLocalBroadcastCipherKey(void) = 0;
    virtual void AuthLoadDeviceKey(void) = 0;
    virtual int32_t LnnInitLocalLedgerDelay(void) = 0;
    virtual int32_t LnnInitDecisionDbDelay(void) = 0;
    virtual int32_t LnnInitCommonEventMonitorImpl(void) = 0;
    virtual void LnnDeinitMetaNodeLedger(void) = 0;
    virtual void LnnDeinitDistributedLedger(void) = 0;
    virtual void LnnDeinitLocalLedger(void) = 0;
    virtual void LnnDeinitHuksInterface(void) = 0;
    virtual void LnnDeinitMetaNodeExtLedger(void) = 0;
    virtual void LnnDeInitCloudSyncModule(void) = 0;
    virtual int32_t LnnGetLocalNum16Info(InfoKey key, int16_t *info) = 0;
    virtual int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t LnnGetRemoteNumU32Info(const char *networkId, InfoKey key, uint32_t *info) = 0;
    virtual int32_t LnnGetRemoteNumInfo(const char *networkId, InfoKey key, int32_t *info) = 0;
    virtual int32_t LnnGetRemoteNum16Info(const char *networkId, InfoKey key, int16_t *info) = 0;
    virtual int32_t LnnGetRemoteBoolInfo(const char *networkId, InfoKey key, bool *info) = 0;
    virtual int32_t LnnSetLocalNum16Info(InfoKey key, int16_t info) = 0;
    virtual int32_t LnnSetLocalNumU16Info(InfoKey key, uint16_t info) = 0;
    virtual int32_t LnnSetLocalNumU32Info(InfoKey key, uint32_t info) = 0;
    virtual int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen,
        const unsigned char *inBuf, uint32_t inLen) = 0;
    virtual int32_t LnnGetLocalPtkByUuid(const char *uuid, char *localPtk, uint32_t len) = 0;
    virtual void LnnClearPtkList(void) = 0;
    virtual void ClearDeviceInfo(void) = 0;
    virtual void AuthClearDeviceKey(void) = 0;
    virtual int32_t LnnGenLocalNetworkId(char *networkId, uint32_t len) = 0;
    virtual int32_t LnnSetLocalStrInfo(InfoKey key, const char *info) = 0;
    virtual int32_t GenerateNewLocalCipherKey(void) = 0;
    virtual void LnnRemoveDb(void) = 0;
    virtual int32_t InitTrustedDevInfoTable(void) = 0;
    virtual int32_t LnnGenBroadcastCipherInfo(void) = 0;
    virtual int32_t HandleDeviceInfoIfUdidChanged(void) = 0;
    virtual int32_t LnnInitHuksInterface(void) = 0;
    virtual int32_t LnnGetRemoteByteInfo(const char *networkId, InfoKey key, uint8_t *info, uint32_t len) = 0;
    virtual int32_t LnnGetLocalStrInfoByIfnameIdx(InfoKey key, char *info, uint32_t len, int32_t ifIdx) = 0;
    virtual int32_t LnnGetRemoteStrInfoByIfnameIdx(const char *networkId, InfoKey key,
        char *info, uint32_t len, int32_t ifIdx) = 0;
    virtual void LnnAnonymizeDeviceStr(const char *deviceStr, uint32_t strLen, uint32_t defaultLen,
        char **anonymizedStr) = 0;
    virtual int32_t LnnUpdateLocalHuksKeyTime(uint64_t huksKeyTime) = 0;
    virtual int32_t LnnGetLocalDevInfoPacked(NodeInfo *deviceInfo) = 0;
    virtual bool IsSupportLpFeaturePacked(void) = 0;
    virtual bool LnnIsSupportLpSparkFeaturePacked(void) = 0;
    virtual int32_t LnnClearFeatureCapability(uint64_t *feature, FeatureCapability capaBit) = 0;
};

class NetLedgerDepsInterfaceMock : public NetLedgerDepsInterface {
public:
    NetLedgerDepsInterfaceMock();
    ~NetLedgerDepsInterfaceMock() override;

    MOCK_METHOD4(LnnInitModuleNotifyWithRetrySync, int32_t (uint32_t, ModuleInitCallBack, uint32_t, uint32_t));
    MOCK_METHOD0(LnnInitLocalLedger, int32_t (void));
    MOCK_METHOD0(LnnInitDistributedLedger, int32_t (void));
    MOCK_METHOD0(LnnInitMetaNodeLedger, int32_t (void));
    MOCK_METHOD0(LnnInitMetaNodeExtLedger, int32_t (void));
    MOCK_METHOD2(LnnGetLocalNumU64Info, int32_t (InfoKey, uint64_t *));
    MOCK_METHOD2(LnnGetLocalNumU32Info, int32_t (InfoKey key, uint32_t *info));
    MOCK_METHOD3(LnnGetLocalByteInfo, int32_t(InfoKey key, uint8_t *info, uint32_t len));
    MOCK_METHOD3(LnnGetLocalBoolInfo, int32_t(InfoKey key, bool *info, uint32_t len));
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t (InfoKey, char *, uint32_t));
    MOCK_METHOD2(LnnGetLocalNumInfo, int32_t(InfoKey, int32_t *));
    MOCK_METHOD0(IsSupportLpFeature, bool());
    MOCK_METHOD2(LnnSetLocalNum64Info, int32_t(InfoKey, int64_t));
    MOCK_METHOD1(LnnGetLocalDevInfo, int32_t (NodeInfo *));
    MOCK_METHOD2(LnnDumpNodeInfo, void (const NodeInfo *, const char *));
    MOCK_METHOD1(LnnSaveLocalDeviceInfo, int32_t (const NodeInfo *));
    MOCK_METHOD2(LnnSetLocalNumInfo, int32_t(InfoKey, int32_t));
    MOCK_METHOD1(LnnUpdateLocalNetworkId, int32_t (const void *));
    MOCK_METHOD1(LnnUpdateLocalDeviceName, int32_t (const DeviceBasicInfo *));
    MOCK_METHOD1(LnnNotifyNetworkIdChangeEvent, void (const char *));
    MOCK_METHOD1(LnnUpdateLocalNetworkIdTime, int32_t (int64_t));
    MOCK_METHOD0(LnnGetLocalNodeInfo, NodeInfo *());
    MOCK_METHOD2(LnnInitDeviceInfoStatusSet, void (uint32_t, InitDepsStatus));
    MOCK_METHOD0(LnnInitSetDeviceInfoReady, void (void));
    MOCK_METHOD0(LnnLoadLocalDeviceInfo, int32_t (void));
    MOCK_METHOD1(LnnRemoveStorageConfigPath, int32_t (LnnFileId));
    MOCK_METHOD0(LnnUpdateLocalUuidAndIrk, int32_t ());
    MOCK_METHOD0(LnnLoadPtkInfo, void ());
    MOCK_METHOD0(LnnLoadRemoteDeviceInfo, int32_t ());
    MOCK_METHOD0(LoadBleBroadcastKey, void ());
    MOCK_METHOD0(LnnLoadLocalBroadcastCipherKey, int32_t(void));
    MOCK_METHOD0(AuthLoadDeviceKey, void(void));
    MOCK_METHOD0(LnnInitLocalLedgerDelay, int32_t(void));
    MOCK_METHOD0(LnnInitDecisionDbDelay, int32_t(void));
    MOCK_METHOD0(LnnInitCommonEventMonitorImpl, int32_t(void));
    MOCK_METHOD0(LnnDeinitMetaNodeLedger, void(void));
    MOCK_METHOD0(LnnDeinitDistributedLedger, void(void));
    MOCK_METHOD0(LnnDeinitLocalLedger, void(void));
    MOCK_METHOD0(LnnDeinitHuksInterface, void(void));
    MOCK_METHOD0(LnnDeinitMetaNodeExtLedger, void(void));
    MOCK_METHOD0(LnnDeInitCloudSyncModule, void(void));
    MOCK_METHOD2(LnnGetLocalNum16Info, int32_t(InfoKey, int16_t *));
    MOCK_METHOD4(LnnGetRemoteStrInfo, int32_t(const char *, InfoKey, char *, uint32_t));
    MOCK_METHOD3(LnnGetRemoteNumU32Info, int32_t(const char *, InfoKey, uint32_t *));
    MOCK_METHOD3(LnnGetRemoteNumInfo, int32_t(const char *, InfoKey, int32_t *));
    MOCK_METHOD3(LnnGetRemoteNum16Info, int32_t(const char *, InfoKey, int16_t *));
    MOCK_METHOD3(LnnGetRemoteBoolInfo, int32_t (const char *networkId, InfoKey key, bool *info));
    MOCK_METHOD2(LnnSetLocalNum16Info, int32_t (InfoKey, int16_t));
    MOCK_METHOD2(LnnSetLocalNumU16Info, int32_t(InfoKey, uint16_t));
    MOCK_METHOD2(LnnSetLocalNumU32Info, int32_t (InfoKey key, uint32_t info));
    MOCK_METHOD4(ConvertBytesToHexString, int32_t(char *, uint32_t, const unsigned char *, uint32_t));
    MOCK_METHOD3(LnnGetLocalPtkByUuid, int32_t (const char *, char *, uint32_t));
    MOCK_METHOD0(LnnClearPtkList, void (void));
    MOCK_METHOD0(ClearDeviceInfo, void (void));
    MOCK_METHOD0(AuthClearDeviceKey, void (void));
    MOCK_METHOD2(LnnGenLocalNetworkId, int32_t(char *, uint32_t));
    MOCK_METHOD2(LnnSetLocalStrInfo, int32_t (InfoKey, const char *));
    MOCK_METHOD0(GenerateNewLocalCipherKey, int32_t ());
    MOCK_METHOD0(LnnRemoveDb, void ());
    MOCK_METHOD0(InitTrustedDevInfoTable, int32_t ());
    MOCK_METHOD0(LnnGenBroadcastCipherInfo, int32_t ());
    MOCK_METHOD0(HandleDeviceInfoIfUdidChanged, int32_t ());
    MOCK_METHOD0(LnnInitHuksInterface, int32_t ());
    MOCK_METHOD4(LnnGetRemoteByteInfo, int32_t (const char *, InfoKey, uint8_t *, uint32_t));
    MOCK_METHOD4(LnnGetLocalStrInfoByIfnameIdx, int32_t (InfoKey, char *, uint32_t, int32_t));
    MOCK_METHOD5(LnnGetRemoteStrInfoByIfnameIdx, int32_t (const char *, InfoKey, char *, uint32_t, int32_t));
    MOCK_METHOD4(LnnAnonymizeDeviceStr, void (const char *, uint32_t, uint32_t, char **));
    MOCK_METHOD1(LnnUpdateLocalHuksKeyTime, int32_t (uint64_t));
    MOCK_METHOD1(LnnGetLocalDevInfoPacked, int32_t (NodeInfo *));
    MOCK_METHOD0(IsSupportLpFeaturePacked, bool(void));
    MOCK_METHOD0(LnnIsSupportLpSparkFeaturePacked, bool(void));
    MOCK_METHOD2(LnnClearFeatureCapability, int32_t (uint64_t *, FeatureCapability));
};
} // namespace OHOS
#endif // LNN_NET_LEDGER_COMMON_MOCK_H