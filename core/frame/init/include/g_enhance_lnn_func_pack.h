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
#ifndef G_ENHANCE_LNN_FUNC_PACK_H
#define G_ENHANCE_LNN_FUNC_PACK_H

#include <stdint.h>
#include <stdbool.h>

#include "auth_attest_interface_struct.h"
#include "auth_device_common_key_struct.h"
#include "auth_interface_struct.h"
#include "bus_center_event_struct.h"
#include "cJSON.h"
#include "lnn_cipherkey_manager_struct.h"
#include "lnn_data_cloud_sync_struct.h"
#include "lnn_fast_offline_struct.h"
#include "lnn_heartbeat_medium_mgr_struct.h"
#include "lnn_heartbeat_utils_struct.h"
#include "lnn_lane_link_struct.h"
#include "lnn_lane_power_control_struct.h"
#include "lnn_lane_qos_struct.h"
#include "lnn_lane_score_struct.h"
#include "lnn_lane_vap_info_struct.h"
#include "lnn_log.h"
#include "lnn_node_info_struct.h"
#include "lnn_ranging_manager_struct.h"
#include "lnn_secure_storage_struct.h"
#include "lnn_sync_info_manager_struct.h"
#include "lnn_time_sync_impl_struct.h"
#include "lnn_trans_lane_struct.h"
#include "softbus_bus_center.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t AuthMetaOpenConnPacked(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback);
int32_t AuthMetaPostTransDataPacked(int64_t authId, const AuthTransData *dataInfo);
void AuthMetaCloseConnPacked(int64_t authId);
int32_t AuthMetaGetPreferConnInfoPacked(const char *uuid, AuthConnInfo *connInfo);
int64_t AuthMetaGetIdByConnInfoPacked(const AuthConnInfo *connInfo, bool isServer);
int64_t AuthMetaGetIdByUuidPacked(const char *uuid, AuthLinkType type, bool isServer);
int64_t AuthMetaGetIdByIpPacked(const char *ip);
int32_t AuthMetaEncryptPacked(int64_t authId, const uint8_t *inData, uint32_t inLen,
    uint8_t *outData, uint32_t *outLen);
int32_t AuthMetaDecryptPacked(int64_t authId, const uint8_t *inData, uint32_t inLen,
    uint8_t *outData, uint32_t *outLen);
int32_t AuthMetaSetP2pMacPacked(int64_t authId, const char *p2pMac);
int32_t AuthMetaGetConnInfoPacked(int64_t authId, AuthConnInfo *connInfo);
int32_t AuthMetaGetDeviceUuidPacked(int64_t authId, char *uuid, uint16_t size);
int32_t AuthMetaGetServerSidePacked(int64_t authId, bool *isServer);
void AuthMetaCheckMetaExistPacked(const AuthConnInfo *connInfo, bool *isExist);
int32_t CustomizedSecurityProtocolInitPacked(void);
void CustomizedSecurityProtocolDeinitPacked(void);
void AuthMetaDeinitPacked(void);
void DelAuthMetaManagerByPidPacked(const char *pkgName, int32_t pid);
void ClearMetaNodeRequestByPidPacked(const char *pkgName, int32_t pid);
void LnnClearAuthExchangeUdidPacked(const char *networkId);
int32_t AuthInsertDeviceKeyPacked(const NodeInfo *deviceInfo, const AuthDeviceKeyInfo *deviceKey,
    AuthLinkType type);
void AuthUpdateKeyIndexPacked(const char *udidHash, int32_t keyType, int64_t index, bool isServer);
int32_t LnnGenerateLocalPtkPacked(char *udid, char *uuid);
bool CalcHKDFPacked(const uint8_t *ikm, uint32_t ikmLen, uint8_t *out, uint32_t outLen);
void AuthUpdateCreateTimePacked(const char *udidHash, int32_t keyType, bool isServer);
int32_t AuthFindNormalizeKeyByServerSidePacked(const char *udidHash, bool isServer, AuthDeviceKeyInfo *deviceKey);
bool IsSupportUDIDAbatementPacked(void);
int32_t AuthMetaGetConnIdByInfoPacked(const AuthConnInfo *connInfo, uint32_t *connectionId);
int32_t LnnGetMetaPtkPacked(uint32_t connId, char *metaPtk, uint32_t len);
bool PackCipherKeySyncMsgPacked(void *json);
void ProcessCipherKeySyncInfoPacked(const void *json, const char *networkId);
void FreeSoftbusChainPacked(SoftbusCertChain *softbusCertChain);
int32_t InitSoftbusChainPacked(SoftbusCertChain *softbusCertChain);
int32_t LnnSyncTrustedRelationShipPacked(const char *pkgName, const char *msg, uint32_t msgLen);
void LnnCoapConnectPacked(const char *ip);
void LnnDestroyCoapConnectListPacked(void);
bool IsSupportLowLatencyPacked(const TransReqInfo *reqInfo, const LaneLinkInfo *laneLinkInfo);
int32_t LnnInitQosPacked(void);
void LnnDeinitQosPacked(void);
int32_t LnnSyncBleOfflineMsgPacked(void);
void LnnBleHbRegDataLevelChangeCbPacked(const IDataLevelChangeCallback *callback);
void LnnBleHbUnregDataLevelChangeCbPacked(void);
int32_t DecryptUserIdPacked(NodeInfo *deviceInfo, uint8_t *advUserId, uint32_t len);
bool IsCloudSyncEnabledPacked(void);
int32_t AuthFindDeviceKeyPacked(const char *udidHash, int32_t keyType, AuthDeviceKeyInfo *deviceKey);
int32_t AuthFindLatestNormalizeKeyPacked(const char *udidHash, AuthDeviceKeyInfo *deviceKey, bool clearOldKey);
bool IsCipherManagerFindKeyPk(const char *udid);
int32_t LnnAddRemoteChannelCodePacked(const char *udid, int32_t channelCode);
int32_t LnnRegistBleHeartbeatMediumMgrPacked(void);
int32_t LnnRegisterBleLpDeviceMediumMgrPacked(void);
int32_t LnnRegisterSleHeartbeatMediumMgrPacked(void);
bool HaveConcurrencyPreLinkReqIdByReuseConnReqIdPacked(uint32_t connReqId, bool isCheckPreLink);
bool HaveConcurrencyPreLinkNodeByLaneReqIdPacked(uint32_t laneReqId, bool isCheckPreLink);
int32_t GetConcurrencyLaneReqIdByConnReqIdPacked(uint32_t connReqId, uint32_t *laneReqId);
void LnnFreePreLinkPacked(void *para);
int32_t LnnRequestCheckOnlineStatusPacked(const char *networkId, uint64_t timeout);
int32_t LnnSyncPtkPacked(const char *networkId);
int32_t GetConcurrencyLaneReqIdByActionIdPacked(uint32_t actionId, uint32_t *laneReqId);
int32_t UpdateConcurrencyReuseLaneReqIdByActionIdPacked(uint32_t actionId, uint32_t reuseLaneReqId, uint32_t connReqId);
int32_t UpdateConcurrencyReuseLaneReqIdByUdidPacked(const char *udidHash, uint32_t udidHashLen, uint32_t reuseLaneReqId,
    uint32_t connReqId);
int32_t LnnAddLocalVapInfoPacked(LnnVapType type, const LnnVapAttr *vapAttr);
int32_t LnnDeleteLocalVapInfoPacked(LnnVapType type);
void DisablePowerControlPacked(const WifiDirectLinkInfo *wifiDirectInfo);
int32_t EnablePowerControlPacked(const WifiDirectLinkInfo *wifiDirectInfo);
int32_t LnnInitScorePacked(void);
int32_t LnnStartScoringPacked(int32_t interval);
int32_t LnnInitVapInfoPacked(void);
void LnnDeinitScorePacked(void);
void LnnDeinitVapInfoPacked(void);
int32_t LnnGetWlanLinkedInfoPacked(LnnWlanLinkedInfo *info);
int32_t LnnGetCurrChannelScorePacked(int32_t channelId);
bool IsPowerControlEnabledPacked(void);
int32_t LnnStartTimeSyncImplPacked(const char *targetNetworkId, TimeSyncAccuracy accuracy,
    TimeSyncPeriod period, const TimeSyncImplCallback *callback);
int32_t LnnStopTimeSyncImplPacked(const char *targetNetworkId);
int32_t LnnTimeSyncImplInitPacked(void);
void LnnTimeSyncImplDeinitPacked(void);
int32_t LnnTimeChangeNotifyPacked(void);

void SendDeviceStateToMlpsPacked(void *para);
int32_t LnnRetrieveDeviceInfoByNetworkIdPacked(const char *networkId, NodeInfo *info);
void SetLpKeepAliveStatePacked(void *para);
int32_t LnnSetRemoteBroadcastCipherInfoPacked(const char *value, const char *udid);
int32_t LnnGetLocalCacheNodeInfoPacked(NodeInfo *info);
void LnnDeleteDeviceInfoPacked(const char *udid);
int32_t LnnUnPackCloudSyncDeviceInfoPacked(cJSON *json, NodeInfo *cloudSyncInfo);
int32_t LnnPackCloudSyncDeviceInfoPacked(cJSON *json, const NodeInfo *cloudSyncInfo);
int32_t LnnGetLocalBroadcastCipherInfoPacked(CloudSyncInfo *info);
int32_t LnnPackCloudSyncAckSeqPacked(cJSON *json, char *peerudid);
int32_t LnnInitCipherKeyManagerPacked(void);
int32_t LnnSendNotTrustedInfoPacked(const NotTrustedDelayInfo *info, uint32_t num,
    LnnSyncInfoMsgComplete complete);
void RegisterOOBEMonitorPacked(void *para);
int32_t LnnLinkFinderInitPacked(void);
int32_t LnnInitFastOfflinePacked(void);
int32_t LnnDeviceCloudConvergenceInitPacked(void);
void LnnDeinitFastOfflinePacked(void);
int32_t LnnRemoveLinkFinderInfoPacked(const char *networkId);
int32_t LnnRetrieveDeviceInfoByUdidPacked(const char *udid, NodeInfo *deviceInfo);
int32_t LnnInitBroadcastLinkKeyPacked(void);
int32_t LnnInitPtkPacked(void);
void LnnDeinitBroadcastLinkKeyPacked(void);
void LnnDeinitPtkPacked(void);
void LnnIpAddrChangeEventHandlerPacked(void);
void LnnInitOOBEStateMonitorImplPacked(void);
void EhLoginEventHandlerPacked(void);
int32_t LnnInitMetaNodeExtLedgerPacked(void);
void LnnDeinitMetaNodeExtLedgerPacked(void);
bool IsSupportLpFeaturePacked(void);
bool LnnIsSupportLpSparkFeaturePacked(void);
bool LnnIsFeatureSupportDetailPacked(void);
void AuthLoadDeviceKeyPacked(void);
int32_t LnnLoadLocalDeviceInfoPacked(void);
void LnnLoadPtkInfoPacked(void);
int32_t LnnLoadRemoteDeviceInfoPacked(void);
void LoadBleBroadcastKeyPacked(void);
void LnnClearPtkListPacked(void);
void ClearDeviceInfoPacked(void);
int32_t GenerateNewLocalCipherKeyPacked(void);
int32_t LnnRetrieveDeviceInfoPacked(const char *udid, NodeInfo *deviceInfo);
int32_t LnnSaveRemoteDeviceInfoPacked(const NodeInfo *deviceInfo);
int32_t LnnInsertLinkFinderInfoPacked(const char *networkId);
int32_t LnnUpdateRemoteDeviceInfoPacked(const NodeInfo *deviceInfo);
int32_t LnnSaveLocalDeviceInfoPacked(const NodeInfo *deviceInfo);
void UpdateLocalDeviceInfoToMlpsPacked(const NodeInfo *localInfo);
int32_t LnnGetAccountIdFromLocalCachePacked(int64_t *buf);
int32_t LnnGetLocalDevInfoPacked(NodeInfo *deviceInfo);
int32_t LnnGetLocalBroadcastCipherKeyPacked(BroadcastCipherKey *broadcastKey);
int32_t LnnLoadLocalBroadcastCipherKeyPacked(void);
int32_t LnnUpdateLocalBroadcastCipherKeyPacked(BroadcastCipherKey *broadcastKey);
int32_t HbBuildUserIdCheckSumPacked(const int32_t *userIdArray, int32_t num, uint8_t *custData, int32_t len);
void LnnUpdateAuthExchangeUdidPacked(void);
void LnnCoapConnectInitPacked(void);
int32_t LnnInitMetaNodePacked(void);
int32_t InitActionBleConcurrencyPacked(void);
int32_t InitActionStateAdapterPacked(void);
int32_t LnnLoadLocalDeviceAccountIdInfoPacked(void);
void LnnDeinitMetaNodePacked(void);
void LnnCoapConnectDeinitPacked(void);
int32_t LnnGetOOBEStatePacked(SoftBusOOBEState *state);
void LnnReportLaneIdStatsInfoPacked(const LaneIdStatsInfo *statsList, uint32_t listSize);
int32_t LnnRequestQosOptimizationPacked(const uint64_t *laneIdList, uint32_t listSize, int32_t *result,
    uint32_t resultSize);
void LnnCancelQosOptimizationPacked(const uint64_t *laneIdList, uint32_t listSize);
void LnnReportRippleDataPacked(uint64_t laneId, const LnnRippleData *data);
int32_t LnnGetUdidByBrMacPacked(const char *brMac, char *udid, uint32_t udidLen);
void AuthRemoveDeviceKeyByUdidPacked(const char *udidOrHash);
int32_t LnnGetRecommendChannelPacked(const char *udid, int32_t *preferChannel);
int32_t LnnGetLocalPtkByUuidPacked(const char *uuid, char *localPtk, uint32_t len);
int32_t RegistAuthTransListenerPacked(void);
void LnnUnregSleRangeCbPacked(void);
void LnnRegSleRangeCbPacked(const ISleRangeInnerCallback *callback);
int32_t LnnStopRangePacked(const RangeConfig *config);
int32_t LnnStartRangePacked(const RangeConfig *config);
int32_t UnregistAuthTransListenerPacked(void);
void SleRangeDeathCallbackPacked(void);
int32_t LnnRetrieveDeviceDataPacked(LnnDataType dataType, char **data, uint32_t *dataLen);
int32_t LnnSaveDeviceDataPacked(const char *data, LnnDataType dataType);
void TriggerSparkGroupBuildPacked(uint32_t delayTime);
void TriggerSparkGroupClearPacked(uint32_t state, uint32_t delayTime);
void TriggerSparkGroupJoinAgainPacked(const char *udid, uint32_t delayTime);
int32_t InitControlPlanePacked(void);
void DeinitControlPlanePacked(void);
int32_t QueryControlPlaneNodeValidPacked(const char *deviceId);
int32_t LnnDumpControlLaneGroupInfoPacked(int32_t fd);
bool IsSparkGroupEnabledPacked(void);
bool IsDeviceHasRiskFactorPacked(void);
int32_t LnnAsyncSaveDeviceDataPacked(const char *data, LnnDataType dataType);
int32_t LnnDeleteDeviceDataPacked(LnnDataType dataType);
void CheckNeedCloudSyncOfflinePacked(DiscoveryType type);
int32_t LnnGetLocalChannelInfoPacked(VapChannelInfo *channelInfo);
int32_t LnnSetLocalChannelInfoPacked(LnnVapType type, int32_t channelId);
int32_t LnnVirtualLinkInitPacked(void);
void LnnVirtualLinkDeinitPacked(void);
int32_t DcTriggerVirtualLinkPacked(const char *peerNetworkId);
int32_t LnnInitDecisionCenterV2Packed(void);
void LnnDeinitDecisionCenterV2Packed(void);
void SdMgrDeathCallbackPacked(const char *pkgName);
int32_t AuthMetaGetIpByMetaNodeIdPacked(const char *metaNodeId, char *ip, int32_t len);
int32_t AuthMetaGetLocalIpByMetaNodeIdPacked(const char *metaNodeId, char *localIp, int32_t len);
int32_t AuthMetaGetConnectionTypeByMetaNodeIdPacked(const char *metaNodeId, NetworkConnectionType *connectionType);
bool IsSupportMcuFeaturePacked(void);
void LnnSendDeviceStateToMcuPacked(void *para);
int32_t LnnInitMcuPacked(void);

#ifdef __cplusplus
}
#endif

#endif