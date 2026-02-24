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

#ifndef G_ENHANCE_LNN_FUNC_H
#define G_ENHANCE_LNN_FUNC_H

#include "auth_attest_interface_struct.h"
#include "auth_device_common_key_struct.h"
#include "auth_interface_struct.h"
#include "bus_center_event_struct.h"
#include "ble_range.h"
#include "cJSON.h"
#include "lnn_ble_lpdevice_struct.h"
#include "lnn_cipherkey_manager_struct.h"
#include "lnn_data_cloud_sync_struct.h"
#include "lnn_decision_center_struct.h"
#include "lnn_device_info_recovery_struct.h"
#include "lnn_fast_offline_struct.h"
#include "lnn_heartbeat_utils_struct.h"
#include "lnn_lane_interface_struct.h"
#include "lnn_lane_link_struct.h"
#include "lnn_lane_power_control_struct.h"
#include "lnn_lane_qos_struct.h"
#include "lnn_lane_score_struct.h"
#include "lnn_lane_vap_info_struct.h"
#include "lnn_node_info_struct.h"
#include "lnn_ranging_manager_struct.h"
#include "lnn_secure_storage_struct.h"
#include "lnn_sync_info_manager_struct.h"
#include "lnn_time_sync_impl_struct.h"
#include "lnn_trans_lane_struct.h"
#include "softbus_adapter_crypto.h"
#include "softbus_broadcast_type_struct.h"
#include "softbus_bus_center.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*OnStatsPeriodAdjustmentFunc)(uint32_t ms);
typedef int32_t (*LnnTimeSyncImplInitFunc)(void);
typedef void (*LnnTimeSyncImplDeinitFunc)(void);
typedef int32_t (*LnnTimeChangeNotifyFunc)(void);
typedef int32_t (*LnnStartTimeSyncImplFunc)(const char *targetNetworkId, TimeSyncAccuracy accuracy,
                                            TimeSyncPeriod period, const TimeSyncImplCallback *cb);
typedef int32_t (*LnnStopTimeSyncImplFunc)(const char *targetNetworkId);
typedef int32_t (*LnnInitDecisionCenterFunc)(uint32_t version);
typedef void (*LnnDeinitDecisionCenterFunc)(void);
typedef int32_t (*LnnDcSubscribeFunc)(DcTask *task);
typedef int32_t (*LnnDcUnsubscribeFunc)(DcTask *task);
typedef void (*LnnDcDispatchEventFunc)(DcEvent *dcEvent);
typedef void (*TriggerSparkGroupBuildFunc)(uint32_t delayTime);
typedef void (*TriggerSparkGroupClearFunc)(uint32_t state, uint32_t delayTime);
typedef void (*TriggerSparkGroupJoinAgainFunc)(const char *udid, uint32_t delayTime);
typedef int32_t (*InitControlPlaneFunc)(void);
typedef void (*DeinitControlPlaneFunc)(void);
typedef int32_t (*QueryControlPlaneNodeValidFunc)(const char *deviceId);
typedef int32_t (*LnnDumpControlLaneGroupInfoFunc)(int32_t fd);
typedef bool (*IsSparkGroupEnabledFunc)(void);
typedef void (*LnnDestroyCoapConnectListFunc)(void);
typedef void (*LnnCoapConnectFunc)(const char *ip);
typedef void (*LnnCoapConnectInitFunc)(void);
typedef void (*LnnCoapConnectDeinitFunc)(void);
typedef int32_t (*HbUpdateBleScanFilterFunc)(int32_t listenerId, LnnHeartbeatType type);
typedef int32_t (*HbGenerateBitPositionFunc)(int32_t min, int32_t max, int64_t seed, int32_t *randPos, int32_t num);
typedef int32_t (*LnnSendBroadcastInfoToLpFunc)(void);
typedef void (*LnnBleHbRegDataLevelChangeCbFunc)(const IDataLevelChangeCallback *callback);
typedef void (*LnnBleHbUnregDataLevelChangeCbFunc)(void);
typedef void (*LnnAdjustScanPolicyFunc)(void);
typedef int32_t (*HbBuildUserIdCheckSumFunc)(const int32_t *userIdArray, int32_t num, uint8_t *custData, int32_t len);
typedef int32_t (*EncryptUserIdFunc)(uint8_t *advUserId, uint32_t len, int32_t userId);
typedef int32_t (*DecryptUserIdFunc)(NodeInfo *deviceInfo, uint8_t *advUserId, uint32_t len);
typedef int32_t (*LnnRegisterBleLpDeviceMediumMgrFunc)(void);
typedef int32_t (*LnnRegisterSleHeartbeatMediumMgrFunc)(void);
typedef void (*SendDeviceStateToMlpsFunc)(void *para);
typedef void (*UpdateLocalDeviceInfoToMlpsFunc)(const NodeInfo *localInfo);
typedef void (*UpdateRemoteDeviceInfoToMlpsFunc)(const NodeInfo *info);
typedef void (*UpdateRemoteDeviceInfoListToMlpsFunc)(void);
typedef int32_t (*GetBurstAdvIdFunc)(void);
typedef int32_t (*SendDeviceInfoToSHByTypeFunc)(LpFeatureType type);
typedef int32_t (*SendAdvInfoToMlpsFunc)(LpBroadcastParam *lpAdvParam, LpServerType type);
typedef int32_t (*SwitchHeartbeatReportChannelFunc)(bool isToAP, uint16_t scanInterval, uint16_t scanWindow);
typedef bool (*IsSupportLpFeatureFunc)(void);
typedef bool (*LnnIsSupportLpSparkFeatureFunc)(void);
typedef bool (*IsFeatureSupportDetailFunc)(void);
typedef void (*SetLpKeepAliveStateFunc)(void *para);
typedef int32_t (*LnnRegistBleHeartbeatMediumMgrFunc)(void);
typedef int32_t (*EnablePowerControlFunc)(const WifiDirectLinkInfo *wifiDirectInfo);
typedef void (*DisablePowerControlFunc)(const WifiDirectLinkInfo *wifiDirectInfo);
typedef void (*LnnDeinitScoreFunc)(void);
typedef int32_t (*LnnInitScoreFunc)(void);
typedef int32_t (*LnnStartScoringFunc)(int32_t interval);
typedef int32_t (*LnnStopScoringFunc)(void);
typedef int32_t (*LnnGetWlanLinkedInfoFunc)(LnnWlanLinkedInfo *info);
typedef int32_t (*LnnGetAllChannelScoreFunc)(LnnChannelScore **scoreList, uint32_t *listSize);
typedef int32_t (*LnnInitVapInfoFunc)(void);
typedef void (*LnnDeinitVapInfoFunc)(void);
typedef int32_t (*LnnAddLocalVapInfoFunc)(LnnVapType type, const LnnVapAttr *vapAttr);
typedef int32_t (*LnnDeleteLocalVapInfoFunc)(LnnVapType type);
typedef int32_t (*LnnGetLocalVapInfoFunc)(LnnVapType type, LnnVapAttr *vapAttr);
typedef int32_t (*LnnAddRemoteVapInfoFunc)(const char *udid, LnnVapType type, const LnnVapAttr *vapAttr);
typedef int32_t (*LnnDeleteRemoteVapInfoFunc)(const char *udid);
typedef int32_t (*LnnGetRemoteVapInfoFunc)(const char *udid, LnnVapType type, LnnVapAttr *vapAttr);
typedef int32_t (*LnnGetLocalPreferChannelFunc)(void);
typedef int32_t (*LnnGetLocalChannelCodeFunc)(void);
typedef int32_t (*LnnAddRemoteChannelCodeFunc)(const char *udid, int32_t channelCode);
typedef int32_t (*LnnGetRecommendChannelFunc)(const char *udid, int32_t *preferChannel);
typedef int32_t (*LnnGetLocalChannelInfoFunc)(VapChannelInfo *channelInfo);
typedef int32_t (*LnnSetLocalChannelInfoFunc)(LnnVapType type, int32_t channelId);
typedef bool (*IsCloudSyncEnabledFunc)(void);
typedef bool (*IsPowerControlEnabledFunc)(void);
typedef int32_t (*LnnRequestCheckOnlineStatusFunc)(const char *networkId, uint64_t timeout);
typedef bool (*IsSupportLowLatencyFunc)(const TransReqInfo *reqInfo, const LaneLinkInfo *laneLinkInfo);
typedef int32_t (*LnnInitQosFunc)(void);
typedef void (*LnnDeinitQosFunc)(void);
typedef int32_t (*LnnRegPeriodAdjustmentCallbackFunc)(OnStatsPeriodAdjustment callback);
typedef void (*LnnReportLaneIdStatsInfoFunc)(const LaneIdStatsInfo *statsList, uint32_t listSize);
typedef void (*LnnReportRippleDataFunc)(uint64_t laneId, const LnnRippleData *data);
typedef int32_t (*LnnRequestQosOptimizationFunc)(const uint64_t *laneIdList, uint32_t listSize,
    int32_t *result, uint32_t resultSize);
typedef void (*LnnCancelQosOptimizationFunc)(const uint64_t *laneIdList, uint32_t listSize);
typedef int32_t (*LnnInitMetaNodeFunc)(void);
typedef void (*LnnDeinitMetaNodeFunc)(void);
typedef int32_t (*LnnInitMetaNodeExtLedgerFunc)(void);
typedef void (*LnnDeinitMetaNodeExtLedgerFunc)(void);
typedef void (*ClearMetaNodeRequestByPidFunc)(const char *pkgName, int32_t pid);
typedef bool (*IsSupportMcuFeatureFunc)(void);
typedef void (*LnnSendDeviceStateToMcuFunc)(void *para);
typedef int32_t (*LnnInitMcuFunc)(void);

/* lnn_cipherkey_manager.h */
typedef int32_t (*LnnInitCipherKeyManagerFunc)(void);
typedef void (*LnnDeinitCipherKeyManagerFunc)(void);
typedef bool (*GetCipherKeyByNetworkIdFunc)(const char *networkId,
                                            int32_t seq, uint32_t tableIndex,
                                            AesCtrCipherKey *cipherkey, int32_t keyLen);
typedef bool (*GetLocalCipherKeyFunc)(int32_t seq, uint32_t *tableIndex, AesCtrCipherKey *cipherkey, int32_t keyLen);
typedef void (*LoadBleBroadcastKeyFunc)(void);
typedef bool (*IsCipherManagerFindKeyFunc)(const char *udid);
typedef bool (*PackCipherKeySyncMsgFunc)(void *json);
typedef void (*ProcessCipherKeySyncInfoFunc)(const void *json, const char *networkId);
typedef int32_t (*LnnLoadLocalBroadcastCipherKeyFunc)(void);
typedef int32_t (*LnnGetLocalBroadcastCipherKeyFunc)(BroadcastCipherKey *broadcastKey);
typedef int32_t (*LnnSaveLocalBroadcastCipherKeyFunc)(const BroadcastCipherKey *broadcastKey);
typedef int32_t (*LnnUpdateLocalBroadcastCipherKeyFunc)(BroadcastCipherKey *broadcastKey);
typedef int32_t (*LnnGetLocalBroadcastCipherInfoFunc)(CloudSyncInfo *info);
typedef int32_t (*LnnSetRemoteBroadcastCipherInfoFunc)(const char *value, const char *udid);

/* lnn_device_info_recovery.h */
typedef int32_t (*LnnLoadLocalDeviceInfoFunc)(void);
typedef int32_t (*LnnLoadRemoteDeviceInfoFunc)(void);
typedef int32_t (*LnnSaveLocalDeviceInfoFunc)(const NodeInfo *deviceInfo);
typedef int32_t (*LnnGetLocalDevInfoFunc)(NodeInfo *deviceInfo);
typedef int32_t (*LnnGetAllRemoteDevInfoFunc)(NodeInfo **info, int32_t *nums);
typedef int32_t (*LnnSaveRemoteDeviceInfoFunc)(const NodeInfo *deviceInfo);
typedef int32_t (*LnnUpdateRemoteDeviceInfoFunc)(const NodeInfo *deviceInfo);
typedef int32_t (*LnnRetrieveDeviceInfoFunc)(const char *udid, NodeInfo *deviceInfo);
typedef int32_t (*LnnRetrieveDeviceInfoByNetworkIdFunc)(const char *networkId, NodeInfo *info);
typedef void (*LnnDeleteDeviceInfoFunc)(const char *udid);
typedef void (*ClearDeviceInfoFunc)(void);
typedef int32_t (*LnnGetUdidByBrMacFunc)(const char *brMac, char *udid, uint32_t udidLen);
typedef int32_t (*LnnGetLocalCacheNodeInfoFunc)(NodeInfo *info);
typedef int32_t (*LnnLoadLocalDeviceAccountIdInfoFunc)(void);
typedef int32_t (*LnnGetAccountIdFromLocalCacheFunc)(int64_t *buf);
typedef int32_t (*LnnPackCloudSyncDeviceInfoFunc)(cJSON *json, const NodeInfo *cloudSyncInfo);
typedef int32_t (*LnnUnPackCloudSyncDeviceInfoFunc)(cJSON *json, NodeInfo *cloudSyncInfo);
typedef void (*LnnUpdateAuthExchangeUdidFunc)(void);
typedef void (*LnnClearAuthExchangeUdidFunc)(const char *networkId);

/* lnn_fast_offline.h */
typedef int32_t (*LnnInitFastOfflineFunc)(void);
typedef int32_t (*LnnDeviceCloudConvergenceInitFunc)(void);
typedef void (*LnnDeinitFastOfflineFunc)(void);
typedef int32_t (*LnnSendNotTrustedInfoFunc)(const NotTrustedDelayInfo *info,
                                             uint32_t num, LnnSyncInfoMsgComplete complete);
typedef int32_t (*LnnBleFastOfflineOnceBeginFunc)(void);
typedef void (*LnnIpAddrChangeEventHandlerFunc)(void);
typedef void (*EhLoginEventHandlerFunc)(void);

typedef int32_t (*LnnInitPtkFunc)(void);
typedef void (*LnnDeinitPtkFunc)(void);
typedef int32_t (*LnnGetLocalPtkByUuidFunc)(const char *uuid, char *localPtk, uint32_t len);
typedef int32_t (*LnnGetLocalDefaultPtkByUuidFunc)(const char *uuid, char *localPtk, uint32_t len);
typedef int32_t (*LnnGetRemoteDefaultPtkByUuidFunc)(const char *uuid, char *remotePtk, uint32_t len);
typedef void (*LnnLoadPtkInfoFunc)(void);
typedef int32_t (*LnnSyncPtkFunc)(const char *networkId);
typedef int32_t (*UpdateLocalPtkIfValidFunc)(char *uuid);
typedef int32_t (*LnnGenerateLocalPtkFunc)(char *udid, char *uuid);
typedef int32_t (*LnnGetMetaPtkFunc)(uint32_t connId, char *metaPtk, uint32_t len);

typedef int32_t (*LnnSaveDeviceDataFunc)(const char *data, LnnDataType dataType);
typedef int32_t (*LnnAsyncSaveDeviceDataFunc)(const char *data, LnnDataType dataType);
typedef int32_t (*LnnRetrieveDeviceDataFunc)(LnnDataType dataType, char **data, uint32_t *dataLen);
typedef int32_t (*LnnUpdateDeviceDataFunc)(const char *data, LnnDataType dataType);
typedef int32_t (*LnnDeleteDeviceDataFunc)(LnnDataType dataType);
typedef int32_t (*LnnLinkFinderInitFunc)(void);
typedef int32_t (*LnnUpdateLinkFinderInfoFunc)(void);
typedef int32_t (*LnnRemoveLinkFinderInfoFunc)(const char *networkId);
typedef int32_t (*LnnInsertLinkFinderInfoFunc)(const char *networkId);

typedef int32_t (*AuthFindDeviceKeyFunc)(const char *udidHash, int32_t keyType, AuthDeviceKeyInfo *deviceKey);
typedef void (*AuthRemoveDeviceKeyByUdidFunc)(const char *udidOrHash);
typedef void (*RegisterOOBEMonitorFunc)(void *para);
typedef void (*LnnInitOOBEStateMonitorImplFunc)(void);
typedef int32_t (*LnnGetOOBEStateFunc)(SoftBusOOBEState *state);
typedef void (*AuthLoadDeviceKeyFunc)(void);
typedef int32_t (*AuthFindLatestNormalizeKeyFunc)(const char *udidHash, AuthDeviceKeyInfo *deviceKey, bool clearOldKey);
typedef int32_t (*AuthFindNormalizeKeyByServerSideFunc)(const char *udidHash,
                                                        bool isServer, AuthDeviceKeyInfo *deviceKey);
typedef void (*AuthUpdateCreateTimeFunc)(const char *udidHash, int32_t keyType, bool isServer);
typedef bool (*IsSupportUDIDAbatementFunc)(void);
typedef int32_t (*AuthMetaGetConnIdByInfoFunc)(const AuthConnInfo *connInfo, uint32_t *connectionId);
typedef void (*FreeSoftbusChainFunc)(SoftbusCertChain *softbusCertChain);
typedef int32_t (*InitSoftbusChainFunc)(SoftbusCertChain *softbusCertChain);
typedef int32_t (*AuthMetaOpenConnFunc)(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback);
typedef int32_t (*AuthMetaPostTransDataFunc)(int64_t authId, const AuthTransData *dataInfo);
typedef void (*AuthMetaCloseConnFunc)(int64_t authId);
typedef int32_t (*AuthMetaGetPreferConnInfoFunc)(const char *uuid, AuthConnInfo *connInfo);
typedef int64_t (*AuthMetaGetIdByConnInfoFunc)(const AuthConnInfo *connInfo, bool isServer);
typedef int64_t (*AuthMetaGetIdByUuidFunc)(const char *uuid, AuthLinkType type, bool isServer);
typedef int64_t (*AuthMetaGetIdByIpFunc)(const char *ip);
typedef int32_t (*AuthMetaEncryptFunc)(int64_t authId, const uint8_t *inData, uint32_t inLen,
    uint8_t *outData, uint32_t *outLen);
typedef int32_t (*AuthMetaDecryptFunc)(int64_t authId, const uint8_t *inData, uint32_t inLen,
    uint8_t *outData, uint32_t *outLen);
typedef int32_t (*AuthMetaSetP2pMacFunc)(int64_t authId, const char *p2pMac);
typedef int32_t (*AuthMetaGetConnInfoFunc)(int64_t authId, AuthConnInfo *connInfo);
typedef int32_t (*AuthMetaGetDeviceUuidFunc)(int64_t authId, char *uuid, uint16_t size);
typedef int32_t (*AuthMetaGetServerSideFunc)(int64_t authId, bool *isServer);
typedef void (*AuthMetaCheckMetaExistFunc)(const AuthConnInfo *connInfo, bool *isExist);
typedef void (*AuthMetaDeinitFunc)(void);
typedef void (*DelAuthMetaManagerByPidFunc)(const char *pkgName, int32_t pid);
typedef int32_t (*LnnSyncTrustedRelationShipFunc)(const char *pkgName, const char *msg, uint32_t msgLen);
typedef int32_t (*LnnGetCurrChannelScoreFunc)(int32_t channelId);
typedef int32_t (*CustomizedSecurityProtocolInitFunc)(void);
typedef void (*CustomizedSecurityProtocolDeinitFunc)(void);
typedef int32_t (*AuthInsertDeviceKeyFunc)(const NodeInfo *deviceInfo,
                                           const AuthDeviceKeyInfo *deviceKey, AuthLinkType type);
typedef void (*AuthUpdateKeyIndexFunc)(const char *udidHash, int32_t keyType, int64_t index, bool isServer);
typedef bool (*CalcHKDFFunc)(const uint8_t *ikm, uint32_t ikmLen, uint8_t *out, uint32_t outLen);
typedef int32_t (*LnnRetrieveDeviceInfoByUdidFunc)(const char *udid, NodeInfo *deviceInfo);
typedef int32_t (*LnnSyncBleOfflineMsgFunc)(void);
typedef int32_t (*LnnInitBroadcastLinkKeyFunc)(void);
typedef void (*LnnDeinitBroadcastLinkKeyFunc)(void);
typedef bool (*IsNeedSyncBroadcastLinkKeyFunc)(const char *networkId);
typedef int32_t (*LnnSyncBroadcastLinkKeyFunc)(const char *networkId);
typedef bool (*HaveConcurrencyPreLinkReqIdByReuseConnReqIdFunc)(uint32_t connReqId, bool isCheckPreLink);
typedef bool (*HaveConcurrencyPreLinkNodeByLaneReqIdFunc)(uint32_t laneReqId, bool isCheckPreLink);
typedef int32_t (*GetConcurrencyLaneReqIdByConnReqIdFunc)(uint32_t connReqId, uint32_t *laneReqId);
typedef void (*LnnFreePreLinkFunc)(void *para);
typedef int32_t (*GetConcurrencyLaneReqIdByActionIdFunc)(uint32_t actionId, uint32_t *laneReqId);
typedef int32_t (*UpdateConcurrencyReuseLaneReqIdByActionIdFunc)(uint32_t actionId, uint32_t reuseLaneReqId,
    uint32_t connRequestId);
typedef int32_t (*UpdateConcurrencyReuseLaneReqIdByUdidFunc)(const char *udidHash, uint32_t udidHashLen,
    uint32_t reuseLaneReqId, uint32_t connReqId);
typedef int32_t (*LnnPackCloudSyncAckSeqFunc)(cJSON *json, char *peerudid);
typedef void (*LnnClearPtkListFunc)(void);
typedef int32_t (*GenerateNewLocalCipherKeyFunc)(void);
typedef int32_t (*InitActionBleConcurrencyFunc)(void);
typedef int32_t (*InitActionStateAdapterFunc)(void);
typedef int32_t (*RegistAuthTransListenerFunc)(void);
typedef void (*LnnUnregSleRangeCbFunc)(void);
typedef void (*LnnRegSleRangeCbFunc)(const ISleRangeInnerCallback *callback);
typedef int32_t (*LnnStopRangeFunc)(const RangeConfig *config);
typedef int32_t (*LnnStartRangeFunc)(const RangeConfig *config);
typedef int32_t (*UnregistAuthTransListenerFunc)(void);
typedef void (*SleRangeDeathCallbackFunc)(void);
typedef int32_t (*LnnInitUsbChannelManagerFunc)(void);
typedef void (*LnnDeinitUsbChannelManagerFunc)(void);
typedef bool (*IsDeviceHasRiskFactorFunc)(void);
typedef void (*CheckNeedCloudSyncOfflineFunc)(DiscoveryType type);
typedef int32_t (*LnnVirtualLinkInitFunc)(void);
typedef void (*LnnVirtualLinkDeinitFunc)(void);
typedef int32_t (*DcTriggerVirtualLinkFunc)(const char *peerNetworkId);
typedef int32_t (*LnnInitDecisionCenterV2Func)(void);
typedef void (*LnnDeinitDecisionCenterV2Func)(void);
typedef void (*SdMgrDeathCallbackFunc)(const char *pkgName);
typedef int32_t (*AuthMetaGetIpByMetaNodeIdFunc)(const char *metaNodeId, char *ip, int32_t len);
typedef int32_t (*AuthMetaGetLocalIpByMetaNodeIdFunc)(const char *metaNodeId, char *localIp, int32_t len);
typedef int32_t (*AuthMetaGetConnectionTypeByMetaNodeIdFunc)(const char *metaNodeId,
    NetworkConnectionType *connectionType);

typedef struct TagLnnEnhanceFuncList {
    // time_sync
    LnnTimeSyncImplInitFunc lnnTimeSyncImplInit;
    LnnTimeChangeNotifyFunc lnnTimeChangeNotify;
    LnnTimeSyncImplDeinitFunc lnnTimeSyncImplDeinit;
    LnnStartTimeSyncImplFunc lnnStartTimeSyncImpl;
    LnnStopTimeSyncImplFunc lnnStopTimeSyncImpl;
    // decision_center
    LnnInitDecisionCenterFunc lnnInitDecisionCenter;
    LnnDeinitDecisionCenterFunc lnnDeinitDecisionCenter;
    LnnDcSubscribeFunc lnnDcSubscribe;
    LnnDcUnsubscribeFunc lnnDcUnsubscribe;
    LnnDcDispatchEventFunc lnnDcDispatchEvent;
    TriggerSparkGroupBuildFunc triggerSparkGroupBuild;
    TriggerSparkGroupClearFunc triggerSparkGroupClear;
    TriggerSparkGroupJoinAgainFunc triggerSparkGroupJoinAgain;
    InitControlPlaneFunc initControlPlane;
    DeinitControlPlaneFunc deinitControlPlane;
    QueryControlPlaneNodeValidFunc queryControlPlaneNodeValid;
    LnnDumpControlLaneGroupInfoFunc lnnDumpControlLaneGroupInfo;
    IsSparkGroupEnabledFunc isSparkGroupEnabled;
    // sle range
    RegistAuthTransListenerFunc registAuthTransListener;
    UnregistAuthTransListenerFunc unregistAuthTransListener;
    LnnUnregSleRangeCbFunc lnnUnregSleRangeCb;
    LnnStopRangeFunc lnnStopRange;
    LnnStartRangeFunc lnnStartRange;
    LnnRegSleRangeCbFunc lnnRegSleRangeCb;
    SleRangeDeathCallbackFunc sleRangeDeathCallback;
    // disc_mgr
    LnnDestroyCoapConnectListFunc lnnDestroyCoapConnectList;
    LnnCoapConnectFunc lnnCoapConnect;
    LnnCoapConnectInitFunc lnnCoapConnectInit;
    LnnCoapConnectDeinitFunc lnnCoapConnectDeinit;
    // heartbeat
    HbUpdateBleScanFilterFunc hbUpdateBleScanFilter;
    HbGenerateBitPositionFunc hbGenerateBitPosition;
    LnnSendBroadcastInfoToLpFunc lnnSendBroadcastInfoToLp;
    LnnBleHbRegDataLevelChangeCbFunc lnnBleHbRegDataLevelChangeCb;
    LnnBleHbUnregDataLevelChangeCbFunc lnnBleHbUnregDataLevelChangeCb;
    LnnAdjustScanPolicyFunc lnnAdjustScanPolicy;
    HbBuildUserIdCheckSumFunc hbBuildUserIdCheckSum;
    EncryptUserIdFunc encryptUserId;
    DecryptUserIdFunc decryptUserId;
    LnnRegisterBleLpDeviceMediumMgrFunc lnnRegisterBleLpDeviceMediumMgr;
    LnnRegisterSleHeartbeatMediumMgrFunc lnnRegisterSleHeartbeatMediumMgr;
    SendDeviceStateToMlpsFunc sendDeviceStateToMlps;
    UpdateLocalDeviceInfoToMlpsFunc updateLocalDeviceInfoToMlps;
    UpdateRemoteDeviceInfoToMlpsFunc updateRemoteDeviceInfoToMlps;
    UpdateRemoteDeviceInfoListToMlpsFunc updateRemoteDeviceInfoListToMlps;
    GetBurstAdvIdFunc getBurstAdvId;
    SendDeviceInfoToSHByTypeFunc sendDeviceInfoToSHByType;
    SendAdvInfoToMlpsFunc sendAdvInfoToMlps;
    SwitchHeartbeatReportChannelFunc switchHeartbeatReportChannel;
    IsSupportLpFeatureFunc isSupportLpFeature;
    LnnIsSupportLpSparkFeatureFunc lnnIsSupportLpSparkFeature;
    IsFeatureSupportDetailFunc isFeatureSupportDetail;
    SetLpKeepAliveStateFunc setLpKeepAliveState;
    LnnRegistBleHeartbeatMediumMgrFunc lnnRegistBleHeartbeatMediumMgr;
    LnnRequestCheckOnlineStatusFunc lnnRequestCheckOnlineStatus;
    IsSupportMcuFeatureFunc isSupportMcuFeature;
    LnnSendDeviceStateToMcuFunc lnnSendDeviceStateToMcu;
    LnnInitMcuFunc lnnInitMcu;
    // lane_manager
    EnablePowerControlFunc enablePowerControl;
    DisablePowerControlFunc disablePowerControl;
    LnnDeinitScoreFunc lnnDeinitScore;
    LnnInitScoreFunc lnnInitScore;
    LnnStartScoringFunc lnnStartScoring;
    LnnStopScoringFunc lnnStopScoring;
    LnnGetWlanLinkedInfoFunc lnnGetWlanLinkedInfo;
    LnnGetAllChannelScoreFunc lnnGetAllChannelScore;
    LnnInitVapInfoFunc lnnInitVapInfo;
    LnnDeinitVapInfoFunc lnnDeinitVapInfo;
    LnnAddLocalVapInfoFunc lnnAddLocalVapInfo;
    LnnDeleteLocalVapInfoFunc lnnDeleteLocalVapInfo;
    LnnGetLocalVapInfoFunc lnnGetLocalVapInfo;
    LnnAddRemoteVapInfoFunc lnnAddRemoteVapInfo;
    LnnDeleteRemoteVapInfoFunc lnnDeleteRemoteVapInfo;
    LnnGetRemoteVapInfoFunc lnnGetRemoteVapInfo;
    LnnGetLocalPreferChannelFunc lnnGetLocalPreferChannel;
    LnnGetLocalChannelCodeFunc lnnGetLocalChannelCode;
    LnnAddRemoteChannelCodeFunc lnnAddRemoteChannelCode;
    LnnGetRecommendChannelFunc lnnGetRecommendChannel;
    IsCloudSyncEnabledFunc isCloudSyncEnabled;
    IsPowerControlEnabledFunc isPowerControlEnabled;
    LnnGetCurrChannelScoreFunc lnnGetCurrChannelScore;
    // lane_low_latency
    IsSupportLowLatencyFunc isSupportLowLatency;
    // lane_qos
    LnnInitQosFunc lnnInitQos;
    LnnDeinitQosFunc lnnDeinitQos;
    LnnRegPeriodAdjustmentCallbackFunc lnnRegPeriodAdjustmentCallback;
    LnnReportLaneIdStatsInfoFunc lnnReportLaneIdStatsInfo;
    LnnReportRippleDataFunc lnnReportRippleData;
    LnnRequestQosOptimizationFunc lnnRequestQosOptimization;
    LnnCancelQosOptimizationFunc lnnCancelQosOptimization;
    // meta_node
    LnnInitMetaNodeFunc lnnInitMetaNode;
    LnnInitMetaNodeExtLedgerFunc lnnInitMetaNodeExtLedger;
    LnnDeinitMetaNodeExtLedgerFunc lnnDeinitMetaNodeExtLedger;
    ClearMetaNodeRequestByPidFunc clearMetaNodeRequestByPid;
    LnnDeinitMetaNodeFunc lnnDeinitMetaNode;
    // net_builder
    LnnInitCipherKeyManagerFunc lnnInitCipherKeyManager;
    LnnDeinitCipherKeyManagerFunc lnnDeinitCipherKeyManager;
    GetCipherKeyByNetworkIdFunc getCipherKeyByNetworkId;
    GetLocalCipherKeyFunc getLocalCipherKey;
    LoadBleBroadcastKeyFunc loadBleBroadcastKey;
    IsCipherManagerFindKeyFunc isCipherManagerFindKey;
    PackCipherKeySyncMsgFunc packCipherKeySyncMsg;
    ProcessCipherKeySyncInfoFunc processCipherKeySyncInfo;
    LnnLoadLocalBroadcastCipherKeyFunc lnnLoadLocalBroadcastCipherKey;
    LnnGetLocalBroadcastCipherKeyFunc lnnGetLocalBroadcastCipherKey;
    LnnSaveLocalBroadcastCipherKeyFunc lnnSaveLocalBroadcastCipherKey;
    LnnUpdateLocalBroadcastCipherKeyFunc lnnUpdateLocalBroadcastCipherKey;
    LnnGetLocalBroadcastCipherInfoFunc lnnGetLocalBroadcastCipherInfo;
    LnnSetRemoteBroadcastCipherInfoFunc lnnSetRemoteBroadcastCipherInfo;
    LnnLoadLocalDeviceInfoFunc lnnLoadLocalDeviceInfo;
    LnnLoadRemoteDeviceInfoFunc lnnLoadRemoteDeviceInfo;
    LnnSaveLocalDeviceInfoFunc lnnSaveLocalDeviceInfo;
    LnnGetLocalDevInfoFunc lnnGetLocalDevInfo;
    LnnGetAllRemoteDevInfoFunc lnnGetAllRemoteDevInfo;
    LnnSaveRemoteDeviceInfoFunc lnnSaveRemoteDeviceInfo;
    LnnUpdateRemoteDeviceInfoFunc lnnUpdateRemoteDeviceInfo;
    LnnRetrieveDeviceInfoFunc lnnRetrieveDeviceInfo;
    LnnRetrieveDeviceInfoByNetworkIdFunc lnnRetrieveDeviceInfoByNetworkId;
    LnnDeleteDeviceInfoFunc lnnDeleteDeviceInfo;
    ClearDeviceInfoFunc clearDeviceInfo;
    LnnGetUdidByBrMacFunc lnnGetUdidByBrMac;
    LnnGetLocalCacheNodeInfoFunc lnnGetLocalCacheNodeInfo;
    LnnLoadLocalDeviceAccountIdInfoFunc lnnLoadLocalDeviceAccountIdInfo;
    LnnGetAccountIdFromLocalCacheFunc lnnGetAccountIdFromLocalCache;
    LnnPackCloudSyncDeviceInfoFunc lnnPackCloudSyncDeviceInfo;
    LnnUnPackCloudSyncDeviceInfoFunc lnnUnPackCloudSyncDeviceInfo;
    LnnUpdateAuthExchangeUdidFunc lnnUpdateAuthExchangeUdid;
    LnnClearAuthExchangeUdidFunc lnnClearAuthExchangeUdid;
    LnnInitFastOfflineFunc lnnInitFastOffline;
    LnnDeviceCloudConvergenceInitFunc lnnDeviceCloudConvergenceInit;
    LnnDeinitFastOfflineFunc lnnDeinitFastOffline;
    LnnSendNotTrustedInfoFunc lnnSendNotTrustedInfo;
    LnnBleFastOfflineOnceBeginFunc lnnBleFastOfflineOnceBegin;
    LnnIpAddrChangeEventHandlerFunc lnnIpAddrChangeEventHandler;
    EhLoginEventHandlerFunc ehLoginEventHandler;
    LnnInitPtkFunc lnnInitPtk;
    LnnDeinitPtkFunc lnnDeinitPtk;
    LnnGetLocalDefaultPtkByUuidFunc lnnGetLocalDefaultPtkByUuid;
    LnnGetRemoteDefaultPtkByUuidFunc lnnGetRemoteDefaultPtkByUuid;
    LnnLoadPtkInfoFunc lnnLoadPtkInfo;
    LnnSyncPtkFunc lnnSyncPtk;
    UpdateLocalPtkIfValidFunc updateLocalPtkIfValid;
    LnnGenerateLocalPtkFunc lnnGenerateLocalPtk;
    LnnGetMetaPtkFunc lnnGetMetaPtk;
    LnnGetLocalPtkByUuidFunc lnnGetLocalPtkByUuid;
    LnnSyncTrustedRelationShipFunc lnnSyncTrustedRelationShip;
    LnnRetrieveDeviceInfoByUdidFunc lnnRetrieveDeviceInfoByUdid;
    LnnSyncBleOfflineMsgFunc lnnSyncBleOfflineMsg;
    LnnInitBroadcastLinkKeyFunc lnnInitBroadcastLinkKey;
    LnnDeinitBroadcastLinkKeyFunc lnnDeinitBroadcastLinkKey;
    IsNeedSyncBroadcastLinkKeyFunc isNeedSyncBroadcastLinkKey;
    LnnSyncBroadcastLinkKeyFunc lnnSyncBroadcastLinkKey;
    IsDeviceHasRiskFactorFunc isDeviceHasRiskFactor;
    // bus_center
    LnnSaveDeviceDataFunc lnnSaveDeviceData;
    LnnAsyncSaveDeviceDataFunc lnnAsyncSaveDeviceData;
    LnnRetrieveDeviceDataFunc lnnRetrieveDeviceData;
    LnnUpdateDeviceDataFunc lnnUpdateDeviceData;
    GetConcurrencyLaneReqIdByConnReqIdFunc getConcurrencyLaneReqIdByConnReqId;
    HaveConcurrencyPreLinkReqIdByReuseConnReqIdFunc haveConcurrencyPreLinkReqIdByReuseConnReqId;
    HaveConcurrencyPreLinkNodeByLaneReqIdFunc haveConcurrencyPreLinkNodeByLaneReqId;
    GetConcurrencyLaneReqIdByActionIdFunc getConcurrencyLaneReqIdByActionId;
    LnnFreePreLinkFunc lnnFreePreLink;
    UpdateConcurrencyReuseLaneReqIdByActionIdFunc updateConcurrencyReuseLaneReqIdByActionId;
    UpdateConcurrencyReuseLaneReqIdByUdidFunc updateConcurrencyReuseLaneReqIdByUdid;
    LnnPackCloudSyncAckSeqFunc lnnPackCloudSyncAckSeq;
    LnnClearPtkListFunc lnnClearPtkList;
    GenerateNewLocalCipherKeyFunc generateNewLocalCipherKey;
    InitActionBleConcurrencyFunc initActionBleConcurrency;
    InitActionStateAdapterFunc initActionStateAdapter;
    // adapter bus_center
    LnnDeleteDeviceDataFunc lnnDeleteDeviceData;
    LnnLinkFinderInitFunc lnnLinkFinderInit;
    LnnUpdateLinkFinderInfoFunc lnnUpdateLinkFinderInfo;
    LnnRemoveLinkFinderInfoFunc lnnRemoveLinkFinderInfo;
    LnnInsertLinkFinderInfoFunc lnnInsertLinkFinderInfo;
    RegisterOOBEMonitorFunc registerOOBEMonitor;
    LnnInitOOBEStateMonitorImplFunc lnnInitOOBEStateMonitorImpl;
    LnnGetOOBEStateFunc lnnGetOOBEState;
    // auth
    AuthFindDeviceKeyFunc authFindDeviceKey;
    AuthRemoveDeviceKeyByUdidFunc authRemoveDeviceKeyByUdid;
    AuthLoadDeviceKeyFunc authLoadDeviceKey;
    AuthFindLatestNormalizeKeyFunc authFindLatestNormalizeKey;
    AuthFindNormalizeKeyByServerSideFunc authFindNormalizeKeyByServerSide;
    AuthUpdateCreateTimeFunc authUpdateCreateTime;
    IsSupportUDIDAbatementFunc isSupportUDIDAbatement;
    AuthMetaGetConnIdByInfoFunc authMetaGetConnIdByInfo;
    FreeSoftbusChainFunc freeSoftbusChain;
    InitSoftbusChainFunc initSoftbusChain;
    AuthMetaOpenConnFunc authMetaOpenConn;
    AuthMetaPostTransDataFunc authMetaPostTransData;
    AuthMetaCloseConnFunc authMetaCloseConn;
    AuthMetaGetPreferConnInfoFunc authMetaGetPreferConnInfo;
    AuthMetaGetIdByConnInfoFunc authMetaGetIdByConnInfo;
    AuthMetaGetIdByUuidFunc authMetaGetIdByUuid;
    AuthMetaGetIdByIpFunc authMetaGetIdByIp;
    AuthMetaEncryptFunc authMetaEncrypt;
    AuthMetaDecryptFunc authMetaDecrypt;
    AuthMetaSetP2pMacFunc authMetaSetP2pMac;
    AuthMetaGetConnInfoFunc authMetaGetConnInfo;
    AuthMetaGetDeviceUuidFunc authMetaGetDeviceUuid;
    AuthMetaGetServerSideFunc authMetaGetServerSide;
    AuthMetaCheckMetaExistFunc authMetaCheckMetaExist;
    AuthMetaDeinitFunc authMetaDeinit;
    DelAuthMetaManagerByPidFunc delAuthMetaManagerByPid;
    AuthInsertDeviceKeyFunc authInsertDeviceKey;
    AuthUpdateKeyIndexFunc authUpdateKeyIndex;
    CalcHKDFFunc calcHKDF;
    // ccmp
    CustomizedSecurityProtocolInitFunc customizedSecurityProtocolInit;
    CustomizedSecurityProtocolDeinitFunc customizedSecurityProtocolDeinit;

    //usb
    LnnInitUsbChannelManagerFunc lnnInitUsbChannelManager;
    LnnDeinitUsbChannelManagerFunc lnnDeinitUsbChannelManager;
    CheckNeedCloudSyncOfflineFunc checkNeedCloudSyncOffline;

    // virtual link
    LnnGetLocalChannelInfoFunc lnnGetLocalChannelInfo;
    LnnSetLocalChannelInfoFunc lnnSetLocalChannelInfo;
    LnnVirtualLinkInitFunc lnnVirtualLinkInit;
    LnnVirtualLinkDeinitFunc lnnVirtualLinkDeinit;
    DcTriggerVirtualLinkFunc dcTriggerVirtualLink;
    LnnInitDecisionCenterV2Func lnnInitDecisionCenterV2;
    LnnDeinitDecisionCenterV2Func lnnDeinitDecisionCenterV2;
    SdMgrDeathCallbackFunc sdMgrDeathCallback;

    // HA interconnection
    AuthMetaGetIpByMetaNodeIdFunc authMetaGetIpByMetaNodeId;
    AuthMetaGetLocalIpByMetaNodeIdFunc authMetaGetLocalIpByMetaNodeId;
    AuthMetaGetConnectionTypeByMetaNodeIdFunc authMetaGetConnectionTypeByMetaNodeId;
} LnnEnhanceFuncList;

LnnEnhanceFuncList *LnnEnhanceFuncListGet(void);
int32_t LnnRegisterEnhanceFunc(void *soHandle);

#ifdef __cplusplus
}
#endif

#endif