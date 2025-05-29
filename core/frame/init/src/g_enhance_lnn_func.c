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

#include "g_enhance_lnn_func.h"

#include <securec.h>
#include <dlfcn.h>

#include "lnn_log.h"

LnnEnhanceFuncList g_lnnEnhanceFuncList = { NULL };

LnnEnhanceFuncList *LnnEnhanceFuncListGet(void)
{
    return &g_lnnEnhanceFuncList;
}

int32_t LnnRegisterEnhanceFunc(void *soHandle)
{
    LnnTimeSyncImplInitFunc lnnTimeSyncImplInit = dlsym(soHandle, "LnnTimeSyncImplInit");
    g_lnnEnhanceFuncList.lnnTimeSyncImplInit = lnnTimeSyncImplInit;

    LnnTimeSyncImplDeinitFunc lnnTimeSyncImplDeinit = dlsym(soHandle, "LnnTimeSyncImplDeinit");
    g_lnnEnhanceFuncList.lnnTimeSyncImplDeinit = lnnTimeSyncImplDeinit;

    LnnStartTimeSyncImplFunc lnnStartTimeSyncImpl = dlsym(soHandle, "LnnStartTimeSyncImpl");
    g_lnnEnhanceFuncList.lnnStartTimeSyncImpl = lnnStartTimeSyncImpl;
    LnnStopTimeSyncImplFunc lnnStopTimeSyncImpl = dlsym(soHandle, "LnnStopTimeSyncImpl");
    g_lnnEnhanceFuncList.lnnStopTimeSyncImpl = lnnStopTimeSyncImpl;
    LnnInitDecisionCenterFunc lnnInitDecisionCenter = dlsym(soHandle, "LnnInitDecisionCenter");
    g_lnnEnhanceFuncList.lnnInitDecisionCenter = lnnInitDecisionCenter;
    LnnDeinitDecisionCenterFunc lnnDeinitDecisionCenter = dlsym(soHandle, "LnnDeinitDecisionCenter");
    g_lnnEnhanceFuncList.lnnDeinitDecisionCenter = lnnDeinitDecisionCenter;
    LnnDcSubscribeFunc lnnDcSubscribe = dlsym(soHandle, "LnnDcSubscribe");
    g_lnnEnhanceFuncList.lnnDcSubscribe = lnnDcSubscribe;
    LnnDcUnsubscribeFunc lnnDcUnsubscribe = dlsym(soHandle, "LnnDcUnsubscribe");
    g_lnnEnhanceFuncList.lnnDcUnsubscribe = lnnDcUnsubscribe;
    LnnDcDispatchEventFunc lnnDcDispatchEvent = dlsym(soHandle, "LnnDcDispatchEvent");
    g_lnnEnhanceFuncList.lnnDcDispatchEvent = lnnDcDispatchEvent;
    LnnDestroyCoapConnectListFunc lnnDestroyCoapConnectList = dlsym(soHandle, "LnnDestroyCoapConnectList");
    g_lnnEnhanceFuncList.lnnDestroyCoapConnectList = lnnDestroyCoapConnectList;
    LnnCoapConnectFunc lnnCoapConnect = dlsym(soHandle, "LnnCoapConnect");
    g_lnnEnhanceFuncList.lnnCoapConnect = lnnCoapConnect;
    LnnCoapConnectInitFunc lnnCoapConnectInit = dlsym(soHandle, "LnnCoapConnectInit");
    g_lnnEnhanceFuncList.lnnCoapConnectInit = lnnCoapConnectInit;
    LnnCoapConnectDeinitFunc lnnCoapConnectDeinit = dlsym(soHandle, "LnnCoapConnectDeinit");
    g_lnnEnhanceFuncList.lnnCoapConnectDeinit = lnnCoapConnectDeinit;
    HbUpdateBleScanFilterFunc hbUpdateBleScanFilter = dlsym(soHandle, "HbUpdateBleScanFilter");
    g_lnnEnhanceFuncList.hbUpdateBleScanFilter = hbUpdateBleScanFilter;
    HbGenerateBitPositionFunc hbGenerateBitPosition = dlsym(soHandle, "HbGenerateBitPosition");
    g_lnnEnhanceFuncList.hbGenerateBitPosition = hbGenerateBitPosition;
    LnnSendBroadcastInfoToLpFunc lnnSendBroadcastInfoToLp = dlsym(soHandle, "LnnSendBroadcastInfoToLp");
    g_lnnEnhanceFuncList.lnnSendBroadcastInfoToLp = lnnSendBroadcastInfoToLp;
    LnnBleHbRegDataLevelChangeCbFunc lnnBleHbRegDataLevelChangeCb = dlsym(soHandle, "LnnBleHbRegDataLevelChangeCb");
    g_lnnEnhanceFuncList.lnnBleHbRegDataLevelChangeCb = lnnBleHbRegDataLevelChangeCb;
    LnnBleHbUnregDataLevelChangeCbFunc lnnBleHbUnregDataLevelChangeCb = dlsym(soHandle,
        "LnnBleHbUnregDataLevelChangeCb");
    g_lnnEnhanceFuncList.lnnBleHbUnregDataLevelChangeCb = lnnBleHbUnregDataLevelChangeCb;
    LnnAdjustScanPolicyFunc lnnAdjustScanPolicy = dlsym(soHandle, "LnnAdjustScanPolicy");
    g_lnnEnhanceFuncList.lnnAdjustScanPolicy = lnnAdjustScanPolicy;
    HbBuildUserIdCheckSumFunc hbBuildUserIdCheckSum = dlsym(soHandle, "HbBuildUserIdCheckSum");
    g_lnnEnhanceFuncList.hbBuildUserIdCheckSum = hbBuildUserIdCheckSum;
    EncryptUserIdFunc encryptUserId = dlsym(soHandle, "EncryptUserId");
    g_lnnEnhanceFuncList.encryptUserId = encryptUserId;
    DecryptUserIdFunc decryptUserId = dlsym(soHandle, "DecryptUserId");
    g_lnnEnhanceFuncList.decryptUserId = decryptUserId;
    LnnRegisterBleLpDeviceMediumMgrFunc lnnRegisterBleLpDeviceMediumMgr = dlsym(soHandle,
        "LnnRegisterBleLpDeviceMediumMgr");
    g_lnnEnhanceFuncList.lnnRegisterBleLpDeviceMediumMgr = lnnRegisterBleLpDeviceMediumMgr;
    SendDeviceStateToMlpsFunc sendDeviceStateToMlps = dlsym(soHandle, "SendDeviceStateToMlps");
    g_lnnEnhanceFuncList.sendDeviceStateToMlps = sendDeviceStateToMlps;
    UpdateLocalDeviceInfoToMlpsFunc updateLocalDeviceInfoToMlps = dlsym(soHandle, "UpdateLocalDeviceInfoToMlps");
    g_lnnEnhanceFuncList.updateLocalDeviceInfoToMlps = updateLocalDeviceInfoToMlps;
    UpdateRemoteDeviceInfoToMlpsFunc updateRemoteDeviceInfoToMlps = dlsym(soHandle, "UpdateRemoteDeviceInfoToMlps");
    g_lnnEnhanceFuncList.updateRemoteDeviceInfoToMlps = updateRemoteDeviceInfoToMlps;
    UpdateRemoteDeviceInfoListToMlpsFunc updateRemoteDeviceInfoListToMlps = dlsym(soHandle,
        "UpdateRemoteDeviceInfoListToMlps");
    g_lnnEnhanceFuncList.updateRemoteDeviceInfoListToMlps = updateRemoteDeviceInfoListToMlps;
    GetBurstAdvIdFunc getBurstAdvId = dlsym(soHandle, "GetBurstAdvId");
    g_lnnEnhanceFuncList.getBurstAdvId = getBurstAdvId;
    SendDeviceInfoToSHByTypeFunc sendDeviceInfoToSHByType = dlsym(soHandle, "SendDeviceInfoToSHByType");
    g_lnnEnhanceFuncList.sendDeviceInfoToSHByType = sendDeviceInfoToSHByType;
    SendAdvInfoToMlpsFunc sendAdvInfoToMlps = dlsym(soHandle, "SendAdvInfoToMlps");
    g_lnnEnhanceFuncList.sendAdvInfoToMlps = sendAdvInfoToMlps;
    SwtichHeartbeatReportChannelFunc swtichHeartbeatReportChannel = dlsym(soHandle, "SwtichHeartbeatReportChannel");
    g_lnnEnhanceFuncList.swtichHeartbeatReportChannel = swtichHeartbeatReportChannel;
    IsSupportLpFeatureFunc isSupportLpFeature = dlsym(soHandle, "IsSupportLpFeature");
    g_lnnEnhanceFuncList.isSupportLpFeature = isSupportLpFeature;
    SetLpKeepAliveStateFunc setLpKeepAliveState = dlsym(soHandle, "SetLpKeepAliveState");
    g_lnnEnhanceFuncList.setLpKeepAliveState = setLpKeepAliveState;
    LnnRegistBleHeartbeatMediumMgrFunc lnnRegistBleHeartbeatMediumMgr = dlsym(soHandle,
        "LnnRegistBleHeartbeatMediumMgr");
    g_lnnEnhanceFuncList.lnnRegistBleHeartbeatMediumMgr = lnnRegistBleHeartbeatMediumMgr;
    EnablePowerControlFunc enablePowerControl = dlsym(soHandle, "EnablePowerControl");
    g_lnnEnhanceFuncList.enablePowerControl = enablePowerControl;
    DisablePowerControlFunc disablePowerControl = dlsym(soHandle, "DisablePowerControl");
    g_lnnEnhanceFuncList.disablePowerControl = disablePowerControl;
    LnnDeinitScoreFunc lnnDeinitScore = dlsym(soHandle, "LnnDeinitScore");
    g_lnnEnhanceFuncList.lnnDeinitScore = lnnDeinitScore;
    LnnInitScoreFunc lnnInitScore = dlsym(soHandle, "LnnInitScore");
    g_lnnEnhanceFuncList.lnnInitScore = lnnInitScore;
    LnnStartScoringFunc lnnStartScoring = dlsym(soHandle, "LnnStartScoring");
    g_lnnEnhanceFuncList.lnnStartScoring = lnnStartScoring;
    LnnStopScoringFunc lnnStopScoring = dlsym(soHandle, "LnnStopScoring");
    g_lnnEnhanceFuncList.lnnStopScoring = lnnStopScoring;
    LnnGetWlanLinkedInfoFunc lnnGetWlanLinkedInfo = dlsym(soHandle, "LnnGetWlanLinkedInfo");
    g_lnnEnhanceFuncList.lnnGetWlanLinkedInfo = lnnGetWlanLinkedInfo;
    LnnGetAllChannelScoreFunc lnnGetAllChannelScore = dlsym(soHandle, "LnnGetAllChannelScore");
    g_lnnEnhanceFuncList.lnnGetAllChannelScore = lnnGetAllChannelScore;
    LnnInitVapInfoFunc lnnInitVapInfo = dlsym(soHandle, "LnnInitVapInfo");
    g_lnnEnhanceFuncList.lnnInitVapInfo = lnnInitVapInfo;
    LnnDeinitVapInfoFunc lnnDeinitVapInfo = dlsym(soHandle, "LnnDeinitVapInfo");
    g_lnnEnhanceFuncList.lnnDeinitVapInfo = lnnDeinitVapInfo;
    LnnAddLocalVapInfoFunc lnnAddLocalVapInfo = dlsym(soHandle, "LnnAddLocalVapInfo");
    g_lnnEnhanceFuncList.lnnAddLocalVapInfo = lnnAddLocalVapInfo;
    LnnDeleteLocalVapInfoFunc lnnDeleteLocalVapInfo = dlsym(soHandle, "LnnDeleteLocalVapInfo");
    g_lnnEnhanceFuncList.lnnDeleteLocalVapInfo = lnnDeleteLocalVapInfo;
    LnnGetLocalVapInfoFunc lnnGetLocalVapInfo = dlsym(soHandle, "LnnGetLocalVapInfo");
    g_lnnEnhanceFuncList.lnnGetLocalVapInfo = lnnGetLocalVapInfo;
    LnnAddRemoteVapInfoFunc lnnAddRemoteVapInfo = dlsym(soHandle, "LnnAddRemoteVapInfo");
    g_lnnEnhanceFuncList.lnnAddRemoteVapInfo = lnnAddRemoteVapInfo;
    LnnDeleteRemoteVapInfoFunc lnnDeleteRemoteVapInfo = dlsym(soHandle, "LnnDeleteRemoteVapInfo");
    g_lnnEnhanceFuncList.lnnDeleteRemoteVapInfo = lnnDeleteRemoteVapInfo;
    LnnGetRemoteVapInfoFunc lnnGetRemoteVapInfo = dlsym(soHandle, "LnnGetRemoteVapInfo");
    g_lnnEnhanceFuncList.lnnGetRemoteVapInfo = lnnGetRemoteVapInfo;
    LnnGetLocalPreferChannelFunc lnnGetLocalPreferChannel = dlsym(soHandle, "LnnGetLocalPreferChannel");
    g_lnnEnhanceFuncList.lnnGetLocalPreferChannel = lnnGetLocalPreferChannel;
    LnnGetLocalChannelCodeFunc lnnGetLocalChannelCode = dlsym(soHandle, "LnnGetLocalChannelCode");
    g_lnnEnhanceFuncList.lnnGetLocalChannelCode = lnnGetLocalChannelCode;
    LnnAddRemoteChannelCodeFunc lnnAddRemoteChannelCode = dlsym(soHandle, "LnnAddRemoteChannelCode");
    g_lnnEnhanceFuncList.lnnAddRemoteChannelCode = lnnAddRemoteChannelCode;
    LnnGetRecommendChannelFunc lnnGetRecommendChannel = dlsym(soHandle, "LnnGetRecommendChannel");
    g_lnnEnhanceFuncList.lnnGetRecommendChannel = lnnGetRecommendChannel;
    IsCloudSyncEnabledFunc isCloudSyncEnabled = dlsym(soHandle, "IsCloudSyncEnabled");
    g_lnnEnhanceFuncList.isCloudSyncEnabled = isCloudSyncEnabled;
    IsPowerControlEnabledFunc isPowerControlEnabled = dlsym(soHandle, "IsPowerControlEnabled");
    g_lnnEnhanceFuncList.isPowerControlEnabled = isPowerControlEnabled;
    LnnRequestCheckOnlineStatusFunc lnnRequestCheckOnlineStatus = dlsym(soHandle, "LnnRequestCheckOnlineStatus");
    g_lnnEnhanceFuncList.lnnRequestCheckOnlineStatus = lnnRequestCheckOnlineStatus;
    LnnInitQosFunc lnnInitQos = dlsym(soHandle, "LnnInitQos");
    g_lnnEnhanceFuncList.lnnInitQos = lnnInitQos;
    LnnDeinitQosFunc lnnDeinitQos = dlsym(soHandle, "LnnDeinitQos");
    g_lnnEnhanceFuncList.lnnDeinitQos = lnnDeinitQos;
    LnnRegPeriodAdjustmentCallbackFunc lnnRegPeriodAdjustmentCallback = dlsym(soHandle,
        "LnnRegPeriodAdjustmentCallback");
    g_lnnEnhanceFuncList.lnnRegPeriodAdjustmentCallback = lnnRegPeriodAdjustmentCallback;
    LnnReportLaneIdStatsInfoFunc lnnReportLaneIdStatsInfo = dlsym(soHandle, "LnnReportLaneIdStatsInfo");
    g_lnnEnhanceFuncList.lnnReportLaneIdStatsInfo = lnnReportLaneIdStatsInfo;
    LnnReportRippleDataFunc lnnReportRippleData = dlsym(soHandle, "LnnReportRippleData");
    g_lnnEnhanceFuncList.lnnReportRippleData = lnnReportRippleData;
    LnnRequestQosOptimizationFunc lnnRequestQosOptimization = dlsym(soHandle, "LnnRequestQosOptimization");
    g_lnnEnhanceFuncList.lnnRequestQosOptimization = lnnRequestQosOptimization;
    LnnCancelQosOptimizationFunc lnnCancelQosOptimization = dlsym(soHandle, "LnnCancelQosOptimization");
    g_lnnEnhanceFuncList.lnnCancelQosOptimization = lnnCancelQosOptimization;
    LnnInitMetaNodeFunc lnnInitMetaNode = dlsym(soHandle, "LnnInitMetaNode");
    g_lnnEnhanceFuncList.lnnInitMetaNode = lnnInitMetaNode;
    LnnDeinitMetaNodeFunc lnnDeinitMetaNode = dlsym(soHandle, "LnnDeinitMetaNode");
    g_lnnEnhanceFuncList.lnnDeinitMetaNode = lnnDeinitMetaNode;
    LnnInitMetaNodeExtLedgerFunc lnnInitMetaNodeExtLedger = dlsym(soHandle, "LnnInitMetaNodeExtLedger");
    g_lnnEnhanceFuncList.lnnInitMetaNodeExtLedger = lnnInitMetaNodeExtLedger;
    LnnDeinitMetaNodeExtLedgerFunc lnnDeinitMetaNodeExtLedger = dlsym(soHandle, "LnnDeinitMetaNodeExtLedger");
    g_lnnEnhanceFuncList.lnnDeinitMetaNodeExtLedger = lnnDeinitMetaNodeExtLedger;
    ClearMetaNodeRequestByPidFunc clearMetaNodeRequestByPid = dlsym(soHandle, "ClearMetaNodeRequestByPid");
    g_lnnEnhanceFuncList.clearMetaNodeRequestByPid = clearMetaNodeRequestByPid;
    LnnInitCipherKeyManagerFunc lnnInitCipherKeyManager = dlsym(soHandle, "LnnInitCipherKeyManager");
    g_lnnEnhanceFuncList.lnnInitCipherKeyManager = lnnInitCipherKeyManager;
    LnnDeinitCipherKeyManagerFunc lnnDeinitCipherKeyManager = dlsym(soHandle, "LnnDeinitCipherKeyManager");
    g_lnnEnhanceFuncList.lnnDeinitCipherKeyManager = lnnDeinitCipherKeyManager;
    GetCipherKeyByNetworkIdFunc getCipherKeyByNetworkId = dlsym(soHandle, "GetCipherKeyByNetworkId");
    g_lnnEnhanceFuncList.getCipherKeyByNetworkId = getCipherKeyByNetworkId;
    GetLocalCipherKeyFunc getLocalCipherKey = dlsym(soHandle, "GetLocalCipherKey");
    g_lnnEnhanceFuncList.getLocalCipherKey = getLocalCipherKey;
    LoadBleBroadcastKeyFunc loadBleBroadcastKey = dlsym(soHandle, "LoadBleBroadcastKey");
    g_lnnEnhanceFuncList.loadBleBroadcastKey = loadBleBroadcastKey;
    IsCipherManagerFindKeyFunc isCipherManagerFindKey = dlsym(soHandle, "IsCipherManagerFindKey");
    g_lnnEnhanceFuncList.isCipherManagerFindKey = isCipherManagerFindKey;
    PackCipherKeySyncMsgFunc packCipherKeySyncMsg = dlsym(soHandle, "PackCipherKeySyncMsg");
    g_lnnEnhanceFuncList.packCipherKeySyncMsg = packCipherKeySyncMsg;
    ProcessCipherKeySyncInfoFunc processCipherKeySyncInfo = dlsym(soHandle, "ProcessCipherKeySyncInfo");
    g_lnnEnhanceFuncList.processCipherKeySyncInfo = processCipherKeySyncInfo;
    LnnLoadLocalBroadcastCipherKeyFunc lnnLoadLocalBroadcastCipherKey = dlsym(soHandle,
        "LnnLoadLocalBroadcastCipherKey");
    g_lnnEnhanceFuncList.lnnLoadLocalBroadcastCipherKey = lnnLoadLocalBroadcastCipherKey;
    LnnGetLocalBroadcastCipherKeyFunc lnnGetLocalBroadcastCipherKey = dlsym(soHandle, "LnnGetLocalBroadcastCipherKey");
    g_lnnEnhanceFuncList.lnnGetLocalBroadcastCipherKey = lnnGetLocalBroadcastCipherKey;
    LnnSaveLocalBroadcastCipherKeyFunc lnnSaveLocalBroadcastCipherKey = dlsym(soHandle,
        "LnnSaveLocalBroadcastCipherKey");
    g_lnnEnhanceFuncList.lnnSaveLocalBroadcastCipherKey = lnnSaveLocalBroadcastCipherKey;
    LnnUpdateLocalBroadcastCipherKeyFunc lnnUpdateLocalBroadcastCipherKey = dlsym(soHandle,
        "LnnUpdateLocalBroadcastCipherKey");
    g_lnnEnhanceFuncList.lnnUpdateLocalBroadcastCipherKey = lnnUpdateLocalBroadcastCipherKey;
    LnnGetLocalBroadcastCipherInfoFunc lnnGetLocalBroadcastCipherInfo = dlsym(soHandle,
        "LnnGetLocalBroadcastCipherInfo");
    g_lnnEnhanceFuncList.lnnGetLocalBroadcastCipherInfo = lnnGetLocalBroadcastCipherInfo;
    LnnSetRemoteBroadcastCipherInfoFunc lnnSetRemoteBroadcastCipherInfo = dlsym(soHandle,
        "LnnSetRemoteBroadcastCipherInfo");
    g_lnnEnhanceFuncList.lnnSetRemoteBroadcastCipherInfo = lnnSetRemoteBroadcastCipherInfo;
    LnnLoadLocalDeviceInfoFunc lnnLoadLocalDeviceInfo = dlsym(soHandle, "LnnLoadLocalDeviceInfo");
    g_lnnEnhanceFuncList.lnnLoadLocalDeviceInfo = lnnLoadLocalDeviceInfo;
    LnnLoadRemoteDeviceInfoFunc lnnLoadRemoteDeviceInfo = dlsym(soHandle, "LnnLoadRemoteDeviceInfo");
    g_lnnEnhanceFuncList.lnnLoadRemoteDeviceInfo = lnnLoadRemoteDeviceInfo;
    LnnSaveLocalDeviceInfoFunc lnnSaveLocalDeviceInfo = dlsym(soHandle, "LnnSaveLocalDeviceInfo");
    g_lnnEnhanceFuncList.lnnSaveLocalDeviceInfo = lnnSaveLocalDeviceInfo;
    LnnGetLocalDevInfoFunc lnnGetLocalDevInfo = dlsym(soHandle, "LnnGetLocalDevInfo");
    g_lnnEnhanceFuncList.lnnGetLocalDevInfo = lnnGetLocalDevInfo;
    LnnGetAllRemoteDevInfoFunc lnnGetAllRemoteDevInfo = dlsym(soHandle, "LnnGetAllRemoteDevInfo");
    g_lnnEnhanceFuncList.lnnGetAllRemoteDevInfo = lnnGetAllRemoteDevInfo;
    LnnSaveRemoteDeviceInfoFunc lnnSaveRemoteDeviceInfo = dlsym(soHandle, "LnnSaveRemoteDeviceInfo");
    g_lnnEnhanceFuncList.lnnSaveRemoteDeviceInfo = lnnSaveRemoteDeviceInfo;
    LnnUpdateRemoteDeviceInfoFunc lnnUpdateRemoteDeviceInfo = dlsym(soHandle, "LnnUpdateRemoteDeviceInfo");
    g_lnnEnhanceFuncList.lnnUpdateRemoteDeviceInfo = lnnUpdateRemoteDeviceInfo;
    LnnRetrieveDeviceInfoFunc lnnRetrieveDeviceInfo = dlsym(soHandle, "LnnRetrieveDeviceInfo");
    g_lnnEnhanceFuncList.lnnRetrieveDeviceInfo = lnnRetrieveDeviceInfo;
    LnnRetrieveDeviceInfoByNetworkIdFunc lnnRetrieveDeviceInfoByNetworkId = dlsym(soHandle,
        "LnnRetrieveDeviceInfoByNetworkId");
    g_lnnEnhanceFuncList.lnnRetrieveDeviceInfoByNetworkId = lnnRetrieveDeviceInfoByNetworkId;
    LnnDeleteDeviceInfoFunc lnnDeleteDeviceInfo = dlsym(soHandle, "LnnDeleteDeviceInfo");
    g_lnnEnhanceFuncList.lnnDeleteDeviceInfo = lnnDeleteDeviceInfo;
    ClearDeviceInfoFunc clearDeviceInfo = dlsym(soHandle, "ClearDeviceInfo");
    g_lnnEnhanceFuncList.clearDeviceInfo = clearDeviceInfo;
    LnnGetUdidByBrMacFunc lnnGetUdidByBrMac = dlsym(soHandle, "LnnGetUdidByBrMac");
    g_lnnEnhanceFuncList.lnnGetUdidByBrMac = lnnGetUdidByBrMac;
    LnnGetLocalCacheNodeInfoFunc lnnGetLocalCacheNodeInfo = dlsym(soHandle, "LnnGetLocalCacheNodeInfo");
    g_lnnEnhanceFuncList.lnnGetLocalCacheNodeInfo = lnnGetLocalCacheNodeInfo;
    LnnLoadLocalDeviceAccountIdInfoFunc lnnLoadLocalDeviceAccountIdInfo = dlsym(soHandle,
        "LnnLoadLocalDeviceAccountIdInfo");
    g_lnnEnhanceFuncList.lnnLoadLocalDeviceAccountIdInfo = lnnLoadLocalDeviceAccountIdInfo;
    LnnGetAccountIdFromLocalCacheFunc lnnGetAccountIdFromLocalCache = dlsym(soHandle, "LnnGetAccountIdFromLocalCache");
    g_lnnEnhanceFuncList.lnnGetAccountIdFromLocalCache = lnnGetAccountIdFromLocalCache;
    LnnPackCloudSyncDeviceInfoFunc lnnPackCloudSyncDeviceInfo = dlsym(soHandle, "LnnPackCloudSyncDeviceInfo");
    g_lnnEnhanceFuncList.lnnPackCloudSyncDeviceInfo = lnnPackCloudSyncDeviceInfo;
    LnnUnPackCloudSyncDeviceInfoFunc lnnUnPackCloudSyncDeviceInfo = dlsym(soHandle, "LnnUnPackCloudSyncDeviceInfo");
    g_lnnEnhanceFuncList.lnnUnPackCloudSyncDeviceInfo = lnnUnPackCloudSyncDeviceInfo;
    LnnUpdateAuthExchangeUdidFunc lnnUpdateAuthExchangeUdid = dlsym(soHandle, "LnnUpdateAuthExchangeUdid");
    g_lnnEnhanceFuncList.lnnUpdateAuthExchangeUdid = lnnUpdateAuthExchangeUdid;
    LnnClearAuthExchangeUdidFunc lnnClearAuthExchangeUdid = dlsym(soHandle, "LnnClearAuthExchangeUdid");
    g_lnnEnhanceFuncList.lnnClearAuthExchangeUdid = lnnClearAuthExchangeUdid;
    LnnInitFastOfflineFunc lnnInitFastOffline = dlsym(soHandle, "LnnInitFastOffline");
    g_lnnEnhanceFuncList.lnnInitFastOffline = lnnInitFastOffline;
    LnnDeinitFastOfflineFunc lnnDeinitFastOffline = dlsym(soHandle, "LnnDeinitFastOffline");
    g_lnnEnhanceFuncList.lnnDeinitFastOffline = lnnDeinitFastOffline;
    LnnSendNotTrustedInfoFunc lnnSendNotTrustedInfo = dlsym(soHandle, "LnnSendNotTrustedInfo");
    g_lnnEnhanceFuncList.lnnSendNotTrustedInfo = lnnSendNotTrustedInfo;
    LnnBleFastOfflineOnceBeginFunc lnnBleFastOfflineOnceBegin = dlsym(soHandle, "LnnBleFastOfflineOnceBegin");
    g_lnnEnhanceFuncList.lnnBleFastOfflineOnceBegin = lnnBleFastOfflineOnceBegin;
    LnnIpAddrChangeEventHandlerFunc lnnIpAddrChangeEventHandler = dlsym(soHandle, "LnnIpAddrChangeEventHandler");
    g_lnnEnhanceFuncList.lnnIpAddrChangeEventHandler = lnnIpAddrChangeEventHandler;
    EhLoginEventHandlerFunc ehLoginEventHandler = dlsym(soHandle, "EhLoginEventHandler");
    g_lnnEnhanceFuncList.ehLoginEventHandler = ehLoginEventHandler;
    LnnInitPtkFunc lnnInitPtk = dlsym(soHandle, "LnnInitPtk");
    g_lnnEnhanceFuncList.lnnInitPtk = lnnInitPtk;
    LnnDeinitPtkFunc lnnDeinitPtk = dlsym(soHandle, "LnnDeinitPtk");
    g_lnnEnhanceFuncList.lnnDeinitPtk = lnnDeinitPtk;
    LnnGetLocalDefaultPtkByUuidFunc lnnGetLocalDefaultPtkByUuid = dlsym(soHandle, "LnnGetLocalDefaultPtkByUuid");
    g_lnnEnhanceFuncList.lnnGetLocalDefaultPtkByUuid = lnnGetLocalDefaultPtkByUuid;
    LnnGetRemoteDefaultPtkByUuidFunc lnnGetRemoteDefaultPtkByUuid = dlsym(soHandle, "LnnGetRemoteDefaultPtkByUuid");
    g_lnnEnhanceFuncList.lnnGetRemoteDefaultPtkByUuid = lnnGetRemoteDefaultPtkByUuid;
    LnnLoadPtkInfoFunc lnnLoadPtkInfo = dlsym(soHandle, "LnnLoadPtkInfo");
    g_lnnEnhanceFuncList.lnnLoadPtkInfo = lnnLoadPtkInfo;
    LnnSyncPtkFunc lnnSyncPtk = dlsym(soHandle, "LnnSyncPtk");
    g_lnnEnhanceFuncList.lnnSyncPtk = lnnSyncPtk;
    UpdateLocalPtkIfValidFunc updateLocalPtkIfValid = dlsym(soHandle, "UpdateLocalPtkIfValid");
    g_lnnEnhanceFuncList.updateLocalPtkIfValid = updateLocalPtkIfValid;
    LnnGenerateLocalPtkFunc lnnGenerateLocalPtk = dlsym(soHandle, "LnnGenerateLocalPtk");
    g_lnnEnhanceFuncList.lnnGenerateLocalPtk = lnnGenerateLocalPtk;
    LnnGetMetaPtkFunc lnnGetMetaPtk = dlsym(soHandle, "LnnGetMetaPtk");
    g_lnnEnhanceFuncList.lnnGetMetaPtk = lnnGetMetaPtk;
    LnnSaveDeviceDataFunc lnnSaveDeviceData = dlsym(soHandle, "LnnSaveDeviceData");
    g_lnnEnhanceFuncList.lnnSaveDeviceData = lnnSaveDeviceData;
    LnnAsyncSaveDeviceDataFunc lnnAsyncSaveDeviceData = dlsym(soHandle, "LnnAsyncSaveDeviceData");
    g_lnnEnhanceFuncList.lnnAsyncSaveDeviceData = lnnAsyncSaveDeviceData;
    LnnRetrieveDeviceDataFunc lnnRetrieveDeviceData = dlsym(soHandle, "LnnRetrieveDeviceData");
    g_lnnEnhanceFuncList.lnnRetrieveDeviceData = lnnRetrieveDeviceData;
    LnnUpdateDeviceDataFunc lnnUpdateDeviceData = dlsym(soHandle, "LnnUpdateDeviceData");
    g_lnnEnhanceFuncList.lnnUpdateDeviceData = lnnUpdateDeviceData;
    LnnDeletaDeviceDataFunc lnnDeletaDeviceData = dlsym(soHandle, "LnnDeletaDeviceData");
    g_lnnEnhanceFuncList.lnnDeletaDeviceData = lnnDeletaDeviceData;
    LnnLinkFinderInitFunc lnnLinkFinderInit = dlsym(soHandle, "LnnLinkFinderInit");
    g_lnnEnhanceFuncList.lnnLinkFinderInit = lnnLinkFinderInit;
    LnnUpdateLinkFinderInfoFunc lnnUpdateLinkFinderInfo = dlsym(soHandle, "LnnUpdateLinkFinderInfo");
    g_lnnEnhanceFuncList.lnnUpdateLinkFinderInfo = lnnUpdateLinkFinderInfo;
    LnnRemoveLinkFinderInfoFunc lnnRemoveLinkFinderInfo = dlsym(soHandle, "LnnRemoveLinkFinderInfo");
    g_lnnEnhanceFuncList.lnnRemoveLinkFinderInfo = lnnRemoveLinkFinderInfo;
    LnnInsertLinkFinderInfoFunc lnnInsertLinkFinderInfo = dlsym(soHandle, "LnnInsertLinkFinderInfo");
    g_lnnEnhanceFuncList.lnnInsertLinkFinderInfo = lnnInsertLinkFinderInfo;
    AuthFindDeviceKeyFunc authFindDeviceKey = dlsym(soHandle, "AuthFindDeviceKey");
    g_lnnEnhanceFuncList.authFindDeviceKey = authFindDeviceKey;
    AuthRemoveDeviceKeyByUdidFunc authRemoveDeviceKeyByUdid = dlsym(soHandle, "AuthRemoveDeviceKeyByUdid");
    g_lnnEnhanceFuncList.authRemoveDeviceKeyByUdid = authRemoveDeviceKeyByUdid;
    RegisterOOBEMonitorFunc registerOOBEMonitor = dlsym(soHandle, "RegisterOOBEMonitor");
    g_lnnEnhanceFuncList.registerOOBEMonitor = registerOOBEMonitor;
    LnnInitOOBEStateMonitorImplFunc lnnInitOOBEStateMonitorImpl = dlsym(soHandle, "LnnInitOOBEStateMonitorImpl");
    g_lnnEnhanceFuncList.lnnInitOOBEStateMonitorImpl = lnnInitOOBEStateMonitorImpl;
    LnnGetOOBEStateFunc lnnGetOOBEState = dlsym(soHandle, "LnnGetOOBEState");
    g_lnnEnhanceFuncList.lnnGetOOBEState = lnnGetOOBEState;

    AuthLoadDeviceKeyFunc authLoadDeviceKey = dlsym(soHandle, "AuthLoadDeviceKey");
    g_lnnEnhanceFuncList.authLoadDeviceKey = authLoadDeviceKey;
    AuthFindLatestNormalizeKeyFunc authFindLatestNormalizeKey = dlsym(soHandle, "AuthFindLatestNormalizeKey");
    g_lnnEnhanceFuncList.authFindLatestNormalizeKey = authFindLatestNormalizeKey;
    AuthFindNormalizeKeyByServerSideFunc authFindNormalizeKeyByServerSide = dlsym(soHandle,
        "AuthFindNormalizeKeyByServerSide");
    g_lnnEnhanceFuncList.authFindNormalizeKeyByServerSide = authFindNormalizeKeyByServerSide;
    AuthUpdateCreateTimeFunc authUpdateCreateTime = dlsym(soHandle, "AuthUpdateCreateTime");
    g_lnnEnhanceFuncList.authUpdateCreateTime = authUpdateCreateTime;
    IsSupportUDIDAbatementFunc isSupportUDIDAbatement = dlsym(soHandle, "IsSupportUDIDAbatement");
    g_lnnEnhanceFuncList.isSupportUDIDAbatement = isSupportUDIDAbatement;
    AuthMetaGetConnIdByInfoFunc authMetaGetConnIdByInfo = dlsym(soHandle, "AuthMetaGetConnIdByInfo");
    g_lnnEnhanceFuncList.authMetaGetConnIdByInfo = authMetaGetConnIdByInfo;
    FreeSoftbusChainFunc freeSoftbusChain = dlsym(soHandle, "FreeSoftbusChain");
    g_lnnEnhanceFuncList.freeSoftbusChain = freeSoftbusChain;
    InitSoftbusChainFunc initSoftbusChain = dlsym(soHandle, "InitSoftbusChain");
    g_lnnEnhanceFuncList.initSoftbusChain = initSoftbusChain;
    AuthMetaOpenConnFunc authMetaOpenConn = dlsym(soHandle, "AuthMetaOpenConn");
    g_lnnEnhanceFuncList.authMetaOpenConn = authMetaOpenConn;
    AuthMetaPostTransDataFunc authMetaPostTransData = dlsym(soHandle, "AuthMetaPostTransData");
    g_lnnEnhanceFuncList.authMetaPostTransData = authMetaPostTransData;
    AuthMetaCloseConnFunc authMetaCloseConn = dlsym(soHandle, "AuthMetaCloseConn");
    g_lnnEnhanceFuncList.authMetaCloseConn = authMetaCloseConn;
    AuthMetaGetPreferConnInfoFunc authMetaGetPreferConnInfo = dlsym(soHandle, "AuthMetaGetPreferConnInfo");
    g_lnnEnhanceFuncList.authMetaGetPreferConnInfo = authMetaGetPreferConnInfo;
    AuthMetaGetIdByConnInfoFunc authMetaGetIdByConnInfo = dlsym(soHandle, "AuthMetaGetIdByConnInfo");
    g_lnnEnhanceFuncList.authMetaGetIdByConnInfo = authMetaGetIdByConnInfo;
    AuthMetaGetIdByUuidFunc authMetaGetIdByUuid = dlsym(soHandle, "AuthMetaGetIdByUuid");
    g_lnnEnhanceFuncList.authMetaGetIdByUuid = authMetaGetIdByUuid;
    AuthMetaEncryptFunc authMetaEncrypt = dlsym(soHandle, "AuthMetaEncrypt");
    g_lnnEnhanceFuncList.authMetaEncrypt = authMetaEncrypt;
    AuthMetaDecryptFunc authMetaDecrypt = dlsym(soHandle, "AuthMetaDecrypt");
    g_lnnEnhanceFuncList.authMetaDecrypt = authMetaDecrypt;
    AuthMetaSetP2pMacFunc authMetaSetP2pMac = dlsym(soHandle, "AuthMetaSetP2pMac");
    g_lnnEnhanceFuncList.authMetaSetP2pMac = authMetaSetP2pMac;
    AuthMetaGetConnInfoFunc authMetaGetConnInfo = dlsym(soHandle, "AuthMetaGetConnInfo");
    g_lnnEnhanceFuncList.authMetaGetConnInfo = authMetaGetConnInfo;
    AuthMetaGetDeviceUuidFunc authMetaGetDeviceUuid = dlsym(soHandle, "AuthMetaGetDeviceUuid");
    g_lnnEnhanceFuncList.authMetaGetDeviceUuid = authMetaGetDeviceUuid;
    AuthMetaGetServerSideFunc authMetaGetServerSide = dlsym(soHandle, "AuthMetaGetServerSide");
    g_lnnEnhanceFuncList.authMetaGetServerSide = authMetaGetServerSide;
    AuthMetaCheckMetaExistFunc authMetaCheckMetaExist = dlsym(soHandle, "AuthMetaCheckMetaExist");
    g_lnnEnhanceFuncList.authMetaCheckMetaExist = authMetaCheckMetaExist;
    AuthMetaDeinitFunc authMetaDeinit = dlsym(soHandle, "AuthMetaDeinit");
    g_lnnEnhanceFuncList.authMetaDeinit = authMetaDeinit;
    DelAuthMetaManagerByPidFunc delAuthMetaManagerByPid = dlsym(soHandle, "DelAuthMetaManagerByPid");
    g_lnnEnhanceFuncList.delAuthMetaManagerByPid = delAuthMetaManagerByPid;
    LnnSyncTrustedRelationShipFunc lnnSyncTrustedRelationShip = dlsym(soHandle, "LnnSyncTrustedRelationShip");
    g_lnnEnhanceFuncList.lnnSyncTrustedRelationShip = lnnSyncTrustedRelationShip;
    LnnGetCurrChannelScoreFunc lnnGetCurrChannelScore = dlsym(soHandle, "LnnGetCurrChannelScore");
    g_lnnEnhanceFuncList.lnnGetCurrChannelScore = lnnGetCurrChannelScore;
    AuthInsertDeviceKeyFunc authInsertDeviceKey = dlsym(soHandle, "AuthInsertDeviceKey");
    g_lnnEnhanceFuncList.authInsertDeviceKey = authInsertDeviceKey;
    AuthUpdateKeyIndexFunc authUpdateKeyIndex = dlsym(soHandle, "AuthUpdateKeyIndex");
    g_lnnEnhanceFuncList.authUpdateKeyIndex = authUpdateKeyIndex;
    CalcHKDFFunc calcHKDF = dlsym(soHandle, "CalcHKDF");
    g_lnnEnhanceFuncList.calcHKDF = calcHKDF;
    LnnRetrieveDeviceInfoByUdidFunc lnnRetrieveDeviceInfoByUdid = dlsym(soHandle, "LnnRetrieveDeviceInfoByUdid");
    g_lnnEnhanceFuncList.lnnRetrieveDeviceInfoByUdid = lnnRetrieveDeviceInfoByUdid;
    LnnSyncBleOfflineMsgFunc lnnSyncBleOfflineMsg = dlsym(soHandle, "LnnSyncBleOfflineMsg");
    g_lnnEnhanceFuncList.lnnSyncBleOfflineMsg = lnnSyncBleOfflineMsg;
    LnnInitBroadcastLinkKeyFunc lnnInitBroadcastLinkKey = dlsym(soHandle, "LnnInitBroadcastLinkKey");
    g_lnnEnhanceFuncList.lnnInitBroadcastLinkKey = lnnInitBroadcastLinkKey;
    LnnDeinitBroadcastLinkKeyFunc lnnDeinitBroadcastLinkKey = dlsym(soHandle, "LnnDeinitBroadcastLinkKey");
    g_lnnEnhanceFuncList.lnnDeinitBroadcastLinkKey = lnnDeinitBroadcastLinkKey;

    CustomizedSecurityProtocolInitFunc customizedSecurityProtocolInit = dlsym(soHandle,
        "CustomizedSecurityProtocolInit");
    g_lnnEnhanceFuncList.customizedSecurityProtocolInit = customizedSecurityProtocolInit;
    CustomizedSecurityProtocolDeinitFunc customizedSecurityProtocolDeinit = dlsym(soHandle,
        "CustomizedSecurityProtocolDeinit");
    g_lnnEnhanceFuncList.customizedSecurityProtocolDeinit = customizedSecurityProtocolDeinit;
    g_lnnEnhanceFuncList.isNeedSyncBroadcastLinkKey = dlsym(soHandle, "IsNeedSyncBroadcastLinkKey");
    g_lnnEnhanceFuncList.lnnSyncBroadcastLinkKey = dlsym(soHandle, "LnnSyncBroadcastLinkKey");
    g_lnnEnhanceFuncList.haveConcurrencyPreLinkReqIdByReuseConnReqId = dlsym(soHandle, "HaveConcurrencyPreLinkReqIdByReuseConnReqId");
    g_lnnEnhanceFuncList.getConcurrencyLaneReqIdByConnReqId = dlsym(soHandle, "GetConcurrencyLaneReqIdByConnReqId");
    g_lnnEnhanceFuncList.lnnFreePreLink = dlsym(soHandle, "LnnFreePreLink");
    g_lnnEnhanceFuncList.getConcurrencyLaneReqIdByActionId = dlsym(soHandle, "GetConcurrencyLaneReqIdByActionId");
    g_lnnEnhanceFuncList.updateConcurrencyReuseLaneReqIdByActionId = dlsym(soHandle, "UpdateConcurrencyReuseLaneReqIdByActionId");
    g_lnnEnhanceFuncList.lnnPackCloudSyncAckSeq = dlsym(soHandle, "LnnPackCloudSyncAckSeq");
    g_lnnEnhanceFuncList.lnnClearPtkList = dlsym(soHandle, "LnnClearPtkList");
    g_lnnEnhanceFuncList.generateNewLocalCipherKey = dlsym(soHandle, "GenerateNewLocalCipherKey");
    g_lnnEnhanceFuncList.initActionBleConcurrency = dlsym(soHandle, "InitActionBleConcurrency");
    g_lnnEnhanceFuncList.initActionStateAdapter = dlsym(soHandle, "InitActionStateAdapter");
    g_lnnEnhanceFuncList.lnnGetLocalPtkByUuid = dlsym(soHandle, "LnnGetLocalPtkByUuid");
    g_lnnEnhanceFuncList.registAuthTransListener = dlsym(soHandle, "RegistAuthTransListener");
    g_lnnEnhanceFuncList.unregistAuthTransListener = dlsym(soHandle, "UnregistAuthTransListener");
    g_lnnEnhanceFuncList.lnnStartRange = dlsym(soHandle, "LnnStartRange");
    g_lnnEnhanceFuncList.lnnStopRange = dlsym(soHandle, "LnnStopRange");
    g_lnnEnhanceFuncList.lnnRegSleRangeCb = dlsym(soHandle, "LnnRegSleRangeCb");
    g_lnnEnhanceFuncList.lnnUnregSleRangeCb = dlsym(soHandle, "LnnUnregSleRangeCb");
    g_lnnEnhanceFuncList.sleRangeDeathCallback = dlsym(soHandle, "SleRangeDeathCallback");

    return SOFTBUS_OK;
}