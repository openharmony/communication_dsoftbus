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

void Register1stPartFunc(void *soHandle)
{
    g_lnnEnhanceFuncList.lnnTimeSyncImplInit = dlsym(soHandle, "LnnTimeSyncImplInit");
    g_lnnEnhanceFuncList.lnnTimeSyncImplDeinit = dlsym(soHandle, "LnnTimeSyncImplDeinit");
    g_lnnEnhanceFuncList.lnnStartTimeSyncImpl = dlsym(soHandle, "LnnStartTimeSyncImpl");
    g_lnnEnhanceFuncList.lnnStopTimeSyncImpl = dlsym(soHandle, "LnnStopTimeSyncImpl");
    g_lnnEnhanceFuncList.lnnInitDecisionCenter = dlsym(soHandle, "LnnInitDecisionCenter");
    g_lnnEnhanceFuncList.lnnDeinitDecisionCenter = dlsym(soHandle, "LnnDeinitDecisionCenter");
    g_lnnEnhanceFuncList.lnnDcSubscribe = dlsym(soHandle, "LnnDcSubscribe");
    g_lnnEnhanceFuncList.lnnDcUnsubscribe = dlsym(soHandle, "LnnDcUnsubscribe");
    g_lnnEnhanceFuncList.lnnDcDispatchEvent = dlsym(soHandle, "LnnDcDispatchEvent");
    g_lnnEnhanceFuncList.registAuthTransListener = dlsym(soHandle, "RegistAuthTransListener");
    g_lnnEnhanceFuncList.unregistAuthTransListener = dlsym(soHandle, "UnregistAuthTransListener");
    g_lnnEnhanceFuncList.lnnUnregSleRangeCb = dlsym(soHandle, "LnnUnregSleRangeCb");
    g_lnnEnhanceFuncList.lnnStopRange = dlsym(soHandle, "LnnStopRange");
    g_lnnEnhanceFuncList.lnnStartRange = dlsym(soHandle, "LnnStartRange");
    g_lnnEnhanceFuncList.lnnRegSleRangeCb = dlsym(soHandle, "LnnRegSleRangeCb");
    g_lnnEnhanceFuncList.sleRangeDeathCallback = dlsym(soHandle, "SleRangeDeathCallback");
    g_lnnEnhanceFuncList.lnnDestroyCoapConnectList = dlsym(soHandle, "LnnDestroyCoapConnectList");
    g_lnnEnhanceFuncList.lnnCoapConnect = dlsym(soHandle, "LnnCoapConnect");
    g_lnnEnhanceFuncList.lnnCoapConnectInit = dlsym(soHandle, "LnnCoapConnectInit");
    g_lnnEnhanceFuncList.lnnCoapConnectDeinit = dlsym(soHandle, "LnnCoapConnectDeinit");
    g_lnnEnhanceFuncList.hbUpdateBleScanFilter = dlsym(soHandle, "HbUpdateBleScanFilter");
    g_lnnEnhanceFuncList.hbGenerateBitPosition = dlsym(soHandle, "HbGenerateBitPosition");
    g_lnnEnhanceFuncList.lnnSendBroadcastInfoToLp = dlsym(soHandle, "LnnSendBroadcastInfoToLp");
    g_lnnEnhanceFuncList.lnnBleHbRegDataLevelChangeCb = dlsym(soHandle, "LnnBleHbRegDataLevelChangeCb");
    g_lnnEnhanceFuncList.lnnBleHbUnregDataLevelChangeCb = dlsym(soHandle, "LnnBleHbUnregDataLevelChangeCb");
    g_lnnEnhanceFuncList.lnnAdjustScanPolicy = dlsym(soHandle, "LnnAdjustScanPolicy");
    g_lnnEnhanceFuncList.hbBuildUserIdCheckSum = dlsym(soHandle, "HbBuildUserIdCheckSum");
    g_lnnEnhanceFuncList.encryptUserId = dlsym(soHandle, "EncryptUserId");
    g_lnnEnhanceFuncList.decryptUserId = dlsym(soHandle, "DecryptUserId");
    g_lnnEnhanceFuncList.lnnRegisterBleLpDeviceMediumMgr = dlsym(soHandle, "LnnRegisterBleLpDeviceMediumMgr");
    g_lnnEnhanceFuncList.sendDeviceStateToMlps = dlsym(soHandle, "SendDeviceStateToMlps");
    g_lnnEnhanceFuncList.updateLocalDeviceInfoToMlps = dlsym(soHandle, "UpdateLocalDeviceInfoToMlps");
    g_lnnEnhanceFuncList.updateRemoteDeviceInfoToMlps = dlsym(soHandle, "UpdateRemoteDeviceInfoToMlps");
    g_lnnEnhanceFuncList.updateRemoteDeviceInfoListToMlps = dlsym(soHandle, "UpdateRemoteDeviceInfoListToMlps");
    g_lnnEnhanceFuncList.getBurstAdvId = dlsym(soHandle, "GetBurstAdvId");
    g_lnnEnhanceFuncList.sendDeviceInfoToSHByType = dlsym(soHandle, "SendDeviceInfoToSHByType");
    g_lnnEnhanceFuncList.sendAdvInfoToMlps = dlsym(soHandle, "SendAdvInfoToMlps");
    g_lnnEnhanceFuncList.switchHeartbeatReportChannel = dlsym(soHandle, "SwitchHeartbeatReportChannel");
    g_lnnEnhanceFuncList.isSupportLpFeature = dlsym(soHandle, "IsSupportLpFeature");
    g_lnnEnhanceFuncList.setLpKeepAliveState = dlsym(soHandle, "SetLpKeepAliveState");
    g_lnnEnhanceFuncList.lnnRegistBleHeartbeatMediumMgr = dlsym(soHandle, "LnnRegistBleHeartbeatMediumMgr");
    g_lnnEnhanceFuncList.lnnRequestCheckOnlineStatus = dlsym(soHandle, "LnnRequestCheckOnlineStatus");
    g_lnnEnhanceFuncList.enablePowerControl = dlsym(soHandle, "EnablePowerControl");
    g_lnnEnhanceFuncList.disablePowerControl = dlsym(soHandle, "DisablePowerControl");
    g_lnnEnhanceFuncList.lnnDeinitScore = dlsym(soHandle, "LnnDeinitScore");
    g_lnnEnhanceFuncList.lnnInitScore = dlsym(soHandle, "LnnInitScore");
    g_lnnEnhanceFuncList.lnnStartScoring = dlsym(soHandle, "LnnStartScoring");
    g_lnnEnhanceFuncList.lnnClearPtkList = dlsym(soHandle, "LnnClearPtkList");
}

void Register2ndPartFunc(void *soHandle)
{
    g_lnnEnhanceFuncList.lnnInitVapInfo = dlsym(soHandle, "LnnInitVapInfo");
    g_lnnEnhanceFuncList.lnnDeinitVapInfo = dlsym(soHandle, "LnnDeinitVapInfo");
    g_lnnEnhanceFuncList.lnnAddLocalVapInfo = dlsym(soHandle, "LnnAddLocalVapInfo");
    g_lnnEnhanceFuncList.lnnDeleteLocalVapInfo = dlsym(soHandle, "LnnDeleteLocalVapInfo");
    g_lnnEnhanceFuncList.lnnGetLocalVapInfo = dlsym(soHandle, "LnnGetLocalVapInfo");
    g_lnnEnhanceFuncList.lnnAddRemoteVapInfo = dlsym(soHandle, "LnnAddRemoteVapInfo");
    g_lnnEnhanceFuncList.lnnDeleteRemoteVapInfo = dlsym(soHandle, "LnnDeleteRemoteVapInfo");
    g_lnnEnhanceFuncList.lnnGetRemoteVapInfo = dlsym(soHandle, "LnnGetRemoteVapInfo");
    g_lnnEnhanceFuncList.lnnGetLocalPreferChannel = dlsym(soHandle, "LnnGetLocalPreferChannel");
    g_lnnEnhanceFuncList.lnnGetLocalChannelCode = dlsym(soHandle, "LnnGetLocalChannelCode");
    g_lnnEnhanceFuncList.lnnAddRemoteChannelCode = dlsym(soHandle, "LnnAddRemoteChannelCode");
    g_lnnEnhanceFuncList.lnnGetRecommendChannel = dlsym(soHandle, "LnnGetRecommendChannel");
    g_lnnEnhanceFuncList.isCloudSyncEnabled = dlsym(soHandle, "IsCloudSyncEnabled");
    g_lnnEnhanceFuncList.isPowerControlEnabled = dlsym(soHandle, "IsPowerControlEnabled");
    g_lnnEnhanceFuncList.lnnGetCurrChannelScore = dlsym(soHandle, "LnnGetCurrChannelScore");
    g_lnnEnhanceFuncList.lnnInitQos = dlsym(soHandle, "LnnInitQos");
    g_lnnEnhanceFuncList.lnnDeinitQos = dlsym(soHandle, "LnnDeinitQos");
    g_lnnEnhanceFuncList.lnnRegPeriodAdjustmentCallback = dlsym(soHandle, "LnnRegPeriodAdjustmentCallback");
    g_lnnEnhanceFuncList.lnnReportLaneIdStatsInfo = dlsym(soHandle, "LnnReportLaneIdStatsInfo");
    g_lnnEnhanceFuncList.lnnReportRippleData = dlsym(soHandle, "LnnReportRippleData");
    g_lnnEnhanceFuncList.lnnRequestQosOptimization = dlsym(soHandle, "LnnRequestQosOptimization");
    g_lnnEnhanceFuncList.lnnCancelQosOptimization = dlsym(soHandle, "LnnCancelQosOptimization");
    g_lnnEnhanceFuncList.lnnInitMetaNode = dlsym(soHandle, "LnnInitMetaNode");
    g_lnnEnhanceFuncList.lnnInitMetaNodeExtLedger = dlsym(soHandle, "LnnInitMetaNodeExtLedger");
    g_lnnEnhanceFuncList.lnnDeinitMetaNodeExtLedger = dlsym(soHandle, "LnnDeinitMetaNodeExtLedger");
    g_lnnEnhanceFuncList.clearMetaNodeRequestByPid = dlsym(soHandle, "ClearMetaNodeRequestByPid");
    g_lnnEnhanceFuncList.lnnDeinitMetaNode = dlsym(soHandle, "LnnDeinitMetaNode");
    g_lnnEnhanceFuncList.lnnInitCipherKeyManager = dlsym(soHandle, "LnnInitCipherKeyManager");
    g_lnnEnhanceFuncList.lnnDeinitCipherKeyManager = dlsym(soHandle, "LnnDeinitCipherKeyManager");
    g_lnnEnhanceFuncList.getCipherKeyByNetworkId = dlsym(soHandle, "GetCipherKeyByNetworkId");
    g_lnnEnhanceFuncList.getLocalCipherKey = dlsym(soHandle, "GetLocalCipherKey");
    g_lnnEnhanceFuncList.loadBleBroadcastKey = dlsym(soHandle, "LoadBleBroadcastKey");
    g_lnnEnhanceFuncList.isCipherManagerFindKey = dlsym(soHandle, "IsCipherManagerFindKey");
    g_lnnEnhanceFuncList.packCipherKeySyncMsg = dlsym(soHandle, "PackCipherKeySyncMsg");
    g_lnnEnhanceFuncList.processCipherKeySyncInfo = dlsym(soHandle, "ProcessCipherKeySyncInfo");
    g_lnnEnhanceFuncList.lnnLoadLocalBroadcastCipherKey = dlsym(soHandle, "LnnLoadLocalBroadcastCipherKey");
    g_lnnEnhanceFuncList.lnnGetLocalBroadcastCipherKey = dlsym(soHandle, "LnnGetLocalBroadcastCipherKey");
    g_lnnEnhanceFuncList.lnnSaveLocalBroadcastCipherKey = dlsym(soHandle, "LnnSaveLocalBroadcastCipherKey");
    g_lnnEnhanceFuncList.lnnUpdateLocalBroadcastCipherKey = dlsym(soHandle, "LnnUpdateLocalBroadcastCipherKey");
    g_lnnEnhanceFuncList.lnnGetLocalBroadcastCipherInfo = dlsym(soHandle, "LnnGetLocalBroadcastCipherInfo");
    g_lnnEnhanceFuncList.lnnSetRemoteBroadcastCipherInfo = dlsym(soHandle, "LnnSetRemoteBroadcastCipherInfo");
    g_lnnEnhanceFuncList.lnnLoadLocalDeviceInfo = dlsym(soHandle, "LnnLoadLocalDeviceInfo");
    g_lnnEnhanceFuncList.lnnLoadRemoteDeviceInfo = dlsym(soHandle, "LnnLoadRemoteDeviceInfo");
    g_lnnEnhanceFuncList.lnnSaveLocalDeviceInfo = dlsym(soHandle, "LnnSaveLocalDeviceInfo");
    g_lnnEnhanceFuncList.lnnGetLocalDevInfo = dlsym(soHandle, "LnnGetLocalDevInfo");
    g_lnnEnhanceFuncList.lnnGetAllRemoteDevInfo = dlsym(soHandle, "LnnGetAllRemoteDevInfo");
    g_lnnEnhanceFuncList.lnnSaveRemoteDeviceInfo = dlsym(soHandle, "LnnSaveRemoteDeviceInfo");
    g_lnnEnhanceFuncList.lnnUpdateRemoteDeviceInfo = dlsym(soHandle, "LnnUpdateRemoteDeviceInfo");
}

void Register3rdPartFunc(void *soHandle)
{
    g_lnnEnhanceFuncList.lnnDeleteDeviceInfo = dlsym(soHandle, "LnnDeleteDeviceInfo");
    g_lnnEnhanceFuncList.clearDeviceInfo = dlsym(soHandle, "ClearDeviceInfo");
    g_lnnEnhanceFuncList.lnnGetUdidByBrMac = dlsym(soHandle, "LnnGetUdidByBrMac");
    g_lnnEnhanceFuncList.lnnGetLocalCacheNodeInfo = dlsym(soHandle, "LnnGetLocalCacheNodeInfo");
    g_lnnEnhanceFuncList.lnnLoadLocalDeviceAccountIdInfo = dlsym(soHandle, "LnnLoadLocalDeviceAccountIdInfo");
    g_lnnEnhanceFuncList.lnnGetAccountIdFromLocalCache = dlsym(soHandle, "LnnGetAccountIdFromLocalCache");
    g_lnnEnhanceFuncList.lnnPackCloudSyncDeviceInfo = dlsym(soHandle, "LnnPackCloudSyncDeviceInfo");
    g_lnnEnhanceFuncList.lnnUnPackCloudSyncDeviceInfo = dlsym(soHandle, "LnnUnPackCloudSyncDeviceInfo");
    g_lnnEnhanceFuncList.lnnUpdateAuthExchangeUdid = dlsym(soHandle, "LnnUpdateAuthExchangeUdid");
    g_lnnEnhanceFuncList.lnnClearAuthExchangeUdid = dlsym(soHandle, "LnnClearAuthExchangeUdid");
    g_lnnEnhanceFuncList.lnnInitFastOffline = dlsym(soHandle, "LnnInitFastOffline");
    g_lnnEnhanceFuncList.lnnDeinitFastOffline = dlsym(soHandle, "LnnDeinitFastOffline");
    g_lnnEnhanceFuncList.lnnSendNotTrustedInfo = dlsym(soHandle, "LnnSendNotTrustedInfo");
    g_lnnEnhanceFuncList.lnnBleFastOfflineOnceBegin = dlsym(soHandle, "LnnBleFastOfflineOnceBegin");
    g_lnnEnhanceFuncList.lnnIpAddrChangeEventHandler = dlsym(soHandle, "LnnIpAddrChangeEventHandler");
    g_lnnEnhanceFuncList.ehLoginEventHandler = dlsym(soHandle, "EhLoginEventHandler");
    g_lnnEnhanceFuncList.lnnInitPtk = dlsym(soHandle, "LnnInitPtk");
    g_lnnEnhanceFuncList.lnnDeinitPtk = dlsym(soHandle, "LnnDeinitPtk");
    g_lnnEnhanceFuncList.lnnGetLocalDefaultPtkByUuid = dlsym(soHandle, "LnnGetLocalDefaultPtkByUuid");
    g_lnnEnhanceFuncList.lnnGetRemoteDefaultPtkByUuid = dlsym(soHandle, "LnnGetRemoteDefaultPtkByUuid");
    g_lnnEnhanceFuncList.lnnLoadPtkInfo = dlsym(soHandle, "LnnLoadPtkInfo");
    g_lnnEnhanceFuncList.lnnSyncPtk = dlsym(soHandle, "LnnSyncPtk");
    g_lnnEnhanceFuncList.updateLocalPtkIfValid = dlsym(soHandle, "UpdateLocalPtkIfValid");
    g_lnnEnhanceFuncList.lnnGenerateLocalPtk = dlsym(soHandle, "LnnGenerateLocalPtk");
    g_lnnEnhanceFuncList.lnnGetMetaPtk = dlsym(soHandle, "LnnGetMetaPtk");
    g_lnnEnhanceFuncList.lnnGetLocalPtkByUuid = dlsym(soHandle, "LnnGetLocalPtkByUuid");
    g_lnnEnhanceFuncList.lnnSyncTrustedRelationShip = dlsym(soHandle, "LnnSyncTrustedRelationShip");
    g_lnnEnhanceFuncList.lnnRetrieveDeviceInfoByUdid = dlsym(soHandle, "LnnRetrieveDeviceInfoByUdid");
    g_lnnEnhanceFuncList.lnnSyncBleOfflineMsg = dlsym(soHandle, "LnnSyncBleOfflineMsg");
    g_lnnEnhanceFuncList.lnnInitBroadcastLinkKey = dlsym(soHandle, "LnnInitBroadcastLinkKey");
    g_lnnEnhanceFuncList.lnnDeinitBroadcastLinkKey = dlsym(soHandle, "LnnDeinitBroadcastLinkKey");
    g_lnnEnhanceFuncList.isNeedSyncBroadcastLinkKey = dlsym(soHandle, "IsNeedSyncBroadcastLinkKey");
    g_lnnEnhanceFuncList.lnnSyncBroadcastLinkKey = dlsym(soHandle, "LnnSyncBroadcastLinkKey");
    g_lnnEnhanceFuncList.lnnSaveDeviceData = dlsym(soHandle, "LnnSaveDeviceData");
    g_lnnEnhanceFuncList.lnnAsyncSaveDeviceData = dlsym(soHandle, "LnnAsyncSaveDeviceData");
    g_lnnEnhanceFuncList.lnnRetrieveDeviceData = dlsym(soHandle, "LnnRetrieveDeviceData");
    g_lnnEnhanceFuncList.lnnUpdateDeviceData = dlsym(soHandle, "LnnUpdateDeviceData");
    g_lnnEnhanceFuncList.getConcurrencyLaneReqIdByConnReqId = dlsym(soHandle, "GetConcurrencyLaneReqIdByConnReqId");
    g_lnnEnhanceFuncList.haveConcurrencyPreLinkReqIdByReuseConnReqId =
        dlsym(soHandle, "HaveConcurrencyPreLinkReqIdByReuseConnReqId");
    g_lnnEnhanceFuncList.getConcurrencyLaneReqIdByActionId = dlsym(soHandle, "GetConcurrencyLaneReqIdByActionId");
    g_lnnEnhanceFuncList.lnnFreePreLink = dlsym(soHandle, "LnnFreePreLink");
    g_lnnEnhanceFuncList.updateConcurrencyReuseLaneReqIdByActionId =
        dlsym(soHandle, "UpdateConcurrencyReuseLaneReqIdByActionId");
    g_lnnEnhanceFuncList.lnnPackCloudSyncAckSeq = dlsym(soHandle, "LnnPackCloudSyncAckSeq");
    g_lnnEnhanceFuncList.generateNewLocalCipherKey = dlsym(soHandle, "GenerateNewLocalCipherKey");
}

void Register4thPartFunc(void *soHandle)
{
    g_lnnEnhanceFuncList.lnnLinkFinderInit = dlsym(soHandle, "LnnLinkFinderInit");
    g_lnnEnhanceFuncList.lnnUpdateLinkFinderInfo = dlsym(soHandle, "LnnUpdateLinkFinderInfo");
    g_lnnEnhanceFuncList.lnnRemoveLinkFinderInfo = dlsym(soHandle, "LnnRemoveLinkFinderInfo");
    g_lnnEnhanceFuncList.lnnInsertLinkFinderInfo = dlsym(soHandle, "LnnInsertLinkFinderInfo");
    g_lnnEnhanceFuncList.registerOOBEMonitor = dlsym(soHandle, "RegisterOOBEMonitor");
    g_lnnEnhanceFuncList.lnnInitOOBEStateMonitorImpl = dlsym(soHandle, "LnnInitOOBEStateMonitorImpl");
    g_lnnEnhanceFuncList.lnnGetOOBEState = dlsym(soHandle, "LnnGetOOBEState");
    g_lnnEnhanceFuncList.authFindDeviceKey = dlsym(soHandle, "AuthFindDeviceKey");
    g_lnnEnhanceFuncList.authRemoveDeviceKeyByUdid = dlsym(soHandle, "AuthRemoveDeviceKeyByUdid");
    g_lnnEnhanceFuncList.authLoadDeviceKey = dlsym(soHandle, "AuthLoadDeviceKey");
    g_lnnEnhanceFuncList.authFindLatestNormalizeKey = dlsym(soHandle, "AuthFindLatestNormalizeKey");
    g_lnnEnhanceFuncList.authFindNormalizeKeyByServerSide = dlsym(soHandle, "AuthFindNormalizeKeyByServerSide");
    g_lnnEnhanceFuncList.authUpdateCreateTime = dlsym(soHandle, "AuthUpdateCreateTime");
    g_lnnEnhanceFuncList.isSupportUDIDAbatement = dlsym(soHandle, "IsSupportUDIDAbatement");
    g_lnnEnhanceFuncList.authMetaGetConnIdByInfo = dlsym(soHandle, "AuthMetaGetConnIdByInfo");
    g_lnnEnhanceFuncList.freeSoftbusChain = dlsym(soHandle, "FreeSoftbusChain");
    g_lnnEnhanceFuncList.initSoftbusChain = dlsym(soHandle, "InitSoftbusChain");
    g_lnnEnhanceFuncList.authMetaOpenConn = dlsym(soHandle, "AuthMetaOpenConn");
    g_lnnEnhanceFuncList.authMetaPostTransData = dlsym(soHandle, "AuthMetaPostTransData");
    g_lnnEnhanceFuncList.authMetaCloseConn = dlsym(soHandle, "AuthMetaCloseConn");
    g_lnnEnhanceFuncList.authMetaGetPreferConnInfo = dlsym(soHandle, "AuthMetaGetPreferConnInfo");
    g_lnnEnhanceFuncList.authMetaGetIdByConnInfo = dlsym(soHandle, "AuthMetaGetIdByConnInfo");
    g_lnnEnhanceFuncList.authMetaGetIdByUuid = dlsym(soHandle, "AuthMetaGetIdByUuid");
    g_lnnEnhanceFuncList.authMetaGetIdByIp = dlsym(soHandle, "AuthMetaGetIdByIp");
    g_lnnEnhanceFuncList.authMetaEncrypt = dlsym(soHandle, "AuthMetaEncrypt");
    g_lnnEnhanceFuncList.authMetaDecrypt = dlsym(soHandle, "AuthMetaDecrypt");
    g_lnnEnhanceFuncList.authMetaSetP2pMac = dlsym(soHandle, "AuthMetaSetP2pMac");
    g_lnnEnhanceFuncList.authMetaGetConnInfo = dlsym(soHandle, "AuthMetaGetConnInfo");
    g_lnnEnhanceFuncList.authMetaGetDeviceUuid = dlsym(soHandle, "AuthMetaGetDeviceUuid");
    g_lnnEnhanceFuncList.authMetaGetServerSide = dlsym(soHandle, "AuthMetaGetServerSide");
    g_lnnEnhanceFuncList.authMetaCheckMetaExist = dlsym(soHandle, "AuthMetaCheckMetaExist");
    g_lnnEnhanceFuncList.authMetaDeinit = dlsym(soHandle, "AuthMetaDeinit");
    g_lnnEnhanceFuncList.delAuthMetaManagerByPid = dlsym(soHandle, "DelAuthMetaManagerByPid");
    g_lnnEnhanceFuncList.authInsertDeviceKey = dlsym(soHandle, "AuthInsertDeviceKey");
    g_lnnEnhanceFuncList.authUpdateKeyIndex = dlsym(soHandle, "AuthUpdateKeyIndex");
    g_lnnEnhanceFuncList.calcHKDF = dlsym(soHandle, "CalcHKDF");
    g_lnnEnhanceFuncList.customizedSecurityProtocolInit = dlsym(soHandle, "CustomizedSecurityProtocolInit");
    g_lnnEnhanceFuncList.customizedSecurityProtocolDeinit = dlsym(soHandle, "CustomizedSecurityProtocolDeinit");
    g_lnnEnhanceFuncList.lnnInitUsbChannelManager = dlsym(soHandle, "LnnInitUsbChannelManager");
    g_lnnEnhanceFuncList.lnnDeinitUsbChannelManager = dlsym(soHandle, "LnnDeinitUsbChannelManager");
    g_lnnEnhanceFuncList.lnnStopScoring = dlsym(soHandle, "LnnStopScoring");
    g_lnnEnhanceFuncList.lnnGetWlanLinkedInfo = dlsym(soHandle, "LnnGetWlanLinkedInfo");
    g_lnnEnhanceFuncList.lnnGetAllChannelScore = dlsym(soHandle, "LnnGetAllChannelScore");
    g_lnnEnhanceFuncList.initActionBleConcurrency = dlsym(soHandle, "InitActionBleConcurrency");
    g_lnnEnhanceFuncList.initActionStateAdapter = dlsym(soHandle, "InitActionStateAdapter");
    g_lnnEnhanceFuncList.lnnDeleteDeviceData = dlsym(soHandle, "LnnDeleteDeviceData");
}

void Register5thPartFunc(void *soHandle)
{
    g_lnnEnhanceFuncList.lnnRetrieveDeviceInfo = dlsym(soHandle, "LnnRetrieveDeviceInfo");
    g_lnnEnhanceFuncList.lnnRetrieveDeviceInfoByNetworkId = dlsym(soHandle, "LnnRetrieveDeviceInfoByNetworkId");
    g_lnnEnhanceFuncList.haveConcurrencyPreLinkNodeByLaneReqId = dlsym(soHandle,
        "HaveConcurrencyPreLinkNodeByLaneReqId");
    g_lnnEnhanceFuncList.updateConcurrencyReuseLaneReqIdByUdid = dlsym(soHandle,
        "UpdateConcurrencyReuseLaneReqIdByUdid");
    g_lnnEnhanceFuncList.lnnTimeChangeNotify = dlsym(soHandle, "LnnTimeChangeNotify");
    g_lnnEnhanceFuncList.lnnVirtualLinkInit = dlsym(soHandle, "LnnVirtualLinkInit");
    g_lnnEnhanceFuncList.lnnVirtualLinkDeinit = dlsym(soHandle, "LnnVirtualLinkDeinit");
    g_lnnEnhanceFuncList.dcTriggerVirtualLink = dlsym(soHandle, "DcTriggerVirtualLink");
    g_lnnEnhanceFuncList.lnnGetLocalChannelInfo = dlsym(soHandle, "LnnGetLocalChannelInfo");
    g_lnnEnhanceFuncList.lnnSetLocalChannelInfo = dlsym(soHandle, "LnnSetLocalChannelInfo");
    g_lnnEnhanceFuncList.triggerSparkGroupBuild = dlsym(soHandle, "TriggerSparkGroupBuild");
    g_lnnEnhanceFuncList.triggerSparkGroupClear = dlsym(soHandle, "TriggerSparkGroupClear");
    g_lnnEnhanceFuncList.triggerSparkGroupJoinAgain = dlsym(soHandle, "TriggerSparkGroupJoinAgain");
    g_lnnEnhanceFuncList.initControlPlane = dlsym(soHandle, "InitControlPlane");
    g_lnnEnhanceFuncList.deinitControlPlane = dlsym(soHandle, "DeinitControlPlane");
    g_lnnEnhanceFuncList.queryControlPlaneNodeValid = dlsym(soHandle, "QueryControlPlaneNodeValid");
    g_lnnEnhanceFuncList.lnnDumpControlLaneGroupInfo = dlsym(soHandle, "LnnDumpControlLaneGroupInfo");
    g_lnnEnhanceFuncList.isSparkGroupEnabled = dlsym(soHandle, "IsSparkGroupEnabled");
    g_lnnEnhanceFuncList.lnnRegisterSleHeartbeatMediumMgr = dlsym(soHandle, "LnnRegisterSleHeartbeatMediumMgr");
    g_lnnEnhanceFuncList.isDeviceHasRiskFactor = dlsym(soHandle, "IsDeviceHasRiskFactor");
    g_lnnEnhanceFuncList.checkNeedCloudSyncOffline = dlsym(soHandle, "CheckNeedCloudSyncOffline");
    g_lnnEnhanceFuncList.lnnDeviceCloudConvergenceInit = dlsym(soHandle, "LnnDeviceCloudConvergenceInit");
    g_lnnEnhanceFuncList.isSupportLowLatency = dlsym(soHandle, "IsSupportLowLatency");
    g_lnnEnhanceFuncList.lnnIsSupportLpSparkFeature = dlsym(soHandle, "LnnIsSupportLpSparkFeature");
    g_lnnEnhanceFuncList.isFeatureSupportDetail = dlsym(soHandle, "IsFeatureSupportDetail");
    g_lnnEnhanceFuncList.lnnInitDecisionCenterV2 = dlsym(soHandle, "LnnInitDecisionCenterV2");
    g_lnnEnhanceFuncList.lnnDeinitDecisionCenterV2 = dlsym(soHandle, "LnnDeinitDecisionCenterV2");
    g_lnnEnhanceFuncList.sdMgrDeathCallback = dlsym(soHandle, "SdMgrDeathCallback");
    g_lnnEnhanceFuncList.authMetaGetIpByMetaNodeId = dlsym(soHandle, "AuthMetaGetIpByMetaNodeId");
    g_lnnEnhanceFuncList.authMetaGetLocalIpByMetaNodeId = dlsym(soHandle, "AuthMetaGetLocalIpByMetaNodeId");
    g_lnnEnhanceFuncList.authMetaGetConnectionTypeByMetaNodeId = dlsym(soHandle,
        "AuthMetaGetConnectionTypeByMetaNodeId");
    g_lnnEnhanceFuncList.isSupportMcuFeature = dlsym(soHandle, "IsSupportMcuFeature");
    g_lnnEnhanceFuncList.lnnSendDeviceStateToMcu = dlsym(soHandle, "LnnSendDeviceStateToMcu");
    g_lnnEnhanceFuncList.lnnInitMcu = dlsym(soHandle, "LnnInitMcu");
}

int32_t LnnRegisterEnhanceFunc(void *soHandle)
{
    (void)Register1stPartFunc(soHandle);
    (void)Register2ndPartFunc(soHandle);
    (void)Register3rdPartFunc(soHandle);
    (void)Register4thPartFunc(soHandle);
    (void)Register5thPartFunc(soHandle);
    return SOFTBUS_OK;
}