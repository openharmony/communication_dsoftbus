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

#ifndef G_REG_LNN_FUNC_H
#define G_REG_LNN_FUNC_H

#include "g_reg_lnn_ext_func.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TagLnnOpenFuncList {
    // heartbeat
    IsHeartbeatEnableFunc isHeartbeatEnable;
    LnnRegistHeartbeatMediumMgrFunc lnnRegistHeartbeatMediumMgr;
    LnnSetMediumParamBySpecificTypeFunc lnnSetMediumParamBySpecificType;
    LnnGetMediumParamBySpecificTypeFunc lnnGetMediumParamBySpecificType;
    LnnStartHbByTypeAndStrategyFunc lnnStartHbByTypeAndStrategy;
    LnnIsHeartbeatEnableFunc lnnIsHeartbeatEnable;
    LnnHasActiveConnectionFunc lnnHasActiveConnection;
    LnnGetShortAccountHashFunc lnnGetShortAccountHash;
    LnnGenerateHexStringHashFunc lnnGenerateHexStringHash;
    LnnIsLocalSupportBurstFeatureFunc lnnIsLocalSupportBurstFeature;
    LnnTriggerDirectHeartbeatFunc lnnTriggerDirectHeartbeat;
    LnnOfflineTimingByHeartbeatFunc lnnOfflineTimingByHeartbeat;
    LnnIsCloudSyncEndFunc lnnIsCloudSyncEnd;
    LnnIsSupportHeartbeatCapFunc lnnIsSupportHeartbeatCap;
    LnnRequestBleDiscoveryProcessFunc lnnRequestBleDiscoveryProcess;
    GetScreenStateFunc getScreenState;
    GetScreenLockStateFunc getScreenLockState;
    LnnTriggerSleHeartbeatFunc lnnTriggerSleHeartbeat;
    LnnCleanTriggerSparkInfoFunc lnnCleanTriggerSparkInfo;
    LnnOfflineTimingBySleHbFunc lnnOfflineTimingBySleHb;
    LnnStopSleHeartbeatFunc lnnStopSleHeartbeat;
    LnnStopSleOfflineTimingStrategyFunc lnnStopSleOfflineTimingStrategy;
    IsHeartbeatEnableForMcuFunc isHeartbeatEnableForMcu;
    LnnIsLocalSupportMcuFeatureFunc lnnIsLocalSupportMcuFeature;

    // net_builder
    LnnRegSyncInfoHandlerFunc lnnRegSyncInfoHandler;
    LnnUnregSyncInfoHandlerFunc lnnUnregSyncInfoHandler;
    LnnSendSyncInfoMsgFunc lnnSendSyncInfoMsg;
    LnnSendWifiOfflineInfoMsgFunc lnnSendWifiOfflineInfoMsg;
    LnnDeleteDevInfoSyncToDBFunc lnnDeleteDevInfoSyncToDB;
    LnnNotifyDiscoveryDeviceFunc lnnNotifyDiscoveryDevice;
    LnnRequestLeaveSpecificFunc lnnRequestLeaveSpecific;
    LnnGetReAuthVerifyCallbackFunc lnnGetReAuthVerifyCallback;
    NotifyForegroundUseridChangeFunc notifyForegroundUseridChange;
    DfxRecordTriggerTimeFunc dfxRecordTriggerTime;
    CreateSyncInfoParamFunc createSyncInfoParam;
    LnnSendAsyncInfoMsgFunc lnnSendAsyncInfoMsg;

    // net_buscenter
    LnnRegistProtocolFunc lnnRegistProtocol;
    LnnRegistPhysicalSubnetFunc lnnRegistPhysicalSubnet;
    LnnUnregistPhysicalSubnetByTypeFunc lnnUnregistPhysicalSubnetByType;
    LnnNotifyPhysicalSubnetStatusChangedFunc lnnNotifyPhysicalSubnetStatusChanged;
    LnnGetProtocolListenerModuleFunc lnnGetProtocolListenerModule;

    // net_ledger
    LnnSetFeatureCapabilityFunc lnnSetFeatureCapability;
    LnnClearFeatureCapabilityFunc lnnClearFeatureCapability;
    LnnHasCapabilityFunc lnnHasCapability;
    LnnGetNetCapabiltyFunc lnnGetNetCapabilty;
    LnnSetDiscoveryTypeFunc lnnSetDiscoveryType;
    LnnClearDiscoveryTypeFunc lnnClearDiscoveryType;
    LnnIsNodeOnlineFunc lnnIsNodeOnline;
    LnnDumpNodeInfoFunc lnnDumpNodeInfo;
    LnnSetPtkFunc lnnSetPtk;
    EncryptStorageDataFunc encryptStorageData;
    DecryptStorageDataFunc decryptStorageData;
    LnnAddOnlineNodeFunc lnnAddOnlineNode;
    LnnRemoveNodeFunc lnnRemoveNode;
    LnnSetRemoteScreenStatusInfoFunc lnnSetRemoteScreenStatusInfo;
    LnnGetDLHeartbeatTimestampFunc lnnGetDLHeartbeatTimestamp;
    LnnGetDLBleDirectTimestampFunc lnnGetDLBleDirectTimestamp;
    LnnGetDLUpdateTimestampFunc lnnGetDLUpdateTimestamp;
    LnnSetDLBleDirectTimestampFunc lnnSetDLBleDirectTimestamp;
    LnnSetDLConnCapabilityFunc lnnSetDLConnCapability;
    LnnAddMetaInfoFunc lnnAddMetaInfo;
    LnnDeleteMetaInfoFunc lnnDeleteMetaInfo;
    LnnUpdateStateVersionFunc lnnUpdateStateVersion;
    LnnGetLocalDeviceInfoFunc lnnGetLocalDeviceInfo;
    LnnGetRemoteStrInfoFunc lnnGetRemoteStrInfo;
    LnnGetRemoteNodeInfoByIdFunc lnnGetRemoteNodeInfoById;
    LnnMapInitIteratorFunc lnnMapInitIterator;
    LnnConvertIdToDeviceTypeFunc lnnConvertIdToDeviceType;
    LnnConvertDeviceTypeToIdFunc lnnConvertDeviceTypeToId;
    IsFeatureSupportFunc isFeatureSupport;
    LnnGetDeviceUdidFunc lnnGetDeviceUdid;
    LnnHasDiscoveryTypeFunc lnnHasDiscoveryType;
    LnnDumpRemotePtkFunc lnnDumpRemotePtk;
    LnnGetTrustedDevInfoFromDbFunc lnnGetTrustedDevInfoFromDb;
    LnnGetRemoteNodeInfoByKeyFunc lnnGetRemoteNodeInfoByKey;
    LnnConvertDlIdFunc lnnConvertDlId;
    LnnGetOnlineStateByIdFunc lnnGetOnlineStateById;
    LnnSetDlPtkFunc lnnSetDlPtk;
    LnnGetLocalNodeInfoFunc lnnGetLocalNodeInfo;
    LnnGetLocalNodeInfoSafeFunc lnnGetLocalNodeInfoSafe;
    LnnGetRemoteNumInfoFunc lnnGetRemoteNumInfo;
    LnnGetRemoteNumU64InfoFunc lnnGetRemoteNumU64Info;
    LnnGetRemoteByteInfoFunc lnnGetRemoteByteInfo;
    LnnSetLocalStrInfoFunc lnnSetLocalStrInfo;
    LnnSetLocalNumInfoFunc lnnSetLocalNumInfo;
    LnnGetLocalStrInfoFunc lnnGetLocalStrInfo;
    LnnGetLocalNumInfoFunc lnnGetLocalNumInfo;
    LnnGetLocalNumU64InfoFunc lnnGetLocalNumU64Info;
    LnnGetLocalNum64InfoFunc lnnGetLocalNum64Info;
    LnnSetLocalNum64InfoFunc lnnSetLocalNum64Info;
    LnnSetLocalByteInfoFunc lnnSetLocalByteInfo;
    LnnGetLocalNum16InfoFunc lnnGetLocalNum16Info;
    LnnGetLocalNumU16InfoFunc lnnGetLocalNumU16Info;
    LnnGetLocalNumU32InfoFunc lnnGetLocalNumU32Info;
    LnnGetLocalByteInfoFunc lnnGetLocalByteInfo;
    LnnGetAllOnlineNodeInfoFunc lnnGetAllOnlineNodeInfo;
    LnnGetOnlineAndOfflineWithinTimeUdidsFunc lnnGetOnlineAndOfflineWithinTimeUdids;
    LnnGetNodeKeyInfoFunc lnnGetNodeKeyInfo;
    LnnSetNodeKeyInfoFunc lnnSetNodeKeyInfo;
    LnnGetNetworkIdByUdidFunc lnnGetNetworkIdByUdid;
    LnnGetNetworkIdByUdidHashFunc lnnGetNetworkIdByUdidHash;
    LnnGetAllMetaNodeInfoFunc lnnGetAllMetaNodeInfo;
    LnnIsLSANodeFunc lnnIsLSANode;
    LnnGetNodeInfoByIdFunc lnnGetNodeInfoById;
    LnnConvertDLidToUdidFunc lnnConvertDLidToUdid;
    LnnSetDLConnUserIdCheckSumFunc lnnSetDLConnUserIdCheckSum;
    LnnSetDLDeviceBroadcastCipherKeyFunc lnnSetDLDeviceBroadcastCipherKey;
    LnnSetDLDeviceBroadcastCipherIvFunc lnnSetDLDeviceBroadcastCipherIv;
    LnnSaveBroadcastLinkKeyFunc lnnSaveBroadcastLinkKey;
    LnnUpdateNodeBleMacFunc lnnUpdateNodeBleMac;
    LnnGetOnlineNodeByUdidHashFunc lnnGetOnlineNodeByUdidHash;
    LnnGetRemoteStrInfoByIfnameIdxFunc lnnGetRemoteStrInfoByIfnameIdx;
    LnnGetLocalNumInfoByIfnameIdxFunc lnnGetLocalNumInfoByIfnameIdx;
    LnnGetRemoteNumInfoByIfnameIdxFunc lnnGetRemoteNumInfoByIfnameIdx;
    LnnDumpSparkCheckFunc lnnDumpSparkCheck;
    LnnNotifyHaLeaveMetaNodeEventFunc lnnNotifyHaLeaveMetaNodeEvent;

    // lane_manager
    GetAllDevIdWithLinkTypeFunc getAllDevIdWithLinkType;
    FindLaneResourceByDevInfoFunc findLaneResourceByDevInfo;
    QueryOtherLaneResourceFunc queryOtherLaneResource;
    LnnReadDataFunc lnnReadData;
    LnnCreateDataFunc lnnCreateData;
    LnnDeleteDataFunc lnnDeleteData;
    LnnGetSysTimeMsFunc lnnGetSysTimeMs;
    GetLaneProfileFunc getLaneProfile;
    GetLaneIdListFunc getLaneIdList;
    RegisterLaneIdListenerFunc registerLaneIdListener;
    UnregisterLaneIdListenerFunc unregisterLaneIdListener;
    GenerateLaneIdFunc generateLaneId;
    RemoveAuthSessionServerFunc removeAuthSessionServer;
    CheckIsAuthSessionServerFunc checkIsAuthSessionServer;
    UpdateLaneResourceLaneIdFunc updateLaneResourceLaneId;
    UpdateLaneBusinessInfoItemFunc updateLaneBusinessInfoItem;
    UpdateReqListLaneIdFunc updateReqListLaneId;
    HandleForceDownWifiDirectTransFunc handleForceDownWifiDirectTrans;
    GetConflictTypeWithErrcodeFunc getConflictTypeWithErrcode;
    HandleForceDownVirtualLinkFunc handleForceDownVirtualLink;
    CheckVirtualLinkOnlyFunc checkVirtualLinkOnly;
    GetLaneManagerFunc getLaneManager;
    AddLinkConflictInfoFunc addLinkConflictInfo;
    GetSupportBandWidthFunc getSupportBandWidth;
    GetAllSupportReuseBandWidthFunc getAllSupportReuseBandWidth;
    FindLaneResourceByLinkTypeFunc findLaneResourceByLinkType;

    // bus_center
    LnnNotifyDeviceTrustedChangeFunc lnnNotifyDeviceTrustedChange;
    LnnNotifyLpReportEventFunc lnnNotifyLpReportEvent;
    IsEnableSoftBusHeartbeatFunc isEnableSoftBusHeartbeat;
    LnnDiscTypeToConnAddrTypeFunc lnnDiscTypeToConnAddrType;
    LnnConvertAddrToAuthConnInfoFunc lnnConvertAddrToAuthConnInfo;
    LnnGetFullStoragePathFunc lnnGetFullStoragePath;
    LnnGenLocalNetworkIdFunc lnnGenLocalNetworkId;
    LnnMapHasNextFunc lnnMapHasNext;
    LnnMapNextFunc lnnMapNext;
    LnnMapDeinitIteratorFunc lnnMapDeinitIterator;
    LnnMapInitFunc lnnMapInit;
    LnnMapDeleteFunc lnnMapDelete;
    LnnMapSetFunc lnnMapSet;
    LnnMapGetFunc lnnMapGet;
    LnnMapEraseFunc lnnMapErase;
    LnnRegisterEventHandlerFunc lnnRegisterEventHandler;
    LnnUnregisterEventHandlerFunc lnnUnregisterEventHandler;
    LnnAsyncCallbackHelperFunc lnnAsyncCallbackHelper;
    LnnAsyncCallbackDelayHelperFunc lnnAsyncCallbackDelayHelper;
    LnnIsSameConnectionAddrFunc lnnIsSameConnectionAddr;
    LnnConvAddrTypeToDiscTypeFunc lnnConvAddrTypeToDiscType;
    GetOsAccountUidFunc getOsAccountUid;
    LnnIsDefaultOhosAccountFunc lnnIsDefaultOhosAccount;
    GetActiveOsAccountIdsFunc getActiveOsAccountIds;
    JudgeDeviceTypeAndGetOsAccountIdsFunc judgeDeviceTypeAndGetOsAccountIds;
    LnnNotifyNodeStatusChangedFunc lnnNotifyNodeStatusChanged;
    LnnNotifyOOBEStateChangeEventFunc lnnNotifyOOBEStateChangeEvent;
    LnnNotifyNetlinkStateChangeEventFunc lnnNotifyNetlinkStateChangeEvent;
    LnnGetLocalStrInfoByIfnameIdxFunc lnnGetLocalStrInfoByIfnameIdx;
    LnnNotifyAddressChangedEventFunc lnnNotifyAddressChangedEvent;
    LnnIsNeedInterceptBroadcastFunc lnnIsNeedInterceptBroadcast;

    // common
    SoftBusFrequencyToChannelFunc softBusFrequencyToChannel;
    GetLooperFunc getLooper;

    // broadcast
    BroadcastDiscEventFunc broadcastDiscEvent;
    BroadcastScanEventFunc broadcastScanEvent;
    SchedulerRegisterScanListenerFunc schedulerRegisterScanListener;
    SchedulerUnregisterListenerFunc schedulerUnregisterListener;

    // dfx
    AddChannelStatisticsInfoFunc addChannelStatisticsInfo;

    // trans
    TransGetChannelInfoByLaneHandleFunc transGetChannelInfoByLaneHandle;
    TransGetConnByChanIdFunc transGetConnByChanId;
    NotifyUdpQosEventFunc notifyUdpQosEvent;
    TransGetUdpChannelByIdFunc transGetUdpChannelById;

    // conn
    ConnCocTransRecvFunc connCocTransRecv;
    ConnBleGetConnectionByIdFunc connBleGetConnectionById;
    ConnBleReturnConnectionFunc connBleReturnConnection;
    ConnBleGetConnectionByAddrFunc connBleGetConnectionByAddr;
    ConnBleFreeConnectionFunc connBleFreeConnection;
    ConnBleSaveConnectionFunc connBleSaveConnection;
    ConnBleCreateConnectionFunc connBleCreateConnection;
    ConnDisconnectDeviceFunc connDisconnectDevice;
    ConnConnectDeviceFunc connConnectDevice;
    ConnSetConnectCallbackFunc connSetConnectCallback;
    ConnUnSetConnectCallbackFunc connUnSetConnectCallback;
    ConnPostBytesFunc connPostBytes;
    ConnGetHeadSizeFunc connGetHeadSize;
    ConnConfigPostLimitFunc connConfigPostLimit;

    // auth
    AuthGetLatestAuthSeqListByTypeFunc authGetLatestAuthSeqListByType;
    AuthGetIdByConnInfoFunc authGetIdByConnInfo;
    AuthPostTransDataFunc authPostTransData;
    AuthGetHmlConnInfoFunc authGetHmlConnInfo;
    AuthOpenConnFunc authOpenConn;
    AuthCloseConnFunc authCloseConn;
    SocketGetConnInfoFunc socketGetConnInfo;
    GetConnInfoByConnectionIdFunc getConnInfoByConnectionId;
    AuthGenRequestIdFunc authGenRequestId;
    AuthStartVerifyFunc authStartVerify;
    IsPotentialTrustedDeviceFunc isPotentialTrustedDevice;
    GenSeqFunc genSeq;
    RequireAuthLockFunc requireAuthLock;
    ReleaseAuthLockFunc releaseAuthLock;
    ConvertToDiscoveryTypeFunc convertToDiscoveryType;
    DupMemBufferFunc dupMemBuffer;
    GetAuthDataSizeFunc getAuthDataSize;
    ConvertToConnectOptionFunc convertToConnectOption;
    ProcessAuthDataFunc processAuthData;
    AuthDeviceFunc authDevice;
    RegAuthTransListenerFunc regAuthTransListener;
    UnregAuthTransListenerFunc unregAuthTransListener;
    AuthGetLatestAuthSeqListFunc authGetLatestAuthSeqList;
    AuthHasTrustedRelationFunc authHasTrustedRelation;
    CompareConnInfoFunc compareConnInfo;
    GetAuthManagerByAuthIdFunc getAuthManagerByAuthId;
    GetLatestSessionKeyFunc getLatestSessionKey;
    DelDupAuthManagerFunc delDupAuthManager;
    GetSessionKeyByIndexFunc getSessionKeyByIndex;

    // adapter
    SoftBusGetCurrentGroupFunc softBusGetCurrentGroup;
    SoftBusGetHotspotConfigFunc softBusGetHotspotConfig;
    SoftBusGetPublicKeyFunc softBusGetPublicKey;
    SoftBusRsaEncryptFunc softBusRsaEncrypt;
    SoftBusRsaDecryptFunc softBusRsaDecrypt;
    SoftBusRequestWlanChannelInfoFunc softBusRequestWlanChannelInfo;
    SoftBusRegWlanChannelInfoCbFunc softBusRegWlanChannelInfoCb;
    SoftBusRegisterWifiEventFunc softBusRegisterWifiEvent;
    SoftBusUnRegisterWifiEventFunc softBusUnRegisterWifiEvent;
    SoftBusAddBtStateListenerFunc softBusAddBtStateListener;
    SoftBusRemoveBtStateListenerFunc softBusRemoveBtStateListener;
    InitBroadcastMgrFunc initBroadcastMgr;
    DeInitBroadcastMgrFunc deInitBroadcastMgr;
    SetScanFilterFunc setScanFilter;
    GetScanFilterFunc getScanFilter;
    QueryBroadcastStatusFunc queryBroadcastStatus;
    BroadcastIsLpDeviceAvailableFunc broadcastIsLpDeviceAvailable;
    BroadcastGetBroadcastHandleFunc broadcastGetBroadcastHandle;
    BroadcastSetLpAdvParamFunc broadcastSetLpAdvParam;
    BroadcastSetAdvDeviceParamFunc broadcastSetAdvDeviceParam;
    BroadcastSetScanReportChannelToLpDeviceFunc broadcastSetScanReportChannelToLpDevice;
    BroadcastDisableSyncDataToLpDeviceFunc broadcastDisableSyncDataToLpDevice;
    StartBroadcastingFunc startBroadcasting;
    BroadcastEnableSyncDataToLpDeviceFunc broadcastEnableSyncDataToLpDevice;
    StartScanFunc startScan;
    RegisterScanListenerFunc registerScanListener;
    RegisterBroadcasterFunc registerBroadcaster;
    UnRegisterScanListenerFunc unRegisterScanListener;
    UnRegisterBroadcasterFunc unRegisterBroadcaster;
    StopBroadcastingFunc stopBroadcasting;
    StopScanFunc stopScan;
    SetBroadcastingDataFunc setBroadcastingData;
    LnnQueryLocalScreenStatusOnceFunc lnnQueryLocalScreenStatusOnce;
    SoftBusGetLinkedInfoFunc softBusGetLinkedInfo;
    SoftBusGetChannelListFor5GFunc softBusGetChannelListFor5G;
    SoftBusGetBrStateFunc softBusGetBrState;
    SoftBusGetBtStateFunc softBusGetBtState;
    LnnIsLinkReadyFunc lnnIsLinkReady;
    CheckLnnPermissionFunc checkLnnPermission;
} LnnOpenFuncList;

#ifdef __cplusplus
}
#endif

#endif