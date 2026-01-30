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

#ifndef G_REG_LNN_EXT_FUNC_H
#define G_REG_LNN_EXT_FUNC_H

#include <string.h>

#include "auth_interface_struct.h"
#include "auth_manager_struct.h"
#include "auth_hichain_adapter_struct.h"
#include "bus_center_event_struct.h"
#include "bus_center_info_key_struct.h"
#include "device_auth.h"
#include "form/disc_event_form.h"
#include "g_enhance_lnn_func.h"
#include "lnn_node_info_struct.h"
#include "lnn_heartbeat_medium_mgr_struct.h"
#include "lnn_heartbeat_utils_struct.h"
#include "lnn_sync_info_manager_struct.h"
#include "lnn_network_manager_struct.h"
#include "lnn_physical_subnet_manager_struct.h"
#include "lnn_decision_db_struct.h"
#include "lnn_feature_capability_struct.h"
#include "lnn_lane_link_struct.h"
#include "lnn_local_net_ledger_struct.h"
#include "lnn_file_utils_struct.h"
#include "lnn_lane_interface_struct.h"
#include "lnn_lane_link_conflict_struct.h"
#include "lnn_map_struct.h"
#include "lnn_distributed_net_ledger_struct.h"
#include "form/lnn_event_form.h"
#include "lnn_async_callback_utils_struct.h"
#include "lnn_lane_struct.h"
#include "lnn_lane_def_struct.h"
#include "message_handler.h"
#include "softbus_broadcast_type_struct.h"
#include "softbus_broadcast_manager_struct.h"
#include "softbus_conn_common.h"
#include "softbus_conn_ble_connection_struct.h"
#include "softbus_conn_interface_struct.h"
#include "softbus_adapter_bt_common_struct.h"
#include "softbus_protocol_def.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"
#include "softbus_wifi_api_adapter_struct.h"
#include "softbus_app_info.h"
#include "session.h"
#include "softbus_adapter_wlan_extend_struct.h"
#include "softbus_rsa_encrypt_struct.h"
#include "trans_udp_channel_manager_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t (*AuthGetLatestAuthSeqListByTypeFunc)(const char *udid, int64_t *seqList,
    uint64_t *authVerifyTime, DiscoveryType type);
typedef void (*LnnDeinitHeartbeatFunc)(void);
typedef bool (*IsHeartbeatEnableFunc)(void);
typedef int32_t (*LnnRegistHeartbeatMediumMgrFunc)(LnnHeartbeatMediumMgr *mgr);
typedef int32_t (*LnnSetMediumParamBySpecificTypeFunc)(const LnnHeartbeatMediumParam *param);
typedef int32_t (*LnnGetMediumParamBySpecificTypeFunc)(LnnHeartbeatMediumParam *param, LnnHeartbeatType type);
typedef int32_t (*LnnStartHbByTypeAndStrategyFunc)(LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType,
    bool isRelay);
typedef bool (*LnnIsHeartbeatEnableFunc)(LnnHeartbeatType type);
typedef bool (*LnnHasActiveConnectionFunc)(const char *networkId, ConnectionAddrType addrType);
typedef int32_t (*LnnGetShortAccountHashFunc)(uint8_t *accountHash, uint32_t len);
typedef int32_t (*LnnGenerateHexStringHashFunc)(const unsigned char *str, char *hashStr, uint32_t len);
typedef bool (*LnnIsLocalSupportBurstFeatureFunc)(void);
typedef int32_t (*LnnRegSyncInfoHandlerFunc)(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler);
typedef int32_t (*LnnUnregSyncInfoHandlerFunc)(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler);
typedef int32_t (*LnnSendSyncInfoMsgFunc)(LnnSyncInfoType type, const char *networkId,
    const uint8_t *msg, uint32_t len, LnnSyncInfoMsgComplete complete);
typedef int32_t (*LnnSendWifiOfflineInfoMsgFunc)(void);
typedef int32_t (*LnnRegistProtocolFunc)(LnnProtocolManager *impl);
typedef int32_t (*LnnRegistPhysicalSubnetFunc)(LnnPhysicalSubnet *manager);
typedef int32_t (*LnnUnregistPhysicalSubnetByTypeFunc)(ProtocolType type);
typedef void (*LnnNotifyPhysicalSubnetStatusChangedFunc)(const char *ifName, ProtocolType type, void *status);
typedef int32_t (*LnnSetFeatureCapabilityFunc)(uint64_t *feature, FeatureCapability capaBit);
typedef int32_t (*LnnClearFeatureCapabilityFunc)(uint64_t *feature, FeatureCapability capaBit);
typedef bool (*LnnHasCapabilityFunc)(uint32_t capability, NetCapability type);
typedef uint32_t (*LnnGetNetCapabiltyFunc)(void);
typedef int32_t (*LnnSetDiscoveryTypeFunc)(NodeInfo *info, DiscoveryType type);
typedef int32_t (*LnnClearDiscoveryTypeFunc)(NodeInfo *info, DiscoveryType type);
typedef bool (*LnnIsNodeOnlineFunc)(const NodeInfo *info);
typedef void (*LnnDumpNodeInfoFunc)(const NodeInfo *deviceInfo, const char *log);
typedef int32_t (*LnnSetPtkFunc)(NodeInfo *info, const char *remotePtk);
typedef int32_t (*EncryptStorageDataFunc)(LnnEncryptDataLevel level, uint8_t *dbKey, uint32_t len);
typedef int32_t (*DecryptStorageDataFunc)(LnnEncryptDataLevel level, uint8_t *dbKey, uint32_t len);
typedef ReportCategory (*LnnAddOnlineNodeFunc)(NodeInfo *info);
typedef void (*LnnRemoveNodeFunc)(const char *udid);
typedef bool (*LnnSetRemoteScreenStatusInfoFunc)(const char *networkId, bool isScreenOn);
typedef int32_t (*LnnGetDLHeartbeatTimestampFunc)(const char *networkId, uint64_t *timestamp);
typedef int32_t (*LnnGetDLBleDirectTimestampFunc)(const char *networkId, uint64_t *timestamp);
typedef int32_t (*LnnGetDLUpdateTimestampFunc)(const char *udid, uint64_t *timestamp);
typedef int32_t (*LnnSetDLBleDirectTimestampFunc)(const char *networkId, uint64_t timestamp);
typedef int32_t (*LnnSetDLConnCapabilityFunc)(const char *networkId, uint32_t connCapability);
typedef int32_t (*LnnAddMetaInfoFunc)(NodeInfo *info);
typedef int32_t (*LnnDeleteMetaInfoFunc)(const char *udid, AuthLinkType type);
typedef void (*LnnUpdateStateVersionFunc)(StateVersionChangeReason reason);
typedef int32_t (*LnnGetLocalDeviceInfoFunc)(NodeBasicInfo *info);
typedef void (*LnnNotifyDeviceTrustedChangeFunc)(int32_t type, const char *msg, uint32_t msgLen);
typedef void (*LnnNotifyLpReportEventFunc)(SoftBusLpEventType type);
typedef bool (*IsEnableSoftBusHeartbeatFunc)(void);
typedef ConnectionAddrType (*LnnDiscTypeToConnAddrTypeFunc)(DiscoveryType type);
typedef bool (*LnnConvertAddrToAuthConnInfoFunc)(const ConnectionAddr *addr, AuthConnInfo *connInfo);
typedef int32_t (*LnnGetFullStoragePathFunc)(LnnFileId id, char *path, uint32_t len);
typedef int32_t (*LnnGenLocalNetworkIdFunc)(char *networkId, uint32_t len);

typedef int32_t (*LnnTriggerDirectHeartbeatFunc)(const char *networkId, uint64_t timeout);
typedef int32_t (*GetAllDevIdWithLinkTypeFunc)(LaneLinkType type, char **devIdList, uint8_t *devIdCnt);
typedef bool (*FindLaneResourceByDevInfoFunc)(const DevIdentifyInfo *inputInfo, LaneLinkType type);
typedef int32_t (*QueryOtherLaneResourceFunc)(const DevIdentifyInfo *inputInfo, LaneLinkType type);
typedef void *(*LnnReadDataFunc)(const Map *map, uint32_t key);
typedef int32_t (*LnnCreateDataFunc)(Map *map, uint32_t key, const void *value, uint32_t valueSize);
typedef void (*LnnDeleteDataFunc)(Map *map, uint32_t key);
typedef int32_t (*LnnDeleteDevInfoSyncToDBFunc)(const char *udid, int64_t accountId);
typedef int32_t (*SoftBusGetCurrentGroupFunc)(SoftBusWifiP2pGroupInfo *groupInfo);
typedef uint64_t (*LnnGetSysTimeMsFunc)(void);
typedef int32_t (*LnnGetRemoteStrInfoFunc)(const char *networkId, InfoKey key, char *info, uint32_t len);
typedef int32_t (*AuthGetHmlConnInfoFunc)(const char *uuid, AuthConnInfo *connInfo, bool isMeta);
typedef int64_t (*AuthGetIdByConnInfoFunc)(const AuthConnInfo *connInfo, bool isServer, bool isMeta);
typedef int32_t (*AuthOpenConnFunc)(const AuthConnInfo *info, uint32_t requestId,
    const AuthConnCallback *callback, bool isMeta);
typedef void (*AuthCloseConnFunc)(AuthHandle authHandle);
typedef int32_t (*AuthPostTransDataFunc)(AuthHandle authHandle, const AuthTransData *dataInfo);
typedef int32_t (*LnnGetRemoteNodeInfoByIdFunc)(const char *id, IdCategory type, NodeInfo *info);
typedef AuthManager *(*GetAuthManagerByAuthIdFunc)(int64_t authId);
typedef int32_t (*GetLatestSessionKeyFunc)(const SessionKeyList *list, AuthLinkType type,
    int32_t *index, SessionKey *key);
typedef void (*DelDupAuthManagerFunc)(AuthManager *auth);
typedef int32_t (*GetSessionKeyByIndexFunc)(const SessionKeyList *list, int32_t index,
    AuthLinkType type, SessionKey *key);

typedef MapIterator *(*LnnMapInitIteratorFunc)(Map *map);
typedef bool (*LnnMapHasNextFunc)(MapIterator *it);
typedef MapIterator *(*LnnMapNextFunc)(MapIterator *it);
typedef void (*LnnMapDeinitIteratorFunc)(MapIterator *it);
typedef void (*LnnMapInitFunc)(Map *map);
typedef void (*LnnMapDeleteFunc)(Map *map);
typedef int32_t (*LnnMapSetFunc)(Map *map, const char *key, const void *value, uint32_t valueSize);
typedef void* (*LnnMapGetFunc)(const Map *map, const char *key);
typedef int32_t (*LnnMapEraseFunc)(Map *map, const char *key);
typedef int32_t (*StrCmpIgnoreCaseFunc)(const char *str1, const char *str2);
typedef int32_t (*SoftBusAccessFileFunc)(const char *pathName, int32_t mode);
typedef void (*SoftBusRemoveFileFunc)(const char *fileName);
typedef int32_t (*SoftBusWriteFileFunc)(const char *fileName, const char *writeBuf, uint32_t len);
typedef int32_t (*SoftBusReadFullFileAndSizeFunc)(const char *fileName, char *readBuf, uint32_t maxLen, int32_t *size);
typedef int (*SoftBusChannelToFrequencyFunc)(int channel);
typedef bool (*SoftBusIs5GBandFunc)(int frequency);
typedef int32_t (*LnnNotifyDiscoveryDeviceFunc)(
    const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport, bool isNeedConnect);
typedef int32_t (*LnnRequestLeaveSpecificFunc)(const char *networkId, ConnectionAddrType addrType,
    DeviceLeaveReason leaveReason);
typedef ListenerModule (*LnnGetProtocolListenerModuleFunc)(ProtocolType protocol, ListenerMode mode);
typedef char *(*LnnConvertIdToDeviceTypeFunc)(uint16_t typeId);
typedef int32_t (*LnnConvertDeviceTypeToIdFunc)(const char *deviceType, uint16_t *typeId);
typedef bool (*IsFeatureSupportFunc)(uint64_t feature, FeatureCapability capaBit);
typedef const char *(*LnnGetDeviceUdidFunc)(const NodeInfo *info);
typedef bool (*LnnHasDiscoveryTypeFunc)(const NodeInfo *info, DiscoveryType type);
typedef void (*LnnDumpRemotePtkFunc)(const char *oldPtk, const char *newPtk, const char *log);
typedef int32_t (*LnnGetTrustedDevInfoFromDbFunc)(char **udidArray, uint32_t *num);
typedef int32_t (*LnnGetRemoteNodeInfoByKeyFunc)(const char *key, NodeInfo *info);
typedef int32_t (*LnnConvertDlIdFunc)(const char *srcId, IdCategory srcIdType, IdCategory dstIdType,
    char *dstIdBuf, uint32_t dstIdBufLen);
typedef bool (*LnnGetOnlineStateByIdFunc)(const char *id, IdCategory type);
typedef bool (*LnnSetDlPtkFunc)(const char *networkId, const char *remotePtk);
typedef const NodeInfo *(*LnnGetLocalNodeInfoFunc)(void);
typedef int32_t (*LnnGetLocalNodeInfoSafeFunc)(NodeInfo *info);
typedef int32_t (*LnnGetRemoteNumInfoFunc)(const char *networkId, InfoKey key, int32_t *info);
typedef int32_t (*LnnGetRemoteNumU64InfoFunc)(const char *networkId, InfoKey key, uint64_t *info);
typedef int32_t (*LnnGetRemoteByteInfoFunc)(const char *networkId, InfoKey key, uint8_t *info, uint32_t len);
typedef int32_t (*LnnSetLocalStrInfoFunc)(InfoKey key, const char *info);
typedef int32_t (*LnnSetLocalNumInfoFunc)(InfoKey key, int32_t info);
typedef int32_t (*LnnGetLocalStrInfoFunc)(InfoKey key, char *info, uint32_t len);
typedef int32_t (*LnnGetLocalNumInfoFunc)(InfoKey key, int32_t *info);

typedef int32_t (*LnnGetLocalNumU64InfoFunc)(InfoKey key, uint64_t *info);
typedef int32_t (*LnnGetLocalNum64InfoFunc)(InfoKey key, int64_t *info);
typedef int32_t (*LnnSetLocalNum64InfoFunc)(InfoKey key, int64_t info);
typedef int32_t (*LnnSetLocalByteInfoFunc)(InfoKey key, const uint8_t *info, uint32_t len);
typedef int32_t (*LnnGetLocalNum16InfoFunc)(InfoKey key, int16_t *info);
typedef int32_t (*LnnGetLocalNumU16InfoFunc)(InfoKey key, uint16_t *info);
typedef int32_t (*LnnGetLocalNumU32InfoFunc)(InfoKey key, uint32_t *info);
typedef int32_t (*LnnGetLocalByteInfoFunc)(InfoKey key, uint8_t *info, uint32_t len);
typedef int32_t (*LnnGetAllOnlineNodeInfoFunc)(NodeBasicInfo **info, int32_t *infoNum);
typedef int32_t (*LnnGetOnlineAndOfflineWithinTimeUdidsFunc)(char **udids, int32_t *udidNum, uint64_t timeRange);
typedef int32_t (*LnnGetNodeKeyInfoFunc)(const char *networkId, int key, uint8_t *info, uint32_t infoLen);
typedef int32_t (*LnnSetNodeKeyInfoFunc)(const char *networkId, int key, uint8_t *info, uint32_t infoLen);
typedef int32_t (*LnnGetNetworkIdByUdidFunc)(const char *udid, char *buf, uint32_t len);
typedef int32_t (*LnnGetNetworkIdByUdidHashFunc)(const uint8_t *udidHash, uint32_t udidHashLen, char *buf, uint32_t len,
    bool needOnline);
typedef int32_t (*LnnRegisterEventHandlerFunc)(LnnEventType event, LnnEventHandler handler);
typedef void (*LnnUnregisterEventHandlerFunc)(LnnEventType event, LnnEventHandler handler);
typedef int32_t (*LnnAsyncCallbackHelperFunc)(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para);
typedef int32_t (*LnnAsyncCallbackDelayHelperFunc)(SoftBusLooper *looper, LnnAsyncCallbackFunc callback,
    void *para, uint64_t delayMillis);
typedef bool (*LnnIsSameConnectionAddrFunc)(const ConnectionAddr *addr1, const ConnectionAddr *addr2, bool isShort);
typedef DiscoveryType (*LnnConvAddrTypeToDiscTypeFunc)(ConnectionAddrType type);
typedef int32_t (*GetOsAccountUidFunc)(char *id, uint32_t idLen, uint32_t *len);
typedef bool (*LnnIsDefaultOhosAccountFunc)(void);
typedef int32_t (*GetActiveOsAccountIdsFunc)(void);
typedef int32_t (*JudgeDeviceTypeAndGetOsAccountIdsFunc)(void);
typedef int32_t (*LnnGetAllMetaNodeInfoFunc)(MetaNodeInfo *infos, int32_t *infoNum);
typedef void (*LnnNotifyNodeStatusChangedFunc)(NodeStatus *info, NodeStatusType type);
typedef bool (*LnnIsLSANodeFunc)(const NodeBasicInfo *info);
typedef NodeInfo *(*LnnGetNodeInfoByIdFunc)(const char *id, IdCategory type);
typedef void (*LnnDumpSparkCheckFunc)(const unsigned char *sparkCheck, const char *log);
typedef void (*LnnNotifyHaLeaveMetaNodeEventFunc)(const char *metaNodeId);

typedef int32_t (*TransGetChannelInfoByLaneHandleFunc)(uint32_t laneHandle, int32_t *channelId, int32_t *channelType);
typedef int32_t (*SoftBusGetLinkedInfoFunc)(SoftBusWifiLinkedInfo *info);
typedef int32_t (*SoftBusGetChannelListFor5GFunc)(int32_t *channelList, int32_t num);
typedef int32_t (*RegAuthTransListenerFunc)(int32_t module, const AuthTransListener *listener);
typedef void (*UnregAuthTransListenerFunc)(int32_t module);
typedef int32_t (*GetLaneProfileFunc)(uint32_t profileId, LaneProfile *profile);
typedef void (*DfxRecordTriggerTimeFunc)(LnnTriggerReason reason, LnnEventLnnStage stage);
typedef int (*SoftBusGetBrStateFunc)(void);
typedef int32_t (*GetLaneIdListFunc)(uint32_t profileId, uint64_t **laneIdList, uint32_t *listSize);
typedef void (*RegisterLaneIdListenerFunc)(const ILaneIdStateListener *listener);
typedef int32_t (*TransGetConnByChanIdFunc)(int32_t channelId, int32_t channelType, int32_t* connId);
typedef void (*LnnNotifyOOBEStateChangeEventFunc)(SoftBusOOBEState state);
typedef int32_t (*AuthGetLatestAuthSeqListFunc)(const char *udid, int64_t *seqList, uint32_t num);
typedef int (*SoftBusGetBtStateFunc)(void);
typedef TrustedReturnType (*AuthHasTrustedRelationFunc)(void);
typedef SoftBusScreenState (*GetScreenStateFunc)(void);
typedef SoftBusScreenLockState (*GetScreenLockStateFunc)(void);
typedef int32_t (*LnnTriggerSleHeartbeatFunc)(void);
typedef int32_t (*LnnCleanTriggerSparkInfoFunc)(const char *udid, ConnectionAddrType addrType);
typedef int32_t (*LnnOfflineTimingBySleHbFunc)(const char *networkId, ConnectionAddrType addrType);
typedef int32_t (*LnnStopSleHeartbeatFunc)(void);
typedef int32_t (*LnnStopSleOfflineTimingStrategyFunc)(const char *networkId);
typedef int32_t (*SocketGetConnInfoFunc)(int32_t fd, AuthConnInfo *connInfo, bool *isServer, int32_t ifnameIdx);
typedef int32_t (*GetConnInfoByConnectionIdFunc)(uint32_t connectionId, AuthConnInfo *connInfo);
typedef uint32_t (*AuthGenRequestIdFunc)(void);
typedef void (*UnregisterLaneIdListenerFunc)(const ILaneIdStateListener *listener);

typedef bool (*LnnQueryLocalScreenStatusOnceFunc)(bool notify);
typedef bool (*IsPotentialTrustedDeviceFunc)(TrustedRelationIdType idType,
                                             const char *deviceId, bool isPrecise, bool isPointToPoint);
typedef int32_t (*LnnOfflineTimingByHeartbeatFunc)(const char *networkId, ConnectionAddrType addrType);
typedef bool (*LnnIsCloudSyncEndFunc)(void);
typedef bool (*LnnIsSupportHeartbeatCapFunc)(uint32_t hbCapacity, HeartbeatCapability capaBit);
typedef void (*LnnRequestBleDiscoveryProcessFunc)(int32_t strategy, int64_t timeout);
typedef int32_t (*BroadcastGetBroadcastHandleFunc)(int32_t bcId, int32_t *bcHandle);
typedef int32_t (*BroadcastSetLpAdvParamFunc)(int32_t duration, int32_t maxExtAdvEvents, int32_t window,
    int32_t interval, int32_t bcHandle);
typedef bool (*BroadcastSetAdvDeviceParamFunc)(LpServerType type, const LpBroadcastParam *bcParam,
    const LpScanParam *scanParam);
typedef int32_t (*BroadcastSetScanReportChannelToLpDeviceFunc)(int32_t listenerId, bool enable);
typedef int32_t (*BroadcastDisableSyncDataToLpDeviceFunc)(void);
typedef int32_t (*StartBroadcastingFunc)(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet);
typedef int32_t (*BroadcastEnableSyncDataToLpDeviceFunc)(void);
typedef int32_t (*StartScanFunc)(int32_t listenerId, const BcScanParams *param);
typedef int32_t (*RegisterScanListenerFunc)(BroadcastProtocol protocol,
    BaseServiceType srvType, int32_t *listenerId, const ScanCallback *cb);
typedef int32_t (*AuthStartVerifyFunc)(const AuthConnInfo *connInfo, const AuthVerifyParam *authVerifyParam,
    const AuthVerifyCallback *callback);
typedef AuthVerifyCallback *(*LnnGetReAuthVerifyCallbackFunc)(void);
typedef void (*NotifyForegroundUseridChangeFunc)(char *networkId, uint32_t discoveryType, bool isChange);
typedef int32_t (*LnnSetDLConnUserIdCheckSumFunc)(const char *networkId, int32_t userIdCheckSum);

typedef int32_t (*RegisterBroadcasterFunc)(BroadcastProtocol protocol,
    BaseServiceType srvType, int32_t *bcId, const BroadcastCallback *cb);
typedef int32_t (*UnRegisterScanListenerFunc)(int32_t listenerId);
typedef int32_t (*UnRegisterBroadcasterFunc)(int32_t bcId);
typedef int32_t (*StopBroadcastingFunc)(int32_t bcId);
typedef int32_t (*StopScanFunc)(int32_t listenerId);

typedef uint8_t *(*ConnCocTransRecvFunc)(
    uint32_t connectionId, LimitedBuffer *buffer, int32_t *outLen);
typedef ConnBleConnection *(*ConnBleGetConnectionByIdFunc)(uint32_t connectionId);
typedef void (*ConnBleReturnConnectionFunc)(ConnBleConnection **connection);
typedef ConnBleConnection *(*ConnBleGetConnectionByAddrFunc)(const char *addr,
                                                             ConnSideType side, BleProtocolType protocol);
typedef int32_t (*SetBroadcastingDataFunc)(int32_t bcId, const BroadcastPacket *packet);
typedef int (*SoftBusAddBtStateListenerFunc)(const SoftBusBtStateListener *listener, int *listenerId);
typedef int (*SoftBusRemoveBtStateListenerFunc)(int listenerId);
typedef int32_t (*InitBroadcastMgrFunc)(void);
typedef int32_t (*DeInitBroadcastMgrFunc)(void);
typedef int32_t (*SetScanFilterFunc)(int32_t listenerId, const BcScanFilter *scanFilter, uint8_t filterNum);
typedef int32_t (*GetScanFilterFunc)(int32_t listenerId, BcScanFilter **scanFilter, uint8_t *filterNum);
typedef int32_t (*QueryBroadcastStatusFunc)(int32_t bcId, int32_t *status);
typedef bool (*BroadcastIsLpDeviceAvailableFunc)(void);

typedef void (*ConnBleFreeConnectionFunc)(ConnBleConnection *connection);
typedef int32_t (*ConnBleSaveConnectionFunc)(ConnBleConnection *connection);
typedef ConnBleConnection *(*ConnBleCreateConnectionFunc)(
    const char *addr, BleProtocolType protocol, ConnSideType side, int32_t underlayerHandle, bool fastestConnectEnable);
typedef int32_t (*TransGetUdpChannelByIdFunc)(int32_t channelId, UdpChannelInfo *channel);
typedef int32_t (*NotifyUdpQosEventFunc)(const AppInfo *info, int32_t eventId, int32_t tvCount, const QosTv *tvList);
typedef int64_t (*GenSeqFunc)(bool isServer);
typedef bool (*RequireAuthLockFunc)(void);
typedef void (*ReleaseAuthLockFunc)(void);
typedef bool (*CompareConnInfoFunc)(const AuthConnInfo *info1, const AuthConnInfo *info2, bool cmpShortHash);

typedef uint64_t (*GenerateLaneIdFunc)(const char *localUdid, const char *remoteUdid, LaneLinkType linkType);
typedef int32_t (*RemoveAuthSessionServerFunc)(const char *peerIp);
typedef int32_t (*CheckIsAuthSessionServerFunc)(const char *peerIp, bool *isServer);
typedef DiscoveryType (*ConvertToDiscoveryTypeFunc)(AuthLinkType type);
typedef uint8_t *(*DupMemBufferFunc)(const uint8_t *buf, uint32_t size);
typedef uint32_t (*GetAuthDataSizeFunc)(uint32_t len);
typedef int32_t (*ConnPostBytesFunc)(uint32_t connectionId, ConnPostData *data);
typedef uint32_t (*ConnGetHeadSizeFunc)(void);

typedef int32_t (*UpdateLaneResourceLaneIdFunc)(uint64_t oldLaneId, uint64_t newLaneId, const char *peerUdid);
typedef int32_t (*UpdateLaneBusinessInfoItemFunc)(uint64_t oldLaneId, uint64_t newLaneId);
typedef int32_t (*UpdateReqListLaneIdFunc)(uint64_t oldLaneId, uint64_t newLaneId);
typedef int32_t (*ConvertToConnectOptionFunc)(const AuthConnInfo *connInfo, ConnectOption *option);
typedef int32_t (*ConnDisconnectDeviceFunc)(uint32_t connectionId);
typedef int32_t (*ConnConnectDeviceFunc)(const ConnectOption *info, uint32_t requestId, const ConnectResult *result);
typedef int32_t (*ConnSetConnectCallbackFunc)(ConnModule moduleId, const ConnectCallback *callback);
typedef void (*ConnUnSetConnectCallbackFunc)(ConnModule moduleId);

typedef int (*SoftBusFrequencyToChannelFunc)(int frequency);
typedef int32_t (*SoftBusRequestWlanChannelInfoFunc)(int32_t *channelId, uint32_t num);
typedef int32_t (*SoftBusRegWlanChannelInfoCbFunc)(WlanChannelInfoCb *cb);
typedef int32_t (*SoftBusRegisterWifiEventFunc)(ISoftBusScanResult *cb);
typedef int32_t (*SoftBusUnRegisterWifiEventFunc)(ISoftBusScanResult *cb);
typedef int32_t (*ConnConfigPostLimitFunc)(const LimitConfiguration *configuration);
typedef int32_t (*ProcessAuthDataFunc)(int64_t authSeq, const uint8_t *data, uint32_t len, DeviceAuthCallback *cb);
typedef int32_t (*AuthDeviceFunc)(int32_t userId, int64_t authReqId,
                                  const char *authParams, const DeviceAuthCallback *cb);
typedef int32_t (*SoftBusGetPublicKeyFunc)(uint8_t *publicKey, uint32_t publicKeyLen);
typedef int32_t (*SoftBusRsaEncryptFunc)(const uint8_t *srcData,
                                         uint32_t srcDataLen, PublicKey *publicKey,
                                         uint8_t **encryptedData, uint32_t *encryptedDataLen);
typedef int32_t (*SoftBusRsaDecryptFunc)(
    const uint8_t *srcData, uint32_t srcDataLen, uint8_t **decryptedData, uint32_t *decryptedDataLen);
typedef void (*BroadcastDiscEventFunc)(int32_t eventScene,
    int32_t eventStage, DiscEventDiscExtra *discExtra, int32_t size);
typedef void (*BroadcastScanEventFunc)(int32_t eventScene,
    int32_t eventStage, DiscEventScanExtra *scanExtra, int32_t size);
typedef int32_t (*LnnConvertDLidToUdidFunc)(const char *id, IdCategory type, char *udid, uint32_t len);
typedef void (*LnnNotifyNetlinkStateChangeEventFunc)(NetManagerIfNameState state, const char *ifName);
typedef SendSyncInfoParam *(*CreateSyncInfoParamFunc)(
    LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len, LnnSyncInfoMsgComplete complete);
typedef bool (*LnnIsLinkReadyFunc)(const char *iface);
typedef void (*LnnSendAsyncInfoMsgFunc)(void *param);
typedef int32_t (*LnnSetDLDeviceBroadcastCipherKeyFunc)(const char *udid, const void *cipherKey);
typedef int32_t (*LnnSetDLDeviceBroadcastCipherIvFunc)(const char *udid, const void *cipherIv);
typedef bool (*LnnSaveBroadcastLinkKeyFunc)(const char *udid, const BroadcastCipherInfo *info);
typedef SoftBusLooper *(*GetLooperFunc)(int type);
typedef void (*LnnUpdateNodeBleMacFunc)(const char *networkId, char *bleMac, uint32_t len);
typedef int32_t (*HandleForceDownWifiDirectTransFunc)(const char *udidhashStr, LinkConflictType conflictType);

typedef LinkConflictType (*GetConflictTypeWithErrcodeFunc)(int32_t conflictErrcode);
typedef LnnLaneManager* (*GetLaneManagerFunc)(void);
typedef void (*AddChannelStatisticsInfoFunc)(int32_t channelId, int32_t channelType);
typedef int32_t (*AddLinkConflictInfoFunc)(const LinkConflictInfo *inputInfo);
typedef int32_t (*SchedulerRegisterScanListenerFunc)(BroadcastProtocol protocol,
    BaseServiceType type, int32_t *listenerId, const ScanCallback *cb);
typedef int32_t (*SchedulerUnregisterListenerFunc)(int32_t listenerId);
typedef const NodeInfo *(*LnnGetOnlineNodeByUdidHashFunc)(const char *recvUdidHash);
typedef int32_t (*LnnGetLocalStrInfoByIfnameIdxFunc)(InfoKey key, char *info, uint32_t len, int32_t ifIdx);
typedef int32_t (*LnnGetRemoteStrInfoByIfnameIdxFunc)(const char *networkId,
                                                      InfoKey key, char *info, uint32_t len, int32_t ifIdx);
typedef void (*LnnNotifyAddressChangedEventFunc)(const char *ifName);
typedef int32_t (*LnnGetLocalNumInfoByIfnameIdxFunc)(InfoKey key, int32_t *info, int32_t ifIdx);
typedef int32_t (*LnnGetRemoteNumInfoByIfnameIdxFunc)(const char *networkId, InfoKey key, int32_t *info, int32_t ifIdx);
typedef int32_t (*GetSupportBandWidthFunc)(const char *peerNetworkId, LaneTransType transType, uint32_t *supportBw);
typedef int32_t (*GetAllSupportReuseBandWidthFunc)(const char *peerNetworkId, LaneTransType transType,
    uint32_t **supportBw, uint8_t *bwCnt);
typedef int32_t (*FindLaneResourceByLinkTypeFunc)(const char *peerUdid, LaneLinkType type, LaneResource *resource);
typedef bool (*LnnIsNeedInterceptBroadcastFunc)(bool disableGlass);
typedef int32_t (*CheckLnnPermissionFunc)(const char *interfaceName, const char *processName);

typedef int32_t (*HandleForceDownVirtualLinkFunc)(void);
typedef bool (*CheckVirtualLinkOnlyFunc)(void);
typedef int32_t (*SoftBusGetHotspotConfigFunc)(int32_t *apChannel);
typedef bool (*IsHeartbeatEnableForMcuFunc)(void);
typedef bool (*LnnIsLocalSupportMcuFeatureFunc)(void);

#ifdef __cplusplus
}
#endif

#endif