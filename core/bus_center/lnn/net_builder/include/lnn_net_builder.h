/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef LNN_NET_BUILDER_H
#define LNN_NET_BUILDER_H

#include <stdint.h>

#include "auth_interface.h"
#include "lnn_connId_callback_manager.h"
#include "lnn_event.h"
#include "lnn_sync_info_manager.h"
#include "softbus_bus_center.h"
#include "message_handler.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NODE_TYPE_C,
    NODE_TYPE_L
} NodeType;

#define JSON_KEY_NODE_CODE "NODE_CODE"
#define JSON_KEY_NODE_ADDR "NODE_ADDR"
#define JSON_KEY_NODE_PROXY_PORT "PROXY_PORT"
#define JSON_KEY_NODE_SESSION_PORT "SESSION_PORT"

typedef enum {
    MSG_TYPE_JOIN_LNN = 0,
    MSG_TYPE_DISCOVERY_DEVICE,
    MSG_TYPE_CLEAN_CONN_FSM,
    MSG_TYPE_VERIFY_RESULT,
    MSG_TYPE_DEVICE_VERIFY_PASS,
    MSG_TYPE_DEVICE_DISCONNECT = 5,
    MSG_TYPE_DEVICE_NOT_TRUSTED,
    MSG_TYPE_LEAVE_LNN,
    MSG_TYPE_SYNC_OFFLINE_FINISH,
    MSG_TYPE_NODE_STATE_CHANGED,
    MSG_TYPE_MASTER_ELECT = 10,
    MSG_TYPE_LEAVE_INVALID_CONN,
    MSG_TYPE_LEAVE_BY_ADDR_TYPE,
    MSG_TYPE_LEAVE_SPECIFIC,
    MSG_TYPE_LEAVE_BY_AUTH_ID,
    MSG_TYPE_BUILD_MAX,
} NetBuilderMessageType;

typedef struct {
    char nodeAddr[SHORT_ADDRESS_MAX_LEN];
    int32_t code;
    int32_t proxyPort;
    int32_t sessionPort;
    int32_t authPort;
} LnnNodeAddr;

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    char pkgName[PKG_NAME_SIZE_MAX];
    bool needReportFailure;
    int32_t callingPid;
    uint32_t requestId;
    uint32_t flag;
    ConnectionAddr addr;
    int64_t authId;
    ListNode node;
} MetaJoinRequestNode;

typedef struct {
    ListNode node;
    ConnectionAddr addr;
    bool needReportFailure;
} PendingJoinRequestNode;

typedef struct {
    NodeType nodeType;

    /* connection fsm list */
    ListNode fsmList;
    ListNode pendingList;
    /* connection count */
    int32_t connCount;

    SoftBusLooper *looper;
    SoftBusHandler handler;

    int32_t maxConnCount;
    int32_t maxConcurrentCount;
    bool isInit;
} NetBuilder;

typedef struct {
    uint32_t requestId;
    int32_t retCode;
    NodeInfo *nodeInfo;
    AuthHandle authHandle;
} VerifyResultMsgPara;

typedef struct {
    NodeInfo *nodeInfo;
    AuthHandle authHandle;
    ConnectionAddr addr;
} DeviceVerifyPassMsgPara;

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    char masterUdid[UDID_BUF_LEN];
    int32_t masterWeight;
} ElectMsgPara;

typedef struct {
    char oldNetworkId[NETWORK_ID_BUF_LEN];
    char newNetworkId[NETWORK_ID_BUF_LEN];
    ConnectionAddrType addrType;
} LeaveInvalidConnMsgPara;

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    ConnectionAddrType addrType;
} SpecificLeaveMsgPara;

typedef struct {
    char pkgName[PKG_NAME_SIZE_MAX];
    bool isNeedConnect;
    bool isSession;
    ConnectionAddr addr;
    NodeInfo *dupInfo;
    LnnDfxDeviceInfoReport infoReport;
} JoinLnnMsgPara;

typedef struct {
    char pkgName[PKG_NAME_SIZE_MAX];
    char networkId[NETWORK_ID_BUF_LEN];
} LeaveLnnMsgPara;

int32_t LnnInitNetBuilder(void);
int32_t LnnInitNetBuilderDelay(void);
void LnnDeinitNetBuilder(void);

int32_t LnnNotifyDiscoveryDevice(
    const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport, bool isNeedConnect);
void LnnSyncOfflineComplete(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len);
int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen);
int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType);
void LnnRequestLeaveAllOnlineNodes(void);
int32_t LnnRequestLeaveInvalidConn(const char *oldNetworkId, ConnectionAddrType addrType, const char *newNetworkId);
int32_t LnnRequestCleanConnFsm(uint16_t connFsmId);
int32_t LnnNotifyNodeStateChanged(const ConnectionAddr *addr);
int32_t LnnNotifyMasterElect(const char *networkId, const char *masterUdid, int32_t masterWeight);
int32_t LnnNotifyAuthHandleLeaveLNN(AuthHandle authHandle);
int32_t LnnNotifyEmptySessionKey(int64_t authId);
int32_t LnnNotifyLeaveLnnByAuthHandle(AuthHandle *authHandle);
int32_t LnnUpdateNodeAddr(const char *addr);
NodeInfo *FindNodeInfoByRquestId(uint32_t requestId);
AuthVerifyCallback *LnnGetVerifyCallback(void);
AuthVerifyCallback *LnnGetReAuthVerifyCallback(void);
void SetWatchdogFlag(bool flag);
bool GetWatchdogFlag(void);
NetBuilder* LnnGetNetBuilder(void);
void AddNodeToLnnBleReportExtraMap(const char *udidHash, const LnnBleReportExtra *bleExtra);
int32_t GetNodeFromLnnBleReportExtraMap(const char *udidHash, LnnBleReportExtra *bleExtra);
bool IsExistLnnDfxNodeByUdidHash(const char *udidHash, LnnBleReportExtra *bleExtra);
void DeleteNodeFromLnnBleReportExtraMap(const char *udidHash);
void ClearLnnBleReportExtraMap(void);
void DfxRecordLnnServerjoinStart(const ConnectionAddr *addr, const char *packageName, bool needReportFailure);
bool TryPendingJoinRequest(const JoinLnnMsgPara *para, bool needReportFailure);
bool IsNeedWifiReauth(const char *networkId, const char *newAccountHash, int32_t len);
void DfxRecordLnnAuthStart(const AuthConnInfo *connInfo, const JoinLnnMsgPara *para, uint32_t requestId);
void TryRemovePendingJoinRequest(void);
void UpdateLocalMasterNode(bool isCurrentNode, const char *masterUdid, int32_t weight);
void SendElectMessageToAll(const char *skipNetworkId);
bool IsNodeOnline(const char *networkId);
void RemovePendingRequestByAddrType(const bool *addrType, uint32_t typeLen);
void UpdateLocalNetCapability(void);
void OnReceiveMasterElectMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len);
void OnReceiveNodeAddrChangedMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t size);
int32_t ConifgLocalLedger(void);
int32_t SyncElectMessage(const char *networkId);
ConnectionAddrType GetCurrentConnectType(void);
NodeInfo *DupNodeInfo(const NodeInfo *nodeInfo);
bool NeedPendingJoinRequest(void);
void PostVerifyResult(uint32_t requestId, int32_t retCode, AuthHandle authHandle, const NodeInfo *info);
int32_t TrySendJoinLNNRequest(const JoinLnnMsgPara *para, bool needReportFailure, bool isShort);
int32_t PostBuildMessageToHandler(int32_t msgType, void *para);
bool DeletePcNodeInfo(const char *peerUdid);
const char *SelectUseUdid(const char *peerUdid, const char *lowerUdid);
void LnnDeleteLinkFinderInfo(const char *peerUdid);
void LnnProcessCompleteNotTrustedMsg(LnnSyncInfoType syncType, const char *networkId,
    const uint8_t *msg, uint32_t len);
void OnLnnProcessNotTrustedMsgDelay(void *para);
void LnnBlePcRestrictMapInit(void);
void AddNodeToPcRestrictMap(const char *udidHash);
void ClearPcRestrictMap(void);
void DeleteNodeFromPcRestrictMap(const char *udidHash);
int32_t GetNodeFromPcRestrictMap(const char *udidHash, uint32_t *count);
int32_t UpdateNodeFromPcRestrictMap(const char *udidHash);
int32_t JoinLnnWithNodeInfo(ConnectionAddr *addr, NodeInfo *info, bool isSession);
int32_t LnnServerJoinExt(ConnectionAddr *addr, LnnServerJoinExtCallBack *callback);
int32_t AuthFailNotifyProofInfo(int32_t errCode, const char *errorReturn, uint32_t errorReturnLen);
void NotifyForegroundUseridChange(char *networkId, uint32_t discoveryType, bool isChange);
#ifdef __cplusplus
}
#endif

#endif