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

#ifndef BR_CONNECTION_MANAGER_H
#define BR_CONNECTION_MANAGER_H

#include "common_list.h"
#include "softbus_conn_interface.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    ListNode node;
    uint32_t requestId;
    ConnectResult callback;
} RequestInfo;

#define BT_RFCOM_CONGEST_ON 0
#define BT_RFCOM_CONGEST_OFF 1
#define BR_CLIENT_TYPE 0
#define BR_SERVICE_TYPE 1

#define METHOD_NOTIFY_REQUEST 1
#define METHOD_NOTIFY_RESPONSE 2
#define METHOD_NOTIFY_ACK 4
#define METHOD_ACK_RESPONSE 5

#define MAGIC_NUMBER 0xBABEFACE

#define MIN_WINDOWS 10
#define MAX_WINDOWS 80
#define DEFAULT_WINDOWS 20

typedef enum {
    ADD_CONN_BR_INVALID,
    ADD_CONN_BR_CLIENT_CONNECTED_MSG,
    ADD_CONN_BR_CLIENT_DISCONNECTED_MSG,
    ADD_CONN_BR_SERVICE_CONNECTED_MSG,
    ADD_CONN_BR_SERVICE_DISCONNECTED_MSG,
    ADD_CONN_BR_CONGEST_MSG,
    ADD_CONN_BR_RECV_MSG,
    ADD_CONN_BR_CLOSING_TIMEOUT_MSG,
    ADD_CONN_BR_MAX
} BrConnLoopMsgType;

enum BRConnectionState {
    BR_CONNECTION_STATE_CONNECTING = 0,
    BR_CONNECTION_STATE_CONNECTED,
    BR_CONNECTION_STATE_CLOSING,
    BR_CONNECTION_STATE_CLOSED
};

typedef struct BrConnectionInfo {
    ListNode node;
    uint32_t connectionId;
    int32_t socketFd;
    int32_t sideType;
    char mac[BT_MAC_LEN];
    int32_t connectQueueState;
    int32_t state;
    int32_t refCount;
    int32_t refCountRemote;
    int32_t infoObjRefCount;
    char *recvBuf;
    int32_t recvSize;
    int32_t recvPos;
    int32_t conGestState;
    ListNode requestList;
    pthread_mutex_t lock;
    pthread_cond_t congestCond;
    uint64_t seq;
    uint64_t waitSeq;
    uint32_t windows;
    uint32_t ackTimeoutCount;
    ListNode pendingRequestList;
} BrConnectionInfo;

void InitBrConnectionManager(int32_t brBuffSize);

uint32_t GetLocalWindowsByConnId(uint32_t connId);

int32_t GetBrConnectionCount(void);

bool IsExitConnectionById(uint32_t connId);

bool IsExitBrConnectByFd(int32_t socketFd);

BrConnectionInfo *GetConnectionRef(uint32_t connId);

void ReleaseBrconnectionNode(BrConnectionInfo *conn);

void ReleaseConnectionRef(BrConnectionInfo *connInfo);

void ReleaseConnectionRefByConnId(uint32_t connId);

BrConnectionInfo* CreateBrconnectionNode(bool clientFlag);

int32_t GetConnectionInfo(uint32_t connectionId, ConnectionInfo *info);

int32_t SetRefCountByConnId(int32_t delta, int32_t *refCount, uint32_t connectionId);

void SetBrConnStateByConnId(uint32_t connId, int32_t state);

uint32_t SetBrConnStateBySocket(int32_t socket, int32_t state, int32_t *perState);

int32_t AddRequestByConnId(uint32_t connId, RequestInfo *requestInfo);

int32_t AddPendingRequestByConnId(uint32_t connId, RequestInfo *requestInfo);

int32_t AddConnectionList(BrConnectionInfo *newConnInfo);

void RfcomCongestEvent(int32_t socketFd, int32_t value);

int32_t GetBrRequestListByConnId(uint32_t connId, ListNode *notifyList,
    ConnectionInfo *connectionInfo, int32_t *sideType);

int32_t GetAndRemovePendingRequestByConnId(uint32_t connId, ListNode *pendings);

bool HasDiffMacDeviceExit(const ConnectOption *option);

int32_t GetBrConnStateByConnOption(const ConnectOption *option, uint32_t *outCountId, uint32_t *connectingReqId);

int32_t GetBrConnStateByConnectionId(uint32_t connId);

int32_t BrClosingByConnOption(const ConnectOption *option, int32_t *socketFd, int32_t *sideType);

bool BrCheckActiveConnection(const ConnectOption *option);

int32_t ResumeConnection(uint32_t connId, ListNode *pendings);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* BR_CONNECTION_MANAGER_H */
