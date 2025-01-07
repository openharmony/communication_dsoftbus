/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef CLIENT_TRANS_SESSION_OPERATE_H
#define CLIENT_TRANS_SESSION_OPERATE_H

#include "inner_socket.h"
#include "session.h"
#include "softbus_def.h"
#include "softbus_trans_def.h"
#include "client_trans_session_adapter.h"
#include "client_trans_session_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    ListNode node;
    int32_t socketId;
    int32_t channelId;
    int32_t seq;
    int32_t channelType;
    uint32_t timeout;
} DataSeqInfo;

int32_t GenerateSessionId(void);

void DestroySessionId(void);

bool IsValidSessionParam(const SessionParam *param);

SessionInfo *CreateNewSession(const SessionParam *param);

NO_SANITIZE("cfi") DestroySessionInfo *CreateDestroySessionNode(SessionInfo *sessionNode,
    const ClientSessionServer *server);

NO_SANITIZE("cfi") void ClientDestroySession(const ListNode *destroyList, ShutdownReason reason);

void DestroyClientSessionServer(ClientSessionServer *server, ListNode *destroyList);

ClientSessionServer *GetNewSessionServer(SoftBusSecType type, const char *sessionName,
    const char *pkgName, const ISessionListener *listener);

SessionInfo *CreateNonEncryptSessionInfo(const char *sessionName);

void DestroyAllClientSession(const ClientSessionServer *server, ListNode *destroyList);

void DestroyClientSessionByNetworkId(const ClientSessionServer *server,
    const char *networkId, int32_t type, ListNode *destroyList);

SessionServerInfo *CreateSessionServerInfoNode(const ClientSessionServer *clientSessionServer);

ClientSessionServer *GetNewSocketServer(SoftBusSecType type, const char *sessionName, const char *pkgName);

bool IsDistributedDataSession(const char *sessionName);

bool IsDifferentDataType(const SessionInfo *sessionInfo, int dataType, bool isEncyptedRawStream);

SessionInfo *CreateNewSocketSession(const SessionParam *param);

int32_t CheckBindSocketInfo(const SessionInfo *session);

void FillSessionParam(SessionParam *param, SessionAttribute *tmpAttr,
    ClientSessionServer *serverNode, SessionInfo *sessionNode);

void ClientConvertRetVal(int32_t socket, int32_t *retOut);

void ClientCleanUpIdleTimeoutSocket(const ListNode *destroyList);

void ClientCheckWaitTimeOut(const ClientSessionServer *serverNode, SessionInfo *sessionNode,
    int32_t waitOutSocket[], uint32_t capacity, uint32_t *num);

void ClientCleanUpWaitTimeoutSocket(int32_t waitOutSocket[], uint32_t waitOutNum);

void ClientUpdateIdleTimeout(const ClientSessionServer *serverNode, SessionInfo *sessionNode, ListNode *destroyList);

int32_t ClientDeleteSocketSession(int32_t sessionId);

int32_t ClientRemovePermission(const char *busName);

int32_t ClientGrantPermission(int uid, int pid, const char *busName);

int32_t GetQosValue(const QosTV *qos, uint32_t qosCount, QosType type, int32_t *value, int32_t defVal);

int32_t ReCreateSessionServerToServer(ListNode *sessionServerInfoList);

void FillDfsSocketParam(
    SessionParam *param, SessionAttribute *tmpAttr, ClientSessionServer *serverNode, SessionInfo *sessionNode);

void PrivilegeDestroyAllClientSession(
    const ClientSessionServer *server, ListNode *destroyList, const char *peerNetworkId);

int32_t ClientRegisterRelationChecker(IFeatureAbilityRelationChecker *relationChecker);

int32_t ClientTransCheckCollabRelation(
    const CollabInfo *sourceInfo, const CollabInfo *sinkInfo, int32_t channelId, int32_t channelType);

void DestroyRelationChecker(void);

int32_t LockClientDataSeqInfoList(void);

void UnlockClientDataSeqInfoList(void);

int32_t TransDataSeqInfoListInit(void);

void TransDataSeqInfoListDeinit(void);

int32_t DataSeqInfoListAddItem(uint32_t dataSeq, int32_t channelId, int32_t socketId, int32_t channelType);

int32_t DeleteDataSeqInfoList(uint32_t dataSeq, int32_t channelId);

void TransAsyncSendBytesTimeoutProc(void);
#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_SESSION_OPERATE_H
