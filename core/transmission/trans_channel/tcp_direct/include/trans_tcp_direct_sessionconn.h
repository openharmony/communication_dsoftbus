/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_TCP_DIRECT_SESSIONCONN_H
#define SOFTBUS_TCP_DIRECT_SESSIONCONN_H

#include <stdint.h>
#include "auth_interface.h"
#include "common_list.h"
#include "softbus_app_info.h"
#include "softbus_base_listener.h"
#include "softbus_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

#define REQUEST_INVALID 0

typedef enum {
    TCP_DIRECT_CHANNEL_STATUS_INIT,
    TCP_DIRECT_CHANNEL_STATUS_AUTH_CHANNEL,
    TCP_DIRECT_CHANNEL_STATUS_VERIFY_P2P,
    TCP_DIRECT_CHANNEL_STATUS_HANDSHAKING,
    TCP_DIRECT_CHANNEL_STATUS_CONNECTING,
    TCP_DIRECT_CHANNEL_STATUS_CONNECTED,
    TCP_DIRECT_CHANNEL_STATUS_TIMEOUT,
} TcpDirectChannelStatus;

typedef struct {
    bool serverSide;
    bool isMeta;
    ListenerModule listenMod;
    int32_t channelId;
    uint32_t status;
    uint32_t timeout;
    uint32_t requestId;
    int64_t req;
    ListNode node;
    AuthHandle authHandle;
    AppInfo appInfo;
} SessionConn;

typedef struct {
    ListNode node;
    int32_t channelId;
    int32_t businessType;
    int32_t connectType;
    char myIp[IP_LEN];
    char pkgName[PKG_NAME_SIZE_MAX];
    int32_t pid;
    bool isServer;
    int32_t channelType;
    char peerSessionName[SESSION_NAME_SIZE_MAX];
    char peerDeviceId[DEVICE_ID_SIZE_MAX];
    char peerIp[IP_LEN];
    int64_t timeStart;
    int32_t linkType;
    uint64_t callingTokenId;
} TcpChannelInfo;

uint64_t TransTdcGetNewSeqId(void);

int32_t CreatSessionConnList(void);

SoftBusList *GetSessionConnList(void);

SoftBusList *GetTcpChannelInfoList(void);

int32_t GetSessionConnLock(void);

int32_t GetTcpChannelInfoLock(void);

void ReleaseSessionConnLock(void);

void ReleaseTcpChannelInfoLock(void);

SessionConn *GetSessionConnByRequestId(uint32_t requestId);

SessionConn *GetSessionConnByReq(int64_t req);

SessionConn *CreateNewSessinConn(ListenerModule module, bool isServerSid);

int32_t GetSessionConnByFd(int32_t fd, SessionConn *conn);

int32_t GetSessionConnById(int32_t channelId, SessionConn *conn);

int32_t SetAppInfoById(int32_t channelId, const AppInfo *appInfo);
int32_t GetAppInfoById(int32_t channelId, AppInfo *appInfo);

int32_t SetAuthHandleByChanId(int32_t channelId, AuthHandle *authHandle);
int64_t GetAuthIdByChanId(int32_t channelId);
int32_t GetAuthHandleByChanId(int32_t channelId, AuthHandle *authHandle);

void TransDelSessionConnById(int32_t channelId);

int32_t TransTdcAddSessionConn(SessionConn *conn);

void SetSessionKeyByChanId(int32_t chanId, const char *sessionKey, int32_t keyLen);

int32_t SetSessionConnStatusById(int32_t channelId, uint32_t status);

int32_t TcpTranGetAppInfobyChannelId(int32_t channelId, AppInfo* appInfo);

int32_t *GetChannelIdsByAuthIdAndStatus(int32_t *num, const AuthHandle *authHandle, uint32_t status);

bool IsTdcRecoveryTransLimit(void);

int32_t CreateTcpChannelInfoList(void);

TcpChannelInfo *CreateTcpChannelInfo(const ChannelInfo *channel);

int32_t TransAddTcpChannelInfo(TcpChannelInfo *info);

int32_t TransDelTcpChannelInfoByChannelId(int32_t channelId);

void TransTdcChannelInfoDeathCallback(const char *pkgName, int32_t pid);

int32_t TransTdcGetIpAndConnectTypeById(int32_t channelId, char *localIp, char *remoteIp, uint32_t maxIpLen,
    int32_t *connectType);

int32_t TransGetPidByChanId(int32_t channelId, int32_t channelType, int32_t *pid);

int32_t TransTdcUpdateReplyCnt(int32_t channelId);

int32_t TransCheckTdcChannelOpenStatus(int32_t channelId, int32_t *curCount);

int32_t TransTcpGetPrivilegeCloseList(ListNode *privilegeCloseList, uint64_t tokenId, int32_t pid);

int32_t TransTdcResetReplyCnt(int32_t channelId);
#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif
