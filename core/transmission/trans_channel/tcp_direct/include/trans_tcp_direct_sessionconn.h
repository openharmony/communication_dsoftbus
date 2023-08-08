/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "softbus_def.h"
#include "common_list.h"
#include "softbus_app_info.h"
#include "softbus_base_listener.h"

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
    ListNode node;
    bool serverSide;
    int32_t channelId;
    AppInfo appInfo;
    uint32_t status;
    uint32_t timeout;
    int64_t req;
    uint32_t requestId;
    int64_t authId;
    bool isMeta;
    ListenerModule listenMod;
} SessionConn;

uint64_t TransTdcGetNewSeqId(void);

int32_t CreatSessionConnList(void);

SoftBusList *GetSessionConnList(void);

int32_t GetSessionConnLock(void);

void ReleaseSessonConnLock(void);

SessionConn *GetSessionConnByRequestId(uint32_t requestId);

SessionConn *GetSessionConnByReq(int64_t req);

SessionConn *CreateNewSessinConn(ListenerModule module, bool isServerSid);

SessionConn *GetSessionConnByFd(int32_t fd, SessionConn *conn);

SessionConn *GetSessionConnById(int32_t channelId, SessionConn *conn);

int32_t SetAppInfoById(int32_t channelId, const AppInfo *appInfo);
int32_t GetAppInfoById(int32_t channelId, AppInfo *appInfo);

int32_t SetAuthIdByChanId(int32_t channelId, int64_t authId);
int64_t GetAuthIdByChanId(int32_t channelId);

void TransDelSessionConnById(int32_t channelId);

int32_t TransTdcAddSessionConn(SessionConn *conn);

void SetSessionKeyByChanId(int32_t chanId, const char *sessionKey, int32_t keyLen);

int32_t SetSessionConnStatusById(int32_t channelId, uint32_t status);

int32_t TcpTranGetAppInfobyChannelId(int32_t channelId, AppInfo* appInfo);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif
