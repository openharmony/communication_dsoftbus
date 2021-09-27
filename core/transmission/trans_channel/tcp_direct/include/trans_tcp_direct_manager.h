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

#ifndef SOFTBUS_DIRECT_CHANNEL_INTERFACE_H
#define SOFTBUS_DIRECT_CHANNEL_INTERFACE_H

#include <stdbool.h>

#include "softbus_app_info.h"
#include "softbus_base_listener.h"
#include "softbus_conn_interface.h"
#include "softbus_property.h"
#include "trans_channel_callback.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DC_MSG_PACKET_HEAD_SIZE 24
#define SESSION_KEY_INDEX_SIZE 4
#define MESSAGE_INDEX_SIZE 4

#define MAGIC_NUMBER 0xBABEFACE
#define MODULE_SESSION 6
#define FLAG_REQUEST 0
#define FLAG_REPLY 1

#define SKEY_LENGTH 16

typedef enum {
    TCP_DIRECT_CHANNEL_STATUS_HANDSHAKING,
    TCP_DIRECT_CHANNEL_STATUS_CONNECTING,
    TCP_DIRECT_CHANNEL_STATUS_CONNECTED,
    TCP_DIRECT_CHANNEL_STATUS_TIMEOUT,
} TcpDirectChannelStatus;

typedef struct {
    char sessionKey[SKEY_LENGTH];
    int sessionIndex;
} IAuthConnection;

typedef struct {
    ListNode node;
    bool serverSide;
    int32_t channelId;
    AppInfo appInfo;
    uint32_t status;
    uint32_t timeout;
} SessionConn;

typedef struct {
    uint32_t magicNumber;
    uint32_t module;
    uint64_t seq;
    uint32_t flags;
    uint32_t dataLen;
} TdcPacketHead;

int32_t TransOpenTcpDirectChannel(AppInfo *appInfo, const ConnectOption *connInfo, int32_t *channelId);

uint64_t TransTdcGetNewSeqId(void);
SessionConn *GetSessionConnById(int32_t channelId, SessionConn *conn);
SessionConn *GetSessionConnByFd(int fd, SessionConn *conn);

int32_t SetAppInfoById(int32_t channelId, const AppInfo *appInfo);
int32_t SetSessionConnStatusById(int32_t channelId, int32_t status);

int32_t TransTdcAddSessionConn(SessionConn *conn);

void TransDelSessionConnById(int32_t channelId);

SoftBusList *GetTdcInfoList(void);
void SetTdcInfoList(SoftBusList *sessionConnList);
int32_t TransTcpDirectInit(const IServerChannelCallBack *cb);
void TransTcpDirectDeinit(void);
void TransTdcDeathCallback(const char *pkgName);
int32_t GenerateTdcChannelId(void);
void SetSessionKeyByChanId(int chanId, const char *sessionKey, int32_t keyLen);
#ifdef __cplusplus
}
#endif

#endif
