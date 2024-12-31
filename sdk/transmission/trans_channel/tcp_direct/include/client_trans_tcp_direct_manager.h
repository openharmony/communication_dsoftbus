/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef CLIENT_TRANS_TCP_DIRECT_MANAGER_H
#define CLIENT_TRANS_TCP_DIRECT_MANAGER_H

#include "client_trans_session_callback.h"
#include "client_trans_tcp_direct_message.h"
#include "softbus_sequence_verification.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int32_t fd;
    int32_t channelType;
    int32_t businessType;
    bool needStopListener;
    bool needRelease;
    int32_t fdRefCnt;
    int apiVersion;
    int32_t sequence;
    SeqVerifyInfo verifyInfo;
    char sessionKey[SESSION_KEY_LENGTH];
    char myIp[IP_LEN];
    SoftBusMutex fdLock;
    SoftBusList *pendingPacketsList;
} TcpDirectChannelDetail;

typedef struct {
    ListNode node;
    int32_t channelId;
    TcpDirectChannelDetail detail;
} TcpDirectChannelInfo;

int32_t ClientTransTdcOnChannelOpened(const char *sessionName, const ChannelInfo *channel);
int32_t ClientTransTdcOnChannelOpenFailed(int32_t channelId, int32_t errCode);

void TransTdcCloseChannel(int32_t channelId);

int32_t TransTdcGetInfoById(int32_t channelId, TcpDirectChannelInfo *info);
int32_t TransTdcGetInfoByFd(int32_t fd, TcpDirectChannelInfo *info);
TcpDirectChannelInfo *TransTdcGetInfoIncFdRefById(int32_t channelId, TcpDirectChannelInfo *info, bool withSeq);

int32_t TransTdcManagerInit(const IClientSessionCallBack *callback);
void TransTdcManagerDeinit(void);

int32_t TransTdcGetSessionKey(int32_t channelId, char *key, unsigned int len);
int32_t TransTdcGetHandle(int32_t channelId, int *handle);
int32_t TransDisableSessionListener(int32_t channelId);
int32_t TransTdcSetListenerStateById(int32_t channelId, bool needStopListener);

void TransUpdateFdState(int32_t channelId);

#ifdef __cplusplus
}
#endif

#endif
