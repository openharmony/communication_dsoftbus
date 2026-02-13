/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef CLIENT_TRANS_UDP_MANAGER_STRUCT_H
#define CLIENT_TRANS_UDP_MANAGER_STRUCT_H

#include <netinet/in.h>
#include <stdint.h>
#include <stdbool.h>
#include "session.h"
#include "softbus_def.h"
#include "trans_type.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void (*OnStreamReceived)(int32_t channelId, const StreamData *data, const StreamData *ext,
        const StreamFrameInfo *param);
    int32_t (*OnFileGetSessionId)(int32_t channelId, int32_t *sessionId);
    void (*OnMessageReceived)(void);
    int32_t (*OnUdpChannelOpened)(int32_t channelId, SocketAccessInfo *accessInfo);
    void (*OnUdpChannelClosed)(int32_t channelId, ShutdownReason reason);
    void (*OnQosEvent)(int channelId, int eventId, int tvCount, const QosTv *tvList);
    int32_t (*OnIdleTimeoutReset)(int32_t sessionId);
    int32_t (*OnRawStreamEncryptDefOptGet)(const char *sessionName, bool *isEncrypt);
    int32_t (*OnRawStreamEncryptOptGet)(int32_t sessionId, int32_t channelId, bool *isEncrypt);
} UdpChannelMgrCb;

typedef struct {
    bool isServer;
    int32_t peerUid;
    int32_t peerPid;
    char mySessionName[SESSION_NAME_SIZE_MAX];
    char peerSessionName[SESSION_NAME_SIZE_MAX];
    char peerDeviceId[DEVICE_ID_SIZE_MAX];
    char groupId[GROUP_ID_SIZE_MAX];
    char myIp[IP_LEN];
} sessionNeed;

typedef struct {
    ListNode node;
    int32_t channelId;
    int32_t dfileId;
    int32_t businessType;
    sessionNeed info;
    int32_t routeType;
    int32_t sessionId;
    OnRenameFileCallback onRenameFile;
    bool isEnable;
    bool isTosSet;
    int32_t peerUserId;
    int32_t tokenType;
    uint64_t peerTokenId;
    char peerAccountId[ACCOUNT_UID_LEN_MAX];
    char extraAccessInfo[EXTRA_ACCESS_INFO_LEN_MAX];
    bool enableMultipath;
    bool isReserveChannel;
    socklen_t addrLen;
    struct sockaddr_storage addr;
} UdpChannel;

#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_UDP_MANAGER_STRUCT_H