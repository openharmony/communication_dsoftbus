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

#ifndef CLIENT_TRANS_UDP_MANAGER_H
#define CLIENT_TRANS_UDP_MANAGER_H

#include <stdint.h>

#include "client_trans_session_callback.h"
#include "session.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void (*OnStreamReceived)(int32_t channelId, const StreamData *data, const StreamData *ext,
        const StreamFrameInfo *param);
    int32_t (*OnFileGetSessionId)(int32_t channelId, int32_t *sessionId);
    void (*OnMessageReceived)(void);
    int32_t (*OnUdpChannelOpened)(int32_t channelId);
    void (*OnUdpChannelClosed)(int32_t channelId, ShutdownReason reason);
    void (*OnQosEvent)(int channelId, int eventId, int tvCount, const QosTv *tvList);
    int32_t (*OnIdleTimeoutReset)(int32_t sessionId);
    int32_t (*OnRawStreamEncryptDefOptGet)(const char *sessionName, bool *isEncrypt);
    int32_t (*OnRawStreamEncryptOptGet)(int32_t channelId, bool *isEncrypt);
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
} UdpChannel;

int32_t ClientTransUdpMgrInit(IClientSessionCallBack *callback);
void ClientTransUdpMgrDeinit(void);

int32_t TransOnUdpChannelOpened(const char *sessionName, const ChannelInfo *channel, int32_t *udpPort);
int32_t TransOnUdpChannelOpenFailed(int32_t channelId, int32_t errCode);
int32_t TransOnUdpChannelClosed(int32_t channelId, ShutdownReason reason);
int32_t TransOnUdpChannelQosEvent(int32_t channelId, int32_t eventId, int32_t tvCount, const QosTv *tvList);
int32_t TransOnUdpChannelBind(int32_t channelId, int32_t channelType);

int32_t ClientTransCloseUdpChannel(int32_t channelId, ShutdownReason reason);

int32_t TransUdpChannelSendStream(int32_t channelId, const StreamData *data, const StreamData *ext,
    const StreamFrameInfo *param);

int32_t TransUdpChannelSendFile(int32_t channelId, const char *sFileList[], const char *dFileList[], uint32_t fileCnt);

int32_t TransGetUdpChannelByFileId(int32_t dfileId, UdpChannel *udpChannel);

int32_t TransGetUdpChannel(int32_t channelId, UdpChannel *udpChannel);

void TransUdpDeleteFileListener(const char *sessionName);

int32_t TransUdpOnCloseAckReceived(int32_t channelId);

int32_t ClientEmitFileEvent(int32_t channelId);

int32_t TransLimitChange(int32_t channelId, uint8_t tos);

int32_t TransSetUdpChanelSessionId(int32_t channelId, int32_t sessionId);

int32_t TransSetUdpChannelRenameHook(int32_t channelId, OnRenameFileCallback onRenameFile);

int32_t TransUdpChannelSetStreamMultiLayer(int32_t channelId, const void *optValue);

int32_t TransSetUdpChannelTos(int32_t channelId);

int32_t TransGetUdpChannelTos(int32_t channelId, bool *isTosSet);
#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_UDP_MANAGER_H