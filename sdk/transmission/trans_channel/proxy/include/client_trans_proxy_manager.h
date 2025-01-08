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

#ifndef CLIENT_TRANS_PROXY_CHANNEL_H
#define CLIENT_TRANS_PROXY_CHANNEL_H

#include "client_trans_file_listener.h"
#include "client_trans_session_callback.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int32_t isEncrypted;
    int32_t sequence;
    char sessionKey[SESSION_KEY_LENGTH];
    int32_t linkType;
    int32_t osType;
}ProxyChannelInfoDetail;

typedef struct {
    ListNode node;
    int32_t channelId;
    ProxyChannelInfoDetail detail;
}ClientProxyChannelInfo;

typedef struct {
    int32_t active;
    int32_t timeout;
    int32_t sliceNumber;
    int32_t expectedSeq;
    int32_t dataLen;
    int32_t bufLen;
    char *data;
}SliceProcessor;

typedef enum {
    PROXY_CHANNEL_PRORITY_MESSAGE = 0,
    PROXY_CHANNEL_PRORITY_BYTES = 1,
    PROXY_CHANNEL_PRORITY_FILE = 2,
    PROXY_CHANNEL_PRORITY_BUTT = 3,
} ProxyChannelPriority;

typedef struct {
    ListNode head;
    int32_t channelId;
    SliceProcessor processor[PROXY_CHANNEL_PRORITY_BUTT];
}ChannelSliceProcessor;

int32_t ClientTransProxyInit(const IClientSessionCallBack *cb);

void ClientTransProxyDeinit(void);

int32_t ClientTransProxyGetInfoByChannelId(int32_t channelId, ProxyChannelInfoDetail *info);

int32_t ClientTransProxyGetOsTypeByChannelId(int32_t channelId, int32_t *osType);

int32_t ClientTransProxyGetLinkTypeByChannelId(int32_t channelId, int32_t *linkType);

int32_t ClientTransProxyAddChannelInfo(ClientProxyChannelInfo *info);

int32_t ClientTransProxyDelChannelInfo(int32_t channelId);

int32_t ClientTransProxyOnChannelOpened(const char *sessionName, const ChannelInfo *channel);

int32_t ClientTransProxyOnChannelClosed(int32_t channelId, ShutdownReason reason);

int32_t ClientTransProxyOnChannelOpenFailed(int32_t channelId, int32_t errCode);

int32_t ClientTransProxyOnDataReceived(int32_t channelId,
    const void *data, uint32_t len, SessionPktType type);

void ClientTransProxyCloseChannel(int32_t channelId);

int32_t TransProxyPackAndSendData(int32_t channelId, const void *data, uint32_t len,
    ProxyChannelInfoDetail* info, SessionPktType pktType);

int32_t TransProxyAsyncPackAndSendData(int32_t channelId, const void *data, uint32_t len, uint32_t dataSeq,
    SessionPktType pktType);

int32_t TransProxyChannelSendBytes(int32_t channelId, const void *data, uint32_t len, bool neeedAck);

int32_t TransProxyChannelAsyncSendBytes(int32_t channelId, const void *data, uint32_t len, uint32_t dataSeq);

int32_t TransProxyChannelSendMessage(int32_t channelId, const void *data, uint32_t len);

int32_t TransProxyChannelSendFile(int32_t channelId, const char *sFileList[], const char *dFileList[],
    uint32_t fileCnt);

int32_t ProcessFileFrameData(int32_t sessionId, int32_t channelId, const char *data, uint32_t len, int32_t type);
int32_t ClientTransProxyOnChannelBind(int32_t channelId, int32_t channelType);

#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_PROXY_CHANNEL_H
