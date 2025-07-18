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

#include "client_trans_session_callback.h"
#include "trans_proxy_process_data.h"

#define PAGING_NONCE_LEN 16

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int32_t isEncrypted;
    int32_t sequence;
    char sessionKey[SESSION_KEY_LENGTH];
    int32_t linkType;
    int32_t osType;
    bool isD2D;
    uint32_t dataLen;
    char extraData[EXTRA_DATA_MAX_LEN];
    char pagingNonce[PAGING_NONCE_LEN];
    char pagingSessionkey[SHORT_SESSION_KEY_LENGTH];
    char pagingAccountId[ACCOUNT_UID_LEN_MAX];
}ProxyChannelInfoDetail;

typedef struct {
    ListNode node;
    int32_t channelId;
    ProxyChannelInfoDetail detail;
}ClientProxyChannelInfo;

int32_t ClientTransProxyInit(const IClientSessionCallBack *cb);

void ClientTransProxyDeinit(void);

int32_t ClientTransProxyGetInfoByChannelId(int32_t channelId, ProxyChannelInfoDetail *info);

int32_t ClientTransProxyGetOsTypeByChannelId(int32_t channelId, int32_t *osType);

int32_t ClientTransProxyGetLinkTypeByChannelId(int32_t channelId, int32_t *linkType);

int32_t ClientTransProxyAddChannelInfo(ClientProxyChannelInfo *info);

int32_t ClientTransProxyDelChannelInfo(int32_t channelId);

int32_t ClientTransProxyOnChannelOpened(
    const char *sessionName, const ChannelInfo *channel, SocketAccessInfo *accessInfo);

int32_t ClientTransProxyOnChannelClosed(int32_t channelId, ShutdownReason reason);

int32_t ClientTransProxyOnChannelOpenFailed(int32_t channelId, int32_t errCode);

int32_t ClientTransProxyOnDataReceived(int32_t channelId,
    const void *data, uint32_t len, SessionPktType type);

void ClientTransProxyCloseChannel(int32_t channelId);

int32_t ClientTransProxyPackAndSendData(int32_t channelId, const void *data, uint32_t len,
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

int32_t TransProxyChannelAsyncSendMessage(int32_t channelId, const void *data, uint32_t len, uint16_t dataSeq);

int32_t TransProxyAsyncPackAndSendMessage(
    int32_t channelId, const void *data, uint32_t len, uint16_t dataSeq, SessionPktType pktType);
#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_PROXY_CHANNEL_H
