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

#ifndef SOFTBUS_PROXYCHANNEL_MESSAGE_H
#define SOFTBUS_PROXYCHANNEL_MESSAGE_H
#include "softbus_app_info.h"
#include "softbus_conn_interface.h"
#include "trans_proxy_process_data.h"
#include "trans_uk_manager.h"
#include "softbus_proxychannel_message_struct.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t TransProxyUnPackHandshakeErrMsg(const char *msg, int32_t *errCode, int32_t len);
int32_t TransProxyUnPackRestErrMsg(const char *msg, int32_t *errCode, int32_t len);
int32_t TransProxyUnpackHandshakeAckMsg(const char *msg, ProxyChannelInfo *chanInfo,
    int32_t len, uint16_t *fastDataSize);
char* TransProxyPackHandshakeAckMsg(ProxyChannelInfo *chan);
char* TransProxyPackHandshakeErrMsg(int32_t errCode);
int32_t TransProxyParseMessage(char *data, int32_t len, ProxyMessage *msg, AuthHandle *auth);
int32_t TransProxyPackMessage(ProxyMessageHead *msg, AuthHandle authHandle, ProxyDataInfo *dataInfo);
char* TransProxyPackHandshakeMsg(ProxyChannelInfo *info);
int32_t TransProxyUnpackHandshakeMsg(const char *msg, ProxyChannelInfo *chan, int32_t len);
char* TransProxyPackIdentity(const char *identity);
int32_t TransProxyUnpackIdentity(const char *msg, char *identity, uint32_t identitySize, int32_t len);
char *TransProxyPackFastData(const AppInfo *appInfo, uint32_t *outLen);
int32_t PackPlaintextMessage(ProxyMessageHead *msg, ProxyDataInfo *dataInfo);
int32_t GetBrMacFromConnInfo(uint32_t connId, char *peerBrMac, uint32_t len);
int32_t TransPagingPackMessage(PagingProxyMessage *msg, ProxyDataInfo *dataInfo,
    ProxyChannelInfo *chan, bool needHash);
int32_t TransParseMessageHeadType(char *data, int32_t len, ProxyMessage *msg);
char *TransPagingPackHandshakeAckMsg(ProxyChannelInfo *chan);
void TransPagingProcessHandshakeMsg(const ProxyMessage *msg, uint8_t *accountHash, uint8_t *udidHash);
int32_t TransPagingParseMessage(char *data, int32_t len, ProxyMessage *msg);
void TransWaitListenResult(uint32_t businessFlag, int32_t reason);
char *TransPagingPackHandshakeErrMsg(int32_t errCode, int32_t channelId);
char *TransProxyPagingPackChannelId(int16_t channelId);

int32_t TransProxyParseD2DData(const char *data, int32_t len);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
