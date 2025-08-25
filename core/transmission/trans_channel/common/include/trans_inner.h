/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef TRANS_INNER_H
#define TRANS_INNER_H

#include <stdint.h>
#include "trans_inner_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t GetSessionInfo(int32_t channelId, int32_t *fd, int32_t *channelType, char *sessionKey, int32_t keyLen);
int32_t InnerListInit(void);
int32_t InnerAddSession(InnerSessionInfo *innerInfo);
int32_t ProxyDataRecvHandler(int32_t channelId, const char *data, uint32_t len);
int32_t ServerSideSendAck(int32_t sessionId, int32_t result);
int32_t TransSendData(int32_t channelId, const void *data, uint32_t len);
int32_t DirectChannelCreateListener(int32_t fd);
void CloseSessionInner(int32_t channelId);
int32_t DeleteChannel(int32_t channelId);
void ClientTransInnerDataBufDeinit(void);
int32_t TransInnerAddDataBufNode(int32_t channelId, int32_t fd, int32_t channelType);
void InnerListDeinit(void);
void TransCloseInnerSessionByNetworkId(const char *networkId);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif