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

#ifndef TRANS_INNER_SESSION_H
#define TRANS_INNER_SESSION_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct {
    int32_t (*OnSessionOpened)(int32_t channelId, int32_t channelType, char *peerNetworkId, int32_t result);
    void (*OnSessionClosed)(int32_t channelId);
    void (*OnBytesReceived)(int32_t channelId, const void *data, uint32_t dataLen);
    void (*OnLinkDown)(const char *networkId);
    int32_t (*OnSetChannelInfoByReqId)(uint32_t reqId, int32_t channelId, int32_t channelType);
} ISessionListenerInner;
#ifdef __cplusplus
}
#endif // __cplusplus
#endif // TRANS_INNER_SESSION_H