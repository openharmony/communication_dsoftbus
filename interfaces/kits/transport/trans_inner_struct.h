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

#ifndef TRANS_INNER_STRUCT_H
#define TRANS_INNER_STRUCT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SESSION_KEY_LENGTH
#define SESSION_KEY_LENGTH 32
#endif

typedef struct {
    int32_t (*func)(int32_t sessionId, const void *data, uint32_t dataLen);
} SessionInnerCallback;

typedef struct {
    bool supportTlv;
    char sessionKey[SESSION_KEY_LENGTH];
    char peerNetworkId[NETWORK_ID_BUF_LEN];
    int32_t fd;
    int32_t channelId;
    int32_t channelType;
    SessionInnerCallback *listener;
} InnerSessionInfo;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif