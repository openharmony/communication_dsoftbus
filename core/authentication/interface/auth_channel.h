/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef AUTH_CHANNEL_H
#define AUTH_CHANNEL_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    int32_t module;
    int32_t flag;
    int64_t seq;
    uint32_t len;
    const uint8_t *data;
} AuthChannelData;

typedef struct {
    void (*onDataReceived)(int32_t channelId, const AuthChannelData *data);
    void (*onDisconnected)(int32_t channelId);
} AuthChannelListener;
int32_t RegAuthChannelListener(int32_t module, const AuthChannelListener *listener);
void UnregAuthChannelListener(int32_t module);

/* NOTO: open successfully, return channelId. Otherwise, return -1. */
int32_t AuthOpenChannelWithAllIp(const char *localIp, const char *remoteIp, int32_t port);
int32_t AuthOpenChannel(const char *ip, int32_t port);
void AuthCloseChannel(int32_t channelId, int32_t moduleId);

int32_t AuthPostChannelData(int32_t channelId, const AuthChannelData *data);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_CHANNEL_H */
