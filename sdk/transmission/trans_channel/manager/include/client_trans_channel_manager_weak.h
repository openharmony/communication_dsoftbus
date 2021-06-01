/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef CLIENT_TRANS_CHANNEL_MANAGER_WEAK_H
#define CLIENT_TRANS_CHANNEL_MANAGER_WEAK_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t __attribute__ ((weak)) TransTdcManagerInit(void);

void __attribute__ ((weak)) TransTdcManagerDeinit(void);

int32_t __attribute__ ((weak)) TransCloseProxyChannel(int32_t channelId);

void __attribute__ ((weak)) TransTdcCloseChannel(int32_t channelId);

int32_t __attribute__ ((weak)) TransProxyChannelSendBytes(int32_t channelId, const void *data, uint32_t len);

int32_t __attribute__ ((weak)) TransTdcSendBytes(int32_t channelId, const char *data, uint32_t len);

int32_t __attribute__ ((weak)) TransProxyChannelSendMessage(int32_t channelId, const void *data, uint32_t len);

int32_t __attribute__ ((weak)) TransTdcSendMessage(int32_t channelId, const char *data, uint32_t len);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif // CLIENT_TRANS_CHANNEL_MANAGER_WEAK_H

