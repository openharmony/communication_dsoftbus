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

#ifndef SOFTBUS_PROXYCHANNEL_CALLBACK_H
#define SOFTBUS_PROXYCHANNEL_CALLBACK_H

#include <stdint.h>

#include "trans_channel_callback.h"
#include "softbus_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t TransProxySetCallBack(const IServerChannelCallBack *cb);

int32_t TransProxyOnChannelOpened(const char *pkgName, int32_t pid, const char *sessionName,
    const ChannelInfo *channel);

int32_t TransProxyOnChannelClosed(const char *pkgName, int32_t pid, int32_t channelId);

int32_t TransProxyOnChannelBind(const char *pkgName, int32_t pid, int32_t channelId);

int32_t TransProxyOnChannelOpenFailed(const char *pkgName, int32_t pid, int32_t channelId, int32_t errCode);

int32_t TransProxyOnMsgReceived(const char *pkgName, int32_t pid, int32_t channelId,
    TransReceiveData *receiveData);

int32_t TransProxyGetPkgName(const char *sessionName, char *pkgName, uint16_t len);

int32_t TransProxyGetUidAndPidBySessionName(const char *sessionName, int32_t *uid, int32_t *pid);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif
