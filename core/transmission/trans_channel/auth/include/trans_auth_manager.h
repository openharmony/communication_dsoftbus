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

#ifndef TRANS_AUTH_MANAGER_H
#define TRANS_AUTH_MANAGER_H

#include "softbus_conn_interface.h"
#include "trans_channel_callback.h"
#include "softbus_app_info.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

#define MIN(a, b) ((a) < (b) ? (a) : (b))

int32_t TransAuthInit(IServerChannelCallBack *cb);
void TransAuthDeinit(void);
int32_t TransAuthGetNameByChanId(int32_t chanId, char *pkgName, char *sessionName,
    uint16_t pkgLen, uint16_t sessionLen);
int32_t TransOpenAuthMsgChannel(const char *sessionName, const ConnectOption *connOpt, int32_t *channelId,
    const char *reqId);
int32_t TransNotifyAuthDataSuccess(int32_t channelId, const ConnectOption *connOpt);
int32_t TransCloseAuthChannel(int32_t channelId);
int32_t TransSendAuthMsg(int32_t channelId, const char *msg, int32_t len);
int32_t TransAuthGetAppInfoByChanId(int32_t channelId, AppInfo *appInfo);
int32_t TransAuthGetConnOptionByChanId(int32_t channelId, ConnectOption *connOpt);
int32_t TransAuthGetConnIdByChanId(int32_t channelId, int32_t *connId);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif