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
#include "lnn_lane_interface.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

#define MIN(a, b) ((a) < (b) ? (a) : (b))

typedef struct {
    ListNode node;
    AppInfo appInfo;
    int32_t authId;
    ConnectOption connOpt;
    bool isClient;
    bool accountInfo;
} AuthChannelInfo;

SoftBusList *GetAuthChannelListHead(void);
int32_t GetAuthChannelLock(void);
void ReleaseAuthChannelLock(void);
int32_t TransAuthInit(IServerChannelCallBack *cb);
void TransAuthDeinit(void);
int32_t TransAuthGetNameByChanId(int32_t chanId, char *pkgName, char *sessionName,
    uint16_t pkgLen, uint16_t sessionLen);
int32_t TransOpenAuthMsgChannelWithPara(const char *sessionName, const LaneConnInfo *connInfo, int32_t *channelId,
    bool accountInfo);
int32_t TransOpenAuthMsgChannel(const char *sessionName, const ConnectOption *connOpt, int32_t *channelId,
    const char *reqId);
int32_t TransNotifyAuthDataSuccess(int32_t channelId, const ConnectOption *connOpt);
int32_t TransCloseAuthChannel(int32_t channelId);
int32_t TransSendAuthMsg(int32_t channelId, const char *msg, int32_t len);
int32_t TransAuthGetAppInfoByChanId(int32_t channelId, AppInfo *appInfo);
int32_t TransAuthGetConnOptionByChanId(int32_t channelId, ConnectOption *connOpt);
int32_t TransAuthGetConnIdByChanId(int32_t channelId, int32_t *connId);
int32_t GetAppInfo(const char *sessionName, int32_t channelId, AppInfo *appInfo, bool isClient);
int32_t NotifyOpenAuthChannelFailed(const char *pkgName, int32_t pid, int32_t channelId, int32_t errCode);
int32_t CheckIsWifiAuthChannel(ConnectOption *connInfo);
int32_t TransAuthGetPeerUdidByChanId(int32_t channelId, char *peerUdid, uint32_t len);
int32_t TransDealAuthChannelOpenResult(int32_t channelId, int32_t openResult);
void TransAsyncAuthChannelTask(int32_t channelId);
void TransAuthDeathCallback(const char *pkgName, int32_t pid);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif