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

#ifndef TRANS_UDP_CHANNEL_MANAGER_H
#define TRANS_UDP_CHANNEL_MANAGER_H

#include "softbus_app_info.h"
#include "softbus_common.h"
#include "trans_uk_manager.h"
#include "trans_udp_channel_manager_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UDP_CHANNEL_MULTIPATH_OFFSET 1
#define CHANNEL_ISMULTINEG_OFFSET 2
#define TRANS_UDP_CHANNEL_CAPBILITY 6 /* bit1 & bit2 */

SoftBusList *GetUdpChannelMgrHead(void);

int32_t TransUdpChannelMgrInit(void);
void TransUdpChannelMgrDeinit(void);

int32_t GetUdpChannelLock(void);
void ReleaseUdpChannelLock(void);

int32_t TransAddUdpChannel(UdpChannelInfo *channel);
int32_t TransDelUdpChannel(int32_t channelId);
void TransCloseUdpChannelByNetWorkId(const char* netWorkId);

int32_t TransGetUdpChannelBySeq(int64_t seq, UdpChannelInfo *channel, bool isReply);
int32_t TransGetUdpChannelById(int32_t channelId, UdpChannelInfo *channel);
int32_t TransGetUdpChannelByPeerId(int32_t channelId, UdpChannelInfo *channel);
int32_t TransGetUdpChannelByRequestId(uint32_t requestId, UdpChannelInfo *channel);

int32_t TransSetUdpChannelStatus(int64_t seq, UdpChannelStatus status, bool isReply);
int32_t TransSetUdpChannelOptType(int32_t channelId, UdpChannelOptType type);

int32_t TransUdpGetNameByChanId(int32_t channelId, char *pkgName, char *sessionName,
    uint16_t pkgNameLen, uint16_t sessionNameLen);

void TransUpdateUdpChannelInfo(int64_t seq, const AppInfo *appInfo, bool isReply);

UdpChannelInfo *TransGetChannelObj(int32_t channelId);

int32_t TransGetUdpAppInfoByChannelId(int32_t channelId, AppInfo *appInfo);
int32_t TransUdpGetChannelIdByAddr(AppInfo *appInfo);

int32_t UdpChannelFileTransLimit(const ChannelInfo *channel, uint8_t tos);

int32_t UdpChannelFileTransRecoveryLimit(uint8_t tos);

bool IsUdpRecoveryTransLimit(void);

int32_t TransUdpGetIpAndConnectTypeById(int32_t channelId, char *localIp, char *remoteIp, uint32_t maxIpLen,
    int32_t *connectType);

int32_t TransUdpUpdateReplyCnt(int32_t channelId);

int32_t TransUdpResetReplyCnt(int32_t channelId);

int32_t TransUdpUpdateUdpPort(int32_t channelId, int32_t udpPort);

void TransAsyncUdpChannelTask(int32_t channelId);

int32_t TransSetTos(int32_t channelId, uint8_t tos, pid_t callingPid);

int32_t TransUdpGetPrivilegeCloseList(ListNode *privilegeCloseList, uint64_t tokenId, int32_t pid);

bool CompareSessionName(const char *dstSessionName, const char *srcSessionName);

void TransSetUdpChannelMsgType(uint32_t requestId);

int32_t TransUdpUpdateAccessInfo(int32_t channelId, const AccessInfo *accessInfo);

int32_t TransUdpGetWakeUpInfo(int32_t channelId, char *uuid, int32_t uuidLen, bool *needFastWakeUp);

int32_t TransUdpSetWakeUpInfo(int32_t channelId, bool needFastWakeUp);
#ifdef __cplusplus
}
#endif

#endif // !TRANS_UDP_CHANNEL_MANAGER_H