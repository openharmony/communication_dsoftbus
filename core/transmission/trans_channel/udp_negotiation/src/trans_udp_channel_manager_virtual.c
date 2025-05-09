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

#include "trans_udp_channel_manager.h"

#include "softbus_error_code.h"

int32_t TransGetUdpAppInfoByChannelId(int32_t channelId, AppInfo *appInfo)
{
    (void)channelId;
    (void)appInfo;
    return SOFTBUS_TRANS_UDP_PREPARE_APP_INFO_FAILED;
}

bool IsUdpRecoveryTransLimit(void)
{
    return false;
}

int32_t UdpChannelFileTransLimit(const ChannelInfo *channel, uint8_t tos)
{
    (void)channel;
    (void)tos;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t UdpChannelFileTransRecoveryLimit(uint8_t tos)
{
    (void)tos;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransDelUdpChannel(int32_t channelId)
{
    (void)channelId;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

SoftBusList *GetUdpChannelMgrHead(void)
{
    return NULL;
}

int32_t GetUdpChannelLock(void)
{
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

void ReleaseUdpChannelLock(void)
{
}

int32_t TransGetUdpChannelById(int32_t channelId, UdpChannelInfo *channel)
{
    (void)channelId;
    (void)channel;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

void TransAsyncUdpChannelTask(int32_t channelId)
{
    (void)channelId;
}

int32_t TransSetTos(int32_t channelId, uint8_t tos)
{
    (void)channelId;
    (void)tos;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransUdpGetIpAndConnectTypeById(int32_t channelId, char *localIp, char *remoteIp, uint32_t maxIpLen,
    int32_t *connectType)
{
    (void)channelId;
    (void)localIp;
    (void)remoteIp;
    (void)maxIpLen;
    (void)connectType;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t TransUdpGetPrivilegeCloseList(ListNode *privilegeCloseList, uint64_t tokenId, int32_t pid)
{
    (void)privilegeCloseList;
    (void)tokenId;
    (void)pid;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}