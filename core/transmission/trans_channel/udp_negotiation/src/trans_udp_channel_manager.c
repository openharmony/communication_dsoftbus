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

#include "common_list.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"
#include "trans_udp_negotiation.h"

#define MAX_WAIT_CONNECT_TIME 5

static SoftBusList *g_udpChannelMgr = NULL;

static void TransUdpTimerProc(void)
{
    if (g_udpChannelMgr == NULL) {
        return;
    }
    if (pthread_mutex_lock(&g_udpChannelMgr->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    UdpChannelInfo *udpChannel = NULL;
    UdpChannelInfo *nextUdpChannel = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(udpChannel, nextUdpChannel, &g_udpChannelMgr->list, UdpChannelInfo, node) {
        if (udpChannel->status == UDP_CHANNEL_STATUS_NEGING) {
            udpChannel->timeOut++;
            if (udpChannel->timeOut < MAX_WAIT_CONNECT_TIME) {
                continue;
            }
            if (udpChannel->info.udpChannelOptType == TYPE_UDP_CHANNEL_OPEN) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "open udp channel time out, notify open failed.");
                (void)NotifyUdpChannelOpenFailed(&(udpChannel->info));
            } else if (udpChannel->info.udpChannelOptType == TYPE_UDP_CHANNEL_CLOSE) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "close udp channel time out, notify close.");
                (void)NotifyUdpChannelClosed(&(udpChannel->info));
            }
            ReleaseUdpChannelId((int32_t)(udpChannel->info.myData.channelId));
            ListDelete(&(udpChannel->node));
            SoftBusFree(udpChannel);
            g_udpChannelMgr->cnt--;
        }
    }
    (void)pthread_mutex_unlock(&g_udpChannelMgr->lock);
}

int32_t TransUdpChannelMgrInit(void)
{
    if (g_udpChannelMgr != NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "udp channel info manager has initialized.");
        return SOFTBUS_OK;
    }
    g_udpChannelMgr = CreateSoftBusList();
    if (g_udpChannelMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create udp channel manager list failed.");
        return SOFTBUS_MALLOC_ERR;
    }
    if (RegisterTimeoutCallback(SOFTBUS_UDP_CHANNEL_TIMER_FUN, TransUdpTimerProc) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "register udp channel time out callback failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void TransUdpChannelMgrDeinit(void)
{
    if (g_udpChannelMgr == NULL) {
        return;
    }
    if (pthread_mutex_lock(&g_udpChannelMgr->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    UdpChannelInfo *udpChannel = NULL;
    UdpChannelInfo *nextUdpChannel = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(udpChannel, nextUdpChannel, &g_udpChannelMgr->list, UdpChannelInfo, node) {
        ReleaseUdpChannelId((int32_t)(udpChannel->info.myData.channelId));
        ListDelete(&(udpChannel->node));
        SoftBusFree(udpChannel);
    }
    (void)pthread_mutex_unlock(&g_udpChannelMgr->lock);
    DestroySoftBusList(g_udpChannelMgr);
    g_udpChannelMgr = NULL;
    return;
}

int32_t TransAddUdpChannel(UdpChannelInfo *channel)
{
    if (g_udpChannelMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel manager hasn't initialized.");
        return SOFTBUS_ERR;
    }

    if (channel == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    if (pthread_mutex_lock(&(g_udpChannelMgr->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->info.myData.channelId == channel->info.myData.channelId) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "udp channel has exited.[channelId = %lld]",
                channel->info.myData.channelId);
            (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_ERR;
        }
    }
    ListInit(&(channel->node));
    ListAdd(&(g_udpChannelMgr->list), &(channel->node));
    g_udpChannelMgr->cnt++;

    (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "add udp channel success.[channelId = %lld].",
        channel->info.myData.channelId);
    return SOFTBUS_OK;
}

int32_t TransDelUdpChannel(int32_t channelId)
{
    if (g_udpChannelMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel manager hasn't initialized.");
        return SOFTBUS_ERR;
    }
    if (pthread_mutex_lock(&(g_udpChannelMgr->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->info.myData.channelId == channelId) {
            ReleaseUdpChannelId((int32_t)(udpChannelNode->info.myData.channelId));
            ListDelete(&(udpChannelNode->node));
            SoftBusFree(udpChannelNode);
            g_udpChannelMgr->cnt--;
            (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel not found.[channelId = %d]", channelId);
    return SOFTBUS_ERR;
}

int32_t TransGetUdpChannelBySeq(int64_t seq, UdpChannelInfo *channel)
{
    if (g_udpChannelMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel manager hasn't initialized.");
        return SOFTBUS_ERR;
    }

    if (channel == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    if (pthread_mutex_lock(&(g_udpChannelMgr->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->seq == seq) {
            if (memcpy_s(channel, sizeof(UdpChannelInfo), udpChannelNode, sizeof(UdpChannelInfo)) != EOK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy_s failed.");
                (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
                return SOFTBUS_MEM_ERR;
            }
            (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel not found.[seq = %lld]", seq);
    return SOFTBUS_ERR;
}

int32_t TransGetUdpChannelById(int32_t channelId, UdpChannelInfo *channel)
{
    if (g_udpChannelMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel manager hasn't initialized.");
        return SOFTBUS_ERR;
    }

    if (channel == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    if (pthread_mutex_lock(&(g_udpChannelMgr->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->info.myData.channelId == channelId) {
            if (memcpy_s(channel, sizeof(UdpChannelInfo), udpChannelNode, sizeof(UdpChannelInfo)) != EOK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy_s failed.");
                (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
                return SOFTBUS_MEM_ERR;
            }
            (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel not found.[channelId = %d]", channelId);
    return SOFTBUS_ERR;
}

int32_t TransUdpGetNameByChanId(int32_t channelId, char *pkgName, char *sessionName,
    uint16_t pkgNameLen, uint16_t sessionNameLen)
{
    if (g_udpChannelMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel manager hasn't initialized.");
        return SOFTBUS_ERR;
    }
    if (pkgName == NULL || sessionName == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&(g_udpChannelMgr->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->info.myData.channelId == channelId) {
            if (strcpy_s(pkgName, pkgNameLen, udpChannelNode->info.myData.pkgName) != EOK ||
                strcpy_s(sessionName, sessionNameLen, udpChannelNode->info.myData.sessionName) != EOK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "strcpy_s failed.");
                (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
                return SOFTBUS_MEM_ERR;
            }
            (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel not found.[channelId = %d]", channelId);
    return SOFTBUS_ERR;
}

int32_t TransSetUdpChannelStatus(int64_t seq, UdpChannelStatus status)
{
    if (g_udpChannelMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel manager hasn't initialized.");
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&(g_udpChannelMgr->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->seq == seq) {
            udpChannelNode->status = status;
            (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel not found.[seq = %lld]", seq);
    return SOFTBUS_ERR;
}

int32_t TransSetUdpChannelOptType(int32_t channelId, UdpChannelOptType type)
{
    if (g_udpChannelMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel manager hasn't initialized.");
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&(g_udpChannelMgr->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->info.myData.channelId == channelId) {
            udpChannelNode->info.udpChannelOptType = type;
            (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel not found.[channelId = %d]", channelId);
    return SOFTBUS_ERR;
}

void TransUpdateUdpChannelInfo(int64_t seq, const AppInfo *appInfo)
{
    if (g_udpChannelMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel manager hasn't initialized.");
        return;
    }

    if (appInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param.");
        return;
    }

    if (pthread_mutex_lock(&(g_udpChannelMgr->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }

    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->seq == seq) {
            if (memcpy_s(&(udpChannelNode->info), sizeof(AppInfo), appInfo, sizeof(AppInfo)) != EOK) {
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy_s failed.");
            }
            (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
            return;
        }
    }
    (void)pthread_mutex_unlock(&(g_udpChannelMgr->lock));
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "udp channel not found.[seq = %lld]", seq);
}
