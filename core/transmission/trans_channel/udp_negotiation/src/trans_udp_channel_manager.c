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
#include "regex.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "trans_channel_manager.h"
#include "trans_client_proxy.h"
#include "trans_log.h"
#include "trans_udp_negotiation.h"

#define MAX_WAIT_CONNECT_TIME 15

static SoftBusList *g_udpChannelMgr = NULL;

SoftBusList *GetUdpChannelMgrHead(void)
{
    return g_udpChannelMgr;
}

int32_t GetUdpChannelLock(void)
{
    if (g_udpChannelMgr == NULL) {
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_udpChannelMgr->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

void ReleaseUdpChannelLock(void)
{
    (void)SoftBusMutexUnlock(&g_udpChannelMgr->lock);
}

static void NotifyTimeOutUdpChannel(ListNode *udpChannelList)
{
    UdpChannelInfo *udpChannel = NULL;
    UdpChannelInfo *nextUdpChannel = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(udpChannel, nextUdpChannel, udpChannelList, UdpChannelInfo, node) {
        if (udpChannel->info.udpChannelOptType == TYPE_UDP_CHANNEL_OPEN) {
            TRANS_LOGW(TRANS_CTRL, "open udp channel time out, notify open failed.");
            (void)NotifyUdpChannelOpenFailed(&(udpChannel->info), SOFTBUS_TRANS_HANDSHAKE_TIMEOUT);
        } else if (udpChannel->info.udpChannelOptType == TYPE_UDP_CHANNEL_CLOSE) {
            TRANS_LOGW(TRANS_CTRL, "close udp channel time out, notify close.");
            (void)NotifyUdpChannelClosed(&(udpChannel->info), MESSAGE_TYPE_NOMAL);
        }
        ListDelete(&(udpChannel->node));
        if (udpChannel->info.fastTransData != NULL) {
            SoftBusFree((void *)udpChannel->info.fastTransData);
        }
        (void)memset_s(udpChannel->info.sessionKey, sizeof(udpChannel->info.sessionKey), 0,
            sizeof(udpChannel->info.sessionKey));
        SoftBusFree(udpChannel);
    }
}

static void TransUdpTimerProc(void)
{
    if (g_udpChannelMgr == NULL) {
        return;
    }
    if (SoftBusMutexLock(&g_udpChannelMgr->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return;
    }

    ListNode udpTmpChannelList;
    ListInit(&udpTmpChannelList);

    UdpChannelInfo *udpChannel = NULL;
    UdpChannelInfo *nextUdpChannel = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(udpChannel, nextUdpChannel, &g_udpChannelMgr->list, UdpChannelInfo, node) {
        if (udpChannel->status == UDP_CHANNEL_STATUS_NEGING) {
            udpChannel->timeOut++;
            if (udpChannel->timeOut < MAX_WAIT_CONNECT_TIME) {
                continue;
            }
            ReleaseUdpChannelId((int32_t)(udpChannel->info.myData.channelId));
            ListDelete(&(udpChannel->node));
            g_udpChannelMgr->cnt--;

            ListAdd(&udpTmpChannelList, &(udpChannel->node));
        }
    }
    (void)SoftBusMutexUnlock(&g_udpChannelMgr->lock);

    NotifyTimeOutUdpChannel(&udpTmpChannelList);
}

int32_t TransUdpChannelMgrInit(void)
{
    if (g_udpChannelMgr != NULL) {
        TRANS_LOGI(TRANS_INIT, "udp channel info manager has init.");
        return SOFTBUS_OK;
    }
    g_udpChannelMgr = CreateSoftBusList();
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_INIT, "create udp channel manager list failed.");
        return SOFTBUS_MALLOC_ERR;
    }

    int32_t ret = RegisterTimeoutCallback(SOFTBUS_UDP_CHANNEL_TIMER_FUN, TransUdpTimerProc);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
        TRANS_INIT, "register udp channel time out callback failed.");

    return SOFTBUS_OK;
}

void TransUdpChannelMgrDeinit(void)
{
    if (g_udpChannelMgr == NULL) {
        return;
    }
    if (SoftBusMutexLock(&g_udpChannelMgr->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "lock failed");
        return;
    }
    UdpChannelInfo *udpChannel = NULL;
    UdpChannelInfo *nextUdpChannel = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(udpChannel, nextUdpChannel, &g_udpChannelMgr->list, UdpChannelInfo, node) {
        ReleaseUdpChannelId((int32_t)(udpChannel->info.myData.channelId));
        ListDelete(&(udpChannel->node));
        if (udpChannel->info.fastTransData != NULL) {
            SoftBusFree((void *)udpChannel->info.fastTransData);
        }
        (void)memset_s(udpChannel->info.sessionKey, sizeof(udpChannel->info.sessionKey), 0,
            sizeof(udpChannel->info.sessionKey));
        SoftBusFree(udpChannel);
    }
    (void)SoftBusMutexUnlock(&g_udpChannelMgr->lock);
    DestroySoftBusList(g_udpChannelMgr);
    g_udpChannelMgr = NULL;
    return;
}

int32_t TransAddUdpChannel(UdpChannelInfo *channel)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_INIT, "udp channel manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }

    if (channel == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->info.myData.channelId == channel->info.myData.channelId) {
            TRANS_LOGE(TRANS_CTRL, "udp channel has exited. channelId=%{public}" PRId64,
                channel->info.myData.channelId);
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_TRANS_UDP_CHANNEL_ALREADY_EXIST;
        }
    }
    int64_t channelId = channel->info.myData.channelId;
    ListInit(&(channel->node));
    ListAdd(&(g_udpChannelMgr->list), &(channel->node));
    TRANS_LOGI(TRANS_CTRL, "add channelId=%{public}" PRId64, channelId);
    g_udpChannelMgr->cnt++;

    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGI(TRANS_CTRL, "add udp channel success. channelId=%{public}" PRId64, channelId);
    return SOFTBUS_OK;
}

int32_t TransDelUdpChannel(int32_t channelId)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_INIT, "udp channel manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannelInfo *udpChannelNode = NULL;
    UdpChannelInfo *udpChannelNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(udpChannelNode, udpChannelNext, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->info.myData.channelId == channelId) {
            ReleaseUdpChannelId((int32_t)(udpChannelNode->info.myData.channelId));
            ListDelete(&(udpChannelNode->node));
            TRANS_LOGI(TRANS_CTRL, "delete channelId=%{public}d", channelId);
            if (udpChannelNode->info.fastTransData != NULL) {
                SoftBusFree((void *)(udpChannelNode->info.fastTransData));
            }
            (void)memset_s(udpChannelNode->info.sessionKey, sizeof(udpChannelNode->info.sessionKey), 0,
                sizeof(udpChannelNode->info.sessionKey));
            SoftBusFree(udpChannelNode);
            g_udpChannelMgr->cnt--;
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_CTRL, "udp channel not found. channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND;
}

static void NotifyUdpChannelCloseInList(ListNode *udpChannelList)
{
    UdpChannelInfo *udpChannel = NULL;
    UdpChannelInfo *udpChannelNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(udpChannel, udpChannelNext, udpChannelList, UdpChannelInfo, node) {
        (void)NotifyUdpChannelClosed(&udpChannel->info, MESSAGE_TYPE_NOMAL);

        ListDelete(&(udpChannel->node));
        TRANS_LOGI(TRANS_CTRL, "channelId=%{public}" PRId64, udpChannel->info.myData.channelId);
        if (udpChannel->info.fastTransData != NULL) {
            SoftBusFree((void *)(udpChannel->info.fastTransData));
        }
        (void)memset_s(udpChannel->info.sessionKey, sizeof(udpChannel->info.sessionKey), 0,
            sizeof(udpChannel->info.sessionKey));
        SoftBusFree(udpChannel);
    }
}

void TransCloseUdpChannelByNetWorkId(const char* netWorkId)
{
    TRANS_LOGI(TRANS_CTRL, "enter.");
    if ((g_udpChannelMgr == NULL) || (netWorkId == NULL)) {
        return;
    }
    if (SoftBusMutexLock(&g_udpChannelMgr->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "TransCloseUdpChannelByAuId lock failed");
        return;
    }

    ListNode udpDeleteChannelList;
    ListInit(&udpDeleteChannelList);

    UdpChannelInfo *udpChannel = NULL;
    UdpChannelInfo *udpChannelNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(udpChannel, udpChannelNext, &g_udpChannelMgr->list, UdpChannelInfo, node) {
        if (strcmp(udpChannel->info.peerNetWorkId, netWorkId) == 0) {
            ReleaseUdpChannelId((int32_t)(udpChannel->info.myData.channelId));
            ListDelete(&(udpChannel->node));
            g_udpChannelMgr->cnt--;

            ListAdd(&udpDeleteChannelList, &(udpChannel->node));
        }
    }
    (void)SoftBusMutexUnlock(&g_udpChannelMgr->lock);

    NotifyUdpChannelCloseInList(&udpDeleteChannelList);
}

int32_t TransGetUdpChannelBySeq(int64_t seq, UdpChannelInfo *channel, bool isReply)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_INIT, "udp channel manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }

    if (channel == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->seq == seq && udpChannelNode->isReply == isReply) {
            if (memcpy_s(channel, sizeof(UdpChannelInfo), udpChannelNode, sizeof(UdpChannelInfo)) != EOK) {
                TRANS_LOGE(TRANS_CTRL, "memcpy_s UdpChannelInfo failed.");
                (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_CTRL, "udp channel not found. seq=%{public}" PRId64 "", seq);
    return SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND;
}

int32_t TransGetUdpChannelById(int32_t channelId, UdpChannelInfo *channel)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_CTRL, "udp channel manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }

    if (channel == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->info.myData.channelId == channelId) {
            if (memcpy_s(channel, sizeof(UdpChannelInfo), udpChannelNode, sizeof(UdpChannelInfo)) != EOK) {
                TRANS_LOGE(TRANS_CTRL, "memcpy_s UdpChannelInfo failed.");
                (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_CTRL, "udp channel not found. channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND;
}

int32_t TransUdpGetNameByChanId(int32_t channelId, char *pkgName, char *sessionName,
    uint16_t pkgNameLen, uint16_t sessionNameLen)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_INIT, "udp channel manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }
    if (pkgName == NULL || sessionName == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->info.myData.channelId == channelId) {
            if (strcpy_s(pkgName, pkgNameLen, udpChannelNode->info.myData.pkgName) != EOK ||
                strcpy_s(sessionName, sessionNameLen, udpChannelNode->info.myData.sessionName) != EOK) {
                TRANS_LOGE(TRANS_CTRL, "strcpy_s failed.");
                (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
                return SOFTBUS_STRCPY_ERR;
            }
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_CTRL, "udp channel not found. channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND;
}

int32_t TransSetUdpChannelStatus(int64_t seq, UdpChannelStatus status, bool isReply)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_INIT, "udp channel manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->seq == seq && udpChannelNode->isReply == isReply) {
            udpChannelNode->status = status;
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_CTRL, "udp channel not found. seq=%{public}" PRId64, seq);
    return SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND;
}

int32_t TransSetUdpChannelOptType(int32_t channelId, UdpChannelOptType type)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_INIT, "udp channel manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->info.myData.channelId == channelId) {
            udpChannelNode->info.udpChannelOptType = type;
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_CTRL, "udp channel not found. channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND;
}

void TransUpdateUdpChannelInfo(int64_t seq, const AppInfo *appInfo, bool isReply)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_INIT, "udp channel manager hasn't init.");
        return;
    }

    if (appInfo == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return;
    }

    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return;
    }

    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->seq == seq && udpChannelNode->isReply == isReply) {
            udpChannelNode->isReply = false;
            if (memcpy_s(&(udpChannelNode->info), sizeof(AppInfo), appInfo, sizeof(AppInfo)) != EOK) {
                TRANS_LOGE(TRANS_CTRL, "memcpy_s UdpChannelInfo failed.");
            }
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_CTRL, "udp channel not found. seq=%{public}" PRId64, seq);
}

void TransSetUdpChannelMsgType(uint32_t requestId)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_INIT, "udp channel manager hasn't init.");
        return;
    }

    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return;
    }

    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->requestId == requestId) {
            udpChannelNode->isReply = true;
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_CTRL, "udp channel not found. reqId=%{public}u", requestId);
    return;
}

int32_t TransGetUdpChannelByRequestId(uint32_t requestId, UdpChannelInfo *channel)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_INIT, "udp channel manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }

    if (channel == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->requestId == requestId) {
            if (memcpy_s(channel, sizeof(UdpChannelInfo), udpChannelNode, sizeof(UdpChannelInfo)) != EOK) {
                (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_CTRL, "udp channel not found. reqId=%{public}u", requestId);
    return SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND;
}

UdpChannelInfo *TransGetChannelObj(int32_t channelId)
{
    if (g_udpChannelMgr == NULL) {
        return NULL;
    }
    UdpChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (item->info.myData.channelId == channelId) {
            return item;
        }
    }
    TRANS_LOGE(TRANS_CTRL, "not found: channelId=%{public}d", channelId);
    return NULL;
}

int32_t TransGetUdpAppInfoByChannelId(int32_t channelId, AppInfo *appInfo)
{
    if (appInfo == NULL) {
        TRANS_LOGE(TRANS_INIT, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_INIT, "udp channel manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->info.myData.channelId == channelId) {
            memcpy_s(appInfo, sizeof(AppInfo), &udpChannelNode->info, sizeof(AppInfo));
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_CTRL, "udp channel not found. channelId=%{public}d", channelId);
    return SOFTBUS_NOT_FIND;
}

int32_t TransUdpGetChannelIdByAddr(AppInfo *appInfo)
{
    if (appInfo == NULL) {
        TRANS_LOGE(TRANS_INIT, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_INIT, "udp channel manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->info.peerData.channelId == appInfo->peerData.channelId) {
            if (strcmp(udpChannelNode->info.peerData.addr, appInfo->peerData.addr) == EOK) {
                appInfo->myData.channelId = udpChannelNode->info.myData.channelId;
                (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
                return SOFTBUS_OK;
            }
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_CTRL, "not found peerChannelId and addr");
    return SOFTBUS_NOT_FIND;
}

static int32_t ModifyUdpChannelTos(uint8_t tos)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_CTRL, "udp channel manager not initialized.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->info.businessType == BUSINESS_TYPE_FILE && udpChannelNode->info.isClient &&
            udpChannelNode->tos != tos) {
            int32_t ret = ClientIpcOnTransLimitChange(udpChannelNode->info.myData.pkgName,
                udpChannelNode->info.myData.pid, udpChannelNode->info.myData.channelId, tos);
            if (ret != SOFTBUS_OK) {
                TRANS_LOGE(TRANS_CTRL, "ClientIpcOnTransLimitChange send request failed");
                (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
                return ret;
            }
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    return SOFTBUS_OK;
}

int32_t UdpChannelFileTransLimit(const ChannelInfo *channel, uint8_t tos)
{
    if (channel == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    TRANS_LOGD(TRANS_CTRL, "new session opened, channelId=%{public}d, channelType=%{public}d, businessType=%{public}d",
        channel->channelId, channel->channelType, channel->businessType);
    if (channel->channelType == CHANNEL_TYPE_PROXY) {
        TRANS_LOGI(TRANS_CTRL, "channel type is proxy, no need to limit file trans.");
        return SOFTBUS_OK;
    }
    if (channel->businessType == BUSINESS_TYPE_MESSAGE) {
        TRANS_LOGI(TRANS_CTRL, "business type is message, no need to limit file trans.");
        return SOFTBUS_OK;
    }
    int32_t ret = ModifyUdpChannelTos(tos);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "ModifyUdpChannelTos failed, ret=%{public}d", ret);
    }
    return SOFTBUS_OK;
}

int32_t UdpChannelFileTransRecoveryLimit(uint8_t tos)
{
    int32_t ret = ModifyUdpChannelTos(tos);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "ModifyUdpChannelTos failed, ret=%{public}d", ret);
    }
    return SOFTBUS_OK;
}

bool IsUdpRecoveryTransLimit(void)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return false;
    }
    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return false;
    }
    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->info.businessType == BUSINESS_TYPE_STREAM) {
            TRANS_LOGD(TRANS_CTRL, "udp channel exists stream business, no need to recovery limit.");
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return false;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    return true;
}

int32_t TransUdpGetIpAndConnectTypeById(int32_t channelId, char *localIp, char *remoteIp, uint32_t maxIpLen,
    int32_t *connectType)
{
    if (localIp == NULL || remoteIp == NULL || maxIpLen < IP_LEN || connectType == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_CTRL, "udp channel manager not initialized.");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->info.myData.channelId == channelId) {
            if (strcpy_s(localIp, maxIpLen, udpChannelNode->info.myData.addr) != EOK) {
                TRANS_LOGE(TRANS_CTRL, "failed to strcpy localIp, channelId=%{public}d", channelId);
                (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
                return SOFTBUS_STRCPY_ERR;
            }
            if (strcpy_s(remoteIp, maxIpLen, udpChannelNode->info.peerData.addr) != EOK) {
                TRANS_LOGE(TRANS_CTRL, "failed to strcpy remoteIp, channelId=%{public}d", channelId);
                (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
                return SOFTBUS_STRCPY_ERR;
            }
            *connectType = udpChannelNode->info.connectType;
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_CTRL, "not found locapIp and connectType by channelId=%{public}d", channelId);
    return SOFTBUS_NOT_FIND;
}

int32_t TransUdpUpdateReplyCnt(int32_t channelId)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_CTRL, "udp channel manager not initialized.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->info.myData.channelId == channelId) {
            udpChannelNode->info.waitOpenReplyCnt = CHANNEL_OPEN_SUCCESS;
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_CTRL, "not found udpChannelNode by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

int32_t TransUdpResetReplyCnt(int32_t channelId)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_CTRL, "udp channel manager not initialized.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->info.myData.channelId == channelId) {
            udpChannelNode->info.waitOpenReplyCnt = 0;
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_CTRL, "not found udpChannelNode by channelId=%{public}d", channelId);
    return SOFTBUS_NOT_FIND;
}

int32_t TransUdpUpdateUdpPort(int32_t channelId, int32_t udpPort)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_CTRL, "udp channel manager not initialized.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->info.myData.channelId == channelId) {
            udpChannelNode->info.myData.port = udpPort;
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_CTRL, "not found udpChannelNode by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

static int32_t TransCheckUdpChannelOpenStatus(int32_t channelId, int32_t *curCount)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_CTRL, "udp channel manager not initialized.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->info.myData.channelId == channelId) {
            if (udpChannelNode->info.waitOpenReplyCnt != CHANNEL_OPEN_SUCCESS) {
                udpChannelNode->info.waitOpenReplyCnt++;
            }
            *curCount = udpChannelNode->info.waitOpenReplyCnt;
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_CTRL, "not found udp channel info by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

void TransAsyncUdpChannelTask(int32_t channelId)
{
    int32_t curCount = 0;
    int32_t ret = TransCheckUdpChannelOpenStatus(channelId, &curCount);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL,
            "check udp channel open statue failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return;
    }
    if (curCount == CHANNEL_OPEN_SUCCESS) {
        TRANS_LOGI(TRANS_CTRL, "open udp channel success, channelId=%{public}d", channelId);
        return;
    }
    UdpChannelInfo channel;
    (void)memset_s(&channel, sizeof(UdpChannelInfo), 0, sizeof(UdpChannelInfo));
    ret = TransGetUdpChannelById(channelId, &channel);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get udp channel failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return;
    }
    if (curCount >= LOOPER_REPLY_CNT_MAX) {
        char *errDesc = (char *)"open udp channel timeout";
        TRANS_LOGE(TRANS_CTRL, "Open udp channel timeout, channelId=%{public}d", channelId);
        if (SendReplyErrInfo(
            SOFTBUS_TRANS_OPEN_CHANNEL_NEGTIATE_TIMEOUT, errDesc, channel.authHandle, channel.seq) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "send reply error info failed.");
        }
        (void)NotifyUdpChannelOpenFailed(&channel.info, SOFTBUS_TRANS_OPEN_CHANNEL_NEGTIATE_TIMEOUT);
        (void)TransDelUdpChannel(channelId);
    }
    TRANS_LOGI(TRANS_CTRL, "open channelId=%{public}d not finished, generate new task and waiting", channelId);
    uint32_t delayTime = (curCount <= LOOPER_SEPARATE_CNT) ? FAST_INTERVAL_MILLISECOND : SLOW_INTERVAL_MILLISECOND;
    TransCheckChannelOpenToLooperDelay(channelId, CHANNEL_TYPE_UDP, delayTime);
}

int32_t TransSetTos(int32_t channelId, uint8_t tos)
{
    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_CTRL, "udp channel manager not initialized.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (udpChannelNode->info.myData.channelId == channelId) {
            udpChannelNode->tos = tos;
            (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    TRANS_LOGE(TRANS_CTRL, "not found udpChannelNode by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

int32_t TransUdpGetPrivilegeCloseList(ListNode *privilegeCloseList, uint64_t tokenId, int32_t pid)
{
    if (privilegeCloseList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "privilegeCloseList is null");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_udpChannelMgr == NULL) {
        TRANS_LOGE(TRANS_CTRL, "udp channel manager not initialized.");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&(g_udpChannelMgr->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    UdpChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_udpChannelMgr->list), UdpChannelInfo, node) {
        if (item->info.callingTokenId == tokenId && item->info.myData.pid == pid) {
            (void)PrivilegeCloseListAddItem(privilegeCloseList, item->info.myData.pid, item->info.myData.pkgName);
        }
    }
    (void)SoftBusMutexUnlock(&(g_udpChannelMgr->lock));
    return SOFTBUS_OK;
}

bool CompareSessionName(const char *dstSessionName, const char *srcSessionName)
{
    if (dstSessionName == NULL || srcSessionName == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid sessionName");
        return false;
    }
    regex_t regComp;
    if (regcomp(&regComp, dstSessionName, REG_EXTENDED | REG_NOSUB) != REG_OK) {
        TRANS_LOGE(TRANS_CTRL, "regcomp failed.");
        return false;
    }
    bool compare = regexec(&regComp, srcSessionName, 0, NULL, 0) == REG_OK;
    regfree(&regComp);
    return compare;
}
