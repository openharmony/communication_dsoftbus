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

#include "trans_pending_pkt.h"

#include <sys/time.h>
#include <unistd.h>

#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

#define TIME_OUT 2
#define USECTONSEC 1000

static SoftBusList *g_pendingList[PENDING_TYPE_BUTT] = {NULL, NULL};

int32_t PendingInit(int type)
{
    if (type < PENDING_TYPE_PROXY || type >= PENDING_TYPE_BUTT) {
        return SOFTBUS_ERR;
    }

    g_pendingList[type] = CreateSoftBusList();
    if (g_pendingList[type] == NULL) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void PendingDeinit(int type)
{
    if (type < PENDING_TYPE_PROXY || type >= PENDING_TYPE_BUTT) {
        return;
    }

    if (g_pendingList[type] != NULL) {
        DestroySoftBusList(g_pendingList[type]);
        g_pendingList[type] = NULL;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "PendigPackManagerDeinit init ok");
}

int32_t ProcPendingPacket(int32_t channelId, int32_t seqNum, int type)
{
    if (type < PENDING_TYPE_PROXY || type >= PENDING_TYPE_BUTT) {
        return SOFTBUS_ERR;
    }

    PendingPktInfo *item;
    SoftBusList *pendingList = g_pendingList[type];
    if (pendingList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pending[%d] list not inited.", type);
        return SOFTBUS_ERR;
    }

    pthread_mutex_lock(&pendingList->lock);
    LIST_FOR_EACH_ENTRY(item, &pendingList->list, PendingPktInfo, node) {
        if (item->seq == seqNum && item->channelId == channelId) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "PendingPacket already Created");
            pthread_mutex_unlock(&pendingList->lock);
            return SOFTBUS_ERR;
        }
    }
    item = (PendingPktInfo *)SoftBusMalloc(sizeof(PendingPktInfo));
    if (item == NULL) {
        pthread_mutex_unlock(&pendingList->lock);
        return SOFTBUS_MALLOC_ERR;
    }

    pthread_mutex_init(&item->lock, NULL);
    pthread_cond_init(&item->cond, NULL);
    item->channelId = channelId;
    item->seq = seqNum;
    item->finded = false;

    ListAdd(&pendingList->list, &item->node);
    pendingList->cnt++;
    pthread_mutex_unlock(&pendingList->lock);

    struct timespec outtime;
    struct timeval now;
    gettimeofday(&now, NULL);
    outtime.tv_sec = now.tv_sec + TIME_OUT;
    outtime.tv_nsec = now.tv_usec * USECTONSEC;

    pthread_mutex_lock(&item->lock);
    pthread_cond_timedwait(&item->cond, &item->lock, &outtime);

    int32_t ret = SOFTBUS_OK;
    if (item->finded != true) {
        ret = SOFTBUS_TIMOUT;
    }
    pthread_mutex_unlock(&item->lock);

    pthread_mutex_lock(&pendingList->lock);
    ListDelete(&item->node);
    pthread_mutex_destroy(&item->lock);
    pthread_cond_destroy(&item->cond);
    SoftBusFree(item);
    pendingList->cnt--;
    pthread_mutex_unlock(&pendingList->lock);

    return ret;
}

int32_t SetPendingPacket(int32_t channelId, int32_t seqNum, int type)
{
    if (type < PENDING_TYPE_PROXY || type >= PENDING_TYPE_BUTT) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "type[%d] illegal.", type);
        return SOFTBUS_ERR;
    }

    SoftBusList *pendingList = g_pendingList[type];
    if (pendingList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "pendind list not exist");
        return SOFTBUS_ERR;
    }

    PendingPktInfo *item = NULL;
    pthread_mutex_lock(&pendingList->lock);
    LIST_FOR_EACH_ENTRY(item, &pendingList->list, PendingPktInfo, node) {
        if (item->seq == seqNum && item->channelId == channelId) {
            item->finded = true;
            pthread_cond_signal(&item->cond);
            pthread_mutex_unlock(&pendingList->lock);
            return SOFTBUS_OK;
        }
    }
    pthread_mutex_unlock(&pendingList->lock);
    return SOFTBUS_ERR;
}

int32_t DelPendingPacket(int32_t channelId, int type)
{
    if (type < PENDING_TYPE_PROXY || type >= PENDING_TYPE_BUTT) {
        return SOFTBUS_ERR;
    }

    SoftBusList *pendingList = g_pendingList[type];
    if (pendingList == NULL) {
        return SOFTBUS_ERR;
    }

    PendingPktInfo *item = NULL;
    pthread_mutex_lock(&pendingList->lock);
    LIST_FOR_EACH_ENTRY(item, &pendingList->list, PendingPktInfo, node) {
        if (item->channelId == channelId) {
            pthread_cond_signal(&item->cond);
            pthread_mutex_unlock(&pendingList->lock);
            return SOFTBUS_OK;
        }
    }
    pthread_mutex_unlock(&pendingList->lock);
    return SOFTBUS_OK;
}

