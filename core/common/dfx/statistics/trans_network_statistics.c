/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "trans_network_statistics.h"

#include <securec.h>
#include "cJSON.h"

#include "comm_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_utils.h"
#include "trans_event.h"

typedef struct {
    ListNode node;
    int32_t channelId;
    char *channelInfo;
    uint32_t len;
} ChannelStatisticsInfo;

static SoftBusList *g_networkResourceList = NULL;

void AddNetworkResource(NetworkResource *networkResource)
{
    if (networkResource == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    if (g_networkResourceList == NULL) {
        COMM_LOGE(COMM_DFX, "g_networkResourceList init fail");
        return;
    }
    if (SoftBusMutexLock(&g_networkResourceList->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_DFX, "lock failed");
        return;
    }
    if ((int32_t)g_networkResourceList->cnt >= MAX_NETWORK_RESOURCE_NUM) {
        COMM_LOGE(COMM_DFX, "network Resource out of max num");
        (void)SoftBusMutexUnlock(&g_networkResourceList->lock);
        return;
    }

    NetworkResource *temp = NULL;
    LIST_FOR_EACH_ENTRY(temp, &g_networkResourceList->list, NetworkResource, node) {
        if (temp->laneId == networkResource->laneId) {
            COMM_LOGE(COMM_DFX, "laneId already in g_networkResourceList");
            (void)SoftBusMutexUnlock(&g_networkResourceList->lock);
            return;
        }
    }
    ListInit(&networkResource->node);
    ListInit(&networkResource->channels);
    networkResource->startTime = SoftBusGetSysTimeMs();
    ListAdd(&g_networkResourceList->list, &networkResource->node);
    g_networkResourceList->cnt++;
    (void)SoftBusMutexUnlock(&g_networkResourceList->lock);
}

void UpdateNetworkResourceByLaneId(int32_t channelId, uint64_t laneId, const void *dataInfo, uint32_t len)
{
    if (dataInfo == NULL || g_networkResourceList == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param or g_networkResourceList init fail");
        return;
    }
    if (SoftBusMutexLock(&g_networkResourceList->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_DFX, "lock failed");
        return;
    }

    NetworkResource *temp = NULL;
    LIST_FOR_EACH_ENTRY(temp, &g_networkResourceList->list, NetworkResource, node) {
        if (temp->laneId != laneId) {
            continue;
        }
        ChannelStatisticsInfo *item = NULL;
        LIST_FOR_EACH_ENTRY(item, &temp->channels, ChannelStatisticsInfo, node) {
            if (item->channelId == channelId) {
                COMM_LOGE(COMM_DFX, "channelId already in channels");
                (void)SoftBusMutexUnlock(&g_networkResourceList->lock);
                return;
            }
        }
        ChannelStatisticsInfo *info = (ChannelStatisticsInfo *)SoftBusCalloc(sizeof(ChannelStatisticsInfo));
        if (info == NULL) {
            COMM_LOGE(COMM_DFX, "channel statistics info SoftBusCalloc fail");
            (void)SoftBusMutexUnlock(&g_networkResourceList->lock);
            return;
        }
        ListInit(&info->node);
        info->channelId = channelId;
        info->len = len;
        info->channelInfo = (char *)SoftBusMalloc(len);
        if (info->channelInfo == NULL || memcpy_s(info->channelInfo, len, (char *)dataInfo, len) != EOK) {
            COMM_LOGE(COMM_DFX, "channel info is null or channel info memcpy fail");
        }
        ListAdd(&temp->channels, &info->node);
        (void)SoftBusMutexUnlock(&g_networkResourceList->lock);
        return;
    }
    (void)SoftBusMutexUnlock(&g_networkResourceList->lock);
}

static int32_t PackNetworkStatistics(cJSON *json, NetworkResource *resource)
{
    if (json == NULL || resource == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
 
    char laneId[MAX_LANE_ID_LEN] = { 0 };
    if (sprintf_s(laneId, sizeof(laneId), "%"PRIu64"", resource->laneId) < 0) {
        COMM_LOGE(COMM_DFX, "sprintf lane id fail");
        return SOFTBUS_MEM_ERR;
    }
    if (!AddStringToJsonObject(json, "laneId", laneId) ||
        !AddStringToJsonObject(json, "localUdid", resource->localUdid) ||
        !AddStringToJsonObject(json, "peerUdid", resource->peerUdid)) {
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (!AddNumberToJsonObject(json, "lineLinkType", resource->laneLinkType) ||
        !AddNumber64ToJsonObject(json, "startTime", resource->startTime) ||
        !AddNumber64ToJsonObject(json, "endTime", resource->endTime)) {
        return SOFTBUS_PARSE_JSON_ERR;
    }

    cJSON *channelStatsObj = cJSON_AddArrayToObject(json, "channelStats");
    if (channelStatsObj == NULL) {
        return SOFTBUS_PARSE_JSON_ERR;
    }
    ChannelStatisticsInfo *temp = NULL;
    LIST_FOR_EACH_ENTRY(temp, &resource->channels, ChannelStatisticsInfo, node) {
        if (temp->channelInfo != NULL) {
            cJSON_AddItemToArray(channelStatsObj, cJSON_Parse(temp->channelInfo));
        }
    }
    return SOFTBUS_OK;
}

static void DfxRecordTransChannelStatistics(NetworkResource *networkResource)
{
    if (networkResource == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    if (IsListEmpty(&networkResource->channels)) {
        return;
    }
    cJSON *json = cJSON_CreateObject();
    COMM_CHECK_AND_RETURN_LOGW(json != NULL, COMM_DFX, "cJSON_CreateObject fail");

    if (PackNetworkStatistics(json, networkResource) != SOFTBUS_OK) {
        cJSON_Delete(json);
        return;
    }
    char *trafficStats = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    COMM_CHECK_AND_RETURN_LOGW(trafficStats != NULL, COMM_DFX, "cJSON_PrintUnformatted fail");
    TransEventExtra extra = {
        .result = EVENT_STAGE_RESULT_OK,
        .trafficStats = trafficStats
    };
    TRANS_EVENT(EVENT_SCENE_TRANS_CHANNEL_STATISTICS, EVENT_STAGE_TRANS_COMMON_ONE, extra);
    cJSON_free(trafficStats);
}

void DeleteNetworkResourceByLaneId(uint64_t laneId)
{
    if (g_networkResourceList == NULL) {
        COMM_LOGE(COMM_DFX, "network resource list init fail");
        return;
    }
    if (SoftBusMutexLock(&g_networkResourceList->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_DFX, "lock failed");
        return;
    }

    NetworkResource *item = NULL;
    NetworkResource *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &(g_networkResourceList->list), NetworkResource, node) {
        if (item->laneId == laneId) {
            item->endTime = SoftBusGetSysTimeMs();
            DfxRecordTransChannelStatistics(item);
            ChannelStatisticsInfo *channelItem = NULL;
            ChannelStatisticsInfo *channelNext = NULL;
            LIST_FOR_EACH_ENTRY_SAFE(channelItem, channelNext, &item->channels, ChannelStatisticsInfo, node) {
                ListDelete(&channelItem->node);
                SoftBusFree(channelItem->channelInfo);
                SoftBusFree(channelItem);
            }
            ListDelete(&item->node);
            g_networkResourceList->cnt--;
            SoftBusFree(item);
        }
    }
    (void)SoftBusMutexUnlock(&g_networkResourceList->lock);
}

int32_t TransNetworkStatisticsInit(void)
{
    if (g_networkResourceList != NULL) {
        COMM_LOGI(COMM_DFX, "network statistics has init");
        return SOFTBUS_OK;
    }

    g_networkResourceList = CreateSoftBusList();
    if (g_networkResourceList == NULL) {
        COMM_LOGI(COMM_DFX, "network statistics init fail");
        return SOFTBUS_MALLOC_ERR;
    }
    return SOFTBUS_OK;
}

void TransNetworkStatisticsDeinit(void)
{
    if (g_networkResourceList == NULL) {
        COMM_LOGI(COMM_DFX, "network statistics has deinit");
        return;
    }

    if (SoftBusMutexLock(&g_networkResourceList->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_DFX, "lock failed");
        return;
    }
    NetworkResource *item = NULL;
    NetworkResource *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &(g_networkResourceList->list), NetworkResource, node) {
        if (!IsListEmpty(&item->channels)) {
            ChannelStatisticsInfo *channelItem = NULL;
            ChannelStatisticsInfo *channelNext = NULL;
            LIST_FOR_EACH_ENTRY_SAFE(channelItem, channelNext, &item->channels, ChannelStatisticsInfo, node) {
                ListDelete(&channelItem->node);
                SoftBusFree(channelItem->channelInfo);
                SoftBusFree(channelItem);
            }
        }
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    g_networkResourceList->cnt = 0;
    (void)SoftBusMutexUnlock(&g_networkResourceList->lock);
    DestroySoftBusList(g_networkResourceList);
    g_networkResourceList = NULL;
}