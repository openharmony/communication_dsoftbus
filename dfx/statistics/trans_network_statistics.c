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
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "softbus_utils.h"
#include "trans_event.h"

typedef struct {
    ListNode node;
    int32_t channelId;
    int32_t channelType;
} ChannelDfxInfo;

typedef struct {
    ListNode node;
    int32_t channelId;
    char *channelInfo;
    uint32_t len;
} ChannelStatisticsInfo;

typedef struct {
    ListNode node;
    NetworkResource resource;
    int64_t startTime;
    int64_t endTime;
    ListNode channels;
} NetworkStatisticsInfo;

static SoftBusList *g_networkResourceList = NULL;

static SoftBusList *g_channelDfxInfoList = NULL;

void AddChannelStatisticsInfo(int32_t channelId, int32_t channelType)
{
    if (channelId < 0) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    if (g_channelDfxInfoList == NULL) {
        COMM_LOGE(COMM_DFX, "channel info list init failed, channelId=%{public}d", channelId);
        return;
    }
    if (SoftBusMutexLock(&g_channelDfxInfoList->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_DFX, "channel info list lock failed, channelId=%{public}d", channelId);
        return;
    }
    if ((int32_t)g_channelDfxInfoList->cnt >= MAX_CHANNEL_INFO_NUM) {
        COMM_LOGE(COMM_DFX, "channel info list out of max num, channelId=%{public}d", channelId);
        (void)SoftBusMutexUnlock(&g_channelDfxInfoList->lock);
        return;
    }

    ChannelDfxInfo *temp = NULL;
    LIST_FOR_EACH_ENTRY(temp, &g_channelDfxInfoList->list, ChannelDfxInfo, node) {
        if (temp->channelId == channelId && temp->channelType == channelType) {
            COMM_LOGE(COMM_DFX, "channel info already in channel info list, channelId=%{public}d", channelId);
            (void)SoftBusMutexUnlock(&g_channelDfxInfoList->lock);
            return;
        }
    }
    ChannelDfxInfo *channelInfo = (ChannelDfxInfo *)SoftBusCalloc(sizeof(ChannelDfxInfo));
    if (channelInfo == NULL) {
        COMM_LOGE(COMM_DFX, "channel info calloc failed, channelId=%{public}d", channelId);
        (void)SoftBusMutexUnlock(&g_channelDfxInfoList->lock);
        return;
    }
    channelInfo->channelId = channelId;
    channelInfo->channelType = channelType;
    ListAdd(&g_channelDfxInfoList->list, &channelInfo->node);
    g_channelDfxInfoList->cnt++;
    (void)SoftBusMutexUnlock(&g_channelDfxInfoList->lock);
}

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

    NetworkStatisticsInfo *temp = NULL;
    LIST_FOR_EACH_ENTRY(temp, &g_networkResourceList->list, NetworkStatisticsInfo, node) {
        if (temp->resource.laneId == networkResource->laneId) {
            COMM_LOGE(COMM_DFX, "laneId already in g_networkResourceList");
            (void)SoftBusMutexUnlock(&g_networkResourceList->lock);
            return;
        }
    }
    NetworkStatisticsInfo *info = (NetworkStatisticsInfo *)SoftBusCalloc(sizeof(NetworkStatisticsInfo));
    if (info == NULL) {
        COMM_LOGE(COMM_DFX, "network resource info SoftBusCalloc fail");
        (void)SoftBusMutexUnlock(&g_networkResourceList->lock);
        return;
    }
    if (memcpy_s(&info->resource, sizeof(NetworkResource), networkResource, sizeof(NetworkResource)) != EOK) {
        COMM_LOGE(COMM_DFX, "network resource memcpy fail");
        (void)SoftBusMutexUnlock(&g_networkResourceList->lock);
        SoftBusFree(info);
        return;
    }
    ListInit(&info->node);
    ListInit(&info->channels);
    info->startTime = SoftBusGetSysTimeMs();
    ListAdd(&g_networkResourceList->list, &info->node);
    g_networkResourceList->cnt++;
    (void)SoftBusMutexUnlock(&g_networkResourceList->lock);
}

static bool IsChannelDfxInfoValid(int32_t channelId, int32_t channelType)
{
    if (channelId < 0) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return false;
    }
    if (g_channelDfxInfoList == NULL) {
        COMM_LOGE(COMM_DFX, "channel info list init failed, channelId=%{public}d", channelId);
        return false;
    }
    if (SoftBusMutexLock(&g_channelDfxInfoList->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_DFX, "channel info list lock failed, channelId=%{public}d", channelId);
        return false;
    }

    bool ret = false;
    ChannelDfxInfo *temp = NULL;
    LIST_FOR_EACH_ENTRY(temp, &g_channelDfxInfoList->list, ChannelDfxInfo, node) {
        if (temp->channelId == channelId && temp->channelType == channelType) {
            ret = true;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_channelDfxInfoList->lock);
    return ret;
}

static void RemoveChannelDfxInfo(int32_t channelId, int32_t channelType)
{
    if (channelId < 0) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    if (g_channelDfxInfoList == NULL) {
        COMM_LOGE(COMM_DFX, "channel info list init failed, channelId=%{public}d", channelId);
        return;
    }
    if (SoftBusMutexLock(&g_channelDfxInfoList->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_DFX, "channel info list lock failed, channelId=%{public}d", channelId);
        return;
    }

    ChannelDfxInfo *temp = NULL;
    ChannelDfxInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(temp, next, &(g_channelDfxInfoList->list), ChannelDfxInfo, node) {
        if (temp->channelId == channelId && temp->channelType == channelType) {
            ListDelete(&temp->node);
            g_channelDfxInfoList->cnt--;
            SoftBusFree(temp);
        }
    }
    (void)SoftBusMutexUnlock(&g_channelDfxInfoList->lock);
}

static int32_t ChannelStatisticsInfoInit(ChannelStatisticsInfo *info, int32_t channelId, const void *dataInfo,
    uint32_t len)
{
    if (info == NULL || dataInfo == NULL || len > MAX_SOCKET_RESOURCE_LEN) {
        COMM_LOGE(COMM_DFX, "invalid param, channelId=%{public}d", channelId);
        return SOFTBUS_INVALID_PARAM;
    }

    info->channelInfo = (char *)SoftBusCalloc(len + 1);
    if (info->channelInfo == NULL) {
        COMM_LOGE(COMM_DFX, "channel info mallloc fail, channelId=%{public}d", channelId);
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(info->channelInfo, len + 1, (char *)dataInfo, len) != EOK) {
        COMM_LOGE(COMM_DFX, "channel info memcpy fail, channelId=%{public}d", channelId);
        SoftBusFree(info->channelInfo);
        return SOFTBUS_MEM_ERR;
    }
    info->channelId = channelId;
    info->len = len;
    return SOFTBUS_OK;
}

void UpdateNetworkResourceByLaneId(int32_t channelId, int32_t channelType, uint64_t laneId,
    const void *dataInfo, uint32_t len)
{
    if (dataInfo == NULL || len > MAX_SOCKET_RESOURCE_LEN || !IsChannelDfxInfoValid(channelId, channelType)) {
        COMM_LOGE(COMM_DFX, "invalid param, channelId=%{public}d", channelId);
        return;
    }
    RemoveChannelDfxInfo(channelId, channelType);
    if (g_networkResourceList == NULL) {
        COMM_LOGE(COMM_DFX, "network resource list init fail, channelId=%{public}d", channelId);
        return;
    }
    if (SoftBusMutexLock(&g_networkResourceList->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_DFX, "lock failed, channelId=%{public}d", channelId);
        return;
    }

    NetworkStatisticsInfo *temp = NULL;
    LIST_FOR_EACH_ENTRY(temp, &g_networkResourceList->list, NetworkStatisticsInfo, node) {
        if (temp->resource.laneId != laneId) {
            continue;
        }
        ChannelStatisticsInfo *item = NULL;
        LIST_FOR_EACH_ENTRY(item, &temp->channels, ChannelStatisticsInfo, node) {
            if (item->channelId == channelId) {
                COMM_LOGE(COMM_DFX, "channelId already in channels, channelId=%{public}d", channelId);
                (void)SoftBusMutexUnlock(&g_networkResourceList->lock);
                return;
            }
        }
        ChannelStatisticsInfo *info = (ChannelStatisticsInfo *)SoftBusCalloc(sizeof(ChannelStatisticsInfo));
        if (info == NULL) {
            COMM_LOGE(COMM_DFX, "channel statistics info SoftBusCalloc fail, channelId=%{public}d", channelId);
            (void)SoftBusMutexUnlock(&g_networkResourceList->lock);
            return;
        }
        if (ChannelStatisticsInfoInit(info, channelId, dataInfo, len) != SOFTBUS_OK) {
            COMM_LOGE(COMM_DFX, "channel statistics info set fail, channelId=%{public}d", channelId);
            (void)SoftBusMutexUnlock(&g_networkResourceList->lock);
            SoftBusFree(info);
            return;
        }
        ListInit(&info->node);
        ListAdd(&temp->channels, &info->node);
        (void)SoftBusMutexUnlock(&g_networkResourceList->lock);
        return;
    }
    (void)SoftBusMutexUnlock(&g_networkResourceList->lock);
}

static int32_t PackNetworkStatistics(cJSON *json, NetworkStatisticsInfo *info)
{
    if (json == NULL || info == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
 
    char laneId[MAX_LANE_ID_LEN] = { 0 };
    if (sprintf_s(laneId, sizeof(laneId), "%" PRIu64, info->resource.laneId) < 0) {
        COMM_LOGE(COMM_DFX, "sprintf lane id fail");
        return SOFTBUS_MEM_ERR;
    }
    if (!AddStringToJsonObject(json, "laneId", laneId) ||
        !AddStringToJsonObject(json, "localUdid", info->resource.localUdid) ||
        !AddStringToJsonObject(json, "peerUdid", info->resource.peerUdid)) {
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (!AddNumberToJsonObject(json, "lineLinkType", info->resource.laneLinkType) ||
        !AddNumber64ToJsonObject(json, "startTime", info->startTime) ||
        !AddNumber64ToJsonObject(json, "endTime", info->endTime)) {
        return SOFTBUS_PARSE_JSON_ERR;
    }

    cJSON *channelStatsObj = cJSON_AddArrayToObject(json, "channelStats");
    if (channelStatsObj == NULL) {
        return SOFTBUS_PARSE_JSON_ERR;
    }
    ChannelStatisticsInfo *temp = NULL;
    LIST_FOR_EACH_ENTRY(temp, &info->channels, ChannelStatisticsInfo, node) {
        if (temp->channelInfo != NULL) {
            cJSON_AddItemToArray(channelStatsObj, cJSON_ParseWithLength(temp->channelInfo, temp->len));
        }
    }
    return SOFTBUS_OK;
}

static void DfxRecordTransChannelStatistics(NetworkStatisticsInfo *networkStatisticsInfo)
{
    if (networkStatisticsInfo == NULL) {
        COMM_LOGE(COMM_DFX, "invalid param");
        return;
    }
    if (IsListEmpty(&networkStatisticsInfo->channels)) {
        return;
    }
    cJSON *json = cJSON_CreateObject();
    COMM_CHECK_AND_RETURN_LOGW(json != NULL, COMM_DFX, "cJSON_CreateObject fail");

    if (PackNetworkStatistics(json, networkStatisticsInfo) != SOFTBUS_OK) {
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

    NetworkStatisticsInfo *item = NULL;
    NetworkStatisticsInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &(g_networkResourceList->list), NetworkStatisticsInfo, node) {
        if (item->resource.laneId == laneId) {
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
        COMM_LOGW(COMM_DFX, "network statistics has init");
    } else {
        g_networkResourceList = CreateSoftBusList();
        if (g_networkResourceList == NULL) {
            COMM_LOGE(COMM_DFX, "network statistics init fail");
            return SOFTBUS_MALLOC_ERR;
        }
    }

    if (g_channelDfxInfoList != NULL) {
        COMM_LOGW(COMM_DFX, "channel statistics has init");
    } else {
        g_channelDfxInfoList = CreateSoftBusList();
        if (g_channelDfxInfoList == NULL) {
            COMM_LOGE(COMM_DFX, "channel statistics init fail");
            return SOFTBUS_MALLOC_ERR;
        }
    }
    return SOFTBUS_OK;
}

static void TransNetworkResourceDeinit(void)
{
    if (g_networkResourceList == NULL) {
        COMM_LOGW(COMM_DFX, "network statistics has deinit");
        return;
    }

    if (SoftBusMutexLock(&g_networkResourceList->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_DFX, "lock failed");
        return;
    }
    NetworkStatisticsInfo *item = NULL;
    NetworkStatisticsInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &(g_networkResourceList->list), NetworkStatisticsInfo, node) {
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

static void TransChannelStatisticsDeinit(void)
{
    if (g_channelDfxInfoList == NULL) {
        COMM_LOGW(COMM_DFX, "channel statistics has deinit");
        return;
    }

    if (SoftBusMutexLock(&g_channelDfxInfoList->lock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_DFX, "channel statistics lock failed");
        return;
    }
    ChannelDfxInfo *item = NULL;
    ChannelDfxInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &(g_channelDfxInfoList->list), ChannelDfxInfo, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    g_channelDfxInfoList->cnt = 0;
    (void)SoftBusMutexUnlock(&g_channelDfxInfoList->lock);
    DestroySoftBusList(g_channelDfxInfoList);
    g_channelDfxInfoList = NULL;
}

void TransNetworkStatisticsDeinit(void)
{
    TransNetworkResourceDeinit();
    TransChannelStatisticsDeinit();
}