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

#include "client_trans_statistics.h"

#include <securec.h>
#include "cJSON.h"

#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_utils.h"
#include "trans_log.h"
#include "trans_server_proxy.h"

static SoftBusList *g_channelStatisticsList = NULL;

static void CreateSocketResource(SocketResource *item, const char *sessionName, const ChannelInfo *channel)
{
    if (item == NULL || sessionName == NULL || channel == NULL) {
        return;
    }
    item->laneId = channel->laneId;
    item->channelId = channel->channelId;
    item->startTime = (int64_t)SoftBusGetSysTimeMs();

    if (strcpy_s(item->socketName, SESSION_NAME_SIZE_MAX, sessionName) != EOK) {
        TRANS_LOGE(TRANS_SDK, "strcpy failed");
    }
}

void AddSocketResource(const char *sessionName, const ChannelInfo *channel)
{
    if (sessionName == NULL || channel == NULL) {
        return;
    }
    if (channel->connectType != CONNECT_BR && channel->connectType != CONNECT_BLE &&
        channel->connectType != CONNECT_P2P && channel->connectType != CONNECT_HML) {
        return;
    }
    if (channel->isServer) {
        return;
    }
    SocketResource *newItem = SoftBusCalloc(sizeof(SocketResource));
    if (newItem == NULL) {
        return;
    }
    ClientGetSessionIdByChannelId(channel->channelId, channel->channelType, &newItem->socketId);
    if (SoftBusMutexLock(&g_channelStatisticsList->lock) != SOFTBUS_OK) {
        SoftBusFree(newItem);
        return;
    }

    SocketResource *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_channelStatisticsList->list, SocketResource, node) {
        if (item->socketId == newItem->socketId) {
            (void)SoftBusMutexUnlock(&g_channelStatisticsList->lock);
            SoftBusFree(newItem);
            return;
        }
    }

    ListInit(&newItem->node);
    CreateSocketResource(newItem, sessionName, channel);
    ListAdd(&g_channelStatisticsList->list, &newItem->node);
    g_channelStatisticsList->cnt++;
    (void)SoftBusMutexUnlock(&g_channelStatisticsList->lock);
}

void UpdateChannelStatistics(int32_t socketId, int64_t len)
{
    if (SoftBusMutexLock(&g_channelStatisticsList->lock) != SOFTBUS_OK) {
        return;
    }
    SocketResource *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_channelStatisticsList->list, SocketResource, node) {
        if (item->socketId == socketId) {
            item->traffic += len;
            item->endTime = (int64_t)SoftBusGetSysTimeMs();
            (void)SoftBusMutexUnlock(&g_channelStatisticsList->lock);
            return;
        }
    }
    (void)SoftBusMutexUnlock(&g_channelStatisticsList->lock);
}

static int32_t PackStatistics(cJSON *json, SocketResource *resource)
{
    if (json == NULL || resource == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    char laneId[MAX_LANE_ID_LEN] = { 0 };
    if (sprintf_s(laneId, sizeof(laneId), "%"PRIu64"", resource->laneId) < 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (!AddNumberToJsonObject(json, "channelId", resource->channelId) ||
        !AddNumberToJsonObject(json, "socketId", resource->socketId) ||
        !AddNumber64ToJsonObject(json, "traffic", resource->traffic) ||
        !AddNumber64ToJsonObject(json, "startTime", resource->startTime) ||
        !AddNumber64ToJsonObject(json, "endTime", resource->endTime)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (!AddStringToJsonObject(json, "laneId", laneId) ||
        !AddStringToJsonObject(json, "socketName", resource->socketName)) {
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}


static void CloseChannelAndSendStatistics(SocketResource *resource)
{
    if (resource == NULL) {
        return;
    }
    cJSON *json = cJSON_CreateObject();
    TRANS_CHECK_AND_RETURN_LOGE(json != NULL, TRANS_SDK, "cJSON_CreateObject failed");
    int32_t ret = PackStatistics(json, resource);
    if (ret != SOFTBUS_OK) {
        cJSON_Delete(json);
        return;
    }
    char *str = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    TRANS_CHECK_AND_RETURN_LOGE(str != NULL, TRANS_SDK, "cJSON_PrintUnformatted failed");
    ServerIpcCloseChannelWithStatistics(resource->channelId, resource->laneId, str, strlen(str));
    cJSON_free(str);
}

void DeleteSocketResourceByChannelId(int32_t channelId, int32_t channelType)
{
    if (SoftBusMutexLock(&g_channelStatisticsList->lock) != SOFTBUS_OK) {
        return;
    }
    int32_t socketId;
    ClientGetSessionIdByChannelId(channelId, channelType, &socketId);
    SocketResource *item = NULL;
    SocketResource *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_channelStatisticsList->list, SocketResource, node) {
        if (item->socketId == socketId) {
            CloseChannelAndSendStatistics(item);
            ListDelete(&item->node);
            g_channelStatisticsList->cnt--;
            SoftBusFree(item);
        }
    }
    (void)SoftBusMutexUnlock(&g_channelStatisticsList->lock);
}

int32_t ClientTransStatisticsInit(void)
{
    if (g_channelStatisticsList != NULL) {
        return SOFTBUS_OK;
    }
    g_channelStatisticsList = CreateSoftBusList();
    if (g_channelStatisticsList == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    TRANS_LOGI(TRANS_SDK, "ClientTransStatisticsInit");
    return SOFTBUS_OK;
}

void ClientTransStatisticsDeinit(void)
{
    if (g_channelStatisticsList == NULL) {
        return;
    }
    if (SoftBusMutexLock(&g_channelStatisticsList->lock) != SOFTBUS_OK) {
        return;
    }
    SocketResource *laneItem = NULL;
    SocketResource *nextLaneItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(laneItem, nextLaneItem, &g_channelStatisticsList->list, SocketResource, node) {
        ListDelete(&(laneItem->node));
        SoftBusFree(laneItem);
    }
    g_channelStatisticsList->cnt = 0;
    (void)SoftBusMutexUnlock(&g_channelStatisticsList->lock);
    DestroySoftBusList(g_channelStatisticsList);
    g_channelStatisticsList = NULL;
    TRANS_LOGI(TRANS_SDK, "ClientTransStatisticsDeinit");
}
