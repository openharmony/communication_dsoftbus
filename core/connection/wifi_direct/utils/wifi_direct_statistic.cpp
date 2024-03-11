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

#include <map>
#include "wifi_direct_statistic.h"
#include "softbus_adapter_timer.h"
#include "softbus_error_code.h"
#include "softbus_adapter_thread.h"
#include "conn_log.h"

struct WifiDirectStatistic {
    StatisticLinkType linkType = STATISTIC_LINK_TYPE_NUM;
    StatisticBootLinkType bootLinkType = STATISTIC_BOOT_LINK_TYPE_NUM;
    bool isRenegotiate = false;
    uint64_t negotiateTimeConsuming = 0;
    uint64_t linkTimeConsuming = 0;
    bool isReuse = false;
    uint64_t processConsuming = 0;
    uint64_t hmlTriggerStartTime = 0;
    uint64_t hmlTriggerConsuming = 0;
    uint64_t createGroupStartTime = 0;
    uint64_t createGroupConsuming = 0;
    uint64_t createGroupNotifyStartTime = 0;
    uint64_t createGroupNotifyConsuming = 0;
    uint64_t connectGroupStartTime = 0;
    uint64_t connectGroupConsuming = 0;
    uint64_t openAuthConnectionStartTime = 0;
    uint64_t openAuthConnectionConsuming = 0;
    uint64_t renegotiateCreateGroupStartTime = 0;
    uint64_t renegotiateCreateGroupConsuming = 0;
    uint64_t renegotiateCreateGroupNotifyStartTime = 0;
    uint64_t renegotiateCreateGroupNotifyConsuming = 0;
    uint64_t renegotiateRemoveStartTime = 0;
    uint64_t renegotiateRemoveConsuming = 0;
};
std::map<int32_t, WifiDirectStatistic> g_wifiDirectStatistic;
static SoftBusMutex g_statisticLock;

int32_t InitStatisticMutexLock()
{
    if (SoftBusMutexInit(&g_statisticLock, nullptr) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void SetWifiDirectStatisticLinkType(int32_t requestId, enum StatisticLinkType linkType)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    g_wifiDirectStatistic[requestId].linkType = linkType;
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void GetWifiDirectStatisticLinkType(int32_t requestId, enum StatisticLinkType *linkType)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    *linkType = g_wifiDirectStatistic[requestId].linkType;
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void SetWifiDirectStatisticBootLinkType(int32_t requestId, enum StatisticBootLinkType bootLinkType)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    g_wifiDirectStatistic[requestId].bootLinkType = bootLinkType;
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void GetWifiDirectStatisticBootLinkType(int32_t requestId, int32_t *bootLinkType)
{
    enum StatisticBootLinkType tmp;
    (void)SoftBusMutexLock(&g_statisticLock);
    tmp = g_wifiDirectStatistic[requestId].bootLinkType;
    (void)SoftBusMutexUnlock(&g_statisticLock);
    *bootLinkType = tmp;
}

void SetWifiDirectStatisticRenegotiate(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    g_wifiDirectStatistic[requestId].isRenegotiate = true;
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void GetWifiDirectStatisticRenegotiate(int32_t requestId, int32_t *isRenegotiate)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    *isRenegotiate = g_wifiDirectStatistic[requestId].isRenegotiate ? 1 : 0;
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void SetWifiDirectStatisticReuse(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    g_wifiDirectStatistic[requestId].isReuse = true;
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void GetWifiDirectStatisticReuse(int32_t requestId, int32_t *isReuse)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    *isReuse = g_wifiDirectStatistic[requestId].isReuse ? 1 : 0;
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void SetWifiDirectStatisticLinkStartTime(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    g_wifiDirectStatistic[requestId].linkTimeConsuming = SoftBusGetSysTimeMs();
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void SetWifiDirectStatisticLinkEndTime(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    uint64_t startTime = g_wifiDirectStatistic[requestId].linkTimeConsuming;
    g_wifiDirectStatistic[requestId].linkTimeConsuming = SoftBusGetSysTimeMs() - startTime;
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void GetWifiDirectStatisticLinkTime(int32_t requestId, uint64_t *linkTime)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    *linkTime = g_wifiDirectStatistic[requestId].linkTimeConsuming;
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void SetWifiDirectStatisticNegotiateStartTime(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    g_wifiDirectStatistic[requestId].linkTimeConsuming = SoftBusGetSysTimeMs();
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void SetWifiDirectStatisticNegotiateEndTime(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    uint64_t startTime = g_wifiDirectStatistic[requestId].negotiateTimeConsuming;
    g_wifiDirectStatistic[requestId].negotiateTimeConsuming = SoftBusGetSysTimeMs() - startTime;
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void GetWifiDirectStatisticNegotiateTime(int32_t requestId, uint64_t *negotiateTime)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    *negotiateTime = g_wifiDirectStatistic[requestId].negotiateTimeConsuming;
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void DestroyWifiDirectStatisticElement(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    g_wifiDirectStatistic.erase(requestId);
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

bool IsReNegotiate(int32_t requestId)
{
    return g_wifiDirectStatistic[requestId].isRenegotiate;
}

void SetIsReNegotiate(int32_t requestId)
{
    g_wifiDirectStatistic[requestId].isRenegotiate = true;
}

void SetHmlTriggerStartTime(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    g_wifiDirectStatistic[requestId].hmlTriggerStartTime = SoftBusGetSysTimeMs();
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void SetHmlTriggerEndTime(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    uint64_t startTime = g_wifiDirectStatistic[requestId].hmlTriggerStartTime;
    g_wifiDirectStatistic[requestId].hmlTriggerConsuming = SoftBusGetSysTimeMs() - startTime;
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void SetCreateGroupStartTime(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    g_wifiDirectStatistic[requestId].createGroupStartTime = SoftBusGetSysTimeMs();
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void SetCreateGroupEndTime(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    uint64_t startTime = g_wifiDirectStatistic[requestId].createGroupStartTime;
    g_wifiDirectStatistic[requestId].createGroupConsuming = SoftBusGetSysTimeMs() - startTime;
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void SetCreateGroupNotifyStartTime(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    g_wifiDirectStatistic[requestId].createGroupNotifyStartTime = SoftBusGetSysTimeMs();
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void SetCreateGroupNotifyEndTime(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    uint64_t startTime = g_wifiDirectStatistic[requestId].createGroupNotifyStartTime;
    g_wifiDirectStatistic[requestId].createGroupNotifyConsuming = SoftBusGetSysTimeMs() - startTime;
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void SetConnectGroupStartTime(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    g_wifiDirectStatistic[requestId].connectGroupStartTime = SoftBusGetSysTimeMs();
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void SetConnectGroupEndTime(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    uint64_t startTime = g_wifiDirectStatistic[requestId].connectGroupStartTime;
    g_wifiDirectStatistic[requestId].connectGroupConsuming = SoftBusGetSysTimeMs() - startTime;
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void SetOpenAuthConnectionStartTime(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    g_wifiDirectStatistic[requestId].openAuthConnectionStartTime = SoftBusGetSysTimeMs();
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void SetOpenAuthConnectionEndTime(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    uint64_t startTime = g_wifiDirectStatistic[requestId].openAuthConnectionStartTime;
    g_wifiDirectStatistic[requestId].openAuthConnectionConsuming = SoftBusGetSysTimeMs() - startTime;
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void SetRenegotiateCreateGroupStartTime(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    g_wifiDirectStatistic[requestId].renegotiateCreateGroupStartTime = SoftBusGetSysTimeMs();
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void SetRenegotiateCreateGroupEndTime(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    uint64_t startTime = g_wifiDirectStatistic[requestId].renegotiateCreateGroupStartTime;
    g_wifiDirectStatistic[requestId].renegotiateCreateGroupConsuming = SoftBusGetSysTimeMs() - startTime;
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void SetRenegotiateCreateGroupNotifyStartTime(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    g_wifiDirectStatistic[requestId].renegotiateCreateGroupNotifyStartTime = SoftBusGetSysTimeMs();
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void SetRenegotiateCreateGroupNotifyEndTime(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    uint64_t startTime = g_wifiDirectStatistic[requestId].renegotiateCreateGroupNotifyStartTime;
    g_wifiDirectStatistic[requestId].renegotiateCreateGroupNotifyConsuming = SoftBusGetSysTimeMs() - startTime;
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void SetRenegotiateRemoveStartTime(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    g_wifiDirectStatistic[requestId].renegotiateRemoveStartTime = SoftBusGetSysTimeMs();
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void SetRenegotiateRemoveEndTime(int32_t requestId)
{
    (void)SoftBusMutexLock(&g_statisticLock);
    uint64_t startTime = g_wifiDirectStatistic[requestId].renegotiateRemoveStartTime;
    g_wifiDirectStatistic[requestId].renegotiateRemoveConsuming = SoftBusGetSysTimeMs() - startTime;
    (void)SoftBusMutexUnlock(&g_statisticLock);
}

void HmlTriggerRenegotiateLogPrint(int32_t requestId)
{
    g_wifiDirectStatistic[requestId].processConsuming = g_wifiDirectStatistic[requestId].hmlTriggerConsuming -
        g_wifiDirectStatistic[requestId].createGroupConsuming -
        g_wifiDirectStatistic[requestId].createGroupNotifyConsuming -
        g_wifiDirectStatistic[requestId].renegotiateRemoveConsuming -
        g_wifiDirectStatistic[requestId].renegotiateCreateGroupConsuming -
        g_wifiDirectStatistic[requestId].renegotiateCreateGroupNotifyConsuming -
        g_wifiDirectStatistic[requestId].connectGroupConsuming -
        g_wifiDirectStatistic[requestId].openAuthConnectionConsuming;
    CONN_LOGI(CONN_WIFI_DIRECT,
        "hmlTriggerReNegotiate statistic requestId=%{public}d, total=%{public}" PRIu64
        "MS, createGroup=%{public}" PRIu64 "MS, createGroupConnectNotify=%{public}" PRIu64
        "MS, removeGroup=%{public}" PRIu64 "MS, reNegotiateCreateGroup=%{public}" PRIu64
        "MS,reNegotiateCreateGroupConnectNotify=%{public}" PRIu64 " MS connectGroup=%{public}" PRIu64
        "MS,openAuthConnection=%{public}" PRIu64 "MS, process=%{public}" PRIu64 "MS",
        requestId, g_wifiDirectStatistic[requestId].hmlTriggerConsuming,
        g_wifiDirectStatistic[requestId].createGroupConsuming,
        g_wifiDirectStatistic[requestId].createGroupNotifyConsuming,
        g_wifiDirectStatistic[requestId].renegotiateRemoveConsuming,
        g_wifiDirectStatistic[requestId].renegotiateCreateGroupConsuming,
        g_wifiDirectStatistic[requestId].renegotiateCreateGroupNotifyConsuming,
        g_wifiDirectStatistic[requestId].connectGroupConsuming,
        g_wifiDirectStatistic[requestId].openAuthConnectionConsuming,
        g_wifiDirectStatistic[requestId].processConsuming);
}

void HmlTriggerLogPrint(int32_t requestId)
{
    g_wifiDirectStatistic[requestId].processConsuming = g_wifiDirectStatistic[requestId].hmlTriggerConsuming -
        g_wifiDirectStatistic[requestId].createGroupConsuming -
        g_wifiDirectStatistic[requestId].createGroupNotifyConsuming -
        g_wifiDirectStatistic[requestId].connectGroupConsuming -
        g_wifiDirectStatistic[requestId].openAuthConnectionConsuming;
    CONN_LOGI(CONN_WIFI_DIRECT,
        "hmlTrigger statistic requestId=%{public}d, total=%{public}" PRIu64 "MS, createGroup=%{public}" PRIu64
        "MS, createGroupConnectNotify=%{public}" PRIu64 "MS, connectGroup=%{public}" PRIu64
        "MS, openAuthConnection=%{public}" PRIu64 "MS, process=%{public}" PRIu64 "MS",
        requestId, g_wifiDirectStatistic[requestId].hmlTriggerConsuming,
        g_wifiDirectStatistic[requestId].createGroupConsuming,
        g_wifiDirectStatistic[requestId].createGroupNotifyConsuming,
        g_wifiDirectStatistic[requestId].connectGroupConsuming,
        g_wifiDirectStatistic[requestId].openAuthConnectionConsuming,
        g_wifiDirectStatistic[requestId].processConsuming);
}

void HmlTriggerCalculate(int32_t requestId)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "hmlTrigger isRenegotiate=%{public}d", g_wifiDirectStatistic[requestId].isRenegotiate);
    if (g_wifiDirectStatistic[requestId].isRenegotiate) {
        HmlTriggerRenegotiateLogPrint(requestId);
    } else {
        HmlTriggerLogPrint(requestId);
    }
}