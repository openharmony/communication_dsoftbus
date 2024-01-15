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

struct WifiDirectStatistic {
    StatisticLinkType linkType = STATISTIC_LINK_TYPE_NUM;
    StatisticBootLinkType bootLinkType = STATISTIC_BOOT_LINK_TYPE_NUM;
    bool isRenegotiate = false;
    uint64_t negotiateTimeConsuming = 0;
    uint64_t linkTimeConsuming = 0;
    bool isReuse = false;
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