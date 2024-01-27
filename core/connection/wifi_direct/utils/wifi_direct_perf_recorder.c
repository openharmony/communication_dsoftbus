/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "wifi_direct_perf_recorder.h"
#include <securec.h>
#include "conn_log.h"
#include "softbus_adapter_timer.h"

#define TIME_POINT_ITEM_DEFINE(TP) { TP, #TP }
static const char* GetTimePointTypeString(enum TimePointType type)
{
    static struct CmdStringItem {
        enum TimePointType type;
        const char *string;
    } typeStringMap[] = {
        TIME_POINT_ITEM_DEFINE(TP_P2P_CONNECT_START),
        TIME_POINT_ITEM_DEFINE(TP_P2P_CONNECT_END),
        TIME_POINT_ITEM_DEFINE(TP_P2P_CREATE_GROUP_START),
        TIME_POINT_ITEM_DEFINE(TP_P2P_CREATE_GROUP_END),
        TIME_POINT_ITEM_DEFINE(TP_P2P_CONNECT_GROUP_START),
        TIME_POINT_ITEM_DEFINE(TP_P2P_CONNECT_GROUP_END),
        TIME_POINT_ITEM_DEFINE(TP_P2P_GET_WIFI_CONFIG_START),
        TIME_POINT_ITEM_DEFINE(TP_P2P_GET_WIFI_CONFIG_END),
    };
    for (uint32_t i = 0; i < ARRAY_SIZE(typeStringMap); i++) {
        if (typeStringMap[i].type == type) {
            return typeStringMap[i].string;
        }
    }
    return "";
}

static void SetPid(int32_t pid)
{
    GetWifiDirectPerfRecorder()->pid = pid;
}

static int32_t GetPid(void)
{
    return GetWifiDirectPerfRecorder()->pid;
}

static void SetConnectType(enum WifiDirectLinkType type)
{
    GetWifiDirectPerfRecorder()->type = type;
}

static enum WifiDirectLinkType GetConnectType(void)
{
    return GetWifiDirectPerfRecorder()->type;
}

static void Record(enum TimePointType type)
{
    CONN_CHECK_AND_RETURN_LOGW(type >= 0 && type < TP_MAX, CONN_WIFI_DIRECT, "type invalid");
    uint64_t currentMs = SoftBusGetSysTimeMs();
    GetWifiDirectPerfRecorder()->timePoints[type] = currentMs;
    CONN_LOGI(CONN_WIFI_DIRECT,
        "timePointType=%{public}s, currentMs=%{public}" PRIu64, GetTimePointTypeString(type), currentMs);
}

static void Calculate(void)
{
    struct WifiDirectPerfRecorder *self = GetWifiDirectPerfRecorder();

    uint64_t start = self->timePoints[TP_P2P_CONNECT_START];
    uint64_t end = self->timePoints[TP_P2P_CONNECT_END];
    if (end != 0 && start != 0) {
        self->timeCosts[TC_TOTAL] = end - start;
    }

    start = self->timePoints[TP_P2P_CREATE_GROUP_START];
    end = self->timePoints[TP_P2P_CREATE_GROUP_END];
    if (end != 0 && start != 0) {
        self->timeCosts[TC_CREATE_GROUP] = end - start;
    }

    start = self->timePoints[TP_P2P_CONNECT_GROUP_START];
    end = self->timePoints[TP_P2P_CONNECT_GROUP_END];
    if (end != 0 && start != 0) {
        self->timeCosts[TC_CONNECT_GROUP] = end - start;
    }

    start = self->timePoints[TP_P2P_GET_WIFI_CONFIG_START];
    end = self->timePoints[TP_P2P_GET_WIFI_CONFIG_END];
    if (end != 0 && start != 0) {
        self->timeCosts[TC_GET_WIFI_CONFIG] = end - start;
    }

    if (self->timeCosts[TC_TOTAL]) {
        self->timeCosts[TC_NEGOTIATE] = self->timeCosts[TC_TOTAL] - self->timeCosts[TC_CREATE_GROUP] -
            self->timeCosts[TC_CONNECT_GROUP] - self->timeCosts[TC_GET_WIFI_CONFIG];
    }

    CONN_LOGI(CONN_WIFI_DIRECT,
        "pid=%{public}d, total=%{public}" PRIu64 "MS, create=%{public}" PRIu64 "MS, connect=%{public}" PRIu64 "MS, "
        "wifiConfig=%{public}" PRIu64 "MS, negotiate=%{public}" PRIu64 "MS",
        self->pid, self->timeCosts[TC_TOTAL], self->timeCosts[TC_CREATE_GROUP], self->timeCosts[TC_CONNECT_GROUP],
        self->timeCosts[TC_GET_WIFI_CONFIG], self->timeCosts[TC_NEGOTIATE]);
}

static uint64_t GetTime(enum TimeCostType type)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(type >= 0 && type < TC_MAX, -1, CONN_WIFI_DIRECT, "invalid type");
    return GetWifiDirectPerfRecorder()->timeCosts[type];
}

static void Clear(void)
{
    struct WifiDirectPerfRecorder *self = GetWifiDirectPerfRecorder();
    self->pid = 0;
    (void)memset_s(self->timePoints, sizeof(self->timePoints), 0, sizeof(self->timePoints));
    (void)memset_s(&self->timeCosts, sizeof(self->timeCosts), 0, sizeof(self->timeCosts));
}

static struct WifiDirectPerfRecorder g_perfRecorder = {
    .setPid = SetPid,
    .getPid = GetPid,
    .setConnectType = SetConnectType,
    .getConnectType = GetConnectType,
    .record = Record,
    .calculate = Calculate,
    .getTime = GetTime,
    .clear = Clear,
    .timePoints = {0},
    .timeCosts = {0},
};

struct WifiDirectPerfRecorder* GetWifiDirectPerfRecorder(void)
{
    return &g_perfRecorder;
}