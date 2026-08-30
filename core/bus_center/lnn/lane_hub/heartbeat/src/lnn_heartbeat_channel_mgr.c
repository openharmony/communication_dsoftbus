/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "lnn_heartbeat_channel_mgr.h"

#include "lnn_heartbeat_fsm.h"
#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

#define HB_ADV_INTERVAL_MIN    160
#define HB_ADV_INTERVAL_MAX    480
#define HB_SCAN_INTERVAL       48
#define HB_SCAN_WINDOW         48
#define HB_TX_POWER_DEFAULT    0
#define HB_TX_POWER_LOW        (-10)
#define HB_TX_POWER_HIGH       10

static const LnnHeartbeatChannelCapability g_defaultChannelCaps[HB_MAX_CHANNEL_COUNT] = {
    [HEARTBEAT_CHANNEL_DEFAULT] = {
        .channel = HEARTBEAT_CHANNEL_DEFAULT,
        .supportTypes = HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1 | HEARTBEAT_TYPE_BLE_V3,
        .advMinInterval = HB_ADV_INTERVAL_MIN,
        .advMaxInterval = HB_ADV_INTERVAL_MAX,
        .scanWindow = HB_SCAN_WINDOW,
        .txPower = HB_TX_POWER_DEFAULT,
        .supportRelay = true,
        .supportDirectOnline = true,
        .userId = 100,
    },
    [HEARTBEAT_CHANNEL_1] = {
        .channel = HEARTBEAT_CHANNEL_1,
        .supportTypes = HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1 | HEARTBEAT_TYPE_BLE_V3,
        .advMinInterval = HB_ADV_INTERVAL_MIN,
        .advMaxInterval = HB_ADV_INTERVAL_MAX,
        .scanInterval = HB_SCAN_INTERVAL,
        .scanWindow = HB_SCAN_WINDOW,
        .txPower = HB_TX_POWER_DEFAULT,
        .supportRelay = true,
        .supportDirectOnline = true,
        .userId = 101,
    },
    [HEARTBEAT_CHANNEL_2] = {
        .channel = HEARTBEAT_CHANNEL_2,
        .supportTypes = HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1 | HEARTBEAT_TYPE_BLE_V3,
        .advMinInterval = HB_ADV_INTERVAL_MIN,
        .advMaxInterval = HB_ADV_INTERVAL_MAX,
        .scanInterval = HB_SCAN_INTERVAL,
        .scanWindow = HB_SCAN_WINDOW,
        .txPower = HB_TX_POWER_DEFAULT,
        .supportRelay = true,
        .supportDirectOnline = true,
        .userId = 102,
    },
};

static const bool g_channelFeatureFlags[HB_MAX_CHANNEL_COUNT] = {
    [HEARTBEAT_CHANNEL_DEFAULT] = true,
#ifdef DSOFTBUS_FEATURE_HB_CHANNEL_1
    [HEARTBEAT_CHANNEL_1] = true,
#else
    [HEARTBEAT_CHANNEL_1] = false,
#endif
#ifdef DSOFTBUS_FEATURE_HB_CHANNEL_2
    [HEARTBEAT_CHANNEL_2] = true,
#else
    [HEARTBEAT_CHANNEL_2] = false,
#endif
};

typedef struct {
    bool isRegistered;
    bool isEnabled;
    LnnHeartbeatChannelCapability capability;
} LnnHbChannelContext;

static SoftBusMutex g_channelMutex;
static LnnHbChannelContext g_channel[HB_MAX_CHANNEL_COUNT] = { 0 };

int32_t LnnHbChannelMgrInit(void)
{
    if (SoftBusMutexInit(&g_channelMutex, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "channel mgr init mutex fail");
        return SOFTBUS_LOCK_ERR;
    }

    for (int32_t i = 0; i < HB_MAX_CHANNEL_COUNT; i++) {
        if (!g_channelFeatureFlags[i]) {
            LNN_LOGD(LNN_HEART_BEAT, "channel %{public}d disabled by feature flag", i);
            continue;
        }
        g_channel[i].isRegistered = true;
        g_channel[i].isEnabled = (i == HEARTBEAT_CHANNEL_DEFAULT);
        g_channel[i].capability = g_defaultChannelCaps[i];
        LNN_LOGI(LNN_HEART_BEAT, "channel %{public}d registered, supportTypes=0x%{public}x",
            i, g_channel[i].capability.supportTypes);
    }
    return SOFTBUS_OK;
}

void LnnHbChannelMgrDeinit(void)
{
    for (int32_t i = 0; i < HB_MAX_CHANNEL_COUNT; i++) {
        g_channel[i].isRegistered = false;
        g_channel[i].isEnabled = false;
    }
    SoftBusMutexDestroy(&g_channelMutex);
}

int32_t LnnHbChannelEnable(LnnHeartbeatChannel channel, bool enable)
{
    if (channel >= HB_MAX_CHANNEL_COUNT) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (!g_channelFeatureFlags[channel]) {
        LNN_LOGW(LNN_HEART_BEAT, "channel %{public}d not support (feature disabled)", channel);
        return SOFTBUS_NETWORK_NOT_SUPPORT;
    }
    if (SoftBusMutexLock(&g_channelMutex) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    g_channel[channel].isEnabled = enable;
    LNN_LOGI(LNN_HEART_BEAT, "channel %{public}d %{public}s", channel, enable ? "enabled" : "disabled");
    (void)SoftBusMutexUnlock(&g_channelMutex);
    return SOFTBUS_OK;
}

bool LnnHbChannelIsEnabled(LnnHeartbeatChannel channel)
{
    if (channel >= HB_MAX_CHANNEL_COUNT) {
        return false;
    }
    if (SoftBusMutexLock(&g_channelMutex) != SOFTBUS_OK) {
        return false;
    }
    bool enable = g_channelFeatureFlags[channel] && g_channel[channel].isRegistered &&
        g_channel[channel].isEnabled;
    (void)SoftBusMutexUnlock(&g_channelMutex);
    return enable;
}

int32_t LnnHbChannelSetUserId(LnnHeartbeatChannel channel, int32_t userId)
{
    if (channel >= HB_MAX_CHANNEL_COUNT) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_channelMutex) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    g_channel[channel].capability.userId = userId;
    LNN_LOGI(LNN_HEART_BEAT, "set userId=%{public}d, channel=%{public}d", userId, channel);
    (void)SoftBusMutexUnlock(&g_channelMutex);
    return SOFTBUS_OK;
}

int32_t LnnHbChannelGetUserId(LnnHeartbeatChannel channel, int32_t *userId)
{
    if (channel >= HB_MAX_CHANNEL_COUNT || userId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_channelMutex) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    *userId = g_channel[channel].capability.userId;
    LNN_LOGI(LNN_HEART_BEAT, "get userId=%{public}d, channel=%{public}d", *userId, channel);
    (void)SoftBusMutexUnlock(&g_channelMutex);
    return SOFTBUS_OK;
}

bool LnnHbChannelIsSupportRelay(LnnHeartbeatChannel channel)
{
    if (channel >= HB_MAX_CHANNEL_COUNT) {
        return false;
    }
    bool support = false;
    if (SoftBusMutexLock(&g_channelMutex) == SOFTBUS_OK) {
        support = g_channels[channel].capability.supportRelay && g_channels[channel].isRegistered &&
            g_channels[channel].isEnabled;
        (void)SoftBusMutexUnlock(&g_channelMutex);
    }
    return support;
}
