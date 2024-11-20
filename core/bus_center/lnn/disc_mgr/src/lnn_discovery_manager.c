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

#include "lnn_discovery_manager.h"

#include <string.h>

#include "lnn_coap_discovery_impl.h"
#include "lnn_log.h"
#include "lnn_net_builder.h"
#include "softbus_error_code.h"
#include "legacy/softbus_hisysevt_bus_center.h"

static void DeviceFound(const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport);

typedef enum {
    LNN_DISC_IMPL_TYPE_COAP,
    LNN_DISC_IMPL_TYPE_MAX,
} LnnDiscoveryImplType;

typedef struct {
    int32_t (*InitDiscoveryImpl)(LnnDiscoveryImplCallback *callback);
    int32_t (*StartPublishImpl)(void);
    int32_t (*StopPublishImpl)(void);
    int32_t (*StartDiscoveryImpl)(void);
    int32_t (*StopDiscoveryImpl)(void);
} DiscoveryImpl;

static DiscoveryImpl g_discoveryImpl[LNN_DISC_IMPL_TYPE_MAX] = {
    [LNN_DISC_IMPL_TYPE_COAP] = {
        .InitDiscoveryImpl = LnnInitCoapDiscovery,
        .StartPublishImpl = LnnStartCoapPublish,
        .StopPublishImpl = LnnStopCoapPublish,
        .StartDiscoveryImpl = LnnStartCoapDiscovery,
        .StopDiscoveryImpl = LnnStopCoapDiscovery,
    },
};

static LnnDiscoveryImplCallback g_discoveryCallback = {
    .onDeviceFound = DeviceFound,
};

static void ReportDeviceFoundResultEvt(void)
{
    LNN_LOGD(LNN_BUILDER, "report device found result evt enter");
    if (SoftBusRecordDiscoveryResult(DEVICE_FOUND, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "report device found result fail");
    }
}

static void DeviceFound(const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport)
{
    if (addr == NULL) {
        LNN_LOGE(LNN_BUILDER, "device addr is null\n");
        return;
    }
    ReportDeviceFoundResultEvt();
    if (LnnNotifyDiscoveryDevice(addr, infoReport, true) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "notify device found failed\n");
    }
}

int32_t LnnInitDiscoveryManager(void)
{
    uint32_t i;

    for (i = 0; i < LNN_DISC_IMPL_TYPE_MAX; ++i) {
        if (g_discoveryImpl[i].InitDiscoveryImpl == NULL) {
            continue;
        }
        if (g_discoveryImpl[i].InitDiscoveryImpl(&g_discoveryCallback) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "init discovery impl failed. i=%{public}d", i);
            return SOFTBUS_DISCOVER_MANAGER_INIT_FAIL;
        }
    }
    return SOFTBUS_OK;
}

int32_t LnnStartPublish(void)
{
    uint32_t i;

    for (i = 0; i < LNN_DISC_IMPL_TYPE_MAX; ++i) {
        if (g_discoveryImpl[i].StartPublishImpl == NULL) {
            LNN_LOGE(LNN_BUILDER, "not support start publish. i=%{public}d", i);
            continue;
        }
        if (g_discoveryImpl[i].StartPublishImpl() != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "start publish impl failed. i=%{public}d", i);
            return SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL;
        }
    }
    return SOFTBUS_OK;
}

void LnnStopPublish(void)
{
    uint32_t i;

    for (i = 0; i < LNN_DISC_IMPL_TYPE_MAX; ++i) {
        if (g_discoveryImpl[i].StopPublishImpl == NULL) {
            LNN_LOGE(LNN_BUILDER, "not support stop publish. i=%{public}d", i);
            continue;
        }
        if (g_discoveryImpl[i].StopPublishImpl() != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "stop publish impl failed. i=%{public}d", i);
        }
    }
}

static void ReportStartDiscoveryResultEvt(void)
{
    LNN_LOGI(LNN_BUILDER, "report start discovery result evt enter");
    if (SoftBusRecordDiscoveryResult(START_DISCOVERY, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "report start discovery result fail");
    }
}

int32_t LnnStartDiscovery(void)
{
    uint32_t i;

    for (i = 0; i < LNN_DISC_IMPL_TYPE_MAX; ++i) {
        if (g_discoveryImpl[i].StartDiscoveryImpl == NULL) {
            LNN_LOGE(LNN_BUILDER, "not support start discovery. i=%{public}d", i);
            continue;
        }
        if (g_discoveryImpl[i].StartDiscoveryImpl() != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "start discovery impl failed. i=%{public}d", i);
            return SOFTBUS_DISCOVER_COAP_START_DISCOVER_FAIL;
        }
    }
    ReportStartDiscoveryResultEvt();
    return SOFTBUS_OK;
}

void LnnStopDiscovery(void)
{
    uint32_t i;

    for (i = 0; i < LNN_DISC_IMPL_TYPE_MAX; ++i) {
        if (g_discoveryImpl[i].StopDiscoveryImpl == NULL) {
            LNN_LOGE(LNN_BUILDER, "not support stop discovery. i=%{public}d", i);
            continue;
        }
        if (g_discoveryImpl[i].StopDiscoveryImpl() != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "stop discovery impl failed. i=%{public}d", i);
        }
    }
}
