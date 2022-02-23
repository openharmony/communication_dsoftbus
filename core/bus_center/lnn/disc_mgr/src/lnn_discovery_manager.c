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

#include <securec.h>
#include <string.h>

#include "disc_interface.h"
#include "discovery_service.h"
#include "lnn_coap_discovery_impl.h"
#include "lnn_net_builder.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

static void DeviceFound(const ConnectionAddr *addr);

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
    .OnDeviceFound = DeviceFound,
};

static void DeviceFound(const ConnectionAddr *addr)
{
    if (addr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "device addr is null\n");
        return;
    }
    if (LnnNotifyDiscoveryDevice(addr) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "notify device found failed\n");
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
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init discovery impl(%d) failed\n", i);
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t LnnStartPublish(void)
{
    uint32_t i;

    for (i = 0; i < LNN_DISC_IMPL_TYPE_MAX; ++i) {
        if (g_discoveryImpl[i].StartPublishImpl == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "not support start publish(%d)\n", i);
            continue;
        }
        if (g_discoveryImpl[i].StartPublishImpl() != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "start publish impl(%d) failed\n", i);
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

void LnnStopPublish(void)
{
    uint32_t i;

    for (i = 0; i < LNN_DISC_IMPL_TYPE_MAX; ++i) {
        if (g_discoveryImpl[i].StopPublishImpl == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "not support stop publish(%d)\n", i);
            continue;
        }
        if (g_discoveryImpl[i].StopPublishImpl() != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "stop publish impl(%d) failed\n", i);
        }
    }
}

int32_t LnnStartDiscovery(void)
{
    uint32_t i;

    for (i = 0; i < LNN_DISC_IMPL_TYPE_MAX; ++i) {
        if (g_discoveryImpl[i].StartDiscoveryImpl == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "not support start discovery(%d)\n", i);
            continue;
        }
        if (g_discoveryImpl[i].StartDiscoveryImpl() != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "start discovery impl(%d) failed\n", i);
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

void LnnStopDiscovery(void)
{
    uint32_t i;

    for (i = 0; i < LNN_DISC_IMPL_TYPE_MAX; ++i) {
        if (g_discoveryImpl[i].StopDiscoveryImpl == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "not support stop discovery(%d)\n", i);
            continue;
        }
        if (g_discoveryImpl[i].StopDiscoveryImpl() != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "stop discovery impl(%d) failed\n", i);
        }
    }
}
