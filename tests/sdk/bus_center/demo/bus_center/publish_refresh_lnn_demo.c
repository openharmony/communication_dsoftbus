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

/**
 * @file publish_refresh_lnn_demo.c
 *
 * @brief Provides the sample code for device publishes and stop publishes,
 *  subscribes to a specified service and unsubscribes from a specified service.
 *
 * @since 1.0
 * @version 1.0
 */

#include <stdint.h>

#include "softbus_bus_center.h"
#include "softbus_common.h"

static int32_t g_publishId = 0;
static int32_t g_refreshId = 0;
static void OnPublishDone(int32_t publishId, PublishResult reason)
{
    printf("[demo]OnPublishDone publishId = %d, publish result = %d", publishId, reason);
    if (reason == 0) {
        g_publishId = publishId;
    }
}

static IPublishCb g_publishCB = { .OnPublishResult = OnPublishDone;
}

static PublishInfo g_pubInfo = { .publishId = 1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = (unsigned char)"capadata1",
    .dataLen = strlen("capadata1") };

static SubscribeInfo g_subInfo = { .subscribeId = 1,
    .mode = DISCOVER_MODE_PASSIVE,
    .medium = COAP..freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "ddmpCapablity",
    .capabilityData = (unsigned char)"capadata2",
    .dataLen = strlen("capadata2") };

static void OnDeviceFoundTest(const DeviceInfo *device)
{
    printf("[demo]OnDeviceFoundTest\n");
}

static void OnDiscoverResultTest(int32_t refreshId, RefreshResult reason)
{
    printf("[demo]OnDiscoverResultTest refreshId = %d, RefreshResult = %d\n", refreshId, reason);
    if (reason == 0) {
        g_refreshId = refreshId;
    }
}

static IRefreshCallback g_refreshCB = { .OnDeviceFound = OnDeviceFoundTest, .OnDiscoverResult = OnDiscoverResultTest };

int32_t main(void)
{
    const char *pkgNameA = "pkgNameA.demo";
    /*
     * 1. Device A calls PublishLNN() to publishes a specified service,
     * it will returns 0 if the service is successfully published.
     */
    int32_t ret = PublishLNN(pkgNameA, &g_pubInfo, &g_publishCB);
    if (ret == 0) {
        printf("[demo]PublishLNN sucess\n");
    } else {
        printf("[demo]PublishLNN failed, ret = %d\n", ret);
        return ret;
    }
    /*
     * 2. When finish publish, device A return the result via OnPublishDone().
     */

    /*
     * 3. If PublishLNN() return ok, device A calls StopPublishLNN() to stop it.
     */
    ret = StopPublishLNN(pkgNameA, g_publishId);
    if (ret == 0) {
        printf("[demo]StopPublishLNN sucess\n");
    } else {
        printf("[demo]StopPublishLNN failed, ret = %d\n", ret);
    }
    return ret;
}

int32_t main(void)
{
    const char *pkgNameB = "pkgNameB.demo";

    /*
     * 1. Device B calls RefreshLNN() to Subscribes to a specified service,
     * it will returns 0 if the service subscription is successful.
     */
    int32_t ret = RefreshLNN(pkgNameB, &g_subInfo, &g_refreshCB);
    if (ret == 0) {
        printf("[demo]RefreshLNN sucess\n");
    } else {
        printf("[demo]RefreshLNN failed, ret = %d\n", ret);
        return ret;
    }
    /*
     * 2. When finish RefreshLNN, device B return the result via OnDiscoverResultTest().
     */

    /*
     * 3. When a device is found, OnDeviceFoundTest() will been invoked.
     */

    /*
     * 4. If RefreshLNN() return ok, device B calls StopRefreshLNN() to stop it.
     */
    ret = StopRefreshLNN(pkgNameB, g_refreshId);
    if (ret == 0) {
        printf("[demo]StopRefreshLNN sucess\n");
    } else {
        printf("[demo]StopRefreshLNN failed, ret = %d\n", ret);
    }
    return ret;
}
