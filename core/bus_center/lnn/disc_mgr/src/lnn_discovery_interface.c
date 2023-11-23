/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "bus_center_manager.h"

#include <securec.h>
#include "disc_log.h"
#include "softbus_adapter_perf.h"
#include "softbus_def.h"
#include "softbus_errcode.h"

int32_t LnnPublishService(const char *pkgName, const PublishInfo *info, bool isInnerRequest)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(!SoftBusIsRamTest(), SOFTBUS_ERR, DISC_LNN, "LnnPublishService: ram test abort");
    int32_t ret;
    if (!isInnerRequest) {
        if ((ret = DiscPublishService(pkgName, info)) != SOFTBUS_OK) {
            DISC_LOGE(DISC_LNN, "DiscPublishService failed\n");
            return ret;
        }
        return SOFTBUS_OK;
    }
    if ((ret = DiscStartScan(MODULE_LNN, info)) != SOFTBUS_OK) {
        DISC_LOGE(DISC_LNN, "DiscStartScan failed\n");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t LnnUnPublishService(const char *pkgName, int32_t publishId, bool isInnerRequest)
{
    if (!isInnerRequest) {
        if (DiscUnPublishService(pkgName, publishId) != SOFTBUS_OK) {
            DISC_LOGE(DISC_LNN, "DiscUnPublishService failed\n");
            return SOFTBUS_ERR;
        }
        return SOFTBUS_OK;
    }
    if (DiscUnpublish(MODULE_LNN, publishId) != SOFTBUS_OK) {
        DISC_LOGE(DISC_LNN, "DiscUnpublish fail!\n");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnStartDiscDevice(const char *pkgName, const SubscribeInfo *info, const InnerCallback *cb,
    bool isInnerRequest)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(!SoftBusIsRamTest(), SOFTBUS_ERR, DISC_LNN, "LnnStartDiscDevice: ram test abort");
    int32_t ret;
    if (!isInnerRequest) {
        if ((ret = DiscStartDiscovery(pkgName, info, &cb->serverCb)) != SOFTBUS_OK) {
            DISC_LOGE(DISC_LNN, "DiscStartDiscovery failed\n");
            return ret;
        }
        return SOFTBUS_OK;
    }
    if ((ret = DiscSetDiscoverCallback(MODULE_LNN, &cb->innerCb)) != SOFTBUS_OK) {
        DISC_LOGE(DISC_LNN, "DiscSetDiscoverCallback failed\n");
        return ret;
    }
    if ((ret = DiscStartAdvertise(MODULE_LNN, info)) != SOFTBUS_OK) {
        DISC_LOGE(DISC_LNN, "DiscStartAdvertise failed\n");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t LnnStopDiscDevice(const char *pkgName, int32_t subscribeId, bool isInnerRequest)
{
    if (!isInnerRequest) {
        if (DiscStopDiscovery(pkgName, subscribeId) != SOFTBUS_OK) {
            DISC_LOGE(DISC_LNN, "DiscStopDiscovery failed\n");
            return SOFTBUS_ERR;
        }
        return SOFTBUS_OK;
    }
    if (DiscStopAdvertise(MODULE_LNN, subscribeId) != SOFTBUS_OK) {
        DISC_LOGE(DISC_LNN, "DiscStopAdvertise fail!\n");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
