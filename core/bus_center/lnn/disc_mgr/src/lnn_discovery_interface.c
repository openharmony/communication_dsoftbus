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

#include "softbus_errcode.h"
#include "softbus_log.h"

int32_t LnnPublishService(const char *pkgName, const PublishInfo *info, bool isInnerRequest)
{
    int32_t ret;
    if (!isInnerRequest) {
        if ((ret = DiscPublishService(pkgName, info)) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "DiscPublishService failed\n");
            return ret;
        }
        return SOFTBUS_OK;
    }
    if ((ret = DiscStartScan(MODULE_LNN, info)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "DiscStartScan failed\n");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t LnnUnPublishService(const char *pkgName, int32_t publishId, bool isInnerRequest)
{
    if (!isInnerRequest) {
        if (DiscUnPublishService(pkgName, publishId) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "DiscUnPublishService failed\n");
            return SOFTBUS_ERR;
        }
        return SOFTBUS_OK;
    }
    if (DiscUnpublish(MODULE_LNN, publishId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "DiscUnpublish fail!\n");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnStartDiscDevice(const char *pkgName, const SubscribeInfo *info, const InnerCallback *cb, bool isInnerRequest)
{
    int32_t ret;
    if (!isInnerRequest) {
        if ((ret = DiscStartDiscovery(pkgName, info, &cb->serverCb)) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "DiscStartDiscovery failed\n");
            return ret;
        }
        return SOFTBUS_OK;
    }
    if ((ret = DiscSetDiscoverCallback(MODULE_LNN, &cb->innerCb)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "DiscSetDiscoverCallback failed\n");
        return ret;
    }
    if ((ret = DiscStartAdvertise(MODULE_LNN, info)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "DiscStartAdvertise failed\n");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t LnnStopDiscDevice(const char *pkgName, int32_t subscribeId, bool isInnerRequest)
{
    if (!isInnerRequest) {
        if (DiscStopDiscovery(pkgName, subscribeId) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "DiscStopDiscovery failed\n");
            return SOFTBUS_ERR;
        }
        return SOFTBUS_OK;
    }
    if (DiscStopAdvertise(MODULE_LNN, subscribeId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "DiscStopAdvertise fail!\n");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
