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

#include "lnn_event.h"
#include "lnn_log.h"
#include "softbus_adapter_perf.h"
#include "softbus_errcode.h"

static void DfxRecordLnnDiscServiceStart(int32_t serverType, const char *packageName)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    extra.discServerType = serverType;

    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    if (packageName != NULL && strncpy_s(pkgName, PKG_NAME_SIZE_MAX, packageName, PKG_NAME_SIZE_MAX - 1) == EOK) {
        extra.callerPkg = pkgName;
    }
}

static void DfxRecordLnnDiscServiceEnd(int32_t serverType, const char *packageName, int32_t reason)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    extra.discServerType = serverType;
    extra.errcode = reason;
    extra.result = (reason == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;

    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    if (packageName != NULL && strncpy_s(pkgName, PKG_NAME_SIZE_MAX, packageName, PKG_NAME_SIZE_MAX - 1) == EOK) {
        extra.callerPkg = pkgName;
    }
}

int32_t LnnPublishService(const char *pkgName, const PublishInfo *info, bool isInnerRequest)
{
    DfxRecordLnnDiscServiceStart(DISC_SERVER_PUBLISH, pkgName);
    LNN_CHECK_AND_RETURN_RET_LOGE(!SoftBusIsRamTest(), SOFTBUS_ERR, LNN_BUILDER, "LnnPublishService: ram test abort");
    int32_t ret;
    if (!isInnerRequest) {
        if ((ret = DiscPublishService(pkgName, info)) != SOFTBUS_OK) {
            DfxRecordLnnDiscServiceEnd(DISC_SERVER_PUBLISH, pkgName, ret);
            LNN_LOGE(LNN_BUILDER, "DiscPublishService failed\n");
            return ret;
        }
        DfxRecordLnnDiscServiceEnd(DISC_SERVER_PUBLISH, pkgName, SOFTBUS_OK);
        return SOFTBUS_OK;
    }
    if ((ret = DiscStartScan(MODULE_LNN, info)) != SOFTBUS_OK) {
        DfxRecordLnnDiscServiceEnd(DISC_SERVER_PUBLISH, pkgName, ret);
        LNN_LOGE(LNN_BUILDER, "DiscStartScan failed\n");
        return ret;
    }
    DfxRecordLnnDiscServiceEnd(DISC_SERVER_PUBLISH, pkgName, SOFTBUS_OK);
    return SOFTBUS_OK;
}

int32_t LnnUnPublishService(const char *pkgName, int32_t publishId, bool isInnerRequest)
{
    DfxRecordLnnDiscServiceStart(DISC_SERVER_STOP_PUBLISH, pkgName);
    if (!isInnerRequest) {
        if (DiscUnPublishService(pkgName, publishId) != SOFTBUS_OK) {
            DfxRecordLnnDiscServiceEnd(DISC_SERVER_STOP_PUBLISH, pkgName, SOFTBUS_ERR);
            LNN_LOGE(LNN_BUILDER, "DiscUnPublishService failed\n");
            return SOFTBUS_ERR;
        }
        DfxRecordLnnDiscServiceEnd(DISC_SERVER_STOP_PUBLISH, pkgName, SOFTBUS_OK);
        return SOFTBUS_OK;
    }
    if (DiscUnpublish(MODULE_LNN, publishId) != SOFTBUS_OK) {
        DfxRecordLnnDiscServiceEnd(DISC_SERVER_STOP_PUBLISH, pkgName, SOFTBUS_ERR);
        LNN_LOGE(LNN_BUILDER, "DiscUnpublish fail!\n");
        return SOFTBUS_ERR;
    }
    DfxRecordLnnDiscServiceEnd(DISC_SERVER_STOP_PUBLISH, pkgName, SOFTBUS_OK);
    return SOFTBUS_OK;
}

int32_t LnnStartDiscDevice(const char *pkgName, const SubscribeInfo *info, const InnerCallback *cb,
    bool isInnerRequest)
{
    DfxRecordLnnDiscServiceStart(DISC_SERVER_DISCOVERY, pkgName);
    LNN_CHECK_AND_RETURN_RET_LOGE(!SoftBusIsRamTest(), SOFTBUS_ERR, LNN_BUILDER, "LnnStartDiscDevice: ram test abort");
    int32_t ret;
    if (!isInnerRequest) {
        if ((ret = DiscStartDiscovery(pkgName, info, &cb->serverCb)) != SOFTBUS_OK) {
            DfxRecordLnnDiscServiceEnd(DISC_SERVER_DISCOVERY, pkgName, ret);
            LNN_LOGE(LNN_BUILDER, "DiscStartDiscovery failed\n");
            return ret;
        }
        DfxRecordLnnDiscServiceEnd(DISC_SERVER_DISCOVERY, pkgName, SOFTBUS_OK);
        return SOFTBUS_OK;
    }
    if ((ret = DiscSetDiscoverCallback(MODULE_LNN, &cb->innerCb)) != SOFTBUS_OK) {
        DfxRecordLnnDiscServiceEnd(DISC_SERVER_DISCOVERY, pkgName, ret);
        LNN_LOGE(LNN_BUILDER, "DiscSetDiscoverCallback failed\n");
        return ret;
    }
    if ((ret = DiscStartAdvertise(MODULE_LNN, info)) != SOFTBUS_OK) {
        DfxRecordLnnDiscServiceEnd(DISC_SERVER_DISCOVERY, pkgName, ret);
        LNN_LOGE(LNN_BUILDER, "DiscStartAdvertise failed\n");
        return ret;
    }
    DfxRecordLnnDiscServiceEnd(DISC_SERVER_DISCOVERY, pkgName, SOFTBUS_OK);
    return SOFTBUS_OK;
}

int32_t LnnStopDiscDevice(const char *pkgName, int32_t subscribeId, bool isInnerRequest)
{
    DfxRecordLnnDiscServiceStart(DISC_SERVER_STOP_DISCOVERY, pkgName);
    if (!isInnerRequest) {
        if (DiscStopDiscovery(pkgName, subscribeId) != SOFTBUS_OK) {
            DfxRecordLnnDiscServiceEnd(DISC_SERVER_STOP_DISCOVERY, pkgName, SOFTBUS_ERR);
            LNN_LOGE(LNN_BUILDER, "DiscStopDiscovery failed\n");
            return SOFTBUS_ERR;
        }
        DfxRecordLnnDiscServiceEnd(DISC_SERVER_STOP_DISCOVERY, pkgName, SOFTBUS_OK);
        return SOFTBUS_OK;
    }
    if (DiscStopAdvertise(MODULE_LNN, subscribeId) != SOFTBUS_OK) {
        DfxRecordLnnDiscServiceEnd(DISC_SERVER_STOP_DISCOVERY, pkgName, SOFTBUS_ERR);
        LNN_LOGE(LNN_BUILDER, "DiscStopAdvertise fail!\n");
        return SOFTBUS_ERR;
    }
    DfxRecordLnnDiscServiceEnd(DISC_SERVER_STOP_DISCOVERY, pkgName, SOFTBUS_OK);
    return SOFTBUS_OK;
}
