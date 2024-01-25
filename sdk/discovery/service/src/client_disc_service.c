/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "client_disc_service.h"

#include <securec.h>
#include <stdbool.h>
#include <string.h>

#include "client_disc_manager.h"
#include "disc_event.h"
#include "disc_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_client_frame_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"

static int32_t PublishInfoCheck(const PublishInfo *info)
{
    if ((info->mode != DISCOVER_MODE_PASSIVE) && (info->mode != DISCOVER_MODE_ACTIVE)) {
        DISC_LOGE(DISC_SDK, "mode is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((info->medium < AUTO) || (info->medium > COAP)) {
        DISC_LOGE(DISC_SDK, "medium is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((info->freq < LOW) || (info->freq > SUPER_HIGH)) {
        DISC_LOGE(DISC_SDK, "freq is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((info->capabilityData == NULL) && (info->dataLen != 0)) {
        DISC_LOGE(DISC_SDK, "data is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if (info->dataLen == 0) {
        return SOFTBUS_OK;
    }

    if ((info->dataLen > MAX_CAPABILITYDATA_LEN) ||
        (strlen((char *)(info->capabilityData)) >= MAX_CAPABILITYDATA_LEN)) {
        DISC_LOGE(DISC_SDK, "data exceeds the maximum length");
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static int32_t SubscribeInfoCheck(const SubscribeInfo *info)
{
    if ((info->mode != DISCOVER_MODE_PASSIVE) && (info->mode != DISCOVER_MODE_ACTIVE)) {
        DISC_LOGE(DISC_SDK, "mode is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((info->medium < AUTO) || (info->medium > COAP)) {
        DISC_LOGE(DISC_SDK, "medium is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((info->freq < LOW) || (info->freq > SUPER_HIGH)) {
        DISC_LOGE(DISC_SDK, "freq is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((info->capabilityData == NULL) && (info->dataLen != 0)) {
        DISC_LOGE(DISC_SDK, "data is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if (info->dataLen == 0) {
        return SOFTBUS_OK;
    }

    if ((info->dataLen > MAX_CAPABILITYDATA_LEN) ||
        (strlen((char *)(info->capabilityData)) >= MAX_CAPABILITYDATA_LEN)) {
        DISC_LOGE(DISC_SDK, "data exceeds the maximum length");
        return SOFTBUS_INVALID_PARAM;
    }

    return SOFTBUS_OK;
}

static void DfxRecordDiscServerEnd(int32_t serverType, int32_t reason, const char *packageName)
{
    if (reason == SOFTBUS_OK) {
        return;
    }
    DiscEventExtra extra = { 0 };
    DiscEventExtraInit(&extra);
    extra.serverType = serverType;
    extra.errcode = reason;
    extra.result = EVENT_STAGE_RESULT_FAILED;

    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    if (packageName != NULL && IsValidString(packageName, PKG_NAME_SIZE_MAX - 1) && strncpy_s(pkgName,
        PKG_NAME_SIZE_MAX, packageName, PKG_NAME_SIZE_MAX - 1) == EOK) {
        extra.callerPkg = pkgName;
    }
    DISC_EVENT(EVENT_SCENE_DISC, EVENT_STAGE_DISC_SDK, extra);
}

int PublishService(const char *packageName, const PublishInfo *info, const IPublishCallback *cb)
{
    if ((packageName == NULL) || (strlen(packageName) >= PKG_NAME_SIZE_MAX) || (info == NULL) || (cb == NULL)) {
        DfxRecordDiscServerEnd(SERVER_PUBLISH, SOFTBUS_INVALID_PARAM, packageName);
        DISC_LOGE(DISC_SDK, "invalid parameter:null");
        return SOFTBUS_INVALID_PARAM;
    }

    if (InitSoftBus(packageName) != SOFTBUS_OK) {
        DfxRecordDiscServerEnd(SERVER_PUBLISH, SOFTBUS_DISCOVER_NOT_INIT, packageName);
        DISC_LOGE(DISC_SDK, "init softbus err");
        return SOFTBUS_DISCOVER_NOT_INIT;
    }

    if (CheckPackageName(packageName) != SOFTBUS_OK) {
        DfxRecordDiscServerEnd(SERVER_PUBLISH, SOFTBUS_INVALID_PARAM, packageName);
        DISC_LOGE(DISC_SDK, "check packageName failed");
        return SOFTBUS_INVALID_PARAM;
    }

    if (PublishInfoCheck(info) != SOFTBUS_OK) {
        DfxRecordDiscServerEnd(SERVER_PUBLISH, SOFTBUS_INVALID_PARAM, packageName);
        DISC_LOGE(DISC_SDK, "publish infoCheck failed");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = PublishServiceInner(packageName, info, cb);
    DfxRecordDiscServerEnd(SERVER_PUBLISH, ret, packageName);
    return ret;
}

int UnPublishService(const char *packageName, int publishId)
{
    if ((packageName == NULL) || (strlen(packageName) >= PKG_NAME_SIZE_MAX)) {
        DfxRecordDiscServerEnd(SERVER_STOP_PUBLISH, SOFTBUS_INVALID_PARAM, packageName);
        DISC_LOGE(DISC_SDK, "invalid packageName");
        return SOFTBUS_INVALID_PARAM;
    }

    if (CheckPackageName(packageName) != SOFTBUS_OK) {
        DfxRecordDiscServerEnd(SERVER_STOP_PUBLISH, SOFTBUS_INVALID_PARAM, packageName);
        DISC_LOGE(DISC_SDK, "check packageName failed");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = UnpublishServiceInner(packageName, publishId);
    DfxRecordDiscServerEnd(SERVER_STOP_PUBLISH, ret, packageName);
    return ret;
}

int StartDiscovery(const char *packageName, const SubscribeInfo *info, const IDiscoveryCallback *cb)
{
    if ((packageName == NULL) || (strlen(packageName) >= PKG_NAME_SIZE_MAX) || (info == NULL) || (cb == NULL)) {
        DfxRecordDiscServerEnd(SERVER_DISCOVERY, SOFTBUS_INVALID_PARAM, packageName);
        DISC_LOGE(DISC_SDK, " invalid parameter:null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (InitSoftBus(packageName) != SOFTBUS_OK) {
        DfxRecordDiscServerEnd(SERVER_DISCOVERY, SOFTBUS_DISCOVER_NOT_INIT, packageName);
        DISC_LOGE(DISC_SDK, "init softbus err");
        return SOFTBUS_DISCOVER_NOT_INIT;
    }
    if (CheckPackageName(packageName) != SOFTBUS_OK) {
        DfxRecordDiscServerEnd(SERVER_DISCOVERY, SOFTBUS_INVALID_PARAM, packageName);
        DISC_LOGE(DISC_SDK, "check packageName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SubscribeInfoCheck(info) != SOFTBUS_OK) {
        DfxRecordDiscServerEnd(SERVER_DISCOVERY, SOFTBUS_INVALID_PARAM, packageName);
        DISC_LOGE(DISC_SDK, "subscribe infoCheck failed");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = StartDiscoveryInner(packageName, info, cb);
    DfxRecordDiscServerEnd(SERVER_DISCOVERY, ret, packageName);
    return ret;
}

int StopDiscovery(const char *packageName, int subscribeId)
{
    if ((packageName == NULL) || (strlen(packageName) >= PKG_NAME_SIZE_MAX)) {
        DfxRecordDiscServerEnd(SERVER_STOP_DISCOVERY, SOFTBUS_INVALID_PARAM, packageName);
        DISC_LOGE(DISC_SDK, "invalid packageName:null");
        return SOFTBUS_INVALID_PARAM;
    }

    if (CheckPackageName(packageName) != SOFTBUS_OK) {
        DfxRecordDiscServerEnd(SERVER_STOP_DISCOVERY, SOFTBUS_INVALID_PARAM, packageName);
        DISC_LOGE(DISC_SDK, "check packageName failed");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = StopDiscoveryInner(packageName, subscribeId);
    DfxRecordDiscServerEnd(SERVER_STOP_DISCOVERY, ret, packageName);
    return ret;
}