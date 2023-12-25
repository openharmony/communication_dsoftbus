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

#include <stdbool.h>
#include <string.h>
#include "client_disc_manager.h"
#include "disc_log.h"
#include "softbus_client_frame_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"

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

int PublishService(const char *packageName, const PublishInfo *info, const IPublishCallback *cb)
{
    if ((packageName == NULL) || (strlen(packageName) >= PKG_NAME_SIZE_MAX) || (info == NULL) || (cb == NULL)) {
        DISC_LOGE(DISC_SDK, "invalid parameter:null");
        return SOFTBUS_INVALID_PARAM;
    }

    if (InitSoftBus(packageName) != SOFTBUS_OK) {
        DISC_LOGE(DISC_SDK, "init softbus err");
        return SOFTBUS_DISCOVER_NOT_INIT;
    }

    if (CheckPackageName(packageName) != SOFTBUS_OK) {
        DISC_LOGE(DISC_SDK, "check packageName failed");
        return SOFTBUS_INVALID_PARAM;
    }

    if (PublishInfoCheck(info) != SOFTBUS_OK) {
        DISC_LOGE(DISC_SDK, "publish infoCheck failed");
        return SOFTBUS_INVALID_PARAM;
    }

    return PublishServiceInner(packageName, info, cb);
}

int UnPublishService(const char *packageName, int publishId)
{
    if ((packageName == NULL) || (strlen(packageName) >= PKG_NAME_SIZE_MAX)) {
        DISC_LOGE(DISC_SDK, "invalid packageName");
        return SOFTBUS_INVALID_PARAM;
    }

    if (CheckPackageName(packageName) != SOFTBUS_OK) {
        DISC_LOGE(DISC_SDK, "check packageName failed");
        return SOFTBUS_INVALID_PARAM;
    }

    return UnpublishServiceInner(packageName, publishId);
}

int StartDiscovery(const char *packageName, const SubscribeInfo *info, const IDiscoveryCallback *cb)
{
    if ((packageName == NULL) || (strlen(packageName) >= PKG_NAME_SIZE_MAX) || (info == NULL) || (cb == NULL)) {
        DISC_LOGE(DISC_SDK, " invalid parameter:null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (InitSoftBus(packageName) != SOFTBUS_OK) {
        DISC_LOGE(DISC_SDK, "init softbus err");
        return SOFTBUS_DISCOVER_NOT_INIT;
    }
    if (CheckPackageName(packageName) != SOFTBUS_OK) {
        DISC_LOGE(DISC_SDK, "check packageName failed");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SubscribeInfoCheck(info) != SOFTBUS_OK) {
        DISC_LOGE(DISC_SDK, "subscribe infoCheck failed");
        return SOFTBUS_INVALID_PARAM;
    }
    return StartDiscoveryInner(packageName, info, cb);
}

int StopDiscovery(const char *packageName, int subscribeId)
{
    if ((packageName == NULL) || (strlen(packageName) >= PKG_NAME_SIZE_MAX)) {
        DISC_LOGE(DISC_SDK, "invalid packageName:null");
        return SOFTBUS_INVALID_PARAM;
    }

    if (CheckPackageName(packageName) != SOFTBUS_OK) {
        DISC_LOGE(DISC_SDK, "check packageName failed");
        return SOFTBUS_INVALID_PARAM;
    }

    return StopDiscoveryInner(packageName, subscribeId);
}