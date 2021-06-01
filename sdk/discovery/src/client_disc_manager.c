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

#include "client_disc_manager.h"
#include "securec.h"
#include "softbus.h"
#include "softbus_client_frame_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_interface.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_utils.h"
#include "stdbool.h"

typedef struct {
    IPublishCallback publishCb;
    IDiscoveryCallback subscribeCb;
    pthread_mutex_t lock;
} DiscInfo;

static DiscInfo *g_discInfo = NULL;
static bool g_isInited = false;

static int32_t PublishInfoCheck(const PublishInfo *info)
{
    if ((info->mode != DISCOVER_MODE_PASSIVE) && (info->mode != DISCOVER_MODE_ACTIVE)) {
        LOG_ERR("mode is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((info->medium < AUTO) || (info->medium > COAP)) {
        LOG_ERR("medium is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((info->freq < LOW) || (info->freq > SUPER_HIGH)) {
        LOG_ERR("freq is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((info->capabilityData == NULL) && (info->dataLen != 0)) {
        LOG_ERR("data is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if (info->dataLen == 0) {
        return SOFTBUS_OK;
    }

    if ((info->dataLen > MAX_CAPABILITYDATA_LEN) ||
        (strlen((char *)(info->capabilityData)) >= MAX_CAPABILITYDATA_LEN)) {
        LOG_ERR("data exceeds the maximum length");
        return SOFTBUS_INVALID_PARAM;
    }

    return SOFTBUS_OK;
}

static int32_t SubscribeInfoCheck(const SubscribeInfo *info)
{
    if ((info->mode != DISCOVER_MODE_PASSIVE) && (info->mode != DISCOVER_MODE_ACTIVE)) {
        LOG_ERR("mode is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((info->medium < AUTO) || (info->medium > COAP)) {
        LOG_ERR("medium is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((info->freq < LOW) || (info->freq > SUPER_HIGH)) {
        LOG_ERR("freq is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((info->capabilityData == NULL) && (info->dataLen != 0)) {
        LOG_ERR("data is invalid");
        return SOFTBUS_INVALID_PARAM;
    }

    if (info->dataLen == 0) {
        return SOFTBUS_OK;
    }

    if ((info->dataLen > MAX_CAPABILITYDATA_LEN) ||
        (strlen((char *)(info->capabilityData)) >= MAX_CAPABILITYDATA_LEN)) {
        LOG_ERR("data exceeds the maximum length");
        return SOFTBUS_INVALID_PARAM;
    }

    return SOFTBUS_OK;
}

static int32_t CheckPackageName(const char *packageName)
{
    char clientPackageName[PKG_NAME_SIZE_MAX] = {0};
    if (GetSoftBusClientName(clientPackageName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK) {
        LOG_ERR("GetSoftBusClientName failed!");
        return SOFTBUS_DISCOVER_INVALID_PKGNAME;
    }
    if (strcmp(clientPackageName, packageName) == 0) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_DISCOVER_INVALID_PKGNAME;
}

static int32_t AddPublishInfo(const IPublishCallback *cb)
{
    if (pthread_mutex_lock(&(g_discInfo->lock)) != 0) {
        LOG_ERR("lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    if (memcpy_s(&(g_discInfo->publishCb), sizeof(IPublishCallback), cb, sizeof(IPublishCallback)) != EOK) {
        (void)pthread_mutex_unlock(&(g_discInfo->lock));
        LOG_ERR("memcpy failed");
        return SOFTBUS_MEM_ERR;
    }
    (void)pthread_mutex_unlock(&(g_discInfo->lock));

    return SOFTBUS_OK;
}

static int32_t AddSubscribeInfo(const IDiscoveryCallback *cb)
{
    if (pthread_mutex_lock(&(g_discInfo->lock)) != 0) {
        LOG_ERR("lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    if (memcpy_s(&(g_discInfo->subscribeCb), sizeof(IDiscoveryCallback), cb, sizeof(IDiscoveryCallback)) != EOK) {
        (void)pthread_mutex_unlock(&(g_discInfo->lock));
        LOG_ERR("memcpy failed");
        return SOFTBUS_MEM_ERR;
    }
    (void)pthread_mutex_unlock(&(g_discInfo->lock));

    return SOFTBUS_OK;
}

int32_t PublishService(const char *packageName, const PublishInfo *info, const IPublishCallback *cb)
{
    if ((packageName == NULL) || (strlen(packageName) >= PKG_NAME_SIZE_MAX) || (info == NULL) || (cb == NULL)) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (InitSoftBus(packageName) != SOFTBUS_OK) {
        LOG_ERR("init softbus err");
        return SOFTBUS_DISCOVER_NOT_INIT;
    }

    if (PublishInfoCheck(info) != SOFTBUS_OK) {
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = CheckPackageName(packageName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    ret = AddPublishInfo(cb);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    ret = GetServerProvideInterface()->publishService(packageName, info);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("Server PublishService failed, ret = %d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t UnPublishService(const char *packageName, int32_t publishId)
{
    if ((packageName == NULL) || (strlen(packageName) >= PKG_NAME_SIZE_MAX)) {
        LOG_ERR("invalid packageName");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_isInited == false) {
        LOG_ERR("not init");
        return SOFTBUS_DISCOVER_NOT_INIT;
    }

    int32_t ret = CheckPackageName(packageName);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("check packageName failed, ret = %d", ret);
        return ret;
    }

    ret = GetServerProvideInterface()->unPublishService(packageName, publishId);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("Server UnPublishService failed, ret = %d", ret);
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t StartDiscovery(const char *packageName, const SubscribeInfo *info, const IDiscoveryCallback *cb)
{
    if ((packageName == NULL) || (strlen(packageName) >= PKG_NAME_SIZE_MAX) || (info == NULL) || (cb == NULL)) {
        LOG_ERR("invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (InitSoftBus(packageName) != SOFTBUS_OK) {
        LOG_ERR("init softbus err");
        return SOFTBUS_DISCOVER_NOT_INIT;
    }

    if (SubscribeInfoCheck(info) != SOFTBUS_OK) {
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = CheckPackageName(packageName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    ret = AddSubscribeInfo(cb);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    ret = GetServerProvideInterface()->startDiscovery(packageName, info);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("Server StartDiscovery failed, ret = %d", ret);
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t StopDiscovery(const char *packageName, int32_t subscribeId)
{
    if ((packageName == NULL) || (strlen(packageName) >= PKG_NAME_SIZE_MAX)) {
        LOG_ERR("invalid packageName");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_isInited == false) {
        LOG_ERR("not init");
        return SOFTBUS_DISCOVER_NOT_INIT;
    }

    int32_t ret = CheckPackageName(packageName);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    ret = GetServerProvideInterface()->stopDiscovery(packageName, subscribeId);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("Server StopDiscovery failed, ret = %d", ret);
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t DiscClientInit(void)
{
    if (g_isInited == true) {
        LOG_INFO("Module has been initialised");
        return SOFTBUS_OK;
    }
    g_discInfo = (DiscInfo *)SoftBusCalloc(sizeof(DiscInfo));
    if (g_discInfo == NULL) {
        LOG_ERR("Calloc failed");
        return SOFTBUS_MALLOC_ERR;
    }
    pthread_mutex_init(&(g_discInfo->lock), NULL);
    g_isInited = true;
    LOG_INFO("Init success");
    return SOFTBUS_OK;
}

int32_t DiscClientDeInit(void)
{
    if (g_isInited == false) {
        LOG_ERR("Module hsa not been initialised");
        return SOFTBUS_DISCOVER_NOT_INIT;
    }
    pthread_mutex_destroy(&g_discInfo->lock);
    SoftBusFree(g_discInfo);
    g_discInfo = NULL;
    g_isInited = false;
    LOG_INFO("DeInit success");
    return SOFTBUS_OK;
}

void DiscClientOnDeviceFound(const DeviceInfo *device)
{
    g_discInfo->subscribeCb.OnDeviceFound(device);
}

void DiscClientOnDiscoverySuccess(int32_t subscribeId)
{
    g_discInfo->subscribeCb.OnDiscoverySuccess(subscribeId);
}

void DiscClientOnDiscoverFailed(int32_t subscribeId, DiscoveryFailReason failReason)
{
    g_discInfo->subscribeCb.OnDiscoverFailed(subscribeId, failReason);
}

void DiscClientOnPublishSuccess(int32_t publishId)
{
    g_discInfo->publishCb.OnPublishSuccess(publishId);
}

void DiscClientOnPublishFail(int32_t publishId, PublishFailReason reason)
{
    g_discInfo->publishCb.OnPublishFail(publishId, reason);
}
