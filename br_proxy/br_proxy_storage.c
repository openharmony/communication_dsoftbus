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

#include "br_proxy_storage.h"

#include <securec.h>

#include "softbus_adapter_file.h"
#include "softbus_json_utils.h"
#include "trans_log.h"

#define TAG "[br_proxy] "
#define BR_PROXY_STORAGE_FILE "/data/service/el1/public/dsoftbus/brproxystorage"
#define BUFFER_LEN            2048
#define JSON_KEY_VERSION      "version"
#define JSON_KEY_BUNDLE_NAME  "bundleName"
#define JSON_KEY_ABILITY_NAME "abilityName"
#define JSON_KEY_APP_INDEX    "appIndex"
#define JSON_KEY_USER_ID      "userId"
#define JSON_KEY_UID          "uid"
#define JSON_VALUE_VERSION    1

TransBrProxyStorage *TransBrProxyStorageGetInstance(void)
{
    static TransBrProxyStorage instance = { 0 };
    static bool init = false;
    if (init) {
        return &instance;
    }

    instance.filepath = BR_PROXY_STORAGE_FILE;
    int32_t code = SoftBusMutexInit(&instance.mutex, NULL);
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        code == SOFTBUS_OK, NULL, TRANS_SVC, TAG "init lock failed, error=%{public}d", code);
    
    int32_t ret = memset_s(&instance.info, sizeof(TransBrProxyStorageInfo), 0, sizeof(TransBrProxyStorageInfo));
    if (ret != EOK) {
        TRANS_LOGE(TRANS_SVC, TAG "memset_s info failed, err=%{public}d", ret);
        SoftBusMutexDestroy(&instance.mutex);
        return NULL;
    }
    instance.loaded = false;

    init = true;
    return &instance;
}

static void LoadIfNeed(TransBrProxyStorage *instance)
{
    if (instance->loaded) {
        return;
    }

    char buffer[BUFFER_LEN] = { 0 };
    uint32_t capacity = sizeof(buffer);
    int32_t size = 0;
    int32_t code = SoftBusReadFullFileAndSize(instance->filepath, buffer, capacity, &size);
    TRANS_CHECK_AND_RETURN_LOGE(code == SOFTBUS_OK, TRANS_SVC, TAG "read storage file failed, error=%{public}d", code);
    TRANS_CHECK_AND_RETURN_LOGE(size > 0 && size < BUFFER_LEN, TRANS_SVC,
        TAG "invalid storage content, size=%{public}d, capacity=%{public}u", size, capacity);
    
    cJSON *json = cJSON_ParseWithLength(buffer, size);
    TRANS_CHECK_AND_RETURN_LOGE(json != NULL, TRANS_SVC, TAG "parse storage json failed");

    if (!GetJsonObjectStringItem(json, JSON_KEY_BUNDLE_NAME, instance->info.bundleName, NAME_MAX_LEN) ||
        !GetJsonObjectStringItem(json, JSON_KEY_ABILITY_NAME, instance->info.abilityName, NAME_MAX_LEN) ||
        !GetJsonObjectNumberItem(json, JSON_KEY_APP_INDEX, &instance->info.appIndex) ||
        !GetJsonObjectNumberItem(json, JSON_KEY_USER_ID, &instance->info.userId) ||
        !GetJsonObjectNumberItem(json, JSON_KEY_UID, &instance->info.uid)) {
        TRANS_LOGE(TRANS_SVC, TAG "parse storage fields failed");
        cJSON_Delete(json);
        return;
    }
    instance->loaded = true;

    cJSON_Delete(json);
}

static void Persist(TransBrProxyStorage *instance)
{
    cJSON *json = cJSON_CreateObject();
    TRANS_CHECK_AND_RETURN_LOGE(json != NULL, TRANS_SVC, TAG "create storage json failed");
    if (!AddNumberToJsonObject(json, JSON_KEY_VERSION, JSON_VALUE_VERSION) ||
        !AddStringToJsonObject(json, JSON_KEY_BUNDLE_NAME, instance->info.bundleName) ||
        !AddStringToJsonObject(json, JSON_KEY_ABILITY_NAME, instance->info.abilityName) ||
        !AddNumberToJsonObject(json, JSON_KEY_APP_INDEX, instance->info.appIndex) ||
        !AddNumberToJsonObject(json, JSON_KEY_USER_ID, instance->info.userId) ||
        !AddNumberToJsonObject(json, JSON_KEY_UID, instance->info.uid)) {
        TRANS_LOGE(TRANS_SVC, TAG "marshal storage fields failed");
        cJSON_Delete(json);
        return;
    }

    char *buffer = cJSON_PrintUnformatted(json);
    if (buffer == NULL) {
        TRANS_LOGE(TRANS_SVC, TAG "marshal storage json failed");
        cJSON_Delete(json);
        return;
    }

    uint32_t size = strlen(buffer);
    (void)SoftBusWriteFile(instance->filepath, buffer, size + 1);

    cJSON_free(buffer);
    cJSON_Delete(json);
}

bool TransBrProxyStorageRead(TransBrProxyStorage *instance, TransBrProxyStorageInfo *info)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(instance != NULL, false, TRANS_SVC, TAG "instance is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(info != NULL, false, TRANS_SVC, TAG "info buffer is null");

    int32_t code = SoftBusMutexLock(&instance->mutex);
    TRANS_CHECK_AND_RETURN_RET_LOGE(code == SOFTBUS_OK, false, TRANS_SVC, TAG "lock failed, error=%{public}d", code);

    LoadIfNeed(instance);
    if (!instance->loaded) {
        SoftBusMutexUnlock(&instance->mutex);
        return false;
    }

    int32_t ret = memcpy_s(info, sizeof(TransBrProxyStorageInfo), &instance->info, sizeof(TransBrProxyStorageInfo));
    if (ret != EOK) {
        TRANS_LOGE(TRANS_SVC, TAG "memcpy_s read info failed, err=%{public}d", ret);
        SoftBusMutexUnlock(&instance->mutex);
        return false;
    }

    SoftBusMutexUnlock(&instance->mutex);
    TRANS_LOGW(TRANS_SVC, TAG "read storage success, userId=%{public}d, uid=%{public}d, appIndex=%{public}d",
        info->userId, info->uid, info->appIndex);
    return true;
}

void TransBrProxyStorageWrite(TransBrProxyStorage *instance, const TransBrProxyStorageInfo *info)
{
    TRANS_CHECK_AND_RETURN_LOGE(instance != NULL, TRANS_SVC, TAG "instance is null");
    TRANS_CHECK_AND_RETURN_LOGE(info != NULL, TRANS_SVC, TAG "storage info is null");

    int32_t code = SoftBusMutexLock(&instance->mutex);
    TRANS_CHECK_AND_RETURN_LOGE(code == SOFTBUS_OK, TRANS_SVC, TAG "lock failed, error=%{public}d", code);

    int32_t ret = memcpy_s(&instance->info, sizeof(TransBrProxyStorageInfo), info, sizeof(TransBrProxyStorageInfo));
    if (ret != EOK) {
        TRANS_LOGE(TRANS_SVC, TAG "memcpy_s write info failed, err=%{public}d", ret);
        SoftBusMutexUnlock(&instance->mutex);
        return;
    }
    Persist(instance);
    instance->loaded = true;

    SoftBusMutexUnlock(&instance->mutex);
    TRANS_LOGW(TRANS_SVC, TAG "write storage success, userId=%{public}d, uid=%{public}d, appIndex=%{public}d",
        info->userId, info->uid, info->appIndex);
}

void TransBrProxyStorageClear(TransBrProxyStorage *instance)
{
    TRANS_CHECK_AND_RETURN_LOGE(instance != NULL, TRANS_SVC, TAG "instance is null");

    int32_t code = SoftBusMutexLock(&instance->mutex);
    TRANS_CHECK_AND_RETURN_LOGE(code == SOFTBUS_OK, TRANS_SVC, TAG "lock failed, error=%{public}d", code);

    int32_t ret = memset_s(&instance->info, sizeof(TransBrProxyStorageInfo), 0, sizeof(TransBrProxyStorageInfo));
    if (ret != EOK) {
        TRANS_LOGE(TRANS_SVC, TAG "memset_s clear info failed, err=%{public}d", ret);
        SoftBusMutexUnlock(&instance->mutex);
        return;
    }
    (void)SoftBusRemoveFile(instance->filepath);

    SoftBusMutexUnlock(&instance->mutex);
    TRANS_LOGW(TRANS_SVC, TAG "clear storage success and delete file");
}