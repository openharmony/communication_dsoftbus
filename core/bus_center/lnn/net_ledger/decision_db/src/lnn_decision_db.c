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

#include "lnn_decision_db.h"

#include <securec.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "anonymizer.h"
#include "auth_deviceprofile.h"
#include "auth_device_common_key.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_async_callback_utils.h"
#include "lnn_cipherkey_manager_struct.h"
#include "lnn_device_info_recovery_struct.h"
#include "lnn_ohos_account.h"
#include "lnn_file_utils.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_huks_utils.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_p2p_info.h"
#include "lnn_secure_storage_struct.h"
#include "sqlite3_utils.h"
#include "g_enhance_lnn_func_pack.h"

#include "softbus_adapter_crypto.h"
#include "softbus_adapter_file.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_timer.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

typedef struct {
    ListNode node;
    TrustedInfo infoRecord;
} DeviceDbInfo;

static ListNode g_deviceInfoList = { &g_deviceInfoList, &g_deviceInfoList };
static SoftBusMutex g_deviceDbMutex;

static bool g_isDbListInit = false;

#define LNN_DB_KEY_LEN 1024
#define LNN_DB_KEY_AILAS "dsoftbus_decision_db_key_alias"
#define DEFAULT_USER_ID "0"

#define WAIT_ONE_HOUR_QUERY_INTERVAL (60 * 60 * 1000)
#define WAIT_SEVEN_DAYS_QUERY_INTERVAL (7 * 24 * 60 * 60 * 1000)

static struct HksBlob g_keyAlias = { sizeof(LNN_DB_KEY_AILAS), (uint8_t *)LNN_DB_KEY_AILAS };
static struct HksBlob g_ceKeyAlias = { sizeof(LNN_DB_KEY_AILAS), (uint8_t *)LNN_DB_KEY_AILAS };


static bool DeviceDbRecoveryInit(void)
{
    if (SoftBusMutexInit(&g_deviceDbMutex, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "g_deviceDbMutex init fail");
        return false;
    }
    g_isDbListInit = true;
    return true;
}

static int32_t DeviceDbListLock(void)
{
    if (!g_isDbListInit) {
        if (!DeviceDbRecoveryInit()) {
            return SOFTBUS_NETWORK_DB_LOCK_INIT_FAILED;
        }
    }
    return SoftBusMutexLock(&g_deviceDbMutex);
}

static void DeviceDbListUnlock(void)
{
    if (!g_isDbListInit) {
        (void)DeviceDbRecoveryInit();
        return;
    }
    (void)SoftBusMutexUnlock(&g_deviceDbMutex);
}

static bool IsNeedUpdateHukKey(uint64_t *diffTime)
{
    uint64_t nowTime = SoftBusGetSysTimeMs();
    uint64_t huksTime = 0;
    if (LnnGetLocalNumU64Info(NUM_KEY_HUKS_TIME, &huksTime) != SOFTBUS_OK) {
        LNN_LOGW(LNN_LEDGER, "get huk time fail");
        return false;
    }
    if (huksTime == 0) {
        if (LnnSetLocalNum64Info(NUM_KEY_HUKS_TIME, nowTime) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "set huks Key time fail");
            return false;
        }
    }
    if (huksTime + WAIT_SEVEN_DAYS_QUERY_INTERVAL > nowTime) {
        *diffTime = huksTime + WAIT_SEVEN_DAYS_QUERY_INTERVAL - nowTime;
        LNN_LOGI(LNN_LEDGER, "nowTime=%{public}" PRIu64 ",huksTime=%{public}" PRIu64 ",diffTime=%{public}" PRIu64 "",
        nowTime, huksTime, *diffTime);
        return false;
    }
    return true;
}

static void StartCheckHukKeyTimeProc(void *para)
{
    (void)para;
    int32_t ret = SOFTBUS_ERR;
    uint64_t diffTime = WAIT_ONE_HOUR_QUERY_INTERVAL;
    if ((IsNeedUpdateHukKey(&diffTime)) && (UpdateKeyAndLocalInfo() == SOFTBUS_OK)) {
        LNN_LOGI(LNN_LEDGER, "update key and local info success");
        LnnAsyncCallbackDelayHelper(
            GetLooper(LOOP_TYPE_DEFAULT), StartCheckHukKeyTimeProc, NULL, WAIT_SEVEN_DAYS_QUERY_INTERVAL);
        return;
    }
    if (diffTime > WAIT_SEVEN_DAYS_QUERY_INTERVAL) {
        diffTime = WAIT_ONE_HOUR_QUERY_INTERVAL;
    }
    LNN_LOGI(LNN_LEDGER, "diffTime= %{public}" PRIu64 "", diffTime);
    ret = LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), StartCheckHukKeyTimeProc, NULL, diffTime);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "LnnAsyncCallbackDelayHelper errno:%d", ret);
        return;
    }
}

int32_t EncryptStorageData(LnnEncryptDataLevel level, uint8_t *data, uint32_t len,
    uint8_t **out, uint32_t *outLen)
{
    if (level < LNN_ENCRYPT_LEVEL_DE || level > LNN_ENCRYPT_LEVEL_ECE ||
        data == NULL || out == NULL || outLen == NULL || len + LNN_HUKS_HEADER_SIZE < len) {
        LNN_LOGE(LNN_LEDGER, "invalid param, level=%{public}u", level);
        return SOFTBUS_MEM_ERR;
    }
    uint32_t encBufSize = len + LNN_HUKS_HEADER_SIZE;
    *out = (uint8_t *)SoftBusCalloc(encBufSize);
    if (*out == NULL) {
        LNN_LOGE(LNN_LEDGER, "calloc encrypt data fail");
        return SOFTBUS_MEM_ERR;
    }
    struct HksBlob plainData = { len, data };
    struct HksBlob encData = { encBufSize, *out };
    int32_t ret;
    if (level == LNN_ENCRYPT_LEVEL_CE) {
        ret = LnnCeEncryptDataByHuks(&g_ceKeyAlias, &plainData, &encData);
    } else {
        ret = LnnEncryptDataByHuks(&g_keyAlias, &plainData, &encData);
    }
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "encrypt data by huks fail, ret=%{public}d", ret);
        SoftBusFree(*out);
        return ret;
    }
    *outLen = encData.size;
    return SOFTBUS_OK;
}

int32_t DecryptStorageData(LnnEncryptDataLevel level, uint8_t *data, uint32_t len,
    uint8_t **out, uint32_t *outLen)
{
    if (level < LNN_ENCRYPT_LEVEL_DE || level > LNN_ENCRYPT_LEVEL_ECE ||
        data == NULL || out == NULL || outLen == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param, level=%{public}u", level);
        return SOFTBUS_MEM_ERR;
    }
    uint8_t *decryptData = (uint8_t *)SoftBusCalloc(len);
    if (decryptData == NULL) {
        LNN_LOGE(LNN_LEDGER, "calloc decryptData fail");
        return SOFTBUS_MALLOC_ERR;
    }
    struct HksBlob encData = { len, data };
    struct HksBlob decData = { len, decryptData };
    int32_t ret;
    if (level == LNN_ENCRYPT_LEVEL_CE) {
        ret = LnnCeDecryptDataByHuks(&g_ceKeyAlias, &encData, &decData);
    } else {
        ret = LnnDecryptDataByHuks(&g_keyAlias, &encData, &decData);
    }
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "decrypt data by huks fail, ret=%{public}d", ret);
        SoftBusFree(decryptData);
        return ret;
    }
    *out = (uint8_t *)SoftBusCalloc(decData.size);
    if (*out == NULL) {
        LNN_LOGE(LNN_LEDGER, "calloc mem fail");
        (void)memset_s(decryptData, len, 0, len);
        SoftBusFree(decryptData);
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(*out, decData.size, decryptData, decData.size) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s data fail");
        (void)memset_s(decryptData, len, 0, len);
        SoftBusFree(decryptData);
        SoftBusFree(*out);
        return SOFTBUS_MEM_ERR;
    }
    (void)memset_s(decryptData, len, 0, len);
    SoftBusFree(decryptData);
    *outLen = decData.size;
    return SOFTBUS_OK;
}

static void CompleteUpdateTrustedDevInfo(void *para)
{
    (void)para;

    LNN_LOGD(LNN_LEDGER, "complete trusted dev info update enter");
    LnnUpdateHeartbeatInfo(UPDATE_HB_NETWORK_INFO);
}

static int32_t DeleteDeviceFromList(TrustedInfo *record)
{
    if (DeviceDbListLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    DeviceDbInfo *item = NULL;
    DeviceDbInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_deviceInfoList, DeviceDbInfo, node) {
        if (strcmp(item->infoRecord.udid, record->udid) == 0 &&
            item->infoRecord.userId == record->userId) {
            char *anonyUdid = NULL;
            Anonymize(record->udid, &anonyUdid);
            LNN_LOGI(LNN_LEDGER, "delete device db from list. udid=%{public}s", AnonymizeWrapper(anonyUdid));
            AnonymizeFree(anonyUdid);
            ListDelete(&item->node);
            SoftBusFree(item);
            break;
        }
    }
    DeviceDbListUnlock();
    return SOFTBUS_OK;
}

static int32_t InsertDeviceToList(TrustedInfo *record)
{
    if (DeviceDbListLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    DeviceDbInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_deviceInfoList, DeviceDbInfo, node) {
        if (strcmp(item->infoRecord.udid, record->udid) == 0 &&
            item->infoRecord.userId == record->userId) {
            DeviceDbListUnlock();
            return SOFTBUS_OK;
        }
    }
    DeviceDbInfo *info = (DeviceDbInfo *)SoftBusCalloc(sizeof(DeviceDbInfo));
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc info fail");
        DeviceDbListUnlock();
        return SOFTBUS_MALLOC_ERR;
    }
    info->infoRecord = *record;
    ListNodeInsert(&g_deviceInfoList, &info->node);
    DeviceDbListUnlock();
    return SOFTBUS_OK;
}

int32_t LnnInsertSpecificTrustedDevInfo(const char *udid)
{
    if (udid == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    TrustedInfo record;
    record.userId = JudgeDeviceTypeAndGetOsAccountIds();
    if (strcpy_s(record.udid, sizeof(record.udid), udid) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s udid hash failed");
        return SOFTBUS_STRCPY_ERR;
    }
    if (InsertDeviceToList(&record) == SOFTBUS_OK) {
        (void)LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), CompleteUpdateTrustedDevInfo, NULL);
    }
    return SOFTBUS_OK;
}

int32_t LnnDeleteSpecificTrustedDevInfo(const char *udid, int32_t localUserId)
{
    if (udid == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    TrustedInfo record;
    record.userId = localUserId;
    if (strcpy_s(record.udid, sizeof(record.udid), udid) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s udid hash failed");
        return SOFTBUS_STRCPY_ERR;
    }
    if (DeleteDeviceFromList(&record) == SOFTBUS_OK) {
        (void)LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), CompleteUpdateTrustedDevInfo, NULL);
    }
    return SOFTBUS_OK;
}

static int32_t GetAllDevNums(uint32_t *num, int32_t userId)
{
    DeviceDbInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_deviceInfoList, DeviceDbInfo, node) {
        if (item->infoRecord.userId == userId) {
            (*num)++;
        }
    }
    return SOFTBUS_OK;
}

int32_t LnnGetTrustedDevInfo(char **udidArray, uint32_t *num)
{
    LNN_CHECK_AND_RETURN_RET_LOGE((udidArray != NULL) && (num != NULL), SOFTBUS_INVALID_PARAM, LNN_LEDGER,
        "invalid param");
    int32_t userId = JudgeDeviceTypeAndGetOsAccountIds();
    if (DeviceDbListLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    GetAllDevNums(num, userId);
    if (*num == 0) {
        LNN_LOGD(LNN_LEDGER, "get none trusted dev info");
        *udidArray = NULL;
        DeviceDbListUnlock();
        return SOFTBUS_OK;
    }
    *udidArray = (char *)SoftBusCalloc(*num * UDID_BUF_LEN);
    if (*udidArray == NULL) {
        LNN_LOGW(LNN_LEDGER, "malloc fail");
        *num = 0;
        DeviceDbListUnlock();
        return SOFTBUS_MALLOC_ERR;
    }
    uint32_t cur = 0;
    DeviceDbInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_deviceInfoList, DeviceDbInfo, node) {
        if (cur >= *num) {
            break;
        }
        if (item->infoRecord.userId != userId) {
            continue;
        }
        if (strcpy_s(*udidArray + cur * UDID_BUF_LEN, UDID_BUF_LEN, item->infoRecord.udid) != EOK) {
            LNN_LOGE(LNN_LEDGER, "strcpy udid fail.");
            continue;
        }
        cur++;
    }
    DeviceDbListUnlock();
    return SOFTBUS_OK;
}

static int32_t RecoveryTrustedDevInfoProcess(void)
{
    uint32_t num = 0;
    TrustedInfo *trustedInfoArray = NULL;
    if (SelectAllAcl(&trustedInfoArray, &num) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get trusted dev info fail");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    LNN_LOGI(LNN_LEDGER, "get trusted relation num=%{public}u", num);
    if (trustedInfoArray == NULL || num == 0) {
        LNN_LOGE(LNN_LEDGER, "get none trusted dev info");
        return SOFTBUS_OK;
    }
    if (DeviceDbListLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "db lock fail");
        SoftBusFree(trustedInfoArray);
        return SOFTBUS_LOCK_ERR;
    }
    for (uint32_t i = 0; i < num; i++) {
        DeviceDbInfo *info = (DeviceDbInfo *)SoftBusCalloc(sizeof(DeviceDbInfo));
        if (info == NULL) {
            LNN_LOGE(LNN_BUILDER, "malloc info fail");
            continue;
        }
        info->infoRecord = trustedInfoArray[i];
        ListNodeInsert(&g_deviceInfoList, &info->node);
    }
    DeviceDbListUnlock();
    SoftBusFree(trustedInfoArray);
    return SOFTBUS_OK;
}

static void ClearRecoveryDeviceList(void)
{
    if (DeviceDbListLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "db lock fail");
        return;
    }
    DeviceDbInfo *item = NULL;
    DeviceDbInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_deviceInfoList, DeviceDbInfo, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    DeviceDbListUnlock();
}

int32_t UpdateRecoveryDeviceInfo(void)
{
    if (!g_isDbListInit) {
        return SOFTBUS_NETWORK_NOT_INIT;
    }
    ClearRecoveryDeviceList();
    return RecoveryTrustedDevInfoProcess();
}

int32_t InitDbListDelay(void)
{
    if (!DeviceDbRecoveryInit()) {
        LNN_LOGE(LNN_LEDGER, "init fail");
        return SOFTBUS_NETWORK_DB_LOCK_INIT_FAILED;
    }
    ClearRecoveryDeviceList();
    return RecoveryTrustedDevInfoProcess();
}

static bool IsDeviceTrusted(const char *udid, int32_t userId)
{
    if (udid == NULL) {
        return false;
    }
    DeviceDbInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_deviceInfoList, DeviceDbInfo, node) {
        if (strcmp(udid, item->infoRecord.udid) == 0 &&
            item->infoRecord.userId == userId) {
            return true;
        }
    }
    return false;
}

bool LnnIsPotentialHomeGroup(const char *udid)
{
    (void)udid;

    LNN_LOGE(LNN_LEDGER, "check is potential home group not implemented");
    return false;
}

int32_t LnnGenerateCeParams(bool isUnlocked)
{
    int32_t ret = LnnGenerateCeKeyByHuks(&g_ceKeyAlias, isUnlocked);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "gen huks ce key fail, ret=%{public}d", ret);
        return ret;
    }
    StartCheckHukKeyTimeProc(NULL);
    return SOFTBUS_OK;
}

int32_t LnnCheckGenerateSoftBusKeyByHuks(void)
{
    if (LnnGenerateKeyByHuks(&g_keyAlias) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "generate decision db huks de key fail");
        return SOFTBUS_GENERATE_KEY_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t LnnFindDeviceUdidTrustedInfo(const char *deviceUdid)
{
    if (deviceUdid == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (DeviceDbListLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    int32_t userId = JudgeDeviceTypeAndGetOsAccountIds();
    if (!IsDeviceTrusted(deviceUdid, userId)) {
        LNN_LOGE(LNN_LEDGER, "not find trusted in db");
        DeviceDbListUnlock();
        return SOFTBUS_NOT_FIND;
    }
    DeviceDbListUnlock();
    return SOFTBUS_OK;
}

static int32_t RetrieveDeviceInfoAndKeys(UpdateKeyRes *res)
{
    if (res == NULL) {
        LNN_LOGE(LNN_LEDGER, "input param is null");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = LnnRetrieveDeviceDataPacked(
        LNN_DATA_TYPE_REMOTE_DEVINFO, &res->remoteDevinfoData, &res->remoteDevinfoLen);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "retrieve remote devinfo fail");
        return ret;
    }
    ret = LnnRetrieveDeviceDataPacked(LNN_DATA_TYPE_DEVICE_KEY, &res->deviceKey, &res->deviceKeyLen);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "retrieve device key fail");
        return ret;
    }
    ret = LnnRetrieveDeviceDataPacked(LNN_DATA_TYPE_BLE_BROADCAST_KEY, &res->broadcastKey, &res->broadcastKeyLen);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "retrieve broadcast key fail");
        return ret;
    }
    ret = LnnRetrieveDeviceDataPacked(LNN_DATA_TYPE_PTK_KEY, &res->ptkKey, &res->ptkKeyLen);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "retrieve ptk key fail");
        return ret;
    }
    ret = LnnRetrieveDeviceDataPacked(
        LNN_DATA_TYPE_LOCAL_BROADCAST_KEY, &res->localBroadcastKey, &res->localBroadcastKeyLen);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "retrieve local broadcast key fail");
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t SaveDeviceInfoAndKeys(UpdateKeyRes *res)
{
    if (res == NULL) {
        LNN_LOGE(LNN_LEDGER, "input param is null");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = LnnSaveDeviceDataPacked(res->remoteDevinfoData, LNN_DATA_TYPE_REMOTE_DEVINFO);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "retrieve remote devinfo fail");
        return ret;
    }
    ret = LnnSaveDeviceDataPacked(res->deviceKey, LNN_DATA_TYPE_DEVICE_KEY);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "save device key fail");
        return ret;
    }
    ret = LnnSaveDeviceDataPacked(res->broadcastKey, LNN_DATA_TYPE_BLE_BROADCAST_KEY);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "save broadcast key fail");
        return ret;
    }
    ret = LnnSaveDeviceDataPacked(res->ptkKey, LNN_DATA_TYPE_PTK_KEY);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "save ptk key fail");
        return ret;
    }
    ret = LnnSaveDeviceDataPacked(res->localBroadcastKey, LNN_DATA_TYPE_LOCAL_BROADCAST_KEY);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "save local broadcast key fail");
        return ret;
    }
    return SOFTBUS_OK;
}


void FreeUpdateKeyResources(UpdateKeyRes *res)
{
    if (res == NULL) {
        LNN_LOGE(LNN_LEDGER, "param invalid");
        return;
    }
    if (res->remoteDevinfoData != NULL) {
        SoftBusFree(res->remoteDevinfoData);
        res->remoteDevinfoData = NULL;
    }
    if (res->deviceKey != NULL) {
        (void)memset_s(res->deviceKey, res->deviceKeyLen, 0, res->deviceKeyLen);
        SoftBusFree(res->deviceKey);
        res->deviceKey = NULL;
    }
    if (res->broadcastKey != NULL) {
        (void)memset_s(res->broadcastKey, res->broadcastKeyLen, 0, res->broadcastKeyLen);
        SoftBusFree(res->broadcastKey);
        res->broadcastKey = NULL;
    }
    if (res->ptkKey != NULL) {
        (void)memset_s(res->ptkKey, res->ptkKeyLen, 0, res->ptkKeyLen);
        SoftBusFree(res->ptkKey);
        res->ptkKey = NULL;
    }
    if (res->localBroadcastKey != NULL) {
        (void)memset_s(res->localBroadcastKey, res->localBroadcastKeyLen, 0, res->localBroadcastKeyLen);
        SoftBusFree(res->localBroadcastKey);
        res->localBroadcastKey = NULL;
    }
}

int32_t UpdateKeyAndLocalInfo(void)
{
    uint64_t keyTime = (uint64_t)SoftBusGetSysTimeMs();
    UpdateKeyRes res = { 0 };
    NodeInfo localNodeInfo;
    (void)memset_s(&localNodeInfo, sizeof(localNodeInfo), 0, sizeof(localNodeInfo));
    (void)LnnGetLocalDevInfoPacked(&localNodeInfo);
    int32_t  ret = RetrieveDeviceInfoAndKeys(&res);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "retrieve device key failed");
        FreeUpdateKeyResources(&res);
        return ret;
    }
    if (LnnSetLocalNum64Info(NUM_KEY_HUKS_TIME, keyTime) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "set huks key time fail");
        FreeUpdateKeyResources(&res);
        return SOFTBUS_HUKS_ERR;
    }
    localNodeInfo.huksKeyTime = keyTime;
    ret = LnnSaveLocalDeviceInfoPacked(&localNodeInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "save local device info fail");
        FreeUpdateKeyResources(&res);
        return ret;
    }
    ret = SaveDeviceInfoAndKeys(&res);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "save device info or key fail");
        FreeUpdateKeyResources(&res);
        return ret;
    }
    FreeUpdateKeyResources(&res);
    return SOFTBUS_OK;
}
