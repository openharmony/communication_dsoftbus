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

#include "anonymizer.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_async_callback_utils.h"
#include "lnn_ohos_account.h"
#include "lnn_file_utils.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_huks_utils.h"
#include "lnn_log.h"
#include "sqlite3_utils.h"

#include "softbus_adapter_crypto.h"
#include "softbus_adapter_file.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

typedef struct {
    ListNode node;
    TrustedDevInfoRecord infoRecord;
} DeviceDbInfo;

static ListNode g_deviceInfoList = { &g_deviceInfoList, &g_deviceInfoList };
static SoftBusMutex g_deviceDbMutex;
static SoftBusMutex g_dbMutex;

static bool g_isDbListInit = false;

#define LNN_DB_KEY_LEN 1024
#define LNN_DB_KEY_AILAS "dsoftbus_decision_db_key_alias"
#define DEFAULT_USER_ID "0"

static struct HksBlob g_keyAlias = { sizeof(LNN_DB_KEY_AILAS), (uint8_t *)LNN_DB_KEY_AILAS };
static struct HksBlob g_ceKeyAlias = { sizeof(LNN_DB_KEY_AILAS), (uint8_t *)LNN_DB_KEY_AILAS };

static int32_t GetLocalAccountHexHash(char *accountHexHash);

static bool DeviceDbRecoveryInit(void)
{
    if (SoftBusMutexInit(&g_deviceDbMutex, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "g_deviceDbMutex init fail");
        return false;
    }
    if (SoftBusMutexInit(&g_dbMutex, NULL) != SOFTBUS_OK) {
        SoftBusMutexDestroy(&g_deviceDbMutex);
        LNN_LOGE(LNN_LEDGER, "g_isDbMutexInit init fail");
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

static int32_t DbLock(void)
{
    if (!g_isDbListInit) {
        if (!DeviceDbRecoveryInit()) {
            LNN_LOGE(LNN_LEDGER, "g_isDbListInit init fail");
            return SOFTBUS_NETWORK_DB_LOCK_INIT_FAILED;
        }
    }
    return SoftBusMutexLock(&g_dbMutex);
}

static void DbUnlock(void)
{
    if (!g_isDbListInit) {
        if (!DeviceDbRecoveryInit()) {
            LNN_LOGE(LNN_LEDGER, "g_isDbListInit init fail");
            return;
        }
    }
    (void)SoftBusMutexUnlock(&g_dbMutex);
}

int32_t EncryptStorageData(LnnEncryptDataLevel level, uint8_t *dbKey, uint32_t len)
{
    struct HksBlob plainData = { 0 };
    struct HksBlob encryptData = { 0 };
    if (level < LNN_ENCRYPT_LEVEL_DE || level > LNN_ENCRYPT_LEVEL_ECE) {
        LNN_LOGE(LNN_LEDGER, "invalid param, level=%{public}u", level);
        return SOFTBUS_MEM_ERR;
    }
    encryptData.data = (uint8_t *)SoftBusCalloc(len);
    if (encryptData.data == NULL) {
        LNN_LOGE(LNN_LEDGER, "calloc encrypt dbKey fail");
        return SOFTBUS_MALLOC_ERR;
    }
    LNN_LOGI(LNN_LEDGER, "Encrypt data, level=%{public}u len=%{public}u", level, len);
    plainData.size = len;
    plainData.data = dbKey;
    int32_t ret = SOFTBUS_OK;
    if (level == LNN_ENCRYPT_LEVEL_CE) {
        ret = LnnCeEncryptDataByHuks(&g_ceKeyAlias, &plainData, &encryptData);
    } else {
        ret = LnnEncryptDataByHuks(&g_keyAlias, &plainData, &encryptData);
    }
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "encrypt dbKey by huks fail, ret=%{public}d", ret);
        (void)memset_s(plainData.data, len, 0x0, len);
        SoftBusFree(encryptData.data);
        return ret;
    }
    LNN_LOGW(LNN_LEDGER, "encrypt dbKey log for audit");
    (void)memset_s(plainData.data, len, 0x0, len);
    if (memcpy_s(dbKey, len, encryptData.data, len) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s dbKey fail");
        SoftBusFree(encryptData.data);
        return SOFTBUS_MEM_ERR;
    }
    SoftBusFree(encryptData.data);
    return SOFTBUS_OK;
}

int32_t DecryptStorageData(LnnEncryptDataLevel level, uint8_t *dbKey, uint32_t len)
{
    struct HksBlob encryptData = { 0 };
    struct HksBlob decryptData = { 0 };
    if (level < LNN_ENCRYPT_LEVEL_DE || level > LNN_ENCRYPT_LEVEL_ECE) {
        LNN_LOGE(LNN_LEDGER, "invalid param, level=%{public}u", level);
        return SOFTBUS_MEM_ERR;
    }
    decryptData.data = (uint8_t *)SoftBusCalloc(len);
    if (decryptData.data == NULL) {
        LNN_LOGE(LNN_LEDGER, "calloc decrypt dbKey fail");
        return SOFTBUS_MEM_ERR;
    }
    encryptData.size = len;
    encryptData.data = dbKey;
    int32_t ret;
    do {
        if (level == LNN_ENCRYPT_LEVEL_CE) {
            ret = LnnCeDecryptDataByHuks(&g_ceKeyAlias, &encryptData, &decryptData);
        } else {
            ret = LnnDecryptDataByHuks(&g_keyAlias, &encryptData, &decryptData);
        }
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "decrypt dbKey by huks fail, ret=%{public}d", ret);
            break;
        }
        if (memcpy_s(dbKey, len, decryptData.data, decryptData.size) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "memcpy_s dbKey fail");
            ret = SOFTBUS_MEM_ERR;
            break;
        }
        ret = SOFTBUS_OK;
    } while (false);
    (void)memset_s(decryptData.data, decryptData.size, 0x0, decryptData.size);
    SoftBusFree(decryptData.data);
    return ret;
}

static int32_t GetDecisionDbKey(uint8_t *dbKey, uint32_t len, bool isUpdate)
{
    char dbKeyFilePath[SOFTBUS_MAX_PATH_LEN] = {0};
    int32_t ret = SOFTBUS_OK;

    if (LnnGetFullStoragePath(LNN_FILE_ID_DB_KEY, dbKeyFilePath, SOFTBUS_MAX_PATH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get dbKey save path fail");
        return SOFTBUS_NETWORK_GET_PATH_FAILED;
    }
    do {
        if (!isUpdate && SoftBusAccessFile(dbKeyFilePath, SOFTBUS_F_OK) == SOFTBUS_OK) {
            LNN_LOGD(LNN_LEDGER, "dbKey file is exist");
            break;
        }
        ret = LnnGenerateRandomByHuks(dbKey, len);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "generate random dbKey fail");
            return ret;
        }
        ret = EncryptStorageData(LNN_ENCRYPT_LEVEL_DE, dbKey, len);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "encrypt dbKey fail");
            return ret;
        }
        if (SoftBusWriteFile(dbKeyFilePath, (char *)dbKey, len) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "write dbKey to file fail");
            return SOFTBUS_FILE_ERR;
        }
    } while (false);
    if (SoftBusReadFullFile(dbKeyFilePath, (char *)dbKey, len) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "read dbKey from file fail");
        return SOFTBUS_FILE_ERR;
    }
    ret = DecryptStorageData(LNN_ENCRYPT_LEVEL_DE, dbKey, len);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "decrypt dbKey fail");
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t EncryptDecisionDb(DbContext *ctx)
{
    uint8_t dbKey[LNN_DB_KEY_LEN] = {0};
    int32_t ret = SOFTBUS_OK;

    ret = GetDecisionDbKey(dbKey, sizeof(dbKey), false);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get decision dbKey fail");
        (void)memset_s(dbKey, sizeof(dbKey), 0x0, sizeof(dbKey));
        return ret;
    }
    ret = EncryptedDb(ctx, dbKey, sizeof(dbKey));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "encrypt decision db fail");
        (void)memset_s(dbKey, sizeof(dbKey), 0x0, sizeof(dbKey));
        return ret;
    }
    (void)memset_s(dbKey, sizeof(dbKey), 0x0, sizeof(dbKey));
    return SOFTBUS_OK;
}

static int32_t UpdateDecisionDbKey(DbContext *ctx)
{
    uint8_t dbKey[LNN_DB_KEY_LEN] = {0};

    if (LnnGenerateKeyByHuks(&g_keyAlias) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "update decision db de key fail");
        return SOFTBUS_GENERATE_KEY_FAIL;
    }
    if (LnnGenerateCeKeyByHuks(&g_ceKeyAlias) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "update decision db ce key fail");
        return SOFTBUS_GENERATE_KEY_FAIL;
    }
    int32_t ret = GetDecisionDbKey(dbKey, sizeof(dbKey), true);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get decision dbKey fail");
        (void)memset_s(dbKey, sizeof(dbKey), 0x0, sizeof(dbKey));
        return ret;
    }
    ret = UpdateDbPassword(ctx, dbKey, sizeof(dbKey));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "encrypt decision db fail");
        (void)memset_s(dbKey, sizeof(dbKey), 0x0, sizeof(dbKey));
        return ret;
    }
    LNN_LOGW(LNN_LEDGER, "update dbKey log for audit");
    (void)memset_s(dbKey, sizeof(dbKey), 0x0, sizeof(dbKey));
    return SOFTBUS_OK;
}

static int32_t BuildTrustedDevInfoRecord(const char *udid, TrustedDevInfoRecord *record)
{
    uint8_t accountHash[SHA_256_HASH_LEN] = {0};
    char accountHexHash[SHA_256_HEX_HASH_LEN] = {0};
    int32_t userId = GetActiveOsAccountIds();
    if (udid == NULL || record == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local account hash failed");
        return SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR;
    }
    if (memset_s(record, sizeof(TrustedDevInfoRecord), 0, sizeof(TrustedDevInfoRecord)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memset_s record failed");
        return SOFTBUS_MEM_ERR;
    }
    if (ConvertBytesToHexString(accountHexHash, SHA_256_HEX_HASH_LEN, accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "convert accountHash failed");
        return SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR;
    }
    if (sprintf_s(record->accountHexHash, SHA_256_HEX_HASH_LEN + LNN_INT32_NUM_STR_MAX_LEN + 1,
        "%s-%d", accountHexHash, userId) < 0) {
        LNN_LOGE(LNN_LEDGER, "sprintf_s fail");
        return SOFTBUS_SPRINTF_ERR;
    }
    if (strcpy_s(record->udid, sizeof(record->udid), udid) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s udid hash failed");
        return SOFTBUS_STRCPY_ERR;
    }
    record->userId = userId;
    return SOFTBUS_OK;
}

static void CompleteUpdateTrustedDevInfo(void *para)
{
    (void)para;

    LNN_LOGD(LNN_LEDGER, "complete trusted dev info update enter");
    LnnUpdateHeartbeatInfo(UPDATE_HB_NETWORK_INFO);
}

static void InsertTrustedDevInfoRecord(void *param)
{
    DbContext *ctx = NULL;
    TrustedDevInfoRecord record;

    char *udid = (char *)param;
    if (udid == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return;
    }
    if (BuildTrustedDevInfoRecord(udid, &record) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "build insert trusted dev info record failed");
        SoftBusFree(udid);
        return;
    }
    if (DbLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lock fail");
        SoftBusFree(udid);
        return;
    }
    if (OpenDatabase(&ctx) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "open database failed");
        SoftBusFree(udid);
        DbUnlock();
        return;
    }
    do {
        if (EncryptDecisionDb(ctx) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "encrypt database failed");
            break;
        }
        char *anonyUdid = NULL;
        Anonymize(udid, &anonyUdid);
        LNN_LOGI(LNN_LEDGER, "insert udid to trusted dev info table. udid=%{public}s", AnonymizeWrapper(anonyUdid));
        AnonymizeFree(anonyUdid);
        if (InsertRecord(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&record) == SOFTBUS_OK) {
            (void)LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), CompleteUpdateTrustedDevInfo, NULL);
        }
    } while (false);
    if (CloseDatabase(ctx) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "close database failed");
        DbUnlock();
        SoftBusFree(udid);
        return;
    }
    DbUnlock();
    SoftBusFree(udid);
}

static void RemoveTrustedDevInfoRecord(void *param)
{
    DbContext *ctx = NULL;
    TrustedDevInfoRecord record;

    TrustedDevInfoRecord *tempRecord = (TrustedDevInfoRecord *)param;
    if (tempRecord == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return;
    }
    record = *tempRecord;
    SoftBusFree(tempRecord);
    if (DbLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lock fail");
        return;
    }
    if (OpenDatabase(&ctx) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "open database failed");
        DbUnlock();
        return;
    }
    do {
        if (EncryptDecisionDb(ctx) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "encrypt database failed");
            break;
        }
        // delete oldRecord
        TrustedDevInfoRecord oldRecord = record;
        (void)memset_s(oldRecord.accountHexHash, sizeof(oldRecord.accountHexHash), 0, sizeof(oldRecord.accountHexHash));
        if (GetLocalAccountHexHash(oldRecord.accountHexHash) == SOFTBUS_OK) {
            (void)RemoveRecordByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&oldRecord);
        }
        if (RemoveRecordByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&record) == SOFTBUS_OK) {
            (void)LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), CompleteUpdateTrustedDevInfo, NULL);
        }
    } while (false);
    if (CloseDatabase(ctx) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "close database failed");
    }
    DbUnlock();
    char *anonyUdid = NULL;
    Anonymize(record.udid, &anonyUdid);
    LNN_LOGI(LNN_LEDGER, "remove udid from trusted dev info table. udid=%{public}s", AnonymizeWrapper(anonyUdid));
    AnonymizeFree(anonyUdid);
}

static void DeleteDeviceFromList(TrustedDevInfoRecord *record)
{
    if (DeviceDbListLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lock fail");
        return;
    }
    DeviceDbInfo *item = NULL;
    DeviceDbInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_deviceInfoList, DeviceDbInfo, node) {
        if (strcmp(item->infoRecord.accountHexHash, record->accountHexHash) == 0 &&
            strcmp(item->infoRecord.udid, record->udid) == 0 &&
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
}

static void InsertDeviceToList(TrustedDevInfoRecord *record)
{
    if (DeviceDbListLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lock fail");
        return;
    }
    DeviceDbInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_deviceInfoList, DeviceDbInfo, node) {
        if (strcmp(item->infoRecord.accountHexHash, record->accountHexHash) == 0 &&
            strcmp(item->infoRecord.udid, record->udid) == 0 &&
            item->infoRecord.userId == record->userId) {
            DeviceDbListUnlock();
            return;
        }
    }
    DeviceDbInfo *info = (DeviceDbInfo *)SoftBusCalloc(sizeof(DeviceDbInfo));
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc info fail");
        DeviceDbListUnlock();
        return;
    }
    info->infoRecord = *record;
    ListNodeInsert(&g_deviceInfoList, &info->node);
    DeviceDbListUnlock();
}

int32_t LnnInsertSpecificTrustedDevInfo(const char *udid)
{
    char *dupUdid = NULL;

    if (udid == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    TrustedDevInfoRecord record;
    int32_t ret = BuildTrustedDevInfoRecord(udid, &record);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "build insert trusted dev info record failed");
        return ret;
    }
    InsertDeviceToList(&record);
    dupUdid = (char *)SoftBusMalloc(UDID_BUF_LEN);
    if (dupUdid == NULL) {
        LNN_LOGE(LNN_LEDGER, "malloc dupUdid failed");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s(dupUdid, UDID_BUF_LEN, udid) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s dupUdid failed");
        SoftBusFree(dupUdid);
        return SOFTBUS_STRCPY_ERR;
    }
    if (LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), InsertTrustedDevInfoRecord,
        (void *)dupUdid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "async call insert trusted dev info failed");
        SoftBusFree(dupUdid);
        return SOFTBUS_NETWORK_ASYNC_CALLBACK_FAILED;
    }
    return SOFTBUS_OK;
}

static int32_t BuildTrustedDevInfoRecordEx(const char *udid, TrustedDevInfoRecord *record, int32_t localUserId)
{
    uint8_t accountHash[SHA_256_HASH_LEN] = {0};
    char accountHexHash[SHA_256_HEX_HASH_LEN] = {0};
    if (udid == NULL || record == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnGetOhosAccountInfoByUserId(localUserId, accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local account hash failed");
        if (SoftBusGenerateStrHash((const unsigned char *)DEFAULT_USER_ID,
            strlen(DEFAULT_USER_ID), (unsigned char *)accountHash) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "generate default str hash fail");
            return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR;
        }
    }
    if (memset_s(record, sizeof(TrustedDevInfoRecord), 0, sizeof(TrustedDevInfoRecord)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memset_s record failed");
        return SOFTBUS_MEM_ERR;
    }
    if (ConvertBytesToHexString(accountHexHash, SHA_256_HEX_HASH_LEN, accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "convert accountHash failed");
        return SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR;
    }
    if (sprintf_s(record->accountHexHash, SHA_256_HEX_HASH_LEN + LNN_INT32_NUM_STR_MAX_LEN + 1,
        "%s-%d", accountHexHash, localUserId) < 0) {
        LNN_LOGE(LNN_LEDGER, "sprintf_s fail");
        return SOFTBUS_SPRINTF_ERR;
    }
    if (strcpy_s(record->udid, sizeof(record->udid), udid) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s udid hash failed");
        return SOFTBUS_STRCPY_ERR;
    }
    record->userId = localUserId;
    return SOFTBUS_OK;
}

int32_t LnnDeleteSpecificTrustedDevInfo(const char *udid, int32_t localUserId)
{
    TrustedDevInfoRecord *dupRecord = NULL;

    if (udid == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    TrustedDevInfoRecord record;
    int32_t ret = BuildTrustedDevInfoRecordEx(udid, &record, localUserId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "build delete trusted dev info record failed");
        return ret;
    }
    DeleteDeviceFromList(&record);
    dupRecord = (TrustedDevInfoRecord *)SoftBusMalloc(sizeof(TrustedDevInfoRecord));
    if (dupRecord == NULL) {
        LNN_LOGE(LNN_LEDGER, "malloc dupRecord failed");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(dupRecord, sizeof(TrustedDevInfoRecord), &record, sizeof(TrustedDevInfoRecord)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s dupRecord failed");
        SoftBusFree(dupRecord);
        return SOFTBUS_STRCPY_ERR;
    }
    if (LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), RemoveTrustedDevInfoRecord,
        (void *)dupRecord) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "async call remove trusted dev info failed");
        SoftBusFree(dupRecord);
        return SOFTBUS_NETWORK_ASYNC_CALLBACK_FAILED;
    }
    return SOFTBUS_OK;
}

static int32_t GetTrustedDevInfoRecord(DbContext *ctx, const char *accountHexHash, char **udidArray, uint32_t *num)
{
    int32_t ret = EncryptDecisionDb(ctx);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "encrypt database failed");
        *udidArray = NULL;
        *num = 0;
        return ret;
    }
    *((int32_t *)num) = GetRecordNumByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)accountHexHash);
    if (*num == 0) {
        LNN_LOGW(LNN_LEDGER, "get none trusted dev info");
        *udidArray = NULL;
        return SOFTBUS_OK;
    }
    *udidArray = (char *)SoftBusCalloc(*num * UDID_BUF_LEN);
    if (*udidArray == NULL) {
        *num = 0;
        return SOFTBUS_MALLOC_ERR;
    }
    ret = QueryRecordByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)accountHexHash,
        (uint8_t **)udidArray, *((int32_t *)num));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "query udidArray failed");
        SoftBusFree(*udidArray);
        *udidArray = NULL;
        *num = 0;
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t GetLocalAccountHexHash(char *accountHexHash)
{
    uint8_t accountHash[SHA_256_HASH_LEN] = {0};
    if (LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local account hash failed");
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    if (ConvertBytesToHexString(accountHexHash, SHA_256_HEX_HASH_LEN, accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "convert accountHash failed");
        return SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t GetAllDevNums(char *accountHexHash, uint32_t *num, int32_t userId)
{
    DeviceDbInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_deviceInfoList, DeviceDbInfo, node) {
        if (strcmp(accountHexHash, item->infoRecord.accountHexHash) == 0 && item->infoRecord.userId == userId) {
            (*num)++;
        }
    }
    return SOFTBUS_OK;
}

static int32_t GenerateAccountHexHashWithUserId(char *accountHexHashAndUserId, int32_t *userId)
{
    char accountHexHash[SHA_256_HEX_HASH_LEN] = {0};
    *userId = GetActiveOsAccountIds();
    if (GetLocalAccountHexHash(accountHexHash) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local account hash failed");
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    if (sprintf_s(accountHexHashAndUserId, SHA_256_HEX_HASH_LEN + LNN_INT32_NUM_STR_MAX_LEN + 1,
        "%s-%d", accountHexHash, *userId) < 0) {
        LNN_LOGE(LNN_LEDGER, "sprintf_s fail");
        return SOFTBUS_SPRINTF_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnGetTrustedDevInfoFromDb(char **udidArray, uint32_t *num)
{
    char accountHexHashAndUserId[SHA_256_HEX_HASH_LEN + LNN_INT32_NUM_STR_MAX_LEN + 1] = {0};
    int32_t userId = 0;
    LNN_CHECK_AND_RETURN_RET_LOGE((udidArray != NULL) && (num != NULL), SOFTBUS_INVALID_PARAM, LNN_LEDGER,
        "invalid param");
    if (GenerateAccountHexHashWithUserId(accountHexHashAndUserId, &userId) != SOFTBUS_OK) {
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }

    if (DeviceDbListLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    int32_t ret = GetAllDevNums(accountHexHashAndUserId, num, userId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get all dev num fail");
        DeviceDbListUnlock();
        return ret;
    }
    if (*num == 0) {
        LNN_LOGW(LNN_LEDGER, "get none trusted dev info");
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
        if (strcmp(accountHexHashAndUserId, item->infoRecord.accountHexHash) != 0 ||
            item->infoRecord.userId != userId) {
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

static int32_t GetTrustedDevInfoFromDb(char **udidArray, uint32_t *num, char *accountHexHash)
{
    DbContext *ctx = NULL;

    if (udidArray == NULL || num == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (DbLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    if (OpenDatabase(&ctx) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "open database failed");
        DbUnlock();
        return SOFTBUS_NETWORK_DATABASE_FAILED;
    }
    int32_t rc = GetTrustedDevInfoRecord(ctx, accountHexHash, udidArray, num);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get trusted dev info failed");
    }
    if (CloseDatabase(ctx) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "close database failed");
        DbUnlock();
        SoftBusFree(*udidArray);
        *udidArray = NULL;
        *num = 0;
        return SOFTBUS_NETWORK_DATABASE_FAILED;
    }
    DbUnlock();
    return rc;
}

static int32_t RecoveryTrustedDevInfoProcess(char *accountHexHash, int32_t activeUserId, bool oldData)
{
    uint32_t num = 0;
    char *udidArray = NULL;
    if (GetTrustedDevInfoFromDb(&udidArray, &num, accountHexHash) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get trusted dev info fail");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    LNN_LOGI(LNN_LEDGER, "get trusted relation num=%{public}u", num);
    if (udidArray == NULL || num == 0) {
        LNN_LOGE(LNN_LEDGER, "get none trusted dev info");
        return SOFTBUS_OK;
    }
    if (oldData && sprintf_s(accountHexHash, SHA_256_HEX_HASH_LEN + LNN_INT32_NUM_STR_MAX_LEN + 1,
        "%s-%d", accountHexHash, activeUserId) < 0) {
        LNN_LOGE(LNN_LEDGER, "sprintf_s fail");
        return SOFTBUS_STRCPY_ERR;
    }
    if (DeviceDbListLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "db lock fail");
        SoftBusFree(udidArray);
        return SOFTBUS_LOCK_ERR;
    }
    for (uint32_t i = 0; i < num; i++) {
        char udidStr[UDID_BUF_LEN] = { 0 };
        DeviceDbInfo *info = (DeviceDbInfo *)SoftBusCalloc(sizeof(DeviceDbInfo));
        if (info == NULL) {
            LNN_LOGE(LNN_BUILDER, "malloc info fail");
            continue;
        }
        if (memcpy_s(udidStr, UDID_BUF_LEN, udidArray + i * UDID_BUF_LEN, UDID_BUF_LEN) != EOK ||
            memcpy_s(info->infoRecord.udid, UDID_BUF_LEN, udidStr, UDID_BUF_LEN) != EOK ||
            memcpy_s(info->infoRecord.accountHexHash, SHA_256_HEX_HASH_LEN + LNN_INT32_NUM_STR_MAX_LEN + 1,
                accountHexHash, SHA_256_HEX_HASH_LEN + LNN_INT32_NUM_STR_MAX_LEN + 1) != EOK) {
            LNN_LOGE(LNN_LEDGER, "udid str cpy fail.");
            DeviceDbListUnlock();
            SoftBusFree(info);
            SoftBusFree(udidArray);
            return SOFTBUS_MEM_ERR;
        }
        info->infoRecord.userId = activeUserId;
        ListNodeInsert(&g_deviceInfoList, &info->node);
    }
    DeviceDbListUnlock();
    SoftBusFree(udidArray);
    return SOFTBUS_OK;
}

static int32_t RecoveryTrustedDevInfo(void)
{
    char accountHexHash[SHA_256_HEX_HASH_LEN + LNN_INT32_NUM_STR_MAX_LEN + 1] = {0};
    char tempAccountAccountHexHash[SHA_256_HEX_HASH_LEN + LNN_INT32_NUM_STR_MAX_LEN + 1] = {0};
    if (GetLocalAccountHexHash(accountHexHash) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local account hash failed");
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    if (strcpy_s(tempAccountAccountHexHash, SHA_256_HEX_HASH_LEN + LNN_INT32_NUM_STR_MAX_LEN + 1,
        accountHexHash)!= EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy fail");
        return SOFTBUS_STRCPY_ERR;
    }
    RecoveryTrustedDevInfoProcess(accountHexHash, LNN_DEFAULT_USERID, true);

    char accountHexHashAndUserId[SHA_256_HEX_HASH_LEN + LNN_INT32_NUM_STR_MAX_LEN + 1] = {0};
    int32_t userId = GetActiveOsAccountIds();
    LNN_LOGI(LNN_LEDGER, "activeUserId=%{public}d", userId);
    if (sprintf_s(accountHexHashAndUserId, SHA_256_HEX_HASH_LEN + LNN_INT32_NUM_STR_MAX_LEN + 1,
        "%s-%d", tempAccountAccountHexHash, userId) < 0) {
        LNN_LOGE(LNN_LEDGER, "sprintf_s fail");
        return SOFTBUS_SPRINTF_ERR;
    }
    RecoveryTrustedDevInfoProcess(accountHexHashAndUserId, userId, false);
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

int32_t UpdateRecoveryDeviceInfoFromDb(void)
{
    if (!g_isDbListInit) {
        return SOFTBUS_NETWORK_NOT_INIT;
    }
    ClearRecoveryDeviceList();
    return RecoveryTrustedDevInfo();
}

static int32_t InitDbList(void)
{
    if (!DeviceDbRecoveryInit()) {
        LNN_LOGE(LNN_LEDGER, "init fail");
        return SOFTBUS_NETWORK_DB_LOCK_INIT_FAILED;
    }
    ClearRecoveryDeviceList();
    return RecoveryTrustedDevInfo();
}

static int32_t InitTrustedDevInfoTable(void)
{
    bool isExist = false;
    int32_t rc = SOFTBUS_NETWORK_INIT_TRUST_DEV_INFO_FAILED;
    DbContext *ctx = NULL;
 
    if (OpenDatabase(&ctx) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "open database failed");
        return SOFTBUS_NETWORK_DATABASE_FAILED;
    }
    do {
        if (EncryptDecisionDb(ctx) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "encrypt database failed");
            break;
        }
        if (UpdateDecisionDbKey(ctx) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "update database dbKey failed");
            break;
        }
        if (CheckTableExist(ctx, TABLE_TRUSTED_DEV_INFO, &isExist) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "check table exist failed");
            break;
        }
        if (!isExist && CreateTable(ctx, TABLE_TRUSTED_DEV_INFO) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "create trusted dev info table failed");
            break;
        }
        rc = SOFTBUS_OK;
    } while (false);
    if (CloseDatabase(ctx) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "close database failed");
        return SOFTBUS_NETWORK_DATABASE_FAILED;
    }
    if (rc == SOFTBUS_OK) {
        rc = InitDbList();
    }
    return rc;
}

static int32_t TryRecoveryTrustedDevInfoTable(void)
{
    char dbKeyFilePath[SOFTBUS_MAX_PATH_LEN] = {0};

    if (LnnGetFullStoragePath(LNN_FILE_ID_DB_KEY, dbKeyFilePath, SOFTBUS_MAX_PATH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get dbKey save path fail");
        return SOFTBUS_NETWORK_GET_PATH_FAILED;
    }
    SoftBusRemoveFile(dbKeyFilePath);
    SoftBusRemoveFile(DATABASE_NAME);
    return InitTrustedDevInfoTable();
}

bool LnnIsPotentialHomeGroup(const char *udid)
{
    (void)udid;

    LNN_LOGE(LNN_LEDGER, "check is potential home group not implemented");
    return false;
}

int32_t LnnGenerateCeParams(void)
{
    return LnnGenerateCeKeyByHuks(&g_ceKeyAlias);
}

int32_t LnnCheckGenerateSoftBusKeyByHuks(void)
{
    if (LnnGenerateKeyByHuks(&g_keyAlias) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "generate decision db huks de key fail");
        return SOFTBUS_GENERATE_KEY_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t LnnInitDecisionDbDelay(void)
{
    if (LnnGenerateKeyByHuks(&g_keyAlias) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "generate decision db huks de key fail");
        return SOFTBUS_GENERATE_KEY_FAIL;
    }
    if (LnnGenerateCeKeyByHuks(&g_ceKeyAlias) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "update decision db huks ce key fail");
        return SOFTBUS_GENERATE_KEY_FAIL;
    }
    if (InitTrustedDevInfoTable() != SOFTBUS_OK) {
        LNN_LOGI(LNN_LEDGER, "try init trusted dev info table again");
        return TryRecoveryTrustedDevInfoTable();
    }
    return SOFTBUS_OK;
}
