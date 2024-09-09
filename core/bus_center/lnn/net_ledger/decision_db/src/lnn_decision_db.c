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
#include "lnn_file_utils.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_huks_utils.h"
#include "lnn_log.h"
#include "sqlite3_utils.h"

#include "softbus_adapter_crypto.h"
#include "softbus_adapter_file.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
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

static struct HksBlob g_keyAlias = { sizeof(LNN_DB_KEY_AILAS), (uint8_t *)LNN_DB_KEY_AILAS };
static struct HksBlob g_ceKeyAlias = { sizeof(LNN_DB_KEY_AILAS), (uint8_t *)LNN_DB_KEY_AILAS };

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
            return SOFTBUS_ERR;
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
            return SOFTBUS_ERR;
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
        return SOFTBUS_MEM_ERR;
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
        return SOFTBUS_ERR;
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

    if (LnnGetFullStoragePath(LNN_FILE_ID_DB_KEY, dbKeyFilePath, SOFTBUS_MAX_PATH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get dbKey save path fail");
        return SOFTBUS_ERR;
    }
    do {
        if (!isUpdate && SoftBusAccessFile(dbKeyFilePath, SOFTBUS_F_OK) == SOFTBUS_OK) {
            LNN_LOGD(LNN_LEDGER, "dbKey file is exist");
            break;
        }
        if (LnnGenerateRandomByHuks(dbKey, len) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "generate random dbKey fail");
            return SOFTBUS_ERR;
        }
        if (EncryptStorageData(LNN_ENCRYPT_LEVEL_DE, dbKey, len) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "encrypt dbKey fail");
            return SOFTBUS_ERR;
        }
        if (SoftBusWriteFile(dbKeyFilePath, (char *)dbKey, len) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "write dbKey to file fail");
            return SOFTBUS_ERR;
        }
    } while (false);
    if (SoftBusReadFullFile(dbKeyFilePath, (char *)dbKey, len) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "read dbKey from file fail");
        return SOFTBUS_ERR;
    }
    if (DecryptStorageData(LNN_ENCRYPT_LEVEL_DE, dbKey, len) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "decrypt dbKey fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t EncryptDecisionDb(DbContext *ctx)
{
    uint8_t dbKey[LNN_DB_KEY_LEN] = {0};

    if (GetDecisionDbKey(dbKey, sizeof(dbKey), false) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get decision dbKey fail");
        (void)memset_s(dbKey, sizeof(dbKey), 0x0, sizeof(dbKey));
        return SOFTBUS_ERR;
    }
    if (EncryptedDb(ctx, dbKey, sizeof(dbKey)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "encrypt decision db fail");
        (void)memset_s(dbKey, sizeof(dbKey), 0x0, sizeof(dbKey));
        return SOFTBUS_ERR;
    }
    (void)memset_s(dbKey, sizeof(dbKey), 0x0, sizeof(dbKey));
    return SOFTBUS_OK;
}

static int32_t UpdateDecisionDbKey(DbContext *ctx)
{
    uint8_t dbKey[LNN_DB_KEY_LEN] = {0};

    if (LnnGenerateKeyByHuks(&g_keyAlias) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "update decision db de key fail");
        return SOFTBUS_ERR;
    }
    if (LnnGenerateCeKeyByHuks(&g_ceKeyAlias) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "update decision db ce key fail");
        return SOFTBUS_ERR;
    }
    if (GetDecisionDbKey(dbKey, sizeof(dbKey), true) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get decision dbKey fail");
        (void)memset_s(dbKey, sizeof(dbKey), 0x0, sizeof(dbKey));
        return SOFTBUS_ERR;
    }
    if (UpdateDbPassword(ctx, dbKey, sizeof(dbKey)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "encrypt decision db fail");
        (void)memset_s(dbKey, sizeof(dbKey), 0x0, sizeof(dbKey));
        return SOFTBUS_ERR;
    }
    LNN_LOGW(LNN_LEDGER, "update dbKey log for audit");
    (void)memset_s(dbKey, sizeof(dbKey), 0x0, sizeof(dbKey));
    return SOFTBUS_OK;
}

static int32_t BuildTrustedDevInfoRecord(const char *udid, TrustedDevInfoRecord *record)
{
    uint8_t accountHash[SHA_256_HASH_LEN] = {0};
    char accountHexHash[SHA_256_HEX_HASH_LEN] = {0};

    if (udid == NULL || record == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local account hash failed");
        return SOFTBUS_ERR;
    }
    if (memset_s(record, sizeof(TrustedDevInfoRecord), 0, sizeof(TrustedDevInfoRecord)) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memset_s record failed");
        return SOFTBUS_MEM_ERR;
    }
    if (ConvertBytesToHexString(accountHexHash, SHA_256_HEX_HASH_LEN, accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "convert accountHash failed");
        return SOFTBUS_ERR;
    }
    if (strcpy_s(record->accountHexHash, sizeof(record->accountHexHash), accountHexHash) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s account hash failed");
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(record->udid, sizeof(record->udid), udid) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s udid hash failed");
        return SOFTBUS_MEM_ERR;
    }
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
        LNN_LOGI(LNN_LEDGER, "insert udid to trusted dev info table. udid=%{public}s", anonyUdid);
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

    char *udid = (char *)param;
    if (udid == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return;
    }
    if (BuildTrustedDevInfoRecord(udid, &record) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "build remove trusted dev info record failed");
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
        if (RemoveRecordByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)&record) == SOFTBUS_OK) {
            (void)LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), CompleteUpdateTrustedDevInfo, NULL);
        }
    } while (false);
    if (CloseDatabase(ctx) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "close database failed");
    }
    DbUnlock();
    char *anonyUdid = NULL;
    Anonymize(udid, &anonyUdid);
    LNN_LOGI(LNN_LEDGER, "remove udid from trusted dev info table. udid=%{public}s", anonyUdid);
    AnonymizeFree(anonyUdid);
    SoftBusFree(udid);
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
            strcmp(item->infoRecord.udid, record->udid) == 0) {
            char *anonyUdid = NULL;
            Anonymize(record->udid, &anonyUdid);
            LNN_LOGI(LNN_LEDGER, "delete device db from list. udid=%{public}s", anonyUdid);
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
            strcmp(item->infoRecord.udid, record->udid) == 0) {
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
        return SOFTBUS_ERR;
    }
    if (LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), InsertTrustedDevInfoRecord,
        (void *)dupUdid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "async call insert trusted dev info failed");
        SoftBusFree(dupUdid);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnDeleteSpecificTrustedDevInfo(const char *udid)
{
    char *dupUdid = NULL;

    if (udid == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    TrustedDevInfoRecord record;
    int32_t ret = BuildTrustedDevInfoRecord(udid, &record);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "build delete trusted dev info record failed");
        return ret;
    }
    DeleteDeviceFromList(&record);
    dupUdid = (char *)SoftBusMalloc(UDID_BUF_LEN);
    if (dupUdid == NULL) {
        LNN_LOGE(LNN_LEDGER, "malloc dupUdid failed");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s(dupUdid, UDID_BUF_LEN, udid) != EOK) {
        LNN_LOGE(LNN_LEDGER, "strcpy_s dupUdid failed");
        SoftBusFree(dupUdid);
        return SOFTBUS_ERR;
    }
    if (LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), RemoveTrustedDevInfoRecord,
        (void *)dupUdid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "async call remove trusted dev info failed");
        SoftBusFree(dupUdid);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t GetTrustedDevInfoRecord(DbContext *ctx, const char *accountHexHash, char **udidArray, uint32_t *num)
{
    if (EncryptDecisionDb(ctx) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "encrypt database failed");
        *udidArray = NULL;
        *num = 0;
        return SOFTBUS_ERR;
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
    if (QueryRecordByKey(ctx, TABLE_TRUSTED_DEV_INFO, (uint8_t *)accountHexHash,
        (uint8_t **)udidArray, *((int32_t *)num)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "query udidArray failed");
        SoftBusFree(*udidArray);
        *udidArray = NULL;
        *num = 0;
        return SOFTBUS_ERR;
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
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t GetAllDevNums(char *accountHexHash, uint32_t *num)
{
    DeviceDbInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_deviceInfoList, DeviceDbInfo, node) {
        if (strcmp(accountHexHash, item->infoRecord.accountHexHash) == 0) {
            (*num)++;
        }
    }
    return SOFTBUS_OK;
}

int32_t LnnGetTrustedDevInfoFromDb(char **udidArray, uint32_t *num)
{
    char accountHexHash[SHA_256_HEX_HASH_LEN] = {0};
    if (udidArray == NULL || num == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (GetLocalAccountHexHash(accountHexHash) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local account hash failed");
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    if (DeviceDbListLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    int32_t ret = GetAllDevNums(accountHexHash, num);
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
        if (strcmp(accountHexHash, item->infoRecord.accountHexHash) != 0) {
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

static int32_t GetTrustedDevInfoFromDb(char **udidArray, uint32_t *num)
{
    char accountHexHash[SHA_256_HEX_HASH_LEN] = {0};
    DbContext *ctx = NULL;

    if (udidArray == NULL || num == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (GetLocalAccountHexHash(accountHexHash) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local account hash failed");
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    if (DbLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    if (OpenDatabase(&ctx) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "open database failed");
        DbUnlock();
        return SOFTBUS_ERR;
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
        return SOFTBUS_ERR;
    }
    DbUnlock();
    return rc;
}

static int32_t RecoveryTrustedDevInfo(void)
{
    uint32_t num = 0;
    char *udidArray = NULL;
    char accountHexHash[SHA_256_HEX_HASH_LEN] = {0};
    if (GetTrustedDevInfoFromDb(&udidArray, &num) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get trusted dev info fail");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    LNN_LOGI(LNN_LEDGER, "get trusted relation num=%{public}u", num);
    if (udidArray == NULL || num == 0) {
        LNN_LOGE(LNN_LEDGER, "get none trusted dev info");
        return SOFTBUS_OK;
    }
    if (GetLocalAccountHexHash(accountHexHash) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local account hash failed");
        SoftBusFree(udidArray);
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
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
            memcpy_s(info->infoRecord.accountHexHash, SHA_256_HEX_HASH_LEN, accountHexHash,
                SHA_256_HEX_HASH_LEN) != EOK) {
            LNN_LOGE(LNN_LEDGER, "udid str cpy fail.");
            DeviceDbListUnlock();
            SoftBusFree(info);
            SoftBusFree(udidArray);
            return SOFTBUS_MEM_ERR;
        }
        ListNodeInsert(&g_deviceInfoList, &info->node);
    }
    DeviceDbListUnlock();
    SoftBusFree(udidArray);
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
        return SOFTBUS_ERR;
    }
    ClearRecoveryDeviceList();
    return RecoveryTrustedDevInfo();
}

static int32_t InitTrustedDevInfoTable(void)
{
    bool isExist = false;
    int32_t rc = SOFTBUS_ERR;
    DbContext *ctx = NULL;

    if (OpenDatabase(&ctx) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "open database failed");
        return SOFTBUS_ERR;
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
        return SOFTBUS_ERR;
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
        return SOFTBUS_ERR;
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

int32_t LnnInitDecisionDbDelay(void)
{
    if (LnnGenerateKeyByHuks(&g_keyAlias) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "generate decision db huks de key fail");
        return SOFTBUS_ERR;
    }
    if (LnnGenerateCeKeyByHuks(&g_ceKeyAlias) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "update decision db huks ce key fail");
        return SOFTBUS_ERR;
    }
    if (InitTrustedDevInfoTable() != SOFTBUS_OK) {
        LNN_LOGI(LNN_LEDGER, "try init trusted dev info table again");
        return TryRecoveryTrustedDevInfoTable();
    }
    return SOFTBUS_OK;
}
