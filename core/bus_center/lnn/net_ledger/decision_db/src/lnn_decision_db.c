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
#include "bus_center_manager.h"
#include "lnn_async_callback_utils.h"
#include "lnn_file_utils.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_huks_utils.h"
#include "lnn_log.h"
#include "sqlite3_utils.h"

#include "softbus_adapter_file.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"

#define LNN_DB_KEY_LEN 1024
#define LNN_DB_KEY_AILAS "dsoftbus_decision_db_key_alias"

static struct HksBlob g_keyAlias = {sizeof(LNN_DB_KEY_AILAS), (uint8_t *)LNN_DB_KEY_AILAS};

int32_t EncryptStorageData(uint8_t *dbKey, uint32_t len)
{
    struct HksBlob plainData = {0};
    struct HksBlob encryptData = {0};

    encryptData.data = (uint8_t *)SoftBusCalloc(len);
    if (encryptData.data == NULL) {
        LNN_LOGE(LNN_LEDGER, "calloc encrypt dbKey fail");
        return SOFTBUS_MEM_ERR;
    }
    LNN_LOGI(LNN_LEDGER, "Encrypt, data len=%{public}u", len);
    plainData.size = len;
    plainData.data = dbKey;
    if (LnnEncryptDataByHuks(&g_keyAlias, &plainData, &encryptData) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "encrypt dbKey by huks fail");
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

int32_t DecryptStorageData(uint8_t *dbKey, uint32_t len)
{
    struct HksBlob encryptData = {0};
    struct HksBlob decryptData = {0};

    decryptData.data = (uint8_t *)SoftBusCalloc(len);
    if (decryptData.data == NULL) {
        LNN_LOGE(LNN_LEDGER, "calloc decrypt dbKey fail");
        return SOFTBUS_MEM_ERR;
    }
    encryptData.size = len;
    encryptData.data = dbKey;
    int32_t ret;
    do {
        if (LnnDecryptDataByHuks(&g_keyAlias, &encryptData, &decryptData) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "decrypt dbKey by huks fail");
            ret = SOFTBUS_ERR;
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
    char dbKeyFilePath[SOFTBUS_MAX_PATH_LEN];

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
        if (EncryptStorageData(dbKey, len) != SOFTBUS_OK) {
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
    if (DecryptStorageData(dbKey, len) != SOFTBUS_OK) {
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
        LNN_LOGE(LNN_LEDGER, "update decision db root key fail");
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
    if (OpenDatabase(&ctx) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "open database failed");
        SoftBusFree(udid);
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
        SoftBusFree(udid);
        return;
    }
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
    if (OpenDatabase(&ctx) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "open database failed");
        SoftBusFree(udid);
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
    char *anonyUdid = NULL;
    Anonymize(udid, &anonyUdid);
    LNN_LOGI(LNN_LEDGER, "remove udid from trusted dev info table. udid=%{public}s", anonyUdid);
    AnonymizeFree(anonyUdid);
    SoftBusFree(udid);
}

int32_t LnnInsertSpecificTrustedDevInfo(const char *udid)
{
    char *dupUdid = NULL;

    if (udid == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
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

static int32_t GetTrustedDevInfoRecord(DbContext *ctx, const char *accountHexHash,
    char **udidArray, uint32_t *num)
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

int32_t LnnGetTrustedDevInfoFromDb(char **udidArray, uint32_t *num)
{
    uint8_t accountHash[SHA_256_HASH_LEN] = {0};
    char accountHexHash[SHA_256_HEX_HASH_LEN] = {0};
    DbContext *ctx = NULL;

    if (udidArray == NULL || num == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get local account hash failed");
        return SOFTBUS_ERR;
    }
    if (ConvertBytesToHexString(accountHexHash, SHA_256_HEX_HASH_LEN, accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "convert accountHash failed");
        return SOFTBUS_ERR;
    }
    if (OpenDatabase(&ctx) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "open database failed");
        return SOFTBUS_ERR;
    }
    int32_t rc = GetTrustedDevInfoRecord(ctx, accountHexHash, udidArray, num);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get trusted dev info failed");
    }
    if (CloseDatabase(ctx) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "close database failed");
        SoftBusFree(*udidArray);
        *udidArray = NULL;
        *num = 0;
        return SOFTBUS_ERR;
    }
    return rc;
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
    return rc;
}

static int32_t TryRecoveryTrustedDevInfoTable(void)
{
    char dbKeyFilePath[SOFTBUS_MAX_PATH_LEN];

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

int32_t LnnInitDecisionDbDelay(void)
{
    if (LnnGenerateKeyByHuks(&g_keyAlias) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "generate decision db huks key fail");
        return SOFTBUS_ERR;
    }
    if (InitTrustedDevInfoTable() != SOFTBUS_OK) {
        LNN_LOGI(LNN_LEDGER, "try init trusted dev info table again");
        return TryRecoveryTrustedDevInfoTable();
    }
    return SOFTBUS_OK;
}
