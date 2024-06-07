/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cstring>
#include <securec.h>
#include <string>

#include "lnn_kv_adapter_wrapper.h"
#include "lnn_device_info_recovery.h"
#include "lnn_kv_adapter.h"
#include "lnn_kv_data_change_listener.h"
#include "lnn_log.h"
#include "lnn_node_info.h"
#include "softbus_errcode.h"
#include "softbus_def.h"
#include "softbus_utils.h"
#include "iservice_registry.h"
#include "lnn_kv_store_launch_listener.h"
#include "system_ability_definition.h"

using namespace OHOS;
using namespace OHOS::DistributedKv;
namespace {
constexpr int32_t MIN_DBID_COUNT = 1;
constexpr int32_t MAX_STRING_LEN = 4096;
constexpr int32_t MIN_STRING_LEN = 1;
const std::string SEPARATOR = "#";
std::mutex g_kvAdapterWrapperMutex;
} // namespace

static int32_t g_dbId = 1;
static bool g_isSubscribed = false;
static std::map<int32_t, std::shared_ptr<OHOS::KVAdapter>> g_dbID2KvAdapter;
static void BasicCloudSyncInfoToMap(const CloudSyncInfo *localInfo, std::map<std::string, std::string> &values,
    const uint64_t &nowTime);
static void ComplexCloudSyncInfoToMap(const CloudSyncInfo *localInfo, std::map<std::string, std::string> &values,
    const uint64_t &nowTime);
static std::shared_ptr<OHOS::KVAdapter> FindKvStorePtr(int32_t &dbId);

int32_t LnnCreateKvAdapter(int32_t *dbId, const char *appId, int32_t appIdLen, const char *storeId, int32_t storeIdLen)
{
    if (dbId == nullptr || appId == nullptr || appIdLen < MIN_STRING_LEN || appIdLen > MAX_STRING_LEN ||
        storeId == nullptr || storeIdLen < MIN_STRING_LEN || storeIdLen > MAX_STRING_LEN) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        if (!g_dbID2KvAdapter.empty()) {
            *dbId = g_dbID2KvAdapter.begin()->first;
            LNN_LOGI(LNN_LEDGER, "kvAdapter is exist, dbId=%{public}d", *dbId);
            return SOFTBUS_OK;
        }
    }
    std::string appIdStr(appId, appIdLen);
    std::string storeIdStr(storeId, storeIdLen);
    std::shared_ptr<KVAdapter> kvAdapter = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        kvAdapter = std::make_shared<KVAdapter>(appIdStr, storeIdStr);
        int32_t initRet = kvAdapter->Init();
        if (initRet != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "kvAdapter init failed, ret=%{public}d", initRet);
            return initRet;
        }
        *dbId = g_dbId;
        g_dbID2KvAdapter.insert(std::make_pair(g_dbId, kvAdapter));
        g_dbId++;
    }
    LNN_LOGI(LNN_LEDGER, "kvAdapter init success, dbId=%{public}d", *dbId);
    return SOFTBUS_OK;
}

int32_t LnnDestroyKvAdapter(int32_t dbId)
{
    int32_t unInitRet;
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        if (dbId < MIN_DBID_COUNT || dbId >= g_dbId) {
            LNN_LOGE(LNN_LEDGER, "invalid param");
            return SOFTBUS_INVALID_PARAM;
        }
        auto kvAdapter = FindKvStorePtr(dbId);
        if (kvAdapter == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId=%{public}d", dbId);
            return SOFTBUS_NOT_FIND;
        }
        unInitRet = kvAdapter->DeInit();
    }
    if (unInitRet != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter unInit failed, ret=%{public}d", unInitRet);
        return unInitRet;
    }
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        g_dbID2KvAdapter.erase(dbId);
    }
    LNN_LOGI(LNN_LEDGER, "kvAdapter unInit success, dbId=%{public}d", dbId);
    return SOFTBUS_OK;
}

static std::shared_ptr<KVAdapter> FindKvStorePtr(int32_t &dbId)
{
    auto iter = g_dbID2KvAdapter.find(dbId);
    if (iter == g_dbID2KvAdapter.end()) {
        LNN_LOGE(LNN_LEDGER, "dbID is not exist, dbId=%{public}d", dbId);
        return nullptr;
    }
    return iter->second;
}

int32_t LnnPutDBData(int32_t dbId, const char *key, int32_t keyLen, const char *value, int32_t valueLen)
{
    int32_t putRet;
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        if (key == nullptr || keyLen < MIN_STRING_LEN || keyLen > MAX_STRING_LEN || value == nullptr ||
            valueLen < MIN_STRING_LEN || valueLen > MAX_STRING_LEN || dbId < MIN_DBID_COUNT || dbId >= g_dbId) {
            LNN_LOGE(LNN_LEDGER, "invalid param");
            return SOFTBUS_INVALID_PARAM;
        }
        std::string keyStr(key, keyLen);
        std::string valueStr(value, valueLen);
        auto kvAdapter = FindKvStorePtr(dbId);
        if (kvAdapter == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId=%{public}d", dbId);
            return SOFTBUS_NOT_FIND;
        }
        putRet = kvAdapter->Put(keyStr, valueStr);
    }
    if (putRet != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter put failed, ret=%{public}d", putRet);
        return putRet;
    }
    LNN_LOGI(LNN_LEDGER, "kvAdapter put success, dbId=%{public}d", dbId);
    return SOFTBUS_OK;
}

int32_t LnnDeleteDBData(int32_t dbId, const char *key, int32_t keyLen)
{
    int32_t deleteRet;
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        if (key == nullptr || keyLen < MIN_STRING_LEN || keyLen > MAX_STRING_LEN || dbId < MIN_DBID_COUNT ||
            dbId >= g_dbId) {
            LNN_LOGE(LNN_LEDGER, "invalid param");
            return SOFTBUS_INVALID_PARAM;
        }
        std::string keyStr(key, keyLen);
        auto kvAdapter = FindKvStorePtr(dbId);
        if (kvAdapter == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId=%{public}d", dbId);
            return SOFTBUS_NOT_FIND;
        }
        deleteRet = kvAdapter->Delete(keyStr);
    }
    if (deleteRet != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter delete failed, ret=%{public}d", deleteRet);
        return deleteRet;
    }
    LNN_LOGI(LNN_LEDGER, "kvAdapter delete success, dbId=%{public}d", dbId);
    return SOFTBUS_OK;
}

int32_t LnnGetDBData(int32_t dbId, const char *key, int32_t keyLen, char **value)
{
    std::string valueStr;
    int32_t getRet;
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        if (value == nullptr || key == nullptr || keyLen < MIN_STRING_LEN || keyLen > MAX_STRING_LEN ||
            dbId < MIN_DBID_COUNT || dbId >= g_dbId) {
            LNN_LOGE(LNN_LEDGER, "invalid param");
            return SOFTBUS_INVALID_PARAM;
        }
        std::string keyStr(key, keyLen);
        auto kvAdapter = FindKvStorePtr(dbId);
        if (kvAdapter == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId=%{public}d", dbId);
            return SOFTBUS_NOT_FIND;
        }
        getRet = kvAdapter->Get(keyStr, valueStr);
    }
    if (getRet != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter get failed, ret=%{public}d", getRet);
        return getRet;
    }
    *value = strdup(valueStr.c_str());
    if (*value == nullptr) {
        LNN_LOGE(LNN_LEDGER, "strdup failed");
        return SOFTBUS_MALLOC_ERR;
    }
    LNN_LOGD(LNN_LEDGER, "kvAdapter get success, dbId=%{public}d", dbId);
    return SOFTBUS_OK;
}

int32_t LnnDeleteDBDataByPrefix(int32_t dbId, const char *keyPrefix, int32_t keyPrefixLen)
{
    int32_t deleteRet;
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        if (keyPrefix == nullptr || keyPrefixLen < MIN_STRING_LEN || keyPrefixLen > MAX_STRING_LEN ||
            dbId < MIN_DBID_COUNT || dbId >= g_dbId) {
            LNN_LOGE(LNN_LEDGER, "invalid param");
            return SOFTBUS_INVALID_PARAM;
        }
        std::string keyPrefixStr(keyPrefix, keyPrefixLen);
        auto kvAdapter = FindKvStorePtr(dbId);
        if (kvAdapter == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId=%{public}d", dbId);
            return SOFTBUS_NOT_FIND;
        }
        deleteRet = kvAdapter->DeleteByPrefix(keyPrefixStr);
    }
    if (deleteRet != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter delete failed, ret=%{public}d", deleteRet);
        return deleteRet;
    }
    LNN_LOGI(LNN_LEDGER, "kvAdapter delete success, dbId=%{public}d", dbId);
    return SOFTBUS_OK;
}

int32_t LnnPutDBDataBatch(int32_t dbId, const CloudSyncInfo *localInfo)
{
    int32_t putBatchRet;
    {
        LNN_LOGI(LNN_LEDGER, "call");
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        if (localInfo == nullptr || dbId < MIN_DBID_COUNT || dbId >= g_dbId) {
            LNN_LOGE(LNN_LEDGER, "invalid param, dbId=%{public}d", dbId);
            return SOFTBUS_INVALID_PARAM;
        }
        std::map<std::string, std::string> values;
        auto kvAdapter = FindKvStorePtr(dbId);
        if (kvAdapter == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId=%{public}d", dbId);
            return SOFTBUS_NOT_FIND;
        }
        uint64_t nowTime = SoftBusGetSysTimeMs();
        BasicCloudSyncInfoToMap(localInfo, values, nowTime);
        ComplexCloudSyncInfoToMap(localInfo, values, nowTime);
        putBatchRet = kvAdapter->PutBatch(values);
        values.clear();
    }
    if (putBatchRet != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter putBatch failed, ret=%{public}d", putBatchRet);
        return putBatchRet;
    }
    LNN_LOGI(LNN_LEDGER, "kvAdapter putBatch success, dbId=%{public}d", dbId);
    return SOFTBUS_OK;
}

int32_t LnnCloudSync(int32_t dbId)
{
    std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
    if (dbId < MIN_DBID_COUNT || dbId >= g_dbId) {
        LNN_LOGI(LNN_LEDGER, "Invalid dbId ");
        return SOFTBUS_INVALID_PARAM;
    }
    auto kvAdapter = FindKvStorePtr(dbId);
    if (kvAdapter == nullptr) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId=%{public}d", dbId);
        return SOFTBUS_NOT_FIND;
    }
    return (kvAdapter->CloudSync());
}

static void BasicCloudSyncInfoToMap(const CloudSyncInfo *localInfo, std::map<std::string, std::string> &values,
    const uint64_t &nowTime)
{
    if (localInfo == nullptr) {
        LNN_LOGE(LNN_LEDGER, "localInfo is null");
        return;
    }
    std::string keyPrefix = std::to_string(localInfo->accountId) + SEPARATOR + localInfo->deviceUdid + SEPARATOR;
    std::string stateVersionStr = SEPARATOR + std::to_string(localInfo->stateVersion);
    std::string nowTimeStr = SEPARATOR + std::to_string(nowTime);
    std::string valueSuffix = stateVersionStr + nowTimeStr;

    values[keyPrefix + DEVICE_INFO_NETWORK_ID] = localInfo->networkId + valueSuffix;
    values[keyPrefix + DEVICE_INFO_DEVICE_NAME] = localInfo->deviceName + valueSuffix;
    values[keyPrefix + DEVICE_INFO_UNIFIED_DEVICE_NAME] = localInfo->unifiedName + valueSuffix;
    values[keyPrefix + DEVICE_INFO_UNIFIED_DEFAULT_DEVICE_NAME] = localInfo->unifiedDefaultName + valueSuffix;
    values[keyPrefix + DEVICE_INFO_SETTINGS_NICK_NAME] = localInfo->nickName + valueSuffix;
    values[keyPrefix + DEVICE_INFO_DEVICE_TYPE] = std::to_string(localInfo->deviceTypeId) + valueSuffix;
    values[keyPrefix + DEVICE_INFO_DEVICE_UDID] = localInfo->deviceUdid + valueSuffix;
    values[keyPrefix + DEVICE_INFO_DEVICE_UUID] = localInfo->uuid + valueSuffix;
    values[keyPrefix + DEVICE_INFO_SW_VERSION] = localInfo->softBusVersion + valueSuffix;
    values[keyPrefix + DEVICE_INFO_BLE_P2P] = (localInfo->isBleP2p ? "true" : "false") + valueSuffix;
    values[keyPrefix + DEVICE_INFO_TRANSPORT_PROTOCOL] =
        std::to_string(localInfo->supportedProtocols) + valueSuffix;
    values[keyPrefix + DEVICE_INFO_PKG_VERSION] = localInfo->pkgVersion + valueSuffix;
    values[keyPrefix + DEVICE_INFO_WIFI_VERSION] = std::to_string(localInfo->wifiVersion) + valueSuffix;
    values[keyPrefix + DEVICE_INFO_BLE_VERSION] = std::to_string(localInfo->bleVersion) + valueSuffix;
    values[keyPrefix + DEVICE_INFO_BT_MAC] = localInfo->macAddr + valueSuffix;
    values[keyPrefix + DEVICE_INFO_ACCOUNT_ID] = std::to_string(localInfo->accountId) + valueSuffix;
    values[keyPrefix + DEVICE_INFO_FEATURE] = std::to_string(localInfo->feature) + valueSuffix;
    values[keyPrefix + DEVICE_INFO_CONN_SUB_FEATURE] = std::to_string(localInfo->connSubFeature) + valueSuffix;
    values[keyPrefix + DEVICE_INFO_AUTH_CAP] = std::to_string(localInfo->authCapacity) + valueSuffix;
    values[keyPrefix + DEVICE_INFO_OS_TYPE] = std::to_string(localInfo->osType) + valueSuffix;
    values[keyPrefix + DEVICE_INFO_OS_VERSION] = localInfo->osVersion + valueSuffix;
    values[keyPrefix + DEVICE_INFO_STATE_VERSION] = std::to_string(localInfo->stateVersion) + valueSuffix;
    values[keyPrefix + DEVICE_INFO_P2P_MAC_ADDR] = localInfo->p2pMac + valueSuffix;
}

static int32_t CipherAndRpaInfoToMap(const CloudSyncInfo *localInfo, std::map<std::string, std::string> &values,
    const std::string &keyPrefix, const std::string &valueSuffix)
{
    char cipherKey[SESSION_KEY_STR_LEN] = { 0 };
    char cipherIv[BROADCAST_IV_STR_LEN] = { 0 };
    char peerIrk[LFINDER_IRK_STR_LEN] = { 0 };
    char pubMac[LFINDER_MAC_ADDR_STR_LEN] = { 0 };
    if (ConvertBytesToHexString(cipherKey, SESSION_KEY_STR_LEN, localInfo->cipherKey, SESSION_KEY_LENGTH) !=
        SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "convert cipherkey to string fail.");
        return SOFTBUS_KV_CONVERT_STRING_FAILED;
    }
    if (ConvertBytesToHexString(cipherIv, BROADCAST_IV_STR_LEN, localInfo->cipherIv, BROADCAST_IV_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "convert cipheriv to string fail.");
        (void)memset_s(cipherKey, SESSION_KEY_STR_LEN, 0, SESSION_KEY_STR_LEN);
        return SOFTBUS_KV_CONVERT_STRING_FAILED;
    }
    if (ConvertBytesToHexString(peerIrk, LFINDER_IRK_STR_LEN, localInfo->peerIrk, LFINDER_IRK_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "convert peerIrk to string fail.");
        (void)memset_s(cipherKey, SESSION_KEY_STR_LEN, 0, SESSION_KEY_STR_LEN);
        (void)memset_s(cipherIv, BROADCAST_IV_STR_LEN, 0, BROADCAST_IV_STR_LEN);
        return SOFTBUS_KV_CONVERT_STRING_FAILED;
    }
    if (ConvertBytesToHexString(pubMac, LFINDER_MAC_ADDR_STR_LEN, localInfo->publicAddress, LFINDER_MAC_ADDR_LEN) !=
        SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "convert publicAddress to string fail.");
        (void)memset_s(cipherKey, SESSION_KEY_STR_LEN, 0, SESSION_KEY_STR_LEN);
        (void)memset_s(cipherIv, BROADCAST_IV_STR_LEN, 0, BROADCAST_IV_STR_LEN);
        (void)memset_s(peerIrk, LFINDER_IRK_STR_LEN, 0, LFINDER_IRK_STR_LEN);
        return SOFTBUS_KV_CONVERT_STRING_FAILED;
    }
    values[keyPrefix + DEVICE_INFO_DEVICE_IRK] = peerIrk + valueSuffix;
    values[keyPrefix + DEVICE_INFO_DEVICE_PUB_MAC] = pubMac + valueSuffix;
    values[keyPrefix + DEVICE_INFO_BROADCAST_CIPHER_KEY] = cipherKey + valueSuffix;
    values[keyPrefix + DEVICE_INFO_BROADCAST_CIPHER_IV] = cipherIv + valueSuffix;
    (void)memset_s(cipherKey, SESSION_KEY_STR_LEN, 0, SESSION_KEY_STR_LEN);
    (void)memset_s(cipherIv, BROADCAST_IV_STR_LEN, 0, BROADCAST_IV_STR_LEN);
    (void)memset_s(peerIrk, LFINDER_IRK_STR_LEN, 0, LFINDER_IRK_STR_LEN);
    return SOFTBUS_OK;
}

static void ComplexCloudSyncInfoToMap(const CloudSyncInfo *localInfo, std::map<std::string, std::string> &values,
    const uint64_t &nowTime)
{
    if (localInfo == nullptr) {
        LNN_LOGE(LNN_LEDGER, "localInfo is null");
        return;
    }
    std::string keyPrefix = std::to_string(localInfo->accountId) + SEPARATOR + localInfo->deviceUdid + SEPARATOR;
    std::string stateVersionStr = SEPARATOR + std::to_string(localInfo->stateVersion);
    std::string nowTimeStr = SEPARATOR + std::to_string(nowTime);
    std::string valueSuffix = stateVersionStr + nowTimeStr;

    char remotePtkStr[PTK_DEFAULT_LEN + 1] = {0};
    for (int32_t i = 0; i < PTK_DEFAULT_LEN; i++) {
        remotePtkStr[i] = static_cast<char>(localInfo->remotePtk[i]);
    }
    values[keyPrefix + DEVICE_INFO_PTK] = remotePtkStr + valueSuffix;
    values[keyPrefix + DEVICE_INFO_JSON_BROADCAST_KEY_TABLE] = localInfo->broadcastCipherKey + valueSuffix;
    values[keyPrefix + DEVICE_INFO_JSON_KEY_TOTAL_LIFE] = std::to_string(localInfo->lifeTotal) + valueSuffix;
    values[keyPrefix + DEVICE_INFO_JSON_KEY_TIMESTAMP_BEGIN] =
        std::to_string(localInfo->curBeginTime) + valueSuffix;
    values[keyPrefix + DEVICE_INFO_JSON_KEY_CURRENT_INDEX] = std::to_string(localInfo->currentIndex) + valueSuffix;
    values[keyPrefix + DEVICE_INFO_DISTRIBUTED_SWITCH] =
        (localInfo->distributedSwitch ? "true" : "false") + valueSuffix;
    if (CipherAndRpaInfoToMap(localInfo, values, keyPrefix, valueSuffix) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "convert cipher and rpa info to map fail");
    }
}

void LnnRegisterDataChangeListener(int32_t dbId, const char *appId, int32_t appIdLen, const char *storeId,
    int32_t storeIdLen)
{
    std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
    if (dbId < MIN_DBID_COUNT || dbId >= g_dbId || appId == nullptr || appIdLen < MIN_STRING_LEN ||
    appIdLen > MAX_STRING_LEN || storeId == nullptr || storeIdLen < MIN_STRING_LEN ||
    storeIdLen > MAX_STRING_LEN) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return;
    }
    if (g_isSubscribed) {
        LNN_LOGI(LNN_LEDGER, "DataChangeListener is already registered");
        return;
    }
    std::string appIdStr(appId, appIdLen);
    std::string storeIdStr(storeId, storeIdLen);
    auto kvAdapter = FindKvStorePtr(dbId);
    if (kvAdapter == nullptr) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId=%{public}d", dbId);
        return;
    }
    int32_t status = kvAdapter->RegisterDataChangeListener(std::make_shared<KvDataChangeListener>(appIdStr,
        storeIdStr));
    if (status != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "RegisterDataChangeListener failed");
        return;
    }
    g_isSubscribed = true;
    LNN_LOGI(LNN_LEDGER, "RegisterDataChangeListener success");
}

void LnnUnRegisterDataChangeListener(int32_t dbId)
{
    std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
    if (dbId < MIN_DBID_COUNT || dbId >= g_dbId) {
        LNN_LOGI(LNN_LEDGER, "Invalid dbId ");
        return;
    }
    auto kvAdapter = FindKvStorePtr(dbId);
    if (kvAdapter == nullptr) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId=%{public}d", dbId);
        return;
    }
    if (kvAdapter->DeRegisterDataChangeListener() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "DeRegisterDataChangeListener failed");
        return;
    }
    g_isSubscribed = false;
    LNN_LOGI(LNN_LEDGER, "DeRegisterDataChangeListener success");
}

void LnnClearRedundancyCache(void)
{
    KvDataChangeListener::ClearCache();
}

bool LnnSubcribeKvStoreService(void)
{
    auto abilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (abilityManager == nullptr) {
        LNN_LOGE(LNN_LEDGER, "abilityManager is nullptr");
        return false;
    }
    auto listener = new (std::nothrow) KvStoreStatusChangeListener();
    if (listener == nullptr) {
        LNN_LOGE(LNN_LEDGER, "failed to create listener");
        return false;
    }
    int32_t ret = abilityManager->SubscribeSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, listener);
    if (ret != ERR_OK) {
        LNN_LOGE(LNN_LEDGER, "subscribe system ability failed, ret=%{public}d", ret);
        return false;
    }
    LNN_LOGI(LNN_LEDGER, "subscribe kv store service success");
    return true;
}
