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

#include <string>
#include <cstring>
#include "lnn_kv_adapter_wrapper.h"
#include "lnn_log.h"
#include "softbus_errcode.h"
#include "lnn_kv_adapter.h"
#include "lnn_kv_data_change_listener.h"
#include "lnn_device_info_recovery.h"

using namespace OHOS;
using namespace OHOS::DistributedKv;
namespace {
constexpr int32_t MIN_DBID_COUNT = 1;
constexpr int32_t MAX_STRING_LEN = 4096;
constexpr int32_t MIN_STRING_LEN = 1;
const std::string SEPARATOR = "#";
std::mutex g_kvAdapterWrapperMutex;
}

static int32_t g_dbId = 1;
static std::map<int32_t, std::shared_ptr<OHOS::KVAdapter>> g_dbID2KvAdapter;
void BasicCloudSyncInfoToMap(const CloudSyncInfo *localInfo, std::map<std::string, std::string>& values);
void ComplexCloudSyncInfoToMap(const CloudSyncInfo *localInfo, std::map<std::string, std::string>& values);
std::shared_ptr<OHOS::KVAdapter> FindKvStorePtr(int32_t& dbId);

int32_t LnnCreateKvAdapter(int32_t *dbId, const char *appId, int32_t appIdLen, const char *storeId,
    int32_t storeIdLen)
{
    if (dbId == nullptr || appId == nullptr || appIdLen < MIN_STRING_LEN || appIdLen > MAX_STRING_LEN ||
        storeId == nullptr || storeIdLen < MIN_STRING_LEN || storeIdLen > MAX_STRING_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    std::string appIdStr(appId, appIdLen);
    std::string storeIdStr(storeId, storeIdLen);
    std::shared_ptr<KVAdapter> kvAdapter = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        kvAdapter = std::make_shared<KVAdapter>(appIdStr, storeIdStr,
            std::make_shared<KvDataChangeListener>());
        int32_t initRet = kvAdapter->Init();
        if (initRet != SOFTBUS_OK) {
            LNN_LOGE(LNN_LEDGER, "kvAdapter init failed, ret = %{public}d", initRet);
            return initRet;
        }
        *dbId = g_dbId;
        g_dbID2KvAdapter.insert(std::make_pair(g_dbId, kvAdapter));
        g_dbId++;
    }
    LNN_LOGI(LNN_LEDGER, "kvAdapter init success, dbId = %{public}d", *dbId);
    return SOFTBUS_OK;
}

int32_t LnnDestroyKvAdapter(int32_t dbId)
{
    int32_t unInitRet;
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        if (dbId < MIN_DBID_COUNT || dbId >= g_dbId) {
            return SOFTBUS_INVALID_PARAM;
        }
        auto kvAdapter = FindKvStorePtr(dbId);
        if (kvAdapter == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId = %{public}d", dbId);
            return SOFTBUS_NOT_FIND;
        }
        unInitRet = kvAdapter->DeInit();
    }
    if (unInitRet != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter unInit failed, ret = %{public}d", unInitRet);
        return unInitRet;
    }
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        g_dbID2KvAdapter.erase(dbId);
    }
    LNN_LOGI(LNN_LEDGER, "kvAdapter unInit success, dbId = %{public}d", dbId);
    return SOFTBUS_OK;
}

std::shared_ptr<KVAdapter> FindKvStorePtr(int32_t &dbId)
{
    auto iter = g_dbID2KvAdapter.find(dbId);
    if (iter == g_dbID2KvAdapter.end()) {
        LNN_LOGE(LNN_LEDGER, "dbID is not exist, dbId = %{public}d", dbId);
        return nullptr;
    }
    return iter->second;
}

int32_t LnnPutDBData(int32_t dbId, const char *key, int32_t keyLen, const char *value, int32_t valueLen)
{
    int32_t putRet;
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        if (key == nullptr || keyLen < MIN_STRING_LEN || keyLen > MAX_STRING_LEN ||
            value == nullptr || valueLen < MIN_STRING_LEN || valueLen > MAX_STRING_LEN ||
            dbId < MIN_DBID_COUNT || dbId >= g_dbId) {
            return SOFTBUS_INVALID_PARAM;
        }
        std::string keyStr(key, keyLen);
        std::string valueStr(value, valueLen);
        auto kvAdapter = FindKvStorePtr(dbId);
        if (kvAdapter == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId = %{public}d", dbId);
            return SOFTBUS_NOT_FIND;
        }
        putRet = kvAdapter->Put(keyStr, valueStr);
    }
    if (putRet != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter put failed, ret = %{public}d", putRet);
        return putRet;
    }
    LNN_LOGI(LNN_LEDGER, "kvAdapter put success, dbId = %{public}d", dbId);
    return SOFTBUS_OK;
}

int32_t LnnDeleteDBData(int32_t dbId, const char *key, int32_t keyLen)
{
    int32_t deleteRet;
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        if (key == nullptr || keyLen < MIN_STRING_LEN || keyLen > MAX_STRING_LEN ||
            dbId < MIN_DBID_COUNT || dbId >= g_dbId) {
            return SOFTBUS_INVALID_PARAM;
        }
        std::string keyStr(key, keyLen);
        auto kvAdapter = FindKvStorePtr(dbId);
        if (kvAdapter == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId = %{public}d", dbId);
            return SOFTBUS_NOT_FIND;
        }
        deleteRet = kvAdapter->Delete(keyStr);
    }
    if (deleteRet != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter delete failed, ret = %{public}d", deleteRet);
        return deleteRet;
    }
    LNN_LOGI(LNN_LEDGER, "kvAdapter delete success, dbId = %{public}d", dbId);
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
            return SOFTBUS_INVALID_PARAM;
        }
        std::string keyStr(key, keyLen);
        auto kvAdapter = FindKvStorePtr(dbId);
        if (kvAdapter == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId = %{public}d", dbId);
            return SOFTBUS_NOT_FIND;
        }
        getRet = kvAdapter->Get(keyStr, valueStr);
    }
    if (getRet != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter get failed, ret = %{public}d", getRet);
        return getRet;
    }
    *value = strdup(valueStr.c_str());
    if (*value == nullptr) {
        LNN_LOGE(LNN_LEDGER, "strdup failed");
        return SOFTBUS_MALLOC_ERR;
    }
    LNN_LOGI(LNN_LEDGER, "kvAdapter get success, dbId = %{public}d", dbId);
    return SOFTBUS_OK;
}

int32_t LnnDeleteDBDataByPrefix(int32_t dbId, const char *keyPrefix, int32_t keyPrefixLen)
{
    int32_t deleteRet;
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        if (keyPrefix == nullptr || keyPrefixLen < MIN_STRING_LEN || keyPrefixLen > MAX_STRING_LEN ||
            dbId < MIN_DBID_COUNT || dbId >= g_dbId) {
            return SOFTBUS_INVALID_PARAM;
        }
        std::string keyPrefixStr(keyPrefix, keyPrefixLen);
        auto kvAdapter = FindKvStorePtr(dbId);
        if (kvAdapter == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId = %{public}d", dbId);
            return SOFTBUS_NOT_FIND;
        }
        deleteRet = kvAdapter->DeleteByPrefix(keyPrefixStr);
    }
    if (deleteRet != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter delete failed, ret = %{public}d", deleteRet);
        return deleteRet;
    }
    LNN_LOGI(LNN_LEDGER, "kvAdapter delete success, dbId = %{public}d", dbId);
    return SOFTBUS_OK;
}

int32_t LnnPutDBDataBatch(int32_t dbId, const CloudSyncInfo *localInfo)
{
    int32_t putBatchRet;
    {
        std::lock_guard<std::mutex> lock(g_kvAdapterWrapperMutex);
        if (localInfo == nullptr || dbId < MIN_DBID_COUNT || dbId >= g_dbId) {
            return SOFTBUS_INVALID_PARAM;
        }
        std::map<std::string, std::string> values;
        BasicCloudSyncInfoToMap(localInfo, values);
        ComplexCloudSyncInfoToMap(localInfo, values);
        auto kvAdapter = FindKvStorePtr(dbId);
        if (kvAdapter == nullptr) {
            LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId = %{public}d", dbId);
            return SOFTBUS_NOT_FIND;
        }
        putBatchRet = kvAdapter->PutBatch(values);
    }
    if (putBatchRet != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "kvAdapter putBatch failed, ret = %{public}d", putBatchRet);
        return putBatchRet;
    }
    LNN_LOGI(LNN_LEDGER, "kvAdapter putBatch success, dbId = %{public}d", dbId);
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
        LNN_LOGE(LNN_LEDGER, "kvAdapter is not exist, dbId = %{public}d", dbId);
        return SOFTBUS_NOT_FIND;
    }
    return (kvAdapter->CloudSync());
}

void BasicCloudSyncInfoToMap(const CloudSyncInfo *localInfo, std::map<std::string, std::string>& values)
{
    if (localInfo == nullptr) {
        LNN_LOGE(LNN_LEDGER, "localInfo is null");
        return;
    }
    std::string keyPrefix = std::to_string(localInfo->accountId) + SEPARATOR + localInfo->deviceUdid + SEPARATOR;
    std::string stateVersionStr = SEPARATOR + std::to_string(localInfo->stateVersion);

    values[keyPrefix + DEVICE_INFO_NETWORK_ID] = localInfo->networkId + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_DEVICE_NAME] = localInfo->deviceName + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_UNIFIED_DEVICE_NAME] = localInfo->unifiedName + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_UNIFIED_DEFAULT_DEVICE_NAME] = localInfo->unifiedDefaultName + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_SETTINGS_NICK_NAME] = localInfo->nickName + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_DEVICE_TYPE] = std::to_string(localInfo->deviceTypeId) + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_DEVICE_UDID] = localInfo->deviceUdid + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_DEVICE_UUID] = localInfo->uuid + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_SW_VERSION] = localInfo->softBusVersion + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_BLE_P2P] = (localInfo->isBleP2p ? "true" : "false") + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_TRANSPORT_PROTOCOL] = std::to_string(localInfo->supportedProtocols) +
        stateVersionStr;
    values[keyPrefix + DEVICE_INFO_PKG_VERSION] = localInfo->pkgVersion + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_WIFI_VERSION] = std::to_string(localInfo->wifiVersion) + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_BLE_VERSION] = std::to_string(localInfo->bleVersion) + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_BT_MAC] = localInfo->macAddr + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_ACCOUNT_ID] = std::to_string(localInfo->accountId) + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_FEATURE] = std::to_string(localInfo->feature) + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_CONN_SUB_FEATURE] = std::to_string(localInfo->connSubFeature) + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_AUTH_CAP] = std::to_string(localInfo->authCapacity) + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_OS_TYPE] = std::to_string(localInfo->osType) + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_OS_VERSION] = localInfo->osVersion + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_STATE_VERSION] = std::to_string(localInfo->stateVersion) + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_P2P_MAC_ADDR] = localInfo->p2pMac + stateVersionStr;
}

void ComplexCloudSyncInfoToMap(const CloudSyncInfo *localInfo, std::map<std::string, std::string>& values)
{
    if (localInfo == nullptr) {
        LNN_LOGE(LNN_LEDGER, "localInfo is null");
        return;
    }
    std::string keyPrefix = std::to_string(localInfo->accountId) + SEPARATOR + localInfo->deviceUdid + SEPARATOR;
    std::string stateVersionStr = SEPARATOR + std::to_string(localInfo->stateVersion);

    char peerIrkStr[LFINDER_IRK_LEN];
    for (int32_t i = 0; i < LFINDER_IRK_LEN; i++) {
        peerIrkStr[i] = static_cast<char>(localInfo->peerIrk[i]);
    }
    values[keyPrefix + DEVICE_INFO_DEVICE_IRK] = peerIrkStr + stateVersionStr;
    char publicAddressStr[LFINDER_MAC_ADDR_LEN];
    for (int32_t i = 0; i < LFINDER_MAC_ADDR_LEN; i++) {
        publicAddressStr[i] = static_cast<char>(localInfo->publicAddress[i]);
    }
    values[keyPrefix + DEVICE_INFO_DEVICE_PUB_MAC] = publicAddressStr + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_PTK] = localInfo->remotePtk + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_JSON_KEY_TABLE_MIAN] = localInfo->tableMain + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_JSON_KEY_TOTAL_LIFE] = std::to_string(localInfo->lifeTotal) + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_JSON_KEY_TIMESTAMP_BEGIN] = std::to_string(localInfo->curBeginTime) +
        stateVersionStr;
    values[keyPrefix + DEVICE_INFO_JSON_KEY_CURRENT_INDEX] = std::to_string(localInfo->currentIndex) + stateVersionStr;
    char cipherKeyStr[SESSION_KEY_LENGTH];
    for (int32_t i = 0; i < SESSION_KEY_LENGTH; i++) {
        cipherKeyStr[i] = static_cast<char>(localInfo->cipherKey[i]);
    }
    values[keyPrefix + DEVICE_INFO_BROADCAST_CIPHER_KEY] = cipherKeyStr + stateVersionStr;
    char cipherIvStr[BROADCAST_IV_LEN];
    for (int32_t i = 0; i < BROADCAST_IV_LEN; i++) {
        cipherIvStr[i] = static_cast<char>(localInfo->cipherIv[i]);
    }
    values[keyPrefix + DEVICE_INFO_BROADCAST_CIPHER_IV] = cipherIvStr + stateVersionStr;
    values[keyPrefix + DEVICE_INFO_DISTRIBUTED_SWITCH] = (localInfo->distributedSwitch ? "true" : "false") +
        stateVersionStr;
}
