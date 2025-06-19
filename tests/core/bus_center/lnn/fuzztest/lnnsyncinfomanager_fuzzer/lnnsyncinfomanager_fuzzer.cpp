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

#include <cstddef>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>

#include "cJSON.h"
#include "comm_log.h"
#include "lnn_node_info_struct.h"
#include "lnn_sync_info_manager.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_common.h"
#include "softbus_json_utils.h"

#define JSON_KEY_BATTERY_LEAVEL  "BatteryLeavel"
#define JSON_KEY_IS_CHARGING     "IsCharging"
#define JSON_KEY_MASTER_UDID     "MasterUdid"
#define JSON_KEY_MASTER_WEIGHT   "MasterWeight"
#define JSON_KEY_P2P_ROLE        "P2P_ROLE"
#define JSON_KEY_WIFI_CFG        "WIFI_CFG"
#define JSON_KEY_CHAN_LIST_5G    "CHAN_LIST_5G"
#define JSON_KEY_STA_FREQUENCY   "STA_FREQUENCY"
#define JSON_KEY_P2P_MAC         "P2P_MAC"
#define JSON_KEY_GO_MAC          "GO_MAC"
#define JSON_KEY_WIFIDIRECT_ADDR "WIFIDIRECT_ADDR"
#define JSON_KEY_SLE_MAC         "SLE_MAC"
#define JSON_KEY_SLE_CAP         "SLE_CAP"
#define DISCOVERY_TYPE_MASK      0x7FFF
#define MSG_LEN                  10
#define BITS                     8
#define BITLEN                   4
#define WIFI_CFG_INFO_MAX_LEN    512
#define CHANNEL_LIST_STR_LEN     256
#define MAC_LEN         18
#define CONN_CODE_SHIFT 16

using namespace std;
namespace OHOS {
static char *ProcessSendBatteryInfo(FuzzedDataProvider &dataProvider)
{
    cJSON *json = cJSON_CreateObject();
    if (json == nullptr) {
        COMM_LOGE(COMM_TEST, "create json fail");
        return nullptr;
    }
    int32_t level = dataProvider.ConsumeIntegral<int32_t>();
    bool isCharging = dataProvider.ConsumeBool();
    if (!AddNumberToJsonObject(json, JSON_KEY_BATTERY_LEAVEL, level) ||
        !AddBoolToJsonObject(json, JSON_KEY_IS_CHARGING, isCharging)) {
        COMM_LOGE(COMM_TEST, "add json object failed!");
        cJSON_Delete(json);
        return nullptr;
    }
    char *data = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (data == nullptr) {
        COMM_LOGE(COMM_TEST, "json transform unformatted failed!");
        return nullptr;
    }
    return data;
}

static char *ProcessSendMasterSelectMsg(FuzzedDataProvider &dataProvider)
{
    cJSON *json = cJSON_CreateObject();
    if (json == nullptr) {
        COMM_LOGE(COMM_TEST, "create json fail");
        return nullptr;
    }
    char masterUdid[NETWORK_ID_BUF_LEN] = { 0 };
    string udidStr = dataProvider.ConsumeBytesAsString(UDID_BUF_LEN - 1);
    int32_t masterWeight = dataProvider.ConsumeIntegral<int32_t>();
    if (strcpy_s(masterUdid, NETWORK_ID_BUF_LEN, udidStr.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s master udid failed!");
        cJSON_Delete(json);
        return nullptr;
    }
    if (!AddStringToJsonObject(json, JSON_KEY_MASTER_UDID, masterUdid) ||
        !AddNumberToJsonObject(json, JSON_KEY_MASTER_WEIGHT, masterWeight)) {
        COMM_LOGE(COMM_TEST, "add json object failed!");
        cJSON_Delete(json);
        return nullptr;
    }
    char *data = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (data == nullptr) {
        COMM_LOGE(COMM_TEST, "json transform unformatted failed!");
        return nullptr;
    }
    return data;
}

static uint8_t *ConvertCapabilityToMsg(FuzzedDataProvider &dataProvider)
{
    uint8_t *arr = reinterpret_cast<uint8_t *>(SoftBusCalloc(MSG_LEN));
    if (arr == nullptr) {
        COMM_LOGE(COMM_TEST, "malloc failed!");
        return nullptr;
    }
    uint32_t localCapability = dataProvider.ConsumeIntegral<uint32_t>();
    for (uint32_t i = 0; i < BITLEN; i++) {
        *(arr + i) = (localCapability >> (i * BITS)) & 0xFF;
    }
    return arr;
}

static char *LnnGetP2pInfoMsg(FuzzedDataProvider &dataProvider)
{
    cJSON *json = cJSON_CreateObject();
    if (json == nullptr) {
        COMM_LOGE(COMM_TEST, "create json fail");
        return nullptr;
    }
    char wifiCfg[WIFI_CFG_INFO_MAX_LEN] = { 0 };
    char chanList5g[CHANNEL_LIST_STR_LEN] = { 0 };
    char p2pMac[MAC_LEN] = { 0 };
    char goMac[MAC_LEN] = { 0 };
    int32_t p2pRole = dataProvider.ConsumeIntegral<int32_t>();
    string wifiCfgStr = dataProvider.ConsumeBytesAsString(WIFI_CFG_INFO_MAX_LEN - 1);
    string chanList5gStr = dataProvider.ConsumeBytesAsString(CHANNEL_LIST_STR_LEN - 1);
    int32_t staFrequency = dataProvider.ConsumeIntegral<int32_t>();
    string p2pMacStr = dataProvider.ConsumeBytesAsString(MAC_LEN - 1);
    string goMacStr = dataProvider.ConsumeBytesAsString(MAC_LEN - 1);
    if (strcpy_s(wifiCfg, WIFI_CFG_INFO_MAX_LEN, wifiCfgStr.c_str()) != EOK ||
        strcpy_s(chanList5g, CHANNEL_LIST_STR_LEN, chanList5gStr.c_str()) != EOK ||
        strcpy_s(p2pMac, MAC_LEN, p2pMacStr.c_str()) != EOK ||
        strcpy_s(goMac, MAC_LEN, goMacStr.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s p2p info failed!");
        cJSON_Delete(json);
        return nullptr;
    }
    if (!AddNumberToJsonObject(json, JSON_KEY_P2P_ROLE, p2pRole) ||
        !AddStringToJsonObject(json, JSON_KEY_WIFI_CFG, wifiCfg) ||
        !AddStringToJsonObject(json, JSON_KEY_CHAN_LIST_5G, chanList5g) ||
        !AddNumberToJsonObject(json, JSON_KEY_STA_FREQUENCY, staFrequency) ||
        !AddStringToJsonObject(json, JSON_KEY_P2P_MAC, p2pMac) ||
        !AddStringToJsonObject(json, JSON_KEY_GO_MAC, goMac)) {
        COMM_LOGE(COMM_TEST, "add json object failed!");
        cJSON_Delete(json);
        return nullptr;
    }
    char *msg = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (msg == nullptr) {
        COMM_LOGE(COMM_TEST, "json transform unformatted failed!");
        return nullptr;
    }
    return msg;
}

static char *LnnGetWifiDirectAddrMsg(FuzzedDataProvider &dataProvider)
{
    cJSON *json = cJSON_CreateObject();
    if (json == nullptr) {
        COMM_LOGE(COMM_TEST, "create json fail");
        return nullptr;
    }
    char wifiDirectAddr[MAC_LEN] = { 0 };
    string addrStr = dataProvider.ConsumeBytesAsString(MAC_LEN - 1);
    if (strcpy_s(wifiDirectAddr, MAC_LEN, addrStr.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s wifi direct addr udid failed!");
        cJSON_Delete(json);
        return nullptr;
    }
    if (!AddStringToJsonObject(json, JSON_KEY_WIFIDIRECT_ADDR, wifiDirectAddr)) {
        COMM_LOGE(COMM_TEST, "add json object failed!");
        cJSON_Delete(json);
        return nullptr;
    }
    char *msg = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (msg == nullptr) {
        COMM_LOGE(COMM_TEST, "json transform unformatted failed!");
        return nullptr;
    }
    return msg;
}

static char *ProcessSendSleMacInfo(FuzzedDataProvider &dataProvider)
{
    cJSON *json = cJSON_CreateObject();
    if (json == nullptr) {
        COMM_LOGE(COMM_TEST, "create json fail");
        return nullptr;
    }
    int32_t sleCap = dataProvider.ConsumeIntegral<int32_t>();
    char sleMac[MAC_LEN] = { 0 };
    string sleMacStr = dataProvider.ConsumeBytesAsString(MAC_LEN - 1);
    if (strcpy_s(sleMac, MAC_LEN, sleMacStr.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s sle mac failed!");
        cJSON_Delete(json);
        return nullptr;
    }
    if (!AddNumberToJsonObject(json, JSON_KEY_SLE_CAP, sleCap) ||
        !AddStringToJsonObject(json, JSON_KEY_SLE_MAC, sleMac)) {
        COMM_LOGE(COMM_TEST, "add json object failed!");
        cJSON_Delete(json);
        return nullptr;
    }
    char *msg = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (msg == nullptr) {
        COMM_LOGE(COMM_TEST, "json transform unformatted failed!");
        return nullptr;
    }
    return msg;
}

static uint8_t *ProcessSendOfflineCode(FuzzedDataProvider &dataProvider)
{
    uint32_t *combinedInt = reinterpret_cast<uint32_t *>(SoftBusCalloc(sizeof(uint32_t)));
    if (combinedInt == nullptr) {
        COMM_LOGE(COMM_TEST, "malloc failed!");
        return nullptr;
    }
    int16_t code = dataProvider.ConsumeIntegral<int16_t>();
    *combinedInt = ((uint16_t)code << CONN_CODE_SHIFT) | ((uint16_t)DISCOVERY_TYPE_BR & DISCOVERY_TYPE_MASK);
    *combinedInt = SoftBusHtoNl(*combinedInt);
    return reinterpret_cast<uint8_t *>(combinedInt);
}

static uint8_t *ProcessFuzzSyncInfoMsg(FuzzedDataProvider &dataProvider, LnnSyncInfoType type)
{
    switch (type) {
        case LNN_INFO_TYPE_BATTERY_INFO:
            return reinterpret_cast<uint8_t *>(ProcessSendBatteryInfo(dataProvider));
        case LNN_INFO_TYPE_MASTER_ELECT:
            return reinterpret_cast<uint8_t *>(ProcessSendMasterSelectMsg(dataProvider));
        case LNN_INFO_TYPE_CAPABILITY:
            return ConvertCapabilityToMsg(dataProvider);
        case LNN_INFO_TYPE_P2P_INFO:
            return reinterpret_cast<uint8_t *>(LnnGetP2pInfoMsg(dataProvider));
        case LNN_INFO_TYPE_WIFI_DIRECT:
            return reinterpret_cast<uint8_t *>(LnnGetWifiDirectAddrMsg(dataProvider));
        case LNN_INFO_TYPE_SLE_MAC:
            return reinterpret_cast<uint8_t *>(ProcessSendSleMacInfo(dataProvider));
        case LNN_INFO_TYPE_OFFLINE:
            return reinterpret_cast<uint8_t *>(ProcessSendOfflineCode(dataProvider));
        default:
            return nullptr;
    }
}

static void FreeMsgInner(uint8_t *msg, LnnSyncInfoType type)
{
    if (msg == nullptr) {
        return;
    }
    switch (type) {
        case LNN_INFO_TYPE_BATTERY_INFO:
        case LNN_INFO_TYPE_MASTER_ELECT:
        case LNN_INFO_TYPE_P2P_INFO:
        case LNN_INFO_TYPE_WIFI_DIRECT:
        case LNN_INFO_TYPE_SLE_MAC:
            cJSON_free(msg);
            return;
        case LNN_INFO_TYPE_CAPABILITY:
        case LNN_INFO_TYPE_OFFLINE:
            SoftBusFree(msg);
            return;
        default:
            return;
    }
}

bool LnnSendSyncInfoMsgFuzzTest(FuzzedDataProvider &dataProvider)
{
    int32_t typeData = dataProvider.ConsumeIntegral<int32_t>();
    LnnSyncInfoType type = static_cast<LnnSyncInfoType>
    (typeData % (LNN_INFO_TYPE_COUNT - LNN_INFO_TYPE_CAPABILITY + 1));
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    string outData = dataProvider.ConsumeBytesAsString(NETWORK_ID_BUF_LEN - 1);
    if (strcpy_s(networkId, NETWORK_ID_BUF_LEN, outData.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s networkId failed!");
        return false;
    }
    uint8_t *msg = ProcessFuzzSyncInfoMsg(dataProvider, type);
    if (msg == nullptr) {
        COMM_LOGE(COMM_TEST, "process fuzz sync info msg failed!");
        return false;
    }
    LnnSyncInfoMsgComplete complete;
    (void)memset_s(&complete, sizeof(LnnSyncInfoMsgComplete), 0, sizeof(LnnSyncInfoMsgComplete));
    LnnSendSyncInfoMsg(type, networkId, msg, strlen(reinterpret_cast<const char *>(msg)), complete);
    FreeMsgInner(msg, type);
    return true;
}

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider dataProvider(data, size);
    OHOS::LnnSendSyncInfoMsgFuzzTest(dataProvider);
    return 0;
}
} // namespace OHOS