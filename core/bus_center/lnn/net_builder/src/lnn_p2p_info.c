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

#include "lnn_p2p_info.h"

#include <securec.h>

#include "anonymizer.h"
#include "auth_device_common_key.h"
#include "bus_center_manager.h"
#include "lnn_async_callback_utils.h"
#include "lnn_cipherkey_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_lane_link_p2p.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_secure_storage.h"
#include "lnn_sync_info_manager.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_json.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "wifi_direct_manager.h"

#define JSON_KEY_P2P_ROLE "P2P_ROLE"
#define JSON_KEY_WIFI_CFG "WIFI_CFG"
#define JSON_KEY_CHAN_LIST_5G "CHAN_LIST_5G"
#define JSON_KEY_STA_FREQUENCY "STA_FREQUENCY"
#define JSON_KEY_P2P_MAC "P2P_MAC"
#define JSON_KEY_GO_MAC "GO_MAC"
#define JSON_KEY_WIFIDIRECT_ADDR "WIFIDIRECT_ADDR"

static char *LnnGetP2pInfoMsg(const P2pInfo *info)
{
    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        LNN_LOGE(LNN_BUILDER, "create p2p info json fail");
        return NULL;
    }
    if (!AddNumberToJsonObject(json, JSON_KEY_P2P_ROLE, info->p2pRole)) {
        LNN_LOGE(LNN_BUILDER, "add p2p role fail");
        cJSON_Delete(json);
        return NULL;
    }
    if (!AddStringToJsonObject(json, JSON_KEY_WIFI_CFG, info->wifiCfg)) {
        LNN_LOGE(LNN_BUILDER, "add wifi cfg fail");
        cJSON_Delete(json);
        return NULL;
    }
    if (!AddStringToJsonObject(json, JSON_KEY_CHAN_LIST_5G, info->chanList5g)) {
        LNN_LOGE(LNN_BUILDER, "add chan list 5g fail");
        cJSON_Delete(json);
        return NULL;
    }
    if (!AddNumberToJsonObject(json, JSON_KEY_STA_FREQUENCY, info->staFrequency)) {
        LNN_LOGE(LNN_BUILDER, "add sta frequency fail");
        cJSON_Delete(json);
        return NULL;
    }
    if (!AddStringToJsonObject(json, JSON_KEY_P2P_MAC, info->p2pMac)) {
        LNN_LOGE(LNN_BUILDER, "add p2p mac fail");
        cJSON_Delete(json);
        return NULL;
    }
    if (!AddStringToJsonObject(json, JSON_KEY_GO_MAC, info->goMac)) {
        LNN_LOGE(LNN_BUILDER, "add go mac fail");
        cJSON_Delete(json);
        return NULL;
    }
    char *msg = cJSON_PrintUnformatted(json);
    if (msg == NULL) {
        LNN_LOGE(LNN_BUILDER, "unformat p2p info fail");
    }
    cJSON_Delete(json);
    return msg;
}

static char *LnnGetWifiDirectAddrMsg(const NodeInfo *info)
{
    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        LNN_LOGE(LNN_BUILDER, "create wifidirect addr json fail");
        return NULL;
    }
    if (!AddStringToJsonObject(json, JSON_KEY_WIFIDIRECT_ADDR, info->wifiDirectAddr)) {
        LNN_LOGE(LNN_BUILDER, "add wifidirect addr fail");
        cJSON_Delete(json);
        return NULL;
    }
    char *msg = cJSON_PrintUnformatted(json);
    if (msg == NULL) {
        LNN_LOGE(LNN_BUILDER, "unformat wifidirect addr fail");
    }
    cJSON_Delete(json);
    return msg;
}

static int32_t LnnParseP2pInfoMsg(const char *msg, P2pInfo *info, uint32_t len)
{
    JsonObj *json = JSON_Parse((char *)msg, len);
    if (json == NULL) {
        LNN_LOGE(LNN_BUILDER, "parse p2p info json fail");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (!JSON_GetInt32FromOject(json, JSON_KEY_P2P_ROLE, &info->p2pRole)) {
        LNN_LOGE(LNN_BUILDER, "p2p role not found");
        JSON_Delete(json);
        return SOFTBUS_GET_INFO_FROM_JSON_FAIL;
    }
    if (!JSON_GetStringFromOject(json, JSON_KEY_WIFI_CFG, info->wifiCfg, sizeof(info->wifiCfg))) {
        LNN_LOGE(LNN_BUILDER, "wifi cfg not found");
        JSON_Delete(json);
        return SOFTBUS_GET_INFO_FROM_JSON_FAIL;
    }
    if (!JSON_GetStringFromOject(json, JSON_KEY_CHAN_LIST_5G, info->chanList5g, sizeof(info->chanList5g))) {
        LNN_LOGE(LNN_BUILDER, "chan list 5g not found");
        JSON_Delete(json);
        return SOFTBUS_GET_INFO_FROM_JSON_FAIL;
    }
    if (!JSON_GetInt32FromOject(json, JSON_KEY_STA_FREQUENCY, &info->staFrequency)) {
        LNN_LOGE(LNN_BUILDER, "sta frequency not found");
        JSON_Delete(json);
        return SOFTBUS_GET_INFO_FROM_JSON_FAIL;
    }
    if (!JSON_GetStringFromOject(json, JSON_KEY_P2P_MAC, info->p2pMac, sizeof(info->p2pMac))) {
        LNN_LOGE(LNN_BUILDER, "p2p mac not found");
        JSON_Delete(json);
        return SOFTBUS_GET_INFO_FROM_JSON_FAIL;
    }
    if (!JSON_GetStringFromOject(json, JSON_KEY_GO_MAC, info->goMac, sizeof(info->goMac))) {
        LNN_LOGE(LNN_BUILDER, "go mac not found");
        JSON_Delete(json);
        return SOFTBUS_GET_INFO_FROM_JSON_FAIL;
    }
    JSON_Delete(json);
    return SOFTBUS_OK;
}

static int32_t LnnParseWifiDirectAddrMsg(const char *msg, char *wifiDirectAddr, uint32_t len)
{
    JsonObj *json = JSON_Parse((char *)msg, len);
    if (json == NULL) {
        LNN_LOGE(LNN_BUILDER, "parse wifidirect addr json fail");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (!JSON_GetStringFromOject(json, JSON_KEY_WIFIDIRECT_ADDR, wifiDirectAddr, MAC_LEN)) {
        LNN_LOGE(LNN_BUILDER, "wifidirect addr not found");
        JSON_Delete(json);
        return SOFTBUS_GET_INFO_FROM_JSON_FAIL;
    }
    JSON_Delete(json);
    return SOFTBUS_OK;
}

static bool IsNeedSyncP2pInfo(const NodeInfo *localInfo, const NodeBasicInfo *info)
{
    int32_t osType = 0;
    // rk need to sync
    if (!IsFeatureSupport(localInfo->feature, BIT_WIFI_DIRECT_TLV_NEGOTIATION)) {
        return true;
    }
    if (LnnGetOsTypeByNetworkId(info->networkId, &osType) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get remote osType fail");
    }
    if (osType != OH_OS_TYPE) {
        LNN_LOGE(LNN_BUILDER, "remote osType is %{public}d, need sync p2pinfo", osType);
        return true;
    }
    return false;
}

static void ProcessSyncP2pInfo(void *para)
{
    (void)para;
    int32_t i;
    int32_t infoNum = 0;
    uint32_t len;
    NodeBasicInfo *info = NULL;
    if (LnnGetAllOnlineAndMetaNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get all online node info fail");
        return;
    }
    if (infoNum == 0) {
        LNN_LOGI(LNN_BUILDER, "online device num is 0, not need to sync p2p info");
        return;
    }

    const NodeInfo *localInfo = LnnGetLocalNodeInfo();
    if (localInfo == NULL) {
        SoftBusFree(info);
        return;
    }
    char *msg = LnnGetP2pInfoMsg(&localInfo->p2pInfo);
    if (msg == NULL) {
        LNN_LOGE(LNN_BUILDER, "get p2p info msg fail");
        SoftBusFree(info);
        return;
    }
    len = strlen(msg) + 1; /* add 1 for '\0' */
    for (i = 0; i < infoNum; i++) {
        if (LnnIsLSANode(&info[i])) {
            continue;
        }
        if (IsNeedSyncP2pInfo(localInfo, &info[i]) &&
            LnnSendSyncInfoMsg(LNN_INFO_TYPE_P2P_INFO, info[i].networkId, (uint8_t *)msg, len, NULL) != SOFTBUS_OK) {
            char *anonyDeviceName = NULL;
            Anonymize(info[i].deviceName, &anonyDeviceName);
            LNN_LOGE(LNN_BUILDER, "sync p2p info fail. deviceName=%{public}s", AnonymizeWrapper(anonyDeviceName));
            AnonymizeFree(anonyDeviceName);
        }
    }
    cJSON_free(msg);
    SoftBusFree(info);
    LNN_LOGI(LNN_BUILDER, "sync p2p info done");
}

static void ProcessSyncWifiDirectAddr(void *para)
{
    (void)para;
    int32_t i;
    int32_t infoNum = 0;
    uint32_t len;
    NodeBasicInfo *info = NULL;
    if (LnnGetAllOnlineAndMetaNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get all online node info fail");
        return;
    }
    if (infoNum == 0) {
        LNN_LOGI(LNN_BUILDER, "online device num is 0, not need to sync wifidirect addr");
        return;
    }
    const NodeInfo *localInfo = LnnGetLocalNodeInfo();
    if (localInfo == NULL) {
        SoftBusFree(info);
        return;
    }
    char *msg = LnnGetWifiDirectAddrMsg(localInfo);
    if (msg == NULL) {
        LNN_LOGE(LNN_BUILDER, "get wifidirect addr msg fail");
        SoftBusFree(info);
        return;
    }
    len = strlen(msg) + 1; /* add 1 for '\0' */
    for (i = 0; i < infoNum; i++) {
        if (LnnIsLSANode(&info[i])) {
            continue;
        }
        int32_t osType = 0;
        if (LnnGetOsTypeByNetworkId(info[i].networkId, &osType) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "get remote osType fail");
        }
        if (osType != OH_OS_TYPE &&
            LnnSendSyncInfoMsg(LNN_INFO_TYPE_WIFI_DIRECT, info[i].networkId, (uint8_t *)msg, len, NULL)
            != SOFTBUS_OK) {
            char *anonyNetworkId = NULL;
            Anonymize(info[i].networkId, &anonyNetworkId);
            LNN_LOGE(LNN_BUILDER, "sync wifidirect addr fail. anonyNetworkId=%{public}s",
                AnonymizeWrapper(anonyNetworkId));
            AnonymizeFree(anonyNetworkId);
        }
    }
    cJSON_free(msg);
    SoftBusFree(info);
    LNN_LOGI(LNN_BUILDER, "sync wifidirect addr done");
}

static void OnReceiveP2pSyncInfoMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
    LNN_LOGI(LNN_BUILDER, "Recv p2p info, type=%{public}d, len=%{public}d", type, len);
    if (type != LNN_INFO_TYPE_P2P_INFO) {
        return;
    }
    if (msg == NULL || len == 0) {
        return;
    }
    P2pInfo p2pInfo = {0};
    if (LnnParseP2pInfoMsg((const char *)msg, &p2pInfo, len) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "parse p2p info fail");
        return;
    }
    if (!LnnSetDLP2pInfo(networkId, &p2pInfo)) {
        LNN_LOGE(LNN_BUILDER, "set p2p info fail");
    }
}

static void OnReceiveWifiDirectSyncAddr(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
    LNN_LOGI(LNN_BUILDER, "Recv wifidirect addr, type=%{public}d, len=%{public}d", type, len);
    if (type != LNN_INFO_TYPE_WIFI_DIRECT) {
        LNN_LOGI(LNN_BUILDER, "lnnsyncinfo type is null");
        return;
    }
    if (msg == NULL || len == 0) {
        LNN_LOGI(LNN_BUILDER, "invalid null msg or len");
        return;
    }
    char wifiDirectAddr[MAC_LEN] = { 0 };
    if (LnnParseWifiDirectAddrMsg((const char *)msg, wifiDirectAddr, len) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "parse wifidirect addr fail");
        return;
    }
    if (!LnnSetDLWifiDirectAddr(networkId, wifiDirectAddr)) {
        LNN_LOGE(LNN_BUILDER, "set wifidirect addr fail");
    }
}

int32_t LnnSyncP2pInfo(void)
{
    int32_t rc = LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), ProcessSyncP2pInfo, NULL);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "async p2p info fail, rc=%{public}d", rc);
        return rc;
    }
    return SOFTBUS_OK;
}

int32_t LnnSyncWifiDirectAddr(void)
{
    int32_t rc = LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), ProcessSyncWifiDirectAddr, NULL);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "async wifidirect addr fail, rc=%{public}d", rc);
        return rc;
    }
    return SOFTBUS_OK;
}

int32_t LnnInitLocalP2pInfo(NodeInfo *info)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    bool isSupportBle = info->netCapacity & (1 << BIT_BLE);
    bool isSupportP2p = info->netCapacity & (1 << BIT_WIFI_P2P);
    if (LnnSetP2pRole(info, WIFI_DIRECT_ROLE_NONE) != SOFTBUS_OK ||
        LnnSetP2pMac(info, "") != SOFTBUS_OK ||
        LnnSetP2pGoMac(info, "") != SOFTBUS_OK ||
        LnnSetWifiDirectAddr(info, "") != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "init p2p info fail");
        return SOFTBUS_SET_P2P_INFO_FAIL;
    }
    info->isBleP2p = (isSupportBle && isSupportP2p);
    return SOFTBUS_OK;
}

int32_t LnnInitP2p(void)
{
    if (LnnInitPtk() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init ptk fail");
    }
    if (LnnInitPtkSyncListener() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init ptk listener fail");
    }
    if (LnnInitBroadcastLinkKey() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init broadcast link key fail");
    }
    return LnnRegSyncInfoHandler(LNN_INFO_TYPE_P2P_INFO, OnReceiveP2pSyncInfoMsg);
}

void LnnDeinitP2p(void)
{
    LnnDeinitPtk();
    LnnDeinitBroadcastLinkKey();
    (void)LnnUnregSyncInfoHandler(LNN_INFO_TYPE_P2P_INFO, OnReceiveP2pSyncInfoMsg);
}

int32_t LnnInitWifiDirect(void)
{
    return LnnRegSyncInfoHandler(LNN_INFO_TYPE_WIFI_DIRECT, OnReceiveWifiDirectSyncAddr);
}

void LnnDeinitWifiDirect(void)
{
    (void)LnnUnregSyncInfoHandler(LNN_INFO_TYPE_WIFI_DIRECT, OnReceiveWifiDirectSyncAddr);
}