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

#include "bus_center_manager.h"
#include "lnn_async_callback_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_local_net_ledger.h"
#include "lnn_sync_info_manager.h"
#include "p2plink_interface.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"

#define JSON_KEY_P2P_ROLE "P2P_ROLE"
#define JSON_KEY_P2P_MAC "P2P_MAC"
#define JSON_KEY_GO_MAC "GO_MAC"

static char *LnnGetP2pInfoMsg(const P2pInfo *info)
{
    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "create p2p info json fail.");
        return NULL;
    }
    if (!AddNumberToJsonObject(json, JSON_KEY_P2P_ROLE, info->p2pRole)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "add p2p role fail.");
        cJSON_Delete(json);
        return NULL;
    }
    if (!AddStringToJsonObject(json, JSON_KEY_P2P_MAC, info->p2pMac)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "add p2p mac fail.");
        cJSON_Delete(json);
        return NULL;
    }
    if (!AddStringToJsonObject(json, JSON_KEY_GO_MAC, info->goMac)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "add go mac fail.");
        cJSON_Delete(json);
        return NULL;
    }
    char *msg = cJSON_PrintUnformatted(json);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "unformat p2p info fail");
    }
    cJSON_Delete(json);
    return msg;
}

static int32_t LnnParseP2pInfoMsg(const char *msg, P2pInfo *info)
{
    cJSON *json = cJSON_Parse((char *)msg);
    if (json == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parse p2p info json fail.");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (!GetJsonObjectNumberItem(json, JSON_KEY_P2P_ROLE, &info->p2pRole)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "p2p role not found.");
        cJSON_Delete(json);
        return SOFTBUS_ERR;
    }
    if (!GetJsonObjectStringItem(json, JSON_KEY_P2P_MAC, info->p2pMac, sizeof(info->p2pMac))) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "p2p mac not found.");
        cJSON_Delete(json);
        return SOFTBUS_ERR;
    }
    if (!GetJsonObjectStringItem(json, JSON_KEY_GO_MAC, info->goMac, sizeof(info->goMac))) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "go mac not found.");
        cJSON_Delete(json);
        return SOFTBUS_ERR;
    }
    cJSON_Delete(json);
    return SOFTBUS_OK;
}

static void ProcessSyncP2pInfo(void *para)
{
    (void)para;
    int32_t i;
    int32_t infoNum = 0;
    uint32_t len;
    NodeBasicInfo *info = NULL;
    if (LnnGetAllOnlineAndMetaNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get all online node info fail.");
        return;
    }
    if (infoNum == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "online device num is 0, not need to sync p2p info.");
        return;
    }

    const NodeInfo *localInfo = LnnGetLocalNodeInfo();
    if (localInfo == NULL) {
        SoftBusFree(info);
        return;
    }
    char *msg = LnnGetP2pInfoMsg(&localInfo->p2pInfo);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get p2p info msg fail.");
        SoftBusFree(info);
        return;
    }
    len = strlen(msg) + 1; /* add 1 for '\0' */
    for (i = 0; i < infoNum; i++) {
        if (LnnSendSyncInfoMsg(LNN_INFO_TYPE_P2P_INFO, info[i].networkId, (uint8_t *)msg, len, NULL) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sync p2p info to %s fail.", info[i].deviceName);
        }
    }
    cJSON_free(msg);
    SoftBusFree(info);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "sync p2p info done.");
}

static void OnReceiveP2pSyncInfoMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "Recv p2p info, type:%d, len: %d", type, len);
    if (type != LNN_INFO_TYPE_P2P_INFO) {
        return;
    }
    if (msg == NULL || len == 0) {
        return;
    }
    if (strnlen((char *)msg, len) == len) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnReceiveP2pSyncInfoMsg msg invalid");
        return;
    }
    P2pInfo p2pInfo = {0};
    if (LnnParseP2pInfoMsg((const char *)msg, &p2pInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parse p2p info fail");
        return;
    }
    if (!LnnSetDLP2pInfo(networkId, &p2pInfo)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set p2p info fail");
    }
}

int32_t LnnSyncP2pInfo(void)
{
    int32_t rc = LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), ProcessSyncP2pInfo, NULL);
    if (rc != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "async p2p info fail, rc=%d", rc);
        return SOFTBUS_ERR;
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
    if (LnnSetP2pRole(info, ROLE_NONE) != SOFTBUS_OK ||
        LnnSetP2pMac(info, "") != SOFTBUS_OK ||
        LnnSetP2pGoMac(info, "") != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init p2p info fail.");
        return SOFTBUS_ERR;
    }
    info->isBleP2p = (isSupportBle && isSupportP2p);
    return SOFTBUS_OK;
}

int32_t LnnInitP2p(void)
{
    return LnnRegSyncInfoHandler(LNN_INFO_TYPE_P2P_INFO, OnReceiveP2pSyncInfoMsg);
}

void LnnDeinitP2p(void)
{
    (void)LnnUnregSyncInfoHandler(LNN_INFO_TYPE_P2P_INFO, OnReceiveP2pSyncInfoMsg);
}