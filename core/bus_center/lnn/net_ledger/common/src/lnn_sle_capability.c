/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <stdatomic.h>
#include <securec.h>

#include "anonymizer.h"
#include "bus_center_manager.h"
#include "cJSON.h"
#include "g_enhance_adapter_func_pack.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_distributed_net_ledger_common.h"
#include "lnn_sle_capability.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_sle_common_struct.h"
#include "softbus_json_utils.h"
#include "softbus_error_code.h"

static void SleStateChangeEventHandler(int32_t state);

const SoftBusSleStateListener g_sleStateChangedListener = {
    .onSleStateChanged = SleStateChangeEventHandler,
};

static int32_t g_sleStateListenerId = -1;
static int32_t g_sleRangeCap = 0;
static char g_sleMacAddr[MAC_LEN];

int32_t SetSleRangeCapToLocalLedger(void)
{
    g_sleRangeCap = GetSleRangeCapacityPacked();
    int32_t sleCapCache = 0;
    int32_t ret = LnnGetLocalNumInfo(NUM_KEY_SLE_RANGE_CAP, &sleCapCache);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnGetLocalNumInfo fail, ret=%{public}d", ret);
    }
    if (sleCapCache == g_sleRangeCap) {
        LNN_LOGW(LNN_LEDGER, "slecap is consistent, not fix");
        return SOFTBUS_OK;
    }
    ret = LnnUpdateSleCapacityAndVersion(g_sleRangeCap);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnSetLocalNumInfo fail, ret=%{public}d", ret);
        return ret;
    }
    LNN_LOGI(LNN_LEDGER, "LnnSetLocalNumInfo set sle range cap %{public}d", g_sleRangeCap);
    return SOFTBUS_OK;
}

int32_t SetSleAddrToLocalLedger(void)
{
    if (!IsSleEnabledPacked()) {
        LNN_LOGI(LNN_LEDGER, "SLE not enabled!");
        return SOFTBUS_SLE_RANGING_NOT_ENABLE;
    }
    int32_t ret = GetLocalSleAddrPacked(g_sleMacAddr, MAC_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "GetLocalSleAddr fail, ret=%{public}d", ret);
        return ret;
    }
    ret = LnnSetLocalStrInfo(STRING_KEY_SLE_ADDR, g_sleMacAddr);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnSetLocalStrInfo fail, ret=%{public}d", ret);
        return ret;
    }
    char *anonySleMac = NULL;
    Anonymize(g_sleMacAddr, &anonySleMac);
    LNN_LOGI(LNN_LEDGER, "LnnSetLocalStrInfo set sle mac %{public}s", AnonymizeWrapper(anonySleMac));
    AnonymizeFree(anonySleMac);
    return SOFTBUS_OK;
}

void LnnSendSleInfoForAllNode(void)
{
    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        LNN_LOGE(LNN_LEDGER, "json object create failed");
        return;
    }
    if (!AddNumberToJsonObject(json, JSON_KEY_SLE_CAP, g_sleRangeCap) ||
        !AddStringToJsonObject(json, JSON_KEY_SLE_MAC, g_sleMacAddr)) {
        cJSON_Delete(json);
        LNN_LOGE(LNN_LEDGER, "json object add failed");
        return;
    }
    char *data = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (data == NULL) {
        LNN_LOGE(LNN_LEDGER, "json print failed");
        return;
    }
    NodeBasicInfo *info = NULL;
    int32_t infoNum = 0;
    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "get all online node info fail");
        cJSON_free(data);
        return;
    }
    if (info == NULL || infoNum == 0) {
        cJSON_free(data);
        LNN_LOGE(LNN_LEDGER, "online node is zero");
        return;
    }
    LNN_LOGI(LNN_BUILDER, "online nodes count=%{public}d", infoNum);
    for (int32_t i = 0; i < infoNum; ++i) {
        if (LnnIsLSANode(&info[i])) {
            continue;
        }
        char *anonyNetworkId = NULL;
        Anonymize(info[i].networkId, &anonyNetworkId);
        LNN_LOGI(LNN_BUILDER, "sync slecap and slemac to networkId=%{public}s", AnonymizeWrapper(anonyNetworkId));
        if (LnnSendSyncInfoMsg(LNN_INFO_TYPE_SLE_MAC, info[i].networkId,
            (const uint8_t *)data, strlen(data) + 1, NULL) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "sync slecap and slemac failed. networkId=%{public}s",
                AnonymizeWrapper(anonyNetworkId));
        }
        AnonymizeFree(anonyNetworkId);
    }
    cJSON_free(data);
    SoftBusFree(info);
}

static void SleStateChangeEventHandler(int32_t state)
{
    LNN_LOGE(LNN_LEDGER, "SleStateChangeEventHandler enter!");
    if (state != SOFTBUS_SLE_STATE_TURN_ON) {
        LNN_LOGI(LNN_LEDGER, "event is not sle turn on, ignore");
        return;
    }
    (void)SetSleRangeCapToLocalLedger();
    (void)SetSleAddrToLocalLedger();
    (void)LnnSendSleInfoForAllNode();
}

int32_t LocalLedgerInitSleCapacity(NodeInfo* nodeInfo)
{
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "NodeInfo is NULL");
        return SOFTBUS_ERR;
    }
    int32_t sleCapacity = GetSleRangeCapacityPacked();
    char sleMacAddr[MAC_LEN] = { 0 };
    int32_t ret = GetLocalSleAddrPacked(sleMacAddr, MAC_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "GetLocalSleAddr fail, init pass, ret=%{public}d", ret);
    }
    nodeInfo->sleRangeCapacity = sleCapacity;
    memcpy_s(nodeInfo->connectInfo.sleMacAddr, MAC_LEN, sleMacAddr, MAC_LEN);
    ret = SoftBusAddSleStateListenerPacked(&g_sleStateChangedListener, &g_sleStateListenerId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "Add sle state listener failed.");
        return ret;
    }
    return SOFTBUS_OK;
}

void OnReceiveSleMacChangedMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t size)
{
    if (type != LNN_INFO_TYPE_SLE_MAC) {
        LNN_LOGE(LNN_LEDGER, "not sle mac type");
        return;
    }
    if (networkId == NULL || msg == NULL) {
        LNN_LOGE(LNN_LEDGER, "networkId or msg is null");
        return;
    }
    uint32_t addrLen = (uint32_t)strnlen((const char *)msg, size);
    if (size == 0 || addrLen != size - 1 || addrLen == 0) {
        LNN_LOGE(LNN_LEDGER, "invalid msg");
        return;
    }
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    LNN_LOGI(LNN_LEDGER, "OnReceiveSleMacChangedMsg networkId=%{public}s", AnonymizeWrapper(anonyNetworkId));
    AnonymizeFree(anonyNetworkId);
    char sleMacSync [MAC_LEN];
    int32_t sleCapSync = 0;
    cJSON *json = cJSON_Parse((char *)msg);
    if (json == NULL) {
        LNN_LOGE(LNN_LEDGER, "json parse failed");
        return;
    }
    if (!GetJsonObjectStringItem(json, JSON_KEY_SLE_MAC, sleMacSync, MAC_LEN) ||
        !GetJsonObjectNumberItem(json, JSON_KEY_SLE_CAP, &sleCapSync)) {
        LNN_LOGE(LNN_BUILDER, "parse sle mac and sle cap");
        cJSON_Delete(json);
        return;
    }
    cJSON_Delete(json);
    if (LnnSetDLSleRangeInfo(networkId, CATEGORY_NETWORK_ID, sleCapSync, sleMacSync) != SOFTBUS_OK) {
        return;
    }
    char *anonySleMac = NULL;
    Anonymize(networkId, &anonySleMac);
    LNN_LOGI(LNN_LEDGER, "slecap and slemac sync succ, slecap %{public}d sle mac %{public}s", sleCapSync,
        AnonymizeWrapper(anonySleMac));
    AnonymizeFree(anonySleMac);
}

int32_t LnnInitSleInfo(void)
{
    int32_t ret = LnnRegSyncInfoHandler(LNN_INFO_TYPE_SLE_MAC, OnReceiveSleMacChangedMsg);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "Add handler for sle mac changed");
        return ret;
    }
    return SOFTBUS_OK;
}

void LnnDeinitSleInfo(void)
{
    (void)LnnUnregSyncInfoHandler(LNN_INFO_TYPE_SLE_MAC, OnReceiveSleMacChangedMsg);
}

void LocalLedgerDeinitSleCapacity(void)
{
    SoftBusRemoveSleStateListenerPacked(g_sleStateListenerId);
    g_sleStateListenerId = -1;
}
