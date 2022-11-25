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

#include "lnn_topo_manager.h"

#include <securec.h>

#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "common_list.h"
#include "lnn_async_callback_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_sync_info_manager.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"

#define JSON_KEY_TYPE "type"
#define JSON_KEY_SEQ "seq"
#define JSON_KEY_COMPLETE "complete"
#define JSON_KEY_INFO "info"
#define JSON_KEY_TYPE "type"
#define JSON_KEY_UDID "udid"
#define JSON_KEY_PEER_UDID "peerUdid"
#define JSON_KEY_WLAN_RELATION "wlanRelation"
#define JSON_KEY_BR_RELATION "brRelation"
#define JSON_KEY_BLE_RELATION "bleRelation"
#define JSON_KEY_ETH_RELATION "ethRelation"

#define LNN_RELATION_JOIN_THREAD 1
#define RELATION_CHANGED_MSG_DELAY (5 * 1000)

#define TOPO_HASH_TABLE_SIZE 16

typedef struct {
    ConnectionAddrType type;
    uint8_t relation;
    bool isJoin;
    char udid[UDID_BUF_LEN];
} RelationChangedMsg;

typedef enum {
    TOPO_MSG_TYPE_UPDATE,
} TopoUpdateMsgType;

typedef enum {
    TOPO_MSG_FLAG_NOT_COMPLETE = 0,
    TOPO_MSG_FLAG_COMPLETE,
} TopoUpdateMsgFlag;

typedef struct {
    ListNode table[TOPO_HASH_TABLE_SIZE];
    bool isSupportTopo;
    uint32_t totalCount;
    SoftBusMutex lock;
} TopoHashTable;

typedef struct {
    ListNode node;
    char udid[UDID_BUF_LEN];
    uint32_t count;
    ListNode joinList;
} TopoTableItem;

typedef struct {
    ListNode node;
    char peerUdid[UDID_BUF_LEN];
    uint8_t relation[CONNECTION_ADDR_MAX];
} TopoInfo;

static TopoHashTable g_topoTable;

static bool IsSameRelation(const uint8_t *newRelation, const uint8_t *oldRelation, uint32_t len)
{
    uint32_t i;

    for (i = 0; i < len; ++i) {
        if ((newRelation[i] != 0 && oldRelation[i] == 0) || (newRelation[i] == 0 && oldRelation[i] != 0)) {
            return false;
        }
    }
    return true;
}

static bool HasRelation(const uint8_t *relation, uint32_t len)
{
    uint32_t i;

    for (i = 0; i < len; ++i) {
        if (relation[i] > 0) {
            return true;
        }
    }
    return false;
}

static uint32_t HashIndex(const char *udid)
{
    return ((*(const uint32_t *)udid) % TOPO_HASH_TABLE_SIZE);
}

static TopoTableItem *CreateTopoItem(const char *udid)
{
    TopoTableItem *item = SoftBusMalloc(sizeof(TopoTableItem));
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc topo item fail");
        return NULL;
    }
    ListInit(&item->joinList);
    ListInit(&item->node);
    item->count = 0;
    if (strcpy_s(item->udid, UDID_BUF_LEN, udid) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy udid to topo item fail");
        SoftBusFree(item);
        return NULL;
    }
    return item;
}

static TopoInfo *CreateTopoInfo(const char *udid, const uint8_t *relation, uint32_t len)
{
    TopoInfo *info = SoftBusMalloc(sizeof(TopoInfo));
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc topo info fail");
        return NULL;
    }
    ListInit(&info->node);
    if (strcpy_s(info->peerUdid, UDID_BUF_LEN, udid) != EOK ||
        memcpy_s(info->relation, CONNECTION_ADDR_MAX, relation, len) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy info to topo info fail");
        SoftBusFree(info);
        return NULL;
    }
    return info;
}

static TopoTableItem *FindTopoItem(const char *udid)
{
    TopoTableItem *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_topoTable.table[HashIndex(udid)], TopoTableItem, node) {
        if (strcmp(item->udid, udid) == 0) {
            return item;
        }
    }
    return NULL;
}

static int32_t FindTopoInfo(const char *udid, const char *peerUdid, TopoTableItem **item, TopoInfo **info)
{
    TopoTableItem *topoItem = NULL;
    TopoInfo *topoInfo = NULL;
    const char *compareUdid = peerUdid;

    topoItem = FindTopoItem(udid);
    if (topoItem == NULL) {
        topoItem = FindTopoItem(peerUdid);
        if (topoItem != NULL) {
            compareUdid = udid;
        }
    }
    if (topoItem == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "topo item not exist");
        return SOFTBUS_NOT_FIND;
    }
    *item = topoItem;
    LIST_FOR_EACH_ENTRY(topoInfo, &topoItem->joinList, TopoInfo, node) {
        if (strcmp(compareUdid, topoInfo->peerUdid) == 0) {
            *info = topoInfo;
            return SOFTBUS_OK;
        }
    }
    return SOFTBUS_NOT_FIND;
}

static void ClearTopoTable(void)
{
    TopoTableItem *item = NULL;
    TopoTableItem *itemNext = NULL;
    TopoInfo *info = NULL;
    TopoInfo *infoNext = NULL;
    uint32_t i;

    for (i = 0; i < TOPO_HASH_TABLE_SIZE; ++i) {
        LIST_FOR_EACH_ENTRY_SAFE(item, itemNext, &g_topoTable.table[i], TopoTableItem, node) {
            LIST_FOR_EACH_ENTRY_SAFE(info, infoNext, &item->joinList, TopoInfo, node) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "delete topo info, local:%s, peer:%s",
                    AnonymizesUDID(item->udid), AnonymizesUDID(info->peerUdid));
                ListDelete(&info->node);
                SoftBusFree(info);
            }
            ListDelete(&item->node);
            SoftBusFree(item);
        }
    }
    g_topoTable.totalCount = 0;
}

static int32_t PackCommonTopoMsg(cJSON **json, cJSON **info)
{
    int32_t seq;

    if (SoftBusGenerateRandomArray((uint8_t *)&seq, sizeof(uint32_t)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "generate seq fail");
        return SOFTBUS_ERR;
    }
    if (seq < 0) {
        seq = -seq;
    }
    *json = cJSON_CreateObject();
    if (*json == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "create topo update json fail");
        return SOFTBUS_ERR;
    }
    if (!AddNumberToJsonObject(*json, JSON_KEY_TYPE, TOPO_MSG_TYPE_UPDATE) ||
        !AddNumberToJsonObject(*json, JSON_KEY_SEQ, seq) ||
        !AddNumberToJsonObject(*json, JSON_KEY_COMPLETE, TOPO_MSG_FLAG_COMPLETE)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "pack topo common json fail");
        cJSON_Delete(*json);
        return SOFTBUS_ERR;
    }
    *info = cJSON_CreateArray();
    if (*info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "create topo info json fail");
        cJSON_Delete(*json);
        return SOFTBUS_ERR;
    }
    if (!cJSON_AddItemToObject(*json, JSON_KEY_INFO, *info)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "pack topo info json to msg fail");
        cJSON_Delete(*info);
        cJSON_Delete(*json);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t PackTopoInfo(cJSON *info, const char *udid, const char *peerUdid,
    const uint8_t *relation, uint32_t len)
{
    cJSON *item = cJSON_CreateObject();
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "create topo info json fail");
        return SOFTBUS_ERR;
    }
    if (len < CONNECTION_ADDR_MAX) {
        cJSON_Delete(item);
        return SOFTBUS_INVALID_PARAM;
    }
    if (!AddStringToJsonObject(item, JSON_KEY_UDID, udid) ||
        !AddStringToJsonObject(item, JSON_KEY_PEER_UDID, peerUdid)) {
        cJSON_Delete(item);
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "pack topo udid json fail");
        return SOFTBUS_ERR;
    }
    if (!AddNumberToJsonObject(item, JSON_KEY_WLAN_RELATION, relation[CONNECTION_ADDR_WLAN]) ||
        !AddNumberToJsonObject(item, JSON_KEY_BR_RELATION, relation[CONNECTION_ADDR_BR]) ||
        !AddNumberToJsonObject(item, JSON_KEY_BLE_RELATION, relation[CONNECTION_ADDR_BLE]) ||
        !AddNumberToJsonObject(item, JSON_KEY_ETH_RELATION, relation[CONNECTION_ADDR_ETH]) ||
        !cJSON_AddItemToArray(info, item)) {
        cJSON_Delete(item);
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "pack topo relation json fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static const char *PackOneLnnRelation(const char *udid, const char *peerUdid,
    const uint8_t *relation, uint32_t len)
{
    cJSON *json = NULL;
    cJSON *info = NULL;
    const char *msg = NULL;

    if (PackCommonTopoMsg(&json, &info) != SOFTBUS_OK) {
        return NULL;
    }
    if (PackTopoInfo(info, udid, peerUdid, relation, len) != SOFTBUS_OK) {
        cJSON_Delete(json);
        return NULL;
    }
    msg = cJSON_PrintUnformatted(json);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "format lnn relation json fail");
    }
    cJSON_Delete(json);
    return msg;
}

static const char *PackLocalTopoUpdateMsg(const char *skipUdid)
{
    TopoTableItem *topoItem = NULL;
    TopoInfo *topoInfo = NULL;
    int32_t i, count;
    cJSON *json = NULL;
    cJSON *info = NULL;
    const char *msg = NULL;

    if (PackCommonTopoMsg(&json, &info) != SOFTBUS_OK) {
        return NULL;
    }
    count = 0;
    for (i = 0; i < TOPO_HASH_TABLE_SIZE; ++i) {
        LIST_FOR_EACH_ENTRY(topoItem, &g_topoTable.table[i], TopoTableItem, node) {
            if (strcmp(skipUdid, topoItem->udid) == 0) {
                continue;
            }
            LIST_FOR_EACH_ENTRY(topoInfo, &topoItem->joinList, TopoInfo, node) {
                if (strcmp(topoInfo->peerUdid, skipUdid) == 0) {
                    continue;
                }
                if (PackTopoInfo(info, topoItem->udid, topoInfo->peerUdid, topoInfo->relation,
                    CONNECTION_ADDR_MAX) == SOFTBUS_OK) {
                    count++;
                }
            }
        }
    }
    if (count == 0) {
        cJSON_Delete(json);
        return NULL;
    }
    msg = cJSON_PrintUnformatted(json);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "format lnn relation json fail");
    }
    cJSON_Delete(json);
    return msg;
}

static int32_t AddTopoInfo(const char *udid, const char *peerUdid, const uint8_t *relation, uint32_t len)
{
    TopoTableItem *topoItem = NULL;
    TopoInfo *topoInfo = NULL;
    bool isKeyUdid = true;
    bool isCreateTopoItem = false;

    topoItem = FindTopoItem(udid);
    if (topoItem == NULL) {
        topoItem = FindTopoItem(peerUdid);
        if (topoItem != NULL) {
            isKeyUdid = false;
        }
    }
    if (topoItem == NULL) {
        topoItem = CreateTopoItem(udid);
        if (topoItem == NULL) {
            return SOFTBUS_MEM_ERR;
        }
        ListAdd(&g_topoTable.table[HashIndex(udid)], &topoItem->node);
        isCreateTopoItem = true;
    }
    topoInfo = CreateTopoInfo(isKeyUdid ? peerUdid : udid, relation, len);
    if (topoInfo == NULL) {
        if (isCreateTopoItem) {
            ListDelete(&topoItem->node);
            SoftBusFree(topoItem);
        }
        return SOFTBUS_MEM_ERR;
    }
    ListAdd(&topoItem->joinList, &topoInfo->node);
    topoItem->count++;
    g_topoTable.totalCount++;
    return SOFTBUS_OK;
}

static int32_t UpdateLocalTopo(const char *udid, const char *peerUdid, const uint8_t *relation, uint32_t len)
{
    TopoTableItem *topoItem = NULL;
    TopoInfo *topoInfo = NULL;
    bool hasRelation = HasRelation(relation, len);

    if (FindTopoInfo(udid, peerUdid, &topoItem, &topoInfo) != SOFTBUS_OK) {
        if (!hasRelation) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "topo info not exist when delete");
            return SOFTBUS_NOT_FIND;
        }
        if (AddTopoInfo(udid, peerUdid, relation, len) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "add topo info fail");
            return SOFTBUS_MEM_ERR;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "add topo info: local:%s peer:%s",
            AnonymizesUDID(udid), AnonymizesUDID(peerUdid));
    } else {
        if (IsSameRelation(topoInfo->relation, relation, len)) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "relation are same");
            return SOFTBUS_ERR;
        }
        if (memcpy_s(topoInfo->relation, CONNECTION_ADDR_MAX, relation, len) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcpy topo info relation fail");
            return SOFTBUS_MEM_ERR;
        }
        if (!hasRelation) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "delete topo info: local:%s peer:%s",
                AnonymizesUDID(topoItem->udid), AnonymizesUDID(topoInfo->peerUdid));
            ListDelete(&topoInfo->node);
            SoftBusFree(topoInfo);
            topoItem->count--;
            g_topoTable.totalCount--;
        }
        if (IsListEmpty(&topoItem->joinList)) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "delete topo item");
            ListDelete(&topoItem->node);
            SoftBusFree(topoItem);
        }
    }
    return SOFTBUS_OK;
}

static void ForwardTopoMsgToAll(const char *networkId, const uint8_t *msg, uint32_t len)
{
    NodeBasicInfo *info = NULL;
    int32_t infoNum, i;

    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get all online node info fail");
        return;
    }
    for (i = 0; i < infoNum; ++i) {
        if (strcmp(networkId, info[i].networkId) == 0) {
            continue;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "forward topo update msg");
        if (LnnSendSyncInfoMsg(LNN_INFO_TYPE_TOPO_UPDATE, info[i].networkId, msg, len, NULL) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sync topo update fail");
        }
    }
    SoftBusFree(info);
}

static void TryCorrectRelation(const char *networkId, const char *udid, const char *peerUdid,
    const uint8_t *relation, uint32_t len)
{
    uint8_t correctRelation[CONNECTION_ADDR_MAX] = {0};
    const char *msg = NULL;
    char localUdid[UDID_BUF_LEN];
    const char *keyUdid = udid;

    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "read local udid fail");
        return;
    }
    if (strcmp(localUdid, udid) == 0) {
        keyUdid = peerUdid;
    }
    LnnGetLnnRelation(keyUdid, CATEGORY_UDID, correctRelation, CONNECTION_ADDR_MAX);
    if (IsSameRelation(correctRelation, relation, len)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "relation are ok, no need correct");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "relation not right and notify update: %d",
        HasRelation(correctRelation, CONNECTION_ADDR_MAX));
    msg = PackOneLnnRelation(udid, peerUdid, correctRelation, CONNECTION_ADDR_MAX);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "pack correct lnn relation msg fail");
        return;
    }
    if (LnnSendSyncInfoMsg(LNN_INFO_TYPE_TOPO_UPDATE, networkId, (const uint8_t *)msg,
        strlen(msg) + 1, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sync correct lnn relation msg fail");
    }
    cJSON_free((void *)msg);
}

static void ProcessTopoUpdateInfo(cJSON *json, const char *networkId, const uint8_t *msg, uint32_t len)
{
    char udid[UDID_BUF_LEN], peerUdid[UDID_BUF_LEN];
    uint8_t relation[CONNECTION_ADDR_MAX];
    int32_t value;
    cJSON *item = NULL;
    char localUdid[UDID_BUF_LEN];
    bool needForward = false;
    cJSON *info = cJSON_GetObjectItemCaseSensitive(json, JSON_KEY_INFO);
    if (!cJSON_IsArray(info)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "topo update msg not contain info");
        return;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "read local udid fail");
        return;
    }
    cJSON_ArrayForEach(item, info) {
        if (!GetJsonObjectStringItem(item, JSON_KEY_UDID, udid, UDID_BUF_LEN) ||
            !GetJsonObjectStringItem(item, JSON_KEY_PEER_UDID, peerUdid, UDID_BUF_LEN)) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parse topo update for uuid fail");
            continue;
        }
        if (strlen(udid) == 0 || strlen(peerUdid) == 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid uuid in topo update msg");
            continue;
        }
        (void)GetJsonObjectNumberItem(item, JSON_KEY_WLAN_RELATION, &value);
        relation[CONNECTION_ADDR_WLAN] = (uint8_t)value;
        (void)GetJsonObjectNumberItem(item, JSON_KEY_BR_RELATION, &value);
        relation[CONNECTION_ADDR_BR] = (uint8_t)value;
        (void)GetJsonObjectNumberItem(item, JSON_KEY_BLE_RELATION, &value);
        relation[CONNECTION_ADDR_BLE] = (uint8_t)value;
        (void)GetJsonObjectNumberItem(item, JSON_KEY_ETH_RELATION, &value);
        relation[CONNECTION_ADDR_ETH] = (uint8_t)value;
        if (strcmp(localUdid, udid) == 0 || strcmp(localUdid, peerUdid) == 0) {
            TryCorrectRelation(networkId, udid, peerUdid, relation, CONNECTION_ADDR_MAX);
            continue;
        }
        if (UpdateLocalTopo(udid, peerUdid, relation, CONNECTION_ADDR_MAX) == SOFTBUS_OK) {
            needForward = true;
        }
    }
    if (needForward) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "notify local topo to others");
        ForwardTopoMsgToAll(networkId, msg, len);
    }
}

static void OnReceiveTopoUpdateMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
    cJSON *json = NULL;
    int32_t topoMsgType, seq, complete;

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "recv topo update msg, type:%d, len:%d", type, len);
    if (type != LNN_INFO_TYPE_TOPO_UPDATE) {
        return;
    }
    if (strnlen((char *)msg, len) == len) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnReceiveTopoUpdateMsg msg invalid");
        return;
    }
    json = cJSON_Parse((char *)msg);
    if (json == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "cjson parse topo msg fail");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "recv topo update msg");
    if (!GetJsonObjectNumberItem(json, JSON_KEY_TYPE, &topoMsgType) ||
        !GetJsonObjectNumberItem(json, JSON_KEY_SEQ, &seq) ||
        !GetJsonObjectNumberItem(json, JSON_KEY_COMPLETE, &complete)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "cjson parse topo common info fail");
        cJSON_Delete(json);
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "topoMsgType:%d, seq:%d, complete:%d", topoMsgType, seq, complete);
    if (topoMsgType != TOPO_MSG_TYPE_UPDATE || complete != TOPO_MSG_FLAG_COMPLETE) {
        cJSON_Delete(json);
        return;
    }
    if (SoftBusMutexLock(&g_topoTable.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock topo table fail");
        cJSON_Delete(json);
        return;
    }
    ProcessTopoUpdateInfo(json, networkId, msg, len);
    cJSON_Delete(json);
    (void)SoftBusMutexUnlock(&g_topoTable.lock);
}

static void NotifyLocalTopo(const char *udid)
{
    const char *msg = NULL;
    char networkId[NETWORK_ID_BUF_LEN] = {0};

    if (LnnConvertDlId(udid, CATEGORY_UDID, CATEGORY_NETWORK_ID, networkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "convert networkId fail");
        return;
    }
    msg = PackLocalTopoUpdateMsg(udid);
    if (msg == NULL) {
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "sync local topo");
    if (LnnSendSyncInfoMsg(LNN_INFO_TYPE_TOPO_UPDATE, networkId, (const uint8_t *)msg,
        strlen(msg) + 1, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sync local topo fail");
    }
    cJSON_free((void *)msg);
}

static void NotifyLnnRelationChange(const char *localUdid, const char *udid,
    const uint8_t *relation, uint32_t len)
{
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    NodeBasicInfo *info = NULL;
    int32_t infoNum, i;
    const char *msg = NULL;
    uint32_t msgLen;

    LnnConvertDlId(udid, CATEGORY_UDID, CATEGORY_NETWORK_ID, networkId, NETWORK_ID_BUF_LEN);
    msg = PackOneLnnRelation(localUdid, udid, relation, len);
    if (msg == NULL) {
        return;
    }
    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get all online node info fail");
        cJSON_free((void *)msg);
        return;
    }
    msgLen = strlen(msg) + 1;
    for (i = 0; i < infoNum; ++i) {
        if (strcmp(networkId, info[i].networkId) == 0) {
            continue;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "sync topo update");
        if (LnnSendSyncInfoMsg(LNN_INFO_TYPE_TOPO_UPDATE, info[i].networkId,
            (const uint8_t *)msg, msgLen, NULL) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sync topo update fail");
        }
    }
    cJSON_free((void *)msg);
    SoftBusFree(info);
}

static void TryClearTopoTable(void)
{
    NodeBasicInfo *info = NULL;
    int32_t infoNum;

    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get all online node info fail");
        return;
    }
    SoftBusFree(info);
    if (infoNum != 0) {
        return;
    }
    ClearTopoTable();
}

static void ProcessLnnRelationChange(const char *udid, const uint8_t *relation, uint32_t len, bool isJoin)
{
    char localUdid[UDID_BUF_LEN];

    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "read local udid fail");
        return;
    }
    if (SoftBusMutexLock(&g_topoTable.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock topo table fail");
        return;
    }
    // 1. notify this lnn relation to other node
    NotifyLnnRelationChange(localUdid, udid, relation, len);
    // 2. update local topo talbe
    if (UpdateLocalTopo(localUdid, udid, relation, len) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "update local topo fail");
        (void)SoftBusMutexUnlock(&g_topoTable.lock);
        return;
    }
    if (isJoin) {
        // 3. send local topo table to peer node
        NotifyLocalTopo(udid);
    } else {
        TryClearTopoTable();
    }
    (void)SoftBusMutexUnlock(&g_topoTable.lock);
}

static void OnLnnRelationChangedDelay(void *para)
{
    uint8_t newRelation[CONNECTION_ADDR_MAX] = {0};
    int32_t rc;
    RelationChangedMsg *msg = (RelationChangedMsg *)para;

    if (msg == NULL) {
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "OnLnnRelationChangedDelay: %d", msg->type);
    if (msg->type == CONNECTION_ADDR_MAX) {
        SoftBusFree(msg);
        return;
    }
    rc = LnnGetLnnRelation(msg->udid, CATEGORY_UDID, newRelation, CONNECTION_ADDR_MAX);
    if (rc != SOFTBUS_OK && rc != SOFTBUS_NOT_FIND) { // NOT_FIND means node is offline
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get new lnn relation fail");
        SoftBusFree(msg);
        return;
    }
    if (msg->isJoin) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "lnn join relaion is %d/%d for type:%d",
            msg->relation, newRelation[msg->type], msg->type);
        if (msg->relation != LNN_RELATION_JOIN_THREAD || newRelation[msg->type] == 0) {
            SoftBusFree(msg);
            return;
        }
    } else {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "lnn leave relaion is %d/%d for type:%d",
            msg->relation, newRelation[msg->type], msg->type);
        if (msg->relation > 0 || newRelation[msg->type] > 0) {
            SoftBusFree(msg);
            return;
        }
    }
    ProcessLnnRelationChange(msg->udid, newRelation, CONNECTION_ADDR_MAX, msg->isJoin);
    SoftBusFree(msg);
}

static void OnLnnRelationChanged(const LnnEventBasicInfo *info)
{
    const LnnRelationChanedEventInfo *eventInfo = (const LnnRelationChanedEventInfo *)info;
    RelationChangedMsg *msg = NULL;

    if (info == NULL || info->event != LNN_EVENT_RELATION_CHANGED) {
        return;
    }
    if (eventInfo->udid == NULL || eventInfo->type == CONNECTION_ADDR_MAX) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid relation changed params");
        return;
    }
    msg = SoftBusMalloc(sizeof(RelationChangedMsg));
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc relation changed msg fail");
        return;
    }
    msg->type = eventInfo->type;
    msg->relation = eventInfo->relation;
    msg->isJoin = eventInfo->isJoin;
    if (strcpy_s(msg->udid, UDID_BUF_LEN, eventInfo->udid) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy udid to relation changed msg fail");
        SoftBusFree(msg);
        return;
    }
    if (LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), OnLnnRelationChangedDelay, msg,
        RELATION_CHANGED_MSG_DELAY) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "async relation changed msg delay fail");
        SoftBusFree(msg);
    }
}

static int32_t FillAllRelation(LnnRelation *relation, uint32_t relationNum)
{
    TopoTableItem *item = NULL;
    TopoTableItem *itemNext = NULL;
    TopoInfo *info = NULL;
    TopoInfo *infoNext = NULL;
    uint32_t i, index;

    index = 0;
    for (i = 0; i < TOPO_HASH_TABLE_SIZE; ++i) {
        LIST_FOR_EACH_ENTRY_SAFE(item, itemNext, &g_topoTable.table[i], TopoTableItem, node) {
            LIST_FOR_EACH_ENTRY_SAFE(info, infoNext, &item->joinList, TopoInfo, node) {
                if (strcpy_s(relation[index].udid, UDID_BUF_LEN, item->udid) != EOK) {
                    return SOFTBUS_MEM_ERR;
                }
                if (strcpy_s(relation[index].peerUdid, UDID_BUF_LEN, info->peerUdid) != EOK) {
                    return SOFTBUS_MEM_ERR;
                }
                if (memcpy_s(relation[index].relation, sizeof(relation[index].relation), info->relation,
                    sizeof(info->relation)) != EOK) {
                    return SOFTBUS_MEM_ERR;
                }
                index++;
            }
        }
    }
    if (index != relationNum) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnInitTopoManager(void)
{
    int32_t i;

    if (SoftbusGetConfig(SOFTBUS_BOOL_SUPPORT_TOPO, (unsigned char*)&g_topoTable.isSupportTopo,
        sizeof(g_topoTable.isSupportTopo)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Cannot get isSupportTopo from config file");
        g_topoTable.isSupportTopo = true;
    }
    if (!g_topoTable.isSupportTopo) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "not Support Topo");
        return SOFTBUS_ERR;
    }
    for (i = 0; i < TOPO_HASH_TABLE_SIZE; ++i) {
        ListInit(&g_topoTable.table[i]);
    }
    g_topoTable.totalCount = 0;
    SoftBusMutexInit(&g_topoTable.lock, NULL);
    if (LnnRegisterEventHandler(LNN_EVENT_RELATION_CHANGED, OnLnnRelationChanged) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "reg discovery type changed event fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegSyncInfoHandler(LNN_INFO_TYPE_TOPO_UPDATE, OnReceiveTopoUpdateMsg) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "reg recv topo update msg fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void LnnDeinitTopoManager(void)
{
    if (!g_topoTable.isSupportTopo) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "not Support Topo");
        return;
    }
    LnnUnregSyncInfoHandler(LNN_INFO_TYPE_TOPO_UPDATE, OnReceiveTopoUpdateMsg);
    LnnUnregisterEventHandler(LNN_EVENT_RELATION_CHANGED, OnLnnRelationChanged);
    SoftBusMutexDestroy(&g_topoTable.lock);
}

int32_t LnnGetAllRelation(LnnRelation **relation, uint32_t *relationNum)
{
    int32_t rc;
    if (relation == NULL || relationNum == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid params");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_topoTable.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock topo table fail");
        return SOFTBUS_LOCK_ERR;
    }
    *relation = NULL;
    *relationNum = g_topoTable.totalCount;
    if (*relationNum == 0) {
        (void)SoftBusMutexUnlock(&g_topoTable.lock);
        return SOFTBUS_OK;
    }
    *relation = SoftBusMalloc(*relationNum * sizeof(LnnRelation));
    if (*relation == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc LnnRelation error");
        (void)SoftBusMutexUnlock(&g_topoTable.lock);
        return SOFTBUS_MEM_ERR;
    }
    rc = FillAllRelation(*relation, *relationNum);
    (void)SoftBusMutexUnlock(&g_topoTable.lock);
    if (rc != SOFTBUS_OK) {
        SoftBusFree(*relation);
    }
    return rc;
}

int32_t LnnGetRelation(const char *udid, const char *peerUdid, uint8_t *relation, uint32_t len)
{
    TopoTableItem *topoItem = NULL;
    TopoInfo *topoInfo = NULL;
    int32_t rc;
    if (udid == NULL || peerUdid == NULL || relation == NULL || len != CONNECTION_ADDR_MAX) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid params");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_topoTable.lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lock topo table fail");
        return SOFTBUS_LOCK_ERR;
    }
    rc = FindTopoInfo(udid, peerUdid, &topoItem, &topoInfo);
    if (rc != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "FindTopoInfo error");
        (void)SoftBusMutexUnlock(&g_topoTable.lock);
        return rc;
    }
    if (memcpy_s(relation, len * sizeof(relation[0]), topoInfo->relation, sizeof(topoInfo->relation)) != EOK) {
        rc = SOFTBUS_MEM_ERR;
    }
    (void)SoftBusMutexUnlock(&g_topoTable.lock);
    return rc;
}