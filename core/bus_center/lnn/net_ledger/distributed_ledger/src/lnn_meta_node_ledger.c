/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "lnn_meta_node_ledger.h"

#include <securec.h>
#include <string.h>

#include "lnn_deviceinfo_to_profile.h"
#include "lnn_log.h"
#include "lnn_network_id.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

typedef struct {
    ListNode node;
    MetaNodeInfo info;
} MetaNodeStorageInfo;

static SoftBusList *g_metaNodeList = NULL;

static bool CheckMetaNodeConfigInfo(const MetaNodeConfigInfo *info)
{
    if (info == NULL) {
        return false;
    }
    if (info->addrNum > CONNECTION_ADDR_MAX) {
        return false;
    }
    return true;
}

static MetaNodeStorageInfo *FindMetaNodeStorageInfo(const char *id, bool isUdid)
{
    MetaNodeStorageInfo *item = NULL;
    MetaNodeStorageInfo *next = NULL;
    const char *itemId = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_metaNodeList->list, MetaNodeStorageInfo, node) {
        itemId = isUdid ? item->info.configInfo.udid : item->info.metaNodeId;
        if (strlen(id) > strlen(itemId)) {
            LNN_LOGE(LNN_LEDGER, "id is invalid");
            continue;
        }
        if (strncmp(itemId, id, strlen(id)) == 0) {
            return item;
        }
    }
    return NULL;
}

static MetaNodeStorageInfo *CreateMetaNodeStorageInfo(const MetaNodeConfigInfo *info, const char *networkId)
{
    MetaNodeStorageInfo *storageInfo = SoftBusCalloc(sizeof(MetaNodeStorageInfo));
    if (storageInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "create meta node storage info fail");
        return NULL;
    }
    ListInit(&storageInfo->node);
    storageInfo->info.configInfo = *info;
    storageInfo->info.isOnline = false;
    if (strncpy_s(storageInfo->info.metaNodeId, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "copy meta node id fail");
        SoftBusFree(storageInfo);
        return NULL;
    }
    return storageInfo;
}

int32_t LnnActiveMetaNode(const MetaNodeConfigInfo *info, char *metaNodeId)
{
    MetaNodeStorageInfo *storageInfo = NULL;
    int32_t rc = SOFTBUS_NETWORK_ACTIVE_META_NODE_ERR;

    if (!CheckMetaNodeConfigInfo(info) || metaNodeId == NULL) {
        LNN_LOGE(LNN_LEDGER, "LnnActiveMetaNode: para is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_metaNodeList->lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnActiveMetaNode: lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    do {
        storageInfo = FindMetaNodeStorageInfo(info->udid, true);
        if (storageInfo == NULL) {
            if (g_metaNodeList->cnt >= MAX_META_NODE_NUM) {
                LNN_LOGE(LNN_LEDGER, "meta node exceed maximum");
                break;
            }
            if (LnnGenLocalNetworkId(metaNodeId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
                LNN_LOGE(LNN_LEDGER, "generate meta node id fail");
                break;
            }
            storageInfo = CreateMetaNodeStorageInfo(info, metaNodeId);
            if (storageInfo == NULL) {
                break;
            }
            ListAdd(&g_metaNodeList->list, &storageInfo->node);
            g_metaNodeList->cnt++;
            InsertMetaNodeInfoToProfile(&storageInfo->info);
            LNN_LOGI(LNN_LEDGER, "active a mete node");
        } else {
            if (strncpy_s(metaNodeId, NETWORK_ID_BUF_LEN, storageInfo->info.metaNodeId,
                strlen(storageInfo->info.metaNodeId)) != EOK) {
                LNN_LOGE(LNN_LEDGER, "copy meta node id fail");
                break;
            }
            storageInfo->info.configInfo = *info;
            UpdateMetaNodeProfile(&storageInfo->info);
            LNN_LOGI(LNN_LEDGER, "update a mete node");
        }
        rc = SOFTBUS_OK;
    } while (false);
    if (SoftBusMutexUnlock(&g_metaNodeList->lock) != 0) {
        LNN_LOGE(LNN_LEDGER, "LnnActiveMetaNode: unlock failed");
    }
    return rc;
}

int32_t LnnDeactiveMetaNode(const char *metaNodeId)
{
    MetaNodeStorageInfo *storageInfo = NULL;
    int32_t rc = SOFTBUS_OK;

    if (metaNodeId == NULL) {
        LNN_LOGE(LNN_LEDGER, "LnnDeactiveMetaNode: para is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_metaNodeList->lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnDeactiveMetaNode: lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    storageInfo = FindMetaNodeStorageInfo(metaNodeId, false);
    if (storageInfo != NULL) {
        ListDelete(&storageInfo->node);
        g_metaNodeList->cnt--;
        DeleteFromProfile(storageInfo->info.configInfo.udid);
        SoftBusFree(storageInfo);
        LNN_LOGI(LNN_LEDGER, "deactive a mete node");
    } else {
        LNN_LOGE(LNN_LEDGER, "meta node not exist");
        rc = SOFTBUS_NETWORK_NOT_FOUND;
    }
    if (SoftBusMutexUnlock(&g_metaNodeList->lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnDeactiveMetaNode: unlock failed");
    }
    return rc;
}

int32_t LnnGetAllMetaNodeInfo(MetaNodeInfo *infos, int32_t *infoNum)
{
    MetaNodeStorageInfo *item = NULL;
    int32_t i = 0;

    if (infos == NULL || infoNum == NULL) {
        LNN_LOGE(LNN_LEDGER, "LnnGetAllMetaNodeInfo: para is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_metaNodeList->lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnGetAllMetaNodeInfo: lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (*infoNum < (int32_t)g_metaNodeList->cnt) {
        LNN_LOGE(LNN_LEDGER, "meta node info num too small");
        (void)SoftBusMutexUnlock(&g_metaNodeList->lock);
        return SOFTBUS_INVALID_PARAM;
    }
    LIST_FOR_EACH_ENTRY(item, &g_metaNodeList->list, MetaNodeStorageInfo, node) {
        infos[i] = item->info;
        i += 1;
    }
    *infoNum = i;
    if (SoftBusMutexUnlock(&g_metaNodeList->lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnGetAllMetaNodeInfo: unlock failed");
    }
    return SOFTBUS_OK;
}

int32_t LnnGetMetaNodeUdidByNetworkId(const char *networkId, char *udid)
{
    MetaNodeStorageInfo *item = NULL;
    int32_t ret = SOFTBUS_NETWORK_NOT_FOUND;
    if (networkId == NULL) {
        LNN_LOGE(LNN_LEDGER, "LnnGetMetaNodeInfoByNetworkId: para is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_metaNodeList->lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnGetMetaNodeInfoByNetworkId: lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(item, &g_metaNodeList->list, MetaNodeStorageInfo, node) {
        if (strcmp(item->info.metaNodeId, networkId) != 0) {
            continue;
        }
        if (strcpy_s(udid, UDID_BUF_LEN, item->info.configInfo.udid) != EOK) {
            LNN_LOGE(LNN_LEDGER, "meta node udid copy error");
            ret = SOFTBUS_STRCPY_ERR;
            break;
        }
        ret = SOFTBUS_OK;
        break;
    }
    if (SoftBusMutexUnlock(&g_metaNodeList->lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnGetMetaNodeInfoByNetworkId: unlock failed");
    }
    return ret;
}


int32_t LnnGetMetaNodeInfoByNetworkId(const char *networkId, MetaNodeInfo *nodeInfo)
{
    MetaNodeStorageInfo *item = NULL;
    int32_t ret = SOFTBUS_NETWORK_NOT_FOUND;
    if (networkId == NULL) {
        LNN_LOGE(LNN_LEDGER, "LnnGetMetaNodeInfoByNetworkId: para is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_metaNodeList->lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnGetMetaNodeInfoByNetworkId: lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(item, &g_metaNodeList->list, MetaNodeStorageInfo, node) {
        if (strcmp(item->info.metaNodeId, networkId) != 0) {
            continue;
        }
        if (memcpy_s(nodeInfo, sizeof(MetaNodeInfo), &item->info, sizeof(MetaNodeInfo)) != EOK) {
            LNN_LOGE(LNN_LEDGER, "memcpy reply fail");
            ret = SOFTBUS_MEM_ERR;
            break;
        }
        ret = SOFTBUS_OK;
        break;
    }
    if (SoftBusMutexUnlock(&g_metaNodeList->lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnGetMetaNodeInfoByNetworkId: unlock failed");
    }
    return ret;
}

int32_t LnnInitMetaNodeLedger(void)
{
    if (g_metaNodeList == NULL) {
        g_metaNodeList = CreateSoftBusList();
    }
    if (g_metaNodeList == NULL) {
        LNN_LOGE(LNN_LEDGER, "create meta node list failed");
        return SOFTBUS_CREATE_LIST_ERR;
    }
    LNN_LOGI(LNN_LEDGER, "meta node init success");
    return SOFTBUS_OK;
}

void LnnDeinitMetaNodeLedger(void)
{
    if (g_metaNodeList == NULL) {
        return;
    }

    MetaNodeStorageInfo *item = NULL;
    MetaNodeStorageInfo *next = NULL;
    if (SoftBusMutexLock(&g_metaNodeList->lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "lock failed");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_metaNodeList->list, MetaNodeStorageInfo, node) {
        ListDelete(&item->node);
        g_metaNodeList->cnt--;
        SoftBusFree(item);
    }
    (void)SoftBusMutexUnlock(&g_metaNodeList->lock);
    DestroySoftBusList(g_metaNodeList);
    g_metaNodeList = NULL;
}