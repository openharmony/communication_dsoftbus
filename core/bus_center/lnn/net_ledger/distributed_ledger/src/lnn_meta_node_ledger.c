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

#include "lnn_network_id.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
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
    const char *itemId = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_metaNodeList->list, MetaNodeStorageInfo, node) {
        itemId = isUdid ? item->info.configInfo.udid : item->info.metaNodeId;
        if (strncmp(itemId, id, strlen(id)) == 0) {
            return item;
        }
    }
    return NULL;
}

static MetaNodeStorageInfo *CreateMetaNodeStorageInfo(const MetaNodeConfigInfo *info, const char *networkId)
{
    MetaNodeStorageInfo *storageInfo = SoftBusMalloc(sizeof(MetaNodeStorageInfo));
    if (storageInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "create meta node storage info fail");
        return NULL;
    }
    ListInit(&storageInfo->node);
    storageInfo->info.configInfo = *info;
    storageInfo->info.isOnline = false;
    if (strncpy_s(storageInfo->info.metaNodeId, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy meta node id fail");
        SoftBusFree(storageInfo);
        return NULL;
    }
    return storageInfo;
}

int32_t LnnActiveMetaNode(const MetaNodeConfigInfo *info, char *metaNodeId)
{
    MetaNodeStorageInfo *storageInfo = NULL;
    int32_t rc = SOFTBUS_ERR;

    if (!CheckMetaNodeConfigInfo(info) || metaNodeId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnActiveMetaNode: para is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_metaNodeList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnActiveMetaNode: lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    do {
        storageInfo = FindMetaNodeStorageInfo(info->udid, true);
        if (storageInfo == NULL) {
            if (g_metaNodeList->cnt >= MAX_META_NODE_NUM) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "meta node exceed maximum");
                break;
            }
            if (LnnGenLocalNetworkId(metaNodeId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "generate meta node id fail");
                break;
            }
            storageInfo = CreateMetaNodeStorageInfo(info, metaNodeId);
            if (storageInfo == NULL) {
                break;
            }
            ListAdd(&g_metaNodeList->list, &storageInfo->node);
            g_metaNodeList->cnt++;
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "active a mete node");
        } else {
            if (strncpy_s(metaNodeId, NETWORK_ID_BUF_LEN, storageInfo->info.metaNodeId,
                strlen(storageInfo->info.metaNodeId)) != EOK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy meta node id fail");
                break;
            }
            storageInfo->info.configInfo = *info;
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "update a mete node");
        }
        rc = SOFTBUS_OK;
    } while (false);
    if (SoftBusMutexUnlock(&g_metaNodeList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnActiveMetaNode: unlock failed");
    }
    return rc;
}

int32_t LnnDeactiveMetaNode(const char *metaNodeId)
{
    MetaNodeStorageInfo *storageInfo = NULL;
    int32_t rc = SOFTBUS_OK;

    if (metaNodeId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnDeactiveMetaNode: para is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_metaNodeList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnDeactiveMetaNode: lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    storageInfo = FindMetaNodeStorageInfo(metaNodeId, false);
    if (storageInfo != NULL) {
        ListDelete(&storageInfo->node);
        g_metaNodeList->cnt--;
        SoftBusFree(storageInfo);
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "deactive a mete node");
    } else {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "meta node not exist");
        rc = SOFTBUS_ERR;
    }
    if (SoftBusMutexUnlock(&g_metaNodeList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnDeactiveMetaNode: unlock failed");
    }
    return rc;
}

int32_t LnnGetAllMetaNodeInfo(MetaNodeInfo *infos, int32_t *infoNum)
{
    MetaNodeStorageInfo *item = NULL;
    int32_t i = 0;

    if (infos == NULL || infoNum == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetAllMetaNodeInfo: para is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_metaNodeList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetAllMetaNodeInfo: lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (*infoNum < (int32_t)g_metaNodeList->cnt) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "meta node info num too small");
        (void)SoftBusMutexUnlock(&g_metaNodeList->lock);
        return SOFTBUS_INVALID_PARAM;
    }
    LIST_FOR_EACH_ENTRY(item, &g_metaNodeList->list, MetaNodeStorageInfo, node) {
        infos[i] = item->info;
        i += 1;
    }
    *infoNum = i;
    if (SoftBusMutexUnlock(&g_metaNodeList->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetAllMetaNodeInfo: unlock failed");
    }
    return SOFTBUS_OK;
}

int32_t LnnInitMetaNodeLedger(void)
{
    g_metaNodeList = CreateSoftBusList();
    if (g_metaNodeList == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "create meta node list failed");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "meta node init success");
    return SOFTBUS_OK;
}

void LnnDeinitMetaNodeLedger(void)
{
    if (g_metaNodeList != NULL) {
        DestroySoftBusList(g_metaNodeList);
        g_metaNodeList = NULL;
    }
}