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

#include "lnn_connId_callback_manager.h"

#include <securec.h>

#include "lnn_log.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

typedef enum {
    CONNID_CB_OK = 0,
    CONNID_CB_CONNID_IS_EXIST,
    CONNID_CB_UDID_IS_EXIST,
    CONNID_CB_ERROR_MAX
} ConnIdCbErrorType;

static bool g_connIdCbInit = false;

static SoftBusMutex g_lnnConnIdCbMutex;
static ListNode *g_lnnConnIdCbInfoList;

static int32_t LnnConnIdCallbackLock(void)
{
    if (!g_connIdCbInit) {
        LNN_LOGE(LNN_BUILDER, "connIdCallback not init");
        return SOFTBUS_NO_INIT;
    }
    return SoftBusMutexLock(&g_lnnConnIdCbMutex);
}

static void LnnConnIdCallbackUnLock(void)
{
    (void)SoftBusMutexUnlock(&g_lnnConnIdCbMutex);
}

static int32_t DupItem(const ConnIdCbInfo *item, ConnIdCbInfo *dupItem)
{
    if (item == NULL || dupItem == NULL) {
        LNN_LOGE(LNN_BUILDER, "item or dupItem is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(dupItem, sizeof(ConnIdCbInfo), item, sizeof(ConnIdCbInfo)) != EOK) {
        LNN_LOGE(LNN_BUILDER, "copy ConnIdCbInfo fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t CopyCbToListAndDelCbByUdid(char *udid, ListNode *list)
{
    if (LnnConnIdCallbackLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "Lock connIdCallback mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    ConnIdCbInfo *item = NULL;
    ConnIdCbInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_lnnConnIdCbInfoList, ConnIdCbInfo, node) {
        if (strncmp(item->udid, udid, UDID_BUF_LEN) == 0) {
            ConnIdCbInfo *dupItem = (ConnIdCbInfo *)SoftBusCalloc(sizeof(ConnIdCbInfo));
            if (dupItem == NULL) {
                ListDelete(&item->node);
                SoftBusFree(item);
                LNN_LOGE(LNN_BUILDER, "mcalloc fail.");
                continue;
            }
            int32_t ret = DupItem(item, dupItem);
            ListDelete(&item->node);
            SoftBusFree(item);
            if (ret != SOFTBUS_OK) {
                SoftBusFree(dupItem);
                LNN_LOGE(LNN_BUILDER, "dupItem fail");
                continue;
            }
            ListTailInsert(list, &dupItem->node);
        }
    }
    LnnConnIdCallbackUnLock();
    return SOFTBUS_OK;
}

void InvokeCallbackForJoinExt(const char *udid, int32_t result)
{
    if (udid == NULL || strlen(udid) == 0) {
        LNN_LOGE(LNN_BUILDER, "invalid udid.");
        return;
    }
    if (!g_connIdCbInit) {
        LNN_LOGE(LNN_BUILDER, "connIdCallback is not init.");
        return;
    }
    ListNode list = {0};
    ListInit(&list);
    int32_t ret = CopyCbToListAndDelCbByUdid((char *)udid, &list);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "CopyCbToListAndDelCbByUdid fail.");
        return;
    }
    ConnIdCbInfo *item = NULL;
    ConnIdCbInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &list, ConnIdCbInfo, node) {
        item->callBack.lnnServerJoinExtCallback(&item->sessionAddr, result);
        LNN_LOGI(LNN_BUILDER, "addr.channelId = %{public}d, result = %{public}d",
            item->sessionAddr.info.session.channelId, result);
        ListDelete(&item->node);
        SoftBusFree(item);
    }
}

static ConnIdCbErrorType IsRepeatConnIdCallbackInfoItem(uint32_t connId, char *peerUdid)
{
    if (connId <= 0 || peerUdid == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid connId = %{public}u or peerUdid.", connId);
        return SOFTBUS_INVALID_PARAM;
    }
    ConnIdCbErrorType ret = CONNID_CB_OK;
    ConnIdCbInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, g_lnnConnIdCbInfoList, ConnIdCbInfo, node) {
        if (connId == item->connId) {
            return CONNID_CB_CONNID_IS_EXIST;
        } else {
            if (strncmp(item->udid, peerUdid, UDID_BUF_LEN) == 0) {
                ret = CONNID_CB_UDID_IS_EXIST;
            }
        }
    }
    return ret;
}

static int32_t FillConnIdCbInfo(ConnIdCbInfo *item, const ConnectionAddr *sessionAddr,
    const LnnServerJoinExtCallBack *callBack, char *peerUdid)
{
    if (strcpy_s(item->udid, UDID_BUF_LEN, peerUdid) != EOK) {
        LNN_LOGE(LNN_BUILDER, "strcpy udid fail");
        return SOFTBUS_STRCPY_ERR;
    }
    if (memcpy_s(&item->callBack, sizeof(LnnServerJoinExtCallBack),
        callBack, sizeof(LnnServerJoinExtCallBack)) != EOK) {
        LNN_LOGE(LNN_BUILDER, "copy callBack fail");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(&item->sessionAddr, sizeof(ConnectionAddr), sessionAddr, sizeof(ConnectionAddr)) != EOK) {
        LNN_LOGE(LNN_BUILDER, "copy sessionAddr fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t AddConnIdCallbackInfoItem(const ConnectionAddr *sessionAddr, const LnnServerJoinExtCallBack *callBack,
    uint32_t connId, char *peerUdid)
{
    if (sessionAddr == NULL || callBack == NULL || callBack->lnnServerJoinExtCallback == NULL ||
        peerUdid == NULL || connId <= 0) {
        LNN_LOGE(LNN_BUILDER, "invalid param, connId = %{public}u.", connId);
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnConnIdCallbackLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "Lock connIdCallback mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    ConnIdCbErrorType errorType = IsRepeatConnIdCallbackInfoItem(connId, peerUdid);
    if (errorType == CONNID_CB_CONNID_IS_EXIST) {
        LnnConnIdCallbackUnLock();
        LNN_LOGE(LNN_BUILDER, "repeat connId, add fail.");
        return SOFTBUS_NETWORK_JOIN_LNN_START_ERR;
    }

    ConnIdCbInfo *item = (ConnIdCbInfo *)SoftBusCalloc(sizeof(ConnIdCbInfo));
    if (item == NULL) {
        LNN_LOGE(LNN_BUILDER, "calloc connIdCallback info fail");
        LnnConnIdCallbackUnLock();
        return SOFTBUS_MALLOC_ERR;
    }
    item->connId = connId;
    int32_t ret = FillConnIdCbInfo(item, sessionAddr, callBack, peerUdid);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "add connIdCallback info fail, need free item. ret = %{public}d", ret);
        SoftBusFree(item);
        LnnConnIdCallbackUnLock();
        return ret;
    }
    ListTailInsert(g_lnnConnIdCbInfoList, &item->node);
    if (errorType == CONNID_CB_UDID_IS_EXIST) {
        LNN_LOGE(LNN_BUILDER, "repeat udid, only add connIdCbInfo.");
        ret = SOFTBUS_ALREADY_EXISTED;
    }
    LnnConnIdCallbackUnLock();
    return ret;
}

int32_t DelConnIdCallbackInfoItem(uint32_t connId)
{
    if (connId <= 0) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnConnIdCallbackLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "Lock connIdCallback mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    ConnIdCbInfo *item = NULL;
    ConnIdCbInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_lnnConnIdCbInfoList, ConnIdCbInfo, node) {
        if (connId == item->connId) {
            ListDelete(&item->node);
            SoftBusFree(item);
            break;
        }
    }
    LnnConnIdCallbackUnLock();
    return SOFTBUS_OK;
}

int32_t GetConnIdCbInfoByAddr(const ConnectionAddr *addr, ConnIdCbInfo *dupItem)
{
    if (addr == NULL || dupItem == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnConnIdCallbackLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "Lock connIdCallback mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    int32_t ret = SOFTBUS_NOT_FIND;
    ConnIdCbInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, g_lnnConnIdCbInfoList, ConnIdCbInfo, node) {
        if (addr->type == CONNECTION_ADDR_SESSION) {
            if (addr->info.session.channelId == item->sessionAddr.info.session.channelId) {
                ret = DupItem(item, dupItem);
                LnnConnIdCallbackUnLock();
                return ret;
            }
        }
    }
    LnnConnIdCallbackUnLock();
    return ret;
}

int32_t LnnInitConnIdCallbackManager(void)
{
    if (g_connIdCbInit) {
        LNN_LOGW(LNN_BUILDER, "callback manager has init.");
        return SOFTBUS_OK;
    }
    SoftBusMutexAttr attr = {
        .type = SOFTBUS_MUTEX_RECURSIVE,
    };
    int32_t ret = SoftBusMutexInit(&g_lnnConnIdCbMutex, &attr);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "g_lnnConnIdCbMutex init fail.");
        return ret;
    }
    g_lnnConnIdCbInfoList = (ListNode *)SoftBusMalloc(sizeof(ListNode));
    if (g_lnnConnIdCbInfoList == NULL) {
        (void)SoftBusMutexDestroy(&g_lnnConnIdCbMutex);
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(g_lnnConnIdCbInfoList);
    g_connIdCbInit = true;
    return ret;
}

void LnnDeinitConnIdCallbackManager(void)
{
    if (!g_connIdCbInit) {
        LNN_LOGE(LNN_BUILDER, "callback manager not init");
        return;
    }
    if (LnnConnIdCallbackLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "Lock ConnIdCallback mutex fail");
        return;
    }
    ConnIdCbInfo *item = NULL;
    ConnIdCbInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_lnnConnIdCbInfoList, ConnIdCbInfo, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    SoftBusFree(g_lnnConnIdCbInfoList);
    g_lnnConnIdCbInfoList = NULL;
    g_connIdCbInit = false;
    LnnConnIdCallbackUnLock();
    (void)SoftBusMutexDestroy(&g_lnnConnIdCbMutex);
}