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

#include <securec.h>
#include <unistd.h>

#include "message_handler.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_socket.h"
#include "softbus_tcp_socket.h"
#include "softbus_utils.h"
#include "trans_channel_manager.h"
#include "trans_client_proxy.h"
#include "trans_inner.h"
#include "trans_ipc_adapter.h"
#include "trans_lane_manager.h"
#include "trans_log.h"
#include "trans_proxy_process_data.h"
#include "trans_session_service.h"
#include "trans_tcp_direct_message.h"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_tcp_process_data.h"

typedef struct {
    bool supportTlv;
    bool isSessionKeyInit;
    char sessionKey[SESSION_KEY_LENGTH];
    char peerNetworkId[NETWORK_ID_BUF_LEN];
    int32_t channelId;
    int32_t fd;
    int32_t channelType;
    SessionInnerCallback listener;
    ListNode node;
} TransInnerSessionInfo;

#define SLICE_LEN (4 * 1024)
#define DATA_BUF_MAX 4194304
#ifndef MAGIC_NUMBER
#define MAGIC_NUMBER 0xBABEFACE
#endif

static ListenerModule g_baseListenerModule = (ListenerModule) - 1;
static SoftBusList *g_sessionList = NULL;
static SoftBusList *g_innerChannelSliceProcessorList = NULL;
static SoftBusList *g_innerChannelDataBufList = NULL;

void ClientTransInnerSliceListDeinit(void)
{
    if (g_innerChannelSliceProcessorList != NULL) {
        DestroySoftBusList(g_innerChannelSliceProcessorList);
        g_innerChannelSliceProcessorList = NULL;
    }
}

void ClientTransInnerDataBufDeinit(void)
{
    if (g_innerChannelDataBufList != NULL) {
        DestroySoftBusList(g_innerChannelDataBufList);
        g_innerChannelDataBufList = NULL;
    }
}

void ClientTransInnerSessionDeinit(void)
{
    if (g_sessionList != NULL) {
        DestroySoftBusList(g_sessionList);
        g_sessionList = NULL;
    }
}

static int32_t DirectChannelOnConnectEvent(ListenerModule module, int32_t cfd, const ConnectOption *clientAddr)
{
    (void)module;
    (void)cfd;
    (void)clientAddr;
    return SOFTBUS_OK;
}

static void TransSrvDestroyDataBuf(void)
{
    if (g_innerChannelDataBufList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "g_innerChannelDataBufList is null");
        return;
    }

    DataBuf *item = NULL;
    DataBuf *next = NULL;
    if (SoftBusMutexLock(&g_innerChannelDataBufList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "mutex lock failed");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_innerChannelDataBufList->list, DataBuf, node) {
        ListDelete(&item->node);
        SoftBusFree(item->data);
        SoftBusFree(item);
        g_innerChannelDataBufList->cnt--;
    }
    (void)SoftBusMutexUnlock(&g_innerChannelDataBufList->lock);
}

void TransSrvDelInnerDataBufNode(int32_t channelId)
{
    if (g_innerChannelDataBufList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "g_innerChannelDataBufList is null");
        return;
    }

    DataBuf *item = NULL;
    DataBuf *next = NULL;
    if (SoftBusMutexLock(&g_innerChannelDataBufList->lock) != SOFTBUS_OK) {
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_innerChannelDataBufList->list, DataBuf, node) {
        if (item->channelId == channelId) {
            ListDelete(&item->node);
            TRANS_LOGI(TRANS_CTRL, "delete channelId=%{public}d", item->channelId);
            SoftBusFree(item->data);
            SoftBusFree(item);
            g_innerChannelDataBufList->cnt--;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_innerChannelDataBufList->lock);
}

int32_t TransInnerAddDataBufNode(int32_t channelId, int32_t fd, int32_t channelType)
{
    if (channelType != CHANNEL_TYPE_TCP_DIRECT) {
        return SOFTBUS_OK;
    }
#define MAX_DATA_BUF 4096
    DataBuf *node = (DataBuf *)SoftBusCalloc(sizeof(DataBuf));
    if (node == NULL) {
        TRANS_LOGE(TRANS_CTRL, "create server data buf node fail");
        return SOFTBUS_MALLOC_ERR;
    }
    node->channelId = channelId;
    node->fd = fd;
    node->size = MAX_DATA_BUF;
    node->data = (char *)SoftBusCalloc(MAX_DATA_BUF);
    if (node->data ==NULL) {
        TRANS_LOGE(TRANS_CTRL, "create server data buf node fail");
        SoftBusFree(node);
        return SOFTBUS_MALLOC_ERR;
    }
    node->w = node->data;

    if (SoftBusMutexLock(&(g_innerChannelDataBufList->lock)) != SOFTBUS_OK) {
        SoftBusFree(node->data);
        SoftBusFree(node);
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&node->node);
    ListTailInsert(&g_innerChannelDataBufList->list, &node->node);
    g_innerChannelDataBufList->cnt++;
    (void)SoftBusMutexUnlock(&(g_innerChannelDataBufList->lock));

    return SOFTBUS_OK;
}

int32_t InnerAddSession(InnerSessionInfo *innerInfo)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(g_sessionList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "session list not init");

    TransInnerSessionInfo *info = (TransInnerSessionInfo *)SoftBusCalloc(sizeof(TransInnerSessionInfo));
    TRANS_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_MALLOC_ERR, TRANS_CTRL, "malloc failed");
    info->fd = innerInfo->fd;
    info->channelId = innerInfo->channelId;
    info->channelType = innerInfo->channelType;
    info->supportTlv = innerInfo->supportTlv;
    if (info->channelType == CHANNEL_TYPE_TCP_DIRECT) {
        info->isSessionKeyInit = true;
    } else if (info->channelType == CHANNEL_TYPE_PROXY) {
        info->isSessionKeyInit = false;
    }
    int32_t ret = memcpy_s(info->sessionKey, sizeof(info->sessionKey),
        innerInfo->sessionKey, sizeof(innerInfo->sessionKey));
    if (ret != EOK) {
        SoftBusFree(info);
        info = NULL;
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_MEM_ERR, TRANS_CTRL, "memcpy failed");
    }

    ret = memcpy_s(&info->listener, sizeof(info->listener), innerInfo->listener, sizeof(SessionInnerCallback));
    if (ret != EOK) {
        SoftBusFree(info);
        info = NULL;
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_MEM_ERR, TRANS_CTRL, "memcpy failed");
    }

    (void)memcpy_s(info->peerNetworkId, NETWORK_ID_BUF_LEN, innerInfo->peerNetworkId, NETWORK_ID_BUF_LEN);

    if (SoftBusMutexLock(&g_sessionList->lock) != SOFTBUS_OK) {
        SoftBusFree(info);
        info = NULL;
        return SOFTBUS_LOCK_ERR;
    }
    ListAdd(&g_sessionList->list, &info->node);
    g_sessionList->cnt++;
    (void)SoftBusMutexUnlock(&g_sessionList->lock);
    TRANS_LOGI(TRANS_CTRL, "add fd=%{public}d, channelId=%{public}d", info->fd, info->channelId);

    return SOFTBUS_OK;
}

static void DirectOnChannelClose(int32_t channelId, const char *pkgName)
{
    ChannelMsg data = {
        .msgChannelId = channelId,
        .msgPid = getpid(),
        .msgPkgName = pkgName,
    };
    (void)ClientIpcOnChannelClosed(&data);
}

void TransCloseInnerSessionByNetworkId(const char *networkId)
{
    if (g_sessionList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "session list not init");
        return;
    }

    if (SoftBusMutexLock(&(g_sessionList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return;
    }
    TransInnerSessionInfo *pos = NULL;
    TransInnerSessionInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(pos, next, &(g_sessionList->list), TransInnerSessionInfo, node) {
        if (strcmp(pos->peerNetworkId, networkId) == 0) {
            TRANS_LOGI(TRANS_CTRL, "DeleteSession session when link down, channelId=%{public}d", pos->channelId);
            char pkgName[PKG_NAME_SIZE_MAX] = {0};
            TransGetPkgNameByChanId(pos->channelId, pkgName);
            CloseSessionInner(pos->channelId);
            DirectOnChannelClose(pos->channelId, pkgName);
        }
    }
    (void)SoftBusMutexUnlock(&(g_sessionList->lock));
    return;
}

static int32_t DeleteSession(int32_t fd, int32_t channelId)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(g_sessionList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "session list not init");

    if (SoftBusMutexLock(&(g_sessionList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    TransInnerSessionInfo *pos = NULL;
    TransInnerSessionInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(pos, next, &(g_sessionList->list), TransInnerSessionInfo, node) {
        if (pos->fd != fd || pos->channelId != channelId) {
            continue;
        }
        ListDelete(&pos->node);
        SoftBusFree(pos);
        g_sessionList->cnt--;
        (void)SoftBusMutexUnlock(&(g_sessionList->lock));
        TRANS_LOGI(TRANS_CTRL, "DeleteSession success, fd=%{public}d, channelId=%{public}d", fd, channelId);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_sessionList->lock));
    TRANS_LOGE(TRANS_CTRL, "DeleteSession failed, fd=%{public}d, channelId=%{public}d", fd, channelId);
    return SOFTBUS_NOT_FIND;
}

static int32_t GetSessionInfoByFd(int32_t fd, TransInnerSessionInfo *info)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(g_sessionList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "session list not init");

    if (SoftBusMutexLock(&(g_sessionList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    TransInnerSessionInfo *pos = NULL;
    LIST_FOR_EACH_ENTRY(pos, &(g_sessionList->list), TransInnerSessionInfo, node) {
        if (pos->fd != fd) {
            continue;
        }
        int32_t ret = memcpy_s(info, sizeof(TransInnerSessionInfo), pos, sizeof(TransInnerSessionInfo));
        if (ret != EOK) {
            (void)SoftBusMutexUnlock(&(g_sessionList->lock));
            TRANS_LOGE(TRANS_CTRL, "memcpy_s failed! ret=%{public}d", ret);
            return SOFTBUS_MEM_ERR;
        }
        (void)SoftBusMutexUnlock(&(g_sessionList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_sessionList->lock));
    TRANS_LOGE(TRANS_CTRL, "get session info by fd=%{public}d failed", fd);
    return SOFTBUS_NOT_FIND;
}

static int32_t GetSessionInfoByChanId(int32_t channelId, TransInnerSessionInfo *info)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(g_sessionList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "session list not init");
    int32_t ret = 0;
    if (SoftBusMutexLock(&(g_sessionList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    TransInnerSessionInfo *pos = NULL;
    LIST_FOR_EACH_ENTRY(pos, &(g_sessionList->list), TransInnerSessionInfo, node) {
        if (pos->channelId != channelId) {
            continue;
        }
        if (pos->channelType == CHANNEL_TYPE_PROXY && !pos->isSessionKeyInit) {
            AppInfo appInfo;
            ret = TransProxyGetAppInfoByChanId(channelId, &appInfo);
            if (ret != SOFTBUS_OK) {
                (void)SoftBusMutexUnlock(&(g_sessionList->lock));
                TRANS_LOGE(TRANS_CTRL, "get appinfo by id failed, channelId=%{public}d", channelId);
                return ret;
            }
            pos->fd = appInfo.fd;
            ret = memcpy_s(pos->sessionKey, sizeof(pos->sessionKey), appInfo.sessionKey, sizeof(appInfo.sessionKey));
            (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
            if (ret != EOK) {
                (void)SoftBusMutexUnlock(&(g_sessionList->lock));
                TRANS_LOGE(TRANS_CTRL, "memcpy_s failed! ret=%{public}d", ret);
                return SOFTBUS_MEM_ERR;
            }
            pos->isSessionKeyInit = true;
        }
        ret = memcpy_s(info, sizeof(TransInnerSessionInfo), pos, sizeof(TransInnerSessionInfo));
        if (ret != EOK) {
            (void)SoftBusMutexUnlock(&(g_sessionList->lock));
            TRANS_LOGE(TRANS_CTRL, "memcpy_s failed! ret=%{public}d", ret);
            return SOFTBUS_MEM_ERR;
        }
        (void)SoftBusMutexUnlock(&(g_sessionList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_sessionList->lock));
    TRANS_LOGE(TRANS_CTRL, "get session info by channelId=%{public}d failed", channelId);
    return SOFTBUS_NOT_FIND;
}

static int32_t TransInnerGetTdcDataBufById(int32_t channelId, int32_t fd, size_t *len)
{
    if (len == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_innerChannelDataBufList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "tdc data list empty");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&(g_innerChannelDataBufList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    DataBuf *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_innerChannelDataBufList->list), DataBuf, node) {
        if (item->channelId == channelId && item->fd == fd) {
            *len = item->size - (item->w - item->data);
            (void)SoftBusMutexUnlock(&(g_innerChannelDataBufList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_innerChannelDataBufList->lock));
    TRANS_LOGE(TRANS_CTRL, "client get tdc data buf not found. channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND;
}

int32_t TransInnerUpdateTdcDataBufWInfo(int32_t channelId, char *recvBuf, int32_t recvLen)
{
    if (recvBuf == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_innerChannelDataBufList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "tdc data list empty");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_innerChannelDataBufList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    DataBuf *item = NULL;
    DataBuf *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &(g_innerChannelDataBufList->list), DataBuf, node) {
        if (item->channelId != channelId) {
            continue;
        }
        int32_t freeLen = (int32_t)(item->size) - (item->w - item->data);
        if (recvLen > freeLen) {
            (void)SoftBusMutexUnlock(&(g_innerChannelDataBufList->lock));
            TRANS_LOGE(TRANS_CTRL,
                "client tdc recvLen override freeLen. recvLen=%{public}d, freeLen=%{public}d", recvLen, freeLen);
            return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
        }
        if (memcpy_s(item->w, recvLen, recvBuf, recvLen) != EOK) {
            (void)SoftBusMutexUnlock(&(g_innerChannelDataBufList->lock));
            TRANS_LOGE(TRANS_CTRL, "client tdc memcpy failed. channelId=%{public}d", channelId);
            return SOFTBUS_MEM_ERR;
        }
        item->w += recvLen;
        (void)SoftBusMutexUnlock(&(g_innerChannelDataBufList->lock));
        TRANS_LOGD(TRANS_CTRL, "client update tdc data success, channelId=%{public}d", channelId);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_innerChannelDataBufList->lock));
    TRANS_LOGE(TRANS_CTRL, "client update tdc data buf not found. channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND;
}

static DataBuf *TransGetInnerDataBufNodeById(int32_t channelId)
{
    if (g_innerChannelDataBufList == NULL) {
        return NULL;
    }

    DataBuf *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_innerChannelDataBufList->list), DataBuf, node) {
        if (item->channelId == channelId) {
            return item;
        }
    }
    TRANS_LOGE(TRANS_CTRL, "tcp direct channel not exist. channelId=%{public}d", channelId);
    return NULL;
}

static int32_t TransTdcProcessInnerTlvData(
    TransInnerSessionInfo *info, TcpDataTlvPacketHead *pktHead, int32_t pkgHeadSize)
{
    if (info->listener.func == NULL) {
        TRANS_LOGE(TRANS_CTRL, "callback func is null, channelId=%{public}d", info->channelId);
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_innerChannelDataBufList->lock)) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    uint32_t plainLen = 1;
    DataBuf *node = TransGetInnerDataBufNodeById(info->channelId);
    if (node == NULL) {
        (void)SoftBusMutexUnlock(&(g_innerChannelDataBufList->lock));
        TRANS_LOGE(TRANS_CTRL, "node is null. channelId=%{public}d", info->channelId);
        return SOFTBUS_TRANS_NODE_NOT_FOUND;
    }
    uint32_t dataLen = pktHead->dataLen;
    TRANS_LOGI(TRANS_CTRL, "data received, channelId=%{public}d, dataLen=%{public}u, size=%{public}d, seq=%{public}d",
        info->channelId, dataLen, node->size, pktHead->seq);
    char *plain = (char *)SoftBusCalloc(dataLen - OVERHEAD_LEN);
    if (plain == NULL) {
        (void)SoftBusMutexUnlock(&(g_innerChannelDataBufList->lock));
        TRANS_LOGE(TRANS_CTRL, "malloc fail, channelId=%{public}d, dataLen=%{public}u", info->channelId, dataLen);
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = TransTdcDecrypt(info->sessionKey, node->data + pkgHeadSize, dataLen, plain, &plainLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "decrypt fail, channelId=%{public}d, dataLen=%{public}u", info->channelId, dataLen);
        SoftBusFree(plain);
        (void)SoftBusMutexUnlock(&(g_innerChannelDataBufList->lock));
        return SOFTBUS_DECRYPT_ERR;
    }
    ret = MoveNode(info->channelId, node, dataLen, pkgHeadSize);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(plain);
        (void)SoftBusMutexUnlock(&(g_innerChannelDataBufList->lock));
        return ret;
    }
    (void)SoftBusMutexUnlock(&(g_innerChannelDataBufList->lock));
    ret = info->listener.func(info->channelId, plain, plainLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(
            TRANS_CTRL, "exit ret=%{public}d, fd=%{public}d, channelId=%{public}d", ret, info->fd, info->channelId);
    }
    SoftBusFree(plain);
    return ret;
}

static int32_t TransInnerTdcProcAllTlvData(TransInnerSessionInfo *info)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(g_innerChannelDataBufList != NULL,
        SOFTBUS_NO_INIT, TRANS_CTRL, "g_tcpSrvData list not init");
    while (1) {
        SoftBusMutexLock(&(g_innerChannelDataBufList->lock));
        TcpDataTlvPacketHead pktHead;
        uint32_t newPktHeadSize = 0;
        DataBuf *node = TransGetInnerDataBufNodeById(info->channelId);
        if (node == NULL) {
            (void)SoftBusMutexUnlock(&(g_innerChannelDataBufList->lock));
            TRANS_LOGE(TRANS_CTRL, "can not find data buf node. channelId=%{public}d", info->channelId);
            return SOFTBUS_TRANS_NODE_NOT_FOUND;
        }
        bool flag = false;
        int32_t ret = TransTdcUnPackAllTlvData(info->channelId, &pktHead, &newPktHeadSize, node, &flag);
        if (ret != SOFTBUS_OK || flag == true) {
            (void)SoftBusMutexUnlock(&(g_innerChannelDataBufList->lock));
            return ret;
        }
        (void)SoftBusMutexUnlock(&(g_innerChannelDataBufList->lock));
        ret = TransTdcProcessInnerTlvData(info, &pktHead, newPktHeadSize);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "data process failed. channelId=%{public}d", info->channelId);
            return ret;
        }
    }
}

static int32_t TransTdcProcessInnerData(TransInnerSessionInfo *info)
{
    if (info->listener.func == NULL) {
        TRANS_LOGE(TRANS_CTRL, "callback func is null, channelId=%{public}d", info->channelId);
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_innerChannelDataBufList->lock)) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    uint32_t plainLen = 1;
    DataBuf *node = TransGetInnerDataBufNodeById(info->channelId);
    if (node == NULL) {
        (void)SoftBusMutexUnlock(&(g_innerChannelDataBufList->lock));
        TRANS_LOGE(TRANS_CTRL, "node is null. channelId=%{public}d", info->channelId);
        return SOFTBUS_TRANS_NODE_NOT_FOUND;
    }
    TcpDataPacketHead *pktHead = (TcpDataPacketHead *)(node->data);
    uint32_t dataLen = pktHead->dataLen;
    TRANS_LOGI(TRANS_CTRL, "data received, channelId=%{public}d, dataLen=%{public}u, size=%{public}d, seq=%{public}d",
        info->channelId, dataLen, node->size, pktHead->seq);
    char *plain = (char *)SoftBusCalloc(dataLen - OVERHEAD_LEN);
    if (plain == NULL) {
        (void)SoftBusMutexUnlock(&(g_innerChannelDataBufList->lock));
        TRANS_LOGE(TRANS_CTRL, "malloc fail, channelId=%{public}d, dataLen=%{public}u", info->channelId, dataLen);
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = TransTdcUnPackData(info->channelId, info->sessionKey, plain, &plainLen, node);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(plain);
        (void)SoftBusMutexUnlock(&(g_innerChannelDataBufList->lock));
        return ret;
    }
    (void)SoftBusMutexUnlock(&(g_innerChannelDataBufList->lock));
    ret = info->listener.func(info->channelId, plain, plainLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(
            TRANS_CTRL, "exit ret=%{public}d, fd=%{public}d, channelId=%{public}d", ret, info->fd, info->channelId);
    }
    SoftBusFree(plain);
    return ret;
}

static int32_t TransInnerTdcProcAllData(TransInnerSessionInfo *info)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_innerChannelDataBufList != NULL, SOFTBUS_NO_INIT, TRANS_CTRL, "g_tcpSrvDataList is null");
    while (1) {
        SoftBusMutexLock(&(g_innerChannelDataBufList->lock));
        DataBuf *node = TransGetInnerDataBufNodeById(info->channelId);
        if (node == NULL) {
            (void)SoftBusMutexUnlock(&(g_innerChannelDataBufList->lock));
            TRANS_LOGE(TRANS_CTRL, "can not find data buf node. channelId=%{public}d", info->channelId);
            return SOFTBUS_TRANS_NODE_NOT_FOUND;
        }
        bool flag = false;
        int32_t ret = TransTdcUnPackAllData(info->channelId, node, &flag);
        if (ret != SOFTBUS_OK || flag == true) {
            (void)SoftBusMutexUnlock(&(g_innerChannelDataBufList->lock));
            return ret;
        }
        (void)SoftBusMutexUnlock(&(g_innerChannelDataBufList->lock));
        ret = TransTdcProcessInnerData(info);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "data process failed. channelId=%{public}d", info->channelId);
            return ret;
        }
    }
}

static int32_t TdcDataReceived(int32_t fd)
{
    TransInnerSessionInfo info;
    int32_t recvLen = 1;
    size_t len = 0;
    int32_t ret = GetSessionInfoByFd(fd, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get sessionInfo by id fail fd=%{public}d", info.fd);
        return ret;
    }
    ret = TransInnerGetTdcDataBufById(info.channelId, fd, &len);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get tdc data buf by channelId=%{public}d, ret=%{public}d", info.channelId, ret);
        return ret;
    }
    char *recvBuf = (char *)SoftBusCalloc(len);
    if (recvBuf == NULL) {
        TRANS_LOGE(TRANS_CTRL, "client tdc malloc failed, channelId=%{public}d, len=%{public}zu", info.channelId, len);
        return SOFTBUS_MEM_ERR;
    }
    ret = TransTdcRecvFirstData(info.channelId, recvBuf, &recvLen, fd, len);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(recvBuf);
        return ret;
    }
    ret = TransInnerUpdateTdcDataBufWInfo(info.channelId, recvBuf, recvLen);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(recvBuf);
        TRANS_LOGE(TRANS_CTRL, "update data buf failed, channelId=%{public}d, ret=%{public}d", info.channelId, ret);
        return ret;
    }
    SoftBusFree(recvBuf);
    if (info.supportTlv) {
        return TransInnerTdcProcAllTlvData(&info);
    }
    return TransInnerTdcProcAllData(&info);
}

static void DirectChannelCloseSocket(int32_t fd)
{
    if (fd < 0) {
        TRANS_LOGE(TRANS_CTRL, "fd=%{public}d less than zero", fd);
        return;
    }
    TransInnerSessionInfo info;
    int32_t ret = GetSessionInfoByFd(fd, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get sessionInfo by id fail fd=%{public}d", info.fd);
        return;
    }
    TRANS_LOGI(TRANS_CTRL, "close socket, fd=%{public}d", fd);
    (void)TransLaneMgrDelLane(info.channelId, CHANNEL_TYPE_TCP_DIRECT, fd);
    (void)TransDelTcpChannelInfoByChannelId(info.channelId);
    DelTrigger(g_baseListenerModule, fd, READ_TRIGGER);
    ConnShutdownSocket(fd);
}

static int32_t DirectChannelOnDataEvent(ListenerModule module, int32_t events, int32_t fd)
{
    (void)module;
    TRANS_LOGD(TRANS_CTRL, "enter events=%{public}d, fd=%{public}d", events, fd);

    if (events == SOFTBUS_SOCKET_IN) {
        int32_t ret = TdcDataReceived(fd);
        if (ret == SOFTBUS_DATA_NOT_ENOUGH) {
            TRANS_LOGE(TRANS_CTRL, "client process data fail, SOFTBUS_DATA_NOT_ENOUGH. fd=%{public}d", fd);
            return SOFTBUS_OK;
        }
        if (ret != SOFTBUS_OK) {
            TransInnerSessionInfo info = {0};
            char pkgName[PKG_NAME_SIZE_MAX] = {0};
            int32_t res = GetSessionInfoByFd(fd, &info);
            TRANS_CHECK_AND_RETURN_RET_LOGE(res == SOFTBUS_OK, ret, TRANS_CTRL, "get sessionInfo failed");
            TransGetPkgNameByChanId(info.channelId, pkgName);
            DirectChannelCloseSocket(fd);
            TransSrvDelInnerDataBufNode(info.channelId);
            DeleteSession(fd, info.channelId);
            DirectOnChannelClose(info.channelId, pkgName);
            TRANS_LOGE(TRANS_CTRL, "direct channel receive data fail, fd=%{public}d", fd);
            return ret;
        }
    }
    return SOFTBUS_OK;
}

int32_t DirectChannelCreateListener(int32_t fd)
{
    static bool isInitedFlag = false;

    if (!isInitedFlag) {
        isInitedFlag = true;

        static SoftbusBaseListener listener = {
            .onConnectEvent = DirectChannelOnConnectEvent,
            .onDataEvent = DirectChannelOnDataEvent,
        };

        g_baseListenerModule = (ListenerModule)CreateListenerModule();
        if (g_baseListenerModule == UNUSE_BUTT) {
            TRANS_LOGE(TRANS_CTRL, "create listener module fialed");
            return SOFTBUS_TRANS_ILLEGAL_MODULE;
        }
        int32_t ret = StartBaseClient(g_baseListenerModule, &listener);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "start client base listener failed, ret=%{public}d", ret);
            return ret;
        }
        TRANS_LOGI(TRANS_CTRL, "init tcp direct channel success, fd=%{public}d", fd);
    }
    TRANS_LOGI(TRANS_CTRL, "add fd=%{public}d", fd);
    return AddTrigger(g_baseListenerModule, fd, READ_TRIGGER);
}

int32_t TdcSendData(int32_t channelId, const void *data, uint32_t len)
{
    if (data == NULL || len == 0 || len > DATA_BUF_MAX) {
        TRANS_LOGE(TRANS_CTRL, "Invalid param, len=%{public}u", len);
        return SOFTBUS_INVALID_PARAM;
    }
    TransInnerSessionInfo info;
    int32_t ret = GetSessionInfoByChanId(channelId, &info);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    DataLenInfo lenInfo = { 0 };
    static uint32_t seq = 1;
    TransTdcPackDataInfo dataInfo = {
        .needAck = false,
        .supportTlv = info.supportTlv,
        .seq = seq,
        .len = len,
    };
    seq++;
    char *buf = TransTdcPackAllData(&dataInfo, info.sessionKey, (const char *)data, FLAG_BYTES, &lenInfo);
    if (buf == NULL) {
        TRANS_LOGE(TRANS_CTRL, "tdc send bytes failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return SOFTBUS_ENCRYPT_ERR;
    }
    #define BYTE_TOS 0x60
    ret = SetIpTos(info.fd, BYTE_TOS);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "failed to set tos. channelId=%{public}d", channelId);
        SoftBusFree(buf);
        return ret;
    }
    ret = TransTdcSendData(&lenInfo, info.supportTlv, info.fd, len, buf);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(buf);
        return ret;
    }
    SoftBusFree(buf);
    buf = NULL;
    return SOFTBUS_OK;
}

static int32_t ClientTransInnerProxyProcData(int32_t channelId, const DataHeadTlvPacketHead *dataHead,
    const char *data)
{
    ProxyDataInfo dataInfo = { 0 };
    TransInnerSessionInfo info;
    int32_t ret = GetSessionInfoByChanId(channelId, &info);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (info.listener.func == NULL) {
        TRANS_LOGE(TRANS_CTRL, "callback func is null, channelId=%{public}d", info.channelId);
        return SOFTBUS_NO_INIT;
    }
    ret = TransProxyProcData(&dataInfo, dataHead, data);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    ret = TransProxyDecryptPacketData(dataHead->seq, &dataInfo, info.sessionKey);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "decrypt err");
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_DECRYPT_ERR;
    }

    if (TransProxySessionDataLenCheck(dataInfo.outLen, (SessionPktType)(dataHead->flags)) != SOFTBUS_OK) {
        TRANS_LOGE(
            TRANS_CTRL, "data len is too large outlen=%{public}d, flags=%{public}d", dataInfo.outLen, dataHead->flags);
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    TRANS_LOGD(TRANS_CTRL, "ProcessData debug: outlen=%{public}d", dataInfo.outLen);
    info.listener.func(channelId, (const char *)dataInfo.outData, dataInfo.outLen);
    SoftBusFree(dataInfo.outData);
    return SOFTBUS_OK;
}

static int32_t ClientTransProxyInnerNoSubPacketTlvProc(int32_t channelId, const char *data, uint32_t len)
{
    DataHeadTlvPacketHead pktHead;
    uint32_t newPktHeadSize = 0;
    int32_t ret = TransProxyParseTlv(len, data, &pktHead, &newPktHeadSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "proxy channel parse tlv failed, ret=%{public}d", ret);
        return ret;
    }
    ret = TransProxyNoSubPacketTlvProc(channelId, data, len, &pktHead, newPktHeadSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "process data err, channelId=%{public}d, len=%{public}u", channelId, len);
        return ret;
    }
    ret = ClientTransInnerProxyProcData(channelId, &pktHead, data + newPktHeadSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "process data err, channelId=%{public}d, len=%{public}u", channelId, len);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t ClientTransInnerProxyProcessSessionData(int32_t channelId, const PacketHead *dataHead, const char *data)
{
    ProxyDataInfo dataInfo = { 0 };
    TransInnerSessionInfo info;
    int32_t ret = GetSessionInfoByChanId(channelId, &info);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (info.listener.func == NULL) {
        TRANS_LOGE(TRANS_CTRL, "callback func is null, channelId=%{public}d", info.channelId);
        return SOFTBUS_NO_INIT;
    }
    ret = TransProxyProcessSessionData(&dataInfo, dataHead, data);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    ret = TransProxyDecryptPacketData(dataHead->seq, &dataInfo, info.sessionKey);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "decrypt err");
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_DECRYPT_ERR;
    }

    if (TransProxySessionDataLenCheck(dataInfo.outLen, (SessionPktType)(dataHead->flags)) != SOFTBUS_OK) {
        TRANS_LOGE(
            TRANS_CTRL, "data len is too large outlen=%{public}d, flags=%{public}d", dataInfo.outLen, dataHead->flags);
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }

    TRANS_LOGD(TRANS_CTRL, "ProcessData debug: outlen=%{public}d", dataInfo.outLen);
    info.listener.func(channelId, (const char *)dataInfo.outData, dataInfo.outLen);
    SoftBusFree(dataInfo.outData);
    return SOFTBUS_OK;
}

static int32_t ClientTransInnerProxyNoSubPacketProc(int32_t channelId, const char *data, uint32_t len)
{
    TransInnerSessionInfo info;
    int32_t ret = GetSessionInfoByChanId(channelId, &info);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (info.supportTlv) {
        return ClientTransProxyInnerNoSubPacketTlvProc(channelId, data, len);
    }
    PacketHead head;
    ret = TransProxyNoSubPacketProc(&head, len, data, channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "NoSubPacketProc failed, channelId=%{public}d, len=%{public}u", channelId, len);
        return ret;
    }
    ret = ClientTransInnerProxyProcessSessionData(channelId, &head, data + sizeof(PacketHead));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "process data err, channelId=%{public}d, len=%{public}u", channelId, len);
        return ret;
    }
    return SOFTBUS_OK;
}

static ChannelSliceProcessor *ClientTransProxyGetChannelSlice(int32_t channelId)
{
    ChannelSliceProcessor *processor = NULL;
    LIST_FOR_EACH_ENTRY(processor, &g_innerChannelSliceProcessorList->list, ChannelSliceProcessor, head) {
        if (processor->channelId == channelId) {
            return processor;
        }
    }

    ChannelSliceProcessor *node = (ChannelSliceProcessor *)SoftBusCalloc(sizeof(ChannelSliceProcessor));
    if (node == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc err");
        return NULL;
    }
    node->channelId = channelId;
    ListInit(&(node->head));
    ListAdd(&(g_innerChannelSliceProcessorList->list), &(node->head));
    g_innerChannelSliceProcessorList->cnt++;
    TRANS_LOGI(TRANS_CTRL, "add new node, channelId=%{public}d", channelId);
    return node;
}

static int32_t ClientTransInnerProxyFirstSliceProcess(
    SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len, int32_t channelId)
{
    TransProxyClearProcessor(processor);
    TransInnerSessionInfo info;
    int32_t ret = GetSessionInfoByChanId(channelId, &info);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    uint32_t actualDataLen = 0;
    ret = TransGetActualDataLen(head, &actualDataLen);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return TransProxyFirstSliceProcess(processor, head, data, len, info.supportTlv);
}

static bool IsValidCheckoutSliceProcess(int32_t channelId)
{
    ChannelSliceProcessor *processor = NULL;
    LIST_FOR_EACH_ENTRY(processor, &g_innerChannelSliceProcessorList->list, ChannelSliceProcessor, head) {
        if (processor->channelId == channelId) {
            return true;
        }
    }

    TRANS_LOGE(TRANS_CTRL, "process not exist, channelId=%{public}d", channelId);
    return false;
}

static int32_t ClientTransProxyLastSliceProcess(
    SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len, int32_t channelId)
{
    int32_t ret = TransProxySliceProcessChkPkgIsValid(processor, head, data, len);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (memcpy_s(processor->data + processor->dataLen, (uint32_t)(processor->bufLen - processor->dataLen), data, len) !=
        EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy fail when proc last slice");
        return SOFTBUS_MEM_ERR;
    }
    processor->expectedSeq++;
    processor->dataLen += (int32_t)len;

    ret = ClientTransInnerProxyNoSubPacketProc(channelId, processor->data, (uint32_t)processor->dataLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "process packets err");
        return ret;
    }

    if (IsValidCheckoutSliceProcess(channelId)) {
        TransProxyClearProcessor(processor);
    }

    TRANS_LOGI(TRANS_CTRL, "LastSliceProcess ok");
    return ret;
}

static int32_t TransProxyDelSliceProcessorByChannelId(int32_t channelId)
{
    ChannelSliceProcessor *node = NULL;
    ChannelSliceProcessor *next = NULL;

    if (g_innerChannelSliceProcessorList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_innerChannelSliceProcessorList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "mutex lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(node, next, &g_innerChannelSliceProcessorList->list, ChannelSliceProcessor, head) {
        if (node->channelId == channelId) {
            for (int32_t i = PROXY_CHANNEL_PRORITY_MESSAGE; i < PROXY_CHANNEL_PRORITY_BUTT; i++) {
                TransProxyClearProcessor(&(node->processor[i]));
            }
            ListDelete(&(node->head));
            TRANS_LOGI(TRANS_CTRL, "delete channelId=%{public}d", channelId);
            SoftBusFree(node);
            g_innerChannelSliceProcessorList->cnt--;
            (void)SoftBusMutexUnlock(&g_innerChannelSliceProcessorList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_innerChannelSliceProcessorList->lock);
    return SOFTBUS_OK;
}

static int32_t ClientTransProxySubPacketProc(int32_t channelId, const SliceHead *head, const char *data, uint32_t len)
{
    if (g_innerChannelSliceProcessorList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "not inti");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_innerChannelSliceProcessorList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "mutex lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    ChannelSliceProcessor *channelProcessor = ClientTransProxyGetChannelSlice(channelId);
    if (channelProcessor == NULL) {
        (void)SoftBusMutexUnlock(&g_innerChannelSliceProcessorList->lock);
        return SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL;
    }
    int32_t ret = 0;
    int32_t index = head->priority;
    SliceProcessor *processor = &(channelProcessor->processor[index]);
    if (head->sliceSeq == 0) {
        ret = ClientTransInnerProxyFirstSliceProcess(processor, head, data, len, channelId);
    } else if (head->sliceNum == head->sliceSeq + 1) {
        ret = ClientTransProxyLastSliceProcess(processor, head, data, len, channelId);
    } else {
        ret = TransProxyNormalSliceProcess(processor, head, data, len);
    }

    (void)SoftBusMutexUnlock(&g_innerChannelSliceProcessorList->lock);
    if (ret != SOFTBUS_OK) {
        TransProxyClearProcessor(processor);
    }
    return ret;
}

int32_t ProxyDataRecvHandler(int32_t channelId, const char *data, uint32_t len)
{
    if (data == NULL || len <= sizeof(SliceHead)) {
        TRANS_LOGE(TRANS_CTRL, "dataLen err, len=%{public}u, channelId=%{public}d", len, channelId);
        return SOFTBUS_INVALID_PARAM;
    }
    SliceHead headSlice = *(SliceHead *)data;
    TransUnPackSliceHead(&headSlice);
    if (TransProxyCheckSliceHead(&headSlice) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "invalid slicehead");
        return SOFTBUS_TRANS_PROXY_INVALID_SLICE_HEAD;
    }
    uint32_t dataLen = len - sizeof(SliceHead);
    if (headSlice.sliceNum == 1) {
        TRANS_LOGD(TRANS_CTRL, "no sub packets proc channelId=%{public}d", channelId);
        return ClientTransInnerProxyNoSubPacketProc(channelId, data + sizeof(SliceHead), dataLen);
    } else {
        TRANS_LOGI(TRANS_CTRL, "no sub packets proc sliceNum=%{public}d", headSlice.sliceNum);
        return ClientTransProxySubPacketProc(channelId, &headSlice, data + sizeof(SliceHead), dataLen);
    }
}

static int32_t TransInnerProxyPackBytes(int32_t channelId, ProxyDataInfo *dataInfo, TransInnerSessionInfo *info)
{
    if (dataInfo == NULL || info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    static int32_t seq = 1;
    uint32_t dataSeq = 0;
    if (info->supportTlv) {
        DataHeadTlvPacketHead headInfo = {
            .needAck = false,
            .dataSeq = dataSeq,
        };
        return TransProxyPackTlvBytes(dataInfo, info->sessionKey, TRANS_SESSION_BYTES, seq++, &headInfo);
    }
    return TransProxyPackBytes(channelId, dataInfo, info->sessionKey, TRANS_SESSION_BYTES, seq++);
}

static int32_t ProxySendData(int32_t channelId, const void *data, uint32_t len, TransInnerSessionInfo *info)
{
    if (data == NULL || info == NULL || len > DATA_BUF_MAX) {
        TRANS_LOGI(TRANS_CTRL, "data is null channelId=%{public}d", channelId);
        return SOFTBUS_INVALID_PARAM;
    }
    ProxyDataInfo dataInfo = { (uint8_t *)data, len, (uint8_t *)data, len };
    int32_t ret = TransInnerProxyPackBytes(channelId, &dataInfo, info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGI(TRANS_CTRL, "proxy inner session pack bytes failed, channelId=%{public}d", channelId);
        return ret;
    }
    uint32_t dataLen = 1;

    uint32_t sliceNum = (dataInfo.outLen + (uint32_t)(SLICE_LEN - 1)) / (uint32_t)SLICE_LEN;
    if (sliceNum > INT32_MAX) {
        TRANS_LOGI(TRANS_CTRL, "data overflow");
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_INVALID_NUM;
    }
    for (uint32_t cnt = 0; cnt < sliceNum; cnt++) {
        uint8_t *sliceData = TransProxyPackData(&dataInfo, sliceNum, TRANS_SESSION_BYTES, cnt, &dataLen);
        if (sliceData == NULL) {
            TRANS_LOGE(TRANS_CTRL, "pack data failed, channelId=%{public}d", channelId);
            SoftBusFree(dataInfo.outData);
            return SOFTBUS_MALLOC_ERR;
        }
        ret = TransSendMsg(channelId, CHANNEL_TYPE_PROXY, sliceData, dataLen + sizeof(SliceHead), TRANS_SESSION_BYTES);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "send msg error, channelId=%{public}d, ret=%{public}d", channelId, ret);
            SoftBusFree(sliceData);
            SoftBusFree(dataInfo.outData);
            return ret;
        }

        SoftBusFree(sliceData);
    }
    SoftBusFree(dataInfo.outData);

    TRANS_LOGI(TRANS_CTRL, "send data success, channelId=%{public}d", channelId);
    return SOFTBUS_OK;
}

int32_t TransSendData(int32_t channelId, const void *data, uint32_t len)
{
    TransInnerSessionInfo info = { 0 };
    int32_t ret = GetSessionInfoByChanId(channelId, &info);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (info.channelType == CHANNEL_TYPE_PROXY) {
        return ProxySendData(channelId, data, len, &info);
    }
    
    return TdcSendData(channelId, data, len);
}

void CloseSessionInner(int32_t channelId)
{
    TransInnerSessionInfo info = { 0 };
    int32_t ret = GetSessionInfoByChanId(channelId, &info);
    if (ret != SOFTBUS_OK) {
        (void)TransDelSessionConnById(channelId);
        (void)TransLaneMgrDelLane(channelId, CHANNEL_TYPE_TCP_DIRECT, true);
        (void)TransProxyCloseProxyChannel(channelId);
        (void)TransLaneMgrDelLane(channelId, CHANNEL_TYPE_PROXY, true);
        return;
    }
    if (info.channelType == CHANNEL_TYPE_TCP_DIRECT) {
        DirectChannelCloseSocket(info.fd);
        TransSrvDelInnerDataBufNode(channelId);
    } else {
        (void)TransProxyDelSliceProcessorByChannelId(channelId);
        (void)TransLaneMgrDelLane(channelId, info.channelType, true);
        ret = TransProxyCloseProxyChannel(channelId);
        TRANS_LOGI(TRANS_CTRL, "ret=%{public}d, channelId=%{public}d", ret, channelId);
    }
    TRANS_LOGI(TRANS_CTRL, "fd=%{public}d, channelId=%{public}d", info.fd, channelId);
    DeleteSession(info.fd, info.channelId);
}

int32_t GetSessionInfo(int32_t channelId, int32_t *fd, int32_t *channelType, char *sessionKey, int32_t keyLen)
{
    TRANS_LOGI(TRANS_CTRL, "enter! channelId=%{public}d", channelId);
    AppInfo appInfo;
    int32_t ret = GetAppInfoById(channelId, &appInfo);
    if (ret == SOFTBUS_OK) {
        *channelType = CHANNEL_TYPE_TCP_DIRECT;
        *fd = dup(appInfo.fd);
        ret = memcpy_s(sessionKey, keyLen, appInfo.sessionKey, sizeof(appInfo.sessionKey));
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_MEM_ERR, TRANS_CTRL, "memcpy failed");
        TRANS_LOGI(TRANS_CTRL, "exit! fd=%{public}d, channelId=%{public}d", *fd, channelId);
        return SOFTBUS_OK;
    }
    *channelType = CHANNEL_TYPE_PROXY;
    *fd = -1;
    TRANS_LOGI(TRANS_CTRL, "exit! channelId=%{public}d", channelId);
    return SOFTBUS_OK;
}

int32_t InnerListInit(void)
{
    g_innerChannelSliceProcessorList = CreateSoftBusList();
    if (g_innerChannelSliceProcessorList == NULL) {
        TRANS_LOGI(TRANS_CTRL, "g_innerChannelSliceProcessorList init failed");
        return SOFTBUS_NO_INIT;
    }
    g_innerChannelDataBufList = CreateSoftBusList();
    if (g_innerChannelDataBufList == NULL) {
        TRANS_LOGI(TRANS_CTRL, "g_innerChannelDataBufList init failed");
        ClientTransInnerSliceListDeinit();
        return SOFTBUS_NO_INIT;
    }
    g_sessionList = CreateSoftBusList();
    if (g_sessionList == NULL) {
        TRANS_LOGI(TRANS_CTRL, "g_sessionList init failed");
        ClientTransInnerSliceListDeinit();
        ClientTransInnerDataBufDeinit();
        return SOFTBUS_NO_INIT;
    }
    int32_t ret = TransGetTdcDataBufMaxSize();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGI(TRANS_CTRL, "tcp data buf init failed");
        ClientTransInnerSliceListDeinit();
        ClientTransInnerDataBufDeinit();
        ClientTransInnerSessionDeinit();
        return SOFTBUS_NO_INIT;
    }
    TransGetProxyDataBufMaxSize();
    return SOFTBUS_OK;
}

void InnerListDeinit(void)
{
    TransSrvDestroyDataBuf();
    ClientTransInnerSliceListDeinit();
    ClientTransInnerDataBufDeinit();
    ClientTransInnerSessionDeinit();
}

int32_t ServerSideSendAck(int32_t sessionId, int32_t result)
{
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    AppInfo appInfo;
    int32_t ret = GetAppInfoById(sessionId, &appInfo);
    if (ret != SOFTBUS_OK) {
        channelType = CHANNEL_TYPE_PROXY;
    }
    pid_t callingPid = TransGetCallingPid();
    TRANS_LOGI(TRANS_CTRL, "channelId=%{public}d, result=%{public}d, channelType=%{public}d, callingPid=%{public}d",
        sessionId, result, channelType, callingPid);
    if (channelType == CHANNEL_TYPE_TCP_DIRECT) {
        return TransDealTdcChannelOpenResult(sessionId, result, NULL, callingPid);
    }
    return TransDealProxyChannelOpenResult(sessionId, result, NULL, callingPid);
}