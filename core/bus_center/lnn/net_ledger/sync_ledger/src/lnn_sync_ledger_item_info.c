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

#include "lnn_sync_ledger_item_info.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <securec.h>

#include "lnn_distributed_net_ledger.h"
#include "lnn_local_net_ledger.h"
#include "lnn_map.h"
#include "lnn_net_builder.h"
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_transmission_interface.h"

#define MSG_HEAD_LEN 4
#define MSG_MAX_COUNT 10
#define MSG_OFFLINE_LEN 4
#define ITEM_INFO_COUNT 10
#define CHANNEL_NAME "com.huawei.hwddmp.service.DeviceInfoSynchronize"

static uint8_t *GetDeviceNameMsg(const char *networkId, DiscoveryType discoveryType, uint32_t *bufLen);
static uint8_t *GetOfflineMsg(const char *networkId, DiscoveryType type, uint32_t *bufLen);
static uint8_t *ConvertToDeviceName(const uint8_t *msg, uint32_t len, uint32_t *outLen);
static void ReleaseMsgResources(int32_t channelId);

static ItemFunc g_itemGetFunTable[] = {
    {INFO_TYPE_DEVICE_NAME, GetDeviceNameMsg, ConvertToDeviceName},
    {INFO_TYPE_OFFLINE, GetOfflineMsg, NULL},
};
typedef enum {
    SYNC_INIT_UNKNOWN = 0,
    SYNC_INIT_FAIL,
    SYNC_INIT_SUCCESS,
} SyncLedgerStatus;

typedef struct {
    Map idMap;
    SyncLedgerStatus status;
} SyncLedgerItem;

typedef struct {
    char udid[UDID_BUF_LEN];
    SyncItemInfo *info[ITEM_INFO_COUNT];
} SyncElement;

static SyncLedgerItem g_syncLedgerItem;

static int32_t AddNewElementToMap(const char *key, const char *udid, SyncItemInfo *itemInfo)
{
    if (key == NULL || udid == NULL) {
        return SOFTBUS_INVALID_PARAM; // itemInfo may be null
    }

    SyncElement temp;
    if (memset_s(&temp, sizeof(SyncElement), 0, sizeof(SyncElement)) != EOK) {
        LOG_ERR("memset_s temp fail!");
    }
    if (strncpy_s(temp.udid, UDID_BUF_LEN, udid, strlen(udid)) != EOK) {
        LOG_ERR("strncpy_s fail!");
        return SOFTBUS_ERR;
    }
    temp.info[0] = itemInfo;
    if (LnnMapSet(&g_syncLedgerItem.idMap, key, (void *)&temp, sizeof(SyncElement)) != SOFTBUS_OK) {
        LOG_ERR("LnnMapSet fail!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ServerProccess(const char *key, const char *udid)
{
    int32_t ret;

    SyncElement *element = (SyncElement *)LnnMapGet(&g_syncLedgerItem.idMap, key);
    if (element != NULL) {
        LOG_ERR("server element should be null!");
        for (uint32_t i = 0; i < ITEM_INFO_COUNT; i++) {
            if (element->info[i] != NULL) {
                LnnDeleteSyncItemInfo(element->info[i]);
                element->info[i] = NULL;
            }
        }
        LnnMapErase(&g_syncLedgerItem.idMap, key);
    }
    ret = AddNewElementToMap(key, udid, NULL);
    return ret;
}

int32_t LnnSendMessageToPeer(int32_t channelId)
{
    char key[INT_TO_STR_SIZE] = {0};
    if (sprintf_s(key, INT_TO_STR_SIZE, "%d", channelId) == -1) {
        LOG_ERR("int convert char error!");
        return SOFTBUS_ERR;
    }
    LOG_INFO("LnnSendMessageToPeer enter channelId =%d!", channelId);
    SyncElement *element = (SyncElement *)LnnMapGet(&g_syncLedgerItem.idMap, key);
    if (element == NULL) {
        LOG_ERR("key not exist!");
        return SOFTBUS_ERR;
    }
    // send message to peer.
    for (uint32_t i = 0; i < ITEM_INFO_COUNT; i++) {
        if (element->info[i] != NULL) {
            LOG_INFO("LnnSendMessageToPeer send data!");
            TransSendNetworkingMessage(channelId, (char *)element->info[i]->buf,
                element->info[i]->bufLen, CONN_HIGH);
            LnnDeleteSyncItemInfo(element->info[i]);
            element->info[i] = NULL;
        }
    }
    (void)LnnMapErase(&g_syncLedgerItem.idMap, key);
    if (TransCloseNetWorkingChannel(channelId) != SOFTBUS_OK) {
        LOG_ERR("TransCloseNetWorkingChannel error!");
    }
    ReleaseMsgResources(channelId);
    LnnNotifySyncOfflineFinish();
    return SOFTBUS_OK;
}

static int32_t OnChannelOpened(int32_t id, const char *peerUuid, unsigned char isServer)
{
    if (peerUuid == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    LOG_INFO("OnChannelOpened enter!");
    char key[INT_TO_STR_SIZE] = {0};
    if (sprintf_s(key, INT_TO_STR_SIZE, "%d", id) == -1) {
        LOG_ERR("int convert char error!");
        return SOFTBUS_ERR;
    }
    const char *peerUdid = LnnConvertDLidToUdid(peerUuid, CATEGORY_UUID);
    if (peerUdid == NULL) {
        LOG_ERR("peerUuid not be found.");
        return SOFTBUS_ERR;
    }
    if (isServer == 0) {
        if (LnnNotifySendOfflineMessage(id) != SOFTBUS_OK) {
            if (TransCloseNetWorkingChannel(id) != SOFTBUS_OK) {
                ReleaseMsgResources(id);
                LnnNotifySyncOfflineFinish();
            }
        }
        return SOFTBUS_OK;
    }
    return ServerProccess(key, peerUdid);
}

static void ReleaseMsgResources(int32_t channelId)
{
    char key[INT_TO_STR_SIZE] = {0};
    if (sprintf_s(key, INT_TO_STR_SIZE, "%d", channelId) == -1) {
        LOG_ERR("int convert char error!");
        return;
    }
    SyncElement *element = (SyncElement *)LnnMapGet(&g_syncLedgerItem.idMap, key);
    if (element != NULL) {
        for (uint32_t i = 0; i < ITEM_INFO_COUNT; i++) {
            if (element->info[i] != NULL) {
                LnnDeleteSyncItemInfo(element->info[i]);
                element->info[i] = NULL;
            }
        }
        LnnMapErase(&g_syncLedgerItem.idMap, key);
    }
}

static void OnChannelOpenFailed(int32_t channelId, const char *uuid)
{
    (void)uuid;
    LOG_INFO("open channel fail channelId = %d", channelId);
    ReleaseMsgResources(channelId);
    LnnNotifySyncOfflineFinish();
}

static void  OnChannelClosed(int32_t channelId)
{
    ReleaseMsgResources(channelId);
    LnnNotifySyncOfflineFinish();
}

static uint8_t *ConvertToDeviceName(const uint8_t *msg, uint32_t len, uint32_t *outLen)
{
    char *buf = NULL;
    buf = SoftBusCalloc(len + 1);
    if (buf == NULL) {
        return NULL;
    }
    if (memcpy_s(buf, len, msg, len) != EOK) {
        SoftBusFree(buf);
        return NULL;
    }
    *outLen = len + 1;
    return (uint8_t*)buf;
}

static int32_t ConvertMsgToSyncItemInfo(const uint8_t *message, uint32_t len, SyncItemInfo *itemInfo)
{
    uint32_t i;
    uint32_t outLen = 0;
    if (itemInfo == NULL || message == NULL || len <= MSG_HEAD_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    itemInfo->type = (SyncItemType)(*(int32_t *)message);
    itemInfo->buf = NULL;
    itemInfo->bufLen = 0;
    for (i = 0; i < sizeof(g_itemGetFunTable) / sizeof (ItemFunc); i++) {
        if (itemInfo->type == g_itemGetFunTable[i].type && g_itemGetFunTable[i].convert != NULL) {
            itemInfo->buf = g_itemGetFunTable[i].convert(message + MSG_HEAD_LEN, len - MSG_HEAD_LEN, &outLen);
            if (itemInfo->buf != NULL) {
                itemInfo->bufLen = outLen;
                return SOFTBUS_OK;
            }
            LOG_ERR("convert fail!");
            return SOFTBUS_ERR;
        }
    }
    LOG_ERR("type not support!");
    return SOFTBUS_ERR;
}

static void OnMessageReceived(int32_t id, const char *message, uint32_t len)
{
    char *peerUdid = NULL;
    SyncItemInfo *itemInfo = NULL;
    char str[INT_TO_STR_SIZE] = {0};
    if (message == NULL || len <= MSG_HEAD_LEN) {
        return;
    }
    if (sprintf_s(str, INT_TO_STR_SIZE, "%d", id) == -1) {
        LOG_ERR("int convert char error!");
        return;
    }
    SyncElement *element  = (SyncElement *)LnnMapGet(&g_syncLedgerItem.idMap, str);
    if (element == NULL) {
        return;
    }
    peerUdid = element->udid;
    itemInfo = (SyncItemInfo *)SoftBusCalloc(sizeof(SyncItemInfo));
    if (itemInfo == NULL) {
        return;
    }
    if (ConvertMsgToSyncItemInfo((uint8_t *)message, len, itemInfo) != SOFTBUS_OK) {
        SoftBusFree(itemInfo);
        return;
    }
    // Notify netbuild report name change
    if (LnnNotifyPeerDevInfoChanged(peerUdid, itemInfo) != SOFTBUS_OK) {
        LOG_ERR("NotifyPeerDevInfoChange error!");
        LnnDeleteSyncItemInfo(itemInfo);
    }
}

static int32_t Little2Big(int32_t little)
{
    uint32_t lit = (uint32_t)little;
    return (((lit & 0xff) << 24) | ((lit & 0xff00) << 8) | ((lit & 0xff0000) >> 8) | ((lit >> 24) & 0xff));
}

static uint8_t *GetOfflineMsg(const char *networkId, DiscoveryType type, uint32_t *bufLen)
{
    if (networkId == NULL || type != DISCOVERY_TYPE_BR || bufLen == NULL) {
        LOG_ERR("fail: para error!");
        return NULL;
    }
    *bufLen = 0;
    const NodeInfo *info = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (info == NULL) {
        LOG_ERR("fail: para error!");
        return NULL;
    }

    if (!LnnHasDiscoveryType(info, type)) {
        LOG_INFO("sync offline type error type = %d.", type);
        return NULL;
    }
    short code = LnnGetCnnCode(info->uuid, type);
    if (code == INVALID_CONNECTION_CODE_VALUE) {
        LOG_ERR("uuid not exist!");
        return NULL;
    }
    int32_t infoType = INFO_TYPE_OFFLINE;
    unsigned short shortType = (unsigned short)type;
    int32_t combinedInt = ((unsigned short)code << 16) | (shortType & 0x7FFF);
    combinedInt = Little2Big(combinedInt);
    LOG_INFO("GetOfflineMsg, infoType = %d, combinedInt = %d", infoType, combinedInt);
    uint8_t *msg = (uint8_t *)SoftBusCalloc(MSG_HEAD_LEN + MSG_OFFLINE_LEN);
    if (msg == NULL) {
        return NULL;
    }
    if (memcpy_s(msg, MSG_HEAD_LEN, &infoType, sizeof(int32_t)) != EOK) {
        LOG_ERR("memcpy fail!");
        SoftBusFree(msg);
        return NULL;
    }
    if (memcpy_s(msg + MSG_HEAD_LEN, MSG_OFFLINE_LEN, &combinedInt, sizeof(int)) != EOK) {
        LOG_ERR("memcpy fail!");
        SoftBusFree(msg);
        return NULL;
    }
    *bufLen = MSG_HEAD_LEN + MSG_OFFLINE_LEN;
    return msg;
}

static uint8_t *GetDeviceNameMsg(const char *networkId, DiscoveryType discoveryType, uint32_t *bufLen)
{
    uint8_t *msg = NULL;
    const char *deviceName = NULL;
    uint32_t len;
    int32_t type = INFO_TYPE_DEVICE_NAME;
    (void)networkId;
    (void)discoveryType;
    if (bufLen == NULL) {
        LOG_ERR("fail: para error!");
        return NULL;
    }
    *bufLen = 0;
    const NodeInfo *info = LnnGetLocalNodeInfo();
    if (info == NULL) {
        return NULL;
    }
    deviceName = LnnGetDeviceName(&info->deviceInfo);
    if (deviceName == NULL) {
        return NULL;
    }
    len = strlen(deviceName) + MSG_HEAD_LEN;
    msg = SoftBusCalloc(len);
    if (msg == NULL) {
        return NULL;
    }
    if (memcpy_s(msg, MSG_HEAD_LEN, &type, MSG_HEAD_LEN) != EOK) {
        LOG_ERR("memcpy fail!");
        SoftBusFree(msg);
        return NULL;
    }
    if (memcpy_s(msg + MSG_HEAD_LEN, len - MSG_HEAD_LEN, deviceName, strlen(deviceName)) != EOK) {
        LOG_ERR("memcpy fail!");
        SoftBusFree(msg);
        return NULL;
    }
    *bufLen = len;
    return msg;
}

static int32_t GetItemInfoMsg(const char *networkId, DiscoveryType discoveryType, SyncItemInfo *itemInfo)
{
    uint32_t i;
    uint32_t outLen = 0;
    if (networkId == NULL || itemInfo == NULL) {
        LOG_ERR("fail:para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    for (i = 0; i < sizeof(g_itemGetFunTable) / sizeof (ItemFunc); i++) {
        if (itemInfo->type == g_itemGetFunTable[i].type && g_itemGetFunTable[i].get != NULL) {
            itemInfo->buf = g_itemGetFunTable[i].get(networkId, discoveryType, &outLen);
            if (itemInfo->buf != NULL) {
                itemInfo->bufLen = outLen;
                return SOFTBUS_OK;
            }
            LOG_ERR("type = %d get function error!", itemInfo->type);
            return SOFTBUS_ERR;
        }
    }
    LOG_ERR("type = %d, not support!", itemInfo->type);
    return SOFTBUS_ERR;
}

static int32_t SaveMsgToBuf(int32_t channelId, const char *udid, SyncItemInfo *itemInfo)
{
    if (channelId == INVALID_CHANNEL_ID || udid == NULL || itemInfo == NULL) {
        LOG_ERR("fail: para error channelId =%d!", channelId);
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = SOFTBUS_OK;
    char key[INT_TO_STR_SIZE] = {0};
    if (sprintf_s(key, INT_TO_STR_SIZE, "%d", channelId) == -1) {
        LOG_ERR("int convert char error!");
        return SOFTBUS_ERR;
    }
    SyncElement *element  = (SyncElement *)LnnMapGet(&g_syncLedgerItem.idMap, key);
    if (element == NULL) {
        ret = AddNewElementToMap(key, udid, itemInfo);
        goto EXIT;
    } else {
        for (uint32_t i = 0; i < ITEM_INFO_COUNT; i++) {
            if (element->info[i] == NULL) {
                element->info[i] = itemInfo;
                goto EXIT;
            }
        }
        LOG_ERR("sending buf already full and abandon the first buf!");
        element->info[0] = itemInfo;
        goto EXIT;
    }
EXIT:
    return ret;
}

static INetworkingListener  g_nodeChangeListener = {
    OnChannelOpened,
    OnChannelOpenFailed,
    OnChannelClosed,
    OnMessageReceived,
};

int32_t LnnSyncLedgerItemInfo(const char *networkId, DiscoveryType discoveryType, SyncItemType itemType)
{
    if (networkId == NULL) {
        LOG_ERR("fail: networkId = NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    LOG_INFO("LnnSyncLedgerItemInfo enter!");
    const char *udid = LnnConvertDLidToUdid(networkId, CATEGORY_NETWORK_ID);
    if (udid == NULL) {
        LOG_ERR("fail : networkId not exist!");
        return SOFTBUS_INVALID_PARAM;
    }

    SyncItemInfo *itemInfo = (SyncItemInfo *)SoftBusCalloc(sizeof(SyncItemInfo));
    if (itemInfo == NULL) {
        LOG_ERR("fail: SoftBusCalloc fail!");
        return SOFTBUS_MALLOC_ERR;
    }
    itemInfo->type = itemType;
    if (GetItemInfoMsg(networkId, discoveryType, itemInfo) != SOFTBUS_OK) {
        SoftBusFree(itemInfo);
        return SOFTBUS_ERR;
    }
    if (itemType == INFO_TYPE_OFFLINE) {
        int type = *(int *)itemInfo->buf;
        int seq = *(int *)(itemInfo->buf + MSG_HEAD_LEN);
        LOG_INFO("INFO: type = %d, seq = %d", type, seq);
    }
    int32_t channelId = TransOpenNetWorkingChannel(CHANNEL_NAME, networkId);
    LOG_INFO("OpenNetWorkingChannel channelId =%d!", channelId);
    if (SaveMsgToBuf(channelId, udid, itemInfo) != SOFTBUS_OK) {
        LOG_ERR("SaveMsgToBuf error!");
        LnnDeleteSyncItemInfo(itemInfo);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void LnnDeleteSyncItemInfo(SyncItemInfo *info)
{
    if (info == NULL) {
        return;
    }
    if (info->buf != NULL) {
        SoftBusFree(info->buf);
    }
    SoftBusFree(info);
}

int32_t LnnInitSyncLedgerItem(void)
{
    if (g_syncLedgerItem.status == SYNC_INIT_SUCCESS) {
        LOG_INFO("LnnInitSyncLedgerItem already success!");
        return SOFTBUS_OK;
    }
    LnnMapInit(&g_syncLedgerItem.idMap);
    if (TransRegisterNetworkingChannelListener(&g_nodeChangeListener) != SOFTBUS_OK) {
        g_syncLedgerItem.status = SYNC_INIT_FAIL;
        LOG_ERR("TransRegisterNetworkingChannelListener error!");
        return SOFTBUS_ERR;
    }
    g_syncLedgerItem.status = SYNC_INIT_SUCCESS;
    LOG_INFO("LnnInitSyncLedgerItem INIT success!");
    return SOFTBUS_OK;
}

void LnnDeinitSyncLedgerItem(void)
{
    LnnMapDelete(&g_syncLedgerItem.idMap);
    g_syncLedgerItem.status = SYNC_INIT_UNKNOWN;
}