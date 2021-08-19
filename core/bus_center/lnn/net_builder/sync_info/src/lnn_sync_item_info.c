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

#include "lnn_sync_item_info.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <securec.h>

#include "lnn_async_callback_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_local_net_ledger.h"
#include "lnn_map.h"
#include "lnn_net_builder.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_transmission_interface.h"

#define MSG_HEAD_LEN 4
#define MSG_MAX_COUNT 10
#define MSG_OFFLINE_LEN 4
#define ITEM_INFO_COUNT 10
#define CHANNEL_NAME "com.huawei.hwddmp.service.DeviceInfoSynchronize"
/* maximum lnn control message length */
#define MAX_LNN_CTRL_MSG_LEN 4096

#define JSON_KEY_MSG_ID "MsgId"
#define JSON_KEY_MASTER_UDID "MasterUdid"
#define JSON_KEY_MASTER_WEIGHT "MasterWeight"

static SyncItemInfo *GetDeviceNameMsg(const char *networkId, DiscoveryType discoveryType);
static SyncItemInfo *GetOfflineMsg(const char *networkId, DiscoveryType discoveryType);
static SyncItemInfo *GetElectMsg(const char *networkId, DiscoveryType discoveryType);
static int32_t ReceiveDeviceName(uint8_t *msg, uint32_t len, const SyncItemInfo *info);
static int32_t ReceiveElectMsg(uint8_t *msg, uint32_t len, const SyncItemInfo *info);

static ItemFunc g_itemGetFunTable[] = {
    {INFO_TYPE_DEVICE_NAME, GetDeviceNameMsg, ReceiveDeviceName},
    {INFO_TYPE_OFFLINE, GetOfflineMsg, NULL},
    {INFO_TYPE_MASTER_ELECT, GetElectMsg, ReceiveElectMsg}
};

typedef enum {
    SYNC_INIT_UNKNOWN = 0,
    SYNC_INIT_FAIL,
    SYNC_INIT_SUCCESS,
} SyncLedgerStatus;

typedef enum {
    TRANS_CHANNEL_EVENT_OPENED,
    TRANS_CHANNEL_EVENT_OPEN_FAILED,
    TRANS_CHANNEL_EVENT_CLOSED
} TransChannelEvent;

typedef struct {
    Map idMap; // channelId-->SyncItemInfo
    SyncLedgerStatus status;
} SyncLedgerItem;

typedef struct {
    int32_t channelId;
    TransChannelEvent event;
    char peerUuid[UUID_BUF_LEN];
    bool isServer;
} ChannelEventMsgPara;

typedef struct {
    int32_t channelId;
    uint8_t *data;
    uint32_t len;
} ChannelDataMsgPara;

static SyncLedgerItem g_syncLedgerItem;

static char *PackElectMessage(int32_t weight, const char *masterUdid)
{
    char *data = NULL;
    cJSON *json = cJSON_CreateObject();

    if (json == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "create elect json object failed");
        return NULL;
    }
    if (!AddStringToJsonObject(json, JSON_KEY_MASTER_UDID, masterUdid) ||
        !AddNumberToJsonObject(json, JSON_KEY_MASTER_WEIGHT, weight)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "add elect info to json failed");
        cJSON_Delete(json);
        return NULL;
    }
    data = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    return data;
}

static int32_t UnpackElectMessage(const char *msg, uint32_t len,
    char *masterUdid, int32_t masterUdidLen, int32_t *masterWeight)
{
    cJSON *json = cJSON_Parse((char *)msg);

    if (json == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parse elect msg json fail");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!GetJsonObjectNumberItem(json, JSON_KEY_MASTER_WEIGHT, masterWeight) ||
        !GetJsonObjectStringItem(json, JSON_KEY_MASTER_UDID, masterUdid, masterUdidLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parse master info json fail");
        cJSON_Delete(json);
        return SOFTBUS_INVALID_PARAM;
    }
    cJSON_Delete(json);
    return SOFTBUS_OK;
}

static void RemoveMsgFromMap(const char *key)
{
    (void)LnnMapErase(&g_syncLedgerItem.idMap, key);
}

static int32_t SaveMsgToMap(int32_t channelId, SyncItemInfo *itemInfo)
{
    char key[INT_TO_STR_SIZE] = {0};

    if (channelId == INVALID_CHANNEL_ID || itemInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: para error channelId =%d", channelId);
        return SOFTBUS_INVALID_PARAM;
    }
    if (sprintf_s(key, INT_TO_STR_SIZE, "%d", channelId) == -1) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "int convert char error: %d", itemInfo->type);
        return SOFTBUS_ERR;
    }
    SyncItemInfo *info = (SyncItemInfo *)LnnMapGet(&g_syncLedgerItem.idMap, key);
    if (info != NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "send buf already exist, abandon the previous: %d",
            itemInfo->type);
        (void)LnnMapErase(&g_syncLedgerItem.idMap, key);
    }
    if (LnnMapSet(&g_syncLedgerItem.idMap, key, (void *)info, sizeof(SyncItemInfo)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnMapSet fail: %d", itemInfo->type);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ServerProccess(const char *key, const char *udid)
{
    int32_t rc;
    SyncItemInfo *info = (SyncItemInfo *)LnnMapGet(&g_syncLedgerItem.idMap, key);
    if (info != NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "server element should be null!");
        LnnMapErase(&g_syncLedgerItem.idMap, key);
    }
    info = (SyncItemInfo *)SoftBusCalloc(sizeof(SyncItemInfo));
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc empty sync item info fail");
        return SOFTBUS_MEM_ERR;
    }
    if (strncpy_s(info->udid, UDID_BUF_LEN, udid, strlen(udid)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy uuid to sync item info fail");
        SoftBusFree(info);
        return SOFTBUS_ERR;
    }
    rc = LnnMapSet(&g_syncLedgerItem.idMap, key, info, sizeof(SyncItemInfo));
    SoftBusFree(info);
    return rc;
}

static int32_t SendMessageToPeer(int32_t channelId)
{
    char key[INT_TO_STR_SIZE] = {0};

    if (sprintf_s(key, INT_TO_STR_SIZE, "%d", channelId) == -1) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "format channelId to key fail");
        return SOFTBUS_ERR;
    }
    SyncItemInfo *info = (SyncItemInfo *)LnnMapGet(&g_syncLedgerItem.idMap, key);
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sync item info key not exist");
        return SOFTBUS_ERR;
    }
    if (TransSendNetworkingMessage(channelId, (char *)info->buf, info->bufLen, CONN_HIGH) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "trans send data fail");
    }
    if (TransCloseNetWorkingChannel(channelId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "TransCloseNetWorkingChannel error!");
    }
    if (info->type == INFO_TYPE_OFFLINE) {
        LnnNotifySyncOfflineFinish(info->udid);
    }
    RemoveMsgFromMap(key);
    return SOFTBUS_OK;
}

static int32_t HandleChannelOpened(const ChannelEventMsgPara *msgPara)
{
    char key[INT_TO_STR_SIZE] = {0};
    int32_t rc;

    if (msgPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "channel opened msg para is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (msgPara->isServer) {
        const char *peerUdid = LnnConvertDLidToUdid(msgPara->peerUuid, CATEGORY_UUID);
        if (peerUdid == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "peerUuid not be found.");
            SoftBusFree((void *)msgPara);
            return SOFTBUS_ERR;
        }
        if (sprintf_s(key, INT_TO_STR_SIZE, "%d", msgPara->channelId) == -1) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "format channelId to key fail");
            SoftBusFree((void *)msgPara);
            return SOFTBUS_ERR;
        }
        rc = ServerProccess(key, peerUdid);
    } else {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "channel opened, send message to peer");
        rc = SendMessageToPeer(msgPara->channelId);
    }
    SoftBusFree((void *)msgPara);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "handle channel opened msg result: %d", rc);
    return rc;
}

static int32_t ClearSyncItemInfo(const ChannelEventMsgPara *msgPara)
{
    char key[INT_TO_STR_SIZE] = {0};
    int32_t rc = SOFTBUS_ERR;

    do {
        if (sprintf_s(key, INT_TO_STR_SIZE, "%d", msgPara->channelId) == -1) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "format channelId to key fail");
            break;
        }
        SyncItemInfo *info = (SyncItemInfo *)LnnMapGet(&g_syncLedgerItem.idMap, key);
        if (info == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sync item info key not exist");
            break;
        }
        if (info->type == INFO_TYPE_OFFLINE) {
            LnnNotifySyncOfflineFinish(info->udid);
        }
        RemoveMsgFromMap(key);
        rc = SOFTBUS_OK;
    } while (false);
    return rc;
}

static int32_t HandleChannelOpenFailed(const ChannelEventMsgPara *msgPara)
{
    int32_t rc;

    if (msgPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "channel open failed msg para is null");
        return SOFTBUS_INVALID_PARAM;
    }
    rc = ClearSyncItemInfo(msgPara);
    SoftBusFree((void *)msgPara);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "handle channel opened failed msg result: %d", rc);
    return rc;
}

static int32_t HandleChannelClosed(const ChannelEventMsgPara *msgPara)
{
    int32_t rc;

    if (msgPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "channel closed msg para is null");
        return SOFTBUS_INVALID_PARAM;
    }
    rc = ClearSyncItemInfo(msgPara);
    SoftBusFree((void *)msgPara);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "handle channel closed msg result: %d", rc);
    return rc;
}

static void ChannelEventHandler(void *para)
{
    ChannelEventMsgPara *msgPara = (ChannelEventMsgPara *)para;

    if (msgPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ChannelEventHandler: null para");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "handle channel event: %d, channelId=%d",
        msgPara->event, msgPara->channelId);
    switch (msgPara->event) {
        case TRANS_CHANNEL_EVENT_OPENED:
            HandleChannelOpened(para);
            break;
        case TRANS_CHANNEL_EVENT_OPEN_FAILED:
            HandleChannelOpenFailed(para);
            break;
        case TRANS_CHANNEL_EVENT_CLOSED:
            HandleChannelClosed(para);
            break;
        default:
            break;
    }
}

static int32_t ReceiveDeviceName(uint8_t *msg, uint32_t len, const SyncItemInfo *info)
{
    msg[len - 1] = '\0';
    if (!LnnSetDLDeviceInfoName(info->udid, (char *)msg)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "set peer device name fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ReceiveElectMsg(uint8_t *msg, uint32_t len, const SyncItemInfo *info)
{
    char masterUdid[UDID_BUF_LEN] = {0};
    int32_t masterWeight = -1;

    msg[len - 1] = '\0';
    if (UnpackElectMessage((char *)msg, len, masterUdid, UDID_BUF_LEN, &masterWeight) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "unpack elect message fail");
        return SOFTBUS_ERR;
    }
    return LnnNotifyMasterElect(info->udid, masterUdid, masterWeight);
}

static int32_t DispatchReceivedData(uint8_t *message, uint32_t len, SyncItemInfo *info)
{
    uint32_t i;

    if (message == NULL || len <= MSG_HEAD_LEN || len > MAX_LNN_CTRL_MSG_LEN) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid data msg para");
        return SOFTBUS_INVALID_PARAM;
    }
    info->type = (SyncItemType)(*(int32_t *)message);
    for (i = 0; i < sizeof(g_itemGetFunTable) / sizeof (ItemFunc); i++) {
        if (info->type != g_itemGetFunTable[i].type) {
            continue;
        }
        if (g_itemGetFunTable[i].receive != NULL) {
            return g_itemGetFunTable[i].receive(message + MSG_HEAD_LEN, len - MSG_HEAD_LEN, info);
        }
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "not support type=%d", info->type);
    return SOFTBUS_ERR;
}

static void ChannelDataHandler(void *para)
{
    ChannelDataMsgPara *msgPara = (ChannelDataMsgPara *)para;
    SyncItemInfo *info = NULL;
    char key[INT_TO_STR_SIZE] = {0};
    int32_t rc = SOFTBUS_ERR;

    if (msgPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid channel data msg para");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "handle channel data msg, channelId = %d", msgPara->channelId);
    do {
        if (sprintf_s(key, INT_TO_STR_SIZE, "%d", msgPara->channelId) == -1) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "format channelId to key fail");
            break;
        }
        info = (SyncItemInfo *)LnnMapGet(&g_syncLedgerItem.idMap, key);
        if (info == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sync item info key not exist");
            break;
        }
        rc = DispatchReceivedData(msgPara->data, msgPara->len, info);
        RemoveMsgFromMap(key);
    } while (false);
    SoftBusFree(msgPara);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "handle channel data msg result: %d", rc);
}

static int32_t SendChannelEventMsg(int32_t channelId, TransChannelEvent event,
    const char *peerUuid, bool isServer)
{
    ChannelEventMsgPara *para = NULL;

    para = (ChannelEventMsgPara *)SoftBusCalloc(sizeof(ChannelEventMsgPara));
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc channel open msg para fail");
        return SOFTBUS_MEM_ERR;
    }
    para->channelId = channelId;
    para->event = event;
    para->isServer = isServer ? true : false;
    if (peerUuid != NULL && strncpy_s(para->peerUuid, UUID_BUF_LEN, peerUuid, strlen(peerUuid)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy peer uuid to msg para fail");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    if (LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), ChannelEventHandler, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "async handle channel opened message fail");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t OnChannelOpened(int32_t channelId, const char *peerUuid, unsigned char isServer)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "OnChannelOpened enter, server: %u", isServer);
    return SendChannelEventMsg(channelId, TRANS_CHANNEL_EVENT_OPENED, peerUuid, isServer ? true : false);
}

static void OnChannelOpenFailed(int32_t channelId, const char *peerUuid)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "open channel fail channelId = %d", channelId);
    (void)SendChannelEventMsg(channelId, TRANS_CHANNEL_EVENT_OPEN_FAILED, peerUuid, true);
}

static void OnChannelClosed(int32_t channelId)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "channel closed, channelId = %d", channelId);
    (void)SendChannelEventMsg(channelId, TRANS_CHANNEL_EVENT_CLOSED, NULL, false);
}

static void OnMessageReceived(int32_t channelId, const char *data, uint32_t len)
{
    ChannelDataMsgPara *para = NULL;

    if (data == NULL || len <= MSG_HEAD_LEN || len > MAX_LNN_CTRL_MSG_LEN) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid channel data para");
        return;
    }
    para = (ChannelDataMsgPara *)SoftBusMalloc(sizeof(ChannelDataMsgPara) + len);
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc channel data msg para fail");
        return;
    }
    para->channelId = channelId;
    para->data = (uint8_t *)para + sizeof(ChannelDataMsgPara);
    para->len = len;
    if (memcpy_s(para->data, len, data, len) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy data to msg para fail");
        SoftBusFree(para);
        return;
    }
    if (LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), ChannelDataHandler, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "async handle channel opened message fail");
    }
    SoftBusFree(para);
}

static int32_t FillSyncItemInfo(const char *networkId, SyncItemInfo *info, SyncItemType type,
    const uint8_t *data, uint32_t dataLen)
{
    info->type = type;
    if (LnnGetDLStrInfo(networkId, STRING_KEY_DEV_UDID, info->udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get udid fail");
        return SOFTBUS_ERR;
    }
    info->buf = (uint8_t *)info + sizeof(SyncItemInfo);
    if (memcpy_s(info->buf, MSG_HEAD_LEN, &info->type, MSG_HEAD_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcpy item info type fail");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(info->buf + MSG_HEAD_LEN, info->bufLen - MSG_HEAD_LEN, data, dataLen) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcpy data buffer fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t Little2Big(int32_t little)
{
    uint32_t lit = (uint32_t)little;
    return (((lit & 0xff) << 24) | ((lit & 0xff00) << 8) | ((lit & 0xff0000) >> 8) | ((lit >> 24) & 0xff));
}

static SyncItemInfo *GetOfflineMsg(const char *networkId, DiscoveryType discoveryType)
{
    SyncItemInfo *itemInfo = NULL;
    NodeInfo *nodeInfo = NULL;
    int16_t code;
    int32_t combinedInt;

    if (discoveryType != DISCOVERY_TYPE_BR) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: para error!");
        return NULL;
    }
    nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get node info fail");
        return NULL;
    }
    if (!LnnHasDiscoveryType(nodeInfo, discoveryType)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "sync offline type error type = %d.", discoveryType);
        return NULL;
    }
    code = LnnGetCnnCode(nodeInfo->uuid, discoveryType);
    if (code == INVALID_CONNECTION_CODE_VALUE) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "uuid not exist!");
        return NULL;
    }
    combinedInt = ((unsigned short)code << 16) | ((unsigned short)discoveryType & 0x7FFF);
    combinedInt = Little2Big(combinedInt);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "GetOfflineMsg combinedInt = %d", combinedInt);
    itemInfo = (SyncItemInfo *)SoftBusMalloc(sizeof(SyncItemInfo) + MSG_HEAD_LEN + MSG_OFFLINE_LEN);
    if (itemInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc sync offline info fail");
        return NULL;
    }
    itemInfo->bufLen = MSG_HEAD_LEN + MSG_OFFLINE_LEN;
    if (FillSyncItemInfo(networkId, itemInfo, INFO_TYPE_OFFLINE,
        (uint8_t *)&combinedInt, sizeof(int)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fill sync offline info fail");
        SoftBusFree(itemInfo);
        return NULL;
    }
    return itemInfo;
}

static SyncItemInfo *GetDeviceNameMsg(const char *networkId, DiscoveryType discoveryType)
{
    SyncItemInfo *itemInfo = NULL;
    const char *deviceName = NULL;
    uint32_t len;

    (void)discoveryType;
    const NodeInfo *info = LnnGetLocalNodeInfo();
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local node info fail");
        return NULL;
    }
    deviceName = LnnGetDeviceName(&info->deviceInfo);
    if (deviceName == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get device name fail");
        return NULL;
    }
    len = strlen(deviceName) + 1 + MSG_HEAD_LEN;
    itemInfo = SoftBusMalloc(sizeof(SyncItemInfo) + len);
    if (itemInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc sync item info for device name fail");
        return NULL;
    }
    itemInfo->bufLen = len;
    if (FillSyncItemInfo(networkId, itemInfo, INFO_TYPE_DEVICE_NAME,
        (const uint8_t *)deviceName, strlen(deviceName) + 1) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fill sync item info fail");
        SoftBusFree(itemInfo);
        return NULL;
    }
    return itemInfo;
}

static SyncItemInfo *GetElectMsg(const char *networkId, DiscoveryType discoveryType)
{
    SyncItemInfo *itemInfo = NULL;
    uint32_t len;
    char *data = NULL;
    char masterUdid[UDID_BUF_LEN] = {0};
    int32_t masterWeight;

    (void)discoveryType;
    if (LnnGetLocalLedgerStrInfo(STRING_KEY_MASTER_NODE_UDID, masterUdid, UDID_BUF_LEN) != SOFTBUS_OK ||
        LnnGetLocalLedgerNumInfo(NUM_KEY_MASTER_NODE_WEIGHT, &masterWeight) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local master node info failed");
        return NULL;
    }
    data = PackElectMessage(masterWeight, masterUdid);
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "pack elect packet fail");
        return NULL;
    }
    len = strlen(data) + 1 + MSG_HEAD_LEN;
    itemInfo = SoftBusMalloc(sizeof(SyncItemInfo) + len);
    if (itemInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc sync item info for device name fail");
        cJSON_free(data);
        return NULL;
    }
    itemInfo->bufLen = len;
    if (FillSyncItemInfo(networkId, itemInfo, INFO_TYPE_MASTER_ELECT,
        (const uint8_t *)data, strlen(data) + 1) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fill sync item info fail");
        SoftBusFree(itemInfo);
        cJSON_free(data);
        return NULL;
    }
    cJSON_free(data);
    return itemInfo;
}

static SyncItemInfo *GetItemInfoMsg(const char *networkId, DiscoveryType discoveryType, SyncItemType itemType)
{
    uint32_t i;
    SyncItemInfo *itemInfo = NULL;

    for (i = 0; i < sizeof(g_itemGetFunTable) / sizeof (ItemFunc); i++) {
        if (itemType == g_itemGetFunTable[i].type && g_itemGetFunTable[i].get != NULL) {
            itemInfo = g_itemGetFunTable[i].get(networkId, discoveryType);
            if (itemInfo == NULL) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get item info fail, type = %d", itemType);
            }
            return itemInfo;
        }
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "not support item, type = %d", itemType);
    return NULL;
}

static INetworkingListener  g_nodeChangeListener = {
    OnChannelOpened,
    OnChannelOpenFailed,
    OnChannelClosed,
    OnMessageReceived,
};

int32_t LnnSyncLedgerItemInfo(const char *networkId, DiscoveryType discoveryType, SyncItemType itemType)
{
    SyncItemInfo *info = NULL;
    int32_t channelId;

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LnnSyncLedgerItemInfo type=%d", itemType);
    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: networkId = NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    info = GetItemInfoMsg(networkId, discoveryType, itemType);
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get item info failed, type=%d", itemType);
        return SOFTBUS_ERR;
    }
    if (itemType == INFO_TYPE_OFFLINE) {
        int type = *(int *)info->buf;
        int seq = *(int *)(info->buf + MSG_HEAD_LEN);
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "INFO: type = %d, seq = %d", type, seq);
    }
    channelId = TransOpenNetWorkingChannel(CHANNEL_NAME, networkId);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "OpenNetWorkingChannel channelId =%d!", channelId);
    if (SaveMsgToMap(channelId, info) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "save message to buffer fail, type=%d", itemType);
        SoftBusFree(info);
        return SOFTBUS_ERR;
    }
    SoftBusFree(info);
    return SOFTBUS_OK;
}

int32_t LnnInitSyncLedgerItem(void)
{
    if (g_syncLedgerItem.status == SYNC_INIT_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LnnInitSyncLedgerItem already success!");
        return SOFTBUS_OK;
    }
    LnnMapInit(&g_syncLedgerItem.idMap);
    if (TransRegisterNetworkingChannelListener(&g_nodeChangeListener) != SOFTBUS_OK) {
        g_syncLedgerItem.status = SYNC_INIT_FAIL;
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "TransRegisterNetworkingChannelListener error!");
        return SOFTBUS_ERR;
    }
    g_syncLedgerItem.status = SYNC_INIT_SUCCESS;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LnnInitSyncLedgerItem INIT success!");
    return SOFTBUS_OK;
}

void LnnDeinitSyncLedgerItem(void)
{
    LnnMapDelete(&g_syncLedgerItem.idMap);
    g_syncLedgerItem.status = SYNC_INIT_UNKNOWN;
}