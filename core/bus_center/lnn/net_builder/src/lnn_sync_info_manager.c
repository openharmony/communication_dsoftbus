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

#include "lnn_sync_info_manager.h"

#include <securec.h>
#include <string.h>

#include "anonymizer.h"
#include "auth_manager.h"
#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "common_list.h"
#include "lnn_async_callback_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_net_builder.h"
#include "lnn_log.h"
#include "message_handler.h"
#include "softbus_adapter_json.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_timer.h"
#include "softbus_bus_center.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_transmission_interface.h"

#define MSG_HEAD_LEN 4
#define MAX_SYNC_INFO_MSG_LEN 4096
#define UNUSED_CHANNEL_CLOSED_DELAY (60 * 1000)
#define TIME_CONVERSION_UNIT 1000
#define CHANNEL_NAME "com.huawei.hwddmp.service.DeviceInfoSynchronize"
#define WIFI_OFFLINE_CODE_LEN 4
#define NETWORK_SYNC_CONN_CAP "conn_cap_long"
#define NETWORK_SYNC_TYPE "networking_type"
#define NETWORK_SYNC_SEQ "auth_seq"
#define NETWORK_OFFLINE_PORT "offline_port"
#define NETWORK_OFFLINE_CODE "offline_code"

typedef struct {
    ListNode node;
    LnnSyncInfoMsgComplete complete;
    uint32_t dataLen;
    uint8_t data[0];
} SyncInfoMsg;

typedef struct {
    ListNode node;
    ListNode syncMsgList;
    char networkId[NETWORK_ID_BUF_LEN];
    int32_t clientChannelId;
    int32_t serverChannelId;
    SoftBusSysTime accessTime;
    bool isClientOpened;
} SyncChannelInfo;

typedef struct {
    ListNode channelInfoList;
    LnnSyncInfoMsgHandler handlers[LNN_INFO_TYPE_COUNT];
    SoftBusMutex lock;
} SyncInfoManager;

static SyncInfoManager g_syncInfoManager;

static void ClearSyncInfoMsg(SyncChannelInfo *info, ListNode *list)
{
    SyncInfoMsg *item = NULL;
    SyncInfoMsg *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, list, SyncInfoMsg, node) {
        ListDelete(&item->node);
        if (item->complete != NULL) {
            item->complete((LnnSyncInfoType)(*(uint32_t *)item->data), info->networkId,
                &item->data[MSG_HEAD_LEN], item->dataLen - MSG_HEAD_LEN);
        }
        SoftBusFree(item);
    }
}

static void ClearSyncChannelInfo(void)
{
    SyncChannelInfo *item = NULL;
    SyncChannelInfo *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_syncInfoManager.channelInfoList, SyncChannelInfo, node) {
        ListDelete(&item->node);
        ClearSyncInfoMsg(item, &item->syncMsgList);
        SoftBusFree(item);
    }
}

static SyncChannelInfo *FindSyncChannelInfoByNetworkId(const char *networkId)
{
    SyncChannelInfo *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_syncInfoManager.channelInfoList, SyncChannelInfo, node) {
        if (strcmp(item->networkId, networkId) == 0) {
            return item;
        }
    }
    return NULL;
}

static SyncChannelInfo *FindSyncChannelInfoByChannelId(int32_t channelId)
{
    SyncChannelInfo *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_syncInfoManager.channelInfoList, SyncChannelInfo, node) {
        if (item->clientChannelId == channelId || item->serverChannelId == channelId) {
            return item;
        }
    }
    return NULL;
}

static SyncChannelInfo *CreateSyncChannelInfo(const char *networkId)
{
    SyncChannelInfo *item = (SyncChannelInfo *)SoftBusMalloc(sizeof(SyncChannelInfo));
    if (item == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc sync channel info fail");
        return NULL;
    }
    ListInit(&item->node);
    ListInit(&item->syncMsgList);
    if (strcpy_s(item->networkId, NETWORK_ID_BUF_LEN, networkId) != EOK) {
        LNN_LOGE(LNN_BUILDER, "copy network id to sync channel info fail");
        SoftBusFree(item);
        return NULL;
    }
    item->clientChannelId = INVALID_CHANNEL_ID;
    item->serverChannelId = INVALID_CHANNEL_ID;
    SoftBusGetTime(&item->accessTime);
    item->isClientOpened = false;
    return item;
}

static SyncInfoMsg *CreateSyncInfoMsg(LnnSyncInfoType type, const uint8_t *msg,
    uint32_t len, LnnSyncInfoMsgComplete complete)
{
    uint32_t dataLen = len + MSG_HEAD_LEN;
    SyncInfoMsg *syncMsg = NULL;

    if (dataLen > MAX_SYNC_INFO_MSG_LEN) {
        LNN_LOGE(LNN_BUILDER, "sync info msg length too large. type=%{public}d, len=%{public}u",
            type, dataLen);
        return NULL;
    }
    syncMsg = (SyncInfoMsg *)SoftBusMalloc(sizeof(SyncInfoMsg) + dataLen);
    if (syncMsg == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc sync info msg fail. type=%{public}d, len=%{public}u",
            type, dataLen);
        return NULL;
    }
    *(int32_t *)syncMsg->data = type;
    if (memcpy_s(syncMsg->data + MSG_HEAD_LEN, dataLen - MSG_HEAD_LEN, msg, len) != EOK) {
        LNN_LOGE(LNN_BUILDER, "copy sync info msg fail. type=%{public}d, len=%{public}u",
            type, dataLen);
        SoftBusFree(syncMsg);
        return NULL;
    }
    ListInit(&syncMsg->node);
    syncMsg->complete = complete;
    syncMsg->dataLen = dataLen;
    return syncMsg;
}

static void SendSyncInfoMsgOnly(const char *networkId, int32_t clientChannelId, SyncInfoMsg *msg)
{
    LNN_LOGI(LNN_BUILDER, "only send sync info");
    if (TransSendNetworkingMessage(clientChannelId, (char *)msg->data, msg->dataLen, CONN_HIGH) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "trans send data fail");
    }
    if (msg->complete != NULL) {
        msg->complete((LnnSyncInfoType)(*(uint32_t *)msg->data), networkId,
            &msg->data[MSG_HEAD_LEN], msg->dataLen - MSG_HEAD_LEN);
    }
    SoftBusFree(msg);
}

static void SendSyncInfoMsg(SyncChannelInfo *info, SyncInfoMsg *msg)
{
    if (TransSendNetworkingMessage(info->clientChannelId, (char *)msg->data, msg->dataLen, CONN_HIGH) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "trans send data fail");
    }
    SoftBusGetTime(&info->accessTime);
    ListDelete(&msg->node);
    if (msg->complete != NULL) {
        msg->complete((LnnSyncInfoType)(*(uint32_t *)msg->data), info->networkId,
            &msg->data[MSG_HEAD_LEN], msg->dataLen - MSG_HEAD_LEN);
    }
    SoftBusFree(msg);
}

static void CloseUnusedChannel(void *para)
{
    SyncChannelInfo *item = NULL;
    SyncChannelInfo *itemNext = NULL;
    SoftBusSysTime now;
    int64_t diff;

    (void)para;
    LNN_LOGI(LNN_BUILDER, "try close unused channel");
    if (SoftBusMutexLock(&g_syncInfoManager.lock) != 0) {
        LNN_LOGE(LNN_BUILDER, "close unused channel lock fail");
        return;
    }
    SoftBusGetTime(&now);
    LIST_FOR_EACH_ENTRY_SAFE(item, itemNext, &g_syncInfoManager.channelInfoList, SyncChannelInfo, node) {
        if (!IsListEmpty(&item->syncMsgList)) {
            continue;
        }
        if (item->clientChannelId == INVALID_CHANNEL_ID) {
            continue;
        }
        diff = (now.sec - item->accessTime.sec) * TIME_CONVERSION_UNIT +
            (now.usec - item->accessTime.usec) / TIME_CONVERSION_UNIT;
        if (diff <= UNUSED_CHANNEL_CLOSED_DELAY) {
            continue;
        }
        (void)TransCloseNetWorkingChannel(item->clientChannelId);
        item->clientChannelId = INVALID_CHANNEL_ID;
        item->isClientOpened = false;
        if (item->serverChannelId == INVALID_CHANNEL_ID) {
            ListDelete(&item->node);
            SoftBusFree(item);
        }
    }
    if (!IsListEmpty(&g_syncInfoManager.channelInfoList)) {
        (void)LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT),
            CloseUnusedChannel, NULL, UNUSED_CHANNEL_CLOSED_DELAY);
    }
    (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
}

static void ResetOpenChannelInfo(int32_t channelId, unsigned char isServer, SyncChannelInfo *info)
{
    SyncInfoMsg *msg = NULL;
    SyncInfoMsg *msgNext = NULL;

    SoftBusGetTime(&info->accessTime);
    if (isServer) {
        if (info->serverChannelId != channelId && info->serverChannelId != INVALID_CHANNEL_ID) {
            LNN_LOGD(LNN_BUILDER, "reset sync info server channel. serverChannelId=%{public}d, channelId=%{public}d",
                info->serverChannelId, channelId);
            (void)TransCloseNetWorkingChannel(info->serverChannelId);
        }
        info->serverChannelId = channelId;
    } else {
        info->isClientOpened = true;
        if (info->clientChannelId != channelId && info->clientChannelId != INVALID_CHANNEL_ID) {
            LNN_LOGD(LNN_BUILDER, "reset sync info client channel. clientChannelId=%{public}d, channelId=%{public}d",
                info->clientChannelId, channelId);
            (void)TransCloseNetWorkingChannel(info->clientChannelId);
        }
        info->clientChannelId = channelId;
        LIST_FOR_EACH_ENTRY_SAFE(msg, msgNext, &info->syncMsgList, SyncInfoMsg, node) {
            SendSyncInfoMsg(info, msg);
        }
    }
}

static int32_t OnChannelOpened(int32_t channelId, const char *peerUuid, unsigned char isServer)
{
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    SyncChannelInfo *info = NULL;

    LNN_LOGI(LNN_BUILDER, "channelId=%{public}d, server=%{public}u", channelId, isServer);
    if (LnnConvertDlId(peerUuid, CATEGORY_UUID, CATEGORY_NETWORK_ID, networkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGI(LNN_BUILDER, "peer device not online");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_syncInfoManager.lock) != 0) {
        LNN_LOGE(LNN_BUILDER, "sync channel opened lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    info = FindSyncChannelInfoByNetworkId(networkId);
    if (info == NULL) {
        if (!isServer) {
            LNN_LOGI(LNN_BUILDER, "unexpected client channel opened");
            (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
            return SOFTBUS_INVALID_PARAM;
        }
        info = CreateSyncChannelInfo(networkId);
        if (info == NULL) {
            (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
            return SOFTBUS_MALLOC_ERR;
        }
        if (IsListEmpty(&g_syncInfoManager.channelInfoList)) {
            (void)LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT),
                CloseUnusedChannel, NULL, UNUSED_CHANNEL_CLOSED_DELAY);
        }
        info->serverChannelId = channelId;
        ListNodeInsert(&g_syncInfoManager.channelInfoList, &info->node);
    } else {
        ResetOpenChannelInfo(channelId, isServer, info);
    }
    (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
    return SOFTBUS_OK;
}

static void OnChannelCloseCommon(SyncChannelInfo *info, int32_t channelId)
{
    if (info->serverChannelId == channelId) {
        info->serverChannelId = INVALID_CHANNEL_ID;
    } else {
        ClearSyncInfoMsg(info, &info->syncMsgList);
        info->clientChannelId = INVALID_CHANNEL_ID;
        info->isClientOpened = false;
        if (info->serverChannelId == INVALID_CHANNEL_ID) {
            LNN_LOGI(LNN_BUILDER, "free empty sync channel info");
            ListDelete(&info->node);
            SoftBusFree(info);
        }
    }
}

static void OnChannelOpenFailed(int32_t channelId, const char *peerUuid)
{
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    SyncChannelInfo *info = NULL;

    LNN_LOGI(LNN_BUILDER, "open channel fail. channelId=%{public}d", channelId);
    if (LnnConvertDlId(peerUuid, CATEGORY_UUID, CATEGORY_NETWORK_ID, networkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGI(LNN_BUILDER, "peer device not online");
        return;
    }
    if (SoftBusMutexLock(&g_syncInfoManager.lock) != 0) {
        LNN_LOGE(LNN_BUILDER, "sync channel opened failed lock fail");
        return;
    }
    info = FindSyncChannelInfoByNetworkId(networkId);
    if (info == NULL || (info->clientChannelId != channelId && info->serverChannelId != channelId)) {
        LNN_LOGE(LNN_BUILDER, "unexpected channel open fail event");
        (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
        return;
    }
    OnChannelCloseCommon(info, channelId);
    (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
}

static void OnChannelClosed(int32_t channelId)
{
    SyncChannelInfo *info = NULL;

    LNN_LOGI(LNN_BUILDER, "channel closed, channelId=%{public}d", channelId);
    if (SoftBusMutexLock(&g_syncInfoManager.lock) != 0) {
        LNN_LOGE(LNN_BUILDER, "sync channel opened failed lock fail");
        return;
    }
    info = FindSyncChannelInfoByChannelId(channelId);
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "unexpected channel closed event");
        (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
        return;
    }
    OnChannelCloseCommon(info, channelId);
    (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
}

static void OnMessageReceived(int32_t channelId, const char *data, uint32_t len)
{
    SyncChannelInfo *info = NULL;
    LnnSyncInfoType type;
    LnnSyncInfoMsgHandler handler;
    char networkId[NETWORK_ID_BUF_LEN] = {0};

    if (data == NULL) {
        LNN_LOGE(LNN_BUILDER, "recv NULL data, channelId=%{public}d", channelId);
        return;
    }
    if (len <= MSG_HEAD_LEN || len > MAX_SYNC_INFO_MSG_LEN) {
        LNN_LOGE(LNN_BUILDER, "invalid msg. len=%{public}d", len);
        return;
    }
    LNN_LOGI(LNN_BUILDER, "recv sync info msg. type=%{public}d, channelId=%{public}d, len=%{public}d",
        (LnnSyncInfoType)(*(int32_t *)data), channelId, len);
    if (SoftBusMutexLock(&g_syncInfoManager.lock) != 0) {
        LNN_LOGE(LNN_BUILDER, "sync channel opened failed lock fail");
        return;
    }
    info = FindSyncChannelInfoByChannelId(channelId);
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "unexpected channel data received event");
        (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
        return;
    }
    type = (LnnSyncInfoType)(*(int32_t *)data);
    if (type < 0 || type >= LNN_INFO_TYPE_COUNT) {
        LNN_LOGE(LNN_BUILDER, "received data is exception");
        (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
        return;
    }
    handler = g_syncInfoManager.handlers[type];
    if (handler == NULL) {
        (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
        return;
    }
    if (strcpy_s(networkId, NETWORK_ID_BUF_LEN, info->networkId) != EOK) {
        LNN_LOGE(LNN_BUILDER, "copy networkId fail");
        (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
        return;
    }
    SoftBusGetTime(&info->accessTime);
    (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
    handler(type, networkId, (const uint8_t *)&data[MSG_HEAD_LEN], len - MSG_HEAD_LEN);
}

static INetworkingListener g_networkListener = {
    OnChannelOpened,
    OnChannelOpenFailed,
    OnChannelClosed,
    OnMessageReceived,
};

static char *PackBleOfflineMsg(int64_t connCap, int32_t networkType, int64_t authSeq)
{
    JsonObj *json = JSON_CreateObject();
    if (json == NULL) {
        LNN_LOGE(LNN_BUILDER, "create json object fail");
        return NULL;
    }
    if (!JSON_AddInt64ToObject(json, NETWORK_SYNC_CONN_CAP, connCap) ||
        !JSON_AddInt32ToObject(json, NETWORK_SYNC_TYPE, networkType) ||
        !JSON_AddInt64ToObject(json, NETWORK_SYNC_SEQ, authSeq)) {
        LNN_LOGE(LNN_BUILDER, "add p2p networking msg to json fail");
        JSON_Delete(json);
        return NULL;
    }
    char *msg = JSON_PrintUnformatted(json);
    JSON_Delete(json);
    return msg;
}

static char *PackWifiOfflineMsg(int32_t authPort, char *offlineCode)
{
    JsonObj *json = JSON_CreateObject();
    if (json == NULL) {
        LNN_LOGE(LNN_BUILDER, "create json object fail");
        return NULL;
    }
    if (!JSON_AddInt32ToObject(json, NETWORK_OFFLINE_PORT, authPort) ||
        !JSON_AddInt32ToObject(json, NETWORK_SYNC_TYPE, DISCOVERY_TYPE_WIFI) ||
        !JSON_AddStringToObject(json, NETWORK_OFFLINE_CODE, offlineCode)) {
        LNN_LOGE(LNN_BUILDER, "add wifi offline msg to json fail");
        JSON_Delete(json);
        return NULL;
    }
    char *msg = JSON_PrintUnformatted(json);
    JSON_Delete(json);
    return msg;
}

static int32_t CheckPeerAuthSeq(const char *uuid, int64_t peerAuthSeq)
{
    int64_t localAuthSeq[2] = {0};
    uint64_t authVerifyTime[2] = {0};
    char udid[UDID_BUF_LEN] = {0};

    if (LnnConvertDlId(uuid, CATEGORY_UUID, CATEGORY_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "convert uuid fail");
        return SOFTBUS_ERR;
    }
    if (AuthGetLatestAuthSeqListByType(udid, localAuthSeq, authVerifyTime, DISCOVERY_TYPE_BLE) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get authseq fail");
        return SOFTBUS_ERR;
    }
    char *anonyUdid = NULL;
    Anonymize(udid, &anonyUdid);
    if (peerAuthSeq == 0 || (peerAuthSeq != localAuthSeq[0] && peerAuthSeq != localAuthSeq[1])) {
        LNN_LOGE(LNN_BUILDER, "authSeq is invalid, udid:%{public}s, local:%{public}" PRId64 ", %{public}"
            PRId64 "peer:%{public}" PRId64 "", anonyUdid, localAuthSeq[0], localAuthSeq[1], peerAuthSeq);
        AnonymizeFree(anonyUdid);
        return SOFTBUS_ERR;
    }
    AnonymizeFree(anonyUdid);
    return SOFTBUS_OK;
}

static void BleOffLineProcess(const AuthTransData *data, AuthHandle authHandle)
{
    int64_t peerConnCap = 0;
    int64_t peerAuthSeq = 0;
    JsonObj *json = JSON_Parse((const char *)data->data, data->len);
    if (json == NULL) {
        LNN_LOGE(LNN_BUILDER, "json parse fail");
        return;
    }
    if (!JSON_GetInt64FromOject(json, NETWORK_SYNC_CONN_CAP, &peerConnCap) ||
        !JSON_GetInt64FromOject(json, NETWORK_SYNC_SEQ, &peerAuthSeq)) {
        LNN_LOGE(LNN_BUILDER, "ble json parse object fail");
        JSON_Delete(json);
        return;
    }
    JSON_Delete(json);
    if (LnnHasCapability((uint32_t)peerConnCap, BIT_BLE)) {
        LNN_LOGE(LNN_BUILDER, "no need to offline, peerConnCap:%{public}u", (uint32_t)peerConnCap);
        return;
    }
    char uuid[UUID_BUF_LEN] = {0};
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    if (AuthGetDeviceUuid(authHandle.authId, uuid, UUID_BUF_LEN) != SOFTBUS_OK ||
        CheckPeerAuthSeq(uuid, peerAuthSeq) != SOFTBUS_OK) {
        char *anonyUuid = NULL;
        Anonymize(uuid, &anonyUuid);
        LNN_LOGW(LNN_BUILDER, "device has offline or get authId/authSeq fail, uuid:%{public}s", anonyUuid);
        AnonymizeFree(anonyUuid);
        return;
    }
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    (void)LnnConvertDlId(uuid, CATEGORY_UUID, CATEGORY_NETWORK_ID, networkId, NETWORK_ID_BUF_LEN);
    if (LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_BLE) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "request leave specific fail, networkId:%{public}s", anonyNetworkId);
    } else {
        LNN_LOGD(LNN_BUILDER, "offline ble by p2p succ, networkId:%{public}s", anonyNetworkId);
    }
    AnonymizeFree(anonyNetworkId);
}

static bool CheckWifiOfflineMsgResult(const char *networkId, int32_t authPort, const char *offlineCode)
{
    int32_t port = 0;
    uint8_t remoteOfflineCode[WIFI_OFFLINE_CODE_LEN] = {0};
    char convertOfflineCode[WIFI_OFFLINE_CODE_LEN * HEXIFY_UNIT_LEN + 1] = {0};
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);

    if (LnnGetRemoteNumInfo(networkId, NUM_KEY_AUTH_PORT, &port) != 0) {
        LNN_LOGE(LNN_BUILDER, "get remote port fail, neteorkId:%{public}s", anonyNetworkId);
        AnonymizeFree(anonyNetworkId);
        return false;
    }
    if (LnnGetNodeKeyInfo(networkId, NODE_KEY_BLE_OFFLINE_CODE, remoteOfflineCode, WIFI_OFFLINE_CODE_LEN) != 0) {
        LNN_LOGE(LNN_BUILDER, "get remote offlinecode fail, neteorkId:%{public}s", anonyNetworkId);
        AnonymizeFree(anonyNetworkId);
        return false;
    }
    if (ConvertBytesToHexString(convertOfflineCode, WIFI_OFFLINE_CODE_LEN * HEXIFY_UNIT_LEN + 1,
        (unsigned char *)remoteOfflineCode, WIFI_OFFLINE_CODE_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "coonvert offlinecode fail, neteorkId:%{public}s", anonyNetworkId);
        AnonymizeFree(anonyNetworkId);
        return false;
    }
    if (strcmp(convertOfflineCode, offlineCode) != 0 || port != authPort) {
        LNN_LOGE(LNN_BUILDER, "check offline msg info fail, neteorkId:%{public}s", anonyNetworkId);
        AnonymizeFree(anonyNetworkId);
        return false;
    }
    AnonymizeFree(anonyNetworkId);
    return true;
}

static void WlanOffLineProcess(const AuthTransData *data, AuthHandle authHandle)
{
    char uuid[UUID_BUF_LEN] = {0};
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    char *anonyNetworkId = NULL;
    int32_t authPort = 0;
    char convertOfflineCode[WIFI_OFFLINE_CODE_LEN * HEXIFY_UNIT_LEN + 1] = {0};
    JsonObj *json = JSON_Parse((const char *)data->data, data->len);
    if (json == NULL) {
        LNN_LOGE(LNN_BUILDER, "json parse fail");
        return;
    }
    if (!JSON_GetInt32FromOject(json, NETWORK_OFFLINE_PORT, &authPort) ||
        !JSON_GetStringFromOject(json, NETWORK_OFFLINE_CODE, convertOfflineCode,
            WIFI_OFFLINE_CODE_LEN * HEXIFY_UNIT_LEN + 1)) {
        LNN_LOGE(LNN_BUILDER, "wifi json parse object fail");
        JSON_Delete(json);
        return;
    }
    JSON_Delete(json);
    if (AuthGetDeviceUuid(authHandle.authId, uuid, UUID_BUF_LEN) != SOFTBUS_OK) {
        char *anonyUuid = NULL;
        Anonymize(uuid, &anonyUuid);
        LNN_LOGW(LNN_BUILDER, "device has offline or get authId/authSeq fail, uuid:%{public}s", anonyUuid);
        AnonymizeFree(anonyUuid);
        return;
    }
    if (LnnConvertDlId(uuid, CATEGORY_UUID, CATEGORY_NETWORK_ID, networkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "convert networkid fail");
        return;
    }
    if (CheckWifiOfflineMsgResult(networkId, authPort, convertOfflineCode)) {
        Anonymize(networkId, &anonyNetworkId);
        if (LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_WLAN) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "wifi fast offline failed, networkId:%{public}s", anonyNetworkId);
        } else {
            LNN_LOGI(LNN_BUILDER, "wifi fast offline success networkId:%{public}s", anonyNetworkId);
        }
        AnonymizeFree(anonyNetworkId);
    }
}

static void OnP2pNetworkingDataRecv(AuthHandle authHandle, const AuthTransData *data)
{
    if (data == NULL || data->data == NULL || data->len ==0) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return;
    }
    LNN_LOGI(LNN_BUILDER, "authId=%{public}" PRId64 ", module=%{public}d, seq=%{public}" PRId64 ", len=%{public}u.",
        authHandle.authId, data->module, data->seq, data->len);
    if (data->module != MODULE_P2P_NETWORKING_SYNC) {
        LNN_LOGE(LNN_BUILDER, "data->module is not MODULE_P2P_NETWORKING_SYNC");
        return;
    }
    JsonObj *json = JSON_Parse((const char *)data->data, data->len);
    if (json == NULL) {
        LNN_LOGE(LNN_BUILDER, "json parse fail");
        return;
    }
    int32_t peerNetworkType = DISCOVERY_TYPE_UNKNOWN;
    if (!JSON_GetInt32FromOject(json, NETWORK_SYNC_TYPE, &peerNetworkType)) {
        LNN_LOGE(LNN_BUILDER, "json parse object fail");
        JSON_Delete(json);
        return;
    }
    JSON_Delete(json);
    if (peerNetworkType == DISCOVERY_TYPE_BLE) {
        BleOffLineProcess(data, authHandle);
    } else if (peerNetworkType == DISCOVERY_TYPE_WIFI) {
        WlanOffLineProcess(data, authHandle);
    }
}

static void LnnSyncManagerHandleOffline(const char *networkId)
{
    if (SoftBusMutexLock(&g_syncInfoManager.lock) != 0) {
        LNN_LOGE(LNN_BUILDER, "Lock fail");
        return;
    }
    SyncChannelInfo *item = FindSyncChannelInfoByNetworkId(networkId);
    if (item == NULL) {
        (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
        return;
    }
    ListDelete(&item->node);
    (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
    LNN_LOGI(LNN_BUILDER, "close sync channel. client=%{public}d, server=%{public}d", item->clientChannelId,
        item->serverChannelId);
    if (item->clientChannelId != INVALID_CHANNEL_ID) {
        (void)TransCloseNetWorkingChannel(item->clientChannelId);
    }
    if (item->serverChannelId != INVALID_CHANNEL_ID) {
        (void)TransCloseNetWorkingChannel(item->serverChannelId);
    }
    ClearSyncInfoMsg(item, &item->syncMsgList);
    SoftBusFree(item);
}

static void OnLnnOnlineStateChange(const LnnEventBasicInfo *info)
{
    if ((info == NULL) || (info->event != LNN_EVENT_NODE_ONLINE_STATE_CHANGED)) {
        return;
    }
    LnnOnlineStateEventInfo *onlineStateInfo = (LnnOnlineStateEventInfo*)info;
    if (!onlineStateInfo->isOnline) {
        LnnSyncManagerHandleOffline(onlineStateInfo->networkId);
    }
}

int32_t LnnInitSyncInfoManager(void)
{
    int32_t i;

    ListInit(&g_syncInfoManager.channelInfoList);
    for (i = 0; i < LNN_INFO_TYPE_COUNT; ++i) {
        g_syncInfoManager.handlers[i] = NULL;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_NODE_ONLINE_STATE_CHANGED, OnLnnOnlineStateChange) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "reg online lister fail");
        return SOFTBUS_ERR;
    }
    if (TransRegisterNetworkingChannelListener(CHANNEL_NAME, &g_networkListener) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "reg proxy channel lister fail");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexInit(&g_syncInfoManager.lock, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "sync info manager mutex init fail");
        return SOFTBUS_LOCK_ERR;
    }
    AuthTransListener p2pNetworkingCb = {
        .onDataReceived = OnP2pNetworkingDataRecv,
        .onDisconnected = NULL,
    };
    if (RegAuthTransListener(MODULE_P2P_NETWORKING_SYNC, &p2pNetworkingCb) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "p2p networking sync set cb fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void LnnDeinitSyncInfoManager(void)
{
    int32_t i;
    for (i = 0; i < LNN_INFO_TYPE_COUNT; ++i) {
        g_syncInfoManager.handlers[i] = NULL;
    }
    UnregAuthTransListener(MODULE_P2P_NETWORKING_SYNC);
    LnnRegisterEventHandler(LNN_EVENT_NODE_ONLINE_STATE_CHANGED, OnLnnOnlineStateChange);
    ClearSyncChannelInfo();
    SoftBusMutexDestroy(&g_syncInfoManager.lock);
}

int32_t LnnRegSyncInfoHandler(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler)
{
    if (type >= LNN_INFO_TYPE_COUNT || handler == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid sync info hander reg param. type=%{public}d", type);
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_syncInfoManager.lock) != 0) {
        LNN_LOGE(LNN_BUILDER, "reg sync info handler lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    if (g_syncInfoManager.handlers[type] != NULL) {
        LNN_LOGE(LNN_BUILDER, "sync info already have handler. type=%{public}d", type);
        (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
        return SOFTBUS_INVALID_PARAM;
    }
    g_syncInfoManager.handlers[type] = handler;
    (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
    return SOFTBUS_OK;
}

int32_t LnnUnregSyncInfoHandler(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler)
{
    if (type >= LNN_INFO_TYPE_COUNT || handler == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid sync info hander unreg param. type=%{public}d", type);
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_syncInfoManager.lock) != 0) {
        LNN_LOGE(LNN_BUILDER, "unreg sync info handler lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    if (g_syncInfoManager.handlers[type] != handler) {
        LNN_LOGE(LNN_BUILDER, "sync info handler not valid. type=%{public}d", type);
        (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
        return SOFTBUS_INVALID_PARAM;
    }
    g_syncInfoManager.handlers[type] = NULL;
    (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
    return SOFTBUS_OK;
}

static void ResetSendSyncInfo(SyncChannelInfo *oldInfo, const SyncChannelInfo *newInfo, SyncInfoMsg *msg)
{
    if (oldInfo->clientChannelId == INVALID_CHANNEL_ID) {
        oldInfo->clientChannelId = newInfo->clientChannelId;
        oldInfo->accessTime = newInfo->accessTime;
    } else {
        if (oldInfo->clientChannelId != newInfo->clientChannelId && oldInfo->clientChannelId != INVALID_CHANNEL_ID) {
            LNN_LOGD(LNN_BUILDER, "reset sync info send channel. clientChannelId:%{public}d->%{public}d",
                oldInfo->clientChannelId, newInfo->clientChannelId);
            (void)TransCloseNetWorkingChannel(oldInfo->clientChannelId);
            oldInfo->isClientOpened = false;
            oldInfo->clientChannelId = newInfo->clientChannelId;
        }
        if (oldInfo->isClientOpened) {
            SendSyncInfoMsg(oldInfo, msg);
        } else {
            LNN_LOGW(LNN_BUILDER, "send sync info client is not opened, channelId=%{public}d",
                oldInfo->clientChannelId);
        }
    }
}

static int32_t SendSyncInfoByNewChannel(const char *networkId, SyncInfoMsg *msg)
{
    SyncChannelInfo *info = CreateSyncChannelInfo(networkId);
    if (info == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    info->clientChannelId = TransOpenNetWorkingChannel(CHANNEL_NAME, networkId, NULL);
    if (info->clientChannelId == INVALID_CHANNEL_ID) {
        LNN_LOGE(LNN_BUILDER, "open sync info channel fail");
        SoftBusFree(info);
        return SOFTBUS_ERR;
    }
    LNN_LOGI(LNN_BUILDER, "open sync info. channelId=%{public}d", info->clientChannelId);
    SoftBusGetTime(&info->accessTime);
    if (SoftBusMutexLock(&g_syncInfoManager.lock) != 0) {
        LNN_LOGE(LNN_BUILDER, "send sync info lock fail");
        SoftBusFree(info);
        return SOFTBUS_LOCK_ERR;
    }
    SyncChannelInfo *item = FindSyncChannelInfoByNetworkId(networkId);
    if (item == NULL) {
        ListTailInsert(&info->syncMsgList, &msg->node);
        if (IsListEmpty(&g_syncInfoManager.channelInfoList)) {
            (void)LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT),
                CloseUnusedChannel, NULL, UNUSED_CHANNEL_CLOSED_DELAY);
        }
        ListNodeInsert(&g_syncInfoManager.channelInfoList, &info->node);
    } else {
        ListTailInsert(&item->syncMsgList, &msg->node);
        ResetSendSyncInfo(item, info, msg);
        SoftBusFree(info);
    }
    (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
    return SOFTBUS_OK;
}

static int32_t TrySendSyncInfoMsg(const char *networkId, SyncInfoMsg *msg)
{
    SyncChannelInfo *info = NULL;
    if (SoftBusMutexLock(&g_syncInfoManager.lock) != 0) {
        LNN_LOGE(LNN_BUILDER, "send sync info lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    info = FindSyncChannelInfoByNetworkId(networkId);
    if (info == NULL) {
        (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
        return SendSyncInfoByNewChannel(networkId, msg);
    }
    if (info->clientChannelId == INVALID_CHANNEL_ID) {
        (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
        return SendSyncInfoByNewChannel(networkId, msg);
    }
    ListTailInsert(&info->syncMsgList, &msg->node);
    if (info->isClientOpened) {
        SoftBusGetTime(&info->accessTime);
        ListDelete(&msg->node);
        int32_t id = info->clientChannelId;
        (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
        SendSyncInfoMsgOnly(networkId, id, msg);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&g_syncInfoManager.lock);
    return SOFTBUS_OK;
}

int32_t LnnSendSyncInfoMsg(LnnSyncInfoType type, const char *networkId,
    const uint8_t *msg, uint32_t len, LnnSyncInfoMsgComplete complete)
{
    if (type >= LNN_INFO_TYPE_COUNT || networkId == NULL || msg == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid sync info msg param");
        return SOFTBUS_INVALID_PARAM;
    }

    SyncInfoMsg *syncMsg = NULL;
    LNN_LOGI(LNN_BUILDER, "send sync info msg. type=%{public}d, len=%{public}d", type, len);
    syncMsg = CreateSyncInfoMsg(type, msg, len, complete);
    if (syncMsg == NULL) {
        return SOFTBUS_ERR;
    }
    int32_t rc = TrySendSyncInfoMsg(networkId, syncMsg);
    if (rc != SOFTBUS_OK) {
        SoftBusFree(syncMsg);
    }
    return rc;
}

static void FillAuthdataInfo(AuthTransData *dataInfo, char *msg)
{
    dataInfo->module = MODULE_P2P_NETWORKING_SYNC;
    dataInfo->flag = 0;
    dataInfo->seq = 0;
    dataInfo->len = strlen(msg) + 1;
    dataInfo->data = (const uint8_t *)msg;
}

static int32_t GetAuthHandleByNetworkId(const char *networkId, AuthHandle *authHandle)
{
    char uuid[UUID_BUF_LEN] = {0};
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    (void)LnnConvertDlId(networkId, CATEGORY_NETWORK_ID, CATEGORY_UUID, uuid, UUID_BUF_LEN);
    AuthDeviceGetLatestIdByUuid(uuid, AUTH_LINK_TYPE_P2P, authHandle);
    if (authHandle->authId != AUTH_INVALID_ID) {
        LNN_LOGI(LNN_BUILDER, "find p2p authHandle, networkId:%{public}s", anonyNetworkId);
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_OK;
    }
    AuthDeviceGetLatestIdByUuid(uuid, AUTH_LINK_TYPE_ENHANCED_P2P, authHandle);
    if (authHandle->authId != AUTH_INVALID_ID) {
        LNN_LOGI(LNN_BUILDER, "find hml authHandle, networkId:%{public}s", anonyNetworkId);
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_OK;
    }
    AnonymizeFree(anonyNetworkId);
    return SOFTBUS_ERR;
}

int32_t LnnSendP2pSyncInfoMsg(const char *networkId, uint32_t netCapability)
{
    char *anonyNetworkId = NULL;
    if (networkId == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    Anonymize(networkId, &anonyNetworkId);
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID };
    if (GetAuthHandleByNetworkId(networkId, &authHandle) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get authHandle fail, networkId:%{public}s", anonyNetworkId);
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_ERR;
    }
    int64_t authSeq[2] = {0};
    uint64_t authVerifyTime[2] = {0};
    char udid[UDID_BUF_LEN] = {0};
    (void)LnnConvertDlId(networkId, CATEGORY_NETWORK_ID, CATEGORY_UDID, udid, UDID_BUF_LEN);
    if (AuthGetLatestAuthSeqListByType(udid, authSeq, authVerifyTime, DISCOVERY_TYPE_BLE) != SOFTBUS_OK ||
        (authSeq[0] == 0 && authSeq[1] == 0)) {
        LNN_LOGE(LNN_BUILDER, "seqErr, ble authSeq:%{public}" PRId64 ", %{public}" PRId64 "", authSeq[0], authSeq[1]);
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_ERR;
    }
    char *msg = PackBleOfflineMsg((int64_t)netCapability, DISCOVERY_TYPE_BLE,
        authVerifyTime[0] > authVerifyTime[1] ? authSeq[0] : authSeq[1]);
    if (msg == NULL) {
        LNN_LOGE(LNN_BUILDER, "pack p2p networking msg fail, networkId:%{public}s", anonyNetworkId);
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_ERR;
    }
    AuthTransData dataInfo = {0};
    FillAuthdataInfo(&dataInfo, msg);
    if (SoftBusGenerateRandomArray((uint8_t *)&dataInfo.seq, sizeof(int64_t)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "generate seq fail");
        AnonymizeFree(anonyNetworkId);
        cJSON_free(msg);
        return SOFTBUS_ERR;
    }
    if (AuthPostTransData(authHandle, &dataInfo) == SOFTBUS_OK) {
        LNN_LOGI(LNN_BUILDER, "send p2p sync info msg to networkId:%{public}s, netCap:%{public}u, seq:%{public}"
            PRId64 ", [%{public}" PRId64 "/%{public}" PRId64 ", %{public}" PRIu64 "/%{public}" PRId64 "]",
            anonyNetworkId, netCapability, dataInfo.seq, authVerifyTime[0], authSeq[0], authVerifyTime[1], authSeq[1]);
    } else {
        LNN_LOGE(LNN_BUILDER, "post trans data fail, networkId:%{public}s", anonyNetworkId);
    }
    AnonymizeFree(anonyNetworkId);
    cJSON_free(msg);
    return SOFTBUS_OK;
}

int32_t LnnSendWifiOfflineInfoMsg(void)
{
    int32_t authPort = 0;
    char localOfflineCode[WIFI_OFFLINE_CODE_LEN] = {0};
    if (LnnGetLocalNumInfo(NUM_KEY_AUTH_PORT, &authPort) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local authPort fail");
        return SOFTBUS_ERR;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_OFFLINE_CODE, localOfflineCode, WIFI_OFFLINE_CODE_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local offlinecode fail");
        return SOFTBUS_ERR;
    }
    char convertOfflineCode[WIFI_OFFLINE_CODE_LEN * HEXIFY_UNIT_LEN + 1] = {0};
    if (ConvertBytesToHexString(convertOfflineCode, WIFI_OFFLINE_CODE_LEN * HEXIFY_UNIT_LEN + 1,
        (unsigned char *)localOfflineCode, WIFI_OFFLINE_CODE_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "coonvert offlinecode fail");
        return SOFTBUS_ERR;
    }
    char *msg = PackWifiOfflineMsg(authPort, convertOfflineCode);
    if (msg == NULL) {
        LNN_LOGE(LNN_BUILDER, "pack p2p networking msg fail");
        return SOFTBUS_ERR;
    }
    AuthTransData dataInfo = {0};
    FillAuthdataInfo(&dataInfo, msg);
    AuthHandle *authHandle = NULL;
    int32_t num = 0;
    if (GetHmlOrP2pAuthHandle(&authHandle, &num) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get authHandle fail");
        cJSON_free(msg);
        return SOFTBUS_ERR;
    }
    char *anonyOfflineCode = NULL;
    Anonymize(convertOfflineCode, &anonyOfflineCode);
    for (int32_t i = 0; i < num; i++) {
        if (AuthPostTransData(authHandle[i], &dataInfo) == SOFTBUS_OK) {
            LNN_LOGI(LNN_BUILDER, "send wifi offline msg sucess, authPort:%{public}d, offlineCode:%{public}s,"
                "authId:%{public}" PRId64, authPort, anonyOfflineCode, authHandle->authId);
        } else {
            LNN_LOGE(LNN_BUILDER, "post trans data fail, authId:%{public}" PRId64, authHandle->authId);
        }
    }
    cJSON_free(msg);
    SoftBusFree(authHandle);
    AnonymizeFree(anonyOfflineCode);
    return SOFTBUS_OK;
}
