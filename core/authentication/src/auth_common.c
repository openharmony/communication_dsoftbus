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

#include "auth_common.h"

#include <securec.h>

#include "bus_center_manager.h"
#include "message_handler.h"
#include "softbus_base_listener.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_feature_config.h"

#define TIME_SEC_TO_MSEC 1000L
#define TIME_MSEC_TO_USEC 1000L

#define SEQ_NETWORK_ID_BITS 32
#define SEQ_TIME_STAMP_BITS 8
#define SEQ_TIME_STAMP_MASK 0xFFL
#define SEQ_INTEGER_BITS 24
#define SEQ_INTEGER_MAX 0xFFFFFF

#define AUTH_SUPPORT_AS_SERVER_MASK 0x01

typedef struct {
    EventType event;
    RemoveCompareFunc cmpFunc;
    void *param;
} EventRemoveInfo;

static uint64_t g_uniqueId = 0;
static SoftBusMutex g_authLock;
static SoftBusHandler g_authHandler = { NULL, NULL, NULL };

/* auth handler */
static bool IsAuthHandlerInit(void)
{
    if (g_authHandler.looper == NULL ||
        g_authHandler.looper->PostMessage == NULL ||
        g_authHandler.looper->PostMessageDelay == NULL ||
        g_authHandler.looper->RemoveMessageCustom == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth handler not init.");
        return false;
    }
    return true;
}

static void DelAuthMessage(SoftBusMessage *msg)
{
    CHECK_NULL_PTR_RETURN_VOID(msg);
    if (msg->obj != NULL) {
        SoftBusFree(msg->obj);
        msg->obj = NULL;
    }
    SoftBusFree(msg);
}

static SoftBusMessage *NewAuthMessage(const uint8_t *obj, uint32_t size)
{
    SoftBusMessage *msg = MallocMessage();
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "malloc message fail.");
        return NULL;
    }
    msg->obj = NULL;
    if (obj != NULL && size > 0) {
        msg->obj = DupMemBuffer(obj, size);
        if (msg->obj == NULL) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "dup data fail.");
            SoftBusFree(msg);
            return NULL;
        }
    }
    msg->handler = &g_authHandler;
    msg->FreeMessage = DelAuthMessage;
    return msg;
}

static void HandleAuthMessage(SoftBusMessage *msg)
{
    CHECK_NULL_PTR_RETURN_VOID(msg);
    EventHandler handler = (EventHandler)msg->arg1;
    if (handler == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "invalid event handler, event: %d", msg->what);
        return;
    }
    handler(msg->obj);
}

int32_t PostAuthEvent(EventType event, EventHandler handler,
    const void *obj, uint32_t size, uint64_t delayMs)
{
    if (!IsAuthHandlerInit()) {
        return SOFTBUS_NO_INIT;
    }
    SoftBusMessage *msg = NewAuthMessage(obj, size);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "malloc fail, event: %d", event);
        return SOFTBUS_MALLOC_ERR;
    }
    msg->what = (int32_t)event;
    msg->arg1 = (uint64_t)handler;
    if (delayMs == 0) {
        g_authHandler.looper->PostMessage(g_authHandler.looper, msg);
    } else {
        g_authHandler.looper->PostMessageDelay(g_authHandler.looper, msg, delayMs);
    }
    return SOFTBUS_OK;
}

static int32_t CustomFunc(const SoftBusMessage *msg, void *param)
{
    CHECK_NULL_PTR_RETURN_VALUE(msg, SOFTBUS_ERR);
    CHECK_NULL_PTR_RETURN_VALUE(param, SOFTBUS_ERR);
    EventRemoveInfo *info = (EventRemoveInfo *)param;
    if (msg->what != (int32_t)info->event) {
        return SOFTBUS_ERR;
    }
    if (info->cmpFunc == NULL) {
        return SOFTBUS_ERR;
    }
    return info->cmpFunc(msg->obj, info->param);
}

int32_t RemoveAuthEvent(EventType event, RemoveCompareFunc func, void *param)
{
    if (!IsAuthHandlerInit()) {
        return SOFTBUS_NO_INIT;
    }
    EventRemoveInfo info = {
        .event = event,
        .cmpFunc = func,
        .param = param,
    };
    g_authHandler.looper->RemoveMessageCustom(g_authHandler.looper, &g_authHandler, CustomFunc, &info);
    return SOFTBUS_OK;
}

/* auth lock */
bool RequireAuthLock(void)
{
    if (SoftBusMutexLock(&g_authLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth lock fail.");
        return false;
    }
    return true;
}

void ReleaseAuthLock(void)
{
    if (SoftBusMutexUnlock(&g_authLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth unlock fail.");
    }
}

/* auth config */
bool GetConfigSupportAsServer(void)
{
    uint32_t ability = 0;
    if (SoftbusGetConfig(SOFTBUS_INT_AUTH_ABILITY_COLLECTION,
        (uint8_t *)(&ability), sizeof(ability)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "get auth ability from config file fail.");
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth ability: %u", ability);
    return ((ability & AUTH_SUPPORT_AS_SERVER_MASK) != 0);
}

/* auth common function */
uint8_t *DupMemBuffer(const uint8_t *buf, uint32_t size)
{
    if (buf == NULL || size == 0) {
        return NULL;
    }
    uint8_t *dup = (uint8_t *)SoftBusMalloc(size);
    if (dup == NULL) {
        return NULL;
    }
    if (memcpy_s(dup, size, buf, size) != EOK) {
        SoftBusFree(dup);
        return NULL;
    }
    return dup;
}

static void UpdateUniqueId(void)
{
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_NETWORKID, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "get local networkId fail.");
        return;
    }
    uint8_t hashId[SHA_256_HASH_LEN] = {0};
    if (SoftBusGenerateStrHash((uint8_t *)networkId, strlen(networkId), hashId) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "GenerateStrHash fail.");
        return;
    }
    for (uint32_t i = 0; i < SEQ_NETWORK_ID_BITS / BYTES_BIT_NUM; i++) {
        g_uniqueId = (g_uniqueId << BYTES_BIT_NUM) | hashId[i];
    }
    uint64_t timeStamp = GetCurrentTimeMs();
    g_uniqueId = (g_uniqueId << SEQ_TIME_STAMP_BITS) | (SEQ_TIME_STAMP_MASK & timeStamp);
}

int64_t GenSeq(bool isServer)
{
    static uint32_t integer = 0;
    if (integer >= SEQ_INTEGER_MAX) {
        integer = 0;
    }
    if (integer == 0) {
        UpdateUniqueId();
    }
    integer += SEQ_INTERVAL;
    uint64_t seq = isServer ? (integer + 1) : integer;
    /* |----NetworkIdHash(32)----|-----timeStamp(8)----|----AtomicInteger(24)----| */
    seq = (g_uniqueId << SEQ_INTEGER_BITS) | (seq & SEQ_INTEGER_MAX);
    return (int64_t)seq;
}

uint64_t GetCurrentTimeMs(void)
{
    SoftBusSysTime now = {0};
    if (SoftBusGetTime(&now) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "SoftBusGetTime fail.");
        return 0;
    }
    return (uint64_t)now.sec * TIME_SEC_TO_MSEC + (uint64_t)now.usec / TIME_MSEC_TO_USEC;
}

const char *GetAuthSideStr(bool isServer)
{
    return isServer ? "server" : "client";
}

bool CompareConnInfo(const AuthConnInfo *info1, const AuthConnInfo *info2)
{
    CHECK_NULL_PTR_RETURN_VALUE(info1, false);
    CHECK_NULL_PTR_RETURN_VALUE(info2, false);
    switch (info1->type) {
        case AUTH_LINK_TYPE_WIFI:
            if (info2->type == AUTH_LINK_TYPE_WIFI &&
                strcmp(info1->info.ipInfo.ip, info2->info.ipInfo.ip) == 0) {
                return true;
            }
            break;
        case AUTH_LINK_TYPE_BR:
            if (info2->type == AUTH_LINK_TYPE_BR &&
                StrCmpIgnoreCase(info1->info.brInfo.brMac, info2->info.brInfo.brMac) == 0) {
                return true;
            }
            break;
        case AUTH_LINK_TYPE_BLE:
            if (info2->type == AUTH_LINK_TYPE_BLE &&
                memcmp(info1->info.bleInfo.deviceIdHash, info2->info.bleInfo.deviceIdHash, UDID_HASH_LEN) == 0) {
                return true;
            }
            break;
        case AUTH_LINK_TYPE_P2P:
            if (info2->type == AUTH_LINK_TYPE_P2P &&
                info1->info.ipInfo.port == info2->info.ipInfo.port &&
                strcmp(info1->info.ipInfo.ip, info2->info.ipInfo.ip) == 0) {
                return true;
            }
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "unexpected connInfo, type = %d.", info1->type);
            return false;
    }
    return false;
}

int32_t ConvertToConnectOption(const AuthConnInfo *connInfo, ConnectOption *option)
{
    CHECK_NULL_PTR_RETURN_VALUE(connInfo, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(option, SOFTBUS_INVALID_PARAM);
    switch (connInfo->type) {
        case AUTH_LINK_TYPE_BR:
            option->type = CONNECT_BR;
            if (strcpy_s(option->brOption.brMac, BT_MAC_LEN, connInfo->info.brInfo.brMac) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy brMac fail.");
                return SOFTBUS_MEM_ERR;
            }
            break;
        case AUTH_LINK_TYPE_BLE:
            option->type = CONNECT_BLE;
            if (strcpy_s(option->bleOption.bleMac, BT_MAC_LEN, connInfo->info.bleInfo.bleMac) != EOK ||
                memcpy_s(option->bleOption.deviceIdHash, UDID_HASH_LEN,
                    connInfo->info.bleInfo.deviceIdHash, UDID_HASH_LEN) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy bleMac/deviceIdHash fail.");
                return SOFTBUS_MEM_ERR;
            }
            option->bleOption.fastestConnectEnable = true;
            break;
        case AUTH_LINK_TYPE_P2P:
            option->type = CONNECT_TCP;
            if (strcpy_s(option->socketOption.addr, sizeof(option->socketOption.addr),
                connInfo->info.ipInfo.ip) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy ip fail.");
                return SOFTBUS_MEM_ERR;
            }
            option->socketOption.port = connInfo->info.ipInfo.port;
            option->socketOption.moduleId = AUTH_P2P;
            option->socketOption.protocol = LNN_PROTOCOL_IP;
            option->socketOption.keepAlive = 1;
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "unexpected connType=%d.", connInfo->type);
            return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ConvertToAuthConnInfo(const ConnectionInfo *info, AuthConnInfo *connInfo)
{
    CHECK_NULL_PTR_RETURN_VALUE(info, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(connInfo, SOFTBUS_INVALID_PARAM);
    switch (info->type) {
        case CONNECT_TCP:
            if (info->socketInfo.protocol != LNN_PROTOCOL_IP) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_WARN, "only support LNN_PROTOCOL_IP.");
                return SOFTBUS_ERR;
            }
            connInfo->type = AUTH_LINK_TYPE_P2P;
            connInfo->info.ipInfo.port = info->socketInfo.port;
            if (strcpy_s(connInfo->info.ipInfo.ip, IP_LEN, info->socketInfo.addr) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy ip fail.");
                return SOFTBUS_MEM_ERR;
            }
            break;
        case CONNECT_BR:
            connInfo->type = AUTH_LINK_TYPE_BR;
            if (strcpy_s(connInfo->info.brInfo.brMac, BT_MAC_LEN, info->brInfo.brMac) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy brMac fail.");
                return SOFTBUS_MEM_ERR;
            }
            break;
        case CONNECT_BLE:
            connInfo->type = AUTH_LINK_TYPE_BLE;
            if (strcpy_s(connInfo->info.bleInfo.bleMac, BT_MAC_LEN, info->bleInfo.bleMac) != EOK ||
                memcpy_s(connInfo->info.bleInfo.deviceIdHash, UDID_HASH_LEN,
                    info->bleInfo.deviceIdHash, UDID_HASH_LEN) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy bleMac/deviceIdHash fail.");
                return SOFTBUS_MEM_ERR;
            }
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "unexpected connectionInfo, type=%d.", info->type);
            return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t AuthCommonInit(void)
{
    g_authHandler.name = "AuthHandler";
    g_authHandler.HandleMessage = HandleAuthMessage;
    g_authHandler.looper = GetLooper(LOOP_TYPE_DEFAULT);

    if (SoftBusMutexInit(&g_authLock, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth mutex init fail.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void AuthCommonDeinit(void)
{
    g_authHandler.looper = NULL;
    g_authHandler.HandleMessage = NULL;

    if (SoftBusMutexDestroy(&g_authLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth mutex destroy fail.");
    }
}
