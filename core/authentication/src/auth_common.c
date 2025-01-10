/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "anonymizer.h"
#include "auth_log.h"
#include "bus_center_manager.h"
#include "message_handler.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_base_listener.h"
#include "softbus_def.h"
#include "softbus_feature_config.h"

#define TIME_SEC_TO_MSEC  1000L
#define TIME_MSEC_TO_USEC 1000L

#define SEQ_NETWORK_ID_BITS 32
#define SEQ_TIME_STAMP_BITS 8
#define SEQ_TIME_STAMP_MASK 0xFFL
#define SEQ_INTEGER_BITS    24
#define SEQ_INTEGER_MAX     0xFFFFFF

#define AUTH_SUPPORT_AS_SERVER_MASK 0x01

typedef struct {
    EventType event;
    RemoveCompareFunc cmpFunc;
    void *param;
} EventRemoveInfo;

typedef struct {
    AuthLinkType type;
    bool (*compareConnInfo)(const AuthConnInfo *info1, const AuthConnInfo *info2, bool cmpShortHash);
} CompareByType;

static uint64_t g_uniqueId = 0;
static SoftBusMutex g_authLock;
static SoftBusHandler g_authHandler = { NULL, NULL, NULL };

/* auth handler */
static bool IsAuthHandlerInit(void)
{
    if (g_authHandler.looper == NULL || g_authHandler.looper->PostMessage == NULL ||
        g_authHandler.looper->PostMessageDelay == NULL || g_authHandler.looper->RemoveMessageCustom == NULL) {
        AUTH_LOGE(AUTH_INIT, "auth handler not init");
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
        AUTH_LOGE(AUTH_CONN, "malloc message fail");
        return NULL;
    }
    msg->obj = NULL;
    if (obj != NULL && size > 0) {
        msg->obj = DupMemBuffer(obj, size);
        if (msg->obj == NULL) {
            AUTH_LOGE(AUTH_CONN, "dup data fail");
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
    EventHandler handler = (EventHandler)(uintptr_t)msg->arg1;
    if (handler == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid event handler, event=%{public}d", msg->what);
        return;
    }
    handler(msg->obj);
}

int32_t PostAuthEvent(EventType event, EventHandler handler, const void *obj, uint32_t size, uint64_t delayMs)
{
    if (!IsAuthHandlerInit()) {
        return SOFTBUS_NO_INIT;
    }
    SoftBusMessage *msg = NewAuthMessage(obj, size);
    if (msg == NULL) {
        AUTH_LOGE(AUTH_CONN, "malloc fail, event=%{public}d", event);
        return SOFTBUS_MALLOC_ERR;
    }
    msg->what = (int32_t)event;
    msg->arg1 = (uint64_t)(uintptr_t)handler;
    if (delayMs == 0) {
        g_authHandler.looper->PostMessage(g_authHandler.looper, msg);
    } else {
        g_authHandler.looper->PostMessageDelay(g_authHandler.looper, msg, delayMs);
    }
    return SOFTBUS_OK;
}

static int32_t CustomFunc(const SoftBusMessage *msg, void *param)
{
    CHECK_NULL_PTR_RETURN_VALUE(msg, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(param, SOFTBUS_INVALID_PARAM);
    EventRemoveInfo *info = (EventRemoveInfo *)param;
    if (msg->what != (int32_t)info->event) {
        AUTH_LOGE(AUTH_CONN, "msg->what and event inequality");
        return SOFTBUS_INVALID_PARAM;
    }
    if (info->cmpFunc == NULL) {
        AUTH_LOGE(AUTH_CONN, "cmpFunc is null");
        return SOFTBUS_INVALID_PARAM;
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
        AUTH_LOGE(AUTH_CONN, "auth lock fail");
        return false;
    }
    return true;
}

void ReleaseAuthLock(void)
{
    if (SoftBusMutexUnlock(&g_authLock) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "auth unlock fail");
    }
}

/* auth config */
bool GetConfigSupportAsServer(void)
{
    uint32_t ability = 0;
    if (SoftbusGetConfig(SOFTBUS_INT_AUTH_ABILITY_COLLECTION, (uint8_t *)(&ability), sizeof(ability)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get auth ability from config file fail");
    }
    AUTH_LOGI(AUTH_CONN, "auth ability=%{public}u", ability);
    return ((ability & AUTH_SUPPORT_AS_SERVER_MASK) != 0);
}

/* auth capacity */
uint32_t GetAuthCapacity(void)
{
    uint32_t authCapacity = 0;
    int32_t ret = SoftbusGetConfig(SOFTBUS_INT_AUTH_CAPACITY, (uint8_t *)(&authCapacity), sizeof(authCapacity));
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get auth capacity from config file fail, ret=%{public}d", ret);
        return authCapacity;
    }
    AUTH_LOGI(AUTH_CONN, "auth capacity=%{public}u", authCapacity);
    return authCapacity;
}

/* auth common function */
uint8_t *DupMemBuffer(const uint8_t *buf, uint32_t size)
{
    if (buf == NULL || size == 0) {
        AUTH_LOGE(AUTH_CONN, "param err");
        return NULL;
    }
    uint8_t *dup = (uint8_t *)SoftBusMalloc(size);
    if (dup == NULL) {
        AUTH_LOGE(AUTH_CONN, "malloc err");
        return NULL;
    }
    if (memcpy_s(dup, size, buf, size) != EOK) {
        AUTH_LOGE(AUTH_CONN, "memcpy err");
        SoftBusFree(dup);
        return NULL;
    }
    return dup;
}

static void UpdateUniqueId(void)
{
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (LnnGetLocalStrInfo(STRING_KEY_NETWORKID, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get local networkId fail");
        return;
    }
    uint8_t hashId[SHA_256_HASH_LEN] = { 0 };
    if (SoftBusGenerateStrHash((uint8_t *)networkId, strlen(networkId), hashId) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "GenerateStrHash fail");
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
    SoftBusSysTime now = { 0 };
    if (SoftBusGetTime(&now) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "SoftBusGetTime fail");
        return 0;
    }
    return (uint64_t)now.sec * TIME_SEC_TO_MSEC + (uint64_t)now.usec / TIME_MSEC_TO_USEC;
}

const char *GetAuthSideStr(bool isServer)
{
    return isServer ? "server" : "client";
}

static bool CompareBrConnInfo(const AuthConnInfo *info1, const AuthConnInfo *info2, bool cmpShortHash)
{
    if (info2->type == AUTH_LINK_TYPE_BR &&
        StrCmpIgnoreCase(info1->info.brInfo.brMac, info2->info.brInfo.brMac) == 0) {
        return true;
    }
    return false;
}

static bool CompareWifiConnInfo(const AuthConnInfo *info1, const AuthConnInfo *info2, bool cmpShortHash)
{
    if (info2->type == AUTH_LINK_TYPE_WIFI && strcmp(info1->info.ipInfo.ip, info2->info.ipInfo.ip) == 0) {
        return true;
    }
    return false;
}

static bool CompareBleConnInfo(const AuthConnInfo *info1, const AuthConnInfo *info2, bool cmpShortHash)
{
    bool isLinkble = (info2->type == AUTH_LINK_TYPE_BLE &&
                        (memcmp(info1->info.bleInfo.deviceIdHash, info2->info.bleInfo.deviceIdHash,
                        (cmpShortHash ? SHORT_HASH_LEN : UDID_HASH_LEN)) == 0 ||
                        StrCmpIgnoreCase(info1->info.bleInfo.bleMac, info2->info.bleInfo.bleMac) == 0));
    return isLinkble;
}

static bool CompareP2pConnInfo(const AuthConnInfo *info1, const AuthConnInfo *info2, bool cmpShortHash)
{
    if (info2->type == AUTH_LINK_TYPE_P2P && info1->info.ipInfo.port == info2->info.ipInfo.port &&
        strcmp(info1->info.ipInfo.ip, info2->info.ipInfo.ip) == 0) {
        return true;
    }
    return false;
}

static bool CompareEnhancedP2pConnInfo(const AuthConnInfo *info1, const AuthConnInfo *info2, bool cmpShortHash)
{
    if (info2->type == AUTH_LINK_TYPE_ENHANCED_P2P && info1->info.ipInfo.port == info2->info.ipInfo.port &&
        strcmp(info1->info.ipInfo.ip, info2->info.ipInfo.ip) == 0) {
        return true;
    }
    return false;
}

static bool CompareSessionConnInfo(const AuthConnInfo *info1, const AuthConnInfo *info2, bool cmpShortHash)
{
    if (info2->type == AUTH_LINK_TYPE_SESSION &&
        info1->info.sessionInfo.connId == info2->info.sessionInfo.connId &&
        strcmp(info1->info.sessionInfo.udid, info2->info.sessionInfo.udid) == 0) {
        return true;
    }
    return false;
}

static CompareByType g_compareByType[] = {
    {AUTH_LINK_TYPE_WIFI,         CompareWifiConnInfo},
    {AUTH_LINK_TYPE_BR,           CompareBrConnInfo},
    {AUTH_LINK_TYPE_BLE,          CompareBleConnInfo},
    {AUTH_LINK_TYPE_P2P,          CompareP2pConnInfo},
    {AUTH_LINK_TYPE_ENHANCED_P2P, CompareEnhancedP2pConnInfo},
    {AUTH_LINK_TYPE_SESSION,      CompareSessionConnInfo},
};

bool CompareConnInfo(const AuthConnInfo *info1, const AuthConnInfo *info2, bool cmpShortHash)
{
    CHECK_NULL_PTR_RETURN_VALUE(info1, false);
    CHECK_NULL_PTR_RETURN_VALUE(info2, false);
    for (uint32_t i = 0; i < sizeof(g_compareByType) / sizeof(CompareByType); i++) {
        if (info1->type == g_compareByType[i].type) {
            if (g_compareByType[i].compareConnInfo != NULL) {
                return g_compareByType[i].compareConnInfo(info1, info2, cmpShortHash);
            }
        }
    }
    AUTH_LOGE(AUTH_CONN, "link type not support, info1-type: %{public}d", info1->type);
    return false;
}

static int32_t SetP2pSocketOption(const AuthConnInfo *connInfo, ConnectOption *option)
{
    CHECK_NULL_PTR_RETURN_VALUE(connInfo, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(option, SOFTBUS_INVALID_PARAM);
    option->type = CONNECT_TCP;
    if (strcpy_s(option->socketOption.addr, sizeof(option->socketOption.addr), connInfo->info.ipInfo.ip) != EOK) {
        AUTH_LOGE(AUTH_CONN, "copy ip fail");
        return SOFTBUS_MEM_ERR;
    }
    option->socketOption.port = connInfo->info.ipInfo.port;
    option->socketOption.protocol = LNN_PROTOCOL_IP;
    option->socketOption.keepAlive = 1;
    if (connInfo->type == AUTH_LINK_TYPE_P2P) {
        option->socketOption.moduleId = AUTH_P2P;
    } else {
        option->socketOption.moduleId = connInfo->info.ipInfo.moduleId;
    }
    return SOFTBUS_OK;
}

int32_t ConvertToConnectOption(const AuthConnInfo *connInfo, ConnectOption *option)
{
    CHECK_NULL_PTR_RETURN_VALUE(connInfo, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(option, SOFTBUS_INVALID_PARAM);
    switch (connInfo->type) {
        case AUTH_LINK_TYPE_BR:
            option->type = CONNECT_BR;
            if (strcpy_s(option->brOption.brMac, BT_MAC_LEN, connInfo->info.brInfo.brMac) != EOK) {
                AUTH_LOGE(AUTH_CONN, "copy brMac fail");
                return SOFTBUS_MEM_ERR;
            }
            option->brOption.connectionId = connInfo->info.brInfo.connectionId;
            break;
        case AUTH_LINK_TYPE_BLE:
            option->type = CONNECT_BLE;
            if (strcpy_s(option->bleOption.bleMac, BT_MAC_LEN, connInfo->info.bleInfo.bleMac) != EOK ||
                memcpy_s(option->bleOption.deviceIdHash, UDID_HASH_LEN, connInfo->info.bleInfo.deviceIdHash,
                    UDID_HASH_LEN) != EOK) {
                AUTH_LOGE(AUTH_CONN, "copy bleMac/deviceIdHash fail");
                return SOFTBUS_MEM_ERR;
            }
            option->bleOption.fastestConnectEnable = true;
            option->bleOption.psm = connInfo->info.bleInfo.psm;
            option->bleOption.protocol = connInfo->info.bleInfo.protocol;
            break;
        case AUTH_LINK_TYPE_P2P:
        case AUTH_LINK_TYPE_ENHANCED_P2P:
            if (SetP2pSocketOption(connInfo, option) != SOFTBUS_OK) {
                return SOFTBUS_MEM_ERR;
            }
            break;
        default:
            AUTH_LOGE(AUTH_CONN, "unexpected connType=%{public}d", connInfo->type);
            return SOFTBUS_AUTH_UNEXPECTED_CONN_TYPE;
    }
    return SOFTBUS_OK;
}

static bool IsEnhanceP2pModuleId(ListenerModule moduleId)
{
    if (moduleId >= AUTH_ENHANCED_P2P_START && moduleId <= AUTH_ENHANCED_P2P_END) {
        return true;
    }
    return false;
}

int32_t ConvertToAuthConnInfo(const ConnectionInfo *info, AuthConnInfo *connInfo)
{
    CHECK_NULL_PTR_RETURN_VALUE(info, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(connInfo, SOFTBUS_INVALID_PARAM);
    switch (info->type) {
        case CONNECT_TCP:
            if (info->socketInfo.protocol != LNN_PROTOCOL_IP) {
                AUTH_LOGW(AUTH_CONN, "only support LNN_PROTOCOL_IP");
                return SOFTBUS_AUTH_INVALID_PROTOCOL;
            }
            if (IsEnhanceP2pModuleId(info->socketInfo.moduleId)) {
                connInfo->type = AUTH_LINK_TYPE_ENHANCED_P2P;
            } else {
                connInfo->type = AUTH_LINK_TYPE_P2P;
            }
            connInfo->info.ipInfo.moduleId = info->socketInfo.moduleId;
            connInfo->info.ipInfo.port = info->socketInfo.port;
            if (strcpy_s(connInfo->info.ipInfo.ip, IP_LEN, info->socketInfo.addr) != EOK) {
                AUTH_LOGE(AUTH_CONN, "copy ip fail");
                return SOFTBUS_MEM_ERR;
            }
            break;
        case CONNECT_BR:
            connInfo->type = AUTH_LINK_TYPE_BR;
            if (strcpy_s(connInfo->info.brInfo.brMac, BT_MAC_LEN, info->brInfo.brMac) != EOK) {
                AUTH_LOGE(AUTH_CONN, "copy brMac fail");
                return SOFTBUS_MEM_ERR;
            }
            break;
        case CONNECT_BLE:
            connInfo->type = AUTH_LINK_TYPE_BLE;
            if (strcpy_s(connInfo->info.bleInfo.bleMac, BT_MAC_LEN, info->bleInfo.bleMac) != EOK ||
                memcpy_s(connInfo->info.bleInfo.deviceIdHash, UDID_HASH_LEN, info->bleInfo.deviceIdHash,
                    UDID_HASH_LEN) != EOK) {
                AUTH_LOGE(AUTH_CONN, "copy bleMac/deviceIdHash fail");
                return SOFTBUS_MEM_ERR;
            }
            connInfo->info.bleInfo.protocol = info->bleInfo.protocol;
            connInfo->info.bleInfo.psm = info->bleInfo.psm;
            break;
        default:
            AUTH_LOGE(AUTH_CONN, "unexpected connType=%{public}d", info->type);
            return SOFTBUS_AUTH_UNEXPECTED_CONN_TYPE;
    }
    return SOFTBUS_OK;
}

DiscoveryType ConvertToDiscoveryType(AuthLinkType type)
{
    switch (type) {
        case AUTH_LINK_TYPE_WIFI:
            return DISCOVERY_TYPE_WIFI;
        case AUTH_LINK_TYPE_BLE:
            return DISCOVERY_TYPE_BLE;
        case AUTH_LINK_TYPE_BR:
            return DISCOVERY_TYPE_BR;
        case AUTH_LINK_TYPE_P2P:
            return DISCOVERY_TYPE_P2P;
        default:
            break;
    }
    AUTH_LOGE(AUTH_CONN, "unexpected AuthLinkType=%{public}d", type);
    return DISCOVERY_TYPE_UNKNOWN;
}

AuthLinkType ConvertToAuthLinkType(DiscoveryType type)
{
    switch (type) {
        case DISCOVERY_TYPE_WIFI:
            return AUTH_LINK_TYPE_WIFI;
        case DISCOVERY_TYPE_BLE:
            return AUTH_LINK_TYPE_BLE;
        case DISCOVERY_TYPE_BR:
            return AUTH_LINK_TYPE_BR;
        case DISCOVERY_TYPE_P2P:
            return AUTH_LINK_TYPE_P2P;
        default:
            AUTH_LOGE(AUTH_CONN, "unexpected discType=%{public}d", type);
            break;
    }
    return AUTH_LINK_TYPE_MAX;
}

int32_t AuthCommonInit(void)
{
    g_authHandler.name = "AuthHandler";
    g_authHandler.HandleMessage = HandleAuthMessage;
    g_authHandler.looper = GetLooper(LOOP_TYPE_DEFAULT);

    if (SoftBusMutexInit(&g_authLock, NULL) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_INIT, "auth mutex init fail");
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

void AuthCommonDeinit(void)
{
    g_authHandler.looper = NULL;
    g_authHandler.HandleMessage = NULL;

    if (SoftBusMutexDestroy(&g_authLock) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_INIT, "auth mutex destroy fail");
    }
}

int32_t GetPeerUdidByNetworkId(const char *networkId, char *udid, uint32_t len)
{
    if (networkId == NULL || udid == NULL || len < UDID_BUF_LEN) {
        AUTH_LOGW(AUTH_CONN, "param err");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo cacheInfo;
    (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnRetrieveDeviceInfoByNetworkId(networkId, &cacheInfo) == SOFTBUS_OK &&
        cacheInfo.deviceInfo.deviceUdid[0] != '\0') {
        if (strcpy_s(udid, len, cacheInfo.deviceInfo.deviceUdid) != EOK) {
            AUTH_LOGE(AUTH_CONN, "copy deviceUdid failed");
            return SOFTBUS_STRCPY_ERR;
        }
        return SOFTBUS_OK;
    }
    AUTH_LOGE(AUTH_CONN, "info or deviceUdid is null");
    return SOFTBUS_NOT_FIND;
}

int32_t GetIsExchangeUdidByNetworkId(const char *networkId, bool *isExchangeUdid)
{
    if (networkId == NULL || isExchangeUdid == NULL) {
        AUTH_LOGW(AUTH_CONN, "param err");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeInfo cacheInfo;
    (void)memset_s(&cacheInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnRetrieveDeviceInfoByNetworkId(networkId, &cacheInfo) == SOFTBUS_OK) {
        *isExchangeUdid = cacheInfo.isAuthExchangeUdid;
        return SOFTBUS_OK;
    }
    AUTH_LOGE(AUTH_CONN, "deviceInfo not found");
    return SOFTBUS_NOT_FIND;
}

bool CheckAuthConnInfoType(const AuthConnInfo *connInfo)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(connInfo != NULL, false, AUTH_FSM, "connInfo is null");
    if (connInfo->type >= AUTH_LINK_TYPE_WIFI && connInfo->type < AUTH_LINK_TYPE_MAX) {
        return true;
    }
    return false;
}

void PrintAuthConnInfo(const AuthConnInfo *connInfo)
{
    if (connInfo == NULL) {
        return;
    }
    char *anonyUdidHash = NULL;
    char *anonyMac = NULL;
    char *anonyIp = NULL;
    char udidHash[UDID_BUF_LEN] = { 0 };
    switch (connInfo->type) {
        case AUTH_LINK_TYPE_WIFI:
            Anonymize(connInfo->info.ipInfo.ip, &anonyIp);
            AUTH_LOGD(AUTH_CONN, "print AuthConninfo ip=*.*.*%{public}s", AnonymizeWrapper(anonyIp));
            AnonymizeFree(anonyIp);
            break;
        case AUTH_LINK_TYPE_BR:
            Anonymize(connInfo->info.brInfo.brMac, &anonyMac);
            AUTH_LOGD(AUTH_CONN, "print AuthConninfo brMac=**:**:**:**:%{public}s", AnonymizeWrapper(anonyMac));
            AnonymizeFree(anonyMac);
            break;
        case AUTH_LINK_TYPE_BLE:
            if (ConvertBytesToHexString(udidHash, UDID_BUF_LEN,
                (const unsigned char *)connInfo->info.bleInfo.deviceIdHash, UDID_HASH_LEN) != SOFTBUS_OK) {
                AUTH_LOGE(AUTH_CONN, "gen udid hash hex str err");
                return;
            }
            Anonymize(udidHash, &anonyUdidHash);
            Anonymize(connInfo->info.bleInfo.bleMac, &anonyMac);
            AUTH_LOGD(AUTH_CONN, "print AuthConninfo bleMac=**:**:**:**:%{public}s, udidhash=%{public}s",
                AnonymizeWrapper(anonyMac), AnonymizeWrapper(anonyUdidHash));
            AnonymizeFree(anonyMac);
            AnonymizeFree(anonyUdidHash);
            break;
        default:
            break;
    }
}