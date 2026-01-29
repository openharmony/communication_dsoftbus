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

#include <ctype.h>
#include <securec.h>
#include <unistd.h>

#include "br_proxy.h"
#include "legacy/softbus_hisysevt_transreporter.h"
#include "softbus_adapter_mem.h"
#include "softbus_client_stub_interface.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "trans_event.h"
#include "trans_event_form.h"
#include "trans_server_proxy.h"

typedef struct {
    ListNode node;
    char peerBRMacAddr[BR_MAC_LEN];
    char peerBRUuid[UUID_LEN];
    int32_t channelId;
    int32_t sessionId;
    IBrProxyListener listener;
    bool enableDataRecv;
    bool enableStateChange;
    int64_t timeStart;
} ClientBrProxyChannelInfo;

static SoftBusList *g_clientList = NULL;

// MAC地址格式常量定义
#define MAC_ADDRESS_BYTES 6           // MAC地址字节数
#define MAC_VALID_CHARS 12            // 有效十六进制字符数
#define MAC_MAX_SEPARATORS 5          // 最大分隔符数量

// 分隔符定义
#define MAC_SEPARATOR_COLON ':'       // 冒号分隔符
#define MAC_SEPARATOR_HYPHEN '-'      // 连字符分隔符
#define MAC_SEPARATOR_DOT '.'         // 点分隔符

// UUID格式常量定义
#define UUID_HYPHEN_COUNT 4       // 标准格式中的连字符数量
#define UUID_GROUP_COUNT 5        // UUID分组数量

// 连字符位置定义（0-based索引）
#define UUID_HYPHEN_POS1 8  // 第一个连字符位置
#define UUID_HYPHEN_POS2 13 // 第二个连字符位置
#define UUID_HYPHEN_POS3 18 // 第三个连字符位置
#define UUID_HYPHEN_POS4 23 // 第四个连字符位置

/**
 * @brief 检查字符是否为MAC地址分隔符
 */
static bool IsMacSeparator(char c)
{
    return c == MAC_SEPARATOR_COLON ||
           c == MAC_SEPARATOR_HYPHEN ||
           c == MAC_SEPARATOR_DOT;
}

/**
 * @brief 检查MAC地址的基本格式和字符有效性
 */
static bool CheckMacFormat(const char *macAddr, int32_t len, int32_t *validChars, int32_t *sepCount)
{
    char prevChar = '\0';
    for (int32_t i = 0; i < len; i++) {
        char c = macAddr[i];
        if (IsMacSeparator(c)) {
            // 分隔符不能在首尾或连续出现
            if (i == 0 || i == len - 1 || prevChar == c) {
                return false;
            }
            (*sepCount)++;
            prevChar = c;
            continue;
        }
        if (!isxdigit((unsigned char)c)) {
            return false; // 非十六进制字符
        }
        (*validChars)++;
        prevChar = c;
    }
    return true;
}

/**
 * @brief 检查分隔符一致性
 */
static bool CheckSeparatorConsistency(const char *macAddr, int32_t len)
{
    char firstSep = '\0';
    for (int32_t i = 0; i < len; i++) {
        char c = macAddr[i];
        
        if (IsMacSeparator(c)) {
            if (firstSep == '\0') {
                firstSep = c; // 记录第一个分隔符
            } else if (c != firstSep) {
                return false; // 分隔符不一致
            }
        }
    }
    return true;
}

/**
 * @brief 校验蓝牙MAC地址格式是否合法
 */
static bool IsMacValid(const char *macAddr)
{
    if (macAddr == NULL) {
        return false;
    }

    int32_t len = strlen(macAddr);
    // 快速检查长度
    if (len < MAC_MIN_LENGTH || len > MAC_MAX_LENGTH) {
        return false;
    }
    int32_t validChars = 0;
    int32_t sepCount = 0;
    // 检查基本格式
    if (!CheckMacFormat(macAddr, len, &validChars, &sepCount)) {
        return false;
    }
    // 检查字符数量
    if (validChars != MAC_VALID_CHARS) {
        return false;
    }
    // 检查分隔符数量
    if (sepCount != 0 && sepCount != MAC_MAX_SEPARATORS) {
        return false;
    }
    // 检查分隔符一致性（如果有分隔符）
    if (sepCount == MAC_MAX_SEPARATORS && !CheckSeparatorConsistency(macAddr, len)) {
        return false;
    }
    return true;
}

static bool IsHexChar(char c)
{
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static bool IsValidSha256(const char *str)
{
    if (str == NULL) {
        return false;
    }
    int32_t len = strlen(str);
    if (len != MAC_SHA256_LEN) {
        return false;
    }
    for (int32_t i = 0; i < len; i++) {
        if (!IsHexChar(str[i])) {
            return false;
        }
    }
    return true;
}

static bool IsPeerDevAddrValid(const char *addr)
{
    if (addr == NULL) {
        return false;
    }

    if (IsValidSha256(addr)) {
        return true;
    } else if (IsMacValid(addr)) {
        return true;
    }

    return false;
}

static bool IsUuidValid(const char *uuid)
{
    if (uuid == NULL) {
        return false;
    }
    int32_t len = strlen(uuid);
    int32_t validCchars = 0; // 记录有效的十六进制字符数
    int32_t hyphenCount = 0; // 记录连字符（-）数量
    char prevChar = '\0'; // 记录前一个字符（用于连续连字符校验）

    // 检查长度是否符合标准格式或无分隔符格式
    if (len != UUID_STD_LENGTH && len != UUID_NO_HYPHEN_LENGTH) {
        return false;
    }
    // 存储连字符位置的数组
    static const int hyphenPositions[UUID_HYPHEN_COUNT] = {
        UUID_HYPHEN_POS1, UUID_HYPHEN_POS2, UUID_HYPHEN_POS3, UUID_HYPHEN_POS4
    };
    for (int32_t i = 0; i < len; i++) {
        char c = uuid[i];
        // 处理连字符（仅标准格式允许连字符）
        if (c == '-') {
            if (len != UUID_STD_LENGTH) {
                return false;
            } // 非标准格式不允许连字符
            if (hyphenCount >= UUID_HYPHEN_COUNT) {
                return false;
            }
            // 连字符位置必须符合8-4-4-4-12模式
            if (i != hyphenPositions[hyphenCount]) {
                return false;
            }
            hyphenCount++;
            prevChar = c;
            continue;
        }
        // 校验十六进制字符（0-9/A-F/a-f）
        if (!isxdigit((unsigned char)c)) {
            return false; // 包含非法字符
        }
        validCchars++;
        prevChar = c;
    }
    // 标准格式必须包含4个连字符
    if (len == UUID_STD_LENGTH && hyphenCount != UUID_HYPHEN_COUNT) {
        return false;
    }
    // 无分隔符格式必须无连字符
    if (len == UUID_NO_HYPHEN_LENGTH && hyphenCount != 0) {
        return false;
    }
    return true; // 所有校验通过
}

static int32_t TransClientInit(void)
{
    if (g_clientList != NULL) {
        return SOFTBUS_OK;
    }
    g_clientList = CreateSoftBusList();
    if (g_clientList == NULL) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] init list failed");
        return SOFTBUS_CREATE_LIST_ERR;
    }
    TRANS_LOGI(TRANS_SDK, "[br_proxy] init trans client success");
    return SOFTBUS_OK;
}

static int32_t ClientAddChannelToList(int32_t sessionId, BrProxyChannelInfo *channelInfo, IBrProxyListener *listener)
{
    if (channelInfo == NULL || listener == NULL) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = SOFTBUS_OK;
    ClientBrProxyChannelInfo *info = (ClientBrProxyChannelInfo *)SoftBusCalloc(sizeof(ClientBrProxyChannelInfo));
    if (info == NULL) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] calloc failed");
        return SOFTBUS_MALLOC_ERR;
    }
    info->sessionId = sessionId;
    info->timeStart = GetSoftbusRecordTimeMillis();
    if (strcpy_s(info->peerBRMacAddr, sizeof(info->peerBRMacAddr), channelInfo->peerBRMacAddr) != EOK ||
        strcpy_s(info->peerBRUuid, sizeof(info->peerBRUuid), channelInfo->peerBRUuid) != EOK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] copy brMac or uuid failed");
        ret = SOFTBUS_STRCPY_ERR;
        goto EXIT_ERR;
    }
    ret = memcpy_s(&info->listener, sizeof(IBrProxyListener), listener, sizeof(IBrProxyListener));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] memcpy failed! ret=%{public}d", ret);
        ret = SOFTBUS_MEM_ERR;
        goto EXIT_ERR;
    }
    ListInit(&info->node);
    if (SoftBusMutexLock(&(g_clientList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] lock failed");
        ret = SOFTBUS_LOCK_ERR;
        goto EXIT_ERR;
    }
    ListAdd(&g_clientList->list, &info->node);
    g_clientList->cnt++;
    TRANS_LOGI(TRANS_SDK, "[br_proxy] add node success, cnt:%{public}d", g_clientList->cnt);
    (void)SoftBusMutexUnlock(&g_clientList->lock);
    return SOFTBUS_OK;

EXIT_ERR:
    SoftBusFree(info);
    return ret;
}

static int32_t ClientDeleteChannelFromList(int32_t channelId, const char *brMac, const char *uuid)
{
    if (g_clientList == NULL) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_clientList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    ClientBrProxyChannelInfo *channelNode = NULL;
    ClientBrProxyChannelInfo *channelNodeNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(channelNode, channelNodeNext, &(g_clientList->list), ClientBrProxyChannelInfo, node) {
        if (brMac == NULL) {
            if (channelNode->channelId != channelId) {
                continue;
            }
        } else {
            if (strcmp(brMac, channelNode->peerBRMacAddr) != 0 || strcmp(uuid, channelNode->peerBRUuid) != 0) {
                continue;
            }
        }
        TRANS_LOGI(TRANS_SDK, "[br_proxy] by channelId:%{public}d delete node success, cnt:%{public}d",
            channelNode->channelId, g_clientList->cnt);
        ListDelete(&channelNode->node);
        SoftBusFree(channelNode);
        g_clientList->cnt--;
        (void)SoftBusMutexUnlock(&(g_clientList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_clientList->lock));
    return SOFTBUS_NOT_FIND;
}

static int32_t ClientUpdateList(const char *mac, const char *uuid, int32_t channelId)
{
    if (g_clientList == NULL) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_clientList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    ClientBrProxyChannelInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_clientList->list), ClientBrProxyChannelInfo, node) {
        if (strcmp(nodeInfo->peerBRMacAddr, mac) != 0 || strcmp(nodeInfo->peerBRUuid, uuid) != 0) {
            continue;
        }
        nodeInfo->channelId = channelId;
        (void)SoftBusMutexUnlock(&(g_clientList->lock));
        return SOFTBUS_OK;
    }
    char *brMactmpName = NULL;
    Anonymize(mac, &brMactmpName);
    TRANS_LOGE(TRANS_SDK, "[br_proxy] not find brMac:%{public}s", brMactmpName);
    AnonymizeFree(brMactmpName);
    (void)SoftBusMutexUnlock(&(g_clientList->lock));
    return SOFTBUS_NOT_FIND;
}

static int32_t ClientQueryList(int32_t channelId, const char *peerBRMacAddr, const char *uuid,
    ClientBrProxyChannelInfo *info)
{
    if (g_clientList == NULL) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] not init");
        return SOFTBUS_NO_INIT;
    }
    if ((channelId == DEFAULT_CHANNEL_ID && peerBRMacAddr == NULL) || info == NULL) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&(g_clientList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    int32_t ret = SOFTBUS_NOT_FIND;
    ClientBrProxyChannelInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_clientList->list), ClientBrProxyChannelInfo, node) {
        if (channelId != DEFAULT_CHANNEL_ID) {
            if (nodeInfo->channelId != channelId) {
                continue;
            }
        } else {
            if (strcmp(nodeInfo->peerBRMacAddr, peerBRMacAddr) != 0 || strcmp(nodeInfo->peerBRUuid, uuid) != 0) {
                continue;
            }
        }
        ret = memcpy_s(info, sizeof(ClientBrProxyChannelInfo), nodeInfo, sizeof(ClientBrProxyChannelInfo));
        if (ret != EOK) {
            ret = SOFTBUS_MEM_ERR;
            goto EXIT;
        }
        (void)SoftBusMutexUnlock(&(g_clientList->lock));
        return SOFTBUS_OK;
    }
EXIT:
    (void)SoftBusMutexUnlock(&(g_clientList->lock));
    TRANS_LOGE(TRANS_SDK, "[br_proxy] failed! channelId=%{public}d", channelId);
    return ret;
}

static int32_t ClientRecordListenerState(int32_t channelId, ListenerType type, bool isEnable)
{
    if (g_clientList == NULL) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] not init");
        return SOFTBUS_NO_INIT;
    }
    if (type != DATA_RECEIVE && type != CHANNEL_STATE) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] ListenerType is wrong, type=%{public}d", type);
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&(g_clientList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    ClientBrProxyChannelInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_clientList->list), ClientBrProxyChannelInfo, node) {
        if (nodeInfo->channelId != channelId) {
            continue;
        }
        switch (type) {
            case DATA_RECEIVE:
                nodeInfo->enableDataRecv = isEnable;
                break;
            case CHANNEL_STATE:
                nodeInfo->enableStateChange = isEnable;
                break;
            default:
                break;
        }
        (void)SoftBusMutexUnlock(&(g_clientList->lock));
        return SOFTBUS_OK;
    }
    TRANS_LOGE(TRANS_SDK, "[br_proxy] not find channelId=%{public}d", channelId);
    (void)SoftBusMutexUnlock(&(g_clientList->lock));
    return SOFTBUS_NOT_FIND;
}

static bool IsChannelValid(int32_t channelId)
{
    if (channelId <= 0) {
        return false;
    }
    bool isValid = false;
    if (g_clientList == NULL) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] not init");
        return isValid;
    }
    if (SoftBusMutexLock(&(g_clientList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] lock failed");
        return isValid;
    }
    ClientBrProxyChannelInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_clientList->list), ClientBrProxyChannelInfo, node) {
        if (nodeInfo->channelId == channelId) {
            isValid = true;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&(g_clientList->lock));
    return isValid;
}

static int32_t CheckOpenParm(BrProxyChannelInfo *channelInfo, IBrProxyListener *listener)
{
    if (channelInfo == NULL || listener == NULL) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] channelInfo or listener is NULL");
        return SOFTBUS_INVALID_PARAM;
    }

    if (!IsPeerDevAddrValid(channelInfo->peerBRMacAddr)) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] mac is invalid!");
        return SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM;
    }
    if (!IsUuidValid(channelInfo->peerBRUuid)) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] uuid is invalid!");
        return SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

int32_t OpenBrProxy(int32_t sessionId, BrProxyChannelInfo *channelInfo, IBrProxyListener *listener)
{
    TRANS_LOGI(TRANS_SDK, "[br_proxy] enter");
    int32_t ret = CheckOpenParm(channelInfo, listener);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    ret = TransClientInit();
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    ret = ClientStubInit();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] client stub init failed! ret:%{public}d", ret);
        return ret;
    }
    ret = ClientRegisterBrProxyService(COMM_PKGNAME_BRPROXY);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] client register service failed! ret:%{public}d", ret);
        return ret;
    }

    ret = ClientAddChannelToList(sessionId, channelInfo, listener);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] add to list failed! ret=%{public}d", ret);
        return ret;
    }

    ret = ServerIpcOpenBrProxy(channelInfo->peerBRMacAddr, channelInfo->peerBRUuid);
    if (ret != SOFTBUS_OK && ret != SOFTBUS_TRANS_SESSION_OPENING) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] ipc open brproxy failed! ret=%{public}d", ret);
        TransEventExtra extra = {
            .result = EVENT_STAGE_RESULT_FAILED,
            .errcode = ret,
        };
        TRANS_EVENT(EVENT_SCENE_TRANS_BR_PROXY, EVENT_STAGE_OPEN_CHANNEL, extra);
        return ret;
    }
    if (ret == SOFTBUS_TRANS_SESSION_OPENING) {
        int32_t res = ClientDeleteChannelFromList(DEFAULT_CHANNEL_ID,
            channelInfo->peerBRMacAddr, channelInfo->peerBRUuid);
        if (res != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "[br_proxy] add to list failed! ret=%{public}d", res);
            return ret;
        }
        TRANS_LOGI(TRANS_SDK, "[br_proxy] sdk reopen");
    }
    TRANS_LOGE(TRANS_SDK, "[br_proxy] ret=%{public}d", ret);
    return ret;
}

int32_t CloseBrProxy(int32_t channelId)
{
    TRANS_LOGI(TRANS_SDK, "[br_proxy] enter! channelId:%{public}d", channelId);
    if (!IsChannelValid(channelId)) {
        return SOFTBUS_TRANS_INVALID_CHANNEL_ID;
    }
    TransEventExtra extra = {
        .result = EVENT_STAGE_RESULT_OK,
        .errcode = SOFTBUS_OK,
    };
    TRANS_EVENT(EVENT_SCENE_TRANS_BR_PROXY, EVENT_STAGE_CLOSE_BR_PROXY, extra);
    (void)ClientRecordListenerState(channelId, DATA_RECEIVE, false);
    (void)ClientRecordListenerState(channelId, CHANNEL_STATE, false);
    int32_t ret = ServerIpcCloseBrProxy(channelId);
    if (ret != SOFTBUS_OK && ret != SOFTBUS_TRANS_INVALID_CHANNEL_ID) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] ipc close brproxy failed! ret:%{public}d", ret);
        return ret;
    }
    ClientDeleteChannelFromList(channelId, NULL, NULL);
    return SOFTBUS_OK;
}

int32_t SendBrProxyData(int32_t channelId, char *data, uint32_t dataLen)
{
    TRANS_LOGI(TRANS_SDK, "[br_proxy] channelId:%{public}d, datalen:%{public}d", channelId, dataLen);
    if (!IsChannelValid(channelId)) {
        return SOFTBUS_TRANS_INVALID_CHANNEL_ID;
    }
    if (dataLen > BR_PROXY_SEND_MAX_LEN) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] data too long! datalen:%{public}d", dataLen);
        return SOFTBUS_TRANS_BR_PROXY_DATA_TOO_LONG;
    }
    int32_t ret = ServerIpcSendBrProxyData(channelId, data, dataLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(
            TRANS_SDK, "[br_proxy] ipc brproxy send failed! ret:%{public}d, channelId:%{public}d", ret, channelId);
        TransEventExtra extra = {
            .result = EVENT_STAGE_RESULT_FAILED,
            .errcode = ret,
            .channelId = channelId,
            .dataLen = dataLen,
        };
        TRANS_EVENT(EVENT_SCENE_TRANS_BR_PROXY, EVENT_STAGE_SEND_DATA, extra);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t SetListenerState(int32_t channelId, ListenerType type, bool isEnable)
{
    if (!IsChannelValid(channelId)) {
        return SOFTBUS_TRANS_INVALID_CHANNEL_ID;
    }
    TRANS_LOGI(TRANS_SDK,
        "[br_proxy] enter! channelId:%{public}d, type:%{public}d, type_desc:%{public}s, isEnable:%{public}s",
        channelId, type, type == DATA_RECEIVE ? "receiveData":"receiveChannelStatus", isEnable ? "on":"off");
    int32_t ret = ServerIpcSetListenerState(channelId, type, isEnable);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] set listener state failed! ret=%{public}d", ret);
        return ret;
    }
    return ClientRecordListenerState(channelId, type, isEnable);
}

int32_t ClientTransBrProxyDataReceived(int32_t channelId, const uint8_t *data, uint32_t len)
{
    TRANS_LOGI(TRANS_SDK, "[br_proxy] client recv brproxy data! channelId:%{public}d", channelId);
    ClientBrProxyChannelInfo info;
    int32_t ret = ClientQueryList(channelId, NULL, NULL, &info);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (info.enableDataRecv && info.listener.onDataReceived != NULL) {
        info.listener.onDataReceived(channelId, (const char *)data, len);
    } else {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] receiveData is off, listener is null");
    }
    return SOFTBUS_OK;
}

typedef struct {
    int32_t softbusErrCode;
    int32_t channelState;
} SoftBusCodeToStateMap;

const SoftBusCodeToStateMap G_CODE_MAP[] = {
    { SOFTBUS_CONN_BR_UNDERLAY_SOCKET_CLOSED,   CHANNEL_WAIT_RESUME },
    { SOFTBUS_OK,                               CHANNEL_RESUME      },
    { SOFTBUS_CONN_BR_UNPAIRED,                 CHANNEL_BR_NO_PAIRED},
};

static int32_t SoftbusErrConvertChannelState(int32_t err)
{
    size_t mapSize = sizeof(G_CODE_MAP) / sizeof(G_CODE_MAP[0]);
    for (size_t i = 0; i < mapSize; ++i) {
        if (err == G_CODE_MAP[i].softbusErrCode) {
            return G_CODE_MAP[i].channelState;
        }
    }
    return CHANNEL_EXCEPTION_SOFTWARE_FAILED;
}

int32_t ClientTransBrProxyChannelChange(int32_t channelId, int32_t errCode)
{
    TRANS_LOGI(TRANS_SDK, "[br_proxy] channelId:%{public}d, errCode:%{public}d", channelId, errCode);
    ClientBrProxyChannelInfo info;
    int32_t ret = ClientQueryList(channelId, NULL, NULL, &info);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (info.enableStateChange && info.listener.onChannelStatusChanged != NULL) {
        info.listener.onChannelStatusChanged(channelId, SoftbusErrConvertChannelState(errCode));
        TransEventExtra extra = {
            .result = EVENT_STAGE_RESULT_OK,
            .errcode = errCode,
            .channelId = info.channelId,
            .channelStatus = SoftbusErrConvertChannelState(errCode),
        };
        TRANS_EVENT(EVENT_SCENE_TRANS_BR_PROXY, EVENT_STAGE_CHANNEL_STATUS, extra);
    } else {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] receiveChannelStatus is off, listener is null");
    }
    return SOFTBUS_OK;
}

int32_t ClientTransOnBrProxyOpened(int32_t channelId, const char *brMac, const char *uuid, int32_t result)
{
    TRANS_LOGI(TRANS_SDK, "[br_proxy] channelId:%{public}d, result:%{public}d.", channelId, result);
    if (brMac == NULL || uuid == NULL) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] brMac is NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    ClientBrProxyChannelInfo info;
    int32_t ret = ClientQueryList(DEFAULT_CHANNEL_ID, brMac, uuid, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGI(TRANS_SDK, "[br_proxy] query list failed! ret:%{public}d", ret);
        return ret;
    }
    if (result == SOFTBUS_OK) {
        ret = ClientUpdateList(brMac, uuid, channelId);
        if (ret != SOFTBUS_OK) {
            return ret;
        }
    } else {
        ClientDeleteChannelFromList(DEFAULT_CHANNEL_ID, brMac, uuid);
    }
    TRANS_LOGI(TRANS_SDK, "[br_proxy] sessionId:%{public}d.", info.sessionId);
    if (info.listener.onChannelOpened != NULL) {
        info.listener.onChannelOpened(info.sessionId, channelId, result);
        int64_t timeStart = info.timeStart;
        int64_t timeDiff = GetSoftbusRecordTimeMillis() - timeStart;
        TransEventExtra extra = {
            .result = (result == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED,
            .errcode = result,
            .channelId = info.channelId,
            .costTime = (result == SOFTBUS_OK) ? (int32_t)timeDiff : 0,
        };
        TRANS_EVENT(EVENT_SCENE_TRANS_BR_PROXY, EVENT_STAGE_OPEN_CHANNEL, extra);
    }
    return SOFTBUS_OK;
}

bool IsProxyChannelEnabled(int32_t uid)
{
    int32_t ret = ClientStubInit();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] client stub init failed! ret:%{public}d", ret);
        return false;
    }
    TRANS_LOGI(TRANS_SVC, "[br_proxy] enter uid:%{public}d", uid);
    ret = ClientRegisterService(COMM_PKGNAME_PUSH);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] client register service failed! ret:%{public}d", ret);
        return false;
    }
    bool isEnable = false;
    ret = ServerIpcIsProxyChannelEnabled(uid, &isEnable);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] ipc get brproxy channel state failed! ret:%{public}d", ret);
    }
    TRANS_LOGI(TRANS_SVC, "[br_proxy] exit uid:%{public}d, %{public}s", uid, isEnable ? "true" : "false");
    return isEnable;
}

static PermissonHookCb g_pushCb;
int32_t RegisterAccessHook(PermissonHookCb *cb)
{
    if (cb == NULL) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] cb is NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = ClientStubInit();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] client stub init failed! ret:%{public}d", ret);
        return ret;
    }
    TRANS_LOGI(TRANS_SVC, "[br_proxy] enter");
    ret = ClientRegisterService(COMM_PKGNAME_PUSH);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] client register service failed! ret:%{public}d", ret);
        return ret;
    }
    ret = ServerIpcRegisterPushHook();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] client register push hook failed! ret:%{public}d", ret);
        return ret;
    }
    ret = memcpy_s(&g_pushCb, sizeof(PermissonHookCb), cb, sizeof(PermissonHookCb));
    if (ret != EOK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] memcpy failed! ret:%{public}d", ret);
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientTransBrProxyQueryPermission(const char *bundleName, bool *isEmpowered)
{
    if (bundleName == NULL || isEmpowered == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_pushCb.queryPermission == NULL) {
        return SOFTBUS_NO_INIT;
    }

    int32_t ret = g_pushCb.queryPermission(bundleName, isEmpowered);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] client query permission failed! ret:%{public}d", ret);
    }

    return ret;
}