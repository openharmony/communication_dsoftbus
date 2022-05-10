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

#include "auth_common.h"

#include <securec.h>
#include <sys/time.h>

#include "softbus_base_listener.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "softbus_utils.h"

#define DEFAULT_AUTH_ABILITY_COLLECTION 0
#define AUTH_SUPPORT_SERVER_SIDE_MASK 0x01
#define INTERVAL_VALUE 2
#define OFFSET_BITS 24
#define INT_MAX_VALUE 0xFFFFFEL
#define LOW_24_BITS 0xFFFFFFL
#define MAX_BYTE_RECORD 230
#define ANONYMOUS_INTEVER_LEN 60

static uint64_t g_uniqueId = 0;
static uint32_t g_authAbility = 0;

int64_t GetSeq(AuthSideFlag flag)
{
    static uint64_t integer = 0;
    if (integer == INT_MAX_VALUE) {
        integer = 0;
    }
    integer += INTERVAL_VALUE;
    uint64_t temp = integer;
    if (flag == SERVER_SIDE_FLAG) {
        temp += 1;
    }
    temp = ((g_uniqueId << OFFSET_BITS) | (temp & LOW_24_BITS));
    int64_t seq = 0;
    if (memcpy_s(&seq, sizeof(int64_t), &temp, sizeof(uint64_t)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "memcpy_s seq error");
    }
    return seq;
}

uint16_t AuthGetNextConnectionId(void)
{
    static uint16_t authConnId = 0;
    return ++authConnId;
}

AuthSideFlag AuthGetSideByRemoteSeq(int64_t seq)
{
    /* even odd check */
    return (seq % 2) == 0 ? SERVER_SIDE_FLAG : CLIENT_SIDE_FLAG;
}

void AuthGetAbility(void)
{
    if (SoftbusGetConfig(SOFTBUS_INT_AUTH_ABILITY_COLLECTION,
        (unsigned char*)&g_authAbility, sizeof(g_authAbility)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "Cannot get auth ability from config file");
        g_authAbility = DEFAULT_AUTH_ABILITY_COLLECTION;
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth ability is %u", g_authAbility);
}

bool AuthIsSupportServerSide(void)
{
    return (g_authAbility & AUTH_SUPPORT_SERVER_SIDE_MASK) ? true : false;
}

void UniqueIdInit(void)
{
    struct timeval time = {0};
    gettimeofday(&time, NULL);
    g_uniqueId = (uint64_t)(time.tv_usec);
}

int32_t AuthGetDeviceKey(char *key, uint32_t size, uint32_t *len, const ConnectOption *option)
{
    if (key == NULL || len == NULL || option == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return SOFTBUS_ERR;
    }
    switch (option->type) {
        case CONNECT_BR:
            if (strcpy_s(key, size, option->info.brOption.brMac) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "strcpy_s failed");
                return SOFTBUS_ERR;
            }
            *len = BT_MAC_LEN;
            break;
        case CONNECT_BLE:
            if (strcpy_s(key, size, option->info.bleOption.bleMac) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "strcpy_s failed");
                return SOFTBUS_ERR;
            }
            *len = BT_MAC_LEN;
            break;
        case CONNECT_TCP:
            if (strcpy_s(key, size, option->info.ipOption.ip) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "strcpy_s failed");
                return SOFTBUS_ERR;
            }
            *len = IP_LEN;
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "unknown type");
            return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t AuthConvertConnInfo(ConnectOption *option, const ConnectionInfo *connInfo)
{
    if (option == NULL || connInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return SOFTBUS_ERR;
    }
    option->type = connInfo->type;
    switch (connInfo->type) {
        case CONNECT_BR: {
            if (strcpy_s(option->info.brOption.brMac, BT_MAC_LEN, connInfo->info.brInfo.brMac) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "strcpy_s failed");
                return SOFTBUS_ERR;
            }
            break;
        }
        case CONNECT_BLE:
            if (strcpy_s(option->info.bleOption.bleMac, BT_MAC_LEN, connInfo->info.bleInfo.bleMac) != EOK ||
                memcpy_s(option->info.bleOption.deviceIdHash, UDID_HASH_LEN,
                connInfo->info.bleInfo.deviceIdHash, UDID_HASH_LEN) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy bleMac or deviceIdHash failed");
                return SOFTBUS_ERR;
            }
            break;
        case CONNECT_TCP: {
            if (strcpy_s(option->info.ipOption.ip, IP_LEN, connInfo->info.ipInfo.ip) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "strcpy_s failed");
                return SOFTBUS_ERR;
            }
            option->info.ipOption.port = connInfo->info.ipInfo.port;
            break;
        }
        default: {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "unknown type");
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t ConvertAuthConnInfoToOption(const AuthConnInfo *info, ConnectOption *option)
{
    if (info == NULL || option == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    switch (info->type) {
        case AUTH_LINK_TYPE_WIFI:
            option->type = CONNECT_TCP;
            if (strcpy_s(option->info.ipOption.ip, sizeof(option->info.ipOption.ip), info->info.ipInfo.ip) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy ip failed.");
                return SOFTBUS_MEM_ERR;
            }
            option->info.ipOption.port = info->info.ipInfo.port;
            break;
        case AUTH_LINK_TYPE_BR:
            option->type = CONNECT_BR;
            if (strcpy_s(option->info.brOption.brMac, sizeof(option->info.brOption.brMac),
                info->info.brInfo.brMac) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy brMac failed.");
                return SOFTBUS_MEM_ERR;
            }
            break;
        case AUTH_LINK_TYPE_BLE:
            option->type = CONNECT_BLE;
            if (strcpy_s(option->info.bleOption.bleMac, sizeof(option->info.bleOption.bleMac),
                info->info.bleInfo.bleMac) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy bleMac failed.");
                return SOFTBUS_MEM_ERR;
            }
            break;
        case AUTH_LINK_TYPE_P2P:
            option->type = CONNECT_TCP;
            if (strcpy_s(option->info.ipOption.ip, sizeof(option->info.ipOption.ip), info->info.ipInfo.ip) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy ip failed.");
                return SOFTBUS_MEM_ERR;
            }
            option->info.ipOption.port = info->info.ipInfo.port;
            option->info.ipOption.moduleId = AUTH_P2P;
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "unsupport link type, type = %d.", info->type);
            return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

int32_t ConvertOptionToAuthConnInfo(const ConnectOption *option, bool isAuthP2p, AuthConnInfo *info)
{
    if (option == NULL || info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    switch (option->type) {
        case CONNECT_TCP:
            info->type = isAuthP2p ? AUTH_LINK_TYPE_P2P : AUTH_LINK_TYPE_WIFI;
            if (strcpy_s(info->info.ipInfo.ip, sizeof(info->info.ipInfo.ip), option->info.ipOption.ip) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy ip failed.");
                return SOFTBUS_MEM_ERR;
            }
            info->info.ipInfo.port = option->info.ipOption.port;
            break;
        case CONNECT_BR:
            info->type = AUTH_LINK_TYPE_BR;
            if (strcpy_s(info->info.brInfo.brMac, sizeof(info->info.brInfo.brMac),
                option->info.brOption.brMac) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy brMac failed.");
                return SOFTBUS_MEM_ERR;
            }
            break;
        case CONNECT_BLE:
            info->type = AUTH_LINK_TYPE_BLE;
            if (strcpy_s(info->info.bleInfo.bleMac, sizeof(info->info.bleInfo.bleMac),
                option->info.bleOption.bleMac) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "copy bleMac failed.");
                return SOFTBUS_MEM_ERR;
            }
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "unknown type, type = %d.", option->type);
            return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

bool CompareConnectOption(const ConnectOption *option1, const ConnectOption *option2)
{
    if (option1 == NULL || option2 == NULL) {
        return false;
    }
    switch (option1->type) {
        case CONNECT_TCP:
            if (option2->type == CONNECT_TCP &&
                strcmp(option1->info.ipOption.ip, option2->info.ipOption.ip) == 0) {
                return true;
            }
            break;
        case CONNECT_BR:
            if (option2->type == CONNECT_BR &&
                strcmp(option1->info.brOption.brMac, option2->info.brOption.brMac) == 0) {
                return true;
            }
            break;
        case CONNECT_BLE:
            if (option2->type == CONNECT_BLE &&
                strcmp(option1->info.bleOption.bleMac, option2->info.bleOption.bleMac) == 0) {
                return true;
            }
            break;
        default:
            break;
    }
    return false;
}

void AnoonymousDid(char *outBuf, uint32_t len)
{
    if (outBuf == NULL || len == 0) {
        return;
    }
    uint32_t size = len > MAX_BYTE_RECORD ? MAX_BYTE_RECORD : len;
    uint32_t internal = 1;
    while ((internal * ANONYMOUS_INTEVER_LEN) < size) {
        outBuf[internal * ANONYMOUS_INTEVER_LEN] = '*';
        outBuf[internal * ANONYMOUS_INTEVER_LEN - 1] = '*';
        outBuf[internal * ANONYMOUS_INTEVER_LEN - 2] = '*';
        outBuf[internal * ANONYMOUS_INTEVER_LEN - 3] = '*';
        ++internal;
    }
}

void AuthPrintDfxMsg(uint32_t module, char *data, int len)
{
    if (!GetSignalingMsgSwitch()) {
        return;
    }
    if (data == NULL || len <= 0) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid parameter");
        return;
    }
    if (!(module == MODULE_TRUST_ENGINE ||
        module == MODULE_AUTH_CONNECTION ||
        module == DATA_TYPE_DEVICE_ID ||
        module == DATA_TYPE_SYNC)) {
        return;
    }
    int32_t size = len > MAX_BYTE_RECORD ? (MAX_BYTE_RECORD - 1) : len;
    char outBuf[MAX_BYTE_RECORD + 1] = {0};
    if (ConvertBytesToHexString(outBuf, MAX_BYTE_RECORD, (const unsigned char *)data, size / 2) == SOFTBUS_OK) {
        AnoonymousDid(outBuf, strlen(outBuf));
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "[signaling]:%s", outBuf);
    }
}