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

#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"


#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_AUTH_ABILITY_COLLECTION 0
#define AUTH_SUPPORT_SERVER_SIDE_MASK 0x01
#define INTERVAL_VALUE 2
#define OFFSET_BITS 24
#define INT_MAX_VALUE 0xFFFFFEL
#define LOW_24_BITS 0xFFFFFFL
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
    temp = ((g_uniqueId << OFFSET_BITS) | (temp & LOW_24_BITS));
    int64_t seq = 0;
    if (memcpy_s(&seq, sizeof(int64_t), &temp, sizeof(uint64_t)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "memcpy_s seq error");
    }
    return seq;
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
        case CONNECT_BR: {
            if (strncpy_s(key, size, option->info.brOption.brMac, BT_MAC_LEN) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "strncpy_s failed");
                return SOFTBUS_ERR;
            }
            *len = BT_MAC_LEN;
            break;
        }
        case CONNECT_TCP: {
            if (strncpy_s(key, size, option->info.ipOption.ip, IP_LEN) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "strncpy_s failed");
                return SOFTBUS_ERR;
            }
            *len = IP_LEN;
            break;
        }
        default: {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "unknown type");
            return SOFTBUS_ERR;
        }
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
            if (strncpy_s(option->info.brOption.brMac, BT_MAC_LEN, connInfo->info.brInfo.brMac, BT_MAC_LEN) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "strncpy_s failed");
                return SOFTBUS_ERR;
            }
            break;
        }
        case CONNECT_TCP: {
            if (strncpy_s(option->info.ipOption.ip, IP_LEN, connInfo->info.ipInfo.ip, IP_LEN) != EOK) {
                SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "strncpy_s failed");
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

#ifdef __cplusplus
}
#endif
