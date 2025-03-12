/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "client_trans_socket_option.h"

#include "client_trans_session_manager.h"
#include "softbus_error_code.h"
#include "trans_log.h"
#include "trans_type.h"

typedef struct {
    OptType optType;
    int32_t (*GetOpt)(int32_t socket, OptLevel level, OptType optType, void *optValue, int32_t *optValueSize);
    int32_t (*SetOpt)(int32_t socket, OptLevel level, OptType optType, void *optValue, int32_t optValueSize);
} SocketOptMap;

static int32_t TransGetSocketMaxBufferLen(
    int32_t socket, OptLevel level, OptType optType, void *optValue, int32_t *optValueSize)
{
    (void)socket;
    (void)level;
    (void)optType;
    (void)optValue;
    (void)optValueSize;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t TransGetSocketFirstPackage(
    int32_t socket, OptLevel level, OptType optType, void *optValue, int32_t *optValueSize)
{
    (void)socket;
    (void)level;
    (void)optType;
    (void)optValue;
    (void)optValueSize;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t TransGetSocketMaxIdleTime(
    int32_t socket, OptLevel level, OptType optType, void *optValue, int32_t *optValueSize)
{
    if (socket < 0) {
        TRANS_LOGE(TRANS_SDK, "invalid socket, socket=%{public}d", socket);
        return SOFTBUS_INVALID_PARAM;
    }
    *optValueSize = sizeof(uint32_t);
    return GetMaxIdleTimeBySocket(socket, (uint32_t *)optValue);
}

static int32_t TransSetSocketMaxIdleTime(
    int32_t socket, OptLevel level, OptType optType, void *optValue, int32_t optValueSize)
{
    if (socket < 0 || optValueSize < (int32_t)sizeof(uint32_t)) {
        TRANS_LOGE(TRANS_SDK, "invalid param, socket=%{public}d, optValueSize=%{public}d", socket, optValueSize);
        return SOFTBUS_INVALID_PARAM;
    }

    uint32_t maxIdleTime = *(uint32_t *)optValue;
    return SetMaxIdleTimeBySocket(socket, maxIdleTime);
}

static int32_t TransGetSupportTlv(
    int32_t socket, OptLevel level, OptType optType, void *optValue, int32_t *optValueSize)
{
    if (socket <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid socket, socket=%{public}d", socket);
        return SOFTBUS_INVALID_PARAM;
    }
    return TransGetSupportTlvBySocket(socket, (bool *)optValue, optValueSize);
}

static int32_t TransSetNeedAck(
    int32_t socket, OptLevel level, OptType optType, void *optValue, int32_t optValueSize)
{
    if (socket <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid socket, socket=%{public}d, optValueSize=%{public}d", socket, optValueSize);
        return SOFTBUS_INVALID_PARAM;
    }
    if (optValueSize != sizeof(bool)) {
        TRANS_LOGE(TRANS_SDK, "optValueSize invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    bool needAck = *(bool *)optValue;
    return TransSetNeedAckBySocket(socket, needAck);
}

static SocketOptMap g_socketOptMap[] = {
    { OPT_TYPE_MAX_BUFFER, TransGetSocketMaxBufferLen, NULL },
    { OPT_TYPE_FIRST_PACKAGE, TransGetSocketFirstPackage, NULL },
    { OPT_TYPE_MAX_IDLE_TIMEOUT, TransGetSocketMaxIdleTime, TransSetSocketMaxIdleTime },
    { OPT_TYPE_SUPPORT_ACK, TransGetSupportTlv, NULL },
    { OPT_TYPE_NEED_ACK, NULL, TransSetNeedAck },
};

int32_t GetCommonSocketOpt(int32_t socket, OptLevel level, OptType optType, void *optValue, int32_t *optValueSize)
{
    if (optValue == NULL || optValueSize == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t count = sizeof(g_socketOptMap) / sizeof(SocketOptMap);
    for (int32_t i = 0; i < count; i++) {
        if (optType == g_socketOptMap[i].optType) {
            if (g_socketOptMap[i].GetOpt != NULL) {
                int32_t ret = g_socketOptMap[i].GetOpt(socket, level, optType, optValue, optValueSize);
                return ret;
            }
        }
    }
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t SetCommonSocketOpt(int32_t socket, OptLevel level, OptType optType, void *optValue, int32_t optValueSize)
{
    if (optValue == NULL || optValueSize <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t count = sizeof(g_socketOptMap) / sizeof(SocketOptMap);
    for (int32_t i = 0; i < count; i++) {
        if (optType == g_socketOptMap[i].optType) {
            if (g_socketOptMap[i].SetOpt != NULL) {
                int32_t ret = g_socketOptMap[i].SetOpt(socket, level, optType, optValue, optValueSize);
                return ret;
            }
        }
    }
    return SOFTBUS_NOT_IMPLEMENT;
}