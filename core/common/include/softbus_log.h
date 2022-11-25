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

#ifndef SOFTBUS_LOG_H
#define SOFTBUS_LOG_H

#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include "softbus_adapter_log.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#if defined(__ICCARM__) || defined(__LITEOS_M__)
#define SOFTBUS_DPRINTF(fd, fmt, ...)
#else
#define SOFTBUS_DPRINTF(fd, fmt, ...) dprintf(fd, fmt, ##__VA_ARGS__)
#endif

typedef enum {
    SOFTBUS_LOG_AUTH,
    SOFTBUS_LOG_TRAN,
    SOFTBUS_LOG_CONN,
    SOFTBUS_LOG_LNN,
    SOFTBUS_LOG_DISC,
    SOFTBUS_LOG_COMM,
    SOFTBUS_LOG_MODULE_MAX,
} SoftBusLogModule;

void SoftBusLog(SoftBusLogModule module, SoftBusLogLevel level, const char *fmt, ...);
void NstackxLog(const char *moduleName, uint32_t nstackLevel, const char *format, ...);

void AnonyPacketPrintout(SoftBusLogModule module, const char *msg, const char *packet, size_t packetLen);

const char *AnonyDevId(char **outName, const char *inName);

#define UUID_ANONYMIZED_LENGTH 4
#define NETWORKID_ANONYMIZED_LENGTH 4
#define UDID_ANONYMIZED_LENGTH 4
#define MACADDR_ANONYMIZED_LENGTH 5

const char *Anonymizes(const char *target, const uint8_t expectAnonymizedLength);

static inline const char *AnonymizesUUID(const char *input)
{
    return Anonymizes(input, UUID_ANONYMIZED_LENGTH);
}

static inline const char *AnonymizesNetworkID(const char *input)
{
    return Anonymizes(input, NETWORKID_ANONYMIZED_LENGTH);
}

static inline const char *AnonymizesUDID(const char *input)
{
    return Anonymizes(input, UDID_ANONYMIZED_LENGTH);
}

static inline const char *AnonymizesMac(const char *input)
{
    return Anonymizes(input, MACADDR_ANONYMIZED_LENGTH);
}

// discovery log print macro
#define DLOGD(fmt, ...) SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_DBG, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)
#define DLOGI(fmt, ...) SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)
#define DLOGW(fmt, ...) SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_WARN, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)
#define DLOGE(fmt, ...) SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)

// connection log print macro
#define CLOGD(fmt, ...) SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)
#define CLOGI(fmt, ...) SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)
#define CLOGW(fmt, ...) SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_WARN, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)
#define CLOGE(fmt, ...) SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)

// bus center lnn log print macro
#define LLOGD(fmt, ...) SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)
#define LLOGI(fmt, ...) SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)
#define LLOGW(fmt, ...) SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)
#define LLOGE(fmt, ...) SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)

// transmission log print macro
#define TLOGD(fmt, ...) SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_DBG, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)
#define TLOGI(fmt, ...) SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)
#define TLOGW(fmt, ...) SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)
#define TLOGE(fmt, ...) SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)

// authority log print macro
#define ALOGD(fmt, ...) SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_DBG, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)
#define ALOGI(fmt, ...) SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)
#define ALOGW(fmt, ...) SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_WARN, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)
#define ALOGE(fmt, ...) SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)

// common log print macro
#define MLOGD(fmt, ...) SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_DBG, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)
#define MLOGI(fmt, ...) SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)
#define MLOGW(fmt, ...) SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_WARN, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)
#define MLOGE(fmt, ...) SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "[%s()] " fmt, __FUNCTION__, ##__VA_ARGS__)

#define CHECK_AND_RETURN_RET_LOG(cond, ret, log, fmt, ...)  \
    do {                                                    \
        if (!(cond)) {                                      \
            log(fmt, ##__VA_ARGS__);                        \
            return ret;                                     \
        }                                                   \
    } while (0)

#define CHECK_AND_RETURN_LOG(cond, log, fmt, ...)           \
    do {                                                    \
        if (!(cond)) {                                      \
            log(fmt, ##__VA_ARGS__);                        \
            return;                                         \
        }                                                   \
    } while (0)

#define DISC_CHECK_AND_RETURN_RET_LOG(cond, ret, fmt, ...)             \
    CHECK_AND_RETURN_RET_LOG(cond, ret, DLOGE, fmt, ##__VA_ARGS__)
#define DISC_CHECK_AND_RETURN_LOG(cond, fmt, ...)                      \
    CHECK_AND_RETURN_LOG(cond, DLOGE, fmt, ##__VA_ARGS__)

#define CONN_CHECK_AND_RETURN_RET_LOG(cond, ret, fmt, ...)             \
    CHECK_AND_RETURN_RET_LOG(cond, ret, CLOGE, fmt, ##__VA_ARGS__)
#define CONN_CHECK_AND_RETURN_LOG(cond, fmt, ...)                      \
    CHECK_AND_RETURN_LOG(cond, CLOGE, fmt, ##__VA_ARGS__)

#define LNN_CHECK_AND_RETURN_RET_LOG(cond, ret, fmt, ...)              \
    CHECK_AND_RETURN_RET_LOG(cond, ret, LLOGE, fmt, ##__VA_ARGS__)
#define LNN_CHECK_AND_RETURN_LOG(cond, fmt, ...)                       \
    CHECK_AND_RETURN_LOG(cond, LLOGE, fmt, ##__VA_ARGS__)

#define TRAN_CHECK_AND_RETURN_RET_LOG(cond, ret, fmt, ...)             \
    CHECK_AND_RETURN_RET_LOG(cond, ret, TLOGE, fmt, ##__VA_ARGS__)
#define TRAN_CHECK_AND_RETURN_LOG(cond, fmt, ...)                      \
    CHECK_AND_RETURN_LOG(cond, TLOGE, fmt, ##__VA_ARGS__)

#define AUTH_CHECK_AND_RETURN_RET_LOG(cond, ret, fmt, ...)             \
    CHECK_AND_RETURN_RET_LOG(cond, ret, ALOGE, fmt, ##__VA_ARGS__)
#define AUTH_CHECK_AND_RETURN_LOG(cond, fmt, ...)                      \
    CHECK_AND_RETURN_LOG(cond, ALOGE, fmt, ##__VA_ARGS__)

#define COMM_CHECK_AND_RETURN_RET_LOG(cond, ret, fmt, ...)             \
    CHECK_AND_RETURN_RET_LOG(cond, ret, MLOGE, fmt, ##__VA_ARGS__)
#define COMM_CHECK_AND_RETURN_LOG(cond, fmt, ...)                      \
    CHECK_AND_RETURN_LOG(cond, MLOGE, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* SOFTBUS_LOG_H */