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
#include <inttypes.h>
#include "softbus_adapter_log.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
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

int32_t AnonymizePacket(char **output, const char *in, size_t len);

const char *AnonyDevId(char **outName, const char *inName, size_t inNameLen);

#define UUID_ANONYMIZED_LENGTH 4
#define NETWORKID_ANONYMIZED_LENGTH 4
#define UDID_ANONYMIZED_LENGTH 4

const char *Anonymizes(const char *target, const uint8_t expectAnonymizedLength);

inline const char *AnonymizesUUID(const char *input)
{
    return Anonymizes(input, UUID_ANONYMIZED_LENGTH);
}

inline const char *AnonymizesNetworkID(const char *input)
{
    return Anonymizes(input, NETWORKID_ANONYMIZED_LENGTH);
}

inline const char *AnonymizesUDID(const char *input)
{
    return Anonymizes(input, UDID_ANONYMIZED_LENGTH);
}

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* SOFTBUS_LOG_H */
