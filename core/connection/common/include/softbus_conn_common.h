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

#ifndef SOFTBUS_CONN_COMMON_H
#define SOFTBUS_CONN_COMMON_H

#include <stdint.h>

#include "message_handler.h"
#include "softbus_error_code.h"

#ifdef __cplusplus
extern "C" {
#endif

#define COMPARE_SUCCESS 0
#define COMPARE_FAILED  1
#define MAX_DATA_LEN (40 * 1000)
// provide remove event compare function field
typedef struct {
    SoftBusHandler handler;
    int (*eventCompareFunc)(const SoftBusMessage *, void *);
} SoftBusHandlerWrapper;

typedef struct {
    uint8_t *buffer;
    uint32_t capacity;
    uint32_t length;
} LimitedBuffer;

int32_t ConnStartActionAsync(void *arg, void *(*runnable)(void *));
void ConvertAnonymizeMacAddress(char *outAnomize, uint32_t anomizeLen, const char *mac, uint32_t macLen);
void ConvertAnonymizeSensitiveString(char *outAnomize, uint32_t anomizeLen, const char *origin);
void ConvertAnonymizeIpAddress(char *outAnomize, uint32_t anomizeLen, const char *ip, uint32_t ipLen);

int32_t ConnPostMsgToLooper(
    SoftBusHandlerWrapper *wrapper, int32_t what, uint64_t arg1, uint64_t arg2, void *obj, uint64_t delayMillis);
void ConnRemoveMsgFromLooper(
    const SoftBusHandlerWrapper *wrapper, int32_t what, uint64_t arg1, uint64_t arg2, void *obj);

int32_t ConnNewLimitedBuffer(LimitedBuffer **outLimiteBuffer, uint32_t capacity);
void ConnDeleteLimitedBuffer(LimitedBuffer **limiteBuffer);
#ifdef __cplusplus
}
#endif /* __clpusplus */
#endif /* SOFTBUS_CONN_COMMON_H  */