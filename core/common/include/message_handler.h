/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef MESSAGE_HANDLER_H
#define MESSAGE_HANDLER_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SoftBusMessage SoftBusMessage;
typedef struct SoftBusHandler SoftBusHandler;
typedef struct SoftBusLooperContext SoftBusLooperContext;
typedef struct SoftBusLooper SoftBusLooper;
typedef struct FfrtMsgQueue MsgQueue;

struct SoftBusLooper {
    SoftBusLooperContext *context;
    MsgQueue *queue;
    bool dumpable;
    void (*PostMessage)(const SoftBusLooper *looper, SoftBusMessage *msg);
    void (*PostMessageDelay)(const SoftBusLooper *looper, SoftBusMessage *msg, uint64_t delayMillis);
    void (*RemoveMessage)(const SoftBusLooper *looper, const SoftBusHandler *handler, int32_t what);
    // customFunc, when match, return 0
    void (*RemoveMessageCustom)(const SoftBusLooper *looper, const SoftBusHandler *handler,
        int32_t (*)(const SoftBusMessage*, void*), void *args);
};

struct SoftBusHandler {
    char *name;
    SoftBusLooper *looper;
    void (*HandleMessage)(SoftBusMessage *msg);
};

struct SoftBusMessage {
    int32_t what;
    uint64_t arg1;
    uint64_t arg2;
    int64_t time;
    void *obj;
    SoftBusHandler *handler;
    void (*FreeMessage)(SoftBusMessage *msg);
};

SoftBusMessage *MallocMessage(void);

void FreeMessage(SoftBusMessage *msg);

enum LooperType {
    LOOP_TYPE_DEFAULT = 1,
    LOOP_TYPE_CONN,
    LOOP_TYPE_LNN
};

SoftBusLooper *GetLooper(int looper);

int LooperInit(void);

void SetLooper(int type, SoftBusLooper *looper);

void LooperDeinit(void);

void DumpLooper(const SoftBusLooper *looper);

SoftBusLooper *CreateNewLooper(const char *name);

void DestroyLooper(SoftBusLooper *looper);

void SetLooperDumpable(SoftBusLooper *looper, bool dumpable);

#ifdef __cplusplus
}
#endif

#endif /* MESSAGE_HANDLER_H */
