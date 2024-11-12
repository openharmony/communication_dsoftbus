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

#ifndef SOFTBUS_HIDUMPER_H
#define SOFTBUS_HIDUMPER_H

#include <stdint.h>
#include "common_list.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define SOFTBUS_MODULE_NAME_LEN 32
#define SOFTBUS_MODULE_HELP_LEN 128
#define SOFTBUS_DUMP_VAR_NAME_LEN 32
#define SOFTBUS_DUMP_EXIST 1
#define SOFTBUS_DUMP_NOT_EXIST 0

typedef int32_t (*SoftBusVarDumpCb)(int fd);

typedef struct {
    ListNode node;
    char varName[SOFTBUS_MODULE_NAME_LEN];
    SoftBusVarDumpCb dumpCallback;
} SoftBusDumpVarNode;

typedef int32_t (*DumpHandlerFunc)(int fd, int32_t argc, const char **argv);

typedef struct {
    ListNode node;
    char moduleName[SOFTBUS_MODULE_NAME_LEN];
    char helpInfo[SOFTBUS_MODULE_HELP_LEN];
    DumpHandlerFunc dumpHandler;
} HandlerNode;

void SoftBusDumpShowHelp(int fd);
void SoftBusDumpErrInfo(int fd, const char *argv);
void SoftBusDumpSubModuleHelp(int fd, char *moduleName, ListNode *varList);
int32_t SoftBusAddDumpVarToList(const char *dumpVar, SoftBusVarDumpCb cb, ListNode *subModoleVarList);
void SoftBusReleaseDumpVar(ListNode *varList);
int32_t SoftBusRegHiDumperHandler(char *moduleName, char *helpInfo, DumpHandlerFunc handler);
int32_t SoftBusDumpDispatch(int fd, int32_t argc, const char **argv);
int32_t SoftBusHiDumperModuleInit(void);
void SoftBusHiDumperModuleDeInit(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* SOFTBUS_HIDUMPER_H */
