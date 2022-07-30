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

#include "common_list.h"

#define SOFTBUS_MODULE_NAME_LEN 16
#define SOFTBUS_MODULE_HELP_LEN 128
#define SOFTBUS_DUMP_VAR_NAME_LEN 16
#define SOFTBUS_DUMP_EXIST 1
#define SOFTBUS_DUMP_NOT_EXIST 0

typedef int (*SoftBusVarDumpCb)(int fd);

typedef struct {
    ListNode node;
    char varName[SOFTBUS_MODULE_NAME_LEN];
    SoftBusVarDumpCb dumpCallback;
} SoftBusDumpVarNode;

typedef int (*DumpHandlerFunc)(int fd, int argc, const char **argv);

typedef struct {
    ListNode node;
    char moduleName[SOFTBUS_MODULE_NAME_LEN];
    char helpInfo[SOFTBUS_MODULE_HELP_LEN];
    DumpHandlerFunc dumpHandler;
} HandlerNode;

void SoftBusDumpShowHelp(int fd);
void SoftBusDumpErrInfo(int fd, const char *argv);
void SoftBusDumpSubModuleHelp(int fd, char *moduleName, ListNode *varList);
int SoftBusAddDumpVarToList(char *dumpVar, SoftBusVarDumpCb cb, ListNode *subModoleVarList);
void SoftBusReleaseDumpVar(ListNode *varList);
void SoftBusHiDumperInit(void);
int SoftBusRegHiDumperHandler(char *moduleName, char *helpInfo, DumpHandlerFunc handler);
ListNode *SoftBusGetHiDumpHandler();

#endif
