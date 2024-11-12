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
#include <stdio.h>
#include "legacy/softbus_hidumper_trans.h"
#include "softbus_error_code.h"

int32_t SoftBusRegTransVarDump(const char* dumpVar, SoftBusVarDumpCb cb)
{
    (void)dumpVar;
    (void)cb;
    return SOFTBUS_OK;
}

void SoftBusTransDumpRegisterSession(int fd, const char* pkgName, const char* sessionName,
    int uid, int pid)
{
    (void)fd;
    (void)pkgName;
    (void)sessionName;
    (void)uid;
    (void)pid;

    return;
}

void SoftBusTransDumpRunningSession(int fd, TransDumpLaneLinkType type, AppInfo* appInfo)
{
    (void)fd;
    (void)type;
    (void)appInfo;

    return;
}

int32_t SoftBusTransDumpHanderInit(void)
{
    return SOFTBUS_OK;
}

void SoftBusHiDumperTransDeInit(void)
{
}

int32_t SoftBusTransDumpHandlerInit(void)
{
    return SOFTBUS_OK;
}
