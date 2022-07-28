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

#ifndef SOFTBUS_HIDUMPER_DISC_H
#define SOFTBUS_HIDUMPER_DISC_H
#include <stdio.h>

typedef enum {
    SOFTBUS_DISC_DUMP_VAR_BLEINFOMANGER = 0,
    SOFTBUS_DISC_DUMP_VAR_BLEADVERTISER,
    SOFTBUS_DISC_DUMP_VAR_BLELISTENER,
    SOFTBUS_DISC_DUMP_VAR_PUBLICMGR,
    SOFTBUS_DISC_DUMP_VAR_SUBSCRIBEMGR,
    SOFTBUS_DISC_DUMP_VAR_CAPABILITYDATA,
    SOFTBUS_DISC_DUMP_VAR_LOCALDEVINFO,

    SOFTBUS_DISC_DUMP_VAR_BUTT,    
} SoftBusDiscDumpVar;

typedef int SoftBusDiscDumpCb(int fd);
int SoftBusRegDiscDumpCb(int varId, SoftBusDiscDumpCb cb);
int SoftBusDiscDumpHander(int fd, int argc, const char **argv);
#endif /* SOFTBUS_HIDUMPER_DISC_H */