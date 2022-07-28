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
#ifndef SOFTBUS_HIDUMPER_CONN_H
#define SOFTBUS_HIDUMPER_CONN_H
#include <stdio.h>

typedef enum {
    SOFTBUS_CONN_DUMP_VAR_BLECONNECTLIST = 0,
    SOFTBUS_CONN_DUMP_VAR_BLGATTCINFOLIST,
    SOFTBUS_CONN_DUMP_VAR_BLEGATTSERVICE,
    SOFTBUS_CONN_DUMP_VAR_BRCONNECTLIST,
    SOFTBUS_CONN_DUMP_VAR_BRPENDINGLIST,
    SOFTBUS_CONN_DUMP_VAR_TCPCONNECTLIST,
    SOFTBUS_CONN_DUMP_VAR_P2PCONNECTINGDEVICE,
    SOFTBUS_CONN_DUMP_VAR_P2PCONNECTEDDEVICE,

    SOFTBUS_CONN_DUMP_VAR_BUTT,    
} SoftBusConnDumpVar;
typedef int SoftBusConnDumpCb(int fd);
int SoftBusRegConnDumpCb(int varId, SoftBusConnDumpCb cb);
int SoftBusConnDumpHander(int fd, int argc, const char **argv);
#endif /* SOFTBUS_HIDUMPER_CONN_H */