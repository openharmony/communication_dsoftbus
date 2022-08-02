/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef NSTACKX_STATISTICS_H
#define NSTACKX_STATISTICS_H
#include <stdint.h>

typedef enum {
    INVALID_OPT_AND_PAYLOAD,
    DECODE_FAILED,
    ENCODE_FAILED,
    CREATE_HEADER_FAILED,
    BUILD_PKT_FAILED,
    SOCKET_ERROR,
    EPOLL_ERROR,
    CREATE_SERVER_FAILED,
    CREATE_CLIENT_FAILED,
    DROP_LOOPBACK_PKT,
    SEND_MSG_FAILED,
    SEND_REQUEST_FAILED,
    DROP_MSG_ID,
    HANDLE_SERVICE_MSG_FAILED,
    HANDLE_DEVICE_DISCOVER_MSG_FAILED,
    INVALID_RESPONSE_MSG,
    POST_SD_REQUEST_FAILED,
    ABORT_SD,
    START_SD_FAILED,
    CREATE_SERVICE_MSG_FAILED,
    SEND_SD_RESPONSE_FAILED,
    BACKUP_DEVICE_DB_FAILED,
    UPDATE_DEVICE_DB_FAILED,
    CREATE_CONTEX_FAILED,
    CREATE_SESSION_FAILED,
    PREPARE_SD_MSG_FAILED,
    PARSE_SD_MSG_FAILED,
    ALLOC_RECORD_FAILED,
    FREE_RECORD_FAILED,
    STATISTICS_MAX
} StatisticsType;

void InitStatistics(void);
void IncStatistics(StatisticsType type);
const uint64_t *GetStatistics();
#endif