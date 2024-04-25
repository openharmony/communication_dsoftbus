/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    STATS_INVALID_OPT_AND_PAYLOAD,
    STATS_DECODE_FAILED,
    STATS_ENCODE_FAILED,
    STATS_CREATE_HEADER_FAILED,
    STATS_BUILD_PKT_FAILED,
    STATS_SOCKET_ERROR,
    STATS_EPOLL_ERROR,
    STATS_CREATE_SERVER_FAILED,
    STATS_CREATE_CLIENT_FAILED,
    STATS_DROP_LOOPBACK_PKT,
    STATS_SEND_MSG_FAILED,
    STATS_SEND_REQUEST_FAILED,
    STATS_DROP_MSG_ID,
    STATS_HANDLE_SERVICE_MSG_FAILED,
    STATS_HANDLE_DEVICE_DISCOVER_MSG_FAILED,
    STATS_INVALID_RESPONSE_MSG,
    STATS_POST_SD_REQUEST_FAILED,
    STATS_ABORT_SD,
    STATS_START_SD_FAILED,
    STATS_CREATE_SERVICE_MSG_FAILED,
    STATS_SEND_SD_RESPONSE_FAILED,
    STATS_BACKUP_DEVICE_DB_FAILED,
    STATS_UPDATE_DEVICE_DB_FAILED,
    STATS_CREATE_CONTEX_FAILED,
    STATS_CREATE_SESSION_FAILED,
    STATS_PREPARE_SD_MSG_FAILED,
    STATS_PARSE_SD_MSG_FAILED,
    STATS_ALLOC_RECORD_FAILED,
    STATS_FREE_RECORD_FAILED,
    STATS_OVER_DEVICE_LIMIT,
    STATS_COAP_RESOURCE_INIT_FAILED,
    STATS_PREPARE_SN_MSG_FAILED,
    STATS_MAX
} StatisticsType;

void ResetStatistics(void);
void IncStatistics(StatisticsType type);
const uint64_t *GetStatistics(void);

#ifdef __cplusplus
}
#endif

#endif
