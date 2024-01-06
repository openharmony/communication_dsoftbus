/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

/**
 * @file softbus_broadcast_utils.h
 * @brief Declare functions and constants for the softbus broadcast or scan data fill or parse common functions.
 *
 * @since 4.1
 * @version 1.0
 */

#ifndef SOFTBUS_BROADCAST_UTILS_H
#define SOFTBUS_BROADCAST_UTILS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"{
#endif

#define MEDIUM_NUM_MAX         2

// max broadcasting and scan limit
#define BC_NUM_MAX             16
#define SCAN_NUM_MAX           16

#define BC_DATA_MAX_LEN        24
#define RSP_DATA_MAX_LEN       27
#define BC_BYTE_MASK           0xFF
#define BC_SHIFT_BIT           8

// adv broadcast head
#define BC_HEAD_LEN             7
#define BC_FLAG_LEN             3
#define IDX_BC_FLAG_BYTE_LEN    0
#define IDX_BC_FLAG_AD_TYPE     1
#define IDX_BC_FLAG_AD_DATA     2
#define IDX_PACKET_LEN          3
#define IDX_BC_TYPE             4
#define IDX_BC_UUID             5
#define BC_UUID_LEN             2

#define BC_FLAG_BYTE_LEN        0x2
#define BC_FLAG_AD_TYPE         0x1
#define BC_FLAG_AD_DATA         0x2

// broadcast type
#define SHORTENED_LOCAL_NAME_BC_TYPE    0x08
#define LOCAL_NAME_BC_TYPE       0x09
#define SERVICE_BC_TYPE          0x16
#define MANUFACTURE_BC_TYPE      0xFF

// scan rsp head
#define RSP_HEAD_LEN             4

#define IDX_RSP_PACKET_LEN       0
#define IDX_RSP_TYPE             1
#define IDX_RSP_UUID             2
#define RSP_UUID_LEN             2

#define RSP_FLAG_BYTE_LEN        0x2
#define RSP_FLAG_AD_TYPE         0x1
#define RSP_FLAG_AD_DATA         0x2

#ifdef __cplusplus
}
#endif

#endif /* SOFTBUS_BROADCAST_UTILS_H */
