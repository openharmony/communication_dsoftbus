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

#ifndef IF_BUS_CENTER_EX_STRUCT_H
#define IF_BUS_CENTER_EX_STRUCT_H

#include <stdbool.h>
#include <stdint.h>
#include "meta_socket_struct.h"
#include "softbus_bus_center.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DATA_MAX_LEN 2048

typedef enum {
    DISCOVERT_POLICY_ALLOW_REPLY,
    DISCOVERT_POLICY_REJECT_REPLY,
    DISCOVERT_POLICY_ALLOW_REPLY_SYNC,
} DiscoveryPolicy;

/**
* @brief Defines parameter, see {@link CustomData}.
*
* @since 1.0
* @version 1.0
*/
typedef struct {
    MetaNodeType type;           /**< User type */
    uint8_t data[DATA_MAX_LEN];  /**< User data */
} CustomData;

#ifdef __cplusplus
}
#endif

#endif  //SOFTBUS_BUS_CENTER_EX_STRUCT_H