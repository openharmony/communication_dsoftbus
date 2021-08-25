/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_CONFIG_TYPE_H
#define SOFTBUS_CONFIG_TYPE_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

typedef enum {
    SOFTBUS_INT_MAX_BYTES_LENGTH, /* the default val is 4194304 */
    SOFTBUS_INT_MAX_MESSAGE_LENGTH, /* the default val is 4096 */
    SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH, /* the default val is 4096 */
    SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN, /* the default val is 990 */
    SOFTBUS_INT_CONN_BR_RECEIVE_MAX_LEN, /* the default val is 10 */
    SOFTBUS_INT_CONN_TCP_MAX_LENGTH, /* the default val is 3072 */
    SOFTBUS_INT_CONN_TCP_MAX_CONN_NUM, /* the default val is 30 */
    SOFTBUS_INT_CONN_TCP_TIME_OUT, /* the default val is 100 */
    SOFTBUS_INT_MAX_NODE_STATE_CB_CNT, /* the default val is 10 */
    SOFTBUS_INT_MAX_LNN_CONNECTION_CNT, /* the default val is 10 */
    SOFTBUS_INT_LNN_SUPPORT_CAPBILITY, /* the default val is 22 */
    SOFTBUS_INT_AUTH_ABILITY_COLLECTION, /* the default val is 0 */
    SOFTBUS_INT_ADAPTER_LOG_LEVEL, /* the default val is 0 */
    SOFTBUS_STR_STORAGE_DIRECTORY, /* the max length is MAX_STORAGE_PATH_LEN */
    SOFTBUS_CONFIG_TYPE_MAX,
} ConfigType;

typedef struct {
    int32_t (* SetConfig)(ConfigType type, const unsigned char *val, int32_t len);
} ConfigSetProc;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif