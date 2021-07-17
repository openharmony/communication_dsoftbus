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

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

typedef enum {
    SOFTBUS_INT_MAX_BYTES_LENGTH,
    SOFTBUS_INT_MAX_MESSAGE_LENGTH,
    SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH,
    SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN,
    SOFTBUS_INT_CONN_BR_RECEIVE_MAX_LEN,
    SOFTBUS_INT_CONN_TCP_MAX_LENGTH,
    SOFTBUS_INT_CONN_TCP_MAX_CONN_NUM,
    SOFTBUS_INT_CONN_TCP_TIME_OUT,
    SOFTBUS_INT_MAX_NODE_STATE_CB_CNT,
    SOFTBUS_INT_MAX_LNN_CONNECTION_CNT,
    SOFTBUS_INT_LNN_SUPPORT_CAPBILITY,
    SOFTBUS_INT_AUTH_ABILITY_COLLECTION,
    SOFTBUS_CONFIG_TYPE_MAX,
} ConfigType;

typedef struct {
    int (* SetConfig)(ConfigType type, unsigned char *val, int len);
} ConfigSetProc;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif