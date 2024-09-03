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
    SOFTBUS_INT_MAX_BYTES_NEW_LENGTH, /* the default val is 4194304 */
    SOFTBUS_INT_MAX_MESSAGE_NEW_LENGTH, /* the default val is 4096 */
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
    SOFTBUS_INT_LNN_SUPPORT_CAPABILITY, /* the default val is 30 */
    SOFTBUS_INT_AUTH_ABILITY_COLLECTION, /* the default val is 0 */
    SOFTBUS_INT_ADAPTER_LOG_LEVEL, /* the default val is 0 */
    SOFTBUS_STR_STORAGE_DIRECTORY, /* the max length is MAX_STORAGE_PATH_LEN */
    SOFTBUS_INT_SUPPORT_TCP_PROXY, /* the l0 devices val is 0 , others is 1 */
    SOFTBUS_INT_LNN_UDID_INIT_DELAY_LEN, /* the default val is 0 */
    SOFTBUS_STR_LNN_NET_IF_NAME, /* the default val is 0:eth0,1:wlan0 */
    SOFTBUS_INT_LNN_MAX_CONCURRENT_NUM, /* the default val is 0 */
    SOFTBUS_INT_AUTH_MAX_BYTES_LENGTH, /* L1: 4K, L2: 64K */
    SOFTBUS_INT_AUTH_MAX_MESSAGE_LENGTH, /* L1: 1K, L2: 4K */
    SOFTBUS_INT_AUTO_NETWORKING_SWITCH, /* support auto networking: true, not support: false */
    SOFTBUS_BOOL_SUPPORT_TOPO, /* support: true, not support: false */
    SOFTBUS_INT_DISC_FREQ, /* the default val is 5s 12 times */
    SOFTBUS_INT_PROXY_MAX_BYTES_LENGTH, /* 4K */
    SOFTBUS_INT_PROXY_MAX_MESSAGE_LENGTH, /* 1K */
    SOFTBUS_INT_LNN_SUPPORT_FEATURE, /* the default val is 30658 */
    SOFTBUS_INT_CONN_COC_MAX_DATA_LENGTH, /* the default val is 4096 */
    SOFTBUS_INT_CONN_COC_SEND_MTU, /* the default val is 990 */
    SOFTBUS_INT_CONN_BLE_CLOSE_DELAY_TIME, /* the default val is 1000 */
    SOFTBUS_INT_BLE_MAC_AUTO_REFRESH_SWITCH, /* the default val is 1 */
    SOFTBUS_INT_DISC_COAP_MAX_DEVICE_NUM, /* the default val is 20 */
    SOFTBUS_INT_AUTH_CAPACITY, /* the default val is 0x07 */
    SOFTBUS_CONFIG_TYPE_MAX,
} ConfigType;

typedef struct {
    int32_t (* SetConfig)(ConfigType type, const unsigned char *val, uint32_t len);
} ConfigSetProc;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* SOFTBUS_CONFIG_TYPE_H */