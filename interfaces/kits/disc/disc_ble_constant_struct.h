/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef DISC_BLE_CONSTANT_STRUCT_H
#define DISC_BLE_CONSTANT_STRUCT_H

#define INT32_MAX_BIT_NUM                        32
#define MAX_CAP_NUM                              (CAPABILITY_NUM * INT32_MAX_BIT_NUM)

#define BLE_SCAN_FILTER_LEN                      7
#define SOFTBUS_BLE_CLIENT_ID                    0x1
#define SHA_HASH_LEN                             32
#define BT_ADDR_LEN                              6
#define BLE_DISCOVERY_TYPE_VAL_MAX_LEN           16
#define PRE_LINK_MAX_LEN                         16
#define DISC_EXT_CUST_MAX_LEN                    256

#define BLE_DISCOVERY_KEY_CUST                   "castPlus"
#define BLE_DISCOVERY_KEY_EXT_CUST               "extCustData"
#define BLE_DISCOVERY_KEY_ACTION_ID              "actionId"
#define BLE_DISCOVERY_KEY_PRE_LINKTYPE           "preLinkType"

#define BLE_DISCOVERY_KEY_HML                    "HML"

#define BLE_DISCOVERY_TYPE                       "discType"
#define BLE_DISCOVERY_TYPE_HANDLE                "handle"
#define BLE_REPORT_HANDLE_JSON_LEY               "handleId"

/* TLV constant defination */
#define TLV_TYPE_END                             0x00
#define TLV_TYPE_DEVICE_ID_HASH                  0x01
#define TLV_TYPE_DEVICE_TYPE                     0x02
#define TLV_TYPE_DEVICE_NAME                     0x03
#define TLV_TYPE_CUST                            0x04
#define TLV_TYPE_BR_MAC                          0x05
#define TLV_TYPE_RANGE_POWER                     0x06
#define TLV_TYPE_ACTION                          0x07

#define POS_VERSION                              0
#define POS_BUSINESS                             1
#define POS_BUSINESS_EXTENSION                   2
#define POS_USER_ID_HASH                         3
#define POS_CAPABILITY                           5
#define POS_CAPABILITY_EXTENSION                 6
#define POS_TLV                                  7

#define SHORT_USER_ID_HASH_LEN                   2
#define SHORT_DEVICE_ID_HASH_LENGTH              8
#define BT_MAX_STR_LEN                           18
#define BT_MAC_BYTES_LEN                         6
#define DEVICE_TYPE_LEN                          2
#define DEVICE_TYPE_MASK                         0xFF
#define ONE_BYTE_LENGTH                          8
#define RANGE_POWER_TYPE_LEN                     1

#endif