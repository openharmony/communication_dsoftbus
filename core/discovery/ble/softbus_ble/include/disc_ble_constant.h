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

#ifndef DISC_BLE_CONSTANT_H
#define DISC_BLE_CONSTANT_H

#define INT32_MAX_BIT_NUM 32
#define MAX_CAP_NUM (CAPABILITY_NUM * INT32_MAX_BIT_NUM)

#define BLE_SCAN_FILTER_LEN 5
#define SOFTBUS_BLE_CLIENT_ID 0x1

#define SHA_HASH_LEN 32
#define BLE_UUID 0xFDEE
#define COMPANY_ID 0x027D
#define BYTE_SHIFT_BIT 8

#define BT_ADDR_LEN 6

/* ADV Boardcast head */
#define POS_FLAG_BYTE_LEN 0
#define POS_FLAG_AD_TYPE 1
#define POS_FLAG_AD_DATA 2
#define POS_PACKET_LENGTH 3
#define POS_AD_TYPE 4
#define POS_UUID 5
#define UUID_LEN 2
#define ADV_HEAD_LEN 7
#define RSP_HEAD_LEN 4

#define FLAG_BYTE_LEN 0x2
#define FLAG_AD_TYPE 0x1
#define FLAG_AD_DATA 0x2
#define AD_TYPE 0x16

/* SCAN Rsp head */
#define POS_RSP_LENGTH 0
#define POS_RSP_TYPE 1
#define POS_COMPANY_ID 2
#define RSP_TYPE 0xFF

/* TLV constant defination */
#define TLV_TYPE_END 0x00
#define TLV_TYPE_DEVICE_ID_HASH 0x01
#define TLV_TYPE_DEVICE_TYPE 0x02
#define TLV_TYPE_DEVICE_NAME 0x03
#define TLV_TYPE_CUST 0x04
#define TLV_TYPE_BR_MAC 0x05
#define TLV_TYPE_RANGE_POWER 0x06

#define POS_VERSION 0
#define POS_BUSINESS 1
#define POS_BUSINESS_EXTENSION 2
#define POS_USER_ID_HASH 3
#define POS_CAPABLITY 5
#define POS_CAPABLITY_EXTENSION 6
#define POS_TLV 7

#define SHORT_USER_ID_HASH_LEN 2
#define SHORT_DEVICE_ID_HASH_LENGTH 8
#define BT_MAX_STR_LEN 18
#define BT_MAC_BYTES_LEN 6
#define DEVICE_TYPE_LEN 2
#define DEVICE_TYPE_MASK 0xFF
#define ONE_BYTE_LENGTH 8
#define RANGE_POWER_TYPE_LEN 1
#define TL_LEN 1

#define MAX_BROADCAST_DATA_LEN 31
#define SCAN_RSP_HEADER_LEN 4

#endif
