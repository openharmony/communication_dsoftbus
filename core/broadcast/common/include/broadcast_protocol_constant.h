/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef BROADCAST_PROTOCOL_CONSTANT_H
#define BROADCAST_PROTOCOL_CONSTANT_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_ADV_DATA_LEN            31
#define LENGTH_LEN                  1
#define AD_TYPE_LEN                 1
#define AD_ID_LEN                   2 /* Service UUID or Company ID */

/*            Adv Struct
 * | length |           Data           |
 * | length |   AD Type | AD Data      |
 */

/* Flag */
#define FLAG_DATA_LEN               2
#define FLAG_AD_DATA                0x2
#define FLAG_AD_DATA_LEN            (FLAG_DATA_LEN - AD_TYPE_LEN) /* 1 */
#define FLAG_ADV_LEN                (LENGTH_LEN + FLAG_DATA_LEN) /* 3 */

#define POS_FLAG_LEN                0
#define POS_FLAG_AD_TYPE            (POS_FLAG_LEN + LENGTH_LEN) /* 1 */
#define POS_FLAG_AD_DATA            (POS_FLAG_AD_TYPE + AD_TYPE_LEN) /* 2 */

/* Service Data */
#define SERVICE_AD_TYPE             0x16
#define SERVICE_AD_TYPE_LEN         1
#define SERVICE_UUID                0xFDEE

#define POS_SERVICE_DATA_LEN        (POS_FLAG_AD_DATA + FLAG_AD_DATA_LEN) /* 3 */
#define POS_AD_TYPE                 (POS_SERVICE_DATA_LEN + LENGTH_LEN) /* 4 */
#define POS_AD_UUID                 (POS_AD_TYPE + AD_TYPE_LEN) /* 5 */

/* Manufacture Data */
#define MANU_AD_TYPE                0xFF
#define MANU_COMPANY_ID             0x027D

#define POS_MANU_DATA_LEN           0
#define POS_MANU_AD_TYPE            (POS_MANU_DATA_LEN + LENGTH_LEN) /* 1 */
#define POS_MANU_COMPANY_ID         (POS_MANU_AD_TYPE + AD_TYPE_LEN) /* 2 */

/* Adv head */
#define HEAD_LEN                    (LENGTH_LEN + AD_TYPE_LEN + AD_ID_LEN) /* 4 */
#define ADV_HEAD_LEN                (FLAG_ADV_LEN + HEAD_LEN) /* 7 */

/* Payload */
#define MAX_ADV_PAYLOAD_LEN         ((MAX_ADV_DATA_LEN) - (ADV_HEAD_LEN)) /* 24 */
#define MAX_RSP_PAYLOAD_LEN         ((MAX_ADV_DATA_LEN) - HEAD_LEN) /* 27 */
#define MAX_SUM_PAYLOAD_LEN         ((MAX_ADV_PAYLOAD_LEN) + MAX_RSP_PAYLOAD_LEN) /* 51 */

/* TLV */
#define TL_LEN                      1

/* Mask */
#define BYTE_MASK                   0xFF
#define MOST_SIGNIFICANT_4BIT_MASK  0xF0
#define LEAST_SIGNIFICANT_4BIT_MASK 0x0F

/* Byte Shift */
#define BYTE_SHIFT_BIT              1
#define BYTE_SHIFT_2BIT             2
#define BYTE_SHIFT_4BIT             4
#define BYTE_SHIFT_7BIT             7
#define BYTE_SHIFT_8BIT             8
#define BYTE_SHIFT_13BIT            13

#define DISC_MAX_NICKNAME_LEN 21

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* BROADCAST_PROTOCOL_CONSTANT_H */