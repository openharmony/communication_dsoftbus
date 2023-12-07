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
#define BC_NUM_MAX             9
#define SCAN_NUM_MAX           9

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

/**
 * @brief Defines the format of broadcast TLV data
 *
 * DATA_FORMAT_TL_1BYTE indicates BcTlvDataFormatThe TLV format is 4 bits for T and 4 bits for L
 * DATA_FORMAT_TL_2BYTE indicates BcTlvDataFormatThe TLV format is 1 byte for T and 1 byte for L
 *
 * @since 4.1
 * @version 1.0
 */
enum BcTlvDataFormat {
    DATA_FORMAT_TL_1BYTE,
    DATA_FORMAT_TL_2BYTE,
};

/**
 * @brief Defines the broadcast TLV data
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    uint8_t type;
    uint8_t len;
    uint8_t *value;
} BcTlv;

/**
 * @brief Get the advertising service data object.
 *
 * @param uuid Indicates the uuid of the service data.
 * @param advPosPtr Indicates the position of the broadcast service data pointer in the scanned raw data.
 * @param advLen Indicates the length of the broadcast service data.
 * @param rawData Indicates the scanned raw data by reporter.
 * @param dataLen Indicates the length of the scanned raw data.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service gets service data successful.
 * returns any other value if the service fails to get service data.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t GetServiceAdvData(uint16_t uuid, uint8_t **advPosPtr, uint32_t *advLen,
    const uint8_t *rawData, uint32_t dataLen);

/**
 * @brief Get the respond service data object.
 *
 * @param uuid Indicates the uuid of the respond service data.
 * @param advPosPtr Indicates the position of the respond service data pointer in the scanned raw data.
 * @param advLen Indicates the length of the respond service data.
 * @param rawData Indicates the scanned raw data by reporter.
 * @param dataLen Indicates the length of the scanned raw data.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service gets respond service data successful.
 * returns any other value if the service fails to get respond service data.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t GetServiceRspData(uint16_t uuid, uint8_t **rspPosPtr, uint32_t *rspLen,
    const uint8_t *rawData, uint32_t dataLen);

/**
 * @brief Get the advertising manufacturer data object.
 *
 * @param companyId Indicates the companyId of the manufacturer data.
 * @param advPosPtr Indicates the position of the broadcast manufacturer data pointer in the scanned raw data.
 * @param advLen Indicates the length of the broadcast manufacturer data.
 * @param rawData Indicates the scanned raw data by reporter.
 * @param dataLen Indicates the length of the scanned raw data.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service gets manufacturer data successful.
 * returns any other value if the service fails to get manufacturer data.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t GetManufacturerAdvData(uint16_t companyId, uint8_t **advPosPtr, uint32_t *advLen, const uint8_t *rawData,
    uint32_t dataLen);

/**
 * @brief Get the respond manufacturer data object.
 *
 * @param companyId Indicates the companyId of the respond manufacturer data.
 * @param advPosPtr Indicates the position of the respond manufacturer data pointer in the scanned raw data.
 * @param advLen Indicates the length of the respond manufacturer data.
 * @param rawData Indicates the scanned raw data by reporter.
 * @param dataLen Indicates the length of the scanned raw data.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service gets respond manufacturer data successful.
 * returns any other value if the service fails to get respond manufacturer data.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t GetManufacturerRspData(uint16_t companyId, uint8_t **rspPosPtr, uint32_t *rspLen, const uint8_t *rawData,
    uint32_t dataLen);

/**
 * @brief Get the local name data object by the scanned raw data.
 *
 * @param localName Indicates shortened local name or complete local name.
 * @param len Indicates the length of local name.
 * @param rawData Indicates the scanned raw data by reporter.
 * @param dataLen Indicates the length of the scanned raw data.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service gets local name successful.
 * returns any other value if the service fails to get local name.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t GetLocalNameData(uint8_t *localName, uint32_t *len, const uint8_t *rawData, uint32_t dataLen);

/**
 * @brief Get the broadcast flag object
 *
 * @param flag Indicates the flag value of the advertising data.
 * @param rawData Indicates the scanned raw data by reporter.
 * @param dataLen Indicates the length of the scanned raw data.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service gets flag successful.
 * returns any other value if the service fails to get flag.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t GetBcFlag(uint8_t *flag, const uint8_t *rawData, uint32_t dataLen);

/**
 * @brief Get the service Uuid object
 *
 * @param uuid Indicates the uuid of the advertising service data.
 * @param rawData Indicates the scanned raw data by reporter.
 * @param dataLen Indicates the length of the scanned raw data.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service gets uuid successful.
 * returns any other value if the service fails to get uuid.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t GetServiceUuid(uint16_t *uuid, const uint8_t *rawData, uint32_t dataLen);

/**
 * @brief Get the manufacturer companyId object
 *
 * @param companyId Indicates the companyId of the advertising manufacturer data.
 * @param rawData Indicates the scanned raw data by reporter.
 * @param dataLen Indicates the length of the scanned raw data.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service gets companyId successful.
 * returns any other value if the service fails to get companyId.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t GetManufacturerId(uint16_t *companyId, const uint8_t *rawData, uint32_t dataLen);

/**
 * @brief Check whether it is service data.
 *
 * @param rawData Indicates the scanned raw data by reporter.
 * @param dataLen Indicates the length of the scanned raw data.
 *
 * @return true
 * @return false
 *
 * @since 4.1
 * @version 1.0
 */
bool IsServiceData(const uint8_t *rawData, uint32_t dataLen);

/**
 * @brief Assemble TLV packet.
 *
 * @param bcData Indicates the pointers to the destination data to be assembled.
 * @param dataLen Indicates the length of the destination data.
 * @param tlv Indicates Assemble TLV data.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the TLV packet assemble successful.
 * returns any other value if the TLV packet fails to assemble.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t AssembleTlvPkg(enum BcTlvDataFormat, uint8_t *bcData, uint32_t dataLen, const BcTlv *tlv);

/**
 * @brief Parse TLV packet by the source data.
 *
 * @param bcData Indicates the source data of the scanned raw data.
 * @param dataLen Indicates the length of the source data
 * @param tlv Indicates parsed TLV data.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the TLV packet parse successful.
 * returns any other value if the TLV packet fails to parse.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t ParseTlvPkg(enum BcTlvDataFormat, const uint8_t *bcData, uint32_t dataLen, BcTlv *tlv);

#ifdef __cplusplus
}
#endif

#endif /* SOFTBUS_BROADCAST_UTILS_H */
