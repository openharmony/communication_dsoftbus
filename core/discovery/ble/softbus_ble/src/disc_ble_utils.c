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
#include "disc_ble_utils.h"

#include <stdbool.h>
#include <stdint.h>

#include "bus_center_manager.h"
#include "cJSON.h"
#include "disc_ble_constant.h"
#include "discovery_service.h"
#include "lnn_device_info.h"
#include "securec.h"
#include "softbus_adapter_crypto.h"
#include "softbus_common.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"
#include "softbus_adapter_mem.h"

#define DATA_TYPE_MASK 0xF0
#define DATA_LENGTH_MASK 0x0F
#define BYTE_SHIFT 4

#define MAC_BIT_ZERO 0
#define MAC_BIT_ONE 1
#define MAC_BIT_TWO 2
#define MAC_BIT_THREE 3
#define MAC_BIT_FOUR 4
#define MAC_BIT_FIVE 5

#ifndef PACKET_CHECK_LENGTH
#define PACKET_CHECK_LENGTH(len) \
    if (len >= 0) { \
        curLen += len; \
    } else { \
        return len; \
    }
#endif

bool CheckBitMapEmpty(uint32_t capBitMapNum, const uint32_t *capBitMap)
{
    if (capBitMap == NULL) {
        return false;
    }
    for (uint32_t i = 0; i < capBitMapNum; i++) {
        if (capBitMap[i] != 0x0) {
            return false;
        }
    }
    return true;
}

bool CheckCapBitMapExist(uint32_t capBitMapNum, const uint32_t *capBitMap, uint32_t pos)
{
    if (capBitMap == NULL) {
        return false;
    }
    uint32_t index = pos / INT32_MAX_BIT_NUM;
    if (index >= capBitMapNum) {
        return false;
    }
    return (capBitMap[index] >> (pos % INT32_MAX_BIT_NUM)) & 0x1 ? true : false;
}

void SetCapBitMapPos(uint32_t capBitMapNum, uint32_t *capBitMap, uint32_t pos)
{
    if (capBitMap == NULL) {
        return;
    }
    uint32_t index = pos / INT32_MAX_BIT_NUM;
    if (index >= capBitMapNum) {
        return;
    }
    capBitMap[index] = capBitMap[index] | (0x1 << (pos % INT32_MAX_BIT_NUM));
}

void UnsetCapBitMapPos(uint32_t capBitMapNum, uint32_t *capBitMap, uint32_t pos)
{
    if (capBitMap == NULL) {
        return;
    }
    uint32_t index = pos / INT32_MAX_BIT_NUM;
    if (index >= capBitMapNum) {
        return;
    }
    uint32_t mask = 0xffffffff ^ (0x1 << (pos % INT32_MAX_BIT_NUM));
    capBitMap[index] = capBitMap[index] & mask;
}

int32_t DiscBleGetDeviceUdid(char *udid, uint32_t len)
{
    if (udid == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, len) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Get local dev Id failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t DiscBleGetDeviceName(char *deviceName)
{
    if (deviceName == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, deviceName, DEVICE_NAME_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Get local device name failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

uint16_t DiscBleGetDeviceType(void)
{
    char type[DEVICE_TYPE_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_TYPE, type, DEVICE_TYPE_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Get local device type failed.");
        return TYPE_UNKNOW_ID;
    }
    uint16_t typeId = 0;
    if (LnnConvertDeviceTypeToId(type, &typeId) != SOFTBUS_OK) {
        return TYPE_UNKNOW_ID;
    }
    return typeId;
}

int32_t DiscBleGetDeviceIdHash(unsigned char *hashStr)
{
    if (hashStr == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "hashstr is null");
        return SOFTBUS_INVALID_PARAM;
    }
    char udid[DISC_MAX_DEVICE_ID_LEN] = {0};
    char hashResult[SHA_HASH_LEN] = {0};
    int32_t ret = DiscBleGetDeviceUdid(udid, sizeof(udid));
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "GetDeviceId failed");
        return ret;
    }
    ret = SoftBusGenerateStrHash((const unsigned char *)udid, strlen(udid) + 1, (unsigned char *)hashResult);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "GenerateStrHash failed");
        return ret;
    }
    ret = ConvertBytesToHexString((char *)hashStr, SHORT_DEVICE_ID_HASH_LENGTH + 1, (const unsigned char *)hashResult,
        SHORT_DEVICE_ID_HASH_LENGTH / HEXIFY_UNIT_LEN);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "ConvertBytesToHexString failed");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t DiscBleGetShortUserIdHash(unsigned char *hashStr, uint32_t len)
{
    if (hashStr == NULL || len == 0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "hashstr is null");
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t account[SHA_256_HASH_LEN] = {0};
    if (LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, account, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "DiscBleGetShortUserIdHash get local user id failed");
        return SOFTBUS_ERR;
    }
    if (len > SHORT_USER_ID_HASH_LEN || memcpy_s(hashStr, len, account, len) != EOK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "DiscBleGetShortUserIdHash memcpy_s failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t AssembleTLV(BoardcastData *boardcastData, unsigned char dataType, const void *value, uint32_t dataLen)
{
    if (boardcastData == NULL || value == NULL || dataLen == 0 || boardcastData->dataLen >= BOARDCAST_MAX_LEN) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "AssembleTLV invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t len = dataLen & DATA_LENGTH_MASK;
    boardcastData->data.data[boardcastData->dataLen] = (dataType << BYTE_SHIFT) & DATA_TYPE_MASK;
    boardcastData->data.data[boardcastData->dataLen] |= dataLen & DATA_LENGTH_MASK;
    boardcastData->dataLen += 1;
    uint32_t remainLen = BOARDCAST_MAX_LEN - boardcastData->dataLen;
    if (remainLen == 0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "tlv remainLen is 0.");
        return SOFTBUS_ERR;
    }
    uint32_t validLen = (len > remainLen) ? remainLen : len;
    if (memcpy_s(&(boardcastData->data.data[boardcastData->dataLen]), validLen, value, validLen) != EOK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "assemble tlv memcpy failed");
        return SOFTBUS_MEM_ERR;
    }
    boardcastData->dataLen += validLen;
    return SOFTBUS_OK;
}

/* A helper function for copying TLV value to destination */
static int32_t CopyValue(void *dst, uint32_t dstLen, void *src, uint32_t srcLen, const char *hint)
{
    if (memcpy_s(dst, dstLen, src, srcLen) != EOK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "parse tlv memcpy failed, "
            "tlvType: %s, tlvLen: %u, dstLen: %u", hint, srcLen, dstLen);
            return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

/* A helper function for convert br mac bin address to string address */
static int32_t CopyBrAddrValue(DeviceWrapper *device, const unsigned char *src, uint32_t srcLen)
{
    uint32_t i = device->info->addrNum;
    int32_t ret = ConvertBtMacToStr(device->info->addr[i].info.br.brMac, BT_MAC_LEN,
        (uint8_t *)src, srcLen);
    if (ret == SOFTBUS_OK) {
        device->info->addr[i].type = CONNECTION_ADDR_BR;
        device->info->addrNum += 1;
        return SOFTBUS_OK;
    }
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "parse tlv convert br failed, "
        "tlvType: TLV_TYPE_BR_MAC, tlvLen: %u, dstLen: %d", srcLen, BT_MAC_LEN);
    return ret;
}

static int32_t ParseDeviceType(DeviceWrapper *device, const unsigned char* data, const uint32_t len)
{
    uint8_t recvDevType[DEVICE_TYPE_LEN] = {0};
    if (CopyValue(recvDevType, DEVICE_TYPE_LEN, data, len, "TLV_TYPE_DEVICE_TYPE") != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    device->info->devType = recvDevType[0];
    if (len == DEVICE_TYPE_LEN) {
        device->info->devType = (recvDevType[1] << ONE_BYTE_LENGTH) | recvDevType[0];
    }
    return SOFTBUS_OK;
}

static int32_t ParseRecvTlvs(DeviceWrapper *device, const unsigned char *data, uint32_t dataLen)
{
    uint32_t curLen = POS_TLV + ADV_HEAD_LEN;
    int32_t ret = SOFTBUS_OK;
    while (curLen < dataLen) {
        unsigned char type = (data[curLen] & DATA_TYPE_MASK) >> BYTE_SHIFT;
        uint32_t len = (uint32_t)(data[curLen] & DATA_LENGTH_MASK);
        if (curLen + TL_LEN + len > dataLen) {
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "unexperted advData: out of range, "
                "tlvType: %d, tlvLen: %u, current pos: %u, total pos: %u", type, len, curLen, dataLen);
            return SOFTBUS_ERR;
        }
        switch (type) {
            case TLV_TYPE_DEVICE_ID_HASH:
                ret = CopyValue(device->info->devId, DISC_MAX_DEVICE_ID_LEN,
                    &data[curLen + 1], len, "TLV_TYPE_DEVICE_ID_HASH");
                break;
            case TLV_TYPE_DEVICE_TYPE:
                ret = ParseDeviceType(device, &data[curLen + 1], len);
                break;
            case TLV_TYPE_DEVICE_NAME:
                ret = CopyValue(device->info->devName, DISC_MAX_DEVICE_NAME_LEN,
                    &data[curLen + 1], len, "TLV_TYPE_DEVICE_NAME");
                break;
            case TLV_TYPE_CUST:
                ret = CopyValue(device->info->custData, DISC_MAX_CUST_DATA_LEN,
                    &data[curLen + 1], len, "TLV_TYPE_CUST");
                break;
            case TLV_TYPE_BR_MAC:
                ret = CopyBrAddrValue(device, &data[curLen + 1], len);
                break;
            case TLV_TYPE_RANGE_POWER:
                ret = CopyValue(&device->power, RANGE_POWER_TYPE_LEN, &data[curLen + 1], len, "TLV_TYPE_RANGE_POWER");
                break;
            default:
                SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_WARN, "Unknown TLV, tlvType: %d, tlvLen: %u, just skip",
                    type, len);
                break;
        }
        if (ret != SOFTBUS_OK) {
            break;
        }
        // move cursor to next TLV
        curLen += len + 1;
    }
    return ret;
}

int32_t GetDeviceInfoFromDisAdvData(DeviceWrapper *device, const unsigned char *data, uint32_t dataLen)
{
    if (device == NULL || device->info == NULL || data == NULL || dataLen == 0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "GetDeviceInfoFromAdvData input param is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(device->info->accountHash, SHORT_USER_ID_HASH_LEN,
        &data[POS_USER_ID_HASH + ADV_HEAD_LEN], SHORT_USER_ID_HASH_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "copy accountHash failed");
        return SOFTBUS_MEM_ERR;
    }
    device->info->capabilityBitmap[0] = data[POS_CAPABLITY + ADV_HEAD_LEN];

    // ble scan data consists of multiple ADStructures
    // ADStructure format: <length (1 octet)> <type (1 octet)> <data(length octect - 1)>
    // More info about ADStructure, please ref Generic Access Profile Specification
    // We only use Flag(0x01) + ServiceData(0x16) + Manufacture(0xff) in order, so we should join them together
    // before parse
    uint32_t scanRspPtr = 0;
    uint32_t scanRspTlvLen = 0;
    uint32_t nextAdsPtr = FLAG_BYTE_LEN + 1 + data[POS_PACKET_LENGTH] + 1;
    while (nextAdsPtr + 1 < dataLen) {
        if (data[nextAdsPtr + 1] == RSP_TYPE) {
            scanRspPtr = nextAdsPtr;
            scanRspTlvLen = data[scanRspPtr] - RSP_HEAD_LEN + 1;
            break;
        }
        nextAdsPtr += data[nextAdsPtr] + 1;
    }

    uint32_t advLen = FLAG_BYTE_LEN + 1 + data[POS_PACKET_LENGTH] + 1;
    unsigned char *copyData = SoftBusCalloc(advLen + scanRspTlvLen);
    if (copyData == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "malloc failed.");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(copyData, advLen, data, advLen) != EOK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "memcpy_s adv failed, advLen: %u", advLen);
        SoftBusFree(copyData);
        return SOFTBUS_MEM_ERR;
    }
    if (scanRspTlvLen != 0) {
        if (memcpy_s(copyData + advLen, scanRspTlvLen, data + scanRspPtr + RSP_HEAD_LEN, scanRspTlvLen) != EOK) {
            SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "memcpy_s scan resp failed, advLen: %u, "
                "scanRspTlvLen: %u.", advLen, scanRspTlvLen);
            SoftBusFree(copyData);
            return SOFTBUS_MEM_ERR;
        }
    }
    int32_t ret = ParseRecvTlvs(device, copyData, advLen + scanRspTlvLen);
    SoftBusFree(copyData);
    return ret;
}
