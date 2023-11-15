/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "disc_log.h"
#include "lnn_device_info.h"
#include "securec.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"

#define DATA_TYPE_MASK 0xF0
#define DATA_LENGTH_MASK 0x0F
#define BYTE_SHIFT 4

#define MAC_BIT_ZERO 0
#define MAC_BIT_ONE 1
#define MAC_BIT_TWO 2
#define MAC_BIT_THREE 3
#define MAC_BIT_FOUR 4
#define MAC_BIT_FIVE 5
#define TLV_MAX_DATA_LEN 15
#define TLV_VARIABLE_DATA_LEN 0

bool CheckBitMapEmpty(uint32_t capBitMapNum, const uint32_t *capBitMap)
{
    for (uint32_t i = 0; i < capBitMapNum; i++) {
        if (capBitMap[i] != 0x0) {
            return false;
        }
    }
    return true;
}

bool CheckCapBitMapExist(uint32_t capBitMapNum, const uint32_t *capBitMap, uint32_t pos)
{
    uint32_t index = pos / INT32_MAX_BIT_NUM;
    if (index >= capBitMapNum) {
        return false;
    }
    return (capBitMap[index] >> (pos % INT32_MAX_BIT_NUM)) & 0x1 ? true : false;
}

void SetCapBitMapPos(uint32_t capBitMapNum, uint32_t *capBitMap, uint32_t pos)
{
    uint32_t index = pos / INT32_MAX_BIT_NUM;
    if (index >= capBitMapNum) {
        return;
    }
    capBitMap[index] = capBitMap[index] | (0x1 << (pos % INT32_MAX_BIT_NUM));
}

void UnsetCapBitMapPos(uint32_t capBitMapNum, uint32_t *capBitMap, uint32_t pos)
{
    uint32_t index = pos / INT32_MAX_BIT_NUM;
    if (index >= capBitMapNum) {
        return;
    }
    uint32_t mask = 0xffffffff ^ (0x1 << (pos % INT32_MAX_BIT_NUM));
    capBitMap[index] = capBitMap[index] & mask;
}

static int32_t DiscBleGetDeviceUdid(char *udid, uint32_t len)
{
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, len) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "Get local dev Id failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t DiscBleGetDeviceName(char *deviceName)
{
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, deviceName, DEVICE_NAME_BUF_LEN) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "Get local device name failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

uint16_t DiscBleGetDeviceType(void)
{
    char type[DEVICE_TYPE_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_TYPE, type, DEVICE_TYPE_BUF_LEN) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "Get local device type failed.");
        return TYPE_UNKNOW_ID;
    }
    uint16_t typeId = 0;
    if (LnnConvertDeviceTypeToId(type, &typeId) != SOFTBUS_OK) {
        return TYPE_UNKNOW_ID;
    }
    return typeId;
}

int32_t DiscBleGetDeviceIdHash(uint8_t *devIdHash)
{
    char udid[DISC_MAX_DEVICE_ID_LEN] = {0};
    char hashResult[SHA_HASH_LEN] = {0};
    int32_t ret = DiscBleGetDeviceUdid(udid, sizeof(udid));
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "GetDeviceId failed");
        return ret;
    }
    ret = SoftBusGenerateStrHash((const uint8_t *)udid, strlen(udid), (uint8_t *)hashResult);
    if (ret != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "GenerateStrHash failed");
        return ret;
    }

    if (memcpy_s(devIdHash, DISC_MAX_DEVICE_ID_LEN, hashResult, SHORT_DEVICE_ID_HASH_LENGTH) != EOK) {
        DISC_LOGE(DISC_BLE, "copy device id hash failed");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t DiscBleGetShortUserIdHash(uint8_t *hashStr, uint32_t len)
{
    uint8_t account[SHA_256_HASH_LEN] = {0};
    if (LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, account, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "DiscBleGetShortUserIdHash get local user id failed");
        return SOFTBUS_ERR;
    }
    if (len > SHORT_USER_ID_HASH_LEN || memcpy_s(hashStr, len, account, len) != EOK) {
        DISC_LOGE(DISC_BLE, "DiscBleGetShortUserIdHash memcpy_s failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t AssembleTLV(BroadcastData *broadcastData, uint8_t dataType, const void *value,
    uint32_t dataLen)
{
    broadcastData->data.data[broadcastData->dataLen] = (dataType << BYTE_SHIFT) & DATA_TYPE_MASK;
    if (dataLen <= TLV_MAX_DATA_LEN) {
        broadcastData->data.data[broadcastData->dataLen] |= dataLen & DATA_LENGTH_MASK;
    }
    broadcastData->dataLen += 1;
    uint32_t remainLen = BROADCAST_MAX_LEN - broadcastData->dataLen;
    if (remainLen == 0) {
        DISC_LOGE(DISC_BLE, "tlv remainLen is 0.");
        return SOFTBUS_ERR;
    }
    uint32_t validLen = (dataLen > remainLen) ? remainLen : dataLen;
    if (memcpy_s(&(broadcastData->data.data[broadcastData->dataLen]), validLen, value, validLen) != EOK) {
        DISC_LOGE(DISC_BLE, "assemble tlv memcpy failed");
        return SOFTBUS_MEM_ERR;
    }
    broadcastData->dataLen += validLen;
    return SOFTBUS_OK;
}

/* A helper function for copying TLV value to destination */
static int32_t CopyValue(void *dst, uint32_t dstLen, const void *src, uint32_t srcLen, const char *hint)
{
    if (memcpy_s(dst, dstLen, src, srcLen) != EOK) {
        DISC_LOGE(DISC_BLE, "parse tlv memcpy failed, tlvType: %s, tlvLen: %u, dstLen: %u", hint, srcLen, dstLen);
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

/* A helper function for convert br mac bin address to string address */
static int32_t CopyBrAddrValue(DeviceWrapper *device, const uint8_t *src, uint32_t srcLen)
{
    uint32_t i = device->info->addrNum;
    int32_t ret = ConvertBtMacToStr(device->info->addr[i].info.br.brMac, BT_MAC_LEN, (uint8_t *)src, srcLen);
    if (ret == SOFTBUS_OK) {
        device->info->addr[i].type = CONNECTION_ADDR_BR;
        device->info->addrNum += 1;
        return SOFTBUS_OK;
    }
    DISC_LOGE(DISC_BLE, "parse tlv convert br failed, tlvType: TLV_TYPE_BR_MAC, tlvLen: %u, dstLen: %d",
        srcLen, BT_MAC_LEN);
    return ret;
}

static int32_t ParseDeviceType(DeviceWrapper *device, const uint8_t* data, const uint32_t len)
{
    uint8_t recvDevType[DEVICE_TYPE_LEN] = {0};
    if (CopyValue(recvDevType, DEVICE_TYPE_LEN, (void *)data, len, "TLV_TYPE_DEVICE_TYPE") != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    device->info->devType = recvDevType[0];
    if (len == DEVICE_TYPE_LEN) {
        device->info->devType = (recvDevType[1] << ONE_BYTE_LENGTH) | recvDevType[0];
    }
    return SOFTBUS_OK;
}

static int32_t ParseRecvTlvs(DeviceWrapper *device, const uint8_t *data, uint32_t dataLen)
{
    uint32_t curLen = POS_TLV + ADV_HEAD_LEN;
    int32_t ret = SOFTBUS_OK;
    while (curLen < dataLen) {
        uint8_t type = (data[curLen] & DATA_TYPE_MASK) >> BYTE_SHIFT;
        uint32_t len = (uint32_t)(data[curLen] & DATA_LENGTH_MASK);
        DISC_CHECK_AND_RETURN_RET_LOGE(curLen + TL_LEN + len <= dataLen, SOFTBUS_ERR, DISC_BLE,
            "advData out of range, type:%d, len:%u, curLen:%u, dataLen:%u", type, len, curLen, dataLen);
        switch (type) {
            case TLV_TYPE_DEVICE_ID_HASH:
                ret = CopyValue(device->info->addr[0].info.ble.udidHash, DISC_MAX_DEVICE_ID_LEN,
                                (void *)&data[curLen + 1], len, "TLV_TYPE_DEVICE_ID_HASH");
                if (ConvertBytesToHexString((char *)device->info->devId, DISC_MAX_DEVICE_ID_LEN,
                    (const uint8_t *)device->info->addr[0].info.ble.udidHash, len) != SOFTBUS_OK) {
                    DISC_LOGE(DISC_BLE, "ConvertBytesToHexString failed");
                    return SOFTBUS_ERR;
                }
                break;
            case TLV_TYPE_DEVICE_TYPE:
                ret = ParseDeviceType(device, &data[curLen + 1], len);
                break;
            case TLV_TYPE_DEVICE_NAME:
                if (len == TLV_VARIABLE_DATA_LEN) {
                    len = strlen((char *)&data[curLen + 1]);
                }
                ret = CopyValue(device->info->devName, DISC_MAX_DEVICE_NAME_LEN,
                                (void *)&data[curLen + 1], len, "TLV_TYPE_DEVICE_NAME");
                break;
            case TLV_TYPE_CUST:
                ret = CopyValue(device->info->custData, DISC_MAX_CUST_DATA_LEN,
                                (void *)&data[curLen + 1], len, "TLV_TYPE_CUST");
                break;
            case TLV_TYPE_BR_MAC:
                ret = CopyBrAddrValue(device, &data[curLen + 1], len);
                break;
            case TLV_TYPE_RANGE_POWER:
                ret = CopyValue(&device->power, RANGE_POWER_TYPE_LEN, (void *)&data[curLen + 1], len,
                                "TLV_TYPE_RANGE_POWER");
                break;
            default:
                DISC_LOGW(DISC_BLE, "Unknown TLV, tlvType: %d, tlvLen: %u, just skip", type, len);
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

int32_t GetDeviceInfoFromDisAdvData(DeviceWrapper *device, const uint8_t *data, uint32_t dataLen)
{
    DISC_CHECK_AND_RETURN_RET_LOGW(device != NULL && device->info != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE,
        "device is invalid");
    DISC_CHECK_AND_RETURN_RET_LOGW(data != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "data=NULL is invalid");
    DISC_CHECK_AND_RETURN_RET_LOGW(dataLen != 0, SOFTBUS_INVALID_PARAM, DISC_BLE, "dataLen=0 is invalid");
    if (memcpy_s(device->info->accountHash, SHORT_USER_ID_HASH_LEN,
        &data[POS_USER_ID_HASH + ADV_HEAD_LEN], SHORT_USER_ID_HASH_LEN) != EOK) {
        DISC_LOGE(DISC_BLE, "copy accountHash failed");
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
            DISC_CHECK_AND_RETURN_RET_LOGE(data[scanRspPtr] >= (RSP_HEAD_LEN - 1), SOFTBUS_ERR, DISC_BLE,
                "rspLen[%hhu] is less than rsp head length", data[scanRspPtr]);
            scanRspTlvLen = data[scanRspPtr] - (RSP_HEAD_LEN - 1);
            DISC_CHECK_AND_RETURN_RET_LOGE(scanRspPtr + data[scanRspPtr] + 1 <= dataLen, SOFTBUS_ERR, DISC_BLE,
                "curScanLen(%u) > dataLen(%u)", scanRspPtr + data[scanRspPtr] + 1, dataLen);
            break;
        }
        nextAdsPtr += data[nextAdsPtr] + 1;
    }
    uint32_t advLen = FLAG_BYTE_LEN + 1 + data[POS_PACKET_LENGTH] + 1;
    uint8_t *copyData = SoftBusCalloc(advLen + scanRspTlvLen);
    DISC_CHECK_AND_RETURN_RET_LOGE(copyData != NULL, SOFTBUS_MEM_ERR, DISC_BLE, "malloc failed.");
    if (memcpy_s(copyData, advLen, data, advLen) != EOK) {
        DISC_LOGE(DISC_BLE, "memcpy_s adv failed, advLen: %u", advLen);
        SoftBusFree(copyData);
        return SOFTBUS_MEM_ERR;
    }
    if (scanRspTlvLen != 0) {
        if (memcpy_s(copyData + advLen, scanRspTlvLen, data + scanRspPtr + RSP_HEAD_LEN, scanRspTlvLen) != EOK) {
            DISC_LOGE(DISC_BLE, "memcpy_s scan resp failed, advLen: %u, scanRspTlvLen: %u.", advLen, scanRspTlvLen);
            SoftBusFree(copyData);
            return SOFTBUS_MEM_ERR;
        }
    }
    int32_t ret = ParseRecvTlvs(device, copyData, advLen + scanRspTlvLen);
    SoftBusFree(copyData);
    return ret;
}

