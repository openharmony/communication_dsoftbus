/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include <locale.h>
#include <stdbool.h>
#include <stdint.h>
#include <wchar.h>

#include "bus_center_manager.h"
#include "cJSON.h"
#include "disc_ble_constant.h"
#include "softbus_broadcast_type.h"
#include "disc_log.h"
#include "lnn_device_info.h"
#include "securec.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_utils.h"

#define DATA_TYPE_MASK 0xF0
#define DATA_LENGTH_MASK 0x0F
#define BYTE_SHIFT 4
#define CUST_CAPABILITY_LEN 2
#define WIDE_CHAR_MAX_LEN 8
#define WIDE_STR_MAX_LEN 128

#define MAC_BIT_ZERO 0
#define MAC_BIT_ONE 1
#define MAC_BIT_TWO 2
#define MAC_BIT_THREE 3
#define MAC_BIT_FOUR 4
#define MAC_BIT_FIVE 5
#define TLV_MAX_DATA_LEN 15
#define TLV_VARIABLE_DATA_LEN 0

static int32_t CalculateMbsTruncateSize(const char *multiByteStr, uint32_t capacity, uint32_t *truncatedSize);

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

int32_t DiscBleGetDeviceName(char *deviceName, uint32_t size)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(deviceName != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "device name is null");
    DISC_CHECK_AND_RETURN_RET_LOGE(size != 0, SOFTBUS_INVALID_PARAM, DISC_BLE, "device name size is 0");

    char localDevName[DEVICE_NAME_BUF_LEN] = {0};
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, localDevName, sizeof(localDevName));
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_ERR, DISC_BLE, "get local device name failed");

    uint32_t truncateLen = 0;
    if (CalculateMbsTruncateSize((const char *)localDevName, size - 1, &truncateLen) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "truncate device name failed");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(deviceName, size, localDevName, truncateLen) != EOK) {
        DISC_LOGE(DISC_BLE, "copy local device name failed");
        return SOFTBUS_MEM_ERR;
    }
    deviceName[truncateLen] = '\0';
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

int32_t DiscBleGetDeviceIdHash(uint8_t *devIdHash, uint32_t len)
{
    if (devIdHash == NULL || len > DISC_MAX_DEVICE_ID_LEN) {
        DISC_LOGE(DISC_BLE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
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
    if (memset_s(devIdHash, len, 0, len) != EOK) {
        DISC_LOGE(DISC_BLE, "memset devIdHash failed");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(devIdHash, len, hashResult, SHORT_DEVICE_ID_HASH_LENGTH) != EOK) {
        DISC_LOGE(DISC_BLE, "copy device id hash failed");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t DiscBleGetShortUserIdHash(uint8_t *hashStr, uint32_t len)
{
    if (hashStr == NULL || len > SHORT_USER_ID_HASH_LEN) {
        DISC_LOGE(DISC_BLE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t account[SHA_256_HASH_LEN] = {0};
    if (LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, account, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "DiscBleGetShortUserIdHash get local user id failed");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(hashStr, len, account, len) != EOK) {
        DISC_LOGE(DISC_BLE, "DiscBleGetShortUserIdHash memcpy_s failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SetLocale(char **localeBefore)
{
    *localeBefore = setlocale(LC_CTYPE, NULL);
    if (*localeBefore == NULL) {
        DISC_LOGW(DISC_BLE, "get locale failed");
    }

    char *localeAfter = setlocale(LC_CTYPE, "C.UTF-8");
    return (localeAfter != NULL) ? SOFTBUS_OK : SOFTBUS_ERR;
}

static void RestoreLocale(const char *localeBefore)
{
    if (setlocale(LC_CTYPE, localeBefore) == NULL) {
        DISC_LOGW(DISC_BLE, "restore locale failed");
    }
}

// Calculate the truncated length in wide characters, ensuring that the truncation is performed in wide character
static int32_t CalculateMbsTruncateSize(const char *multiByteStr, uint32_t capacity, uint32_t *truncatedSize)
{
    size_t multiByteStrLen = strlen(multiByteStr);
    if (multiByteStrLen == 0) {
        *truncatedSize = 0;
        return SOFTBUS_OK;
    }
    DISC_CHECK_AND_RETURN_RET_LOGE(multiByteStrLen <= WIDE_STR_MAX_LEN, SOFTBUS_INVALID_PARAM, DISC_BLE,
        "multi byte str too long: %zu", multiByteStrLen);

    char *localeBefore = NULL;
    int32_t ret = SetLocale(&localeBefore);
    DISC_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_ERR, DISC_BLE, "set locale failed");

    // convert multi byte str to wide str
    wchar_t wideStr[WIDE_STR_MAX_LEN] = {0};
    size_t numConverted = mbstowcs(wideStr, multiByteStr, multiByteStrLen);
    if (numConverted <= 0) {
        DISC_LOGE(DISC_BLE, "mbstowcs failed");
        RestoreLocale(localeBefore);
        return SOFTBUS_ERR;
    }

    // truncate wide str until <= capacity
    uint32_t truncateTotal = 0;
    int32_t truncateIndex = numConverted - 1;
    char multiByteChar[WIDE_CHAR_MAX_LEN] = {0};
    while (capacity < multiByteStrLen - truncateTotal && truncateIndex >= 0) {
        int32_t truncateCharLen = wctomb(multiByteChar, wideStr[truncateIndex]);
        if (truncateCharLen <= 0) {
            DISC_LOGE(DISC_BLE, "wctomb failed on w_char. truncateIndex=%{public}d", truncateIndex);
            RestoreLocale(localeBefore);
            return SOFTBUS_ERR;
        }
        truncateTotal += (uint32_t)truncateCharLen;
        truncateIndex--;
    }

    *truncatedSize = (multiByteStrLen >= truncateTotal) ? (multiByteStrLen - truncateTotal) : 0;
    RestoreLocale(localeBefore);
    return SOFTBUS_OK;
}

int32_t AssembleTLV(BroadcastData *broadcastData, uint8_t dataType, const void *value,
    uint32_t dataLen)
{
    uint32_t remainLen = BROADCAST_MAX_LEN - broadcastData->dataLen;
    if (remainLen == 0) {
        DISC_LOGE(DISC_BLE, "tlv remainLen is 0.");
        return SOFTBUS_ERR;
    }
    broadcastData->data.data[broadcastData->dataLen] = (dataType << BYTE_SHIFT) & DATA_TYPE_MASK;
    if (dataLen <= TLV_MAX_DATA_LEN) {
        broadcastData->data.data[broadcastData->dataLen] |= dataLen & DATA_LENGTH_MASK;
    }
    broadcastData->dataLen += 1;
    remainLen -= 1;

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
        DISC_LOGE(DISC_BLE, "parse tlv memcpy failed, tlvType=%{public}s, tlvLen=%{public}u, dstLen=%{public}u",
            hint, srcLen, dstLen);
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
    DISC_LOGE(DISC_BLE, "parse tlv convert br failed, tlvType=TLV_TYPE_BR_MAC, tlvLen=%{public}u, dstLen=%{public}d",
        srcLen, BT_MAC_LEN);
    return ret;
}

static int32_t CopyDeviceIdHashValue(DeviceWrapper *device, const uint8_t *data, uint32_t len)
{
    if (CopyValue(device->info->addr[0].info.ble.udidHash, DISC_MAX_DEVICE_ID_LEN,
        (void *)data, len, "TLV_TYPE_DEVICE_ID_HASH") != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "parse tlv copy device id hash value failed");
        return SOFTBUS_ERR;
    }
    if (ConvertBytesToHexString((char *)device->info->devId, DISC_MAX_DEVICE_ID_LEN,
        (const uint8_t *)device->info->addr[0].info.ble.udidHash, len) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "ConvertBytesToHexString failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t CopyDeviceNameValue(DeviceWrapper *device, const uint8_t *data, uint32_t *len, uint32_t remainLen)
{
    // TLV_VARIBALE_DATA_LEN indicate indefinite length
    if (*len == TLV_VARIABLE_DATA_LEN) {
        uint32_t devNameLen = strlen((char *)data) + 1; // +1 is device name end '\0'
        *len = (devNameLen > remainLen) ? remainLen : devNameLen;
    }
    if (CopyValue(device->info->devName, DISC_MAX_DEVICE_NAME_LEN,
        (void *)data, *len, "TLV_TYPE_DEVICE_NAME") != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "parse tlv copy device name value failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
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

static int32_t ParseCustData(DeviceWrapper *device, const uint8_t *data, const uint32_t len)
{
    if ((int32_t)data[0] != (int32_t)CAST_PLUS) {
        DISC_LOGI(DISC_BLE, "not castPlus, just ignore");
        return SOFTBUS_OK;
    }
    cJSON *custJson = cJSON_CreateObject();
    DISC_CHECK_AND_RETURN_RET_LOGE(custJson != NULL, SOFTBUS_CREATE_JSON_ERR, DISC_BLE, "create cust json obj failed");

    int32_t custLen = HEXIFY_LEN(len);
    char *custString = SoftBusCalloc(sizeof(char) * custLen);
    if (custString == NULL) {
        DISC_LOGE(DISC_BLE, "calloc custString failed.");
        cJSON_Delete(custJson);
        return SOFTBUS_MEM_ERR;
    }
    if (ConvertBytesToUpperCaseHexString(custString, custLen, data, len) != SOFTBUS_OK) {
        DISC_LOGE(DISC_BLE, "ConvertBytesToUpperCaseHexString failed");
        cJSON_Delete(custJson);
        SoftBusFree(custString);
        return SOFTBUS_ERR;
    }

    if (!AddStringToJsonObject(custJson, g_capabilityMap[CASTPLUS_CAPABILITY_BITMAP].capability,
        &custString[CUST_CAPABILITY_LEN])) {
        DISC_LOGE(DISC_BLE, "add string to json failed");
        cJSON_Delete(custJson);
        SoftBusFree(custString);
        return SOFTBUS_PARSE_JSON_ERR;
    }

    char *custData = cJSON_PrintUnformatted(custJson);
    cJSON_Delete(custJson);
    if (custData == NULL) {
        DISC_LOGE(DISC_BLE, "cJSON_PrintUnformatted failed");
        SoftBusFree(custString);
        return SOFTBUS_ERR;
    }
    if (memcpy_s(device->info->custData, DISC_MAX_CUST_DATA_LEN, custData, strlen(custData) + 1) != EOK) {
        DISC_LOGE(DISC_BLE, "memcpy custData failed");
        cJSON_free(custData);
        SoftBusFree(custString);
        return SOFTBUS_ERR;
    }
    cJSON_free(custData);
    SoftBusFree(custString);
    return SOFTBUS_OK;
}

static int32_t ParseRecvTlvs(DeviceWrapper *device, const uint8_t *data, uint32_t dataLen)
{
    uint32_t curLen = 0;
    int32_t ret = SOFTBUS_OK;
    while (curLen < dataLen) {
        uint8_t type = (data[curLen] & DATA_TYPE_MASK) >> BYTE_SHIFT;
        uint32_t len = (uint32_t)(data[curLen] & DATA_LENGTH_MASK);
        if (curLen + TL_LEN + len > dataLen || (len == TLV_VARIABLE_DATA_LEN && curLen + TL_LEN  >= dataLen)) {
            DISC_LOGE(DISC_BLE,
                "unexperted advData: out of range, "
                "tlvType=%{public}d, tlvLen=%{public}u, currentPos=%{public}u, totalPos=%{public}u",
                type, len, curLen, dataLen);
            return SOFTBUS_ERR;
        }
        switch (type) {
            case TLV_TYPE_DEVICE_ID_HASH:
                ret = CopyDeviceIdHashValue(device, &data[curLen + 1], len);
                break;
            case TLV_TYPE_DEVICE_TYPE:
                ret = ParseDeviceType(device, &data[curLen + 1], len);
                break;
            case TLV_TYPE_DEVICE_NAME:
                ret = CopyDeviceNameValue(device, &data[curLen + 1], &len, dataLen - curLen - TL_LEN);
                break;
            case TLV_TYPE_CUST:
                ret = ParseCustData(device, &data[curLen + 1], len);
                break;
            case TLV_TYPE_BR_MAC:
                ret = CopyBrAddrValue(device, &data[curLen + 1], len);
                break;
            case TLV_TYPE_RANGE_POWER:
                ret = CopyValue(&device->power, RANGE_POWER_TYPE_LEN, (void *)&data[curLen + 1], len,
                                "TLV_TYPE_RANGE_POWER");
                break;
            default:
                DISC_LOGW(DISC_BLE, "Unknown TLV, just skip, tlvType=%{public}d, tlvLen=%{public}u", type, len);
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
        "device is null");
    BroadcastReportInfo *reportInfo = (BroadcastReportInfo *)data;
    DISC_CHECK_AND_RETURN_RET_LOGW(reportInfo != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "reportInfo=NULL is invalid");
    DISC_CHECK_AND_RETURN_RET_LOGW(dataLen == sizeof(BroadcastReportInfo), SOFTBUS_INVALID_PARAM, DISC_BLE,
        "bcData.payload=NULL is invalid");
    DISC_CHECK_AND_RETURN_RET_LOGW(
        reportInfo->packet.bcData.payload != NULL, SOFTBUS_INVALID_PARAM, DISC_BLE, "payload=NULL is invalid");
    uint16_t bcLen = reportInfo->packet.bcData.payloadLen;
    uint16_t rspLen = reportInfo->packet.rspData.payloadLen;
    if (bcLen > ADV_DATA_MAX_LEN || bcLen < POS_TLV || rspLen > RESP_DATA_MAX_LEN) {
        DISC_LOGE(DISC_BLE, "get discovery adv data fail");
        return SOFTBUS_INVALID_PARAM;
    }

    uint8_t *serviceData = reportInfo->packet.bcData.payload;
    if (memcpy_s(device->info->accountHash, SHORT_USER_ID_HASH_LEN,
        &serviceData[POS_USER_ID_HASH], SHORT_USER_ID_HASH_LEN) != EOK) {
        DISC_LOGE(DISC_BLE, "copy accountHash failed");
        return SOFTBUS_MEM_ERR;
    }
    device->info->capabilityBitmap[0] = serviceData[POS_CAPABLITY];

    uint32_t bcTlvLen = reportInfo->packet.bcData.payloadLen - POS_TLV;

    if (bcTlvLen == 0) {
        return SOFTBUS_OK;
    }
    uint8_t *copyData = SoftBusCalloc(bcTlvLen + rspLen + 1); // calloc 1 bytes to add tail 0
    DISC_CHECK_AND_RETURN_RET_LOGE(copyData != NULL, SOFTBUS_MEM_ERR, DISC_BLE, "malloc failed.");
    if (memcpy_s(copyData, bcTlvLen, &serviceData[POS_TLV], bcTlvLen) != EOK) {
        DISC_LOGE(DISC_BLE, "memcpy_s adv failed, bcTlvLen=%{public}u", bcTlvLen);
        SoftBusFree(copyData);
        return SOFTBUS_MEM_ERR;
    }

    if (rspLen > 0 && reportInfo->packet.rspData.payload != NULL) {
        if (memcpy_s(copyData + bcTlvLen, rspLen, reportInfo->packet.rspData.payload, rspLen) != EOK) {
            DISC_LOGE(DISC_BLE, "memcpy_s rsp data failed, rspLen=%{public}u", rspLen);
            SoftBusFree(copyData);
            return SOFTBUS_MEM_ERR;
        }
    }

    int32_t ret = ParseRecvTlvs(device, copyData, bcTlvLen + rspLen);
    SoftBusFree(copyData);
    return ret;
}

