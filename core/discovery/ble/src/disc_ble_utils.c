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
#include "mbedtls/md.h"
#include "mbedtls/platform.h"
#include "securec.h"
#include "softbus_common.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C

#define DATA_TYPE_MASK 0xF0
#define DATA_LENGTH_MASK 0x0F
#define BYTE_SHIFT 4

#ifndef PACKET_CHECK_LENGTH
#define PACKET_CHECK_LENGTH(len) \
    if (len >= 0) { \
        curLen += len; \
    } else { \
        return len; \
    }
#endif

int32_t GenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    if (str == NULL || hash == NULL || len == 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *info;
    mbedtls_md_init(&ctx);
    info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (mbedtls_md_setup(&ctx, info, 0) != 0) {
        goto EXIT;
    }
    if (mbedtls_md_starts(&ctx) != 0) {
        goto EXIT;
    }
    if (mbedtls_md_update(&ctx, str, len) != 0) {
        goto EXIT;
    }
    if (mbedtls_md_finish(&ctx, hash) != 0) {
        goto EXIT;
    }
    mbedtls_md_free(&ctx);
    return SOFTBUS_OK;
EXIT:
    mbedtls_md_free(&ctx);
    return SOFTBUS_ENCRYPT_ERR;
}

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

bool CheckCapBitMapEqual(const uint32_t *srcBitMap, const uint32_t *dstBitMap, uint32_t capBitMapNum)
{
    if (srcBitMap == NULL || dstBitMap == NULL) {
        return false;
    }
    for (uint32_t i = 0; i < capBitMapNum; i++) {
        if (srcBitMap[i] != dstBitMap[i]) {
            return false;
        }
    }
    return true;
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

int32_t DiscBleGetHwAccount(char *hwAccount)
{
    if (hwAccount == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    const char *account = "";
    if (memcpy_s(hwAccount, strlen(account) + 1, account, strlen(account) + 1) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t DiscBleGetDeviceUdid(char *devId)
{
    if (devId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, devId, UDID_BUF_LEN) != SOFTBUS_OK) {
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
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_NAME, deviceName, DEVICE_TYPE_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Get local device name failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

uint8_t DiscBleGetDeviceType(void)
{
    char type[DEVICE_TYPE_BUF_LEN];
    uint8_t typeId;
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_TYPE, type, DEVICE_TYPE_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Get local device type failed.");
        return TYPE_UNKNOW_ID;
    }
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
    char devId[DISC_MAX_DEVICE_ID_LEN] = {0};
    char hashResult[SHA_HASH_LEN] = {0};
    int32_t ret = DiscBleGetDeviceUdid(devId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "GetDeviceId failed");
        return ret;
    }
    ret = GenerateStrHash(devId, strlen(devId) + 1, hashResult);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "GenerateStrHash failed");
        return ret;
    }
    ret = ConvertBytesToHexString(hashStr, SHORT_DEVICE_ID_HASH_LENGTH + 1, hashResult,
        SHORT_DEVICE_ID_HASH_LENGTH / HEXIFY_UNIT_LEN);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "ConvertBytesToHexString failed");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t DiscBleGetShortUserIdHash(unsigned char *hashStr)
{
    if (hashStr == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "hashstr is null");
        return SOFTBUS_INVALID_PARAM;
    }
    unsigned char account[MAX_ACCOUNT_HASH_LEN] = {0};
    unsigned char hashResult[SHA_HASH_LEN] = {0};
    int32_t ret = DiscBleGetHwAccount(account);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "DiscBleGetHwAccount failed");
        return ret;
    }
    ret = GenerateStrHash(account, strlen(account) + 1, hashResult);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "GenerateStrHash failed");
        return ret;
    }
    ret = ConvertBytesToHexString(hashStr, SHORT_USER_ID_HASH_LEN + 1, hashResult,
        SHORT_USER_ID_HASH_LEN / HEXIFY_UNIT_LEN);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "ConvertBytesToHexString failed");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ConvertBtMacToBinary(char *strMac, int32_t strMacLen,
    const uint8_t *binMac, int32_t binMacLen)
{
    int32_t ret;

    if (strMac == NULL || strMacLen < BT_MAC_LEN || binMac == NULL || binMacLen < BT_ADDR_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    ret = sscanf_s(strMac, "%02x:%02x:%02x:%02x:%02x:%02x",
        &binMac[0], &binMac[1], &binMac[2], &binMac[3], &binMac[4], &binMac[5]);
    if (ret < 0) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ConvertBtMacToStr(char *strMac, int32_t strMacLen,
    const uint8_t *binMac, int32_t binMacLen)
{
    int32_t ret;

    if (strMac == NULL || strMacLen < BT_MAC_LEN || binMac == NULL || binMacLen < BT_ADDR_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    ret = snprintf_s(strMac, strMacLen, strMacLen - 1, "%02x:%02x:%02x:%02x:%02x:%02x",
        binMac[0], binMac[1], binMac[2], binMac[3], binMac[4], binMac[5]);
    if (ret < 0) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t AssembleTLV(BoardcastData *boardcastData, unsigned char dataType, const unsigned char *value, uint32_t dataLen)
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
    uint32_t validLen = (len > remainLen) ? remainLen : len;
    if (memcpy_s(&(boardcastData->data.data[boardcastData->dataLen]), validLen, value, validLen) != EOK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "assemble tlv memcpy failed");
        return SOFTBUS_MEM_ERR;
    }
    boardcastData->dataLen += validLen;
    return SOFTBUS_OK;
}

static int32_t ParseRecvAdvData(const unsigned char *data, uint32_t dataLen, unsigned char type,
    uint32_t index, unsigned char *value)
{
    if (data == NULL || value == NULL) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "ParseRecvAdvData input param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (dataLen <= index) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "index >= dataLen");
        return 0;
    }
    if (type != ((data[index] & DATA_TYPE_MASK) >> BYTE_SHIFT)) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "type check failed");
        return 0;
    }
    uint32_t len = (uint32_t)(data[index] & DATA_LENGTH_MASK);
    if (index + TL_LEN >= dataLen) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "advData out of range");
        return SOFTBUS_ERR;
    }
    if (len == 0) {
        return 0;
    }
    if (memcpy_s(value, len, &data[index + 1], len) != EOK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "ParseRecvAdvData memcpy failed");
        return SOFTBUS_MEM_ERR;
    }
    return len + TL_LEN;
}

int32_t GetDeviceInfoFromDisAdvData(DeviceInfo *info, const unsigned char *data, uint32_t dataLen)
{
    if (info == NULL || data == NULL || dataLen == 0) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "GetDeviceInfoFromAdvData input param is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(info->hwAccountHash, SHORT_USER_ID_HASH_LEN,
        &data[POS_USER_ID_HASH + ADV_HEAD_LEN], SHORT_USER_ID_HASH_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "copy hwAccountHash failed");
        return SOFTBUS_MEM_ERR;
    }
    info->capabilityBitmap[0] = data[POS_CAPABLITY + ADV_HEAD_LEN];
    int32_t curLen = POS_TLV + ADV_HEAD_LEN;
    unsigned char devType;
    int32_t len = ParseRecvAdvData(data, dataLen, TLV_TYPE_DEVICE_ID_HASH, curLen, info->devId);
    PACKET_CHECK_LENGTH(len);
    len = ParseRecvAdvData(data, dataLen, TLV_TYPE_DEVICE_TYPE, curLen, &devType);
    PACKET_CHECK_LENGTH(len);
    info->devType = (DeviceType)devType;
    len = ParseRecvAdvData(data, dataLen, TLV_TYPE_BR_MAC, curLen, (unsigned char *)info->addr[0].info.ble.bleMac);
    len = ParseRecvAdvData(data, dataLen, TLV_TYPE_CUST, curLen, (unsigned char *)info->custData);
    PACKET_CHECK_LENGTH(len);
    len = ParseRecvAdvData(data, dataLen, TLV_TYPE_DEVICE_NAME, curLen, info->devName);
    PACKET_CHECK_LENGTH(len);
    return SOFTBUS_OK;
}