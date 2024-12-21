/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "softbus_ble_utils.h"
#include "softbus_adapter_mem.h"
#include "softbus_broadcast_type.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "softbus_broadcast_utils.h"
#include "disc_log.h"
#include <securec.h>

#define UUID_LEN 2
#define UUID_MASK_LEN 2
#define ID_LEN 2
#define MANUFACTURE_DATA_LEN 1
#define MANUFACTURE_DATA_ID 0x027D

int32_t BtStatusToSoftBus(BtStatus btStatus)
{
    switch (btStatus) {
        case OHOS_BT_STATUS_SUCCESS:
            return SOFTBUS_BC_STATUS_SUCCESS;
        case OHOS_BT_STATUS_FAIL:
            return SOFTBUS_BC_STATUS_FAIL;
        case OHOS_BT_STATUS_NOT_READY:
            return SOFTBUS_BC_STATUS_NOT_READY;
        case OHOS_BT_STATUS_NOMEM:
            return SOFTBUS_BC_STATUS_NOMEM;
        case OHOS_BT_STATUS_BUSY:
            return SOFTBUS_BC_STATUS_BUSY;
        case OHOS_BT_STATUS_DONE:
            return SOFTBUS_BC_STATUS_DONE;
        case OHOS_BT_STATUS_UNSUPPORTED:
            return SOFTBUS_BC_STATUS_UNSUPPORTED;
        case OHOS_BT_STATUS_PARM_INVALID:
            return SOFTBUS_BC_STATUS_PARM_INVALID;
        case OHOS_BT_STATUS_UNHANDLED:
            return SOFTBUS_BC_STATUS_UNHANDLED;
        case OHOS_BT_STATUS_AUTH_FAILURE:
            return SOFTBUS_BC_STATUS_AUTH_FAILURE;
        case OHOS_BT_STATUS_RMT_DEV_DOWN:
            return SOFTBUS_BC_STATUS_RMT_DEV_DOWN;
        case OHOS_BT_STATUS_AUTH_REJECTED:
            return SOFTBUS_BC_STATUS_AUTH_REJECTED;
        case OHOS_BT_STATUS_DUPLICATED_ADDR:
            return SOFTBUS_BC_STATUS_DUPLICATED_ADDR;
        default:
            return SOFTBUS_BC_STATUS_FAIL;
    }
}

static uint16_t SoftbusAdvDataTypeToBt(uint16_t advType)
{
    switch (advType) {
        case BC_DATA_TYPE_SERVICE:
            return SERVICE_BC_TYPE;
        case BC_DATA_TYPE_MANUFACTURER:
            return MANUFACTURE_BC_TYPE;
        default:
            return 0x00;
    }
}

static uint16_t BtAdvTypeToSoftbus(uint16_t advType)
{
    switch (advType) {
        case SERVICE_BC_TYPE:
            return BC_DATA_TYPE_SERVICE;
        case MANUFACTURE_BC_TYPE:
            return BC_DATA_TYPE_MANUFACTURER;
        default:
            return 0x00;
    }
}

static BleAdvFilter SoftbusAdvFilterToBt(uint8_t advFilter)
{
    switch (advFilter) {
        case SOFTBUS_BC_ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY:
            return OHOS_BLE_ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY;
        case SOFTBUS_BC_ADV_FILTER_ALLOW_SCAN_WLST_CON_ANY:
            return OHOS_BLE_ADV_FILTER_ALLOW_SCAN_WLST_CON_ANY;
        case SOFTBUS_BC_ADV_FILTER_ALLOW_SCAN_ANY_CON_WLST:
            return OHOS_BLE_ADV_FILTER_ALLOW_SCAN_ANY_CON_WLST;
        case SOFTBUS_BC_ADV_FILTER_ALLOW_SCAN_WLST_CON_WLST:
            return OHOS_BLE_ADV_FILTER_ALLOW_SCAN_WLST_CON_WLST;
        default:
            return OHOS_BLE_ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY;
    }
}

static BleAdvType SoftbusAdvTypeToBt(uint8_t advType)
{
    switch (advType) {
        case SOFTBUS_BC_ADV_IND:
            return OHOS_BLE_ADV_IND;
        case SOFTBUS_BC_ADV_DIRECT_IND_HIGH:
            return OHOS_BLE_ADV_DIRECT_IND_HIGH;
        case SOFTBUS_BC_ADV_SCAN_IND:
            return OHOS_BLE_ADV_SCAN_IND;
        case SOFTBUS_BC_ADV_NONCONN_IND:
            return OHOS_BLE_ADV_NONCONN_IND;
        case SOFTBUS_BC_ADV_DIRECT_IND_LOW:
            return OHOS_BLE_ADV_DIRECT_IND_LOW;
        default:
            return OHOS_BLE_ADV_IND;
    }
}

void SoftbusAdvParamToBt(const SoftbusBroadcastParam *src, BleAdvParams *dst)
{
    DISC_CHECK_AND_RETURN_LOGE(src != NULL, DISC_BLE_ADAPTER, "src is null!");
    DISC_CHECK_AND_RETURN_LOGE(dst != NULL, DISC_BLE_ADAPTER, "dst is null!");
    if (memcpy_s(dst->peerAddr.addr, SOFTBUS_ADDR_MAC_LEN, src->peerAddr.addr, SOFTBUS_ADDR_MAC_LEN) != EOK) {
        DISC_LOGW(DISC_BLE_ADAPTER, "copy peer addr failed");
    }
    dst->minInterval = src->minInterval;
    dst->maxInterval = src->maxInterval;
    dst->advType = SoftbusAdvTypeToBt(src->advType);
    dst->ownAddrType = (unsigned char)src->ownAddrType;
    dst->peerAddrType = (unsigned char)src->peerAddrType;
    dst->channelMap = src->channelMap;
    dst->advFilterPolicy = SoftbusAdvFilterToBt(src->advFilterPolicy);
    dst->txPower = src->txPower;
    dst->duration = src->duration;
}

static uint8_t BtScanEventTypeToSoftbus(unsigned char eventType)
{
    switch (eventType) {
        case OHOS_BLE_EVT_NON_CONNECTABLE_NON_SCANNABLE:
            return SOFTBUS_BC_EVT_NON_CONNECTABLE_NON_SCANNABLE;
        case OHOS_BLE_EVT_NON_CONNECTABLE_NON_SCANNABLE_DIRECTED:
            return SOFTBUS_BC_EVT_NON_CONNECTABLE_NON_SCANNABLE_DIRECTED;
        case OHOS_BLE_EVT_CONNECTABLE:
            return SOFTBUS_BC_EVT_CONNECTABLE;
        case OHOS_BLE_EVT_CONNECTABLE_DIRECTED:
            return SOFTBUS_BC_EVT_CONNECTABLE_DIRECTED;
        case OHOS_BLE_EVT_SCANNABLE:
            return SOFTBUS_BC_EVT_SCANNABLE;
        case OHOS_BLE_EVT_SCANNABLE_DIRECTED:
            return SOFTBUS_BC_EVT_SCANNABLE_DIRECTED;
        case OHOS_BLE_EVT_LEGACY_NON_CONNECTABLE:
            return SOFTBUS_BC_EVT_LEGACY_NON_CONNECTABLE;
        case OHOS_BLE_EVT_LEGACY_SCANNABLE:
            return SOFTBUS_BC_EVT_LEGACY_SCANNABLE;
        case OHOS_BLE_EVT_LEGACY_CONNECTABLE:
            return SOFTBUS_BC_EVT_LEGACY_CONNECTABLE;
        case OHOS_BLE_EVT_LEGACY_CONNECTABLE_DIRECTED:
            return SOFTBUS_BC_EVT_LEGACY_CONNECTABLE_DIRECTED;
        case OHOS_BLE_EVT_LEGACY_SCAN_RSP_TO_ADV_SCAN:
            return SOFTBUS_BC_EVT_LEGACY_SCAN_RSP_TO_ADV_SCAN;
        case OHOS_BLE_EVT_LEGACY_SCAN_RSP_TO_ADV:
            return SOFTBUS_BC_EVT_LEGACY_SCAN_RSP_TO_ADV;
        default:
            return SOFTBUS_BC_EVT_NON_CONNECTABLE_NON_SCANNABLE;
    }
}

static uint8_t BtScanDataStatusToSoftbus(unsigned char dataStatus)
{
    switch (dataStatus) {
        case OHOS_BLE_DATA_COMPLETE:
            return SOFTBUS_BC_DATA_COMPLETE;
        case OHOS_BLE_DATA_INCOMPLETE_MORE_TO_COME:
            return SOFTBUS_BC_DATA_INCOMPLETE_MORE_TO_COME;
        case OHOS_BLE_DATA_INCOMPLETE_TRUNCATED:
            return SOFTBUS_BC_DATA_INCOMPLETE_TRUNCATED;
        default:
            return SOFTBUS_BC_DATA_INCOMPLETE_TRUNCATED;
    }
}

static uint8_t BtScanAddrTypeToSoftbus(unsigned char addrType)
{
    switch (addrType) {
        case OHOS_BLE_PUBLIC_DEVICE_ADDRESS:
            return SOFTBUS_BC_PUBLIC_DEVICE_ADDRESS;
        case OHOS_BLE_RANDOM_DEVICE_ADDRESS:
            return SOFTBUS_BC_RANDOM_DEVICE_ADDRESS;
        case OHOS_BLE_PUBLIC_IDENTITY_ADDRESS:
            return SOFTBUS_BC_PUBLIC_IDENTITY_ADDRESS;
        case OHOS_BLE_RANDOM_STATIC_IDENTITY_ADDRESS:
            return SOFTBUS_BC_RANDOM_STATIC_IDENTITY_ADDRESS;
        case OHOS_BLE_UNRESOLVABLE_RANDOM_DEVICE_ADDRESS:
            return SOFTBUS_BC_UNRESOLVABLE_RANDOM_DEVICE_ADDRESS;
        case OHOS_BLE_NO_ADDRESS:
            return SOFTBUS_BC_NO_ADDRESS;
        default:
            return SOFTBUS_BC_NO_ADDRESS;
    }
}

static uint8_t BtScanPhyTypeToSoftbus(unsigned char phyType)
{
    switch (phyType) {
        case OHOS_BLE_SCAN_PHY_NO_PACKET:
            return SOFTBUS_BC_SCAN_PHY_NO_PACKET;
        case OHOS_BLE_SCAN_PHY_1M:
            return SOFTBUS_BC_SCAN_PHY_1M;
        case OHOS_BLE_SCAN_PHY_2M:
            return SOFTBUS_BC_SCAN_PHY_2M;
        case OHOS_BLE_SCAN_PHY_CODED:
            return SOFTBUS_BC_SCAN_PHY_CODED;
        default:
            return SOFTBUS_BC_SCAN_PHY_NO_PACKET;
    }
}

void BtScanResultToSoftbus(const BtScanResultData *src, SoftBusBcScanResult *dst)
{
    DISC_CHECK_AND_RETURN_LOGE(src != NULL, DISC_BLE_ADAPTER, "src is null!");
    DISC_CHECK_AND_RETURN_LOGE(dst != NULL, DISC_BLE_ADAPTER, "dst is null!");
    dst->eventType = BtScanEventTypeToSoftbus(src->eventType);
    dst->dataStatus = BtScanDataStatusToSoftbus(src->dataStatus);
    dst->addrType = BtScanAddrTypeToSoftbus(src->addrType);
    if (memcpy_s(dst->addr.addr, SOFTBUS_ADDR_MAC_LEN, src->addr.addr, SOFTBUS_ADDR_MAC_LEN) != EOK) {
        DISC_LOGW(DISC_BLE_ADAPTER, "copy addr failed");
    }
    dst->primaryPhy = BtScanPhyTypeToSoftbus(src->primaryPhy);
    dst->secondaryPhy = BtScanPhyTypeToSoftbus(src->secondaryPhy);
    dst->advSid = (uint8_t)src->advSid;
    dst->txPower = (int8_t)src->txPower;
    dst->rssi = (int8_t)src->rssi;
}

void SoftbusFilterToBt(BleScanNativeFilter *nativeFilter, const SoftBusBcScanFilter *filter, uint8_t filterSize)
{
    DISC_CHECK_AND_RETURN_LOGE(nativeFilter != NULL, DISC_BLE_ADAPTER, "ble scan native filter is null!");
    DISC_CHECK_AND_RETURN_LOGE(filter != NULL, DISC_BLE_ADAPTER, "bc scan filter is null!");
    DISC_CHECK_AND_RETURN_LOGE(filterSize > 0, DISC_BLE_ADAPTER, "filter size is 0 or smaller!");
    while (filterSize-- > 0) {
        (nativeFilter + filterSize)->address = (char *)(filter + filterSize)->address;
        (nativeFilter + filterSize)->deviceName = (char *)(filter + filterSize)->deviceName;
        (nativeFilter + filterSize)->manufactureData = (unsigned char *)(filter + filterSize)->manufactureData;
        (nativeFilter + filterSize)->manufactureDataLength =
            (unsigned int)(filter + filterSize)->manufactureDataLength;
        (nativeFilter + filterSize)->manufactureDataMask = (unsigned char *)(filter + filterSize)->manufactureDataMask;
        (nativeFilter + filterSize)->manufactureId = (unsigned short)(filter + filterSize)->manufactureId;
        (nativeFilter + filterSize)->advIndReport = (filter + filterSize)->advIndReport;

        if ((filter + filterSize)->serviceData == NULL || (filter + filterSize)->serviceDataMask == NULL) {
            continue;
        }

        // serviceData = uuid + serviceData, serviceDataMask = 0xFFFF + serviceDataMask
        uint16_t serviceUuid = (filter + filterSize)->serviceUuid;
        uint16_t serviceDataLen = (filter + filterSize)->serviceDataLength + 2;
        uint8_t *serviceData = (uint8_t *)SoftBusCalloc(serviceDataLen);
        if (serviceData == NULL) {
            DISC_LOGW(DISC_BLE_ADAPTER, "malloc service data failed");
            continue;
        }
        serviceData[0] = serviceUuid & BC_BYTE_MASK;
        serviceData[1] = (serviceUuid >> BC_SHIFT_BIT) & BC_BYTE_MASK;
        if (memcpy_s(serviceData + UUID_LEN, serviceDataLen - UUID_LEN, (filter + filterSize)->serviceData,
            serviceDataLen - UUID_LEN) != EOK) {
            DISC_LOGW(DISC_BLE_ADAPTER, "copy service data failed");
        }
        uint8_t *serviceDataMask = (uint8_t *)SoftBusCalloc(serviceDataLen);
        if (serviceDataMask == NULL) {
            SoftBusFree(serviceData);
            DISC_LOGW(DISC_BLE_ADAPTER, "malloc service data mask failed");
            continue;
        }
        serviceDataMask[0] = BC_BYTE_MASK;
        serviceDataMask[1] = BC_BYTE_MASK;
        if (memcpy_s(serviceDataMask + UUID_MASK_LEN, serviceDataLen - UUID_MASK_LEN,
            (filter + filterSize)->serviceDataMask, serviceDataLen - UUID_MASK_LEN) != EOK) {
            DISC_LOGW(DISC_BLE_ADAPTER, "copy service data mask failed");
        }
        (nativeFilter + filterSize)->serviceData = (unsigned char *)serviceData;
        (nativeFilter + filterSize)->serviceDataLength = (unsigned int)serviceDataLen;
        (nativeFilter + filterSize)->serviceDataMask = (unsigned char *)serviceDataMask;
    }
}

void SoftbusSetManufactureFilter(BleScanNativeFilter *nativeFilter, uint8_t filterSize)
{
    DISC_CHECK_AND_RETURN_LOGE(nativeFilter != NULL, DISC_BLE_ADAPTER, "ble scan native filter is null!");
    DISC_CHECK_AND_RETURN_LOGE(filterSize > 0, DISC_BLE_ADAPTER, "filter size is 0 or smaller!");
    while (filterSize-- > 0) {
        uint8_t *manufactureData = (uint8_t *)SoftBusCalloc(MANUFACTURE_DATA_LEN);
        if (manufactureData == NULL) {
            DISC_LOGW(DISC_BLE_ADAPTER, "malloc manufacture data failed");
            return;
        }
        uint8_t *manufactureMask = (uint8_t *)SoftBusCalloc(MANUFACTURE_DATA_LEN);
        if (manufactureMask == NULL) {
            SoftBusFree(manufactureData);
            DISC_LOGW(DISC_BLE_ADAPTER, "malloc manufacture mask failed");
            return;
        }
        (nativeFilter + filterSize)->manufactureData = manufactureData;
        (nativeFilter + filterSize)->manufactureDataLength = MANUFACTURE_DATA_LEN;
        (nativeFilter + filterSize)->manufactureDataMask = manufactureMask;
        (nativeFilter + filterSize)->manufactureId = MANUFACTURE_DATA_ID;
    }
}

void FreeBtFilter(BleScanNativeFilter *nativeFilter, int32_t filterSize)
{
    DISC_CHECK_AND_RETURN_LOGE(nativeFilter != NULL, DISC_BLE_ADAPTER, "ble scan native filter is null!");
    DISC_CHECK_AND_RETURN_LOGE(filterSize > 0, DISC_BLE_ADAPTER, "filter size is 0 or smaller!");
    while (filterSize-- > 0) {
        SoftBusFree((nativeFilter + filterSize)->serviceData);
        SoftBusFree((nativeFilter + filterSize)->serviceDataMask);
    }
    SoftBusFree(nativeFilter);
}

void DumpBleScanFilter(BleScanNativeFilter *nativeFilter, int32_t filterSize)
{
    DISC_CHECK_AND_RETURN_LOGE(nativeFilter != NULL, DISC_BLE_ADAPTER, "ble scan native filter is null!");
    DISC_CHECK_AND_RETURN_LOGE(filterSize > 0, DISC_BLE_ADAPTER, "filter size is 0 or smaller!");
    while (filterSize-- > 0) {
        bool advIndReport = (nativeFilter + filterSize)->advIndReport;
        uint32_t len = (nativeFilter + filterSize)->serviceDataLength;
        if (len == 0) {
            continue;
        }
        uint32_t hexLen = HEXIFY_LEN(len);
        char *serviceData = (char *)SoftBusCalloc(sizeof(char) * hexLen);
        if (serviceData == NULL) {
            continue;
        }
        char *serviceDataMask = (char *)SoftBusCalloc(sizeof(char) * hexLen);
        if (serviceDataMask == NULL) {
            SoftBusFree(serviceData);
            continue;
        }
        (void)ConvertBytesToHexString(serviceData, hexLen, (nativeFilter + filterSize)->serviceData, len);
        (void)ConvertBytesToHexString(serviceDataMask, hexLen, (nativeFilter + filterSize)->serviceDataMask, len);
        DISC_LOGD(DISC_BLE_ADAPTER,
            "ble scan filter size=%{public}d, serviceData=%{public}s, serviceDataMask=%{public}s,"
            "advIndReport=%{public}d", filterSize, serviceData, serviceDataMask, advIndReport);
        SoftBusFree(serviceData);
        SoftBusFree(serviceDataMask);
    }
}

int GetBtScanMode(uint16_t scanInterval, uint16_t scanWindow)
{
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P2 && scanWindow == SOFTBUS_BC_SCAN_WINDOW_P2) {
        return OHOS_BLE_SCAN_MODE_OP_P2_60_3000;
    }
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P2_FAST && scanWindow == SOFTBUS_BC_SCAN_WINDOW_P2_FAST) {
        return OHOS_BLE_SCAN_MODE_OP_P2_30_1500;
    }
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P10 && scanWindow == SOFTBUS_BC_SCAN_WINDOW_P10) {
        return OHOS_BLE_SCAN_MODE_OP_P10_30_300;
    }
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P25 && scanWindow == SOFTBUS_BC_SCAN_WINDOW_P25) {
        return OHOS_BLE_SCAN_MODE_OP_P25_60_240;
    }
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P50 && scanWindow == SOFTBUS_BC_SCAN_WINDOW_P50) {
        return OHOS_BLE_SCAN_MODE_OP_P50_30_60;
    }
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P75 && scanWindow == SOFTBUS_BC_SCAN_WINDOW_P75) {
        return OHOS_BLE_SCAN_MODE_OP_P75_30_40;
    }
    if (scanInterval == SOFTBUS_BC_SCAN_INTERVAL_P100 && scanWindow == SOFTBUS_BC_SCAN_WINDOW_P100) {
        return OHOS_BLE_SCAN_MODE_OP_P100_1000_1000;
    }
    return OHOS_BLE_SCAN_MODE_LOW_POWER;
}

uint8_t *AssembleAdvData(const SoftbusBroadcastData *data, uint16_t *dataLen)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(data != NULL, NULL, DISC_BLE_ADAPTER, "data is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(dataLen != NULL, NULL, DISC_BLE_ADAPTER, "data len is null!");
    uint16_t payloadLen = (data->bcData.payloadLen > BC_DATA_MAX_LEN) ? BC_DATA_MAX_LEN : data->bcData.payloadLen;
    uint16_t len = data->isSupportFlag ? payloadLen + BC_HEAD_LEN : payloadLen + BC_HEAD_LEN - BC_FLAG_LEN;
    uint8_t *advData = (uint8_t *)SoftBusCalloc(len);
    if (advData == NULL) {
        DISC_LOGE(DISC_BLE_ADAPTER, "malloc adv data failed");
        return NULL;
    }

    int8_t offset = -BC_FLAG_LEN;
    if (data->isSupportFlag) {
        advData[IDX_BC_FLAG_BYTE_LEN] = BC_FLAG_BYTE_LEN;
        advData[IDX_BC_FLAG_AD_TYPE] = BC_FLAG_AD_TYPE;
        advData[IDX_BC_FLAG_AD_DATA] = data->flag;
        offset += BC_FLAG_LEN;
    }

    advData[IDX_PACKET_LEN + offset] = payloadLen + BC_HEAD_LEN - BC_FLAG_LEN - 1;
    advData[IDX_BC_TYPE + offset] = SoftbusAdvDataTypeToBt(data->bcData.type);
    uint16_t payloadId = data->bcData.id;
    advData[IDX_BC_UUID + offset] = (uint8_t)(payloadId & BC_BYTE_MASK);
    advData[IDX_BC_UUID + offset + 1] = (uint8_t)((payloadId >> BC_SHIFT_BIT) & BC_BYTE_MASK);

    if (memcpy_s(&advData[BC_HEAD_LEN + offset], payloadLen, data->bcData.payload, payloadLen) != EOK) {
        DISC_LOGE(DISC_BLE_ADAPTER, "copy adv payload failed");
        SoftBusFree(advData);
        return NULL;
    }
    *dataLen = len;
    return advData;
}

uint8_t *AssembleRspData(const SoftbusBroadcastPayload *data, uint16_t *dataLen)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(data != NULL, NULL, DISC_BLE_ADAPTER, "data is null!");
    DISC_CHECK_AND_RETURN_RET_LOGE(dataLen != NULL, NULL, DISC_BLE_ADAPTER, "data len is null!");
    uint16_t payloadLen = (data->payloadLen > RSP_DATA_MAX_LEN) ? RSP_DATA_MAX_LEN : data->payloadLen;
    uint16_t len = payloadLen + RSP_HEAD_LEN;
    uint8_t *rspData = (uint8_t *)SoftBusCalloc(len);
    if (rspData == NULL) {
        DISC_LOGE(DISC_BLE_ADAPTER, "malloc rsp data failed");
        return NULL;
    }
    rspData[IDX_RSP_PACKET_LEN] = payloadLen + RSP_HEAD_LEN - 1;
    rspData[IDX_RSP_TYPE] = SoftbusAdvDataTypeToBt(data->type);
    uint16_t payloadId = data->id;
    rspData[IDX_RSP_UUID] = (uint8_t)(payloadId & BC_BYTE_MASK);
    rspData[IDX_RSP_UUID + 1] = (uint8_t)((payloadId >> BC_SHIFT_BIT) & BC_BYTE_MASK);

    if (memcpy_s(&rspData[RSP_HEAD_LEN], payloadLen, data->payload, payloadLen) != EOK) {
        DISC_LOGE(DISC_BLE_ADAPTER, "copy rsp payload failed");
        SoftBusFree(rspData);
        return NULL;
    }
    *dataLen = len;
    return rspData;
}

static int32_t ParseFlag(const uint8_t *advData, uint8_t advLen, SoftBusBcScanResult *dst, uint8_t index)
{
    if (index + 1 >= advLen) {
        DISC_LOGW(DISC_BLE_ADAPTER, "parse flag failed");
        return SOFTBUS_OK;
    }
    dst->data.flag = advData[index + 1];
    dst->data.isSupportFlag = true;
    return SOFTBUS_OK;
}

static int32_t ParseLocalName(const uint8_t *advData, uint8_t advLen, SoftBusBcScanResult *dst, uint8_t index,
    uint8_t len)
{
    if (index + 1 >= advLen) {
        DISC_LOGW(DISC_BLE_ADAPTER, "parse local name failed");
        return SOFTBUS_OK;
    }
    if (memcpy_s(dst->localName, sizeof(dst->localName), &advData[index + 1], len - 1) != EOK) {
        DISC_LOGE(DISC_BLE_ADAPTER, "copy local name failed");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ParseScanResult(const uint8_t *advData, uint8_t advLen, SoftBusBcScanResult *dst)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(advData != NULL && dst != NULL && advLen > 0, SOFTBUS_INVALID_PARAM,
        DISC_BLE_ADAPTER, "input is invalid!");
    uint8_t index = 0;
    bool isRsp = false;
    while (index < advLen) {
        uint8_t len = advData[index];
        if (len == 0) {
            index++;
            continue;
        }
        if (index + len >= advLen || index + 1 >= advLen) {
            break;
        }
        uint8_t type = advData[++index];
        if (type == BC_FLAG_AD_TYPE) {
            DISC_CHECK_AND_RETURN_RET_LOGE(ParseFlag(advData, advLen, dst, index) == SOFTBUS_OK,
                SOFTBUS_BC_ADAPTER_PARSE_FAIL, DISC_BLE_ADAPTER, "parse flag failed");
        } else if (type == SHORTENED_LOCAL_NAME_BC_TYPE || type == LOCAL_NAME_BC_TYPE) {
            DISC_CHECK_AND_RETURN_RET_LOGE(ParseLocalName(advData, advLen, dst, index, len) == SOFTBUS_OK,
                SOFTBUS_BC_ADAPTER_PARSE_FAIL, DISC_BLE_ADAPTER, "parse local name failed");
        } else {
            if (type != SERVICE_BC_TYPE && type != MANUFACTURE_BC_TYPE) {
                index += len;
                DISC_LOGD(DISC_BLE_ADAPTER, "unsupported type, type=%{public}hhu", type);
                continue;
            }
            SoftbusBroadcastPayload *data = isRsp ? &dst->data.rspData : &dst->data.bcData;
            data->payloadLen = len - ID_LEN - 1;
            if (data->payloadLen < 0 || index + ID_LEN >= advLen) {
                DISC_LOGE(DISC_BLE_ADAPTER, "parse payload failed");
                return SOFTBUS_BC_ADAPTER_PARSE_FAIL;
            }
            isRsp = !isRsp;
            data->type = BtAdvTypeToSoftbus(type);
            data->id = ((uint16_t)advData[index + ID_LEN] << BC_SHIFT_BIT) | (uint16_t)advData[index + ID_LEN - 1];
            if (data->payloadLen == 0) {
                index += len;
                DISC_LOGW(DISC_BLE_ADAPTER, "parse no payload, isRsp=%{public}d", isRsp);
                continue;
            }
            data->payload = (uint8_t *)SoftBusCalloc(data->payloadLen);
            DISC_CHECK_AND_RETURN_RET_LOGE(data->payload != NULL, SOFTBUS_MALLOC_ERR, DISC_BLE_ADAPTER,
                "malloc payload failed");
            (void)memcpy_s(data->payload, data->payloadLen, &advData[index + ID_LEN + 1], data->payloadLen);
        }
        index += len;
    }
    return SOFTBUS_OK;
}

void DumpSoftbusAdapterData(const char *description, uint8_t *data, uint16_t len)
{
    DISC_CHECK_AND_RETURN_LOGE(description != NULL, DISC_BLE_ADAPTER, "data is null!");
    DISC_CHECK_AND_RETURN_LOGE(len != 0, DISC_BLE_ADAPTER, "len is 0!");
    DISC_CHECK_AND_RETURN_LOGE(data != NULL, DISC_BLE_ADAPTER, "data is null!");

    int32_t hexLen = HEXIFY_LEN(len);
    char *softbusData = (char *)SoftBusCalloc(sizeof(char) * hexLen);
    DISC_CHECK_AND_RETURN_LOGE(softbusData != NULL, DISC_BLE_ADAPTER, "malloc failed!");

    (void)ConvertBytesToHexString(softbusData, hexLen, data, len);
    DISC_LOGI(DISC_BLE_ADAPTER, "description=%{public}s, softbusData=%{public}s", description, softbusData);

    SoftBusFree(softbusData);
}
