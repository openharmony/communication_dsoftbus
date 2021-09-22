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

#ifndef SOFTBUS_ADAPTER_BLE_GATT_H
#define SOFTBUS_ADAPTER_BLE_GATT_H

#include "softbus_adapter_bt_common.h"

typedef enum {
    SOFTBUS_BLE_EVT_NON_CONNECTABLE_NON_SCANNABLE = 0x00,
    SOFTBUS_BLE_EVT_NON_CONNECTABLE_NON_SCANNABLE_DIRECTED = 0x04,
    SOFTBUS_BLE_EVT_CONNECTABLE = 0x01,
    SOFTBUS_BLE_EVT_CONNECTABLE_DIRECTED = 0x05,
    SOFTBUS_BLE_EVT_SCANNABLE = 0x02,
    SOFTBUS_BLE_EVT_SCANNABLE_DIRECTED = 0x06,
    SOFTBUS_BLE_EVT_LEGACY_NON_CONNECTABLE = 0x10,
    SOFTBUS_BLE_EVT_LEGACY_SCANNABLE = 0x12,
    SOFTBUS_BLE_EVT_LEGACY_CONNECTABLE = 0x13,
    SOFTBUS_BLE_EVT_LEGACY_CONNECTABLE_DIRECTED = 0x15,
    SOFTBUS_BLE_EVT_LEGACY_SCAN_RSP_TO_ADV_SCAN = 0x1A,
    SOFTBUS_BLE_EVT_LEGACY_SCAN_RSP_TO_ADV = 0x1B
} SoftBusBleScanResultEvtType;

typedef enum {
    SOFTBUS_BLE_PUBLIC_DEVICE_ADDRESS = 0x00,
    SOFTBUS_BLE_RANDOM_DEVICE_ADDRESS = 0x01,
    SOFTBUS_BLE_PUBLIC_IDENTITY_ADDRESS = 0x02,
    SOFTBUS_BLE_RANDOM_STATIC_IDENTITY_ADDRESS = 0x03,
    SOFTBUS_BLE_UNRESOLVABLE_RANDOM_DEVICE_ADDRESS = 0xFE,
    SOFTBUS_BLE_NO_ADDRESS = 0xFF,
} SoftBusBleScanResultAddrType;

typedef enum {
    SOFTBUS_BLE_SCAN_TYPE_PASSIVE = 0x00,
    SOFTBUS_BLE_SCAN_TYPE_ACTIVE,
} SoftBusBleScanType;

typedef enum {
    SOFTBUS_BLE_SCAN_PHY_NO_PACKET = 0x00,
    SOFTBUS_BLE_SCAN_PHY_1M = 0x01,
    SOFTBUS_BLE_SCAN_PHY_2M = 0x02,
    SOFTBUS_BLE_SCAN_PHY_CODED = 0x03
} SoftBusBleScanResultPhyType;

typedef enum {
    SOFTBUS_BLE_SCAN_FILTER_POLICY_ACCEPT_ALL = 0x00,
    SOFTBUS_BLE_SCAN_FILTER_POLICY_ONLY_WHITE_LIST,
    SOFTBUS_BLE_SCAN_FILTER_POLICY_ACCEPT_ALL_AND_RPA,
    SOFTBUS_BLE_SCAN_FILTER_POLICY_ONLY_WHITE_LIST_AND_RPA
} SoftBusBleScanFilterPolicy;

typedef enum {
    SOFTBUS_BLE_ADV_IND = 0x00,
    SOFTBUS_BLE_ADV_DIRECT_IND_HIGH = 0x01,
    SOFTBUS_BLE_ADV_SCAN_IND = 0x02,
    SOFTBUS_BLE_ADV_NONCONN_IND = 0x03,
    SOFTBUS_BLE_ADV_DIRECT_IND_LOW  = 0x04,
} SoftBusBleAdvType;

typedef enum {
    SOFTBUS_BLE_ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY = 0x00,
    SOFTBUS_BLE_ADV_FILTER_ALLOW_SCAN_WLST_CON_ANY = 0x01,
    SOFTBUS_BLE_ADV_FILTER_ALLOW_SCAN_ANY_CON_WLST = 0x02,
    SOFTBUS_BLE_ADV_FILTER_ALLOW_SCAN_WLST_CON_WLST = 0x03,
} SoftBusBleAdvFilter;

typedef struct {
    unsigned short scanInterval;
    unsigned short scanWindow;
    unsigned char scanType;
    unsigned char scanPhy;
    unsigned char scanFilterPolicy;
} SoftBusBleScanParams;

typedef enum {
    SOFTBUS_BLE_DATA_COMPLETE = 0x00,
    SOFTBUS_BLE_DATA_INCOMPLETE_MORE_TO_COME = 0x01,
    SOFTBUS_BLE_DATA_INCOMPLETE_TRUNCATED = 0x02,
} SoftBusScanResultDataStatus;

typedef struct {
    unsigned char eventType;
    unsigned char dataStatus;
    unsigned char addrType;
    SoftBusBtAddr addr;
    unsigned char primaryPhy;
    unsigned char secondaryPhy;
    unsigned char advSid;
    char txPower;
    char rssi;
    unsigned short periodicAdvInterval;
    unsigned char directAddrType;
    SoftBusBtAddr directAddr;
    unsigned char advLen;
    unsigned char *advData;
} SoftBusBleScanResult;

typedef struct {
    void (*OnScanStart)(int listenerId, int status);
    void (*OnScanStop)(int listenerId, int status);
    void (*OnScanResult)(int listenerId, SoftBusBleScanResult *scanResultdata);
} SoftBusScanListener;

typedef struct {
    unsigned short advLength;
    char *advData;
    unsigned short scanRspLength;
    char *scanRspData;
} SoftBusBleAdvData;

typedef struct {
    int minInterval;
    int maxInterval;
    unsigned char advType;
    unsigned char ownAddrType;
    unsigned char peerAddrType;
    SoftBusBtAddr peerAddr;
    int channelMap;
    unsigned char advFilterPolicy;
    int txPower;
    int duration;
} SoftBusBleAdvParams;

typedef struct {
    void (*AdvEnableCallback)(int advId, int status);
    void (*AdvDisableCallback)(int advId, int status);
    void (*AdvDataCallback)(int advId, int status);
    void (*AdvUpdateCallback)(int advId, int status);
} SoftBusAdvCallback;

int SoftBusAddScanListener(const SoftBusScanListener *listener);

int SoftBusRemoveScanListener(int listenerId);

int SoftBusStartScan(int listnerId, const SoftBusBleScanParams *param);

int SoftBusStopScan(int listenerId);

int SoftBusGetAdvChannel(const SoftBusAdvCallback *callback);

int SoftBusReleaseAdvChannel(int advId);

int SoftBusSetAdvData(int advId, const SoftBusBleAdvData *data);

int SoftBusStartAdv(int advId, const SoftBusBleAdvParams *param);

int SoftBusStopAdv(int advId);

int SoftBusUpdateAdv(int advId, const SoftBusBleAdvData *data, const SoftBusBleAdvParams *param);

#endif