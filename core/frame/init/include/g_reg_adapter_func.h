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

#ifndef G_REG_ADAPTER_FUNC_H
#define G_REG_ADAPTER_FUNC_H

#include "auth_interface_struct.h"
#include "bus_center_event_struct.h"
#include "link_broadcast_manager_struct.h"
#include "c_header/ohos_bt_gatt.h"
#include "c_header/ohos_bt_def.h"
#include "g_enhance_adapter_func.h"
#include "softbus_adapter_ble_gatt_client_struct.h"
#include "softbus_adapter_ble_gatt_server_struct.h"
#include "softbus_adapter_bt_common_struct.h"
#include "softbus_wifi_api_adapter_struct.h"
#include "softbus_broadcast_adapter_type_struct.h"
#include "softbus_broadcast_adapter_interface_struct.h"
#include "softbus_broadcast_type_struct.h"
#include "softbus_wrapper_br_interface_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef SppSocketDriver *(*InitSppSocketDriverFunc)(void);
typedef int32_t (*SoftbusGattcRegisterFunc)(void);
typedef int32_t (*SoftbusGattcSetFastestConnFunc)(int32_t clientId);
typedef int (*SoftBusGattsDeleteServiceFunc)(int srvcHandle);
typedef int32_t (*SoftbusGattcRegisterCallbackFunc)(SoftBusGattcCallback *cb, int32_t clientId);
typedef void (*SoftBusUnRegisterGattsCallbacksFunc)(SoftBusBtUuid serviceUuid);
typedef int (*SoftBusGattsAddServiceFunc)(SoftBusBtUuid srvcUuid, bool isPrimary, int number);
typedef int (*SoftBusGattsAddCharacteristicFunc)(int srvcHandle, SoftBusBtUuid characUuid, int properties,
    int permissions);
typedef int (*SoftBusGattsAddDescriptorFunc)(int srvcHandle, SoftBusBtUuid descUuid, int permissions);
typedef int (*SoftBusGattsStartServiceFunc)(int srvcHandle);
typedef int (*SoftBusGattsDisconnectFunc)(SoftBusBtAddr btAddr, int connId);
typedef int (*SoftBusGattsStopServiceFunc)(int srvcHandle);
typedef int (*SoftBusGattsSendNotifyFunc)(SoftBusGattsNotify *param);
typedef int (*SoftBusGattsConnectFunc)(SoftBusBtAddr btAddr);
typedef int32_t (*SoftbusGattcUnRegisterFunc)(int32_t clientId);
typedef int32_t (*SoftbusGattcRegisterNotificationFunc)(
    int32_t clientId, SoftBusBtUuid *serverUuid, SoftBusBtUuid *charaUuid, SoftBusBtUuid *descriptorUuid);
typedef int32_t (*SoftbusGattcWriteCharacteristicFunc)(int32_t clientId, SoftBusGattcData *clientData);
typedef int32_t (*SoftbusBleGattcDisconnectFunc)(int32_t clientId, bool refreshGatt);
typedef int32_t (*SoftbusGattcGetServiceFunc)(int32_t clientId, SoftBusBtUuid *serverUuid);
typedef int32_t (*SoftbusGattcSearchServicesFunc)(int32_t clientId);
typedef int32_t (*SoftbusGattcConnectFunc)(int32_t clientId, SoftBusBtAddr *addr);
typedef int (*SoftBusRegisterGattsCallbacksFunc)(SoftBusGattsCallback *callback, SoftBusBtUuid serviceUuid);
typedef int (*SoftBusGattsSendResponseFunc)(SoftBusGattsResponse *param);
typedef void (*RemoveConnIdFunc)(int32_t connId);
typedef int32_t (*SoftbusGattcConfigureMtuSizeFunc)(int32_t clientId, int mtuSize);
typedef int32_t (*ConfigNetLinkUpFunc)(const char *ifName);
typedef int32_t (*ConfigLocalIpFunc)(const char *ifName, const char *localIp);
typedef int32_t (*GetNetworkIpByIfNameFunc)(const char *ifName, char *ip, char *netmask, uint32_t len);
typedef int32_t (*ConfigRouteFunc)(const int32_t id, const char *ifName, const char *destination, const char *gateway);
typedef SoftBusWifiDetailState (*SoftBusGetWifiStateFunc)(void);
typedef int32_t (*AuthStartListeningFunc)(AuthLinkType type, const char *ip, int32_t port);
typedef bool (*SoftBusIsHotspotActiveFunc)(void);
typedef int32_t (*BtStatusToSoftBusFunc)(BtStatus btStatus);
typedef void (*SoftbusAdvParamToBtFunc)(const SoftbusBroadcastParam *src, BleAdvParams *dst);
typedef void (*BtScanResultToSoftbusFunc)(const BtScanResultData *src, SoftBusBcScanResult *dst);
typedef void (*SoftbusFilterToBtFunc)(BleScanNativeFilter *nativeFilter, const SoftBusBcScanFilter *filter,
    uint8_t filterSize);
typedef void (*DumpBleScanFilterFunc)(BleScanNativeFilter *nativeFilter, int32_t filterSize);
typedef int (*GetBtScanModeFunc)(uint16_t scanInterval, uint16_t scanWindow);
typedef uint8_t *(*AssembleAdvDataFunc)(const SoftbusBroadcastData *data, uint16_t *dataLen);
typedef uint8_t *(*AssembleRspDataFunc)(const SoftbusBroadcastPayload *data, uint16_t *dataLen);
typedef int32_t (*ParseScanResultFunc)(const uint8_t *advData, uint8_t advLen, SoftBusBcScanResult *dst);

typedef int32_t (*RegisterBroadcastMediumFunctionFunc)(BroadcastProtocol type,
    const SoftbusBroadcastMediumInterface *interface);
typedef void (*FreeBtFilterFunc)(BleScanNativeFilter *nativeFilter, int32_t filterSize);
typedef void (*SoftbusSetManufactureFilterFunc)(BleScanNativeFilter *nativeFilter, uint8_t filterSize);
typedef int32_t (*SetBroadcastingParamFunc)(int32_t bcId, const BroadcastParam *param);
typedef int32_t (*StartUsbNcmAdapterFunc)(int32_t mode);
typedef int32_t (*ConfigLocalIpv6Func)(const char *ifName, const char *localIpv6);
typedef int (*SoftBusGetBtMacAddrFunc)(SoftBusBtAddr *mac);

typedef struct TagAdapterOpenFuncList {
    InitSppSocketDriverFunc initSppSocketDriver;
    SoftbusGattcRegisterFunc softbusGattcRegister;
    SoftbusGattcSetFastestConnFunc softbusGattcSetFastestConn;
    SoftBusGattsDeleteServiceFunc softBusGattsDeleteService;
    SoftbusGattcRegisterCallbackFunc softbusGattcRegisterCallback;
    SoftBusUnRegisterGattsCallbacksFunc softBusUnRegisterGattsCallbacks;
    SoftBusGattsAddServiceFunc softBusGattsAddService;
    SoftBusGattsAddCharacteristicFunc softBusGattsAddCharacteristic;
    SoftBusGattsAddDescriptorFunc softBusGattsAddDescriptor;
    SoftBusGattsStartServiceFunc softBusGattsStartService;
    SoftBusGattsDisconnectFunc softBusGattsDisconnect;
    SoftBusGattsStopServiceFunc softBusGattsStopService;
    SoftBusGattsSendNotifyFunc softBusGattsSendNotify;
    SoftBusGattsConnectFunc softBusGattsConnect;
    SoftbusGattcUnRegisterFunc softbusGattcUnRegister;
    SoftbusGattcRegisterNotificationFunc softbusGattcRegisterNotification;
    SoftbusGattcWriteCharacteristicFunc softbusGattcWriteCharacteristic;
    SoftbusBleGattcDisconnectFunc softbusBleGattcDisconnect;

    SoftbusGattcGetServiceFunc softbusGattcGetService;
    SoftbusGattcSearchServicesFunc softbusGattcSearchServices;
    SoftbusGattcConnectFunc softbusGattcConnect;
    SoftBusRegisterGattsCallbacksFunc softBusRegisterGattsCallbacks;
    SoftBusGattsSendResponseFunc softBusGattsSendResponse;
    RemoveConnIdFunc removeConnId;
    SoftbusGattcConfigureMtuSizeFunc softbusGattcConfigureMtuSize;
    ConfigNetLinkUpFunc configNetLinkUp;
    ConfigLocalIpFunc configLocalIp;
    GetNetworkIpByIfNameFunc getNetworkIpByIfName;
    ConfigRouteFunc configRoute;

    SoftBusGetWifiStateFunc softBusGetWifiState;
    AuthStartListeningFunc authStartListening;

    SoftBusIsHotspotActiveFunc softBusIsHotspotActive;
    BtStatusToSoftBusFunc btStatusToSoftBus;
    SoftbusAdvParamToBtFunc softbusAdvParamToBt;
    BtScanResultToSoftbusFunc btScanResultToSoftbus;
    SoftbusFilterToBtFunc softbusFilterToBt;
    DumpBleScanFilterFunc dumpBleScanFilter;
    GetBtScanModeFunc getBtScanMode;
    AssembleAdvDataFunc assembleAdvData;
    AssembleRspDataFunc assembleRspData;
    ParseScanResultFunc parseScanResult;

    FreeBtFilterFunc freeBtFilter;
    SoftbusSetManufactureFilterFunc softbusSetManufactureFilter;
    RegisterBroadcastMediumFunctionFunc registerBroadcastMediumFunction;
    SetBroadcastingParamFunc setBroadcastingParam;
    StartUsbNcmAdapterFunc startUsbNcmAdapter;
    ConfigLocalIpv6Func configLocalIpv6;
    SoftBusGetBtMacAddrFunc softBusGetBtMacAddr;
} AdapterOpenFuncList;

#ifdef __cplusplus
}
#endif

#endif