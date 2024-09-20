/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef NSTACKX_DEVICE_H
#define NSTACKX_DEVICE_H

#ifndef _WIN32
#include <arpa/inet.h>
#endif
#include <stdbool.h>

#include "nstackx.h"
#include "coap_discover.h"
#include "coap_app.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    IFACE_TYPE_ETH,
    IFACE_TYPE_WLAN,
    IFACE_TYPE_P2P,
    IFACE_TYPE_USB,
    IFACE_TYPE_UNKNOWN,
    IFACE_TYPE_MAX,
};

#define MAX_ADDRESS_LEN 64
#define MAX_MAC_ADDRESS_LENGTH 6
#define MAX_IPV4_ADDRESS_LEN 4
#define INTERFACE_NAME_POSSIBLE 3

/*
 * 1st discover interval: 100ms
 * 2nd ~ 3rd discover interval: 200ms
 * Remaining discover interval (9 times): 500ms
 */
#define COAP_DEFAULT_DISCOVER_COUNT 12
#define COAP_FIRST_DISCOVER_COUNT_RANGE 1
#define COAP_SECOND_DISCOVER_COUNT_RANGE 3
#define COAP_FIRST_DISCOVER_INTERVAL 100
#define COAP_SECOND_DISCOVER_INTERVAL 200
#define COAP_LAST_DISCOVER_INTERVAL 500

enum DeviceState {
    IDEL,
    ACTIVE,
    LEAVE
};

typedef enum {
    NSTACKX_EVENT_JOIN,
    NSTACKX_EVENT_UPDATE,
    NSTACKX_EVENT_LEAVE,
} NSTACKX_Event;

enum NetChannelState {
    NET_CHANNEL_STATE_START,
    NET_CHANNEL_STATE_DISABLED,
    NET_CHANNEL_STATE_DISCONNECT,
    NET_CHANNEL_STATE_CONNETING,
    NET_CHANNEL_STATE_CONNETED,
    NET_CHANNEL_STATE_END,
};

typedef enum  {
    DFINDER_UPDATE_STATE_NULL,
    DFINDER_UPDATE_STATE_BROADCAST,
    DFINDER_UPDATE_STATE_UNICAST,
    DFINDER_UPDATE_STATE_ALL,
    DFINDER_UPDATE_STATE_END,
} UpdateState;

typedef struct {
    char name[NSTACKX_MAX_INTERFACE_NAME_LEN];
    char alias[NSTACKX_MAX_INTERFACE_NAME_LEN];
    struct in_addr ip;
} NetworkInterfaceInfo;

typedef struct {
    char name[INTERFACE_NAME_POSSIBLE][NSTACKX_MAX_INTERFACE_NAME_LEN];
} NetworkInterfacePrefiexPossible;

typedef struct {
    struct in_addr ip;
    uint8_t state;
} WifiApChannelInfo;

typedef struct {
    WifiApChannelInfo wifiApInfo;
} NetChannelInfo;

typedef struct BusinessDataAll {
    uint8_t isBroadcast; /* Used only to process received packets */
    char businessDataBroadcast[NSTACKX_MAX_BUSINESS_DATA_LEN];
    char businessDataUnicast[NSTACKX_MAX_BUSINESS_DATA_LEN];
} BusinessDataAll;

typedef struct SeqAll {
    uint8_t dealBcast;
    uint16_t seqBcast;
    uint16_t seqUcast;
} SeqAll;

typedef struct DeviceInfo {
    char deviceId[NSTACKX_MAX_DEVICE_ID_LEN];
    char deviceName[NSTACKX_MAX_DEVICE_NAME_LEN];
#ifdef DFINDER_SAVE_DEVICE_LIST
    int8_t update : 1;
    uint8_t reserved : 7;
#endif
    uint32_t deviceType;
    NetChannelInfo netChannelInfo;
    /* Capability data */
    uint32_t capabilityBitmapNum;
    uint32_t capabilityBitmap[NSTACKX_MAX_CAPABILITY_NUM];
    uint8_t mode;
    uint8_t discoveryType;
    char deviceHash[DEVICE_HASH_LEN];
    char serviceData[NSTACKX_MAX_SERVICE_DATA_LEN];
    uint8_t businessType;
    BusinessDataAll businessData;
#ifndef DFINDER_USE_MINI_NSTACKX
    char extendServiceData[NSTACKX_MAX_EXTEND_SERVICE_DATA_LEN];
#endif
    char networkName[NSTACKX_MAX_INTERFACE_NAME_LEN];
    SeqAll seq;
    char notification[NSTACKX_MAX_NOTIFICATION_DATA_LEN];
} DeviceInfo;

int32_t DeviceModuleInit(EpollDesc epollfd, uint32_t maxDeviceNum);
void DeviceModuleClean(void);

#ifdef DFINDER_SAVE_DEVICE_LIST
int32_t UpdateDeviceDb(const CoapCtxType *coapCtx, const DeviceInfo *deviceInfo, uint8_t forceUpdate,
    uint8_t receiveBcast);
#endif

int32_t DeviceInfoNotify(const DeviceInfo *deviceInfo);
int32_t ReportDiscoveredDevice(const CoapCtxType *coapCtx, const DeviceInfo *deviceInfo,
    uint8_t forceUpdate, uint8_t receiveBcast);

void SetModeInfo(uint8_t mode);
uint8_t GetModeInfo(void);

uint32_t GetNotifyTimeoutMs(void);

int32_t ConfigureDiscoverySettings(const NSTACKX_DiscoverySettings *discoverySettings);
int32_t DiscConfigInner(const DFinderDiscConfig *discConfig);

#ifndef DFINDER_USE_MINI_NSTACKX
void UpdateAllNetworkInterfaceNameIfNeed(const NetworkInterfaceInfo *interfaceInfo);
#endif /* END OF DFINDER_USE_MINI_NSTACKX */

void SetMaxDeviceNum(uint32_t maxDeviceNum);
uint32_t GetMaxDeviceNum(void);
uint32_t *GetFilterCapability(uint32_t *capabilityBitmapNum);
void IncreaseSequenceNumber(uint8_t sendBcast);
uint16_t GetSequenceNumber(uint8_t sendBcast);
void ResetSequenceNumber(void);

int32_t RegisterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[]);
int32_t SetFilterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[]);
bool MatchDeviceFilter(const DeviceInfo *deviceInfo);
int32_t RegisterServiceData(const char *serviceData);
void ResetDeviceTaskCount(uint8_t isBusy);

uint8_t GetIfaceType(const char *ifname);
int32_t SetReservedInfoFromDeviceInfo(NSTACKX_DeviceInfo *deviceList, const DeviceInfo *deviceInfo);
int32_t GetNotifyDeviceInfo(NSTACKX_DeviceInfo *notifyDevice, const DeviceInfo *deviceInfo);

#ifdef __cplusplus
}
#endif

#endif /* #ifndef NSTACKX_DEVICE_H */
