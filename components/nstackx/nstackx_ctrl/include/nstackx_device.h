/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#define REDUNDANCY_NET_CHANNEL_NUM 2
#define NSTACKX_MAX_NET_CHANNEL_NUM (NSTACKX_MAX_LISTENED_NIF_NUM + REDUNDANCY_NET_CHANNEL_NUM)
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
    /* AP information? */
} WifiApChannelInfo;

typedef struct {
    WifiApChannelInfo wifiApInfo;
} NetChannelInfo;

typedef struct BusinessDataAll {
    uint8_t isBroadcast; /* Used only to process received packets */
    char businessDataBroadcast[NSTACKX_MAX_BUSINESS_DATA_LEN];
    char businessDataUnicast[NSTACKX_MAX_BUSINESS_DATA_LEN];
} BusinessDataAll;

typedef struct DeviceRemoteChannelInfo {
    BusinessDataAll businessDataAll;
    NetChannelInfo remoteChannelInfo;
    struct timespec lastRecvTime;
    UpdateState updateState;
} DeviceRemoteChannelInfo;

typedef struct LocalIfInfoAll {
    NSTACKX_InterfaceInfo localIfInfo;
    DeviceRemoteChannelInfo deviceRemoteChannelInfo[NSTACKX_MAX_NET_CHANNEL_NUM];
    uint8_t nextRemoteIdx;
} LocalIfInfoAll;

typedef struct DeviceInfo {
    char deviceName[NSTACKX_MAX_DEVICE_NAME_LEN];
    char deviceId[NSTACKX_MAX_DEVICE_ID_LEN];
#ifdef DFINDER_SAVE_DEVICE_LIST
    uint8_t update : 1;
    uint8_t reserved : 7;
#ifndef DFINDER_SUPPORT_MULTI_NIF
    UpdateState updateState;
#endif
#endif
    uint8_t deviceType;
    uint16_t portNumber;
#ifdef DFINDER_SUPPORT_MULTI_NIF
    LocalIfInfoAll localIfInfoAll[NSTACKX_MAX_LISTENED_NIF_NUM];
    uint8_t ifState[NSTACKX_MAX_LISTENED_NIF_NUM];
    uint8_t ifNums;
    uint8_t nextNifIdx;
#endif
    NetChannelInfo netChannelInfo;
    /* Capability data */
    uint32_t capabilityBitmapNum;
    uint32_t capabilityBitmap[NSTACKX_MAX_CAPABILITY_NUM];
    char version[NSTACKX_MAX_HICOM_VERSION];
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
} DeviceInfo;

int32_t DeviceModuleInit(EpollDesc epollfd, uint32_t maxDeviceNum);
#ifndef DFINDER_USE_MINI_NSTACKX
int32_t P2pUsbTimerInit(EpollDesc epollfd);
void DestroyP2pUsbServerInitRetryTimer(void);
#endif /* END OF DFINDER_USE_MINI_NSTACKX */
void DeviceModuleClean(void);
void PushPublishInfo(DeviceInfo *deviceInfo, NSTACKX_DeviceInfo *deviceList, uint32_t deviceNum);

#ifdef DFINDER_SUPPORT_MULTI_NIF
int32_t UpdateDeviceDbWithIdx(const DeviceInfo *deviceInfo, uint8_t forceUpdate, uint8_t idx);
#endif

#ifdef DFINDER_SAVE_DEVICE_LIST
int32_t UpdateDeviceDb(const DeviceInfo *deviceInfo, uint8_t forceUpdate);
uint8_t ClearDevices(void *deviceList);
int32_t BackupDeviceDB(void);
void *GetDeviceDB(void);
void *GetDeviceDBBackup(void);
DeviceInfo *GetDeviceInfoById(const char *deviceId, const void *db);
void GetDeviceListWrapper(NSTACKX_DeviceInfo *deviceList, uint32_t *deviceCountPtr, bool doFilter);
#else
int32_t DeviceInfoNotify(const DeviceInfo *deviceInfo, uint8_t forceUpdate);
#endif

void SetModeInfo(uint8_t mode);
uint8_t GetModeInfo(void);
void SetDeviceHash(uint64_t deviceHash);

int32_t ConfigureLocalDeviceInfo(const NSTACKX_LocalDeviceInfo *localDeviceInfo);
void ConfigureLocalDeviceName(const char *localDeviceName);
void ConfigureDiscoverySettings(const NSTACKX_DiscoverySettings *discoverySettings);

#ifdef DFINDER_SUPPORT_MULTI_NIF
int32_t UpdateLocalNetworkInterface(void);
#else
int32_t UpdateLocalNetworkInterface(const NetworkInterfaceInfo *interfaceInfo);
#endif

#ifndef DFINDER_USE_MINI_NSTACKX
void UpdateAllNetworkInterfaceNameIfNeed(const NetworkInterfaceInfo *interfaceInfo);
int32_t UpdateLocalNetworkInterfaceP2pMode(const NetworkInterfaceInfo *interfaceInfo, uint16_t nlmsgType);
int32_t UpdateLocalNetworkInterfaceUsbMode(const NetworkInterfaceInfo *interfaceInfo, uint16_t nlmsgType);
uint8_t FilterNetworkInterface(const char *ifName);
#ifdef _WIN32
uint8_t IsWlanIpAddr(const struct in_addr *ifAddr);
uint8_t IsEthIpAddr(const struct in_addr *ifAddr);
uint8_t IsP2pIpAddr(const struct in_addr *ifAddr);
uint8_t IsUsbIpAddr(const struct in_addr *ifAddr);
#else
uint8_t IsWlanIpAddr(const char *ifName);
uint8_t IsEthIpAddr(const char *ifName);
uint8_t IsP2pIpAddr(const char *ifName);
uint8_t IsUsbIpAddr(const char *ifName);
#endif
#endif /* END OF DFINDER_USE_MINI_NSTACKX */

const DeviceInfo *GetLocalDeviceInfoPtr(void);

#ifdef DFINDER_SUPPORT_MULTI_NIF
uint8_t IsApConnected(void);
uint8_t IsApConnectedWithIdx(uint32_t idx);
char *GetLocalNifNameWithIdx(uint32_t idx);
#else
uint8_t IsWifiApConnected(void);
#endif

#ifdef DFINDER_SUPPORT_MULTI_NIF
int32_t GetLocalIpStringWithIdx(char *ipString, size_t length, uint32_t idx);
int32_t GetLocalInterfaceNameWithIdx(char *ifName, size_t ifNameLen, uint32_t idx);
#endif

int32_t GetLocalIpString(char *ipString, size_t length);
int32_t GetLocalInterfaceName(char *ifName, size_t ifNameLength);
int32_t GetNetworkName(char *name, int32_t len);

int32_t RegisterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[]);
int32_t SetFilterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[]);
int32_t RegisterServiceData(const char *serviceData);
void ResetDeviceTaskCount(uint8_t isBusy);
void GetLocalIp(struct in_addr *ip);
#ifndef DFINDER_USE_MINI_NSTACKX
int32_t RegisterExtendServiceData(const char *extendServiceData);
void GetLocalNetworkInterface(void *arg);
void SetP2pIp(const struct in_addr *ip);
void SetUsbIp(const struct in_addr *ip);
int32_t GetP2pIpString(char *ipString, size_t length);
int32_t GetUsbIpString(char *ipString, size_t length);
#endif /* END OF DFINDER_USE_MINI_NSTACKX */
int32_t SetLocalDeviceBusinessDataUnicast(const char* businessData, uint32_t length);
#endif /* #ifndef NSTACKX_DEVICE_H */
