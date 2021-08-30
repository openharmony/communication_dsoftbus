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

#include <arpa/inet.h>
#include <stdbool.h>

#include "nstackx.h"
#include "coap_discover.h"

#define MAX_ADDRESS_LEN 64
#define MAX_MAC_ADDRESS_LENGTH 6
#define MAX_IPV4_ADDRESS_LEN 4

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

typedef struct {
    char name[NSTACKX_MAX_INTERFACE_NAME_LEN];
    char alias[NSTACKX_MAX_INTERFACE_NAME_LEN];
    struct in_addr ip;
} NetworkInterfaceInfo;

typedef struct {
    struct in_addr ip;
    uint8_t state;
    /* AP information? */
} WifiApChannelInfo;

typedef struct {
    WifiApChannelInfo wifiApInfo;
} NetChannelInfo;

typedef struct DeviceInfo {
    char deviceName[NSTACKX_MAX_DEVICE_NAME_LEN];
    char deviceId[NSTACKX_MAX_DEVICE_ID_LEN];
    uint8_t update : 1;
    uint8_t reserved : 7;
    uint8_t deviceType;
    uint16_t portNumber;
    NetChannelInfo netChannelInfo;
    /* Capability data */
    uint32_t capabilityBitmapNum;
    uint32_t capabilityBitmap[NSTACKX_MAX_CAPABILITY_NUM];
    char version[NSTACKX_MAX_HICOM_VERSION];
    uint8_t mode;
    char deviceHash[DEVICE_HASH_LEN];
    char serviceData[NSTACKX_MAX_SERVICE_DATA_LEN];
} DeviceInfo;

int32_t DeviceModuleInit(EpollDesc epollfd);

void DeviceModuleClean(void);
void PushPublishInfo(DeviceInfo *deviceInfo, NSTACKX_DeviceInfo *deviceList, uint32_t deviceNum);

int32_t UpdateDeviceDb(const DeviceInfo *deviceInfo, uint8_t forceUpdate);
uint8_t ClearDevices(void *deviceList);
int32_t BackupDeviceDB(void);
void *GetDeviceDB(void);
void *GetDeviceDBBackup(void);

DeviceInfo *GetDeviceInfoById(const char *deviceId, const void *db);

void GetDeviceList(NSTACKX_DeviceInfo *deviceList, uint32_t *deviceCountPtr, bool doFilter);
void SetModeInfo(uint8_t mode);
uint8_t GetModeInfo(void);
void SetDeviceHash(uint64_t deviceHash);

int32_t ConfigureLocalDeviceInfo(const NSTACKX_LocalDeviceInfo *localDeviceInfo);

const DeviceInfo *GetLocalDeviceInfoPtr(void);
uint8_t IsWifiApConnected(void);
int32_t GetLocalIpString(char *ipString, size_t length);
int32_t GetLocalInterfaceName(char *ifName, size_t ifNameLength);

int32_t RegisterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[]);
int32_t SetFilterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[]);
int32_t RegisterServiceData(const char *serviceData);
void ResetDeviceTaskCount(uint8_t isBusy);
#endif /* #ifndef NSTACKX_DEVICE_H */
