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

#ifndef SOFTBUS_WIFI_API_ADAPTER_H
#define SOFTBUS_WIFI_API_ADAPTER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif
#define WIFI_MAX_SSID_LEN 33
#define WIFI_MAC_LEN 6
#define WIFI_MAX_KEY_LEN 65
#define WIFI_MAX_CONFIG_SIZE 10
#define WIFI_MAX_SCAN_HOTSPOT_LIMIT 128
#define MAX_CALLBACK_NUM 5
#define WIFI_COMMON_MAC_LEN 6
#define WIFI_PASSPHRASE_LENGTH 64
#define WIFI_P2P_NAME_LENGTH 33
#define WIFI_INTERFACE_LENGTH 16
#define WIFI_DEVICE_TYPE_LENGTH 128
#define WIFI_MAX_DEVICES_NUM 256
#define WIFI_IP_ADDR_STR_LEN 16

typedef enum {
    BAND_UNKNOWN,
    BAND_24G,
    BAND_5G,
} SoftBusBand;

typedef struct {
    char ssid[WIFI_MAX_SSID_LEN];
    unsigned char bssid[WIFI_MAC_LEN];
    char preSharedKey[WIFI_MAX_KEY_LEN];
    int32_t securityType;
    int32_t netId;
    int32_t isHiddenSsid;
} SoftBusWifiDevConf;

typedef struct {
    /* call back for scan result */
    void (*onSoftBusWifiScanResult)(int state, int size);
} ISoftBusScanResult;

typedef struct {
    char ssid[WIFI_MAX_SSID_LEN];
    unsigned char bssid[WIFI_MAC_LEN];
    int32_t securityType;
    int32_t rssi;
    int32_t band;
    int32_t frequency;
    int32_t channelWidth;
    int32_t centerFrequency0;
    int32_t centerFrequency1;
    int64_t timestamp;
} SoftBusWifiScanInfo;

typedef enum {
    SOFTBUS_API_WIFI_DISCONNECTED,
    SOFTBUS_API_WIFI_CONNECTED,
} SoftBusWifiConnState;

typedef struct {
    char ssid[WIFI_MAX_SSID_LEN];
    unsigned char bssid[WIFI_MAC_LEN];
    int32_t rssi;
    int32_t band;
    int32_t frequency;
    SoftBusWifiConnState connState;
    unsigned short disconnectedReason;
    unsigned int ipAddress;
} SoftBusWifiLinkedInfo;

typedef enum SoftBusP2pGroupStatus {
    SOFTBUS_API_WIFI_GS_CREATING,
    SOFTBUS_API_WIFI_GS_CREATED,
    SOFTBUS_API_WIFI_GS_STARTED,
    SOFTBUS_API_WIFI_GS_REMOVING,
    SOFTBUS_API_WIFI_GS_INVALID
} SoftBusP2pGroupStatus;

typedef enum SoftBusP2pDeviceStatus {
    SOFTBUS_API_WIFI_PDS_CONNECTED,
    SOFTBUS_API_WIFI_PDS_INVITED,
    SOFTBUS_API_WIFI_PDS_FAILED,
    SOFTBUS_API_WIFI_PDS_AVAILABLE,
    SOFTBUS_API_WIFI_PDS_UNAVAILABLE
} SoftBusP2pDeviceStatus;

typedef enum SoftBusWifiDetailState {
    SOFTBUS_WIFI_STATE_UNKNOWN = -1,
    SOFTBUS_WIFI_STATE_INACTIVE,
    SOFTBUS_WIFI_STATE_ACTIVED,
    SOFTBUS_WIFI_STATE_ACTIVATING,
    SOFTBUS_WIFI_STATE_DEACTIVATING,
    SOFTBUS_WIFI_STATE_SEMIACTIVATING,
    SOFTBUS_WIFI_STATE_SEMIACTIVE,
} SoftBusWifiDetailState;

typedef struct SoftBusWifiP2pWfdInfo {
    int32_t wfdEnabled; /* 0: false, 1: true */
    int32_t deviceInfo;
    int32_t ctrlPort;
    int32_t maxThroughput;
} SoftBusWifiP2pWfdInfo;

typedef struct SoftBusWifiP2pDevice {
    char deviceName[WIFI_P2P_NAME_LENGTH]; /* the value range is 0 to 32 characters. */
    unsigned char devAddr[WIFI_COMMON_MAC_LEN]; /* the device MAC address */
    char primaryDeviceType[WIFI_DEVICE_TYPE_LENGTH];
    char secondaryDeviceType[WIFI_DEVICE_TYPE_LENGTH];
    SoftBusP2pDeviceStatus status;
    SoftBusWifiP2pWfdInfo wfdInfo;
    unsigned int supportWpsConfigMethods;
    int32_t deviceCapabilitys;
    int32_t groupCapabilitys;
} SoftBusWifiP2pDevice;

typedef struct SoftBusWifiP2pGroupInfo {
    char passphrase[WIFI_PASSPHRASE_LENGTH]; /* the value ranges from 8 to 63. */
    char interface[WIFI_INTERFACE_LENGTH];
    char groupName[WIFI_P2P_NAME_LENGTH];
    char goIpAddress[WIFI_IP_ADDR_STR_LEN];
    SoftBusP2pGroupStatus groupStatus;
    int32_t networkId;
    int32_t frequency; /* for example : freq=2412 to select 2.4 GHz channel 1.(Based on 2.4 GHz or 5 GHz) */
    int32_t isP2pPersistent; /* 0: false, 1: true */
    int32_t isP2pGroupOwner; /* 0: false, 1: true */
    int32_t clientDevicesSize; /* the true size of clientDevices array */
    SoftBusWifiP2pDevice clientDevices[WIFI_MAX_DEVICES_NUM];
    SoftBusWifiP2pDevice owner;
} SoftBusWifiP2pGroupInfo;

int32_t SoftBusGetWifiDeviceConfig(SoftBusWifiDevConf *configList, uint32_t *num);
int32_t SoftBusConnectToDevice(const SoftBusWifiDevConf *wifiConfig);
int32_t SoftBusDisconnectDevice(void);
int32_t SoftBusStartWifiScan(void);
int32_t SoftBusRegisterWifiEvent(ISoftBusScanResult *cb);
/* parameter *result is released by the caller. */
int32_t SoftBusGetWifiScanList(SoftBusWifiScanInfo **result, uint32_t *size);
int32_t SoftBusUnRegisterWifiEvent(ISoftBusScanResult *cb);
int32_t SoftBusGetChannelListFor5G(int32_t *channelList, int32_t num);
SoftBusBand SoftBusGetLinkBand(void);
int32_t SoftBusGetLinkedInfo(SoftBusWifiLinkedInfo *info);
int32_t SoftBusGetCurrentGroup(SoftBusWifiP2pGroupInfo *groupInfo);
bool SoftBusHasWifiDirectCapability(void);
bool SoftBusIsWifiTripleMode(void);
char* SoftBusGetWifiInterfaceCoexistCap(void);
bool SoftBusIsWifiActive(void);
bool SoftBusIsHotspotActive(void);
SoftBusWifiDetailState SoftBusGetWifiState(void);
bool SoftBusIsWifiP2pEnabled(void);

#ifdef __cplusplus
}
#endif
#endif // SOFTBUS_WIFI_API_ADAPTER_H
