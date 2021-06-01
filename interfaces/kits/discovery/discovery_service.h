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

#ifndef DISCOVERY_SERVICE_H
#define DISCOVERY_SERVICE_H

#include <stdbool.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/**
 * @brief Indicates the maximum length of the capability data in <b>PublishInfo</b> and <b>SubscribeInfo</b>.
 *
 */
#define MAX_CAPABILITYDATA_LEN 513

/**
 * @brief Indicates the maximum length of the device ID in <b>IDiscoveryCallback</b>.
 *
 */
#define DISC_MAX_DEVICE_ID_LEN 96

/**
 * @brief Indicates the maximum length of the account hash code in <b>IDiscoveryCallback</b>.
 *
 */
#define DISC_MAX_ACCOUNT_HASH_LEN 96

/**
 * @brief Indicates the maximum length of the device name in <b>IDiscoveryCallback</b>.
 *
 */
#define DISC_MAX_DEVICE_NAME_LEN 65

/**
 * @brief Indicates the maximum length of the custom data in <b>IDiscoveryCallback</b>.
 *
 */
#define DISC_MAX_CUST_DATA_LEN 219

/**
 * @brief Indicates the maximum number of capabilities contained in the bitmap in <b>IDiscoveryCallback</b>.
 *
 */
#define DISC_MAX_CAPABILITY_NUM 2

/**
 * @brief Indicates the maximum length of the device address in <b>IDiscoveryCallback</b>.
 *
 */
#define CONNECT_ADDR_LEN 46

/**
 * @brief Enumerates the modes in which services are published.
 *
 */
typedef enum  {
    /* Passive */
    DISCOVER_MODE_PASSIVE = 0x55,
    /* Proactive */
    DISCOVER_MODE_ACTIVE  = 0xAA
} DiscoverMode;

/**
 * @brief Enumerates media, such as Bluetooth, Wi-Fi, and USB, used for publishing services.
 *
 * Currently, only <b>COAP</b> is supported.
 * When <b>AUTO</b> is selected, all the supported media will be called automatically.
 */
typedef enum {
    /** Automatic medium selection */
    AUTO = 0,
    /** Bluetooth */
    BLE = 1,
    /** Wi-Fi */
    COAP = 2,
    /** USB */
    USB = 3,
    MEDIUM_BUTT
} ExchanageMedium;

/**
 * @brief Enumerates frequencies for publishing services.
 *
 * This enumeration applies only to Bluetooth and is not supported currently.
 */
typedef enum {
    /** Low */
    LOW = 0,
    /** Medium */
    MID = 1,
    /** High */
    HIGH = 2,
    /** Super-high */
    SUPER_HIGH = 3,
    FREQ_BUTT
} ExchangeFreq;

/**
 * @brief Defines service publishing information.
 *
 */
typedef struct {
    /** Service ID */
    int publishId;
    /** Discovery mode for service publishing. For details, see {@link Discovermode}. */
    DiscoverMode mode;
    /** Service publishing medium. For details, see {@link ExchanageMedium}. */
    ExchanageMedium medium;
    /** Service publishing frequency. For details, see {@link ExchangeFre}. */
    ExchangeFreq freq;
    /** Service publishing capabilities. For details, see {@link g_capabilityMap}. */
    const char *capability;
    /** Capability data for service publishing */
    unsigned char *capabilityData;
    /** Maximum length of the capability data for service publishing (512 bytes) */
    unsigned int dataLen;
} PublishInfo;

/**
 * @brief Enumerates error codes for service publishing failures.
 *
 * The error codes are returned to the caller through <b>IPublishCallback</b>.
 *
 */
typedef enum {
    /* Unsupported medium */
    PUBLISH_FAIL_REASON_NOT_SUPPORT_MEDIUM = 1,
    /* internal error */
    PUBLISH_FAIL_REASON_INTERNAL = 2,
    /* Unknown reason */
    PUBLISH_FAIL_REASON_UNKNOWN = 0xFF
} PublishFailReason;

/**
 * @brief Defines the callbacks for successful and failed service publishing.
 *
 */
typedef struct {
    /** Callback for successful publishing */
    void (*OnPublishSuccess)(int publishId);
    /** Callback for failed publishing */
    void (*OnPublishFail)(int publishId, PublishFailReason reason);
} IPublishCallback;

/**
 * @brief Enumerates supported capabilities published by a device.
 *
 */
typedef enum {
    /** MeeTime */
    HICALL_CAPABILITY_BITMAP = 0,
    /** Video reverse connection in the smart domain */
    PROFILE_CAPABILITY_BITMAP = 1,
    /** Gallery in Vision */
    HOMEVISIONPIC_CAPABILITY_BITMAP = 2,
    /** cast+ */
    CASTPLUS_CAPABILITY_BITMAP,
    /** Input method in Vision */
    AA_CAPABILITY_BITMAP,
    /** Device virtualization tool package */
    DVKIT_CAPABILITY_BITMAP,
    /** Distributed middleware */
    DDMP_CAPABILITY_BITMAP
} DataBitMap;

/**
 * @brief Defines the mapping between supported capabilities and bitmaps.
 *
 */
typedef struct {
    /** Bitmaps. For details, see {@link DataBitMap}. */
    DataBitMap bitmap;
    /** Capability. For details, see {@link g_capabilityMap}. */
    char *capability;
} CapabilityMap;

/**
 * @brief Defines the mapping between supported capabilities and bitmaps.
 *
 */
static const CapabilityMap g_capabilityMap[] = {
    {HICALL_CAPABILITY_BITMAP, (char *)"hicall"},
    {PROFILE_CAPABILITY_BITMAP, (char *)"profile"},
    {HOMEVISIONPIC_CAPABILITY_BITMAP, (char *)"homevisionPic"},
    {CASTPLUS_CAPABILITY_BITMAP, (char *)"castPlus"},
    {AA_CAPABILITY_BITMAP, (char *)"aaCapability"},
    {DVKIT_CAPABILITY_BITMAP, (char *)"dvKit"},
    {DDMP_CAPABILITY_BITMAP, (char *)"ddmpCapability"},
};

/**
 * @brief Defines service subscription information.
 *
 */
typedef struct {
    /** Service ID */
    int subscribeId;
    /** Discovery mode for service subscription. For details, see {@link Discovermode}. */
    DiscoverMode mode;
    /** Service subscription medium. For details, see {@link ExchanageMedium}. */
    ExchanageMedium medium;
    /** Service subscription frequency. For details, see {@link ExchangeFre}. */
    ExchangeFreq freq;
    /** only find the device with the same account */
    bool isSameAccount;
    /** find the sleeping devices */
    bool isWakeRemote;
    /** Service subscription capability. For details, see {@link g_capabilityMap}. */
    const char *capability;
    /** Capability data for service subscription */
    unsigned char *capabilityData;
    /** Maximum length of the capability data for service subscription (512 bytes) */
    unsigned int dataLen;
} SubscribeInfo;

/**
 * @brief Enumerates error codes for service subscription failures.
 *
 * The error codes are returned to the caller through <b>IDiscoveryCallback</b>.
 *
 */
typedef enum {
    /* Unsupported medium */
    DISCOVERY_FAIL_REASON_NOT_SUPPORT_MEDIUM = 1,
    /* internal error */
    DISCOVERY_FAIL_REASON_INTERNAL = 2,
    /* Unknown error */
    DISCOVERY_FAIL_REASON_UNKNOWN = 0xFF
} DiscoveryFailReason;

/**
 * @brief Enumerates device types.
 *
 */
typedef enum {
    /* Smart speaker */
    SMART_SPEAKER = 0x00,
    /* PC */
    DESKTOP_PC,
    /* Laptop */
    LAPTOP,
    /* Mobile phone */
    SMART_PHONE,
    /* Tablet */
    SMART_PAD,
    /* Smart watch */
    SMART_WATCH,
    /* Smart car */
    SMART_CAR,
    /* Kids' watch */
    CHILDREN_WATCH,
    /* Smart TV */
    SMART_TV,
} DeviceType;

/**
 * @brief Enumerates connection types returned by <b>IDiscoveryCallback</b>.
 *
 */
typedef enum {
    /** WLAN */
    CONNECT_ADDR_WLAN = 1,
    /** BR */
    CONNECT_ADDR_BR,
    /** BLE */
    CONNECT_ADDR_BLE,
    /** MAX */
    CONNECT_ADDR_TYPE_MAX
} ConnectAddrType;

/**
 * @brief Defines connection information.
 *
 */
typedef struct  {
    /** Connection type. For details, see {@link ConnectAddrType}. */
    ConnectAddrType type;
    /** Connection address. For its length, see {@link CONNECT_ADDR_LEN}. */
    char addr[CONNECT_ADDR_LEN];
    /** Port number */
    int port;
} ConnectAddr;

/**
 * @brief Defines the device information returned by <b>IDiscoveryCallback</b>.
 *
 */
typedef struct {
    /** Device ID. Its maximum length is specified by {@link DISC_MAX_DEVICE_ID_LEN}. */
    char devId[DISC_MAX_DEVICE_ID_LEN];
    /** Account hash code. Its maximum length is specified by {@link DISC_MAX_ACCOUNT_HASH_LEN}. */
    char hwAccountHash[DISC_MAX_ACCOUNT_HASH_LEN];
    /** Device type. For details, see {@link DeviceType}. */
    DeviceType devType;
    /** Device name. Its maximum length is specified by {@link DISC_MAX_DEVICE_NAME_LEN}. */
    char devName[DISC_MAX_DEVICE_NAME_LEN];
    /** Number of available connections */
    unsigned int addrNum;
    /** Connection information. For details, see {@link ConnectAddr}. */
    ConnectAddr addr[CONNECT_ADDR_TYPE_MAX];
    /** Number of capabilities */
    unsigned int capabilityBitmapNum;
    /** Device capability bitmap.
     * The maximum number of capabilities in the bitmap is specified by {@link DISC_MAX_CAPABILITY_NUM}.
     */
    unsigned int capabilityBitmap[DISC_MAX_CAPABILITY_NUM];
    /** Custom data. Its length is specified by {@link DISC_MAX_CUST_DATA_LEN}. */
    char custData[DISC_MAX_CUST_DATA_LEN];
} DeviceInfo;

/**
 * @brief Defines a callback for service subscription.
 *
 * Three types of callbacks are available.
 *
 */
typedef struct {
    /** Callback that is invoked when a device is found */
    void (*OnDeviceFound)(const DeviceInfo *device);
    /** Callback for a subscription failure */
    void (*OnDiscoverFailed)(int subscribeId, DiscoveryFailReason failReason);
    /** Callback for a subscription success */
    void (*OnDiscoverySuccess)(int subscribeId);
} IDiscoveryCallback;

/**
 * @brief Publishes a specified service.
 *
 * Peer devices in the same LAN as the device that publishes this service can discover this service as needed.
 * The service is identified by <b>publicId</b> and <b>pkgName</b>.
 *
 * @param pkgName Indicates the pointer to the service package name, which can contain a maximum of 64 bytes.
 * @param info Indicates the pointer to the service publishing information. For details, see {@link PublishInfo}.
 * @param cb Indicates the pointer to the service publishing callback {@link IPublishCallback}.
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if any parameter is null or invalid.
 * @return Returns <b>SOFTBUS_DISCOVER_NOT_INIT</b> if the Intelligent Soft Bus client fails to be initialized.
 * @return Returns <b>SOFTBUS_LOCK_ERR</b> if the mutex fails to be locked.
 * @return Returns <b>SOFTBUS_OK</b> if the service is successfully published.
 */
int PublishService(const char *pkgName, const PublishInfo *info, const IPublishCallback *cb);

/**
 * @brief Unpublishes a specified service.
 *
 * @param pkgName Indicates the pointer to the service package name, which can contain a maximum of 64 bytes.
 * @param publishId Indicates the service ID.
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if <b>pkgName</b> is invalid.
 * @return Returns <b>SOFTBUS_DISCOVER_NOT_INIT</b> if the Intelligent Soft Bus client fails to be initialized.
 * @return Returns <b>SOFTBUS_OK</b> if the service is successfully unpublished.
 */
int UnPublishService(const char *pkgName, int publishId);

/**
 * @brief Subscribes to a specified service.
 *
 * Information about the device that publishes the service will be reported to the device that subscribes to
 * the service.
 * The service is identified by <b>subscribeId</b> and <b>pkgName</b>.
 *
 * @param pkgName Indicates the pointer to the service package name, which can contain a maximum of 64 bytes.
 * @param info Indicates the pointer to the service subscription information. For details, see {@link SubscribeInfo}.
 * @param cb Indicates the service subscription callback {@link IDiscoveryCallback}.
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if any parameter is null or invalid.
 * @return Returns <b>SOFTBUS_DISCOVER_NOT_INIT</b> if the Intelligent Soft Bus client fails to be initialized.
 * @return Returns <b>SOFTBUS_LOCK_ERR</b> if the mutex fails to be locked.
 * @return Returns <b>SOFTBUS_OK</b> if the service subscription is successful.
 */
int StartDiscovery(const char *pkgName, const SubscribeInfo *info, const IDiscoveryCallback *cb);

/**
 * @brief Unsubscribes from a specified service.
 *
 * @param pkgName Indicates the pointer to the service package name, which can contain a maximum of 64 bytes.
 * @param subscribeId Indicates the service ID.
 * @return Returns <b>SOFTBUS_INVALID_PARAM</b> if <b>pkgName</b> is invalid.
 * @return Returns <b>SOFTBUS_DISCOVER_NOT_INIT</b> if the Intelligent Soft Bus client fails to be initialized.
 * @return Returns <b>SOFTBUS_OK</b> if the service unsubscription is successful.
 */
int StopDiscovery(const char *pkgName, int subscribeId);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* DISCOVERY_SERVICE_H */
