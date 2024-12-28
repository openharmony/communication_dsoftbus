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

/**
 * @addtogroup SoftBus
 * @{
 *
 * @brief Provides high-speed, secure communication between devices.
 *
 * This module implements unified distributed communication capability management between nearby devices, and provides
 * link-independent device discovery and transmission interfaces to support service publishing and data transmission.
 *
 * @since 1.0
 * @version 1.0
 */
/** @} */

/**
 * @file softbus_common.h
 *
 * @brief Declares common APIs for the Intelligent Soft Bus.
 *
 * This file provides common functions and constants for each submodule of the Intelligent Soft Bus, including: \n
 *
 * <ul>
 * <li>Constants such as the network ID length</li>
 * <li>Functions such as that for initializing the Intelligent Soft Bus client</li>
 * </ul>
 *
 * @since 1.0
 * @version 1.0
 */

#ifndef SOFTBUS_CLIENT_COMMON_H
#define SOFTBUS_CLIENT_COMMON_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Permission of softbus component
 *
 * @since 3.0
 * @version 3.0
*/
#define OHOS_PERMISSION_DISTRIBUTED_DATASYNC "ohos.permission.DISTRIBUTED_DATASYNC"
#define OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER "ohos.permission.DISTRIBUTED_SOFTBUS_CENTER"

/**
 * @brief Indicates the length of the Bluetooth device MAC address in string format,
 * including the terminating null character <b>\0</b>.
 *
 * @since 1.0
 * @version 1.0
 */
#define BT_MAC_LEN 18

/**
 * @brief Indicates the length of the network ID string, including the terminating null character <b>\0</b>.
 *
 * @since 1.0
 * @version 1.0
 */
#define NETWORK_ID_BUF_LEN 65

/**
 * @brief Indicates the length of the UDID string, including the terminating null character <b>\0</b>.
 *
 * @since 1.0
 * @version 1.0
 */
#define UDID_BUF_LEN 65

/**
 * @brief Indicates the length of the UDID hash value.
 *
 * @since 1.0
 * @version 1.0
 */
#define UDID_HASH_LEN 32

/**
 * @brief Indicates the length of the UUID string, including the terminating null character <b>\0</b>.
 *
 * @since 1.0
 * @version 1.0
 */
#define UUID_BUF_LEN 65

/**
 * @brief Indicates the maximum length of an IP address in string format,
 * including the terminating null character <b>\0</b>. IPv6 addresses are supported.
 *
 * @since 1.0
 * @version 1.0
 */
#define IP_STR_MAX_LEN 46

/**
 * @brief Indicates the maximum length of the account hash code in <b>IDiscoveryCallback</b>.
 *
 */
#define MAX_ACCOUNT_HASH_LEN 96

/**
 * @brief Indicates the maximum length of the hash code in HEX calculated by SHA-256.
 *
 */
#define SHA_256_HASH_LEN 32

/**
 * @brief Indicates the maximum length of the hash code in string format calculated by SHA-256,
 * including the terminating null character <b>\0</b>.
 *
 */
#define SHA_256_HEX_HASH_LEN 65

/**
 * @brief Indicates the maximum length of the capability data in <b>PublishInfo</b> and <b>SubscribeInfo</b>.
 *
 */
#define MAX_CAPABILITYDATA_LEN 513

/**
 * @brief Indicates the maximum length of the custom data in <b>IDiscoveryCallback</b>.
 *
 */
#define DISC_MAX_CUST_DATA_LEN 513

/**
 * @brief Indicates the maximum number of capabilities contained in the bitmap in <b>IDiscoveryCallback</b>.
 *
 */
#define DISC_MAX_CAPABILITY_NUM 2

/**
 * @brief Indicates the maximum length of the device name in <b>IDiscoveryCallback</b>.
 *
 */
#define DISC_MAX_DEVICE_NAME_LEN 65

/**
 * @brief Indicates the maximum length of the device ID in <b>IDiscoveryCallback</b>.
 *
 */
#define DISC_MAX_DEVICE_ID_LEN 96

/**
 * @brief Indicates the maximum length of the network commmon length <b>IDiscoveryCallback</b>.
 *
 */
#define LNN_COMMON_LEN 4

/**
 * @brief Indicates the short hash length of the networkId.
 *
 */
#define NODEID_SHORT_HASH_LEN 6

/**
 * @brief Indicates the short hash length of the udid.
 *
 */
#define UDID_SHORT_HASH_LEN 6

/**
 * @brief Indicates the maximum length of the device database status in <b>INodeStateCb</b>.
 *
 */
#define DATA_CHANGE_FLAG_BUF_LEN 2

/**
 * @brief Indicates the maximum length of the database dynamic level in <b>IDataLevelCb</b>.
 *
 */
#define DATA_DYNAMIC_LEVEL_BUF_LEN 2

/**
 * @brief Indicates the maximum length of the database static level in <b>IDataLevelCb</b>.
 *
 */
#define DATA_STATIC_LEVEL_BUF_LEN 2

/**
 * @brief Indicates the maximum length of the database switch level in <b>IDataLevelCb</b>.
 *
 */
#define DATA_SWITCH_LEVEL_BUF_LEN 4

/**
 * @brief Device screen on/off bool data.
 *
 */
#define DATA_DEVICE_SCREEN_STATUS_LEN 1

/**
 * @brief Indicates the maximum length of the database switch length in <b>IDataLevelCb</b>.
 *
 */
#define DATA_SWITCH_LENGTH_BUF_LEN 2

/**
 * @brief Indicates the maximum length of the node address.
 *
 */
#define SHORT_ADDRESS_MAX_LEN 20

/**
 * @brief Indicates the maximum num of the node status.
 *
 */
#define NODE_STATUS_MAX_NUM 32

/**
 * @brief Indicates the maximum num of the device type size.
 *
 */
#define DEVICE_TYPE_MAX_SIZE 3

/**
 * @brief Indicates the length of the node screen status.
 *
 */
#define NODE_SCREEN_STATUS_LEN 1

/**
 * @brief Enumerates {@link ConnectionAddrType} types of a device that is added to a LNN.
 *
 * @since 1.0
 * @version 1.0
 */
typedef enum {
    CONNECTION_ADDR_WLAN = 0, /**< WLAN */
    CONNECTION_ADDR_BR,       /**< BR */
    CONNECTION_ADDR_BLE,      /**< BLE */
    CONNECTION_ADDR_ETH,      /**< Ethernet */
    CONNECTION_ADDR_SESSION,  /**< SESSION */
    CONNECTION_ADDR_USB,      /**< USB */
    CONNECTION_ADDR_MAX       /**< Invalid type */
} ConnectionAddrType;

/**
 * @brief Enumerates {@link BleProtocolType} types of ble connection type
 *
 */
typedef enum  {
    BLE_PROTOCOL_ANY = -1,
    BLE_GATT = 0,
    BLE_COC,
    BLE_PROTOCOL_MAX
} BleProtocolType;

/**
 * @brief Defines the address of a device that is added to a LNN.
 * For details, see {@link ConnectionAddr}.
 *
 * @since 1.0
 * @version 1.0
 */
typedef struct {
    /**< Address type. This field is used to explain the <b>info</b> field. */
    ConnectionAddrType type;
    /**< Connection address information */
    union {
        /**< BR address */
        struct BrAddr {
            char brMac[BT_MAC_LEN];   /**< BR MAC address in string format */
        } br;
        /**< BLE address */
        struct BleAddr {
            BleProtocolType protocol;
            char bleMac[BT_MAC_LEN];  /**< BLE MAC address in string format */
            uint8_t udidHash[UDID_HASH_LEN];  /**< udid hash value */
            uint32_t psm;
        } ble;
        /**< IPv4 or IPv6 address */
        struct IpAddr {
            /**
             * IP address in string format. It can be an IPv4 address written in dotted decimal notation
             * or an IPv6 address written in hexadecimal colon-separated notation.
             */
            char ip[IP_STR_MAX_LEN];
            uint16_t port;            /**< Port number represented by the host byte order */
            uint8_t udidHash[UDID_HASH_LEN]; /**< udid hash value */
        } ip;
        /**< Session address */
        struct SessionAddr {
            int32_t sessionId;  /**< Session Id in int format */
            int32_t channelId;  /**< Channel Id in int format */
            int32_t type;   /**< Session type in int format */
        } session;
    } info;
    char peerUid[MAX_ACCOUNT_HASH_LEN];
} ConnectionAddr;

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
    /** HiLink */
    COAP1 = 4,
    MEDIUM_BUTT
} ExchangeMedium;

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
    /** Extreme-high */
    EXTREME_HIGH = 4,
    FREQ_BUTT
} ExchangeFreq;

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
    DDMP_CAPABILITY_BITMAP,
    /** Osd capability */
    OSD_CAPABILITY_BITMAP,
    /**Share capability */
    SHARE_CAPABILITY_BITMAP,
    /**Approach capability */
    APPROACH_CAPABILITY_BITMAP,
    /**virtual link capability */
    VLINK_CAPABILITY_BITMAP,
    /**Touch capability */
    TOUCH_CAPABILITY_BITMAP
} DataBitMap;

typedef struct {
    int64_t authId;
    uint32_t type;
} AuthHandle;

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
    {OSD_CAPABILITY_BITMAP, (char *)"osdCapability"},
    {SHARE_CAPABILITY_BITMAP, (char *)"share"},
    {APPROACH_CAPABILITY_BITMAP, (char *)"approach"},
    {VLINK_CAPABILITY_BITMAP, (char *)"virtualLink"},
    {TOUCH_CAPABILITY_BITMAP, (char *)"touch"}
};

/**
 * @brief Defines service publishing information.
 *
 */
typedef struct {
    /** Service ID */
    int publishId;
    /** Discovery mode for service publishing. For details, see {@link Discovermode}. */
    DiscoverMode mode;
    /** Service publishing medium. For details, see {@link ExchangeMedium}. */
    ExchangeMedium medium;
    /** Service publishing frequency. For details, see {@link ExchangeFreq}. */
    ExchangeFreq freq;
    /** Service publishing capabilities. For details, see {@link g_capabilityMap}. */
    const char *capability;
    /** Capability data for service publishing, MUST be c-string format. */
    unsigned char *capabilityData;
    /** Maximum length of the capability data for service publishing (512 bytes) */
    unsigned int dataLen;
    /** Whether the device should be ranged  by discoverers.*/
    bool ranging;
} PublishInfo;

/**
 * @brief Defines service subscription information.
 *
 */
typedef struct {
    /** Service ID */
    int subscribeId;
    /** Discovery mode for service subscription. For details, see {@link Discovermode}. */
    DiscoverMode mode;
    /** Service subscription medium. For details, see {@link ExchangeMedium}. */
    ExchangeMedium medium;
    /** Service subscription frequency. For details, see {@link ExchangeFreq}. */
    ExchangeFreq freq;
    /** only find the device with the same account */
    bool isSameAccount;
    /** find the sleeping devices */
    bool isWakeRemote;
    /** Service subscription capability. For details, see {@link g_capabilityMap}. */
    const char *capability;
    /** Capability data for service subscription, MUST be c-string format. */
    unsigned char *capabilityData;
    /** Maximum length of the capability data for service subscription (512 bytes) */
    unsigned int dataLen;
} SubscribeInfo;

/**
 * @brief Enumerates single heartbeat cycle parameter.
 *
 * @since 1.0
 * @version 1.0
 */
typedef enum {
    /**< Heartbeat interval 30 sec */
    HIGH_FREQ_CYCLE = 30,
    /**< Heartbeat interval 60 sec */
    MID_FREQ_CYCLE = 60,
    /**< Heartbeat interval 5 * 60 sec */
    LOW_FREQ_CYCLE = 5 * 60,
    /**< Heartbeat interval 10 * 60 sec */
    DEFAULT_FREQ_CYCLE = 10 * 60,
} ModeCycle;

/**
 * @brief Enumerates duration of heartbeat keeping alive parameter.
 *
 * @since 1.0
 * @version 1.0
 */
typedef enum {
    /**< Heartbeat continues for 60 sec */
    DEFAULT_DURATION = 60,
    /**< Heartbeat continues for 10 * 60 sec. */
    NORMAL_DURATION = 10 * 60,
    /**< Heartbeat continues for 30 * 60 sec. */
    LONG_DURATION = 30 * 60,
} ModeDuration;

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
 * @brief Defines the device information returned by <b>IDiscoveryCallback</b>.
 *
 */
typedef struct {
    /** Device ID. Its maximum length is specified by {@link DISC_MAX_DEVICE_ID_LEN}. */
    char devId[DISC_MAX_DEVICE_ID_LEN];
    /** Account hash code. Its maximum length is specified by {@link MAX_ACCOUNT_HASH_LEN}. */
    char accountHash[MAX_ACCOUNT_HASH_LEN];
    /** Device type. For details, see {@link DeviceType}. */
    DeviceType devType;
    /** Device name. Its maximum length is specified by {@link DISC_MAX_DEVICE_NAME_LEN}. */
    char devName[DISC_MAX_DEVICE_NAME_LEN];
    /** Device Online Status **/
    bool isOnline;
    /** Number of available connections */
    unsigned int addrNum;
    /** Connection information. For details, see {@link ConnectionAddr}. */
    ConnectionAddr addr[CONNECTION_ADDR_MAX];
    /** Number of capabilities */
    unsigned int capabilityBitmapNum;
    /** Device capability bitmap.
     * The maximum number of capabilities in the bitmap is specified by {@link DISC_MAX_CAPABILITY_NUM}.
     */
    unsigned int capabilityBitmap[DISC_MAX_CAPABILITY_NUM];
    /** Custom data. Its length is specified by {@link DISC_MAX_CUST_DATA_LEN}. */
    char custData[DISC_MAX_CUST_DATA_LEN];
    /** The distance of discovered device, in centimeters(cm)*/
    int32_t range;
} DeviceInfo;

/**
 * @brief Defines device additional info used by inner
 *
 */
typedef struct {
    /** medium which describe the device found by. */
    ExchangeMedium medium;
} InnerDeviceInfoAddtions;

/**
 * @brief Defines the capability enumeration of suppressing and restoring ble.
 * the value same as lnn_heartbeat_utils.h
 *
 */
typedef enum {
    /* Suppress ble */
    REQUEST_DISABLE_BLE_DISCOVERY = 100,
    /* Restore ble */
    REQUEST_ENABLE_BLE_DISCOVERY,
    /* Same accout device suppress ble */
    SAME_ACCOUNT_REQUEST_DISABLE_BLE_DISCOVERY,
    /* Same accout device restore ble */
    SAME_ACCOUNT_REQUEST_ENABLE_BLE_DISCOVERY,
} StrategyForBle;

#ifdef __cplusplus
}
#endif
#endif
/** @} */
