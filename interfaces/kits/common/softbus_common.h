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

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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
 * @brief Enumerates {@link ConnectionAddr} types of a device that is added to a LNN.
 *
 * @since 1.0
 * @version 1.0
 */
typedef enum {
    CONNECTION_ADDR_WLAN = 0, /**< WLAN */
    CONNECTION_ADDR_BR,       /**< BR */
    CONNECTION_ADDR_BLE,      /**< BLE */
    CONNECTION_ADDR_ETH,      /**< Ethernet */
    CONNECTION_ADDR_MIX,      /**< Mix */
    CONNECTION_ADDR_MAX       /**< Invalid type */
} ConnectionAddrType;
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
            char bleMac[BT_MAC_LEN];  /**< BLE MAC address in string format */
        } ble;
        /**< IPv4 or IPv6 address */
        struct IpAddr {
            /**
             * IP address in string format. It can be an IPv4 address written in dotted decimal notation
             * or an IPv6 address written in hexadecimal colon-separated notation.
             */
            char ip[IP_STR_MAX_LEN];
            uint16_t port;            /**< Port number represented by the host byte order */
        } ip;
    } info;
    char peerUid[MAX_ACCOUNT_HASH_LEN];
} ConnectionAddr;
#ifdef __cplusplus
}
#endif
#endif
/** @} */
