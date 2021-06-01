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
  * @addtogroup Softbus
  * @{
  *
  * @brief Provides high-speed, secure communication between devices.
  *
  * This module implements unified distributed communication capability management between nearby devices,
  * and provides link-independent device LNN management.
  *
  * @since 1.0
  * @version 1.0
  */

 /**
  * @file softbus_bus_center.h
  *
  * @brief Declares unified device LNN management interfaces.
  *
  * This file provides capabilities related to device join LNN, leave LNN and perceiving the LNN state changed event.
  *
  * @since 1.0
  * @version 1.0
  */
#ifndef SOFTBUS_BUS_CENTER_H
#define SOFTBUS_BUS_CENTER_H

#include <stdbool.h>
#include <stdint.h>

#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IP_STR_MAX_LEN 46

#define DEVICE_NAME_BUF_LEN 128

#define EVENT_NODE_STATE_ONLINE 0x1
#define EVENT_NODE_STATE_OFFLINE 0x02
#define EVENT_NODE_STATE_INFO_CHANGED 0x04

#define EVENT_NODE_STATE_MASK 0x07

typedef enum {
    CONNECTION_ADDR_WLAN = 0,
    CONNECTION_ADDR_BR,
    CONNECTION_ADDR_BLE,
    CONNECTION_ADDR_ETH,
    CONNECTION_ADDR_MAX
} ConnectionAddrType;

typedef enum {
    TYPE_NETWORK_ID = 0,
    TYPE_DEVICE_NAME,
} NodeBasicInfoType;

typedef enum {
    NODE_KEY_UDID = 0,
    NODE_KEY_UUID,
} NodeDeivceInfoKey;

typedef struct {
    ConnectionAddrType type;
    union {
        struct BrAddr {
            char brMac[BT_MAC_LEN];
        } br;
        struct BleAddr {
            char bleMac[BT_MAC_LEN];
        } ble;
        struct IpAddr {
            char ip[IP_STR_MAX_LEN];
            int port;
        } ip;
    } info;
} ConnectionAddr;

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    char deviceName[DEVICE_NAME_BUF_LEN];
    uint8_t deviceTypeId;
} NodeBasicInfo;

typedef struct {
    uint32_t events;
    void (*onNodeOnline)(NodeBasicInfo *info);
    void (*onNodeOffline)(NodeBasicInfo *info);
    void (*onNodeBasicInfoChanged)(NodeBasicInfoType type, NodeBasicInfo *info);
} INodeStateCb;

typedef void (*OnJoinLNNResult)(ConnectionAddr *addr, const char *networkId, int32_t retCode);
typedef void (*OnLeaveLNNResult)(const char *networkId, int32_t retCode);

int32_t JoinLNN(const char *pkgName, ConnectionAddr *target, OnJoinLNNResult cb);
int32_t LeaveLNN(const char *networkId, OnLeaveLNNResult cb);

int32_t RegNodeDeviceStateCb(const char *pkgName, INodeStateCb *callback);
int32_t UnregNodeDeviceStateCb(INodeStateCb *callback);

int32_t GetAllNodeDeviceInfo(const char *pkgName, NodeBasicInfo **info, int32_t *infoNum);
void FreeNodeInfo(NodeBasicInfo *info);

int32_t GetLocalNodeDeviceInfo(const char *pkgName, NodeBasicInfo *info);

int32_t GetNodeKeyInfo(const char *pkgName, const char *networkId,
    NodeDeivceInfoKey key, uint8_t *info, int32_t infoLen);

#ifdef __cplusplus
}
#endif

#endif
