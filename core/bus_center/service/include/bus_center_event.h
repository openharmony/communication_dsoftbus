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

#ifndef BUS_CENTER_EVENT_H
#define BUS_CENTER_EVENT_H

#include <stdbool.h>
#include <stdint.h>

#include "softbus_bus_center.h"
#include "bus_center_info_key.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    /* event from system monitor */
    LNN_EVENT_IP_ADDR_CHANGED,
    LNN_EVENT_WIFI_STATE_CHANGED,
    LNN_EVENT_BT_STATE_CHANGED,
    LNN_EVENT_BT_ACL_STATE_CHANGED,
    LNN_EVENT_WLAN_PARAM,
    LNN_EVENT_SCREEN_STATE_CHANGED,
    LNN_EVENT_SCREEN_LOCK_CHANGED,
    LNN_EVENT_ACCOUNT_CHANGED,
    LNN_EVENT_DIF_ACCOUNT_DEV_CHANGED,
    LNN_EVENT_USER_STATE_CHANGED,
    LNN_EVENT_NIGHT_MODE_CHANGED,
    LNN_EVENT_OOBE_STATE_CHANGED,
    LNN_EVENT_HOME_GROUP_CHANGED,
    /* event from internal lnn */
    LNN_EVENT_NODE_ONLINE_STATE_CHANGED,
    LNN_EVENT_NODE_MIGRATE,
    LNN_EVENT_RELATION_CHANGED,
    LNN_EVENT_NODE_MASTER_STATE_CHANGED,
    LNN_EVENT_NODE_ADDR_CHANGED,
    LNN_EVENT_NETWORK_STATE_CHANGED,
    LNN_EVENT_SINGLE_NETWORK_OFFLINE,
    LNN_EVENT_NODE_HB_REPEAT_CYCLE,
    LNN_EVENT_NETWORKID_CHANGED,
    LNN_EVENT_TYPE_MAX,
} LnnEventType;

typedef struct {
    LnnEventType event;
} LnnEventBasicInfo;

typedef struct {
    LnnEventBasicInfo basic;
    char ifName[NET_IF_NAME_LEN];
} LnnMonitorAddressChangedEvent;

typedef enum {
    SOFTBUS_WIFI_CONNECTED,
    SOFTBUS_WIFI_DISCONNECTED,
    SOFTBUS_WIFI_DISABLING,
    SOFTBUS_WIFI_DISABLED,
    SOFTBUS_WIFI_ENABLING,
    SOFTBUS_WIFI_ENABLED,
    SOFTBUS_AP_DISABLED,
    SOFTBUS_AP_ENABLED,
    SOFTBUS_WIFI_OBTAINING_IPADDR,
    SOFTBUS_WIFI_UNKNOWN,
} SoftBusWifiState;

typedef enum {
    SOFTBUS_SCREEN_ON,
    SOFTBUS_SCREEN_OFF,
    SOFTBUS_SCREEN_UNKNOWN,
} SoftBusScreenState;

typedef enum {
    SOFTBUS_BLE_TURN_ON,
    SOFTBUS_BLE_TURN_OFF,
    SOFTBUS_BR_TURN_ON,
    SOFTBUS_BR_TURN_OFF,
    SOFTBUS_BT_UNKNOWN,
} SoftBusBtState;

typedef enum {
    SOFTBUS_SCREEN_LOCK,
    SOFTBUS_SCREEN_UNLOCK,
    SOFTBUS_SCREEN_LOCK_UNKNOWN,
} SoftBusScreenLockState;

typedef enum {
    SOFTBUS_ACCOUNT_LOG_IN,
    SOFTBUS_ACCOUNT_LOG_OUT,
    SOFTBUS_ACCOUNT_UNKNOWN,
} SoftBusAccountState;

typedef enum {
    SOFTBUS_DIF_ACCOUNT_DEV_CHANGE,
    SOFTBUS_DIF_ACCOUNT_UNKNOWN,
} SoftBusDifferentAccountState;

typedef enum {
    SOFTBUS_USER_FOREGROUND,
    SOFTBUS_USER_BACKGROUND,
    SOFTBUS_USER_UNKNOWN,
} SoftBusUserState;

typedef enum {
    SOFTBUS_NIGHT_MODE_ON,
    SOFTBUS_NIGHT_MODE_OFF,
    SOFTBUS_NIGHT_MODE_UNKNOWN,
} SoftBusNightModeState;

typedef enum {
    SOFTBUS_OOBE_RUNNING,
    SOFTBUS_OOBE_END,
    SOFTBUS_OOBE_UNKNOWN,
} SoftBusOOBEState;

typedef enum {
    SOFTBUS_HOME_GROUP_CHANGE = 0X1,
    SOFTBUS_HOME_GROUP_JOIN,
    SOFTBUS_HOME_GROUP_LEAVE,
    SOFTBUS_HOME_GROUP_UNKNOWN,
} SoftBusHomeGroupState;

typedef enum {
    SOFTBUS_BR_ACL_CONNECTED,
    SOFTBUS_BR_ACL_DISCONNECTED,
} SoftBusBtAclState;

typedef enum {
    SOFTBUS_WIFI_NETWORKD_ENABLE,
    SOFTBUS_WIFI_NETWORKD_DISABLE,
    SOFTBUS_BLE_NETWORKD_ENABLE,
    SOFTBUS_BLE_NETWORKD_DISABLE,
    SOFTBUS_NETWORKD_UNKNOWN,
} SoftBusNetworkState;

typedef struct {
    LnnEventBasicInfo basic;
    uint8_t status;
} LnnMonitorWlanStateChangedEvent;

typedef struct {
    LnnEventBasicInfo basic;
    uint8_t status;
} LnnMonitorScreenStateChangedEvent;

typedef struct {
    LnnEventBasicInfo basic;
    uint8_t status;
} LnnMonitorHbStateChangedEvent;

typedef struct {
    LnnEventBasicInfo basic;
    uint8_t status;
    char btMac[BT_MAC_LEN];
} LnnMonitorBtAclStateChangedEvent;

typedef struct {
    LnnEventBasicInfo basic;
    bool isOnline;
    const char *networkId;
    const char *uuid;
    const char *udid;
} LnnOnlineStateEventInfo;

typedef struct {
    LnnEventBasicInfo basic;
    ConnectionAddrType type;
    uint8_t relation;
    bool isJoin;
    const char *udid;
} LnnRelationChanedEventInfo;

typedef struct {
    LnnEventBasicInfo basic;
    const char* masterNodeUDID;
    int32_t weight;
    bool isMasterNode;
} LnnMasterNodeChangedEvent;

typedef struct {
    LnnEventBasicInfo basic;
    char addr[SHORT_ADDRESS_MAX_LEN];
    char networkId[NETWORK_ID_BUF_LEN];
    bool delFlag;
    bool isLocal;
} LnnNodeAddrChangedEvent;

typedef struct {
    LnnEventBasicInfo basic;
    ConnectionAddrType type;
    const char *networkId;
    const char *uuid;
    const char *udid;
} LnnSingleNetworkOffLineEvent;

typedef struct {
    LnnEventBasicInfo basic;
    char networkId[NETWORK_ID_BUF_LEN];
} LnnNetworkIdChangedEvent;

typedef void (*LnnEventHandler)(const LnnEventBasicInfo *info);

int32_t LnnInitBusCenterEvent(void);
void LnnDeinitBusCenterEvent(void);

int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler);
void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler);

void LnnNotifyJoinResult(ConnectionAddr *addr,
    const char *networkId, int32_t retCode);
void LnnNotifyLeaveResult(const char *networkId, int32_t retCode);

void LnnNotifyOnlineState(bool isOnline, NodeBasicInfo *info);
void LnnNotifyBasicInfoChanged(NodeBasicInfo *info, NodeBasicInfoType type);
void LnnNotifyMigrate(bool isOnline, NodeBasicInfo *info);

void LnnNotifyWlanStateChangeEvent(SoftBusWifiState state);
void LnnNotifyScreenStateChangeEvent(SoftBusScreenState state);
void LnnNotifyDifferentAccountChangeEvent(void *state);
void LnnNotifyBtStateChangeEvent(void *state);
void LnnNotifyScreenLockStateChangeEvent(SoftBusScreenLockState state);
void LnnNotifyAccountStateChangeEvent(void *state);
void LnnNotifyUserStateChangeEvent(SoftBusUserState state);
void LnnNotifyHomeGroupChangeEvent(SoftBusHomeGroupState state);
void LnnNotifyNightModeStateChangeEvent(void *state);
void LnnNotifyOOBEStateChangeEvent(SoftBusOOBEState state);
void LnnNotifyBtAclStateChangeEvent(const char *btMac, SoftBusBtAclState state);
void LnnNotifyAddressChangedEvent(const char* ifName);
void LnnNotifyLnnRelationChanged(const char *udid, ConnectionAddrType type, uint8_t relation, bool isJoin);
void LnnNotifyDeviceVerified(const char *udid);

void LnnNotifyTimeSyncResult(const char *pkgName, int32_t pid, const TimeSyncResultInfo *info, int32_t retCode);

void LnnNotifyMasterNodeChanged(bool isMaster, const char* masterNodeUdid, int32_t weight);

void LnnNotifyNodeAddressChanged(const char *addr, const char *networkId, bool isLocal);

void LnnNotifyNetworkStateChanged(SoftBusNetworkState state);

void LnnNotifySingleOffLineEvent(const ConnectionAddr *addr, NodeBasicInfo *basicInfo);

void LnnNotifyNetworkIdChangeEvent(const char *networkId);
void LnnNotifyHBRepeat(void);

#ifdef __cplusplus
}
#endif
#endif
