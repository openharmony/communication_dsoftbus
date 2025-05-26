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

#ifndef AUTH_INTERFACE_STRUCT_H
#define AUTH_INTERFACE_STRUCT_H

#include <stdbool.h>
#include <stdint.h>
#include "lnn_node_info_struct.h"
#include "softbus_common.h"
#include "../connect/softbus_conn_interface_struct.h"
#include "softbus_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define AUTH_INVALID_ID (-1)

#define AUTH_IDENTICAL_ACCOUNT_GROUP 1
#define AUTH_PEER_TO_PEER_GROUP 256
#define CUST_UDID_LEN 16
#define AUTH_INVALID_DEVICEKEY_ID 0x0

typedef enum {
   /* nearby type v1 */
   SOFTBUS_OLD_V1 = 1,
   /* nearby type v2 */
   SOFTBUS_OLD_V2 = 2,
   /* softbus type v1 */
   SOFTBUS_NEW_V1 = 100,
   /* softbus type v2 */
   SOFTBUS_NEW_V2 = 101,
} SoftBusVersion;

typedef enum {
   AUTH_VERSION_INVALID = 0,
   AUTH_VERSION_V1 = 1,
   AUTH_VERSION_V2 = 2,
} AuthVersion;

typedef enum {
   AUTH_LINK_TYPE_WIFI = 1,
   AUTH_LINK_TYPE_BR,
   AUTH_LINK_TYPE_BLE,
   AUTH_LINK_TYPE_P2P,
   AUTH_LINK_TYPE_ENHANCED_P2P,
   AUTH_LINK_TYPE_RAW_ENHANCED_P2P,
   AUTH_LINK_TYPE_NORMALIZED,
   AUTH_LINK_TYPE_SESSION,
   AUTH_LINK_TYPE_SESSION_KEY,
   AUTH_LINK_TYPE_SLE,
   AUTH_LINK_TYPE_USB,
   AUTH_LINK_TYPE_MAX,
} AuthLinkType;

typedef struct {
   uint32_t linkTypeNum;
   AuthLinkType linkType[AUTH_LINK_TYPE_MAX];
} AuthLinkTypeList;

typedef enum {
   AUTH_MODULE_LNN,
   AUTH_MODULE_TRANS,
   AUTH_MODULE_BUTT,
} AuthVerifyModule;

typedef struct {
   AuthLinkType type;
   union {
       struct {
           char brMac[BT_MAC_LEN];
           uint32_t connectionId;
       } brInfo;
       struct {
           BleProtocolType protocol;
           char bleMac[BT_MAC_LEN];
           uint8_t deviceIdHash[UDID_HASH_LEN];
           int32_t psm;
       } bleInfo;
       struct {
           char ip[IP_LEN];
           uint8_t deviceIdHash[UDID_HASH_LEN];
           int32_t port;
           int64_t authId; /* for open p2p auth conn */
           ListenerModule moduleId; /* for open enhance p2p auth conn */
           char udid[UDID_BUF_LEN];
           int32_t fd;
       } ipInfo;
       struct {
           uint32_t connId;
           char udid[UDID_BUF_LEN];
       } sessionInfo;
       struct {
           SleProtocolType protocol;
           char sleMac[BT_MAC_LEN];
           char networkId[NETWORK_ID_BUF_LEN];
       } sleInfo;
   } info;
   char peerUid[MAX_ACCOUNT_HASH_LEN];
} AuthConnInfo;

typedef struct {
   bool isForceJoin;
   ConnectionAddr addr;
   char networkId[NETWORK_ID_BUF_LEN];
} ForceJoinInfo;

typedef struct {
   uint32_t requestId;
   AuthVerifyModule module;
   bool isFastAuth;
   DeviceKeyId deviceKeyId;
   ForceJoinInfo forceJoinInfo;
} AuthVerifyParam;

typedef enum {
   ONLINE_HICHAIN = 0,
   ONLINE_METANODE,
   ONLINE_MIX,
   AUTH_TYPE_BUTT,
} AuthType;

typedef struct {
   void (*onDeviceVerifyPass)(AuthHandle authHandle, const NodeInfo *info);
   void (*onDeviceNotTrusted)(const char *peerUdid);
   void (*onDeviceDisconnect)(AuthHandle authHandle);
} AuthVerifyListener;

typedef struct {
   void (*onVerifyPassed)(uint32_t requestId, AuthHandle authHandle, const NodeInfo *info);
   void (*onVerifyFailed)(uint32_t requestId, int32_t reason);
} AuthVerifyCallback;

typedef struct {
   void (*onConnOpened)(uint32_t requestId, AuthHandle authHandle);
   void (*onConnOpenFailed)(uint32_t requestId, int32_t reason);
} AuthConnCallback;

typedef struct {
   const uint8_t *key;
   uint32_t keyLen;
} AuthKeyInfo;

typedef struct {
   void (*onGroupCreated)(const char *groupId, int32_t groupType);
   void (*onGroupDeleted)(const char *groupId, int32_t groupType);
   void (*onDeviceBound)(const char *udid, const char *groupInfo);
} GroupChangeListener;

typedef enum {
   TRUSTED_RELATION_IGNORE = 0,
   TRUSTED_RELATION_NO,
   TRUSTED_RELATION_YES,
} TrustedReturnType;

typedef struct {
   int32_t module;
   int32_t flag;
   int64_t seq;
   uint32_t len;
   const uint8_t *data;
} AuthTransData;

typedef struct {
   void (*onDataReceived)(AuthHandle authHandle, const AuthTransData *data);
   void (*onDisconnected)(AuthHandle authHandle);
   void (*onException)(AuthHandle authHandle, int32_t error);
} AuthTransListener;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_INTERFACE_STRUCT_H */