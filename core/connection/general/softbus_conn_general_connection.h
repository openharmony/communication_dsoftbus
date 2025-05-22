/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_CONN_GENERAL_CONNECTION_H
#define SOFTBUS_CONN_GENERAL_CONNECTION_H

#include "softbus_conn_general_negotiation.h"
#include "softbus_conn_interface.h"
#include "softbus_utils.h"

#include "stdint.h"
#ifdef __cplusplus
extern "C" {
#endif

enum GeneralConnState {
    STATE_CONNECTING,
    STATE_CONNECTED,
};

typedef struct {
    int32_t pid;
    char name[GENERAL_NAME_LEN];
    char pkgName[PKG_NAME_SIZE_MAX];
    char bundleName[BUNDLE_NAME_MAX];
} GeneralConnectionParam;

typedef struct {
    ListNode node;
    GeneralConnectionParam info;
} Server;

struct GeneralConnection {
    ListNode node;
    uint32_t requestId;
    uint32_t generalId;
    uint32_t peerGeneralId;
    uint32_t abilityBitSet;
    uint32_t underlayerHandle;
    int32_t objectRc;
    BleProtocolType protocol;
    char udid[UDID_BUF_LEN];
    char networkId[NETWORK_ID_BUF_LEN];
    char addr[BT_MAC_LEN];
    bool isSupportNetWorkIdExchange;
    bool isClient;
    enum GeneralConnState state;
    GeneralConnectionParam info;
    void (*reference)(struct GeneralConnection *self);
    void (*dereference)(struct GeneralConnection *self);
    SoftBusMutex lock;
};

typedef struct {
    void (*onConnectSuccess)(GeneralConnectionParam *info, uint32_t generalHandle);
    void (*onConnectFailed)(GeneralConnectionParam *info, uint32_t generalHandle, int32_t reason);
    void (*onAcceptConnect)(GeneralConnectionParam *info, uint32_t generalHandle);
    void (*onDataReceived)(GeneralConnectionParam *info, uint32_t generalHandle, const uint8_t *data, uint32_t dataLen);
    void (*onConnectionDisconnected)(GeneralConnectionParam *info, uint32_t generalHandle, int32_t reason);
} GeneralConnectionListener;

typedef struct {
    int32_t (*registerListener)(const GeneralConnectionListener *listener);
    int32_t (*createServer)(const GeneralConnectionParam *param);
    void (*closeServer)(const GeneralConnectionParam *param);

    int32_t (*connect)(const GeneralConnectionParam *param, const char *addr);
    int32_t (*send)(uint32_t generalHandle, const uint8_t *data, uint32_t dataLen, int32_t pid);

    void (*disconnect)(uint32_t generalHandle);
    int32_t (*getPeerDeviceId)(uint32_t generalHandle, char *addr, uint32_t length, uint32_t tokenId);
    void (*cleanupGeneralConnection)(const char *pkgName, int32_t pid);
} GeneralConnectionManager;

GeneralConnectionManager *GetGeneralConnectionManager(void);
int32_t InitGeneralConnectionManager(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* SOFTBUS_CONN_GENERAL_CONNECTION_H */