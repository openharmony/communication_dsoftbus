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

#ifndef LNN_NETWORK_MANAGER_H
#define LNN_NETWORK_MANAGER_H

#include <stdbool.h>
#include <stdint.h>

#include "bus_center_info_key.h"
#include "common_list.h"
#include "softbus_bus_center.h"
#include "softbus_conn_interface.h"
#include "softbus_protocol_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define LNN_LOOPBACK_IFNAME "lo"

// netif type
#define LNN_NETIF_TYPE_ETH  (0x1)
#define LNN_NETIF_TYPE_WLAN (0x1 << 1)
#define LNN_NETIF_TYPE_BR   (0x1 << 2)
#define LNN_NETIF_TYPE_BLE  (0x1 << 3)
typedef uint16_t LnnNetIfType;

#define LNN_NETWORK_MAX_PROTOCOL_COUNT 3

typedef struct {
    ListNode node;
    LnnNetIfType type;
    char ifName[NET_IF_NAME_LEN];
} LnnNetIfMgr;

typedef LnnNetIfMgr *(*LnnNetIfManagerBuilder)(const char *ifName);

typedef enum {
    CHOICE_VISIT_NEXT,
    CHOICE_FINISH_VISITING
} VisitNextChoice;

typedef VisitNextChoice (*VisitNetifCallback)(const LnnNetIfMgr *, void *);

typedef enum {
    LNN_LISTENER_MODE_PROXY,
    LNN_LISTENER_MODE_DIRECT,
    LNN_LISTENER_MODE_AUTH
} ListenerMode;

typedef struct LnnProtocolManager {
    int32_t (*init)(struct LnnProtocolManager *self);
    void (*deinit)(struct LnnProtocolManager *self);
    int32_t (*enable)(struct LnnProtocolManager *self, LnnNetIfMgr *netifMgr);
    int32_t (*disable)(struct LnnProtocolManager *self, LnnNetIfMgr *netifMgr);
    ListenerModule (*getListenerModule)(ListenerMode mode);
    ProtocolType id;
    LnnNetIfType supportedNetif;
    uint16_t pri;
} LnnProtocolManager;

typedef VisitNextChoice (*VisitProtocolCallback)(const LnnProtocolManager *, void *);

int32_t LnnRegistProtocol(LnnProtocolManager *impl);

int32_t LnnInitNetworkManager(void);
int32_t LnnInitNetworkManagerDelay(void);
void LnnDeinitNetworkManager(void);

int32_t LnnGetNetIfTypeByName(const char *ifName, LnnNetIfType *type);
int32_t LnnGetAddrTypeByIfName(const char *ifName, ConnectionAddrType *type);

ListenerModule LnnGetProtocolListenerModule(ProtocolType protocol, ListenerMode mode);

void RestartCoapDiscovery(void);
bool LnnIsAutoNetWorkingEnabled(void);

bool LnnVisitNetif(VisitNetifCallback callback, void *data);
bool LnnVisitProtocol(VisitProtocolCallback callback, void *data);
int32_t RegistIPProtocolManager(void);
void LnnSetUnlockState(void);
void LnnGetDataShareInitResult(bool *isDataShareInit);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* LNN_NETWORK_MANAGER_H */
