/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "lnn_physical_subnet_manager.h"

#include <stddef.h>
#include <string.h>

#include "lnn_log.h"
#include "lnn_network_manager.h"
#include "softbus_adapter_thread.h"
#include "softbus_error_code.h"

#define MAX_SUPPORTED_PHYSICAL_SUBNET 6

static SoftBusMutex g_physicalSubnetsLock;
static LnnPhysicalSubnet *g_physicalSubnets[MAX_SUPPORTED_PHYSICAL_SUBNET];

#define CALL_WITH_LOCK(RET, LOCK, ACTION)                                    \
    do {                                                                     \
        ret = SoftBusMutexLock(LOCK);                                        \
        if (ret != SOFTBUS_OK) {                                             \
            LNN_LOGE(LNN_BUILDER, "lock mutex failed"); \
            break;                                                           \
        }                                                                    \
        (RET) = (ACTION);                                                    \
        SoftBusMutexUnlock(LOCK);                                            \
    } while (false)

#define CALL_VOID_FUNC_WITH_LOCK(LOCK, ACTION)                               \
    do {                                                                     \
        if (SoftBusMutexLock(LOCK) != 0) {                                   \
            LNN_LOGE(LNN_BUILDER, "lock mutex failed"); \
            break;                                                           \
        }                                                                    \
        (ACTION);                                                            \
        SoftBusMutexUnlock(LOCK);                                            \
    } while (false)

int32_t LnnInitPhysicalSubnetManager(void)
{
    LNN_LOGI(LNN_BUILDER, "g_physicalSubnetsLock init");
    int32_t ret = SoftBusMutexInit(&g_physicalSubnetsLock, NULL);
    LNN_LOGI(LNN_BUILDER, "g_physicalSubnetsLock init succ");
    return ret;
}

static void ClearSubnetManager(void)
{
    for (uint8_t i = 0; i < MAX_SUPPORTED_PHYSICAL_SUBNET; i++) {
        if (g_physicalSubnets[i] != NULL) {
            if (g_physicalSubnets[i]->destroy != NULL) {
                g_physicalSubnets[i]->destroy(g_physicalSubnets[i]);
            }
            g_physicalSubnets[i] = NULL;
        }
    }
}

void LnnDeinitPhysicalSubnetManager(void)
{
    LNN_LOGI(LNN_BUILDER, "g_physicalSubnetsLock deinit");
    CALL_VOID_FUNC_WITH_LOCK(&g_physicalSubnetsLock, ClearSubnetManager());
    LNN_LOGI(LNN_BUILDER, "g_physicalSubnetsLock deinit succ");
    if (SoftBusMutexDestroy(&g_physicalSubnetsLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "destroy mutex failed");
    }
}

static int32_t DoRegistSubnet(LnnPhysicalSubnet *subnet)
{
    for (uint8_t i = 0; i < MAX_SUPPORTED_PHYSICAL_SUBNET; i++) {
        if (g_physicalSubnets[i] != NULL) {
            continue;
        }
        g_physicalSubnets[i] = subnet;
        if (g_physicalSubnets[i]->onNetifStatusChanged != NULL) {
            g_physicalSubnets[i]->onNetifStatusChanged(g_physicalSubnets[i], NULL);
        }
        return SOFTBUS_OK;
    }
    LNN_LOGE(LNN_BUILDER, "subnet list is full");
    return SOFTBUS_NETWORK_SUBNET_LIST_FULL;
}

int32_t LnnRegistPhysicalSubnet(LnnPhysicalSubnet *subnet)
{
    if (subnet == NULL || subnet->protocol == NULL) {
        LNN_LOGE(LNN_BUILDER, "protocol of subnet is required");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = SOFTBUS_OK;
    LNN_LOGI(LNN_BUILDER, "get g_physicalSubnetsLock start, currTime=%{public}" PRIu64, SoftBusGetSysTimeMs());
    CALL_WITH_LOCK(ret, &g_physicalSubnetsLock, DoRegistSubnet(subnet));
    LNN_LOGI(LNN_BUILDER, "get g_physicalSubnetsLock end, currTime=%{public}" PRIu64, SoftBusGetSysTimeMs());
    return ret;
}

static int32_t DoUnregistSubnetByType(ProtocolType type)
{
    for (uint8_t i = 0; i < MAX_SUPPORTED_PHYSICAL_SUBNET; i++) {
        if (g_physicalSubnets[i] != NULL && g_physicalSubnets[i]->protocol->id == type) {
            if (g_physicalSubnets[i]->destroy != NULL) {
                g_physicalSubnets[i]->destroy(g_physicalSubnets[i]);
            }
            g_physicalSubnets[i] = NULL;
        }
    }
    return SOFTBUS_OK;
}

int32_t LnnUnregistPhysicalSubnetByType(ProtocolType type)
{
    int32_t ret = SOFTBUS_OK;
    LNN_LOGI(LNN_BUILDER, "get g_physicalSubnetsLock start, currTime=%{public}" PRIu64, SoftBusGetSysTimeMs());
    CALL_WITH_LOCK(ret, &g_physicalSubnetsLock, DoUnregistSubnetByType(type));
    LNN_LOGI(LNN_BUILDER, "get g_physicalSubnetsLock end, currTime=%{public}" PRIu64, SoftBusGetSysTimeMs());
    return ret;
}

void DoNotifyStatusChange(const char *ifName, ProtocolType protocolType, void *status)
{
    for (uint16_t i = 0; i < MAX_SUPPORTED_PHYSICAL_SUBNET; i++) {
        if (g_physicalSubnets[i] == NULL || g_physicalSubnets[i]->protocol->id != protocolType) {
            continue;
        }

        if (strcmp(g_physicalSubnets[i]->ifName, LNN_PHYSICAL_SUBNET_ALL_NETIF) != 0 &&
            strcmp(g_physicalSubnets[i]->ifName, ifName) != 0) {
            continue;
        }

        if (g_physicalSubnets[i]->onNetifStatusChanged != NULL) {
            g_physicalSubnets[i]->onNetifStatusChanged(g_physicalSubnets[i], status);
        }
    }
}

void LnnNotifyPhysicalSubnetStatusChanged(const char *ifName, ProtocolType protocolType, void *status)
{
    CALL_VOID_FUNC_WITH_LOCK(&g_physicalSubnetsLock, DoNotifyStatusChange(ifName, protocolType, status));
    LNN_LOGI(LNN_BUILDER, "success");
}

static void EnableResetingSubnetByType(ProtocolType protocolType)
{
    for (uint16_t i = 0; i < MAX_SUPPORTED_PHYSICAL_SUBNET; i++) {
        if (g_physicalSubnets[i] == NULL || g_physicalSubnets[i]->protocol->id != protocolType) {
            continue;
        }
        if (g_physicalSubnets[i]->onSoftbusNetworkDisconnected != NULL) {
            g_physicalSubnets[i]->onSoftbusNetworkDisconnected(g_physicalSubnets[i]);
        }
    }
}

void LnnNotifyAllTypeOffline(ConnectionAddrType type)
{
    if (type == CONNECTION_ADDR_ETH || type == CONNECTION_ADDR_WLAN || type == CONNECTION_ADDR_MAX) {
        CALL_VOID_FUNC_WITH_LOCK(&g_physicalSubnetsLock, EnableResetingSubnetByType(LNN_PROTOCOL_IP));
        LNN_LOGI(LNN_BUILDER, "success");
    }
}

static bool DoVisitSubnet(LnnVisitPhysicalSubnetCallback callback, void *data)
{
    VisitNextChoice result = CHOICE_VISIT_NEXT;
    for (uint16_t i = 0; i < MAX_SUPPORTED_PHYSICAL_SUBNET; i++) {
        if (g_physicalSubnets[i] == NULL) {
            continue;
        }
        result = callback(g_physicalSubnets[i], data);
        if (result == CHOICE_FINISH_VISITING) {
            return false;
        }
    }
    return true;
}

bool LnnVisitPhysicalSubnet(LnnVisitPhysicalSubnetCallback callback, void *data)
{
    bool ret = false;
    LNN_LOGI(LNN_BUILDER, "get g_physicalSubnetsLock start, currTime=%{public}" PRIu64, SoftBusGetSysTimeMs());
    CALL_WITH_LOCK(ret, &g_physicalSubnetsLock, DoVisitSubnet(callback, data));
    LNN_LOGI(LNN_BUILDER, "get g_physicalSubnetsLock end, currTime=%{public}" PRIu64, SoftBusGetSysTimeMs());
    return ret;
}
