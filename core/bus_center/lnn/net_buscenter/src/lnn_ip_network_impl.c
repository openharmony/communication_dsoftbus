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

#include "lnn_network_manager.h"

#include <securec.h>
#include <string.h>

#include <stdio.h>
#include <unistd.h>

#include "auth_interface.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "disc_interface.h"
#include "lnn_net_builder.h"
#include "lnn_discovery_manager.h"
#include "lnn_event_monitor.h"
#include "lnn_ip_utils.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "trans_tcp_direct_listener.h"

#define IP_DEFAULT_PORT 0

typedef struct {
    bool isIpLinkClosed;
    pthread_mutex_t lock;
} LNNIpNetworkInfo;

static LNNIpNetworkInfo g_lnnIpNetworkInfo = {
    .isIpLinkClosed = true,
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

static int32_t OpenAuthPort(void)
{
    int32_t port = OpenAuthServer();
    if (port < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "open auth server failed\n");
        return SOFTBUS_ERR;
    }
    return LnnSetLocalNumInfo(NUM_KEY_AUTH_PORT, port);
}

static void CloseAuthPort(void)
{
    CloseAuthServer();
    (void)LnnSetLocalNumInfo(NUM_KEY_AUTH_PORT, IP_DEFAULT_PORT);
}

static int32_t OpenSessionPort(void)
{
    char ipAddr[IP_LEN] = {0};
    int32_t port;

    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, ipAddr, IP_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local ip failed\n");
        return SOFTBUS_ERR;
    }
    port = TransTdcStartSessionListener(ipAddr, 0);
    if (port < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "open session server failed\n");
        return SOFTBUS_ERR;
    }
    return LnnSetLocalNumInfo(NUM_KEY_SESSION_PORT, port);
}

static void CloseSessionPort(void)
{
    TransTdcStopSessionListener();
    (void)LnnSetLocalNumInfo(NUM_KEY_SESSION_PORT, IP_DEFAULT_PORT);
}

static void CloseProxyPort(void)
{
    LocalListenerInfo listenerInfo = {0};
    listenerInfo.type = CONNECT_TCP;
    if (ConnStopLocalListening(&listenerInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ConnStopLocalListening fail!\n");
    }
    (void)LnnSetLocalNumInfo(NUM_KEY_PROXY_PORT, IP_DEFAULT_PORT);
}

static int32_t OpenIpLink(void)
{
    int32_t ret = OpenAuthPort();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OpenAuthPort fail!\n");
        return SOFTBUS_ERR;
    }
    ret = OpenSessionPort();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OpenSessionPort fail!\n");
        CloseAuthPort();
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void CloseIpLink(void)
{
    CloseAuthPort();
    CloseSessionPort();
    CloseProxyPort();
}

static int32_t SetLocalIpInfo(char *ipAddr, char *ifName)
{
    if (LnnSetLocalStrInfo(STRING_KEY_WLAN_IP, ipAddr) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set local ip error!\n");
        return SOFTBUS_ERR;
    }
    if (LnnSetLocalStrInfo(STRING_KEY_NET_IF_NAME, ifName) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set local ifname error!\n");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t GetLocalIpInfo(char *ipAddr, uint32_t ipAddrLen, char *ifName, uint32_t ifNameLen)
{
    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, ipAddr, ipAddrLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local ip error!\n");
        return SOFTBUS_ERR;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_NET_IF_NAME, ifName, ifNameLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local ifname error!\n");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t GetUpdateLocalIp(char *ipAddr, uint32_t ipAddrLen, char *ifName, uint32_t ifNameLen, bool isWifiDisc)
{
    if (!isWifiDisc && LnnGetLocalIp(ipAddr, ipAddrLen, ifName, ifNameLen, CONNECTION_ADDR_ETH) == SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "get eth ip success\n");
        return SOFTBUS_OK;
    }
    if (!isWifiDisc && LnnGetLocalIp(ipAddr, ipAddrLen, ifName, ifNameLen, CONNECTION_ADDR_WLAN) == SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "get wlan ip success\n");
        return SOFTBUS_OK;
    }
    if (strncpy_s(ipAddr, ipAddrLen, LNN_LOOPBACK_IP, strlen(LNN_LOOPBACK_IP)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy loopback ip addr failed\n");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(ifName, ifNameLen, LNN_LOOPBACK_IFNAME, strlen(LNN_LOOPBACK_IFNAME)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy loopback ifname failed\n");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set loopback ip as default\n");
    return SOFTBUS_OK;
}

static void LeaveOldIpNetwork(const char *ifCurrentName)
{
    ConnectionAddrType type;

    if (strstr(ifCurrentName, LNN_WLAN_IF_NAME_PREFIX) != NULL) {
        type = CONNECTION_ADDR_WLAN;
    } else if (strstr(ifCurrentName, LNN_ETH_IF_NAME_PREFIX) != NULL) {
        type = CONNECTION_ADDR_ETH;
    } else {
        type = CONNECTION_ADDR_MAX;
    }

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LNN start leave ip network\n");
    if (LnnRequestLeaveByAddrType(type) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LNN leave ip network fail\n");
    }
}

static int32_t UpdateLocalIp(char *ipAddr, uint32_t ipAddrLen, char *ifName, uint32_t ifNameLen, bool isWifiDisc)
{
    char ipNewAddr[IP_LEN] = {0};
    char ifNewName[NET_IF_NAME_LEN] = {0};

    if (GetLocalIpInfo(ipAddr, ipAddrLen, ifName, ifNameLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get current ip info failed\n");
        return SOFTBUS_ERR;
    }
    if (GetUpdateLocalIp(ipNewAddr, IP_LEN, ifNewName, NET_IF_NAME_LEN, isWifiDisc) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get new ip info failed\n");
        return SOFTBUS_ERR;
    }
    if (strcmp(ipAddr, ipNewAddr) == 0 && strcmp(ifName, ifNewName) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "ip info not changed\n");
        return SOFTBUS_ERR;
    }
    if (strncmp(ifName, LNN_LOOPBACK_IFNAME, strlen(LNN_LOOPBACK_IFNAME)) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "close previous ip link and stop previous discovery\n");
        CloseIpLink();
        LnnStopDiscovery();
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "update local ledger\n");
    if (SetLocalIpInfo(ipNewAddr, ifNewName) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set local ip info failed\n");
        return SOFTBUS_ERR;
    }
    if (strncmp(ifNewName, LNN_LOOPBACK_IFNAME, strlen(LNN_LOOPBACK_IFNAME)) != 0) {
        DiscLinkStatusChanged(LINK_STATUS_UP, COAP);
    } else {
        DiscLinkStatusChanged(LINK_STATUS_DOWN, COAP);
    }
    return SOFTBUS_OK;
}

static void IpAddrChangeEventHandler(LnnMonitorEventType event, const LnnMoniterData *para)
{
    char ipCurrentAddr[IP_LEN] = {0};
    char ifCurrentName[NET_IF_NAME_LEN] = {0};

    (void)para;
    if (event != LNN_MONITOR_EVENT_IP_ADDR_CHANGED) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "not interest event: %d\n", event);
        return;
    }
    if (pthread_mutex_lock(&g_lnnIpNetworkInfo.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    if (UpdateLocalIp(ipCurrentAddr, IP_LEN, ifCurrentName, NET_IF_NAME_LEN, false) != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&g_lnnIpNetworkInfo.lock);
        return;
    }
    LeaveOldIpNetwork(ifCurrentName);
    g_lnnIpNetworkInfo.isIpLinkClosed = true;
    (void)pthread_mutex_unlock(&g_lnnIpNetworkInfo.lock);
}

static void WifiStateChangeEventHandler(LnnMonitorEventType event, const LnnMoniterData *para)
{
    char ipCurrentAddr[IP_LEN] = {0};
    char ifCurrentName[NET_IF_NAME_LEN] = {0};
    if (event != LNN_MONITOR_EVENT_WIFI_STATE_CHANGED) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "not interest event: %d\n", event);
        return;
    }
    if (pthread_mutex_lock(&g_lnnIpNetworkInfo.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    SoftBusWifiState state = *(SoftBusWifiState *)para->value;
    bool isWifiDisconnect = false;
    if (state == SOFTBUS_WIFI_DISCONNECTED) {
        isWifiDisconnect = true;
    }
    if (UpdateLocalIp(ipCurrentAddr, IP_LEN, ifCurrentName, NET_IF_NAME_LEN, isWifiDisconnect) != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&g_lnnIpNetworkInfo.lock);
        return;
    }
    LeaveOldIpNetwork(ifCurrentName);
    g_lnnIpNetworkInfo.isIpLinkClosed = true;
    (void)pthread_mutex_unlock(&g_lnnIpNetworkInfo.lock);
}

int32_t LnnInitIpNetwork(void)
{
    char ipAddr[IP_LEN] = {0};
    char ifName[NET_IF_NAME_LEN] = {0};

    if (LnnRegisterEventHandler(LNN_MONITOR_EVENT_IP_ADDR_CHANGED, IpAddrChangeEventHandler) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "register ip addr change event handler failed\n");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_MONITOR_EVENT_WIFI_STATE_CHANGED, WifiStateChangeEventHandler) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "register wifi state change event handler failed\n");
        return SOFTBUS_ERR;
    }
    if (pthread_mutex_lock(&g_lnnIpNetworkInfo.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_ERR;
    }
    if (GetUpdateLocalIp(ipAddr, IP_LEN, ifName, NET_IF_NAME_LEN, false) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get new ip info failed\n");
        (void)pthread_mutex_unlock(&g_lnnIpNetworkInfo.lock);
        return SOFTBUS_ERR;
    }
    if (SetLocalIpInfo(ipAddr, ifName) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set local ip info failed\n");
        (void)pthread_mutex_unlock(&g_lnnIpNetworkInfo.lock);
        return SOFTBUS_ERR;
    }
    if (strncmp(ifName, LNN_LOOPBACK_IFNAME, strlen(LNN_LOOPBACK_IFNAME)) != 0) {
        DiscLinkStatusChanged(LINK_STATUS_UP, COAP);
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "open ip link and start discovery\n");           
        if (OpenIpLink() != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "open ip link failed\n");
        }
        if (LnnStartDiscovery() != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "start discovery failed\n");
        }
        SetCallLnnStatus(true);
        g_lnnIpNetworkInfo.isIpLinkClosed = false;
    } else {
        DiscLinkStatusChanged(LINK_STATUS_DOWN, COAP);
    }
    (void)pthread_mutex_unlock(&g_lnnIpNetworkInfo.lock);
    return SOFTBUS_OK;
}

void LnnCallIpDiscovery(void)
{
    char ipCurrentAddr[IP_LEN] = {0};
    char ifCurrentName[NET_IF_NAME_LEN] = {0};

    if (pthread_mutex_lock(&g_lnnIpNetworkInfo.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    if (!g_lnnIpNetworkInfo.isIpLinkClosed) {
        (void)pthread_mutex_unlock(&g_lnnIpNetworkInfo.lock);
        return;
    }
    if (GetLocalIpInfo(ipCurrentAddr, IP_LEN, ifCurrentName, NET_IF_NAME_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get current ip info failed\n");
        (void)pthread_mutex_unlock(&g_lnnIpNetworkInfo.lock);
        return;
    }
    if (strncmp(ifCurrentName, LNN_LOOPBACK_IFNAME, strlen(LNN_LOOPBACK_IFNAME)) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "open ip link and start discovery\n");           
        if (OpenIpLink() != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "open ip link failed\n");
        }
        if (LnnStartDiscovery() != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "start discovery failed\n");
        }
        SetCallLnnStatus(true);
        g_lnnIpNetworkInfo.isIpLinkClosed = false;
    }
    (void)pthread_mutex_unlock(&g_lnnIpNetworkInfo.lock);
}

