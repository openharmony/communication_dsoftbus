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

#include <securec.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "auth_interface.h"
#include "bus_center_event.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "disc_interface.h"
#include "lnn_async_callback_utils.h"
#include "lnn_common_utils.h"
#include "lnn_discovery_manager.h"
#include "lnn_fast_offline.h"
#include "lnn_ip_utils_adapter.h"
#include "bus_center_adapter.h"
#include "lnn_linkwatch.h"
#include "lnn_net_builder.h"
#include "lnn_network_manager.h"
#include "lnn_physical_subnet_manager.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_timer.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "softbus_protocol_def.h"
#include "trans_tcp_direct_listener.h"

#define IP_DEFAULT_PORT 0
#define LNN_LOOPBACK_IP "127.0.0.1"
#define WLAN_IFNAME "wlan0"

static bool g_wifiConnected = false;
static bool g_apEnabled = false;
static bool g_heartbeatEnable = false;

#define GET_IP_RETRY_TIMES 10
#define GET_IP_INTERVAL_TIME 500 // uint:ms

static int32_t GetWifiServiceIpAddr(const char *ifName, char *ip, uint32_t size)
{
    if (ifName == NULL || ip == NULL || size == 0) {
        return SOFTBUS_ERR;
    }
    if (strcmp(ifName, WLAN_IFNAME) != 0) {
        LLOGE("ifname isn't expected, ifname:%s", ifName);
        return SOFTBUS_ERR;
    }
    if (GetWlanIpv4Addr(ip, size) != SOFTBUS_OK) {
        LLOGE("get wlan ip addr from wifiservice fail");
        return SOFTBUS_ERR;
    }
    if (strnlen(ip, size) == 0 || strnlen(ip, size) == size) {
        LLOGE("get ipAddr fail, from wifiService");
        return SOFTBUS_ERR;
    }
    if (strcmp(ip, LNN_LOOPBACK_IP) == 0 || strcmp(ip, "") == 0 || strcmp(ip, "0.0.0.0") == 0) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t GetIpAddrFromNetlink(const char *ifName, char *ip, uint32_t size)
{
    if (GetNetworkIpByIfName(ifName, ip, NULL, size) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:get network IP by ifName failed!", __func__);
        return SOFTBUS_ERR;
    }

    if (strcmp(ip, LNN_LOOPBACK_IP) == 0 || strcmp(ip, "") == 0 || strcmp(ip, "0.0.0.0") == 0) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static bool GetIpProcess(const char *ifName, char *ip, uint32_t size)
{
    if (GetIpAddrFromNetlink(ifName, ip, size) != SOFTBUS_OK &&
        GetWifiServiceIpAddr(ifName, ip, size) != SOFTBUS_OK) {
        LLOGE("get network IP by ifName failed!");
        return false;
    }
    return true;
}

static VisitNextChoice NotifyWlanAddressChanged(const LnnNetIfMgr *netifManager, void *data)
{
    if (netifManager->type == LNN_NETIF_TYPE_WLAN) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "%s: notify wlan changed", __func__);
        LnnNotifyPhysicalSubnetStatusChanged(netifManager->ifName, LNN_PROTOCOL_IP, data);
    }
    return CHOICE_VISIT_NEXT;
}

static void RetryGetAvailableIpAddr(void *para)
{
    (void)para;
    (void)LnnVisitNetif(NotifyWlanAddressChanged, NULL);
}

static int32_t GetAvailableIpAddr(const char *ifName, char *ip, uint32_t size)
{
    static int32_t retryTime = GET_IP_RETRY_TIMES;
    if (!LnnIsLinkReady(ifName)) {
        LLOGE("ifName %s link not ready", ifName);
    }
    if (strcmp(ifName, WLAN_IFNAME) != 0) {
        retryTime = 0;
    }
    if (GetIpProcess(ifName, ip, size)) {
        retryTime = GET_IP_RETRY_TIMES;
        return SOFTBUS_OK;
    }
    LLOGI("get ip retry time :%d", retryTime);
    if (--retryTime > 0 && LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), RetryGetAvailableIpAddr,
        NULL, GET_IP_INTERVAL_TIME) != SOFTBUS_OK) {
        LLOGE("LnnAsyncCallbackDelayHelper get available ip fail.");
        return SOFTBUS_ERR;
    }
    if (retryTime <= 0) {
        retryTime = GET_IP_RETRY_TIMES;
    }
    return SOFTBUS_ERR;
}

static int32_t OpenAuthPort(void)
{
    int32_t port;
    char localIp[MAX_ADDR_LEN] = {0};

    int32_t authPort;
    if (LnnGetLocalNumInfo(NUM_KEY_AUTH_PORT, &authPort) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get port failed");
        authPort = 0;
    }

    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, localIp, MAX_ADDR_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local ip failed");
        return SOFTBUS_ERR;
    }
    port = AuthStartListening(AUTH_LINK_TYPE_WIFI, localIp, authPort);
    if (port < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "AuthStartListening failed");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "open auth port listening on ip:%s", AnonymizesIp(localIp));
    if (authPort == 0) {
        return LnnSetLocalNumInfo(NUM_KEY_AUTH_PORT, port);
    }
    return SOFTBUS_OK;
}

static void CloseAuthPort(void)
{
    AuthStopListening(AUTH_LINK_TYPE_WIFI);
    (void)LnnSetLocalNumInfo(NUM_KEY_AUTH_PORT, IP_DEFAULT_PORT);
}

static int32_t OpenSessionPort(void)
{
    int32_t sessionPort;
    if (LnnGetLocalNumInfo(NUM_KEY_SESSION_PORT, &sessionPort) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get port failed");
        sessionPort = 0;
    }

    int32_t port;
    LocalListenerInfo info = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = "",
            .port = sessionPort,
            .moduleId = DIRECT_CHANNEL_SERVER_WIFI,
            .protocol = LNN_PROTOCOL_IP,
        }
    };
    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, info.socketOption.addr, sizeof(info.socketOption.addr)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local ip failed\n");
        return SOFTBUS_ERR;
    }
    port = TransTdcStartSessionListener(DIRECT_CHANNEL_SERVER_WIFI, &info);
    if (port < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "open session server failed");
        return SOFTBUS_ERR;
    }
    if (sessionPort == 0) {
        return LnnSetLocalNumInfo(NUM_KEY_SESSION_PORT, port);
    }

    return SOFTBUS_OK;
}

static void CloseSessionPort(void)
{
    TransTdcStopSessionListener(DIRECT_CHANNEL_SERVER_WIFI);
    (void)LnnSetLocalNumInfo(NUM_KEY_SESSION_PORT, IP_DEFAULT_PORT);
}

static void OpenProxyPort(void)
{
    int32_t proxyPort;
    if (LnnGetLocalNumInfo(NUM_KEY_PROXY_PORT, &proxyPort) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get port failed");
        proxyPort = 0;
    }

    LocalListenerInfo listenerInfo = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = "",
            .port = proxyPort,
            .moduleId = PROXY,
            .protocol = LNN_PROTOCOL_IP,
        }
    };
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, listenerInfo.socketOption.addr,
        sizeof(listenerInfo.socketOption.addr));
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local ip failed\n");
        return;
    }
    int32_t port = ConnStartLocalListening(&listenerInfo);
    if (port < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "open proxy server failed");
        return;
    }
    if (proxyPort == 0) {
        (void)LnnSetLocalNumInfo(NUM_KEY_PROXY_PORT, port);
    }
}

static void CloseProxyPort(void)
{
    LocalListenerInfo listenerInfo = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = "",
            .port = 0,
            .moduleId = PROXY,
            .protocol = LNN_PROTOCOL_IP,
        }
    };
    if (ConnStopLocalListening(&listenerInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ConnStopLocalListening fail!");
    }
    (void)LnnSetLocalNumInfo(NUM_KEY_PROXY_PORT, IP_DEFAULT_PORT);
}

static int32_t OpenIpLink(void)
{
    int32_t ret = OpenAuthPort();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OpenAuthPort fail!");
        return SOFTBUS_ERR;
    }
    ret = OpenSessionPort();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OpenSessionPort fail!");
        CloseAuthPort();
        return SOFTBUS_ERR;
    }
    OpenProxyPort();
    return SOFTBUS_OK;
}

static void CloseIpLink(void)
{
    CloseAuthPort();
    CloseSessionPort();
    CloseProxyPort();
}

static int32_t GetLocalIpInfo(char *ipAddr, uint32_t ipAddrLen, char *ifName, uint32_t ifNameLen)
{
    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, ipAddr, ipAddrLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local ip error!");
        return SOFTBUS_ERR;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_NET_IF_NAME, ifName, ifNameLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local ifName error!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SetLocalIpInfo(const char *ipAddr, const char *ifName)
{
    if (LnnSetLocalStrInfo(STRING_KEY_WLAN_IP, ipAddr) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set local ip error!");
        return SOFTBUS_ERR;
    }
    if (LnnSetLocalStrInfo(STRING_KEY_NET_IF_NAME, ifName) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set local ifName error!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void LeaveOldIpNetwork(const char *ifCurrentName)
{
    ConnectionAddrType type = CONNECTION_ADDR_MAX;
    bool addrType[CONNECTION_ADDR_MAX] = {0};

    if (LnnGetAddrTypeByIfName(ifCurrentName, &type) != SOFTBUS_OK) {
        SoftBusLog(
            SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:LnnGetAddrTypeByIfName failed! ifName=%s", __func__, ifCurrentName);
        return;
    }
    if (type == CONNECTION_ADDR_MAX) {
        addrType[CONNECTION_ADDR_WLAN] = true;
        addrType[CONNECTION_ADDR_ETH] = true;
    } else {
        addrType[type] = true;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LNN start leave ip network");
    if (LnnRequestLeaveByAddrType(addrType, CONNECTION_ADDR_MAX) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LNN leave ip network fail");
    }
}

static int32_t ReleaseMainPort(const char *ifName)
{
    char oldMainIf[NET_IF_NAME_LEN] = {0};
    do {
        if (LnnGetLocalStrInfo(STRING_KEY_NET_IF_NAME, oldMainIf, sizeof(oldMainIf)) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:get local ifName error!", __func__);
            break;
        }
        if (strcmp(ifName, oldMainIf) != 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ifName %s is not main port!", ifName);
            return SOFTBUS_ERR;
        }
    } while (false);
    if (SetLocalIpInfo(LNN_LOOPBACK_IP, LNN_LOOPBACK_IFNAME) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:set local ip info failed", __func__);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t RequestMainPort(const char *ifName, const char *address)
{
    if (strcmp(ifName, LNN_LOOPBACK_IFNAME) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "loopback ifName not allowed!");
        return SOFTBUS_ERR;
    }
    if (strcmp(address, LNN_LOOPBACK_IP) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "loopback ip not allowed!");
        return SOFTBUS_ERR;
    }
    char oldMainIf[NET_IF_NAME_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_NET_IF_NAME, oldMainIf, sizeof(oldMainIf)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local ifName error!");
        return SOFTBUS_ERR;
    }
    if (strcmp(oldMainIf, ifName) != 0 && strcmp(oldMainIf, LNN_LOOPBACK_IFNAME) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Only 1 local subnet is allowed!");
        return SOFTBUS_ERR;
    }
    if (SetLocalIpInfo(address, ifName) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set local ip info failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t EnableIpSubnet(LnnPhysicalSubnet *subnet)
{
    char address[IP_LEN] = {0};

    int32_t ret = GetAvailableIpAddr(subnet->ifName, address, sizeof(address));
    if (ret != SOFTBUS_OK) {
        SoftBusLog(
            SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get available Ip failed!ifName=%s, ret=%d", subnet->ifName, ret);
        return ret;
    }
    if (RequestMainPort(subnet->ifName, address)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "request main port failed! ifName=%s", subnet->ifName);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "open ip link and start discovery");
    if (OpenIpLink() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "open ip link failed");
    }
    if (!LnnIsAutoNetWorkingEnabled()) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "auto network disable");
        return SOFTBUS_OK;
    }
    DiscLinkStatusChanged(LINK_STATUS_UP, COAP);
    if (LnnStartPublish() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "start publish failed");
    }
    if (LnnStartDiscovery() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "start discovery failed");
    }
    SetCallLnnStatus(true);
    return SOFTBUS_OK;
}

static int32_t DisableIpSubnet(LnnPhysicalSubnet *subnet)
{
    if (subnet->status == LNN_SUBNET_RUNNING) {
        LnnIpAddrChangeEventHandler();
        CloseIpLink();
        LnnStopPublish();
        LnnStopDiscovery();
        DiscLinkStatusChanged(LINK_STATUS_DOWN, COAP);
        LeaveOldIpNetwork(subnet->ifName);
        ReleaseMainPort(subnet->ifName);
    }
    return SOFTBUS_OK;
}

static int32_t ChangeIpSubnetAddress(LnnPhysicalSubnet *subnet)
{
    CloseIpLink();
    LnnStopPublish();
    LnnStopDiscovery();
    DiscLinkStatusChanged(LINK_STATUS_DOWN, COAP);
    LeaveOldIpNetwork(subnet->ifName);
    return SOFTBUS_OK;
}

static void DestroyIpSubnetManager(LnnPhysicalSubnet *subnet)
{
    if (subnet->status == LNN_SUBNET_RUNNING) {
        DisableIpSubnet(subnet);
    }
    SoftBusFree(subnet);
}

typedef enum {
    IP_SUBNET_MANAGER_EVENT_IF_READY,
    IP_SUBNET_MANAGER_EVENT_IF_DOWN,    // addr change from available to
    IP_SUBNET_MANAGER_EVENT_IF_CHANGED, // addr changed
    IP_SUBNET_MANAGER_EVENT_MAX
} IpSubnetManagerEvent;

typedef enum {
    IP_EVENT_RESULT_ACCEPTED = 0,
    IP_EVENT_RESULT_REJECTED,
    IP_EVENT_RESULT_OPTION_COUNT
} IpSubnetManagerEventResultOptions;

static void TransactIpSubnetState(LnnPhysicalSubnet *subnet, IpSubnetManagerEvent event, bool isAccepted)
{
    LnnPhysicalSubnetStatus transactMap[][IP_EVENT_RESULT_OPTION_COUNT] = {
        [IP_SUBNET_MANAGER_EVENT_IF_READY] = {LNN_SUBNET_RUNNING, LNN_SUBNET_IDLE},
        [IP_SUBNET_MANAGER_EVENT_IF_DOWN] = {LNN_SUBNET_SHUTDOWN, subnet->status},
        [IP_SUBNET_MANAGER_EVENT_IF_CHANGED] = {LNN_SUBNET_RESETTING, subnet->status}
    };
    subnet->status = transactMap[event][isAccepted ? IP_EVENT_RESULT_ACCEPTED : IP_EVENT_RESULT_REJECTED];
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "subnet [%s, %u] state change to %d", subnet->ifName,
        subnet->protocol->id, subnet->status);
}

static IpSubnetManagerEvent GetIpEventInOther(LnnPhysicalSubnet *subnet)
{
    char currentIfAddress[IP_LEN] = {0};
    int32_t ret = GetAvailableIpAddr(subnet->ifName, currentIfAddress, sizeof(currentIfAddress));
    if (ret == SOFTBUS_OK) {
        return IP_SUBNET_MANAGER_EVENT_IF_READY;
    } else {
        return subnet->status == LNN_SUBNET_SHUTDOWN ? IP_SUBNET_MANAGER_EVENT_IF_DOWN : IP_SUBNET_MANAGER_EVENT_MAX;
    }
}

static IpSubnetManagerEvent GetIpEventInRunning(LnnPhysicalSubnet *subnet)
{
    char currentIfAddress[IP_LEN] = {0};
    int32_t ret = GetAvailableIpAddr(subnet->ifName, currentIfAddress, sizeof(currentIfAddress));
    if (ret != SOFTBUS_OK) {
        return IP_SUBNET_MANAGER_EVENT_IF_DOWN;
    }

    char localIpAddr[IP_LEN] = {0};
    char localNetifName[NET_IF_NAME_LEN] = {0};
    if (GetLocalIpInfo(localIpAddr, sizeof(localIpAddr), localNetifName, sizeof(localNetifName)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get main ip info failed");
        return IP_SUBNET_MANAGER_EVENT_IF_READY;
    }
    if (strcmp(localNetifName, subnet->ifName) != 0) {
        return IP_SUBNET_MANAGER_EVENT_IF_READY;
    }
    if (strcmp(localIpAddr, currentIfAddress) == 0) {
        return IP_SUBNET_MANAGER_EVENT_MAX;
    } else {
        return IP_SUBNET_MANAGER_EVENT_IF_CHANGED;
    }
}

static void OnSoftbusIpNetworkDisconnected(LnnPhysicalSubnet *subnet)
{
    if (subnet->status == LNN_SUBNET_RESETTING || subnet->status == LNN_SUBNET_IDLE) {
        int32_t ret = EnableIpSubnet(subnet);
        TransactIpSubnetState(subnet, IP_SUBNET_MANAGER_EVENT_IF_READY, (ret == SOFTBUS_OK));
    }
}

static void OnIpNetifStatusChanged(LnnPhysicalSubnet *subnet, void *status)
{
    IpSubnetManagerEvent event = IP_SUBNET_MANAGER_EVENT_MAX;
    if (status == NULL) {
        if (subnet->status == LNN_SUBNET_RUNNING) {
            event = GetIpEventInRunning(subnet);
        } else {
            event = GetIpEventInOther(subnet);
        }
    } else {
        event = *(IpSubnetManagerEvent *)status;
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "want to enter event %d", event);
        SoftBusFree(status);
        if (event < IP_SUBNET_MANAGER_EVENT_IF_READY || event > IP_SUBNET_MANAGER_EVENT_MAX) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "is not right event %d", event);
            return;
        }
    }

    int32_t ret = SOFTBUS_ERR;
    switch (event) {
        case IP_SUBNET_MANAGER_EVENT_IF_READY: {
            ret = EnableIpSubnet(subnet);
            break;
        }
        case IP_SUBNET_MANAGER_EVENT_IF_DOWN: {
            ret = DisableIpSubnet(subnet);
            break;
        }
        case IP_SUBNET_MANAGER_EVENT_IF_CHANGED: {
            ret = ChangeIpSubnetAddress(subnet);
            break;
        }
        default:
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "discard unexpected event %d", event);
            return;
    }

    TransactIpSubnetState(subnet, event, (ret == SOFTBUS_OK));
}

static LnnPhysicalSubnet *CreateIpSubnetManager(const struct LnnProtocolManager *self, const char *ifName)
{
    LnnPhysicalSubnet *subnet = (LnnPhysicalSubnet *)SoftBusCalloc(sizeof(LnnPhysicalSubnet));
    if (subnet == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:oom", __func__);
        return NULL;
    }

    do {
        subnet->destroy = DestroyIpSubnetManager;
        subnet->protocol = self;
        subnet->status = LNN_SUBNET_IDLE;
        subnet->onNetifStatusChanged = OnIpNetifStatusChanged;
        subnet->onSoftbusNetworkDisconnected = OnSoftbusIpNetworkDisconnected;

        int32_t ret = strcpy_s(subnet->ifName, sizeof(subnet->ifName), ifName);
        if (ret != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:copy ifName failed! ret=%d", __func__, ret);
            break;
        }
        return subnet;
    } while (false);

    subnet->destroy((LnnPhysicalSubnet *)subnet);
    return NULL;
}

static VisitNextChoice NotifyIpAddressChanged(const LnnPhysicalSubnet *subnet, void *data)
{
    (void)data;
    if (subnet->protocol->id == LNN_PROTOCOL_IP) {
        LnnNotifyPhysicalSubnetStatusChanged(subnet->ifName, LNN_PROTOCOL_IP, NULL);
    }
    return CHOICE_VISIT_NEXT;
}

static void IpAddrChangeEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_IP_ADDR_CHANGED) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "not interest event");
        return;
    }
    const LnnMonitorAddressChangedEvent *event = (const LnnMonitorAddressChangedEvent *)info;
    if (strlen(event->ifName) != 0) {
        LnnNotifyPhysicalSubnetStatusChanged(event->ifName, LNN_PROTOCOL_IP, NULL);
    } else {
        (void)LnnVisitPhysicalSubnet(NotifyIpAddressChanged, NULL);
    }
}

static bool IsValidLocalIp(void)
{
    char localIp[MAX_ADDR_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, localIp, MAX_ADDR_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local ip failed");
        return false;
    }
    if (strcmp(localIp, LNN_LOOPBACK_IP) == 0 || strcmp(localIp, "") == 0 || strcmp(localIp, "0.0.0.0") == 0) {
        return false;
    }
    return true;
}

static void WifiStateChangeEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_WIFI_STATE_CHANGED) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:not interest event", __func__);
        return;
    }
    if (!g_heartbeatEnable) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "%s:g_heartbeatEnable not enable", __func__);
        return;
    }
    bool beforeConnected = false;
    bool currentConnected = false;
    bool isValidIp = false;
    const LnnMonitorWlanStateChangedEvent *event = (const LnnMonitorWlanStateChangedEvent *)info;
    SoftBusWifiState wifiState = (SoftBusWifiState)event->status;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "wifi state change wifiState = %d", wifiState);
    beforeConnected = g_apEnabled || g_wifiConnected;
    switch (wifiState) {
        case SOFTBUS_WIFI_CONNECTED:
            g_wifiConnected = true;
            break;
        case SOFTBUS_WIFI_DISCONNECTED:
            g_wifiConnected = false;
            break;
        case SOFTBUS_AP_ENABLED:
             g_apEnabled = true;
            break;
        case SOFTBUS_AP_DISABLED:
            g_apEnabled = false;
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "%s:not interest wifi event", __func__);
            return;
    }
    currentConnected = g_apEnabled || g_wifiConnected;
    isValidIp = IsValidLocalIp();
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
        "wifi or ap wifiConnected = %d, apEnabled = %d, beforeConnected = %d, currentConnected = %d, isValidIp = %d",
        g_wifiConnected, g_apEnabled, beforeConnected, currentConnected, isValidIp);
    IpSubnetManagerEvent *status = (IpSubnetManagerEvent *)SoftBusCalloc(sizeof(IpSubnetManagerEvent));
    if (status == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "wifi start calloc fail");
        return;
    }
    if ((beforeConnected != currentConnected) || (currentConnected && !isValidIp)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "wifi start to subnet change!");
        if (currentConnected) {
            SoftBusFree(status);
            (void)LnnVisitNetif(NotifyWlanAddressChanged, NULL);
        } else {
            *status = IP_SUBNET_MANAGER_EVENT_IF_DOWN;
            (void)LnnVisitNetif(NotifyWlanAddressChanged, status);
        }
    }
}

int32_t LnnInitIpProtocol(struct LnnProtocolManager *self)
{
    (void)self;
    int32_t ret = SOFTBUS_OK;
    if (LnnRegisterEventHandler(LNN_EVENT_IP_ADDR_CHANGED, IpAddrChangeEventHandler) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "register ip addr change event handler failed");
        return SOFTBUS_ERR;
    }
    if (SetLocalIpInfo(LNN_LOOPBACK_IP, LNN_LOOPBACK_IFNAME) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init local ip as loopback failed!");
        return SOFTBUS_ERR;
    }
    DiscLinkStatusChanged(LINK_STATUS_DOWN, COAP);
    g_heartbeatEnable = IsEnableSoftBusHeartbeat();
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "init IP protocol g_heartbeatEnable = %d!", g_heartbeatEnable);
    return ret;
}

int32_t LnnEnableIpProtocol(struct LnnProtocolManager *self, LnnNetIfMgr *netifMgr)
{
    (void)self;
    if (netifMgr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:null ptr!", __func__);
        return SOFTBUS_ERR;
    }
    LnnPhysicalSubnet *manager = CreateIpSubnetManager(self, netifMgr->ifName);
    if (manager == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:oom!", __func__);
        return SOFTBUS_ERR;
    }
    int ret = LnnRegistPhysicalSubnet(manager);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:regist subnet manager failed! ret=%d", __func__, ret);
        manager->destroy(manager);
        return ret;
    }
    return SOFTBUS_OK;
}

static ListenerModule LnnGetIpListenerModule(ListenerMode mode)
{
    if (mode == LNN_LISTENER_MODE_PROXY) {
        return PROXY;
    } else if (mode == LNN_LISTENER_MODE_DIRECT) {
        return DIRECT_CHANNEL_SERVER_WIFI;
    } else {
        return UNUSE_BUTT;
    }
}

void LnnDeinitIpNetwork(struct LnnProtocolManager *self)
{
    (void)self;
    LnnUnregisterEventHandler(LNN_EVENT_IP_ADDR_CHANGED, IpAddrChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_WIFI_STATE_CHANGED, WifiStateChangeEventHandler);
    LnnUnregistPhysicalSubnetByType(LNN_PROTOCOL_IP);
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_WARN, "%s:ip network deinited", __func__);
}

static LnnProtocolManager g_ipProtocol = {
    .init = LnnInitIpProtocol,
    .deinit = LnnDeinitIpNetwork,
    .enable = LnnEnableIpProtocol,
    .disable = NULL,
    .getListenerModule = LnnGetIpListenerModule,
    .id = LNN_PROTOCOL_IP,
    .supportedNetif = LNN_NETIF_TYPE_ETH | LNN_NETIF_TYPE_WLAN,
    .pri = 10,
};

int32_t RegistIPProtocolManager(void)
{
    return LnnRegistProtocol(&g_ipProtocol);
}
