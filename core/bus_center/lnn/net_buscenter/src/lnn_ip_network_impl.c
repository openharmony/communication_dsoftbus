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

#include "anonymizer.h"
#include "auth_interface.h"
#include "bus_center_adapter.h"
#include "bus_center_event.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "disc_interface.h"
#include "lnn_async_callback_utils.h"
#include "lnn_common_utils.h"
#include "lnn_discovery_manager.h"
#include "lnn_fast_offline.h"
#include "lnn_ip_utils_adapter.h"
#include "lnn_linkwatch.h"
#include "lnn_log.h"
#include "lnn_net_builder.h"
#include "lnn_network_manager.h"
#include "lnn_physical_subnet_manager.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_timer.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_protocol_def.h"
#include "trans_tcp_direct_listener.h"
#include "conn_coap.h"
#include "lnn_connection_fsm.h"

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
        LNN_LOGE(LNN_BUILDER, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcmp(ifName, WLAN_IFNAME) != 0) {
        return SOFTBUS_NETWORK_GET_IP_ADDR_FAILED;
    }
    if (GetWlanIpv4Addr(ip, size) != SOFTBUS_OK) {
        return SOFTBUS_NETWORK_GET_IP_ADDR_FAILED;
    }
    if (strnlen(ip, size) == 0 || strnlen(ip, size) == size) {
        return SOFTBUS_NETWORK_GET_IP_ADDR_FAILED;
    }
    if (strcmp(ip, LNN_LOOPBACK_IP) == 0 || strcmp(ip, "") == 0 || strcmp(ip, "0.0.0.0") == 0) {
        return SOFTBUS_NETWORK_GET_IP_ADDR_FAILED;
    }
    return SOFTBUS_OK;
}

static int32_t GetIpAddrFromNetlink(const char *ifName, char *ip, uint32_t size)
{
    if (GetNetworkIpByIfName(ifName, ip, NULL, size) != SOFTBUS_OK) {
        return SOFTBUS_NETWORK_GET_IP_ADDR_FAILED;
    }

    if (strcmp(ip, LNN_LOOPBACK_IP) == 0 || strcmp(ip, "") == 0 || strcmp(ip, "0.0.0.0") == 0) {
        LNN_LOGE(LNN_BUILDER, "invalid ip addr");
        return SOFTBUS_NETWORK_GET_IP_ADDR_FAILED;
    }
    return SOFTBUS_OK;
}

static bool GetIpProcess(const char *ifName, char *ip, uint32_t size)
{
    if (GetIpAddrFromNetlink(ifName, ip, size) != SOFTBUS_OK &&
        GetWifiServiceIpAddr(ifName, ip, size) != SOFTBUS_OK) {
        LNN_LOGD(LNN_BUILDER, "get network IP by ifName fail");
        return false;
    }
    return true;
}

static VisitNextChoice NotifyWlanAddressChanged(const LnnNetIfMgr *netifManager, void *data)
{
    if (netifManager->type == LNN_NETIF_TYPE_WLAN) {
        LNN_LOGI(LNN_BUILDER, "notify wlan changed at %{public}" PRIu64, SoftBusGetSysTimeMs());
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
    if (strcmp(ifName, WLAN_IFNAME) != 0) {
        retryTime = 0;
    }
    if (GetIpProcess(ifName, ip, size)) {
        retryTime = GET_IP_RETRY_TIMES;
        return SOFTBUS_OK;
    }
    LNN_LOGD(LNN_BUILDER, "get ip retry time=%{public}d", retryTime);
    if (--retryTime > 0 && LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), RetryGetAvailableIpAddr,
        NULL, GET_IP_INTERVAL_TIME) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "LnnAsyncCallbackDelayHelper get available ip fail");
        return SOFTBUS_NETWORK_GET_IP_ADDR_FAILED;
    }
    if (retryTime <= 0) {
        retryTime = GET_IP_RETRY_TIMES;
    }
    return SOFTBUS_NETWORK_GET_IP_ADDR_FAILED;
}

static int32_t OpenAuthPort(void)
{
    char localIp[MAX_ADDR_LEN] = {0};

    int32_t authPort;
    if (LnnGetLocalNumInfo(NUM_KEY_AUTH_PORT, &authPort) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get port failed");
        authPort = 0;
    }

    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, localIp, MAX_ADDR_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local ip failed");
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    int32_t port = AuthStartListening(AUTH_LINK_TYPE_WIFI, localIp, authPort);
    if (port < 0) {
        LNN_LOGE(LNN_BUILDER, "AuthStartListening failed");
        return SOFTBUS_INVALID_PORT;
    }
    char *anonyIp = NULL;
    Anonymize(localIp, &anonyIp);
    LNN_LOGI(LNN_BUILDER, "open auth port listening on ip=%{public}s", AnonymizeWrapper(anonyIp));
    AnonymizeFree(anonyIp);
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
        LNN_LOGE(LNN_BUILDER, "get port failed");
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
        LNN_LOGE(LNN_BUILDER, "get local ip failed");
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    port = TransTdcStartSessionListener(DIRECT_CHANNEL_SERVER_WIFI, &info);
    if (port < 0) {
        LNN_LOGE(LNN_BUILDER, "open session server failed");
        return SOFTBUS_INVALID_PORT;
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
        LNN_LOGE(LNN_BUILDER, "get port failed");
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
        LNN_LOGE(LNN_BUILDER, "get local ip failed");
        return;
    }
    int32_t port = ConnStartLocalListening(&listenerInfo);
    if (port < 0) {
        LNN_LOGE(LNN_BUILDER, "open proxy server failed");
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
        LNN_LOGE(LNN_BUILDER, "ConnStopLocalListening fail");
    }
    (void)LnnSetLocalNumInfo(NUM_KEY_PROXY_PORT, IP_DEFAULT_PORT);
}

static int32_t OpenIpLink(void)
{
    int32_t ret = OpenAuthPort();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "OpenAuthPort fail");
        return SOFTBUS_NETWORK_PORT_PROCESS_FAILED;
    }
    ret = OpenSessionPort();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "OpenSessionPort fail");
        CloseAuthPort();
        return SOFTBUS_NETWORK_PORT_PROCESS_FAILED;
    }
    OpenProxyPort();
    return SOFTBUS_OK;
}

static void CloseIpLink(void)
{
    CloseAuthPort();
    CloseSessionPort();
    CloseProxyPort();
    LNN_LOGI(LNN_BUILDER, "close port success");
}

static int32_t GetLocalIpInfo(char *ipAddr, uint32_t ipAddrLen, char *ifName, uint32_t ifNameLen)
{
    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, ipAddr, ipAddrLen) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local ip error");
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_NET_IF_NAME, ifName, ifNameLen) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local ifName error");
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SetLocalIpInfo(const char *ipAddr, const char *ifName)
{
    if (LnnSetLocalStrInfo(STRING_KEY_WLAN_IP, ipAddr) != SOFTBUS_OK) {
        return SOFTBUS_NETWORK_SET_NODE_INFO_ERR;
    }
    if (LnnSetLocalStrInfo(STRING_KEY_NET_IF_NAME, ifName) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "set local ifName error");
        return SOFTBUS_NETWORK_SET_NODE_INFO_ERR;
    }
    return SOFTBUS_OK;
}

static void LeaveOldIpNetwork(const char *ifCurrentName)
{
    ConnectionAddrType type = CONNECTION_ADDR_MAX;
    bool addrType[CONNECTION_ADDR_MAX] = {false};

    if (LnnGetAddrTypeByIfName(ifCurrentName, &type) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "LnnGetAddrTypeByIfName failed ifName=%{public}s", ifCurrentName);
        return;
    }
    if (type == CONNECTION_ADDR_MAX) {
        addrType[CONNECTION_ADDR_WLAN] = true;
        addrType[CONNECTION_ADDR_ETH] = true;
    } else {
        addrType[type] = true;
    }
    LNN_LOGI(LNN_BUILDER, "LNN start leave ip network");
    if (LnnRequestLeaveByAddrType(addrType, CONNECTION_ADDR_MAX) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "LNN leave ip network fail");
    }
}

static int32_t ReleaseMainPort(const char *ifName)
{
    char oldMainIf[NET_IF_NAME_LEN] = {0};
    do {
        if (LnnGetLocalStrInfo(STRING_KEY_NET_IF_NAME, oldMainIf, sizeof(oldMainIf)) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "get local ifName error!");
            break;
        }
        if (strcmp(ifName, oldMainIf) != 0) {
            LNN_LOGE(LNN_BUILDER, "if is not main port! ifName=%{public}s", ifName);
            return SOFTBUS_CMP_FAIL;
        }
    } while (false);
    if (SetLocalIpInfo(LNN_LOOPBACK_IP, LNN_LOOPBACK_IFNAME) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "set local ip info failed");
        return SOFTBUS_NETWORK_SET_NODE_INFO_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t RequestMainPort(const char *ifName, const char *address)
{
    if (strcmp(ifName, LNN_LOOPBACK_IFNAME) == 0) {
        LNN_LOGE(LNN_BUILDER, "loopback ifName not allowed");
        return SOFTBUS_CMP_FAIL;
    }
    if (strcmp(address, LNN_LOOPBACK_IP) == 0) {
        LNN_LOGE(LNN_BUILDER, "loopback ip not allowed");
        return SOFTBUS_CMP_FAIL;
    }
    LNN_LOGI(LNN_BUILDER, "get local ifName begin");
    char oldMainIf[NET_IF_NAME_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_NET_IF_NAME, oldMainIf, sizeof(oldMainIf)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local ifName error");
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    LNN_LOGD(LNN_BUILDER, "get local ifName end");
    if (strcmp(oldMainIf, ifName) != 0 && strcmp(oldMainIf, LNN_LOOPBACK_IFNAME) != 0) {
        LNN_LOGE(LNN_BUILDER, "Only 1 local subnet is allowed");
        return SOFTBUS_CMP_FAIL;
    }
    if (SetLocalIpInfo(address, ifName) != SOFTBUS_OK) {
        return SOFTBUS_NETWORK_SET_NODE_INFO_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t EnableIpSubnet(LnnPhysicalSubnet *subnet)
{
    char address[IP_LEN] = {0};

    int32_t ret = GetAvailableIpAddr(subnet->ifName, address, sizeof(address));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get available Ip failed! ifName=%{public}s, ret=%{public}d", subnet->ifName, ret);
        return ret;
    }
    if (RequestMainPort(subnet->ifName, address)) {
        LNN_LOGE(LNN_BUILDER, "request main port failed! ifName=%{public}s", subnet->ifName);
        return SOFTBUS_NETWORK_PORT_PROCESS_FAILED;
    }
    LNN_LOGI(LNN_BUILDER, "open ip link and start discovery");
    if (OpenIpLink() != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "open ip link failed");
        return SOFTBUS_CONN_AUTH_START_LISTEN_FAIL;
    }
    if (ConnCoapStartServerListen() != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "start coap conn server failed");
    }
    if (!LnnIsAutoNetWorkingEnabled()) {
        LNN_LOGI(LNN_BUILDER, "auto network disable");
        return SOFTBUS_OK;
    }
    DiscLinkStatusChanged(LINK_STATUS_UP, COAP);
    if (LnnStartPublish() != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "start publish failed");
    }
    if (LnnStartDiscovery() != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "start discovery failed");
    }
    return SOFTBUS_OK;
}

static int32_t DisableIpSubnet(LnnPhysicalSubnet *subnet)
{
    if (subnet->status == LNN_SUBNET_RUNNING) {
        LnnIpAddrChangeEventHandler();
        CloseIpLink();
        LnnStopPublish();
        LnnStopDiscovery();
        ConnCoapStopServerListen();
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
    ConnCoapStopServerListen();
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
    LNN_LOGD(LNN_BUILDER, "subnet state change. ifName=%{public}s, protocolId=%{public}u, status=%{public}d",
        subnet->ifName, subnet->protocol->id, subnet->status);
}

static IpSubnetManagerEvent GetIpEventInOther(LnnPhysicalSubnet *subnet)
{
    char currentIfAddress[IP_LEN] = {0};
    int32_t ret = GetAvailableIpAddr(subnet->ifName, currentIfAddress, sizeof(currentIfAddress));
    if (ret == SOFTBUS_OK) {
        return IP_SUBNET_MANAGER_EVENT_IF_READY;
    }
    return subnet->status == LNN_SUBNET_SHUTDOWN ? IP_SUBNET_MANAGER_EVENT_IF_DOWN : IP_SUBNET_MANAGER_EVENT_MAX;
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
        LNN_LOGE(LNN_BUILDER, "get main ip info failed");
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
        LNN_LOGI(LNN_BUILDER, "want to enter event=%{public}d", event);
        SoftBusFree(status);
        if (event < IP_SUBNET_MANAGER_EVENT_IF_READY || event > IP_SUBNET_MANAGER_EVENT_MAX) {
            LNN_LOGW(LNN_BUILDER, "is not right event=%{public}d", event);
            return;
        }
    }

    int32_t ret = SOFTBUS_NETWORK_NETIF_STATUS_CHANGED;
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
            return;
    }

    TransactIpSubnetState(subnet, event, (ret == SOFTBUS_OK));
}

static LnnPhysicalSubnet *CreateIpSubnetManager(const struct LnnProtocolManager *self, const char *ifName)
{
    LnnPhysicalSubnet *subnet = (LnnPhysicalSubnet *)SoftBusCalloc(sizeof(LnnPhysicalSubnet));
    if (subnet == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc subnet fail");
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
            LNN_LOGE(LNN_BUILDER, "copy ifName failed ret=%{public}d", ret);
            break;
        }
        return subnet;
    } while (false);

    subnet->destroy((LnnPhysicalSubnet *)subnet);
    return NULL;
}

static void IpAddrChangeEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_IP_ADDR_CHANGED) {
        LNN_LOGE(LNN_BUILDER, "not interest event");
        return;
    }
    const LnnMonitorAddressChangedEvent *event = (const LnnMonitorAddressChangedEvent *)info;
    if (strlen(event->ifName) != 0) {
        LnnNotifyPhysicalSubnetStatusChanged(event->ifName, LNN_PROTOCOL_IP, NULL);
        DfxRecordTriggerTime(WIFI_IP_ADDR_CHANGED, EVENT_STAGE_LNN_WIFI_TRIGGER);
    }
}

static bool WifiStateChangeWifiOrAp(const SoftBusWifiState wifiState)
{
    switch (wifiState) {
        case SOFTBUS_WIFI_CONNECTED:
            g_wifiConnected = true;
            return true;
        case SOFTBUS_WIFI_DISCONNECTED:
            g_wifiConnected = false;
            return true;
        case SOFTBUS_AP_ENABLED:
            g_apEnabled = true;
            return true;
        case SOFTBUS_AP_DISABLED:
            g_apEnabled = false;
            return true;
        default:
            return false;
    }
}

static bool IsValidLocalIp(void)
{
    char localIp[MAX_ADDR_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, localIp, MAX_ADDR_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local ip failed");
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
        LNN_LOGE(LNN_BUILDER, "not interest event");
        return;
    }
    if (!g_heartbeatEnable) {
        LNN_LOGI(LNN_BUILDER, "g_heartbeatEnable not enable");
        return;
    }
    const LnnMonitorWlanStateChangedEvent *event = (const LnnMonitorWlanStateChangedEvent *)info;
    SoftBusWifiState wifiState = (SoftBusWifiState)event->status;
    LNN_LOGI(LNN_BUILDER, "wifi state change. wifiState=%{public}d", wifiState);
    bool beforeConnected = g_apEnabled || g_wifiConnected;
    if (!WifiStateChangeWifiOrAp(wifiState)) {
        LNN_LOGI(LNN_BUILDER, "not interest wifi event");
        return;
    }
    bool currentConnected = g_apEnabled || g_wifiConnected;
    bool isValidIp = IsValidLocalIp();
    LNN_LOGI(LNN_BUILDER,
        "wifi or ap wifiConnected=%{public}d, apEnabled=%{public}d, beforeConnected=%{public}d, "
        "currentConnected=%{public}d, isValidIp=%{public}d",
        g_wifiConnected, g_apEnabled, beforeConnected, currentConnected, isValidIp);
    IpSubnetManagerEvent *status = (IpSubnetManagerEvent *)SoftBusCalloc(sizeof(IpSubnetManagerEvent));
    if (status == NULL) {
        LNN_LOGE(LNN_BUILDER, "wifi start calloc fail");
        return;
    }
    if ((beforeConnected != currentConnected) || (currentConnected && !isValidIp)) {
        LNN_LOGI(LNN_BUILDER, "wifi start to subnet change!");
        if (currentConnected) {
            SoftBusFree(status);
            (void)LnnVisitNetif(NotifyWlanAddressChanged, NULL);
        } else {
            *status = IP_SUBNET_MANAGER_EVENT_IF_DOWN;
            (void)LnnVisitNetif(NotifyWlanAddressChanged, status);
        }
        return;
    }
    SoftBusFree(status);
}

int32_t LnnInitIpProtocol(struct LnnProtocolManager *self)
{
    (void)self;
    int32_t ret = SOFTBUS_OK;
    if (LnnRegisterEventHandler(LNN_EVENT_IP_ADDR_CHANGED, IpAddrChangeEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "register ip addr change event handler failed");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    if (SetLocalIpInfo(LNN_LOOPBACK_IP, LNN_LOOPBACK_IFNAME) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init local ip as loopback failed!");
        return SOFTBUS_NETWORK_SET_NODE_INFO_ERR;
    }
    DiscLinkStatusChanged(LINK_STATUS_DOWN, COAP);
    g_heartbeatEnable = IsEnableSoftBusHeartbeat();
    LNN_LOGI(LNN_INIT, "init IP protocol g_heartbeatEnable=%{public}d", g_heartbeatEnable);
    return ret;
}

int32_t LnnEnableIpProtocol(struct LnnProtocolManager *self, LnnNetIfMgr *netifMgr)
{
    (void)self;
    if (netifMgr == NULL) {
        LNN_LOGE(LNN_BUILDER, "netif mgr is null");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnPhysicalSubnet *manager = CreateIpSubnetManager(self, netifMgr->ifName);
    if (manager == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc subnet mgr fail");
        return SOFTBUS_MALLOC_ERR;
    }
    int ret = LnnRegistPhysicalSubnet(manager);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "regist subnet manager failed! ret=%{public}d", ret);
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
    LNN_LOGW(LNN_INIT, "ip network deinited");
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
