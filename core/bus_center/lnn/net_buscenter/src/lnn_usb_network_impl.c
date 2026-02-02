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
#include "lnn_connection_fsm.h"
#include "lnn_discovery_manager.h"
#include "lnn_ip_utils_adapter.h"
#include "lnn_linkwatch.h"
#include "lnn_log.h"
#include "lnn_net_builder.h"
#include "lnn_network_manager.h"
#include "lnn_physical_subnet_manager.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_protocol_def.h"
#include "trans_tcp_direct_listener.h"

#define IP_DEFAULT_PORT 0
#define LNN_LOOPBACK_IPV6 "::1"

#define GET_IP_RETRY_TIMES 1
#define GET_IP_INTERVAL_TIME 500 // uint:ms

static bool IsValidUsbIfname(const char* ifname)
{
    if (ifname != NULL &&
        ((strstr(ifname, "ncm") != NULL) || (strstr(ifname, "wwan") != NULL))) {
        return true;
    }
    return false;
}

static void UpdateUsbNetCap(bool isSet)
{
    uint32_t netCapability = 0;
    if (LnnGetLocalNumU32Info(NUM_KEY_NET_CAP, &netCapability) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get netcap fail");
        return;
    }
    if (isSet) {
        (void)LnnSetNetCapability(&netCapability, BIT_USB);
    } else {
        (void)LnnClearNetCapability(&netCapability, BIT_USB);
    }
    if (LnnSetLocalNumInfo(NUM_KEY_NET_CAP, (int32_t)netCapability) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "set cap to local ledger fail");
        return;
    }
}

static int32_t GetIpAddrFromNetlink(const char *ifName, char *ip, uint32_t size)
{
    if (GetNetworkIpv6ByIfName(ifName, ip, size) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get ip by ifname fail");
        return SOFTBUS_NETWORK_GET_IP_ADDR_FAILED;
    }

    if (strcmp(ip, LNN_LOOPBACK_IPV6) == 0 || strcmp(ip, "") == 0) {
        LNN_LOGE(LNN_BUILDER, "invalid ip addr");
        return SOFTBUS_NETWORK_GET_IP_ADDR_FAILED;
    }
    return SOFTBUS_OK;
}

static bool GetIpProcess(const char *ifName, char *ip, uint32_t size)
{
    if (GetIpAddrFromNetlink(ifName, ip, size) != SOFTBUS_OK) {
        LNN_LOGD(LNN_BUILDER, "get network IP by ifName fail");
        return false;
    }
    return true;
}

static VisitNextChoice NotifyUsbAddressChanged(const LnnNetIfMgr *netifManager, void *data)
{
    if (netifManager != NULL && netifManager->type == LNN_NETIF_TYPE_USB) {
        LNN_LOGI(LNN_BUILDER, "notify usb changed at %{public}" PRIu64, SoftBusGetSysTimeMs());
        LnnNotifyPhysicalSubnetStatusChanged(netifManager->ifName, LNN_PROTOCOL_USB, data);
    }
    return CHOICE_VISIT_NEXT;
}

static void RetryGetAvailableIpAddr(void *para)
{
    (void)para;
    (void)LnnVisitNetif(NotifyUsbAddressChanged, NULL);
}

static int32_t GetAvailableIpAddr(const char *ifName, char *ip, uint32_t size)
{
    static int32_t retryTime = GET_IP_RETRY_TIMES;
    if (!IsValidUsbIfname(ifName)) {
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
    if (LnnGetLocalNumInfoByIfnameIdx(NUM_KEY_AUTH_PORT, &authPort, USB_IF) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get port failed");
        authPort = 0;
    }

    if (LnnGetLocalStrInfoByIfnameIdx(STRING_KEY_IP6_WITH_IF, localIp, MAX_ADDR_LEN, USB_IF) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local ip failed");
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    int32_t port = AuthStartListening(AUTH_LINK_TYPE_USB, localIp, authPort);
    if (port < 0) {
        LNN_LOGE(LNN_BUILDER, "AuthStartListening failed");
        return SOFTBUS_INVALID_PORT;
    }
    char *anonyIp = NULL;
    Anonymize(localIp, &anonyIp);
    LNN_LOGI(LNN_BUILDER, "open auth port listening on ip=%{public}s", AnonymizeWrapper(anonyIp));
    AnonymizeFree(anonyIp);
    if (authPort == 0) {
        return LnnSetLocalNumInfoByIfnameIdx(NUM_KEY_AUTH_PORT, port, USB_IF);
    }
    return SOFTBUS_OK;
}

static void CloseAuthPort(void)
{
    AuthStopListening(AUTH_LINK_TYPE_USB);
    (void)LnnSetLocalNumInfoByIfnameIdx(NUM_KEY_AUTH_PORT, IP_DEFAULT_PORT, USB_IF);
}

static int32_t OpenSessionPort(void)
{
    int32_t sessionPort = 0;
    if (LnnGetLocalNumInfoByIfnameIdx(NUM_KEY_SESSION_PORT, &sessionPort, USB_IF) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get port failed, use default value.");
    }

    LocalListenerInfo info = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = "",
            .port = sessionPort,
            .moduleId = DIRECT_CHANNEL_SERVER_USB,
            .protocol = LNN_PROTOCOL_USB,
        }
    };
    if (LnnGetLocalStrInfoByIfnameIdx(STRING_KEY_IP6_WITH_IF, info.socketOption.addr,
        sizeof(info.socketOption.addr), USB_IF) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local ip failed");
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    int32_t port = TransTdcStartSessionListener(DIRECT_CHANNEL_SERVER_WIFI, &info);
    if (port < 0) {
        LNN_LOGE(LNN_BUILDER, "open session server failed");
        return SOFTBUS_INVALID_PORT;
    }
    if (sessionPort == 0) {
        return LnnSetLocalNumInfoByIfnameIdx(NUM_KEY_SESSION_PORT, port, USB_IF);
    }

    return SOFTBUS_OK;
}

static void CloseSessionPort(void)
{
    TransTdcStopSessionListener(DIRECT_CHANNEL_SERVER_USB);
    (void)LnnSetLocalNumInfoByIfnameIdx(NUM_KEY_SESSION_PORT, IP_DEFAULT_PORT, USB_IF);
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
    return SOFTBUS_OK;
}

static void CloseIpLink(void)
{
    CloseAuthPort();
    CloseSessionPort();
    LNN_LOGI(LNN_BUILDER, "close port success");
}

static int32_t GetLocalIpInfo(char *ipAddr, uint32_t ipAddrLen, char *ifName, uint32_t ifNameLen)
{
    if (LnnGetLocalStrInfoByIfnameIdx(STRING_KEY_IP, ipAddr, ipAddrLen, USB_IF) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local ip error");
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    if (LnnGetLocalStrInfoByIfnameIdx(STRING_KEY_NET_IF_NAME, ifName, ifNameLen, USB_IF) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local ifName error");
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SetLocalIpInfo(const char *ipAddr, const char *ifName)
{
    if (LnnSetLocalStrInfoByIfnameIdx(STRING_KEY_IP, ipAddr, USB_IF) != SOFTBUS_OK) {
        return SOFTBUS_NETWORK_SET_NODE_INFO_ERR;
    }
    if (LnnSetLocalStrInfoByIfnameIdx(STRING_KEY_NET_IF_NAME, ifName, USB_IF) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "set local ifName error");
        return SOFTBUS_NETWORK_SET_NODE_INFO_ERR;
    }
    return SOFTBUS_OK;
}

static void LeaveOldIpNetwork(const char *ifCurrentName)
{
    ConnectionAddrType type = CONNECTION_ADDR_MAX;
    bool addrType[CONNECTION_ADDR_MAX] = { false };

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
    if (LnnRequestLeaveByAddrType(addrType, CONNECTION_ADDR_MAX, false) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "LNN leave ip network fail");
    }
}

static int32_t ReleaseMainPort(const char *ifName)
{
    char oldMainIf[NET_IF_NAME_LEN] = {0};
    do {
        if (LnnGetLocalStrInfoByIfnameIdx(
            STRING_KEY_NET_IF_NAME, oldMainIf, sizeof(oldMainIf), USB_IF) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "get local ifName error!");
            break;
        }
        if (strcmp(ifName, oldMainIf) != 0) {
            LNN_LOGE(LNN_BUILDER, "if is not main port! ifName=%{public}s", ifName);
            return SOFTBUS_CMP_FAIL;
        }
    } while (false);
    if (SetLocalIpInfo(LNN_LOOPBACK_IPV6, LNN_LOOPBACK_IFNAME) != SOFTBUS_OK) {
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
    if (strcmp(address, LNN_LOOPBACK_IPV6) == 0) {
        LNN_LOGE(LNN_BUILDER, "loopback ip not allowed");
        return SOFTBUS_CMP_FAIL;
    }
    LNN_LOGI(LNN_BUILDER, "get local ifName begin");
    char oldMainIf[NET_IF_NAME_LEN] = {0};
    if (LnnGetLocalStrInfoByIfnameIdx(STRING_KEY_NET_IF_NAME, oldMainIf, sizeof(oldMainIf), USB_IF) != SOFTBUS_OK) {
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
    if (OpenIpLink() != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "open ip link failed");
        return SOFTBUS_CONN_AUTH_START_LISTEN_FAIL;
    }
    UpdateUsbNetCap(true);
    DiscLinkStatusChanged(LINK_STATUS_UP, COAP, USB_IF);
    LNN_LOGI(LNN_BUILDER, "notify ip ready");
    LnnNotifyNetlinkStateChangeEvent(SOFTBUS_NETMANAGER_IFNAME_LINK_CHANGED, subnet->ifName);
    return SOFTBUS_OK;
}

static int32_t DisableIpSubnet(LnnPhysicalSubnet *subnet)
{
    if (subnet->status == LNN_SUBNET_RUNNING) {
        CloseIpLink();
        UpdateUsbNetCap(false);
        LeaveOldIpNetwork(subnet->ifName);
        ReleaseMainPort(subnet->ifName);
        DiscLinkStatusChanged(LINK_STATUS_DOWN, COAP, USB_IF);
    }
    return SOFTBUS_OK;
}

static int32_t ChangeIpSubnetAddress(LnnPhysicalSubnet *subnet)
{
    CloseIpLink();
    UpdateUsbNetCap(false);
    LeaveOldIpNetwork(subnet->ifName);
    ReleaseMainPort(subnet->ifName);
    DiscLinkStatusChanged(LINK_STATUS_DOWN, COAP, USB_IF);
    return SOFTBUS_OK;
}

static void DestroyUsbSubnetManager(LnnPhysicalSubnet *subnet)
{
    if (subnet == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid subnet");
        return;
    }
    if (subnet->status == LNN_SUBNET_RUNNING) {
        DisableIpSubnet(subnet);
    }
    SoftBusFree(subnet);
}

typedef enum {
    USB_SUBNET_MANAGER_EVENT_IF_READY,
    USB_SUBNET_MANAGER_EVENT_IF_DOWN,    // addr change from available to
    USB_SUBNET_MANAGER_EVENT_IF_CHANGED, // addr changed
    USB_SUBNET_MANAGER_EVENT_MAX
} IpSubnetManagerEvent;

typedef enum {
    IP_EVENT_RESULT_ACCEPTED = 0,
    IP_EVENT_RESULT_REJECTED,
    IP_EVENT_RESULT_OPTION_COUNT
} IpSubnetManagerEventResultOptions;

static void TransactIpSubnetState(LnnPhysicalSubnet *subnet, IpSubnetManagerEvent event, bool isAccepted)
{
    LnnPhysicalSubnetStatus transactMap[][IP_EVENT_RESULT_OPTION_COUNT] = {
        [USB_SUBNET_MANAGER_EVENT_IF_READY] = {LNN_SUBNET_RUNNING, LNN_SUBNET_IDLE},
        [USB_SUBNET_MANAGER_EVENT_IF_DOWN] = {LNN_SUBNET_SHUTDOWN, subnet->status},
        [USB_SUBNET_MANAGER_EVENT_IF_CHANGED] = {LNN_SUBNET_RESETTING, subnet->status}
    };
    subnet->status = transactMap[event][isAccepted ? IP_EVENT_RESULT_ACCEPTED : IP_EVENT_RESULT_REJECTED];
    LNN_LOGI(LNN_BUILDER, "subnet state change. ifName=%{public}s, protocolId=%{public}u, new status=%{public}d",
        subnet->ifName, subnet->protocol->id, subnet->status);
}

static IpSubnetManagerEvent GetIpEventInOther(LnnPhysicalSubnet *subnet)
{
    char currentIfAddress[IP_LEN] = {0};
    int32_t ret = GetAvailableIpAddr(subnet->ifName, currentIfAddress, sizeof(currentIfAddress));
    if (ret == SOFTBUS_OK) {
        return USB_SUBNET_MANAGER_EVENT_IF_READY;
    }
    return subnet->status == LNN_SUBNET_SHUTDOWN ? USB_SUBNET_MANAGER_EVENT_IF_DOWN : USB_SUBNET_MANAGER_EVENT_MAX;
}

static IpSubnetManagerEvent GetIpEventInRunning(LnnPhysicalSubnet *subnet)
{
    char currentIfAddress[IP_LEN] = {0};
    int32_t ret = GetAvailableIpAddr(subnet->ifName, currentIfAddress, sizeof(currentIfAddress));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "GetAvailableIpAddr fail");
        return USB_SUBNET_MANAGER_EVENT_IF_DOWN;
    }

    char localIpAddr[IP_LEN] = {0};
    char localNetifName[NET_IF_NAME_LEN] = {0};
    if (GetLocalIpInfo(localIpAddr, sizeof(localIpAddr), localNetifName, sizeof(localNetifName)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get main ip info failed");
        return USB_SUBNET_MANAGER_EVENT_IF_READY;
    }
    if (strcmp(localNetifName, subnet->ifName) != 0) {
        return USB_SUBNET_MANAGER_EVENT_IF_READY;
    }
    if (strcmp(localIpAddr, currentIfAddress) == 0) {
        return USB_SUBNET_MANAGER_EVENT_MAX;
    } else {
        return USB_SUBNET_MANAGER_EVENT_IF_CHANGED;
    }
}

static void OnSoftbusIpNetworkDisconnected(LnnPhysicalSubnet *subnet)
{
    if (subnet != NULL && (subnet->status == LNN_SUBNET_RESETTING || subnet->status == LNN_SUBNET_IDLE)) {
        int32_t ret = EnableIpSubnet(subnet);
        TransactIpSubnetState(subnet, USB_SUBNET_MANAGER_EVENT_IF_READY, (ret == SOFTBUS_OK));
    }
}

static void OnIpNetifStatusChanged(LnnPhysicalSubnet *subnet, void *status)
{
    if (subnet == NULL) {
        LNN_LOGE(LNN_BUILDER, "invaild subnet paramter");
        if (status != NULL) {
            SoftBusFree(status);
        }
        return;
    }
    LNN_LOGI(LNN_BUILDER, "subnet now status=%{public}d", subnet->status);
    IpSubnetManagerEvent event = USB_SUBNET_MANAGER_EVENT_MAX;
    if (status == NULL) {
        if (subnet->status == LNN_SUBNET_RUNNING) {
            event = GetIpEventInRunning(subnet);
        } else {
            event = GetIpEventInOther(subnet);
        }
    } else {
        event = *(IpSubnetManagerEvent *)status;
        SoftBusFree(status);
        if (event < USB_SUBNET_MANAGER_EVENT_IF_READY || event > USB_SUBNET_MANAGER_EVENT_MAX) {
            LNN_LOGW(LNN_BUILDER, "is not right event=%{public}d", event);
            return;
        }
    }

    int32_t ret = SOFTBUS_NETWORK_NETIF_STATUS_CHANGED;
    switch (event) {
        case USB_SUBNET_MANAGER_EVENT_IF_READY: {
            ret = EnableIpSubnet(subnet);
            break;
        }
        case USB_SUBNET_MANAGER_EVENT_IF_DOWN: {
            ret = DisableIpSubnet(subnet);
            break;
        }
        case USB_SUBNET_MANAGER_EVENT_IF_CHANGED: {
            ret = ChangeIpSubnetAddress(subnet);
            break;
        }
        default:
            return;
    }

    TransactIpSubnetState(subnet, event, (ret == SOFTBUS_OK));
}

static LnnPhysicalSubnet *CreateUsbSubnetManager(const struct LnnProtocolManager *self, const char *ifName)
{
    LnnPhysicalSubnet *subnet = (LnnPhysicalSubnet *)SoftBusCalloc(sizeof(LnnPhysicalSubnet));
    if (subnet == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc subnet fail");
        return NULL;
    }

    do {
        subnet->destroy = DestroyUsbSubnetManager;
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
    if (IsValidUsbIfname(event->ifName)) {
        LNN_LOGI(LNN_BUILDER, "if name is %{public}s", event->ifName);
        LnnNotifyPhysicalSubnetStatusChanged(event->ifName, LNN_PROTOCOL_USB, NULL);
    }
}

static void UsbNcmChangeHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_NET_LINK_STATE_CHANGE) {
        LNN_LOGE(LNN_BUILDER, "get invalid param");
        return;
    }
    const LnnMonitorNetlinkStateInfo *event = (const LnnMonitorNetlinkStateInfo *)info;
    if (!IsValidUsbIfname(event->ifName)) {
        LNN_LOGD(LNN_BUILDER, "not interest event");
        return;
    }
    NetManagerIfNameState status = (NetManagerIfNameState)event->status;
    switch (status) {
        case SOFTBUS_NETMANAGER_IFNAME_REMOVED:
            LNN_LOGI(LNN_BUILDER, "%{public}s removed", event->ifName);
            LnnNotifyPhysicalSubnetStatusChanged(event->ifName, LNN_PROTOCOL_USB, NULL);
            break;
        default:
            LNN_LOGD(LNN_BUILDER, "status %{public}d skip", status);
    }
}

int32_t LnnInitUsbProtocol(struct LnnProtocolManager *self)
{
    LNN_LOGI(LNN_INIT, "LnnInitUsbProtocol");
    (void)self;
    int32_t ret = SOFTBUS_OK;
    if (LnnRegisterEventHandler(LNN_EVENT_IP_ADDR_CHANGED, IpAddrChangeEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "register ip addr change event handler failed");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }

    if (LnnRegisterEventHandler(LNN_EVENT_NET_LINK_STATE_CHANGE, UsbNcmChangeHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "usb regist evt handle faild");
        return SOFTBUS_NETWORK_USB_REG_EVENT_FAILED;
    }

    if (SetLocalIpInfo(LNN_LOOPBACK_IPV6, LNN_LOOPBACK_IFNAME) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init local ip as loopback failed!");
        return SOFTBUS_NETWORK_SET_NODE_INFO_ERR;
    }
    UpdateUsbNetCap(false);
    DiscLinkStatusChanged(LINK_STATUS_DOWN, COAP, USB_IF);
    return ret;
}

int32_t LnnEnableUsbProtocol(struct LnnProtocolManager *self, LnnNetIfMgr *netifMgr)
{
    (void)self;
    if (netifMgr == NULL) {
        LNN_LOGE(LNN_BUILDER, "netif mgr is null");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnPhysicalSubnet *manager = CreateUsbSubnetManager(self, netifMgr->ifName);
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

static ListenerModule LnnGetUsbListenerModule(ListenerMode mode)
{
    if (mode == LNN_LISTENER_MODE_PROXY ||
        mode == LNN_LISTENER_MODE_DIRECT) {
        return DIRECT_CHANNEL_SERVER_USB;
    } else {
        return UNUSE_BUTT;
    }
}

void LnnDeinitUsbNetwork(struct LnnProtocolManager *self)
{
    (void)self;
    LnnUnregisterEventHandler(LNN_EVENT_IP_ADDR_CHANGED, IpAddrChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_NET_LINK_STATE_CHANGE, UsbNcmChangeHandler);
    LnnUnregistPhysicalSubnetByType(LNN_PROTOCOL_USB);
    LNN_LOGW(LNN_INIT, "usb network deinited");
}

static LnnProtocolManager g_usbProtocol = {
    .init = LnnInitUsbProtocol,
    .deinit = LnnDeinitUsbNetwork,
    .enable = LnnEnableUsbProtocol,
    .disable = NULL,
    .getListenerModule = LnnGetUsbListenerModule,
    .id = LNN_PROTOCOL_USB,
    .supportedNetif = LNN_NETIF_TYPE_USB,
    .pri = 10,
};

int32_t RegistUsbProtocolManager(void)
{
    return LnnRegistProtocol(&g_usbProtocol);
}
