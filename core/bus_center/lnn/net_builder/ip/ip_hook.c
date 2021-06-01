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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <securec.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "auth_socket.h"
#include "bus_center_manager.h"
#include "disc_interface.h"
#include "lnn_connect_info.h"
#include "lnn_net_builder.h"
#include "lnn_state_machine.h"
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "trans_tcp_direct_listener.h"

#define WLAN_IF_NAME_PRE "wlan"
#define ETH_IF_NAME_PRE  "eth"
#define IF_COUNT_MAX 16
#define LNN_DISC_CAPABILITY "ddmpCapability"
#define LNN_PUBLISH_ID 0
#define LNN_SUBSCRIBE_ID 0
#define IP_DEFAULT_PORT 0

typedef struct {
    FsmStateMachine *fsm;
    ConnectionAddrType type;
} IpHookStatus;

typedef struct {
    char *ifName;
    uint32_t  ifNameLen;
} IfInfo;

static IpHookStatus g_status = {
    .fsm = NULL,
    .type = CONNECTION_ADDR_WLAN,
};

static int32_t GetNetworkIfList(int32_t fd, struct ifconf *conf, struct ifreq *buf, uint32_t len)
{
    if (fd < 0 || conf == NULL || buf == NULL) {
        LOG_ERR("fail: parameter error!");
        return SOFTBUS_INVALID_PARAM;
    }
    conf->ifc_len = len;
    conf->ifc_buf = (char *)buf;
    if (ioctl(fd, SIOCGIFCONF, (char*)conf) < 0) {
        LOG_ERR("ioctl fail, errno = %d", errno);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t GetNetworkIfIp(int32_t fd, struct ifreq *req, char *ip, uint32_t len)
{
    if (fd < 0 || req == NULL || ip == NULL) {
        LOG_ERR("fail: parameter error!");
        return SOFTBUS_INVALID_PARAM;
    }

    if (ioctl(fd, SIOCGIFFLAGS, (char*)req) < 0) {
        LOG_ERR("ioctl SIOCGIFFLAGS fail, errno = %d", errno);
        return SOFTBUS_ERR;
    }
    if (!((uint16_t)req->ifr_flags & IFF_UP)) {
        LOG_ERR("interface is not up");
        return SOFTBUS_ERR;
    }

    /* get IP of this interface */
    if (ioctl(fd, SIOCGIFADDR, (char*)req) < 0) {
        LOG_ERR("ioctl SIOCGIFADDR fail, errno = %d", errno);
        return SOFTBUS_ERR;
    }

    if (strcpy_s(ip, len, inet_ntoa(((struct sockaddr_in *)&(req->ifr_addr))->sin_addr)) != EOK) {
        LOG_ERR("STR COPY ERROR!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static char *GetIfNamePre(ConnectionAddrType type)
{
    if (type == CONNECTION_ADDR_WLAN) {
        return WLAN_IF_NAME_PRE;
    } else if (type == CONNECTION_ADDR_ETH) {
        return ETH_IF_NAME_PRE;
    } else {
        LOG_ERR("type = %d, error!", type);
        return NULL;
    }
}

static int32_t GetLocalIp(char *ip, uint32_t len, IfInfo *info, ConnectionAddrType type)
{
    LOG_INFO("type = %d", type);
    if (ip == NULL || len < IP_MAX_LEN || info == NULL || info->ifName == NULL) {
        LOG_ERR("fail : para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    char *pre = GetIfNamePre(type);
    if (pre == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t preLen = strlen(pre);
    int32_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return SOFTBUS_ERR;
    }
    struct ifreq req[IF_COUNT_MAX];
    struct ifconf conf;
    int32_t ret = GetNetworkIfList(fd, &conf, req, sizeof(req));
    if (ret != SOFTBUS_OK) {
        LOG_ERR("GetNetworkIfList fail!");
        close(fd);
        return SOFTBUS_ERR;
    }
    int32_t num = conf.ifc_len / sizeof(struct ifreq);
    ret = SOFTBUS_ERR;
    LOG_INFO("network interface num = %d", num);
    for (int32_t i = 0; (i < num) && (i < IF_COUNT_MAX); i++) {
        LOG_INFO("network interface name is %s", req[i].ifr_name);
        if (strlen(req[i].ifr_name) < preLen) {
            continue;
        }
        if (memcmp(pre, req[i].ifr_name, preLen) == 0) {
            if (GetNetworkIfIp(fd, &req[i], ip, len) == SOFTBUS_OK) {
                (void)strncpy_s(info->ifName, info->ifNameLen, req[i].ifr_name, strlen(req[i].ifr_name));
                LOG_INFO("GetNetworkIfIp ok!");
                ret = SOFTBUS_OK;
            }
            break;
        }
    }
    close(fd);
    return ret;
}

static void DeviceFound(const DeviceInfo *device)
{
    ConnectionAddr *para = NULL;
    if (device == NULL) {
        LOG_ERR("DeviceFound error!");
        return;
    }
    LOG_INFO("DeviceFound! type = %d", g_status.type);
    para = (ConnectionAddr *)SoftBusCalloc(sizeof(ConnectionAddr));
    if (para == NULL) {
        LOG_ERR("malloc init message fail");
        return;
    }
    para->type = g_status.type;
    para->info.ip.port = device->addr[0].port;
    if (strncpy_s(para->info.ip.ip, IP_STR_MAX_LEN, device->addr[0].addr, strlen(device->addr[0].addr)) != EOK) {
        LOG_ERR("STR ERROR!");
        SoftBusFree(para);
        return;
    }

    if (g_status.fsm != NULL) {
        LOG_INFO("PostMessageToFsm!");
        (void)LnnFsmRemoveMessage(g_status.fsm, FSM_MSG_TYPE_DISCOVERY_TIMEOUT);
        if (LnnFsmPostMessage(g_status.fsm, FSM_MSG_TYPE_JOIN_LNN, para) != SOFTBUS_OK) {
            LOG_ERR("LnnFsmPostMessage FSM_MSG_TYPE_JOIN_LNN error!");
            SoftBusFree(para);
        }
    } else {
        LOG_ERR("DeviceFound don't post to fsm!");
        SoftBusFree(para);
    }
    return;
}

static DiscInnerCallback g_discCb = {
    .OnDeviceFound = DeviceFound,
};

static int32_t EnableCoapDisc(void)
{
    LOG_INFO("EnableCoapDisc begin");
    int32_t ret = DiscSetDiscoverCallback(MODULE_LNN, &g_discCb);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("DiscSetDiscoverCallback error!");
        return SOFTBUS_ERR;
    }
    PublishInnerInfo publishInfo = {
        .publishId = LNN_PUBLISH_ID,
        .medium = COAP,
        .freq = HIGH,
        .capability = LNN_DISC_CAPABILITY,
        .capabilityData = (unsigned char *)LNN_DISC_CAPABILITY,
        .dataLen = strlen(LNN_DISC_CAPABILITY) + 1,
    };
    LOG_INFO("DiscStartScan!");
    ret = DiscStartScan(MODULE_LNN, &publishInfo);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("DiscStartScan fail!");
        return SOFTBUS_ERR;
    }

    SubscribeInnerInfo subscribeInfo = {
        .subscribeId = LNN_SUBSCRIBE_ID,
        .medium = COAP,
        .freq = HIGH,
        .isSameAccount = false,
        .isWakeRemote = false,
        .capability = LNN_DISC_CAPABILITY,
        .capabilityData = (unsigned char *)LNN_DISC_CAPABILITY,
        .dataLen = strlen(LNN_DISC_CAPABILITY) + 1,
    };
    LOG_INFO("DiscStartAdvertise!");
    ret = DiscStartAdvertise(MODULE_LNN, &subscribeInfo);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("DiscStartAdvertise fail!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t UpdateLocalIp(ConnectionAddrType type)
{
    char ipAddr[IP_MAX_LEN] = {0};
    char ifName[NET_IF_NAME_LEN] = {0};
    IfInfo info = {
        .ifName = ifName,
        .ifNameLen = NET_IF_NAME_LEN,
    };
    int32_t ret = GetLocalIp(ipAddr, IP_MAX_LEN, &info, type);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("GetLocalIp error!");
        return SOFTBUS_ERR;
    }
    ret = LnnSetLocalStrInfo(STRING_KEY_WLAN_IP, ipAddr);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("LnnSetLocalStrInfo error!");
        return SOFTBUS_ERR;
    }
    (void)LnnSetLocalStrInfo(STRING_KEY_NET_IF_NAME, ifName);
    return SOFTBUS_OK;
}

static int32_t UpdateProxyPort(void)
{
    LocalListenerInfo listenerInfo = {0};
    char ipAddr[IP_MAX_LEN] = {0};
    listenerInfo.type = CONNECT_TCP;
    listenerInfo.info.ipListenerInfo.port = 0;
    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, ipAddr, IP_MAX_LEN) != SOFTBUS_OK) {
        LOG_ERR("LnnGetLocalStrInfo fail!");
        return SOFTBUS_ERR;
    }
    if (strncpy_s(listenerInfo.info.ipListenerInfo.ip, IP_LEN, ipAddr, strlen(ipAddr)) != EOK) {
        LOG_ERR("fail:strncpy_s fail!");
        return SOFTBUS_MEM_ERR;
    }
    int32_t port = ConnStartLocalListening(&listenerInfo);
    return LnnSetLocalNumInfo(NUM_KEY_PROXY_PORT, port);
}

static int32_t UpdateSessionPort(void)
{
    char ipAddr[IP_MAX_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, ipAddr, IP_MAX_LEN) != SOFTBUS_OK) {
        LOG_ERR("LnnGetLocalStrInfo fail!");
        return SOFTBUS_ERR;
    }
    int32_t port = TransTdcStartSessionListener(ipAddr, 0);
    return LnnSetLocalNumInfo(NUM_KEY_SESSION_PORT, port);
}

static int32_t UpdateAuthPort(void)
{
    int32_t port = OpenAuthServer();
    return LnnSetLocalNumInfo(NUM_KEY_AUTH_PORT, port);
}

static void CloseAuthPort(void)
{
    CloseAuthServer();
    (void)LnnSetLocalNumInfo(NUM_KEY_AUTH_PORT, IP_DEFAULT_PORT);
    return;
}

static void CloseSessionPort(void)
{
    TransTdcStopSessionListener();
    (void)LnnSetLocalNumInfo(NUM_KEY_SESSION_PORT, IP_DEFAULT_PORT);
    return;
}

static void CloseProxyPort(void)
{
    LocalListenerInfo listenerInfo = {0};
    listenerInfo.type = CONNECT_TCP;
    if (ConnStopLocalListening(&listenerInfo) != SOFTBUS_OK) {
        LOG_ERR("ConnStopLocalListening fail!");
    }
    (void)LnnSetLocalNumInfo(NUM_KEY_PROXY_PORT, IP_DEFAULT_PORT);
    return;
}

static int32_t OpenIpLink(void)
{
    int32_t ret = UpdateAuthPort();
    if (ret != SOFTBUS_OK) {
        LOG_ERR("UpdateSeesionPort fail!");
        return SOFTBUS_ERR;
    }
    ret = UpdateSessionPort();
    if (ret != SOFTBUS_OK) {
        LOG_ERR("UpdateSeesionPort fail!");
        CloseAuthPort();
        return SOFTBUS_ERR;
    }
    ret = UpdateProxyPort();
    if (ret != SOFTBUS_OK) {
        LOG_ERR("UpdateProxyPort fail!");
        CloseAuthPort();
        CloseSessionPort();
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

static void CloseCoapDisc(void)
{
    if (DiscUnpublish(MODULE_LNN, LNN_PUBLISH_ID) != SOFTBUS_OK) {
        LOG_ERR("DiscUnpublish fail!");
    }
    if (DiscStopAdvertise(MODULE_LNN, LNN_SUBSCRIBE_ID) != SOFTBUS_OK) {
        LOG_ERR("DiscStopAdvertise fail!");
    }
    return;
}

static int32_t IpPreprocess(const ConnectionAddr *addr, FsmStateMachine *fsm, NetworkType networkType)
{
    if (addr == NULL || fsm == NULL) {
        LOG_ERR("para error!");
        return SOFTBUS_ERR;
    }
    ConnectionAddrType type = addr->type;

    if (UpdateLocalIp(type) != SOFTBUS_OK) {
        LOG_ERR("UpdateLocalIp fail!");
        return SOFTBUS_ERR;
    }
    if (OpenIpLink() != SOFTBUS_OK) {
        LOG_ERR("OpenIpLink fail!");
        return SOFTBUS_ERR;
    }
    if (networkType == NETWORK_TYPE_ACTIVE) {
        ConnectionAddrType *para = (ConnectionAddrType *)SoftBusCalloc(sizeof(ConnectionAddrType));
        if (para == NULL) {
            LOG_ERR("malloc init message fail");
            return SOFTBUS_ERR;
        }
        *para = type;
        if (LnnFsmPostMessageDelay(fsm, FSM_MSG_TYPE_DISCOVERY_TIMEOUT, para, JOIN_DISCOVERY_TIMEOUT_LEN)
            != SOFTBUS_OK) {
            SoftBusFree(para);
            return SOFTBUS_ERR;
        }
    }
    if (EnableCoapDisc() != SOFTBUS_OK) {
        LOG_ERR("EnableCoapDisc fail!");
        return SOFTBUS_ERR;
    }

    LOG_INFO("IpPreprocess ok!");
    g_status.fsm = fsm;
    g_status.type = type;
    return SOFTBUS_OK;
}

static void IpShutdown(const ConnectionAddr *addr)
{
    (void)addr;
    (void)LnnSetLocalStrInfo(STRING_KEY_WLAN_IP, LOCAL_IP);
    CloseIpLink();
    CloseCoapDisc();
    g_status.fsm = NULL;
    return;
}

static ConnTypeHook g_hook = {
    .preprocess = IpPreprocess,
    .shutdown = IpShutdown,
};

void LnnInitIpHook(void)
{
    LnnRegisterConnTypeHook(CONNECTION_ADDR_WLAN, &g_hook);
    LnnRegisterConnTypeHook(CONNECTION_ADDR_ETH, &g_hook);
    if (UpdateLocalIp(CONNECTION_ADDR_ETH) == SOFTBUS_OK) {
        LOG_INFO("update eth ip success");
        return;
    }
    if (UpdateLocalIp(CONNECTION_ADDR_WLAN) == SOFTBUS_OK) {
        LOG_INFO("update wlan ip success");
    }
}
