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

#include "lnn_ip_utils.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <net/if.h>
#include <securec.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "softbus_errcode.h"
#include "softbus_log.h"

#define IF_COUNT_MAX 16

static const char *GetIfNamePrefix(ConnectionAddrType type)
{
    if (type == CONNECTION_ADDR_WLAN) {
        return LNN_WLAN_IF_NAME_PREFIX;
    } else if (type == CONNECTION_ADDR_ETH) {
        return LNN_ETH_IF_NAME_PREFIX;
    } else {
        return NULL;
    }
}

static int32_t GetNetworkIfIp(int32_t fd, struct ifreq *req, char *ip, uint32_t len)
{
    if (ioctl(fd, SIOCGIFFLAGS, (char*)req) < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ioctl SIOCGIFFLAGS fail, errno = %d", errno);
        return SOFTBUS_ERR;
    }
    if (!((uint16_t)req->ifr_flags & IFF_UP)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "interface is not up");
        return SOFTBUS_ERR;
    }

    /* get IP of this interface */
    if (ioctl(fd, SIOCGIFADDR, (char*)req) < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ioctl SIOCGIFADDR fail, errno = %d", errno);
        return SOFTBUS_ERR;
    }
    struct sockaddr_in *sockAddr = (struct sockaddr_in *)&(req->ifr_addr);
    if (inet_ntop(sockAddr->sin_family, &sockAddr->sin_addr, ip, len) == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "convert ip addr to string failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnGetLocalIp(char *ip, uint32_t len, char *ifName, uint32_t ifNameLen, ConnectionAddrType type)
{
    if (ip == NULL || ifName == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ip or ifName buffer is null");
        return SOFTBUS_INVALID_PARAM;
    }
    const char *prefix = GetIfNamePrefix(type);
    if (prefix == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get ifname prefix failed");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "open socket failed");
        return SOFTBUS_ERR;
    }
    struct ifreq req[IF_COUNT_MAX];
    struct ifconf conf = {
        .ifc_len = sizeof(req),
        .ifc_buf = (char *)&req,
    };
    int32_t ret = ioctl(fd, SIOCGIFCONF, (char *)&conf);
    if (ret < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ioctl fail, errno = %d", errno);
        close(fd);
        return SOFTBUS_ERR;
    }
    int32_t num = conf.ifc_len / sizeof(struct ifreq);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "network interface num = %d", num);
    ret = SOFTBUS_ERR;
    for (int32_t i = 0; (i < num) && (i < IF_COUNT_MAX); i++) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "network interface name is %s", req[i].ifr_name);
        if (strncmp(prefix, req[i].ifr_name, strlen(prefix)) != 0) {
            continue;
        }
        if (GetNetworkIfIp(fd, &req[i], ip, len) != SOFTBUS_OK) {
            continue;
        }
        if (strncpy_s(ifName, ifNameLen, req[i].ifr_name, strlen(req[i].ifr_name)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy ifname failed");
            continue;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "GetNetworkIfIp ok!");
        ret = SOFTBUS_OK;
        break;
    }
    close(fd);
    return ret;
}
