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

#include "lnn_ip_utils_adapter.h"

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int32_t GetNetworkIfIp(int32_t fd, struct ifreq *req, char *ip, char *netmask, uint32_t len)
{
    if (ioctl(fd, SIOCGIFFLAGS, (char*)req) < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "ioctl SIOCGIFFLAGS fail, errno = %d", errno);
        return SOFTBUS_ERR;
    }
    if (!((uint16_t)req->ifr_flags & IFF_UP)) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "interface is not up");
        return SOFTBUS_ERR;
    }

    /* get IP of this interface */
    if (ioctl(fd, SIOCGIFADDR, (char*)req) < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "ioctl SIOCGIFADDR fail, errno = %d", errno);
        return SOFTBUS_ERR;
    }
    struct sockaddr_in *sockAddr = (struct sockaddr_in *)&(req->ifr_addr);
    if (inet_ntop(sockAddr->sin_family, &sockAddr->sin_addr, ip, len) == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "convert ip addr to string failed");
        return SOFTBUS_ERR;
    }

    /* get netmask of this interface */
    if (netmask != NULL) {
        if (ioctl(fd, SIOCGIFNETMASK, (char*)req) < 0) {
            HILOG_ERROR(SOFTBUS_HILOG_ID, "ioctl SIOCGIFNETMASK fail, errno = %d", errno);
            return SOFTBUS_ERR;
        }
        sockAddr = (struct sockaddr_in *)&(req->ifr_netmask);
        if (inet_ntop(sockAddr->sin_family, &sockAddr->sin_addr, netmask, len) == NULL) {
            HILOG_ERROR(SOFTBUS_HILOG_ID, "convert netmask addr to string failed");
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t GetNetworkIpByIfName(const char *ifName, char *ip, char *netmask, uint32_t len)
{
    if (ifName == NULL || ip == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "ifName or ip buffer is NULL!");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "open socket failed");
        return SOFTBUS_ERR;
    }
    struct ifreq ifr;
    if (strncpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), ifName, strlen(ifName)) != EOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "copy netIfName:%{public}s fail", ifName);
        close(fd);
        return SOFTBUS_ERR;
    }
    if (GetNetworkIfIp(fd, &ifr, ip, netmask, len) != SOFTBUS_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "GetNetworkIfIp ifName:%{public}s fail", ifName);
        close(fd);
        return SOFTBUS_ERR;
    }
    close(fd);
    return SOFTBUS_OK;
}
